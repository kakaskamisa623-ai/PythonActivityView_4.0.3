from __future__ import annotations

"""Small, testable helpers for Python Activity View 2.5.0.

All functions operate on explicitly supplied local records/files.  They do not
collect keystrokes, read browser data, access other users' profiles or alter
source evidence.
"""

import hashlib
import json
import os
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

def file_sha256(path: Path, max_bytes: int = 512 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return "not_computed_file_over_limit"
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception as exc:
        return f"unavailable: {type(exc).__name__}: {exc}"


def event_fingerprint(row: dict[str, Any]) -> str:
    """Stable-ish identity for scan comparison; it is not a forensic identifier."""
    details = row.get("details") or {}
    stable_detail = {
        key: details.get(key)
        for key in (
            "line_number", "execution_number", "session", "process_id",
            "parent_process_id", "process_guid", "parent_process_guid",
            "event_id", "record_id", "line_number_in_scanned_fragment",
        ) if key in details
    }
    payload = {
        "timestamp": row.get("timestamp", ""),
        "kind": row.get("kind", ""),
        "description": row.get("description", ""),
        "command": row.get("command", ""),
        "source": row.get("source", ""),
        "stable_detail": stable_detail,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()



def event_deduplication_fingerprint(row: dict[str, Any]) -> str:
    """Fingerprint a complete event so different records from one source survive.

    This is for in-memory duplicate suppression only. It deliberately includes
    the timestamp and full details because multiple real events can share the
    same kind, source path, and even command text.
    """
    payload = {
        "timestamp": row.get("timestamp", ""),
        "kind": row.get("kind", ""),
        "description": row.get("description", ""),
        "command": row.get("command", ""),
        "source": row.get("source", ""),
        "user": row.get("user", ""),
        "details": row.get("details", {}),
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()


def deduplicate_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove exact duplicate records while preserving distinct same-source events."""
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = event_deduplication_fingerprint(row)
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result

def compare_snapshots(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_events = old.get("events") or []
    new_events = new.get("events") or []
    old_counter = Counter(event_fingerprint(x) for x in old_events if isinstance(x, dict))
    new_counter = Counter(event_fingerprint(x) for x in new_events if isinstance(x, dict))
    old_map = {event_fingerprint(x): x for x in old_events if isinstance(x, dict)}
    new_map = {event_fingerprint(x): x for x in new_events if isinstance(x, dict)}
    added_keys = list((new_counter - old_counter).elements())
    removed_keys = list((old_counter - new_counter).elements())
    old_sources = {str(x.get("path", "")).casefold(): x for x in old.get("sources", []) if isinstance(x, dict)}
    new_sources = {str(x.get("path", "")).casefold(): x for x in new.get("sources", []) if isinstance(x, dict)}

    def file_map(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
        result = {}
        for row in snapshot.get("python_files", []):
            if not isinstance(row, dict) or not row.get("path"):
                continue
            result[str(row["path"]).casefold()] = row
        return result

    old_files, new_files = file_map(old), file_map(new)
    added_files = [new_files[k] for k in new_files.keys() - old_files.keys()]
    removed_files = [old_files[k] for k in old_files.keys() - new_files.keys()]
    changed_files = []
    for key in new_files.keys() & old_files.keys():
        before, after = old_files[key], new_files[key]
        if (before.get("size_bytes"), before.get("modified_local")) != (after.get("size_bytes"), after.get("modified_local")):
            changed_files.append({"before": before, "after": after})

    def process_key(row: dict[str, Any]) -> tuple[str, str, str, str]:
        return (str(row.get("pid", "")), str(row.get("name", "")).casefold(), str(row.get("path", "")).casefold(), str(row.get("command_line", "")))

    old_processes = {process_key(x): x for x in old.get("process_snapshot", []) if isinstance(x, dict)}
    new_processes = {process_key(x): x for x in new.get("process_snapshot", []) if isinstance(x, dict)}
    return {
        "added_events": [new_map[k] for k in added_keys if k in new_map],
        "removed_events": [old_map[k] for k in removed_keys if k in old_map],
        "added_sources": [new_sources[k] for k in new_sources.keys() - old_sources.keys()],
        "removed_sources": [old_sources[k] for k in old_sources.keys() - new_sources.keys()],
        "added_python_files": added_files,
        "removed_python_files": removed_files,
        "changed_python_files": changed_files,
        "added_processes": [new_processes[k] for k in new_processes.keys() - old_processes.keys()],
        "removed_processes": [old_processes[k] for k in old_processes.keys() - new_processes.keys()],
        "common_event_count": sum((old_counter & new_counter).values()),
        "old_event_count": len(old_events),
        "new_event_count": len(new_events),
    }


def normalize_pid(value: Any) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    try:
        if raw.startswith("0x"):
            return str(int(raw, 16))
        return str(int(raw))
    except Exception:
        return raw


def make_process_tree_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build conservative historical parent-child links from retained event data.

    Parent links are created only if the parent event is present and precedes the
    child by no more than 10 minutes. Sysmon ProcessGuid links are preferred.
    """
    candidates: list[dict[str, Any]] = []
    for row in events:
        details = row.get("details") or {}
        fields = details.get("fields") or {}
        pid = normalize_pid(details.get("process_id") or details.get("ProcessId") or fields.get("NewProcessId"))
        ppid = normalize_pid(details.get("parent_process_id") or details.get("ParentProcessId") or fields.get("ProcessId"))
        guid = str(details.get("process_guid") or fields.get("ProcessGuid") or "").strip().casefold()
        pguid = str(details.get("parent_process_guid") or fields.get("ParentProcessGuid") or "").strip().casefold()
        image = str(details.get("process_image") or fields.get("Image") or fields.get("NewProcessName") or "")
        parent_image = str(details.get("parent_process") or fields.get("ParentImage") or fields.get("CreatorProcessName") or "")
        if not (pid or guid) or not (image or row.get("command")):
            continue
        stamp = str(row.get("timestamp", ""))
        try:
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if stamp else None
            epoch = parsed.timestamp() if parsed else None
        except Exception:
            epoch = None
        candidates.append({
            "pid": pid, "ppid": ppid, "guid": guid, "parent_guid": pguid,
            "image": image or str(row.get("description", "")),
            "parent_image": parent_image,
            "timestamp": stamp, "epoch": epoch,
            "command": str(row.get("command", "")),
            "source": str(row.get("source", "")),
            "relation": str(details.get("process_relation", "")),
            "current_snapshot": str(row.get("source", "")) == "Текущий снимок процессов" or str(details.get("process_relation", "")).startswith("current process snapshot"),
            "event": row,
        })

    candidates.sort(key=lambda x: x["epoch"] if x["epoch"] is not None else float("inf"))
    by_pid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_guid: dict[str, dict[str, Any]] = {}
    for item in candidates:
        parent = None
        if item["parent_guid"] and item["parent_guid"] in by_guid:
            parent = by_guid[item["parent_guid"]]
        elif item["ppid"]:
            known_parents = by_pid.get(item["ppid"], [])
            if item["current_snapshot"]:
                # In a single current process snapshot, PID uniqueness is valid
                # for concurrently running processes; the 10-minute historical
                # guard is not needed for these contemporaneous rows.
                eligible = [p for p in known_parents if p["current_snapshot"]]
            else:
                eligible = [
                    p for p in known_parents
                    if not p["current_snapshot"] and p["epoch"] is not None and item["epoch"] is not None
                    and 0 <= item["epoch"] - p["epoch"] <= 600
                ]
            if eligible:
                parent = eligible[-1]
        item["parent_key"] = id(parent) if parent else ""
        item["key"] = id(item)
        if item["pid"]:
            by_pid[item["pid"]].append(item)
        if item["guid"]:
            by_guid[item["guid"]] = item

    # Break any unexpected cycles by promoting the node to a root.
    known = {x["key"] for x in candidates}
    for item in candidates:
        if item["parent_key"] not in known or item["parent_key"] == item["key"]:
            item["parent_key"] = ""
    return candidates


def normalize_imported_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a saved scan/report for cross-computer snapshot comparison.

    Supports local scan snapshots and exported JSON/ZIP report payloads.
    Duplicate system-trace rows are removed by event fingerprint; captured record values are kept as supplied by their source.
    """
    if not isinstance(payload, dict):
        raise TypeError("Snapshot must be a JSON object")

    events: list[dict[str, Any]] = []
    seen_events: set[str] = set()
    sources: list[dict[str, Any]] = []
    seen_sources: set[tuple[str, str, str]] = set()

    def add_events(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            key = event_fingerprint(item)
            if key not in seen_events:
                seen_events.add(key)
                events.append(item)

    def add_sources(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            key = (str(item.get("path", "")).casefold(), str(item.get("type", "")).casefold(), str(item.get("status", "")).casefold())
            if key not in seen_sources:
                seen_sources.add(key)
                sources.append(item)

    add_events(payload.get("events"))
    add_sources(payload.get("sources"))

    for key in ("system_trace", "system_trace_analysis"):
        section = payload.get(key)
        if isinstance(section, dict):
            add_events(section.get("events"))
            add_sources(section.get("sources"))

    python_files = payload.get("python_files") if isinstance(payload.get("python_files"), list) else []
    process_snapshot = payload.get("process_snapshot")
    if not isinstance(process_snapshot, list):
        process_snapshot = payload.get("current_process_snapshot")
    if not isinstance(process_snapshot, list):
        process_snapshot = []
    warnings = list(payload.get("warnings", [])) if isinstance(payload.get("warnings"), list) else []
    for key in ("system_trace", "system_trace_analysis"):
        section = payload.get(key)
        if isinstance(section, dict) and isinstance(section.get("warnings"), list):
            warnings.extend(section["warnings"])

    normalized = dict(payload)
    normalized.update({
        "events": events,
        "sources": sources,
        "python_files": python_files,
        "process_snapshot": process_snapshot,
        "warnings": warnings,
        "summary": {
            "events": len(events),
            "sources": len(sources),
            "python_files": len(python_files),
            "processes": len(process_snapshot),
            "warnings": len(warnings),
        },
        "normalized_for_comparison": True,
    })
    return normalized


def verify_authenticode(path: Path, timeout: int = 20) -> dict[str, Any]:
    """Verify a Windows Authenticode signature using built-in PowerShell cmdlets."""
    digest = file_sha256(path)
    result = {
        "path": str(path),
        "sha256": digest,
        "platform_supported": os.name == "nt",
        "signature_status": "not_checked",
        "signer": "",
        "status_message": "",
    }
    if os.name != "nt":
        result["status_message"] = "Authenticode is available only on Windows."
        return result
    powershell = os.environ.get("SystemRoot", r"C:\Windows") + r"\System32\WindowsPowerShell\v1.0\powershell.exe"
    if not Path(powershell).is_file():
        powershell = "powershell.exe"
    # Pass the path as an encoded script literal to avoid command-line injection.
    encoded_path = json.dumps(str(path.resolve()), ensure_ascii=False)
    script = (
        "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        "$OutputEncoding = New-Object System.Text.UTF8Encoding($false); "
        f"$p = ConvertFrom-Json -InputObject '{encoded_path.replace(chr(39), chr(39)*2)}'; "
        "$s = Get-AuthenticodeSignature -LiteralPath $p; "
        "$signer=''; $issuer=''; $thumb=''; "
        "if($s.SignerCertificate){$signer=$s.SignerCertificate.Subject; $issuer=$s.SignerCertificate.Issuer; $thumb=$s.SignerCertificate.Thumbprint}; "
        "$o = [pscustomobject]@{Status=[string]$s.Status; StatusMessage=[string]$s.StatusMessage; Signer=$signer; Issuer=$issuer; Thumbprint=$thumb}; "
        "$o | ConvertTo-Json -Compress"
    )
    import base64
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    try:
        proc = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True, text=False,
            timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        from pav_encoding import decode_text_bytes
        stdout_text, _stdout_encoding = decode_text_bytes(proc.stdout or b"")
        stderr_text, _stderr_encoding = decode_text_bytes(proc.stderr or b"")
        if proc.returncode != 0 or not stdout_text.strip():
            result["signature_status"] = "error"
            result["status_message"] = (stderr_text or stdout_text or f"PowerShell exit {proc.returncode}").strip()[:1000]
            return result
        data = json.loads(stdout_text.strip().splitlines()[-1])
        result.update({
            "signature_status": data.get("Status", "unknown"),
            "status_message": data.get("StatusMessage", ""),
            "signer": data.get("Signer", ""),
            "issuer": data.get("Issuer", ""),
            "thumbprint": data.get("Thumbprint", ""),
        })
    except subprocess.TimeoutExpired:
        result["signature_status"] = "timeout"
        result["status_message"] = "Signature check timed out."
    except Exception as exc:
        result["signature_status"] = "error"
        result["status_message"] = f"{type(exc).__name__}: {exc}"
    return result
