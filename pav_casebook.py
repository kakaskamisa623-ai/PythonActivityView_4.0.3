from __future__ import annotations

"""Portable case/evidence management for Python Activity View.

The module copies only files explicitly selected by the operator. It never
modifies the selected source file. Hash chaining is tamper-evident, not a
cryptographic signature or protection against a person who can rewrite the
entire case and recompute the chain.
"""

import hashlib
import json
import os
import re
import shutil
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA = "python-activity-view.case"
SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64


def now_local() -> str:
    return datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sha256_file(path: str | os.PathLike[str], chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_directory(case_path: str | os.PathLike[str]) -> Path:
    p = Path(case_path)
    return p.with_name(p.stem + ".evidence")


def safe_filename(value: str, limit: int = 100) -> str:
    value = Path(str(value)).name
    value = re.sub(r"[^\w.() -]+", "_", value, flags=re.UNICODE).strip(" ._")
    return (value or "evidence.bin")[:limit]


def new_case(name: str, notes: str = "") -> dict[str, Any]:
    stamp = now_local()
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "case_id": str(uuid.uuid4()),
        "name": str(name or "Unnamed case").strip(),
        "notes": str(notes),
        "created_local": stamp,
        "updated_local": stamp,
        "trusted_context_paths": [],
        "evidence": [],
        "audit_log": [],
        "scope": "Locally managed case. Evidence copies are read-only records; findings require human review.",
    }
    append_audit(payload, "case_created", {"name": payload["name"]})
    return payload


def migrate_case(payload: dict[str, Any], fallback_name: str = "Unnamed case") -> dict[str, Any]:
    """Migrate 3.x note-only cases without dropping any existing values."""
    result = dict(payload)
    result.setdefault("schema", SCHEMA)
    result.setdefault("schema_version", SCHEMA_VERSION)
    result.setdefault("case_id", str(uuid.uuid4()))
    result.setdefault("name", fallback_name)
    result.setdefault("notes", "")
    result.setdefault("created_local", result.get("updated_local") or now_local())
    result.setdefault("updated_local", now_local())
    result.setdefault("trusted_context_paths", [])
    result.setdefault("evidence", [])
    result.setdefault("audit_log", [])
    result.setdefault("scope", "Migrated case; legacy notes are context, not forensic findings.")
    if not isinstance(result["evidence"], list):
        result["evidence"] = []
    if not isinstance(result["audit_log"], list):
        result["audit_log"] = []
    if not result["audit_log"]:
        append_audit(result, "case_migrated", {"from_schema": payload.get("schema_version", "legacy")})
    return result


def load_case(path: str | os.PathLike[str]) -> dict[str, Any]:
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8-sig"))
    if not isinstance(raw, dict):
        raise ValueError("Case JSON root must be an object")
    return migrate_case(raw, p.stem)


def append_audit(payload: dict[str, Any], action: str, details: dict[str, Any] | None = None,
                 actor: str | None = None) -> dict[str, Any]:
    rows = payload.setdefault("audit_log", [])
    previous = rows[-1].get("entry_hash", GENESIS_HASH) if rows else GENESIS_HASH
    row = {
        "sequence": len(rows) + 1,
        "timestamp_local": now_local(),
        "actor": actor or os.environ.get("USERNAME") or os.environ.get("USER") or "local-user",
        "action": str(action),
        "details": details or {},
        "previous_hash": previous,
    }
    row["entry_hash"] = hashlib.sha256(_canonical(row)).hexdigest()
    rows.append(row)
    payload["updated_local"] = row["timestamp_local"]
    return row


def verify_audit_chain(payload: dict[str, Any]) -> dict[str, Any]:
    rows = payload.get("audit_log", [])
    if not isinstance(rows, list):
        return {"valid": False, "checked": 0, "error": "audit_log is not a list"}
    previous = GENESIS_HASH
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            return {"valid": False, "checked": index - 1, "error": f"entry {index} is not an object"}
        supplied = row.get("entry_hash", "")
        material = {k: v for k, v in row.items() if k != "entry_hash"}
        expected = hashlib.sha256(_canonical(material)).hexdigest()
        if row.get("sequence") != index:
            return {"valid": False, "checked": index - 1, "error": f"sequence mismatch at entry {index}"}
        if row.get("previous_hash") != previous:
            return {"valid": False, "checked": index - 1, "error": f"previous hash mismatch at entry {index}"}
        if supplied != expected:
            return {"valid": False, "checked": index - 1, "error": f"entry hash mismatch at entry {index}"}
        previous = supplied
    return {"valid": True, "checked": len(rows), "head_hash": previous, "error": ""}


def _copy_and_hash(source: Path, destination: Path) -> tuple[str, int]:
    before = source.stat()
    digest = hashlib.sha256()
    total = 0
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with source.open("rb") as src, destination.open("xb") as dst:
            for chunk in iter(lambda: src.read(1024 * 1024), b""):
                dst.write(chunk)
                digest.update(chunk)
                total += len(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        after = source.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError("Source file changed while it was being copied")
        copied_hash = sha256_file(destination)
        if copied_hash != digest.hexdigest() or total != before.st_size:
            raise RuntimeError("Evidence copy verification failed")
        try:
            shutil.copystat(source, destination, follow_symlinks=True)
        except OSError:
            pass
        return copied_hash, total
    except Exception:
        try:
            destination.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def add_evidence(payload: dict[str, Any], case_path: str | os.PathLike[str],
                source_path: str | os.PathLike[str], note: str = "") -> dict[str, Any]:
    source = Path(source_path).expanduser().resolve(strict=True)
    if not source.is_file():
        raise ValueError("Selected evidence source is not a regular file")
    root = evidence_directory(case_path)
    root.mkdir(parents=True, exist_ok=True)
    seq = len(payload.get("evidence", [])) + 1
    base = safe_filename(source.name)
    destination = root / f"{seq:04d}_{base}"
    suffix = 1
    while destination.exists():
        destination = root / f"{seq:04d}_{suffix}_{base}"
        suffix += 1
    digest, size = _copy_and_hash(source, destination)
    record = {
        "evidence_id": str(uuid.uuid4()),
        "name": source.name,
        "original_path": str(source),
        "stored_path": destination.relative_to(Path(case_path).parent).as_posix(),
        "size_bytes": size,
        "sha256": digest,
        "source_mtime_ns": source.stat().st_mtime_ns,
        "added_local": now_local(),
        "note": str(note),
        "included": True,
    }
    payload.setdefault("evidence", []).append(record)
    append_audit(payload, "evidence_added", {"evidence_id": record["evidence_id"], "name": record["name"], "sha256": digest, "size_bytes": size})
    return record


def resolve_stored_path(case_path: str | os.PathLike[str], record: dict[str, Any]) -> Path:
    root = Path(case_path).parent.resolve()
    relative = PurePosixPath(str(record.get("stored_path", "")))
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Unsafe evidence path in case file")
    target = (root / Path(*relative.parts)).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Evidence path escapes the case directory")
    return target


def verify_evidence(payload: dict[str, Any], case_path: str | os.PathLike[str]) -> list[dict[str, Any]]:
    results = []
    for row in payload.get("evidence", []):
        if not row.get("included", True):
            results.append({"evidence_id": row.get("evidence_id"), "status": "excluded", "path": "", "actual_sha256": ""})
            continue
        try:
            path = resolve_stored_path(case_path, row)
            if not path.is_file():
                results.append({"evidence_id": row.get("evidence_id"), "status": "missing", "path": str(path), "actual_sha256": ""})
                continue
            actual = sha256_file(path)
            expected = str(row.get("sha256", ""))
            results.append({"evidence_id": row.get("evidence_id"), "status": "ok" if actual == expected else "hash_mismatch", "path": str(path), "actual_sha256": actual, "expected_sha256": expected})
        except Exception as exc:
            results.append({"evidence_id": row.get("evidence_id"), "status": "error", "error": str(exc)})
    return results


def verify_case(payload: dict[str, Any], case_path: str | os.PathLike[str]) -> dict[str, Any]:
    audit = verify_audit_chain(payload)
    evidence = verify_evidence(payload, case_path)
    return {
        "audit_chain": audit,
        "evidence": evidence,
        "evidence_ok": sum(1 for row in evidence if row.get("status") == "ok"),
        "evidence_problem": [row for row in evidence if row.get("status") not in {"ok", "excluded"}],
        "valid": bool(audit.get("valid")) and all(row.get("status") in {"ok", "excluded"} for row in evidence),
        "note": "Hash-chain verification is tamper-evident, not a digital signature. A party able to rewrite the whole case can recompute an unsigned chain.",
    }


def save_case_as(payload: dict[str, Any], old_case_path: str | os.PathLike[str],
                 new_case_path: str | os.PathLike[str]) -> None:
    """Copy the evidence vault to a new case location and preserve hashes."""
    old_path = Path(old_case_path)
    new_path = Path(new_case_path)
    new_root = evidence_directory(new_path)
    new_root.mkdir(parents=True, exist_ok=True)
    relocated: list[tuple[dict[str, Any], str]] = []
    copied_paths: list[Path] = []
    try:
        for index, row in enumerate(payload.get("evidence", []), 1):
            try:
                old_file = resolve_stored_path(old_path, row)
            except Exception:
                if row.get("included", True):
                    raise
                continue
            if not old_file.is_file():
                if row.get("included", True):
                    raise FileNotFoundError(f"Evidence copy is missing: {old_file}")
                continue
            new_file = new_root / f"{index:04d}_{safe_filename(old_file.name, 140)}"
            suffix = 1
            while new_file.exists():
                new_file = new_root / f"{index:04d}_{suffix}_{safe_filename(old_file.name, 140)}"
                suffix += 1
            shutil.copy2(old_file, new_file)
            copied_paths.append(new_file)
            if sha256_file(new_file) != str(row.get("sha256", "")):
                raise RuntimeError(f"Evidence changed while saving case as: {old_file.name}")
            relocated.append((row, new_file.relative_to(new_path.parent).as_posix()))
        for row, relative in relocated:
            row["stored_path"] = relative
        append_audit(payload, "case_saved_as", {"new_case_file": new_path.name, "evidence_count": len(relocated)})
        save_case(payload, new_path)
    except Exception:
        # Keep old references intact; remove only newly copied files from this attempt.
        for path in copied_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def mark_evidence_excluded(payload: dict[str, Any], evidence_id: str) -> bool:
    for row in payload.get("evidence", []):
        if str(row.get("evidence_id")) == str(evidence_id):
            row["included"] = False
            row["excluded_local"] = now_local()
            append_audit(payload, "evidence_excluded", {"evidence_id": evidence_id, "name": row.get("name", "")})
            return True
    return False


def save_case(payload: dict[str, Any], case_path: str | os.PathLike[str]) -> None:
    target = Path(case_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload["updated_local"] = now_local()
    temp = target.with_name(target.name + ".tmp")
    data = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    with temp.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, target)


def _manifest_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def export_case_package(payload: dict[str, Any], case_path: str | os.PathLike[str],
                        destination: str | os.PathLike[str], app_version: str = "4.0.0") -> dict[str, Any]:
    case_path = Path(case_path)
    append_audit(payload, "case_package_exported", {"destination_name": Path(destination).name})
    save_case(payload, case_path)
    # Keep the local case's paths intact, but write portable relative paths
    # into the packaged copy. Imported packages use a sibling case.evidence folder.
    portable_payload = json.loads(json.dumps(payload, ensure_ascii=False, default=str))
    files: dict[str, bytes] = {}
    for row in portable_payload.get("evidence", []):
        if not row.get("included", True):
            continue
        original_row = next((x for x in payload.get("evidence", []) if x.get("evidence_id") == row.get("evidence_id")), None)
        if not original_row:
            continue
        evidence_path = resolve_stored_path(case_path, original_row)
        if not evidence_path.is_file():
            raise FileNotFoundError(f"Evidence copy is missing: {evidence_path}")
        portable_name = safe_filename(evidence_path.name, 160)
        row["stored_path"] = "case.evidence/" + portable_name
        arcname = "evidence/" + portable_name
        files[arcname] = evidence_path.read_bytes()
    files["case.json"] = json.dumps(portable_payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
    manifest = {
        "format": SCHEMA,
        "format_version": 1,
        "application_version": app_version,
        "created_local": now_local(),
        "files": {name: {"size_bytes": len(data), "sha256": _manifest_hash(data)} for name, data in sorted(files.items())},
        "verification_note": "Manifest hashes detect accidental changes after export; they are not a digital signature.",
    }
    files["manifest.json"] = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return {"path": str(dest), "files": len(files), "manifest": manifest}


def verify_case_package(package_path: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(package_path)
    with zipfile.ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Package contains duplicate paths")
        for name in names:
            item = PurePosixPath(name)
            if item.is_absolute() or ".." in item.parts or "\\" in name:
                raise ValueError(f"Unsafe package member: {name}")
        if "manifest.json" not in names or "case.json" not in names:
            raise ValueError("Not a PAV case package: manifest.json or case.json is missing")
        manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        declared = manifest.get("files", {})
        results = []
        for name, meta in declared.items():
            if name not in names:
                results.append({"path": name, "status": "missing"})
                continue
            data = archive.read(name)
            digest = _manifest_hash(data)
            status = "ok" if digest == meta.get("sha256") and len(data) == meta.get("size_bytes") else "hash_mismatch"
            results.append({"path": name, "status": status, "sha256": digest})
        undeclared = sorted(set(names) - set(declared) - {"manifest.json"})
        try:
            case_payload = json.loads(archive.read("case.json").decode("utf-8"))
            audit_status = verify_audit_chain(case_payload if isinstance(case_payload, dict) else {})
        except Exception as exc:
            audit_status = {"valid": False, "error": f"case.json cannot be read: {exc}"}
        valid = bool(results) and all(row["status"] == "ok" for row in results) and not undeclared and bool(audit_status.get("valid"))
        return {"valid": valid, "files": results, "undeclared": undeclared, "manifest": manifest, "audit_chain": audit_status}


def import_case_package(package_path: str | os.PathLike[str], destination_root: str | os.PathLike[str]) -> Path:
    verification = verify_case_package(package_path)
    if not verification.get("valid"):
        raise ValueError("Case package verification failed; nothing was extracted")
    root = Path(destination_root)
    root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(package_path, "r") as archive:
        raw_case = json.loads(archive.read("case.json").decode("utf-8"))
        payload = migrate_case(raw_case)
        safe_name = safe_filename(str(payload.get("name", "case")), 48).replace(" ", "_") or "case"
        short_id = re.sub(r"[^a-fA-F0-9]", "", str(payload.get("case_id", "")))[:8] or uuid.uuid4().hex[:8]
        destination = root / f"{safe_name}_{short_id}"
        index = 1
        while destination.exists():
            destination = root / f"{safe_name}_{short_id}_{index}"
            index += 1
        destination.mkdir(parents=True)
        evidence_root = destination / "case.evidence"
        for member in archive.namelist():
            if member in {"manifest.json", "case.json"}:
                continue
            relative = PurePosixPath(member)
            if not relative.parts or relative.parts[0] != "evidence":
                continue
            target = evidence_root.joinpath(*relative.parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst)
        case_path = destination / "case.json"
        save_case(payload, case_path)
        return case_path
