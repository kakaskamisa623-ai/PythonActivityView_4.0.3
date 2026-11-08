from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import os
import platform
import queue
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import tokenize
import zipfile
import gzip
import tkinter as tk
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Callable
from forensic_review import scan_local_review
from pav_features_250 import (
    compare_snapshots, make_process_tree_rows, verify_authenticode, file_sha256, normalize_imported_snapshot, deduplicate_events
)
from pav_v30 import (
    collect_audit_readiness, windows_compatibility, attach_analysis, build_scan_coverage,
    copy_original_artifacts, export_event_logs
)
from pav_browser import scan_browser_history, DOMAIN_CATEGORIES, normalize_domain, classify_domain, parse_domain_rule_input
from pav_runtime import analyze_python_java_processes, assess_suspiciousness
from pav_330 import (
    scan_artifact_inventory, import_evtx_file, inspect_file as inspect_static_file,
    parse_offline_amcache, parse_srum_database, parse_lnk_file, parse_jumplist_file,
    parse_prefetch_file,
    build_hourly_heatmap, summarize_independent_evidence,
)
from pav_v30 import correlate_events
from pav_plugins import PluginRegistry
from pav_encoding import read_text_compat, read_python_source_compat, decode_text_bytes
from pav_casebook import (
    new_case as create_case_payload, load_case as load_case_payload,
    migrate_case as migrate_case_payload, append_audit as append_case_audit,
    save_case as persist_case_payload, add_evidence as add_case_evidence,
    verify_case as verify_case_integrity, mark_evidence_excluded,
    export_case_package, import_case_package, save_case_as as relocate_case,
)
from pav_search import global_search as search_loaded_data, compare_file_reports
from pav_exports import build_pdf_report
from pav_diagnostics import collect_diagnostics

APP_NAME = "Просмотр активности Python"
APP_VERSION = "4.0.3"
CURRENT_USER = getpass.getuser()


class ScanCancelled(Exception):
    """Raised when the user explicitly cancels a running scan."""


# This utility only reads the current Windows user's known Python history
# locations. SQLite databases are copied to a temporary folder before opening,
# so SQLite cannot create or update -shm/-wal files beside the originals.

PYTHON_LAUNCH_RE = re.compile(
    r'(?i)(?:^|[\s;&|])(?:(?:"[^"]*[\\/])|(?:[^\s;&|" ]*[\\/]))?'
    r'(?:py|pythonw?|python\d+(?:\.\d+)*)(?:\.exe)?"?(?=\s|$)'
)
PYTHON_IMAGE_NAMES = {"python.exe", "pythonw.exe", "py.exe"}
PYTHON_TOOL_IMAGE_NAMES = PYTHON_IMAGE_NAMES | {
    "pip.exe", "pip3.exe", "ipython.exe", "jupyter.exe", "jupyter-lab.exe",
    "jupyter-notebook.exe", "uv.exe", "poetry.exe", "conda.exe", "mamba.exe",
    "pdm.exe", "hatch.exe",
}
SHELL_IMAGE_NAMES = {"cmd.exe", "powershell.exe", "pwsh.exe"}
PYTHON_ACTIVITY_RE = re.compile(
    r"(?i)(?<![\w.-])(?:pythonw?|python\d+(?:\.\d+)*|py|pip\d*|ipython|"
    r"jupyter(?:-lab|-notebook)?|conda|mamba|uv|poetry|pdm|hatch)(?![\w.-])"
)


def local_iso(value: Any) -> str:
    """Normalize a time value to local ISO text when possible."""
    if value is None or value == "":
        return ""
    try:
        if isinstance(value, (int, float)):
            # IPython stores session start times as ISO strings, but support
            # Unix timestamps in case a third-party database uses them.
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        else:
            text = str(value).strip()
            if not text:
                return ""
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                return dt.isoformat(sep=" ", timespec="seconds")
        return dt.astimezone().isoformat(sep=" ", timespec="seconds")
    except Exception:
        return str(value)


def time_sort_value(value: str) -> float:
    if not value:
        return -1.0
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        return -1.0


def file_metadata(path: Path) -> dict[str, Any]:
    st = path.stat()
    result = {
        "path": str(path),
        "size_bytes": st.st_size,
        "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(
            sep=" ", timespec="seconds"
        ),
        "created_or_changed_local": datetime.fromtimestamp(st.st_ctime).astimezone().isoformat(
            sep=" ", timespec="seconds"
        ),
    }
    # Hash history files for source identification. Avoid hashing very large files.
    if st.st_size <= 100 * 1024 * 1024:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result["sha256"] = digest.hexdigest()
    else:
        result["sha256"] = "skipped: file over 100 MiB"
    return result


def event(
    *,
    kind: str,
    description: str,
    source: str,
    timestamp: str = "",
    time_basis: str = "",
    command: str = "",
    user: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    date_part = ""
    time_part = ""
    if timestamp:
        try:
            parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            date_part = parsed.date().isoformat()
            time_part = parsed.strftime("%H:%M:%S")
        except Exception:
            # Preserve the source value in timestamp; do not invent a date/time.
            pass
    return {
        "timestamp": timestamp,
        "date": date_part,
        "time": time_part,
        "time_basis": time_basis,
        "kind": kind,
        "description": description,
        "command": command,
        "source": source,
        "user": user,
        "details": details or {},
    }


def candidate_roots() -> list[Path]:
    home = Path.home()
    roots = [
        home / ".ipython",
        home / ".jupyter",
        home / ".local" / "share" / "jupyter",
    ]
    appdata = os.environ.get("APPDATA")
    localappdata = os.environ.get("LOCALAPPDATA")
    if appdata:
        roots.extend([
            Path(appdata) / "jupyter",
            Path(appdata) / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine",
        ])
    if localappdata:
        roots.append(Path(localappdata) / "jupyter")
    roots.append(home / "Documents" / "PowerShell" / "PSReadLine")
    roots.append(home / "Documents" / "WindowsPowerShell" / "PSReadLine")
    # Stable de-duplication
    seen: set[str] = set()
    result = []
    for root in roots:
        key = str(root).casefold()
        if key not in seen:
            seen.add(key)
            result.append(root)
    return result


def find_history_files() -> tuple[list[Path], list[Path], list[Path]]:
    home = Path.home()
    history_files: set[Path] = set()
    sqlite_files: set[Path] = set()
    powershell_files: set[Path] = set()

    direct_python = home / ".python_history"
    if direct_python.is_file():
        history_files.add(direct_python)

    for root in candidate_roots():
        if not root.exists() or not root.is_dir():
            continue
        # Scan only known application data folders, with no traversal into
        # arbitrary project directories or other Windows user profiles.
        for current, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {
                "__pycache__", "node_modules", ".git", "venv", ".venv",
                "site-packages", "dist-packages"
            }]
            for filename in files:
                lower = filename.casefold()
                path = Path(current) / filename
                if lower == "history.sqlite":
                    sqlite_files.add(path)
                elif lower.startswith("history.sqlite-") or lower in {
                    "history.sqlite-wal", "history.sqlite-shm", "history.sqlite-journal"
                }:
                    # Sidecar files are recorded with the database, not parsed as DBs.
                    sqlite_files.add(path)
                elif lower in {".python_history", ".python_history.bak", ".python_history.old", ".python_history.backup"}:
                    history_files.add(path)
                elif lower.endswith("_history.txt") and "psreadline" in str(path.parent).casefold():
                    # PSReadLine names one history file per host (ConsoleHost,
                    # VS Code, custom IDE terminals, etc.).
                    powershell_files.add(path)

    return (
        sorted(history_files, key=lambda p: str(p).casefold()),
        sorted(sqlite_files, key=lambda p: str(p).casefold()),
        sorted(powershell_files, key=lambda p: str(p).casefold()),
    )


def find_powershell_transcripts() -> list[Path]:
    """Find conventional PowerShell transcript locations in this user profile."""
    home = Path.home()
    roots = [
        home / "Documents",
        home / "Documents" / "PowerShell_transcripts",
        home / "Documents" / "WindowsPowerShell" / "Transcripts",
        home / "PowerShell_transcripts",
    ]
    found: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        # Limit recursion to normal document areas and avoid huge/irrelevant trees.
        for current, dirs, files in os.walk(root):
            depth = len(Path(current).relative_to(root).parts)
            if depth >= 5:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d.casefold() not in {
                "node_modules", ".git", "venv", ".venv", "site-packages"
            }]
            for filename in files:
                lower = filename.casefold()
                if lower.endswith(".txt") and "transcript" in lower:
                    found.add(Path(current) / filename)
    return sorted(found, key=lambda p: str(p).casefold())



def find_pycharm_console_history_files() -> list[Path]:
    """Find persisted Python Console history across PyCharm versions."""
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    if appdata:
        roots.append(Path(appdata) / "JetBrains")
    # Legacy IDE releases used a product directory directly in the profile.
    roots.extend(Path.home().glob(".PyCharm*"))

    found: set[Path] = set()
    custom_history = os.environ.get("PAV_PYCHARM_HISTORY")
    if custom_history:
        custom_path = Path(os.path.expandvars(custom_history)).expanduser()
        if custom_path.is_file():
            found.add(custom_path)
    for root in roots:
        if not root.is_dir():
            continue
        if root.name.casefold() == "jetbrains":
            product_dirs = [
                item for item in root.iterdir()
                if item.is_dir() and "pycharm" in item.name.casefold()
            ]
        else:
            product_dirs = [root]
        for product_dir in product_dirs:
            candidates = [
                product_dir / "consoles" / ".history" / "py",
                product_dir / "consoles" / ".history" / "python",
                product_dir / "config" / "consoles" / ".history" / "py",
                product_dir / "config" / "consoles" / ".history" / "python",
            ]
            for candidate in candidates:
                if candidate.is_file():
                    found.add(candidate)
    return sorted(found, key=lambda item: str(item).casefold())


def read_pycharm_console_history(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read saved PyCharm Python Console input history, not editor keystrokes."""
    meta = file_metadata(path)
    text, _encoding = read_text_compat(path)

    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        rows.append(event(
            kind="PyCharm Python Console",
            description=f"История Python Console, строка #{line_no}",
            source=str(path),
            timestamp=meta.get("modified_local", ""),
            time_basis="Время изменения файла истории; отдельная временная метка команды обычно не хранится",
            command=line,
            user=CURRENT_USER,
            details={
                "line_number": line_no,
                "history_file": meta,
                "note": "Это введённые команды Python Console. Скрипты, запущенные кнопкой Run из редактора, не обязаны попадать в эту историю; для их запуска нужен журнал процессов Windows, если аудит был включён заранее.",
            },
        ))
    return rows, meta


def scan_current_cmd_buffer() -> tuple[list[dict[str, Any]], list[str]]:
    """Read the current console's Doskey buffer when started from that CMD."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return rows, warnings
    try:
        if not (sys.stdin and sys.stdout and sys.stdin.isatty() and sys.stdout.isatty()):
            return rows, warnings
        doskey = shutil.which("doskey.exe") or "doskey.exe"
        completed = subprocess.run(
            [doskey, "/history"], capture_output=True, text=False,
            timeout=4, check=False,
        )
        stdout_text, _stdout_encoding = decode_text_bytes(completed.stdout or b"", prefer_oem=True)
        if completed.returncode != 0 or not stdout_text.strip():
            return rows, warnings
        for line_no, line in enumerate(stdout_text.splitlines(), 1):
            candidate = line.strip()
            if not candidate or not PYTHON_ACTIVITY_RE.search(candidate):
                continue
            if "pythonactivityview.py" in candidate.casefold():
                continue
            rows.append(event(
                kind="CMD: текущая история Doskey",
                description=f"Команда из текущего окна CMD, позиция #{line_no}",
                source="CMD / Doskey current buffer",
                timestamp="",
                time_basis="Doskey не хранит точное время каждой команды",
                command=candidate,
                user=CURRENT_USER,
                details={
                    "buffer_position": line_no,
                    "note": "Снимок истории только того CMD-окна, из которого запущена эта версия программы. После закрытия окна эта история обычно исчезает.",
                },
            ))
    except Exception as exc:
        warnings.append(f"Не удалось прочитать текущую историю CMD: {exc}")
    return rows, warnings


def scan_live_python_processes(progress: Callable[[str], None]) -> tuple[list[dict[str, Any]], list[str]]:
    """Snapshot currently running Python and shell processes for this user."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return rows, warnings

    progress("Проверяю активные процессы Python, PyCharm, CMD и PowerShell…")
    ps_script = r"""
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$names = @('python.exe','pythonw.exe','py.exe','cmd.exe','powershell.exe','pwsh.exe','ipython.exe','jupyter.exe','pycharm64.exe','pycharm.exe')
$result = @(Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name.ToLowerInvariant() } | ForEach-Object {
  $owner = ''
  try { $owner = (Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop).User } catch {}
  [pscustomobject]@{ Name=$_.Name; ProcessId=$_.ProcessId; ParentProcessId=$_.ParentProcessId; ExecutablePath=$_.ExecutablePath; CommandLine=$_.CommandLine; Owner=$owner; CreationDate=$_.CreationDate }
})
ConvertTo-Json -InputObject $result -Depth 3 -Compress
"""
    executable = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not executable:
        return rows, warnings
    try:
        completed = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=False,
            timeout=12, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout_text, _stdout_encoding = decode_text_bytes(completed.stdout or b"")
        stderr_text, _stderr_encoding = decode_text_bytes(completed.stderr or b"")
        if completed.returncode != 0:
            warnings.append("Не удалось получить активные процессы: " + (stderr_text.strip() or stdout_text.strip())[:400])
            return rows, warnings
        raw = stdout_text.strip()
        if not raw:
            return rows, warnings
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            parsed = [parsed]
        for item in parsed if isinstance(parsed, list) else []:
            owner = str(item.get("Owner") or "")
            if owner and owner.casefold() != CURRENT_USER.casefold():
                continue
            name = str(item.get("Name") or "").casefold()
            command_line = str(item.get("CommandLine") or "")
            is_python = name.startswith("python") or name in {"py.exe", "ipython.exe", "jupyter.exe"}
            is_relevant_shell = (
                name in SHELL_IMAGE_NAMES
                and bool(PYTHON_ACTIVITY_RE.search(command_line))
                and "get-ciminstance win32_process" not in command_line.casefold()
            )
            is_pycharm = name in {"pycharm.exe", "pycharm64.exe"}
            if not (is_python or is_relevant_shell or is_pycharm):
                continue
            created = str(item.get("CreationDate") or "")
            timestamp = ""
            if created:
                try:
                    if created.startswith("/Date("):
                        epoch_ms = int(created[6:].split(")", 1)[0])
                        timestamp = datetime.fromtimestamp(epoch_ms / 1000).astimezone().isoformat(sep=" ", timespec="seconds")
                    elif "T" in created:
                        timestamp = datetime.fromisoformat(created.replace("Z", "+00:00")).astimezone().isoformat(sep=" ", timespec="seconds")
                    else:
                        timestamp = datetime.strptime(created[:14], "%Y%m%d%H%M%S").astimezone().isoformat(sep=" ", timespec="seconds")
                except Exception:
                    pass
            rows.append(event(
                kind="Активный процесс Python / IDE / терминала",
                description=f"{name} • PID {item.get('ProcessId', '')}",
                source="Windows CIM / Win32_Process",
                timestamp=timestamp,
                time_basis="Время создания активного процесса из WMI" if timestamp else "Время создания процесса недоступно",
                command=command_line,
                user=owner or CURRENT_USER,
                details={
                    "process_id": item.get("ProcessId"),
                    "parent_process_id": item.get("ParentProcessId"),
                    "executable_path": item.get("ExecutablePath"),
                    "creation_date_raw": created,
                    "note": "Это снимок процессов, которые работают сейчас, а не архив завершённых команд.",
                },
            ))
    except subprocess.TimeoutExpired:
        warnings.append("Проверка активных процессов превысила 12 секунд.")
    except Exception as exc:
        warnings.append(f"Ошибка проверки активных процессов: {exc}")
    return rows, warnings


def read_text_history(path: Path, backup: bool = False) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    meta = file_metadata(path)
    try:
        text, _encoding = read_text_compat(path)
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            rows.append(event(
                kind="Python history backup" if backup else "Python REPL history",
                description=f"Сохранённая строка истории #{line_no}",
                source=str(path),
                timestamp=meta.get("modified_local", ""),
                time_basis="Время изменения файла истории; не точное время ввода этой команды",
                command=line,
                details={"line_number": line_no, "file": meta},
            ))
    except Exception as exc:
        raise RuntimeError(f"Не удалось прочитать {path}: {exc}") from exc
    return rows, meta


def sqlite_copy_and_read(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Read IPython/Jupyter SQLite history from temporary copies only."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta = file_metadata(path)
    db_name = path.name
    if db_name != "history.sqlite":
        return rows, meta, warnings

    with tempfile.TemporaryDirectory(prefix="python_activity_view_") as temp_dir:
        temp_root = Path(temp_dir)
        copied_db = temp_root / "history.sqlite"
        shutil.copy2(path, copied_db)
        # Copy the SQLite sidecar files so committed WAL transactions can be
        # visible to SQLite. Originals are never opened in read-write mode.
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            if sidecar.is_file():
                try:
                    shutil.copy2(sidecar, Path(str(copied_db) + suffix))
                    meta[suffix.lstrip("-") + "_present"] = True
                    meta[suffix.lstrip("-") + "_size_bytes"] = sidecar.stat().st_size
                except Exception as exc:
                    warnings.append(f"Не удалось скопировать {sidecar}: {exc}")

        connection = None
        try:
            connection = sqlite3.connect(str(copied_db), timeout=5)
            connection.row_factory = sqlite3.Row
            table_names = [
                r[0] for r in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]
            meta["tables"] = table_names
            # These values help assess whether SQLite may have reusable/free
            # pages. A non-zero freelist is only a forensic clue, not proof that
            # deleted commands remain recoverable.
            for pragma_name in ("page_count", "freelist_count", "journal_mode", "secure_delete"):
                try:
                    pragma_value = connection.execute(f"PRAGMA {pragma_name}").fetchone()
                    meta[pragma_name] = pragma_value[0] if pragma_value else None
                except sqlite3.Error:
                    meta[pragma_name] = None
            session_starts: dict[int, str] = {}
            if "sessions" in table_names:
                for row in connection.execute("SELECT * FROM sessions").fetchall():
                    d = dict(row)
                    try:
                        sid = int(d.get("session"))
                    except (TypeError, ValueError):
                        continue
                    session_starts[sid] = local_iso(d.get("start"))
                    rows.append(event(
                        kind="IPython session",
                        description=f"Сессия IPython #{sid}",
                        source=str(path),
                        timestamp=session_starts[sid],
                        time_basis="Начало сессии из таблицы sessions",
                        details={
                            "session": sid,
                            "start": local_iso(d.get("start")),
                            "end": local_iso(d.get("end")),
                            "num_commands": d.get("num_cmds"),
                            "remark": d.get("remark"),
                        },
                    ))

            output_map: dict[tuple[int, int], Any] = {}
            for output_table in ("output_history", "output"):
                if output_table not in table_names:
                    continue
                try:
                    for row in connection.execute(f'SELECT * FROM "{output_table}"').fetchall():
                        d = dict(row)
                        if "session" in d and "line" in d:
                            try:
                                output_map[(int(d["session"]), int(d["line"]))] = d.get("output", d)
                            except (TypeError, ValueError):
                                pass
                except sqlite3.Error as exc:
                    warnings.append(f"Таблица {output_table}: {exc}")

            if "history" in table_names:
                table_columns = [
                    r["name"] for r in connection.execute(
                        'PRAGMA table_info("history")'
                    ).fetchall()
                ]
                meta["history_columns"] = table_columns
                db_rows = connection.execute('SELECT * FROM "history" ORDER BY session, line').fetchall()
                for db_row in db_rows:
                    d = dict(db_row)
                    src = d.get("source_raw") or d.get("source") or ""
                    try:
                        sid = int(d.get("session"))
                    except (TypeError, ValueError):
                        sid = -1
                    try:
                        line_no = int(d.get("line"))
                    except (TypeError, ValueError):
                        line_no = -1
                    session_time = session_starts.get(sid, "")
                    output = output_map.get((sid, line_no))
                    details = {
                        "session": sid if sid >= 0 else d.get("session"),
                        "execution_number": line_no if line_no >= 0 else d.get("line"),
                        "source_field": "source_raw" if d.get("source_raw") else "source",
                        "database": str(path),
                        "output_available": output is not None,
                    }
                    if output is not None:
                        details["stored_output"] = output
                    rows.append(event(
                        kind="IPython / Jupyter history",
                        description=f"Сессия {sid}, выполнение #{line_no}",
                        source=str(path),
                        timestamp=session_time,
                        time_basis="Начало сессии (не точное время команды)" if session_time else "Время команды не записано",
                        command=str(src),
                        details=details,
                    ))
            else:
                warnings.append(f"В {path} нет таблицы history")

            # Keep useful session metadata in the source record.
            meta["session_count"] = len(session_starts)
            meta["history_row_count"] = sum(
                1 for item in rows if item.get("kind") == "IPython / Jupyter history"
            )
        except sqlite3.Error as exc:
            warnings.append(f"SQLite {path}: {exc}")
        finally:
            if connection is not None:
                connection.close()

    return rows, meta, warnings


def read_powershell_python_invocations(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    meta = file_metadata(path)
    try:
        lines = read_text_compat(path)[0].splitlines()
        for line_no, line in enumerate(lines, 1):
            if PYTHON_ACTIVITY_RE.search(line):
                rows.append(event(
                    kind="PowerShell: команда Python",
                    description=f"Команда, связанная с Python, из PSReadLine, строка #{line_no}",
                    source=str(path),
                    timestamp=meta.get("modified_local", ""),
                    time_basis="Время изменения файла PSReadLine; точное время строки не записано",
                    command=line,
                    details={"line_number": line_no, "history_file": meta},
                    user=CURRENT_USER,
                ))
    except Exception as exc:
        raise RuntimeError(f"Не удалось прочитать {path}: {exc}") from exc
    return rows, meta


def _parse_transcript_start(text: str) -> str:
    match = re.search(r"(?im)^\s*Start time:\s*(.+?)\s*$", text)
    if not match:
        return ""
    raw = match.group(1).strip()
    for parser in (
        lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")),
        lambda s: datetime.strptime(s, "%m/%d/%Y %I:%M:%S %p"),
        lambda s: datetime.strptime(s, "%d.%m.%Y %H:%M:%S"),
    ):
        try:
            parsed = parser(raw)
            if parsed.tzinfo is not None:
                parsed = parsed.astimezone()
            return parsed.isoformat(sep=" ", timespec="seconds")
        except Exception:
            continue
    return ""


def read_powershell_transcript(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    meta = file_metadata(path)
    text = read_text_compat(path)[0]
    transcript_start = _parse_transcript_start(text)
    prompt_re = re.compile(r"^\s*PS\s+.*?>\s?(.*)$", re.IGNORECASE)
    for line_no, line in enumerate(text.splitlines(), 1):
        prompt = prompt_re.match(line)
        # Commands in a transcript are normally prefixed by a PowerShell prompt.
        # Do not mistake arbitrary command output mentioning Python for input.
        if not prompt:
            continue
        candidate = prompt.group(1)
        if not candidate or not PYTHON_ACTIVITY_RE.search(candidate):
            continue
        rows.append(event(
            kind="PowerShell transcript: Python",
            description=f"Запись PowerShell transcript, строка #{line_no}",
            source=str(path),
            # Transcript start is only a session-level reference, not an exact
            # timestamp for this individual command.
            timestamp=transcript_start,
            time_basis="Начало transcript-сессии; точное время этой команды не записано" if transcript_start else "Время отдельной команды не записано",
            command=candidate,
            user=CURRENT_USER,
            details={
                "line_number": line_no,
                "transcript_start": transcript_start,
                "transcript_file": meta,
                "raw_line": line,
            },
        ))
    return rows, meta


def read_captured_cmd_history(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read Python-related lines explicitly exported from an open CMD session."""
    rows: list[dict[str, Any]] = []
    meta = file_metadata(path)
    text = read_text_compat(path, prefer_oem=True)[0]
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or not PYTHON_ACTIVITY_RE.search(line):
            continue
        rows.append(event(
            kind="CMD: команда Python (Doskey)",
            description=f"Команда из вручную сохранённой истории CMD, строка #{line_no}",
            source=str(path),
            timestamp=meta.get("modified_local", ""),
            time_basis="Время изменения файла экспорта; не точное время команды",
            command=line.strip(),
            user=CURRENT_USER,
            details={
                "line_number": line_no,
                "history_file": meta,
                "note": "Команда сохранена вручную из открытого окна CMD через doskey /history.",
            },
        ))
    return rows, meta


def scan_prefetch() -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return rows, warnings
    prefetch = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
    if not prefetch.is_dir():
        return rows, warnings
    try:
        for path in prefetch.iterdir():
            name = path.name.upper()
            if path.is_file() and name.endswith(".PF") and (
                name.startswith("PYTHON") or name.startswith("PY.EXE-")
            ):
                st = path.stat()
                modified = datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(
                    sep=" ", timespec="seconds"
                )
                rows.append(event(
                    kind="Windows Prefetch: Python",
                    description=f"Найден Prefetch-файл {path.name}",
                    source=str(path),
                    timestamp=modified,
                    time_basis="Время изменения Prefetch-файла (не точное время запуска)",
                    details={
                        "file_size_bytes": st.st_size,
                        "filesystem_modified": modified,
                        "note": "Наличие Prefetch-файла — косвенный след запуска; mtime не равен времени запуска.",
                    },
                ))
    except Exception as exc:
        warnings.append(f"Не удалось прочитать Prefetch: {exc}")
    return rows, warnings


def xml_child_text(parent: ET.Element, wanted: str) -> str:
    for child in parent.iter():
        if child.tag.rsplit("}", 1)[-1] == wanted:
            return child.text or ""
    return ""


def scan_windows_process_events(progress: Callable[[str], None]) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        warnings.append("Журнал безопасности Windows доступен только в Windows.")
        return rows, warnings

    progress("Читаю события 4688: запуски Python-инструментов из CMD/PowerShell…")
    command = [
        "wevtutil", "qe", "Security",
        "/q:*[System[(EventID=4688)]]",
        "/f:xml", "/rd:true", "/c:5000",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=False, timeout=18, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout_text, output_encoding = decode_text_bytes(completed.stdout or b"", prefer_oem=True)
        stderr_text, _stderr_encoding = decode_text_bytes(completed.stderr or b"", prefer_oem=True)
        if completed.returncode != 0:
            error = stderr_text.strip() or stdout_text.strip() or f"wevtutil exit code {completed.returncode}"
            warnings.append(
                "Журнал Security недоступен или аудит запуска процессов не включён: " + error[:700]
            )
            return rows, warnings
        try:
            root = ET.fromstring("<Events>" + stdout_text + "</Events>")
        except ET.ParseError as exc:
            warnings.append(f"Не удалось разобрать XML журнала Security: {exc}")
            return rows, warnings

        current = CURRENT_USER.casefold()
        for item in root:
            system = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "System"), None)
            data_node = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "EventData"), None)
            if system is None or data_node is None:
                continue
            time_node = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "TimeCreated"), None)
            raw_time = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
            data: dict[str, str] = {}
            for node in data_node:
                if node.tag.rsplit("}", 1)[-1] == "Data":
                    data[node.attrib.get("Name", "")] = node.text or ""
            image_path = data.get("NewProcessName", "")
            image_name = image_path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
            subject = data.get("SubjectUserName", "")
            if subject.casefold() != current:
                continue
            command_line = data.get("CommandLine", "")
            parent_path = data.get("ParentProcessName", "")
            parent_name = parent_path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
            is_python_tool = image_name in PYTHON_TOOL_IMAGE_NAMES
            is_java_runtime = image_name in {"java.exe", "javaw.exe"}
            is_shell_invocation = (
                image_name in SHELL_IMAGE_NAMES
                and bool(re.search(r"(?i)(pythonw?|python\d*(?:\.\d+)*|javaw?)\.exe", command_line))
            )
            if not (is_python_tool or is_java_runtime or is_shell_invocation):
                continue
            timestamp = local_iso(raw_time)
            rows.append(event(
                kind=(
                    "CMD/PowerShell: запуск runtime (Event 4688)" if is_shell_invocation
                    else ("Запуск Java-процесса (Event 4688)" if is_java_runtime else f"Запуск Python-инструмента из {parent_name or 'неизвестного процесса'}")
                ),
                description=f"{image_name} (Event ID 4688)",
                source="Windows Event Log / Security",
                timestamp=timestamp,
                time_basis="Время события Windows",
                command=command_line,
                user=subject,
                details={
                    "image_path": image_path,
                    "command_line": command_line,
                    "parent_process": parent_path,
                    "parent_process_name": parent_name,
                    "subject_domain": data.get("SubjectDomainName", ""),
                    "subject_logon_id": data.get("SubjectLogonId", ""),
                    "process_id": data.get("NewProcessId", ""),
                    "NewProcessId": data.get("NewProcessId", ""),
                    "ParentProcessId": data.get("ProcessId", ""),
                    "NewProcessName": image_path,
                    "process_family": "Java" if is_java_runtime else ("Python" if is_python_tool else "runtime_command"),
                    "event_id": 4688,
                    "note": "Событие отражает запуск процесса. Командная строка может отсутствовать, если аудит командной строки не был включён заранее.",
                },
            ))
    except FileNotFoundError:
        warnings.append("Команда wevtutil не найдена; чтение журнала Windows недоступно.")
    except subprocess.TimeoutExpired:
        warnings.append("Чтение журнала Windows превысило лимит времени (18 секунд).")
    except Exception as exc:
        warnings.append(f"Ошибка чтения журнала Windows: {exc}")
    return rows, warnings


def scan_powershell_operational_events(progress: Callable[[str], None]) -> tuple[list[dict[str, Any]], list[str]]:
    """Read available PowerShell script-block/module logging (4103/4104)."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return rows, warnings
    log_name = "Microsoft-Windows-PowerShell/Operational"
    progress("Проверяю журнал PowerShell 4103/4104 (если ведётся)…")
    current_sid = ""
    try:
        who = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        parsed = next(csv.reader([who.stdout.strip()]), [])
        if len(parsed) >= 2:
            current_sid = parsed[-1].strip()
    except Exception:
        current_sid = ""
    if not current_sid:
        warnings.append("Не удалось определить SID текущего пользователя; события PowerShell не прочитаны, чтобы не смешивать записи разных пользователей.")
        return rows, warnings
    command = [
        "wevtutil", "qe", log_name,
        "/q:*[System[(EventID=4103 or EventID=4104)]]",
        "/f:xml", "/rd:true", "/c:2500",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=False, timeout=18, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout_text, output_encoding = decode_text_bytes(completed.stdout or b"", prefer_oem=True)
        stderr_text, _stderr_encoding = decode_text_bytes(completed.stderr or b"", prefer_oem=True)
        if completed.returncode != 0:
            # This log often exists but has no matching entries; avoid a noisy
            # error if the provider/log is simply unavailable.
            detail = (stderr_text.strip() or stdout_text.strip())[:500]
            warnings.append(f"Журнал PowerShell Operational недоступен или пуст: {detail}")
            return rows, warnings
        try:
            root = ET.fromstring("<Events>" + stdout_text + "</Events>")
        except ET.ParseError as exc:
            warnings.append(f"Не удалось разобрать журнал PowerShell: {exc}")
            return rows, warnings

        for item in root:
            system = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "System"), None)
            data_node = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "EventData"), None)
            if system is None:
                continue
            security_node = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "Security"), None)
            event_sid = security_node.attrib.get("UserID", "") if security_node is not None else ""
            if event_sid.casefold() != current_sid.casefold():
                continue
            event_id_node = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "EventID"), None)
            event_id = event_id_node.text if event_id_node is not None else ""
            time_node = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "TimeCreated"), None)
            raw_time = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
            data: dict[str, str] = {}
            if data_node is not None:
                for node in data_node:
                    if node.tag.rsplit("}", 1)[-1] == "Data":
                        data[node.attrib.get("Name", f"field_{len(data)}")] = node.text or ""
            message = "\n".join([f"{k}: {v}" for k, v in data.items()])
            if not PYTHON_ACTIVITY_RE.search(message):
                continue
            rows.append(event(
                kind=f"PowerShell Operational: событие {event_id}",
                description="PowerShell script block / module logging",
                source=f"Windows Event Log / {log_name}",
                timestamp=local_iso(raw_time),
                time_basis="Время события Windows",
                command=message,
                user=CURRENT_USER,
                details={
                    "event_id": event_id,
                    "event_data": data,
                    "note": "Содержимое доступно только если соответствующее журналирование PowerShell было включено в момент выполнения.",
                },
            ))
    except FileNotFoundError:
        warnings.append("wevtutil не найден; чтение журнала PowerShell невозможно.")
    except subprocess.TimeoutExpired:
        warnings.append("Чтение журнала PowerShell превысило лимит времени (18 секунд).")
    except Exception as exc:
        warnings.append(f"Ошибка чтения журнала PowerShell: {exc}")
    return rows, warnings



# ---------------------------------------------------------------------------
# Deep discovery: current user's folders, IDE caches/logs, shell histories,
# archived history copies and additional SQLite history databases.
# This is deliberately read-only and does not inspect source-code files.
# ---------------------------------------------------------------------------

DEEP_SKIP_DIRS = {
    "$recycle.bin", "system volume information", "node_modules", ".git", ".cache",
    ".hg", ".svn", "__pycache__", "site-packages", "dist-packages",
    "venv", ".venv", ".tox", "build", "dist", "cache", "caches", "pip-cache", "npm-cache",
    "gpuCache".casefold(), "code cache", "shadercache", "dawncache",
    "crashpad", "wheels", ".mypy_cache", ".pytest_cache",
}
DEEP_PATH_HINTS = {
    "jetbrains", "pycharm", "idea", "spyder", "thonny", "ipython",
    "jupyter", "vscode", "visual studio code", "python", "powershell",
    "psreadline", "terminal", "windows terminal", "cmd", "anaconda",
    "miniconda", "conda", "vscode-insiders", "microsoft.windowsTerminal".casefold(),
}
TEXT_SUFFIXES = {".txt", ".log", ".json", ".jsonl", ".xml", ".ini", ".cfg", ".dat"}
SQLITE_SUFFIXES = {".sqlite", ".sqlite3", ".db", ".db3"}
ARCHIVE_SUFFIXES = {".zip", ".gz"}
HISTORY_BASENAMES = {
    ".python_history", ".bash_history", ".zsh_history", ".fish_history",
    "consolehost_history.txt", "psreadline_history.txt", "cmd_history.txt",
    "cmd_history_python.txt", "history", "history.txt", "history.log",
    "history.json", "history.jsonl", "history.sqlite", "history.db",
    "pyhistory.txt", "python_history.txt", "spyder.history",
}
IDE_LOG_NAMES = {
    "idea.log", "idea.log.1", "idea.log.2", "pycharm.log", "ptyhost.log",
    "window.log", "main.log", "extensionhost.log", "renderer.log",
    "terminal.log", "python.log", "spyder.log", "thonny.log",
}
MAX_DEEP_CANDIDATES = 12000
MAX_TEXT_FILE_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 40 * 1024 * 1024


def _deep_roots() -> list[Path]:
    home = Path.home()
    roots = [home]
    for env_name in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "TEMP"):
        value = os.environ.get(env_name)
        if value:
            roots.append(Path(value).expanduser())
    # Common redirected/legacy configuration locations.
    roots.extend([
        home / ".config", home / ".cache", home / ".local" / "share",
        home / "Documents", home / "Desktop", home / "Downloads",
    ])

    # Keep only the highest existing roots. On Windows APPDATA, LOCALAPPDATA,
    # TEMP, Documents, Desktop and Downloads are usually children of HOME;
    # scanning them again would duplicate work and make the UI appear stuck.
    unique: list[Path] = []
    seen: set[str] = set()
    resolved_roots: list[Path] = []
    for root in roots:
        try:
            resolved_path = root.resolve()
            key = str(resolved_path).casefold()
        except Exception:
            resolved_path = root
            key = str(root).casefold()
        if key in seen or not resolved_path.exists() or not resolved_path.is_dir():
            continue
        seen.add(key)
        try:
            is_nested = any(parent == resolved_path or parent in resolved_path.parents for parent in resolved_roots)
        except Exception:
            is_nested = False
        if not is_nested:
            unique.append(resolved_path)
            resolved_roots.append(resolved_path)
    return unique


def _path_has_deep_hint(path: Path) -> bool:
    try:
        parts = {part.casefold() for part in path.parts}
        joined = str(path).casefold()
        return bool(parts & DEEP_PATH_HINTS) or any(hint in joined for hint in DEEP_PATH_HINTS)
    except Exception:
        return False


def _is_deep_candidate(path: Path) -> bool:
    name = path.name.casefold()
    suffix = path.suffix.casefold()
    lower_path = str(path).casefold()
    known_history = name in HISTORY_BASENAMES or "history" in name or "transcript" in name
    known_ide_log = name in IDE_LOG_NAMES
    app_log = suffix in TEXT_SUFFIXES and _path_has_deep_hint(path) and (
        "log" in name or "console" in name or "terminal" in name or "pty" in name
    )
    app_db = suffix in SQLITE_SUFFIXES and (
        "history" in name or _path_has_deep_hint(path)
    )
    archive = suffix in ARCHIVE_SUFFIXES and (
        known_history or _path_has_deep_hint(path) or "backup" in name
    )
    # Include shell history in WSL/Git Bash and history files with nonstandard names.
    shell_history = name.endswith(("_history", "_history.txt", ".history"))
    return known_history or known_ide_log or app_log or app_db or archive or shell_history


def discover_deep_artifacts(progress: Callable[[Any], None]) -> list[Path]:
    found: set[Path] = set()
    visited_dirs = 0
    files_seen = 0
    errors = 0
    roots = _deep_roots()
    for root in roots:
        progress({
            "message": f"Поиск файлов истории и логов в {root}",
            "phase": "discovery",
            "current_path": str(root),
            "directories_checked": visited_dirs,
            "files_seen": files_seen,
            "candidate_files": len(found),
        })
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            visited_dirs += 1
            dirs[:] = [d for d in dirs if d.casefold() not in DEEP_SKIP_DIRS]
            # Avoid following junctions/symlinks into unrelated or remote trees.
            safe_dirs = []
            for dirname in dirs:
                candidate_dir = Path(current) / dirname
                try:
                    if candidate_dir.is_symlink():
                        continue
                except OSError:
                    continue
                safe_dirs.append(dirname)
            dirs[:] = safe_dirs
            for filename in files:
                files_seen += 1
                path = Path(current) / filename
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    if _is_deep_candidate(path):
                        found.add(path)
                        if len(found) >= MAX_DEEP_CANDIDATES:
                            progress({
                                "message": f"Достигнут лимит кандидатов: {MAX_DEEP_CANDIDATES}",
                                "phase": "discovery",
                                "current_path": str(path),
                                "directories_checked": visited_dirs,
                                "files_seen": files_seen,
                                "candidate_files": len(found),
                            })
                            return sorted(found, key=lambda x: str(x).casefold())
                except (OSError, PermissionError):
                    errors += 1
                if files_seen % 300 == 0:
                    progress({
                        "message": f"Ищу подходящие файлы… сейчас: {path}",
                        "phase": "discovery",
                        "current_path": str(path),
                        "directories_checked": visited_dirs,
                        "files_seen": files_seen,
                        "candidate_files": len(found),
                    })
            if visited_dirs % 100 == 0:
                progress({
                    "message": f"Просмотрено папок: {visited_dirs}",
                    "phase": "discovery",
                    "current_path": str(current),
                    "directories_checked": visited_dirs,
                    "files_seen": files_seen,
                    "candidate_files": len(found),
                })
    progress({
        "message": f"Поиск файлов завершён: найдено кандидатов {len(found)}; недоступных объектов {errors}",
        "phase": "discovery_done",
        "current_path": str(roots[-1]) if roots else "",
        "directories_checked": visited_dirs,
        "files_seen": files_seen,
        "candidate_files": len(found),
    })
    return sorted(found, key=lambda x: str(x).casefold())


def _extract_timestamp_from_log_line(line: str) -> str:
    patterns = [
        r"(?<!\d)(20\d{2}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)",
        r"(?<!\d)(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})",
    ]
    for pattern in patterns:
        match = re.search(pattern, line)
        if match:
            raw = match.group(1).replace(",", ".")
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return parsed.astimezone().isoformat(sep=" ", timespec="seconds") if parsed.tzinfo else parsed.isoformat(sep=" ", timespec="seconds")
            except ValueError:
                continue
    # PowerShell history supports `# <unix timestamp>` records in bash-like forms.
    match = re.match(r"^:\s*(\d{9,})\s*:\s*\d+\s*;", line)
    if match:
        try:
            return datetime.fromtimestamp(int(match.group(1))).astimezone().isoformat(sep=" ", timespec="seconds")
        except (ValueError, OSError, OverflowError):
            pass
    return ""


def _is_python_command_line(line: str) -> bool:
    if PYTHON_ACTIVITY_RE.search(line):
        return True
    # Shell commands that invoke a .py script by file association or launcher.
    return bool(re.search(r"(?i)(?:^|[\\/\s\"'])[^\s\"']+\.py(?:\s|$|\")", line))


def read_deep_text_artifact(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Extract command-like lines only from identified history/log artefacts."""
    meta = file_metadata(path)
    size = path.stat().st_size
    if size > MAX_TEXT_FILE_BYTES:
        raise RuntimeError(f"Пропущен большой текстовый файл ({size:,} байт): {path}")
    raw = path.read_bytes()
    text, detected_encoding = decode_text_bytes(raw)
    meta["text_encoding"] = detected_encoding
    lines = text.splitlines()
    name = path.name.casefold()
    full = str(path).casefold()
    is_ide_history = any(tag in full for tag in ("pycharm", "jetbrains", "spyder", "thonny", "ipython", "jupyter")) and ("history" in name or ".history" in name or name in {"py", "python"})
    is_shell_history = name in HISTORY_BASENAMES or name.endswith(("_history", "_history.txt", ".history"))
    is_log = path.suffix.casefold() in {".log", ".json", ".jsonl", ".xml"} or name in IDE_LOG_NAMES
    rows: list[dict[str, Any]] = []
    pending_bash_time = ""
    fallback_time = meta.get("modified_local", "")
    for line_no, original in enumerate(lines, 1):
        line = original.strip()
        if not line:
            continue
        # Bash history timestamp is a comment line immediately before a command.
        if line.startswith("#") and line[1:].strip().isdigit():
            try:
                pending_bash_time = datetime.fromtimestamp(int(line[1:].strip())).astimezone().isoformat(sep=" ", timespec="seconds")
            except (ValueError, OSError, OverflowError):
                pending_bash_time = ""
            continue
        if is_log and not _is_python_command_line(line):
            continue
        if is_shell_history and not is_ide_history and not _is_python_command_line(line):
            pending_bash_time = ""
            continue
        if not (is_ide_history or is_shell_history or is_log) and not _is_python_command_line(line):
            continue

        timestamp = _extract_timestamp_from_log_line(line) or pending_bash_time
        pending_bash_time = ""
        if not timestamp and fallback_time and (is_shell_history or is_ide_history):
            time_basis = "Время изменения файла; отдельное время команды в этой истории не хранится"
        elif timestamp:
            time_basis = "Временная метка извлечена из самой записи/формата истории"
        else:
            time_basis = "Время отдельной команды в этом источнике не обнаружено"

        # Keep logs distinct from commands actually entered in a shell.
        if is_log:
            kind = "След Python в логе IDE/терминала"
            description = f"Строка лога #{line_no}; возможный запуск/активность Python"
            command_value = original[:4000]
        elif is_ide_history:
            kind = "История Python IDE (глубокий поиск)"
            description = f"История IDE, строка #{line_no}"
            command_value = original
        else:
            kind = "История shell (глубокий поиск)"
            description = f"Команда shell, строка #{line_no}"
            # zsh extended history stores metadata before the command.
            command_value = re.sub(r"^:\s*\d+\s*:\s*\d+\s*;", "", original).strip()
        rows.append(event(
            kind=kind,
            description=description,
            source=str(path),
            timestamp=timestamp or fallback_time if (is_ide_history or is_shell_history) else timestamp,
            time_basis=time_basis,
            command=command_value,
            user=CURRENT_USER,
            details={
                "line_number": line_no,
                "artifact_size_bytes": size,
                "file_modified": fallback_time,
                "classification": "history_entry" if not is_log else "log_evidence_not_proof_of_typed_command",
                "note": "Глубокий поиск по артефактам текущего профиля. Строка из лога может быть контекстом запуска, а не буквальным вводом пользователя.",
            },
        ))
    return rows, meta


def scan_generic_sqlite_history(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Inspect history-like SQLite databases via a temporary copy."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta = file_metadata(path)
    if path.stat().st_size > 250 * 1024 * 1024:
        return rows, meta, [f"Пропущена большая SQLite-база (>250 MiB): {path}"]
    with tempfile.TemporaryDirectory(prefix="pav_deep_sqlite_") as tmp:
        copied = Path(tmp) / path.name
        shutil.copy2(path, copied)
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(path) + suffix)
            if sidecar.is_file():
                try:
                    shutil.copy2(sidecar, Path(str(copied) + suffix))
                except OSError as exc:
                    warnings.append(f"Не удалось скопировать sidecar {sidecar}: {exc}")
        con = None
        try:
            con = sqlite3.connect(str(copied), timeout=4)
            con.row_factory = sqlite3.Row
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            meta["tables"] = tables
            meta["freelist_count"] = con.execute("PRAGMA freelist_count").fetchone()[0]
            for table in tables:
                safe_table = table.replace('"', '""')
                cols = [r[1] for r in con.execute(f'PRAGMA table_info("{safe_table}")').fetchall()]
                lower_cols = {c.casefold(): c for c in cols}
                command_col = next((lower_cols[c] for c in ("source_raw", "source", "command", "input", "code", "cmd", "statement") if c in lower_cols), None)
                if not command_col:
                    continue
                # Avoid bulk-reading arbitrary unrelated app tables.
                if not ("history" in table.casefold() or _path_has_deep_hint(path)):
                    continue
                timestamp_col = next((lower_cols[c] for c in ("timestamp", "time", "created_at", "created", "date", "ts") if c in lower_cols), None)
                session_col = lower_cols.get("session")
                line_col = lower_cols.get("line")
                selected = [command_col]
                for col in (timestamp_col, session_col, line_col):
                    if col and col not in selected:
                        selected.append(col)
                query = f'SELECT {", ".join(chr(34)+c.replace(chr(34), chr(34)*2)+chr(34) for c in selected)} FROM "{safe_table}" LIMIT 20000'
                try:
                    db_rows = con.execute(query).fetchall()
                except sqlite3.Error as exc:
                    warnings.append(f"{path} / {table}: {exc}")
                    continue
                meta.setdefault("history_tables", []).append({"table": table, "columns": cols, "rows_seen": len(db_rows)})
                for idx, db_row in enumerate(db_rows, 1):
                    d = dict(db_row)
                    command_text = str(d.get(command_col) or "")
                    if not command_text.strip():
                        continue
                    # For command history tables, accept free-form Python input;
                    # for generic app DBs require a Python-related marker.
                    if "history" not in table.casefold() and not _is_python_command_line(command_text):
                        continue
                    ts_raw = d.get(timestamp_col) if timestamp_col else None
                    timestamp = local_iso(ts_raw) if ts_raw is not None else ""
                    rows.append(event(
                        kind="SQLite history (глубокий поиск)",
                        description=f"{table} • запись #{idx}",
                        source=str(path),
                        timestamp=timestamp or meta.get("modified_local", ""),
                        time_basis="Временная метка из столбца БД" if timestamp else "Время изменения БД; точное время записи не обнаружено",
                        command=command_text,
                        user=CURRENT_USER,
                        details={"table": table, "row_number": idx, "session": d.get(session_col) if session_col else None, "line": d.get(line_col) if line_col else None, "timestamp_raw": ts_raw, "classification": "history_table_entry"},
                    ))
            if not tables:
                warnings.append(f"В SQLite-базе нет таблиц: {path}")
        except sqlite3.Error as exc:
            warnings.append(f"Не удалось прочитать SQLite-кандидат {path}: {exc}")
        finally:
            if con is not None:
                con.close()
    return rows, meta, warnings



def _normalize_residual_fragment(value: str) -> str:
    text = value.strip(" \t\r\n\x00\ufeff\"'`;,|")
    # SQLite record boundaries can leave a one-byte serial-type/header fragment
    # attached to the front of an otherwise readable command.
    for token in ("print(", "import ", "from ", "python", "pip ", "jupyter", "ipython", "def ", "class "):
        position = text.casefold().find(token.casefold())
        if 1 <= position <= 3 and text[:position].isalnum():
            text = text[position:]
            break
    return text


def _looks_like_command_residue(value: str) -> bool:
    text = _normalize_residual_fragment(value)
    if len(text) < 4 or len(text) > 1500:
        return False
    if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in text):
        return False
    if _is_python_command_line(text):
        # Require an invocation-like shape rather than a stray mention of Python.
        return bool(re.search(r"(?i)(?:^|[\\/\s\"'])(?:pythonw?|python\d*(?:\.\d+)?|py|pip\d*|ipython|jupyter|conda|uv|poetry)(?:\.exe)?(?:\s|$)|\.py(?:\s|$|\")", text))
    code_prefix = re.match(
        r"(?is)^\s*(?:>>>\s*)?(?:import\s+|from\s+\S+\s+import\s+|print\s*\(|def\s+\w+|class\s+\w+|async\s+def\s+|await\s+|for\s+\w+\s+in\s+|while\s+.+:|if\s+.+:|with\s+.+:|try\s*:|raise\s+|assert\s+|del\s+|[A-Za-z_]\w*\s*=(?!=)|[A-Za-z_]\w*\s*\([^\n]*\)\s*$)",
        text,
    )
    return bool(code_prefix)


def _extract_residual_strings(data: bytes) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    # SQLite TEXT payloads are commonly UTF-8/ASCII.
    for match in re.finditer(rb"[\x20-\x7e]{4,1500}", data):
        value, _encoding = decode_text_bytes(match.group(0))
        value = value.strip()
        if value and value not in seen:
            seen.add(value)
            found.append(value)
    # Also inspect UTF-16LE text cells, which appear in some third-party DBs.
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,1500}", data):
        try:
            value = match.group(0).decode("utf-16le", errors="strict").strip()
        except UnicodeDecodeError:
            continue
        if value and value not in seen:
            seen.add(value)
            found.append(value)
    return found


def _sqlite_freelist_pages(data: bytes) -> tuple[int, list[int]]:
    """Return SQLite page size and free-list leaf page numbers from the DB header."""
    if not data.startswith(b"SQLite format 3\x00") or len(data) < 100:
        return 0, []
    page_size = int.from_bytes(data[16:18], "big")
    if page_size == 1:
        page_size = 65536
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        return 0, []
    trunk = int.from_bytes(data[32:36], "big")
    remaining = int.from_bytes(data[36:40], "big")
    leaves: list[int] = []
    seen_trunks: set[int] = set()
    while trunk and trunk not in seen_trunks and len(seen_trunks) < 10000 and remaining > 0:
        seen_trunks.add(trunk)
        offset = (trunk - 1) * page_size
        if offset < 0 or offset + 8 > len(data):
            break
        next_trunk = int.from_bytes(data[offset:offset + 4], "big")
        leaf_count = int.from_bytes(data[offset + 4:offset + 8], "big")
        max_entries = max(0, (page_size - 8) // 4)
        leaf_count = min(leaf_count, max_entries, remaining)
        for i in range(leaf_count):
            pos = offset + 8 + i * 4
            page_no = int.from_bytes(data[pos:pos + 4], "big")
            if 0 < page_no <= (len(data) // page_size):
                leaves.append(page_no)
        remaining -= leaf_count + 1
        trunk = next_trunk
    return page_size, leaves


def scan_sqlite_residual_commands(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Heuristically find command-like text fragments in SQLite free pages/WAL.

    Results are intentionally labelled as unconfirmed remnants: raw fragments
    have no reliable row boundary, user identity or execution timestamp.
    """
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if path.stat().st_size > 250 * 1024 * 1024:
        return rows, [f"Пропущен residual-анализ крупной SQLite-базы (>250 MiB): {path}"]
    try:
        main_data = path.read_bytes()
    except OSError as exc:
        return rows, [f"Не удалось прочитать байты SQLite {path}: {exc}"]
    page_size, free_pages = _sqlite_freelist_pages(main_data)
    targets: list[tuple[str, bytes, str]] = []
    for page_no in free_pages:
        start = (page_no - 1) * page_size
        targets.append((f"SQLite free page {page_no}", main_data[start:start + page_size], "free_page"))
    wal = Path(str(path) + "-wal")
    if wal.is_file() and wal.stat().st_size <= 100 * 1024 * 1024:
        try:
            targets.append(("SQLite WAL residual", wal.read_bytes(), "wal_fragment"))
        except OSError as exc:
            warnings.append(f"Не удалось прочитать WAL {wal}: {exc}")
    seen_commands: set[str] = set()
    for label, blob, residual_type in targets:
        for fragment in _extract_residual_strings(blob):
            normalized = _normalize_residual_fragment(fragment)
            if not _looks_like_command_residue(normalized):
                continue
            # Avoid strings already visible in the regular command history table.
            if normalized in seen_commands:
                continue
            seen_commands.add(normalized)
            rows.append(event(
                kind="Возможный остаток команды SQLite (неподтверждённый)",
                description=f"Текстовый фрагмент найден: {label}",
                source=str(path) if residual_type == "free_page" else str(wal),
                timestamp="",
                time_basis="В остаточных байтах SQLite нет достоверной даты/времени команды",
                command=normalized,
                user=CURRENT_USER,
                details={
                    "residual_type": residual_type,
                    "sqlite_page": label if residual_type == "free_page" else None,
                    "database": str(path),
                    "classification": "heuristic_unconfirmed_residual",
                    "confidence": "low",
                    "note": "Это эвристически найденный текстовый фрагмент в свободной странице/WAL, а не восстановленная SQLite-запись. Он может быть неполным, дублированным или ложным совпадением; время выполнения и принадлежность пользователю не установлены.",
                },
            ))
            if len(rows) >= 300:
                warnings.append(f"Residual-анализ {path} ограничен 300 фрагментами.")
                return rows, warnings
    return rows, warnings

def scan_zip_history_archive(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta = file_metadata(path)
    total = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            members = archive.infolist()[:2000]
            for member in members:
                name = Path(member.filename).name.casefold()
                if member.is_dir() or member.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    continue
                if not ("history" in name or "transcript" in name or name in HISTORY_BASENAMES):
                    continue
                total += member.file_size
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    warnings.append(f"Остановлено чтение архива после лимита распаковки 40 MiB: {path}")
                    break
                if Path(name).suffix.casefold() not in TEXT_SUFFIXES and name not in HISTORY_BASENAMES:
                    continue
                try:
                    content = archive.read(member)
                    decoded, _archive_encoding = decode_text_bytes(content)
                    archive_time = datetime(*member.date_time).astimezone().isoformat(sep=" ", timespec="seconds")
                    for line_no, line in enumerate(decoded.splitlines(), 1):
                        candidate = line.strip()
                        if not candidate or not _is_python_command_line(candidate):
                            continue
                        rows.append(event(
                            kind="История из ZIP-архива",
                            description=f"{member.filename} • строка #{line_no}",
                            source=f"{path}!{member.filename}",
                            timestamp=archive_time,
                            time_basis="Время элемента архива (не обязательно время выполнения команды)",
                            command=candidate,
                            user=CURRENT_USER,
                            details={"archive": str(path), "member": member.filename, "line_number": line_no, "note": "Команда найдена в архивной копии истории; время элемента архива не является временем ввода."},
                        ))
                except Exception as exc:
                    warnings.append(f"Не удалось прочитать {member.filename} из {path}: {exc}")
    except (zipfile.BadZipFile, OSError) as exc:
        warnings.append(f"Архив не прочитан {path}: {exc}")
    meta["archive_records_found"] = len(rows)
    return rows, meta, warnings


def scan_deep_artifacts(progress: Callable[[Any], None], use_cache: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    events_found: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    artifacts = discover_deep_artifacts(progress)
    progress({
        "message": f"Анализирую найденные файлы-кандидаты: {len(artifacts)}",
        "phase": "deep_analysis",
        "artifacts_done": 0,
        "artifacts_total": len(artifacts),
        "deep_records_found": 0,
    })
    cache_root = app_data_dir() / "deep_cache"
    if use_cache:
        try:
            cache_root.mkdir(parents=True, exist_ok=True)
        except OSError:
            use_cache = False
    for index, path in enumerate(artifacts, 1):
        progress({
            "message": f"Анализ глубокого поиска: {index}/{len(artifacts)} — {path.name}",
            "phase": "deep_analysis",
            "current_path": str(path),
            "artifacts_done": index - 1,
            "artifacts_total": len(artifacts),
            "deep_records_found": len(events_found),
        })
        cache_file = None
        cache_signature = ""
        if use_cache:
            try:
                st_cache = path.stat()
                cache_signature = f"{st_cache.st_size}:{st_cache.st_mtime_ns}"
                cache_key = hashlib.sha256(str(path.resolve()).casefold().encode("utf-8", errors="replace")).hexdigest()
                cache_file = cache_root / f"{cache_key}.json"
                if cache_file.is_file():
                    cached = json.loads(cache_file.read_text(encoding="utf-8"))
                    if cached.get("cache_version") == 1 and cached.get("signature") == cache_signature:
                        events_found.extend(cached.get("events", []))
                        sources.extend(cached.get("sources", []))
                        warnings.extend(cached.get("warnings", []))
                        errors.extend(cached.get("errors", []))
                        progress({
                            "message": f"Из кэша: {index}/{len(artifacts)} — {path.name}",
                            "phase": "deep_analysis", "current_path": str(path),
                            "artifacts_done": index, "artifacts_total": len(artifacts),
                            "deep_records_found": len(events_found),
                        })
                        continue
            except Exception:
                cache_file = None
        before_events, before_sources, before_warnings, before_errors = (len(events_found), len(sources), len(warnings), len(errors))
        try:
            suffix = path.suffix.casefold()
            name = path.name.casefold()
            if name.endswith(("-wal", "-shm", "-journal")):
                meta = file_metadata(path)
                sources.append({"type": "deep_sqlite_sidecar", **meta})
            elif suffix in SQLITE_SUFFIXES or name == "history.sqlite":
                found, meta, notes = scan_generic_sqlite_history(path)
                events_found.extend(found)
                residuals, residual_warnings = scan_sqlite_residual_commands(path)
                events_found.extend(residuals)
                sources.append({"type": "deep_sqlite", **meta, "records": len(found), "unconfirmed_residual_fragments": len(residuals)})
                warnings.extend(notes)
                warnings.extend(residual_warnings)
            elif suffix == ".zip":
                found, meta, notes = scan_zip_history_archive(path)
                events_found.extend(found)
                sources.append({"type": "deep_zip_archive", **meta, "records": len(found)})
                warnings.extend(notes)
            elif suffix == ".gz":
                # Gzip support is limited to reasonably small history-like files.
                if path.stat().st_size <= MAX_ARCHIVE_MEMBER_BYTES:
                    with gzip.open(path, "rb") as stream:
                        compressed_text = stream.read(MAX_ARCHIVE_MEMBER_BYTES + 1)
                    decoded_text, _gzip_encoding = decode_text_bytes(compressed_text)
                    lines = decoded_text.splitlines()
                    extracted = []
                    for line_no, line in enumerate(lines, 1):
                        if _is_python_command_line(line):
                            extracted.append(event(
                                kind="История из GZ-архива",
                                description=f"Строка #{line_no}", source=str(path),
                                timestamp="", time_basis="Временная метка в gzip-файле не обнаружена",
                                command=line, user=CURRENT_USER,
                                details={"line_number": line_no, "classification": "archived_history_candidate"},
                            ))
                    events_found.extend(extracted)
                    meta = file_metadata(path)
                    sources.append({"type": "deep_gzip", **meta, "records": len(extracted)})
            elif (
                suffix in (TEXT_SUFFIXES | {".bak", ".old", ".backup", ".py"})
                or name in IDE_LOG_NAMES
                or (not suffix and ("history" in name or "transcript" in name))
            ):
                found, meta = read_deep_text_artifact(path)
                events_found.extend(found)
                sources.append({"type": "deep_text_artifact", **meta, "records": len(found)})
        except PermissionError as exc:
            warnings.append(f"Нет доступа к {path}: {exc}")
        except Exception as exc:
            errors.append(f"Глубокий поиск {path}: {exc}")
        if use_cache and cache_file is not None and cache_signature:
            try:
                cache_payload = {
                    "cache_version": 1,
                    "signature": cache_signature,
                    "events": (events_found[before_events:]),
                    "sources": (sources[before_sources:]),
                    "warnings": (warnings[before_warnings:]),
                    "errors": (errors[before_errors:]),
                }
                cache_file.write_text(json.dumps(cache_payload, ensure_ascii=False, separators=(",", ":"), default=str), encoding="utf-8")
            except Exception:
                pass
        progress({
            "message": f"Обработано файлов: {index}/{len(artifacts)}",
            "phase": "deep_analysis",
            "current_path": str(path),
            "artifacts_done": index,
            "artifacts_total": len(artifacts),
            "deep_records_found": len(events_found),
        })
    if use_cache:
        try:
            cached_files = sorted(cache_root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            for stale in cached_files[1500:]:
                try:
                    stale.unlink()
                except OSError:
                    pass
        except OSError:
            pass
    return events_found, sources, warnings, errors


def _windows_current_sid() -> str:
    if os.name != "nt":
        return ""
    try:
        completed = subprocess.run(
            ["whoami", "/user", "/fo", "csv", "/nh"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=5, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        parsed = next(csv.reader([completed.stdout.strip()]), [])
        return parsed[-1].strip() if len(parsed) >= 2 else ""
    except Exception:
        return ""


def _windows_fixed_drives() -> list[Path]:
    if os.name != "nt":
        return []
    drives: list[Path] = []
    try:
        import ctypes
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for index in range(26):
            if not (mask & (1 << index)):
                continue
            drive = f"{chr(65 + index)}:\\"
            # DRIVE_FIXED = 3; skip removable, network and optical drives.
            if ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(drive)) == 3:
                drives.append(Path(drive))
    except Exception:
        system_drive = os.environ.get("SystemDrive", "C:")
        drives.append(Path(system_drive + "\\"))
    return drives


def _filetime_to_local(raw: int) -> str:
    try:
        # Windows FILETIME ticks are 100-ns intervals since 1601-01-01 UTC.
        seconds = (raw - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone().isoformat(sep=" ", timespec="seconds")
    except (ValueError, OSError, OverflowError):
        return ""


def scan_windows_recycle_bin(progress: Callable[[str], None]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Read matching deleted history artifacts from the current SID's Recycle Bin; never restore them."""
    rows: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return rows, sources, warnings
    sid = _windows_current_sid()
    if not sid:
        warnings.append("Не удалось определить SID для проверки Корзины Windows.")
        return rows, sources, warnings
    progress("Проверяю Корзину Windows на удалённые файлы истории Python/терминалов…")
    for drive in _windows_fixed_drives():
        sid_dir = drive / "$Recycle.Bin" / sid
        if not sid_dir.is_dir():
            continue
        try:
            for meta_file in sid_dir.glob("$I*"):
                try:
                    data = meta_file.read_bytes()
                    if len(data) < 24:
                        continue
                    version = int.from_bytes(data[0:8], "little")
                    deletion_time = _filetime_to_local(int.from_bytes(data[16:24], "little"))
                    original = ""
                    if version == 1:
                        original = data[24:].decode("utf-16le", errors="replace").split("\x00", 1)[0]
                    elif version == 2 and len(data) >= 28:
                        chars = int.from_bytes(data[24:28], "little")
                        original = data[28:28 + chars * 2].decode("utf-16le", errors="replace")
                    lower_original = original.casefold()
                    relevant = any(token in lower_original for token in (
                        "history", "transcript", "pycharm", "jetbrains", "ipython",
                        "jupyter", "spyder", "thonny", "powershell", "cmd_history",
                    ))
                    if not relevant:
                        continue
                    payload = meta_file.with_name("$R" + meta_file.name[2:])
                    source_info = {
                        "metadata_file": str(meta_file),
                        "deleted_payload": str(payload),
                        "original_path": original,
                        "deleted_at": deletion_time,
                        "metadata_version": version,
                        "payload_exists": payload.is_file(),
                    }
                    sources.append({"type": "recycle_bin_deleted_artifact", **source_info})
                    if not payload.is_file() or payload.stat().st_size > MAX_TEXT_FILE_BYTES:
                        rows.append(event(
                            kind="Удалённый артефакт (Корзина Windows)",
                            description="Найдены метаданные удалённого файла истории; содержимое недоступно или слишком большое",
                            source=str(meta_file), timestamp=deletion_time,
                            time_basis="Время удаления из метаданных Корзины Windows" if deletion_time else "Время удаления неизвестно",
                            user=CURRENT_USER,
                            details=source_info,
                        ))
                        continue
                    try:
                        raw = payload.read_bytes()
                        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                            content = raw.decode("utf-16", errors="replace")
                        else:
                            content = raw.decode("utf-8-sig", errors="replace")
                        original_is_ide_history = any(t in lower_original for t in ("pycharm", "jetbrains", "spyder", "thonny", "ipython", "jupyter")) and "history" in lower_original
                        recovered_count = 0
                        for line_no, line in enumerate(content.splitlines(), 1):
                            if not line.strip() or (not original_is_ide_history and not _is_python_command_line(line)):
                                continue
                            rows.append(event(
                                kind="Удалённая история (Корзина Windows)",
                                description=f"Содержимое удалённого файла • строка #{line_no}",
                                source=str(payload), timestamp=deletion_time,
                                time_basis="Время удаления файла из метаданных Корзины; не время ввода команды",
                                command=line,
                                user=CURRENT_USER,
                                details={**source_info, "line_number": line_no, "classification": "recovered_deleted_file_content", "note": "Строка прочитана из файла, который всё ещё находится в Корзине; запись не восстановлена на диск."},
                            ))
                            recovered_count += 1
                        if recovered_count == 0:
                            rows.append(event(
                                kind="Удалённый артефакт (Корзина Windows)",
                                description="Файл истории найден, но подходящих команд в его содержимом не обнаружено",
                                source=str(payload), timestamp=deletion_time,
                                time_basis="Время удаления из метаданных Корзины Windows" if deletion_time else "Время удаления неизвестно",
                                user=CURRENT_USER, details=source_info,
                            ))
                    except (OSError, UnicodeError) as exc:
                        warnings.append(f"Не удалось прочитать удалённый файл {payload}: {exc}")
                except (OSError, ValueError) as exc:
                    warnings.append(f"Не удалось разобрать метаданные {meta_file}: {exc}")
        except (OSError, PermissionError) as exc:
            warnings.append(f"Нет доступа к Корзине {sid_dir}: {exc}")
    return rows, sources, warnings


def scan_windows_run_mru() -> tuple[list[dict[str, Any]], list[str]]:
    """Read only the current user's Run-dialog MRU entries that reference Python."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return rows, warnings
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            values: dict[str, str] = {}
            index = 0
            while True:
                try:
                    name, value, _kind = winreg.EnumValue(key, index)
                    values[name] = str(value)
                    index += 1
                except OSError:
                    break
            order = values.get("MRUList", "")
            names = list(order) + [n for n in values if len(n) == 1 and n not in order]
            for rank, name in enumerate(names, 1):
                command_line = values.get(name, "").replace("\\1", "")
                if not command_line or not _is_python_command_line(command_line):
                    continue
                rows.append(event(
                    kind="Windows Run MRU: команда Python",
                    description=f"Запись Run dialog • позиция MRU {rank}",
                    source=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                    timestamp="",
                    time_basis="Реестр RunMRU хранит порядок MRU, но не точную дату/время ввода",
                    command=command_line,
                    user=CURRENT_USER,
                    details={"mru_value": name, "mru_position": rank, "note": "Команда запускалась через диалог Win+R или связанный механизм Run; это не журнал команд CMD."},
                ))
    except FileNotFoundError:
        return rows, warnings
    except PermissionError as exc:
        warnings.append(f"Нет доступа к RunMRU текущего пользователя: {exc}")
    except Exception as exc:
        warnings.append(f"Не удалось прочитать RunMRU: {exc}")
    return rows, warnings


PYTHON_SOURCE_EXTENSIONS = {".py", ".pyw", ".pyi", ".ipynb"}
PYTHON_SOURCE_SKIP_DIRS = {
    ".git", ".hg", ".svn", ".idea", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".venv", "venv", "env", "virtualenv",
    "__pycache__", "node_modules", "site-packages", "dist-packages",
    "build", "dist", "target", "coverage", ".cache", "cache",
    "packages", "bower_components", "$recycle.bin", "system volume information",
    "windows", "program files", "program files (x86)", "appdata",
}
MAX_SOURCE_FILES = 10000
MAX_SOURCE_SCAN_FILES = 60000
MAX_SOURCE_DEPTH = 9
MAX_SOURCE_PREVIEW_BYTES = 3 * 1024 * 1024


def _decode_file_uri(value: str) -> str:
    value = str(value or "").strip()
    if value.startswith("file://"):
        value = value[7:]
        if value.startswith("/") and re.match(r"^/[A-Za-z]:", value):
            value = value[1:]
        value = value.replace("/", os.sep)
    return value.replace("%20", " ")


def discover_python_project_roots() -> list[Path]:
    """Find likely user project folders without walking the whole drive."""
    home = Path.home()
    candidates: list[Path] = []
    common_names = (
        "PycharmProjects", "PyCharmProjects", "Projects", "projects", "project",
        "Code", "code", "Dev", "dev", "Workspace", "Workspaces", "workspace",
        "GitHub", "src", "Source", "Documents", "Desktop", "Downloads", "OneDrive",
    )
    for name in common_names:
        candidates.append(home / name)
    # Custom project paths are added below from IDE recent-project metadata.
    # Avoid crawling every folder in the profile: that can include large media
    # libraries and cloud-sync roots and would make the quick scan unnecessarily slow.

    appdata = os.environ.get("APPDATA")
    localappdata = os.environ.get("LOCALAPPDATA")

    # PyCharm's recentProjects.xml reveals project roots that may have custom names.
    if appdata:
        jetbrains = Path(appdata) / "JetBrains"
        if jetbrains.is_dir():
            try:
                for ide_dir in jetbrains.iterdir():
                    if not ide_dir.is_dir() or "pycharm" not in ide_dir.name.casefold():
                        continue
                    for xml_path in (
                        ide_dir / "options" / "recentProjects.xml",
                        ide_dir / "options" / "recentProjectDirectories.xml",
                    ):
                        if not xml_path.is_file() or xml_path.stat().st_size > 5 * 1024 * 1024:
                            continue
                        try:
                            tree = ET.parse(xml_path)
                            for node in tree.iter():
                                raw = node.attrib.get("value", "")
                                if not raw:
                                    continue
                                raw = raw.replace("$USER_HOME$", str(home))
                                raw = os.path.expandvars(raw)
                                raw = _decode_file_uri(raw)
                                p = Path(raw).expanduser()
                                if p.is_dir():
                                    candidates.append(p)
                        except (ET.ParseError, OSError, ValueError):
                            continue
            except OSError:
                pass

    # VS Code workspaceStorage entries point to folders or .code-workspace files.
    if appdata:
        storage = Path(appdata) / "Code" / "User" / "workspaceStorage"
        if storage.is_dir():
            try:
                for entry in storage.iterdir():
                    workspace_json = entry / "workspace.json"
                    if not workspace_json.is_file() or workspace_json.stat().st_size > 256 * 1024:
                        continue
                    try:
                        payload = json.loads(workspace_json.read_text(encoding="utf-8", errors="replace"))
                        raw = payload.get("folder") or payload.get("workspace", {}).get("configPath")
                        if raw:
                            p = Path(_decode_file_uri(os.path.expandvars(raw))).expanduser()
                            if p.suffix.casefold() == ".code-workspace":
                                if p.is_file() and p.stat().st_size <= 2 * 1024 * 1024:
                                    ws = json.loads(p.read_text(encoding="utf-8", errors="replace"))
                                    for folder in ws.get("folders", []):
                                        fpath = folder.get("path") or folder.get("uri")
                                        if fpath:
                                            target = Path(_decode_file_uri(os.path.expandvars(fpath))).expanduser()
                                            if not target.is_absolute():
                                                target = p.parent / target
                                            candidates.append(target)
                            elif p.is_dir():
                                candidates.append(p)
                    except Exception:
                        continue
            except OSError:
                pass

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.resolve()
            key = str(resolved).casefold()
            if key in seen or not resolved.is_dir():
                continue
            seen.add(key)
            unique.append(resolved)
        except (OSError, RuntimeError):
            continue
    # Known and recently-opened roots first; deterministic order aids repeat scans.
    return unique


def scan_python_source_catalog(progress: Callable[[Any], None]) -> tuple[list[dict[str, Any]], list[str]]:
    """Index Python source/notebook files from the current user's likely project roots."""
    found: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    roots = discover_python_project_roots()
    dirs_seen = 0
    files_seen = 0
    limit_hit = False
    progress({
        "phase": "file_catalog",
        "message": f"Ищу Python-файлы в {len(roots)} папках проектов…",
        "directories_checked": 0,
        "files_seen": 0,
        "python_files_found": 0,
        "current_path": "",
    })

    for root in roots:
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            folder, depth = stack.pop()
            dirs_seen += 1
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                name = entry.name.casefold()
                                if depth < MAX_SOURCE_DEPTH and name not in PYTHON_SOURCE_SKIP_DIRS and not name.startswith("."):
                                    stack.append((Path(entry.path), depth + 1))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            files_seen += 1
                            if files_seen > MAX_SOURCE_SCAN_FILES:
                                limit_hit = True
                                break
                            suffix = Path(entry.name).suffix.casefold()
                            if suffix not in PYTHON_SOURCE_EXTENSIONS:
                                continue
                            try:
                                st = entry.stat(follow_symlinks=False)
                            except OSError:
                                continue
                            # Retain large files in the index but mark their preview limitation.
                            p = Path(entry.path)
                            key = str(p.resolve()).casefold()
                            found[key] = {
                                "path": str(p),
                                "name": p.name,
                                "extension": suffix,
                                "size_bytes": st.st_size,
                                "size_display": f"{st.st_size / 1024:.1f} КБ" if st.st_size < 1024 * 1024 else f"{st.st_size / (1024 * 1024):.2f} МБ",
                                "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"),
                                "root": str(root),
                                "preview_available": st.st_size <= MAX_SOURCE_PREVIEW_BYTES,
                            }
                            if len(found) >= MAX_SOURCE_FILES:
                                limit_hit = True
                                break
                        except (OSError, PermissionError):
                            continue
                if files_seen % 500 < 40 or dirs_seen % 100 == 0:
                    progress({
                        "phase": "file_catalog",
                        "message": f"Ищу исходники Python… просмотрено {files_seen:,} файлов".replace(",", " "),
                        "directories_checked": dirs_seen,
                        "files_seen": files_seen,
                        "python_files_found": len(found),
                        "current_path": str(folder),
                    })
                if limit_hit:
                    break
            except (OSError, PermissionError):
                continue
        if limit_hit:
            break

    if limit_hit:
        warnings.append(
            f"Каталог Python-файлов ограничен: просмотрено до {MAX_SOURCE_SCAN_FILES:,} файлов "
            f"или найдено {MAX_SOURCE_FILES:,} исходников. Для дополнительного проекта добавьте его в одну из папок проектов или откройте через IDE и повторите поиск."
        )
    result = sorted(found.values(), key=lambda x: (x["modified_local"], x["path"].casefold()), reverse=True)
    progress({
        "phase": "file_catalog_done",
        "message": f"Каталог Python-файлов готов: найдено {len(result)} файлов",
        "directories_checked": dirs_seen,
        "files_seen": files_seen,
        "python_files_found": len(result),
        "current_path": "",
    })
    return result, warnings


def read_python_source_file(path: Path) -> str:
    """Read Python source or extract code/output text from a Jupyter notebook."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        return f"Не удалось получить сведения о файле:\n{exc}"
    if size > MAX_SOURCE_PREVIEW_BYTES:
        return (
            f"Предпросмотр отключён: файл слишком большой ({size / (1024 * 1024):.2f} МБ).\n"
            f"Лимит предпросмотра: {MAX_SOURCE_PREVIEW_BYTES / (1024 * 1024):.0f} МБ.\n\n{path}"
        )
    if path.suffix.casefold() == ".ipynb":
        try:
            notebook = json.loads(path.read_text(encoding="utf-8"))
            output: list[str] = [f"# Jupyter Notebook: {path.name}", ""]
            cells = notebook.get("cells", [])
            for index, cell in enumerate(cells, 1):
                if cell.get("cell_type") != "code":
                    continue
                source = cell.get("source", "")
                if isinstance(source, list):
                    source = "".join(source)
                output.append(f"# ===== ЯЧЕЙКА {index} | execution_count={cell.get('execution_count')} =====")
                output.append(str(source).rstrip())
                outputs = cell.get("outputs", [])
                for cell_output in outputs:
                    text_parts = []
                    if cell_output.get("text"):
                        value = cell_output.get("text")
                        text_parts.append("".join(value) if isinstance(value, list) else str(value))
                    data = cell_output.get("data", {})
                    plain = data.get("text/plain") if isinstance(data, dict) else None
                    if plain:
                        text_parts.append("".join(plain) if isinstance(plain, list) else str(plain))
                    if text_parts:
                        output.append("# --- ВЫВОД ЯЧЕЙКИ ---")
                        output.append("\n".join(text_parts)[:5000])
                output.append("")
            return "\n".join(output) if len(output) > 2 else "# В ноутбуке не найдено ячеек с Python-кодом."
        except Exception as exc:
            return f"Не удалось разобрать Jupyter Notebook:\n{exc}"
    try:
        with tokenize.open(str(path)) as stream:
            return stream.read(MAX_SOURCE_PREVIEW_BYTES + 1)
    except Exception:
        try:
            return read_text_compat(path)[0]
        except Exception as exc:
            return f"Не удалось прочитать файл:\n{exc}"


def scan_all(include_windows_events: bool, deep_scan: bool, progress: Callable[[Any], None], cancel_event: threading.Event | None = None, use_cache: bool = True, domain_rules: dict[str, str] | None = None, include_browser_history: bool = False, trusted_paths: list[str] | None = None) -> dict[str, Any]:
    all_events: list[dict[str, Any]] = []
    source_records: list[dict[str, Any]] = []
    warnings: list[str] = []
    errors: list[str] = []
    progress_state: dict[str, Any] = {
        "phase": "initializing",
        "message": "Подготавливаю список источников…",
        "directories_checked": 0,
        "files_seen": 0,
        "candidate_files": 0,
        "artifacts_done": 0,
        "artifacts_total": 0,
        "sources_checked": 0,
        "records_found": 0,
        "deep_records_found": 0,
        "current_path": "",
    }
    external_progress = progress

    def check_cancelled() -> None:
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelled("Сканирование отменено пользователем")

    def report_progress(message: Any) -> None:
        check_cancelled()
        if isinstance(message, dict):
            progress_state.update(message)
        else:
            progress_state["message"] = str(message)
            progress_state["phase"] = progress_state.get("phase") or "scan"
            # Count source operations as they are entered; raw file/directory
            # traversal counters are supplied by the deep discovery stage.
            if any(token in str(message).casefold() for token in ("читаю", "проверяю")):
                progress_state["sources_checked"] = int(progress_state.get("sources_checked", 0)) + 1
        progress_state["records_found"] = len(all_events) + int(progress_state.get("deep_records_found", 0) or 0)
        external_progress(dict(progress_state))

    progress = report_progress
    progress("Проверяю текущую готовность аудита Windows и совместимость среды…")
    audit_readiness = collect_audit_readiness(progress=progress)
    compatibility = audit_readiness.get("environment", {})
    if include_browser_history:
        progress("Проверяю доступные истории браузеров Chrome/Edge/Firefox/Opera/Brave и Chromium…")
        browser_events, browser_sources, browser_warnings = scan_browser_history(
            progress, domain_rules=domain_rules, cancel_check=check_cancelled
        )
        all_events.extend(browser_events)
        source_records.extend(browser_sources)
        warnings.extend(browser_warnings)
    else:
        source_records.append({"type": "browser_history", "status": "disabled", "records": 0,
                              "note": "Пользователь не включил чтение истории браузеров. URL и загрузки не анализировались."})
    progress("Ищу истории PyCharm/Python, CMD/PowerShell и журналы Windows…")
    text_files, sqlite_paths, powershell_files = find_history_files()

    for path in text_files:
        try:
            progress(f"Читаю {path}…")
            found, meta = read_text_history(path, backup=(path.name.casefold() != ".python_history"))
            all_events.extend(found)
            source_records.append({"type": "text_history", **meta, "records": len(found)})
        except Exception as exc:
            errors.append(str(exc))

    # Only process primary DB files; WAL/SHM are copied alongside the DB.
    primary_dbs = [p for p in sqlite_paths if p.name.casefold() == "history.sqlite"]
    sidecars = [p for p in sqlite_paths if p.name.casefold() != "history.sqlite"]
    for path in primary_dbs:
        try:
            progress(f"Читаю SQLite-историю {path} (через временную копию)…")
            found, meta, db_warnings = sqlite_copy_and_read(path)
            all_events.extend(found)
            source_records.append({"type": "sqlite_history", **meta, "records": len(found)})
            warnings.extend(db_warnings)
            if meta.get("freelist_count"):
                all_events.append(event(
                    kind="SQLite forensic clue",
                    description=f"В базе есть свободные страницы: {meta.get('freelist_count')}",
                    source=str(path),
                    time_basis="Не является временной меткой события",
                    details={
                        "freelist_count": meta.get("freelist_count"),
                        "page_count": meta.get("page_count"),
                        "secure_delete": meta.get("secure_delete"),
                        "note": "Свободные страницы могут содержать остатки старых данных, но это не доказывает наличие удалённых команд. Эта версия показывает индикатор, но не выдаёт найденные байты за восстановленную историю.",
                    },
                ))
        except Exception as exc:
            errors.append(f"SQLite {path}: {exc}")

    for path in sidecars:
        try:
            meta = file_metadata(path)
            side_type = "SQLite WAL" if path.name.casefold().endswith("-wal") else "SQLite sidecar"
            all_events.append(event(
                kind=side_type,
                description=f"Найден вспомогательный файл SQLite: {path.name}",
                source=str(path),
                timestamp=meta.get("modified_local", ""),
                time_basis="Время изменения файла; не время выполнения команды",
                details={
                    "size_bytes": meta.get("size_bytes"),
                    "note": "WAL может содержать ещё не перенесённые в основной файл транзакции. Отдельные удалённые команды по одному факту наличия WAL не подтверждаются.",
                },
            ))
            source_records.append({"type": side_type, **meta})
        except Exception as exc:
            errors.append(str(exc))

    for path in powershell_files:
        try:
            progress(f"Проверяю команды запуска Python в {path}…")
            found, meta = read_powershell_python_invocations(path)
            all_events.extend(found)
            source_records.append({"type": "powershell_history", **meta, "records": len(found)})
        except Exception as exc:
            errors.append(str(exc))

    pycharm_history_paths = find_pycharm_console_history_files()
    for path in pycharm_history_paths:
        try:
            progress(f"Читаю историю Python Console PyCharm: {path}…")
            found, meta = read_pycharm_console_history(path)
            all_events.extend(found)
            source_records.append({"type": "pycharm_console_history", **meta, "records": len(found)})
        except Exception as exc:
            errors.append(f"PyCharm history {path}: {exc}")
    if not pycharm_history_paths:
        appdata = os.environ.get("APPDATA", "")
        jetbrains_root = Path(appdata) / "JetBrains" if appdata else None
        legacy_dirs = list(Path.home().glob(".PyCharm*"))
        if (jetbrains_root and jetbrains_root.is_dir() and any("pycharm" in d.name.casefold() for d in jetbrains_root.iterdir() if d.is_dir())) or legacy_dirs:
            warnings.append(
                "Найдена папка PyCharm, но файл истории Python Console по стандартному пути не найден. "
                "Проверь Help → Diagnostic Tools → Special Files and Folders. "
                "При необходимости задай переменную PAV_PYCHARM_HISTORY с полным путём к файлу consoles\\.history\\py."
            )

    for path in find_powershell_transcripts():
        try:
            progress(f"Читаю PowerShell transcript {path}…")
            found, meta = read_powershell_transcript(path)
            all_events.extend(found)
            source_records.append({"type": "powershell_transcript", **meta, "records": len(found)})
        except Exception as exc:
            errors.append(f"Transcript {path}: {exc}")

    cmd_history_paths = [
        Path.home() / "cmd_history_python.txt",
        Path.home() / "cmd_history.txt",
        Path.home() / "Documents" / "cmd_history_python.txt",
    ]
    for path in cmd_history_paths:
        if not path.is_file():
            continue
        try:
            progress(f"Читаю сохранённый фрагмент истории CMD: {path}…")
            found, meta = read_captured_cmd_history(path)
            all_events.extend(found)
            source_records.append({"type": "cmd_history_export", **meta, "records": len(found)})
        except Exception as exc:
            errors.append(f"CMD history {path}: {exc}")

    cmd_buffer_events, cmd_buffer_warnings = scan_current_cmd_buffer()
    all_events.extend(cmd_buffer_events)
    warnings.extend(cmd_buffer_warnings)

    live_events, live_warnings = scan_live_python_processes(progress)
    all_events.extend(live_events)
    warnings.extend(live_warnings)

    progress("Проверяю Prefetch-следы Python…")
    prefetch_events, prefetch_warnings = scan_prefetch()
    all_events.extend(prefetch_events)
    warnings.extend(prefetch_warnings)

    if include_windows_events:
        win_events, win_warnings = scan_windows_process_events(progress)
        all_events.extend(win_events)
        warnings.extend(win_warnings)
        ps_events, ps_warnings = scan_powershell_operational_events(progress)
        all_events.extend(ps_events)
        warnings.extend(ps_warnings)

    if deep_scan:
        run_mru_events, run_mru_warnings = scan_windows_run_mru()
        all_events.extend(run_mru_events)
        warnings.extend(run_mru_warnings)
        recycle_events, recycle_sources, recycle_warnings = scan_windows_recycle_bin(progress)
        all_events.extend(recycle_events)
        source_records.extend(recycle_sources)
        warnings.extend(recycle_warnings)
        deep_events, deep_sources, deep_warnings, deep_errors = scan_deep_artifacts(progress, use_cache=use_cache)
        all_events.extend(deep_events)
        progress_state["deep_records_found"] = 0
        source_records.extend(deep_sources)
        warnings.extend(deep_warnings)
        errors.extend(deep_errors)
        progress({
            "message": f"Глубокий анализ завершён: добавлено записей {len(deep_events)}",
            "phase": "finalizing",
            "artifacts_done": progress_state.get("artifacts_total", 0),
            "records_found": len(all_events),
        })

    # Remove only exact duplicate records. A source path can legitimately
    # contain many visits, downloads, repeated commands, or process events.
    all_events = deduplicate_events(all_events)

    if os.name == "nt":
        warnings.append(
            "CMD не сохраняет историю команд между закрытиями окон по умолчанию. "
            "Поэтому старые команды CMD можно увидеть только в доступных журналах "
            "запуска процессов (4688), экспортированных историях или других заранее включённых средствах аудита."
        )

    # A separate, bounded catalog of user project files is useful even in quick mode.
    # File contents are loaded lazily only when the user selects a file in the UI.
    python_files, source_file_warnings = scan_python_source_catalog(progress)
    warnings.extend(source_file_warnings)

    # Preserve each source timestamp, add UTC/local rendering, and explain what
    # each record can and cannot establish. Correlations use explicit identifiers.
    analysis_quality = attach_analysis(all_events)
    python_java_analysis = analyze_python_java_processes(all_events)
    risk_assessment = assess_suspiciousness(all_events, python_java_analysis, source_records, trusted_paths=trusted_paths)
    analysis_quality["python_java_analysis"] = python_java_analysis
    analysis_quality["risk_assessment"] = risk_assessment
    coverage = build_scan_coverage(source_records, audit_readiness, errors, warnings, all_events)
    all_events.sort(key=lambda e: time_sort_value(e.get("timestamp", "")), reverse=True)
    progress({
        "message": f"Сканирование завершено: {len(all_events)} событий; Python-файлов: {len(python_files)}",
        "phase": "completed",
        "current_path": "",
        "records_found": len(all_events),
        "artifacts_done": progress_state.get("artifacts_total", 0),
        "artifacts_total": progress_state.get("artifacts_total", 0),
    })
    return {
        "events": all_events,
        "sources": source_records,
        "python_files": python_files,
        "warnings": warnings,
        "errors": errors,
        "scan_info": {
            "progress_summary": {
                key: progress_state.get(key) for key in (
                    "directories_checked", "files_seen", "candidate_files",
                    "artifacts_done", "artifacts_total", "sources_checked",
                )
            },
            "generated_local": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"),
            "user": CURRENT_USER,
            "home": str(Path.home()),
            "platform": platform.platform(),
            "python_version": sys.version,
            "windows_event_log_requested": include_windows_events,
            "deep_scan_requested": deep_scan,
            "browser_history_requested": include_browser_history,
            "python_source_files_found": len(python_files),
            "audit_readiness": audit_readiness,
            "compatibility": compatibility,
            "coverage": coverage,
            "analysis_quality": analysis_quality,
            "python_java_analysis": python_java_analysis,
            "risk_assessment": risk_assessment,
            "scope": "Current user profile, selected user environment folders, matching Python-related Windows process and PowerShell events; other Windows accounts and remote computers are not scanned",
        },
    }


class PythonActivityView:
    def __init__(self, root: tk.Tk, include_windows_events: bool = False):
        self.root = root
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        try:
            screen_w = int(self.root.winfo_screenwidth())
            screen_h = int(self.root.winfo_screenheight())
        except Exception:
            screen_w, screen_h = 1600, 1000
        start_w = min(1540, max(980, screen_w - 48))
        start_h = min(940, max(680, screen_h - 80))
        self.root.geometry(f"{start_w}x{start_h}")
        self.root.minsize(min(1180, start_w), min(740, start_h))
        self.events: list[dict[str, Any]] = []
        self.filtered: list[dict[str, Any]] = []
        self.sources: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.scan_info: dict[str, Any] = {}
        self.python_files: list[dict[str, Any]] = []
        self.filtered_python_files: list[dict[str, Any]] = []
        self._event_search_index: list[tuple[str, str]] = []
        self.worker_queue: queue.Queue = queue.Queue()
        self.sort_column = "timestamp"
        self.sort_reverse = True

        self.search_var = tk.StringVar()
        self.command_search_var = tk.StringVar()
        self.filter_var = tk.StringVar(value="Все события")
        self.search_mode_var = tk.StringVar(value="contains")
        self.search_mode_display_var = tk.StringVar(value="")
        self.case_sensitive_var = tk.BooleanVar(value=False)
        self.date_from_var = tk.StringVar(value="")
        self.date_to_var = tk.StringVar(value="")
        self.timeline_search_var = tk.StringVar(value="")
        self.timeline_from_var = tk.StringVar(value="")
        self.timeline_to_var = tk.StringVar(value="")
        self.use_cache_var = tk.BooleanVar(value=True)
        self.cancel_event = threading.Event()
        self.windows_events_var = tk.BooleanVar(value=include_windows_events)
        self.deep_scan_var = tk.BooleanVar(value=False)
        self.file_search_var = tk.StringVar()
        self.selected_file_var = tk.StringVar(value="Файл не выбран")
        self.file_count_var = tk.StringVar(value="Python-файлов не найдено")
        self.status_var = tk.StringVar(value="Готово к сканированию")
        self.progress_message_var = tk.StringVar(value="Ожидание сканирования")
        self.progress_stats_var = tk.StringVar(value="Папок: 0 • просмотрено файлов: 0 • кандидатов: 0 • найдено записей: 0")
        self.current_path_var = tk.StringVar(value="Текущая папка/файл: —")

        self._build_menu()
        self._build_ui()
        self.search_var.trace_add("write", lambda *_: self.apply_filter())
        self.command_search_var.trace_add("write", lambda *_: self.apply_filter())
        self.date_from_var.trace_add("write", lambda *_: self.apply_filter())
        self.date_to_var.trace_add("write", lambda *_: self.apply_filter())
        self.search_mode_var.trace_add("write", lambda *_: self.apply_filter())
        self.case_sensitive_var.trace_add("write", lambda *_: self.apply_filter())
        self.file_search_var.trace_add("write", lambda *_: self.apply_file_filter())
        self.timeline_search_var.trace_add("write", lambda *_: self.refresh_timeline())
        self.timeline_from_var.trace_add("write", lambda *_: self.refresh_timeline())
        self.timeline_to_var.trace_add("write", lambda *_: self.refresh_timeline())
        self.root.bind("<Control-f>", lambda _e: self.command_search_entry.focus_set())
        self.root.bind("<Control-Shift-f>", lambda _e: self.search_entry.focus_set())
        self.root.bind("<Control-r>", lambda _e: self.start_scan())
        self.root.bind("<Control-s>", lambda _e: self.export_csv())
        self.root.bind("<Escape>", lambda _e: self.search_var.set(""))
        self.root.after(350, self.start_scan)

    def save_auto_admin_setting(self) -> None:
        self.settings["auto_admin"] = bool(self.auto_admin_var.get())
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(
                json.dumps(self.settings, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            messagebox.showwarning(self.T("admin_info_title"), str(exc))
            return
        key = "admin_auto_on" if self.auto_admin_var.get() else "admin_auto_off"
        messagebox.showinfo(self.T("admin_info_title"), self.T(key) + "\n\n" + self.T("admin_auto_note"))

    def show_admin_info(self) -> None:
        state = self.T("admin_state_yes" if self.is_admin else "admin_state_no")
        body = self.T("admin_info_body") + "\n\n" + state + "\n\n" + self.T("admin_auto_note")
        messagebox.showinfo(self.T("admin_info_title"), body)

    def restart_as_admin(self) -> None:
        if os.name != "nt":
            messagebox.showwarning(self.T("admin_info_title"), self.T("admin_not_supported"))
            return
        if is_windows_admin():
            messagebox.showinfo(self.T("admin_info_title"), self.T("admin_already"))
            return
        if not messagebox.askyesno(self.T("admin_restart"), self.T("admin_restart_confirm")):
            return
        launched, code = request_windows_elevation()
        if launched:
            # Close this copy only after ShellExecute confirms the elevated
            # process was created. Existing session recording is stopped cleanly.
            self.root.after(250, self.close_application)
            return
        messagebox.showwarning(
            self.T("admin_info_title"),
            self.T("admin_restart_failed", code=(code if code is not None else "unknown")),
        )

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Сканировать\tCtrl+R", command=self.start_scan)
        file_menu.add_separator()
        file_menu.add_command(label="Экспорт событий в CSV…\tCtrl+S", command=self.export_csv)
        file_menu.add_command(label="Экспорт отчёта в JSON…", command=self.export_json)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.destroy)
        menu.add_cascade(label="Файл", menu=file_menu)

        edit_menu = tk.Menu(menu, tearoff=False)
        edit_menu.add_command(label="Копировать выбранную команду", command=self.copy_command)
        edit_menu.add_command(label="Копировать детали записи", command=self.copy_details)
        menu.add_cascade(label="Правка", menu=edit_menu)

        view_menu = tk.Menu(menu, tearoff=False)
        view_menu.add_command(label="Сбросить фильтр", command=self.reset_filters)
        view_menu.add_command(label="Показать источники и предупреждения", command=self.show_diagnostics)
        menu.add_cascade(label="Вид", menu=view_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="О программе", command=self.show_about)
        menu.add_cascade(label="Справка", menu=help_menu)
        self.root.config(menu=menu)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=(10, 8))
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="ПРОСМОТР АКТИВНОСТИ PYTHON", font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Label(header, text=f"  версия {APP_VERSION}  •  пользователь: {CURRENT_USER}", foreground="#666666").pack(side="left", padx=8)
        ttk.Button(header, text="Экспорт CSV", command=self.export_csv).pack(side="right", padx=(6, 0))
        ttk.Button(header, text="Экспорт JSON", command=self.export_json).pack(side="right", padx=(6, 0))
        self.scan_button = ttk.Button(header, text="⟳  Сканировать", command=self.start_scan)
        self.scan_button.pack(side="right")

        options = ttk.Frame(outer)
        options.pack(fill="x", pady=(0, 7))
        ttk.Checkbutton(
            options,
            text="Журналы Windows: запуск процессов 4688 и PowerShell 4103/4104 (может быть медленно)",
            variable=self.windows_events_var,
        ).pack(side="left")
        ttk.Checkbutton(
            options,
            text="Полный поиск по архивам, логам и остаткам SQLite (дольше)",
            variable=self.deep_scan_var,
        ).pack(side="left", padx=(14, 0))

        progress_frame = ttk.LabelFrame(outer, text="Состояние сканирования", padding=(8, 5))
        progress_frame.pack(fill="x", pady=(0, 8))
        progress_top = ttk.Frame(progress_frame)
        progress_top.pack(fill="x")
        ttk.Label(progress_top, textvariable=self.progress_message_var).pack(side="left", fill="x", expand=True)
        self.progressbar = ttk.Progressbar(progress_top, mode="indeterminate", length=260)
        self.progressbar.pack(side="right", padx=(10, 0))
        ttk.Label(progress_frame, textvariable=self.progress_stats_var, foreground="#444444").pack(anchor="w", pady=(3, 0))
        ttk.Label(
            progress_frame, textvariable=self.current_path_var, foreground="#666666",
            wraplength=1400, justify="left",
        ).pack(anchor="w", pady=(2, 0))

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        history_tab = ttk.Frame(self.notebook, padding=7)
        files_tab = ttk.Frame(self.notebook, padding=7)
        self.notebook.add(history_tab, text="История команд и запусков")
        self.notebook.add(files_tab, text="Python-файлы и исходный код")

        # --- History tab ---
        filters = ttk.Frame(history_tab)
        filters.pack(fill="x", pady=(0, 7))
        filter_row = ttk.Frame(filters)
        filter_row.pack(fill="x")
        ttk.Label(filter_row, text="Поиск команды:").pack(side="left")
        self.command_search_entry = ttk.Entry(filter_row, textvariable=self.command_search_var, width=35)
        self.command_search_entry.pack(side="left", padx=(6, 12))
        ttk.Label(filter_row, text="Поиск по всем полям:").pack(side="left")
        self.search_entry = ttk.Entry(filter_row, textvariable=self.search_var, width=32)
        self.search_entry.pack(side="left", padx=(6, 12))
        ttk.Label(filter_row, text="Источник:").pack(side="left")
        self.filter_combo = ttk.Combobox(
            filter_row, textvariable=self.filter_var, state="readonly", width=28,
            values=["Все события"],
        )
        self.filter_combo.pack(side="left", padx=6)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self.apply_filter())
        ttk.Button(filter_row, text="Сбросить", command=self.reset_filters).pack(side="right")

        pane = ttk.Panedwindow(history_tab, orient="vertical")
        pane.pack(fill="both", expand=True)
        table_frame = ttk.Frame(pane)
        detail_frame = ttk.Frame(pane)
        pane.add(table_frame, weight=4)
        pane.add(detail_frame, weight=2)

        columns = ("date", "time", "kind", "description", "command", "source", "user")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
        headings = {
            "date": "Дата", "time": "Время", "kind": "Тип события",
            "description": "Описание", "command": "Введённая команда / содержимое",
            "source": "Откуда получено", "user": "Пользователь",
        }
        widths = {"date": 100, "time": 82, "kind": 230, "description": 250, "command": 420, "source": 320, "user": 100}
        for col in columns:
            self.tree.heading(col, text=headings[col], command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=widths[col], minwidth=75, stretch=(col in {"description", "command", "source"}))
        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda _e: self.show_properties())
        self.tree.tag_configure("even", background="#f3f6fa")
        self.tree.tag_configure("odd", background="#ffffff")
        self.tree.bind("<Button-3>", self.show_context_menu)

        detail_header = ttk.Frame(detail_frame)
        detail_header.pack(fill="x", pady=(7, 4))
        ttk.Label(detail_header, text="Подробности выбранной записи", font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(detail_header, text="Копировать команду", command=self.copy_command).pack(side="right")
        ttk.Button(detail_header, text="Копировать сведения", command=self.copy_details).pack(side="right", padx=6)
        self.details_text = tk.Text(detail_frame, height=8, wrap="word", font=("Consolas", 9),
                                    background="#f7f7f7", relief="solid", borderwidth=1)
        self.details_text.pack(fill="both", expand=True)
        self.details_text.insert("1.0", "Выберите запись в таблице. Здесь отобразятся команда, путь к источнику и дополнительные сведения.")
        self.details_text.configure(state="disabled")

        # --- Python files tab ---
        file_toolbar = ttk.Frame(files_tab)
        file_toolbar.pack(fill="x", pady=(0, 7))
        ttk.Label(file_toolbar, text="Найти файл:").pack(side="left")
        self.file_search_entry = ttk.Entry(file_toolbar, textvariable=self.file_search_var, width=42)
        self.file_search_entry.pack(side="left", padx=(6, 12))
        ttk.Label(file_toolbar, textvariable=self.file_count_var, foreground="#555555").pack(side="left")
        ttk.Button(file_toolbar, text="Копировать путь", command=self.copy_selected_file_path).pack(side="right")
        ttk.Button(file_toolbar, text="Открыть файл", command=self.open_selected_python_file).pack(side="right", padx=6)

        file_pane = ttk.Panedwindow(files_tab, orient="horizontal")
        file_pane.pack(fill="both", expand=True)
        file_list_frame = ttk.Frame(file_pane)
        code_frame = ttk.Frame(file_pane)
        file_pane.add(file_list_frame, weight=2)
        file_pane.add(code_frame, weight=5)

        file_columns = ("name", "modified", "size", "extension")
        self.file_tree = ttk.Treeview(file_list_frame, columns=file_columns, show="headings", selectmode="browse")
        file_headings = {"name": "Файл", "modified": "Изменён", "size": "Размер", "extension": "Тип"}
        file_widths = {"name": 210, "modified": 135, "size": 80, "extension": 65}
        for col in file_columns:
            self.file_tree.heading(col, text=file_headings[col])
            self.file_tree.column(col, width=file_widths[col], minwidth=55, stretch=(col == "name"))
        file_y = ttk.Scrollbar(file_list_frame, orient="vertical", command=self.file_tree.yview)
        file_x = ttk.Scrollbar(file_list_frame, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=file_y.set, xscrollcommand=file_x.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        file_y.grid(row=0, column=1, sticky="ns")
        file_x.grid(row=1, column=0, sticky="ew")
        file_list_frame.rowconfigure(0, weight=1)
        file_list_frame.columnconfigure(0, weight=1)
        self.file_tree.bind("<<TreeviewSelect>>", self.on_python_file_select)
        self.file_tree.bind("<Double-1>", lambda _e: self.open_selected_python_file())

        code_header = ttk.Frame(code_frame)
        code_header.pack(fill="x", pady=(0, 4))
        ttk.Label(code_header, textvariable=self.selected_file_var, font=("Segoe UI", 9, "bold")).pack(side="left", fill="x", expand=True)
        code_body = ttk.Frame(code_frame)
        code_body.pack(fill="both", expand=True)
        self.code_text = tk.Text(code_body, wrap="none", font=("Consolas", 10),
                                 background="#fbfbfb", foreground="#202020", undo=False)
        code_y = ttk.Scrollbar(code_body, orient="vertical", command=self.code_text.yview)
        code_x = ttk.Scrollbar(code_body, orient="horizontal", command=self.code_text.xview)
        self.code_text.configure(yscrollcommand=code_y.set, xscrollcommand=code_x.set)
        self.code_text.grid(row=0, column=0, sticky="nsew")
        code_y.grid(row=0, column=1, sticky="ns")
        code_x.grid(row=1, column=0, sticky="ew")
        code_body.rowconfigure(0, weight=1)
        code_body.columnconfigure(0, weight=1)
        self.code_text.insert("1.0", "После сканирования выберите файл слева.\n\nПоддерживаются .py, .pyw, .pyi и Jupyter Notebook (.ipynb).\nСодержимое читается только по запросу и не изменяется.")
        self.code_text.configure(state="disabled")

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(7, 0))
        ttk.Label(footer, textvariable=self.status_var).pack(side="left")
        ttk.Label(footer, text="Только чтение • данные остаются на этом компьютере • Ctrl+R — сканировать", foreground="#666666").pack(side="right")

    def start_scan(self) -> None:
        if getattr(self, "scanning", False):
            return
        self.scanning = True
        self.cancel_event.clear()
        self.scan_button.configure(state="disabled")
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="normal")
        self.status_var.set("Сканирование…")
        self.progress_message_var.set("Подготовка сканирования…")
        self.progress_stats_var.set("Папок: 0 • просмотрено файлов: 0 • кандидатов: 0 • обработано: 0 • найдено записей: 0")
        self.current_path_var.set("Текущая папка/файл: —")
        self.progressbar.stop()
        self.progressbar.configure(mode="indeterminate")
        self.progressbar.start(10)
        self.tree.delete(*self.tree.get_children())
        self.file_tree.delete(*self.file_tree.get_children())
        self.python_files = []
        self.filtered_python_files = []
        self.file_count_var.set("Сканирование…")
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", "Идёт сбор доступных записей…")
        self.details_text.configure(state="disabled")
        self.code_text.configure(state="normal")
        self.code_text.delete("1.0", "end")
        self.code_text.insert("1.0", "Сканирование. После завершения выберите файл в списке слева.")
        self.code_text.configure(state="disabled")
        self.selected_file_var.set("Ожидание списка файлов…")

        def progress(message: str) -> None:
            self.worker_queue.put(("progress", message))

        include_windows_events = bool(self.windows_events_var.get())
        deep_scan = bool(self.deep_scan_var.get())
        use_cache = bool(getattr(self, "use_cache_var", tk.BooleanVar(value=True)).get())
        browser_domain_rules = dict(self.settings.get("browser_domain_categories", {})) if isinstance(self.settings.get("browser_domain_categories", {}), dict) else {}
        include_browser_history = bool(self.browser_history_var.get())
        trusted_context_paths = list(getattr(self, "trusted_paths", []))

        def worker() -> None:
            try:
                result = scan_all(include_windows_events, deep_scan, progress, cancel_event=self.cancel_event, use_cache=use_cache, domain_rules=browser_domain_rules, include_browser_history=include_browser_history, trusted_paths=trusted_context_paths)
                if self.cancel_event.is_set():
                    raise ScanCancelled("Сканирование отменено пользователем")
                self.worker_queue.put(("done", result))
            except ScanCancelled:
                self.worker_queue.put(("cancelled", None))
            except Exception as exc:
                self.worker_queue.put(("fatal", str(exc)))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(120, self.poll_worker)

    def cancel_scan(self) -> None:
        if not getattr(self, "scanning", False):
            return
        self.cancel_event.set()
        self.status_var.set(self.T("scan_cancelling") if hasattr(self, "T") else "Останавливаю сканирование…")
        self.progress_message_var.set(self.status_var.get())
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="disabled")

    def poll_worker(self) -> None:
        try:
            while True:
                kind, payload = self.worker_queue.get_nowait()
                if kind == "progress":
                    if isinstance(payload, dict):
                        self.update_progress(payload)
                    else:
                        self.status_var.set(str(payload))
                        self.progress_message_var.set(str(payload))
                elif kind == "done":
                    self.scanning = False
                    self.scan_button.configure(state="normal")
                    self.progressbar.stop()
                    self.progressbar.configure(mode="determinate", maximum=100, value=100)
                    self.progress_message_var.set("Сканирование завершено")
                    self.events = payload["events"]
                    self.sources = payload["sources"]
                    self.warnings = payload["warnings"]
                    self.errors = payload["errors"]
                    self.scan_info = payload["scan_info"]
                    self.python_files = payload.get("python_files", [])
                    self.readiness_report = self.scan_info.get("audit_readiness", {})
                    self.coverage_report = self.scan_info.get("coverage", {})
                    self.analysis_quality = self.scan_info.get("analysis_quality", {})
                    self._event_search_index = []
                    for item in self.events:
                        command_text = str(item.get("command", ""))
                        searchable = " ".join([
                            str(item.get("timestamp", "")), str(item.get("kind", "")),
                            str(item.get("description", "")), command_text,
                            str(item.get("source", "")), str(item.get("user", "")),
                            json.dumps(item.get("details", {}), ensure_ascii=False, default=str),
                        ]).casefold()
                        self._event_search_index.append((command_text.casefold(), searchable))
                    self.update_filter_options()
                    self.apply_filter()
                    self.apply_file_filter()
                    self.render_browser_rows()
                    self.render_download_rows()
                    self.render_runtime_panel()
                    self.status_var.set(
                        f"Готово: {len(self.events)} событий • {len(self.python_files)} Python-файлов • "
                        f"{len(self.sources)} источников • {len(self.warnings)} предупреждений • {len(self.errors)} ошибок"
                    )
                    if self.warnings or self.errors:
                        self.root.after(250, self._maybe_show_diagnostics_hint)
                    return
                elif kind == "cancelled":
                    self.scanning = False
                    self.scan_button.configure(state="normal")
                    if hasattr(self, "cancel_button"):
                        self.cancel_button.configure(state="disabled")
                    self.progressbar.stop()
                    self.progress_message_var.set("Сканирование отменено")
                    self.status_var.set("Сканирование отменено")
                    return
                elif kind == "fatal":
                    self.scanning = False
                    self.scan_button.configure(state="normal")
                    if hasattr(self, "cancel_button"):
                        self.cancel_button.configure(state="disabled")
                    self.progressbar.stop()
                    self.progress_message_var.set("Сканирование завершилось с ошибкой")
                    self.status_var.set("Ошибка сканирования")
                    messagebox.showerror("Ошибка", str(payload))
                    return
        except queue.Empty:
            pass
        if getattr(self, "scanning", False):
            self.root.after(120, self.poll_worker)

    def update_progress(self, payload: dict[str, Any]) -> None:
        message = str(payload.get("message", "Сканирование…"))
        self.progress_message_var.set(message)
        self.status_var.set(message)

        folders = int(payload.get("directories_checked", 0) or 0)
        files_seen = int(payload.get("files_seen", 0) or 0)
        candidates = int(payload.get("candidate_files", 0) or 0)
        sources = int(payload.get("sources_checked", 0) or 0)
        checked = int(payload.get("artifacts_done", 0) or 0)
        total = int(payload.get("artifacts_total", 0) or 0)
        records = int(payload.get("records_found", 0) or 0)
        python_files = int(payload.get("python_files_found", 0) or 0)
        self.progress_stats_var.set(
            f"Папок: {folders:,} • просмотрено файлов: {files_seen:,} • "
            f"кандидатов: {candidates:,} • проверено источников: {sources:,} • "
            f"анализ: {checked:,}/{total:,} • событий: {records:,} • исходников: {python_files:,}".replace(",", " ")
        )
        current_path = str(payload.get("current_path", "") or "—")
        self.current_path_var.set(f"Текущая папка/файл: {current_path}")

        phase = str(payload.get("phase", ""))
        if phase == "deep_analysis" and total > 0:
            self.progressbar.stop()
            self.progressbar.configure(mode="determinate", maximum=total, value=min(checked, total))
        elif self.progressbar.cget("mode") != "indeterminate":
            self.progressbar.stop()
            self.progressbar.configure(mode="indeterminate")
            self.progressbar.start(10)

    def _maybe_show_diagnostics_hint(self) -> None:
        if self.warnings or self.errors:
            self.status_var.set(self.status_var.get() + " • Подробности: Вид → Показать предупреждения")

    def update_filter_options(self) -> None:
        kinds = sorted({e.get("kind", "") for e in (list(self.events) + list(getattr(self, "forensic_rows", []))) if e.get("kind")})
        self.filter_combo["values"] = ["Все события"] + kinds
        if self.filter_var.get() not in self.filter_combo["values"]:
            self.filter_var.set("Все события")

    def apply_filter(self) -> None:
        query = self.search_var.get().casefold().strip()
        command_query = self.command_search_var.get().casefold().strip()
        kind_filter = self.filter_var.get()
        kind_filter_raw = getattr(self, "filter_display_to_raw", {}).get(kind_filter, kind_filter)
        result = []
        combined_events = list(self.events) + list(getattr(self, "forensic_rows", []))
        index = self._event_search_index if len(self._event_search_index) == len(combined_events) else None
        for position, item in enumerate(combined_events):
            if kind_filter != "Все события" and item.get("kind") != kind_filter:
                continue
            if index is not None:
                command_blob, searchable = index[position]
            else:
                command_blob = str(item.get("command", "")).casefold()
                searchable = " ".join([
                    str(item.get("timestamp", "")), str(item.get("kind", "")),
                    str(item.get("description", "")), command_blob,
                    str(item.get("source", "")), str(item.get("user", "")),
                ]).casefold()
            if command_query and command_query not in command_blob:
                continue
            if query and query not in searchable:
                continue
            result.append(item)
        self.filtered = result
        self.render_rows()

    def reset_filters(self) -> None:
        self.command_search_var.set("")
        self.search_var.set("")
        self.filter_var.set("Все события")
        self.apply_filter()

    def render_rows(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.filtered):
            command = str(item.get("command", "")).replace("\n", " ⏎ ").replace("\r", "")
            if len(command) > 240:
                command = command[:237] + "..."
            self.tree.insert("", "end", iid=str(index), tags=("even" if index % 2 == 0 else "odd",), values=(
                item.get("date", "") or "—",
                item.get("time", "") or "—",
                item.get("kind", ""),
                item.get("description", ""),
                command,
                item.get("source", ""),
                item.get("user", ""),
            ))

    def apply_file_filter(self) -> None:
        query = self.file_search_var.get().casefold().strip()
        if query:
            self.filtered_python_files = [
                item for item in self.python_files
                if query in str(item.get("name", "")).casefold()
                or query in str(item.get("path", "")).casefold()
            ]
        else:
            self.filtered_python_files = list(self.python_files)
        self.file_tree.delete(*self.file_tree.get_children())
        for index, item in enumerate(self.filtered_python_files):
            self.file_tree.insert(
                "", "end", iid=str(index),
                values=(item.get("name", ""), item.get("modified_local", ""),
                        item.get("size_display", ""), item.get("extension", "")),
            )
        self.file_count_var.set(
            f"Показано {len(self.filtered_python_files)} из {len(self.python_files)} файлов"
        )

    def selected_python_file(self) -> dict[str, Any] | None:
        selection = self.file_tree.selection()
        if not selection:
            return None
        try:
            return self.filtered_python_files[int(selection[0])]
        except (ValueError, IndexError):
            return None

    def on_python_file_select(self, _event: Any = None) -> None:
        item = self.selected_python_file()
        if not item:
            return
        path = Path(item.get("path", ""))
        self.selected_file_var.set(str(path))
        content = read_python_source_file(path)
        # Number lines in the preview for easier reading and referencing.
        numbered = "\n".join(f"{line_no:5d}  {line}" for line_no, line in enumerate(content.splitlines(), 1))
        self.code_text.configure(state="normal")
        self.code_text.delete("1.0", "end")
        self.code_text.insert("1.0", numbered or "(файл пуст)")
        self.code_text.configure(state="disabled")

    def copy_selected_file_path(self) -> None:
        item = self.selected_python_file()
        if not item:
            messagebox.showinfo("Копирование пути", "Сначала выберите файл в списке.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(item.get("path", "")))
        self.status_var.set("Путь к файлу скопирован")

    def open_selected_python_file(self) -> None:
        item = self.selected_python_file()
        if not item:
            messagebox.showinfo("Открытие файла", "Сначала выберите файл в списке.")
            return
        path = Path(item.get("path", ""))
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Не удалось открыть файл", str(exc))

    def sort_by(self, column: str) -> None:
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        if column == "date":
            key = lambda item: item.get("date", "")
        elif column == "time":
            key = lambda item: item.get("time", "")
        elif column == "timestamp":
            key = lambda item: time_sort_value(item.get("timestamp", ""))
        else:
            key = lambda item: str(item.get(column, "")).casefold()
        self.filtered.sort(key=key, reverse=self.sort_reverse)
        self.render_rows()

    def selected_event(self) -> dict[str, Any] | None:
        selected = self.tree.selection()
        if not selected:
            return None
        try:
            return self.filtered[int(selected[0])]
        except (ValueError, IndexError):
            return None

    def on_select(self, _event: Any = None) -> None:
        item = self.selected_event()
        if not item:
            return
        display = dict(item)
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", json.dumps(display, ensure_ascii=False, indent=2, default=str))
        self.details_text.configure(state="disabled")

    def show_context_menu(self, event: Any) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label="Копировать команду", command=self.copy_command)
        menu.add_command(label="Копировать детали", command=self.copy_details)
        menu.add_separator()
        menu.add_command(label="Свойства…", command=self.show_properties)
        menu.tk_popup(event.x_root, event.y_root)

    def show_properties(self) -> None:
        item = self.selected_event()
        if not item:
            return
        window = tk.Toplevel(self.root)
        window.title("Свойства события")
        window.geometry("900x620")
        text = tk.Text(window, wrap="word", font=("Consolas", 9))
        scroll = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("1.0", json.dumps(item, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")

    def copy_command(self) -> None:
        item = self.selected_event()
        if not item:
            return
        value = item.get("command") or item.get("description", "")
        self.root.clipboard_clear()
        self.root.clipboard_append(str(value))
        self.status_var.set("Содержимое записи скопировано в буфер обмена")

    def copy_details(self) -> None:
        item = self.selected_event()
        if not item:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps(item, ensure_ascii=False, indent=2, default=str))
        self.status_var.set("Детали записи скопированы в буфер обмена")

    def export_csv(self) -> None:
        if not self.events:
            messagebox.showinfo("Экспорт", "Сначала выполни сканирование.")
            return
        path = filedialog.asksaveasfilename(
            title="Экспорт событий в CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("Все файлы", "*.*")],
            initialfile="python_activity_events.csv",
        )
        if not path:
            return
        try:
            fields = ["timestamp", "time_basis", "kind", "description", "command", "source", "user", "timestamp_utc", "timestamp_local", "time_normalization", "evidence_assessment", "details"]
            with open(path, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                combined_rows = list(self.filtered) + list(getattr(self, "forensic_rows", []))
                for item in combined_rows:
                    row = dict(item)
                    for nested_key in ("details", "time_normalization", "evidence_assessment"):
                        row[nested_key] = json.dumps(row.get(nested_key, {}), ensure_ascii=False, default=str)
                    writer.writerow(row)
            self.status_var.set(f"Экспортировано {len(self.filtered)} строк: {path}")
        except Exception as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))

    def export_json(self) -> None:
        if not self.events:
            messagebox.showinfo("Экспорт", "Сначала выполни сканирование.")
            return
        path = filedialog.asksaveasfilename(
            title="Экспорт отчёта JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")],
            initialfile="python_activity_report.json",
        )
        if not path:
            return
        report = {
            "application": APP_NAME,
            "version": APP_VERSION,
            "scan_info": self.scan_info,
            "audit_readiness": self.readiness_report,
            "coverage": self.coverage_report,
            "analysis_quality": self.analysis_quality,
            "summary": {
                "events_total": len(self.events),
                "events_exported": len(self.filtered),
                "event_types": dict(Counter(e.get("kind", "") for e in self.events)),
            },
            "sources": self.sources,
            "python_files": self.python_files,
            "events": self.filtered,
            "warnings": self.warnings,
            "errors": self.errors,
        }
        try:
            Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.status_var.set(f"JSON-отчёт сохранён: {path}")
        except Exception as exc:
            messagebox.showerror("Ошибка экспорта", str(exc))

    def show_diagnostics(self) -> None:
        payload = {
            "Предупреждения": self.warnings,
            "Ошибки": self.errors,
            "Найденные источники": self.sources,
        }
        window = tk.Toplevel(self.root)
        window.title("Диагностика и источники")
        window.geometry("900x600")
        text = tk.Text(window, wrap="word", font=("Consolas", 9))
        scroll = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")

    def show_about(self) -> None:
        messagebox.showinfo(
            "О программе",
            f"{APP_NAME} {APP_VERSION}\n\n"
            "Просмотр истории Python / IPython / PyCharm Python Console, запусков через терминалы, "
            "а также списка Python-файлов и их исходного кода.\n\n"
            "Утилита работает в режиме чтения. Это не кейлоггер и не средство удалённого мониторинга.\n"
            "Удалённые записи, которые нигде не сохранились, восстановить нельзя."
        )



# -----------------------------------------------------------------------------
# Version 2.0 UI and optional in-app session recorder
# -----------------------------------------------------------------------------

import ast
import difflib
import html
import textwrap
import uuid

LANGUAGE_TEXT = {
    "ru": {
        "app_title": "Просмотр активности Python",
        "header": "ПРОСМОТР АКТИВНОСТИ PYTHON",
        "language": "Язык",
        "language_name": "Русский",
        "scan": "⟳  Сканировать",
        "export_csv": "Экспорт CSV",
        "export_json": "Экспорт JSON",
        "export_html": "HTML-отчёт",
        "windows_logs": "Журналы Windows: запуск процессов 4688 и PowerShell 4103/4104",
        "deep_scan": "Глубокий поиск по логам, архивам и SQLite (дольше)",
        "scan_state": "Состояние сканирования",
        "tab_overview": "Обзор",
        "tab_history": "История команд",
        "tab_files": "Python-файлы",
        "tab_processes": "Процессы",
        "tab_recovery": "Восстановление",
        "tab_sessions": "Запись сессии",
        "tab_timeline": "Хронология",
        "tab_lineage": "Дерево процессов",
        "tab_scans": "История сканирований",
        "tab_readiness": "Готовность и полнота",
        "readiness_title": "Готовность аудита и полнота проверки",
        "readiness_note": "Показывает текущие настройки Windows и источники, которые удалось проверить. Текущая настройка не доказывает, что аудит был включён в прошлом.",
        "readiness_refresh": "Проверить сейчас",
        "readiness_summary": "Состояние готовности",
        "coverage_summary": "Полнота текущего сканирования",
        "readiness_name": "Проверка",
        "readiness_category": "Категория",
        "readiness_status": "Состояние",
        "readiness_note_col": "Пояснение",
        "readiness_detail": "Подробности выбранной проверки",
        "evidence_confidence": "Достоверность источника",
        "utc_time": "Время UTC",
        "search_mode": "Режим поиска:",
        "search_contains": "Содержит",
        "search_exact": "Точное совпадение",
        "search_regex": "Регулярное выражение",
        "case_sensitive": "Учитывать регистр",
        "date_from": "С даты (ГГГГ-ММ-ДД):",
        "date_to": "По дату:",
        "timeline_search": "Фильтр событий:",
        "timeline_empty": "Нет событий для отображения.",
        "lineage_note": "Исторические связи строятся только по сохранённым событиям 4688/Sysmon. Если родительского события нет, процесс остаётся корневым.",
        "lineage_refresh": "Обновить дерево",
        "scan_history_note": "Снимки сохраняются локально и позволяют сравнивать результаты разных проверок.",
        "scan_history_compare": "Сравнить выбранные",
        "scan_history_import": "Импортировать снимок",
        "scan_history_view": "Открыть снимок",
        "scan_history_open_title": "Содержимое снимка сканирования",
        "scan_history_empty": "Снимков пока нет. Выполните сканирование.",
        "scan_history_columns": "Дата и время",
        "scan_history_events": "События",
        "scan_history_sources": "Источники",
        "scan_history_warnings": "Предупреждения",
        "scan_history_hash": "SHA-256",
        "scan_history_need_two": "Выберите ровно два снимка для сравнения.",
        "scan_compare_title": "Сравнение сканирований",
        "cancel_scan": "Остановить сканирование",
        "scan_cancelled": "Сканирование отменено",
        "scan_cancelling": "Останавливаю сканирование… Дождитесь завершения текущей операции.",
        "use_cache": "Использовать кэш глубокого поиска",
        "clear_cache": "Очистить кэш",
        "cache_cleared": "Кэш глубокого поиска очищен.",
        "verify_signature": "Проверить подпись EXE/DLL…",
        "signature_title": "Проверка цифровой подписи",
        "signature_pick": "Выберите EXE, DLL или SYS-файл для проверки подписи.",
        "evidence_bundle": "Пакет отчёта…",
        "evidence_bundle_saved": "Пакет отчёта сохранён.",
        "search_invalid_regex": "Некорректное регулярное выражение: {error}",
        "compare_summary": "Добавлено событий: {added}; исчезло событий: {removed}; общих: {common}.",
        "compare_files_summary": "Python-файлы: новых {added}, удалённых {removed}, изменённых {changed}.",
        "compare_process_summary": "Снимки процессов: добавлено {added}, отсутствует в новом снимке {removed}.",
        "compare_old_snapshot": "Старый снимок: {value}",
        "compare_new_snapshot": "Новый снимок: {value}",
        "compare_added_sources": "Добавлено источников: {n}",
        "compare_removed_sources": "Удалено источников: {n}",
        "compare_files_heading": "НОВЫЕ/ИЗМЕНЁННЫЕ PYTHON-ФАЙЛЫ:",
        "compare_processes_heading": "ИЗМЕНЕНИЯ СНИМКА ПРОЦЕССОВ:",
        "compare_new_events_heading": "НОВЫЕ СОБЫТИЯ:",
        "compare_removed_events_heading": "ИСЧЕЗНУВШИЕ СОБЫТИЯ:",
        "search_command": "Поиск команды:",
        "search_all": "Поиск везде:",
        "event_type": "Тип события:",
        "all_events": "Все события",
        "reset": "Сбросить",
        "date": "Дата",
        "time": "Время",
        "description": "Описание",
        "command": "Команда / содержимое",
        "source": "Источник данных",
        "user": "Пользователь",
        "details": "Подробности выбранной записи",
        "copy_command": "Копировать команду",
        "copy_details": "Копировать сведения",
        "select_event": "Выберите запись в таблице — здесь появятся команда, источник и дополнительные сведения.",
        "find_file": "Найти файл:",
        "file_count": "Python-файлов не найдено",
        "copy_path": "Копировать путь",
        "open_file": "Открыть файл",
        "choose_folder": "Добавить папку…",
        "snapshot": "Сохранить снимок",
        "compare": "Сравнить с версией",
        "file": "Файл",
        "modified": "Изменён",
        "size": "Размер",
        "type": "Тип",
        "file_not_selected": "Файл не выбран",
        "select_file": "Выберите файл слева. Исходник открывается только для чтения.",
        "process_refresh": "Обновить список",
        "process_warning": "Это снимок процессов, работающих СЕЙЧАС. Историю завершённых процессов см. во вкладке «История команд», если журналы были включены заранее.",
        "pid": "PID",
        "process": "Процесс",
        "parent_pid": "PID родителя",
        "started": "Запущен",
        "path": "Путь",
        "cmdline": "Командная строка",
        "recovery_title": "Найденные следы и возможные остатки",
        "recovery_note": "Здесь собраны доступные признаки из истории, резервных копий, SQLite/WAL и журналов. Фрагмент с пометкой «возможный остаток» не считается доказанной восстановленной командой. Утилита не сканирует нераспределённые сектора диска и не обходит чужие профили.",
        "run_deep": "Запустить глубокое сканирование",
        "no_recovery": "Пока нет найденных следов для этого раздела. Запустите глубокое сканирование.",
        "session_notice": "Запись выключена. Включайте её только когда хотите сохранить команды, вводимые в эту встроенную консоль.",
        "session_start": "Начать запись",
        "session_stop": "Остановить запись",
        "run_code": "Выполнить и сохранить",
        "clear_code": "Очистить ввод",
        "code_input": "Введите Python-код (можно несколько строк):",
        "session_history": "Записи текущей сессии",
        "terminal": "Терминал / результат выполнения",
        "terminal_empty": "Вывод и ошибки выполнения появятся здесь.",
        "session_warning": "Код запускается в отдельном процессе Python с правами текущего пользователя. Это не песочница: выполняйте только код, которому доверяете. Ввод из PyCharm/CMD/PowerShell автоматически не перехватывается.",
        "recording_on": "Запись включена",
        "recording_off": "Запись выключена",
        "overview_events": "Событий найдено",
        "overview_files": "Python-файлов",
        "overview_sources": "Источников",
        "overview_warnings": "Предупреждений",
        "timeline": "Активность по датам",
        "recent": "Последние события",
        "no_events": "События ещё не собраны. Нажмите «Сканировать».",
        "ready": "Готово к сканированию",
        "scanning": "Сканирование…",
        "finished": "Сканирование завершено",
        "fatal": "Сканирование завершилось с ошибкой",
        "footer": "Только чтение для найденных источников • запись команд — только во встроенной консоли • Ctrl+R — сканировать",
        "menu_file": "Файл",
        "menu_edit": "Правка",
        "menu_view": "Вид",
        "menu_help": "Справка",
        "menu_scan": "Сканировать  Ctrl+R",
        "menu_csv": "Экспорт CSV…",
        "menu_json": "Экспорт JSON…",
        "menu_html": "HTML-отчёт…",
        "menu_exit": "Выход",
        "menu_copy_command": "Копировать выбранную команду",
        "menu_copy_details": "Копировать подробности",
        "menu_reset": "Сбросить фильтры",
        "menu_diagnostics": "Источники и предупреждения",
        "menu_about": "О программе",
        "choose_language": "Выберите язык интерфейса:",
        "saved": "Сохранено",
        "no_selection": "Сначала выберите запись.",
        "scan_first": "Сначала выполните сканирование.",
        "process_unavailable": "Не удалось получить список процессов",
        "process_count": "Найдено процессов: {n}",
        "snapshot_saved": "Снимок файла сохранён.",
        "no_snapshot": "Для этого файла ещё нет снимка.",
        "diff_title": "Сравнение с последним снимком",
        "session_confirm": "Встроенная консоль запускает Python-код с правами вашей учётной записи. Продолжить?",
        "session_started": "Запись сессии включена. Команды сохраняются локально.",
        "session_stopped": "Запись сессии остановлена.",
        "enter_code": "Введите Python-код.",
        "session_busy": "Предыдущее выполнение ещё обрабатывается.",
        "console_start_error": "Не удалось запустить встроенную консоль",
        "scan_summary": "Готово: {events} событий • {files} файлов • {sources} источников • {warnings} предупреждений",
        "status_only_local": "Локальная активность текущего пользователя",
    },
    "en": {
        "app_title": "Python Activity View",
        "header": "PYTHON ACTIVITY VIEW",
        "language": "Language",
        "language_name": "English",
        "scan": "⟳  Scan",
        "export_csv": "Export CSV",
        "export_json": "Export JSON",
        "export_html": "HTML report",
        "windows_logs": "Windows logs: process start 4688 and PowerShell 4103/4104",
        "deep_scan": "Deep search in logs, archives and SQLite (slower)",
        "scan_state": "Scan status",
        "tab_overview": "Overview",
        "tab_history": "Command history",
        "tab_files": "Python files",
        "tab_processes": "Processes",
        "tab_recovery": "Recovery",
        "tab_sessions": "Session recorder",
        "tab_timeline": "Timeline",
        "tab_lineage": "Process tree",
        "tab_scans": "Scan history",
        "tab_readiness": "Readiness & coverage",
        "readiness_title": "Audit readiness and scan coverage",
        "readiness_note": "Shows current Windows settings and sources that could be inspected. A current setting does not prove auditing was enabled in the past.",
        "readiness_refresh": "Check now",
        "readiness_summary": "Readiness status",
        "coverage_summary": "Current scan coverage",
        "readiness_name": "Check",
        "readiness_category": "Category",
        "readiness_status": "Status",
        "readiness_note_col": "Explanation",
        "readiness_detail": "Selected check details",
        "evidence_confidence": "Evidence strength",
        "utc_time": "UTC time",
        "search_mode": "Search mode:",
        "search_contains": "Contains",
        "search_exact": "Exact match",
        "search_regex": "Regular expression",
        "case_sensitive": "Case-sensitive",
        "date_from": "From date (YYYY-MM-DD):",
        "date_to": "To date:",
        "timeline_search": "Filter events:",
        "timeline_empty": "No events to display.",
        "lineage_note": "Historical links are built only from retained 4688/Sysmon events. If a parent event is missing, the process remains a root node.",
        "lineage_refresh": "Refresh tree",
        "scan_history_note": "Snapshots are stored locally and can be compared across scans.",
        "scan_history_compare": "Compare selected",
        "scan_history_import": "Import snapshot",
        "scan_history_view": "Open snapshot",
        "scan_history_open_title": "Scan snapshot details",
        "scan_history_empty": "No snapshots yet. Run a scan.",
        "scan_history_columns": "Date and time",
        "scan_history_events": "Events",
        "scan_history_sources": "Sources",
        "scan_history_warnings": "Warnings",
        "scan_history_hash": "SHA-256",
        "scan_history_need_two": "Select exactly two snapshots to compare.",
        "scan_compare_title": "Scan comparison",
        "cancel_scan": "Cancel scan",
        "scan_cancelled": "Scan cancelled",
        "scan_cancelling": "Stopping the scan… Waiting for the current operation to finish.",
        "use_cache": "Use deep-search cache",
        "clear_cache": "Clear cache",
        "cache_cleared": "Deep-search cache cleared.",
        "verify_signature": "Verify EXE/DLL signature…",
        "signature_title": "Digital signature check",
        "signature_pick": "Choose an EXE, DLL or SYS file to verify its signature.",
        "evidence_bundle": "Evidence package…",
        "evidence_bundle_saved": "Evidence package saved.",
        "search_invalid_regex": "Invalid regular expression: {error}",
        "compare_summary": "Added events: {added}; removed events: {removed}; common: {common}.",
        "compare_files_summary": "Python files: {added} added, {removed} removed, {changed} changed.",
        "compare_process_summary": "Process snapshots: {added} added, {removed} absent from the new snapshot.",
        "compare_old_snapshot": "Older snapshot: {value}",
        "compare_new_snapshot": "Newer snapshot: {value}",
        "compare_added_sources": "Sources added: {n}",
        "compare_removed_sources": "Sources removed: {n}",
        "compare_files_heading": "NEW / CHANGED PYTHON FILES:",
        "compare_processes_heading": "PROCESS SNAPSHOT CHANGES:",
        "compare_new_events_heading": "NEW EVENTS:",
        "compare_removed_events_heading": "REMOVED EVENTS:",
        "search_command": "Search command:",
        "search_all": "Search everywhere:",
        "event_type": "Event type:",
        "all_events": "All events",
        "reset": "Reset",
        "date": "Date",
        "time": "Time",
        "description": "Description",
        "command": "Command / content",
        "source": "Data source",
        "user": "User",
        "details": "Selected record details",
        "copy_command": "Copy command",
        "copy_details": "Copy details",
        "select_event": "Select a row to view its command, source and extra details here.",
        "find_file": "Find file:",
        "file_count": "No Python files found",
        "copy_path": "Copy path",
        "open_file": "Open file",
        "choose_folder": "Add folder…",
        "snapshot": "Save snapshot",
        "compare": "Compare version",
        "file": "File",
        "modified": "Modified",
        "size": "Size",
        "type": "Type",
        "file_not_selected": "No file selected",
        "select_file": "Select a file on the left. Source files are opened read-only.",
        "process_refresh": "Refresh list",
        "process_warning": "This is a snapshot of processes running NOW. See command history for completed processes if logging was enabled beforehand.",
        "pid": "PID",
        "process": "Process",
        "parent_pid": "Parent PID",
        "started": "Started",
        "path": "Path",
        "cmdline": "Command line",
        "recovery_title": "Found traces and possible remnants",
        "recovery_note": "This view collects available clues from histories, backups, SQLite/WAL and logs. An item marked 'possible remnant' is not a confirmed recovered command. The utility does not scan unallocated disk sectors or other users' profiles.",
        "run_deep": "Run deep scan",
        "no_recovery": "No traces found for this section yet. Run a deep scan.",
        "session_notice": "Recording is off. Enable it only when you want to save commands entered in this built-in console.",
        "session_start": "Start recording",
        "session_stop": "Stop recording",
        "run_code": "Run and save",
        "clear_code": "Clear input",
        "code_input": "Enter Python code (multiple lines are supported):",
        "session_history": "Current session entries",
        "terminal": "Terminal / execution output",
        "terminal_empty": "Execution output and errors will appear here.",
        "session_warning": "Code runs in a separate Python process with your current user permissions. This is not a sandbox: run only code you trust. Input from PyCharm/CMD/PowerShell is not captured automatically.",
        "recording_on": "Recording enabled",
        "recording_off": "Recording disabled",
        "overview_events": "Events found",
        "overview_files": "Python files",
        "overview_sources": "Sources",
        "overview_warnings": "Warnings",
        "timeline": "Activity by date",
        "recent": "Recent events",
        "no_events": "No events collected yet. Click Scan.",
        "ready": "Ready to scan",
        "scanning": "Scanning…",
        "finished": "Scan completed",
        "fatal": "Scan failed",
        "footer": "Read-only for discovered sources • command recording only in built-in console • Ctrl+R to scan",
        "menu_file": "File",
        "menu_edit": "Edit",
        "menu_view": "View",
        "menu_help": "Help",
        "menu_scan": "Scan  Ctrl+R",
        "menu_csv": "Export CSV…",
        "menu_json": "Export JSON…",
        "menu_html": "HTML report…",
        "menu_exit": "Exit",
        "menu_copy_command": "Copy selected command",
        "menu_copy_details": "Copy details",
        "menu_reset": "Reset filters",
        "menu_diagnostics": "Sources and warnings",
        "menu_about": "About",
        "choose_language": "Choose interface language:",
        "saved": "Saved",
        "no_selection": "Select a record first.",
        "scan_first": "Run a scan first.",
        "process_unavailable": "Could not retrieve the process list",
        "process_count": "Processes found: {n}",
        "snapshot_saved": "File snapshot saved.",
        "no_snapshot": "No snapshot exists for this file yet.",
        "diff_title": "Comparison with latest snapshot",
        "session_confirm": "The built-in console executes Python code with your account permissions. Continue?",
        "session_started": "Session recording enabled. Entries are stored locally.",
        "session_stopped": "Session recording stopped.",
        "enter_code": "Enter Python code.",
        "session_busy": "The previous execution is still running.",
        "console_start_error": "Could not start the built-in console",
        "scan_summary": "Done: {events} events • {files} files • {sources} sources • {warnings} warnings",
        "status_only_local": "Local activity for the current user",
    },
    "uk": {
        "app_title": "Перегляд активності Python",
        "header": "ПЕРЕГЛЯД АКТИВНОСТІ PYTHON",
        "language": "Мова",
        "language_name": "Українська",
        "scan": "⟳  Сканувати",
        "export_csv": "Експорт CSV",
        "export_json": "Експорт JSON",
        "export_html": "HTML-звіт",
        "windows_logs": "Журнали Windows: запуск процесів 4688 і PowerShell 4103/4104",
        "deep_scan": "Глибокий пошук у логах, архівах і SQLite (довше)",
        "scan_state": "Стан сканування",
        "tab_overview": "Огляд",
        "tab_history": "Історія команд",
        "tab_files": "Файли Python",
        "tab_processes": "Процеси",
        "tab_recovery": "Відновлення",
        "tab_sessions": "Запис сеансу",
        "tab_timeline": "Хронологія",
        "tab_lineage": "Дерево процесів",
        "tab_scans": "Історія сканувань",
        "tab_readiness": "Готовність і повнота",
        "readiness_title": "Готовність аудиту та повнота перевірки",
        "readiness_note": "Показує поточні налаштування Windows і джерела, які вдалося перевірити. Поточне налаштування не доводить, що аудит був увімкнений раніше.",
        "readiness_refresh": "Перевірити зараз",
        "readiness_summary": "Стан готовності",
        "coverage_summary": "Повнота поточного сканування",
        "readiness_name": "Перевірка",
        "readiness_category": "Категорія",
        "readiness_status": "Стан",
        "readiness_note_col": "Пояснення",
        "readiness_detail": "Докладно про вибрану перевірку",
        "evidence_confidence": "Достовірність джерела",
        "utc_time": "Час UTC",
        "search_mode": "Режим пошуку:",
        "search_contains": "Містить",
        "search_exact": "Точний збіг",
        "search_regex": "Регулярний вираз",
        "case_sensitive": "Враховувати регістр",
        "date_from": "З дати (РРРР-ММ-ДД):",
        "date_to": "До дати:",
        "timeline_search": "Фільтр подій:",
        "timeline_empty": "Немає подій для відображення.",
        "lineage_note": "Історичні зв’язки будуються лише за збереженими подіями 4688/Sysmon. Якщо батьківської події немає, процес лишається кореневим.",
        "lineage_refresh": "Оновити дерево",
        "scan_history_note": "Знімки зберігаються локально та дозволяють порівнювати результати різних перевірок.",
        "scan_history_compare": "Порівняти вибрані",
        "scan_history_import": "Імпортувати знімок",
        "scan_history_view": "Відкрити знімок",
        "scan_history_open_title": "Вміст знімка сканування",
        "scan_history_empty": "Знімків поки немає. Виконайте сканування.",
        "scan_history_columns": "Дата й час",
        "scan_history_events": "Події",
        "scan_history_sources": "Джерела",
        "scan_history_warnings": "Попередження",
        "scan_history_hash": "SHA-256",
        "scan_history_need_two": "Виберіть рівно два знімки для порівняння.",
        "scan_compare_title": "Порівняння сканувань",
        "cancel_scan": "Зупинити сканування",
        "scan_cancelled": "Сканування скасовано",
        "scan_cancelling": "Зупиняю сканування… Очікується завершення поточної операції.",
        "use_cache": "Використовувати кеш глибокого пошуку",
        "clear_cache": "Очистити кеш",
        "cache_cleared": "Кеш глибокого пошуку очищено.",
        "verify_signature": "Перевірити підпис EXE/DLL…",
        "signature_title": "Перевірка цифрового підпису",
        "signature_pick": "Виберіть EXE, DLL або SYS-файл для перевірки підпису.",
        "evidence_bundle": "Пакет звіту…",
        "evidence_bundle_saved": "Пакет звіту збережено.",
        "search_invalid_regex": "Некоректний регулярний вираз: {error}",
        "compare_summary": "Додано подій: {added}; зникло подій: {removed}; спільних: {common}.",
        "compare_files_summary": "Python-файли: нових {added}, видалених {removed}, змінених {changed}.",
        "compare_process_summary": "Знімки процесів: додано {added}, відсутні в новому знімку {removed}.",
        "compare_old_snapshot": "Старий знімок: {value}",
        "compare_new_snapshot": "Новий знімок: {value}",
        "compare_added_sources": "Додано джерел: {n}",
        "compare_removed_sources": "Видалено джерел: {n}",
        "compare_files_heading": "НОВІ/ЗМІНЕНІ PYTHON-ФАЙЛИ:",
        "compare_processes_heading": "ЗМІНИ ЗНІМКА ПРОЦЕСІВ:",
        "compare_new_events_heading": "НОВІ ПОДІЇ:",
        "compare_removed_events_heading": "ЗНИКЛІ ПОДІЇ:",
        "search_command": "Пошук команди:",
        "search_all": "Пошук усюди:",
        "event_type": "Тип події:",
        "all_events": "Усі події",
        "reset": "Скинути",
        "date": "Дата",
        "time": "Час",
        "description": "Опис",
        "command": "Команда / вміст",
        "source": "Джерело даних",
        "user": "Користувач",
        "details": "Докладно про вибраний запис",
        "copy_command": "Копіювати команду",
        "copy_details": "Копіювати відомості",
        "select_event": "Виберіть запис у таблиці — тут з’являться команда, джерело та додаткові відомості.",
        "find_file": "Знайти файл:",
        "file_count": "Файлів Python не знайдено",
        "copy_path": "Копіювати шлях",
        "open_file": "Відкрити файл",
        "choose_folder": "Додати папку…",
        "snapshot": "Зберегти знімок",
        "compare": "Порівняти версії",
        "file": "Файл",
        "modified": "Змінено",
        "size": "Розмір",
        "type": "Тип",
        "file_not_selected": "Файл не вибрано",
        "select_file": "Виберіть файл ліворуч. Вихідний код відкривається лише для читання.",
        "process_refresh": "Оновити список",
        "process_warning": "Це знімок процесів, що працюють ЗАРАЗ. Завершені процеси дивіться в історії, якщо журнали були заздалегідь увімкнені.",
        "pid": "PID",
        "process": "Процес",
        "parent_pid": "PID батьківського",
        "started": "Запущено",
        "path": "Шлях",
        "cmdline": "Командний рядок",
        "recovery_title": "Знайдені сліди та можливі залишки",
        "recovery_note": "Тут зібрані доступні ознаки з історії, резервних копій, SQLite/WAL і журналів. Фрагмент із позначкою «можливий залишок» не є підтвердженою відновленою командою. Утиліта не сканує нерозподілені сектори диска та чужі профілі.",
        "run_deep": "Запустити глибоке сканування",
        "no_recovery": "Поки не знайдено слідів для цього розділу. Запустіть глибоке сканування.",
        "session_notice": "Запис вимкнено. Увімкніть його, лише якщо хочете зберігати команди з цієї вбудованої консолі.",
        "session_start": "Почати запис",
        "session_stop": "Зупинити запис",
        "run_code": "Виконати й зберегти",
        "clear_code": "Очистити ввід",
        "code_input": "Введіть Python-код (підтримується кілька рядків):",
        "session_history": "Записи поточного сеансу",
        "terminal": "Термінал / результат виконання",
        "terminal_empty": "Тут з’являться вивід і помилки виконання.",
        "session_warning": "Код запускається в окремому процесі Python із правами поточного користувача. Це не пісочниця: запускайте лише код, якому довіряєте. Ввід із PyCharm/CMD/PowerShell автоматично не перехоплюється.",
        "recording_on": "Запис увімкнено",
        "recording_off": "Запис вимкнено",
        "overview_events": "Знайдено подій",
        "overview_files": "Файлів Python",
        "overview_sources": "Джерел",
        "overview_warnings": "Попереджень",
        "timeline": "Активність за датами",
        "recent": "Останні події",
        "no_events": "Події ще не зібрані. Натисніть «Сканувати».",
        "ready": "Готово до сканування",
        "scanning": "Сканування…",
        "finished": "Сканування завершено",
        "fatal": "Помилка сканування",
        "footer": "Лише читання знайдених джерел • запис команд тільки у вбудованій консолі • Ctrl+R — сканувати",
        "menu_file": "Файл",
        "menu_edit": "Правка",
        "menu_view": "Вигляд",
        "menu_help": "Довідка",
        "menu_scan": "Сканувати  Ctrl+R",
        "menu_csv": "Експорт CSV…",
        "menu_json": "Експорт JSON…",
        "menu_html": "HTML-звіт…",
        "menu_exit": "Вихід",
        "menu_copy_command": "Копіювати вибрану команду",
        "menu_copy_details": "Копіювати подробиці",
        "menu_reset": "Скинути фільтри",
        "menu_diagnostics": "Джерела та попередження",
        "menu_about": "Про програму",
        "choose_language": "Виберіть мову інтерфейсу:",
        "saved": "Збережено",
        "no_selection": "Спочатку виберіть запис.",
        "scan_first": "Спочатку виконайте сканування.",
        "process_unavailable": "Не вдалося отримати список процесів",
        "process_count": "Знайдено процесів: {n}",
        "snapshot_saved": "Знімок файлу збережено.",
        "no_snapshot": "Для цього файлу ще немає знімка.",
        "diff_title": "Порівняння з останнім знімком",
        "session_confirm": "Вбудована консоль запускає Python-код із правами вашого облікового запису. Продовжити?",
        "session_started": "Запис сеансу увімкнено. Записи зберігаються локально.",
        "session_stopped": "Запис сеансу зупинено.",
        "enter_code": "Введіть Python-код.",
        "session_busy": "Попереднє виконання ще обробляється.",
        "console_start_error": "Не вдалося запустити вбудовану консоль",
        "scan_summary": "Готово: {events} подій • {files} файлів • {sources} джерел • {warnings} попереджень",
        "status_only_local": "Локальна активність поточного користувача",
    },
}


# Administrator / UAC controls. The app never bypasses UAC; it uses the
# standard Windows ShellExecute("runas") verb and otherwise stays unelevated.
ADMIN_TRANSLATIONS = {
    "ru": {
        "menu_system": "Система",
        "admin_restart": "Перезапустить от имени администратора…",
        "admin_enabled": "Права администратора включены",
        "admin_auto": "Запрашивать права администратора при запуске",
        "admin_auto_on": "Автозапрос UAC включён. Настройка действует при следующем запуске.",
        "admin_auto_off": "Автозапрос UAC выключен. Текущий уровень прав не изменён.",
        "admin_info": "Сведения о правах доступа…",
        "admin_info_title": "Права доступа",
        "admin_info_body": "Программа использует обычный запрос UAC Windows. Повышение прав может открыть доступ к некоторым системным журналам и защищённым каталогам, но не включает аудит задним числом и не восстанавливает данные, которые не были сохранены.",
        "admin_state_yes": "Текущий процесс запущен с правами администратора.",
        "admin_state_no": "Текущий процесс запущен без повышенных прав.",
        "admin_restart_confirm": "Будет запущена новая копия программы. После успешного запуска текущая копия закроется. Продолжить?",
        "admin_restart_failed": "Не удалось запросить повышение прав (код ShellExecute: {code}). Возможно, запрос UAC был отменён.",
        "admin_not_supported": "Повышение прав через UAC доступно только в Windows.",
        "admin_already": "Программа уже запущена от имени администратора.",
        "admin_auto_note": "Автоматический запрос не обходит UAC: Windows всё равно покажет стандартное подтверждение.",
    },
    "en": {
        "menu_system": "System",
        "admin_restart": "Restart as administrator…",
        "admin_enabled": "Administrator rights enabled",
        "admin_auto": "Request administrator rights at startup",
        "admin_auto_on": "Automatic UAC request enabled. This setting takes effect on the next launch.",
        "admin_auto_off": "Automatic UAC request disabled. The current permission level is unchanged.",
        "admin_info": "Permission information…",
        "admin_info_title": "Permissions",
        "admin_info_body": "The app uses the standard Windows UAC prompt. Elevation may provide access to some system logs and protected folders, but it does not enable auditing retroactively or recover data that was never saved.",
        "admin_state_yes": "This process is running with administrator privileges.",
        "admin_state_no": "This process is running without elevated privileges.",
        "admin_restart_confirm": "A new copy of the app will be started. The current copy will close after the new one starts successfully. Continue?",
        "admin_restart_failed": "Could not request elevation (ShellExecute code: {code}). The UAC request may have been cancelled.",
        "admin_not_supported": "UAC elevation is available only on Windows.",
        "admin_already": "The app is already running as administrator.",
        "admin_auto_note": "Automatic prompting does not bypass UAC: Windows will still show its standard confirmation.",
    },
    "uk": {
        "menu_system": "Система",
        "admin_restart": "Перезапустити від імені адміністратора…",
        "admin_enabled": "Права адміністратора увімкнено",
        "admin_auto": "Запитувати права адміністратора під час запуску",
        "admin_auto_on": "Автоматичний запит UAC увімкнено. Налаштування почне діяти під час наступного запуску.",
        "admin_auto_off": "Автоматичний запит UAC вимкнено. Поточний рівень прав не змінено.",
        "admin_info": "Відомості про права доступу…",
        "admin_info_title": "Права доступу",
        "admin_info_body": "Програма використовує стандартний запит UAC Windows. Підвищення прав може відкрити доступ до деяких системних журналів і захищених каталогів, але не вмикає аудит заднім числом і не відновлює дані, які не були збережені.",
        "admin_state_yes": "Поточний процес запущено з правами адміністратора.",
        "admin_state_no": "Поточний процес запущено без підвищених прав.",
        "admin_restart_confirm": "Буде запущено нову копію програми. Після успішного запуску поточна копія закриється. Продовжити?",
        "admin_restart_failed": "Не вдалося запросити підвищення прав (код ShellExecute: {code}). Можливо, запит UAC скасовано.",
        "admin_not_supported": "Підвищення прав через UAC доступне лише у Windows.",
        "admin_already": "Програму вже запущено від імені адміністратора.",
        "admin_auto_note": "Автоматичний запит не обходить UAC: Windows все одно покаже стандартне підтвердження.",
    },
}
for _lang_code, _entries in ADMIN_TRANSLATIONS.items():
    LANGUAGE_TEXT[_lang_code].update(_entries)


FORENSIC_TRANSLATIONS = {
    "ru": {
        "tab_forensics": "Анализ системных следов",
        "forensic_title": "Локальный анализ запусков Python и связанных системных событий",
        "forensic_notice": "Анализ выполняется на компьютере, где запущена программа. Ищет доступные следы запусков Python и дочерних процессов в Windows 4688, Sysmon (если он уже установлен), PowerShell, Prefetch, Defender и журналах AnyDesk как дополнительном источнике. Не записывает клавиатуру, не изменяет исходные журналы.",
        "forensic_consent": "Владелец компьютера согласен на локальный просмотр перечисленных системных журналов и файлов",
        "forensic_start": "Начать анализ",
        "forensic_export": "Сохранить отчёт анализа…",
        "forensic_status_ready": "Анализ ещё не запускался",
        "forensic_status_running": "Выполняется анализ…",
        "forensic_status_done": "Анализ завершён: {events} событий • {sources} источников • {warnings} предупреждений",
        "forensic_status_need_consent": "Перед началом необходимо подтвердить согласие владельца компьютера.",
        "forensic_col_time": "Дата и время",
        "forensic_col_category": "Категория",
        "forensic_col_event": "Событие",
        "forensic_col_source": "Источник",
        "forensic_details": "Подробности выбранной находки",
        "forensic_search": "Поиск по команде, процессу или источнику:",
        "forensic_search_hint": "Например: python, -c, cmd.exe, powershell…",
        "forensic_clear_search": "Очистить",
        "forensic_empty": "Событий пока нет. Запустите анализ после согласия владельца компьютера.",
        "forensic_no_result": "Сначала выполните анализ.",
        "forensic_saved": "Отчёт анализа сохранён",
        "forensic_scope": "Важно: это универсальный анализатор, не привязанный к конкретной игре или программе. 4688/Sysmon могут показать запуск Python и процессы, созданные им, но только если соответствующее журналирование уже велось. Внутренний ввод Python не записывается автоматически. Найденные события — технические следы, а не готовый вывод о нарушении.",
        "forensic_export_title": "Сохранить отчёт анализа",
        "forensic_file_type": "Отчёт JSON",
    },
    "en": {
        "tab_forensics": "System trace analysis",
        "forensic_title": "Local analysis of Python launches and related system events",
        "forensic_notice": "Analysis runs on the computer where this app is launched. It checks available traces of Python launches and child processes in Windows 4688, Sysmon (if already installed), PowerShell, Prefetch, Defender and AnyDesk logs as an optional source. It does not record keystrokes or modify source logs.",
        "forensic_consent": "The computer owner consents to local review of the listed system logs and files",
        "forensic_start": "Start analysis",
        "forensic_export": "Save analysis report…",
        "forensic_status_ready": "Analysis has not started",
        "forensic_status_running": "Analysis in progress…",
        "forensic_status_done": "Analysis complete: {events} events • {sources} sources • {warnings} warnings",
        "forensic_status_need_consent": "Confirm the computer owner's consent before starting.",
        "forensic_col_time": "Date and time",
        "forensic_col_category": "Category",
        "forensic_col_event": "Event",
        "forensic_col_source": "Source",
        "forensic_details": "Selected finding details",
        "forensic_search": "Search command, process or source:",
        "forensic_search_hint": "For example: python, -c, cmd.exe, powershell…",
        "forensic_clear_search": "Clear",
        "forensic_empty": "No events yet. Start analysis after the computer owner consents.",
        "forensic_no_result": "Run an analysis first.",
        "forensic_saved": "Analysis report saved",
        "forensic_scope": "This is a general-purpose analyzer, not tied to a game or specific program. 4688/Sysmon may show Python launches and child processes only if logging was already enabled. Python interactive input is not recorded automatically. Findings are technical traces, not a verdict.",
        "forensic_export_title": "Save analysis report",
        "forensic_file_type": "JSON report",
    },
    "uk": {
        "tab_forensics": "Аналіз системних слідів",
        "forensic_title": "Локальний аналіз запусків Python і пов’язаних системних подій",
        "forensic_notice": "Аналіз виконується на комп’ютері, де запущено програму. Шукає доступні сліди запусків Python і дочірніх процесів у Windows 4688, Sysmon (якщо він уже встановлений), PowerShell, Prefetch, Defender та журналах AnyDesk як додатковому джерелі. Не записує клавіатуру, не читає паролі й не змінює вихідні журнали.",
        "forensic_consent": "Власник комп’ютера погоджується на локальний перегляд перелічених системних журналів і файлів",
        "forensic_start": "Почати аналіз",
        "forensic_export": "Зберегти звіт аналізу…",
        "forensic_status_ready": "Аналіз ще не запускали",
        "forensic_status_running": "Триває аналіз…",
        "forensic_status_done": "Аналіз завершено: {events} подій • {sources} джерел • {warnings} попереджень",
        "forensic_status_need_consent": "Перед початком потрібно підтвердити згоду власника комп’ютера.",
        "forensic_col_time": "Дата й час",
        "forensic_col_category": "Категорія",
        "forensic_col_event": "Подія",
        "forensic_col_source": "Джерело",
        "forensic_details": "Докладно про вибрану знахідку",
        "forensic_search": "Пошук за командою, процесом або джерелом:",
        "forensic_search_hint": "Наприклад: python, -c, cmd.exe, powershell…",
        "forensic_clear_search": "Очистити",
        "forensic_empty": "Подій поки немає. Запустіть аналіз після згоди власника комп’ютера.",
        "forensic_no_result": "Спочатку виконайте аналіз.",
        "forensic_saved": "Звіт аналізу збережено",
        "forensic_scope": "Це універсальний аналізатор, не прив’язаний до гри чи конкретної програми. 4688/Sysmon можуть показати запуск Python і створені ним процеси лише якщо журналювання вже було ввімкнено. Внутрішнє введення Python автоматично не записується. Знахідки — технічні сліди, а не готовий висновок.",
        "forensic_export_title": "Зберегти звіт аналізу",
        "forensic_file_type": "Звіт JSON",
    },
}
for _lang_code, _entries in FORENSIC_TRANSLATIONS.items():
    LANGUAGE_TEXT[_lang_code].update(_entries)

INVESTIGATION_TRANSLATIONS = {
    "ru": {
        "tab_browser": "История браузеров", "tab_downloads": "Загрузки", "tab_runtime": "Python ↔ Java",
        "tab_java": "Java Activity", "tab_suspicious": "Подозрительная активность", "tab_cleanup": "Признаки очистки", "tab_final_report": "Итоговый отчёт",
        "browser_history_enabled": "Читать историю браузеров (только чтение; может содержать личные URL)",
        "browser_title": "Локальная история браузеров и загрузок",
        "browser_note": "История читается из SQLite-баз Chrome, Edge, Brave, Opera, Vivaldi, Chromium и Firefox текущего профиля. База копируется во временный каталог; пароли, cookies и переписка не читаются. Неизвестный домен не считается подозрительным без пользовательского правила.",
        "browser_scan_now": "Сканировать историю браузеров",
        "browser_scan_hint": "Отдельная проверка браузерных профилей текущего пользователя. Читаются только URL, заголовки посещений и метаданные загрузок; пароли и cookies не читаются.",
        "browser_scan_pending": "История ещё не проверялась. Нажми «Сканировать историю браузеров».",
        "browser_scan_running": "Читаю профили браузеров… Можно остановить кнопкой «Остановить сканирование».",
        "browser_scan_done": "Профилей: {profiles} · посещений: {visits} · загрузок: {downloads} · проблемы/не найдено/пропущено: {issues}",
        "browser_scan_cancelled": "Проверка истории браузеров отменена; частичные результаты не добавлены.",
        "browser_scan_failed": "Ошибка проверки истории браузеров: {error}",
        "browser_scan_busy": "Сейчас уже выполняется другая проверка.",
        "browser_search": "Фильтр по URL, домену, браузеру или файлу:", "browser_domains": "Пользовательские категории доменов",
        "browser_domain_placeholder": "https://site1.com, site2.com : https://site3.com", "browser_category": "Категория", "browser_add": "Добавить / обновить",
        "browser_remove": "Удалить правило", "browser_col_time": "Время", "browser_col_browser": "Браузер / профиль",
        "browser_col_type": "Тип", "browser_col_domain": "Домен", "browser_col_category": "Категория",
        "browser_col_title": "Заголовок / файл", "browser_col_source": "Источник",
        "cat_ordinary": "Обычный сайт", "cat_unknown": "Неизвестный сайт", "cat_suspicious": "Подозрительный сайт",
        "cat_distribution": "Распространение стороннего ПО", "browser_empty": "История браузеров ещё не просканирована.",
        "browser_rules_hint": "Можно вставить сразу несколько URL или доменов. Разделители: запятая, точка с запятой, новая строка или двоеточие между ссылками. Порты (например :8080) сохраняются. Правило действует для поддоменов.",
        "browser_rule_saved": "Правило домена сохранено", "browser_rule_invalid": "Не найдено корректных доменов. Проверь ссылки и разделители.",
        "browser_rules_result": "Добавлено: {added} · обновлено: {updated} · без изменений: {unchanged} · некорректно пропущено: {invalid}",
        "browser_rules_invalid_skipped": "Некорректные фрагменты пропущены:",
        "browser_rule_selected": "Выбери правило в таблице.", "runtime_title": "Сопоставление сохранённых запусков Python и Java",
        "runtime_note": "Показываются только найденные события запуска/завершения из журналов Windows и других источников. Если завершение процесса не сохранилось, одновременная работа не утверждается. Java — обычная часть Minecraft и других приложений.",
        "runtime_summary": "Сводка процессов", "runtime_relation": "Связь / состояние", "runtime_confidence": "Достоверность связи",
        "runtime_col_time": "Время запуска", "runtime_col_family": "Runtime", "runtime_col_pid": "PID", "runtime_col_parent": "Parent PID",
        "runtime_col_state": "Результат сопоставления", "runtime_col_command": "Командная строка", "runtime_col_source": "Источник",
        "risk_not_run": "Оценка совокупности признаков появится после сканирования.",
        "risk_label": "Оценка", "risk_points": "условных баллов", "risk_note": "Это ориентир для ручной проверки, не вероятность и не вердикт.",
        "java_title": "Найденные запуски Java", "java_note": "Показываются только сохранённые события Java. Обычный запуск Minecraft/лаунчера сам по себе не подозрителен.",
        "suspicious_title": "События, требующие ручной проверки", "suspicious_note": "Список формируется из пользовательских меток доменов, временного контекста, совпадений путей и сохранённых связей процессов. Это не вывод о нарушении.",
        "cleanup_title": "Сохранённые индикаторы очистки и пробелы источников", "cleanup_note": "События очистки журналов показываются отдельно. Отсутствие истории браузера, разрывы во времени или недоступность источника не доказывают удаление.",
        "final_report_title": "Сводный результат проверки", "final_report_note": "Сводка основана только на доступных локальных источниках. Перед передачей отчёта проверьте URL, пути, команды и имена пользователей.",
    },
    "en": {
        "tab_browser": "Browser history", "tab_downloads": "Downloads", "tab_runtime": "Python ↔ Java",
        "tab_java": "Java Activity", "tab_suspicious": "Suspicious activity", "tab_cleanup": "Cleanup indicators", "tab_final_report": "Final report",
        "browser_history_enabled": "Read browser history (read-only; may contain personal URLs)",
        "browser_title": "Local browser history and downloads",
        "browser_note": "Reads SQLite history from Chrome, Edge, Brave, Opera, Vivaldi, Chromium and Firefox profiles for the current user. Databases are copied to a temporary folder; passwords, cookies and messages are not read. Unknown domains are not suspicious without a user rule.",
        "browser_scan_now": "Scan browser history",
        "browser_scan_hint": "Scans browser profiles for the current user only. Reads visit URLs, page titles and download metadata; passwords and cookies are not read.",
        "browser_scan_pending": "History has not been checked yet. Select “Scan browser history”.",
        "browser_scan_running": "Reading browser profiles… Use “Cancel scan” to stop.",
        "browser_scan_done": "Profiles: {profiles} · visits: {visits} · downloads: {downloads} · issues/not found/skipped: {issues}",
        "browser_scan_cancelled": "Browser history scan cancelled; partial results were discarded.",
        "browser_scan_failed": "Browser history scan failed: {error}",
        "browser_scan_busy": "Another scan is already running.",
        "browser_search": "Filter URL, domain, browser or file:", "browser_domains": "User-defined domain categories",
        "browser_domain_placeholder": "https://site1.com, site2.com : https://site3.com", "browser_category": "Category", "browser_add": "Add / update",
        "browser_remove": "Remove rule", "browser_col_time": "Time", "browser_col_browser": "Browser / profile",
        "browser_col_type": "Type", "browser_col_domain": "Domain", "browser_col_category": "Category",
        "browser_col_title": "Title / file", "browser_col_source": "Source",
        "cat_ordinary": "Ordinary site", "cat_unknown": "Unknown site", "cat_suspicious": "Suspicious site",
        "cat_distribution": "Third-party software distribution", "browser_empty": "Browser history has not been scanned yet.",
        "browser_rules_hint": "Paste multiple URLs or domains at once. Separators: comma, semicolon, newline, or a colon between links. Ports (for example :8080) are preserved. Rules also apply to subdomains.",
        "browser_rule_saved": "Domain rule saved", "browser_rule_invalid": "No valid domains were found. Check the URLs and separators.",
        "browser_rules_result": "Added: {added} · updated: {updated} · unchanged: {unchanged} · invalid skipped: {invalid}",
        "browser_rules_invalid_skipped": "Invalid fragments were skipped:",
        "browser_rule_selected": "Select a rule in the table.", "runtime_title": "Correlation of retained Python and Java process starts",
        "runtime_note": "Only retained process start/termination records are shown. If termination records are missing, simultaneous execution is not asserted. Java is a normal part of Minecraft and many other applications.",
        "runtime_summary": "Process summary", "runtime_relation": "Relationship / state", "runtime_confidence": "Link confidence",
        "runtime_col_time": "Start time", "runtime_col_family": "Runtime", "runtime_col_pid": "PID", "runtime_col_parent": "Parent PID",
        "runtime_col_state": "Correlation result", "runtime_col_command": "Command line", "runtime_col_source": "Source",
        "risk_not_run": "Combined-evidence assessment appears after a scan.",
        "risk_label": "Assessment", "risk_points": "heuristic points", "risk_note": "This is a manual-review aid, not a probability or verdict.",
    },
    "uk": {
        "tab_browser": "Історія браузерів", "tab_downloads": "Завантаження", "tab_runtime": "Python ↔ Java",
        "tab_java": "Java Activity", "tab_suspicious": "Підозріла активність", "tab_cleanup": "Ознаки очищення", "tab_final_report": "Підсумковий звіт",
        "browser_history_enabled": "Читати історію браузерів (лише читання; може містити особисті URL)",
        "browser_title": "Локальна історія браузерів і завантажень",
        "browser_note": "Історія читається з SQLite-баз Chrome, Edge, Brave, Opera, Vivaldi, Chromium і Firefox поточного профілю. База копіюється в тимчасовий каталог; паролі, cookies та листування не читаються. Невідомий домен не вважається підозрілим без правила користувача.",
        "browser_scan_now": "Сканувати історію браузерів",
        "browser_scan_hint": "Окрема перевірка профілів браузерів поточного користувача. Читаються URL, заголовки відвідувань і метадані завантажень; паролі та cookies не читаються.",
        "browser_scan_pending": "Історію ще не перевіряли. Натисни «Сканувати історію браузерів».",
        "browser_scan_running": "Читаю профілі браузерів… Зупинити можна кнопкою «Зупинити сканування».",
        "browser_scan_done": "Профілів: {profiles} · відвідувань: {visits} · завантажень: {downloads} · проблем/не знайдено/пропущено: {issues}",
        "browser_scan_cancelled": "Перевірку історії браузерів скасовано; часткові результати не додано.",
        "browser_scan_failed": "Помилка перевірки історії браузерів: {error}",
        "browser_scan_busy": "Зараз уже виконується інша перевірка.",
        "browser_search": "Фільтр за URL, доменом, браузером або файлом:", "browser_domains": "Користувацькі категорії доменів",
        "browser_domain_placeholder": "https://site1.com, site2.com : https://site3.com", "browser_category": "Категорія", "browser_add": "Додати / оновити",
        "browser_remove": "Видалити правило", "browser_col_time": "Час", "browser_col_browser": "Браузер / профіль",
        "browser_col_type": "Тип", "browser_col_domain": "Домен", "browser_col_category": "Категорія",
        "browser_col_title": "Заголовок / файл", "browser_col_source": "Джерело",
        "cat_ordinary": "Звичайний сайт", "cat_unknown": "Невідомий сайт", "cat_suspicious": "Підозрілий сайт",
        "cat_distribution": "Поширення стороннього ПЗ", "browser_empty": "Історію браузерів ще не проскановано.",
        "browser_rules_hint": "Можна вставити кілька URL або доменів. Роздільники: кома, крапка з комою, новий рядок або двокрапка між посиланнями. Порти (наприклад :8080) зберігаються. Правило діє також для піддоменів.",
        "browser_rule_saved": "Правило домену збережено", "browser_rule_invalid": "Не знайдено коректних доменів. Перевір посилання та роздільники.",
        "browser_rules_result": "Додано: {added} · оновлено: {updated} · без змін: {unchanged} · некоректних пропущено: {invalid}",
        "browser_rules_invalid_skipped": "Некоректні фрагменти пропущено:",
        "browser_rule_selected": "Вибери правило в таблиці.", "runtime_title": "Зіставлення збережених запусків Python і Java",
        "runtime_note": "Показуються лише знайдені записи запуску/завершення з журналів Windows та інших джерел. Якщо завершення процесу не збереглося, одночасна робота не стверджується. Java — звичайна частина Minecraft та інших програм.",
        "runtime_summary": "Зведення процесів", "runtime_relation": "Зв’язок / стан", "runtime_confidence": "Достовірність зв’язку",
        "runtime_col_time": "Час запуску", "runtime_col_family": "Runtime", "runtime_col_pid": "PID", "runtime_col_parent": "Parent PID",
        "runtime_col_state": "Результат зіставлення", "runtime_col_command": "Командний рядок", "runtime_col_source": "Джерело",
        "risk_not_run": "Оцінка сукупності ознак з’явиться після сканування.",
        "risk_label": "Оцінка", "risk_points": "умовних балів", "risk_note": "Це орієнтир для ручної перевірки, не ймовірність і не вердикт.",
        "java_title": "Збережені запуски Java", "java_note": "Показуються лише збережені події Java. Звичайний запуск Minecraft/лаунчера сам по собі не є підозрілим.",
        "suspicious_title": "Події для ручної перевірки", "suspicious_note": "Список враховує користувацькі мітки доменів, часовий контекст, збіги шляхів і збережені зв’язки процесів. Це не висновок про порушення.",
        "cleanup_title": "Збережені індикатори очищення та прогалини джерел", "cleanup_note": "Події очищення журналів показано окремо. Відсутність історії браузера, часові прогалини або недоступність джерела не доводять видалення.",
        "final_report_title": "Зведений результат перевірки", "final_report_note": "Зведення базується лише на доступних локальних джерелах. Перевірте URL, шляхи, команди та імена користувачів перед передаванням звіту.",
    },
}
for _lang_code, _entries in INVESTIGATION_TRANSLATIONS.items():
    LANGUAGE_TEXT[_lang_code].update(_entries)

SESSION_WORKER_SOURCE = r"""import ast, contextlib, io, json, sys, traceback, builtins
namespace = {"__name__": "__main__"}
protocol = sys.__stdout__
def no_interactive_input(prompt=""):
    raise EOFError("input() is disabled in the Activity View console; use a file or a dedicated input UI")
builtins.input = no_interactive_input
for raw in sys.stdin:
    try:
        request = json.loads(raw)
        source = request.get("code", "")
        out = io.StringIO()
        err = io.StringIO()
        status = "ok"
        try:
            tree = ast.parse(source, filename="<Python Activity View session>", mode="exec")
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                if tree.body and isinstance(tree.body[-1], ast.Expr):
                    before = ast.Module(body=tree.body[:-1], type_ignores=[])
                    if before.body:
                        exec(compile(ast.fix_missing_locations(before), "<PAV session>", "exec"), namespace, namespace)
                    expression = ast.Expression(body=tree.body[-1].value)
                    value = eval(compile(ast.fix_missing_locations(expression), "<PAV session>", "eval"), namespace, namespace)
                    if value is not None:
                        print(repr(value))
                else:
                    exec(compile(tree, "<PAV session>", "exec"), namespace, namespace)
        except BaseException:
            status = "error"
            traceback.print_exc(file=err)
        response = {"status": status, "stdout": out.getvalue(), "stderr": err.getvalue()}
        protocol.write(json.dumps(response, ensure_ascii=False) + "\n")
        protocol.flush()
    except BaseException as exc:
        protocol.write(json.dumps({"status":"fatal","stdout":"","stderr":repr(exc)}, ensure_ascii=False) + "\n")
        protocol.flush()
"""


def app_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    root = Path(base) / "PythonActivityView" if base else Path.home() / ".python_activity_view"
    root.mkdir(parents=True, exist_ok=True)
    return root


def is_windows_admin() -> bool:
    """Return True when this process has an elevated Windows token."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def request_windows_elevation(extra_args: list[str] | None = None) -> tuple[bool, int | None]:
    """Start a new elevated copy through the standard UAC consent dialog."""
    if os.name != "nt":
        return False, None
    try:
        import ctypes
        script = Path(__file__).resolve()
        is_frozen = bool(getattr(sys, "frozen", False))
        args = list(extra_args if extra_args is not None else sys.argv[1:])
        if not is_frozen:
            args.insert(0, str(script))
        parameters = subprocess.list2cmdline(args)
        working_directory = Path(sys.executable).resolve().parent if is_frozen else script.parent
        shell32 = ctypes.windll.shell32
        shell32.ShellExecuteW.argtypes = [
            ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_int,
        ]
        shell32.ShellExecuteW.restype = ctypes.c_void_p
        result = shell32.ShellExecuteW(
            None,
            "runas",
            str(Path(sys.executable).resolve()),
            parameters,
            str(working_directory),
            1,
        )
        numeric = int(result or 0)
        return numeric > 32, numeric
    except Exception:
        return False, None


def load_auto_admin_setting() -> bool:
    """Read the user's opt-in auto-UAC preference without creating app state."""
    try:
        settings_file = app_data_dir() / "settings.json"
        if settings_file.is_file():
            value = json.loads(settings_file.read_text(encoding="utf-8"))
            return bool(value.get("auto_admin", False)) if isinstance(value, dict) else False
    except Exception:
        pass
    return False


def get_running_python_related_processes() -> tuple[list[dict[str, Any]], list[str]]:
    """Read a current process snapshot; this is not a historical process log."""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name == "nt":
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if ps:
            script = (
                "$names = 'python.exe','pythonw.exe','py.exe','pycharm64.exe','pycharm.exe',"
                "'cmd.exe','powershell.exe','pwsh.exe','Code.exe','jupyter.exe','jupyter-lab.exe','jupyter-notebook.exe';"
                "Get-CimInstance Win32_Process | Where-Object { $names -contains $_.Name } | "
                "Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate | "
                "ConvertTo-Json -Compress"
            )
            try:
                proc = subprocess.run(
                    [ps, "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True, text=False, timeout=15,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                ps_stdout, _ps_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
                ps_stderr, _ps_error_encoding = decode_text_bytes(proc.stderr or b"", prefer_oem=True)
                if proc.returncode == 0 and ps_stdout.strip():
                    payload = json.loads(ps_stdout.strip())
                    if isinstance(payload, dict):
                        payload = [payload]
                    for item in payload or []:
                        rows.append({
                            "name": item.get("Name", ""),
                            "pid": item.get("ProcessId", ""),
                            "parent_pid": item.get("ParentProcessId", ""),
                            "path": item.get("ExecutablePath", "") or "",
                            "command_line": str(item.get("CommandLine", "") or ""),
                            "started": str(item.get("CreationDate", "") or ""),
                            "snapshot_time": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"),
                        })
                    return rows, warnings
                warnings.append((ps_stderr or "PowerShell did not return process data").strip())
            except Exception as exc:
                warnings.append(str(exc))
        try:
            proc = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=False, timeout=10)
            tasklist_text, _tasklist_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
            import csv as _csv
            import io as _io
            wanted = {"python.exe", "pythonw.exe", "py.exe", "pycharm64.exe", "pycharm.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "code.exe", "jupyter.exe"}
            for row in _csv.reader(_io.StringIO(tasklist_text)):
                if len(row) >= 2 and row[0].casefold() in wanted:
                    rows.append({"name": row[0], "pid": row[1], "parent_pid": "", "path": "", "command_line": "", "started": "", "snapshot_time": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")})
        except Exception as exc:
            warnings.append(str(exc))
    else:
        try:
            proc = subprocess.run(["ps", "-eo", "pid=,ppid=,lstart=,args="], capture_output=True, text=True, timeout=10)
            for line in proc.stdout.splitlines():
                if re.search(r"(?i)(python|pycharm|code|jupyter|powershell|pwsh|\bcmd\b)", line):
                    parts = line.strip().split(None, 7)
                    if len(parts) >= 6:
                        rows.append({"pid": parts[0], "parent_pid": parts[1], "started": " ".join(parts[2:7]), "name": Path(parts[-1].split()[0]).name, "path": "", "command_line": str(" ".join(parts[7:]) if len(parts) > 7 else parts[-1]), "snapshot_time": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")})
        except Exception as exc:
            warnings.append(str(exc))
    return rows, warnings


class PythonActivityViewPro(PythonActivityView):
    def __init__(self, root: tk.Tk, include_windows_events: bool = False):
        settings_path = app_data_dir() / "settings.json"
        try:
            self.settings_path = settings_path
            self.settings = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.exists() else {}
        except Exception:
            self.settings = {}
            self.settings_path = settings_path
        self.lang = self.settings.get("language", "ru")
        self.is_admin = is_windows_admin()
        self.auto_admin_var = tk.BooleanVar(master=root, value=bool(self.settings.get("auto_admin", False)))
        if self.lang not in LANGUAGE_TEXT:
            self.lang = "ru"
        self.process_queue: queue.Queue = queue.Queue()
        self.folder_queue: queue.Queue = queue.Queue()
        self.session_queue: queue.Queue = queue.Queue()
        self.process_rows: list[dict[str, Any]] = []
        self.session_process: subprocess.Popen | None = None
        self.session_active = False
        self.session_busy = False
        self.session_id = ""
        self.session_file: Path | None = None
        self.session_rows: list[dict[str, Any]] = []
        self.snapshot_root = app_data_dir() / "file_snapshots"
        self.snapshot_root.mkdir(parents=True, exist_ok=True)
        self._last_recovery_rows: list[dict[str, Any]] = []
        self.last_progress_payload: dict[str, Any] | None = None
        self.forensic_queue: queue.Queue = queue.Queue()
        self.signature_queue: queue.Queue = queue.Queue()
        self.forensic_rows: list[dict[str, Any]] = []
        self.forensic_sources: list[dict[str, Any]] = []
        self.forensic_warnings: list[str] = []
        self.forensic_scan_info: dict[str, Any] = {}
        self.signature_checks: list[dict[str, Any]] = []
        self.forensic_scanning = False
        self.readiness_queue: queue.Queue = queue.Queue()
        self.readiness_scanning = False
        self.readiness_report: dict[str, Any] = {}
        self.coverage_report: dict[str, Any] = {}
        self.analysis_quality: dict[str, Any] = {}
        self.readiness_rows: list[dict[str, Any]] = []
        self.forensic_consent_var = tk.BooleanVar(master=root, value=False)
        initial_forensic_status = {
            "ru": "Анализ ещё не запускался",
            "en": "Analysis has not started",
            "uk": "Аналіз ще не запускали",
        }.get(self.lang, "Анализ ещё не запускался")
        self.forensic_status_var = tk.StringVar(master=root, value=initial_forensic_status)
        self.forensic_progress_var = tk.StringVar(master=root, value="")
        self.forensic_search_var = tk.StringVar(master=root, value="")
        # Controls used by the optional browser-history and runtime tabs must
        # exist before the base constructor builds the translated UI.
        self.browser_history_var = tk.BooleanVar(master=root, value=False)
        self.browser_search_var = tk.StringVar(master=root, value="")
        self.browser_domain_var = tk.StringVar(master=root, value="")
        self.browser_rule_category_var = tk.StringVar(master=root, value="unknown")
        self.browser_scan_status_var = tk.StringVar(master=root, value="")
        self._active_scan_kind = ""
        self.download_search_var = tk.StringVar(master=root, value="")
        self.scan_profile_var = tk.StringVar(master=root, value=str(self.settings.get("scan_profile", "standard")))
        self.artifact_queue: queue.Queue = queue.Queue()
        self.artifact_job_active = False
        self.artifact_job_kind = ""
        self.artifact_sources: list[dict[str, Any]] = []
        self.artifact_events: list[dict[str, Any]] = []
        self.artifact_details: dict[str, Any] = {}
        self.trusted_paths: list[str] = list(self.settings.get("trusted_paths", []))
        self.plugin_registry = PluginRegistry(app_data_dir() / "plugins")
        self.case_dir = app_data_dir() / "cases"
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.case_name_var = tk.StringVar(master=root, value="Проверка без названия" if self.lang == "ru" else ("Unnamed case" if self.lang == "en" else "Перевірка без назви"))
        self.case_notes_initial = ""
        self.case_notes_file = self.case_dir / "current_case.json"
        self.active_case_file = self.case_notes_file
        self.case_payload = create_case_payload(self.case_name_var.get())
        self.case_verification: dict[str, Any] = {}
        self.case_evidence_rows: list[dict[str, Any]] = []
        try:
            if self.case_notes_file.exists():
                self.case_payload = load_case_payload(self.case_notes_file)
                self.case_name_var.set(str(self.case_payload.get("name", self.case_name_var.get())))
                self.case_notes_initial = str(self.case_payload.get("notes", ""))
        except Exception:
            # Do not block startup on a damaged legacy notes file. Keep it untouched
            # and start an empty case; diagnostics will still expose file errors.
            self.case_payload = create_case_payload(self.case_name_var.get())
        super().__init__(root, include_windows_events=include_windows_events)
        self._install_keyboard_shortcuts()
        self._install_edit_context_menus()
        self._configure_compact_tables()
        self.root.bind_all("<Control-f>", self.open_global_search, add="+")
        self.root.bind_all("<Control-F>", self.open_global_search, add="+")
        saved_geometry = str(self.settings.get("window_geometry", ""))
        if re.fullmatch(r"\d{3,5}x\d{3,5}(?:[+-]\d{1,5}){0,2}", saved_geometry):
            try:
                self.root.geometry(saved_geometry)
            except tk.TclError:
                pass
        self.root.title(f"{self.T('app_title')} {APP_VERSION}")
        self.root.protocol("WM_DELETE_WINDOW", self.close_application)
        self.root.after(300, self.load_saved_session_entries)
        self.root.after(650, self.refresh_scan_history)
        self.root.after(900, self.refresh_processes)

    def T(self, key: str, **kwargs: Any) -> str:
        text_value = LANGUAGE_TEXT.get(self.lang, LANGUAGE_TEXT["ru"]).get(key, LANGUAGE_TEXT["ru"].get(key, key))
        try:
            return text_value.format(**kwargs)
        except Exception:
            return text_value

    def localize_kind(self, value: str) -> str:
        text_value = str(value or "")
        if self.lang == "ru":
            return text_value
        mapping = {
            "PyCharm Python Console": "PyCharm Python Console command" if self.lang == "en" else "Команда PyCharm Python Console",
            "CMD: текущая история Doskey": "CMD: current Doskey history" if self.lang == "en" else "CMD: поточна історія Doskey",
            "Активный процесс Python / IDE / терминала": "Active Python / IDE / terminal process" if self.lang == "en" else "Активний процес Python / IDE / термінала",
            "Python REPL history": "Python REPL history",
            "Python history backup": "Python history backup" if self.lang == "en" else "Резервна копія історії Python",
            "IPython session": "IPython session" if self.lang == "en" else "Сеанс IPython",
            "IPython / Jupyter history": "IPython / Jupyter history" if self.lang == "en" else "Історія IPython / Jupyter",
            "PowerShell: команда Python": "PowerShell: Python command" if self.lang == "en" else "PowerShell: команда Python",
            "PowerShell transcript: Python": "PowerShell transcript: Python",
            "CMD: команда Python (Doskey)": "CMD: Python command (Doskey)" if self.lang == "en" else "CMD: команда Python (Doskey)",
            "Windows Prefetch: Python": "Windows Prefetch: Python",
            "Возможный остаток команды SQLite (неподтверждённый)": "Possible SQLite command remnant (unconfirmed)" if self.lang == "en" else "Можливий залишок команди SQLite (непідтверджений)",
            "История из ZIP-архива": "History from ZIP archive" if self.lang == "en" else "Історія з ZIP-архіву",
            "Удалённый артефакт (Корзина Windows)": "Deleted artifact (Windows Recycle Bin)" if self.lang == "en" else "Видалений артефакт (Кошик Windows)",
            "Удалённая история (Корзина Windows)": "Deleted history (Windows Recycle Bin)" if self.lang == "en" else "Видалена історія (Кошик Windows)",
            "Windows Run MRU: команда Python": "Windows Run MRU: Python command" if self.lang == "en" else "Windows Run MRU: команда Python",
            "SQLite forensic clue": "SQLite forensic clue" if self.lang == "en" else "Криміналістична ознака SQLite",
            "SQLite WAL": "SQLite WAL",
            "SQLite sidecar": "SQLite sidecar" if self.lang == "en" else "Допоміжний файл SQLite",
            "AnyDesk: след журнала": "AnyDesk: trace record" if self.lang == "en" else "AnyDesk: запис журналу",
            "Windows: журналы аудита": "Windows: audit logs" if self.lang == "en" else "Windows: журнали аудиту",
            "Windows: Prefetch": "Windows: Prefetch" if self.lang == "en" else "Windows: Prefetch",
            "Windows: задача планировщика": "Windows: scheduled task" if self.lang == "en" else "Windows: завдання планувальника",
            "Windows: служба": "Windows: service" if self.lang == "en" else "Windows: служба",
            "Windows: автозапуск": "Windows: startup entry" if self.lang == "en" else "Windows: запис автозапуску",
            "Windows: журналы аудита": "Windows: audit logs" if self.lang == "en" else "Windows: журнали аудиту",
            "AnyDesk: след журнала": "AnyDesk: trace record" if self.lang == "en" else "AnyDesk: запис журналу",
            "Windows: файловая система": "Windows: file system" if self.lang == "en" else "Windows: файлова система",
        }
        if text_value in mapping:
            return mapping[text_value]
        if text_value.startswith("PowerShell Operational: событие "):
            suffix = text_value.rsplit(" ", 1)[-1]
            return ("PowerShell Operational: event " if self.lang == "en" else "Подія PowerShell Operational: ") + suffix
        return text_value

    def set_language(self, lang: str) -> None:
        if lang not in LANGUAGE_TEXT or lang == self.lang:
            return
        self.lang = lang
        self.settings["language"] = lang
        try:
            self.settings_path.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        # Rebuild the view while preserving collected data and current scan worker.
        selected_event = self.selected_event() if hasattr(self, "tree") else None
        selected_path = self.selected_python_file() if hasattr(self, "file_tree") else None
        selected_tab_key = self._current_app_tab_key() if hasattr(self, "_tab_groups") else "overview"
        session_draft = self.session_input.get("1.0", "end-1c") if hasattr(self, "session_input") else ""
        case_draft = self.case_notes_text.get("1.0", "end-1c") if hasattr(self, "case_notes_text") else self.case_notes_initial
        try:
            session_selection = int(self.session_tree.selection()[0]) if self.session_tree.selection() else None
        except Exception:
            session_selection = None
        for child in self.root.winfo_children():
            child.destroy()
        self._build_menu()
        self._build_ui()
        self.root.title(f"{self.T('app_title')} {APP_VERSION}")
        self.update_filter_options()
        self.apply_filter()
        self.apply_file_filter()
        self.update_dashboard()
        self.render_recovery_rows()
        self.render_forensic_rows()
        self.render_browser_rows()
        self.render_download_rows()
        self.render_runtime_panel()
        self.refresh_timeline()
        self.render_lineage()
        self.render_artifact_inventory()
        if hasattr(self, "case_notes_text"):
            self.case_notes_text.delete("1.0", "end")
            self.case_notes_text.insert("1.0", case_draft)
            self._install_edit_context_menus()
        self.refresh_scan_history()
        self.render_readiness_panel()
        try:
            self._select_app_tab_key(selected_tab_key)
        except Exception:
            self._select_app_tab_key("overview")
        if selected_event:
            for i, item in enumerate(self.filtered):
                if item is selected_event or item == selected_event:
                    self.tree.selection_set(str(i))
                    self.on_select()
                    break
        if selected_path:
            for i, item in enumerate(self.filtered_python_files):
                if item.get("path") == selected_path.get("path"):
                    self.file_tree.selection_set(str(i))
                    self.on_python_file_select()
                    break
        self.refresh_session_table()
        if self.last_progress_payload:
            self.update_progress(self.last_progress_payload)
        if session_draft:
            self.session_input.insert("1.0", session_draft)
        if session_selection is not None and 0 <= session_selection < len(self.session_rows):
            self.session_tree.selection_set(str(session_selection))
            self.display_session_record(self.session_rows[session_selection])
        elif self.session_rows:
            self.display_session_record(self.session_rows[-1])
        self.process_tree.delete(*self.process_tree.get_children())
        for i, row in enumerate(self.process_rows):
            self.process_tree.insert("", "end", iid=str(i), values=(row.get("name", ""), row.get("pid", ""), row.get("parent_pid", ""), row.get("started", ""), row.get("path", ""), row.get("command_line", "")))
        self.process_status_var.set(self.T("process_count", n=len(self.process_rows)))
        if self.session_active:
            self.session_state_var.set(self.T("recording_on"))
            self.session_start_button.configure(state="disabled")
            self.session_stop_button.configure(state="normal")
            self.run_code_button.configure(state="normal" if not self.session_busy else "disabled")
        elif self.session_rows:
            self.display_session_record(self.session_rows[-1])
        if getattr(self, "scanning", False):
            self.progressbar.start(10)
            self.scan_button.configure(state="disabled")
        if getattr(self, "forensic_scanning", False) and hasattr(self, "forensic_start_button"):
            self.forensic_start_button.configure(state="disabled")

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label=self.T("menu_scan"), command=self.start_scan)
        file_menu.add_separator()
        file_menu.add_command(label=self.T("menu_csv"), command=self.export_csv)
        file_menu.add_command(label=self.T("menu_json"), command=self.export_json)
        file_menu.add_command(label=self.T("menu_html"), command=self.export_html)
        file_menu.add_command(label=self._artifact_text("Экспорт PDF…", "Export PDF…", "Експорт PDF…"), command=self.export_pdf)
        file_menu.add_command(label=self.T("evidence_bundle"), command=self.export_evidence_bundle)
        file_menu.add_separator()
        file_menu.add_command(label=self.T("menu_exit"), command=self.close_application)
        menu.add_cascade(label=self.T("menu_file"), menu=file_menu)
        edit_menu = tk.Menu(menu, tearoff=False)
        edit_menu.add_command(label=self.T("menu_copy_command") + "\tCtrl+C", command=self.copy_command)
        edit_menu.add_command(label=self.T("menu_copy_details") + "\tCtrl+Shift+C", command=self.copy_details)
        edit_menu.add_separator()
        edit_menu.add_command(label={"ru": "Вырезать\tCtrl+X", "en": "Cut\tCtrl+X", "uk": "Вирізати\tCtrl+X"}.get(self.lang, "Cut\tCtrl+X"), command=lambda: self._edit_action("cut"))
        edit_menu.add_command(label={"ru": "Копировать текст\tCtrl+C", "en": "Copy text\tCtrl+C", "uk": "Копіювати текст\tCtrl+C"}.get(self.lang, "Copy text\tCtrl+C"), command=lambda: self._edit_action("copy"))
        edit_menu.add_command(label={"ru": "Вставить\tCtrl+V", "en": "Paste\tCtrl+V", "uk": "Вставити\tCtrl+V"}.get(self.lang, "Paste\tCtrl+V"), command=lambda: self._edit_action("paste"))
        edit_menu.add_command(label={"ru": "Выделить всё\tCtrl+A", "en": "Select all\tCtrl+A", "uk": "Виділити все\tCtrl+A"}.get(self.lang, "Select all\tCtrl+A"), command=lambda: self._edit_action("select_all"))
        edit_menu.add_command(label={"ru": "Отменить\tCtrl+Z", "en": "Undo\tCtrl+Z", "uk": "Скасувати\tCtrl+Z"}.get(self.lang, "Undo\tCtrl+Z"), command=lambda: self._edit_action("undo"))
        edit_menu.add_command(label={"ru": "Повторить\tCtrl+Y", "en": "Redo\tCtrl+Y", "uk": "Повторити\tCtrl+Y"}.get(self.lang, "Redo\tCtrl+Y"), command=lambda: self._edit_action("redo"))
        edit_menu.add_separator()
        edit_menu.add_command(label={"ru": "Импорт EVTX…\tCtrl+O", "en": "Import EVTX…\tCtrl+O", "uk": "Імпорт EVTX…\tCtrl+O"}.get(self.lang, "Import EVTX…\tCtrl+O"), command=self.import_evtx_files)
        menu.add_cascade(label=self.T("menu_edit"), menu=edit_menu)
        view_menu = tk.Menu(menu, tearoff=False)
        view_menu.add_command(label=self._artifact_text("Глобальный поиск…\tCtrl+F", "Global search…\tCtrl+F", "Глобальний пошук…\tCtrl+F"), command=self.open_global_search)
        view_menu.add_command(label=self.T("menu_reset"), command=self.reset_filters)
        view_menu.add_command(label=self.T("menu_diagnostics"), command=self.show_diagnostics)
        menu.add_cascade(label=self.T("menu_view"), menu=view_menu)
        system_menu = tk.Menu(menu, tearoff=False)
        system_menu.add_command(label=self.T("admin_restart"), command=self.restart_as_admin, state=("disabled" if self.is_admin else "normal"))
        system_menu.add_checkbutton(label=self.T("admin_auto"), variable=self.auto_admin_var, command=self.save_auto_admin_setting)
        system_menu.add_command(label=self.T("admin_info"), command=self.show_admin_info)
        menu.add_cascade(label=self.T("menu_system"), menu=system_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label=self.T("menu_about"), command=self.show_about)
        menu.add_cascade(label=self.T("menu_help"), menu=help_menu)
        self.root.config(menu=menu)

    def _language_menu(self) -> None:
        menu = tk.Menu(self.root, tearoff=False)
        labels = {"ru": "Русский", "en": "English", "uk": "Українська"}
        for code in ("ru", "en", "uk"):
            menu.add_radiobutton(label=labels[code], value=code, variable=self.language_var,
                                 command=lambda c=code: self.set_language(c))
        try:
            menu.tk_popup(self.language_button.winfo_rootx(), self.language_button.winfo_rooty() + self.language_button.winfo_height())
        finally:
            menu.grab_release()

    def _build_ui(self) -> None:
        outer = ttk.Frame(self.root, padding=(10, 8))
        outer.pack(fill="both", expand=True)
        self.outer = outer

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 5))
        brand_row = ttk.Frame(header)
        brand_row.pack(fill="x")
        ttk.Label(brand_row, text=self.T("header"), font=("Segoe UI", 16, "bold")).pack(side="left")
        ttk.Label(brand_row, text=f"  v{APP_VERSION}  •  {CURRENT_USER}", foreground="#666666").pack(side="left", padx=8)
        self.language_var = tk.StringVar(value=self.lang)
        self.language_button = ttk.Button(brand_row, text=f"🌐 {self.T('language')}: {self.T('language_name')}", command=self._language_menu)
        self.language_button.pack(side="right", padx=(6, 0))
        admin_label = {
            "ru": ("🛡 Администратор: да" if self.is_admin else "🛡 Права администратора…"),
            "en": ("🛡 Administrator: yes" if self.is_admin else "🛡 Administrator rights…"),
            "uk": ("🛡 Адміністратор: так" if self.is_admin else "🛡 Права адміністратора…"),
        }.get(self.lang, "🛡 Administrator")
        self.admin_button = ttk.Button(brand_row, text=admin_label, command=self.restart_as_admin,
            state=("disabled" if self.is_admin else "normal"))
        self.admin_button.pack(side="right", padx=(0, 6))

        actions_row = ttk.Frame(outer)
        actions_row.pack(fill="x", pady=(0, 7))
        self.scan_button = ttk.Button(actions_row, text=self.T("scan"), command=self.start_scan)
        self.scan_button.pack(side="left")
        self.cancel_button = ttk.Button(actions_row, text=self.T("cancel_scan"), command=self.cancel_scan,
            state=("normal" if getattr(self, "scanning", False) else "disabled"))
        self.cancel_button.pack(side="left", padx=(6, 0))
        ttk.Button(actions_row, text=self.T("export_csv"), command=self.export_csv).pack(side="right", padx=(6, 0))
        ttk.Button(actions_row, text=self.T("export_json"), command=self.export_json).pack(side="right", padx=(6, 0))
        ttk.Button(actions_row, text=self.T("export_html"), command=self.export_html).pack(side="right", padx=(6, 0))
        if getattr(self, "scanning", False):
            self.scan_button.configure(state="disabled")

        # Scanning options are arranged in two readable rows instead of one
        # overfilled ribbon. The original neutral Windows ttk appearance stays.
        options = ttk.LabelFrame(outer, text=self._artifact_text("Параметры сканирования", "Scan options", "Параметри сканування"), padding=(8, 5))
        options.pack(fill="x", pady=(0, 7))
        option_row_one = ttk.Frame(options)
        option_row_one.pack(fill="x", pady=(0, 3))
        option_row_two = ttk.Frame(options)
        option_row_two.pack(fill="x")
        ttk.Checkbutton(option_row_one, text=self.T("windows_logs"), variable=self.windows_events_var).pack(side="left", fill="x", expand=True, anchor="w")
        ttk.Checkbutton(option_row_one, text=self.T("deep_scan"), variable=self.deep_scan_var).pack(side="left", fill="x", expand=True, anchor="w", padx=(14, 0))
        ttk.Checkbutton(option_row_two, text=self.T("use_cache"), variable=self.use_cache_var).pack(side="left", anchor="w")
        ttk.Checkbutton(option_row_two, text=self.T("browser_history_enabled"), variable=self.browser_history_var).pack(side="left", anchor="w", padx=(18, 0))
        ttk.Label(option_row_two, text={"ru": "Профиль:", "en": "Profile:", "uk": "Профіль:"}.get(self.lang, "Profile:")).pack(side="left", padx=(20, 5))
        profile_values = {"ru": ["Быстрый", "Стандартный", "Расширенный"], "en": ["Quick", "Standard", "Extended"], "uk": ["Швидкий", "Стандартний", "Розширений"]}.get(self.lang, ["Quick", "Standard", "Extended"])
        profile_key = str(self.settings.get("scan_profile", "standard"))
        profile_index = {"quick": 0, "standard": 1, "extended": 2}.get(profile_key, 1)
        self.scan_profile_var.set(profile_values[profile_index])
        self.scan_profile_combo = ttk.Combobox(option_row_two, textvariable=self.scan_profile_var, state="readonly", width=16, values=profile_values)
        self.scan_profile_combo.pack(side="left")
        self.scan_profile_combo.bind("<<ComboboxSelected>>", self.apply_scan_profile)

        progress_frame = ttk.LabelFrame(outer, text=self.T("scan_state"), padding=(8, 5))
        progress_frame.pack(fill="x", pady=(0, 7))
        top = ttk.Frame(progress_frame)
        top.pack(fill="x")
        ttk.Label(top, textvariable=self.progress_message_var).pack(side="left", fill="x", expand=True)
        self.progressbar = ttk.Progressbar(top, mode="indeterminate", length=260)
        self.progressbar.pack(side="right", padx=(10, 0))
        ttk.Label(progress_frame, textvariable=self.progress_stats_var, foreground="#444444").pack(anchor="w", pady=(3, 0))
        ttk.Label(progress_frame, textvariable=self.current_path_var, foreground="#666666", wraplength=1450).pack(anchor="w", pady=(2, 0))
        if getattr(self, "scanning", False):
            self.progressbar.start(10)

        # Main navigation has six top-level groups. Each group contains a
        # compact inner notebook, so labels no longer collapse into a single
        # unreadable horizontal strip. All original content frames are kept.
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)
        self._tab_groups: list[dict[str, Any]] = []
        self._tab_order: list[tuple[str, str, tk.Widget]] = []
        self._tab_key_by_widget: dict[str, str] = {}

        section_labels = {
            "overview": self._artifact_text("Обзор", "Overview", "Огляд"),
            "browser": self._artifact_text("Браузер", "Browser", "Браузер"),
            "activity": self._artifact_text("Активность", "Activity", "Активність"),
            "processes": self._artifact_text("Процессы", "Processes", "Процеси"),
            "logs": self._artifact_text("Журналы и отчёты", "Logs & reports", "Журнали та звіти"),
            "artifacts": self._artifact_text("Артефакты и дело", "Artifacts & case", "Артефакти й справа"),
        }
        section_tabs = {
            "overview": [("overview", "overview_tab", 8), ("readiness", "readiness_tab", 7)],
            "browser": [("browser", "browser_tab", 7), ("downloads", "downloads_tab", 7)],
            "activity": [("history", "history_tab", 7), ("runtime", "runtime_tab", 7), ("java", "java_tab", 7), ("suspicious", "suspicious_tab", 7), ("cleanup", "cleanup_tab", 7), ("timeline", "timeline_tab", 7)],
            "processes": [("files", "files_tab", 7), ("processes", "processes_tab", 7), ("lineage", "lineage_tab", 7), ("recovery", "recovery_tab", 7), ("sessions", "sessions_tab", 7)],
            "logs": [("forensics", "forensic_tab", 7), ("scans", "scan_history_tab", 7), ("final_report", "final_report_tab", 7)],
            "artifacts": [("artifacts", "artifact_tab", 7)],
        }
        short_labels = {
            "ru": {"overview": "Сводка", "readiness": "Полнота", "browser": "История", "downloads": "Загрузки", "history": "Команды", "runtime": "Python", "java": "Java", "suspicious": "Подозрительная активность", "cleanup": "Очистка", "timeline": "Хронология", "files": "Файлы Python", "processes": "Процессы", "lineage": "Связи", "recovery": "Восстановление", "sessions": "Сеансы", "forensics": "Системный анализ", "scans": "История проверок", "final_report": "Итоговый отчёт", "artifacts": "Источники и дело"},
            "en": {"overview": "Summary", "readiness": "Coverage", "browser": "History", "downloads": "Downloads", "history": "Commands", "runtime": "Python", "java": "Java", "suspicious": "Suspicious activity", "cleanup": "Cleanup", "timeline": "Timeline", "files": "Python files", "processes": "Processes", "lineage": "Relations", "recovery": "Recovery", "sessions": "Sessions", "forensics": "System analysis", "scans": "Scan history", "final_report": "Final report", "artifacts": "Sources & case"},
            "uk": {"overview": "Зведення", "readiness": "Повнота", "browser": "Історія", "downloads": "Завантаження", "history": "Команди", "runtime": "Python", "java": "Java", "suspicious": "Підозріла активність", "cleanup": "Очищення", "timeline": "Хронологія", "files": "Файли Python", "processes": "Процеси", "lineage": "Зв’язки", "recovery": "Відновлення", "sessions": "Сеанси", "forensics": "Системний аналіз", "scans": "Історія перевірок", "final_report": "Підсумковий звіт", "artifacts": "Джерела і справа"},
        }.get(self.lang, {})
        self._tab_refs: dict[str, tk.Widget] = {}
        for section_key, entries in section_tabs.items():
            section_frame = ttk.Frame(self.notebook, padding=4)
            inner = ttk.Notebook(section_frame)
            inner.pack(fill="both", expand=True)
            self.notebook.add(section_frame, text=section_labels[section_key])
            group = {"key": section_key, "frame": section_frame, "notebook": inner, "tabs": []}
            self._tab_groups.append(group)
            for tab_key, attr_name, padding in entries:
                tab_frame = ttk.Frame(inner, padding=padding)
                setattr(self, attr_name, tab_frame)
                inner.add(tab_frame, text=short_labels.get(tab_key, tab_key))
                group["tabs"].append(tab_frame)
                self._tab_refs[tab_key] = tab_frame
                self._tab_key_by_widget[str(tab_frame)] = tab_key
                self._tab_order.append((section_key, tab_key, tab_frame))

        self._build_overview_tab()
        self._build_readiness_tab()
        self._build_browser_tab()
        self._build_downloads_tab()
        self._build_runtime_tab()
        self._build_java_tab()
        self._build_suspicious_tab()
        self._build_cleanup_tab()
        self._build_final_report_tab()
        self._build_timeline_tab()
        self._build_history_tab()
        self._build_files_tab()
        self._build_processes_tab()
        self._build_lineage_tab()
        self._build_recovery_tab()
        self._build_sessions_tab()
        self._build_forensic_tab()
        self._build_scan_history_tab()
        self._build_artifacts_tab()

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(7, 0))
        ttk.Label(footer, textvariable=self.status_var).pack(side="left")
        ttk.Label(footer, text=self.T("footer"), foreground="#666666").pack(side="right")

    def _artifact_text(self, ru: str, en: str, uk: str) -> str:
        return {"ru": ru, "en": en, "uk": uk}.get(self.lang, ru)

    def _build_artifacts_tab(self) -> None:
        intro = ttk.Label(self.artifact_tab,
            text=self._artifact_text(
                "Дополнительные источники Windows, импорт офлайн-журналов, статический анализ файлов и материалы дела. Исходные артефакты не изменяются.",
                "Additional Windows sources, offline log import, static file inspection and case notes. Source artefacts are not modified.",
                "Додаткові джерела Windows, імпорт офлайн-журналів, статичний аналіз файлів і матеріали справи. Вихідні артефакти не змінюються."),
            wraplength=1400, justify="left", foreground="#555555")
        intro.pack(fill="x", anchor="w", pady=(0, 7))

        controls = ttk.Frame(self.artifact_tab)
        controls.pack(fill="x", pady=(0, 5))
        buttons = [
            (self._artifact_text("Обновить каталог", "Refresh inventory", "Оновити каталог"), self.start_artifact_inventory),
            (self._artifact_text("Импорт EVTX…", "Import EVTX…", "Імпорт EVTX…"), self.import_evtx_files),
            (self._artifact_text("Анализ EXE/JAR…", "Inspect EXE/JAR…", "Аналіз EXE/JAR…"), self.inspect_artifact_file),
            (self._artifact_text("Разбор DLL и машинного кода…", "DLL / machine-code analysis…", "Аналіз DLL і машинного коду…"), self.inspect_dll_file),
            (self._artifact_text("Сравнить два файла…", "Compare two files…", "Порівняти два файли…"), self.compare_static_files),
            (self._artifact_text("Amcache офлайн…", "Offline Amcache…", "Amcache офлайн…"), self.import_offline_amcache),
            (self._artifact_text("SRUM офлайн…", "Offline SRUM…", "SRUM офлайн…"), self.import_offline_srum),
            (self._artifact_text("Разобрать LNK…", "Parse LNK…", "Розібрати LNK…"), self.parse_lnk_dialog),
            (self._artifact_text("Разобрать Jump Lists…", "Parse Jump Lists…", "Розібрати Jump Lists…"), self.parse_jumplist_dialog),
            (self._artifact_text("Разобрать Prefetch…", "Parse Prefetch…", "Розібрати Prefetch…"), self.parse_prefetch_dialog),
        ]
        for label, callback in buttons:
            ttk.Button(controls, text=label, command=callback).pack(side="left", padx=(0, 5))
        self.artifact_status_var = tk.StringVar(value=self._artifact_text("Ожидание анализа артефактов", "Waiting for artifact analysis", "Очікування аналізу артефактів"))
        ttk.Label(self.artifact_tab, textvariable=self.artifact_status_var, foreground="#555555").pack(anchor="w", pady=(0, 3))
        artifact_filter = ttk.Frame(self.artifact_tab)
        artifact_filter.pack(fill="x", pady=(0, 5))
        ttk.Label(artifact_filter, text=self._artifact_text("Фильтр артефактов:", "Filter artifacts:", "Фільтр артефактів:")).pack(side="left")
        self.artifact_filter_var = tk.StringVar(value="")
        artifact_filter_entry = ttk.Entry(artifact_filter, textvariable=self.artifact_filter_var, width=38)
        artifact_filter_entry.pack(side="left", padx=(6, 5))
        artifact_filter_entry.bind("<KeyRelease>", lambda _e: self.render_artifact_inventory())
        ttk.Button(artifact_filter, text=self._artifact_text("Очистить", "Clear", "Очистити"), command=lambda: (self.artifact_filter_var.set(""), self.render_artifact_inventory())).pack(side="left")

        # Keep all artifact views inside one notebook. Placing the inventory
        # pane beside a second expanding notebook used to halve the available
        # vertical space and could leave the lower Treeview effectively hidden.
        self.artifact_subnotebook = ttk.Notebook(self.artifact_tab)
        self.artifact_subnotebook.pack(fill="both", expand=True, pady=(7, 0))
        self.artifact_inventory_tab = ttk.Frame(self.artifact_subnotebook, padding=5)
        self.artifact_subnotebook.add(self.artifact_inventory_tab,
            text=self._artifact_text("Каталог артефактов", "Artifact inventory", "Каталог артефактів"))

        main_pane = ttk.Panedwindow(self.artifact_inventory_tab, orient="horizontal")
        main_pane.pack(fill="both", expand=True)
        left = ttk.LabelFrame(main_pane, text=self._artifact_text("Каталог артефактов", "Artifact inventory", "Каталог артефактів"), padding=5)
        right = ttk.LabelFrame(main_pane, text=self._artifact_text("Подробности выбранной записи", "Selected item details", "Подробиці вибраного запису"), padding=5)
        main_pane.add(left, weight=3)
        main_pane.add(right, weight=2)
        artifact_cols = ("category", "status", "records", "path")
        self.artifact_tree = ttk.Treeview(left, columns=artifact_cols, show="headings", selectmode="extended")
        artifact_headers = {
            "category": self._artifact_text("Источник", "Source", "Джерело"),
            "status": self._artifact_text("Статус", "Status", "Статус"),
            "records": self._artifact_text("Записи", "Records", "Записи"),
            "path": self._artifact_text("Путь", "Path", "Шлях"),
        }
        for col, width in (("category", 210), ("status", 125), ("records", 80), ("path", 410)):
            self.artifact_tree.heading(col, text=artifact_headers[col])
            self.artifact_tree.column(col, width=width, minwidth=75, stretch=(col in {"category", "path"}))
        artifact_y = ttk.Scrollbar(left, orient="vertical", command=self.artifact_tree.yview)
        artifact_x = ttk.Scrollbar(left, orient="horizontal", command=self.artifact_tree.xview)
        self.artifact_tree.configure(yscrollcommand=artifact_y.set, xscrollcommand=artifact_x.set)
        self.artifact_tree.grid(row=0, column=0, sticky="nsew")
        artifact_y.grid(row=0, column=1, sticky="ns")
        artifact_x.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.artifact_tree.bind("<<TreeviewSelect>>", self.on_artifact_select)
        self.artifact_tree.bind("<Double-1>", self.on_artifact_open)

        self.artifact_details_text = tk.Text(right, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        details_y = ttk.Scrollbar(right, orient="vertical", command=self.artifact_details_text.yview)
        self.artifact_details_text.configure(yscrollcommand=details_y.set)
        self.artifact_details_text.grid(row=0, column=0, sticky="nsew")
        details_y.grid(row=0, column=1, sticky="ns")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)
        self.artifact_details_text.insert("1.0", self._artifact_text("Выберите источник или событие слева.", "Select a source or event on the left.", "Виберіть джерело або подію ліворуч."))
        self.artifact_details_text.configure(state="disabled")

        self.artifact_links_tab = ttk.Frame(self.artifact_subnotebook, padding=5)
        self.artifact_heatmap_tab = ttk.Frame(self.artifact_subnotebook, padding=5)
        self.artifact_case_tab = ttk.Frame(self.artifact_subnotebook, padding=5)
        self.artifact_trusted_tab = ttk.Frame(self.artifact_subnotebook, padding=5)
        self.artifact_plugins_tab = ttk.Frame(self.artifact_subnotebook, padding=5)
        self.artifact_subnotebook.add(self.artifact_links_tab, text=self._artifact_text("Связи событий", "Event links", "Зв’язки подій"))
        self.artifact_subnotebook.add(self.artifact_heatmap_tab, text=self._artifact_text("Плотность активности", "Activity density", "Щільність активності"))
        self.artifact_subnotebook.add(self.artifact_case_tab, text=self._artifact_text("Материалы дела", "Case notes", "Матеріали справи"))
        self.artifact_subnotebook.add(self.artifact_trusted_tab, text=self._artifact_text("Доверенный контекст", "Trusted context", "Довірений контекст"))
        self.artifact_subnotebook.add(self.artifact_plugins_tab, text=self._artifact_text("Плагины", "Plugins", "Плагіни"))

        link_note = ttk.Label(self.artifact_links_tab,
            text=self._artifact_text("Связи строятся по сохранённым идентификаторам процессов и сеансов. Временная близость не доказывает причинность.",
                                     "Links use preserved process/session identifiers. Time proximity does not prove causation.",
                                     "Зв’язки будуються за збереженими ідентифікаторами процесів і сеансів. Часова близькість не доводить причинність."),
            foreground="#555555", wraplength=1300, justify="left")
        link_note.pack(anchor="w", pady=(0, 5))
        self.relationship_canvas = tk.Canvas(self.artifact_links_tab, height=178, background="#ffffff", highlightthickness=0)
        self.relationship_canvas.pack(fill="x", expand=False, pady=(0, 5))
        self.relationship_canvas.bind("<Configure>", lambda _event: self.draw_relationship_graph(), add="+")
        link_cols = ("relation", "confidence", "delta", "from_event", "to_event", "basis")
        self.artifact_links_tree = ttk.Treeview(self.artifact_links_tab, columns=link_cols, show="headings", height=7)
        link_labels = {"relation": "Связь", "confidence": "Сила", "delta": "Δ времени", "from_event": "Событие A", "to_event": "Событие B", "basis": "Основание"}
        if self.lang == "en":
            link_labels = {"relation": "Relation", "confidence": "Strength", "delta": "Time Δ", "from_event": "Event A", "to_event": "Event B", "basis": "Basis"}
        elif self.lang == "uk":
            link_labels = {"relation": "Зв’язок", "confidence": "Сила", "delta": "Δ часу", "from_event": "Подія A", "to_event": "Подія B", "basis": "Підстава"}
        for col, width in (("relation", 190), ("confidence", 90), ("delta", 90), ("from_event", 220), ("to_event", 220), ("basis", 460)):
            self.artifact_links_tree.heading(col, text=link_labels[col])
            self.artifact_links_tree.column(col, width=width, minwidth=70, stretch=(col in {"basis", "from_event", "to_event"}))
        self.artifact_links_tree.pack(fill="both", expand=True)
        self.artifact_links_tree.bind("<Double-1>", self.open_linked_event)

        heat_top = ttk.Frame(self.artifact_heatmap_tab)
        heat_top.pack(fill="x")
        ttk.Label(heat_top, text=self._artifact_text("Последние 14 дней; каждый квадрат — один час. Цвет показывает только количество сохранённых событий.",
            "Last 14 days; each cell is one hour. Color represents only the number of preserved events.",
            "Останні 14 днів; кожен квадрат — одна година. Колір показує лише кількість збережених подій."),
            foreground="#555555", wraplength=1300).pack(side="left", fill="x", expand=True)
        ttk.Button(heat_top, text=self._artifact_text("Обновить", "Refresh", "Оновити"), command=self.draw_activity_heatmap).pack(side="right")
        self.heatmap_canvas = tk.Canvas(self.artifact_heatmap_tab, height=260, background="#ffffff", highlightthickness=0)
        self.heatmap_canvas.pack(fill="both", expand=True, pady=(6, 0))
        self.heatmap_summary_var = tk.StringVar(value="")
        ttk.Label(self.artifact_heatmap_tab, textvariable=self.heatmap_summary_var, foreground="#666666").pack(anchor="w", pady=(4, 0))

        case_top = ttk.Frame(self.artifact_case_tab)
        case_top.pack(fill="x", pady=(0, 5))
        ttk.Label(case_top, text=self._artifact_text("Название дела:", "Case name:", "Назва справи:")).pack(side="left")
        self.case_name_entry = ttk.Entry(case_top, textvariable=self.case_name_var, width=34)
        self.case_name_entry.pack(side="left", padx=(6, 8))
        ttk.Button(case_top, text=self._artifact_text("Сохранить", "Save", "Зберегти"), command=self.save_case_notes).pack(side="left")
        ttk.Button(case_top, text=self._artifact_text("Новое дело", "New case", "Нова справа"), command=self.new_case).pack(side="left", padx=(5, 0))
        ttk.Button(case_top, text=self._artifact_text("Открыть…", "Open…", "Відкрити…"), command=self.open_case).pack(side="left", padx=(5, 0))
        ttk.Button(case_top, text=self._artifact_text("Сохранить как…", "Save as…", "Зберегти як…"), command=self.save_case_as).pack(side="left", padx=(5, 0))
        ttk.Button(case_top, text=self._artifact_text("Импорт .pavcase…", "Import .pavcase…", "Імпорт .pavcase…"), command=self.import_case_package_dialog).pack(side="left", padx=(5, 0))
        self.case_file_var = tk.StringVar(value=str(getattr(self, "active_case_file", self.case_notes_file).name))
        ttk.Label(case_top, textvariable=self.case_file_var, foreground="#666666").pack(side="left", padx=(8, 0))
        ttk.Label(self.artifact_case_tab,
            text=self._artifact_text("Дело хранит заметки, список файлов-доказательств и журнал действий. Выбранные файлы копируются в локальное хранилище дела; оригиналы не изменяются.",
                "A case stores notes, an evidence-file register and an audit trail. Selected files are copied into the local case vault; originals are not modified.",
                "Справа зберігає нотатки, список файлів-доказів і журнал дій. Вибрані файли копіюються до локального сховища справи; оригінали не змінюються."),
            foreground="#555555", wraplength=1300).pack(anchor="w", pady=(0, 4))

        evidence_box = ttk.LabelFrame(self.artifact_case_tab, text=self._artifact_text("Реестр доказательств", "Evidence register", "Реєстр доказів"), padding=5)
        evidence_box.pack(fill="both", expand=True, pady=(0, 6))
        evidence_toolbar = ttk.Frame(evidence_box)
        evidence_toolbar.pack(fill="x", pady=(0, 4))
        ttk.Button(evidence_toolbar, text=self._artifact_text("Добавить файлы…", "Add files…", "Додати файли…"), command=self.add_case_evidence_files).pack(side="left")
        ttk.Button(evidence_toolbar, text=self._artifact_text("Проверить целостность", "Verify integrity", "Перевірити цілісність"), command=self.verify_case_dialog).pack(side="left", padx=5)
        ttk.Button(evidence_toolbar, text=self._artifact_text("Исключить выбранное", "Exclude selected", "Виключити вибране"), command=self.exclude_case_evidence).pack(side="left")
        ttk.Button(evidence_toolbar, text=self._artifact_text("Экспорт дела…", "Export case…", "Експорт справи…"), command=self.export_case_package_dialog).pack(side="left", padx=5)
        self.case_integrity_var = tk.StringVar(value=self._artifact_text("Целостность ещё не проверялась", "Integrity has not been checked", "Цілісність ще не перевіряли"))
        ttk.Label(evidence_toolbar, textvariable=self.case_integrity_var, foreground="#555555").pack(side="right", padx=5)
        evidence_table_frame = ttk.Frame(evidence_box)
        evidence_table_frame.pack(fill="both", expand=True)
        evidence_cols = ("name", "size", "sha256", "status")
        self.case_evidence_tree = ttk.Treeview(evidence_table_frame, columns=evidence_cols, show="headings", height=5, selectmode="extended")
        evidence_labels = {
            "name": self._artifact_text("Файл", "File", "Файл"),
            "size": self._artifact_text("Размер", "Size", "Розмір"),
            "sha256": "SHA-256",
            "status": self._artifact_text("Статус", "Status", "Статус"),
        }
        for col, width in (("name", 260), ("size", 100), ("sha256", 430), ("status", 130)):
            self.case_evidence_tree.heading(col, text=evidence_labels[col])
            self.case_evidence_tree.column(col, width=width, minwidth=80, stretch=(col in {"name", "sha256"}))
        evidence_y = ttk.Scrollbar(evidence_table_frame, orient="vertical", command=self.case_evidence_tree.yview)
        evidence_x = ttk.Scrollbar(evidence_table_frame, orient="horizontal", command=self.case_evidence_tree.xview)
        self.case_evidence_tree.configure(yscrollcommand=evidence_y.set, xscrollcommand=evidence_x.set)
        self.case_evidence_tree.grid(row=0, column=0, sticky="nsew")
        evidence_y.grid(row=0, column=1, sticky="ns")
        evidence_x.grid(row=1, column=0, sticky="ew")
        evidence_table_frame.rowconfigure(0, weight=1)
        evidence_table_frame.columnconfigure(0, weight=1)
        self.case_evidence_tree.bind("<Control-c>", lambda _e: self._copy_tree_selection(self.case_evidence_tree))
        self.case_evidence_tree.bind("<Double-1>", self.show_case_evidence_details)

        notes_box = ttk.LabelFrame(self.artifact_case_tab, text=self._artifact_text("Заметки модератора", "Moderator notes", "Нотатки модератора"), padding=5)
        notes_box.pack(fill="both", expand=True)
        self.case_notes_text = tk.Text(notes_box, height=5, wrap="word", font=("Segoe UI", 10), undo=True)
        self.case_notes_text.pack(fill="both", expand=True)
        if self.case_notes_initial:
            self.case_notes_text.insert("1.0", self.case_notes_initial)
        self.render_case_evidence()

        trusted_top = ttk.Frame(self.artifact_trusted_tab)
        trusted_top.pack(fill="x", pady=(0, 5))
        ttk.Label(trusted_top, text=self._artifact_text("Добавить путь к известной легитимной программе:", "Add a known legitimate application path:", "Додати шлях до відомої легітимної програми:")).pack(side="left")
        self.trusted_path_var = tk.StringVar(value="")
        ttk.Entry(trusted_top, textvariable=self.trusted_path_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(trusted_top, text=self._artifact_text("Выбрать…", "Browse…", "Вибрати…"), command=self.browse_trusted_path).pack(side="left", padx=(0, 5))
        ttk.Button(trusted_top, text=self._artifact_text("Добавить", "Add", "Додати"), command=self.add_trusted_path).pack(side="left")
        ttk.Label(self.artifact_trusted_tab,
            text=self._artifact_text("Указанные пути влияют на оценку: совпадения с доверенным файлом/каталогом не добавляют баллы. События остаются в отчёте; добавляйте только конкретные проверенные пути, не весь диск.",
                "Listed paths affect scoring: matches within a trusted file/folder do not add points. Events remain in reports; add only verified specific paths, not an entire drive.",
                "Зазначені шляхи впливають на оцінку: збіги з довіреним файлом/каталогом не додають балів. Події залишаються у звіті; додавайте лише перевірені конкретні шляхи, не весь диск."), foreground="#555555", wraplength=1300).pack(anchor="w", pady=(0, 4))
        trust_frame = ttk.Frame(self.artifact_trusted_tab)
        trust_frame.pack(fill="both", expand=True)
        self.trusted_listbox = tk.Listbox(trust_frame, height=5, activestyle="dotbox")
        trust_scroll = ttk.Scrollbar(trust_frame, orient="vertical", command=self.trusted_listbox.yview)
        self.trusted_listbox.configure(yscrollcommand=trust_scroll.set)
        self.trusted_listbox.pack(side="left", fill="both", expand=True)
        trust_scroll.pack(side="right", fill="y")
        trust_bottom = ttk.Frame(self.artifact_trusted_tab)
        trust_bottom.pack(fill="x", pady=(4, 0))
        ttk.Button(trust_bottom, text=self._artifact_text("Удалить выбранное", "Remove selected", "Видалити вибране"), command=self.remove_trusted_path).pack(side="left")
        ttk.Button(trust_bottom, text=self._artifact_text("Обновить список", "Refresh list", "Оновити список"), command=self.render_trusted_paths).pack(side="left", padx=5)

        plugin_top = ttk.Frame(self.artifact_plugins_tab)
        plugin_top.pack(fill="x", pady=(0, 5))
        ttk.Label(plugin_top, text=self._artifact_text("Обнаружение плагинов не выполняет их код.", "Plugin discovery does not execute plugin code.", "Виявлення плагінів не виконує їхній код."), foreground="#555555").pack(side="left", fill="x", expand=True)
        ttk.Button(plugin_top, text=self._artifact_text("Обновить", "Refresh", "Оновити"), command=self.render_plugin_list).pack(side="right")
        self.plugin_tree = ttk.Treeview(self.artifact_plugins_tab, columns=("file", "status", "note"), show="headings", height=5)
        for col, width in (("file", 260), ("status", 140), ("note", 600)):
            self.plugin_tree.heading(col, text={"file": "Файл", "status": "Статус", "note": "Примечание"}.get(col, col))
            self.plugin_tree.column(col, width=width, minwidth=80, stretch=(col == "note"))
        self.plugin_tree.pack(fill="both", expand=True)
        self.render_trusted_paths()
        self.render_plugin_list()
        self.render_artifact_inventory()
        self.render_relationships()
        self.draw_activity_heatmap()

    def _configure_compact_tables(self) -> None:
        try:
            style = ttk.Style(self.root)
            style.configure("Treeview", rowheight=25, padding=(3, 2))
            style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"), padding=(5, 4))
        except Exception:
            pass

    def _install_keyboard_shortcuts(self) -> None:
        # Entry/Text widgets retain Tk's native clipboard bindings; tree views gain row-copy support.
        bindings = {
            "<Control-c>": self._shortcut_copy,
            "<Control-C>": self._shortcut_copy,
            "<Control-Shift-c>": self._shortcut_copy_details,
            "<Control-o>": lambda _e: self.import_evtx_files(),
            "<Control-r>": lambda _e: self.start_scan(),
            "<F5>": lambda _e: self.start_scan(),
            "<Control-Shift-s>": lambda _e: self.export_json(),
            "<Control-Shift-e>": lambda _e: self.export_evidence_bundle(),
            "<Control-Tab>": self._next_tab,
            "<Control-Shift-Tab>": self._previous_tab,
            "<Escape>": lambda _e: self.search_var.set(""),
        }
        for sequence, callback in bindings.items():
            try:
                self.root.bind_all(sequence, callback, add="+")
            except Exception:
                pass
        self.root.bind_all("<Control-a>", self._shortcut_select_all, add="+")
        self.root.bind_all("<Control-A>", self._shortcut_select_all, add="+")
        self.root.bind_all("<Control-x>", self._shortcut_cut, add="+")
        self.root.bind_all("<Control-v>", self._shortcut_paste, add="+")

    def _install_edit_context_menus(self) -> None:
        def visit(widget: tk.Misc) -> None:
            try:
                cls = widget.winfo_class()
                if cls in {"Entry", "Text", "TEntry", "TCombobox", "Spinbox"}:
                    widget.bind("<Button-3>", self._show_edit_context_menu, add="+")
                    # Bind on the widget tag (before Tk's class tag) so the
                    # command executes once instead of running alongside the
                    # default Text Ctrl+Z / Ctrl+Y bindings.
                    widget.bind("<Control-z>", self._shortcut_undo, add="+")
                    widget.bind("<Control-y>", self._shortcut_redo, add="+")
                    widget.bind("<Control-Shift-z>", self._shortcut_redo, add="+")
                    if cls == "Text":
                        try:
                            widget.configure(undo=True, autoseparators=True, maxundo=1000)
                        except Exception:
                            pass
                for child in widget.winfo_children():
                    visit(child)
            except Exception:
                pass
        visit(self.root)

    def _show_edit_context_menu(self, event: Any) -> str:
        widget = event.widget
        menu = tk.Menu(self.root, tearoff=False)
        labels = {
            "cut": self._artifact_text("Вырезать", "Cut", "Вирізати"),
            "copy": self._artifact_text("Копировать", "Copy", "Копіювати"),
            "paste": self._artifact_text("Вставить", "Paste", "Вставити"),
            "select_all": self._artifact_text("Выделить всё", "Select all", "Виділити все"),
            "undo": self._artifact_text("Отменить", "Undo", "Скасувати"),
            "redo": self._artifact_text("Повторить", "Redo", "Повторити"),
        }
        for action in ("undo", "redo", "cut", "copy", "paste", "select_all"):
            menu.add_command(label=labels[action], command=lambda a=action, w=widget: self._edit_action(a, w))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
        return "break"

    def _edit_action(self, action: str, widget: Any = None) -> None:
        widget = widget or self.root.focus_get()
        if widget is None:
            return
        cls = ""
        try:
            cls = widget.winfo_class()
        except Exception:
            pass
        try:
            if action == "select_all":
                if cls == "Text":
                    widget.tag_add("sel", "1.0", "end-1c")
                    widget.mark_set("insert", "1.0")
                    widget.see("insert")
                elif cls in {"Entry", "TEntry", "TCombobox", "Spinbox"}:
                    widget.selection_range(0, "end")
                    widget.icursor("end")
                elif isinstance(widget, ttk.Treeview):
                    widget.selection_set(widget.get_children(""))
            elif action in {"cut", "copy", "paste"}:
                if action == "copy" and isinstance(widget, ttk.Treeview):
                    self._copy_tree_selection(widget)
                elif action == "copy" and cls not in {"Text", "Entry", "TEntry", "TCombobox", "Spinbox"}:
                    self._copy_selected_event()
                else:
                    widget.event_generate({"cut": "<<Cut>>", "copy": "<<Copy>>", "paste": "<<Paste>>"}[action])
            elif action == "undo":
                widget.event_generate("<<Undo>>")
            elif action == "redo":
                widget.event_generate("<<Redo>>")
        except Exception:
            pass

    def _shortcut_select_all(self, event: Any) -> str | None:
        widget = event.widget
        self._edit_action("select_all", widget)
        return "break"

    def _shortcut_cut(self, event: Any) -> str | None:
        # Tk maps Ctrl+X to <<Cut>>. Do not generate a second virtual event.
        return None

    def _shortcut_paste(self, event: Any) -> str | None:
        # Tk maps Ctrl+V to <<Paste>>. Returning None lets the class binding
        # perform exactly one paste into Entry/Text/Combobox widgets.
        return None

    def _shortcut_undo(self, event: Any) -> str:
        widget = event.widget
        try:
            if widget.winfo_class() == "Text":
                widget.edit_undo()
            else:
                widget.event_generate("<<Undo>>")
        except (tk.TclError, AttributeError):
            pass
        return "break"

    def _shortcut_redo(self, event: Any) -> str:
        # Handle Ctrl+Y explicitly: on some Tk builds the default binding is
        # "yank" rather than redo, which can unexpectedly paste the clipboard.
        widget = event.widget
        try:
            if widget.winfo_class() == "Text":
                widget.edit_redo()
            else:
                widget.event_generate("<<Redo>>")
        except (tk.TclError, AttributeError):
            pass
        return "break"

    def _shortcut_copy(self, event: Any) -> str | None:
        widget = event.widget
        if widget.winfo_class() in {"Entry", "Text", "TEntry", "TCombobox", "Spinbox"}:
            # Tk's virtual <<Copy>> event handles editable widgets exactly once.
            return None
        if isinstance(widget, ttk.Treeview):
            self._copy_tree_selection(widget)
        else:
            self._copy_selected_event()
        return "break"

    def _shortcut_copy_details(self, event: Any) -> str:
        self.copy_details()
        return "break"

    def _copy_tree_selection(self, tree: ttk.Treeview) -> None:
        selected = tree.selection()
        if not selected:
            return
        rows = []
        headings = [tree.heading(c, "text") for c in tree["columns"]]
        rows.append("\t".join(str(x) for x in headings))
        for iid in selected:
            rows.append("\t".join(str(x) for x in tree.item(iid, "values")))
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(rows))
            self.status_var.set(self._artifact_text("Строки скопированы", "Rows copied", "Рядки скопійовано"))
        except Exception:
            pass

    def _copy_selected_event(self) -> None:
        item = self.selected_event()
        if item:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(item.get("command") or item.get("description", "")))
            self.status_var.set(self._artifact_text("Событие скопировано", "Event copied", "Подію скопійовано"))

    def _current_app_tab_key(self) -> str:
        try:
            active_section = str(self.notebook.select())
        except Exception:
            active_section = ""
        for group in getattr(self, "_tab_groups", []):
            if str(group.get("frame")) != active_section:
                continue
            try:
                selected = group["notebook"].select()
                return self._tab_key_by_widget.get(str(selected), "overview")
            except Exception:
                break
        return "overview"

    def _select_app_tab(self, tab: tk.Widget) -> None:
        target_key = self._tab_key_by_widget.get(str(tab))
        if target_key:
            self._select_app_tab_key(target_key)

    def _select_app_tab_key(self, tab_key: str) -> None:
        for group in getattr(self, "_tab_groups", []):
            for section_key, key, frame in self._tab_order:
                if section_key == group["key"] and key == tab_key:
                    self.notebook.select(group["frame"])
                    group["notebook"].select(frame)
                    return

    def _move_app_tab(self, delta: int) -> str:
        if not self._tab_order:
            return "break"
        current = self._current_app_tab_key()
        keys = [item[1] for item in self._tab_order]
        try:
            index = keys.index(current)
        except ValueError:
            index = 0
        next_key = keys[(index + delta) % len(keys)]
        self._select_app_tab_key(next_key)
        return "break"

    def _next_tab(self, _event: Any = None) -> str:
        return self._move_app_tab(1)

    def _previous_tab(self, _event: Any = None) -> str:
        return self._move_app_tab(-1)

    def apply_scan_profile(self, _event: Any = None) -> None:
        labels = {
            "ru": {"Быстрый": "quick", "Стандартный": "standard", "Расширенный": "extended"},
            "en": {"Quick": "quick", "Standard": "standard", "Extended": "extended"},
            "uk": {"Швидкий": "quick", "Стандартний": "standard", "Розширений": "extended"},
        }
        selected = labels.get(self.lang, labels["en"]).get(self.scan_profile_var.get(), "standard")
        self.settings["scan_profile"] = selected
        try:
            self.settings_path.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        if selected == "quick":
            self.windows_events_var.set(False)
            self.deep_scan_var.set(False)
            self.use_cache_var.set(True)
        elif selected == "standard":
            self.windows_events_var.set(True)
            self.deep_scan_var.set(False)
            self.use_cache_var.set(True)
        else:
            self.windows_events_var.set(True)
            self.deep_scan_var.set(True)
            self.use_cache_var.set(False)
        # Browser history remains an explicit, independent opt-in for privacy.
        self.status_var.set(self._artifact_text(
            "Профиль применён. История браузера не включается автоматически — используйте отдельный флажок.",
            "Profile applied. Browser history is not enabled automatically; use its separate checkbox.",
            "Профіль застосовано. Історія браузера не вмикається автоматично — використовуйте окремий прапорець."))

    @staticmethod
    def _dedupe_sources_local(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[tuple[str, str, str]] = set()
        result: list[dict[str, Any]] = []
        for row in rows:
            key = (str(row.get("type", "")), str(row.get("path", "")), str(row.get("status", "")))
            if key not in seen:
                seen.add(key)
                result.append(row)
        return result

    def _start_artifact_job(self, kind: str, work: Callable[[], Any]) -> None:
        if self.artifact_job_active:
            messagebox.showinfo(self._artifact_text("Анализ артефактов", "Artifact analysis", "Аналіз артефактів"),
                self._artifact_text("Друга операция уже выполняется.", "Another operation is already running.", "Інша операція вже виконується."))
            return
        self.artifact_job_active = True
        self.artifact_job_kind = kind
        self.artifact_status_var.set(self._artifact_text("Выполняется операция:", "Running operation:", "Виконується операція:") + " " + kind)
        def worker() -> None:
            try:
                result = work()
                self.artifact_queue.put(("done", kind, result))
            except Exception as exc:
                self.artifact_queue.put(("error", kind, f"{type(exc).__name__}: {exc}"))
        threading.Thread(target=worker, name="PAV-Artifact-" + kind, daemon=True).start()
        self.root.after(150, self.poll_artifact_job)

    def poll_artifact_job(self) -> None:
        try:
            while True:
                state, kind, payload = self.artifact_queue.get_nowait()
                if state == "error":
                    self.artifact_job_active = False
                    self.artifact_status_var.set(self._artifact_text("Ошибка операции", "Operation failed", "Помилка операції") + ": " + str(payload))
                    messagebox.showerror(kind, str(payload))
                    return
                self.artifact_job_active = False
                self._handle_artifact_result(kind, payload)
                self.artifact_status_var.set(self._artifact_text("Готово", "Completed", "Готово") + f": {kind}")
        except queue.Empty:
            pass
        if self.artifact_job_active:
            self.root.after(150, self.poll_artifact_job)

    def start_artifact_inventory(self) -> None:
        self._start_artifact_job("inventory", lambda: scan_artifact_inventory())

    def import_evtx_files(self) -> None:
        paths = filedialog.askopenfilenames(title=self._artifact_text("Импортировать журналы EVTX", "Import EVTX logs", "Імпортувати журнали EVTX"),
            filetypes=[("Windows Event Logs", "*.evtx"), ("All files", "*.*")])
        if not paths:
            return
        def work() -> dict[str, Any]:
            rows: list[dict[str, Any]] = []; sources: list[dict[str, Any]] = []; warnings: list[str] = []
            for path in paths:
                found, meta, warn = import_evtx_file(Path(path))
                rows.extend(found); sources.append(meta); warnings.extend(warn)
            return {"events": rows, "sources": sources, "warnings": warnings}
        self._start_artifact_job("evtx", work)

    def inspect_artifact_file(self) -> None:
        path = filedialog.askopenfilename(title=self._artifact_text("Статический анализ файла", "Static file inspection", "Статичний аналіз файлу"),
            filetypes=[("Executable/archive/source", "*.exe *.dll *.jar *.zip *.py *.pyw *.pyi"), ("All files", "*.*")])
        if not path:
            return
        self._start_artifact_job("file", lambda: inspect_static_file(Path(path)))

    def inspect_dll_file(self) -> None:
        path = filedialog.askopenfilename(
            title=self._artifact_text("Статический разбор DLL (без запуска)", "Static DLL analysis (no execution)", "Статичний аналіз DLL (без запуску)"),
            filetypes=[("Windows DLL libraries", "*.dll"), ("PE executable / DLL", "*.exe *.dll"), ("All files", "*.*")],
        )
        if not path:
            return
        self._start_artifact_job("file", lambda: inspect_static_file(Path(path)))

    def import_offline_amcache(self) -> None:
        path = filedialog.askopenfilename(title=self._artifact_text("Выбрать офлайн-копию Amcache.hve", "Select offline Amcache.hve", "Вибрати офлайн-копію Amcache.hve"),
            filetypes=[("Amcache hive", "*.hve"), ("All files", "*.*")])
        if not path:
            return
        self._start_artifact_job("amcache", lambda: parse_offline_amcache(Path(path)))

    def import_offline_srum(self) -> None:
        path = filedialog.askopenfilename(title=self._artifact_text("Выбрать офлайн-копию SRUDB.dat", "Select offline SRUDB.dat", "Вибрати офлайн-копію SRUDB.dat"),
            filetypes=[("SRUM database", "*.dat"), ("All files", "*.*")])
        if not path:
            return
        self._start_artifact_job("srum", lambda: parse_srum_database(Path(path)))

    def parse_prefetch_dialog(self) -> None:
        paths = filedialog.askopenfilenames(title=self._artifact_text("Выбрать Prefetch-файлы", "Select Prefetch files", "Вибрати Prefetch-файли"),
            filetypes=[("Windows Prefetch", "*.pf"), ("All files", "*.*")])
        if not paths:
            return
        if len(paths) > 200:
            messagebox.showwarning(self._artifact_text("Лимит файлов", "File limit", "Обмеження файлів"),
                self._artifact_text("За один раз можно выбрать не более 200 файлов.", "Select no more than 200 files at once.", "За один раз можна вибрати не більше 200 файлів."))
            return
        def work() -> dict[str, Any]:
            rows: list[dict[str, Any]] = []; sources: list[dict[str, Any]] = []; warnings: list[str] = []
            for path in paths:
                found, meta, warn = parse_prefetch_file(Path(path))
                rows.extend(found); sources.append(meta); warnings.extend(warn)
            return {"events": rows, "sources": sources, "warnings": warnings}
        self._start_artifact_job("prefetch", work)

    def parse_lnk_dialog(self) -> None:
        path = filedialog.askopenfilename(title=self._artifact_text("Выбрать ярлык LNK", "Select LNK shortcut", "Вибрати ярлик LNK"),
            filetypes=[("Windows shortcuts", "*.lnk"), ("All files", "*.*")])
        if not path:
            return
        self._start_artifact_job("lnk", lambda: parse_lnk_file(Path(path)))

    def parse_jumplist_dialog(self) -> None:
        paths = filedialog.askopenfilenames(title=self._artifact_text("Выбрать Jump Lists", "Select Jump Lists", "Вибрати Jump Lists"),
            filetypes=[("Windows Jump Lists", "*.automaticDestinations-ms *.customDestinations-ms"), ("All files", "*.*")])
        if not paths:
            return
        if len(paths) > 100:
            messagebox.showwarning(self._artifact_text("Лимит файлов", "File limit", "Обмеження файлів"),
                self._artifact_text("За один раз можно выбрать не более 100 файлов.", "Select no more than 100 files at once.", "За один раз можна вибрати не більше 100 файлів."))
            return
        def work() -> dict[str, Any]:
            rows: list[dict[str, Any]] = []; sources: list[dict[str, Any]] = []; warnings: list[str] = []
            for path in paths:
                found, meta, warn = parse_jumplist_file(Path(path))
                rows.extend(found); sources.append(meta); warnings.extend(warn)
            return {"events": rows, "sources": sources, "warnings": warnings}
        self._start_artifact_job("jumplist", work)

    def _handle_artifact_result(self, kind: str, payload: Any) -> None:
        if kind == "compare_files":
            self.open_file_comparison_window(payload)
            return
        if kind == "case_evidence":
            self.case_payload = payload.get("case_payload", self.case_payload)
            persist_case_payload(self.case_payload, self.active_case_file)
            self.case_verification = {}
            self.render_case_evidence()
            added = len(payload.get("added", [])); errors = payload.get("errors", [])
            self.status_var.set(self._artifact_text("Добавлено файлов:", "Files added:", "Додано файлів:") + f" {added}; " + self._artifact_text("ошибок:", "errors:", "помилок:") + f" {len(errors)}")
            if errors:
                messagebox.showwarning(self._artifact_text("Добавление доказательств", "Adding evidence", "Додавання доказів"), json.dumps(errors, ensure_ascii=False, indent=2))
            return
        if kind == "case_verify":
            self.case_verification = payload
            audit = payload.get("audit_chain", {})
            append_case_audit(self.case_payload, "case_integrity_verified", {"valid": payload.get("valid"), "audit_chain_valid": audit.get("valid"), "evidence_ok": payload.get("evidence_ok", 0), "evidence_problem_count": len(payload.get("evidence_problem", []))})
            persist_case_payload(self.case_payload, self.active_case_file)
            self.render_case_evidence()
            messagebox.showinfo(self._artifact_text("Проверка целостности", "Integrity verification", "Перевірка цілісності"), json.dumps(payload, ensure_ascii=False, indent=2))
            return
        if kind == "case_export":
            self.case_payload = payload.get("case_payload", self.case_payload)
            persist_case_payload(self.case_payload, self.active_case_file)
            self.render_case_evidence()
            result = payload.get("result", {})
            messagebox.showinfo(self._artifact_text("Экспорт дела", "Case export", "Експорт справи"), f"{result.get('path', '')}\nFiles: {result.get('files', 0)}")
            return
        if kind == "case_import":
            self.active_case_file = Path(payload)
            self.case_payload = load_case_payload(payload)
            self.case_name_var.set(str(self.case_payload.get("name", "Unnamed case")))
            self.case_notes_text.delete("1.0", "end")
            self.case_notes_text.insert("1.0", str(self.case_payload.get("notes", "")))
            self.case_verification = {}
            self.case_file_var.set(self.active_case_file.name)
            self.render_case_evidence()
            messagebox.showinfo(self._artifact_text("Импорт дела", "Case import", "Імпорт справи"), str(payload))
            return
        events: list[dict[str, Any]] = []
        sources: list[dict[str, Any]] = []
        warnings: list[str] = []
        if kind == "inventory":
            self.artifact_events = list(payload.get("events", []))
            self.artifact_sources = list(payload.get("sources", []))
            events, sources, warnings = self.artifact_events, self.artifact_sources, list(payload.get("warnings", []))
        elif kind in {"evtx", "jumplist", "prefetch"}:
            events = list(payload.get("events", [])); sources = list(payload.get("sources", [])); warnings = list(payload.get("warnings", []))
        elif kind == "amcache":
            events, warnings = payload
            sources = [{"type": "Imported offline Amcache", "status": "available" if events else "empty_or_unparsed", "records": len(events)}]
        elif kind == "srum":
            events, meta, warnings = payload
            sources = [meta]
        elif kind in {"file", "lnk"}:
            self.artifact_details = payload[0] if kind == "lnk" and isinstance(payload, tuple) and len(payload) == 2 else payload
            if kind == "lnk" and isinstance(payload, tuple):
                self.artifact_details = {"lnk_parse_status": payload[1], "result": payload[0]}
            self.show_artifact_details(self.artifact_details)
            if isinstance(self.artifact_details, dict) and isinstance(self.artifact_details.get("pe_analysis"), dict):
                self.open_pe_analysis_window(self.artifact_details)
            return
        self.artifact_events = deduplicate_events(list(self.artifact_events) + events)
        self.artifact_sources = self._dedupe_sources_local(list(self.artifact_sources) + sources)
        self.forensic_rows = deduplicate_events(list(self.forensic_rows) + events)
        self.forensic_sources = self._dedupe_sources_local(list(self.forensic_sources) + sources)
        self.forensic_warnings = list(dict.fromkeys(list(self.forensic_warnings) + warnings))
        self._refresh_combined_analysis()
        self.render_artifact_inventory()
        self.render_relationships()
        self.draw_activity_heatmap()
        self.render_final_report()
        self.save_scan_snapshot()
        self.status_var.set(self._artifact_text("Новые события и источники добавлены в общий отчёт.", "New events and sources added to the combined report.", "Нові події та джерела додано до спільного звіту."))

    def _refresh_combined_analysis(self) -> None:
        combined_events = list(self.events) + list(self.forensic_rows)
        self.analysis_quality = attach_analysis(combined_events)
        runtime_analysis = analyze_python_java_processes(combined_events)
        risk_assessment = assess_suspiciousness(combined_events, runtime_analysis, list(self.sources) + list(self.forensic_sources), trusted_paths=list(self.trusted_paths))
        evidence_summary = summarize_independent_evidence(combined_events)
        self.analysis_quality["python_java_analysis"] = runtime_analysis
        self.analysis_quality["risk_assessment"] = risk_assessment
        self.analysis_quality["independent_evidence"] = evidence_summary
        self.scan_info["python_java_analysis"] = runtime_analysis
        self.scan_info["risk_assessment"] = risk_assessment
        self.scan_info["independent_evidence"] = evidence_summary
        self.coverage_report = build_scan_coverage(list(self.sources) + list(self.forensic_sources), self.readiness_report,
            list(self.errors) + list(self.forensic_warnings), list(self.warnings) + list(self.forensic_warnings), combined_events)
        self.scan_info["coverage"] = self.coverage_report
        self.scan_info["analysis_quality"] = self.analysis_quality
        self.update_filter_options(); self.apply_filter(); self.refresh_timeline(); self.update_dashboard(); self.render_lineage()
        self.render_forensic_rows(); self.render_browser_rows(); self.render_download_rows(); self.render_runtime_panel(); self.render_cleanup_panel()

    def render_artifact_inventory(self) -> None:
        if not hasattr(self, "artifact_tree"):
            return
        self.artifact_tree.delete(*self.artifact_tree.get_children())
        self._artifact_item_rows: list[dict[str, Any]] = []
        sources = list(getattr(self, "forensic_sources", [])) + list(getattr(self, "artifact_sources", []))
        keywords = ("prefetch", "amcache", "srum", "usn", "bam", "dam", "userassist", "jump", "lnk", "artifact", "offline")
        seen = set()
        query = str(getattr(self, "artifact_filter_var", tk.StringVar(value="")).get()).strip().casefold()
        for row in sources:
            label = str(row.get("type", ""))
            if not any(k in label.casefold() for k in keywords):
                continue
            searchable = " ".join(str(row.get(k, "")) for k in ("type", "status", "path", "note"))
            if query and query not in searchable.casefold():
                continue
            marker = (label, str(row.get("path", "")), str(row.get("status", "")))
            if marker in seen:
                continue
            seen.add(marker)
            iid = str(len(self._artifact_item_rows))
            self._artifact_item_rows.append({"category": label, "item": row, "row_type": "source"})
            self.artifact_tree.insert("", "end", iid=iid, values=(label, row.get("status", "unknown"),
                row.get("records_indexed", row.get("matched_records", row.get("records_checked", row.get("files_seen", "—")))), row.get("path", "")))
        event_rows = list(getattr(self, "forensic_rows", []))
        for row in event_rows:
            kind = str(row.get("kind", ""))
            if not any(k in kind.casefold() for k in ("prefetch", "bam", "dam", "userassist", "amcache", "srum", "lnk", "jump list")):
                continue
            searchable = " ".join(str(row.get(k, "")) for k in ("kind", "description", "source", "command"))
            if query and query not in searchable.casefold():
                continue
            iid = str(len(self._artifact_item_rows))
            self._artifact_item_rows.append({"category": kind, "item": row, "row_type": "event"})
            self.artifact_tree.insert("", "end", iid=iid, values=(kind, "observed", "1", row.get("source", "")))
        evidence = summarize_independent_evidence(list(self.events) + list(self.forensic_rows))
        self.artifact_status_var.set(self._artifact_text("Источников артефактов:", "Artifact sources:", "Джерел артефактів:") + f" {len(self._artifact_item_rows)} • " +
            self._artifact_text("груп независимых данных:", "independent data groups:", "груп незалежних даних:") + f" {evidence.get('group_count', 0)}")
        self.render_trusted_paths()

    def on_artifact_select(self, _event: Any = None) -> None:
        selected = self.artifact_tree.selection()
        if not selected:
            return
        try:
            row = self._artifact_item_rows[int(selected[0])]
            self.show_artifact_details(row)
        except Exception:
            pass

    def show_artifact_details(self, value: Any) -> None:
        if not hasattr(self, "artifact_details_text"):
            return
        self.artifact_details_text.configure(state="normal")
        self.artifact_details_text.delete("1.0", "end")
        self.artifact_details_text.insert("1.0", json.dumps(value, ensure_ascii=False, indent=2, default=str))
        self.artifact_details_text.configure(state="disabled")

    def open_pe_analysis_window(self, report: dict[str, Any]) -> None:
        pe = report.get("pe_analysis", {}) if isinstance(report, dict) else {}
        if not pe or pe.get("status") == "parse_error":
            return
        window = tk.Toplevel(self.root)
        window.title(self._artifact_text("Статический анализ DLL / PE", "Static DLL / PE analysis", "Статичний аналіз DLL / PE") + " — " + str(report.get("name", "")))
        window.geometry("1180x780")
        window.minsize(850, 560)
        outer = ttk.Frame(window, padding=8)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text=str(report.get("path", "")), foreground="#555555", wraplength=1120).pack(fill="x", pady=(0, 6))
        ttk.Label(outer, text=self._artifact_text(
            "Файл не запускался. Просмотр включает заголовки PE, импорты, экспорты, строки и, при наличии Capstone, машинные инструкции. Это не восстановление исходного C/C++ кода.",
            "The file was not executed. Views include PE headers, imports, exports, strings and, when Capstone is installed, machine instructions. This does not recover original C/C++ source.",
            "Файл не запускався. Перегляд містить заголовки PE, імпорти, експорти, рядки та, за наявності Capstone, машинні інструкції. Це не відновлення вихідного C/C++ коду."),
            foreground="#555555", wraplength=1120, justify="left").pack(fill="x", pady=(0, 6))
        tabs = ttk.Notebook(outer)
        tabs.pack(fill="both", expand=True)

        def add_text_tab(title: str, value: Any, *, monospace: bool = True) -> tk.Text:
            frame = ttk.Frame(tabs, padding=5)
            tabs.add(frame, text=title)
            text_box = tk.Text(frame, wrap="none" if monospace else "word", font=("Consolas" if monospace else "Segoe UI", 9), background="#f7f7f7", undo=False)
            ybar = ttk.Scrollbar(frame, orient="vertical", command=text_box.yview)
            xbar = ttk.Scrollbar(frame, orient="horizontal", command=text_box.xview)
            text_box.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
            text_box.grid(row=0, column=0, sticky="nsew")
            ybar.grid(row=0, column=1, sticky="ns")
            xbar.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
            text_box.insert("1.0", value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2, default=str))
            text_box.configure(state="disabled")
            return text_box

        summary = {k: v for k, v in pe.items() if k not in {"imports", "exports", "strings", "disassembly", "sections"}}
        summary["file"] = {k: report.get(k) for k in ("name", "path", "size_bytes", "sha256", "modified_local", "authenticode", "zone_identifier")}
        add_text_tab(self._artifact_text("Обзор", "Summary", "Огляд"), summary)
        add_text_tab(self._artifact_text("Секции", "Sections", "Секції"), pe.get("sections", []))
        add_text_tab(self._artifact_text("Импорты", "Imports", "Імпорти"), pe.get("imports", []))
        add_text_tab(self._artifact_text("Экспорты", "Exports", "Експорти"), pe.get("exports", []))
        add_text_tab(self._artifact_text("Строки", "Strings", "Рядки"), pe.get("strings", []))
        disassembly = pe.get("disassembly", {})
        instructions = disassembly.get("instructions", []) if isinstance(disassembly, dict) else []
        if instructions:
            asm_lines = [f"{row.get('address', ''):>14}  {row.get('bytes', ''):<24}  {row.get('mnemonic', '')} {row.get('operands', '')}    ; {row.get('section', '')}" for row in instructions]
            asm_text = "\n".join(asm_lines)
        else:
            asm_text = str(disassembly.get("note", "Дизассемблировка недоступна.")) if isinstance(disassembly, dict) else "Дизассемблировка недоступна."
        add_text_tab(self._artifact_text("Машинный код", "Machine code", "Машинний код"), asm_text)
        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(6, 0))
        ttk.Button(footer, text=self._artifact_text("Скопировать SHA-256", "Copy SHA-256", "Копіювати SHA-256"), command=lambda: (window.clipboard_clear(), window.clipboard_append(str(report.get("sha256", ""))))).pack(side="left")
        ttk.Button(footer, text=self._artifact_text("Экспорт JSON…", "Export JSON…", "Експорт JSON…"), command=lambda: self._export_pe_report(report)).pack(side="left", padx=(6, 0))
        ttk.Button(footer, text=self._artifact_text("Закрыть", "Close", "Закрити"), command=window.destroy).pack(side="right")

    def _export_pe_report(self, report: dict[str, Any]) -> None:
        path = filedialog.asksaveasfilename(
            title=self._artifact_text("Сохранить PE-анализ", "Save PE analysis", "Зберегти аналіз PE"),
            defaultextension=".json", filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.status_var.set(self._artifact_text("PE-анализ сохранён", "PE analysis saved", "Аналіз PE збережено") + ": " + path)
        except Exception as exc:
            messagebox.showerror(self._artifact_text("Ошибка экспорта", "Export error", "Помилка експорту"), str(exc))

    def on_artifact_open(self, _event: Any = None) -> None:
        selected = self.artifact_tree.selection()
        if not selected:
            return
        try:
            row = self._artifact_item_rows[int(selected[0])]["item"]
            path = row.get("path") if isinstance(row, dict) else ""
            if path and Path(path).is_file():
                self._start_artifact_job("file", lambda: inspect_static_file(Path(path)))
        except Exception:
            pass

    def render_relationships(self) -> None:
        if not hasattr(self, "artifact_links_tree"):
            return
        self.artifact_links_tree.delete(*self.artifact_links_tree.get_children())
        combined = list(self.events) + list(self.forensic_rows)
        links = correlate_events(combined)
        self._artifact_links = links
        self._artifact_link_event_indices = []
        for link in links:
            a = int(link.get("from_event_index", link.get("parent_event_index", link.get("python_event_index", -1))))
            b = int(link.get("to_event_index", link.get("child_event_index", link.get("java_event_index", -1))))
            if a < 0 or b < 0 or a >= len(combined) or b >= len(combined):
                continue
            arow, brow = combined[a], combined[b]
            atext = f"{arow.get('timestamp', '')} • {arow.get('description', '')}"[:160]
            btext = f"{brow.get('timestamp', '')} • {brow.get('description', '')}"[:160]
            basis = str(link.get("basis", ""))
            delta = link.get("time_delta_seconds")
            iid = str(len(self._artifact_link_event_indices))
            self._artifact_link_event_indices.append((a, b))
            self.artifact_links_tree.insert("", "end", iid=iid, values=(link.get("relation", ""), link.get("confidence", ""),
                f"{delta:.3f}s" if isinstance(delta, (int, float)) else "—", atext, btext, basis[:400]))
        self.draw_relationship_graph()

    def draw_relationship_graph(self) -> None:
        canvas = getattr(self, "relationship_canvas", None)
        if canvas is None:
            return
        try:
            canvas.delete("all")
            links = list(getattr(self, "_artifact_links", []))
            combined = list(self.events) + list(self.forensic_rows)
            width = max(640, canvas.winfo_width())
            if not links:
                canvas.create_text(12, 18, anchor="w", text=self._artifact_text(
                    "Пока нет подтверждённых связей процессов/событий. Временная близость сама по себе не создаёт связь.",
                    "No process/event links are available yet. Time proximity alone does not create a link.",
                    "Поки немає підтверджених зв’язків процесів/подій. Часова близькість сама по собі не створює зв’язок."),
                    fill="#666666", font=("Segoe UI", 9))
                return
            visible = links[:5]
            canvas.configure(height=max(112, 22 + len(visible) * 29))
            left_x = 10
            box_width = min(290, max(180, int(width * 0.34)))
            right_x = width - box_width - 10
            if right_x < left_x + box_width + 70:
                right_x = left_x + box_width + 70
            for index, link in enumerate(visible):
                a = int(link.get("from_event_index", link.get("parent_event_index", link.get("python_event_index", -1))))
                b = int(link.get("to_event_index", link.get("child_event_index", link.get("java_event_index", -1))))
                if not (0 <= a < len(combined) and 0 <= b < len(combined)):
                    continue
                y = 17 + index * 29
                arow, brow = combined[a], combined[b]
                def node_text(row: dict[str, Any]) -> str:
                    stamp = str(row.get("timestamp", ""))[-8:]
                    label = str(row.get("description") or row.get("kind") or "Event")
                    return (stamp + "  " + label).strip()[:43]
                canvas.create_rectangle(left_x, y - 9, left_x + box_width, y + 9,
                    fill="#f2f5f8", outline="#b8c4d0")
                canvas.create_text(left_x + 6, y, anchor="w", text=node_text(arow), fill="#263442", font=("Segoe UI", 8))
                canvas.create_rectangle(right_x, y - 9, right_x + box_width, y + 9,
                    fill="#f2f5f8", outline="#b8c4d0")
                canvas.create_text(right_x + 6, y, anchor="w", text=node_text(brow), fill="#263442", font=("Segoe UI", 8))
                canvas.create_line(left_x + box_width + 5, y, right_x - 5, y, fill="#7b8794", width=1, arrow="last")
                relation = str(link.get("relation", "link"))
                confidence = str(link.get("confidence", ""))
                canvas.create_text((left_x + box_width + right_x) / 2, y - 8,
                    text=(relation + " · " + confidence)[:42], fill="#5d6975", font=("Segoe UI", 7))
            if len(links) > len(visible):
                canvas.create_text(12, 17 + len(visible) * 29, anchor="w",
                    text=self._artifact_text(f"Показаны первые {len(visible)} связей; полный список — в таблице ниже.",
                        f"Showing first {len(visible)} links; see the table below for all links.",
                        f"Показано перші {len(visible)} зв’язків; повний список — у таблиці нижче."),
                    fill="#666666", font=("Segoe UI", 8))
        except Exception:
            pass

    def open_linked_event(self, _event: Any = None) -> None:
        selected = self.artifact_links_tree.selection()
        if not selected:
            return
        try:
            a, b = self._artifact_link_event_indices[int(selected[0])]
            combined = list(self.events) + list(self.forensic_rows)
            self.show_artifact_details({"event_a": combined[a], "event_b": combined[b], "relationship": self._artifact_links[int(selected[0])]})
        except Exception:
            pass

    def draw_activity_heatmap(self) -> None:
        if not hasattr(self, "heatmap_canvas"):
            return
        result = build_hourly_heatmap(list(self.events) + list(self.forensic_rows), days=14)
        canvas = self.heatmap_canvas
        canvas.delete("all")
        cell_w, cell_h, left, top = 34, 17, 112, 28
        rows = result["rows"]
        maximum = max((max(row["hours"]) for row in rows), default=0)
        canvas.create_text(8, 10, anchor="w", text=self._artifact_text("Дата", "Date", "Дата"), fill="#333333")
        for hour in range(24):
            if hour % 2 == 0:
                canvas.create_text(left + hour * cell_w + cell_w / 2, 12, text=f"{hour:02d}", fill="#555555", font=("Segoe UI", 8))
        for r, row in enumerate(rows):
            y = top + r * cell_h
            canvas.create_text(8, y + cell_h / 2, anchor="w", text=row["date"][5:], fill="#333333", font=("Segoe UI", 8))
            for hour, count in enumerate(row["hours"]):
                intensity = 0 if maximum == 0 else count / maximum
                # Same subdued blue/grey visual language as the current interface.
                if intensity <= 0:
                    fill = "#f1f3f5"
                elif intensity < 0.25:
                    fill = "#dce5ef"
                elif intensity < 0.5:
                    fill = "#b7c9dc"
                elif intensity < 0.75:
                    fill = "#829fbd"
                else:
                    fill = "#4f7198"
                x = left + hour * cell_w
                canvas.create_rectangle(x, y, x + cell_w - 2, y + cell_h - 2, fill=fill, outline="#ffffff")
                if count:
                    canvas.create_text(x + (cell_w - 2) / 2, y + (cell_h - 2) / 2, text=str(count), fill="#1f2933", font=("Segoe UI", 7))
        canvas.configure(scrollregion=(0, 0, left + 24 * cell_w + 4, top + len(rows) * cell_h + 8))
        self.heatmap_summary_var.set(self._artifact_text("Событий за период:", "Events in period:", "Подій за період:") + f" {result['total_events']} • " + result["note"])

    def _global_search_collections(self) -> dict[str, list[Any]]:
        return {
            "Python / IDE / terminal events": list(getattr(self, "events", [])),
            "Windows system events": list(getattr(self, "forensic_rows", [])),
            "Browser history": list(getattr(self, "browser_detail_rows", [])),
            "Browser downloads": list(getattr(self, "download_detail_rows", [])),
            "Python processes": list(getattr(self, "runtime_detail_rows", [])),
            "Java processes": list(getattr(self, "java_detail_rows", [])),
            "Suspicious activity": list(getattr(self, "suspicious_detail_rows", [])),
            "Windows artifact events": list(getattr(self, "artifact_events", [])),
            "Windows artifact sources": list(getattr(self, "artifact_sources", [])),
            "Python source files": list(getattr(self, "python_files", [])),
            "Process snapshot": list(getattr(self, "process_rows", [])),
            "Recorded local sessions": list(getattr(self, "session_rows", [])),
            "Signature checks": list(getattr(self, "signature_checks", [])),
            "Case evidence": list(getattr(getattr(self, "case_payload", {}), "get", lambda *_: [])("evidence", [])),
        }

    def open_global_search(self, _event: Any = None) -> str:
        window = tk.Toplevel(self.root)
        window.title(self._artifact_text("Глобальный поиск по результатам", "Global search across results", "Глобальний пошук за результатами"))
        window.geometry("1120x700")
        window.minsize(820, 500)
        outer = ttk.Frame(window, padding=8)
        outer.pack(fill="both", expand=True)
        top = ttk.Frame(outer)
        top.pack(fill="x", pady=(0, 7))
        query_var = tk.StringVar()
        ttk.Label(top, text=self._artifact_text("Запрос:", "Query:", "Запит:")).pack(side="left")
        entry = ttk.Entry(top, textvariable=query_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        case_var = tk.BooleanVar(value=False)
        regex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text=self._artifact_text("Учитывать регистр", "Case-sensitive", "Враховувати регістр"), variable=case_var).pack(side="left", padx=4)
        ttk.Checkbutton(top, text="Regex", variable=regex_var).pack(side="left", padx=4)
        status_var = tk.StringVar(value=self._artifact_text("Поиск выполняется только по уже загруженным данным.", "Search covers only data already loaded in this session.", "Пошук виконується лише за вже завантаженими даними."))
        ttk.Label(outer, textvariable=status_var, foreground="#555555").pack(anchor="w", pady=(0, 5))
        pane = ttk.Panedwindow(outer, orient="vertical")
        pane.pack(fill="both", expand=True)
        result_frame = ttk.Frame(pane)
        detail_frame = ttk.Frame(pane)
        pane.add(result_frame, weight=3)
        pane.add(detail_frame, weight=2)
        cols = ("section", "timestamp", "title", "source")
        tree = ttk.Treeview(result_frame, columns=cols, show="headings", selectmode="extended")
        labels = {"section": self._artifact_text("Раздел", "Section", "Розділ"), "timestamp": self._artifact_text("Время", "Time", "Час"), "title": self._artifact_text("Название / тип", "Name / type", "Назва / тип"), "source": self._artifact_text("Источник / путь", "Source / path", "Джерело / шлях")}
        for col, width in (("section", 190), ("timestamp", 165), ("title", 230), ("source", 420)):
            tree.heading(col, text=labels[col])
            tree.column(col, width=width, minwidth=70, stretch=(col in {"title", "source"}))
        sy = ttk.Scrollbar(result_frame, orient="vertical", command=tree.yview)
        sx = ttk.Scrollbar(result_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        tree.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        result_frame.rowconfigure(0, weight=1); result_frame.columnconfigure(0, weight=1)
        details = tk.Text(detail_frame, height=10, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        dy = ttk.Scrollbar(detail_frame, orient="vertical", command=details.yview)
        details.configure(yscrollcommand=dy.set)
        details.grid(row=0, column=0, sticky="nsew"); dy.grid(row=0, column=1, sticky="ns")
        detail_frame.rowconfigure(0, weight=1); detail_frame.columnconfigure(0, weight=1)
        hits: list[dict[str, Any]] = []

        def run_search(_event: Any = None) -> None:
            nonlocal hits
            tree.delete(*tree.get_children())
            details.delete("1.0", "end")
            q = query_var.get().strip()
            if not q:
                status_var.set(self._artifact_text("Введите текст для поиска.", "Enter text to search.", "Введіть текст для пошуку."))
                hits = []
                return
            try:
                hits = search_loaded_data(self._global_search_collections(), q, case_sensitive=case_var.get(), regex=regex_var.get())
            except re.error as exc:
                status_var.set(self._artifact_text("Некорректное регулярное выражение:", "Invalid regular expression:", "Некоректний регулярний вираз:") + " " + str(exc))
                hits = []
                return
            for index, hit in enumerate(hits):
                tree.insert("", "end", iid=str(index), values=(hit["section"], hit["timestamp"], hit["title"], hit["source"]))
            status_var.set(self._artifact_text("Найдено:", "Found:", "Знайдено:") + f" {len(hits)}")

        def show_hit(_event: Any = None) -> None:
            selected = tree.selection()
            if not selected:
                return
            try:
                row = hits[int(selected[0])]
            except (ValueError, IndexError):
                return
            details.delete("1.0", "end")
            details.insert("1.0", json.dumps(row.get("row", {}), ensure_ascii=False, indent=2, default=str))

        def copy_hit() -> None:
            selected = tree.selection()
            if not selected:
                return
            payload = "\n\n".join(json.dumps(hits[int(i)].get("row", {}), ensure_ascii=False, indent=2, default=str) for i in selected)
            window.clipboard_clear(); window.clipboard_append(payload)
            status_var.set(self._artifact_text("Выбранные результаты скопированы.", "Selected results copied.", "Вибрані результати скопійовано."))

        tree.bind("<<TreeviewSelect>>", show_hit)
        tree.bind("<Double-1>", show_hit)
        entry.bind("<Return>", run_search)
        buttons = ttk.Frame(outer); buttons.pack(fill="x", pady=(7, 0))
        ttk.Button(buttons, text=self._artifact_text("Найти", "Search", "Знайти"), command=run_search).pack(side="left")
        ttk.Button(buttons, text=self._artifact_text("Копировать выбранное", "Copy selected", "Копіювати вибране"), command=copy_hit).pack(side="left", padx=5)
        ttk.Button(buttons, text=self._artifact_text("Закрыть", "Close", "Закрити"), command=window.destroy).pack(side="right")
        entry.focus_set()
        return "break"

    def compare_static_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title=self._artifact_text("Выберите ровно два файла для статического сравнения", "Select exactly two files for static comparison", "Виберіть рівно два файли для статичного порівняння"),
            filetypes=[("PE / DLL / EXE / JAR / files", "*.dll *.exe *.sys *.jar *.zip *.py *.pyw *.*")],
        )
        if not paths:
            return
        if len(paths) != 2:
            messagebox.showwarning(self._artifact_text("Сравнение файлов", "File comparison", "Порівняння файлів"), self._artifact_text("Нужно выбрать ровно два файла.", "Select exactly two files.", "Потрібно вибрати рівно два файли."))
            return
        self._start_artifact_job("compare_files", lambda: {
            "left": inspect_static_file(Path(paths[0]), signature_check=False),
            "right": inspect_static_file(Path(paths[1]), signature_check=False),
        })

    def open_file_comparison_window(self, payload: dict[str, Any]) -> None:
        comparison = compare_file_reports(payload.get("left", {}), payload.get("right", {}))
        window = tk.Toplevel(self.root)
        window.title(self._artifact_text("Сравнение файлов — статический анализ", "File comparison — static analysis", "Порівняння файлів — статичний аналіз"))
        window.geometry("1000x700")
        outer = ttk.Frame(window, padding=8); outer.pack(fill="both", expand=True)
        ttk.Label(outer, text=self._artifact_text("Оба файла анализировались без запуска.", "Both files were inspected without execution.", "Обидва файли аналізувалися без запуску."), foreground="#555555").pack(anchor="w", pady=(0, 5))
        text = tk.Text(outer, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        scroll = ttk.Scrollbar(outer, orient="vertical", command=text.yview); text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y")
        text.insert("1.0", json.dumps(comparison, ensure_ascii=False, indent=2, default=str)); text.configure(state="disabled")

    def render_case_evidence(self) -> None:
        if not hasattr(self, "case_evidence_tree"):
            return
        self.case_evidence_tree.delete(*self.case_evidence_tree.get_children())
        self.case_evidence_rows = list(getattr(self, "case_payload", {}).get("evidence", []))
        results = {str(row.get("evidence_id")): row for row in self.case_verification.get("evidence", [])}
        for row in self.case_evidence_rows:
            status = results.get(str(row.get("evidence_id")), {}).get("status", "not_checked")
            if not row.get("included", True):
                status = "excluded"
            size = int(row.get("size_bytes", 0) or 0)
            size_text = f"{size:,} B".replace(",", " ")
            self.case_evidence_tree.insert("", "end", iid=str(row.get("evidence_id")), values=(row.get("name", ""), size_text, row.get("sha256", ""), status))
        audit = self.case_verification.get("audit_chain", {})
        if audit:
            label = ("Журнал: целостен" if audit.get("valid") else "Журнал: ошибка") if self.lang == "ru" else ("Audit: valid" if audit.get("valid") else "Audit: invalid")
            self.case_integrity_var.set(f"{label} • {self.case_verification.get('evidence_ok', 0)}/{len(self.case_evidence_rows)}")
        else:
            self.case_integrity_var.set(self._artifact_text("Целостность ещё не проверялась", "Integrity not checked", "Цілісність ще не перевіряли"))

    def add_case_evidence_files(self) -> None:
        paths = filedialog.askopenfilenames(title=self._artifact_text("Добавить копии файлов в дело", "Add file copies to case", "Додати копії файлів до справи"))
        if not paths:
            return
        if len(paths) > 100:
            messagebox.showwarning(self._artifact_text("Лимит файлов", "File limit", "Обмеження файлів"), self._artifact_text("За один раз можно добавить не более 100 файлов.", "Add no more than 100 files at once.", "За один раз можна додати не більше 100 файлів."))
            return
        note = simpledialog.askstring(self._artifact_text("Примечание к доказательствам", "Evidence note", "Примітка до доказів"), self._artifact_text("Общее примечание для выбранных файлов (необязательно):", "Shared note for selected files (optional):", "Спільна примітка для вибраних файлів (необов’язково):"), parent=self.root) or ""
        payload_copy = json.loads(json.dumps(self._current_case_payload(), ensure_ascii=False, default=str))
        case_path = Path(self.active_case_file)
        def work() -> dict[str, Any]:
            added, errors = [], []
            for item in paths:
                try:
                    added.append(add_case_evidence(payload_copy, case_path, item, note))
                except Exception as exc:
                    errors.append({"path": str(item), "error": f"{type(exc).__name__}: {exc}"})
            return {"case_payload": payload_copy, "added": added, "errors": errors}
        self._start_artifact_job("case_evidence", work)

    def show_case_evidence_details(self, _event: Any = None) -> None:
        selected = self.case_evidence_tree.selection() if hasattr(self, "case_evidence_tree") else ()
        if not selected:
            return
        record = next((row for row in self.case_evidence_rows if str(row.get("evidence_id")) == str(selected[0])), None)
        if record:
            messagebox.showinfo(self._artifact_text("Сведения о доказательстве", "Evidence details", "Відомості про доказ"), json.dumps(record, ensure_ascii=False, indent=2))

    def verify_case_dialog(self) -> None:
        payload_copy = json.loads(json.dumps(self._current_case_payload(), ensure_ascii=False, default=str))
        case_path = Path(self.active_case_file)
        self._start_artifact_job("case_verify", lambda: verify_case_integrity(payload_copy, case_path))

    def exclude_case_evidence(self) -> None:
        selected = self.case_evidence_tree.selection() if hasattr(self, "case_evidence_tree") else ()
        if not selected:
            return
        payload = self._current_case_payload()
        changed = 0
        for evidence_id in selected:
            changed += int(mark_evidence_excluded(payload, evidence_id))
        if changed:
            persist_case_payload(payload, self.active_case_file)
            self.case_payload = payload
            self.case_verification = {}
            self.render_case_evidence()
            self.status_var.set(self._artifact_text("Файлы исключены из состава пакета; копии сохранены.", "Files excluded from package; stored copies were kept.", "Файли виключено з пакета; копії збережено."))

    def export_case_package_dialog(self) -> None:
        name = re.sub(r"[^\w.-]+", "_", self.case_name_var.get().strip(), flags=re.UNICODE).strip("._") or "case"
        destination = filedialog.asksaveasfilename(title=self._artifact_text("Экспорт переносимого дела", "Export portable case", "Експорт переносної справи"), initialdir=str(self.case_dir), initialfile=name + ".pavcase", defaultextension=".pavcase", filetypes=[("PAV case package", "*.pavcase"), ("ZIP", "*.zip")])
        if not destination:
            return
        payload_copy = json.loads(json.dumps(self._current_case_payload(), ensure_ascii=False, default=str))
        case_path = Path(self.active_case_file)
        self._start_artifact_job("case_export", lambda: {"case_payload": payload_copy, "result": export_case_package(payload_copy, case_path, destination, APP_VERSION)})

    def import_case_package_dialog(self) -> None:
        package = filedialog.askopenfilename(title=self._artifact_text("Импорт переносимого дела", "Import portable case", "Імпорт переносної справи"), filetypes=[("PAV case package", "*.pavcase *.zip"), ("All files", "*.*")])
        if not package:
            return
        root = filedialog.askdirectory(title=self._artifact_text("Папка для импортированного дела", "Destination folder for imported case", "Папка для імпортованої справи"))
        if not root:
            return
        self._start_artifact_job("case_import", lambda: import_case_package(package, root))

    def export_pdf(self) -> None:
        destination = filedialog.asksaveasfilename(title=self._artifact_text("Экспорт PDF-отчёта", "Export PDF report", "Експорт PDF-звіту"), defaultextension=".pdf", filetypes=[("PDF", "*.pdf")], initialfile="python_activity_report.pdf")
        if not destination:
            return
        report = {
            "application": APP_NAME, "version": APP_VERSION,
            "generated_local": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"),
            "case_context": {"case": self._current_case_payload()},
            "analysis_quality": self.analysis_quality,
            "events": list(self.events),
            "system_trace_analysis": {"events": list(getattr(self, "forensic_rows", []))},
            "warnings": list(self.warnings) + list(getattr(self, "forensic_warnings", [])),
            "errors": list(self.errors),
        }
        try:
            result = build_pdf_report(report, destination)
            self.status_var.set(self._artifact_text("PDF-отчёт сохранён:", "PDF report saved:", "PDF-звіт збережено:") + " " + destination)
            messagebox.showinfo(self._artifact_text("Экспорт PDF", "PDF export", "Експорт PDF"), f"{destination}\n{result['events_included']} events included")
        except Exception as exc:
            messagebox.showerror(self._artifact_text("Экспорт PDF", "PDF export", "Експорт PDF"), str(exc))

    def _current_case_payload(self) -> dict[str, Any]:
        payload = getattr(self, "case_payload", None)
        if not isinstance(payload, dict):
            payload = create_case_payload(self.case_name_var.get())
            self.case_payload = payload
        payload["schema"] = payload.get("schema", "python-activity-view.case")
        payload["schema_version"] = 1
        payload["name"] = self.case_name_var.get().strip() or "Unnamed case"
        payload["notes"] = self.case_notes_text.get("1.0", "end-1c")
        payload["trusted_context_paths"] = list(self.trusted_paths)
        return payload

    def save_case_notes(self) -> None:
        try:
            payload = self._current_case_payload()
            append_case_audit(payload, "case_saved", {"notes_length": len(payload.get("notes", "")), "evidence_count": len(payload.get("evidence", []))})
            target = Path(getattr(self, "active_case_file", self.case_notes_file))
            persist_case_payload(payload, target)
            self.case_payload = payload
            self.case_notes_initial = payload["notes"]
            if hasattr(self, "case_file_var"):
                self.case_file_var.set(target.name)
            self.status_var.set(self._artifact_text("Материалы дела сохранены:", "Case saved:", "Матеріали справи збережено:") + " " + str(target))
            self.render_case_evidence()
        except Exception as exc:
            messagebox.showerror(self._artifact_text("Материалы дела", "Case notes", "Матеріали справи"), str(exc))

    def new_case(self) -> None:
        name = simpledialog.askstring(self._artifact_text("Новое дело", "New case", "Нова справа"),
            self._artifact_text("Название проверки:", "Case name:", "Назва перевірки:"), parent=self.root)
        if not name or not name.strip():
            return
        try:
            self.save_case_notes()
        except Exception:
            pass
        stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        safe = re.sub(r"[^\w.-]+", "_", name.strip(), flags=re.UNICODE).strip("._")[:48] or "case"
        self.active_case_file = self.case_dir / f"{safe}_{stamp}.json"
        self.case_name_var.set(name.strip())
        self.case_notes_text.delete("1.0", "end")
        self.case_payload = create_case_payload(name.strip())
        self.case_verification = {}
        if hasattr(self, "case_file_var"):
            self.case_file_var.set(self.active_case_file.name)
        self.save_case_notes()

    def open_case(self) -> None:
        path = filedialog.askopenfilename(title=self._artifact_text("Открыть материалы дела", "Open case", "Відкрити матеріали справи"),
            initialdir=str(self.case_dir), filetypes=[("PAV case JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            payload = load_case_payload(path)
            self.active_case_file = Path(path)
            self.case_payload = payload
            self.case_verification = {}
            self.case_name_var.set(str(payload.get("name", "Unnamed case")))
            self.case_notes_text.delete("1.0", "end")
            self.case_notes_text.insert("1.0", str(payload.get("notes", "")))
            self.case_notes_initial = str(payload.get("notes", ""))
            if hasattr(self, "case_file_var"):
                self.case_file_var.set(self.active_case_file.name)
            self.render_case_evidence()
            self.status_var.set(self._artifact_text("Дело открыто:", "Case opened:", "Справу відкрито:") + " " + str(self.active_case_file))
        except Exception as exc:
            messagebox.showerror(self._artifact_text("Открыть дело", "Open case", "Відкрити справу"), str(exc))

    def save_case_as(self) -> None:
        name = re.sub(r"[^\w.-]+", "_", self.case_name_var.get().strip(), flags=re.UNICODE).strip("._") or "case"
        path = filedialog.asksaveasfilename(title=self._artifact_text("Сохранить дело как", "Save case as", "Зберегти справу як"),
            initialdir=str(self.case_dir), initialfile=name + ".json", defaultextension=".json",
            filetypes=[("PAV case JSON", "*.json"), ("All files", "*.*")])
        if not path:
            return
        try:
            payload = self._current_case_payload()
            relocate_case(payload, self.active_case_file, path)
            self.active_case_file = Path(path)
            self.case_payload = payload
            self.case_verification = {}
            if hasattr(self, "case_file_var"):
                self.case_file_var.set(self.active_case_file.name)
            self.render_case_evidence()
            self.status_var.set(self._artifact_text("Дело сохранено в новом месте:", "Case saved to new location:", "Справу збережено в новому місці:") + " " + str(path))
        except Exception as exc:
            messagebox.showerror(self._artifact_text("Сохранить дело как", "Save case as", "Зберегти справу як"), str(exc))

    def browse_trusted_path(self) -> None:
        path = filedialog.askopenfilename(title=self._artifact_text("Выбрать исполняемый файл", "Select executable", "Вибрати виконуваний файл"),
            filetypes=[("Applications", "*.exe *.dll *.jar"), ("All files", "*.*")])
        if path:
            self.trusted_path_var.set(path)

    def add_trusted_path(self) -> None:
        value = self.trusted_path_var.get().strip()
        if not value:
            return
        normalized = os.path.normcase(os.path.normpath(value))
        if normalized not in {os.path.normcase(os.path.normpath(p)) for p in self.trusted_paths}:
            self.trusted_paths.append(value)
        self.settings["trusted_paths"] = list(self.trusted_paths)
        try:
            self.settings_path.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        self.trusted_path_var.set("")
        self.render_trusted_paths()
        self.save_case_notes()

    def remove_trusted_path(self) -> None:
        selected = self.trusted_listbox.curselection()
        if not selected:
            return
        del self.trusted_paths[selected[0]]
        self.settings["trusted_paths"] = list(self.trusted_paths)
        try:
            self.settings_path.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        self.render_trusted_paths()

    def render_trusted_paths(self) -> None:
        if not hasattr(self, "trusted_listbox"):
            return
        self.trusted_listbox.delete(0, "end")
        for value in self.trusted_paths:
            self.trusted_listbox.insert("end", value)

    def render_plugin_list(self) -> None:
        if not hasattr(self, "plugin_tree"):
            return
        self.plugin_tree.delete(*self.plugin_tree.get_children())
        try:
            rows = self.plugin_registry.discover()
        except Exception as exc:
            rows = [{"file": "—", "status": "error", "note": str(exc)}]
        for i, row in enumerate(rows):
            self.plugin_tree.insert("", "end", iid=str(i), values=(row.get("file", ""), row.get("status", ""), row.get("note", "")))
        if not rows:
            self.plugin_tree.insert("", "end", values=("—", "none", self._artifact_text("Папка plugins пуста. Добавьте собственный модуль по шаблону из PLUGINS_RU.txt.",
                "plugins folder is empty. Add your own module using PLUGINS_RU.txt.", "Папка plugins порожня. Додайте власний модуль за шаблоном із PLUGINS_RU.txt.")))

    def _build_overview_tab(self) -> None:
        self.risk_status_var = tk.StringVar(value=self.T("risk_not_run"))
        risk_line = ttk.Label(self.overview_tab, textvariable=self.risk_status_var, wraplength=1400, justify="left", foreground="#4b4b4b")
        risk_line.pack(fill="x", anchor="w", pady=(0, 8))
        cards = ttk.Frame(self.overview_tab)
        cards.pack(fill="x", pady=(0, 8))
        self.overview_vars = [tk.StringVar(value="0") for _ in range(4)]
        self.overview_labels = []
        metric_defs = [("overview_events", "events"), ("overview_files", "files"), ("overview_sources", "sources"), ("overview_warnings", "warnings")]
        for index, (title_key, _field) in enumerate(metric_defs):
            card = ttk.LabelFrame(cards, text=self.T(title_key), padding=(10, 7))
            card.pack(side="left", fill="both", expand=True, padx=(0 if index == 0 else 7, 0))
            label = ttk.Label(card, textvariable=self.overview_vars[index], font=("Segoe UI", 20, "bold"))
            label.pack(anchor="w")
            self.overview_labels.append(label)
        lower = ttk.Panedwindow(self.overview_tab, orient="horizontal")
        lower.pack(fill="both", expand=True)
        timeline_frame = ttk.LabelFrame(lower, text=self.T("timeline"), padding=7)
        recent_frame = ttk.LabelFrame(lower, text=self.T("recent"), padding=7)
        lower.add(timeline_frame, weight=2)
        lower.add(recent_frame, weight=3)
        self.timeline_text = tk.Text(timeline_frame, height=14, wrap="none", font=("Consolas", 10), background="#f7f7f7", relief="solid", borderwidth=1)
        self.timeline_text.pack(fill="both", expand=True)
        self.timeline_text.insert("1.0", self.T("no_events"))
        self.timeline_text.configure(state="disabled")
        recent_cols = ("date", "time", "kind", "command")
        self.recent_tree = ttk.Treeview(recent_frame, columns=recent_cols, show="headings", height=12)
        for col, key, width in [("date", "date", 95), ("time", "time", 75), ("kind", "event_type", 200), ("command", "command", 360)]:
            self.recent_tree.heading(col, text=self.T(key))
            self.recent_tree.column(col, width=width, minwidth=65, stretch=(col in {"kind", "command"}))
        self.recent_tree.pack(fill="both", expand=True)
        self.recent_tree.bind("<Double-1>", self._open_recent_event)

    def _build_readiness_tab(self) -> None:
        top = ttk.Frame(self.readiness_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Label(top, text=self.T("readiness_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(top, text=self.T("readiness_note"), foreground="#666666", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        controls = ttk.Frame(top)
        controls.pack(fill="x")
        self.readiness_refresh_button = ttk.Button(controls, text=self.T("readiness_refresh"), command=self.start_readiness_check)
        self.readiness_refresh_button.pack(side="left")
        self.readiness_status_var = tk.StringVar(value=self.T("readiness_summary") + ": —")
        ttk.Label(controls, textvariable=self.readiness_status_var, foreground="#555555").pack(side="left", padx=(12, 0))
        self.coverage_status_var = tk.StringVar(value=self.T("coverage_summary") + ": —")
        ttk.Label(top, textvariable=self.coverage_status_var, foreground="#555555", wraplength=1400).pack(anchor="w", pady=(5, 0))

        pane = ttk.Panedwindow(self.readiness_tab, orient="vertical")
        pane.pack(fill="both", expand=True)
        upper = ttk.Frame(pane)
        lower = ttk.Frame(pane)
        pane.add(upper, weight=3)
        pane.add(lower, weight=2)
        cols = ("category", "name", "status", "note")
        self.readiness_tree = ttk.Treeview(upper, columns=cols, show="headings")
        labels = {
            "category": self.T("readiness_category"),
            "name": self.T("readiness_name"),
            "status": self.T("readiness_status"),
            "note": self.T("readiness_note_col"),
        }
        widths = {"category": 180, "name": 260, "status": 125, "note": 650}
        for col in cols:
            self.readiness_tree.heading(col, text=labels[col])
            self.readiness_tree.column(col, width=widths[col], minwidth=90, stretch=(col == "note"))
        ry = ttk.Scrollbar(upper, orient="vertical", command=self.readiness_tree.yview)
        rx = ttk.Scrollbar(upper, orient="horizontal", command=self.readiness_tree.xview)
        self.readiness_tree.configure(yscrollcommand=ry.set, xscrollcommand=rx.set)
        self.readiness_tree.grid(row=0, column=0, sticky="nsew")
        ry.grid(row=0, column=1, sticky="ns")
        rx.grid(row=1, column=0, sticky="ew")
        upper.rowconfigure(0, weight=1)
        upper.columnconfigure(0, weight=1)
        self.readiness_tree.bind("<<TreeviewSelect>>", self.on_readiness_select)
        ttk.Label(lower, text=self.T("readiness_detail"), font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 3))
        self.readiness_detail_text = tk.Text(lower, height=9, wrap="word", font=("Consolas", 9), background="#f7f7f7", relief="solid", borderwidth=1)
        rd = ttk.Scrollbar(lower, orient="vertical", command=self.readiness_detail_text.yview)
        self.readiness_detail_text.configure(yscrollcommand=rd.set)
        self.readiness_detail_text.pack(side="left", fill="both", expand=True)
        rd.pack(side="right", fill="y")
        self.readiness_detail_text.insert("1.0", self.T("readiness_note"))
        self.readiness_detail_text.configure(state="disabled")

    def _readiness_status_label(self, status: str) -> str:
        labels = {
            "ru": {"enabled": "Включено сейчас", "disabled": "Отключено сейчас", "available": "Доступно", "standard_user": "Обычные права", "inaccessible": "Нет доступа", "not_found": "Не найдено", "not_applicable": "Не применяется", "unknown": "Не удалось определить", "not_configured": "Не настроено", "error": "Ошибка", "timeout": "Тайм-аут", "observed": "Обнаружено", "exported": "Экспортировано", "skipped": "Пропущено", "not_run": "Не запускалось", "incomplete": "Неполная проверка", "undetermined": "Неопределённо", "reviewed_known_sources": "Проверены известные источники"},
            "en": {"enabled": "Enabled now", "disabled": "Disabled now", "available": "Available", "standard_user": "Standard user", "inaccessible": "Inaccessible", "not_found": "Not found", "not_applicable": "Not applicable", "unknown": "Unknown", "not_configured": "Not configured", "error": "Error", "timeout": "Timeout", "observed": "Observed", "exported": "Exported", "skipped": "Skipped", "not_run": "Not run", "incomplete": "Incomplete", "undetermined": "Undetermined", "reviewed_known_sources": "Known sources reviewed"},
            "uk": {"enabled": "Увімкнено зараз", "disabled": "Вимкнено зараз", "available": "Доступно", "standard_user": "Звичайні права", "inaccessible": "Немає доступу", "not_found": "Не знайдено", "not_applicable": "Не застосовується", "unknown": "Не вдалося визначити", "not_configured": "Не налаштовано", "error": "Помилка", "timeout": "Тайм-аут", "observed": "Виявлено", "exported": "Експортовано", "skipped": "Пропущено", "not_run": "Не запускалося", "incomplete": "Неповна перевірка", "undetermined": "Невизначено", "reviewed_known_sources": "Перевірено відомі джерела"},
        }
        return labels.get(self.lang, labels["ru"]).get(status, status)

    def render_readiness_panel(self) -> None:
        if not hasattr(self, "readiness_tree"):
            return
        self.readiness_tree.delete(*self.readiness_tree.get_children())
        self.readiness_rows = []
        compatibility = (self.readiness_report or {}).get("environment", {})
        category_labels = {
            "ru": {"environment": "Среда", "coverage": "Полнота"},
            "en": {"environment": "Environment", "coverage": "Coverage"},
            "uk": {"environment": "Середовище", "coverage": "Повнота"},
        }
        categories = category_labels.get(self.lang, category_labels["ru"])
        for item in compatibility.get("capabilities", []):
            self.readiness_rows.append({"category": categories["environment"], **item})
        for item in (self.readiness_report or {}).get("checks", []):
            self.readiness_rows.append(item)
        for item in (self.coverage_report or {}).get("items", []):
            self.readiness_rows.append({"category": categories["coverage"], **item})
        for index, item in enumerate(self.readiness_rows):
            category = str(item.get("category", ""))
            name = str(item.get("name", item.get("type", "")))
            status = str(item.get("status", "unknown"))
            note = str(item.get("note", item.get("basis", "")))
            self.readiness_tree.insert("", "end", iid=str(index), values=(category, name, self._readiness_status_label(status), note[:700]))
        checks = (self.readiness_report or {}).get("status_counts", {})
        if checks:
            summary = " • ".join(f"{self._readiness_status_label(k)}: {v}" for k, v in sorted(checks.items()))
        else:
            summary = "—"
        self.readiness_status_var.set(self.T("readiness_summary") + ": " + summary)
        coverage = self.coverage_report or {}
        overall = self._readiness_status_label(str(coverage.get("overall", "not_run")))
        coverage_labels = {
            "ru": ("проверок", "недоступно/не найдено", "отключено или не настроено", "событий"),
            "en": ("checks", "unavailable / missing", "disabled or not configured", "events"),
            "uk": ("перевірок", "недоступно / не знайдено", "вимкнено або не налаштовано", "подій"),
        }
        c_labels = coverage_labels.get(self.lang, coverage_labels["ru"])
        self.coverage_status_var.set(
            self.T("coverage_summary") + f": {overall} • "
            + f"{c_labels[0]}: {coverage.get('checks_total', 0)} • "
            + f"{c_labels[1]}: {coverage.get('unavailable_or_missing', 0)} • "
            + f"{c_labels[2]}: {coverage.get('disabled_now', 0)} • "
            + f"{c_labels[3]}: {coverage.get('events_count', len(self.events) + len(self.forensic_rows))}"
        )
        self.readiness_detail_text.configure(state="normal")
        self.readiness_detail_text.delete("1.0", "end")
        detail_labels = {
            "ru": ["Совместимость", "Часовой пояс", "Готовность аудита", "Полнота проверки", "Оценка доказательств и связи событий"],
            "en": ["Compatibility", "Time zone", "Audit readiness", "Scan coverage", "Evidence assessment and event correlations"],
            "uk": ["Сумісність", "Часовий пояс", "Готовність аудиту", "Повнота перевірки", "Оцінка доказів і зв’язки подій"],
        }
        dlabels = detail_labels.get(self.lang, detail_labels["ru"])
        detail = {
            dlabels[0]: compatibility,
            dlabels[1]: (compatibility or {}).get("timezone", {}),
            dlabels[2]: self.readiness_report,
            dlabels[3]: coverage,
            dlabels[4]: self.analysis_quality,
        }
        self.readiness_detail_text.insert("1.0", json.dumps(detail, ensure_ascii=False, indent=2, default=str))
        self.readiness_detail_text.configure(state="disabled")

    def on_readiness_select(self, _event: Any = None) -> None:
        selected = self.readiness_tree.selection() if hasattr(self, "readiness_tree") else ()
        if not selected:
            return
        try:
            row = self.readiness_rows[int(selected[0])]
        except Exception:
            return
        self.readiness_detail_text.configure(state="normal")
        self.readiness_detail_text.delete("1.0", "end")
        self.readiness_detail_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.readiness_detail_text.configure(state="disabled")

    def start_readiness_check(self) -> None:
        if self.readiness_scanning:
            return
        self.readiness_scanning = True
        self.readiness_refresh_button.configure(state="disabled")
        self.readiness_status_var.set(self.T("readiness_summary") + ": …")
        def worker() -> None:
            try:
                def progress(message: str) -> None:
                    self.readiness_queue.put(("progress", str(message)))
                report = collect_audit_readiness(progress=progress)
                self.readiness_queue.put(("done", report))
            except Exception as exc:
                self.readiness_queue.put(("fatal", str(exc)))
        threading.Thread(target=worker, name="PAV-Audit-Readiness", daemon=True).start()
        self.root.after(120, self.poll_readiness_check)

    def poll_readiness_check(self) -> None:
        try:
            while True:
                kind, payload = self.readiness_queue.get_nowait()
                if kind == "progress":
                    if hasattr(self, "readiness_status_var"):
                        self.readiness_status_var.set(self.translate_runtime(str(payload)))
                elif kind == "done":
                    self.readiness_scanning = False
                    self.readiness_refresh_button.configure(state="normal")
                    self.readiness_report = payload
                    self.scan_info["audit_readiness"] = payload
                    self.scan_info["compatibility"] = payload.get("environment", {})
                    self.coverage_report = build_scan_coverage(
                        self.sources + self.forensic_sources, self.readiness_report,
                        self.errors + self.forensic_warnings,
                        self.warnings + self.forensic_warnings,
                        self.events + self.forensic_rows,
                    )
                    self.scan_info["coverage"] = self.coverage_report
                    self.render_readiness_panel()
                    self.status_var.set(self.T("readiness_summary") + ": OK")
                    return
                elif kind == "fatal":
                    self.readiness_scanning = False
                    self.readiness_refresh_button.configure(state="normal")
                    messagebox.showerror(self.T("readiness_title"), str(payload))
                    return
        except queue.Empty:
            pass
        if self.readiness_scanning:
            self.root.after(150, self.poll_readiness_check)

    def _browser_category_label(self, category: str) -> str:
        key = {
            "ordinary": "cat_ordinary", "unknown": "cat_unknown",
            "suspicious": "cat_suspicious", "software_distribution": "cat_distribution",
        }.get(str(category), "cat_unknown")
        return self.T(key)

    def _build_browser_tab(self) -> None:
        top = ttk.Frame(self.browser_tab)
        top.pack(fill="x", pady=(0, 6))
        ttk.Label(top, text=self.T("browser_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(top, text=self.T("browser_note"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        browser_actions = ttk.Frame(top)
        browser_actions.pack(fill="x", pady=(0, 6))
        self.browser_scan_button = ttk.Button(
            browser_actions, text=self.T("browser_scan_now"), command=self.start_browser_history_scan
        )
        self.browser_scan_button.pack(side="left")
        ttk.Label(
            browser_actions, textvariable=self.browser_scan_status_var,
            foreground="#555555", wraplength=1050, justify="left",
        ).pack(side="left", fill="x", expand=True, padx=(10, 0))
        if not self.browser_scan_status_var.get():
            self.browser_scan_status_var.set(self.T("browser_scan_pending"))
        search = ttk.Frame(top)
        search.pack(fill="x")
        ttk.Label(search, text=self.T("browser_search")).pack(side="left")
        entry = ttk.Entry(search, textvariable=self.browser_search_var)
        entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.browser_search_var.trace_add("write", lambda *_: self.render_browser_rows())

        rules_frame = ttk.LabelFrame(self.browser_tab, text=self.T("browser_domains"), padding=7)
        rules_frame.pack(fill="x", pady=(0, 7))
        rule_controls = ttk.Frame(rules_frame)
        rule_controls.pack(fill="x")
        domain_entry = ttk.Entry(rule_controls, textvariable=self.browser_domain_var, width=52)
        domain_entry.pack(side="left", fill="x", expand=True)
        domain_entry.configure(cursor="xterm")
        self.browser_category_values = ["ordinary", "unknown", "suspicious", "software_distribution"]
        category_box = ttk.Combobox(rule_controls, state="readonly", width=29,
            values=[self._browser_category_label(x) for x in self.browser_category_values])
        category_box.current(self.browser_category_values.index(self.browser_rule_category_var.get()) if self.browser_rule_category_var.get() in self.browser_category_values else 1)
        category_box.pack(side="left", padx=(6, 6))
        category_box.bind("<<ComboboxSelected>>", lambda _e: self.browser_rule_category_var.set(self.browser_category_values[category_box.current()]))
        ttk.Button(rule_controls, text=self.T("browser_add"), command=self.add_browser_domain_rule).pack(side="left")
        ttk.Button(rule_controls, text=self.T("browser_remove"), command=self.remove_browser_domain_rule).pack(side="left", padx=(6, 0))
        ttk.Label(rules_frame, text=self.T("browser_rules_hint"), foreground="#666666").pack(anchor="w", pady=(5, 3))
        self.browser_rules_tree = ttk.Treeview(rules_frame, columns=("domain", "category"), show="headings", height=3)
        self.browser_rules_tree.heading("domain", text="Domain")
        self.browser_rules_tree.heading("category", text=self.T("browser_category"))
        self.browser_rules_tree.column("domain", width=320, stretch=True)
        self.browser_rules_tree.column("category", width=280, stretch=False)
        self.browser_rules_tree.pack(fill="x")
        self.render_browser_rules()

        pane = ttk.Panedwindow(self.browser_tab, orient="vertical")
        pane.pack(fill="both", expand=True)
        upper = ttk.Frame(pane)
        lower = ttk.Frame(pane)
        pane.add(upper, weight=4)
        pane.add(lower, weight=2)
        cols = ("timestamp", "browser", "type", "domain", "category", "title", "source")
        self.browser_tree = ttk.Treeview(upper, columns=cols, show="headings")
        headings = {"timestamp": self.T("browser_col_time"), "browser": self.T("browser_col_browser"),
                    "type": self.T("browser_col_type"), "domain": self.T("browser_col_domain"),
                    "category": self.T("browser_col_category"), "title": self.T("browser_col_title"),
                    "source": self.T("browser_col_source")}
        widths = {"timestamp": 160, "browser": 160, "type": 130, "domain": 210, "category": 200, "title": 260, "source": 320}
        for col in cols:
            self.browser_tree.heading(col, text=headings[col])
            self.browser_tree.column(col, width=widths[col], minwidth=80, stretch=(col in {"domain", "title", "source"}))
        by = ttk.Scrollbar(upper, orient="vertical", command=self.browser_tree.yview)
        bx = ttk.Scrollbar(upper, orient="horizontal", command=self.browser_tree.xview)
        self.browser_tree.configure(yscrollcommand=by.set, xscrollcommand=bx.set)
        self.browser_tree.grid(row=0, column=0, sticky="nsew")
        by.grid(row=0, column=1, sticky="ns")
        bx.grid(row=1, column=0, sticky="ew")
        upper.rowconfigure(0, weight=1)
        upper.columnconfigure(0, weight=1)
        self.browser_tree.bind("<<TreeviewSelect>>", self.on_browser_select)
        ttk.Label(lower, text=self.T("forensic_details"), font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(4, 3))
        detail_frame = ttk.Frame(lower)
        detail_frame.pack(fill="both", expand=True)
        self.browser_details_text = tk.Text(detail_frame, height=5, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.browser_details_text.yview)
        self.browser_details_text.configure(yscrollcommand=scroll.set)
        self.browser_details_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.browser_details_text.insert("1.0", self.T("browser_empty"))
        self.browser_details_text.configure(state="disabled")

    def _browser_rules(self) -> dict[str, str]:
        rules = self.settings.get("browser_domain_categories", {}) if isinstance(getattr(self, "settings", {}), dict) else {}
        return dict(rules) if isinstance(rules, dict) else {}

    def _save_browser_rules(self, rules: dict[str, str]) -> None:
        self.settings["browser_domain_categories"] = rules
        try:
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            messagebox.showwarning(self.T("browser_domains"), str(exc))
        self.render_browser_rules()

    def render_browser_rules(self) -> None:
        if not hasattr(self, "browser_rules_tree"):
            return
        self.browser_rules_tree.delete(*self.browser_rules_tree.get_children())
        for domain, category in sorted(self._browser_rules().items()):
            self.browser_rules_tree.insert("", "end", iid=domain, values=(domain, self._browser_category_label(category)))

    def _raise_if_scan_cancelled(self) -> None:
        if getattr(self, "cancel_event", None) is not None and self.cancel_event.is_set():
            raise ScanCancelled("Сканирование отменено пользователем")

    def _set_main_scan_controls_idle(self) -> None:
        self.scanning = False
        self._active_scan_kind = ""
        self.scan_button.configure(state="normal")
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="disabled")
        if hasattr(self, "browser_scan_button"):
            self.browser_scan_button.configure(state="normal")
        self.progressbar.stop()

    def start_browser_history_scan(self) -> None:
        """Run only the browser-history reader, without the full system scan."""
        if getattr(self, "scanning", False):
            self.browser_scan_status_var.set(self.T("browser_scan_busy"))
            return

        # Explicit button press is the user's opt-in to read browser history.
        self.browser_history_var.set(True)
        self.cancel_event.clear()
        self.scanning = True
        self._active_scan_kind = "browser_only"
        self.scan_button.configure(state="disabled")
        self.browser_scan_button.configure(state="disabled")
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="normal")
        self.progressbar.stop()
        self.progressbar.configure(mode="indeterminate")
        self.progressbar.start(10)
        self.browser_scan_status_var.set(self.T("browser_scan_running"))
        self.status_var.set(self.T("browser_scan_running"))
        self.progress_message_var.set(self.T("browser_scan_running"))

        # Remove stale queue messages left by a previously completed worker.
        try:
            while True:
                self.worker_queue.get_nowait()
        except queue.Empty:
            pass

        rules = self._browser_rules()

        def progress(message: str) -> None:
            self.worker_queue.put(("progress", {"message": message, "phase": "browser_history"}))

        def worker() -> None:
            try:
                self._raise_if_scan_cancelled()
                events, sources, warnings = scan_browser_history(
                    progress=progress,
                    domain_rules=rules,
                    cancel_check=self._raise_if_scan_cancelled,
                )
                self._raise_if_scan_cancelled()
                self.worker_queue.put(("browser_done", {
                    "events": events, "sources": sources, "warnings": warnings,
                }))
            except ScanCancelled:
                self.worker_queue.put(("cancelled", None))
            except Exception as exc:
                self.worker_queue.put(("browser_fatal", str(exc)))

        threading.Thread(target=worker, name="PAV-Browser-History", daemon=True).start()
        self.root.after(120, self.poll_worker)

    def _apply_browser_scan_result(self, payload: dict[str, Any]) -> None:
        browser_kinds = {"browser_visit", "browser_download"}
        self.events = [row for row in self.events if row.get("kind") not in browser_kinds]
        self.events.extend(payload.get("events", []))
        self.sources = [row for row in self.sources if row.get("type") != "browser_history"]
        self.sources.extend(payload.get("sources", []))
        self.warnings = list(dict.fromkeys(self.warnings + payload.get("warnings", [])))
        self.events.sort(key=lambda row: str(row.get("timestamp", "")), reverse=True)
        self._event_search_index = []
        for item in self.events:
            command_text = str(item.get("command", ""))
            searchable = " ".join([
                str(item.get("timestamp", "")), str(item.get("kind", "")),
                str(item.get("description", "")), command_text,
                str(item.get("source", "")), str(item.get("user", "")),
                json.dumps(item.get("details", {}), ensure_ascii=False, default=str),
            ]).casefold()
            self._event_search_index.append((command_text.casefold(), searchable))

        if not isinstance(self.scan_info, dict):
            self.scan_info = {}
        self.scan_info["browser_history_requested"] = True
        self.scan_info["browser_history_scan_only"] = True
        self.scan_info["browser_history_scanned_local"] = datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")
        sources = payload.get("sources", [])
        available = [row for row in sources if row.get("status") == "available"]
        visits = sum(int(row.get("visits", 0) or 0) for row in available)
        downloads = sum(int(row.get("downloads", 0) or 0) for row in available)
        issues = sum(1 for row in sources if row.get("status") != "available")
        self.browser_scan_status_var.set(self.T(
            "browser_scan_done", profiles=len(available), visits=visits,
            downloads=downloads, issues=issues,
        ))
        self.update_filter_options()
        self.apply_filter()
        self.render_browser_rows()
        self.render_download_rows()
        self.render_runtime_panel()
        self.update_dashboard()
        self.refresh_timeline()
        self.render_lineage()
        self.render_recovery_rows()
        self.render_readiness_panel()
        self.status_var.set(self.browser_scan_status_var.get())

    def add_browser_domain_rule(self) -> None:
        domains, invalid = parse_domain_rule_input(self.browser_domain_var.get())
        category = self.browser_rule_category_var.get()
        if not domains or category not in DOMAIN_CATEGORIES:
            messagebox.showwarning(self.T("browser_domains"), self.T("browser_rule_invalid"))
            return

        rules = self._browser_rules()
        added = updated = unchanged = 0
        for domain in domains:
            previous = rules.get(domain)
            if previous is None:
                added += 1
            elif previous == category:
                unchanged += 1
            else:
                updated += 1
            rules[domain] = category

        self._save_browser_rules(rules)
        self.browser_domain_var.set("")
        summary = self.T("browser_rules_result").format(
            added=added, updated=updated, unchanged=unchanged, invalid=len(invalid)
        )
        self.status_var.set(summary)
        if invalid:
            details = "\n".join(f"• {item}" for item in invalid[:8])
            if len(invalid) > 8:
                details += f"\n… (+{len(invalid) - 8})"
            messagebox.showwarning(
                self.T("browser_domains"),
                summary + "\n\n" + self.T("browser_rules_invalid_skipped") + "\n" + details,
            )

        # Reclassify already collected browser rows without rescanning source databases.
        for item in self.events:
            details = item.get("details") or {}
            if item.get("kind") in {"browser_visit", "browser_download"} and details.get("domain"):
                d = normalize_domain(details.get("domain", ""))
                match, note = classify_domain(d, rules)
                details["domain_category"] = match
                details["domain_category_note"] = note
        self.render_browser_rows()
        self.render_download_rows()
        self.render_runtime_panel()

    def remove_browser_domain_rule(self) -> None:
        selected = self.browser_rules_tree.selection() if hasattr(self, "browser_rules_tree") else ()
        if not selected:
            messagebox.showinfo(self.T("browser_domains"), self.T("browser_rule_selected"))
            return
        rules = self._browser_rules()
        for domain in selected:
            rules.pop(domain, None)
        self._save_browser_rules(rules)
        # Refresh categories after removing the rule.
        for item in self.events:
            details = item.get("details") or {}
            if item.get("kind") in {"browser_visit", "browser_download"} and details.get("domain"):
                d = normalize_domain(details.get("domain", ""))
                match, note = classify_domain(d, rules)
                details["domain_category"] = match
                details["domain_category_note"] = note
        self.render_browser_rows()
        self.render_download_rows()
        self.render_runtime_panel()

    def render_browser_rows(self) -> None:
        if not hasattr(self, "browser_tree"):
            return
        self.browser_tree.delete(*self.browser_tree.get_children())
        query = self.browser_search_var.get().strip().casefold() if hasattr(self, "browser_search_var") else ""
        self.browser_detail_rows = []
        for row in self.events:
            if row.get("kind") != "browser_visit":
                continue
            details = row.get("details") or {}
            blob = json.dumps(row, ensure_ascii=False, default=str).casefold()
            if query and query not in blob:
                continue
            browser = str(details.get("browser", "")) + " / " + str(details.get("profile", ""))
            title = str(details.get("title", "") or details.get("target_path", "") or "")
            type_label = "Посещение"
            values = (row.get("timestamp", "") or "—", browser, type_label, details.get("domain", ""),
                     self._browser_category_label(details.get("domain_category", "unknown")), title, row.get("source", ""))
            iid = str(len(self.browser_detail_rows))
            self.browser_detail_rows.append(row)
            self.browser_tree.insert("", "end", iid=iid, values=values)
        if not self.browser_detail_rows:
            self.browser_details_text.configure(state="normal")
            self.browser_details_text.delete("1.0", "end")
            self.browser_details_text.insert("1.0", self.T("browser_empty"))
            self.browser_details_text.configure(state="disabled")

    def on_browser_select(self, _event: Any = None) -> None:
        selected = self.browser_tree.selection() if hasattr(self, "browser_tree") else ()
        if not selected:
            return
        try:
            row = self.browser_detail_rows[int(selected[0])]
        except Exception:
            return
        self.browser_details_text.configure(state="normal")
        self.browser_details_text.delete("1.0", "end")
        self.browser_details_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.browser_details_text.configure(state="disabled")

    def _build_downloads_tab(self) -> None:
        top = ttk.Frame(self.downloads_tab)
        top.pack(fill="x", pady=(0, 7))
        ttk.Label(top, text="Записи о загрузках из локальных баз браузеров", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(top, text="Отображаются только сохранённые метаданные загрузок; наличие записи не доказывает успешный запуск файла.",
                  foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        search = ttk.Frame(top)
        search.pack(fill="x")
        ttk.Label(search, text="Фильтр по URL, домену, браузеру или пути:").pack(side="left")
        ttk.Entry(search, textvariable=self.download_search_var).pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.download_search_var.trace_add("write", lambda *_: self.render_download_rows())
        pane = ttk.Panedwindow(self.downloads_tab, orient="vertical")
        pane.pack(fill="both", expand=True, pady=(7, 0))
        upper = ttk.Frame(pane)
        lower = ttk.Frame(pane)
        pane.add(upper, weight=4)
        pane.add(lower, weight=2)
        cols = ("timestamp", "browser", "domain", "category", "file", "path", "source")
        self.download_tree = ttk.Treeview(upper, columns=cols, show="headings")
        labels = {"timestamp": self.T("browser_col_time"), "browser": self.T("browser_col_browser"),
                  "domain": self.T("browser_col_domain"), "category": self.T("browser_col_category"),
                  "file": "Файл", "path": "Путь назначения", "source": self.T("browser_col_source")}
        widths = {"timestamp": 160, "browser": 160, "domain": 210, "category": 190, "file": 200, "path": 360, "source": 280}
        for col in cols:
            self.download_tree.heading(col, text=labels[col])
            self.download_tree.column(col, width=widths[col], minwidth=75, stretch=(col in {"path", "source"}))
        dy = ttk.Scrollbar(upper, orient="vertical", command=self.download_tree.yview)
        dx = ttk.Scrollbar(upper, orient="horizontal", command=self.download_tree.xview)
        self.download_tree.configure(yscrollcommand=dy.set, xscrollcommand=dx.set)
        self.download_tree.grid(row=0, column=0, sticky="nsew")
        dy.grid(row=0, column=1, sticky="ns")
        dx.grid(row=1, column=0, sticky="ew")
        upper.rowconfigure(0, weight=1)
        upper.columnconfigure(0, weight=1)
        self.download_tree.bind("<<TreeviewSelect>>", self.on_download_select)
        ttk.Label(lower, text=self.T("forensic_details"), font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(4, 3))
        self.download_details_text = tk.Text(lower, height=5, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        self.download_details_text.pack(fill="both", expand=True)
        self.download_details_text.insert("1.0", "Загрузки появятся после включения чтения истории браузеров и сканирования.")
        self.download_details_text.configure(state="disabled")

    def render_download_rows(self) -> None:
        if not hasattr(self, "download_tree"):
            return
        self.download_tree.delete(*self.download_tree.get_children())
        query = self.download_search_var.get().strip().casefold()
        self.download_detail_rows = []
        for row in self.events:
            if row.get("kind") != "browser_download":
                continue
            details = row.get("details") or {}
            if query and query not in json.dumps(row, ensure_ascii=False, default=str).casefold():
                continue
            browser = str(details.get("browser", "")) + " / " + str(details.get("profile", ""))
            path = str(details.get("target_path", ""))
            values = (row.get("timestamp", "") or "—", browser, details.get("domain", ""),
                      self._browser_category_label(details.get("domain_category", "unknown")),
                      Path(path).name if path else str(details.get("title", "")), path, row.get("source", ""))
            iid = str(len(self.download_detail_rows))
            self.download_detail_rows.append(row)
            self.download_tree.insert("", "end", iid=iid, values=values)
        if not self.download_detail_rows:
            self.download_details_text.configure(state="normal")
            self.download_details_text.delete("1.0", "end")
            self.download_details_text.insert("1.0", "Загрузки не найдены или чтение истории браузеров не включено.")
            self.download_details_text.configure(state="disabled")

    def on_download_select(self, _event: Any = None) -> None:
        selected = self.download_tree.selection() if hasattr(self, "download_tree") else ()
        if not selected:
            return
        try:
            row = self.download_detail_rows[int(selected[0])]
        except Exception:
            return
        self.download_details_text.configure(state="normal")
        self.download_details_text.delete("1.0", "end")
        self.download_details_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.download_details_text.configure(state="disabled")

    def _build_runtime_tab(self) -> None:
        ttk.Label(self.runtime_tab, text=self.T("runtime_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.runtime_tab, text=self.T("runtime_note"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        self.runtime_risk_var = tk.StringVar(value=self.T("risk_not_run"))
        ttk.Label(self.runtime_tab, textvariable=self.runtime_risk_var, wraplength=1400, justify="left", foreground="#4b4b4b").pack(fill="x", anchor="w", pady=(0, 5))
        self.runtime_summary_var = tk.StringVar(value=self.T("runtime_summary") + ": —")
        ttk.Label(self.runtime_tab, textvariable=self.runtime_summary_var, foreground="#555555").pack(anchor="w", pady=(0, 6))
        frame = ttk.Frame(self.runtime_tab)
        frame.pack(fill="both", expand=True)
        cols = ("timestamp", "family", "pid", "parent", "state", "command", "source")
        self.runtime_tree = ttk.Treeview(frame, columns=cols, show="headings")
        labels = {"timestamp": self.T("runtime_col_time"), "family": self.T("runtime_col_family"),
                  "pid": self.T("runtime_col_pid"), "parent": self.T("runtime_col_parent"),
                  "state": self.T("runtime_col_state"), "command": self.T("runtime_col_command"), "source": self.T("runtime_col_source")}
        widths = {"timestamp": 165, "family": 85, "pid": 80, "parent": 95, "state": 220, "command": 430, "source": 260}
        for col in cols:
            self.runtime_tree.heading(col, text=labels[col])
            self.runtime_tree.column(col, width=widths[col], minwidth=65, stretch=(col in {"state", "command", "source"}))
        ry = ttk.Scrollbar(frame, orient="vertical", command=self.runtime_tree.yview)
        rx = ttk.Scrollbar(frame, orient="horizontal", command=self.runtime_tree.xview)
        self.runtime_tree.configure(yscrollcommand=ry.set, xscrollcommand=rx.set)
        self.runtime_tree.grid(row=0, column=0, sticky="nsew")
        ry.grid(row=0, column=1, sticky="ns")
        rx.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.runtime_tree.bind("<<TreeviewSelect>>", self.on_runtime_select)
        self.runtime_details_text = tk.Text(self.runtime_tab, height=7, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        self.runtime_details_text.pack(fill="x", pady=(6, 0))
        self.runtime_details_text.insert("1.0", self.T("risk_not_run"))
        self.runtime_details_text.configure(state="disabled")

    def render_runtime_panel(self) -> None:
        if not hasattr(self, "runtime_tree"):
            return
        combined = list(self.events) + list(getattr(self, "forensic_rows", []))
        analysis = analyze_python_java_processes(combined)
        risk = assess_suspiciousness(combined, analysis, list(self.sources) + list(getattr(self, "forensic_sources", [])), trusted_paths=list(getattr(self, "trusted_paths", [])))
        self.analysis_quality["python_java_analysis"] = analysis
        self.analysis_quality["risk_assessment"] = risk
        if isinstance(self.scan_info, dict):
            self.scan_info["python_java_analysis"] = analysis
            self.scan_info["risk_assessment"] = risk
        self.runtime_summary_var.set(
            f"Python: {analysis['python_process_starts']} • Java: {analysis['java_process_starts']} • "
            f"прямая связь: {len(analysis['direct_python_java_links'])} • "
            f"подтверждённое перекрытие: {len(analysis['confirmed_time_overlaps'])} • "
            f"только близкое время запуска: {len(analysis['nearby_start_times'])}"
        )
        risk_text = f"{self.T('risk_label')}: {risk['label']} ({risk['score']} {self.T('risk_points')}). {risk['explanation']} {self.T('risk_note')}"
        self.runtime_risk_var.set(risk_text)
        if hasattr(self, "risk_status_var"):
            self.risk_status_var.set(risk_text)
        linked_indexes: set[int] = set()
        pair_states: dict[int, list[str]] = {}
        for link in analysis["direct_python_java_links"]:
            pi, ci = link["parent_event_index"], link["child_event_index"]
            linked_indexes.update((pi, ci))
            pair_states.setdefault(pi, []).append("Родительский процесс подтверждён")
            pair_states.setdefault(ci, []).append("Дочерний процесс подтверждён")
        for item in analysis["confirmed_time_overlaps"]:
            pair_states.setdefault(item["python_event_index"], []).append("Одновременная работа подтверждена")
            pair_states.setdefault(item["java_event_index"], []).append("Одновременная работа подтверждена")
        for item in analysis["nearby_start_times"]:
            pair_states.setdefault(item["python_event_index"], []).append("Только близкое время запуска")
            pair_states.setdefault(item["java_event_index"], []).append("Только близкое время запуска")
        self.runtime_tree.delete(*self.runtime_tree.get_children())
        self.runtime_detail_rows = []
        for process in analysis["process_records"]:
            idx = process["event_index"]
            states = pair_states.get(idx, [])
            state = "; ".join(dict.fromkeys(states)) if states else "Связь с другим runtime не найдена"
            command = str(process.get("command_line", "")).replace("\n", " ")
            if len(command) > 260:
                command = command[:257] + "..."
            values = (process.get("timestamp", "") or "—", process.get("family", ""), process.get("pid", ""),
                      process.get("parent_pid", ""), state, command, process.get("source", ""))
            iid = str(len(self.runtime_detail_rows))
            self.runtime_detail_rows.append({"process": process, "analysis": analysis, "risk": risk})
            self.runtime_tree.insert("", "end", iid=iid, values=values)
        self.runtime_details_text.configure(state="normal")
        self.runtime_details_text.delete("1.0", "end")
        self.runtime_details_text.insert("1.0", json.dumps({"assessment": risk, "python_java_analysis": analysis}, ensure_ascii=False, indent=2, default=str))
        self.runtime_details_text.configure(state="disabled")
        self.render_java_panel()
        self.render_suspicious_panel()
        self.render_cleanup_panel()
        self.render_final_report()

    def on_runtime_select(self, _event: Any = None) -> None:
        selected = self.runtime_tree.selection() if hasattr(self, "runtime_tree") else ()
        if not selected:
            return
        try:
            row = self.runtime_detail_rows[int(selected[0])]
        except Exception:
            return
        self.runtime_details_text.configure(state="normal")
        self.runtime_details_text.delete("1.0", "end")
        self.runtime_details_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.runtime_details_text.configure(state="disabled")

    def _build_java_tab(self) -> None:
        ttk.Label(self.java_tab, text=self.T("java_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.java_tab, text=self.T("java_note"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        self.java_summary_var = tk.StringVar(value="Java: 0")
        ttk.Label(self.java_tab, textvariable=self.java_summary_var, foreground="#555555").pack(anchor="w", pady=(0, 5))
        frame = ttk.Frame(self.java_tab)
        frame.pack(fill="both", expand=True)
        cols = ("timestamp", "pid", "parent", "duration", "image", "command", "source")
        self.java_tree = ttk.Treeview(frame, columns=cols, show="headings")
        labels = {"timestamp": self.T("runtime_col_time"), "pid": "PID", "parent": "Parent PID",
                  "duration": "Duration", "image": "Image", "command": self.T("runtime_col_command"), "source": self.T("runtime_col_source")}
        widths = {"timestamp": 165, "pid": 80, "parent": 95, "duration": 100, "image": 260, "command": 430, "source": 260}
        for col in cols:
            self.java_tree.heading(col, text=labels[col])
            self.java_tree.column(col, width=widths[col], minwidth=65, stretch=(col in {"image", "command", "source"}))
        y = ttk.Scrollbar(frame, orient="vertical", command=self.java_tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=self.java_tree.xview)
        self.java_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.java_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.java_tree.bind("<<TreeviewSelect>>", self.on_java_select)
        self.java_details_text = tk.Text(self.java_tab, height=6, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        self.java_details_text.pack(fill="x", pady=(5, 0))
        self.java_details_text.insert("1.0", self.T("risk_not_run"))
        self.java_details_text.configure(state="disabled")

    def render_java_panel(self) -> None:
        if not hasattr(self, "java_tree"):
            return
        analysis = (self.analysis_quality or {}).get("python_java_analysis", {})
        processes = [p for p in analysis.get("process_records", []) if p.get("family") == "Java"]
        self.java_summary_var.set(f"Java process starts: {len(processes)} • termination records: {analysis.get('termination_records', 0)}")
        self.java_tree.delete(*self.java_tree.get_children())
        self.java_detail_rows = []
        for process in processes:
            duration = process.get("duration_seconds")
            values = (process.get("timestamp", "") or "—", process.get("pid", ""), process.get("parent_pid", ""),
                      (f"{duration:.1f} s" if isinstance(duration, (int, float)) else "—"), process.get("image", ""),
                      process.get("command_line", ""), process.get("source", ""))
            iid = str(len(self.java_detail_rows))
            self.java_detail_rows.append(process)
            self.java_tree.insert("", "end", iid=iid, values=values)

    def on_java_select(self, _event: Any = None) -> None:
        selected = self.java_tree.selection() if hasattr(self, "java_tree") else ()
        if not selected:
            return
        try:
            row = self.java_detail_rows[int(selected[0])]
        except Exception:
            return
        self.java_details_text.configure(state="normal")
        self.java_details_text.delete("1.0", "end")
        self.java_details_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.java_details_text.configure(state="disabled")

    def _build_suspicious_tab(self) -> None:
        ttk.Label(self.suspicious_tab, text=self.T("suspicious_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.suspicious_tab, text=self.T("suspicious_note"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        self.suspicious_summary_var = tk.StringVar(value=self.T("risk_not_run"))
        ttk.Label(self.suspicious_tab, textvariable=self.suspicious_summary_var, foreground="#555555").pack(anchor="w", pady=(0, 5))
        frame = ttk.Frame(self.suspicious_tab)
        frame.pack(fill="both", expand=True)
        cols = ("timestamp", "signal", "kind", "description", "source")
        self.suspicious_tree = ttk.Treeview(frame, columns=cols, show="headings")
        labels = {"timestamp": self.T("date") + " / " + self.T("time"), "signal": "Signal", "kind": self.T("event_type"),
                  "description": self.T("description"), "source": self.T("source")}
        widths = {"timestamp": 165, "signal": 220, "kind": 180, "description": 380, "source": 260}
        for col in cols:
            self.suspicious_tree.heading(col, text=labels[col])
            self.suspicious_tree.column(col, width=widths[col], minwidth=70, stretch=(col in {"signal", "description", "source"}))
        y = ttk.Scrollbar(frame, orient="vertical", command=self.suspicious_tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=self.suspicious_tree.xview)
        self.suspicious_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.suspicious_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.suspicious_tree.bind("<<TreeviewSelect>>", self.on_suspicious_select)
        self.suspicious_details_text = tk.Text(self.suspicious_tab, height=6, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        self.suspicious_details_text.pack(fill="x", pady=(5, 0))
        self.suspicious_details_text.insert("1.0", self.T("risk_not_run"))
        self.suspicious_details_text.configure(state="disabled")

    def render_suspicious_panel(self) -> None:
        if not hasattr(self, "suspicious_tree"):
            return
        combined = list(self.events) + list(getattr(self, "forensic_rows", []))
        risk = (self.analysis_quality or {}).get("risk_assessment", {})
        analysis = (self.analysis_quality or {}).get("python_java_analysis", {})
        signals: dict[int, list[str]] = {}
        for index, row in enumerate(combined):
            details = row.get("details") if isinstance(row.get("details"), dict) else {}
            if row.get("kind") in {"browser_visit", "browser_download"} and details.get("domain_category") in {"suspicious", "software_distribution"}:
                signals.setdefault(index, []).append("User-marked domain")
            event_id = details.get("event_id")
            if str(event_id) in {"104", "1102"}:
                signals.setdefault(index, []).append("Windows event-log clear")
        for link in analysis.get("direct_python_java_links", []):
            signals.setdefault(link.get("parent_event_index", -1), []).append("Python/Java parent-child link")
            signals.setdefault(link.get("child_event_index", -1), []).append("Python/Java parent-child link")
        for pair in analysis.get("confirmed_time_overlaps", []):
            signals.setdefault(pair.get("python_event_index", -1), []).append("Confirmed time overlap")
            signals.setdefault(pair.get("java_event_index", -1), []).append("Confirmed time overlap")
        for pair in risk.get("temporal_correlations", []):
            if pair.get("domain_category") in {"suspicious", "software_distribution"}:
                signals.setdefault(pair.get("browser_event_index", -1), []).append("Marked site/download near runtime")
                signals.setdefault(pair.get("runtime_event_index", -1), []).append("Runtime near marked site/download")
        for pair in risk.get("download_execution_matches", []):
            signals.setdefault(pair.get("browser_event_index", -1), []).append("Download path appears in runtime command line/image")
            signals.setdefault(pair.get("runtime_event_index", -1), []).append("Runtime command line/image matches download path")
        self.suspicious_tree.delete(*self.suspicious_tree.get_children())
        self.suspicious_detail_rows = []
        valid = sorted(i for i in signals if isinstance(i, int) and 0 <= i < len(combined))
        for index in valid:
            row = combined[index]
            values = (row.get("timestamp", "") or "—", "; ".join(dict.fromkeys(signals[index])),
                      row.get("kind", ""), row.get("description", ""), row.get("source", ""))
            iid = str(len(self.suspicious_detail_rows))
            self.suspicious_detail_rows.append({"event": row, "signals": list(dict.fromkeys(signals[index]))})
            self.suspicious_tree.insert("", "end", iid=iid, values=values)
        self.suspicious_summary_var.set(f"{risk.get('label', self.T('risk_not_run'))} • {risk.get('score', 0)} heuristic points • review items: {len(valid)}")

    def on_suspicious_select(self, _event: Any = None) -> None:
        selected = self.suspicious_tree.selection() if hasattr(self, "suspicious_tree") else ()
        if not selected:
            return
        try:
            row = self.suspicious_detail_rows[int(selected[0])]
        except Exception:
            return
        self.suspicious_details_text.configure(state="normal")
        self.suspicious_details_text.delete("1.0", "end")
        self.suspicious_details_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.suspicious_details_text.configure(state="disabled")

    def _build_cleanup_tab(self) -> None:
        ttk.Label(self.cleanup_tab, text=self.T("cleanup_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.cleanup_tab, text=self.T("cleanup_note"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        frame = ttk.Frame(self.cleanup_tab)
        frame.pack(fill="both", expand=True)
        cols = ("timestamp", "indicator", "status", "explanation", "source")
        self.cleanup_tree = ttk.Treeview(frame, columns=cols, show="headings")
        labels = {"timestamp": self.T("date") + " / " + self.T("time"), "indicator": "Indicator", "status": "Status",
                  "explanation": "Interpretation", "source": self.T("source")}
        widths = {"timestamp": 165, "indicator": 220, "status": 115, "explanation": 450, "source": 260}
        for col in cols:
            self.cleanup_tree.heading(col, text=labels[col])
            self.cleanup_tree.column(col, width=widths[col], minwidth=70, stretch=(col in {"indicator", "explanation", "source"}))
        y = ttk.Scrollbar(frame, orient="vertical", command=self.cleanup_tree.yview)
        x = ttk.Scrollbar(frame, orient="horizontal", command=self.cleanup_tree.xview)
        self.cleanup_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.cleanup_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        self.cleanup_tree.bind("<<TreeviewSelect>>", self.on_cleanup_select)
        self.cleanup_details_text = tk.Text(self.cleanup_tab, height=6, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        self.cleanup_details_text.pack(fill="x", pady=(5, 0))
        self.cleanup_details_text.insert("1.0", self.T("cleanup_note"))
        self.cleanup_details_text.configure(state="disabled")

    def render_cleanup_panel(self) -> None:
        if not hasattr(self, "cleanup_tree"):
            return
        combined = list(self.events) + list(getattr(self, "forensic_rows", []))
        rows: list[dict[str, Any]] = []
        for item in combined:
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            event_id = details.get("event_id") or details.get("EventID") or (details.get("fields") or {}).get("EventID")
            if str(event_id) in {"104", "1102"}:
                rows.append({"timestamp": item.get("timestamp", ""), "indicator": f"Windows event {event_id}",
                             "status": "Observed", "explanation": "В журнале сохранилась запись об очистке журнала; она не устанавливает автора или мотив.",
                             "source": item.get("source", ""), "event": item})
            elif str(event_id) == "4719":
                rows.append({"timestamp": item.get("timestamp", ""), "indicator": "Audit policy change (4719)",
                             "status": "Observed", "explanation": "Зафиксировано изменение политики аудита; это не доказывает очистку истории или журналов.",
                             "source": item.get("source", ""), "event": item})
        source_records = list(self.sources) + list(getattr(self, "forensic_sources", []))
        for source in source_records:
            if source.get("type") == "browser_history" and source.get("status") in {"disabled", "not_found", "inaccessible", "error"}:
                rows.append({"timestamp": "", "indicator": f"Browser source: {source.get('browser', 'unknown')}",
                             "status": str(source.get("status")),
                             "explanation": "Покрытие истории отсутствует/неполно. Это не является доказательством очистки браузера.",
                             "source": source.get("path", source.get("browser", "")), "event": source})
        self.cleanup_tree.delete(*self.cleanup_tree.get_children())
        self.cleanup_detail_rows = []
        for row in rows:
            iid = str(len(self.cleanup_detail_rows))
            self.cleanup_detail_rows.append(row)
            self.cleanup_tree.insert("", "end", iid=iid, values=(row.get("timestamp", "") or "—", row.get("indicator", ""),
                                      row.get("status", ""), row.get("explanation", ""), row.get("source", "")))

    def on_cleanup_select(self, _event: Any = None) -> None:
        selected = self.cleanup_tree.selection() if hasattr(self, "cleanup_tree") else ()
        if not selected:
            return
        try:
            row = self.cleanup_detail_rows[int(selected[0])]
        except Exception:
            return
        self.cleanup_details_text.configure(state="normal")
        self.cleanup_details_text.delete("1.0", "end")
        self.cleanup_details_text.insert("1.0", json.dumps(row, ensure_ascii=False, indent=2, default=str))
        self.cleanup_details_text.configure(state="disabled")

    def _build_final_report_tab(self) -> None:
        ttk.Label(self.final_report_tab, text=self.T("final_report_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.final_report_tab, text=self.T("final_report_note"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        buttons = ttk.Frame(self.final_report_tab)
        buttons.pack(fill="x", pady=(0, 6))
        ttk.Button(buttons, text=self.T("export_csv"), command=self.export_csv).pack(side="left", padx=(0, 5))
        ttk.Button(buttons, text=self.T("export_json"), command=self.export_json).pack(side="left", padx=5)
        ttk.Button(buttons, text=self.T("export_html"), command=self.export_html).pack(side="left", padx=5)
        ttk.Button(buttons, text=self._artifact_text("PDF…", "PDF…", "PDF…"), command=self.export_pdf).pack(side="left", padx=5)
        ttk.Button(buttons, text=self.T("evidence_bundle"), command=self.export_evidence_bundle).pack(side="left", padx=5)
        self.final_report_text = tk.Text(self.final_report_tab, wrap="word", font=("Consolas", 10), background="#f7f7f7")
        self.final_report_text.pack(fill="both", expand=True)
        self.final_report_text.insert("1.0", self.T("risk_not_run"))
        self.final_report_text.configure(state="disabled")

    def render_final_report(self) -> None:
        if not hasattr(self, "final_report_text"):
            return
        combined = list(self.events) + list(getattr(self, "forensic_rows", []))
        risk = (self.analysis_quality or {}).get("risk_assessment", {})
        runtime = (self.analysis_quality or {}).get("python_java_analysis", {})
        sources = list(self.sources) + list(getattr(self, "forensic_sources", []))
        counts = {}
        for event in combined:
            kind = str(event.get("kind", "unknown"))
            counts[kind] = counts.get(kind, 0) + 1
        source_states = {}
        for source in sources:
            state = str(source.get("status", "unknown"))
            source_states[state] = source_states.get(state, 0) + 1
        lines = [
            f"Python Activity View {APP_VERSION}",
            "=" * 48,
            f"Создано: {self.scan_info.get('generated_local', '—')}",
            f"Пользователь: {self.scan_info.get('user', CURRENT_USER)}",
            f"ОС: {self.scan_info.get('platform', platform.platform())}",
            "",
            f"ИТОГОВАЯ ОЦЕНКА: {risk.get('label', 'Недостаточно данных')} ({risk.get('score', 0)} условных баллов)",
            str(risk.get('explanation', 'Сканирование ещё не завершено.')),
            str(risk.get('note', '')),
            "",
            f"Всего основных и системных событий: {len(combined)}",
            f"Запуски Python: {runtime.get('python_process_starts', 0)}; Java: {runtime.get('java_process_starts', 0)}",
            f"Прямые Python/Java связи: {len(runtime.get('direct_python_java_links', []))}; подтверждённые перекрытия: {len(runtime.get('confirmed_time_overlaps', []))}; близкие запуски: {len(runtime.get('nearby_start_times', []))}",
            f"Временные связи браузер ↔ runtime: {len(risk.get('temporal_correlations', []))}; совпадения пути загрузки с запуском: {len(risk.get('download_execution_matches', []))}",
            f"Состояния источников: {source_states}",
            f"Независимые группы источников: {(self.analysis_quality or {}).get('independent_evidence', summarize_independent_evidence(combined)).get('independent_source_groups', [])}",
            f"Материалы дела: {getattr(self, 'active_case_file', self.case_notes_file)}",
            "",
            "ПРИЧИНЫ ОЦЕНКИ:",
        ]
        if risk.get("reasons"):
            for reason in risk.get("reasons", []):
                lines.append(f"- {reason.get('evidence', '')} — {reason.get('points', 0)} баллов; записей: {reason.get('records', 0)}; сила: {reason.get('strength', '')}")
        else:
            lines.append("- Значимые дополнительные признаки не найдены или доступных данных недостаточно.")
        if hasattr(self, "case_name_var"):
            lines.extend(["", "ДЕЛО:", f"- Название: {self.case_name_var.get()}", f"- Файл: {getattr(self, 'active_case_file', self.case_notes_file)}"])
            try:
                case_notes = self.case_notes_text.get("1.0", "end-1c").strip()
                if case_notes:
                    lines.append("- Заметки модератора (ручной контекст, не найденное системой доказательство):")
                    lines.extend("  " + line for line in case_notes.splitlines()[:100])
            except Exception:
                pass
        lines.extend(["", "ТИПЫ СОБЫТИЙ:"])
        lines.extend(f"- {kind}: {count}" for kind, count in sorted(counts.items()))
        lines.extend(["", "ПРЕДУПРЕЖДЕНИЯ И ОГРАНИЧЕНИЯ:"])
        warnings = list(self.warnings) + list(getattr(self, "forensic_warnings", []))
        lines.extend(f"- {warning}" for warning in warnings[:100])
        lines.append("- Отсутствие записи не доказывает отсутствие действия; отсутствие истории не доказывает её очистку.")
        lines.append("- Итоговая оценка является эвристической и не заменяет ручную проверку первичных источников.")
        self.final_report_text.configure(state="normal")
        self.final_report_text.delete("1.0", "end")
        self.final_report_text.insert("1.0", "\n".join(lines))
        self.final_report_text.configure(state="disabled")

    def _build_timeline_tab(self) -> None:
        bar = ttk.Frame(self.timeline_tab)
        bar.pack(fill="x", pady=(0, 7))
        ttk.Label(bar, text=self.T("timeline_search")).pack(side="left")
        ttk.Entry(bar, textvariable=self.timeline_search_var, width=34).pack(side="left", padx=(5, 10))
        ttk.Label(bar, text=self.T("date_from")).pack(side="left")
        ttk.Entry(bar, textvariable=self.timeline_from_var, width=12).pack(side="left", padx=(5, 8))
        ttk.Label(bar, text=self.T("date_to")).pack(side="left")
        ttk.Entry(bar, textvariable=self.timeline_to_var, width=12).pack(side="left", padx=(5, 8))
        ttk.Button(bar, text=self.T("reset"), command=self.reset_timeline_filter).pack(side="right")
        table_frame = ttk.Frame(self.timeline_tab)
        table_frame.pack(fill="both", expand=True)
        cols = ("timestamp", "utc_time", "kind", "confidence", "description", "command", "source")
        self.timeline_tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        labels = {"timestamp": self.T("date") + " / " + self.T("time"), "utc_time": self.T("utc_time"), "kind": self.T("event_type"), "confidence": self.T("evidence_confidence"), "description": self.T("description"), "command": self.T("command"), "source": self.T("source")}
        widths = {"timestamp": 165, "utc_time": 165, "kind": 180, "confidence": 140, "description": 270, "command": 420, "source": 280}
        for col in cols:
            self.timeline_tree.heading(col, text=labels[col])
            self.timeline_tree.column(col, width=widths[col], minwidth=80, stretch=(col in {"description", "command", "source"}))
        y = ttk.Scrollbar(table_frame, orient="vertical", command=self.timeline_tree.yview)
        x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.timeline_tree.xview)
        self.timeline_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.timeline_tree.grid(row=1, column=0, sticky="nsew")
        y.grid(row=1, column=1, sticky="ns")
        x.grid(row=2, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.timeline_tree.bind("<Double-1>", self.open_timeline_event)
        self._timeline_visible_rows = []

    def _build_lineage_tab(self) -> None:
        top = ttk.Frame(self.lineage_tab)
        top.pack(fill="x", pady=(0, 6))
        ttk.Label(top, text=self.T("lineage_note"), wraplength=1180, justify="left", foreground="#666666").pack(side="left", fill="x", expand=True)
        ttk.Button(top, text=self.T("lineage_refresh"), command=self.render_lineage).pack(side="right")
        table_frame = ttk.Frame(self.lineage_tab)
        table_frame.pack(fill="both", expand=True)
        cols = ("pid", "parent_pid", "timestamp", "relation", "command", "source")
        self.lineage_tree = ttk.Treeview(table_frame, columns=cols, show="tree headings")
        self.lineage_tree.heading("#0", text=self.T("process"))
        self.lineage_tree.column("#0", width=220, minwidth=120)
        labels = {"pid": self.T("pid"), "parent_pid": self.T("parent_pid"), "timestamp": self.T("date") + " / " + self.T("time"), "relation": self.T("event_type"), "command": self.T("cmdline"), "source": self.T("source")}
        widths = {"pid": 75, "parent_pid": 90, "timestamp": 165, "relation": 190, "command": 430, "source": 280}
        for col in cols:
            self.lineage_tree.heading(col, text=labels[col])
            self.lineage_tree.column(col, width=widths[col], minwidth=65, stretch=(col in {"command", "source"}))
        y = ttk.Scrollbar(table_frame, orient="vertical", command=self.lineage_tree.yview)
        x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.lineage_tree.xview)
        self.lineage_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.lineage_tree.grid(row=1, column=0, sticky="nsew")
        y.grid(row=1, column=1, sticky="ns")
        x.grid(row=2, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self._lineage_nodes = []

    def _build_scan_history_tab(self) -> None:
        top = ttk.Frame(self.scan_history_tab)
        top.pack(fill="x", pady=(0, 6))
        ttk.Label(top, text=self.T("scan_history_note"), wraplength=950, justify="left", foreground="#666666").pack(side="left", fill="x", expand=True)
        ttk.Button(top, text=self.T("scan_history_compare"), command=self.compare_selected_scans).pack(side="right", padx=(5, 0))
        ttk.Button(top, text=self.T("scan_history_import"), command=self.import_scan_snapshot).pack(side="right", padx=(5, 0))
        ttk.Button(top, text=self.T("scan_history_view"), command=self.open_scan_snapshot).pack(side="right")
        cols = ("timestamp", "events", "sources", "warnings")
        self.scan_history_tree = ttk.Treeview(self.scan_history_tab, columns=cols, show="headings", selectmode="extended")
        labels = {"timestamp": self.T("scan_history_columns"), "events": self.T("scan_history_events"), "sources": self.T("scan_history_sources"), "warnings": self.T("scan_history_warnings")}
        widths = {"timestamp": 210, "events": 100, "sources": 100, "warnings": 120}
        for col in cols:
            self.scan_history_tree.heading(col, text=labels[col])
            self.scan_history_tree.column(col, width=widths[col], minwidth=70, stretch=(col == "timestamp"))
        self.scan_history_tree.pack(fill="both", expand=True)
        self.scan_history_tree.bind("<Double-1>", self.open_scan_snapshot)
        self.scan_history_status_var = tk.StringVar(value=self.T("scan_history_empty"))
        ttk.Label(self.scan_history_tab, textvariable=self.scan_history_status_var, foreground="#666666").pack(anchor="w", pady=(5, 0))
        self._scan_history_files = []

    def reset_timeline_filter(self) -> None:
        self.timeline_search_var.set("")
        self.timeline_from_var.set("")
        self.timeline_to_var.set("")
        self.refresh_timeline()

    def refresh_timeline(self) -> None:
        if not hasattr(self, "timeline_tree"):
            return
        query = self.timeline_search_var.get().strip().casefold()
        date_from = self.timeline_from_var.get().strip()
        date_to = self.timeline_to_var.get().strip()
        visible = []
        combined_events = list(self.events) + list(getattr(self, "forensic_rows", []))
        for item in combined_events:
            day = str(item.get("date") or item.get("timestamp", "")[:10])
            if date_from and day and day < date_from:
                continue
            if date_to and day and day > date_to:
                continue
            blob = " ".join([str(item.get("timestamp", "")), str(item.get("kind", "")), str(item.get("description", "")), str(item.get("command", "")), str(item.get("source", ""))]).casefold()
            if query and query not in blob:
                continue
            visible.append(item)
        visible.sort(key=lambda x: time_sort_value(x.get("timestamp", "")), reverse=True)
        self._timeline_visible_rows = visible[:20000]
        self.timeline_tree.delete(*self.timeline_tree.get_children())
        for i, item in enumerate(self._timeline_visible_rows):
            command = str(item.get("command", "") or "").replace("\n", " ⏎ ")
            if len(command) > 200:
                command = command[:197] + "..."
            confidence = item.get("evidence_assessment", {}).get("confidence", "unknown")
            confidence_labels = {
                "ru": {"high": "Высокая (источник)", "medium": "Средняя", "low": "Низкая", "context_only": "Контекст", "unknown": "Неизвестно"},
                "en": {"high": "High (source)", "medium": "Medium", "low": "Low", "context_only": "Context", "unknown": "Unknown"},
                "uk": {"high": "Висока (джерело)", "medium": "Середня", "low": "Низька", "context_only": "Контекст", "unknown": "Невідомо"},
            }
            confidence_display = confidence_labels.get(self.lang, confidence_labels["ru"]).get(confidence, confidence)
            utc_value = item.get("time_normalization", {}).get("timestamp_utc", "") or "—"
            self.timeline_tree.insert("", "end", iid=str(i), values=(item.get("timestamp", "") or "—", utc_value, self.localize_kind(item.get("kind", "")), confidence_display, item.get("description", ""), command, item.get("source", "")))

    def open_timeline_event(self, _event: Any = None) -> None:
        selected = self.timeline_tree.selection()
        if not selected:
            return
        try:
            item = self._timeline_visible_rows[int(selected[0])]
        except Exception:
            return
        self._select_app_tab(self.history_tab)
        self.command_search_var.set(str(item.get("command", ""))[:100])
        self.search_var.set("")
        self.date_from_var.set("")
        self.date_to_var.set("")

    def _on_search_mode_selected(self, _event: Any = None) -> None:
        display = self.search_mode_display_var.get() if hasattr(self, "search_mode_display_var") else ""
        mapping = {self.T("search_contains"): "contains", self.T("search_exact"): "exact", self.T("search_regex"): "regex"}
        self.search_mode_var.set(mapping.get(display, "contains"))

    def render_lineage(self) -> None:
        if not hasattr(self, "lineage_tree"):
            return
        combined = list(self.events) + list(self.forensic_rows)
        for proc in getattr(self, "process_rows", []):
            combined.append({
                "timestamp": proc.get("started", "") or proc.get("snapshot_time", ""),
                "kind": "Текущий снимок процессов",
                "description": f"Активный процесс: {proc.get('name', '')}",
                "command": proc.get("command_line", ""),
                "source": "Текущий снимок процессов",
                "details": {
                    "process_id": proc.get("pid", ""),
                    "parent_process_id": proc.get("parent_pid", ""),
                    "process_image": proc.get("path", "") or proc.get("name", ""),
                    "process_relation": "current process snapshot (not historical)",
                },
            })
        nodes = make_process_tree_rows(combined)
        self._lineage_nodes = nodes
        self.lineage_tree.delete(*self.lineage_tree.get_children())
        iid_by_key = {str(node["key"]): f"node_{i}" for i, node in enumerate(nodes)}
        inserted: set[str] = set()
        for i, node in enumerate(nodes):
            candidate_parent = iid_by_key.get(str(node.get("parent_key", "")), "")
            parent_iid = candidate_parent if candidate_parent in inserted else ""
            label = node.get("image", "") or "process"
            if len(label) > 100:
                label = label[:97] + "..."
            self.lineage_tree.insert(parent_iid, "end", iid=f"node_{i}", text=label, values=(node.get("pid", ""), node.get("ppid", ""), node.get("timestamp", ""), node.get("relation", ""), node.get("command", ""), node.get("source", "")))
            inserted.add(f"node_{i}")
        if nodes:
            self.status_var.set(f"{self.T('tab_lineage')}: {len(nodes)}")
        else:
            self.status_var.set(self.T("lineage_note"))

    def _scan_history_directory(self) -> Path:
        folder = app_data_dir() / "scan_history"
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def save_scan_snapshot(self) -> None:
        try:
            folder = self._scan_history_directory()
            now = datetime.now().astimezone()
            name = "scan_" + now.strftime("%Y%m%d_%H%M%S_%f") + ".json"
            payload = {
                "application": APP_NAME, "version": APP_VERSION,
                "generated_local": now.isoformat(sep=" ", timespec="seconds"),
                "summary": {"events": len(self.events), "system_trace_events": len(self.forensic_rows), "sources": len(self.sources) + len(self.forensic_sources), "python_files": len(self.python_files), "warnings": len(self.warnings) + len(self.forensic_warnings), "errors": len(self.errors)},
                "scan_info": (self.scan_info),
                "case_context": self._case_context_payload(),
                "artifact_sources": getattr(self, "artifact_sources", []),
                "audit_readiness": self.readiness_report,
                "coverage": self.coverage_report,
                "analysis_quality": self.analysis_quality,
                "events": (self.events + self.forensic_rows),
                "sources": (self.sources + self.forensic_sources),
                "python_files": (self.python_files),
                "process_snapshot": (getattr(self, "process_rows", [])),
                "forensic_analysis": (self.forensic_scan_info),
                "warnings": (self.warnings + self.forensic_warnings),
                "errors": (self.errors),
            }
            target = folder / name
            target.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            # Keep the most recent 40 snapshots to limit local storage use.
            saved = sorted(folder.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            for old in saved[40:]:
                try:
                    old.unlink()
                except OSError:
                    pass
            self.refresh_scan_history()
        except Exception as exc:
            self.warnings.append(f"Не удалось сохранить снимок сканирования: {exc}")

    def refresh_scan_history(self) -> None:
        if not hasattr(self, "scan_history_tree"):
            return
        folder = self._scan_history_directory()
        files = sorted(folder.glob("scan_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        self._scan_history_files = files
        self.scan_history_tree.delete(*self.scan_history_tree.get_children())
        for i, path in enumerate(files):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                summary = data.get("summary", {})
                self.scan_history_tree.insert("", "end", iid=str(i), values=(data.get("generated_local", path.name), summary.get("events", 0), summary.get("sources", 0), summary.get("warnings", 0)))
            except Exception:
                self.scan_history_tree.insert("", "end", iid=str(i), values=(path.name, "?", "?", "ошибка чтения"))
        self.scan_history_status_var.set(f"{len(files)}" if files else self.T("scan_history_empty"))

    def open_scan_snapshot(self, _event: Any = None) -> None:
        selected = self.scan_history_tree.selection() if hasattr(self, "scan_history_tree") else ()
        if not selected:
            messagebox.showinfo(self.T("scan_history_open_title"), self.T("scan_history_empty"))
            return
        try:
            path = self._scan_history_files[int(selected[0])]
            data = json.loads(path.read_text(encoding="utf-8"))
            window = tk.Toplevel(self.root)
            window.title(self.T("scan_history_open_title"))
            window.geometry("1050x720")
            frame = ttk.Frame(window, padding=6)
            frame.pack(fill="both", expand=True)
            text_widget = tk.Text(frame, wrap="none", font=("Consolas", 9))
            sy = ttk.Scrollbar(frame, orient="vertical", command=text_widget.yview)
            sx = ttk.Scrollbar(frame, orient="horizontal", command=text_widget.xview)
            text_widget.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            text_widget.grid(row=0, column=0, sticky="nsew")
            sy.grid(row=0, column=1, sticky="ns")
            sx.grid(row=1, column=0, sticky="ew")
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            text_widget.insert("1.0", json.dumps(data, ensure_ascii=False, indent=2, default=str))
            text_widget.configure(state="disabled")
            ttk.Label(window, text=path.name, foreground="#666666").pack(anchor="w", padx=8, pady=(0, 6))
        except Exception as exc:
            messagebox.showerror(self.T("scan_history_open_title"), str(exc))

    def import_scan_snapshot(self) -> None:
        """Import a saved local snapshot or exported report for cross-PC comparison."""
        path = filedialog.askopenfilename(
            title=self.T("scan_history_import"),
            filetypes=[("JSON reports", "*.json"), ("Evidence ZIP", "*.zip"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            source_path = Path(path)
            if source_path.stat().st_size > 100 * 1024 * 1024:
                raise ValueError("Файл превышает лимит импорта 100 MiB.")
            if source_path.suffix.casefold() == ".zip":
                with zipfile.ZipFile(source_path, "r") as archive:
                    try:
                        info = archive.getinfo("report.json")
                    except KeyError as exc:
                        raise ValueError("В ZIP нет report.json.") from exc
                    if info.file_size > 100 * 1024 * 1024:
                        raise ValueError("report.json внутри ZIP превышает лимит 100 MiB.")
                    raw_report = archive.read(info)
                payload = json.loads(raw_report.decode("utf-8-sig"))
            else:
                payload = json.loads(source_path.read_text(encoding="utf-8-sig"))
            normalized = normalize_imported_snapshot(payload)
            if not normalized.get("events") and not normalized.get("sources") and not normalized.get("python_files"):
                raise ValueError("В выбранном JSON не найдены события, источники или Python-файлы.")
            normalized["imported_from"] = source_path.name
            normalized["imported_at_local"] = datetime.now().astimezone().isoformat(sep=" ", timespec="seconds")
            normalized["generated_local"] = str(normalized.get("generated_local") or normalized.get("generated") or normalized["imported_at_local"])
            folder = self._scan_history_directory()
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            destination = folder / f"imported_{stamp}.json"
            destination.write_text(json.dumps(normalized, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.refresh_scan_history()
            message = {
                "ru": f"Снимок импортирован: {len(normalized['events'])} событий, {len(normalized['sources'])} источников.",
                "en": f"Snapshot imported: {len(normalized['events'])} events, {len(normalized['sources'])} sources.",
                "uk": f"Знімок імпортовано: {len(normalized['events'])} подій, {len(normalized['sources'])} джерел.",
            }.get(self.lang, "Snapshot imported")
            self.scan_history_status_var.set(message)
            self.status_var.set(message)
        except Exception as exc:
            messagebox.showerror(self.T("scan_history_import"), str(exc))

    def compare_selected_scans(self, _event: Any = None) -> None:
        selected = self.scan_history_tree.selection() if hasattr(self, "scan_history_tree") else ()
        if len(selected) != 2:
            messagebox.showinfo(self.T("scan_compare_title"), self.T("scan_history_need_two"))
            return
        try:
            files = [self._scan_history_files[int(x)] for x in selected]
            snapshots = [json.loads(p.read_text(encoding="utf-8")) for p in files]
            snapshots.sort(key=lambda x: x.get("generated_local", ""))
            diff = compare_snapshots(snapshots[0], snapshots[1])
            summary = self.T("compare_summary", added=len(diff["added_events"]), removed=len(diff["removed_events"]), common=diff["common_event_count"])
            lines = [summary,
                     self.T("compare_files_summary", added=len(diff.get("added_python_files", [])), removed=len(diff.get("removed_python_files", [])), changed=len(diff.get("changed_python_files", []))),
                     self.T("compare_process_summary", added=len(diff.get("added_processes", [])), removed=len(diff.get("removed_processes", []))),
                     "", self.T("compare_old_snapshot", value=snapshots[0].get('generated_local', '')),
                     self.T("compare_new_snapshot", value=snapshots[1].get('generated_local', '')),
                     "", self.T("compare_added_sources", n=len(diff['added_sources'])),
                     self.T("compare_removed_sources", n=len(diff['removed_sources'])),
                     "", self.T("compare_files_heading")]
            for row in diff.get("added_python_files", [])[:100]:
                lines.append("+ " + str(row.get("path", "")))
            for row in diff.get("removed_python_files", [])[:100]:
                lines.append("- " + str(row.get("path", "")))
            for row in diff.get("changed_python_files", [])[:100]:
                lines.append("~ " + str(row.get("after", {}).get("path", "")))
            lines.extend(["", self.T("compare_processes_heading")])
            for row in diff.get("added_processes", [])[:100]:
                lines.append("+ " + str(row.get("name", "")) + " | PID " + str(row.get("pid", "")))
            for row in diff.get("removed_processes", [])[:100]:
                lines.append("- " + str(row.get("name", "")) + " | PID " + str(row.get("pid", "")))
            lines.extend(["", self.T("compare_new_events_heading")])
            for row in diff["added_events"][:250]:
                lines.append(f"[{row.get('timestamp','')}] {row.get('kind','')} | {row.get('command') or row.get('description','')}")
            lines.extend(["", self.T("compare_removed_events_heading")])
            for row in diff["removed_events"][:250]:
                lines.append(f"[{row.get('timestamp','')}] {row.get('kind','')} | {row.get('command') or row.get('description','')}")
            window = tk.Toplevel(self.root)
            window.title(self.T("scan_compare_title"))
            window.geometry("1050x700")
            text_widget = tk.Text(window, wrap="none", font=("Consolas", 9))
            sy = ttk.Scrollbar(window, orient="vertical", command=text_widget.yview)
            sx = ttk.Scrollbar(window, orient="horizontal", command=text_widget.xview)
            text_widget.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            text_widget.grid(row=0, column=0, sticky="nsew")
            sy.grid(row=0, column=1, sticky="ns")
            sx.grid(row=1, column=0, sticky="ew")
            window.rowconfigure(0, weight=1); window.columnconfigure(0, weight=1)
            text_widget.insert("1.0", "\n".join(lines))
            text_widget.configure(state="disabled")
        except Exception as exc:
            messagebox.showerror(self.T("scan_compare_title"), str(exc))

    def clear_deep_cache(self) -> None:
        folder = app_data_dir() / "deep_cache"
        deleted = 0
        if folder.is_dir():
            for path in folder.glob("*.json"):
                try:
                    path.unlink(); deleted += 1
                except OSError:
                    pass
        messagebox.showinfo(self.T("clear_cache"), f"{self.T('cache_cleared')} ({deleted})")

    def verify_file_signature(self) -> None:
        selected = filedialog.askopenfilename(
            title=self.T("signature_title"),
            filetypes=[("Executable files", "*.exe *.dll *.sys *.ocx"), ("All files", "*.*")],
        )
        if not selected:
            return
        path = Path(selected)
        self.status_var.set(self.T("signature_title") + "…")
        def worker() -> None:
            result = verify_authenticode(path)
            self.signature_queue.put(result)
        threading.Thread(target=worker, name="PAV-Authenticode", daemon=True).start()
        self.root.after(120, self.poll_signature_result)

    def poll_signature_result(self) -> None:
        try:
            payload = self.signature_queue.get_nowait()
        except queue.Empty:
            self.root.after(120, self.poll_signature_result)
            return
        self.signature_checks.append(payload)
        details = json.dumps(payload, ensure_ascii=False, indent=2)
        messagebox.showinfo(self.T("signature_title"), details)
        self.status_var.set(self.T("saved"))

    def _build_history_tab(self) -> None:
        filters = ttk.Frame(self.history_tab)
        filters.pack(fill="x", pady=(0, 7))
        ttk.Label(filters, text=self.T("search_command")).pack(side="left")
        self.command_search_entry = ttk.Entry(filters, textvariable=self.command_search_var, width=32)
        self.command_search_entry.pack(side="left", padx=(6, 12))
        ttk.Label(filters, text=self.T("search_all")).pack(side="left")
        self.search_entry = ttk.Entry(filters, textvariable=self.search_var, width=30)
        self.search_entry.pack(side="left", padx=(6, 12))
        ttk.Label(filters, text=self.T("event_type")).pack(side="left")
        self.filter_combo = ttk.Combobox(filters, textvariable=self.filter_var, state="readonly", width=25, values=[self.T("all_events")])
        self.filter_combo.pack(side="left", padx=6)
        self.filter_combo.bind("<<ComboboxSelected>>", lambda _e: self.apply_filter())
        ttk.Button(filters, text=self.T("reset"), command=self.reset_filters).pack(side="right")
        advanced = ttk.Frame(self.history_tab)
        advanced.pack(fill="x", pady=(0, 7))
        ttk.Label(advanced, text=self.T("search_mode")).pack(side="left")
        mode_labels = [self.T("search_contains"), self.T("search_exact"), self.T("search_regex")]
        self.search_mode_display_var.set(mode_labels[{"contains": 0, "exact": 1, "regex": 2}.get(self.search_mode_var.get(), 0)])
        self.search_mode_combo = ttk.Combobox(advanced, textvariable=self.search_mode_display_var, state="readonly", width=20, values=mode_labels)
        self.search_mode_combo.pack(side="left", padx=(5, 10))
        self.search_mode_combo.bind("<<ComboboxSelected>>", self._on_search_mode_selected)
        ttk.Checkbutton(advanced, text=self.T("case_sensitive"), variable=self.case_sensitive_var).pack(side="left", padx=(0, 12))
        ttk.Label(advanced, text=self.T("date_from")).pack(side="left")
        ttk.Entry(advanced, textvariable=self.date_from_var, width=12).pack(side="left", padx=(5, 10))
        ttk.Label(advanced, text=self.T("date_to")).pack(side="left")
        ttk.Entry(advanced, textvariable=self.date_to_var, width=12).pack(side="left", padx=(5, 10))
        pane = ttk.Panedwindow(self.history_tab, orient="vertical")
        pane.pack(fill="both", expand=True)
        table_frame = ttk.Frame(pane)
        detail_frame = ttk.Frame(pane)
        pane.add(table_frame, weight=4)
        pane.add(detail_frame, weight=2)
        columns = ("date", "time", "kind", "description", "command", "source", "user")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="extended")
        keys = {"date": "date", "time": "time", "kind": "event_type", "description": "description", "command": "command", "source": "source", "user": "user"}
        widths = {"date": 100, "time": 82, "kind": 220, "description": 245, "command": 420, "source": 315, "user": 100}
        for col in columns:
            self.tree.heading(col, text=self.T(keys[col]), command=lambda c=col: self.sort_by(c))
            self.tree.column(col, width=widths[col], minwidth=70, stretch=(col in {"description", "command", "source"}))
        y = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.tree.bind("<Double-1>", lambda _e: self.show_properties())
        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.tag_configure("even", background="#f3f6fa")
        self.tree.tag_configure("odd", background="#ffffff")
        dh = ttk.Frame(detail_frame)
        dh.pack(fill="x", pady=(7, 4))
        ttk.Label(dh, text=self.T("details"), font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(dh, text=self.T("copy_command"), command=self.copy_command).pack(side="right")
        ttk.Button(dh, text=self.T("copy_details"), command=self.copy_details).pack(side="right", padx=6)
        self.details_text = tk.Text(detail_frame, height=8, wrap="word", font=("Consolas", 9), background="#f7f7f7", relief="solid", borderwidth=1)
        self.details_text.pack(fill="both", expand=True)
        self.details_text.insert("1.0", self.T("select_event"))
        self.details_text.configure(state="disabled")

    def _build_files_tab(self) -> None:
        toolbar = ttk.Frame(self.files_tab)
        toolbar.pack(fill="x", pady=(0, 7))
        ttk.Label(toolbar, text=self.T("find_file")).pack(side="left")
        self.file_search_entry = ttk.Entry(toolbar, textvariable=self.file_search_var, width=36)
        self.file_search_entry.pack(side="left", padx=(6, 10))
        ttk.Label(toolbar, textvariable=self.file_count_var, foreground="#555555").pack(side="left")
        ttk.Button(toolbar, text=self.T("choose_folder"), command=self.add_folder_to_catalog).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text=self.T("compare"), command=self.compare_file_snapshot).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text=self.T("verify_signature"), command=self.verify_file_signature).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text=self.T("snapshot"), command=self.save_file_snapshot).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text=self.T("copy_path"), command=self.copy_selected_file_path).pack(side="right", padx=(6, 0))
        ttk.Button(toolbar, text=self.T("open_file"), command=self.open_selected_python_file).pack(side="right")
        paned = ttk.Panedwindow(self.files_tab, orient="horizontal")
        paned.pack(fill="both", expand=True)
        left = ttk.Frame(paned)
        right = ttk.Frame(paned)
        paned.add(left, weight=2)
        paned.add(right, weight=5)
        cols = ("name", "modified", "size", "extension")
        self.file_tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="browse")
        for col, key, width in [("name", "file", 210), ("modified", "modified", 140), ("size", "size", 82), ("extension", "type", 70)]:
            self.file_tree.heading(col, text=self.T(key))
            self.file_tree.column(col, width=width, minwidth=55, stretch=(col == "name"))
        fy = ttk.Scrollbar(left, orient="vertical", command=self.file_tree.yview)
        fx = ttk.Scrollbar(left, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=fy.set, xscrollcommand=fx.set)
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        fy.grid(row=0, column=1, sticky="ns")
        fx.grid(row=1, column=0, sticky="ew")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.file_tree.bind("<<TreeviewSelect>>", self.on_python_file_select)
        self.file_tree.bind("<Double-1>", lambda _e: self.open_selected_python_file())
        ttk.Label(right, textvariable=self.selected_file_var, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 4))
        codebox = ttk.Frame(right)
        codebox.pack(fill="both", expand=True)
        self.code_text = tk.Text(codebox, wrap="none", font=("Consolas", 10), background="#fbfbfb", foreground="#202020")
        cy = ttk.Scrollbar(codebox, orient="vertical", command=self.code_text.yview)
        cx = ttk.Scrollbar(codebox, orient="horizontal", command=self.code_text.xview)
        self.code_text.configure(yscrollcommand=cy.set, xscrollcommand=cx.set)
        self.code_text.grid(row=0, column=0, sticky="nsew")
        cy.grid(row=0, column=1, sticky="ns")
        cx.grid(row=1, column=0, sticky="ew")
        codebox.rowconfigure(0, weight=1)
        codebox.columnconfigure(0, weight=1)
        self.code_text.insert("1.0", self.T("select_file"))
        self.code_text.configure(state="disabled")

    def _build_processes_tab(self) -> None:
        toolbar = ttk.Frame(self.processes_tab)
        toolbar.pack(fill="x", pady=(0, 6))
        ttk.Label(toolbar, text=self.T("process_warning"), foreground="#666666", wraplength=1050, justify="left").pack(side="left", fill="x", expand=True)
        ttk.Button(toolbar, text=self.T("process_refresh"), command=self.refresh_processes).pack(side="right")
        table_frame = ttk.Frame(self.processes_tab)
        table_frame.pack(fill="both", expand=True)
        cols = ("name", "pid", "parent_pid", "started", "path", "command_line")
        self.process_tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        labels = {"name": "process", "pid": "pid", "parent_pid": "parent_pid", "started": "started", "path": "path", "command_line": "cmdline"}
        widths = {"name": 150, "pid": 75, "parent_pid": 90, "started": 155, "path": 300, "command_line": 540}
        for col in cols:
            self.process_tree.heading(col, text=self.T(labels[col]))
            self.process_tree.column(col, width=widths[col], minwidth=70, stretch=(col in {"path", "command_line"}))
        y = ttk.Scrollbar(table_frame, orient="vertical", command=self.process_tree.yview)
        x = ttk.Scrollbar(table_frame, orient="horizontal", command=self.process_tree.xview)
        self.process_tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.process_tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.process_status_var = tk.StringVar(value=self.T("process_count", n=len(self.process_rows)))
        ttk.Label(toolbar, textvariable=self.process_status_var).pack(side="left", padx=(8, 0))

    def _build_recovery_tab(self) -> None:
        ttk.Label(self.recovery_tab, text=self.T("recovery_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(0, 4))
        ttk.Label(self.recovery_tab, text=self.T("recovery_note"), wraplength=1400, justify="left", foreground="#555555").pack(anchor="w", pady=(0, 7))
        recovery_buttons = ttk.Frame(self.recovery_tab)
        recovery_buttons.pack(fill="x", pady=(0, 7))
        ttk.Button(recovery_buttons, text=self.T("run_deep"), command=self.run_deep_scan).pack(side="left")
        ttk.Button(recovery_buttons, text=self.T("clear_cache"), command=self.clear_deep_cache).pack(side="left", padx=(6, 0))
        cols = ("date", "time", "kind", "description", "command", "source")
        self.recovery_tree = ttk.Treeview(self.recovery_tab, columns=cols, show="headings")
        widths = {"date": 100, "time": 82, "kind": 210, "description": 260, "command": 400, "source": 300}
        for col in cols:
            self.recovery_tree.heading(col, text=self.T(col if col in {"date", "time", "description", "command", "source"} else "event_type"))
            self.recovery_tree.column(col, width=widths[col], minwidth=70, stretch=(col in {"description", "command", "source"}))
        self.recovery_tree.pack(fill="both", expand=True)
        self.recovery_tree.bind("<Double-1>", self._open_recovery_event)
        self.recovery_empty_var = tk.StringVar(value=self.T("no_recovery"))
        ttk.Label(self.recovery_tab, textvariable=self.recovery_empty_var, foreground="#666666").pack(anchor="w", pady=(5, 0))

    def _build_sessions_tab(self) -> None:
        toolbar = ttk.Frame(self.sessions_tab)
        toolbar.pack(fill="x", pady=(0, 6))
        self.session_state_var = tk.StringVar(value=self.T("recording_off"))
        ttk.Label(toolbar, textvariable=self.session_state_var, font=("Segoe UI", 9, "bold")).pack(side="left")
        self.session_start_button = ttk.Button(toolbar, text=self.T("session_start"), command=self.start_session_recording)
        self.session_start_button.pack(side="right", padx=(6, 0))
        self.session_stop_button = ttk.Button(toolbar, text=self.T("session_stop"), command=self.stop_session_recording, state="disabled")
        self.session_stop_button.pack(side="right")
        ttk.Label(self.sessions_tab, text=self.T("session_warning"), foreground="#8a4b08", wraplength=1400, justify="left").pack(anchor="w", pady=(0, 7))
        mainpane = ttk.Panedwindow(self.sessions_tab, orient="vertical")
        mainpane.pack(fill="both", expand=True)
        upper = ttk.Frame(mainpane)
        lower = ttk.Frame(mainpane)
        mainpane.add(upper, weight=3)
        mainpane.add(lower, weight=2)
        ttk.Label(upper, text=self.T("code_input"), font=("Segoe UI", 9, "bold")).pack(anchor="w")
        entry_row = ttk.Frame(upper)
        entry_row.pack(fill="x", pady=(4, 5))
        self.session_input = tk.Text(entry_row, height=6, wrap="none", font=("Consolas", 10), background="#fbfbfb")
        sy = ttk.Scrollbar(entry_row, orient="vertical", command=self.session_input.yview)
        sx = ttk.Scrollbar(entry_row, orient="horizontal", command=self.session_input.xview)
        self.session_input.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.session_input.grid(row=0, column=0, sticky="nsew")
        sy.grid(row=0, column=1, sticky="ns")
        sx.grid(row=1, column=0, sticky="ew")
        entry_row.rowconfigure(0, weight=1)
        entry_row.columnconfigure(0, weight=1)
        buttons = ttk.Frame(upper)
        buttons.pack(fill="x", pady=(0, 5))
        self.run_code_button = ttk.Button(buttons, text=self.T("run_code"), command=self.run_session_code, state="disabled")
        self.run_code_button.pack(side="left")
        ttk.Button(buttons, text=self.T("clear_code"), command=lambda: self.session_input.delete("1.0", "end")).pack(side="left", padx=6)
        ttk.Label(upper, text=self.T("session_history"), font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 3))
        cols = ("timestamp", "status", "command")
        self.session_tree = ttk.Treeview(upper, columns=cols, show="headings", height=6)
        for col, title, width in [("timestamp", self.T("time") + " / " + self.T("date"), 165), ("status", self.T("type"), 90), ("command", self.T("command"), 650)]:
            self.session_tree.heading(col, text=title)
            self.session_tree.column(col, width=width, minwidth=70, stretch=(col == "command"))
        self.session_tree.pack(fill="both", expand=True)
        self.session_tree.bind("<<TreeviewSelect>>", self.show_session_output)
        ttk.Label(lower, text=self.T("terminal"), font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 3))
        terminal_box = ttk.Frame(lower)
        terminal_box.pack(fill="both", expand=True)
        self.session_output = tk.Text(terminal_box, height=7, wrap="word", font=("Consolas", 9), background="#f7f7f7", relief="solid", borderwidth=1)
        ty = ttk.Scrollbar(terminal_box, orient="vertical", command=self.session_output.yview)
        self.session_output.configure(yscrollcommand=ty.set)
        self.session_output.pack(side="left", fill="both", expand=True)
        ty.pack(side="right", fill="y")
        self.session_output.insert("1.0", self.T("terminal_empty"))
        self.session_output.configure(state="disabled")


    def _build_forensic_tab(self) -> None:
        top = ttk.Frame(self.forensic_tab)
        top.pack(fill="x", pady=(0, 7))
        ttk.Label(top, text=self.T("forensic_title"), font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(top, text=self.T("forensic_notice"), foreground="#555555", wraplength=1400, justify="left").pack(anchor="w", pady=(4, 7))
        ttk.Checkbutton(top, text=self.T("forensic_consent"), variable=self.forensic_consent_var).pack(anchor="w", pady=(0, 6))
        controls = ttk.Frame(top)
        controls.pack(fill="x")
        self.forensic_start_button = ttk.Button(controls, text=self.T("forensic_start"), command=self.start_forensic_scan)
        self.forensic_start_button.pack(side="left")
        self.forensic_export_button = ttk.Button(controls, text=self.T("forensic_export"), command=self.export_forensic_report)
        self.forensic_export_button.pack(side="left", padx=(6, 0))
        sources_label = {"ru": "Состояние источников", "en": "Source availability", "uk": "Стан джерел"}.get(self.lang, "Состояние источников")
        ttk.Button(controls, text=sources_label, command=self.show_forensic_sources).pack(side="left", padx=(6, 0))
        ttk.Label(controls, textvariable=self.forensic_status_var, foreground="#555555").pack(side="left", padx=(12, 0), fill="x", expand=True)
        ttk.Label(top, textvariable=self.forensic_progress_var, foreground="#666666", wraplength=1400).pack(anchor="w", pady=(4, 0))
        ttk.Label(self.forensic_tab, text=self.T("forensic_scope"), foreground="#8a4b08", wraplength=1400, justify="left").pack(anchor="w", pady=(0, 7))

        search_bar = ttk.Frame(self.forensic_tab)
        search_bar.pack(fill="x", pady=(0, 7))
        ttk.Label(search_bar, text=self.T("forensic_search")).pack(side="left")
        search_entry = ttk.Entry(search_bar, textvariable=self.forensic_search_var, width=42)
        search_entry.pack(side="left", padx=(6, 7), fill="x", expand=True)
        search_entry.bind("<KeyRelease>", lambda _event: self.render_forensic_rows())
        ttk.Button(search_bar, text=self.T("forensic_clear_search"), command=lambda: self.forensic_search_var.set("") or self.render_forensic_rows()).pack(side="right")

        pane = ttk.Panedwindow(self.forensic_tab, orient="vertical")
        pane.pack(fill="both", expand=True)
        upper = ttk.Frame(pane)
        lower = ttk.Frame(pane)
        pane.add(upper, weight=4)
        pane.add(lower, weight=2)
        cols = ("timestamp", "kind", "description", "command", "source")
        self.forensic_tree = ttk.Treeview(upper, columns=cols, show="headings")
        labels = {"timestamp": "forensic_col_time", "kind": "forensic_col_category", "description": "forensic_col_event", "command": "command", "source": "forensic_col_source"}
        widths = {"timestamp": 175, "kind": 205, "description": 280, "command": 430, "source": 330}
        for col in cols:
            self.forensic_tree.heading(col, text=self.T(labels[col]))
            self.forensic_tree.column(col, width=widths[col], minwidth=85, stretch=(col in {"description", "command", "source"}))
        fy = ttk.Scrollbar(upper, orient="vertical", command=self.forensic_tree.yview)
        fx = ttk.Scrollbar(upper, orient="horizontal", command=self.forensic_tree.xview)
        self.forensic_tree.configure(yscrollcommand=fy.set, xscrollcommand=fx.set)
        self.forensic_tree.grid(row=0, column=0, sticky="nsew")
        fy.grid(row=0, column=1, sticky="ns")
        fx.grid(row=1, column=0, sticky="ew")
        upper.rowconfigure(0, weight=1)
        upper.columnconfigure(0, weight=1)
        self.forensic_tree.bind("<<TreeviewSelect>>", self.on_forensic_select)
        self.forensic_tree.bind("<Double-1>", self.on_forensic_select)
        ttk.Label(lower, text=self.T("forensic_details"), font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(5, 3))
        detail_box = ttk.Frame(lower)
        detail_box.pack(fill="both", expand=True)
        self.forensic_details_text = tk.Text(detail_box, height=6, wrap="word", font=("Consolas", 9), background="#f7f7f7")
        dy = ttk.Scrollbar(detail_box, orient="vertical", command=self.forensic_details_text.yview)
        self.forensic_details_text.configure(yscrollcommand=dy.set)
        self.forensic_details_text.pack(side="left", fill="both", expand=True)
        dy.pack(side="right", fill="y")
        self.forensic_details_text.insert("1.0", self.T("forensic_empty"))
        self.forensic_details_text.configure(state="disabled")

    def start_forensic_scan(self) -> None:
        if self.forensic_scanning:
            return
        if not self.forensic_consent_var.get():
            messagebox.showwarning(self.T("tab_forensics"), self.T("forensic_status_need_consent"))
            return
        self.forensic_scanning = True
        self.forensic_start_button.configure(state="disabled")
        self.forensic_status_var.set(self.T("forensic_status_running"))
        self.forensic_progress_var.set("")
        self.forensic_tree.delete(*self.forensic_tree.get_children())

        def worker() -> None:
            try:
                def progress(message: str) -> None:
                    self.forensic_queue.put(("progress", str(message)))
                self.forensic_queue.put(("done", scan_local_review(progress)))
            except Exception as exc:
                self.forensic_queue.put(("fatal", str(exc)))

        threading.Thread(target=worker, name="PAV-System-Trace-Review", daemon=True).start()
        self.root.after(120, self.poll_forensic_scan)

    def poll_forensic_scan(self) -> None:
        try:
            while True:
                kind, payload = self.forensic_queue.get_nowait()
                if kind == "progress":
                    self.forensic_progress_var.set(self.translate_runtime(payload))
                elif kind == "done":
                    self.forensic_scanning = False
                    self.forensic_start_button.configure(state="normal")
                    self.forensic_rows = payload.get("events", [])
                    self.forensic_sources = payload.get("sources", [])
                    self.forensic_warnings = payload.get("warnings", [])
                    self.forensic_scan_info = {k: v for k, v in payload.items() if k not in {"events", "sources", "warnings"}}
                    combined_events = self.events + self.forensic_rows
                    self.analysis_quality = attach_analysis(combined_events)
                    runtime_analysis = analyze_python_java_processes(combined_events)
                    risk_assessment = assess_suspiciousness(combined_events, runtime_analysis, self.sources + self.forensic_sources, trusted_paths=list(self.trusted_paths))
                    self.analysis_quality["python_java_analysis"] = runtime_analysis
                    self.analysis_quality["risk_assessment"] = risk_assessment
                    self.scan_info["python_java_analysis"] = runtime_analysis
                    self.scan_info["risk_assessment"] = risk_assessment
                    self.coverage_report = build_scan_coverage(
                        self.sources + self.forensic_sources, self.readiness_report,
                        self.errors + self.forensic_warnings,
                        self.warnings + self.forensic_warnings,
                        combined_events,
                    )
                    self.scan_info["coverage"] = self.coverage_report
                    self.scan_info["analysis_quality"] = self.analysis_quality
                    self.render_readiness_panel()
                    self.render_forensic_rows()
                    self.render_browser_rows()
                    self.render_download_rows()
                    self.render_runtime_panel()
                    self.update_filter_options()
                    self.apply_filter()
                    self.refresh_timeline()
                    self.update_dashboard()
                    self.render_lineage()
                    self.render_artifact_inventory()
                    self.render_relationships()
                    self.draw_activity_heatmap()
                    self.render_final_report()
                    self.save_scan_snapshot()
                    self.forensic_status_var.set(self.T("forensic_status_done", events=len(self.forensic_rows), sources=len(self.forensic_sources), warnings=len(self.forensic_warnings)))
                    self.forensic_progress_var.set("; ".join(self.forensic_warnings[:3]) if self.forensic_warnings else self.T("finished"))
                    return
                elif kind == "fatal":
                    self.forensic_scanning = False
                    self.forensic_start_button.configure(state="normal")
                    self.forensic_status_var.set(self.T("fatal"))
                    self.forensic_progress_var.set(str(payload))
                    messagebox.showerror(self.T("tab_forensics"), str(payload))
                    return
        except queue.Empty:
            pass
        if self.forensic_scanning:
            self.root.after(150, self.poll_forensic_scan)

    def localize_forensic_description(self, value: str) -> str:
        if self.lang == "ru":
            return value
        maps = {
            "AnyDesk: trace record": "AnyDesk: trace record",
            "Запрос подключения отклонён": "Connection request rejected" if self.lang == "en" else "Запит на підключення відхилено",
            "Запрос подключения принят / аутентификация": "Connection request accepted / authentication" if self.lang == "en" else "Запит на підключення прийнято / автентифікація",
            "Запись о запросе подключения": "Connection request record" if self.lang == "en" else "Запис про запит на підключення",
            "Событие передачи файла": "File transfer event" if self.lang == "en" else "Подія передавання файлу",
            "Завершение соединения": "Connection ended" if self.lang == "en" else "Завершення з’єднання",
            "Событие соединения": "Connection event" if self.lang == "en" else "Подія з’єднання",
            "Событие аутентификации": "Authentication event" if self.lang == "en" else "Подія автентифікації",
            "Ошибка или предупреждение": "Error or warning" if self.lang == "en" else "Помилка або попередження",
            "Создание процесса": "Process creation" if self.lang == "en" else "Створення процесу",
            "Завершение процесса": "Process termination" if self.lang == "en" else "Завершення процесу",
            "Доступ к объекту файловой системы": "File-system object access" if self.lang == "en" else "Доступ до об’єкта файлової системи",
            "Изменение состояния службы": "Service state change" if self.lang == "en" else "Зміна стану служби",
            "Изменён тип запуска службы": "Service start type changed" if self.lang == "en" else "Змінено тип запуску служби",
            "Установлена служба Windows": "Windows service installed" if self.lang == "en" else "Встановлено службу Windows",
            "Служба журнала событий запущена": "Event Log service started" if self.lang == "en" else "Службу журналу подій запущено",
            "Служба журнала событий остановлена": "Event Log service stopped" if self.lang == "en" else "Службу журналу подій зупинено",
            "Предыдущее завершение Windows было неожиданным": "Previous Windows shutdown was unexpected" if self.lang == "en" else "Попереднє завершення Windows було неочікуваним",
            "Загрузка библиотеки процессом из цепочки Python (Sysmon Event 7)": "Library loaded by a Python-chain process (Sysmon Event 7)" if self.lang == "en" else "Бібліотеку завантажено процесом у ланцюжку Python (Sysmon Event 7)",
            "DNS-запрос процесса из цепочки Python (Sysmon Event 22)": "DNS query by a Python-chain process (Sysmon Event 22)" if self.lang == "en" else "DNS-запит процесу в ланцюжку Python (Sysmon Event 22)",
            "Событие состояния/конфигурации Sysmon": "Sysmon service/configuration event" if self.lang == "en" else "Подія стану/конфігурації Sysmon",
            "Установка службы, связанной с инструментами разработки (Security 4697)": "Installation of a service related to development tools (Security 4697)" if self.lang == "en" else "Встановлення служби, пов’язаної з інструментами розробки (Security 4697)",
            "Сбой приложения": "Application crash" if self.lang == "en" else "Збій програми",
            "Отчёт Windows Error Reporting": "Windows Error Reporting event" if self.lang == "en" else "Подія Windows Error Reporting",
            "Ошибка .NET Runtime": ".NET Runtime error" if self.lang == "en" else "Помилка .NET Runtime",
            "Запуск движка PowerShell": "PowerShell engine started" if self.lang == "en" else "Запуск рушія PowerShell",
            "Остановка движка PowerShell": "PowerShell engine stopped" if self.lang == "en" else "Зупинка рушія PowerShell",
            "Событие провайдера PowerShell": "PowerShell provider event" if self.lang == "en" else "Подія провайдера PowerShell",
            "PowerShell Module Logging": "PowerShell Module Logging" if self.lang == "en" else "Журналювання модулів PowerShell",
            "PowerShell Script Block Logging": "PowerShell Script Block Logging" if self.lang == "en" else "Журналювання блоків сценаріїв PowerShell",
            "Доступ к Python/IDE-файлу (Security 4663)": "Access to Python/IDE file (Security 4663)" if self.lang == "en" else "Доступ до файлу Python/IDE (Security 4663)",
            "Завершение Python-процесса (Security 4689)": "Python process terminated (Security 4689)" if self.lang == "en" else "Завершення процесу Python (Security 4689)",
            "Файл создан (Sysmon Event 11)": "File created (Sysmon Event 11)" if self.lang == "en" else "Файл створено (Sysmon Event 11)",
            "Файл удалён и архивирован Sysmon (Event 23)": "File deleted and archived by Sysmon (Event 23)" if self.lang == "en" else "Файл видалено й заархівовано Sysmon (Event 23)",
            "Обнаружено удаление файла (Sysmon Event 26)": "File deletion detected (Sysmon Event 26)" if self.lang == "en" else "Виявлено видалення файлу (Sysmon Event 26)",
            "Изменено время создания файла (Sysmon Event 2)": "File creation time changed (Sysmon Event 2)" if self.lang == "en" else "Змінено час створення файлу (Sysmon Event 2)",
            "Задача планировщика содержит ссылку на Python/IDE": "Scheduled task references Python/IDE" if self.lang == "en" else "Завдання планувальника містить посилання на Python/IDE",
            "WMI Activity: событие связано с Python/терминалом": "WMI Activity event relates to Python/terminal" if self.lang == "en" else "Подія WMI Activity пов’язана з Python/терміналом",
            "Сводка источников": "Source inventory summary" if self.lang == "en" else "Зведення джерел",
            "Журнал System очищен": "System log cleared" if self.lang == "en" else "Журнал System очищено",
            "Журнал Security очищен": "Security log cleared" if self.lang == "en" else "Журнал Security очищено",
            "Изменена политика аудита": "Audit policy changed" if self.lang == "en" else "Політику аудиту змінено",
            "Defender обнаружил угрозу": "Defender detected a threat" if self.lang == "en" else "Defender виявив загрозу",
            "Defender выполнил действие": "Defender took action" if self.lang == "en" else "Defender виконав дію",
            "Отключена защита Defender в реальном времени": "Defender real-time protection disabled" if self.lang == "en" else "Захист Defender у реальному часі вимкнено",
            "Изменена конфигурация Defender": "Defender configuration changed" if self.lang == "en" else "Конфігурацію Defender змінено",
            "Запуск Python / IDE / терминала (4688)": "Python / IDE / shell process started (4688)" if self.lang == "en" else "Запущено процес Python / IDE / оболонки (4688)",
            "USN-журнал доступен (проверены только метаданные)": "USN journal available (metadata only)" if self.lang == "en" else "Журнал USN доступний (лише метадані)",
            "Файл Amcache.hve присутствует": "Amcache.hve file is present" if self.lang == "en" else "Файл Amcache.hve присутній",
            "Установлена служба Windows": "Windows service installed" if self.lang == "en" else "Встановлено службу Windows",
            "Служба журнала событий запущена": "Event Log service started" if self.lang == "en" else "Службу журналу подій запущено",
            "Служба журнала событий остановлена": "Event Log service stopped" if self.lang == "en" else "Службу журналу подій зупинено",
            "Предыдущее завершение Windows было неожиданным": "Previous Windows shutdown was unexpected" if self.lang == "en" else "Попереднє завершення Windows було неочікуваним",
            "Изменение параметра автозапуска реестра": "Registry startup entry changed" if self.lang == "en" else "Змінено запис автозапуску реєстру",
            "Изменение задачи планировщика, связанной с Python": "Python-related scheduled task changed" if self.lang == "en" else "Змінено завдання планувальника, пов’язане з Python",
            "Загрузка образа (Sysmon)": "Image loaded (Sysmon)" if self.lang == "en" else "Завантаження образу (Sysmon)",
            "Изменена конфигурация Sysmon": "Sysmon configuration changed" if self.lang == "en" else "Конфігурацію Sysmon змінено",
            "DNS-запрос процесса (Sysmon)": "Process DNS query (Sysmon)" if self.lang == "en" else "DNS-запит процесу (Sysmon)",
        }
        dynamic_prefixes = (
            ("Запуск интерпретатора Python (4688)", "Python interpreter started (4688)", "Запущено інтерпретатор Python (4688)"),
            ("Запуск Python (Sysmon Event 1)", "Python started (Sysmon Event 1)", "Запуск Python (Sysmon Event 1)"),
        )
        for ru, en, uk in dynamic_prefixes:
            if value == ru:
                return en if self.lang == "en" else uk
        if value.startswith("Процесс создан Python: "):
            suffix = value.split(": ", 1)[1]
            return ("Process created by Python: " if self.lang == "en" else "Процес створено Python: ") + suffix
        if value.startswith("Процесс в цепочке Python: "):
            suffix = value.split(": ", 1)[1]
            return ("Process in Python chain: " if self.lang == "en" else "Процес у ланцюжку Python: ") + suffix
        if value.startswith("Оболочка запускает Python: "):
            suffix = value.split(": ", 1)[1]
            return ("Shell launches Python: " if self.lang == "en" else "Оболонка запускає Python: ") + suffix
        return maps.get(value, value)

    def show_forensic_sources(self) -> None:
        title = {"ru": "Состояние источников", "en": "Source availability", "uk": "Стан джерел"}.get(self.lang, "Состояние источников")
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("1050x620")
        frame = ttk.Frame(window, padding=8)
        frame.pack(fill="both", expand=True)
        columns = ("status", "type", "path", "events", "note")
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        labels = {
            "ru": ("Состояние", "Тип", "Источник / путь", "Записей", "Примечание"),
            "en": ("Status", "Type", "Source / path", "Records", "Note"),
            "uk": ("Стан", "Тип", "Джерело / шлях", "Записів", "Примітка"),
        }.get(self.lang, ("Состояние", "Тип", "Источник / путь", "Записей", "Примечание"))
        widths = (110, 190, 330, 80, 360)
        for col, label, width in zip(columns, labels, widths):
            tree.heading(col, text=label)
            tree.column(col, width=width, minwidth=70, stretch=(col in {"path", "note"}))
        yscroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        xscroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        status_labels = {
            "ru": {"available": "доступен", "inaccessible": "нет доступа", "not_found": "не найден", "not_applicable": "не применимо", "timeout": "тайм-аут", "error": "ошибка", "unknown": "неизвестно"},
            "en": {"available": "available", "inaccessible": "inaccessible", "not_found": "not found", "not_applicable": "not applicable", "timeout": "timeout", "error": "error", "unknown": "unknown"},
            "uk": {"available": "доступне", "inaccessible": "немає доступу", "not_found": "не знайдено", "not_applicable": "не застосовується", "timeout": "тайм-аут", "error": "помилка", "unknown": "невідомо"},
        }
        for i, item in enumerate(self.forensic_sources):
            raw_status = str(item.get("status", "unknown"))
            status = status_labels.get(self.lang, status_labels["ru"]).get(raw_status, raw_status)
            records = item.get("matched_events", item.get("events_read", item.get("matched_files", "")))
            note = str(item.get("note", ""))
            if item.get("read_status") == "warning":
                read_note = str(item.get("read_note", ""))
                note = (note + " | " if note else "") + ("Ошибка чтения: " if self.lang == "ru" else ("Read warning: " if self.lang == "en" else "Попередження читання: ")) + read_note[:350]
            if not note and item.get("log_metadata"):
                note = str(item.get("log_metadata", "")).replace("\r", " ").replace("\n", " ")[:350]
            source_type = str(item.get("type", ""))
            source_type_map = {
                "Task Scheduler inventory": {"en": "Task Scheduler inventory", "uk": "Інвентаризація планувальника"},
                "Win32_Service inventory": {"en": "Win32 service inventory", "uk": "Інвентаризація служб Win32"},
                "Run/RunOnce registry inventory": {"en": "Run/RunOnce registry inventory", "uk": "Інвентаризація реєстру Run/RunOnce"},
                "Windows Event Log channel": {"en": "Windows Event Log channel", "uk": "Канал журналу подій Windows"},
            }
            if self.lang != "ru" and source_type in source_type_map:
                source_type = source_type_map[source_type][self.lang]
            tree.insert("", "end", iid=str(i), values=(status, source_type, item.get("path", ""), records, note))
        summary = self.forensic_scan_info.get("source_status_counts", {})
        summary_text = " • ".join(f"{key}: {value}" for key, value in sorted(summary.items())) if summary else f"{len(self.forensic_sources)}"
        ttk.Label(window, text=summary_text, foreground="#666666").pack(anchor="w", padx=8, pady=(5, 8))

    def render_forensic_rows(self) -> None:
        if not hasattr(self, "forensic_tree"):
            return
        self.forensic_tree.delete(*self.forensic_tree.get_children())
        query = self.forensic_search_var.get().strip().casefold() if hasattr(self, "forensic_search_var") else ""
        visible = 0
        for index, row in enumerate(self.forensic_rows):
            searchable = json.dumps(row, ensure_ascii=False, default=str).casefold()
            if query and query not in searchable:
                continue
            values = (
                row.get("timestamp", "") or "—",
                self.localize_kind(row.get("kind", "")),
                self.localize_forensic_description(row.get("description", "")),
                row.get("command", ""),
                row.get("source", ""),
            )
            self.forensic_tree.insert("", "end", iid=str(index), values=values)
            visible += 1
        if not self.forensic_rows or visible == 0:
            self.forensic_details_text.configure(state="normal")
            self.forensic_details_text.delete("1.0", "end")
            message = self.T("forensic_empty") if not self.forensic_rows else self.T("no_selection")
            self.forensic_details_text.insert("1.0", message)
            self.forensic_details_text.configure(state="disabled")

    def on_forensic_select(self, _event: Any = None) -> None:
        selected = self.forensic_tree.selection() if hasattr(self, "forensic_tree") else ()
        if not selected:
            return
        try:
            row = self.forensic_rows[int(selected[0])]
        except Exception:
            return
        text_value = json.dumps(row, ensure_ascii=False, indent=2, default=str)
        self.forensic_details_text.configure(state="normal")
        self.forensic_details_text.delete("1.0", "end")
        self.forensic_details_text.insert("1.0", text_value)
        self.forensic_details_text.configure(state="disabled")

    def export_forensic_report(self) -> None:
        if not self.forensic_scan_info:
            messagebox.showinfo(self.T("forensic_export_title"), self.T("forensic_no_result"))
            return
        path = filedialog.asksaveasfilename(
            title=self.T("forensic_export_title"), defaultextension=".json",
            filetypes=[(self.T("forensic_file_type"), "*.json"), ("All files", "*.*")],
            initialfile="python_activity_system_trace_report.json",
        )
        if not path:
            return
        report = {
            "application": APP_NAME,
            "version": APP_VERSION,
            "consent_confirmed_in_ui": bool(self.forensic_consent_var.get()),
            "analysis": self.forensic_scan_info,
            "audit_readiness": self.readiness_report,
            "coverage": self.coverage_report,
            "analysis_quality": self.analysis_quality,
            "summary": {"events": len(self.forensic_rows), "sources": len(self.forensic_sources), "warnings": len(self.forensic_warnings), "source_status_counts": self.forensic_scan_info.get("source_status_counts", {})},
            "sources": self.forensic_sources,
            "events": self.forensic_rows,
            "warnings": self.forensic_warnings,
            "limitations": [
                "An absent event does not prove that an action did not occur.",
                "Windows process command lines are available only if process-creation command-line auditing was enabled before the event.",
                "AnyDesk traces are only an optional source; they are not required for the utility to work.",
                "Sysmon process events are available only if Sysmon was already installed and logging before the reviewed activity.",
                "A Python-launched child process can be linked only when its parent process identifiers/names are present in retained event logs.",
                "AnyDesk logs may be missing, rotated, moved or deleted; this utility does not carve raw disk sectors.",
                "USN inspection is limited to journal availability metadata; it does not enumerate deleted files.",
                "Review local paths, usernames, command lines and event metadata before sharing the report; exact values are exported without masking.",
                "This JSON report is not digitally signed and has no tamper-detection mechanism.",
            ],
        }
        try:
            Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.forensic_status_var.set(self.T("forensic_saved") + ": " + path)
            messagebox.showinfo(self.T("forensic_export_title"), self.T("forensic_saved"))
        except Exception as exc:
            messagebox.showerror(self.T("forensic_export_title"), str(exc))

    def translate_runtime(self, value: str) -> str:
        """Translate common scanner status fragments while preserving paths and file names."""
        text_value = str(value)
        if self.lang == "ru":
            return text_value
        replacements = [
            ("Подготавливаю список источников", "Preparing source list" if self.lang == "en" else "Готую список джерел"),
            ("Ищу истории PyCharm/Python, CMD/PowerShell и журналы Windows", "Searching PyCharm/Python, CMD/PowerShell histories and Windows logs" if self.lang == "en" else "Пошук історій PyCharm/Python, CMD/PowerShell і журналів Windows"),
            ("Читаю SQLite-историю", "Reading SQLite history" if self.lang == "en" else "Читання історії SQLite"),
            ("Читаю историю Python Console PyCharm", "Reading PyCharm Python Console history" if self.lang == "en" else "Читання історії Python Console PyCharm"),
            ("Читаю PowerShell transcript", "Reading PowerShell transcript" if self.lang == "en" else "Читання транскрипту PowerShell"),
            ("Ищу Python-файлы", "Searching Python files" if self.lang == "en" else "Пошук файлів Python"),
            ("Сканирование завершено", self.T("finished")),
            ("Сканирование…", self.T("scanning")),
            ("Подготовка сканирования…", self.T("scanning")),
            ("Глубокий анализ завершён", "Deep analysis completed" if self.lang == "en" else "Глибокий аналіз завершено"),
            ("читаю", "reading" if self.lang == "en" else "читаю"),
            ("Проверяю активные процессы Python, PyCharm, CMD и PowerShell", "Checking active Python, PyCharm, CMD and PowerShell processes" if self.lang == "en" else "Перевірка активних процесів Python, PyCharm, CMD і PowerShell"),
            ("Читаю события 4688: запуски Python-инструментов из CMD/PowerShell", "Reading event 4688: Python tool launches from CMD/PowerShell" if self.lang == "en" else "Читання подій 4688: запуск інструментів Python із CMD/PowerShell"),
            ("Проверяю журнал PowerShell 4103/4104", "Checking PowerShell log 4103/4104" if self.lang == "en" else "Перевірка журналу PowerShell 4103/4104"),
            ("Проверяю Корзину Windows", "Checking the Windows Recycle Bin" if self.lang == "en" else "Перевірка Кошика Windows"),
            ("Проверяю Prefetch-следы Python", "Checking Python Prefetch traces" if self.lang == "en" else "Перевірка слідів Python у Prefetch"),
            ("Проверка дополнительных диагностических журналов AnyDesk (если доступны)…", "Checking optional AnyDesk diagnostic logs…" if self.lang == "en" else "Перевірка додаткових діагностичних журналів AnyDesk…"),
            ("Проверка AnyDesk: найдено файлов журналов", "Optional AnyDesk logs found" if self.lang == "en" else "Додаткових журналів AnyDesk знайдено"),
            ("Анализ цепочек процессов по Windows Security 4688…", "Analyzing process chains from Windows Security 4688…" if self.lang == "en" else "Аналіз ланцюжків процесів за Windows Security 4688…"),
            ("Проверка Sysmon: запуски Python и дочерние процессы (Event ID 1)…", "Checking Sysmon: Python launches and child processes (Event ID 1)…" if self.lang == "en" else "Перевірка Sysmon: запуски Python і дочірні процеси (Event ID 1)…"),
            ("Проверка доступных локальных журналов Windows", "Checking available local Windows logs" if self.lang == "en" else "Перевірка доступних локальних журналів Windows"),
            ("Проверка событий запуска процессов", "Checking process creation events" if self.lang == "en" else "Перевірка подій запуску процесів"),
            ("Проверка событий очистки журналов и изменения аудита", "Checking log-clear and audit-policy-change events" if self.lang == "en" else "Перевірка подій очищення журналів і зміни аудиту"),
            ("Проверка сценарных блоков PowerShell", "Checking PowerShell script-block events" if self.lang == "en" else "Перевірка подій блоків сценаріїв PowerShell"),
            ("Проверка событий Microsoft Defender", "Checking Microsoft Defender events" if self.lang == "en" else "Перевірка подій Microsoft Defender"),
            ("Проверка Prefetch для Python и IDE", "Checking Prefetch for Python and IDEs" if self.lang == "en" else "Перевірка Prefetch для Python та IDE"),
            ("Проверка Amcache и состояния USN-журнала", "Checking Amcache and USN journal status" if self.lang == "en" else "Перевірка Amcache та стану журналу USN"),
            ("Проверка зарегистрированных задач планировщика", "Checking registered scheduled tasks" if self.lang == "en" else "Перевірка зареєстрованих завдань планувальника"),
            ("Проверка служб Windows", "Checking Windows services" if self.lang == "en" else "Перевірка служб Windows"),
            ("Проверка выбранных ключей автозапуска реестра", "Checking selected registry startup keys" if self.lang == "en" else "Перевірка вибраних ключів автозапуску реєстру"),
            ("Ищу исходники Python", "Searching Python source files" if self.lang == "en" else "Пошук вихідних файлів Python"),
            ("Проверяю", "Checking" if self.lang == "en" else "Перевіряю"),
            ("Читаю", "Reading" if self.lang == "en" else "Читаю"),
            ("Ищу", "Searching" if self.lang == "en" else "Шукаю"),
        ]
        for old, new in replacements:
            text_value = text_value.replace(old, new)
        if self.lang == "en":
            text_value = text_value.replace("папках проектов", "project folders").replace("проверено", "checked").replace("просмотрено", "scanned").replace("файлов", "files").replace("кандидатов", "candidates").replace("событий", "events").replace("Python-файлов", "Python files").replace("найдено", "found").replace("добавлено записей", "records added")
        elif self.lang == "uk":
            text_value = text_value.replace("папках проектов", "папках проєктів").replace("проверено", "перевірено").replace("просмотрено", "переглянуто").replace("файлов", "файлів").replace("кандидатов", "кандидатів").replace("событий", "подій").replace("Python-файлов", "файлів Python").replace("найдено", "знайдено")
        return text_value

    def start_scan(self) -> None:
        if getattr(self, "scanning", False):
            return
        self._active_scan_kind = "full"
        super().start_scan()
        if getattr(self, "scanning", False):
            if hasattr(self, "browser_scan_button"):
                self.browser_scan_button.configure(state="disabled")
            if hasattr(self, "cancel_button"):
                self.cancel_button.configure(state="normal")
            self.status_var.set(self.T("scanning"))
            self.progress_message_var.set(self.T("scanning"))
            self.file_count_var.set(self.T("scanning"))
            self.details_text.configure(state="normal")
            self.details_text.delete("1.0", "end")
            self.details_text.insert("1.0", self.T("scanning"))
            self.details_text.configure(state="disabled")
            self.code_text.configure(state="normal")
            self.code_text.delete("1.0", "end")
            self.code_text.insert("1.0", self.T("select_file"))
            self.code_text.configure(state="disabled")

    def copy_command(self) -> None:
        item = self.selected_event()
        if not item:
            return
        value = item.get("command") or item.get("description", "")
        self.root.clipboard_clear()
        self.root.clipboard_append(str(value))
        self.status_var.set(self.T("saved"))

    def copy_details(self) -> None:
        item = self.selected_event()
        if not item:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(json.dumps(item, ensure_ascii=False, indent=2, default=str))
        self.status_var.set(self.T("saved"))

    def _maybe_show_diagnostics_hint(self) -> None:
        if self.warnings or self.errors:
            hint = {"ru": " • Подробности: Вид → Источники и предупреждения", "en": " • Details: View → Sources and warnings", "uk": " • Докладно: Вигляд → Джерела та попередження"}[self.lang]
            self.status_var.set(self.status_var.get() + hint)

    def copy_selected_file_path(self) -> None:
        item = self.selected_python_file()
        if not item:
            messagebox.showinfo(self.T("copy_path"), self.T("no_selection"))
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(str(item.get("path", "")))
        self.status_var.set(self.T("saved"))

    def open_selected_python_file(self) -> None:
        item = self.selected_python_file()
        if not item:
            messagebox.showinfo(self.T("open_file"), self.T("no_selection"))
            return
        path = Path(item.get("path", ""))
        try:
            if os.name == "nt":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror(self.T("open_file"), str(exc))

    def show_context_menu(self, event: Any) -> None:
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_command(label=self.T("copy_command"), command=self.copy_command)
        menu.add_command(label=self.T("copy_details"), command=self.copy_details)
        menu.add_separator()
        props = {"ru": "Свойства…", "en": "Properties…", "uk": "Властивості…"}[self.lang]
        menu.add_command(label=props, command=self.show_properties)
        menu.tk_popup(event.x_root, event.y_root)

    def show_properties(self) -> None:
        item = self.selected_event()
        if not item:
            return
        window = tk.Toplevel(self.root)
        title = {"ru": "Свойства события", "en": "Event properties", "uk": "Властивості події"}[self.lang]
        window.title(title)
        window.geometry("900x620")
        text = tk.Text(window, wrap="word", font=("Consolas", 9))
        scroll = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("1.0", json.dumps(item, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")

    def export_csv(self) -> None:
        if not self.events and not getattr(self, "forensic_rows", []):
            messagebox.showinfo(self.T("export_csv"), self.T("scan_first"))
            return
        path = filedialog.asksaveasfilename(
            title=self.T("export_csv"), defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("All files", "*.*")], initialfile="python_activity_events.csv",
        )
        if not path:
            return
        try:
            fields = ["timestamp", "time_basis", "kind", "description", "command", "source", "user", "timestamp_utc", "timestamp_local", "time_normalization", "evidence_assessment", "details"]
            with open(path, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                combined_rows = list(self.filtered) + list(getattr(self, "forensic_rows", []))
                for item in combined_rows:
                    row = dict(item)
                    for nested_key in ("details", "time_normalization", "evidence_assessment"):
                        row[nested_key] = json.dumps(row.get(nested_key, {}), ensure_ascii=False, default=str)
                    writer.writerow(row)
            self.status_var.set(f"{self.T('saved')}: {path} ({len(combined_rows)} строк)")
        except Exception as exc:
            messagebox.showerror(self.T("export_csv"), str(exc))

    def _case_context_payload(self) -> dict[str, Any]:
        return {
            "case": self._current_case_payload() if hasattr(self, "case_notes_text") else {},
            "case_file": str(getattr(self, "active_case_file", self.case_notes_file)),
            "trusted_context_paths": list(getattr(self, "trusted_paths", [])),
        }

    def export_json(self) -> None:
        if not self.events and not getattr(self, "forensic_rows", []):
            messagebox.showinfo(self.T("export_json"), self.T("scan_first"))
            return
        path = filedialog.asksaveasfilename(
            title=self.T("export_json"), defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")], initialfile="python_activity_report.json",
        )
        if not path:
            return
        combined_total = len(self.events) + len(getattr(self, "forensic_rows", []))
        combined_exported = len(self.filtered) + len(getattr(self, "forensic_rows", []))
        combined_types = Counter(e.get("kind", "") for e in (list(self.events) + list(getattr(self, "forensic_rows", []))))
        report = {
            "application": APP_NAME, "version": APP_VERSION, "scan_info": self.scan_info,
            "case_context": self._case_context_payload(),
            "artifact_sources": getattr(self, "artifact_sources", []),
            "audit_readiness": self.readiness_report, "coverage": self.coverage_report, "analysis_quality": self.analysis_quality,
            "summary": {"events_total": combined_total, "events_exported": combined_exported, "event_types": dict(combined_types)},
            "sources": (self.sources), "python_files": (self.python_files), "events": (self.filtered),
            "current_process_snapshot": (getattr(self, "process_rows", [])),
            "warnings": (self.warnings), "errors": (self.errors),
            "session_log_path": str(self.session_file) if self.session_file else None,
            "session_entries": (self.session_rows),
            "signature_checks": (self.signature_checks),
            "system_trace_analysis": ({
                "analysis": (self.forensic_scan_info),
                "events": (self.forensic_rows),
                "sources": (self.forensic_sources),
                "warnings": (self.forensic_warnings),
            } if self.forensic_scan_info or self.forensic_rows or self.forensic_sources else None),
        }
        try:
            Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
            self.status_var.set(f"{self.T('saved')}: {path}")
        except Exception as exc:
            messagebox.showerror(self.T("export_json"), str(exc))

    def update_progress(self, payload: dict[str, Any]) -> None:
        self.last_progress_payload = dict(payload)
        message = self.translate_runtime(str(payload.get("message", self.T("scanning"))))
        self.progress_message_var.set(message)
        self.status_var.set(message)
        folders = int(payload.get("directories_checked", 0) or 0)
        files_seen = int(payload.get("files_seen", 0) or 0)
        candidates = int(payload.get("candidate_files", 0) or 0)
        sources = int(payload.get("sources_checked", 0) or 0)
        checked = int(payload.get("artifacts_done", 0) or 0)
        total = int(payload.get("artifacts_total", 0) or 0)
        records = int(payload.get("records_found", 0) or 0)
        pyfiles = int(payload.get("python_files_found", 0) or 0)
        if self.lang == "en":
            stats = f"Folders: {folders:,} • files seen: {files_seen:,} • candidates: {candidates:,} • sources checked: {sources:,} • analysis: {checked:,}/{total:,} • events: {records:,} • source files: {pyfiles:,}"
            path_label = "Current folder/file: "
        elif self.lang == "uk":
            stats = f"Папок: {folders:,} • переглянуто файлів: {files_seen:,} • кандидатів: {candidates:,} • перевірено джерел: {sources:,} • аналіз: {checked:,}/{total:,} • подій: {records:,} • вихідних файлів: {pyfiles:,}"
            path_label = "Поточна папка/файл: "
        else:
            stats = f"Папок: {folders:,} • просмотрено файлов: {files_seen:,} • кандидатов: {candidates:,} • проверено источников: {sources:,} • анализ: {checked:,}/{total:,} • событий: {records:,} • исходников: {pyfiles:,}"
            path_label = "Текущая папка/файл: "
        self.progress_stats_var.set(stats.replace(",", " "))
        self.current_path_var.set(path_label + str(payload.get("current_path", "") or "—"))
        phase = str(payload.get("phase", ""))
        if phase == "deep_analysis" and total > 0:
            self.progressbar.stop()
            self.progressbar.configure(mode="determinate", maximum=total, value=min(checked, total))
        elif self.progressbar.cget("mode") != "indeterminate":
            self.progressbar.stop()
            self.progressbar.configure(mode="indeterminate")
            self.progressbar.start(10)

    def poll_worker(self) -> None:
        try:
            while True:
                kind, payload = self.worker_queue.get_nowait()
                if kind == "progress":
                    if isinstance(payload, dict):
                        self.update_progress(payload)
                    else:
                        msg = self.translate_runtime(str(payload))
                        self.status_var.set(msg)
                        self.progress_message_var.set(msg)
                elif kind == "browser_done":
                    self._set_main_scan_controls_idle()
                    self._apply_browser_scan_result(payload)
                    return
                elif kind == "browser_fatal":
                    self._set_main_scan_controls_idle()
                    error_text = str(payload)
                    self.browser_scan_status_var.set(self.T("browser_scan_failed", error=error_text))
                    self.status_var.set(self.browser_scan_status_var.get())
                    messagebox.showerror(self.T("tab_browser"), error_text)
                    return
                elif kind == "done":
                    self._set_main_scan_controls_idle()
                    self.progressbar.stop()
                    self.progressbar.configure(mode="determinate", maximum=100, value=100)
                    self.progress_message_var.set(self.T("finished"))
                    self.events = payload["events"]
                    self.sources = payload["sources"]
                    self.warnings = payload["warnings"]
                    self.errors = payload["errors"]
                    self.scan_info = payload["scan_info"]
                    if self.scan_info.get("browser_history_requested"):
                        browser_sources = [row for row in self.sources if row.get("type") == "browser_history"]
                        available = [row for row in browser_sources if row.get("status") == "available"]
                        self.browser_scan_status_var.set(self.T(
                            "browser_scan_done",
                            profiles=len(available),
                            visits=sum(int(row.get("visits", 0) or 0) for row in available),
                            downloads=sum(int(row.get("downloads", 0) or 0) for row in available),
                            issues=sum(1 for row in browser_sources if row.get("status") != "available"),
                        ))
                    else:
                        self.browser_scan_status_var.set(self.T("browser_scan_pending"))
                    self.python_files = payload.get("python_files", [])
                    self.readiness_report = self.scan_info.get("audit_readiness", {})
                    self.coverage_report = self.scan_info.get("coverage", {})
                    self.analysis_quality = self.scan_info.get("analysis_quality", {})
                    self._event_search_index = []
                    for item in self.events:
                        cmd = str(item.get("command", ""))
                        blob = " ".join([str(item.get("timestamp", "")), str(item.get("kind", "")), str(item.get("description", "")), cmd, str(item.get("source", "")), str(item.get("user", "")), json.dumps(item.get("details", {}), ensure_ascii=False, default=str)]).casefold()
                        self._event_search_index.append((cmd.casefold(), blob))
                    self.update_filter_options()
                    self.apply_filter()
                    self.apply_file_filter()
                    self.update_dashboard()
                    self.refresh_timeline()
                    self.render_lineage()
                    self.render_recovery_rows()
                    self.render_readiness_panel()
                    self.save_scan_snapshot()
                    self.status_var.set(self.T("scan_summary", events=len(self.events), files=len(self.python_files), sources=len(self.sources), warnings=len(self.warnings)))
                    if self.warnings or self.errors:
                        self.root.after(250, self._maybe_show_diagnostics_hint)
                    return
                elif kind == "cancelled":
                    was_browser_only = self._active_scan_kind == "browser_only"
                    self._set_main_scan_controls_idle()
                    self.progress_message_var.set(self.T("scan_cancelled"))
                    self.status_var.set(self.T("scan_cancelled"))
                    if was_browser_only:
                        self.browser_scan_status_var.set(self.T("browser_scan_cancelled"))
                    return
                elif kind == "fatal":
                    self._set_main_scan_controls_idle()
                    self.progressbar.stop()
                    self.progress_message_var.set(self.T("fatal"))
                    self.status_var.set(self.T("fatal"))
                    messagebox.showerror(self.T("fatal"), str(payload))
                    return
        except queue.Empty:
            pass
        if getattr(self, "scanning", False):
            self.root.after(120, self.poll_worker)

    def update_filter_options(self) -> None:
        raw_kinds = sorted({e.get("kind", "") for e in (list(self.events) + list(getattr(self, "forensic_rows", []))) if e.get("kind")})
        self.filter_display_to_raw = {self.localize_kind(kind): kind for kind in raw_kinds}
        values = [self.T("all_events")] + list(self.filter_display_to_raw)
        self.filter_combo["values"] = values
        if self.filter_var.get() not in values:
            self.filter_var.set(self.T("all_events"))

    def apply_filter(self) -> None:
        command_raw = self.command_search_var.get().strip()
        query_raw = self.search_var.get().strip()
        mode = self.search_mode_var.get()
        case_sensitive = bool(self.case_sensitive_var.get())
        date_from = self.date_from_var.get().strip()
        date_to = self.date_to_var.get().strip()
        for label, value in (("date_from", date_from), ("date_to", date_to)):
            if value:
                try:
                    datetime.strptime(value, "%Y-%m-%d")
                except ValueError:
                    self.status_var.set("Неверный формат даты. Используйте ГГГГ-ММ-ДД." if self.lang == "ru" else ("Invalid date. Use YYYY-MM-DD." if self.lang == "en" else "Невірний формат дати. Використовуйте РРРР-ММ-ДД."))
                    return
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            command_pattern = re.compile(command_raw, flags) if mode == "regex" and command_raw else None
            all_pattern = re.compile(query_raw, flags) if mode == "regex" and query_raw else None
        except re.error as exc:
            self.status_var.set(self.T("search_invalid_regex", error=str(exc)))
            return

        def normalize(value: str) -> str:
            return value if case_sensitive else value.casefold()

        def matches(value: str, needle: str, pattern: Any = None, command_exact: bool = False) -> bool:
            if not needle:
                return True
            if mode == "regex":
                return bool(pattern.search(value)) if pattern else True
            lhs, rhs = normalize(value), normalize(needle)
            if mode == "exact":
                return lhs.strip() == rhs.strip() if command_exact else rhs in lhs.split("\n")
            return rhs in lhs

        kind_filter = self.filter_var.get()
        kind_filter_raw = getattr(self, "filter_display_to_raw", {}).get(kind_filter, kind_filter)
        result = []
        combined_events = list(self.events) + list(getattr(self, "forensic_rows", []))
        for position, item in enumerate(combined_events):
            if kind_filter not in {self.T("all_events"), "Все события", "All events", "Усі події"} and item.get("kind") != kind_filter_raw:
                continue
            day = str(item.get("date") or item.get("timestamp", "")[:10])
            if date_from and (not day or day < date_from):
                continue
            if date_to and (not day or day > date_to):
                continue
            command_value = str(item.get("command", ""))
            if command_raw and not matches(command_value, command_raw, command_pattern, command_exact=True):
                continue
            fields = [str(item.get(k, "")) for k in ("timestamp", "kind", "description", "source", "user")]
            if query_raw:
                if mode == "exact":
                    if not any(normalize(query_raw) == normalize(field.strip()) for field in fields + [command_value]):
                        continue
                else:
                    searchable = "\n".join(fields + [command_value, json.dumps(item.get("details", {}), ensure_ascii=False, default=str)])
                    if not matches(searchable, query_raw, all_pattern):
                        continue
            result.append(item)
        self.filtered = result
        self.render_rows()

    def reset_filters(self) -> None:
        self.command_search_var.set("")
        self.search_var.set("")
        self.filter_var.set(self.T("all_events"))
        self.date_from_var.set("")
        self.date_to_var.set("")
        self.search_mode_var.set("contains")
        self.case_sensitive_var.set(False)
        if hasattr(self, "search_mode_display_var"):
            self.search_mode_display_var.set(self.T("search_contains"))
        self.apply_filter()

    def apply_file_filter(self) -> None:
        query = self.file_search_var.get().casefold().strip()
        self.filtered_python_files = [x for x in self.python_files if not query or query in str(x.get("name", "")).casefold() or query in str(x.get("path", "")).casefold()]
        self.file_tree.delete(*self.file_tree.get_children())
        for i, item in enumerate(self.filtered_python_files):
            self.file_tree.insert("", "end", iid=str(i), values=(item.get("name", ""), item.get("modified_local", ""), item.get("size_display", ""), item.get("extension", "")))
        if self.lang == "en":
            self.file_count_var.set(f"Showing {len(self.filtered_python_files)} of {len(self.python_files)} files")
        elif self.lang == "uk":
            self.file_count_var.set(f"Показано {len(self.filtered_python_files)} із {len(self.python_files)} файлів")
        else:
            self.file_count_var.set(f"Показано {len(self.filtered_python_files)} из {len(self.python_files)} файлов")

    def render_rows(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for index, item in enumerate(self.filtered):
            command = str(item.get("command", "")).replace("\n", " ⏎ ").replace("\r", "")
            if len(command) > 240:
                command = command[:237] + "..."
            self.tree.insert("", "end", iid=str(index), tags=("even" if index % 2 == 0 else "odd",), values=(item.get("date", "") or "—", item.get("time", "") or "—", self.localize_kind(item.get("kind", "")), item.get("description", ""), command, item.get("source", ""), item.get("user", "")))
        self.update_dashboard()

    def on_select(self, _event: Any = None) -> None:
        item = self.selected_event()
        if not item:
            return
        labels = {
            "ru": ("Дата и время", "Основание времени", "Тип события", "Описание", "Команда / содержимое", "Источник", "Пользователь", "Дополнительные сведения"),
            "en": ("Date and time", "Time basis", "Event type", "Description", "Command / content", "Source", "User", "Additional details"),
            "uk": ("Дата й час", "Підстава часу", "Тип події", "Опис", "Команда / вміст", "Джерело", "Користувач", "Додаткові відомості"),
        }[self.lang]
        values = [item.get("timestamp", "") or "—", item.get("time_basis", "") or "—", item.get("kind", ""), item.get("description", ""), item.get("command", "") or "—", item.get("source", ""), item.get("user", "") or "—", json.dumps(item.get("details", {}), ensure_ascii=False, indent=2, default=str)]
        body = "\n\n".join(f"{label}:\n{value}" for label, value in zip(labels, values))
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", "end")
        self.details_text.insert("1.0", body)
        self.details_text.configure(state="disabled")

    def update_dashboard(self) -> None:
        if not hasattr(self, "overview_vars"):
            return
        values = [len(self.events), len(self.python_files), len(self.sources), len(self.warnings) + len(self.errors)]
        for var, value in zip(self.overview_vars, values):
            var.set(f"{value:,}".replace(",", " "))
        by_day: Counter = Counter()
        for item in self.events:
            day = item.get("date") or ""
            if day:
                by_day[day] += 1
        timeline = []
        for day, count in sorted(by_day.items())[-21:]:
            timeline.append(f"{day}  {'█' * min(count, 42)}  {count}")
        if not timeline:
            timeline = [self.T("no_events")]
        self.timeline_text.configure(state="normal")
        self.timeline_text.delete("1.0", "end")
        self.timeline_text.insert("1.0", "\n".join(timeline))
        self.timeline_text.configure(state="disabled")
        self.recent_tree.delete(*self.recent_tree.get_children())
        recent = sorted(self.events, key=lambda x: time_sort_value(x.get("timestamp", "")), reverse=True)[:100]
        for i, item in enumerate(recent):
            cmd = str(item.get("command", "") or item.get("description", "")).replace("\n", " ⏎ ")
            if len(cmd) > 180:
                cmd = cmd[:177] + "..."
            self.recent_tree.insert("", "end", iid=str(i), values=(item.get("date", "") or "—", item.get("time", "") or "—", self.localize_kind(item.get("kind", "")), cmd))

    def _open_recent_event(self, _event: Any = None) -> None:
        selected = self.recent_tree.selection()
        if not selected:
            return
        row = self.recent_tree.item(selected[0], "values")
        for item in self.events:
            if item.get("date", "") == row[0] and item.get("time", "") == row[1] and item.get("kind", "") == row[2]:
                self._select_app_tab(self.history_tab)
                self.search_var.set(str(item.get("command", "") or item.get("description", ""))[:40])
                self.apply_filter()
                break

    def render_recovery_rows(self) -> None:
        if not hasattr(self, "recovery_tree"):
            return
        keywords = ("остат", "возможн", "recovery", "residual", "freelist", "sqlite", "wal", "backup", "архив", "archive", "recycle", "резерв")
        rows = [item for item in self.events if any(k in (str(item.get("kind", "")) + " " + str(item.get("description", ""))).casefold() for k in keywords)]
        self._last_recovery_rows = rows
        self.recovery_tree.delete(*self.recovery_tree.get_children())
        for i, item in enumerate(rows):
            command = str(item.get("command", "") or item.get("description", "")).replace("\n", " ⏎ ")
            if len(command) > 200:
                command = command[:197] + "..."
            self.recovery_tree.insert("", "end", iid=str(i), values=(item.get("date", "") or "—", item.get("time", "") or "—", self.localize_kind(item.get("kind", "")), item.get("description", ""), command, item.get("source", "")))
        if self.lang == "en":
            self.recovery_empty_var.set(f"{len(rows)} trace(s) displayed. These are clues, not guaranteed recovered commands." if rows else self.T("no_recovery"))
        elif self.lang == "uk":
            self.recovery_empty_var.set(f"Показано слідів: {len(rows)}. Це ознаки, а не гарантовано відновлені команди." if rows else self.T("no_recovery"))
        else:
            self.recovery_empty_var.set(f"Показано следов: {len(rows)}. Это признаки, а не гарантированно восстановленные команды." if rows else self.T("no_recovery"))

    def _open_recovery_event(self, _event: Any = None) -> None:
        selected = self.recovery_tree.selection()
        if not selected:
            return
        try:
            item = self._last_recovery_rows[int(selected[0])]
        except Exception:
            return
        self._select_app_tab(self.history_tab)
        self.search_var.set(str(item.get("command", "") or item.get("description", ""))[:50])
        self.apply_filter()

    def run_deep_scan(self) -> None:
        if getattr(self, "scanning", False):
            message = {"ru": "Сканирование уже выполняется. Дождитесь его завершения перед глубоким поиском.", "en": "A scan is already running. Wait for it to finish before starting a deep scan.", "uk": "Сканування вже триває. Дочекайтеся завершення перед глибоким пошуком."}[self.lang]
            messagebox.showinfo(self.T("tab_recovery"), message)
            return
        self.deep_scan_var.set(True)
        self.start_scan()

    def refresh_processes(self) -> None:
        if getattr(self, "process_scanning", False):
            return
        self.process_scanning = True
        self.process_status_var.set(self.T("scanning"))
        def worker() -> None:
            rows, warnings = get_running_python_related_processes()
            self.process_queue.put((rows, warnings))
        threading.Thread(target=worker, daemon=True).start()
        self.root.after(150, self.poll_processes)

    def poll_processes(self) -> None:
        try:
            rows, warnings = self.process_queue.get_nowait()
        except queue.Empty:
            if getattr(self, "process_scanning", False):
                self.root.after(150, self.poll_processes)
            return
        self.process_scanning = False
        self.process_rows = rows
        self.process_tree.delete(*self.process_tree.get_children())
        for i, row in enumerate(rows):
            self.process_tree.insert("", "end", iid=str(i), values=(row.get("name", ""), row.get("pid", ""), row.get("parent_pid", ""), row.get("started", ""), row.get("path", ""), row.get("command_line", "")))
        self.process_status_var.set(self.T("process_count", n=len(rows)))
        if warnings and not rows:
            self.process_status_var.set(self.T("process_unavailable") + ": " + warnings[0])
        if hasattr(self, "lineage_tree"):
            self.render_lineage()

    def add_folder_to_catalog(self) -> None:
        folder = filedialog.askdirectory(title=self.T("choose_folder"))
        if not folder:
            return
        root_path = Path(folder)
        self.status_var.set(self.T("scanning"))
        def worker() -> None:
            rows: dict[str, dict[str, Any]] = {}
            seen = 0
            skip = PYTHON_SOURCE_SKIP_DIRS
            for current, dirs, files in os.walk(root_path):
                depth = len(Path(current).relative_to(root_path).parts)
                if depth >= 16:
                    dirs[:] = []
                else:
                    dirs[:] = [d for d in dirs if d.casefold() not in skip and not d.startswith(".")]
                for name in files:
                    seen += 1
                    if seen > MAX_SOURCE_SCAN_FILES:
                        break
                    if Path(name).suffix.casefold() not in PYTHON_SOURCE_EXTENSIONS:
                        continue
                    path = Path(current) / name
                    try:
                        if path.is_symlink():
                            continue
                        st = path.stat()
                        rows[str(path.resolve()).casefold()] = {"path": str(path), "name": path.name, "extension": path.suffix.casefold(), "size_bytes": st.st_size, "size_display": f"{st.st_size / 1024:.1f} KB", "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"), "root": str(root_path), "preview_available": st.st_size <= MAX_SOURCE_PREVIEW_BYTES}
                    except OSError:
                        continue
                if seen > MAX_SOURCE_SCAN_FILES:
                    break
            self.folder_queue.put(("folder", list(rows.values()), str(root_path)))
        threading.Thread(target=worker, daemon=True).start()
        self.root.after(200, self.poll_folder_add)

    def poll_folder_add(self) -> None:
        try:
            payload = self.folder_queue.get_nowait()
        except queue.Empty:
            self.root.after(200, self.poll_folder_add)
            return
        if payload and payload[0] == "folder":
            _, rows, root_path = payload
            merged = {str(x.get("path", "")).casefold(): x for x in self.python_files}
            merged.update({str(x.get("path", "")).casefold(): x for x in rows})
            self.python_files = sorted(merged.values(), key=lambda x: x.get("modified_local", ""), reverse=True)
            self.apply_file_filter()
            self.status_var.set(f"{len(rows)} file(s) indexed from {root_path}" if self.lang == "en" else f"Добавлено файлов: {len(rows)} • {root_path}")
        else:
            return

    def _snapshot_dir_for(self, path: Path) -> Path:
        digest = hashlib.sha256(str(path.resolve()).casefold().encode("utf-8", errors="replace")).hexdigest()
        return self.snapshot_root / digest

    def save_file_snapshot(self) -> None:
        item = self.selected_python_file()
        if not item:
            messagebox.showinfo(self.T("snapshot"), self.T("no_selection"))
            return
        path = Path(item.get("path", ""))
        try:
            if path.stat().st_size > MAX_SOURCE_PREVIEW_BYTES:
                messagebox.showwarning(self.T("snapshot"), "File is over the 3 MiB snapshot limit." if self.lang == "en" else "Файл больше лимита снимка 3 МБ.")
                return
            folder = self._snapshot_dir_for(path)
            folder.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            destination = folder / f"{stamp}_{path.name}"
            shutil.copy2(path, destination)
            index_path = folder / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8")) if index_path.exists() else []
            index.append({"path": str(path), "snapshot": str(destination), "created": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"), "sha256": file_metadata(destination).get("sha256")})
            index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
            messagebox.showinfo(self.T("snapshot"), self.T("snapshot_saved"))
        except Exception as exc:
            messagebox.showerror(self.T("snapshot"), str(exc))

    def compare_file_snapshot(self) -> None:
        item = self.selected_python_file()
        if not item:
            messagebox.showinfo(self.T("compare"), self.T("no_selection"))
            return
        path = Path(item.get("path", ""))
        index_path = self._snapshot_dir_for(path) / "index.json"
        if not index_path.exists():
            messagebox.showinfo(self.T("compare"), self.T("no_snapshot"))
            return
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
            latest = index[-1]
            old_text = Path(latest["snapshot"]).read_text(encoding="utf-8", errors="replace").splitlines(True)
            new_text = path.read_text(encoding="utf-8", errors="replace").splitlines(True)
            diff = "".join(difflib.unified_diff(old_text, new_text, fromfile="Saved snapshot", tofile=str(path), n=3)) or ("No changes." if self.lang == "en" else "Изменений нет.")
            win = tk.Toplevel(self.root)
            win.title(self.T("diff_title"))
            win.geometry("1000x700")
            box = tk.Text(win, wrap="none", font=("Consolas", 9), background="#fbfbfb")
            sy = ttk.Scrollbar(win, orient="vertical", command=box.yview)
            sx = ttk.Scrollbar(win, orient="horizontal", command=box.xview)
            box.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
            box.grid(row=0, column=0, sticky="nsew")
            sy.grid(row=0, column=1, sticky="ns")
            sx.grid(row=1, column=0, sticky="ew")
            win.rowconfigure(0, weight=1)
            win.columnconfigure(0, weight=1)
            box.insert("1.0", diff)
            box.configure(state="disabled")
        except Exception as exc:
            messagebox.showerror(self.T("compare"), str(exc))

    def _session_data_dir(self) -> Path:
        folder = app_data_dir() / "sessions"
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    def start_session_recording(self) -> None:
        if self.session_active:
            return
        if not messagebox.askyesno(self.T("session_start"), self.T("session_confirm")):
            return
        try:
            self.session_process = subprocess.Popen(
                ([sys.executable, "--pav-session-worker"] if getattr(sys, "frozen", False)
                 else [sys.executable, "-u", "-c", SESSION_WORKER_SOURCE]),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.session_id = uuid.uuid4().hex[:12]
            self.session_file = self._session_data_dir() / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.session_id}.jsonl"
            self.session_active = True
            self.session_rows = []
            self.session_state_var.set(self.T("recording_on"))
            self.session_start_button.configure(state="disabled")
            self.session_stop_button.configure(state="normal")
            self.run_code_button.configure(state="normal")
            self.session_output.configure(state="normal")
            self.session_output.delete("1.0", "end")
            self.session_output.insert("1.0", self.T("session_started") + "\n")
            self.session_output.configure(state="disabled")
            self.status_var.set(self.T("session_started"))
        except Exception as exc:
            self.session_process = None
            messagebox.showerror(self.T("console_start_error"), str(exc))

    def stop_session_recording(self) -> None:
        if self.session_process:
            try:
                self.session_process.terminate()
                self.session_process.wait(timeout=2)
            except Exception:
                try:
                    self.session_process.kill()
                except Exception:
                    pass
        self.session_process = None
        self.session_active = False
        self.session_busy = False
        if hasattr(self, "session_state_var"):
            self.session_state_var.set(self.T("recording_off"))
            self.session_start_button.configure(state="normal")
            self.session_stop_button.configure(state="disabled")
            self.run_code_button.configure(state="disabled")
        self.status_var.set(self.T("session_stopped"))

    def run_session_code(self) -> None:
        if not self.session_active or not self.session_process or not self.session_process.stdin or not self.session_process.stdout:
            return
        if self.session_busy:
            messagebox.showinfo(self.T("tab_sessions"), self.T("session_busy"))
            return
        code_text = self.session_input.get("1.0", "end-1c").strip()
        if not code_text:
            messagebox.showinfo(self.T("tab_sessions"), self.T("enter_code"))
            return
        self.session_busy = True
        self.run_code_button.configure(state="disabled")
        proc = self.session_process
        def worker() -> None:
            try:
                proc.stdin.write(json.dumps({"code": code_text}, ensure_ascii=False) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                result = json.loads(line) if line else {"status": "error", "stdout": "", "stderr": "Python worker exited without a response."}
            except Exception as exc:
                result = {"status": "error", "stdout": "", "stderr": str(exc)}
            self.session_queue.put(("session_result", code_text, result))
        threading.Thread(target=worker, daemon=True).start()
        self.root.after(100, self.poll_session_result)

    def poll_session_result(self) -> None:
        try:
            payload = self.session_queue.get_nowait()
        except queue.Empty:
            if self.session_busy:
                self.root.after(100, self.poll_session_result)
            return
        if not payload or payload[0] != "session_result":
            return
        _, source, result = payload
        self.session_busy = False
        if self.session_active:
            self.run_code_button.configure(state="normal")
        safe_stdout = str(result.get("stdout", ""))
        safe_stderr = str(result.get("stderr", ""))
        record = {
            "timestamp": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"),
            "status": result.get("status", "error"),
            "command": source,
            "stdout": safe_stdout,
            "stderr": safe_stderr,
            "interpreter": sys.executable,
            "session_id": self.session_id,
        }
        self.session_rows.append(record)
        if self.session_file:
            try:
                with self.session_file.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception as exc:
                self.status_var.set(str(exc))
        self.refresh_session_table()
        self.display_session_record(record)
        self.session_input.delete("1.0", "end")


    def refresh_session_table(self) -> None:
        if not hasattr(self, "session_tree"):
            return
        self.session_tree.delete(*self.session_tree.get_children())
        for i, row in enumerate(self.session_rows):
            command = row.get("command", "").replace("\n", " ⏎ ")
            if len(command) > 150:
                command = command[:147] + "..."
            status = row.get("status", "")
            if status == "ok":
                status = "OK" if self.lang != "uk" else "Успіх"
            elif status == "error":
                status = "Error" if self.lang == "en" else ("Помилка" if self.lang == "uk" else "Ошибка")
            self.session_tree.insert("", "end", iid=str(i), values=(row.get("timestamp", ""), status, command))

    def show_session_output(self, _event: Any = None) -> None:
        selected = self.session_tree.selection()
        if not selected:
            return
        try:
            row = self.session_rows[int(selected[0])]
        except Exception:
            return
        self.display_session_record(row)

    def display_session_record(self, row: dict[str, Any]) -> None:
        if self.lang == "en":
            input_label, output_label, error_label = "INPUT", "OUTPUT", "ERROR / TRACEBACK"
        elif self.lang == "uk":
            input_label, output_label, error_label = "ВВІД", "ВИВІД", "ПОМИЛКА / TRACEBACK"
        else:
            input_label, output_label, error_label = "ВВОД", "ВЫВОД", "ОШИБКА / TRACEBACK"
        text = f"[{row.get('timestamp', '')}]  {row.get('status', '')}\n\n{input_label}\n{row.get('command', '')}\n\n{output_label}\n{row.get('stdout', '') or '—'}"
        if row.get("stderr"):
            text += f"\n\n{error_label}\n{row.get('stderr')}"
        self.session_output.configure(state="normal")
        self.session_output.delete("1.0", "end")
        self.session_output.insert("1.0", text)
        self.session_output.configure(state="disabled")

    def load_saved_session_entries(self) -> None:
        if self.session_rows:
            return
        folder = self._session_data_dir()
        latest = sorted(folder.glob("session_*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
        if latest:
            self.session_file = latest[0]
            try:
                self.session_rows = [json.loads(line) for line in latest[0].read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
                self.refresh_session_table()
            except Exception:
                pass

    def export_evidence_bundle(self) -> None:
        if not self.events and not self.forensic_rows:
            messagebox.showinfo(self.T("evidence_bundle"), self.T("scan_first"))
            return
        destination = filedialog.asksaveasfilename(
            title=self.T("evidence_bundle"), defaultextension=".zip",
            filetypes=[("ZIP archive", "*.zip"), ("All files", "*.*")],
            initialfile="python_activity_evidence_bundle.zip",
        )
        if not destination:
            return
        report_core_events = self.events
        report_forensic_events = self.forensic_rows
        report_events = list(self.filtered) + list(report_forensic_events)
        report_sources = self.sources
        report_forensic_sources = self.forensic_sources
        originals_prompts = {
            "ru": "Добавить в ZIP копии доступных исходных файлов и экспортируемые EVTX-журналы?\nЭто может включить личные пути, имена пользователей и содержимое локальных историй. Оригиналы не изменяются.\n\nПродолжить?",
            "en": "Include copies of available source files and exportable EVTX logs in the ZIP? This may include personal paths, usernames, and local history contents. Original sources are not modified.\n\nContinue?",
            "uk": "Додати до ZIP копії доступних вихідних файлів та експортовані EVTX-журнали? Це може включати особисті шляхи, імена користувачів і вміст локальних історій. Оригінали не змінюються.\n\nПродовжити?",
        }
        include_originals = messagebox.askyesno(self.T("evidence_bundle"), originals_prompts.get(self.lang, originals_prompts["ru"]))
        original_manifest: list[dict[str, Any]] = []
        evtx_manifest: list[dict[str, Any]] = []
        payload = {
            "application": APP_NAME, "version": APP_VERSION,
            "generated_local": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"),
            "scope": "Локальный анализ только доступных источников на текущем компьютере. Отсутствие записи не доказывает отсутствие события.",
            "scan_info": (self.scan_info),
            "case_context": self._case_context_payload(),
            "artifact_sources": getattr(self, "artifact_sources", []),
            "audit_readiness": self.readiness_report,
            "coverage": self.coverage_report,
            "analysis_quality": self.analysis_quality,
            "summary": {"events_total": len(report_core_events) + len(report_forensic_events), "events_core": len(report_core_events), "events_system_trace": len(report_forensic_events), "events_in_export_view": len(report_events), "sources": len(report_sources), "system_trace_sources": len(report_forensic_sources), "warnings": len(self.warnings) + len(self.forensic_warnings)},
            "events": report_core_events, "sources": report_sources,
            "python_files": (self.python_files),
            "current_process_snapshot": (getattr(self, "process_rows", [])),
            "system_trace": {"analysis": self.forensic_scan_info, "events": report_forensic_events, "sources": report_forensic_sources},
            "signature_checks": (self.signature_checks),
            "warnings": (self.warnings + self.forensic_warnings),
            "limitations": [
                "Отчёт экспортирует точные значения без маскирования. Перед передачей проверьте команды, пути, имена пользователей и прочие данные.",
                "Текст команд внутри интерактивного Python виден только если он сохранился в истории или другой заранее включённой записи.",
                "Windows 4688/Sysmon фиксируют создание процессов, а не произвольные строки, введённые внутри уже запущенного Python.",
                "Время изменения файла не является точным временем выполнения команды.",
                "Неподтверждённые остатки не являются доказанными восстановленными командами.",
                "Перед передачей отчёта проверьте пути, имена пользователей и иные сведения о системе.",
            ],
        }
        try:
            with tempfile.TemporaryDirectory(prefix="pav_bundle_") as temp:
                work = Path(temp)
                files: dict[str, bytes] = {}
                if include_originals:
                    original_root = work / "original_artifacts"
                    original_manifest = copy_original_artifacts(report_sources + report_forensic_sources, original_root)
                    evtx_root = work / "original_event_logs"
                    evtx_manifest = export_event_logs(evtx_root)
                    payload["original_artifacts_manifest"] = original_manifest
                    payload["evtx_export_manifest"] = evtx_manifest
                else:
                    payload["original_artifacts_manifest"] = [{"status": "not_included", "note": "Пользователь не включил копии исходных файлов."}]
                    payload["evtx_export_manifest"] = [{"status": "not_included", "note": "Пользователь не включил EVTX-экспорт."}]
                json_bytes = json.dumps(payload, ensure_ascii=False, indent=2, default=str).encode("utf-8")
                files["report.json"] = json_bytes
                import io
                csv_buffer = io.StringIO(newline="")
                writer = csv.DictWriter(csv_buffer, fieldnames=["timestamp", "time_basis", "kind", "description", "command", "source", "user", "details", "time_normalization", "evidence_assessment"], extrasaction="ignore")
                writer.writeheader()
                for row in report_events:
                    export_row = dict(row)
                    for nested_key in ("details", "time_normalization", "evidence_assessment"):
                        export_row[nested_key] = json.dumps(export_row.get(nested_key, {}), ensure_ascii=False, default=str)
                    writer.writerow(export_row)
                files["events.csv"] = csv_buffer.getvalue().encode("utf-8-sig")
                html_rows = []
                for row in report_events[:20000]:
                    cells = [row.get("timestamp", ""), row.get("kind", ""), row.get("description", ""), row.get("command", ""), row.get("source", "")]
                    html_rows.append("<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in cells) + "</tr>")
                risk = (self.analysis_quality or {}).get("risk_assessment", {})
                risk_title = html.escape(str(risk.get("label", "Недостаточно данных")))
                risk_reasons = "".join("<li>" + html.escape(str(reason.get("evidence", ""))) + " — " + html.escape(str(reason.get("strength", ""))) + "</li>" for reason in risk.get("reasons", []))
                html_report = "<!doctype html><html lang='ru'><meta charset='utf-8'><title>Python Activity View</title><style>body{font-family:Segoe UI,Arial;margin:24px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #ccc;padding:6px;text-align:left;vertical-align:top;white-space:pre-wrap}th{background:#eef2f6}</style><h1>Python Activity View " + APP_VERSION + "</h1><p>Оценка: " + risk_title + "</p><p>Эвристическая оценка не является вероятностью или вердиктом; вывод зависит от доступных предварительно сохранённых источников.</p><ul>" + risk_reasons + "</ul><p>Событий в представлении: " + str(len(report_events)) + " (основные и Windows/System Trace)</p><table><thead><tr><th>Дата/время</th><th>Тип</th><th>Описание</th><th>Команда</th><th>Источник</th></tr></thead><tbody>" + "".join(html_rows) + "</tbody></table></html>"
                files["summary.html"] = html_report.encode("utf-8")
                with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                    for name, data in files.items():
                        archive.writestr(name, data)
                    if include_originals:
                        for folder_name, folder in (("original_artifacts", work / "original_artifacts"), ("original_event_logs", work / "original_event_logs")):
                            if folder.is_dir():
                                for original in folder.rglob("*"):
                                    if original.is_file():
                                        archive.write(original, f"{folder_name}/{original.relative_to(folder).as_posix()}")
            self.status_var.set(self.T("evidence_bundle_saved") + " " + destination)
            messagebox.showinfo(self.T("evidence_bundle"), self.T("evidence_bundle_saved"))
        except Exception as exc:
            messagebox.showerror(self.T("evidence_bundle"), str(exc))

    def export_html(self) -> None:
        if not self.events and not getattr(self, "forensic_rows", []) and not self.python_files:
            messagebox.showinfo(self.T("export_html"), self.T("scan_first"))
            return
        path = filedialog.asksaveasfilename(title=self.T("export_html"), defaultextension=".html", filetypes=[("HTML", "*.html"), ("All files", "*.*")], initialfile="python_activity_report.html")
        if not path:
            return
        rows = []
        html_events = list(self.filtered) + list(getattr(self, "forensic_rows", []))
        for item in html_events:
            assessment = item.get("evidence_assessment", {})
            time_info = item.get("time_normalization", {})
            cells = [item.get("timestamp", ""), time_info.get("timestamp_utc", ""), item.get("kind", ""), assessment.get("confidence", "unknown"), item.get("description", ""), item.get("command", ""), item.get("source", "")]
            rows.append("<tr>" + "".join(f"<td>{html.escape(str(v))}</td>" for v in cells) + "</tr>")
        risk = (self.analysis_quality or {}).get("risk_assessment", {})
        risk_reasons = "".join("<li>" + html.escape(str(reason.get("evidence", ""))) + "</li>" for reason in risk.get("reasons", []))
        document = """<!doctype html><html lang='en'><head><meta charset='utf-8'><title>Python Activity View</title><style>body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#202124}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #d5d9df;padding:7px;text-align:left;vertical-align:top;white-space:pre-wrap}th{background:#edf1f6}tr:nth-child(even){background:#f8f9fb}code{font-family:Consolas,monospace}</style></head><body>""" + f"<h1>Python Activity View {APP_VERSION}</h1><p>Assessment: {html.escape(str(risk.get('label', 'Insufficient data')))}</p><p>This is an explainable heuristic, not a probability or a verdict.</p><ul>{risk_reasons}</ul><h2>Case notes</h2><p><b>{html.escape(self.case_name_var.get() if hasattr(self, 'case_name_var') else '—')}</b></p><pre>{html.escape(self.case_notes_text.get('1.0', 'end-1c') if hasattr(self, 'case_notes_text') else '')}</pre><p>{len(html_events)} events (main and Windows/System Trace) • {len(self.python_files)} Python source files • Generated {html.escape(datetime.now().astimezone().isoformat())}</p><table><thead><tr><th>Source time</th><th>UTC time</th><th>Event</th><th>Evidence strength</th><th>Description</th><th>Command / content</th><th>Source</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table></body></html>"
        try:
            Path(path).write_text(document, encoding="utf-8")
            self.status_var.set(self.T("saved") + ": " + path)
        except Exception as exc:
            messagebox.showerror(self.T("export_html"), str(exc))

    def show_diagnostics(self) -> None:
        payload = {"warnings": self.warnings, "errors": self.errors, "sources": self.sources, "scan_info": self.scan_info,
                   "audit_readiness": getattr(self, "readiness_report", {}),
                   "coverage": getattr(self, "coverage_report", {}),
                   "analysis_quality": getattr(self, "analysis_quality", {}),
                   "runtime_diagnostics": collect_diagnostics(app_data_dir())}
        window = tk.Toplevel(self.root)
        title = {"ru": "Источники и предупреждения", "en": "Sources and warnings", "uk": "Джерела та попередження"}[self.lang]
        window.title(title)
        window.geometry("950x620")
        text = tk.Text(window, wrap="word", font=("Consolas", 9))
        scroll = ttk.Scrollbar(window, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.insert("1.0", json.dumps(payload, ensure_ascii=False, indent=2, default=str))
        text.configure(state="disabled")

    def show_about(self) -> None:
        if self.lang == "en":
            body = f"Python Activity View {APP_VERSION}\n\nA local viewer for saved Python / IDE / shell histories, Python source files, process snapshots and optional built-in session recording.\n\nHistorical sources are read-only. The session console is opt-in and executes code in a separate process, not a sandbox. The app does not automatically capture input from other applications."
        elif self.lang == "uk":
            body = f"Перегляд активності Python {APP_VERSION}\n\nЛокальний переглядач збереженої історії Python / IDE / терміналів, файлів Python, знімків процесів і додаткового запису у вбудованій консолі.\n\nІсторичні джерела відкриваються лише для читання. Вбудована консоль вмикається вручну та запускає код в окремому процесі, але не є пісочницею. Ввід з інших програм автоматично не перехоплюється."
        else:
            body = f"Просмотр активности Python {APP_VERSION}\n\nЛокальный просмотрщик сохранённой истории Python / IDE / терминалов, исходников Python, снимков процессов и дополнительной записи во встроенной консоли.\n\nИсторические источники доступны только для чтения. Встроенная консоль включается вручную и запускает код в отдельном процессе, но не является песочницей. Ввод из других программ автоматически не перехватывается."
        messagebox.showinfo(self.T("menu_about"), body)

    def close_application(self) -> None:
        if self.session_active:
            self.stop_session_recording()
        try:
            if hasattr(self, "case_notes_text"):
                payload = self._current_case_payload()
                append_case_audit(payload, "application_closed", {"evidence_count": len(payload.get("evidence", []))})
                persist_case_payload(payload, Path(getattr(self, "active_case_file", self.case_notes_file)))
                self.case_payload = payload
            self.settings["window_geometry"] = self.root.geometry()
            self.settings_path.parent.mkdir(parents=True, exist_ok=True)
            self.settings_path.write_text(json.dumps(self.settings, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass
        self.root.destroy()


def main() -> int:
    # In a PyInstaller one-file build, start the optional built-in console
    # worker by re-entering this executable in a private pipe protocol mode.
    # This avoids trying to invoke a Python interpreter that is not installed
    # on the inspected computer.
    if "--pav-session-worker" in sys.argv[1:]:
        namespace = {"__name__": "__main__"}
        exec(compile(SESSION_WORKER_SOURCE, "<PAV session worker>", "exec"), namespace, namespace)
        return 0

    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument(
        "--windows-events", action="store_true",
        help="Включить чтение Windows Security 4688 и PowerShell Operational 4103/4104 при старте",
    )
    parser.add_argument(
        "--deep-scan", action="store_true",
        help="Включить расширенный поиск по профилю, логам, архивам и SQLite (медленно)",
    )
    args = parser.parse_args()

    if os.name != "nt":
        print("Предупреждение: программа рассчитана на Windows; часть источников будет недоступна.")

    # Opt-in only: when enabled in settings, ask Windows UAC at each normal
    # startup until an elevated instance is running. Cancellation falls back
    # to the ordinary, non-elevated app.
    if os.name == "nt" and load_auto_admin_setting() and not is_windows_admin():
        elevated, _code = request_windows_elevation(sys.argv[1:])
        if elevated:
            return 0

    root = tk.Tk()
    try:
        style = ttk.Style(root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    app = PythonActivityViewPro(root, include_windows_events=args.windows_events)
    app.deep_scan_var.set(args.deep_scan)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
