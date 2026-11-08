from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
from pav_encoding import decode_text_bytes
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

APP_VERSION = "3.4.1"

# These checks are read-only. A current setting says nothing conclusive about
# whether it was enabled at the time of an earlier event.
EVENT_CHANNELS = [
    ("Security", "Windows Security"),
    ("System", "Windows System"),
    ("Application", "Windows Application"),
    ("Microsoft-Windows-PowerShell/Operational", "PowerShell Operational"),
    ("Microsoft-Windows-Sysmon/Operational", "Sysmon Operational"),
    ("Microsoft-Windows-Windows Defender/Operational", "Defender Operational"),
    ("Microsoft-Windows-TaskScheduler/Operational", "Task Scheduler Operational"),
    ("Microsoft-Windows-WMI-Activity/Operational", "WMI Activity Operational"),
]

AUDIT_SUBCATEGORIES = [
    ("{0CCE922B-69AE-11D9-BED3-505054503030}", "Process Creation"),
    ("{0CCE922C-69AE-11D9-BED3-505054503030}", "Process Termination"),
    ("{0CCE922D-69AE-11D9-BED3-505054503030}", "File System access auditing"),
]


def _run_readonly(args: list[str], timeout: int = 8) -> tuple[int | None, str, str]:
    try:
        cp = subprocess.run(
            args, capture_output=True, text=False,
            timeout=timeout, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout, _stdout_encoding = decode_text_bytes(cp.stdout or b"", prefer_oem=True)
        stderr, _stderr_encoding = decode_text_bytes(cp.stderr or b"", prefer_oem=True)
        return cp.returncode, stdout.strip(), stderr.strip()
    except subprocess.TimeoutExpired as exc:
        raw_stdout = exc.stdout if isinstance(exc.stdout, bytes) else str(exc.stdout or "").encode("utf-8", errors="replace")
        timeout_text, _ = decode_text_bytes(raw_stdout, prefer_oem=True)
        return None, timeout_text[:2000], "timeout"
    except FileNotFoundError as exc:
        return None, "", f"not_found: {exc}"
    except Exception as exc:
        return None, "", f"error: {exc}"


def _is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _status_from_auditpol(text: str, rc: int | None) -> tuple[str, str]:
    if rc != 0:
        return ("inaccessible" if rc not in (None, 0) else "unknown", text[:1200])
    low = text.casefold()
    disabled_markers = ("no auditing", "нет аудита", "аудит не ведется", "аудит не ведётся", "без аудита", "не здійснюється аудит")
    enabled_markers = ("success", "failure", "успех", "сбой", "успіш", "невдач", "у разі успіху", "у разі невдачі")
    if any(marker in low for marker in disabled_markers):
        return "disabled", text[:1200]
    if any(marker in low for marker in enabled_markers):
        return "enabled", text[:1200]
    return "unknown", text[:1200]


def _registry_dword(hive_name: str, subkey: str, value_name: str) -> tuple[int | None, str]:
    if os.name != "nt":
        return None, "Требуется Windows"
    try:
        import winreg
        hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
        if value_type not in (winreg.REG_DWORD, winreg.REG_QWORD):
            return None, f"Значение имеет тип {value_type}, ожидался DWORD"
        return int(value), "Значение прочитано из реестра (только чтение)"
    except FileNotFoundError:
        return None, "Параметр не найден"
    except PermissionError as exc:
        return None, f"Нет доступа: {exc}"
    except Exception as exc:
        return None, str(exc)


def windows_compatibility() -> dict[str, Any]:
    """Return environment capability facts; never changes system settings."""
    is_windows = os.name == "nt"
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "python_bits": 64 if sys.maxsize > 2**32 else 32,
        "is_windows": is_windows,
        "is_admin": _is_admin(),
        "checked_local_time": datetime.now().astimezone().isoformat(timespec="seconds"),
        "capabilities": [],
    }
    capabilities = []
    if not is_windows:
        capabilities.append({"name": "Windows event logs", "status": "not_applicable", "note": "Для чтения системных журналов требуется Windows."})
    else:
        for executable, label in (("wevtutil.exe", "Windows Event Utility"), ("auditpol.exe", "Audit Policy Utility"), ("powershell.exe", "Windows PowerShell"), ("fsutil.exe", "FSUtil")):
            found = shutil.which(executable) is not None
            capabilities.append({"name": label, "status": "available" if found else "not_found", "note": executable})
        capabilities.append({"name": "Administrator token", "status": "available" if info["is_admin"] else "standard_user", "note": "Права текущего процесса; не гарантируют доступ ко всем источникам."})
        try:
            import tkinter
            capabilities.append({"name": "Tkinter", "status": "available", "note": f"Tcl/Tk {tkinter.TkVersion}"})
        except Exception as exc:
            capabilities.append({"name": "Tkinter", "status": "error", "note": str(exc)})
    info["capabilities"] = capabilities
    try:
        now = datetime.now().astimezone()
        info["timezone"] = {
            "local_name": now.tzname() or "unknown",
            "utc_offset": now.strftime("%z"),
            "iana_name": getattr(now.tzinfo, "key", None),
            "local_iso": now.isoformat(timespec="seconds"),
            "utc_iso": now.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "note": "Пояс текущей системы на момент проверки; исходные временные метки сохраняются отдельно.",
        }
    except Exception as exc:
        info["timezone"] = {"note": str(exc)}
    return info


def collect_audit_readiness(progress=None) -> dict[str, Any]:
    """Inspect whether relevant Windows audit channels/policies are currently enabled."""
    generated = datetime.now().astimezone().isoformat(timespec="seconds")
    compatibility = windows_compatibility()
    checks: list[dict[str, Any]] = []

    def add(name: str, category: str, status: str, note: str = "", raw: str = "") -> None:
        checks.append({"name": name, "category": category, "status": status, "note": note, "raw_excerpt": raw[:1600]})

    if os.name != "nt":
        for _, label in EVENT_CHANNELS:
            add(label, "Event Log channel", "not_applicable", "Требуется Windows.")
        for _, label in AUDIT_SUBCATEGORIES:
            add(label, "Audit policy", "not_applicable", "Требуется Windows.")
        add("Process command-line inclusion", "Audit policy", "not_applicable", "Требуется Windows.")
        add("PowerShell Script Block Logging", "PowerShell policy", "not_applicable", "Требуется Windows.")
    else:
        for guid, label in AUDIT_SUBCATEGORIES:
            if progress:
                progress(f"Проверяю состояние аудита: {label}")
            rc, out, err = _run_readonly(["auditpol.exe", "/get", "/subcategory:" + guid], timeout=6)
            text = out or err
            status, note = _status_from_auditpol(text, rc)
            add(label, "Audit policy", status, note or ("Не удалось определить настройку по выводу Windows."), text)

        cmdline_value, cmdline_note = _registry_dword(
            "HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            "ProcessCreationIncludeCmdLine_Enabled",
        )
        add("Process command-line inclusion", "Audit policy",
            "enabled" if cmdline_value == 1 else ("disabled" if cmdline_value == 0 else ("not_configured" if cmdline_value is None and "не найден" in cmdline_note.casefold() else "unknown")),
            cmdline_note + (f"; значение={cmdline_value}" if cmdline_value is not None else ""))

        sb_value, sb_note = _registry_dword(
            "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            "EnableScriptBlockLogging",
        )
        add("PowerShell Script Block Logging", "PowerShell policy",
            "enabled" if sb_value == 1 else ("disabled" if sb_value == 0 else ("not_configured" if sb_value is None and "не найден" in sb_note.casefold() else "unknown")),
            sb_note + (f"; значение={sb_value}" if sb_value is not None else ""))

        module_value, module_note = _registry_dword(
            "HKLM", r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
            "EnableModuleLogging",
        )
        add("PowerShell Module Logging", "PowerShell policy",
            "enabled" if module_value == 1 else ("disabled" if module_value == 0 else ("not_configured" if module_value is None and "не найден" in module_note.casefold() else "unknown")),
            module_note + (f"; значение={module_value}" if module_value is not None else ""))

        for channel, label in EVENT_CHANNELS:
            if progress:
                progress(f"Проверяю канал журнала: {label}")
            rc, out, err = _run_readonly(["wevtutil.exe", "gl", channel], timeout=8)
            raw = out or err
            match = re.search(r"(?im)^\s*enabled\s*:\s*(true|false)\s*$", out)
            if rc == 0 and match:
                status = "enabled" if match.group(1).casefold() == "true" else "disabled"
                note = "Состояние канала на момент проверки; не доказывает его состояние в прошлом."
            elif rc == 0:
                status, note = "unknown", "Канал существует, но состояние enabled не удалось разобрать."
            elif "not_found" in err:
                status, note = "not_found", err
            elif rc is None or "access" in err.casefold() or "доступ" in err.casefold():
                status, note = "inaccessible", err or "Тайм-аут или нет доступа."
            else:
                status, note = "not_found", err or "Канал не найден или недоступен."
            add(label, "Event Log channel", status, note, raw)

        # Sysmon service is a separate indicator; it does not prove that every
        # relevant Sysmon event type is configured.
        rc, out, err = _run_readonly(["sc.exe", "query", "Sysmon64"], timeout=5)
        if rc != 0:
            rc2, out2, err2 = _run_readonly(["sc.exe", "query", "Sysmon"], timeout=5)
            if rc2 == 0:
                rc, out, err = rc2, out2, err2
        sysmon_text = out or err
        sysmon_status = "available" if rc == 0 and "RUNNING" in sysmon_text.upper() else ("disabled" if rc == 0 else "not_found")
        add("Sysmon service", "Service", sysmon_status, "Наличие/состояние службы; конфигурацию событий нужно проверять отдельно.", sysmon_text)

    counts: dict[str, int] = {}
    for row in checks:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return {
        "generated_local": generated,
        "environment": compatibility,
        "checks": checks,
        "status_counts": counts,
        "note": "Это снимок текущей конфигурации. Он не показывает, была ли настройка включена в прошлом, и не включает аудит автоматически.",
    }


def normalize_event_timestamp(row: dict[str, Any]) -> dict[str, Any]:
    """Add UTC/local representations while preserving the source timestamp verbatim."""
    raw = str(row.get("timestamp", "") or "").strip()
    result = {
        "source_timestamp": raw,
        "timestamp_utc": "",
        "timestamp_local": "",
        "timezone_name": "",
        "timezone_offset": "",
        "timestamp_interpretation": "missing",
        "timestamp_precision": "unknown",
    }
    if not raw:
        row["time_normalization"] = result
        return row
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        had_timezone = dt.tzinfo is not None and dt.utcoffset() is not None
        if not had_timezone:
            # For naive source timestamps the system-local interpretation is only
            # an explicit assumption; never overwrite the original value.
            dt = dt.astimezone()
            result["timestamp_interpretation"] = "assumed_system_local_no_source_offset"
        else:
            result["timestamp_interpretation"] = "source_offset_present"
        local_dt = dt.astimezone()
        utc_dt = dt.astimezone(timezone.utc)
        result.update({
            "timestamp_utc": utc_dt.isoformat(timespec="microseconds" if dt.microsecond else "seconds"),
            "timestamp_local": local_dt.isoformat(timespec="microseconds" if dt.microsecond else "seconds"),
            "timezone_name": local_dt.tzname() or "unknown",
            "timezone_offset": local_dt.strftime("%z"),
            "timestamp_precision": "fractional_seconds" if dt.microsecond else "seconds",
        })
    except Exception as exc:
        result["timestamp_interpretation"] = "unparsed_source_value"
        result["parse_note"] = str(exc)
    row["time_normalization"] = result
    return row


def assess_event_evidence(row: dict[str, Any]) -> dict[str, Any]:
    """Describe what a record supports, without turning clues into conclusions."""
    kind = str(row.get("kind", "")).casefold()
    source = str(row.get("source", "")).casefold()
    description = str(row.get("description", "")).casefold()
    command = str(row.get("command", "") or "").strip()
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    event_id = details.get("event_id")
    fields = details.get("fields") if isinstance(details.get("fields"), dict) else {}

    result = {
        "evidence_class": "context_only",
        "confidence": "unknown",
        "what_it_supports": "Запись требует ручной интерпретации; сама по себе не подтверждает выполнение конкретной команды.",
        "execution_proven": False,
        "limitations": [],
    }
    if kind == "browser_visit":
        result.update({
            "evidence_class": "recorded_browser_visit",
            "confidence": "high",
            "what_it_supports": "Локальная база браузера содержит запись о посещении URL в указанное время. Это не доказывает загрузку, запуск файла или использование программного обеспечения.",
            "execution_proven": False,
            "limitations": ["История может быть неполной, синхронизированной или импортированной.", "Само посещение сайта не подтверждает использование распространяемого там ПО."],
        })
    elif kind == "browser_download":
        result.update({
            "evidence_class": "recorded_browser_download",
            "confidence": "high",
            "what_it_supports": "База браузера содержит запись о загрузке/попытке загрузки. Наличие записи не доказывает, что файл был запущен или успешно использован.",
            "execution_proven": False,
            "limitations": ["Запись загрузки может относиться к прерванной загрузке либо к файлу, впоследствии удалённому.", "Путь назначения и состояние зависят от версии браузера и доступной схемы SQLite."],
        })
    elif any(token in kind + " " + source + " " + description for token in ("residual", "остаток", "freelist", "wal fragment", "восстановлен")):
        result.update({
            "evidence_class": "recovered_fragment",
            "confidence": "low",
            "what_it_supports": "Обнаружен фрагмент или остаточная структура данных; связь с выполнением команды не подтверждена.",
            "limitations": ["Фрагмент может быть неполным, повторно используемым или не относиться к исполненной команде."],
        })
    elif event_id in (4688, 1) or "process creation" in description or "запуск процесса" in description or "создание процесса" in description:
        result.update({
            "evidence_class": "recorded_process_start",
            "confidence": "high",
            "what_it_supports": "Журнал содержит запись о создании процесса. Это не доказывает ввод команд внутри уже запущенного интерпретатора.",
            "execution_proven": True,
            "limitations": ["Текст командной строки может отсутствовать, если аудит не был настроен заранее."],
        })
    elif event_id in (4689, 5) or "завершение процесса" in description or "process termination" in description:
        result.update({
            "evidence_class": "recorded_process_end",
            "confidence": "high",
            "what_it_supports": "Журнал содержит запись о завершении процесса.",
            "execution_proven": True,
        })
    elif command and any(token in source + " " + kind for token in ("history", "истори", "console", "консол", "ipython", "jupyter", "transcript", "транскрипт")):
        result.update({
            "evidence_class": "preserved_command_text",
            "confidence": "high",
            "what_it_supports": "Текст команды найден в сохранённой истории/транскрипте. Запись подтверждает наличие текста в этом источнике; успешный результат выполнения может требовать отдельного подтверждения.",
            "execution_proven": False,
            "limitations": ["Наличие строки в истории само по себе не подтверждает успешное завершение команды."],
        })
    elif "prefetch" in kind or "prefetch" in source:
        result.update({
            "evidence_class": "execution_supporting_artifact",
            "confidence": "medium",
            "what_it_supports": "Найден Prefetch-артефакт, согласующийся с запуском приложения; он не задаёт точную временную метку каждого запуска.",
            "limitations": ["Время изменения файла не равно точному времени запуска."],
        })
    elif any(token in kind + " " + description for token in ("inventory", "инвентаризац", "автозапуск", "scheduled task", "задача планировщика", "служба windows")):
        result.update({
            "evidence_class": "configuration_snapshot",
            "confidence": "context_only",
            "what_it_supports": "Обнаружена текущая конфигурация системы; это не доказывает исторический запуск.",
        })
    elif any(token in kind + " " + description for token in ("active process", "активный процесс", "current process", "текущий процесс")):
        result.update({
            "evidence_class": "current_process_snapshot",
            "confidence": "medium",
            "what_it_supports": "Процесс присутствовал в системе во время снимка; это не историческая запись.",
        })
    elif command:
        result.update({
            "evidence_class": "command_or_event_text",
            "confidence": "medium",
            "what_it_supports": "Источник содержит текст, похожий на команду или описание события. Семантику и факт выполнения следует оценить отдельно.",
        })
    row["evidence_assessment"] = result
    normalize_event_timestamp(row)
    return row


def _parse_pid(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    try:
        number = int(text, 16) if text.lower().startswith("0x") else int(text)
        return str(number)
    except Exception:
        return text.casefold()


def _event_fields(row: dict[str, Any]) -> dict[str, Any]:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    fields = details.get("fields") if isinstance(details.get("fields"), dict) else {}
    merged = dict(details)
    merged.update(fields)
    return merged


def correlate_events(events: list[dict[str, Any]], max_links: int = 1000) -> list[dict[str, Any]]:
    """Create conservative links using explicit process/session identifiers only."""
    links: list[dict[str, Any]] = []
    starts: list[tuple[int, dict[str, Any], str, str, str]] = []
    ends: list[tuple[int, dict[str, Any], str, str]] = []
    by_pid_start: dict[str, list[tuple[int, dict[str, Any], str, str, str]]] = {}
    for index, row in enumerate(events):
        fields = _event_fields(row)
        pid = _parse_pid(fields.get("NewProcessId") or fields.get("ProcessId") or fields.get("ProcessID") or fields.get("process_id") or fields.get("pid"))
        parent = _parse_pid(fields.get("ProcessId") if fields.get("NewProcessId") else fields.get("ParentProcessId") or fields.get("parent_process_id") or fields.get("parent_pid"))
        guid = str(fields.get("ProcessGuid") or fields.get("ProcessGUID") or fields.get("process_guid") or "").casefold()
        ppid = _parse_pid(fields.get("ParentProcessId") or fields.get("parent_process_id") or fields.get("parent_pid"))
        eid = fields.get("event_id")
        kind = str(row.get("kind", "")).casefold()
        desc = str(row.get("description", "")).casefold()
        is_start = eid in (4688, 1) or "создание процесса" in desc or "process started" in desc or "запуск процесса" in desc
        is_end = eid in (4689, 5) or "завершение процесса" in desc or "process terminated" in desc
        if is_start and pid:
            if not ppid and fields.get("NewProcessId"):
                ppid = _parse_pid(fields.get("ProcessId"))
            item = (index, row, pid, ppid, guid)
            starts.append(item)
            by_pid_start.setdefault(pid, []).append(item)
        elif is_end and pid:
            ends.append((index, row, pid, guid))

    for index, row, pid, ppid, guid in starts:
        if ppid:
            candidates = by_pid_start.get(ppid, [])
            child_time = _time_epoch(row.get("timestamp"))
            for parent_index, parent_row, parent_pid, _, parent_guid in candidates:
                if parent_index == index:
                    continue
                parent_time = _time_epoch(parent_row.get("timestamp"))
                delta = abs(child_time - parent_time) if child_time is not None and parent_time is not None else None
                if delta is not None and delta <= 3600 and parent_index < index:
                    links.append({
                        "relation": "parent_child_process",
                        "from_event_index": parent_index,
                        "to_event_index": index,
                        "basis": "Parent PID matches child ParentProcessId; timestamps within one hour.",
                        "confidence": "high",
                        "time_delta_seconds": delta,
                    })
                    break
        if len(links) >= max_links:
            return links

    for end_index, end_row, end_pid, end_guid in ends:
        end_time = _time_epoch(end_row.get("timestamp"))
        candidates = by_pid_start.get(end_pid, [])
        for start_index, start_row, _, _, start_guid in reversed(candidates):
            start_time = _time_epoch(start_row.get("timestamp"))
            if end_guid and start_guid and end_guid == start_guid:
                delta = abs(end_time - start_time) if end_time is not None and start_time is not None else None
                links.append({"relation": "same_process_start_end", "from_event_index": start_index,
                              "to_event_index": end_index, "basis": "Exact ProcessGuid match.",
                              "confidence": "high", "time_delta_seconds": delta})
                break
            if start_time is not None and end_time is not None and 0 <= end_time - start_time <= 7 * 86400:
                # PID-only join is weaker due to PID reuse; keep the time window explicit.
                links.append({"relation": "same_pid_possible_start_end", "from_event_index": start_index,
                              "to_event_index": end_index, "basis": "PID match only; PID reuse is possible.",
                              "confidence": "low", "time_delta_seconds": end_time - start_time})
                break
        if len(links) >= max_links:
            break

    # Session IDs are useful for grouping saved REPL/IPython records. This is a
    # source/session grouping, not a claim that one command caused another.
    groups: dict[tuple[str, str], list[int]] = {}
    for index, row in enumerate(events):
        fields = _event_fields(row)
        session = str(fields.get("session") or fields.get("session_id") or "").strip()
        source = str(row.get("source", "")).strip()
        if session and source:
            groups.setdefault((source.casefold(), session), []).append(index)
    for (source, session), indexes in groups.items():
        if len(indexes) < 2:
            continue
        indexes.sort(key=lambda i: _time_epoch(events[i].get("timestamp")) or 0)
        for first, second in zip(indexes, indexes[1:]):
            links.append({"relation": "same_saved_session", "from_event_index": first,
                          "to_event_index": second, "basis": "Same source path and session ID in stored metadata.",
                          "confidence": "high", "time_delta_seconds": _time_difference(events[first].get("timestamp"), events[second].get("timestamp"))})
            if len(links) >= max_links:
                return links
    return links


def _time_epoch(value: Any) -> float | None:
    try:
        text = str(value or "").strip()
        if not text:
            return None
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return dt.timestamp()
    except Exception:
        return None


def _time_difference(a: Any, b: Any) -> float | None:
    x, y = _time_epoch(a), _time_epoch(b)
    return abs(x - y) if x is not None and y is not None else None


def build_scan_coverage(
    source_records: list[dict[str, Any]],
    readiness: dict[str, Any] | None,
    errors: list[str] | None = None,
    warnings: list[str] | None = None,
    events: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Summarize what was examined, found, inaccessible, or not configured."""
    source_records = source_records or []
    errors = errors or []
    warnings = warnings or []
    events = events or []
    statuses: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for source in source_records:
        status = str(source.get("status", "observed" if source.get("path") else "unknown"))
        statuses[status] = statuses.get(status, 0) + 1
        rows.append({
            "name": source.get("type", "Источник"),
            "path": source.get("path", ""),
            "status": status,
            "records": source.get("records", source.get("matched_events", source.get("matched_files", 0))),
            "note": source.get("note", ""),
            "basis": "Наблюдение из записи сканера; отсутствие записи не означает отсутствия активности.",
        })
    for check in (readiness or {}).get("checks", []):
        status = str(check.get("status", "unknown"))
        statuses[status] = statuses.get(status, 0) + 1
        rows.append({
            "name": check.get("name", "Проверка"), "path": "", "status": status,
            "records": "", "note": check.get("note", ""),
            "basis": "Снимок текущей конфигурации Windows, а не историческая конфигурация.",
        })
    # Never produce a deceptive single percentage: many checks are not applicable,
    # disabled by default, or require preconfiguration.
    unavailable = sum(statuses.get(s, 0) for s in ("inaccessible", "error", "timeout", "not_found"))
    disabled = statuses.get("disabled", 0) + statuses.get("not_configured", 0)
    unknown = statuses.get("unknown", 0)
    not_applicable = statuses.get("not_applicable", 0)
    known = len(rows) - unknown - not_applicable
    if rows and not_applicable == len(rows):
        overall = "not_applicable"
    elif errors or unavailable or disabled:
        overall = "incomplete"
    elif unknown:
        overall = "undetermined"
    elif rows:
        overall = "reviewed_known_sources"
    else:
        overall = "not_run"
    return {
        "overall": overall,
        "checks_total": len(rows),
        "checks_with_known_result": known,
        "unavailable_or_missing": unavailable,
        "disabled_now": disabled,
        "unknown": unknown,
        "not_applicable": not_applicable,
        "events_count": len(events),
        "scanner_errors": len(errors),
        "scanner_warnings": len(warnings),
        "items": rows,
        "interpretation": "Это полнота проверки перечисленных источников, а не процент вероятности обнаружения. Проверяются только источники, которые включены в область сканирования и доступны текущему пользователю.",
    }


def attach_analysis(events: list[dict[str, Any]]) -> dict[str, Any]:
    for row in events:
        assess_event_evidence(row)
    correlations = correlate_events(events)
    counts: dict[str, int] = {}
    confidence_counts: dict[str, int] = {}
    for row in events:
        assessment = row.get("evidence_assessment", {})
        evidence_class = str(assessment.get("evidence_class", "unknown"))
        confidence = str(assessment.get("confidence", "unknown"))
        counts[evidence_class] = counts.get(evidence_class, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
    naive_times = sum(1 for row in events if row.get("time_normalization", {}).get("timestamp_interpretation") == "assumed_system_local_no_source_offset")
    return {
        "evidence_class_counts": counts,
        "confidence_counts": confidence_counts,
        "correlations_count": len(correlations),
        "correlations": correlations,
        "timestamps_assumed_local": naive_times,
        "note": "Оценка описывает силу конкретного источника и пределы того, что он подтверждает. Она не является вероятностью виновности пользователя.",
    }


def copy_original_artifacts(
    source_records: Iterable[dict[str, Any]],
    destination: Path,
    per_file_limit: int = 20 * 1024 * 1024,
    total_limit: int = 100 * 1024 * 1024,
) -> list[dict[str, Any]]:
    """Copy bounded, existing source artifacts byte-for-byte to an export folder."""
    destination.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    copied_total = 0
    seen: set[str] = set()
    allowed_suffixes = {".txt", ".log", ".sqlite", ".sqlite-wal", ".sqlite-shm", ".wal", ".shm", ".db", ".ipynb", ".json", ".xml", ".zip", ".gz", ".py", ".pyw", ".pyi", ".pf", ".evtx", ".hve", ".dat"}
    for item in source_records:
        raw_path = str(item.get("path", "") or "")
        if not raw_path:
            continue
        try:
            source = Path(raw_path)
            key = str(source.resolve()).casefold()
            if key in seen:
                continue
            seen.add(key)
            if not source.is_file():
                continue
            size = source.stat().st_size
            if source.suffix.casefold() not in allowed_suffixes:
                manifest.append({"source_path": raw_path, "status": "skipped", "reason": "Тип файла не входит в ограниченный список форматов."})
                continue
            if size > per_file_limit:
                manifest.append({"source_path": raw_path, "status": "skipped", "reason": f"Файл превышает лимит {per_file_limit} байт.", "size_bytes": size})
                continue
            if copied_total + size > total_limit:
                manifest.append({"source_path": raw_path, "status": "skipped", "reason": f"Достигнут общий лимит {total_limit} байт.", "size_bytes": size})
                continue
            safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", source.name)[:90] or "artifact.bin"
            prefix = hashlib.sha256(raw_path.encode("utf-8", errors="replace")).hexdigest()[:10]
            target = destination / f"{prefix}_{safe_name}"
            source_digest = hashlib.sha256()
            with source.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    source_digest.update(chunk)
            shutil.copy2(source, target)
            digest = hashlib.sha256()
            with target.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            source_hash = source_digest.hexdigest()
            copy_hash = digest.hexdigest()
            copied_total += size
            manifest.append({
                "source_path": raw_path, "archive_path": str(target.name), "status": "copied" if source_hash == copy_hash else "copy_changed_during_read",
                "size_bytes": size, "sha256_source_before_copy": source_hash, "sha256_of_copy": copy_hash,
                "modified_source_local": datetime.fromtimestamp(source.stat().st_mtime).astimezone().isoformat(timespec="seconds"),
            })
        except PermissionError as exc:
            manifest.append({"source_path": raw_path, "status": "inaccessible", "reason": str(exc)})
        except Exception as exc:
            manifest.append({"source_path": raw_path, "status": "error", "reason": str(exc)})
    return manifest


def export_event_logs(destination: Path, channels: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Export selected Windows EVTX channels without clearing or changing them."""
    results: list[dict[str, Any]] = []
    if os.name != "nt":
        return [{"channel": str(c), "status": "not_applicable", "note": "Требуется Windows."} for c in channels]
    destination.mkdir(parents=True, exist_ok=True)
    selected = list(channels) or [channel for channel, _ in EVENT_CHANNELS]
    for channel in selected:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", channel)
        target = destination / f"{safe}.evtx"
        rc, out, err = _run_readonly(["wevtutil.exe", "epl", channel, str(target), "/ow:true"], timeout=45)
        if rc == 0 and target.is_file():
            size = target.stat().st_size
            if size > 50 * 1024 * 1024:
                target.unlink(missing_ok=True)
                results.append({"channel": channel, "status": "skipped", "note": "Экспорт журнала превысил лимит 50 MiB."})
            else:
                digest = hashlib.sha256()
                with target.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        digest.update(chunk)
                results.append({"channel": channel, "status": "exported", "archive_path": target.name, "size_bytes": size, "sha256_of_export": digest.hexdigest()})
        else:
            target.unlink(missing_ok=True)
            results.append({"channel": channel, "status": "inaccessible_or_failed", "note": (err or out or "wevtutil epl завершился с ошибкой")[:1200]})
    return results
