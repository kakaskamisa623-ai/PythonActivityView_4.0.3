from __future__ import annotations

"""Visible, consent-based, read-only local evidence review for Windows.

This module deliberately collects only selected AnyDesk trace events and
selected Windows event IDs. It does not record keystrokes, inspect browser
profiles, read chat content, access other Windows users' profiles, change
settings, or modify source evidence.
"""

import hashlib
import json
import os
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Callable, Any
from pav_encoding import read_text_compat, decode_text_bytes

ANYDESK_NAMES = {"ad.trace", "ad_svc.trace", "connection_trace.txt"}
TIMESTAMP_RE = re.compile(r"(?P<ts>20\d{2}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:[.,]\d{1,6})?)?)")
PYTHON_RE = re.compile(r"(?i)(?<![\w.-])(?:pythonw?|python\d+(?:\.\d+)*|py|pycharm(?:64)?|ipython|jupyter|cmd|powershell|pwsh)(?![\w.-])")
SHELL_PYTHON_COMMAND_RE = re.compile(r"""(?i)(?:^|\s|["'])(?:pythonw?|py)(?:\.exe)?(?=\s|["']|$)""")
def _local_time(raw: str) -> str:
    if not raw:
        return ""
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00").replace(",", "."))
        if dt.tzinfo is None:
            return dt.isoformat(sep=" ", timespec="seconds")
        return dt.astimezone().isoformat(sep=" ", timespec="seconds")
    except Exception:
        return raw


def _sha256(path: Path, max_bytes: int = 100 * 1024 * 1024) -> str:
    try:
        if path.stat().st_size > max_bytes:
            return "not_computed_file_over_100_MiB"
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except Exception as exc:
        return f"unavailable: {exc}"


def _file_source(path: Path) -> dict[str, Any]:
    st = path.stat()
    return {
        "type": "file",
        "path": str(path),
        "size_bytes": st.st_size,
        "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"),
        "created_or_changed_local": datetime.fromtimestamp(st.st_ctime).astimezone().isoformat(sep=" ", timespec="seconds"),
        "sha256": _sha256(path),
    }


def _event(kind: str, description: str, source: str, timestamp: str = "", time_basis: str = "", details: dict | None = None, command: str = "") -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "date": timestamp[:10] if len(timestamp) >= 10 else "",
        "time": timestamp[11:19] if len(timestamp) >= 19 else "",
        "time_basis": time_basis,
        "kind": kind,
        "description": description,
        "command": command,
        "source": source,
        "user": "",
        "details": details or {},
    }


def find_anydesk_logs() -> list[Path]:
    roots: list[Path] = []
    appdata = os.environ.get("APPDATA")
    programdata = os.environ.get("PROGRAMDATA") or os.environ.get("ProgramData")
    if appdata:
        roots.append(Path(appdata) / "AnyDesk")
    if programdata:
        roots.append(Path(programdata) / "AnyDesk")
    results: set[Path] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for current, dirs, files in os.walk(root):
            depth = len(Path(current).relative_to(root).parts)
            if depth >= 4:
                dirs[:] = []
            dirs[:] = [d for d in dirs if d.casefold() not in {"chat", "thumbnails", "cache", "temp"}]
            for filename in files:
                lower = filename.casefold()
                parent = Path(current).name.casefold()
                if lower in ANYDESK_NAMES or (lower.endswith(".trace") and (lower.startswith("ad_") or parent.startswith("ad_"))):
                    results.add(Path(current) / filename)
    return sorted(results, key=lambda p: str(p).casefold())


def _anydesk_category(line: str, filename: str) -> str:
    low = line.casefold()
    if filename.casefold() == "connection_trace.txt":
        if any(x in low for x in ("reject", "denied", "declined")):
            return "Запрос подключения отклонён"
        if any(x in low for x in ("accept", "accepted", "password", "token")):
            return "Запрос подключения принят / аутентификация"
        return "Запись о запросе подключения"
    if any(x in low for x in ("file transfer", "file_transfer", "transfer started", "transfer finished")):
        return "Событие передачи файла"
    if any(x in low for x in ("disconnect", "disconnected", "session closed", "connection closed")):
        return "Завершение соединения"
    if any(x in low for x in ("incoming", "outgoing", "connect", "connected", "session started", "new session")):
        return "Событие соединения"
    if any(x in low for x in ("authentication", "auth failed", "login failed", "password")):
        return "Событие аутентификации"
    if any(x in low for x in ("error", "failed", "failure", "warning")):
        return "Ошибка или предупреждение"
    return ""


def scan_anydesk(progress: Callable[[str], None]) -> tuple[list[dict], list[dict], list[str]]:
    events: list[dict] = []
    sources: list[dict] = []
    warnings: list[str] = []
    files = find_anydesk_logs()
    progress(f"Проверка AnyDesk: найдено файлов журналов — {len(files)} (дополнительный источник)")
    if not files:
        # AnyDesk is optional context, never a required dependency.
        sources.append({
            "type": "Optional AnyDesk traces",
            "status": "not_found",
            "note": "Дополнительный источник. Отсутствие журналов AnyDesk не влияет на анализ Python и системных событий.",
        })
        return events, sources, warnings
    for path in files:
        try:
            meta = _file_source(path)
            source_row = {"type": "AnyDesk trace", **meta, "matched_events": 0}
            sources.append(source_row)
            max_bytes = 8 * 1024 * 1024
            with path.open("rb") as stream:
                stream.seek(0, os.SEEK_END)
                size = stream.tell()
                start = max(0, size - max_bytes)
                stream.seek(start)
                raw = stream.read(max_bytes)
            if start:
                warnings.append(f"{path.name}: прочитан последний фрагмент 8 MiB; ранние части большого файла не анализировались.")
            text = raw.decode("utf-8-sig", errors="replace")
            count = 0
            for line_no, line in enumerate(text.splitlines(), 1):
                category = _anydesk_category(line, path.name)
                if not category:
                    continue
                match = TIMESTAMP_RE.search(line)
                timestamp = _local_time(match.group("ts")) if match else ""
                line_hash = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()
                events.append(_event(
                    "AnyDesk: след журнала", category, str(path), timestamp,
                    "Время из строки AnyDesk" if timestamp else "Время в строке не распознано",
                    {
                        "file_name": path.name,
                        "line_number_in_scanned_fragment": line_no,
                        "line_sha256": line_hash,
                        "source_file_sha256": meta.get("sha256", ""),
                        "note": "Текст строки, AnyDesk-ID и сетевые адреса не копируются в отчёт. Хеш исходного файла помогает проверить неизменность файла после сбора.",
                    },
                ))
                count += 1
                if count >= 1500:
                    warnings.append(f"{path.name}: достигнут лимит 1500 событий из одного файла.")
                    break
            source_row["matched_events"] = count
        except Exception as exc:
            warnings.append(f"Ошибка чтения журнала AnyDesk {path}: {exc}")
    return events, sources, warnings


def parse_event_xml(xml_text: str, log_name: str, ids: set[int]) -> list[dict]:
    """Parse wevtutil XML into normalized event rows; pure helper for tests."""
    if not xml_text.strip():
        return []
    clean_xml = re.sub(r"^\s*<\?xml[^>]*\?>", "", xml_text, count=1, flags=re.IGNORECASE | re.DOTALL).strip()
    if clean_xml.startswith("<Events") or clean_xml.startswith("<ns0:Events"):
        root = ET.fromstring(clean_xml)
    else:
        root = ET.fromstring("<Events>" + clean_xml + "</Events>")
    labels = {
        104: ("Журнал System очищен", "Журнал System был очищен; требуется проверка контекста."),
        1102: ("Журнал Security очищен", "Windows зарегистрировала очистку журнала Security."),
        4719: ("Изменена политика аудита", "Политика аудита безопасности была изменена."),
        1116: ("Defender обнаружил угрозу", "Defender обнаружил угрозу или потенциально нежелательное ПО."),
        1117: ("Defender выполнил действие", "Defender зарегистрировал действие в ответ на обнаружение."),
        5001: ("Изменилось состояние защиты Defender", "Изменилось состояние защиты Defender в реальном времени."),
        5007: ("Изменена конфигурация Defender", "Изменилась конфигурация Microsoft Defender."),
        4688: ("Создание процесса", "Windows зарегистрировала создание процесса."),
        4689: ("Завершение процесса", "Windows зарегистрировала завершение процесса."),
        4663: ("Доступ к объекту файловой системы", "Событие доступно только при предварительно настроенном аудите доступа к объектам."),
        7036: ("Изменение состояния службы", "Служба Windows изменила состояние."),
        7040: ("Изменён тип запуска службы", "Изменился тип запуска службы Windows."),
        7045: ("Установлена служба Windows", "Windows зарегистрировала установку службы; нужно проверить имя и путь службы."),
        6005: ("Служба журнала событий запущена", "Полезная временная отметка запуска службы журнала событий."),
        6006: ("Служба журнала событий остановлена", "Полезная временная отметка штатной остановки службы журнала событий."),
        6008: ("Предыдущее завершение Windows было неожиданным", "Системное событие указывает на неожиданное завершение работы."),
        4697: ("Установлена служба Windows (Security 4697)", "Security зарегистрировал установку службы."),
        4: ("Состояние службы Sysmon", "Sysmon зарегистрировал изменение своего состояния службы."),
        7: ("Загрузка образа (Sysmon)", "Sysmon зарегистрировал загрузку DLL/образа процессом; событие доступно только при соответствующей конфигурации."),
        16: ("Изменена конфигурация Sysmon", "Sysmon зарегистрировал изменение своей конфигурации."),
        22: ("DNS-запрос процесса (Sysmon)", "Sysmon зарегистрировал DNS-запрос процесса, если соответствующее событие включено."),
        1000: ("Сбой приложения", "Windows зарегистрировала сбой приложения."),
        1001: ("Отчёт Windows Error Reporting", "Windows зарегистрировала отчёт об ошибке."),
        1026: ("Ошибка .NET Runtime", "Windows зарегистрировала ошибку .NET Runtime."),
        400: ("Запуск движка PowerShell", "PowerShell зарегистрировал запуск движка."),
        403: ("Остановка движка PowerShell", "PowerShell зарегистрировал остановку движка."),
        600: ("Событие провайдера PowerShell", "PowerShell зарегистрировал событие провайдера."),
        4103: ("PowerShell Module Logging", "Содержимое зависит от настроек журналирования модулей."),
        4104: ("PowerShell Script Block Logging", "Содержимое блока сценария доступно, если журналирование было включено заранее."),
        12: ("Sysmon Registry Event 12", "Создание или удаление ключа/объекта реестра."),
        13: ("Sysmon Registry Event 13", "Изменение значения реестра."),
        14: ("Sysmon Registry Event 14", "Переименование ключа или значения реестра."),
    }
    rows: list[dict] = []
    for item in root:
        if item.tag.rsplit("}", 1)[-1] != "Event":
            continue
        system = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "System"), None)
        data_node = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "EventData"), None)
        user_data = next((c for c in item if c.tag.rsplit("}", 1)[-1] == "UserData"), None)
        if system is None:
            continue

        def child(name: str) -> str:
            for node in system.iter():
                if node.tag.rsplit("}", 1)[-1] == name:
                    return node.text or ""
            return ""

        try:
            event_id = int(child("EventID") or 0)
        except ValueError:
            event_id = 0
        if event_id not in ids:
            continue
        time_node = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "TimeCreated"), None)
        timestamp = _local_time(time_node.attrib.get("SystemTime", "")) if time_node is not None else ""
        fields: dict[str, str] = {}
        if data_node is not None:
            for node in data_node.iter():
                if node is data_node:
                    continue
                local = node.tag.rsplit("}", 1)[-1]
                if local == "Data":
                    key = node.attrib.get("Name", f"field_{len(fields)}")
                    fields[key] = (node.text or "")[:5000]
        if user_data is not None:
            for node in user_data.iter():
                if node is user_data or list(node):
                    continue
                key = node.tag.rsplit("}", 1)[-1]
                if key and node.text:
                    fields.setdefault(key, node.text[:5000])

        provider = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "Provider"), None)
        execution = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "Execution"), None)
        security = next((c for c in system if c.tag.rsplit("}", 1)[-1] == "Security"), None)
        title, interpretation = labels.get(event_id, (f"Событие {event_id}", "Проверьте контекст."))
        rows.append(_event(
            "Windows: журналы аудита", title, f"Windows Event Log / {log_name}", timestamp,
            "Время события Windows", {
                "event_id": event_id,
                "event_record_id": child("EventRecordID"),
                "provider": provider.attrib.get("Name", "") if provider is not None else "",
                "channel": log_name,
                "computer": child("Computer"),
                "system_process_id": execution.attrib.get("ProcessID", "") if execution is not None else "",
                "system_thread_id": execution.attrib.get("ThreadID", "") if execution is not None else "",
                "event_user_sid": security.attrib.get("UserID", "") if security is not None else "",
                "fields": fields,
                "interpretation": interpretation,
                "note": "Технический источник для ручной проверки; событие само по себе не доказывает нарушение.",
            }
        ))
    return rows


def _event_log(log_name: str, ids: set[int], max_count: int = 500) -> tuple[list[dict], list[str]]:
    events: list[dict] = []
    warnings: list[str] = []
    if os.name != "nt":
        return events, warnings
    id_query = " or ".join(f"EventID={x}" for x in sorted(ids))
    command = ["wevtutil", "qe", log_name, "/q:*[System[(" + id_query + ")]]", "/f:xml", "/rd:true", f"/c:{max_count}"]
    try:
        proc = subprocess.run(command, capture_output=True, text=False, timeout=12, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stdout_text, _stdout_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
        stderr_text, _stderr_encoding = decode_text_bytes(proc.stderr or b"", prefer_oem=True)
        if proc.returncode != 0:
            detail = (stderr_text or stdout_text or f"exit {proc.returncode}").strip()
            warnings.append(f"{log_name}: запрос не выполнен ({detail[:250]}).")
            return events, warnings
        if stdout_text.strip():
            events = parse_event_xml(stdout_text, log_name, ids)
            if len(events) >= max_count:
                warnings.append(f"{log_name}: достигнут лимит {max_count} событий; более старые записи могли не попасть в выборку.")
    except FileNotFoundError:
        warnings.append("wevtutil не найден; Windows Event Log не прочитан.")
    except subprocess.TimeoutExpired:
        warnings.append(f"Тайм-аут чтения журнала {log_name}.")
    except Exception as exc:
        warnings.append(f"Ошибка разбора журнала {log_name}: {exc}")
    return events, warnings


def _probe_event_log(log_name: str) -> dict:
    """Return availability state without changing the event log."""
    result = {"type": "Windows Event Log channel", "path": log_name, "status": "unknown", "matched_events": 0}
    if os.name != "nt":
        result["status"] = "not_applicable"
        result["note"] = "Доступно только в Windows."
        return result
    try:
        proc = subprocess.run(["wevtutil", "gli", log_name], capture_output=True, text=False,
                              timeout=5, check=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stdout_text, _stdout_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
        stderr_text, _stderr_encoding = decode_text_bytes(proc.stderr or b"", prefer_oem=True)
        if proc.returncode == 0:
            result["status"] = "available"
            result["log_metadata"] = stdout_text[:1800]
        else:
            detail = (stderr_text or stdout_text or "").strip()
            low = detail.casefold()
            result["status"] = "not_found" if any(x in low for x in ("cannot find", "не удается найти", "не удалось найти", "not found")) else "inaccessible"
            result["note"] = detail[:500] or f"wevtutil exit {proc.returncode}"
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
    except Exception as exc:
        result["status"] = "error"
        result["note"] = str(exc)[:500]
    return result


def _fields_text(row: dict) -> str:
    fields = (row.get("details") or {}).get("fields") or {}
    return " ".join(str(k) + "=" + str(v) for k, v in fields.items())


def _is_relevant_artifact_path(value: str) -> bool:
    text = str(value or "").replace("/", "\\").casefold()
    suffix = Path(text).suffix.casefold()
    script_suffixes = {".py", ".pyw", ".pyi", ".pyc", ".pyo", ".ipynb"}
    config_suffixes = {".toml", ".ini", ".cfg", ".yaml", ".yml", ".json", ".sqlite", ".db", ".log"}
    binary_suffixes = {".exe", ".dll", ".jar", ".zip", ".7z"}
    if suffix in script_suffixes:
        return True
    context_terms = ("python", "pycharm", "jetbrains", "vscode", "\\code\\", "jupyter", "ipython", ".minecraft", "minecraft", "\\temp\\", "\\tmp\\")
    if suffix in config_suffixes and any(term in text for term in context_terms):
        return True
    if suffix in binary_suffixes and any(term in text for term in context_terms):
        return True
    return False


def _is_related_application_event(row: dict) -> bool:
    text = _fields_text(row).casefold()
    markers = ("python", "pythonw", "pycharm", "jetbrains", "ipython", "jupyter", "java.exe", "javaw.exe", "cmd.exe", "powershell", "pwsh.exe", "code.exe", "minecraft")
    return any(marker in text for marker in markers)


def _is_relevant_registry_event(fields: dict) -> bool:
    text = " ".join(str(k) + "=" + str(v) for k, v in fields.items()).casefold()
    markers = (
        "\\software\\microsoft\\windows\\currentversion\\run",
        "\\software\\wow6432node\\microsoft\\windows\\currentversion\\run",
        "python", "pycharm", "jetbrains", "jupyter", "ipython", "javaw.exe", "java.exe",
    )
    return any(marker in text for marker in markers)


def _source_status(path: str, status: str, note: str = "", **extra: Any) -> dict:
    row = {"type": "Additional source", "path": path, "status": status}
    if note:
        row["note"] = note
    row.update(extra)
    return row



def _powershell_executable() -> str | None:
    import shutil
    return shutil.which("powershell") or shutil.which("pwsh")


def _powershell_json(script: str, timeout: int = 18) -> tuple[Any, str]:
    '''Run a fixed, read-only PowerShell inventory query and parse its JSON output.'''
    executable = _powershell_executable()
    if not executable:
        return None, "PowerShell executable not found"
    command = [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        proc = subprocess.run(command, capture_output=True, text=False,
                              timeout=timeout, check=False,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stdout_text, _stdout_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
        stderr_text, _stderr_encoding = decode_text_bytes(proc.stderr or b"", prefer_oem=True)
        if proc.returncode != 0:
            return None, (stderr_text or stdout_text or f"exit {proc.returncode}").strip()[:700]
        output = (stdout_text or "").strip()
        if not output:
            return [], ""
        return json.loads(output), ""
    except subprocess.TimeoutExpired:
        return None, f"PowerShell query timed out after {timeout}s"
    except json.JSONDecodeError as exc:
        return None, f"PowerShell returned invalid JSON: {exc}"
    except Exception as exc:
        return None, f"PowerShell query failed: {exc}"


def _scan_scheduled_task_inventory(progress: Callable[[str], None]) -> tuple[list[dict], list[dict], list[str]]:
    '''Read scheduled task definitions that reference common development runtimes.'''
    events: list[dict] = []
    sources: list[dict] = []
    warnings: list[str] = []
    progress("Проверка зарегистрированных задач планировщика (только чтение)…")
    script = r'''$ErrorActionPreference='Stop'; if(-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)){ throw 'ScheduledTasks cmdlet is unavailable' }; $pattern='(?i)(pythonw?|\\py\.exe|pycharm|jetbrains|ipython|jupyter|javaw?\.exe|powershell|pwsh\.exe)'; $out=@(); foreach($t in Get-ScheduledTask -ErrorAction SilentlyContinue){ foreach($a in @($t.Actions)){ $exe=[string]$a.Execute; $args=[string]$a.Arguments; $wd=[string]$a.WorkingDirectory; $blob="$exe $args $wd"; if($blob -match $pattern -or [string]$t.TaskName -match $pattern){ $info=$null; try{$info=Get-ScheduledTaskInfo -InputObject $t -ErrorAction Stop}catch{}; $last=''; $next=''; $result=''; if($info){ if($info.LastRunTime -and $info.LastRunTime.Year -gt 1601){$last=$info.LastRunTime.ToString('yyyy-MM-ddTHH:mm:ss')}; if($info.NextRunTime -and $info.NextRunTime.Year -gt 1601){$next=$info.NextRunTime.ToString('yyyy-MM-ddTHH:mm:ss')}; $result=[string]$info.LastTaskResult }; $out += [pscustomobject]@{TaskName=[string]$t.TaskName;TaskPath=[string]$t.TaskPath;State=[string]$t.State;Execute=$exe;Arguments=$args;WorkingDirectory=$wd;UserId=[string]$t.Principal.UserId;LastRunTime=$last;NextRunTime=$next;LastTaskResult=$result} } } }; ConvertTo-Json -InputObject @($out) -Depth 4 -Compress'''
    data, error = _powershell_json(script, timeout=25)
    if data is None:
        sources.append(_source_status("Task Scheduler inventory", "inaccessible" if "access" in error.casefold() else "error", error))
        warnings.append(f"Инвентаризация задач планировщика не выполнена: {error}")
        return events, sources, warnings
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    sources.append(_source_status("Task Scheduler inventory", "available", f"Найдено задач со ссылками на инструменты: {len(rows)}", matched_events=len(rows)))
    for task in rows[:1500]:
        if not isinstance(task, dict):
            continue
        task_path = str(task.get("TaskPath", "")) + str(task.get("TaskName", ""))
        command = " ".join(x for x in (str(task.get("Execute", "")), str(task.get("Arguments", "")), str(task.get("WorkingDirectory", ""))) if x)
        last_run = str(task.get("LastRunTime", ""))
        timestamp = ""
        if last_run and last_run not in {"1/1/0001 12:00:00 AM", "01.01.0001 00:00:00"}:
            try:
                dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                timestamp = dt.astimezone().isoformat(sep=" ", timespec="seconds") if dt.tzinfo else dt.isoformat(sep=" ", timespec="seconds")
            except ValueError:
                timestamp = last_run
        events.append(_event("Windows: задача планировщика", "Зарегистрированная задача с действием, связанным с инструментами разработки", "Task Scheduler inventory", timestamp,
                             "LastRunTime из Get-ScheduledTaskInfo; может быть локализованным/пустым", {
                                 "task_name": task.get("TaskName", ""), "task_path": task.get("TaskPath", ""),
                                 "state": task.get("State", ""), "execute": task.get("Execute", ""),
                                 "arguments": task.get("Arguments", ""), "working_directory": task.get("WorkingDirectory", ""),
                                 "user_id": task.get("UserId", ""), "last_run_time": last_run,
                                 "next_run_time": task.get("NextRunTime", ""), "last_task_result": task.get("LastTaskResult", ""),
                                 "note": "Текущая конфигурация задачи; LastRunTime не доказывает содержание команды, выполненной в прошлом.",
                             }, command[:5000]))
    return events, sources, warnings


def _scan_related_services(progress: Callable[[str], None]) -> tuple[list[dict], list[dict], list[str]]:
    '''Inventory current Windows services whose image paths mention reviewed tools.'''
    events: list[dict] = []
    sources: list[dict] = []
    warnings: list[str] = []
    progress("Проверка служб Windows, связанных с Python/Java/IDE и журналированием…")
    script = r'''$ErrorActionPreference='Stop'; $pattern='(?i)(pythonw?|pycharm|jetbrains|ipython|jupyter|javaw?\.exe|anydesk|sysmon|powershell)'; if(Get-Command Get-CimInstance -ErrorAction SilentlyContinue){$svc=Get-CimInstance Win32_Service}else{$svc=Get-WmiObject Win32_Service}; $out=$svc | Where-Object { ([string]$_.PathName) -match $pattern -or ([string]$_.Name) -match $pattern -or ([string]$_.DisplayName) -match $pattern } | Select-Object Name,DisplayName,State,StartMode,StartName,PathName,ProcessId; ConvertTo-Json -InputObject @($out) -Depth 3 -Compress'''
    data, error = _powershell_json(script, timeout=20)
    if data is None:
        sources.append(_source_status("Win32_Service inventory", "inaccessible" if "access" in error.casefold() else "error", error))
        warnings.append(f"Инвентаризация служб Windows не выполнена: {error}")
        return events, sources, warnings
    rows = data if isinstance(data, list) else ([data] if isinstance(data, dict) else [])
    sources.append(_source_status("Win32_Service inventory", "available", f"Найдено связанных служб: {len(rows)}", matched_events=len(rows)))
    for service in rows[:1000]:
        if not isinstance(service, dict):
            continue
        label = str(service.get("DisplayName") or service.get("Name") or "Windows service")
        command = str(service.get("PathName", ""))
        events.append(_event("Windows: служба", f"Найдена служба, связанная с инструментами разработки: {label}", "Win32_Service inventory", "", "Текущий снимок конфигурации, не история установки", {
            "name": service.get("Name", ""), "display_name": service.get("DisplayName", ""),
            "state": service.get("State", ""), "start_mode": service.get("StartMode", ""),
            "start_name": service.get("StartName", ""), "process_id": service.get("ProcessId", ""),
            "path_name": command, "note": "Инвентаризация текущего состояния; не показывает, кто и когда создал службу.",
        }, command[:5000]))
    return events, sources, warnings


def _scan_relevant_autoruns(progress: Callable[[str], None]) -> tuple[list[dict], list[dict], list[str]]:
    '''Read selected Run/RunOnce registry values for the current user and machine.'''
    events: list[dict] = []
    sources: list[dict] = []
    warnings: list[str] = []
    progress("Проверка выбранных ключей автозапуска реестра (только чтение)…")
    if os.name != "nt":
        return events, [_source_status("Run/RunOnce registry", "not_applicable", "Требуется Windows.")], warnings
    try:
        import winreg
    except Exception as exc:
        return events, [_source_status("Run/RunOnce registry", "error", str(exc))], [f"Не удалось подключить winreg: {exc}"]
    paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    ]
    markers = ("python", "pycharm", "jetbrains", "ipython", "jupyter", "javaw", "java.exe", "powershell", "anydesk", "sysmon")
    found_keys = 0
    for hive, subkey, hive_name in paths:
        access = winreg.KEY_READ
        try:
            with winreg.OpenKey(hive, subkey, 0, access) as key:
                found_keys += 1
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                        index += 1
                    except OSError:
                        break
                    text = str(value)
                    if not any(token in (str(name) + " " + text).casefold() for token in markers):
                        continue
                    path = f"{hive_name}\\{subkey}"
                    events.append(_event("Windows: автозапуск", f"Запись Run/RunOnce содержит ссылку на инструмент: {name}", path, "", "Реестр не хранит здесь точное время создания значения", {
                        "value_name": str(name), "value_data": text, "value_type": int(value_type),
                        "registry_path": path, "note": "Текущий снимок автозапуска; запись сама по себе не доказывает запуск или нарушение.",
                    }, text[:5000]))
        except FileNotFoundError:
            sources.append(_source_status(f"{hive_name}\\{subkey}", "not_found", "Ключ не существует."))
        except PermissionError as exc:
            sources.append(_source_status(f"{hive_name}\\{subkey}", "inaccessible", str(exc)))
        except OSError as exc:
            sources.append(_source_status(f"{hive_name}\\{subkey}", "error", str(exc)))
    sources.append(_source_status("Run/RunOnce registry inventory", "available" if found_keys else "not_found", f"Проверено доступных ключей: {found_keys}", matched_events=len(events)))
    return events, sources, warnings


def _pid_key(value: Any) -> str:
    """Normalize Windows PID strings (often hexadecimal) for correlation."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(int(raw, 0))
    except ValueError:
        try:
            return str(int(raw, 16))
        except ValueError:
            return raw.casefold()


def _is_python_image(value: str) -> bool:
    name = str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    return bool(re.fullmatch(r"(?:pythonw?|python\d+(?:\.\d+)*|py)\.exe", name))


def _is_java_image(value: str) -> bool:
    name = str(value or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()
    return name in {"java.exe", "javaw.exe"}


def _is_runtime_image(value: str) -> bool:
    return _is_python_image(value) or _is_java_image(value)


def _time_epoch(value: str) -> float | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.timestamp()
        return dt.timestamp()
    except Exception:
        return None


def _select_python_related_4688(rows: list[dict], active_user: str) -> list[dict]:
    """Keep Python/Java launches, shell invocations, and child-process lineage.

    The helper works only with retained 4688 event records. It cannot reconstruct
    events that Windows did not log, and PID correlation is deliberately limited
    to a short window to reduce false matches caused by PID reuse.
    """
    candidates = []
    for row in rows:
        details = row.get("details", {})
        fields = details.get("fields", {})
        subject = str(fields.get("SubjectUserName", "") or fields.get("TargetUserName", "")).casefold()
        if active_user and subject and subject not in {active_user, active_user + "$"}:
            continue
        image = str(fields.get("NewProcessName", ""))
        image_name = image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        command_line = str(fields.get("CommandLine", ""))
        parent_path = str(fields.get("ParentProcessName", "") or fields.get("CreatorProcessName", ""))
        parent_name = parent_path.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        new_pid = _pid_key(fields.get("NewProcessId", ""))
        parent_pid = _pid_key(fields.get("ProcessId", "") or fields.get("ParentProcessId", ""))
        candidates.append({
            "row": row, "fields": fields, "image": image, "image_name": image_name,
            "command_line": command_line, "parent_path": parent_path,
            "parent_name": parent_name, "new_pid": new_pid,
            "parent_pid": parent_pid, "epoch": _time_epoch(row.get("timestamp", "")),
        })

    # Oldest first so a retained parent event is available before child events.
    candidates.sort(key=lambda item: item["epoch"] if item["epoch"] is not None else float("inf"))
    lineage: dict[str, float | None] = {}
    selected: list[dict] = []
    for item in candidates:
        is_python = _is_python_image(item["image_name"])
        is_java = _is_java_image(item["image_name"])
        parent_is_python = _is_python_image(item["parent_name"])
        parent_is_java = _is_java_image(item["parent_name"])
        parent_epoch = lineage.get(item["parent_pid"]) if item["parent_pid"] else None
        linked_by_pid = (
            item["parent_pid"] in lineage
            and item["epoch"] is not None
            and parent_epoch is not None
            and 0 <= item["epoch"] - parent_epoch <= 600
        )
        shell_starts_python = (
            item["image_name"] in {"cmd.exe", "powershell.exe", "pwsh.exe", "wt.exe"}
            and bool(SHELL_PYTHON_COMMAND_RE.search(item["command_line"]))
        )
        if not (is_python or is_java or parent_is_python or parent_is_java or linked_by_pid or shell_starts_python):
            continue

        row = item["row"]
        if is_python:
            row["description"] = "Запуск интерпретатора Python (4688)"
            relation = "Python interpreter"
            runtime_family = "Python"
        elif is_java:
            row["description"] = "Запуск Java-процесса (4688)"
            relation = "Java runtime"
            runtime_family = "Java"
        elif parent_is_python:
            row["description"] = f"Процесс создан Python: {item['image_name']} (4688)"
            relation = "direct child of Python"
            runtime_family = "child_of_Python"
        elif parent_is_java:
            row["description"] = f"Процесс создан Java: {item['image_name']} (4688)"
            relation = "direct child of Java"
            runtime_family = "child_of_Java"
        elif linked_by_pid:
            row["description"] = f"Процесс в цепочке Python/Java: {item['image_name']} (4688)"
            relation = "descendant in runtime process chain (PID correlation)"
            runtime_family = "runtime_descendant"
        else:
            row["description"] = f"Оболочка запускает runtime: {item['image_name']} (4688)"
            relation = "shell command launches Python or Java"
            runtime_family = "runtime_command"

        row["command"] = item["command_line"][:5000]
        details = row.setdefault("details", {})
        details.update({
            "process_image": item["image"],
            "process_id": item["new_pid"],
            "parent_process": item["parent_path"],
            "parent_process_id": item["parent_pid"],
            "process_relation": relation,
            "process_family": runtime_family,
            "NewProcessId": item["new_pid"],
            "ParentProcessId": item["parent_pid"],
            "NewProcessName": item["image"],
            "event_id": 4688,
            "note": "Событие 4688 показывает создание процесса. Связь по PID ограничена десятью минутами; точная внутренняя команда интерпретатора видна только если Windows сохранила её в командной строке запуска или другом источнике.",
        })
        selected.append(row)

        if item["new_pid"] and (is_python or is_java or parent_is_python or parent_is_java or linked_by_pid):
            lineage[item["new_pid"]] = item["epoch"]

    return selected


def _select_sysmon_python_related(rows: list[dict], active_user: str) -> list[dict]:
    """Select Sysmon Event ID 1 records involving Python/Java and their child tree."""
    candidates = []
    for row in rows:
        fields = row.get("details", {}).get("fields", {})
        user = str(fields.get("User", "")).casefold()
        if active_user and user and not (user == active_user or user.endswith("\\" + active_user)):
            continue
        image = str(fields.get("Image", ""))
        parent_image = str(fields.get("ParentImage", ""))
        image_name = image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        parent_name = parent_image.replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        candidates.append({
            "row": row, "fields": fields, "image": image, "parent_image": parent_image,
            "image_name": image_name, "parent_name": parent_name,
            "guid": str(fields.get("ProcessGuid", "")).casefold(),
            "parent_guid": str(fields.get("ParentProcessGuid", "")).casefold(),
            "command_line": str(fields.get("CommandLine", "")),
            "epoch": _time_epoch(row.get("timestamp", "")),
        })
    candidates.sort(key=lambda item: item["epoch"] if item["epoch"] is not None else float("inf"))
    lineage: set[str] = set()
    selected = []
    for item in candidates:
        is_python = _is_python_image(item["image_name"])
        is_java = _is_java_image(item["image_name"])
        parent_is_python = _is_python_image(item["parent_name"])
        parent_is_java = _is_java_image(item["parent_name"])
        parent_linked = bool(item["parent_guid"] and item["parent_guid"] in lineage)
        if not (is_python or is_java or parent_is_python or parent_is_java or parent_linked):
            continue
        row = item["row"]
        if is_python:
            row["description"] = "Запуск Python (Sysmon Event 1)"
            relation = "Python interpreter"
            runtime_family = "Python"
        elif is_java:
            row["description"] = "Запуск Java (Sysmon Event 1)"
            relation = "Java runtime"
            runtime_family = "Java"
        elif parent_is_python:
            row["description"] = f"Процесс создан Python: {item['image_name']} (Sysmon)"
            relation = "direct child of Python"
            runtime_family = "child_of_Python"
        elif parent_is_java:
            row["description"] = f"Процесс создан Java: {item['image_name']} (Sysmon)"
            relation = "direct child of Java"
            runtime_family = "child_of_Java"
        else:
            row["description"] = f"Процесс в цепочке Python/Java: {item['image_name']} (Sysmon)"
            relation = "descendant in runtime process tree (ProcessGuid)"
            runtime_family = "runtime_descendant"
        row["command"] = item["command_line"][:5000]
        row.setdefault("details", {}).update({
            "process_image": item["image"],
            "parent_process": item["parent_image"],
            "process_guid": item["guid"],
            "parent_process_guid": item["parent_guid"],
            "process_id": str(item["fields"].get("ProcessId", "")),
            "parent_process_id": str(item["fields"].get("ParentProcessId", "")),
            "process_family": runtime_family,
            "event_id": 1,
            "process_relation": relation,
            "note": "Sysmon Event ID 1 фиксирует создание процесса только если Sysmon уже был установлен и журналировал события в момент запуска.",
        })
        selected.append(row)
        if item["guid"] and (is_python or is_java or parent_is_python or parent_is_java or parent_linked):
            lineage.add(item["guid"])
    return selected


def _windows_markers(progress: Callable[[str], None]) -> tuple[list[dict], list[dict], list[str]]:
    events: list[dict] = []
    sources: list[dict] = []
    warnings: list[str] = []
    if os.name != "nt":
        warnings.append("Системные журналы, Prefetch, SRUM и USN доступны только в Windows.")
        for channel in (
            "Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-WMI-Activity/Operational",
        ):
            sources.append(_source_status(channel, "not_applicable", "Требуется Windows."))
        return events, sources, warnings

    active_user = (os.environ.get("USERNAME") or os.environ.get("USER") or "").casefold()
    channel_specs = [
        ("Security", "Security", {4688, 4689, 4616, 4663, 4657, 4697, 4698, 4699, 4700, 4701, 4702, 1102, 4719, 5156}, 12000),
        ("System", "System", {104, 6005, 6006, 6008, 7036, 7040, 7045}, 2200),
        ("Application", "Application", {1000, 1001, 1026}, 1200),
        ("Sysmon", "Microsoft-Windows-Sysmon/Operational", {1, 2, 3, 4, 5, 7, 11, 12, 13, 14, 16, 22, 23, 26}, 12000),
        ("PowerShell", "Microsoft-Windows-PowerShell/Operational", {400, 403, 600, 4103, 4104}, 2200),
        ("Defender", "Microsoft-Windows-Windows Defender/Operational", {1116, 1117, 5001, 5007}, 800),
        ("Task Scheduler", "Microsoft-Windows-TaskScheduler/Operational", {106, 140, 141, 200, 201}, 1000),
        ("WMI Activity", "Microsoft-Windows-WMI-Activity/Operational", {5857, 5858, 5860, 5861}, 800),
    ]
    raw_events: dict[str, list[dict]] = {}
    for key, log_name, ids, limit in channel_specs:
        progress(f"Проверяю канал Windows: {log_name}…")
        status_row = _probe_event_log(log_name)
        status_row["requested_event_ids"] = sorted(ids)
        sources.append(status_row)
        rows, w = _event_log(log_name, ids, limit)
        raw_events[key] = rows
        status_row["events_read"] = len(rows)
        status_row["read_status"] = "ok" if not w else "warning"
        if w:
            status_row["read_note"] = " | ".join(w)[:1000]
        warnings.extend(w)

    # Security process creation: selected Python/Java-related processes and descendants.
    security_rows = raw_events.get("Security", [])
    creation_rows = [r for r in security_rows if (r.get("details", {}).get("event_id") == 4688)]
    process_events = _select_python_related_4688(creation_rows, active_user)
    events.extend(process_events)
    known_pids: set[str] = set()
    for row in process_events:
        fields = (row.get("details") or {}).get("fields") or {}
        pid = _pid_key(fields.get("NewProcessId", ""))
        if pid:
            known_pids.add(pid)

    # Security process-termination records, linked conservatively to known Python process IDs.
    for row in security_rows:
        fields = (row.get("details") or {}).get("fields") or {}
        event_id = (row.get("details") or {}).get("event_id")
        subject = str(fields.get("SubjectUserName", "") or fields.get("TargetUserName", "")).casefold()
        if active_user and subject and subject not in {active_user, active_user + "$"}:
            continue
        if event_id == 4689:
            image = str(fields.get("ProcessName", "") or fields.get("Process", ""))
            pid = _pid_key(fields.get("ProcessId", ""))
            if _is_runtime_image(image) or pid in known_pids:
                family = "Java" if _is_java_image(image) else "Python"
                row["description"] = f"Завершение {family}-процесса (Security 4689)"
                row.setdefault("details", {}).update({"process_id": pid, "ProcessId": pid, "process_image": image, "process_family": family, "event_id": 4689})
                row["command"] = image
                events.append(row)
        elif event_id == 4663:
            target = str(fields.get("ObjectName", ""))
            process_name = str(fields.get("ProcessName", ""))
            if _is_relevant_artifact_path(target) or _is_python_image(process_name):
                row["description"] = "Доступ к Python/IDE-файлу (Security 4663)"
                row["command"] = f"{process_name} → {target}"[:5000]
                events.append(row)
        elif event_id == 4657 and _is_relevant_registry_event(fields):
            row["description"] = "Изменение связанного параметра реестра (Security 4657)"
            row["command"] = _fields_text(row)[:5000]
            events.append(row)
        elif event_id in {4698, 4699, 4700, 4701, 4702} and re.search(r"(?i)(pythonw?|pycharm|ipython|jupyter|javaw?)", _fields_text(row)):
            row["description"] = f"Изменение задачи планировщика, связанной с Python (Security {event_id})"
            row["command"] = _fields_text(row)[:5000]
            events.append(row)
        elif event_id == 4697 and re.search(r"(?i)(pythonw?|pycharm|ipython|jupyter|javaw?|sysmon|anydesk)", _fields_text(row)):
            row["description"] = "Установка службы, связанной с инструментами разработки (Security 4697)"
            row["command"] = _fields_text(row)[:5000]
            events.append(row)
        elif event_id == 4616:
            # Recorded system-time change. Keep previous/new time fields as supplied.
            row["description"] = "Изменено системное время Windows (Security 4616)"
            row["command"] = _fields_text(row)[:3000]
            row.setdefault("details", {})["time_change_context"] = True
            events.append(row)
        elif event_id == 5156:
            # WFP connection metadata is useful only when the application path is clearly relevant.
            app_path = str(fields.get("Application", ""))
            if _is_runtime_image(app_path) or re.search(r"(?i)(pythonw?|javaw?|\\py\.exe)", app_path):
                row["description"] = "Сетевое подключение приложения Python/Java (Security 5156)"
                row["command"] = _fields_text(row)[:3000]
                row.setdefault("details", {})["network_metadata_only"] = True
                events.append(row)
        elif event_id in {1102, 4719}:
            events.append(row)

    # Sysmon: starts, exits and selected file create/delete events.
    sysmon_rows = raw_events.get("Sysmon", [])
    sysmon_start = [r for r in sysmon_rows if (r.get("details", {}).get("event_id") == 1)]
    selected_sysmon = _select_sysmon_python_related(sysmon_start, active_user)
    events.extend(selected_sysmon)
    known_guids: set[str] = set()
    known_sysmon_pids: set[str] = set()
    for row in selected_sysmon:
        fields = (row.get("details") or {}).get("fields") or {}
        guid = str(fields.get("ProcessGuid", "")).casefold()
        pid = _pid_key(fields.get("ProcessId", ""))
        if guid:
            known_guids.add(guid)
        if pid:
            known_sysmon_pids.add(pid)
    for row in sysmon_rows:
        details = row.get("details") or {}
        fields = details.get("fields") or {}
        event_id = details.get("event_id")
        image = str(fields.get("Image", ""))
        guid = str(fields.get("ProcessGuid", "")).casefold()
        pid = _pid_key(fields.get("ProcessId", ""))
        if event_id == 5 and (_is_runtime_image(image) or guid in known_guids or pid in known_sysmon_pids):
            family = "Java" if _is_java_image(image) else "Python"
            row["description"] = f"Завершение процесса {family}/связанной цепочки (Sysmon Event 5)"
            row.setdefault("details", {}).update({"process_id": pid, "ProcessId": pid, "process_image": image, "process_family": family, "event_id": 5, "process_guid": guid})
            row["command"] = image
            events.append(row)
        elif event_id == 3 and (guid in known_guids or _is_runtime_image(image)):
            # Sysmon network-connect events; include only a process already linked to the
            # Python/Java lineage. No packet payload or content is collected.
            destination = str(fields.get("DestinationHostname", "") or fields.get("DestinationIp", ""))
            port = str(fields.get("DestinationPort", ""))
            row["description"] = "Сетевое подключение процесса из цепочки Python/Java (Sysmon Event 3)"
            row["command"] = f"{image} → {destination}:{port}"[:1000]
            row.setdefault("details", {}).update({
                "associated_process": image, "network_metadata_only": True,
                "process_guid": guid, "process_id": pid,
                "note": "Sysmon Event 3 содержит метаданные соединения, если событие было включено заранее; содержимое трафика не анализируется."
            })
            events.append(row)
        elif event_id == 7 and guid in known_guids:
            loaded = str(fields.get("ImageLoaded", ""))
            if loaded and Path(loaded).suffix.casefold() in {".dll", ".pyd", ".so", ".jar"}:
                row["description"] = "Загрузка библиотеки процессом из цепочки Python (Sysmon Event 7)"
                row["command"] = loaded
                row.setdefault("details", {})["associated_process"] = image
                events.append(row)
        elif event_id == 22 and guid in known_guids:
            query_name = str(fields.get("QueryName", ""))
            if query_name:
                row["description"] = "DNS-запрос процесса из цепочки Python (Sysmon Event 22)"
                row["command"] = query_name
                row.setdefault("details", {})["associated_process"] = image
                events.append(row)
        elif event_id in {4, 16}:
            # Sysmon service/configuration events are system-wide context, not proof of tampering.
            row["description"] = "Событие состояния/конфигурации Sysmon"
            row["command"] = _fields_text(row)[:5000]
            events.append(row)
        elif event_id in {12, 13, 14}:
            if _is_relevant_registry_event(fields):
                row["description"] = {12: "Создание/удаление ключа реестра (Sysmon 12)", 13: "Изменение значения реестра (Sysmon 13)", 14: "Переименование ключа/значения реестра (Sysmon 14)"}[event_id]
                row["command"] = _fields_text(row)[:5000]
                events.append(row)
        elif event_id in {2, 11, 23, 26}:
            target = str(fields.get("TargetFilename", "") or fields.get("FileName", ""))
            if not target or not _is_relevant_artifact_path(target):
                continue
            if guid not in known_guids and not any(x in target.casefold() for x in ("python", "pycharm", "jetbrains", "jupyter", "\\code\\", ".minecraft", "minecraft", "\\temp\\", "\\tmp\\")) and Path(target).suffix.casefold() not in {".py", ".pyw", ".pyi", ".pyc", ".pyo", ".ipynb"}:
                continue
            labels = {
                2: "Изменено время создания файла (Sysmon Event 2)",
                11: "Файл создан (Sysmon Event 11)",
                23: "Файл удалён и архивирован Sysmon (Event 23)",
                26: "Обнаружено удаление файла (Sysmon Event 26)",
            }
            row["description"] = labels[event_id]
            row["command"] = target
            row["details"]["file_path"] = target
            row["details"]["associated_process"] = image
            row["details"]["note"] = "Файловое событие включено по пути/связи с процессом; само по себе не подтверждает назначение файла."
            events.append(row)

    # System log: clearing and selected service state/configuration changes.
    for row in raw_events.get("System", []):
        event_id = (row.get("details") or {}).get("event_id")
        text = _fields_text(row).casefold()
        if event_id in {104, 6005, 6006, 6008}:
            events.append(row)
        elif event_id in {7036, 7040, 7045} and any(x in text for x in ("sysmon", "winrm", "win defender", "windefend", "anydesk", "event log", "powershell", "python", "java")):
            events.append(row)

    # Application crashes and WER reports only when fields mention relevant runtimes/IDEs.
    for row in raw_events.get("Application", []):
        if _is_related_application_event(row):
            events.append(row)
            row["command"] = _fields_text(row)[:5000]

    # PowerShell engine/script-block events: retain only records mentioning relevant tools.
    for row in raw_events.get("PowerShell", []):
        text = _fields_text(row)
        low = text.casefold()
        if any(marker in low for marker in ("python", "pythonw", "pycharm", "ipython", "jupyter", "java.exe", "javaw.exe", "cmd.exe", "code.exe")):
            event_id = (row.get("details") or {}).get("event_id")
            row["description"] = f"PowerShell: событие {event_id}, связанное с инструментами разработки"
            row["command"] = text[:5000]
            events.append(row)

    # Defender operational log: keep detections/config changes as surrounding context.
    events.extend(raw_events.get("Defender", []))

    # Task Scheduler actions may reveal an interpreter or script invocation.
    for row in raw_events.get("Task Scheduler", []):
        text = _fields_text(row)
        if re.search(r"(?i)(pythonw?|\\py\.exe|pycharm|jupyter|ipython)", text):
            row["description"] = "Задача планировщика содержит ссылку на Python/IDE"
            row["command"] = text[:5000]
            events.append(row)

    # WMI activity is included only when the event text clearly mentions a relevant runtime.
    for row in raw_events.get("WMI Activity", []):
        text = _fields_text(row)
        if re.search(r"(?i)(pythonw?|pycharm|ipython|jupyter|javaw?|cmd\.exe|powershell)", text):
            row["description"] = "WMI Activity: событие связано с Python/терминалом"
            row["command"] = text[:5000]
            events.append(row)

    # Current configuration inventories complement event logs; they do not prove historical execution.
    for scanner in (_scan_scheduled_task_inventory, _scan_related_services, _scan_relevant_autoruns):
        extra_events, extra_sources, extra_warnings = scanner(progress)
        events.extend(extra_events)
        sources.extend(extra_sources)
        warnings.extend(extra_warnings)

    # Prefetch metadata: broaden beyond Python to common launchers/IDEs/terminals.
    progress("Проверка Prefetch для Python, Java, IDE и терминалов…")
    prefetch = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
    prefetch_patterns = ("PYTHON", "PY.EXE-", "PYCHARM", "CODE.EXE", "JAVA", "JAVA W", "CMD.EXE", "POWERSHELL", "PWSH", "WINDOWSTERMINAL", "JUPYTER", "IPYTHON", "ANYDESK")
    prefetch_source = {"type": "Windows Prefetch directory", "path": str(prefetch), "status": "available" if prefetch.is_dir() else "not_found", "matched_files": 0}
    if prefetch.is_dir():
        try:
            for path in prefetch.iterdir():
                if path.is_file() and path.name.upper().endswith(".PF") and path.name.upper().startswith(prefetch_patterns):
                    st = path.stat()
                    mtime = datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds")
                    events.append(_event("Windows: Prefetch", f"Найден Prefetch-файл {path.name}", str(path), mtime, "Время изменения файла, не точное время запуска", {
                        "size_bytes": st.st_size,
                        "note": "Prefetch подтверждает наличие артефакта, но время изменения не следует считать точным временем каждого запуска.",
                    }))
                    prefetch_source["matched_files"] += 1
        except PermissionError as exc:
            prefetch_source["status"] = "inaccessible"
            warnings.append(f"Нет доступа к Prefetch: {exc}")
        except Exception as exc:
            warnings.append(f"Не удалось прочитать Prefetch: {exc}")
    sources.append(prefetch_source)

    # Amcache: metadata only; do not open/modify the live registry hive.
    progress("Проверка Amcache и SRUM (метаданные доступности)…")
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    amcache = system_root / "AppCompat" / "Programs" / "Amcache.hve"
    try:
        if amcache.is_file():
            st = amcache.stat()
            sources.append({"type": "Amcache metadata only", "path": str(amcache), "status": "available", "size_bytes": st.st_size,
                            "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"),
                            "note": "В этой версии проверяются наличие и метаданные; активный registry hive не разбирается."})
        else:
            sources.append(_source_status(str(amcache), "not_found", "Amcache.hve отсутствует по стандартному пути."))
    except PermissionError as exc:
        sources.append(_source_status(str(amcache), "inaccessible", str(exc)))
    except Exception as exc:
        sources.append(_source_status(str(amcache), "error", str(exc)))

    srum = system_root / "System32" / "sru" / "SRUDB.dat"
    try:
        if srum.is_file():
            st = srum.stat()
            sources.append({"type": "SRUM metadata only", "path": str(srum), "status": "available", "size_bytes": st.st_size,
                            "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"),
                            "note": "База ESE обнаружена. Содержимое SRUM не извлекается и не разбирается этой версией."})
        else:
            sources.append(_source_status(str(srum), "not_found", "SRUDB.dat отсутствует по стандартному пути."))
    except PermissionError as exc:
        sources.append(_source_status(str(srum), "inaccessible", str(exc)))
    except Exception as exc:
        sources.append(_source_status(str(srum), "error", str(exc)))

    # USN Journal: query availability metadata only; never enumerate file names here.
    progress("Проверка состояния USN-журнала…")
    try:
        drive = system_root.anchor or "C:\\"
        proc = subprocess.run(["fsutil", "usn", "queryjournal", drive], capture_output=True, text=False, timeout=8, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        stdout_text, _stdout_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
        stderr_text, _stderr_encoding = decode_text_bytes(proc.stderr or b"", prefer_oem=True)
        if proc.returncode == 0:
            lines = [line.strip() for line in stdout_text.splitlines() if re.search(r"(?i)(journal id|first usn|next usn|lowest valid usn|maximum size|allocation delta|идентификатор журнала|первый usn|следующий usn)", line)]
            sources.append({"type": "USN Journal metadata", "path": drive, "status": "available", "metadata": lines[:12],
                            "note": "Проверена только доступность журнала; список операций и имён файлов не извлекается."})
            events.append(_event("Windows: файловая система", "USN-журнал доступен (метаданные)", f"fsutil usn queryjournal {drive}", datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"), "Время проверки, не время файлового события", {"metadata": lines[:12]}))
        else:
            detail = (stderr_text or stdout_text or "").strip()
            sources.append(_source_status("USN Journal " + drive, "inaccessible", detail[:400] or "Требуются права или журнал недоступен."))
            warnings.append("USN-журнал не удалось проверить; возможно, требуются права администратора.")
    except Exception as exc:
        sources.append(_source_status("USN Journal", "error", str(exc)))
        warnings.append(f"Не удалось проверить состояние USN-журнала: {exc}")

    # One compact source-index event helps show which channels were available.
    available = sum(1 for row in sources if row.get("status") == "available")
    unavailable = sum(1 for row in sources if row.get("status") in {"inaccessible", "not_found", "timeout", "error"})
    events.append(_event("Сводка источников", f"Доступно источников: {available}; недоступно/не найдено: {unavailable}", "Индекс источников Python Activity View", datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"), "Время проверки", {
        "available_sources": available,
        "unavailable_or_missing_sources": unavailable,
        "statuses": [{"path": r.get("path", ""), "status": r.get("status", "unknown"), "type": r.get("type", "")} for r in sources],
    }))
    return events, sources, warnings


def scan_local_review(progress: Callable[[str], None]) -> dict[str, Any]:
    events: list[dict] = []
    sources: list[dict] = []
    warnings: list[str] = []
    progress("Проверка дополнительных диагностических журналов AnyDesk (если доступны)…")
    e, s, w = scan_anydesk(progress)
    events.extend(e); sources.extend(s); warnings.extend(w)
    progress("Проверка доступных локальных журналов Windows…")
    e, s, w = _windows_markers(progress)
    events.extend(e); sources.extend(s); warnings.extend(w)
    progress("Индексирование дополнительных Windows-артефактов (Prefetch, LNK, Jump Lists, BAM/UserAssist)…")
    try:
        from pav_330 import scan_artifact_inventory
        inventory = scan_artifact_inventory(progress)
        events.extend(inventory.get("events", []))
        sources.extend(inventory.get("sources", []))
        warnings.extend(inventory.get("warnings", []))
    except Exception as exc:
        warnings.append(f"Расширенный каталог Windows-артефактов недоступен: {type(exc).__name__}: {exc}")
    events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    status_counts: dict[str, int] = {}
    for source in sources:
        status = str(source.get("status", "unknown"))
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "events": events,
        "sources": sources,
        "source_status_counts": status_counts,
        "warnings": warnings,
        "generated_local": datetime.now().astimezone().isoformat(sep=" ", timespec="seconds"),
        "host": platform.node(),
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "platform": platform.platform(),
        "scope": "Универсальный локальный анализ следов Python и связанных процессов на компьютере, где запущена программа. Журналы AnyDesk являются дополнительным необязательным источником. Другие профили и сетевые компьютеры не сканируются.",
        "read_only": True,
    }
