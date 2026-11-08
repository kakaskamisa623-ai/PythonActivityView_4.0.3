from __future__ import annotations

"""Python Activity View 3.4.0 forensic extensions.

All collectors are local and read-only. Optional parsers are loaded only when
needed. Unsupported/locked artefacts are reported as such instead of being
presented as parsed evidence.
"""

import configparser
import contextlib
import io
import hashlib
import json
import os
import re
import shutil
import subprocess
import struct
import math
import sys
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from pav_encoding import read_text_compat, read_python_source_compat, decode_text_bytes

APP_HINTS = (
    "python", "pythonw", "py.exe", "java", "javaw", "pycharm", "jupyter",
    "ipython", "code.exe", "visual studio code", "powershell", "pwsh",
    "cmd.exe", "minecraft", "launcher",
)
PROCESS_EVENT_IDS = {4688, 4689, 4616, 5156, 1102, 4719, 104, 6005, 6006, 6008, 1, 3, 5, 22, 12, 13, 14, 4103, 4104}


def _iso_from_filetime(raw: int) -> str:
    try:
        if raw <= 0:
            return ""
        epoch = (raw - 116444736000000000) / 10_000_000
        return datetime.fromtimestamp(epoch, tz=timezone.utc).astimezone().isoformat(sep=" ", timespec="seconds")
    except Exception:
        return ""


def _event(timestamp: str, kind: str, description: str, source: str, details: dict[str, Any], command: str = "") -> dict[str, Any]:
    return {
        "timestamp": timestamp or "",
        "date": timestamp[:10] if timestamp else "",
        "time": timestamp[11:19] if len(timestamp) >= 19 else "",
        "time_basis": "Время исходного артефакта" if timestamp else "Временная метка отсутствует в источнике",
        "kind": kind,
        "description": description,
        "command": command,
        "source": source,
        "user": "",
        "details": details,
    }


def _file_meta(path: Path, hash_limit: int = 64 * 1024 * 1024) -> dict[str, Any]:
    st = path.stat()
    result: dict[str, Any] = {
        "path": str(path),
        "size_bytes": st.st_size,
        "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"),
        "created_or_changed_local": datetime.fromtimestamp(st.st_ctime).astimezone().isoformat(sep=" ", timespec="seconds"),
    }
    if st.st_size <= hash_limit:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result["sha256"] = digest.hexdigest()
    else:
        result["sha256"] = "not_computed_over_limit"
    return result


def _looks_relevant(text: str) -> bool:
    low = str(text or "").casefold()
    return any(hint in low for hint in APP_HINTS)


def _walk_small(directory: Path, suffixes: set[str], max_items: int = 3000) -> list[Path]:
    found: list[Path] = []
    if not directory.is_dir():
        return found
    try:
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d.casefold() not in {"cache", "temp", "thumbnails"}]
            for filename in files:
                path = Path(root) / filename
                if path.suffix.casefold() in suffixes:
                    found.append(path)
                    if len(found) >= max_items:
                        return found
    except (PermissionError, OSError):
        return found
    return found


def _read_userassist() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return events, [{"type": "UserAssist registry", "status": "not_applicable", "note": "Требуется Windows."}], warnings
    try:
        import winreg
        root_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, root_path, 0, winreg.KEY_READ) as root:
            total = 0
            for i in range(winreg.QueryInfoKey(root)[0]):
                guid = winreg.EnumKey(root, i)
                count_path = root_path + "\\" + guid + r"\Count"
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path, 0, winreg.KEY_READ) as count_key:
                        for j in range(winreg.QueryInfoKey(count_key)[1]):
                            value_name, _value_data, _value_type = winreg.EnumValue(count_key, j)
                            decoded = value_name.translate(str.maketrans(
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                            ))
                            if not _looks_relevant(decoded):
                                continue
                            events.append(_event(
                                "", "Windows UserAssist: reference",
                                "UserAssist содержит запись пути/имени приложения; счётчик и успешный запуск отдельно не интерпретируются.",
                                "HKCU\\" + count_path,
                                {"value_name_rot13": value_name, "decoded_value_name": decoded,
                                 "note": "UserAssist — вспомогательный артефакт активности оболочки. Запись имени не доказывает успешное выполнение."},
                                decoded,
                            ))
                            total += 1
                            if total >= 500:
                                break
                    if total >= 500:
                        break
                except OSError as exc:
                    warnings.append(f"UserAssist {guid}: {exc}")
            sources.append({"type": "UserAssist registry", "status": "available", "matched_records": total,
                            "path": "HKCU\\" + root_path,
                            "note": "Чтение только подходящих имён значений; реестр не изменяется."})
    except FileNotFoundError:
        sources.append({"type": "UserAssist registry", "status": "not_found", "note": "Ключ UserAssist отсутствует."})
    except PermissionError as exc:
        sources.append({"type": "UserAssist registry", "status": "inaccessible", "note": str(exc)})
    except Exception as exc:
        sources.append({"type": "UserAssist registry", "status": "error", "note": f"{type(exc).__name__}: {exc}"})
    return events, sources, warnings


def _read_bam() -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    events: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return events, [{"type": "BAM/DAM registry", "status": "not_applicable", "note": "Требуется Windows."}], warnings
    try:
        import winreg
        matched_total = 0
        found_any = False
        for service in ("bam", "dam"):
            base = rf"SYSTEM\CurrentControlSet\Services\{service}\State\UserSettings"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ) as root:
                    found_any = True
                    sid_count = winreg.QueryInfoKey(root)[0]
                    matched = 0
                    for i in range(sid_count):
                        sid = winreg.EnumKey(root, i)
                        try:
                            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sid, 0, winreg.KEY_READ) as key:
                                for j in range(winreg.QueryInfoKey(key)[1]):
                                    name, data, _typ = winreg.EnumValue(key, j)
                                    if not _looks_relevant(name):
                                        continue
                                    stamp = ""
                                    if isinstance(data, bytes) and len(data) >= 8:
                                        stamp = _iso_from_filetime(int.from_bytes(data[:8], "little", signed=False))
                                    events.append(_event(
                                        stamp, f"Windows {service.upper()}: activity reference",
                                        f"{service.upper()} содержит запись активности приложения; трактовка зависит от версии Windows и структуры значения.",
                                        "HKLM\\" + base + "\\" + sid,
                                        {"sid": sid, "image_path": name,
                                         "timestamp_basis": "FILETIME из первых 8 байт значения" if stamp else "FILETIME не распознан",
                                         "note": f"{service.upper()}-запись — supporting artifact; сама по себе не определяет назначение файла."},
                                        name,
                                    ))
                                    matched += 1; matched_total += 1
                                    if matched_total >= 500:
                                        break
                            if matched_total >= 500:
                                break
                        except OSError as exc:
                            warnings.append(f"{service.upper()} {sid}: {exc}")
                sources.append({"type": f"{service.upper()} registry", "status": "available", "matched_records": matched,
                                "path": "HKLM\\" + base,
                                "note": "Чтение только для просмотра. Для HKLM может потребоваться повышенный доступ."})
            except FileNotFoundError:
                sources.append({"type": f"{service.upper()} registry", "status": "not_found", "path": "HKLM\\" + base,
                                "note": "Ветка отсутствует или не поддерживается этой системой."})
            except PermissionError as exc:
                sources.append({"type": f"{service.upper()} registry", "status": "inaccessible", "path": "HKLM\\" + base, "note": str(exc)})
        if not found_any:
            warnings.append("BAM/DAM registry keys were not accessible or were not present.")
    except FileNotFoundError:
        sources.append({"type": "BAM registry", "status": "not_found", "note": "Ключ BAM отсутствует; на некоторых версиях/системах это ожидаемо."})
    except PermissionError as exc:
        sources.append({"type": "BAM registry", "status": "inaccessible", "note": str(exc)})
    except Exception as exc:
        sources.append({"type": "BAM registry", "status": "error", "note": f"{type(exc).__name__}: {exc}"})
    return events, sources, warnings


def parse_prefetch_header(path: Path) -> dict[str, Any]:
    """Parse stable Prefetch header fields without guessing version-dependent offsets."""
    path = Path(path)
    with path.open("rb") as stream:
        head = stream.read(512)
    if head.startswith(b"MAM"):
        return {"path": str(path), "status": "compressed_mam",
                "note": "Обнаружен сжатый MAM Prefetch. Встроенный декомпрессор не используется; нужен совместимый специализированный парсер."}
    if len(head) < 84 or head[4:8] != b"SCCA":
        return {"path": str(path), "status": "unknown_format", "note": "Заголовок Prefetch не распознан."}
    version = int.from_bytes(head[0:4], "little")
    raw_name = head[16:76]
    try:
        exe_name = raw_name.decode("utf-16le", errors="ignore").split("\x00", 1)[0]
    except Exception:
        exe_name = ""
    result = {"path": str(path), "status": "header_parsed", "format_version": version,
              "executable_name": exe_name, "prefetch_hash": int.from_bytes(head[76:80], "little"),
              "note": "Извлечены только стабильные поля заголовка. Поля запуска/времени не интерпретируются без версии-зависимого декодера."}
    return result



def parse_prefetch_file(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Parse one selected Prefetch file using the optional Dissect parser.

    The parser's reported timestamps are preserved as source values. The
    function does not infer an execution interval or claim the parser is
    validated against every Windows Prefetch generation.
    """
    path = Path(path)
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta: dict[str, Any] = {"type": "Prefetch", "path": str(path), "status": "error"}
    if not path.is_file():
        return events, meta, [f"Файл не найден: {path}"]
    if path.stat().st_size <= 0 or path.stat().st_size > 128 * 1024 * 1024:
        return events, meta, ["Файл пустой или превышает 128 MiB; импорт остановлен по защитному лимиту."]
    header = parse_prefetch_header(path)
    if header.get("status") == "compressed_mam":
        return events, {**meta, "status": "compressed_unsupported", "header": header}, [
            "Сжатый MAM Prefetch не передан декодеру: требуется совместимая версия парсера, поддерживающая этот вариант."]
    if header.get("status") != "header_parsed":
        return events, {**meta, "status": "unknown_format", "header": header}, [
            "Формат заголовка Prefetch не распознан; запись не интерпретировалась."]
    try:
        from dissect.target.plugins.os.windows.prefetch import Prefetch
    except Exception:
        return events, {**meta, "status": "parser_unavailable", "header": header}, [
            "Для подробного разбора Prefetch установите необязательный пакет dissect.target: python -m pip install dissect.target"]
    try:
        with path.open("rb") as stream:
            parser = Prefetch(stream)
            parser.parse()
            latest = getattr(parser, "latest_timestamp", None)
            previous = getattr(parser, "previous_timestamps", [])
            previous = previous or []
            info = getattr(parser, "fn", None)
            run_count = None
            if info is not None:
                for attr_name in ("run_count", "RunCount"):
                    try:
                        candidate = getattr(info, attr_name, None)
                        if isinstance(candidate, int) and candidate >= 0:
                            run_count = candidate
                            break
                    except Exception:
                        pass
            latest_text = latest.isoformat(sep=" ", timespec="seconds") if isinstance(latest, datetime) else str(latest or "")
            previous_text = [item.isoformat(sep=" ", timespec="seconds") if isinstance(item, datetime) else str(item)
                             for item in previous if item]
            meta.update({"status": "parsed", "format_version": header.get("format_version"),
                         "executable_name": header.get("executable_name"), "prefetch_hash": header.get("prefetch_hash"),
                         "latest_timestamp": latest_text, "previous_timestamps": previous_text,
                         "parser_reported_run_count": run_count,
                         "previous_timestamp_count": len(previous_text), "size_bytes": path.stat().st_size,
                         "sha256": _file_meta(path).get("sha256", ""),
                         "parser": "dissect.target.plugins.os.windows.prefetch.Prefetch",
                         "note": "Показаны значения, возвращённые установленным парсером. Учитывайте версию Prefetch, версию парсера и необходимость сопоставления с независимыми источниками."})
            for index, stamp in enumerate(previous_text):
                events.append(_event(stamp, "Windows Prefetch: previous run timestamp",
                    "Парсер Prefetch вернул предыдущую временную метку запуска; это не доказывает назначение программы или нарушение.",
                    str(path), {"timestamp_index": index, "executable_name": header.get("executable_name"),
                                "parser": meta["parser"], "note": "Временная метка получена из Prefetch parser; подтвердите её другими источниками."},
                    header.get("executable_name", "")))
            if latest_text:
                events.append(_event(latest_text, "Windows Prefetch: latest run timestamp",
                    "Парсер Prefetch вернул последнюю временную метку; используйте её как один из supporting artifacts.",
                    str(path), {"timestamp_type": "latest", "executable_name": header.get("executable_name"),
                                "parser_reported_run_count": run_count, "parser": meta["parser"],
                                "note": "Prefetch не является самостоятельным доказательством использования стороннего ПО."},
                    header.get("executable_name", "")))
            if not events:
                warnings.append("Prefetch прочитан, но парсер не вернул временные метки запуска.")
    except Exception as exc:
        warnings.append(f"Ошибка разбора Prefetch {path}: {type(exc).__name__}: {exc}")
        meta["status"] = "parse_error"
    return events, meta, warnings


def scan_artifact_inventory(progress: Callable[[str], None] | None = None) -> dict[str, Any]:
    """Read-only inventory of Windows artefact locations and relevant records."""
    progress = progress or (lambda _message: None)
    events: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    warnings: list[str] = []
    if os.name != "nt":
        return {"events": events, "sources": [{"type": "Windows artefact inventory", "status": "not_applicable",
                "note": "Каталог Windows-артефактов доступен только на Windows."}], "warnings": warnings}

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    local = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    recent = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / r"Microsoft\Windows\Recent"
    jump_auto = recent / "AutomaticDestinations"
    jump_custom = recent / "CustomDestinations"

    specs = [
        ("Prefetch", system_root / "Prefetch", {".pf"}, 10000,
         "Список Prefetch-файлов и метаданные; время изменения файла не равно точному времени запуска."),
        ("LNK shortcuts", recent, {".lnk"}, 3000,
         "Ярлыки Recent — вспомогательные сведения о ссылках/документах; содержимое не открывается."),
        ("Automatic Jump Lists", jump_auto, {".automaticdestinations-ms"}, 1500,
         "Файлы Jump Lists обнаружены по наличию и метаданным; полноценный разбор требует выделенного парсера."),
        ("Custom Jump Lists", jump_custom, {".customdestinations-ms"}, 1500,
         "Файлы Jump Lists обнаружены по наличию и метаданным; полноценный разбор требует выделенного парсера."),
    ]
    for label, directory, suffixes, limit, note in specs:
        progress(f"Каталог артефактов: {label}…")
        files = _walk_small(directory, suffixes, limit)
        matched = []
        for path in files:
            try:
                meta = _file_meta(path, hash_limit=8 * 1024 * 1024)
                if label == "Prefetch":
                    try:
                        meta["prefetch_header"] = parse_prefetch_header(path)
                    except Exception as parse_exc:
                        meta["prefetch_header"] = {"status": "error", "note": str(parse_exc)}
                # Prefetch is inventory-wide; LNK/Jump Lists can be many, preserve counts and relevant files.
                if label == "Prefetch" or _looks_relevant(str(path)) or label.endswith("Jump Lists"):
                    matched.append(meta)
                    if label == "Prefetch" and len(matched) <= 1500:
                        events.append(_event(meta.get("modified_local", ""), "Windows Prefetch artifact",
                            f"Найден Prefetch-файл {path.name}; изменение файла не является точной меткой каждого запуска.",
                            str(path), {"size_bytes": meta.get("size_bytes"), "sha256": meta.get("sha256"), "artifact_type": "Prefetch"}))
                    elif label == "LNK shortcuts" and _looks_relevant(path.name):
                        events.append(_event(meta.get("modified_local", ""), "Windows LNK artifact",
                            f"Найден ярлык, имя которого связано с инструментами разработки: {path.name}",
                            str(path), {"size_bytes": meta.get("size_bytes"), "sha256": meta.get("sha256"),
                                        "note": "Цель ярлыка не извлечена без LnkParse3."}))
            except Exception as exc:
                warnings.append(f"{label}: {path}: {exc}")
        status = "available" if directory.is_dir() else "not_found"
        sources.append({"type": label, "path": str(directory), "status": status,
                        "files_seen": len(files), "records_indexed": len(matched), "sample": matched[:80], "note": note})

    for label, path, note in (
        ("Amcache hive", system_root / "AppCompat" / "Programs" / "Amcache.hve",
         "Обнаружен hive Amcache. Живой системный hive не экспортируется; для полного разбора используйте офлайн-копию."),
        ("SRUM ESE database", system_root / "System32" / "sru" / "SRUDB.dat",
         "Обнаружена ESE-база SRUM. Для полного разбора нужна копия базы и необязательный dissect.database."),
    ):
        try:
            if path.is_file():
                meta = _file_meta(path, hash_limit=0)
                sources.append({"type": label, "status": "available_metadata_only", **meta, "note": note})
            else:
                sources.append({"type": label, "status": "not_found", "path": str(path), "note": note})
        except PermissionError as exc:
            sources.append({"type": label, "status": "inaccessible", "path": str(path), "note": str(exc)})
        except Exception as exc:
            sources.append({"type": label, "status": "error", "path": str(path), "note": str(exc)})

    e, s, w = _read_userassist(); events.extend(e); sources.extend(s); warnings.extend(w)
    e, s, w = _read_bam(); events.extend(e); sources.extend(s); warnings.extend(w)

    # USN query only checks journal metadata. It does not enumerate file names or records.
    progress("Проверяю доступность USN-журнала (только метаданные)…")
    fsutil = shutil.which("fsutil.exe") or shutil.which("fsutil")
    if fsutil:
        for drive in sorted({(system_root.anchor or "C:\\")[:2], (Path.home().anchor or "C:\\")[:2]}):
            try:
                proc = subprocess.run([fsutil, "usn", "queryjournal", drive + "\\"], capture_output=True,
                    text=False, timeout=8, check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                stdout_text, _stdout_encoding = decode_text_bytes(proc.stdout or b"", prefer_oem=True)
                stderr_text, _stderr_encoding = decode_text_bytes(proc.stderr or b"", prefer_oem=True)
                if proc.returncode == 0:
                    selected = [line.strip() for line in stdout_text.splitlines()
                                if re.search(r"(?i)(journal id|first usn|next usn|lowest valid usn|maximum size|allocation delta|идентификатор журнала|первый usn|следующий usn)", line)]
                    sources.append({"type": "USN Journal metadata", "path": drive + "\\", "status": "available",
                                    "metadata": selected[:12],
                                    "note": "Проверена доступность и метаданные журнала; история имён файлов не извлекается."})
                else:
                    sources.append({"type": "USN Journal metadata", "path": drive + "\\", "status": "inaccessible",
                                    "note": (stderr_text or stdout_text or "Требуются права или журнал недоступен.")[:300]})
            except Exception as exc:
                warnings.append(f"USN {drive}: {exc}")
    else:
        sources.append({"type": "USN Journal metadata", "status": "unsupported", "note": "fsutil.exe недоступен."})
    return {"events": events, "sources": sources, "warnings": warnings}


def _parse_event_xml(xml_text: str, source_path: str, record_id: int | None = None) -> dict[str, Any] | None:
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return None
    def tag(el: ET.Element) -> str:
        return el.tag.rsplit("}", 1)[-1]
    system = next((el for el in root.iter() if tag(el) == "System"), None)
    if system is None:
        return None
    def system_child(name: str) -> str:
        node = next((el for el in system.iter() if tag(el) == name), None)
        return str(node.attrib.get("Name", "") if name == "Provider" and node is not None else ((node.text or "") if node is not None else ""))
    provider_node = next((el for el in system.iter() if tag(el) == "Provider"), None)
    provider = provider_node.attrib.get("Name", "") if provider_node is not None else ""
    event_id_text = system_child("EventID")
    try:
        event_id = int(event_id_text)
    except Exception:
        return None
    time_node = next((el for el in system.iter() if tag(el) == "TimeCreated"), None)
    timestamp = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    if timestamp:
        try:
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).astimezone().isoformat(sep=" ", timespec="seconds")
        except Exception:
            pass
    fields: dict[str, Any] = {}
    for container_name in ("EventData", "UserData"):
        container = next((el for el in root.iter() if tag(el) == container_name), None)
        if container is None:
            continue
        for child in container.iter():
            if child is container:
                continue
            name = child.attrib.get("Name") or tag(child)
            value = (child.text or "").strip()
            if value:
                fields[name] = value
    flat = " ".join(str(v) for v in fields.values())
    low = flat.casefold()
    recognized = event_id in PROCESS_EVENT_IDS
    relevant = _looks_relevant(flat) or event_id in {4616, 1102, 4719, 104, 6005, 6006, 6008}
    # Generic network-filtering events are included only where the program path is relevant.
    if not recognized or (event_id in {5156, 3} and not relevant):
        return None
    names = {
        1: "Sysmon process creation", 3: "Sysmon network connection", 5: "Sysmon process termination",
        22: "Sysmon DNS query", 4688: "Windows process creation", 4689: "Windows process termination",
        4616: "Windows system time changed", 5156: "Windows Filtering Platform connection allowed",
        1102: "Windows Security log cleared", 104: "Windows event log cleared",
        4719: "Windows audit policy changed", 4103: "PowerShell module logging", 4104: "PowerShell script-block logging",
        12: "Sysmon registry create/delete", 13: "Sysmon registry value set", 14: "Sysmon registry key/value rename",
        6005: "Windows Event Log service started", 6006: "Windows Event Log service stopped", 6008: "Unexpected Windows shutdown",
    }
    description = names.get(event_id, f"Windows event {event_id}")
    if event_id in {3, 5156}:
        description += " (network metadata; not packet content)"
    command = ""
    for candidate in ("Image", "NewProcessName", "ProcessName", "Application", "QueryName", "TargetFilename"):
        if fields.get(candidate):
            command = str(fields[candidate]); break
    if event_id == 3:
        command = f"{fields.get('Image', '')} → {fields.get('DestinationHostname', fields.get('DestinationIp', ''))}:{fields.get('DestinationPort', '')}"
    elif event_id == 5156:
        command = f"{fields.get('Application', '')} → {fields.get('DestAddress', '')}:{fields.get('DestPort', '')}"
    details = {
        "event_id": event_id, "provider": provider, "record_id": record_id or system_child("EventRecordID"),
        "computer": system_child("Computer"), "fields": fields,
        "imported_evtx": True,
        "note": "Импортированная запись EVTX. Поля зависят от провайдера, версии Windows и настроек журналирования.",
    }
    return _event(timestamp, "Imported EVTX", description, source_path, details, command)


def import_evtx_file(path: Path, max_records: int = 200_000) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Import relevant event records from EVTX using optional python-evtx."""
    path = Path(path)
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta: dict[str, Any] = {"path": str(path), "type": "Imported EVTX", "status": "error"}
    if not path.is_file():
        return events, meta, [f"Файл не найден: {path}"]
    if path.stat().st_size > 2 * 1024 * 1024 * 1024:
        return events, meta, ["EVTX больше 2 GiB; импорт остановлен по защитному лимиту."]
    try:
        with path.open("rb") as stream:
            signature = stream.read(8)
        if not signature.startswith(b"ElfFile"):
            return events, meta, ["Файл не похож на EVTX: ожидается сигнатура ElfFile."]
        try:
            from Evtx.Evtx import Evtx
        except Exception:
            return events, meta, ["Для импорта EVTX установите необязательный пакет python-evtx: python -m pip install python-evtx"]
        read = 0
        with Evtx(str(path)) as log:
            for record in log.records():
                read += 1
                if read > max_records:
                    warnings.append(f"Достигнут лимит {max_records} записей; остальная часть файла не обработана.")
                    break
                record_num_attr = getattr(record, "record_num", None)
                try:
                    record_num = record_num_attr() if callable(record_num_attr) else record_num_attr
                except Exception:
                    record_num = None
                row = _parse_event_xml(record.xml(), str(path), record_num)
                if row:
                    events.append(row)
        meta.update({"status": "available", "records_read": min(read, max_records), "relevant_records": len(events),
                     "size_bytes": path.stat().st_size,
                     "sha256": _file_meta(path).get("sha256", ""),
                     "note": "Импорт содержит только выбранные классы событий; исходный EVTX не изменён."})
    except Exception as exc:
        warnings.append(f"Не удалось прочитать EVTX {path}: {type(exc).__name__}: {exc}")
    return events, meta, warnings


def _pe_c_string(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    raw = data[offset:end]
    text, _encoding = decode_text_bytes(raw)
    return text.strip()


def _pe_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _pe_extract_strings(data: bytes, limit: int = 500, minimum: int = 5) -> list[dict[str, str]]:
    """Extract printable ASCII, UTF-8/CP1251 and UTF-16LE strings as data."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(raw: bytes, encoding: str, offset: int) -> None:
        if len(found) >= limit:
            return
        try:
            value = raw.decode(encoding, errors="strict").strip(" \t\r\n\x00")
        except (UnicodeDecodeError, LookupError):
            return
        add_value(value, encoding, offset)

    def add_value(value: str, encoding: str, offset: int) -> None:
        if len(found) >= limit:
            return
        value = value.strip(" \t\r\n\x00")
        if len(value) < minimum or value in seen:
            return
        printable = sum(1 for ch in value if ch.isprintable())
        if printable / max(1, len(value)) < 0.9:
            return
        if not any(ch.isalpha() or ch.isdigit() for ch in value):
            return
        seen.add(value)
        found.append({"offset": hex(offset), "encoding": encoding, "value": value[:500]})

    # ASCII / UTF-8 / single-byte legacy strings. Cap the source slice to
    # keep processing bounded even for very large DLLs.
    scan = data[:64 * 1024 * 1024]
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % minimum, scan):
        add(match.group(0), "ascii", match.start())
        if len(found) >= limit:
            return found

    # Wide strings (typical for Win32 APIs and Windows resource text).
    wide_pattern = rb"(?:[\x20-\x7e]\x00){%d,}|(?:[\x00-\xff][\x04-\x05]){%d,}" % (minimum, minimum)
    for match in re.finditer(wide_pattern, scan):
        add(match.group(0), "utf-16-le", match.start())
        if len(found) >= limit:
            return found

    # UTF-8 / CP1251 / CP866 strings are common in newer and legacy Windows binaries.
    # Use strict UTF-8 first, then the compatibility decoder to choose a legacy code page.
    legacy_pattern = rb"[\x20-\xff]{%d,}" % minimum
    for match in re.finditer(legacy_pattern, scan):
        raw = match.group(0)
        if not any(value >= 0x80 for value in raw):
            continue
        decoded, encoding = decode_text_bytes(raw)
        add_value(decoded, encoding, match.start())
        if len(found) >= limit:
            break
    return found


def analyze_pe_static(path: Path, *, include_strings: bool = True,
                      include_disassembly: bool = True,
                      max_disassembly_bytes: int = 128 * 1024,
                      max_instructions: int = 2500) -> dict[str, Any]:
    """Read-only PE/DLL static inspection; never loads or executes the image.

    The built-in parser extracts PE headers, sections, imports, exports and
    strings. Capstone, when installed, adds a bounded assembly listing for
    executable sections. It does not recover original C/C++ source code.
    """
    path = Path(path)
    file_size = path.stat().st_size
    if file_size < 64:
        raise ValueError("Файл слишком мал для PE-образа.")
    if file_size > 512 * 1024 * 1024:
        raise ValueError("Файл больше 512 MiB; анализ остановлен по защитному лимиту.")
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("Нет сигнатуры MZ: файл не похож на PE/DLL.")
    if len(data) < 0x40:
        raise ValueError("Обрезанный DOS-заголовок PE.")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        raise ValueError("Некорректное смещение PE-заголовка.")
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Не найдена сигнатура PE\\0\\0.")

    coff_offset = pe_offset + 4
    machine, section_count, timestamp, _sym_ptr, _sym_count, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, coff_offset)
    optional_offset = coff_offset + 20
    optional_end = optional_offset + optional_size
    if optional_end > len(data) or optional_size < 2:
        raise ValueError("Обрезанный optional header PE.")
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    if magic == 0x10B:
        bitness, image_base_offset, image_base_fmt = 32, 28, "<I"
        number_dirs_offset, dirs_offset = 92, 96
        pointer_size = 4
    elif magic == 0x20B:
        bitness, image_base_offset, image_base_fmt = 64, 24, "<Q"
        number_dirs_offset, dirs_offset = 108, 112
        pointer_size = 8
    else:
        raise ValueError(f"Неподдерживаемый формат optional header: {hex(magic)}")

    def u16(offset: int) -> int:
        return struct.unpack_from("<H", data, offset)[0] if offset + 2 <= len(data) else 0

    def u32(offset: int) -> int:
        return struct.unpack_from("<I", data, offset)[0] if offset + 4 <= len(data) else 0

    def u64(offset: int) -> int:
        return struct.unpack_from("<Q", data, offset)[0] if offset + 8 <= len(data) else 0

    entry_point = u32(optional_offset + 16)
    image_base = (u32(optional_offset + image_base_offset) if bitness == 32
                  else u64(optional_offset + image_base_offset))
    size_of_image = u32(optional_offset + 56)
    size_of_headers = u32(optional_offset + 60)
    subsystem_code = u16(optional_offset + 68)
    dll_characteristics = u16(optional_offset + 70)
    directory_count = min(u32(optional_offset + number_dirs_offset), 16)

    machine_names = {0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM", 0x01C2: "ARM Thumb", 0x01C4: "ARMv7", 0xAA64: "ARM64"}
    subsystem_names = {1: "Native", 2: "Windows GUI", 3: "Windows Console", 7: "POSIX Console", 9: "Windows CE GUI", 10: "EFI Application", 14: "Xbox"}
    char_flags = {
        "is_dll": bool(characteristics & 0x2000),
        "large_address_aware": bool(characteristics & 0x0020),
        "executable_image": bool(characteristics & 0x0002),
        "relocations_stripped": bool(characteristics & 0x0001),
    }
    dll_flags = {
        "dynamic_base_aslr": bool(dll_characteristics & 0x0040),
        "force_integrity": bool(dll_characteristics & 0x0080),
        "nx_compatible_dep": bool(dll_characteristics & 0x0100),
        "no_isolation": bool(dll_characteristics & 0x0200),
        "no_seh": bool(dll_characteristics & 0x0400),
        "control_flow_guard": bool(dll_characteristics & 0x4000),
        "high_entropy_va": bool(dll_characteristics & 0x0020),
    }

    sections: list[dict[str, Any]] = []
    section_rows: list[dict[str, int | str]] = []
    section_offset = optional_end
    if section_offset + section_count * 40 > len(data):
        raise ValueError("Таблица секций выходит за границы файла.")
    for index in range(min(section_count, 96)):
        off = section_offset + index * 40
        raw_name = data[off:off + 8].split(b"\x00", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError:
            name = raw_name.decode("cp1251", errors="replace")
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, off + 8)
        flags = struct.unpack_from("<I", data, off + 36)[0]
        raw_end = min(len(data), raw_pointer + raw_size)
        raw_blob = data[raw_pointer:raw_end] if raw_pointer < len(data) else b""
        row = {
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_pointer": raw_pointer,
            "characteristics": hex(flags),
            "executable": bool(flags & 0x20000000),
            "readable": bool(flags & 0x40000000),
            "writable": bool(flags & 0x80000000),
            "entropy": round(_pe_entropy(raw_blob), 3) if raw_blob else 0.0,
        }
        sections.append(row)
        section_rows.append({"name": name, "virtual_address": virtual_address,
                             "virtual_size": virtual_size, "raw_pointer": raw_pointer,
                             "raw_size": raw_size})

    def rva_to_offset(rva: int) -> int | None:
        if rva < 0:
            return None
        if rva < size_of_headers and rva < len(data):
            return rva
        for section in section_rows:
            start = int(section["virtual_address"])
            size = max(int(section["virtual_size"]), int(section["raw_size"]))
            if start <= rva < start + size:
                candidate = int(section["raw_pointer"]) + (rva - start)
                return candidate if 0 <= candidate < len(data) else None
        return None

    directories: list[tuple[int, int]] = []
    for index in range(directory_count):
        off = optional_offset + dirs_offset + index * 8
        if off + 8 > optional_end:
            break
        directories.append(struct.unpack_from("<II", data, off))

    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    import_dir = directories[1] if len(directories) > 1 else (0, 0)
    import_offset = rva_to_offset(import_dir[0]) if import_dir[0] else None
    if import_offset is not None:
        descriptor_size = 20
        for descriptor_index in range(5000):
            off = import_offset + descriptor_index * descriptor_size
            if off + descriptor_size > len(data):
                break
            original_thunk, _time, _chain, name_rva, first_thunk = struct.unpack_from("<IIIII", data, off)
            if not any((original_thunk, _time, _chain, name_rva, first_thunk)):
                break
            name_offset = rva_to_offset(name_rva)
            dll_name = _pe_c_string(data, name_offset) if name_offset is not None else "<invalid DLL name RVA>"
            thunk_rva = original_thunk or first_thunk
            thunk_offset = rva_to_offset(thunk_rva) if thunk_rva else None
            function_names: list[str] = []
            if thunk_offset is not None:
                ordinal_mask = (1 << (pointer_size * 8 - 1))
                for thunk_index in range(4096):
                    item_offset = thunk_offset + thunk_index * pointer_size
                    if item_offset + pointer_size > len(data):
                        break
                    value = int.from_bytes(data[item_offset:item_offset + pointer_size], "little")
                    if value == 0:
                        break
                    if value & ordinal_mask:
                        function_names.append(f"ordinal #{value & 0xffff}")
                    else:
                        hint_offset = rva_to_offset(value & (ordinal_mask - 1))
                        if hint_offset is not None and hint_offset + 2 <= len(data):
                            function_names.append(_pe_c_string(data, hint_offset + 2, 256) or "<unnamed import>")
                    if len(function_names) >= 4096:
                        break
            imports.append({"dll": dll_name, "functions": function_names,
                            "function_count": len(function_names)})
            if len(imports) >= 1000:
                break

    export_dir = directories[0] if directories else (0, 0)
    export_offset = rva_to_offset(export_dir[0]) if export_dir[0] else None
    if export_offset is not None and export_offset + 40 <= len(data):
        (characteristics_e, time_e, major_e, minor_e, name_rva, ordinal_base,
         number_functions, number_names, address_functions, address_names,
         address_ordinals) = struct.unpack_from("<IIHHIIIIIII", data, export_offset)
        module_name_offset = rva_to_offset(name_rva) if name_rva else None
        module_name = _pe_c_string(data, module_name_offset) if module_name_offset is not None else ""
        names_offset = rva_to_offset(address_names) if address_names else None
        ordinals_offset = rva_to_offset(address_ordinals) if address_ordinals else None
        funcs_offset = rva_to_offset(address_functions) if address_functions else None
        if names_offset is not None and ordinals_offset is not None:
            for idx in range(min(number_names, 10000)):
                noff = names_offset + idx * 4
                ooff = ordinals_offset + idx * 2
                if noff + 4 > len(data) or ooff + 2 > len(data):
                    break
                function_name_rva = u32(noff)
                ordinal_index = u16(ooff)
                function_name_offset = rva_to_offset(function_name_rva)
                function_rva = u32(funcs_offset + ordinal_index * 4) if funcs_offset is not None else 0
                exports.append({"name": _pe_c_string(data, function_name_offset) if function_name_offset is not None else "",
                                "ordinal": ordinal_base + ordinal_index,
                                "rva": hex(function_rva),
                                "forwarded": bool(export_dir[0] <= function_rva < export_dir[0] + export_dir[1])})

    timestamp_text = ""
    try:
        timestamp_text = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat() if timestamp else ""
    except (OverflowError, OSError, ValueError):
        pass

    # API families are context indicators for a human reviewer, not verdicts.
    imported_api_names = {
        str(function).split("!", 1)[-1].casefold()
        for item in imports for function in item.get("functions", [])
    }
    api_families = {
        "process_memory": {"openprocess", "readprocessmemory", "writeprocessmemory",
                           "virtualallocex", "virtualprotectex", "ntreadvirtualmemory",
                           "ntwritevirtualmemory", "ntqueryvirtualmemory"},
        "remote_thread_or_apc": {"createremotethread", "ntcreatethreadex", "queueuserapc",
                                  "setthreadcontext", "resumethread"},
        "input_or_window_hooks": {"getasynckeystate", "getkeystate", "setwindowshookexw",
                                  "setwindowshookexa", "registerrawinputdevices", "getrawinputdata"},
        "graphics_or_overlay": {"direct3dcreate9", "d3d11createdevice", "createdxgifactory",
                                "wglswapbuffers", "swapbuffers", "glbegin"},
        "network": {"wsastartup", "connect", "internetopenw", "internetopenurlw",
                    "winhttpopen", "winhttpsendrequest", "urldownloadtofilew"},
    }
    api_indicators = []
    for family, names in api_families.items():
        matched = sorted(name for name in imported_api_names if name in names)
        if matched:
            api_indicators.append({"family": family, "matched_imports": matched,
                                   "meaning": "API присутствует в таблице импортов; наличие импорта не доказывает фактическое использование функции."})
    packed_sections = [section["name"] for section in sections if section.get("entropy", 0) >= 7.2]
    writable_executable_sections = [section["name"] for section in sections
                                    if section.get("writable") and section.get("executable")]

    result: dict[str, Any] = {
        "parser": "Python Activity View built-in PE reader",
        "file_format": "PE32+" if bitness == 64 else "PE32",
        "machine": machine_names.get(machine, f"Unknown ({hex(machine)})"),
        "machine_code": hex(machine),
        "bitness": bitness,
        "characteristics": {**char_flags, "raw": hex(characteristics)},
        "dll_characteristics": {**dll_flags, "raw": hex(dll_characteristics)},
        "subsystem": subsystem_names.get(subsystem_code, f"Unknown ({subsystem_code})"),
        "entry_point_rva": hex(entry_point),
        "entry_point_va": hex(image_base + entry_point),
        "image_base": hex(image_base),
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "linker_timestamp_utc": timestamp_text,
        "sections": sections,
        "imports": imports,
        "import_dll_count": len(imports),
        "import_function_count": sum(len(item["functions"]) for item in imports),
        "exports": exports,
        "export_count": len(exports),
        "api_indicators": api_indicators,
        "high_entropy_sections_review_hint": packed_sections,
        "writable_executable_sections_review_hint": writable_executable_sections,
        "execution_performed": False,
        "analysis_note": "Статический разбор байтов PE. Файл не загружался в процесс и не исполнялся. Высокая энтропия/импорты сами по себе не доказывают вредоносность.",
    }
    if include_strings:
        result["strings"] = _pe_extract_strings(data)
        result["strings_truncated"] = len(data) > 64 * 1024 * 1024

    if include_disassembly:
        try:
            import capstone
            arch_mode = None
            if machine == 0x014C:
                arch_mode = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif machine == 0x8664:
                arch_mode = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif machine == 0xAA64:
                arch_mode = (capstone.CS_ARCH_ARM64, 0)
            elif machine in {0x01C0, 0x01C2, 0x01C4}:
                arm_mode = capstone.CS_MODE_THUMB if machine == 0x01C2 else capstone.CS_MODE_ARM
                arch_mode = (capstone.CS_ARCH_ARM, arm_mode)
            if arch_mode is None:
                result["disassembly"] = {"status": "unsupported_architecture", "instructions": [],
                                         "note": f"Capstone не настроен для machine={hex(machine)}."}
            else:
                decoder = capstone.Cs(*arch_mode)
                decoder.detail = False
                listing: list[dict[str, str]] = []
                remaining = max(0, int(max_disassembly_bytes))
                truncated = False
                for section in sections:
                    if not section["executable"] or remaining <= 0:
                        continue
                    offset = int(section["raw_pointer"])
                    size = min(int(section["raw_size"]), remaining)
                    blob = data[offset:offset + size] if offset < len(data) else b""
                    base = image_base + int(section["virtual_address"])
                    consumed = 0
                    for insn in decoder.disasm(blob, base):
                        listing.append({"address": hex(insn.address), "bytes": insn.bytes.hex(" "),
                                        "mnemonic": insn.mnemonic, "operands": insn.op_str,
                                        "section": str(section["name"])})
                        consumed = max(consumed, (insn.address - base) + len(insn.bytes))
                        if len(listing) >= max_instructions:
                            truncated = True
                            break
                    remaining -= size
                    if len(listing) >= max_instructions:
                        break
                result["disassembly"] = {
                    "status": "available" if listing else "no_instructions",
                    "engine": f"Capstone {getattr(capstone, '__version__', 'unknown')}",
                    "instructions": listing,
                    "instruction_count": len(listing),
                    "truncated": truncated or remaining <= 0,
                    "note": "Это машинные инструкции, а не исходный C/C++ код. Для анализа неизвестных бинарников вывод нужно интерпретировать с учётом архитектуры и контекста.",
                }
        except ImportError:
            result["disassembly"] = {
                "status": "optional_dependency_missing", "instructions": [],
                "note": "Для просмотра машинных инструкций установите пакет Capstone: python -m pip install capstone. Заголовки, импорты, экспорты и строки уже разобраны без него.",
            }
        except Exception as exc:
            result["disassembly"] = {"status": "error", "instructions": [],
                                     "note": f"Не удалось выполнить статическую дизассемблировку: {type(exc).__name__}: {exc}"}
    else:
        result["disassembly"] = {"status": "skipped", "instructions": []}

    # Optional pefile enrichment: version resources and CLR/managed metadata.
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        directory_names = ("IMAGE_DIRECTORY_ENTRY_RESOURCE", "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")
        selected_directories = [pefile.DIRECTORY_ENTRY[name] for name in directory_names
                                if name in getattr(pefile, "DIRECTORY_ENTRY", {})]
        try:
            pe.parse_data_directories(directories=selected_directories)
        except Exception:
            pass
        clr_directory = bool(getattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR", None))
        try:
            directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
            clr_directory = clr_directory or (len(directories) > 14 and
                bool(directories[14].VirtualAddress and directories[14].Size))
        except Exception:
            pass
        result["pefile"] = {"version": getattr(pefile, "__version__", "installed"),
                            "has_clr_directory": clr_directory}
        try:
            version_values = []
            for file_info in getattr(pe, "FileInfo", []) or []:
                for string_table in getattr(file_info, "StringTable", []) or []:
                    for key, value in getattr(string_table, "entries", {}).items():
                        try:
                            key_text = decode_text_bytes(key)[0] if isinstance(key, bytes) else str(key)
                            value_text = decode_text_bytes(value)[0] if isinstance(value, bytes) else str(value)
                            version_values.append({key_text: value_text})
                        except Exception:
                            continue
            if version_values:
                result["version_resource_summary"] = version_values[:80]
        except Exception:
            pass
        pe.close()
    except ImportError:
        result["pefile"] = {"status": "not_installed", "note": "Дополнительный pefile не установлен; встроенный PE-парсер использован самостоятельно."}
    except Exception as exc:
        result["pefile"] = {"status": "optional_parser_error", "note": f"{type(exc).__name__}: {exc}"}

    return result


def inspect_file(path: Path, signature_check: bool = True) -> dict[str, Any]:
    """Static file metadata inspection. Never executes the target file."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    st = path.stat()
    if st.st_size > 512 * 1024 * 1024:
        raise ValueError("Файл больше 512 MiB; анализ остановлен по защитному лимиту.")
    result: dict[str, Any] = {"path": str(path), "name": path.name, "size_bytes": st.st_size,
        "modified_local": datetime.fromtimestamp(st.st_mtime).astimezone().isoformat(sep=" ", timespec="seconds"),
        "extension": path.suffix.casefold(), "sha256": _file_meta(path)["sha256"],
        "execution_performed": False,
        "note": "Файл только прочитан как данные. Он не запускался и не распаковывался на диск."}
    with path.open("rb") as stream:
        head = stream.read(4096)
    if head.startswith(b"MZ"):
        result["file_type"] = "PE executable / DLL (MZ signature)"
        try:
            result["pe_analysis"] = analyze_pe_static(path)
        except Exception as pe_exc:
            result["pe_analysis"] = {"status": "parse_error", "note": f"{type(pe_exc).__name__}: {pe_exc}",
                                     "execution_performed": False}
        if len(head) >= 64:
            pe_offset = int.from_bytes(head[0x3C:0x40], "little")
            if 0 < pe_offset <= 1024 * 1024:
                with path.open("rb") as stream:
                    stream.seek(pe_offset)
                    pe = stream.read(256)
                if pe[:4] == b"PE\0\0" and len(pe) >= 24:
                    result["pe_machine"] = hex(int.from_bytes(pe[4:6], "little"))
                    result["pe_sections"] = int.from_bytes(pe[6:8], "little")
                    result["pe_timestamp_utc"] = datetime.fromtimestamp(int.from_bytes(pe[8:12], "little"), tz=timezone.utc).isoformat()
                    optional_size = int.from_bytes(pe[20:22], "little")
                    result["pe_optional_header_size"] = optional_size
    elif head.startswith(b"PK\x03\x04") or path.suffix.casefold() in {".jar", ".zip"}:
        result["file_type"] = "ZIP/JAR archive"
        try:
            with zipfile.ZipFile(path, "r") as archive:
                names = archive.namelist()
                result["archive_entries"] = len(names)
                result["archive_name_samples"] = names[:80]
                manifest_name = next((n for n in names if n.casefold() == "meta-inf/manifest.mf"), None)
                if manifest_name:
                    raw, _manifest_encoding = decode_text_bytes(archive.read(manifest_name)[:256 * 1024])
                    result["manifest"] = {line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
                                           for line in raw.splitlines() if ":" in line and not line.startswith(" ")}
        except Exception as exc:
            result["archive_error"] = f"{type(exc).__name__}: {exc}"
    elif path.suffix.casefold() in {".py", ".pyw", ".pyi"}:
        result["file_type"] = "Python source (not executed)"
        try:
            import ast
            text, source_encoding = read_python_source_compat(path)
            result["source_encoding"] = source_encoding
            tree = ast.parse(text, filename=path.name)
            result["python_syntax"] = "valid"
            result["python_top_level_nodes"] = len(tree.body)
        except SyntaxError as exc:
            result["python_syntax"] = "syntax_error"
            result["python_syntax_error"] = {"line": exc.lineno, "message": exc.msg}
    else:
        result["file_type"] = "Unknown / data file"
        result["header_hex"] = head[:32].hex(" ")

    # Mark-of-the-Web (Zone.Identifier) is an NTFS alternate data stream.
    zone_path = Path(str(path) + ":Zone.Identifier") if os.name == "nt" else None
    if zone_path:
        try:
            zone_text, _zone_encoding = read_text_compat(zone_path)
            parser = configparser.ConfigParser()
            parser.read_string(zone_text)
            section = parser["ZoneTransfer"] if parser.has_section("ZoneTransfer") else {}
            result["zone_identifier"] = {k: section.get(k, "") for k in ("ZoneId", "HostUrl", "ReferrerUrl")}
        except FileNotFoundError:
            result["zone_identifier"] = {"status": "not_present"}
        except Exception as exc:
            result["zone_identifier"] = {"status": "unavailable", "note": str(exc)}
    else:
        result["zone_identifier"] = {"status": "not_checked_non_windows"}

    if signature_check:
        try:
            from pav_features_250 import verify_authenticode
            result["authenticode"] = verify_authenticode(path)
        except Exception as exc:
            result["authenticode"] = {"signature_status": "not_checked", "status_message": str(exc)}
    return result


def build_hourly_heatmap(events: Iterable[dict[str, Any]], days: int = 14, now: datetime | None = None) -> dict[str, Any]:
    """Return counts per local calendar day/hour; this is activity density only."""
    now = now or datetime.now().astimezone()
    start = (now.date() - timedelta(days=max(1, days) - 1))
    counts: dict[str, list[int]] = {}
    for row in events:
        value = str(row.get("timestamp") or "")
        if not value:
            continue
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.astimezone()
            local = dt.astimezone()
            if local.date() < start or local.date() > now.date():
                continue
            key = local.date().isoformat()
            counts.setdefault(key, [0] * 24)[local.hour] += 1
        except Exception:
            continue
    rows = []
    for offset in range(days - 1, -1, -1):
        date_key = (now.date() - timedelta(days=offset)).isoformat()
        rows.append({"date": date_key, "hours": counts.get(date_key, [0] * 24)})
    return {"start_date": start.isoformat(), "end_date": now.date().isoformat(), "rows": rows,
            "total_events": sum(sum(r["hours"]) for r in rows),
            "note": "Плотность событий из доступных источников; пустые интервалы могут означать отсутствие журналирования, а не отсутствие активности."}


def summarize_independent_evidence(events: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate evidence groups so repeated rows from one source do not inflate breadth."""
    groups: dict[str, set[str]] = {}
    counts: dict[str, int] = {}
    for row in events:
        kind = str(row.get("kind", "")).casefold()
        source = str(row.get("source", "")).casefold()
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        eid = details.get("event_id")
        if "browser" in kind or "download" in kind:
            group = "browser"
        elif "prefetch" in kind or "bam" in kind or "userassist" in kind or "amcache" in kind or "srum" in kind:
            group = "windows_artifacts"
        elif "sysmon" in source.casefold() or "sysmon" in kind:
            group = "sysmon"
        elif "security" in source.casefold() or eid in {4688, 4689, 4616, 5156, 1102}:
            group = "windows_security"
        elif "powershell" in source.casefold() or "powershell" in kind:
            group = "powershell"
        elif "python" in kind or "history" in kind or "console" in kind:
            group = "python_history"
        else:
            group = "other"
        groups.setdefault(group, set()).add(source or kind or "unknown")
        counts[group] = counts.get(group, 0) + 1
    return {"independent_source_groups": sorted(k for k, v in groups.items() if v),
            "group_count": len([k for k, v in groups.items() if v]),
            "event_counts_by_group": counts,
            "source_counts_by_group": {k: len(v) for k, v in groups.items()},
            "note": "Группы показывают разнообразие источников, а не вероятность нарушения. Несколько событий из одного источника не считаются независимыми доказательствами."}


def parse_offline_amcache(path: Path, max_records: int = 3000) -> tuple[list[dict[str, Any]], list[str]]:
    """Extract selected app/file inventory values from an offline Amcache hive.

    Requires optional python-registry. The live system hive is not copied or
    modified by this function; callers should pass an offline evidence copy.
    """
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    try:
        from Registry import Registry
    except Exception:
        return events, ["Для офлайн-разбора Amcache установите необязательный пакет python-registry."]
    try:
        reg = Registry.Registry(str(path))
        roots = ("Root\\InventoryApplicationFile", "Root\\InventoryApplication", "Root\\File", "Root\\Programs")
        processed = 0
        for root_name in roots:
            try:
                root = reg.open(root_name)
            except Exception:
                continue
            stack = [(root, 0)]
            while stack and processed < max_records:
                key, depth = stack.pop()
                try:
                    values = {v.name(): v.value() for v in key.values()}
                    joined = " | ".join(f"{k}={v}" for k, v in values.items())
                    name_blob = key.name() + " | " + joined
                    if _looks_relevant(name_blob):
                        selected = {k: str(v)[:1000] for k, v in values.items()
                                    if re.search(r"(?i)(name|path|program|publisher|version|sha|file|time|link)", k)}
                        events.append(_event("", "Amcache: application/file inventory",
                            "В офлайн-hive Amcache найдена запись, связанная с инструментами разработки; это инвентаризационный артефакт, не самостоятельное доказательство запуска.",
                            str(path), {"registry_key": root_name + "\\" + key.name(), "values": selected,
                                        "note": "Содержимое извлечено из явно выбранной офлайн-копии hive."}, joined[:1000]))
                    processed += 1
                    if depth < 3:
                        try:
                            stack.extend((child, depth + 1) for child in key.subkeys())
                        except Exception:
                            pass
                except Exception as exc:
                    warnings.append(f"Amcache key: {exc}")
        if not events:
            warnings.append("Офлайн-hive прочитан, но релевантные записи не обнаружены в проверенных ветках.")
    except Exception as exc:
        warnings.append(f"Не удалось разобрать Amcache: {type(exc).__name__}: {exc}")
    return events, warnings


def parse_srum_database(path: Path, max_records_per_table: int = 20000) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Parse an offline SRUM/ESE database using optional dissect.database."""
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta: dict[str, Any] = {"path": str(path), "type": "SRUM ESE database", "status": "error"}
    try:
        from dissect.database.ese import ESE
    except Exception:
        return events, meta, ["Для офлайн-разбора SRUM установите необязательный пакет dissect.database."]
    try:
        with Path(path).open("rb") as stream:
            db = ESE(stream)
            tables_meta = []
            total = 0
            for table in db.tables():
                table_name = getattr(table, "name", "")
                table_name = table_name() if callable(table_name) else str(table_name)
                count = 0
                iterator = getattr(table, "records", None) or getattr(table, "get_records", None)
                if not callable(iterator):
                    tables_meta.append({"name": table_name, "records_checked": 0, "status": "iterator_unavailable"})
                    continue
                for record in iterator():
                    if count >= max_records_per_table:
                        break
                    count += 1; total += 1
                    try:
                        raw = record.as_dict()
                        normalized = {str(k): str(v)[:1000] for k, v in raw.items()}
                        joined = " | ".join(f"{k}={v}" for k, v in normalized.items())
                        if _looks_relevant(joined):
                            events.append(_event("", "SRUM: relevant application record",
                                "В SRUM обнаружена запись, связанная с инструментами разработки; поле времени/семантика зависят от таблицы и схемы ОС.",
                                str(path) + " :: " + table_name,
                                {"table": table_name, "values": normalized,
                                 "note": "Запись извлечена из выбранной офлайн-копии ESE-базы. Схема SRUM зависит от версии Windows."}, joined[:1000]))
                    except Exception as exc:
                        warnings.append(f"SRUM {table_name}: {exc}")
                tables_meta.append({"name": table_name, "records_checked": count})
            meta.update({"status": "available", "tables": tables_meta, "records_checked": total,
                         "relevant_records": len(events),
                         "note": "Таблицы/записи прочитаны из ESE; интерпретация конкретных столбцов зависит от версии Windows."})
    except Exception as exc:
        warnings.append(f"Не удалось разобрать SRUM: {type(exc).__name__}: {exc}")
    return events, meta, warnings


def _bounded_object(value: Any, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Convert parser objects to bounded JSON-safe data without invoking private fields."""
    if budget is None:
        budget = [4000]
    budget[0] -= 1
    if budget[0] < 0:
        return "<limit reached>"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value if not isinstance(value, str) or len(value) <= 4000 else value[:4000] + "…"
    if isinstance(value, (datetime,)):
        return value.isoformat(sep=" ", timespec="seconds")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"byte_length": len(value), "hex_prefix": value[:64].hex()}
    if depth >= 5:
        return str(value)[:400]
    if isinstance(value, dict):
        return {str(k): _bounded_object(v, depth + 1, budget) for k, v in list(value.items())[:100]}
    if isinstance(value, (list, tuple, set)):
        return [_bounded_object(v, depth + 1, budget) for v in list(value)[:200]]
    try:
        fields = vars(value)
    except Exception:
        fields = {}
    if fields:
        return {str(k): _bounded_object(v, depth + 1, budget)
                for k, v in fields.items() if not str(k).startswith("_") and not callable(v)}
    return str(value)[:400]


def parse_jumplist_file(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Parse a selected Jump List with the optional ANSSI dfir-jumplist-parser package."""
    path = Path(path)
    events: list[dict[str, Any]] = []
    warnings: list[str] = []
    meta: dict[str, Any] = {"type": "Jump List", "path": str(path), "status": "error"}
    if not path.is_file():
        return events, meta, [f"Файл не найден: {path}"]
    if path.stat().st_size <= 0 or path.stat().st_size > 128 * 1024 * 1024:
        return events, meta, ["Файл пустой или больше 128 MiB; импорт остановлен по защитному лимиту."]
    if path.suffix.casefold() not in {".automaticdestinations-ms", ".customdestinations-ms"}:
        return events, meta, ["Ожидается .automaticDestinations-ms или .customDestinations-ms."]
    try:
        from jumplist_parser import parse_jumplist
    except Exception:
        return events, meta, [
            "Для разбора Jump Lists установите необязательный ANSSI parser: "
            "pip install git+https://github.com/ANSSI-FR/dfir-jumplist-parser.git"
        ]
    try:
        with path.open("rb") as stream:
            parsed = parse_jumplist(stream, path=path)
        normalized = _bounded_object(parsed)
        meta.update({"status": "available", "size_bytes": path.stat().st_size,
                     "sha256": _file_meta(path).get("sha256", ""), "parsed_summary": normalized,
                     "note": "Jump List разобран необязательным внешним parser; интерпретируйте дату и цель с учётом типа списка."})
        # Expose entry-level records where the parser yields a conventional .lnk collection.
        links = getattr(parsed, "lnk", None)
        if links is None and isinstance(normalized, dict):
            links = normalized.get("lnk") or normalized.get("links")
        if links is None:
            links = []
        if not isinstance(links, (list, tuple)):
            try:
                links = list(links)
            except Exception:
                links = []
        for index, link in enumerate(list(links)[:1000]):
            detail = _bounded_object(link)
            if isinstance(detail, dict):
                encoded = json.dumps(detail, ensure_ascii=False, default=str)
                target = ""
                for key in ("local_path", "path", "target", "full_path", "network_path"):
                    if detail.get(key):
                        target = str(detail[key]); break
                event_time = ""
                for key in ("modification_time", "last_modified", "last_access_time"):
                    value = detail.get(key)
                    if value:
                        event_time = str(value); break
                events.append(_event(event_time, "Windows Jump List entry",
                    "Извлечена запись из Jump List; last-used timestamp относится к самой записи, а не обязательно к запуску программы.",
                    str(path), {"entry_index": index, "target_hint": target,
                                "entry": detail, "note": "Jump List фиксирует недавние/частые элементы и контекст приложения; не доказывает запуск конкретного исполняемого файла."},
                    target or encoded[:1000]))
            else:
                events.append(_event("", "Windows Jump List entry", "Извлечена запись Jump List без распознанных полей.",
                    str(path), {"entry_index": index, "entry": detail}))
        if not events:
            # Preserve the parsed object even when a library version exposes another schema.
            events.append(_event("", "Windows Jump List parsed", "Файл успешно разобран; структура записей сохранена в источнике.",
                str(path), {"parsed_summary": normalized, "note": "Схема parser не предоставила список .lnk напрямую."}))
    except Exception as exc:
        warnings.append(f"Ошибка разбора Jump List {path}: {type(exc).__name__}: {exc}")
    return events, meta, warnings


def parse_lnk_file(path: Path) -> tuple[dict[str, Any] | None, str]:
    """Parse a single LNK through optional LnkParse3; otherwise metadata only."""
    try:
        import LnkParse3
        with Path(path).open("rb") as stream, contextlib.redirect_stdout(io.StringIO()) as captured:
            parsed = LnkParse3.lnk_file(stream)
            output = parsed.print_json()
        raw = output if isinstance(output, str) else captured.getvalue()
        if isinstance(raw, str) and raw.strip():
            try:
                return json.loads(raw), "parsed"
            except Exception:
                return {"parser_output": raw[:12000]}, "parsed_text"
        return {"note": "LnkParse3 did not return JSON text for this file."}, "partial"
    except Exception as exc:
        return None, f"unavailable: {type(exc).__name__}: {exc}"
