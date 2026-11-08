from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any


def _epoch(value: Any) -> float | None:
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


def _pid(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return str(int(raw, 16) if raw.lower().startswith("0x") else int(raw))
    except Exception:
        try:
            return str(int(raw, 16))
        except Exception:
            return raw.casefold()


def _fields(row: dict[str, Any]) -> dict[str, Any]:
    details = row.get("details") if isinstance(row.get("details"), dict) else {}
    result = dict(details)
    nested = details.get("fields")
    if isinstance(nested, dict):
        result.update(nested)
    return result


def _family(image: str, command: str = "", description: str = "") -> str:
    """Identify only an actual Python/Java executable, not a descendant's description."""
    def family_from_executable(value: str) -> str:
        base = str(value or "").strip().strip('"').replace("/", "\\").rsplit("\\", 1)[-1].casefold()
        if re.fullmatch(r"(?:pythonw?|python\d+(?:\.\d+)*|py)\.exe", base):
            return "Python"
        if base in {"java.exe", "javaw.exe"}:
            return "Java"
        return ""

    actual_image = family_from_executable(image)
    if actual_image:
        return actual_image
    # Some event providers omit the image field. Only then inspect the first
    # command-line token; never search descriptions or later arguments for names.
    if str(image or "").strip():
        return ""
    raw_command = str(command or "").strip()
    if not raw_command:
        return ""
    if raw_command.startswith('"'):
        closing = raw_command.find('"', 1)
        executable = raw_command[1:closing] if closing > 1 else raw_command.strip('"')
    else:
        executable = raw_command.split(None, 1)[0]
    return family_from_executable(executable)


def _event_id(value: Any) -> int | None:
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None


def analyze_python_java_processes(events: list[dict[str, Any]], proximity_seconds: int = 300) -> dict[str, Any]:
    """Correlate retained Python/Java start/end records without inventing intervals."""
    starts: list[dict[str, Any]] = []
    ends: list[dict[str, Any]] = []
    seen_records: set[tuple[Any, ...]] = set()

    for index, row in enumerate(events):
        fields = _fields(row)
        event_id = _event_id(fields.get("event_id"))
        description = str(row.get("description", ""))
        image = str(
            fields.get("NewProcessName") or fields.get("Image") or fields.get("ProcessName")
            or fields.get("process_image") or fields.get("image_path") or ""
        )
        command = str(fields.get("CommandLine") or fields.get("command_line") or row.get("command", ""))
        family = _family(image, command, description)
        if not family:
            continue

        pid = _pid(fields.get("NewProcessId") or fields.get("ProcessId") or fields.get("process_id") or fields.get("pid"))
        parent_pid = _pid(fields.get("ParentProcessId") or fields.get("parent_process_id") or fields.get("parent_pid"))
        # In Security 4688, ProcessId is the creator PID when NewProcessId exists.
        if fields.get("NewProcessId"):
            parent_pid = _pid(fields.get("ProcessId") or fields.get("ParentProcessId") or fields.get("parent_process_id"))
        process_guid = str(fields.get("ProcessGuid") or fields.get("process_guid") or "").strip().casefold()
        parent_guid = str(fields.get("ParentProcessGuid") or fields.get("parent_process_guid") or "").strip().casefold()
        is_end = event_id in (4689, 5) or "завершение" in description.casefold() or "terminated" in description.casefold()
        is_start = event_id in (4688, 1) or "запуск" in description.casefold() or "started" in description.casefold() or "process created" in description.casefold()
        if not (is_start or is_end):
            continue

        timestamp = str(row.get("timestamp", "") or "")
        # The same Security record can be collected by both the quick scan and
        # the consent-based system review. Collapse only the same process record.
        identity = (
            str(row.get("source", "")).casefold(), event_id, family, pid, process_guid,
            timestamp, image.casefold(), is_start, is_end,
        )
        if identity in seen_records:
            continue
        seen_records.add(identity)

        record = {
            "event_index": index,
            "family": family,
            "pid": pid,
            "parent_pid": parent_pid,
            "process_guid": process_guid,
            "parent_process_guid": parent_guid,
            "image": image,
            "command_line": command,
            "timestamp": timestamp,
            "epoch": _epoch(timestamp),
            "source": row.get("source", ""),
            "event_id": event_id,
            "description": description,
            "is_start": is_start,
            "is_end": is_end,
        }
        (ends if is_end else starts).append(record)

    starts.sort(key=lambda item: (item["epoch"] if item["epoch"] is not None else float("inf"), item["event_index"]))
    ends.sort(key=lambda item: (item["epoch"] if item["epoch"] is not None else float("inf"), item["event_index"]))

    start_by_pid: dict[str, list[dict[str, Any]]] = {}
    start_by_guid: dict[str, list[dict[str, Any]]] = {}
    end_by_pid: dict[str, list[dict[str, Any]]] = {}
    end_by_guid: dict[str, list[dict[str, Any]]] = {}
    for item in starts:
        if item["pid"]:
            start_by_pid.setdefault(item["pid"], []).append(item)
        if item["process_guid"]:
            start_by_guid.setdefault(item["process_guid"], []).append(item)
    for item in ends:
        if item["pid"]:
            end_by_pid.setdefault(item["pid"], []).append(item)
        if item["process_guid"]:
            end_by_guid.setdefault(item["process_guid"], []).append(item)

    # Match each start to the earliest valid termination before a subsequent
    # start reuses the same PID. The input event list is often newest-first.
    for item in starts:
        item["end_timestamp"] = ""
        item["end_epoch"] = None
        item["duration_seconds"] = None
        if item["epoch"] is None:
            continue

        next_same_pid_start = None
        if item["pid"]:
            later = [
                other["epoch"] for other in start_by_pid.get(item["pid"], [])
                if other["event_index"] != item["event_index"] and other["epoch"] is not None
                and other["epoch"] > item["epoch"]
            ]
            next_same_pid_start = min(later) if later else None

        candidates: list[dict[str, Any]] = []
        if item["process_guid"]:
            candidates.extend(end_by_guid.get(item["process_guid"], []))
            # Cross-provider fallback is allowed only for GUID-less end records.
            candidates.extend(
                candidate for candidate in end_by_pid.get(item["pid"], [])
                if not candidate["process_guid"]
            )
        elif item["pid"]:
            candidates.extend(end_by_pid.get(item["pid"], []))

        valid_ends = [
            candidate for candidate in candidates
            if candidate["epoch"] is not None
            and candidate["epoch"] >= item["epoch"]
            and candidate["family"] == item["family"]
            and (next_same_pid_start is None or candidate["epoch"] < next_same_pid_start)
            and (not item["process_guid"] or not candidate["process_guid"] or candidate["process_guid"] == item["process_guid"])
        ]
        if valid_ends:
            end = min(valid_ends, key=lambda candidate: (candidate["epoch"], candidate["event_index"]))
            item["end_timestamp"] = end["timestamp"]
            item["end_epoch"] = end["epoch"]
            item["duration_seconds"] = round(end["epoch"] - item["epoch"], 3)

    direct_links: list[dict[str, Any]] = []
    nearby: list[dict[str, Any]] = []
    overlaps: list[dict[str, Any]] = []
    linked_pairs: set[tuple[int, int]] = set()
    for child in starts:
        if not child["parent_pid"] and not child["parent_process_guid"]:
            continue
        if child["epoch"] is None:
            continue

        if child["parent_process_guid"]:
            # An explicit but unavailable GUID must not silently fall back to a
            # possibly recycled PID, which could link unrelated processes.
            parents = start_by_guid.get(child["parent_process_guid"], [])
        else:
            parents = start_by_pid.get(child["parent_pid"], []) if child["parent_pid"] else []

        eligible = [
            parent for parent in parents
            if parent["event_index"] != child["event_index"]
            and parent["epoch"] is not None
            and -2 <= child["epoch"] - parent["epoch"] <= 1800
        ]
        if not eligible:
            continue
        # For PID-only records, use the most recent candidate, not list order.
        parent = max(eligible, key=lambda candidate: (candidate["epoch"], candidate["event_index"]))
        if parent["end_epoch"] is not None and parent["end_epoch"] < child["epoch"] - 2:
            continue

        if {parent["family"], child["family"]} == {"Python", "Java"}:
            exact_guid = bool(child["parent_process_guid"] and parent["process_guid"] == child["parent_process_guid"])
            delta = round(child["epoch"] - parent["epoch"], 3)
            direct_links.append({
                "relation": "python_parent_java" if parent["family"] == "Python" else "java_parent_python",
                "parent_family": parent["family"], "child_family": child["family"],
                "parent_pid": parent["pid"], "child_pid": child["pid"],
                "parent_event_index": parent["event_index"], "child_event_index": child["event_index"],
                "parent_time": parent["timestamp"], "child_time": child["timestamp"],
                "delta_seconds": delta, "confidence": "high" if exact_guid else "medium",
                "basis": "ParentProcessGuid совпадает с ProcessGuid." if exact_guid else "Parent PID совпадает с последним подходящим сохранённым запуском; связь менее надёжна из-за возможного повторного использования PID.",
            })
            linked_pairs.add((min(parent["event_index"], child["event_index"]), max(parent["event_index"], child["event_index"])))

    python_starts = [row for row in starts if row["family"] == "Python"]
    java_starts = [row for row in starts if row["family"] == "Java"]
    for python in python_starts:
        for java in java_starts:
            if python["epoch"] is None or java["epoch"] is None:
                continue
            pair_key = (min(python["event_index"], java["event_index"]), max(python["event_index"], java["event_index"]))
            if python["end_epoch"] is not None and java["end_epoch"] is not None:
                overlap_start = max(python["epoch"], java["epoch"])
                overlap_end = min(python["end_epoch"], java["end_epoch"])
                if overlap_end > overlap_start:
                    overlaps.append({
                        "relation": "confirmed_time_overlap", "python_pid": python["pid"], "java_pid": java["pid"],
                        "python_event_index": python["event_index"], "java_event_index": java["event_index"],
                        "overlap_seconds": round(overlap_end - overlap_start, 3),
                        "python_start": python["timestamp"], "python_end": python["end_timestamp"],
                        "java_start": java["timestamp"], "java_end": java["end_timestamp"],
                        "confidence": "high", "basis": "Для обоих PID найдены соответствующие записи начала и завершения; интервалы перекрываются.",
                    })
            if abs(python["epoch"] - java["epoch"]) <= proximity_seconds and pair_key not in linked_pairs:
                nearby.append({
                    "relation": "start_time_proximity", "python_pid": python["pid"], "java_pid": java["pid"],
                    "python_event_index": python["event_index"], "java_event_index": java["event_index"],
                    "delta_seconds": round(abs(python["epoch"] - java["epoch"]), 3), "confidence": "low",
                    "basis": f"Времена запуска отличаются не более чем на {proximity_seconds} секунд; родственная связь и одновременная работа не подтверждены.",
                })

    linked_python_indexes: set[int] = set()
    linked_java_indexes: set[int] = set()
    for link in direct_links:
        if link["parent_family"] == "Python":
            linked_python_indexes.add(link["parent_event_index"])
            linked_java_indexes.add(link["child_event_index"])
        else:
            linked_java_indexes.add(link["parent_event_index"])
            linked_python_indexes.add(link["child_event_index"])

    return {
        "python_process_starts": len(python_starts),
        "java_process_starts": len(java_starts),
        "python_processes_without_confirmed_java_link": sum(1 for row in python_starts if row["event_index"] not in linked_python_indexes),
        "java_processes_without_confirmed_python_link": sum(1 for row in java_starts if row["event_index"] not in linked_java_indexes),
        "direct_python_java_links": direct_links,
        "confirmed_time_overlaps": overlaps,
        "nearby_start_times": nearby,
        "process_records": starts,
        "termination_records": len(ends),
        "limitations": [
            "Анализ использует только сохранённые события создания/завершения процессов; отсутствующие записи не восстанавливаются задним числом.",
            "Совпадение времён запуска не доказывает, что один процесс запустил другой.",
            "Связь по ProcessGuid/ParentProcessGuid надёжнее; связь по PID имеет риск повторного использования PID.",
            "Если событие завершения не сохранилось, точный интервал работы процесса не вычисляется.",
            "Совместная работа Python и Java сама по себе не свидетельствует о нарушении.",
        ],
    }

def _normalized_trusted_path(value: Any) -> str:
    return str(value or "").strip().replace("/", "\\").rstrip("\\").casefold()


def _is_trusted_path(value: Any, trusted_paths: list[str]) -> bool:
    candidate = _normalized_trusted_path(value)
    if not candidate:
        return False
    for item in trusted_paths:
        trusted = _normalized_trusted_path(item)
        if trusted and (candidate == trusted or candidate.startswith(trusted + "\\")):
            return True
    return False


def assess_suspiciousness(
    events: list[dict[str, Any]],
    runtime_analysis: dict[str, Any],
    sources: list[dict[str, Any]] | None = None,
    trusted_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Explainable heuristic score; intentionally not a probability or verdict.

    User-approved trusted paths are context, not proof of safety. They suppress
    only the specific path-based indicators fully covered by those paths.
    """
    score = 0
    categories: set[str] = set()
    reasons: list[dict[str, Any]] = []
    trusted_paths = [str(path) for path in (trusted_paths or []) if str(path).strip()]
    trusted_context_matches: list[dict[str, Any]] = []
    records_by_event_index = {
        int(record.get("event_index")): record
        for record in runtime_analysis.get("process_records", [])
        if record.get("event_index") is not None
    }
    suspicious_visits = [e for e in events if (e.get("details") or {}).get("domain_category") == "suspicious" and e.get("kind") == "browser_visit"]
    software_visits = [e for e in events if (e.get("details") or {}).get("domain_category") == "software_distribution" and e.get("kind") == "browser_visit"]
    suspicious_downloads = [e for e in events if e.get("kind") == "browser_download" and (e.get("details") or {}).get("domain_category") in {"suspicious", "software_distribution"}]
    if suspicious_visits:
        score += 8
        categories.add("user_marked_site_visit")
        reasons.append({"points": 8, "evidence": "Посещение домена, который пользователь пометил как подозрительный", "records": len(suspicious_visits), "strength": "weak"})
    if software_visits:
        score += 6
        categories.add("software_distribution_site_visit")
        reasons.append({"points": 6, "evidence": "Посещение домена из пользовательской категории распространения ПО", "records": len(software_visits), "strength": "weak"})
    if suspicious_downloads:
        score += 15
        categories.add("marked_domain_download")
        reasons.append({"points": 15, "evidence": "История браузера содержит запись о загрузке с домена, отмеченного пользователем", "records": len(suspicious_downloads), "strength": "medium"})

    # Correlate visits/downloads with runtime starts using a bounded time window.
    # The relation is temporal context only; it does not establish causation.
    correlation_window_seconds = 24 * 60 * 60
    runtime_starts = [p for p in runtime_analysis.get("process_records", []) if p.get("epoch") is not None and p.get("family") in {"Python", "Java"}]
    runtime_starts.sort(key=lambda p: p["epoch"])
    temporal_correlations: list[dict[str, Any]] = []
    download_execution_matches: list[dict[str, Any]] = []
    omitted_temporal_correlations = 0
    for browser_index, browser_event in enumerate(events):
        kind = str(browser_event.get("kind", ""))
        if kind not in {"browser_visit", "browser_download"}:
            continue
        details = browser_event.get("details") if isinstance(browser_event.get("details"), dict) else {}
        browser_epoch = _epoch(browser_event.get("timestamp"))
        if browser_epoch is None:
            continue
        for process in runtime_starts:
            delta = process["epoch"] - browser_epoch
            if abs(delta) > correlation_window_seconds:
                continue
            if len(temporal_correlations) < 5000:
                temporal_correlations.append({
                    "relation": "browser_event_near_runtime_start",
                    "browser_event_index": browser_index,
                    "browser_event_type": kind,
                    "browser_timestamp": browser_event.get("timestamp", ""),
                    "domain": details.get("domain", ""),
                    "domain_category": details.get("domain_category", "unknown"),
                    "runtime_event_index": process.get("event_index"),
                    "runtime_family": process.get("family", ""),
                    "runtime_image": process.get("image", ""),
                    "runtime_timestamp": process.get("timestamp", ""),
                    "delta_seconds": round(delta, 3),
                    "confidence": "low",
                    "basis": "События находятся в пределах 24 часов друг от друга. Это временной контекст, не доказательство связи или причинности.",
                })
            else:
                omitted_temporal_correlations += 1

            if kind == "browser_download" and delta >= 0:
                target = str(details.get("target_path") or browser_event.get("command") or "").strip()
                image = str(process.get("image") or "").strip()
                normalize_path = lambda value: value.replace("/", "\\").rstrip("\\").casefold()
                normalized_target = normalize_path(target) if target else ""
                normalized_image = normalize_path(image) if image else ""
                normalized_command = normalize_path(str(process.get("command_line") or ""))
                path_in_image = bool(normalized_target and normalized_image == normalized_target)
                path_in_command = bool(normalized_target and normalized_target in normalized_command)
                if path_in_image or path_in_command:
                    relation = "downloaded_path_later_observed_as_process_image" if path_in_image else "downloaded_path_later_observed_in_runtime_command_line"
                    basis = (
                        "Путь из записи загрузки совпадает с образом запущенного процесса; совпадение пути не доказывает назначение или вредоносность файла."
                        if path_in_image else
                        "Путь из записи загрузки присутствует в командной строке позже запущенного runtime-процесса; командная строка не доказывает успешную загрузку/исполнение файла."
                    )
                    if _is_trusted_path(target, trusted_paths):
                        trusted_context_matches.append({
                            "type": "downloaded_path_in_user_trusted_context",
                            "path": target,
                            "runtime_image": image,
                            "basis": "Путь загруженного файла попадает в путь, который проверяющий явно добавил в доверенный контекст. События сохранены, но этот путь не увеличивает эвристический балл.",
                        })
                        continue
                    download_execution_matches.append({
                        "relation": relation,
                        "browser_event_index": browser_index,
                        "download_timestamp": browser_event.get("timestamp", ""),
                        "download_path": target,
                        "runtime_event_index": process.get("event_index"),
                        "runtime_family": process.get("family", ""),
                        "runtime_image": image,
                        "runtime_command_line": process.get("command_line", ""),
                        "process_timestamp": process.get("timestamp", ""),
                        "delta_seconds": round(delta, 3),
                        "confidence": "medium",
                        "basis": basis,
                    })

    if download_execution_matches:
        score += 8
        categories.add("downloaded_path_in_process_context")
        reasons.append({"points": 8, "evidence": "Путь из записи загрузки найден в образе процесса или его командной строке после времени загрузки", "records": len(download_execution_matches), "strength": "medium"})

    marked_temporal = [item for item in temporal_correlations if item.get("domain_category") in {"suspicious", "software_distribution"}]
    if marked_temporal:
        score += 2
        reasons.append({"points": 2, "evidence": "Посещение/загрузка с отмеченного домена находится во временном окне запуска Python/Java; причинная связь не подтверждена", "records": len(marked_temporal), "strength": "context"})

    direct_links = runtime_analysis.get("direct_python_java_links", [])
    untrusted_direct_links = []
    for link in direct_links:
        parent = records_by_event_index.get(int(link.get("parent_event_index", -1)), {})
        child = records_by_event_index.get(int(link.get("child_event_index", -1)), {})
        parent_image = parent.get("image", "")
        child_image = child.get("image", "")
        if parent_image and child_image and _is_trusted_path(parent_image, trusted_paths) and _is_trusted_path(child_image, trusted_paths):
            trusted_context_matches.append({
                "type": "python_java_parent_child_in_user_trusted_context",
                "parent_image": parent_image, "child_image": child_image,
                "basis": "Оба исполняемых файла попадают в пути, которые проверяющий явно добавил в доверенный контекст. Связь остаётся в хронологии, но сама по себе не увеличивает эвристический балл.",
            })
        else:
            untrusted_direct_links.append(link)
    if untrusted_direct_links:
        points = min(24, 12 + 4 * (len(untrusted_direct_links) - 1))
        score += points
        categories.add("runtime_parent_child")
        reasons.append({"points": points, "evidence": "Сохранённые данные указывают на прямую связь родительского процесса Python/Java", "records": len(untrusted_direct_links), "strength": "medium"})
    overlaps = runtime_analysis.get("confirmed_time_overlaps", [])
    untrusted_overlaps = []
    for item in overlaps:
        python_record = records_by_event_index.get(int(item.get("python_event_index", -1)), {})
        java_record = records_by_event_index.get(int(item.get("java_event_index", -1)), {})
        python_image = python_record.get("image", "")
        java_image = java_record.get("image", "")
        if python_image and java_image and _is_trusted_path(python_image, trusted_paths) and _is_trusted_path(java_image, trusted_paths):
            trusted_context_matches.append({
                "type": "python_java_overlap_in_user_trusted_context",
                "python_image": python_image, "java_image": java_image,
                "basis": "Оба исполняемых файла попадают в пользовательский доверенный контекст; временное перекрытие показывается, но не увеличивает балл.",
            })
        else:
            untrusted_overlaps.append(item)
    if untrusted_overlaps:
        score += 6
        categories.add("runtime_overlap")
        reasons.append({"points": 6, "evidence": "Найдены записи начала и завершения, интервалы Python и Java перекрываются", "records": len(untrusted_overlaps), "strength": "context"})
    nearby = runtime_analysis.get("nearby_start_times", [])
    untrusted_nearby = []
    for item in nearby:
        python_record = records_by_event_index.get(int(item.get("python_event_index", -1)), {})
        java_record = records_by_event_index.get(int(item.get("java_event_index", -1)), {})
        python_image = python_record.get("image", "")
        java_image = java_record.get("image", "")
        if python_image and java_image and _is_trusted_path(python_image, trusted_paths) and _is_trusted_path(java_image, trusted_paths):
            trusted_context_matches.append({
                "type": "python_java_nearby_in_user_trusted_context",
                "python_image": python_image, "java_image": java_image,
                "basis": "Оба исполняемых файла попадают в пользовательский доверенный контекст; близость времени не увеличивает балл.",
            })
        else:
            untrusted_nearby.append(item)
    if untrusted_nearby:
        score += 2
        reasons.append({"points": 2, "evidence": "Времена запуска Python и Java близки, но причинность не подтверждена", "records": len(untrusted_nearby), "strength": "context"})
    # Event-log clear records are objective indicators of clearing, but don't establish intent.
    cleanup = [e for e in events if (e.get("details") or {}).get("event_id") in {104, 1102}]
    if cleanup:
        score += 8
        categories.add("recorded_log_clear")
        reasons.append({"points": 8, "evidence": "Журнал содержит событие очистки журнала Windows", "records": len(cleanup), "strength": "medium"})

    if trusted_context_matches:
        reasons.append({
            "points": 0,
            "evidence": "Пользовательский доверенный контекст: конкретные путь/связь сохранены, но не увеличивают оценку",
            "records": len(trusted_context_matches),
            "strength": "context",
        })
    browser_available = any(s.get("type") == "browser_history" and s.get("status") == "available" for s in (sources or []))
    process_available = runtime_analysis.get("python_process_starts", 0) > 0 or runtime_analysis.get("java_process_starts", 0) > 0
    data_available = browser_available or process_available or bool(events)
    independent_categories = len(categories)
    if not data_available:
        level = "insufficient_data"
    elif score >= 32 and independent_categories >= 2 and (direct_links or suspicious_downloads or download_execution_matches):
        level = "high"
    elif score >= 12:
        level = "moderate"
    else:
        level = "low"
    labels = {"low": "Низкая подозрительность", "moderate": "Умеренная подозрительность", "high": "Высокая подозрительность", "insufficient_data": "Недостаточно данных"}
    explanations = {
        "low": "Обнаруженные признаки отсутствуют или слабы. Обычный запуск Python/Java и неизвестные домены сами по себе не повышают оценку.",
        "moderate": "Есть сочетание нескольких контекстных или пользовательски отмеченных признаков. Требуется ручная проверка первичных записей.",
        "high": "Есть несколько независимых групп признаков, включая более значимую связь процесса или совпадение загруженного пути с образом запущенного процесса. Это всё ещё не доказательство нарушения.",
        "insufficient_data": "Доступных данных недостаточно для содержательной оценки; отсутствие записей не подтверждает отсутствие активности.",
    }
    return {
        "level": level, "label": labels[level], "score": score, "independent_evidence_categories": independent_categories,
        "reasons": reasons, "explanation": explanations[level],
        "temporal_correlations": temporal_correlations,
        "temporal_correlation_window_seconds": correlation_window_seconds,
        "temporal_correlations_omitted_over_limit": omitted_temporal_correlations,
        "download_execution_matches": download_execution_matches,
        "trusted_context_matches": trusted_context_matches,
        "trusted_context_paths": trusted_paths,
        "note": "Доверенный контекст — пользовательская пометка пути, а не гарантия безопасности; исходные события сохраняются в отчётах. Эвристическая шкала для сортировки находок, не вероятность и не вывод о виновности. Посещение сайта, загрузка, запуск Java/Python или временное совпадение по отдельности не доказывают использование чита.",
    }
