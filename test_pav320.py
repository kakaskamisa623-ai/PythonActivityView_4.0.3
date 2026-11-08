from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pav_browser import classify_domain, scan_browser_history
from pav_features_250 import deduplicate_events
from pav_runtime import analyze_python_java_processes, assess_suspiciousness
import PythonActivityView as pav_app


def chrome_time(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((value.astimezone(timezone.utc) - epoch).total_seconds() * 1_000_000)


def process_event(timestamp: datetime, image: str, pid: str, parent_pid: str = "",
                  event_id: int = 4688, process_guid: str = "", parent_guid: str = "") -> dict:
    is_end = event_id in (4689, 5)
    if event_id in (1, 5):
        details = {
            "event_id": event_id,
            "process_image": image,
            "process_id": pid,
            "parent_process_id": parent_pid,
            "process_guid": process_guid,
            "parent_process_guid": parent_guid,
        }
    elif is_end:
        details = {"event_id": event_id, "ProcessId": pid, "process_id": pid, "ProcessName": image}
    else:
        details = {
            "event_id": event_id,
            "NewProcessName": image,
            "NewProcessId": pid,
            "ProcessId": parent_pid,
        }
    return {
        "timestamp": timestamp.isoformat(sep=" ", timespec="seconds"),
        "kind": "Windows process event",
        "description": "Process termination" if is_end else "Process start",
        "source": "Windows Event Log / Security" if event_id in (4688, 4689) else "Sysmon",
        "details": details,
    }


class EventDeduplicationTests(unittest.TestCase):
    def test_distinct_visits_in_same_history_database_survive(self):
        base = {
            "kind": "browser_visit",
            "description": "visit",
            "source": r"C:\Users\test\Chrome\History",
            "command": "",
            "details": {"url": "https://example.test/", "visit_id": 1},
        }
        second = {**base, "timestamp": "2026-10-01T12:00:01+00:00", "details": {"url": "https://example.test/", "visit_id": 2}}
        first = {**base, "timestamp": "2026-10-01T12:00:00+00:00"}
        duplicate = {**first, "details": dict(first["details"])}
        result = deduplicate_events([first, second, duplicate])
        self.assertEqual(len(result), 2)
        self.assertEqual([row["details"]["visit_id"] for row in result], [1, 2])

    def test_repeated_same_command_at_different_times_survives(self):
        base = {"kind": "command", "description": "Python command", "source": "history.txt", "command": "python tool.py", "details": {}}
        rows = [
            {**base, "timestamp": "2026-10-01T12:00:00+00:00"},
            {**base, "timestamp": "2026-10-01T12:10:00+00:00"},
        ]
        self.assertEqual(len(deduplicate_events(rows)), 2)


class ScanIntegrationRegressionTests(unittest.TestCase):
    def test_scan_all_keeps_distinct_browser_visits_from_one_source(self):
        first = {
            "timestamp": "2026-10-01T12:00:00+00:00", "kind": "browser_visit",
            "description": "visit", "command": "", "source": "profile/History",
            "details": {"url": "https://example.test/", "visit_id": 1},
        }
        second = {
            "timestamp": "2026-10-01T12:00:01+00:00", "kind": "browser_visit",
            "description": "visit", "command": "", "source": "profile/History",
            "details": {"url": "https://example.test/", "visit_id": 2},
        }
        with patch.object(pav_app, "collect_audit_readiness", return_value={"environment": {}}), \
             patch.object(pav_app, "scan_browser_history", return_value=([first, second, dict(first)], [{"type": "browser_history", "status": "ok", "records": 3}], [])), \
             patch.object(pav_app, "find_history_files", return_value=([], [], [])), \
             patch.object(pav_app, "find_pycharm_console_history_files", return_value=[]), \
             patch.object(pav_app, "find_powershell_transcripts", return_value=[]), \
             patch.object(pav_app, "scan_current_cmd_buffer", return_value=([], [])), \
             patch.object(pav_app, "scan_live_python_processes", return_value=([], [])), \
             patch.object(pav_app, "scan_prefetch", return_value=([], [])), \
             patch.object(pav_app, "scan_python_source_catalog", return_value=([], [])), \
             patch.object(pav_app, "build_scan_coverage", return_value={}):
            result = pav_app.scan_all(False, False, lambda _payload: None, include_browser_history=True)
        visits = [row for row in result["events"] if row["kind"] == "browser_visit"]
        self.assertEqual(len(visits), 2)
        self.assertEqual({row["details"]["visit_id"] for row in visits}, {1, 2})


class RuntimeCorrelationRegressionTests(unittest.TestCase):
    def test_process_start_matches_earliest_end_before_pid_reuse(self):
        t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        rows = [
            process_event(t0 + timedelta(seconds=10), r"C:\Python\python.exe", "100", event_id=4689),
            process_event(t0 + timedelta(seconds=7), r"C:\Python\python.exe", "100"),
            process_event(t0 + timedelta(seconds=5), r"C:\Python\python.exe", "100", event_id=4689),
            process_event(t0, r"C:\Python\python.exe", "100"),
        ]
        result = analyze_python_java_processes(rows)
        starts = result["process_records"]
        self.assertEqual(len(starts), 2)
        self.assertEqual(starts[0]["duration_seconds"], 5.0)
        self.assertEqual(starts[1]["duration_seconds"], 3.0)

    def test_terminated_parent_is_not_linked_to_later_child(self):
        t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        rows = [
            process_event(t0 + timedelta(seconds=10), r"C:\Java\javaw.exe", "200", "100"),
            process_event(t0 + timedelta(seconds=5), r"C:\Python\python.exe", "100", event_id=4689),
            process_event(t0, r"C:\Python\python.exe", "100"),
        ]
        result = analyze_python_java_processes(rows)
        self.assertEqual(result["direct_python_java_links"], [])
        self.assertEqual(len(result["nearby_start_times"]), 1)

    def test_explicit_unavailable_parent_guid_does_not_fall_back_to_pid(self):
        t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        rows = [
            process_event(t0 + timedelta(seconds=5), r"C:\Java\java.exe", "200", "100", 1, "{java}", "{not-collected}"),
            process_event(t0, r"C:\Python\python.exe", "100", "50", 1, "{old-python}", "{shell}"),
        ]
        result = analyze_python_java_processes(rows)
        self.assertEqual(result["direct_python_java_links"], [])

    def test_latest_active_pid_candidate_is_used(self):
        t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        rows = [
            process_event(t0 + timedelta(seconds=10), r"C:\Java\java.exe", "200", "100"),
            process_event(t0 + timedelta(seconds=8), r"C:\Python\python.exe", "100", "50"),
            process_event(t0 + timedelta(seconds=5), r"C:\Python\python.exe", "100", event_id=4689),
            process_event(t0, r"C:\Python\python.exe", "100", "50"),
        ]
        result = analyze_python_java_processes(rows)
        self.assertEqual(len(result["direct_python_java_links"]), 1)
        link = result["direct_python_java_links"][0]
        self.assertEqual(link["parent_time"], (t0 + timedelta(seconds=8)).isoformat(sep=" ", timespec="seconds"))

    def test_descendant_description_does_not_turn_other_image_into_python(self):
        t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        row = process_event(t0, r"C:\Temp\launcher.exe", "300")
        row["description"] = "Процесс в цепочке Python/Java: launcher.exe"
        result = analyze_python_java_processes([row])
        self.assertEqual(result["python_process_starts"], 0)
        self.assertEqual(result["java_process_starts"], 0)
        self.assertEqual(result["process_records"], [])


class BrowserHistoryRegressionTests(unittest.TestCase):
    def test_most_specific_user_domain_rule_wins(self):
        category, note = classify_domain(
            "download.sub.example.test",
            {"example.test": "suspicious", "sub.example.test": "ordinary"},
        )
        self.assertEqual(category, "ordinary")
        self.assertIn("sub.example.test", note)

    def test_malformed_download_id_does_not_abort_profile_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "History"
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE downloads (
                    id TEXT, current_path TEXT, target_path TEXT,
                    start_time INTEGER, end_time INTEGER, state INTEGER
                );
                CREATE TABLE downloads_url_chains (
                    id TEXT, chain_index INTEGER, url TEXT
                );
            """)
            stamp = chrome_time(datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc))
            conn.execute("INSERT INTO downloads VALUES ('not-an-integer', ?, ?, ?, ?, ?)",
                         (r"C:\Users\test\Downloads\unknown.bin", r"C:\Users\test\Downloads\unknown.bin", stamp, stamp + 1_000_000, 1))
            conn.execute("INSERT INTO downloads_url_chains VALUES ('not-an-integer', 0, ?)", ("https://example.test/file",))
            conn.commit()
            conn.close()
            with patch("pav_browser._browser_profile_databases", return_value=[("Google Chrome", "Default", db)]):
                events, _sources, warnings = scan_browser_history()
            self.assertEqual(warnings, [])
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["kind"], "browser_download")

    def test_chromium_modern_download_chain_provides_origin_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "History"
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE downloads (
                    id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT,
                    start_time INTEGER, end_time INTEGER, state INTEGER
                );
                CREATE TABLE downloads_url_chains (
                    id INTEGER, chain_index INTEGER, url TEXT
                );
            """)
            stamp = chrome_time(datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc))
            conn.execute("INSERT INTO downloads VALUES (1, ?, ?, ?, ?, ?)",
                         (r"C:\Users\test\Downloads\payload.jar", r"C:\Users\test\Downloads\payload.jar", stamp, stamp + 1_000_000, 1))
            conn.execute("INSERT INTO downloads_url_chains VALUES (1, 0, ?)", ("https://redirect.example.test/start",))
            conn.execute("INSERT INTO downloads_url_chains VALUES (1, 1, ?)", ("https://files.example.test/payload.jar",))
            conn.commit()
            conn.close()
            with patch("pav_browser._browser_profile_databases", return_value=[("Google Chrome", "Default", db)]):
                events, _sources, warnings = scan_browser_history(domain_rules={"example.test": "software_distribution"})
            self.assertEqual(warnings, [])
            self.assertEqual(len(events), 1)
            download = events[0]
            self.assertEqual(download["kind"], "browser_download")
            self.assertEqual(download["details"]["domain"], "files.example.test")
            self.assertEqual(download["details"]["domain_category"], "software_distribution")
            self.assertEqual(download["details"]["title"], "payload.jar")

    def test_download_path_is_not_correlated_to_process_started_before_download(self):
        t0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        path = r"C:\Users\test\Downloads\tool.jar"
        download = {
            "timestamp": t0.isoformat(), "kind": "browser_download", "command": path,
            "details": {"target_path": path, "domain_category": "software_distribution", "domain": "files.example.test"},
        }
        java = process_event(t0 - timedelta(seconds=30), r"C:\Java\java.exe", "200", "50")
        java["details"]["CommandLine"] = f'java.exe -jar "{path}"'
        runtime = analyze_python_java_processes([java])
        risk = assess_suspiciousness([download, java], runtime, [])
        self.assertEqual(risk["download_execution_matches"], [])


if __name__ == "__main__":
    unittest.main()
