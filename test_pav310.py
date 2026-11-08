from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pav_browser import scan_browser_history, normalize_domain, classify_domain
from pav_runtime import analyze_python_java_processes, assess_suspiciousness


def chrome_time(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((value.astimezone(timezone.utc) - epoch).total_seconds() * 1_000_000)


def runtime_event(timestamp: datetime, image: str, pid: str, parent_pid: str = "", event_id: int = 4688,
                  process_guid: str = "", parent_guid: str = "") -> dict:
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
        details = {"event_id": event_id, "ProcessId": pid, "process_id": pid, "ProcessName": image, "process_image": image}
    else:
        details = {
            "event_id": event_id,
            "NewProcessName": image,
            "NewProcessId": pid,
            "ProcessId": parent_pid,
            "process_id": pid,
            "parent_process_id": parent_pid,
        }
    return {
        "timestamp": timestamp.astimezone().isoformat(sep=" ", timespec="seconds"),
        "kind": "Windows process event",
        "description": "Process start" if not is_end else "Process termination",
        "source": "Windows Event Log / Security",
        "details": details,
    }


class BrowserHistoryTests(unittest.TestCase):
    def test_domain_rules_are_explicit_and_subdomain_aware(self):
        self.assertEqual(normalize_domain("https://WWW.Example.com/path"), "www.example.com")
        self.assertEqual(classify_domain("download.example.com", {})[0], "unknown")
        self.assertEqual(classify_domain("download.example.com", {"example.com": "suspicious"})[0], "suspicious")
        self.assertEqual(classify_domain("notexample.com", {"example.com": "suspicious"})[0], "unknown")

    def test_chromium_history_and_downloads_are_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "History"
            conn = sqlite3.connect(db)
            conn.executescript("""
                CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
                CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
                CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT, start_time INTEGER, end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER, state INTEGER, tab_url TEXT, site_url TEXT, danger_type INTEGER, interrupt_reason INTEGER);
            """)
            stamp = chrome_time(datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc))
            conn.execute("INSERT INTO urls VALUES (1, ?, ?, 3)", ("https://download.example.test/page", "Download Page"))
            conn.execute("INSERT INTO visits VALUES (1, 1, ?)", (stamp,))
            conn.execute("INSERT INTO downloads VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         ("C:/Users/test/Downloads/tool.jar", "C:/Users/test/Downloads/tool.jar", stamp, stamp + 30_000_000, 120, 120, 1,
                          "https://download.example.test/page", "https://download.example.test", 0, 0))
            conn.commit()
            conn.close()
            with patch("pav_browser._browser_profile_databases", return_value=[("Google Chrome", "Default", db)]):
                events, sources, warnings = scan_browser_history(domain_rules={"example.test": "software_distribution"})
            self.assertEqual(len(events), 2)
            self.assertEqual({e["kind"] for e in events}, {"browser_visit", "browser_download"})
            self.assertTrue(all(e["details"]["domain_category"] == "software_distribution" for e in events))
            self.assertEqual(next(s for s in sources if s.get("browser") == "Google Chrome")["status"], "available")
            self.assertEqual(warnings, [])
            self.assertTrue(all("password" not in str(e).casefold() and "cookie" not in str(e).casefold() for e in events))


class RuntimeCorrelationTests(unittest.TestCase):
    def test_parent_pid_link_python_to_java(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        events = [
            runtime_event(start, r"C:\Python\python.exe", "100", "50"),
            runtime_event(start + timedelta(seconds=3), r"C:\Java\bin\javaw.exe", "200", "100"),
        ]
        result = analyze_python_java_processes(events)
        self.assertEqual(result["python_process_starts"], 1)
        self.assertEqual(result["java_process_starts"], 1)
        self.assertEqual(len(result["direct_python_java_links"]), 1)
        self.assertEqual(result["direct_python_java_links"][0]["confidence"], "medium")
        self.assertEqual(len(result["nearby_start_times"]), 0)

    def test_sysmon_parent_guid_and_confirmed_overlap(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        events = [
            runtime_event(start, r"C:\Python\python.exe", "100", "50", 1, "{py}", "{shell}"),
            runtime_event(start + timedelta(seconds=4), r"C:\Java\java.exe", "200", "100", 1, "{jv}", "{py}"),
            runtime_event(start + timedelta(minutes=2), r"C:\Python\python.exe", "100", "", 5, "{py}"),
            runtime_event(start + timedelta(minutes=3), r"C:\Java\java.exe", "200", "", 5, "{jv}"),
        ]
        result = analyze_python_java_processes(events)
        self.assertEqual(result["direct_python_java_links"][0]["confidence"], "high")
        self.assertEqual(len(result["confirmed_time_overlaps"]), 1)
        self.assertGreater(result["confirmed_time_overlaps"][0]["overlap_seconds"], 0)

    def test_close_starts_are_not_called_parent_child_or_overlap(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        events = [
            runtime_event(start, r"C:\Python\python.exe", "100", "50"),
            runtime_event(start + timedelta(seconds=20), r"C:\Java\java.exe", "200", "60"),
        ]
        result = analyze_python_java_processes(events)
        self.assertEqual(result["direct_python_java_links"], [])
        self.assertEqual(result["confirmed_time_overlaps"], [])
        self.assertEqual(len(result["nearby_start_times"]), 1)
        self.assertEqual(result["nearby_start_times"][0]["confidence"], "low")

    def test_shell_command_line_is_not_counted_as_runtime_process(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        events = [{
            "timestamp": start.isoformat(),
            "kind": "CMD/PowerShell: запуск runtime (Event 4688)",
            "description": "cmd.exe (Event ID 4688)",
            "source": "Windows Event Log / Security",
            "details": {"image_path": r"C:\Windows\System32\cmd.exe",
                        "command_line": 'cmd.exe /c "python.exe tool.py"',
                        "event_id": 4688, "process_id": "300", "NewProcessId": "300",
                        "NewProcessName": r"C:\Windows\System32\cmd.exe"},
        }]
        result = analyze_python_java_processes(events)
        self.assertEqual(result["python_process_starts"], 0)
        self.assertEqual(result["java_process_starts"], 0)
        self.assertEqual(result["process_records"], [])

    def test_browser_visit_is_temporally_correlated_with_runtime(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        browser = {"timestamp": start.isoformat(), "kind": "browser_visit", "description": "visit",
                   "details": {"domain": "example.test", "domain_category": "unknown"}}
        runtime = runtime_event(start + timedelta(minutes=5), r"C:\Python\python.exe", "100", "50")
        runtime_analysis = analyze_python_java_processes([runtime])
        assessment = assess_suspiciousness([browser, runtime], runtime_analysis, [])
        self.assertEqual(len(assessment["temporal_correlations"]), 1)
        self.assertEqual(assessment["temporal_correlations"][0]["runtime_family"], "Python")
        self.assertEqual(assessment["score"], 0)

    def test_downloaded_file_path_can_be_correlated_to_later_process_image(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        path = r"C:\Users\test\Downloads\mod-tool.jar"
        download = {"timestamp": start.isoformat(), "kind": "browser_download", "description": "download",
                    "command": path,
                    "details": {"domain": "example.test", "domain_category": "software_distribution", "target_path": path}}
        java = runtime_event(start + timedelta(minutes=1), r"C:\Java\bin\java.exe", "200", "50")
        java["details"]["CommandLine"] = f'"java.exe" -jar "{path}"'
        runtime_analysis = analyze_python_java_processes([java])
        assessment = assess_suspiciousness([download, java], runtime_analysis, [])
        self.assertEqual(len(assessment["download_execution_matches"]), 1)
        self.assertGreaterEqual(assessment["score"], 20)
        self.assertEqual(assessment["level"], "moderate")

    def test_unknown_sites_and_java_alone_do_not_raise_suspicion(self):
        start = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
        events = [runtime_event(start, r"C:\Java\javaw.exe", "200", "60")]
        events.append({"timestamp": start.isoformat(), "kind": "browser_visit", "details": {"domain_category": "unknown"}})
        runtime = analyze_python_java_processes(events)
        score = assess_suspiciousness(events, runtime, [])["score"]
        self.assertEqual(score, 0)


if __name__ == "__main__":
    unittest.main()
