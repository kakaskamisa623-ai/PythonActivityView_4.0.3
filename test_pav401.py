from __future__ import annotations

import os
import queue
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from PythonActivityView import PythonActivityViewPro, ScanCancelled
from pav_browser import _browser_profile_databases, scan_browser_history


def _chrome_time(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((value.astimezone(timezone.utc) - epoch).total_seconds() * 1_000_000)


def _make_chrome_history(path: Path, count: int = 5) -> None:
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
        CREATE TABLE downloads(
            id INTEGER PRIMARY KEY, current_path TEXT, target_path TEXT,
            start_time INTEGER, end_time INTEGER, received_bytes INTEGER,
            total_bytes INTEGER, state INTEGER, tab_url TEXT, site_url TEXT,
            danger_type INTEGER, interrupt_reason INTEGER
        );
        """
    )
    stamp = _chrome_time(datetime(2026, 11, 8, 10, 0, tzinfo=timezone.utc))
    for index in range(count):
        url = f"https://history-{index}.example.test/page"
        connection.execute("INSERT INTO urls VALUES (?, ?, ?, ?)", (index + 1, url, f"Тестовая страница {index}", 1))
        connection.execute("INSERT INTO visits VALUES (?, ?, ?)", (index + 1, index + 1, stamp + index * 1_000_000))
    connection.commit()
    connection.close()


class BrowserScannerFixTests(unittest.TestCase):
    def test_scans_chromium_profile_and_reports_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "История браузера Chrome" / "History"
            db_path.parent.mkdir(parents=True)
            _make_chrome_history(db_path, 7)
            with patch("pav_browser._browser_profile_databases", return_value=[("Google Chrome", "Default", db_path)]):
                events, sources, warnings = scan_browser_history()
            visits = [row for row in events if row["kind"] == "browser_visit"]
            self.assertEqual(len(visits), 7)
            chrome_source = next(row for row in sources if row.get("browser") == "Google Chrome")
            self.assertEqual(chrome_source["status"], "available")
            self.assertEqual(chrome_source["visits"], 7)
            self.assertEqual(warnings, [])
            self.assertIn("Тестовая страница", visits[0]["details"]["title"])

    def test_browser_scan_checks_cancel_during_profile_processing(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "History"
            _make_chrome_history(db_path, 100)
            calls = 0
            cancelled = threading.Event()

            def check_cancel():
                nonlocal calls
                calls += 1
                if calls >= 10:
                    cancelled.set()
                if cancelled.is_set():
                    raise ScanCancelled("cancelled in test")

            with patch("pav_browser._browser_profile_databases", return_value=[("Google Chrome", "Default", db_path)]):
                with self.assertRaises(ScanCancelled):
                    scan_browser_history(cancel_check=check_cancel)
            self.assertGreaterEqual(calls, 10)

    def test_chromium_paths_are_discovered_from_userprofile_and_firefox_ini(self):
        with tempfile.TemporaryDirectory() as tmp:
            user = Path(tmp) / "User With Кириллица"
            local = user / "AppData" / "Local"
            roaming = user / "AppData" / "Roaming"
            chrome_profile = local / "Google" / "Chrome" / "User Data" / "Default"
            chrome_profile.mkdir(parents=True)
            (chrome_profile / "History").write_bytes(b"sqlite-test")
            firefox_root = roaming / "Mozilla" / "Firefox"
            firefox_root.mkdir(parents=True)
            custom_profile = Path(tmp) / "Custom Firefox Profile"
            custom_profile.mkdir()
            (custom_profile / "places.sqlite").write_bytes(b"sqlite-test")
            relative_profile = firefox_root / "Profiles" / "relative.default-release"
            relative_profile.mkdir(parents=True)
            (relative_profile / "places.sqlite").write_bytes(b"sqlite-test")
            (firefox_root / "profiles.ini").write_text(
                "[Profile0]\nName=Custom\nIsRelative=0\nPath=" + str(custom_profile)
                + "\n[Profile1]\nName=Relative\nIsRelative=1\nPath=Profiles/relative.default-release\n",
                encoding="utf-8",
            )
            env = {
                "USERPROFILE": str(user),
                "LOCALAPPDATA": str(local),
                "APPDATA": str(roaming),
            }
            with patch.dict(os.environ, env, clear=False):
                profiles = _browser_profile_databases()
            self.assertTrue(any(browser == "Google Chrome" and profile == "Default" for browser, profile, _ in profiles))
            self.assertTrue(any(browser == "Mozilla Firefox" and profile == "Custom" for browser, profile, _ in profiles))
            self.assertTrue(any(browser == "Mozilla Firefox" and profile == "Relative" for browser, profile, _ in profiles))

    def test_gui_worker_poller_reschedules_when_queue_is_empty(self):
        class FakeRoot:
            def __init__(self):
                self.calls = []

            def after(self, milliseconds, callback):
                self.calls.append((milliseconds, callback))

        app = PythonActivityViewPro.__new__(PythonActivityViewPro)
        app.worker_queue = queue.Queue()
        app.scanning = True
        app.root = FakeRoot()
        PythonActivityViewPro.poll_worker(app)
        self.assertEqual(len(app.root.calls), 1)
        self.assertEqual(app.root.calls[0][0], 120)
        app.scanning = False


if __name__ == "__main__":
    unittest.main()
