from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pav_browser import (
    BrowserSourceTimeout,
    _BrowserDeadline,
    _sqlite_open_live_readonly,
    _sqlite_readonly_backup,
    scan_browser_history,
)


def _chrome_time(value: datetime) -> int:
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((value.astimezone(timezone.utc) - epoch).total_seconds() * 1_000_000)


def _make_history(path: Path, count: int = 10) -> None:
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
        connection.execute(
            "INSERT INTO urls VALUES (?, ?, ?, ?)",
            (index + 1, f"https://example-{index}.test/", f"Тест {index}", 1),
        )
        connection.execute(
            "INSERT INTO visits VALUES (?, ?, ?)",
            (index + 1, index + 1, stamp + index * 1_000_000),
        )
    connection.commit()
    connection.close()


class BrowserTimeoutFixTests(unittest.TestCase):
    def test_deadline_raises_after_limit(self):
        deadline = _BrowserDeadline(0.1, "Chrome/Default")
        time.sleep(0.12)
        with self.assertRaises(BrowserSourceTimeout):
            deadline.check()

    def test_sqlite_progress_handler_interrupts_expensive_query(self):
        class CancelledForTest(Exception):
            pass

        cancelled = False

        def check_cancel():
            nonlocal cancelled
            cancelled = True
            raise CancelledForTest("cancel requested")

        deadline = _BrowserDeadline(5, "Chrome/Default", check_cancel)
        connection = sqlite3.connect(":memory:")
        connection.set_progress_handler(deadline.sqlite_progress, 1)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                connection.execute(
                    "WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<100000) SELECT sum(x) FROM cnt"
                ).fetchone()
            self.assertTrue(cancelled)
            with self.assertRaises(CancelledForTest):
                deadline.raise_pending()
        finally:
            connection.close()

    def test_timeout_on_one_profile_does_not_block_next_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "первый" / "History"
            second = Path(tmp) / "второй" / "History"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            _make_history(first, 3)
            _make_history(second, 4)
            real_open = _sqlite_open_live_readonly

            def open_live(path, cancel_check=None, progress=None, **kwargs):
                if path == first:
                    raise BrowserSourceTimeout("тестовый timeout первого профиля")
                return real_open(path, cancel_check=cancel_check, progress=progress, **kwargs)

            with patch("pav_browser._browser_profile_databases", return_value=[
                ("Google Chrome", "Default", first),
                ("Microsoft Edge", "Default", second),
            ]), patch("pav_browser._sqlite_open_live_readonly", side_effect=open_live):
                events, sources, warnings = scan_browser_history()

            first_result = next(row for row in sources if row.get("path") == str(first))
            second_result = next(row for row in sources if row.get("path") == str(second))
            self.assertEqual(first_result["status"], "timeout")
            self.assertEqual(second_result["status"], "available")
            self.assertEqual(second_result["visits"], 4)
            self.assertEqual(len([row for row in events if row["kind"] == "browser_visit"]), 4)
            self.assertTrue(any("timeout" in warning for warning in warnings))

    def test_browser_progress_names_profile_and_database_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "History"
            _make_history(history, 2)
            messages: list[str] = []
            with patch("pav_browser._browser_profile_databases", return_value=[
                ("Google Chrome", "Default", history),
            ]):
                scan_browser_history(progress=messages.append)
            self.assertTrue(any("Читаю профиль 1/1" in message for message in messages))
            self.assertTrue(any("активная база History" in message for message in messages))

    def test_sql_query_timeout_marks_profile_and_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first" / "History"
            second = Path(tmp) / "second" / "History"
            first.parent.mkdir(parents=True)
            second.parent.mkdir(parents=True)
            _make_history(first, 3)
            _make_history(second, 4)
            from pav_browser import _scan_chromium as real_scan_chromium
            first_call = True

            def delayed_first_scan(connection, browser, profile, path, rules, limit, cancel_check=None):
                nonlocal first_call
                if path == first and first_call:
                    first_call = False
                    time.sleep(0.12)
                    # The SQLite progress handler installed by scan_browser_history
                    # interrupts this query because this profile's deadline elapsed.
                    connection.execute(
                        "WITH RECURSIVE cnt(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM cnt WHERE x<100000) SELECT sum(x) FROM cnt"
                    ).fetchone()
                return real_scan_chromium(connection, browser, profile, path, rules, limit, cancel_check)

            with patch("pav_browser._browser_profile_databases", return_value=[
                ("Google Chrome", "Default", first),
                ("Microsoft Edge", "Default", second),
            ]), patch("pav_browser._scan_chromium", side_effect=delayed_first_scan):
                events, sources, warnings = scan_browser_history(per_profile_timeout=0.1)

            first_result = next(row for row in sources if row.get("path") == str(first))
            second_result = next(row for row in sources if row.get("path") == str(second))
            self.assertEqual(first_result["status"], "timeout")
            self.assertEqual(second_result["status"], "available")
            self.assertEqual(second_result["visits"], 4)
            self.assertTrue(any("timeout" in warning for warning in warnings))

    def test_total_timeout_marks_remaining_profiles_as_not_scanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            profiles = []
            for index in range(2):
                path = Path(tmp) / str(index) / "History"
                path.parent.mkdir(parents=True)
                _make_history(path, 1)
                profiles.append(("Google Chrome" if index == 0 else "Microsoft Edge", "Default", path))
            def slow_first_profile(path, cancel_check=None, progress=None, **kwargs):
                time.sleep(1.05)
                raise BrowserSourceTimeout("profile timeout in test")

            with patch("pav_browser._browser_profile_databases", return_value=profiles), patch(
                "pav_browser._sqlite_open_live_readonly", side_effect=slow_first_profile
            ):
                _events, sources, warnings = scan_browser_history(total_timeout=1, per_profile_timeout=10)
            profile_statuses = {row.get("path"): row["status"] for row in sources if row.get("path")}
            self.assertEqual(profile_statuses[str(profiles[0][2])], "timeout")
            self.assertEqual(profile_statuses[str(profiles[1][2])], "not_scanned")
            self.assertTrue(any("Общий лимит" in warning for warning in warnings))

    def test_profile_timeout_is_bounded_to_at_least_one_tenth_second(self):
        deadline = _BrowserDeadline(0.001, "Firefox/Default")
        self.assertGreaterEqual(deadline.seconds, 0.1)


if __name__ == "__main__":
    unittest.main()
