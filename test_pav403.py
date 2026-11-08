from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pav_browser import _sqlite_open_live_readonly, scan_browser_history
from test_pav402 import _make_history, _chrome_time


class ActiveBrowserReadTests(unittest.TestCase):
    def _active_wal_database(self, path: Path) -> sqlite3.Connection:
        _make_history(path, 2)
        writer = sqlite3.connect(path, timeout=2.0)
        mode = writer.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        self.assertEqual(str(mode).casefold(), "wal")
        stamp = _chrome_time(datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc))
        writer.execute(
            "INSERT INTO urls(id, url, title, visit_count) VALUES (?, ?, ?, ?)",
            (100, "https://active-browser.test/", "Активная вкладка", 1),
        )
        writer.execute(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            (100, 100, stamp),
        )
        writer.commit()
        # Keep the writer connection open: it simulates a browser that is still
        # running and still owns an active SQLite WAL connection.
        return writer

    def test_live_readonly_snapshot_reads_committed_wal_while_writer_is_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "История" / "History"
            history.parent.mkdir(parents=True)
            writer = self._active_wal_database(history)
            try:
                self.assertTrue(Path(str(history) + "-wal").exists())
                reader = _sqlite_open_live_readonly(history)
                try:
                    urls = [row[0] for row in reader.execute("SELECT url FROM urls ORDER BY id")]
                    self.assertIn("https://active-browser.test/", urls)
                    with self.assertRaises(sqlite3.OperationalError):
                        reader.execute(
                            "INSERT INTO urls(id, url, title, visit_count) VALUES (101, 'https://must-not-write.test/', '', 1)"
                        )
                finally:
                    reader.close()
                self.assertIsNone(
                    writer.execute("SELECT url FROM urls WHERE id=101").fetchone(),
                    "The analyzer must not write to the browser database.",
                )
            finally:
                writer.close()

    def test_scanner_reads_active_chromium_profile_without_closing_browser(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "Chrome" / "Default" / "History"
            history.parent.mkdir(parents=True)
            writer = self._active_wal_database(history)
            try:
                with patch("pav_browser._browser_profile_databases", return_value=[
                    ("Google Chrome", "Default", history),
                ]):
                    events, sources, warnings = scan_browser_history()
                result = next(row for row in sources if row.get("path") == str(history))
                self.assertEqual(result["status"], "available")
                self.assertEqual(result["read_mode"], "live_readonly")
                self.assertGreaterEqual(result["visits"], 3)
                self.assertTrue(any(row.get("details", {}).get("url") == "https://active-browser.test/" for row in events))
                self.assertFalse(warnings)
                # Writer is still alive and able to commit after the scan.
                writer.execute("UPDATE urls SET title=? WHERE id=100", ("Вкладка всё ещё открыта",))
                writer.commit()
            finally:
                writer.close()

    def test_backup_fallback_is_used_if_live_readonly_open_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            history = Path(tmp) / "History"
            _make_history(history, 2)
            with patch("pav_browser._browser_profile_databases", return_value=[
                ("Google Chrome", "Default", history),
            ]), patch(
                "pav_browser._sqlite_open_live_readonly",
                side_effect=sqlite3.OperationalError("database is locked"),
            ):
                events, sources, _warnings = scan_browser_history()
            result = next(row for row in sources if row.get("path") == str(history))
            self.assertEqual(result["status"], "available")
            self.assertEqual(result["read_mode"], "sqlite_backup")
            self.assertEqual(result["visits"], 2)


if __name__ == "__main__":
    unittest.main()
