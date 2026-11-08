import tempfile
import unittest
from pathlib import Path

from pav_features_250 import compare_snapshots, event_fingerprint, file_sha256, make_process_tree_rows, normalize_imported_snapshot
from forensic_review import parse_event_xml, _is_relevant_artifact_path, _is_related_application_event, _select_python_related_4688, _is_relevant_registry_event


class SnapshotTests(unittest.TestCase):
    def test_compare_added_and_removed_events(self):
        old = {
            "events": [
                {"timestamp": "2026-11-06 10:00:00", "kind": "Python", "command": "a=1", "source": "history"},
                {"timestamp": "2026-11-06 10:01:00", "kind": "Python", "command": "b=2", "source": "history"},
            ],
            "sources": [{"path": "history"}],
            "python_files": [{"path": "project/main.py", "size_bytes": 10, "modified_local": "earlier"}],
            "process_snapshot": [{"pid": 44, "name": "cmd.exe", "path": "C:/cmd.exe", "command_line": "cmd"}],
        }
        new = {
            "events": [
                {"timestamp": "2026-11-06 10:00:00", "kind": "Python", "command": "a=1", "source": "history"},
                {"timestamp": "2026-11-06 10:02:00", "kind": "Python", "command": "c=3", "source": "history"},
            ],
            "sources": [{"path": "history"}, {"path": "new.log"}],
            "python_files": [{"path": "project/main.py", "size_bytes": 12, "modified_local": "later"}],
            "process_snapshot": [{"pid": 55, "name": "python.exe", "path": "C:/python.exe", "command_line": "python a.py"}],
        }
        diff = compare_snapshots(old, new)
        self.assertEqual(len(diff["added_events"]), 1)
        self.assertEqual(len(diff["removed_events"]), 1)
        self.assertEqual(len(diff["added_sources"]), 1)
        self.assertEqual(diff["common_event_count"], 1)
        self.assertEqual(len(diff["changed_python_files"]), 1)
        self.assertEqual(len(diff["added_processes"]), 1)
        self.assertEqual(len(diff["removed_processes"]), 1)


    def test_normalize_imported_report_deduplicates_system_trace(self):
        event = {"timestamp": "2026-11-06T10:00:00+02:00", "kind": "Python", "command": "print(1)", "source": "history"}
        payload = {
            "generated_local": "2026-11-06T10:00:00+02:00",
            "events": [event],
            "sources": [{"path": "history", "type": "text"}],
            "system_trace": {"events": [event, {"timestamp": "2026-11-06T10:01:00+02:00", "kind": "Sysmon", "command": "python.exe", "source": "Sysmon"}], "sources": [{"path": "sysmon", "type": "event-log"}]},
            "current_process_snapshot": [{"pid": 10, "name": "python.exe"}],
        }
        normalized = normalize_imported_snapshot(payload)
        self.assertEqual(len(normalized["events"]), 2)
        self.assertEqual(len(normalized["sources"]), 2)
        self.assertEqual(normalized["process_snapshot"][0]["pid"], 10)
        self.assertTrue(normalized["normalized_for_comparison"])

    def test_fingerprint_stable(self):
        row = {"timestamp": "2026-11-06T10:00:00+02:00", "kind": "x", "command": "print(1)"}
        self.assertEqual(event_fingerprint(row), event_fingerprint(dict(row)))


class ProcessTreeTests(unittest.TestCase):
    def test_parent_child_link(self):
        events = [
            {"timestamp": "2026-11-06T10:00:00+02:00", "kind": "start", "description": "cmd", "details": {"process_id": 100, "process_image": "cmd.exe"}},
            {"timestamp": "2026-11-06T10:00:02+02:00", "kind": "start", "description": "python", "details": {"process_id": 101, "parent_process_id": 100, "process_image": "python.exe"}, "command": "python -c print(1)"},
        ]
        rows = make_process_tree_rows(events)
        self.assertEqual(len(rows), 2)
        child = next(row for row in rows if row["pid"] == "101")
        self.assertTrue(child["parent_key"])
        self.assertIn("python", child["command"])


class WindowsEventParsingTests(unittest.TestCase):
    def test_parse_event_xml_preserves_exact_command_line(self):
        xml = r'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4688</EventID>
          <TimeCreated SystemTime="2026-11-06T17:42:00.000Z"/><EventRecordID>1234</EventRecordID>
          <Execution ProcessID="100" ThreadID="200"/><Security UserID="S-1-5-21-1"/></System>
          <EventData><Data Name="NewProcessName">C:\Python313\python.exe</Data>
          <Data Name="CommandLine">python.exe -c "print(1)"</Data><Data Name="NewProcessId">0x2A</Data></EventData>
        </Event>'''
        rows = parse_event_xml(xml, "Security", {4688})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["details"]["event_id"], 4688)
        self.assertEqual(rows[0]["details"]["fields"]["CommandLine"], 'python.exe -c "print(1)"')
        self.assertEqual(rows[0]["details"]["event_record_id"], "1234")
        self.assertIn("2026-11-06", rows[0]["timestamp"])

    def test_parse_filters_ids(self):
        xml = '''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>104</EventID></System></Event>'''
        self.assertEqual(parse_event_xml(xml, "System", {4688}), [])


    def test_parse_event_xml_with_declaration_and_multiple_events(self):
        xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + (
            '<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4688</EventID><TimeCreated SystemTime=\"2026-11-06T17:42:00Z\"/></System><EventData><Data Name=\"CommandLine\">python -c print(1)</Data></EventData></Event>'
            '<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4689</EventID><TimeCreated SystemTime=\"2026-11-06T17:42:01Z\"/></System></Event>'
        )
        rows = parse_event_xml(xml, "Security", {4688, 4689})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["details"]["fields"]["CommandLine"], "python -c print(1)")

    def test_security_selection_keeps_raw_account_name(self):
        rows = [{
            "timestamp": "2026-11-06T17:42:00+00:00",
            "kind": "Windows: журналы аудита",
            "description": "Создание процесса",
            "command": "",
            "details": {"event_id": 4688, "fields": {
                "SubjectUserName": "alice", "NewProcessName": r"C:\Python313\python.exe",
                "NewProcessId": "0x65", "ProcessId": "0x64", "CommandLine": "python.exe -c a=5"
            }}
        }]
        selected = _select_python_related_4688(rows, "alice")
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0]["details"]["fields"]["SubjectUserName"], "alice")
        self.assertEqual(selected[0]["command"], "python.exe -c a=5")

    def test_relevant_registry_markers(self):
        self.assertTrue(_is_relevant_registry_event({"ValueName": "Python Launcher", "Value": r"C:\Python313\python.exe"}))
        self.assertFalse(_is_relevant_registry_event({"ValueName": "Wallpaper", "Value": r"C:\Images\wallpaper.jpg"}))

    def test_relevant_file_paths(self):
        self.assertTrue(_is_relevant_artifact_path(r"C:\Users\A\AppData\Local\Temp\mod.py"))
        self.assertTrue(_is_relevant_artifact_path(r"C:\Users\A\AppData\JetBrains\PyCharm\options\other.toml"))
        self.assertFalse(_is_relevant_artifact_path(r"C:\Users\A\Pictures\photo.jpg"))

    def test_application_event_filter(self):
        row = {"details": {"fields": {"FaultingApplicationName": "python.exe", "ExceptionCode": "0xc000"}}}
        self.assertTrue(_is_related_application_event(row))
        self.assertFalse(_is_related_application_event({"details": {"fields": {"FaultingApplicationName": "notepad.exe"}}}))


class HashTests(unittest.TestCase):
    def test_sha256_helper(self):
        with tempfile.TemporaryDirectory() as temp:
            file_path = Path(temp) / "x.txt"
            file_path.write_text("abc", encoding="utf-8")
            self.assertEqual(file_sha256(file_path), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main(verbosity=2)
