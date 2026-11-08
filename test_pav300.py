import hashlib
import tempfile
import unittest
from pathlib import Path

from pav_v30 import (
    assess_event_evidence,
    attach_analysis,
    build_scan_coverage,
    collect_audit_readiness,
    copy_original_artifacts,
    correlate_events,
    export_event_logs,
    normalize_event_timestamp,
    windows_compatibility,
)


class TimestampTests(unittest.TestCase):
    def test_aware_timestamp_has_utc_and_local(self):
        row = {"timestamp": "2026-11-06T17:42:00Z"}
        normalize_event_timestamp(row)
        normalized = row["time_normalization"]
        self.assertEqual(normalized["timestamp_utc"], "2026-11-06T17:42:00+00:00")
        self.assertEqual(normalized["timestamp_interpretation"], "source_offset_present")
        self.assertEqual(row["timestamp"], "2026-11-06T17:42:00Z")

    def test_naive_timestamp_is_explicitly_assumed_local(self):
        row = {"timestamp": "2026-11-06 19:42:00"}
        normalize_event_timestamp(row)
        normalized = row["time_normalization"]
        self.assertEqual(normalized["timestamp_interpretation"], "assumed_system_local_no_source_offset")
        self.assertTrue(normalized["timestamp_utc"])
        self.assertEqual(row["timestamp"], "2026-11-06 19:42:00")

    def test_missing_timestamp_is_not_invented(self):
        row = {"timestamp": ""}
        normalize_event_timestamp(row)
        self.assertEqual(row["time_normalization"]["timestamp_interpretation"], "missing")
        self.assertEqual(row["time_normalization"]["timestamp_utc"], "")


class EvidenceAssessmentTests(unittest.TestCase):
    def test_saved_command_is_not_mislabeled_as_successful_execution(self):
        row = {"kind": "PyCharm Python Console", "source": "consoles/history/py", "command": "a=5", "timestamp": "2026-11-06T19:00:00+02:00"}
        assessment = assess_event_evidence(row)["evidence_assessment"]
        self.assertEqual(assessment["evidence_class"], "preserved_command_text")
        self.assertEqual(assessment["confidence"], "high")
        self.assertFalse(assessment["execution_proven"])
        self.assertIn("time_normalization", row)

    def test_sqlite_residue_is_low_confidence(self):
        row = {"kind": "Possible residual command", "source": "database.sqlite", "command": "exec('x')"}
        assessment = assess_event_evidence(row)["evidence_assessment"]
        self.assertEqual(assessment["evidence_class"], "recovered_fragment")
        self.assertEqual(assessment["confidence"], "low")

    def test_process_creation_event_is_scoped_to_process_start(self):
        row = {"kind": "Windows audit", "description": "Создание процесса", "details": {"event_id": 4688, "fields": {"NewProcessName": "python.exe"}}}
        assessment = assess_event_evidence(row)["evidence_assessment"]
        self.assertEqual(assessment["evidence_class"], "recorded_process_start")
        self.assertTrue(assessment["execution_proven"])
        self.assertIn("внутри", assessment["what_it_supports"])


class CorrelationTests(unittest.TestCase):
    def test_parent_child_link_uses_pid_fields(self):
        events = [
            {"timestamp": "2026-11-06T10:00:00+00:00", "kind": "Windows audit", "description": "Создание процесса", "details": {"event_id": 4688, "fields": {"NewProcessId": "0x64", "NewProcessName": "cmd.exe"}}},
            {"timestamp": "2026-11-06T10:00:02+00:00", "kind": "Windows audit", "description": "Создание процесса", "details": {"event_id": 4688, "fields": {"NewProcessId": "0x65", "ProcessId": "0x64", "NewProcessName": "python.exe"}}},
        ]
        links = correlate_events(events)
        self.assertTrue(any(link["relation"] == "parent_child_process" for link in links))

    def test_exact_process_guid_links_start_and_end(self):
        events = [
            {"timestamp": "2026-11-06T10:00:00+00:00", "details": {"event_id": 1, "fields": {"ProcessId": 100, "ProcessGuid": "{ABC}"}}},
            {"timestamp": "2026-11-06T10:00:09+00:00", "details": {"event_id": 5, "fields": {"ProcessId": 100, "ProcessGuid": "{ABC}"}}},
        ]
        links = correlate_events(events)
        self.assertTrue(any(link["relation"] == "same_process_start_end" and link["confidence"] == "high" for link in links))

    def test_analysis_attaches_annotations_and_correlations(self):
        events = [{"kind": "IPython history", "source": "history.sqlite", "command": "print(1)", "timestamp": "2026-11-06T10:00:00+00:00"}]
        result = attach_analysis(events)
        self.assertIn("evidence_assessment", events[0])
        self.assertEqual(result["evidence_class_counts"]["preserved_command_text"], 1)
        self.assertEqual(result["correlations_count"], 0)


class CoverageAndExportTests(unittest.TestCase):
    def test_coverage_marks_disabled_and_missing_as_incomplete(self):
        readiness = {"checks": [{"name": "4688", "status": "disabled"}, {"name": "Sysmon", "status": "inaccessible"}], "status_counts": {"disabled": 1, "inaccessible": 1}}
        coverage = build_scan_coverage([], readiness, [], [], [])
        self.assertEqual(coverage["overall"], "incomplete")
        self.assertEqual(coverage["disabled_now"], 1)
        self.assertEqual(coverage["unavailable_or_missing"], 1)

    def test_non_windows_readiness_is_not_applicable_not_enabled(self):
        report = collect_audit_readiness()
        if not windows_compatibility()["is_windows"]:
            self.assertTrue(all(row["status"] == "not_applicable" for row in report["checks"]))

    def test_copy_original_artifact_is_byte_identical_and_hashable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "python_history.txt"
            source.write_bytes(b"a=5\nb=5\na+b\n")
            target = root / "included"
            manifest = copy_original_artifacts([{"path": str(source), "type": "history"}], target)
            copied = next(target.glob("*"))
            self.assertEqual(copied.read_bytes(), source.read_bytes())
            self.assertEqual(manifest[0]["status"], "copied")
            self.assertEqual(manifest[0]["sha256_of_copy"], hashlib.sha256(source.read_bytes()).hexdigest())

    def test_event_log_export_is_explicitly_not_applicable_off_windows(self):
        if not windows_compatibility()["is_windows"]:
            with tempfile.TemporaryDirectory() as temp:
                result = export_event_logs(Path(temp), ["Security"])
                self.assertEqual(result[0]["status"], "not_applicable")


if __name__ == "__main__":
    unittest.main(verbosity=2)
