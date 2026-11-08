from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pav_runtime import analyze_python_java_processes, assess_suspiciousness

from pav_330 import (
    _parse_event_xml,
    build_hourly_heatmap,
    import_evtx_file,
    inspect_file,
    parse_prefetch_header,
    parse_prefetch_file,
    scan_artifact_inventory,
    summarize_independent_evidence,
)
from pav_plugins import PluginRegistry


def evtx_xml(event_id: int, fields: dict[str, str] | None = None, provider: str = "Microsoft-Windows-Sysmon") -> str:
    fields_xml = "".join(f'<Data Name="{name}">{value}</Data>' for name, value in (fields or {}).items())
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><Provider Name="{provider}"/><EventID>{event_id}</EventID>
      <TimeCreated SystemTime="2026-11-08T12:00:00.000Z"/><EventRecordID>123</EventRecordID>
      <Computer>TEST-PC</Computer></System><EventData>{fields_xml}</EventData></Event>'''


class EvtxImportTests(unittest.TestCase):
    def test_sysmon_network_event_for_python_is_parsed_as_metadata(self):
        row = _parse_event_xml(evtx_xml(3, {
            "Image": r"C:\\Python\\python.exe",
            "DestinationHostname": "example.test",
            "DestinationIp": "203.0.113.10",
            "DestinationPort": "443",
        }), "sample.evtx", 123)
        self.assertIsNotNone(row)
        self.assertIn("network metadata", row["description"])
        self.assertIn("python.exe", row["command"].casefold())
        self.assertEqual(row["details"]["event_id"], 3)
        self.assertTrue(row["details"]["imported_evtx"])

    def test_unrelated_network_events_are_filtered(self):
        self.assertIsNone(_parse_event_xml(evtx_xml(3, {"Image": r"C:\\Windows\\System32\\svchost.exe"}), "sample.evtx"))
        self.assertIsNone(_parse_event_xml(evtx_xml(5156, {"Application": r"C:\\Windows\\System32\\notepad.exe"}, "Microsoft-Windows-Security-Auditing"), "sample.evtx"))

    def test_system_clock_change_is_preserved(self):
        row = _parse_event_xml(evtx_xml(4616, {"ProcessName": r"C:\\Windows\\System32\\svchost.exe"}, "Microsoft-Windows-Security-Auditing"), "sample.evtx")
        self.assertIsNotNone(row)
        self.assertEqual(row["details"]["event_id"], 4616)
        self.assertIn("time changed", row["description"])

    def test_evtx_signature_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "not.evtx"
            path.write_bytes(b"not an evtx")
            events, meta, warnings = import_evtx_file(path)
            self.assertEqual(events, [])
            self.assertEqual(meta["status"], "error")
            self.assertTrue(any("сигнатур" in item.casefold() for item in warnings))


class StaticFileTests(unittest.TestCase):
    def test_python_source_is_inspected_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "safe_sample.py"
            path.write_text("VALUE = 42\nprint(VALUE)\n", encoding="utf-8")
            result = inspect_file(path, signature_check=False)
            self.assertEqual(result["python_syntax"], "valid")
            self.assertFalse(result["execution_performed"])
            self.assertEqual(len(result["sha256"]), 64)

    def test_invalid_python_syntax_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.py"
            path.write_text("def broken(:\n", encoding="utf-8")
            result = inspect_file(path, signature_check=False)
            self.assertEqual(result["python_syntax"], "syntax_error")
            self.assertEqual(result["python_syntax_error"]["line"], 1)

    def test_jar_manifest_is_read_as_archive_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.jar"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nMain-Class: example.Main\n")
                archive.writestr("example/Main.class", b"dummy")
            result = inspect_file(path, signature_check=False)
            self.assertEqual(result["file_type"], "ZIP/JAR archive")
            self.assertEqual(result["manifest"].get("Main-Class"), "example.Main")
            self.assertFalse(result["execution_performed"])

    def test_missing_file_fails_clearly(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                inspect_file(Path(tmp) / "missing.exe", signature_check=False)


class WindowsArtifactTests(unittest.TestCase):
    def test_prefetch_header_parses_only_stable_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "PYTHON.EXE-12345678.pf"
            header = bytearray(512)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            name = "PYTHON.EXE".encode("utf-16le")
            header[16:16 + len(name)] = name
            header[76:80] = (0x12345678).to_bytes(4, "little")
            path.write_bytes(header)
            result = parse_prefetch_header(path)
            self.assertEqual(result["status"], "header_parsed")
            self.assertEqual(result["format_version"], 30)
            self.assertEqual(result["executable_name"], "PYTHON.EXE")
            self.assertEqual(result["prefetch_hash"], 0x12345678)
            self.assertIn("не интерпретируются", result["note"])

    def test_non_windows_inventory_is_marked_not_applicable(self):
        import os
        if os.name == "nt":
            self.skipTest("This branch is for non-Windows environments")
        result = scan_artifact_inventory()
        self.assertEqual(result["events"], [])
        self.assertEqual(result["sources"][0]["status"], "not_applicable")

    def test_prefetch_parser_unavailable_is_reported_without_guessing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "PYTHON.EXE-12345678.pf"
            header = bytearray(512)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[16:36] = "PYTHON.EXE".encode("utf-16le")
            path.write_bytes(header)
            with patch.dict(sys.modules, {"dissect": None, "dissect.target": None,
                                          "dissect.target.plugins": None, "dissect.target.plugins.os": None,
                                          "dissect.target.plugins.os.windows": None,
                                          "dissect.target.plugins.os.windows.prefetch": None}):
                events, meta, warnings = parse_prefetch_file(path)
            self.assertEqual(events, [])
            self.assertEqual(meta["status"], "parser_unavailable")
            self.assertTrue(any("dissect.target" in warning for warning in warnings))

    def test_prefetch_parser_exports_latest_and_previous_timestamps(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "PYTHON.EXE-12345678.pf"
            header = bytearray(512)
            header[0:4] = (30).to_bytes(4, "little")
            header[4:8] = b"SCCA"
            header[16:36] = "PYTHON.EXE".encode("utf-16le")
            path.write_bytes(header)
            fake_modules = {}
            package_names = ["dissect", "dissect.target", "dissect.target.plugins",
                             "dissect.target.plugins.os", "dissect.target.plugins.os.windows"]
            for name in package_names:
                module = types.ModuleType(name)
                module.__path__ = []
                fake_modules[name] = module
            parser_module = types.ModuleType("dissect.target.plugins.os.windows.prefetch")
            class FakePrefetch:
                def __init__(self, stream):
                    self.stream = stream
                    self.fn = types.SimpleNamespace(run_count=4)
                def parse(self):
                    return None
                @property
                def latest_timestamp(self):
                    return datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
                @property
                def previous_timestamps(self):
                    return [datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc), None]
            parser_module.Prefetch = FakePrefetch
            fake_modules[parser_module.__name__] = parser_module
            with patch.dict(sys.modules, fake_modules):
                events, meta, warnings = parse_prefetch_file(path)
            self.assertEqual(meta["status"], "parsed")
            self.assertEqual(meta["parser_reported_run_count"], 4)
            self.assertEqual(len(events), 2)
            self.assertEqual(len(warnings), 0)
            self.assertEqual(events[-1]["details"]["timestamp_type"], "latest")


class AnalysisSummaryTests(unittest.TestCase):
    def test_heatmap_counts_events_by_local_hour(self):
        now = datetime(2026, 11, 8, 12, 30, tzinfo=datetime.now().astimezone().tzinfo)
        events = [
            {"timestamp": now.replace(hour=10).isoformat()},
            {"timestamp": now.replace(hour=10, minute=5).isoformat()},
            {"timestamp": now.replace(hour=11).isoformat()},
            {"timestamp": "not-a-timestamp"},
            {"timestamp": ""},
        ]
        result = build_hourly_heatmap(events, days=1, now=now)
        self.assertEqual(result["total_events"], 3)
        self.assertEqual(result["rows"][0]["hours"][10], 2)
        self.assertEqual(result["rows"][0]["hours"][11], 1)

    def test_repeated_events_from_one_source_do_not_inflate_source_breadth(self):
        events = [
            {"kind": "Windows Prefetch artifact", "source": r"C:\\Windows\\Prefetch\\A.pf"},
            {"kind": "Windows Prefetch artifact", "source": r"C:\\Windows\\Prefetch\\B.pf"},
            {"kind": "browser_visit", "source": r"C:\\Users\\User\\Chrome\\History"},
        ]
        result = summarize_independent_evidence(events)
        self.assertEqual(result["event_counts_by_group"]["windows_artifacts"], 2)
        self.assertEqual(result["source_counts_by_group"]["windows_artifacts"], 2)
        self.assertEqual(result["group_count"], 2)


class TrustedContextTests(unittest.TestCase):
    def _process_event(self, stamp: datetime, image: str, pid: str, parent_pid: str) -> dict:
        return {
            "timestamp": stamp.astimezone().isoformat(sep=" ", timespec="seconds"),
            "kind": "Windows process event",
            "description": "Process start",
            "source": "Windows Event Log / Security",
            "details": {
                "event_id": 4688,
                "NewProcessName": image,
                "NewProcessId": pid,
                "ProcessId": parent_pid,
            },
        }

    def test_trusted_python_java_executables_remain_visible_but_do_not_add_link_points(self):
        stamp = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
        events = [
            self._process_event(stamp, r"C:\Tools\Python\python.exe", "100", "50"),
            self._process_event(stamp + timedelta(seconds=2), r"C:\Tools\Java\javaw.exe", "200", "100"),
        ]
        runtime = analyze_python_java_processes(events)
        ordinary = assess_suspiciousness(events, runtime, [])
        trusted = assess_suspiciousness(events, runtime, [], trusted_paths=[r"C:\Tools\Python", r"C:\Tools\Java"])
        self.assertEqual(len(runtime["direct_python_java_links"]), 1)
        self.assertEqual(ordinary["score"], 12)
        self.assertEqual(trusted["score"], 0)
        self.assertTrue(any(item["type"] == "python_java_parent_child_in_user_trusted_context"
                            for item in trusted["trusted_context_matches"]))

    def test_trusted_download_path_does_not_add_execution_match_points(self):
        stamp = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
        target = r"C:\TrustedTools\helper.jar"
        download = {
            "timestamp": stamp.isoformat(), "kind": "browser_download", "description": "download",
            "command": target,
            "details": {"target_path": target, "domain_category": "unknown", "domain": "example.test"},
        }
        java = self._process_event(stamp + timedelta(seconds=30), r"C:\Java\bin\java.exe", "200", "50")
        java["details"]["CommandLine"] = f'java.exe -jar "{target}"'
        runtime = analyze_python_java_processes([download, java])
        ordinary = assess_suspiciousness([download, java], runtime, [])
        trusted = assess_suspiciousness([download, java], runtime, [], trusted_paths=[r"C:\TrustedTools"])
        self.assertEqual(len(ordinary["download_execution_matches"]), 1)
        self.assertEqual(ordinary["score"], 8)
        self.assertEqual(trusted["download_execution_matches"], [])
        self.assertEqual(trusted["score"], 0)
        self.assertTrue(trusted["trusted_context_matches"])


class PluginRegistryTests(unittest.TestCase):
    def test_discovery_does_not_execute_plugin_and_load_requires_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            plugin_dir = Path(tmp)
            marker = plugin_dir / "executed.txt"
            plugin = plugin_dir / "sample_plugin.py"
            plugin.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
                "PAV_PLUGIN = {'name': 'sample', 'version': '1', 'read_only': True}\n"
                "def analyze(context): return {'ok': True}\n",
                encoding="utf-8",
            )
            registry = PluginRegistry(plugin_dir)
            discovered = registry.discover()
            self.assertEqual(len(discovered), 1)
            self.assertFalse(marker.exists())
            with self.assertRaises(PermissionError):
                registry.load(plugin.name, approved=False)
            self.assertFalse(marker.exists())
            loaded = registry.load(plugin.name, approved=True)
            self.assertEqual(loaded["name"], "sample")
            self.assertTrue(marker.exists())
            self.assertEqual(registry.run(plugin.name, {})["ok"], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
