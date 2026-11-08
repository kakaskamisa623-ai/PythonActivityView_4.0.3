from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from pav_casebook import (
    add_evidence, append_audit,
    export_case_package, import_case_package, load_case, mark_evidence_excluded,
    migrate_case, new_case, save_case, verify_audit_chain, verify_case,
    verify_case_package,
)
from pav_search import compare_file_reports, global_search


class CasebookTests(unittest.TestCase):
    def test_case_audit_chain_detects_changed_record(self):
        case = new_case("Тестовое дело")
        append_audit(case, "note", {"text": "привет"})
        self.assertTrue(verify_audit_chain(case)["valid"])
        case["audit_log"][0]["action"] = "rewritten"
        self.assertFalse(verify_audit_chain(case)["valid"])

    def test_add_evidence_unicode_path_and_hash_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "исходный файл.dll"
            source.write_bytes(b"safe static sample\x00\x01")
            case_path = root / "дело.json"
            case = new_case("Проверка кириллицы")
            save_case(case, case_path)
            record = add_evidence(case, case_path, source, "Тестовое примечание")
            save_case(case, case_path)
            self.assertEqual(record["name"], source.name)
            self.assertEqual(len(record["sha256"]), 64)
            result = verify_case(case, case_path)
            self.assertTrue(result["valid"])
            stored = case_path.parent / Path(record["stored_path"])
            stored.write_bytes(b"tampered")
            result = verify_case(case, case_path)
            self.assertFalse(result["valid"])
            self.assertEqual(result["evidence"][0]["status"], "hash_mismatch")

    def test_package_export_verify_and_import_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "пример.txt"
            source.write_text("данные", encoding="utf-8")
            case_path = root / "дело.json"
            package = root / "дело.pavcase"
            case = new_case("Дело 01", "Заметки")
            add_evidence(case, case_path, source, "source sample")
            save_case(case, case_path)
            export_case_package(case, case_path, package, "4.0.0")
            checked = verify_case_package(package)
            self.assertTrue(checked["valid"])
            imported = import_case_package(package, root / "imported")
            imported_case = load_case(imported)
            self.assertEqual(imported_case["name"], "Дело 01")
            self.assertEqual(imported_case["evidence"][0]["name"], "пример.txt")
            imported_check = verify_case(imported_case, imported)
            self.assertTrue(imported_check["valid"])

    def test_package_tampering_is_detected_and_nothing_is_extracted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_path = root / "case.json"
            package = root / "case.pavcase"
            case = new_case("Case")
            save_case(case, case_path)
            export_case_package(case, case_path, package)
            tampered = root / "tampered.pavcase"
            with zipfile.ZipFile(package) as src, zipfile.ZipFile(tampered, "w") as dst:
                for name in src.namelist():
                    data = src.read(name)
                    if name == "case.json":
                        data += b" "
                    dst.writestr(name, data)
            self.assertFalse(verify_case_package(tampered)["valid"])
            destination = root / "must_stay_empty"
            destination.mkdir()
            with self.assertRaises(ValueError):
                import_case_package(tampered, destination)
            self.assertEqual(list(destination.iterdir()), [])

    def test_unsafe_evidence_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case_path = root / "case.json"
            payload = new_case("Unsafe")
            payload["evidence"].append({"evidence_id": "x", "stored_path": "../outside", "sha256": "0" * 64})
            save_case(payload, case_path)
            result = verify_case(payload, case_path)
            self.assertFalse(result["valid"])
            self.assertEqual(result["evidence"][0]["status"], "error")

    def test_excluded_evidence_is_not_required_in_portable_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "item.bin"
            source.write_bytes(b"sample")
            case_path = root / "case.json"
            package = root / "case.pavcase"
            case = new_case("Exclusion")
            record = add_evidence(case, case_path, source)
            self.assertTrue(mark_evidence_excluded(case, record["evidence_id"]))
            save_case(case, case_path)
            export_case_package(case, case_path, package)
            imported = import_case_package(package, root / "imported")
            imported_case = load_case(imported)
            result = verify_case(imported_case, imported)
            self.assertTrue(result["valid"])
            self.assertEqual(result["evidence"][0]["status"], "excluded")

    def test_legacy_case_migration_preserves_notes_and_trusted_paths(self):
        old = {"name": "Legacy", "notes": "Сохранить", "trusted_context_paths": ["C:/trusted.exe"]}
        migrated = migrate_case(old)
        self.assertEqual(migrated["notes"], "Сохранить")
        self.assertEqual(migrated["trusted_context_paths"], ["C:/trusted.exe"])
        self.assertTrue(verify_audit_chain(migrated)["valid"])


class GlobalSearchTests(unittest.TestCase):
    def test_global_search_is_unicode_aware_and_casefolded(self):
        collections = {"browser": [{"url": "https://пример.рф/ПУТЬ", "title": "Тестовый сайт"}]}
        results = global_search(collections, "ТЕСТОВЫЙ")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["section"], "browser")

    def test_global_search_regex_and_result_limit(self):
        collections = {"events": [{"command": "python test.py"}, {"command": "java -jar file.jar"}, {"command": "pythonw app.py"}]}
        results = global_search(collections, r"python\w?", regex=True, max_results=1)
        self.assertEqual(len(results), 1)

    def test_invalid_regex_is_reported_by_regex_engine(self):
        with self.assertRaises(Exception):
            global_search({"x": [{"text": "abc"}]}, "[", regex=True)

    def test_file_comparison_returns_import_export_differences(self):
        left = {"name": "a.dll", "sha256": "a", "size_bytes": 10, "pe_analysis": {"status": "parsed", "architecture": "x64", "imports": [{"name": "CreateFileW"}, {"name": "ReadFile"}], "exports": [{"name": "Start"}], "sections": [{"name": ".text", "entropy": 4.1}]}}
        right = {"name": "b.dll", "sha256": "b", "size_bytes": 15, "pe_analysis": {"status": "parsed", "architecture": "x86", "imports": [{"name": "CreateFileW"}, {"name": "WriteFile"}], "exports": [{"name": "Init"}], "sections": [{"name": ".text", "entropy": 7.8}, {"name": ".data"}]}}
        result = compare_file_reports(left, right)
        self.assertEqual(result["size_delta_bytes"], 5)
        self.assertTrue(result["architecture_changed"])
        self.assertIn("writefile", result["imports"]["added"])
        self.assertIn("readfile", result["imports"]["removed"])
        self.assertEqual(result["sections"]["added"], [".data"])


if __name__ == "__main__":
    unittest.main()
