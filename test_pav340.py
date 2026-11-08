from __future__ import annotations

import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path

from pav_encoding import decode_text_bytes, read_text_compat, read_python_source_compat
from pav_330 import analyze_pe_static, inspect_file
from pav_browser import parse_domain_rule_input


def make_minimal_pe64_dll(path: Path) -> None:
    """Create a tiny valid PE32+ DLL fixture with one import and executable section."""
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    pe = 0x80
    image[pe:pe + 4] = b"PE\0\0"
    coff = pe + 4
    struct.pack_into("<HHIIIHH", image, coff,
                     0x8664, 1, 0x65000000, 0, 0, 0xF0, 0x2022)
    opt = coff + 20
    struct.pack_into("<H", image, opt, 0x20B)
    struct.pack_into("<I", image, opt + 16, 0x1000)
    struct.pack_into("<Q", image, opt + 24, 0x140000000)
    struct.pack_into("<I", image, opt + 32, 0x1000)
    struct.pack_into("<I", image, opt + 36, 0x200)
    struct.pack_into("<I", image, opt + 56, 0x2000)
    struct.pack_into("<I", image, opt + 60, 0x200)
    struct.pack_into("<H", image, opt + 68, 3)
    struct.pack_into("<H", image, opt + 70, 0x8160)
    struct.pack_into("<I", image, opt + 108, 16)
    # Import data-directory entry #1: RVA 0x1100, size 40 bytes.
    struct.pack_into("<II", image, opt + 112 + 8, 0x1100, 40)
    section = opt + 0xF0
    image[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)  # code, execute, read
    # Minimal x64 function bytes in .text.
    image[0x200:0x205] = bytes.fromhex("48 83 EC 28 C3")
    # Import descriptor, then a zero descriptor.
    struct.pack_into("<IIIII", image, 0x300, 0x1140, 0, 0, 0x1130, 0x1150)
    image[0x330:0x33D] = b"KERNEL32.dll\0"
    struct.pack_into("<Q", image, 0x340, 0x1160)
    struct.pack_into("<Q", image, 0x348, 0)
    struct.pack_into("<H", image, 0x360, 0)
    image[0x362:0x377] = b"WriteProcessMemory\0"
    cp1251_text = "DLL библиотека".encode("cp1251")
    image[0x380:0x380 + len(cp1251_text)] = cp1251_text
    utf8_text = "DLL UTF8 кириллица".encode("utf-8")
    image[0x390:0x390 + len(utf8_text)] = utf8_text
    path.write_bytes(image)


class CyrillicSupportTests(unittest.TestCase):
    def test_cp1251_text_keeps_cyrillic(self):
        raw = "Проверка кириллицы: файл и путь".encode("cp1251")
        text, enc = decode_text_bytes(raw)
        self.assertIn("Проверка кириллицы", text)
        self.assertNotIn("\ufffd", text)
        self.assertTrue(enc)

    def test_utf8_bom_text(self):
        raw = "Тестовая строка".encode("utf-8-sig")
        text, enc = decode_text_bytes(raw)
        self.assertEqual(text, "Тестовая строка")
        self.assertEqual(enc, "utf-8-sig")

    def test_cp1251_file_path_and_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "проверка.txt"
            path.write_bytes("Привет, Windows!".encode("cp1251"))
            text, _encoding = read_text_compat(path)
            self.assertEqual(text, "Привет, Windows!")

    def test_casefold_supports_cyrillic(self):
        self.assertIn("папка", "ПАПКА с ФАЙЛАМИ".casefold())

    def test_cp866_oem_text(self):
        raw = "История команд Windows".encode("cp866")
        text, encoding = decode_text_bytes(raw, prefer_oem=True)
        self.assertIn("История команд", text)
        self.assertEqual(encoding, "cp866")

    def test_python_source_cp1251_without_cookie(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "код.py"
            path.write_bytes("# комментарий на русском\nvalue = 42\n".encode("cp1251"))
            text, _encoding = read_python_source_compat(path)
            self.assertIn("комментарий на русском", text)


class ApplicationHistoryEncodingTests(unittest.TestCase):
    def test_python_history_reader_decodes_cp1251_commands(self):
        from PythonActivityView import read_text_history
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "python_history.txt"
            path.write_bytes("print('Привет из истории')\n".encode("cp1251"))
            rows, meta = read_text_history(path)
            self.assertTrue(rows)
            self.assertIn("Привет из истории", rows[0]["command"])

    def test_deep_history_reader_decodes_cp1251_and_reports_encoding(self):
        from PythonActivityView import read_deep_text_artifact
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".bash_history"
            path.write_bytes('python "проект/скрипт.py" --имя "Тест"\n'.encode("cp1251"))
            rows, meta = read_deep_text_artifact(path)
            self.assertTrue(rows)
            self.assertIn("проект/скрипт.py", rows[0]["command"])
            self.assertEqual(meta["text_encoding"], "cp1251")


class WindowsCliDecodingTests(unittest.TestCase):
    @patch("pav_v30.subprocess.run")
    def test_readonly_windows_command_decodes_cp866(self, mocked_run):
        from pav_v30 import _run_readonly
        mocked_run.return_value = SimpleNamespace(
            returncode=0,
            stdout="Аудит успешно включён".encode("cp866"),
            stderr=b"",
        )
        code, stdout, stderr = _run_readonly(["auditpol", "/get", "/category:*"])
        self.assertEqual(code, 0)
        self.assertIn("Аудит", stdout)
        self.assertIn("включён", stdout)
        self.assertEqual(stderr, "")


class PEStaticAnalysisTests(unittest.TestCase):
    def test_minimal_pe64_dll_headers_and_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "пример.dll"
            make_minimal_pe64_dll(path)
            report = analyze_pe_static(path, include_disassembly=True)
            self.assertEqual(report["machine"], "x64")
            self.assertEqual(report["bitness"], 64)
            self.assertTrue(report["characteristics"]["is_dll"])
            self.assertGreaterEqual(report["import_dll_count"], 1)
            self.assertEqual(report["imports"][0]["dll"], "KERNEL32.dll")
            self.assertIn("WriteProcessMemory", report["imports"][0]["functions"])
            self.assertTrue(any(item["family"] == "process_memory" for item in report["api_indicators"]))
            self.assertTrue(any("DLL библиотека" in item["value"] for item in report["strings"]))
            self.assertTrue(any("DLL UTF8 кириллица" in item["value"] for item in report["strings"]))
            self.assertFalse(report["execution_performed"])

    def test_inspect_file_attaches_pe_analysis(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "test.dll"
            make_minimal_pe64_dll(path)
            report = inspect_file(path, signature_check=False)
            self.assertIn("pe_analysis", report)
            self.assertEqual(report["pe_analysis"]["machine"], "x64")

    def test_invalid_mz_is_reported_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.dll"
            path.write_bytes(b"MZ" + b"\x00" * 80)
            report = inspect_file(path, signature_check=False)
            self.assertEqual(report["pe_analysis"]["status"], "parse_error")
            self.assertFalse(report["execution_performed"])


class BulkDomainRuleInputTests(unittest.TestCase):
    def test_parses_comma_colon_and_newline_separated_urls(self):
        domains, invalid = parse_domain_rule_input(
            "https://one.example/path, two.example : https://three.example\nhttps://four.example"
        )
        self.assertEqual(domains, ["one.example", "two.example", "three.example", "four.example"])
        self.assertEqual(invalid, [])

    def test_preserves_scheme_and_numeric_ports(self):
        domains, invalid = parse_domain_rule_input(
            "https://localhost:8080, https://example.net:8443 : https://other.example"
        )
        self.assertEqual(domains, ["localhost", "example.net", "other.example"])
        self.assertEqual(invalid, [])

    def test_deduplicates_normalized_hosts_and_reports_invalid_fragments(self):
        domains, invalid = parse_domain_rule_input(
            "HTTPS://Example.COM/path, example.com, not a url, https://пример.рф"
        )
        self.assertEqual(domains, ["example.com", "xn--e1afmkfd.xn--p1ai"])
        self.assertEqual(invalid, ["not a url"])

    def test_unspaced_absolute_url_colon_separator(self):
        domains, invalid = parse_domain_rule_input("https://one.example:https://two.example")
        self.assertEqual(domains, ["one.example", "two.example"])
        self.assertEqual(invalid, [])

    def test_unspaced_bare_domain_colon_separator_without_splitting_port(self):
        domains, invalid = parse_domain_rule_input("one.example:two.example, port.example:8080")
        self.assertEqual(domains, ["one.example", "two.example", "port.example"])
        self.assertEqual(invalid, [])

    def test_bracketed_ipv6_urls_and_ports_are_kept(self):
        domains, invalid = parse_domain_rule_input("[::1]:8080, https://[2001:db8::1]:8443")
        self.assertEqual(domains, ["::1", "2001:db8::1"])
        self.assertEqual(invalid, [])



if __name__ == "__main__":
    unittest.main()
