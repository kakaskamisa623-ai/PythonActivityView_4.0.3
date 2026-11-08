from __future__ import annotations

"""Unicode and legacy Windows text decoding helpers for Python Activity View."""

import locale
import os
import re
import sys
from pathlib import Path
from typing import Iterable


_CODING_COOKIE = re.compile(br"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")


def _text_score(value: str) -> tuple[int, int, int]:
    """Prefer readable text with plausible Cyrillic over mojibake."""
    cyrillic = sum(1 for ch in value if "\u0400" <= ch <= "\u052f")
    replacement = value.count("\ufffd")
    # Common UTF-8-as-ANSI mojibake fragments; penalize, but do not reject.
    mojibake = sum(value.count(token) for token in ("Рђ", "РЎ", "Рњ", "СЂ", "Сѓ", "Ã", "Â"))
    return (cyrillic - mojibake * 2, -replacement, -mojibake)


def decode_text_bytes(data: bytes, *, prefer_oem: bool = False) -> tuple[str, str]:
    """Decode text from common Windows/Unicode encodings without losing Cyrillic.

    Returns (text, encoding). UTF BOMs and valid UTF-8 are preferred. If the
    input is legacy Windows text, the Windows ANSI code page / CP1251 / CP866
    are tried and the most plausible readable candidate is selected.
    """
    if not data:
        return "", "utf-8"
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", errors="replace"), "utf-8-sig"
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16", errors="replace"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", errors="replace"), "utf-16-be"

    # BOM-less UTF-16 is common in exported Windows text/XML files.
    sample = data[:4096]
    if len(sample) >= 8:
        even_nuls = sample[0::2].count(0)
        odd_nuls = sample[1::2].count(0)
        if odd_nuls > len(sample) // 8 and odd_nuls > even_nuls * 2:
            try:
                return data.decode("utf-16-le"), "utf-16-le"
            except UnicodeDecodeError:
                pass
        if even_nuls > len(sample) // 8 and even_nuls > odd_nuls * 2:
            try:
                return data.decode("utf-16-be"), "utf-16-be"
            except UnicodeDecodeError:
                pass

    # Explicit Python source encoding declaration has priority after BOMs.
    first_line = data.splitlines()[0][:256] if data else b""
    match = _CODING_COOKIE.match(first_line)
    if match:
        try:
            encoding = match.group(1).decode("ascii")
            return data.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError):
            pass

    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass

    candidates: list[str] = []
    if os.name == "nt":
        # mbcs follows the active Windows ANSI code page (e.g. CP1251).
        candidates.append("mbcs")
    try:
        preferred = locale.getpreferredencoding(False)
        if preferred:
            candidates.append(preferred)
    except Exception:
        pass
    if prefer_oem:
        candidates.extend(("cp866", "cp1251", "cp1252"))
    else:
        candidates.extend(("cp1251", "cp866", "cp1252"))

    decoded: list[tuple[tuple[int, int, int], str, str]] = []
    seen: set[str] = set()
    for encoding in candidates:
        key = encoding.casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            text = data.decode(encoding)
        except (LookupError, UnicodeDecodeError):
            continue
        decoded.append((_text_score(text), text, encoding))
    if decoded:
        decoded.sort(key=lambda item: item[0], reverse=True)
        _score, text, encoding = decoded[0]
        return text, encoding

    # Last-resort decoding never crashes the whole scan. Preserve bytes as
    # replacement characters and report the chosen fallback to the caller.
    return data.decode("utf-8", errors="replace"), "utf-8-replace"


def read_text_compat(path: str | os.PathLike[str], *, prefer_oem: bool = False,
                     max_bytes: int | None = None) -> tuple[str, str]:
    """Read a local text artifact with BOM/UTF-8/Windows Cyrillic fallback."""
    file_path = Path(path)
    with file_path.open("rb") as stream:
        data = stream.read(max_bytes + 1 if max_bytes is not None else -1)
    if max_bytes is not None and len(data) > max_bytes:
        data = data[:max_bytes]
    return decode_text_bytes(data, prefer_oem=prefer_oem)


def read_python_source_compat(path: str | os.PathLike[str]) -> tuple[str, str]:
    """Read Python source respecting PEP 263 and legacy CP1251/CP866 files."""
    file_path = Path(path)
    raw = file_path.read_bytes()
    # tokenize.open handles UTF-8 BOM and PEP 263 coding cookies. It uses
    # UTF-8 by default; use the compatibility decoder only if that fails.
    try:
        import tokenize
        with tokenize.open(str(file_path)) as stream:
            return stream.read(), "python-source-cookie/default"
    except (SyntaxError, UnicodeDecodeError, LookupError):
        return decode_text_bytes(raw)
