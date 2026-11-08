from __future__ import annotations

"""Bounded, Unicode-aware global search across loaded PAV result collections."""

import json
import re
from typing import Any, Iterable


def _flatten(value: Any, depth: int = 0, budget: list[int] | None = None) -> str:
    if budget is None:
        budget = [50000]
    if budget[0] <= 0 or depth > 6:
        return ""
    budget[0] -= 1
    if value is None:
        return ""
    if isinstance(value, dict):
        return " ".join(f"{k} {_flatten(v, depth + 1, budget)}" for k, v in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten(v, depth + 1, budget) for v in list(value)[:500])
    return str(value)


def global_search(collections: dict[str, Iterable[Any]], query: str, *, case_sensitive: bool = False,
                  regex: bool = False, max_results: int = 5000) -> list[dict[str, Any]]:
    """Return source-labelled results; malformed regex fails clearly."""
    query = str(query or "").strip()
    if not query:
        return []
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(query, flags) if regex else None
    needle = query if case_sensitive else query.casefold()
    results: list[dict[str, Any]] = []
    for section, rows in collections.items():
        for index, row in enumerate(rows or []):
            if not isinstance(row, dict):
                row = {"value": row}
            text = _flatten(row)
            matched = bool(pattern.search(text)) if pattern else (needle in (text if case_sensitive else text.casefold()))
            if matched:
                results.append({"section": section, "index": index, "row": row,
                                "title": str(row.get("name") or row.get("kind") or row.get("category") or row.get("type") or section),
                                "timestamp": str(row.get("timestamp") or row.get("modified_local") or row.get("added_local") or ""),
                                "source": str(row.get("source") or row.get("path") or row.get("original_path") or ""),
                                "excerpt": text[:1000]})
                if len(results) >= max_results:
                    return results
    return results


def compare_file_reports(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Compare statically collected file reports without loading either file."""
    left_pe = left.get("pe_analysis") or {}
    right_pe = right.get("pe_analysis") or {}

    def names(rows: Any, key: str) -> set[str]:
        output = set()
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                output.add(str(row.get(key) or row.get("name") or row.get("function") or row.get("api") or "").casefold())
            else:
                output.add(str(row).casefold())
        return {x for x in output if x}

    def section_map(pe: dict[str, Any]) -> dict[str, dict[str, Any]]:
        out = {}
        for row in pe.get("sections", []) if isinstance(pe.get("sections"), list) else []:
            if isinstance(row, dict):
                name = str(row.get("name", ""))
                if name:
                    out[name] = row
        return out

    left_sections, right_sections = section_map(left_pe), section_map(right_pe)
    li, ri = names(left_pe.get("imports"), "name"), names(right_pe.get("imports"), "name")
    le, rexp = names(left_pe.get("exports"), "name"), names(right_pe.get("exports"), "name")
    return {
        "left": {"name": left.get("name", ""), "path": left.get("path", ""), "sha256": left.get("sha256", "")},
        "right": {"name": right.get("name", ""), "path": right.get("path", ""), "sha256": right.get("sha256", "")},
        "identical_hash": bool(left.get("sha256")) and left.get("sha256") == right.get("sha256"),
        "size_delta_bytes": (right.get("size_bytes") or 0) - (left.get("size_bytes") or 0),
        "file_type_changed": left.get("file_type") != right.get("file_type"),
        "pe_status": {"left": left_pe.get("status", "not_pe"), "right": right_pe.get("status", "not_pe")},
        "architecture_changed": left_pe.get("architecture") != right_pe.get("architecture"),
        "machine_changed": left_pe.get("machine") != right_pe.get("machine"),
        "imports": {"added": sorted(ri - li), "removed": sorted(li - ri), "common": len(li & ri)},
        "exports": {"added": sorted(rexp - le), "removed": sorted(le - rexp), "common": len(le & rexp)},
        "sections": {
            "added": sorted(set(right_sections) - set(left_sections)),
            "removed": sorted(set(left_sections) - set(right_sections)),
            "changed": sorted(name for name in set(left_sections) & set(right_sections)
                              if left_sections[name] != right_sections[name]),
        },
        "note": "Static metadata comparison only. It does not establish that either file is malicious or that differing files are related.",
    }
