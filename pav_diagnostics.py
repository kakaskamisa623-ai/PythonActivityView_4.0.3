from __future__ import annotations

"""Read-only runtime and dependency diagnostics."""

import importlib.util
import os
import platform
import sys
import tempfile
from pathlib import Path
from typing import Any

OPTIONAL_MODULES = {
    "python-evtx": "Evtx",
    "python-registry": "Registry",
    "LnkParse3": "LnkParse3",
    "jumplist_parser": "jumplist_parser",
    "pefile": "pefile",
    "Capstone": "capstone",
    "Dissect Target": "dissect.target",
    "ReportLab (PDF)": "reportlab",
}


def collect_diagnostics(app_data: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    modules = {}
    for label, module in OPTIONAL_MODULES.items():
        try:
            modules[label] = bool(importlib.util.find_spec(module))
        except (ImportError, ModuleNotFoundError, ValueError):
            modules[label] = False
    tkinter_version = "unavailable"
    try:
        import tkinter
        tkinter_version = str(tkinter.TkVersion)
    except Exception:
        pass
    writable = None
    app_data_path = Path(app_data).expanduser() if app_data else None
    if app_data_path:
        try:
            app_data_path.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(prefix="pav_diag_", dir=app_data_path, delete=True):
                writable = True
        except Exception:
            writable = False
    return {
        "python": sys.version,
        "python_executable": sys.executable,
        "platform": platform.platform(),
        "architecture": platform.architecture()[0],
        "tk_version": tkinter_version,
        "is_frozen": bool(getattr(sys, "frozen", False)),
        "is_windows": os.name == "nt",
        "optional_modules": modules,
        "app_data_path": str(app_data_path) if app_data_path else "",
        "app_data_writable": writable,
        "environment_note": "Diagnostics inspect versions and module availability only. No network request or system change is performed.",
    }
