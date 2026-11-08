from __future__ import annotations

"""Explicit, opt-in plugin registry for Python Activity View.

A plugin is a trusted Python module exposing:
    PAV_PLUGIN = {"name": "Example", "version": "1.0", "read_only": True}
    def analyze(context: dict) -> dict: ...

Discovery only reads file names/JSON metadata; it never imports or executes a
plugin. Loading is a separate explicit action because a plugin is executable
code and inherits the user's permissions.
"""

import importlib.util
import json
from pathlib import Path
from typing import Any


class PluginRegistry:
    def __init__(self, plugin_dir: Path):
        self.plugin_dir = Path(plugin_dir)
        self.loaded: dict[str, Any] = {}

    def discover(self) -> list[dict[str, Any]]:
        self.plugin_dir.mkdir(parents=True, exist_ok=True)
        rows = []
        for path in sorted(self.plugin_dir.glob("*.py")):
            if path.name.startswith("_"):
                continue
            rows.append({"file": path.name, "path": str(path), "status": "not_loaded",
                         "note": "Модуль не выполнялся. Загрузка требует отдельного явного действия."})
        return rows

    def load(self, filename: str, approved: bool = False) -> dict[str, Any]:
        if not approved:
            raise PermissionError("Plugin loading requires explicit approval by the user.")
        path = (self.plugin_dir / filename).resolve()
        if path.parent != self.plugin_dir.resolve() or path.suffix.casefold() != ".py" or not path.is_file():
            raise ValueError("Invalid plugin path.")
        module_name = "pav_user_plugin_" + path.stem
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ImportError("Unable to load plugin module.")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        metadata = getattr(module, "PAV_PLUGIN", {})
        analyzer = getattr(module, "analyze", None)
        if not isinstance(metadata, dict) or not callable(analyzer):
            raise ValueError("Plugin must define PAV_PLUGIN dict and analyze(context) function.")
        self.loaded[filename] = module
        return {"file": filename, "name": str(metadata.get("name", path.stem)),
                "version": str(metadata.get("version", "unknown")),
                "read_only": bool(metadata.get("read_only", False)),
                "warning": "Плагин — исполняемый код; он работает с правами текущего процесса."}

    def run(self, filename: str, context: dict[str, Any]) -> dict[str, Any]:
        if filename not in self.loaded:
            raise KeyError("Plugin has not been loaded.")
        result = self.loaded[filename].analyze(context)
        if not isinstance(result, dict):
            raise TypeError("Plugin analyze() must return a dictionary.")
        return result
