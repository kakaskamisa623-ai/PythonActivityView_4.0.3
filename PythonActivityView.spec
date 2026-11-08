# -*- mode: python ; coding: utf-8 -*-
# One-file, windowed build. Elevation remains opt-in via the app's UAC action.

from pathlib import Path
import importlib.util

from PyInstaller.utils.hooks import collect_submodules

project_root = Path(SPECPATH)
hiddenimports = [
    "forensic_review",
    "pav_features_250",
    "pav_v30",
    "pav_browser",
    "pav_runtime",
    "pav_330",
    "pav_plugins",
    "pav_encoding",
    "pav_casebook",
    "pav_search",
    "pav_exports",
    "pav_diagnostics",
]

# Optional parsers are included only if installed in the environment used to
# build the EXE. This keeps the base application buildable without them.
def has_module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False

optional_modules = {
    "Evtx": ["Evtx.Evtx"],
    "Registry": ["Registry"],
    "LnkParse3": ["LnkParse3"],
    "jumplist_parser": ["jumplist_parser"],
    "pefile": ["pefile"],
    "capstone": ["capstone"],
}
for root_name, modules in optional_modules.items():
    if has_module(root_name):
        hiddenimports.extend(modules)

# Dissect uses plugin modules and dynamic imports; collect the specific parser
# packages only when their parent distributions are installed.
if has_module("dissect.target"):
    try:
        hiddenimports += collect_submodules("dissect.target.plugins.os.windows.prefetch")
    except Exception:
        hiddenimports.append("dissect.target.plugins.os.windows.prefetch")
if has_module("dissect.database"):
    try:
        hiddenimports += collect_submodules("dissect.database.ese")
    except Exception:
        hiddenimports.append("dissect.database.ese")

analysis = Analysis(
    [str(project_root / "PythonActivityView.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=[],
    hiddenimports=sorted(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="PythonActivityView",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)
