# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path
from PyInstaller.utils.hooks import copy_metadata

project_root = Path(SPECPATH)
src_root = project_root / "src"
runtime_metadata = []
for line in (project_root / "requirements-runtime.lock.txt").read_text(encoding="utf-8").splitlines():
    if "==" in line and not line.startswith("#"):
        runtime_metadata.extend(copy_metadata(line.split("==", 1)[0]))
runtime_metadata.extend(copy_metadata("paxoinsight"))

a = Analysis(
    [str(project_root / "launcher.py")],
    pathex=[
        str(src_root),
    ],
    binaries=[],
    # The current PyInstaller hook selects only the Windows x64/Tcl 9 TkDnD
    # payload.  Collecting the whole package would also ship unrelated Linux,
    # macOS, x86 and ARM binaries.
    datas=runtime_metadata + [
        (str(project_root / "assets" / "paxoinsight-icon.png"), "assets"),
        (str(project_root / "assets" / "paxoinsight-logo.png"), "assets"),
    ],
    hiddenimports=[
        "paxoinsight._vendor.analyzers",
        "py7zr",
        "rarfile",
        "tkinter",
        "tkinter.ttk",
        "tkinterdnd2",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "PySide6", "shiboken6", "fastapi", "uvicorn", "httpx",
        "pip", "setuptools", "pkg_resources", "wheel", "PaxoInsight",
    ],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PaxoInsight",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    icon=str(project_root / "assets" / "paxoinsight.ico"),
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="PaxoInsight",
)
