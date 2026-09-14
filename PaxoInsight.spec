# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

project_root = Path(SPECPATH)
workspace_root = project_root.parent
src_root = project_root / "src"
legacy_root = workspace_root / ".inspection_v5_1_0" / "PaxoInsight_v5.1.0_Portable"

a = Analysis(
    [str(project_root / "launcher.py")],
    pathex=[
        str(src_root),
        str(legacy_root),
    ],
    binaries=[],
    # The current PyInstaller hook selects only the Windows x64/Tcl 9 TkDnD
    # payload.  Collecting the whole package would also ship unrelated Linux,
    # macOS, x86 and ARM binaries.
    datas=[
        (str(project_root / "assets" / "paxoinsight-icon.png"), "assets"),
        (str(project_root / "assets" / "paxoinsight-logo.png"), "assets"),
    ],
    hiddenimports=[
        "PaxoInsight",
        "py7zr",
        "rarfile",
        "tkinter",
        "tkinter.ttk",
        "tkinterdnd2",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PySide6", "shiboken6"],
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
