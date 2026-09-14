from __future__ import annotations

import importlib
import os
import sys
from contextlib import suppress
from pathlib import Path
from types import ModuleType

_CURRENT_DEPENDENCIES = ("py7zr", "rarfile", "tkinterdnd2")


def _development_legacy_root() -> Path:
    override = os.environ.get("PAXOINSIGHT_LEGACY_ROOT")
    if override:
        return Path(override).expanduser().resolve()
    return (
        Path(__file__).resolve().parents[3]
        / ".inspection_v5_1_0"
        / "PaxoInsight_v5.1.0_Portable"
    )


def load_legacy_backend() -> ModuleType:
    """Load the proven v5 analysis algorithms without starting its Tk interface."""
    # PaxoInsight 5.1 adds its adjacent ``lib`` directory to the start of
    # sys.path.  That directory contains CPython 3.12 native extensions and
    # must never provide dependencies to the Python 3.14 application.  Load
    # the current environment's packages first and remove the legacy path
    # again after importing the pure-Python analyzer module.
    for dependency in _CURRENT_DEPENDENCIES:
        with suppress(ModuleNotFoundError):
            importlib.import_module(dependency)

    try:
        return importlib.import_module("PaxoInsight")
    except ModuleNotFoundError:
        root = _development_legacy_root()
        if not (root / "PaxoInsight.py").is_file():
            raise RuntimeError(
                "Не найден модуль анализаторов PaxoInsight v5.1.0. "
                "Переустановите приложение."
            ) from None
        root_value = str(root)
        legacy_lib_value = str(root / "lib")
        if root_value not in sys.path:
            sys.path.insert(0, root_value)
        try:
            return importlib.import_module("PaxoInsight")
        finally:
            while legacy_lib_value in sys.path:
                sys.path.remove(legacy_lib_value)
