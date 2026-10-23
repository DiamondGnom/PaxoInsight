"""Supported desktop runtime policy, also checked before packaging."""

from __future__ import annotations

import struct
import sys
import sysconfig

MINIMUM_PYTHON = (3, 14, 8)


def require_supported_runtime() -> None:
    if sys.implementation.name != "cpython" or not (
        MINIMUM_PYTHON <= sys.version_info[:3] < (3, 15, 0)
    ):
        raise RuntimeError("PaxoInsight требует CPython 3.14.8 или новее в ветке 3.14")
    if struct.calcsize("P") != 8:
        raise RuntimeError("PaxoInsight требует 64-разрядный Python")
    if sysconfig.get_config_var("Py_GIL_DISABLED") or not getattr(
        sys, "_is_gil_enabled", lambda: True
    )():
        raise RuntimeError("Используйте обычную сборку CPython с GIL, не free-threaded")
