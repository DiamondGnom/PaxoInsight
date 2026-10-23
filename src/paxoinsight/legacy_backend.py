from __future__ import annotations

from types import ModuleType


def load_legacy_backend() -> ModuleType:
    """Load bundled v5.1 algorithms with input hardening, without GUI or old DLLs."""
    from ._vendor import analyzers

    return analyzers
