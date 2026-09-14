from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

from paxoinsight.legacy_backend import load_legacy_backend


class Python314MigrationTests(unittest.TestCase):
    def test_legacy_cp312_dependencies_are_never_used(self) -> None:
        backend = load_legacy_backend()
        legacy_lib = Path(backend.__file__).resolve().parent / "lib"

        self.assertNotIn(str(legacy_lib), sys.path)
        for name in ("cryptography", "py7zr", "rarfile", "tkinterdnd2"):
            module = importlib.import_module(name)
            module_path = Path(module.__file__).resolve()
            self.assertFalse(
                module_path.is_relative_to(legacy_lib),
                f"{name} was loaded from the legacy CPython 3.12 bundle: {module_path}",
            )


if __name__ == "__main__":
    unittest.main()
