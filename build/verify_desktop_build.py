"""Reject stale/mixed runtimes and prove frozen critical modules match sources."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import marshal
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

def locked_versions() -> dict[str, str]:
    result = {}
    for filename in ("requirements-runtime.lock.txt", "requirements-build.lock.txt"):
        for line in (ROOT / filename).read_text(encoding="utf-8").splitlines():
            if "==" in line and not line.startswith("#"):
                name, version = line.strip().split("==")
                result[name] = version
    return result


def normalize(code: types.CodeType) -> types.CodeType:
    return code.replace(co_filename="<source>", co_consts=tuple(
        normalize(value) if isinstance(value, types.CodeType) else value
        for value in code.co_consts
    ))


def verify(distribution: Path | None) -> None:
    from paxoinsight import VERSION
    from paxoinsight.runtime import require_supported_runtime

    require_supported_runtime()
    if importlib.metadata.version("paxoinsight") != VERSION:
        raise RuntimeError("Stale project metadata shadows the current app version")
    versions = locked_versions()
    for name, expected in versions.items():
        actual = importlib.metadata.version(name)
        if actual != expected:
            raise RuntimeError(f"Lock mismatch: {name} {actual}, expected {expected}")
    if distribution is None:
        print(f"Verified {len(versions)} exact dependency versions; "
              f"Python {sys.version.split()[0]}")
        return

    import pefile
    from PyInstaller.archive.readers import CArchiveReader

    exe = distribution / "PaxoInsight.exe"
    pyz = CArchiveReader(str(exe)).open_embedded_archive("PYZ.pyz")
    forbidden = ("PaxoInsight", "pip", "setuptools", "pkg_resources", "fastapi", "uvicorn", "httpx")
    if found := [name for name in pyz.toc
                 if any(name == item or name.startswith(item + ".") for item in forbidden)]:
        raise RuntimeError(f"Forbidden frozen modules: {found[:10]}")
    modules = (
        "archive_service", "archive_io", "analysis_inputs", "legacy_backend",
        "_vendor.analyzers", "runtime", "self_test", "security_self_test", "rar_metadata",
        "workflow", "reporting", "models", "ui.password_dialog", "ui.tk_main_window",
        "analysis_service", "jvm_class", "kotlin_source", "kotlin_analysis", "kotlin_coverage",
        "ui.appearance", "ui.brand_logo",
    )
    checked = []
    for relative in modules:
        name = "paxoinsight." + relative
        source = ROOT / "src" / (name.replace(".", "/") + ".py")
        frozen = pyz.extract(name)
        expected = compile(source.read_bytes(), str(source), "exec", optimize=1)
        if marshal.dumps(normalize(frozen)) != marshal.dumps(normalize(expected)):
            raise RuntimeError(f"Frozen code differs from reviewed source: {name}")
        checked.append(name)
    dll = distribution / "_internal/python314.dll"
    with pefile.PE(str(dll), fast_load=False) as pe:
        pe_versions = [table.entries.get(b"FileVersion", b"").decode("utf-8")
                       for group in getattr(pe, "FileInfo", []) for info in group
                       for table in getattr(info, "StringTable", [])]
    dll_version = next((value for value in pe_versions if value), "")
    # CPython's fixed PE version encodes release level in the patch field (8150
    # for 3.14.8 final). Check the readable version AND the complete DLL hash.
    base_dll = Path(sys.base_prefix) / "python314.dll"
    with dll.open("rb") as packaged, base_dll.open("rb") as base:
        packaged_hash = hashlib.file_digest(packaged, "sha256").hexdigest()
        base_hash = hashlib.file_digest(base, "sha256").hexdigest()
    if dll_version != sys.version.split()[0] or packaged_hash != base_hash:
        raise RuntimeError(f"Mixed Python DLL: {dll_version}; interpreter {sys.version.split()[0]}")
    metadata = {name: importlib.metadata.version(name) for name in versions}
    report = {"python": sys.version, "python_dll": dll_version,
              "python_dll_sha256": packaged_hash,
              "matched_frozen_sources": checked, "dependencies": metadata,
              "forbidden_modules_absent": True}
    (distribution / "BUILD_VERIFICATION.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Verified Python DLL and {len(checked)} frozen source modules")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", action="store_true")
    parser.add_argument("--distribution", type=Path)
    arguments = parser.parse_args()
    verify(arguments.distribution)
