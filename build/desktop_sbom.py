"""Inventory the actual Windows distribution, not just a requirements file."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.metadata
import json
import sys
import uuid
from pathlib import Path

import pefile
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def generate(distribution: Path) -> None:
    from paxoinsight import VERSION
    from paxoinsight.runtime import require_supported_runtime

    require_supported_runtime()
    if sys.version_info[:3] != (3, 14, 8):
        raise RuntimeError("Refresh the verified Python archive reference before changing runtime")
    components = []
    dependencies = []
    references = {}
    for line in (ROOT / "requirements-runtime.lock.txt").read_text(encoding="utf-8").splitlines():
        if "==" not in line or line.startswith("#"):
            continue
        name, version = line.strip().split("==")
        if importlib.metadata.version(name) != version:
            raise RuntimeError(f"Dependency mismatch: {name}")
        reference = f"pkg:pypi/{canonicalize_name(name)}@{version}"
        references[canonicalize_name(name)] = reference
        components.append({"type": "library", "name": name, "version": version,
                           "bom-ref": reference, "purl": reference})
    for name, reference in references.items():
        required = []
        for value in importlib.metadata.requires(name) or []:
            requirement = Requirement(value)
            if (requirement.marker is None or requirement.marker.evaluate({"extra": ""})) and (
                child := references.get(canonicalize_name(requirement.name))
            ):
                required.append(child)
        dependencies.append({"ref": reference, "dependsOn": sorted(set(required))})

    runtime_reference = f"cpython-{sys.version.split()[0]}"
    components.append({
        "type": "platform", "name": "CPython", "version": sys.version.split()[0],
        "bom-ref": runtime_reference,
        "externalReferences": [{"type": "distribution",
                                "url": "https://www.python.org/ftp/python/3.14.8/python-3.14.8-amd64.zip",
                                "hashes": [{"alg": "SHA-256", "content":
                                            "4873947a8afc037846b180312b83c744a4146a851cfd316a75c3125a4d8299da"}]}],
    })
    native_references = []
    files = []
    excluded = {"SBOM.cdx.json", "BUNDLE_MANIFEST.json"}
    for path in sorted(distribution.rglob("*")):
        if not path.is_file() or path.name in excluded:
            continue
        relative = path.relative_to(distribution).as_posix()
        digest = sha256(path)
        files.append({"path": relative, "size": path.stat().st_size, "sha256": digest})
        if path.suffix.lower() not in {".exe", ".dll", ".pyd"}:
            continue
        with pefile.PE(str(path), fast_load=False) as image:
            if image.FILE_HEADER.Machine != 0x8664:
                raise RuntimeError(f"Non-x64 binary in distribution: {relative}")
            info = getattr(image, "VS_FIXEDFILEINFO", [])
            readable = [table.entries.get(b"FileVersion", b"").decode("utf-8")
                        for group in getattr(image, "FileInfo", []) for entry in group
                        for table in getattr(entry, "StringTable", [])]
            version = next((value for value in readable if value), "")
            if info and not version:
                value = info[0]
                version = ".".join(map(str, (value.FileVersionMS >> 16,
                                             value.FileVersionMS & 65535,
                                             value.FileVersionLS >> 16,
                                             value.FileVersionLS & 65535)))
        reference = "file:" + relative
        native_references.append(reference)
        component = {"type": "file", "name": path.name, "bom-ref": reference,
                     "hashes": [{"alg": "SHA-256", "content": digest}],
                     "properties": [{"name": "paxoinsight:path", "value": relative},
                                    {"name": "paxoinsight:architecture", "value": "x86_64"}]}
        if version:
            component["version"] = version
        components.append(component)
    dependencies.append({"ref": runtime_reference, "dependsOn": sorted(native_references)})
    dependencies.append({"ref": "paxoinsight", "dependsOn": sorted(
        [runtime_reference, *references.values()]
    )})
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
        "metadata": {
            "timestamp": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "component": {"type": "application", "name": "PaxoInsight Standalone",
                          "version": VERSION, "bom-ref": "paxoinsight"},
            "tools": {"components": [{"type": "application", "name": "desktop_sbom.py",
                                      "version": "1.0"}]},
            "properties": [{"name": "paxoinsight:scope", "value":
                            "Actual bundled Python distributions and PE binaries; "
                            "static native subcomponents may require upstream SBOMs"}],
        },
        "components": components, "dependencies": dependencies,
    }
    (ROOT / "SBOM.cdx.json").write_text(json.dumps(document, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
    (distribution / "BUNDLE_MANIFEST.json").write_text(
        json.dumps({"version": VERSION, "python": sys.version, "files": files,
                    "excluded_self_describing_files": sorted(excluded)}, indent=2), encoding="utf-8"
    )
    print(f"SBOM: {len(references)} libraries, Python, {len(native_references)} native files")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--distribution", type=Path, required=True)
    generate(parser.parse_args().distribution)
