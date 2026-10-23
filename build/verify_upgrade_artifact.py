"""Check public encrypted RAR fixtures and a separately unpacked portable ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path
from threading import Event

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_rar(fixtures: Path) -> dict:
    from paxoinsight.archive_service import ArchiveService
    from paxoinsight.models import AnalysisOptions
    from paxoinsight.rar_metadata import RarMetadataFile

    # These passwords belong ONLY to the upstream project's public test data.
    fixture_password = "password"
    sources = json.loads((ROOT / "docs/security-2026-10-20/rar-fixture-sources.json")
                         .read_text(encoding="utf-8"))
    rows = []
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-RarUpgrade-") as temporary:
        service = ArchiveService(Path(temporary))
        if service.seven_zip_executable is None:
            raise RuntimeError("Real RAR regression requires an installed 7-Zip")
        for fixture in sources["fixtures"]:
            source = fixtures / fixture["name"]
            if digest(source) != fixture["sha256"]:
                raise RuntimeError(f"Public fixture hash mismatch: {source.name}")
            attempts = []

            def password_provider(_source, attempt, _previous_failed, attempts=attempts):
                attempts.append(attempt)
                return ("deliberately-incorrect-test-password" if len(attempts) == 1
                        else fixture_password)

            session = service.prepare(
                source, AnalysisOptions(expand_nested=False, delete_source_archive=False),
                lambda *_: None, Event(), password_provider,
            )
            try:
                if len(attempts) != 2:
                    raise RuntimeError("Incorrect RAR password was not retried")
                crc_checks = 0
                with RarMetadataFile(source) as archive:
                    archive.setpassword(fixture_password)
                    members = [member for member in archive.infolist() if not member.isdir()]
                    expected = sorted(member.filename for member in members)
                    actual = sorted(path.relative_to(session.content_root).as_posix()
                                    for path in session.content_root.rglob("*") if path.is_file())
                    if actual != expected:
                        raise RuntimeError("RAR output file list differs")
                    for member in members:
                        output = session.content_root / member.filename
                        if output.stat().st_size != member.file_size:
                            raise RuntimeError("RAR output size differs")
                        # RAR5 data-encryption fixture uses keyed CRC; 7-Zip
                        # checks it internally. Other two fixtures have plain CRC.
                        if source.name != "rar5-psw.rar":
                            if zlib.crc32(output.read_bytes()) != member.CRC:
                                raise RuntimeError("RAR output CRC differs")
                            crc_checks += 1
                rows.append({"fixture": source.name, "sha256": digest(source),
                             "password_attempts": len(attempts), "files": actual,
                             "sizes_verified": True, "native_integrity_verified": True,
                             "additional_plain_crc_checks": crc_checks})
            finally:
                service.cleanup(session)
            if session.session_root.exists() or digest(source) != fixture["sha256"]:
                raise RuntimeError("RAR cleanup/source preservation failed")
        return {"status": "passed", "cases": rows, "cleanup_verified": True,
                "seven_zip": str(service.seven_zip_executable),
                "scope": "Current source core, real native 7-Zip, public RAR3/RAR5 fixtures"}


def verify_zip(path: Path) -> dict:
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-PortableUpgrade-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(path) as archive:
            if bad := archive.testzip():
                raise RuntimeError(f"ZIP CRC mismatch: {bad}")
            for name in archive.namelist():
                (root / name).resolve().relative_to(root.resolve())
            archive.extractall(root)  # nosec B202: just-built ZIP; all destinations checked above
        distribution = root / "PaxoInsight"
        manifest = json.loads((distribution / "BUNDLE_MANIFEST.json").read_text(encoding="utf-8"))
        for row in manifest["files"]:
            file = distribution / row["path"]
            if file.stat().st_size != row["size"] or digest(file) != row["sha256"]:
                raise RuntimeError(f"Manifest mismatch: {row['path']}")
        environment = os.environ.copy()
        for name in ("PYTHONPATH", "PYTHONHOME", "PAXOINSIGHT_BUILD_PYTHON"):
            environment.pop(name, None)
        environment["PAXOINSIGHT_LEGACY_ROOT"] = str(root / "not-an-installed-backend")
        executable = distribution / "PaxoInsight.exe"
        checks = []
        for option in ("--self-test", "--gui-self-test", "--security-self-test"):
            command = [str(executable), option]
            if option == "--security-self-test":
                command.extend(("--self-test-report", str(root / "security-result.json")))
            result = subprocess.run(command, cwd=root, env=environment, check=False,
                                    timeout=120, creationflags=flags)
            if result.returncode:
                raise RuntimeError(f"Unpacked EXE {option} failed: {result.returncode}")
            checks.append(option)
        security = json.loads((root / "security-result.json").read_text(encoding="utf-8"))
        return {"status": "passed", "zip_sha256": digest(path),
                "zip_size": path.stat().st_size, "exe_sha256": digest(executable),
                "manifest_files_verified": len(manifest["files"]), "checks_passed": checks,
                "frozen_security_report": security,
                "scope": "Fresh temporary extraction; Python/backend overrides removed; "
                         "not a separate clean Windows VM"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, required=True)
    parser.add_argument("--rar-fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    report = {"rar": verify_rar(arguments.rar_fixtures), "portable": verify_zip(arguments.zip)}
    arguments.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
