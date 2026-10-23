"""Small synthetic security regressions executable inside the frozen application."""

from __future__ import annotations

import bz2
import dataclasses
import json
import pyexpat
import ssl
import struct
import sys
import tarfile
import tempfile
import types
import warnings
import zipfile
import zlib
from pathlib import Path
from threading import Event
from unittest.mock import patch

import py7zr

from . import VERSION
from .analysis_inputs import parse_xml
from .archive_service import ArchiveService
from .models import AnalysisOptions
from .reporting import build_kotlin_html_report
from .runtime import require_supported_runtime


def check_zip_allocation(service: ArchiveService, root: Path) -> int:
    """Real ZIP with false small size; bound the test payload itself to 16 MiB."""
    source = root / "memory.zip"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_BZIP2) as archive:
        archive.writestr("payload.bin", bytes(16 * 1024**2))
    data = bytearray(source.read_bytes())
    central = data.index(b"PK\x01\x02")
    checksum = zlib.crc32(bytes(32))
    for offset, value in ((14, checksum), (22, 32), (central + 16, checksum),
                          (central + 24, 32)):
        struct.pack_into("<I", data, offset, value)
    source.write_bytes(data)
    allocations = []

    class Decoder:
        def __init__(self):
            self.decoder = bz2.BZ2Decompressor()

        def __getattr__(self, name):
            return getattr(self.decoder, name)

        def decompress(self, *arguments, **keywords):
            value = self.decoder.decompress(*arguments, **keywords)
            allocations.append(len(value))
            return value

    original = zipfile._get_decompressor

    def decoder(kind):
        return Decoder() if kind == zipfile.ZIP_BZIP2 else original(kind)

    destination = root / "memory-output"
    destination.mkdir()
    with patch.object(zipfile, "_get_decompressor", side_effect=decoder):
        service._extract_zip(source, destination, AnalysisOptions(max_unpacked_bytes=32), None)
    largest = max(allocations, default=0)
    if largest > 1024**2 or (destination / "payload.bin").stat().st_size != 32:
        raise RuntimeError("ZIP decompressor allocation is not bounded")
    return largest


def run_security_self_test(report_path: Path | None = None) -> int:
    require_supported_runtime()
    checks = []
    largest = 0
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-SecurityTest-") as temporary:
        root = Path(temporary)
        service = ArchiveService(root / "work")
        options = AnalysisOptions(delete_source_archive=False)

        def rejected(source, **changes):
            try:
                session = service.prepare(source, dataclasses.replace(options, **changes),
                                          lambda *_: None, Event())
            except (ValueError, FileExistsError, py7zr.exceptions.DecompressionBombError) as error:
                if list((root / "work").glob("PaxoInsight-*")):
                    raise RuntimeError("Failed extraction left a workspace") from error
                return
            service.cleanup(session)
            raise RuntimeError(f"Unsafe input was accepted: {source.name}")

        for name in ("../outside.txt", "C:/outside.txt", "data.txt:stream"):
            source = root / "unsafe.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(name, b"synthetic")
            rejected(source)
        checks.append("zip_unsafe_paths_rejected")

        source = root / "duplicates.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("same.txt", "first")
                archive.writestr("same.txt", "second")
        rejected(source)
        checks.append("zip_duplicates_rejected")

        source = root / "directories.tar"
        with tarfile.open(source, "w") as archive:
            for index in range(5):
                item = tarfile.TarInfo(f"directory-{index}")
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
        rejected(source, max_files=3)
        checks.append("tar_directory_budget")

        source = root / "implicit.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("a/b/c/d/data.txt", b"data")
        rejected(source, max_files=3)
        checks.append("zip_implicit_directory_budget")

        folder = root / "folder"
        folder.mkdir()
        for index in range(5):
            (folder / f"directory-{index}").mkdir()
        rejected(folder, max_files=3)
        if len(list(folder.iterdir())) != 5:
            raise RuntimeError("Folder source was modified")
        checks.append("folder_directory_budget_and_source_preserved")

        source = root / "payload.7z"
        with py7zr.SevenZipFile(source, "w") as archive:
            archive.writestr(b"A" * 4096, "payload.bin")
        listing = py7zr.SevenZipFile.list

        def false_listing(archive):
            return [dataclasses.replace(item, uncompressed=1) for item in listing(archive)]

        with patch.object(py7zr.SevenZipFile, "list", false_listing):
            rejected(source, max_unpacked_bytes=32)
        checks.append("7z_actual_write_budget_mocked_listing")

        source = root / "disk.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("payload.bin", b"A" * 4096)
        with patch("shutil.disk_usage", return_value=types.SimpleNamespace(free=0)):
            rejected(source)
        checks.append("disk_reserve_mocked_free_space")

        xml = root / "pom.xml"
        xml.write_text('<!DOCTYPE a [<!ENTITY x "test">]><a>&x;</a>', encoding="utf-8")
        try:
            parse_xml(xml)
        except Exception as error:
            if type(error).__name__ != "DTDForbidden":
                raise
        else:
            raise RuntimeError("XML DTD was accepted")
        checks.append("xml_dtd_rejected")

        value = '<script>alert("synthetic")</script>.kt'
        result = types.SimpleNamespace(
            analysis_data={"kotlin_mapping": {"unmatched_main": [value]}},
            kotlin_files=[value], class_files=[], source_name=value, finished_at="synthetic",
        )
        html = build_kotlin_html_report(result)
        if "<script>" in html or "&lt;script&gt;" not in html:
            raise RuntimeError("Report did not escape untrusted text")
        checks.append("html_report_escaped")

        largest = check_zip_allocation(service, root)
        checks.append("zip_bzip2_decoder_allocation_bounded")

    report = {
        "version": VERSION, "python": sys.version, "openssl": ssl.OPENSSL_VERSION,
        "expat": pyexpat.EXPAT_VERSION, "py7zr": py7zr.__version__,
        "checks_passed": checks, "largest_zip_decoder_buffer": largest,
        "test_payload_expansion_limit": 16 * 1024**2,
        "scope": "Synthetic regressions; not full native parser fuzzing or certification",
    }
    if report_path is not None:
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0
