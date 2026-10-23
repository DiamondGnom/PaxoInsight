from __future__ import annotations

import dataclasses
import gzip
import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

import py7zr
from defusedxml.common import DefusedXmlException

from paxoinsight.analysis_inputs import MAX_METADATA_BYTES, parse_xml, read_limited
from paxoinsight.archive_io import GuardedArchiveOutput
from paxoinsight.archive_service import ArchiveService
from paxoinsight.legacy_backend import load_legacy_backend
from paxoinsight.models import AnalysisOptions, OperationCancelled


class UntrustedInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archives = ArchiveService(self.root / "work")

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, source, **options):
        return self.archives.prepare(
            source,
            AnalysisOptions(delete_source_archive=False, **options),
            lambda *_: None,
            Event(),
        )

    def test_xml_dtd_entities_and_large_metadata_are_rejected(self):
        source = self.root / "pom.xml"
        for dtd in (
            '<!DOCTYPE a [<!ENTITY x "expanded">]><a>&x;</a>',
            '<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>',
            '<!DOCTYPE a SYSTEM "http://127.0.0.1/internal"><a/>',
        ):
            source.write_text(dtd, encoding="utf-8")
            with self.assertRaises(DefusedXmlException):
                parse_xml(source)
        source.write_bytes(b"<a>" + b"x" * MAX_METADATA_BYTES + b"</a>")
        with self.assertRaises(ValueError):
            parse_xml(source)
        with self.assertRaises(ValueError):
            read_limited(io.StringIO("x" * (MAX_METADATA_BYTES + 1)))

    def test_normal_xml_and_dependency_analysis_still_work(self):
        source = self.root / "pom.xml"
        source.write_text(
            "<project><dependencies><dependency><groupId>test</groupId>"
            "<artifactId>example</artifactId><version>1.2</version>"
            "</dependency></dependencies></project>",
            encoding="utf-8",
        )
        self.assertEqual(parse_xml(source).getroot().tag, "project")
        dependencies = load_legacy_backend()._extract_dependencies(str(self.root))
        self.assertEqual(dependencies["pom"][0]["name"], "test:example")

    def test_tar_directory_bomb_is_rejected_and_cleaned(self):
        source = self.root / "directories.tar"
        with tarfile.open(source, "w") as archive:
            for index in range(5):
                item = tarfile.TarInfo(f"directory-{index}")
                item.type = tarfile.DIRTYPE
                archive.addfile(item)
        with self.assertRaises(ValueError):
            self.prepare(source, max_files=3)
        self.assertFalse(list((self.root / "work").glob("PaxoInsight-*")))

    def test_implicit_directories_count_towards_extraction_budget(self):
        source = self.root / "deep.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("a/b/c/d/data.txt", b"one file, four directories")
        with self.assertRaises(ValueError):
            self.prepare(source, max_files=3)

    def test_duplicate_destinations_and_control_characters_are_rejected(self):
        for filename in ("bad\rname.txt", "bad\x7fname.txt", "/absolute", "../escape"):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                self.archives._validate_member_name(filename)
        source = self.root / "duplicates.tar"
        with tarfile.open(source, "w") as archive:
            for _ in range(2):
                item = tarfile.TarInfo("same.txt")
                item.size = 3
                archive.addfile(item, io.BytesIO(b"abc"))
        with self.assertRaises(FileExistsError):
            self.prepare(source)

    def test_7z_false_size_metadata_cannot_bypass_actual_output_limit(self):
        source = self.root / "misreported.7z"
        with py7zr.SevenZipFile(source, "w") as archive:
            archive.writestr(b"a" * 4096, "payload.bin")
        original = py7zr.SevenZipFile.list

        def false_sizes(archive):
            return [dataclasses.replace(item, uncompressed=1) for item in original(archive)]

        with (
            patch.object(py7zr.SevenZipFile, "list", false_sizes),
            self.assertRaises(py7zr.exceptions.DecompressionBombError),
        ):
            self.prepare(source, max_unpacked_bytes=32)
        self.assertFalse(list((self.root / "work").glob("PaxoInsight-*")))

    def test_stream_copy_cancellation_releases_temporary_files(self):
        source = self.root / "cancel.gz"
        source.write_bytes(gzip.compress(b"data"))
        destination = self.root / "destination"
        destination.mkdir()
        cancelled = Event()
        cancelled.set()
        with self.assertRaises(OperationCancelled):
            self.archives._extract_gzip(source, destination, AnalysisOptions(), cancelled)
        self.assertFalse(list(destination.iterdir()))

    def test_rar_password_is_sent_to_stdin_and_never_to_argv(self):
        source = self.root / "encrypted.rar"
        source.write_bytes(b"Rar!\x1a\x07\x00 synthetic")
        destination = self.root / "rar-output"

        class Archive:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def needs_password(self):
                return True

            def setpassword(self, password):
                pass

            def infolist(self):
                return []

        class Input(io.BytesIO):
            recorded = b""

            def close(self):
                self.recorded = self.getvalue()

        class Process:
            stdin = Input()

            def poll(self):
                return 0

            def wait(self):
                return 0

        process = Process()
        self.archives._seven_zip = Path("7z")
        secret = "temporary-archive-password"
        with (
            patch("paxoinsight.archive_service.RarMetadataFile", return_value=Archive()),
            patch("paxoinsight.archive_service.subprocess.Popen", return_value=process) as popen,
        ):
            self.archives._extract_rar(source, destination, AnalysisOptions(), secret)
        command = popen.call_args.args[0]
        self.assertNotIn(secret, repr(command))
        self.assertIn("-tRar", command)
        self.assertEqual(process.stdin.recorded, (secret + "\n").encode())
        source.write_bytes(b"Rar!\x1a\x07\x01\x00 synthetic")
        with (
            patch("paxoinsight.archive_service.RarMetadataFile", return_value=Archive()),
            patch("paxoinsight.archive_service.subprocess.Popen", return_value=Process()) as popen,
        ):
            self.archives._extract_rar(source, destination, AnalysisOptions(), secret)
        self.assertIn("-tRar5", popen.call_args.args[0])

    def test_directory_limits_apply_to_existing_and_nested_trees(self):
        tree = self.root / "tree"
        (tree / "a" / "b" / "c").mkdir(parents=True)
        with self.assertRaises(ValueError):
            self.archives._enforce_limits(tree, AnalysisOptions(max_files=2))

    def test_packaging_stops_before_consuming_disk_headroom(self):
        target = self.root / "output.7z"
        usage = type("Usage", (), {"free": 512 * 1024**2 + 2})()
        with (
            target.open("xb", buffering=0) as raw,
            GuardedArchiveOutput(raw, self.root, Event(), 1024) as writer,
            patch("paxoinsight.archive_io.shutil.disk_usage", return_value=usage),
            self.assertRaisesRegex(ValueError, "свободного места"),
        ):
            writer.write(b"payload")
        self.assertEqual(target.stat().st_size, 0)

    def test_legacy_extractor_uses_validated_path_checks(self):
        source = self.root / "legacy.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("../escaped.txt", b"attack")
        with self.assertRaises(ValueError):
            load_legacy_backend()._extract_archive_static(str(source), str(self.root / "out"))
        self.assertFalse((self.root / "escaped.txt").exists())
