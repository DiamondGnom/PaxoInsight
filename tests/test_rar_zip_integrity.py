from __future__ import annotations

import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from paxoinsight.archive_service import (
    ArchiveContentMismatch,
    ArchiveService,
    find_7zip_executable,
)
from paxoinsight.models import AnalysisOptions
from paxoinsight.self_test import stored_rar_fixture
from paxoinsight.workflow import WorkflowService


def zip_bytes(name: str, payload: bytes) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(name, payload)
    return stream.getvalue()


class RarZipIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.service = ArchiveService(self.root / "work")
        self.members = {
            "first.zip": zip_bytes("first.txt", b"first ZIP payload"),
            "keep.txt": b"RAR sibling must survive",
            "last.zip": zip_bytes("last.txt", b"last ZIP payload"),
        }
        self.rar = stored_rar_fixture(self.members)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, source, **options):
        return self.service.prepare(
            source, AnalysisOptions(delete_source_archive=False, **options),
            lambda *_: None, Event(),
        )

    def test_real_rar_with_zip_footer_is_not_a_java_resource_adapter(self):
        for signature in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"):
            with self.subTest(signature=signature):
                source = self.root / "source.rar"
                source.write_bytes(signature + self.rar[7:])
                # This permissive stdlib probe is the original failure mode.
                self.assertTrue(zipfile.is_zipfile(source))
                self.assertFalse(self.service._is_application_container(source, ".rar"))
                with (
                    patch.object(self.service, "_extract_rar") as native,
                    patch.object(self.service, "_extract_zip") as wrong,
                ):
                    self.service._extract_archive(
                        source, self.root / "out", ".rar", AnalysisOptions()
                    )
                native.assert_called_once()
                wrong.assert_not_called()

    @unittest.skipUnless(find_7zip_executable(), "7-Zip is not installed")
    def test_real_rar_retains_every_zip_when_nested_expansion_is_off(self):
        source = self.root / "source.rar"
        source.write_bytes(self.rar)
        session = self.prepare(source, expand_nested=False)
        try:
            actual = {
                path.relative_to(session.content_root).as_posix(): path.read_bytes()
                for path in session.content_root.rglob("*") if path.is_file()
            }
            self.assertEqual(actual, self.members)
        finally:
            self.service.cleanup(session)

    @unittest.skipUnless(find_7zip_executable(), "7-Zip is not installed")
    def test_real_rar_expands_every_zip_and_preserves_siblings(self):
        for replace in (True, False):
            with self.subTest(replace=replace):
                source = self.root / "source.rar"
                source.write_bytes(self.rar)
                session = self.prepare(
                    source, replace_nested_archives=replace,
                    unpack_application_containers=False,
                )
                try:
                    actual = {
                        path.relative_to(session.content_root).as_posix(): path.read_bytes()
                        for path in session.content_root.rglob("*") if path.is_file()
                    }
                    expected = {
                        "first/first.txt": b"first ZIP payload",
                        "last/last.txt": b"last ZIP payload",
                        "keep.txt": self.members["keep.txt"],
                    }
                    if not replace:
                        expected.update(self.members)
                    self.assertEqual(actual, expected)
                    self.assertEqual(set(session.expanded_archives), {"first.zip", "last.zip"})
                finally:
                    self.service.cleanup(session)

    @unittest.skipUnless(find_7zip_executable(), "7-Zip is not installed")
    def test_real_rar_inside_zip_is_not_skipped_with_application_option_off(self):
        source = self.root / "source.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("bundle.rar", self.rar)
        session = self.prepare(source, unpack_application_containers=False)
        try:
            self.assertEqual(
                (session.content_root / "bundle/first/first.txt").read_bytes(),
                b"first ZIP payload",
            )
            self.assertEqual(
                (session.content_root / "bundle/last/last.txt").read_bytes(),
                b"last ZIP payload",
            )
            self.assertEqual(
                (session.content_root / "bundle/keep.txt").read_bytes(), self.members["keep.txt"]
            )
            self.assertEqual(len(session.expanded_archives), 3)
        finally:
            self.service.cleanup(session)

    @unittest.skipUnless(find_7zip_executable(), "7-Zip is not installed")
    def test_full_rar_zip_analysis_and_7z_roundtrip_preserves_all_payloads(self):
        source = self.root / "roundtrip.rar"
        source.write_bytes(self.rar)
        workflow = WorkflowService(self.root / "roundtrip-work")
        session = workflow.scan(source, AnalysisOptions(), lambda *_: None, Event())
        try:
            self.assertFalse(source.exists())
            self.assertTrue(session.source_deleted)
            self.assertEqual(session.result.total_files, 3)
            output = self.root / "result.7z"
            package = workflow.package(session, output, False, lambda *_: None, Event())
            self.assertTrue(package.verified)
            destination = self.root / "unpacked-result"
            destination.mkdir()
            workflow.archives._extract_7z(output, destination, AnalysisOptions(), None, Event())
            self.assertEqual(
                {path.relative_to(destination).as_posix(): path.read_bytes()
                 for path in destination.rglob("*") if path.is_file()},
                {"first/first.txt": b"first ZIP payload", "last/last.txt": b"last ZIP payload",
                 "keep.txt": self.members["keep.txt"]},
            )
        finally:
            workflow.cleanup(session)

    def test_zip_format_resource_adapter_keeps_checkbox_semantics(self):
        for empty in (True, False):
            source = self.root / "connector.rar"
            source.write_bytes(zip_bytes("META-INF/ra.xml", b"<connector/>"))
            if empty:
                with zipfile.ZipFile(source, "w"):
                    pass
            self.assertTrue(self.service._is_application_container(source, ".rar"))
            with (
                patch.object(self.service, "_extract_rar") as wrong,
                patch.object(self.service, "_extract_zip") as zip_extract,
            ):
                self.service._extract_archive(source, self.root / "out", ".rar", AnalysisOptions())
            zip_extract.assert_called_once()
            wrong.assert_not_called()
        outer = self.root / "outer.zip"
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("connector.rar", zip_bytes("META-INF/ra.xml", b"<connector/>"))
        for expand in (True, False):
            session = self.prepare(outer, unpack_application_containers=expand)
            try:
                self.assertEqual((session.content_root / "connector.rar").is_file(), not expand)
                self.assertEqual(
                    (session.content_root / "connector/META-INF/ra.xml").is_file(), expand
                )
            finally:
                self.service.cleanup(session)

    def fake_extractor(self, files):
        def extract(command, **_kwargs):
            destination = Path(next(item[2:] for item in command if item.startswith("-o")))
            for name, data in files.items():
                path = destination / name
                if data is None:
                    path.mkdir(parents=True, exist_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            return type(
                "Process", (), {"stdin": None, "poll": lambda _: 0, "wait": lambda _: 0}
            )()
        return extract

    def assert_incomplete_extraction_stops_workflow(self, files, *, nested=False):
        source = self.root / ("source.zip" if nested else "source.rar")
        if nested:
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("inner.rar", self.rar)
        else:
            source.write_bytes(self.rar)
        original = source.read_bytes()
        workflow = WorkflowService(self.root / "workflow")
        workflow.archives._seven_zip = Path("mock-7z")
        with (
            patch("paxoinsight.archive_service.subprocess.Popen", self.fake_extractor(files)),
            patch.object(workflow.analysis, "analyze") as analysis,
            patch.object(workflow.archives, "finalize_source_deletion") as delete,
            self.assertRaises(ArchiveContentMismatch),
        ):
            workflow.scan(source, AnalysisOptions(), lambda *_: None, Event())
        analysis.assert_not_called()
        delete.assert_not_called()
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse(list((self.root / "workflow").glob("PaxoInsight-*")))

    def test_native_success_with_missing_zip_stops_analysis_and_keeps_source(self):
        files = dict(self.members)
        del files["first.zip"]
        self.assert_incomplete_extraction_stops_workflow(files)

    def test_native_success_with_truncated_zip_stops_analysis_and_keeps_source(self):
        files = dict(self.members)
        files["first.zip"] = b"truncated"
        self.assert_incomplete_extraction_stops_workflow(files)

    def test_native_success_with_unexpected_file_stops_analysis_and_keeps_source(self):
        self.assert_incomplete_extraction_stops_workflow({**self.members, "extra.txt": b"extra"})

    def test_native_success_with_unexpected_directory_stops_analysis_and_keeps_source(self):
        self.assert_incomplete_extraction_stops_workflow({**self.members, "extra": None})

    def test_nested_rar_mismatch_is_not_swallowed_and_keeps_outer_source(self):
        self.assert_incomplete_extraction_stops_workflow({"keep.txt": b"partial"}, nested=True)

    def test_missing_password_named_file_does_not_trigger_password_retry(self):
        source = self.root / "source.rar"
        source.write_bytes(stored_rar_fixture({"passwords.zip": b"important"}))
        self.service._seven_zip = Path("mock-7z")
        with (
            patch("paxoinsight.archive_service.subprocess.Popen", self.fake_extractor({})),
            patch.object(self.service, "_reset_destination") as reset,
            self.assertRaises(ArchiveContentMismatch),
        ):
            self.prepare(source)
        reset.assert_not_called()
        self.assertTrue(source.is_file())

    def test_duplicate_rar_destinations_are_rejected_before_native_overwrite(self):
        first = stored_rar_fixture({"same.txt": b"first"})
        second = stored_rar_fixture({"same.txt": b"second"})
        source = self.root / "duplicate.rar"
        source.write_bytes(first[:-7] + second[20:-7] + first[-7:])
        self.service._seven_zip = Path("mock-7z")
        with (
            patch("paxoinsight.archive_service.subprocess.Popen") as native,
            self.assertRaises(ArchiveContentMismatch),
        ):
            self.prepare(source)
        native.assert_not_called()

    def test_rar_file_directory_conflict_is_rejected_before_native_overwrite(self):
        source = self.root / "conflict.rar"
        source.write_bytes(stored_rar_fixture({"folder": b"file", "folder/data.txt": b"data"}))
        self.service._seven_zip = Path("mock-7z")
        with (
            patch("paxoinsight.archive_service.subprocess.Popen") as native,
            self.assertRaises(ArchiveContentMismatch),
        ):
            self.prepare(source)
        native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
