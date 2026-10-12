from __future__ import annotations

import gzip
import io
import struct
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from threading import Event
from unittest.mock import patch

from paxoinsight.archive_service import (
    ArchivePasswordRequired,
    ArchiveService,
    find_7zip_executable,
)
from paxoinsight.models import AnalysisOptions, AnalysisResult, OperationCancelled


def _write_stored_rar(path: Path, name: str, data: bytes) -> None:
    """Create a small RAR 4 archive using the uncompressed storage method."""

    def header(body: bytes) -> bytes:
        return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body

    name_bytes = name.encode("utf-8")
    signature = b"Rar!\x1a\x07\x00"
    main_header = header(struct.pack("<BHHHI", 0x73, 0, 13, 0, 0))
    file_body = struct.pack(
        "<BHHIIBIIBBHI",
        0x74,
        0x8000,
        32 + len(name_bytes),
        len(data),
        len(data),
        2,
        zlib.crc32(data) & 0xFFFFFFFF,
        0,
        20,
        0x30,
        len(name_bytes),
        0x20,
    ) + name_bytes
    end_header = header(struct.pack("<BHH", 0x7B, 0, 7))
    path.write_bytes(signature + main_header + header(file_body) + data + end_header)


def _result(workspace: Path, source: Path) -> AnalysisResult:
    return AnalysisResult(
        source_path=str(source),
        source_name=source.name,
        source_size=source.stat().st_size,
        source_sha256="0" * 64,
        workspace=str(workspace),
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:00:01+00:00",
        duration_seconds=1.0,
        total_files=1,
        total_bytes=5,
        extension_counts={".txt": 1},
        class_files=[],
        kotlin_files=[],
        special_files=[],
        third_party_archives=[],
        remaining_archives=[],
        expanded_archives=[],
        integrity_score=100,
        integrity_verdict="OK",
        sast_mode="Не определён",
        sast_reason="",
    )


class ArchiveServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.service = ArchiveService()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_nested_archive_is_replaced_and_source_is_preserved(self) -> None:
        nested = self.root / "nested.zip"
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("inside/data.txt", "hello")
        source = self.root / "source.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.write(nested, "bundle.zip")
            archive.writestr("root.txt", "root")

        session = self.service.prepare(
            source,
            AnalysisOptions(
                expand_nested=True,
                replace_nested_archives=True,
                delete_source_archive=False,
            ),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertTrue(source.is_file())
            self.assertFalse((session.content_root / "bundle.zip").exists())
            self.assertEqual(
                (session.content_root / "bundle" / "inside" / "data.txt").read_text(),
                "hello",
            )
            self.assertIn("bundle.zip", session.expanded_archives)
        finally:
            self.service.cleanup(session)

    def test_named_zip_containers_are_accepted_as_primary_archives(self) -> None:
        extensions = (
            ".ear",
            ".bar",
            ".sar",
            ".aar",
            ".aab",
            ".eba",
            ".cba",
            ".esa",
            ".appzip",
            ".libzip",
            ".shlibzip",
            ".appdomainzip",
            ".xsdzip",
        )
        for extension in extensions:
            with self.subTest(extension=extension):
                source = self.root / f"application{extension}"
                with zipfile.ZipFile(source, "w") as archive:
                    archive.writestr("META-INF/descriptor.txt", extension)
                session = self.service.prepare(
                    source,
                    AnalysisOptions(
                        expand_nested=False, delete_source_archive=False
                    ),
                    lambda _value, _text: None,
                    Event(),
                )
                try:
                    self.assertEqual(
                        (
                            session.content_root / "META-INF" / "descriptor.txt"
                        ).read_text(),
                        extension,
                    )
                finally:
                    self.service.cleanup(session)

    def test_tar_variants_are_extracted(self) -> None:
        payload = self.root / "payload.txt"
        payload.write_text("tar content", encoding="utf-8")
        variants = {
            ".tar": "w",
            ".tar.gz": "w:gz",
            ".tgz": "w:gz",
            ".tar.bz2": "w:bz2",
            ".tbz2": "w:bz2",
            ".tar.xz": "w:xz",
            ".txz": "w:xz",
        }
        for extension, mode in variants.items():
            with self.subTest(extension=extension):
                source = self.root / f"source{extension}"
                with tarfile.open(source, mode) as archive:
                    archive.add(payload, arcname="folder/payload.txt")
                session = self.service.prepare(
                    source,
                    AnalysisOptions(
                        expand_nested=False, delete_source_archive=False
                    ),
                    lambda _value, _text: None,
                    Event(),
                )
                try:
                    self.assertEqual(
                        (
                            session.content_root / "folder" / "payload.txt"
                        ).read_text(encoding="utf-8"),
                        "tar content",
                    )
                finally:
                    self.service.cleanup(session)

    def test_standalone_gzip_is_extracted(self) -> None:
        source = self.root / "payload.txt.gz"
        with gzip.open(source, "wb") as stream:
            stream.write(b"gzip content")
        session = self.service.prepare(
            source,
            AnalysisOptions(expand_nested=False, delete_source_archive=False),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertEqual(
                (session.content_root / "payload.txt").read_bytes(), b"gzip content"
            )
        finally:
            self.service.cleanup(session)

    def _tgz_bytes(self, files: dict[str, bytes]) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return stream.getvalue()

    def test_many_nested_tgz_do_not_rescan_the_workspace_per_archive(self) -> None:
        source = self.root / "many.zip"
        payload = self._tgz_bytes({f"src/file-{i}.txt": b"data" for i in range(12)})
        with zipfile.ZipFile(source, "w") as archive:
            for index in range(32):
                archive.writestr(f"package-{index}.tgz", payload)
        with patch.object(self.service, "_walk_files", wraps=self.service._walk_files) as walks:
            session = self.service.prepare(
                source, AnalysisOptions(delete_source_archive=False), lambda *_: None, Event()
            )
        try:
            files = [path for path in session.content_root.rglob("*") if path.is_file()]
            self.assertEqual(len(files), 32 * 12)
            self.assertEqual(len(session.expanded_archives), 32)
            self.assertTrue(all(path.read_bytes() == b"data" for path in files))
            whole_tree_walks = sum(
                call.args[0] == session.content_root for call in walks.call_args_list
            )
            self.assertLessEqual(whole_tree_walks, 2)
        finally:
            self.service.cleanup(session)

    def test_tar_is_extracted_without_preloading_the_member_index(self) -> None:
        source = self.root / "streamed.tgz"
        source.write_bytes(self._tgz_bytes({f"file-{i}.txt": b"data" for i in range(25)}))
        destination = self.root / "streamed"
        destination.mkdir()
        with patch.object(
            tarfile.TarFile, "getmembers", side_effect=AssertionError("TAR pre-scan")
        ):
            self.service._extract_tar(source, destination, AnalysisOptions())
        self.assertEqual(len(list(destination.iterdir())), 25)

    def test_tgz_rejects_unsafe_paths_links_and_special_members(self) -> None:
        for name in ("../outside.txt", "/absolute.txt", "C:/absolute.txt", "file.txt:stream"):
            with self.subTest(name=name):
                source = self.root / "unsafe.tgz"
                source.write_bytes(self._tgz_bytes({name: b"no"}))
                with self.assertRaises(ValueError):
                    self.service.prepare(source, AnalysisOptions(), lambda *_: None, Event())
                self.assertFalse((self.root / "outside.txt").exists())
                self.assertTrue(source.is_file())
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                source = self.root / "link.tgz"
                with tarfile.open(source, "w:gz") as archive:
                    member = tarfile.TarInfo("link")
                    member.type = kind
                    member.linkname = "../outside.txt"
                    archive.addfile(member)
                with self.assertRaises(ValueError):
                    self.service.prepare(source, AnalysisOptions(), lambda *_: None, Event())

    def test_streamed_tgz_stops_at_file_and_size_limits(self) -> None:
        source = self.root / "limited.tgz"
        source.write_bytes(self._tgz_bytes({"first.txt": b"one", "second.txt": b"two"}))
        for options in (AnalysisOptions(max_files=1), AnalysisOptions(max_unpacked_bytes=5)):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, "лимит"):
                    self.service.prepare(source, options, lambda *_: None, Event())
                self.assertTrue(source.is_file())

    def test_global_nested_limits_keep_the_archive_and_remove_partial_output(self) -> None:
        payload = self._tgz_bytes({"first.txt": b"one", "second.txt": b"two"})
        source = self.root / "limited.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("nested.tgz", payload)
            archive.writestr("existing.txt", b"existing")
        for options in (
            AnalysisOptions(max_files=3, delete_source_archive=False),
            AnalysisOptions(max_unpacked_bytes=len(payload) + 10, delete_source_archive=False),
        ):
            with self.subTest(options=options):
                session = self.service.prepare(source, options, lambda *_: None, Event())
                try:
                    self.assertTrue((session.content_root / "nested.tgz").is_file())
                    self.assertFalse((session.content_root / "nested").exists())
                    self.assertEqual(session.expanded_archives, [])
                    self.assertEqual(
                        (session.content_root / "existing.txt").read_bytes(), b"existing"
                    )
                finally:
                    self.service.cleanup(session)

    def test_tgz_depth_limit_and_rescan_do_not_expand_retained_archives_twice(self) -> None:
        inner = self._tgz_bytes({"data.txt": b"deep"})
        outer = self._tgz_bytes({"inner.tgz": inner})
        source = self.root / "levels.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("outer.tgz", outer)
        options = AnalysisOptions(
            max_depth=1, replace_nested_archives=False, delete_source_archive=False
        )
        session = self.service.prepare(source, options, lambda *_: None, Event())
        try:
            self.assertTrue((session.content_root / "outer" / "inner.tgz").is_file())
            self.assertFalse((session.content_root / "outer" / "inner").exists())
            self.service.reprepare(session, options, lambda *_: None, Event())
            self.assertEqual(session.expanded_archives, ["outer.tgz", "outer/inner.tgz"])
            self.assertEqual(
                (session.content_root / "outer" / "inner" / "data.txt").read_bytes(), b"deep"
            )
            self.assertFalse((session.content_root / "outer_extracted_1").exists())
            self.service.reprepare(session, options, lambda *_: None, Event())
            self.assertEqual(len(session.expanded_archives), 2)
        finally:
            self.service.cleanup(session)

    def test_successfully_replaced_tgz_release_their_quota(self) -> None:
        payload = self._tgz_bytes({"one.txt": b"a" * 10, "two.txt": b"b" * 10})
        source = self.root / "quota.zip"
        with zipfile.ZipFile(source, "w") as archive:
            for index in range(3):
                archive.writestr(f"part-{index}.tgz", payload)
        for options in (
            AnalysisOptions(max_files=7, delete_source_archive=False),
            AnalysisOptions(max_unpacked_bytes=len(payload) * 3 + 20, delete_source_archive=False),
        ):
            with self.subTest(options=options):
                session = self.service.prepare(source, options, lambda *_: None, Event())
                try:
                    self.assertEqual(len(session.expanded_archives), 3)
                    self.assertFalse(list(session.content_root.rglob("*.tgz")))
                    self.assertEqual(len(list(session.content_root.rglob("*.txt"))), 6)
                finally:
                    self.service.cleanup(session)

    def test_tar_progress_reports_completed_files_and_bytes(self) -> None:
        source = self.root / "progress.tgz"
        source.write_bytes(self._tgz_bytes({"first.txt": b"one", "second.txt": b"two"}))
        destination = self.root / "progress"
        destination.mkdir()
        updates = []
        self.service._extract_tar(
            source, destination, AnalysisOptions(), Event(),
            lambda count, size: updates.append((count, size)),
        )
        self.assertEqual(updates[-1], (2, 6))
        self.assertEqual((destination / "second.txt").read_bytes(), b"two")

    def test_streamed_tar_checks_cancellation_between_members(self) -> None:
        source = self.root / "cancel.tgz"
        source.write_bytes(self._tgz_bytes({"first.txt": b"one", "second.txt": b"two"}))
        destination = self.root / "cancelled"
        destination.mkdir()
        cancelled = Event()
        original_extract = tarfile.TarFile._extract_member

        def cancel_after_member(archive, *args, **kwargs):
            original_extract(archive, *args, **kwargs)
            cancelled.set()

        with (
            patch.object(tarfile.TarFile, "_extract_member", new=cancel_after_member),
            self.assertRaises(OperationCancelled),
        ):
            self.service._extract_tar(source, destination, AnalysisOptions(), cancelled)
        self.assertTrue((destination / "first.txt").is_file())
        self.assertFalse((destination / "second.txt").exists())

    def test_nested_ear_respects_application_container_option(self) -> None:
        nested = self.root / "module.ear"
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("META-INF/application.xml", "<application/>")
        source = self.root / "with-ear.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.write(nested, "module.ear")

        session = self.service.prepare(
            source,
            AnalysisOptions(
                expand_nested=True,
                delete_source_archive=False,
                unpack_application_containers=False,
            ),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertTrue((session.content_root / "module.ear").is_file())
            self.assertFalse((session.content_root / "module").exists())
        finally:
            self.service.cleanup(session)

        session = self.service.prepare(
            source,
            AnalysisOptions(
                expand_nested=True,
                delete_source_archive=False,
                unpack_application_containers=True,
            ),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertFalse((session.content_root / "module.ear").exists())
            self.assertTrue(
                (
                    session.content_root
                    / "module"
                    / "META-INF"
                    / "application.xml"
                ).is_file()
            )
            self.assertIn("module.ear", session.expanded_archives)
        finally:
            self.service.cleanup(session)

    def test_java_resource_adapter_rar_is_detected_as_zip(self) -> None:
        source = self.root / "connector.rar"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("META-INF/ra.xml", "<connector/>")
        self.service._seven_zip = None

        session = self.service.prepare(
            source,
            AnalysisOptions(expand_nested=False, delete_source_archive=False),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertTrue(
                (session.content_root / "META-INF" / "ra.xml").is_file()
            )
        finally:
            self.service.cleanup(session)

    def test_source_archive_deletion_is_deferred_until_finalization(self) -> None:
        source = self.root / "delete-me.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("data.txt", "hello")
        session = self.service.prepare(
            source,
            AnalysisOptions(expand_nested=False),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertTrue(source.exists())
            self.assertFalse(session.source_deleted)
            self.assertEqual((session.content_root / "data.txt").read_text(), "hello")
            self.assertGreater(session.source_size, 0)
            self.assertEqual(len(session.source_sha256), 64)
            self.service.finalize_source_deletion(session)
            self.assertFalse(source.exists())
            self.assertTrue(session.source_deleted)
        finally:
            self.service.cleanup(session)

    def test_password_protected_7z_retries_until_password_is_correct(self) -> None:
        source = self.root / "protected.7z"
        with self.service._py7zr.SevenZipFile(source, "w", password="secret") as archive:
            archive.writestr(b"protected content", "inside.txt")

        prompts: list[tuple[int, bool]] = []

        def provide_password(_path: Path, attempt: int, incorrect: bool) -> str:
            prompts.append((attempt, incorrect))
            return "wrong" if attempt == 1 else "secret"

        session = self.service.prepare(
            source,
            AnalysisOptions(expand_nested=False, delete_source_archive=False),
            lambda _value, _text: None,
            Event(),
            provide_password,
        )
        try:
            self.assertEqual(
                (session.content_root / "inside.txt").read_bytes(),
                b"protected content",
            )
            self.assertEqual(prompts, [(1, False), (2, True)])
        finally:
            self.service.cleanup(session)

    def test_7zip_finder_honours_explicit_override(self) -> None:
        executable = self.root / "custom-7z.exe"
        executable.write_bytes(b"test executable")
        with patch.dict(
            "os.environ", {"PAXOINSIGHT_7ZIP": str(executable)}, clear=False
        ):
            self.assertEqual(find_7zip_executable(), executable.resolve())

    def test_rar_is_validated_and_extracted_with_7zip(self) -> None:
        source = self.root / "source.rar"
        source.write_bytes(b"Rar! test")
        destination = self.root / "rar-output"
        fake_7zip = self.root / "7z.exe"
        fake_7zip.write_bytes(b"test executable")

        class Info:
            filename = "folder/data.txt"
            file_size = 5
            file_redir = None

            @staticmethod
            def is_symlink() -> bool:
                return False

        class FakeArchive:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            @staticmethod
            def needs_password() -> bool:
                return False

            @staticmethod
            def infolist() -> list[Info]:
                return [Info()]

        class FakeRarModule:
            @staticmethod
            def RarFile(_source: Path) -> FakeArchive:  # noqa: N802
                return FakeArchive()

        self.service._seven_zip = fake_7zip
        self.service._rarfile = FakeRarModule()

        def run_7zip(command, **_kwargs):
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "folder").mkdir()
            (destination / "folder" / "data.txt").write_text("hello")
            return type(
                "Completed",
                (),
                {"returncode": 0, "stdout": "Everything is Ok", "stderr": ""},
            )()

        with patch(
            "paxoinsight.archive_service.subprocess.run", side_effect=run_7zip
        ) as runner:
            self.service._extract_rar(
                source, destination, AnalysisOptions(), password=None
            )

        command = runner.call_args.args[0]
        self.assertEqual(command[0], str(fake_7zip))
        self.assertIn("x", command)
        self.assertIn("-p", command)
        self.assertIn(f"-o{destination}", command)
        self.assertEqual(
            (destination / "folder" / "data.txt").read_text(), "hello"
        )

    @unittest.skipUnless(find_7zip_executable(), "7-Zip is not installed")
    def test_actual_rar_is_extracted_with_installed_7zip(self) -> None:
        source = self.root / "real.rar"
        _write_stored_rar(source, "folder/test.txt", b"RAR extraction works")
        session = self.service.prepare(
            source,
            AnalysisOptions(expand_nested=False, delete_source_archive=False),
            lambda _value, _text: None,
            Event(),
        )
        try:
            self.assertEqual(
                (session.content_root / "folder" / "test.txt").read_bytes(),
                b"RAR extraction works",
            )
        finally:
            self.service.cleanup(session)

    def test_encrypted_rar_requests_password_before_starting_7zip(self) -> None:
        source = self.root / "protected.rar"
        source.write_bytes(b"Rar! test")

        class FakeArchive:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            @staticmethod
            def needs_password() -> bool:
                return True

        class FakeRarModule:
            @staticmethod
            def RarFile(_source: Path) -> FakeArchive:  # noqa: N802
                return FakeArchive()

        self.service._seven_zip = self.root / "7z.exe"
        self.service._rarfile = FakeRarModule()
        with (
            patch("paxoinsight.archive_service.subprocess.run") as runner,
            self.assertRaises(ArchivePasswordRequired),
        ):
            self.service._extract_rar(
                source, self.root / "output", AnalysisOptions(), password=None
            )
        runner.assert_not_called()

    def test_zip_path_traversal_is_rejected(self) -> None:
        source = self.root / "unsafe.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("../outside.txt", "no")
        with self.assertRaisesRegex(ValueError, "Небезопасный путь"):
            self.service.prepare(
                source,
                AnalysisOptions(),
                lambda _value, _text: None,
                Event(),
            )
        self.assertFalse((self.root / "outside.txt").exists())
        self.assertTrue(source.exists())

    def test_windows_alternate_data_stream_name_is_rejected(self) -> None:
        source = self.root / "unsafe-ads.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("folder/file.txt:payload", "no")
        with self.assertRaisesRegex(ValueError, "Небезопасный путь"):
            self.service.prepare(
                source,
                AnalysisOptions(),
                lambda _value, _text: None,
                Event(),
            )

    def test_package_has_no_outer_workspace_folder_and_is_verified(self) -> None:
        source = self.root / "source.zip"
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("folder/data.txt", "hello")
        session = self.service.prepare(
            source,
            AnalysisOptions(expand_nested=False, delete_source_archive=False),
            lambda _value, _text: None,
            Event(),
        )
        session.result = _result(session.content_root, source)
        output = self.root / "prepared.7z"
        try:
            package = self.service.package_7z(
                session,
                output,
                include_report=True,
                progress=lambda _value, _text: None,
                cancelled=Event(),
            )
            self.assertTrue(package.verified)
            self.assertTrue(output.is_file())
            self.assertEqual(len(package.sha256), 64)
            with self.service._py7zr.SevenZipFile(output, "r") as archive:
                names = set(archive.getnames())
            self.assertIn("folder/data.txt", names)
            self.assertIn("PaxoInsight_Report.json", names)
            self.assertIn("PaxoInsight_Kotlin_Report.html", names)
            self.assertNotIn(session.content_root.name, names)
        finally:
            self.service.cleanup(session)


if __name__ == "__main__":
    unittest.main()
