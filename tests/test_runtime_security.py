from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from paxoinsight.archive_service import ArchiveService
from paxoinsight.models import AnalysisOptions, OperationCancelled
from paxoinsight.rar_metadata import RarMetadataFile, _Rar3MetadataParser, _Rar5MetadataParser
from paxoinsight.runtime import require_supported_runtime
from paxoinsight.security_self_test import check_zip_allocation


class RuntimePolicyTests(unittest.TestCase):
    def test_supported_runtime(self):
        require_supported_runtime()

    def test_old_patch_and_other_minor_are_rejected(self):
        for version in ((3, 14, 7), (3, 13, 12), (3, 15, 0)):
            with (
                self.subTest(version=version), patch("sys.version_info", version),
                self.assertRaises(RuntimeError),
            ):
                require_supported_runtime()

    def test_free_threaded_and_32_bit_builds_are_rejected(self):
        with patch("sysconfig.get_config_var", return_value=1), self.assertRaises(RuntimeError):
            require_supported_runtime()
        with patch("struct.calcsize", return_value=4), self.assertRaises(RuntimeError):
            require_supported_runtime()


class RarMetadataTests(unittest.TestCase):
    def test_comments_never_start_an_implicit_extraction_tool(self):
        rar3 = object.__new__(_Rar3MetadataParser)
        rar5 = object.__new__(_Rar5MetadataParser)
        with (
            patch("rarfile.rar3_decompress") as decompress,
            patch("rarfile.tool_setup") as setup,
        ):
            self.assertEqual(rar3._parse_subblocks(None, b"unused comment data", 0), 19)
            self.assertIsNone(rar3._read_comment_v3(None, "public-test-password"))
            self.assertIsNone(rar5._load_comment(None, None))
        decompress.assert_not_called()
        setup.assert_not_called()

    def test_metadata_adapter_requires_review_on_dependency_upgrade(self):
        archive = object.__new__(RarMetadataFile)
        with (
            patch("rarfile.__version__", "5.0"),
            self.assertRaisesRegex(RuntimeError, "Revalidate"),
        ):
            archive._parse()


class FolderCopyBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.destination = self.root / "output"
        self.destination.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def copy(self, options, cancelled=None):
        return ArchiveService._copy_directory(
            self.source, self.destination, self.root / "excluded", options,
            lambda *_: None, cancelled if cancelled is not None else Event(),
        )

    def test_directories_are_limited_before_creation(self):
        for index in range(5):
            (self.source / f"directory-{index}").mkdir()
        with self.assertRaisesRegex(ValueError, "лимит"):
            self.copy(AnalysisOptions(max_files=3))
        self.assertLessEqual(len(list(self.destination.rglob("*"))), 3)
        self.assertEqual(len(list(self.source.iterdir())), 5)

    def test_files_and_directories_share_one_budget(self):
        (self.source / "a").mkdir()
        (self.source / "b").mkdir()
        (self.source / "one.txt").write_bytes(b"one")
        (self.source / "two.txt").write_bytes(b"two")
        with self.assertRaisesRegex(ValueError, "лимит"):
            self.copy(AnalysisOptions(max_files=3))
        self.assertLessEqual(len(list(self.destination.rglob("*"))), 3)

    def test_disk_reserve_is_kept_before_writing(self):
        source = self.source / "payload.bin"
        source.write_bytes(b"payload")
        with (
            patch("shutil.disk_usage", return_value=type("Usage", (), {"free": 0})()),
            self.assertRaisesRegex(ValueError, "свободного места"),
        ):
            self.copy(AnalysisOptions())
        self.assertEqual(source.read_bytes(), b"payload")
        self.assertEqual(sum(p.stat().st_size for p in self.destination.rglob("*")
                             if p.is_file()), 0)

    def test_actual_byte_limit_applies_before_writing(self):
        (self.source / "payload.bin").write_bytes(b"payload")
        with self.assertRaisesRegex(ValueError, "лимит"):
            self.copy(AnalysisOptions(max_unpacked_bytes=3))
        self.assertEqual((self.destination / "payload.bin").stat().st_size, 0)

    def test_cancelled_copy_does_not_touch_source(self):
        (self.source / "payload.bin").write_bytes(b"payload")
        cancelled = Event()
        cancelled.set()
        with self.assertRaises(OperationCancelled):
            self.copy(AnalysisOptions(), cancelled)
        self.assertEqual((self.source / "payload.bin").read_bytes(), b"payload")
        self.assertFalse(list(self.destination.iterdir()))

    def test_bzip2_zip_cannot_allocate_an_unbounded_buffer(self):
        size = check_zip_allocation(ArchiveService(self.root / "work"), self.root)
        self.assertLessEqual(size, 1024**2)


if __name__ == "__main__":
    unittest.main()
