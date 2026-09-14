from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from paxoinsight.models import AnalysisOptions
from paxoinsight.workflow import WorkflowService


class AnalysisWorkflowTests(unittest.TestCase):
    def test_source_archive_survives_analysis_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "must-survive.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("data.txt", "important")
            workflow = WorkflowService()

            with patch.object(
                workflow.analysis,
                "analyze",
                side_effect=RuntimeError("simulated analysis failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated"):
                    workflow.scan(
                        source,
                        AnalysisOptions(),
                        lambda _value, _text: None,
                        Event(),
                    )

            self.assertTrue(source.is_file())
            with zipfile.ZipFile(source, "r") as archive:
                self.assertEqual(archive.read("data.txt"), b"important")

    def test_attention_inventory_contains_packages_executables_and_containers(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "input"
            source.mkdir()
            for filename in (
                "server.rpm",
                "setup.msi",
                "tool.exe",
                "module.ear",
                "Main.kt",
            ):
                (source / filename).write_bytes(b"test")

            workflow = WorkflowService()
            session = workflow.scan(
                source,
                AnalysisOptions(expand_nested=False),
                lambda _value, _text: None,
                Event(),
            )
            try:
                self.assertEqual(
                    set(session.result.attention_files),
                    {"server.rpm", "setup.msi", "tool.exe", "module.ear"},
                )
                self.assertEqual(session.result.kotlin_files, ["Main.kt"])
                kotlin_mapping = session.result.analysis_data["kotlin_mapping"]
                self.assertEqual(kotlin_mapping["unmatched_main"], ["Main.kt"])
                self.assertEqual(kotlin_mapping["total_matched"], 0)
                report = session.result.to_text()
                self.assertIn("Файлы повышенного внимания:", report)
                self.assertIn("server.rpm", report)
                self.assertIn("Kotlin-файлы:", report)
                self.assertIn("Main.kt", report)
            finally:
                workflow.cleanup(session)

    def test_folder_is_analyzed_packaged_and_left_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source-folder"
            (source / "src" / "main").mkdir(parents=True)
            (source / "src" / "main" / "App.java").write_text(
                "public class App {}", encoding="utf-8"
            )
            (source / "empty").mkdir()
            original = (source / "src" / "main" / "App.java").read_bytes()

            workflow = WorkflowService()
            session = workflow.scan(
                source,
                AnalysisOptions(expand_nested=False),
                lambda _value, _text: None,
                Event(),
            )
            output = root / "source-folder_prepared.7z"
            try:
                self.assertTrue(session.source_is_directory)
                self.assertFalse(session.source_deleted)
                self.assertTrue(source.is_dir())
                self.assertEqual(
                    (source / "src" / "main" / "App.java").read_bytes(), original
                )
                self.assertEqual(
                    (session.content_root / "src" / "main" / "App.java").read_bytes(),
                    original,
                )
                self.assertTrue((session.content_root / "empty").is_dir())
                self.assertEqual(session.source_size, len(original))
                self.assertEqual(len(session.source_sha256), 64)

                package = workflow.package(
                    session,
                    output,
                    False,
                    lambda _value, _text: None,
                    Event(),
                )
                self.assertTrue(package.verified)
                with workflow.archives._py7zr.SevenZipFile(output, "r") as archive:
                    names = set(archive.getnames())
                self.assertIn("src/main/App.java", names)
                self.assertIn("empty", names)
                self.assertNotIn("source-folder", names)
                self.assertTrue(source.is_dir())
            finally:
                workflow.cleanup(session)

    def test_folder_copy_can_expand_jar_without_changing_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input"
            source.mkdir()
            jar = source / "library.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("inside.txt", "folder input")
            original_jar = jar.read_bytes()

            workflow = WorkflowService()
            session = workflow.scan(
                source,
                AnalysisOptions(
                    expand_nested=True,
                    replace_nested_archives=True,
                    unpack_application_containers=True,
                ),
                lambda _value, _text: None,
                Event(),
            )
            try:
                self.assertEqual(jar.read_bytes(), original_jar)
                self.assertFalse((session.content_root / "library.jar").exists())
                self.assertEqual(
                    (session.content_root / "library" / "inside.txt").read_text(),
                    "folder input",
                )
                self.assertIn("library.jar", session.expanded_archives)
            finally:
                workflow.cleanup(session)

    def test_end_to_end_result_is_kept_only_in_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "sample.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr(
                    "src/main/java/example/App.java",
                    "package example; public class App { public static void main(String[] a) {} }",
                )
                archive.writestr("pom.xml", "<project></project>")
            workflow = WorkflowService()
            session = workflow.scan(
                source,
                AnalysisOptions(expand_nested=False),
                lambda _value, _text: None,
                Event(),
            )
            try:
                self.assertIsNotNone(session.result)
                self.assertEqual(session.result.source_name, "sample.zip")
                self.assertGreaterEqual(session.result.total_files, 2)
                self.assertFalse(source.exists())
                self.assertTrue(session.source_deleted)
                self.assertEqual(len(session.result.source_sha256), 64)
                self.assertFalse(any(root.glob("*.db")))
            finally:
                workflow.cleanup(session)

    def test_rescan_can_expand_containers_after_source_was_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            nested = root / "library.jar"
            with zipfile.ZipFile(nested, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                archive.writestr("inside.txt", "expanded on rescan")
            source = root / "sample.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.write(nested, "library.jar")

            workflow = WorkflowService()
            session = workflow.scan(
                source,
                AnalysisOptions(
                    expand_nested=True,
                    unpack_application_containers=False,
                ),
                lambda _value, _text: None,
                Event(),
            )
            try:
                self.assertFalse(source.exists())
                self.assertTrue((session.content_root / "library.jar").is_file())
                first_result = session.result
                previous_output = root / "previous.7z"
                previous_output.write_bytes(b"previous build")
                session.output_archive = previous_output

                rescanned = workflow.rescan(
                    session,
                    AnalysisOptions(
                        expand_nested=True,
                        unpack_application_containers=True,
                    ),
                    lambda _value, _text: None,
                    Event(),
                )

                self.assertIs(rescanned, session)
                self.assertIsNot(session.result, first_result)
                self.assertFalse((session.content_root / "library.jar").exists())
                self.assertEqual(
                    (session.content_root / "library" / "inside.txt").read_text(),
                    "expanded on rescan",
                )
                self.assertIsNone(session.output_archive)
                self.assertTrue(previous_output.is_file())
            finally:
                workflow.cleanup(session)


if __name__ == "__main__":
    unittest.main()
