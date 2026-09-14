from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from paxoinsight.models import AnalysisResult
from paxoinsight.reporting import (
    build_kotlin_html_report,
    extract_kotlin_mapping,
    save_kotlin_html_report,
)


def _result() -> AnalysisResult:
    return AnalysisResult(
        source_path="C:/input/source.zip",
        source_name="source.zip",
        source_size=100,
        source_sha256="0" * 64,
        workspace="C:/temporary/workspace",
        started_at="2026-09-10T10:00:00+03:00",
        finished_at="2026-09-10T10:00:01+03:00",
        duration_seconds=1.0,
        total_files=7,
        total_bytes=700,
        extension_counts={".kt": 4, ".class": 3},
        class_files=[
            "build/classes/kotlin/main/org/example/App.class",
            "build/classes/kotlin/main/org/example/LooseKt.class",
        ],
        kotlin_files=[
            "src/main/kotlin/org/example/App.kt",
            "src/main/kotlin/org/example/<Danger>.kt",
            "src/test/kotlin/org/example/AppTest.kt",
            "build.gradle.kts",
        ],
        special_files=[],
        third_party_archives=[],
        remaining_archives=[],
        expanded_archives=[],
        integrity_score=100,
        integrity_verdict="OK",
        sast_mode="Исходный код",
        sast_reason="Kotlin",
        analysis_data={
            "kotlin_mapping": {
                "matched": [
                    {
                        "kt": "src/main/kotlin/org/example/App.kt",
                        "classes": ["App.class"],
                    }
                ],
                "unmatched_kt": [
                    "src/main/kotlin/org/example/<Danger>.kt",
                    "src/test/kotlin/org/example/AppTest.kt",
                ],
                "unmatched_main": ["src/main/kotlin/org/example/<Danger>.kt"],
                "unmatched_test": ["src/test/kotlin/org/example/AppTest.kt"],
                "orphan_kt_classes": [
                    "build/classes/kotlin/main/org/example/LooseKt.class"
                ],
            }
        },
    )


class KotlinReportingTests(unittest.TestCase):
    def test_empty_inventory_is_available_and_requires_no_mapping(self) -> None:
        result = _result()
        result.kotlin_files = []
        result.class_files = []
        result.analysis_data = {}

        mapping = extract_kotlin_mapping(result)

        self.assertTrue(mapping.available)
        self.assertEqual(mapping.issue_count, 0)

    def test_mapping_exposes_missing_matched_orphan_and_ignored_files(self) -> None:
        mapping = extract_kotlin_mapping(_result())

        self.assertTrue(mapping.available)
        self.assertEqual(mapping.missing_count, 2)
        self.assertEqual(mapping.issue_count, 3)
        self.assertEqual(mapping.matched[0].class_files, ("App.class",))
        self.assertEqual(mapping.ignored_scripts, ("build.gradle.kts",))

    def test_html_report_is_standalone_and_escapes_paths(self) -> None:
        report = build_kotlin_html_report(_result())

        self.assertIn("Отчёт сопоставления Kotlin и .class", report)
        self.assertIn("App.class", report)
        self.assertIn("LooseKt.class", report)
        self.assertIn("&lt;Danger&gt;.kt", report)
        self.assertNotIn("<Danger>.kt", report)
        self.assertNotIn("http://", report)
        self.assertNotIn("https://", report)

    def test_report_is_saved_atomically_with_html_extension(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = save_kotlin_html_report(_result(), Path(temp) / "kotlin-report")

            self.assertEqual(destination.suffix, ".html")
            self.assertTrue(destination.is_file())
            self.assertIn("charset=\"utf-8\"", destination.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
