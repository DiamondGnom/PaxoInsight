from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from paxoinsight.models import AnalysisResult
from paxoinsight.reporting import (
    build_kotlin_html_report,
    build_kotlin_text_report,
    extract_kotlin_mapping,
    kotlin_table_rows,
    save_kotlin_html_report,
    save_kotlin_text_report,
    save_text_report,
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
                "orphan_kt_classes": ["build/classes/kotlin/main/org/example/LooseKt.class"],
            }
        },
    )


class KotlinReportingTests(unittest.TestCase):
    def test_structural_status_and_evidence_are_preserved_and_escaped(self):
        result = _result()
        result.analysis_data["kotlin_mapping"] = {
            "schema_version": 2,
            "records": [
                {
                    "source": "src/main/kotlin/<Danger>.kt",
                    "status": "partial",
                    "classes": ["build/classes/p/User.class"],
                    "reason": "<Missing>",
                    "context": {"module": "app", "source_set": "main", "test": False},
                    "declarations": [
                        {
                            "declaration": "class User",
                            "status": "confirmed",
                            "expected": "p/User.class",
                            "classes": ["build/classes/p/User.class"],
                            "reason": "Подтверждено",
                        },
                        {
                            "declaration": "class Account",
                            "status": "missing",
                            "expected": "p/Account.class",
                            "classes": [],
                            "reason": "Не обнаружен",
                        },
                    ],
                }
            ],
        }
        mapping = extract_kotlin_mapping(result)
        self.assertEqual(mapping.issue_count, 1)
        self.assertEqual(len(kotlin_table_rows(mapping)), 3)
        self.assertEqual(mapping.coverage["estimated_percent"], 50.0)
        report = build_kotlin_html_report(result)
        self.assertIn("ЧАСТИЧНО", report)
        self.assertIn("p/Account.class", report)
        self.assertIn("build/classes/p/User.class", report)
        self.assertNotIn("<Danger>", report)
        self.assertNotIn("<Missing>", report)
        self.assertIn("&lt;Missing&gt;", report)
        self.assertIn("≈50.0%", report)
        self.assertIn("ЧАСТИЧНО", result.to_text())
        self.assertIn("p/Account.class", result.to_text())
        self.assertIn("≈50.0%", result.to_text())

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
            self.assertIn('charset="utf-8"', destination.read_text(encoding="utf-8"))

    def test_kotlin_text_contains_legacy_missing_and_orphan_paths(self):
        text = build_kotlin_text_report(_result())
        for value in (
            "App.class",
            "LooseKt.class",
            "<Danger>.kt",
            "AppTest.kt",
            "build.gradle.kts",
            "покрытие SAST",
            "≈33.3%",
        ):
            self.assertIn(value, text)
        self.assertNotIn("<html", text)

    def test_both_text_exports_use_utf8_bom_and_clean_temporary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            for exporter, name in ((save_kotlin_text_report, "kotlin"), (save_text_report, "full")):
                path = exporter(_result(), folder / name)
                self.assertEqual(path.suffix, ".txt")
                self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))
                self.assertIn("PaxoInsight", path.read_text(encoding="utf-8-sig"))
            self.assertEqual(
                sorted(item.name for item in folder.iterdir()), ["full.txt", "kotlin.txt"]
            )
            self.assertEqual(
                (folder / "full.txt").read_text(encoding="utf-8-sig"), _result().to_text()
            )

    def test_failed_text_save_does_not_truncate_existing_report(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "report.txt"
            destination.write_text("old report", encoding="utf-8")
            with (
                patch("paxoinsight.reporting.os.replace", side_effect=PermissionError("test")),
                self.assertRaises(PermissionError),
            ):
                save_kotlin_text_report(_result(), destination)
            self.assertEqual(destination.read_text(), "old report")
            self.assertEqual([item.name for item in destination.parent.iterdir()], ["report.txt"])


if __name__ == "__main__":
    unittest.main()
