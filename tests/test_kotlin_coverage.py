from __future__ import annotations

import unittest

from paxoinsight.kotlin_coverage import coverage_for_mapping, coverage_text, percent


def row(*statuses, test=False, complete=True, excluded=False):
    return {"status": "not_applicable" if excluded else "partial",
            "context": {"test": test}, "recognition_complete": complete,
            "declarations": [{"status": status} for status in statuses]}


class CoverageTests(unittest.TestCase):
    def calculate(self, *records, **extra):
        return coverage_for_mapping({"records": list(records), **extra})

    def test_partial_files_are_fractional_not_all_or_nothing(self):
        result = self.calculate(row("confirmed"),
                                row("confirmed", "confirmed", "missing", "missing"))
        self.assertEqual(result["estimated_percent"], 75.0)
        self.assertEqual(result["confirmed_percent"], 75.0)
        self.assertEqual(result["expected_units"], 5)

    def test_probable_links_count_only_in_estimate(self):
        result = self.calculate(row("confirmed", "probable"))
        self.assertEqual(result["estimated_percent"], 100.0)
        self.assertEqual(result["confirmed_percent"], 50.0)

    def test_ambiguous_and_unverified_links_are_not_credited(self):
        result = self.calculate(row("confirmed", "ambiguous", "unverified", "missing"))
        self.assertEqual(result["estimated_percent"], 25.0)
        self.assertEqual(result["confirmed_percent"], 25.0)
        self.assertTrue(result["incomplete"])

    def test_unreadable_file_remains_in_file_denominator(self):
        result = self.calculate(row("confirmed"), row(complete=False))
        self.assertEqual(result["estimated_percent"], 50.0)
        self.assertEqual(result["unresolved_files"], 1)

    def test_incomplete_lexer_cannot_give_confirmed_100_percent(self):
        result = self.calculate(row("confirmed", complete=False))
        self.assertEqual(result["estimated_percent"], 100.0)
        self.assertEqual(result["confirmed_percent"], 0.0)

    def test_scripts_and_other_platforms_are_excluded(self):
        result = self.calculate(row("confirmed"), row(excluded=True))
        self.assertEqual(result["estimated_percent"], 100.0)
        self.assertEqual(result["applicable_files"], 1)
        self.assertEqual(result["excluded_files"], 1)

    def test_main_and_test_are_separate(self):
        result = self.calculate(row("confirmed"), row("missing", test=True))
        self.assertEqual(result["estimated_percent"], 50.0)
        self.assertEqual(result["main"]["estimated_percent"], 100.0)
        self.assertEqual(result["test"]["estimated_percent"], 0.0)

    def test_empty_or_no_parse_data_is_not_100_or_zero(self):
        for records in ([], [row(excluded=True)], [row(complete=False)]):
            result = self.calculate(*records)
            self.assertIsNone(result["estimated_percent"])
            self.assertEqual(percent(result["estimated_percent"]), "н/д")

    def test_known_missing_declaration_is_zero(self):
        self.assertEqual(self.calculate(row("missing"))["estimated_percent"], 0.0)

    def test_container_and_invalid_bytecode_limitations_remain_visible(self):
        result = self.calculate(row("confirmed"), uninspected_containers=["lib.jar"])
        self.assertTrue(result["incomplete"])
        self.assertIn("Оценка неполная", coverage_text(result))

    def test_legacy_heuristic_is_never_confirmed(self):
        result = coverage_for_mapping({"matched": [{"kt": "A.kt"}], "unmatched_kt": ["B.kt"]})
        self.assertTrue(result["legacy_heuristic"])
        self.assertEqual(result["estimated_percent"], 50.0)
        self.assertEqual(result["confirmed_percent"], 0.0)
