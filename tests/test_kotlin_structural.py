from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from kotlin_fixtures import class_bytes

from paxoinsight.jvm_class import ClassFormatError, modified_utf8, parse_class
from paxoinsight.kotlin_analysis import KotlinIndex
from paxoinsight.kotlin_source import parse_source
from paxoinsight.models import OperationCancelled


class ClassParserTests(unittest.TestCase):
    def test_structural_fields_and_metadata(self):
        info = parse_class(class_bytes("org/example/User", "Models.kt"))
        self.assertEqual(info.name, "org/example/User")
        self.assertEqual(info.package, "org/example")
        self.assertEqual(info.source_file, "Models.kt")
        self.assertTrue(info.kotlin)
        self.assertEqual(info.metadata_version, (2, 0, 0))

    def test_multifile_metadata_headers(self):
        info = parse_class(class_bytes("p/Helpers__AKt", "A.kt", kind=5, facade="p/Helpers"))
        self.assertEqual(info.metadata_kind, 5)
        self.assertEqual(info.facade, "p/Helpers")
        facade = parse_class(class_bytes("p/Helpers", kind=4, parts=("p/Helpers__AKt",)))
        self.assertEqual(facade.part_names, ("p/Helpers__AKt",))

    def test_truncation_is_rejected_at_every_byte(self):
        data = class_bytes("p/User", "User.kt")
        for end in range(len(data)):
            with self.subTest(end=end), self.assertRaises(ClassFormatError):
                parse_class(data[:end])

    def test_trailing_data_and_fake_magic_rejected(self):
        for data in (b"not a class", class_bytes("p/User") + b"trailing"):
            with self.assertRaises(ClassFormatError):
                parse_class(data)

    def test_new_metadata_is_reported_not_silently_supported(self):
        self.assertTrue(parse_class(class_bytes("p/User", version=(9, 0, 0))).metadata_warning)

    def test_modified_utf8(self):
        self.assertEqual(modified_utf8(b"A\xc0\x80B"), "A\0B")
        self.assertEqual(modified_utf8(b"\xed\xa0\xbd\xed\xb8\x80"), "\U0001f600")
        with self.assertRaises(ClassFormatError):
            modified_utf8(b"\xff")


class SourceParserTests(unittest.TestCase):
    def test_nested_string_templates_do_not_hide_following_declarations(self):
        source = parse_source(b'package p\nclass App { val s = "${call("class Fake { }", '
                              b'"${another("}")}")}" }\nclass Real', "Models.kt")
        self.assertEqual([name for _, name in source.declarations], ["p/App", "p/Real"])
        self.assertEqual(source.notes, [])

    def test_raw_multidollar_templates_and_template_comments(self):
        text = ('package p\nclass App { val s = $$"""$literal $${call("}") /* } */} """ }'
                '\nclass Real')
        source = parse_source(text.encode(), "Models.kt")
        self.assertEqual([name for _, name in source.declarations], ["p/App", "p/Real"])
        self.assertEqual(source.notes, [])

    def test_template_recursion_is_bounded(self):
        expression = '"x"'
        for _ in range(30):
            expression = '"${' + expression + '}"'
        with self.assertRaises(ValueError):
            parse_source(('val text = ' + expression).encode(), "Models.kt")

    def test_jvmname_and_multifile_import_aliases(self):
        source = parse_source(b'@file:FileName("Helpers")\n@file:ManyFiles\npackage p\n'
                              b'import kotlin.jvm.JvmName as FileName\n'
                              b'import kotlin.jvm.JvmMultifileClass as ManyFiles\n'
                              b'fun hello()=1', "Models.kt")
        self.assertEqual(source.facade, "Helpers")
        self.assertTrue(source.multifile)
        self.assertEqual(source.notes, [])

    def test_escaped_identifiers_do_not_become_directives(self):
        source = parse_source(b'package p\nclass App { fun f() { val `package` = 1 } }',
                              "Models.kt")
        self.assertEqual(source.package, "p")

    def test_constructor_lambda_keeps_the_enclosing_class_scope(self):
        source = parse_source(b'package p\nclass App(val f:()->Unit = {}) { class Nested }',
                              "App.kt")
        self.assertEqual([name for _, name in source.declarations], ["p/App", "p/App$Nested"])
        self.assertEqual(source.notes, [])

    def test_multiple_nested_and_companion_declarations(self):
        source = parse_source(b"package p\nclass User\nclass Account { class Nested; "
                              b"companion object { fun f() {} } }", "Models.kt")
        self.assertEqual([name for _, name in source.declarations],
                         ["p/User", "p/Account", "p/Account$Nested", "p/Account$Companion"])
        self.assertFalse(source.facade)

    def test_comments_strings_and_class_literals_are_not_declarations(self):
        source = parse_source(b'package p\n/* class Fake */\nclass Real { '
                              b'val text="class Hidden { }"; fun f() { val c=Real::class } }',
                              "Real.kt")
        self.assertEqual(source.declarations, [("class Real", "p/Real")])

    def test_fun_interface_does_not_require_file_facade(self):
        source = parse_source(b"fun interface Handler { fun run() }", "Handler.kt")
        self.assertFalse(source.facade)
        self.assertEqual(source.declarations, [("interface Handler", "Handler")])

    def test_jvmname_multifile_and_lowercase_filename(self):
        source = parse_source(b'@file:kotlin.jvm.JvmName("Helpers")\n'
                              b'@file:JvmMultifileClass\npackage p\nfun hello() = 1', "utils.kt")
        self.assertEqual(source.facade, "Helpers")
        self.assertTrue(source.multifile)
        ordinary = parse_source(b"fun hello() = 1", "utils.kt")
        self.assertEqual(ordinary.facade, "UtilsKt")

    def test_scripts_and_native_are_separate(self):
        for path in ("build.gradle.kts", "settings.gradle.kts", "run.kts",
                     "app/src/iosMain/kotlin/User.kt"):
            self.assertTrue(parse_source(b"", path).excluded)

    def test_unbalanced_input_is_not_treated_as_complete(self):
        with self.assertRaises(ValueError):
            parse_source(b"class App {", "App.kt")


class KotlinMappingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sources = []
        self.classes = []

    def tearDown(self):
        self.temporary.cleanup()

    def source(self, path="src/main/kotlin/p/App.kt", text="package p\nclass App"):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8")
        self.sources.append(path)
        return path

    def binary(self, path="build/classes/kotlin/main/p/App.class", name="p/App",
               source="App.kt", **kwargs):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(class_bytes(name, source, **kwargs))
        self.classes.append(path)
        return path

    def analyze(self, uninspected=None):
        index = KotlinIndex(self.root)
        index.index_classes(self.classes)
        return index.mapping(self.sources, uninspected)

    def test_standard_root_layout_and_real_class_paths(self):
        self.source()
        binary = self.binary()
        mapping = self.analyze()
        self.assertEqual(mapping["total_matched"], 1)
        self.assertEqual(mapping["records"][0]["status"], "confirmed")
        self.assertEqual(mapping["matched"][0]["classes"], [binary])

    def test_multiplatform_jvm_output_root(self):
        self.source("src/jvmMain/kotlin/p/App.kt")
        self.binary("build/classes/kotlin/jvm/main/p/App.class")
        self.assertEqual(self.analyze()["total_matched"], 1)

    def test_custom_jvm_target_output_root(self):
        self.source("src/desktopMain/kotlin/p/App.kt")
        self.binary("build/classes/kotlin/desktop/main/p/App.class")
        self.assertEqual(self.analyze()["total_matched"], 1)

    def test_target_platforms_are_not_mixed(self):
        self.source("src/androidMain/kotlin/p/App.kt")
        self.binary("build/classes/kotlin/jvm/main/p/App.class")
        self.assertEqual(self.analyze()["total_matched"], 0)

    def test_test_fixtures_and_instrumented_tests_cannot_cover_unit_tests(self):
        for source_set in ("testFixtures", "androidTest"):
            with self.subTest(source_set=source_set):
                self.sources = []
                self.classes = []
                self.source("src/test/kotlin/p/App.kt")
                self.binary(f"build/classes/kotlin/{source_set}/p/App.class")
                self.assertEqual(self.analyze()["records"][0]["status"], "missing")

    def test_one_unknown_layout_class_cannot_cover_two_modules(self):
        self.source("a/src/main/kotlin/p/App.kt")
        self.source("b/src/main/kotlin/p/App.kt")
        self.binary("bundled/p/App.class")
        result = self.analyze()
        self.assertEqual([row["status"] for row in result["records"]], ["ambiguous", "ambiguous"])
        self.assertEqual(result["coverage"]["estimated_percent"], 0.0)

    def test_parser_accuracy_changes_result_from_partial_to_confirmed(self):
        self.source(text='package p\nclass App(val f:()->Unit = {}) { '
                         'val message="${call("x")}"; class Nested }')
        self.binary()
        self.binary("build/classes/kotlin/main/p/App$Nested.class", "p/App$Nested")
        result = self.analyze()
        self.assertEqual(result["records"][0]["status"], "confirmed")
        self.assertEqual(result["coverage"]["confirmed_percent"], 100.0)

    def test_shared_multifile_facade_is_not_a_collision(self):
        template = '@file:JvmName("Helpers")\n@file:JvmMultifileClass\npackage p\nfun hello()=1'
        self.source(text=template)
        self.source("src/main/kotlin/p/Other.kt", template)
        self.binary("build/classes/kotlin/main/p/Helpers__AppKt.class", "p/Helpers__AppKt",
                    kind=5, facade="p/Helpers")
        self.binary("build/classes/kotlin/main/p/Helpers__OtherKt.class", "p/Helpers__OtherKt",
                    "Other.kt", kind=5, facade="p/Helpers")
        self.binary("build/classes/kotlin/main/p/Helpers.class", "p/Helpers", None,
                    kind=4, parts=("p/Helpers__AppKt", "p/Helpers__OtherKt"))
        self.assertEqual(self.analyze()["total_matched"], 2)

    def test_source_file_name_can_differ_from_declared_class(self):
        self.source("src/main/kotlin/p/Models.kt", "package p\nclass User")
        self.binary("build/classes/kotlin/main/p/User.class", "p/User", "Models.kt")
        self.assertEqual(self.analyze()["total_matched"], 1)

    def test_partial_missing_declarations(self):
        self.source(text="package p\nclass App\nclass User")
        self.binary()
        row = self.analyze()["records"][0]
        self.assertEqual(row["status"], "partial")
        self.assertEqual(row["declarations"][1]["expected"], "p/User.class")
        self.assertEqual(row["declarations"][1]["status"], "missing")

    def test_modules_do_not_share_one_class(self):
        self.source("a/src/main/kotlin/p/App.kt")
        self.source("b/src/main/kotlin/p/App.kt")
        self.binary("b/build/classes/kotlin/main/p/App.class")
        rows = self.analyze()["records"]
        self.assertEqual([row["status"] for row in rows], ["missing", "confirmed"])

    def test_test_bytecode_cannot_cover_main_source(self):
        self.source()
        self.binary("build/classes/kotlin/test/p/App.class")
        self.assertEqual(self.analyze()["records"][0]["status"], "missing")

    def test_nested_class_does_not_invent_missing_outer(self):
        self.source(text="package p\nclass App { class Nested }")
        binary = self.binary("build/classes/kotlin/main/p/App$Nested.class", "p/App$Nested")
        row = self.analyze()["records"][0]
        self.assertEqual(row["status"], "partial")
        self.assertEqual(row["classes"], [binary])
        self.assertEqual(row["declarations"][0]["classes"], [])

    def test_custom_facade(self):
        self.source(text='@file:JvmName("Helpers")\npackage p\nfun hello()=1')
        self.binary("build/classes/kotlin/main/p/Helpers.class", "p/Helpers", kind=2)
        self.assertEqual(self.analyze()["total_matched"], 1)

    def test_multifile_requires_part_and_facade(self):
        self.source(text='@file:JvmName("Helpers")\n@file:JvmMultifileClass\n'
                         'package p\nfun hello()=1')
        self.binary("build/classes/kotlin/main/p/Helpers__AppKt.class", "p/Helpers__AppKt",
                    kind=5, facade="p/Helpers")
        self.assertEqual(self.analyze()["records"][0]["status"], "partial")
        self.binary("build/classes/kotlin/main/p/Helpers.class", "p/Helpers", None,
                    kind=4, parts=("p/Helpers__AppKt",))
        self.assertEqual(self.analyze()["records"][0]["status"], "confirmed")

    def test_wrong_multifile_part_list_is_not_confirmed(self):
        self.source(text='@file:JvmName("Helpers")\n@file:JvmMultifileClass\n'
                         'package p\nfun hello()=1')
        self.binary("build/classes/kotlin/main/p/Helpers__AppKt.class", "p/Helpers__AppKt",
                    kind=5, facade="p/Helpers")
        self.binary("build/classes/kotlin/main/p/Helpers.class", "p/Helpers", None,
                    kind=4, parts=("p/Helpers__OtherKt",))
        self.assertNotEqual(self.analyze()["records"][0]["status"], "confirmed")

    def test_synthetic_class_is_not_an_orphan_or_replacement(self):
        self.source()
        self.binary()
        synthetic = self.binary("build/classes/kotlin/main/p/App$1.class", "p/App$1", kind=3)
        result = self.analyze()
        self.assertEqual(result["orphan_kt_classes"], [])
        self.assertEqual(result["records"][0]["auxiliary_classes"], [synthetic])

    def test_class_cannot_replace_top_level_function_facade(self):
        self.source(text="package p\nfun hello()=1")
        self.binary("build/classes/kotlin/main/p/AppKt.class", "p/AppKt", kind=1)
        result = self.analyze()
        self.assertEqual(result["records"][0]["status"], "unverified")
        self.assertEqual(result["coverage"]["estimated_percent"], 0.0)

    def test_missing_debug_information_is_only_probable(self):
        self.source()
        self.binary(source=None)
        self.assertEqual(self.analyze()["records"][0]["status"], "probable")

    def test_ordinary_java_lookalike_is_not_confirmed(self):
        self.source()
        self.binary(metadata=False)
        self.assertEqual(self.analyze()["records"][0]["status"], "probable")

    def test_same_filename_from_wrong_source_is_not_confirmed(self):
        self.source()
        self.binary(source="Other.kt")
        result = self.analyze()
        self.assertEqual(result["records"][0]["status"], "unverified")
        self.assertEqual(result["coverage"]["estimated_percent"], 0.0)

    def test_nonstandard_filename_facade_is_resolved_by_sourcefile(self):
        self.source("src/main/kotlin/p/my-utils.kt", "package p\nfun hello()=1")
        binary = self.binary("build/classes/kotlin/main/p/My_utilsKt.class", "p/My_utilsKt",
                             "my-utils.kt", kind=2)
        result = self.analyze()
        self.assertEqual(result["total_matched"], 1)
        self.assertEqual(result["records"][0]["classes"], [binary])

    def test_computed_jvmname_can_have_an_estimated_sourcefile_link(self):
        self.source(text='@file:JvmName(FACADE_NAME)\npackage p\nfun hello()=1')
        self.binary("build/classes/kotlin/main/p/Helpers.class", "p/Helpers", kind=2)
        result = self.analyze()
        self.assertEqual(result["coverage"]["estimated_percent"], 100.0)
        self.assertEqual(result["coverage"]["confirmed_percent"], 0.0)

    def test_literal_jvmname_mismatch_cannot_be_hidden_by_sourcefile_fallback(self):
        self.source(text='@file:JvmName("Expected")\npackage p\nfun hello()=1')
        self.binary("build/classes/kotlin/main/p/Other.class", "p/Other", kind=2)
        self.assertEqual(self.analyze()["coverage"]["estimated_percent"], 0.0)

    def test_duplicate_variants_are_ambiguous(self):
        self.source()
        self.binary("build/tmp/kotlin-classes/debug/p/App.class")
        self.binary("build/tmp/kotlin-classes/release/p/App.class")
        self.assertEqual(self.analyze()["records"][0]["status"], "ambiguous")

    def test_variant_specific_source_matches_only_that_variant(self):
        self.source("src/debug/kotlin/p/App.kt")
        self.binary("build/tmp/kotlin-classes/debug/p/App.class")
        self.assertEqual(self.analyze()["records"][0]["status"], "confirmed")

    def test_complex_constructor_is_not_misreported_as_complete(self):
        self.source(text="package p\nclass App(val f:()->Unit = {}) { class Nested }")
        self.binary()
        self.assertNotEqual(self.analyze()["records"][0]["status"], "confirmed")

    def test_closed_container_means_unverified_not_missing(self):
        self.source()
        result = self.analyze(["module.jar"])
        self.assertEqual(result["records"][0]["status"], "unverified")
        self.assertFalse(result["unmatched_kt"])

    def test_corrupt_candidate_is_not_a_match_or_definite_absence(self):
        self.source()
        path = self.binary()
        (self.root / path).write_bytes(b"not a class")
        result = self.analyze()
        self.assertEqual(result["invalid_class_count"], 1)
        self.assertEqual(result["records"][0]["status"], "unverified")

    def test_kotlin_class_without_Kt_suffix_is_an_orphan(self):
        binary = self.binary(name="p/User", path="build/classes/kotlin/main/p/User.class",
                             source="Models.kt")
        self.assertEqual(self.analyze()["orphan_kt_classes"], [binary])

    def test_unknown_metadata_does_not_claim_support(self):
        self.source()
        self.binary(version=(9, 0, 0))
        self.assertEqual(self.analyze()["records"][0]["status"], "unverified")

    def test_common_main_is_not_excluded_from_jvm(self):
        self.source("src/commonMain/kotlin/p/App.kt")
        self.binary()
        self.assertEqual(self.analyze()["total_matched"], 1)

    def test_test_classification_handles_custom_source_sets(self):
        self.source("src/commonTest/kotlin/p/App.kt")
        mapping = self.analyze()
        self.assertEqual(mapping["unmatched_main"], [])
        self.assertEqual(mapping["unmatched_test"], self.sources)

    def test_malformed_source_is_unverified(self):
        self.source(text="package p\nclass App {")
        self.binary()
        self.assertEqual(self.analyze()["records"][0]["status"], "unverified")

    def test_budget_and_cancellation(self):
        self.source()
        self.binary()
        with patch("paxoinsight.kotlin_analysis.MAX_ANALYSIS_BYTES", 1):
            self.assertEqual(self.analyze()["records"][0]["status"], "unverified")
        cancelled = Event()
        cancelled.set()
        with self.assertRaises(OperationCancelled):
            KotlinIndex(self.root, cancelled).index_classes(self.classes)

    def test_paths_cannot_escape_the_workspace(self):
        self.sources = ["../outside.kt"]
        self.assertEqual(self.analyze()["records"][0]["status"], "unverified")
