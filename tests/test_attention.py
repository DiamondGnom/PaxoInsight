from __future__ import annotations

import unittest

from paxoinsight.attention import classify_attention, classify_highlight


class AttentionClassificationTests(unittest.TestCase):
    def test_installable_packages_are_high_attention(self) -> None:
        for path in (
            "server.rpm",
            "client.deb",
            "setup.msi",
            "bundle.msix",
            "mobile.apk",
            "ios.ipa",
            "browser.crx",
            "update.cab",
        ):
            with self.subTest(path=path):
                style = classify_attention(path)
                self.assertIsNotNone(style)
                self.assertEqual(style.key, "package")
                self.assertEqual(style.level, "high")

    def test_native_and_jar_like_files_are_distinguished(self) -> None:
        self.assertEqual(classify_attention("bin/tool.exe").key, "executable")
        self.assertEqual(classify_attention("lib/native.so").key, "executable")
        for path in ("lib.jar", "web.war", "app.ear", "flow.bar", "service.sar"):
            with self.subTest(path=path):
                self.assertEqual(
                    classify_attention(path).key, "application_container"
                )

    def test_kotlin_is_highlighted_but_not_classified_as_a_risk(self) -> None:
        for path in ("src/App.kt", "build.gradle.kts", ".kt", ".kts"):
            with self.subTest(path=path):
                self.assertIsNone(classify_attention(path))
                self.assertEqual(classify_highlight(path).key, "kotlin")


if __name__ == "__main__":
    unittest.main()
