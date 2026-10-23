from __future__ import annotations

import json
import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from threading import Event
from tkinter import ttk
from unittest.mock import patch

from paxoinsight.models import AnalysisOptions
from paxoinsight.self_test import KOTLIN_CLASS_FIXTURE
from paxoinsight.ui.appearance import DARK, LIGHT, PALETTES, Color, load_theme, save_theme
from paxoinsight.ui.brand_logo import AdaptiveLogo
from paxoinsight.ui.password_dialog import PasswordDialog
from paxoinsight.ui.tk_main_window import PaxoInsightWindow


class AppearancePreferenceTests(unittest.TestCase):
    def test_only_theme_is_saved_and_reloaded(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "preferences" / "appearance.json"
            self.assertEqual(load_theme(path), "light")
            for theme in ("dark", "light"):
                save_theme(theme, path)
                self.assertEqual(load_theme(path), theme)
                self.assertEqual(json.loads(path.read_text()), {"theme": theme})
            self.assertEqual([item.name for item in path.parent.iterdir()], [path.name])

    def test_invalid_or_oversized_preference_falls_back_without_rewriting(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "appearance.json"
            for data in (
                b"bad",
                b"\xff",
                b"[]",
                b'{"theme": []}',
                b'{"theme":"invalid"}',
                b'{"theme":"dark"}' + b" " * 4096,
                b"[" * 2000 + b"]" * 2000,
            ):
                path.write_bytes(data)
                self.assertEqual(load_theme(path), "light")
                self.assertEqual(path.read_bytes(), data)

    def test_failed_atomic_replace_preserves_old_preference(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "appearance.json"
            save_theme("light", path)
            with (
                patch("paxoinsight.ui.appearance.os.replace", side_effect=PermissionError("test")),
                self.assertRaises(PermissionError),
            ):
                save_theme("dark", path)
            self.assertEqual(load_theme(path), "light")
            self.assertEqual([item.name for item in path.parent.iterdir()], [path.name])
            with self.assertRaises(ValueError):
                save_theme("unknown", path)

    def test_palette_text_contrast(self):
        def luminance(hex_color):
            channels = [int(hex_color[pos : pos + 2], 16) / 255 for pos in (1, 3, 5)]
            values = [
                value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
                for value in channels
            ]
            return sum(
                value * weight
                for value, weight in zip(values, (0.2126, 0.7152, 0.0722), strict=True)
            )

        pairs = [
            (Color.TEXT, Color.CARD),
            (Color.HEADING, Color.CARD),
            (Color.MUTED, Color.CARD),
            (Color.TEXT, Color.FIELD),
            (Color.ON_ACCENT, Color.ACCENT),
            (Color.SELECT_TEXT, Color.SELECT),
            (Color.DANGER_TEXT, Color.DANGER_BG),
            (Color.WARNING_TEXT, Color.WARNING_BG),
            (Color.SUCCESS_TEXT, Color.SUCCESS_BG),
            (Color.INFO_TEXT, Color.INFO_BG),
            (Color.KOTLIN_TEXT, Color.KOTLIN_BG),
        ]
        for name, palette in PALETTES.items():
            self.assertEqual(set(palette), set(Color))
            for foreground, background in pairs:
                with self.subTest(theme=name, foreground=foreground, background=background):
                    values = sorted(
                        [luminance(palette[foreground]), luminance(palette[background])]
                    )
                    self.assertGreaterEqual((values[1] + 0.05) / (values[0] + 0.05), 4.5)


class DesktopAppearanceTests(unittest.TestCase):
    def setUp(self):
        try:
            self.root = tk.Tk()
        except tk.TclError as error:
            self.skipTest(str(error))
        self.root.withdraw()
        self.addCleanup(self._destroy_root)
        self.temporary = tempfile.TemporaryDirectory(prefix="PaxoInsight-DesktopTest-")
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        with patch("paxoinsight.ui.tk_main_window.load_theme", return_value="light"):
            self.window = PaxoInsightWindow(self.root)
        self.addCleanup(lambda: self.window.workflow.cleanup(self.window.session))

    def _destroy_root(self):
        for timer in self.root.tk.splitlist(self.root.tk.call("after", "info")):
            self.root.after_cancel(timer)
        self.root.destroy()

    def _analyze(self):
        source = self.folder / "project"
        kt = source / "src/main/kotlin/demo/Models.kt"
        cls = source / "build/classes/kotlin/main/demo/Demo.class"
        kt.parent.mkdir(parents=True)
        cls.parent.mkdir(parents=True)
        kt.write_text("package demo\nclass Demo\nclass Missing", encoding="utf-8")
        cls.write_bytes(KOTLIN_CLASS_FIXTURE)
        self.window.source = source
        session = self.window.workflow.scan(source, AnalysisOptions(), lambda *_: None, Event())
        self.window._scan_completed(session, repeated=False)
        self.window._refresh_controls()

    def test_report_menu_states_and_both_txt_commands(self):
        for index in (0, 2, 3, 4):
            self.assertEqual(self.window.report_menu.entrycget(index, "state"), "disabled")
        self._analyze()
        for index, stem in ((2, "html"), (3, "kotlin"), (4, "full")):
            self.assertEqual(self.window.report_menu.entrycget(index, "state"), "normal")
            with (
                patch(
                    "paxoinsight.ui.tk_main_window.filedialog.asksaveasfilename",
                    return_value=str(self.folder / stem),
                ) as dialog,
                patch("paxoinsight.ui.tk_main_window.messagebox.showinfo"),
            ):
                self.window.report_menu.invoke(index)
            suffix = ".html" if index == 2 else ".txt"
            self.assertEqual(dialog.call_args.kwargs["defaultextension"], suffix)
            text = (self.folder / (stem + suffix)).read_text(encoding="utf-8-sig")
            self.assertIn("≈50.0%", text)
            self.assertIn("demo/Missing.class", text)
            if index == 4:
                self.assertIn("Оценка целостности", text)
        self.window.busy_kind = "rescan"
        self.window._refresh_controls()
        for index in (0, 2, 3, 4):
            self.assertEqual(self.window.report_menu.entrycget(index, "state"), "disabled")
        with patch("paxoinsight.ui.tk_main_window.filedialog.asksaveasfilename") as dialog:
            self.window._save_kotlin_report("txt")
            dialog.assert_not_called()

    def test_cancel_and_save_error_are_handled(self):
        self._analyze()
        with (
            patch("paxoinsight.ui.tk_main_window.filedialog.asksaveasfilename", return_value=""),
            patch("paxoinsight.ui.tk_main_window.save_kotlin_text_report") as exporter,
        ):
            self.window._save_kotlin_report("txt")
            exporter.assert_not_called()
        with (
            patch(
                "paxoinsight.ui.tk_main_window.filedialog.asksaveasfilename",
                return_value=str(self.folder / "result.txt"),
            ),
            patch(
                "paxoinsight.ui.tk_main_window.save_kotlin_text_report",
                side_effect=PermissionError("read-only test destination"),
            ),
            patch("paxoinsight.ui.tk_main_window.messagebox.showerror") as error,
        ):
            self.window._save_kotlin_report("txt")
            error.assert_called_once()

    def test_switching_theme_preserves_job_results_selection_and_progress(self):
        self._analyze()
        window = self.window
        session = window.session
        rows = window.kotlin_tree.get_children()
        window.kotlin_tree.selection_set(rows[1])
        window.notebook.select(window.kotlin_tree.master)
        window.progress["value"] = 63
        window._log("preserve this log")
        text = window.summary_text.get("1.0", "end")
        path = self.folder / "appearance.json"
        with patch(
            "paxoinsight.ui.tk_main_window.save_theme",
            side_effect=lambda name: save_theme(name, path),
        ):
            for index, name in ((1, "dark"), (0, "light"), (1, "dark")):
                window.theme_menu.invoke(index)
                self.root.update_idletasks()
                self.assertEqual(window.theme.name, name)
                self.assertEqual(load_theme(path), name)
                self.assertIs(window.session, session)
                self.assertEqual(window.kotlin_tree.get_children(), rows)
                self.assertEqual(window.kotlin_tree.selection(), (rows[1],))
                self.assertEqual(window.notebook.select(), str(window.kotlin_tree.master))
                self.assertEqual(window.summary_text.get("1.0", "end"), text)
                self.assertIn("preserve this log", window.log_text.get("1.0", "end"))
                self.assertEqual(float(window.progress["value"]), 63)
                self.assertIn("≈50.0%", window.kotlin_coverage_var.get())

    def test_dark_styles_status_tags_and_dynamic_updates(self):
        window = self.window
        window.theme.apply("dark")
        self._analyze()
        window._set_status("Test error", "error")
        self.assertEqual(window.status_badge.cget("bg"), DARK[Color.DANGER_BG])
        self.assertEqual(window.status_badge.cget("fg"), DARK[Color.DANGER_TEXT])
        self.assertEqual(
            str(window.kotlin_tree.tag_configure("missing_main", "foreground")),
            DARK[Color.DANGER_TEXT],
        )
        self.assertEqual(window.summary_text.cget("fg"), DARK[Color.TEXT])
        self.assertEqual(window.depth_spin.cget("disabledbackground"), DARK[Color.DISABLED])
        style = ttk.Style(self.root)
        self.assertEqual(style.lookup("Treeview", "fieldbackground"), DARK[Color.CARD])
        self.assertEqual(style.lookup("Treeview", "background", ("selected",)), DARK[Color.SELECT])
        self.assertEqual(
            style.lookup("TButton", "background", ("disabled", "active")), DARK[Color.DISABLED]
        )
        window.theme.apply("light")
        self.assertEqual(window.status_badge.cget("bg"), LIGHT[Color.DANGER_BG])
        self.assertEqual(window.status_badge.cget("text"), "ОШИБКА")
        self.assertEqual(
            str(window.kotlin_tree.tag_configure("missing_main", "foreground")),
            LIGHT[Color.DANGER_TEXT],
        )

    def test_theme_preference_write_failure_does_not_undo_switch(self):
        self.window.theme_var.set("dark")
        with (
            patch("paxoinsight.ui.tk_main_window.save_theme", side_effect=PermissionError("test")),
            patch("paxoinsight.ui.tk_main_window.messagebox.showwarning") as warning,
        ):
            self.window._change_theme()
        self.assertEqual(self.window.theme.name, "dark")
        self.assertIn("не удалось сохранить", self.window.log_text.get("1.0", "end"))
        warning.assert_called_once()

    def test_theme_switch_remains_available_while_busy(self):
        self.window.busy_kind = "rescan"
        self.window._refresh_controls()
        self.window.theme_var.set("dark")
        with patch("paxoinsight.ui.tk_main_window.save_theme"):
            self.window._change_theme()
        self.assertEqual(self.window.theme.name, "dark")
        self.assertEqual(self.window.busy_kind, "rescan")
        self.assertEqual(str(self.window.report_menu.entrycget(3, "state")), "disabled")

    def test_saved_dark_theme_is_used_when_window_is_created(self):
        path = self.folder / "appearance.json"
        save_theme("dark", path)
        with patch(
            "paxoinsight.ui.tk_main_window.load_theme", side_effect=lambda: load_theme(path)
        ):
            second_root = tk.Tk()
            second_root.withdraw()
            try:
                window = PaxoInsightWindow(second_root)
                self.assertEqual(window.theme_var.get(), "dark")
                self.assertEqual(second_root.cget("bg"), DARK[Color.SURFACE])
                self.assertEqual(window.summary_text.cget("fg"), DARK[Color.TEXT])
            finally:
                for timer in second_root.tk.splitlist(second_root.tk.call("after", "info")):
                    second_root.after_cancel(timer)
                second_root.destroy()

    def test_about_dialog_follows_theme_without_reopening(self):
        self.window.theme.apply("dark")
        self.window._show_about()
        dialog = next(item for item in self.root.winfo_children() if isinstance(item, tk.Toplevel))
        try:
            dialog.withdraw()
            self.assertEqual(dialog.cget("bg"), DARK[Color.CARD])
            self.window.theme.apply("light")
            self.assertEqual(dialog.cget("bg"), LIGHT[Color.CARD])
        finally:
            dialog.destroy()

    def test_logo_background_and_wordmark_follow_theme_in_header_and_about(self):
        self.window._show_about()
        dialog = next(item for item in self.root.winfo_children() if isinstance(item, tk.Toplevel))
        dialog.withdraw()

        def logos(parent):
            for child in parent.winfo_children():
                if isinstance(child, AdaptiveLogo):
                    yield child
                yield from logos(child)

        try:
            all_logos = list(logos(self.root))
            self.assertEqual(len(all_logos), 2)
            for name in ("light", "dark", "light", "dark"):
                self.window.theme.apply(name)
                self.root.update_idletasks()
                palette = PALETTES[name]
                for logo in all_logos:
                    self.assertEqual(logo.cget("bg"), palette[Color.CARD])
                    self.assertEqual(logo.emblem.cget("bg"), palette[Color.CARD])
                    self.assertEqual(logo.paxo.cget("bg"), palette[Color.CARD])
                    self.assertEqual(logo.insight.cget("bg"), palette[Color.CARD])
                    self.assertEqual(logo.paxo.cget("fg"), palette[Color.HEADING])
                    self.assertEqual(logo.insight.cget("fg"), "#0098FF")
                    self.assertEqual(logo.cget("width"), logo.image.width())
                    self.assertEqual(logo.cget("height"), logo.image.height())
                    available = logo.image.width() - int(logo.emblem.cget("width"))
                    self.assertLessEqual(
                        sum(logo.word_font.measure(part) for part in ("Paxo", "Insight")), available
                    )
                    self.assertLessEqual(logo.word_font.metrics("linespace"), logo.image.height())
                    self.assertTrue(logo.image.transparency_get(0, 0))
                    if name == "dark":
                        self.assertNotEqual(logo.cget("bg"), "#FFFFFF")
            self.assertEqual(self.window.header_logo.image.width(), 192)
            self.assertEqual(self.window.logo_image.width(), 384)
        finally:
            dialog.destroy()

    def test_adaptive_logo_does_not_modify_shared_original_image(self):
        image = self.window.logo_image
        original = image.data(format="png")
        for name in ("dark", "light"):
            self.window.theme.apply(name)
            self.root.update_idletasks()
            self.assertEqual(image.data(format="png"), original)

    def test_password_dialog_inherits_theme_and_preserves_masked_paste(self):
        self.window.theme.apply("dark")
        with (
            patch("tkinter.simpledialog._place_window"),
            patch.object(PasswordDialog, "wait_visibility"),
            patch.object(PasswordDialog, "grab_set"),
            patch.object(PasswordDialog, "wait_window"),
        ):
            dialog = PasswordDialog(self.root, "Test", "Password")
        try:
            self.assertIs(dialog.theme, self.window.theme)
            self.assertEqual(dialog.entry.cget("bg"), DARK[Color.FIELD])
            self.assertEqual(dialog.entry.cget("show"), "*")
            with patch.object(dialog.entry, "clipboard_get", return_value="  Secret  "):
                dialog._paste()
            self.window.theme.apply("light")
            self.assertEqual(dialog.entry.cget("bg"), LIGHT[Color.FIELD])
            self.assertEqual(dialog.entry.get(), "  Secret  ")
        finally:
            dialog.destroy()
        # Destroyed modal windows must not break future switches.
        self.window.theme.apply("dark")


if __name__ == "__main__":
    unittest.main()
