from __future__ import annotations

import os
import tkinter as tk
import unittest
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

from paxoinsight.ui.password_dialog import PasswordDialog
from paxoinsight.ui.tk_main_window import PaxoInsightWindow


class PasswordDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.root = tk.Tk()
        except tk.TclError as error:
            raise unittest.SkipTest(f"Tk is unavailable: {error}") from error
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.root.destroy()

    def setUp(self) -> None:
        # Construct the real Tk dialog without showing a modal window. All
        # clipboard calls below are mocked, leaving the user's clipboard intact.
        with (
            patch("tkinter.simpledialog._place_window"),
            patch.object(PasswordDialog, "wait_visibility"),
            patch.object(PasswordDialog, "grab_set"),
            patch.object(PasswordDialog, "wait_window"),
        ):
            self.dialog = PasswordDialog(self.root, "Test", "Test password")

    def tearDown(self) -> None:
        self.dialog.destroy()

    def test_ctrl_v_pastes_once_in_latin_and_russian_layouts(self) -> None:
        for keysym in ("v", "V", "Cyrillic_em", "Cyrillic_EM", "м"):
            with self.subTest(keysym=keysym):
                self.dialog.entry.delete(0, "end")
                with patch.object(
                    self.dialog.entry, "clipboard_get", return_value="secret"
                ) as read:
                    event = SimpleNamespace(keysym=keysym, keycode=86, state=0x0004)
                    self.assertEqual(self.dialog._control_key(event), "break")
                read.assert_called_once_with()
                self.assertEqual(self.dialog.entry.get(), "secret")
                self.assertEqual(self.dialog.entry.cget("show"), "*")

    @unittest.skipUnless(os.name == "nt", "Windows virtual key test")
    def test_windows_physical_v_key_works_without_a_latin_keysym(self) -> None:
        event = SimpleNamespace(keysym="unknown", keycode=86, state=0x0004)
        with patch.object(self.dialog.entry, "clipboard_get", return_value="secret"):
            self.assertEqual(self.dialog._control_key(event), "break")
        self.assertEqual(self.dialog.entry.get(), "secret")

    def test_paste_replaces_selection_without_changing_password_characters(self) -> None:
        self.dialog.entry.insert(0, "beforeOLDafter")
        self.dialog.entry.selection_range(6, 9)
        password = "  Па$$word🔑  "
        with patch.object(self.dialog.entry, "clipboard_get", return_value=password):
            self.dialog._paste()
        self.assertEqual(self.dialog.entry.get(), "before" + password + "after")
        self.dialog.apply()
        self.assertEqual(self.dialog.result, "before" + password + "after")

    def test_paste_inserts_at_caret_without_erasing_other_characters(self) -> None:
        self.dialog.entry.insert(0, "abcd")
        self.dialog.entry.icursor(2)
        with patch.object(self.dialog.entry, "clipboard_get", return_value="123"):
            self.dialog._paste()
        self.assertEqual(self.dialog.entry.get(), "ab123cd")
        self.assertEqual(self.dialog.entry.index("insert"), 5)

    def test_empty_or_non_text_clipboard_keeps_existing_password(self) -> None:
        for clipboard in ("", tk.TclError("No text available")):
            with self.subTest(clipboard=type(clipboard).__name__):
                self.dialog.entry.delete(0, "end")
                self.dialog.entry.insert(0, "existing")
                self.dialog.entry.selection_range(0, "end")
                kwargs = ({"side_effect": clipboard} if isinstance(clipboard, Exception)
                          else {"return_value": clipboard})
                with patch.object(self.dialog.entry, "clipboard_get", **kwargs):
                    self.assertEqual(self.dialog._paste(), "break")
                self.assertEqual(self.dialog.entry.get(), "existing")

    def test_other_control_keys_and_altgr_do_not_paste(self) -> None:
        with patch.object(self.dialog.entry, "clipboard_get") as read:
            self.assertIsNone(self.dialog._control_key(
                SimpleNamespace(keysym="c", keycode=67, state=0x0004)
            ))
            self.assertIsNone(self.dialog._control_key(
                SimpleNamespace(keysym="v", keycode=86, state=0x000C)
            ))
            read.assert_not_called()

    def test_virtual_paste_and_context_menu_use_the_same_handler(self) -> None:
        self.dialog.attributes("-alpha", 0.0)
        self.dialog.deiconify()
        self.root.update()
        with patch.object(self.dialog.entry, "clipboard_get", return_value="secret") as read:
            self.dialog.entry.event_generate("<<Paste>>")
            self.root.update_idletasks()
            self.assertEqual(self.dialog.entry.get(), "secret")
            read.assert_called_once_with()
            self.dialog.entry.delete(0, "end")
            self.dialog.paste_menu.invoke(0)
            self.assertEqual(self.dialog.entry.get(), "secret")
        self.assertTrue(self.dialog.entry.bind("<Shift-Insert>"))

    def test_registered_control_v_and_shift_insert_bindings_paste_once(self) -> None:
        self.dialog.attributes("-alpha", 0.0)
        self.dialog.deiconify()
        self.dialog.entry.focus_force()
        self.root.update()
        for shortcut in ("<Control-KeyPress-v>", "<Control-KeyPress-Cyrillic_em>",
                         "<Shift-KeyPress-Insert>"):
            with self.subTest(shortcut=shortcut):
                self.dialog.entry.delete(0, "end")
                with patch.object(
                    self.dialog.entry, "clipboard_get", return_value="secret"
                ) as read:
                    # Windows Tk does not derive a physical key code from a
                    # synthetic Unicode keysym. Supply VK_V as a real key event does.
                    kwargs = {"keycode": 86} if os.name == "nt" and "Control-" in shortcut else {}
                    self.dialog.entry.event_generate(shortcut, **kwargs)
                    self.root.update()
                    read.assert_called_once_with()
                self.assertEqual(self.dialog.entry.get(), "secret")

    def test_password_response_and_cancellation_release_the_worker(self) -> None:
        window = PaxoInsightWindow.__new__(PaxoInsightWindow)
        window.root = self.root
        for value in ("  secret  ", None):
            with self.subTest(cancelled=value is None):
                resolved = Event()
                response = {"password": None}
                with patch(
                    "paxoinsight.ui.tk_main_window.ask_archive_password", return_value=value
                ):
                    window._ask_password(Path("protected.7z"), 1, False, resolved, response)
                self.assertTrue(resolved.is_set())
                self.assertEqual(response["password"], value)


if __name__ == "__main__":
    unittest.main()
