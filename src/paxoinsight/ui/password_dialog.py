from __future__ import annotations

import os
import tkinter as tk
from tkinter import simpledialog


class PasswordDialog(simpledialog.Dialog):
    """Masked password input with paste support independent of keyboard layout."""

    def __init__(self, parent: tk.Misc, title: str, prompt: str) -> None:
        self.prompt = prompt
        super().__init__(parent, title)

    def body(self, master: tk.Misc) -> tk.Entry:
        tk.Label(master, text=self.prompt, justify="left", wraplength=470).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 6)
        )
        self.entry = tk.Entry(master, show="*", width=42)
        self.entry.grid(row=1, column=0, sticky="ew", padx=(8, 4), pady=4)
        master.columnconfigure(0, weight=1)
        tk.Button(master, text="Вставить", command=self._paste).grid(
            row=1, column=1, padx=(4, 8), pady=4
        )
        tk.Label(master, text="Вставка: Ctrl+V или Shift+Insert", anchor="w").grid(
            row=2, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 6)
        )
        self.entry.bind("<<Paste>>", self._paste)
        self.entry.bind("<Control-KeyPress>", self._control_key)
        self.entry.bind("<Shift-Insert>", self._paste)
        self.paste_menu = tk.Menu(self.entry, tearoff=False)
        self.paste_menu.add_command(label="Вставить", command=self._paste)
        self.entry.bind("<Button-3>", self._popup_menu)
        return self.entry

    def buttonbox(self) -> None:
        box = tk.Frame(self)
        tk.Button(box, text="ОК", width=10, command=self.ok, default="active").pack(
            side="left", padx=5, pady=5
        )
        tk.Button(box, text="Отмена", width=10, command=self.cancel).pack(
            side="left", padx=5, pady=5
        )
        self.bind("<Return>", self.ok)
        self.bind("<Escape>", self.cancel)
        box.pack()

    def _control_key(self, event: tk.Event) -> str | None:
        # On Windows the physical V key has VK_V=86 even when Tk reports
        # Cyrillic_em (м) in the Russian layout. Leave other Ctrl keys alone.
        if event.state & 0x0008:  # AltGr / Ctrl+Alt is not a paste shortcut.
            return None
        if event.keysym.lower() in {"v", "cyrillic_em", "м"} or (
            os.name == "nt" and event.keycode == 86
        ):
            return self._paste()
        return None

    def _paste(self, _event: tk.Event | None = None) -> str:
        try:
            value = self.entry.clipboard_get()
        except tk.TclError:
            return "break"
        if not value:
            return "break"
        position = self.entry.index("insert")
        if self.entry.selection_present():
            position = self.entry.index("sel.first")
            self.entry.delete("sel.first", "sel.last")
        self.entry.insert(position, value)
        self.entry.icursor(position + len(value))
        self.entry.selection_clear()
        self.entry.focus_set()
        # Stop Tk's class binding, which would otherwise paste a second time.
        return "break"

    def _popup_menu(self, event: tk.Event) -> str:
        try:
            self.paste_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.paste_menu.grab_release()
        return "break"

    def apply(self) -> None:
        self.result = self.entry.get()


def ask_archive_password(title: str, prompt: str, *, parent: tk.Misc) -> str | None:
    return PasswordDialog(parent, title, prompt).result
