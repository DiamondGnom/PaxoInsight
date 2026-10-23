"""Live desktop colours and a single non-sensitive user preference; no job history."""

from __future__ import annotations

import json
import os
import uuid
import weakref
from enum import Enum
from pathlib import Path
from tkinter import ttk


class Color(Enum):
    SURFACE = "surface"
    CARD = "card"
    TEXT = "text"
    MUTED = "muted"
    HEADING = "heading"
    BORDER = "border"
    ACCENT = "accent"
    ACCENT_HOVER = "accent_hover"
    ON_ACCENT = "on_accent"
    SUBTLE = "subtle"
    SUBTLE_HOVER = "subtle_hover"
    DISABLED = "disabled"
    DISABLED_TEXT = "disabled_text"
    FIELD = "field"
    DROP = "drop"
    DROP_BORDER = "drop_border"
    TROUGH = "trough"
    TAB = "tab"
    SELECT = "select"
    SELECT_TEXT = "select_text"
    SUCCESS = "success"
    SUCCESS_BG = "success_bg"
    SUCCESS_TEXT = "success_text"
    WARNING = "warning"
    WARNING_BG = "warning_bg"
    WARNING_TEXT = "warning_text"
    DANGER = "danger"
    DANGER_BG = "danger_bg"
    DANGER_TEXT = "danger_text"
    INFO_BG = "info_bg"
    INFO_TEXT = "info_text"
    KOTLIN_BG = "kotlin_bg"
    KOTLIN_TEXT = "kotlin_text"


LIGHT = dict(
    zip(
        Color,
        (
            "#F8FAFC",
            "#FFFFFF",
            "#0F172A",
            "#64748B",
            "#0B2A5B",
            "#E2E8F0",
            "#0073C4",
            "#005F9F",
            "#FFFFFF",
            "#EFF6FF",
            "#D7EBFF",
            "#E2E8F0",
            "#64748B",
            "#FFFFFF",
            "#F4F9FF",
            "#80B8EC",
            "#EAF2FB",
            "#EAF0F7",
            "#0B2A5B",
            "#FFFFFF",
            "#15803D",
            "#DCFCE7",
            "#166534",
            "#B45309",
            "#FEF3C7",
            "#92400E",
            "#DC2626",
            "#FEE2E2",
            "#B91C1C",
            "#DBEAFE",
            "#1D4ED8",
            "#F3E8FF",
            "#7E22CE",
        ),
        strict=True,
    )
)
DARK = dict(
    zip(
        Color,
        (
            "#0B1220",
            "#111D30",
            "#E5EDF8",
            "#A5B4CB",
            "#B9DFFF",
            "#35455F",
            "#0073C4",
            "#005F9F",
            "#FFFFFF",
            "#142C49",
            "#203F62",
            "#26354A",
            "#A0AEC3",
            "#0D1728",
            "#14263E",
            "#4889BC",
            "#26354A",
            "#17263D",
            "#24588E",
            "#FFFFFF",
            "#6EE7A0",
            "#123B2B",
            "#9AF2B8",
            "#FBBF24",
            "#443319",
            "#FFD485",
            "#FB7185",
            "#482433",
            "#FFAFB9",
            "#173559",
            "#A8D5FF",
            "#352747",
            "#E2BBFF",
        ),
        strict=True,
    )
)
PALETTES = {"light": LIGHT, "dark": DARK}


def preference_path() -> Path:
    base = os.environ.get("APPDATA") if os.name == "nt" else os.environ.get("XDG_CONFIG_HOME")
    return (Path(base) if base else Path.home() / ".config") / "PaxoInsight" / "appearance.json"


def load_theme(path: Path | None = None) -> str:
    try:
        with (path or preference_path()).open("rb") as stream:
            data = stream.read(4097)
        if len(data) > 4096:
            return "light"
        value = json.loads(data)
        name = value.get("theme") if isinstance(value, dict) else None
        return name if isinstance(name, str) and name in PALETTES else "light"
    except OSError, ValueError, UnicodeError, RecursionError:
        return "light"


def save_theme(name: str, path: Path | None = None) -> None:
    if name not in PALETTES:
        raise ValueError("Unknown desktop theme")
    destination = path or preference_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps({"theme": name}) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


class Theme:
    """Keep semantic colour bindings, so switching never rebuilds or clears widgets."""

    def __init__(self, root, name: str = "light", font: str = "Segoe UI"):
        self.root = root
        self.name = name if name in PALETTES else "light"
        self.font = font
        self.bindings = weakref.WeakKeyDictionary()
        self.tags = weakref.WeakKeyDictionary()

    def resolve(self, options: dict) -> dict:
        return {
            key: PALETTES[self.name][value] if isinstance(value, Color) else value
            for key, value in options.items()
        }

    def configure(self, widget, **options) -> None:
        aliases = {"bg": "background", "fg": "foreground"}
        options = {aliases.get(key, key): value for key, value in options.items()}
        bindings = self.bindings.setdefault(widget, {})
        for key, value in options.items():
            if isinstance(value, Color):
                bindings[key] = value
            else:
                bindings.pop(key, None)
        widget.configure(**self.resolve(options))

    def widget(self, constructor, *args, **options):
        widget = constructor(*args, **self.resolve(options))
        self.configure(widget, **options)
        kind = widget.winfo_class()
        if kind in {"Entry", "Spinbox", "Text"}:
            common = dict(
                background=Color.FIELD,
                foreground=Color.TEXT,
                insertbackground=Color.TEXT,
                selectbackground=Color.SELECT,
                selectforeground=Color.SELECT_TEXT,
                highlightcolor=Color.ACCENT,
                highlightbackground=Color.BORDER,
            )
            if kind != "Text":
                common.update(
                    disabledbackground=Color.DISABLED,
                    disabledforeground=Color.DISABLED_TEXT,
                    readonlybackground=Color.FIELD,
                )
            if kind == "Spinbox":
                common.update(buttonbackground=Color.SUBTLE)
            self.configure(widget, **common)
        elif kind == "Menu":
            self.configure(
                widget,
                background=Color.CARD,
                foreground=Color.TEXT,
                activebackground=Color.SELECT,
                activeforeground=Color.SELECT_TEXT,
                disabledforeground=Color.DISABLED_TEXT,
                selectcolor=Color.HEADING,
            )
        elif kind == "Checkbutton":
            self.configure(widget, disabledforeground=Color.DISABLED_TEXT)
        return widget

    def tag_configure(self, widget, tag: str, **options) -> None:
        bindings = self.tags.setdefault(widget, {}).setdefault(tag, {})
        for key, value in options.items():
            if isinstance(value, Color):
                bindings[key] = value
            else:
                bindings.pop(key, None)
        widget.tag_configure(tag, **self.resolve(options))

    def apply(self, name: str) -> None:
        if name not in PALETTES:
            raise ValueError("Unknown desktop theme")
        self.name = name
        self.configure_styles()
        for widget, bindings in list(self.bindings.items()):
            if widget.winfo_exists():
                widget.configure(**self.resolve(bindings))
        for widget, tags in list(self.tags.items()):
            if widget.winfo_exists():
                for tag, bindings in tags.items():
                    widget.tag_configure(tag, **self.resolve(bindings))

    def configure_styles(self) -> None:
        style = ttk.Style(self.root)
        if style.theme_use() != "clam":
            style.theme_use("clam")

        def config(name, **options):
            style.configure(name, **self.resolve(options))

        def mapped(name, **options):
            style.map(
                name,
                **{
                    key: [(*item[:-1], self.resolve({"x": item[-1]})["x"]) for item in values]
                    for key, values in options.items()
                },
            )

        config(
            ".",
            background=Color.SURFACE,
            foreground=Color.TEXT,
            bordercolor=Color.BORDER,
            lightcolor=Color.BORDER,
            darkcolor=Color.BORDER,
            troughcolor=Color.TROUGH,
            selectbackground=Color.SELECT,
            selectforeground=Color.SELECT_TEXT,
            font=(self.font, 10),
        )
        config("TFrame", background=Color.SURFACE)
        config("Card.TFrame", background=Color.CARD, relief="solid", borderwidth=1)
        config(
            "Card.TLabelframe",
            background=Color.CARD,
            bordercolor=Color.BORDER,
            lightcolor=Color.BORDER,
            darkcolor=Color.BORDER,
            padding=12,
        )
        config(
            "Card.TLabelframe.Label",
            background=Color.CARD,
            foreground=Color.HEADING,
            font=(self.font, 10, "bold"),
        )
        config("TLabel", background=Color.SURFACE, foreground=Color.TEXT)
        config("Card.TLabel", background=Color.CARD, foreground=Color.TEXT)
        config(
            "TButton",
            background=Color.CARD,
            foreground=Color.HEADING,
            bordercolor=Color.BORDER,
            focusthickness=1,
            focuscolor=Color.ACCENT,
            font=(self.font, 9),
            padding=(11, 7),
        )
        mapped(
            "TButton",
            background=[("disabled", Color.DISABLED), ("active", Color.SUBTLE)],
            foreground=[("disabled", Color.DISABLED_TEXT)],
        )
        config(
            "TProgressbar",
            background=Color.ACCENT,
            troughcolor=Color.TROUGH,
            bordercolor=Color.TROUGH,
            lightcolor=Color.ACCENT,
            darkcolor=Color.ACCENT,
        )
        config(
            "Treeview",
            background=Color.CARD,
            fieldbackground=Color.CARD,
            foreground=Color.TEXT,
            bordercolor=Color.BORDER,
            rowheight=27,
            font=(self.font, 9),
        )
        mapped(
            "Treeview",
            background=[("selected", Color.SELECT)],
            foreground=[("selected", Color.SELECT_TEXT)],
        )
        config(
            "Treeview.Heading",
            background=Color.SUBTLE,
            foreground=Color.HEADING,
            bordercolor=Color.BORDER,
            font=(self.font, 9, "bold"),
            padding=(7, 6),
        )
        mapped("Treeview.Heading", background=[("active", Color.SUBTLE_HOVER)])
        config("TNotebook", background=Color.SURFACE, bordercolor=Color.BORDER)
        config(
            "TNotebook.Tab",
            background=Color.TAB,
            foreground=Color.MUTED,
            padding=(14, 8),
            font=(self.font, 9, "bold"),
        )
        mapped(
            "TNotebook.Tab",
            background=[("selected", Color.CARD), ("active", Color.SUBTLE)],
            foreground=[("selected", Color.HEADING)],
        )
        config(
            "TScrollbar",
            background=Color.SUBTLE,
            arrowcolor=Color.TEXT,
            troughcolor=Color.SURFACE,
            bordercolor=Color.BORDER,
        )
        mapped("TScrollbar", background=[("active", Color.SUBTLE_HOVER)])
