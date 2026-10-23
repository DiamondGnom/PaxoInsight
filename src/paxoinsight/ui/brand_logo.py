"""Theme-native wordmark around the unchanged, transparently clipped brand emblem."""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont

from .appearance import Color, Theme


class AdaptiveLogo(tk.Frame):
    """No white plate, raster recolouring, generated asset or extra dependency."""

    def __init__(self, parent, image: tk.PhotoImage, theme: Theme, family: str):
        super().__init__(parent, borderwidth=0, highlightthickness=0)
        self.image = image  # Keep the original Tk image alive.
        theme.configure(self, bg=Color.CARD, width=image.width(), height=image.height())
        self.pack_propagate(False)

        # The first 96 px of the bundled 384 px-wide logo contain its emblem.
        # Canvas clips only the view; the original PNG and its alpha stay intact.
        emblem_width = image.width() // 4
        self.emblem = theme.widget(
            tk.Canvas,
            self,
            width=emblem_width,
            height=image.height(),
            bg=Color.CARD,
            borderwidth=0,
            highlightthickness=0,
        )
        self.emblem.create_image(0, 0, image=image, anchor="nw")
        self.emblem.pack(side="left")

        size = max(1, image.height() // 2)
        self.word_font = tkfont.Font(root=self, family=family, size=-size, weight="bold")
        available = image.width() - emblem_width
        while (
            size > 1
            and sum(self.word_font.measure(part) for part in ("Paxo", "Insight")) > available
        ):
            size -= 1
            self.word_font.configure(size=-size)
        self.paxo = theme.widget(
            tk.Label,
            self,
            text="Paxo",
            bg=Color.CARD,
            fg=Color.HEADING,
            font=self.word_font,
            borderwidth=0,
            padx=0,
            pady=0,
        )
        self.insight = theme.widget(
            tk.Label,
            self,
            text="Insight",
            bg=Color.CARD,
            fg="#0098FF",
            font=self.word_font,
            borderwidth=0,
            padx=0,
            pady=0,
        )
        self.paxo.pack(side="left")
        self.insight.pack(side="left")
