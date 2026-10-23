from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont

from .. import APP_NAME, VERSION
from ..archive_service import (
    SUPPORTED_EXTENSIONS,
    archive_extension,
    strip_archive_extension,
)
from ..attention import ARCHIVE_STYLE, KOTLIN_STYLE, classify_attention, classify_highlight
from ..kotlin_coverage import coverage_text, percent
from ..models import AnalysisOptions, Finding, OperationCancelled, PreparedSession
from ..reporting import (
    STATUS_LABELS,
    expected_class_names,
    extract_kotlin_mapping,
    kotlin_table_rows,
    save_kotlin_html_report,
    save_kotlin_text_report,
    save_text_report,
)
from ..workflow import WorkflowService
from .appearance import Color, Theme, load_theme, save_theme
from .brand_logo import AdaptiveLogo
from .password_dialog import ask_archive_password

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except ImportError, OSError:
    DND_FILES = None
    TkinterDnD = None


ARCHIVE_FILETYPES = [
    (
        "Архивы",
        "*.zip *.7z *.rar *.tar *.tar.gz *.tgz *.tar.bz2 *.tbz2 "
        "*.tar.xz *.txz *.gz *.jar *.war *.ear *.bar *.sar *.aar *.aab "
        "*.apk *.ipa *.eba *.cba *.esa *.appzip *.libzip *.shlibzip "
        "*.appdomainzip *.xsdzip",
    ),
    ("Все файлы", "*.*"),
]

NAVY = Color.HEADING
BRAND_BLUE = Color.ACCENT
TEXT_PRIMARY = Color.TEXT
TEXT_SECONDARY = Color.MUTED
BORDER = Color.BORDER
SURFACE = Color.SURFACE
WHITE = Color.CARD
SUCCESS = Color.SUCCESS
WARNING = Color.WARNING
DANGER = Color.DANGER

SEVERITY_COLORS = {
    "critical": (Color.DANGER_BG, Color.DANGER_TEXT),
    "high": (Color.DANGER_BG, Color.DANGER_TEXT),
    "medium": (Color.WARNING_BG, Color.WARNING_TEXT),
    "low": (Color.INFO_BG, Color.INFO_TEXT),
    "info": (SURFACE, TEXT_SECONDARY),
}
ATTENTION_COLORS = {
    "package": (Color.DANGER_BG, Color.DANGER_TEXT),
    "executable": (Color.DANGER_BG, Color.DANGER_TEXT),
    "application_container": (Color.WARNING_BG, Color.WARNING_TEXT),
    "third_party_archive": (SURFACE, TEXT_SECONDARY),
    "kotlin": (Color.KOTLIN_BG, Color.KOTLIN_TEXT),
    "archive": (Color.INFO_BG, Color.INFO_TEXT),
}
MAX_VISIBLE_ITEMS = 500


def _resource_path(filename: str) -> Path:
    """Resolve an asset in both source and PyInstaller builds."""
    if getattr(sys, "frozen", False):
        base = Path(sys._MEIPASS)
    else:
        base = Path(__file__).resolve().parents[3]
    return base / "assets" / filename


class PaxoInsightWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_NAME} {VERSION}")
        self.root.geometry("1220x820")
        self.root.minsize(980, 680)
        self.theme = Theme(root, load_theme())
        self.root._paxo_theme = self.theme
        self.theme_var = tk.StringVar(root, value=self.theme.name)
        self.theme.configure(self.root, bg=SURFACE)

        installed_fonts = set(tkfont.families(self.root))
        self.ui_font = "Inter" if "Inter" in installed_fonts else "Segoe UI"
        self.mono_font = "JetBrains Mono" if "JetBrains Mono" in installed_fonts else "Consolas"
        self.theme.font = self.ui_font
        self.icon_image: tk.PhotoImage | None = None
        self.logo_image: tk.PhotoImage | None = None
        self.header_logo_image: tk.PhotoImage | None = None
        self.header_logo: AdaptiveLogo | None = None
        self._load_brand_assets()

        self.workflow = WorkflowService()
        self.source: Path | None = None
        self.session: PreparedSession | None = None
        self.cancel_event = threading.Event()
        self.events: queue.Queue[tuple] = queue.Queue()
        self.busy_kind: str | None = None
        self.closing = False

        self.path_var = tk.StringVar(value="Архив или папка не выбраны")
        self.status_var = tk.StringVar(value="Готов к работе")
        self.expand_nested_var = tk.BooleanVar(value=True)
        self.replace_nested_var = tk.BooleanVar(value=True)
        self.delete_source_var = tk.BooleanVar(value=True)
        self.unpack_containers_var = tk.BooleanVar(value=False)
        self.include_report_var = tk.BooleanVar(value=False)
        self.depth_var = tk.IntVar(value=5)

        self._configure_styles()
        self._build_menu()
        self._build_ui()
        self._refresh_controls()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(80, self._drain_events)

    def _load_brand_assets(self) -> None:
        try:
            self.icon_image = tk.PhotoImage(file=str(_resource_path("paxoinsight-icon.png")))
            self.logo_image = tk.PhotoImage(file=str(_resource_path("paxoinsight-logo.png")))
            self.header_logo_image = self.logo_image.subsample(2, 2)
            self.root.iconphoto(True, self.icon_image)
        except OSError, tk.TclError:
            # The application stays usable even when a development checkout lacks assets.
            self.icon_image = None
            self.logo_image = None
            self.header_logo_image = None

    def _configure_styles(self) -> None:
        self.theme.configure_styles()

    def _build_menu(self) -> None:
        menu = self.theme.widget(tk.Menu, self.root)
        self.report_menu = self.theme.widget(tk.Menu, menu, tearoff=False)
        self.report_menu.add_command(
            label="Показать Kotlin ↔ .class",
            command=self._show_kotlin_report,
            state="disabled",
        )
        self.report_menu.add_separator()
        self.report_menu.add_command(
            label="Сохранить Kotlin-отчёт в HTML…",
            command=self._save_kotlin_report,
            state="disabled",
        )
        self.report_menu.add_command(
            label="Сохранить Kotlin-отчёт в TXT…",
            command=lambda: self._save_kotlin_report("txt"),
            state="disabled",
        )
        self.report_menu.add_command(
            label="Сохранить полное заключение в TXT…",
            command=lambda: self._save_kotlin_report("full_txt"),
            state="disabled",
        )
        menu.add_cascade(label="Отчёт", menu=self.report_menu)
        view_menu = self.theme.widget(tk.Menu, menu, tearoff=False)
        self.theme_menu = self.theme.widget(tk.Menu, view_menu, tearoff=False)
        for name, label in (("light", "Светлая"), ("dark", "Тёмная")):
            self.theme_menu.add_radiobutton(
                label=label, value=name, variable=self.theme_var, command=self._change_theme
            )
        view_menu.add_cascade(label="Тема оформления", menu=self.theme_menu)
        menu.add_cascade(label="Вид", menu=view_menu)
        help_menu = self.theme.widget(tk.Menu, menu, tearoff=False)
        help_menu.add_command(label="О программе", command=self._show_about)
        menu.add_cascade(label="Справка", menu=help_menu)
        self.theme.configure(self.root, menu=menu)

    def _change_theme(self) -> None:
        name = self.theme_var.get()
        self.theme.apply(name)
        try:
            save_theme(name)
        except OSError as error:
            self._log(f"Тема применена, но не удалось сохранить настройку: {error}")
            messagebox.showwarning(
                "Настройка темы",
                "Тема изменена для текущего запуска, но настройку не удалось сохранить.\n"
                "При следующем запуске может использоваться прежняя тема.",
                parent=self.root,
            )

    def _build_ui(self) -> None:
        header = self.theme.widget(tk.Frame, self.root, bg=WHITE, padx=24, pady=10)
        header.pack(fill="x")
        title_column = self.theme.widget(tk.Frame, header, bg=WHITE)
        title_column.pack(side="left", fill="x", expand=True)
        if self.header_logo_image is not None:
            self.header_logo = AdaptiveLogo(
                title_column, self.header_logo_image, self.theme, self.ui_font
            )
            self.header_logo.pack(anchor="w")
        else:
            self.theme.widget(
                tk.Label,
                title_column,
                text=APP_NAME,
                bg=WHITE,
                fg=NAVY,
                font=(self.ui_font, 24, "bold"),
            ).pack(anchor="w")
        self.theme.widget(
            tk.Label,
            title_column,
            text="Анализ и подготовка архивов и папок для последующего сканирования",
            bg=WHITE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 10),
        ).pack(anchor="w", pady=(2, 0))
        version_box = self.theme.widget(tk.Frame, header, bg=Color.SUBTLE, padx=12, pady=8)
        version_box.pack(side="right", anchor="n", padx=(20, 0))
        self.theme.widget(
            tk.Label,
            version_box,
            text=f"v{VERSION}",
            bg=Color.SUBTLE,
            fg=NAVY,
            font=(self.ui_font, 10, "bold"),
        ).pack()
        self.theme.widget(
            tk.Label,
            version_box,
            text="standalone",
            bg=Color.SUBTLE,
            fg=BRAND_BLUE,
            font=(self.ui_font, 8),
        ).pack()
        self.theme.widget(tk.Frame, self.root, bg=NAVY, height=4).pack(fill="x")

        body = ttk.Frame(self.root, padding=(20, 16))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(1, weight=1)

        source_card = ttk.LabelFrame(body, text="Источник и подготовка", style="Card.TLabelframe")
        source_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 10))
        source_card.columnconfigure(0, weight=1)

        self.drop_frame = self.theme.widget(
            tk.Frame,
            source_card,
            bg=Color.DROP,
            highlightbackground=Color.DROP_BORDER,
            highlightthickness=2,
            padx=16,
            pady=12,
        )
        self.drop_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        self.theme.widget(
            tk.Label,
            self.drop_frame,
            text="Перетащите архив или папку сюда",
            bg=Color.DROP,
            fg=NAVY,
            font=(self.ui_font, 12, "bold"),
        ).pack()
        self.path_label = self.theme.widget(
            tk.Label,
            self.drop_frame,
            textvariable=self.path_var,
            bg=Color.DROP,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
            wraplength=660,
        )
        self.path_label.pack(fill="x", pady=(3, 7))
        choose_row = self.theme.widget(tk.Frame, self.drop_frame, bg=Color.DROP)
        choose_row.pack()
        self.archive_button = ttk.Button(
            choose_row, text="Выбрать архив", command=self._choose_archive
        )
        self.archive_button.pack(side="left", padx=4)
        self.folder_button = ttk.Button(
            choose_row, text="Выбрать папку", command=self._choose_folder
        )
        self.folder_button.pack(side="left", padx=4)
        self._register_drop_target(self.drop_frame)
        self._register_drop_target(self.path_label)

        options = self.theme.widget(tk.Frame, source_card, bg=WHITE)
        options.grid(row=1, column=0, sticky="ew")
        self.expand_check = self.theme.widget(
            tk.Checkbutton,
            options,
            text="Распаковывать вложенные архивы",
            variable=self.expand_nested_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            activebackground=WHITE,
            activeforeground=NAVY,
            selectcolor=WHITE,
            font=(self.ui_font, 9),
            anchor="w",
        )
        self.expand_check.grid(row=0, column=0, columnspan=2, sticky="w")
        self.replace_check = self.theme.widget(
            tk.Checkbutton,
            options,
            text="Заменять их распакованным содержимым",
            variable=self.replace_nested_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            activebackground=WHITE,
            activeforeground=NAVY,
            selectcolor=WHITE,
            font=(self.ui_font, 9),
            anchor="w",
        )
        self.replace_check.grid(row=1, column=0, columnspan=2, sticky="w")
        self.delete_check = self.theme.widget(
            tk.Checkbutton,
            options,
            text="Удалять исходный архив после успешного анализа",
            variable=self.delete_source_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            activebackground=WHITE,
            activeforeground=NAVY,
            selectcolor=WHITE,
            font=(self.ui_font, 9),
            anchor="w",
        )
        self.delete_check.grid(row=2, column=0, columnspan=2, sticky="w")
        self.container_check = self.theme.widget(
            tk.Checkbutton,
            options,
            text="Распаковывать ZIP/JAR-контейнеры",
            variable=self.unpack_containers_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            activebackground=WHITE,
            activeforeground=NAVY,
            selectcolor=WHITE,
            font=(self.ui_font, 9),
            anchor="w",
        )
        self.container_check.grid(row=3, column=0, sticky="w")
        self.theme.widget(
            tk.Label,
            options,
            text="Макс. глубина:",
            bg=WHITE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
        ).grid(row=3, column=1, sticky="e", padx=(12, 4))
        self.depth_spin = self.theme.widget(
            tk.Spinbox, options, from_=1, to=10, textvariable=self.depth_var, width=4
        )
        self.depth_spin.grid(row=3, column=2, sticky="w")
        self.report_check = self.theme.widget(
            tk.Checkbutton,
            options,
            text="Включить отчёты TXT/JSON/HTML в итоговый 7Z",
            variable=self.include_report_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            activebackground=WHITE,
            activeforeground=NAVY,
            selectcolor=WHITE,
            font=(self.ui_font, 9),
            anchor="w",
        )
        self.report_check.grid(row=4, column=0, columnspan=2, sticky="w")

        action_row = self.theme.widget(tk.Frame, source_card, bg=WHITE)
        action_row.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        action_row.columnconfigure(0, weight=1)
        action_row.columnconfigure(1, weight=1)
        self.scan_button = self.theme.widget(
            tk.Button,
            action_row,
            text="Запустить анализ",
            command=self._start_scan,
            font=(self.ui_font, 10, "bold"),
            relief="flat",
            bd=0,
            padx=14,
            pady=8,
            cursor="hand2",
        )
        self.scan_button.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.cancel_button = ttk.Button(action_row, text="Отменить", command=self._cancel)
        self.cancel_button.grid(row=0, column=1, sticky="ew", padx=(4, 0))

        state_card = ttk.LabelFrame(body, text="Текущее задание", style="Card.TLabelframe")
        state_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 10))
        state_card.columnconfigure(0, weight=1)
        status_row = self.theme.widget(tk.Frame, state_card, bg=WHITE)
        status_row.grid(row=0, column=0, sticky="ew")
        status_row.columnconfigure(1, weight=1)
        self.status_dot = self.theme.widget(
            tk.Label,
            status_row,
            text="●",
            bg=WHITE,
            fg=SUCCESS,
            font=(self.ui_font, 13, "bold"),
        )
        self.status_dot.grid(row=0, column=0, sticky="n", padx=(0, 7))
        self.status_label = self.theme.widget(
            tk.Label,
            status_row,
            textvariable=self.status_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            font=(self.ui_font, 10, "bold"),
            justify="left",
            wraplength=410,
        )
        self.status_label.grid(row=0, column=1, sticky="ew")
        self.status_badge = self.theme.widget(
            tk.Label,
            status_row,
            text="ГОТОВО",
            bg=Color.SUCCESS_BG,
            fg=Color.SUCCESS_TEXT,
            font=(self.ui_font, 8, "bold"),
            padx=7,
            pady=3,
        )
        self.status_badge.grid(row=0, column=2, sticky="ne", padx=(8, 0))
        self.progress = ttk.Progressbar(state_card, maximum=100)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 10))
        metrics = self.theme.widget(tk.Frame, state_card, bg=WHITE)
        metrics.grid(row=2, column=0, sticky="nsew")
        for column in range(2):
            metrics.columnconfigure(column, weight=1)
        self.metric_files = self._metric(metrics, 0, 0, "файлов")
        self.metric_size = self._metric(metrics, 0, 1, "распаковано")
        self.metric_score = self._metric(metrics, 1, 0, "целостность")
        self.metric_findings = self._metric(metrics, 1, 1, "находок")
        self.sast_label = self.theme.widget(
            tk.Label,
            state_card,
            text="SAST: —",
            bg=SURFACE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
            justify="left",
            anchor="w",
            wraplength=410,
            padx=8,
            pady=6,
        )
        self.sast_label.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        self.preparation_hint = self.theme.widget(
            tk.Label,
            state_card,
            text="",
            bg=Color.WARNING_BG,
            fg=Color.WARNING_TEXT,
            font=(self.ui_font, 9),
            justify="left",
            anchor="w",
            wraplength=410,
            padx=8,
            pady=8,
        )
        self.preparation_hint.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        self.preparation_hint.grid_remove()

        self.notebook = ttk.Notebook(body)
        self.notebook.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.summary_text = self._text_tab("Заключение")
        self.kotlin_tree = self._tree_tab(
            "Kotlin ↔ .class",
            (
                "mapping_status",
                "kotlin_source",
                "declaration",
                "expected_class",
                "class_result",
                "mapping_context",
                "mapping_reason",
            ),
            (190, 330, 210, 280, 420, 220, 500),
        )
        self.kotlin_coverage_var = tk.StringVar(
            value="Покрытие Kotlin/JVM: н/д — анализ не выполнен"
        )
        coverage_label = self.theme.widget(
            tk.Label,
            self.kotlin_tree.master,
            textvariable=self.kotlin_coverage_var,
            bg=Color.SUBTLE,
            fg=NAVY,
            font=(self.ui_font, 10),
            justify="left",
            anchor="w",
            padx=12,
            pady=8,
            wraplength=1000,
        )
        coverage_label.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.kotlin_tree.master.bind(
            "<Configure>",
            lambda event: self.theme.configure(
                coverage_label, wraplength=max(250, event.width - 24)
            ),
            add="+",
        )
        self.findings_tree = self._tree_tab(
            "Находки", ("severity", "category", "title"), (110, 180, 620)
        )
        self.attention_tree = self._tree_tab(
            "Контроль файлов", ("group", "path", "state"), (210, 430, 330)
        )
        self.extensions_tree = self._tree_tab("Состав", ("extension", "count"), (500, 130))
        self.log_text = self._text_tab("Ход выполнения")
        self._configure_tree_tags()

        footer = ttk.Frame(body)
        footer.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.new_button = ttk.Button(footer, text="Следующее задание", command=self._new_task)
        self.new_button.pack(side="left", padx=(0, 5))
        self.workspace_button = ttk.Button(
            footer, text="Открыть рабочую папку", command=self._open_workspace
        )
        self.workspace_button.pack(side="left", padx=5)
        self.output_button = ttk.Button(
            footer, text="Открыть созданный 7Z", command=self._open_output
        )
        self.output_button.pack(side="left", padx=5)
        self.package_button = self.theme.widget(
            tk.Button,
            footer,
            text="Собрать и проверить 7Z",
            command=self._start_package,
            font=(self.ui_font, 10, "bold"),
            relief="flat",
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
        )
        self.package_button.pack(side="right")

    def _metric(self, parent: tk.Widget, row: int, column: int, caption: str) -> tk.Label:
        card = self.theme.widget(
            tk.Frame, parent, bg=WHITE, highlightbackground=BORDER, highlightthickness=1
        )
        card.grid(row=row, column=column, sticky="nsew", padx=4, pady=4)
        value = self.theme.widget(
            tk.Label, card, text="—", bg=WHITE, fg=NAVY, font=(self.ui_font, 17, "bold")
        )
        value.pack(anchor="w", padx=10, pady=(7, 0))
        self.theme.widget(
            tk.Label,
            card,
            text=caption,
            bg=WHITE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
        ).pack(anchor="w", padx=10, pady=(0, 7))
        return value

    def _text_tab(self, title: str) -> tk.Text:
        frame = ttk.Frame(self.notebook)
        text = self.theme.widget(
            tk.Text,
            frame,
            wrap="word",
            bg=WHITE,
            fg=TEXT_PRIMARY,
            relief="flat",
            font=(self.mono_font, 10),
            padx=10,
            pady=8,
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        self.theme.configure(text, yscrollcommand=scroll.set, state="disabled")
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.notebook.add(frame, text=title)
        return text

    def _tree_tab(
        self, title: str, columns: tuple[str, ...], widths: tuple[int, ...]
    ) -> ttk.Treeview:
        frame = ttk.Frame(self.notebook)
        tree = ttk.Treeview(frame, columns=columns, show="headings")
        headings = {
            "severity": "Уровень",
            "category": "Категория",
            "title": "Находка",
            "group": "Группа",
            "path": "Файл",
            "state": "Состояние / пояснение",
            "extension": "Расширение",
            "count": "Количество",
            "mapping_status": "Статус",
            "kotlin_source": "Kotlin / .class",
            "class_result": "Результат сопоставления",
            "declaration": "Объявление",
            "expected_class": "Ожидаемый класс",
            "mapping_context": "Модуль / набор",
            "mapping_reason": "Основание / пояснение",
        }
        for column, width in zip(columns, widths, strict=True):
            tree.heading(column, text=headings[column])
            tree.column(
                column,
                width=width,
                stretch=column not in {"severity", "count", "mapping_status"},
            )
        vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        self.theme.configure(tree, yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.notebook.add(frame, text=title)
        return tree

    def _configure_tree_tags(self) -> None:
        for key, (background, foreground) in SEVERITY_COLORS.items():
            self.theme.tag_configure(
                self.findings_tree, key, background=background, foreground=foreground
            )
        for tree in (self.attention_tree, self.extensions_tree):
            for key, (background, foreground) in ATTENTION_COLORS.items():
                self.theme.tag_configure(tree, key, background=background, foreground=foreground)
        self.theme.tag_configure(
            self.kotlin_tree, "matched", background=Color.SUCCESS_BG, foreground=Color.SUCCESS_TEXT
        )
        self.theme.tag_configure(
            self.kotlin_tree,
            "missing_main",
            background=Color.DANGER_BG,
            foreground=Color.DANGER_TEXT,
        )
        self.theme.tag_configure(
            self.kotlin_tree,
            "missing_test",
            background=Color.WARNING_BG,
            foreground=Color.WARNING_TEXT,
        )
        self.theme.tag_configure(
            self.kotlin_tree, "orphan", background=Color.SUBTLE, foreground=Color.INFO_TEXT
        )
        self.theme.tag_configure(
            self.kotlin_tree, "ignored", background=SURFACE, foreground=TEXT_SECONDARY
        )
        self.theme.tag_configure(
            self.kotlin_tree,
            "unavailable",
            background=Color.DANGER_BG,
            foreground=Color.DANGER_TEXT,
        )
        for tag in ("partial", "probable", "ambiguous", "unverified"):
            self.theme.tag_configure(
                self.kotlin_tree, tag, background=Color.WARNING_BG, foreground=Color.WARNING_TEXT
            )

    def _register_drop_target(self, widget: tk.Widget) -> None:
        if DND_FILES is None or not hasattr(widget, "drop_target_register"):
            return
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self._on_drop)
        except tk.TclError:
            pass

    def _on_drop(self, event) -> str:
        try:
            values = self.root.tk.splitlist(event.data)
            if values:
                self._set_source(Path(values[0]))
        except tk.TclError, ValueError:
            pass
        return "break"

    def _choose_archive(self) -> None:
        value = filedialog.askopenfilename(
            parent=self.root, title="Выберите архив", filetypes=ARCHIVE_FILETYPES
        )
        if value:
            self._set_source(Path(value))

    def _choose_folder(self) -> None:
        value = filedialog.askdirectory(parent=self.root, title="Выберите папку для анализа")
        if value:
            self._set_source(Path(value))

    def _set_source(self, value: Path) -> None:
        if self.busy_kind:
            return
        source = value.expanduser().resolve()
        supported = source.is_dir() or (
            source.is_file() and archive_extension(source) in SUPPORTED_EXTENSIONS
        )
        if not supported:
            messagebox.showwarning(
                "Неподдерживаемый источник",
                "Выберите папку или поддерживаемый архив.",
                parent=self.root,
            )
            return
        if self.session and not self._discard_current():
            return
        self.source = source
        self.path_var.set(str(source))
        self._clear_results(clear_log=True)
        kind = "Папка" if source.is_dir() else "Архив"
        self._set_status(f"{kind} выбран. Запустите анализ.", "ready")
        self._log(f"Выбран источник: {source}")
        self._refresh_controls()

    def _options(self) -> AnalysisOptions:
        try:
            depth = max(1, min(10, int(self.depth_var.get())))
        except TypeError, ValueError, tk.TclError:
            depth = 5
            self.depth_var.set(depth)
        return AnalysisOptions(
            expand_nested=self.expand_nested_var.get(),
            replace_nested_archives=self.replace_nested_var.get(),
            delete_source_archive=self.delete_source_var.get(),
            unpack_application_containers=self.unpack_containers_var.get(),
            max_depth=depth,
        )

    def _start_scan(self) -> None:
        if self.busy_kind:
            return
        options = self._options()
        self._clear_results(clear_log=False)
        if self.session:
            session = self.session
            self._log("Повторный анализ текущей рабочей области")
            self._start_job(
                "rescan",
                lambda: self.workflow.rescan(
                    session,
                    options,
                    self._progress_callback,
                    self.cancel_event,
                    self._password_provider,
                ),
            )
            return
        if not self.source or not self.source.exists():
            return
        source = self.source
        self._log(f"Запуск анализа: {source.name}")
        self._start_job(
            "scan",
            lambda: self.workflow.scan(
                source,
                options,
                self._progress_callback,
                self.cancel_event,
                self._password_provider,
            ),
        )

    def _start_package(self) -> None:
        if self.busy_kind or not self.session or not self.session.result:
            return
        source = self.session.source_path
        base = source.name if self.session.source_is_directory else strip_archive_extension(source)
        default = str(source.with_name(f"{base or 'PaxoInsight'}_prepared.7z"))
        value = filedialog.asksaveasfilename(
            parent=self.root,
            title="Сохранить подготовленный 7Z",
            initialfile=Path(default).name,
            initialdir=str(Path(default).parent),
            defaultextension=".7z",
            filetypes=[("Архив 7Z", "*.7z")],
        )
        if not value:
            return
        destination = Path(value)
        if destination.suffix.lower() != ".7z":
            destination = destination.with_suffix(".7z")
        if destination.exists() and not messagebox.askyesno(
            "Заменить файл?",
            f"Файл уже существует:\n{destination}\n\nЗаменить после успешной проверки?",
            parent=self.root,
        ):
            return
        session = self.session
        include_report = self.include_report_var.get()
        self._log(f"Сборка 7Z: {destination}")
        self._start_job(
            "package",
            lambda: self.workflow.package(
                session,
                destination,
                include_report,
                self._progress_callback,
                self.cancel_event,
            ),
        )

    def _start_job(self, kind: str, callback) -> None:
        self.cancel_event = threading.Event()
        self.busy_kind = kind
        self.progress["value"] = 0
        self._set_status("Запуск операции…", "busy")
        self._refresh_controls()

        def run() -> None:
            try:
                result = callback()
                self.events.put(("completed", kind, result))
            except OperationCancelled:
                self.events.put(("cancelled",))
            except Exception as error:
                self.events.put(("failed", str(error)))
            finally:
                self.events.put(("finished",))

        threading.Thread(target=run, name=f"PaxoInsight-{kind}", daemon=True).start()

    def _progress_callback(self, value: int, text: str) -> None:
        self.events.put(("progress", value, text))

    def _password_provider(self, path: Path, attempt: int, incorrect: bool) -> str | None:
        resolved = threading.Event()
        response: dict[str, str | None] = {"password": None}
        self.events.put(("password", path, attempt, incorrect, resolved, response))
        while not resolved.wait(0.1):
            if self.cancel_event.is_set():
                return None
        return response["password"]

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                try:
                    kind = event[0]
                    if kind == "progress":
                        self.progress["value"] = max(0, min(100, event[1]))
                        self._set_status(event[2], "busy")
                        self._log(f"{event[1]:3}%  {event[2]}")
                    elif kind == "password":
                        self._ask_password(*event[1:])
                    elif kind == "completed":
                        self._completed(event[1], event[2])
                    elif kind == "cancelled":
                        self.progress["value"] = 0
                        self._set_status("Операция отменена", "ready")
                        self._log("Операция отменена пользователем.")
                    elif kind == "failed":
                        self.progress["value"] = 0
                        self._set_status(f"Ошибка: {event[1]}", "error")
                        self._log(f"ОШИБКА: {event[1]}")
                        messagebox.showerror("Ошибка", event[1], parent=self.root)
                    elif kind == "finished":
                        self.busy_kind = None
                        self._refresh_controls()
                        if self.closing:
                            self._finish_close()
                except tk.TclError:
                    if self.closing:
                        return
                    raise
                except Exception as error:
                    self.busy_kind = None
                    self.progress["value"] = 0
                    self._set_status(f"Ошибка интерфейса: {error}", "error")
                    self._log(f"ОШИБКА ИНТЕРФЕЙСА: {error}")
                    self._refresh_controls()
                    messagebox.showerror("Ошибка интерфейса", str(error), parent=self.root)
        except queue.Empty:
            pass
        try:
            if self.root.winfo_exists():
                self.root.after(80, self._drain_events)
        except tk.TclError:
            return

    def _ask_password(
        self,
        path: Path,
        attempt: int,
        incorrect: bool,
        resolved: threading.Event,
        response: dict[str, str | None],
    ) -> None:
        title = "Неверный пароль" if incorrect else "Архив защищён паролем"
        prefix = "Пароль не подошёл. " if incorrect else ""
        prompt = f"{prefix}Введите пароль для «{path.name}»\nПопытка {attempt} из 5:"
        try:
            response["password"] = ask_archive_password(title, prompt, parent=self.root)
        finally:
            resolved.set()

    def _completed(self, kind: str, result) -> None:
        if kind in {"scan", "rescan"}:
            self._scan_completed(result, repeated=kind == "rescan")
        else:
            self._package_completed(result)

    def _scan_completed(self, session: PreparedSession, repeated: bool) -> None:
        self.session = session
        result = session.result
        if result is None:
            raise RuntimeError("Анализ завершился без результата")
        self.theme.configure(self.metric_files, text=f"{result.total_files:,}".replace(",", " "))
        self.theme.configure(self.metric_size, text=self._format_size(result.total_bytes))
        if result.integrity_score < 70:
            score_color = DANGER
        elif result.integrity_score < 90:
            score_color = WARNING
        else:
            score_color = SUCCESS
        self.theme.configure(
            self.metric_score, text=f"{result.integrity_score}/100", fg=score_color
        )
        self.theme.configure(self.metric_findings, text=str(len(result.findings)))
        self.theme.configure(
            self.sast_label, text=f"SAST: {result.sast_mode}\n{result.sast_reason}"
        )
        self.theme.configure(self.preparation_hint, text=result.preparation_advice)
        if result.preparation_advice:
            self.preparation_hint.grid()
        else:
            self.preparation_hint.grid_remove()
        self._populate_summary(result)
        kotlin_mapping = self._populate_kotlin_mapping(result)
        self._populate_findings(result.findings)
        self._populate_attention(result)
        self._populate_extensions(result.extension_counts)

        urgent_findings = any(item.severity in {"critical", "high"} for item in result.findings)
        urgent_files = any(
            (style := classify_attention(path)) and style.key in {"package", "executable"}
            for path in result.attention_files
        )
        if urgent_findings:
            self.notebook.select(self.findings_tree.master)
        elif kotlin_mapping.issue_count:
            self.notebook.select(self.kotlin_tree.master)
        elif urgent_files:
            self.notebook.select(self.attention_tree.master)
        elif result.kotlin_files:
            self.notebook.select(self.kotlin_tree.master)

        if result.preparation_advice:
            self._set_status(
                "Анализ завершён. Рекомендуется повторная распаковка ZIP/JAR-контейнеров.",
                "warning",
            )
        elif kotlin_mapping.missing_count:
            self._set_status(
                "Анализ завершён. Kotlin-исходников без соответствующего .class: "
                f"{kotlin_mapping.missing_count}.",
                "warning",
            )
        elif kotlin_mapping.issue_count:
            self._set_status(
                "Анализ завершён. Сопоставления Kotlin/JVM требуют проверки: "
                f"{kotlin_mapping.issue_count}. Подробности в Kotlin ↔ .class.",
                "warning",
            )
        elif result.attention_files:
            self._set_status(
                f"Анализ завершён. Файлов повышенного внимания: {len(result.attention_files)}.",
                "warning",
            )
        elif result.kotlin_files:
            self._set_status(
                f"Анализ завершён. Обнаружено Kotlin-файлов: {len(result.kotlin_files)}.",
                "ready",
            )
        else:
            self._set_status("Анализ завершён. Материал готов к сборке в 7Z.", "ready")
        self._log("Повторный анализ завершён." if repeated else "Анализ завершён.")
        if session.source_deleted and not repeated:
            self._log("Исходный архив удалён после полностью успешного анализа.")

    def _populate_summary(self, result) -> None:
        self.theme.configure(self.summary_text, state="normal")
        self.summary_text.delete("1.0", "end")
        for key, (_background, foreground) in SEVERITY_COLORS.items():
            self.theme.tag_configure(
                self.summary_text, key, foreground=foreground, font=(self.mono_font, 10, "bold")
            )
        self.theme.tag_configure(
            self.summary_text,
            "kotlin",
            foreground=Color.KOTLIN_TEXT,
            font=(self.mono_font, 10, "bold"),
        )
        kotlin_section = False
        preparation_section = False
        for line in result.to_text().splitlines(keepends=True):
            stripped = line.strip()
            tag = None
            for severity in SEVERITY_COLORS:
                if stripped.startswith(f"[{severity.upper()}]"):
                    tag = severity
                    break
            if stripped == "Kotlin-файлы:":
                kotlin_section = True
                tag = "kotlin"
            elif kotlin_section and not stripped:
                kotlin_section = False
            elif kotlin_section:
                tag = "kotlin"
            if stripped == "Рекомендация по подготовке:":
                preparation_section = True
                tag = "medium"
            elif preparation_section and not stripped:
                preparation_section = False
            elif preparation_section:
                tag = "medium"
            self.summary_text.insert("end", line, tag or ())
        self.theme.configure(self.summary_text, state="disabled")

    def _populate_kotlin_mapping(self, result):
        self.kotlin_tree.delete(*self.kotlin_tree.get_children())
        mapping = extract_kotlin_mapping(result)
        self.kotlin_coverage_var.set(coverage_text(mapping.coverage))
        if mapping.records or mapping.invalid_classes:
            tags = {"confirmed": "matched", "missing": "missing_main", "not_applicable": "ignored"}
            for row in kotlin_table_rows(mapping):
                status = row["status"]
                tag = (
                    "missing_test"
                    if status == "missing" and row["test"]
                    else tags.get(status, status)
                )
                self.kotlin_tree.insert(
                    "",
                    "end",
                    values=(
                        STATUS_LABELS.get(status, status),
                        row["source"],
                        row["declaration"],
                        row["expected"],
                        ", ".join(row["classes"]),
                        row["context"],
                        row["reason"],
                    ),
                    tags=(tag,),
                )
            for path in mapping.orphan_kt_classes:
                self.kotlin_tree.insert(
                    "",
                    "end",
                    values=(
                        "БЕЗ ИСХОДНИКА",
                        path,
                        "",
                        "",
                        path,
                        "",
                        "Kotlin-байткод без сопоставленного исходника",
                    ),
                    tags=("orphan",),
                )
            self.notebook.tab(
                self.kotlin_tree.master,
                text="Kotlin ↔ .class · "
                + percent(mapping.coverage.get("estimated_percent"), approximate=True),
            )
            return mapping

        if not mapping.available:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("НЕДОСТУПНО", "Анализатор сопоставления", "Результат не получен"),
                tags=("unavailable",),
            )
        for source in mapping.unmatched_main:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("НЕТ .CLASS", source, expected_class_names(source)),
                tags=("missing_main",),
            )
        for source in mapping.unmatched_test:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("НЕТ .CLASS · ТЕСТ", source, expected_class_names(source)),
                tags=("missing_test",),
            )
        for match in mapping.matched:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("НАЙДЕН", match.source, ", ".join(match.class_files)),
                tags=("matched",),
            )
        for class_file in mapping.orphan_kt_classes:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("БЕЗ .KT", class_file, "Kotlin-подобный .class без исходника"),
                tags=("orphan",),
            )
        for script in mapping.ignored_scripts:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("ИСКЛЮЧЁН", script, "Gradle-скрипт не обязан иметь .class"),
                tags=("ignored",),
            )
        if mapping.available and not result.kotlin_files and not mapping.orphan_kt_classes:
            self.kotlin_tree.insert(
                "",
                "end",
                values=("НЕТ ДАННЫХ", "Kotlin-файлы не обнаружены", "Сопоставление не требуется"),
                tags=("ignored",),
            )

        self.notebook.tab(
            self.kotlin_tree.master,
            text=f"Kotlin ↔ .class ({mapping.issue_count})",
        )
        return mapping

    def _populate_findings(self, findings: list[Finding]) -> None:
        self.findings_tree.delete(*self.findings_tree.get_children())
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        labels = {
            "critical": "КРИТИЧНО",
            "high": "ВЫСОКИЙ",
            "medium": "СРЕДНИЙ",
            "low": "НИЗКИЙ",
            "info": "ИНФО",
        }
        highest = "info"
        if findings:
            highest = min(
                (item.severity for item in findings), key=lambda value: order.get(value, 5)
            )
        highest = highest if highest in SEVERITY_COLORS else "info"
        self.theme.configure(
            self.metric_findings, fg=SEVERITY_COLORS[highest][1] if findings else SUCCESS
        )
        for finding in sorted(findings, key=lambda item: order.get(item.severity, 5)):
            severity = finding.severity if finding.severity in SEVERITY_COLORS else "info"
            title = finding.title
            if finding.details:
                title += " — " + " | ".join(finding.details)
            self.findings_tree.insert(
                "", "end", values=(labels[severity], finding.category, title), tags=(severity,)
            )
        self.notebook.tab(self.findings_tree.master, text=f"Находки ({len(findings)})")

    def _populate_attention(self, result) -> None:
        self.attention_tree.delete(*self.attention_tree.get_children())
        attention = set(result.attention_files)
        kotlin = set(result.kotlin_files)
        remaining = set(result.remaining_archives)
        expanded = set(result.expanded_archives)
        paths = attention | kotlin | remaining | expanded
        grouped: dict[str, tuple[object, list[tuple[str, str]]]] = {}
        for path in sorted(paths, key=str.lower):
            style = KOTLIN_STYLE if path in kotlin else classify_attention(path) or ARCHIVE_STYLE
            if path in kotlin:
                state = "Kotlin-исходник обнаружен"
            elif path in expanded and path in remaining:
                state = "Распакован; исходный контейнер сохранён"
            elif path in expanded:
                state = "Распакован в рабочей области"
            elif path in remaining:
                state = "Остался архивом в рабочем наборе"
            else:
                state = "Обнаружен — требуется контроль"
            grouped.setdefault(style.key, (style, []))[1].append((path, state))
        group_order = {
            "package": 0,
            "executable": 1,
            "application_container": 2,
            "third_party_archive": 3,
            "kotlin": 4,
            "archive": 5,
        }
        for style, items in sorted(
            grouped.values(), key=lambda value: group_order.get(value[0].key, 99)
        ):
            shown = items[:MAX_VISIBLE_ITEMS]
            for index, (path, state) in enumerate(shown):
                group = f"{style.label} ({len(items)})" if index == 0 else ""
                self.attention_tree.insert(
                    "", "end", values=(group, path, state), tags=(style.key,)
                )
            if len(items) > len(shown):
                self.attention_tree.insert(
                    "",
                    "end",
                    values=("", f"… и ещё {len(items) - len(shown)}", "Полный список в отчёте"),
                    tags=(style.key,),
                )
        self.notebook.tab(self.attention_tree.master, text=f"Контроль файлов ({len(paths)})")

    def _populate_extensions(self, values: dict[str, int]) -> None:
        self.extensions_tree.delete(*self.extensions_tree.get_children())
        for extension, count in sorted(values.items(), key=lambda item: (-item[1], item[0])):
            style = classify_highlight(extension)
            if style is None and extension in SUPPORTED_EXTENSIONS:
                style = ARCHIVE_STYLE
            tags = (style.key,) if style else ()
            self.extensions_tree.insert(
                "", "end", values=(extension or "[без расширения]", count), tags=tags
            )

    def _package_completed(self, result) -> None:
        self._set_status("Новый 7Z создан и проверен", "ready")
        self._log(f"Готово: {result.output_path}")
        self._log(f"SHA-256: {result.sha256}")
        messagebox.showinfo(
            "7Z готов",
            f"Новый архив создан и проверен.\n\n{result.output_path}\n"
            f"Размер: {self._format_size(result.size)}\nSHA-256: {result.sha256}",
            parent=self.root,
        )

    def _new_task(self) -> None:
        if self.busy_kind or not self._discard_current():
            return
        self.source = None
        self.path_var.set("Архив или папка не выбраны")
        self._clear_results(clear_log=True)
        self._set_status("Готов к следующему заданию", "ready")
        self._refresh_controls()

    def _discard_current(self) -> bool:
        if not self.session:
            return True
        if not self.session.output_archive and not messagebox.askyesno(
            "Завершить текущее задание?",
            "Подготовленный 7Z ещё не создан. Очистить временные файлы?",
            parent=self.root,
        ):
            return False
        self.workflow.cleanup(self.session)
        self.session = None
        return True

    def _cancel(self) -> None:
        if self.busy_kind:
            self.cancel_event.set()
            self._set_status("Отмена операции…", "busy")

    def _open_workspace(self) -> None:
        if self.session and self.session.content_root.is_dir():
            os.startfile(self.session.content_root)

    def _open_output(self) -> None:
        if self.session and self.session.output_archive and self.session.output_archive.exists():
            os.startfile(self.session.output_archive)

    def _show_kotlin_report(self) -> None:
        if not self.session or not self.session.result:
            messagebox.showinfo(
                "Kotlin ↔ .class",
                "Сначала завершите анализ архива или папки.",
                parent=self.root,
            )
            return
        self.notebook.select(self.kotlin_tree.master)

    def _save_kotlin_report(self, report_format: str = "html") -> None:
        if self.busy_kind:
            return
        if not self.session or not self.session.result:
            messagebox.showinfo(
                "Kotlin-отчёт",
                "Сначала завершите анализ архива или папки.",
                parent=self.root,
            )
            return

        source = self.session.source_path
        base = source.name if self.session.source_is_directory else strip_archive_extension(source)
        full = report_format == "full_txt"
        extension = ".html" if report_format == "html" else ".txt"
        description = "Полное заключение" if full else "Отчёт Kotlin ↔ .class"
        filename = f"{base or 'PaxoInsight'}_{'Report' if full else 'Kotlin_Report'}{extension}"
        value = filedialog.asksaveasfilename(
            parent=self.root,
            title=f"Сохранить: {description}",
            initialdir=str(source.parent),
            initialfile=filename,
            defaultextension=extension,
            filetypes=[("HTML-страница", "*.html")]
            if extension == ".html"
            else [("Текстовый отчёт UTF-8", "*.txt")],
        )
        if not value:
            return
        try:
            exporter = (
                save_text_report
                if full
                else save_kotlin_html_report
                if extension == ".html"
                else save_kotlin_text_report
            )
            destination = exporter(self.session.result, value)
        except OSError as error:
            self._set_status(f"Не удалось сохранить Kotlin-отчёт: {error}", "error")
            messagebox.showerror(
                "Ошибка сохранения отчёта",
                str(error),
                parent=self.root,
            )
            return
        label = "HTML" if extension == ".html" else "TXT"
        self._set_status(f"Сохранён отчёт: {description} ({label})", "ready")
        self._log(f"{description} ({label}): {destination}")
        messagebox.showinfo(
            "Отчёт сохранён",
            f"{description} ({label}):\n\n{destination}",
            parent=self.root,
        )

    def _refresh_controls(self) -> None:
        busy = self.busy_kind is not None
        has_session = bool(self.session and self.session.content_root.is_dir())
        analyzed = bool(self.session and self.session.result)
        packaged = bool(self.session and self.session.output_archive)
        source_exists = bool(self.source and self.source.exists())
        scan_enabled = not busy and (source_exists or has_session)
        package_enabled = analyzed and not busy
        self.theme.configure(
            self.scan_button, text="Повторить анализ" if has_session else "Запустить анализ"
        )
        self._style_action_button(self.scan_button, primary=not analyzed, enabled=scan_enabled)
        self._state(self.cancel_button, busy)
        self._style_action_button(self.package_button, primary=analyzed, enabled=package_enabled)
        self._state(self.new_button, not busy and bool(self.source or self.session))
        self._state(self.workspace_button, analyzed and not busy)
        self._state(self.output_button, packaged and not busy)
        report_state = "normal" if analyzed and not busy else "disabled"
        for index in (0, 2, 3, 4):
            self.report_menu.entryconfigure(index, state=report_state)
        for widget in (
            self.archive_button,
            self.folder_button,
            self.expand_check,
            self.replace_check,
            self.container_check,
            self.report_check,
            self.depth_spin,
        ):
            self._state(widget, not busy)
        source_is_archive = bool(self.source and self.source.is_file())
        self._state(self.delete_check, not busy and not has_session and source_is_archive)

    def _style_action_button(self, button: tk.Button, primary: bool, enabled: bool) -> None:
        if not enabled:
            self.theme.configure(
                button,
                state="disabled",
                bg=Color.DISABLED,
                fg=Color.DISABLED_TEXT,
                disabledforeground=Color.DISABLED_TEXT,
                activebackground=Color.DISABLED,
                activeforeground=Color.DISABLED_TEXT,
            )
        elif primary:
            self.theme.configure(
                button,
                state="normal",
                bg=BRAND_BLUE,
                fg=Color.ON_ACCENT,
                activebackground=Color.ACCENT_HOVER,
                activeforeground=Color.ON_ACCENT,
            )
        else:
            self.theme.configure(
                button,
                state="normal",
                bg=Color.SUBTLE,
                fg=NAVY,
                activebackground=Color.SUBTLE_HOVER,
                activeforeground=NAVY,
            )

    def _state(self, widget: tk.Widget, enabled: bool) -> None:
        self.theme.configure(widget, state="normal" if enabled else "disabled")

    def _clear_results(self, clear_log: bool) -> None:
        metrics = (
            self.metric_files,
            self.metric_size,
            self.metric_score,
            self.metric_findings,
        )
        for metric in metrics:
            self.theme.configure(metric, text="—", fg=NAVY)
        self.theme.configure(self.sast_label, text="SAST: —")
        self.theme.configure(self.preparation_hint, text="")
        self.preparation_hint.grid_remove()
        for text in (self.summary_text,):
            self.theme.configure(text, state="normal")
            text.delete("1.0", "end")
            self.theme.configure(text, state="disabled")
        for tree in (
            self.kotlin_tree,
            self.findings_tree,
            self.attention_tree,
            self.extensions_tree,
        ):
            tree.delete(*tree.get_children())
        self.notebook.tab(self.kotlin_tree.master, text="Kotlin ↔ .class")
        self.kotlin_coverage_var.set("Покрытие Kotlin/JVM: н/д — анализ не выполнен")
        self.notebook.tab(self.findings_tree.master, text="Находки")
        self.notebook.tab(self.attention_tree.master, text="Контроль файлов")
        self.progress["value"] = 0
        if clear_log:
            self.theme.configure(self.log_text, state="normal")
            self.log_text.delete("1.0", "end")
            self.theme.configure(self.log_text, state="disabled")

    def _set_status(self, text: str, kind: str) -> None:
        styles = {
            "ready": (SUCCESS, "ГОТОВО", Color.SUCCESS_BG, Color.SUCCESS_TEXT),
            "busy": (BRAND_BLUE, "В РАБОТЕ", Color.INFO_BG, Color.INFO_TEXT),
            "warning": (WARNING, "ВНИМАНИЕ", Color.WARNING_BG, Color.WARNING_TEXT),
            "error": (DANGER, "ОШИБКА", Color.DANGER_BG, Color.DANGER_TEXT),
        }
        color, label, badge_bg, badge_fg = styles.get(kind, styles["ready"])
        self.status_var.set(text)
        self.theme.configure(self.status_label, fg=TEXT_PRIMARY)
        self.theme.configure(self.status_dot, fg=color)
        self.theme.configure(self.status_badge, text=label, bg=badge_bg, fg=badge_fg)

    def _log(self, text: str) -> None:
        self.theme.configure(self.log_text, state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.theme.configure(self.log_text, state="disabled")

    def _show_about(self) -> None:
        seven_zip = self.workflow.archives.seven_zip_executable
        rar_status = str(seven_zip) if seven_zip else "не найден"
        dialog = self.theme.widget(tk.Toplevel, self.root)
        dialog.title(f"О программе {APP_NAME}")
        dialog.geometry("700x690")
        dialog.resizable(False, False)
        self.theme.configure(dialog, bg=WHITE)
        dialog.transient(self.root)
        if self.icon_image is not None:
            dialog.iconphoto(True, self.icon_image)

        hero = self.theme.widget(tk.Frame, dialog, bg=WHITE, padx=28, pady=20)
        hero.pack(fill="x")
        if self.logo_image is not None:
            AdaptiveLogo(hero, self.logo_image, self.theme, self.ui_font).pack(anchor="w")
        else:
            self.theme.widget(
                tk.Label,
                hero,
                text=APP_NAME,
                bg=WHITE,
                fg=NAVY,
                font=(self.ui_font, 24, "bold"),
            ).pack(anchor="w")
        self.theme.widget(
            tk.Label,
            hero,
            text=f"Версия {VERSION} · самостоятельное приложение",
            bg=WHITE,
            fg=BRAND_BLUE,
            font=(self.ui_font, 10, "bold"),
        ).pack(anchor="w", pady=(4, 0))

        self.theme.widget(tk.Frame, dialog, bg=NAVY, height=4).pack(fill="x")
        about_tabs = ttk.Notebook(dialog)
        about_tabs.pack(fill="both", expand=True, padx=24, pady=(18, 0))
        content = self.theme.widget(tk.Frame, about_tabs, bg=SURFACE, padx=22, pady=18)
        release = self.theme.widget(tk.Frame, about_tabs, bg=SURFACE, padx=22, pady=18)
        about_tabs.add(content, text="О программе")
        about_tabs.add(release, text=f"Релиз {VERSION}")
        self.theme.widget(
            tk.Label,
            content,
            text="Что делает PaxoInsight",
            bg=SURFACE,
            fg=NAVY,
            font=(self.ui_font, 13, "bold"),
        ).pack(anchor="w")
        self.theme.widget(
            tk.Label,
            content,
            text=(
                "Анализирует переданные архивы и папки, раскрывает вложенные контейнеры, "
                "выделяет потенциально проблемные файлы и Kotlin-исходники, после чего "
                "по вашей команде собирает и проверяет новый архив 7Z."
            ),
            bg=SURFACE,
            fg=TEXT_PRIMARY,
            font=(self.ui_font, 10),
            justify="left",
            wraplength=585,
        ).pack(anchor="w", pady=(7, 16))
        self.theme.widget(
            tk.Label,
            content,
            text="Поддерживаемые форматы",
            bg=SURFACE,
            fg=NAVY,
            font=(self.ui_font, 11, "bold"),
        ).pack(anchor="w")
        self.theme.widget(
            tk.Label,
            content,
            text=(
                "ZIP, 7Z, RAR, TAR, TAR.GZ, TGZ, TAR.BZ2, TBZ2, TAR.XZ, TXZ, GZ, "
                "JAR, WAR, EAR, BAR, SAR, AAR, AAB, APK, IPA, EBA, CBA, ESA, "
                "APPZIP, LIBZIP, SHLIBZIP, APPDOMAINZIP и XSDZIP."
            ),
            bg=SURFACE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
            justify="left",
            wraplength=585,
        ).pack(anchor="w", pady=(6, 16))

        info = self.theme.widget(tk.Frame, content, bg=Color.SUBTLE, padx=13, pady=10)
        info.pack(fill="x")
        self.theme.widget(
            tk.Label,
            info,
            text="Локальная обработка",
            bg=Color.SUBTLE,
            fg=NAVY,
            font=(self.ui_font, 9, "bold"),
        ).pack(anchor="w")
        self.theme.widget(
            tk.Label,
            info,
            text=(
                "История и база данных не используются. Исходные папки не изменяются.\n"
                f"7-Zip для распаковки RAR: {rar_status}"
            ),
            bg=Color.SUBTLE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
            justify="left",
            wraplength=555,
        ).pack(anchor="w", pady=(3, 0))

        self.theme.widget(
            tk.Label,
            release,
            text=f"PaxoInsight {VERSION}",
            bg=SURFACE,
            fg=NAVY,
            font=(self.ui_font, 16, "bold"),
        ).pack(anchor="w")
        self.theme.widget(
            tk.Label,
            release,
            text=(
                "Самостоятельное приложение для подготовки "
                "программных архивов к последующему сканированию."
            ),
            bg=SURFACE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 10),
            justify="left",
            wraplength=610,
        ).pack(anchor="w", pady=(5, 16))

        release_card = self.theme.widget(
            tk.Frame,
            release,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
            padx=16,
            pady=13,
        )
        release_card.pack(fill="x")
        release_items = (
            "CPython 3.14.8 x64 и проверенные зависимости; усилен контроль распаковки.",
            "Структурное сопоставление Kotlin/JVM: объявления, пакеты, модули и Metadata.",
            "Оценочный и подтверждённый проценты; реальные пути классов и причины статусов.",
            "Kotlin HTML/TXT и полное заключение TXT — через меню «Отчёт».",
            "Светлая/тёмная темы и адаптивный логотип; выбор темы запоминается.",
            "Один индекс на задание, без базы и истории; сохранены RAR, TGZ и сборка 7Z.",
            "Процент отражает комплектность байткода, не SAST и не тождество исходников.",
        )
        for item in release_items:
            row = self.theme.widget(tk.Frame, release_card, bg=WHITE)
            row.pack(fill="x", pady=3)
            self.theme.widget(
                tk.Label,
                row,
                text="●",
                bg=WHITE,
                fg=BRAND_BLUE,
                font=(self.ui_font, 9, "bold"),
            ).pack(side="left", anchor="n", padx=(0, 8))
            self.theme.widget(
                tk.Label,
                row,
                text=item,
                bg=WHITE,
                fg=TEXT_PRIMARY,
                font=(self.ui_font, 9),
                justify="left",
                wraplength=550,
            ).pack(side="left", anchor="w")

        self.theme.widget(
            tk.Label,
            release,
            text="Совместимость: Windows x64 · CPython 3.14.8+ · 7-Zip для архивов RAR",
            bg=Color.SUBTLE,
            fg=NAVY,
            font=(self.ui_font, 9, "bold"),
            padx=12,
            pady=9,
        ).pack(fill="x", pady=(16, 0))

        dialog_footer = self.theme.widget(tk.Frame, dialog, bg=WHITE, padx=28, pady=12)
        dialog_footer.pack(fill="x")

        close_button = self.theme.widget(
            tk.Button,
            dialog_footer,
            text="Закрыть",
            command=dialog.destroy,
            bg=BRAND_BLUE,
            fg=Color.ON_ACCENT,
            activebackground=Color.ACCENT_HOVER,
            activeforeground=Color.ON_ACCENT,
            relief="flat",
            bd=0,
            padx=24,
            pady=8,
            font=(self.ui_font, 10, "bold"),
            cursor="hand2",
        )
        close_button.pack(anchor="e")
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.grab_set()
        close_button.focus_set()

    def _close(self) -> None:
        if self.busy_kind:
            if messagebox.askyesno(
                "Операция выполняется",
                "Отменить операцию и закрыть приложение?",
                parent=self.root,
            ):
                self.closing = True
                self.cancel_event.set()
                self._set_status("Остановка операции…", "busy")
            return
        self._finish_close()

    def _finish_close(self) -> None:
        self.workflow.cleanup(self.session)
        self.root.destroy()

    @staticmethod
    def _format_size(value: int) -> str:
        size = float(value)
        for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
            if size < 1024 or unit == "ТБ":
                return f"{size:.1f} {unit}" if unit != "Б" else f"{int(size)} {unit}"
            size /= 1024
        return f"{value} Б"


def run_application() -> int:
    if TkinterDnD is not None:
        try:
            root = TkinterDnD.Tk()
        except tk.TclError:
            root = tk.Tk()
    else:
        root = tk.Tk()
    PaxoInsightWindow(root)
    root.mainloop()
    return 0
