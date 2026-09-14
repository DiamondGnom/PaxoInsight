from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
from contextlib import suppress
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from tkinter import font as tkfont

from .. import APP_NAME, VERSION
from ..archive_service import (
    APPLICATION_CONTAINER_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    archive_extension,
    strip_archive_extension,
)
from ..attention import ARCHIVE_STYLE, KOTLIN_STYLE, classify_attention, classify_highlight
from ..models import AnalysisOptions, Finding, OperationCancelled, PreparedSession
from ..reporting import (
    expected_class_names,
    extract_kotlin_mapping,
    save_kotlin_html_report,
)
from ..workflow import WorkflowService

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except (ImportError, OSError):
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

NAVY = "#0B2A5B"
BRAND_BLUE = "#0098FF"
CYAN = "#00D4FF"
TEXT_PRIMARY = "#0F172A"
TEXT_SECONDARY = "#64748B"
BORDER = "#E2E8F0"
SURFACE = "#F8FAFC"
WHITE = "#FFFFFF"
SUCCESS = "#22C55E"
WARNING = "#F59E0B"
DANGER = "#EF4444"

SEVERITY_COLORS = {
    "critical": ("#FEE2E2", "#B91C1C"),
    "high": ("#FFF7ED", "#C2410C"),
    "medium": ("#FFFBEB", "#B45309"),
    "low": ("#EFF6FF", "#1D4ED8"),
    "info": (SURFACE, "#475569"),
}
ATTENTION_COLORS = {
    "package": ("#FEE2E2", "#B91C1C"),
    "executable": ("#FEF2F2", "#DC2626"),
    "application_container": ("#FFFBEB", "#B45309"),
    "third_party_archive": (SURFACE, "#475569"),
    "kotlin": ("#F3E8FF", "#7E22CE"),
    "archive": ("#EFF6FF", "#1D4ED8"),
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
        self.root.configure(bg=SURFACE)

        installed_fonts = set(tkfont.families(self.root))
        self.ui_font = "Inter" if "Inter" in installed_fonts else "Segoe UI"
        self.mono_font = "JetBrains Mono" if "JetBrains Mono" in installed_fonts else "Consolas"
        self.icon_image: tk.PhotoImage | None = None
        self.logo_image: tk.PhotoImage | None = None
        self.header_logo_image: tk.PhotoImage | None = None
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
        except (OSError, tk.TclError):
            # The application stays usable even when a development checkout lacks assets.
            self.icon_image = None
            self.logo_image = None
            self.header_logo_image = None

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        with suppress(tk.TclError):
            style.theme_use("clam")
        style.configure("TFrame", background=SURFACE)
        style.configure("Card.TFrame", background=WHITE, relief="solid", borderwidth=1)
        style.configure(
            "Card.TLabelframe",
            background=WHITE,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
            padding=12,
        )
        style.configure(
            "Card.TLabelframe.Label",
            background=WHITE,
            foreground=NAVY,
            font=(self.ui_font, 10, "bold"),
        )
        style.configure(
            "TLabel",
            background=SURFACE,
            foreground=TEXT_PRIMARY,
            font=(self.ui_font, 10),
        )
        style.configure("Card.TLabel", background=WHITE, foreground=TEXT_PRIMARY)
        style.configure(
            "TButton",
            background=WHITE,
            foreground=NAVY,
            bordercolor=BORDER,
            focusthickness=1,
            focuscolor=BRAND_BLUE,
            font=(self.ui_font, 9),
            padding=(11, 7),
        )
        style.map(
            "TButton",
            background=[("active", "#EFF6FF"), ("disabled", "#F1F5F9")],
            foreground=[("disabled", "#94A3B8")],
        )
        style.configure(
            "TProgressbar",
            background=BRAND_BLUE,
            troughcolor="#EAF2FB",
            bordercolor="#EAF2FB",
            lightcolor=BRAND_BLUE,
            darkcolor=BRAND_BLUE,
        )
        style.configure(
            "Treeview",
            background=WHITE,
            fieldbackground=WHITE,
            foreground=TEXT_PRIMARY,
            bordercolor=BORDER,
            rowheight=27,
            font=(self.ui_font, 9),
        )
        style.map("Treeview", background=[("selected", NAVY)], foreground=[("selected", WHITE)])
        style.configure(
            "Treeview.Heading",
            background="#F1F5F9",
            foreground=NAVY,
            bordercolor=BORDER,
            font=(self.ui_font, 9, "bold"),
            padding=(7, 6),
        )
        style.map("Treeview.Heading", background=[("active", "#E2E8F0")])
        style.configure("TNotebook", background=SURFACE, bordercolor=BORDER)
        style.configure(
            "TNotebook.Tab",
            background="#EAF0F7",
            foreground=TEXT_SECONDARY,
            padding=(14, 8),
            font=(self.ui_font, 9, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", WHITE), ("active", "#F1F5F9")],
            foreground=[("selected", NAVY)],
        )

    def _build_menu(self) -> None:
        menu = tk.Menu(self.root)
        self.report_menu = tk.Menu(menu, tearoff=False)
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
        menu.add_cascade(label="Отчёт", menu=self.report_menu)
        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="О программе", command=self._show_about)
        menu.add_cascade(label="Справка", menu=help_menu)
        self.root.configure(menu=menu)

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg=WHITE, padx=24, pady=10)
        header.pack(fill="x")
        title_column = tk.Frame(header, bg=WHITE)
        title_column.pack(side="left", fill="x", expand=True)
        if self.header_logo_image is not None:
            tk.Label(title_column, image=self.header_logo_image, bg=WHITE, bd=0).pack(anchor="w")
        else:
            tk.Label(
                title_column,
                text=APP_NAME,
                bg=WHITE,
                fg=NAVY,
                font=(self.ui_font, 24, "bold"),
            ).pack(anchor="w")
        tk.Label(
            title_column,
            text="Анализ и подготовка архивов и папок для последующего сканирования",
            bg=WHITE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 10),
        ).pack(anchor="w", pady=(2, 0))
        version_box = tk.Frame(header, bg="#EFF6FF", padx=12, pady=8)
        version_box.pack(side="right", anchor="n", padx=(20, 0))
        tk.Label(
            version_box,
            text=f"v{VERSION}",
            bg="#EFF6FF",
            fg=NAVY,
            font=(self.ui_font, 10, "bold"),
        ).pack()
        tk.Label(
            version_box,
            text="standalone",
            bg="#EFF6FF",
            fg=BRAND_BLUE,
            font=(self.ui_font, 8),
        ).pack()
        tk.Frame(self.root, bg=NAVY, height=4).pack(fill="x")

        body = ttk.Frame(self.root, padding=(20, 16))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(1, weight=1)

        source_card = ttk.LabelFrame(body, text="Источник и подготовка", style="Card.TLabelframe")
        source_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 10))
        source_card.columnconfigure(0, weight=1)

        self.drop_frame = tk.Frame(
            source_card,
            bg="#F4F9FF",
            highlightbackground="#9CCEFF",
            highlightthickness=2,
            padx=16,
            pady=12,
        )
        self.drop_frame.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        tk.Label(
            self.drop_frame,
            text="Перетащите архив или папку сюда",
            bg="#F4F9FF",
            fg=NAVY,
            font=(self.ui_font, 12, "bold"),
        ).pack()
        self.path_label = tk.Label(
            self.drop_frame,
            textvariable=self.path_var,
            bg="#F4F9FF",
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
            wraplength=660,
        )
        self.path_label.pack(fill="x", pady=(3, 7))
        choose_row = tk.Frame(self.drop_frame, bg="#F4F9FF")
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

        options = tk.Frame(source_card, bg=WHITE)
        options.grid(row=1, column=0, sticky="ew")
        self.expand_check = tk.Checkbutton(
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
        self.replace_check = tk.Checkbutton(
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
        self.delete_check = tk.Checkbutton(
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
        self.container_check = tk.Checkbutton(
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
        tk.Label(
            options,
            text="Макс. глубина:",
            bg=WHITE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
        ).grid(
            row=3, column=1, sticky="e", padx=(12, 4)
        )
        self.depth_spin = tk.Spinbox(
            options, from_=1, to=10, textvariable=self.depth_var, width=4
        )
        self.depth_spin.grid(row=3, column=2, sticky="w")
        self.report_check = tk.Checkbutton(
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

        action_row = tk.Frame(source_card, bg=WHITE)
        action_row.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        action_row.columnconfigure(0, weight=1)
        action_row.columnconfigure(1, weight=1)
        self.scan_button = tk.Button(
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
        status_row = tk.Frame(state_card, bg=WHITE)
        status_row.grid(row=0, column=0, sticky="ew")
        status_row.columnconfigure(1, weight=1)
        self.status_dot = tk.Label(
            status_row,
            text="●",
            bg=WHITE,
            fg=SUCCESS,
            font=(self.ui_font, 13, "bold"),
        )
        self.status_dot.grid(row=0, column=0, sticky="n", padx=(0, 7))
        self.status_label = tk.Label(
            status_row,
            textvariable=self.status_var,
            bg=WHITE,
            fg=TEXT_PRIMARY,
            font=(self.ui_font, 10, "bold"),
            justify="left",
            wraplength=410,
        )
        self.status_label.grid(row=0, column=1, sticky="ew")
        self.status_badge = tk.Label(
            status_row,
            text="ГОТОВО",
            bg="#DCFCE7",
            fg="#15803D",
            font=(self.ui_font, 8, "bold"),
            padx=7,
            pady=3,
        )
        self.status_badge.grid(row=0, column=2, sticky="ne", padx=(8, 0))
        self.progress = ttk.Progressbar(state_card, maximum=100)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 10))
        metrics = tk.Frame(state_card, bg=WHITE)
        metrics.grid(row=2, column=0, sticky="nsew")
        for column in range(2):
            metrics.columnconfigure(column, weight=1)
        self.metric_files = self._metric(metrics, 0, 0, "файлов")
        self.metric_size = self._metric(metrics, 0, 1, "распаковано")
        self.metric_score = self._metric(metrics, 1, 0, "целостность")
        self.metric_findings = self._metric(metrics, 1, 1, "находок")
        self.sast_label = tk.Label(
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

        self.notebook = ttk.Notebook(body)
        self.notebook.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.summary_text = self._text_tab("Заключение")
        self.kotlin_tree = self._tree_tab(
            "Kotlin ↔ .class",
            ("mapping_status", "kotlin_source", "class_result"),
            (150, 470, 350),
        )
        self.findings_tree = self._tree_tab(
            "Находки", ("severity", "category", "title"), (110, 180, 620)
        )
        self.attention_tree = self._tree_tab(
            "Контроль файлов", ("group", "path", "state"), (210, 430, 330)
        )
        self.extensions_tree = self._tree_tab(
            "Состав", ("extension", "count"), (500, 130)
        )
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
        self.package_button = tk.Button(
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
        card = tk.Frame(parent, bg=WHITE, highlightbackground=BORDER, highlightthickness=1)
        card.grid(row=row, column=column, sticky="nsew", padx=4, pady=4)
        value = tk.Label(
            card, text="—", bg=WHITE, fg=NAVY, font=(self.ui_font, 17, "bold")
        )
        value.pack(anchor="w", padx=10, pady=(7, 0))
        tk.Label(
            card,
            text=caption,
            bg=WHITE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
        ).pack(
            anchor="w", padx=10, pady=(0, 7)
        )
        return value

    def _text_tab(self, title: str) -> tk.Text:
        frame = ttk.Frame(self.notebook)
        text = tk.Text(
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
        text.configure(yscrollcommand=scroll.set, state="disabled")
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
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        self.notebook.add(frame, text=title)
        return tree

    def _configure_tree_tags(self) -> None:
        for key, (background, foreground) in SEVERITY_COLORS.items():
            self.findings_tree.tag_configure(key, background=background, foreground=foreground)
        for tree in (self.attention_tree, self.extensions_tree):
            for key, (background, foreground) in ATTENTION_COLORS.items():
                tree.tag_configure(key, background=background, foreground=foreground)
        self.kotlin_tree.tag_configure("matched", background="#F0FDF4", foreground="#15803D")
        self.kotlin_tree.tag_configure("missing_main", background="#FEE2E2", foreground="#B91C1C")
        self.kotlin_tree.tag_configure("missing_test", background="#FEF3C7", foreground="#B45309")
        self.kotlin_tree.tag_configure("orphan", background="#EFF6FF", foreground="#1D4ED8")
        self.kotlin_tree.tag_configure("ignored", background=SURFACE, foreground=TEXT_SECONDARY)
        self.kotlin_tree.tag_configure("unavailable", background="#FEE2E2", foreground="#B91C1C")

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
        except (tk.TclError, ValueError):
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
        except (TypeError, ValueError, tk.TclError):
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
            response["password"] = simpledialog.askstring(
                title, prompt, show="*", parent=self.root
            )
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
        self.metric_files.configure(text=f"{result.total_files:,}".replace(",", " "))
        self.metric_size.configure(text=self._format_size(result.total_bytes))
        if result.integrity_score < 70:
            score_color = DANGER
        elif result.integrity_score < 90:
            score_color = WARNING
        else:
            score_color = SUCCESS
        self.metric_score.configure(text=f"{result.integrity_score}/100", fg=score_color)
        self.metric_findings.configure(text=str(len(result.findings)))
        self.sast_label.configure(text=f"SAST: {result.sast_mode}\n{result.sast_reason}")
        self._populate_summary(result)
        kotlin_mapping = self._populate_kotlin_mapping(result)
        self._populate_findings(result.findings)
        self._populate_attention(result)
        self._populate_extensions(result.extension_counts)

        remaining_containers = [
            path
            for path in result.remaining_archives
            if archive_extension(path) in APPLICATION_CONTAINER_EXTENSIONS
        ]
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

        if remaining_containers and not session.options.unpack_application_containers:
            self._set_status(
                "Обнаружены ZIP/JAR-контейнеры. Включите их распаковку и повторите анализ.",
                "warning",
            )
        elif kotlin_mapping.missing_count:
            self._set_status(
                "Анализ завершён. Kotlin-исходников без соответствующего .class: "
                f"{kotlin_mapping.missing_count}.",
                "warning",
            )
        elif kotlin_mapping.orphan_kt_classes:
            self._set_status(
                "Анализ завершён. Kotlin-подобных .class без исходника: "
                f"{len(kotlin_mapping.orphan_kt_classes)}.",
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
        self.summary_text.configure(state="normal")
        self.summary_text.delete("1.0", "end")
        for key, (_background, foreground) in SEVERITY_COLORS.items():
            self.summary_text.tag_configure(
                key, foreground=foreground, font=(self.mono_font, 10, "bold")
            )
        self.summary_text.tag_configure(
            "kotlin", foreground="#7E22CE", font=(self.mono_font, 10, "bold")
        )
        kotlin_section = False
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
            self.summary_text.insert("end", line, tag or ())
        self.summary_text.configure(state="disabled")

    def _populate_kotlin_mapping(self, result):
        self.kotlin_tree.delete(*self.kotlin_tree.get_children())
        mapping = extract_kotlin_mapping(result)

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
        self.metric_findings.configure(fg=SEVERITY_COLORS[highest][1] if findings else SUCCESS)
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

    def _save_kotlin_report(self) -> None:
        if not self.session or not self.session.result:
            messagebox.showinfo(
                "Kotlin-отчёт",
                "Сначала завершите анализ архива или папки.",
                parent=self.root,
            )
            return

        source = self.session.source_path
        base = source.name if self.session.source_is_directory else strip_archive_extension(source)
        filename = f"{base or 'PaxoInsight'}_Kotlin_Report.html"
        value = filedialog.asksaveasfilename(
            parent=self.root,
            title="Сохранить отчёт Kotlin ↔ .class",
            initialdir=str(source.parent),
            initialfile=filename,
            defaultextension=".html",
            filetypes=[("HTML-страница", "*.html"), ("Все файлы", "*.*")],
        )
        if not value:
            return
        try:
            destination = save_kotlin_html_report(self.session.result, value)
        except OSError as error:
            self._set_status(f"Не удалось сохранить Kotlin-отчёт: {error}", "error")
            messagebox.showerror(
                "Ошибка сохранения отчёта",
                str(error),
                parent=self.root,
            )
            return
        self._set_status("HTML-отчёт Kotlin ↔ .class сохранён", "ready")
        self._log(f"Kotlin HTML-отчёт: {destination}")
        messagebox.showinfo(
            "Kotlin-отчёт сохранён",
            f"HTML-страница создана:\n\n{destination}",
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
        self.scan_button.configure(text="Повторить анализ" if has_session else "Запустить анализ")
        self._style_action_button(self.scan_button, primary=not analyzed, enabled=scan_enabled)
        self._state(self.cancel_button, busy)
        self._style_action_button(self.package_button, primary=analyzed, enabled=package_enabled)
        self._state(self.new_button, not busy and bool(self.source or self.session))
        self._state(self.workspace_button, analyzed and not busy)
        self._state(self.output_button, packaged and not busy)
        report_state = "normal" if analyzed and not busy else "disabled"
        self.report_menu.entryconfigure(0, state=report_state)
        self.report_menu.entryconfigure(2, state=report_state)
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

    @staticmethod
    def _style_action_button(button: tk.Button, primary: bool, enabled: bool) -> None:
        if not enabled:
            button.configure(
                state="disabled",
                bg="#E2E8F0",
                fg="#94A3B8",
                disabledforeground="#94A3B8",
                activebackground="#E2E8F0",
                activeforeground="#94A3B8",
            )
        elif primary:
            button.configure(
                state="normal",
                bg=BRAND_BLUE,
                fg=WHITE,
                activebackground="#007FD6",
                activeforeground=WHITE,
            )
        else:
            button.configure(
                state="normal",
                bg="#EAF4FF",
                fg=NAVY,
                activebackground="#D7EBFF",
                activeforeground=NAVY,
            )

    @staticmethod
    def _state(widget: tk.Widget, enabled: bool) -> None:
        widget.configure(state="normal" if enabled else "disabled")

    def _clear_results(self, clear_log: bool) -> None:
        metrics = (
            self.metric_files,
            self.metric_size,
            self.metric_score,
            self.metric_findings,
        )
        for metric in metrics:
            metric.configure(text="—", fg=NAVY)
        self.sast_label.configure(text="SAST: —")
        for text in (self.summary_text,):
            text.configure(state="normal")
            text.delete("1.0", "end")
            text.configure(state="disabled")
        for tree in (
            self.kotlin_tree,
            self.findings_tree,
            self.attention_tree,
            self.extensions_tree,
        ):
            tree.delete(*tree.get_children())
        self.notebook.tab(self.kotlin_tree.master, text="Kotlin ↔ .class")
        self.notebook.tab(self.findings_tree.master, text="Находки")
        self.notebook.tab(self.attention_tree.master, text="Контроль файлов")
        self.progress["value"] = 0
        if clear_log:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")

    def _set_status(self, text: str, kind: str) -> None:
        styles = {
            "ready": (SUCCESS, "ГОТОВО", "#DCFCE7", "#15803D"),
            "busy": (BRAND_BLUE, "В РАБОТЕ", "#DBEAFE", "#1D4ED8"),
            "warning": (WARNING, "ВНИМАНИЕ", "#FEF3C7", "#B45309"),
            "error": (DANGER, "ОШИБКА", "#FEE2E2", "#B91C1C"),
        }
        color, label, badge_bg, badge_fg = styles.get(kind, styles["ready"])
        self.status_var.set(text)
        self.status_label.configure(fg=TEXT_PRIMARY)
        self.status_dot.configure(fg=color)
        self.status_badge.configure(text=label, bg=badge_bg, fg=badge_fg)

    def _log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _show_about(self) -> None:
        seven_zip = self.workflow.archives.seven_zip_executable
        rar_status = str(seven_zip) if seven_zip else "не найден"
        dialog = tk.Toplevel(self.root)
        dialog.title(f"О программе {APP_NAME}")
        dialog.geometry("700x690")
        dialog.resizable(False, False)
        dialog.configure(bg=WHITE)
        dialog.transient(self.root)
        if self.icon_image is not None:
            dialog.iconphoto(True, self.icon_image)

        hero = tk.Frame(dialog, bg=WHITE, padx=28, pady=20)
        hero.pack(fill="x")
        if self.logo_image is not None:
            tk.Label(hero, image=self.logo_image, bg=WHITE, bd=0).pack(anchor="w")
        else:
            tk.Label(
                hero,
                text=APP_NAME,
                bg=WHITE,
                fg=NAVY,
                font=(self.ui_font, 24, "bold"),
            ).pack(anchor="w")
        tk.Label(
            hero,
            text=f"Версия {VERSION} · самостоятельное приложение",
            bg=WHITE,
            fg=BRAND_BLUE,
            font=(self.ui_font, 10, "bold"),
        ).pack(anchor="w", pady=(4, 0))

        tk.Frame(dialog, bg=NAVY, height=4).pack(fill="x")
        about_tabs = ttk.Notebook(dialog)
        about_tabs.pack(fill="both", expand=True, padx=24, pady=(18, 0))
        content = tk.Frame(about_tabs, bg=SURFACE, padx=22, pady=18)
        release = tk.Frame(about_tabs, bg=SURFACE, padx=22, pady=18)
        about_tabs.add(content, text="О программе")
        about_tabs.add(release, text="Релиз 6.0")
        tk.Label(
            content,
            text="Что делает PaxoInsight",
            bg=SURFACE,
            fg=NAVY,
            font=(self.ui_font, 13, "bold"),
        ).pack(anchor="w")
        tk.Label(
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
        tk.Label(
            content,
            text="Поддерживаемые форматы",
            bg=SURFACE,
            fg=NAVY,
            font=(self.ui_font, 11, "bold"),
        ).pack(anchor="w")
        tk.Label(
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

        info = tk.Frame(content, bg="#EFF6FF", padx=13, pady=10)
        info.pack(fill="x")
        tk.Label(
            info,
            text="Локальная обработка",
            bg="#EFF6FF",
            fg=NAVY,
            font=(self.ui_font, 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            info,
            text=(
                "История и база данных не используются. Исходные папки не изменяются.\n"
                f"7-Zip для распаковки RAR: {rar_status}"
            ),
            bg="#EFF6FF",
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 9),
            justify="left",
            wraplength=555,
        ).pack(anchor="w", pady=(3, 0))

        tk.Label(
            release,
            text="PaxoInsight 6.0",
            bg=SURFACE,
            fg=NAVY,
            font=(self.ui_font, 16, "bold"),
        ).pack(anchor="w")
        tk.Label(
            release,
            text=(
                "Стабильный релиз самостоятельного приложения для подготовки "
                "программных архивов к последующему сканированию."
            ),
            bg=SURFACE,
            fg=TEXT_SECONDARY,
            font=(self.ui_font, 10),
            justify="left",
            wraplength=610,
        ).pack(anchor="w", pady=(5, 16))

        release_card = tk.Frame(
            release,
            bg=WHITE,
            highlightbackground=BORDER,
            highlightthickness=1,
            padx=16,
            pady=13,
        )
        release_card.pack(fill="x")
        release_items = (
            "Обновлённый дизайн.",
            "Добавлены новые форматы архивов и JAR-контейнеров.",
            "Обновлён механизм работы с текущим архивом.",
            "Выполнен переход на стабильный Python 3.14.",
        )
        for item in release_items:
            row = tk.Frame(release_card, bg=WHITE)
            row.pack(fill="x", pady=3)
            tk.Label(
                row,
                text="●",
                bg=WHITE,
                fg=BRAND_BLUE,
                font=(self.ui_font, 9, "bold"),
            ).pack(side="left", anchor="n", padx=(0, 8))
            tk.Label(
                row,
                text=item,
                bg=WHITE,
                fg=TEXT_PRIMARY,
                font=(self.ui_font, 9),
                justify="left",
                wraplength=550,
            ).pack(side="left", anchor="w")

        tk.Label(
            release,
            text="Совместимость: Windows x64 · CPython 3.14 · 7-Zip для архивов RAR",
            bg="#EFF6FF",
            fg=NAVY,
            font=(self.ui_font, 9, "bold"),
            padx=12,
            pady=9,
        ).pack(fill="x", pady=(16, 0))

        dialog_footer = tk.Frame(dialog, bg=WHITE, padx=28, pady=12)
        dialog_footer.pack(fill="x")

        close_button = tk.Button(
            dialog_footer,
            text="Закрыть",
            command=dialog.destroy,
            bg=BRAND_BLUE,
            fg=WHITE,
            activebackground="#007FD6",
            activeforeground=WHITE,
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
