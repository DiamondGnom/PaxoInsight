from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Any

from . import VERSION
from .models import AnalysisResult


@dataclass(frozen=True, slots=True)
class KotlinClassMatch:
    source: str
    class_files: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KotlinMappingSummary:
    available: bool
    matched: tuple[KotlinClassMatch, ...]
    unmatched_main: tuple[str, ...]
    unmatched_test: tuple[str, ...]
    orphan_kt_classes: tuple[str, ...]
    ignored_scripts: tuple[str, ...]

    @property
    def missing_count(self) -> int:
        return len(self.unmatched_main) + len(self.unmatched_test)

    @property
    def issue_count(self) -> int:
        return self.missing_count + len(self.orphan_kt_classes)

    @property
    def checked_source_count(self) -> int:
        return len(self.matched) + self.missing_count


def _unique_strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)):
        return ()
    return tuple(dict.fromkeys(str(item) for item in value if str(item).strip()))


def _is_test_source(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return any(
        marker in normalized
        for marker in ("/test/", "/test-", "/androidTest/", "/testFixtures/")
    )


def extract_kotlin_mapping(result: AnalysisResult) -> KotlinMappingSummary:
    raw = result.analysis_data.get("kotlin_mapping")
    has_mapping = isinstance(raw, dict)
    available = has_mapping or not (result.kotlin_files or result.class_files)
    data: dict[str, Any] = raw if has_mapping else {}

    matched: list[KotlinClassMatch] = []
    raw_matches = data.get("matched")
    if isinstance(raw_matches, (list, tuple)):
        for item in raw_matches:
            if not isinstance(item, dict):
                continue
            source = str(item.get("kt") or "").strip()
            if source:
                matched.append(
                    KotlinClassMatch(source, _unique_strings(item.get("classes")))
                )

    unmatched_main = _unique_strings(data.get("unmatched_main"))
    unmatched_test = _unique_strings(data.get("unmatched_test"))
    if not unmatched_main and not unmatched_test:
        unmatched = _unique_strings(data.get("unmatched_kt"))
        unmatched_main = tuple(path for path in unmatched if not _is_test_source(path))
        unmatched_test = tuple(path for path in unmatched if _is_test_source(path))

    ignored_scripts = tuple(
        path for path in result.kotlin_files if path.lower().endswith(".gradle.kts")
    )
    return KotlinMappingSummary(
        available=available,
        matched=tuple(matched),
        unmatched_main=unmatched_main,
        unmatched_test=unmatched_test,
        orphan_kt_classes=_unique_strings(data.get("orphan_kt_classes")),
        ignored_scripts=ignored_scripts,
    )


def expected_class_names(source: str) -> str:
    stem = Path(source.replace("\\", "/")).stem
    return f"{stem}.class или {stem}Kt.class"


def _path_rows(paths: tuple[str, ...], status: str, css_class: str) -> str:
    if not paths:
        return '<tr><td colspan="3" class="empty">Нет файлов</td></tr>'
    return "".join(
        "<tr>"
        f'<td><span class="badge {css_class}">{escape(status)}</span></td>'
        f"<td><code>{escape(path)}</code></td>"
        f"<td><code>{escape(expected_class_names(path))}</code></td>"
        "</tr>"
        for path in paths
    )


def _matched_rows(matches: tuple[KotlinClassMatch, ...]) -> str:
    if not matches:
        return '<tr><td colspan="3" class="empty">Нет сопоставлений</td></tr>'
    return "".join(
        "<tr>"
        '<td><span class="badge ok">НАЙДЕН</span></td>'
        f"<td><code>{escape(match.source)}</code></td>"
        f"<td><code>{escape(', '.join(match.class_files) or 'класс найден')}</code></td>"
        "</tr>"
        for match in matches
    )


def _orphan_rows(paths: tuple[str, ...]) -> str:
    if not paths:
        return '<tr><td colspan="2" class="empty">Нет файлов</td></tr>'
    return "".join(
        "<tr>"
        '<td><span class="badge info">БЕЗ ИСХОДНИКА</span></td>'
        f"<td><code>{escape(path)}</code></td>"
        "</tr>"
        for path in paths
    )


def build_kotlin_html_report(result: AnalysisResult) -> str:
    summary = extract_kotlin_mapping(result)
    availability = (
        "Сопоставление выполнено"
        if summary.available
        else "Сопоставление недоступно: анализатор не вернул результат"
    )
    main_rows = _path_rows(summary.unmatched_main, "НЕТ .CLASS", "danger")
    test_rows = _path_rows(summary.unmatched_test, "НЕТ .CLASS", "warning")
    matched_rows = _matched_rows(summary.matched)
    orphan_rows = _orphan_rows(summary.orphan_kt_classes)
    ignored = "".join(f"<li><code>{escape(path)}</code></li>" for path in summary.ignored_scripts)
    ignored_block = (
        f"<ul>{ignored}</ul>"
        if ignored
        else '<p class="empty standalone">Нет исключённых Gradle-скриптов</p>'
    )

    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PaxoInsight — Kotlin / .class</title>
  <style>
    :root {{ --navy:#0B2A5B; --blue:#0098FF; --text:#0F172A; --muted:#64748B;
      --border:#E2E8F0; --surface:#F8FAFC; --ok:#15803D; --warn:#B45309;
      --danger:#B91C1C; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--text); background:var(--surface);
      font:14px/1.5 Inter,Segoe UI,Arial,sans-serif; }}
    header {{ color:white; background:linear-gradient(120deg,var(--navy),#075A9C);
      padding:28px max(24px,calc((100% - 1180px)/2)); }}
    .brand {{ font-size:28px; font-weight:800; letter-spacing:-.5px; }}
    .brand span {{ color:#00D4FF; }}
    .subtitle {{ margin-top:4px; color:#D9EEFF; }}
    main {{ max-width:1180px; margin:24px auto; padding:0 20px 32px; }}
    .meta,.notice,.section {{ background:white; border:1px solid var(--border);
      border-radius:12px; box-shadow:0 2px 8px rgba(11,42,91,.05); }}
    .meta {{ display:grid; grid-template-columns:repeat(4,minmax(130px,1fr)); gap:1px;
      overflow:hidden; background:var(--border); }}
    .metric {{ background:white; padding:16px; }}
    .metric strong {{ display:block; color:var(--navy); font-size:24px; }}
    .metric span,.muted {{ color:var(--muted); }}
    .notice {{ margin-top:16px; padding:14px 16px; border-left:4px solid var(--blue); }}
    .section {{ margin-top:18px; overflow:hidden; }}
    h2 {{ margin:0; padding:16px 18px; color:var(--navy); font-size:17px;
      border-bottom:1px solid var(--border); }}
    table {{ width:100%; border-collapse:collapse; }}
    th,td {{ padding:10px 14px; text-align:left; vertical-align:top;
      border-bottom:1px solid var(--border); }}
    th {{ color:var(--navy); background:#F1F5F9; font-size:12px; }}
    tr:last-child td {{ border-bottom:0; }}
    code {{ overflow-wrap:anywhere; font-family:Consolas,monospace; }}
    .badge {{ display:inline-block; padding:3px 7px; border-radius:999px;
      font-size:11px; font-weight:800; white-space:nowrap; }}
    .ok {{ color:var(--ok); background:#DCFCE7; }}
    .warning {{ color:var(--warn); background:#FEF3C7; }}
    .danger {{ color:var(--danger); background:#FEE2E2; }}
    .info {{ color:#1D4ED8; background:#DBEAFE; }}
    .empty {{ color:var(--muted); text-align:center; }}
    .standalone {{ padding:0 18px 16px; text-align:left; }}
    ul {{ margin:0; padding:14px 36px 18px; }}
    footer {{ max-width:1180px; margin:0 auto; padding:0 20px 24px; color:var(--muted); }}
    @media(max-width:760px) {{ .meta {{ grid-template-columns:1fr 1fr; }}
      th:nth-child(3),td:nth-child(3) {{ display:none; }} }}
  </style>
</head>
<body>
<header>
  <div class="brand">Paxo<span>Insight</span></div>
  <div class="subtitle">Kotlin ↔ Java bytecode · версия {escape(VERSION)}</div>
</header>
<main>
  <h1>Отчёт сопоставления Kotlin и .class</h1>
  <p class="muted">Источник: <strong>{escape(result.source_name)}</strong><br>
    Анализ завершён: {escape(result.finished_at)} · {escape(availability)}</p>
  <div class="meta">
    <div class="metric"><strong>{len(result.kotlin_files)}</strong><span>Kotlin-файлов</span></div>
    <div class="metric"><strong>{len(summary.matched)}</strong><span>сопоставлено</span></div>
    <div class="metric"><strong>{summary.missing_count}</strong><span>без .class</span></div>
    <div class="metric">
      <strong>{len(summary.orphan_kt_classes)}</strong><span>.class без .kt</span>
    </div>
  </div>
  <div class="notice"><strong>Как читать результат.</strong> Для каждого Kotlin-исходника
    проверяются варианты <code>Name.class</code>, <code>NameKt.class</code> и вложенные
    <code>Name$*.class</code> с учётом стандартных каталогов Gradle. Отсутствие совпадения —
    повод для проверки, но не доказательство ошибки: имя может быть изменено аннотациями
    <code>@file:JvmName</code>, multifile-классами или нестандартной схемой сборки.</div>

  <section class="section">
    <h2>Основной код без соответствующего .class ({len(summary.unmatched_main)})</h2>
    <table><thead><tr><th>Статус</th><th>Kotlin-исходник</th><th>Ожидаемые имена</th></tr></thead>
      <tbody>{main_rows}</tbody></table></section>
  <section class="section">
    <h2>Тестовый код без соответствующего .class ({len(summary.unmatched_test)})</h2>
    <table><thead><tr><th>Статус</th><th>Kotlin-исходник</th><th>Ожидаемые имена</th></tr></thead>
      <tbody>{test_rows}</tbody></table></section>
  <section class="section"><h2>Успешные сопоставления ({len(summary.matched)})</h2>
    <table><thead><tr><th>Статус</th><th>Kotlin-исходник</th><th>Найденные .class</th></tr></thead>
      <tbody>{matched_rows}</tbody></table></section>
  <section class="section">
    <h2>Kotlin-подобные .class без исходника ({len(summary.orphan_kt_classes)})</h2>
    <table><thead><tr><th>Статус</th><th>.class</th></tr></thead>
      <tbody>{orphan_rows}</tbody></table></section>
  <section class="section"><h2>Исключённые Gradle-скрипты ({len(summary.ignored_scripts)})</h2>
    {ignored_block}</section>
</main>
<footer>
  PaxoInsight {escape(VERSION)} · отчёт создан локально, без сохранения истории в базе данных.
</footer>
</body>
</html>
"""


def save_kotlin_html_report(result: AnalysisResult, destination: str | Path) -> Path:
    path = Path(destination).expanduser().resolve()
    if path.suffix.lower() not in {".html", ".htm"}:
        path = path.with_suffix(".html")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(build_kotlin_html_report(result), encoding="utf-8")
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return path
