from __future__ import annotations

import dataclasses
import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Any, Callable

from . import VERSION


ProgressCallback = Callable[[int, str], None]
PasswordProvider = Callable[[Path, int, bool], str | None]


class OperationCancelled(RuntimeError):
    """Raised when the user cancels an active operation."""


class PasswordPromptCancelled(OperationCancelled):
    """Raised when the password dialog is cancelled."""


@dataclass(frozen=True, slots=True)
class AnalysisOptions:
    expand_nested: bool = True
    replace_nested_archives: bool = True
    delete_source_archive: bool = True
    unpack_application_containers: bool = False
    max_depth: int = 5
    max_files: int = 300_000
    max_unpacked_bytes: int = 50 * 1024**3


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    severity: str = "info"
    details: list[str] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "Finding":
        details = value.get("details", [])
        if isinstance(details, str):
            details = [details]
        return cls(
            category=str(value.get("group") or value.get("category") or "analysis"),
            title=str(value.get("title") or value.get("detail") or "Находка"),
            severity=str(value.get("severity") or "info").lower(),
            details=[str(item) for item in details],
        )


@dataclass(slots=True)
class AnalysisResult:
    source_path: str
    source_name: str
    source_size: int
    source_sha256: str
    workspace: str
    started_at: str
    finished_at: str
    duration_seconds: float
    total_files: int
    total_bytes: int
    extension_counts: dict[str, int]
    class_files: list[str]
    kotlin_files: list[str]
    special_files: list[str]
    third_party_archives: list[str]
    remaining_archives: list[str]
    expanded_archives: list[str]
    integrity_score: int
    integrity_verdict: str
    sast_mode: str
    sast_reason: str
    attention_files: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    kotlin_warnings: list[str] = field(default_factory=list)
    analysis_data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = dataclasses.asdict(self)
        value.pop("workspace", None)
        value["paxoinsight_version"] = VERSION
        return value

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str)

    def to_text(self) -> str:
        lines = [
            f"PaxoInsight {VERSION} — результат анализа",
            f"Источник: {self.source_name}",
            f"Путь: {self.source_path}",
            f"SHA-256: {self.source_sha256}",
            f"Размер источника: {self.source_size} байт",
            f"Начало: {self.started_at}",
            f"Завершение: {self.finished_at}",
            f"Длительность: {self.duration_seconds:.2f} сек.",
            "",
            f"Файлов: {self.total_files}",
            f"Объём распакованных данных: {self.total_bytes} байт",
            f".class: {len(self.class_files)}",
            f"Kotlin: {len(self.kotlin_files)}",
            f"Специальных файлов: {len(self.special_files)}",
            f"Оценка целостности: {self.integrity_score}/100",
            f"Вердикт: {self.integrity_verdict}",
            f"Режим SAST: {self.sast_mode}",
            f"Обоснование: {self.sast_reason}",
        ]
        if self.kotlin_warnings:
            lines.extend(["", "Предупреждения Kotlin:"])
            lines.extend(f"  - {item}" for item in self.kotlin_warnings)
        if self.kotlin_files:
            lines.extend(["", "Kotlin-файлы:"])
            lines.extend(f"  - {item}" for item in self.kotlin_files)
        if self.attention_files:
            lines.extend(["", "Файлы повышенного внимания:"])
            lines.extend(f"  - {item}" for item in self.attention_files)
        if self.findings:
            lines.extend(["", "Находки:"])
            for finding in self.findings:
                lines.append(f"  [{finding.severity.upper()}] {finding.title}")
                lines.extend(f"    - {detail}" for detail in finding.details)
        if self.extension_counts:
            lines.extend(["", "Расширения:"])
            for extension, count in sorted(
                self.extension_counts.items(), key=lambda item: (-item[1], item[0])
            ):
                lines.append(f"  {extension or '[без расширения]'}: {count}")
        return "\n".join(lines) + "\n"


@dataclass(slots=True)
class PreparedSession:
    source_path: Path
    session_root: Path
    content_root: Path
    options: AnalysisOptions
    source_is_directory: bool = False
    source_size: int = 0
    source_sha256: str = ""
    source_deleted: bool = False
    expanded_archives: list[str] = field(default_factory=list)
    result: AnalysisResult | None = None
    output_archive: Path | None = None


@dataclass(frozen=True, slots=True)
class PackageResult:
    output_path: str
    size: int
    sha256: str
    file_count: int
    verified: bool


@dataclass(slots=True)
class PasswordRequest:
    archive_path: Path
    attempt: int
    incorrect: bool
    resolved: Event = field(default_factory=Event)
    password: str | None = None

    def accept(self, password: str) -> None:
        self.password = password
        self.resolved.set()

    def reject(self) -> None:
        self.password = None
        self.resolved.set()


def iso_now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")
