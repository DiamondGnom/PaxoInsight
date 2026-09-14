from __future__ import annotations

import os
import time
from pathlib import Path
from threading import Event
from typing import Any, Callable

from .archive_service import SUPPORTED_EXTENSIONS, archive_extension
from .attention import classify_attention
from .legacy_backend import load_legacy_backend
from .models import (
    AnalysisResult,
    Finding,
    OperationCancelled,
    PreparedSession,
    ProgressCallback,
    iso_now,
)


class AnalysisService:
    """Run each expensive analyzer once and retain its structured result."""

    def __init__(self) -> None:
        self._backend = load_legacy_backend()

    def analyze(
        self,
        session: PreparedSession,
        progress: ProgressCallback,
        cancelled: Event,
    ) -> AnalysisResult:
        started_at = iso_now()
        started = time.monotonic()
        root = session.content_root
        source = session.source_path

        progress(38, "Индексация файлов")
        inventory = self._build_inventory(root, cancelled)
        classes = inventory["classes"]
        kotlins = inventory["kotlins"]
        specials = inventory["specials"]
        third_party = inventory["third_party"]
        ext_counts = inventory["ext_counts"]
        remaining_archives = inventory["archives"]

        findings: list[Finding] = []
        analysis_data: dict[str, Any] = {}

        progress(44, "Проверка целостности комплекта")
        integrity = self._run(
            "integrity",
            lambda: self._backend._check_archive_integrity(
                str(root), classes, kotlins, specials, ext_counts
            ),
            analysis_data,
            findings,
        ) or {}
        for item in integrity.get("findings", []):
            findings.append(Finding.from_mapping(item))

        self._check_cancelled(cancelled)
        progress(52, "Определение режима SAST")
        recommendations = self._run(
            "appscreener",
            lambda: self._backend._generate_appscreener_recommendations(
                str(root), ext_counts, classes, kotlins, specials, integrity
            ),
            analysis_data,
            findings,
        ) or {}

        stages: list[tuple[int, str, str, Callable[[], Any]]] = [
            (
                58,
                "Анализ Kotlin и Java bytecode",
                "kotlin_mapping",
                lambda: self._backend._check_kotlin_class_mapping(classes, kotlins),
            ),
            (
                62,
                "Проверка версий bytecode",
                "bytecode_versions",
                lambda: self._backend._check_bytecode_versions(str(root), classes),
            ),
            (
                66,
                "Поиск подозрительных файлов",
                "suspicious_files",
                lambda: self._backend._detect_suspicious(str(root)),
            ),
            (
                70,
                "Анализ зависимостей и CVE",
                "dependencies",
                lambda: self._backend._extract_dependency_versions(str(root)),
            ),
            (
                74,
                "Поиск секретов",
                "secrets",
                lambda: self._backend._scan_secrets(str(root)),
            ),
            (
                78,
                "Определение фреймворков",
                "frameworks",
                lambda: self._backend._detect_frameworks(str(root)),
            ),
            (
                82,
                "Анализ Android-компонентов",
                "android_permissions",
                lambda: self._backend._extract_android_permissions(str(root)),
            ),
            (
                85,
                "Проверка цифровых подписей",
                "signatures",
                lambda: self._backend._check_signatures(str(root)),
            ),
            (
                88,
                "Поиск неиспользуемого кода",
                "dead_code",
                lambda: self._backend._detect_dead_code_enhanced(str(root), classes, kotlins),
            ),
        ]

        for percent, message, key, callback in stages:
            self._check_cancelled(cancelled)
            progress(percent, message)
            if key == "kotlin_mapping" and not (kotlins or classes):
                continue
            if key in {"bytecode_versions", "dead_code"} and not (classes or kotlins):
                continue
            analysis_data[key] = self._json_safe(
                self._run(key, callback, {}, findings)
            )

        dependencies = analysis_data.get("dependencies") or {}
        if dependencies:
            cves = self._run(
                "known_cves",
                lambda: self._backend._check_known_cves(dependencies),
                {},
                findings,
            ) or []
            analysis_data["known_cves"] = self._json_safe(cves)
            for cve in cves:
                findings.append(
                    Finding(
                        category="cve",
                        title=f"{cve.get('cve', 'CVE')}: {cve.get('artifact', '')} {cve.get('version', '')}".strip(),
                        severity=str(cve.get("severity", "high")).lower(),
                        details=[str(cve.get("description", "Известная уязвимость зависимости"))],
                    )
                )

        for item in analysis_data.get("suspicious_files") or []:
            findings.append(
                Finding(
                    category="suspicious",
                    title=str(item.get("detail") or item.get("type") or "Подозрительный файл"),
                    severity="medium",
                    details=[str(item.get("file", ""))],
                )
            )
        for item in analysis_data.get("secrets") or []:
            findings.append(
                Finding(
                    category="secret",
                    title=str(item.get("type") or "Возможный секрет"),
                    severity=str(item.get("severity") or "high").lower(),
                    details=[str(item.get("file") or item.get("detail") or "")],
                )
            )

        score = int(integrity.get("score", 100) or 0)
        verdict = str(integrity.get("verdict", "Нет данных"))
        sast_mode = str(recommendations.get("sast_mode", "Не определён"))
        sast_reason = str(recommendations.get("sast_reason", ""))
        kotlin_warnings = [str(item) for item in recommendations.get("kotlin_warnings", [])]

        finished_at = iso_now()
        result = AnalysisResult(
            source_path=str(source),
            source_name=source.name,
            source_size=session.source_size,
            source_sha256=session.source_sha256,
            workspace=str(root),
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=round(time.monotonic() - started, 3),
            total_files=int(inventory["total_files"]),
            total_bytes=int(inventory["total_bytes"]),
            extension_counts=ext_counts,
            class_files=classes,
            kotlin_files=kotlins,
            special_files=specials,
            third_party_archives=third_party,
            remaining_archives=remaining_archives,
            expanded_archives=list(session.expanded_archives),
            integrity_score=score,
            integrity_verdict=verdict,
            sast_mode=sast_mode,
            sast_reason=sast_reason,
            attention_files=inventory["attention_files"],
            findings=findings,
            kotlin_warnings=kotlin_warnings,
            analysis_data=self._json_safe(analysis_data),
        )
        session.result = result
        progress(98, "Анализ завершён")
        return result

    def _build_inventory(self, root: Path, cancelled: Event) -> dict[str, Any]:
        special_extensions = set(getattr(self._backend, "SPECIAL_EXTENSIONS", set()))
        third_party_extensions = set(
            getattr(self._backend, "THIRD_PARTY_ARCHIVE_EXTS", set())
        )
        classes: list[str] = []
        kotlins: list[str] = []
        specials: list[str] = []
        third_party: list[str] = []
        archives: list[str] = []
        attention_files: list[str] = []
        ext_counts: dict[str, int] = {}
        total_files = 0
        total_bytes = 0

        for current_root, directories, files in os.walk(root):
            self._check_cancelled(cancelled)
            directories[:] = [item for item in directories if item != "__MACOSX"]
            for filename in files:
                if filename.startswith("._"):
                    continue
                path = Path(current_root, filename)
                relative = path.relative_to(root).as_posix()
                lower = filename.lower()
                extension = archive_extension(filename)
                if extension not in SUPPORTED_EXTENSIONS:
                    extension = Path(lower).suffix
                ext_counts[extension] = ext_counts.get(extension, 0) + 1
                total_files += 1
                try:
                    total_bytes += path.stat().st_size
                except OSError:
                    pass
                if lower.endswith(".class"):
                    classes.append(relative)
                if lower.endswith((".kt", ".kts")):
                    kotlins.append(relative)
                if extension in special_extensions:
                    specials.append(relative)
                if extension in third_party_extensions:
                    third_party.append(relative)
                if extension in SUPPORTED_EXTENSIONS:
                    archives.append(relative)
                if classify_attention(relative):
                    attention_files.append(relative)

        return {
            "classes": sorted(classes),
            "kotlins": sorted(kotlins),
            "specials": sorted(specials),
            "third_party": sorted(third_party),
            "archives": sorted(archives),
            "attention_files": sorted(attention_files),
            "ext_counts": dict(sorted(ext_counts.items())),
            "total_files": total_files,
            "total_bytes": total_bytes,
        }

    @staticmethod
    def _run(
        name: str,
        callback: Callable[[], Any],
        target: dict[str, Any],
        findings: list[Finding],
    ) -> Any:
        try:
            value = callback()
            if target is not None:
                target[name] = AnalysisService._json_safe(value)
            return value
        except Exception as error:
            findings.append(
                Finding(
                    category="analyzer_error",
                    title=f"Анализатор {name} завершился с ошибкой",
                    severity="low",
                    details=[str(error)],
                )
            )
            return None

    @staticmethod
    def _json_safe(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): AnalysisService._json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [AnalysisService._json_safe(item) for item in value]
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    @staticmethod
    def _check_cancelled(cancelled: Event) -> None:
        if cancelled.is_set():
            raise OperationCancelled("Операция отменена")
