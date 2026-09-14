from __future__ import annotations

from pathlib import Path
from threading import Event

from .analysis_service import AnalysisService
from .archive_service import ArchiveService
from .models import (
    AnalysisOptions,
    AnalysisResult,
    PackageResult,
    PasswordProvider,
    PreparedSession,
    ProgressCallback,
)


class WorkflowService:
    def __init__(self) -> None:
        self.archives = ArchiveService()
        self.analysis = AnalysisService()

    def scan(
        self,
        source: str | Path,
        options: AnalysisOptions,
        progress: ProgressCallback,
        cancelled: Event,
        password_provider: PasswordProvider | None = None,
    ) -> PreparedSession:
        session = self.archives.prepare(
            source, options, progress, cancelled, password_provider
        )
        try:
            result: AnalysisResult = self.analysis.analyze(session, progress, cancelled)
            session.result = result
            if options.delete_source_archive and not session.source_is_directory:
                progress(100, "Удаление исходного архива после успешного анализа")
                self.archives.finalize_source_deletion(session)
            else:
                progress(100, "Анализ завершён — можно собирать 7Z")
            return session
        except Exception:
            self.archives.cleanup(session)
            raise

    def rescan(
        self,
        session: PreparedSession,
        options: AnalysisOptions,
        progress: ProgressCallback,
        cancelled: Event,
        password_provider: PasswordProvider | None = None,
    ) -> PreparedSession:
        self.archives.reprepare(
            session, options, progress, cancelled, password_provider
        )
        result: AnalysisResult = self.analysis.analyze(session, progress, cancelled)
        session.result = result
        progress(100, "Повторный анализ завершён — можно собирать 7Z")
        return session

    def package(
        self,
        session: PreparedSession,
        output: str | Path,
        include_report: bool,
        progress: ProgressCallback,
        cancelled: Event,
    ) -> PackageResult:
        return self.archives.package_7z(
            session, output, include_report, progress, cancelled
        )

    def cleanup(self, session: PreparedSession | None) -> None:
        self.archives.cleanup(session)
