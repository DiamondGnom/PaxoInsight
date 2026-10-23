"""Limits for untrusted metadata read by the bundled static analyzers."""

from __future__ import annotations

import io
from pathlib import Path
from threading import Event

from defusedxml import ElementTree

MAX_METADATA_BYTES = 8 * 1024**2


def read_limited(stream, limit: int = MAX_METADATA_BYTES):
    value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Файл метаданных превышает безопасный лимит анализа (8 МиБ)")
    return value


def parse_xml(path):
    with Path(path).open("rb") as stream:
        data = read_limited(stream)
    # Reject DTDs too, including documents which have not referenced an entity yet.
    return ElementTree.parse(
        io.BytesIO(data), forbid_dtd=True, forbid_entities=True, forbid_external=True
    )


def extract_legacy_archive(path: str, destination: str) -> None:
    # Keep legacy callers on the same path/link/size checks as the web workflow.
    from .archive_service import ArchiveService, archive_extension
    from .models import AnalysisOptions

    target = Path(destination)
    if target.exists() and any(target.iterdir()):
        raise ValueError("Для распаковки требуется пустая рабочая папка")
    target.mkdir(parents=True, exist_ok=True)
    service = ArchiveService()
    service._extract_with_password(
        Path(path), target, archive_extension(path), AnalysisOptions(), None, Event()
    )
