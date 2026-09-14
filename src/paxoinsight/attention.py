from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .archive_service import APPLICATION_CONTAINER_EXTENSIONS


@dataclass(frozen=True, slots=True)
class AttentionStyle:
    key: str
    label: str
    reason: str
    level: str


INSTALLER_PACKAGE_EXTENSIONS = {
    ".rpm",
    ".deb",
    ".msi",
    ".msix",
    ".msixbundle",
    ".appx",
    ".appxbundle",
    ".appinstaller",
    ".cab",
    ".pkg",
    ".dmg",
    ".appimage",
    ".snap",
    ".flatpak",
    ".flatpakref",
    ".flatpakrepo",
    ".apk",
    ".apks",
    ".xapk",
    ".aab",
    ".ipa",
    ".xpi",
    ".xap",
    ".crx",
}

NATIVE_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".sys",
    ".ocx",
    ".scr",
    ".com",
    ".pif",
    ".cpl",
    ".so",
    ".dylib",
    ".bin",
    ".run",
}

THIRD_PARTY_ARCHIVE_EXTENSIONS = {
    ".xz",
    ".lzma",
    ".lz",
    ".bz2",
    ".zst",
    ".lz4",
    ".iso",
    ".cpio",
    ".ace",
    ".arj",
    ".z",
}

KOTLIN_EXTENSIONS = {".kt", ".kts"}

PACKAGE_STYLE = AttentionStyle(
    "package",
    "ПАКЕТ / УСТАНОВЩИК",
    "Исполняемый или устанавливаемый пакет — требует отдельной проверки",
    "high",
)
EXECUTABLE_STYLE = AttentionStyle(
    "executable",
    "ИСПОЛНЯЕМЫЙ ФАЙЛ",
    "Нативный исполняемый файл или библиотека",
    "high",
)
CONTAINER_STYLE = AttentionStyle(
    "application_container",
    "JAR-ПОДОБНЫЙ КОНТЕЙНЕР",
    "Прикладной ZIP/JAR-контейнер может содержать исполняемый код",
    "medium",
)
THIRD_PARTY_STYLE = AttentionStyle(
    "third_party_archive",
    "СТОРОННИЙ АРХИВ / ОБРАЗ",
    "Архив, образ или пакет внешнего формата",
    "low",
)
ARCHIVE_STYLE = AttentionStyle(
    "archive",
    "АРХИВ",
    "Архив обнаружен в рабочем наборе",
    "info",
)
KOTLIN_STYLE = AttentionStyle(
    "kotlin",
    "KOTLIN (.KT / .KTS)",
    "Исходный код Kotlin обнаружен внутри анализируемого содержимого",
    "info",
)


ATTENTION_EXTENSIONS = (
    INSTALLER_PACKAGE_EXTENSIONS
    | NATIVE_EXECUTABLE_EXTENSIONS
    | THIRD_PARTY_ARCHIVE_EXTENSIONS
    | APPLICATION_CONTAINER_EXTENSIONS
)


def attention_extension(path: str | Path) -> str:
    lower = str(path).lower()
    for extension in sorted(ATTENTION_EXTENSIONS, key=len, reverse=True):
        if lower.endswith(extension):
            return extension
    return Path(lower).suffix


def classify_attention(path: str | Path) -> AttentionStyle | None:
    extension = attention_extension(path)
    if extension in INSTALLER_PACKAGE_EXTENSIONS:
        return PACKAGE_STYLE
    if extension in NATIVE_EXECUTABLE_EXTENSIONS:
        return EXECUTABLE_STYLE
    if extension in APPLICATION_CONTAINER_EXTENSIONS:
        return CONTAINER_STYLE
    if extension in THIRD_PARTY_ARCHIVE_EXTENSIONS:
        return THIRD_PARTY_STYLE
    return None


def classify_highlight(path: str | Path) -> AttentionStyle | None:
    lower = str(path).lower()
    extension = lower if lower in KOTLIN_EXTENSIONS else Path(lower).suffix
    if extension in KOTLIN_EXTENSIONS:
        return KOTLIN_STYLE
    return classify_attention(path)
