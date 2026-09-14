from __future__ import annotations

import gzip
import hashlib
import ntpath
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path, PurePosixPath
from threading import Event

from .legacy_backend import load_legacy_backend
from .models import (
    AnalysisOptions,
    OperationCancelled,
    PackageResult,
    PasswordPromptCancelled,
    PasswordProvider,
    PreparedSession,
    ProgressCallback,
)
from .reporting import build_kotlin_html_report

COMPOUND_EXTENSIONS = (".tar.gz", ".tar.bz2", ".tar.xz")
SUPPORTED_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".gz",
    ".jar",
    ".war",
    ".ear",
    ".bar",
    ".sar",
    ".aar",
    ".aab",
    ".apk",
    ".ipa",
    ".eba",
    ".cba",
    ".esa",
    ".appzip",
    ".libzip",
    ".shlibzip",
    ".appdomainzip",
    ".xsdzip",
}
APPLICATION_CONTAINER_EXTENSIONS = {
    ".jar",
    ".war",
    ".ear",
    ".bar",
    ".sar",
    ".aar",
    ".aab",
    ".apk",
    ".ipa",
    ".eba",
    ".cba",
    ".esa",
    ".appzip",
    ".libzip",
    ".shlibzip",
    ".appdomainzip",
    ".xsdzip",
}
ZIP_EXTENSIONS = {".zip", *APPLICATION_CONTAINER_EXTENSIONS}
TAR_EXTENSIONS = {".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"}
MARKER_NAME = ".paxoinsight-session"
MAX_PASSWORD_ATTEMPTS = 5


class ArchivePasswordRequired(RuntimeError):
    """An archive is encrypted or the supplied password is invalid."""


def archive_extension(path: str | Path) -> str:
    name = str(path).lower()
    for extension in COMPOUND_EXTENSIONS:
        if name.endswith(extension):
            return extension
    return Path(name).suffix.lower()


def strip_archive_extension(path: Path) -> str:
    name = path.name
    extension = archive_extension(path)
    if extension and name.lower().endswith(extension):
        return name[: -len(extension)]
    return path.stem


def find_7zip_executable() -> Path | None:
    """Find a local 7-Zip console executable without invoking a shell."""
    candidates: list[Path] = []

    for variable in ("PAXOINSIGHT_7ZIP", "PAXO_7Z_PATH"):
        override = os.environ.get(variable)
        if override:
            candidates.append(Path(override).expanduser())

    application_dir = Path(sys.executable).resolve().parent
    for name in ("7z.exe", "7za.exe", "7zr.exe", "7z"):
        candidates.extend((application_dir / name, application_dir / "bin" / name))
        discovered = shutil.which(name)
        if discovered:
            candidates.append(Path(discovered))

    if os.name == "nt":
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            program_files = os.environ.get(variable)
            if program_files:
                candidates.extend(
                    (
                        Path(program_files) / "7-Zip" / "7z.exe",
                        Path(program_files) / "7-Zip" / "7za.exe",
                    )
                )
        candidates.extend(
            (
                Path(r"C:\Program Files\7-Zip\7z.exe"),
                Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
            )
        )
        try:
            import winreg

            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for key_name in (r"SOFTWARE\7-Zip", r"SOFTWARE\7-Zip-Zstandard"):
                    try:
                        with winreg.OpenKey(hive, key_name) as key:
                            install_dir, _ = winreg.QueryValueEx(key, "Path")
                        candidates.append(Path(install_dir) / "7z.exe")
                    except OSError:
                        continue
        except ImportError:
            pass

    seen: set[str] = set()
    for candidate in candidates:
        normalized = os.path.normcase(os.path.abspath(candidate))
        if normalized in seen:
            continue
        seen.add(normalized)
        path = Path(normalized)
        if path.is_file():
            return path
    return None


class ArchiveService:
    def __init__(self) -> None:
        self._legacy = load_legacy_backend()
        self._py7zr = getattr(self._legacy, "py7zr", None)
        self._rarfile = getattr(self._legacy, "rarfile", None)
        self._seven_zip = find_7zip_executable()

    @property
    def seven_zip_executable(self) -> Path | None:
        return self._seven_zip

    def prepare(
        self,
        source: str | Path,
        options: AnalysisOptions,
        progress: ProgressCallback,
        cancelled: Event,
        password_provider: PasswordProvider | None = None,
    ) -> PreparedSession:
        source_path = Path(source).expanduser().resolve()
        source_is_directory = source_path.is_dir()
        if not source_is_directory and not source_path.is_file():
            raise FileNotFoundError(f"Источник не найден: {source_path}")
        extension = "" if source_is_directory else archive_extension(source_path)
        if not source_is_directory and extension not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Неподдерживаемый формат архива: {extension or source_path.name}"
            )

        session_root = Path(tempfile.mkdtemp(prefix="PaxoInsight-"))
        (session_root / MARKER_NAME).write_text("PaxoInsight 6 session\n", encoding="utf-8")
        content_root = session_root / "content"
        content_root.mkdir()
        session = PreparedSession(
            source_path,
            session_root,
            content_root,
            options,
            source_is_directory=source_is_directory,
        )

        try:
            self._check_cancelled(cancelled)
            if source_is_directory:
                progress(1, f"Копирование папки {source_path.name}")
                source_size, source_sha256 = self._copy_directory(
                    source_path,
                    content_root,
                    session_root,
                    options,
                    progress,
                    cancelled,
                )
                session.source_size = source_size
                session.source_sha256 = source_sha256
            else:
                session.source_size = source_path.stat().st_size
                progress(1, "Вычисление SHA-256 исходного архива")
                session.source_sha256 = self._sha256(source_path, cancelled)
                progress(4, f"Распаковка {source_path.name}")
                self._extract_with_password(
                    source_path,
                    content_root,
                    extension,
                    options,
                    password_provider,
                    cancelled,
                )
                self._enforce_limits(content_root, options)

            if options.expand_nested:
                self._expand_nested(
                    session, progress, cancelled, password_provider
                )

            self._enforce_limits(content_root, options)
            progress(
                35,
                "Подготовка папки завершена"
                if source_is_directory
                else "Распаковка завершена",
            )
            return session
        except Exception:
            self.cleanup(session)
            raise

    @staticmethod
    def finalize_source_deletion(session: PreparedSession) -> None:
        """Delete the source only after the complete analysis has succeeded."""
        if (
            session.source_is_directory
            or not session.options.delete_source_archive
            or session.source_deleted
        ):
            return
        if session.source_path.exists():
            session.source_path.unlink()
        session.source_deleted = True

    def cleanup(self, session: PreparedSession | None) -> None:
        if session is None:
            return
        root = session.session_root.resolve()
        temp_root = Path(tempfile.gettempdir()).resolve()
        try:
            allowed = root.parent == temp_root and root.name.startswith("PaxoInsight-")
            if allowed and (root / MARKER_NAME).is_file():
                shutil.rmtree(root)
        except OSError:
            # The OS can finish cleanup later if a preview still owns a handle.
            pass

    def reprepare(
        self,
        session: PreparedSession,
        options: AnalysisOptions,
        progress: ProgressCallback,
        cancelled: Event,
        password_provider: PasswordProvider | None = None,
    ) -> PreparedSession:
        if not session.content_root.is_dir() or not (
            session.session_root / MARKER_NAME
        ).is_file():
            raise RuntimeError("Рабочая область текущего задания недоступна")

        session.options = options
        session.result = None
        session.output_archive = None
        self._check_cancelled(cancelled)
        progress(4, "Повторная подготовка рабочей области")
        if options.expand_nested:
            self._expand_nested(session, progress, cancelled, password_provider)
        self._enforce_limits(session.content_root, options)
        progress(35, "Повторная подготовка завершена")
        return session

    def package_7z(
        self,
        session: PreparedSession,
        output_path: str | Path,
        include_report: bool,
        progress: ProgressCallback,
        cancelled: Event,
    ) -> PackageResult:
        if not session.result:
            raise RuntimeError("Сначала необходимо завершить анализ")
        if self._py7zr is None:
            raise RuntimeError("Компонент создания 7Z недоступен")

        content_root = session.content_root.resolve()
        if not content_root.is_dir():
            raise RuntimeError("Временная рабочая область уже удалена")

        destination = Path(output_path).expanduser().resolve()
        if destination.suffix.lower() != ".7z":
            destination = destination.with_suffix(".7z")
        if self._is_within(destination, content_root):
            raise ValueError("Выходной архив нельзя сохранить внутрь упаковываемой папки")
        destination.parent.mkdir(parents=True, exist_ok=True)
        partial = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.partial")

        entries = self._package_entries(content_root)
        file_count = sum(1 for item in entries if item.is_file())
        if not entries:
            raise RuntimeError("Рабочая область пуста — нечего упаковывать")

        try:
            progress(2, "Подготовка списка файлов")
            with self._py7zr.SevenZipFile(partial, mode="w") as archive:
                total = len(entries)
                for index, item in enumerate(entries, start=1):
                    self._check_cancelled(cancelled)
                    relative = item.relative_to(content_root).as_posix()
                    archive.write(item, arcname=relative)
                    percent = 5 + int(index / total * 80)
                    progress(percent, f"Упаковка: {relative}")
                if include_report:
                    archive.writestr(session.result.to_json(), "PaxoInsight_Report.json")
                    archive.writestr(session.result.to_text(), "PaxoInsight_Report.txt")
                    archive.writestr(
                        build_kotlin_html_report(session.result),
                        "PaxoInsight_Kotlin_Report.html",
                    )

            self._check_cancelled(cancelled)
            progress(90, "Проверка целостности нового 7Z")
            with self._py7zr.SevenZipFile(partial, mode="r") as archive:
                archive_names = set(archive.getnames())
                expected_names = {
                    item.relative_to(content_root).as_posix() for item in entries
                }
                if include_report:
                    expected_names.update(
                        {
                            "PaxoInsight_Report.json",
                            "PaxoInsight_Report.txt",
                            "PaxoInsight_Kotlin_Report.html",
                        }
                    )
                missing = expected_names.difference(archive_names)
                if missing:
                    preview = ", ".join(sorted(missing)[:5])
                    raise RuntimeError(f"Проверка 7Z не пройдена, отсутствуют записи: {preview}")
                if archive.test() is False:
                    raise RuntimeError("Проверка контрольных сумм 7Z не пройдена")
                damaged = archive.testzip()
                if damaged:
                    raise RuntimeError(f"Повреждённая запись в новом 7Z: {damaged}")

            progress(96, "Вычисление SHA-256")
            sha256 = self._sha256(partial, cancelled)
            size = partial.stat().st_size
            os.replace(partial, destination)
            session.output_archive = destination
            progress(100, "Новый архив создан и проверен")
            return PackageResult(str(destination), size, sha256, file_count, True)
        finally:
            try:
                if partial.exists():
                    partial.unlink()
            except OSError:
                pass

    def _expand_nested(
        self,
        session: PreparedSession,
        progress: ProgressCallback,
        cancelled: Event,
        password_provider: PasswordProvider | None,
    ) -> None:
        processed: set[Path] = set()
        for relative in session.expanded_archives:
            previous = session.content_root / Path(relative)
            if previous.is_file():
                processed.add(previous.resolve())
        for depth in range(session.options.max_depth):
            self._check_cancelled(cancelled)
            candidates = []
            for path in session.content_root.rglob("*"):
                if not path.is_file():
                    continue
                resolved = path.resolve()
                if resolved in processed:
                    continue
                extension = archive_extension(path)
                if extension not in SUPPORTED_EXTENSIONS:
                    continue
                if (
                    self._is_application_container(path, extension)
                    and not session.options.unpack_application_containers
                ):
                    continue
                candidates.append((path, extension))
            if not candidates:
                break

            for index, (nested, extension) in enumerate(candidates, start=1):
                self._check_cancelled(cancelled)
                processed.add(nested.resolve())
                relative = nested.relative_to(session.content_root).as_posix()
                progress(
                    8 + min(24, depth * 5 + int(index / len(candidates) * 5)),
                    f"Вложенный архив: {relative}",
                )
                target = self._unique_nested_target(nested)
                try:
                    target.mkdir(parents=True)
                    self._extract_with_password(
                        nested,
                        target,
                        extension,
                        session.options,
                        password_provider,
                        cancelled,
                    )
                    self._enforce_limits(session.content_root, session.options)
                    session.expanded_archives.append(relative)
                    if session.options.replace_nested_archives:
                        nested.unlink()
                except PasswordPromptCancelled:
                    shutil.rmtree(target, ignore_errors=True)
                    # Cancelling a nested password keeps that archive untouched.
                    continue
                except OperationCancelled:
                    shutil.rmtree(target, ignore_errors=True)
                    raise
                except Exception:
                    shutil.rmtree(target, ignore_errors=True)
                    # Damaged/password protected nested archives remain in the result.
                    continue

    def _extract_archive(
        self,
        source: Path,
        destination: Path,
        extension: str,
        options: AnalysisOptions,
        password: str | None = None,
    ) -> None:
        if extension in ZIP_EXTENSIONS:
            self._extract_zip(source, destination, options, password)
        elif extension in TAR_EXTENSIONS:
            self._extract_tar(source, destination, options)
        elif extension == ".7z":
            self._extract_7z(source, destination, options, password)
        elif extension == ".rar":
            # Jakarta/Java resource adapters also use .rar, but their actual
            # format is JAR/ZIP. A WinRAR archive keeps the 7-Zip route.
            if zipfile.is_zipfile(source):
                self._extract_zip(source, destination, options, password)
            else:
                self._extract_rar(source, destination, options, password)
        elif extension == ".gz":
            self._extract_gzip(source, destination, options)
        else:
            raise ValueError(f"Распаковка {extension} не поддерживается")

    def _extract_with_password(
        self,
        source: Path,
        destination: Path,
        extension: str,
        options: AnalysisOptions,
        password_provider: PasswordProvider | None,
        cancelled: Event,
    ) -> None:
        password: str | None = None
        attempts = 0
        while True:
            self._check_cancelled(cancelled)
            try:
                self._extract_archive(
                    source, destination, extension, options, password
                )
                return
            except Exception as error:
                if not self._is_password_error(error, password is not None):
                    raise
                self._reset_destination(destination)
                if password_provider is None:
                    raise RuntimeError(
                        f"Архив защищён паролем: {source.name}"
                    ) from error
                if attempts >= MAX_PASSWORD_ATTEMPTS:
                    raise RuntimeError(
                        f"Не удалось подобрать пароль за {MAX_PASSWORD_ATTEMPTS} попыток: "
                        f"{source.name}"
                    ) from error
                attempts += 1
                supplied = password_provider(source, attempts, password is not None)
                if supplied is None:
                    raise PasswordPromptCancelled(
                        f"Ввод пароля отменён: {source.name}"
                    ) from error
                password = supplied

    @staticmethod
    def _is_password_error(error: Exception, password_was_supplied: bool) -> bool:
        if isinstance(error, ArchivePasswordRequired):
            return True
        error_name = type(error).__name__.lower()
        message = str(error).lower()
        password_names = {
            "passwordrequired",
            "badpassword",
            "passworderror",
            "rarwrongpassword",
        }
        if error_name in password_names:
            return True
        markers = (
            "password",
            "пароль",
            "encrypted",
            "шифрован",
            "bad password",
            "wrong password",
        )
        if any(marker in message for marker in markers):
            return True
        # Encrypted 7Z archives commonly report a CRC/decompression error for
        # a wrong password after a password has already been supplied.
        return password_was_supplied and error_name in {
            "crcerror",
            "lzmaerror",
            "decompressionerror",
        }

    @staticmethod
    def _reset_destination(destination: Path) -> None:
        if destination.exists():
            shutil.rmtree(destination)
        destination.mkdir(parents=True, exist_ok=True)

    def _extract_zip(
        self,
        source: Path,
        destination: Path,
        options: AnalysisOptions,
        password: str | None,
    ) -> None:
        with zipfile.ZipFile(source, "r") as archive:
            infos = archive.infolist()
            self._check_member_totals(
                [(item.filename, item.file_size) for item in infos], options
            )
            if password is None and any(item.flag_bits & 0x1 for item in infos):
                raise ArchivePasswordRequired("ZIP защищён паролем")
            password_bytes = password.encode("utf-8") if password is not None else None
            for info in infos:
                target = self._safe_member_target(destination, info.filename)
                mode = (info.external_attr >> 16) & 0xFFFF
                if stat.S_ISLNK(mode):
                    raise ValueError(f"Символические ссылки запрещены: {info.filename}")
                if info.is_dir() or info.filename.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(
                    info, "r", pwd=password_bytes
                ) as source_stream, target.open("wb") as target_stream:
                    shutil.copyfileobj(source_stream, target_stream, 1024 * 1024)

    def _extract_tar(self, source: Path, destination: Path, options: AnalysisOptions) -> None:
        with tarfile.open(source, "r:*") as archive:
            members = archive.getmembers()
            self._check_member_totals(
                [(item.name, item.size) for item in members if item.isfile()], options
            )
            for member in members:
                self._safe_member_target(destination, member.name)
                if member.issym() or member.islnk() or member.isdev():
                    raise ValueError(f"Небезопасная запись TAR: {member.name}")
            archive.extractall(destination, members=members, filter="data")

    def _extract_7z(
        self,
        source: Path,
        destination: Path,
        options: AnalysisOptions,
        password: str | None,
    ) -> None:
        if self._py7zr is None:
            raise RuntimeError("Компонент распаковки 7Z недоступен")
        kwargs = {"mode": "r"}
        if password is not None:
            kwargs["password"] = password
        with self._py7zr.SevenZipFile(source, **kwargs) as archive:
            if archive.needs_password() and password is None:
                raise ArchivePasswordRequired("7Z защищён паролем")
            infos = archive.list()
            members: list[tuple[str, int]] = []
            for info in infos:
                name = str(getattr(info, "filename", ""))
                self._safe_member_target(destination, name)
                size = int(getattr(info, "uncompressed", 0) or 0)
                members.append((name, size))
                if bool(getattr(info, "is_symlink", False)):
                    raise ValueError(f"Символические ссылки запрещены: {name}")
            self._check_member_totals(members, options)
            archive.extractall(path=destination)

    def _extract_rar(
        self,
        source: Path,
        destination: Path,
        options: AnalysisOptions,
        password: str | None,
    ) -> None:
        if self._seven_zip is None:
            raise RuntimeError(
                "Для распаковки RAR не найден 7-Zip. Установите 7-Zip либо "
                "укажите путь к 7z.exe в переменной PAXOINSIGHT_7ZIP."
            )
        if self._rarfile is None:
            raise RuntimeError("Компонент проверки структуры RAR недоступен")

        encrypted = False
        with self._rarfile.RarFile(source) as archive:
            encrypted = archive.needs_password()
            if encrypted:
                if password is None:
                    raise ArchivePasswordRequired("RAR защищён паролем")
                archive.setpassword(password)
            infos = archive.infolist()
            self._check_member_totals(
                [(item.filename, item.file_size) for item in infos], options
            )
            for info in infos:
                self._safe_member_target(destination, info.filename)
                is_symlink = getattr(info, "is_symlink", lambda: False)()
                if is_symlink or getattr(info, "file_redir", None):
                    raise ValueError(
                        f"Ссылки внутри RAR запрещены: {info.filename}"
                    )

        destination.mkdir(parents=True, exist_ok=True)
        password_argument = f"-p{password}" if password is not None else "-p"
        command = [
            str(self._seven_zip),
            "x",
            "-y",
            "-aoa",
            "-bb0",
            "-bd",
            "-sccUTF-8",
            f"-o{destination}",
            password_argument,
            str(source),
        ]
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=1800,
                creationflags=creation_flags,
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"7-Zip превысил время ожидания при распаковке RAR: {source.name}"
            ) from error
        except OSError as error:
            raise RuntimeError(f"Не удалось запустить 7-Zip: {error}") from error

        if completed.returncode != 0:
            if encrypted:
                raise ArchivePasswordRequired("Неверный пароль для RAR")
            details = (completed.stderr or completed.stdout).strip()
            if len(details) > 1000:
                details = details[-1000:]
            raise RuntimeError(
                f"7-Zip не смог распаковать RAR (код {completed.returncode})"
                + (f":\n{details}" if details else "")
            )

    def _extract_gzip(self, source: Path, destination: Path, options: AnalysisOptions) -> None:
        target_name = source.stem or "content"
        target = self._safe_member_target(destination, target_name)
        target.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        with gzip.open(source, "rb") as source_stream, target.open("wb") as target_stream:
            while True:
                chunk = source_stream.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > options.max_unpacked_bytes:
                    raise ValueError("Превышен лимит распакованного объёма")
                target_stream.write(chunk)

    @staticmethod
    def _is_application_container(path: Path, extension: str) -> bool:
        return extension in APPLICATION_CONTAINER_EXTENSIONS or (
            extension == ".rar" and zipfile.is_zipfile(path)
        )

    @staticmethod
    def _safe_member_target(base: Path, member_name: str) -> Path:
        normalized = member_name.replace("\\", "/").replace("\r", "")
        pure = PurePosixPath(normalized)
        drive, _ = ntpath.splitdrive(normalized)
        invalid_part = any(
            part in {"", ".", ".."} or ":" in part for part in pure.parts
        )
        if drive or pure.is_absolute() or invalid_part:
            raise ValueError(f"Небезопасный путь в архиве: {member_name}")
        target = (base / Path(*pure.parts)).resolve()
        if not ArchiveService._is_within(target, base.resolve()):
            raise ValueError(f"Выход за пределы рабочей папки: {member_name}")
        return target

    @staticmethod
    def _is_within(candidate: Path, base: Path) -> bool:
        try:
            candidate.relative_to(base)
            return True
        except ValueError:
            return False

    @staticmethod
    def _check_member_totals(
        members: list[tuple[str, int]], options: AnalysisOptions
    ) -> None:
        if len(members) > options.max_files:
            raise ValueError(f"В архиве слишком много файлов: {len(members):,}")
        total = 0
        for name, size in members:
            if size < 0:
                raise ValueError(f"Некорректный размер записи: {name}")
            total += size
            if total > options.max_unpacked_bytes:
                raise ValueError("Архив превышает лимит распакованного объёма")

    @staticmethod
    def _enforce_limits(root: Path, options: AnalysisOptions) -> None:
        count = 0
        total = 0
        for current_root, directories, files in os.walk(root):
            directories[:] = [item for item in directories if not Path(current_root, item).is_symlink()]
            for filename in files:
                path = Path(current_root, filename)
                if path.is_symlink():
                    raise ValueError(f"Символические ссылки запрещены: {path}")
                count += 1
                total += path.stat().st_size
                if count > options.max_files:
                    raise ValueError("Превышен лимит количества распакованных файлов")
                if total > options.max_unpacked_bytes:
                    raise ValueError("Превышен лимит распакованного объёма")

    @staticmethod
    def _unique_nested_target(archive_path: Path) -> Path:
        base_name = strip_archive_extension(archive_path) or "archive"
        candidate = archive_path.with_name(base_name)
        if not candidate.exists():
            return candidate
        index = 1
        while True:
            candidate = archive_path.with_name(f"{base_name}_extracted_{index}")
            if not candidate.exists():
                return candidate
            index += 1

    @staticmethod
    def _package_entries(root: Path) -> list[Path]:
        entries: list[Path] = []
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().lower()):
            if path.is_symlink():
                raise ValueError(f"Символические ссылки нельзя включать в 7Z: {path}")
            if path.is_file() or (path.is_dir() and not any(path.iterdir())):
                entries.append(path)
        return entries

    @classmethod
    def _copy_directory(
        cls,
        source: Path,
        destination: Path,
        excluded_root: Path,
        options: AnalysisOptions,
        progress: ProgressCallback,
        cancelled: Event,
    ) -> tuple[int, str]:
        digest = hashlib.sha256()
        total_bytes = 0
        file_count = 0
        excluded = excluded_root.resolve()

        for current_root, directories, files in os.walk(source, followlinks=False):
            cls._check_cancelled(cancelled)
            current = Path(current_root)
            kept_directories: list[str] = []
            for name in sorted(directories, key=str.lower):
                directory = current / name
                if cls._is_link_or_reparse(directory):
                    raise ValueError(
                        f"Ссылки и точки повторной обработки запрещены: {directory}"
                    )
                if directory.resolve() == excluded:
                    continue
                relative = directory.relative_to(source)
                (destination / relative).mkdir(parents=True, exist_ok=True)
                cls._update_tree_digest(digest, b"D", relative)
                kept_directories.append(name)
            directories[:] = kept_directories

            for name in sorted(files, key=str.lower):
                cls._check_cancelled(cancelled)
                path = current / name
                if cls._is_link_or_reparse(path):
                    raise ValueError(
                        f"Ссылки и точки повторной обработки запрещены: {path}"
                    )
                metadata = path.stat()
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError(f"Неподдерживаемый объект в папке: {path}")

                file_count += 1
                if file_count > options.max_files:
                    raise ValueError("Превышен лимит количества файлов в папке")
                relative = path.relative_to(source)
                cls._update_tree_digest(digest, b"F", relative)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                with path.open("rb") as source_stream, target.open("wb") as target_stream:
                    while True:
                        cls._check_cancelled(cancelled)
                        chunk = source_stream.read(1024 * 1024)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > options.max_unpacked_bytes:
                            raise ValueError("Папка превышает лимит обрабатываемого объёма")
                        digest.update(chunk)
                        target_stream.write(chunk)
                # The workspace must stay writable: source files may carry the
                # Windows read-only attribute, but nested archives can be
                # replaced only inside this private copy.
                if file_count % 1000 == 0:
                    progress(3, f"Скопировано файлов: {file_count:,}")

        return total_bytes, digest.hexdigest()

    @staticmethod
    def _update_tree_digest(digest, kind: bytes, relative: Path) -> None:
        encoded = relative.as_posix().encode("utf-8", errors="surrogatepass")
        digest.update(kind)
        digest.update(len(encoded).to_bytes(8, "little"))
        digest.update(encoded)

    @staticmethod
    def _is_link_or_reparse(path: Path) -> bool:
        try:
            if path.is_symlink():
                return True
            attributes = int(getattr(path.lstat(), "st_file_attributes", 0) or 0)
            reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0) or 0)
            return bool(reparse_flag and attributes & reparse_flag)
        except OSError:
            return True

    @staticmethod
    def _sha256(path: Path, cancelled: Event) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                if cancelled.is_set():
                    raise OperationCancelled("Операция отменена")
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _check_cancelled(cancelled: Event) -> None:
        if cancelled.is_set():
            raise OperationCancelled("Операция отменена")
