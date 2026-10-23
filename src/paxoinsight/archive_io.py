"""Filesystem writers which enforce limits on actual extracted bytes and paths."""

from __future__ import annotations

import io
import shutil
from pathlib import Path
from threading import Event, RLock

from py7zr.io import Py7zIO, WriterFactory

from .models import AnalysisOptions, OperationCancelled


class GuardedArchiveOutput(io.BufferedWriter):
    """Keep disk headroom even while packaging a single very large input file."""

    def __init__(self, raw, parent: Path, cancelled: Event, maximum: int):
        super().__init__(raw)
        self.parent = parent
        self.cancelled = cancelled
        self.maximum = maximum
        self.written = 0

    def write(self, data):
        if self.cancelled.is_set():
            raise OperationCancelled("Операция отменена")
        if self.written + len(data) > self.maximum:
            raise ValueError("Превышен лимит размера итогового архива")
        if shutil.disk_usage(self.parent).free < 512 * 1024**2 + len(data):
            raise ValueError("Недостаточно свободного места для сборки архива")
        self.written += len(data)
        return super().write(data)


class ExtractionBudget:
    def __init__(self, root: Path, options: AnalysisOptions, cancelled: Event | None):
        self.root = root.resolve()
        self.options = options
        self.cancelled = cancelled
        self.total = 0
        self.entries = 0
        self.lock = RLock()

    def check(self) -> None:
        if self.cancelled is not None and self.cancelled.is_set():
            raise OperationCancelled("Операция отменена")

    def count_entry(self) -> None:
        self.check()
        self.entries += 1
        if self.entries > self.options.max_files:
            raise ValueError("Превышен лимит количества распакованных объектов")

    def ensure_space(self, size: int = 0) -> None:
        if shutil.disk_usage(self.root).free < 512 * 1024**2 + size:
            raise ValueError("Недостаточно свободного места для подготовки файлов")

    def directory(self, path: Path) -> None:
        path = path.resolve()
        path.relative_to(self.root)
        if path == self.root:
            return
        with self.lock:
            self.check()
            if not path.exists():
                self.directory(path.parent)
                self.count_entry()
                self.ensure_space()
                path.mkdir(mode=0o700)
            elif not path.is_dir() or path.is_symlink():
                raise ValueError("Небезопасный объект в рабочей папке")

    def open_file(self, path: Path):
        path = path.resolve()
        path.relative_to(self.root)
        with self.lock:
            self.directory(path.parent)
            self.count_entry()
            # Reject duplicate destinations instead of overwriting earlier entries.
            return path.open("xb")

    def write(self, stream, data: bytes | bytearray) -> int:
        with self.lock:
            self.check()
            if self.total + len(data) > self.options.max_unpacked_bytes:
                raise ValueError("Превышен лимит распакованного объёма")
            self.ensure_space(len(data))
            self.total += len(data)
        return stream.write(data)

    def copy(self, source, target: Path) -> None:
        with self.open_file(target) as destination:
            while True:
                self.check()
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                self.write(destination, chunk)


class Bounded7zWriter(Py7zIO):
    def __init__(self, path: Path, budget: ExtractionBudget):
        self.stream = budget.open_file(path)
        self.budget = budget
        self.length = 0

    def write(self, data: bytes | bytearray) -> int:
        count = self.budget.write(self.stream, data)
        self.length += count
        return count

    def read(self, size: int | None = None) -> bytes:
        raise OSError("Extraction output is write-only")

    def seek(self, offset: int, whence: int = 0) -> int:
        # py7zr rewinds the output before calling close(). No reads are needed.
        return self.stream.seek(offset, whence)

    def flush(self) -> None:
        self.stream.flush()

    def size(self) -> int:
        return self.length

    def close(self) -> None:
        self.stream.close()


class Bounded7zFactory(WriterFactory):
    def __init__(self, budget: ExtractionBudget):
        self.budget = budget
        self.writers: list[Bounded7zWriter] = []

    def create(self, filename: str) -> Py7zIO:
        writer = Bounded7zWriter(Path(filename), self.budget)
        self.writers.append(writer)
        return writer

    def close(self) -> None:
        for writer in self.writers:
            writer.close()
