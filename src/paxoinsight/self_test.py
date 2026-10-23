from __future__ import annotations

import io
import struct
import tarfile
import tempfile
import zipfile
import zlib
from pathlib import Path
from threading import Event

from . import VERSION
from .archive_service import find_7zip_executable
from .models import AnalysisOptions
from .workflow import WorkflowService

KOTLIN_CLASS_FIXTURE = bytes.fromhex(
    "cafebabe0000003d000f01000964656d6f2f44656d6f0700010100106a6176612f6c616e672f"
    "4f626a65637407000301000a536f7572636546696c650100094d6f64656c732e6b740100114c"
    "6b6f746c696e2f4d657461646174613b0100016b03000000010100026d7603000000020300"
    "000000030000000001001952756e74696d6556697369626c65416e6e6f746174696f6e730021"
    "0002000400000000000000020005000000020006000e000000190001000700020008490009"
    "000a5b000349000b49000c49000d"
)


def stored_rar_fixture(members: dict[str, bytes]) -> bytes:
    """Build a tiny stored RAR4 fixture (ASCII names) without a RAR writer."""
    def header(body: bytes) -> bytes:
        return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body

    output = bytearray(b"Rar!\x1a\x07\x00")
    output.extend(header(struct.pack("<BHHHI", 0x73, 0, 13, 0, 0)))
    for name, data in members.items():
        encoded = name.encode("ascii")
        body = struct.pack(
            "<BHHIIBIIBBHI", 0x74, 0x8000, 32 + len(encoded),
            len(data), len(data), 2, zlib.crc32(data) & 0xFFFFFFFF,
            0, 20, 0x30, len(encoded), 0x20,
        ) + encoded
        output.extend(header(body))
        output.extend(data)
    output.extend(header(struct.pack("<BHH", 0x7B, 0, 7)))
    return bytes(output)


def run_self_test() -> int:
    """Exercise the packaged extraction, analysis and 7Z creation stack."""
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-SelfTest-") as temp:
        root = Path(temp)
        nested = root / "library.jar"
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("inside.txt", "portable self-test")

        source = root / "input.zip"
        rar_members: dict[str, bytes] = {}
        if find_7zip_executable() is not None:
            for name in ("first", "last"):
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w") as archive:
                    archive.writestr(f"{name}.txt", name)
                rar_members[f"{name}.zip"] = stream.getvalue()
            rar_members = {
                "first.zip": rar_members["first.zip"], "keep.txt": b"RAR sibling",
                "last.zip": rar_members["last.zip"],
            }
            rar = root / "stored.rar"
            rar.write_bytes(stored_rar_fixture(rar_members))
            raw_workflow = WorkflowService()
            raw_session = raw_workflow.archives.prepare(
                rar, AnalysisOptions(expand_nested=False, delete_source_archive=False),
                lambda *_: None, Event(),
            )
            try:
                actual = {
                    path.relative_to(raw_session.content_root).as_posix(): path.read_bytes()
                    for path in raw_session.content_root.rglob("*") if path.is_file()
                }
                if actual != rar_members:
                    raise RuntimeError("Самопроверка RAR потеряла вложенные ZIP или соседний файл")
            finally:
                raw_workflow.cleanup(raw_session)
        tgz = io.BytesIO()
        with tarfile.open(fileobj=tgz, mode="w:gz") as archive:
            member = tarfile.TarInfo("package/data.txt")
            payload = b"nested TGZ portable self-test"
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr("root.txt", f"PaxoInsight {VERSION}")
            archive.write(nested, "library.jar")
            archive.writestr("bundle.tgz", tgz.getvalue())
            archive.writestr(
                "src/main/kotlin/demo/Models.kt", "package demo\nclass Demo\nclass Missing"
            )
            archive.writestr("build/classes/kotlin/main/demo/Demo.class", KOTLIN_CLASS_FIXTURE)
            if rar_members:
                archive.write(rar, "stored.rar")

        workflow = WorkflowService()
        session = None
        try:
            session = workflow.scan(
                source,
                AnalysisOptions(
                    expand_nested=True,
                    replace_nested_archives=True,
                    delete_source_archive=False,
                    unpack_application_containers=True,
                ),
                lambda _value, _text: None,
                Event(),
            )
            if session.result is None:
                raise RuntimeError("Самопроверка не получила результат анализа")
            from .reporting import save_kotlin_text_report, save_text_report

            for exporter, name in ((save_kotlin_text_report, "kotlin"), (save_text_report, "full")):
                text_report = exporter(session.result, root / name)
                text = text_report.read_text(encoding="utf-8-sig")
                if "≈50.0%" not in text or "demo/Missing.class" not in text:
                    raise RuntimeError("Самопроверка TXT потеряла процент или отсутствующий класс")
            mapping = session.result.analysis_data.get("kotlin_mapping", {})
            if mapping.get("engine") != "python-structural-jvm" or (
                mapping["records"][0]["status"] != "partial"
                or mapping["records"][0]["declarations"][1]["status"] != "missing"
                or mapping.get("coverage", {}).get("estimated_percent") != 50.0
                or mapping.get("coverage", {}).get("confirmed_percent") != 50.0
            ):
                raise RuntimeError("Самопроверка Kotlin не обнаружила частичный комплект классов")
            if not (session.content_root / "library" / "inside.txt").is_file():
                raise RuntimeError("Самопроверка не раскрыла вложенный JAR")
            if (session.content_root / "bundle" / "package" / "data.txt").read_bytes() != payload:
                raise RuntimeError("Самопроверка не раскрыла вложенный TGZ")

            output = root / "result.7z"
            package = workflow.package(
                session,
                output,
                True,
                lambda _value, _text: None,
                Event(),
            )
            if not package.verified or not output.is_file():
                raise RuntimeError("Самопроверка не создала проверенный 7Z")
            with workflow.archives._py7zr.SevenZipFile(output, "r") as archive:
                names = set(archive.getnames())
            required = {
                "root.txt",
                "library/inside.txt",
                "bundle/package/data.txt",
                "PaxoInsight_Report.json",
                "PaxoInsight_Report.txt",
                "PaxoInsight_Kotlin_Report.html",
            }
            if missing := required.difference(names):
                raise RuntimeError(
                    f"Самопроверка не нашла записи в 7Z: {', '.join(sorted(missing))}"
                )
            if rar_members:
                for name, payload in {
                    "stored/first/first.txt": b"first",
                    "stored/last/last.txt": b"last", "stored/keep.txt": b"RAR sibling",
                }.items():
                    if (session.content_root / name).read_bytes() != payload or name not in names:
                        raise RuntimeError("Самопроверка RAR → ZIP → 7Z потеряла содержимое")
        finally:
            workflow.cleanup(session)
    return 0
