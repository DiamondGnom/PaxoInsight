from __future__ import annotations

import io
import tarfile
import tempfile
import zipfile
from pathlib import Path
from threading import Event

from . import VERSION
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


def run_self_test() -> int:
    """Exercise the packaged extraction, analysis and 7Z creation stack."""
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-SelfTest-") as temp:
        root = Path(temp)
        nested = root / "library.jar"
        with zipfile.ZipFile(nested, "w") as archive:
            archive.writestr("inside.txt", "portable self-test")

        source = root / "input.zip"
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
        finally:
            workflow.cleanup(session)
    return 0
