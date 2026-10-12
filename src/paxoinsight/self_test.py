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
