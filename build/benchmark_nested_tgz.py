"""Reproducible extraction benchmark; uses generated files, never user archives."""
from __future__ import annotations

import argparse
import io
import json
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path
from threading import Event
from unittest.mock import patch

from paxoinsight.archive_service import ArchiveService
from paxoinsight.models import AnalysisOptions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", type=int, nargs="+", default=[60, 180])
    parser.add_argument("--files-per-tgz", type=int, default=16)
    args = parser.parse_args()
    service = ArchiveService()
    rows = []
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-TgzBenchmark-") as temp:
        root = Path(temp)
        payload = b"PaxoInsight nested TGZ benchmark\n" * 256
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            for index in range(args.files_per_tgz):
                member = tarfile.TarInfo(f"package/src/file-{index:04d}.txt")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        tgz = stream.getvalue()
        for count in args.counts:
            source = root / f"input-{count}.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
                for index in range(count):
                    archive.writestr(f"packages/package-{index:05d}.tgz", tgz)
            session = None
            started = time.perf_counter()
            with (
                patch.object(service, "_enforce_limits", wraps=service._enforce_limits) as limits,
                patch.object(
                    service, "_inspect_tree",
                    wraps=getattr(service, "_inspect_tree", None), create=True
                ) as inspections,
            ):
                try:
                    session = service.prepare(
                        source,
                        AnalysisOptions(delete_source_archive=False),
                        lambda _percent, _message: None,
                        Event(),
                    )
                    seconds = time.perf_counter() - started
                    file_count = sum(path.is_file() for path in session.content_root.rglob("*"))
                    expected = count * args.files_per_tgz
                    if file_count != expected or len(session.expanded_archives) != count:
                        raise RuntimeError("Not all nested archives were extracted")
                    workspace_checks = sum(
                        call.args[0] == session.content_root for call in limits.call_args_list
                    )
                    workspace_checks += sum(
                        call.args[0] == session.content_root for call in inspections.call_args_list
                    )
                    rows.append({
                        "archives": count,
                        "output_files": file_count,
                        "seconds": round(seconds, 4),
                        "whole_workspace_limit_checks": workspace_checks,
                    })
                finally:
                    service.cleanup(session)
    print(json.dumps(rows, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
