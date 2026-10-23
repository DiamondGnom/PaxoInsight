"""Reproduce real Kotlin library inspection and actual Tk table/rescan checks."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import tempfile
import time
import tkinter as tk
import zipfile
from pathlib import Path
from threading import Event

from paxoinsight.jvm_class import parse_class
from paxoinsight.kotlin_analysis import KotlinIndex
from paxoinsight.models import AnalysisOptions
from paxoinsight.reporting import save_kotlin_html_report
from paxoinsight.self_test import KOTLIN_CLASS_FIXTURE
from paxoinsight.ui.tk_main_window import PaxoInsightWindow


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def real_library(fixtures: Path) -> dict:
    binary = fixtures / "kotlin-stdlib-2.4.21.jar"
    source = fixtures / "kotlin-stdlib-2.4.21-sources.jar"
    kinds = collections.Counter()
    selected = {}
    started = time.perf_counter()
    with zipfile.ZipFile(binary) as jar:
        if jar.testzip():
            raise RuntimeError("Fixture JAR failed CRC")
        for item in jar.infolist():
            if item.filename.endswith(".class"):
                parsed = parse_class(jar.read(item), item.filename)
                kinds[parsed.metadata_kind] += 1
                if parsed.source_file == "Tuples.kt" and parsed.package == "kotlin":
                    selected[item.filename] = jar.read(item)
    seconds = time.perf_counter() - started
    with tempfile.TemporaryDirectory(prefix="PaxoInsight-RealKotlin-") as temporary:
        root = Path(temporary)
        source_name = "src/commonMain/kotlin/kotlin/Tuples.kt"
        (root / source_name).parent.mkdir(parents=True)
        with zipfile.ZipFile(source) as jar:
            (root / source_name).write_bytes(jar.read("commonMain/kotlin/util/Tuples.kt"))
        classes = []
        for name, data in selected.items():
            path = "build/classes/kotlin/main/" + name
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_bytes(data)
            classes.append(path)
        index = KotlinIndex(root)
        index.index_classes(classes)
        mapping = index.mapping([source_name])
        if mapping["records"][0]["status"] != "confirmed":
            raise RuntimeError(f"Real Tuples.kt mapping failed: {mapping['records']}")
        record = mapping["records"][0]
    return {"classes_parsed": sum(kinds.values()), "metadata_kinds": dict(kinds),
            "seconds": round(seconds, 4), "binary_sha256": sha256(binary),
            "source_sha256": sha256(source), "real_source_mapping": record,
            "source": "https://repo.maven.apache.org/maven2/org/jetbrains/kotlin/"
                      "kotlin-stdlib/2.4.21/", "jar_executed": False}


def gui(output: Path) -> dict:
    root = tk.Tk()
    root.withdraw()
    window = PaxoInsightWindow(root)
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix="PaxoInsight-KotlinGui-") as temporary:
            source = Path(temporary) / "project"
            kt = source / "src/main/kotlin/demo/Models.kt"
            cls = source / "build/classes/kotlin/main/demo/Demo.class"
            kt.parent.mkdir(parents=True)
            cls.parent.mkdir(parents=True)
            kt.write_text("package demo\nclass Demo\nclass Missing", encoding="utf-8")
            cls.write_bytes(KOTLIN_CLASS_FIXTURE)
            window.source = source
            session = window.workflow.scan(source, AnalysisOptions(), lambda *_: None, Event())
            window._scan_completed(session, repeated=False)
            root.update_idletasks()
            rows = [window.kotlin_tree.item(item, "values")
                    for item in window.kotlin_tree.get_children()]
            if not any(row[0] == "ЧАСТИЧНО" for row in rows):
                raise RuntimeError("Actual Tk table did not show partial status")
            if not any(row[3] == "demo/Missing.class" for row in rows):
                raise RuntimeError("Actual Tk table lost the missing declaration")
            if len(window.kotlin_tree["columns"]) != 7:
                raise RuntimeError("Actual Tk table lost evidence columns")
            if "≈50.0%" not in window.kotlin_coverage_var.get():
                raise RuntimeError("Actual Tk footer lost partial coverage percentage")
            if "≈50.0%" not in window.notebook.tab(window.kotlin_tree.master, "text"):
                raise RuntimeError("Actual Tk tab lost partial coverage percentage")
            save_kotlin_html_report(session.result, output / "kotlin-example-partial.html")
            (session.content_root / "src/main/kotlin/demo/Models.kt").write_text(
                "package demo\nclass Demo", encoding="utf-8"
            )
            window.workflow.rescan(session, AnalysisOptions(), lambda *_: None, Event())
            window._scan_completed(session, repeated=True)
            root.update_idletasks()
            rows = [window.kotlin_tree.item(item, "values")
                    for item in window.kotlin_tree.get_children()]
            if any(row[0] in {"ЧАСТИЧНО", "НЕ ОБНАРУЖЕН"} for row in rows):
                raise RuntimeError("Repeated scan retained stale mapping")
            if not any(row[0] == "ПОДТВЕРЖДЕНО" for row in rows):
                raise RuntimeError("Actual Tk table did not show confirmed status")
            if "≈100.0%" not in window.kotlin_coverage_var.get():
                raise RuntimeError("Repeated analysis did not refresh coverage percentage")
            window._clear_results(clear_log=True)
            cleared = window.kotlin_coverage_var.get()
            if "50.0%" in cleared or "100.0%" in cleared:
                raise RuntimeError("Next task retained previous coverage")
        return {"status": "passed", "columns": 7, "partial_and_missing_visible": True,
                "real_class_paths_visible": True, "rescan_discards_old_index": True,
                "partial_coverage_percent": 50.0, "rescanned_coverage_percent": 100.0,
                "new_task_clears_coverage": True,
                "scope": "Actual withdrawn Tk widgets; no interactive desktop screenshot"}
    finally:
        window.workflow.cleanup(session)
        root.destroy()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"real_library": real_library(args.fixtures), "gui": gui(args.output)}
    (args.output / "kotlin-verification.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=True, indent=2))
