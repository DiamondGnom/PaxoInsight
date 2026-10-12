"""Check the actual Tk task description with a BAR and a repeated analysis."""
from __future__ import annotations

import io
import tempfile
import tkinter as tk
import zipfile
from pathlib import Path
from threading import Event

from paxoinsight.models import AnalysisOptions
from paxoinsight.ui.tk_main_window import PaxoInsightWindow


def main() -> None:
    root = tk.Tk()
    root.withdraw()
    window = PaxoInsightWindow(root)
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix="PaxoInsight-BarHint-") as temp:
            source = Path(temp) / "application.bar"
            jar = io.BytesIO()
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("inside.txt", "BAR content")
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("module.jar", jar.getvalue())
            window.source = source
            session = window.workflow.scan(source, AnalysisOptions(), lambda *_: None, Event())
            window._scan_completed(session, repeated=False)
            window._refresh_controls()
            root.update_idletasks()
            assert window.preparation_hint.grid_info(), "Task recommendation is hidden"
            assert "ZIP/JAR-контейнеры»" in window.preparation_hint.cget("text")
            assert "Повторить анализ»" in window.summary_text.get("1.0", "end")
            assert window.scan_button.cget("state") == "normal"
            assert window.scan_button.cget("text") == "Повторить анализ"
            window.workflow.rescan(
                session, AnalysisOptions(unpack_application_containers=True),
                lambda *_: None, Event(),
            )
            window._scan_completed(session, repeated=True)
            root.update_idletasks()
            assert not window.preparation_hint.grid_info(), "Old recommendation remains visible"
            assert "Рекомендация по подготовке:" not in window.summary_text.get("1.0", "end")
            # A new task must not inherit the previous task's advice.
            window.preparation_hint.configure(text="previous task")
            window.preparation_hint.grid()
            window._clear_results(clear_log=True)
            assert not window.preparation_hint.grid_info()
            assert window.preparation_hint.cget("text") == ""
        print("BAR task recommendation / summary / repeat analysis / reset: OK")
    finally:
        window.workflow.cleanup(session)
        root.destroy()


if __name__ == "__main__":
    main()
