from __future__ import annotations

import multiprocessing
import sys

if __name__ == "__main__":
    multiprocessing.freeze_support()
    from paxoinsight.runtime import require_supported_runtime

    require_supported_runtime()
    if "--security-self-test" in sys.argv:
        import argparse
        from pathlib import Path

        from paxoinsight.security_self_test import run_security_self_test

        parser = argparse.ArgumentParser()
        parser.add_argument("--security-self-test", action="store_true")
        parser.add_argument("--self-test-report", type=Path)
        arguments = parser.parse_args()
        raise SystemExit(run_security_self_test(arguments.self_test_report))
    if "--self-test" in sys.argv:
        from paxoinsight.self_test import run_self_test

        raise SystemExit(run_self_test())
    if "--gui-self-test" in sys.argv:
        from tkinterdnd2 import TkinterDnD

        from paxoinsight.ui.appearance import DARK, LIGHT, Color
        from paxoinsight.ui.tk_main_window import PaxoInsightWindow

        root = TkinterDnD.Tk()
        root.withdraw()
        window = PaxoInsightWindow(root)
        for name, palette in (("dark", DARK), ("light", LIGHT)):
            window.theme.apply(name)
            if window.summary_text.cget("foreground") != palette[Color.TEXT]:
                raise RuntimeError("Portable desktop theme self-test failed")
            if window.header_logo is None or (
                window.header_logo.cget("bg") != palette[Color.CARD]
                or window.header_logo.emblem.cget("bg") != palette[Color.CARD]
                or window.header_logo.paxo.cget("fg") != palette[Color.HEADING]
            ):
                raise RuntimeError("Portable adaptive logo self-test failed")
        if "TXT" not in window.report_menu.entrycget(3, "label"):
            raise RuntimeError("Portable TXT report menu is missing")
        root.update_idletasks()
        window._finish_close()
        raise SystemExit(0)

    from paxoinsight.__main__ import main

    main()
