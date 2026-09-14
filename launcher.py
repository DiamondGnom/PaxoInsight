from __future__ import annotations

import multiprocessing
import sys


if __name__ == "__main__":
    multiprocessing.freeze_support()
    if "--self-test" in sys.argv:
        from paxoinsight.self_test import run_self_test

        raise SystemExit(run_self_test())
    if "--gui-self-test" in sys.argv:
        from paxoinsight.ui.tk_main_window import PaxoInsightWindow
        from tkinterdnd2 import TkinterDnD

        root = TkinterDnD.Tk()
        root.withdraw()
        window = PaxoInsightWindow(root)
        root.update_idletasks()
        window._finish_close()
        raise SystemExit(0)

    from paxoinsight.__main__ import main

    main()
