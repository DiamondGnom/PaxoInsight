from __future__ import annotations

import multiprocessing
import sys

from .ui.tk_main_window import run_application


def main() -> None:
    multiprocessing.freeze_support()
    raise SystemExit(run_application())


if __name__ == "__main__":
    main()
