from __future__ import annotations

import multiprocessing

from .runtime import require_supported_runtime


def main() -> None:
    multiprocessing.freeze_support()
    require_supported_runtime()
    from .ui.tk_main_window import run_application

    raise SystemExit(run_application())


if __name__ == "__main__":
    main()
