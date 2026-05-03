"""Алиас точки входа: python run_gui.py — то же, что python main.py."""

from __future__ import annotations

import os

os.environ.setdefault("MPLBACKEND", "QtAgg")

from safer_k64.gui.bootstrap import main


if __name__ == "__main__":
    raise SystemExit(main())
