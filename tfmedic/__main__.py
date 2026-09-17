"""Allow `python -m tfmedic ...` in addition to the console script entrypoint."""

from __future__ import annotations

from tfmedic.cli import run

if __name__ == "__main__":  # pragma: no cover - trivial delegation
    run()
