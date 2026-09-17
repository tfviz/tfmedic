"""Console singletons and the tfmedic colour theme."""

from __future__ import annotations

from rich.console import Console
from rich.theme import Theme

TFMEDIC_THEME = Theme(
    {
        "brand": "bold cyan",
        "muted": "dim",
        "ok": "green",
        "warn": "yellow",
        "danger": "bold red",
        "read": "cyan",
        "write": "bold magenta",
        "field": "bold white",
        "value": "white",
    }
)

console = Console(theme=TFMEDIC_THEME, highlight=False, soft_wrap=False)
err_console = Console(theme=TFMEDIC_THEME, stderr=True, highlight=False)


def get_console(*, stderr: bool = False) -> Console:
    """Return the shared console instance (stdout by default)."""
    return err_console if stderr else console
