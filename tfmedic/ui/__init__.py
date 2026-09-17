"""Rich-based terminal presentation layer."""

from __future__ import annotations

from tfmedic.ui.components import (
    approval_panel,
    banner,
    diagnosis_panel,
    error_panel,
    run_summary_table,
    tool_call_line,
    tool_result_line,
)
from tfmedic.ui.console import console, err_console, get_console

__all__ = [
    "console",
    "err_console",
    "get_console",
    "approval_panel",
    "banner",
    "diagnosis_panel",
    "error_panel",
    "run_summary_table",
    "tool_call_line",
    "tool_result_line",
]
