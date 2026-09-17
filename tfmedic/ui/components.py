"""Reusable Rich components: banners, approval panels, result lines, summaries."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from rich.console import Group, RenderableType
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tfmedic import __version__

_ASCII = r"""
 _    __                     _ _
| |  / _|                   | (_)
| |_| |_ _ __ ___   ___  ___| |_  ___
| __|  _| '_ ` _ \ / _ \/ _ \ | |/ __|
| |_| | | | | | | |  __/  __/ | | (__
 \__|_| |_| |_| |_|\___|\___|_|_|\___|
"""


def banner() -> RenderableType:
    """ASCII splash rendered on CLI start-up."""
    return Group(
        Text(_ASCII.strip("\n"), style="brand"),
        Text(
            f"  AI CloudOps triage agent  v{__version__}  ·  human-in-the-loop by default",
            style="muted",
        ),
    )


def session_header(
    *,
    model: str,
    base_url: str | None,
    profile: str | None,
    region: str,
    terraform_dir: str,
    read_only: bool,
    auto_approve: bool,
) -> RenderableType:
    """One-line environment banner printed before the agent loop starts."""
    mode = "READ-ONLY" if read_only else ("AUTO-APPROVE" if auto_approve else "HIL GATED")
    mode_style = "ok" if read_only else ("danger" if auto_approve else "warn")
    endpoint = base_url or "api.openai.com"
    line = Text()
    line.append("Using AWS Profile: ", style="muted")
    line.append(f"{profile or 'default'} ({region})", style="value")
    line.append("  |  Model: ", style="muted")
    line.append(model, style="value")
    line.append("  |  Endpoint: ", style="muted")
    line.append(endpoint, style="value")
    line.append("  |  Terraform: ", style="muted")
    line.append(terraform_dir, style="value")
    line.append("  |  Mode: ", style="muted")
    line.append(mode, style=mode_style)
    return line


def tool_call_line(name: str, arguments: Mapping[str, Any], *, is_write: bool) -> Text:
    """Compact one-line rendering of an outgoing tool invocation."""
    text = Text()
    text.append("→ ", style="muted")
    text.append(name, style="write" if is_write else "read")
    if arguments:
        rendered = ", ".join(f"{k}={_short(v)}" for k, v in arguments.items())
        text.append(f"({rendered})", style="muted")
    else:
        text.append("()", style="muted")
    return text


def tool_result_line(summary: str, *, ok: bool) -> Text:
    marker = "✓ " if ok else "✗ "
    style = "ok" if ok else "danger"
    return Text(marker, style=style).append(summary, style="value" if ok else "danger")


def approval_panel(
    *,
    action: str,
    resource: str,
    region: str,
    changes: Sequence[tuple[str, str]],
    rationale: str,
) -> Panel:
    """The blocking HIL warning panel rendered before any state mutation."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="field", justify="right", no_wrap=True)
    table.add_column(style="value", overflow="fold")
    table.add_row("Action", Text(action, style="write"))
    table.add_row("Resource", resource)
    table.add_row("Region", region)
    for label, value in changes:
        table.add_row(label, Text(value, style="warn"))
    table.add_row("Reason", rationale or "(no rationale supplied by the agent)")
    body = Group(
        table,
        Text(""),
        Text(
            "This mutates live cloud infrastructure. Terraform state will drift "
            "until you codify the change.",
            style="muted",
        ),
    )
    return Panel(
        body,
        title=Text("!  APPROVAL REQUIRED", style="danger"),
        title_align="center",
        border_style="danger",
        padding=(1, 2),
    )


def diagnosis_panel(markdown_text: str) -> Panel:
    return Panel(
        Markdown(markdown_text or "_The agent produced no final summary._"),
        title=Text("Diagnosis & Remediation", style="ok"),
        border_style="green",
        padding=(1, 2),
    )


def error_panel(message: str, *, title: str = "tfmedic error") -> Panel:
    return Panel(Text(message, style="danger"), title=title, border_style="danger", padding=(1, 2))


def run_summary_table(
    *,
    iterations: int,
    tool_calls: int,
    writes_applied: int,
    writes_denied: int,
    elapsed_seconds: float,
) -> Table:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="muted", justify="right")
    table.add_column(style="value")
    table.add_row("iterations", str(iterations))
    table.add_row("tool calls", str(tool_calls))
    table.add_row("writes applied", str(writes_applied))
    table.add_row("writes denied", str(writes_denied))
    table.add_row("elapsed", f"{elapsed_seconds:.1f}s")
    return table


def audit_table(entries: Iterable[Mapping[str, Any]]) -> Table:
    table = Table(show_lines=False, header_style="brand", border_style="muted")
    table.add_column("timestamp", style="muted", no_wrap=True)
    table.add_column("tool")
    table.add_column("write", justify="center")
    table.add_column("decision", justify="center")
    table.add_column("status")
    table.add_column("target", overflow="fold")
    for entry in entries:
        is_write = bool(entry.get("is_write"))
        decision = entry.get("decision") or "-"
        status = str(entry.get("status") or "-")
        table.add_row(
            str(entry.get("timestamp", "")),
            str(entry.get("tool", "")),
            Text("WRITE", style="write") if is_write else Text("read", style="read"),
            Text(str(decision), style="danger" if decision == "denied" else "ok"),
            Text(status, style="ok" if status == "success" else "danger"),
            str(entry.get("target") or "-"),
        )
    return table


def tools_table(rows: Sequence[tuple[str, bool, str]]) -> Table:
    table = Table(header_style="brand", border_style="muted")
    table.add_column("tool", no_wrap=True)
    table.add_column("class", justify="center", no_wrap=True)
    table.add_column("description", overflow="fold")
    for name, is_write, description in rows:
        table.add_row(
            name,
            Text("WRITE", style="write") if is_write else Text("READ", style="read"),
            description,
        )
    return table


def _short(value: Any, limit: int = 60) -> str:
    rendered = json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value)
    return rendered if len(rendered) <= limit else rendered[: limit - 1] + "…"
