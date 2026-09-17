"""The Human-in-the-Loop safety gate.

Architectural rule: diagnostic reconnaissance is autonomous, state mutation is
not. Every tool declares an immutable ``is_write_operation`` flag; the gate
intercepts those calls *before* any SDK method is invoked.
"""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from rich.console import Console
from rich.prompt import Confirm

from tfmedic.tools.base import BaseTool
from tfmedic.ui.components import approval_panel
from tfmedic.ui.console import get_console

ABORT_MESSAGE = (
    "Action aborted by user. Please propose an alternative diagnostic or manual runbook step."
)

READ_ONLY_MESSAGE = (
    "Action blocked: tfmedic is running in --read-only mode, so write operations are disabled. "
    "Propose a manual runbook step or a Terraform code change instead."
)

NON_INTERACTIVE_MESSAGE = (
    "Action blocked: no interactive terminal is attached, so the write could not be confirmed "
    "by a human. Propose a manual runbook step instead."
)


@dataclass(frozen=True)
class ApprovalDecision:
    """Outcome of a gate review."""

    approved: bool
    decision: str  # approved | denied | auto | not_required
    message: str | None = None

    @property
    def blocked(self) -> bool:
        return not self.approved


class SafetyGate:
    """Intercepts write tools and requires explicit keyboard confirmation."""

    def __init__(
        self,
        *,
        console: Console | None = None,
        region: str = "us-east-1",
        auto_approve: bool = False,
        read_only: bool = False,
        interactive: bool | None = None,
    ) -> None:
        self._console = console or get_console()
        self._region = region
        self.auto_approve = auto_approve
        self.read_only = read_only
        self.interactive = sys.stdin.isatty() if interactive is None else interactive

    def review(
        self,
        tool: BaseTool[Any],
        arguments: Mapping[str, Any],
        *,
        rationale: str = "",
    ) -> ApprovalDecision:
        """Return the approval decision for ``tool``.

        READ tools pass through untouched. WRITE tools are blocked in read-only
        mode, blocked without a TTY, auto-approved only when the operator
        explicitly opted in, and otherwise gated behind a ``[y/N]`` prompt.
        """
        if not tool.is_write_operation:
            return ApprovalDecision(approved=True, decision="not_required")

        if self.read_only:
            return ApprovalDecision(approved=False, decision="denied", message=READ_ONLY_MESSAGE)

        if self.auto_approve:
            self._console.print(
                f"[danger]! auto-approving write operation[/danger] [write]{tool.name}[/write] "
                "[muted](--auto-approve is set; no human reviewed this change)[/muted]"
            )
            return ApprovalDecision(approved=True, decision="auto")

        if not self.interactive:
            return ApprovalDecision(
                approved=False, decision="denied", message=NON_INTERACTIVE_MESSAGE
            )

        self._console.print()
        self._console.print(
            approval_panel(
                action=tool.action_identifier(),
                resource=tool.target_resource(arguments),
                region=self._region,
                changes=tool.change_preview(arguments),
                rationale=rationale,
            )
        )
        try:
            approved = Confirm.ask(
                "[warn]Apply change to AWS infrastructure?[/warn]",
                default=False,
                console=self._console,
            )
        except (EOFError, KeyboardInterrupt):
            self._console.print("[danger]x Approval aborted.[/danger]")
            return ApprovalDecision(approved=False, decision="denied", message=ABORT_MESSAGE)

        if approved:
            return ApprovalDecision(approved=True, decision="approved")
        return ApprovalDecision(approved=False, decision="denied", message=ABORT_MESSAGE)
