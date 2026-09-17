"""The reasoning loop.

A hand-written while loop rather than a framework graph: every state transition
here - iteration budget, tool dispatch, gate interception, abort injection,
audit write - is a place where an agent with production write access can go
wrong, and each one is explicit and testable.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from tfmedic.agent.models import LLMClient, LLMResponse, ToolCall
from tfmedic.agent.prompts import FINAL_SUMMARY_NUDGE, SYSTEM_PROMPT
from tfmedic.exceptions import LLMError
from tfmedic.safety.audit import AuditEvent, AuditLogger, new_session_id
from tfmedic.safety.gatekeeper import SafetyGate
from tfmedic.tools.base import ToolResult
from tfmedic.tools.registry import ToolRegistry
from tfmedic.ui.components import tool_call_line, tool_result_line
from tfmedic.ui.console import get_console

MAX_CONSECUTIVE_FAILURES = 4


@dataclass
class AgentRunResult:
    """Everything the CLI needs to render and exit correctly."""

    answer: str
    iterations: int = 0
    tool_calls: int = 0
    writes_applied: int = 0
    writes_denied: int = 0
    completed: bool = False
    elapsed_seconds: float = 0.0
    session_id: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    messages: list[dict[str, Any]] = field(default_factory=list)


class AgentLoop:
    """Drives model reasoning, tool execution and the human approval gate."""

    def __init__(
        self,
        *,
        llm: LLMClient,
        registry: ToolRegistry,
        gate: SafetyGate,
        audit: AuditLogger,
        console: Console | None = None,
        max_iterations: int = 12,
        aws_profile: str | None = None,
        aws_region: str = "us-east-1",
        verbose: bool = False,
        session_id: str | None = None,
    ) -> None:
        self._llm = llm
        self._registry = registry
        self._gate = gate
        self._audit = audit
        self._console = console or get_console()
        self._max_iterations = max_iterations
        self._aws_profile = aws_profile
        self._aws_region = aws_region
        self._verbose = verbose
        self._session_id = session_id or new_session_id()

    # ------------------------------------------------------------------ #
    def run(self, query: str, *, environment_context: str = "") -> AgentRunResult:
        started = time.monotonic()
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"{environment_context}\n\nINCIDENT REPORT\n{query.strip()}"
                    if environment_context
                    else query.strip()
                ),
            },
        ]
        result = AgentRunResult(answer="", session_id=self._session_id)
        schemas = self._registry.schemas()
        consecutive_failures = 0

        self._audit.record(
            AuditEvent(
                session_id=self._session_id,
                event="run_start",
                summary=query.strip()[:500],
                aws_profile=self._aws_profile,
                aws_region=self._aws_region,
            )
        )

        while result.iterations < self._max_iterations:
            result.iterations += 1
            try:
                response = self._call_llm(messages, schemas)
            except LLMError as exc:
                result.answer = f"**Investigation halted.** {exc}"
                result.elapsed_seconds = time.monotonic() - started
                self._record_run_end(result, status="failure", error=str(exc))
                return result

            _accumulate_usage(result.usage, response.usage)
            messages.append(response.to_message())

            if response.content and response.wants_tools and self._verbose:
                self._console.print(f"[muted]{response.content.strip()}[/muted]")

            if not response.wants_tools:
                content = (response.content or "").strip()
                
                import re
                if re.search(r'\{\s*"name"\s*:\s*"[^"]+"', content) or ('"parameters"' in content and "{" in content):
                    self._console.print("[yellow]! Intercepted hallucinated raw JSON in text. Forcing model to retry via native API.[/yellow]")
                    messages.append({
                        "role": "user",
                        "content": "CRITICAL: You output raw JSON representing a tool call in your text response. You MUST use the native tool calling API format. Do not output raw JSON in the conversation."
                    })
                    consecutive_failures += 1
                    continue

                result.answer = content
                result.completed = True
                break

            for call in response.tool_calls:
                result.tool_calls += 1
                outcome = self._dispatch(call, result)
                messages.append(
                    {"role": "tool", "tool_call_id": call.id, "content": outcome.content}
                )
                consecutive_failures = 0 if outcome.ok else consecutive_failures + 1

            if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"{MAX_CONSECUTIVE_FAILURES} consecutive tool calls failed. Stop "
                            "retrying, summarise what you established and what is blocked, and "
                            "propose a manual next step."
                        ),
                    }
                )
                consecutive_failures = 0
        else:
            result.answer = self._force_final_answer(messages, result)

        result.elapsed_seconds = time.monotonic() - started
        result.messages = messages
        self._record_run_end(result, status="success" if result.completed else "incomplete")
        return result

    # ------------------------------------------------------------------ #
    def _call_llm(
        self, messages: list[dict[str, Any]], schemas: list[dict[str, Any]]
    ) -> LLMResponse:
        with self._console.status("[muted]reasoning…[/muted]", spinner="dots"):
            return self._llm.complete(messages, schemas)

    def _dispatch(self, call: ToolCall, result: AgentRunResult) -> _Outcome:
        """Execute one tool call through validation, the gate and the audit log."""
        if call.parse_error:
            self._console.print(
                tool_result_line(f"{call.name}: malformed arguments", ok=False)
            )
            return _Outcome(
                ok=False,
                content=(
                    f"Tool call rejected: {call.parse_error} "
                    "Re-issue the call with a valid JSON object matching the schema."
                ),
            )

        if not self._registry.has(call.name):
            available = ", ".join(tool.name for tool in self._registry)
            self._console.print(tool_result_line(f"unknown tool '{call.name}'", ok=False))
            return _Outcome(
                ok=False,
                content=f"Unknown tool '{call.name}'. Available tools: {available}.",
            )

        tool = self._registry.get(call.name)
        self._console.print(
            tool_call_line(call.name, call.arguments, is_write=tool.is_write_operation)
        )

        if tool.is_write_operation:
            rationale = str(call.arguments.get("reason") or call.arguments.get("description") or "")
            decision = self._gate.review(tool, call.arguments, rationale=rationale)
            self._audit.record(
                AuditEvent(
                    session_id=self._session_id,
                    event="approval",
                    tool=tool.name,
                    is_write=True,
                    decision=decision.decision,
                    target=tool.target_resource(call.arguments),
                    arguments=dict(call.arguments),
                    aws_profile=self._aws_profile,
                    aws_region=self._aws_region,
                )
            )
            if decision.blocked:
                result.writes_denied += 1
                self._console.print(tool_result_line("write operation denied", ok=False))
                self._audit.record(
                    AuditEvent(
                        session_id=self._session_id,
                        event="tool_call",
                        tool=tool.name,
                        is_write=True,
                        decision=decision.decision,
                        status="aborted",
                        target=tool.target_resource(call.arguments),
                        arguments=dict(call.arguments),
                        aws_profile=self._aws_profile,
                        aws_region=self._aws_region,
                    )
                )
                return _Outcome(ok=False, content=decision.message or "Action aborted by user.")

        started = time.monotonic()
        with self._console.status(f"[muted]running {tool.name}…[/muted]", spinner="dots"):
            tool_result: ToolResult = tool.execute(call.arguments)
        duration_ms = int((time.monotonic() - started) * 1000)

        if tool.is_write_operation and tool_result.ok:
            result.writes_applied += 1

        self._console.print(tool_result_line(tool_result.summary, ok=tool_result.ok))
        if not tool_result.ok and tool_result.error and self._verbose:
            self._console.print(f"[muted]  {tool_result.error}[/muted]")

        self._audit.record(
            AuditEvent(
                session_id=self._session_id,
                event="tool_call",
                tool=tool.name,
                is_write=tool.is_write_operation,
                decision="approved" if tool.is_write_operation else "not_required",
                status="success" if tool_result.ok else "failure",
                target=tool.target_resource(call.arguments),
                arguments=dict(call.arguments),
                summary=tool_result.summary,
                error=tool_result.error,
                duration_ms=duration_ms,
                aws_profile=self._aws_profile,
                aws_region=self._aws_region,
            )
        )
        return _Outcome(ok=tool_result.ok, content=tool_result.to_llm_payload())

    def _force_final_answer(
        self, messages: list[dict[str, Any]], result: AgentRunResult
    ) -> str:
        """Budget exhausted: ask for a summary with tools disabled."""
        self._console.print(
            "[warn]! iteration budget exhausted - requesting a final summary[/warn]"
        )
        messages.append({"role": "user", "content": FINAL_SUMMARY_NUDGE})
        try:
            with self._console.status("[muted]summarising…[/muted]", spinner="dots"):
                response = self._llm.complete(messages, None)
        except LLMError as exc:
            return (
                f"**Investigation incomplete.** The iteration budget of {self._max_iterations} "
                f"was exhausted and the summary request failed: {exc}"
            )
        _accumulate_usage(result.usage, response.usage)
        messages.append(response.to_message())
        return (response.content or "").strip() or (
            f"**Investigation incomplete.** The iteration budget of {self._max_iterations} was "
            "exhausted before a conclusion was reached. Re-run with --max-iterations raised, or "
            "narrow the incident report."
        )

    def _record_run_end(
        self, result: AgentRunResult, *, status: str, error: str | None = None
    ) -> None:
        self._audit.record(
            AuditEvent(
                session_id=self._session_id,
                event="run_end",
                status=status,
                error=error,
                summary=(
                    f"iterations={result.iterations} tool_calls={result.tool_calls} "
                    f"writes_applied={result.writes_applied} writes_denied={result.writes_denied}"
                ),
                duration_ms=int(result.elapsed_seconds * 1000),
                aws_profile=self._aws_profile,
                aws_region=self._aws_region,
            )
        )


@dataclass(frozen=True)
class _Outcome:
    ok: bool
    content: str


def _accumulate_usage(target: dict[str, int], usage: dict[str, int]) -> None:
    for key, value in (usage or {}).items():
        target[key] = target.get(key, 0) + int(value or 0)
