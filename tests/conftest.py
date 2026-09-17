"""Shared fakes. No test touches AWS, the network, or a real LLM."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest
from pydantic import BaseModel, Field

from tfmedic.agent.models import LLMResponse, ToolCall
from tfmedic.providers import CommandResult
from tfmedic.tools.base import BaseTool, ToolResult


class EchoArgs(BaseModel):
    value: str = Field(default="ok")


class FakeReadTool(BaseTool[EchoArgs]):
    name = "fake_read"
    description = "A read-only fake used in tests."
    args_model = EchoArgs
    is_write_operation = False

    def __init__(self) -> None:
        self.calls: list[EchoArgs] = []

    def run(self, args: EchoArgs) -> ToolResult:
        self.calls.append(args)
        return ToolResult.success(f"read {args.value}", value=args.value)


class FakeWriteArgs(BaseModel):
    group_id: str = "sg-01234567"
    reason: str = "because the port is blocked"


class FakeWriteTool(BaseTool[FakeWriteArgs]):
    name = "fake_write"
    description = "A write fake used to exercise the safety gate."
    args_model = FakeWriteArgs
    is_write_operation = True
    action_id = "aws:fake:Write"

    def __init__(self) -> None:
        self.calls: list[FakeWriteArgs] = []

    def run(self, args: FakeWriteArgs) -> ToolResult:
        self.calls.append(args)
        return ToolResult.success(f"wrote {args.group_id}", group_id=args.group_id)

    def target_resource(self, arguments: Mapping[str, Any]) -> str:
        return str(arguments.get("group_id", "-"))

    def change_preview(self, arguments: Mapping[str, Any]) -> Sequence[tuple[str, str]]:
        return (("Change", "+ INGRESS allow TCP 5432 from 10.0.1.0/24"),)


class FakeBoomTool(BaseTool[EchoArgs]):
    name = "fake_boom"
    description = "Always raises, to prove failures never escape into the loop."
    args_model = EchoArgs

    def run(self, args: EchoArgs) -> ToolResult:
        raise RuntimeError("provider exploded")


class ScriptedLLM:
    """Replays a fixed list of LLMResponse objects and records the requests."""

    model = "scripted-model"

    def __init__(self, responses: Sequence[LLMResponse]) -> None:
        self._responses = list(responses)
        self.requests: list[list[dict[str, Any]]] = []
        self.tool_payloads: list[Any] = []

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]] | None = None,
    ) -> LLMResponse:
        self.requests.append([dict(message) for message in messages])
        self.tool_payloads.append(tools)
        if not self._responses:
            return LLMResponse(content="no more scripted responses")
        return self._responses.pop(0)


class FakeAwsClientFactory:
    """Serves canned boto3-shaped responses keyed by ``service.operation``."""

    def __init__(self, responses: Mapping[str, Any] | None = None) -> None:
        self.region = "us-east-1"
        self.responses: dict[str, Any] = dict(responses or {})
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def client(self, service_name: str) -> Any:
        return _FakeClient(service_name, self)


class _FakeClient:
    def __init__(self, service: str, factory: FakeAwsClientFactory) -> None:
        self._service = service
        self._factory = factory

    def __getattr__(self, operation: str):
        key = f"{self._service}.{operation}"

        def _call(**kwargs: Any) -> Any:
            self._factory.calls.append((key, kwargs))
            if key not in self._factory.responses:
                raise AssertionError(f"Unexpected AWS call: {key}")
            value = self._factory.responses[key]
            if isinstance(value, Exception):
                raise value
            if callable(value):
                return value(**kwargs)
            return value

        return _call


class FakeCommandRunner:
    """Returns canned CommandResults and records the argv it was handed."""

    def __init__(self, result: CommandResult | None = None) -> None:
        self.result = result or CommandResult(0, "{}", "")
        self.commands: list[list[str]] = []

    def run(self, command, *, cwd=None, timeout=60, env=None) -> CommandResult:
        self.commands.append([str(part) for part in command])
        return self.result


def tool_call(name: str, arguments: dict[str, Any] | None = None, call_id: str = "call_1") -> ToolCall:
    import json

    payload = arguments or {}
    return ToolCall(
        id=call_id, name=name, arguments=payload, raw_arguments=json.dumps(payload)
    )


@pytest.fixture()
def read_tool() -> FakeReadTool:
    return FakeReadTool()


@pytest.fixture()
def write_tool() -> FakeWriteTool:
    return FakeWriteTool()


@pytest.fixture()
def audit_logger(tmp_path):
    from tfmedic.safety.audit import AuditLogger

    return AuditLogger(tmp_path / "audit.jsonl")


@pytest.fixture()
def quiet_console():
    """A themed console that renders to nowhere, so tests stay silent."""
    import io

    from rich.console import Console

    from tfmedic.ui.console import TFMEDIC_THEME

    return Console(file=io.StringIO(), theme=TFMEDIC_THEME, width=100, force_terminal=False)
