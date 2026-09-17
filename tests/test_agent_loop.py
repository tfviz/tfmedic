"""Loop mechanics: tool dispatch, iteration cutoff, gate integration, resilience."""

from __future__ import annotations

import json

from tfmedic.agent.loop import AgentLoop
from tfmedic.agent.models import LLMResponse
from tfmedic.safety.gatekeeper import SafetyGate
from tfmedic.tools.registry import ToolRegistry

from .conftest import FakeBoomTool, ScriptedLLM, tool_call


def build_loop(llm, tools, *, gate=None, audit=None, console=None, max_iterations=5, tmp_path=None):
    from tfmedic.safety.audit import AuditLogger

    return AgentLoop(
        llm=llm,
        registry=ToolRegistry(tools),
        gate=gate or SafetyGate(console=console, interactive=False),
        audit=audit or AuditLogger(enabled=False),
        console=console,
        max_iterations=max_iterations,
    )


def test_read_tool_runs_autonomously_then_loop_terminates(read_tool, quiet_console):
    llm = ScriptedLLM(
        [
            LLMResponse(content=None, tool_calls=(tool_call("fake_read", {"value": "logs"}),)),
            LLMResponse(content="**Diagnosis** the port was blocked."),
        ]
    )
    loop = build_loop(llm, [read_tool], console=quiet_console)
    result = loop.run("why is web-api crashing?")

    assert result.completed is True
    assert result.iterations == 2
    assert result.tool_calls == 1
    assert read_tool.calls[0].value == "logs"
    assert "Diagnosis" in result.answer

    tool_message = llm.requests[-1][-1]
    assert tool_message["role"] == "tool"
    assert json.loads(tool_message["content"])["summary"] == "read logs"


def test_denied_write_injects_abort_message_and_keeps_loop_coherent(
    write_tool, quiet_console
):
    llm = ScriptedLLM(
        [
            LLMResponse(
                content=None,
                tool_calls=(tool_call("fake_write", {"group_id": "sg-0418c39f"}),),
            ),
            LLMResponse(content="Understood, proposing a manual runbook step instead."),
        ]
    )
    gate = SafetyGate(console=quiet_console, interactive=False)
    loop = build_loop(llm, [write_tool], gate=gate, console=quiet_console)
    result = loop.run("fix the security group")

    assert write_tool.calls == []  # the SDK was never reached
    assert result.writes_denied == 1
    assert result.writes_applied == 0
    tool_message = llm.requests[-1][-1]
    assert tool_message["role"] == "tool"
    assert "manual runbook step" in tool_message["content"]


def test_approved_write_executes_and_is_counted(write_tool, quiet_console, monkeypatch):
    monkeypatch.setattr("tfmedic.safety.gatekeeper.Confirm.ask", lambda *a, **k: True)
    llm = ScriptedLLM(
        [
            LLMResponse(
                content=None,
                tool_calls=(tool_call("fake_write", {"group_id": "sg-0418c39f"}),),
            ),
            LLMResponse(content="Applied."),
        ]
    )
    gate = SafetyGate(console=quiet_console, interactive=True)
    loop = build_loop(llm, [write_tool], gate=gate, console=quiet_console)
    result = loop.run("authorise the ingress rule")

    assert len(write_tool.calls) == 1
    assert result.writes_applied == 1
    assert result.writes_denied == 0


def test_iteration_cutoff_forces_a_final_summary(read_tool, quiet_console):
    responses = [
        LLMResponse(content=None, tool_calls=(tool_call("fake_read", {"value": str(i)}),))
        for i in range(3)
    ]
    responses.append(LLMResponse(content="Partial findings, budget exhausted."))
    llm = ScriptedLLM(responses)
    loop = build_loop(llm, [read_tool], console=quiet_console, max_iterations=3)
    result = loop.run("keep digging")

    assert result.iterations == 3
    assert result.completed is False
    assert "budget exhausted" in result.answer.lower()
    assert llm.tool_payloads[-1] is None  # summary request disables tools


def test_unknown_tool_is_reported_back_not_raised(read_tool, quiet_console):
    llm = ScriptedLLM(
        [
            LLMResponse(content=None, tool_calls=(tool_call("does_not_exist", {}),)),
            LLMResponse(content="Recovered."),
        ]
    )
    loop = build_loop(llm, [read_tool], console=quiet_console)
    result = loop.run("call a bogus tool")

    assert result.completed is True
    assert "Unknown tool" in llm.requests[-1][-1]["content"]


def test_malformed_tool_arguments_are_returned_as_guidance(read_tool, quiet_console):
    from tfmedic.agent.models import ToolCall

    bad_call = ToolCall(
        id="call_bad",
        name="fake_read",
        arguments={},
        raw_arguments="{not json",
        parse_error="Tool arguments were not valid JSON: boom",
    )
    llm = ScriptedLLM(
        [
            LLMResponse(content=None, tool_calls=(bad_call,)),
            LLMResponse(content="Retried correctly."),
        ]
    )
    loop = build_loop(llm, [read_tool], console=quiet_console)
    loop.run("send malformed arguments")

    assert "valid JSON object" in llm.requests[-1][-1]["content"]
    assert read_tool.calls == []


def test_tool_exceptions_never_escape_into_the_loop(quiet_console):
    llm = ScriptedLLM(
        [
            LLMResponse(content=None, tool_calls=(tool_call("fake_boom", {}),)),
            LLMResponse(content="Handled the failure."),
        ]
    )
    loop = build_loop(llm, [FakeBoomTool()], console=quiet_console)
    result = loop.run("trigger a provider failure")

    assert result.completed is True
    payload = json.loads(llm.requests[-1][-1]["content"])
    assert payload["ok"] is False
    assert "provider exploded" in payload["error"]


def test_audit_log_records_every_decision(write_tool, quiet_console, audit_logger, monkeypatch):
    monkeypatch.setattr("tfmedic.safety.gatekeeper.Confirm.ask", lambda *a, **k: True)
    llm = ScriptedLLM(
        [
            LLMResponse(
                content=None,
                tool_calls=(tool_call("fake_write", {"group_id": "sg-0418c39f"}),),
            ),
            LLMResponse(content="Done."),
        ]
    )
    gate = SafetyGate(console=quiet_console, interactive=True)
    loop = build_loop(llm, [write_tool], gate=gate, audit=audit_logger, console=quiet_console)
    loop.run("apply the rule")

    lines = [json.loads(line) for line in audit_logger.path.read_text().splitlines()]
    events = [entry["event"] for entry in lines]
    assert events[0] == "run_start"
    assert "approval" in events
    assert "tool_call" in events
    assert events[-1] == "run_end"
    approval = next(entry for entry in lines if entry["event"] == "approval")
    assert approval["decision"] == "approved"
    assert approval["is_write"] is True
