"""The safety gate is the single most important component to get right."""

from __future__ import annotations

import pytest

from tfmedic.safety.gatekeeper import (
    ABORT_MESSAGE,
    NON_INTERACTIVE_MESSAGE,
    READ_ONLY_MESSAGE,
    SafetyGate,
)


def test_read_tools_are_never_intercepted(read_tool, quiet_console):
    gate = SafetyGate(console=quiet_console, interactive=True)
    decision = gate.review(read_tool, {"value": "x"})
    assert decision.approved is True
    assert decision.decision == "not_required"


def test_write_tool_requires_confirmation_and_is_approved(write_tool, quiet_console, monkeypatch):
    monkeypatch.setattr("tfmedic.safety.gatekeeper.Confirm.ask", lambda *a, **k: True)
    gate = SafetyGate(console=quiet_console, interactive=True)
    decision = gate.review(write_tool, {"group_id": "sg-0418c39f"}, rationale="unblock db")
    assert decision.approved is True
    assert decision.decision == "approved"


def test_write_tool_denied_injects_abort_message(write_tool, quiet_console, monkeypatch):
    monkeypatch.setattr("tfmedic.safety.gatekeeper.Confirm.ask", lambda *a, **k: False)
    gate = SafetyGate(console=quiet_console, interactive=True)
    decision = gate.review(write_tool, {"group_id": "sg-0418c39f"})
    assert decision.blocked is True
    assert decision.message == ABORT_MESSAGE


def test_read_only_mode_blocks_writes_without_prompting(write_tool, quiet_console, monkeypatch):
    def _explode(*args, **kwargs):
        raise AssertionError("read-only mode must not reach the prompt")

    monkeypatch.setattr("tfmedic.safety.gatekeeper.Confirm.ask", _explode)
    gate = SafetyGate(console=quiet_console, read_only=True, interactive=True)
    decision = gate.review(write_tool, {"group_id": "sg-0418c39f"})
    assert decision.blocked is True
    assert decision.message == READ_ONLY_MESSAGE


def test_non_interactive_sessions_deny_by_default(write_tool, quiet_console):
    gate = SafetyGate(console=quiet_console, interactive=False)
    decision = gate.review(write_tool, {"group_id": "sg-0418c39f"})
    assert decision.blocked is True
    assert decision.message == NON_INTERACTIVE_MESSAGE


def test_auto_approve_is_explicit_and_recorded(write_tool, quiet_console, monkeypatch):
    monkeypatch.setattr(
        "tfmedic.safety.gatekeeper.Confirm.ask",
        lambda *a, **k: pytest.fail("auto-approve must not prompt"),
    )
    gate = SafetyGate(console=quiet_console, auto_approve=True, interactive=True)
    decision = gate.review(write_tool, {"group_id": "sg-0418c39f"})
    assert decision.approved is True
    assert decision.decision == "auto"


def test_keyboard_interrupt_during_prompt_is_a_denial(write_tool, quiet_console, monkeypatch):
    def _interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("tfmedic.safety.gatekeeper.Confirm.ask", _interrupt)
    gate = SafetyGate(console=quiet_console, interactive=True)
    decision = gate.review(write_tool, {"group_id": "sg-0418c39f"})
    assert decision.blocked is True
