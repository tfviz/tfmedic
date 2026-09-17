"""Append-only JSONL audit log of every tool invocation and approval decision.

The log is the forensic record for post-incident review: it captures what the
agent asked for, what the human decided, and what the cloud actually returned.
"""

from __future__ import annotations

import json
import os
import stat
import uuid
from collections.abc import Iterator, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from tfmedic.config import audit_file

_SENSITIVE_HINTS = ("password", "secret", "token", "apikey", "api_key", "credential", "passwd")
_REDACTED = "***REDACTED***"


def new_session_id() -> str:
    return uuid.uuid4().hex[:12]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively strip credential-looking values before they hit disk."""
    if _depth > 6:
        return "…"
    if isinstance(value, Mapping):
        return {
            key: (
                _REDACTED
                if any(hint in str(key).lower() for hint in _SENSITIVE_HINTS)
                else redact(val, _depth=_depth + 1)
            )
            for key, val in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth=_depth + 1) for item in value]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + "…[truncated]"
    return value


class AuditEvent(BaseModel):
    """A single immutable audit record."""

    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(default_factory=_utc_now)
    session_id: str
    event: str = Field(description="run_start | tool_call | approval | run_end")
    tool: str | None = None
    is_write: bool = False
    decision: str | None = Field(
        default=None, description="approved | denied | auto | not_required"
    )
    status: str | None = Field(default=None, description="success | failure | aborted")
    target: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)
    summary: str | None = None
    error: str | None = None
    duration_ms: int | None = None
    aws_profile: str | None = None
    aws_region: str | None = None
    actor: str = Field(default_factory=lambda: os.environ.get("USER", "unknown"))

    def to_json_line(self) -> str:
        payload = self.model_dump(exclude_none=True)
        payload["arguments"] = redact(payload.get("arguments", {}))
        return json.dumps(payload, default=str, ensure_ascii=False)


class AuditLogger:
    """Writes :class:`AuditEvent` records to ``~/.config/tfmedic/audit.jsonl``.

    Audit failures are intentionally non-fatal: losing a log line must never
    abort an in-flight incident response.
    """

    def __init__(self, path: Path | None = None, *, enabled: bool = True) -> None:
        self.path = Path(path) if path is not None else audit_file()
        self.enabled = enabled
        self.last_error: str | None = None

    def record(self, event: AuditEvent) -> None:
        if not self.enabled:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(event.to_json_line() + "\n")
            self.path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:  # pragma: no cover - disk full / read-only fs
            self.last_error = str(exc)


def read_audit_entries(path: Path | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Return the newest ``limit`` audit entries, oldest first."""
    target = Path(path) if path is not None else audit_file()
    if not target.is_file():
        return []
    entries: list[dict[str, Any]] = []
    for line in _tail_lines(target, limit):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            entries.append(parsed)
    return entries


def _tail_lines(path: Path, limit: int) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    for line in lines[-limit:]:
        stripped = line.strip()
        if stripped:
            yield stripped
