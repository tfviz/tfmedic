"""Tool contract: Pydantic-validated arguments, structured results, write flags.

Two invariants hold for every tool in tfmedic:

1. The LLM never emits free-form shell commands. It fills a typed schema; the
   tool builds the command deterministically.
2. ``is_write_operation`` is a class-level constant, not a runtime decision, so
   the safety gate can classify a call before any SDK method is touched.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar, Generic, TypeVar

from pydantic import BaseModel, Field, ValidationError

from tfmedic.exceptions import ProviderError, ToolExecutionError

ArgsT = TypeVar("ArgsT", bound=BaseModel)

MAX_TOOL_PAYLOAD_CHARS = 12_000


class ToolResult(BaseModel):
    """Structured tool output handed back to the model and rendered in the UI."""

    ok: bool = True
    summary: str = Field(description="One-line, human-readable outcome.")
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    @classmethod
    def success(cls, summary: str, **data: Any) -> ToolResult:
        return cls(ok=True, summary=summary, data=data)

    @classmethod
    def failure(cls, summary: str, error: str, **data: Any) -> ToolResult:
        return cls(ok=False, summary=summary, error=error, data=data)

    def to_llm_payload(self, limit: int = MAX_TOOL_PAYLOAD_CHARS) -> str:
        """Serialise for the ``tool`` message, truncating oversized payloads.

        Context windows are a finite budget during an incident; a 4 MB
        ``describe_*`` response must never evict the reasoning history.
        """
        body: dict[str, Any] = {"ok": self.ok, "summary": self.summary}
        if self.error:
            body["error"] = self.error
        data_text = json.dumps(self.data, default=str, ensure_ascii=False)
        if len(data_text) > limit:
            body["data_truncated"] = True
            body["data_original_chars"] = len(data_text)
            body["data"] = data_text[:limit] + "…[truncated]"
        else:
            body["data"] = self.data
        return json.dumps(body, default=str, ensure_ascii=False)


class EmptyArgs(BaseModel):
    """Schema for tools that take no arguments."""


class BaseTool(ABC, Generic[ArgsT]):
    """Abstract base for every diagnostic or remediation capability."""

    name: ClassVar[str] = ""
    description: ClassVar[str] = ""
    is_write_operation: ClassVar[bool] = False
    args_model: ClassVar[type[BaseModel]] = EmptyArgs
    action_id: ClassVar[str] = ""

    # ---- schema -----------------------------------------------------------
    @classmethod
    def openai_schema(cls) -> dict[str, Any]:
        """Render the OpenAI/Ollama-compatible function-calling schema."""
        parameters = cls.args_model.model_json_schema()
        parameters.pop("title", None)
        parameters.setdefault("type", "object")
        parameters.setdefault("properties", {})
        return {
            "type": "function",
            "function": {
                "name": cls.name,
                "description": " ".join(cls.description.split()),
                "parameters": parameters,
            },
        }

    @classmethod
    def action_identifier(cls) -> str:
        """Stable identifier shown in the approval panel and audit log."""
        return cls.action_id or cls.name

    # ---- execution --------------------------------------------------------
    def parse_arguments(self, raw_arguments: Mapping[str, Any]) -> ArgsT:
        try:
            return self.args_model.model_validate(dict(raw_arguments))  # type: ignore[return-value]
        except ValidationError as exc:
            raise ToolExecutionError(_format_validation_error(exc)) from exc

    def execute(self, raw_arguments: Mapping[str, Any]) -> ToolResult:
        """Validate then run, converting every failure into a ``ToolResult``.

        The agent loop stays coherent: a tool never raises into the loop, it
        returns a structured failure the model can reason about and retry.
        """
        try:
            args = self.parse_arguments(raw_arguments)
        except ToolExecutionError as exc:
            return ToolResult.failure(
                summary=f"Invalid arguments for {self.name}", error=str(exc)
            )

        try:
            return self.run(args)
        except ToolExecutionError as exc:
            return ToolResult.failure(summary=f"{self.name} rejected the request", error=str(exc))
        except ProviderError as exc:
            return ToolResult.failure(summary=f"{self.name} provider failure", error=str(exc))
        except Exception as exc:  # noqa: BLE001 - deliberate boundary
            aws = describe_aws_exception(exc)
            if aws is not None:
                code, message = aws
                return ToolResult.failure(
                    summary=f"AWS rejected {self.name} ({code})",
                    error=message,
                    aws_error_code=code,
                )
            return ToolResult.failure(
                summary=f"Unexpected failure in {self.name}",
                error=f"{type(exc).__name__}: {exc}",
            )

    @abstractmethod
    def run(self, args: ArgsT) -> ToolResult:
        """Perform the operation. Called only with validated arguments."""

    # ---- write-operation metadata ----------------------------------------
    def target_resource(self, arguments: Mapping[str, Any]) -> str:
        """Resource identifier shown in the HIL approval panel."""
        for key in ("group_id", "instance_id", "db_instance_identifier", "resource_id"):
            if arguments.get(key):
                return str(arguments[key])
        return "-"

    def change_preview(self, arguments: Mapping[str, Any]) -> Sequence[tuple[str, str]]:
        """Human-readable diff rows for the approval panel."""
        return ()


def describe_aws_exception(exc: BaseException) -> tuple[str, str] | None:
    """Extract ``(code, message)`` from a botocore ``ClientError``.

    Implemented by duck-typing rather than importing botocore so the tool
    contract stays free of any cloud-SDK dependency.
    """
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            return str(error.get("Code", "Unknown")), str(error.get("Message", exc))
    if type(exc).__name__ in {"BotoCoreError", "EndpointConnectionError", "NoCredentialsError"}:
        return type(exc).__name__, str(exc)
    return None


def _format_validation_error(exc: ValidationError) -> str:
    problems = []
    for error in exc.errors():
        location = ".".join(str(part) for part in error.get("loc", ())) or "(root)"
        problems.append(f"{location}: {error.get('msg', 'invalid value')}")
    return "; ".join(problems)
