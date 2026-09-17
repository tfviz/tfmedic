"""Provider-agnostic LLM client.

tfmedic speaks the OpenAI Chat Completions dialect with native tool calling.
Anything that implements it - OpenAI, Azure, vLLM, LM Studio, Ollama - is a
drop-in swap via ``base_url``. The rest of the codebase depends on the
:class:`LLMClient` protocol, never on the vendor SDK.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from tfmedic.exceptions import LLMError

_RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class ToolCall:
    """A single function call requested by the model."""

    id: str
    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    raw_arguments: str = "{}"
    parse_error: str | None = None


@dataclass(frozen=True)
class LLMResponse:
    """Normalised assistant turn."""

    content: str | None
    tool_calls: tuple[ToolCall, ...] = ()
    finish_reason: str | None = None
    usage: dict[str, int] = field(default_factory=dict)

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)

    def to_message(self) -> dict[str, Any]:
        """Render the assistant turn for the next request's message history.

        Built explicitly rather than dumping the SDK object, so self-hosted
        endpoints never receive vendor-specific fields they will reject.
        """
        message: dict[str, Any] = {"role": "assistant", "content": self.content or ""}
        if self.tool_calls:
            message["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.name, "arguments": call.raw_arguments},
                }
                for call in self.tool_calls
            ]
        return message


class LLMClient(Protocol):
    """Minimal contract the agent loop depends on."""

    model: str

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]] | None = None,
    ) -> LLMResponse: ...


class OpenAICompatibleClient:
    """OpenAI SDK wrapper with bounded exponential backoff."""

    def __init__(
        self,
        *,
        model: str,
        api_key: str,
        base_url: str | None = None,
        timeout: int = 90,
        max_retries: int = 3,
        temperature: float = 0.0,
        backoff_base: float = 1.5,
        sleep: Any = time.sleep,
    ) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise LLMError("The 'openai' package is required: pip install openai") from exc

        self.model = model
        self._temperature = temperature
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._sleep = sleep
        # The SDK's own retry logic is disabled; backoff is handled here so that
        # every attempt is observable and bounded by tfmedic's own policy.
        self._client = OpenAI(
            api_key=api_key,
            base_url=base_url,
            timeout=timeout,
            max_retries=0,
        )

    def complete(
        self,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]] | None = None,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": list(messages),
            "temperature": self._temperature,
        }
        if tools:
            payload["tools"] = list(tools)
            payload["tool_choice"] = "auto"

        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                completion = self._client.chat.completions.create(**payload)
            except Exception as exc:  # noqa: BLE001 - normalised below
                last_error = exc
                if attempt >= self._max_retries or not _is_retryable(exc):
                    raise LLMError(_describe_llm_error(exc, self.model)) from exc
                self._sleep(self._backoff_base ** (attempt + 1))
                continue
            return _parse_completion(completion)

        raise LLMError(_describe_llm_error(last_error, self.model))  # pragma: no cover


def _parse_completion(completion: Any) -> LLMResponse:
    choices = getattr(completion, "choices", None) or []
    if not choices:
        raise LLMError("The LLM returned no choices. The endpoint may be misconfigured.")
    choice = choices[0]
    message = getattr(choice, "message", None)
    if message is None:
        raise LLMError("The LLM returned a choice without a message body.")

    calls: list[ToolCall] = []
    for index, raw_call in enumerate(getattr(message, "tool_calls", None) or []):
        function = getattr(raw_call, "function", None)
        name = getattr(function, "name", "") or ""
        raw_arguments = getattr(function, "arguments", "") or "{}"
        parsed: dict[str, Any] = {}
        parse_error: str | None = None
        try:
            decoded = json.loads(raw_arguments or "{}")
            if isinstance(decoded, dict):
                parsed = decoded
            else:
                parse_error = "Tool arguments must be a JSON object."
        except json.JSONDecodeError as exc:
            parse_error = f"Tool arguments were not valid JSON: {exc}"
        calls.append(
            ToolCall(
                id=getattr(raw_call, "id", None) or f"call_{index}",
                name=name,
                arguments=parsed,
                raw_arguments=raw_arguments,
                parse_error=parse_error,
            )
        )

    usage_obj = getattr(completion, "usage", None)
    usage = {
        "prompt_tokens": getattr(usage_obj, "prompt_tokens", 0) or 0,
        "completion_tokens": getattr(usage_obj, "completion_tokens", 0) or 0,
        "total_tokens": getattr(usage_obj, "total_tokens", 0) or 0,
    }
    return LLMResponse(
        content=getattr(message, "content", None),
        tool_calls=tuple(calls),
        finish_reason=getattr(choice, "finish_reason", None),
        usage=usage,
    )


def _is_retryable(exc: BaseException) -> bool:
    name = type(exc).__name__
    if name in {"APIConnectionError", "APITimeoutError", "RateLimitError", "InternalServerError"}:
        return True
    status = getattr(exc, "status_code", None)
    return isinstance(status, int) and status in _RETRYABLE_STATUS


def _describe_llm_error(exc: BaseException | None, model: str) -> str:
    if exc is None:  # pragma: no cover - defensive
        return f"LLM request for model '{model}' failed for an unknown reason."
    name = type(exc).__name__
    if name in {"AuthenticationError", "PermissionDeniedError"}:
        return (
            f"LLM authentication failed ({name}). Check OPENAI_API_KEY, or run "
            "`tfmedic configure` to store a key."
        )
    if name == "NotFoundError":
        return (
            f"Model '{model}' was not found at this endpoint. For Ollama, pull the model first "
            "(e.g. `ollama pull qwen2.5-coder:14b`) and set TFMEDIC_MODEL to match."
        )
    if name in {"APIConnectionError", "APITimeoutError"}:
        return (
            f"Could not reach the LLM endpoint ({name}). If using TFMEDIC_LLM_URL, confirm the "
            "server is running and reachable."
        )
    return f"LLM request failed ({name}): {exc}"
