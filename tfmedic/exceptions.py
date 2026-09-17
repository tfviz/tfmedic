"""Exception hierarchy for tfmedic.

Every failure mode raised inside the package derives from :class:`TfmedicError`
so the CLI can render a single, predictable error surface instead of leaking
tracebacks from boto3, subprocess or the OpenAI SDK.
"""

from __future__ import annotations


class TfmedicError(Exception):
    """Base class for all tfmedic failures."""


class ConfigurationError(TfmedicError):
    """Raised when credentials, environment or CLI options are unusable."""


class ProviderError(TfmedicError):
    """Raised when an execution provider (AWS SDK, shell, LLM) fails hard."""


class ToolExecutionError(TfmedicError):
    """Raised when a tool cannot run, typically due to invalid arguments."""


class LLMError(ProviderError):
    """Raised when the LLM provider is unreachable or returns an unusable body."""


class AgentLoopError(TfmedicError):
    """Raised when the reasoning loop enters an unrecoverable state."""


class SafetyViolationError(TfmedicError):
    """Raised when a write operation is attempted while the gate forbids it."""
