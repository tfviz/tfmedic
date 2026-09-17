"""Runtime configuration: environment discovery, precedence rules and on-disk state.

Precedence (highest first):
    1. Explicit CLI flags
    2. Process environment variables
    3. ``~/.config/tfmedic/config.json``
    4. Built-in defaults
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr

from tfmedic.exceptions import ConfigurationError

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_REGION = "us-east-1"
DEFAULT_MAX_ITERATIONS = 12
DEFAULT_SSM_TIMEOUT_SECONDS = 60
DEFAULT_REQUEST_TIMEOUT_SECONDS = 90

CONFIG_FILENAME = "config.json"
AUDIT_FILENAME = "audit.jsonl"


def config_dir() -> Path:
    """Return the tfmedic configuration directory, honouring ``TFMEDIC_HOME``."""
    override = os.environ.get("TFMEDIC_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".config" / "tfmedic"


def ensure_config_dir() -> Path:
    """Create the config directory with 0700 permissions and return it."""
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):  # exotic filesystems (e.g. mounted shares)
        directory.chmod(stat.S_IRWXU)
    return directory


def config_file() -> Path:
    return config_dir() / CONFIG_FILENAME


def audit_file() -> Path:
    return config_dir() / AUDIT_FILENAME


def load_config_file() -> dict[str, Any]:
    """Read the persisted config file. Corrupt files are ignored, never fatal."""
    path = config_file()
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def save_config_values(values: Mapping[str, Any]) -> Path:
    """Merge ``values`` into the config file and enforce 0600 permissions."""
    ensure_config_dir()
    path = config_file()
    current = load_config_file()
    current.update(values)
    try:
        path.write_text(json.dumps(current, indent=2, sort_keys=True), encoding="utf-8")
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:  # pragma: no cover - permission-denied edge case
        raise ConfigurationError(f"Unable to persist configuration to {path}: {exc}") from exc
    return path


def _first(*candidates: Any) -> Any:
    for candidate in candidates:
        if candidate not in (None, ""):
            return candidate
    return None


class Settings(BaseModel):
    """Immutable, validated runtime settings for a single tfmedic invocation."""

    model_config = ConfigDict(frozen=True, protected_namespaces=())

    model: str = Field(default=DEFAULT_MODEL, description="LLM model identifier.")
    llm_base_url: str | None = Field(default=None, description="OpenAI-compatible base URL.")
    api_key: SecretStr | None = Field(default=None, repr=False)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    request_timeout: int = Field(default=DEFAULT_REQUEST_TIMEOUT_SECONDS, ge=5, le=600)
    max_retries: int = Field(default=3, ge=0, le=8)

    aws_profile: str | None = None
    aws_region: str = DEFAULT_REGION

    terraform_dir: Path = Field(default_factory=Path.cwd)
    terraform_binary: str = "terraform"

    max_iterations: int = Field(default=DEFAULT_MAX_ITERATIONS, ge=1, le=50)
    ssm_timeout: int = Field(default=DEFAULT_SSM_TIMEOUT_SECONDS, ge=10, le=900)

    auto_approve: bool = False
    read_only: bool = False
    audit_enabled: bool = True
    verbose: bool = False

    @property
    def is_local_llm(self) -> bool:
        """True when pointed at a self-hosted, OpenAI-compatible endpoint."""
        if not self.llm_base_url:
            return False
        lowered = self.llm_base_url.lower()
        local_hosts = ("localhost", "127.0.0.1", "0.0.0.0", "::1")  # noqa: S104 - substring match
        return any(token in lowered for token in local_hosts)

    def resolved_api_key(self) -> str:
        """Return a usable API key string.

        Self-hosted runtimes (Ollama, vLLM, LM Studio) ignore the key but the
        OpenAI SDK still requires a non-empty value.
        """
        if self.api_key is not None:
            secret = self.api_key.get_secret_value()
            if secret:
                return secret
        if self.is_local_llm:
            return "not-needed"
        raise ConfigurationError(
            "No LLM API key configured. Set OPENAI_API_KEY, run `tfmedic configure`, "
            "or point TFMEDIC_LLM_URL at a local OpenAI-compatible endpoint."
        )

    @classmethod
    def from_env(
        cls,
        *,
        env: Mapping[str, str] | None = None,
        file_values: Mapping[str, Any] | None = None,
        **overrides: Any,
    ) -> Settings:
        """Build settings from CLI overrides > env > config file > defaults."""
        env = os.environ if env is None else env
        stored = dict(load_config_file() if file_values is None else file_values)

        raw_key = _first(
            overrides.pop("api_key", None),
            env.get("TFMEDIC_API_KEY"),
            env.get("OPENAI_API_KEY"),
            stored.get("api_key"),
        )
        terraform_dir = _first(
            overrides.pop("terraform_dir", None),
            env.get("TFMEDIC_TERRAFORM_DIR"),
            stored.get("terraform_dir"),
            Path.cwd(),
        )

        values: dict[str, Any] = {
            "model": _first(
                overrides.pop("model", None),
                env.get("TFMEDIC_MODEL"),
                stored.get("model"),
                DEFAULT_MODEL,
            ),
            "llm_base_url": _first(
                overrides.pop("llm_base_url", None),
                env.get("TFMEDIC_LLM_URL"),
                env.get("OPENAI_BASE_URL"),
                stored.get("llm_base_url"),
            ),
            "api_key": SecretStr(str(raw_key)) if raw_key else None,
            "aws_profile": _first(
                overrides.pop("aws_profile", None),
                env.get("AWS_PROFILE"),
                stored.get("aws_profile"),
            ),
            "aws_region": _first(
                overrides.pop("aws_region", None),
                env.get("AWS_REGION"),
                env.get("AWS_DEFAULT_REGION"),
                stored.get("aws_region"),
                DEFAULT_REGION,
            ),
            "terraform_dir": Path(str(terraform_dir)).expanduser(),
            "terraform_binary": _first(
                env.get("TFMEDIC_TERRAFORM_BIN"), stored.get("terraform_binary"), "terraform"
            ),
            "max_iterations": int(
                _first(
                    overrides.pop("max_iterations", None),
                    env.get("TFMEDIC_MAX_ITERATIONS"),
                    stored.get("max_iterations"),
                    DEFAULT_MAX_ITERATIONS,
                )
            ),
            "ssm_timeout": int(
                _first(
                    overrides.pop("ssm_timeout", None),
                    env.get("TFMEDIC_SSM_TIMEOUT"),
                    stored.get("ssm_timeout"),
                    DEFAULT_SSM_TIMEOUT_SECONDS,
                )
            ),
        }
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)
