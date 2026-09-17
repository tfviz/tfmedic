"""Execution providers.

Dependency inversion lives here: tools depend on the narrow ``AwsClientFactory``
and ``CommandRunner`` protocols, never on boto3 or ``subprocess`` directly. That
keeps the agent core testable with in-memory fakes and makes swapping the
underlying SDK a local change.
"""

from __future__ import annotations

import os
import subprocess
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from tfmedic.exceptions import ConfigurationError, ProviderError


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a local subprocess invocation."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandRunner(Protocol):
    """Runs a local, argv-style command. No shell interpolation, ever."""

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        timeout: int = 60,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult: ...


class SubprocessRunner:
    """Default :class:`CommandRunner` backed by :mod:`subprocess`."""

    def run(
        self,
        command: Sequence[str],
        *,
        cwd: str | None = None,
        timeout: int = 60,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        argv = [str(part) for part in command]
        merged_env = {**os.environ, **(env or {})}
        try:
            completed = subprocess.run(  # noqa: S603 - argv list, shell=False
                argv,
                cwd=cwd,
                env=merged_env,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ProviderError(
                f"Executable '{argv[0]}' not found on PATH. Install it or set the binary path."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise ProviderError(
                f"Command '{' '.join(argv)}' exceeded the {timeout}s timeout."
            ) from exc
        except OSError as exc:  # pragma: no cover - permission / fork failures
            raise ProviderError(f"Failed to execute '{' '.join(argv)}': {exc}") from exc
        return CommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


class AwsClientFactory(Protocol):
    """Supplies cached, region-bound AWS service clients."""

    region: str

    def client(self, service_name: str) -> Any: ...


class Boto3ClientFactory:
    """Thread-safe boto3 session wrapper.

    Credentials are never handled by tfmedic itself: the standard chain
    (``AWS_PROFILE``, static env vars, SSO cache, instance IAM role) is used.
    """

    def __init__(
        self,
        profile: str | None = None,
        region: str | None = None,
        *,
        connect_timeout: int = 10,
        read_timeout: int = 60,
        max_attempts: int = 4,
    ) -> None:
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError, ProfileNotFound
        except ImportError as exc:  # pragma: no cover - packaging guard
            raise ProviderError("boto3 is required: pip install 'tfmedic[aws]'") from exc

        try:
            self._session = boto3.Session(profile_name=profile, region_name=region)
        except ProfileNotFound as exc:
            raise ConfigurationError(f"AWS profile '{profile}' was not found.") from exc
        except BotoCoreError as exc:  # pragma: no cover - malformed local config
            raise ConfigurationError(f"Unable to initialise AWS session: {exc}") from exc

        self.profile = profile or self._session.profile_name
        self.region = self._session.region_name or region or "us-east-1"
        self._config = Config(
            region_name=self.region,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
            retries={"max_attempts": max_attempts, "mode": "adaptive"},
            user_agent_extra="tfmedic/0.1.0",
        )
        self._clients: dict[str, Any] = {}
        self._lock = threading.Lock()

    def client(self, service_name: str) -> Any:
        with self._lock:
            if service_name not in self._clients:
                self._clients[service_name] = self._session.client(
                    service_name, config=self._config
                )
            return self._clients[service_name]

    def caller_identity(self) -> dict[str, str]:
        """Resolve the active principal; used by ``tfmedic doctor``."""
        try:
            identity = self.client("sts").get_caller_identity()
        except Exception as exc:  # noqa: BLE001 - surfaced as a config error
            raise ConfigurationError(f"AWS credentials are not usable: {exc}") from exc
        return {
            "account": identity.get("Account", ""),
            "arn": identity.get("Arn", ""),
            "user_id": identity.get("UserId", ""),
        }
