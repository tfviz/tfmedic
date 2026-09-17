"""AWS Systems Manager tools: keyless container and host diagnostics.

SSM removes the SSH bastion from the incident path. Critically, the LLM never
supplies a shell string: it selects a diagnostic from a closed enum and fills
validated parameters, and this module deterministically renders the command.
"""

from __future__ import annotations

import re
import shlex
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from tfmedic.exceptions import ProviderError, ToolExecutionError
from tfmedic.providers import AwsClientFactory
from tfmedic.tools.base import BaseTool, ToolResult

INSTANCE_ID_PATTERN = r"^i-[0-9a-fA-F]{8,17}$"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
_SAFE_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,253}$")

MAX_STREAM_CHARS = 1_500  # truncate long stdout/stderr to avoid LLM context overflow
TERMINAL_STATES = {"Success", "Failed", "Cancelled", "TimedOut", "Undeliverable", "Terminated"}


class SsmDiagnostic(str, Enum):
    """Closed set of read-only host diagnostics."""

    DOCKER_PS = "docker_ps"
    DOCKER_LOGS = "docker_logs"
    DOCKER_INSPECT = "docker_inspect"
    DOCKER_STATS = "docker_stats"
    SYSTEM_RESOURCES = "system_resources"
    DISK_USAGE = "disk_usage"
    LISTENING_PORTS = "listening_ports"
    SERVICE_STATUS = "service_status"
    JOURNAL_TAIL = "journal_tail"
    TCP_CONNECTIVITY = "tcp_connectivity"
    DNS_RESOLVE = "dns_resolve"


@dataclass(frozen=True)
class SsmInvocation:
    """Normalised result of one ``AWS-RunShellScript`` invocation."""

    command_id: str
    status: str
    response_code: int | None
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.status == "Success"


class SsmCommandExecutor:
    """Sends shell payloads through SSM and polls to a terminal state."""

    def __init__(
        self,
        aws: AwsClientFactory,
        *,
        timeout: int = 60,
        poll_interval: float = 2.0,
    ) -> None:
        self._aws = aws
        self._timeout = timeout
        self._poll_interval = poll_interval

    def run_shell(
        self,
        instance_id: str,
        commands: Sequence[str],
        *,
        comment: str = "tfmedic diagnostic",
    ) -> SsmInvocation:
        ssm = self._aws.client("ssm")
        send = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Comment=comment[:100],
            Parameters={
                "commands": list(commands),
                "executionTimeout": [str(max(30, self._timeout))],
            },
        )
        command_id = send["Command"]["CommandId"]

        deadline = time.monotonic() + self._timeout + 15
        invocation: dict[str, Any] = {}
        while time.monotonic() < deadline:
            try:
                invocation = ssm.get_command_invocation(
                    CommandId=command_id, InstanceId=instance_id
                )
            except Exception as exc:  # noqa: BLE001 - eventual consistency window
                if type(exc).__name__ != "InvocationDoesNotExist":
                    raise
                time.sleep(self._poll_interval)
                continue
            if invocation.get("Status") in TERMINAL_STATES:
                break
            time.sleep(self._poll_interval)
        else:
            raise ProviderError(
                f"SSM command {command_id} did not reach a terminal state within "
                f"{self._timeout}s. The SSM agent may be offline on {instance_id}."
            )

        return SsmInvocation(
            command_id=command_id,
            status=str(invocation.get("Status", "Unknown")),
            response_code=invocation.get("ResponseCode"),
            stdout=_tail(invocation.get("StandardOutputContent", "")),
            stderr=_tail(invocation.get("StandardErrorContent", "")),
        )


# --------------------------------------------------------------------------- #
# READ: run_ssm_diagnostic
# --------------------------------------------------------------------------- #
class RunSsmDiagnosticArgs(BaseModel):
    instance_id: str = Field(pattern=INSTANCE_ID_PATTERN)
    diagnostic: SsmDiagnostic = Field(description="Which read-only diagnostic to run.")
    container: str | None = Field(
        default=None, description="Container name or id (docker_* diagnostics)."
    )
    service: str | None = Field(
        default=None, description="systemd unit name (service_status, journal_tail)."
    )
    host: str | None = Field(
        default=None, description="Target hostname or IP (tcp_connectivity, dns_resolve)."
    )
    port: int | None = Field(
        default=None, ge=1, le=65535, description="Target port (tcp_connectivity)."
    )
    tail_lines: int = Field(default=20, ge=1, le=1000, description="Log lines to return.")

    @field_validator("container", "service")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SAFE_NAME.match(value):
            raise ValueError(
                "must match ^[A-Za-z0-9][A-Za-z0-9_.@:-]*$ (no shell metacharacters)"
            )
        return value

    @field_validator("host")
    @classmethod
    def _validate_host(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _SAFE_HOST.match(value):
            raise ValueError("must be a plain hostname or IP address")
        return value

    @model_validator(mode="after")
    def _validate_requirements(self) -> RunSsmDiagnosticArgs:
        needs_container = {
            SsmDiagnostic.DOCKER_LOGS,
            SsmDiagnostic.DOCKER_INSPECT,
        }
        needs_service = {SsmDiagnostic.SERVICE_STATUS, SsmDiagnostic.JOURNAL_TAIL}
        if self.diagnostic in needs_container and not self.container:
            raise ValueError(f"'container' is required for {self.diagnostic.value}")
        if self.diagnostic in needs_service and not self.service:
            raise ValueError(f"'service' is required for {self.diagnostic.value}")
        if self.diagnostic is SsmDiagnostic.TCP_CONNECTIVITY and not (self.host and self.port):
            raise ValueError("'host' and 'port' are required for tcp_connectivity")
        if self.diagnostic is SsmDiagnostic.DNS_RESOLVE and not self.host:
            raise ValueError("'host' is required for dns_resolve")
        return self


def build_diagnostic_commands(args: RunSsmDiagnosticArgs) -> list[str]:
    """Deterministically render the shell payload for a diagnostic.

    Every interpolated value has already passed a strict allow-list validator and
    is shell-quoted again here. Defence in depth against command injection.
    """
    container = shlex.quote(args.container) if args.container else ""
    service = shlex.quote(args.service) if args.service else ""
    host = shlex.quote(args.host) if args.host else ""

    if args.diagnostic is SsmDiagnostic.DOCKER_PS:
        return [
            "docker ps -a --format "
            "'table {{.Names}}\\t{{.Image}}\\t{{.Status}}\\t{{.Ports}}' 2>&1 | head -50"
        ]
    if args.diagnostic is SsmDiagnostic.DOCKER_LOGS:
        return [
            f"docker logs --tail {args.tail_lines} --timestamps {container} "
            f"2>&1 | tail -{args.tail_lines}"
        ]
    if args.diagnostic is SsmDiagnostic.DOCKER_INSPECT:
        return [
            f"docker inspect {container} --format 'STATE={{{{json .State}}}}' 2>&1",
            f"docker inspect {container} --format 'RESTART_COUNT={{{{.RestartCount}}}}' 2>&1",
            f"docker inspect {container} --format 'PORTS={{{{json .NetworkSettings.Ports}}}}' 2>&1",
            f"docker inspect {container} --format 'ENV={{{{json .Config.Env}}}}' 2>&1",
            f"docker inspect {container} --format 'CMD={{{{json .Config.Cmd}}}}' 2>&1",
        ]
    if args.diagnostic is SsmDiagnostic.DOCKER_STATS:
        return [
            "docker stats --no-stream --format "
            "'table {{.Name}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.MemPerc}}' 2>&1 | head -30"
        ]
    if args.diagnostic is SsmDiagnostic.SYSTEM_RESOURCES:
        return [
            "uptime",
            "free -m",
            "top -b -n 1 | head -20",
            "dmesg -T 2>/dev/null | grep -i -E 'oom|killed process' | tail -10 || true",
        ]
    if args.diagnostic is SsmDiagnostic.DISK_USAGE:
        return ["df -h", "du -sh /var/lib/docker 2>/dev/null || true"]
    if args.diagnostic is SsmDiagnostic.LISTENING_PORTS:
        return ["(ss -tulpn || netstat -tulpn) 2>&1 | head -40"]
    if args.diagnostic is SsmDiagnostic.SERVICE_STATUS:
        return [f"systemctl status {service} --no-pager --lines 20 2>&1"]
    if args.diagnostic is SsmDiagnostic.JOURNAL_TAIL:
        return [f"journalctl -u {service} --no-pager -n {args.tail_lines} 2>&1"]
    if args.diagnostic is SsmDiagnostic.TCP_CONNECTIVITY:
        return [
            f"timeout 5 bash -c 'cat < /dev/null > /dev/tcp/{args.host}/{args.port}' "
            f"&& echo 'TCP_OPEN {args.host}:{args.port}' "
            f"|| echo 'TCP_BLOCKED {args.host}:{args.port}'"
        ]
    if args.diagnostic is SsmDiagnostic.DNS_RESOLVE:
        return [f"getent hosts {host} || nslookup {host} 2>&1 | tail -10"]
    raise ToolExecutionError(f"Unsupported diagnostic: {args.diagnostic}")


class RunSsmDiagnosticTool(BaseTool[RunSsmDiagnosticArgs]):
    name = "run_ssm_diagnostic"
    description = """
    Run a read-only diagnostic on an EC2 instance through AWS Systems Manager, with no SSH key.
    Choose one diagnostic: docker_ps (container states and restart loops), docker_logs (tail
    application logs), docker_inspect (exit code, restart count, env, port bindings),
    docker_stats, system_resources (load, memory, OOM kills), disk_usage, listening_ports,
    service_status and journal_tail (systemd), tcp_connectivity (prove whether a host:port is
    reachable from the instance) and dns_resolve. Requires the SSM agent and an instance profile
    with AmazonSSMManagedInstanceCore.
    """
    args_model = RunSsmDiagnosticArgs
    is_write_operation = False

    def __init__(self, executor: SsmCommandExecutor) -> None:
        self._executor = executor

    def run(self, args: RunSsmDiagnosticArgs) -> ToolResult:
        commands = build_diagnostic_commands(args)
        invocation = self._executor.run_shell(
            args.instance_id, commands, comment=f"tfmedic {args.diagnostic.value}"
        )
        data = {
            "instance_id": args.instance_id,
            "diagnostic": args.diagnostic.value,
            "command_id": invocation.command_id,
            "ssm_status": invocation.status,
            "exit_code": invocation.response_code,
            "stdout": invocation.stdout,
            "stderr": invocation.stderr,
        }
        if not invocation.ok:
            return ToolResult.failure(
                summary=f"{args.diagnostic.value} on {args.instance_id} -> {invocation.status}",
                error=invocation.stderr or f"SSM status {invocation.status}",
                **data,
            )
        return ToolResult.success(
            f"{args.diagnostic.value} on {args.instance_id} completed "
            f"(exit {invocation.response_code}, {len(invocation.stdout)} chars stdout)",
            **data,
        )


# --------------------------------------------------------------------------- #
# WRITE: restart_docker_container
# --------------------------------------------------------------------------- #
class RestartDockerContainerArgs(BaseModel):
    instance_id: str = Field(pattern=INSTANCE_ID_PATTERN)
    container: str = Field(description="Container name or id to restart.")
    reason: str = Field(min_length=8, max_length=500, description="Why the restart is warranted.")

    @field_validator("container")
    @classmethod
    def _validate_container(cls, value: str) -> str:
        if not _SAFE_NAME.match(value):
            raise ValueError("container must match ^[A-Za-z0-9][A-Za-z0-9_.@:-]*$")
        return value


class RestartDockerContainerTool(BaseTool[RestartDockerContainerArgs]):
    name = "restart_docker_container"
    description = """
    WRITE OPERATION (requires human approval). Restart a Docker container on an EC2 instance via
    SSM, then re-read its state so the outcome is verified rather than assumed. Only restart once
    the underlying cause is understood: restarting a crash-looping container without fixing its
    dependency simply restarts the loop.
    """
    args_model = RestartDockerContainerArgs
    is_write_operation = True
    action_id = "aws:ssm:SendCommand(docker restart)"

    def __init__(self, executor: SsmCommandExecutor) -> None:
        self._executor = executor

    def target_resource(self, arguments: Mapping[str, Any]) -> str:
        return f"{arguments.get('container', '?')} @ {arguments.get('instance_id', '?')}"

    def change_preview(self, arguments: Mapping[str, Any]) -> Sequence[tuple[str, str]]:
        return (
            ("Change", f"docker restart {arguments.get('container', '?')}"),
            ("Blast radius", "in-flight requests to this container will be dropped"),
        )

    def run(self, args: RestartDockerContainerArgs) -> ToolResult:
        container = shlex.quote(args.container)
        invocation = self._executor.run_shell(
            args.instance_id,
            [
                f"docker restart {container} 2>&1",
                "sleep 3",
                f"docker ps -a --filter name={container} "
                "--format '{{.Names}} {{.Status}} {{.Ports}}' 2>&1",
            ],
            comment=f"tfmedic restart {args.container}",
        )
        data = {
            "instance_id": args.instance_id,
            "container": args.container,
            "command_id": invocation.command_id,
            "ssm_status": invocation.status,
            "exit_code": invocation.response_code,
            "stdout": invocation.stdout,
            "stderr": invocation.stderr,
            "reason": args.reason,
        }
        if not invocation.ok:
            return ToolResult.failure(
                summary=f"Restart of {args.container} failed ({invocation.status})",
                error=invocation.stderr or f"SSM status {invocation.status}",
                **data,
            )
        return ToolResult.success(
            f"Restarted {args.container} on {args.instance_id}; post-restart state captured",
            **data,
        )


# --------------------------------------------------------------------------- #
# WRITE: restart_systemd_service
# --------------------------------------------------------------------------- #
class RestartSystemdServiceArgs(BaseModel):
    instance_id: str = Field(pattern=INSTANCE_ID_PATTERN)
    service: str = Field(description="systemd unit name, e.g. docker or nginx.")
    reason: str = Field(min_length=8, max_length=500)

    @field_validator("service")
    @classmethod
    def _validate_service(cls, value: str) -> str:
        if not _SAFE_NAME.match(value):
            raise ValueError("service must match ^[A-Za-z0-9][A-Za-z0-9_.@:-]*$")
        return value


class RestartSystemdServiceTool(BaseTool[RestartSystemdServiceArgs]):
    name = "restart_systemd_service"
    description = """
    WRITE OPERATION (requires human approval). Restart a systemd unit on an EC2 instance via SSM
    and capture the resulting unit status. Use for host-level daemons (docker, nginx, the app
    unit) when container-level remediation is not applicable.
    """
    args_model = RestartSystemdServiceArgs
    is_write_operation = True
    action_id = "aws:ssm:SendCommand(systemctl restart)"

    def __init__(self, executor: SsmCommandExecutor) -> None:
        self._executor = executor

    def target_resource(self, arguments: Mapping[str, Any]) -> str:
        return f"{arguments.get('service', '?')} @ {arguments.get('instance_id', '?')}"

    def change_preview(self, arguments: Mapping[str, Any]) -> Sequence[tuple[str, str]]:
        return (
            ("Change", f"systemctl restart {arguments.get('service', '?')}"),
            ("Blast radius", "every workload depending on this unit on the host"),
        )

    def run(self, args: RestartSystemdServiceArgs) -> ToolResult:
        service = shlex.quote(args.service)
        invocation = self._executor.run_shell(
            args.instance_id,
            [
                f"systemctl restart {service} 2>&1",
                "sleep 2",
                f"systemctl status {service} --no-pager --lines 10 2>&1",
            ],
            comment=f"tfmedic restart {args.service}",
        )
        data = {
            "instance_id": args.instance_id,
            "service": args.service,
            "command_id": invocation.command_id,
            "ssm_status": invocation.status,
            "exit_code": invocation.response_code,
            "stdout": invocation.stdout,
            "stderr": invocation.stderr,
            "reason": args.reason,
        }
        if not invocation.ok:
            return ToolResult.failure(
                summary=f"Restart of {args.service} failed ({invocation.status})",
                error=invocation.stderr or f"SSM status {invocation.status}",
                **data,
            )
        return ToolResult.success(
            f"Restarted {args.service} on {args.instance_id}; unit status captured", **data
        )


def _tail(content: str | None, limit: int = MAX_STREAM_CHARS) -> str:
    text = content or ""
    if len(text) <= limit:
        return text
    return f"…[{len(text) - limit} earlier chars truncated]\n" + text[-limit:]
