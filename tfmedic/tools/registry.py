"""Tool registry: the seam between agent reasoning and concrete SDK calls.

The agent knows only names and JSON schemas. Swapping boto3 for another SDK, or
wiring a fake for tests, happens here and nowhere else.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import Any

from tfmedic.config import Settings
from tfmedic.exceptions import ToolExecutionError
from tfmedic.providers import AwsClientFactory, CommandRunner, SubprocessRunner
from tfmedic.tools.base import BaseTool


class ToolRegistry:
    """Ordered, name-unique collection of tools."""

    def __init__(self, tools: Sequence[BaseTool[Any]] | None = None) -> None:
        self._tools: dict[str, BaseTool[Any]] = {}
        for tool in tools or ():
            self.register(tool)

    def register(self, tool: BaseTool[Any]) -> None:
        if not tool.name:
            raise ToolExecutionError(f"{type(tool).__name__} does not define a tool name.")
        if tool.name in self._tools:
            raise ToolExecutionError(f"Duplicate tool name registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool[Any]:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise ToolExecutionError(f"Unknown tool '{name}'.") from exc

    def has(self, name: str) -> bool:
        return name in self._tools

    def all(self) -> list[BaseTool[Any]]:
        return list(self._tools.values())

    def read_tools(self) -> list[BaseTool[Any]]:
        return [tool for tool in self._tools.values() if not tool.is_write_operation]

    def write_tools(self) -> list[BaseTool[Any]]:
        return [tool for tool in self._tools.values() if tool.is_write_operation]

    def schemas(self) -> list[dict[str, Any]]:
        return [tool.openai_schema() for tool in self._tools.values()]

    def __iter__(self) -> Iterator[BaseTool[Any]]:
        return iter(self._tools.values())

    def __len__(self) -> int:
        return len(self._tools)


def build_default_registry(
    settings: Settings,
    aws: AwsClientFactory,
    *,
    runner: CommandRunner | None = None,
) -> ToolRegistry:
    """Wire the production tool set for a three-tier web application stack."""
    # Imported lazily so the registry module stays import-cheap for tests.
    from tfmedic.tools.aws_ec2 import (
        AuthorizeSecurityGroupIngressTool,
        DescribeEc2InstanceTool,
        DescribeSecurityGroupsTool,
        RebootEc2InstanceTool,
    )
    from tfmedic.tools.aws_rds import DescribeRdsInstanceTool, RdsConnectionMetricsTool
    from tfmedic.tools.aws_ssm import (
        RestartDockerContainerTool,
        RestartSystemdServiceTool,
        RunSsmDiagnosticTool,
        SsmCommandExecutor,
    )
    from tfmedic.tools.terraform import (
        ListTerraformResourcesTool,
        ReadTerraformStateTool,
        TerraformStateReader,
    )

    ssm = SsmCommandExecutor(aws, timeout=settings.ssm_timeout)
    terraform = TerraformStateReader(
        runner=runner or SubprocessRunner(),
        working_dir=settings.terraform_dir,
        binary=settings.terraform_binary,
    )

    return ToolRegistry(
        [
            # --- READ: autonomous reconnaissance ---------------------------
            DescribeEc2InstanceTool(aws),
            DescribeSecurityGroupsTool(aws),
            RunSsmDiagnosticTool(ssm),
            DescribeRdsInstanceTool(aws),
            RdsConnectionMetricsTool(aws),
            ListTerraformResourcesTool(terraform),
            ReadTerraformStateTool(terraform),
            # --- WRITE: gate-protected state mutation ----------------------
            AuthorizeSecurityGroupIngressTool(aws),
            RestartDockerContainerTool(ssm),
            RestartSystemdServiceTool(ssm),
            RebootEc2InstanceTool(aws),
        ]
    )
