"""Terraform state tools.

Runtime telemetry alone cannot tell you whether a live resource matches intent.
These tools parse ``terraform show -json`` so the agent can correlate what the
cloud *is* doing with what the code *says* it should do - which is how
configuration drift gets named rather than guessed at.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from tfmedic.exceptions import ProviderError, ToolExecutionError
from tfmedic.providers import CommandRunner
from tfmedic.tools.base import BaseTool, EmptyArgs, ToolResult

_NOISY_ATTRIBUTES = {"user_data", "user_data_base64", "policy", "assume_role_policy", "body"}
_MAX_ATTRIBUTE_CHARS = 1200


class TerraformStateReader:
    """Runs and caches ``terraform show -json`` for the working directory."""

    def __init__(
        self,
        runner: CommandRunner,
        working_dir: Path | str,
        *,
        binary: str = "terraform",
        timeout: int = 120,
    ) -> None:
        self._runner = runner
        self._working_dir = Path(working_dir)
        self._binary = binary
        self._timeout = timeout
        self._cache: dict[str, Any] | None = None

    @property
    def working_dir(self) -> Path:
        return self._working_dir

    def load(self, *, refresh: bool = False) -> dict[str, Any]:
        if self._cache is not None and not refresh:
            return self._cache
        if not self._working_dir.is_dir():
            raise ToolExecutionError(
                f"Terraform working directory '{self._working_dir}' does not exist. "
                "Re-run tfmedic with --terraform-dir pointing at your root module."
            )
        result = self._runner.run(
            [self._binary, "show", "-json"],
            cwd=str(self._working_dir),
            timeout=self._timeout,
        )
        if not result.ok:
            stderr = (result.stderr or result.stdout or "").strip()
            raise ProviderError(
                f"`{self._binary} show -json` failed in {self._working_dir} "
                f"(exit {result.returncode}): {stderr[:500]}"
            )
        try:
            parsed = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ProviderError(
                f"`{self._binary} show -json` returned invalid JSON: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise ProviderError("Unexpected Terraform state payload: expected a JSON object.")
        self._cache = parsed
        return parsed

    def resources(self, *, refresh: bool = False) -> list[dict[str, Any]]:
        state = self.load(refresh=refresh)
        root = (state.get("values") or {}).get("root_module") or {}
        return list(_walk_module(root))


class ListTerraformResourcesTool(BaseTool[EmptyArgs]):
    name = "list_terraform_resources"
    description = """
    List every managed resource address in the local Terraform state, grouped by type. Call this
    first to learn what the code actually manages (security groups, instances, RDS, subnets)
    before requesting specific attributes. Cheap, and it prevents guessing resource addresses.
    """
    args_model = EmptyArgs
    is_write_operation = False

    def __init__(self, reader: TerraformStateReader) -> None:
        self._reader = reader

    def run(self, args: EmptyArgs) -> ToolResult:
        resources = self._reader.resources()
        if not resources:
            return ToolResult.failure(
                summary="Terraform state contains no managed resources",
                error=(
                    f"No resources found in {self._reader.working_dir}. Confirm you are pointed at "
                    "the correct root module and that state has been initialised."
                ),
            )
        grouped: dict[str, list[str]] = {}
        for resource in resources:
            grouped.setdefault(str(resource["type"]), []).append(str(resource["address"]))
        return ToolResult.success(
            f"{len(resources)} managed resources across {len(grouped)} types in "
            f"{self._reader.working_dir}",
            working_dir=str(self._reader.working_dir),
            terraform_version=self._reader.load().get("terraform_version"),
            resources_by_type={key: sorted(value) for key, value in sorted(grouped.items())},
        )


class ReadTerraformStateArgs(BaseModel):
    resource_type: str | None = Field(
        default=None, description="Filter by type, e.g. aws_security_group, aws_instance."
    )
    address: str | None = Field(
        default=None, description="Exact resource address, e.g. aws_security_group.db_sg."
    )
    name_filter: str | None = Field(
        default=None, description="Case-insensitive substring match on the resource address."
    )
    max_results: int = Field(default=10, ge=1, le=50)


class ReadTerraformStateTool(BaseTool[ReadTerraformStateArgs]):
    name = "read_terraform_state"
    description = """
    Read declared attributes of resources from the local Terraform state, filtered by type,
    address or substring. Use it to compare intent against runtime: which CIDR a subnet declares,
    which ingress rules a security group is supposed to have, which endpoint an app was wired to.
    A mismatch between this output and the live AWS API response is configuration drift, and
    naming it is usually the diagnosis.
    """
    args_model = ReadTerraformStateArgs
    is_write_operation = False

    def __init__(self, reader: TerraformStateReader) -> None:
        self._reader = reader

    def run(self, args: ReadTerraformStateArgs) -> ToolResult:
        resources = self._reader.resources()
        matched = [
            resource
            for resource in resources
            if _matches(resource, args.resource_type, args.address, args.name_filter)
        ]
        if not matched:
            available = sorted({str(resource["type"]) for resource in resources})
            return ToolResult.failure(
                summary="No Terraform resources matched the filter",
                error=(
                    "Nothing matched. Available types: "
                    + (", ".join(available[:25]) if available else "(state is empty)")
                ),
                available_types=available[:50],
            )
        truncated = matched[: args.max_results]
        return ToolResult.success(
            f"{len(matched)} matching resource(s); returning {len(truncated)}",
            working_dir=str(self._reader.working_dir),
            match_count=len(matched),
            resources=[
                {
                    "address": resource["address"],
                    "type": resource["type"],
                    "name": resource["name"],
                    "provider": resource["provider"],
                    "attributes": _prune(resource["values"]),
                }
                for resource in truncated
            ],
        )


def _walk_module(module: Mapping[str, Any], prefix: str = "") -> Iterator[dict[str, Any]]:
    for resource in module.get("resources", []) or []:
        if resource.get("mode") not in (None, "managed"):
            continue
        address = f"{prefix}{resource.get('address', '')}"
        yield {
            "address": address,
            "type": resource.get("type", ""),
            "name": resource.get("name", ""),
            "provider": resource.get("provider_name", ""),
            "values": resource.get("values", {}) or {},
        }
    for child in module.get("child_modules", []) or []:
        yield from _walk_module(child, prefix)


def _matches(
    resource: Mapping[str, Any],
    resource_type: str | None,
    address: str | None,
    name_filter: str | None,
) -> bool:
    if address and str(resource.get("address")) != address:
        return False
    if resource_type and str(resource.get("type")) != resource_type:
        return False
    return not (
        name_filter and name_filter.lower() not in str(resource.get("address", "")).lower()
    )


def _prune(values: Mapping[str, Any]) -> dict[str, Any]:
    """Drop bulky, low-signal attributes before they reach the context window."""
    pruned: dict[str, Any] = {}
    for key, value in values.items():
        if key in _NOISY_ATTRIBUTES:
            pruned[key] = "<omitted by tfmedic>"
            continue
        rendered = json.dumps(value, default=str) if not isinstance(value, str) else value
        if len(rendered) > _MAX_ATTRIBUTE_CHARS:
            pruned[key] = rendered[:_MAX_ATTRIBUTE_CHARS] + "…[truncated]"
        else:
            pruned[key] = value
    return pruned
