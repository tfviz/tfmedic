"""RDS tools: instance state, endpoint topology and CloudWatch connection pressure."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from tfmedic.providers import AwsClientFactory
from tfmedic.tools.base import BaseTool, ToolResult

_HEALTHY_STATES = {"available"}
_TRANSITIONAL_STATES = {
    "backing-up",
    "configuring-enhanced-monitoring",
    "modifying",
    "rebooting",
    "starting",
    "upgrading",
}


class DescribeRdsInstanceArgs(BaseModel):
    db_instance_identifier: str | None = Field(
        default=None,
        max_length=63,
        description="RDS instance identifier. Omit to list every instance in the region.",
    )

    @field_validator("db_instance_identifier")
    @classmethod
    def _validate_identifier(cls, value: str | None) -> str | None:
        import re

        if value is None:
            return None
        if not re.match(r"^[A-Za-z][A-Za-z0-9-]{0,62}$", value):
            raise ValueError("must be a valid RDS DB instance identifier")
        return value


class DescribeRdsInstanceTool(BaseTool[DescribeRdsInstanceArgs]):
    name = "describe_rds_instance"
    description = """
    Describe one or all RDS instances: lifecycle status, endpoint address and port, engine and
    version, Multi-AZ, storage, publicly_accessible, attached VPC security groups and subnet
    group. Use this to confirm whether a database is actually 'available' and to learn the exact
    endpoint and port an application should be reaching, before chasing application-side bugs.
    """
    args_model = DescribeRdsInstanceArgs
    is_write_operation = False

    def __init__(self, aws: AwsClientFactory) -> None:
        self._aws = aws

    def run(self, args: DescribeRdsInstanceArgs) -> ToolResult:
        rds = self._aws.client("rds")
        kwargs: dict[str, Any] = {}
        if args.db_instance_identifier:
            kwargs["DBInstanceIdentifier"] = args.db_instance_identifier

        instances = rds.describe_db_instances(**kwargs).get("DBInstances", [])
        if not instances:
            return ToolResult.failure(
                summary="No RDS instances found",
                error="describe_db_instances returned an empty result set for this region.",
            )

        described = [_normalise_instance(instance) for instance in instances]
        unhealthy = [i for i in described if i["status"] not in _HEALTHY_STATES]
        if unhealthy:
            summary = "Unhealthy RDS: " + ", ".join(
                f"{i['identifier']}={i['status']}" for i in unhealthy
            )
        else:
            summary = "All inspected RDS instances report status=available: " + ", ".join(
                f"{i['identifier']} @ {i['endpoint']}:{i['port']}" for i in described
            )
        return ToolResult.success(
            summary,
            db_instances=described,
            unhealthy_count=len(unhealthy),
            transitional_states=sorted(_TRANSITIONAL_STATES),
        )


class RdsConnectionMetricsArgs(BaseModel):
    db_instance_identifier: str = Field(max_length=63)
    minutes: int = Field(default=60, ge=5, le=1440, description="Look-back window in minutes.")
    period_seconds: int = Field(default=300, ge=60, le=3600, description="Datapoint period.")


class RdsConnectionMetricsTool(BaseTool[RdsConnectionMetricsArgs]):
    name = "get_rds_connection_metrics"
    description = """
    Fetch CloudWatch DatabaseConnections, CPUUtilization and FreeableMemory for an RDS instance
    over a look-back window. Use this to separate 'the database refuses connections' (connection
    count pinned at the max, memory exhausted) from 'the network blocks connections' (connection
    count flat at zero while the application reports timeouts) - the two have completely
    different remediations.
    """
    args_model = RdsConnectionMetricsArgs
    is_write_operation = False

    _METRICS = (
        ("DatabaseConnections", "Count"),
        ("CPUUtilization", "Percent"),
        ("FreeableMemory", "Bytes"),
    )

    def __init__(self, aws: AwsClientFactory) -> None:
        self._aws = aws

    def run(self, args: RdsConnectionMetricsArgs) -> ToolResult:
        cloudwatch = self._aws.client("cloudwatch")
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=args.minutes)

        metrics: dict[str, Any] = {}
        for metric_name, unit in self._METRICS:
            response = cloudwatch.get_metric_statistics(
                Namespace="AWS/RDS",
                MetricName=metric_name,
                Dimensions=[
                    {"Name": "DBInstanceIdentifier", "Value": args.db_instance_identifier}
                ],
                StartTime=start,
                EndTime=end,
                Period=args.period_seconds,
                Statistics=["Average", "Maximum"],
                Unit=unit,
            )
            datapoints = sorted(
                response.get("Datapoints", []), key=lambda point: point.get("Timestamp")
            )
            metrics[metric_name] = {
                "unit": unit,
                "datapoint_count": len(datapoints),
                "latest": _format_point(datapoints[-1]) if datapoints else None,
                "maximum": max((p.get("Maximum", 0) for p in datapoints), default=None),
                "average": (
                    round(sum(p.get("Average", 0) for p in datapoints) / len(datapoints), 2)
                    if datapoints
                    else None
                ),
            }

        connections = metrics.get("DatabaseConnections", {})
        if connections.get("datapoint_count", 0) == 0:
            summary = (
                f"No DatabaseConnections datapoints for {args.db_instance_identifier} in the last "
                f"{args.minutes}m - the instance may be idle, unreachable, or the identifier wrong."
            )
        else:
            summary = (
                f"{args.db_instance_identifier}: connections avg={connections.get('average')} "
                f"max={connections.get('maximum')} over {args.minutes}m"
            )
        return ToolResult.success(
            summary,
            db_instance_identifier=args.db_instance_identifier,
            window_minutes=args.minutes,
            metrics=metrics,
        )


def _normalise_instance(instance: Mapping[str, Any]) -> dict[str, Any]:
    endpoint = instance.get("Endpoint") or {}
    return {
        "identifier": instance.get("DBInstanceIdentifier"),
        "status": instance.get("DBInstanceStatus"),
        "engine": f"{instance.get('Engine')} {instance.get('EngineVersion', '')}".strip(),
        "instance_class": instance.get("DBInstanceClass"),
        "endpoint": endpoint.get("Address"),
        "port": endpoint.get("Port"),
        "multi_az": instance.get("MultiAZ"),
        "publicly_accessible": instance.get("PubliclyAccessible"),
        "storage_gb": instance.get("AllocatedStorage"),
        "max_allocated_storage_gb": instance.get("MaxAllocatedStorage"),
        "availability_zone": instance.get("AvailabilityZone"),
        "vpc_id": (instance.get("DBSubnetGroup") or {}).get("VpcId"),
        "db_subnet_group": (instance.get("DBSubnetGroup") or {}).get("DBSubnetGroupName"),
        "vpc_security_groups": [
            {
                "group_id": sg.get("VpcSecurityGroupId"),
                "status": sg.get("Status"),
            }
            for sg in instance.get("VpcSecurityGroups", [])
        ],
        "parameter_groups": [
            pg.get("DBParameterGroupName") for pg in instance.get("DBParameterGroups", [])
        ],
        "pending_modified_values": instance.get("PendingModifiedValues") or {},
    }


def _format_point(point: Mapping[str, Any]) -> dict[str, Any]:
    timestamp = point.get("Timestamp")
    return {
        "timestamp": timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp),
        "average": point.get("Average"),
        "maximum": point.get("Maximum"),
    }
