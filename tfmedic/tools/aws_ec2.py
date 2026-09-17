"""EC2 and VPC tools: instance topology, security-group inspection, ingress repair."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from tfmedic.providers import AwsClientFactory
from tfmedic.tools.base import BaseTool, ToolResult

INSTANCE_ID_PATTERN = r"^i-[0-9a-fA-F]{8,17}$"
SECURITY_GROUP_PATTERN = r"^sg-[0-9a-fA-F]{8,17}$"
VPC_PATTERN = r"^vpc-[0-9a-fA-F]{8,17}$"
CIDR_PATTERN = r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$"


# --------------------------------------------------------------------------- #
# READ: describe_ec2_instance
# --------------------------------------------------------------------------- #
class DescribeEc2InstanceArgs(BaseModel):
    instance_id: str = Field(
        pattern=INSTANCE_ID_PATTERN, description="EC2 instance id, e.g. i-09a8b7c6d."
    )


class DescribeEc2InstanceTool(BaseTool[DescribeEc2InstanceArgs]):
    name = "describe_ec2_instance"
    description = """
    Return the runtime state and network topology of an EC2 instance: lifecycle state,
    system/instance status checks, private and public IP, subnet id and subnet CIDR, VPC id,
    attached security group ids, IAM instance profile and SSM-relevant metadata.
    Start here when an instance or the workload on it is reported unhealthy.
    """
    args_model = DescribeEc2InstanceArgs
    is_write_operation = False

    def __init__(self, aws: AwsClientFactory) -> None:
        self._aws = aws

    def run(self, args: DescribeEc2InstanceArgs) -> ToolResult:
        ec2 = self._aws.client("ec2")
        reservations = ec2.describe_instances(InstanceIds=[args.instance_id]).get(
            "Reservations", []
        )
        instances = [i for r in reservations for i in r.get("Instances", [])]
        if not instances:
            return ToolResult.failure(
                summary=f"Instance {args.instance_id} not found",
                error="No instance matched the supplied id in this region.",
            )
        instance = instances[0]

        checks = {"system_status": "unknown", "instance_status": "unknown"}
        statuses = ec2.describe_instance_status(
            InstanceIds=[args.instance_id], IncludeAllInstances=True
        ).get("InstanceStatuses", [])
        if statuses:
            checks = {
                "system_status": statuses[0].get("SystemStatus", {}).get("Status", "unknown"),
                "instance_status": statuses[0].get("InstanceStatus", {}).get("Status", "unknown"),
            }

        subnet_id = instance.get("SubnetId")
        subnet_cidr = None
        if subnet_id:
            subnets = ec2.describe_subnets(SubnetIds=[subnet_id]).get("Subnets", [])
            if subnets:
                subnet_cidr = subnets[0].get("CidrBlock")

        state = instance.get("State", {}).get("Name", "unknown")
        security_groups = [
            {"group_id": sg.get("GroupId"), "group_name": sg.get("GroupName")}
            for sg in instance.get("SecurityGroups", [])
        ]
        data = {
            "instance_id": instance.get("InstanceId"),
            "state": state,
            "status_checks": checks,
            "instance_type": instance.get("InstanceType"),
            "availability_zone": instance.get("Placement", {}).get("AvailabilityZone"),
            "private_ip": instance.get("PrivateIpAddress"),
            "public_ip": instance.get("PublicIpAddress"),
            "vpc_id": instance.get("VpcId"),
            "subnet_id": subnet_id,
            "subnet_cidr": subnet_cidr,
            "security_groups": security_groups,
            "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn"),
            "launch_time": instance.get("LaunchTime"),
            "tags": {t.get("Key"): t.get("Value") for t in instance.get("Tags", [])},
        }
        summary = (
            f"{data['instance_id']} is {state} in {data['availability_zone']} "
            f"({checks['system_status']}/{checks['instance_status']} checks), "
            f"ip {data['private_ip']} on {subnet_id} {subnet_cidr or ''}".strip()
        )
        return ToolResult.success(summary, **data)


# --------------------------------------------------------------------------- #
# READ: describe_security_groups
# --------------------------------------------------------------------------- #
class DescribeSecurityGroupsArgs(BaseModel):
    group_ids: list[str] | None = Field(
        default=None, description="Explicit security group ids to inspect."
    )
    instance_id: str | None = Field(
        default=None,
        pattern=INSTANCE_ID_PATTERN,
        description="Resolve and inspect every security group attached to this instance.",
    )
    vpc_id: str | None = Field(
        default=None, pattern=VPC_PATTERN, description="Inspect all security groups in a VPC."
    )
    port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Optional: annotate which rules cover this port (e.g. 5432, 3306).",
    )

    @field_validator("group_ids")
    @classmethod
    def _validate_group_ids(cls, value: list[str] | None) -> list[str] | None:
        import re

        if value is None:
            return None
        for group_id in value:
            if not re.match(SECURITY_GROUP_PATTERN, group_id):
                raise ValueError(f"'{group_id}' is not a valid security group id")
        return value

    @model_validator(mode="after")
    def _require_one_selector(self) -> DescribeSecurityGroupsArgs:
        if not (self.group_ids or self.instance_id or self.vpc_id):
            raise ValueError("Provide one of group_ids, instance_id or vpc_id")
        return self


class DescribeSecurityGroupsTool(BaseTool[DescribeSecurityGroupsArgs]):
    name = "describe_security_groups"
    description = """
    Inspect VPC security groups by id, by attached instance, or across a VPC. Returns normalised
    ingress and egress rules (protocol, port range, CIDR blocks, referenced security groups,
    descriptions). Use this to prove whether a port such as 5432 or 3306 is actually reachable
    from the caller's subnet before blaming the application.
    """
    args_model = DescribeSecurityGroupsArgs
    is_write_operation = False

    def __init__(self, aws: AwsClientFactory) -> None:
        self._aws = aws

    def run(self, args: DescribeSecurityGroupsArgs) -> ToolResult:
        ec2 = self._aws.client("ec2")
        group_ids = list(args.group_ids or [])

        if args.instance_id:
            reservations = ec2.describe_instances(InstanceIds=[args.instance_id]).get(
                "Reservations", []
            )
            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    group_ids.extend(
                        sg["GroupId"]
                        for sg in instance.get("SecurityGroups", [])
                        if sg.get("GroupId")
                    )

        if group_ids:
            response = ec2.describe_security_groups(GroupIds=sorted(set(group_ids)))
        else:
            response = ec2.describe_security_groups(
                Filters=[{"Name": "vpc-id", "Values": [str(args.vpc_id)]}]
            )

        groups = [
            _normalise_group(group, args.port) for group in response.get("SecurityGroups", [])
        ]
        if not groups:
            return ToolResult.failure(
                summary="No security groups matched the selector",
                error="Empty result set; verify the ids, instance or VPC.",
            )

        if args.port is not None:
            covering = [g["group_id"] for g in groups if g["matches_port"]]
            port_note = (
                f"port {args.port} allowed by {', '.join(covering)}"
                if covering
                else f"NO ingress rule covers port {args.port}"
            )
        else:
            port_note = f"{sum(len(g['ingress']) for g in groups)} ingress rules"

        return ToolResult.success(
            f"Inspected {len(groups)} security group(s); {port_note}",
            security_groups=groups,
            port_filter=args.port,
        )


# --------------------------------------------------------------------------- #
# WRITE: authorize_security_group_ingress
# --------------------------------------------------------------------------- #
class AuthorizeSecurityGroupIngressArgs(BaseModel):
    group_id: str = Field(pattern=SECURITY_GROUP_PATTERN, description="Target security group id.")
    ip_protocol: str = Field(default="tcp", description="tcp, udp, icmp or -1 for all.")
    from_port: int = Field(ge=-1, le=65535)
    to_port: int = Field(ge=-1, le=65535)
    cidr_ip: str | None = Field(
        default=None, pattern=CIDR_PATTERN, description="Source CIDR, e.g. 10.0.1.0/24."
    )
    source_security_group_id: str | None = Field(
        default=None, pattern=SECURITY_GROUP_PATTERN, description="Source security group id."
    )
    description: str = Field(
        default="Added by tfmedic",
        max_length=255,
        description="Rule description recorded in AWS.",
    )

    @field_validator("ip_protocol")
    @classmethod
    def _validate_protocol(cls, value: str) -> str:
        allowed = {"tcp", "udp", "icmp", "-1"}
        lowered = value.lower()
        if lowered not in allowed:
            raise ValueError(f"ip_protocol must be one of {sorted(allowed)}")
        return lowered

    @model_validator(mode="after")
    def _validate_source_and_ports(self) -> AuthorizeSecurityGroupIngressArgs:
        if bool(self.cidr_ip) == bool(self.source_security_group_id):
            raise ValueError("Provide exactly one of cidr_ip or source_security_group_id")
        if self.to_port < self.from_port:
            raise ValueError("to_port must be greater than or equal to from_port")
        if self.cidr_ip == "0.0.0.0/0" and self.from_port in {22, 3306, 5432, 6379, 27017}:
            raise ValueError(
                f"Refusing to expose port {self.from_port} to 0.0.0.0/0. "
                "Scope the rule to a specific subnet CIDR or source security group."
            )
        return self


class AuthorizeSecurityGroupIngressTool(BaseTool[AuthorizeSecurityGroupIngressArgs]):
    name = "authorize_security_group_ingress"
    description = """
    WRITE OPERATION (requires human approval). Add a single ingress rule to a security group to
    unblock connectivity. Always scope the source to a specific subnet CIDR or security group;
    never to 0.0.0.0/0. After approval, remind the operator to codify the rule in Terraform,
    because the live change is drift until it lands in the module.
    """
    args_model = AuthorizeSecurityGroupIngressArgs
    is_write_operation = True
    action_id = "aws:ec2:AuthorizeSecurityGroupIngress"

    def __init__(self, aws: AwsClientFactory) -> None:
        self._aws = aws

    def target_resource(self, arguments: Mapping[str, Any]) -> str:
        return str(arguments.get("group_id", "-"))

    def change_preview(self, arguments: Mapping[str, Any]) -> Sequence[tuple[str, str]]:
        source = arguments.get("cidr_ip") or arguments.get("source_security_group_id") or "?"
        protocol = str(arguments.get("ip_protocol", "tcp")).upper()
        from_port = arguments.get("from_port")
        to_port = arguments.get("to_port")
        ports = str(from_port) if from_port == to_port else f"{from_port}-{to_port}"
        return (
            ("Change", f"+ INGRESS allow {protocol} {ports} from {source}"),
            ("Description", str(arguments.get("description", "Added by tfmedic"))),
        )

    def run(self, args: AuthorizeSecurityGroupIngressArgs) -> ToolResult:
        ec2 = self._aws.client("ec2")
        permission: dict[str, Any] = {
            "IpProtocol": args.ip_protocol,
            "FromPort": args.from_port,
            "ToPort": args.to_port,
        }
        if args.cidr_ip:
            permission["IpRanges"] = [{"CidrIp": args.cidr_ip, "Description": args.description}]
            source = args.cidr_ip
        else:
            permission["UserIdGroupPairs"] = [
                {"GroupId": args.source_security_group_id, "Description": args.description}
            ]
            source = str(args.source_security_group_id)

        try:
            response = ec2.authorize_security_group_ingress(
                GroupId=args.group_id, IpPermissions=[permission]
            )
        except Exception as exc:  # noqa: BLE001 - duplicate rules are a success case
            code = _aws_error_code(exc)
            if code == "InvalidPermission.Duplicate":
                return ToolResult.success(
                    f"Rule already present on {args.group_id}: {args.ip_protocol} "
                    f"{args.from_port}-{args.to_port} from {source}",
                    group_id=args.group_id,
                    already_existed=True,
                )
            raise

        rule_ids = [
            rule.get("SecurityGroupRuleId")
            for rule in response.get("SecurityGroupRules", [])
            if rule.get("SecurityGroupRuleId")
        ]
        terraform_hint = _terraform_rule_snippet(args)
        return ToolResult.success(
            f"Authorized {args.ip_protocol} {args.from_port}-{args.to_port} from {source} "
            f"on {args.group_id}",
            group_id=args.group_id,
            security_group_rule_ids=rule_ids,
            terraform_remediation=terraform_hint,
            drift_warning=(
                "Live rule applied. Codify it in Terraform or the next apply may revert it."
            ),
        )


# --------------------------------------------------------------------------- #
# WRITE: reboot_ec2_instance
# --------------------------------------------------------------------------- #
class RebootEc2InstanceArgs(BaseModel):
    instance_id: str = Field(pattern=INSTANCE_ID_PATTERN)
    reason: str = Field(
        min_length=8,
        max_length=500,
        description="Why a full instance reboot is warranted over a targeted service restart.",
    )


class RebootEc2InstanceTool(BaseTool[RebootEc2InstanceArgs]):
    name = "reboot_ec2_instance"
    description = """
    WRITE OPERATION (requires human approval). Reboot an EC2 instance. This is a blunt,
    high-blast-radius action: exhaust container and systemd restarts first, and only use it when
    the instance itself is wedged (kernel hang, failing system status check, unresponsive SSM).
    """
    args_model = RebootEc2InstanceArgs
    is_write_operation = True
    action_id = "aws:ec2:RebootInstances"

    def __init__(self, aws: AwsClientFactory) -> None:
        self._aws = aws

    def target_resource(self, arguments: Mapping[str, Any]) -> str:
        return str(arguments.get("instance_id", "-"))

    def change_preview(self, arguments: Mapping[str, Any]) -> Sequence[tuple[str, str]]:
        return (
            ("Change", "REBOOT instance (all workloads on this host will drop)"),
            ("Blast radius", "every container and service running on the instance"),
        )

    def run(self, args: RebootEc2InstanceArgs) -> ToolResult:
        ec2 = self._aws.client("ec2")
        ec2.reboot_instances(InstanceIds=[args.instance_id])
        return ToolResult.success(
            f"Reboot requested for {args.instance_id}",
            instance_id=args.instance_id,
            reason=args.reason,
            note="Reboot is asynchronous; re-run describe_ec2_instance to confirm status checks.",
        )


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _normalise_group(group: Mapping[str, Any], port: int | None) -> dict[str, Any]:
    ingress = [_normalise_rule(rule) for rule in group.get("IpPermissions", [])]
    egress = [_normalise_rule(rule) for rule in group.get("IpPermissionsEgress", [])]
    matches_port = port is not None and any(_rule_covers_port(rule, port) for rule in ingress)
    return {
        "group_id": group.get("GroupId"),
        "group_name": group.get("GroupName"),
        "vpc_id": group.get("VpcId"),
        "description": group.get("Description"),
        "ingress": ingress,
        "egress": egress,
        "matches_port": matches_port,
    }


def _normalise_rule(rule: Mapping[str, Any]) -> dict[str, Any]:
    protocol = rule.get("IpProtocol", "-1")
    return {
        "protocol": "all" if protocol == "-1" else protocol,
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "cidr_blocks": [r.get("CidrIp") for r in rule.get("IpRanges", []) if r.get("CidrIp")],
        "ipv6_cidr_blocks": [
            r.get("CidrIpv6") for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6")
        ],
        "source_security_groups": [
            p.get("GroupId") for p in rule.get("UserIdGroupPairs", []) if p.get("GroupId")
        ],
        "descriptions": [
            r.get("Description")
            for r in list(rule.get("IpRanges", [])) + list(rule.get("UserIdGroupPairs", []))
            if r.get("Description")
        ],
    }


def _rule_covers_port(rule: Mapping[str, Any], port: int) -> bool:
    if rule.get("protocol") == "all":
        return True
    from_port, to_port = rule.get("from_port"), rule.get("to_port")
    if from_port is None or to_port is None:
        return False
    return int(from_port) <= port <= int(to_port)


def _aws_error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping):
            return str(error.get("Code", ""))
    return ""


def _terraform_rule_snippet(args: AuthorizeSecurityGroupIngressArgs) -> str:
    source_line = (
        f'  cidr_blocks       = ["{args.cidr_ip}"]'
        if args.cidr_ip
        else f'  source_security_group_id = "{args.source_security_group_id}"'
    )
    return (
        'resource "aws_security_group_rule" "tfmedic_generated" {\n'
        '  type              = "ingress"\n'
        f"  from_port         = {args.from_port}\n"
        f"  to_port           = {args.to_port}\n"
        f'  protocol          = "{args.ip_protocol}"\n'
        f'  security_group_id = "{args.group_id}"\n'
        f"{source_line}\n"
        f'  description       = "{args.description}"\n'
        "}"
    )
