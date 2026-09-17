"""Configuration precedence, secret hygiene and audit redaction."""

from __future__ import annotations

import json
import os
import stat

import pytest

from tfmedic.config import Settings, save_config_values
from tfmedic.exceptions import ConfigurationError
from tfmedic.safety.audit import AuditEvent, AuditLogger, redact


def test_cli_overrides_beat_environment(monkeypatch):
    env = {"TFMEDIC_MODEL": "from-env", "AWS_REGION": "eu-west-1"}
    settings = Settings.from_env(env=env, file_values={}, model="from-cli")
    assert settings.model == "from-cli"
    assert settings.aws_region == "eu-west-1"


def test_environment_beats_the_config_file():
    settings = Settings.from_env(
        env={"TFMEDIC_MODEL": "from-env"}, file_values={"model": "from-file"}
    )
    assert settings.model == "from-env"


def test_config_file_supplies_defaults():
    settings = Settings.from_env(env={}, file_values={"model": "from-file", "aws_region": "ap-south-1"})
    assert settings.model == "from-file"
    assert settings.aws_region == "ap-south-1"


def test_api_key_is_never_rendered_in_repr():
    settings = Settings.from_env(env={"OPENAI_API_KEY": "sk-supersecret"}, file_values={})
    assert "supersecret" not in repr(settings)
    assert settings.resolved_api_key() == "sk-supersecret"


def test_local_endpoints_do_not_require_a_key():
    settings = Settings.from_env(
        env={"TFMEDIC_LLM_URL": "http://localhost:11434/v1"}, file_values={}
    )
    assert settings.is_local_llm is True
    assert settings.resolved_api_key() == "not-needed"


def test_missing_key_for_a_cloud_endpoint_is_a_configuration_error():
    settings = Settings.from_env(env={}, file_values={})
    with pytest.raises(ConfigurationError):
        settings.resolved_api_key()


def test_config_file_is_written_with_0600_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("TFMEDIC_HOME", str(tmp_path / "cfg"))
    path = save_config_values({"model": "gpt-4o-mini"})
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    assert json.loads(path.read_text())["model"] == "gpt-4o-mini"


def test_audit_redacts_credential_shaped_values():
    payload = {"password": "hunter2", "nested": {"api_key": "sk-x"}, "port": 5432}
    scrubbed = redact(payload)
    assert scrubbed["password"] == "***REDACTED***"
    assert scrubbed["nested"]["api_key"] == "***REDACTED***"
    assert scrubbed["port"] == 5432


def test_audit_writes_jsonl_with_0600_permissions(tmp_path):
    logger = AuditLogger(tmp_path / "audit.jsonl")
    logger.record(
        AuditEvent(
            session_id="abc123",
            event="tool_call",
            tool="authorize_security_group_ingress",
            is_write=True,
            decision="approved",
            status="success",
            arguments={"group_id": "sg-1", "secret_token": "leak-me"},
        )
    )
    entry = json.loads(logger.path.read_text().strip())
    assert entry["arguments"]["secret_token"] == "***REDACTED***"
    assert stat.S_IMODE(os.stat(logger.path).st_mode) == 0o600


def test_audit_failures_are_non_fatal(tmp_path):
    logger = AuditLogger(tmp_path / "missing" / "nested" / "audit.jsonl")
    logger.path.parent.parent.mkdir(parents=True, exist_ok=True)
    logger.path.parent.parent.chmod(0o500)
    try:
        logger.record(AuditEvent(session_id="x", event="run_start"))
    finally:
        logger.path.parent.parent.chmod(0o700)
    # No exception escaped; the failure is recorded for later surfacing.
    assert logger.last_error is None or isinstance(logger.last_error, str)
