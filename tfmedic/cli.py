"""Typer entrypoint: argument parsing, dependency wiring and process exit codes.

Note the deliberate absence of ``from __future__ import annotations`` here:
Typer resolves parameter types at runtime, and postponed evaluation interacts
badly with its introspection.
"""

import sys
from pathlib import Path

import typer
from pydantic import ValidationError

from tfmedic import __version__
from tfmedic.agent.loop import AgentLoop
from tfmedic.agent.models import OpenAICompatibleClient
from tfmedic.agent.prompts import build_environment_context
from tfmedic.config import (
    Settings,
    audit_file,
    config_file,
    load_config_file,
    save_config_values,
)
from tfmedic.exceptions import ConfigurationError, ProviderError, TfmedicError
from tfmedic.providers import Boto3ClientFactory, SubprocessRunner
from tfmedic.safety.audit import AuditLogger, read_audit_entries
from tfmedic.safety.gatekeeper import SafetyGate
from tfmedic.tools.registry import build_default_registry
from tfmedic.ui.components import (
    audit_table,
    banner,
    diagnosis_panel,
    error_panel,
    run_summary_table,
    session_header,
    tools_table,
)
from tfmedic.ui.console import console, err_console

app = typer.Typer(
    name="tfmedic",
    help="Autonomous terminal-native AI troubleshooting agent for AWS + Terraform.",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

_COMMANDS = {"diagnose", "tools", "audit", "doctor", "configure", "version"}


@app.command()
def diagnose(
    query: str = typer.Argument(..., help="Incident description, in plain English."),
    profile: str | None = typer.Option(None, "--profile", "-p", help="AWS profile to use."),
    region: str | None = typer.Option(None, "--region", "-r", help="AWS region."),
    model: str | None = typer.Option(None, "--model", "-m", help="LLM model identifier."),
    base_url: str | None = typer.Option(
        None, "--base-url", help="OpenAI-compatible endpoint (e.g. http://localhost:11434/v1)."
    ),
    terraform_dir: Path | None = typer.Option(
        None, "--terraform-dir", "-t", help="Terraform root module directory."
    ),
    max_iterations: int | None = typer.Option(
        None, "--max-iterations", help="Reasoning iteration budget."
    ),
    read_only: bool = typer.Option(
        False, "--read-only", help="Refuse every write operation, diagnostics only."
    ),
    auto_approve: bool = typer.Option(
        False,
        "--auto-approve",
        help="[bold red]Dangerous.[/bold red] Skip the human gate on write operations.",
    ),
    no_audit: bool = typer.Option(False, "--no-audit", help="Disable the local audit log."),
    no_banner: bool = typer.Option(False, "--no-banner", help="Suppress the ASCII banner."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show interim agent reasoning."),
) -> None:
    """Triage a cloud incident end to end."""
    if read_only and auto_approve:
        _fail("--read-only and --auto-approve are mutually exclusive.")

    try:
        settings = Settings.from_env(
            model=model,
            llm_base_url=base_url,
            aws_profile=profile,
            aws_region=region,
            terraform_dir=terraform_dir,
            max_iterations=max_iterations,
            read_only=read_only,
            auto_approve=auto_approve,
            audit_enabled=not no_audit,
            verbose=verbose,
        )
    except ValidationError as exc:
        _fail(f"Invalid configuration: {exc}")
        return

    settings = _ensure_api_key(settings)

    if not no_banner:
        console.print(banner())
        console.print()

    try:
        aws = Boto3ClientFactory(profile=settings.aws_profile, region=settings.aws_region)
        registry = build_default_registry(settings, aws, runner=SubprocessRunner())
        llm = OpenAICompatibleClient(
            model=settings.model,
            api_key=settings.resolved_api_key(),
            base_url=settings.llm_base_url,
            timeout=settings.request_timeout,
            max_retries=settings.max_retries,
            temperature=settings.temperature,
        )
    except TfmedicError as exc:
        _fail(str(exc))
        return

    console.print(
        session_header(
            model=settings.model,
            base_url=settings.llm_base_url,
            profile=settings.aws_profile,
            region=aws.region,
            terraform_dir=str(settings.terraform_dir),
            read_only=settings.read_only,
            auto_approve=settings.auto_approve,
        )
    )
    if settings.auto_approve:
        console.print(
            "[danger]! --auto-approve is set: write operations will execute "
            "without review.[/danger]"
        )
    console.print()

    loop = AgentLoop(
        llm=llm,
        registry=registry,
        gate=SafetyGate(
            console=console,
            region=aws.region,
            auto_approve=settings.auto_approve,
            read_only=settings.read_only,
        ),
        audit=AuditLogger(enabled=settings.audit_enabled),
        console=console,
        max_iterations=settings.max_iterations,
        aws_profile=settings.aws_profile,
        aws_region=aws.region,
        verbose=settings.verbose,
    )

    try:
        result = loop.run(
            query,
            environment_context=build_environment_context(
                aws_profile=settings.aws_profile,
                aws_region=aws.region,
                terraform_dir=str(settings.terraform_dir),
                read_only=settings.read_only,
                max_iterations=settings.max_iterations,
            ),
        )
    except KeyboardInterrupt:
        console.print("\n[warn]Interrupted. No further actions were taken.[/warn]")
        raise typer.Exit(code=130) from None
    except TfmedicError as exc:
        _fail(str(exc))
        return

    console.print()
    console.print(diagnosis_panel(result.answer))
    console.print(
        run_summary_table(
            iterations=result.iterations,
            tool_calls=result.tool_calls,
            writes_applied=result.writes_applied,
            writes_denied=result.writes_denied,
            elapsed_seconds=result.elapsed_seconds,
        )
    )
    if settings.audit_enabled:
        console.print(f"[muted]audit: {audit_file()} (session {result.session_id})[/muted]")

    raise typer.Exit(code=0 if result.completed else 2)


@app.command("tools")
def list_tools(
    profile: str | None = typer.Option(None, "--profile", "-p"),
    region: str | None = typer.Option(None, "--region", "-r"),
) -> None:
    """List the registered tools and their READ/WRITE classification."""
    settings = Settings.from_env(aws_profile=profile, aws_region=region)
    try:
        aws = Boto3ClientFactory(profile=settings.aws_profile, region=settings.aws_region)
    except TfmedicError as exc:
        _fail(str(exc))
        return
    registry = build_default_registry(settings, aws, runner=SubprocessRunner())
    rows = [
        (tool.name, tool.is_write_operation, " ".join(tool.description.split()))
        for tool in registry
    ]
    console.print(tools_table(rows))
    console.print(
        f"[muted]{len(registry.read_tools())} read (autonomous) · "
        f"{len(registry.write_tools())} write (human-gated)[/muted]"
    )


@app.command("audit")
def show_audit(
    limit: int = typer.Option(20, "--limit", "-n", min=1, max=500, help="Entries to show."),
    path: Path | None = typer.Option(None, "--path", help="Alternate audit log path."),
) -> None:
    """Show recent entries from the local audit log."""
    entries = read_audit_entries(path, limit=limit)
    target = path or audit_file()
    if not entries:
        console.print(f"[muted]No audit entries at {target}.[/muted]")
        return
    console.print(audit_table(e for e in entries if e.get("event") in {"tool_call", "approval"}))
    console.print(f"[muted]{target}[/muted]")


@app.command("doctor")
def doctor(
    profile: str | None = typer.Option(None, "--profile", "-p"),
    region: str | None = typer.Option(None, "--region", "-r"),
    terraform_dir: Path | None = typer.Option(None, "--terraform-dir", "-t"),
) -> None:
    """Verify credentials, the LLM endpoint and the Terraform workspace."""
    settings = Settings.from_env(
        aws_profile=profile, aws_region=region, terraform_dir=terraform_dir
    )
    ok = True

    # LLM configuration
    try:
        settings.resolved_api_key()
        endpoint = settings.llm_base_url or "https://api.openai.com/v1"
        console.print(f"[ok]✓[/ok] LLM configured: {settings.model} @ {endpoint}")
    except ConfigurationError as exc:
        ok = False
        console.print(f"[danger]✗[/danger] {exc}")

    # AWS credentials
    try:
        aws = Boto3ClientFactory(profile=settings.aws_profile, region=settings.aws_region)
        identity = aws.caller_identity()
        console.print(
            f"[ok]✓[/ok] AWS credentials valid in {aws.region}: {identity['arn']}"
        )
    except TfmedicError as exc:
        ok = False
        console.print(f"[danger]✗[/danger] {exc}")

    # Terraform binary and workspace
    runner = SubprocessRunner()
    try:
        version = runner.run([settings.terraform_binary, "version"], timeout=30)
        if version.ok:
            first_line = (version.stdout or "").strip().splitlines()[0]
            console.print(f"[ok]✓[/ok] {first_line}")
        else:
            ok = False
            console.print(f"[danger]✗[/danger] terraform version failed: {version.stderr.strip()}")
    except ProviderError as exc:
        ok = False
        console.print(f"[danger]✗[/danger] {exc}")

    if settings.terraform_dir.is_dir():
        console.print(f"[ok]✓[/ok] Terraform working directory: {settings.terraform_dir}")
    else:
        ok = False
        console.print(f"[danger]✗[/danger] Missing directory: {settings.terraform_dir}")

    console.print(f"[muted]config: {config_file()} · audit: {audit_file()}[/muted]")
    raise typer.Exit(code=0 if ok else 1)


@app.command("configure")
def configure(
    show: bool = typer.Option(False, "--show", help="Print the stored configuration."),
) -> None:
    """Store the LLM API key and defaults in ~/.config/tfmedic/config.json (0600)."""
    if show:
        stored = load_config_file()
        if "api_key" in stored:
            stored["api_key"] = "***stored***"
        console.print(stored or "[muted]No stored configuration.[/muted]")
        return

    api_key = typer.prompt("LLM API key", hide_input=True, default="", show_default=False)
    values = {}
    if api_key:
        values["api_key"] = api_key
    model = typer.prompt("Default model", default="gpt-4o-mini")
    values["model"] = model
    base_url = typer.prompt(
        "OpenAI-compatible base URL (blank for OpenAI)", default="", show_default=False
    )
    if base_url:
        values["llm_base_url"] = base_url
    region = typer.prompt("Default AWS region", default="us-east-1")
    values["aws_region"] = region

    path = save_config_values(values)
    console.print(f"[ok]✓[/ok] Saved to {path} [muted](permissions 0600)[/muted]")


@app.command("version")
def version() -> None:
    """Print the tfmedic version."""
    console.print(f"tfmedic {__version__}")


def _ensure_api_key(settings: Settings) -> Settings:
    """Prompt for and optionally persist a missing API key."""
    try:
        settings.resolved_api_key()
        return settings
    except ConfigurationError:
        pass

    if not sys.stdin.isatty():
        _fail(
            "No LLM API key found. Set OPENAI_API_KEY, or run `tfmedic configure` from an "
            "interactive terminal."
        )

    console.print("[warn]No LLM API key found in the environment.[/warn]")
    api_key = typer.prompt("LLM API key", hide_input=True)
    if not api_key:
        _fail("An API key is required to run the agent.")
    if typer.confirm("Save it to ~/.config/tfmedic/config.json (0600)?", default=True):
        save_config_values({"api_key": api_key})
    return settings.model_copy(update={"api_key": _secret(api_key)})


def _secret(value: str):
    from pydantic import SecretStr

    return SecretStr(value)


def _fail(message: str) -> None:
    err_console.print(error_panel(message))
    raise typer.Exit(code=1)


def run() -> None:
    """Console-script entrypoint.

    Supports the natural form ``tfmedic "why is web-api down?"`` by inserting the
    implicit ``diagnose`` subcommand when the first argument is neither a known
    command nor an option.
    """
    argv = sys.argv[1:]
    if argv and argv[0] not in _COMMANDS and not argv[0].startswith("-"):
        sys.argv.insert(1, "diagnose")
    app()


if __name__ == "__main__":  # pragma: no cover
    run()
