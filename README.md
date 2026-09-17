# tfmedic

**Autonomous terminal-native AI troubleshooting agent for AWS + Terraform.**

tfmedic triages cloud incidents by correlating live runtime telemetry (EC2/Docker via SSM, RDS,
VPC security groups) with the Terraform code that is supposed to define it — then proposes
remediation behind an explicit human approval gate.

No LangChain. No AutoGen. No web UI. A hand-written agent loop, typed tool schemas, and a safety
gate you can read end to end in one sitting.

```
$ tfmedic "Diagnose why web-api container is crashing on instance i-09a8b7c6d"
```

---

## Why it exists

Cloud failures rarely live in one layer. A crash-looping container is often a security group that
drifted from the Terraform module three refactors ago. Triaging that means cross-referencing
`docker logs`, `describe_security_groups`, and `terraform show -json` by hand, in three terminals,
at 03:00. tfmedic does the cross-referencing and shows its work.

---

## Install

```bash
git clone https://github.com/your-org/tfmedic && cd tfmedic
python -m pip install .          # or: make install
tfmedic doctor                   # verify credentials, LLM endpoint, terraform binary
```

Requires Python 3.10+.

### Credentials

| Concern | How tfmedic handles it |
| --- | --- |
| AWS | Inherits the standard chain: `AWS_PROFILE`, static env vars, SSO cache, instance IAM role. tfmedic stores **no** AWS secrets. |
| LLM key | `OPENAI_API_KEY` from the environment, else `~/.config/tfmedic/config.json` (created `0600`), else a masked interactive prompt. |

### Self-hosted / zero-exfiltration mode

The OpenAI SDK accepts a custom `base_url`, so nothing leaves your network:

```bash
export TFMEDIC_LLM_URL=http://localhost:11434/v1
export TFMEDIC_MODEL=qwen2.5-coder:14b
tfmedic "why is the payments API returning 502s on i-0123456789abcdef0?"
```

Function-calling precision degrades on smaller local models. Prefer a 14B-class coder model or
larger, and expect more iterations.

---

## Usage

```bash
tfmedic "RDS connections are timing out from the app tier"   # implicit `diagnose`
tfmedic diagnose "..." --read-only                           # diagnostics only, all writes refused
tfmedic diagnose "..." --terraform-dir ./infra/prod -v       # point at a root module, show reasoning
tfmedic tools                                                # list tools and READ/WRITE classes
tfmedic audit -n 50                                          # review what was executed and approved
tfmedic doctor                                               # preflight checks
tfmedic configure                                            # store key + defaults at 0600
```

| Flag | Purpose |
| --- | --- |
| `--profile` / `--region` | AWS profile and region |
| `--model` / `--base-url` | LLM model and OpenAI-compatible endpoint |
| `--terraform-dir` | Terraform root module to read state from |
| `--max-iterations` | Reasoning budget (default 12) |
| `--read-only` | Refuse every write operation |
| `--auto-approve` | **Dangerous.** Skip the human gate. CI use only, if ever. |
| `--no-audit` | Disable the local audit log |

Exit codes: `0` concluded, `1` configuration/provider failure, `2` iteration budget exhausted,
`130` interrupted.

---

## The safety model

Write access to production without supervision is a liability, so the partition is structural
rather than prompt-based.

1. **Deterministic classification.** Every tool carries a class-level `is_write_operation`
   constant. Nothing about the model's output can change a tool's class.
2. **Execution interception.** When the loop receives a write call, it suspends **before** any SDK
   method is reached. A denied call means boto3 was never touched.
3. **A panel with the actual diff.** Target resource, region, the concrete change
   (`+ INGRESS allow TCP 5432 from 10.0.1.0/24`), blast radius, and the agent's stated reason.
4. **Explicit `[y/N]`.** Default no. On rejection, `"Action aborted by user. Please propose an
   alternative diagnostic or manual runbook step."` is injected back as the tool response, so the
   loop stays coherent and the agent re-plans instead of hanging.
5. **Fail closed.** No TTY attached (CI, pipes, cron) means every write is denied automatically.
6. **Constrained arguments.** Schemas refuse structurally dangerous changes before a human ever
   sees the prompt — e.g. exposing 5432/3306/22 to `0.0.0.0/0` is a validation error, not a
   judgement call.
7. **Audit trail.** Every call, decision and outcome appends to `~/.config/tfmedic/audit.jsonl`
   (`0600`), with credential-shaped values redacted.

The LLM never emits shell strings. It selects a diagnostic from a closed enum and fills validated
fields; the tool renders the command. Container and service names must match
`^[A-Za-z0-9][A-Za-z0-9_.@:-]*$` and are shell-quoted again on the way out.

---

## Tool catalogue

| Tool | Class | Layer | What it does |
| --- | --- | --- | --- |
| `describe_ec2_instance` | READ | Compute | State, status checks, private IP, subnet + CIDR, VPC, attached SGs |
| `run_ssm_diagnostic` | READ | Compute | `docker_ps`, `docker_logs`, `docker_inspect`, `docker_stats`, `system_resources` (incl. OOM kills), `disk_usage`, `listening_ports`, `service_status`, `journal_tail`, `tcp_connectivity`, `dns_resolve` |
| `describe_security_groups` | READ | Network | Normalised ingress/egress by id, instance or VPC, with port coverage analysis |
| `describe_rds_instance` | READ | Storage | Status, endpoint, port, Multi-AZ, subnet group, attached SGs |
| `get_rds_connection_metrics` | READ | Storage | CloudWatch `DatabaseConnections`, `CPUUtilization`, `FreeableMemory` |
| `list_terraform_resources` | READ | IaC | Managed resource addresses grouped by type |
| `read_terraform_state` | READ | IaC | Declared attributes, filtered by type/address/substring |
| `authorize_security_group_ingress` | **WRITE** | Network | Add one scoped ingress rule, returns the Terraform snippet to codify it |
| `restart_docker_container` | **WRITE** | Compute | `docker restart` via SSM, then verifies the resulting state |
| `restart_systemd_service` | **WRITE** | Compute | `systemctl restart` via SSM, then captures unit status |
| `reboot_ec2_instance` | **WRITE** | Compute | Last-resort host reboot |

---

## Golden demo

```
$ tfmedic "Diagnose why web-api container is crashing on instance i-09a8b7c6d"

Using AWS Profile: default (us-east-1) | Model: gpt-4o-mini | Mode: HIL GATED

→ describe_ec2_instance(instance_id=i-09a8b7c6d)
✓ i-09a8b7c6d is running in us-east-1a (ok/ok checks), ip 10.0.1.50 on subnet-0web1234 10.0.1.0/24
→ run_ssm_diagnostic(instance_id=i-09a8b7c6d, diagnostic=docker_logs, container=web-api)
✓ docker_logs on i-09a8b7c6d completed (exit 0, 812 chars stdout)
    ConnectionRefusedError: [Errno 111] Connect failed: postgres-prod.internal:5432
→ read_terraform_state(resource_type=aws_security_group)
✓ 1 matching resource(s); returning 1
→ describe_security_groups(group_ids=["sg-0418c39f"], port=5432)
✓ Inspected 1 security group(s); port 5432 allowed by sg-0418c39f  ← but only from 10.0.2.0/24

╭──────────────── !  APPROVAL REQUIRED ────────────────╮
│       Action  aws:ec2:AuthorizeSecurityGroupIngress  │
│     Resource  sg-0418c39f                            │
│       Region  us-east-1                              │
│       Change  + INGRESS allow TCP 5432 from 10.0.1.0/24
│       Reason  Unblocks database connectivity for the crashing web-api container
│                                                      │
│  This mutates live cloud infrastructure. Terraform   │
│  state will drift until you codify the change.       │
╰──────────────────────────────────────────────────────╯
Apply change to AWS infrastructure? [y/n]: y
✓ Authorized tcp 5432-5432 from 10.0.1.0/24 on sg-0418c39f
✓ Restarted web-api on i-09a8b7c6d; post-restart state captured

╭─────────────────── Diagnosis & Remediation ───────────────────╮
│ Terraform configuration drift: aws_security_group.db_sg       │
│ allows 5432 from 10.0.2.0/24, but web-api runs on 10.0.1.50.  │
│ ...                                                           │
╰───────────────────────────────────────────────────────────────╯
```

---

## Architecture

```
          Terminal (Typer + Rich)
                    │
        ┌───────────▼───────────┐        ┌──────────────────────┐
        │   Agent loop          │◄──────►│  Tool registry       │
        │   (iteration budget,  │        │  (Pydantic schemas,  │
        │    backoff, recovery) │        │   is_write flags)    │
        └───────────┬───────────┘        └──────────┬───────────┘
                    │                               │
        ┌───────────▼───────────┐        ┌──────────▼───────────┐
        │  LLM client (protocol)│        │  Safety gate (HIL)   │
        │  OpenAI / Ollama      │        │  write? → [y/N]      │
        └───────────────────────┘        └──────────┬───────────┘
                                                    │
                    ┌───────────────────────────────▼───────────────┐
                    │  Providers (protocols)                        │
                    │  AwsClientFactory · CommandRunner             │
                    │  SSM · EC2 · RDS · CloudWatch · terraform CLI  │
                    └───────────────────────────────────────────────┘
                                         │
                              audit.jsonl (0600, redacted)
```

Four seams keep the core testable and swappable:

- `LLMClient` — any OpenAI-compatible endpoint; the loop never imports the vendor SDK.
- `AwsClientFactory` — boto3 in production, canned responses in tests.
- `CommandRunner` — `subprocess` in production, recorded argv in tests.
- `BaseTool` — cloud-SDK-free; botocore errors are recognised by duck-typing, not by import.

The entire test suite runs with no AWS account, no network and no API key.

### Layout

```
tfmedic/
├── cli.py                  Typer entrypoint, wiring, exit codes
├── config.py               Settings precedence, 0600 key persistence
├── providers.py            AwsClientFactory / CommandRunner protocols + impls
├── exceptions.py           Single error hierarchy
├── agent/
│   ├── loop.py             Iteration budget, dispatch, gate integration, recovery
│   ├── models.py           LLM protocol, OpenAI-compatible client, backoff
│   └── prompts.py          SRE persona, evidence discipline, answer format
├── tools/
│   ├── base.py             BaseTool, ToolResult, schema generation, truncation
│   ├── registry.py         Registration + dependency wiring
│   ├── aws_ec2.py          Instance topology, SG inspection, ingress repair
│   ├── aws_ssm.py          Enum-driven keyless diagnostics, container/service restart
│   ├── aws_rds.py          Instance state + CloudWatch connection pressure
│   └── terraform.py        `terraform show -json` parsing, module flattening, pruning
├── safety/
│   ├── gatekeeper.py       Write interception, approval panel, abort injection
│   └── audit.py            JSONL audit log with redaction
└── ui/
    ├── console.py          Themed Rich console singletons
    └── components.py       Banner, approval panel, diff rows, tables
```

---

## Minimum IAM policy

Read-only triage:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups", "rds:DescribeDBInstances",
        "cloudwatch:GetMetricStatistics",
        "ssm:SendCommand", "ssm:GetCommandInvocation", "ssm:DescribeInstanceInformation"
      ],
      "Resource": "*"
    }
  ]
}
```

Remediation additionally requires `ec2:AuthorizeSecurityGroupIngress` and `ec2:RebootInstances`.
Scope `ssm:SendCommand` to the `AWS-RunShellScript` document and tagged instances. Managed
instances need the SSM agent and `AmazonSSMManagedInstanceCore`.

---

## Development

```bash
make dev        # editable install with dev extras
make test       # pytest
make cov        # coverage report
make lint       # ruff
make typecheck  # mypy --strict
```

Tests cover the gate (approve, deny, read-only, non-interactive, auto-approve, interrupt), loop
mechanics (dispatch, iteration cutoff, unknown tools, malformed arguments, exception containment),
tool schemas and injection resistance, Terraform state parsing, config precedence, and audit
redaction and permissions.

---

## Known limits

- Read-only Terraform. tfmedic never runs `apply`; it emits the HCL for you to commit.
- Single region per invocation.
- `docker logs` heuristics assume a Linux host with Docker and the SSM agent.
- `--auto-approve` exists for pipelines. Treat it as a loaded weapon.
- Findings are evidence-backed proposals, not a substitute for an on-call engineer's judgement.
