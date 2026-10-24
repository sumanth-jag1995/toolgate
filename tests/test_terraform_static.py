"""Static checks over infra/terraform (no AWS calls, no apply/plan).

Terraform is located via TERRAFORM_BIN (takes precedence; an invalid path skips
the test with a reason) or shutil.which("terraform"). Use TERRAFORM_BIN when a
shell started before the install has a stale PATH.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TF = ROOT / "infra" / "terraform"
AGENTS = ("servicing", "claims-intake", "fraud-triage")
REALM = ROOT / "infra" / "keycloak" / "toolgate-realm.template.json"


def _read(rel: str) -> str:
    return (TF / rel).read_text(encoding="utf-8")


def _all_tf() -> dict[Path, str]:
    return {p: p.read_text(encoding="utf-8") for p in sorted(TF.rglob("*.tf"))}


def _terraform_bin() -> tuple[str | None, str]:
    """TERRAFORM_BIN wins over PATH; an invalid TERRAFORM_BIN is reported."""
    override = os.environ.get("TERRAFORM_BIN")
    if override:
        if Path(override).is_file():
            return override, ""
        return None, f"TERRAFORM_BIN is not a file: {override}"
    found = shutil.which("terraform")
    if found:
        return found, ""
    return None, "terraform not installed (set TERRAFORM_BIN or add it to PATH)"


def test_provider_default_tags_project_toolgate():
    main = _read("main.tf")
    assert re.search(
        r"default_tags\s*\{\s*tags\s*=\s*\{[^}]*project\s*=\s*\"toolgate\"", main
    )
    versions = _read("versions.tf")
    assert 'required_version = ">= 1.9"' in versions
    assert 'version = "~> 5.0"' in versions


def test_budget_default_is_25_and_has_email_notification():
    variables = _read("variables.tf")
    assert re.search(
        r'variable "budget_usd"[^}]*default\s*=\s*25', variables, re.DOTALL
    )
    assert re.search(
        r'variable "region"[^}]*default\s*=\s*"us-east-1"', variables, re.DOTALL
    )
    budget = _read("modules/budget/main.tf")
    assert "aws_budgets_budget" in budget
    assert "subscriber_email_addresses" in budget


def test_budget_notification_types():
    budget = _read("modules/budget/main.tf")
    found = set(
        re.findall(
            r"threshold\s*=\s*(\d+)\s*\n\s*threshold_type\s*=\s*\"PERCENTAGE\"\s*\n"
            r"\s*notification_type\s*=\s*\"(\w+)\"",
            budget,
        )
    )
    assert found == {("80", "ACTUAL"), ("100", "ACTUAL"), ("100", "FORECASTED")}
    assert "account-wide" in budget


def test_no_literal_secrets_or_account_ids():
    bad = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"(?<![0-9A-Za-z-])\d{12}(?![0-9A-Za-z-])"),
        re.compile(r"password\s*=\s*\""),
        re.compile(r"(secret_string|client_secret)\s*=\s*\""),
    ]
    files = _all_tf()
    assert files
    for path, text in files.items():
        for rx in bad:
            assert not rx.search(text), f"{path.name}: {rx.pattern}"


def test_outputs_expose_no_secret_values():
    outputs = [(p, t) for p, t in _all_tf().items() if p.name == "outputs.tf"]
    assert outputs
    for path, text in outputs:
        assert "password" not in text.lower(), path
        assert "client_secret" not in text.replace("client_secret_arns", ""), path
        assert "secret_string" not in text, path


def test_tfvars_example_present_and_real_tfvars_ignored():
    assert (TF / "terraform.tfvars.example").is_file()
    git = shutil.which("git")
    assert git
    ignored = subprocess.run(
        [git, "check-ignore", "-q", "infra/terraform/terraform.tfvars"],
        cwd=ROOT,
        check=False,
    )
    assert ignored.returncode == 0
    example = subprocess.run(
        [git, "check-ignore", "-q", "infra/terraform/terraform.tfvars.example"],
        cwd=ROOT,
        check=False,
    )
    assert example.returncode == 1


def test_rds_is_not_publicly_accessible_and_encrypted():
    data = _read("modules/data/main.tf")
    assert re.search(r'engine\s*=\s*"postgres"', data)
    assert re.search(r'engine_version\s*=\s*"16', data)
    assert "db.t4g.micro" in data
    assert re.search(r'storage_type\s*=\s*"gp3"', data)
    assert re.search(r"publicly_accessible\s*=\s*false", data)
    assert re.search(r"storage_encrypted\s*=\s*true", data)
    assert re.search(r"manage_master_user_password\s*=\s*true", data)
    assert "random_password" not in data
    outputs = _read("modules/data/outputs.tf")
    assert "master_user_secret[0].secret_arn" in outputs


def test_teardown_friendly_settings():
    data = _read("modules/data/main.tf")
    assert re.search(r"deletion_protection\s*=\s*false", data)
    assert re.search(r"skip_final_snapshot\s*=\s*true", data)
    for path, text in _all_tf().items():
        assert "prevent_destroy" not in text, path.name
    cognito = _read("modules/cognito/main.tf")
    assert re.search(r"recovery_window_in_days\s*=\s*0", cognito)


def test_variable_validations():
    variables = _read("variables.tf")
    assert variables.count("validation {") >= 3
    assert 'var.region == "us-east-1"' in variables
    assert "var.budget_usd > 0" in variables
    assert "regex(" in variables


def _tf_map(var_name: str) -> dict[str, set[str]]:
    text = _read("modules/cognito/variables.tf")
    match = re.search(rf'variable "{var_name}"\s*\{{(.*?)\n\}}', text, re.DOTALL)
    assert match
    block = match.group(1)
    default = block[block.index("default") :]
    return {
        name: set(re.findall(r'"([^"]+)"', items))
        for name, items in re.findall(r'"([\w-]+)"\s*=\s*\[(.*?)\]', default, re.DOTALL)
    }


def _realm() -> dict:
    return json.loads(REALM.read_text(encoding="utf-8"))


def test_cognito_clients_are_client_credentials_only():
    cognito = _read("modules/cognito/main.tf")
    assert "aws_cognito_user_pool_client" in cognito
    assert re.search(r"allowed_oauth_flows\s*=\s*\[\"client_credentials\"\]", cognito)
    assert re.search(
        r"explicit_auth_flows\s*=\s*\[\"ALLOW_REFRESH_TOKEN_AUTH\"\]", cognito
    )
    assert "generate_secret" in cognito
    assert not re.search(r'"(code|implicit)"', cognito)
    assert "allow_admin_create_user_only = true" in cognito
    assert "audience check" in cognito
    for out in ("user_pool_id", "issuer_url", "app_client_ids", "client_secret_arns"):
        assert out in _read("modules/cognito/outputs.tf")


def test_cognito_scopes_mirror_keycloak_and_agents_yaml():
    agents = yaml.safe_load((ROOT / "policy/agents.yaml").read_text("utf-8"))["agents"]
    assert set(agents) == set(AGENTS)
    clients = _tf_map("clients")
    assert set(clients) == {*AGENTS, "gateway", "core-read", "core-write", "comms"}
    realm = {c["clientId"]: c for c in _realm()["clients"]}

    for agent in agents:
        # Per-agent tool authorization lives in the gateway policy, not the IdP.
        assert clients[agent] == {"toolgate-gateway/invoke"}
        audiences = {
            m["config"]["included.custom.audience"]
            for m in realm[agent]["protocolMappers"]
        }
        assert audiences == {"toolgate-gateway"}
        assert not any(s.startswith("mock-enterprise/") for s in clients[agent])

    gateway_aud = {
        m["config"]["included.custom.audience"]
        for m in realm["toolgate-gateway"]["protocolMappers"]
    }
    assert clients["gateway"] == {f"{a}/invoke" for a in gateway_aud}

    for server in ("core-read", "core-write", "comms"):
        expected = {
            f"mock-enterprise/{s}" for s in realm[server]["defaultClientScopes"]
        }
        assert clients[server] == expected

    servers = _tf_map("resource_servers")
    assert set(servers) == {
        "toolgate-gateway",
        "core-read",
        "core-write",
        "comms",
        "mock-enterprise",
    }
    assert servers["mock-enterprise"] == {s["name"] for s in _realm()["clientScopes"]}
    for name in ("toolgate-gateway", "core-read", "core-write", "comms"):
        assert servers[name] == {"invoke"}
    for scopes in clients.values():
        for scope in scopes:
            resource, _, short = scope.partition("/")
            assert short in servers[resource]


def _ecs() -> str:
    return _read("modules/ecs/main.tf")


def test_every_ecs_service_has_log_group_and_task_role():
    ecs = _ecs()
    assert re.search(
        r'resource "aws_ecs_service" "this" \{\s*for_each\s*=\s*local.services', ecs
    )
    assert "services = { for k, v in local.active" in ecs
    for res in ("task", "execution"):
        assert re.search(
            rf'resource "aws_iam_role" "{res}" \{{\s*for_each\s*=\s*local.active', ecs
        )
    assert (
        'resource "aws_ecs_task_definition" "this" {' in ecs
        and "for_each                 = local.active" in ecs
    )
    assert "task_role_arn            = aws_iam_role.task[each.key].arn" in ecs
    assert ecs.count('"awslogs-group"') == 2
    assert "var.log_group_names[each.key]" in ecs
    obs = _read("modules/observability/main.tf")
    assert re.search(r"for_each\s*=\s*var.log_group_names", obs)
    root = _read("main.tf")
    assert "log_group_names = local.task_names" in root
    assert "keys(local.active_images)" in root
    # least privilege: no wildcard secret access
    assert re.search(r"GetSecretValue", ecs)
    assert "secretsmanager:*" not in ecs


def test_alb_http_only_when_no_domain():
    ecs = _ecs()
    assert re.search(
        r'resource "aws_lb_listener" "http" \{\s*count\s*=\s*var.domain_name == "" \? 1 : 0',
        ecs,
    )
    assert re.search(
        r'resource "aws_lb_listener" "https" \{\s*count\s*=\s*var.domain_name != "" \? 1 : 0',
        ecs,
    )
    assert 'protocol          = "HTTPS"' in ecs and "certificate_arn" in ecs
    assert "http_redirect" in ecs


def test_only_gateway_target_group_is_internet_facing():
    ecs = _ecs()
    assert ecs.count('resource "aws_lb_target_group"') == 1
    assert ecs.count('resource "aws_lb_listener_rule"') == 1
    assert ecs.count('dynamic "load_balancer"') == 1
    assert 'for_each = each.key == "gateway" ? [1] : []' in ecs
    assert "assign_public_ip = false" in ecs
    assert "/.well-known/oauth-protected-resource/mcp" in ecs
    assert '"/mcp"' in ecs
    assert "port                 = 8200" in ecs
    # Only the gateway task, never the MCP servers, is registered with the ALB.
    assert ecs.count("target_group_arn") == 2  # listener rule action + gateway service


def test_log_retention_is_7_days():
    obs = _read("modules/observability/main.tf")
    assert re.search(r"retention_in_days\s*=\s*7\b", obs)
    assert "aws-otel-collector" in _read("modules/observability/outputs.tf")


def test_eval_targets_off_by_default_and_destroyable():
    variables = _read("variables.tf")
    assert re.search(
        r'variable "enable_eval_targets"[^}]*default\s*=\s*false', variables, re.DOTALL
    )
    assert "var.enable_eval_targets ? keys(var.eval_target_ports) : []" in _read(
        "main.tf"
    )
    ecs = _ecs()
    assert re.search(r"force_delete\s*=\s*true", ecs)
    assert re.search(r"recovery_window_in_days\s*=\s*0", ecs)
    assert 'name = "toolgate.local"' in ecs


def test_ecs_mirrors_compose_ports_and_variable_names():
    compose = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text("utf-8"))
    services = compose["services"]
    ecs = _ecs()
    for name in ("mock-api", "core-read", "core-write", "comms", "gateway"):
        svc = services[name]
        port = int(svc["ports"][0].rsplit(":", 1)[1])
        assert f"{port}" in ecs, name
        for var in svc.get("environment", {}):
            if var == "DATABASE_URL":
                continue  # composed in the container command from secret parts
            if var in ("OTEL_EXPORTER_OTLP_ENDPOINT", "GATEWAY_CLIENT_ID"):
                assert var in ecs
                continue
            assert re.search(rf"\b{var}\b", ecs), f"{name}: {var}"
    assert "mock_enterprise.seed --reset" in ecs
    assert "toolgate_mcp_servers" in ecs
    assert "toolgate-gateway serve" in ecs


def test_ecs_secrets_only_by_reference():
    ecs = _ecs()
    assert "valueFrom" in ecs
    assert not re.search(r"(CLIENT_SECRET|PASSWORD|HMAC_KEY)\s*=\s*\"[^$]", ecs)
    assert "secret_string" in ecs  # only the generated gateway secret
    assert ecs.count("secret_string") == 1


def test_terraform_fmt_and_validate():
    tf, reason = _terraform_bin()
    if not tf:
        pytest.skip(reason)
    base = [tf, f"-chdir={TF}"]

    def run(*args: str) -> None:
        res = subprocess.run(
            [*base, *args], capture_output=True, text=True, check=False
        )
        assert res.returncode == 0, (
            f"terraform {' '.join(args)}\n{res.stdout}{res.stderr}"
        )

    run("init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color")
    run("fmt", "-check", "-recursive", "-no-color")
    run("validate", "-no-color")


def test_validate_still_passes():
    tf, reason = _terraform_bin()
    if not tf:
        pytest.skip(reason)
    res = subprocess.run(
        [tf, f"-chdir={TF}", "validate", "-no-color"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert res.returncode == 0, res.stdout + res.stderr
