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
    assert variables.count("validation {") == 7
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


def _spec_block(ecs: str, name: str) -> str:
    """Text of one explicit entry in local.specs (mock-api, gateway, gateway-migrate)."""
    start = ecs.index(f'    "{name}" = {{')
    rest = ecs[start + 1 :]
    nxt = re.search(r'\n    "[\w-]+" = \{|\n  \}\)\n', rest)
    assert nxt
    return rest[: nxt.start()]


def _names_in(block: str, section: str) -> set[str]:
    """Keys assigned inside `env = ...{ }` or `secrets = {  }` of a spec block."""
    m = re.search(
        rf"\b{section}\s*=\s*(?:merge\(\w+(?:\.\w+)*, )?\{{(.*?)\n\s*\}}",
        block,
        re.DOTALL,
    )
    assert m, section
    return set(re.findall(r"^\s*([A-Z][A-Z0-9_]+)\s*=", m.group(1), re.MULTILINE))


def test_ecs_mirrors_compose_ports_and_variable_names():
    compose = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text("utf-8"))
    services = compose["services"]
    ecs = _ecs()

    def compose_port(name: str) -> int:
        return int(services[name]["ports"][0].rsplit(":", 1)[1])

    # MCP servers: generated from one template; ports in the lookup map.
    mcp_port_map = re.search(r"port\s*=\s*(\{[^}]*\})\[n\]", ecs)
    assert mcp_port_map
    mcp_ports = {
        k: int(v)
        for k, v in re.findall(r'"([\w-]+)"\s*=\s*(\d+)', mcp_port_map.group(1))
    }
    mcp_block = ecs[ecs.index("mcp_env = {") : ecs.index("eval_spec")]
    mcp_env_names = set(
        re.findall(
            r"^\s*([A-Z][A-Z_]+)\s*=", mcp_block.split("mcp_spec")[0], re.MULTILINE
        )
    )
    mcp_secret_names = set(
        re.findall(r"^\s*([A-Z][A-Z_]+)\s*=\s*\"\$\{", mcp_block, re.MULTILINE)
    )
    for name in ("core-read", "core-write", "comms"):
        assert mcp_ports[name] == compose_port(name), name
        compose_env = set(services[name]["environment"])
        assert compose_env == mcp_env_names | mcp_secret_names, name
        assert services[name]["command"] == [
            "python",
            "-m",
            f"toolgate_mcp_servers.{name.replace('-', '_')}",
        ]
    assert "toolgate_mcp_servers.${replace(n," in ecs

    for name in ("mock-api", "gateway"):
        block = _spec_block(ecs, name)
        assert re.search(rf"\bport\s*=\s*{compose_port(name)}\b", block), name
        tf_names = _names_in(block, "env") | _names_in(block, "secrets")
        compose_env = set(services[name].get("environment", {}))
        assert compose_env <= tf_names, (name, compose_env - tf_names)

    mock = _spec_block(ecs, "mock-api")
    assert (
        "python -m mock_enterprise.seed --reset && exec python -m mock_enterprise.app"
        in mock
    )
    # Gateway uses the image CMD (`toolgate-gateway serve`), as compose does.
    assert re.search(r"command\s*=\s*\[\]", _spec_block(ecs, "gateway"))
    migrate = _spec_block(ecs, "gateway-migrate")
    cmd = services["gateway-migrate"]["command"]
    for token in cmd:
        assert f'"{token}"' in migrate, token


def test_db_credentials_are_never_in_urls_or_plain_env():
    ecs = _ecs()
    # No userinfo in any URL or DSN.
    assert not re.search(r"://[^/\s\"]*@", ecs)
    for dsn in ("postgresql+asyncpg:///toolgate", "postgresql:///toolgate"):
        assert f'"{dsn}"' in ecs
    for name in ("mock-api", "gateway-migrate"):
        block = _spec_block(ecs, name)
        secrets = _names_in(block, "secrets")
        assert {"PGUSER", "PGPASSWORD"} <= secrets, name
        assert ":username::" in block and ":password::" in block
    gateway = _spec_block(ecs, "gateway")
    assert "PGPASSWORD" in _names_in(gateway, "secrets")
    assert "gateway_db_password" in gateway


def test_asyncpg_and_sqlalchemy_fall_back_to_pg_env(monkeypatch):
    """Verifies the empty-host DSNs used in the task definitions."""
    connect_utils = pytest.importorskip("asyncpg.connect_utils")
    sqlalchemy_url = pytest.importorskip("sqlalchemy.engine")
    pg_dialect = pytest.importorskip("sqlalchemy.dialects.postgresql.asyncpg")
    for key, value in {
        "PGHOST": "db.example.internal",
        "PGPORT": "5432",
        "PGUSER": "app user",
        "PGPASSWORD": "p:/@ss%w",
        "PGDATABASE": "ignored",
    }.items():
        monkeypatch.setenv(key, value)
    none_args = dict.fromkeys(
        (
            "host",
            "port",
            "user",
            "password",
            "passfile",
            "database",
            "ssl",
            "direct_tls",
            "server_settings",
            "target_session_attrs",
            "krbsrvname",
            "gsslib",
            "service",
            "servicefile",
        )
    )
    addrs, params = connect_utils._parse_connect_dsn_and_args(
        dsn="postgresql:///toolgate", **none_args
    )
    assert addrs == [("db.example.internal", 5432)]
    assert (params.user, params.password, params.database) == (
        "app user",
        "p:/@ss%w",
        "toolgate",
    )
    # SQLAlchemy forwards only the database, leaving host and credentials to asyncpg.
    url = sqlalchemy_url.make_url("postgresql+asyncpg:///toolgate")
    args, kwargs = pg_dialect.dialect().create_connect_args(url)
    assert args == [] and kwargs == {"database": "toolgate"}


def test_cloud_policy_downstreams_match_compose_ports():
    from toolgate_gateway.downstreams import load_downstreams

    cloud = load_downstreams(ROOT / "policy" / "gateway.cloud.yaml")
    local = load_downstreams(ROOT / "policy" / "gateway.yaml")
    assert {d.server_id for d in cloud} == {d.server_id for d in local}
    ports = {"core-read": 8101, "core-write": 8102, "comms": 8103}
    compose = yaml.safe_load((ROOT / "infra/docker-compose.yml").read_text("utf-8"))
    for name, port in ports.items():
        assert int(compose["services"][name]["ports"][0].rsplit(":", 1)[1]) == port
    assert {d.server_id for d in cloud} == set(ports)
    for d in cloud:
        assert d.url == f"http://{d.server_id}.toolgate.local:{ports[d.server_id]}/mcp"


def test_ecs_secrets_only_by_reference():
    ecs = _ecs()
    assert "valueFrom" in ecs
    # Any assignment whose name looks secret must be a reference, never a literal
    # (this also catches a value moved into an `environment`/`env` map).
    sensitive = re.compile(
        r"^\s*\w*(SECRET|PASSWORD|PASSWD|HMAC|TOKEN_VALUE|API_KEY)\w*\s*=\s*\"([^\"]*)\"",
        re.MULTILINE,
    )
    for match in sensitive.finditer(ecs):
        assert match.group(2).startswith("${"), match.group(0)
    # Secret-looking names never appear under an environment/env map.
    for name in ("mock-api", "gateway", "gateway-migrate"):
        env = _names_in(_spec_block(ecs, name), "env")
        assert not [n for n in env if re.search(r"SECRET|PASSWORD|HMAC", n)], name
    assert ecs.count("secret_string") == 1  # only the generated gateway secret
    assert ecs.count("random_password.gateway_db.result") == 1
    assert ecs.count("random_password.audit_hmac.result") == 1
    # Task roles carry no secret access; the execution role fetches `secrets`.
    assert ecs.count("secretsmanager:GetSecretValue") == 1
    assert 'data "aws_caller_identity" "current"' in ecs
    assert 'propagate_tags          = "SERVICE"' in ecs
    assert "enable_ecs_managed_tags = true" in ecs


def _mcp_spec_text(ecs: str) -> str:
    return ecs[ecs.index("mcp_spec = {") : ecs.index("eval_spec = {")]


def test_gateway_task_sets_cognito_mode_and_client_map():
    gateway = _spec_block(_ecs(), "gateway")
    env = _names_in(gateway, "env")
    assert {"GATEWAY_IDP", "GATEWAY_AGENT_CLIENT_MAP", "GATEWAY_TOKEN_SCOPE"} <= env
    assert re.search(r'GATEWAY_IDP\s*=\s*"cognito"', gateway)
    clients = _tf_map("clients")
    scope = re.search(r'GATEWAY_TOKEN_SCOPE\s*=\s*"([^"]*)"', gateway)
    assert scope
    # The gateway's one outbound token carries exactly its client's scopes.
    assert set(scope.group(1).split()) == clients["gateway"]
    assert scope.group(1) == "core-read/invoke core-write/invoke comms/invoke"


def test_agent_client_map_covers_exactly_the_three_agents_in_agents_yaml():
    agents = yaml.safe_load((ROOT / "policy/agents.yaml").read_text("utf-8"))["agents"]
    ecs = _ecs()
    listed = re.search(r"agents\s*=\s*\[(.*?)\]", ecs, re.DOTALL)
    assert listed
    assert re.findall(r'"([\w-]+)"', listed.group(1)) == list(agents)
    assert set(agents) == set(AGENTS)
    gateway = _spec_block(ecs, "gateway")
    assert (
        "jsonencode({ for agent in local.agents : var.app_client_ids[agent] => agent })"
        in gateway
    )
    # Only ids are mapped; no secret reaches the plain environment.
    assert "client_secret" not in gateway.split("secrets = {")[0]


def test_every_service_task_sets_idp_cognito():
    ecs = _ecs()
    gateway = _spec_block(ecs, "gateway")
    mock = _spec_block(ecs, "mock-api")
    mcp = _mcp_spec_text(ecs)
    assert re.search(r'GATEWAY_IDP\s*=\s*"cognito"', gateway)
    assert re.search(r"(?<![A-Z_])IDPs*=s*\"cognito\"", mock)
    assert re.search(r'SCOPE_PREFIX\s*=\s*"mock-enterprise/"', mock)
    assert re.search(r"(?<![A-Z_])IDPs*=s*\"cognito\"", mcp)
    assert "TOKEN_SCOPE = var.server_token_scopes[n]" in mcp
    # No task is left in the default (keycloak) mode.
    assert ecs.count('"cognito"') == 3


def test_server_token_scopes_match_cognito_clients():
    out = _read("modules/cognito/outputs.tf")
    assert re.search(
        r'output "server_token_scopes"\s*\{\s*value = \{ for n in '
        r'\["core-read", "core-write", "comms"\] : n => join\(" ", var.clients\[n\]\) \}',
        out,
    )
    clients = _tf_map("clients")
    realm = {c["clientId"]: c for c in _realm()["clients"]}
    for server in ("core-read", "core-write", "comms"):
        issued = {f"mock-enterprise/{s}" for s in realm[server]["defaultClientScopes"]}
        assert clients[server] == issued
    root = _read("main.tf")
    assert "server_token_scopes = module.cognito.server_token_scopes" in root
    assert "app_client_ids" in root
    for var in ("server_token_scopes", "app_client_ids"):
        assert f'variable "{var}"' in _read("modules/ecs/variables.tf")


def test_no_client_secret_in_plain_environment():
    ecs = _ecs()
    for name in ("gateway", "mock-api"):
        env = _names_in(_spec_block(ecs, name), "env")
        assert not [n for n in env if re.search(r"SECRET|CLIENT_ID", n)], name
    mcp_env_block = ecs[ecs.index("mcp_env = {") : ecs.index("mcp_spec = {")]
    assert not re.search(r"SECRET|CLIENT_ID", mcp_env_block)
    mcp = _mcp_spec_text(ecs)
    assert "client_secret::" in mcp
    env_part = mcp[mcp.index("env = merge") : mcp.index("secrets = {")]
    assert not re.search(r"SECRET|CLIENT_ID", env_part)
    gateway_env = _spec_block(ecs, "gateway").split("secrets = {")[0]
    assert "GATEWAY_CLIENT_SECRET" not in gateway_env
    assert "app_client_ids" in gateway_env  # ids only, never secrets


def _run_tf(tf: str, *args: str) -> None:
    res = subprocess.run(
        [tf, f"-chdir={TF}", *args], capture_output=True, text=True, check=False
    )
    assert res.returncode == 0, f"terraform {' '.join(args)}\n{res.stdout}{res.stderr}"


def test_terraform_fmt_and_validate():
    tf, reason = _terraform_bin()
    if not tf:
        pytest.skip(reason)
    _run_tf(
        tf, "init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"
    )
    _run_tf(tf, "fmt", "-check", "-recursive", "-no-color")
    _run_tf(tf, "validate", "-no-color")
