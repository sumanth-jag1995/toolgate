import json
from pathlib import Path

import pytest

from scripts.gen_dev_env import generate_env, render_realm

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / "infra" / "keycloak" / "toolgate-realm.template.json"


def test_generate_env_replaces_placeholders(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\nB=change-me\nC=fixed\n")
    env = generate_env(ex, tmp_path / ".env")
    assert (
        env["C"] == "fixed"
        and env["A"] != "change-me"
        and env["A"] != env["B"]
        and len(env["A"]) >= 32
    )
    assert (tmp_path / ".env").read_text().splitlines()[2] == "C=fixed"


def test_generate_env_refuses_overwrite(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\n")
    out = tmp_path / ".env"
    out.write_text("A=keep\n")
    with pytest.raises(FileExistsError):
        generate_env(ex, out)
    assert out.read_text() == "A=keep\n"
    env = generate_env(ex, out, overwrite=True)
    assert env["A"] != "keep"


def test_render_realm_fails_on_unresolved(tmp_path):
    t = tmp_path / "t.json"
    t.write_text('{"secret": "${MISSING}"}')
    with pytest.raises(ValueError):
        render_realm(t, tmp_path / "o.json", {})


def test_render_realm_substitutes(tmp_path):
    t = tmp_path / "t.json"
    t.write_text('{"secret": "${S}"}')
    render_realm(t, tmp_path / "o.json", {"S": "abc"})
    assert json.loads((tmp_path / "o.json").read_text()) == {"secret": "abc"}


def test_committed_template_has_no_literal_secrets():
    data = json.loads(TEMPLATE.read_text())
    secrets_ = [c["secret"] for c in data["clients"] if "secret" in c]
    assert secrets_ and all(s.startswith("${") and s.endswith("}") for s in secrets_)


def test_committed_template_renders_with_example_keys(tmp_path):
    env = generate_env(ROOT / ".env.example", tmp_path / ".env")
    out = tmp_path / "realm.json"
    render_realm(TEMPLATE, out, env)
    rendered = json.loads(out.read_text())
    assert rendered["realm"] == "toolgate"
    assert "${" not in out.read_text()


def test_committed_template_client_default_scopes_are_exact():
    data = json.loads(TEMPLATE.read_text())
    got = {c["clientId"]: set(c["defaultClientScopes"]) for c in data["clients"]}
    assert got["core-read"] == {
        "members:read",
        "policies:read",
        "claims:read",
        "payments:read",
        "comms:read",
    }
    assert got["core-write"] == {"claims:write", "members:write"}
    assert got["comms"] == {"comms:write"}


GATEWAY_CLIENTS = ("servicing", "claims-intake", "fraud-triage", "toolgate-gateway")


def _clients() -> dict[str, dict]:
    data = json.loads(TEMPLATE.read_text())
    return {c["clientId"]: c for c in data["clients"]}


def _audiences(client: dict) -> set[str]:
    return {
        m["config"]["included.custom.audience"]
        for m in client.get("protocolMappers", [])
        if m["protocolMapper"] == "oidc-audience-mapper"
    }


def test_committed_template_gateway_clients_have_no_scopes():
    clients = _clients()
    for cid in GATEWAY_CLIENTS:
        c = clients[cid]
        assert c["defaultClientScopes"] == [], cid
        assert c["optionalClientScopes"] == [], cid
        assert c["fullScopeAllowed"] is False, cid
        assert c["publicClient"] is False, cid
        assert c["serviceAccountsEnabled"] is True, cid
        assert c["standardFlowEnabled"] is False, cid
        assert c["directAccessGrantsEnabled"] is False, cid
        assert c["implicitFlowEnabled"] is False, cid


def test_committed_template_gateway_client_audiences():
    clients = _clients()
    for cid in ("servicing", "claims-intake", "fraud-triage"):
        assert _audiences(clients[cid]) == {"toolgate-gateway"}, cid
    assert _audiences(clients["toolgate-gateway"]) == {
        "core-read",
        "core-write",
        "comms",
    }


def test_committed_template_gateway_client_secrets_are_placeholders():
    clients = _clients()
    expected = {
        "servicing": "${SERVICING_CLIENT_SECRET}",
        "claims-intake": "${CLAIMS_INTAKE_CLIENT_SECRET}",
        "fraud-triage": "${FRAUD_TRIAGE_CLIENT_SECRET}",
        "toolgate-gateway": "${GATEWAY_CLIENT_SECRET}",
    }
    assert {cid: clients[cid]["secret"] for cid in expected} == expected


def test_env_example_has_gateway_keys_as_placeholders():
    pairs = dict(
        line.split("=", 1)
        for line in (ROOT / ".env.example").read_text().splitlines()
        if "=" in line and not line.startswith("#")
    )
    for key in (
        "SERVICING_CLIENT_SECRET",
        "CLAIMS_INTAKE_CLIENT_SECRET",
        "FRAUD_TRIAGE_CLIENT_SECRET",
        "GATEWAY_CLIENT_SECRET",
        "GATEWAY_DB_PASSWORD",
        "AUDIT_HMAC_KEY",
    ):
        assert pairs.get(key) == "change-me", key


def test_generate_env_add_missing_keeps_existing_and_appends_new(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\nB=change-me\nC=fixed\n")
    out = tmp_path / ".env"
    out.write_text("# local\nA=keep-a\n")
    env = generate_env(ex, out, add_missing=True)
    lines = out.read_text().splitlines()
    assert lines[:2] == ["# local", "A=keep-a"]
    assert env["A"] == "keep-a"
    assert env["C"] == "fixed"
    assert env["B"] != "change-me" and len(env["B"]) >= 32
    assert lines[2:] == [f"B={env['B']}", "C=fixed"]


def test_generate_env_add_missing_is_idempotent(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\n")
    out = tmp_path / ".env"
    first = generate_env(ex, out, add_missing=True)  # no .env yet: creates it
    before = out.read_text()
    again = generate_env(ex, out, add_missing=True)
    assert again == first and out.read_text() == before


def test_generate_env_add_missing_handles_missing_trailing_newline(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\nB=fixed\n")
    out = tmp_path / ".env"
    out.write_text("A=keep")
    generate_env(ex, out, add_missing=True)
    assert out.read_text().splitlines() == ["A=keep", "B=fixed"]


def test_generate_env_add_missing_and_overwrite_are_exclusive(tmp_path):
    ex = tmp_path / ".env.example"
    ex.write_text("A=change-me\n")
    with pytest.raises(ValueError):
        generate_env(ex, tmp_path / ".env", overwrite=True, add_missing=True)


def test_main_add_missing_flag_keeps_existing_env(tmp_path, monkeypatch, capsys):
    import scripts.gen_dev_env as gen

    (tmp_path / "infra" / "keycloak").mkdir(parents=True)
    (tmp_path / "infra" / "keycloak" / "toolgate-realm.template.json").write_text(
        '{"a": "${A}", "b": "${B}"}'
    )
    (tmp_path / ".env.example").write_text("A=change-me\nB=change-me\n")
    (tmp_path / ".env").write_text("A=keep-a\n")
    monkeypatch.setattr(gen, "_ROOT", tmp_path)
    with pytest.raises(FileExistsError):
        gen.main([])
    gen.main(["--add-missing"])
    env = dict(
        line.split("=", 1) for line in (tmp_path / ".env").read_text().splitlines()
    )
    assert env["A"] == "keep-a" and len(env["B"]) >= 32
    rendered = json.loads(
        (tmp_path / "infra/keycloak/generated/toolgate-realm.json").read_text()
    )
    assert rendered == {"a": "keep-a", "b": env["B"]}
    assert env["B"] not in capsys.readouterr().out
