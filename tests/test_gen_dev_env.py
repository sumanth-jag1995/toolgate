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
