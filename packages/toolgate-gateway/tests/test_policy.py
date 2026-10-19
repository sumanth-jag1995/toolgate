from pathlib import Path

import pytest
from toolgate_gateway.downstreams import (
    load_downstreams,
    namespaced,
    split_namespaced,
)
from toolgate_gateway.policy import Allowlist, PolicyError

ROOT = Path(__file__).resolve().parents[3]
AGENTS = ROOT / "policy" / "agents.yaml"
GATEWAY = ROOT / "policy" / "gateway.yaml"
a = Allowlist.load(AGENTS)


def test_glob_and_exact():
    assert a.allowed("servicing", "core-read.get_claim_status")
    assert a.allowed("servicing", "core-write.add_claim_note")


def test_deny_by_default():
    assert not a.allowed("servicing", "core-write.log_claim")
    assert not a.allowed("unknown-client", "core-read.get_claim_status")


def test_fraud_triage_read_only():
    assert not any(
        a.allowed("fraud-triage", f"core-write.{t}")
        for t in ("log_claim", "add_claim_note")
    )


def test_glob_does_not_cross_namespace():
    assert not a.allowed("fraud-triage", "core-readx.get_claim_status")


def test_clients():
    assert a.clients == {"servicing", "claims-intake", "fraud-triage"}


def test_malformed_policy_raises(tmp_path):
    bad = tmp_path / "a.yaml"
    bad.write_text("agents: [unclosed", encoding="utf-8")
    with pytest.raises(PolicyError) as e:
        Allowlist.load(bad)
    assert str(bad) in str(e.value)
    bad.write_text("agents:\n  x: notalist\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        Allowlist.load(bad)
    with pytest.raises(PolicyError):
        Allowlist.load(tmp_path / "missing.yaml")


def test_split_namespaced():
    assert split_namespaced("core-read.get_claim_status") == (
        "core-read",
        "get_claim_status",
    )
    assert split_namespaced("nodot") is None
    assert namespaced("comms", "x") == "comms.x"


def test_load_downstreams():
    ds = load_downstreams(GATEWAY)
    assert [(d.server_id, d.url) for d in ds] == [
        ("core-read", "http://core-read:8101/mcp"),
        ("core-write", "http://core-write:8102/mcp"),
        ("comms", "http://comms:8103/mcp"),
    ]


@pytest.mark.parametrize("sid", ["Bad", "1abc", "a_b", "", "a" * 42])
def test_bad_downstream_id_rejected(tmp_path, sid):
    f = tmp_path / "g.yaml"
    f.write_text(
        f'downstreams:\n  - server_id: "{sid}"\n    url: http://x/mcp\n',
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_downstreams(f)


def test_duplicate_downstream_rejected(tmp_path):
    f = tmp_path / "g.yaml"
    f.write_text(
        "downstreams:\n  - {server_id: a, url: http://x}\n  - {server_id: a, url: http://y}\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_downstreams(f)


def test_downstream_id_with_trailing_newline_rejected(tmp_path):
    f = tmp_path / "g.yaml"
    # YAML "\n" escape: the parsed id is "core-read" plus a newline, which
    # re.match with "$" would accept.
    f.write_text(
        'downstreams:\n  - server_id: "core-read\\n"\n    url: http://x/mcp\n',
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_downstreams(f)
