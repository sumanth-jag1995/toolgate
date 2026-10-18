from __future__ import annotations

from toolgate_pin.models import Target
from toolgate_pin.pinning import pin_server

TARGET = Target(command=("x",))


def _tool(name: str, desc: str) -> dict:
    return {
        "name": name,
        "description": desc,
        "inputSchema": {"type": "object", "properties": {}},
    }


def test_repin_keeps_unchanged_and_updates_changed():
    first = pin_server(
        "s",
        "srv",
        TARGET,
        [_tool("a", "alpha"), _tool("b", "beta"), _tool("c", "gamma")],
        approved_by="alice",
    )
    second = pin_server(
        "s",
        "srv",
        TARGET,
        [_tool("a", "alpha"), _tool("b", "beta\U000e0041hidden")],
        approved_by="bob",
        prior=first,
    )
    assert second.tools["a"] is first.tools["a"]
    assert second.tools["a"].approved_by == "alice"
    b = second.tools["b"]
    assert b.approved_by == "bob" and b.hash != first.tools["b"].hash
    assert set(b.scan) == {"verdict", "rule_ids", "tiers"}
    assert "TG-UNI-001" in b.scan["rule_ids"]
    assert b.scan["tiers"] == ["rules"]
    assert "c" not in second.tools


def test_initial_pin_summary():
    sp = pin_server("s", "srv", TARGET, [_tool("a", "alpha")], approved_by="me")
    tp = sp.tools["a"]
    assert tp.approved_by == "me" and tp.approved_at.endswith("Z")
    assert tp.scan["verdict"] == "benign" and tp.scan["rule_ids"] == []
