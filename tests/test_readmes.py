"""Documentation checks for the top-level README and the toolgate-pin README."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOP = ROOT / "README.md"
PIN = ROOT / "packages" / "toolgate-pin" / "README.md"

MERMAID_KEYWORDS = (
    "flowchart",
    "graph",
    "sequenceDiagram",
    "stateDiagram-v2",
    "classDiagram",
)

FLOW_NODES = [
    "Agent",
    "Keycloak",
    "Gateway",
    "auth",
    "allowlist",
    "pin check",
    "schema validation",
    "forward",
    "output scan",
    "audit",
    "core-read",
    "core-write",
    "comms",
    "Mock enterprise API",
    "Postgres audit",
    "OTel/Tempo",
    "Attacker server",
    "Sink",
]


def _mermaid_blocks(text: str) -> list[str]:
    return re.findall(r"^```mermaid\n(.*?)^```$", text, flags=re.DOTALL | re.MULTILINE)


def _section(text: str, heading: str) -> str:
    """Body of the `## heading` section (up to the next `## `)."""
    m = re.search(
        rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.DOTALL | re.MULTILINE
    )
    assert m, f"missing section: {heading}"
    return m.group(1)


def test_top_level_has_two_mermaid_diagrams_with_required_nodes():
    blocks = _mermaid_blocks(TOP.read_text(encoding="utf-8"))
    assert len(blocks) == 2
    flow, seq = blocks
    assert flow.lstrip().startswith("flowchart")
    assert seq.lstrip().startswith("sequenceDiagram")
    missing = [n for n in FLOW_NODES if n not in flow]
    assert not missing, f"architecture diagram lacks: {missing}"
    for step in ("tools/list", "tools/call", "drift", "review"):
        assert step in seq, f"sequence diagram lacks: {step}"


@pytest.mark.parametrize("path", [TOP, PIN], ids=["top", "pin"])
def test_mermaid_blocks_are_balanced(path: Path):
    text = path.read_text(encoding="utf-8")
    fences = [ln for ln in text.splitlines() if ln.startswith("```")]
    opens = [ln for ln in fences[0::2]]
    closes = [ln for ln in fences[1::2]]
    assert len(fences) % 2 == 0, "unclosed code fence"
    assert all(ln.strip() == "```" for ln in closes)
    assert opens, "no code fences"
    blocks = _mermaid_blocks(text)
    assert len(blocks) == sum(1 for ln in opens if ln.strip() == "```mermaid")
    for block in blocks:
        first = block.strip().splitlines()[0].strip()
        assert first.split()[0] in MERMAID_KEYWORDS, first
        assert block.count("[") == block.count("]")
        assert block.count("(") == block.count(")")
        assert block.count('"') % 2 == 0


def test_no_fixture_tables_in_top_level():
    text = TOP.read_text(encoding="utf-8")
    assert "FIXTURE" not in text
    assert "pending" in _section(text, "Results: canary matrix").lower()
    assert "pending" in _section(text, "AgentCore comparison").lower()
    assert "F2" in _section(text, "AgentCore comparison")


def test_relative_links_resolve():
    for path in (TOP, PIN):
        text = path.read_text(encoding="utf-8")
        text = re.sub(r"^```.*?^```$", "", text, flags=re.DOTALL | re.MULTILINE)
        for target in re.findall(r"\]\(([^)\s]+)\)", text):
            if re.match(r"^(https?:|mailto:|#)", target):
                continue
            rel = target.split("#", 1)[0]
            assert (path.parent / rel).exists(), f"{path.name}: broken link {target}"


def _subcommands(parser) -> set[str]:
    import argparse

    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices)
    return set()


def test_commands_in_readme_exist():
    from toolgate_eval.cli import _parser as eval_parser
    from toolgate_gateway.cli import _parser as gw_parser

    text = TOP.read_text(encoding="utf-8")
    eval_subs = _subcommands(eval_parser())
    gw_subs = _subcommands(gw_parser())
    pin_subs = {"demo", "demo-server", "approve", "check", "bench"}
    found = {
        "eval": set(re.findall(r"toolgate-eval ([a-z][\w-]*)", text)),
        "gateway": set(re.findall(r"toolgate-gateway ([a-z][\w-]*)", text)),
        "pin": set(re.findall(r"toolgate-pin ([a-z][\w-]*)", text)),
    }
    assert found["eval"], "README mentions no toolgate-eval command"
    assert found["eval"] <= eval_subs, found["eval"] - eval_subs
    assert found["gateway"] <= gw_subs, found["gateway"] - gw_subs
    assert found["pin"] <= pin_subs, found["pin"] - pin_subs
    # every script and make target the README names exists
    for script in set(re.findall(r"scripts/([\w.-]+\.(?:py|sh))", text)):
        assert (ROOT / "scripts" / script).exists(), script
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    for target in set(re.findall(r"make (aws-[\w-]+)", text)):
        assert f"{target}:" in makefile, target


def test_pin_readme_has_lifecycle_diagram():
    text = PIN.read_text(encoding="utf-8")
    life = _section(text, "Lifecycle")
    blocks = _mermaid_blocks(life)
    assert len(blocks) == 1
    block = blocks[0]
    assert block.lstrip().startswith(("stateDiagram-v2", "flowchart"))
    for word in ("pin", "verify", "drift", "quarantine", "approve"):
        assert word in block.lower(), word


def test_cognito_token_gaps_documented():
    top = TOP.read_text(encoding="utf-8")
    tf = (ROOT / "infra" / "terraform" / "README.md").read_text(encoding="utf-8")
    for text in (top, tf):
        for needle in ("`aud`", "`azp`", "client_id", "members:read"):
            assert needle in text, needle
    assert "next task" not in tf and "Task 6" not in tf
