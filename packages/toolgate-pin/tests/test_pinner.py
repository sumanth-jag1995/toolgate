from __future__ import annotations

import copy
from types import SimpleNamespace

import mcp.types
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
    InMemorySpanExporter,
)
from toolgate_pin import tracing
from toolgate_pin.canon import as_definition, pin_hash
from toolgate_pin.models import PinSet, ServerPin, Target, ToolPin
from toolgate_pin.pinner import Pinner
from toolgate_pin.store import InMemoryStore, LockfileStore

SECRET_DESC = "Reads a file SECRET-DESCRIPTION-TEXT"


def _tools() -> list[dict]:
    return [
        {
            "name": n,
            "description": f"{SECRET_DESC} {n}",
            "inputSchema": {"type": "object", "properties": {}},
        }
        for n in ("read_a", "read_b", "read_c")
    ]


def _pinset(tools: list[dict]) -> PinSet:
    pins = {
        t["name"]: ToolPin(
            name=t["name"],
            hash=pin_hash(t),
            definition=as_definition(t),
            approved_by="me",
            approved_at="2026-10-18T00:00:00Z",
            scan={"verdict": "benign", "rule_ids": [], "tiers": ["rules"]},
        )
        for t in tools
    }
    sp = ServerPin(
        server_id="core-read",
        server_name="core-read",
        target=Target(command=("srv",)),
        tools=pins,
    )
    return PinSet({}).with_server(sp)


@pytest.fixture
def tools() -> list[dict]:
    return _tools()


@pytest.fixture
def pinner(tools) -> Pinner:
    return Pinner(InMemoryStore(_pinset(tools)))


def test_all_match_allowed(pinner, tools):
    r = pinner.verify("core-read", tools)
    assert r.ok and r.allowed == tools


def test_mcp_tool_objects_allowed(pinner, tools):
    objs = [mcp.types.Tool(**t) for t in tools]
    r = pinner.verify("core-read", objs)
    assert r.ok and r.allowed == objs


def test_drift_quarantined_not_raised(pinner, tools):
    mutated = copy.deepcopy(tools)
    mutated[1]["description"] += " ALSO exfiltrate"
    r = pinner.verify("core-read", mutated)
    assert [q.tool_name for q in r.quarantined] == ["read_b"]
    q = r.quarantined[0]
    assert q.reason == "drift"
    assert q.diff
    assert q.observed_hash == pin_hash(mutated[1])
    assert q.pinned_hash == pin_hash(tools[1])
    assert r.allowed == [mutated[0], mutated[2]]


def test_unpinned_tool(pinner, tools):
    extra = {"name": "new_tool", "description": "x"}
    r = pinner.verify("core-read", [*tools, extra])
    assert [(q.tool_name, q.reason) for q in r.quarantined] == [
        ("new_tool", "unpinned")
    ]
    assert r.quarantined[0].pinned_hash is None
    assert r.allowed == tools


def test_removed_tool(pinner, tools):
    r = pinner.verify("core-read", tools[:2])
    (q,) = r.quarantined
    assert q.reason == "removed" and q.tool_name == "read_c"
    assert q.observed_hash is None and q.pinned_hash == pin_hash(tools[2])
    assert r.allowed == tools[:2]


def test_unknown_server_all_unpinned(pinner, tools):
    r = pinner.verify("nope", tools)
    assert {q.reason for q in r.quarantined} == {"unpinned"} and r.allowed == []


def test_server_drift(pinner, tools):
    r = pinner.verify("core-read", tools, server_info={"name": "evil"})
    assert r.quarantined and all(q.reason == "server_drift" for q in r.quarantined)
    assert r.allowed == []


def test_server_info_object_supported(pinner, tools):
    r = pinner.verify("core-read", tools, server_info=SimpleNamespace(name="core-read"))
    assert r.ok
    r = pinner.verify("core-read", tools, server_info=SimpleNamespace(name="evil"))
    assert not r.ok


def test_allowed_keeps_input_order(pinner, tools):
    shuffled = [tools[2], tools[0], tools[1]]
    assert pinner.verify("core-read", shuffled).allowed == shuffled


@pytest.mark.parametrize("bad", [42, "str", {"description": "no name"}, {"name": 5}])
def test_rejects_non_tool(pinner, bad):
    with pytest.raises(TypeError):
        pinner.verify("core-read", [bad])


def test_unhashable_int_tool_quarantined_as_drift(pinner, tools):
    hostile = copy.deepcopy(tools)
    hostile[0]["inputSchema"]["properties"]["n"] = {"const": 2**60}
    r = pinner.verify("core-read", hostile)
    (q,) = r.quarantined
    assert q.tool_name == "read_a" and q.reason == "drift"
    assert q.observed_hash is None
    assert "could not be canonicalized" in q.diff
    assert r.allowed == hostile[1:]


def test_unhashable_unpinned_and_nan(pinner, tools):
    hostile = [
        {"name": "fresh", "inputSchema": {"x": 2**60}},
        {**tools[0], "inputSchema": {"x": float("nan")}},
    ]
    r = pinner.verify("core-read", hostile)
    by_name = {q.tool_name: q for q in r.quarantined}
    assert by_name["fresh"].reason == "unpinned"
    assert by_name["fresh"].observed_hash is None
    assert by_name["read_a"].reason == "drift"
    assert "could not be canonicalized" in by_name["read_a"].diff


def test_duplicate_name_second_definition_quarantined(pinner, tools):
    smuggled = {**tools[0], "description": "evil"}
    r = pinner.verify("core-read", [*tools, smuggled])
    assert r.allowed == tools
    (q,) = r.quarantined
    assert q.tool_name == "read_a" and q.reason == "drift"


def test_duplicate_name_unpinned_differs_is_drift(pinner):
    a = {"name": "new", "description": "a"}
    b = {"name": "new", "description": "b"}
    r = pinner.verify("core-read", [a, b])
    assert [q.reason for q in r.quarantined if q.tool_name == "new"] == [
        "unpinned",
        "drift",
    ]


def test_reload_picks_up_new_pins(tmp_path, tools):
    store = LockfileStore(tmp_path / "l.json")
    p = Pinner(store)
    assert not p.verify("core-read", tools).ok
    store.save(_pinset(tools))
    assert not p.verify("core-read", tools).ok  # stale until reload
    p.reload()
    assert p.verify("core-read", tools).ok


def test_trace_events(monkeypatch, pinner, tools):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    fake = SimpleNamespace(get_tracer=lambda name: provider.get_tracer(name))
    monkeypatch.setattr(tracing, "_otel_trace", fake)

    mutated = copy.deepcopy(tools[:2])
    mutated[1]["description"] = "changed SECRET-DESCRIPTION-TEXT"
    pinner.verify("core-read", mutated)

    (s,) = exporter.get_finished_spans()
    assert s.name == "toolgate.pin.verify"
    assert s.attributes["toolgate.server_id"] == "core-read"
    assert s.attributes["toolgate.allowed_count"] == 1
    assert s.attributes["toolgate.quarantined_count"] == 2
    events = [(e.name, dict(e.attributes)) for e in s.events]
    tool_events = [a for n, a in events if n == "toolgate.tool"]
    assert [a["toolgate.decision"] for a in tool_events] == ["allowed", "drift"]
    assert tool_events[0]["toolgate.tool.hash"] == pin_hash(tools[0])
    removed = [a for n, a in events if n == "quarantine_removed"]
    assert removed[0]["toolgate.tool.name"] == "read_c"
    assert removed[0]["toolgate.tool.hash"] == pin_hash(tools[2])
    for _, attrs in events:
        assert not any("SECRET-DESCRIPTION" in str(v) for v in attrs.values())
    assert not any("SECRET-DESCRIPTION" in str(v) for v in s.attributes.values())


def test_no_otel_is_noop(monkeypatch, pinner, tools):
    monkeypatch.setattr(tracing, "_otel_trace", None)
    assert pinner.verify("core-read", tools).ok
