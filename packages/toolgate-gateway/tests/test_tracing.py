"""OpenTelemetry spans: one tree per tools/list and tools/call, the audit
trace id equal to the call span's, and no sensitive values in any span."""

import re

import pytest
from mcp.server.fastmcp import FastMCP
from toolgate_gateway.core import GatewayCore
from toolgate_gateway.downstreams import DownstreamConfig
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist
from toolgate_gateway.pool import DownstreamPool
from toolgate_gateway.tracing import setup_tracing
from toolgate_pin.demo_server import build_demo_server

CONFIGS = [
    DownstreamConfig("core-read", "http://core-read.test/mcp"),
    DownstreamConfig("core-write", "http://core-write.test/mcp"),
]
ALLOWLIST = Allowlist({"servicing": ("core-read.*",)})
SECRET = "S3CRET-ARG-VALUE"
NAME = "core-read.get_claim_status"


class FakeAudit:
    accepting = True

    def __init__(self):
        self.records = []

    def submit(self, rec):
        self.records.append(rec)
        return True


@pytest.fixture
async def core(tmp_path, memory_factory_cls, build_core_write, write_lockfile):
    builders = {"core-read": build_demo_server, "core-write": build_core_write}
    lock = tmp_path / "toolgate.lock.json"
    await write_lockfile(lock, builders, CONFIGS)
    pool = DownstreamPool(CONFIGS, memory_factory_cls(builders))
    await pool.start()
    core = GatewayCore(
        pool, PinSource(lock), ALLOWLIST, FakeAudit(), None, hmac_key="k" * 32
    )
    await core.refresh_snapshot()
    yield core
    await pool.close()


def by_name(exporter):
    return {s.name: s for s in exporter.get_finished_spans()}


async def test_call_span_tree(core, spans):
    spans.clear()
    result = await core.call_tool("servicing", "a", NAME, {"claim_id": "C-1"})
    assert not result.isError
    got = by_name(spans)
    root = got["gateway.tools_call"]
    assert root.parent is None
    stages = [
        "gateway.auth_scope",
        "gateway.pin_check",
        "gateway.schema",
        "gateway.forward",
        "gateway.output_scan",
        "gateway.audit",
    ]
    for name in stages:
        assert got[name].parent.span_id == root.context.span_id, name
    assert root.attributes["toolgate.decision"] == "allow"
    assert root.attributes["toolgate.client_id"] == "servicing"
    assert root.attributes["toolgate.tool"] == NAME
    assert root.attributes["toolgate.tool_hash"] == core.snapshot[NAME].tool_hash
    # only the deciding stage carries the decision
    deciding = [n for n in stages if "toolgate.decision" in got[n].attributes]
    assert deciding == ["gateway.output_scan"]
    assert got["gateway.output_scan"].attributes["toolgate.decision"] == "allow"


async def test_denied_call_has_only_reached_stages(core, spans):
    spans.clear()
    await core.call_tool("servicing", "a", "core-write.log_claim", {})
    got = by_name(spans)
    assert "gateway.forward" not in got
    assert "gateway.pin_check" not in got
    assert got["gateway.auth_scope"].attributes["toolgate.decision"] == "deny_scope"
    assert got["gateway.tools_call"].attributes["toolgate.decision"] == "deny_scope"
    assert "gateway.audit" in got


async def test_tools_list_span(core, spans):
    spans.clear()
    tools = await core.list_tools("servicing")
    got = by_name(spans)
    root = got["gateway.tools_list"]
    assert root.attributes["toolgate.client_id"] == "servicing"
    assert root.attributes["toolgate.allowed_count"] == len(tools) > 0
    assert root.attributes["toolgate.quarantined_count"] == 0
    # toolgate_pin spans nest under the gateway span via the global tracer
    verify = got["toolgate.pin.verify"]
    assert verify.context.trace_id == root.context.trace_id


async def test_alert_span_event_has_no_definitions(
    core, spans, tmp_path, memory_factory_cls, build_core_write
):
    def drifted():
        server = FastMCP("core-read")

        @server.tool(name="get_claim_status", description="CHANGED DESCRIPTION")
        def get_claim_status(claim_id: str) -> str:
            return "x"

        return server

    builders = {"core-read": drifted, "core-write": build_core_write}
    pool = DownstreamPool(CONFIGS, memory_factory_cls(builders))
    await pool.start()
    try:
        drift_core = GatewayCore(
            pool,
            PinSource(tmp_path / "toolgate.lock.json"),
            ALLOWLIST,
            FakeAudit(),
            None,
            hmac_key="k" * 32,
        )
        spans.clear()
        await drift_core.list_tools("servicing")
    finally:
        await pool.close()
    root = by_name(spans)["gateway.tools_list"]
    assert root.attributes["toolgate.quarantined_count"] >= 1
    events = [e for e in root.events if e.name == "toolgate.alert"]
    assert events
    for e in events:
        assert set(e.attributes) == {
            "toolgate.server_id",
            "toolgate.tool",
            "toolgate.reason",
            "toolgate.observed_hash",
            "toolgate.pinned_hash",
        }
        assert "CHANGED" not in repr(dict(e.attributes))


async def test_audit_trace_id_matches_span(core, spans):
    spans.clear()
    await core.call_tool("servicing", "a", NAME, {"claim_id": "C-1"})
    [rec] = core.audit.records
    root = by_name(spans)["gateway.tools_call"]
    assert re.fullmatch(r"[0-9a-f]{32}", rec.trace_id)
    assert rec.trace_id == format(root.context.trace_id, "032x")


async def test_audit_trace_id_none_without_provider(core):
    await core.call_tool("servicing", "a", NAME, {"claim_id": "C-1"})
    [rec] = core.audit.records
    assert rec.trace_id is None


def test_setup_without_endpoint_is_noop(monkeypatch):
    from opentelemetry import trace

    calls = []
    monkeypatch.setattr(trace, "set_tracer_provider", lambda p: calls.append(p))
    setup_tracing("toolgate-gateway", None)
    setup_tracing("toolgate-gateway", "")
    assert calls == []


def test_setup_with_endpoint_installs_provider(monkeypatch):
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    calls = []
    monkeypatch.setattr(trace, "set_tracer_provider", lambda p: calls.append(p))
    setup_tracing("toolgate-gateway", "http://tempo.test:4318")
    (provider,) = calls
    assert isinstance(provider, TracerProvider)
    assert provider.resource.attributes["service.name"] == "toolgate-gateway"
    provider.shutdown()
