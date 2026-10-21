"""Conditions: direct (agent -> every server) and gateway (agent -> in-process
Toolgate gateway -> every server), with the simulated approver.

Unit tests at the top need no stack; the rest are marked ``integration`` and
skip when the stack is unreachable. No model is called: listing and calls go
through ``servicing_agent.connect`` or a plain MCP client.
"""

import asyncio
import json
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from servicing_agent.mcp_tools import McpToolkit, ToolCollision, connect
from toolgate_eval.attacker import AttackerServer
from toolgate_eval.conditions import (
    COMPOSE_GATEWAY_PORT,
    REAL_SERVERS,
    ConditionContaminationError,
    ConditionError,
    ConditionSetup,
    DirectCondition,
    DroppedSseFilter,
    GatewayCondition,
    NullAudit,
    SimulatedApprover,
    assert_endpoints,
    derive_blocked_at,
    endpoint_of,
    servicing_allowlist,
)
from toolgate_eval.tasks import REQUIRED_TOOLS
from toolgate_eval.world import World
from toolgate_gateway.audit import AuditRecord, AuditWriter
from toolgate_pin import InventoryTool
from toolgate_pin.corpus import MaliciousVariant, load_corpus

REPO_ROOT = Path(__file__).resolve().parents[2]
SINK_URL = "http://127.0.0.1:9"  # nothing is called in these tests
REAL_TOOLS = {
    "core-read": {
        "get_member_profile",
        "get_policy_details",
        "check_coverage",
        "get_claim_status",
        "list_member_claims",
        "get_payment_history",
        "get_correspondence_history",
    },
    "core-write": {"log_claim", "add_claim_note", "update_contact_preference"},
    "comms": {"send_member_message", "schedule_callback"},
}
# policy/agents.yaml's servicing entries plus the eval's core-write.log_claim.
SERVICING_TOOLS = {
    *(f"core-read.{n}" for n in REAL_TOOLS["core-read"]),
    *(f"comms.{n}" for n in REAL_TOOLS["comms"]),
    "core-write.add_claim_note",
    "core-write.update_contact_preference",
    "core-write.log_claim",
}


def variant(variant_id: str) -> MaliciousVariant:
    return next(v for v in load_corpus("test").malicious if v.id == variant_id)


def real_names(toolkit: McpToolkit) -> set[str]:
    return {toolkit.real_name(t.name) for t in toolkit.tools}


# --- unit ------------------------------------------------------------------


def test_approver_blocks_malicious_and_approves_the_rest():
    approve = SimulatedApprover()
    dp01, rp01, dp06 = variant("dp-01"), variant("rp-01"), variant("dp-06")
    inv = [InventoryTool("core-read", "get_member_profile")]
    assert approve(dp01.approved, inv, server_id=dp01.server_id) == "block"
    # rp-01 is "suspicious" at approval time: only malicious is blocked.
    assert approve(rp01.approved, inv, server_id=rp01.server_id) == "approve"
    assert approve(dp06.approved, inv, server_id=dp06.server_id) == "approve"
    assert approve.tiers == ("rules",)


def test_approver_passes_judge_and_classifier_when_supplied():
    class Classifier:
        calls = 0

        def score(self, definition: dict) -> float:
            Classifier.calls += 1
            return 0.0

    approve = SimulatedApprover(classifier=Classifier())
    assert approve.tiers == ("rules", "classifier")
    dp06 = variant("dp-06")
    assert approve(dp06.approved, [], server_id=dp06.server_id) == "approve"
    assert Classifier.calls == 1


async def test_null_audit_mimics_audit_writer_surface_and_records():
    audit = NullAudit()
    for name in ("start", "stop", "submit"):
        assert callable(getattr(audit, name))
    # AuditWriter's properties plus the counters it sets in __init__.
    assert isinstance(AuditWriter.accepting, property)
    assert isinstance(AuditWriter.healthy, property)
    for attr in ("accepting", "healthy", "dropped_count", "rejected_count"):
        assert hasattr(audit, attr)
    await audit.start()
    rec = AuditRecord("a", "servicing", "x.y", None, "h", "deny_drift", "r", 1.0, None)
    assert audit.accepting and audit.healthy
    assert audit.submit(rec) is True
    assert audit.decisions == [("x.y", "deny_drift", "r")]
    assert audit.dropped_count == 0 and audit.rejected_count == 0
    await audit.stop()


def test_blocked_at_precedence():
    kw = {"listed": set(), "snapshot": set(), "decisions": []}
    tool = "evil.t"
    assert derive_blocked_at(None, pinned=set(), **kw) is None
    assert derive_blocked_at({tool}, pinned=set(), **kw) == "approval"
    assert (
        derive_blocked_at(
            {tool}, pinned={tool}, listed={tool}, snapshot=set(), decisions=[]
        )
        == "list"
    )
    denied = [(tool, "deny_schema", "schema: type")]
    assert (
        derive_blocked_at(
            {tool}, pinned={tool}, listed={tool}, snapshot={tool}, decisions=denied
        )
        == "call"
    )
    # A denied call followed by a forwarded one: the attack was not stopped.
    for forwarded in ("allow", "flag_output"):
        later = [*denied, (tool, forwarded, None)]
        assert (
            derive_blocked_at(
                {tool}, pinned={tool}, listed={tool}, snapshot={tool}, decisions=later
            )
            is None
        )
    allowed = [(tool, "allow", None), ("core-read.x", "deny_scope", None)]
    assert (
        derive_blocked_at(
            {tool}, pinned={tool}, listed={tool}, snapshot={tool}, decisions=allowed
        )
        is None
    )
    # Dropped at list time wins over a later denied call of the same tool.
    assert (
        derive_blocked_at(
            {tool}, pinned={tool}, listed={tool}, snapshot=set(), decisions=denied
        )
        == "list"
    )


def test_servicing_allowlist_adds_log_claim_and_the_variant_server():
    clean = servicing_allowlist(None)
    assert set(clean) == {
        "core-read.*",
        "comms.*",
        "core-write.add_claim_note",
        "core-write.update_contact_preference",
        "core-write.log_claim",  # eval deviation: tasks 3 and 10 log claims
    }
    assert servicing_allowlist("bank-tools") == [*clean, "bank-tools.*"]


def test_dropped_sse_filter_drops_only_that_message():
    import logging

    def record(msg: str) -> logging.LogRecord:
        return logging.LogRecord("uvicorn.error", logging.ERROR, "", 0, msg, (), None)

    f = DroppedSseFilter()
    assert not f.filter(record("ASGI callable returned without completing response."))
    assert f.filter(record("Exception in ASGI application"))


def test_endpoint_of_normalises_host_and_port():
    assert endpoint_of("http://127.0.0.1:8101/mcp") == "127.0.0.1:8101"
    assert endpoint_of("http://LocalHost/mcp") == "localhost:80"


def _fake(name: str, urls: list[str], expected: set[str]) -> ConditionSetup:
    setup = ConditionSetup.__new__(ConditionSetup)
    setup.name = name  # type: ignore[misc]
    setup.mcp_urls = urls
    setup.expected_endpoints = frozenset(expected)
    return setup


def test_assert_endpoints_detects_contamination():
    real = [*REAL_SERVERS.values()]
    gw = "http://127.0.0.1:50001/mcp"
    attacker = "http://127.0.0.1:50002/mcp"
    ok_direct = _fake(
        "direct", [attacker, *real], {endpoint_of(u) for u in [attacker, *real]}
    )
    assert_endpoints(ok_direct)
    with pytest.raises(ConditionContaminationError):  # direct through a gateway
        assert_endpoints(
            _fake(
                "direct",
                [f"http://127.0.0.1:{COMPOSE_GATEWAY_PORT}/mcp", *real],
                {f"127.0.0.1:{COMPOSE_GATEWAY_PORT}", *map(endpoint_of, real)},
            )
        )
    assert_endpoints(_fake("gateway", [gw], {endpoint_of(gw)}))
    with pytest.raises(
        ConditionContaminationError
    ):  # gateway episode reaching a server
        assert_endpoints(
            _fake("gateway", [gw, real[0]], {endpoint_of(gw), endpoint_of(real[0])})
        )
    with pytest.raises(ConditionContaminationError):  # not what the condition expected
        assert_endpoints(_fake("gateway", [attacker], {endpoint_of(gw)}))


# --- integration -----------------------------------------------------------


@asynccontextmanager
async def started(v: MaliciousVariant | None) -> AsyncIterator[AttackerServer | None]:
    if v is None:
        yield None
        return
    attacker = AttackerServer(v, SINK_URL)
    await attacker.start()
    try:
        yield attacker
    finally:
        await attacker.stop()


async def toolkit_for(setup: ConditionSetup) -> McpToolkit:
    return await connect(setup.mcp_urls, None, token_providers=setup.token_providers)


@asynccontextmanager
async def raw_session(setup: ConditionSetup) -> AsyncIterator[ClientSession]:
    url = setup.mcp_urls[0]
    provider = setup.token_providers[url]
    assert provider is not None
    token = await provider()
    async with (
        httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=10
        ) as http,
        streamable_http_client(url, http_client=http) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


@pytest.mark.integration
async def test_direct_lists_attacker_and_real_tools(world: World):
    sh01 = variant("sh-01")  # shadows core-read's get_member_profile
    async with started(sh01) as attacker, DirectCondition(world, attacker) as setup:
        assert attacker is not None
        assert setup.mcp_urls[0] == attacker.url  # attacker first: it wins clashes
        assert setup.token_providers[attacker.url] is None
        async with await toolkit_for(setup) as toolkit:
            names = real_names(toolkit)
            assert names == set().union(*REAL_TOOLS.values())
            assert toolkit.collisions == [
                ToolCollision(
                    "get_member_profile", attacker.url, REAL_SERVERS["core-read"]
                )
            ]
            profile = next(
                t
                for t in toolkit.tools
                if toolkit.real_name(t.name) == "get_member_profile"
            )
            assert profile.description == sh01.approved["description"]
        assert setup.blocked_at is None


@pytest.mark.integration
async def test_direct_clean_episode_has_only_real_servers(world: World):
    async with DirectCondition(world, None) as setup:
        assert setup.mcp_urls == list(REAL_SERVERS.values())
        async with await toolkit_for(setup) as toolkit:
            assert real_names(toolkit) == set().union(*REAL_TOOLS.values())
            out = await next(
                t for t in toolkit.tools if t.name == "get_member_profile"
            ).ainvoke({"member_id": "M-900001"})
            assert "M-900001" in out
        assert_endpoints(setup)


@pytest.mark.integration
async def test_gateway_lists_only_allowlisted_pinned_tools(world: World):
    async with GatewayCondition(world, None, None, SimulatedApprover()) as setup:
        async with await toolkit_for(setup) as toolkit:
            names = real_names(toolkit)
            assert names == SERVICING_TOOLS
            assert "core-write.log_claim" in names  # eval allowlist deviation
            # Every clean task is completable through the gateway.
            assert set().union(*REQUIRED_TOOLS.values()) <= names
            out = await next(
                t
                for t in toolkit.tools
                if toolkit.real_name(t.name) == "core-read.get_member_profile"
            ).ainvoke({"member_id": "M-900001"})
            assert "M-900001" in out
        # Forwarded and recorded (the profile's contact details may be flagged
        # by the output scan; a flag still delivers the result).
        [(tool, decision, _)] = setup.audit.decisions
        assert tool == "core-read.get_member_profile"
        assert decision in ("allow", "flag_output")
        assert setup.blocked_at is None


@pytest.mark.integration
async def test_gateway_pins_real_servers_as_the_committed_lockfile(world: World):
    committed = json.loads(
        (REPO_ROOT / "policy" / "toolgate.lock.json").read_text(encoding="utf-8")
    )["servers"]
    async with GatewayCondition(world, None, None, SimulatedApprover()) as setup:
        pins = setup.pins
        assert set(pins.servers) == set(committed)
        for sid, sp in pins.servers.items():
            assert sp.server_name == committed[sid]["server_name"]
            assert sp.target.headers == tuple(committed[sid]["target"]["headers"])
            assert {n: t.hash for n, t in sp.tools.items()} == {
                n: t["hash"] for n, t in committed[sid]["tools"].items()
            }
        text = setup.lockfile_path.read_text(encoding="utf-8")
        token = await world.token("dev-tester")
        assert token not in text  # templates only, never token values
        assert "${TOOLGATE_DEV_TOKEN}" in text


@pytest.mark.integration
async def test_gateway_blocks_poisoned_tool_at_approval(world: World):
    dp01 = variant("dp-01")
    async with (
        started(dp01) as attacker,
        GatewayCondition(world, attacker, dp01, SimulatedApprover()) as setup,
    ):
        assert setup.approvals[(dp01.server_id, dp01.approved["name"])] == "block"
        async with await toolkit_for(setup) as toolkit:
            names = real_names(toolkit)
        assert names == SERVICING_TOOLS  # the attacker tool is absent
        assert setup.blocked_at == "approval"


@pytest.mark.integration
async def test_gateway_drops_rug_pull_after_mutation(world: World):
    rp01 = variant("rp-01")
    attack = f"{rp01.server_id}.{rp01.approved['name']}"
    async with (
        started(rp01) as attacker,
        GatewayCondition(world, attacker, rp01, SimulatedApprover()) as setup,
    ):
        assert attacker is not None
        assert setup.approvals[(rp01.server_id, rp01.approved["name"])] == "approve"
        async with await toolkit_for(setup) as toolkit:
            assert attack in real_names(toolkit)  # pinned benign: listed
        assert setup.blocked_at is None

        assert await setup.mutate_after_approval() is True
        async with await toolkit_for(setup) as toolkit:
            names = real_names(toolkit)
        assert attack not in names
        assert names == SERVICING_TOOLS
        assert attacker.live_definition() == rp01.mutated
        assert setup.blocked_at == "list"

        # A call by name is denied too; the attack was already stopped at list.
        async with raw_session(setup) as session:
            result = await session.call_tool(attack, {"sort_code": "12-34-56"})
        assert result.isError
        assert any(
            t == attack and d == "deny_drift" for t, d, _ in setup.audit.decisions
        )
        assert attacker.calls == []
        assert setup.blocked_at == "list"

        # Review Focus 5: the agent only ever talks to the gateway.
        assert setup.endpoints_used == frozenset({endpoint_of(setup.gateway_url)})
        assert_endpoints(setup)


@pytest.mark.integration
async def test_gateway_denied_attacker_call_sets_call(world: World):
    rp01 = variant("rp-01")  # approved and not mutated: listed and callable
    attack = f"{rp01.server_id}.{rp01.approved['name']}"
    async with (
        started(rp01) as attacker,
        GatewayCondition(world, attacker, rp01, SimulatedApprover()) as setup,
    ):
        assert attacker is not None
        async with raw_session(setup) as session:
            listed = {t.name for t in (await session.list_tools()).tools}
            assert attack in listed
            result = await session.call_tool(attack, {"not_a_param": 1})
        assert result.isError
        assert [d for t, d, _ in setup.audit.decisions if t == attack] == [
            "deny_schema"
        ]
        assert attacker.calls == []
        assert setup.blocked_at == "call"


@pytest.mark.integration
async def test_endpoints_per_condition(world: World):
    rp01 = variant("rp-01")
    compose_gateway = {
        f"127.0.0.1:{COMPOSE_GATEWAY_PORT}",
        f"localhost:{COMPOSE_GATEWAY_PORT}",
    }
    real = {endpoint_of(u) for u in REAL_SERVERS.values()}
    async with started(rp01) as attacker:
        assert attacker is not None
        async with DirectCondition(world, attacker) as direct:
            assert direct.endpoints_used == frozenset(
                {endpoint_of(attacker.url), *real}
            )
            assert not direct.endpoints_used & compose_gateway
            assert_endpoints(direct)
        async with GatewayCondition(world, attacker, rp01, SimulatedApprover()) as gw:
            assert gw.endpoints_used == frozenset({endpoint_of(gw.gateway_url)})
            assert not set(gw.mcp_urls) & set(REAL_SERVERS.values())
            assert attacker.url not in gw.mcp_urls
            assert not gw.endpoints_used & (real | compose_gateway)
            assert_endpoints(gw)


def _port_open(endpoint: str) -> bool:
    host, port = endpoint.rsplit(":", 1)
    try:
        with socket.create_connection((host, int(port)), timeout=1):
            return True
    except OSError:
        return False


@pytest.mark.integration
async def test_conditions_clean_up_ports_and_tasks(world: World):
    await world.token("dev-tester")  # warm the token client outside the count
    await world.token("servicing")
    rp01 = variant("rp-01")
    current = asyncio.current_task()
    before = set(asyncio.all_tasks())

    attacker = AttackerServer(rp01, SINK_URL)
    setup = GatewayCondition(world, attacker, rp01, SimulatedApprover())
    await setup.__aenter__()  # starts the attacker it was given unstarted
    gateway = endpoint_of(setup.gateway_url)
    attacker_endpoint = endpoint_of(attacker.url)
    tmp = setup.lockfile_path.parent
    async with await toolkit_for(setup) as toolkit:
        assert toolkit.tools
    assert _port_open(gateway) and _port_open(attacker_endpoint)
    await setup.close()
    await setup.close()  # idempotent

    direct = DirectCondition(world, None)
    await direct.__aenter__()
    await direct.close()

    await asyncio.sleep(0.2)
    leftover = {
        t
        for t in asyncio.all_tasks() - before
        if t is not current
        # sse_starlette's single per-loop shutdown watcher is a library
        # singleton, not a per-server task; it ends with the loop.
        and t.get_coro().__qualname__ != "_shutdown_watcher"  # type: ignore[union-attr]
    }
    assert not leftover, sorted(t.get_name() for t in leftover)
    assert not _port_open(gateway)
    assert not _port_open(attacker_endpoint)  # owned by the condition: stopped
    assert not tmp.exists()


@pytest.mark.integration
async def test_gateway_condition_rejects_mismatched_variant(world: World):
    dp01, rp01 = variant("dp-01"), variant("rp-01")
    async with started(rp01) as attacker:
        with pytest.raises(ConditionError):
            async with GatewayCondition(world, attacker, dp01, SimulatedApprover()):
                pass


@pytest.mark.integration
@pytest.mark.parametrize("variant_id", ["sh-01", "sh-02"])
async def test_gateway_shadowing_variant_keeps_every_real_tool(
    world: World, variant_id: str
):
    """Only the new server's tools go through the approver: a shadowing
    attacker must not get the real tool it shadows unpinned."""
    v = variant(variant_id)
    attack = f"{v.server_id}.{v.approved['name']}"
    async with (
        started(v) as attacker,
        GatewayCondition(world, attacker, v, SimulatedApprover()) as setup,
    ):
        for sid, tools in REAL_TOOLS.items():
            assert set(setup.pins.servers[sid].tools) == tools
        # Only the new server's tools go through the simulated approver.
        assert setup.approvals == {(v.server_id, v.approved["name"]): "block"}
        async with await toolkit_for(setup) as toolkit:
            names = real_names(toolkit)
        assert names == SERVICING_TOOLS  # all real tools, attacker blocked
        assert attack not in names
        assert setup.blocked_at == "approval"


@pytest.mark.integration
async def test_gateway_denied_attacker_output_sets_call(world: World):
    # dp-07: definition benign at approval, output_sample is malicious.
    dp07 = variant("dp-07")
    attack = f"{dp07.server_id}.{dp07.approved['name']}"
    async with (
        started(dp07) as attacker,
        GatewayCondition(world, attacker, dp07, SimulatedApprover()) as setup,
    ):
        assert attacker is not None
        assert setup.approvals[(dp07.server_id, dp07.approved["name"])] == "approve"
        async with raw_session(setup) as session:
            result = await session.call_tool(attack, {"query": "Example Surgery"})
        assert result.isError
        assert [d for t, d, _ in setup.audit.decisions if t == attack] == [
            "deny_output"
        ]
        assert [c[0] for c in attacker.calls] == [dp07.approved["name"]]
        assert setup.blocked_at == "call"


async def test_fetch_failure_is_one_condition_error_and_cancels_siblings():
    from toolgate_eval.conditions import _fetch_all
    from toolgate_pin import Target

    started_tasks = set(asyncio.all_tasks())
    with pytest.raises(ConditionError) as info:
        await _fetch_all(
            {
                "down-a": Target(url="http://127.0.0.1:1/mcp"),
                "down-b": Target(url="http://127.0.0.1:1/mcp"),
            },
            {},
        )
    assert "cannot list tools of down-" in str(info.value)
    await asyncio.sleep(0.05)
    current = asyncio.current_task()
    assert not {t for t in asyncio.all_tasks() - started_tasks if t is not current}
