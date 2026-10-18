import logging
import os
from contextlib import asynccontextmanager

import anyio
import pytest
from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_client_server_memory_streams
from toolgate_gateway.core import GatewayCore
from toolgate_gateway.downstreams import DownstreamConfig
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist
from toolgate_gateway.pool import DownstreamPool
from toolgate_pin import InventoryTool, LockfileStore, PinSet, Target
from toolgate_pin.demo_server import build_demo_server
from toolgate_pin.pinning import pin_server

CONFIGS = [
    DownstreamConfig("core-read", "http://core-read.test/mcp"),
    DownstreamConfig("core-write", "http://core-write.test/mcp"),
]

ALLOWLIST = Allowlist(
    {
        "servicing": ("core-read.*",),
        "claims-intake": ("core-read.get_claim_status", "core-write.log_claim"),
    }
)


def build_core_write() -> FastMCP:
    server = FastMCP("core-write")

    @server.tool(name="log_claim", description="Log a new claim.")
    def log_claim(member_id: str, amount: float) -> dict:
        return {"member_id": member_id, "amount": amount, "logged": True}

    return server


BUILDERS = {
    "core-read": build_demo_server,
    "core-write": build_core_write,
}


class MemoryFactory:
    """In-memory SessionFactory serving ``builders[server_id]()``; server ids
    in ``down`` always fail to connect."""

    def __init__(self, builders=None, *, down=()):
        self.builders = dict(builders or BUILDERS)
        self.down = set(down)

    @asynccontextmanager
    async def __call__(self, config, *, message_handler=None):
        if config.server_id in self.down:
            raise ConnectionError(f"{config.server_id} is down")
        lowlevel = self.builders[config.server_id]()._mcp_server
        async with (
            create_client_server_memory_streams() as (client, srv),
            anyio.create_task_group() as tg,
        ):
            tg.start_soon(
                lambda: lowlevel.run(
                    srv[0], srv[1], lowlevel.create_initialization_options()
                )
            )
            try:
                async with ClientSession(
                    client[0], client[1], message_handler=message_handler
                ) as session:
                    yield session, await session.initialize()
            finally:
                tg.cancel_scope.cancel()


class FakeReviews:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.records: list[dict] = []
        self.resolved_with: list[PinSet] = []

    async def record(
        self, server_id, tool_name, observed_hash, pinned_hash, reason, diff, findings
    ):
        if self.fail:
            raise RuntimeError("db down")
        self.records.append(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "observed_hash": observed_hash,
                "pinned_hash": pinned_hash,
                "reason": reason,
                "diff": diff,
                "findings": findings,
            }
        )

    async def resolve_pinned(self, pins):
        if self.fail:
            raise RuntimeError("db down")
        self.resolved_with.append(pins)
        return 0


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def live_tools(builders: dict) -> dict:
    """``{server_id: (server_name, tools)}`` as seen through a real session."""
    pool = DownstreamPool(CONFIGS, MemoryFactory(builders))
    try:
        out = {}
        for c in CONFIGS:
            info, tools = await pool.list_tools(c.server_id)
            out[c.server_id] = (info.name, tools)
        return out
    finally:
        await pool.close()


async def write_lockfile(path, builders=None, *, skip=(), server_names=None):
    """Pin every tool served by ``builders`` except ``skip`` (server.tool)."""
    pins = PinSet({})
    for sid, (name, tools) in (await live_tools(builders or BUILDERS)).items():
        kept = [t for t in tools if f"{sid}.{t.name}" not in skip]
        name = (server_names or {}).get(sid, name)
        sp = pin_server(
            sid, name, Target(url=f"http://{sid}.test/mcp"), kept, approved_by="test"
        )
        pins = pins.with_server(sp)
    LockfileStore(path).save(pins)
    if path.exists():  # force a visible (mtime, size) change on rewrite
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))


@pytest.fixture
async def make_core(tmp_path):
    pools = []

    async def make(*, builders=None, down=(), reviews=None, clock=None):
        lock = tmp_path / "toolgate.lock.json"
        if not lock.exists():
            await write_lockfile(lock)
        pool = DownstreamPool(CONFIGS, MemoryFactory(builders, down=down))
        pools.append(pool)
        await pool.start()
        pins = PinSource(lock, clock=clock) if clock else PinSource(lock)
        reviews = reviews if reviews is not None else FakeReviews()
        core = GatewayCore(pool, pins, ALLOWLIST, object(), reviews, hmac_key="k" * 32)
        return core, reviews, lock

    yield make
    for p in pools:
        await p.close()


def names(tools) -> set[str]:
    return {t.name for t in tools}


READ_ALL = {
    "core-read.get_claim_status",
    "core-read.get_member_profile",
    "core-read.check_coverage",
    "core-read.send_member_message",
}


async def test_list_filters_by_allowlist(make_core):
    core, reviews, _ = await make_core()
    assert names(await core.list_tools("servicing")) == READ_ALL
    assert names(await core.list_tools("claims-intake")) == {
        "core-read.get_claim_status",
        "core-write.log_claim",
    }
    assert await core.list_tools("unknown-agent") == []
    assert reviews.records == []
    assert len(reviews.resolved_with) == 3


async def test_namespaced_copy_keeps_definition_verbatim(make_core):
    core, _, _ = await make_core()
    (tool,) = [
        t
        for t in await core.list_tools("claims-intake")
        if t.name == "core-write.log_claim"
    ]
    entry = core.snapshot["core-write.log_claim"]
    assert entry.tool.name == "log_claim"
    assert entry.server_id == "core-write"
    assert tool.model_dump(exclude={"name"}) == entry.tool.model_dump(exclude={"name"})
    assert core.inventory["core-write"] == [InventoryTool("core-write", "log_claim")]


async def test_snapshot_validator_enforces_no_additional_properties(make_core):
    core, _, _ = await make_core()
    await core.refresh_snapshot()
    v = core.snapshot["core-write.log_claim"].input_validator
    assert v.is_valid({"member_id": "m1", "amount": 1.0})
    assert not v.is_valid({"member_id": "m1", "amount": 1.0, "extra": 1})
    assert not v.is_valid({"member_id": "m1", "amount": "lots"})
    # Compiled once per hash: a rebuild reuses the same validator.
    await core.refresh_snapshot()
    assert core.snapshot["core-write.log_claim"].input_validator is v


async def test_drift_tool_dropped_and_review_recorded(make_core, caplog):
    mutated = dict(BUILDERS, **{"core-read": lambda: build_demo_server(mutated=True)})
    core, reviews, _ = await make_core(builders=mutated)
    with caplog.at_level(logging.WARNING, logger="toolgate_gateway.alert"):
        listed = names(await core.list_tools("servicing"))
    assert listed == READ_ALL - {"core-read.get_claim_status"}
    (rec,) = reviews.records
    assert rec["server_id"] == "core-read"
    assert rec["tool_name"] == "get_claim_status"
    assert rec["reason"] == "drift"
    assert rec["diff"] and rec["observed_hash"] != rec["pinned_hash"]
    assert rec["pinned_hash"] is not None
    assert all(isinstance(f, dict) and "rule_id" in f for f in rec["findings"])
    assert rec["findings"], "the hidden-instruction drift should raise findings"
    (alert,) = [r for r in caplog.records if r.name == "toolgate_gateway.alert"]
    assert alert.toolgate_reason == "drift"
    assert alert.toolgate_server_id == "core-read"
    assert "exfil" not in alert.getMessage()  # definitions are never logged


async def test_unpinned_tool_dropped(make_core, tmp_path):
    await write_lockfile(
        tmp_path / "toolgate.lock.json", skip={"core-read.check_coverage"}
    )
    core, reviews, _ = await make_core()
    assert names(await core.list_tools("servicing")) == READ_ALL - {
        "core-read.check_coverage"
    }
    (rec,) = reviews.records
    assert (rec["tool_name"], rec["reason"], rec["pinned_hash"]) == (
        "check_coverage",
        "unpinned",
        None,
    )


async def test_server_drift_drops_all_tools_of_that_server(make_core, tmp_path):
    await write_lockfile(
        tmp_path / "toolgate.lock.json", server_names={"core-read": "someone-else"}
    )
    core, reviews, _ = await make_core()
    assert await core.list_tools("servicing") == []
    assert names(await core.list_tools("claims-intake")) == {"core-write.log_claim"}
    assert {r["reason"] for r in reviews.records} == {"server_drift"}
    assert {r["tool_name"] for r in reviews.records} >= {"get_claim_status"}


async def test_removed_tool_is_not_recorded(make_core, tmp_path):
    def smaller():
        s = build_core_write()
        s.remove_tool("log_claim")
        return s

    core, reviews, _ = await make_core(
        builders=dict(BUILDERS, **{"core-write": smaller})
    )
    assert names(await core.list_tools("claims-intake")) == {
        "core-read.get_claim_status"
    }
    assert reviews.records == []


async def test_lockfile_edit_picked_up(make_core, tmp_path):
    lock = tmp_path / "toolgate.lock.json"
    await write_lockfile(lock, skip={"core-read.check_coverage"})
    core, reviews, _ = await make_core()
    assert "core-read.check_coverage" not in names(await core.list_tools("servicing"))

    await write_lockfile(lock)  # approve: rewrite with the new pin
    assert names(await core.list_tools("servicing")) == READ_ALL
    newest = reviews.resolved_with[-1]
    assert "check_coverage" in newest.get("core-read").tools


async def test_corrupt_lockfile_keeps_last_good_then_goes_empty(make_core):
    clock = FakeClock()
    core, _, lock = await make_core(clock=clock)
    assert names(await core.list_tools("servicing")) == READ_ALL

    lock.write_text("{corrupt", encoding="utf-8")
    clock.now += 5
    assert names(await core.list_tools("servicing")) == READ_ALL
    clock.now += 301
    assert await core.list_tools("servicing") == []
    assert core.snapshot == {}


async def test_down_downstream_omitted_others_listed(make_core):
    core, reviews, _ = await make_core(down={"core-write"})
    assert names(await core.list_tools("claims-intake")) == {
        "core-read.get_claim_status"
    }
    assert "core-write" not in core.inventory
    assert reviews.records == []  # a down server is not drift


async def test_reviews_failure_does_not_fail_list(make_core, caplog):
    mutated = dict(BUILDERS, **{"core-read": lambda: build_demo_server(mutated=True)})
    core, _, _ = await make_core(builders=mutated, reviews=FakeReviews(fail=True))
    with caplog.at_level(logging.WARNING):
        listed = names(await core.list_tools("servicing"))
    assert listed == READ_ALL - {"core-read.get_claim_status"}
    assert any("review" in r.getMessage() for r in caplog.records)


async def test_no_reviews_configured(make_core, tmp_path):
    lock = tmp_path / "toolgate.lock.json"
    await write_lockfile(lock)
    pool = DownstreamPool(CONFIGS, MemoryFactory())
    await pool.start()
    try:
        core = GatewayCore(
            pool, PinSource(lock), ALLOWLIST, object(), None, hmac_key="k" * 32
        )
        assert names(await core.list_tools("servicing")) == READ_ALL
    finally:
        await pool.close()
