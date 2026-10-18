import os

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

import asyncio
from unittest.mock import patch
from urllib.parse import quote, urlsplit

import asyncpg
import pytest
import pytest_asyncio
from testcontainers.community.postgres import PostgresContainer
from toolgate_gateway.audit import AuditRecord, AuditWriter, args_hmac
from toolgate_gateway.db import create_pool, migrate
from toolgate_gateway.reviews import PendingReviews
from toolgate_pin.models import PinSet, ServerPin, Target, ToolPin

APP_PASSWORD = "app'pw\"with;quotes$$"


def _admin_dsn(pg: PostgresContainer) -> str:
    return pg.get_connection_url(driver=None)


def _app_dsn(admin_dsn: str) -> str:
    u = urlsplit(admin_dsn)
    return (
        f"postgresql://toolgate_gateway_app:{quote(APP_PASSWORD, safe='')}"
        f"@{u.hostname}:{u.port}{u.path}"
    )


@pytest.fixture(scope="session")
def pg_container():
    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg


@pytest.fixture(scope="session")
def admin_dsn(pg_container):
    return _admin_dsn(pg_container)


@pytest_asyncio.fixture
async def app_pool(admin_dsn):
    """Fresh schema per test; pool connects as the restricted app role."""
    conn = await asyncpg.connect(admin_dsn)
    await conn.execute("DROP SCHEMA IF EXISTS gateway CASCADE")
    await conn.close()
    await migrate(admin_dsn, APP_PASSWORD)
    pool = await create_pool(_app_dsn(admin_dsn))
    yield pool
    await pool.close()


def _rec(i: int = 0, decision: str = "allow") -> AuditRecord:
    return AuditRecord(
        agent_id="a",
        client_id="servicing",
        tool=f"core-read.t{i}",
        tool_hash="h",
        args_hmac="x" * 64,
        decision=decision,
        reason=None,
        latency_ms=1.5,
        trace_id="t",
    )


async def test_writer_batches_and_flushes(app_pool, admin_dsn):
    writer = AuditWriter(app_pool, flush_interval_s=0.05, batch_size=50)
    calls = 0
    real = type(app_pool).executemany

    async def spy(self, *a, **kw):
        nonlocal calls
        calls += 1
        return await real(self, *a, **kw)

    with patch.object(type(app_pool), "executemany", spy):
        await writer.start()
        assert all(writer.submit(_rec(i)) for i in range(120))
        await writer.stop()
    assert 1 <= calls <= 3
    admin = await asyncpg.connect(admin_dsn)
    try:
        assert await admin.fetchval("SELECT count(*) FROM gateway.audit_log") == 120
    finally:
        await admin.close()
    assert writer.dropped_count == 0 and writer.healthy


async def test_app_role_cannot_update_or_delete(app_pool):
    await app_pool.execute(
        "INSERT INTO gateway.audit_log (agent_id, client_id, tool, args_hmac, decision)"
        " VALUES ('a','c','t','h','allow')"
    )
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_pool.execute("UPDATE gateway.audit_log SET reason = 'x'")
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await app_pool.execute("DELETE FROM gateway.audit_log")


async def test_decision_check_constraint(app_pool):
    with pytest.raises(asyncpg.CheckViolationError):
        await app_pool.execute(
            "INSERT INTO gateway.audit_log (agent_id, client_id, tool, args_hmac,"
            " decision) VALUES ('a','c','t','h','maybe')"
        )


async def test_queue_full_returns_false():
    writer = AuditWriter(None, max_queue=2)  # type: ignore[arg-type]
    assert writer.accepting
    assert writer.submit(_rec(1))
    assert writer.submit(_rec(2))
    assert not writer.accepting
    assert writer.submit(_rec(3)) is False


async def test_accepting_false_when_stopped():
    w = AuditWriter(FakePool())
    await w.start()
    assert w.accepting
    await w.stop()
    assert not w.accepting


async def test_db_down_marks_unhealthy():
    """Own container so stopping it cannot affect other tests."""
    with PostgresContainer("postgres:16-alpine") as pg:
        admin = _admin_dsn(pg)
        await migrate(admin, APP_PASSWORD)
        pool = await create_pool(_app_dsn(admin))
        writer = AuditWriter(pool, flush_interval_s=0.05)
        await writer.start()
        assert writer.submit(_rec(1))
        await asyncio.sleep(0.3)
        assert writer.healthy
        pg.get_wrapped_container().stop()
        assert writer.submit(_rec(2))  # accepted until a flush fails
        for _ in range(100):
            if not writer.healthy:
                break
            await asyncio.sleep(0.1)
        assert writer.healthy is False
        assert writer.submit(_rec(3)) is False
        # Unhealthy after the first failed attempt; the batch is counted as
        # dropped only after the retry also fails.
        for _ in range(100):
            if writer.dropped_count >= 1:
                break
            await asyncio.sleep(0.1)
        assert writer.dropped_count >= 1
        pool.terminate()
        await writer.stop()


class FakePool:
    """executemany fails while `down`, hangs while `hang`; records written rows."""

    def __init__(self):
        self.down = False
        self.hang = False
        self.rows = []

    async def executemany(self, sql, rows, timeout=None):
        if self.hang:
            await asyncio.sleep(3600)
        if self.down:
            raise ConnectionError("down")
        self.rows.extend(rows)

    async def fetchval(self, sql, timeout=None):
        if self.down or self.hang:
            raise ConnectionError("down")
        return 1


async def _until(cond, secs=5.0):
    for _ in range(int(secs / 0.01)):
        if cond():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("condition not met")


async def test_writer_recovers_after_transient_failure():
    pool = FakePool()
    w = AuditWriter(pool, flush_interval_s=0.01, probe_min_s=0.05, probe_max_s=0.1)
    await w.start()
    pool.down = True
    assert w.submit(_rec(1))
    await _until(lambda: not w.healthy)
    assert w.submit(_rec(2)) is False
    pool.down = False
    await _until(lambda: w.healthy)
    assert w.submit(_rec(3)) is True
    await w.stop()
    assert any(r[2] == "core-read.t3" for r in pool.rows)


async def test_queued_rows_survive_outage():
    pool = FakePool()
    w = AuditWriter(
        pool, flush_interval_s=0.01, batch_size=2, probe_min_s=0.05, probe_max_s=0.1
    )
    pool.down = True
    for i in range(6):
        assert w.submit(_rec(i))
    await w.start()
    await _until(lambda: not w.healthy)
    # First batch (2 rows) is dropped after its one retry; the rest stay queued.
    assert w.dropped_count == 2
    pool.down = False
    await _until(lambda: w.healthy)
    await w.stop()
    assert len(pool.rows) == 4
    assert w.dropped_count == 2


async def test_hung_db_marks_unhealthy_and_stop_returns():
    pool = FakePool()
    pool.hang = True
    w = AuditWriter(pool, flush_interval_s=0.01, op_timeout_s=0.1, probe_min_s=0.05)
    await w.start()
    assert w.submit(_rec(1))
    await _until(lambda: not w.healthy, secs=3)
    await asyncio.wait_for(w.stop(), 5)
    assert w.submit(_rec(2)) is False


async def test_submit_after_stop_returns_false():
    w = AuditWriter(FakePool())
    await w.start()
    await w.stop()
    assert w.submit(_rec(1)) is False


async def test_migrate_rejects_empty_password(admin_dsn):
    with pytest.raises(ValueError):
        await migrate(admin_dsn, "")


def test_args_hmac_stable_and_keyed():
    assert (
        args_hmac("k", {"b": 1, "a": 2})
        == args_hmac("k", {"a": 2, "b": 1})
        != args_hmac("k2", {"a": 2, "b": 1})
    )
    assert args_hmac("k", None) == args_hmac("k", {})


def test_args_hmac_never_raises_on_huge_int():
    assert len(args_hmac("k", {"x": 2**80})) == 64
    assert len(args_hmac("k", {"x": float("nan")})) == 64
    assert len(args_hmac("k", {"x": object()})) == 64


def _pins(server: str, tool: str, h: str) -> PinSet:
    tp = ToolPin(
        name=tool, hash=h, definition={}, approved_by="u", approved_at="t", scan={}
    )
    sp = ServerPin(
        server_id=server, server_name=server, target=Target(url="u"), tools={tool: tp}
    )
    return PinSet(servers={server: sp})


async def test_pending_reviews_upsert_and_resolve(app_pool):
    rv = PendingReviews(app_pool)
    await rv.record("s", "t", "h2", "h1", "drift", "diff", [{"rule": "r"}])
    await rv.record("s", "t", "h2", "h1", "drift", "diff", [{"rule": "r"}])
    await rv.record("s", "new", None, None, "unpinned", None, [])
    await rv.record("s", "new", None, None, "unpinned", None, [])
    rows = await rv.list_open()
    assert len(rows) == 2
    drift = next(r for r in rows if r["tool_name"] == "t")
    assert drift["findings"] == [{"rule": "r"}]
    assert drift["last_seen"] >= drift["first_seen"]
    # Observed hash not pinned yet: nothing resolves.
    assert await rv.resolve_pinned(_pins("s", "t", "h1")) == 0
    assert await rv.resolve_pinned(_pins("s", "t", "h2")) == 1
    assert [r["tool_name"] for r in await rv.list_open()] == ["new"]


async def test_migrate_idempotent(admin_dsn):
    await migrate(admin_dsn, APP_PASSWORD)
    await migrate(admin_dsn, APP_PASSWORD)
