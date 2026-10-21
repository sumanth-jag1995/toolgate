"""Load test maths and scheduling (no network) plus one live smoke run.

The ship-gate target (p95 overhead < 30 ms) is machine-dependent and is
deliberately not asserted here.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from toolgate_eval import cli, loadtest
from toolgate_eval.loadtest import (
    LatencyStats,
    LoadResult,
    block_sizes,
    make_result,
    make_stats,
    measure,
    percentile,
)
from toolgate_eval.world import WorldSettings


def test_percentiles_correct():
    samples = [float(i) for i in range(1, 101)]  # 1..100
    assert percentile(samples, 50) == pytest.approx(50.5)
    assert percentile(samples, 95) == pytest.approx(95.05)
    assert percentile(samples, 99) == pytest.approx(99.01)
    assert percentile([7.0], 95) == 7.0
    assert percentile([], 95) == 0.0
    assert percentile([3.0, 1.0, 2.0], 50) == 2.0  # order independent
    stats = make_stats(samples, errors=2)
    assert (stats.n, stats.max_ms, stats.errors) == (100, 100.0, 2)
    assert stats.p95_ms == pytest.approx(95.05)


def test_overhead_math():
    direct = make_stats([10.0] * 50 + [20.0] * 50)  # p50 15.0, p95 20.0
    gateway = make_stats([14.0] * 50 + [31.0] * 50)  # p50 22.5, p95 31.0
    result = make_result(direct, gateway, {})
    assert result.overhead_p50_ms == pytest.approx(7.5)
    assert result.overhead_p95_ms == pytest.approx(11.0)


def _stats(p95: float, *, n: int = 100, errors: int = 0, rps: float = 50.0):
    return LatencyStats(n, p95, p95, p95, p95, errors, rps)


def test_verdict_clean_small_overhead_is_yes():
    assert make_result(_stats(20.0), _stats(35.0), {}).verdict == "yes"


def test_verdict_clean_big_overhead_is_no():
    assert make_result(_stats(20.0), _stats(80.0), {}).verdict == "no"


def test_verdict_all_erroring_side_is_inconclusive():
    dead = _stats(0.0, n=0, errors=100)
    assert make_result(_stats(20.0), dead, {}).verdict == "inconclusive"
    assert make_result(dead, _stats(20.0), {}).verdict == "inconclusive"
    some = _stats(35.0, errors=1)  # any error at all
    assert make_result(_stats(20.0), some, {}).verdict == "inconclusive"


def test_verdict_negative_overhead_is_inconclusive():
    assert make_result(_stats(80.0), _stats(20.0), {}).verdict == "inconclusive"


def test_verdict_ignores_throughput_at_any_concurrency():
    # No "saturated => inconclusive" rule: a slow gateway is judged on its p95.
    slow_small = _stats(35.0, rps=30.0)  # 0.6x the direct throughput, +15 ms
    slow_big = _stats(400.0, rps=10.0)  # +380 ms
    for c in (1, 5, 50):
        assert make_result(_stats(20.0), slow_small, {}, concurrency=c).verdict == "yes"
        assert make_result(_stats(20.0), slow_big, {}, concurrency=c).verdict == "no"
    assert not hasattr(make_result(_stats(20.0), slow_big, {}), "saturated")


def test_contention_note_only_above_one_worker():
    stats = LatencyStats(n=5, p50_ms=1.0, p95_ms=2.0, p99_ms=3.0, max_ms=4.0, errors=0)
    note = "host contention included"
    one = LoadResult(stats, stats, 0.0, 0.0, {}, concurrency=1)
    many = LoadResult(stats, stats, 0.0, 0.0, {}, concurrency=50)
    p1 = {"total": 5, "concurrency": 1, "warmup": 1}
    p50 = {"total": 5, "concurrency": 50, "warmup": 1}
    assert note not in loadtest.format_md(one, **p1)
    md = loadtest.format_md(many, **p50)
    assert (
        "host contention included (gateway, servers, Keycloak and Postgres share "
        "one host)" in md
    )
    assert json.loads(loadtest.format_json(many, **p50))["contention_note"].startswith(
        note
    )
    assert json.loads(loadtest.format_json(one, **p1))["contention_note"] is None


async def test_measure_records_concurrency():
    async def ok() -> None:
        await asyncio.sleep(0)

    result = await measure([ok] * 3, [ok] * 3, total=6, warmup=0, block=6)
    assert result.concurrency == 3


async def test_all_failing_warmup_fails_fast():
    async def ok() -> None:
        await asyncio.sleep(0)

    async def dead() -> None:
        raise ConnectionError("down")

    with pytest.raises(loadtest.LoadTestError, match="warm-up"):
        await measure([ok], [dead], total=5, warmup=3)


async def test_exception_group_from_session_setup_is_a_clean_error(monkeypatch):
    async def boom(*a, **k):
        raise ExceptionGroup("tg", [ConnectionError("secret-ish detail")])

    monkeypatch.setattr(loadtest, "_open_session", boom)

    class FakeWorld:
        def __init__(self, settings):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return None

        async def token(self, client_id):
            return "t"

    monkeypatch.setattr(loadtest, "World", FakeWorld)
    with pytest.raises(loadtest.LoadTestError) as info:
        await loadtest.run_loadtest(
            total=1, concurrency=1, warmup=0, settings=WorldSettings(admin_dsn="x")
        )
    msg = str(info.value)
    assert "ExceptionGroup" in msg and "ConnectionError" in msg
    assert "secret-ish" not in msg


async def test_errors_counted_not_in_latencies():
    calls = {"n": 0}

    async def flaky() -> None:
        calls["n"] += 1
        if calls["n"] % 4 == 0:
            raise ConnectionError("boom")

    async def ok() -> None:
        await asyncio.sleep(0)

    result = await measure([flaky] * 3, [ok] * 3, total=40, warmup=0, block=10)
    assert result.direct.n + result.direct.errors == 40
    assert result.direct.errors == 10
    assert result.gateway.n == 40 and result.gateway.errors == 0
    assert result.errors == {"direct:ConnectionError": 10}


async def test_alternating_blocks_cover_total():
    order: list[str] = []

    def side(name: str):
        async def call() -> None:
            order.append(name)
            await asyncio.sleep(0)

        return call

    result = await measure(
        [side("d")] * 4, [side("g")] * 4, total=23, warmup=5, block=10
    )
    assert block_sizes(23, 10) == [10, 10, 3]
    assert result.direct.n == 23 and result.gateway.n == 23
    assert order.count("d") == 28 and order.count("g") == 28  # + warm-up
    timed = order[10:]  # drop the two warm-up runs (5 each)
    runs = [timed[0]]
    for name in timed[1:]:
        if name != runs[-1]:
            runs.append(name)
    assert runs == ["d", "g"] * 3  # d,g alternate per block, 3 blocks
    assert block_sizes(0, 10) == []
    with pytest.raises(ValueError):
        block_sizes(5, 0)


def test_formats_report_machine_and_shared_host():
    stats = LatencyStats(n=5, p50_ms=1.0, p95_ms=2.0, p99_ms=3.0, max_ms=4.0, errors=0)
    result = LoadResult(stats, stats, 0.0, 0.0, {})
    params = {"total": 5, "concurrency": 2, "warmup": 1}
    md = loadtest.format_md(result, **params)
    assert "share one host" in md and "CPUs" in md
    assert "p95 overhead under 30 ms: yes" in md
    data = json.loads(loadtest.format_json(result, **params))
    assert data["machine"]["cpu_count"] and data["machine"]["os"]
    assert "share one host" in data["machine"]["note"]
    assert data["p95_overhead_under_30ms"] == "yes"
    assert data["direct"]["n"] == 5 and data["params"]["total"] == 5


def test_cli_loadtest_wires_options(monkeypatch, capsys):
    seen: dict[str, int] = {}

    async def fake(**kw: int) -> LoadResult:
        seen.update(kw)
        s = LatencyStats(1, 1.0, 1.0, 1.0, 1.0, 0)
        return LoadResult(s, s, 0.0, 0.0, {})

    monkeypatch.setattr(loadtest, "run_loadtest", fake)
    code = cli.main(
        ["loadtest", "--total", "7", "--concurrency", "3", "--format", "json"]
    )
    assert code == 0
    assert seen == {"total": 7, "concurrency": 3, "warmup": 200}
    assert json.loads(capsys.readouterr().out)["params"]["total"] == 7
    with pytest.raises(SystemExit):
        cli.main(["loadtest", "--format", "text"])


def test_cli_loadtest_exits_nonzero_when_a_side_has_no_samples(monkeypatch, capsys):
    async def dead(**kw: int) -> LoadResult:
        ok = LatencyStats(5, 1.0, 1.0, 1.0, 1.0, 0)
        return LoadResult(ok, LatencyStats(0, 0, 0, 0, 0, 5), 0.0, 0.0, {})

    monkeypatch.setattr(loadtest, "run_loadtest", dead)
    assert cli.main(["loadtest", "--total", "1"]) == 1
    assert "inconclusive" in capsys.readouterr().out


def test_cli_loadtest_unreachable_stack_is_exit_1(monkeypatch, capsys):
    async def boom(**kw: int) -> LoadResult:
        raise loadtest.LoadTestError("stack unreachable")

    monkeypatch.setattr(loadtest, "run_loadtest", boom)
    assert cli.main(["loadtest", "--total", "1"]) == 1
    assert "stack unreachable" in capsys.readouterr().err


async def _audit_count(dsn: str) -> int:
    """Row count of the gateway audit log through a read-only transaction."""
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SET TRANSACTION READ ONLY"))
            row = await conn.execute(text("SELECT count(*) FROM gateway.audit_log"))
            return int(row.scalar_one())
    finally:
        await engine.dispose()


@pytest.mark.integration
async def test_loadtest_small_live(stack_settings):
    import socket

    try:
        socket.create_connection(("127.0.0.1", 8200), timeout=1).close()
        socket.create_connection(("127.0.0.1", 8101), timeout=1).close()
    except OSError:
        pytest.skip("compose gateway or core-read unreachable")
    # stack_settings already skipped the test if Keycloak, the mock API or
    # Postgres is down. warmup=0, so the gateway saw exactly the 200 timed calls.
    dsn = stack_settings.admin_dsn
    try:
        before = await _audit_count(dsn)
    except (OSError, SQLAlchemyError):
        pytest.skip("audit log not readable (gateway not migrated?)")
    result = await loadtest.run_loadtest(
        total=200, concurrency=10, warmup=0, settings=stack_settings
    )
    assert result.direct.n == 200 and result.gateway.n == 200, result.errors
    assert result.errors == {}
    for _ in range(20):  # the audit writer may lag the response briefly
        after = await _audit_count(dsn)
        if after - before >= 200:
            break
        await asyncio.sleep(0.25)
    assert after - before >= 200
