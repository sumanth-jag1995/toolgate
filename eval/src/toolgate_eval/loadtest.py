"""Gateway overhead load test.

Compares ``get_claim_status`` for the canary member's claim called

* **direct** on the real ``core-read`` server (``localhost:8101``) with a
  ``dev-tester`` token, and
* through the **compose gateway** (``localhost:8200``) with a ``servicing``
  token as ``core-read.get_claim_status`` (real audit writer, pins, tracing).

Both use persistent MCP sessions (one per concurrency worker, opened before
timing starts), per-call wall time from ``time.perf_counter`` and discarded
warm-up calls. The two sides run in alternating blocks so drift (caches, CPU
boost, the OS) hits both equally. A failed call is counted in ``errors`` by
exception type and never enters a latency list. ``overhead = gateway -
direct`` for p50 and p95; whether p95 overhead is under the 30 ms ship-gate
target is reported (:attr:`LoadResult.p95_under_target`), never asserted.

Gateway and servers share one host: the numbers exclude real network latency
and include CPU contention between the load generator, the gateway and the
servers. Secrets (client secrets, tokens) are never logged or reported.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import platform
import sys
import time
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import AsyncExitStack
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from toolgate_eval.world import World, WorldSettings

DIRECT_URL = "http://127.0.0.1:8101/mcp"
GATEWAY_URL = "http://127.0.0.1:8200/mcp"
DIRECT_TOOL = "get_claim_status"
GATEWAY_TOOL = "core-read.get_claim_status"
P95_TARGET_MS = 30.0
DEFAULT_BLOCK = 250
CALL_TIMEOUT_S = 30.0

Call = Callable[[], Awaitable[None]]


class LoadTestError(Exception):
    """The load test could not run (stack unreachable, no claim to query)."""


@dataclass(frozen=True)
class LatencyStats:
    n: int
    p50_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    errors: int
    throughput_rps: float = 0.0  # calls per second of this side's block time


@dataclass(frozen=True)
class LoadResult:
    direct: LatencyStats
    gateway: LatencyStats
    overhead_p50_ms: float
    overhead_p95_ms: float
    errors: dict[str, int] = field(default_factory=dict)

    @property
    def p95_under_target(self) -> bool:
        return self.overhead_p95_ms < P95_TARGET_MS


def percentile(samples_ms: Sequence[float], q: float) -> float:
    """The q-th percentile (0-100) by linear interpolation between ranks
    (numpy's default method); 0.0 for an empty list."""
    if not samples_ms:
        return 0.0
    data = sorted(samples_ms)
    pos = (len(data) - 1) * q / 100
    lo = math.floor(pos)
    hi = math.ceil(pos)
    return data[lo] + (data[hi] - data[lo]) * (pos - lo)


def make_stats(
    samples_ms: Sequence[float], errors: int = 0, wall_s: float = 0.0
) -> LatencyStats:
    return LatencyStats(
        n=len(samples_ms),
        p50_ms=percentile(samples_ms, 50),
        p95_ms=percentile(samples_ms, 95),
        p99_ms=percentile(samples_ms, 99),
        max_ms=max(samples_ms, default=0.0),
        errors=errors,
        throughput_rps=(len(samples_ms) / wall_s) if wall_s > 0 else 0.0,
    )


def make_result(
    direct: LatencyStats, gateway: LatencyStats, errors: dict[str, int]
) -> LoadResult:
    return LoadResult(
        direct=direct,
        gateway=gateway,
        overhead_p50_ms=gateway.p50_ms - direct.p50_ms,
        overhead_p95_ms=gateway.p95_ms - direct.p95_ms,
        errors=dict(errors),
    )


def block_sizes(total: int, block: int) -> list[int]:
    """Block sizes that sum to ``total``, each at most ``block``."""
    if total < 0 or block < 1:
        raise ValueError("total must be >= 0 and block >= 1")
    full, rest = divmod(total, block)
    return [block] * full + ([rest] if rest else [])


@dataclass
class _Side:
    samples_ms: list[float] = field(default_factory=list)
    errors: Counter[str] = field(default_factory=Counter)
    wall_s: float = 0.0


async def _run_block(calls: Sequence[Call], count: int, side: _Side) -> None:
    """``count`` timed calls spread over ``len(calls)`` workers (one call
    function, i.e. one session, per worker)."""
    remaining = count
    block_start = time.perf_counter()

    async def worker(call: Call) -> None:
        nonlocal remaining
        while remaining > 0:
            remaining -= 1  # no await between the check and the decrement
            start = time.perf_counter()
            try:
                await call()
            except Exception as exc:  # noqa: BLE001 - any failure is a counted error
                side.errors[type(exc).__name__] += 1
                continue
            side.samples_ms.append((time.perf_counter() - start) * 1000)

    await asyncio.gather(*(worker(c) for c in calls))
    side.wall_s += time.perf_counter() - block_start


async def measure(
    direct_calls: Sequence[Call],
    gateway_calls: Sequence[Call],
    *,
    total: int,
    warmup: int,
    block: int = DEFAULT_BLOCK,
) -> LoadResult:
    """Warm both sides up (results discarded), then run ``total`` timed calls
    per side in alternating blocks: direct, gateway, direct, gateway, ..."""
    discard = _Side()
    for calls in (direct_calls, gateway_calls):
        await _run_block(calls, warmup, discard)
    direct, gateway = _Side(), _Side()
    for size in block_sizes(total, block):
        await _run_block(direct_calls, size, direct)
        await _run_block(gateway_calls, size, gateway)
    errors = {
        f"{name}:{exc}": n
        for name, side in (("direct", direct), ("gateway", gateway))
        for exc, n in side.errors.items()
    }
    return make_result(
        make_stats(direct.samples_ms, sum(direct.errors.values()), direct.wall_s),
        make_stats(gateway.samples_ms, sum(gateway.errors.values()), gateway.wall_s),
        errors,
    )


class _BearerAuth(httpx.Auth):
    """Bearer token fetched per request from a cached provider, so a long run
    outlives one token's lifetime without a re-login stall."""

    def __init__(self, provider: Callable[[], Awaitable[str]]) -> None:
        self._provider = provider

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncIterator[httpx.Request]:
        request.headers["Authorization"] = f"Bearer {await self._provider()}"
        yield request


async def _open_session(
    stack: AsyncExitStack, url: str, provider: Callable[[], Awaitable[str]]
) -> ClientSession:
    http = await stack.enter_async_context(
        httpx.AsyncClient(auth=_BearerAuth(provider), timeout=CALL_TIMEOUT_S)
    )
    read, write, _ = await stack.enter_async_context(
        streamable_http_client(url, http_client=http)
    )
    session = await stack.enter_async_context(ClientSession(read, write))
    await session.initialize()
    return session


def _caller(session: ClientSession, tool: str, args: dict[str, Any]) -> Call:
    async def call() -> None:
        result = await session.call_tool(tool, args)
        if result.isError:
            raise RuntimeError("tool error")

    return call


async def _canary_claim(session: ClientSession, member_id: str) -> str:
    result = await session.call_tool("list_member_claims", {"member_id": member_id})
    claims = (result.structuredContent or {}).get("claims") or []
    if result.isError or not claims:
        raise LoadTestError("no claim found for the canary member")
    return str(claims[0]["claim_id"])


async def run_loadtest(
    *,
    total: int = 5000,
    concurrency: int = 50,
    warmup: int = 200,
    block: int = DEFAULT_BLOCK,
    settings: WorldSettings | None = None,
) -> LoadResult:
    """Run the live load test against the compose stack."""
    if total < 1 or concurrency < 1 or warmup < 0:
        raise LoadTestError("total and concurrency must be >= 1, warmup >= 0")
    settings = settings or WorldSettings.from_env()
    try:
        async with World(settings) as world, AsyncExitStack() as stack:

            async def dev_token() -> str:
                return await world.token("dev-tester")

            async def servicing_token() -> str:
                return await world.token("servicing")

            await dev_token()
            await servicing_token()
            direct_sessions = [
                await _open_session(stack, DIRECT_URL, dev_token)
                for _ in range(concurrency)
            ]
            gateway_sessions = [
                await _open_session(stack, GATEWAY_URL, servicing_token)
                for _ in range(concurrency)
            ]
            claim_id = await _canary_claim(direct_sessions[0], settings.member_id)
            args = {"claim_id": claim_id}
            return await measure(
                [_caller(s, DIRECT_TOOL, args) for s in direct_sessions],
                [_caller(s, GATEWAY_TOOL, args) for s in gateway_sessions],
                total=total,
                warmup=warmup,
                block=block,
            )
    except (httpx.HTTPError, OSError) as exc:
        raise LoadTestError(
            f"stack unreachable or call setup failed ({type(exc).__name__})"
        ) from None


def machine_info() -> dict[str, Any]:
    return {
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "os": f"{platform.system()} {platform.release()}",
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": sys.version.split()[0],
        "note": "gateway and MCP servers share one host with the load generator",
    }


def to_dict(
    result: LoadResult, *, total: int, concurrency: int, warmup: int
) -> dict[str, Any]:
    return {
        "machine": machine_info(),
        "params": {"total": total, "concurrency": concurrency, "warmup": warmup},
        "direct": asdict(result.direct),
        "gateway": asdict(result.gateway),
        "overhead_p50_ms": result.overhead_p50_ms,
        "overhead_p95_ms": result.overhead_p95_ms,
        "p95_overhead_under_30ms": result.p95_under_target,
        "errors": result.errors,
    }


def format_json(result: LoadResult, **params: int) -> str:
    return json.dumps(to_dict(result, **params), indent=2, sort_keys=True)


def format_md(result: LoadResult, *, total: int, concurrency: int, warmup: int) -> str:
    m = machine_info()
    rows = [
        f"| {name} | {s.n} | {s.p50_ms:.1f} | {s.p95_ms:.1f} | {s.p99_ms:.1f} "
        f"| {s.max_ms:.1f} | {s.throughput_rps:.0f} | {s.errors} |"
        for name, s in (("direct", result.direct), ("gateway", result.gateway))
    ]
    verdict = "yes" if result.p95_under_target else "no"
    lines = [
        "**Gateway overhead load test**",
        "",
        (
            f"- Date {m['date']}; {m['os']} ({m['machine']}), {m['cpu_count']} "
            f"CPUs, Python {m['python']}."
        ),
        (
            f"- {total} calls per side, concurrency {concurrency}, warm-up "
            f"{warmup} (discarded), alternating blocks."
        ),
        (
            "- Gateway, MCP servers and the load generator share one host: no "
            "real network latency, and CPU contention is included."
        ),
        "",
        "| Path | n | p50 ms | p95 ms | p99 ms | max ms | calls/s | errors |",
        "|---|---|---|---|---|---|---|---|",
        *rows,
        "",
        (
            f"- Overhead (gateway - direct): p50 {result.overhead_p50_ms:.1f} ms, "
            f"p95 {result.overhead_p95_ms:.1f} ms."
        ),
        f"- p95 overhead under {P95_TARGET_MS:.0f} ms: {verdict}.",
    ]
    if result.errors:
        lines.append(f"- Errors by side:type: {json.dumps(result.errors)}")
    return "\n".join(lines)
