import asyncio
import socket

import anyio
import httpx
import pytest
import uvicorn
from mcp.server.fastmcp import Context, FastMCP
from mcp.types import TextContent
from toolgate_gateway.downstreams import DownstreamConfig
from toolgate_gateway.pool import (
    DownstreamPool,
    DownstreamUnavailable,
    _http_client,
    http_session_factory,
)
from toolgate_pin.demo_server import build_demo_server

CONFIGS = [
    DownstreamConfig("core-read", "http://core-read.test/mcp"),
    DownstreamConfig("comms", "http://comms.test/mcp"),
]


def build_test_server() -> FastMCP:
    """The demo server plus test-only tools: a slow one and one that makes
    the server send notifications/tools/list_changed."""
    server = build_demo_server()

    @server.tool(name="slow", description="Sleeps.")
    async def slow(seconds: float) -> str:
        await anyio.sleep(seconds)
        return "done"

    @server.tool(name="poke", description="Sends tools/list_changed.")
    async def poke(ctx: Context) -> str:
        await ctx.session.send_tool_list_changed()
        return "poked"

    return server


@pytest.fixture
async def pool_and_factory(memory_factory_cls):
    pools = []

    async def make(fail=None, *, hang=(), delay=0.0, **kw):
        factory = memory_factory_cls(
            build_test_server, fail=fail, hang=hang, delay=delay
        )
        pool = DownstreamPool(CONFIGS, factory, **kw)
        pools.append(pool)
        await pool.start()
        return pool, factory

    yield make
    for p in pools:
        await p.close()


def text(result) -> str:
    assert isinstance(result.content[0], TextContent)
    return result.content[0].text


async def test_lists_and_calls_through_pool(pool_and_factory):
    pool, factory = await pool_and_factory()
    listed = await pool.list_tools("core-read")
    assert listed is not None
    info, tools = listed
    assert info.name == "insurer-demo"
    names = {t.name for t in tools}
    assert {"get_claim_status", "get_member_profile", "slow", "poke"} <= names

    result = await pool.call_tool("core-read", "get_claim_status", {"claim_id": "C1"})
    assert not result.isError
    assert '"approved"' in text(result)
    # One persistent session per server: no reconnect between list and call.
    assert factory.attempts == {"core-read": 1, "comms": 1}


async def test_down_server_omitted(pool_and_factory):
    pool, _ = await pool_and_factory(fail={"comms": -1})
    assert await pool.list_tools("comms") is None
    listed = await pool.list_tools("core-read")
    assert listed is not None and listed[1]
    with pytest.raises(DownstreamUnavailable) as ei:
        await pool.call_tool("comms", "send_member_message", {})
    assert ei.value.server_id == "comms"
    assert str(ei.value) == "downstream comms is unavailable"


async def test_unknown_server_is_unavailable(pool_and_factory):
    pool, _ = await pool_and_factory()
    assert await pool.list_tools("nope") is None
    with pytest.raises(DownstreamUnavailable):
        await pool.call_tool("nope", "x", {})


async def test_reconnect_after_failure(pool_and_factory):
    pool, factory = await pool_and_factory(fail={"comms": 2})
    # start() used the first failure; this list uses the second.
    assert await pool.list_tools("comms") is None
    listed = await pool.list_tools("comms")
    assert listed is not None
    assert factory.attempts["comms"] == 3


async def test_call_timeout_raises_unavailable(pool_and_factory):
    pool, factory = await pool_and_factory(call_timeout_s=0.1)
    with pytest.raises(DownstreamUnavailable):
        await pool.call_tool("core-read", "slow", {"seconds": 5})
    # The session was dropped; the next call reconnects and works.
    result = await pool.call_tool("core-read", "get_claim_status", {"claim_id": "C"})
    assert not result.isError
    assert factory.attempts["core-read"] == 2


async def test_server_dies_mid_session_then_reconnects(pool_and_factory):
    pool, factory = await pool_and_factory()
    assert await pool.list_tools("core-read") is not None
    factory.server_scopes["core-read"].cancel()
    await anyio.sleep(0.05)
    with pytest.raises(DownstreamUnavailable):
        await pool.call_tool("core-read", "get_claim_status", {"claim_id": "C"})
    # Other servers are unaffected; the dead one reconnects on the next list.
    assert await pool.list_tools("comms") is not None
    assert await pool.list_tools("core-read") is not None
    assert factory.attempts["core-read"] == 2


async def test_caller_cancellation_propagates_and_session_survives(pool_and_factory):
    pool, factory = await pool_and_factory()
    task = asyncio.create_task(pool.call_tool("core-read", "slow", {"seconds": 5}))
    await anyio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    result = await pool.call_tool("core-read", "get_claim_status", {"claim_id": "C"})
    assert not result.isError
    assert factory.attempts["core-read"] == 1


async def test_list_changed_callback_fires(pool_and_factory):
    pool, _ = await pool_and_factory()
    seen: list[str] = []
    fired = asyncio.Event()

    async def on_changed(server_id: str) -> None:
        seen.append(server_id)
        fired.set()

    pool.on_list_changed = on_changed
    await pool.call_tool("comms", "poke", {})
    await asyncio.wait_for(fired.wait(), 5)
    assert seen == ["comms"]


async def test_list_changed_callback_errors_are_contained(pool_and_factory):
    pool, _ = await pool_and_factory()
    calls = 0

    async def broken(server_id: str) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("boom")

    pool.on_list_changed = broken
    await pool.call_tool("comms", "poke", {})
    await anyio.sleep(0.05)
    assert calls == 1
    # The session still works after the callback failed.
    assert await pool.list_tools("comms") is not None


async def test_close_is_idempotent_and_drops_sessions(pool_and_factory):
    pool, _ = await pool_and_factory()
    await pool.close()
    await pool.close()
    assert await pool.list_tools("core-read") is None
    with pytest.raises(DownstreamUnavailable):
        await pool.call_tool("core-read", "get_claim_status", {"claim_id": "C"})


async def test_concurrent_callers_share_one_bounded_connect(pool_and_factory):
    pool, factory = await pool_and_factory(hang={"comms"}, call_timeout_s=1.0)
    factory.attempts.clear()
    loop = asyncio.get_running_loop()
    t0 = loop.time()

    async def call():
        with pytest.raises(DownstreamUnavailable):
            await pool.call_tool("comms", "send_member_message", {})
        return loop.time() - t0

    elapsed = await asyncio.gather(*(call() for _ in range(4)))
    assert max(elapsed) < 1.5, elapsed
    assert factory.attempts == {"comms": 1}  # one shared connect attempt


async def test_inflight_call_fails_fast_on_close(pool_and_factory):
    pool, _ = await pool_and_factory(call_timeout_s=3.0)
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(pool.call_tool("core-read", "slow", {"seconds": 10}))
    await anyio.sleep(0.2)
    t0 = loop.time()
    await pool.close()
    with pytest.raises(DownstreamUnavailable):
        await task
    assert loop.time() - t0 < 0.5


async def test_inflight_call_fails_fast_on_drop(pool_and_factory):
    pool, factory = await pool_and_factory(call_timeout_s=3.0)
    loop = asyncio.get_running_loop()
    task = asyncio.create_task(pool.call_tool("core-read", "slow", {"seconds": 10}))
    await anyio.sleep(0.2)
    t0 = loop.time()
    pool._drop("core-read", pool._conns["core-read"])
    with pytest.raises(DownstreamUnavailable):
        await task
    assert loop.time() - t0 < 0.5
    # The next request reconnects.
    assert await pool.list_tools("core-read") is not None
    assert factory.attempts["core-read"] == 2


async def test_close_waits_for_holders_started_during_close(pool_and_factory):
    pool, factory = await pool_and_factory(fail={"comms": 1}, delay=0.2)
    assert factory.open == 1  # core-read up, comms failed at start
    pending = asyncio.create_task(pool.list_tools("comms"))  # reconnecting
    await anyio.sleep(0.05)
    await pool.close()
    assert await pending is None
    assert not pool._tasks
    assert factory.open == 0


async def test_close_bounded_with_hanging_connect(pool_and_factory):
    pool, _ = await pool_and_factory(hang={"comms"}, call_timeout_s=1.0)
    pending = asyncio.create_task(pool.list_tools("comms"))
    await anyio.sleep(0.05)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    await pool.close()
    assert loop.time() - t0 < 0.5
    assert await pending is None
    assert not pool._tasks


def _messages(factory, server_id, method):
    """JSON-RPC messages with ``method`` the server received, in order."""
    out = []
    for message in factory.received.get(server_id, []):
        root = getattr(getattr(message, "message", None), "root", None)
        if getattr(root, "method", None) == method:
            out.append(root)
    return out


async def _first(factory, server_id, method):
    for _ in range(500):
        if found := _messages(factory, server_id, method):
            return found[0]
        await anyio.sleep(0.01)
    raise AssertionError(f"{server_id} never received {method}")


@pytest.mark.parametrize("how", ["caller_cancel", "timeout"])
async def test_cancelled_call_notifies_downstream(memory_factory_cls, how):
    """mcp's client sends no notifications/cancelled itself: the pool does,
    with the abandoned request's id, on caller cancel and on timeout."""
    factory = memory_factory_cls(build_test_server, record=True)
    timeout = 0.3 if how == "timeout" else 30.0
    pool = DownstreamPool(CONFIGS, factory, call_timeout_s=timeout)
    await pool.start()
    try:
        task = asyncio.create_task(pool.call_tool("core-read", "slow", {"seconds": 5}))
        request = await _first(factory, "core-read", "tools/call")
        if how == "caller_cancel":
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(DownstreamUnavailable):
                await task
        note = await _first(factory, "core-read", "notifications/cancelled")
        assert note.params["requestId"] == request.id
        assert len(_messages(factory, "core-read", "notifications/cancelled")) == 1
    finally:
        await pool.close()


async def test_completed_call_sends_no_cancel(memory_factory_cls):
    factory = memory_factory_cls(build_test_server, record=True)
    pool = DownstreamPool(CONFIGS, factory)
    await pool.start()
    try:
        await pool.call_tool("core-read", "get_claim_status", {"claim_id": "C"})
        await anyio.sleep(0.05)
        assert _messages(factory, "core-read", "notifications/cancelled") == []
    finally:
        await pool.close()


def test_http_client_config():
    auth = CountingAuth()
    client = _http_client(auth)
    assert client.timeout == httpx.Timeout(30.0, read=300.0)
    assert client.follow_redirects is False
    assert client.auth is auth


# --- production HTTP factory against a real streamable HTTP server ---------


class CountingAuth(httpx.Auth):
    def __init__(self):
        self.requests = 0

    async def async_auth_flow(self, request):
        self.requests += 1
        request.headers["Authorization"] = "Bearer test-downstream-token"
        yield request


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
async def http_server():
    mcp = build_test_server()
    seen_auth: list[str | None] = []
    app = mcp.streamable_http_app()

    async def recording_app(scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope["headers"])
            seen_auth.append(headers.get(b"authorization", b"").decode() or None)
        await app(scope, receive, send)

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(recording_app, host="127.0.0.1", port=port, log_level="error")
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}/mcp", seen_auth
    server.should_exit = True
    await task


async def test_http_factory_uses_auth(http_server):
    url, seen_auth = http_server
    auth = CountingAuth()
    pool = DownstreamPool(
        [DownstreamConfig("core-read", url)], http_session_factory(auth)
    )
    await pool.start()
    try:
        listed = await pool.list_tools("core-read")
        assert listed is not None
        assert listed[0].name == "insurer-demo"
        result = await pool.call_tool(
            "core-read", "get_claim_status", {"claim_id": "C1"}
        )
        assert not result.isError
    finally:
        await pool.close()
    assert auth.requests > 0
    assert seen_auth and all(a == "Bearer test-downstream-token" for a in seen_auth)
