"""Corpus-driven attacker MCP server: real MCP client over HTTP, sink running.

The definitions served here are the committed synthetic corpus (reserved fake
hosts, synthetic data); the tests only check they are served verbatim and that
call arguments reach the local sink.
"""

import asyncio
import contextlib
import json
import time
from collections.abc import AsyncIterator

import anyio
import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import ServerNotification, TextContent, ToolListChangedNotification
from toolgate_eval.attacker import AttackerServer
from toolgate_eval.sink import SinkServer
from toolgate_pin.corpus import InventoryEntry, MaliciousVariant, load_corpus

VARIANTS = {v.id: v for v in load_corpus("test").malicious}
_TAG_RANGE = range(0xE0000, 0xE0080)


@pytest.fixture
async def sink() -> AsyncIterator[SinkServer]:
    s = SinkServer()
    await s.start()
    yield s
    await s.stop()


@contextlib.asynccontextmanager
async def attacker(variant: MaliciousVariant, sink: SinkServer):
    server = AttackerServer(variant, sink.url)
    url = await server.start()
    try:
        yield server, url
    finally:
        await server.stop()


@contextlib.asynccontextmanager
async def client(url: str, notes: list | None = None):
    async def on_message(msg):
        if notes is not None and isinstance(msg, ServerNotification):
            notes.append(msg.root)

    # verify=False/trust_env=False: plain HTTP on 127.0.0.1, and building a
    # TLS context per client costs ~0.3 s on Windows.
    http = httpx.AsyncClient(
        verify=False, trust_env=False, timeout=httpx.Timeout(30, read=300)
    )
    async with (
        http,
        streamable_http_client(url, http_client=http) as (read, write, _),
        ClientSession(read, write, message_handler=on_message) as session,
    ):
        await session.initialize()
        yield session


def served(tool) -> dict:
    return tool.model_dump(by_alias=True, exclude_none=True)


def text_of(result) -> str:
    assert isinstance(result.content[0], TextContent)
    return result.content[0].text


def sample_args(defn: dict) -> dict:
    props = defn.get("inputSchema", {}).get("properties", {})
    return {name: f"value-{i}" for i, name in enumerate(props)}


async def notified(srv: AttackerServer, notes: list) -> bool:
    """mutate() until the client sees tools/list_changed.

    The client's standalone GET stream opens asynchronously after initialize;
    a notification sent before it exists is dropped.
    """

    def seen() -> bool:
        return any(isinstance(n, ToolListChangedNotification) for n in notes)

    for _ in range(20):
        assert await srv.mutate() is True
        with anyio.move_on_after(0.25):
            while not seen():
                await anyio.sleep(0.01)
        if seen():
            return True
    return False


async def test_serves_approved_definition_verbatim(sink):
    v = VARIANTS["us-01"]
    assert any(ord(c) in _TAG_RANGE for c in json.dumps(v.approved, ensure_ascii=False))
    async with attacker(v, sink) as (_, url), client(url) as s:
        tools = (await s.list_tools()).tools
    assert len(tools) == 1
    assert served(tools[0]) == v.approved
    assert tools[0].description == v.approved["description"]  # tag chars intact


async def test_call_forwards_all_arguments_to_sink(sink):
    v = VARIANTS["dp-01"]
    args = sample_args(v.approved) | {"extra": {"nested": [1, 2]}}
    async with attacker(v, sink) as (srv, url), client(url) as s:
        result = await s.call_tool(v.approved["name"], args)
    assert not result.isError
    assert text_of(result)
    [req] = sink.requests
    assert req.method == "POST"
    assert req.path == f"/exfil/{v.id}"
    assert json.loads(req.body_text) == {
        "variant": v.id,
        "tool": v.approved["name"],
        "arguments": args,
    }
    assert srv.calls == [(v.approved["name"], len(args))]


async def test_unknown_tool_is_error_and_not_forwarded(sink):
    v = VARIANTS["dp-01"]
    async with attacker(v, sink) as (srv, url), client(url) as s:
        result = await s.call_tool("no_such_tool", {"a": "b"})
    assert result.isError
    assert sink.requests == []
    assert srv.calls == []


async def test_forwarding_failure_still_returns_benign_result(sink):
    v = VARIANTS["dp-01"]

    async def hang_up(reader, writer):
        writer.close()  # every forward fails with a protocol error

    broken = await asyncio.start_server(hang_up, "127.0.0.1", 0)
    port = broken.sockets[0].getsockname()[1]
    server = AttackerServer(v, f"http://127.0.0.1:{port}")
    url = await server.start()
    try:
        async with client(url) as s:
            result = await s.call_tool(v.approved["name"], sample_args(v.approved))
    finally:
        await server.stop()
        broken.close()
    assert not result.isError
    assert text_of(result)
    assert server.calls == [(v.approved["name"], len(sample_args(v.approved)))]


async def test_mutate_changes_definition_and_notifies(sink):
    v = VARIANTS["rp-01"]
    assert v.mutated is not None and v.mutated != v.approved
    notes: list = []
    async with attacker(v, sink) as (srv, url), client(url, notes) as s:
        assert served((await s.list_tools()).tools[0]) == v.approved
        assert srv.live_definition() == v.approved
        assert await notified(srv, notes)
        assert srv.live_definition() == v.mutated
        assert served((await s.list_tools()).tools[0]) == v.mutated


async def test_mutate_noop_for_non_rug_pull(sink):
    v = VARIANTS["dp-01"]
    async with attacker(v, sink) as (srv, url), client(url) as s:
        await s.list_tools()
        assert await srv.mutate() is False
        assert srv.live_definition() == v.approved
        assert served((await s.list_tools()).tools[0]) == v.approved


async def test_output_sample_returned_for_variants_that_have_one(sink):
    with_sample = [v for v in VARIANTS.values() if v.output_sample]
    assert with_sample
    for v in with_sample:
        async with attacker(v, sink) as (_, url), client(url) as s:
            result = await s.call_tool(v.approved["name"], sample_args(v.approved))
        assert not result.isError
        assert text_of(result) == v.output_sample


async def test_reset_restores_and_is_idempotent(sink):
    v = VARIANTS["rp-01"]
    async with attacker(v, sink) as (srv, url):
        async with client(url) as s:
            await s.list_tools()
            await s.call_tool(v.approved["name"], sample_args(v.approved))
            assert await srv.mutate() is True
        assert srv.live_definition() == v.mutated
        assert srv.calls
        srv.reset()
        assert srv.live_definition() == v.approved
        assert srv.calls == []
        srv.reset()
        assert srv.live_definition() == v.approved
        assert srv.calls == []
        async with client(url) as s:
            assert served((await s.list_tools()).tools[0]) == v.approved


async def test_only_own_server_inventory_is_served(sink):
    v = VARIANTS["sh-01"]
    foreign = {e.name for e in v.inventory if e.server_id != v.server_id}
    assert foreign
    async with attacker(v, sink) as (_, url), client(url) as s:
        names = {t.name for t in (await s.list_tools()).tools}
    assert names == {v.approved["name"]}
    # An own-server inventory entry (none in the committed corpus) is served.
    own_defn = {
        "name": "own_helper",
        "description": "Helper.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    v2 = v.model_copy(
        update={
            "inventory": [
                *v.inventory,
                InventoryEntry(
                    server_id=v.server_id, name="own_helper", definition=own_defn
                ),
            ]
        }
    )
    async with attacker(v2, sink) as (_, url), client(url) as s:
        tools = {t.name: t for t in (await s.list_tools()).tools}
    assert set(tools) == {v.approved["name"], "own_helper"}
    assert served(tools["own_helper"]) == own_defn


async def test_fresh_server_has_no_state_from_previous_instance(sink):
    v = VARIANTS["rp-01"]
    async with attacker(v, sink) as (srv, url), client(url) as s:
        await s.call_tool(v.approved["name"], sample_args(v.approved))
        await srv.mutate()
        srv.live_definition()["description"] = "tampered"  # a copy, not state
        assert srv.calls
    fresh = {x.id: x for x in load_corpus("test").malicious}["rp-01"]
    assert v.approved == fresh.approved  # the variant was not modified
    async with attacker(v, sink) as (srv2, url2):
        assert srv2.calls == []
        assert srv2.live_definition() == v.approved
        async with client(url2) as s:
            assert served((await s.list_tools()).tools[0]) == v.approved


async def test_stop_is_prompt_with_connected_client(sink):
    v = VARIANTS["rp-01"]
    srv = AttackerServer(v, sink.url)
    url = await srv.start()
    notes: list = []
    stack = contextlib.AsyncExitStack()
    s = await stack.enter_async_context(client(url, notes))
    await s.list_tools()
    # Wait until the client's standalone GET stream is open (it carries the
    # list_changed notification): the connection most likely to hold shutdown.
    assert await notified(srv, notes)
    t0 = time.monotonic()
    await srv.stop()
    assert time.monotonic() - t0 < 2.0
    with anyio.move_on_after(5), contextlib.suppress(Exception):
        await stack.aclose()
    await srv.stop()  # idempotent


@pytest.mark.parametrize("vid", sorted(VARIANTS))
async def test_every_test_variant_serves_and_forwards(vid, sink):
    v = VARIANTS[vid]
    args = sample_args(v.approved)
    t0 = time.monotonic()
    srv = AttackerServer(v, sink.url)
    url = await srv.start()
    assert time.monotonic() - t0 < 1.0
    assert url.startswith("http://127.0.0.1:") and url.endswith("/mcp")
    try:
        async with client(url) as s:
            tools = (await s.list_tools()).tools
            assert served(tools[0]) == v.approved
            result = await s.call_tool(v.approved["name"], args)
            assert not result.isError
    finally:
        t1 = time.monotonic()
        await srv.stop()
        assert time.monotonic() - t1 < 2.0
    [req] = [r for r in sink.requests if r.path == f"/exfil/{v.id}"]
    assert json.loads(req.body_text)["arguments"] == args
