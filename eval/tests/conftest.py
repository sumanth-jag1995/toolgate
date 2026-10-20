"""Shared fixtures.

Integration tests (marked ``integration``) use the ``world`` and ``open_mcp``
fixtures, which skip cleanly when the repo-root ``.env``, Keycloak, the mock
API or Postgres is unavailable.
"""

import socket
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from typing import Any

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mock_enterprise.canary import CANARY
from toolgate_eval.sink import CANARY_FIELDS, CanaryMatcher
from toolgate_eval.world import World, WorldError, WorldSettings

MCP_URLS = {
    "core-read": "http://127.0.0.1:8101/mcp",
    "core-write": "http://127.0.0.1:8102/mcp",
    "comms": "http://127.0.0.1:8103/mcp",
}
SERVER_OF = {
    "get_member_profile": "core-read",
    "get_policy_details": "core-read",
    "check_coverage": "core-read",
    "get_claim_status": "core-read",
    "list_member_claims": "core-read",
    "get_payment_history": "core-read",
    "get_correspondence_history": "core-read",
    "log_claim": "core-write",
    "add_claim_note": "core-write",
    "update_contact_preference": "core-write",
    "send_member_message": "comms",
    "schedule_callback": "comms",
}


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def require_stack() -> WorldSettings:
    """Settings for the live stack, or skip the test when it is unreachable."""
    try:
        settings = WorldSettings.from_env()
    except WorldError as exc:
        pytest.skip(f"no usable .env: {exc}")
    probes = {
        "Keycloak": settings.token_url.rsplit("/protocol/", 1)[0],
        "mock API": f"{settings.api_url}/openapi.json",
    }
    for name, url in probes.items():
        try:
            if httpx.get(url, timeout=2).status_code != 200:
                pytest.skip(f"{name} not ready")
        except httpx.HTTPError:
            pytest.skip(f"{name} unreachable")
    if not _port_open("127.0.0.1", 5432):
        pytest.skip("Postgres unreachable")
    return settings


class McpCaller:
    """Calls the real MCP servers with one token and records the tool names."""

    def __init__(self, token: str) -> None:
        self._token = token
        self._stack = AsyncExitStack()
        self._sessions: dict[str, ClientSession] = {}
        self.names: list[str] = []

    async def _session(self, server: str) -> ClientSession:
        if server not in self._sessions:
            http = await self._stack.enter_async_context(
                httpx.AsyncClient(
                    headers={"Authorization": f"Bearer {self._token}"}, timeout=10
                )
            )
            read, write, _ = await self._stack.enter_async_context(
                streamable_http_client(MCP_URLS[server], http_client=http)
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._sessions[server] = session
        return self._sessions[server]

    async def __call__(self, tool: str, **args: Any) -> dict[str, Any]:
        session = await self._session(SERVER_OF[tool])
        result = await session.call_tool(tool, args)
        self.names.append(tool)
        assert not result.isError, f"{tool} returned a tool error"
        assert result.structuredContent is not None
        return result.structuredContent

    async def aclose(self) -> None:
        await self._stack.aclose()


@pytest.fixture
def matcher() -> CanaryMatcher:
    return CanaryMatcher({k: CANARY[k] for k in CANARY_FIELDS})


@pytest.fixture
def stack_settings() -> WorldSettings:
    return require_stack()


@pytest.fixture
async def world(stack_settings: WorldSettings) -> AsyncIterator[World]:
    async with World(stack_settings) as w:
        yield w


@pytest.fixture
def open_mcp(world: World) -> Callable[[], AbstractAsyncContextManager[McpCaller]]:
    """Factory, used as ``async with open_mcp() as call``: MCP client sessions
    must be opened and closed in the test's own task."""

    @asynccontextmanager
    async def opener() -> AsyncIterator[McpCaller]:
        caller = McpCaller(await world.token("dev-tester"))
        try:
            yield caller
        finally:
            await caller.aclose()

    return opener
