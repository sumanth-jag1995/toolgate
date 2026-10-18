"""Connections to MCP servers (in-memory here; Task 6 adds real transports)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session


@asynccontextmanager
async def in_memory_session(server: FastMCP) -> AsyncIterator[ClientSession]:
    """Yield an initialized ClientSession wired directly to ``server``."""
    async with create_connected_server_and_client_session(
        server._mcp_server
    ) as session:
        yield session
