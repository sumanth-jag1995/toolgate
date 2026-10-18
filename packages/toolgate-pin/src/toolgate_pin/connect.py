"""Connections to MCP servers: in-memory, stdio and streamable HTTP.

Header templates such as ``Authorization: Bearer ${TOKEN}`` are expanded only
in memory, for the duration of one connection. Nothing in this module puts an
expanded value into an exception message, a log line or the lockfile.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import AsyncIterator, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from datetime import timedelta
from urllib.parse import urlsplit

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.fastmcp import FastMCP
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.memory import create_client_server_memory_streams
from mcp.types import InitializeResult, PaginatedRequestParams, Tool

from toolgate_pin.models import Target

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_READ_TIMEOUT = timedelta(seconds=30)


class UsageError(Exception):
    """Bad command-line input; the CLI exits 2. Messages never carry secrets."""


class ConnectError(Exception):
    """Could not reach or talk to a server. ``str()`` is the target display only."""


def _split_header(h: str) -> tuple[str, str]:
    name, sep, value = h.partition(":")
    name = name.strip()
    if not sep or not name or any(c.isspace() for c in name):
        # The whole string may be a secret: never echo it.
        raise UsageError('a --header must look like "Name: value with ${ENV_VAR}"')
    return name, value.strip()


def validate_header_template(h: str) -> None:
    """Refuse a header whose value carries no ``${NAME}`` (a literal secret)."""
    name, value = _split_header(h)
    if not _VAR.search(value):
        raise UsageError(
            f"header '{name}' has a literal value; put the secret in an environment "
            f'variable and pass it as a template, e.g. "{name}: Bearer ${{TOKEN}}"'
        )


def expand_headers(templates: Sequence[str], env: Mapping[str, str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for h in templates:
        validate_header_template(h)
        name, value = _split_header(h)
        for var in _VAR.findall(value):
            if var not in env:
                raise UsageError(f"environment variable {var} is not set")
        headers[name] = _VAR.sub(lambda m: env[m.group(1)], value)
    return headers


def target_display(target: Target) -> str:
    """Human-readable target without headers, credentials or query strings."""
    if target.url is not None:
        parts = urlsplit(target.url)
        host = parts.hostname or ""
        if parts.port is not None:
            host = f"{host}:{parts.port}"
        return f"{parts.scheme}://{host}{parts.path}"
    if target.command:
        return shlex.join(target.command)
    return "<no target>"


@asynccontextmanager
async def open_session(
    target: Target, env: Mapping[str, str]
) -> AsyncIterator[tuple[ClientSession, InitializeResult]]:
    """Connect to ``target`` and yield ``(session, initialize_result)``.

    Header templates are validated and expanded before connecting (UsageError).
    Any failure while connected, including in the caller's block, is raised as
    ConnectError carrying only the target display.
    """
    display = target_display(target)
    if target.url is not None:
        if urlsplit(target.url).scheme not in ("http", "https"):
            raise UsageError("a server URL must start with http:// or https://")
        headers = expand_headers(target.headers, env)
    elif target.command:
        if target.headers:
            raise UsageError("--header applies only to http(s) servers")
        headers = {}
    else:
        raise UsageError("no server target: give a URL or --stdio -- <command>")

    try:
        async with AsyncExitStack() as stack:
            if target.url is not None:
                client = await stack.enter_async_context(
                    create_mcp_http_client(headers=headers)
                )
                read, write, _ = await stack.enter_async_context(
                    streamable_http_client(target.url, http_client=client)
                )
            else:
                params = StdioServerParameters(
                    command=target.command[0],
                    args=list(target.command[1:]),
                    env=dict(env),  # inherit the caller's environment (PATH etc.)
                )
                read, write = await stack.enter_async_context(stdio_client(params))
            session = await stack.enter_async_context(
                ClientSession(read, write, read_timeout_seconds=_READ_TIMEOUT)
            )
            init = await session.initialize()
            yield session, init
    except (UsageError, ConnectError):
        raise
    except Exception as exc:
        raise ConnectError(display) from exc


@asynccontextmanager
async def in_memory_session(
    server: FastMCP,
) -> AsyncIterator[tuple[ClientSession, InitializeResult]]:
    """Yield ``(session, initialize_result)`` wired directly to ``server``.

    Same wiring as mcp.shared.memory's helper, but it keeps the one
    InitializeResult instead of making callers initialize a second time.
    """
    lowlevel = server._mcp_server
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
            async with ClientSession(client[0], client[1]) as session:
                init = await session.initialize()
                yield session, init
        finally:
            tg.cancel_scope.cancel()


async def fetch_tools(
    target: Target, env: Mapping[str, str]
) -> tuple[InitializeResult, list[Tool]]:
    """Connect, initialize once, and list every tool (following pagination)."""
    async with open_session(target, env) as (session, init):
        tools: list[Tool] = []
        cursor: str | None = None
        while True:
            params = PaginatedRequestParams(cursor=cursor) if cursor else None
            page = await session.list_tools(params=params)
            tools.extend(page.tools)
            cursor = page.nextCursor
            if not cursor:
                return init, tools


def describe_error(exc: ConnectError) -> str:
    """One line for a ConnectError: the target display plus the underlying
    error *type* only (exception messages may echo request details)."""
    leaf: BaseException | None = exc.__cause__
    while isinstance(leaf, BaseExceptionGroup) and leaf.exceptions:
        leaf = leaf.exceptions[0]
    suffix = f" ({type(leaf).__name__})" if leaf is not None else ""
    return f"cannot connect to {exc}{suffix}"
