"""MCP servers as LangChain tools, over streamable HTTP.

One client session per server URL. Each MCP tool becomes a ``StructuredTool``
whose ``args_schema`` is the server's own JSON schema, so the model sees the
real schema. The toolkit records which tools were called (real MCP names and
success flags) and nothing else: never arguments, never results.

The connections live in a background task owned by the toolkit, so ``close``
may be called from any task (for example a pytest fixture's teardown).
"""

from __future__ import annotations

import asyncio
import json
import re
import warnings
from collections.abc import Awaitable, Callable, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Self
from urllib.parse import urlsplit

from langchain_core.tools import BaseTool, StructuredTool
from mcp.client.session import ClientSession
from mcp.types import CallToolResult, PaginatedRequestParams, TextContent, Tool

TokenProvider = Callable[[], Awaitable[str | None]]

MAX_RESULT_CHARS = 8000
MAX_NAME_CHARS = 64
MAX_TOOL_PAGES = 100
_READ_TIMEOUT = timedelta(seconds=30)
_UNSAFE_NAME_CHARS = re.compile(r"[^a-zA-Z0-9_-]")


@dataclass(frozen=True)
class ToolCallRecord:
    name: str  # the real MCP tool name
    ok: bool


@dataclass(frozen=True)
class ToolCollision:
    name: str
    kept_url: str
    dropped_url: str


def sanitise_tool_names(names: Sequence[str]) -> list[str]:
    """Model-facing names: characters outside ``[a-zA-Z0-9_-]`` become ``_``,
    at most 64 characters, de-duplicated in order with ``_2``, ``_3``..."""
    out: list[str] = []
    taken: set[str] = set()
    for name in names:
        base = _UNSAFE_NAME_CHARS.sub("_", name)[:MAX_NAME_CHARS] or "tool"
        candidate, n = base, 1
        while candidate in taken:
            n += 1
            suffix = f"_{n}"
            candidate = base[: MAX_NAME_CHARS - len(suffix)] + suffix
        taken.add(candidate)
        out.append(candidate)
    return out


def result_text(result: CallToolResult) -> str:
    """Text for the model: text blocks joined, else structured content as
    JSON; ``Tool error: `` prefix for an error result; at most 8000 chars."""
    texts = [b.text for b in result.content if isinstance(b, TextContent)]
    if texts:
        body = "\n".join(texts)
    elif result.structuredContent is not None:
        body = json.dumps(result.structuredContent)
    else:
        body = ""
    if result.isError:
        body = f"Tool error: {body}"
    return body[:MAX_RESULT_CHARS]


def url_display(url: str) -> str:
    """scheme://host[:port]/path, without credentials or a query string."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port is not None:
            host = f"{host}:{parts.port}"
    except ValueError:
        return "<malformed url>"
    return f"{parts.scheme}://{host}{parts.path}"


class McpToolkit:
    """LangChain tools over open MCP sessions plus a names-only call log."""

    def __init__(self) -> None:
        self._closing = asyncio.Event()
        self._keeper: asyncio.Task[None] | None = None
        self._tools: list[BaseTool] = []
        self._real_names: dict[str, str] = {}
        self._calls: list[ToolCallRecord] = []
        self.collisions: list[ToolCollision] = []

    @property
    def tools(self) -> list[BaseTool]:
        return list(self._tools)

    @property
    def calls(self) -> list[ToolCallRecord]:
        return list(self._calls)

    @property
    def call_count(self) -> int:
        return len(self._calls)

    def real_name(self, exposed_name: str) -> str:
        return self._real_names[exposed_name]

    def _add_tools(self, entries: list[tuple[ClientSession, Tool]]) -> None:
        exposed = sanitise_tool_names([tool.name for _, tool in entries])
        for name, (session, tool) in zip(exposed, entries, strict=True):
            self._real_names[name] = tool.name
            self._tools.append(
                StructuredTool(
                    name=name,
                    description=tool.description or "",
                    args_schema=dict(tool.inputSchema),
                    coroutine=self._caller(session, tool.name),
                )
            )

    def _caller(
        self, session: ClientSession, real_name: str
    ) -> Callable[..., Awaitable[str]]:
        async def call(**arguments: Any) -> str:
            try:
                result = await session.call_tool(real_name, arguments=arguments)
            except Exception as exc:  # noqa: BLE001 - shown to the model as text
                self._calls.append(ToolCallRecord(real_name, False))
                return f"Tool error: the call failed ({type(exc).__name__})"
            self._calls.append(ToolCallRecord(real_name, not result.isError))
            return result_text(result)

        return call

    async def close(self) -> None:
        """Close every session. Idempotent; safe from any task."""
        self._closing.set()
        if self._keeper is not None:
            await self._keeper

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()


async def _resolve_tokens(
    urls: Sequence[str], token_provider: TokenProvider | None
) -> dict[str, str | None]:
    """The bearer token for each URL, fetched once per connect."""
    token = await token_provider() if token_provider is not None else None
    return dict.fromkeys(urls, token)


def _auth_headers(token: str | None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"} if token else {}


async def _http_streams(
    stack: AsyncExitStack, url: str, headers: dict[str, str]
) -> tuple[Any, Any]:
    """Streamable HTTP streams: ``streamable_http_client`` in mcp>=1.24,
    the deprecated ``streamablehttp_client`` on older releases."""
    from mcp.client import streamable_http

    new_client = getattr(streamable_http, "streamable_http_client", None)
    if new_client is not None:
        from mcp.shared._httpx_utils import create_mcp_http_client

        client = await stack.enter_async_context(
            create_mcp_http_client(headers=headers)
        )
        read, write, _ = await stack.enter_async_context(
            new_client(url, http_client=client)
        )
        return read, write
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old = streamable_http.streamablehttp_client(url, headers=headers)
    read, write, _ = await stack.enter_async_context(old)
    return read, write


async def _list_all_tools(session: ClientSession) -> list[Tool]:
    tools: list[Tool] = []
    cursor: str | None = None
    seen: set[str] = set()
    for _ in range(MAX_TOOL_PAGES):
        params = PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await session.list_tools(params=params)
        tools.extend(page.tools)
        cursor = page.nextCursor
        if not cursor:
            return tools
        if cursor in seen:
            raise RuntimeError("the server repeated a tools/list cursor")
        seen.add(cursor)
    raise RuntimeError(f"tools/list did not finish within {MAX_TOOL_PAGES} pages")


def _leaf(exc: BaseException) -> BaseException:
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


async def _open(
    stack: AsyncExitStack, url: str, headers: dict[str, str]
) -> tuple[ClientSession, list[Tool]]:
    """Open, initialize and list one server. Its transport is torn down here
    on failure (so the error surfaces as one ConnectionError), and handed to
    ``stack`` on success."""
    try:
        async with AsyncExitStack() as url_stack:
            read, write = await _http_streams(url_stack, url, headers)
            session = await url_stack.enter_async_context(
                ClientSession(read, write, read_timeout_seconds=_READ_TIMEOUT)
            )
            await session.initialize()
            listed = await _list_all_tools(session)
            stack.push_async_callback(url_stack.pop_all().aclose)
    except Exception as exc:  # CancelledError is not an Exception
        raise ConnectionError(
            f"cannot connect to MCP server {url_display(url)} "
            f"({type(_leaf(exc)).__name__})"
        ) from exc
    return session, listed


async def connect(
    mcp_urls: Sequence[str] | str, token_provider: TokenProvider | None
) -> McpToolkit:
    """Open one streamable-HTTP session per URL and expose their tools.

    When two servers list the same tool name the first is kept and the clash
    is recorded in ``toolkit.collisions``. A server that cannot be reached
    raises ``ConnectionError`` naming the URL (never headers or tokens).
    """
    urls = [mcp_urls] if isinstance(mcp_urls, str) else list(mcp_urls)
    tokens = await _resolve_tokens(urls, token_provider)
    toolkit = McpToolkit()
    ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def keep_open() -> None:
        # Transports use anyio task groups, which must be entered and exited
        # in one task: this one, for the toolkit's whole life.
        try:
            async with AsyncExitStack() as stack:
                entries: list[tuple[ClientSession, Tool]] = []
                owner: dict[str, str] = {}
                for url in urls:
                    session, listed = await _open(
                        stack, url, _auth_headers(tokens[url])
                    )
                    for tool in listed:
                        if tool.name in owner:
                            toolkit.collisions.append(
                                ToolCollision(tool.name, owner[tool.name], url)
                            )
                            continue
                        owner[tool.name] = url
                        entries.append((session, tool))
                toolkit._add_tools(entries)
                ready.set_result(None)
                await toolkit._closing.wait()
        except Exception as exc:  # noqa: BLE001 - handed to connect()
            if not ready.done():
                ready.set_exception(exc)
            # After a successful start, a transport failing at teardown or
            # mid-episode surfaces to the agent as tool errors; nothing to do.
        except BaseException:
            if not ready.done():
                ready.cancel()
            raise

    toolkit._keeper = asyncio.create_task(keep_open())
    try:
        await asyncio.shield(ready)
    except BaseException:
        toolkit._keeper.cancel()
        await asyncio.gather(toolkit._keeper, return_exceptions=True)
        raise
    return toolkit
