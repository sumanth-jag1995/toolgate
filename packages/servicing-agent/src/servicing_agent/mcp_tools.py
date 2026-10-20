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
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Literal, Self
from urllib.parse import urlsplit

from langchain_core.tools import BaseTool
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
    """Two tools competing for one name.

    ``kind="name"``: both servers list the same MCP name; the first is kept
    and the tool from ``dropped_url`` is not exposed. ``kind="sanitised"``:
    distinct MCP names that sanitise to the same model-facing name; both are
    exposed, and ``name`` (from ``dropped_url``) gets a ``_2``-style suffix
    while the tool from ``kept_url`` keeps the plain sanitised name.
    """

    name: str
    kept_url: str
    dropped_url: str
    kind: Literal["name", "sanitised"] = "name"


def _sanitise(name: str) -> str:
    return _UNSAFE_NAME_CHARS.sub("_", name)[:MAX_NAME_CHARS] or "tool"


def sanitise_tool_names(names: Sequence[str]) -> list[str]:
    """Model-facing names: characters outside ``[a-zA-Z0-9_-]`` become ``_``,
    at most 64 characters, de-duplicated in order with ``_2``, ``_3``..."""
    out: list[str] = []
    taken: set[str] = set()
    for name in names:
        base = _sanitise(name)
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


class McpTool(BaseTool):
    """One MCP tool. The model's argument dict is passed to ``call_tool``
    whole and untouched: it is never spread into Python keyword arguments,
    so names such as ``self``, ``config`` or ``run_manager`` cannot collide
    with LangChain's own parameters."""

    mcp_call: Callable[[dict[str, Any]], Awaitable[str]]

    def _to_args_and_kwargs(
        self, tool_input: str | dict[str, Any], tool_call_id: str | None
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        if not isinstance(tool_input, dict):
            raise TypeError("tool arguments must be a JSON object")
        return (dict(tool_input),), {}

    def _run(self, *args: Any, **kwargs: Any) -> str:
        raise NotImplementedError("MCP tools are async only")

    async def _arun(self, *args: Any, **kwargs: Any) -> str:
        return await self.mcp_call(args[0])


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

    def _add_tools(self, entries: list[tuple[str, ClientSession, Tool]]) -> None:
        exposed = sanitise_tool_names([tool.name for _, _, tool in entries])
        url_of: dict[str, str] = {}
        for name, (url, session, tool) in zip(exposed, entries, strict=True):
            base = _sanitise(tool.name)
            if name != base:
                self.collisions.append(
                    ToolCollision(tool.name, url_of[base], url, kind="sanitised")
                )
            url_of[name] = url
            self._real_names[name] = tool.name
            self._tools.append(
                McpTool(
                    name=name,
                    description=tool.description or "",
                    args_schema=dict(tool.inputSchema),
                    mcp_call=self._caller(session, tool.name),
                )
            )

    def _caller(
        self, session: ClientSession, real_name: str
    ) -> Callable[[dict[str, Any]], Awaitable[str]]:
        async def call(arguments: dict[str, Any]) -> str:
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
        keeper = self._keeper
        if keeper is None:
            return
        if not keeper.done():
            # wait() neither raises the keeper's outcome nor cancels it if
            # this task is cancelled meanwhile.
            await asyncio.wait({keeper})
        if not keeper.cancelled():
            keeper.exception()  # mark retrieved; keep_open swallows errors

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()


async def _resolve_tokens(
    urls: Sequence[str],
    token_provider: TokenProvider | None,
    token_providers: Mapping[str, TokenProvider | None] | None = None,
) -> dict[str, str | None]:
    """The bearer token for each URL. A URL in ``token_providers`` uses that
    provider (``None``: no token); any other URL uses ``token_provider``.
    Each distinct provider is called once per connect."""
    chosen: dict[str, TokenProvider | None] = {
        url: (
            token_providers[url]
            if token_providers is not None and url in token_providers
            else token_provider
        )
        for url in urls
    }
    distinct = {id(p): p for p in chosen.values() if p is not None}
    fetched = {key: await provider() for key, provider in distinct.items()}
    return {
        url: (fetched[id(provider)] if provider is not None else None)
        for url, provider in chosen.items()
    }


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
    mcp_urls: Sequence[str] | str,
    token_provider: TokenProvider | None,
    *,
    token_providers: Mapping[str, TokenProvider | None] | None = None,
) -> McpToolkit:
    """Open one streamable-HTTP session per URL and expose their tools.

    ``token_providers`` maps a URL to its own provider (``None`` for a URL
    that gets no bearer token) and takes precedence over ``token_provider``,
    which applies to every URL not in the mapping.

    When two servers list the same tool name the first is kept and the clash
    is recorded in ``toolkit.collisions``. A server that cannot be reached
    raises ``ConnectionError`` naming the URL (never headers or tokens).
    """
    urls = [mcp_urls] if isinstance(mcp_urls, str) else list(mcp_urls)
    tokens = await _resolve_tokens(urls, token_provider, token_providers)
    toolkit = McpToolkit()
    ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()

    async def keep_open() -> None:
        # Transports use anyio task groups, which must be entered and exited
        # in one task: this one, for the toolkit's whole life.
        try:
            async with AsyncExitStack() as stack:
                entries: list[tuple[str, ClientSession, Tool]] = []
                owner: dict[str, str] = {}
                for url in urls:
                    session, listed = await _open(
                        stack, url, _auth_headers(tokens[url])
                    )
                    for tool in listed:
                        if tool.name in owner:
                            toolkit.collisions.append(
                                ToolCollision(
                                    tool.name, owner[tool.name], url, kind="name"
                                )
                            )
                            continue
                        owner[tool.name] = url
                        entries.append((url, session, tool))
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
