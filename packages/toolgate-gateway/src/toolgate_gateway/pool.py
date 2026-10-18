"""DownstreamPool: one persistent MCP ClientSession per downstream server.

Each session's context (transport + ClientSession, inside the factory's
AsyncExitStack) is entered and exited by a dedicated background task per
server, because anyio cancel scopes must be exited in the task that entered
them. Requests only use the session object. When a request finds the session
broken, it drops the session by telling that task to exit; the next list or
call reconnects.

Log lines carry server ids and exception *types* only: exception messages
from the transport may echo URLs or headers.
"""

from __future__ import annotations

import asyncio
import logging
import warnings
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine, Iterable
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Protocol

import anyio
import anyio.lowlevel
import httpx
from mcp.client.session import ClientSession, MessageHandlerFnT
from mcp.shared.exceptions import McpError
from mcp.types import (
    CONNECTION_CLOSED,
    CallToolResult,
    Implementation,
    InitializeResult,
    ServerNotification,
    Tool,
    ToolListChangedNotification,
)
from toolgate_pin.connect import list_all_tools

from toolgate_gateway.downstreams import DownstreamConfig

log = logging.getLogger(__name__)

ServerInfo = Implementation
SessionContext = AbstractAsyncContextManager[tuple[ClientSession, InitializeResult]]

# Errors that mean the session (or its transport) is gone, not that the
# downstream answered a request with an error.
_BROKEN = (
    anyio.ClosedResourceError,
    anyio.BrokenResourceError,
    anyio.EndOfStream,
    OSError,
    httpx.HTTPError,
)


class SessionFactory(Protocol):
    """Opens a connected, initialized session. ``message_handler`` must be
    passed to the ClientSession so server notifications reach the pool."""

    def __call__(
        self,
        config: DownstreamConfig,
        *,
        message_handler: MessageHandlerFnT | None = None,
    ) -> SessionContext: ...


class DownstreamUnavailable(Exception):
    """The downstream could not be reached, timed out, or its session closed.
    The message names the server only."""

    def __init__(self, server_id: str) -> None:
        super().__init__(f"downstream {server_id} is unavailable")
        self.server_id = server_id


# 30 s for connect/write/pool; 300 s read so the SDK's idle GET SSE stream
# (server-initiated notifications such as list_changed) is not torn down.
# Per-request bounds are enforced by the pool with asyncio timeouts.
HTTP_TIMEOUT = httpx.Timeout(30.0, read=300.0)


def _http_client(
    auth: httpx.Auth | None, headers: dict[str, str] | None = None
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers=headers, auth=auth, timeout=HTTP_TIMEOUT, follow_redirects=False
    )


def http_session_factory(auth: httpx.Auth) -> SessionFactory:
    """Production factory: streamable HTTP with ``auth`` on every request,
    HTTP_TIMEOUT and no redirect following. Works on mcp 1.12-1.30."""

    def _old_api_client(
        headers: dict[str, str] | None = None,
        timeout: Any = None,  # ignored: HTTP_TIMEOUT always applies
        auth: httpx.Auth | None = auth,
    ) -> httpx.AsyncClient:
        return _http_client(auth, headers)

    @asynccontextmanager
    async def factory(
        config: DownstreamConfig,
        *,
        message_handler: MessageHandlerFnT | None = None,
    ) -> AsyncIterator[tuple[ClientSession, InitializeResult]]:
        from mcp.client import streamable_http

        async with AsyncExitStack() as stack:
            new_client = getattr(streamable_http, "streamable_http_client", None)
            if new_client is not None:  # mcp >= 1.24
                client = await stack.enter_async_context(_http_client(auth))
                read, write, _ = await stack.enter_async_context(
                    new_client(config.url, http_client=client)
                )
            else:  # pragma: no cover - older mcp releases only
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    old = streamable_http.streamablehttp_client(
                        config.url, auth=auth, httpx_client_factory=_old_api_client
                    )
                read, write, _ = await stack.enter_async_context(old)
            session = await stack.enter_async_context(
                ClientSession(read, write, message_handler=message_handler)
            )
            init = await session.initialize()
            yield session, init

    return factory


@dataclass(eq=False)
class _Conn:
    session: ClientSession
    init: InitializeResult
    # Set when the session is dropped, the pool closes, or the holder task
    # ends (session crashed). In-flight requests wait on it to fail fast.
    stop: asyncio.Event
    task: asyncio.Task[None] = field(repr=False)

    @property
    def alive(self) -> bool:
        return not self.task.done() and not self.stop.is_set()


class _Dropped(Exception):
    """The connection was stopped while a request was in flight."""


def _reap(task: asyncio.Future[Any]) -> None:
    """Mark a task's outcome as retrieved so nothing logs 'never retrieved'."""
    task.add_done_callback(lambda t: t.cancelled() or t.exception())


class DownstreamPool:
    def __init__(
        self,
        configs: Iterable[DownstreamConfig],
        factory: SessionFactory,
        *,
        call_timeout_s: float = 30.0,
    ) -> None:
        self._configs = {c.server_id: c for c in configs}
        self._factory = factory
        self._timeout = call_timeout_s
        self._conns: dict[str, _Conn] = {}
        # One in-flight connect per server, shared by every waiting request.
        self._connecting: dict[str, asyncio.Future[_Conn | None]] = {}
        self._tasks: set[asyncio.Task[Any]] = set()  # holders, connectors, callbacks
        self._closed = False
        self.on_list_changed: Callable[[str], Awaitable[None]] | None = None

    # -- lifecycle ---------------------------------------------------------

    async def start(self) -> None:
        """Connect every server; failures are logged and skipped."""

        async def one(sid: str) -> None:
            try:
                await self._get(sid, self._deadline())
            except DownstreamUnavailable:
                pass  # already logged

        await asyncio.gather(*(one(sid) for sid in self._configs))

    async def close(self) -> None:
        """Stop every session and wait (bounded) for all background tasks,
        including ones started while closing."""
        self._closed = True
        loop = asyncio.get_running_loop()
        deadline = self._deadline()
        while True:
            for conn in self._conns.values():
                conn.stop.set()
            self._conns.clear()
            for t in self._tasks:
                if t.get_name().startswith(("connect-", "callback-")):
                    t.cancel()
            if not self._tasks:
                return
            remaining = deadline - loop.time()
            if remaining <= 0:
                for t in self._tasks:
                    t.cancel()
                await asyncio.wait(set(self._tasks), timeout=1.0)
                return
            await asyncio.wait(
                set(self._tasks), timeout=remaining, return_when="FIRST_COMPLETED"
            )

    # -- requests ----------------------------------------------------------

    async def list_tools(self, server_id: str) -> tuple[ServerInfo, list[Tool]] | None:
        """``(serverInfo, tools)``, or None when the server is down."""
        deadline = self._deadline()
        try:
            conn = await self._get(server_id, deadline)
        except DownstreamUnavailable:
            return None
        try:
            async with asyncio.timeout_at(deadline):
                tools = await self._run(conn, list_all_tools(conn.session))
        except Exception as exc:  # noqa: BLE001 - any failure means "down"
            # Timeouts, closed sessions, JSON-RPC errors and ToolListError:
            # for listing, a misbehaving server is treated as down.
            self._fail("tools/list", server_id, conn, exc)
            return None
        return conn.init.serverInfo, tools

    async def call_tool(
        self, server_id: str, name: str, arguments: dict[str, Any] | None
    ) -> CallToolResult:
        """Forward one call within ``call_timeout_s`` (connect included).

        Raises DownstreamUnavailable on connect failure, timeout or a closed
        session (and drops the session). A JSON-RPC error from a live server
        propagates as McpError, keeping the session. The caller's
        cancellation propagates and keeps the session."""
        deadline = self._deadline()
        conn = await self._get(server_id, deadline)
        try:
            async with asyncio.timeout_at(deadline):
                return await self._run(conn, conn.session.call_tool(name, arguments))
        except McpError as exc:
            if exc.error.code != CONNECTION_CLOSED:
                raise
            failure: Exception = exc
        except (TimeoutError, _Dropped, *_BROKEN) as exc:
            failure = exc
        self._fail("tools/call", server_id, conn, failure)
        raise DownstreamUnavailable(server_id) from None

    def _fail(self, what: str, server_id: str, conn: _Conn, exc: Exception) -> None:
        log.warning(
            "%s on downstream %s failed (%s)", what, server_id, type(exc).__name__
        )
        self._drop(server_id, conn)

    async def _run[T](self, conn: _Conn, coro: Awaitable[T]) -> T:
        """Run one request in a child task, failing fast with _Dropped when
        the connection stops (mcp cannot always wake pending waiters)."""
        child = asyncio.ensure_future(coro)
        _reap(child)
        stopped = asyncio.ensure_future(conn.stop.wait())
        try:
            await asyncio.wait({child, stopped}, return_when="FIRST_COMPLETED")
        except BaseException:  # caller cancelled or timed out
            child.cancel()
            raise
        finally:
            stopped.cancel()
        if child.done():
            return child.result()
        child.cancel()
        raise _Dropped

    # -- sessions ----------------------------------------------------------

    def _deadline(self) -> float:
        return asyncio.get_running_loop().time() + self._timeout

    async def _get(self, server_id: str, deadline: float) -> _Conn:
        """The live session, or wait (until ``deadline``) for the one shared
        connect attempt. Raises DownstreamUnavailable."""
        if self._closed or server_id not in self._configs:
            raise DownstreamUnavailable(server_id)
        conn = self._conns.get(server_id)
        if conn is not None and conn.alive:
            return conn
        self._conns.pop(server_id, None)
        fut = self._connecting.get(server_id)
        if fut is None:
            fut = asyncio.get_running_loop().create_future()
            self._connecting[server_id] = fut
            self._spawn(self._connect_shared(server_id, fut), f"connect-{server_id}")
        try:
            async with asyncio.timeout_at(deadline):
                conn = await asyncio.shield(fut)
        except TimeoutError:
            conn = None
        if conn is None:
            raise DownstreamUnavailable(server_id)
        return conn

    async def _connect_shared(
        self, server_id: str, fut: asyncio.Future[_Conn | None]
    ) -> None:
        conn: _Conn | None = None
        try:
            conn = await self._connect(self._configs[server_id])
        except DownstreamUnavailable:
            pass
        finally:
            if self._connecting.get(server_id) is fut:
                del self._connecting[server_id]
            if conn is not None and self._closed:
                conn.stop.set()
                conn = None
            if conn is not None:
                self._conns[server_id] = conn
            if not fut.done():
                fut.set_result(conn)

    async def _connect(self, config: DownstreamConfig) -> _Conn:
        loop = asyncio.get_running_loop()
        ready: asyncio.Future[tuple[ClientSession, InitializeResult]] = (
            loop.create_future()
        )
        _reap(ready)
        stop = asyncio.Event()
        task = self._spawn(
            self._hold(config, ready, stop), f"holder-{config.server_id}"
        )
        try:
            async with asyncio.timeout(self._timeout):
                session, init = await asyncio.shield(ready)
        except BaseException as exc:
            stop.set()
            if not ready.done():
                ready.cancel()
                task.cancel()  # abandon a hung connect; the holder exits
            if isinstance(exc, asyncio.CancelledError):
                raise
            log.warning(
                "cannot connect to downstream %s (%s)",
                config.server_id,
                type(exc).__name__,
            )
            raise DownstreamUnavailable(config.server_id) from None
        return _Conn(session, init, stop, task)

    async def _hold(
        self,
        config: DownstreamConfig,
        ready: asyncio.Future[tuple[ClientSession, InitializeResult]],
        stop: asyncio.Event,
    ) -> None:
        """Own one session's context from enter to exit, in this task."""
        handler = self._message_handler(config.server_id)
        try:
            async with self._factory(config, message_handler=handler) as pair:
                if ready.done():  # the connecting request gave up
                    return
                ready.set_result(pair)
                await stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(
                    exc if isinstance(exc, Exception) else ConnectionError()
                )
            elif not isinstance(exc, asyncio.CancelledError):
                log.info(
                    "downstream %s session ended (%s)",
                    config.server_id,
                    type(exc).__name__,
                )
            if isinstance(exc, asyncio.CancelledError):
                raise
        finally:
            stop.set()

    def _drop(self, server_id: str, conn: _Conn) -> None:
        if self._conns.get(server_id) is conn:
            del self._conns[server_id]
        conn.stop.set()

    def _spawn(self, coro: Coroutine[Any, Any, None], name: str) -> asyncio.Task[None]:
        task = asyncio.create_task(coro, name=name)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def _message_handler(self, server_id: str) -> MessageHandlerFnT:
        async def handler(message: Any) -> None:
            if isinstance(message, ServerNotification) and isinstance(
                message.root, ToolListChangedNotification
            ):
                self._schedule_list_changed(server_id)
            await anyio.lowlevel.checkpoint()

        return handler

    def _schedule_list_changed(self, server_id: str) -> None:
        callback = self.on_list_changed
        if callback is None or self._closed:
            return

        async def run() -> None:
            try:
                await callback(server_id)
            except Exception as exc:  # noqa: BLE001 - never kill the session
                log.warning(
                    "list_changed callback for %s failed (%s)",
                    server_id,
                    type(exc).__name__,
                )

        # Never block the session's receive loop on the callback.
        self._spawn(run(), f"callback-{server_id}")
