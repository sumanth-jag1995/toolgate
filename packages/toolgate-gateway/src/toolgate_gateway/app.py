"""The gateway's MCP endpoint: one authenticated streamable-HTTP server at /mcp.

The wiring mirrors mcp 1.30's ``FastMCP.streamable_http_app()`` for a
low-level ``Server``: ``AuthenticationMiddleware(BearerAuthBackend)`` and
``AuthContextMiddleware`` on the app, ``RequireAuthMiddleware`` (with the RFC
9728 ``resource_metadata`` link) around the session manager, and the
protected-resource metadata route. Every SDK-internal detail lives in this
file.

The tools/list and tools/call handlers are registered in
``Server.request_handlers`` directly rather than through the decorators: the
``call_tool`` decorator consults a tool cache shared by every caller and, on
a miss, re-runs tools/list (a full downstream refresh) and validates
arguments itself, echoing the failing value in its error. GatewayCore owns
listing, validation and errors, so the handlers only resolve the caller and
delegate.

The agent's bearer token is used only to identify the caller (client id and
subject). It is never logged, put in an error, or passed to the core.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.auth.middleware.auth_context import (
    AuthContextMiddleware,
    get_access_token,
)
from mcp.server.auth.middleware.bearer_auth import (
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.routes import (
    build_resource_metadata_url,
    create_protected_resource_routes,
)
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import McpError
from mcp.types import (
    INTERNAL_ERROR,
    CallToolRequest,
    CallToolResult,
    ErrorData,
    ListToolsRequest,
    ListToolsResult,
    ServerResult,
    TextContent,
)
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from toolgate_gateway.core import GatewayCore
from toolgate_gateway.settings import GatewaySettings

log = logging.getLogger(__name__)

SERVER_NAME = "toolgate-gateway"
MCP_PATH = "/mcp"

_UNAUTHENTICATED = "unauthenticated"
_INTERNAL = "internal gateway error; call failed"


class _SessionManagerApp:
    """ASGI endpoint handing each request to the session manager (as
    FastMCP's ``StreamableHTTPASGIApp`` does)."""

    def __init__(self, manager: StreamableHTTPSessionManager) -> None:
        self._manager = manager

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._manager.handle_request(scope, receive, send)


def _error(message: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=message)], isError=True
    )


def build_server(core: GatewayCore) -> Server:
    """The low-level MCP server: tools/list and tools/call via ``core``,
    as the authenticated caller."""
    server: Server = Server(SERVER_NAME)

    async def list_tools(req: ListToolsRequest) -> ServerResult:
        token = get_access_token()
        if token is None:  # unreachable behind RequireAuthMiddleware
            return ServerResult(ListToolsResult(tools=[]))
        try:
            tools = await core.list_tools(token.client_id)
        except Exception as exc:  # noqa: BLE001 - fixed message, type logged
            log.warning(
                "tools/list for %s failed (%s)", token.client_id, type(exc).__name__
            )
            raise McpError(
                ErrorData(code=INTERNAL_ERROR, message="tools/list failed")
            ) from None
        return ServerResult(ListToolsResult(tools=tools))

    async def call_tool(req: CallToolRequest) -> ServerResult:
        token = get_access_token()
        if token is None:  # unreachable behind RequireAuthMiddleware
            return ServerResult(_error(_UNAUTHENTICATED))
        agent_id = token.subject or token.client_id
        try:
            result = await core.call_tool(
                token.client_id, agent_id, req.params.name, req.params.arguments
            )
        except Exception as exc:  # noqa: BLE001 - fixed message, type logged
            log.warning(
                "tools/call for %s failed (%s)", token.client_id, type(exc).__name__
            )
            result = _error(_INTERNAL)
        return ServerResult(result)

    server.request_handlers[ListToolsRequest] = list_tools
    server.request_handlers[CallToolRequest] = call_tool
    return server


def build_app(
    core: GatewayCore, verifier: TokenVerifier, settings: GatewaySettings
) -> Starlette:
    server = build_server(core)
    manager = StreamableHTTPSessionManager(
        app=server,
        event_store=None,
        json_response=False,
        stateless=False,
        security_settings=None,
    )

    resource_url = AnyHttpUrl(settings.public_url.rstrip("/") + MCP_PATH)
    metadata_url = build_resource_metadata_url(resource_url)

    routes = [
        Route(
            MCP_PATH,
            endpoint=RequireAuthMiddleware(
                _SessionManagerApp(manager), [], metadata_url
            ),
        ),
        *create_protected_resource_routes(
            resource_url=resource_url,
            authorization_servers=[AnyHttpUrl(settings.issuer)],
        ),
    ]
    middleware = [
        # The verifier checks aud itself (AccessToken.resource is the
        # audience, not a URL), so no resource_server_url here.
        Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(verifier)),
        Middleware(AuthContextMiddleware),
    ]

    async def on_list_changed(server_id: str) -> None:
        await core.refresh_snapshot()

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        await core.audit.start()
        try:
            await core.pool.start()  # a down downstream is logged, not fatal
            try:
                core.pool.on_list_changed = on_list_changed
                try:
                    await core.refresh_snapshot()
                except Exception as exc:  # noqa: BLE001 - serve anyway
                    log.warning("startup refresh failed (%s)", type(exc).__name__)
                async with manager.run():
                    yield
            finally:
                core.pool.on_list_changed = None
                await core.pool.close()
        finally:
            await core.audit.stop()

    return Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
