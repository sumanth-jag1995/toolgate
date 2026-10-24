"""Outbound client for the mock enterprise API.

MCP servers never forward the inbound token: they authenticate to the API with
their own client-credentials token (see ClientCredentialsTokenProvider).
"""

import asyncio
import functools
import inspect
import time
from collections.abc import Callable
from typing import Any, Protocol

import httpx
from mcp.server.fastmcp.exceptions import ToolError

UNAVAILABLE = "enterprise API unavailable"
_TOKEN_REFRESH_MARGIN_S = 30


class ApiError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


class TokenProvider(Protocol):
    async def token(self) -> str: ...


class StaticTokenProvider:
    """Fixed bearer token (tests)."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def token(self) -> str:
        return self._token


class ClientCredentialsTokenProvider:
    """OAuth2 client-credentials token, cached until 30 s before expiry."""

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        scope: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        self._http = httpx.AsyncClient(transport=transport)
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._refresh_at = 0.0

    async def token(self) -> str:
        async with self._lock:
            if self._token is None or time.monotonic() >= self._refresh_at:
                await self._fetch()
            assert self._token is not None
            return self._token

    async def _fetch(self) -> None:
        try:
            form = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
            if self._scope:
                form["scope"] = self._scope
            resp = await self._http.post(self._token_url, data=form)
            resp.raise_for_status()
            body = resp.json()
            token, expires_in = str(body["access_token"]), int(body["expires_in"])
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise ApiError(503, UNAVAILABLE) from None
        self._token = token
        self._refresh_at = time.monotonic() + expires_in - _TOKEN_REFRESH_MARGIN_S

    async def aclose(self) -> None:
        await self._http.aclose()


def _detail_text(resp: httpx.Response) -> str:
    try:
        detail = resp.json().get("detail")
    except (ValueError, AttributeError):
        detail = None
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):  # FastAPI/pydantic validation errors
        parts = []
        for err in detail:
            if isinstance(err, dict):
                loc = [
                    str(p)
                    for p in err.get("loc", [])
                    if p not in ("body", "query", "path")
                ]
                msg = str(err.get("msg", "invalid value"))
                parts.append(f"{'.'.join(loc)}: {msg}" if loc else msg)
        if parts:
            return "; ".join(parts)
    return resp.reason_phrase or "error"


class ApiClient:
    def __init__(
        self,
        base_url: str,
        token_provider: TokenProvider,
        *,
        timeout_s: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._token_provider = token_provider
        self._timeout_s = timeout_s
        self._http = httpx.AsyncClient(
            base_url=base_url, timeout=timeout_s, transport=transport
        )

    async def get(self, path: str, params: dict | None = None) -> Any:
        return await self._request("GET", path, params=params)

    async def post(self, path: str, json: dict, idempotency_key: str) -> Any:
        return await self._request(
            "POST", path, json=json, headers={"Idempotency-Key": idempotency_key}
        )

    async def put(self, path: str, json: dict, idempotency_key: str) -> Any:
        return await self._request(
            "PUT", path, json=json, headers={"Idempotency-Key": idempotency_key}
        )

    async def _request(
        self, method: str, path: str, *, headers: dict | None = None, **kwargs: Any
    ) -> Any:
        try:
            # Overall deadline (token fetch + request), independent of transport.
            async with asyncio.timeout(self._timeout_s):
                token = await self._token_provider.token()
                resp = await self._http.request(
                    method,
                    path,
                    headers={**(headers or {}), "Authorization": f"Bearer {token}"},
                    **kwargs,
                )
        except (TimeoutError, httpx.TransportError):
            raise ApiError(503, UNAVAILABLE) from None
        if not resp.is_success:
            raise ApiError(resp.status_code, _detail_text(resp))
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            raise ApiError(503, UNAVAILABLE) from None

    async def aclose(self) -> None:
        await self._http.aclose()


def _tool_message(err: ApiError) -> str:
    match err.status:
        case 404:
            return err.detail or "resource not found"
        case 409:
            return "idempotency key reused with different arguments"
        case 422:
            return f"invalid request: {err.detail}"
        case 403:
            return "not permitted"
        case _:
            return "enterprise API unavailable, retry later"


class api_errors_to_tool_errors:
    """Convert ApiError into an MCP ToolError with a client-safe message.

    Usage: ``with api_errors_to_tool_errors(): ...`` or as a decorator
    ``@api_errors_to_tool_errors()`` on sync or async tool functions.
    """

    def __enter__(self) -> None:
        return None

    def __exit__(self, exc_type, exc, tb) -> bool:
        if isinstance(exc, ApiError):
            raise ToolError(_tool_message(exc)) from None
        return False

    def __call__(self, fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                with api_errors_to_tool_errors():
                    return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with api_errors_to_tool_errors():
                return fn(*args, **kwargs)

        return wrapper
