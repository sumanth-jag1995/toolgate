import asyncio
import json
import time
from urllib.parse import parse_qs

import httpx
import pytest
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from toolgate_mcp_servers.api_client import (
    ApiClient,
    ApiError,
    ClientCredentialsTokenProvider,
    StaticTokenProvider,
    api_errors_to_tool_errors,
)

TOKEN_URL = "http://keycloak.test/realms/toolgate/protocol/openid-connect/token"
BASE = "http://mock-api.test"


def _token_transport(calls: list, expires_in: int = 300) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(parse_qs(request.content.decode()))
        return httpx.Response(
            200, json={"access_token": f"tok-{len(calls)}", "expires_in": expires_in}
        )

    return httpx.MockTransport(handler)


def _api_transport(seen: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(handler)


async def _slow(request: httpx.Request) -> httpx.Response:
    await asyncio.sleep(1)
    return httpx.Response(200, json={})


async def test_token_cached_until_near_expiry():
    token_calls, api_requests = [], []
    provider = ClientCredentialsTokenProvider(
        TOKEN_URL, "core-read", "s3cret", transport=_token_transport(token_calls)
    )
    client = ApiClient(BASE, provider, transport=_api_transport(api_requests))
    assert await client.get("/members/M-1") == {"ok": True}
    assert await client.get("/members/M-2") == {"ok": True}
    assert len(token_calls) == 1
    assert token_calls[0] == {
        "grant_type": ["client_credentials"],
        "client_id": ["core-read"],
        "client_secret": ["s3cret"],
    }
    assert all(r.headers["Authorization"] == "Bearer tok-1" for r in api_requests)


async def test_token_refreshed_when_near_expiry():
    token_calls, api_requests = [], []
    provider = ClientCredentialsTokenProvider(
        TOKEN_URL,
        "core-read",
        "s3cret",
        transport=_token_transport(token_calls, expires_in=20),
    )
    client = ApiClient(BASE, provider, transport=_api_transport(api_requests))
    await client.get("/members/M-1")
    await client.get("/members/M-1")
    assert len(token_calls) == 2
    assert api_requests[1].headers["Authorization"] == "Bearer tok-2"


async def test_token_fetch_is_single_flight():
    token_calls = []

    async def handler(request: httpx.Request) -> httpx.Response:
        token_calls.append(request)
        await asyncio.sleep(0.05)
        return httpx.Response(200, json={"access_token": "t", "expires_in": 300})

    provider = ClientCredentialsTokenProvider(
        TOKEN_URL, "c", "s", transport=httpx.MockTransport(handler)
    )
    assert await asyncio.gather(*(provider.token() for _ in range(5))) == ["t"] * 5
    assert len(token_calls) == 1


async def test_token_endpoint_failure_maps_to_503():
    provider = ClientCredentialsTokenProvider(
        TOKEN_URL,
        "c",
        "s",
        transport=httpx.MockTransport(lambda r: httpx.Response(401, json={})),
    )
    client = ApiClient(BASE, provider, transport=_api_transport([]))
    with pytest.raises(ApiError) as exc:
        await client.get("/members/M-1")
    assert (exc.value.status, exc.value.detail) == (503, "enterprise API unavailable")


async def test_get_passes_params_and_returns_json():
    seen = []
    client = ApiClient(BASE, StaticTokenProvider("t"), transport=_api_transport(seen))
    assert await client.get("/claims", params={"member_id": "M-1"}) == {"ok": True}
    assert seen[0].url == httpx.URL(f"{BASE}/claims?member_id=M-1")
    assert seen[0].method == "GET"


async def test_404_maps_to_api_error():
    transport = httpx.MockTransport(
        lambda r: httpx.Response(404, json={"detail": "member not found"})
    )
    client = ApiClient(BASE, StaticTokenProvider("t"), transport=transport)
    with pytest.raises(ApiError) as exc:
        await client.get("/members/M-999999")
    assert (exc.value.status, exc.value.detail) == (404, "member not found")


async def test_422_list_detail_flattened():
    detail = [{"loc": ["body", "amount_pence"], "msg": "Input should be > 0"}]
    transport = httpx.MockTransport(
        lambda r: httpx.Response(422, json={"detail": detail})
    )
    client = ApiClient(BASE, StaticTokenProvider("t"), transport=transport)
    with pytest.raises(ApiError) as exc:
        await client.post("/claims", json={}, idempotency_key="k")
    assert exc.value.status == 422
    assert exc.value.detail == "amount_pence: Input should be > 0"


async def test_timeout_maps_to_503():
    client = ApiClient(
        BASE,
        StaticTokenProvider("t"),
        timeout_s=0.1,
        transport=httpx.MockTransport(_slow),
    )
    start = time.monotonic()
    with pytest.raises(ApiError) as exc:
        await client.get("/members/M-1")
    assert time.monotonic() - start < 0.5
    assert (exc.value.status, exc.value.detail) == (503, "enterprise API unavailable")


async def test_connect_error_maps_to_503():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = ApiClient(
        BASE, StaticTokenProvider("t"), transport=httpx.MockTransport(refuse)
    )
    with pytest.raises(ApiError) as exc:
        await client.get("/members/M-1")
    assert exc.value.status == 503


async def test_post_sends_idempotency_header():
    seen = []
    client = ApiClient(BASE, StaticTokenProvider("t"), transport=_api_transport(seen))
    await client.post("/claims", json={"a": 1}, idempotency_key="key-123")
    assert seen[0].method == "POST"
    assert seen[0].headers["Idempotency-Key"] == "key-123"
    assert json.loads(seen[0].content) == {"a": 1}


async def test_put_sends_idempotency_header():
    seen = []
    client = ApiClient(BASE, StaticTokenProvider("t"), transport=_api_transport(seen))
    await client.put("/members/M-1/contact", json={"b": 2}, idempotency_key="key-9")
    assert seen[0].method == "PUT"
    assert seen[0].headers["Idempotency-Key"] == "key-9"


@pytest.mark.parametrize(
    ("status", "detail", "message"),
    [
        (404, "claim not found", "claim not found"),
        (409, "conflict", "idempotency key reused with different arguments"),
        (422, "claim_id required for X", "invalid request: claim_id required for X"),
        (403, "missing scope: claims:write", "not permitted"),
        (401, "invalid token", "enterprise API unavailable, retry later"),
        (503, "enterprise API unavailable", "enterprise API unavailable, retry later"),
        (
            500,
            "boom at http://mock-api.test/x",
            "enterprise API unavailable, retry later",
        ),
    ],
)
def test_api_errors_to_tool_errors_messages(status, detail, message):
    with pytest.raises(ToolError) as exc, api_errors_to_tool_errors():
        raise ApiError(status, detail)
    assert str(exc.value) == message


async def test_api_errors_to_tool_errors_as_async_decorator():
    @api_errors_to_tool_errors()
    async def tool() -> str:
        raise ApiError(403, "missing scope")

    with pytest.raises(ToolError, match="^not permitted$"):
        await tool()


async def test_slow_api_yields_tool_error_result_not_hang():
    """Review Focus 5: an MCP tool call returns isError quickly when the API hangs."""
    api = ApiClient(
        BASE,
        StaticTokenProvider("t"),
        timeout_s=0.1,
        transport=httpx.MockTransport(_slow),
    )
    mcp = FastMCP("t")

    @mcp.tool()
    async def get_member_profile(member_id: str) -> dict:
        with api_errors_to_tool_errors():
            return await api.get(f"/members/{member_id}")

    start = time.monotonic()
    async with create_connected_server_and_client_session(mcp._mcp_server) as session:
        result = await session.call_tool("get_member_profile", {"member_id": "M-1"})
    assert time.monotonic() - start < 1
    assert result.isError is True
    text = result.content[0].text
    assert "enterprise API unavailable, retry later" in text
    assert "mock-api.test" not in text and "Bearer" not in text


async def test_token_request_includes_scope_only_when_set():
    calls: list = []
    provider = ClientCredentialsTokenProvider(
        TOKEN_URL,
        "core-read",
        "s3cret",
        scope="mock-enterprise/members:read",
        transport=_token_transport(calls),
    )
    await provider.token()
    assert calls == [
        {
            "grant_type": ["client_credentials"],
            "client_id": ["core-read"],
            "client_secret": ["s3cret"],
            "scope": ["mock-enterprise/members:read"],
        }
    ]


async def test_keycloak_provider_sends_no_scope():
    calls: list = []
    provider = ClientCredentialsTokenProvider(
        TOKEN_URL, "core-read", "s3cret", transport=_token_transport(calls)
    )
    await provider.token()
    assert calls == [
        {
            "grant_type": ["client_credentials"],
            "client_id": ["core-read"],
            "client_secret": ["s3cret"],
        }
    ]
