from collections.abc import Iterator
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_connected_server_and_client_session
from pydantic import BaseModel
from toolgate_mcp_servers.api_client import ApiClient, StaticTokenProvider
from toolgate_mcp_servers.app_factory import build_server
from toolgate_mcp_servers.auth import JwtTokenVerifier
from toolgate_mcp_servers.hardening import harden_schemas
from toolgate_mcp_servers.settings import ServerSettings


class Address(BaseModel):
    line1: str
    postcode: str


class Nested(BaseModel):
    name: str
    address: Address
    previous: list[Address] = []
    alt: Address | None = None


def tool_input_schema(mcp: FastMCP, name: str) -> dict[str, Any]:
    return mcp._tool_manager.get_tool(name).parameters


def iter_object_nodes(node: Any) -> Iterator[dict[str, Any]]:
    """Every dict that is an object schema (type object or has properties)."""
    if isinstance(node, dict):
        if node.get("type") == "object" or "properties" in node:
            yield node
        for value in node.values():
            yield from iter_object_nodes(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_object_nodes(item)


def test_harden_sets_additional_properties_false_recursively():
    mcp = FastMCP("t")

    @mcp.tool()
    def f(a: Nested, tags: list[Nested] | None = None) -> str:
        return "ok"

    harden_schemas(mcp)
    schema = tool_input_schema(mcp, "f")
    assert {"Nested", "Address"} <= set(schema["$defs"])
    nodes = list(iter_object_nodes(schema))
    assert len(nodes) >= 3  # root + Nested + Address
    assert all(node.get("additionalProperties") is False for node in nodes)


def test_harden_handles_inline_nested_objects_and_combinators():
    mcp = FastMCP("t")

    @mcp.tool()
    def g(x: int) -> str:
        return "ok"

    # Hand-written schema with inline objects reached via every keyword.
    tool = mcp._tool_manager.get_tool("g")
    tool.parameters = {
        "type": "object",
        "properties": {
            "p": {"type": "object", "properties": {"q": {"type": "string"}}},
            "arr": {"type": "array", "items": {"type": "object", "properties": {}}},
            "any": {"anyOf": [{"type": "object", "properties": {}}, {"type": "null"}]},
            "one": {"oneOf": [{"type": "object", "properties": {}}]},
            "all": {"allOf": [{"type": "object", "properties": {}}]},
        },
        "$defs": {"D": {"type": "object", "properties": {}}},
    }
    harden_schemas(mcp)
    nodes = list(iter_object_nodes(tool.parameters))
    assert len(nodes) == 7
    assert all(node.get("additionalProperties") is False for node in nodes)
    # Non-object nodes are left untouched.
    assert (
        "additionalProperties" not in tool.parameters["properties"]["any"]["anyOf"][1]
    )


def _settings() -> ServerSettings:
    return ServerSettings(
        mock_api_url="http://mock-api.test",
        token_url="http://keycloak.test/token",
        client_id="core-read",
        client_secret="x",
        jwt_issuer="http://keycloak.test/realms/toolgate",
        jwks_url="http://keycloak.test/jwks",
        mcp_audience="core-read",
        port=8101,
    )


async def test_build_server_registers_and_hardens():
    api = ApiClient("http://mock-api.test", StaticTokenProvider("t"))
    received = {}

    def register(mcp: FastMCP, client: ApiClient) -> None:
        received["client"] = client

        @mcp.tool()
        def h(a: Nested) -> str:
            return a.name

    mcp = build_server(
        "core-read", _settings(), register, api_client=api, with_auth=False
    )
    assert received["client"] is api
    assert mcp.settings.auth is None
    async with create_connected_server_and_client_session(mcp._mcp_server) as session:
        tools = (await session.list_tools()).tools
    schema = tools[0].inputSchema
    nodes = list(iter_object_nodes(schema))
    assert nodes and all(n.get("additionalProperties") is False for n in nodes)


def test_build_server_with_auth_wires_verifier():
    mcp = build_server("core-read", _settings(), lambda m, c: None)
    assert mcp.settings.port == 8101
    assert mcp.settings.host == "0.0.0.0"
    assert isinstance(mcp._token_verifier, JwtTokenVerifier)
    assert str(mcp.settings.auth.issuer_url) == "http://keycloak.test/realms/toolgate"
    assert str(mcp.settings.auth.resource_server_url).rstrip("/") == (
        "http://localhost:8101"
    )
