from collections.abc import Callable

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from toolgate_mcp_servers.api_client import ApiClient, ClientCredentialsTokenProvider
from toolgate_mcp_servers.auth import JwtTokenVerifier
from toolgate_mcp_servers.hardening import forbid_extra_arguments, harden_schemas
from toolgate_mcp_servers.settings import ServerSettings


def build_server(
    name: str,
    settings: ServerSettings,
    register: Callable[[FastMCP, ApiClient], None],
    *,
    api_client: ApiClient | None = None,
    with_auth: bool = True,
) -> FastMCP:
    if api_client is None:
        api_client = ApiClient(
            settings.mock_api_url,
            ClientCredentialsTokenProvider(
                settings.token_url,
                settings.client_id,
                settings.client_secret,
                scope=settings.token_scope if settings.idp == "cognito" else None,
            ),
            timeout_s=settings.api_timeout_s,
        )
    if with_auth:
        mcp = FastMCP(
            name,
            host=settings.host,
            port=settings.port,
            token_verifier=JwtTokenVerifier(
                settings.jwt_issuer,
                settings.mcp_audience,
                settings.jwks_url,
                mode=settings.idp,
            ),
            auth=AuthSettings(
                issuer_url=settings.jwt_issuer,
                resource_server_url=f"http://localhost:{settings.port}",
                required_scopes=[],
                # JwtTokenVerifier checks `aud` itself.
                validate_token_resource=False,
            ),
        )
    else:
        mcp = FastMCP(name, host=settings.host, port=settings.port)
    register(mcp, api_client)
    harden_schemas(mcp)
    forbid_extra_arguments(mcp)
    return mcp
