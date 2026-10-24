from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSettings(BaseSettings):
    """Configuration shared by every Toolgate MCP server (env vars, case-insensitive)."""

    # hide_input_in_errors keeps a bad IDP value out of the startup error.
    model_config = SettingsConfigDict(hide_input_in_errors=True)

    mock_api_url: str
    token_url: str
    client_id: str
    client_secret: str
    jwt_issuer: str
    jwks_url: str
    mcp_audience: str
    host: str = "0.0.0.0"
    port: int
    api_timeout_s: float = 5.0
    idp: Literal["keycloak", "cognito"] = "keycloak"
    # Outbound `scope` form parameter; sent in cognito mode only.
    token_scope: str | None = None
