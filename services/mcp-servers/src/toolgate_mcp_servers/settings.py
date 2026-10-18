from pydantic_settings import BaseSettings


class ServerSettings(BaseSettings):
    """Configuration shared by every Toolgate MCP server (env vars, case-insensitive)."""

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
