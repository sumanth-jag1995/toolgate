from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", populate_by_name=True)

    issuer: str
    jwks_url: str
    audience: str = "toolgate-gateway"
    token_url: str
    client_id: str = "toolgate-gateway"
    client_secret: str
    database_url: str = Field(validation_alias="DATABASE_URL")
    audit_hmac_key: str = Field(validation_alias="AUDIT_HMAC_KEY")
    lockfile_path: Path
    policy_path: Path
    downstreams_path: Path
    host: str = "0.0.0.0"
    port: int = 8200
    # Externally visible base URL; the protected resource is ``<public_url>/mcp``
    # (RFC 9728 metadata and the WWW-Authenticate resource_metadata link).
    public_url: str = "http://localhost:8200"
    otlp_endpoint: str | None = Field(
        default=None, validation_alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )
