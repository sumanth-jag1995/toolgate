import json
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from toolgate_idp import parse_agent_client_map


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", populate_by_name=True)

    issuer: str
    jwks_url: str
    audience: str = "toolgate-gateway"
    token_url: str
    client_id: str = "toolgate-gateway"
    client_secret: str
    idp: Literal["keycloak", "cognito"] = "keycloak"
    # JSON object, Cognito client id -> agent name (cognito mode only). NoDecode:
    # parsed by the validator so errors never echo the value.
    agent_client_map: Annotated[dict[str, str], NoDecode] = Field(default_factory=dict)
    # OAuth scope sent on the outbound client-credentials request (cognito mode).
    token_scope: str | None = None
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
    # MCP sessions: a cap on concurrently open sessions (503 beyond it) and
    # the idle time after which a session is closed.
    max_sessions: int = 1000
    session_idle_timeout_s: float = 1800.0
    otlp_endpoint: str | None = Field(
        default=None, validation_alias="OTEL_EXPORTER_OTLP_ENDPOINT"
    )

    @field_validator("agent_client_map", mode="before")
    @classmethod
    def _parse_map(cls, value: Any) -> Any:
        if isinstance(value, str):
            if not value.strip():
                return {}
            return parse_agent_client_map(value)
        if isinstance(value, dict):
            return parse_agent_client_map(json.dumps(value)) if value else {}
        raise ValueError("agent client map must be a JSON object")

    @model_validator(mode="after")
    def _cognito_needs_map(self) -> Self:
        if self.idp == "cognito":
            if not self.agent_client_map:
                raise ValueError("cognito mode requires a non-empty agent client map")
            if not self.audience:
                raise ValueError("cognito mode requires a non-empty audience")
        return self
