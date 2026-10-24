"""Claim rules for Keycloak and Cognito RS256 access tokens.

Keycloak: ``aud`` required and checked, caller id is ``azp``.
Cognito: no ``aud`` (access tokens carry none); ``token_use`` must be ``access``,
caller id is ``client_id``, and the audience stand-in is the scope
``<audience>/invoke``.
"""

import json
import types
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

import jwt

Mode = Literal["keycloak", "cognito"]


@dataclass(frozen=True)
class IdpConfig:
    mode: Mode
    issuer: str
    audience: str
    require_invoke_scope: bool = True
    scope_prefix: str = ""
    agent_client_map: Mapping[str, str] = field(default_factory=dict, hash=False)

    def __post_init__(self) -> None:
        if self.mode not in ("keycloak", "cognito"):
            raise ValueError("unknown idp mode")
        if self.mode == "cognito" and not self.audience:
            raise ValueError("cognito mode requires a non-empty audience")
        if self.scope_prefix and not self.scope_prefix.endswith("/"):
            raise ValueError("scope prefix must end with a slash")
        object.__setattr__(
            self,
            "agent_client_map",
            types.MappingProxyType(dict(self.agent_client_map)),
        )


@dataclass(frozen=True)
class Identity:
    client_id: str
    scopes: frozenset[str]
    subject: str | None
    expires_at: int


def decode_token(token: str, key: Any, cfg: IdpConfig) -> dict[str, Any]:
    """Verify signature, issuer and expiry. Raises PyJWT errors on any failure."""
    if cfg.mode == "keycloak":
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=cfg.audience,  # matches a string or any entry of a list
            issuer=cfg.issuer,
            options={"require": ["exp", "iss", "aud"]},
        )
    if cfg.mode == "cognito":
        return jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            issuer=cfg.issuer,
            options={"require": ["exp", "iss"], "verify_aud": False},
        )
    raise ValueError("unknown idp mode")


def _scopes(claims: Mapping[str, Any]) -> list[str] | None:
    """Space-separated scope string (RFC 6749); None when present but not a string."""
    raw = claims.get("scope", "")
    if not isinstance(raw, str):
        return None
    return [s for s in raw.split(" ") if s]


def _valid_id(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def identity_from_claims(claims: Mapping[str, Any], cfg: IdpConfig) -> Identity | None:
    sub = claims.get("sub")
    subject = sub if isinstance(sub, str) else None
    scopes = _scopes(claims)
    if scopes is None:
        return None
    if cfg.mode == "keycloak":
        azp = claims.get("azp")
        if not _valid_id(azp):
            return None
        return Identity(azp, frozenset(scopes), subject, int(claims["exp"]))
    if cfg.mode != "cognito":
        raise ValueError("unknown idp mode")

    if claims.get("token_use") != "access":
        return None
    client_id = claims.get("client_id")
    if not _valid_id(client_id):
        return None
    if cfg.require_invoke_scope and f"{cfg.audience}/invoke" not in scopes:
        return None
    if cfg.agent_client_map:
        mapped = cfg.agent_client_map.get(client_id)
        if not mapped:
            return None
        client_id = mapped
    normalised = frozenset(t for s in scopes if (t := s.removeprefix(cfg.scope_prefix)))
    return Identity(client_id, normalised, subject, int(claims["exp"]))


def parse_agent_client_map(raw: str) -> dict[str, str]:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        raise ValueError("agent client map is not valid JSON") from None
    if not isinstance(data, dict) or not data:
        raise ValueError("agent client map must be a non-empty JSON object")
    for k, v in data.items():
        if not isinstance(k, str) or not k or not isinstance(v, str) or not v:
            raise ValueError("agent client map entries must be non-empty strings")
    return dict(data)


def validate_cognito_settings(cfg: IdpConfig) -> None:
    if cfg.mode not in ("keycloak", "cognito"):
        raise ValueError("unknown idp mode")
    if cfg.mode == "cognito" and not cfg.audience:
        raise ValueError("cognito mode requires a non-empty audience")
