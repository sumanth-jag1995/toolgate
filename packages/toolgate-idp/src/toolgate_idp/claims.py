"""Claim rules for Keycloak and Cognito RS256 access tokens.

Keycloak: ``aud`` required and checked, caller id is ``azp``.
Cognito: no ``aud`` (access tokens carry none); ``token_use`` must be ``access``,
caller id is ``client_id``, and the audience stand-in is the scope
``<audience>/invoke``.
"""

import json
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
    agent_client_map: Mapping[str, str] = field(default_factory=dict)


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
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        issuer=cfg.issuer,
        options={"require": ["exp", "iss"], "verify_aud": False},
    )


def _normalise(scopes: list[str], prefix: str) -> frozenset[str]:
    if not prefix:
        return frozenset(scopes)
    return frozenset(s.removeprefix(prefix) for s in scopes)


def identity_from_claims(claims: Mapping[str, Any], cfg: IdpConfig) -> Identity | None:
    sub = claims.get("sub")
    subject = sub if isinstance(sub, str) else None
    scopes = str(claims.get("scope", "")).split()
    if cfg.mode == "keycloak":
        azp = claims.get("azp")
        if not isinstance(azp, str) or not azp:
            return None
        return Identity(azp, frozenset(scopes), subject, int(claims["exp"]))

    if claims.get("token_use") != "access":
        return None
    client_id = claims.get("client_id")
    if not isinstance(client_id, str) or not client_id:
        return None
    if cfg.require_invoke_scope and f"{cfg.audience}/invoke" not in scopes:
        return None
    if cfg.agent_client_map:
        mapped = cfg.agent_client_map.get(client_id)
        if mapped is None:
            return None
        client_id = mapped
    return Identity(
        client_id,
        _normalise(scopes, cfg.scope_prefix),
        subject,
        int(claims["exp"]),
    )


def parse_agent_client_map(raw: str) -> dict[str, str]:
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError("agent client map is not valid JSON") from None
    if not isinstance(data, dict) or not data:
        raise ValueError("agent client map must be a non-empty JSON object")
    for k, v in data.items():
        if not isinstance(k, str) or not k or not isinstance(v, str) or not v:
            raise ValueError("agent client map entries must be non-empty strings")
    return dict(data)


def validate_cognito_settings(cfg: IdpConfig) -> None:
    if cfg.mode == "cognito" and not cfg.audience:
        raise ValueError("cognito mode requires a non-empty audience")
