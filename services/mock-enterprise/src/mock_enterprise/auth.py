from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from toolgate_idp import decode_token, identity_from_claims

SCOPES = (
    "members:read",
    "policies:read",
    "claims:read",
    "payments:read",
    "comms:read",
    "claims:write",
    "members:write",
    "comms:write",
)

_bearer = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    client_id: str
    scopes: frozenset[str]


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401, detail=detail, headers={"WWW-Authenticate": "Bearer"}
    )


def get_principal(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    if creds is None:
        raise _unauthorized("missing bearer token")
    cfg = request.app.state.idp_cfg
    try:
        key = request.app.state.jwk_client.get_signing_key_from_jwt(creds.credentials)
        claims = decode_token(creds.credentials, key.key, cfg)
    except jwt.PyJWTError:
        # Covers expired, bad signature, wrong aud/iss, malformed, JWKS lookup failure.
        raise _unauthorized("invalid token") from None
    identity = identity_from_claims(claims, cfg)
    if identity is None:
        raise _unauthorized("invalid token")
    return Principal(client_id=identity.client_id, scopes=identity.scopes)


def require_scope(scope: str) -> Callable[..., Principal]:
    def dependency(
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> Principal:
        if scope not in principal.scopes:
            raise HTTPException(status_code=403, detail=f"missing scope: {scope}")
        return principal

    return dependency
