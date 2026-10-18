"""Inbound auth: verify Keycloak-issued RS256 access tokens presented to an MCP server."""

from typing import Any

import anyio.to_thread
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier


class JwtTokenVerifier(TokenVerifier):
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        *,
        jwk_client: Any | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._jwk_client = jwk_client or jwt.PyJWKClient(jwks_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # JWKS lookup may do blocking HTTP: keep it off the event loop.
            signing_key = await anyio.to_thread.run_sync(
                self._jwk_client.get_signing_key_from_jwt, token
            )
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,  # matches a string or any entry of a list
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception:  # noqa: BLE001 - any failure means "not authenticated"
            return None
        client_id = claims.get("azp")
        if not isinstance(client_id, str) or not client_id:
            return None
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=self._audience,
            subject=claims.get("sub"),
        )
