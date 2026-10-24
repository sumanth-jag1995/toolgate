"""Inbound auth: verify RS256 access tokens (Keycloak or Cognito) presented to an MCP server."""

from typing import Any

import anyio.to_thread
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier
from toolgate_idp import IdpConfig, Mode, decode_token, identity_from_claims


class JwtTokenVerifier(TokenVerifier):
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        *,
        jwk_client: Any | None = None,
        mode: Mode = "keycloak",
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        # Cognito mode requires the `<audience>/invoke` scope; invalid config fails here.
        self._cfg = IdpConfig(
            mode=mode, issuer=issuer, audience=audience, require_invoke_scope=True
        )
        self._jwk_client = jwk_client or jwt.PyJWKClient(jwks_url)

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # JWKS lookup may do blocking HTTP: keep it off the event loop.
            signing_key = await anyio.to_thread.run_sync(
                self._jwk_client.get_signing_key_from_jwt, token
            )
            claims = decode_token(token, signing_key.key, self._cfg)
            identity = identity_from_claims(claims, self._cfg)
        except Exception:  # noqa: BLE001 - any failure means "not authenticated"
            return None
        if identity is None:
            return None
        # Keep the token's own scope order (Identity.scopes is an unordered set).
        scopes = [
            sc for sc in str(claims.get("scope", "")).split() if sc in identity.scopes
        ]
        return AccessToken(
            token=token,
            client_id=identity.client_id,
            scopes=scopes,
            expires_at=identity.expires_at,
            resource=self._audience,
            subject=identity.subject,
        )
