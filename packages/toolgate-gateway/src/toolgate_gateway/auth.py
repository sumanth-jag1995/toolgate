"""Gateway auth.

Inbound: verify Keycloak RS256 agent tokens (aud = toolgate-gateway).
Outbound: the gateway's own client-credentials token for downstream MCP servers.
The agent's token is never forwarded.
"""

import asyncio
import time
from collections.abc import AsyncGenerator
from typing import Any

import anyio.to_thread
import httpx
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier


class DownstreamAuthError(Exception):
    """Token acquisition for downstream calls failed. Message: status or type only."""


class AgentTokenVerifier(TokenVerifier):
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
        # PyJWKClient drops its JWK-set cache after 300 s, so on its own an IdP outage
        # would fail every token. Remember the last good key per kid and fall back to
        # it only when the JWKS fetch itself fails.
        self._last_good: dict[str, Any] = {}

    def _signing_key(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        try:
            key = self._jwk_client.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError:
            if isinstance(kid, str) and kid in self._last_good:
                return self._last_good[kid]
            raise
        if isinstance(kid, str):
            self._last_good[kid] = key
        return key

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # JWKS lookup may do blocking HTTP: keep it off the event loop.
            signing_key = await anyio.to_thread.run_sync(self._signing_key, token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except Exception:  # noqa: BLE001 - any failure means "not authenticated"
            return None
        client_id = claims.get("azp")
        if not isinstance(client_id, str) or not client_id:
            return None
        sub = claims.get("sub")
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=str(claims.get("scope", "")).split(),
            expires_at=int(claims["exp"]),
            resource=self._audience,
            subject=sub if isinstance(sub, str) else None,
        )


class ClientCredentialsAuth(httpx.Auth):
    """httpx auth adding the gateway's client-credentials bearer token.

    Cached until ``expires_in - refresh_margin_s``; refreshes are single-flight.
    A 401 from the downstream triggers one refresh and one retry.
    """

    requires_request_body = True

    def __init__(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        *,
        refresh_margin_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._margin = refresh_margin_s
        # Separate client: the token fetch must not pass through this auth.
        self._http = httpx.AsyncClient(transport=transport)
        self._lock = asyncio.Lock()
        self._token: str | None = None
        self._refresh_at = 0.0

    async def _get_token(self, stale: str | None = None) -> str:
        async with self._lock:
            valid = self._token is not None and time.monotonic() < self._refresh_at
            # `stale`: a token the downstream just rejected; refetch unless another
            # caller already replaced it.
            if not valid or (stale is not None and self._token == stale):
                await self._fetch()
            assert self._token is not None
            return self._token

    async def _fetch(self) -> None:
        try:
            resp = await self._http.post(
                self._token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
        except Exception as exc:  # noqa: BLE001 - message must carry type only
            raise DownstreamAuthError(type(exc).__name__) from None
        if resp.status_code != 200:
            raise DownstreamAuthError(f"token endpoint returned {resp.status_code}")
        try:
            body = resp.json()
            token, expires_in = str(body["access_token"]), float(body["expires_in"])
            if not token or not expires_in > 0:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise DownstreamAuthError("malformed token response") from None
        self._token = token
        self._refresh_at = time.monotonic() + expires_in - self._margin

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        token = await self._get_token()
        request.headers["Authorization"] = f"Bearer {token}"
        response = yield request
        if response.status_code == 401:
            token = await self._get_token(stale=token)
            request.headers["Authorization"] = f"Bearer {token}"
            yield request

    async def aclose(self) -> None:
        await self._http.aclose()
