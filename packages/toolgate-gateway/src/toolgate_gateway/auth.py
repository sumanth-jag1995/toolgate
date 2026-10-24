"""Gateway auth.

Inbound: verify RS256 agent tokens (Keycloak: aud = toolgate-gateway; Cognito:
scope toolgate-gateway/invoke, client id mapped to an agent name).
Outbound: the gateway's own client-credentials token for downstream MCP servers.
The agent's token is never forwarded.
"""

import asyncio
import threading
import time
from collections.abc import AsyncGenerator, Callable, Mapping
from typing import Any

import anyio.to_thread
import httpx
import jwt
from mcp.server.auth.provider import AccessToken, TokenVerifier
from toolgate_idp import IdpConfig, Mode, decode_token, identity_from_claims


class DownstreamAuthError(Exception):
    """Token acquisition for downstream calls failed. Message: status or type only."""


# An unknown kid refetches the JWKS at most once per this many seconds, so
# tokens with random kids cannot make the gateway hammer the IdP.
UNKNOWN_KID_REFETCH_INTERVAL_S = 10.0


class AgentTokenVerifier(TokenVerifier):
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        *,
        jwk_client: Any | None = None,
        refetch_interval_s: float = UNKNOWN_KID_REFETCH_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
        mode: Mode = "keycloak",
        agent_client_map: Mapping[str, str] | None = None,
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        if mode == "cognito" and not agent_client_map:
            # Without the map the raw Cognito client id would become the agent name.
            raise ValueError("cognito mode requires an agent client map")
        self._cfg = IdpConfig(
            mode=mode,
            issuer=issuer,
            audience=audience,
            require_invoke_scope=True,
            agent_client_map=agent_client_map or {},
        )
        self._jwk_client = jwk_client or jwt.PyJWKClient(jwks_url)
        self._refetch_interval = refetch_interval_s
        self._clock = clock
        # PyJWKClient drops its JWK-set cache after 300 s, so on its own an IdP outage
        # would fail every token. Remember the key set of the last successful fetch
        # (rebuilt on each one, so rotated-out kids go) and fall back to it only when
        # the JWKS fetch itself fails.
        self._last_good: dict[str, Any] = {}
        self._last_refetch: float | None = None
        self._lock = threading.Lock()  # _signing_key runs in worker threads

    def _remember(self, keys: list[Any], kid: str) -> Any | None:
        good = {k.key_id: k for k in keys if isinstance(k.key_id, str)}
        with self._lock:
            self._last_good = good
        return good.get(kid)

    def _signing_key(self, token: str) -> Any:
        kid = jwt.get_unverified_header(token).get("kid")
        if not isinstance(kid, str) or not kid:
            raise jwt.InvalidTokenError("token has no kid")
        try:
            keys = self._jwk_client.get_signing_keys()
        except jwt.PyJWKClientConnectionError:
            with self._lock:
                key = self._last_good.get(kid)
            if key is None:
                raise
            return key
        key = self._remember(keys, kid)
        if key is not None:
            return key
        # Unknown kid: maybe a key rotated in since the cached fetch.
        with self._lock:
            now = self._clock()
            last = self._last_refetch
            if last is not None and now - last < self._refetch_interval:
                raise jwt.PyJWKClientError("unknown kid; JWKS refetch rate-limited")
            self._last_refetch = now
        key = self._remember(self._jwk_client.get_signing_keys(refresh=True), kid)
        if key is None:
            raise jwt.PyJWKClientError("unknown kid")
        return key

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # JWKS lookup may do blocking HTTP: keep it off the event loop.
            signing_key = await anyio.to_thread.run_sync(self._signing_key, token)
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
            client_id=identity.client_id,  # cognito: the mapped agent name
            scopes=scopes,
            expires_at=identity.expires_at,
            resource=self._audience,
            subject=identity.subject,
        )


def build_verifier(settings: Any) -> AgentTokenVerifier:
    """The inbound verifier for ``settings`` (a GatewaySettings)."""
    return AgentTokenVerifier(
        settings.issuer,
        settings.audience,
        settings.jwks_url,
        mode=settings.idp,
        agent_client_map=settings.agent_client_map,
    )


def build_auth(
    settings: Any, *, transport: httpx.AsyncBaseTransport | None = None
) -> "ClientCredentialsAuth":
    """The outbound client-credentials auth; scope is sent in cognito mode only."""
    scope = settings.token_scope if settings.idp == "cognito" else None
    return ClientCredentialsAuth(
        settings.token_url,
        settings.client_id,
        settings.client_secret,
        scope=scope or None,
        transport=transport,
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
        scope: str | None = None,
        refresh_margin_s: float = 30.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
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
        form = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if self._scope:
            form["scope"] = self._scope
        try:
            resp = await self._http.post(self._token_url, data=form)
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
