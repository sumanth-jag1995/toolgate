import asyncio

import httpx
import jwt
import pytest
from toolgate_gateway.auth import (
    AgentTokenVerifier,
    ClientCredentialsAuth,
    DownstreamAuthError,
)

TOKEN_URL = "http://keycloak.test/token"


async def test_valid_agent_token(verifier, make_token):
    at = await verifier.verify_token(
        make_token(aud="toolgate-gateway", azp="servicing")
    )
    assert at is not None
    assert at.client_id == "servicing"
    assert at.subject == "agent-sub-1"
    assert at.resource == "toolgate-gateway"


async def test_core_read_audience_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(aud="core-read")) is None


async def test_expired_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(exp_delta=-10)) is None


async def test_hs256_rejected(verifier, make_token):
    token = make_token(key="x" * 64, algorithm="HS256")
    assert await verifier.verify_token(token) is None


async def test_missing_azp_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(azp=None)) is None


async def test_wrong_issuer_rejected(verifier, make_token):
    assert await verifier.verify_token(make_token(iss="http://evil/realms/x")) is None


async def test_garbage_rejected(verifier):
    assert await verifier.verify_token("not-a-jwt") is None


async def test_jwks_failure_never_raises(rsa_key, make_token):
    class Broken:
        def get_signing_key_from_jwt(self, token):
            raise OSError("jwks down")

        def get_signing_keys(self, refresh=False):
            raise OSError("jwks down")

    v = AgentTokenVerifier("i", "toolgate-gateway", "http://x", jwk_client=Broken())
    assert await v.verify_token(make_token()) is None


class Downstream:
    """MockTransport pair: token endpoint + downstream, counting calls."""

    def __init__(self, downstream_statuses=(200,), token_status=200, token_body=None):
        self.token_calls = 0
        self.downstream_calls = 0
        self.seen_auth: list[str] = []
        self.token_bodies: list[str] = []
        self._statuses = list(downstream_statuses)
        self._token_status = token_status
        self._token_body = token_body

    def token_transport(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.token_calls += 1
            self.token_bodies.append(request.content.decode())
            assert "authorization" not in request.headers
            if self._token_body is not None:
                return httpx.Response(self._token_status, json=self._token_body)
            return httpx.Response(
                self._token_status,
                json={"access_token": f"tok-{self.token_calls}", "expires_in": 300},
            )

        return httpx.MockTransport(handler)

    def downstream_transport(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.downstream_calls += 1
            self.seen_auth.append(request.headers.get("authorization", ""))
            status = self._statuses[
                min(self.downstream_calls - 1, len(self._statuses) - 1)
            ]
            return httpx.Response(status)

        return httpx.MockTransport(handler)


def make_client(d: Downstream) -> httpx.AsyncClient:
    auth = ClientCredentialsAuth(
        TOKEN_URL, "toolgate-gateway", "s3cret", transport=d.token_transport()
    )
    return httpx.AsyncClient(transport=d.downstream_transport(), auth=auth)


async def test_cc_auth_caches_token():
    d = Downstream()
    async with make_client(d) as client:
        for _ in range(3):
            assert (await client.get("http://ds.test/x")).status_code == 200
    assert d.token_calls == 1
    assert d.seen_auth == ["Bearer tok-1"] * 3
    assert "grant_type=client_credentials" in d.token_bodies[0]


async def test_cc_auth_refetches_after_expiry():
    d = Downstream(token_body={"access_token": "t", "expires_in": 10})
    async with make_client(d) as client:  # 10s - 30s margin => always stale
        await client.get("http://ds.test/x")
        await client.get("http://ds.test/x")
    assert d.token_calls == 2


async def test_cc_auth_refreshes_on_401_once():
    d = Downstream(downstream_statuses=(401, 200))
    async with make_client(d) as client:
        resp = await client.get("http://ds.test/x")
    assert resp.status_code == 200
    assert d.token_calls == 2
    assert d.seen_auth == ["Bearer tok-1", "Bearer tok-2"]


async def test_cc_auth_second_401_returned_as_is():
    d = Downstream(downstream_statuses=(401, 401, 200))
    async with make_client(d) as client:
        resp = await client.get("http://ds.test/x")
    assert resp.status_code == 401
    assert d.downstream_calls == 2
    assert d.token_calls == 2


async def test_cc_auth_single_flight():
    d = Downstream()
    async with make_client(d) as client:
        await asyncio.gather(*(client.get("http://ds.test/x") for _ in range(5)))
    assert d.token_calls == 1


async def test_cc_auth_error_has_no_secret():
    d = Downstream(token_status=401, token_body={"error": "bad secret s3cret"})
    async with make_client(d) as client:
        with pytest.raises(DownstreamAuthError) as ei:
            await client.get("http://ds.test/x")
    assert "s3cret" not in str(ei.value)
    assert "401" in str(ei.value)
    assert d.downstream_calls == 0


async def test_cc_auth_transport_error_names_type_only():
    def boom(request):
        raise httpx.ConnectError("connect to http://secret-host failed s3cret")

    auth = ClientCredentialsAuth(
        TOKEN_URL, "c", "s3cret", transport=httpx.MockTransport(boom)
    )
    async with httpx.AsyncClient(auth=auth) as client:
        with pytest.raises(DownstreamAuthError) as ei:
            await client.get("http://ds.test/x")
    assert str(ei.value) == "ConnectError"


@pytest.mark.parametrize(
    "body",
    [
        {"access_token": "", "expires_in": 300},
        {"access_token": "t", "expires_in": 0},
        {"access_token": "t", "expires_in": -5},
    ],
)
async def test_cc_auth_rejects_malformed_token_response(body):
    d = Downstream(token_body=body)
    async with make_client(d) as client:
        with pytest.raises(DownstreamAuthError, match="malformed"):
            await client.get("http://ds.test/x")


async def test_verifier_uses_cached_key_when_jwks_refresh_fails(
    rsa_key, make_token, monkeypatch
):
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key(), as_dict=True)
    jwk.update(kid="test", use="sig", alg="RS256")
    client = jwt.PyJWKClient("http://keycloak.test/jwks")
    state = {"down": False}

    def fetch_data():
        if state["down"]:
            raise jwt.PyJWKClientConnectionError("jwks down")
        return {"keys": [jwk]}

    monkeypatch.setattr(client, "fetch_data", fetch_data)
    v = AgentTokenVerifier(
        "http://keycloak.test/realms/toolgate",
        "toolgate-gateway",
        "http://x",
        jwk_client=client,
    )

    assert await v.verify_token(make_token()) is not None
    state["down"] = (
        True  # fetch_data is patched, so nothing is cached: every call refetches
    )
    assert await v.verify_token(make_token()) is not None
    unknown = jwt.encode(
        {
            "iss": "http://keycloak.test/realms/toolgate",
            "aud": "toolgate-gateway",
            "azp": "a",
            "exp": 4102444800,
        },
        rsa_key,
        algorithm="RS256",
        headers={"kid": "unknown"},
    )
    assert await v.verify_token(unknown) is None


def _token(rsa_key, kid: str) -> str:
    return jwt.encode(
        {
            "iss": "http://keycloak.test/realms/toolgate",
            "aud": "toolgate-gateway",
            "azp": "a",
            "exp": 4102444800,
        },
        rsa_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _jwk(rsa_key, kid: str) -> dict:
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key(), as_dict=True)
    jwk.update(kid=kid, use="sig", alg="RS256")
    return jwk


def _verifier(client, **kw) -> AgentTokenVerifier:
    return AgentTokenVerifier(
        "http://keycloak.test/realms/toolgate",
        "toolgate-gateway",
        "http://x",
        jwk_client=client,
        **kw,
    )


async def test_rotated_out_kid_not_used_during_outage(rsa_key, monkeypatch):
    client = jwt.PyJWKClient("http://keycloak.test/jwks", cache_jwk_set=False)
    state = {"down": False, "keys": [_jwk(rsa_key, "A")]}

    def fetch_data():
        if state["down"]:
            raise jwt.PyJWKClientConnectionError("jwks down")
        return {"keys": state["keys"]}

    monkeypatch.setattr(client, "fetch_data", fetch_data)
    v = _verifier(client)
    assert await v.verify_token(_token(rsa_key, "A")) is not None  # A cached
    state["keys"] = [_jwk(rsa_key, "B")]  # A rotated out
    assert await v.verify_token(_token(rsa_key, "B")) is not None
    state["down"] = True
    assert await v.verify_token(_token(rsa_key, "B")) is not None  # fallback
    assert await v.verify_token(_token(rsa_key, "A")) is None


class CountingJWKS:
    """get_signing_keys like PyJWKClient's: cached unless ``refresh``."""

    def __init__(self, keys):
        self.keys = keys
        self.fetches = 0
        self._cached = None

    def get_signing_keys(self, refresh=False):
        if refresh or self._cached is None:
            self.fetches += 1
            self._cached = [jwt.PyJWK(k) for k in self.keys]
        return self._cached


async def test_unknown_kid_refetch_rate_limited(rsa_key):
    client = CountingJWKS([_jwk(rsa_key, "A")])
    now = [1000.0]
    v = _verifier(client, clock=lambda: now[0])
    assert await v.verify_token(_token(rsa_key, "A")) is not None
    assert client.fetches == 1
    assert await v.verify_token(_token(rsa_key, "X")) is None
    assert client.fetches == 2  # one refetch for the unknown kid
    for kid in ("X", "Y", "Z"):  # within 10 s: rejected without fetching
        assert await v.verify_token(_token(rsa_key, kid)) is None
    assert client.fetches == 2
    now[0] += 10.0
    client.keys.append(_jwk(rsa_key, "Y"))  # rotated in meanwhile
    assert await v.verify_token(_token(rsa_key, "Y")) is not None
    assert client.fetches == 3
    assert await v.verify_token(_token(rsa_key, "A")) is not None  # cached
    assert client.fetches == 3
