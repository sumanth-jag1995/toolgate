import httpx
import pytest
from toolgate_gateway.auth import ClientCredentialsAuth, DownstreamAuthError

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
    from toolgate_gateway.auth import AgentTokenVerifier

    class Broken:
        def get_signing_key_from_jwt(self, token):
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
    import asyncio

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
