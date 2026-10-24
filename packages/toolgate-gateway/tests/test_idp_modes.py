import asyncio
import json
import socket
import time
from contextlib import asynccontextmanager

import httpx
import jwt
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from pydantic import ValidationError
from toolgate_gateway.app import build_app
from toolgate_gateway.auth import (
    AgentTokenVerifier,
    ClientCredentialsAuth,
    DownstreamAuthError,
    build_verifier,
)
from toolgate_gateway.core import GatewayCore
from toolgate_gateway.downstreams import DownstreamConfig
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist
from toolgate_gateway.pool import DownstreamPool
from toolgate_gateway.settings import GatewaySettings
from toolgate_pin.demo_server import build_demo_server

# conftest.py cannot be imported (importlib mode); these mirror its constants.
ISSUER = "http://keycloak.test/realms/toolgate"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "toolgate-gateway"
HMAC_KEY = "k" * 32
CONFIGS = [
    DownstreamConfig("core-read", "http://core-read.test/mcp"),
    DownstreamConfig("core-write", "http://core-write.test/mcp"),
    DownstreamConfig("comms", "http://comms.test/mcp"),
]


class StubJWKClient:
    class _Key:
        key_id = "test"

        def __init__(self, key):
            self.key = key

    def __init__(self, public_key):
        self._key = self._Key(public_key)

    def get_signing_key_from_jwt(self, token):
        return self._key

    def get_signing_keys(self, refresh=False):
        return [self._key]


class FakeAudit:
    def __init__(self):
        self.records = []
        self.accepting = True

    async def start(self):
        pass

    async def stop(self):
        pass

    def submit(self, rec):
        self.records.append(rec)
        return True


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_settings(tmp_path, port, **overrides):
    return GatewaySettings(
        issuer=ISSUER,
        jwks_url=JWKS_URL,
        token_url=f"{ISSUER}/protocol/openid-connect/token",
        client_secret="unused",
        database_url="postgresql://unused@localhost/unused",
        audit_hmac_key=HMAC_KEY,
        lockfile_path=tmp_path / "toolgate.lock.json",
        policy_path=tmp_path / "agents.yaml",
        downstreams_path=tmp_path / "gateway.yaml",
        host="127.0.0.1",
        port=port,
        public_url=f"http://127.0.0.1:{port}",
        **overrides,
    )


def spy_factory_cls(base):
    class SpyFactory(base):
        """MemoryFactory recording every tools/call forwarded downstream."""

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.calls = []

        @asynccontextmanager
        async def __call__(self, config, *, message_handler=None):
            opened = base.__call__(self, config, message_handler=message_handler)
            async with opened as (session, init):
                original = session.call_tool

                async def call_tool(name, arguments=None, *args, **kwargs):
                    self.calls.append((config.server_id, name, arguments))
                    return await original(name, arguments, *args, **kwargs)

                session.call_tool = call_tool
                yield session, init

    return SpyFactory


@asynccontextmanager
async def mcp_session(url, token):
    async with (
        httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=30
        ) as http,
        streamable_http_client(url, http_client=http) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


CLIENT_MAP = {"cog-servicing": "servicing", "cog-triage": "fraud-triage"}
GW_SCOPE = "toolgate-gateway/invoke"


@pytest.fixture(scope="module")
def make_cognito_token(rsa_key):
    def _make(
        scopes=(GW_SCOPE,),
        *,
        client_id="cog-servicing",
        token_use="access",
        iss=ISSUER,
        extra=None,
    ):
        now = int(time.time())
        claims = {
            "iss": iss,
            "sub": "cog-sub-1",
            "client_id": client_id,
            "token_use": token_use,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + 300,
        }
        claims.update(extra or {})
        return jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "test"})

    return _make


@pytest.fixture
def cognito_verifier(rsa_key):
    return AgentTokenVerifier(
        ISSUER,
        AUDIENCE,
        JWKS_URL,
        jwk_client=StubJWKClient(rsa_key.public_key()),
        mode="cognito",
        agent_client_map=CLIENT_MAP,
    )


async def test_cognito_valid_token_maps_client_to_agent(
    cognito_verifier, make_cognito_token
):
    at = await cognito_verifier.verify_token(make_cognito_token())
    assert at is not None
    assert at.client_id == "servicing"
    assert at.subject == "cog-sub-1"
    assert at.resource == AUDIENCE
    assert GW_SCOPE in at.scopes


async def test_cognito_unmapped_client_rejected(cognito_verifier, make_cognito_token):
    token = make_cognito_token(client_id="stranger")
    assert await cognito_verifier.verify_token(token) is None


async def test_cognito_rejects_core_read_invoke_scope(
    cognito_verifier, make_cognito_token
):
    token = make_cognito_token(("core-read/invoke",))
    assert await cognito_verifier.verify_token(token) is None


async def test_cognito_rejects_id_token(cognito_verifier, make_cognito_token):
    token = make_cognito_token(token_use="id")
    assert await cognito_verifier.verify_token(token) is None


async def test_cognito_rejects_wrong_issuer_and_hs256(
    cognito_verifier, make_cognito_token
):
    bad_iss = make_cognito_token(iss="http://evil/x")
    assert await cognito_verifier.verify_token(bad_iss) is None
    now = int(time.time())
    hs = jwt.encode(
        {
            "iss": ISSUER,
            "client_id": "cog-servicing",
            "token_use": "access",
            "scope": GW_SCOPE,
            "exp": now + 300,
        },
        "x" * 64,
        algorithm="HS256",
        headers={"kid": "test"},
    )
    assert await cognito_verifier.verify_token(hs) is None


async def test_keycloak_mode_rejects_cognito_token(verifier, make_cognito_token):
    assert await verifier.verify_token(make_cognito_token()) is None


async def test_cognito_jwks_last_good_still_works(rsa_key, make_cognito_token):
    class Flaky(StubJWKClient):
        broken = False

        def get_signing_keys(self, refresh=False):
            if self.broken:
                raise jwt.PyJWKClientConnectionError("jwks down")
            return super().get_signing_keys(refresh)

    client = Flaky(rsa_key.public_key())
    v = AgentTokenVerifier(
        ISSUER,
        AUDIENCE,
        JWKS_URL,
        jwk_client=client,
        mode="cognito",
        agent_client_map=CLIENT_MAP,
    )
    token = make_cognito_token()
    assert await v.verify_token(token) is not None
    client.broken = True  # IdP outage: the last good key set still verifies
    at = await v.verify_token(token)
    assert at is not None and at.client_id == "servicing"


async def test_cognito_broken_jwks_never_raises(make_cognito_token):
    class Broken:
        def get_signing_keys(self, refresh=False):
            raise OSError("jwks down")

    v = AgentTokenVerifier(
        ISSUER,
        AUDIENCE,
        "http://x",
        jwk_client=Broken(),
        mode="cognito",
        agent_client_map=CLIENT_MAP,
    )
    assert await v.verify_token(make_cognito_token()) is None


def test_verifier_cognito_without_map_refused():
    with pytest.raises(ValueError):
        AgentTokenVerifier(ISSUER, AUDIENCE, JWKS_URL, mode="cognito")


# -- settings ---------------------------------------------------------------


def _settings(tmp_path, **kw):
    return make_settings(tmp_path, 1, **kw)


def _env(monkeypatch, tmp_path, **extra):
    env = {
        "GATEWAY_ISSUER": ISSUER,
        "GATEWAY_JWKS_URL": JWKS_URL,
        "GATEWAY_TOKEN_URL": f"{ISSUER}/token",
        "GATEWAY_CLIENT_SECRET": "s3cret",
        "DATABASE_URL": "postgresql://unused@localhost/unused",
        "AUDIT_HMAC_KEY": HMAC_KEY,
        "GATEWAY_LOCKFILE_PATH": str(tmp_path / "l"),
        "GATEWAY_POLICY_PATH": str(tmp_path / "p"),
        "GATEWAY_DOWNSTREAMS_PATH": str(tmp_path / "d"),
        **extra,
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def test_settings_default_is_keycloak(tmp_path):
    s = _settings(tmp_path)
    assert s.idp == "keycloak"
    assert s.agent_client_map == {}
    assert s.token_scope is None


def test_settings_cognito_requires_map(tmp_path):
    with pytest.raises(ValidationError):
        _settings(tmp_path, idp="cognito")
    with pytest.raises(ValidationError):
        _settings(tmp_path, idp="cognito", agent_client_map={})
    s = _settings(tmp_path, idp="cognito", agent_client_map=CLIENT_MAP)
    assert s.agent_client_map == CLIENT_MAP


def test_settings_unknown_idp_rejected(tmp_path):
    with pytest.raises(ValidationError):
        _settings(tmp_path, idp="okta")


@pytest.mark.parametrize(
    "raw",
    [
        "{not json",
        '["a", "b"]',
        '{"cog-secret-id": ""}',
        '{"": "agent"}',
        '{"cog-secret-id": 5}',
        "[]",
    ],
)
def test_settings_reject_malformed_map_json(tmp_path, monkeypatch, raw):
    _env(
        monkeypatch,
        tmp_path,
        GATEWAY_IDP="cognito",
        GATEWAY_AGENT_CLIENT_MAP=raw,
    )
    with pytest.raises(ValidationError) as ei:
        GatewaySettings()  # type: ignore[call-arg]
    errs = ei.value.errors(include_input=False, include_url=False)
    assert [e["loc"] for e in errs] == [("agent_client_map",)]
    assert "cog-secret-id" not in repr(errs)


def test_settings_map_from_env_json(tmp_path, monkeypatch):
    _env(
        monkeypatch,
        tmp_path,
        GATEWAY_IDP="cognito",
        GATEWAY_AGENT_CLIENT_MAP=json.dumps(CLIENT_MAP),
        GATEWAY_TOKEN_SCOPE="a/invoke b/invoke",
    )
    s = GatewaySettings()  # type: ignore[call-arg]
    assert s.agent_client_map == CLIENT_MAP
    assert s.token_scope == "a/invoke b/invoke"


def test_built_cognito_verifier_config_has_nonempty_map(tmp_path):
    """Guards against a refactor that forgets to pass the map: without it the raw
    Cognito client id would become the agent name."""
    s = _settings(tmp_path, idp="cognito", agent_client_map=CLIENT_MAP)
    v = build_verifier(s)
    assert v._cfg.mode == "cognito"
    assert dict(v._cfg.agent_client_map) == CLIENT_MAP
    assert v._cfg.require_invoke_scope is True
    assert build_verifier(_settings(tmp_path))._cfg.mode == "keycloak"


# -- outbound scope ---------------------------------------------------------


async def test_cc_auth_sends_scope_only_when_set():
    bodies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode())
        return httpx.Response(200, json={"access_token": "t", "expires_in": 300})

    def downstream(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    for scope in (None, "a/invoke b/invoke"):
        auth = ClientCredentialsAuth(
            "http://idp.test/token",
            "gw",
            "s3cret",
            scope=scope,
            transport=httpx.MockTransport(handler),
        )
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(downstream), auth=auth
        ) as client:
            await client.get("http://ds.test/x")
    base = "grant_type=client_credentials&client_id=gw&client_secret=s3cret"
    assert bodies[0] == base
    assert bodies[1] == base + "&scope=a%2Finvoke+b%2Finvoke"


async def test_cc_auth_error_never_carries_secret():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="bad client_secret=s3cret")

    auth = ClientCredentialsAuth(
        "http://idp.test/token",
        "gw",
        "s3cret",
        scope="a/invoke",
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(DownstreamAuthError) as ei:
        await auth._get_token()
    assert "s3cret" not in str(ei.value)


# -- end to end -------------------------------------------------------------

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "p", "version": "0"},
    },
}


async def test_cognito_agent_allowlist_applies_to_mapped_agent(
    tmp_path,
    memory_factory_cls,
    write_lockfile,
    build_core_write,
    cognito_verifier,
    make_cognito_token,
):
    builders = {
        "core-read": build_demo_server,
        "core-write": build_core_write,
        "comms": build_demo_server,
    }
    allowlist = Allowlist(
        {
            "fraud-triage": ("core-read.*",),
            "servicing": ("core-read.*", "comms.*"),
        }
    )
    lock = tmp_path / "toolgate.lock.json"
    await write_lockfile(lock, builders, CONFIGS)
    factory = spy_factory_cls(memory_factory_cls)(builders)
    pool = DownstreamPool(CONFIGS, factory)
    audit = FakeAudit()
    core = GatewayCore(pool, PinSource(lock), allowlist, audit, None, hmac_key=HMAC_KEY)
    port = _free_port()
    app = build_app(core, cognito_verifier, make_settings(tmp_path, port))
    server = uvicorn.Server(
        uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="error", lifespan="on"
        )
    )
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        url = f"http://127.0.0.1:{port}/mcp"
        token = make_cognito_token(client_id="cog-triage")
        async with mcp_session(url, token) as session:
            names = {t.name for t in (await session.list_tools()).tools}
            assert names
            assert all(n.startswith("core-read.") for n in names)
            denied = await session.call_tool("core-write.log_claim", {"member_id": "M"})
        assert denied.isError
        assert factory.calls == []
        [rec] = audit.records
        assert (rec.client_id, rec.decision) == ("fraud-triage", "deny_scope")

        # A raw, unmapped Cognito client id is not an agent: 401.
        stranger = make_cognito_token(client_id="x")
        async with httpx.AsyncClient() as http:
            resp = await http.post(
                url,
                json=INIT,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {stranger}",
                },
            )
        assert resp.status_code == 401
    finally:
        server.should_exit = True
        await task
