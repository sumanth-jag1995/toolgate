import os

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

import asyncio
import importlib
import time

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.shared.memory import create_connected_server_and_client_session
from mock_enterprise.app import create_app
from mock_enterprise.db import create_schema, make_sessionmaker
from mock_enterprise.models import Base, Claim, Policy
from mock_enterprise.seed import seed
from mock_enterprise.settings import Settings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer
from toolgate_mcp_servers.api_client import ApiClient, StaticTokenProvider
from toolgate_mcp_servers.app_factory import build_server
from toolgate_mcp_servers.auth import JwtTokenVerifier
from toolgate_mcp_servers.settings import ServerSettings

ISSUER = "http://keycloak.test/realms/toolgate"
JWKS_URL = "http://keycloak.test/realms/toolgate/protocol/openid-connect/certs"


class _StubSigningKey:
    def __init__(self, key):
        self.key = key


class StubJWKClient:
    """Stands in for jwt.PyJWKClient: always returns the test public key."""

    def __init__(self, public_key):
        self._key = _StubSigningKey(public_key)

    def get_signing_key_from_jwt(self, token):
        return self._key


@pytest.fixture(scope="session")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def make_token(rsa_key):
    """Returns a raw RS256 JWT string shaped like a Keycloak access token."""

    def _make(
        *,
        aud="core-read",
        scopes=(),
        exp_delta=300,
        azp="dev-tester",
        iss=ISSUER,
        key=None,
    ):
        now = int(time.time())
        claims = {
            "iss": iss,
            "aud": aud,
            "azp": azp,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + exp_delta,
        }
        return jwt.encode(
            claims, key or rsa_key, algorithm="RS256", headers={"kid": "test"}
        )

    return _make


@pytest.fixture
def verifier(rsa_key):
    return JwtTokenVerifier(
        ISSUER,
        "core-read",
        JWKS_URL,
        jwk_client=StubJWKClient(rsa_key.public_key()),
    )


# --- End-to-end fixtures: MCP server -> ApiClient -> mock-enterprise app -> Postgres ---

ENTERPRISE_SCOPES = [
    "members:read",
    "policies:read",
    "claims:read",
    "payments:read",
    "comms:read",
    "claims:write",
    "members:write",
    "comms:write",
]


@pytest.fixture(scope="session")
def pg_url():
    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest_asyncio.fixture
async def db_session(pg_url):
    """Fresh, seeded schema per test (order-independent); NullPool avoids cross-loop reuse."""
    engine = create_async_engine(pg_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await create_schema(engine)
    async with make_sessionmaker(engine)() as s:
        await seed(s, members=10)
        yield s
    await engine.dispose()


@pytest.fixture(scope="session")
def enterprise_token(rsa_key):
    """A mock-enterprise access token carrying every read and write scope."""
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": "mock-enterprise",
            "azp": "test-client",
            "scope": " ".join(ENTERPRISE_SCOPES),
            "iat": now,
            "exp": now + 3600,
        },
        rsa_key,
        algorithm="RS256",
        headers={"kid": "test"},
    )


@pytest_asyncio.fixture
async def api_client(pg_url, db_session, rsa_key, enterprise_token):
    """ApiClient talking in-process (ASGITransport) to the mock-enterprise app."""
    engine = create_async_engine(pg_url, poolclass=NullPool)
    app = create_app(
        Settings(
            database_url=pg_url,
            jwt_issuer=ISSUER,
            jwks_url="http://keycloak.test/jwks",
        ),
        jwk_client=StubJWKClient(rsa_key.public_key()),
        sessionmaker=make_sessionmaker(engine),
    )
    client = ApiClient(
        "http://test",
        StaticTokenProvider(enterprise_token),
        transport=httpx.ASGITransport(app=app),
    )
    yield client
    await client.aclose()
    await engine.dispose()


@pytest.fixture
def api_down_client(enterprise_token):
    """ApiClient whose upstream hangs; the 0.2 s timeout turns that into a 503."""

    async def hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200, json={})

    return ApiClient(
        "http://enterprise.invalid",
        StaticTokenProvider(enterprise_token),
        timeout_s=0.2,
        transport=httpx.MockTransport(hang),
    )


def _test_settings() -> ServerSettings:
    return ServerSettings(
        mock_api_url="http://test",
        token_url="http://keycloak.test/token",
        client_id="unused",
        client_secret="unused",
        jwt_issuer=ISSUER,
        jwks_url=JWKS_URL,
        mcp_audience="unused",
        port=0,
    )


async def _connected_session(module_name: str, api: ApiClient):
    """Yield a ClientSession connected in-memory to an unauthenticated server.

    Skips if the server module does not exist yet (core_write / comms land in
    later tasks).
    """
    try:
        module = importlib.import_module(f"toolgate_mcp_servers.{module_name}")
    except ModuleNotFoundError:
        pytest.skip(f"toolgate_mcp_servers.{module_name} not implemented yet")
    server = build_server(
        module.NAME, _test_settings(), module.register, api_client=api, with_auth=False
    )
    # The SDK's session context holds anyio cancel scopes, which must be exited by
    # the task that entered them. pytest-asyncio runs fixture setup and teardown in
    # different tasks, so a dedicated task owns the context for the whole fixture.
    ready: asyncio.Future = asyncio.get_running_loop().create_future()
    stop = asyncio.Event()

    async def _owner() -> None:
        try:
            async with create_connected_server_and_client_session(
                server._mcp_server
            ) as client_session:
                ready.set_result(client_session)
                await stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc)
            else:
                raise

    owner = asyncio.create_task(_owner())
    try:
        yield await ready
    finally:
        stop.set()
        await owner


@pytest_asyncio.fixture
async def core_read_session(api_client):
    async for s in _connected_session("core_read", api_client):
        yield s


@pytest_asyncio.fixture
async def core_read_session_api_down(api_down_client):
    async for s in _connected_session("core_read", api_down_client):
        yield s


@pytest_asyncio.fixture
async def core_write_session(api_client):
    async for s in _connected_session("core_write", api_client):
        yield s


@pytest_asyncio.fixture
async def comms_session(api_client):
    async for s in _connected_session("comms", api_client):
        yield s


@pytest.fixture
def sessions(core_read_session, core_write_session, comms_session):
    return {
        "core-read": core_read_session,
        "core-write": core_write_session,
        "comms": comms_session,
    }


@pytest_asyncio.fixture
async def canary_policy_id(db_session):
    return (
        await db_session.scalars(
            select(Policy.policy_id).where(Policy.member_id == "M-900001")
        )
    ).one()


@pytest_asyncio.fixture
async def canary_in_review_claim_id(db_session):
    return (
        await db_session.scalars(
            select(Claim.claim_id).where(
                Claim.member_id == "M-900001", Claim.status == "in_review"
            )
        )
    ).one()


@pytest.fixture(scope="session")
def make_cognito_token(rsa_key):
    """Returns a raw RS256 JWT string shaped like a Cognito access token."""

    def _make(
        scopes=("core-read/invoke",),
        *,
        token_use="access",
        client_id="cog-client",
        extra=None,
    ):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
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
    return JwtTokenVerifier(
        ISSUER,
        "core-read",
        JWKS_URL,
        jwk_client=StubJWKClient(rsa_key.public_key()),
        mode="cognito",
    )
