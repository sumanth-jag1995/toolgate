import os

os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

import time

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from mock_enterprise.app import create_app
from mock_enterprise.db import create_schema, make_sessionmaker
from mock_enterprise.models import Base, Policy
from mock_enterprise.seed import seed
from mock_enterprise.settings import Settings
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer

ISSUER = "http://keycloak.test/realms/toolgate"
READ_SCOPES = [
    "members:read",
    "policies:read",
    "claims:read",
    "payments:read",
    "comms:read",
]


@pytest.fixture(scope="session")
def pg_url():
    with PostgresContainer("postgres:16-alpine", driver="asyncpg") as pg:
        yield pg.get_connection_url()


@pytest_asyncio.fixture
async def session(pg_url):
    """Fresh schema per test (order-independent); NullPool avoids cross-loop reuse."""
    engine = create_async_engine(pg_url, poolclass=NullPool)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await create_schema(engine)
    async with make_sessionmaker(engine)() as s:
        yield s
    await engine.dispose()


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
    def _make(scopes, *, aud="mock-enterprise", exp_delta=300, azp="test-client"):
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": aud,
            "azp": azp,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + exp_delta,
        }
        token = jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "test"})
        return {"Authorization": f"Bearer {token}"}

    return _make


@pytest.fixture
def read_headers(make_token):
    return make_token(READ_SCOPES)


@pytest.fixture
def write_headers(make_token):
    return make_token(["claims:write", "members:write", "comms:write"])


@pytest_asyncio.fixture
async def client(pg_url, session, rsa_key):
    """App wired to the per-test seeded schema (session fixture resets it)."""
    await seed(session, members=10)
    engine = create_async_engine(pg_url, poolclass=NullPool)
    settings = Settings(
        database_url=pg_url,
        jwt_issuer=ISSUER,
        jwks_url="http://keycloak.test/jwks",
    )
    app = create_app(
        settings,
        jwk_client=StubJWKClient(rsa_key.public_key()),
        sessionmaker=make_sessionmaker(engine),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    await engine.dispose()


@pytest_asyncio.fixture
async def canary_policy_id(session):
    return (
        await session.scalars(
            select(Policy.policy_id).where(Policy.member_id == "M-900001")
        )
    ).one()
