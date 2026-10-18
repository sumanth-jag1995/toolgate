import os
import time
from contextlib import asynccontextmanager

import anyio
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.client.session import ClientSession
from mcp.server.fastmcp import FastMCP
from mcp.shared.memory import create_client_server_memory_streams
from toolgate_gateway.auth import AgentTokenVerifier
from toolgate_gateway.pool import DownstreamPool
from toolgate_pin import LockfileStore, PinSet, Target
from toolgate_pin.pinning import pin_server

ISSUER = "http://keycloak.test/realms/toolgate"
JWKS_URL = "http://keycloak.test/realms/toolgate/protocol/openid-connect/certs"
AUDIENCE = "toolgate-gateway"


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
    """Returns a raw JWT string shaped like a Keycloak access token."""

    def _make(
        *,
        aud=AUDIENCE,
        scopes=(),
        exp_delta=300,
        azp="servicing",
        sub="agent-sub-1",
        iss=ISSUER,
        key=None,
        algorithm="RS256",
    ):
        now = int(time.time())
        claims = {
            "iss": iss,
            "aud": aud,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + exp_delta,
        }
        if azp is not None:
            claims["azp"] = azp
        if sub is not None:
            claims["sub"] = sub
        return jwt.encode(
            claims, key or rsa_key, algorithm=algorithm, headers={"kid": "test"}
        )

    return _make


@pytest.fixture
def verifier(rsa_key):
    return AgentTokenVerifier(
        ISSUER,
        AUDIENCE,
        JWKS_URL,
        jwk_client=StubJWKClient(rsa_key.public_key()),
    )


# -- in-memory downstreams and lockfiles (shared by pool and core tests) ----


def _build_core_write() -> FastMCP:
    server = FastMCP("core-write")

    @server.tool(name="log_claim", description="Log a new claim.")
    def log_claim(member_id: str, amount: float) -> dict:
        return {"member_id": member_id, "amount": amount, "logged": True}

    return server


class MemoryFactory:
    """In-memory SessionFactory.

    ``builders`` is either one FastMCP builder used for every server or a
    mapping server_id -> builder. ``fail`` maps server_id -> number of
    connection attempts that raise before one succeeds (-1 = always);
    server ids in ``down`` always fail; those in ``hang`` never connect."""

    def __init__(self, builders, *, fail=None, down=(), hang=(), delay=0.0):
        self.builders = builders if callable(builders) else dict(builders)
        self.fail = dict(fail or {})
        self.fail.update(dict.fromkeys(down, -1))
        self.hang = set(hang)
        self.delay = delay
        self.open = 0
        self.attempts: dict[str, int] = {}
        self.server_scopes: dict[str, anyio.CancelScope] = {}
        self.sessions: list[ClientSession] = []

    def _build(self, server_id: str) -> FastMCP:
        if callable(self.builders):
            return self.builders()
        return self.builders[server_id]()

    @asynccontextmanager
    async def __call__(self, config, *, message_handler=None):
        sid = config.server_id
        self.attempts[sid] = self.attempts.get(sid, 0) + 1
        left = self.fail.get(sid, 0)
        if left:
            if left > 0:
                self.fail[sid] = left - 1
            raise ConnectionError(f"{sid} is down")
        if sid in self.hang:
            await anyio.sleep_forever()
        await anyio.sleep(self.delay)
        lowlevel = self._build(sid)._mcp_server
        async with (
            create_client_server_memory_streams() as (client, srv),
            anyio.create_task_group() as tg,
        ):
            scope = anyio.CancelScope()

            async def run_server():
                with scope:
                    await lowlevel.run(
                        srv[0], srv[1], lowlevel.create_initialization_options()
                    )

            tg.start_soon(run_server)
            self.server_scopes[sid] = scope
            try:
                async with ClientSession(
                    client[0], client[1], message_handler=message_handler
                ) as session:
                    init = await session.initialize()
                    self.sessions.append(session)
                    self.open += 1
                    try:
                        yield session, init
                    finally:
                        self.open -= 1
            finally:
                tg.cancel_scope.cancel()


async def _live_tools(builders, configs) -> dict:
    """``{server_id: (server_name, tools)}`` as seen through a real session."""
    pool = DownstreamPool(configs, MemoryFactory(builders))
    try:
        out = {}
        for c in configs:
            info, tools = await pool.list_tools(c.server_id)
            out[c.server_id] = (info.name, tools)
        return out
    finally:
        await pool.close()


async def _write_lockfile(path, builders, configs, *, skip=(), server_names=None):
    """Pin every tool served by ``builders`` for ``configs`` except ``skip``
    (``server.tool``); ``server_names`` overrides pinned server names."""
    urls = {c.server_id: c.url for c in configs}
    pins = PinSet({})
    for sid, (name, tools) in (await _live_tools(builders, configs)).items():
        kept = [t for t in tools if f"{sid}.{t.name}" not in skip]
        name = (server_names or {}).get(sid, name)
        sp = pin_server(sid, name, Target(url=urls[sid]), kept, approved_by="test")
        pins = pins.with_server(sp)
    LockfileStore(path).save(pins)
    if path.exists():  # force a visible (mtime, size) change on rewrite
        st = path.stat()
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000))


@pytest.fixture(scope="session")
def memory_factory_cls():
    return MemoryFactory


@pytest.fixture(scope="session")
def build_core_write():
    return _build_core_write


@pytest.fixture(scope="session")
def write_lockfile():
    return _write_lockfile
