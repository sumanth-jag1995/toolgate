"""The authenticated streamable-HTTP MCP endpoint, end to end: uvicorn on a
random port, a real MCP client, the test RSA verifier and in-memory (or real
HTTP) downstreams pinned in a lockfile."""

import asyncio
import json
import logging
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
import pytest
import uvicorn
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import TextContent
from toolgate_gateway.app import build_app
from toolgate_gateway.core import GatewayCore
from toolgate_gateway.downstreams import DownstreamConfig
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist
from toolgate_gateway.pool import DownstreamPool, http_session_factory
from toolgate_gateway.settings import GatewaySettings
from toolgate_pin.demo_server import build_demo_server

ISSUER = "http://keycloak.test/realms/toolgate"
HMAC_KEY = "k" * 32

CONFIGS = [
    DownstreamConfig("core-read", "http://core-read.test/mcp"),
    DownstreamConfig("core-write", "http://core-write.test/mcp"),
    DownstreamConfig("comms", "http://comms.test/mcp"),
]

ALLOWLIST = Allowlist(
    {
        "servicing": ("core-read.*", "comms.*"),
        "claims-intake": ("core-read.get_claim_status", "core-write.log_claim"),
    }
)

MCP_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "probe", "version": "0"},
    },
}
MCP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class FakeAudit:
    """AuditWriter stand-in: records rows and its lifecycle."""

    def __init__(self) -> None:
        self.records = []
        self.events: list[str] = []
        self.accepting = True

    async def start(self) -> None:
        self.events.append("start")

    async def stop(self) -> None:
        self.events.append("stop")

    def submit(self, rec) -> bool:
        self.records.append(rec)
        return True


def spy_factory_cls(base):
    class SpyFactory(base):
        """MemoryFactory that records every tools/call forwarded downstream."""

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.calls: list[tuple] = []

        @asynccontextmanager
        async def __call__(self, config, *, message_handler=None):
            opened = base.__call__(self, config, message_handler=message_handler)
            async with opened as (session, init):
                original = session.call_tool

                async def call_tool(name, arguments=None, *args, **kwargs):
                    self.calls.append((config.server_id, name, arguments, args, kwargs))
                    return await original(name, arguments, *args, **kwargs)

                session.call_tool = call_tool
                yield session, init

    return SpyFactory


@dataclass
class Gateway:
    base_url: str
    core: GatewayCore
    audit: FakeAudit
    pool: DownstreamPool
    factory: object

    @property
    def mcp_url(self) -> str:
        return f"{self.base_url}/mcp"


def make_settings(tmp_path, port: int, **overrides) -> GatewaySettings:
    return GatewaySettings(
        issuer=ISSUER,
        jwks_url=f"{ISSUER}/protocol/openid-connect/certs",
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


def assert_token_absent(token: str, text: str) -> None:
    """Neither the raw token nor any of its JWT segments appears in ``text``."""
    for part in (token, *token.split(".")):
        assert part not in text


@pytest.fixture
def builders(build_core_write):
    return {
        "core-read": build_demo_server,
        "core-write": build_core_write,
        "comms": build_demo_server,
    }


@pytest.fixture
async def gateway(tmp_path, memory_factory_cls, write_lockfile, builders, verifier):
    running = []

    async def start(*, down=(), configs=CONFIGS, factory=None, audit=None, **settings):
        lock = tmp_path / "toolgate.lock.json"
        await write_lockfile(lock, builders, configs)
        if factory is None:
            factory = spy_factory_cls(memory_factory_cls)(builders, down=down)
        pool = DownstreamPool(configs, factory)
        audit = FakeAudit() if audit is None else audit
        core = GatewayCore(
            pool, PinSource(lock), ALLOWLIST, audit, None, hmac_key=HMAC_KEY
        )
        port = _free_port()
        app = build_app(core, verifier, make_settings(tmp_path, port, **settings))
        server = uvicorn.Server(
            uvicorn.Config(
                app, host="127.0.0.1", port=port, log_level="error", lifespan="on"
            )
        )
        task = asyncio.create_task(server.serve())
        while not server.started:
            if task.done():
                task.result()
                pytest.fail("gateway exited during startup")
            await asyncio.sleep(0.01)
        gw = Gateway(f"http://127.0.0.1:{port}", core, audit, pool, factory)
        running.append((server, task, gw))
        return gw

    yield start
    for server, task, gw in running:
        server.should_exit = True
        await task
        # Lifespan shutdown stopped what it started.
        if isinstance(gw.audit, FakeAudit):
            assert gw.audit.events == ["start", "stop"]
        else:
            assert not gw.audit.accepting
        assert not gw.pool._conns


@asynccontextmanager
async def mcp_session(url: str, token: str):
    async with (
        httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=30
        ) as http,
        streamable_http_client(url, http_client=http) as (read, write, _),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        yield session


async def test_unauthenticated_401_with_resource_metadata(gateway):
    gw = await gateway()
    async with httpx.AsyncClient() as http:
        resp = await http.post(gw.mcp_url, json=MCP_INIT, headers=MCP_HEADERS)
        assert resp.status_code == 401
        challenge = resp.headers["www-authenticate"]
        assert challenge.startswith("Bearer ")
        metadata_url = f"{gw.base_url}/.well-known/oauth-protected-resource/mcp"
        assert f'resource_metadata="{metadata_url}"' in challenge

        meta = await http.get(metadata_url)
    assert meta.status_code == 200
    body = meta.json()
    assert body["resource"] == gw.mcp_url
    assert body["authorization_servers"] == [ISSUER]


async def test_malformed_and_foreign_tokens_401(gateway, make_token, rsa_key):
    from cryptography.hazmat.primitives.asymmetric import rsa

    gw = await gateway()
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad = [
        "not-a-jwt",
        make_token(key=other_key),  # signed by someone else
        make_token(iss="http://evil.test/realms/toolgate"),
        make_token(azp=None),  # no client id
    ]
    async with httpx.AsyncClient() as http:
        for token in bad:
            resp = await http.post(
                gw.mcp_url,
                json=MCP_INIT,
                headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 401
            assert "resource_metadata=" in resp.headers["www-authenticate"]


async def test_wrong_audience_401_nothing_forwarded(gateway, make_token, caplog):
    caplog.set_level(logging.DEBUG)
    gw = await gateway()
    token = make_token(aud="core-read")
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "core-read.get_claim_status",
            "arguments": {"claim_id": "C"},
        },
    }
    async with httpx.AsyncClient() as http:
        for body in (MCP_INIT, call):
            resp = await http.post(
                gw.mcp_url,
                json=body,
                headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
            )
            assert resp.status_code == 401
            assert_token_absent(token, resp.text + str(resp.headers))
    assert gw.factory.calls == []
    assert gw.audit.records == []
    assert_token_absent(token, caplog.text)


async def test_expired_token_401(gateway, make_token, caplog):
    caplog.set_level(logging.DEBUG)
    gw = await gateway()
    token = make_token(exp_delta=-60)
    async with httpx.AsyncClient() as http:
        resp = await http.post(
            gw.mcp_url,
            json=MCP_INIT,
            headers={**MCP_HEADERS, "Authorization": f"Bearer {token}"},
        )
    assert resp.status_code == 401
    assert 'error="invalid_token"' in resp.headers["www-authenticate"]
    assert gw.factory.calls == []
    assert_token_absent(token, resp.text + str(resp.headers))
    assert_token_absent(token, caplog.text)


async def test_get_and_delete_without_token_401(gateway):
    gw = await gateway()
    async with httpx.AsyncClient() as http:
        get = await http.get(gw.mcp_url, headers={"Accept": "text/event-stream"})
        delete = await http.delete(gw.mcp_url, headers={"mcp-session-id": "x" * 32})
    for resp in (get, delete):
        assert resp.status_code == 401
        assert "resource_metadata=" in resp.headers["www-authenticate"]


@pytest.mark.parametrize(
    "intruder",
    [
        {"azp": "claims-intake"},  # another agent client
        {"azp": "servicing", "sub": "agent-sub-2"},  # same client, other subject
    ],
)
async def test_session_bound_to_its_principal(gateway, make_token, intruder):
    """A valid token for a different principal cannot use another caller's
    MCP session: 404 (as if it did not exist) and nothing is forwarded."""
    gw = await gateway()
    owner = make_token(azp="servicing", sub="agent-sub-1")
    call = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "core-read.get_claim_status",  # allowed for both clients
            "arguments": {"claim_id": "C-1"},
        },
    }
    async with (
        httpx.AsyncClient(headers={"Authorization": f"Bearer {owner}"}) as http,
        streamable_http_client(gw.mcp_url, http_client=http) as (read, write, sid),
        ClientSession(read, write) as session,
    ):
        init = await session.initialize()
        await session.list_tools()
        session_id = sid()
        assert session_id
        async with httpx.AsyncClient() as other:
            resp = await other.post(
                gw.mcp_url,
                json=call,
                headers={
                    **MCP_HEADERS,
                    "Authorization": f"Bearer {make_token(**intruder)}",
                    "mcp-session-id": session_id,
                    "mcp-protocol-version": str(init.protocolVersion),
                },
            )
        assert resp.status_code == 404
        assert gw.factory.calls == []
        assert gw.audit.records == []
        # The owner's session still works.
        result = await session.call_tool(
            "core-read.get_claim_status", {"claim_id": "C-1"}
        )
        assert not result.isError
    assert len(gw.factory.calls) == 1


async def test_max_sessions_enforced(gateway, make_token):
    gw = await gateway(max_sessions=1)
    async with mcp_session(gw.mcp_url, make_token()):
        async with httpx.AsyncClient() as http:
            resp = await http.post(
                gw.mcp_url,
                json=MCP_INIT,
                headers={**MCP_HEADERS, "Authorization": f"Bearer {make_token()}"},
            )
        assert resp.status_code == 503


async def test_starts_with_db_unreachable_lists_but_refuses_calls(gateway, make_token):
    from toolgate_gateway.audit import AuditWriter
    from toolgate_gateway.db import create_pool

    # Nothing listens on this port: creating the pool must not connect.
    db = await create_pool(
        f"postgresql://app:pw@127.0.0.1:{_free_port()}/toolgate", min_size=0
    )
    try:
        audit = AuditWriter(db, probe_min_s=0.05, probe_max_s=0.1)
        gw = await gateway(audit=audit)
        async with mcp_session(gw.mcp_url, make_token(azp="servicing")) as session:
            names = {t.name for t in (await session.list_tools()).tools}
            result = await session.call_tool(
                "core-read.get_claim_status", {"claim_id": "C-1"}
            )
        assert "core-read.get_claim_status" in names
        assert result.isError
        assert isinstance(result.content[0], TextContent)
        assert result.content[0].text == "audit log unavailable; call refused"
        assert gw.factory.calls == []
    finally:
        await db.close()


async def test_servicing_lists_namespaced_tools(gateway, make_token):
    gw = await gateway()
    async with mcp_session(gw.mcp_url, make_token(azp="servicing")) as session:
        names = {t.name for t in (await session.list_tools()).tools}
    assert names == {
        f"{sid}.{tool}"
        for sid in ("core-read", "comms")
        for tool in (
            "get_claim_status",
            "get_member_profile",
            "check_coverage",
            "send_member_message",
        )
    }

    async with mcp_session(gw.mcp_url, make_token(azp="claims-intake")) as session:
        names = {t.name for t in (await session.list_tools()).tools}
    assert names == {"core-read.get_claim_status", "core-write.log_claim"}

    async with mcp_session(gw.mcp_url, make_token(azp="unknown-agent")) as session:
        assert (await session.list_tools()).tools == []


async def test_call_round_trip(gateway, make_token):
    gw = await gateway()
    async with mcp_session(gw.mcp_url, make_token(azp="servicing")) as session:
        result = await session.call_tool(
            "core-read.get_claim_status", {"claim_id": "C-1"}
        )
    assert not result.isError
    assert isinstance(result.content[0], TextContent)
    assert json.loads(result.content[0].text) == {
        "claim_id": "C-1",
        "status": "approved",
        "amount": 1250.0,
    }
    assert [c[:3] for c in gw.factory.calls] == [
        ("core-read", "get_claim_status", {"claim_id": "C-1"})
    ]
    [rec] = gw.audit.records
    assert (rec.client_id, rec.agent_id, rec.decision) == (
        "servicing",
        "agent-sub-1",
        "allow",
    )


async def test_agent_id_falls_back_to_client_id(gateway, make_token):
    gw = await gateway()
    async with mcp_session(gw.mcp_url, make_token(sub=None)) as session:
        result = await session.call_tool(
            "core-read.get_claim_status", {"claim_id": "C-1"}
        )
    assert not result.isError
    [rec] = gw.audit.records
    assert rec.agent_id == "servicing"


async def test_denied_call_is_a_tool_error_not_forwarded(gateway, make_token):
    gw = await gateway()
    async with mcp_session(gw.mcp_url, make_token(azp="servicing")) as session:
        result = await session.call_tool("core-write.log_claim", {"member_id": "M"})
    assert result.isError
    assert isinstance(result.content[0], TextContent)
    assert result.content[0].text == "tool not permitted for this agent"
    assert gw.factory.calls == []
    assert [r.decision for r in gw.audit.records] == ["deny_scope"]


async def test_starts_with_downstream_down(gateway, make_token):
    gw = await gateway(down=("comms",))
    async with mcp_session(gw.mcp_url, make_token(azp="servicing")) as session:
        names = {t.name for t in (await session.list_tools()).tools}
        result = await session.call_tool("comms.send_member_message", {})
    assert names and all(n.startswith("core-read.") for n in names)
    assert result.isError
    assert gw.audit.records[-1].decision == "error_downstream"


# --- the agent token never reaches a downstream ---------------------------


class StaticAuth(httpx.Auth):
    def __init__(self, token: str) -> None:
        self.token = token

    async def async_auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


@pytest.fixture
async def recording_downstream():
    """A real streamable-HTTP demo server that records every request's
    headers and body."""
    app = build_demo_server().streamable_http_app()
    seen: list[tuple[dict[bytes, bytes], bytes]] = []

    async def recording_app(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return
        entry = (dict(scope["headers"]), bytearray())
        seen.append(entry)

        async def recv():
            message = await receive()
            if message["type"] == "http.request":
                entry[1].extend(message.get("body", b""))
            return message

        await app(scope, recv, send)

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(recording_app, host="127.0.0.1", port=port, log_level="error")
    )
    task = asyncio.create_task(server.serve())
    while not server.started:
        await asyncio.sleep(0.01)
    yield f"http://127.0.0.1:{port}/mcp", seen
    server.should_exit = True
    await task


async def test_agent_token_never_forwarded(
    recording_downstream, gateway, make_token, caplog
):
    # recording_downstream is requested first so it is torn down after the
    # gateway has closed its sessions to it.
    url, seen = recording_downstream
    configs = [DownstreamConfig("core-read", url)]
    gw = await gateway(
        configs=configs, factory=http_session_factory(StaticAuth("gateway-own-token"))
    )
    agent_token = make_token(azp="servicing")
    caplog.set_level(logging.DEBUG)
    async with mcp_session(gw.mcp_url, agent_token) as session:
        listed = {t.name for t in (await session.list_tools()).tools}
        result = await session.call_tool(
            "core-read.get_claim_status", {"claim_id": "C-9"}
        )
    assert "core-read.get_claim_status" in listed
    assert not result.isError

    assert seen, "downstream saw no requests"
    bodies = [bytes(body) for _, body in seen]
    assert any(b'"tools/call"' in b for b in bodies)
    # Every downstream request carries the gateway's own token, never the agent's.
    payload_parts = (agent_token, *agent_token.split("."))
    for headers, body in seen:
        assert headers[b"authorization"] == b"Bearer gateway-own-token"
        blob = b"\n".join(k + b": " + v for k, v in headers.items()) + b"\n" + body
        for part in payload_parts:
            assert part.encode() not in blob
    # Nor is it logged.
    assert agent_token not in caplog.text
    assert json.dumps(agent_token)[1:-1] not in caplog.text


# --- CLI ----------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_admin_dsn():
    import os

    os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine") as pg:
        yield pg.get_connection_url(driver=None)


def _app_dsn(admin_dsn: str, password: str) -> str:
    from urllib.parse import quote, urlsplit

    u = urlsplit(admin_dsn)
    return (
        f"postgresql://toolgate_gateway_app:{quote(password, safe='')}"
        f"@{u.hostname}:{u.port}{u.path}"
    )


def test_cli_migrate_reads_password_from_env(pg_admin_dsn, monkeypatch, capsys):
    from toolgate_gateway import cli

    monkeypatch.delenv("GATEWAY_DB_PASSWORD", raising=False)
    args = ["migrate", "--admin-dsn", pg_admin_dsn]
    args += ["--app-password-env", "GATEWAY_DB_PASSWORD"]
    assert cli.main(args) == 2
    assert "GATEWAY_DB_PASSWORD" in capsys.readouterr().err

    monkeypatch.setenv("GATEWAY_DB_PASSWORD", "app-pw-from-env")
    assert cli.main(args) == 0

    async def can_connect():
        import asyncpg

        conn = await asyncpg.connect(_app_dsn(pg_admin_dsn, "app-pw-from-env"))
        await conn.close()

    asyncio.run(can_connect())


def test_cli_migrate_admin_dsn_from_env(pg_admin_dsn, monkeypatch, capsys):
    from toolgate_gateway import cli

    monkeypatch.setenv("GATEWAY_DB_PASSWORD", "app-pw-from-env")
    args = ["migrate", "--admin-dsn-env", "TOOLGATE_ADMIN_DSN"]
    monkeypatch.delenv("TOOLGATE_ADMIN_DSN", raising=False)
    assert cli.main(args) == 2
    assert "TOOLGATE_ADMIN_DSN" in capsys.readouterr().err
    monkeypatch.setenv("TOOLGATE_ADMIN_DSN", pg_admin_dsn)
    assert cli.main(args) == 0
    with pytest.raises(SystemExit):  # exactly one DSN source
        cli.main([*args, "--admin-dsn", pg_admin_dsn])
    with pytest.raises(SystemExit):
        cli.main(["migrate"])


def test_cli_reviews_lists_open(pg_admin_dsn, monkeypatch, capsys):
    from toolgate_gateway import cli
    from toolgate_gateway.db import create_pool
    from toolgate_gateway.reviews import PendingReviews

    monkeypatch.setenv("GATEWAY_DB_PASSWORD", "app-pw-from-env")
    assert cli.main(["migrate", "--admin-dsn", pg_admin_dsn]) == 0
    app_dsn = _app_dsn(pg_admin_dsn, "app-pw-from-env")

    async def seed():
        pool = await create_pool(app_dsn)
        try:
            reviews = PendingReviews(pool)
            await reviews.record(
                "core-read",
                "get_claim_status",
                "sha256:new",
                "sha256:old",
                "drift",
                "- Look up a claim.\n+ Look up a claim.\u200b\x1b[2J",
                [{"rule_id": "hidden-unicode"}],
            )
            await reviews.record(
                "comms", "old_tool", "sha256:gone", None, "unpinned", None, []
            )
            await pool.execute(
                "UPDATE gateway.pending_reviews SET status = 'resolved' "
                "WHERE tool_name = 'old_tool'"
            )
        finally:
            await pool.close()

    asyncio.run(seed())
    capsys.readouterr()

    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert cli.main(["reviews"]) == 2
    assert "DATABASE_URL" in capsys.readouterr().err

    monkeypatch.setenv("DATABASE_URL", app_dsn)
    assert cli.main(["reviews"]) == 0
    out = capsys.readouterr().out
    assert "core-read.get_claim_status" in out
    assert "drift" in out
    assert "sha256:old" in out and "sha256:new" in out
    assert "hidden-unicode" in out
    assert "U+200B" in out  # hidden character revealed
    assert "\u200b" not in out
    assert "\x1b" not in out  # control characters cannot reach the terminal
    assert "old_tool" not in out  # resolved reviews are not listed


@pytest.fixture
def serve_env(tmp_path, monkeypatch):
    (tmp_path / "agents.yaml").write_text(
        "agents:\n  servicing: ['core-read.*']\n", encoding="utf-8"
    )
    (tmp_path / "gateway.yaml").write_text(
        "downstreams:\n  - server_id: core-read\n    url: http://127.0.0.1:9/mcp\n",
        encoding="utf-8",
    )
    # Nothing listens on the DB port: serve must still start.
    dsn = f"postgresql://app:pw@127.0.0.1:{_free_port()}/toolgate"
    env = {
        "GATEWAY_ISSUER": ISSUER,
        "GATEWAY_JWKS_URL": f"{ISSUER}/certs",
        "GATEWAY_TOKEN_URL": f"{ISSUER}/token",
        "GATEWAY_CLIENT_SECRET": "s3cret",
        "DATABASE_URL": dsn,
        "AUDIT_HMAC_KEY": HMAC_KEY,
        "GATEWAY_LOCKFILE_PATH": str(tmp_path / "toolgate.lock.json"),
        "GATEWAY_POLICY_PATH": str(tmp_path / "agents.yaml"),
        "GATEWAY_DOWNSTREAMS_PATH": str(tmp_path / "gateway.yaml"),
        "GATEWAY_HOST": "127.0.0.1",
        "GATEWAY_PORT": "8299",
    }
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return env


def test_cli_serve_builds_from_settings_with_db_down(serve_env, monkeypatch):
    from starlette.applications import Starlette
    from toolgate_gateway import cli

    seen = {}
    real_create_pool = cli.create_pool

    async def spy_create_pool(dsn, **kwargs):
        seen["dsn"], seen["kwargs"] = dsn, kwargs
        seen["db"] = await real_create_pool(dsn, **kwargs)  # must not connect
        return seen["db"]

    async def fake_serve(self, sockets=None):
        seen["config"] = self.config

    monkeypatch.setattr(cli, "create_pool", spy_create_pool)
    monkeypatch.setattr(uvicorn.Server, "serve", fake_serve)

    assert cli.main(["serve"]) == 0
    config = seen["config"]
    assert (config.host, config.port) == ("127.0.0.1", 8299)
    assert isinstance(config.app, Starlette)
    assert seen["dsn"] == serve_env["DATABASE_URL"]
    assert seen["kwargs"] == {"min_size": 0}
    assert seen["db"]._closed


def test_cli_serve_unexpected_error_prints_type_only(serve_env, monkeypatch, capsys):
    from toolgate_gateway import cli

    async def failing_serve(self, sockets=None):
        raise RuntimeError("leaky-detail s3cret")

    monkeypatch.setattr(uvicorn.Server, "serve", failing_serve)
    assert cli.main(["serve"]) == 1
    err = capsys.readouterr().err
    assert "RuntimeError" in err
    assert "leaky-detail" not in err and "s3cret" not in err


def test_cli_serve_reports_missing_settings_without_values(monkeypatch, capsys):
    from toolgate_gateway import cli

    for k in ("GATEWAY_ISSUER", "GATEWAY_JWKS_URL", "GATEWAY_TOKEN_URL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GATEWAY_CLIENT_SECRET", "do-not-print-me")
    assert cli.main(["serve"]) == 2
    err = capsys.readouterr().err
    assert "issuer" in err
    assert "do-not-print-me" not in err
