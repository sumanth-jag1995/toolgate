"""End-to-end smoke test of sub-project B: the Toolgate gateway in the compose stack.

Run after `docker compose --env-file .env -f infra/docker-compose.yml up -d --build`
and `scripts/pin_servers.py` (or with the committed lockfile). Reads from the
local .env only the client secrets it needs (servicing, fraud-triage,
dev-tester) and POSTGRES_PASSWORD for the admin audit queries; never prints
them or any token. Exits non-zero on any failure.
"""

import asyncio
import base64
import json
import re
import subprocess
import sys
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import asyncpg
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ROOT = Path(__file__).resolve().parent.parent
TOKEN_URL = "http://localhost:8080/realms/toolgate/protocol/openid-connect/token"
GATEWAY_URL = "http://localhost:8200/mcp"
TEMPO_SEARCH = "http://localhost:3200/api/search"
ADMIN_DSN = "postgresql://postgres:{pw}@localhost:5432/toolgate"
CANARY = "TG-CANARY-7Q4X9"
NAMESPACED = re.compile(r"^(core-read|core-write|comms)\.[a-z_]+$")
COMPOSE = [
    "docker",
    "compose",
    "--env-file",
    ".env",
    "-f",
    "infra/docker-compose.yml",
]
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}")
    if not ok:
        failures.append(name)


def read_env(*keys: str) -> dict[str, str]:
    wanted = set(keys)
    found: dict[str, str] = {}
    for line in (ROOT / ".env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key in wanted:
            found[key] = value
    missing = wanted - found.keys()
    if missing:
        raise SystemExit(
            f"missing from .env: {sorted(missing)} "
            "(run scripts/gen_dev_env.py --add-missing)"
        )
    return found


def claims(token: str) -> dict[str, Any]:
    """The token's payload, unverified: only to assert its audience."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


async def mint(http: httpx.AsyncClient, client_id: str, secret: str) -> str:
    resp = await http.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": secret,
        },
    )
    if resp.status_code != 200:
        raise SystemExit(f"{client_id} token request failed: HTTP {resp.status_code}")
    return resp.json()["access_token"]


@asynccontextmanager
async def gateway(token: str):
    headers = {"Authorization": f"Bearer {token}"}
    async with (
        streamablehttp_client(GATEWAY_URL, headers=headers) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()
        yield session


def result_text(result: Any) -> str:
    parts = [getattr(c, "text", "") for c in result.content or []]
    if result.structuredContent is not None:
        parts.append(json.dumps(result.structuredContent))
    return " ".join(parts)


async def audit_state(dsn: str) -> tuple[int, int]:
    conn = await asyncpg.connect(dsn)
    try:
        row = await conn.fetchrow(
            "SELECT count(*) AS n, coalesce(max(id), 0) AS max_id"
            " FROM gateway.audit_log"
        )
        return int(row["n"]), int(row["max_id"])
    finally:
        await conn.close()


async def audit_rows_after(dsn: str, after_id: int) -> list[asyncpg.Record]:
    conn = await asyncpg.connect(dsn)
    try:
        return await conn.fetch(
            "SELECT id, client_id, tool, decision, args_hmac FROM gateway.audit_log"
            " WHERE id > $1 ORDER BY id",
            after_id,
        )
    finally:
        await conn.close()


async def app_role_denied(dsn: str, statement: str, row_id: int) -> bool:
    """True when the gateway app role is refused ``statement`` on audit_log."""
    conn = await asyncpg.connect(dsn)
    try:
        tx = conn.transaction()
        await tx.start()
        try:
            await conn.execute("SET LOCAL ROLE toolgate_gateway_app")
            await conn.execute(statement, row_id)
        except asyncpg.InsufficientPrivilegeError:
            return True
        finally:
            await tx.rollback()
        return False
    finally:
        await conn.close()


async def tempo_trace_count(since: float, deadline_s: float = 45.0) -> int:
    query = '{ resource.service.name = "toolgate-gateway" }'
    async with httpx.AsyncClient(timeout=10) as http:
        end_by = time.monotonic() + deadline_s
        while True:
            resp = await http.get(
                TEMPO_SEARCH,
                params={
                    "q": query,
                    "start": int(since) - 5,
                    "end": int(time.time()) + 5,
                    "limit": 50,
                },
            )
            n = len(resp.json().get("traces") or []) if resp.status_code == 200 else 0
            if n or time.monotonic() > end_by:
                return n
            await asyncio.sleep(3)


async def main() -> None:
    started = time.time()
    env = read_env(
        "SERVICING_CLIENT_SECRET",
        "FRAUD_TRIAGE_CLIENT_SECRET",
        "DEV_TESTER_CLIENT_SECRET",
        "POSTGRES_PASSWORD",
    )
    dsn = ADMIN_DSN.format(pw=env["POSTGRES_PASSWORD"])
    count_before, max_id_before = await audit_state(dsn)

    async with httpx.AsyncClient(timeout=10) as http:
        servicing = await mint(http, "servicing", env["SERVICING_CLIENT_SECRET"])
        fraud = await mint(http, "fraud-triage", env["FRAUD_TRIAGE_CLIENT_SECRET"])
        dev = await mint(http, "dev-tester", env["DEV_TESTER_CLIENT_SECRET"])

        # 1. servicing lists namespaced tools, never core-write.log_claim.
        try:
            async with gateway(servicing) as session:
                names = [t.name for t in (await session.list_tools()).tools]
            check(
                "servicing lists namespaced tools",
                bool(names) and all(NAMESPACED.match(n) for n in names),
                f"{len(names)} tools",
            )
            check(
                "servicing does not see core-write.log_claim",
                "core-write.log_claim" not in names,
            )
        except Exception as exc:  # noqa: BLE001
            check("servicing lists tools", False, type(exc).__name__)

        # 2. servicing reads the canary profile through the gateway.
        try:
            async with gateway(servicing) as session:
                res = await session.call_tool(
                    "core-read.get_member_profile", {"member_id": "M-900001"}
                )
            check(
                "servicing core-read.get_member_profile returns canary",
                not res.isError and CANARY in result_text(res),
            )
        except Exception as exc:  # noqa: BLE001
            check("servicing get_member_profile", False, type(exc).__name__)

        # 2b. A clean allowed call: audited as `allow` (checked in 7).
        try:
            async with gateway(servicing) as session:
                res = await session.call_tool(
                    "core-read.get_claim_status", {"claim_id": "C-900001"}
                )
            check(
                "servicing core-read.get_claim_status returns the claim",
                not res.isError and "C-900001" in result_text(res),
            )
        except Exception as exc:  # noqa: BLE001
            check("servicing get_claim_status", False, type(exc).__name__)

        # 3. fraud-triage may not call core-write.log_claim.
        try:
            async with gateway(fraud) as session:
                res = await session.call_tool(
                    "core-write.log_claim",
                    {
                        "member_id": "M-900001",
                        "policy_id": "P-000001",
                        "procedure_code": "mri_scan",
                        "incident_date": "2026-01-01",
                        "amount_pence": 100,
                        "idempotency_key": str(uuid.uuid4()),
                    },
                )
            check(
                "fraud-triage core-write.log_claim is refused (isError)",
                bool(res.isError),
                result_text(res)[:80],
            )
        except Exception as exc:  # noqa: BLE001
            check("fraud-triage log_claim", False, type(exc).__name__)

        # 4. A core-read audience token (dev-tester: aud core-read/core-write/
        #    comms, not toolgate-gateway) is rejected with 401.
        aud = claims(dev).get("aud")
        auds = set(aud if isinstance(aud, list) else [aud])
        resp = await http.post(
            GATEWAY_URL,
            headers={
                "Authorization": f"Bearer {dev}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "smoke-b", "version": "0"},
                },
            },
        )
        check(
            "core-read audience token gets HTTP 401",
            "core-read" in auds
            and "toolgate-gateway" not in auds
            and resp.status_code == 401
            and "www-authenticate" in resp.headers,
            f"aud={sorted(auds)} HTTP {resp.status_code}",
        )

    # 5. An extra argument is refused before any downstream call.
    try:
        async with gateway(servicing) as session:
            res = await session.call_tool(
                "core-read.get_member_profile",
                {"member_id": "M-900001", "smuggled": "x"},
            )
        check(
            "extra argument is refused (isError)",
            bool(res.isError) and CANARY not in result_text(res),
            result_text(res)[:80],
        )
    except Exception as exc:  # noqa: BLE001
        check("extra argument", False, type(exc).__name__)

    # 6. `toolgate-gateway reviews` runs (in the gateway container, app role).
    proc = await asyncio.to_thread(
        subprocess.run,
        [*COMPOSE, "exec", "-T", "gateway", "toolgate-gateway", "reviews"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    lines = proc.stdout.splitlines()
    check(
        "toolgate-gateway reviews runs",
        proc.returncode == 0,
        f"exit {proc.returncode}; {lines[0][:70] if lines else 'no output'}",
    )

    # 7. The audit log grew by one row per audited call (4 tools/call above),
    #    with the expected decisions, and the app role cannot alter it.
    rows: list[asyncpg.Record] = []
    for _ in range(30):  # the writer flushes every 100 ms
        rows = await audit_rows_after(dsn, max_id_before)
        if len(rows) >= 4:
            break
        await asyncio.sleep(0.2)
    count_after, _ = await audit_state(dsn)
    decisions = {(r["client_id"], r["tool"], r["decision"]) for r in rows}
    check(
        "gateway.audit_log count grew",
        count_after >= count_before + 4,
        f"{count_before} -> {count_after}",
    )
    profile = "core-read.get_member_profile"
    # The delivered canary profile is `allow`, or `flag_output` when the
    # output scanner flags (but still returns) its contact details.
    delivered = {("servicing", profile, d) for d in ("allow", "flag_output")}
    check(
        "audit rows carry the expected decisions",
        bool(delivered & decisions)
        and {
            ("fraud-triage", "core-write.log_claim", "deny_scope"),
            ("servicing", profile, "deny_schema"),
        }
        <= decisions,
        ", ".join(sorted(d for _, _, d in decisions)),
    )
    claim_rows = [
        r["decision"]
        for r in rows
        if (r["client_id"], r["tool"]) == ("servicing", "core-read.get_claim_status")
    ]
    check(
        "clean get_claim_status audit row decision is allow",
        claim_rows == ["allow"],
        ", ".join(claim_rows) or "no row",
    )
    check(
        "audit rows store only an args HMAC",
        bool(rows) and all(re.fullmatch(r"[0-9a-f]{64}", r["args_hmac"]) for r in rows),
    )
    if rows:
        row_id = rows[-1]["id"]
        upd = await app_role_denied(
            dsn, "UPDATE gateway.audit_log SET reason = 'x' WHERE id = $1", row_id
        )
        dele = await app_role_denied(
            dsn, "DELETE FROM gateway.audit_log WHERE id = $1", row_id
        )
        check("app role cannot UPDATE or DELETE audit rows", upd and dele)

    # 8. Tempo has the gateway's traces from this run.
    n = await tempo_trace_count(started)
    check("Tempo search returns toolgate-gateway traces", n >= 1, f"{n} traces")


if __name__ == "__main__":
    asyncio.run(main())
    if failures:
        print(f"{len(failures)} check(s) failed")
        sys.exit(1)
    print("All checks passed")
