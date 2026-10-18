"""End-to-end smoke test of sub-project A: 3 authenticated MCP servers over streamable HTTP.

Run after `docker compose -f infra/docker-compose.yml up -d --build`. Reads the
dev-tester client secret from the local .env (never printed). Exits non-zero on failure.
"""

import asyncio
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

ROOT = Path(__file__).resolve().parent.parent
TOKEN_URL = "http://localhost:8080/realms/toolgate/protocol/openid-connect/token"
SERVERS = {"core-read": (8101, 7), "core-write": (8102, 3), "comms": (8103, 2)}
CANARY = "TG-CANARY-7Q4X9"
failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{' - ' + detail if detail else ''}")
    if not ok:
        failures.append(name)


def read_secret() -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        key, _, value = line.partition("=")
        if key == "DEV_TESTER_CLIENT_SECRET":
            return value
    raise SystemExit(
        "DEV_TESTER_CLIENT_SECRET missing from .env (run scripts/gen_dev_env.py)"
    )


def url(server: str) -> str:
    return f"http://localhost:{SERVERS[server][0]}/mcp"


@asynccontextmanager
async def open_session(server: str, token: str):
    headers = {"Authorization": f"Bearer {token}"}
    async with (
        streamablehttp_client(url(server), headers=headers) as (r, w, _),
        ClientSession(r, w) as session,
    ):
        await session.initialize()
        yield session


async def call(server: str, token: str, tool: str, args: dict) -> dict:
    async with open_session(server, token) as session:
        result = await session.call_tool(tool, args)
    if result.isError:
        raise RuntimeError(f"{tool} returned an error: {result.content[0].text}")
    return result.structuredContent


async def tool_count(server: str, token: str) -> int:
    async with open_session(server, token) as session:
        return len((await session.list_tools()).tools)


async def main() -> None:
    http = httpx.AsyncClient(timeout=10)
    resp = await http.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": "dev-tester",
            "client_secret": read_secret(),
        },
        timeout=10,
    )
    check(
        "dev-tester token obtained", resp.status_code == 200, f"HTTP {resp.status_code}"
    )
    token = resp.json()["access_token"]

    for server, (_, expected) in SERVERS.items():
        try:
            n = await tool_count(server, token)
            check(f"{server} lists {expected} tools", n == expected, f"got {n}")
        except Exception as exc:  # noqa: BLE001
            check(f"{server} lists {expected} tools", False, repr(exc))

    try:
        profile = await call(
            "core-read", token, "get_member_profile", {"member_id": "M-900001"}
        )
        check("get_member_profile returns canary", CANARY in str(profile))
        policy_id = profile["policy_ids"][0]
        for pid in profile["policy_ids"]:
            policy = await call(
                "core-read", token, "get_policy_details", {"policy_id": pid}
            )
            if policy["status"] == "active":
                policy_id = pid
                break
        claim = await call(
            "core-write",
            token,
            "log_claim",
            {
                "member_id": "M-900001",
                "policy_id": policy_id,
                "procedure_code": "mri_scan",
                "incident_date": date.today().isoformat(),
                "amount_pence": 12500,
                "idempotency_key": str(uuid.uuid4()),
            },
        )
        check("log_claim succeeds", claim["status"] == "received", claim["claim_id"])
        sent = await call(
            "comms",
            token,
            "send_member_message",
            {
                "member_id": "M-900001",
                "template_id": "documents_required",
                "claim_id": claim["claim_id"],
                "idempotency_key": str(uuid.uuid4()),
            },
        )
        check("send_member_message succeeds", "correspondence_id" in sent)
    except Exception as exc:  # noqa: BLE001
        check("tool calls", False, repr(exc))

    for server in SERVERS:
        r = await http.post(url(server), json={})
        check(
            f"{server} refuses unauthenticated (401)",
            r.status_code == 401,
            f"HTTP {r.status_code}",
        )


if __name__ == "__main__":
    asyncio.run(main())
    if failures:
        print(f"{len(failures)} check(s) failed")
        sys.exit(1)
    print("All checks passed")
