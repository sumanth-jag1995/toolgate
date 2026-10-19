"""Pin the three MCP servers into policy/toolgate.lock.json (run when they change).

Run against the live compose stack. Gets a ``dev-tester`` token and, for each
of core-read, core-write and comms, runs::

    toolgate-pin approve http://localhost:810x/mcp --name <id> \
        --header "Authorization: Bearer ${TOOLGATE_DEV_TOKEN}" \
        --lockfile policy/toolgate.lock.json --yes --as "$(git config user.name)"

The token is set only in the child process environment; the lockfile stores
the header *template*, never the token. Then review the diff and commit the
lockfile: that commit is the approval.
"""

import os
import subprocess
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
TOKEN_URL = "http://localhost:8080/realms/toolgate/protocol/openid-connect/token"
LOCKFILE = "policy/toolgate.lock.json"
SERVERS = {"core-read": 8101, "core-write": 8102, "comms": 8103}
HEADER_TEMPLATE = "Authorization: Bearer ${TOOLGATE_DEV_TOKEN}"


def read_env_value(key: str) -> str:
    for line in (ROOT / ".env").read_text().splitlines():
        k, _, value = line.partition("=")
        if k == key:
            return value
    raise SystemExit(f"{key} missing from .env (run scripts/gen_dev_env.py)")


def dev_token() -> str:
    resp = httpx.post(
        TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": "dev-tester",
            "client_secret": read_env_value("DEV_TESTER_CLIENT_SECRET"),
        },
        timeout=10,
    )
    if resp.status_code != 200:
        raise SystemExit(f"dev-tester token request failed: HTTP {resp.status_code}")
    return resp.json()["access_token"]


def approver() -> str:
    name = subprocess.run(
        ["git", "config", "user.name"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not name:
        raise SystemExit("git config user.name is not set (used as the approver)")
    return name


def main() -> int:
    child_env = {**os.environ, "TOOLGATE_DEV_TOKEN": dev_token()}
    who = approver()
    for server_id, port in SERVERS.items():
        print(f"== {server_id}", flush=True)
        cmd = [
            sys.executable,
            "-m",
            "toolgate_pin.cli",
            "approve",
            f"http://localhost:{port}/mcp",
            "--name",
            server_id,
            "--header",
            HEADER_TEMPLATE,
            "--lockfile",
            LOCKFILE,
            "--yes",
            "--as",
            who,
        ]
        code = subprocess.run(cmd, cwd=ROOT, env=child_env, check=False).returncode
        if code != 0:
            print(f"toolgate-pin approve failed for {server_id} (exit {code})")
            return code
    print(f"pinned {len(SERVERS)} servers into {LOCKFILE}; review and commit it")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
