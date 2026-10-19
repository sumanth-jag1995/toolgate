"""``toolgate-gateway`` console entry point.

serve    run the authenticated MCP endpoint (uvicorn on GATEWAY_HOST:GATEWAY_PORT)
migrate  apply DB migrations as an admin; the app-role password comes from an
         environment variable, never a command-line argument. Prefer
         --admin-dsn-env NAME over --admin-dsn, which exposes the admin
         password in the process list and shell history.
reviews  list open pending reviews (DATABASE_URL), hidden characters revealed

Error output names settings, types and files only: never setting values,
DSNs or exception messages that might echo them.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import os
import sys
from collections.abc import Sequence
from typing import Any, TextIO

import uvicorn
from pydantic import ValidationError
from toolgate_pin.reveal import ascii_brackets, one_line, safe_print

from toolgate_gateway.app import build_app
from toolgate_gateway.audit import AuditWriter
from toolgate_gateway.auth import AgentTokenVerifier, ClientCredentialsAuth
from toolgate_gateway.core import GatewayCore
from toolgate_gateway.db import create_pool, migrate
from toolgate_gateway.downstreams import load_downstreams
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist, PolicyError
from toolgate_gateway.pool import DownstreamPool, http_session_factory
from toolgate_gateway.reviews import PendingReviews
from toolgate_gateway.settings import GatewaySettings
from toolgate_gateway.tracing import setup_tracing, shutdown_tracing

PROG = "toolgate-gateway"
_MAX_FIELD_CHARS = 300
_MAX_DIFF_LINE_CHARS = 2000


def _err(message: str) -> None:
    safe_print(f"{PROG}: {message}", file=sys.stderr)


# -- serve -------------------------------------------------------------------


async def _serve(settings: GatewaySettings) -> None:
    # Config files first, so a bad policy fails before anything connects.
    allowlist = Allowlist.load(settings.policy_path)
    configs = load_downstreams(settings.downstreams_path)
    verifier = AgentTokenVerifier(settings.issuer, settings.audience, settings.jwks_url)
    auth = ClientCredentialsAuth(
        settings.token_url, settings.client_id, settings.client_secret
    )
    try:
        # min_size=0: creating the pool does not connect, so the gateway
        # starts while Postgres is down; calls are refused until the audit
        # writer's probe succeeds.
        db = await create_pool(settings.database_url, min_size=0)
        try:
            core = GatewayCore(
                DownstreamPool(configs, http_session_factory(auth)),
                PinSource(settings.lockfile_path),
                allowlist,
                AuditWriter(db),
                PendingReviews(db),
                hmac_key=settings.audit_hmac_key,
            )
            app = build_app(core, verifier, settings)
            config = uvicorn.Config(
                app, host=settings.host, port=settings.port, lifespan="on"
            )
            await uvicorn.Server(config).serve()
        finally:
            await db.close()
    finally:
        await auth.aclose()


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        settings = GatewaySettings()  # type: ignore[call-arg]  # from the env
    except ValidationError as exc:
        # Only field names and error types: the input values may be secrets.
        for e in exc.errors(include_input=False, include_url=False):
            loc = ".".join(str(p) for p in e["loc"])
            _err(f"setting {loc}: {e['type']}")
        return 2
    try:
        setup_tracing("toolgate-gateway", settings.otlp_endpoint)
        asyncio.run(_serve(settings))
    except PolicyError as exc:
        _err(str(exc))
        return 2
    except Exception as exc:  # noqa: BLE001 - type only: messages may echo values
        _err(f"serve failed ({type(exc).__name__})")
        return 1
    finally:
        with contextlib.suppress(Exception):  # best-effort flush at exit
            shutdown_tracing()
    return 0


# -- migrate -----------------------------------------------------------------


def _cmd_migrate(args: argparse.Namespace) -> int:
    if args.admin_dsn_env is not None:
        admin_dsn = os.environ.get(args.admin_dsn_env, "")
        if not admin_dsn:
            _err(f"environment variable {args.admin_dsn_env} is not set or empty")
            return 2
    else:
        admin_dsn = args.admin_dsn
    password = os.environ.get(args.app_password_env, "")
    if not password:
        _err(f"environment variable {args.app_password_env} is not set or empty")
        return 2
    try:
        asyncio.run(migrate(admin_dsn, password))
    except Exception as exc:  # noqa: BLE001 - type only: messages may echo DSNs
        _err(f"migrate failed ({type(exc).__name__})")
        return 1
    print("migrations applied")
    return 0


# -- reviews -----------------------------------------------------------------


async def _open_reviews(dsn: str) -> list[dict[str, Any]]:
    pool = await create_pool(dsn)
    try:
        return await PendingReviews(pool).list_open()
    finally:
        await pool.close()


def _field(value: object) -> str:
    return one_line("-" if value is None else str(value), max_chars=_MAX_FIELD_CHARS)


def _print_review(r: dict[str, Any], out: TextIO) -> None:
    def emit(text: str) -> None:
        safe_print(ascii_brackets(text, out), file=out)

    emit(
        f"#{r['id']} {_field(r['server_id'])}.{_field(r['tool_name'])} "
        f"reason={_field(r['reason'])}"
    )
    emit(f"  pinned:   {_field(r['pinned_hash'])}")
    emit(f"  observed: {_field(r['observed_hash'])}")
    emit(f"  seen:     {r['first_seen']} .. {r['last_seen']}")
    rules = sorted(
        {str(f.get("rule_id")) for f in r.get("findings") or [] if isinstance(f, dict)}
    )
    if rules:
        emit(f"  findings: {_field(', '.join(rules))}")
    diff = r.get("diff")
    if diff:
        emit("  diff:")
        for line in str(diff).splitlines():
            # one_line runs reveal() and shows control characters as code points.
            emit(f"    {one_line(line, max_chars=_MAX_DIFF_LINE_CHARS)}")


def _cmd_reviews(args: argparse.Namespace) -> int:
    dsn = os.environ.get("DATABASE_URL", "")
    if not dsn:
        _err("environment variable DATABASE_URL is not set or empty")
        return 2
    try:
        rows = asyncio.run(_open_reviews(dsn))
    except Exception as exc:  # noqa: BLE001 - type only: messages may echo DSNs
        _err(f"reading pending reviews failed ({type(exc).__name__})")
        return 1
    out = sys.stdout
    if not rows:
        print("no open pending reviews", file=out)
        return 0
    for r in rows:
        _print_review(r, out)
    return 0


# -- entry point -------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG)
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the authenticated MCP endpoint")
    serve.set_defaults(func=_cmd_serve)
    mig = sub.add_parser("migrate", help="apply database migrations (admin)")
    dsn = mig.add_mutually_exclusive_group(required=True)
    dsn.add_argument(
        "--admin-dsn-env",
        metavar="NAME",
        help="environment variable holding the admin DSN (preferred)",
    )
    dsn.add_argument(
        "--admin-dsn",
        help="admin DSN; prefer --admin-dsn-env (argv is visible to other users)",
    )
    mig.add_argument(
        "--app-password-env",
        default="GATEWAY_DB_PASSWORD",
        help="environment variable holding the app role's password",
    )
    mig.set_defaults(func=_cmd_migrate)
    rev = sub.add_parser("reviews", help="list open pending reviews (DATABASE_URL)")
    rev.set_defaults(func=_cmd_reviews)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return int(args.func(args))
