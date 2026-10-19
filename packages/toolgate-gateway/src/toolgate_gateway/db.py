"""Postgres access: migrations (admin) and the app-role connection pool."""

from __future__ import annotations

from importlib import resources

import asyncpg

APP_ROLE = "toolgate_gateway_app"
_MIGRATIONS = ("001_init.sql",)


async def migrate(admin_dsn: str, app_password: str) -> None:
    """Apply idempotent migrations and set the app role's password."""
    if not app_password:
        raise ValueError("app_password must not be empty")
    conn = await asyncpg.connect(admin_dsn)
    try:
        for name in _MIGRATIONS:
            sql = (
                resources.files("toolgate_gateway")
                .joinpath("migrations", name)
                .read_text(encoding="utf-8")
            )
            await conn.execute(sql)
        # ALTER ROLE cannot take bind parameters; quote the literal server-side.
        literal = await conn.fetchval("SELECT quote_literal($1::text)", app_password)
        await conn.execute(f"ALTER ROLE {APP_ROLE} PASSWORD {literal}")
    finally:
        await conn.close()


async def create_pool(dsn: str, *, min_size: int = 1) -> asyncpg.Pool:
    """App-role pool. With ``min_size=0`` creating it does not connect, so a
    caller can start while Postgres is down (the audit writer's probe then
    decides when calls are accepted). Connects time out after 5 s."""
    return await asyncpg.create_pool(
        dsn, min_size=min_size, max_size=5, command_timeout=5.0, timeout=5.0
    )
