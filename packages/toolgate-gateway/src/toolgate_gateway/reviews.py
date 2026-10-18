"""Pending reviews: drifted or unpinned tools awaiting human approval."""

from __future__ import annotations

import json
from typing import Any

import asyncpg
from toolgate_pin.models import PinSet


class PendingReviews:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    async def record(
        self,
        server_id: str,
        tool_name: str,
        observed_hash: str | None,
        pinned_hash: str | None,
        reason: str,
        diff: str | None,
        findings: list[dict[str, Any]],
    ) -> None:
        await self._pool.execute(
            "INSERT INTO gateway.pending_reviews (server_id, tool_name, "
            "observed_hash, pinned_hash, reason, diff, findings) "
            "VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb) "
            "ON CONFLICT (server_id, tool_name, observed_hash) DO UPDATE SET "
            "last_seen = now(), pinned_hash = EXCLUDED.pinned_hash, "
            "reason = EXCLUDED.reason, diff = EXCLUDED.diff, "
            "findings = EXCLUDED.findings, status = 'open'",
            server_id,
            tool_name,
            observed_hash,
            pinned_hash,
            reason,
            diff,
            json.dumps(findings),
        )

    async def resolve_pinned(self, pins: PinSet) -> int:
        """Mark open rows resolved when their observed hash is now pinned."""
        rows = await self._pool.fetch(
            "SELECT id, server_id, tool_name, observed_hash "
            "FROM gateway.pending_reviews WHERE status = 'open'"
        )
        ids: list[int] = []
        for r in rows:
            server = pins.get(r["server_id"])
            pin = server.tools.get(r["tool_name"]) if server else None
            if pin is not None and r["observed_hash"] == pin.hash:
                ids.append(r["id"])
        if not ids:
            return 0
        await self._pool.execute(
            "UPDATE gateway.pending_reviews SET status = 'resolved' "
            "WHERE id = ANY($1::bigint[])",
            ids,
        )
        return len(ids)

    async def list_open(self) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            "SELECT * FROM gateway.pending_reviews WHERE status = 'open' ORDER BY id"
        )
        out = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("findings"), str):
                d["findings"] = json.loads(d["findings"])
            out.append(d)
        return out
