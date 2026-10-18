"""Append-only audit log: keyed argument hashes and a batched, fail-closed writer."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
from collections.abc import Mapping
from dataclasses import astuple, dataclass
from typing import Any

import asyncpg
import rfc8785

log = logging.getLogger(__name__)


def args_hmac(key: str, arguments: Mapping[str, Any] | None) -> str:
    """Hex HMAC-SHA256 of the RFC 8785 canonical JSON of the arguments. Never raises."""
    value = dict(arguments) if arguments else {}
    try:
        msg = rfc8785.dumps(value)
    except Exception:  # noqa: BLE001 - must never raise
        try:
            msg = json.dumps(
                value, sort_keys=True, separators=(",", ":"), default=str
            ).encode()
        except Exception:  # noqa: BLE001 - must never raise
            msg = b"<uncanonicalisable>"
    return hmac.new(key.encode(), msg, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    agent_id: str
    client_id: str
    tool: str
    tool_hash: str | None
    args_hmac: str
    decision: str
    reason: str | None
    latency_ms: float | None
    trace_id: str | None


_INSERT = (
    "INSERT INTO gateway.audit_log (agent_id, client_id, tool, tool_hash, "
    "args_hmac, decision, reason, latency_ms, trace_id) "
    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
)


class AuditWriter:
    def __init__(
        self,
        pool: asyncpg.Pool,
        *,
        flush_interval_s: float = 0.1,
        batch_size: int = 50,
        max_queue: int = 10_000,
    ) -> None:
        self._pool = pool
        self._interval = flush_interval_s
        self._batch_size = batch_size
        self._queue: asyncio.Queue[AuditRecord] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None
        self._stopping = False
        self._healthy = True
        self.dropped_count = 0

    @property
    def healthy(self) -> bool:
        return self._healthy

    async def start(self) -> None:
        if self._task is None:
            self._stopping = False
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stopping = True
        if self._task is not None:
            await self._task
            self._task = None

    def submit(self, rec: AuditRecord) -> bool:
        if not self._healthy:
            return False
        try:
            self._queue.put_nowait(rec)
        except asyncio.QueueFull:
            return False
        return True

    def _drain(self) -> list[AuditRecord]:
        batch: list[AuditRecord] = []
        while len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    async def _flush(self, batch: list[AuditRecord]) -> None:
        """Write a batch; one retry, then drop and count. Updates health."""
        rows = [astuple(r) for r in batch]
        for attempt in (1, 2):
            try:
                await self._pool.executemany(_INSERT, rows)
            except Exception as exc:  # noqa: BLE001 - any DB failure = unhealthy
                self._healthy = False
                log.warning("audit flush failed (attempt %d): %s", attempt, exc)
            else:
                self._healthy = True
                return
        self.dropped_count += len(batch)

    async def _run(self) -> None:
        while True:
            batch = self._drain()
            if batch:
                await self._flush(batch)
                continue
            if self._stopping:
                return
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wait_nonempty(), self._interval)

    async def _wait_nonempty(self) -> None:
        # Wake early once a full batch is waiting; otherwise the timeout flushes.
        while self._queue.qsize() < self._batch_size and not self._stopping:
            await asyncio.sleep(0.005)
