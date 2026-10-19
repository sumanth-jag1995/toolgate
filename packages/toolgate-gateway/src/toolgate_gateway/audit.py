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
        op_timeout_s: float = 2.0,
        probe_min_s: float = 0.5,
        probe_max_s: float = 5.0,
    ) -> None:
        self._pool = pool
        self._interval = flush_interval_s
        self._batch_size = batch_size
        self._op_timeout = op_timeout_s
        self._probe_min = probe_min_s
        self._probe_max = probe_max_s
        self._queue: asyncio.Queue[AuditRecord] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._stop_event = asyncio.Event()
        self._closed = False
        # Fail closed from a cold start: not healthy (so not accepting) until
        # the first successful probe, which start() kicks off.
        self._healthy = False
        self.dropped_count = 0

    @property
    def healthy(self) -> bool:
        return self._healthy

    @property
    def accepting(self) -> bool:
        """Whether ``submit`` would accept a row now: open, healthy and the
        queue not full. Checked before forwarding a call (fail closed)."""
        return not self._closed and self._healthy and not self._queue.full()

    async def start(self) -> None:
        if self._task is None:
            self._closed = False
            self._stop_event.clear()
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._closed = True
        self._stop_event.set()
        self._wake.set()
        if self._task is not None:
            await self._task
            self._task = None

    def submit(self, rec: AuditRecord) -> bool:
        if self._closed or not self._healthy:
            return False
        try:
            self._queue.put_nowait(rec)
        except asyncio.QueueFull:
            return False
        self._wake.set()
        return True

    def _drain(self) -> list[AuditRecord]:
        batch: list[AuditRecord] = []
        while len(batch) < self._batch_size:
            try:
                batch.append(self._queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    async def _write(self, rows: list[tuple[Any, ...]]) -> None:
        await asyncio.wait_for(
            self._pool.executemany(_INSERT, rows, timeout=self._op_timeout),
            self._op_timeout + 0.5,
        )

    async def _flush(self, batch: list[AuditRecord]) -> None:
        """Write a batch; one retry, then drop and count. Updates health."""
        rows = [astuple(r) for r in batch]
        for attempt in (1, 2):
            try:
                await self._write(rows)
            except Exception as exc:  # noqa: BLE001 - any DB failure = unhealthy
                self._healthy = False
                log.warning("audit flush failed (attempt %d): %s", attempt, exc)
            else:
                self._healthy = True
                return
        self.dropped_count += len(batch)

    async def _probe(self) -> bool:
        try:
            await asyncio.wait_for(
                self._pool.fetchval("SELECT 1", timeout=self._op_timeout),
                self._op_timeout + 0.5,
            )
        except Exception:  # noqa: BLE001 - any failure = still down
            return False
        return True

    async def _recover(self) -> None:
        """Probe with exponential backoff until the DB answers (or we stop)."""
        delay = self._probe_min
        warned = False
        while not self._healthy:
            if await self._probe():
                self._healthy = True
                if warned:
                    log.info("audit database reachable; accepting calls")
                return
            if not warned:
                log.warning(
                    "audit database unreachable; calls refused until it answers"
                )
                warned = True
            if self._stop_event.is_set():
                return
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_event.wait(), delay)
            delay = min(delay * 2, self._probe_max)

    async def _run(self) -> None:
        while True:
            if not self._healthy:
                # Rows stay queued while the DB is down; resume after recovery.
                await self._recover()
                if not self._healthy:  # stopping while still down
                    self.dropped_count += self._queue.qsize()
                    return
            if self._queue.empty():
                if self._stop_event.is_set():
                    return
                self._wake.clear()
                if self._queue.empty():
                    await self._wake.wait()
                continue
            if self._queue.qsize() < self._batch_size and not self._stop_event.is_set():
                await asyncio.sleep(self._interval)
            await self._flush(self._drain())
