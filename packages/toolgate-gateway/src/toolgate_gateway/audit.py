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
from asyncpg.exceptions._base import DataError as ArgumentEncodingError

log = logging.getLogger(__name__)

# Caller- or downstream-controlled text (a tool name) is bounded to this many
# characters in audit rows, span attributes and log lines.
MAX_TEXT = 256

# Errors that reject a row's *data* (not the connection): the row can never
# be written, so it is dropped alone instead of failing its whole batch.
_ROW_ERRORS: tuple[type[BaseException], ...] = (
    asyncpg.DataError,  # SQLSTATE class 22, e.g. NUL in text
    asyncpg.IntegrityConstraintViolationError,  # class 23, e.g. a CHECK
    ArgumentEncodingError,  # client side: an argument cannot be encoded
    UnicodeError,
)


def safe_text(value: str, limit: int = MAX_TEXT) -> str:
    """``value`` made storable as Postgres text and safe for spans and logs:
    truncated, NUL and unencodable characters (lone surrogates) replaced by
    backslash escapes, truncated again. Deterministic; never raises."""
    escaped = value[:limit].encode("utf-8", "backslashreplace").decode("utf-8")
    return escaped.replace("\x00", "\\x00")[:limit]


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
        # A batch whose write failed on a connection error: written first once
        # the database answers again; dropped only by stop() while still down.
        self._held: list[AuditRecord] = []
        self.dropped_count = 0  # rows lost: refused by submit or never written
        self.rejected_count = 0  # rows Postgres rejected for their data

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
        """Queue a row; False (counted in dropped_count) if not accepting."""
        if self._closed or not self._healthy:
            self.dropped_count += 1
            return False
        try:
            self._queue.put_nowait(rec)
        except asyncio.QueueFull:
            self.dropped_count += 1
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
        """Write a batch; updates health. A batch Postgres rejects for its
        data is retried row by row, dropping (and counting) only the rejected
        rows. A connection failure is retried once; then the unwritten rows
        are held until the database answers again."""
        pending = batch
        for attempt in (1, 2):
            try:
                await self._write([astuple(r) for r in pending])
            except _ROW_ERRORS:
                pending, failure = await self._write_rows(pending)
                if failure is None:
                    self._healthy = True
                    return
            except Exception as exc:  # noqa: BLE001 - any DB failure = unhealthy
                failure = exc
            else:
                self._healthy = True
                return
            self._healthy = False
            # Type only: the message may echo a row's values.
            log.warning(
                "audit flush failed (attempt %d: %s)", attempt, type(failure).__name__
            )
        self._held = pending

    async def _write_rows(
        self, batch: list[AuditRecord]
    ) -> tuple[list[AuditRecord], Exception | None]:
        """Insert row by row, dropping rows rejected for their data. On a
        connection failure, returns the unwritten rows and the error."""
        for i, rec in enumerate(batch):
            try:
                await self._write([astuple(rec)])
            except _ROW_ERRORS as exc:
                self.rejected_count += 1
                log.error(
                    "audit row rejected by the database (%s) client=%s decision=%s",
                    type(exc).__name__,
                    safe_text(rec.client_id),
                    safe_text(rec.decision),
                )
            except Exception as exc:  # noqa: BLE001 - connection failure
                return batch[i:], exc
        return [], None

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
                # Rows stay queued (and a failed batch held) while the DB is
                # down; resume after recovery.
                await self._recover()
                if not self._healthy:  # stopping while still down
                    self.dropped_count += len(self._held) + self._queue.qsize()
                    self._held = []
                    return
            if self._held:
                held, self._held = self._held, []
                await self._flush(held)
                continue
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
