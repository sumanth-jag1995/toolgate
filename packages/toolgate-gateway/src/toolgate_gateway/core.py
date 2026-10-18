"""GatewayCore: the verified tool snapshot shared by every caller.

Every tools/list fetches fresh tool lists from all downstreams, verifies them
against the pinned hashes, records drift and unpinned tools as pending
reviews, rebuilds the snapshot from the allowed tools, and returns the
caller's allowlisted tools under namespaced names. tools/call (Task 6) only
consults the snapshot.

Logs carry server ids, tool names, reasons and hashes only: never tool
definitions, arguments or results.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from mcp.types import Tool
from toolgate_pin import InventoryTool, Pinner, PinSet, Quarantine, pin_hash

from toolgate_gateway.audit import AuditWriter
from toolgate_gateway.downstreams import namespaced
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist
from toolgate_gateway.pool import DownstreamPool, ServerInfo
from toolgate_gateway.reviews import PendingReviews

log = logging.getLogger(__name__)
alert_log = logging.getLogger("toolgate_gateway.alert")

# Bound on review bookkeeping per refresh, so a slow database cannot stall
# tools/list. Failures and timeouts are logged, never raised.
REVIEWS_TIMEOUT_S = 5.0

_REVIEWED = frozenset({"drift", "unpinned", "server_drift"})


@dataclass(frozen=True)
class SnapshotEntry:
    server_id: str
    tool: Tool  # as the downstream listed it (original name)
    namespaced: str
    tool_hash: str
    input_validator: Draft202012Validator


def compile_validator(input_schema: Mapping[str, Any]) -> Draft202012Validator:
    """Validator for the pinned inputSchema; a top-level schema without
    ``additionalProperties`` gets ``additionalProperties: false``. Raises
    SchemaError for an invalid schema."""
    schema = dict(input_schema)
    schema.setdefault("additionalProperties", False)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


class GatewayCore:
    def __init__(
        self,
        pool: DownstreamPool,
        pins: PinSource,
        allowlist: Allowlist,
        audit: AuditWriter,
        reviews: PendingReviews | None,
        *,
        hmac_key: str,
    ) -> None:
        self.pool = pool
        self.pins = pins
        self.allowlist = allowlist
        self.audit = audit
        self.reviews = reviews
        self.hmac_key = hmac_key
        # Replaced wholesale on each refresh; readers never see a partial one.
        self.snapshot: dict[str, SnapshotEntry] = {}
        # server_id -> every tool name that server listed on the last refresh
        # (quarantined ones included), for output scanning.
        self.inventory: dict[str, list[InventoryTool]] = {}
        self._validators: dict[str, Draft202012Validator] = {}
        self._started = 0  # refresh generations
        self._applied = 0

    # -- public ------------------------------------------------------------

    async def list_tools(self, client_id: str) -> list[Tool]:
        snapshot = await self._refresh()
        return [
            e.tool.model_copy(update={"name": name})
            for name, e in snapshot.items()
            if self.allowlist.allowed(client_id, name)
        ]

    async def refresh_snapshot(self) -> None:
        await self._refresh()

    # -- refresh -----------------------------------------------------------

    async def _refresh(self) -> dict[str, SnapshotEntry]:
        self._started += 1
        generation = self._started
        state = self.pins.state()
        if state is None:  # stale or corrupt lockfile: fail closed
            snapshot: dict[str, SnapshotEntry] = {}
            inventory: dict[str, list[InventoryTool]] = {}
            quarantines: list[tuple[str, Quarantine]] = []
            pinset: PinSet | None = None
        else:
            pinset, pinner = state
            snapshot, inventory, quarantines = await self._build(pinner)

        # A slower, older refresh never overwrites a newer one.
        if generation > self._applied:
            self._applied = generation
            self.snapshot = snapshot
            self.inventory = inventory
            live = {e.tool_hash for e in snapshot.values()}
            self._validators = {h: v for h, v in self._validators.items() if h in live}

        for server_id, q in quarantines:
            self._alert(server_id, q)
        if self.reviews is not None and pinset is not None:
            await self._update_reviews(pinset, quarantines)
        return snapshot

    async def _build(
        self, pinner: Pinner
    ) -> tuple[
        dict[str, SnapshotEntry],
        dict[str, list[InventoryTool]],
        list[tuple[str, Quarantine]],
    ]:
        server_ids = self.pool.server_ids
        results = await asyncio.gather(
            *(self.pool.list_tools(sid) for sid in server_ids)
        )
        snapshot: dict[str, SnapshotEntry] = {}
        inventory: dict[str, list[InventoryTool]] = {}
        quarantines: list[tuple[str, Quarantine]] = []
        for server_id, listed in zip(server_ids, results, strict=True):
            if listed is None:  # down: its tools are omitted
                continue
            info, tools = listed
            inventory[server_id] = [
                InventoryTool(server_id, n)
                for n in dict.fromkeys(t.name for t in tools)
            ]
            allowed, quarantined = self._verify(pinner, server_id, info, tools)
            quarantines.extend(
                (server_id, q) for q in quarantined if q.reason in _REVIEWED
            )
            for tool in allowed:
                entry = self._entry(server_id, tool)
                if entry is not None:
                    snapshot[entry.namespaced] = entry
        return snapshot, inventory, quarantines

    def _verify(
        self, pinner: Pinner, server_id: str, info: ServerInfo, tools: list[Tool]
    ) -> tuple[list[Tool], list[Quarantine]]:
        try:
            result = pinner.verify(server_id, tools, server_info=info)
        except Exception as exc:  # noqa: BLE001 - fail closed for this server
            log.warning(
                "pin verification failed for %s (%s); omitting its tools",
                server_id,
                type(exc).__name__,
            )
            return [], []
        return list(result.allowed), list(result.quarantined)

    def _entry(self, server_id: str, tool: Tool) -> SnapshotEntry | None:
        name = namespaced(server_id, tool.name)
        tool_hash = pin_hash(tool)  # matched the pin, so it canonicalizes
        validator = self._validators.get(tool_hash)
        if validator is None:
            try:
                validator = compile_validator(tool.inputSchema)
            except SchemaError:
                log.warning(
                    "pinned inputSchema of %s (hash %s) is not a valid JSON "
                    "Schema; omitting the tool",
                    name,
                    tool_hash,
                )
                return None
            self._validators[tool_hash] = validator
        return SnapshotEntry(server_id, tool, name, tool_hash, validator)

    # -- reviews and alerts ------------------------------------------------

    @staticmethod
    def _alert(server_id: str, q: Quarantine) -> None:
        fields = {
            "toolgate_server_id": server_id,
            "toolgate_tool_name": q.tool_name,
            "toolgate_reason": q.reason,
            "toolgate_observed_hash": q.observed_hash,
            "toolgate_pinned_hash": q.pinned_hash,
        }
        alert_log.warning(
            "toolgate.alert server_id=%s tool=%r reason=%s observed_hash=%s "
            "pinned_hash=%s",
            server_id,
            q.tool_name,
            q.reason,
            q.observed_hash,
            q.pinned_hash,
            extra=fields,
        )

    async def _update_reviews(
        self, pinset: PinSet, quarantines: list[tuple[str, Quarantine]]
    ) -> None:
        reviews = self.reviews
        assert reviews is not None

        async def record(server_id: str, q: Quarantine) -> None:
            await reviews.record(
                server_id,
                q.tool_name,
                q.observed_hash,
                q.pinned_hash,
                q.reason,
                q.diff,
                [dataclasses.asdict(f) for f in q.findings],
            )

        try:
            async with asyncio.timeout(REVIEWS_TIMEOUT_S):
                outcomes = await asyncio.gather(
                    *(record(sid, q) for sid, q in quarantines),
                    return_exceptions=True,
                )
                for (sid, q), outcome in zip(quarantines, outcomes, strict=True):
                    if isinstance(outcome, BaseException):
                        log.warning(
                            "recording pending review for %s.%s failed (%s)",
                            sid,
                            q.tool_name,
                            type(outcome).__name__,
                        )
                await reviews.resolve_pinned(pinset)
        except Exception as exc:  # noqa: BLE001 - reviews never fail the list
            log.warning("updating pending reviews failed (%s)", type(exc).__name__)
