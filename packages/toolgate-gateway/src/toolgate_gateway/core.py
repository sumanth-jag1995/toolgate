"""GatewayCore: the verified tool snapshot shared by every caller.

Every tools/list fetches fresh tool lists from all downstreams, verifies them
against the pinned hashes, records drift and unpinned tools as pending
reviews, rebuilds the snapshot from the allowed tools, and returns the
caller's allowlisted tools under namespaced names. tools/call only
consults the snapshot.

The snapshot serves the PINNED definition, never the live one: the pin hash
covers only the normalized hashed fields, so a downstream could otherwise add
``_meta``, ``icons``, extra fields or whitespace variants and still match.

Logs and trace spans carry server ids, tool names, reasons and hashes only:
never tool definitions, arguments or results.
"""

from __future__ import annotations

import asyncio
import dataclasses
import itertools
import logging
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, best_match
from mcp.shared.exceptions import McpError
from mcp.types import CallToolResult, TextContent, Tool
from opentelemetry import trace
from opentelemetry.trace import Span
from toolgate_pin import InventoryTool, Pinner, PinSet, Quarantine, scan_output

from toolgate_gateway.audit import (
    MAX_TEXT,
    AuditRecord,
    AuditWriter,
    args_hmac,
    safe_text,
)
from toolgate_gateway.downstreams import namespaced, split_namespaced
from toolgate_gateway.pins import PinSource
from toolgate_gateway.policy import Allowlist
from toolgate_gateway.pool import DownstreamPool, DownstreamUnavailable, ServerInfo
from toolgate_gateway.reviews import PendingReviews
from toolgate_gateway.tracing import span, trace_id_of

log = logging.getLogger(__name__)
alert_log = logging.getLogger("toolgate_gateway.alert")

# Bound on review bookkeeping per refresh, so a slow database cannot stall
# tools/list. Failures and timeouts are logged, never raised.
REVIEWS_TIMEOUT_S = 5.0

_REVIEWED = frozenset({"drift", "unpinned", "server_drift"})

# Fixed tool-error texts. They never contain arguments or downstream text.
_UNKNOWN = "unknown tool"
_SCOPE = "tool not permitted for this agent"
_UNPINNED = "tool is not approved; call refused"
_DRIFT = "tool definition changed since approval; call refused"
_SCHEMA = "arguments do not match the tool's input schema"
_AUDIT_DOWN = "audit log unavailable; call refused"
_DOWNSTREAM_ERROR = "downstream error; call failed"
_WITHHELD = "tool output withheld by policy"

# Audit reasons of a call abandoned after it was sent downstream.
_CANCELLED = "cancelled (outcome unknown)"
_TIMED_OUT = "timed out (outcome unknown)"

# A caller-supplied tool name is sanitised (safe_text: NUL and lone
# surrogates escaped) and truncated to this length in audit rows, spans and
# logs (it is unbounded on the wire; a known name is far shorter).
MAX_LOGGED_NAME = MAX_TEXT

# Errors examined to name the failing schema keyword (bounds the cost of a
# huge argument with many invalid items).
MAX_SCHEMA_ERRORS = 20


def _unavailable(server_id: str) -> str:
    # server_id is a configured (validated) id, never caller-supplied text.
    return f"downstream {server_id} is unavailable; call failed"


def _error(message: str) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=message)], isError=True
    )


def _without_meta(result: CallToolResult) -> CallToolResult:
    """``result`` without ``_meta``, on the result or any content block: the
    output scan does not read it, so it must not reach the agent."""
    content = [
        c.model_copy(update={"meta": None}) if getattr(c, "meta", None) else c
        for c in result.content
    ]
    return result.model_copy(update={"meta": None, "content": content})


def _schema_failure(validator: Draft202012Validator, args: Any) -> str | None:
    """None if ``args`` is valid, else a reason naming only the failing
    schema keyword (never a value or a caller-chosen property name)."""
    if not isinstance(args, Mapping):
        return "schema: not an object"
    try:
        # is_valid stops at the first error; only a failure pays for picking
        # a reason, and then from at most MAX_SCHEMA_ERRORS errors.
        if validator.is_valid(args):
            return None
        errors = itertools.islice(validator.iter_errors(args), MAX_SCHEMA_ERRORS)
        error = best_match(errors)
    except Exception:  # noqa: BLE001 - cannot validate: fail closed
        return "schema: validation failed"
    if error is None:  # cannot happen after is_valid failed; fail closed
        return "schema: validation failed"
    return f"schema: {error.validator}"


# (audit decision, audit reason, tool-error message) of a refused call.
_Denial = tuple[str, str | None, str]


@contextmanager
def _stage(name: str, denial: list[_Denial]) -> Iterator[Span]:
    """A pipeline-stage span. On exit, the stage that recorded a denial in
    ``denial`` carries ``toolgate.decision``."""
    with span(name) as current:
        try:
            yield current
        finally:
            if denial:
                current.set_attribute("toolgate.decision", denial[0][0])


class _Call:
    """Audit bookkeeping for one tools/call."""

    def __init__(
        self,
        core: GatewayCore,
        client_id: str,
        agent_id: str,
        name: str,
        arguments: Any,
        start: float,
        root: Span,
    ) -> None:
        self.core = core
        self.root = root
        self.client_id = client_id
        self.agent_id = agent_id
        self.name = safe_text(name, MAX_LOGGED_NAME)
        self.arguments = arguments
        self.start = start
        self.tool_hash: str | None = None
        self.forwarded = False  # the downstream was (or may have been) called

    def set_tool_hash(self, tool_hash: str | None) -> None:
        self.tool_hash = tool_hash
        if tool_hash is not None:
            self.root.set_attribute("toolgate.tool_hash", tool_hash)

    def finish(self, decision: str, reason: str | None) -> None:
        """Audit the call in a ``gateway.audit`` span (a child of the call
        span: call it outside any stage span)."""
        self.root.set_attribute("toolgate.decision", decision)
        with span("gateway.audit"):
            self._submit(decision, reason)

    def _submit(self, decision: str, reason: str | None) -> None:
        latency_ms = (time.perf_counter() - self.start) * 1000.0
        args = self.arguments if isinstance(self.arguments, Mapping) else None
        if self.arguments is not None and args is None:
            args = {"<non-object>": type(self.arguments).__name__}
        rec = AuditRecord(
            agent_id=safe_text(self.agent_id),
            client_id=safe_text(self.client_id),
            tool=self.name,
            tool_hash=self.tool_hash,
            args_hmac=args_hmac(self.core.hmac_key, args),
            decision=decision,
            reason=None if reason is None else safe_text(reason),
            latency_ms=latency_ms,
            trace_id=trace_id_of(self.root),
        )
        if not self.core.audit.submit(rec):
            # After forwarding, the call happened but has no audit row.
            level = logging.ERROR if self.forwarded else logging.WARNING
            log.log(
                level,
                "audit drop: row not accepted client=%s tool=%r decision=%s",
                rec.client_id,
                self.name,
                decision,
            )

    def deny(self, denial: _Denial) -> CallToolResult:
        decision, reason, message = denial
        self.finish(decision, reason)
        return _error(message)


@dataclass(frozen=True)
class SnapshotEntry:
    server_id: str
    tool: Tool  # the pinned definition (original, un-namespaced name)
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
        # (server_id, tool name, pin hash) -> (pinned Tool, validator); valid
        # for one PinSet only, since equal hashes may have unequal definitions.
        self._compiled: dict[tuple[str, str, str], tuple[Tool, Draft202012Validator]]
        self._compiled = {}
        self._compiled_for: PinSet | None = None
        self._started = 0  # refresh generations
        self._applied = 0

    # -- public ------------------------------------------------------------

    async def list_tools(self, client_id: str) -> list[Tool]:
        with span("gateway.tools_list", **{"toolgate.client_id": client_id}) as root:
            snapshot = await self._refresh()
            tools = [
                e.tool.model_copy(update={"name": name})
                for name, e in snapshot.items()
                if self.allowlist.allowed(client_id, name)
            ]
            root.set_attribute("toolgate.allowed_count", len(tools))
            return tools

    async def refresh_snapshot(self) -> None:
        await self._refresh()

    async def call_tool(
        self,
        client_id: str,
        agent_id: str,
        name: str,
        arguments: dict[str, Any] | None,
    ) -> CallToolResult:
        """Check, forward, scan and audit one tools/call. Fails closed: the
        first failing check returns a fixed error (never echoing arguments)
        and is audited; the downstream is called only if every check passes
        and the audit log can take the row."""
        start = time.perf_counter()
        with span(
            "gateway.tools_call",
            **{
                "toolgate.client_id": safe_text(client_id),
                "toolgate.tool": safe_text(name, MAX_LOGGED_NAME),
            },
        ) as root:
            call = _Call(self, client_id, agent_id, name, arguments, start, root)
            return await self._call(call, client_id, name, arguments)

    async def _call(
        self, call: _Call, client_id: str, name: str, arguments: Any
    ) -> CallToolResult:
        denial: list[_Denial] = []

        # 1-2. namespace, known server and allowlist
        with _stage("gateway.auth_scope", denial):
            parts = split_namespaced(name)
            if (
                parts is None
                or not parts[0]
                or not parts[1]
                or parts[0] not in self.pool.server_ids
            ):
                denial.append(("deny_unknown_tool", None, _UNKNOWN))
            elif not self.allowlist.allowed(client_id, name):
                denial.append(("deny_scope", None, _SCOPE))
        if denial:
            return call.deny(denial[0])
        assert parts is not None
        server_id, tool_name = parts

        # 3. pins and snapshot. Stale/corrupt pins bound calls as well.
        with _stage("gateway.pin_check", denial):
            entry = self.snapshot.get(name)
            call.set_tool_hash(entry.tool_hash if entry is not None else None)
            denied = self._pin_denial(server_id, tool_name, entry)
            if denied is not None:
                denial.append(denied)
        if denial:
            return call.deny(denial[0])
        assert entry is not None

        # 4. argument schema (the pinned inputSchema)
        args: Any = {} if arguments is None else arguments
        with _stage("gateway.schema", denial):
            schema_failure = _schema_failure(entry.input_validator, args)
            if schema_failure is not None:
                denial.append(("deny_schema", schema_failure, _SCHEMA))
        if denial:
            return call.deny(denial[0])

        # 5. the audit log must be able to take the row before forwarding
        with span("gateway.audit_check") as audit_span:
            if not self.audit.accepting:
                audit_span.set_attribute("toolgate.decision", "error_audit_down")
                call.root.set_attribute("toolgate.decision", "error_audit_down")
                log.warning(
                    "audit log unavailable; refused call client=%s tool=%r",
                    client_id,
                    call.name,
                )
                return _error(_AUDIT_DOWN)

        # 6. forward with the gateway's own credentials
        cancelled: asyncio.CancelledError | None = None
        result: CallToolResult | None = None
        with _stage("gateway.forward", denial) as fwd:
            call.forwarded = True
            try:
                result = await self.pool.call_tool(server_id, tool_name, args)
            except asyncio.CancelledError as exc:
                cancelled = exc
                fwd.set_attribute("toolgate.decision", "error_downstream")
            except DownstreamUnavailable as exc:
                reason = _TIMED_OUT if exc.outcome_unknown else "unavailable"
                denial.append(("error_downstream", reason, _unavailable(server_id)))
            except McpError:
                denial.append(("error_downstream", "jsonrpc_error", _DOWNSTREAM_ERROR))
            except Exception as exc:  # noqa: BLE001 - any failure is a tool error
                log.warning(
                    "tools/call %r on %s failed (%s)",
                    call.name,
                    server_id,
                    type(exc).__name__,
                )
                denial.append(
                    ("error_downstream", type(exc).__name__, _DOWNSTREAM_ERROR)
                )
        if cancelled is not None:
            call.finish("error_downstream", _CANCELLED)
            raise cancelled
        if denial:
            return call.deny(denial[0])
        assert result is not None
        result = _without_meta(result)

        # 7. scan the output
        verdict: tuple[str, str | None] | None = None
        with _stage("gateway.output_scan", denial) as scan_span:
            inventory = [t for tools in self.inventory.values() for t in tools]
            try:
                report = scan_output(result, server_id=server_id, inventory=inventory)
            except Exception as exc:  # noqa: BLE001 - cannot scan: withhold
                log.warning(
                    "output scan of %r failed (%s)", call.name, type(exc).__name__
                )
                denial.append(("deny_output", "scan_failed", _WITHHELD))
            else:
                rules = ",".join(sorted({f.rule_id for f in report.findings})) or None
                if report.verdict == "malicious":
                    denial.append(("deny_output", rules, _WITHHELD))
                elif report.verdict == "suspicious":
                    verdict = ("flag_output", rules)
                else:
                    verdict = ("allow", None)
                if verdict is not None:
                    scan_span.set_attribute("toolgate.decision", verdict[0])
        if denial:
            return call.deny(denial[0])
        assert verdict is not None
        call.finish(*verdict)
        return result

    def _pin_denial(
        self, server_id: str, tool_name: str, entry: SnapshotEntry | None
    ) -> _Denial | None:
        state = self.pins.state()
        if state is None:
            return ("deny_unpinned", "pins unavailable", _UNPINNED)
        sp = state[0].get(server_id)
        pin = sp.tools.get(tool_name) if sp is not None else None
        if pin is None:
            return ("deny_unpinned", None, _UNPINNED)
        if entry is None:
            if server_id not in self.inventory:
                # Down at the last refresh: its tools were omitted, which is
                # not drift. Nothing is forwarded.
                return (
                    "error_downstream",
                    "not listed (down)",
                    _unavailable(server_id),
                )
            return ("deny_drift", "not in verified snapshot", _DRIFT)
        if pin.hash != entry.tool_hash:
            return ("deny_drift", "pin changed since snapshot", _DRIFT)
        return None

    # -- refresh -----------------------------------------------------------

    async def _refresh(self) -> dict[str, SnapshotEntry]:
        self._started += 1
        generation = self._started
        state = self.pins.state()
        if state is None:  # stale or corrupt lockfile: fail closed
            snapshot: dict[str, SnapshotEntry] = {}
            inventory: dict[str, list[InventoryTool]] = {}
            quarantines: list[tuple[str, Quarantine]] = []
            quarantined = 0
            pinset: PinSet | None = None
        else:
            pinset, pinner = state
            snapshot, inventory, quarantines, quarantined = await self._build(
                pinset, pinner
            )
        trace.get_current_span().set_attribute(
            "toolgate.quarantined_count", quarantined
        )

        # A slower, older refresh never overwrites a newer one, and its
        # (outdated) review bookkeeping is skipped.
        if generation <= self._applied:
            return self.snapshot
        self._applied = generation
        self.snapshot = snapshot
        self.inventory = inventory

        for server_id, q in quarantines:
            self._alert(server_id, q)
        if self.reviews is not None and pinset is not None:
            await self._update_reviews(generation, pinset, quarantines)
        return snapshot

    async def _build(
        self, pinset: PinSet, pinner: Pinner
    ) -> tuple[
        dict[str, SnapshotEntry],
        dict[str, list[InventoryTool]],
        list[tuple[str, Quarantine]],
        int,
    ]:
        server_ids = self.pool.server_ids
        results = await asyncio.gather(
            *(self.pool.list_tools(sid) for sid in server_ids)
        )
        snapshot: dict[str, SnapshotEntry] = {}
        inventory: dict[str, list[InventoryTool]] = {}
        quarantines: list[tuple[str, Quarantine]] = []
        quarantined_count = 0
        for server_id, listed in zip(server_ids, results, strict=True):
            if listed is None:  # down: its tools are omitted
                continue
            info, tools = listed
            inventory[server_id] = [
                InventoryTool(server_id, n)
                for n in dict.fromkeys(t.name for t in tools)
            ]
            allowed, quarantined = self._verify(pinner, server_id, info, tools)
            quarantined_count += len(quarantined)
            quarantines.extend(
                (server_id, q) for q in quarantined if q.reason in _REVIEWED
            )
            for tool in allowed:
                entry = self._entry(pinset, server_id, tool.name)
                if entry is not None:
                    snapshot[entry.namespaced] = entry
        return snapshot, inventory, quarantines, quarantined_count

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

    def _entry(
        self, pinset: PinSet, server_id: str, tool_name: str
    ) -> SnapshotEntry | None:
        """Snapshot entry built from the pin of an allowed (hash-matching)
        tool. None (with a warning) if the pinned definition is unusable."""
        if self._compiled_for is not pinset:
            self._compiled, self._compiled_for = {}, pinset
        name = namespaced(server_id, tool_name)
        sp = pinset.get(server_id)
        pin = sp.tools.get(tool_name) if sp is not None else None
        if pin is None:  # cannot happen for an allowed tool; fail closed
            return None
        key = (server_id, tool_name, pin.hash)
        compiled = self._compiled.get(key)
        if compiled is None:
            try:
                served = Tool.model_validate(pin.definition)
                validator = compile_validator(served.inputSchema)
            except (ValueError, SchemaError) as exc:
                log.warning(
                    "pinned definition of %r (hash %s) is unusable (%s); "
                    "omitting the tool",
                    name,
                    pin.hash,
                    type(exc).__name__,
                )
                return None
            compiled = self._compiled[key] = (served, validator)
        served, validator = compiled
        return SnapshotEntry(server_id, served, name, pin.hash, validator)

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
        trace.get_current_span().add_event(
            "toolgate.alert",
            {
                "toolgate.server_id": server_id,
                "toolgate.tool": q.tool_name[:MAX_LOGGED_NAME],
                "toolgate.reason": q.reason,
                "toolgate.observed_hash": q.observed_hash or "",
                "toolgate.pinned_hash": q.pinned_hash or "",
            },
        )
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
        self,
        generation: int,
        pinset: PinSet,
        quarantines: list[tuple[str, Quarantine]],
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
                            "recording pending review for %s %r failed (%s)",
                            sid,
                            q.tool_name,
                            type(outcome).__name__,
                        )
                if generation == self._applied:  # not superseded meanwhile
                    await reviews.resolve_pinned(pinset)
        except Exception as exc:  # noqa: BLE001 - reviews never fail the list
            log.warning("updating pending reviews failed (%s)", type(exc).__name__)
