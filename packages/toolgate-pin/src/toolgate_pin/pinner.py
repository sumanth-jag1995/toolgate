"""Pinner.verify: drop changed tools from a tool list without raising on content."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import mcp.types

from toolgate_pin import tracing
from toolgate_pin.canon import as_definition, pin_hash
from toolgate_pin.difftext import diff
from toolgate_pin.models import (
    Finding,
    InventoryTool,
    PinSet,
    Quarantine,
    ServerPin,
    VerifyResult,
)
from toolgate_pin.scanner import scan_definition
from toolgate_pin.store import PinStore

_UNCANONICALIZABLE = "definition could not be canonicalized"

# Frozen trace vocabulary for toolgate.decision.
_DECISION = {
    None: "allow",
    "drift": "quarantine_drift",
    "unpinned": "quarantine_unpinned",
    "removed": "quarantine_removed",
    "server_drift": "quarantine_server",
}


def _tool_name(tool: Any) -> str:
    if isinstance(tool, mcp.types.Tool):
        name = tool.name
    elif isinstance(tool, Mapping):
        name = tool.get("name")
    else:
        raise TypeError(f"expected Tool or Mapping, got {type(tool).__name__}")
    if not isinstance(name, str):
        raise TypeError("tool is missing a string 'name'")
    return name


def _server_name(server_info: Any) -> str | None:
    if server_info is None:
        return None
    if isinstance(server_info, Mapping):
        return server_info.get("name")
    return getattr(server_info, "name", None)


def _safe_hash(tool: Any) -> tuple[str | None, str]:
    """Return (hash, error). Never raises on tool content."""
    try:
        return pin_hash(tool), ""
    except Exception as exc:  # noqa: BLE001  hostile content must never crash the gateway
        return None, f"{_UNCANONICALIZABLE} ({type(exc).__name__})"


def _safe_diff(pinned: dict | None, tool: Any, error: str) -> str:
    if error:
        return error
    try:
        return diff(pinned, as_definition(tool))
    except Exception as exc:  # noqa: BLE001
        return f"{_UNCANONICALIZABLE} for diff ({type(exc).__name__})"


def _safe_findings(
    tool: Any,
    server_id: str,
    prior: dict | None,
    inventory: tuple[InventoryTool, ...],
) -> tuple[Finding, ...]:
    """Rules-tier findings for a quarantined tool. Never raises on tool content."""
    try:
        return scan_definition(
            tool, server_id=server_id, prior=prior, inventory=inventory
        ).findings
    except Exception:  # noqa: BLE001  hostile content must never crash the gateway
        return ()


class Pinner:
    def __init__(self, store: PinStore) -> None:
        self._store = store
        self._pins: PinSet = store.load()

    def reload(self) -> None:
        self._pins = self._store.load()

    def verify(
        self,
        server_id: str,
        tools: Iterable[mcp.types.Tool | Mapping[str, Any]],
        *,
        server_info: Any | None = None,
    ) -> VerifyResult:
        items = list(tools)
        names = [_tool_name(t) for t in items]  # TypeError before any work
        sp: ServerPin | None = self._pins.get(server_id)
        info_name = _server_name(server_info)
        server_drift = (
            sp is not None and info_name is not None and info_name != sp.server_name
        )

        allowed: list = []
        quarantined: list[Quarantine] = []
        with tracing.span(
            "toolgate.pin.verify", **{"toolgate.server_id": server_id}
        ) as span:
            # Pinner-triggered scans see this server's other tools from this call.
            inventory = tuple(InventoryTool(server_id, n) for n in dict.fromkeys(names))
            first_seen: dict[str, str | None] = {}
            for tool, name in zip(items, names, strict=True):
                observed, err = _safe_hash(tool)
                pin = sp.tools.get(name) if sp is not None else None
                reason: str | None
                if server_drift:
                    reason = "server_drift"
                elif name in first_seen:
                    # Duplicate name: must match the pin, or the first occurrence.
                    baseline = pin.hash if pin is not None else first_seen[name]
                    if observed is not None and observed == baseline:
                        reason = None if pin is not None else "unpinned"
                    else:
                        reason = "drift"
                elif pin is None:
                    reason = "unpinned"
                elif observed is not None and observed == pin.hash:
                    reason = None
                else:
                    reason = "drift"
                first_seen.setdefault(name, observed)

                span.add_event(
                    "toolgate.tool",
                    {
                        "toolgate.tool.name": name,
                        "toolgate.tool.hash": observed or "uncanonicalizable",
                        "toolgate.decision": _DECISION[reason],
                    },
                )
                if reason is None:
                    allowed.append(tool)
                    continue
                quarantined.append(
                    Quarantine(
                        tool_name=name,
                        reason=reason,  # type: ignore[arg-type]
                        observed_hash=observed,
                        pinned_hash=pin.hash if pin is not None else None,
                        diff=_safe_diff(pin.definition if pin else None, tool, err),
                        findings=_safe_findings(
                            tool,
                            server_id,
                            pin.definition if pin is not None else None,
                            inventory,
                        )
                        if reason in ("drift", "unpinned")
                        else (),
                    )
                )

            if sp is not None:
                present = set(names)
                for name, pin in sp.tools.items():
                    if name in present:
                        continue
                    span.add_event(
                        "quarantine_removed",
                        {
                            "toolgate.tool.name": name,
                            "toolgate.tool.hash": pin.hash,
                            "toolgate.decision": _DECISION["removed"],
                        },
                    )
                    quarantined.append(
                        Quarantine(
                            tool_name=name,
                            reason="removed",
                            observed_hash=None,
                            pinned_hash=pin.hash,
                            diff=diff(pin.definition, None),
                        )
                    )
            span.set_attribute("toolgate.allowed_count", len(allowed))
            span.set_attribute("toolgate.quarantined_count", len(quarantined))
        return VerifyResult(allowed=allowed, quarantined=quarantined)
