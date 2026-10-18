"""Build pins from a live tool listing (shared by demo and approve)."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import mcp.types

from toolgate_pin.canon import as_definition, pin_hash
from toolgate_pin.models import InventoryTool, ServerPin, Target, ToolPin
from toolgate_pin.scanner import scan_definition


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def pin_server(
    server_id: str,
    server_name: str,
    target: Target,
    tools: Iterable[mcp.types.Tool | Mapping[str, Any]],
    *,
    approved_by: str,
    prior: ServerPin | None = None,
) -> ServerPin:
    """Pin every tool; tools unchanged since ``prior`` keep their prior approval."""
    items = list(tools)
    defs = [as_definition(t) for t in items]
    inventory = tuple(InventoryTool(server_id, d["name"]) for d in defs)
    approved_at = _now()
    pins: dict[str, ToolPin] = {}
    for tool, definition in zip(items, defs, strict=True):
        name = definition["name"]
        h = pin_hash(tool)
        old = prior.tools.get(name) if prior is not None else None
        if old is not None and old.hash == h:
            pins[name] = old
            continue
        report = scan_definition(
            tool,
            server_id=server_id,
            prior=old.definition if old is not None else None,
            inventory=inventory,
        )
        pins[name] = ToolPin(
            name=name,
            hash=h,
            definition=definition,
            approved_by=approved_by,
            approved_at=approved_at,
            scan={
                "verdict": report.verdict,
                "rule_ids": sorted({f.rule_id for f in report.findings}),
                "tiers": list(report.tiers_run),
            },
        )
    return ServerPin(
        server_id=server_id, server_name=server_name, target=target, tools=pins
    )
