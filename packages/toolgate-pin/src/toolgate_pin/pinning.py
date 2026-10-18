"""Build pins from a live tool listing (shared by demo and approve)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any

import mcp.types

from toolgate_pin.canon import as_definition, pin_hash
from toolgate_pin.models import InventoryTool, ScanReport, ServerPin, Target, ToolPin
from toolgate_pin.scanner import scan_definition


def now_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def duplicate_names(names: Iterable[str]) -> list[str]:
    """Names listed more than once, in first-seen order."""
    counts = Counter(names)
    return [n for n in counts if counts[n] > 1]


def scan_summary(report: ScanReport) -> dict[str, Any]:
    return {
        "verdict": report.verdict,
        "rule_ids": sorted({f.rule_id for f in report.findings}),
        "tiers": list(report.tiers_run),
    }


def pin_server(
    server_id: str,
    server_name: str,
    target: Target,
    tools: Iterable[mcp.types.Tool | Mapping[str, Any]],
    *,
    approved_by: str,
    prior: ServerPin | None = None,
    reports: Mapping[str, ScanReport] | None = None,
    override_reasons: Mapping[str, str] | None = None,
) -> ServerPin:
    """Pin every tool; tools unchanged since ``prior`` keep their prior approval.

    ``reports`` supplies scans already run for changed tools (otherwise the
    rules tier runs here). ``override_reasons`` maps tool name to the recorded
    reason for an approval that overrode a malicious verdict. Raises ValueError
    when a tool name appears more than once.
    """
    items = list(tools)
    defs = [as_definition(t) for t in items]
    dupes = duplicate_names(d["name"] for d in defs)
    if dupes:
        raise ValueError(f"duplicate tool name(s): {', '.join(dupes)}")
    inventory = tuple(InventoryTool(server_id, d["name"]) for d in defs)
    approved_at = now_utc()
    reports = reports or {}
    override_reasons = override_reasons or {}
    pins: dict[str, ToolPin] = {}
    for tool, definition in zip(items, defs, strict=True):
        name = definition["name"]
        h = pin_hash(tool)
        old = prior.tools.get(name) if prior is not None else None
        if old is not None and old.hash == h:
            pins[name] = old
            continue
        report = reports.get(name) or scan_definition(
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
            scan=scan_summary(report),
            override_reason=override_reasons.get(name),
        )
    return ServerPin(
        server_id=server_id, server_name=server_name, target=target, tools=pins
    )
