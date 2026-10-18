"""Data models for pins, scan reports and verification results."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from typing import Any, Literal


@dataclass(frozen=True)
class Target:
    url: str | None = None
    command: tuple[str, ...] | None = None
    # Header templates such as "Authorization: Bearer ${TOOLGATE_TOKEN}".
    headers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ToolPin:
    name: str
    hash: str
    definition: dict[str, Any]
    approved_by: str
    approved_at: str
    # {"verdict": str, "rule_ids": list[str], "tiers": list[str]}
    scan: dict[str, Any]
    override_reason: str | None = None


@dataclass(frozen=True)
class ServerPin:
    server_id: str
    server_name: str
    target: Target
    # Treated as immutable: never mutate in place.
    tools: Mapping[str, ToolPin]


@dataclass(frozen=True)
class PinSet:
    # Treated as immutable: never mutate in place; use with_server.
    servers: Mapping[str, ServerPin] = field(default_factory=dict)

    def with_server(self, sp: ServerPin) -> PinSet:
        servers = dict(self.servers)
        servers[sp.server_id] = sp
        return replace(self, servers=servers)

    def get(self, server_id: str) -> ServerPin | None:
        return self.servers.get(server_id)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Literal["low", "medium", "high"]
    field_path: str
    evidence: str
    message: str
    preexisting: bool = False


@dataclass(frozen=True)
class JudgeResult:
    verdict: Literal["benign", "suspicious", "malicious"]
    reasons: tuple[str, ...]
    model: str


@dataclass(frozen=True)
class ScanReport:
    findings: tuple[Finding, ...]
    tiers_run: tuple[str, ...]
    verdict: str
    classifier_score: float | None = None
    judge: JudgeResult | None = None
    unavailable: tuple[str, ...] = ()


@dataclass(frozen=True)
class InventoryTool:
    server_id: str
    name: str
    definition: dict[str, Any] | None = None


@dataclass(frozen=True)
class Quarantine:
    tool_name: str
    reason: Literal["drift", "unpinned", "removed", "server_drift"]
    observed_hash: str | None
    pinned_hash: str | None
    diff: str
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class VerifyResult:
    allowed: list
    quarantined: list[Quarantine]

    @property
    def ok(self) -> bool:
        return not self.quarantined
