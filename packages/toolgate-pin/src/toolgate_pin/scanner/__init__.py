"""Poisoning scanner: rules tier (always), optional classifier and judge tiers."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any

import mcp.types

from toolgate_pin import tracing
from toolgate_pin.canon import as_definition
from toolgate_pin.models import Finding, InventoryTool, JudgeResult, ScanReport
from toolgate_pin.scanner import rules
from toolgate_pin.scanner.config import DEFAULT_CONFIG, ScanConfig

TIERS = ("rules", "classifier", "judge")

__all__ = [
    "DEFAULT_CONFIG",
    "TIERS",
    "ScanConfig",
    "decide_verdict",
    "scan_definition",
    "scan_output",
    "unavailable_reason",
]


def decide_verdict(
    findings: Iterable[Finding],
    classifier_score: float | None,
    judge: JudgeResult | None,
    config: ScanConfig,
) -> str:
    """malicious > suspicious > benign. Preexisting findings do not count."""
    severities = {f.severity for f in findings if not f.preexisting}
    judged = judge.verdict if judge is not None else None
    score = classifier_score
    if (
        "high" in severities
        or (score is not None and score >= config.classifier_high)
        or judged == "malicious"
    ):
        return "malicious"
    if (
        "medium" in severities
        or (score is not None and score >= config.classifier_grey)
        or judged == "suspicious"
    ):
        return "suspicious"
    return "benign"


def _rules_tier(
    definition: dict[str, Any],
    prior: dict[str, Any] | None,
    server_id: str,
    inventory: tuple[InventoryTool, ...],
    config: ScanConfig,
) -> tuple[Finding, ...]:
    """Rules findings; preexisting when every occurrence, with its surrounding
    context, also occurs in the prior and no match was cut off by the budget."""
    matches = rules.definition_matches(
        definition, server_id=server_id, inventory=inventory, config=config
    )
    if prior is None:
        return tuple(m.finding for m in matches)
    before: set[rules.MatchKey] = set()
    for m in rules.definition_matches(
        prior, server_id=server_id, inventory=inventory, config=config
    ):
        before |= m.keys
    return tuple(
        replace(m.finding, preexisting=True)
        if m.complete and m.keys <= before
        else m.finding
        for m in matches
    )


def scan_definition(
    tool: mcp.types.Tool | Mapping[str, Any],
    *,
    server_id: str,
    prior: mcp.types.Tool | Mapping[str, Any] | None = None,
    inventory: Iterable[InventoryTool] = (),
    tiers: Sequence[str] = ("rules",),
    config: ScanConfig = DEFAULT_CONFIG,
    judge: Any = None,
    classifier: Any = None,
) -> ScanReport:
    unknown = [t for t in tiers if t not in TIERS]
    if unknown:
        raise ValueError(f"unknown scan tier(s): {', '.join(unknown)}")
    definition = as_definition(tool)
    prior_def = as_definition(prior) if prior is not None else None
    inv = tuple(inventory)
    raw_name = definition.get("name")
    name = raw_name if isinstance(raw_name, str) else ""

    with tracing.span(
        "toolgate.pin.scan",
        **{"toolgate.server_id": server_id, "toolgate.tool.name": name},
    ) as span:
        findings: tuple[Finding, ...] = ()
        score: float | None = None
        judged: JudgeResult | None = None
        tiers_run: list[str] = []
        unavailable: list[str] = []
        for tier in dict.fromkeys(tiers):
            if tier == "rules":
                findings = _rules_tier(definition, prior_def, server_id, inv, config)
                tiers_run.append(tier)
            elif tier == "classifier":
                score = _run_classifier(classifier, definition)
                (tiers_run if score is not None else unavailable).append(tier)
            else:
                judged = _run_judge(judge, definition, prior_def)
                (tiers_run if judged is not None else unavailable).append(tier)

        verdict = decide_verdict(findings, score, judged, config)
        span.set_attribute("toolgate.verdict", verdict)
        span.set_attribute("toolgate.tiers_run", tuple(tiers_run))
        span.set_attribute("toolgate.finding_count", len(findings))
    return ScanReport(
        findings=findings,
        tiers_run=tuple(tiers_run),
        verdict=verdict,
        classifier_score=score,
        judge=judged,
        unavailable=tuple(unavailable),
    )


def _run_classifier(classifier: Any, definition: dict[str, Any]) -> float | None:
    if classifier is None:
        return None
    try:
        return float(classifier.score(definition))
    except Exception:  # noqa: BLE001  a broken tier is reported unavailable
        return None


def _run_judge(
    judge: Any, definition: dict[str, Any], prior: dict[str, Any] | None
) -> JudgeResult | None:
    if judge is None:
        return None
    try:
        return judge.judge(definition, prior=prior)
    except Exception:  # noqa: BLE001  a broken tier is reported unavailable
        return None


def unavailable_reason(tier: str, *, judge: Any, classifier: Any) -> str | None:
    """Why ``tier`` did not run, from the scorer's own short error code: the
    judge's ``last_error`` ("HTTP 429", "invalid JSON", an exception type) or
    the classifier's ``load_error`` (an exception type). Never keys or URLs."""
    scorer, attr = {
        "judge": (judge, "last_error"),
        "classifier": (classifier, "load_error"),
    }.get(tier, (None, ""))
    reason = getattr(scorer, attr, None) if scorer is not None else None
    return reason if isinstance(reason, str) and reason else None


def _output_roots(result: Any) -> list[tuple[str, Any]]:
    if isinstance(result, str):
        return [("", result)]
    if isinstance(result, mcp.types.CallToolResult):
        result = result.model_dump(by_alias=True, exclude_none=True)
    if not isinstance(result, Mapping):
        raise TypeError(
            f"expected CallToolResult, str or Mapping, got {type(result).__name__}"
        )
    if "content" not in result and "structuredContent" not in result:
        return [("", result)]
    roots: list[tuple[str, Any]] = []
    content = result.get("content")
    if isinstance(content, (list, tuple)):
        for i, item in enumerate(content):
            if hasattr(item, "model_dump"):
                item = item.model_dump(by_alias=True, exclude_none=True)
            if not isinstance(item, Mapping):
                continue
            if isinstance(item.get("text"), str):
                roots.append((f"/content/{i}/text", item["text"]))
            resource = item.get("resource")
            if isinstance(resource, Mapping) and isinstance(resource.get("text"), str):
                roots.append((f"/content/{i}/resource/text", resource["text"]))
    if result.get("structuredContent") is not None:
        roots.append(("/structuredContent", result["structuredContent"]))
    return roots


def scan_output(
    result: mcp.types.CallToolResult | str | Mapping[str, Any],
    *,
    server_id: str,
    inventory: Iterable[InventoryTool] = (),
    config: ScanConfig = DEFAULT_CONFIG,
) -> ScanReport:
    roots = _output_roots(result)
    with tracing.span("toolgate.pin.scan", **{"toolgate.server_id": server_id}) as span:
        findings = rules.output_findings(
            roots, server_id=server_id, inventory=tuple(inventory), config=config
        )
        verdict = decide_verdict(findings, None, None, config)
        span.set_attribute("toolgate.verdict", verdict)
        span.set_attribute("toolgate.tiers_run", ("rules",))
        span.set_attribute("toolgate.finding_count", len(findings))
    return ScanReport(findings=findings, tiers_run=("rules",), verdict=verdict)
