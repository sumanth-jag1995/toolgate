"""`bench`: run the corpus through the scanner tiers and build the headline table.

Columns are cumulative tiers: "rules", then "+classifier" (rules + classifier),
then "+judge" (rules + classifier + judge, or rules + judge when the classifier
did not run). An item is detected (malicious) or a false positive (benign) when
its verdict is not ``benign``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from toolgate_pin.corpus import InventoryEntry, load_corpus
from toolgate_pin.models import InventoryTool, PinSet, ScanReport, Target
from toolgate_pin.pinner import Pinner
from toolgate_pin.pinning import pin_server
from toolgate_pin.scanner import (
    TIERS,
    decide_verdict,
    scan_definition,
    scan_output,
    unavailable_reason,
)
from toolgate_pin.scanner.config import DEFAULT_CONFIG
from toolgate_pin.store import InMemoryStore

FAMILIES = ("description_poisoning", "rug_pull", "shadowing", "unicode_schema")
COLUMNS = ("rules", "+classifier", "+judge")
CORPUS_VERSION = "v1"
_BENCH_TARGET = Target(command=("toolgate-pin-bench",))


@dataclass(frozen=True)
class BenchRow:
    family: str
    n: int
    detected: dict[str, int]  # keyed by the cumulative columns that ran
    caught_by_pin: int | None  # rug pulls only


@dataclass(frozen=True)
class BenchResult:
    tiers_run: tuple[str, ...]
    unavailable: tuple[str, ...]
    judge_model: str | None
    rows: list[BenchRow]
    output_injection: tuple[int, int]  # (detected, n)
    benign_fp: dict[str, int]
    benign_n: int
    split: str
    # tier -> short cause ("HTTP 429", "OSError") when the scorer reported one
    unavailable_reasons: dict[str, str] = field(default_factory=dict)


def _inventory(entries: Sequence[InventoryEntry]) -> tuple[InventoryTool, ...]:
    return tuple(InventoryTool(e.server_id, e.name, e.definition) for e in entries)


def _cumulative(report: ScanReport, ran: tuple[str, ...]) -> dict[str, bool]:
    """Non-benign verdict per cumulative column, for the columns that ran."""
    findings = report.findings
    score = report.classifier_score if "classifier" in ran else None
    judged = report.judge if "judge" in ran else None
    flagged = {"rules": decide_verdict(findings, None, None, DEFAULT_CONFIG)}
    if "classifier" in ran:
        flagged["+classifier"] = decide_verdict(findings, score, None, DEFAULT_CONFIG)
    if "judge" in ran:
        flagged["+judge"] = decide_verdict(findings, score, judged, DEFAULT_CONFIG)
    return {col: verdict != "benign" for col, verdict in flagged.items()}


def _caught_by_pin(server_id: str, approved: dict, mutated: dict) -> bool:
    sp = pin_server(
        server_id, server_id, _BENCH_TARGET, [approved], approved_by="bench"
    )
    pinner = Pinner(InMemoryStore(PinSet().with_server(sp)))
    result = pinner.verify(server_id, [mutated])
    return any(q.reason == "drift" for q in result.quarantined)


def run_bench(
    *,
    split: Literal["test", "dev"] = "test",
    tiers: Sequence[str] = ("rules",),
    judge: Any = None,
    classifier: Any = None,
) -> BenchResult:
    unknown = [t for t in tiers if t not in TIERS]
    if unknown:
        raise ValueError(f"unknown tier(s): {', '.join(unknown)}")
    requested = tuple(t for t in TIERS if t == "rules" or t in tiers)
    corpus = load_corpus(split)
    reports: list[tuple[str, ScanReport]] = []  # (row key, report)
    reasons: dict[str, str] = {}

    def note_unavailable(report: ScanReport) -> None:
        for tier in report.unavailable:
            why = unavailable_reason(tier, judge=judge, classifier=classifier)
            if why is not None:
                reasons.setdefault(tier, why)

    pin_caught = 0
    output_hits = output_n = 0

    for v in corpus.malicious:
        inventory = _inventory(v.inventory)
        if v.family == "rug_pull" and v.mutated is not None:
            tool, prior = v.mutated, v.approved
            pin_caught += _caught_by_pin(v.server_id, v.approved, v.mutated)
        else:
            tool, prior = v.approved, None
        report = scan_definition(
            tool,
            server_id=v.server_id,
            prior=prior,
            inventory=inventory,
            tiers=requested,
            judge=judge,
            classifier=classifier,
        )
        note_unavailable(report)
        reports.append((v.family, report))
        if v.output_sample is not None:
            output_n += 1
            out = scan_output(
                v.output_sample, server_id=v.server_id, inventory=inventory
            )
            output_hits += out.verdict != "benign"

    for b in corpus.benign:
        report = scan_definition(
            b.definition,
            server_id=b.server_id,
            inventory=_inventory(b.inventory),
            tiers=requested,
            judge=judge,
            classifier=classifier,
        )
        note_unavailable(report)
        reports.append(("benign", report))

    # A tier counts as run only if it ran on every item; a partial run (say,
    # judge API failures part-way) is reported unavailable, never as a pass.
    ran = tuple(t for t in requested if all(t in r.tiers_run for _, r in reports))
    unavailable = tuple(t for t in requested if t not in ran)
    columns = [c for c, t in zip(COLUMNS, TIERS, strict=True) if t in ran]

    counts: dict[str, dict[str, int]] = {
        key: dict.fromkeys(columns, 0) for key in (*FAMILIES, "benign")
    }
    sizes = dict.fromkeys((*FAMILIES, "benign"), 0)
    judge_model: str | None = None
    for key, report in reports:
        sizes[key] += 1
        for col, hit in _cumulative(report, ran).items():
            counts[key][col] += hit
        if report.judge is not None and judge_model is None:
            judge_model = report.judge.model
    if "judge" not in ran:
        judge_model = None

    rows = [
        BenchRow(
            family=f,
            n=sizes[f],
            detected=counts[f],
            caught_by_pin=pin_caught if f == "rug_pull" else None,
        )
        for f in FAMILIES
    ]
    return BenchResult(
        tiers_run=ran,
        unavailable=unavailable,
        judge_model=judge_model,
        rows=rows,
        output_injection=(output_hits, output_n),
        benign_fp=counts["benign"],
        benign_n=sizes["benign"],
        split=split,
        unavailable_reasons={t: reasons[t] for t in unavailable if t in reasons},
    )


# =============================================================================
# Rendering (spec §5.7)
# =============================================================================

DASH = "—"
_HEAD = ("family", "n", "rules", "+classifier", "+judge", "caught by pin")


def _header(result: BenchResult) -> str:
    tiers = ", ".join(result.tiers_run)
    if result.judge_model:
        tiers += f" (model: {result.judge_model})"
    if result.unavailable:
        why = result.unavailable_reasons
        named = (f"{t} ({why[t]})" if t in why else t for t in result.unavailable)
        tiers += f"; unavailable: {', '.join(named)}"
    return (
        f"toolgate-pin bench {DASH} tiers: {tiers}   "
        f"corpus {CORPUS_VERSION}, split {result.split}"
    )


def _cell(detected: dict[str, int], col: str, n: int) -> str:
    return f"{detected[col]}/{n}" if col in detected else DASH


def _table(result: BenchResult) -> list[tuple[str, ...]]:
    """Rows of cells (without the header row); rows may be short."""
    out: list[tuple[str, ...]] = []
    for row in result.rows:
        pin = "n/a" if row.caught_by_pin is None else f"{row.caught_by_pin}/{row.n}"
        out.append(
            (
                row.family,
                str(row.n),
                *(_cell(row.detected, c, row.n) for c in COLUMNS),
                pin,
            )
        )
    hits, k = result.output_injection
    out.append(
        (
            "output_injection",
            str(k),
            f"{hits}/{k}",
            f"(rules only {DASH} runtime scanner)",
        )
    )
    out.append(
        (
            "benign (false pos.)",
            str(result.benign_n),
            *(_cell(result.benign_fp, c, result.benign_n) for c in COLUMNS),
        )
    )
    return out


def _text(result: BenchResult) -> str:
    widths = (22, 2, 6, 12, 7)

    def line(cells: tuple[str, ...]) -> str:
        parts = [f"{cells[0]:<{widths[0]}} {cells[1]:>{widths[1]}}"]
        for i, cell in enumerate(cells[2:], start=2):
            last = i == len(cells) - 1 or i >= len(widths)
            parts.append(cell if last else f"{cell:<{widths[i]}}")
        return "  ".join(parts).rstrip()

    lines = [_header(result), line(_HEAD)]
    lines.extend(line(cells) for cells in _table(result))
    return "\n".join(lines)


def _md(result: BenchResult) -> str:
    lines = [
        _header(result),
        "",
        "| " + " | ".join(_HEAD) + " |",
        "|---|--:|--:|--:|--:|--:|",
    ]
    for cells in _table(result):
        if cells[0] == "output_injection":
            cells = (*cells[:3], cells[3].strip("()"), "", "")
        padded = (*cells, *([""] * (len(_HEAD) - len(cells))))
        lines.append("| " + " | ".join(padded) + " |")
    return "\n".join(lines)


def render(result: BenchResult, fmt: Literal["text", "md", "json"]) -> str:
    if fmt == "text":
        return _text(result)
    if fmt == "md":
        return _md(result)
    if fmt == "json":
        data = asdict(result)
        data["corpus"] = CORPUS_VERSION
        return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
    raise ValueError(f"unknown format: {fmt!r}")
