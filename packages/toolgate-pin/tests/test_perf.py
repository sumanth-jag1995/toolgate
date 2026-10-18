"""Performance targets from the design spec (medians, after a modest warm-up)."""

from __future__ import annotations

import statistics
import time

from toolgate_pin import InMemoryStore, Pinner, scan_output
from toolgate_pin.canon import as_definition, pin_hash
from toolgate_pin.models import PinSet, ServerPin, Target, ToolPin

RUNS = 200
WARMUP = 20


def _median_seconds(fn) -> float:
    for _ in range(WARMUP):
        fn()
    samples = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return statistics.median(samples)


def _tools() -> list[dict]:
    return [
        {
            "name": f"tool_{i}",
            "description": f"Returns record number {i} from the ledger.",
            "inputSchema": {
                "type": "object",
                "properties": {"id": {"type": "string", "description": "Record id"}},
                "required": ["id"],
            },
        }
        for i in range(12)
    ]


def test_verify_12_tools_under_1ms():
    tools = _tools()
    pins = {
        t["name"]: ToolPin(
            name=t["name"],
            hash=pin_hash(t),
            definition=as_definition(t),
            approved_by="me",
            approved_at="2026-10-18T00:00:00Z",
            scan={"verdict": "benign", "rule_ids": [], "tiers": ["rules"]},
        )
        for t in tools
    }
    sp = ServerPin(
        server_id="ledger",
        server_name="ledger",
        target=Target(command=("srv",)),
        tools=pins,
    )
    pinner = Pinner(InMemoryStore(PinSet({"ledger": sp})))
    assert not pinner.verify("ledger", tools).quarantined
    assert _median_seconds(lambda: pinner.verify("ledger", tools)) < 0.001


def test_scan_output_4kb_under_2ms():
    sentence = "The quarterly report lists 14 open invoices totalling 9,210 EUR. "
    text = (sentence * 70)[:4096]
    assert len(text) == 4096
    assert scan_output(text, server_id="ledger").verdict == "benign"
    assert _median_seconds(lambda: scan_output(text, server_id="ledger")) < 0.002
