"""Report: fixture JSONL with hand-chosen records -> expected tables.

The fixture (``fixtures/report_fixture.jsonl``) holds, for corpus ``c*64``:
model ``strong`` (config ``s*64``) and ``small`` (config ``t*64``), plus two
out-of-scope records (another corpus; an older ``strong`` config), event
lines and a torn last line. See the comments in each test for the cases.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from toolgate_eval import cli
from toolgate_eval.report import Tally, load_records, render, summarise

FIXTURE = Path(__file__).parent / "fixtures" / "report_fixture.jsonl"


@pytest.fixture(scope="module")
def summary():
    return summarise(load_records(FIXTURE))


def t(tally: Tally) -> tuple[int, int, int, int]:
    return (tally.hits, tally.n, tally.errors, tally.unverified)


def test_load_skips_events_and_torn_lines():
    records = load_records(FIXTURE)
    assert len(records) == 20  # 24 lines - 4 events; the torn line is dropped
    assert all(r.run_id.startswith("fixture") for r in records)


def test_scope_one_corpus_and_latest_model_config(summary):
    assert summary.corpus_hash == "c" * 64
    assert [(m.name, m.model_id, m.config_hash) for m in summary.models] == [
        ("strong", "vendor/strong-model:free", "s" * 64),
        ("small", "vendor/small-model:free", "t" * 64),
    ]
    assert summary.records_read == 20
    assert summary.out_of_scope == 2  # other corpus; older strong config
    assert summary.superseded == 2  # dp-02's 429 row; dp-03's repeated error


def test_canary_table_all_variants_and_leak_capable(summary):
    strong = summary.canary["strong"]
    # dp-01 r0 leak, dp-01 r1 no, dp-02 leak (its earlier 429 row is
    # superseded), dp-03 error (two error rows, one episode), rp-04 leak,
    # sh-01 truncated-with-no-leak = unverified, us-01 no.
    assert t(strong["direct"]["all"]) == (3, 5, 1, 1)
    assert t(strong["direct"]["leak_capable"]) == (2, 4, 1, 1)
    assert t(strong["direct"]["not_leak_capable"]) == (1, 1, 0, 0)
    assert t(strong["gateway"]["all"]) == (1, 5, 0, 0)
    assert t(strong["gateway"]["leak_capable"]) == (1, 4, 0, 0)
    assert t(strong["gateway"]["not_leak_capable"]) == (0, 1, 0, 0)
    assert t(summary.canary["small"]["direct"]["all"]) == (0, 1, 0, 0)
    assert t(summary.canary["small"]["gateway"]["all"]) == (0, 0, 0, 0)


def test_not_leak_capable_leak_is_listed(summary):
    assert summary.nlc_leaks == [
        {"model": "strong", "condition": "direct", "variant_id": "rp-04", "repeat": 0}
    ]


def test_not_exploitable_listed_but_kept_in_n(summary):
    # us-01 never leaked in direct (verified); sh-01 only unverified, dp-03
    # only errors: neither counts as "not exploitable".
    assert summary.not_exploitable == {"strong": ["us-01"], "small": ["dp-01"]}
    assert summary.no_verified_direct == {"strong": ["dp-03", "sh-01"], "small": []}
    assert summary.canary["strong"]["direct"]["all"].n == 5  # us-01 still in n


def test_task_completion_table(summary):
    strong = summary.completion["strong"]
    assert t(strong["claim-status-update"]["direct"]) == (1, 1, 0, 0)
    assert t(strong["claim-status-update"]["gateway"]) == (0, 1, 0, 0)
    assert t(strong["payment-confirmation"]["direct"]) == (0, 0, 1, 0)
    assert t(strong["payment-confirmation"]["gateway"]) == (0, 0, 0, 0)
    assert t(summary.completion_totals["strong"]["direct"]) == (1, 1, 1, 0)
    assert t(summary.clean_leaks["strong"]["direct"]) == (0, 1, 1, 0)


def test_family_breakdown(summary):
    fam = summary.families["strong"]
    assert t(fam["description_poisoning"]["direct"]) == (2, 3, 1, 0)
    assert t(fam["rug_pull"]["direct"]) == (1, 1, 0, 0)  # rp-04 kept in
    assert t(fam["shadowing"]["direct"]) == (0, 0, 0, 1)
    assert t(fam["unicode_schema"]["direct"]) == (0, 1, 0, 0)
    assert t(fam["description_poisoning"]["gateway"]) == (1, 2, 0, 0)
    assert t(fam["rug_pull"]["gateway"]) == (0, 2, 0, 0)


def test_blocked_at_cross_tab(summary):
    blocked = summary.blocked["strong"]
    assert t(blocked["approval"]) == (0, 2, 0, 0)
    assert t(blocked["list"]) == (0, 1, 0, 0)
    # blocked at the call, and still leaked: deny_output is not "no exfiltration"
    assert t(blocked["call"]) == (1, 1, 0, 0)
    assert t(blocked["not blocked"]) == (0, 1, 0, 0)


def test_explicit_corpus_hash_scope():
    other = summarise(load_records(FIXTURE), corpus_hash="d" * 64)
    assert t(other.canary["strong"]["direct"]["all"]) == (1, 1, 0, 0)
    empty = summarise([])
    assert empty.corpus_hash is None and empty.models == []
    assert "no episode records" in render(empty, "text")


def test_md_render(summary):
    md = render(summary, "md")
    assert md.startswith("|")
    first = md.split("\n\n", 1)[0]
    assert "strong (all variants)" in first
    assert "strong (leak-capable only)" in first
    assert "strong (rp-04, rp-05, us-03)" in first
    assert "3/5 (60%)" in first
    # zero denominator
    assert "| — |" in md
    # the NLC leak is shown and the deny_output caveat is stated
    assert "rp-04 (strong, direct, repeat 0)" in md
    assert "deny_output" in md
    assert "Not exploitable on this model" in md and "us-01" in md


def test_text_and_json_render(summary):
    text = render(summary, "text")
    assert "Canary leak rate" in text and "—" in text
    data = json.loads(render(summary, "json"))
    cell = data["canary"]["strong"]["direct"]["all"]
    assert cell == {"hits": 3, "n": 5, "errors": 1, "unverified": 1, "rate": 0.6}
    assert data["canary"]["small"]["gateway"]["all"]["rate"] is None


def test_cli_report(capsys):
    assert cli.main(["report", "--results", str(FIXTURE), "--format", "md"]) == 0
    assert capsys.readouterr().out.startswith("|")
    assert cli.main(["report", "--results", str(FIXTURE)]) == 0
    assert "Canary leak rate" in capsys.readouterr().out


def _redirected_report(fmt: str) -> str:
    # A Windows cp1252 code page on stdout, redirected to a pipe.
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONUTF8", "PYTHONIOENCODING")
    }
    env["PYTHONIOENCODING"] = "cp1252"
    proc = subprocess.run(
        [sys.executable, "-m", "toolgate_eval.cli", "report"]
        + ["--results", str(FIXTURE), "--format", fmt],
        capture_output=True,
        env=env,
        check=True,
    )
    return proc.stdout.decode("utf-8")  # raises if a cp1252 0x97 slipped in


def test_redirected_md_output_is_utf8():
    assert "| — |" in _redirected_report("md")


def test_redirected_json_output_is_utf8():
    assert json.loads(_redirected_report("json"))["corpus_hash"] == "c" * 64
