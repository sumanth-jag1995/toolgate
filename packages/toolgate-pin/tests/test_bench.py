from __future__ import annotations

import json
import os
import subprocess
import sys

from toolgate_pin import cli
from toolgate_pin.bench import render, run_bench


def test_render_shape_rules_only():
    out = render(run_bench(), "text")
    assert (
        "tiers: rules" in out
        and "description_poisoning  10" in out
        and "benign (false pos.)    50" in out
        and "—" in out
    )


def test_rug_pulls_all_caught_by_pin():
    assert (
        next(r for r in run_bench().rows if r.family == "rug_pull").caught_by_pin == 10
    )


def test_md_format_is_table():
    assert render(run_bench(), "md").splitlines()[2].startswith("|")


def test_unavailable_tier_named():
    out = render(run_bench(tiers=("rules", "judge")), "text")
    assert "unavailable: judge" in out


def test_cli_bench_exit_0(capsys):
    assert cli.main(["bench", "--tiers", "rules"]) == 0


def test_cli_auto_mode_lists_unrun_tiers(capsys, monkeypatch):
    # No OPENROUTER_API_KEY and no classifier module: both are unavailable.
    from toolgate_pin.scanner import classifier

    monkeypatch.setattr(classifier, "available", lambda: False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert cli.main(["bench", "--split", "dev"]) == 0
    out = capsys.readouterr().out
    assert "tiers: rules; unavailable: classifier, judge" in out


def _redirected_bench(fmt: str) -> str:
    # Simulate a Windows cp1252 code page on stdout, redirected to a pipe.
    env = {
        k: v
        for k, v in os.environ.items()
        if k not in ("PYTHONUTF8", "PYTHONIOENCODING")
    }
    env["PYTHONIOENCODING"] = "cp1252"
    proc = subprocess.run(
        [sys.executable, "-m", "toolgate_pin.cli", "bench", "--split", "dev"]
        + ["--tiers", "rules", "--format", fmt],
        capture_output=True,
        env=env,
        check=True,
    )
    return proc.stdout.decode("utf-8")  # raises if cp1252 byte 0x97 slipped in


def test_redirected_md_output_is_utf8():
    out = _redirected_bench("md")
    assert "| — |" in out and "toolgate-pin bench — tiers: rules" in out


def test_redirected_json_output_is_utf8():
    assert json.loads(_redirected_bench("json"))["split"] == "dev"


def test_json_format_parses():
    data = json.loads(render(run_bench(split="dev"), "json"))
    assert data["split"] == "dev" and data["tiers_run"] == ["rules"]


def test_cli_bench_rejects_unknown_tier_but_exits_0(capsys):
    assert cli.main(["bench", "--split", "dev", "--tiers", "rules,bogus"]) == 0
    assert "unknown tier" in capsys.readouterr().err


def test_dev_split_meets_tuning_targets():
    """The freezing criterion: every dev malicious variant detected, FP <= 1/15."""
    result = run_bench(split="dev")
    for row in result.rows:
        assert row.detected["rules"] == row.n, row.family
    assert result.output_injection[0] == result.output_injection[1]
    assert result.benign_n == 15 and result.benign_fp["rules"] <= 1


def test_frozen_rules_numbers():
    """Recorded from the single test-split run after freezing the rules on the
    dev split (Task 9). A change here means a rule or config changed: rerun the
    dev split first and record it; never tune on the test split."""
    result = run_bench()
    assert {r.family: r.detected["rules"] for r in result.rows} == {
        "description_poisoning": 8,
        "rug_pull": 7,
        "shadowing": 5,
        "unicode_schema": 5,
    }
    assert result.output_injection == (5, 6)
    assert result.benign_fp == {"rules": 0} and result.benign_n == 50


class _FailingJudge:
    model = "fake/model"
    last_error: str | None = None

    def judge(self, tool, *, prior):
        self.last_error = "HTTP 429"


class _FailingClassifier:
    load_error = "OSError"

    def score(self, tool):
        raise RuntimeError("model failed to load")


def test_unavailable_header_names_the_cause():
    result = run_bench(
        split="dev",
        tiers=("rules", "classifier", "judge"),
        judge=_FailingJudge(),
        classifier=_FailingClassifier(),
    )
    out = render(result, "text")
    assert "unavailable: classifier (OSError), judge (HTTP 429)" in out
    assert json.loads(render(result, "json"))["unavailable_reasons"] == {
        "classifier": "OSError",
        "judge": "HTTP 429",
    }
