from __future__ import annotations

import json

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
