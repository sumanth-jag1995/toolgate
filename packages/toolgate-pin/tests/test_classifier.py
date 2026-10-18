from __future__ import annotations

import sys

import pytest
from toolgate_pin import cli
from toolgate_pin.bench import render, run_bench
from toolgate_pin.corpus import load_corpus
from toolgate_pin.scanner import classifier

needs_extra = pytest.mark.skipif(
    not classifier.available(), reason="classifier extra not installed"
)
DEMO = (sys.executable, "-m", "toolgate_pin.cli", "demo-server")


def test_bench_without_extra_lists_classifier_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(classifier, "available", lambda: False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    assert cli.main(["bench", "--split", "dev"]) == 0
    assert "unavailable: classifier, judge" in capsys.readouterr().out


def test_texts_cover_description_and_parameter_descriptions():
    tool = {
        "name": "t",
        "description": "top",
        "inputSchema": {
            "type": "object",
            "properties": {
                "a": {"type": "string", "description": "param a"},
                "b": {
                    "type": "object",
                    "properties": {"c": {"description": "nested c"}},
                },
            },
        },
    }
    assert classifier.texts_of(tool) == ["top", "param a", "nested c"]


@needs_extra
def test_scores_injection_higher_than_benign():
    clf = classifier.Classifier()
    corpus = load_corpus("dev")
    mal = [clf.score(v.mutated or v.approved) for v in corpus.malicious]
    ben = [clf.score(b.definition) for b in corpus.benign]
    assert sum(mal) / len(mal) > sum(ben) / len(ben)


@needs_extra
def test_bench_includes_classifier_column():
    out = render(
        run_bench(split="dev", tiers=("rules", "classifier"), classifier=_clf()),
        "text",
    )
    assert "tiers: rules, classifier" in out and "unavailable" not in out


@needs_extra
def test_approve_classifier_flag_runs_tier(tmp_path, capsys):
    import json

    lock = tmp_path / "toolgate.lock.json"
    code = cli.main(
        ["approve", "--lockfile", str(lock), "--yes", "--as", "t", "--classifier"]
        + ["--stdio", "--", *DEMO]
    )
    assert code in (0, 3)
    out = capsys.readouterr()
    assert "classifier tier is unavailable" not in out.out + out.err
    if code == 0:
        tools = json.loads(lock.read_text(encoding="utf-8"))["servers"]
        assert all(
            "classifier" in t["scan"]["tiers"]
            for s in tools.values()
            for t in s["tools"].values()
        )


def _clf():
    return classifier.Classifier()


def test_load_failure_is_memoized(monkeypatch):
    calls: list[int] = []

    def failing_load(self):
        calls.append(1)
        raise OSError("download failed")

    monkeypatch.setattr(classifier.Classifier, "_load", failing_load)
    clf = classifier.Classifier()
    for _ in range(3):
        with pytest.raises(classifier.ClassifierLoadError):
            clf.score({"name": "t", "description": "hello"})
    assert calls == [1]
    assert clf.load_error == "OSError"
