"""Static checks on the GitHub Actions workflows (no network, no runs)."""

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def _load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def _steps_text(job: dict) -> str:
    return yaml.safe_dump(job.get("steps", []))


def test_ci_has_full_history_gitleaks() -> None:
    job = _load("ci.yml")["jobs"]["secrets"]
    checkouts = [
        s
        for s in job["steps"]
        if str(s.get("uses", "")).startswith("actions/checkout@")
    ]
    assert checkouts and checkouts[0]["with"]["fetch-depth"] == 0
    text = _steps_text(job)
    assert "gitleaks" in text and "detect" in text
    assert "--no-git" not in text


def test_release_publish_needs_build_and_scans() -> None:
    jobs = _load("release.yml")["jobs"]
    assert jobs["publish"]["needs"] == "build" or jobs["publish"]["needs"] == ["build"]
    build = _steps_text(jobs["build"])
    assert "check_artifacts.py" in build
    assert "--manifest" in build
    assert "--skip-gitleaks" not in build
    assert "gitleaks" in build


def test_only_publish_job_has_id_token_write() -> None:
    wf = _load("release.yml")
    assert "id-token" not in (wf.get("permissions") or {})
    for name, job in wf["jobs"].items():
        perms = job.get("permissions") or {}
        if name == "publish":
            assert perms.get("id-token") == "write"
        else:
            assert "id-token" not in perms
    assert _load("ci.yml").get("permissions", {}).get("id-token") is None
    assert wf["jobs"]["build"]["permissions"] == {"contents": "read"}
    assert wf["jobs"]["publish"]["environment"] == "pypi"


def test_no_pypi_token_secret_anywhere() -> None:
    for path in WORKFLOWS.glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        assert "PYPI_TOKEN" not in text
        assert "secrets.PYPI" not in text
    publish = _load("release.yml")["jobs"]["publish"]
    for step in publish["steps"]:
        if "gh-action-pypi-publish" in str(step.get("uses", "")):
            assert "password" not in (step.get("with") or {})


def test_release_dry_run_never_publishes() -> None:
    wf = _load("release.yml")
    # PyYAML parses the bare key `on` as boolean True.
    triggers = wf.get("on", wf.get(True))
    dispatch = triggers["workflow_dispatch"]["inputs"]["dry_run"]
    assert dispatch["type"] == "boolean" and dispatch["default"] is True
    condition = wf["jobs"]["publish"]["if"]
    assert "refs/tags/v" in condition
    assert "push" in condition


def test_publish_job_has_no_other_third_party_steps() -> None:
    steps = _load("release.yml")["jobs"]["publish"]["steps"]
    uses = [s["uses"].split("@")[0] for s in steps if "uses" in s]
    assert set(uses) == {"actions/download-artifact", "pypa/gh-action-pypi-publish"}
    assert not any("run" in s for s in steps)


def _all_uses() -> list[str]:
    found = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        for job in yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"].values():
            found += [s["uses"] for s in job["steps"] if "uses" in s]
    return found


@pytest.mark.parametrize("ref", _all_uses())
def test_actions_are_pinned(ref: str) -> None:
    _, _, version = ref.partition("@")
    assert re.fullmatch(r"v\d+(\.\d+){0,2}|[0-9a-f]{40}", version), ref
