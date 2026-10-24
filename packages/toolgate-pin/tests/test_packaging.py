"""Build the wheel and run the demo from it with uvx (slow; needs uv)."""

from __future__ import annotations

import os
import shutil
import subprocess
import zipfile

import pytest

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(shutil.which("uv") is None, reason="uv not on PATH"),
]


def test_wheel_contains_corpus_and_runs_demo(tmp_path):
    subprocess.run(
        ["uv", "build", "--package", "toolgate-pin", "--out-dir", str(tmp_path)],
        check=True,
        capture_output=True,
    )
    wheels = list(tmp_path.glob("toolgate_pin-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as z:
        names = z.namelist()
        metadata = z.read(
            next(n for n in names if n.endswith(".dist-info/METADATA"))
        ).decode("utf-8")
    base = "toolgate_pin/corpus/"
    malicious = [
        n
        for n in names
        if n.endswith(".json")
        and (n.startswith((base + "malicious/", base + "dev/malicious/")))
    ]
    benign = [
        n
        for n in names
        if n.endswith(".json")
        and (n.startswith((base + "benign/", base + "dev/benign/")))
    ]
    assert len(malicious) >= 38
    assert len(benign) == 65
    assert base + "benign/SOURCES.md" in names
    assert "toolgate_pin/py.typed" in names
    # The README is the package's long description.
    assert "five-minute" in metadata.lower()

    def run_demo(*extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["uvx", *extra, "--from", str(wheels[0]), "toolgate-pin", "demo"],
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            timeout=300,
        )

    # Prefer the offline uv cache (fast, no network); a fresh machine such as a
    # CI runner has not cached the wheel's dependencies, so fall back to online.
    proc = run_demo("--offline")
    if "network was disabled" in proc.stderr:
        proc = run_demo()
    assert proc.returncode == 1, proc.stderr
    assert "quarantined get_claim_status (drift)" in proc.stdout
