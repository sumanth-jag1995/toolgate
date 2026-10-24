"""Tests for the aws-up / aws-down / leftovers / push scripts.

Every test puts fake aws/terraform/docker binaries first on PATH; they either
fail the test when executed (dry-run) or record their arguments.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ["aws_up.sh", "aws_down.sh", "aws_leftovers.sh", "push_images.sh"]
BASH = shutil.which("bash")
IMAGES_FILE = ROOT / "infra" / "terraform" / "images.auto.tfvars"

pytestmark = pytest.mark.skipif(BASH is None, reason="bash not available")

URLS = (
    '{"mock-api": "1.dkr.ecr.us-east-1.amazonaws.com/toolgate/mock-api",'
    ' "core-read": "1.dkr.ecr.us-east-1.amazonaws.com/toolgate/core-read",'
    ' "core-write": "1.dkr.ecr.us-east-1.amazonaws.com/toolgate/core-write",'
    ' "comms": "1.dkr.ecr.us-east-1.amazonaws.com/toolgate/comms",'
    ' "gateway": "1.dkr.ecr.us-east-1.amazonaws.com/toolgate/gateway"}'
)


def _fake(bin_dir: Path, name: str, body: str) -> None:
    p = bin_dir / name
    p.write_text("#!/usr/bin/env bash\n" + body + "\n", encoding="utf-8", newline="\n")
    p.chmod(0o755)


def _env(bin_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
    env.pop("TERRAFORM_BIN", None)
    env["FAKE_LOG"] = str(bin_dir / "calls.log")
    env.update(extra or {})
    return env


def _run(script: str, args: list[str], env: dict[str, str]):
    return subprocess.run(
        [BASH, str(ROOT / "scripts" / script), *args],
        capture_output=True,
        check=False,
        text=True,
        env=env,
        cwd=ROOT,
    )


def _calls(bin_dir: Path) -> list[str]:
    log = bin_dir / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


@pytest.fixture
def forbidden(tmp_path: Path) -> Path:
    for n in ("aws", "terraform", "docker"):
        _fake(tmp_path, n, f'echo "{n} executed" >> "$FAKE_LOG"; exit 99')
    return tmp_path


@pytest.fixture
def clean_images_file():
    existed = IMAGES_FILE.exists()
    yield
    if not existed and IMAGES_FILE.exists():
        IMAGES_FILE.unlink()


def test_scripts_pass_bash_n():
    for s in SCRIPTS:
        r = subprocess.run(
            [BASH, "-n", str(ROOT / "scripts" / s)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert r.returncode == 0, f"{s}: {r.stderr}"
        assert "set -euo pipefail" in (ROOT / "scripts" / s).read_text()


def test_aws_up_dry_run_prints_apply_and_runs_nothing(forbidden: Path):
    r = _run("aws_up.sh", ["--dry-run"], _env(forbidden))
    assert r.returncode == 0, r.stderr
    assert _calls(forbidden) == []
    assert "infra/terraform apply" in r.stdout


def test_aws_up_dry_run_two_stage_ordering(forbidden: Path):
    out = _run("aws_up.sh", ["--dry-run"], _env(forbidden)).stdout
    stage1 = out.index("apply -target=module.ecs.aws_ecr_repository.this")
    push = out.index("docker push")
    full = out.rindex("infra/terraform apply")
    assert stage1 < push < full
    assert "docker build" in out and "gateway.cloud.Dockerfile" in out


def test_push_images_dry_run_names_and_dockerfiles(forbidden: Path):
    out = _run("push_images.sh", ["--dry-run"], _env(forbidden)).stdout
    assert _calls(forbidden) == []
    assert out.count("services/mcp-servers/Dockerfile") == 3
    assert "services/mock-enterprise/Dockerfile" in out
    assert "packages/toolgate-gateway/Dockerfile" in out
    assert "evil-server" not in out and "sink" not in out


def test_aws_down_dry_run_orders_destroy_before_leftovers(forbidden: Path):
    r = _run("aws_down.sh", ["--dry-run"], _env(forbidden))
    assert r.returncode == 0, r.stderr
    assert _calls(forbidden) == []
    assert r.stdout.index("destroy") < r.stdout.index("resourcegroupstaggingapi")


def test_leftovers_with_fake_aws_empty_exits_0(tmp_path: Path):
    _fake(tmp_path, "aws", "echo None")
    r = _run("aws_leftovers.sh", [], _env(tmp_path))
    assert r.returncode == 0
    assert "no resources tagged project=toolgate" in r.stdout


def test_leftovers_with_resources_exits_1_and_lists_arns(tmp_path: Path):
    _fake(
        tmp_path,
        "aws",
        'printf "arn:aws:s3:::a\\tarn:aws:ecs:us-east-1:1:cluster/b\\n"',
    )
    r = _run("aws_leftovers.sh", [], _env(tmp_path))
    assert r.returncode == 1
    assert "arn:aws:s3:::a" in r.stdout and "cluster/b" in r.stdout


def test_missing_credentials_message_is_readable(tmp_path: Path):
    _fake(tmp_path, "aws", "echo 'Unable to locate credentials' >&2; exit 255")
    _fake(tmp_path, "terraform", 'echo "terraform executed" >> "$FAKE_LOG"')
    for script in ("aws_up.sh", "aws_down.sh"):
        r = _run(script, [], _env(tmp_path))
        assert r.returncode != 0
        assert "AWS credentials" in r.stderr
        assert "Traceback" not in r.stderr
    assert _calls(tmp_path) == []


def _stateful_fakes(d: Path, repos_exist: bool) -> None:
    _fake(d, "aws", 'echo "aws $*" >> "$FAKE_LOG"; echo pw')
    _fake(d, "docker", 'echo "docker $*" >> "$FAKE_LOG"')
    exist = "1" if repos_exist else "0"
    body = (
        'echo "terraform $*" >> "$FAKE_LOG"\n'
        'if [[ "$*" == *" output "* ]]; then\n'
        f"  if [[ -f \"{d}/applied\" || {exist} == 1 ]]; then echo '{URLS}'; else echo '{{}}'; fi\n"
        'elif [[ "$*" == *"-target"* ]]; then touch "' + str(d) + '/applied"; fi'
    )
    _fake(d, "terraform", body)


def test_aws_up_real_flow_two_stage_with_fakes(tmp_path: Path, clean_images_file):
    _stateful_fakes(tmp_path, repos_exist=False)
    r = _run("aws_up.sh", [], _env(tmp_path, {"IMAGE_TAG": "t1"}))
    assert r.returncode == 0, r.stderr
    calls = _calls(tmp_path)

    def idx(s: str) -> int:
        return next(i for i, c in enumerate(calls) if s in c)

    target = idx("-target=module.ecs.aws_ecr_repository.this")
    push = idx("docker push")
    full = max(i for i, c in enumerate(calls) if c.endswith(" apply"))
    assert target < push < full
    pushes = [c for c in calls if c.startswith("docker push")]
    assert len(pushes) == 5 and all(c.endswith(":t1") for c in pushes)
    logins = [c for c in calls if c.startswith("docker login")]
    assert logins and all(
        "--password-stdin" in c and "pw" not in c.split() for c in logins
    )
    assert '"gateway" = ' in IMAGES_FILE.read_text()
    assert "gateway-migrate" in r.stderr and "infra/terraform/README.md" in r.stderr
    builds = [c for c in calls if c.startswith("docker build")]
    assert builds
    for c in builds:
        parts = c.split()
        assert parts[parts.index("-f") + 1].startswith("/"), c


def test_aws_up_skips_stage_one_when_repos_exist(tmp_path: Path, clean_images_file):
    _stateful_fakes(tmp_path, repos_exist=True)
    r = _run("aws_up.sh", [], _env(tmp_path, {"IMAGE_TAG": "t1"}))
    assert r.returncode == 0, r.stderr
    assert not any("-target" in c for c in _calls(tmp_path))


def test_terraform_bin_is_honoured(tmp_path: Path):
    _fake(tmp_path, "my-tf", 'echo "my-tf $*" >> "$FAKE_LOG"')
    _fake(tmp_path, "aws", "exit 0")
    _fake(tmp_path, "terraform", "exit 99")
    r = _run("aws_down.sh", ["--dry-run"], _env(tmp_path, {"TERRAFORM_BIN": "my-tf"}))
    assert r.returncode == 0
    assert "my-tf -chdir" in r.stdout
    assert _calls(tmp_path) == []  # default terraform (exit 99) never ran


def test_scripts_never_echo_env():
    for s in SCRIPTS:
        text = (ROOT / "scripts" / s).read_text()
        for bad in ("printenv", "env |", "set -x", "declare -p", "export -p"):
            assert bad not in text, f"{s} contains {bad}"


def test_gateway_cloud_dockerfile_references_policy_files():
    text = (ROOT / "infra/docker/gateway.cloud.Dockerfile").read_text()
    assert "ARG BASE_IMAGE" in text and "FROM ${BASE_IMAGE}" in text
    assert "COPY --chown=root:root policy/ /policy/" in text
    assert "gateway.yaml" not in text.replace("gateway.cloud.yaml", "")
    for f in ("gateway.cloud.yaml", "agents.yaml", "toolgate.lock.json"):
        assert (ROOT / "policy" / f).is_file()
    tf = (ROOT / "infra/terraform/modules/ecs/main.tf").read_text()
    for p in (
        "/policy/toolgate.lock.json",
        "/policy/agents.yaml",
        "/policy/gateway.cloud.yaml",
    ):
        assert p in tf


def test_makefile_targets():
    mk = (ROOT / "Makefile").read_text()
    assert "scripts/aws_up.sh" in mk and "scripts/aws_down.sh" in mk


def test_scripts_are_executable_in_git_index():
    r = subprocess.run(
        ["git", "ls-files", "-s", "scripts/*.sh"],
        capture_output=True,
        text=True,
        check=False,
        cwd=ROOT,
    )
    if r.returncode != 0 or not r.stdout.strip():
        pytest.skip("not a git checkout")
    for line in r.stdout.splitlines():
        assert line.startswith("100755"), line


def test_aws_down_runs_leftovers_even_when_destroy_fails(tmp_path: Path):
    _fake(tmp_path, "terraform", 'echo "terraform $*" >> "$FAKE_LOG"; exit 1')
    _fake(
        tmp_path,
        "aws",
        'if [[ "$*" == *sts* ]]; then exit 0; fi; echo "arn:aws:s3:::left"',
    )
    r = _run("aws_down.sh", [], _env(tmp_path, {"LEFTOVERS_RETRY_SLEEP": "0"}))
    assert r.returncode != 0
    assert "arn:aws:s3:::left" in r.stdout
    assert "destroy rc=1" in r.stderr


def test_leftovers_task_definitions_are_informational(tmp_path: Path):
    _fake(tmp_path, "aws", 'echo "arn:aws:ecs:us-east-1:1:task-definition/x:1"')
    r = _run("aws_leftovers.sh", [], _env(tmp_path, {"LEFTOVERS_RETRY_SLEEP": "0"}))
    assert r.returncode == 0
    assert "inactive ECS task definitions (no cost, informational)" in r.stdout
    assert "task-definition/x:1" in r.stdout


def test_leftovers_retries_then_clears(tmp_path: Path):
    _fake(
        tmp_path,
        "aws",
        'echo x >> "$FAKE_LOG"; if [[ $(wc -l < "$FAKE_LOG") -ge 3 ]]; then echo None; '
        "else echo arn:aws:s3:::a; fi",
    )
    r = _run("aws_leftovers.sh", [], _env(tmp_path, {"LEFTOVERS_RETRY_SLEEP": "0"}))
    assert r.returncode == 0
    assert len(_calls(tmp_path)) == 3


def test_leftovers_retries_three_times_before_failing(tmp_path: Path):
    _fake(tmp_path, "aws", 'echo x >> "$FAKE_LOG"; echo arn:aws:s3:::a')
    r = _run("aws_leftovers.sh", [], _env(tmp_path, {"LEFTOVERS_RETRY_SLEEP": "0"}))
    assert r.returncode == 1
    assert len(_calls(tmp_path)) == 3


def test_image_names_come_from_terraform_output_keys(tmp_path: Path, clean_images_file):
    _stateful_fakes(tmp_path, repos_exist=True)
    r = _run("push_images.sh", [], _env(tmp_path, {"IMAGE_TAG": "t1"}))
    assert r.returncode == 0, r.stderr
    assert "ENABLE_EVAL_TARGETS" not in (ROOT / "scripts/push_images.sh").read_text()
    assert "declare -A" not in (ROOT / "scripts/push_images.sh").read_text()


def test_dockerignore_excludes_secrets():
    text = (ROOT / ".dockerignore").read_text()
    for pat in ("**/.env", "**/.env.*", ".venv", "*.tfstate*", ".git", ".superpowers"):
        assert pat in text.splitlines()


def test_gitignore_ignores_env_variants_but_keeps_example():
    lines = (ROOT / ".gitignore").read_text().splitlines()
    assert ".env.*" in lines and "!.env.example" in lines
