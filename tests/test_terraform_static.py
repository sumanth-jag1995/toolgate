"""Static checks over infra/terraform (no AWS calls, no apply/plan).

Terraform is located with shutil.which("terraform"); if a shell started before
the install and has a stale PATH, set TERRAFORM_BIN to the binary's full path.
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TF = ROOT / "infra" / "terraform"
AGENTS = ("servicing", "claims-intake", "fraud-triage")


def _read(rel: str) -> str:
    return (TF / rel).read_text(encoding="utf-8")


def _all_tf() -> dict[Path, str]:
    return {p: p.read_text(encoding="utf-8") for p in sorted(TF.rglob("*.tf"))}


def _terraform_bin() -> str | None:
    return shutil.which("terraform") or os.environ.get("TERRAFORM_BIN") or None


def test_provider_default_tags_project_toolgate():
    main = _read("main.tf")
    assert re.search(
        r"default_tags\s*\{\s*tags\s*=\s*\{[^}]*project\s*=\s*\"toolgate\"", main
    )
    versions = _read("versions.tf")
    assert 'required_version = ">= 1.9"' in versions
    assert 'version = "~> 5.0"' in versions


def test_budget_default_is_25_and_has_email_notification():
    variables = _read("variables.tf")
    assert re.search(
        r'variable "budget_usd"[^}]*default\s*=\s*25', variables, re.DOTALL
    )
    assert re.search(
        r'variable "region"[^}]*default\s*=\s*"us-east-1"', variables, re.DOTALL
    )
    budget = _read("modules/budget/main.tf")
    assert "aws_budgets_budget" in budget
    assert "subscriber_email_addresses" in budget


def test_no_literal_secrets_or_account_ids():
    bad = [
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"(?<![0-9A-Za-z-])\d{12}(?![0-9A-Za-z-])"),
        re.compile(r"password\s*=\s*\""),
    ]
    files = _all_tf()
    assert files
    for path, text in files.items():
        for rx in bad:
            assert not rx.search(text), f"{path.name}: {rx.pattern}"


def test_tfvars_example_present_and_real_tfvars_ignored():
    assert (TF / "terraform.tfvars.example").is_file()
    git = shutil.which("git")
    assert git
    ignored = subprocess.run(
        [git, "check-ignore", "-q", "infra/terraform/terraform.tfvars"],
        cwd=ROOT,
        check=False,
    )
    assert ignored.returncode == 0
    example = subprocess.run(
        [git, "check-ignore", "-q", "infra/terraform/terraform.tfvars.example"],
        cwd=ROOT,
        check=False,
    )
    assert example.returncode == 1


def test_rds_is_not_publicly_accessible_and_encrypted():
    data = _read("modules/data/main.tf")
    assert re.search(r'engine\s*=\s*"postgres"', data)
    assert re.search(r'engine_version\s*=\s*"16', data)
    assert "db.t4g.micro" in data
    assert re.search(r"publicly_accessible\s*=\s*false", data)
    assert re.search(r"storage_encrypted\s*=\s*true", data)
    assert "random_password" in data
    assert "aws_secretsmanager_secret" in data
    outputs = _read("modules/data/outputs.tf")
    assert "db_endpoint" in outputs and "db_secret_arn" in outputs
    assert "random_password" not in outputs


def test_cognito_has_three_app_clients():
    cognito = _read("modules/cognito/main.tf")
    assert "aws_cognito_user_pool_client" in cognito
    assert re.search(r"allowed_oauth_flows\s*=\s*\[\"client_credentials\"\]", cognito)
    assert "aws_cognito_resource_server" in cognito
    variables = _read("modules/cognito/variables.tf")
    for agent in AGENTS:
        assert f'"{agent}"' in variables
    for out in ("user_pool_id", "issuer_url", "app_client_ids", "client_secret_arns"):
        assert out in _read("modules/cognito/outputs.tf")


def test_terraform_fmt_and_validate():
    tf = _terraform_bin()
    if not tf:
        pytest.skip("terraform not installed (set TERRAFORM_BIN or add it to PATH)")
    base = [tf, f"-chdir={TF}"]

    def run(*args: str) -> None:
        res = subprocess.run(
            [*base, *args], capture_output=True, text=True, check=False
        )
        assert res.returncode == 0, (
            f"terraform {' '.join(args)}\n{res.stdout}{res.stderr}"
        )

    run("init", "-backend=false", "-input=false", "-no-color")
    run("fmt", "-check", "-recursive", "-no-color")
    run("validate", "-no-color")
