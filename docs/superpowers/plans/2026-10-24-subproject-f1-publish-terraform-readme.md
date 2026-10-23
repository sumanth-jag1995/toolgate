# Sub-project F1: Publication, Terraform, Bedrock path and README Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Everything in sub-project F that needs no AWS account: artifact secrets scanning, CI and release workflows, Terraform code (validated, never applied), the apply/destroy/leftover scripts, the Bedrock provider path, and the top-level and package READMEs with Mermaid diagrams.

**Architecture:** Python scripts under `scripts/` do the checkable logic (wheel/sdist manifest check, PyPI name check) and are unit-tested; GitHub Actions workflows are thin and asserted structurally by tests; Terraform lives in modules under `infra/terraform/` and is checked by `terraform fmt/validate` plus static Python tests; AWS wrapper scripts have a `--dry-run` mode and are tested with fake `aws`/`terraform` binaries; READMEs are checked by a docs test.

**Tech Stack:** uv, pytest, PyYAML (dev), hatchling build, gitleaks 8.30.1, GitHub Actions (PyPI trusted publishing), Terraform >= 1.9 with AWS provider ~> 5.0, bash, Mermaid.

**Spec:** `docs/superpowers/specs/2026-10-23-subproject-f-aws-publish-readme-design.md` (parent: `2026-10-18-toolgate-design.md` sections 8-9). F2 (real AWS, AgentCore, Bedrock run) is a later plan.

## Global Constraints

- Everything runs in the uv `.venv` (`uv run ...`); new dev deps are added with `uv add --dev` and `uv.lock` committed.
- `toolgate-pin` version `0.1.0`; PyPI name checked first, fallback `mcp-toolpin`; package contents only `src/toolgate_pin/**` (py, py.typed, corpus json/md), `README.md`, `LICENSE`; tests excluded from the wheel.
- Release uploads only if (a) `gitleaks detect --no-git` over the unpacked sdist and wheel is clean and (b) the file list equals the expected manifest. Trusted publishing (OIDC): no stored PyPI token anywhere.
- CI runs `gitleaks detect` over full git history on every push and PR.
- Forbidden files stay rejected: `.env`, `*.pem`, `*.key`, `*.tfstate*`, `*.tfvars` (`*.tfvars.example` allowed). `.gitignore` gains `*.tfstate*`, `.terraform/`, `*.tfvars` with `!*.tfvars.example`.
- Region `us-east-1`; every AWS resource tagged `project=toolgate` (provider `default_tags`); Budget alarm `$25`, Terraform-managed; local Terraform state.
- No secret values in the repo, logs or test output; no `terraform apply`, no AWS calls, no PyPI upload happen in this plan.
- No README claim comes from a fixture: result tables are real runs or marked "pending" with the exact command.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` (or the implementer's own model). pre-commit (gitleaks, ruff, forbidden files) must pass; never `--no-verify`.

## Review Focus

- Wheel contains an unexpected file (a stray `.env`, `*.pem`, a test) -> release check fails and names the file.
- Wheel is missing an expected file (e.g. corpus json dropped by an include change) -> check fails and names it.
- A secret-looking string inside an unpacked sdist/wheel text file -> scan step fails (test with a synthetic AWS-key-shaped canary built into a temp dist).
- Workflow edit that gives `id-token: write` to a job that runs untrusted steps, or adds a `PYPI_TOKEN` secret -> structural test fails.
- `aws-down` / `aws-leftovers` behaviour when nothing exists (empty state, no tagged resources) exits 0 with a clear message; when AWS credentials are absent it fails with a readable message, not a traceback.

---

### Task 1: Artifact check (manifest + secrets) for toolgate-pin

**Files:**
- Create: `scripts/check_artifacts.py`, `packages/toolgate-pin/expected-manifest.txt`, `tests/test_check_artifacts.py`
- Modify: `packages/toolgate-pin/pyproject.toml` (explicit sdist include list), `.gitignore`

**Interfaces:**
- Produces: `unpack_dist(dist_dir: Path, dest: Path) -> dict[str, list[str]]` (kind `"wheel"|"sdist"` to relative file paths, extracting into `dest/<kind>/`); `read_manifest(path: Path) -> dict[str, set[str]]` (manifest lines `wheel: <path>` / `sdist: <path>`, `#` comments); `compare_manifest(found: dict[str, list[str]], expected: dict[str, set[str]]) -> list[str]` (sorted messages `unexpected wheel file: ...` / `missing sdist file: ...`); `scan_secrets(root: Path, gitleaks: str = "gitleaks") -> list[str]` (runs `gitleaks detect --no-git --source <root> --redact --no-banner`, returns finding lines; raises `ArtifactCheckError` if gitleaks is missing); CLI `uv run python scripts/check_artifacts.py DIST_DIR --manifest PATH [--skip-gitleaks]` exit 0 clean, 1 findings, 2 usage/tooling error.

- [ ] **Step 1: Failing tests** in `tests/test_check_artifacts.py`: `test_compare_reports_unexpected_and_missing` (found has `tests/test_x.py` extra and lacks `toolgate_pin/py.typed`; assert both messages, sorted); `test_unpack_dist_reads_wheel_and_sdist` (build tiny zip + tar.gz in tmp_path); `test_unpack_rejects_path_traversal`; `test_read_manifest_ignores_comments`; `test_cli_fails_on_stray_env_file` (dist with `.env` inside wheel -> exit 1, message names `.env`); `test_scan_secrets_flags_canary` (skipped if `gitleaks` not on PATH; file contains an AWS access-key-shaped canary `AKIA` + 16 uppercase alphanumerics assembled at runtime, never written literally in the test source); `test_scan_secrets_missing_binary_is_tooling_error`.
- [ ] **Step 2: Run, expect FAIL** (`uv run pytest tests/test_check_artifacts.py -q`).
- [ ] **Step 3: Implement the interface above** in `scripts/check_artifacts.py` (stdlib only: zipfile, tarfile with a path-traversal guard, subprocess). Reject archive members with absolute paths or `..`.
- [ ] **Step 4: Generate the manifest from a real build:** `uv build --package toolgate-pin`; write `packages/toolgate-pin/expected-manifest.txt` listing every wheel and sdist file (reviewed by hand: no tests, no fixtures); configure `[tool.hatch.build.targets.sdist]` `include` so the sdist holds only `src/toolgate_pin/**`, `README.md`, `LICENSE`, `pyproject.toml`; `.gitignore` additions from Global Constraints.
- [ ] **Step 5:** `uv run python scripts/check_artifacts.py dist --manifest packages/toolgate-pin/expected-manifest.txt` exits 0 (gitleaks must be installed; if not, install it with the platform package manager and record the version). Run the full tests; commit `feat(release): artifact manifest and secrets check`.

### Task 2: CI and release workflows

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `tests/test_workflows.py`
- Modify: `pyproject.toml` (dev dep `pyyaml`)

**Interfaces:**
- Consumes: `scripts/check_artifacts.py` CLI (Task 1).
- Produces: workflows. `ci.yml` (on push, pull_request): job `lint-test` (checkout, setup uv, `uv sync --all-packages --all-extras`, `uv run ruff check`, `uv run ruff format --check`, `uv run pytest -q -m "not integration"`) and job `secrets` (checkout `fetch-depth: 0`, gitleaks v8.30.1 `detect` over full history). `release.yml` (on tag `v*` and `workflow_dispatch` with boolean input `dry_run` default true): job `build` (build, `check_artifacts.py`, gitleaks `--no-git` on the unpacked dirs, upload dist as an artifact, `permissions: contents: read`) and job `publish` (`needs: build`, runs only on tag push, never on a dispatch dry run; `environment: pypi`; `permissions: id-token: write`; `pypa/gh-action-pypi-publish` with no token input; downloads the build artifact and runs no other third-party steps).

- [ ] **Step 1: Failing tests** in `tests/test_workflows.py` (PyYAML): `test_ci_has_full_history_gitleaks` (secrets job checkout has `fetch-depth: 0`); `test_release_publish_needs_build_and_scans`; `test_only_publish_job_has_id_token_write`; `test_no_pypi_token_secret_anywhere` (no workflow text contains `PYPI_TOKEN`, `secrets.PYPI`, or a `password:` input to the publish action); `test_release_dry_run_never_publishes`; `test_actions_are_pinned` (every `uses:` is pinned to a version tag or sha, never a branch).
- [ ] **Step 2: Run, expect FAIL. Step 3: Write the workflows** (`uv add --dev pyyaml`). **Step 4: tests PASS**, and both files parse with `yaml.safe_load`. **Step 5: Commit** `ci: tests, history secret scan and trusted-publishing release`.

### Task 3: PyPI name check and build hygiene

**Files:**
- Create: `scripts/check_pypi_name.py`, `tests/test_check_pypi_name.py`
- Modify: `packages/toolgate-pin/README.md` (install line uses the confirmed name)

**Interfaces:**
- Produces: `pypi_status(name: str, opener=urllib.request.urlopen) -> Literal["free","taken","error"]` (`GET https://pypi.org/pypi/<name>/json`; 404 means free, 200 means taken); CLI `uv run python scripts/check_pypi_name.py toolgate-pin mcp-toolpin` prints one line per name and exits 0 if at least one is free.

- [ ] **Step 1: Failing tests** with a fake opener: 404 -> `"free"`, 200 -> `"taken"`, URLError -> `"error"` (never claims free on error), CLI exit codes. **Step 2: FAIL. Step 3: implement. Step 4: PASS.**
- [ ] **Step 5:** Run the real check once (network). If `toolgate-pin` is free nothing changes; if taken, rule: switch every reference (`pyproject name`, README, manifest, workflows) to `mcp-toolpin` in this task and note it in the ledger. Also run `uv run --with twine twine check dist/*` after `uv build --package toolgate-pin`; it must pass. Commit `feat(release): PyPI name check`.

### Task 4: Terraform modules (network, data, cognito, budget) and root

**Files:**
- Create: `infra/terraform/{main.tf,variables.tf,outputs.tf,versions.tf,terraform.tfvars.example}`, `infra/terraform/modules/{network,data,cognito,budget}/{main.tf,variables.tf,outputs.tf}`, `tests/test_terraform_static.py`

**Interfaces:**
- Produces module outputs used by Task 5: `network` -> `vpc_id`, `public_subnet_ids`, `private_subnet_ids`, `alb_sg_id`, `service_sg_id`, `db_sg_id`; `data` -> `db_endpoint`, `db_secret_arn` (RDS Postgres 16 `db.t4g.micro`, encrypted, not publicly accessible, master password generated into Secrets Manager and never output as plaintext); `cognito` -> `user_pool_id`, `issuer_url`, `app_client_ids` (map `servicing|claims-intake|fraud-triage` to id; client-credentials flow; resource-server scopes mirroring the Keycloak scopes in `infra/keycloak`), `client_secret_arns`; `budget` -> `budget_name`. Root variables: `region` default `us-east-1`, `alert_email`, `budget_usd` default `25`.
- `versions.tf` pins `required_version >= 1.9` and the aws provider `~> 5.0`; the provider block sets `default_tags { tags = { project = "toolgate" } }`.

- [ ] **Step 1: Failing static tests** in `tests/test_terraform_static.py`: `test_provider_default_tags_project_toolgate`; `test_budget_default_is_25_and_has_email_notification`; `test_no_literal_secrets_or_account_ids` (regex for `AKIA...`, 12-digit account ids, `password\s*=\s*"` literals); `test_tfvars_example_present_and_real_tfvars_ignored` (`git check-ignore infra/terraform/terraform.tfvars`); `test_rds_is_not_publicly_accessible_and_encrypted`; `test_cognito_has_three_app_clients`; `test_terraform_fmt_and_validate` (skipped with a reason if `terraform` is not installed; otherwise `terraform -chdir=infra/terraform init -backend=false -input=false`, then `fmt -check -recursive` and `validate`).
- [ ] **Step 2: FAIL. Step 3: Write the modules** to those interfaces (VPC with 2 AZs, public subnets for the ALB, private subnets for tasks and RDS; a single NAT gateway is my default for ECR/Secrets access, with its cost noted in a comment). Install Terraform (platform package manager; record the version) so the validate test runs. **Step 4: PASS. Step 5: Commit** `feat(infra): terraform network, data, cognito and budget modules`.

### Task 5: Terraform ECS services, ALB and observability

**Files:**
- Create: `infra/terraform/modules/{ecs,observability}/{main.tf,variables.tf,outputs.tf}`
- Modify: `infra/terraform/main.tf`, `infra/terraform/variables.tf`, `infra/terraform/outputs.tf`, `tests/test_terraform_static.py`

**Interfaces:**
- Consumes: Task 4 module outputs.
- Produces: ECS cluster; one Fargate service per image name in variable `images` (map name to ECR image URI): `mock-api`, `core-read`, `core-write`, `comms`, `gateway`, plus `evil-server` and `sink` behind `enable_eval_targets` (default true); ECR repositories (one per image, `force_delete = true`); ALB with an HTTPS listener on 443 using an ACM certificate when `domain_name` is set, else HTTP 80 with output `alb_dns_name` (my default, documented as demo-grade); a target group routing `/mcp` to the gateway only; Cloud Map service discovery so the gateway reaches the MCP servers by name; task roles that read only their own secrets; `observability` -> ADOT collector sidecar config and CloudWatch log groups with 7-day retention.

- [ ] **Step 1: Extend static tests:** `test_every_ecs_service_has_log_group_and_task_role`; `test_alb_http_only_when_no_domain` (listener resource conditional on `domain_name`); `test_only_gateway_target_group_is_internet_facing` (MCP server services have no ALB listener rule); `test_log_retention_is_7_days`; `test_validate_still_passes`.
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: `terraform fmt -check -recursive` and `validate` PASS, tests PASS. Step 5: Commit** `feat(infra): terraform ecs, alb and observability`.

### Task 6: aws-up / aws-down / leftovers / image push scripts

**Files:**
- Create: `Makefile`, `scripts/aws_up.sh`, `scripts/aws_down.sh`, `scripts/aws_leftovers.sh`, `scripts/push_images.sh`, `tests/test_aws_scripts.py`

**Interfaces:**
- Produces: `make aws-up` runs `scripts/aws_up.sh` (checks `aws sts get-caller-identity`, builds and pushes images via `push_images.sh`, `terraform apply`); `make aws-down` runs `terraform destroy` then `aws_leftovers.sh`; `aws_leftovers.sh` lists resources tagged `project=toolgate` through the Resource Groups Tagging API and exits 1 listing ARNs if any remain, else exits 0 printing `no resources tagged project=toolgate`. Every script accepts `--dry-run` (prints the exact commands, runs none) and uses `set -euo pipefail`; none prints environment variables.

- [ ] **Step 1: Failing tests** (`tests/test_aws_scripts.py`, run with bash, skipped if bash is unavailable): `test_scripts_pass_bash_n`; `test_aws_up_dry_run_prints_apply_and_runs_nothing` (PATH has fake `aws`/`terraform` that fail the test if executed); `test_aws_down_dry_run_orders_destroy_before_leftovers`; `test_leftovers_with_fake_aws_empty_exits_0` and `test_leftovers_with_resources_exits_1_and_lists_arns`; `test_missing_credentials_message_is_readable` (fake `aws sts` fails -> stderr contains `AWS credentials` and no traceback); `test_scripts_never_echo_env`.
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: PASS. Step 5: Commit** `feat(infra): aws-up, aws-down and leftovers scripts`.

### Task 7: Bedrock provider path

**Files:**
- Modify: `packages/servicing-agent/pyproject.toml` (extra `bedrock` = `langchain-aws`), `eval/README.md`, `packages/servicing-agent/tests/test_models.py`, `eval/tests/` models-config tests
- Create: `eval/models.bedrock.yaml`

**Interfaces:**
- Consumes: `servicing_agent.models.make_chat_model` bedrock branch (existing); the `toolgate_eval` models.yaml loader.
- Produces: `eval/models.bedrock.yaml` with two entries named `strong` and `small`: `provider: bedrock`, `region: us-east-1`, model id set to the literal `TO_BE_CONFIRMED_IN_F2` (F2 fills it from `aws bedrock list-foundation-models` for the account), temperature and max_tokens as in `eval/models.yaml`; the loader refuses to run a config whose model id is the placeholder, with an `error:` message naming the file, so the placeholder can never be run by accident.

- [ ] **Step 1: Failing tests:** `test_bedrock_branch_builds_with_fake_module` (monkeypatch `langchain_aws.ChatBedrockConverse`; assert region/model/temperature/max_tokens are passed and no credentials are read from the config); `test_bedrock_missing_extra_is_config_error`; `test_bedrock_yaml_loads_but_placeholder_cannot_run` (CLI `run` exits with `error:`); `test_config_hash_differs_between_providers`.
- [ ] **Step 2: FAIL. Step 3: Implement. Step 4: PASS** (`uv run pytest eval packages/servicing-agent -q -W error`). **Step 5:** README note on how to run the confirmation later; commit `feat(eval): bedrock model config path`.

### Task 8: READMEs with Mermaid diagrams

**Files:**
- Modify: `README.md` (rewrite top level), `packages/toolgate-pin/README.md` (add a lifecycle diagram section)
- Create: `tests/test_readmes.py`

**Interfaces:**
- Consumes: results in `eval/README.md` (load-test table, report format), `policy/agents.yaml`, compose ports.
- Produces (top-level README sections, in order): problem in three sentences; **Architecture** Mermaid `flowchart` with nodes `Agent`, `Keycloak`, `Gateway` (subgraph with its pipeline stages: auth, allowlist, pin check, schema validation, forward, output scan, audit), `core-read`, `core-write`, `comms`, `Mock enterprise API`, `Postgres audit`, `OTel/Tempo`, and for the eval setup `Attacker server` and `Sink`; **Request flow** Mermaid `sequenceDiagram` for `tools/list` (pin verification, drift -> drop and review path) and `tools/call` through each stage; Results (load-test numbers copied from `eval/README.md` with the honest c=50 statement; the canary matrix marked **pending** with the exact `toolgate-eval run ... && toolgate-eval report` commands because no live run exists yet); Run locally (A, B and D steps in one place); AgentCore comparison marked **pending F2**; Limits. The pin README gains a smaller `stateDiagram-v2` or flowchart for pin, verify, drift, quarantine, approve.

- [ ] **Step 1: Failing tests** in `tests/test_readmes.py`: `test_top_level_has_two_mermaid_diagrams_with_required_nodes`; `test_mermaid_blocks_are_balanced` (each mermaid fence closes and starts with a recognised keyword); `test_no_fixture_tables_in_top_level` (the string `FIXTURE` is absent; pending sections contain the word `pending`); `test_relative_links_resolve`; `test_commands_in_readme_exist` (every `toolgate-eval <sub>` mentioned is a real subcommand); `test_pin_readme_has_lifecycle_diagram`.
- [ ] **Step 2: FAIL. Step 3: Write the READMEs** (read the repo first; copy numbers, do not invent them). Render-check each Mermaid block with the Mermaid CLI only if Node is available; otherwise review syntax carefully and note it in the report. **Step 4: PASS. Step 5: Commit** `docs: top-level README with architecture and request-flow diagrams`.

### Task 9: Whole-branch secrets self-test

**Files:** none unless the check finds a leak.

- [ ] **Step 1:** Run `gitleaks detect` over the full repo history, and `uv build --package toolgate-pin` followed by `check_artifacts.py` with the real manifest; both must be clean. **Step 2:** `uv run pytest -q` (stack-down integration tests skip cleanly). **Step 3:** Report results; fix anything found. No commit unless a fix is needed.
