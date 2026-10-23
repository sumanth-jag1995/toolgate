# Sub-project F: AWS deployment, managed comparison, publication, README

Parent: `2026-10-18-toolgate-design.md` §8–10. A, C, B and D are merged. This document fixes the decisions F's plan needs; where it is silent, the parent spec binds.

## Intent
Finish Toolgate as a shippable portfolio piece: (1) a scripted, cost-guarded AWS deployment, (2) an honest comparison with AgentCore Gateway, (3) the Bedrock model swap, (4) `toolgate-pin` published with an automated secrets check on the artifact, (5) a top-level README with Mermaid architecture and request-flow diagrams and real numbers.

## Two phases (the split is my call)
- **F1 — no AWS account needed, fully verifiable locally:** secrets tooling (gitleaks pre-commit already exists; add CI history scan, built-wheel scan, expected-manifest check), GitHub Actions workflows (CI, release with PyPI trusted publishing), Terraform code (`terraform validate` + `plan` against nothing real is not possible without credentials, so `fmt` + `validate` + `tflint`-style review only), `make aws-up/aws-down`, `scripts/aws-leftovers.sh`, `.gitignore` additions, `toolgate-pin` README with lifecycle diagram, top-level README with diagrams and the D results, and the Bedrock provider path exercised by unit tests (fake client).
- **F2 — needs the user's AWS account (user sets it up today):** AgentCore spike (1 h, verify current MCP-target requirements), `apply`, run corpus + load test on AWS, AgentCore Gateway comparison, one Bedrock confirmation run, `destroy` + leftovers check, fill the README with AWS numbers.
F1 ships first; F2 follows when the account and credentials are ready. Every F2 step that spends money or changes AWS is run by the user's explicit go-ahead (apply, destroy, model invocation).

## Goals
- `make aws-up` / `make aws-down` wrap apply/destroy; Budget alarm $25 Terraform-managed; all resources tagged `project=toolgate`; `aws-leftovers.sh` lists anything still tagged after destroy.
- Release workflow uploads only if (a) gitleaks over the unpacked sdist and wheel is clean and (b) the file list matches the expected manifest.
- CI runs `gitleaks detect` over full history on every push/PR, plus the existing tests.
- README: problem in three sentences, architecture diagram, request-flow diagram, results tables from `toolgate-eval report`, run-locally steps, AgentCore comparison summary, honest limits (including the D findings: c=50 load target not met on one host; live matrix numbers).

## Non-goals / anti-goals
- No secrets, state files or credentials in the repo or published artifacts; no stored PyPI token; nothing left running on AWS after the demo.
- No claims in the README from fixtures: tables are real runs or marked pending.
- No production hardening of the AWS deployment beyond the spec (demo-grade, destroyed after).

## Decisions (my calls — change any)
- AWS region `us-east-1` (widest Bedrock and AgentCore availability); one `terraform.tfvars.example`, real tfvars git-ignored; local state (no S3 backend) since the stack is short-lived.
- Terraform layout `infra/terraform/{network,data,cognito,ecs,observability,budget}` as modules under one root; images built locally and pushed to ECR by a script (no CI image build).
- Publish name: check `toolgate-pin` on PyPI first; fallback `mcp-toolpin`. Version 0.1.0; first release to TestPyPI is not required, but the release workflow supports a dry-run mode that builds and scans without uploading.
- Tools to install before use: Terraform, AWS CLI v2, gitleaks (also run in CI). `gh` is not required; the user pushes to GitHub himself/herself.
- Bedrock models for the swap: Claude Haiku plus one open-weights model, pinned in `eval/models.yaml` with config hashes recorded; one confirmation run, not the matrix.
- Download/install of tools happens only after this document is approved.

## Left to the builder
Exact Fargate sizing, ALB/ACM certificate approach (a self-signed or ALB default DNS name with HTTP inside the VPC and HTTPS at the ALB if a domain is unavailable), the manifest format for the wheel check, AgentCore interceptor vs scheduled-verifier choice (decided by the F2 spike), and the Mermaid diagram layouts.

## Done when
Parent ship-gate items 7 and 8 hold (scripted apply/destroy; published pin package with automated artifact secrets check), the README renders the diagrams on GitHub, the comparison matrix has "managed provides / we added" per row, and `aws-leftovers.sh` is empty after destroy.
