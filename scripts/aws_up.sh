#!/usr/bin/env bash
# Bring toolgate up on AWS. Ordering (ECR repositories are created by Terraform):
#   1. terraform init
#   2. if the ECR repositories do not exist: terraform apply -target=<ecr repos>
#   3. push_images.sh (build + push, writes images.auto.tfvars)
#   4. terraform apply (full)
# --dry-run prints these commands and runs none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF="${TERRAFORM_BIN:-terraform}"
TF_DIR="$ROOT/infra/terraform"
ECR_TARGET="module.ecs.aws_ecr_repository.this"

if [[ "${1:-}" == "--dry-run" ]]; then
  echo "+ aws sts get-caller-identity"
  echo "+ $TF -chdir=infra/terraform init"
  echo "# stage 1, only when the ECR repositories do not exist yet:"
  echo "+ $TF -chdir=infra/terraform apply -target=$ECR_TARGET"
  echo "# stage 2:"
  "$ROOT/scripts/push_images.sh" --dry-run
  echo "# stage 3:"
  echo "+ $TF -chdir=infra/terraform apply"
  exit 0
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "error: AWS credentials are missing or invalid; configure them (for example aws configure sso) and retry" >&2
  exit 1
fi

"$TF" -chdir="$TF_DIR" init
urls="$("$TF" -chdir="$TF_DIR" output -json ecr_repository_urls 2>/dev/null || echo '{}')"
if ! printf '%s' "$urls" | grep -q '"gateway"'; then
  echo "ECR repositories not found; creating them first"
  "$TF" -chdir="$TF_DIR" apply -target="$ECR_TARGET"
fi
"$ROOT/scripts/push_images.sh"
"$TF" -chdir="$TF_DIR" apply
