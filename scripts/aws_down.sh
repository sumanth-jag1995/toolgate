#!/usr/bin/env bash
# Destroy everything, then verify nothing tagged project=toolgate remains.
# --dry-run prints the commands and runs none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF="${TERRAFORM_BIN:-terraform}"
TF_DIR="$ROOT/infra/terraform"

if [[ "${1:-}" == "--dry-run" ]]; then
  echo "+ $TF -chdir=infra/terraform destroy"
  "$ROOT/scripts/aws_leftovers.sh" --dry-run
  exit 0
fi

if ! aws sts get-caller-identity >/dev/null 2>&1; then
  echo "error: AWS credentials are missing or invalid; configure them and retry" >&2
  exit 1
fi
"$TF" -chdir="$TF_DIR" destroy
"$ROOT/scripts/aws_leftovers.sh"
