#!/usr/bin/env bash
# Build and push toolgate images to the ECR repositories Terraform created.
# Writes infra/terraform/images.auto.tfvars (gitignored) mapping image names to
# pushed URIs. --dry-run prints the commands and runs none.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT/infra/terraform"
TF="${TERRAFORM_BIN:-terraform}"
REGION="us-east-1"
DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

# image name -> Dockerfile (all build from the repo root)
declare -A DOCKERFILE=(
  [mock-api]="services/mock-enterprise/Dockerfile"
  [core-read]="services/mcp-servers/Dockerfile"
  [core-write]="services/mcp-servers/Dockerfile"
  [comms]="services/mcp-servers/Dockerfile"
  [gateway]="packages/toolgate-gateway/Dockerfile"
)
NAMES=(mock-api core-read core-write comms gateway)
# Eval targets only when enabled and a Dockerfile exists (F2 supplies them).
if [[ "${ENABLE_EVAL_TARGETS:-0}" == "1" ]]; then
  for n in evil-server sink; do
    if [[ -f "$ROOT/eval/$n/Dockerfile" ]]; then
      DOCKERFILE[$n]="eval/$n/Dockerfile"
      NAMES+=("$n")
    else
      echo "skipping $n: eval/$n/Dockerfile does not exist" >&2
    fi
  done
fi

TAG="${IMAGE_TAG:-$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo latest)}"
OUT="$TF_DIR/images.auto.tfvars"

run() {
  if ((DRY)); then echo "+ $*"; else "$@"; fi
}

if ((DRY)); then
  echo "# repo URLs come from: $TF -chdir=infra/terraform output -json ecr_repository_urls"
  REPO_JSON='{}'
else
  REPO_JSON="$("$TF" -chdir="$TF_DIR" output -json ecr_repository_urls)"
fi

repo_url() {
  local url
  url="$(printf '%s' "$REPO_JSON" | grep -o "\"$1\": *\"[^\"]*\"" | sed 's/.*: *"\(.*\)"/\1/' || true)"
  if [[ -z "$url" ]]; then
    if ((DRY)); then echo "<ecr-url-for-$1>"; return; fi
    echo "error: no ECR repository for $1 (apply the ECR stage first)" >&2
    exit 1
  fi
  printf '%s' "$url"
}

first_url="$(repo_url "${NAMES[0]}")"
registry="${first_url%%/*}"
if ((DRY)); then
  echo "+ aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin <registry>"
else
  aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$registry" >/dev/null
fi

lines=()
for n in "${NAMES[@]}"; do
  url="$(repo_url "$n")"
  ref="$url:$TAG"
  if [[ "$n" == "gateway" ]]; then
    base="toolgate-gateway-base:$TAG"
    run docker build --platform linux/amd64 -f "${DOCKERFILE[$n]}" -t "$base" "$ROOT"
    run docker build --platform linux/amd64 -f infra/docker/gateway.cloud.Dockerfile \
      --build-arg "BASE_IMAGE=$base" -t "$ref" "$ROOT"
  else
    run docker build --platform linux/amd64 -f "${DOCKERFILE[$n]}" -t "$ref" "$ROOT"
  fi
  run docker push "$ref"
  lines+=("  \"$n\" = \"$ref\"")
done

if ((DRY)); then
  echo "+ write $OUT (images = { name = uri, ... })"
else
  { echo "images = {"; printf '%s\n' "${lines[@]}"; echo "}"; } >"$OUT"
  echo "wrote $OUT"
fi
