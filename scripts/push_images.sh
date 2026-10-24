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
dockerfile_for() {
  case "$1" in
    mock-api) echo "services/mock-enterprise/Dockerfile" ;;
    core-read | core-write | comms) echo "services/mcp-servers/Dockerfile" ;;
    gateway) echo "packages/toolgate-gateway/Dockerfile" ;;
    evil-server | sink)
      # Eval targets (Terraform enable_eval_targets); F2 supplies the Dockerfiles.
      if [[ -f "$ROOT/eval/$1/Dockerfile" ]]; then echo "eval/$1/Dockerfile"; fi
      ;;
  esac
}

# Never plain "latest": short sha, plus -dirty-<epoch> for an unclean tree.
if [[ -n "${IMAGE_TAG:-}" ]]; then
  TAG="$IMAGE_TAG"
else
  TAG="$(git -C "$ROOT" rev-parse --short HEAD)"
  if [[ -n "$(git -C "$ROOT" status --porcelain)" ]]; then
    TAG="$TAG-dirty-$(date +%s)"
  fi
fi
OUT="$TF_DIR/images.auto.tfvars"

run() {
  if ((DRY)); then echo "+ $*"; else "$@"; fi
}

if ((DRY)); then
  echo "# repo URLs come from: $TF -chdir=infra/terraform output -json ecr_repository_urls"
  REPO_JSON='{"mock-api": "x", "core-read": "x", "core-write": "x", "comms": "x", "gateway": "x"}'
else
  REPO_JSON="$("$TF" -chdir="$TF_DIR" output -json ecr_repository_urls)"
fi

# Which images to build = the keys of the Terraform ECR repository map.
NAMES=()
while IFS= read -r key; do
  if [[ -n "$(dockerfile_for "$key")" ]]; then
    NAMES+=("$key")
  else
    echo "skipping $key: no Dockerfile known for it" >&2
  fi
done < <(printf '%s' "$REPO_JSON" | grep -o '"[^"]*": *"' | sed -E 's/^"([^"]*)".*/\1/')
if ((${#NAMES[@]} == 0)); then
  echo "error: no ECR repositories in terraform output (apply the ECR stage first)" >&2
  exit 1
fi

repo_url() {
  local url
  if ((DRY)); then echo "<ecr-url-for-$1>"; return; fi
  url="$(printf '%s' "$REPO_JSON" | grep -o "\"$1\": *\"[^\"]*\"" | sed 's/.*: *"\(.*\)"/\1/' || true)"
  if [[ -z "$url" ]]; then
    if ((DRY)); then echo "<ecr-url-for-$1>"; return; fi
    echo "error: no ECR repository for $1" >&2
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
    run docker build --platform linux/amd64 -f "$ROOT/$(dockerfile_for "$n")" -t "$base" "$ROOT"
    run docker build --platform linux/amd64 -f "$ROOT/infra/docker/gateway.cloud.Dockerfile" \
      --build-arg "BASE_IMAGE=$base" -t "$ref" "$ROOT"
  else
    run docker build --platform linux/amd64 -f "$ROOT/$(dockerfile_for "$n")" -t "$ref" "$ROOT"
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
