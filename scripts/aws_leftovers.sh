#!/usr/bin/env bash
# List resources still tagged project=toolgate (Resource Groups Tagging API).
# Exit 0 when none remain, 1 (listing ARNs) otherwise. --dry-run prints the command.
#
# Limits: checks us-east-1 only; the Tagging API does not list every resource
# type, nor global resources, so an empty result is strong evidence, not proof.
# Inactive ECS task definitions (":task-definition/") cost nothing and are
# listed separately without failing. When something is found the query is
# retried (LEFTOVERS_RETRY_SLEEP seconds apart, default 10, 3 attempts) because
# the tagging index is eventually consistent after a destroy.
set -euo pipefail

REGION="us-east-1"
SLEEP="${LEFTOVERS_RETRY_SLEEP:-10}"
CMD=(aws resourcegroupstaggingapi get-resources --region "$REGION"
  --tag-filters Key=project,Values=toolgate
  --query 'ResourceTagMappingList[].ResourceARN' --output text)

if [[ "${1:-}" == "--dry-run" ]]; then
  echo "+ ${CMD[*]}"
  exit 0
fi

arns=""
info=""
for attempt in 1 2 3; do
  if ! out="$("${CMD[@]}")"; then
    echo "error: could not query the Resource Groups Tagging API (check AWS credentials)" >&2
    exit 2
  fi
  all="$(printf '%s' "$out" | tr '\t' '\n' | sed '/^$/d;/^None$/d')"
  info="$(printf '%s\n' "$all" | grep ':task-definition/' || true)"
  arns="$(printf '%s\n' "$all" | grep -v ':task-definition/' | sed '/^$/d' || true)"
  [[ -z "$arns" ]] && break
  ((attempt < 3)) && sleep "$SLEEP"
done

if [[ -n "$info" ]]; then
  echo "inactive ECS task definitions (no cost, informational):"
  printf '%s\n' "$info"
fi
if [[ -z "$arns" ]]; then
  echo "no resources tagged project=toolgate"
  exit 0
fi
echo "resources still tagged project=toolgate:" >&2
printf '%s\n' "$arns"
exit 1
