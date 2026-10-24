#!/usr/bin/env bash
# List resources still tagged project=toolgate (Resource Groups Tagging API).
# Exit 0 when none remain, 1 (listing ARNs) otherwise. --dry-run prints the command.
set -euo pipefail

REGION="us-east-1"
CMD=(aws resourcegroupstaggingapi get-resources --region "$REGION"
  --tag-filters Key=project,Values=toolgate
  --query 'ResourceTagMappingList[].ResourceARN' --output text)

if [[ "${1:-}" == "--dry-run" ]]; then
  echo "+ ${CMD[*]}"
  exit 0
fi

if ! out="$("${CMD[@]}")"; then
  echo "error: could not query the Resource Groups Tagging API (check AWS credentials)" >&2
  exit 2
fi
arns="$(printf '%s' "$out" | tr '\t' '\n' | sed '/^$/d;/^None$/d')"
if [[ -z "$arns" ]]; then
  echo "no resources tagged project=toolgate"
  exit 0
fi
echo "resources still tagged project=toolgate:" >&2
printf '%s\n' "$arns"
exit 1
