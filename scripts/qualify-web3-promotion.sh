#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 promotion qualification requires jq on PATH" >&2
  exit 1
fi

if command -v corepack >/dev/null 2>&1; then
  pnpm_cmd=(corepack pnpm)
elif command -v pnpm >/dev/null 2>&1; then
  pnpm_cmd=(pnpm)
else
  echo "web3 promotion qualification requires pnpm on PATH" >&2
  exit 1
fi

output_root="target/web3-promotion-qualification"
log_path="${output_root}/qualification.log"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run "${pnpm_cmd[@]}" --dir contracts install --frozen-lockfile
run "${pnpm_cmd[@]}" --dir contracts compile
run "${pnpm_cmd[@]}" --dir contracts qualify:review-prep --output-dir "${output_root}/review-prep"
run node contracts/scripts/qualify-promotion.mjs --output-dir "${output_root}"
run jq empty \
  docs/standards/CHIO_WEB3_DEPLOYMENT_APPROVAL_EXAMPLE.json \
  docs/standards/CHIO_WEB3_DEPLOYMENT_PROMOTION_REPORT_EXAMPLE.json \
  docs/standards/CHIO_WEB3_DEPLOYMENT_ROLLBACK_PLAN_EXAMPLE.json \
  "${output_root}/review-prep/qualification.json" \
  "${output_root}/promotion-qualification.json"

printf 'web3 promotion qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
