#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 local qualification requires jq on PATH" >&2
  exit 1
fi

if command -v corepack >/dev/null 2>&1; then
  pnpm_cmd=(corepack pnpm)
elif command -v pnpm >/dev/null 2>&1; then
  pnpm_cmd=(pnpm)
else
  echo "web3 local qualification requires pnpm on PATH" >&2
  exit 1
fi

output_root="target/web3-local-qualification"
log_path="${output_root}/qualification.log"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run "${pnpm_cmd[@]}" --dir contracts install --frozen-lockfile
run ./scripts/qualify-web3-runtime.sh
run ./scripts/qualify-web3-promotion.sh
run ./scripts/qualify-web3-examples.sh

printf 'web3 local qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
