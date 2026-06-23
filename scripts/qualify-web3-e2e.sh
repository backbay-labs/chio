#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 end-to-end qualification requires jq on PATH" >&2
  exit 1
fi

if command -v corepack >/dev/null 2>&1; then
  pnpm_cmd=(corepack pnpm)
elif command -v pnpm >/dev/null 2>&1; then
  pnpm_cmd=(pnpm)
else
  echo "web3 end-to-end qualification requires pnpm on PATH" >&2
  exit 1
fi

output_root="target/web3-e2e-qualification"
output_root_abs="$(pwd)/${output_root}"
cargo_target_dir="${CARGO_TARGET_DIR:-target/chio-web3-e2e-qualification}"
log_path="${output_root}/qualification.log"
rm -rf "${output_root}"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run "${pnpm_cmd[@]}" --dir contracts install --frozen-lockfile
run env CHIO_WEB3_E2E_OUTPUT_DIR="${output_root_abs}" \
  CARGO_TARGET_DIR="${cargo_target_dir}" \
  CARGO_INCREMENTAL=0 \
  CARGO_BUILD_JOBS=1 \
  cargo test -p chio-settle --test web3_e2e_qualification -- --nocapture --test-threads=1

run jq empty \
  "${output_root}/partner-qualification.json" \
  "${output_root}/scenarios/fx-dual-sign-settlement.json" \
  "${output_root}/scenarios/timeout-refund-recovery.json" \
  "${output_root}/scenarios/reorg-recovery.json" \
  "${output_root}/scenarios/bond-impair-recovery.json" \
  "${output_root}/scenarios/bond-expiry-recovery.json"

printf 'web3 end-to-end qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
