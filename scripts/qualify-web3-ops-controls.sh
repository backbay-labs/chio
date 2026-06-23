#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "web3 ops qualification requires jq on PATH" >&2
  exit 1
fi

output_root="target/web3-ops-qualification"
output_root_abs="$(pwd)/${output_root}"
cargo_target_dir="${CARGO_TARGET_DIR:-target/chio-web3-ops-qualification}"
log_path="${output_root}/qualification.log"
rm -rf "${output_root}"
mkdir -p "${output_root}"
: >"${log_path}"

run() {
  printf '==> %s\n' "$*" | tee -a "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run env CHIO_WEB3_OPS_OUTPUT_DIR="${output_root_abs}" \
  CARGO_TARGET_DIR="${cargo_target_dir}" \
  CARGO_INCREMENTAL=0 \
  CARGO_BUILD_JOBS=1 \
  cargo test -p chio-control-plane --test web3_ops_qualification -- --nocapture --test-threads=1

run jq empty \
  "${output_root}/runtime-reports/chio-link-runtime-report.json" \
  "${output_root}/runtime-reports/chio-anchor-runtime-report.json" \
  "${output_root}/runtime-reports/chio-settle-runtime-report.json" \
  "${output_root}/control-state/chio-link-control-state.json" \
  "${output_root}/control-state/chio-anchor-control-state.json" \
  "${output_root}/control-state/chio-settle-control-state.json" \
  "${output_root}/control-traces/chio-link-control-trace.json" \
  "${output_root}/control-traces/chio-anchor-control-trace.json" \
  "${output_root}/control-traces/chio-settle-control-trace.json" \
  "${output_root}/incident-audit.json"

printf 'web3 ops qualification complete; log written to %s\n' "${log_path}" | tee -a "${log_path}"
