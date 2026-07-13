#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cd "${repo_root}"

cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
if [[ "${cargo_target_dir}" != /* ]]; then
  cargo_target_dir="${repo_root}/${cargo_target_dir}"
fi
mkdir -p "${cargo_target_dir}"
cargo_target_dir="$(cd "${cargo_target_dir}" && pwd -P)"

trace_dir="${cargo_target_dir}/formal/distributed-revocation/traces"
model_dir="${cargo_target_dir}/formal/distributed-revocation/model"
apalache_bin="${APALACHE_BIN:-apalache-mc}"

if ! command -v "${apalache_bin}" >/dev/null 2>&1 && [[ ! -x "${apalache_bin}" ]]; then
  echo "distributed-revocation trace projection: Apalache executable not found: ${apalache_bin}" >&2
  exit 2
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "distributed-revocation trace projection: timeout command is required" >&2
  exit 2
fi

apalache_bin="$(command -v "${apalache_bin}")"

version="$(${apalache_bin} version 2>&1)"
if [[ "${version}" != "0.50.1" ]]; then
  echo "distributed-revocation trace projection: Apalache 0.50.1 is required" >&2
  exit 2
fi

rm -rf -- "${trace_dir}" "${model_dir}"
mkdir -p "${trace_dir}" "${model_dir}/input" "${model_dir}/out" "${model_dir}/run"

CHIO_DISTRIBUTED_REVOCATION_TRACE_DIR="${trace_dir}" \
  cargo test -p chio-federation --test distributed_revocation_refinement -- --test-threads=1

cargo test -p chio-kernel --lib stale_snapshot_denies_even_without_revoked_subjects
cargo test -p chio-kernel --lib future_snapshot_denies_even_without_revoked_subjects

python3 scripts/validate-distributed-revocation-trace.py \
  "${trace_dir}" \
  "${model_dir}/input"

cp formal/tla/trace/TraceCheckDistributedRevocation.tla "${model_dir}/input/"

for trace_model in "${model_dir}"/input/Trace*Itf.tla; do
  model_name="$(basename "${trace_model}" .tla)"
  mkdir -p "${model_dir}/out/${model_name}" "${model_dir}/run/${model_name}"
  timeout 900 "${apalache_bin}" \
    --out-dir="${model_dir}/out/${model_name}" \
    --run-dir="${model_dir}/run/${model_name}" \
    check \
    --length=12 \
    --init=TraceInit \
    --next=TraceNext \
    --inv=TraceSafety \
    "${trace_model}"
done

echo "distributed-revocation trace projection: exact emitted scalar trace projections passed"
