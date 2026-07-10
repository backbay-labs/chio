#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-proof-room-docker-workspace.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

copy_path() {
  local path="$1"
  mkdir -p "${tmp_dir}/$(dirname "${path}")"
  cp -R "${repo_root}/${path}" "${tmp_dir}/${path}"
}

cp "${script_dir}/Cargo.toml" "${tmp_dir}/Cargo.toml"
cp "${script_dir}/Cargo.lock" "${tmp_dir}/Cargo.lock"

copy_path "crates/core/chio-core-types"
copy_path "crates/economy/chio-appraisal"
copy_path "crates/economy/chio-credit"
copy_path "crates/economy/chio-underwriting"
copy_path "crates/economy/chio-web3"
copy_path "crates/kernel/chio-runtime-proof-parity"
copy_path "crates/kernel/chio-swarm-authority"
copy_path "crates/platform/chio-agent-web-interop"
copy_path "crates/platform/chio-commerce-order"
copy_path "crates/platform/chio-enterprise-export"
copy_path "crates/platform/chio-risk-comptroller"
copy_path "crates/platform/chio-transaction-passport"
copy_path "crates/platform/chio-trust-market-context"
copy_path "crates/platform/chio-workflow-preflight"
copy_path "crates/products/proof_fixture_build.rs"
copy_path "crates/products/chio-proof-room"
copy_path "crates/trust/chio-disclosure-lineage"
copy_path "crates/tooling/chio-spec-codegen"
copy_path "crates/tooling/chio-test-support"
copy_path "fixtures/proof-room/catalog.json"
copy_path "fixtures/proof-room/first-run/single-call-authority"
copy_path "spec/schemas/chio-proof-room"
copy_path "spec/schemas/chio-runtime"
copy_path "spec/schemas/chio-transaction"

(
  cd "${tmp_dir}"
  cargo metadata --format-version 1 --locked >/dev/null
  cargo check --locked -p chio-proof-room --bin chio-proof-room
)
