#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../.." && pwd)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/chio-cli-docker-workspace.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

copy_path() {
  local path="$1"
  mkdir -p "${tmp_dir}/$(dirname "${path}")"
  ln -s "${repo_root}/${path}" "${tmp_dir}/${path}"
}

cp "${script_dir}/Cargo.toml" "${tmp_dir}/Cargo.toml"
cp "${script_dir}/Cargo.lock" "${tmp_dir}/Cargo.lock"

copy_path ".cargo"
copy_path "crates"
copy_path "examples/chio-3vendor/fixtures/runtime-spine/scenario.json"
copy_path "fixtures/proof-room"
copy_path "spec"
copy_path "wit"

(
  cd "${tmp_dir}"
  cargo metadata --format-version 1 --locked >/dev/null
  cargo check --locked -p chio-cli --bin chio
)
