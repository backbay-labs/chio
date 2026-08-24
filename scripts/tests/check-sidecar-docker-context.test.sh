#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
dockerfile="${repo_root}/deploy/docker/Dockerfile.sidecar"

require_copy() {
  local source="$1"
  local destination="$2"

  if ! grep -Fxq "COPY ${source} ${destination}" "${dockerfile}"; then
    echo "Dockerfile.sidecar must copy ${source} to ${destination}" >&2
    return 1
  fi
}

require_copy "contracts" "./contracts"
require_copy "spec" "./spec"
require_copy "fixtures" "./fixtures"

if ! grep -Fq 'RUN cargo build --release --locked --jobs 1 --package chio-cli --bin chio \' "${dockerfile}"; then
  echo "Dockerfile.sidecar must bound Cargo build parallelism for hosted native runners" >&2
  exit 1
fi

echo "sidecar Docker build context and hosted resource bound are enforced"
