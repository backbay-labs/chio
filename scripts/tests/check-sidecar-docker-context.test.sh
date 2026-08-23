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

echo "sidecar Docker build context includes compile-time artifacts"
