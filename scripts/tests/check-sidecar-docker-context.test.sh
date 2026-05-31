#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
dockerfile="${repo_root}/Dockerfile.sidecar"

require_copy() {
  local source="$1"
  local destination="$2"

  if ! grep -Fxq "COPY ${source} ${destination}" "${dockerfile}"; then
    echo "Dockerfile.sidecar must copy ${source} to ${destination}" >&2
    return 1
  fi
}

require_copy "contracts" "./contracts"

echo "sidecar Docker build context includes contract artifacts"
