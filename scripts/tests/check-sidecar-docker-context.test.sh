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

if ! grep -Fq 'RUN cargo build --profile docker-release --locked --jobs 1 --package chio-cli --bin chio' "${dockerfile}"; then
  echo "Dockerfile.sidecar must use the bounded-memory docker release profile" >&2
  exit 1
fi

if ! grep -Fq '&& cp target/docker-release/chio /chio' "${dockerfile}"; then
  echo "Dockerfile.sidecar must copy the docker-release profile artifact" >&2
  exit 1
fi

python3 - "${repo_root}/Cargo.toml" <<'PY'
from pathlib import Path
import sys
import tomllib

manifest = tomllib.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
profile = manifest.get("profile", {}).get("docker-release")
expected = {"inherits": "release", "codegen-units": 16, "lto": "thin"}
if profile != expected:
    raise SystemExit(
        "Cargo.toml profile.docker-release must be the bounded-memory "
        f"container profile: expected={expected!r} actual={profile!r}"
    )
PY

echo "sidecar Docker build context and bounded-memory release profile are enforced"
