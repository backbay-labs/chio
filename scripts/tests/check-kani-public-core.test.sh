#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

mapfile -t pr_harnesses < <(scripts/check-kani-public-core.sh --lane pr --list)
if [[ "${#pr_harnesses[@]}" -ne 22 ]]; then
  echo "expected 22 public core PR harnesses, found ${#pr_harnesses[@]}" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path
import tomllib

public = tomllib.loads(
    Path("formal/rust-verification/kani-public-harnesses.toml").read_text()
)
multi = tomllib.loads(Path(".kani/harnesses.toml").read_text())
mirrored = [
    entry["harness"]
    for entry in multi["harness"]
    if entry["crate"] == "chio-kernel-core" and entry["lane"] == "pr"
]
if mirrored != public["lanes"]["pr"]["harnesses"]:
    raise SystemExit("public-core PR registries have drifted")
PY

mapfile -t all_harnesses < <(scripts/check-kani-public-core.sh --lane all --list)
if [[ "${pr_harnesses[*]}" != "${all_harnesses[*]}" ]]; then
  echo "all lane must equal PR lane while nightly_only is empty" >&2
  exit 1
fi

mapfile -t nightly_harnesses < <(
  scripts/check-kani-public-core.sh --lane nightly_only --list
)
if [[ "${#nightly_harnesses[@]}" -ne 0 ]]; then
  echo "expected the reserved nightly_only lane to be empty" >&2
  exit 1
fi

if scripts/check-kani-public-core.sh --lane unknown --list >/dev/null 2>&1; then
  echo "unknown lane unexpectedly succeeded" >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
cat > "${tmp_dir}/missing-harness.toml" <<'TOML'
schema = "chio.kani-public-harnesses.v1"
crate = "chio-kernel-core"
script = "scripts/check-kani-public-core.sh"

[lanes.pr]
description = "negative fixture"
harnesses = ["missing_public_harness"]

[lanes.nightly_only]
description = "reserved"
harnesses = []
TOML

if KANI_PUBLIC_HARNESSES_MANIFEST="${tmp_dir}/missing-harness.toml" \
  scripts/check-kani-public-core.sh --lane pr --list >/dev/null 2>&1; then
  echo "missing harness function unexpectedly succeeded" >&2
  exit 1
fi

echo "Kani public core registry contract passed"
