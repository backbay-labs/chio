#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

expected_pr_harness_count="$(
  python3 - <<'PY'
from pathlib import Path
import tomllib

public = tomllib.loads(
    Path("formal/rust-verification/kani-public-harnesses.toml").read_text()
)
print(len(public["lanes"]["pr"]["harnesses"]))
PY
)"
mapfile -t pr_harnesses < <(scripts/check-kani-public-core.sh --lane pr --list)
if [[ "${#pr_harnesses[@]}" -ne "$expected_pr_harness_count" ]]; then
  echo "expected ${expected_pr_harness_count} public core PR harnesses, found ${#pr_harnesses[@]}" >&2
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
multi_unwinding_checks = [
    entry["harness"]
    for entry in multi["harness"]
    if entry["crate"] == "chio-kernel-core"
    and entry["lane"] == "pr"
    and entry.get("unwinding_checks", False)
]
if multi_unwinding_checks != public["unwinding_checks"]:
    raise SystemExit("public-core unwinding-check posture has drifted")
PY

dry_run="$(scripts/run-kani-manifest.sh --lane pr --crate chio-kernel-core --dry-run)"
oracle_line="$(grep -F -- '--harness kani_public_harnesses::verify_oracle_inclusion_walk_parity ' <<<"$dry_run")"
if grep -Fq -- '--no-unwinding-checks' <<<"$oracle_line"; then
  echo "inclusion-walk proof unexpectedly disables unwinding checks" >&2
  exit 1
fi
ordinary_line="$(grep -F -- '--harness kani_public_harnesses::verify_revocation_view_freshness ' <<<"$dry_run")"
if ! grep -Fq -- '--no-unwinding-checks' <<<"$ordinary_line"; then
  echo "ordinary public harness unexpectedly changed unwinding posture" >&2
  exit 1
fi

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

cat > "${tmp_dir}/unknown-unwinding-check.toml" <<'TOML'
schema = "chio.kani-public-harnesses.v1"
crate = "chio-kernel-core"
script = "scripts/check-kani-public-core.sh"
unwinding_checks = ["missing_public_harness"]

[lanes.pr]
description = "negative fixture"
harnesses = ["verify_revocation_view_freshness"]

[lanes.nightly_only]
description = "reserved"
harnesses = []
TOML

if KANI_PUBLIC_HARNESSES_MANIFEST="${tmp_dir}/unknown-unwinding-check.toml" \
  scripts/check-kani-public-core.sh --lane pr --list >/dev/null 2>&1; then
  echo "unknown unwinding-check harness unexpectedly succeeded" >&2
  exit 1
fi

cp formal/rust-verification/kani-public-harnesses.toml \
  "${tmp_dir}/unknown-lane.toml"
cat >>"${tmp_dir}/unknown-lane.toml" <<'TOML'

[lanes.pr_typo]
description = "must not be silently ignored"
harnesses = []
TOML
if KANI_PUBLIC_HARNESSES_MANIFEST="${tmp_dir}/unknown-lane.toml" \
  scripts/check-kani-public-core.sh --lane all --list >/dev/null 2>&1; then
  echo "unknown manifest lane unexpectedly succeeded" >&2
  exit 1
fi

cp crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs \
  "${tmp_dir}/unregistered-proof.rs"
cat >>"${tmp_dir}/unregistered-proof.rs" <<'RS'

#[kani::proof]
pub fn unregistered_public_harness_fixture() {}
RS
if KANI_PUBLIC_HARNESSES_SOURCE="${tmp_dir}/unregistered-proof.rs" \
  scripts/check-kani-public-core.sh --lane all --list >/dev/null 2>&1; then
  echo "unregistered public proof unexpectedly succeeded" >&2
  exit 1
fi

echo "Kani public core registry contract passed"
