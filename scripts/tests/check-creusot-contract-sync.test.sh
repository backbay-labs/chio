#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CHECKER="$REPO_ROOT/scripts/check-creusot-body-sync.sh"

work="$(mktemp -d -t chio-creusot-contract-sync-XXXXXX)"
trap 'rm -rf "$work"' EXIT

assert_passes() {
  local label="$1"
  shift
  if "$@" >"$work/out" 2>"$work/err"; then
    echo "ok: $label"
  else
    echo "FAIL: $label" >&2
    cat "$work/out" >&2
    cat "$work/err" >&2
    exit 1
  fi
}

assert_fails() {
  local label="$1"
  local expected="$2"
  shift 2
  if "$@" >"$work/out" 2>"$work/err"; then
    echo "FAIL: $label unexpectedly passed" >&2
    cat "$work/out" >&2
    exit 1
  fi
  if ! grep -Fq "$expected" "$work/err"; then
    echo "FAIL: $label missing expected diagnostic: $expected" >&2
    cat "$work/err" >&2
    exit 1
  fi
  echo "ok: $label"
}

copy_fixture() {
  local root="$1"
  mkdir -p \
    "$root/.kani" \
    "$root/scripts" \
    "$root/formal/rust-verification/creusot-core/src" \
    "$root/crates/kernel/chio-kernel-core/src"
  cp "$REPO_ROOT/.kani/harnesses.toml" "$root/.kani/"
  cp "$REPO_ROOT/scripts/check-creusot-body-sync.sh" "$root/scripts/"
  cp "$REPO_ROOT/scripts/check-rust-verification-gates.sh" "$root/scripts/"
  cp "$REPO_ROOT/formal/rust-verification/creusot-contracts.toml" \
    "$root/formal/rust-verification/"
  cp "$REPO_ROOT/formal/rust-verification/kani-harnesses.toml" \
    "$root/formal/rust-verification/"
  cp "$REPO_ROOT/formal/rust-verification/kani-public-harnesses.toml" \
    "$root/formal/rust-verification/"
  cp "$REPO_ROOT/formal/rust-verification/creusot-core/src/lib.rs" \
    "$root/formal/rust-verification/creusot-core/src/"
  cp "$REPO_ROOT/crates/kernel/chio-kernel-core/src/formal_aeneas.rs" \
    "$root/crates/kernel/chio-kernel-core/src/"
}

assert_passes "current contract sources are synchronized" bash "$CHECKER"

body_drift="$work/body-drift"
copy_fixture "$body_drift"
python3 - "$body_drift/formal/rust-verification/creusot-core/src/lib.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
call = "aeneas_body::dpop_admits("
start = source.index(call)
token = source.index("nonce_fresh", start)
path.write_text(source[:token] + "!" + source[token:], encoding="utf-8")
PY
assert_fails \
  "one-token contract body drift fails" \
  "creusot-body-sync: BODY DRIFT" \
  bash "$body_drift/scripts/check-creusot-body-sync.sh" --root "$body_drift"

alternate_include="$work/alternate-include"
copy_fixture "$alternate_include"
python3 - "$alternate_include/formal/rust-verification/creusot-core/src/lib.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
expected = '    include!("../../../../crates/kernel/chio-kernel-core/src/formal_aeneas.rs");'
replacement = (
    '    // include!("../../../../crates/kernel/chio-kernel-core/src/formal_aeneas.rs");\n'
    '    include!("alternate.rs");'
)
if expected not in source:
    raise SystemExit("expected include is missing from fixture")
path.write_text(source.replace(expected, replacement, 1), encoding="utf-8")
PY
assert_fails \
  "commented production include cannot hide an alternate include" \
  "contract crate must include the production source in aeneas_body" \
  bash "$alternate_include/scripts/check-creusot-body-sync.sh" --root "$alternate_include"

disabled_include="$work/disabled-include"
copy_fixture "$disabled_include"
python3 - "$disabled_include/formal/rust-verification/creusot-core/src/lib.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
expected = '    include!("../../../../crates/kernel/chio-kernel-core/src/formal_aeneas.rs");'
replacement = '    #[cfg(any())]\n' + expected
if expected not in source:
    raise SystemExit("expected include is missing from fixture")
path.write_text(source.replace(expected, replacement, 1), encoding="utf-8")
PY
assert_fails \
  "conditional production include fails" \
  "conditional compilation is not allowed in the contract crate" \
  bash "$disabled_include/scripts/check-creusot-body-sync.sh" --root "$disabled_include"

disabled_module="$work/disabled-module"
copy_fixture "$disabled_module"
python3 - "$disabled_module/formal/rust-verification/creusot-core/src/lib.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
declaration = "mod aeneas_body {"
if declaration not in source:
    raise SystemExit("expected module declaration is missing from fixture")
path.write_text(
    source.replace(declaration, "#[cfg(any())]\nmod aeneas_body {", 1),
    encoding="utf-8",
)
PY
assert_fails \
  "conditional production module fails" \
  "conditional compilation is not allowed in the contract crate" \
  bash "$disabled_module/scripts/check-creusot-body-sync.sh" --root "$disabled_module"

disabled_crate="$work/disabled-crate"
copy_fixture "$disabled_crate"
python3 - "$disabled_crate/formal/rust-verification/creusot-core/src/lib.rs" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
path.write_text("#![cfg(any())]\n" + source, encoding="utf-8")
PY
assert_fails \
  "conditional contract crate fails" \
  "conditional compilation is not allowed in the contract crate" \
  bash "$disabled_crate/scripts/check-creusot-body-sync.sh" --root "$disabled_crate"

missing_mapping="$work/missing-mapping"
copy_fixture "$missing_mapping"
python3 - "$missing_mapping/formal/rust-verification/creusot-contracts.toml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
block = '''[[contract_twin]]
contract = "dpop_admits_contract"
production = "dpop_admits"

'''
if block not in source:
    raise SystemExit("expected contract mapping is missing from fixture")
path.write_text(source.replace(block, "", 1), encoding="utf-8")
PY
assert_fails \
  "missing contract mapping fails" \
  "contract functions missing from contract_twin" \
  bash "$missing_mapping/scripts/check-creusot-body-sync.sh" --root "$missing_mapping"

missing_symbol="$work/missing-symbol"
copy_fixture "$missing_symbol"
python3 - "$missing_symbol/formal/rust-verification/creusot-contracts.toml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
row = '  "formal/rust-verification/creusot-core::revocation_snapshot_denies_contract",\n'
if row not in source:
    raise SystemExit("expected covered symbol is missing from fixture")
path.write_text(source.replace(row, "", 1), encoding="utf-8")
PY
assert_fails \
  "contract omitted from covered symbols fails" \
  "contract_twin entries missing from covered_symbols: revocation_snapshot_denies_contract" \
  env CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "$missing_symbol/scripts/check-rust-verification-gates.sh"

restricted_visibility="$work/restricted-visibility"
copy_fixture "$restricted_visibility"
python3 - \
  "$restricted_visibility/formal/rust-verification/creusot-core/src/lib.rs" \
  "$restricted_visibility/formal/rust-verification/creusot-contracts.toml" <<'PY'
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
source = source_path.read_text(encoding="utf-8")
signature = "pub fn revocation_snapshot_denies_contract("
if signature not in source:
    raise SystemExit("expected contract signature is missing from fixture")
source_path.write_text(
    source.replace(signature, "pub(crate) fn revocation_snapshot_denies_contract(", 1),
    encoding="utf-8",
)

manifest_path = Path(sys.argv[2])
manifest = manifest_path.read_text(encoding="utf-8")
row = '  "formal/rust-verification/creusot-core::revocation_snapshot_denies_contract",\n'
if row not in manifest:
    raise SystemExit("expected covered symbol is missing from fixture")
manifest_path.write_text(manifest.replace(row, "", 1), encoding="utf-8")
PY
assert_fails \
  "restricted visibility cannot bypass covered symbols" \
  "contract_twin entries missing from covered_symbols: revocation_snapshot_denies_contract" \
  env CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "$restricted_visibility/scripts/check-rust-verification-gates.sh"

extra_symbol="$work/extra-symbol"
copy_fixture "$extra_symbol"
python3 - "$extra_symbol/formal/rust-verification/creusot-contracts.toml" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
source = path.read_text(encoding="utf-8")
end = ']\n\ncontract_goals = ['
if end not in source:
    raise SystemExit("covered_symbols terminator is missing from fixture")
replacement = '  "formal/rust-verification/creusot-core::removed_contract",\n]\n\ncontract_goals = ['
path.write_text(source.replace(end, replacement, 1), encoding="utf-8")
PY
assert_fails \
  "stale covered symbol fails" \
  "covered_symbols entries missing from contract_twin: removed_contract" \
  env CHIO_RUST_VERIFICATION_METADATA_ONLY=1 \
  bash "$extra_symbol/scripts/check-rust-verification-gates.sh"

echo "check-creusot-contract-sync.test.sh: all assertions passed"
