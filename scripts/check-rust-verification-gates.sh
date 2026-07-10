#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for config in \
  formal/rust-verification/creusot-contracts.toml \
  formal/rust-verification/kani-harnesses.toml \
  formal/rust-verification/kani-public-harnesses.toml
do
  if [[ ! -f "${config}" ]]; then
    echo "Rust verification config missing: ${config}" >&2
    exit 1
  fi
done

python3 - <<'PY'
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError as exc:
        raise SystemExit("tomllib or tomli is required for Rust verification gate checks") from exc

expected = {
    "formal/rust-verification/creusot-contracts.toml": "chio.creusot-contracts.v1",
    "formal/rust-verification/kani-harnesses.toml": "chio.kani-harnesses.v1",
    "formal/rust-verification/kani-public-harnesses.toml": "chio.kani-public-harnesses.v1",
}

loaded = {}
for rel, schema in expected.items():
    data = tomllib.loads(Path(rel).read_text(encoding="utf-8"))
    loaded[rel] = data
    if data.get("schema") != schema:
        raise SystemExit(f"schema mismatch in {rel}")
    if not data.get("covered_symbols") and not data.get("harness_groups"):
        raise SystemExit(f"missing coverage declaration in {rel}")

creusot_rel = "formal/rust-verification/creusot-contracts.toml"
creusot_prefix = "formal/rust-verification/creusot-core::"
contract_twins = loaded[creusot_rel].get("contract_twin")
if not isinstance(contract_twins, list) or not contract_twins:
    raise SystemExit("contract_twin must be a non-empty table array")
mapped_contracts = []
for index, twin in enumerate(contract_twins):
    if not isinstance(twin, dict) or not isinstance(twin.get("contract"), str):
        raise SystemExit(f"contract_twin[{index}] must declare a contract string")
    mapped_contracts.append(twin["contract"])
if len(mapped_contracts) != len(set(mapped_contracts)):
    raise SystemExit("duplicate Creusot contract entries in contract_twin")
contract_names = set(mapped_contracts)
covered_contracts = [
    symbol.removeprefix(creusot_prefix)
    for symbol in loaded[creusot_rel].get("covered_symbols", [])
    if symbol.startswith(creusot_prefix)
]
if len(covered_contracts) != len(set(covered_contracts)):
    raise SystemExit("duplicate Creusot contract entries in covered_symbols")
covered_names = set(covered_contracts)
missing_symbols = sorted(contract_names - covered_names)
stale_symbols = sorted(covered_names - contract_names)
if missing_symbols:
    raise SystemExit(
        "contract_twin entries missing from covered_symbols: " + ", ".join(missing_symbols)
    )
if stale_symbols:
    raise SystemExit(
        "covered_symbols entries missing from contract_twin: " + ", ".join(stale_symbols)
    )
PY

./scripts/check-creusot-body-sync.sh

if [[ "${CHIO_RUST_VERIFICATION_METADATA_ONLY:-0}" == "1" ]]; then
  echo "Rust verification gate metadata passed; strict Creusot/Kani execution explicitly disabled"
  exit 0
fi

if ! command -v creusot >/dev/null 2>&1 && ! cargo creusot --help >/dev/null 2>&1; then
  echo "strict Rust verification requires Creusot on PATH or cargo-creusot installed" >&2
  exit 1
fi

if ! command -v kani >/dev/null 2>&1 && ! cargo kani --help >/dev/null 2>&1; then
  echo "strict Rust verification requires Kani on PATH or cargo-kani installed" >&2
  exit 1
fi

./scripts/check-creusot-smoke.sh
./scripts/check-kani-smoke.sh
./scripts/check-creusot-core.sh
./scripts/check-kani-core.sh
./scripts/check-kani-public-core.sh

echo "Strict Rust verification tools and core checks passed"
