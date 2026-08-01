#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

for config in \
  .kani/harnesses.toml \
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
import re
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

multi_rel = ".kani/harnesses.toml"
multi = tomllib.loads(Path(multi_rel).read_text(encoding="utf-8"))
if set(multi) != {"schema", "harness"}:
    raise SystemExit(
        f"{multi_rel} must contain only schema and harness tables"
    )
if multi.get("schema") != "chio.kani.multi-crate.v1":
    raise SystemExit(f"schema mismatch in {multi_rel}")
entries = multi.get("harness")
if not isinstance(entries, list) or not entries:
    raise SystemExit(f"{multi_rel} must contain a non-empty harness array")
required_keys = {"crate", "harness", "default_unwind", "timeout_secs", "lane"}
allowed_keys = required_keys | {
    "unwinding_checks",
    "features",
    "primary_rust_symbol",
    "notes",
}
seen_pairs = set()
for index, entry in enumerate(entries):
    label = f"{multi_rel} harness[{index}]"
    if not isinstance(entry, dict):
        raise SystemExit(f"{label} must be a table")
    missing = sorted(required_keys - set(entry))
    unknown = sorted(set(entry) - allowed_keys)
    if missing or unknown:
        raise SystemExit(f"{label} keys invalid: missing={missing} unknown={unknown}")
    crate = entry["crate"]
    harness = entry["harness"]
    if not isinstance(crate, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", crate):
        raise SystemExit(f"{label}.crate must be a normalized Cargo package name")
    if not isinstance(harness, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", harness):
        raise SystemExit(f"{label}.harness must be a Rust identifier")
    pair = (crate, harness)
    if pair in seen_pairs:
        raise SystemExit(f"{label} duplicates {crate}::{harness}")
    seen_pairs.add(pair)
    for field in ("default_unwind", "timeout_secs"):
        value = entry[field]
        if type(value) is not int or value < 1:
            raise SystemExit(f"{label}.{field} must be a positive integer")
    if entry["lane"] not in {"pr", "nightly"}:
        raise SystemExit(f"{label}.lane must be pr or nightly")
    if type(entry.get("unwinding_checks", False)) is not bool:
        raise SystemExit(f"{label}.unwinding_checks must be a boolean")
    features = entry.get("features", [])
    if not isinstance(features, list) or not all(
        isinstance(feature, str) and feature for feature in features
    ) or len(features) != len(set(features)):
        raise SystemExit(f"{label}.features must be a unique string list")
    primary = entry.get("primary_rust_symbol")
    if primary is not None and (not isinstance(primary, str) or not primary):
        raise SystemExit(f"{label}.primary_rust_symbol must be a non-empty string")
    notes = entry.get("notes")
    if notes is not None and not isinstance(notes, str):
        raise SystemExit(f"{label}.notes must be a string")

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
./scripts/run-kani-manifest.sh --lane pr --exclude-crate chio-kernel-core

echo "Strict Rust verification tools and registered Kani checks passed"
