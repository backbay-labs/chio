#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/t6-real-bbs-proof.json"

python3 - "$FIXTURE" <<'PY'
import json
import sys

fixture = sys.argv[1]
with open(fixture, "r", encoding="utf-8") as handle:
    proof = json.load(handle)

if proof.get("schema") != "chio.selective-disclosure-proof.v1":
    raise SystemExit("T6 BBS fixture does not use the real proof schema")
if str(proof.get("schema", "")).endswith(".stub"):
    raise SystemExit("T6 BBS fixture must not use the legacy stub schema")
if proof.get("projection_version") != "chio.bbs-projection.workflow.v1":
    raise SystemExit("T6 BBS fixture must exercise the workflow projection")
if proof.get("ciphersuite") != "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_":
    raise SystemExit("T6 BBS fixture must declare the SHA-256 BBS ciphersuite")
if len(proof.get("disclosed", [])) != len(proof.get("disclosed_indices", [])):
    raise SystemExit("T6 BBS fixture disclosed messages and indices disagree")

print("OK T6 real BBS fixture metadata")
PY

cargo test -p chio-selective-disclosure --features bbs --test real_bbs
cargo test -p chio-conformance --features t6-bbs --test t6_real_bbs_selective_disclosure
