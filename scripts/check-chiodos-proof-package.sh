#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/selective-disclosure-proof.json"
PACKAGE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
REPORT_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-report.json"

python3 - "$PROOF_FIXTURE" "$PACKAGE_FIXTURE" "$REPORT_FIXTURE" <<'PY'
import json
import sys

proof_fixture, package_fixture, report_fixture = sys.argv[1:]
with open(proof_fixture, "r", encoding="utf-8") as handle:
    proof = json.load(handle)
with open(package_fixture, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(report_fixture, "r", encoding="utf-8") as handle:
    report = json.load(handle)

if proof.get("schema") != "chio.selective-disclosure-proof.v1":
    raise SystemExit("Chiodos BBS fixture does not use the real proof schema")
if str(proof.get("schema", "")).endswith(".stub"):
    raise SystemExit("Chiodos BBS fixture must not use the legacy stub schema")
if proof.get("projection_version") != "chio.bbs-projection.workflow.v1":
    raise SystemExit("Chiodos BBS fixture must exercise the workflow projection")
if proof.get("ciphersuite") != "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_":
    raise SystemExit("Chiodos BBS fixture must declare the SHA-256 BBS ciphersuite")
if len(proof.get("disclosed", [])) != len(proof.get("disclosed_indices", [])):
    raise SystemExit("Chiodos BBS fixture disclosed messages and indices disagree")
if package.get("schema") != "chio.chiodos.proof-package.v1":
    raise SystemExit("Chiodos proof package uses the wrong schema")
if report.get("schema") != "chio.chiodos.verifier-report.v1":
    raise SystemExit("Chiodos verifier report uses the wrong schema")
if not report.get("accepted"):
    raise SystemExit("Chiodos verifier report is not accepted")
claims = package.get("claims", {})
if not claims.get("bbsRevealSet"):
    raise SystemExit("Chiodos package must claim real BBS reveal-set support")
for unsupported in ("hiddenRangePredicates", "vcDataIntegrityBbs", "zkvm"):
    if claims.get(unsupported):
        raise SystemExit(f"Chiodos package must not claim {unsupported}")
if package.get("selectiveDisclosureProof") != proof:
    raise SystemExit("Standalone BBS proof fixture differs from package proof")
if len(package.get("bilateralEnvelopes", [])) != 3:
    raise SystemExit("Chiodos package must contain three bilateral envelopes")
if len(package.get("capabilityLeases", [])) != 3:
    raise SystemExit("Chiodos package must contain three capability leases")
if len(package.get("governanceReceipts", [])) != 1:
    raise SystemExit("Chiodos package must contain one destructive governance receipt")

print("OK Chiodos proof package metadata")
PY

cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure
cargo test -p chio-conformance --features chiodos-bbs --test chiodos_selective_disclosure
cargo test -p chiodos-three-vendor-example
