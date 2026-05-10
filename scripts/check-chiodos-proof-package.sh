#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/selective-disclosure-proof.json"
PACKAGE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUSTED_ISSUERS_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/trusted-issuers.json"
REPORT_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-report.json"

python3 - "$PROOF_FIXTURE" "$PACKAGE_FIXTURE" "$TRUSTED_ISSUERS_FIXTURE" "$REPORT_FIXTURE" <<'PY'
import json
import sys

proof_fixture, package_fixture, trusted_issuers_fixture, report_fixture = sys.argv[1:]
with open(proof_fixture, "r", encoding="utf-8") as handle:
    proof = json.load(handle)
with open(package_fixture, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(trusted_issuers_fixture, "r", encoding="utf-8") as handle:
    trusted_issuers = json.load(handle)
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
if trusted_issuers.get("schema") != "chio.chiodos.trusted-issuer-registry.v1":
    raise SystemExit("Chiodos trusted issuer registry uses the wrong schema")
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
issuers = trusted_issuers.get("issuers", [])
if len(issuers) != 1:
    raise SystemExit("Chiodos trusted issuer registry must contain one fixture issuer")
issuer = issuers[0]
if issuer.get("issuerFingerprint") != proof.get("issuer_fingerprint"):
    raise SystemExit("Trusted issuer registry fingerprint does not match proof issuer")
if issuer.get("publicKeyHex") != proof.get("issuer_public_key_hex"):
    raise SystemExit("Trusted issuer registry key does not match proof issuer key")
if len(package.get("bilateralEnvelopes", [])) != 3:
    raise SystemExit("Chiodos package must contain three bilateral envelopes")
for idx, envelope in enumerate(package.get("bilateralEnvelopes", [])):
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise SystemExit(f"Chiodos envelope {idx} has no payload")
    import base64
    statement = json.loads(base64.b64decode(payload).decode("utf-8"))
    if statement.get("predicateType") != "chio.bilateral-cosign-invocation.v1":
        raise SystemExit(f"Chiodos envelope {idx} is not strict Chiodos")
    predicate = statement.get("predicate", {})
    if "tool_args_hash" not in predicate:
        raise SystemExit(f"Chiodos envelope {idx} is missing tool_args_hash")
    if "receipt_canonical_json" in predicate:
        raise SystemExit(f"Chiodos envelope {idx} carries signature-slice receipt helper")
if len(package.get("capabilityLeases", [])) != 3:
    raise SystemExit("Chiodos package must contain three capability leases")
if len(package.get("governanceReceipts", [])) != 1:
    raise SystemExit("Chiodos package must contain one destructive governance receipt")

print("OK Chiodos proof package metadata")
PY

cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure
cargo test -p chio-conformance --features chiodos-bbs --test chiodos_selective_disclosure
cargo test -p chio-chiodos
cargo test -p chio-cli chiodos
cargo test -p chiodos-three-vendor-example

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
cargo run -p chio-cli -- chiodos verify \
    --package "$PACKAGE_FIXTURE" \
    --trusted-issuers "$TRUSTED_ISSUERS_FIXTURE" \
    --report "$tmpdir/verifier-report.json"
cmp "$REPORT_FIXTURE" "$tmpdir/verifier-report.json"

cat > "$tmpdir/untrusted-issuers.json" <<'JSON'
{
  "schema": "chio.chiodos.trusted-issuer-registry.v1",
  "issuers": [
    {
      "issuerFingerprint": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "publicKeyHex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
JSON
if cargo run -p chio-cli -- chiodos verify \
    --package "$PACKAGE_FIXTURE" \
    --trusted-issuers "$tmpdir/untrusted-issuers.json" \
    --report "$tmpdir/rejected-report.json"; then
    echo "Chiodos CLI accepted an untrusted BBS issuer registry" >&2
    exit 1
fi
