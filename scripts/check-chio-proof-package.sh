#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="all"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    shift
    ;;
  "--negative-only")
    MODE="negative-only"
    shift
    ;;
  *)
    echo "usage: check-chio-proof-package.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-proof-package.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

PROOF_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/selective-disclosure-proof.json"
PACKAGE_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUST_BUNDLE_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verifier-trust-bundle.json"
CONTEXT_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verification-context.json"
REPORT_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/verifier-report.json"
NEGATIVE_CASES_FIXTURE="$ROOT/examples/chio-3vendor/fixtures/negative-cases.json"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"

python3 - "$PROOF_FIXTURE" "$PACKAGE_FIXTURE" "$TRUST_BUNDLE_FIXTURE" "$CONTEXT_FIXTURE" "$REPORT_FIXTURE" "$NEGATIVE_CASES_FIXTURE" "$SCHEMA_REGISTRY" <<'PY'
import base64
import json
import pathlib
import sys

proof_fixture, package_fixture, trust_bundle_fixture, context_fixture, report_fixture, negative_cases_fixture, schema_registry = sys.argv[1:]
with open(proof_fixture, "r", encoding="utf-8") as handle:
    proof = json.load(handle)
with open(package_fixture, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(trust_bundle_fixture, "r", encoding="utf-8") as handle:
    trust_bundle = json.load(handle)
with open(context_fixture, "r", encoding="utf-8") as handle:
    context = json.load(handle)
with open(report_fixture, "r", encoding="utf-8") as handle:
    report = json.load(handle)
with open(negative_cases_fixture, "r", encoding="utf-8") as handle:
    negative_cases = json.load(handle)
with open(schema_registry, "r", encoding="utf-8") as handle:
    registry = json.load(handle)

if proof.get("schema") != "chio.attest.selective-disclosure-proof.v1":
    raise SystemExit("Chio BBS fixture does not use the real proof schema")
if str(proof.get("schema", "")).endswith(".stub"):
    raise SystemExit("Chio BBS fixture must not use the legacy stub schema")
if proof.get("projection_version") != "chio.bbs-projection.workflow.v1":
    raise SystemExit("Chio BBS fixture must exercise the workflow projection")
if proof.get("ciphersuite") != "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_":
    raise SystemExit("Chio BBS fixture must declare the SHA-256 BBS ciphersuite")
if len(proof.get("disclosed", [])) != len(proof.get("disclosed_indices", [])):
    raise SystemExit("Chio BBS fixture disclosed messages and indices disagree")
if len(set(proof.get("disclosed_indices", []))) != len(proof.get("disclosed_indices", [])):
    raise SystemExit("Chio BBS fixture disclosed indices must be unique")
if package.get("schema") != "chio.attest.proof-package.v1":
    raise SystemExit("Chio proof package uses the wrong schema")
if trust_bundle.get("schema") != "chio.federation.verifier-trust-bundle.v1":
    raise SystemExit("Chio verifier trust bundle uses the wrong schema")
if context.get("schema") != "chio.federation.verification-context.v1":
    raise SystemExit("Chio verification context uses the wrong schema")
if report.get("schema") != "chio.attest.verifier-report.v1":
    raise SystemExit("Chio verifier report uses the wrong schema")
if not report.get("accepted"):
    raise SystemExit("Chio verifier report is not accepted")
for field in ("packageSha256", "trustBundleSha256", "contextSha256", "revocationEpochHeight"):
    if field not in report:
        raise SystemExit(f"Chio verifier report is missing {field}")
if not all(check.get("code") for check in report.get("checks", [])):
    raise SystemExit("Chio verifier report checks must carry stable codes")

claims = package.get("claims", {})
if not claims.get("bbsRevealSet"):
    raise SystemExit("Chio package must claim real BBS reveal-set support")
for unsupported in ("hiddenRangePredicates", "vcDataIntegrityBbs", "zkvm"):
    if claims.get(unsupported):
        raise SystemExit(f"Chio package must not claim {unsupported}")
if package.get("selectiveDisclosureProof") != proof:
    raise SystemExit("Standalone BBS proof fixture differs from package proof")

policy = trust_bundle.get("disclosurePolicy", {})
if policy.get("projectionVersion") != proof.get("projection_version"):
    raise SystemExit("Disclosure policy projection does not match proof projection")
if policy.get("ciphersuite") != proof.get("ciphersuite"):
    raise SystemExit("Disclosure policy ciphersuite does not match proof ciphersuite")
if policy.get("messageCount") != proof.get("message_count"):
    raise SystemExit("Disclosure policy message count does not match proof")
if set(policy.get("requiredDisclosedIndices", [])) - set(proof.get("disclosed_indices", [])):
    raise SystemExit("BBS proof does not disclose every verifier-required index")
disclosed_fields = {message.get("field") for message in proof.get("disclosed", [])}
if set(policy.get("requiredDisclosedFields", [])) - disclosed_fields:
    raise SystemExit("BBS proof does not disclose every verifier-required field")

issuers = trust_bundle.get("trustedBbsIssuers", [])
if len(issuers) != 1:
    raise SystemExit("Chio trust bundle must contain one fixture BBS issuer")
issuer = issuers[0]
if issuer.get("issuerFingerprint") != proof.get("issuer_fingerprint"):
    raise SystemExit("Trust bundle issuer fingerprint does not match proof issuer")
if issuer.get("publicKeyHex") != proof.get("issuer_public_key_hex"):
    raise SystemExit("Trust bundle issuer key does not match proof issuer key")

revocation = trust_bundle.get("revocation", {})
body = revocation.get("body", {})
if body.get("schema") != "chio.federation.revocation-checkpoint.v1":
    raise SystemExit("Trust bundle must carry a signed revocation checkpoint")
if body.get("expiresAtUnixMs", 0) <= body.get("issuedAtUnixMs", 0):
    raise SystemExit("Revocation checkpoint must have a live interval")
if "signerKey" not in revocation or "signature" not in revocation:
    raise SystemExit("Revocation checkpoint must be signed")

workflow_intersection = package.get("workflowIntersection", {})
if workflow_intersection.get("schema") != "chio.attest.workflow-intersection.v1":
    raise SystemExit("Chio package must carry workflow intersection v1")
if workflow_intersection.get("workflowId") != package.get("workflowId"):
    raise SystemExit("Workflow intersection workflow id must match package")
if workflow_intersection.get("workflowGrantId") != package.get("workflowReceipt", {}).get("capability_id"):
    raise SystemExit("Workflow intersection grant must match workflow receipt capability")
if len(workflow_intersection.get("pairwiseIntersectionRefs", [])) != 3:
    raise SystemExit("Workflow intersection must bind three pairwise intersections")
if len(workflow_intersection.get("requiredVendorSigners", [])) != 3:
    raise SystemExit("Workflow intersection must bind three vendor signers")
if len(workflow_intersection.get("stepClassBindings", [])) != 3:
    raise SystemExit("Workflow intersection must bind three step classes")
if len(trust_bundle.get("peers", [])) != 4:
    raise SystemExit("Trust bundle must pin buyer and three vendor peers")
if len(trust_bundle.get("vendors", [])) != 3:
    raise SystemExit("Trust bundle must pin three vendor signers")
action_class_ids = {entry.get("actionClassId") for entry in trust_bundle.get("actionClasses", [])}
if len(trust_bundle.get("actionClasses", [])) < 5:
    raise SystemExit("Trust bundle must own vendor and workflow action-class entries")
for required_class in ("workflow.grant_issue", "workflow.aggregate_publish"):
    if required_class not in action_class_ids:
        raise SystemExit(f"Trust bundle must own {required_class}")
if len(trust_bundle.get("workflowIntersections", [])) != 1:
    raise SystemExit("Trust bundle must trust one workflow intersection hash")
if len(package.get("bilateralEnvelopes", [])) != 3:
    raise SystemExit("Chio package must contain three bilateral envelopes")
for idx, envelope in enumerate(package.get("bilateralEnvelopes", [])):
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise SystemExit(f"Chio envelope {idx} has no payload")
    statement = json.loads(base64.b64decode(payload).decode("utf-8"))
    if statement.get("predicateType") != "chio.bilateral-cosign-invocation.v1":
        raise SystemExit(f"Chio envelope {idx} is not a strict bilateral cosign invocation")
    predicate = statement.get("predicate", {})
    if "tool_args_hash" not in predicate:
        raise SystemExit(f"Chio envelope {idx} is missing tool_args_hash")
    if "receipt_canonical_json" in predicate:
        raise SystemExit(f"Chio envelope {idx} carries signature-slice receipt helper")
if len(package.get("capabilityLeases", [])) != 3:
    raise SystemExit("Chio package must contain three capability leases")
if len(package.get("leaseScopeBindings", [])) != 3:
    raise SystemExit("Chio package must contain three lease scope bindings")
for binding in package.get("leaseScopeBindings", []):
    if binding.get("schema") != "chio.federation.lease-scope-binding.v1":
        raise SystemExit("Chio lease scope binding uses the wrong schema")
if len(package.get("governanceReceipts", [])) != 1:
    raise SystemExit("Chio package must contain one destructive governance receipt")

lease_authorities = trust_bundle.get("leaseAuthorities", [])
if len(lease_authorities) != 1:
    raise SystemExit("Trust bundle must pin one lease authority")
lease_authority = lease_authorities[0]
for field in ("keyId", "validFromUnixMs", "validUntilUnixMs", "status"):
    if field not in lease_authority:
        raise SystemExit(f"Lease authority is missing {field}")
if lease_authority.get("issuer") != "did:chio:buyer-kernel":
    raise SystemExit("Fixture lease authority issuer mismatch")
if lease_authority.get("publicKey") != package["capabilityLeases"][0].get("signerKey"):
    raise SystemExit("Fixture lease authority key does not match signed leases")
if "narrow_destructive" not in lease_authority.get("allowedActionClasses", []):
    raise SystemExit("Fixture lease authority must allow narrow destructive leases")

governance_authorities = trust_bundle.get("governanceAuthorities", [])
if len(governance_authorities) != 1:
    raise SystemExit("Trust bundle must pin one governance authority")
governance_authority = governance_authorities[0]
for field in ("keyId", "validFromUnixMs", "validUntilUnixMs", "status"):
    if field not in governance_authority:
        raise SystemExit(f"Governance authority is missing {field}")
if governance_authority.get("authorizingKernel") != "did:chio:buyer-governance":
    raise SystemExit("Fixture governance authority kernel mismatch")
if governance_authority.get("publicKey") != package["governanceReceipts"][0].get("signerKey"):
    raise SystemExit("Fixture governance authority key does not match signed receipt")

if negative_cases.get("schema") != "chio.attest.buyer-proof-negative-fixture-corpus.v1":
    raise SystemExit("Chio negative corpus uses the wrong schema")
if len(negative_cases.get("cases", [])) < 14:
    raise SystemExit("Chio negative corpus must cover verifier trust, context, and package mutations")

# The proof-package, trust-bundle, and supporting artifacts are split across
# the chio-attest and chio-federation schema namespaces. Resolve each schema
# file from the registry (the single source of truth) rather than assuming a
# flat directory layout, then confirm it is frozen as a strict object schema.
expected_schemas = {
    "chio.capability-lease.v1",
    "chio.governance-receipt.v1",
    "chio.federation.lease-scope-binding.v1",
    "chio.attest.proof-package.v1",
    "chio.federation.verifier-trust-bundle.v1",
    "chio.attest.workflow-intersection.v1",
    "chio.attest.selective-disclosure-proof.v1",
    "chio.attest.verifier-report.v1",
    "chio.federation.revocation-checkpoint.v1",
    "chio.federation.verification-context.v1",
    "chio.attest.buyer-proof-negative-fixture-corpus.v1",
    "chio.federation.authority-profile.v1",
    "chio.federation.issuance-request.v1",
    "chio.federation.issuance-bundle.v1",
    "chio.federation.revocation-publication-request.v1",
    "chio.federation.peer-pins.v1",
}
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
root = pathlib.Path(schema_registry).resolve().parents[2]
for schema_id in sorted(expected_schemas):
    schema_file = registered.get(schema_id)
    if schema_file is None:
        raise SystemExit(f"Chio schema {schema_id} is missing from registry")
    schema_path = root / schema_file
    if not schema_path.is_file():
        raise SystemExit(f"Chio schema file {schema_file} is missing on disk")
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    if "$id" not in schema or schema.get("type") != "object":
        raise SystemExit(f"Chio schema {schema_id} is not frozen as an object schema")

print("OK Chio proof package metadata")
PY

# Resolve a registered schema file (relative to the repo root) by schema id.
schema_file_for() {
  local schema_id="$1"
  python3 - "$SCHEMA_REGISTRY" "$schema_id" <<'PY'
import json
import sys

registry_path, schema_id = sys.argv[1:]
with open(registry_path, "r", encoding="utf-8") as handle:
    registry = json.load(handle)
for entry in registry.get("artifacts", []):
    if entry.get("schema") == schema_id:
        print(entry.get("schemaFile"))
        break
else:
    raise SystemExit(f"schema {schema_id} not registered")
PY
}

validate_schema() {
  local schema_id="$1"
  local document="$2"
  local schema_file
  schema_file="$(schema_file_for "$schema_id")"
  cargo run -p chio-spec-validate -- "$ROOT/$schema_file" "$document" >/dev/null
}

validate_schema "chio.attest.selective-disclosure-proof.v1" "$PROOF_FIXTURE"
validate_schema "chio.attest.proof-package.v1" "$PACKAGE_FIXTURE"
validate_schema "chio.federation.verifier-trust-bundle.v1" "$TRUST_BUNDLE_FIXTURE"
validate_schema "chio.federation.verification-context.v1" "$CONTEXT_FIXTURE"
validate_schema "chio.attest.verifier-report.v1" "$REPORT_FIXTURE"
validate_schema "chio.attest.buyer-proof-negative-fixture-corpus.v1" "$NEGATIVE_CASES_FIXTURE"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

# The offline buyer/auditor verifier lives in chio-attest-buyer-core and is
# exercised end to end (positive package acceptance, signed negative-corpus
# rejection, and committed-fixture replay) by the chio-attest-loopback and
# chio-three-vendor-example crates. Run those suites in place of the removed
# top-level CLI verify verb.
if [[ "$MODE" == "all" || "$MODE" == "negative-only" ]]; then
  cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure
  cargo test -p chio-conformance --features chio-bbs --test chio_selective_disclosure
  cargo test -p chio-attest-buyer-core
  cargo test -p chio-attest-loopback
  cargo test -p chio-three-vendor-example
  bash "$ROOT/scripts/check-chio-authority-issuance.sh"
fi
