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
    echo "usage: check-chiodos-proof-package.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-proof-package.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

PROOF_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/selective-disclosure-proof.json"
PACKAGE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUST_BUNDLE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-trust-bundle.json"
CONTEXT_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verification-context.json"
REPORT_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-report.json"
NEGATIVE_CASES_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/negative-cases.json"
SCHEMA_DIR="$ROOT/spec/schemas/chiodos/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"

python3 - "$PROOF_FIXTURE" "$PACKAGE_FIXTURE" "$TRUST_BUNDLE_FIXTURE" "$CONTEXT_FIXTURE" "$REPORT_FIXTURE" "$NEGATIVE_CASES_FIXTURE" "$SCHEMA_DIR" "$SCHEMA_REGISTRY" <<'PY'
import base64
import json
import pathlib
import sys

proof_fixture, package_fixture, trust_bundle_fixture, context_fixture, report_fixture, negative_cases_fixture, schema_dir, schema_registry = sys.argv[1:]
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
if len(set(proof.get("disclosed_indices", []))) != len(proof.get("disclosed_indices", [])):
    raise SystemExit("Chiodos BBS fixture disclosed indices must be unique")
if package.get("schema") != "chio.chiodos.proof-package.v1":
    raise SystemExit("Chiodos proof package uses the wrong schema")
if trust_bundle.get("schema") != "chio.chiodos.verifier-trust-bundle.v1":
    raise SystemExit("Chiodos verifier trust bundle uses the wrong schema")
if context.get("schema") != "chio.chiodos.verification-context.v1":
    raise SystemExit("Chiodos verification context uses the wrong schema")
if report.get("schema") != "chio.chiodos.verifier-report.v1":
    raise SystemExit("Chiodos verifier report uses the wrong schema")
if not report.get("accepted"):
    raise SystemExit("Chiodos verifier report is not accepted")
for field in ("packageSha256", "trustBundleSha256", "contextSha256", "revocationEpochHeight"):
    if field not in report:
        raise SystemExit(f"Chiodos verifier report is missing {field}")
if not all(check.get("code") for check in report.get("checks", [])):
    raise SystemExit("Chiodos verifier report checks must carry stable codes")

claims = package.get("claims", {})
if not claims.get("bbsRevealSet"):
    raise SystemExit("Chiodos package must claim real BBS reveal-set support")
for unsupported in ("hiddenRangePredicates", "vcDataIntegrityBbs", "zkvm"):
    if claims.get(unsupported):
        raise SystemExit(f"Chiodos package must not claim {unsupported}")
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
    raise SystemExit("Chiodos trust bundle must contain one fixture BBS issuer")
issuer = issuers[0]
if issuer.get("issuerFingerprint") != proof.get("issuer_fingerprint"):
    raise SystemExit("Trust bundle issuer fingerprint does not match proof issuer")
if issuer.get("publicKeyHex") != proof.get("issuer_public_key_hex"):
    raise SystemExit("Trust bundle issuer key does not match proof issuer key")

revocation = trust_bundle.get("revocation", {})
body = revocation.get("body", {})
if body.get("schema") != "chio.chiodos.revocation-checkpoint.v1":
    raise SystemExit("Trust bundle must carry a signed revocation checkpoint")
if body.get("expiresAtUnixMs", 0) <= body.get("issuedAtUnixMs", 0):
    raise SystemExit("Revocation checkpoint must have a live interval")
if "signerKey" not in revocation or "signature" not in revocation:
    raise SystemExit("Revocation checkpoint must be signed")

workflow_intersection = package.get("workflowIntersection", {})
if workflow_intersection.get("schema") != "chio.chiodos-workflow-intersection.v1":
    raise SystemExit("Chiodos package must carry workflow intersection v1")
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
    raise SystemExit("Chiodos package must contain three bilateral envelopes")
for idx, envelope in enumerate(package.get("bilateralEnvelopes", [])):
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        raise SystemExit(f"Chiodos envelope {idx} has no payload")
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
if len(package.get("leaseScopeBindings", [])) != 3:
    raise SystemExit("Chiodos package must contain three lease scope bindings")
for binding in package.get("leaseScopeBindings", []):
    if binding.get("schema") != "chio.chiodos-lease-scope-binding.v1":
        raise SystemExit("Chiodos lease scope binding uses the wrong schema")
if len(package.get("governanceReceipts", [])) != 1:
    raise SystemExit("Chiodos package must contain one destructive governance receipt")

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

if negative_cases.get("schema") != "chio.chiodos.negative-fixture-corpus.v1":
    raise SystemExit("Chiodos negative corpus uses the wrong schema")
if len(negative_cases.get("cases", [])) < 14:
    raise SystemExit("Chiodos negative corpus must cover verifier trust, context, and package mutations")

expected_schemas = {
    "capability-lease.schema.json": "chio.capability-lease.v1",
    "governance-receipt.schema.json": "chio.governance-receipt.v1",
    "lease-scope-binding.schema.json": "chio.chiodos-lease-scope-binding.v1",
    "proof-package.schema.json": "chio.chiodos.proof-package.v1",
    "verifier-trust-bundle.schema.json": "chio.chiodos.verifier-trust-bundle.v1",
    "workflow-intersection.schema.json": "chio.chiodos-workflow-intersection.v1",
    "trusted-issuer-registry.schema.json": "chio.chiodos.trusted-issuer-registry.v1",
    "selective-disclosure-proof.schema.json": "chio.selective-disclosure-proof.v1",
    "verifier-report.schema.json": "chio.chiodos.verifier-report.v1",
    "revocation-checkpoint.schema.json": "chio.chiodos.revocation-checkpoint.v1",
    "verification-context.schema.json": "chio.chiodos.verification-context.v1",
    "negative-fixture-corpus.schema.json": "chio.chiodos.negative-fixture-corpus.v1",
    "authority-profile.schema.json": "chio.chiodos.authority-profile.v1",
    "issuance-request.schema.json": "chio.chiodos.issuance-request.v1",
    "issuance-bundle.schema.json": "chio.chiodos.issuance-bundle.v1",
    "revocation-publication-request.schema.json": "chio.chiodos.revocation-publication-request.v1",
    "peer-pins.schema.json": "chio.chiodos.peer-pins.v1",
}
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
schema_root = pathlib.Path(schema_dir)
for filename, schema_id in expected_schemas.items():
    schema_path = schema_root / filename
    if not schema_path.is_file():
        raise SystemExit(f"missing Chiodos schema file {filename}")
    with schema_path.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    if "$id" not in schema or schema.get("type") != "object":
        raise SystemExit(f"Chiodos schema {filename} is not frozen as an object schema")
    if registered.get(schema_id) != f"spec/schemas/chiodos/v1/{filename}":
        raise SystemExit(f"Chiodos schema {schema_id} is missing from registry")

print("OK Chiodos proof package metadata")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

validate_schema "$SCHEMA_DIR/selective-disclosure-proof.schema.json" "$PROOF_FIXTURE"
validate_schema "$SCHEMA_DIR/proof-package.schema.json" "$PACKAGE_FIXTURE"
validate_schema "$SCHEMA_DIR/verifier-trust-bundle.schema.json" "$TRUST_BUNDLE_FIXTURE"
validate_schema "$SCHEMA_DIR/verification-context.schema.json" "$CONTEXT_FIXTURE"
validate_schema "$SCHEMA_DIR/verifier-report.schema.json" "$REPORT_FIXTURE"
validate_schema "$SCHEMA_DIR/negative-fixture-corpus.schema.json" "$NEGATIVE_CASES_FIXTURE"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

if [[ "$MODE" == "all" ]]; then
  cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure
  cargo test -p chio-conformance --features chiodos-bbs --test chiodos_selective_disclosure
  cargo test -p chio-chiodos
  cargo test -p chio-cli chiodos
  cargo test -p chiodos-three-vendor-example
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if [[ "$MODE" == "all" ]]; then
  bash "$ROOT/scripts/check-chiodos-authority-issuance.sh"
  cargo run -p chio-cli -- chiodos verify \
      --package "$PACKAGE_FIXTURE" \
      --trust-bundle "$TRUST_BUNDLE_FIXTURE" \
      --context "$CONTEXT_FIXTURE" \
      --report "$tmpdir/verifier-report.json"
  cmp "$REPORT_FIXTURE" "$tmpdir/verifier-report.json"
fi

python3 - "$PACKAGE_FIXTURE" "$TRUST_BUNDLE_FIXTURE" "$CONTEXT_FIXTURE" "$NEGATIVE_CASES_FIXTURE" "$tmpdir" <<'PY'
import copy
import json
import pathlib
import sys

package_path, trust_bundle_path, context_path, cases_path, out_dir = sys.argv[1:]
with open(package_path, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(trust_bundle_path, "r", encoding="utf-8") as handle:
    trust_bundle = json.load(handle)
with open(context_path, "r", encoding="utf-8") as handle:
    context = json.load(handle)
with open(cases_path, "r", encoding="utf-8") as handle:
    corpus = json.load(handle)
out = pathlib.Path(out_dir)

def select(root, path):
    value = root
    for part in path:
        value = value[part]
    return value

def apply_mutation(root, mutation):
    op = mutation["op"]
    path = mutation["path"]
    if op == "set":
        parent = select(root, path[:-1]) if path[:-1] else root
        parent[path[-1]] = mutation["value"]
        return
    if op == "removeWhere":
        target = select(root, path)
        field = mutation["field"]
        value = mutation["value"]
        parent = select(root, path[:-1]) if path[:-1] else root
        parent[path[-1]] = [item for item in target if item.get(field) != value]
        return
    raise SystemExit(f"unsupported mutation op: {op}")

index_lines = []
for case in corpus["cases"]:
    mutated_package = copy.deepcopy(package)
    mutated_trust = copy.deepcopy(trust_bundle)
    mutated_context = copy.deepcopy(context)
    if case["target"] == "package":
        target = mutated_package
    elif case["target"] == "trustBundle":
        target = mutated_trust
    elif case["target"] == "context":
        target = mutated_context
    else:
        raise SystemExit(f"unsupported target: {case['target']}")
    apply_mutation(target, case["mutation"])
    package_out = out / f"{case['id']}-package.json"
    trust_out = out / f"{case['id']}-trust-bundle.json"
    context_out = out / f"{case['id']}-context.json"
    report_out = out / f"{case['id']}-report.json"
    package_out.write_text(json.dumps(mutated_package, indent=2) + "\n", encoding="utf-8")
    trust_out.write_text(json.dumps(mutated_trust, indent=2) + "\n", encoding="utf-8")
    context_out.write_text(json.dumps(mutated_context, indent=2) + "\n", encoding="utf-8")
    requires_signed = "1" if case.get("requiresSignedMutation") else "0"
    index_lines.append(f"{case['id']}\t{case['expectedFailureCode']}\t{requires_signed}\t{package_out}\t{trust_out}\t{context_out}\t{report_out}")
(out / "negative-index.tsv").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
PY

cargo run -p chiodos-three-vendor-example --bin generate-chiodos-proof-package -- \
    --signed-negative-dir "$tmpdir"

while IFS=$'\t' read -r case_id expected_code requires_signed package_path trust_bundle_path context_path report_path; do
    if cargo run -p chio-cli -- chiodos verify \
        --package "$package_path" \
        --trust-bundle "$trust_bundle_path" \
        --context "$context_path" \
        --report "$report_path"; then
        echo "Chiodos CLI accepted negative case ${case_id}" >&2
        exit 1
    fi
    python3 - "$case_id" "$expected_code" "$requires_signed" "$report_path" <<'PY'
import json
import sys

case_id, expected_code, requires_signed, report_path = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("accepted"):
    raise SystemExit(f"{case_id}: rejected report was accepted")
failure = report.get("failure") or {}
if failure.get("code") != expected_code:
    raise SystemExit(f"{case_id}: expected failure {expected_code}, got {failure.get('code')}")
if "phase" not in failure:
    raise SystemExit(f"{case_id}: failure did not include a phase")
if requires_signed == "1" and "workflow signature is invalid" in failure.get("detail", ""):
    raise SystemExit(f"{case_id}: signed semantic case failed before semantic verification")
if not report.get("checks") and expected_code not in {"package.claim", "package.schema", "verification.context", "workflow"}:
    raise SystemExit(f"{case_id}: rejected report did not retain prior checks")
PY
done < "$tmpdir/negative-index.tsv"
