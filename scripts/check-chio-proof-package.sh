#!/usr/bin/env bash
set -euo pipefail

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

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo_root/target}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"

fixture_dir="$repo_root/examples/chio-3vendor/fixtures"
proof_fixture="$fixture_dir/selective-disclosure-proof.json"
package_fixture="$fixture_dir/buyer-auditor-proof-package.json"
trust_bundle_fixture="$fixture_dir/verifier-trust-bundle.json"
context_fixture="$fixture_dir/verification-context.json"
report_fixture="$fixture_dir/verifier-report.json"
negative_cases_fixture="$fixture_dir/negative-cases.json"
attest_proof_schema_dir="$repo_root/spec/schemas/chio-attest/v1"
federation_schema_dir="$repo_root/spec/schemas/chio-federation/v1"
attest_schema_dir="$repo_root/spec/schemas/chio-attest/v1"
schema_registry="$repo_root/spec/schemas/registry.json"

run_chio() {
  if [[ -n "${CHIO_BIN:-}" ]]; then
    "$CHIO_BIN" "$@"
  else
    cargo run -p chio-cli --bin chio -- "$@"
  fi
}

run_spec_validate() {
  if [[ -n "${CHIO_SPEC_VALIDATE_BIN:-}" ]]; then
    "$CHIO_SPEC_VALIDATE_BIN" "$@"
  else
    cargo run -p chio-spec-validate -- "$@"
  fi
}

validate_schema() {
  run_spec_validate "$1" "$2" >/dev/null
}

run_cargo_test_filter() {
  local package="$1"
  local filter="$2"
  shift 2
  local output
  if ! output="$(cargo test -p "$package" "$filter" "$@" 2>&1)"; then
    printf '%s\n' "$output"
    return 1
  fi
  printf '%s\n' "$output"
  if ! grep -Eq 'test result: ok\. [1-9][0-9]* passed;' <<<"$output"; then
    echo "cargo test filter '$filter' in $package matched zero tests" >&2
    return 1
  fi
}

python3 - "$proof_fixture" "$package_fixture" "$trust_bundle_fixture" \
  "$context_fixture" "$report_fixture" "$negative_cases_fixture" \
  "$attest_proof_schema_dir" "$federation_schema_dir" "$attest_schema_dir" \
  "$schema_registry" <<'PY'
import base64
import json
import pathlib
import sys

(
    proof_fixture,
    package_fixture,
    trust_bundle_fixture,
    context_fixture,
    report_fixture,
    negative_cases_fixture,
    attest_proof_schema_dir,
    federation_schema_dir,
    attest_schema_dir,
    schema_registry,
) = sys.argv[1:]

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
    raise SystemExit("Chio proof package uses the wrong legacy proof schema")
if trust_bundle.get("schema") != "chio.federation.verifier-trust-bundle.v1":
    raise SystemExit("Chio verifier trust bundle uses the wrong schema")
if context.get("schema") != "chio.federation.verification-context.v1":
    raise SystemExit("Chio verification context uses the wrong schema")
if report.get("schema") != "chio.attest.verifier-report.v1":
    raise SystemExit("Chio verifier report uses the wrong legacy report schema")
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
    raise SystemExit("Trust bundle must carry a signed Chio revocation checkpoint")
if body.get("expiresAtUnixMs", 0) <= body.get("issuedAtUnixMs", 0):
    raise SystemExit("Revocation checkpoint must have a live interval")
if "signerKey" not in revocation or "signature" not in revocation:
    raise SystemExit("Revocation checkpoint must be signed")

workflow_intersection = package.get("workflowIntersection", {})
if workflow_intersection.get("schema") != "chio.attest.workflow-intersection.v1":
    raise SystemExit("Chio package must carry the legacy workflow intersection proof schema")
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
        raise SystemExit(f"Chio envelope {idx} is not strict bilateral Chio")
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

expected_schemas = {
    pathlib.Path(attest_proof_schema_dir): {
        "proof-package.schema.json": "chio.attest.proof-package.v1",
        "verifier-report.schema.json": "chio.attest.verifier-report.v1",
        "workflow-intersection.schema.json": "chio.attest.workflow-intersection.v1",
        "selective-disclosure-proof.schema.json": "chio.attest.selective-disclosure-proof.v1",
    },
    pathlib.Path(federation_schema_dir): {
        "capability-lease.schema.json": "chio.capability-lease.v1",
        "governance-receipt.schema.json": "chio.governance-receipt.v1",
        "lease-scope-binding.schema.json": "chio.federation.lease-scope-binding.v1",
        "verifier-trust-bundle.schema.json": "chio.federation.verifier-trust-bundle.v1",
        "verification-context.schema.json": "chio.federation.verification-context.v1",
        "revocation-checkpoint.schema.json": "chio.federation.revocation-checkpoint.v1",
        "authority-profile.schema.json": "chio.federation.authority-profile.v1",
        "issuance-request.schema.json": "chio.federation.issuance-request.v1",
        "issuance-bundle.schema.json": "chio.federation.issuance-bundle.v1",
        "revocation-publication-request.schema.json": "chio.federation.revocation-publication-request.v1",
        "peer-pins.schema.json": "chio.federation.peer-pins.v1",
    },
    pathlib.Path(attest_schema_dir): {
        "buyer-proof-negative-fixture-corpus.schema.json": "chio.attest.buyer-proof-negative-fixture-corpus.v1",
    },
}
registered = {entry.get("schema"): entry.get("schemaFile") for entry in registry.get("artifacts", [])}
repo_prefix = "spec/"
for schema_root, schemas in expected_schemas.items():
    for filename, schema_id in schemas.items():
        schema_path = schema_root / filename
        if not schema_path.is_file():
            raise SystemExit(f"missing Chio schema file {filename}")
        with schema_path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
        if "$id" not in schema or schema.get("type") != "object":
            raise SystemExit(f"Chio schema {filename} is not frozen as an object schema")
        expected_registry_path = repo_prefix + "/".join(schema_path.parts[-4:])
        if registered.get(schema_id) != expected_registry_path:
            raise SystemExit(f"Chio schema {schema_id} is missing from registry")

print("OK Chio proof package metadata")
PY

validate_schema "$attest_proof_schema_dir/selective-disclosure-proof.schema.json" "$proof_fixture"
validate_schema "$attest_proof_schema_dir/proof-package.schema.json" "$package_fixture"
validate_schema "$federation_schema_dir/verifier-trust-bundle.schema.json" "$trust_bundle_fixture"
validate_schema "$federation_schema_dir/verification-context.schema.json" "$context_fixture"
validate_schema "$attest_proof_schema_dir/verifier-report.schema.json" "$report_fixture"
validate_schema "$attest_schema_dir/buyer-proof-negative-fixture-corpus.schema.json" \
  "$negative_cases_fixture"

if [[ "$MODE" == "schema-only" ]]; then
  exit 0
fi

if [[ "$MODE" == "all" ]]; then
  cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure
  cargo test -p chio-conformance --features chio-bbs --test chio_selective_disclosure
  cargo test -p chio-attest-buyer-core
  run_cargo_test_filter chio-cli chio_attest_buyer --bin chio
  cargo test -p chio-three-vendor-example --lib
  cargo check -p chio-three-vendor-example --bins
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

if [[ "$MODE" == "all" ]]; then
  bash "$repo_root/scripts/check-chio-authority-issuance.sh"
  run_chio attest buyer verify-proof \
    --package "$package_fixture" \
    --trust-bundle "$trust_bundle_fixture" \
    --context "$context_fixture" \
    --report "$tmpdir/verifier-report.json"
  cmp "$report_fixture" "$tmpdir/verifier-report.json"
fi

python3 - "$package_fixture" "$trust_bundle_fixture" "$context_fixture" \
  "$negative_cases_fixture" "$tmpdir" <<'PY'
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
    index_lines.append(
        f"{case['id']}\t{case['expectedFailureCode']}\t{requires_signed}\t"
        f"{package_out}\t{trust_out}\t{context_out}\t{report_out}"
    )
out.joinpath("negative-index.tsv").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
PY

cargo run -p chio-three-vendor-example --bin generate-chio-three-vendor-fixtures -- \
  --signed-negative-dir "$tmpdir"

while IFS=$'\t' read -r case_id expected_code requires_signed package_path trust_bundle_path context_path report_path; do
  if run_chio attest buyer verify-proof \
    --package "$package_path" \
    --trust-bundle "$trust_bundle_path" \
    --context "$context_path" \
    --report "$report_path"; then
    echo "Chio CLI accepted negative case ${case_id}" >&2
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
if not report.get("checks") and expected_code not in {
    "package.claim",
    "package.schema",
    "verification.context",
    "workflow",
}:
    raise SystemExit(f"{case_id}: rejected report did not retain prior checks")
PY
done < "$tmpdir/negative-index.tsv"
