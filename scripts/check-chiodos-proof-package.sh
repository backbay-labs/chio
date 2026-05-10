#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROOF_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/selective-disclosure-proof.json"
PACKAGE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/buyer-auditor-proof-package.json"
TRUST_BUNDLE_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-trust-bundle.json"
REPORT_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/verifier-report.json"
NEGATIVE_CASES_FIXTURE="$ROOT/examples/chiodos-3vendor/fixtures/negative-cases.json"
SCHEMA_DIR="$ROOT/spec/schemas/chiodos/v1"
SCHEMA_REGISTRY="$ROOT/spec/schemas/registry.json"

python3 - "$PROOF_FIXTURE" "$PACKAGE_FIXTURE" "$TRUST_BUNDLE_FIXTURE" "$REPORT_FIXTURE" "$NEGATIVE_CASES_FIXTURE" "$SCHEMA_DIR" "$SCHEMA_REGISTRY" <<'PY'
import json
import pathlib
import sys

proof_fixture, package_fixture, trust_bundle_fixture, report_fixture, negative_cases_fixture, schema_dir, schema_registry = sys.argv[1:]
with open(proof_fixture, "r", encoding="utf-8") as handle:
    proof = json.load(handle)
with open(package_fixture, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(trust_bundle_fixture, "r", encoding="utf-8") as handle:
    trust_bundle = json.load(handle)
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
if package.get("schema") != "chio.chiodos.proof-package.v1":
    raise SystemExit("Chiodos proof package uses the wrong schema")
if trust_bundle.get("schema") != "chio.chiodos.verifier-trust-bundle.v1":
    raise SystemExit("Chiodos verifier trust bundle uses the wrong schema")
if report.get("schema") != "chio.chiodos.verifier-report.v1":
    raise SystemExit("Chiodos verifier report uses the wrong schema")
if not report.get("accepted"):
    raise SystemExit("Chiodos verifier report is not accepted")
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
issuers = trust_bundle.get("trustedBbsIssuers", [])
if len(issuers) != 1:
    raise SystemExit("Chiodos trust bundle must contain one fixture BBS issuer")
issuer = issuers[0]
if issuer.get("issuerFingerprint") != proof.get("issuer_fingerprint"):
    raise SystemExit("Trust bundle issuer fingerprint does not match proof issuer")
if issuer.get("publicKeyHex") != proof.get("issuer_public_key_hex"):
    raise SystemExit("Trust bundle issuer key does not match proof issuer key")
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
if len(trust_bundle.get("actionClasses", [])) != 3:
    raise SystemExit("Trust bundle must own three action-class entries")
if len(trust_bundle.get("workflowIntersections", [])) != 1:
    raise SystemExit("Trust bundle must trust one workflow intersection hash")
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
if negative_cases.get("schema") != "chio.chiodos.negative-fixture-corpus.v1":
    raise SystemExit("Chiodos negative corpus uses the wrong schema")
if len(negative_cases.get("cases", [])) < 6:
    raise SystemExit("Chiodos negative corpus must cover verifier trust and package mutations")

expected_schemas = {
    "proof-package.schema.json": "chio.chiodos.proof-package.v1",
    "verifier-trust-bundle.schema.json": "chio.chiodos.verifier-trust-bundle.v1",
    "workflow-intersection.schema.json": "chio.chiodos-workflow-intersection.v1",
    "trusted-issuer-registry.schema.json": "chio.chiodos.trusted-issuer-registry.v1",
    "selective-disclosure-proof.schema.json": "chio.selective-disclosure-proof.v1",
    "verifier-report.schema.json": "chio.chiodos.verifier-report.v1",
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

cargo test -p chio-selective-disclosure --features bbs --test bbs_selective_disclosure
cargo test -p chio-conformance --features chiodos-bbs --test chiodos_selective_disclosure
cargo test -p chio-chiodos
cargo test -p chio-cli chiodos
cargo test -p chiodos-three-vendor-example

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
cargo run -p chio-cli -- chiodos verify \
    --package "$PACKAGE_FIXTURE" \
    --trust-bundle "$TRUST_BUNDLE_FIXTURE" \
    --report "$tmpdir/verifier-report.json"
cmp "$REPORT_FIXTURE" "$tmpdir/verifier-report.json"

python3 - "$PACKAGE_FIXTURE" "$TRUST_BUNDLE_FIXTURE" "$NEGATIVE_CASES_FIXTURE" "$tmpdir" <<'PY'
import copy
import json
import pathlib
import sys

package_path, trust_bundle_path, cases_path, out_dir = sys.argv[1:]
with open(package_path, "r", encoding="utf-8") as handle:
    package = json.load(handle)
with open(trust_bundle_path, "r", encoding="utf-8") as handle:
    trust_bundle = json.load(handle)
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
    target = mutated_package if case["target"] == "package" else mutated_trust
    apply_mutation(target, case["mutation"])
    package_out = out / f"{case['id']}-package.json"
    trust_out = out / f"{case['id']}-trust-bundle.json"
    report_out = out / f"{case['id']}-report.json"
    package_out.write_text(json.dumps(mutated_package, indent=2) + "\n", encoding="utf-8")
    trust_out.write_text(json.dumps(mutated_trust, indent=2) + "\n", encoding="utf-8")
    index_lines.append(f"{case['id']}\t{case['expectedFailureCode']}\t{package_out}\t{trust_out}\t{report_out}")
(out / "negative-index.tsv").write_text("\n".join(index_lines) + "\n", encoding="utf-8")
PY

while IFS=$'\t' read -r case_id expected_code package_path trust_bundle_path report_path; do
    if cargo run -p chio-cli -- chiodos verify \
        --package "$package_path" \
        --trust-bundle "$trust_bundle_path" \
        --report "$report_path"; then
        echo "Chiodos CLI accepted negative case ${case_id}" >&2
        exit 1
    fi
    python3 - "$case_id" "$expected_code" "$report_path" <<'PY'
import json
import sys

case_id, expected_code, report_path = sys.argv[1:]
with open(report_path, "r", encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("accepted"):
    raise SystemExit(f"{case_id}: rejected report was accepted")
failure = report.get("failure") or {}
if failure.get("code") != expected_code:
    raise SystemExit(f"{case_id}: expected failure {expected_code}, got {failure.get('code')}")
PY
done < "$tmpdir/negative-index.tsv"
