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
    echo "usage: check-chiodos-runtime-spine.sh [--schema-only|--negative-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-runtime-spine.sh [--schema-only|--negative-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

SCHEMA_DIR="$ROOT/spec/schemas/chiodos/v1"
LOOPBACK_NOW_UNIX_MS=1766000001000
tmpdir="$(mktemp -d)"
trap 'if [[ "${CHIODOS_KEEP_TMP:-0}" == "1" ]]; then echo "kept tmpdir: $tmpdir" >&2; else rm -rf "$tmpdir"; fi' EXIT

RUNTIME_SPINE_FIXTURE_DIR="$ROOT/examples/chiodos-3vendor/fixtures/runtime-spine"
copy_runtime_spine_fixture() {
  local name="$1"
  cp "$RUNTIME_SPINE_FIXTURE_DIR/$name" "$tmpdir/$name"
}

copy_runtime_spine_fixture "profile.json"
copy_runtime_spine_fixture "request.json"
copy_runtime_spine_fixture "bundle.json"
copy_runtime_spine_fixture "verifier.seed"
copy_runtime_spine_fixture "runtime-trust-body.json"
copy_runtime_spine_fixture "runtime-trust-schema-only.json"
copy_runtime_spine_fixture "trusted-verifiers-schema-only.json"
copy_runtime_spine_fixture "scenario.json"
copy_runtime_spine_fixture "pheromone-query-report.json"
copy_runtime_spine_fixture "runtime-peer-weights-body.json"
copy_runtime_spine_fixture "runtime-policy-body.json"
copy_runtime_spine_fixture "runtime-step-evidence.json"
copy_runtime_spine_fixture "runtime-proof-regeneration-report.json"
copy_runtime_spine_fixture "runtime-evidence-manifest.json"
copy_runtime_spine_fixture "runtime-proof-regeneration-input.json"
copy_runtime_spine_fixture "runtime-proof-parity-report.json"

python3 - "$tmpdir/scenario.json" <<'PY'
import hashlib
import json
import base64
import sys

path = sys.argv[1]
scenario = json.load(open(path, "r", encoding="utf-8"))
steps = [
    (
        "did:chio:vendor-a",
        "lease-vendor-a-read",
        "vendor-a.files",
        "read_refund_case",
        {
            "caseRef": "refund-250",
            "tool": "read_refund_case",
            "workflowId": "wf-chiodos-refund-001",
        },
    ),
    (
        "did:chio:vendor-b",
        "lease-vendor-b-kyc",
        "vendor-b.kyc",
        "verify_customer",
        {
            "caseRef": "refund-250",
            "tool": "verify_customer",
            "workflowId": "wf-chiodos-refund-001",
        },
    ),
    (
        "did:chio:vendor-c",
        "lease-vendor-c-refund",
        "vendor-c.payments",
        "stage_refund",
        {
            "caseRef": "refund-250",
            "tool": "stage_refund",
            "workflowId": "wf-chiodos-refund-001",
        },
    ),
]
for step, (kernel, capability, server, tool, arguments) in zip(scenario["steps"], steps):
    digest = hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    step["arguments"] = arguments
    step["admissionProfile"]["localKernelId"] = kernel
    step["admissionProfile"]["issuedAtUnixMs"] = 1700000000000
    step["admissionProfile"]["expiresAtUnixMs"] = 1900000000000
    step["admissionBundle"]["binding"]["capabilityId"] = capability
    step["admissionBundle"]["binding"]["serverId"] = server
    step["admissionBundle"]["binding"]["toolName"] = tool
    step["admissionBundle"]["binding"]["toolArgsSha256"] = digest
    step["admissionBundle"]["binding"]["hostKernelId"] = kernel
    step["admissionBundle"]["leaseId"] = capability
    step["request"]["capabilityId"] = capability
    step["request"]["serverId"] = server
    step["request"]["toolName"] = tool
    step["request"]["toolArgsSha256"] = digest
    step["request"]["hostKernelId"] = kernel
with open(path, "w", encoding="utf-8") as fh:
    json.dump(scenario, fh, indent=2)
    fh.write("\n")
PY

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

run_schema_checks() {
  validate_schema "$SCHEMA_DIR/runtime-admission-profile.schema.json" "$tmpdir/profile.json"
  validate_schema "$SCHEMA_DIR/runtime-admission-bundle.schema.json" "$tmpdir/bundle.json"
  validate_schema "$SCHEMA_DIR/runtime-verifier-trust-bundle.schema.json" \
    "$tmpdir/runtime-trust-schema-only.json"
  validate_schema "$SCHEMA_DIR/runtime-trusted-verifiers.schema.json" \
    "$tmpdir/trusted-verifiers-schema-only.json"
  validate_schema "$SCHEMA_DIR/runtime-step-evidence.schema.json" \
    "$tmpdir/runtime-step-evidence.json"
  validate_schema "$SCHEMA_DIR/runtime-evidence-manifest.schema.json" \
    "$tmpdir/runtime-evidence-manifest.json"
  validate_schema "$SCHEMA_DIR/runtime-proof-regeneration-input.schema.json" \
    "$tmpdir/runtime-proof-regeneration-input.json"
  validate_schema "$SCHEMA_DIR/runtime-proof-regeneration-report.schema.json" \
    "$tmpdir/runtime-proof-regeneration-report.json"
  validate_schema "$SCHEMA_DIR/runtime-proof-parity-report.schema.json" \
    "$tmpdir/runtime-proof-parity-report.json"
}

run_positive_checks() {
  cargo run -p chio-cli --bin chio -- chiodos runtime sign-trust-input \
    --body "$tmpdir/runtime-trust-body.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/runtime-trust-input.json"
  validate_schema "$SCHEMA_DIR/runtime-verifier-trust-bundle.schema.json" \
    "$tmpdir/runtime-trust-input.json"
  python3 - "$tmpdir/runtime-trust-input.json" "$tmpdir/trusted-verifiers.json" <<'PY'
import json
import sys
signed = json.load(open(sys.argv[1], "r", encoding="utf-8"))
trusted = {
    "schema": "chio.chiodos.runtime-trusted-verifiers.v1",
    "verifierKeys": [
        {
            "verifierId": signed["body"]["verifierId"],
            "keyId": signed["body"]["keyId"],
            "publicKey": signed["signerKey"],
            "validFromUnixMs": 1800000000000,
            "validUntilUnixMs": 1800003600000,
            "status": "active",
        }
    ],
}
json.dump(trusted, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
  validate_schema "$SCHEMA_DIR/runtime-trusted-verifiers.schema.json" \
    "$tmpdir/trusted-verifiers.json"
  cargo run -p chio-cli --bin chio -- chiodos runtime peer-weights hash \
    --body "$tmpdir/runtime-peer-weights-body.json" \
    --out "$tmpdir/runtime-peer-weights.sha256"
  python3 - "$tmpdir/runtime-policy-body.json" "$tmpdir/runtime-peer-weights.sha256" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
peer_hash = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").strip()
body = path.read_text(encoding="utf-8").replace("PEER_WEIGHTS_SHA256", peer_hash)
path.write_text(body, encoding="utf-8")
PY
  cargo run -p chio-cli --bin chio -- chiodos runtime peer-weights sign \
    --body "$tmpdir/runtime-peer-weights-body.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/runtime-peer-weights.json"
  cargo run -p chio-cli --bin chio -- chiodos runtime policy sign \
    --body "$tmpdir/runtime-policy-body.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/runtime-policy.json"
  cargo run -p chio-cli --bin chio -- chiodos runtime pheromone sign-query-report \
    --body "$tmpdir/pheromone-query-report.json" \
    --signing-seed-file "$tmpdir/verifier.seed" \
    --out "$tmpdir/pheromone-query-report.signed.json"
  validate_schema "$SCHEMA_DIR/runtime-peer-weights.schema.json" \
    "$tmpdir/runtime-peer-weights.json"
  validate_schema "$SCHEMA_DIR/runtime-pheromone-policy.schema.json" \
    "$tmpdir/runtime-policy.json"
  cargo run -p chio-cli --bin chio -- chiodos runtime admit \
    --request "$tmpdir/request.json" \
    --admission-profile "$tmpdir/profile.json" \
    --admission-bundle "$tmpdir/bundle.json" \
    --runtime-trust-input "$tmpdir/runtime-trust-input.json" \
    --trusted-verifiers "$tmpdir/trusted-verifiers.json" \
    --pheromone-query-report "$tmpdir/pheromone-query-report.signed.json" \
    --runtime-pheromone-policy "$tmpdir/runtime-policy.json" \
    --runtime-peer-weights "$tmpdir/runtime-peer-weights.json" \
    --store "$tmpdir/admission-store.json" \
    --trust-floor-state "$tmpdir/runtime-trust-floor-live.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/admission-report.json"
  validate_schema "$SCHEMA_DIR/runtime-admission-report.schema.json" "$tmpdir/admission-report.json"
  validate_schema "$SCHEMA_DIR/runtime-trust-floor-state.schema.json" \
    "$tmpdir/runtime-trust-floor-live.json"
  python3 - "$tmpdir/admission-report.json" \
    "$tmpdir/admission-store.json" \
    "$tmpdir/runtime-trust-floor-live.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
admission_store = json.load(open(sys.argv[2], "r", encoding="utf-8"))
trust_floor_state = json.load(open(sys.argv[3], "r", encoding="utf-8"))
if report.get("schema") != "chio.chiodos.runtime-admission-report.v1":
    raise SystemExit("runtime admission report schema mismatch")
if not report.get("accepted"):
    raise SystemExit("runtime admission report was not accepted")
if admission_store.get("schema") != "chio.chiodos.runtime-admission-store.v1":
    raise SystemExit("runtime admission store schema mismatch")
if len(admission_store.get("bundles", [])) != 1:
    raise SystemExit("runtime admission store did not retain admission bundle")
if len(admission_store.get("consumedLeaseIds", [])) != 1:
    raise SystemExit("runtime admission store did not retain lease replay fence")
if admission_store.get("trustFloors"):
    raise SystemExit("runtime admission store leaked separate trust-floor state")
if trust_floor_state.get("schema") != "chio.chiodos.runtime-trust-floor-state.v1":
    raise SystemExit("runtime trust-floor state schema mismatch")
if len(trust_floor_state.get("entries", [])) != 1:
    raise SystemExit("runtime trust-floor state did not persist verifier floor")
metadata = report.get("receiptMetadata", {}).get("chiodos_runtime", {})
if metadata.get("admission_id") != "adm-live-1":
    raise SystemExit("runtime admission metadata did not bind admission id")
if not metadata.get("destructive"):
    raise SystemExit("runtime admission metadata did not record destructive step")
advisory = report.get("pheromoneAdvisory")
if not advisory or not advisory.get("observeOnly"):
    raise SystemExit("runtime admission report did not record observe-only pheromone advisory")
if metadata.get("pheromone_advisory", {}).get("observeOnly") is not True:
    raise SystemExit("runtime admission metadata did not preserve observe-only pheromone advisory")
PY
  cargo run -p chio-cli --bin chio -- chiodos runtime run-loopback \
    --scenario "$tmpdir/scenario.json" \
    --store-dir "$tmpdir/loopback-store" \
    --now-unix-ms "$LOOPBACK_NOW_UNIX_MS" \
    --out-dir "$tmpdir/loopback-out"
  validate_schema "$SCHEMA_DIR/runtime-workflow-run-report.schema.json" \
    "$tmpdir/loopback-out/runtime-run-report.json"
  validate_schema "$SCHEMA_DIR/buyer-attestation-packet.schema.json" \
    "$tmpdir/loopback-out/buyer-attestation-packet.json"
  validate_schema "$SCHEMA_DIR/proof-package.schema.json" \
    "$tmpdir/loopback-out/proof-package.json"
  validate_schema "$SCHEMA_DIR/runtime-proof-regeneration-report.schema.json" \
    "$tmpdir/loopback-out/proof-regeneration-report.json"
  validate_schema "$SCHEMA_DIR/runtime-evidence-manifest.schema.json" \
    "$tmpdir/loopback-out/runtime-evidence-manifest.json"
  validate_schema "$SCHEMA_DIR/runtime-proof-regeneration-input.schema.json" \
    "$tmpdir/loopback-out/runtime-proof-regeneration-input.json"
  validate_schema "$SCHEMA_DIR/runtime-proof-parity-report.schema.json" \
    "$tmpdir/loopback-out/runtime-proof-parity-report.json"
  cargo run -p chio-cli --bin chio -- chiodos verify \
    --package "$tmpdir/loopback-out/proof-package.json" \
    --trust-bundle "$tmpdir/loopback-out/verifier-trust-bundle.json" \
    --context "$tmpdir/loopback-out/verification-context.json" \
    --report "$tmpdir/loopback-out/verifier-report-rerun.json"
  cargo run -p chio-cli --bin chio -- chiodos buyer package \
    --run-output "$tmpdir/loopback-out" \
    --out "$tmpdir/loopback-out/buyer-review-package.json"
  validate_schema "$SCHEMA_DIR/buyer-attestation-review-package.schema.json" \
    "$tmpdir/loopback-out/buyer-review-package.json"
  cargo run -p chio-cli --bin chio -- chiodos buyer verify \
    --package "$tmpdir/loopback-out/buyer-review-package.json" \
    --trust-bundle "$tmpdir/loopback-out/verifier-trust-bundle.json" \
    --context "$tmpdir/loopback-out/verification-context.json" \
    --report "$tmpdir/loopback-out/buyer-review-report.json"
  validate_schema "$SCHEMA_DIR/buyer-attestation-review-report.schema.json" \
    "$tmpdir/loopback-out/buyer-review-report.json"
  python3 - "$tmpdir/loopback-out/runtime-run-report.json" \
    "$tmpdir/loopback-out/proof-regeneration-report.json" \
    "$tmpdir/loopback-out/runtime-proof-parity-report.json" \
    "$tmpdir/loopback-out/runtime-evidence-manifest.json" \
    "$tmpdir/loopback-out/runtime-proof-regeneration-input.json" \
    "$tmpdir/loopback-out/buyer-review-report.json" \
    "$tmpdir/loopback-out/proof-package.json" <<'PY'
import hashlib
import json
import base64
import sys
workflow = json.load(open(sys.argv[1], "r", encoding="utf-8"))
proof = json.load(open(sys.argv[2], "r", encoding="utf-8"))
parity = json.load(open(sys.argv[3], "r", encoding="utf-8"))
manifest = json.load(open(sys.argv[4], "r", encoding="utf-8"))
proof_input = json.load(open(sys.argv[5], "r", encoding="utf-8"))
buyer_review = json.load(open(sys.argv[6], "r", encoding="utf-8"))
proof_package = json.load(open(sys.argv[7], "r", encoding="utf-8"))
if not workflow.get("accepted"):
    raise SystemExit("runtime workflow report was not accepted")
if not workflow.get("stepEvidence"):
    raise SystemExit("runtime workflow report did not carry step evidence")
if workflow.get("proofRegenerationReportSha256") is None:
    raise SystemExit("runtime workflow report did not bind proof regeneration report")
if proof.get("schema") != "chio.chiodos.runtime-proof-regeneration-report.v1":
    raise SystemExit("runtime proof regeneration report schema mismatch")
if not proof.get("accepted"):
    raise SystemExit(f"runtime proof regeneration was not accepted: {proof.get('failureCode')}")
if proof.get("failureCode") == "runtime_proof_semantic_regeneration_pending":
    raise SystemExit("runtime proof regeneration still reports pending")
if not proof.get("proofPackageSha256") or not proof.get("verifierReportSha256"):
    raise SystemExit("runtime proof regeneration did not bind proof package and verifier hashes")
if "runtime_kernel_receipts.captured" not in proof.get("checks", []):
    raise SystemExit("runtime proof regeneration did not capture live kernel receipts")
if "runtime_kernel_receipts.fixture_compatibility_path" in proof.get("checks", []):
    raise SystemExit("runtime proof regeneration used fixture compatibility path")
if "runtime_treaty_buyer_closure.bound" not in proof.get("checks", []):
    raise SystemExit("runtime proof regeneration did not bind treaty buyer closure")
if not parity.get("accepted"):
    raise SystemExit(f"runtime proof parity was not accepted: {parity.get('failureCode')}")
required_parity_fields = {
    "workflow_step_semantics",
    "workflow_step_class_bindings",
    "tool_receipt_semantics",
    "bilateral_dsse_predicate_semantics",
    "lease_scope_semantics",
    "governance_authorization_presence",
}
missing_parity_fields = required_parity_fields - set(parity.get("comparedFields", []))
if missing_parity_fields:
    raise SystemExit(f"runtime proof parity skipped semantic fields: {sorted(missing_parity_fields)}")
manifest_canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
manifest_hash = hashlib.sha256(manifest_canonical).hexdigest()
if proof_input.get("evidenceManifestSha256") != manifest_hash:
    raise SystemExit("runtime proof regeneration input did not bind evidence manifest")
if proof_input.get("workflowRunReportSha256") != manifest.get("workflowRunReportSha256"):
    raise SystemExit("runtime proof regeneration input did not bind workflow report hash")
if proof_input.get("sourceRecords") != proof.get("sourceRecords"):
    raise SystemExit("runtime proof regeneration input source records did not match proof report")
if not buyer_review.get("accepted"):
    raise SystemExit(f"buyer review rejected runtime closure: {buyer_review.get('failureCode')}")
required_buyer_checks = {
    "chiodos_buyer_review.runtime_reports_bound",
    "chiodos_buyer_review.strict_dsse_treaty_bound",
    "chiodos_buyer_review.proof_verifier_accepted",
}
seen_buyer_checks = {
    check.get("code")
    for check in buyer_review.get("checks", [])
    if check.get("passed")
}
missing_buyer_checks = required_buyer_checks - seen_buyer_checks
if missing_buyer_checks:
    raise SystemExit(f"buyer review skipped closure checks: {sorted(missing_buyer_checks)}")
has_treaty_dsse = False
for envelope in proof_package.get("bilateralEnvelopes", []):
    payload = envelope.get("payload")
    if not payload:
        continue
    statement = json.loads(base64.b64decode(payload).decode("utf-8"))
    predicate = statement.get("predicate", {})
    treaty_binding_ref = predicate.get("treaty_binding_ref") or predicate.get("treatyBindingRef")
    consistency_model = predicate.get("consistency_model") or predicate.get("consistencyModel")
    if treaty_binding_ref:
        has_treaty_dsse = True
        if consistency_model != "totally_ordered":
            raise SystemExit("treaty DSSE did not carry ordered consistency")
if not has_treaty_dsse:
    raise SystemExit("proof package did not carry a treaty-bound bilateral DSSE")
for path in workflow.get("evidencePaths", []):
    if path in {"regenerated-proof-package.json", "pheromone-deposit.json"}:
        raise SystemExit(f"placeholder aggregate evidence path survived: {path}")
PY
  if grep -R "runtime_proof_semantic_regeneration_pending" "$tmpdir/loopback-out" >/dev/null; then
    echo "runtime proof parity gate found pending regeneration marker" >&2
    exit 1
  fi
}

run_negative_checks() {
  if cargo run -p chio-cli --bin chio -- chiodos runtime admit \
    --request "$tmpdir/request.json" \
    --admission-profile "$tmpdir/profile.json" \
    --admission-bundle "$tmpdir/bundle.json" \
    --runtime-trust-input "$tmpdir/runtime-trust-input.json" \
    --trusted-verifiers "$tmpdir/trusted-verifiers.json" \
    --pheromone-query-report "$tmpdir/pheromone-query-report.signed.json" \
    --runtime-pheromone-policy "$tmpdir/runtime-policy.json" \
    --runtime-peer-weights "$tmpdir/runtime-peer-weights.json" \
    --store "$tmpdir/admission-store.json" \
    --now-unix-ms 1800000002000 \
    --report "$tmpdir/replay-report.json"; then
    echo "expected destructive lease replay to fail" >&2
    exit 1
  fi
  validate_schema "$SCHEMA_DIR/runtime-admission-report.schema.json" "$tmpdir/replay-report.json"
  python3 - "$tmpdir/replay-report.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
if report.get("accepted"):
    raise SystemExit("replay report unexpectedly accepted")
if report.get("failureCode") != "destructive_lease_replay":
    raise SystemExit(f"wrong replay failure code: {report.get('failureCode')}")
PY

  python3 - "$tmpdir/request.json" "$tmpdir/request-mismatch.json" <<'PY'
import json
import sys
request = json.load(open(sys.argv[1], "r", encoding="utf-8"))
request["toolArgsSha256"] = "d" * 64
json.dump(request, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
  if cargo run -p chio-cli --bin chio -- chiodos runtime admit \
    --request "$tmpdir/request-mismatch.json" \
    --admission-profile "$tmpdir/profile.json" \
    --admission-bundle "$tmpdir/bundle.json" \
    --runtime-trust-input "$tmpdir/runtime-trust-input.json" \
    --trusted-verifiers "$tmpdir/trusted-verifiers.json" \
    --pheromone-query-report "$tmpdir/pheromone-query-report.signed.json" \
    --runtime-pheromone-policy "$tmpdir/runtime-policy.json" \
    --runtime-peer-weights "$tmpdir/runtime-peer-weights.json" \
    --store "$tmpdir/mismatch-store.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/mismatch-report.json"; then
    echo "expected request binding mismatch to fail" >&2
    exit 1
  fi
  python3 - "$tmpdir/mismatch-report.json" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], "r", encoding="utf-8"))
if report.get("failureCode") != "request_binding_mismatch":
    raise SystemExit(f"wrong mismatch failure code: {report.get('failureCode')}")
PY
}

case "$MODE" in
  "schema-only")
    run_schema_checks
    ;;
  "negative-only")
    run_positive_checks
    run_negative_checks
    ;;
  "all")
    run_schema_checks
    cargo test -p chio-chiodos-runtime
    cargo test -p chio-kernel chiodos_runtime
    run_positive_checks
    run_negative_checks
    ;;
esac
