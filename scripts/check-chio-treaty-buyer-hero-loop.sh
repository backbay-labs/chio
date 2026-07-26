#!/usr/bin/env bash
set -euo pipefail

MODE="full"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    ;;
  "--negative-only" | "--runtime-only" | "--packet-only" | "--explain-only")
    MODE="${1#--}"
    ;;
  *)
    echo "usage: check-chio-treaty-buyer-hero-loop.sh [--schema-only|--negative-only|--runtime-only|--packet-only|--explain-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chio-treaty-buyer-hero-loop.sh [--schema-only|--negative-only|--runtime-only|--packet-only|--explain-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHIO_RUNTIME_SCHEMA_DIR="$repo_root/spec/schemas/chio-runtime/v1"
CHIO_ATTEST_SCHEMA_DIR="$repo_root/spec/schemas/chio-attest/v1"
CHIO_FEDERATION_SCHEMA_DIR="$repo_root/spec/schemas/chio-federation/v1"
RUNTIME_FIXTURE_DIR="$repo_root/examples/chio-3vendor/fixtures/runtime-spine"
NEGATIVE_FIXTURE="$repo_root/examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
LOOPBACK_NOW_UNIX_MS="${CHIO_LOOPBACK_NOW_UNIX_MS:-1766000001000}"

tmpdir="$(mktemp -d)"
trap 'if [[ "${CHIO_KEEP_TMP:-0}" == "1" ]]; then echo "kept tmpdir: $tmpdir" >&2; else rm -rf "$tmpdir"; fi' EXIT

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

prepare_runtime_loopback_scenario() {
  local scenario="$tmpdir/chio-runtime-loopback-scenario.json"
  cp "$RUNTIME_FIXTURE_DIR/scenario.json" "$scenario"
  python3 - "$scenario" <<'PY'
import hashlib
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    scenario = json.load(fh)

# The source fixture stays Chio-native. These executable arguments are temp-only
steps = [
    (
        "did:chio:vendor-a",
        "lease-vendor-a-read",
        "vendor-a.files",
        "read_refund_case",
        {
            "caseRef": "refund-250",
            "tool": "read_refund_case",
            "workflowId": "wf-chio-refund-001",
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
            "workflowId": "wf-chio-refund-001",
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
            "workflowId": "wf-chio-refund-001",
        },
    ),
]

fixture_steps = scenario.get("steps")
if not isinstance(fixture_steps, list):
    raise SystemExit("Chio runtime loopback fixture scenario has no steps array")
if len(fixture_steps) != len(steps):
    raise SystemExit(
        f"Chio runtime loopback fixture has {len(fixture_steps)} steps, expected {len(steps)}"
    )

for index, (step, (kernel, capability, server, tool, arguments)) in enumerate(
    zip(fixture_steps, steps),
    start=1,
):
    digest = hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if not isinstance(step, dict):
        raise SystemExit(f"Chio runtime loopback fixture step {index} is not an object")
    step["arguments"] = arguments
    profile = step.setdefault("admissionProfile", {})
    profile["localKernelId"] = kernel
    profile["issuedAtUnixMs"] = 1700000000000
    profile["expiresAtUnixMs"] = 1900000000000
    bundle = step.setdefault("admissionBundle", {})
    binding = bundle.setdefault("binding", {})
    binding["capabilityId"] = capability
    binding["serverId"] = server
    binding["toolName"] = tool
    binding["toolArgsSha256"] = digest
    binding["hostKernelId"] = kernel
    bundle["leaseId"] = capability
    request = step.setdefault("request", {})
    request["capabilityId"] = capability
    request["serverId"] = server
    request["toolName"] = tool
    request["toolArgsSha256"] = digest
    request["hostKernelId"] = kernel

with open(path, "w", encoding="utf-8") as fh:
    json.dump(scenario, fh, indent=2)
    fh.write("\n")
PY
  printf '%s\n' "$scenario"
}

validate_runtime_loopback_outputs() {
  local out_dir="$1"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/workflow-run-report.schema.json" \
    "$out_dir/runtime-run-report.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/workflow-run-report.schema.json" \
    "$out_dir/workflow-run-report.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/buyer-attestation-packet.schema.json" \
    "$out_dir/buyer-attestation-packet.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/proof-package.schema.json" \
    "$out_dir/proof-package.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/verifier-report.schema.json" \
    "$out_dir/verifier-report.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/proof-regeneration-report.schema.json" \
    "$out_dir/proof-regeneration-report.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/evidence-manifest.schema.json" \
    "$out_dir/runtime-evidence-manifest.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/proof-regeneration-input.schema.json" \
    "$out_dir/runtime-proof-regeneration-input.json"
  validate_schema "$CHIO_RUNTIME_SCHEMA_DIR/proof-parity-report.schema.json" \
    "$out_dir/runtime-proof-parity-report.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/receipt-lineage-statement.schema.json" \
    "$out_dir/receipt-lineage-statement.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/receipt-lineage-bundle.schema.json" \
    "$out_dir/receipt-lineage-bundle.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/cross-kernel-continuation.schema.json" \
    "$out_dir/cross-kernel-continuation.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/cross-boundary-admission-report.schema.json" \
    "$out_dir/cross-boundary-admission-report.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/bilateral-invocation.schema.json" \
    "$out_dir/bilateral-invocation.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/verifier-trust-bundle.schema.json" \
    "$out_dir/verifier-trust-bundle.json"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/verification-context.schema.json" \
    "$out_dir/verification-context.json"
}

run_runtime_semantic_checks() {
  local out_dir="$1"
  python3 - "$out_dir/runtime-run-report.json" \
    "$out_dir/proof-regeneration-report.json" \
    "$out_dir/runtime-proof-parity-report.json" \
    "$out_dir/runtime-evidence-manifest.json" \
    "$out_dir/runtime-proof-regeneration-input.json" \
    "$out_dir/buyer-review-report.json" \
    "$out_dir/proof-package.json" <<'PY'
import base64
import hashlib
import json
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
if proof.get("schema") != "chio.runtime.proof-regeneration-report.v1":
    raise SystemExit("runtime proof regeneration report schema mismatch")
if not proof.get("accepted"):
    raise SystemExit(f"runtime proof regeneration was not accepted: {proof.get('failureCode')}")
if proof.get("failureCode") == "runtime_proof_semantic_regeneration_pending":
    raise SystemExit("runtime proof regeneration still reports pending")
if not proof.get("proofPackageSha256") or not proof.get("verifierReportSha256"):
    raise SystemExit("runtime proof regeneration did not bind proof package and verifier hashes")

required_proof_checks = {
    "runtime_kernel_receipts.captured",
    "runtime_treaty_buyer_closure.bound",
}
missing_proof_checks = required_proof_checks - set(proof.get("checks", []))
if missing_proof_checks:
    raise SystemExit(f"runtime proof regeneration skipped checks: {sorted(missing_proof_checks)}")
if "runtime_kernel_receipts.fixture_compatibility_path" in proof.get("checks", []):
    raise SystemExit("runtime proof regeneration used fixture compatibility path")
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
    "chio_attest_buyer.review.runtime_reports_bound",
    "chio_attest_buyer.review.strict_dsse_treaty_bound",
    "chio_attest_buyer.review.proof_verifier_accepted",
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
        if consistency_model != "totally-ordered":
            raise SystemExit("treaty DSSE did not carry ordered consistency")
if not has_treaty_dsse:
    raise SystemExit("proof package did not carry a treaty-bound bilateral DSSE")

for path in workflow.get("evidencePaths", []):
    if path in {"regenerated-proof-package.json", "pheromone-deposit.json"}:
        raise SystemExit(f"placeholder aggregate evidence path survived: {path}")
PY
}

run_buyer_review() {
  local out_dir="$1"
  run_chio attest buyer verify-proof \
    --package "$out_dir/proof-package.json" \
    --trust-bundle "$out_dir/verifier-trust-bundle.json" \
    --context "$out_dir/verification-context.json" \
    --report "$out_dir/verifier-report-rerun.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/verifier-report.schema.json" \
    "$out_dir/verifier-report-rerun.json"
  run_chio attest buyer packet \
    --run-output "$out_dir" \
    --out "$out_dir/buyer-review-package.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/buyer-attestation-review-package.schema.json" \
    "$out_dir/buyer-review-package.json"
  run_chio attest buyer verify \
    --package "$out_dir/buyer-review-package.json" \
    --trust-bundle "$out_dir/verifier-trust-bundle.json" \
    --context "$out_dir/verification-context.json" \
    --report "$out_dir/buyer-review-report.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/buyer-attestation-review-report.schema.json" \
    "$out_dir/buyer-review-report.json"
}

runtime_spine_out_dir=""

run_runtime_loopback_with_artifacts() {
  if [[ -n "$runtime_spine_out_dir" ]]; then
    return 0
  fi
  local scenario
  scenario="$(prepare_runtime_loopback_scenario)"
  runtime_spine_out_dir="$tmpdir/loopback-out"
  run_chio runtime run-loopback \
    --scenario "$scenario" \
    --static-package "$repo_root/examples/chio-3vendor/fixtures/buyer-auditor-proof-package.json" \
    --static-report "$repo_root/examples/chio-3vendor/fixtures/verifier-report.json" \
    --store-dir "$tmpdir/loopback-store" \
    --now-unix-ms "$LOOPBACK_NOW_UNIX_MS" \
    --out-dir "$runtime_spine_out_dir"
  validate_runtime_loopback_outputs "$runtime_spine_out_dir"
  run_buyer_review "$runtime_spine_out_dir"
  run_runtime_semantic_checks "$runtime_spine_out_dir"
  if grep -R "runtime_proof_semantic_regeneration_pending" "$runtime_spine_out_dir" >/dev/null; then
    echo "runtime proof parity gate found pending regeneration marker" >&2
    exit 1
  fi
}

run_strict_dsse_negative_tests() {
  cargo test -p chio-runtime-core buyer_review_package_rejects_missing_strict_dsse_envelope --test runtime_buyer_review
  cargo test -p chio-runtime-core buyer_review_package_rejects_non_strict_dsse_envelope --test runtime_buyer_review
  cargo test -p chio-runtime-core buyer_review_package_rejects_tampered_strict_dsse_signature_when_peer_keys_available --test runtime_buyer_review
  cargo test -p chio-federation strict_chio_treaty_review_binds_live_material --lib
}

if [[ "$MODE" == "schema-only" ]]; then
  bash "$repo_root/scripts/check-chio-runtime-spine-fixtures.sh"
  validate_schema "$CHIO_FEDERATION_SCHEMA_DIR/treaty-runtime-negative-fixture-corpus.schema.json" \
    "$NEGATIVE_FIXTURE"
  exit 0
fi

if [[ "$MODE" == "packet-only" ]]; then
  run_runtime_loopback_with_artifacts
  exit 0
fi

if [[ "$MODE" == "explain-only" ]]; then
  run_runtime_loopback_with_artifacts
  run_chio attest buyer explain \
    --report "$runtime_spine_out_dir/buyer-review-report.json" \
    --format text \
    --out "$tmpdir/review.txt"
  grep -q "Accepted: true" "$tmpdir/review.txt"
  grep -q "Verification state: strict_verified" "$tmpdir/review.txt"
  run_chio attest buyer explain \
    --report "$runtime_spine_out_dir/buyer-review-report.json" \
    --format json \
    --out "$tmpdir/review.json"
  validate_schema "$CHIO_ATTEST_SCHEMA_DIR/buyer-attestation-explanation.schema.json" \
    "$tmpdir/review.json"
  exit 0
fi

if [[ "$MODE" == "negative-only" ]]; then
  run_runtime_loopback_with_artifacts
  run_strict_dsse_negative_tests
  cargo test -p chio-runtime-core buyer_review --test runtime_buyer_review
  exit 0
fi

if [[ "$MODE" == "runtime-only" ]]; then
  cargo test -p chio-runtime-core buyer_review --test runtime_buyer_review
  cargo test -p chio-runtime-core receipt_lineage_bundle --test runtime_buyer_review
  exit 0
fi

if [[ "$MODE" == "full" ]]; then
  bash "$0" --schema-only
  bash "$0" --packet-only
  bash "$0" --explain-only
  bash "$0" --negative-only
  exit 0
fi
