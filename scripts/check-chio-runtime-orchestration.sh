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
  "--run-only")
    MODE="run-only"
    shift
    ;;
  "--resume-only")
    MODE="resume-only"
    shift
    ;;
  "--drift-only")
    MODE="drift-only"
    shift
    ;;
  *)
    echo "usage: check-chio-runtime-orchestration.sh [--schema-only|--negative-only|--run-only|--resume-only|--drift-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chio-runtime-orchestration.sh [--schema-only|--negative-only|--run-only|--resume-only|--drift-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

runtime_schema_dir="$ROOT/spec/schemas/chio-runtime/v1"

cat >"$tmpdir/profile.json" <<'JSON'
{
  "schema": "chio.runtime.orchestration-profile.v1",
  "profileId": "profile-runtime-orchestration",
  "localKernelId": "kernel.vendor-b",
  "verifierId": "did:chio:buyer-verifier",
  "mode": "local",
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000,
  "maxConcurrentRuns": 1,
  "failClosedOn": ["evidence_sink_unavailable", "proof_regeneration_rejected"]
}
JSON

profile_hash="$(python3 - "$tmpdir/profile.json" <<'PY'
import hashlib, json, sys
with open(sys.argv[1], "r", encoding="utf-8") as f:
    value = json.load(f)
print(hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
PY
)"

cat >"$tmpdir/run-contract.json" <<JSON
{
  "schema": "chio.runtime.run-contract.v1",
  "runId": "runtime-orchestration-1",
  "profileSha256": "$profile_hash",
  "workflowId": "wf-chio-refund-001",
  "expectedStepCount": 1,
  "admissionIds": ["adm-loopback-1"],
  "storeId": "runtime-store-local",
  "evidenceSinkId": "runtime-evidence-local",
  "proofRegenerationRequired": true
}
JSON

cat >"$tmpdir/negative-corpus.json" <<'JSON'
{
  "schema": "chio.runtime.orchestration-negative-fixture-corpus.v1",
  "cases": [
    { "caseId": "manifest-hash-mismatch", "expectedCode": "runtime_proof_drift_detected" }
  ]
}
JSON

make_evidence_dir() {
  local dir="$1"
  local run_id="$2"
  local proof_payload="${3:-runtime-proof-package-a}"
  local verifier_state="${4:-accepted}"
  mkdir -p "$dir"
  cat >"$dir/workflow-run-report.json" <<JSON
{
  "schema": "chio.runtime.workflow-run-report.v1",
  "runId": "$run_id",
  "accepted": true,
  "generatedAtUnixMs": 1800000001000,
  "admissionReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "evidencePaths": ["proof-regeneration-report.json"],
  "stepEvidence": [
    {
      "schema": "chio.runtime.step-evidence.v1",
      "stepIndex": 0,
      "admissionId": "adm-loopback-1",
      "admissionReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "toolReceiptId": "receipt-live-1",
      "toolReceiptSha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "outputSha256": "3333333333333333333333333333333333333333333333333333333333333333",
      "bilateralDsseSha256": "4444444444444444444444444444444444444444444444444444444444444444",
      "workflowStepSha256": "5555555555555555555555555555555555555555555555555555555555555555",
      "consistencyAnchor": "chio:consistency:wf-chio-refund-001:0",
      "destructive": false
    }
  ],
  "proofRegenerationReportSha256": "6666666666666666666666666666666666666666666666666666666666666666"
}
JSON
  cat >"$dir/proof-regeneration-report.json" <<JSON
{
  "schema": "chio.runtime.proof-regeneration-report.v1",
  "runId": "$run_id",
  "accepted": true,
  "generatedAtUnixMs": 1800000001000,
  "proofPackageSha256": "9999999999999999999999999999999999999999999999999999999999999999",
  "verifierReportSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "workflowReceiptSha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "sourceRecords": [
    {
      "stepIndex": 0,
      "admissionReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "toolReceiptSha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "bilateralDsseSha256": "4444444444444444444444444444444444444444444444444444444444444444",
      "workflowStepSha256": "5555555555555555555555555555555555555555555555555555555555555555"
    }
  ],
  "checks": ["runtime_semantic_proof_regeneration.verified"]
}
JSON
  cat >"$dir/runtime-evidence-manifest.json" <<JSON
{
  "schema": "chio.runtime.evidence-manifest.v1",
  "runId": "$run_id",
  "generatedAtUnixMs": 1800000001000,
  "workflowRunReportSha256": "7777777777777777777777777777777777777777777777777777777777777777",
  "proofRegenerationReportSha256": "6666666666666666666666666666666666666666666666666666666666666666",
  "entries": [
    {
      "role": "proof_package",
      "path": "buyer-auditor-proof-package.json",
      "sha256": "9999999999999999999999999999999999999999999999999999999999999999",
      "byteCount": 4096
    }
  ]
}
JSON
  printf '{"payload":"%s"}\n' "$proof_payload" >"$dir/buyer-auditor-proof-package.json"
  cat >"$dir/verifier-report.json" <<'JSON'
{}
JSON
  python3 - "$dir" "$verifier_state" <<'PY'
import hashlib
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
verifier_state = sys.argv[2]
proof_package_path = directory / "buyer-auditor-proof-package.json"
proof_package_bytes = proof_package_path.read_bytes()
proof_package_file_hash = hashlib.sha256(proof_package_bytes).hexdigest()

def canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")

verifier_report = {
    "schema": "chio.attest.verifier-report.v1",
    "packageSha256": canonical_hash(json.loads(proof_package_bytes.decode("utf-8"))),
    "accepted": verifier_state == "accepted",
    "checks": [
        {
            "code": "runtime.fixture",
            "name": "runtime-fixture",
            "passed": verifier_state == "accepted",
        }
    ],
}
write_json(directory / "verifier-report.json", verifier_report)
verifier_hash = canonical_hash(verifier_report)

proof_path = directory / "proof-regeneration-report.json"
proof_report = json.loads(proof_path.read_text(encoding="utf-8"))
proof_report["proofPackageSha256"] = verifier_report["packageSha256"]
proof_report["verifierReportSha256"] = verifier_hash
write_json(proof_path, proof_report)
proof_hash = canonical_hash(proof_report)

workflow_path = directory / "workflow-run-report.json"
workflow_report = json.loads(workflow_path.read_text(encoding="utf-8"))
workflow_report["proofRegenerationReportSha256"] = proof_hash
write_json(workflow_path, workflow_report)
workflow_hash = canonical_hash(workflow_report)

manifest_path = directory / "runtime-evidence-manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["workflowRunReportSha256"] = workflow_hash
manifest["proofRegenerationReportSha256"] = proof_hash
for entry in manifest["entries"]:
    if entry["role"] == "proof_package":
        entry["sha256"] = proof_package_file_hash
        entry["byteCount"] = len(proof_package_bytes)
write_json(manifest_path, manifest)
PY
}

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

run_schema_checks() {
  validate_schema "$runtime_schema_dir/orchestration-profile.schema.json" "$tmpdir/profile.json"
  validate_schema "$runtime_schema_dir/run-contract.schema.json" "$tmpdir/run-contract.json"
  validate_schema "$runtime_schema_dir/orchestration-negative-fixture-corpus.schema.json" "$tmpdir/negative-corpus.json"
}

run_positive_flow() {
  make_evidence_dir "$tmpdir/run-a" "runtime-orchestration-1"
  cargo run -p chio-cli -- runtime orchestrate lint \
    --profile "$tmpdir/profile.json" \
    --report "$tmpdir/lint-report.json"
  cargo run -p chio-cli -- runtime orchestrate plan \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/plan-report.json"
  cargo run -p chio-cli -- runtime orchestrate run \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/run-report.json"
  cargo run -p chio-cli -- runtime orchestrate status \
    --profile "$tmpdir/profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/status-report.json"
  validate_schema "$runtime_schema_dir/orchestration-status-report.schema.json" "$tmpdir/lint-report.json"
  validate_schema "$runtime_schema_dir/orchestration-plan.schema.json" "$tmpdir/plan-report.json"
  validate_schema "$runtime_schema_dir/orchestration-run-report.schema.json" "$tmpdir/run-report.json"
  validate_schema "$runtime_schema_dir/orchestration-status-report.schema.json" "$tmpdir/status-report.json"
  python3 - "$tmpdir/status-report.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("accepted") is not True or report.get("ready") is not True:
    raise SystemExit(f"runtime orchestration status was not healthy: {report}")
PY
}

run_resume_flow() {
  cat >"$tmpdir/resume-input.json" <<'JSON'
{
  "schema": "chio.runtime.orchestration-resume-plan.v1",
  "runId": "runtime-orchestration-1",
  "accepted": true,
  "generatedAtUnixMs": 1800000000000,
  "nextStepIndex": 0,
  "reusableStepIndices": [],
  "blocked": false,
  "checks": ["runtime_orchestration.resume_requested"]
}
JSON
  cargo run -p chio-cli -- runtime orchestrate resume \
    --profile "$tmpdir/profile.json" \
    --resume-plan "$tmpdir/resume-input.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000002000 \
    --report "$tmpdir/resume-report.json"
  validate_schema "$runtime_schema_dir/orchestration-resume-plan.schema.json" "$tmpdir/resume-report.json"
}

run_drift_flow() {
  mkdir -p "$tmpdir/runs"
  make_evidence_dir "$tmpdir/runs/run-a" "runtime-orchestration-a"
  make_evidence_dir "$tmpdir/runs/run-b" "runtime-orchestration-b"
  cargo run -p chio-cli -- runtime orchestrate drift \
    --profile "$tmpdir/profile.json" \
    --runs-dir "$tmpdir/runs" \
    --since-unix-ms 1800000000000 \
    --until-unix-ms 1800000002000 \
    --report "$tmpdir/drift-report.json"
  validate_schema "$runtime_schema_dir/proof-drift-report.schema.json" "$tmpdir/drift-report.json"
}

run_negative_flow() {
  mkdir -p "$tmpdir/negative-runs"
  make_evidence_dir "$tmpdir/negative-runs/run-a" "runtime-orchestration-a"
  make_evidence_dir "$tmpdir/negative-runs/run-b" "runtime-orchestration-b" "runtime-proof-package-b"
  cargo run -p chio-cli -- runtime orchestrate drift \
    --profile "$tmpdir/profile.json" \
    --runs-dir "$tmpdir/negative-runs" \
    --since-unix-ms 1800000000000 \
    --until-unix-ms 1800000002000 \
    --report "$tmpdir/negative-drift-report.json"
  grep -q '"accepted": false' "$tmpdir/negative-drift-report.json"
  grep -q '"failureCode": "runtime_proof_drift_detected"' "$tmpdir/negative-drift-report.json"
  validate_schema "$runtime_schema_dir/proof-drift-report.schema.json" "$tmpdir/negative-drift-report.json"
  make_evidence_dir "$tmpdir/proof-missing-run" "runtime-orchestration-1"
  rm "$tmpdir/proof-missing-run/buyer-auditor-proof-package.json"
  cargo run -p chio-cli -- runtime orchestrate run \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime-proof-missing.sqlite3" \
    --evidence-dir "$tmpdir/proof-missing-run" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/proof-missing-run-report.json"
  grep -q '"accepted": false' "$tmpdir/proof-missing-run-report.json"
  grep -q '"failureCode": "runtime_admission_io"' "$tmpdir/proof-missing-run-report.json"
  validate_schema "$runtime_schema_dir/orchestration-run-report.schema.json" "$tmpdir/proof-missing-run-report.json"
  make_evidence_dir "$tmpdir/verifier-package-mismatch-run" "runtime-orchestration-1"
  python3 - "$tmpdir/verifier-package-mismatch-run" <<'PY'
import hashlib
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])

def canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")

verifier_path = directory / "verifier-report.json"
verifier_report = json.loads(verifier_path.read_text(encoding="utf-8"))
verifier_report["packageSha256"] = "0" * 64
write_json(verifier_path, verifier_report)
verifier_hash = canonical_hash(verifier_report)

proof_path = directory / "proof-regeneration-report.json"
proof_report = json.loads(proof_path.read_text(encoding="utf-8"))
proof_report["verifierReportSha256"] = verifier_hash
write_json(proof_path, proof_report)
proof_hash = canonical_hash(proof_report)

workflow_path = directory / "workflow-run-report.json"
workflow_report = json.loads(workflow_path.read_text(encoding="utf-8"))
workflow_report["proofRegenerationReportSha256"] = proof_hash
write_json(workflow_path, workflow_report)
workflow_hash = canonical_hash(workflow_report)

manifest_path = directory / "runtime-evidence-manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["proofRegenerationReportSha256"] = proof_hash
manifest["workflowRunReportSha256"] = workflow_hash
write_json(manifest_path, manifest)
PY
  cargo run -p chio-cli -- runtime orchestrate run \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime-verifier-package-mismatch.sqlite3" \
    --evidence-dir "$tmpdir/verifier-package-mismatch-run" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/verifier-package-mismatch-run-report.json"
  grep -q '"accepted": false' "$tmpdir/verifier-package-mismatch-run-report.json"
  grep -q '"failureCode": "runtime_orchestration_evidence_hash_mismatch"' "$tmpdir/verifier-package-mismatch-run-report.json"
  validate_schema "$runtime_schema_dir/orchestration-run-report.schema.json" "$tmpdir/verifier-package-mismatch-run-report.json"
  make_evidence_dir "$tmpdir/verifier-rejected-run" "runtime-orchestration-1" "runtime-proof-package-a" "rejected"
  cargo run -p chio-cli -- runtime orchestrate run \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime-verifier-negative.sqlite3" \
    --evidence-dir "$tmpdir/verifier-rejected-run" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/verifier-rejected-run-report.json"
  grep -q '"accepted": false' "$tmpdir/verifier-rejected-run-report.json"
  grep -q '"failureCode": "runtime_orchestration_verifier_report_rejected"' "$tmpdir/verifier-rejected-run-report.json"
  validate_schema "$runtime_schema_dir/orchestration-run-report.schema.json" "$tmpdir/verifier-rejected-run-report.json"
}

case "$MODE" in
  "schema-only")
    run_schema_checks
    ;;
  "negative-only")
    run_negative_flow
    ;;
  "run-only")
    run_positive_flow
    ;;
  "resume-only")
    run_positive_flow
    run_resume_flow
    ;;
  "drift-only")
    run_drift_flow
    ;;
  "all")
    cargo test -p chio-runtime-core runtime_orchestration
    cargo test -p chio-runtime-core runtime_proof_drift
    cargo test -p chio-cli --bin chio chio_native_runtime_surface_parses
    run_schema_checks
    run_positive_flow
    run_resume_flow
    run_drift_flow
    run_negative_flow
    ;;
esac
