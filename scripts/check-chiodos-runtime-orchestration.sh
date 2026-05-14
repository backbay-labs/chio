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
    echo "usage: check-chiodos-runtime-orchestration.sh [--schema-only|--negative-only|--run-only|--resume-only|--drift-only]" >&2
    exit 2
    ;;
esac
if [[ $# -ne 0 ]]; then
  echo "usage: check-chiodos-runtime-orchestration.sh [--schema-only|--negative-only|--run-only|--resume-only|--drift-only]" >&2
  exit 2
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

schema_dir="$ROOT/spec/schemas/chiodos/v1"

cat >"$tmpdir/profile.json" <<'JSON'
{
  "schema": "chio.chiodos.runtime-orchestration-profile.v1",
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
  "schema": "chio.chiodos.runtime-run-contract.v1",
  "runId": "runtime-orchestration-1",
  "profileSha256": "$profile_hash",
  "workflowId": "wf-chiodos-refund-001",
  "expectedStepCount": 1,
  "admissionIds": ["adm-loopback-1"],
  "storeId": "runtime-store-local",
  "evidenceSinkId": "runtime-evidence-local",
  "proofRegenerationRequired": true
}
JSON

cat >"$tmpdir/negative-corpus.json" <<'JSON'
{
  "schema": "chio.chiodos.runtime-orchestration-negative-fixture-corpus.v1",
  "cases": [
    { "caseId": "manifest-hash-mismatch", "expectedCode": "runtime_proof_drift_detected" }
  ]
}
JSON

make_evidence_dir() {
  local dir="$1"
  local run_id="$2"
  local proof_hash="${3:-9999999999999999999999999999999999999999999999999999999999999999}"
  mkdir -p "$dir"
  cat >"$dir/workflow-run-report.json" <<JSON
{
  "schema": "chio.chiodos.runtime-workflow-run-report.v1",
  "runId": "$run_id",
  "accepted": true,
  "generatedAtUnixMs": 1800000001000,
  "admissionReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "evidencePaths": ["proof-regeneration-report.json"],
  "stepEvidence": [
    {
      "schema": "chio.chiodos.runtime-step-evidence.v1",
      "stepIndex": 0,
      "admissionId": "adm-loopback-1",
      "admissionReportSha256": "1111111111111111111111111111111111111111111111111111111111111111",
      "toolReceiptId": "receipt-live-1",
      "toolReceiptSha256": "2222222222222222222222222222222222222222222222222222222222222222",
      "outputSha256": "3333333333333333333333333333333333333333333333333333333333333333",
      "bilateralDsseSha256": "4444444444444444444444444444444444444444444444444444444444444444",
      "workflowStepSha256": "5555555555555555555555555555555555555555555555555555555555555555",
      "consistencyAnchor": "chiodos:consistency:wf-chiodos-refund-001:0",
      "destructive": false
    }
  ],
  "proofRegenerationReportSha256": "6666666666666666666666666666666666666666666666666666666666666666"
}
JSON
  cat >"$dir/proof-regeneration-report.json" <<JSON
{
  "schema": "chio.chiodos.runtime-proof-regeneration-report.v1",
  "runId": "$run_id",
  "accepted": true,
  "generatedAtUnixMs": 1800000001000,
  "proofPackageSha256": "$proof_hash",
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
  "schema": "chio.chiodos.runtime-evidence-manifest.v1",
  "runId": "$run_id",
  "generatedAtUnixMs": 1800000001000,
  "workflowRunReportSha256": "7777777777777777777777777777777777777777777777777777777777777777",
  "proofRegenerationReportSha256": "6666666666666666666666666666666666666666666666666666666666666666",
  "entries": [
    {
      "role": "proof_package",
      "path": "buyer-auditor-proof-package.json",
      "sha256": "$proof_hash",
      "byteCount": 4096
    }
  ]
}
JSON
  cat >"$dir/verifier-report.json" <<'JSON'
{}
JSON
}

validate_schema() {
  local schema="$1"
  local document="$2"
  cargo run -p chio-spec-validate -- "$schema" "$document" >/dev/null
}

run_schema_checks() {
  validate_schema "$schema_dir/runtime-orchestration-profile.schema.json" "$tmpdir/profile.json"
  validate_schema "$schema_dir/runtime-run-contract.schema.json" "$tmpdir/run-contract.json"
  validate_schema "$schema_dir/runtime-orchestration-negative-fixture-corpus.schema.json" "$tmpdir/negative-corpus.json"
}

run_positive_flow() {
  make_evidence_dir "$tmpdir/run-a" "runtime-orchestration-1"
  cargo run -p chio-cli -- chiodos runtime orchestrate lint \
    --profile "$tmpdir/profile.json" \
    --report "$tmpdir/lint-report.json"
  cargo run -p chio-cli -- chiodos runtime orchestrate plan \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/plan-report.json"
  cargo run -p chio-cli -- chiodos runtime orchestrate run \
    --profile "$tmpdir/profile.json" \
    --run-contract "$tmpdir/run-contract.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/run-report.json"
  cargo run -p chio-cli -- chiodos runtime orchestrate status \
    --profile "$tmpdir/profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --report "$tmpdir/status-report.json"
  validate_schema "$schema_dir/runtime-orchestration-status-report.schema.json" "$tmpdir/lint-report.json"
  validate_schema "$schema_dir/runtime-orchestration-plan.schema.json" "$tmpdir/plan-report.json"
  validate_schema "$schema_dir/runtime-orchestration-run-report.schema.json" "$tmpdir/run-report.json"
  validate_schema "$schema_dir/runtime-orchestration-status-report.schema.json" "$tmpdir/status-report.json"
}

run_resume_flow() {
  cat >"$tmpdir/resume-input.json" <<'JSON'
{
  "schema": "chio.chiodos.runtime-orchestration-resume-plan.v1",
  "runId": "runtime-orchestration-1",
  "accepted": true,
  "generatedAtUnixMs": 1800000000000,
  "nextStepIndex": 0,
  "reusableStepIndices": [],
  "blocked": false,
  "checks": ["runtime_orchestration.resume_requested"]
}
JSON
  cargo run -p chio-cli -- chiodos runtime orchestrate resume \
    --profile "$tmpdir/profile.json" \
    --resume-plan "$tmpdir/resume-input.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-dir "$tmpdir/run-a" \
    --now-unix-ms 1800000002000 \
    --report "$tmpdir/resume-report.json"
  validate_schema "$schema_dir/runtime-orchestration-resume-plan.schema.json" "$tmpdir/resume-report.json"
}

run_drift_flow() {
  mkdir -p "$tmpdir/runs"
  make_evidence_dir "$tmpdir/runs/run-a" "runtime-orchestration-a"
  make_evidence_dir "$tmpdir/runs/run-b" "runtime-orchestration-b"
  cargo run -p chio-cli -- chiodos runtime orchestrate drift \
    --profile "$tmpdir/profile.json" \
    --runs-dir "$tmpdir/runs" \
    --since-unix-ms 1800000000000 \
    --until-unix-ms 1800000002000 \
    --report "$tmpdir/drift-report.json"
  validate_schema "$schema_dir/runtime-proof-drift-report.schema.json" "$tmpdir/drift-report.json"
}

run_negative_flow() {
  mkdir -p "$tmpdir/negative-runs"
  make_evidence_dir "$tmpdir/negative-runs/run-a" "runtime-orchestration-a"
  make_evidence_dir "$tmpdir/negative-runs/run-b" "runtime-orchestration-b" "8888888888888888888888888888888888888888888888888888888888888888"
  cargo run -p chio-cli -- chiodos runtime orchestrate drift \
    --profile "$tmpdir/profile.json" \
    --runs-dir "$tmpdir/negative-runs" \
    --since-unix-ms 1800000000000 \
    --until-unix-ms 1800000002000 \
    --report "$tmpdir/negative-drift-report.json"
  grep -q '"accepted": false' "$tmpdir/negative-drift-report.json"
  grep -q '"failureCode": "runtime_proof_drift_detected"' "$tmpdir/negative-drift-report.json"
  validate_schema "$schema_dir/runtime-proof-drift-report.schema.json" "$tmpdir/negative-drift-report.json"
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
    cargo test -p chio-chiodos-runtime runtime_orchestration
    cargo test -p chio-chiodos-runtime runtime_proof_drift
    cargo test -p chio-cli --bin chio chiodos_runtime_orchestrate
    run_schema_checks
    run_positive_flow
    run_resume_flow
    run_drift_flow
    run_negative_flow
    ;;
esac
