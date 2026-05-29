#!/usr/bin/env bash
set -euo pipefail

MODE="full"
case "${1:-}" in
  "")
    ;;
  "--schema-only")
    MODE="schema-only"
    ;;
  "--negative-only")
    MODE="negative-only"
    ;;
  "--tick-only")
    MODE="tick-only"
    ;;
  "--recovery-only")
    MODE="recovery-only"
    ;;
  "--evidence-only")
    MODE="evidence-only"
    ;;
  "--provider-only")
    MODE="provider-only"
    ;;
  "--retention-only")
    MODE="retention-only"
    ;;
  "--failure-codes-only")
    MODE="failure-codes-only"
    ;;
  *)
    echo "usage: check-chio-runtime-ops-hardening.sh [--schema-only|--negative-only|--tick-only|--recovery-only|--evidence-only|--provider-only|--retention-only|--failure-codes-only]" >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  echo "usage: check-chio-runtime-ops-hardening.sh [--schema-only|--negative-only|--tick-only|--recovery-only|--evidence-only|--provider-only|--retention-only|--failure-codes-only]" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime_schema_dir="$repo_root/spec/schemas/chio-runtime/v1"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

validate_schema() {
  cargo run -p chio-spec-validate -- "$1" "$2" >/dev/null
}

write_common_fixtures() {
  cat >"$tmpdir/supervisor-profile.json" <<'JSON'
{
  "schema": "chio.runtime.supervisor-profile.v1",
  "profileId": "runtime-supervisor-local",
  "localKernelId": "kernel.vendor-b",
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000,
  "maxConcurrentRuns": 2,
  "runLeaseTtlMs": 60000,
  "staleRunAfterMs": 300000,
  "evidenceRequiredRoles": ["workflow_run_report"],
  "failClosedOn": ["evidence_hash_mismatch"]
}
JSON
  cat >"$tmpdir/provider-bindings.json" <<'JSON'
{
  "schema": "chio.runtime.provider-bindings.v1",
  "bindings": [
    {
      "providerId": "provider-vendor-b",
      "localKernelId": "kernel.vendor-b",
      "serverId": "vendor-ledger",
      "toolName": "close_account",
      "discoveryAllowed": false
    }
  ]
}
JSON
  cat >"$tmpdir/provider-bindings-bad.json" <<'JSON'
{
  "schema": "chio.runtime.provider-bindings.v1",
  "bindings": [
    {
      "providerId": "provider-vendor-b",
      "localKernelId": "kernel.vendor-b",
      "serverId": "vendor-ledger",
      "toolName": "close_account",
      "discoveryAllowed": true
    }
  ]
}
JSON
  cat >"$tmpdir/retention-profile.json" <<'JSON'
{
  "schema": "chio.runtime.artifact-retention-profile.v1",
  "profileId": "runtime-retention-local",
  "localKernelId": "kernel.vendor-b",
  "issuedAtUnixMs": 1800000000000,
  "expiresAtUnixMs": 1800003600000,
  "minRetainMs": 86400000,
  "destructiveHoldMs": 604800000,
  "legalHold": false,
  "dryRunOnly": true
}
JSON
  cat >"$tmpdir/negative-corpus.json" <<'JSON'
{
  "schema": "chio.runtime.ops-negative-fixture-corpus.v1",
  "cases": [
    { "caseId": "provider-discovery", "expectedCode": "runtime_provider_discovery_not_allowed" },
    { "caseId": "evidence-hash-mismatch", "expectedCode": "runtime_evidence_artifact_hash_mismatch" }
  ]
}
JSON
  cat >"$tmpdir/failure-code-registry.json" <<'JSON'
{
  "schema": "chio.runtime.failure-code-registry.v1",
  "codes": [
    "runtime_provider_discovery_not_allowed",
    "runtime_evidence_artifact_hash_mismatch",
    "runtime_run_lease_conflict",
    "runtime_run_stale_fencing_token",
    "runtime_ops_status_degraded",
    "runtime_ops_supervisor_profile_stale",
    "runtime_recovery_supervisor_profile_stale"
  ]
}
JSON
  mkdir -p "$tmpdir/evidence/runtime-run-health"
  printf '{"ok":true}' >"$tmpdir/evidence/runtime-run-health/workflow-run-report.json"
  local hash
  hash="$(shasum -a 256 "$tmpdir/evidence/runtime-run-health/workflow-run-report.json" | awk '{print $1}')"
  local bytes
  bytes="$(wc -c <"$tmpdir/evidence/runtime-run-health/workflow-run-report.json" | tr -d ' ')"
  cat >"$tmpdir/evidence/runtime-run-health/runtime-evidence-manifest.json" <<JSON
{
  "schema": "chio.runtime.evidence-manifest.v1",
  "runId": "runtime-run-health",
  "generatedAtUnixMs": 1800000000000,
  "workflowRunReportSha256": "${hash}",
  "proofRegenerationReportSha256": "${hash}",
  "entries": [
    {
      "role": "workflow_run_report",
      "path": "workflow-run-report.json",
      "sha256": "${hash}",
      "byteCount": ${bytes}
    }
  ]
}
JSON
  mkdir -p "$tmpdir/evidence-bad/runtime-run-health"
  cp "$tmpdir/evidence/runtime-run-health/workflow-run-report.json" "$tmpdir/evidence-bad/runtime-run-health/workflow-run-report.json"
  sed 's/"sha256": "[0-9a-f]*"/"sha256": "3333333333333333333333333333333333333333333333333333333333333333"/' \
    "$tmpdir/evidence/runtime-run-health/runtime-evidence-manifest.json" \
    >"$tmpdir/evidence-bad/runtime-run-health/runtime-evidence-manifest.json"
}

run_schema_flow() {
  write_common_fixtures
  validate_schema "$runtime_schema_dir/supervisor-profile.schema.json" "$tmpdir/supervisor-profile.json"
  validate_schema "$runtime_schema_dir/provider-bindings.schema.json" "$tmpdir/provider-bindings.json"
  validate_schema "$runtime_schema_dir/artifact-retention-profile.schema.json" "$tmpdir/retention-profile.json"
  validate_schema "$runtime_schema_dir/ops-negative-fixture-corpus.schema.json" "$tmpdir/negative-corpus.json"
  validate_schema "$runtime_schema_dir/failure-code-registry.schema.json" "$tmpdir/failure-code-registry.json"
}

run_tick_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops tick \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence" \
    --owner-id "operator-a" \
    --now-unix-ms 1800000001000 \
    --max-runs 2 \
    --report "$tmpdir/tick-report.json" >/dev/null
  validate_schema "$runtime_schema_dir/scheduler-tick-report.schema.json" "$tmpdir/tick-report.json"
}

run_status_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops status \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence" \
    --provider-bindings "$tmpdir/provider-bindings.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/status-report.json" >/dev/null
  validate_schema "$runtime_schema_dir/ops-status-report.schema.json" "$tmpdir/status-report.json"
  cargo run -p chio-cli -- runtime ops status \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence-bad" \
    --provider-bindings "$tmpdir/provider-bindings.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/status-bad-report.json" >/dev/null
  grep -q '"accepted": false' "$tmpdir/status-bad-report.json"
  grep -q '"evidenceSinkHealthy": false' "$tmpdir/status-bad-report.json"
  grep -q '"failureCode": "runtime_ops_status_degraded"' "$tmpdir/status-bad-report.json"
  validate_schema "$runtime_schema_dir/ops-status-report.schema.json" "$tmpdir/status-bad-report.json"
}

run_recovery_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops recovery-drill \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --run-id "missing-run" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/recovery-report.json" >/dev/null
  grep -q '"failureCode": "runtime_recovery_run_not_found"' "$tmpdir/recovery-report.json"
  validate_schema "$runtime_schema_dir/recovery-drill-report.schema.json" "$tmpdir/recovery-report.json"
}

run_evidence_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops evidence-health \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --run-id "runtime-run-health" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/evidence-health-report.json" >/dev/null
  validate_schema "$runtime_schema_dir/evidence-sink-health-report.schema.json" "$tmpdir/evidence-health-report.json"
}

run_provider_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops provider-health \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --provider-bindings "$tmpdir/provider-bindings.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/provider-health-report.json" >/dev/null
  validate_schema "$runtime_schema_dir/provider-health-report.schema.json" "$tmpdir/provider-health-report.json"
}

run_retention_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops retention plan \
    --retention-profile "$tmpdir/retention-profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/retention-report.json" >/dev/null
  validate_schema "$runtime_schema_dir/artifact-retention-plan.schema.json" "$tmpdir/retention-report.json"
}

run_negative_flow() {
  write_common_fixtures
  cargo run -p chio-cli -- runtime ops provider-health \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --provider-bindings "$tmpdir/provider-bindings-bad.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/provider-health-bad.json" >/dev/null
  grep -q '"accepted": false' "$tmpdir/provider-health-bad.json"
  grep -q '"failureCode": "runtime_provider_discovery_not_allowed"' "$tmpdir/provider-health-bad.json"
  cargo run -p chio-cli -- runtime ops evidence-health \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --run-id "runtime-run-health" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence-bad" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/evidence-health-bad.json" >/dev/null
  grep -q '"failureCode": "runtime_evidence_artifact_hash_mismatch"' "$tmpdir/evidence-health-bad.json"
  cargo run -p chio-cli -- runtime ops status \
    --supervisor-profile "$tmpdir/supervisor-profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence-bad" \
    --provider-bindings "$tmpdir/provider-bindings.json" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/status-bad-report.json" >/dev/null
  grep -q '"accepted": false' "$tmpdir/status-bad-report.json"
  grep -q '"evidenceSinkHealthy": false' "$tmpdir/status-bad-report.json"
  grep -q '"failureCode": "runtime_ops_status_degraded"' "$tmpdir/status-bad-report.json"
  if cargo run -p chio-cli -- runtime ops retention plan \
    --retention-profile "$tmpdir/retention-profile.json" \
    --store "$tmpdir/runtime.sqlite3" \
    --evidence-root "$tmpdir/evidence-missing" \
    --now-unix-ms 1800000001000 \
    --report "$tmpdir/retention-missing-report.json" >/dev/null 2>"$tmpdir/retention-missing.err"; then
    echo "retention planning unexpectedly accepted a missing evidence root" >&2
    exit 1
  fi
  grep -q 'requires existing evidence root' "$tmpdir/retention-missing.err"
}

run_failure_code_flow() {
  write_common_fixtures
  validate_schema "$runtime_schema_dir/failure-code-registry.schema.json" "$tmpdir/failure-code-registry.json"
  grep -rq 'runtime_provider_discovery_not_allowed' "$repo_root/crates/chio-runtime-core/src"
  grep -rq 'runtime_evidence_artifact_hash_mismatch' "$repo_root/crates/chio-runtime-core/src"
  grep -rq 'runtime_ops_supervisor_profile_stale' "$repo_root/crates/chio-runtime-core/src"
  grep -rq 'runtime_recovery_supervisor_profile_stale' "$repo_root/crates/chio-runtime-core/src"
}

case "$MODE" in
  "schema-only")
    run_schema_flow
    ;;
  "negative-only")
    run_negative_flow
    ;;
  "tick-only")
    run_tick_flow
    ;;
  "recovery-only")
    run_recovery_flow
    ;;
  "evidence-only")
    run_evidence_flow
    ;;
  "provider-only")
    run_provider_flow
    ;;
  "retention-only")
    run_retention_flow
    ;;
  "failure-codes-only")
    run_failure_code_flow
    ;;
  "full")
    cargo test -p chio-runtime-core runtime_ops
    cargo test -p chio-cli --bin chio chio_native_runtime_surface_parses
    run_schema_flow
    run_tick_flow
    run_status_flow
    run_recovery_flow
    run_evidence_flow
    run_provider_flow
    run_retention_flow
    run_negative_flow
    run_failure_code_flow
    ;;
esac
