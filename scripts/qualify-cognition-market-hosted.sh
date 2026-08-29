#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 022
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0

qualification_mode="promotion"
if [[ "${1:-}" == "--code-only" && "$#" -eq 1 ]]; then
  qualification_mode="code-only"
elif [[ "$#" -ne 0 ]]; then
  echo "usage: $0 [--code-only]" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "hosted cognition-market qualification requires python3 on PATH" >&2
  exit 1
fi
if [[ -z "${CHIO_TEST_POSTGRES_URL:-}" || -z "${CHIO_TEST_POSTGRES_RUNTIME_URL:-}" ]]; then
  echo "hosted cognition-market qualification requires PostgreSQL test URLs" >&2
  exit 1
fi

candidate_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ -n "${GITHUB_SHA:-}" && "${GITHUB_SHA}" != "${candidate_sha}" ]]; then
  echo "hosted cognition-market qualification GITHUB_SHA does not match HEAD" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "hosted cognition-market qualification requires a clean exact candidate" >&2
  exit 1
fi

output_root="target/release-qualification/cognition-market-hosted"
log_root="${output_root}/logs"
gate_index="${output_root}/gate-index.tsv"
report_path="${output_root}/qualification.json"
manifest_path="${output_root}/artifact-manifest.signed.json"
checksums_path="${output_root}/SHA256SUMS"
secret_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-hosted-qualification.XXXXXX")"
chmod 0700 "${secret_root}"
signing_seed="${secret_root}/qualification.seed"
cleanup_secrets() {
  rm -f "${signing_seed}"
  rmdir "${secret_root}" || true
}
trap cleanup_secrets EXIT

python3 - "${signing_seed}" <<'PY'
import os
import secrets
import sys

path = sys.argv[1]
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as seed_file:
    seed_file.write(secrets.token_hex(32) + "\n")
PY

rm -rf "${output_root}"
mkdir -p "${log_root}"
: >"${gate_index}"

run_gate() {
  local gate_id="$1"
  shift
  local log_path="${log_root}/${gate_id}.log"
  local command_display
  printf -v command_display '%q ' "$@"
  command_display="${command_display% }"
  printf '%s\t%s\t%s\n' \
    "${gate_id}" \
    "${log_path#"${output_root}"/}" \
    "${command_display}" >>"${gate_index}"
  printf 'hosted cognition-market gate %s: %s\n' \
    "${gate_id}" \
    "${command_display}" | tee "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run_gate format cargo fmt --all -- --check
run_gate rust-hygiene python3 scripts/check-rust-file-hygiene.py
run_gate workspace-layering bash scripts/check-workspace-layering.sh
run_gate fuzz-lock \
  cargo metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 --no-deps
run_gate signing-remote cargo test -p chio-signing-remote --all-targets
run_gate isolated-worker cargo test -p chio-finding-worker --all-targets
run_gate worker-daemon cargo test -p chio-finding-worker-daemon --all-targets
run_gate postgres-store cargo test -p chio-finding-market-store-postgres --all-targets
run_gate postgres-16-rls \
  cargo test -p chio-finding-market-store-postgres \
    --features postgres-integration --test postgres_store -- --test-threads=1
run_gate hosted-edge cargo test -p chio-finding-hosted-edge --all-targets
run_gate kernel-payment cargo test -p chio-kernel --lib payment
run_gate settlement cargo test -p chio-settle --all-targets
run_gate challenge-control \
  cargo test -p chio-control-plane --lib finding_challenge
run_gate purchase-control \
  cargo test -p chio-control-plane --lib finding_purchase
run_gate status-control \
  cargo test -p chio-control-plane --lib finding_status
run_gate hosted-profile \
  cargo test -p chio-control-plane --lib finding_hosted
run_gate hosted-cli cargo test -p chio-cli --bin chio hosted
run_gate hosted-secret-failure \
  cargo test -p chio-cli missing_secret_references_fail_closed
run_gate strict-clippy \
  cargo clippy \
    -p chio-signing-remote \
    -p chio-finding-worker \
    -p chio-finding-worker-daemon \
    -p chio-finding-market-store-postgres \
    -p chio-finding-hosted-edge \
    -p chio-settle \
    -p chio-kernel \
    -p chio-control-plane \
    -p chio-cli \
    -p chio-release-evidence \
    --all-targets \
    --features chio-finding-market-store-postgres/postgres-integration \
    -- -D warnings
run_gate codegen make codegen-check
run_gate release-evidence cargo test -p chio-release-evidence --all-targets
run_gate dependency-policy cargo deny check
run_gate supply-chain cargo vet check --locked

kvm_evidence_sha256=""
if [[ "${qualification_mode}" == "promotion" ]]; then
  run_gate real-kvm-canary ./scripts/qualify-cognition-market-kvm.sh
  kvm_manifest="target/release-qualification/cognition-market-kvm/artifact-manifest.signed.json"
  if [[ ! -s "${kvm_manifest}" ]]; then
    echo "hosted cognition-market KVM qualification produced no signed manifest" >&2
    exit 1
  fi
  kvm_evidence_sha256="$(sha256sum "${kvm_manifest}" | cut -d' ' -f1)"
fi

python3 - \
  "${candidate_sha}" \
  "${qualification_mode}" \
  "${kvm_evidence_sha256}" \
  "${gate_index}" \
  "${report_path}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

candidate_sha, mode, kvm_sha, gate_index_raw, report_path_raw = sys.argv[1:]
gate_index = Path(gate_index_raw)
report_path = Path(report_path_raw)
artifact_root = report_path.parent

gates = []
for line in gate_index.read_text(encoding="utf-8").splitlines():
    gate_id, relative_log, command = line.split("\t", 2)
    payload = (artifact_root / relative_log).read_bytes()
    gates.append(
        {
            "id": gate_id,
            "command": command,
            "result": "passed",
            "log": relative_log,
            "logSha256": hashlib.sha256(payload).hexdigest(),
        }
    )

promotion = mode == "promotion"
report = {
    "schema": "chio.finding.hosted-qualification.v1",
    "candidateSha": candidate_sha,
    "generatedAt": datetime.now(timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "source": "github-actions"
    if os.environ.get("GITHUB_ACTIONS") == "true"
    else "local",
    "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
    "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "mode": mode,
    "decision": "promote" if promotion else "qualified-code-boundary",
    "promotionReady": promotion,
    "kvmEvidenceSha256": kvm_sha or None,
    "claims": [
        "claim.finding.hosted_postgres_rls_forced",
        "claim.finding.hosted_runtime_role_least_privilege",
        "claim.finding.hosted_remote_custody",
        "claim.finding.hosted_settlement_transport",
        "claim.finding.hosted_worker_protocol",
    ],
    "gates": gates,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY

rm -f "${gate_index}"
cargo run -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --repo-root . \
  --artifact-root "${output_root}" \
  --signing-seed "${signing_seed}" \
  --output "${manifest_path}" \
  --checksums "${checksums_path}" \
  --expected-candidate "${candidate_sha}"
cargo run -p chio-release-evidence \
  --bin chio-release-qualification-manifest -- \
  --verify \
  --repo-root . \
  --artifact-root "${output_root}" \
  --output "${manifest_path}" \
  --checksums "${checksums_path}" \
  --expected-candidate "${candidate_sha}"

printf 'hosted cognition-market %s qualification passed for %s; evidence: %s\n' \
  "${qualification_mode}" \
  "${candidate_sha}" \
  "${manifest_path}"
