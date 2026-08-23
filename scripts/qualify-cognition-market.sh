#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
umask 022

if ! command -v python3 >/dev/null 2>&1; then
  echo "cognition-market qualification requires python3 on PATH" >&2
  exit 1
fi

candidate_sha="$(git rev-parse HEAD)"
if [[ -n "${GITHUB_SHA:-}" && "${GITHUB_SHA}" != "${candidate_sha}" ]]; then
  echo "cognition-market qualification GITHUB_SHA does not match HEAD" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain --untracked-files=all)" ]]; then
  echo "cognition-market qualification requires a clean candidate worktree" >&2
  exit 1
fi

output_root="target/release-qualification/cognition-market"
log_root="${output_root}/logs"
gate_index="${output_root}/gate-index.tsv"
report_path="${output_root}/qualification.json"
report_sha_path="${output_root}/qualification.json.sha256"

rm -rf "${output_root}"
mkdir -p "${log_root}"
: >"${gate_index}"

export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

run_gate() {
  local gate_id="$1"
  shift
  local log_path="${log_root}/${gate_id}.log"
  local command_display
  printf -v command_display '%q ' "$@"
  command_display="${command_display% }"
  printf '%s\t%s\t%s\n' \
    "${gate_id}" \
    "${log_path#target/release-qualification/cognition-market/}" \
    "${command_display}" >>"${gate_index}"
  printf 'cognition-market gate %s: %s\n' "${gate_id}" "${command_display}" | tee "${log_path}"
  "$@" 2>&1 | tee -a "${log_path}"
}

run_gate bounded-profile \
  cargo xtask qualify bounded-chio
run_gate production-router-profile \
  cargo test -p chio-control-plane cognition_market_qualified_profile --lib -- \
    --nocapture --test-threads=1
run_gate same-second-revocation-store \
  cargo test -p chio-store-sqlite \
    revocation_sequence_does_not_skip_same_second_backfill --lib -- \
    --nocapture --test-threads=1
run_gate revocation-store-epoch-index \
  cargo test -p chio-store-sqlite \
    v3_store_migrates_stream_identity_and_projection_history_index --lib -- \
    --nocapture --test-threads=1
run_gate mixed-version-revocation-delta \
  cargo test -p chio-control-plane \
    revocation_delta_endpoint_negotiates_legacy_and_sequence_cursors --lib -- \
    --nocapture --test-threads=1
run_gate revocation-puller-soundness \
  cargo test -p chio-control-plane pull_budget_tests --lib -- \
    --nocapture --test-threads=1
run_gate revocation-snapshot-soundness \
  cargo test -p chio-control-plane \
    revocation_snapshot_is_projection_bounded_and_epoch_bound --lib -- \
    --nocapture --test-threads=1
run_gate legacy-revocation-recovery \
  cargo test -p chio-control-plane \
    legacy_revocation_snapshot_recovers_projection_without_reusing_tuple_cursor --lib -- \
    --nocapture --test-threads=1
run_gate same-second-revocation-cluster \
  cargo test -p chio-cli --test trust_cluster \
    trust_control_cluster_repeat_run_qualification -- \
    --ignored --nocapture --test-threads=1
if rg -n -F \
  "skipping trust_control_cluster_repeat_run_qualification: loopback bind denied:" \
  "${log_root}/same-second-revocation-cluster.log"; then
  echo "cognition-market clustered revocation evidence was skipped" >&2
  exit 1
fi
run_gate public-purchase-route \
  cargo test -p chio-control-plane cognition_market_live_purchase_route_exit --lib -- \
    --nocapture --test-threads=1
run_gate digest-mismatch-zero-charge \
  cargo test -p chio-control-plane wedge_purchase_digest_mismatch_denies_and_releases --lib -- \
    --nocapture --test-threads=1
run_gate cli-finding-surface \
  cargo test -p chio-cli dispatch_cli::finding_cmd --bin chio -- \
    --nocapture --test-threads=1
run_gate transaction-passport \
  cargo test -p chio-transaction-passport --test cognition_market -- \
    --nocapture --test-threads=1
run_gate open-market-flow \
  cargo test -p chio-open-market --test cognition_market_flow -- \
    --nocapture --test-threads=1
run_gate authenticated-pool-ledger \
  cargo test -p chio-store-sqlite --test finding_pool_ledger -- \
    --nocapture --test-threads=1

if rg -n "skipping finding " "${log_root}/cli-finding-surface.log"; then
  echo "cognition-market CLI live-route evidence was skipped" >&2
  exit 1
fi

python3 - "${candidate_sha}" "${gate_index}" "${report_path}" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

candidate_sha = sys.argv[1]
gate_index = Path(sys.argv[2])
report_path = Path(sys.argv[3])
artifact_root = report_path.parent

dogfood_prefix = "cognition-market-dogfood-result "
dogfood_lines = [
    line.split(dogfood_prefix, 1)[1]
    for line in (artifact_root / "logs/public-purchase-route.log")
    .read_text(encoding="utf-8")
    .splitlines()
    if dogfood_prefix in line
]
if len(dogfood_lines) != 1:
    raise SystemExit(
        "public purchase route must emit exactly one cognition-market dogfood result"
    )
dogfood = json.loads(dogfood_lines[0])
expected_dogfood = {
    "formatVersion": 1,
    "scenario": "same-second-revocation-cursor-verified-fix",
    "settlement": "captured",
    "currency": "USD",
    "realizedSpendUnits": 300,
    "captureCount": 1,
    "sellerInvocationCount": 1,
    "replayByteIdentical": True,
    "sourceRegression": [
        "crates/platform/chio-store-sqlite/src/revocation_store.rs",
        "crates/products/chio-cli/tests/trust_cluster.rs",
    ],
}
for field, expected in expected_dogfood.items():
    if dogfood.get(field) != expected:
        raise SystemExit(
            f"invalid cognition-market dogfood field {field}: "
            f"{dogfood.get(field)!r} != {expected!r}"
        )
for field in (
    "findingId",
    "payloadSha256",
    "purchaseRequestId",
    "reservationId",
    "deliveryReceiptId",
    "purchaseRecordSha256",
):
    value = dogfood.get(field)
    if not isinstance(value, str) or not value:
        raise SystemExit(f"cognition-market dogfood result lacks {field}")
for field in ("findingId", "payloadSha256", "purchaseRecordSha256"):
    value = dogfood[field]
    if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise SystemExit(f"cognition-market dogfood result has invalid {field}")

gates = []
for line in gate_index.read_text(encoding="utf-8").splitlines():
    gate_id, relative_log, command = line.split("\t", 2)
    log_path = artifact_root / relative_log
    payload = log_path.read_bytes()
    gates.append(
        {
            "id": gate_id,
            "command": command,
            "result": "passed",
            "log": relative_log,
            "logSha256": hashlib.sha256(payload).hexdigest(),
        }
    )

report = {
    "formatVersion": 1,
    "profile": "cognition-market-single-operator",
    "candidateSha": candidate_sha,
    "generatedAt": datetime.now(timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "source": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
    "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
    "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "decision": "qualified-single-operator-candidate",
    "claims": [
        "claim.finding.delivery_digest_bound",
        "claim.finding.evidence_bound",
        "claim.finding.status_fresh",
        "claim.finding.bond_backed",
    ],
    "auditedAssumptions": [
        "ASSUME-FINDING-STATUS-OPERATOR-COMPLETENESS",
        "ASSUME-FINDING-SELLER-TOOL-SERVER",
    ],
    "m7": {
        "triggered": False,
        "disposition": "conditional-unbuilt",
        "basis": "no verified bilateral seller and buyer deployment request",
    },
    "dogfood": dogfood,
    "gates": gates,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
PY

(
  cd "${output_root}"
  sha256sum "$(basename "${report_path}")" >"$(basename "${report_sha_path}")"
)
rm -f "${gate_index}"
printf 'cognition-market qualification passed for %s; report: %s\n' \
  "${candidate_sha}" \
  "${report_path}"
