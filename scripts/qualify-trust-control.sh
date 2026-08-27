#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

output_root="target/release-qualification/trust-control"
log_root="${output_root}/logs"
report_path="${output_root}/qualification-report.md"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"

rm -rf "${output_root}"
mkdir -p "${log_root}"

run_check() {
  local slug="$1"
  shift
  local log_path="${log_root}/${slug}.log"
  "$@" 2>&1 | tee "${log_path}"
  if ! grep -Eq "test result: ok\. [1-9][0-9]* passed" "${log_path}"; then
    echo "trust-control check ${slug} did not run a nonzero passing test count" >&2
    exit 1
  fi
}

run_check node-identity \
  cargo test -p chio-cli --test trust_cluster \
  trust_control_cluster_internal_status_requires_signed_node_identity -- --nocapture

run_check quorum-heal \
  cargo test -p chio-cli --test trust_cluster \
  trust_control_cluster_requires_quorum_and_heals_after_partition -- --nocapture

run_check stale-leader-fencing \
  cargo test -p chio-cli --test trust_cluster \
  trust_control_cluster_rejects_stale_authority_term_after_failover_and_restart -- --nocapture

run_check denied-event-replication \
  cargo test -p chio-cli --test trust_cluster \
  trust_control_cluster_replicates_denied_budget_events_without_usage_rows -- --nocapture

run_check replay-and-failover \
  cargo test -p chio-cli --test trust_cluster \
  trust_control_cluster_snapshot_replays_holds_and_mutation_events -- --nocapture

run_check duplicate-event-rejection \
  cargo test -p chio-store-sqlite --lib \
  budget_store::tests::budget_store_event_id_retry_rejects_authority_rollover_sqlite -- \
  --exact --nocapture

run_check stale-lease-rejection \
  cargo test -p chio-store-sqlite --test integration_smoke \
  sqlite_budget_hold_authority_metadata_persists_across_reopen -- \
  --exact --nocapture

cat >"${report_path}" <<'EOF'
# Trust-Control Qualification

This bundle records the authoritative trust-control qualification gate for the
current Chio closure program.

Executed checks:

- signed peer node identity is required for internal cluster surfaces
- quorum loss fails budget writes closed and healed peers recover from snapshot
- stale leaders are fenced after failover and restart
- deny-only budget mutations replicate without usage-row projections
- mutation-event replay preserves hold history and follower repair
- duplicate budget event ids reject divergent authority metadata
- stale budget lease metadata fails closed across reopen

Primary logs:

- `logs/node-identity.log`
- `logs/quorum-heal.log`
- `logs/stale-leader-fencing.log`
- `logs/denied-event-replication.log`
- `logs/replay-and-failover.log`
- `logs/duplicate-event-rejection.log`
- `logs/stale-lease-rejection.log`
EOF

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output_root = Path(sys.argv[1])
checksum_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])

entries = []
for artifact in sorted(output_root.rglob("*")):
    if not artifact.is_file():
        continue
    if artifact in {checksum_path, manifest_path}:
        continue
    payload = artifact.read_bytes()
    entries.append(
        {
            "path": artifact.relative_to(output_root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    )

checksum_path.write_text(
    "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)
)

manifest = {
    "generatedAt": datetime.now(timezone.utc)
    .replace(microsecond=0)
    .isoformat()
    .replace("+00:00", "Z"),
    "scope": "trust_control_authoritative_qualification",
    "artifacts": entries,
    "requirements": [
        "node_identity",
        "stale_leader_rejection",
        "duplicate_event_rejection",
        "stale_lease_rejection",
        "replay_safety",
        "failover_preservation",
    ],
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
