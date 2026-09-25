#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "comptroller federation qualification requires cargo on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "comptroller federation qualification requires python3 on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/comptroller-federation"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/CHIO_FEDERATED_OPERATOR_PROOF_MATRIX.json"
matrix_snapshot="${output_root}/CHIO_FEDERATED_OPERATOR_PROOF_MATRIX.json"
proof_src="docs/release/CHIO_COMPTROLLER_FEDERATED_PROOF.md"
proof_snapshot="${output_root}/CHIO_COMPTROLLER_FEDERATED_PROOF.md"
cargo_target_dir="target/qualify-comptroller-federation-build"

rm -rf "${output_root}"
mkdir -p "${log_root}"

run_and_log() {
  local name="$1"
  shift
  local log_path="${log_root}/${name}.log"
  echo "==> ${name}"
  "$@" 2>&1 | tee "${log_path}"
  if ! grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "${log_path}"; then
    echo "${name} did not execute exactly one passing test" >&2
    return 1
  fi
  if grep -Eq 'skipping .*: loopback bind denied:' "${log_path}"; then
    echo "${name} skipped its loopback-backed assertions" >&2
    return 1
  fi
}

python3 -m json.tool "${matrix_src}" >/dev/null
cp "${matrix_src}" "${matrix_snapshot}"
cp "${proof_src}" "${proof_snapshot}"

export CARGO_TARGET_DIR="${cargo_target_dir}"

run_and_log multi-hop-lineage \
  cargo test -p chio-cli --test federated_issue trust_service_federated_issue_supports_multi_hop_imported_upstream_parent -- --exact --nocapture
run_and_log evidence-import \
  cargo test -p chio-cli --test evidence_export evidence_import_roundtrip_surfaces_imported_trust_without_rewriting_local_history -- --exact --nocapture
run_and_log reconciliation-review \
  cargo test -p chio-cli --test receipt_query_export test_settlement_reconciliation_report_and_action_endpoint -- --exact --nocapture
run_and_log adversarial-open-market \
  cargo test -p chio-cli --test certify certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust -- --exact --ignored --nocapture

cat >"${report_path}" <<'EOF'
# Comptroller Federated Multi-Operator Qualification

This bundle records the focused proof that Chio supports one bounded
multi-operator economic/trust flow rather than only internal federation-shaped
capabilities.

Decision:

- Chio qualifies locally for bounded federated multi-operator proof.
- Multi-hop imported upstream lineage, imported evidence without local-history
  rewrite, governed reconciliation review, and adversarial multi-operator
  visibility are all exercised on explicit trust boundaries.

Still not proved:

- ecosystem-wide operator dependence on Chio
- an unavoidable market position across independent economic networks

Executed command set:

- `cargo test -p chio-cli --test federated_issue trust_service_federated_issue_supports_multi_hop_imported_upstream_parent -- --exact --nocapture`
- `cargo test -p chio-cli --test evidence_export evidence_import_roundtrip_surfaces_imported_trust_without_rewriting_local_history -- --exact --nocapture`
- `cargo test -p chio-cli --test receipt_query_export test_settlement_reconciliation_report_and_action_endpoint -- --exact --nocapture`
- `cargo test -p chio-cli --test certify certify_adversarial_multi_operator_open_market_preserves_visibility_without_trust -- --exact --ignored --nocapture`

Supporting documents:

- `CHIO_FEDERATED_OPERATOR_PROOF_MATRIX.json`
- `CHIO_COMPTROLLER_FEDERATED_PROOF.md`
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
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "scope": "comptroller_federated_operator_qualification",
    "decision": "bounded_federated_multi_operator_flow_qualified_market_position_not_yet_qualified",
    "claimLevel": "federated_multi_operator_proof",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
