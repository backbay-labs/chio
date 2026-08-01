#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "comptroller operator-surface qualification requires cargo on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "comptroller operator-surface qualification requires python3 on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/comptroller-operator-surfaces"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
profile_src="docs/standards/CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json"
profile_snapshot="${output_root}/CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json"
runbook_src="docs/release/CHIO_COMPTROLLER_OPERATOR_RUNBOOK.md"
runbook_snapshot="${output_root}/CHIO_COMPTROLLER_OPERATOR_RUNBOOK.md"
cargo_target_dir="target/qualify-comptroller-operator-surfaces-build"

rm -rf "${output_root}"
mkdir -p "${log_root}"

run_surface_test() {
  local binary="$1" name="$2"
  local out
  out="$(cargo test -p chio-cli --test "$binary" "$name" -- --exact 2>&1)"
  echo "$out"
  if ! grep -Eq "test result: ok\. [1-9][0-9]* passed" <<<"$out"; then
    echo "FAIL: $binary::$name did not run a nonzero passing test count (false-green guard)" >&2
    exit 1
  fi
}

python3 -m json.tool "${profile_src}" >/dev/null
cp "${profile_src}" "${profile_snapshot}"
cp "${runbook_src}" "${runbook_snapshot}"

export CARGO_TARGET_DIR="${cargo_target_dir}"

run_surface_test receipt_query_export        test_operator_report_endpoint
run_surface_test receipt_query_export        test_settlement_reconciliation_report_and_action_endpoint
run_surface_test receipt_query_export        test_metered_billing_reconciliation_report_and_action_endpoint
run_surface_test receipt_query_authorization test_authorization_context_report_and_cli
run_surface_test receipt_query_underwriting  test_underwriting_decision_issue_and_list_surfaces
run_surface_test receipt_query_credit_exposure test_credit_facility_report_issue_and_list_surfaces
run_surface_test receipt_query_capital       test_capital_book_report_export_surfaces
run_surface_test receipt_query_export        test_comptroller_surface_report_endpoint

cat >"${report_path}" <<'EOF'
# Comptroller Operator-Surface Qualification

This bundle records the focused post-v3.16 proof that Chio exposes explicit
operator-facing economic control surfaces rather than only crate-internal
comptroller primitives.

Decision:

- Chio qualifies locally for operator-facing economic control surfaces.
- The trust-control service exposes report and action endpoints over governed
  operator evidence, settlement reconciliation, metered billing
  reconciliation, authorization-context review, and comptroller surface.
- Signed underwriting, credit, capital, and liability artifacts are available
  through explicit trust-control issuance surfaces.

Still not proved:

- independent third-party operators running these surfaces in production
- partner economic dependence on Chio as a market control layer

Executed command set:

- `cargo test -p chio-cli --test receipt_query_export test_operator_report_endpoint -- --exact`
- `cargo test -p chio-cli --test receipt_query_export test_settlement_reconciliation_report_and_action_endpoint -- --exact`
- `cargo test -p chio-cli --test receipt_query_export test_metered_billing_reconciliation_report_and_action_endpoint -- --exact`
- `cargo test -p chio-cli --test receipt_query_authorization test_authorization_context_report_and_cli -- --exact`
- `cargo test -p chio-cli --test receipt_query_underwriting test_underwriting_decision_issue_and_list_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query_credit_exposure test_credit_facility_report_issue_and_list_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query_capital test_capital_book_report_export_surfaces -- --exact`
- `cargo test -p chio-cli --test receipt_query_export test_comptroller_surface_report_endpoint -- --exact`

Supporting documents:

- `CHIO_OPERATOR_CONTROL_SURFACE_PROFILE.json`
- `CHIO_COMPTROLLER_OPERATOR_RUNBOOK.md`
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
    "scope": "comptroller_operator_surface_qualification",
    "decision": "externally_operable_control_surfaces_defined_and_exercised_locally",
    "claimLevel": "operator_control_surfaces",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
