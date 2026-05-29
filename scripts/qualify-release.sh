#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v node >/dev/null 2>&1; then
  echo "release qualification requires node on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "release qualification requires python3 on PATH" >&2
  exit 1
fi

# ci-workspace remains the fast regression gate.
./scripts/ci-workspace.sh
./scripts/qualify-trust-control.sh
./scripts/qualify-portable-browser.sh
./scripts/qualify-mobile-kernel.sh
./scripts/check-dashboard-release.sh
./scripts/check-chio-ts-release.sh
./scripts/check-chio-py-release.sh
./scripts/check-chio-go-release.sh

output_root="target/release-qualification"
conformance_root="${output_root}/conformance"
log_root="${output_root}/logs"
coverage_root="${output_root}/coverage"
checksum_path="${output_root}/SHA256SUMS"
manifest_path="${output_root}/artifact-manifest.json"
certify_seed="${output_root}/certify-release.seed"
rm -rf "${conformance_root}" "${log_root}" "${coverage_root}"
mkdir -p "${conformance_root}" "${log_root}" "${coverage_root}"

run_conformance_area() {
  local area="$1"
  local scenarios_dir="$2"
  shift 2
  local area_dir="${conformance_root}/${area}"
  local report_path="${area_dir}/report.md"
  local certification_path="${area_dir}/certification.json"
  local certification_report_path="${area_dir}/certification-report.md"
  local verification_path="${area_dir}/certification-verify.json"
  mkdir -p "${area_dir}/results"
  cargo run -p chio-conformance --bin chio-conformance-runner -- \
    --scenarios-dir "${scenarios_dir}" \
    "$@" \
    --results-dir "${area_dir}/results" \
    --report-output "${report_path}"

  cargo run -p chio-cli --bin chio -- certify check \
    --scenarios-dir "${scenarios_dir}" \
    --results-dir "${area_dir}/results" \
    --output "${certification_path}" \
    --report-output "${certification_report_path}" \
    --tool-server-id "chio-conformance-${area}" \
    --tool-server-name "Chio Conformance ${area}" \
    --signing-seed-file "${certify_seed}"

  cargo run -p chio-cli --bin chio -- certify verify \
    --input "${certification_path}" >"${verification_path}"
}

run_conformance_area mcp-core tests/conformance/scenarios/mcp_core
run_conformance_area tasks tests/conformance/scenarios/tasks
run_conformance_area auth tests/conformance/scenarios/auth --auth-mode oauth-local
run_conformance_area notifications tests/conformance/scenarios/notifications
run_conformance_area nested-callbacks tests/conformance/scenarios/nested_callbacks

cargo test -p chio-cli --test trust_cluster trust_control_cluster_repeat_run_qualification -- --ignored --nocapture \
  | tee "${log_root}/trust-cluster-repeat-run.log"

COVERAGE_FAIL_UNDER=65 ./scripts/run-coverage.sh | tee "${log_root}/coverage.log"
cp -R coverage/. "${coverage_root}/"

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
from __future__ import annotations

import hashlib
import json
import os
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
    "source": "github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
    "candidateSha": os.environ.get("GITHUB_SHA", "local"),
    "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
    "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY
