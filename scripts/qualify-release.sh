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

output_root="target/release-qualification"
conformance_root="${output_root}/conformance"
log_root="${output_root}/logs"
coverage_root="${output_root}/coverage"
formal_root="${output_root}/formal"
peer_root="${output_root}/peers"
checksum_path="${output_root}/SHA256SUMS"
manifest_path="${output_root}/artifact-manifest.json"
certify_seed="${output_root}/certify-release.seed"

# ci-workspace is the fast regression gate.
./scripts/ci-workspace.sh
rm -rf \
  "${conformance_root}" \
  "${log_root}" \
  "${coverage_root}" \
  "${formal_root}" \
  "${peer_root}"
mkdir -p \
  "${conformance_root}" \
  "${log_root}" \
  "${coverage_root}" \
  "${formal_root}" \
  "${peer_root}"
install -m 0644 target/formal/proof-report.json "${formal_root}/proof-report.json"
install -m 0644 target/formal/coverage.json "${formal_root}/coverage.json"

required_formal_lane_count="$(
  python3 - <<'PY'
import tomllib

with open("releases.toml", "rb") as release_config:
    document = tomllib.load(release_config)

gates = document.get("gates")
if not isinstance(gates, dict) or not gates:
    raise SystemExit("releases.toml does not define any formal gates")

postures = [gate.get("posture") for gate in gates.values() if isinstance(gate, dict)]
if len(postures) != len(gates) or any(
    posture not in {"advisory", "required"} for posture in postures
):
    raise SystemExit("releases.toml contains an invalid formal gate posture")

print(sum(posture == "required" for posture in postures))
PY
)"
if [[ "$required_formal_lane_count" -gt 0 ]]; then
  ./scripts/lane-gate.sh --fleet
else
  echo "release qualification: no formal lanes are required; fleet check skipped"
fi
cargo test -p chio-provider-conformance \
  --features fixtures-gemini,fixtures-mistral,fixtures-groq,fixtures-ollama,fixtures-cohere \
  --test replay_gemini \
  --test replay_mistral \
  --test replay_groq \
  --test replay_ollama \
  --test replay_cohere
./scripts/qualify-trust-control.sh
./scripts/qualify-portable-browser.sh
./scripts/qualify-mobile-kernel.sh
./scripts/check-dashboard-release.sh
./scripts/check-chio-ts-release.sh
./scripts/check-chio-py-release.sh
./scripts/check-chio-go-release.sh

# Flagship demo + launch-acceptance regression assets (lane wiring).
cargo build -p chio-cli --bin chio
CHIO_BIN="$(pwd)/target/debug/chio" bash ./scripts/check-chio-transaction-passport.sh
CHIO_BIN="$(pwd)/target/debug/chio" cargo xtask verify launch-acceptance --out target/proof-room/public-bundle
bash ./scripts/tests/check-chio-proof-room-launch-acceptance.test.sh
CHIO_BIN="$(pwd)/target/debug/chio" bash ./scripts/tests/flagship-wall-stops-money.test.sh

# Unified spend/exposure contract regression (governance + codegen + endpoint).
bash ./scripts/check-chio-schema-registry.sh
bash ./scripts/check-comptroller-contract-no-drift.sh
bash ./scripts/check-no-eip3009-broadcast.sh
bash ./scripts/qualify-comptroller-operator-surfaces.sh
read_release_python_peer() {
  python3 - <<'PY'
import sys
import tomllib

expected_target = "x86_64-unknown-linux-gnu"
with open("crates/tooling/chio-conformance/peers.lock.toml", "rb") as fh:
    lock = tomllib.load(fh)

selected = next(
    (
        peer
        for peer in lock.get("peer", [])
        if (
            peer.get("language") == "python"
            and peer.get("target") == expected_target
            and peer.get("published", True)
        )
    ),
    None,
)
if selected is None:
    print(
        "release qualification requires a published python peer for "
        f"{expected_target} in crates/tooling/chio-conformance/peers.lock.toml",
        file=sys.stderr,
    )
    raise SystemExit(1)

print(f"{selected['target']}\t{selected['binary']}")
PY
}

run_external_consumer_smoke() {
  local peer_target="$1"
  local peer_binary="$2"
  local report_path="${conformance_root}/external-consumer-smoke-report.json"

  cargo run -p chio-cli --bin chio -- conformance fetch-peers \
    --language python \
    --out "${peer_root}"

  cargo run -p chio-cli --bin chio -- conformance run \
    --peer python \
    --peer-binary "${peer_root}/python-${peer_target}/${peer_binary}" \
    --report json \
    --output "${report_path}"
}

IFS=$'\t' read -r release_python_target release_python_binary < <(read_release_python_peer)
run_external_consumer_smoke "${release_python_target}" "${release_python_binary}"

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
