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
manifest_path="${output_root}/artifact-manifest.signed.json"
release_secret_root="$(mktemp -d "${TMPDIR:-/tmp}/chio-release-qualification.XXXXXX")"
chmod 0700 "${release_secret_root}"
certify_seed="${release_secret_root}/certify-release.seed"
cleanup_release_secrets() {
  rm -f "${certify_seed}"
  rmdir "${release_secret_root}" || true
}
trap cleanup_release_secrets EXIT

candidate_sha="$(git rev-parse --verify 'HEAD^{commit}')"
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "release qualification requires a clean exact candidate" >&2
  exit 1
fi
if [[ -n "${GITHUB_SHA:-}" && "${GITHUB_SHA}" != "${candidate_sha}" ]]; then
  echo "GITHUB_SHA does not match the checked-out release candidate" >&2
  exit 1
fi

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

# Bind the promoted cognition-market profile, live local routes, CLI surface,
# passport, and durable pool to this exact release candidate.
./scripts/qualify-cognition-market.sh
./scripts/qualify-cognition-market-hosted.sh

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
release_peer_lock="crates/tooling/chio-conformance/peers.lock.toml"
read_release_python_peer() {
  python3 - "${release_peer_lock}" <<'PY'
import sys
import tomllib

expected_target = "x86_64-unknown-linux-gnu"
lock_path = sys.argv[1]
with open(lock_path, "rb") as fh:
    lock = tomllib.load(fh)

matching = [
    peer
    for peer in lock.get("peer", [])
    if (
        peer.get("language") == "python"
        and peer.get("target") == expected_target
    )
]
if len(matching) != 1:
    raise SystemExit(
        "release qualification requires exactly one python peer row for "
        f"{expected_target} in {lock_path}; found {len(matching)}"
    )

selected = matching[0]
if selected.get("published") is False:
    print("source-pre-release\t\t")
else:
    print(f"published\t{selected['target']}\t{selected['binary']}")

PY
}

run_external_consumer_smoke() {
  local peer_mode="$1"
  local peer_target="$2"
  local peer_binary="$3"
  local report_path="${conformance_root}/external-consumer-smoke-report.json"
  local mode_path="${conformance_root}/external-consumer-smoke-mode.txt"
  local scenario_root="tests/conformance/scenarios/mcp_core"

  case "${peer_mode}" in
    published)
      # Published rows prove the immutable download and digest boundary.
      cargo run -p chio-cli --bin chio -- conformance fetch-peers \
        --lockfile "${release_peer_lock}" \
        --language python \
        --out "${peer_root}"

      cargo run -p chio-cli --bin chio -- conformance run \
        --peer python \
        --peer-binary "${peer_root}/python-${peer_target}/${peer_binary}" \
        --report json \
        --output "${report_path}"
      ;;
    source-pre-release)
      # Pre-release locks prove their shape, then execute the real source peer.
      cargo run -p chio-cli --bin chio -- conformance fetch-peers \
        --lockfile "${release_peer_lock}" \
        --language python \
        --check \
        --allow-unpublished-only

      cargo run -p chio-cli --bin chio -- conformance run \
        --peer python \
        --report json \
        --output "${report_path}"
      ;;
    *)
      echo "unknown release python peer mode: ${peer_mode}" >&2
      return 1
      ;;
  esac

  python3 - "${report_path}" "${scenario_root}" <<'PY'
import json
import sys
from pathlib import Path

report_path = sys.argv[1]
scenario_root = Path(sys.argv[2])
with open(report_path, encoding="utf-8") as report_file:
    report = json.load(report_file)

expected_ids = []
for scenario_path in sorted(scenario_root.rglob("*.json")):
    with scenario_path.open(encoding="utf-8") as scenario_file:
        scenario = json.load(scenario_file)
    if scenario.get("expected") != "pass":
        raise SystemExit(
            f"external consumer smoke scenario is not required: {scenario_path}"
        )
    scenario_id = scenario.get("id")
    if not isinstance(scenario_id, str) or not scenario_id:
        raise SystemExit(
            f"external consumer smoke scenario has no valid id: {scenario_path}"
        )
    expected_ids.append(scenario_id)
if not expected_ids or len(expected_ids) != len(set(expected_ids)):
    raise SystemExit(
        "external consumer smoke descriptors are empty or have duplicate ids"
    )

results = report.get("results")
scenario_count = report.get("scenarioCount")
if not isinstance(results, list) or not results:
    raise SystemExit("external consumer smoke produced no scenario results")
reported_ids = [result.get("scenarioId") for result in results]
if (
    scenario_count != len(expected_ids)
    or len(results) != len(expected_ids)
    or sorted(reported_ids) != sorted(expected_ids)
):
    raise SystemExit(
        "external consumer smoke scenario ids do not match required descriptors"
    )

unexpected = [
    result.get("scenarioId", "<unknown>")
    for result in results
    if result.get("status") != "pass"
]
if unexpected:
    raise SystemExit(
        "external consumer smoke has unexpected failures: "
        + ", ".join(unexpected)
    )
PY

  printf '%s\n' "${peer_mode}" >"${mode_path}"
}

release_python_selection="$(read_release_python_peer)"
IFS=$'\t' read -r \
  release_python_mode \
  release_python_target \
  release_python_binary <<<"${release_python_selection}"
run_external_consumer_smoke \
  "${release_python_mode}" \
  "${release_python_target}" \
  "${release_python_binary}"

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

cargo run -p chio-release-evidence --bin chio-release-qualification-manifest -- \
  --repo-root . \
  --artifact-root "${output_root}" \
  --signing-seed "${certify_seed}" \
  --output "${manifest_path}" \
  --checksums "${checksum_path}" \
  --expected-candidate "${candidate_sha}"
