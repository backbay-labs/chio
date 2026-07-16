#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

apalache_bin="${APALACHE_BIN:-apalache-mc}"
output_root="${CHIO_RECEIPT_TRACE_OUTPUT_DIR:-target/formal/receipt-trace}"
report_path="${CHIO_RECEIPT_TRACE_REPORT:-target/formal/trace-validation.json}"
target_dir="${CARGO_TARGET_DIR:-target}"
pinned_key_path="formal/tla/trace/fixtures/native-conformance-observer-key.txt"

python3 - "${output_root}" "${report_path}" "${repo_root}" <<'PY'
from pathlib import Path
import sys

repo = Path(sys.argv[3]).resolve()
target = (repo / "target").resolve()

def checked_target_path(raw: str, label: str) -> Path:
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repo / candidate
    for parent in [candidate, *candidate.parents]:
        if parent == repo.parent:
            break
        if parent.exists() and parent.is_symlink():
            raise SystemExit(f"check-receipt-trace: refusing symlinked {label} component: {parent}")
    resolved = candidate.resolve()
    if target not in resolved.parents:
        raise SystemExit(f"check-receipt-trace: {label} must be strictly below target")
    return resolved

output = checked_target_path(sys.argv[1], "output directory")
report = checked_target_path(sys.argv[2], "report path")
if output == (target / "formal").resolve():
    raise SystemExit("check-receipt-trace: output directory cannot replace target/formal")
if report == output:
    raise SystemExit("check-receipt-trace: report path cannot equal the output directory")
PY

rm -rf -- "${output_root}"
mkdir -p "${output_root}" "$(dirname "${report_path}")"

cargo build -p chio-conformance \
  --bin chio-native-conformance-runner \
  --bin chio-native-conformance-fixture \
  -p chio-trace-validate \
  --bin chio-trace-validate

cargo test -p chio-conformance --lib runtime_trace_refuses_a_dropped_admission_callback
cargo test -p chio-conformance --lib runtime_trace_mutations_reach_the_formal_projection
cargo test -p chio-conformance --test runtime_trace_corpus

checker_binary="$(realpath "$(command -v "${apalache_bin}")")"
if [[ ! -x "${checker_binary}" ]]; then
  echo "check-receipt-trace: checker is not executable: ${checker_binary}" >&2
  exit 2
fi
timeout_binary="$(realpath "$(command -v timeout || command -v gtimeout)")"
if [[ ! -x "${timeout_binary}" ]]; then
  echo "check-receipt-trace: timeout wrapper is not executable: ${timeout_binary}" >&2
  exit 2
fi

runner="${target_dir}/debug/chio-native-conformance-runner"
fixture="${target_dir}/debug/chio-native-conformance-fixture"
validator="${target_dir}/debug/chio-trace-validate"
for executable in "${runner}" "${fixture}" "${validator}"; do
  if [[ ! -x "${executable}" ]]; then
    echo "check-receipt-trace: missing executable ${executable}" >&2
    exit 2
  fi
done

listen_port="$(python3 - <<'PY'
import socket

with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PY
)"
"${fixture}" --http-listen "127.0.0.1:${listen_port}" \
  >"${output_root}/fixture-http.log" 2>&1 &
fixture_pid=$!
cleanup() {
  kill "${fixture_pid}" >/dev/null 2>&1 || true
  wait "${fixture_pid}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 1
"${runner}" \
  --stdio-command "${fixture}" \
  --http-base-url "http://127.0.0.1:${listen_port}" \
  --results-output "${output_root}/native-results.json" \
  --report-output "${output_root}/native-report.md" \
  --trace-output "${output_root}/conformance.ndjson" \
  --trace-negative-output "${output_root}/runtime-negative.ndjson" \
  --trace-monotone-negative-output "${output_root}/runtime-negative-monotone.ndjson" \
  --trace-attenuation-negative-output "${output_root}/runtime-negative-attenuation.ndjson" \
  --trace-freshness-negative-output "${output_root}/runtime-negative-freshness.ndjson" \
  --trace-observer-key-output "${output_root}/conformance-observer-key.txt"
cleanup
trap - EXIT

trusted_key="$(tr -d '\r\n' <"${pinned_key_path}")"
if [[ -z "${trusted_key}" ]]; then
  echo "check-receipt-trace: pinned conformance observer key is empty" >&2
  exit 2
fi

"${validator}" \
  --log "${output_root}/conformance.ndjson" \
  --trusted-key "${trusted_key}" \
  --apalache-bin "${apalache_bin}" \
  --require-revoke 1 \
  --require-post-revocation-evaluate 1 \
  --itf-output "${output_root}/conformance.itf.json" \
  --witness-output "${output_root}/conformance-witness.itf.json" \
  --report-output "${report_path}"

fixture_key="$(tr -d '\r\n' <formal/tla/trace/fixtures/trusted-observer-key.txt)"
"${validator}" \
  --log formal/tla/trace/fixtures/revocation-good.ndjson \
  --trusted-key "${fixture_key}" \
  --apalache-bin "${apalache_bin}" \
  --require-revoke 1 \
  --require-post-revocation-evaluate 1 \
  --itf-output "${output_root}/fixture-good.itf.json" \
  --witness-output "${output_root}/fixture-good-witness.itf.json" \
  --report-output "${output_root}/fixture-good-report.json"

validate_runtime_negative() {
  local slug="$1"
  local expected_invariant="$2"
  local input="${output_root}/runtime-negative${slug:+-${slug}}.ndjson"
  local artifact="${output_root}/runtime-negative${slug:+-${slug}}"
  set +e
  "${validator}" \
    --log "${input}" \
    --trusted-key "${trusted_key}" \
    --apalache-bin "${apalache_bin}" \
    --require-revoke 1 \
    --require-post-revocation-evaluate 1 \
    --itf-output "${artifact}.itf.json" \
    --witness-output "${artifact}-witness.itf.json" \
    --report-output "${artifact}-report.json" \
    >"${artifact}.log" 2>&1
  local negative_exit=$?
  set -e
  if [[ "${negative_exit}" -eq 0 ]]; then
    echo "check-receipt-trace: runtime ${expected_invariant} mutation unexpectedly validated" >&2
    exit 1
  fi
  python3 - "${artifact}-report.json" "${expected_invariant}" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
expected = sys.argv[2]
divergence = report.get("divergence", {})
evaluation = divergence.get("apalacheEvaluation", {})
if report.get("schema") != "chio.trace-validation.v1" or report.get("status") != "failed":
    raise SystemExit(f"check-receipt-trace: runtime {expected} mutation has no failed v2 report")
if divergence.get("failedConjunct") != expected or evaluation.get(expected) is not False:
    raise SystemExit(f"check-receipt-trace: runtime mutation did not falsify {expected} in Apalache")
PY
}

validate_runtime_negative "" "NoAllowAfterRevoke"
validate_runtime_negative "monotone" "MonotoneLog"
validate_runtime_negative "attenuation" "AttenuationPreserving"
validate_runtime_negative "freshness" "RevocationFreshness"

set +e
"${validator}" \
  --log formal/tla/trace/fixtures/allow-after-revoke.ndjson \
  --trusted-key "${fixture_key}" \
  --apalache-bin "${apalache_bin}" \
  --itf-output "${output_root}/fixture-bad.itf.json" \
  --witness-output "${output_root}/fixture-bad-witness.itf.json" \
  --report-output "${output_root}/fixture-bad-report.json" \
  >"${output_root}/fixture-bad.log" 2>&1
negative_exit=$?
set -e
if [[ "${negative_exit}" -eq 0 ]]; then
  echo "check-receipt-trace: allow-after-revoke fixture unexpectedly validated" >&2
  exit 1
fi

python3 scripts/check-receipt-trace-negative-registry.py \
  --registry formal/tla/trace/negative-registry.toml \
  --report NoAllowAfterRevoke="${output_root}/runtime-negative-report.json" \
  --report MonotoneLog="${output_root}/runtime-negative-monotone-report.json" \
  --report AttenuationPreserving="${output_root}/runtime-negative-attenuation-report.json" \
  --report RevocationFreshness="${output_root}/runtime-negative-freshness-report.json"

python3 scripts/check-receipt-trace-bindings.py \
  --report "${report_path}" \
  --model formal/tla/RevocationPropagation.tla \
  --trace-check-model formal/tla/trace/TraceCheckRevocationPropagation.tla \
  --trace-evaluation-model formal/tla/trace/TraceEvaluateRevocationPropagation.tla \
  --log "${output_root}/conformance.ndjson" \
  --itf "${output_root}/conformance.itf.json" \
  --witness "${output_root}/conformance-witness.itf.json" \
  --checker-binary "${checker_binary}" \
  --timeout-binary "${timeout_binary}" \
  --generated-observer-key "${output_root}/conformance-observer-key.txt" \
  --pinned-observer-key "${pinned_key_path}" \
  --negative-registry formal/tla/trace/negative-registry.toml \
  --extra-artifact nativeResults="${output_root}/native-results.json" \
  --extra-artifact nativeReport="${output_root}/native-report.md" \
  --extra-artifact fixtureHttpLog="${output_root}/fixture-http.log" \
  --extra-artifact fixtureGoodItf="${output_root}/fixture-good.itf.json" \
  --extra-artifact fixtureGoodWitness="${output_root}/fixture-good-witness.itf.json" \
  --extra-artifact fixtureGoodReport="${output_root}/fixture-good-report.json" \
  --extra-artifact fixtureBadItf="${output_root}/fixture-bad.itf.json" \
  --extra-artifact fixtureBadWitness="${output_root}/fixture-bad-witness.itf.json" \
  --extra-artifact fixtureBadReport="${output_root}/fixture-bad-report.json" \
  --extra-artifact fixtureBadLog="${output_root}/fixture-bad.log" \
  --extra-artifact runtimeNegativeLog="${output_root}/runtime-negative.log" \
  --extra-artifact runtimeNegativeTrace="${output_root}/runtime-negative.ndjson" \
  --extra-artifact runtimeNegativeItf="${output_root}/runtime-negative.itf.json" \
  --extra-artifact runtimeNegativeWitness="${output_root}/runtime-negative-witness.itf.json" \
  --extra-artifact runtimeNegativeReport="${output_root}/runtime-negative-report.json" \
  --extra-artifact monotoneNegativeLog="${output_root}/runtime-negative-monotone.log" \
  --extra-artifact monotoneNegativeTrace="${output_root}/runtime-negative-monotone.ndjson" \
  --extra-artifact monotoneNegativeItf="${output_root}/runtime-negative-monotone.itf.json" \
  --extra-artifact monotoneNegativeWitness="${output_root}/runtime-negative-monotone-witness.itf.json" \
  --extra-artifact monotoneNegativeReport="${output_root}/runtime-negative-monotone-report.json" \
  --extra-artifact attenuationNegativeLog="${output_root}/runtime-negative-attenuation.log" \
  --extra-artifact attenuationNegativeTrace="${output_root}/runtime-negative-attenuation.ndjson" \
  --extra-artifact attenuationNegativeItf="${output_root}/runtime-negative-attenuation.itf.json" \
  --extra-artifact attenuationNegativeWitness="${output_root}/runtime-negative-attenuation-witness.itf.json" \
  --extra-artifact attenuationNegativeReport="${output_root}/runtime-negative-attenuation-report.json" \
  --extra-artifact freshnessNegativeLog="${output_root}/runtime-negative-freshness.log" \
  --extra-artifact freshnessNegativeTrace="${output_root}/runtime-negative-freshness.ndjson" \
  --extra-artifact freshnessNegativeItf="${output_root}/runtime-negative-freshness.itf.json" \
  --extra-artifact freshnessNegativeWitness="${output_root}/runtime-negative-freshness-witness.itf.json" \
  --extra-artifact freshnessNegativeReport="${output_root}/runtime-negative-freshness-report.json" \
  --output "${output_root}/bindings.json"

python3 - "${report_path}" "${output_root}" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
output_root = Path(sys.argv[2])
good = json.loads((output_root / "fixture-good-report.json").read_text(encoding="utf-8"))
bad = json.loads((output_root / "fixture-bad-report.json").read_text(encoding="utf-8"))
runtime_bad = json.loads(
    (output_root / "runtime-negative-report.json").read_text(encoding="utf-8")
)

for label, value in (("conformance", report), ("known-good", good)):
    if value.get("schema") != "chio.trace-validation.v1":
        raise SystemExit(f"check-receipt-trace: {label} report schema is invalid")
    if value.get("status") != "passed":
        raise SystemExit(f"check-receipt-trace: {label} trace did not pass")
    coverage = value.get("actionCoverage", {})
    if coverage.get("revoke", 0) < 1 or coverage.get("postRevocationEvaluate", 0) < 1:
        raise SystemExit(f"check-receipt-trace: {label} trace is vacuous")
    witnesses = value.get("invariantWitnesses", {})
    if any(witnesses.get(name, 0) < 1 for name in (
        "allowReceipt",
        "orderedReceiptPair",
        "attenuatedAdmission",
        "nonzeroRevocationEpoch",
    )):
        raise SystemExit(f"check-receipt-trace: {label} invariant witnesses are vacuous")
    if len(value.get("apalacheWitnessSha256", "")) != 64:
        raise SystemExit(f"check-receipt-trace: {label} lacks the Apalache ITF witness hash")

for label, rejected in (("runtime bypass", runtime_bad), ("checked fixture", bad)):
    divergence = rejected.get("divergence", {})
    if rejected.get("status") != "failed":
        raise SystemExit(f"check-receipt-trace: {label} report did not fail")
    if divergence.get("step") != 3:
        raise SystemExit(f"check-receipt-trace: {label} divergence moved from step 3")
    if divergence.get("failedConjunct") != "NoAllowAfterRevoke":
        raise SystemExit(f"check-receipt-trace: {label} failed the wrong conjunct")
    evaluation = divergence.get("apalacheEvaluation", {})
    if evaluation.get("NoAllowAfterRevoke") is not False:
        raise SystemExit(f"check-receipt-trace: {label} lacks the Apalache witness")

bad_divergence = bad.get("divergence", {})
if not bad_divergence.get("projectedStep") or not bad_divergence.get("lastReachableState"):
    raise SystemExit("check-receipt-trace: divergence report is missing both trace states")
PY

echo "Receipt trace validation passed"
