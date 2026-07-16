#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="${repo_root}/scripts/check-receipt-trace-bindings.py"
scratch="$(mktemp -d)"
trap 'rm -rf "${scratch}"' EXIT

report="${scratch}/trace-validation.json"
model="${scratch}/RevocationPropagation.tla"
trace_check_model="${scratch}/TraceCheckRevocationPropagation.tla"
trace_evaluation_model="${scratch}/TraceEvaluateRevocationPropagation.tla"
log="${scratch}/conformance.ndjson"
itf="${scratch}/conformance.itf.json"
witness="${scratch}/conformance-witness.itf.json"
checker="${scratch}/apalache-mc"
timeout_binary="${scratch}/timeout"
generated_key="${scratch}/generated-key.txt"
pinned_key="${scratch}/pinned-key.txt"
negative_registry="${scratch}/negative-registry.toml"
bindings="${scratch}/bindings.json"
extra="${scratch}/extra-artifact.txt"
observer_key="c9571eeb4aa9de1159858bc6a3d4a626c4f4845e8eebd5f554b2ec0f50c68860"

printf '%s\n' '---- MODULE RevocationPropagation ----' >"${model}"
printf '%s\n' '---- MODULE TraceCheckRevocationPropagation ----' >"${trace_check_model}"
printf '%s\n' '---- MODULE TraceEvaluateRevocationPropagation ----' >"${trace_evaluation_model}"
printf '%s\n' '{"observation":1}' >"${log}"
printf '%s\n' '{"vars":[],"states":[{}]}' >"${itf}"
printf '%s\n' '{"vars":["evaluated"],"states":[{"evaluated":true}]}' >"${witness}"
printf '%s\n' '#!/usr/bin/env bash' 'echo 0.50.1' >"${checker}"
chmod +x "${checker}"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"${timeout_binary}"
chmod +x "${timeout_binary}"
printf '%s\n' "${observer_key}" >"${generated_key}"
printf '%s\n' "${observer_key}" >"${pinned_key}"
printf '%s\n' 'schema = "chio.runtime-trace-negative.v1"' >"${negative_registry}"
printf '%s\n' 'extra evidence' >"${extra}"

python3 - "${report}" "${model}" "${trace_check_model}" \
  "${trace_evaluation_model}" "${log}" "${itf}" "${witness}" \
  "${checker}" "${timeout_binary}" "${observer_key}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

report = Path(sys.argv[1])
model, trace_check, trace_evaluation, log, itf, witness, checker, timeout_binary = map(
    Path, sys.argv[2:10]
)
observer_key = sys.argv[10]

def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

report.write_text(
    json.dumps(
        {
            "schema": "chio.trace-validation.v1",
            "status": "passed",
            "traceId": "trace-selftest",
            "traceLength": 3,
            "itfStateCount": 1,
            "invariants": [
                "NoAllowAfterRevoke",
                "MonotoneLog",
                "AttenuationPreserving",
                "RevocationFreshness",
            ],
            "actionCoverage": {
                "revoke": 1,
                "evaluate": 2,
                "postRevocationEvaluate": 1,
            },
            "invariantWitnesses": {
                "allowReceipt": 1,
                "orderedReceiptPair": 1,
                "attenuatedAdmission": 1,
                "nonzeroRevocationEpoch": 1,
            },
            "observerKeys": [observer_key],
            "observerKeySetSha256": hashlib.sha256(observer_key.encode("ascii")).hexdigest(),
            "modelSha256": digest(model),
            "traceCheckModelSha256": digest(trace_check),
            "traceEvaluationModelSha256": digest(trace_evaluation),
            "logSha256": digest(log),
            "itfSha256": digest(itf),
            "apalacheWitnessSha256": digest(witness),
            "checkerBinarySha256": digest(checker),
            "timeoutBinarySha256": digest(timeout_binary),
        }
    )
    + "\n",
    encoding="utf-8",
)
PY

check_bindings() {
  python3 "${helper}" \
    --report "${report}" \
    --model "${model}" \
    --trace-check-model "${trace_check_model}" \
    --trace-evaluation-model "${trace_evaluation_model}" \
    --log "${log}" \
    --itf "${itf}" \
    --witness "${witness}" \
    --checker-binary "${checker}" \
    --timeout-binary "${timeout_binary}" \
    --generated-observer-key "${generated_key}" \
    --pinned-observer-key "${pinned_key}" \
    --negative-registry "${negative_registry}" \
    --extra-artifact extraEvidence="${extra}" \
    --output "${bindings}"
}

expect_failure() {
  local label="$1"
  if check_bindings >"${scratch}/${label}.log" 2>&1; then
    echo "check-receipt-trace-bindings.test: ${label} substitution unexpectedly passed" >&2
    exit 1
  fi
}

substitute_and_reject() {
  local path="$1"
  local label="$2"
  cp "${path}" "${path}.original"
  printf '%s\n' 'substituted artifact' >>"${path}"
  expect_failure "${label}"
  mv "${path}.original" "${path}"
}

check_bindings
python3 - "${bindings}" <<'PY'
import json
from pathlib import Path
import sys

value = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if value.get("schema") != "chio.trace-artifact-bindings.v1":
    raise SystemExit("binding selftest: output schema is invalid")
if len(value.get("artifactHashes", {})) != 13:
    raise SystemExit("binding selftest: output does not bind every input")
PY

printf '%064d\n' 0 >"${generated_key}"
expect_failure observer-key
printf '%s\n' "${observer_key}" >"${generated_key}"

substitute_and_reject "${model}" model
substitute_and_reject "${trace_check_model}" trace-check-model
substitute_and_reject "${trace_evaluation_model}" trace-evaluation-model
substitute_and_reject "${log}" log
substitute_and_reject "${itf}" itf
substitute_and_reject "${witness}" witness
substitute_and_reject "${checker}" checker
substitute_and_reject "${timeout_binary}" timeout
substitute_and_reject "${negative_registry}" negative-registry
substitute_and_reject "${extra}" extra-artifact

mv "${model}" "${model}.original"
ln -s "$(basename "${model}.original")" "${model}"
expect_failure model-symlink
rm "${model}"
mv "${model}.original" "${model}"

python3 - "${report}" <<'PY'
import json
from pathlib import Path
import sys

path = Path(sys.argv[1])
report = json.loads(path.read_text(encoding="utf-8"))
report["observerKeys"] = ["0" * 64]
path.write_text(json.dumps(report) + "\n", encoding="utf-8")
PY
expect_failure report-key

if CHIO_RECEIPT_TRACE_OUTPUT_DIR=target \
  "${repo_root}/scripts/check-receipt-trace.sh" >"${scratch}/unsafe-output.log" 2>&1; then
  echo "check-receipt-trace-bindings.test: target root output unexpectedly passed" >&2
  exit 1
fi
if ! grep -Fq 'strictly below target' "${scratch}/unsafe-output.log"; then
  echo "check-receipt-trace-bindings.test: target root failed for the wrong reason" >&2
  exit 1
fi

if CHIO_RECEIPT_TRACE_OUTPUT_DIR=target/formal/receipt-trace-selftest \
  CHIO_RECEIPT_TRACE_REPORT="${scratch}/outside-report.json" \
  "${repo_root}/scripts/check-receipt-trace.sh" >"${scratch}/unsafe-report.log" 2>&1; then
  echo "check-receipt-trace-bindings.test: outside report path unexpectedly passed" >&2
  exit 1
fi
if ! grep -Fq 'strictly below target' "${scratch}/unsafe-report.log"; then
  echo "check-receipt-trace-bindings.test: outside report failed for the wrong reason" >&2
  exit 1
fi

echo "check-receipt-trace-bindings.test: artifact substitutions are rejected"
