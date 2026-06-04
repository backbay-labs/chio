#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${EXAMPLE_ROOT}/../.." && pwd)"

CHIO_BIN="${CHIO_BIN:-${ROOT}/target/debug/chio}"
if [[ ! -x "${CHIO_BIN}" ]]; then
  (cd "${ROOT}" && cargo build --bin chio >/dev/null)
fi

ARTIFACT_ROOT="${EXAMPLE_ROOT}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")"
INPUT_DIR="${ARTIFACT_ROOT}/input-package"
TAMPERED_DIR="${ARTIFACT_ROOT}/tampered-package"
mkdir -p "${ARTIFACT_ROOT}"

cp -R "${EXAMPLE_ROOT}/fixtures/minimal-evidence" "${INPUT_DIR}"
cp -R "${EXAMPLE_ROOT}/fixtures/minimal-evidence" "${TAMPERED_DIR}"

"${CHIO_BIN}" evidence verify --input "${INPUT_DIR}" --json > "${ARTIFACT_ROOT}/verify.json"

python3 - "${TAMPERED_DIR}/query.json" <<'PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_text('{"tampered":true}\n', encoding="utf-8")
PY

if "${CHIO_BIN}" evidence verify --input "${TAMPERED_DIR}" --json > "${ARTIFACT_ROOT}/tamper-out.json" 2> "${ARTIFACT_ROOT}/tamper-err.json"; then
  echo "expected tampered package verification to fail" >&2
  exit 1
fi

python3 "${EXAMPLE_ROOT}/verify_artifacts.py" \
  "${ARTIFACT_ROOT}" \
  --write-summary \
  > "${ARTIFACT_ROOT}/artifact-validation.json"

RECEIPT_ID="$(python3 - "${ARTIFACT_ROOT}/summary.json" <<'PY'
import json
import sys
from pathlib import Path

print(json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))["receipt_id"])
PY
)"

cat <<EOF
hello-receipt-verify smoke passed
artifacts: ${ARTIFACT_ROOT}
receipt id: ${RECEIPT_ID}
EOF
