#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT
cd "${repo_root}"

report="${tmp_dir}/report.json"
cat >"${report}" <<'JSON'
{
  "schema": "chio.spec-mutants-report.v1",
  "commit": "1111111111111111111111111111111111111111",
  "enumerated": 2,
  "full_cycle": true,
  "aggregate": {
    "sampled": 2,
    "killed": 1,
    "survived": 1,
    "unviable": 0,
    "timeout": 0,
    "activation_ratio_percent": 50.0
  },
  "mutants": [
    {
      "id": "22222222222222222222",
      "verdict": "survived",
      "spec": "Fixture",
      "action": "Evaluate",
      "original": "TRUE",
      "replacement": "FALSE"
    },
    {
      "id": "33333333333333333333",
      "verdict": "killed",
      "spec": "Fixture",
      "action": "Deny"
    }
  ]
}
JSON

dry_run="$(python3 scripts/file-mutation-survivors.py --dry-run "${report}")"
grep -Fq '22222222222222222222' <<<"${dry_run}"
if grep -Fq '33333333333333333333' <<<"${dry_run}"; then
  echo "dry run included a killed mutant" >&2
  exit 1
fi

fake_gh="${tmp_dir}/gh"
cat >"${fake_gh}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\0' "$@" >>"${FAKE_GH_ARGUMENTS}"
if [[ "${1:-}" == "issue" && "${2:-}" == "list" ]]; then
  printf '%s\n' '[]'
  exit 0
fi
if [[ "${1:-}" == "issue" && "${2:-}" == "create" ]]; then
  printf '%s\n' 'https://example.invalid/issues/1'
  exit 0
fi
exit 2
SH
chmod +x "${fake_gh}"

GH_BIN="${fake_gh}" FAKE_GH_ARGUMENTS="${tmp_dir}/arguments" \
  python3 scripts/file-mutation-survivors.py "${report}" >"${tmp_dir}/run.log"
grep -Fq 'created=1 existing=0' "${tmp_dir}/run.log"
python3 - "${tmp_dir}/arguments" <<'PY'
from pathlib import Path
import sys

arguments = Path(sys.argv[1]).read_bytes().split(b"\0")
text = b"\n".join(arguments).decode("utf-8")
if "mutation-id: 22222222222222222222" not in text:
    raise SystemExit("created issue omitted its stable mutation identifier")
if '"original": "TRUE"' not in text or '"replacement": "FALSE"' not in text:
    raise SystemExit("created issue omitted the mutation change")
if "report:" not in text:
    raise SystemExit("created issue omitted the report reference")
if "33333333333333333333" in text:
    raise SystemExit("issue workflow touched a killed mutant")
PY

python3 - "${report}" "${tmp_dir}/invalid-verdict.json" <<'PY'
import json
from pathlib import Path
import sys

report = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
report["mutants"][0]["verdict"] = "SURVIVED"
Path(sys.argv[2]).write_text(json.dumps(report), encoding="utf-8")
PY
if python3 scripts/file-mutation-survivors.py --dry-run \
  "${tmp_dir}/invalid-verdict.json" >"${tmp_dir}/invalid-verdict.log" 2>&1; then
  echo "invalid mutation verdict unexpectedly passed" >&2
  exit 1
fi
grep -Fq "invalid verdict" "${tmp_dir}/invalid-verdict.log"

echo "PASS: formal mutation survivors receive idempotent issue identities"
