#!/usr/bin/env bash
# Adversarial-vector to threat-model citation gate.
#
# Owner: chio-maintainers.
#
# Walks `crates/chio-adversarial-suite/cases/<class>/<id>.json` and
# asserts that every non-pending vector cites at least one threat ID
# that exists in `spec/security/chio-threat-model.v1.json`. Vectors
# with `pending: true` are auto-promoted from libFuzzer crashes
# and are excepted from the citation gate until human triage strips
# the flag.
#
# Fails closed: any non-pending vector with an empty / missing
# `threat_id`, or with a `threat_id` that does not appear in the
# threat-model JSON, exits non-zero.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

THREAT_MODEL="$REPO_ROOT/spec/security/chio-threat-model.v1.json"
CASES_DIR="$REPO_ROOT/crates/chio-adversarial-suite/cases"

if [[ ! -f "$THREAT_MODEL" ]]; then
    echo "error: threat model not found at $THREAT_MODEL" >&2
    exit 1
fi
if [[ ! -d "$CASES_DIR" ]]; then
    echo "error: adversarial cases directory not found at $CASES_DIR" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required to parse JSON for this gate" >&2
    exit 1
fi

python3 - "$THREAT_MODEL" "$CASES_DIR" <<'PY'
import json, os, sys
from pathlib import Path

threat_model_path = Path(sys.argv[1])
cases_root = Path(sys.argv[2])

with open(threat_model_path) as fh:
    doc = json.load(fh)
known = {t["id"] for t in doc.get("threats", [])}

bad = []
ok = 0
pending = 0
total = 0

for case_path in sorted(cases_root.rglob("*.json")):
    total += 1
    try:
        with open(case_path) as fh:
            case = json.load(fh)
    except Exception as e:
        bad.append((case_path, f"malformed JSON: {e}"))
        continue
    if case.get("pending", False):
        pending += 1
        continue
    tid = case.get("threat_id", "")
    if not isinstance(tid, str) or not tid.strip():
        bad.append((case_path, "missing or empty threat_id"))
        continue
    if tid not in known:
        bad.append((case_path, f"threat_id {tid!r} is not in chio-threat-model.v1.json"))
        continue
    ok += 1

print(f"adversarial vector citation gate:")
print(f"  total: {total}")
print(f"  pending (excepted): {pending}")
print(f"  cites valid threat ID: {ok}")
print(f"  invalid: {len(bad)}")

if bad:
    print("", file=sys.stderr)
    print("FAIL: adversarial-vector citation gate", file=sys.stderr)
    for path, reason in bad:
        rel = path.relative_to(cases_root.parent.parent.parent) if cases_root.parent.parent.parent in path.parents else path
        print(f"  - {rel}: {reason}", file=sys.stderr)
    print("", file=sys.stderr)
    print("hint: every non-pending adversarial case must cite a `threat_id` that", file=sys.stderr)
    print("       appears in spec/security/chio-threat-model.v1.json. Vectors with", file=sys.stderr)
    print("       `pending: true` are excepted until human triage strips the flag.", file=sys.stderr)
    sys.exit(1)

print("PASS: every non-pending adversarial vector cites a known threat ID.")
PY
