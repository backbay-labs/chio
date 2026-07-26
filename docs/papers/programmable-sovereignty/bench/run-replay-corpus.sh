#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../../../.." && pwd)
SOURCE=${CHIO_SOURCE:-$ROOT}
if [[ ! -d "$SOURCE/crates" || ! -f "$SOURCE/Cargo.toml" ]]; then
  echo "CHIO_SOURCE does not name a Chio workspace: $SOURCE" >&2
  exit 2
fi
SOURCE_COMMIT="$(git -C "$SOURCE" rev-parse HEAD)"
if [[ -n "$(git -C "$SOURCE" status --short)" ]]; then
  SOURCE_DIRTY=true
else
  SOURCE_DIRTY=false
fi
BENCHMARK_INPUT_TREE_SHA256="$(
  python3 "$SOURCE/scripts/generate-programmable-sovereignty-artifact.py" \
    --source-commit "$SOURCE_COMMIT" \
    --benchmark-input-digest PS-B02
)"

RESULT_DIR="${CHIO_PAPER_RESULT_DIR:-$SCRIPT_DIR/results}"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-replay-target}"
THREAT_FIXTURE="$SOURCE/examples/chio-3vendor/fixtures/treaty-runtime-negative-corpus.json"
mkdir -p "$RESULT_DIR" "$TARGET_DIR"

GENERIC_LOG="$RESULT_DIR/replay-generic.log"
BILATERAL_LOG="$RESULT_DIR/replay-bilateral.log"
CSV="$RESULT_DIR/replay-corpus.csv"
JSON="$RESULT_DIR/replay-corpus.json"
INLINE="$RESULT_DIR/replay-corpus-inline.tex"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}

generic_start=$(date +%s)
if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" CHIO_BLESS=0 cargo test -p chio-replay-gate --test golden_byte_equivalence
) > "$GENERIC_LOG" 2>&1; then
  emit_unreported
  exit 1
fi
generic_end=$(date +%s)

if grep -a -q 'all_50_goldens_match_byte_for_byte ... ok' "$GENERIC_LOG"; then
  generic_count=50
else
  generic_count=$(grep -a -E 'test result: ok' "$GENERIC_LOG" | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "passed;" && i > 1) {
          total += $(i - 1);
        }
      }
    }
    END {
      if (total > 0) {
        printf "%d", total;
      }
    }
  ' || true)
fi
if [[ -z "$generic_count" || "$generic_count" -lt 1 ]]; then
  emit_unreported
  exit 1
fi

bilateral_start=$(date +%s)
if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" \
    bash scripts/check-chio-live-treaty-buyer-closure.sh --matrix-only
) > "$BILATERAL_LOG" 2>&1; then
  emit_unreported
  exit 1
fi
bilateral_end=$(date +%s)

read -r bilateral_count assumption_count < <(
  python - "$THREAT_FIXTURE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fixture_file:
    fixture = json.load(fixture_file)
print(len(fixture["cases"]), len(fixture["assumptions"]))
PY
)

if ! grep -a -q "bilateral threat matrix passed: $bilateral_count executable cases" "$BILATERAL_LOG"; then
  emit_unreported
  exit 1
fi

generic_seconds=$((generic_end - generic_start))
bilateral_seconds=$((bilateral_end - bilateral_start))

{
  printf 'corpus,cases,elapsed_seconds,assumptions\n'
  printf 'generic_replay,%d,%d,0\n' "$generic_count" "$generic_seconds"
  printf 'bilateral_threat_matrix,%d,%d,%d\n' \
    "$bilateral_count" "$bilateral_seconds" "$assumption_count"
} > "$CSV"

python - "$JSON" "$INLINE" "$SOURCE_COMMIT" "$SOURCE_DIRTY" \
  "$BENCHMARK_INPUT_TREE_SHA256" \
  "$generic_count" "$generic_seconds" "$bilateral_count" \
  "$bilateral_seconds" "$assumption_count" <<'PY'
import json
import sys

(
    output,
    inline,
    source_commit,
    source_dirty,
    benchmark_input_tree_sha256,
    generic_count,
    generic_seconds,
    bilateral_count,
    bilateral_seconds,
    assumptions,
) = sys.argv[1:]
document = {
    "schema": "chio.programmable-sovereignty.replay-results.v1",
    "commit": source_commit,
    "worktreeDirty": source_dirty == "true",
    "benchmarkInputTreeSha256": benchmark_input_tree_sha256,
    "genericReplay": {
        "cases": int(generic_count),
        "elapsedSeconds": int(generic_seconds),
    },
    "bilateralThreatMatrix": {
        "cases": int(bilateral_count),
        "elapsedSeconds": int(bilateral_seconds),
        "explicitNonTestableAssumptions": int(assumptions),
    },
}
with open(output, "w", encoding="utf-8") as output_file:
    json.dump(document, output_file, indent=2, sort_keys=True)
    output_file.write("\n")
macros = [
    ("PSGenericReplayCases", generic_count),
    ("PSGenericReplaySeconds", generic_seconds),
    ("PSBilateralReplayCases", bilateral_count),
    ("PSBilateralReplaySeconds", bilateral_seconds),
    ("PSReplayAssumptionCount", assumptions),
]
with open(inline, "w", encoding="utf-8") as inline_file:
    for name, value in macros:
        inline_file.write(f"\\newcommand{{\\{name}}}{{{value}}}\n")
PY
