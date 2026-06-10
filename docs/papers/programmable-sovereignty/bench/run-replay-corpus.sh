#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
SOURCE=${CHIO_SOURCE:-$ROOT}
if [[ ! -d "$SOURCE/crates" ]]; then
  SOURCE=$ROOT
fi

RESULT_DIR="$SCRIPT_DIR/results"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-replay-target}"
mkdir -p "$RESULT_DIR" "$TARGET_DIR"

LOG="$RESULT_DIR/replay-corpus.log"
INLINE="$RESULT_DIR/replay-corpus-inline.tex"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}

start=$(date +%s)
if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" CHIO_BLESS=0 cargo test -p chio-replay-gate --test golden_byte_equivalence
) > "$LOG" 2>&1; then
  emit_unreported
  exit 1
fi
end=$(date +%s)

if grep -a -q 'all_50_goldens_match_byte_for_byte ... ok' "$LOG"; then
  summary="50 replay goldens passed"
else
  summary=$(grep -a -E 'test result: ok' "$LOG" | awk '
    {
      for (i = 1; i <= NF; i++) {
        if ($i == "passed;" && i > 1) {
          total += $(i - 1);
        }
      }
    }
    END {
      if (total > 0) {
        printf "%d tests passed", total;
      }
    }
  ' || true)
fi
if [[ -z "$summary" ]]; then
  emit_unreported
  exit 1
fi

printf '%s in %ss\n' "$summary" "$((end - start))" > "$INLINE"
