#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$SCRIPT_DIR/../../.." && pwd)
SOURCE=${CHIO_SOURCE:-$ROOT}
if [[ ! -d "$SOURCE/crates" ]]; then
  SOURCE=$ROOT
fi

RESULT_DIR="$SCRIPT_DIR/results"
TARGET_DIR="${CHIO_TARGET_DIR:-${TMPDIR:-/tmp}/chio-programmable-sovereignty-dispatch-target}"
mkdir -p "$RESULT_DIR" "$TARGET_DIR"

LOG="$RESULT_DIR/dispatch-allow.log"
INLINE="$RESULT_DIR/dispatch-allow-inline.tex"

emit_unreported() {
  printf '\\textnormal{[unreported]}\n' > "$INLINE"
}

if ! (
  cd "$SOURCE"
  CARGO_TARGET_DIR="$TARGET_DIR" cargo bench -p chio-kernel --bench dispatch_allow -- \
    --sample-size 10 \
    --warm-up-time 1 \
    --measurement-time 2 \
    --noplot
) > "$LOG" 2>&1; then
  emit_unreported
  exit 1
fi

line=$(grep -a -E 'time:[[:space:]]+\[' "$LOG" | head -n 1 | perl -CS -pe 's/\x{00B5}/u/g' || true)
if [[ -z "$line" ]]; then
  emit_unreported
  exit 1
fi

summary=$(printf '%s\n' "$line" | awk '
  {
    for (i = 1; i <= NF; i++) {
      gsub(/\[/, "", $i);
      gsub(/\]/, "", $i);
      if ($i == "time:") {
        time_index = i;
      }
    }
    if (time_index > 0 && NF >= time_index + 6) {
      lower = time_index + 1;
      lower_unit = time_index + 2;
      median = time_index + 3;
      median_unit = time_index + 4;
      upper = time_index + 5;
      upper_unit = time_index + 6;
      printf "p50 %s %s (Criterion CI %s %s to %s %s)", $median, $median_unit, $lower, $lower_unit, $upper, $upper_unit;
    }
  }
')

if [[ -z "$summary" ]]; then
  emit_unreported
  exit 1
else
  printf '%s\n' "$summary" > "$INLINE"
fi
