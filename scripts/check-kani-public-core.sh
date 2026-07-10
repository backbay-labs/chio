#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

LANE_FILTER="pr"
LIST_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lane)
      if [[ $# -lt 2 || -z "$2" ]]; then
        echo "check-kani-public-core.sh: --lane requires a value" >&2
        exit 2
      fi
      LANE_FILTER="$2"
      shift 2
      ;;
    --list)
      LIST_ONLY=1
      shift
      ;;
    -h|--help)
      cat <<'EOF'
Usage: scripts/check-kani-public-core.sh [--lane pr|nightly_only|all] [--list]

Reads the public core harness registry and runs the selected Kani lane.
--list prints the selected harness names without invoking Kani.
EOF
      exit 0
      ;;
    *)
      echo "check-kani-public-core.sh: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

MANIFEST="${KANI_PUBLIC_HARNESSES_MANIFEST:-formal/rust-verification/kani-public-harnesses.toml}"
if [[ ! -f "$MANIFEST" ]]; then
  echo "check-kani-public-core.sh: missing manifest $MANIFEST" >&2
  exit 1
fi

HARNESSES=$(python3 - "$MANIFEST" "$LANE_FILTER" "$LIST_ONLY" <<'PY'
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

manifest_path = Path(sys.argv[1])
lane_filter = sys.argv[2]
list_only = sys.argv[3] == "1"
if lane_filter not in {"pr", "nightly_only", "all"}:
    raise SystemExit(
        "check-kani-public-core.sh: --lane must be pr, nightly_only, or all"
    )

try:
    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, tomllib.TOMLDecodeError) as error:
    raise SystemExit(
        f"check-kani-public-core.sh: cannot parse {manifest_path}: {error}"
    ) from error

if data.get("schema") != "chio.kani-public-harnesses.v1":
    raise SystemExit("check-kani-public-core.sh: unsupported manifest schema")
if data.get("crate") != "chio-kernel-core":
    raise SystemExit("check-kani-public-core.sh: manifest crate must be chio-kernel-core")
if data.get("script") != "scripts/check-kani-public-core.sh":
    raise SystemExit("check-kani-public-core.sh: manifest script path does not match")

lanes = data.get("lanes")
if not isinstance(lanes, dict):
    raise SystemExit("check-kani-public-core.sh: manifest has no lanes table")

selected_lanes = ("pr", "nightly_only") if lane_filter == "all" else (lane_filter,)
harnesses = []
seen = set()
for lane_name in selected_lanes:
    lane = lanes.get(lane_name)
    if not isinstance(lane, dict):
        raise SystemExit(f"check-kani-public-core.sh: missing lanes.{lane_name}")
    lane_harnesses = lane.get("harnesses")
    if not isinstance(lane_harnesses, list) or not all(
        isinstance(name, str) and name for name in lane_harnesses
    ):
        raise SystemExit(
            f"check-kani-public-core.sh: lanes.{lane_name}.harnesses must be a string list"
        )
    for name in lane_harnesses:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise SystemExit(f"check-kani-public-core.sh: invalid harness name {name!r}")
        if name in seen:
            raise SystemExit(f"check-kani-public-core.sh: duplicate harness {name}")
        seen.add(name)
        harnesses.append(name)

if not harnesses and not list_only:
    raise SystemExit(f"check-kani-public-core.sh: lane {lane_filter} is empty")

source_path = Path("crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs")
try:
    source = source_path.read_text(encoding="utf-8")
except OSError as error:
    raise SystemExit(
        f"check-kani-public-core.sh: cannot read {source_path}: {error}"
    ) from error

missing = [
    name
    for name in harnesses
    if re.search(rf"\bfn\s+{re.escape(name)}\s*\(", source) is None
]
if missing:
    raise SystemExit(f"check-kani-public-core.sh: missing harness functions: {missing}")

print("\n".join(harnesses))
PY
)

if [[ "$LIST_ONLY" -eq 1 ]]; then
  if [[ -n "$HARNESSES" ]]; then
    printf '%s\n' "$HARNESSES"
  fi
  exit 0
fi

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani public core check requires cargo-kani" >&2
  exit 1
fi

COUNT=0
while IFS= read -r harness; do
  [[ -n "$harness" ]] || continue
  echo "::group::cargo kani --harness ${harness}"
  cargo kani -p chio-kernel-core --lib --harness "$harness" \
    --default-unwind 8 --no-unwinding-checks
  echo "::endgroup::"
  COUNT=$((COUNT + 1))
done <<< "$HARNESSES"

echo "Kani public core harnesses passed (${COUNT} harnesses, lane ${LANE_FILTER})"
