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
import os
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

expected_top_level = {
    "schema",
    "crate",
    "script",
    "unwinding_checks",
    "harness_groups",
    "covered_symbols",
    "lanes",
}
if set(data) != expected_top_level:
    raise SystemExit(
        "check-kani-public-core.sh: manifest top-level keys must be exactly "
        f"{sorted(expected_top_level)}"
    )

lanes = data.get("lanes")
if not isinstance(lanes, dict):
    raise SystemExit("check-kani-public-core.sh: manifest has no lanes table")
expected_lanes = {"pr", "nightly_only"}
if set(lanes) != expected_lanes:
    raise SystemExit(
        "check-kani-public-core.sh: manifest lanes must be exactly pr and nightly_only"
    )

unwinding_checks = data.get("unwinding_checks", [])
if not isinstance(unwinding_checks, list) or not all(
    isinstance(name, str) and name for name in unwinding_checks
):
    raise SystemExit(
        "check-kani-public-core.sh: unwinding_checks must be a string list"
    )
if len(set(unwinding_checks)) != len(unwinding_checks):
    raise SystemExit("check-kani-public-core.sh: duplicate unwinding_checks entry")

all_harnesses = []
lane_harnesses_by_name = {}
seen = set()
for lane_name in ("pr", "nightly_only"):
    lane = lanes[lane_name]
    if not isinstance(lane, dict):
        raise SystemExit(f"check-kani-public-core.sh: lanes.{lane_name} must be a table")
    if set(lane) != {"description", "harnesses"}:
        raise SystemExit(
            f"check-kani-public-core.sh: lanes.{lane_name} must contain only "
            "description and harnesses"
        )
    if not isinstance(lane.get("description"), str) or not lane["description"]:
        raise SystemExit(
            f"check-kani-public-core.sh: lanes.{lane_name}.description must be non-empty"
        )
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
        all_harnesses.append(name)
    lane_harnesses_by_name[lane_name] = lane_harnesses

selected_lanes = ("pr", "nightly_only") if lane_filter == "all" else (lane_filter,)
harnesses = [
    name
    for lane_name in selected_lanes
    for name in lane_harnesses_by_name[lane_name]
]

if not harnesses and not list_only:
    raise SystemExit(f"check-kani-public-core.sh: lane {lane_filter} is empty")

source_path = Path(
    os.environ.get(
        "KANI_PUBLIC_HARNESSES_SOURCE",
        "crates/kernel/chio-kernel-core/src/kani_public_harnesses.rs",
    )
)
try:
    source = source_path.read_text(encoding="utf-8")
except OSError as error:
    raise SystemExit(
        f"check-kani-public-core.sh: cannot read {source_path}: {error}"
    ) from error

proof_functions = re.findall(
    r"(?m)^\s*#\s*\[\s*kani::proof\s*\]\s*"
    r"(?:#\s*\[[^\n]+\]\s*)*"
    r"(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    source,
)
if len(proof_functions) != len(set(proof_functions)):
    raise SystemExit("check-kani-public-core.sh: duplicate #[kani::proof] function")
known_harnesses = set(all_harnesses)
source_harnesses = set(proof_functions)
missing_from_source = sorted(known_harnesses - source_harnesses)
unregistered = sorted(source_harnesses - known_harnesses)
if missing_from_source or unregistered:
    raise SystemExit(
        "check-kani-public-core.sh: source and registry harness sets differ: "
        f"missing_from_source={missing_from_source} unregistered={unregistered}"
    )

unknown_checks = sorted(set(unwinding_checks) - known_harnesses)
if unknown_checks:
    raise SystemExit(
        f"check-kani-public-core.sh: unwinding_checks names unknown harnesses: {unknown_checks}"
    )

print("\n".join(
    f"{name}\t{'true' if name in unwinding_checks else 'false'}"
    for name in harnesses
))
PY
)

if [[ "$LIST_ONLY" -eq 1 ]]; then
  if [[ -n "$HARNESSES" ]]; then
    while IFS=$'\t' read -r harness _; do
      [[ -n "$harness" ]] && printf '%s\n' "$harness"
    done <<< "$HARNESSES"
  fi
  exit 0
fi

if ! cargo kani --version >/dev/null 2>&1; then
  echo "Kani public core check requires cargo-kani" >&2
  exit 1
fi

COUNT=0
while IFS=$'\t' read -r harness unwinding_checks; do
  [[ -n "$harness" ]] || continue
  echo "::group::cargo kani --harness ${harness}"
  args=(
    -p chio-kernel-core --lib --harness "$harness"
    --default-unwind 8
  )
  if [[ "$unwinding_checks" != "true" ]]; then
    args+=(--no-unwinding-checks)
  fi
  cargo kani "${args[@]}"
  echo "::endgroup::"
  COUNT=$((COUNT + 1))
done <<< "$HARNESSES"

echo "Kani public core harnesses passed (${COUNT} harnesses, lane ${LANE_FILTER})"
