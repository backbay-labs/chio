#!/usr/bin/env bash
# run-kani-manifest.sh
#
# Iterate `.kani/harnesses.toml` and invoke `cargo kani` for each
# (crate, harness) pair in the requested lane. It runs the kani sweep
# across every manifest crate, not just chio-kernel-core.
#
# Usage:
#   scripts/run-kani-manifest.sh [--lane pr|nightly] [--crate <name>]
#                                [--list] [--dry-run]
#
# Flags:
#   --lane <l>    Lane filter. Default `pr`. Matches the per-entry
#                 `lane = "pr"` / `lane = "nightly"` field.
#   --crate <c>   Optional crate filter; only entries with `crate = c`
#                 run. Useful for local debugging of a single crate.
#   --exclude-crate <c>
#                 Optional crate exclusion filter. Skip entries whose
#                 crate matches `c`. Used by CI to delegate
#                 chio-kernel-core to the narrowing script while still
#                 running every other manifest crate via this runner.
#                 May be repeated.
#   --list        Print one `<crate>::<harness>` line per matched entry
#                 and exit 0. Does not invoke Kani.
#   --dry-run     Print the cargo-kani command for each matched entry
#                 and exit 0. Does not invoke Kani.
#   --allow-empty Treat an empty match set as success in normal runs.
#                 Without this flag, an empty match exits 1 so a CI
#                 gate cannot silently pass when a lane typo, manifest
#                 bug, or `--exclude-crate` filter removes every
#                 harness. `--list` and `--dry-run` are informational
#                 and always exit 0 on empty match.
#
# Environment:
#   KANI_MANIFEST    Path to the manifest TOML. Defaults to
#                    `.kani/harnesses.toml` relative to repo root.
#
# Exit code: 0 if all matched harnesses pass (or the matched set is
# empty under `--list` / `--dry-run` / `--allow-empty`); non-zero on
# the first failing harness, on an empty match in a normal run without
# `--allow-empty`, or on manifest parse errors. Per-harness wall-clock
# cap is enforced via `timeout(1)` if present on PATH.

set -euo pipefail

cd "$(dirname "$0")/.."

LANE_FILTER="pr"
CRATE_FILTER=""
EXCLUDE_CRATES=""
LIST_ONLY=0
DRY_RUN=0
ALLOW_EMPTY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lane)
      LANE_FILTER="${2:-}"
      shift 2
      ;;
    --crate)
      CRATE_FILTER="${2:-}"
      shift 2
      ;;
    --exclude-crate)
      if [[ -z "$EXCLUDE_CRATES" ]]; then
        EXCLUDE_CRATES="${2:-}"
      else
        EXCLUDE_CRATES="${EXCLUDE_CRATES},${2:-}"
      fi
      shift 2
      ;;
    --list)
      LIST_ONLY=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --allow-empty)
      ALLOW_EMPTY=1
      shift
      ;;
    -h|--help)
      sed -n '2,43p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "run-kani-manifest.sh: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

MANIFEST="${KANI_MANIFEST:-.kani/harnesses.toml}"
if [[ ! -f "$MANIFEST" ]]; then
  echo "run-kani-manifest.sh: missing manifest $MANIFEST" >&2
  exit 1
fi

# Emit one TSV row per matching harness:
#   crate \t harness \t default_unwind \t timeout_secs \t features \t unwinding_checks
ROWS=$(python3 - "$MANIFEST" "$LANE_FILTER" "$CRATE_FILTER" "$EXCLUDE_CRATES" <<'PY'
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

manifest_path = Path(sys.argv[1])
lane_filter = sys.argv[2]
crate_filter = sys.argv[3]
exclude_csv = sys.argv[4]
exclude_set = {x for x in exclude_csv.split(",") if x}

# Lane is a closed enum. Validate both the requested lane filter and
# every entry's lane value against this set so a typo in the manifest
# (e.g. `lane = "prr"`) cannot silently drop a harness from CI by
# never matching any filter.
VALID_LANES = ("pr", "nightly")

if lane_filter not in VALID_LANES:
    sys.stderr.write(
        f"run-kani-manifest.sh: --lane {lane_filter!r} is not one of {list(VALID_LANES)}\n"
    )
    sys.exit(2)

data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
required_schema = "chio.kani.multi-crate.v1"
schema = data.get("schema")
if schema != required_schema:
    sys.stderr.write(
        f"run-kani-manifest.sh: unexpected schema {schema!r}; expected {required_schema!r}\n"
    )
    sys.exit(2)

entries = data.get("harness", [])
if not isinstance(entries, list):
    sys.stderr.write("run-kani-manifest.sh: `harness` must be a TOML array of tables\n")
    sys.exit(2)

required = ("crate", "harness", "default_unwind", "timeout_secs", "lane")
seen = set()
for idx, entry in enumerate(entries):
    for key in required:
        if key not in entry:
            sys.stderr.write(f"harness[{idx}] missing required key {key!r}\n")
            sys.exit(2)
    pair = (entry["crate"], entry["harness"])
    if pair in seen:
        sys.stderr.write(f"duplicate harness entry: {pair[0]}::{pair[1]}\n")
        sys.exit(2)
    seen.add(pair)
    # Reject unknown lane values up front (fail-loud) rather than
    # filtering them silently.
    if entry["lane"] not in VALID_LANES:
        sys.stderr.write(
            f"harness[{idx}] ({pair[0]}::{pair[1]}) has invalid lane "
            f"{entry['lane']!r}; expected one of {list(VALID_LANES)}\n"
        )
        sys.exit(2)
    if entry["lane"] != lane_filter:
        continue
    if crate_filter and entry["crate"] != crate_filter:
        continue
    if entry["crate"] in exclude_set:
        continue
    features = entry.get("features", [])
    if not isinstance(features, list):
        sys.stderr.write(
            f"harness[{idx}].features must be a list of strings\n"
        )
        sys.exit(2)
    unwinding_checks = entry.get("unwinding_checks", False)
    if not isinstance(unwinding_checks, bool):
        sys.stderr.write(
            f"harness[{idx}].unwinding_checks must be a boolean\n"
        )
        sys.exit(2)
    print(
        "\t".join(
            [
                str(entry["crate"]),
                str(entry["harness"]),
                str(int(entry["default_unwind"])),
                str(int(entry["timeout_secs"])),
                ",".join(features) if features else "-",
                "true" if unwinding_checks else "false",
            ]
        )
    )
PY
)

if [[ -z "$ROWS" ]]; then
  # Empty-match policy: informational modes (--list, --dry-run) and
  # explicit opt-in (--allow-empty) succeed; everything else fails so a
  # CI gate cannot silently pass when a lane typo, manifest bug, or
  # `--exclude-crate` filter removes every harness from the sweep.
  if [[ "$LIST_ONLY" -eq 1 || "$DRY_RUN" -eq 1 || "$ALLOW_EMPTY" -eq 1 ]]; then
    echo "run-kani-manifest.sh: no harnesses matched (lane=$LANE_FILTER crate=${CRATE_FILTER:-*})" >&2
    exit 0
  fi
  echo "run-kani-manifest.sh: no harnesses matched (lane=$LANE_FILTER crate=${CRATE_FILTER:-*}); pass --allow-empty to opt in to empty-match success" >&2
  exit 1
fi

if [[ "$LIST_ONLY" -eq 1 ]]; then
  while IFS=$'\t' read -r crate harness _ _ _ _; do
    [[ -z "$crate" ]] && continue
    printf '%s::%s\n' "$crate" "$harness"
  done <<< "$ROWS"
  exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "run-kani-manifest.sh: cargo not on PATH" >&2
  exit 1
fi
if [[ "$DRY_RUN" -eq 0 ]]; then
  if ! cargo kani --version >/dev/null 2>&1; then
    echo "run-kani-manifest.sh: cargo-kani not installed (\`cargo install --locked kani-verifier && cargo kani setup\`)" >&2
    exit 1
  fi
fi

HAS_TIMEOUT=0
if command -v timeout >/dev/null 2>&1; then
  HAS_TIMEOUT=1
fi

COUNT=0
while IFS=$'\t' read -r crate harness unwind timeout features unwinding_checks; do
  [[ -z "$crate" ]] && continue
  COUNT=$((COUNT + 1))

  qualified_harness="kani_public_harnesses::${harness}"
  CMD=(cargo kani -p "$crate" --lib --harness "$qualified_harness" --exact
       --default-unwind "$unwind")
  if [[ "$unwinding_checks" != "true" ]]; then
    CMD+=(--no-unwinding-checks)
  fi
  if [[ "$features" != "-" ]]; then
    CMD+=(--features "$features")
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ "$HAS_TIMEOUT" -eq 1 ]]; then
      echo "timeout ${timeout}s ${CMD[*]}"
    else
      echo "${CMD[*]}  # timeout=${timeout}s (timeout(1) not on PATH)"
    fi
    continue
  fi

  echo "::group::cargo kani ${crate}::${qualified_harness} (unwind=${unwind} timeout=${timeout}s)"
  # Capture the harness exit status without negation. After `if ! cmd; then`,
  # `$?` is 0 because `!` inverts the status before the conditional; running
  # the command directly under a temporary `set +e` and stashing `$?`
  # preserves the real failure code so CI fails on harness verification
  # failure or `timeout`-induced 124.
  set +e
  if [[ "$HAS_TIMEOUT" -eq 1 ]]; then
    timeout "${timeout}s" "${CMD[@]}"
    rc=$?
  else
    "${CMD[@]}"
    rc=$?
  fi
  set -e
  if [[ "$rc" -ne 0 ]]; then
    echo "::endgroup::"
    echo "FAIL: ${crate}::${harness} exited with code ${rc}" >&2
    exit "$rc"
  fi
  echo "::endgroup::"
done <<< "$ROWS"

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "run-kani-manifest.sh: ${COUNT} harnesses matched (dry-run)"
else
  echo "run-kani-manifest.sh: ${COUNT} harnesses passed (lane=${LANE_FILTER}${CRATE_FILTER:+ crate=${CRATE_FILTER}})"
fi
