#!/usr/bin/env bash
# Build per-crate JSON summary files at
# `audits/evidence/mutants/<crate>/<date>.json` from the cargo-mutants
# 25.x `mutants.out/` directory output.
#
# Each summary JSON has the shape:
#   {
#     "crate": "<name>",
#     "ran_at": "<RFC3339-ish from mutants.out/lock.json start_time>",
#     "tool": "cargo-mutants",
#     "tool_version": "<from lock.json>",
#     "test_scope": "workspace (additional_cargo_test_args)",
#     "caught": <int>,
#     "missed": <int>,
#     "timeout": <int>,
#     "unviable": <int>,
#     "kill_rate_percent": <float>,
#     "missed_mutants": [<one line per missed entry>],
#     "timeout_mutants": [<one line per timeout entry>]
#   }
#
# Usage: bash audits/mutation/summary.sh <crate>

set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <crate> [<crate>...]" >&2
  exit 2
fi

ROOT_DIR="$(git rev-parse --show-toplevel)"
EVIDENCE_DIR="${ROOT_DIR}/audits/evidence/mutants"
DATE="$(date -u +%Y-%m-%d)"

for crate in "$@"; do
  # cargo-mutants 25.x writes outputs in one of two layouts (see
  # `scripts/mutants-fuzz-cocoverage.sh` and `audits/mutation/aggregate.sh`
  # for the same probe pattern):
  #   * Newer/default: `<output>/outcomes.json` directly (no mutants.out/).
  #   * Older/in-place: `<output>/mutants.out/outcomes.json`.
  # Prefer the direct `<output>/` layout because that is the current
  # cargo-mutants 25.x default; fall back to the nested layout when the
  # direct layout is absent. The probe order matches `aggregate.sh` so
  # both helpers select the same evidence file when both layouts coexist.
  out_dir=""
  for candidate in \
    "${EVIDENCE_DIR}/${crate}" \
    "${EVIDENCE_DIR}/${crate}/mutants.out"; do
    if [ -f "${candidate}/caught.txt" ] || [ -f "${candidate}/outcomes.json" ]; then
      out_dir="${candidate}"
      break
    fi
  done
  if [ -z "${out_dir}" ]; then
    echo "skip ${crate}: no cargo-mutants output found" >&2
    continue
  fi

  c=$(wc -l < "${out_dir}/caught.txt"   2>/dev/null | tr -d ' ' || echo 0)
  m=$(wc -l < "${out_dir}/missed.txt"   2>/dev/null | tr -d ' ' || echo 0)
  t=$(wc -l < "${out_dir}/timeout.txt"  2>/dev/null | tr -d ' ' || echo 0)
  u=$(wc -l < "${out_dir}/unviable.txt" 2>/dev/null | tr -d ' ' || echo 0)
  c=${c:-0}; m=${m:-0}; t=${t:-0}; u=${u:-0}

  ran_at=$(jq -r '.start_time' "${out_dir}/lock.json" 2>/dev/null || echo "unknown")
  tool_ver=$(jq -r '.cargo_mutants_version' "${out_dir}/lock.json" 2>/dev/null || echo "unknown")

  # Inspect the actual `cargo test` invocation cargo-mutants used.
  # cargo-mutants records the invocation in two places (in order of
  # preference for re-derivability after `audits/evidence/mutants/.gitignore`
  # excludes the verbose log):
  #   1. `outcomes.json` (committed) - per-mutant `cargo_test_args` list
  #   2. `debug.log` (NOT committed) - the literal command line
  # If either records `--workspace`, the run is workspace-scoped.
  test_scope="package-only (--test-package ${crate})"
  if [ -f "${out_dir}/outcomes.json" ] && \
     jq -e '[.outcomes[]?.phase_results[]?.argv[]?] | any(. == "--workspace")' \
       "${out_dir}/outcomes.json" > /dev/null 2>&1; then
    test_scope="workspace (additional_cargo_test_args from .cargo/mutants.toml: --workspace --exclude chio-cpp-kernel-ffi)"
  elif [ -f "${out_dir}/debug.log" ] && \
       grep -q -- "--workspace" "${out_dir}/debug.log"; then
    test_scope="workspace (additional_cargo_test_args from .cargo/mutants.toml: --workspace --exclude chio-cpp-kernel-ffi)"
  fi

  denom=$((c + m + t))
  if [ "${denom}" -gt 0 ]; then
    rate=$(awk "BEGIN { printf \"%.2f\", (${c} / ${denom}) * 100 }")
  else
    rate="null"
  fi

  out_file="${EVIDENCE_DIR}/${crate}/${DATE}.json"

  # Defensive: missed.txt / timeout.txt may not be present on a run that
  # produced only `outcomes.json` (cargo-mutants 25.x has two layouts).
  # `--rawfile` errors fatally if the file is missing; provide an empty
  # tmpfile fallback. (Per Cursor review on PR #603.)
  missed_path="${out_dir}/missed.txt"
  timeout_path="${out_dir}/timeout.txt"
  empty=$(mktemp)
  : > "${empty}"
  [ -f "${missed_path}"  ] || missed_path="${empty}"
  [ -f "${timeout_path}" ] || timeout_path="${empty}"

  jq -n \
    --arg crate "${crate}" \
    --arg ran_at "${ran_at}" \
    --arg tool "cargo-mutants" \
    --arg tool_ver "${tool_ver}" \
    --arg test_scope "${test_scope}" \
    --argjson caught "${c}" \
    --argjson missed "${m}" \
    --argjson timeout "${t}" \
    --argjson unviable "${u}" \
    --arg kill_rate "${rate}" \
    --rawfile missed_text "${missed_path}" \
    --rawfile timeout_text "${timeout_path}" \
    '{
      crate: $crate,
      ran_at: $ran_at,
      tool: $tool,
      tool_version: $tool_ver,
      test_scope: $test_scope,
      caught: $caught,
      missed: $missed,
      timeout: $timeout,
      unviable: $unviable,
      kill_rate_percent: ($kill_rate | tonumber? // null),
      missed_mutants: ($missed_text | split("\n") | map(select(length > 0))),
      timeout_mutants: ($timeout_text | split("\n") | map(select(length > 0)))
    }' > "${out_file}"

  rm -f "${empty}"
  echo "wrote ${out_file} (caught=${c} missed=${m} timeout=${t} unviable=${u} rate=${rate}%)"
done
