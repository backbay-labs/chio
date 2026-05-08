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
  out_dir="${EVIDENCE_DIR}/${crate}/mutants.out"
  if [ ! -d "${out_dir}" ]; then
    echo "skip ${crate}: no mutants.out" >&2
    continue
  fi

  c=$(wc -l < "${out_dir}/caught.txt"   2>/dev/null | tr -d ' ' || echo 0)
  m=$(wc -l < "${out_dir}/missed.txt"   2>/dev/null | tr -d ' ' || echo 0)
  t=$(wc -l < "${out_dir}/timeout.txt"  2>/dev/null | tr -d ' ' || echo 0)
  u=$(wc -l < "${out_dir}/unviable.txt" 2>/dev/null | tr -d ' ' || echo 0)
  c=${c:-0}; m=${m:-0}; t=${t:-0}; u=${u:-0}

  ran_at=$(jq -r '.start_time' "${out_dir}/lock.json" 2>/dev/null || echo "unknown")
  tool_ver=$(jq -r '.cargo_mutants_version' "${out_dir}/lock.json" 2>/dev/null || echo "unknown")

  denom=$((c + m + t))
  if [ "${denom}" -gt 0 ]; then
    rate=$(awk "BEGIN { printf \"%.2f\", (${c} / ${denom}) * 100 }")
  else
    rate="null"
  fi

  out_file="${EVIDENCE_DIR}/${crate}/${DATE}.json"

  jq -n \
    --arg crate "${crate}" \
    --arg ran_at "${ran_at}" \
    --arg tool "cargo-mutants" \
    --arg tool_ver "${tool_ver}" \
    --arg test_scope "workspace (additional_cargo_test_args from .cargo/mutants.toml)" \
    --argjson caught "${c}" \
    --argjson missed "${m}" \
    --argjson timeout "${t}" \
    --argjson unviable "${u}" \
    --arg kill_rate "${rate}" \
    --rawfile missed_text "${out_dir}/missed.txt" \
    --rawfile timeout_text "${out_dir}/timeout.txt" \
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

  echo "wrote ${out_file} (caught=${c} missed=${m} timeout=${t} unviable=${u} rate=${rate}%)"
done
