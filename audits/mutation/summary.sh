#!/usr/bin/env bash
# Build per-crate JSON summary files at
# `audits/evidence/mutants/<crate>/<date>.json` from the cargo-mutants
# 25.x `mutants.out/` directory output.
#
# Each summary JSON has the shape:
#   {
#     "crate": "<name>",
#     "ran_at": "<RFC3339-ish from lock.json, or previous committed summary>",
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
  evaluated=$((c + m + t + u))
  total_discovered="null"
  if [ -f "${out_dir}/mutants.json" ]; then
    total_discovered=$(jq 'length' "${out_dir}/mutants.json" 2>/dev/null || echo "null")
    total_discovered=${total_discovered:-null}
  fi

  out_file="${EVIDENCE_DIR}/${crate}/${DATE}.json"
  previous_summary=""
  shopt -s nullglob
  for candidate in $(printf '%s\n' "${EVIDENCE_DIR}/${crate}"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*.json | sort -r); do
    if [ -f "${candidate}" ]; then
      previous_summary="${candidate}"
      break
    fi
  done
  shopt -u nullglob

  ran_at=$(jq -r '.start_time // empty' "${out_dir}/lock.json" 2>/dev/null || true)
  if [ -z "${ran_at}" ] && [ -n "${previous_summary}" ]; then
    ran_at=$(jq -r '.ran_at // empty' "${previous_summary}" 2>/dev/null || true)
  fi
  ran_at=${ran_at:-unknown}

  tool_ver=$(jq -r '.cargo_mutants_version // empty' "${out_dir}/lock.json" 2>/dev/null || true)
  if [ -z "${tool_ver}" ] && [ -n "${previous_summary}" ]; then
    tool_ver=$(jq -r '.tool_version // empty' "${previous_summary}" 2>/dev/null || true)
  fi
  tool_ver=${tool_ver:-unknown}

  # Inspect the actual `cargo test` invocation cargo-mutants used.
  # cargo-mutants records the invocation in two places (in order of
  # preference for local regeneration after `audits/evidence/mutants/.gitignore`
  # excludes PII-heavy run artifacts from VCS):
  #   1. regenerated `outcomes.json` - per-mutant `cargo_test_args` list
  #   2. regenerated `debug.log` - the literal command line
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

  # Defensive: missed.txt / timeout.txt may not be present on a run that
  # produced only `outcomes.json` (cargo-mutants 25.x has two layouts).
  # `--rawfile` errors fatally if the file is missing; provide an empty
  # tmpfile fallback.
  missed_path="${out_dir}/missed.txt"
  timeout_path="${out_dir}/timeout.txt"
  empty=$(mktemp)
  : > "${empty}"
  [ -f "${missed_path}"  ] || missed_path="${empty}"
  [ -f "${timeout_path}" ] || timeout_path="${empty}"

  # ONLY a strict whitelist of durable, hand-curated annotations is
  # preserved across regenerations. Run-shape and release-truth keys
  # (`run_status`, `target_met`, `result_label`, `evaluated`,
  # `total_discovered`, etc.) are recomputed-or-cleared every run.
  # Preserving them previously caused a chio-policy summary that was
  # interrupted at 314/418 mutants to keep `target_met: true` from a
  # previous edit.
  #
  # Durable (preserved when present, never invented):
  #   * `command`          - the exact cargo-mutants invocation recorded
  #                          by the operator (audit trail).
  #   * `run_started_at`   - operator-recorded wall-clock start.
  #   * `evidence_dir`     - relative path the operator pinned for the run.
  #   * `notes`            - free-form operator commentary.
  #   * `target_kill_rate` - the configured threshold (e.g. 0.65 or 80).
  #
  # Recomputed/cleared every run (NOT preserved):
  #   * caught / missed / timeout / unviable / kill_rate_percent
  #   * crate / ran_at / tool / tool_version / test_scope
  #   * missed_mutants / timeout_mutants
  #   * run_status / target_met / result_label / evaluated /
  #     total_discovered / examine_scope / kill_rate_formula /
  #     subset_invalidated_for_files / subset_invalidation_reason /
  #     result_label_reason / target_explanation
  #
  # If a previous summary recorded any of the recomputed/cleared keys,
  # the operator (or a separate annotate-partial step) MUST re-assert
  # them after this script runs. The script never silently re-emits
  # stale release-truth from prior runs.
  durable_keys='["command", "run_started_at", "evidence_dir", "notes", "target_kill_rate"]'
  prev_extra="${empty}"
  extra_source=""
  if [ -f "${out_file}" ]; then
    extra_source="${out_file}"
  elif [ -n "${previous_summary}" ]; then
    extra_source="${previous_summary}"
  fi
  if [ -n "${extra_source}" ]; then
    prev_extra=$(mktemp)
    if ! jq --argjson keys "${durable_keys}" \
          'with_entries(select(.key as $k | $keys | index($k)))' \
          "${extra_source}" > "${prev_extra}" 2>/dev/null; then
      echo "{}" > "${prev_extra}"
    fi
  fi

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
    --argjson evaluated "${evaluated}" \
    --argjson total_discovered "${total_discovered}" \
    --arg kill_rate "${rate}" \
    --rawfile missed_text "${missed_path}" \
    --rawfile timeout_text "${timeout_path}" \
    --slurpfile prev_extra "${prev_extra}" \
    '($prev_extra[0] // {}) as $extra
    | ($kill_rate | tonumber? // null) as $rate
    | ($extra.target_kill_rate // null) as $target
    | ($extra + {
      crate: $crate,
      ran_at: $ran_at,
      tool: $tool,
      tool_version: $tool_ver,
      test_scope: $test_scope,
      caught: $caught,
      missed: $missed,
      timeout: $timeout,
      unviable: $unviable,
      kill_rate_percent: $rate,
      missed_mutants: ($missed_text | split("\n") | map(select(length > 0))),
      timeout_mutants: ($timeout_text | split("\n") | map(select(length > 0)))
    })
    | if (($target | type) == "number") and ($rate != null) then
        ($target | if . > 1 then . else . * 100 end) as $target_percent
        | if (($total_discovered | type) == "number") and ($total_discovered > 0) and ($evaluated < $total_discovered) then
            . + {
              evaluated: $evaluated,
              total_discovered: $total_discovered,
              target_met: false,
              result_label: "PARTIAL",
              result_label_reason: "partial cargo-mutants output; numeric threshold cannot retire crate target until every discovered mutant is evaluated"
            }
          else
            . + {
              target_met: ($rate >= $target_percent),
              result_label: (if $rate >= $target_percent then "FULL" else "FULL-BELOW-TARGET" end)
            }
          end
      else
        .
      end' > "${out_file}"

  rm -f "${empty}"
  [ "${prev_extra}" != "${empty}" ] && rm -f "${prev_extra}" || true
  echo "wrote ${out_file} (caught=${c} missed=${m} timeout=${t} unviable=${u} rate=${rate}%)"
done
