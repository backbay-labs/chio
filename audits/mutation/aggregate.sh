#!/usr/bin/env bash
# Aggregate per-crate mutation kill rates from cargo-mutants 25.x output.
# Reads `audits/evidence/mutants/<crate>/mutants.out/{caught,missed,timeout,unviable}.txt`
# and emits a markdown table row per crate plus a workspace total row.
#
# Usage:
#   bash audits/mutation/aggregate.sh                # tabulate every directory in audits/evidence/mutants/
#   bash audits/mutation/aggregate.sh chio-credentials chio-attest-verify   # subset
#
# Kill rate is computed as: caught / (caught + missed + timeout)
# excluding `unviable` from the denominator per cargo-mutants 25.x convention
# (an unviable mutant is one cargo-mutants could not compile).

set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
EVIDENCE_DIR="${ROOT_DIR}/audits/evidence/mutants"

if [ ! -d "${EVIDENCE_DIR}" ]; then
  echo "no evidence dir: ${EVIDENCE_DIR}" >&2
  exit 2
fi

if [ "$#" -eq 0 ]; then
  set -- $(ls "${EVIDENCE_DIR}" | sort)
fi

# Markdown table header.
printf "| Crate | Total mutants | Caught | Missed | Timeout | Unviable | Kill rate |\n"
printf "|---|---|---|---|---|---|---|\n"

total_c=0
total_m=0
total_t=0
total_u=0
total_n=0

for crate in "$@"; do
  # cargo-mutants 25.x writes its outputs in one of two layouts depending
  # on the invocation:
  #   * Newer/default: `<output>/outcomes.json` directly (no mutants.out/).
  #   * Older/in-place: `<output>/mutants.out/outcomes.json`.
  # Prefer the direct `<output>/` layout because that is the current
  # cargo-mutants 25.x default; fall back to the nested layout when the
  # direct layout is absent. This avoids reporting stale counts from a
  # legacy nested run when a newer run has overwritten the same crate
  # directory at the top level. Mirrors the dual-layout probe in
  # `scripts/mutants-fuzz-cocoverage.sh`.
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
    printf "| \`%s\` | BASELINE-GAP | - | - | - | - | **n/a** |\n" "${crate}"
    continue
  fi
  c=$(wc -l < "${out_dir}/caught.txt"   2>/dev/null | tr -d ' ' || echo 0)
  m=$(wc -l < "${out_dir}/missed.txt"   2>/dev/null | tr -d ' ' || echo 0)
  t=$(wc -l < "${out_dir}/timeout.txt"  2>/dev/null | tr -d ' ' || echo 0)
  u=$(wc -l < "${out_dir}/unviable.txt" 2>/dev/null | tr -d ' ' || echo 0)
  c=${c:-0}; m=${m:-0}; t=${t:-0}; u=${u:-0}
  n=$((c + m + t + u))
  denom=$((c + m + t))

  # Read result_label, examine_scope, run_status, target_met,
  # evaluated, total_discovered from the per-crate summary JSON and
  # propagate the most-specific label into the row. A naive
  # mutants.json length comparison misses PARTIAL-SUBSET runs
  # (operator-narrowed examine_globs) because the subset mutants.json
  # length matches n.
  #
  # Missing summary JSON / mutants.json / jq parse errors are
  # non-fatal under set -euo pipefail. Emit a warn on stderr when the
  # summary JSON is absent so the operator knows the row may
  # understate caveats.
  #
  # Restrict the glob to date-prefixed filenames (YYYY-MM-DD*.json)
  # because in the direct cargo-mutants layout `out_dir` is the same
  # directory as the summary JSON, and a permissive `*.json` glob
  # would also match cargo-mutants' own `outcomes.json` / `mutants.json`
  # / `lock.json`, which are NOT summary JSONs and would be picked up
  # by `sort -r` whenever no dated summary has been produced yet.
  summary_json=""
  shopt -s nullglob
  for candidate in $(printf '%s\n' "${EVIDENCE_DIR}/${crate}"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*.json | sort -r); do
    if [ -f "${candidate}" ]; then
      summary_json="${candidate}"
      break
    fi
  done
  shopt -u nullglob

  partial_label=""
  partial_detail=""
  if [ -n "${summary_json}" ]; then
    rl=$(jq -r '.result_label // empty' "${summary_json}" 2>/dev/null || echo "")
    es=$(jq -r '.examine_scope // empty' "${summary_json}" 2>/dev/null || echo "")
    tm=$(jq -r '.target_met // empty' "${summary_json}" 2>/dev/null || echo "")
    ev=$(jq -r '.evaluated // empty' "${summary_json}" 2>/dev/null || echo "")
    td=$(jq -r '.total_discovered // empty' "${summary_json}" 2>/dev/null || echo "")
    case "${rl}" in
      PARTIAL-SUBSET)
        partial_label="PARTIAL-SUBSET"
        partial_detail="${es:-subset}"
        ;;
      PARTIAL)
        partial_label="PARTIAL"
        if [ -n "${ev}" ] && [ -n "${td}" ] && [ -n "${es}" ]; then
          partial_detail="${ev}/${td} ${es}"
        elif [ -n "${ev}" ] && [ -n "${td}" ]; then
          partial_detail="${ev}/${td}"
        elif [ -n "${es}" ]; then
          partial_detail="${es}"
        fi
        ;;
      FULL-BELOW-TARGET)
        partial_label="BELOW-TARGET"
        partial_detail=""
        ;;
      FULL|"")
        if [ "${tm}" = "false" ]; then
          partial_label="BELOW-TARGET"
        fi
        ;;
    esac
  else
    echo "warn: ${crate} has no per-crate summary JSON; partial-run label may understate caveats" >&2
  fi

  if [ -z "${partial_label}" ]; then
    # Fall back to count-based detection from mutants.json length when
    # no summary JSON is available or it didn't carry a result_label.
    expected=$(jq 'length' "${out_dir}/mutants.json" 2>/dev/null || echo 0)
    expected=${expected:-0}
    if [ "${expected}" -gt 0 ] && [ "${n}" -lt "${expected}" ]; then
      partial_label="PARTIAL"
      partial_detail="${n}/${expected}"
    fi
  fi

  partial=""
  if [ -n "${partial_label}" ]; then
    if [ -n "${partial_detail}" ]; then
      partial=" (${partial_label} ${partial_detail})"
    else
      partial=" (${partial_label})"
    fi
  fi

  if [ "${denom}" -gt 0 ]; then
    rate=$(awk "BEGIN { printf \"%.1f\", (${c} / ${denom}) * 100 }")
    printf "| \`%s\` | %d%s | %d | %d | %d | %d | **%s%%** |\n" \
      "${crate}" "${n}" "${partial}" "${c}" "${m}" "${t}" "${u}" "${rate}"
  else
    printf "| \`%s\` | %d%s | %d | %d | %d | %d | **n/a (no viable mutants tested)** |\n" \
      "${crate}" "${n}" "${partial}" "${c}" "${m}" "${t}" "${u}"
  fi
  total_c=$((total_c + c))
  total_m=$((total_m + m))
  total_t=$((total_t + t))
  total_u=$((total_u + u))
  total_n=$((total_n + n))
done

denom=$((total_c + total_m + total_t))
if [ "${denom}" -gt 0 ]; then
  rate=$(awk "BEGIN { printf \"%.1f\", (${total_c} / ${denom}) * 100 }")
  printf "| **Workspace total** | **%d** | **%d** | **%d** | **%d** | **%d** | **%s%%** |\n" \
    "${total_n}" "${total_c}" "${total_m}" "${total_t}" "${total_u}" "${rate}"
fi
