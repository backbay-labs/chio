#!/usr/bin/env bash
# Aggregate per-crate mutation kill rates from cargo-mutants 25.x output.
# Reads `audits/evidence/mutants/<crate>/mutants.out/{caught,missed,timeout,unviable}.txt`
# and emits a markdown table row per crate plus per-measurement-class
# totals. It intentionally does not emit a single workspace total because
# the evidence directory can mix workspace runs, package-only runs,
# interrupted partial runs, and hand-picked subset runs.
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
printf "| Crate | Measurement class | Total mutants | Caught | Missed | Timeout | Unviable | Kill rate |\n"
printf "|---|---|---|---|---|---|---|---|\n"

totals_tsv="$(mktemp)"
trap 'rm -f "${totals_tsv}"' EXIT

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
    printf "| \`%s\` | BASELINE-GAP | - | - | - | - | - | **n/a** |\n" "${crate}"
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
  #
  # A newer PENDING-RERUN summary is an instruction to rerun, not a
  # measured baseline. Prefer the newest non-PENDING-RERUN summary when
  # one exists, so a post-gap-closure branch cannot mask the real
  # baseline committed by an earlier evidence branch.
  summary_json=""
  pending_summary_json=""
  shopt -s nullglob
  for candidate in $(printf '%s\n' "${EVIDENCE_DIR}/${crate}"/[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]*.json | sort -r); do
    if [ -f "${candidate}" ]; then
      if jq -e '.result_label == "PENDING-RERUN"' "${candidate}" > /dev/null 2>&1; then
        if [ -z "${pending_summary_json}" ]; then
          pending_summary_json="${candidate}"
        fi
        continue
      fi
      summary_json="${candidate}"
      break
    fi
  done
  shopt -u nullglob
  if [ -z "${summary_json}" ] && [ -n "${pending_summary_json}" ]; then
    summary_json="${pending_summary_json}"
  fi

  partial_label=""
  partial_detail=""
  measurement_class="unknown-summary"
  if [ -n "${summary_json}" ]; then
    rl=$(jq -r '.result_label // empty' "${summary_json}" 2>/dev/null || echo "")
    es=$(jq -r '.examine_scope // empty' "${summary_json}" 2>/dev/null || echo "")
    ts=$(jq -r '.test_scope // empty' "${summary_json}" 2>/dev/null || echo "")
    tm=$(jq -r 'if has("target_met") and .target_met != null then (.target_met | tostring) else empty end' "${summary_json}" 2>/dev/null || echo "")
    ev=$(jq -r '.evaluated // empty' "${summary_json}" 2>/dev/null || echo "")
    td=$(jq -r '.total_discovered // empty' "${summary_json}" 2>/dev/null || echo "")
    case "${rl}" in
      PARTIAL-SUBSET)
        partial_label="PARTIAL-SUBSET"
        partial_detail="${es:-subset}"
        measurement_class="partial-subset"
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
        if printf '%s' "${ts}" | grep -qi 'workspace'; then
          measurement_class="partial-workspace"
        elif printf '%s' "${ts}" | grep -qi 'package-only\|--package\|--test-package'; then
          measurement_class="partial-package-only"
        else
          measurement_class="partial-unknown-scope"
        fi
        ;;
      FULL-BELOW-TARGET)
        partial_label="BELOW-TARGET"
        partial_detail=""
        if printf '%s' "${ts}" | grep -qi 'workspace'; then
          measurement_class="full-workspace"
        elif printf '%s' "${ts}" | grep -qi 'package-only\|--package\|--test-package'; then
          measurement_class="full-package-only"
        else
          measurement_class="full-unknown-scope"
        fi
        ;;
      FULL|"")
        if [ "${tm}" = "false" ]; then
          partial_label="BELOW-TARGET"
        fi
        if printf '%s' "${ts}" | grep -qi 'workspace'; then
          measurement_class="full-workspace"
        elif printf '%s' "${ts}" | grep -qi 'package-only\|--package\|--test-package'; then
          measurement_class="full-package-only"
        elif [ -n "${summary_json}" ]; then
          measurement_class="full-unknown-scope"
        fi
        ;;
      PENDING-RERUN)
        partial_label="PENDING-RERUN"
        partial_detail="${es:-rerun-required}"
        measurement_class="pending-rerun"
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
    printf "| \`%s\` | \`%s\` | %d%s | %d | %d | %d | %d | **%s%%** |\n" \
      "${crate}" "${measurement_class}" "${n}" "${partial}" "${c}" "${m}" "${t}" "${u}" "${rate}"
  else
    printf "| \`%s\` | \`%s\` | %d%s | %d | %d | %d | %d | **n/a (no viable mutants tested)** |\n" \
      "${crate}" "${measurement_class}" "${n}" "${partial}" "${c}" "${m}" "${t}" "${u}"
  fi
  printf '%s\t%d\t%d\t%d\t%d\t%d\n' "${measurement_class}" "${n}" "${c}" "${m}" "${t}" "${u}" >> "${totals_tsv}"
done

if [ -s "${totals_tsv}" ]; then
  printf "\nNo workspace total is emitted. These rows mix measurement classes, so a single workspace score would be misleading.\n\n"
  printf "| Measurement class | Total mutants | Caught | Missed | Timeout | Unviable | Kill rate |\n"
  printf "|---|---|---|---|---|---|---|\n"
  sort "${totals_tsv}" | awk -F '\t' '
    function emit(class, n, c, m, t, u, denom, rate) {
      denom = c + m + t
      if (denom > 0) {
        rate = sprintf("%.1f%%", (c / denom) * 100)
      } else {
        rate = "n/a"
      }
      printf "| `%s` | **%d** | **%d** | **%d** | **%d** | **%d** | **%s** |\n", class, n, c, m, t, u, rate
    }
    NR == 1 {
      class = $1; n = $2; c = $3; m = $4; t = $5; u = $6; next
    }
    $1 != class {
      emit(class, n, c, m, t, u)
      class = $1; n = $2; c = $3; m = $4; t = $5; u = $6; next
    }
    {
      n += $2; c += $3; m += $4; t += $5; u += $6
    }
    END {
      if (NR > 0) {
        emit(class, n, c, m, t, u)
      }
    }'
fi
