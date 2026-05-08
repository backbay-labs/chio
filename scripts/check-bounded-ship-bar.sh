#!/usr/bin/env bash
# Bounded release ship-bar checker.
#
# Verifies the per-bar machine-readable signals enumerated in
# `.planning/trajectory-5/SHIP-BAR-TRACKER.md`. This script is the
# closing-bar companion to `scripts/bounded-release-preflight.sh` (which gates
# kickoff). Together they form the release close gate:
#
#   - bounded-release-preflight.sh: planning artifacts, OWNERS, releases.toml,
#     review trail, drift cleanup.
#   - check-bounded-ship-bar.sh (this file): per-bar evidence presence
#     for the three closing bars.
#
# The script is deliberately presence-and-shape oriented. It is NOT a
# replacement for cargo test / cargo mutants / the demo runner; those
# produce the artifacts this script then verifies are committed.
#
# Bar 1 (Lane A): per-crate mutation kill-rate JSONs for each
# trust-boundary crate listed in `releases.toml [mutants]`. Crates
# without a measured baseline JSON FAIL. A numeric kill-rate alone is
# not enough to close the bar: the JSON must also prove target_met=true,
# an explicit full-scope result label, complete evaluated counts, and no
# partial/subset/interrupted/hand-picked scope markers.
#
# Bar 2 (Lane B): four signed negative conformance fixture files under
# `crates/chio-conformance/tests/`. Missing files FAIL.
#
# Bar 3 (Lane C): demo directory + a pinned receipt fixture under
# `examples/chiodome-bilateral/`. Missing artifacts FAIL.
#
# Run from the chio repo root: `bash scripts/check-bounded-ship-bar.sh`.
# Output is one OK/FAIL/PARTIAL line per check.
#
# Exit modes:
#   * Default (release-gate mode): PARTIAL is treated as a FAIL. The
#     release closes only when every bar is fully MET, so the close
#     gate must reject any bar that is still in baseline / in-progress
#     state. Exits 1 if any partial OR failure row is recorded.
#   * `--diagnostic` (opt-in): PARTIAL is reported but does not
#     contribute to the exit status. Use during Wave-1 baseline
#     measurement and other in-progress windows where the operator
#     wants the honest snapshot without flipping the gate red. Real
#     FAIL rows still flip the gate red.
#
# The strict default is required release-gate behaviour. The diagnostic
# flag is opt-in and clearly labelled in the summary footer.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 1

# Default mode: PARTIAL counts as a failure (release-gate strict).
# `--diagnostic` flips this to advisory, where PARTIAL is reported but
# does not count toward the failure tally.
diagnostic_mode=0
for arg in "$@"; do
  case "$arg" in
    --diagnostic)
      diagnostic_mode=1
      ;;
    -h|--help)
      sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      printf '\nUsage: check-bounded-ship-bar.sh [--diagnostic]\n'
      exit 0
      ;;
    *)
      printf 'check-bounded-ship-bar.sh: unknown argument: %s\n' "$arg" >&2
      exit 2
      ;;
  esac
done

fail=0
partials=0
checks=0

ok() {
  printf 'OK   %s\n' "$1"
  checks=$((checks + 1))
}

partial() {
  # PARTIAL prints with a clear marker so it never reads as a clean
  # MET row. In diagnostic mode the gate stays green; in default
  # release-gate mode the gate flips red so we cannot ship while bars
  # are still in baseline state.
  if [ "$diagnostic_mode" -eq 1 ]; then
    printf 'WARN %s (PARTIAL, diagnostic-mode-only)\n' "$1"
  else
    printf 'PARTIAL %s\n' "$1"
  fi
  partials=$((partials + 1))
  checks=$((checks + 1))
}

failure() {
  printf 'FAIL %s\n' "$1"
  fail=$((fail + 1))
  checks=$((checks + 1))
}

# kill_rate_for_json reads the per-crate mutation JSON and prints the
# numeric kill rate (caught/viable * 100, two decimal places). It
# tolerates a few common field shapes:
#   - `kill_rate_percent` (preferred; pre-computed)
#   - `kill_rate` (numeric percentage)
#   - `caught` and `viable` (computes the rate)
# Prints empty string if no usable shape is found.
kill_rate_for_json() {
  local json_path="$1"
  if [ ! -f "$json_path" ]; then
    return 0
  fi
  local rate
  if command -v jq >/dev/null 2>&1; then
    rate=$(jq -r '
      if (.kill_rate_percent // empty) != null and (.kill_rate_percent != "") then
        (.kill_rate_percent | tostring)
      elif (.kill_rate // empty) != null and (.kill_rate != "") then
        (.kill_rate | tostring)
      elif ((.caught // empty) != null) and ((.viable // empty) != null) and (.viable != 0) then
        ((.caught * 10000 / .viable | floor) / 100 | tostring)
      else
        ""
      end
    ' "$json_path" 2>/dev/null || true)
  else
    # Fallback: best-effort grep for kill_rate_percent or kill_rate.
    rate=$(grep -E '"kill_rate(_percent)?"' "$json_path" \
      | head -1 \
      | sed -E 's/.*"kill_rate(_percent)?"[[:space:]]*:[[:space:]]*"?([0-9.]+)"?.*/\2/' \
      || true)
  fi
  printf '%s' "$rate"
}

json_metadata_for_json() {
  local json_path="$1"
  if [ ! -f "$json_path" ]; then
    printf '\037\037\037\037\037\037'
    return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    jq -r '
      [
        (.target_met | if . == null then "" else tostring end),
        (.result_label // ""),
        (.run_status // ""),
        (.evaluated | if . == null then "" else tostring end),
        (.total_discovered | if . == null then "" else tostring end),
        (.examine_scope // .scope // .mutation_scope // ""),
        (.test_scope // "")
      ] | map(tostring | gsub("\u001f"; " ")) | join("\u001f")
    ' "$json_path" 2>/dev/null || printf '\037\037\037\037\037\037'
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$json_path" <<'PY' || printf '\037\037\037\037\037\037'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)

def value(*keys):
    for key in keys:
        if key in data and data[key] is not None:
            return str(data[key]).replace("\x1f", " ")
    return ""

print("\x1f".join([
    value("target_met").lower(),
    value("result_label"),
    value("run_status"),
    value("evaluated"),
    value("total_discovered"),
    value("examine_scope", "scope", "mutation_scope"),
    value("test_scope"),
]))
PY
    return 0
  fi
  printf '\037\037\037\037\037\037'
}

upper() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]'
}

is_uint() {
  [[ "$1" =~ ^[0-9]+$ ]]
}

bar1_metadata_reasons_for_json() {
  local json_path="$1"
  local metadata_line
  metadata_line=$(json_metadata_for_json "$json_path")
  local target_met result_label run_status evaluated total_discovered examine_scope test_scope
  IFS=$'\037' read -r target_met result_label run_status evaluated total_discovered examine_scope test_scope <<EOF
$metadata_line
EOF

  local reasons=()
  if [ "$target_met" != "true" ]; then
    reasons+=("target_met=${target_met:-missing}")
  fi

  local result_label_upper
  result_label_upper=$(upper "$result_label")
  case "$result_label_upper" in
    FULL|FULL-TARGET-MET|FULL_TARGET_MET|FULL-SCOPE|FULL_SCOPE|TARGET-MET|TARGET_MET)
      ;;
    "")
      reasons+=("result_label missing full-scope marker")
      ;;
    *PARTIAL*|*SUBSET*|*INTERRUPT*|*PENDING*|*DIAGNOSTIC*|*BELOW-TARGET*|*BELOW_TARGET*)
      reasons+=("result_label=$result_label")
      ;;
    *)
      if printf '%s' "$result_label_upper" | grep -q 'FULL' \
         && ! printf '%s' "$result_label_upper" \
           | grep -q -E 'PARTIAL|SUBSET|INTERRUPT|PENDING|DIAGNOSTIC|BELOW[-_]?TARGET'; then
        :
      else
        reasons+=("result_label=$result_label lacks full-scope marker")
      fi
      ;;
  esac

  local run_status_upper
  run_status_upper=$(upper "$run_status")
  if printf '%s' "$run_status_upper" \
     | grep -q -E 'PARTIAL|INTERRUPT|SUBSET|HAND[-_ ]?PICK|ABORT|CANCEL|PENDING|DIAGNOSTIC'; then
    reasons+=("run_status=$run_status")
  fi

  if [ -z "$evaluated" ] || [ -z "$total_discovered" ]; then
    reasons+=("evaluated/total_discovered missing")
  elif ! is_uint "$evaluated" || ! is_uint "$total_discovered"; then
    reasons+=("evaluated/total_discovered non-numeric")
  elif [ "$evaluated" -lt "$total_discovered" ]; then
    reasons+=("evaluated=$evaluated < total_discovered=$total_discovered")
  fi

  local scope_upper
  scope_upper=$(upper "$examine_scope $test_scope")
  if printf '%s' "$scope_upper" \
     | grep -q -E 'HAND[-_ ]?PICK|PARTIAL[-_ ]?SUBSET|SUBSET|TOUCH(ED)?[-_ ]?LINE|NARROW|EXAMINE[-_ ]?GLOBS|EXAMINE_GLOBS|--FILE|--LINE|FILE[-_ ]?ONLY|LINE[-_ ]?ONLY|SELECTED[-_ ]?FILES'; then
    reasons+=("scope=${examine_scope:-${test_scope:-unknown}}")
  fi

  local joined=""
  local reason
  for reason in "${reasons[@]}"; do
    if [ -z "$joined" ]; then
      joined="$reason"
    else
      joined="$joined; $reason"
    fi
  done
  printf '%s' "$joined"
}

printf '\n[Bar 1] Lane A -- per-crate mutation kill-rate baselines\n'

# Trust-boundary crate list mirrors `releases.toml [mutants]
# trust_boundary_crates`. Keep these in sync.
bar1_crates=(
  "chio-policy"
  "chio-credentials"
  "chio-attest-verify"
  "chio-kernel-core"
  "chio-guards"
  "chio-anchor"
)

# Activation floor (per `releases.toml` activation_threshold_percent_per_crate).
bar1_floor_pct=65
# Per-crate target (per `releases.toml` target_catch_ratio_percent and
# `SHIP-BAR-TRACKER.md` Bar 1 chio-attest-verify >=80% requirement).
bar1_target_chio_attest_verify_pct=80

# Lane A planning entries (mutation evidence item / A1.3) write evidence under
# audits/evidence/mutants/<crate>/ (plural). audits/evidence/mutation/
# (singular) was an earlier-draft location. Probe the plural directory
# first, fall back to the singular for legacy commits.
if [ -d "audits/evidence/mutants" ]; then
  bar1_evidence_root="audits/evidence/mutants"
else
  bar1_evidence_root="audits/evidence/mutation"
fi

for crate in "${bar1_crates[@]}"; do
  json_glob="$bar1_evidence_root/$crate"
  if [ ! -d "$json_glob" ]; then
    failure "Bar1 $crate BASELINE-GAP (no $json_glob/ directory)"
    continue
  fi
  # Pick the most-recent baseline JSON in the per-crate directory.
  shopt -s nullglob
  json_files=("$json_glob"/*.json)
  shopt -u nullglob
  if [ "${#json_files[@]}" -eq 0 ]; then
    latest_json=""
  else
    latest_json=$(printf '%s\n' "${json_files[@]}" | sort | tail -1)
  fi
  if [ -z "$latest_json" ] || [ ! -f "$latest_json" ]; then
    failure "Bar1 $crate BASELINE-GAP (no JSON under $json_glob/)"
    continue
  fi
  rate=$(kill_rate_for_json "$latest_json")
  if [ -z "$rate" ]; then
    failure "Bar1 $crate JSON exists ($latest_json) but no kill_rate field"
    continue
  fi
  metadata_reasons=$(bar1_metadata_reasons_for_json "$latest_json")
  if [ -n "$metadata_reasons" ]; then
    partial "Bar1 $crate metadata not release-complete in $latest_json (${metadata_reasons}; measured ${rate}%)"
    continue
  fi
  # Use awk for floating-point comparison.
  meets_floor=$(awk -v r="$rate" -v f="$bar1_floor_pct" \
    'BEGIN { print (r + 0 >= f + 0) ? "yes" : "no" }')
  if [ "$crate" = "chio-attest-verify" ]; then
    meets_target=$(awk -v r="$rate" -v t="$bar1_target_chio_attest_verify_pct" \
      'BEGIN { print (r + 0 >= t + 0) ? "yes" : "no" }')
    if [ "$meets_target" = "yes" ]; then
      ok "Bar1 $crate measured ${rate}% (>= ${bar1_target_chio_attest_verify_pct}% target)"
    elif [ "$meets_floor" = "yes" ]; then
      partial "Bar1 $crate measured ${rate}% (below ${bar1_target_chio_attest_verify_pct}% target, above ${bar1_floor_pct}% floor)"
    else
      partial "Bar1 $crate measured ${rate}% (below ${bar1_floor_pct}% floor; baseline recorded honestly)"
    fi
  else
    if [ "$meets_floor" = "yes" ]; then
      ok "Bar1 $crate measured ${rate}% (>= ${bar1_floor_pct}% floor)"
    else
      partial "Bar1 $crate measured ${rate}% (below ${bar1_floor_pct}% floor; baseline recorded honestly)"
    fi
  fi
done

# Bar 1 also requires the threats directory; bounded-release-preflight.sh already
# checks count == 20. Here we additionally verify each file has
# `caught >= 1` and a non-1970 `ran_at` (the SHIP-BAR-TRACKER.md
# machine-readable signal).
threats_dir="audits/evidence/threats"
if [ ! -d "$threats_dir" ]; then
  failure "Bar1 threats directory missing ($threats_dir)"
else
  threat_count=0
  threat_real=0
  for tjson in "$threats_dir"/*.json; do
    [ -f "$tjson" ] || continue
    threat_count=$((threat_count + 1))
    if command -v jq >/dev/null 2>&1; then
      caught=$(jq -r '.caught // 0' "$tjson" 2>/dev/null || echo 0)
      ran_at=$(jq -r '.ran_at // ""' "$tjson" 2>/dev/null || echo "")
      if [ "$(awk -v c="$caught" 'BEGIN { print (c + 0 >= 1) ? "yes" : "no" }')" = "yes" ] \
         && [ -n "$ran_at" ] \
         && [ "$ran_at" != "1970-01-01T00:00:00Z" ]; then
        threat_real=$((threat_real + 1))
      fi
    fi
  done
  if [ "$threat_count" -eq 0 ]; then
    failure "Bar1 threats directory has zero JSON files"
  elif [ "$threat_real" -eq "$threat_count" ]; then
    ok "Bar1 threats $threat_real of $threat_count with caught>=1 and non-1970 ran_at"
  else
    partial "Bar1 threats $threat_real of $threat_count with real evidence (rest still placeholders)"
  fi
fi

printf '\n[Bar 2] Lane B -- four signed negative conformance fixtures\n'

# Filenames mirror `SHIP-BAR-TRACKER.md` Bar 2 "Machine-readable signal" row.
bar2_fixtures=(
  "b1_capability_v2_single_entry_no_bypass.rs"
  "b2_receipt_v2_failclosed_under_negotiated_v2.rs"
  "b3_anchor_batch_sync_path_rejected_under_public_witness.rs"
  "b4_bilateral_dsse_pae_only_is_conformant.rs"
)
bar2_root="crates/chio-conformance/tests"

for fixture in "${bar2_fixtures[@]}"; do
  fpath="$bar2_root/$fixture"
  if [ -f "$fpath" ]; then
    # Each fixture must carry the negative-conformance annotation per
    # SHIP-BAR-TRACKER.md Bar 2 "Machine-readable signal" row.
    if grep -q -E 'negative-conformance' "$fpath" 2>/dev/null; then
      ok "Bar2 $fixture present with negative-conformance annotation"
    else
      partial "Bar2 $fixture present but missing negative-conformance annotation"
    fi
  else
    failure "Bar2 $fixture missing ($fpath)"
  fi
done

# The async-witness fast-feedback shell script must also exist (per
# SHIP-BAR-TRACKER.md Bar 2 machine-readable signal: "scripts/check-
# anchor-batch-async-witness.sh MUST exist and exit 0 in CI"). Presence
# is the bar; CI validates exit 0 separately.
async_witness_script="scripts/check-anchor-batch-async-witness.sh"
if [ -f "$async_witness_script" ]; then
  ok "Bar2 $async_witness_script present (fast-feedback companion)"
else
  failure "Bar2 $async_witness_script missing"
fi

printf '\n[Bar 3] Lane C -- bilateral demo end-to-end fixture\n'

bar3_demo_dir="examples/chiodome-bilateral"
if [ -d "$bar3_demo_dir" ]; then
  ok "Bar3 demo directory present ($bar3_demo_dir)"
else
  failure "Bar3 demo directory missing ($bar3_demo_dir)"
fi

# Demo recipe: either a Makefile or a `Cargo.toml` example entry.
if [ -f "$bar3_demo_dir/Makefile" ]; then
  ok "Bar3 demo recipe present (Makefile)"
elif [ -f "$bar3_demo_dir/Cargo.toml" ]; then
  ok "Bar3 demo recipe present (Cargo.toml example)"
else
  failure "Bar3 demo recipe missing (no Makefile or Cargo.toml under $bar3_demo_dir)"
fi

# Two-kernel transcripts.
transcripts_dir="$bar3_demo_dir/transcripts"
if [ -d "$transcripts_dir" ]; then
  transcript_count=0
  for transcript_file in "$transcripts_dir"/*.json; do
    [ -f "$transcript_file" ] || continue
    transcript_count=$((transcript_count + 1))
  done
  if [ "$transcript_count" -gt 0 ]; then
    ok "Bar3 transcripts present ($transcript_count file(s) under $transcripts_dir/)"
  else
    failure "Bar3 transcripts directory empty ($transcripts_dir/)"
  fi
else
  failure "Bar3 transcripts directory missing ($transcripts_dir/)"
fi

# `chio receipt explain` golden output.
golden_dir="$bar3_demo_dir/golden"
if [ -d "$golden_dir" ]; then
  golden_count=0
  for golden_file in "$golden_dir"/*.txt; do
    [ -f "$golden_file" ] || continue
    golden_count=$((golden_count + 1))
  done
  if [ "$golden_count" -gt 0 ]; then
    ok "Bar3 golden file present ($golden_count file(s) under $golden_dir/)"
  else
    failure "Bar3 golden directory empty ($golden_dir/)"
  fi
else
  failure "Bar3 golden directory missing ($golden_dir/)"
fi

# Pinned receipt fixture under the v0.1.0-bounded-chiodome release tag.
pinned_receipt="$bar3_demo_dir/fixtures/v0.1.0-bounded-chiodome/receipt.json"
if [ -f "$pinned_receipt" ]; then
  ok "Bar3 pinned receipt fixture present ($pinned_receipt)"
else
  failure "Bar3 pinned receipt fixture missing ($pinned_receipt)"
fi

# releases.toml carries the recorded release tag (or the explicit
# `pending` placeholder during baseline baseline). PARTIAL until tagged.
if [ -f releases.toml ]; then
  tag_line=$(grep -E '^release_tag[[:space:]]*=' releases.toml | head -1 || true)
  if [ -n "$tag_line" ]; then
    if echo "$tag_line" | grep -q 'v0.1.0-bounded-chiodome' \
       && ! echo "$tag_line" | grep -q '"pending"'; then
      ok "Bar3 releases.toml carries release_tag"
    else
      partial "Bar3 releases.toml release_tag is placeholder ($tag_line)"
    fi
  else
    failure "Bar3 releases.toml missing release_tag entry"
  fi
else
  failure "Bar3 releases.toml missing"
fi

printf '\n----- check-bounded-ship-bar summary -----\n'
printf 'checks run: %d\n' "$checks"
printf 'failures:   %d\n' "$fail"
printf 'partials:   %d\n' "$partials"
if [ "$diagnostic_mode" -eq 1 ]; then
  printf 'mode:       DIAGNOSTIC (partials count as warnings, not failures)\n'
else
  printf 'mode:       RELEASE-GATE (partials count as failures; --diagnostic to relax)\n'
fi

# Strict default: PARTIAL rows are treated as failures so the close gate
# cannot pass while any bar is still in baseline / in-progress state.
# `--diagnostic` mode is opt-in and only allows real FAIL rows to flip
# the gate red.
if [ "$fail" -ne 0 ]; then
  printf '\nbounded ship-bar: FAIL (%d fail row(s), %d partial row(s))\n' "$fail" "$partials"
  exit 1
fi

if [ "$diagnostic_mode" -eq 1 ]; then
  if [ "$partials" -gt 0 ]; then
    printf '\nbounded ship-bar: PASS (diagnostic mode; %d partial row(s) reported as warnings)\n' "$partials"
  else
    printf '\nbounded ship-bar: PASS (diagnostic mode; no partial rows)\n'
  fi
  exit 0
fi

if [ "$partials" -ne 0 ]; then
  printf '\nbounded ship-bar: FAIL (release-gate mode; %d partial row(s) block close)\n' "$partials"
  printf '  re-run with --diagnostic for an advisory snapshot during baseline measurement\n'
  exit 1
fi

printf '\nbounded ship-bar: PASS (release-gate mode; all bars MET)\n'
exit 0
