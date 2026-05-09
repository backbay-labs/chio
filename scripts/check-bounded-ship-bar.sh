#!/usr/bin/env bash
# Trajectory 5 assurance checker.
#
# Verifies the claim-by-claim machine-readable signals enumerated in
# `.planning/trajectory-5/SHIP-BAR-TRACKER.md`. This script is the
# evidence close gate for the assurance matrix. It is not a product
# release or tag gate.
#
# Planning consistency lives under `.planning/trajectory-5/`. This root
# checker stays artifact-only: evidence presence and shape for Lane B
# integration, Lane A assurance, and Lane C canary.
#
# The script is deliberately presence-and-shape oriented. It is NOT a
# replacement for cargo test / cargo mutants / the demo runner; those
# produce the artifacts this script then verifies are committed.
#
# Claim A (Lane A): per-crate mutation kill-rate JSONs for each
# trust-boundary crate listed in `releases.toml [mutants]`. Crates
# without a measured baseline JSON remain PARTIAL/PENDING. A numeric
# kill-rate alone is not enough to close the claim: the JSON must also
# prove target_met=true,
# an explicit full-scope result label, complete evaluated counts, and no
# partial/subset/interrupted/hand-picked scope markers.
#
# Claim B (Lane B): source-PR conformance fixture files under
# `crates/chio-conformance/tests/`. Missing source-branch artifacts are
# reported as PARTIAL/PENDING, not as release-truth failures in #620.
#
# Claim C (Lane C): demo directory + pinned canary fixture artifacts under
# `examples/chiodome-bilateral/`. Missing future source artifacts remain
# PARTIAL/PENDING in #620.
#
# Claim C5 (selective disclosure): C5 must carry a machine-readable boundary.
# Deferred status is PARTIAL. A future evidence-complete status is accepted only
# when the implementation crate, feature, and auditor-view fixtures exist.
#
# Run from the chio repo root: `bash scripts/check-bounded-ship-bar.sh`.
# Output is one OK/FAIL/PARTIAL line per evidence check.
#
# Exit modes:
#   * Default (assurance-gate mode): PARTIAL is treated as a FAIL. The
#     assurance claim is complete only when every evidence row is fully
#     MET, so the gate rejects any baseline / in-progress row. Exits 1
#     if any partial OR failure row is recorded.
#   * `--diagnostic` (opt-in): PARTIAL is reported but does not
#     contribute to the exit status. Use during Wave-1 baseline
#     measurement and other in-progress windows where the operator
#     wants the honest snapshot without flipping the gate red. Real
#     FAIL rows still flip the gate red.
#
# The strict default is the audit's required behaviour. The diagnostic
# flag is opt-in and clearly labelled in the summary footer.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root" || exit 1

# Default mode: PARTIAL counts as a failure (assurance-gate strict).
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
  # assurance-gate mode the gate flips red while claims are still in
  # baseline state.
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

toml_value() {
  local section="$1"
  local key="$2"
  local path="${3:-releases.toml}"
  if [ ! -f "$path" ]; then
    return 0
  fi
  awk -v section="$section" -v key="$key" '
    $0 == "[" section "]" { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      sub(/^[^=]*=[[:space:]]*/, "")
      gsub(/^[[:space:]]*"|"[[:space:]]*$/, "")
      print
      exit
    }
  ' "$path"
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
      if ((.kill_rate_percent? // "") != "") then
        (.kill_rate_percent | tostring)
      elif ((.kill_rate? // "") != "") then
        (.kill_rate | tostring)
      elif ((.caught? // null) != null) and ((.viable? // null) != null) and ((.viable | tonumber) != 0) then
        (((.caught | tonumber) * 10000 / (.viable | tonumber) | floor) / 100 | tostring)
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

printf '\n[Claim A] Lane A -- mutation and threat-evidence assurance\n'

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
# `SHIP-BAR-TRACKER.md` Claim A chio-attest-verify >=80% requirement).
bar1_target_chio_attest_verify_pct=80

# Lane A writes release-cycle evidence under
# audits/evidence/mutants/<crate>/ (plural). Earlier singular paths are
# stale and are not accepted by the assurance gate.
bar1_evidence_root="audits/evidence/mutants"

banner_json="$bar1_evidence_root/banner.json"
if [ ! -f "$banner_json" ]; then
  partial "Claim A banner artifact pending ($banner_json)"
elif command -v jq >/dev/null 2>&1; then
  if jq -e '
    (.observed == true)
    and ((.ran_at // "") != "")
    and ((.ran_at // "") != "1970-01-01T00:00:00Z")
    and (((.per_crate // []) | type) == "array")
    and (((.per_crate // []) | length) >= 6)
  ' "$banner_json" >/dev/null 2>&1; then
    ok "Claim A banner artifact is observed and has per-crate entries"
  else
    partial "Claim A banner artifact exists but is not release-complete ($banner_json)"
  fi
else
  ok "Claim A banner artifact present ($banner_json; jq unavailable for shape check)"
fi

for crate in "${bar1_crates[@]}"; do
  json_glob="$bar1_evidence_root/$crate"
  if [ ! -d "$json_glob" ]; then
    partial "Claim A $crate BASELINE-GAP (no $json_glob/ directory yet)"
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
    partial "Claim A $crate BASELINE-GAP (no JSON under $json_glob/ yet)"
    continue
  fi
  rate=$(kill_rate_for_json "$latest_json")
  if [ -z "$rate" ]; then
    failure "Claim A $crate JSON exists ($latest_json) but no kill_rate field"
    continue
  fi
  metadata_reasons=$(bar1_metadata_reasons_for_json "$latest_json")
  if [ -n "$metadata_reasons" ]; then
    partial "Claim A $crate metadata not release-complete in $latest_json (${metadata_reasons}; measured ${rate}%)"
    continue
  fi
  # Use awk for floating-point comparison.
  meets_floor=$(awk -v r="$rate" -v f="$bar1_floor_pct" \
    'BEGIN { print (r + 0 >= f + 0) ? "yes" : "no" }')
  if [ "$crate" = "chio-attest-verify" ]; then
    meets_target=$(awk -v r="$rate" -v t="$bar1_target_chio_attest_verify_pct" \
      'BEGIN { print (r + 0 >= t + 0) ? "yes" : "no" }')
    if [ "$meets_target" = "yes" ]; then
      ok "Claim A $crate measured ${rate}% (>= ${bar1_target_chio_attest_verify_pct}% target)"
    elif [ "$meets_floor" = "yes" ]; then
      partial "Claim A $crate measured ${rate}% (below ${bar1_target_chio_attest_verify_pct}% target, above ${bar1_floor_pct}% floor)"
    else
      partial "Claim A $crate measured ${rate}% (below ${bar1_floor_pct}% floor; baseline recorded honestly)"
    fi
  else
    if [ "$meets_floor" = "yes" ]; then
      ok "Claim A $crate measured ${rate}% (>= ${bar1_floor_pct}% floor)"
    else
      partial "Claim A $crate measured ${rate}% (below ${bar1_floor_pct}% floor; baseline recorded honestly)"
    fi
  fi
done

# Claim A also requires threat evidence. Each file must carry real
# caught evidence, a non-1970 run timestamp, needs_real_run:false, and
# a triage_status value.
threats_dir="audits/evidence/threats"
if [ ! -d "$threats_dir" ]; then
  partial "Claim A threats directory pending ($threats_dir)"
else
  threat_count=0
  threat_real=0
  for tjson in "$threats_dir"/*.json; do
    [ -f "$tjson" ] || continue
    threat_count=$((threat_count + 1))
    if command -v jq >/dev/null 2>&1; then
      caught=$(jq -r '.caught // 0' "$tjson" 2>/dev/null || echo 0)
      ran_at=$(jq -r '.ran_at // ""' "$tjson" 2>/dev/null || echo "")
      needs_real_run=$(jq -r '.needs_real_run // true' "$tjson" 2>/dev/null || echo true)
      triage_status=$(jq -r '.triage_status // ""' "$tjson" 2>/dev/null || echo "")
      if [ "$(awk -v c="$caught" 'BEGIN { print (c + 0 >= 1) ? "yes" : "no" }')" = "yes" ] \
         && [ -n "$ran_at" ] \
         && [ "$ran_at" != "1970-01-01T00:00:00Z" ] \
         && [ "$needs_real_run" = "false" ] \
         && [ -n "$triage_status" ]; then
        threat_real=$((threat_real + 1))
      fi
    fi
  done
  if [ "$threat_count" -eq 0 ]; then
    partial "Claim A threats directory has zero JSON files"
  elif [ "$threat_real" -eq "$threat_count" ]; then
    ok "Claim A threats $threat_real of $threat_count with caught>=1, non-1970 ran_at, needs_real_run=false, and triage_status"
  else
    partial "Claim A threats $threat_real of $threat_count with complete triaged evidence (rest still placeholders)"
  fi
fi

printf '\n[Claim B] Lane B -- production-call-path conformance fixtures\n'

bar2_root="crates/chio-conformance/tests"

claim_b_fixture() {
  local label="$1"
  local fixture="$2"
  local fpath="$bar2_root/$fixture"
  if [ ! -f "$fpath" ]; then
    partial "Claim B $label pending: $fixture not present in this planning tree"
    return 0
  fi
  if grep -q -E 'negative-conformance|MUST fail|Spec MUST|Spec anchor|Reverts-to-fail proof|Production call path' "$fpath" 2>/dev/null; then
    ok "Claim B $label fixture present with upstream evidence marker ($fixture)"
  else
    partial "Claim B $label fixture present but missing upstream evidence marker ($fixture)"
  fi
}

claim_b_fixture "B1 single-entry verifier" "b1_capability_v2_single_entry_no_bypass.rs"
claim_b_fixture "B2 receipt v2 pre-dispatch fail-closed" "b2_receipt_v2_failclosed_pre_dispatch.rs"
claim_b_fixture "B3 anchor-batch async-only" "b3_anchor_batch_sync_path_rejected_under_public_witness.rs"

b4_interim_fixture="$bar2_root/b4_bilateral_dsse_signature_slice.rs"
b4_full_found=0
for b4_candidate in "$bar2_root"/b4_bilateral_dsse_*.rs; do
  [ -f "$b4_candidate" ] || continue
  if [ "$b4_candidate" = "$b4_interim_fixture" ]; then
    continue
  fi
  if grep -q -E 'negative-conformance|full DSSE PAE|DSSE PAE conformance|Spec MUST|Reverts-to-fail proof|Production call path' "$b4_candidate" 2>/dev/null; then
    ok "Claim B B4 full DSSE PAE conformance fixture present ($(basename "$b4_candidate"))"
    b4_full_found=1
    break
  fi
done
if [ "$b4_full_found" -eq 1 ]; then
  :
elif [ -f "$b4_interim_fixture" ]; then
  partial "Claim B B4 has interim signature-slice fixture only; full DSSE PAE conformance fixture pending"
else
  partial "Claim B B4 full DSSE PAE conformance fixture pending"
fi

# The async-witness fast-feedback shell script must also exist (per
# SHIP-BAR-TRACKER.md Claim B machine-readable signal: "scripts/check-
# anchor-batch-async-witness.sh MUST exist and exit 0 in CI"). Presence
# is not enough; the companion must also exit 0.
async_witness_script="scripts/check-anchor-batch-async-witness.sh"
if [ -f "$async_witness_script" ]; then
  if bash "$async_witness_script" >/dev/null 2>&1; then
    ok "Claim B $async_witness_script present and exits 0 (fast-feedback companion)"
  else
    failure "Claim B $async_witness_script present but exits nonzero"
  fi
else
  partial "Claim B $async_witness_script pending"
fi

printf '\n[Claim C] Lane C -- post-Lane-B canary fixture\n'

bar3_demo_dir="examples/chiodome-bilateral"
if [ -d "$bar3_demo_dir" ]; then
  ok "Claim C demo directory present ($bar3_demo_dir)"
else
  partial "Claim C demo directory pending ($bar3_demo_dir)"
fi

# Demo recipe: either a Makefile or a `Cargo.toml` example entry.
if [ -f "$bar3_demo_dir/Makefile" ]; then
  ok "Claim C demo recipe present (Makefile)"
elif [ -f "$bar3_demo_dir/Cargo.toml" ]; then
  ok "Claim C demo recipe present (Cargo.toml example)"
else
  partial "Claim C demo recipe pending (no Makefile or Cargo.toml under $bar3_demo_dir)"
fi

# Two-kernel transcripts.
transcripts_dir="$bar3_demo_dir/transcripts"
if [ -d "$transcripts_dir" ]; then
  transcript_count=0
  for transcript_file in "$transcripts_dir"/*.json; do
    [ -f "$transcript_file" ] || continue
    transcript_count=$((transcript_count + 1))
  done
  if [ "$transcript_count" -ge 2 ]; then
    ok "Claim C two-kernel transcripts present ($transcript_count file(s) under $transcripts_dir/)"
  else
    partial "Claim C transcripts pending ($transcript_count file(s) under $transcripts_dir/; expected at least 2)"
  fi
else
  partial "Claim C transcripts directory pending ($transcripts_dir/)"
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
    ok "Claim C golden file present ($golden_count file(s) under $golden_dir/)"
  else
    partial "Claim C golden directory pending ($golden_dir/)"
  fi
else
  partial "Claim C golden directory pending ($golden_dir/)"
fi

# Pinned canary fixture set under the v0.1.0-bounded-chiodome package id.
pinned_fixture_dir="$bar3_demo_dir/fixtures/v0.1.0-bounded-chiodome"
for pinned_name in receipt.json envelope.json checkpoint.json; do
  pinned_path="$pinned_fixture_dir/$pinned_name"
  if [ -f "$pinned_path" ]; then
    ok "Claim C pinned fixture present ($pinned_path)"
  else
    partial "Claim C pinned fixture pending ($pinned_path)"
  fi
done

# C5 selective disclosure is optional only when explicitly deferred. Without a
# marker, release-facing prose can drift into a false proof claim. With a marker
# that claims evidence completion, real implementation and fixture evidence must
# exist in the tree.
c5_marker=".planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml"
if [ ! -f "$c5_marker" ]; then
  partial "Claim C5 selective-disclosure boundary marker pending ($c5_marker)"
else
  c5_status=$(toml_value "c5_selective_disclosure" "status" "$c5_marker")
  c5_impl_crate=$(toml_value "c5_selective_disclosure" "implementation_crate" "$c5_marker")
  c5_feature=$(toml_value "c5_selective_disclosure" "feature" "$c5_marker")
  c5_proof_path=$(toml_value "c5_selective_disclosure" "proof_path" "$c5_marker")
  c5_predicate_failed_path=$(toml_value "c5_selective_disclosure" "predicate_failed_path" "$c5_marker")
  c5_release_claim_allowed=$(toml_value "c5_selective_disclosure" "release_claim_allowed" "$c5_marker")

  case "$c5_status" in
    deferred_*|blocked_*|pending|partial|not_ready)
      partial "Claim C5 selective-disclosure boundary is not release-complete ($c5_status)"
      ;;
    evidence_complete|complete)
      c5_missing=()
      if [ -z "$c5_impl_crate" ] || [ "$c5_impl_crate" = "deferred" ] || [ ! -f "$c5_impl_crate/Cargo.toml" ]; then
        c5_missing+=("implementation_crate=${c5_impl_crate:-missing}")
      fi
      if [ -z "$c5_feature" ] || [ "$c5_feature" = "deferred" ]; then
        c5_missing+=("feature=${c5_feature:-missing}")
      elif [ -n "$c5_impl_crate" ] && [ -f "$c5_impl_crate/Cargo.toml" ] \
        && ! grep -q -E "^[[:space:]]*$c5_feature[[:space:]]*=" "$c5_impl_crate/Cargo.toml"; then
        c5_missing+=("feature $c5_feature missing from $c5_impl_crate/Cargo.toml")
      fi
      if [ -z "$c5_proof_path" ] || [ "$c5_proof_path" = "deferred" ] || [ ! -f "$c5_proof_path" ]; then
        c5_missing+=("proof_path=${c5_proof_path:-missing}")
      fi
      if [ -z "$c5_predicate_failed_path" ] || [ "$c5_predicate_failed_path" = "deferred" ] || [ ! -f "$c5_predicate_failed_path" ]; then
        c5_missing+=("predicate_failed_path=${c5_predicate_failed_path:-missing}")
      fi
      if [ "$c5_release_claim_allowed" != "yes" ]; then
        c5_missing+=("release_claim_allowed=${c5_release_claim_allowed:-missing}")
      fi

      if [ "${#c5_missing[@]}" -eq 0 ]; then
        ok "Claim C5 selective-disclosure evidence complete ($c5_marker)"
      else
        c5_joined=""
        for c5_reason in "${c5_missing[@]}"; do
          if [ -z "$c5_joined" ]; then
            c5_joined="$c5_reason"
          else
            c5_joined="$c5_joined; $c5_reason"
          fi
        done
        failure "Claim C5 marker claims evidence_complete but evidence is missing ($c5_joined)"
      fi
      ;;
    "")
      partial "Claim C5 selective-disclosure boundary marker has no status ($c5_marker)"
      ;;
    *)
      partial "Claim C5 selective-disclosure boundary status is not recognized ($c5_status)"
      ;;
  esac
fi

# releases.toml carries the bounded package status under its own table.
# A tag alone is insufficient; the canary metadata must be tied to an
# integrated merge SHA before this row can pass.
if [ -f releases.toml ]; then
  release_status=$(toml_value "v0_1_0_bounded_chiodome" "release_status")
  integrated_merge_sha=$(toml_value "v0_1_0_bounded_chiodome" "integrated_merge_sha")
  if [ -z "$release_status" ]; then
    partial "Claim C bounded package release_status not recorded by this planning PR"
  elif printf '%s' "$release_status" | grep -q -E 'blocked|pending|partial|not_ready'; then
    partial "Claim C bounded package release_status is not assurance-complete ($release_status)"
  else
    ok "Claim C bounded package release_status is $release_status"
  fi
  if [ -n "$integrated_merge_sha" ] \
     && ! printf '%s' "$integrated_merge_sha" | grep -q -E 'pending|blocked' \
     && printf '%s' "$integrated_merge_sha" | grep -q -E '^[0-9a-f]{40}$'; then
    ok "Claim C releases.toml records integrated merge SHA"
  else
    partial "Claim C releases.toml integrated_merge_sha is not recorded (${integrated_merge_sha:-missing})"
  fi
else
  partial "Claim C releases.toml missing; bounded package status remains pending"
fi

printf '\n----- check-bounded assurance summary -----\n'
printf 'checks run: %d\n' "$checks"
printf 'failures:   %d\n' "$fail"
printf 'partials:   %d\n' "$partials"
if [ "$diagnostic_mode" -eq 1 ]; then
  printf 'mode:       DIAGNOSTIC (partials count as warnings, not failures)\n'
else
  printf 'mode:       ASSURANCE-GATE (partials count as failures; --diagnostic to relax)\n'
fi

# Strict default: PARTIAL rows are treated as failures so the close gate
# cannot pass while any claim is still in baseline / in-progress state.
# `--diagnostic` mode is opt-in and only allows real FAIL rows to flip
# the gate red.
if [ "$fail" -ne 0 ]; then
  printf '\nbounded assurance gate: FAIL (%d fail row(s), %d partial row(s))\n' "$fail" "$partials"
  exit 1
fi

if [ "$diagnostic_mode" -eq 1 ]; then
  if [ "$partials" -gt 0 ]; then
    printf '\nbounded assurance gate: PASS (diagnostic mode; %d partial row(s) reported as warnings)\n' "$partials"
  else
    printf '\nbounded assurance gate: PASS (diagnostic mode; no partial rows)\n'
  fi
  exit 0
fi

if [ "$partials" -ne 0 ]; then
  printf '\nbounded assurance gate: FAIL (assurance-gate mode; %d partial row(s) block close)\n' "$partials"
  printf '  re-run with --diagnostic for an advisory snapshot during baseline measurement\n'
  exit 1
fi

printf '\nbounded assurance gate: PASS (assurance-gate mode; all claims MET)\n'
exit 0
