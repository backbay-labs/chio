#!/usr/bin/env bash
# Bounded release kickoff preflight gate.
#
# Returns exit 0 only if every kickoff prerequisite enumerated in
# `.planning/trajectory-5/KICKOFF-CHECKLIST.md` is satisfied:
#
#   Gate 1: planning artifacts present (master docs)
#   Gate 2: per-lane PLAN.md / planning docs / README.md present
#   Gate 3: templates and architecture docs present
#   Gate 4: Wave-2 reviews + Wave-3 fix logs + Wave-4 closeout + Wave-2 sign-off ledgers
#   Gate 5: OWNERS.toml human_assignment populated for all three lanes
#   Gate 6: releases.toml [v0_1_0_bounded_chiodome] block exists with status set
#   Gate 7: ship-bar baseline measurements present
#   Gate 8: drift-cleanup checks (no LB-* aliases in Depends-on rows;
#           no live Option A design references; ToolServer mentions
#           confined to retraction notes)
#
# Run from the chio repo root: `bash scripts/bounded-release-preflight.sh`.
# Output is one OK/FAIL line per check. Exit 0 if all PASS, 1 otherwise.

set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

fail=0
checks=0

# --- helpers ---------------------------------------------------------------

ok() {
  printf 'OK   %s\n' "$1"
  checks=$((checks + 1))
}

failure() {
  printf 'FAIL %s\n' "$1"
  fail=$((fail + 1))
  checks=$((checks + 1))
}

warn() {
  printf 'WARN %s\n' "$1"
  checks=$((checks + 1))
}

check_file() {
  local path="$1"
  if [ -f "$path" ]; then
    ok "$path exists"
  else
    failure "$path is missing"
  fi
}

check_dir() {
  local path="$1"
  if [ -d "$path" ]; then
    ok "$path/ exists"
  else
    failure "$path/ is missing"
  fi
}

check_grep_present() {
  local pattern="$1"
  local path="$2"
  local label="$3"
  if grep -q -- "$pattern" "$path" 2>/dev/null; then
    ok "$label"
  else
    failure "$label (pattern '$pattern' not found in $path)"
  fi
}

check_grep_absent_or_in_context() {
  # Variant: pattern must not appear in load-bearing context. We accept
  # matches only if a context word also appears on the same line (e.g.
  # "footnote", "documentation table", or the pattern is preceded by an
  # alias-mapping bar character).
  local pattern="$1"
  local label="$2"
  shift 2
  local hits
  # shellcheck disable=SC2016
  hits=$(grep -rn -E "$pattern" "$@" 2>/dev/null | grep -v -E '/reviews/|/debate/' || true)
  if [ -z "$hits" ]; then
    ok "$label (zero matches in load-bearing prose)"
  else
    # If every hit looks like a documentation-table row (starts with `|`)
    # or is in a retraction/footnote context, accept; otherwise FAIL.
    local non_context
    non_context=$(printf '%s\n' "$hits" \
      | grep -v -E ':[[:space:]]*\|' \
      | grep -v -i -E 'footnote|retraction|rejected|superseded|cross-reference|alias|documentation table|deprecated|legacy|"option a"' || true)
    if [ -z "$non_context" ]; then
      ok "$label (matches confined to documentation tables / retraction notes)"
    else
      failure "$label found in load-bearing prose"
      printf '%s\n' "$non_context" | head -5 | sed 's/^/     /' >&2
    fi
  fi
}

# ---------------------------------------------------------------------------
# Gate 1: planning artifacts present
# ---------------------------------------------------------------------------
printf '\n[Gate 1] planning artifacts\n'
check_file ".planning/trajectory-5/README.md"
check_file ".planning/trajectory-5/EXECUTION-BOARD.md"
check_file ".planning/trajectory-5/SHIP-BAR-TRACKER.md"
check_file ".planning/trajectory-5/SCOPE-LOCK.md"
check_file ".planning/trajectory-5/TIMELINE.md"
check_file ".planning/trajectory-5/KICKOFF-CHECKLIST.md"
check_file ".planning/trajectory-5/OWNERS.toml"
check_file ".planning/trajectory-5/READINESS.md"

# ---------------------------------------------------------------------------
# Gate 2: per-lane PLAN.md / tickets.md / README.md
# ---------------------------------------------------------------------------
printf '\n[Gate 2] per-lane planning files\n'
for lane in lane-a-floor lane-b-wiring lane-c-demo; do
  check_file ".planning/trajectory-5/$lane/PLAN.md"
  check_file ".planning/trajectory-5/$lane/tickets.md"
  check_file ".planning/trajectory-5/$lane/README.md"
done

# ---------------------------------------------------------------------------
# Gate 3: templates and architecture
# ---------------------------------------------------------------------------
printf '\n[Gate 3] templates and architecture\n'
for f in \
  templates/EVIDENCE-GATE.md \
  templates/CONFORMANCE-FIXTURE-PATTERN.md \
  templates/TICKET-TEMPLATE.md \
  architecture/ASYNC-KERNEL-MIGRATION.md \
  architecture/SPEC-TO-RUNTIME-MAP.md \
  architecture/RISK-REGISTER.md
do
  check_file ".planning/trajectory-5/$f"
done

# ---------------------------------------------------------------------------
# Gate 4: Wave-2 reviews + Wave-3 fixes + Wave-4 closeout + Wave-2 sign-offs
# ---------------------------------------------------------------------------
printf '\n[Gate 4] Wave-2 reviews + Wave-3 fixes + Wave-4 closeout + Wave-2 sign-offs\n'
for f in \
  reviews/R1-cross-lane.md \
  reviews/R2-lane-a-depth.md \
  reviews/R3-lane-b-compliance.md \
  reviews/R4-lane-c-feasibility.md \
  reviews/W3-lane-a-fixes.md \
  reviews/W3-lane-b-fixes.md \
  reviews/W3-lane-c-fixes.md \
  reviews/W4-closeout-matrix.md \
  reviews/lane-a-wave2.md \
  reviews/lane-b-wave2.md \
  reviews/lane-c-wave2.md
do
  check_file ".planning/trajectory-5/$f"
done

# ---------------------------------------------------------------------------
# Gate 5: OWNERS.toml has human_assignment populated for all three lanes
# ---------------------------------------------------------------------------
printf '\n[Gate 5] OWNERS.toml human_assignment for all three lanes\n'
owners_path=".planning/trajectory-5/OWNERS.toml"

for lane_label in A B C; do
  if awk -v lane="lanes.$lane_label" '
    BEGIN { in_lane = 0; found = 0 }
    /^\[lanes\.[A-Z]\]/ {
      in_lane = 0
      if ($0 ~ "\\["lane"\\]") { in_lane = 1 }
    }
    in_lane && /^human_assignment[[:space:]]*=/ {
      gsub(/[[:space:]]/, "")
      if ($0 !~ /"TBD"/ && $0 !~ /"tbd"/ && $0 !~ /""/) { found = 1 }
    }
    END { exit (found ? 0 : 1) }
  ' "$owners_path"; then
    ok "OWNERS.toml lanes.$lane_label.human_assignment populated (not TBD/empty)"
  else
    failure "OWNERS.toml lanes.$lane_label.human_assignment is TBD/empty"
  fi
done

# Also assert no leftover TBD/TODO/FIXME tokens in OWNERS.toml proper.
if grep -q -E '"TBD"|"tbd"|TODO|FIXME' "$owners_path"; then
  failure "OWNERS.toml still contains TBD/TODO/FIXME tokens"
  grep -nE '"TBD"|"tbd"|TODO|FIXME' "$owners_path" | head -5 | sed 's/^/     /' >&2
else
  ok "OWNERS.toml has no TBD/TODO/FIXME tokens"
fi

# ---------------------------------------------------------------------------
# Gate 6: releases.toml has [v0_1_0_bounded_chiodome] block with status set
# ---------------------------------------------------------------------------
printf '\n[Gate 6] releases.toml [v0_1_0_bounded_chiodome] block\n'
if [ ! -f releases.toml ]; then
  failure "releases.toml is missing"
else
  if grep -q -E '^\[v0_1_0_bounded_chiodome\]' releases.toml; then
    ok "releases.toml has [v0_1_0_bounded_chiodome] section"
  else
    failure "releases.toml is missing [v0_1_0_bounded_chiodome] section"
  fi
  if grep -q -E '^release_status[[:space:]]*=' releases.toml; then
    ok "releases.toml has release_status set"
  else
    failure "releases.toml is missing release_status"
  fi
  if grep -q -E '^baseline_sha[[:space:]]*=' releases.toml; then
    ok "releases.toml has baseline_sha set"
  else
    failure "releases.toml is missing baseline_sha"
  fi
fi

# ---------------------------------------------------------------------------
# Gate 7: ship-bar baseline measurements
# ---------------------------------------------------------------------------
printf '\n[Gate 7] ship-bar baselines\n'
check_file ".planning/trajectory-5/baselines/BAR-1-MUTATION.md"
check_file ".planning/trajectory-5/baselines/BAR-2-CONFORMANCE-FIXTURES.md"
check_file ".planning/trajectory-5/baselines/BAR-3-DEMO.md"

# ---------------------------------------------------------------------------
# Gate 8: drift-cleanup checks (W4 grep contracts)
# ---------------------------------------------------------------------------
printf '\n[Gate 8] drift cleanup\n'

# (a) No LB-CAP/LB-RV2/LB-AB/LB-AT aliases in Depends-on rows.
# The aliases are allowed in the cross-reference documentation table
# at `lane-c-demo/planning docs` lines ~21-34 (as table rows starting
# with `|`). Failure case: appearance in `Depends on:` lines.
if grep -rn -E '^\s*Depends on:.*(LB-CAP|LB-RV2|LB-AB|LB-AT)\b' .planning/trajectory-5/ 2>/dev/null | grep -v /reviews/ | grep -v /debate/; then
  failure "LB-* aliases still appear in 'Depends on:' rows"
else
  ok "no LB-CAP/LB-RV2/LB-AB/LB-AT aliases in 'Depends on:' rows"
fi

# (b) ToolServer\b only in retraction-notes / struct-name / method-name
# context. Soft check: any bare ToolServer in load-bearing master/lane
# prose (excluding /debate/ and /reviews/) that is NOT clearly a struct
# name (Echo*, Shared*) or method name (register_*) or a footnoted
# synthesis-quote should be flagged. We treat this as a WARN not FAIL
# because the spec calls for soft warning if exact assertion is brittle.
tool_server_hits=$(grep -rn -E 'ToolServer\b' .planning/trajectory-5/ 2>/dev/null \
  | grep -v ToolServerConnection \
  | grep -v ToolServerOutput \
  | grep -v ToolServerEvent \
  | grep -v ToolServerStreamResult \
  | grep -v EchoToolServer \
  | grep -v SharedUpstreamToolServer \
  | grep -v register_tool_server \
  | grep -v tool_server_escape \
  | grep -v /reviews/ \
  | grep -v /debate/ || true)
if [ -z "$tool_server_hits" ]; then
  ok "ToolServer\\b mentions confined to struct/method names or retraction context"
else
  # Each remaining line is benign only if it is itself in retraction
  # context (synthesis quote, footnote, corrected, etc.) OR is a
  # markdown blockquote (`> ...`) whose body is the synthesis-verbatim
  # quote that the surrounding prose corrects on the next line.
  bad=$(printf '%s\n' "$tool_server_hits" \
    | grep -v -i -E 'synthesis|footnote|verbatim|corrected|toolservercon|note[: ]|synthesis-verbatim|tool[- ]server async migration' \
    | grep -v -E ':[[:space:]]*>[[:space:]]*"' \
    || true)
  if [ -z "$bad" ]; then
    ok "ToolServer\\b mentions all in retraction/footnote/synthesis-blockquote context"
  else
    warn "ToolServer\\b mentions in unexpected context (review manually)"
    printf '%s\n' "$bad" | head -5 | sed 's/^/     /' >&2
  fi
fi

# (c) No live "Option A" design references in lane-c-demo/. The W3 fix
# dropped Option A; remaining mentions describe the rejection. Allow
# matches only when "rejected", "superseded", "dropped", "originally",
# "previously-proposed", or "the original" appear nearby.
opta_hits=$(grep -rn -E '"Option A"|\bOption A\b' .planning/trajectory-5/lane-c-demo/ 2>/dev/null || true)
if [ -z "$opta_hits" ]; then
  ok "no 'Option A' references in lane-c-demo/"
else
  # Pull the matches AND a couple of surrounding lines and check for retraction context.
  bad_opta=""
  while IFS= read -r line; do
    file_part=${line%%:*}
    line_no=${line#*:}
    line_no=${line_no%%:*}
    # Read +/- 2 line window around the match.
    if ! awk -v line="$line_no" 'NR >= line - 2 && NR <= line + 2' "$file_part" 2>/dev/null \
      | grep -q -i -E 'rejected|superseded|dropped|originally|previously|original|insufficient|review finding|review|REWORKED|two-signature'; then
      bad_opta="$bad_opta\n$line"
    fi
  done <<< "$opta_hits"
  if [ -z "$bad_opta" ]; then
    ok "'Option A' references all in retraction/rejection context"
  else
    failure "'Option A' references appear in load-bearing design prose"
    printf '%b' "$bad_opta" | head -5 | sed 's/^/     /' >&2
  fi
fi

# (d) dsse-bilateral-signing.md exists in lane-b-wiring/.
check_file ".planning/trajectory-5/lane-b-wiring/dsse-bilateral-signing.md"

# (e) audits/evidence/threats/ has 20 files (per W3 Lane A R1-MAJOR-4.2 fix).
threat_count=$(ls audits/evidence/threats/*.json 2>/dev/null | wc -l | tr -d ' ')
if [ "$threat_count" = "20" ]; then
  ok "audits/evidence/threats/ has exactly 20 JSON files"
else
  failure "audits/evidence/threats/ has $threat_count JSON files (expected 20)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
printf '\n----- bounded-release-preflight summary -----\n'
printf 'checks run: %d\n' "$checks"
printf 'failures:   %d\n' "$fail"
if [ "$fail" -eq 0 ]; then
  printf '\nbounded release preflight: PASS\n'
  exit 0
else
  printf '\nbounded release preflight: %d FAIL(s)\n' "$fail"
  exit 1
fi
