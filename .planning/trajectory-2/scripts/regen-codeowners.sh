#!/usr/bin/env bash
# regen-codeowners.sh - Dual-trajectory CODEOWNERS regenerator.
#
# Reads both .planning/trajectory/OWNERS.toml (trajectory-1) and
# .planning/trajectory-2/OWNERS.toml, then emits a single canonical
# CODEOWNERS file at the workspace root. trajectory-2 entries are merged
# with trajectory-1 entries; for any glob owned by both, the reviewer
# sets are unioned. Output is sorted with longer (more-specific) globs
# first so CODEOWNERS later-pattern-wins semantics resolve to the most
# specific rule by line position.
#
# Usage:
#   .planning/trajectory-2/scripts/regen-codeowners.sh           # write CODEOWNERS
#   .planning/trajectory-2/scripts/regen-codeowners.sh --dry-run # print, do not write
#   .planning/trajectory-2/scripts/regen-codeowners.sh --self-test
#
# Required input files:
#   .planning/trajectory/OWNERS.toml      (optional; warn if absent)
#   .planning/trajectory-2/OWNERS.toml    (required)
#
# Output target:
#   <repo-root>/CODEOWNERS                (overwritten on success)
#
# Exit codes:
#   0  success (or --dry-run / --self-test passed)
#   1  drift / self-test failure
#   2  precondition failure (yq missing, OWNERS.toml malformed)
#
# Requires: yq (mikefarah v4.x), awk, sort, tr (all standard).

set -euo pipefail

# ---------- locate inputs and outputs ----------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
T1_OWNERS="${REPO_ROOT}/.planning/trajectory/OWNERS.toml"
T2_OWNERS="${REPO_ROOT}/.planning/trajectory-2/OWNERS.toml"
CODEOWNERS_OUT="${REPO_ROOT}/CODEOWNERS"

mode="write"
case "${1:-}" in
  --dry-run)   mode="dry-run" ;;
  --self-test) mode="self-test" ;;
  "")          mode="write" ;;
  *) printf 'unknown flag: %s\n' "$1" >&2; exit 2 ;;
esac

err() { printf '%s\n' "$*" >&2; }

if ! command -v yq >/dev/null 2>&1; then
  err "missing required tool: yq (mikefarah v4.x)"
  exit 2
fi
if [[ ! -f "${T2_OWNERS}" ]]; then
  err "trajectory-2 OWNERS.toml not found: ${T2_OWNERS}"
  exit 2
fi

# ---------- parse trajectory-1 OWNERS.toml ----------
#
# Schema: top-level [teams] mapping milestone slug to handle, plus
# [[ownership]] array entries (glob, owners list, optional codeowners
# = false flag). We resolve handles via [teams] and emit
# "<glob>\t<handles space-sep>\t<comment>" lines.

t1_lines=""
if [[ -f "${T1_OWNERS}" ]]; then
  t1_lines="$(yq -p=toml -oy '
    .teams as $teams
    | .ownership
    | map(select(.codeowners != false))
    | map(. + {"handles": [.owners[] | $teams[.] // ("@MISSING_TEAM_" + .)] | unique})
    | .[]
    | .glob + "\t" + (.handles | join(" ")) + "\ttrajectory-1\tfalse"
  ' "${T1_OWNERS}" 2>/dev/null || true)"
fi

# ---------- parse trajectory-2 OWNERS.toml ----------
#
# Schema differs from trajectory-1: top-level scalars
# (trajectory, genesis, single_owner) plus a [milestones.MNN] map
# whose values carry owner_globs[], reviewer, and (optional) review_x2.
# The reviewer field is a single handle. review_x2 = true means the
# emitted line gets a "trust-boundary; review_x2" comment so reviewers
# can spot it in the file.

t2_lines="$(yq -p=toml -oy '
  .milestones | to_entries[] | .key as $mk | .value as $mv |
  $mv.owner_globs[] | . as $g |
  $g + "\t" + $mv.reviewer + "\ttrajectory-2 " + $mk + "\t" + (($mv.review_x2 // false) | tostring)
' "${T2_OWNERS}")"

if [[ -z "${t2_lines}" ]]; then
  err "yq produced no entries from trajectory-2 OWNERS.toml; file may be malformed"
  exit 2
fi

# ---------- merge and dedupe ----------
#
# Combine both line sets, then for each unique glob union the handle
# tokens and the comment tokens. awk preserves insertion order for the
# first appearance of each glob; we re-sort afterwards by glob length
# descending so more-specific paths sort first.

combined="$(printf '%s\n%s\n' "${t1_lines}" "${t2_lines}" | sed '/^$/d')"

merged="$(printf '%s\n' "${combined}" | awk -F'\t' '
  {
    glob   = $1
    owners = $2
    note   = $3
    r2     = $4
    if (!(glob in seen)) {
      order[++n] = glob
      seen[glob] = 1
      ownerlist[glob] = owners
      notelist[glob]  = note
      r2list[glob]    = r2
    } else {
      # union owners (whitespace separated, dedupe)
      split(ownerlist[glob], existing, " ")
      delete have
      for (i in existing) have[existing[i]] = 1
      split(owners, incoming, " ")
      for (i in incoming) {
        if (incoming[i] != "" && !(incoming[i] in have)) {
          have[incoming[i]] = 1
          ownerlist[glob] = ownerlist[glob] " " incoming[i]
        }
      }
      # union note (separator " + ")
      if (index(notelist[glob], note) == 0) {
        notelist[glob] = notelist[glob] " + " note
      }
      # logical OR on review_x2
      if (r2 == "true") r2list[glob] = "true"
    }
  }
  END {
    for (i = 1; i <= n; i++) {
      g = order[i]
      printf "%s\t%s\t%s\t%s\n", g, ownerlist[g], notelist[g], r2list[g]
    }
  }
')"

# ---------- sort by specificity (longest path first) ----------
#
# CODEOWNERS uses "later wins" semantics, so we put the longest globs
# last. Sorting descending by character length and then alphabetically
# emits the shortest (broadest) globs first and the longest (most
# specific) globs last, matching the trajectory-1 layout.

sorted="$(printf '%s\n' "${merged}" | awk -F'\t' '{ print length($1) "\t" $0 }' \
  | sort -k1,1n -k2,2 \
  | cut -f2-)"

# ---------- format with aligned columns and trust-boundary comments ----------

formatted="$(printf '%s\n' "${sorted}" | awk -F'\t' '
  {
    glob   = $1
    owners = $2
    note   = $3
    r2     = $4
    if (r2 == "true") {
      comment = "  # trust-boundary; review_x2"
    } else {
      comment = ""
    }
    if (length(glob) < 45) {
      printf "%-44s %s%s\n", glob, owners, comment
    } else {
      printf "%s %s%s\n", glob, owners, comment
    }
  }
')"

header="$(cat <<'HEADER'
# CODEOWNERS - GENERATED from .planning/trajectory{,-2}/OWNERS.toml. Do not hand-edit.
# Regenerate with .planning/trajectory-2/scripts/regen-codeowners.sh.
# CI fails if this file drifts. Order matters in CODEOWNERS: later
# patterns take precedence, so most-specific globs are emitted last.
HEADER
)"

new_content="${header}

${formatted}"

# ---------- self-test ----------

if [[ "${mode}" == "self-test" ]]; then
  # Re-invoke with --dry-run and validate output well-formedness.
  out="$("${BASH_SOURCE[0]}" --dry-run)"
  if [[ -z "${out}" ]]; then
    err "self-test FAIL: dry-run output is empty"
    exit 1
  fi
  body="$(printf '%s\n' "${out}" | grep -Ev '^[[:space:]]*(#|$)' || true)"
  if [[ -z "${body}" ]]; then
    err "self-test FAIL: dry-run produced no CODEOWNERS entries"
    exit 1
  fi
  bad=0
  while IFS= read -r line; do
    # Strip trailing inline comments before validating.
    bare="${line%%#*}"
    # Each non-comment line must have a path token and at least one
    # @handle token.
    path_tok="$(printf '%s\n' "${bare}" | awk '{print $1}')"
    handle_tok="$(printf '%s\n' "${bare}" | awk '{print $2}')"
    if [[ -z "${path_tok}" ]]; then
      err "self-test FAIL: empty path on line: ${line}"
      bad=$((bad + 1))
    fi
    if [[ "${handle_tok}" != @* ]]; then
      err "self-test FAIL: missing @handle on line: ${line}"
      bad=$((bad + 1))
    fi
  done <<< "${body}"
  if [[ "${bad}" -gt 0 ]]; then
    exit 1
  fi
  printf 'self-test OK: %d entries; all lines well-formed\n' \
    "$(printf '%s\n' "${body}" | wc -l | tr -d ' ')"
  exit 0
fi

# ---------- write or print ----------

case "${mode}" in
  dry-run)
    printf '%s\n' "${new_content}"
    ;;
  write)
    printf '%s\n' "${new_content}" > "${CODEOWNERS_OUT}"
    printf 'wrote %s\n' "${CODEOWNERS_OUT}"
    ;;
esac
