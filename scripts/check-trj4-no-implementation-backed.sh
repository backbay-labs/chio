#!/usr/bin/env bash
# check-trj4-no-implementation-backed.sh
#
# Trajectory-4 closeout gate. The deprecated theorem status
# `implementation_backed` was demoted to `proposed` (see PR titled
# "chore(trj4-closeout): demote implementation_backed theorems to proposed").
# This gate fails closed if the literal string `implementation_backed`
# reappears anywhere under spec/registries/ or formal/, which would silently
# re-promote a theorem past the Evidence Gate.
#
# Exit codes:
#   0 - no occurrences (gate green)
#   1 - one or more occurrences (gate red)

set -euo pipefail

cd "$(dirname "$0")/.."

needle='implementation_backed'
roots=(spec/registries formal)

# `grep -r` returns 1 when no match is found, which is the success case for
# this gate. Capture the exit status manually so `set -e` does not abort us
# on the no-match path. We pass `|| true` to grep so the script proceeds; we
# then inspect the captured output.
hits=""
for root in "${roots[@]}"; do
  if [ -d "$root" ]; then
    found=$(grep -RInF -- "$needle" "$root" 2>/dev/null || true)
    if [ -n "$found" ]; then
      hits+="${found}"$'\n'
    fi
  fi
done

if [ -n "$hits" ]; then
  echo "::error::trj4 closeout gate: found '${needle}' in tracked registry/formal sources." 1>&2
  echo "Demote these entries to 'proposed' (or 'proven'/'assumed') before merging:" 1>&2
  printf '%s' "$hits" 1>&2
  exit 1
fi

echo "trj4 closeout gate: no '${needle}' occurrences under ${roots[*]}"
