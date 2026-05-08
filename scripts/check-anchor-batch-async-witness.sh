#!/usr/bin/env bash
# scripts/check-anchor-batch-async-witness.sh
#
# ============================================================================
# SOUNDNESS CONTRACT (HONEST)
# ============================================================================
#
# This script is intentionally NOT sound. It is a grep-window heuristic. Per
# the R3 review (BLOCKER #2 fix), the lint's contract is:
#
#   - False POSITIVES are tolerated. The window can flag advisory-mode
#     callers if a `require_public_witness: true` literal happens to live
#     within 50 lines of an unrelated sync-wrapper call.
#
#   - False NEGATIVES are also tolerated. The window CANNOT catch:
#       (a) `WitnessPolicy` constructed in a different function from where
#           the sync wrapper is called (50-line windows do not span
#           function boundaries reliably).
#       (b) `WitnessPolicy` deserialized from JSON or YAML configs (the
#           literal `require_public_witness: true` lives outside Rust
#           source).
#       (c) Builder/setter-style construction
#           (`WitnessPolicy::default().require_public_witness(true)` does
#           not match the regex).
#       (d) Cross-crate / cross-file calls where the producer of the policy
#           and the consumer of the sync wrapper live in different files.
#
# `crates/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy`,
# which returns `AnchorError::SyncRouteRequiresAdvisoryPolicy` when the
# policy carries `require_public_witness=true`. That gate is the spec MUST
# (PROTOCOL.md "Anchor batch public-witness lane" lines ~980-993)
# enforcement. The companion negative conformance fixture at
# `crates/chio-conformance/tests/b3_anchor_batch_sync_path_rejected_under_public_witness.rs`
# pins the gate; if the gate is reverted, the fixture fails.
#
# ============================================================================
# ALGORITHM
# ============================================================================
#
# For each Rust file in `crates/` that is NOT under a `tests/`, `benches/`,
# or `fuzz/` path and NOT a `*_test.rs`, `*_tests.rs` file:
#   1. Find lines matching `verify_anchor_batch_with_witness_policy(`
#      that are NOT the async variant (`_async`) and NOT the function
#      definition itself (`pub fn ` / `fn ` prefix).
#   2. For each such call site, scan +/- 50 lines for a literal
#      `require_public_witness: true` (or `require_public_witness:true`).
#   3. If found in the SAME FILE, exit non-zero with the failing site
#      printed.
#
# Idempotent: running the script repeatedly returns the same exit code on
# the same tree. Exit 0 means no obvious-case violations; exit 1 means a
# violation was found.
#
# ============================================================================
# USAGE
# ============================================================================
#
#   ./scripts/check-anchor-batch-async-witness.sh

set -uo pipefail

cd "$(dirname "$0")/.."

WINDOW_LINES=50
SYNC_CALL_RE='verify_anchor_batch_with_witness_policy[[:space:]]*\('
ASYNC_CALL_TOKEN='verify_anchor_batch_with_witness_policy_async'
DEF_RE='^[[:space:]]*(pub[[:space:]]+)?(unsafe[[:space:]]+)?(async[[:space:]]+)?fn[[:space:]]+verify_anchor_batch_with_witness_policy\b'
POLICY_TRUE_RE='require_public_witness[[:space:]]*:[[:space:]]*true'

# Use a temp file to collect failures (portable across bash 3.2 / 4+).
failures_file="$(mktemp)"
trap 'rm -f "$failures_file"' EXIT

# Production-only Rust files. Exclusions: tests/, benches/, fuzz/,
# examples/, *_test.rs, *_tests.rs. Pre-filter to files that actually
# contain the sync-wrapper token to avoid spawning grep on every file.
candidate_files="$(mktemp)"
trap 'rm -f "$failures_file" "$candidate_files"' EXIT

find crates/ -name '*.rs' -type f \
    -not -path '*/tests/*' \
    -not -path '*/benches/*' \
    -not -path '*/fuzz/*' \
    -not -path '*/examples/*' \
    -not -name '*_test.rs' \
    -not -name '*_tests.rs' \
    -print0 \
| xargs -0 grep -lE "$SYNC_CALL_RE" 2>/dev/null \
| sort > "$candidate_files" || true

while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    # Pull every sync-wrapper call line (not the async variant, not the
    # function definition itself).
    while IFS=':' read -r linenum content; do
        [[ -z "$linenum" ]] && continue
        # Skip the function definition line.
        if [[ "$content" =~ $DEF_RE ]]; then
            continue
        fi
        # Skip lines that are the async variant.
        if [[ "$content" == *"$ASYNC_CALL_TOKEN"* ]]; then
            continue
        fi
        # Skip pure documentation lines (start with `//` or `///`).
        trimmed="$(printf '%s' "$content" | sed -e 's/^[[:space:]]*//')"
        if [[ "$trimmed" == //* ]]; then
            continue
        fi

        start=$((linenum - WINDOW_LINES))
        end=$((linenum + WINDOW_LINES))
        if (( start < 1 )); then start=1; fi

        window="$(sed -n "${start},${end}p" "$file")"
        if printf '%s\n' "$window" | grep -Eq "$POLICY_TRUE_RE"; then
            printf '%s:%s: sync wrapper called near literal require_public_witness=true (best-effort lint; see runtime gate at crates/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy)\n' \
                "$file" "$linenum" >> "$failures_file"
        fi
    done < <(grep -nE "$SYNC_CALL_RE" "$file" 2>/dev/null \
        | grep -v "$ASYNC_CALL_TOKEN" \
        || true)
done < "$candidate_files"

if [[ -s "$failures_file" ]]; then
    echo "anchor-batch async-witness gate FAILED:"
    while IFS= read -r line; do
        echo "  $line"
    done < "$failures_file"
    echo
    echo "Hint: route public-witness verification through"
    echo "  chio_anchor::verify_anchor_batch_with_witness_policy_async"
    echo "or set policy.require_public_witness=false for advisory-only callers."
    exit 1
fi

echo "anchor-batch async-witness lint passed (best-effort; runtime gate is load-bearing)"
exit 0
