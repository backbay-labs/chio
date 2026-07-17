#!/usr/bin/env bash
# scripts/check-anchor-batch-async-witness.sh
#
# ============================================================================
# SOUNDNESS CONTRACT (HONEST)
# ============================================================================
#
# This script is a blocking CI companion for the load-bearing runtime gate.
# It is intentionally a grep-window heuristic, not a sound proof. The lint's
# contract is:
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
#       (c) Constructor/builder-style policy flows
#           (`WitnessPolicy::default()` or `WitnessPolicy::advisory()`
#           passed across helper boundaries do not match the regex).
#       (d) Cross-crate / cross-file calls where the producer of the policy
#           and the consumer of the sync wrapper live in different files.
#
# `crates/economy/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy`,
# which returns `AnchorError::SyncRouteRequiresAdvisoryPolicy` when the
# policy carries `require_public_witness=true`. That gate is the spec MUST
# (PROTOCOL.md "Anchor batch public-witness lane" lines ~980-993)
# enforcement. The companion negative conformance fixture at
# `crates/tooling/chio-conformance/tests/b3_anchor_batch_sync_path_rejected_under_public_witness.rs`
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
#   ./scripts/check-anchor-batch-async-witness.sh [--advisory]
#
# `--advisory` is a no-op flag whose purpose is to mark explicit local
# caller intent.
# The script's ALGORITHM is best-effort by design (see SOUNDNESS
# CONTRACT above); the load-bearing public-witness lane gate is the
# runtime `AnchorError::SyncRouteRequiresAdvisoryPolicy` arm in
# `crates/economy/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy`.
# This lint is a fast-feedback companion: it fails loudly on detected
# violations, but a clean exit does NOT prove the absence of a bypass.
# CI posture is non-advisory (blocking); the [PUBLIC-WITNESS-LINT] prefix
# below makes the blocking companion contract visible in logs.

set -euo pipefail

cd "$(dirname "$0")/.."

# `--advisory` is accepted purely to document local caller intent; the
# script's behaviour does not change.
advisory_caller=0
for arg in "$@"; do
  case "$arg" in
    --advisory)
      advisory_caller=1
      ;;
    -h|--help)
      sed -n '2,68p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "check-anchor-batch-async-witness.sh: unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

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
all_files="$(mktemp)"
trap 'rm -f "$failures_file" "$candidate_files" "$all_files"' EXIT

find crates/ -name '*.rs' -type f \
    -not -path '*/tests/*' \
    -not -path '*/benches/*' \
    -not -path '*/fuzz/*' \
    -not -path '*/examples/*' \
    -not -name '*_test.rs' \
    -not -name '*_tests.rs' \
    -print0 > "$all_files"

while IFS= read -r -d '' file; do
    if grep -qE "$SYNC_CALL_RE" "$file"; then
        printf '%s\n' "$file"
    else
        status=$?
        if [[ "$status" -gt 1 ]]; then
            exit "$status"
        fi
    fi
done < "$all_files" | sort > "$candidate_files"

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
            printf '%s:%s: sync wrapper called near literal require_public_witness=true (best-effort lint; see runtime gate at crates/economy/chio-anchor/src/batch.rs::verify_anchor_batch_with_witness_policy)\n' \
                "$file" "$linenum" >> "$failures_file"
        fi
    done < <(grep -nE "$SYNC_CALL_RE" "$file" 2>/dev/null \
        | grep -v "$ASYNC_CALL_TOKEN" \
        || true)
done < "$candidate_files"

if [[ -s "$failures_file" ]]; then
    echo "[PUBLIC-WITNESS-LINT] anchor-batch async-witness gate FAILED:"
    while IFS= read -r line; do
        echo "  [PUBLIC-WITNESS-LINT] $line"
    done < "$failures_file"
    echo
    echo "[PUBLIC-WITNESS-LINT] Hint: route public-witness verification through"
    echo "  chio_anchor::verify_anchor_batch_with_witness_policy_async"
    echo "or use WitnessPolicy::advisory() for explicit advisory-only callers."
    echo
    echo "[PUBLIC-WITNESS-LINT] NOTE: this lint is the fast-feedback companion to"
    echo "  the runtime gate at crates/economy/chio-anchor/src/batch.rs"
    echo "  (AnchorError::SyncRouteRequiresAdvisoryPolicy). The runtime gate"
    echo "  is load-bearing; this lint can produce false negatives (see"
    echo "  SOUNDNESS CONTRACT in this script). Failing here is a real bug;"
    echo "  passing here does NOT prove the absence of a bypass."
    exit 1
fi

if [[ "$advisory_caller" -eq 1 ]]; then
    echo "[PUBLIC-WITNESS-LINT] anchor-batch async-witness lint passed (best-effort; --advisory caller acknowledged the load-bearing runtime gate at crates/economy/chio-anchor/src/batch.rs)"
else
    echo "[PUBLIC-WITNESS-LINT] anchor-batch async-witness lint passed"
    echo "[PUBLIC-WITNESS-LINT] NOTE: this is a best-effort grep heuristic. A clean exit does NOT prove the absence of a bypass; the load-bearing public-witness lane gate is the runtime AnchorError::SyncRouteRequiresAdvisoryPolicy arm in crates/economy/chio-anchor/src/batch.rs. Pass --advisory only for explicit local advisory runs."
fi
exit 0
