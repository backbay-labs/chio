#!/usr/bin/env bash
# Behavioral regression test for scripts/check-trj5-ship-bar.sh strict
# default mode and `--diagnostic` opt-in (audit T5-R2-P0-013, T5-R3-P1-006).
#
# The audit's required behaviour:
#   * Default (release-gate): a single PARTIAL row exits 1.
#   * `--diagnostic`: PARTIAL rows are downgraded to warnings; exit 0.
#   * Real FAIL rows still exit 1 in either mode (sanity).
#
# This test creates a synthesized repo layout under a tempdir and copies
# the real `check-trj5-ship-bar.sh` into it, then exercises the strict /
# diagnostic exit modes against a fixture state that exercises Bar 1
# (PARTIAL chio-policy row) without invoking the rest of the tooling.
#
# The script under test resolves its repo_root via `BASH_SOURCE`, so we
# place a copy of the script in `$WORK/scripts/` and cd that copy. No
# changes to the script are required.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REAL_GATE="$REAL_REPO_ROOT/scripts/check-trj5-ship-bar.sh"

if [ ! -f "$REAL_GATE" ]; then
    echo "FAIL: cannot locate $REAL_GATE" >&2
    exit 1
fi

WORK="$(mktemp -d -t chio-shipbar-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

OUT="$WORK/out"
ERR="$WORK/err"

# ---------------------------------------------------------------------
# Stage 1: build a synthetic repo layout with one PARTIAL bar 1 row,
# everything else passing. PARTIAL is induced via a chio-policy
# baseline JSON that records `kill_rate_percent = 50` (below the 65%
# floor; the script reports it as PARTIAL with rate printed).
# ---------------------------------------------------------------------

# Copy the script unchanged so its `BASH_SOURCE`-based repo_root pivots
# to $WORK.
mkdir -p "$WORK/scripts"
cp "$REAL_GATE" "$WORK/scripts/check-trj5-ship-bar.sh"
chmod +x "$WORK/scripts/check-trj5-ship-bar.sh"

GATE="$WORK/scripts/check-trj5-ship-bar.sh"

# Bar 1 evidence:
#   * Five trust-boundary crates with passing baselines (>=65%).
#   * chio-policy with a 50% baseline -> PARTIAL row (the fixture).
mkdir -p "$WORK/audits/evidence/mutants"
for crate in chio-credentials chio-attest-verify chio-kernel-core chio-guards chio-anchor; do
    mkdir -p "$WORK/audits/evidence/mutants/$crate"
    if [ "$crate" = "chio-attest-verify" ]; then
        # chio-attest-verify has a 80% target; meet it cleanly.
        cat > "$WORK/audits/evidence/mutants/$crate/2026-05-08.json" <<EOF
{"crate":"$crate","kill_rate_percent":85.0,"caught":85,"viable":100}
EOF
    else
        cat > "$WORK/audits/evidence/mutants/$crate/2026-05-08.json" <<EOF
{"crate":"$crate","kill_rate_percent":75.0,"caught":75,"viable":100}
EOF
    fi
done
# chio-policy: PARTIAL fixture (50% < 65% floor).
mkdir -p "$WORK/audits/evidence/mutants/chio-policy"
cat > "$WORK/audits/evidence/mutants/chio-policy/2026-05-08-per-crate-baseline.json" <<'EOF'
{"crate":"chio-policy","kill_rate_percent":50.0,"caught":50,"viable":100}
EOF

# Bar 1 threats: 20 placeholder JSONs all with caught>=1 and a non-1970
# `ran_at`. (The script reports PARTIAL when count<20 OR any are still
# placeholders; we want all real so we are not double-counting partials
# from this row when validating Bar 1 chio-policy alone.)
mkdir -p "$WORK/audits/evidence/threats"
for i in $(seq 1 20); do
    cat > "$WORK/audits/evidence/threats/t-${i}.json" <<EOF
{"id":"t-${i}","caught":1,"ran_at":"2026-05-08T00:00:00Z"}
EOF
done

# Bar 2 fixtures: presence + negative-conformance annotation.
mkdir -p "$WORK/crates/chio-conformance/tests"
for f in single_entry_verifier_no_bypass.rs \
         receipt_v2_fail_closed_under_negotiated_v2.rs \
         anchor_batch_async_only_with_public_witness.rs \
         b4_bilateral_dsse_pae_only_is_conformant.rs; do
    printf '// negative-conformance fixture\nfn main() {}\n' \
        > "$WORK/crates/chio-conformance/tests/$f"
done
# Companion async-witness script.
printf '#!/usr/bin/env bash\nexit 0\n' \
    > "$WORK/scripts/check-anchor-batch-async-witness.sh"
chmod +x "$WORK/scripts/check-anchor-batch-async-witness.sh"

# Bar 3 demo scaffolding.
mkdir -p "$WORK/examples/chiodome-bilateral/transcripts"
mkdir -p "$WORK/examples/chiodome-bilateral/golden"
mkdir -p "$WORK/examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome"
printf 'all:\n\t@echo demo\n' > "$WORK/examples/chiodome-bilateral/Makefile"
printf '{"transcript":"a"}\n' \
    > "$WORK/examples/chiodome-bilateral/transcripts/a.json"
printf 'golden line\n' \
    > "$WORK/examples/chiodome-bilateral/golden/a.txt"
printf '{"receipt":"v0.1.0"}\n' \
    > "$WORK/examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json"

# releases.toml carries the v0_1_0_bounded_chiodome_release_tag entry.
# Use the placeholder so Bar 3's tag check fires PARTIAL too -- this
# strengthens the test by ensuring at least two PARTIAL rows are
# reported (chio-policy + tag placeholder), so the diagnostic-vs-strict
# gate flip is unambiguous.
cat > "$WORK/releases.toml" <<'EOF'
v0_1_0_bounded_chiodome_release_tag = "pending"
EOF

# ---------------------------------------------------------------------
# Stage 2: default (release-gate) mode -> exit 1.
# ---------------------------------------------------------------------
rc=0
bash "$GATE" >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 2 release-gate mode: expected rc=1 with PARTIAL fixture, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    echo "--- stderr ---" >&2; cat "$ERR" >&2
    exit 1
fi
if ! grep -q -E '^PARTIAL Bar1 chio-policy' "$OUT"; then
    echo "FAIL: stage 2 missing PARTIAL Bar1 chio-policy line" >&2
    cat "$OUT" >&2
    exit 1
fi
if ! grep -q 'release-gate mode' "$OUT"; then
    echo "FAIL: stage 2 missing 'release-gate mode' summary line" >&2
    cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 2 release-gate mode exits 1 with PARTIAL fixture (rc=1)"

# ---------------------------------------------------------------------
# Stage 3: --diagnostic mode -> exit 0 (PARTIAL rows are warnings).
# ---------------------------------------------------------------------
rc=0
bash "$GATE" --diagnostic >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "FAIL: stage 3 --diagnostic mode: expected rc=0 with PARTIAL fixture, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    echo "--- stderr ---" >&2; cat "$ERR" >&2
    exit 1
fi
if ! grep -q -E '^WARN Bar1 chio-policy' "$OUT"; then
    echo "FAIL: stage 3 missing 'WARN Bar1 chio-policy' line (diagnostic-mode marker)" >&2
    cat "$OUT" >&2
    exit 1
fi
if ! grep -q 'diagnostic mode' "$OUT"; then
    echo "FAIL: stage 3 missing 'diagnostic mode' summary line" >&2
    cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 3 --diagnostic mode exits 0 with PARTIAL fixture (rc=0)"

# ---------------------------------------------------------------------
# Stage 4: sanity -- a real FAIL row exits 1 in either mode.
# Trigger by removing one Bar 2 fixture so the script records a FAIL.
# ---------------------------------------------------------------------
rm "$WORK/crates/chio-conformance/tests/single_entry_verifier_no_bypass.rs"
rc=0
bash "$GATE" --diagnostic >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 4 --diagnostic with real FAIL: expected rc=1, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 4 real FAIL row exits 1 even under --diagnostic (rc=1)"

# Stage 5 (cleanup) is implicit via `trap rm -rf $WORK`.
echo "PASS: check-trj5-ship-bar behavioral regression test (T5-R3-P1-006)"
