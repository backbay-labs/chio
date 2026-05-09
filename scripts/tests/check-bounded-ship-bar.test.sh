#!/usr/bin/env bash
# Behavioral regression test for scripts/check-bounded-ship-bar.sh strict
# default mode and `--diagnostic` opt-in.
#
# The audit's required behaviour:
#   * Default (assurance-gate): a single PARTIAL row exits 1.
#   * `--diagnostic`: PARTIAL rows are downgraded to warnings; exit 0.
#   * Real FAIL rows still exit 1 in either mode (sanity).
#
# This test creates a synthesized repo layout under a tempdir and copies
# the real `check-bounded-ship-bar.sh` into it, then exercises the strict
# and diagnostic exit modes against a Bar 1 fixture with a high numeric
# kill rate but explicit partial metadata.
#
# The script under test resolves its repo_root via `BASH_SOURCE`, so we
# place a copy of the script in `$WORK/scripts/` and cd that copy. No
# changes to the script are required.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
REAL_GATE="$REAL_REPO_ROOT/scripts/check-bounded-ship-bar.sh"

if [ ! -f "$REAL_GATE" ]; then
    echo "FAIL: cannot locate $REAL_GATE" >&2
    exit 1
fi

WORK="$(mktemp -d -t chio-shipbar-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

OUT="$WORK/out"
ERR="$WORK/err"

# ---------------------------------------------------------------------
# Stage 1: build a synthetic repo layout with one PARTIAL Claim A row,
# everything else passing. The partial row has a high kill rate, but
# explicit metadata says it is not release-complete.
# ---------------------------------------------------------------------

# Copy the script unchanged so its `BASH_SOURCE`-based repo_root pivots
# to $WORK.
mkdir -p "$WORK/scripts"
cp "$REAL_GATE" "$WORK/scripts/check-bounded-ship-bar.sh"
cp "$REAL_REPO_ROOT/scripts/check-threat-coverage-mutants.sh" \
    "$WORK/scripts/check-threat-coverage-mutants.sh"
chmod +x "$WORK/scripts/check-bounded-ship-bar.sh"
chmod +x "$WORK/scripts/check-threat-coverage-mutants.sh"

GATE="$WORK/scripts/check-bounded-ship-bar.sh"

# Bar 1 evidence:
#   * Five trust-boundary crates with full target-met baselines.
#   * chio-policy with high kill_rate_percent but target_met=false,
#     result_label=PARTIAL, incomplete evaluated counts, interrupted
#     run status, and hand-picked subset scope -> PARTIAL row.
mkdir -p "$WORK/audits/evidence/mutants"
cat > "$WORK/audits/evidence/mutants/banner.json" <<'EOF'
{"kill_rate_percent":75.0,"observed":true,"ran_at":"2026-05-08T00:00:00Z","per_crate":["chio-policy","chio-credentials","chio-attest-verify","chio-kernel-core","chio-guards","chio-anchor"]}
EOF
for crate in chio-credentials chio-attest-verify chio-kernel-core chio-guards chio-anchor; do
    mkdir -p "$WORK/audits/evidence/mutants/$crate"
    if [ "$crate" = "chio-attest-verify" ]; then
        # chio-attest-verify has a 80% target; meet it cleanly.
        cat > "$WORK/audits/evidence/mutants/$crate/2026-05-08.json" <<EOF
{"crate":"$crate","kill_rate_percent":85.0,"caught":85,"viable":100,"target_met":true,"result_label":"FULL","run_status":"COMPLETE","evaluated":100,"total_discovered":100,"examine_scope":"full-crate"}
EOF
    else
        cat > "$WORK/audits/evidence/mutants/$crate/2026-05-08.json" <<EOF
{"crate":"$crate","kill_rate_percent":75.0,"caught":75,"viable":100,"target_met":true,"result_label":"FULL","run_status":"COMPLETE","evaluated":100,"total_discovered":100,"examine_scope":"full-crate"}
EOF
    fi
done
# chio-policy: R4 false-pass fixture. Numeric rate is high enough to
# pass the old gate, but every metadata field says it is partial.
mkdir -p "$WORK/audits/evidence/mutants/chio-policy"
cat > "$WORK/audits/evidence/mutants/chio-policy/2026-05-08-per-crate-baseline.json" <<'EOF'
{"crate":"chio-policy","kill_rate_percent":99.9,"caught":999,"viable":1000,"target_met":false,"result_label":"PARTIAL","run_status":"PARTIAL: interrupted at 1/999 by session budget","evaluated":1,"total_discovered":999,"examine_scope":"hand-picked subset"}
EOF

# Bar 1 threats: 20 strict evidence JSONs with caught>=1 and metadata that the
# threat mutants gate accepts. We want all real so we are not double-counting
# partials from this row when validating Bar 1 chio-policy alone.
mkdir -p "$WORK/audits/evidence/threats"
mkdir -p "$WORK/spec/security"
python3 - "$WORK/spec/security/chio-threat-model.v1.json" <<'PY'
import json
import sys

threats = []
for i in range(1, 21):
    tid = f"t-{i}"
    threats.append({
        "id": tid,
        "name": tid,
        "coverage_state": "covered",
        "coveredBy": [f"crates/chio-conformance/tests/threats/{tid}.rs"],
    })

with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"threats": threats}, handle)
    handle.write("\n")
PY
for i in $(seq 1 20); do
    cat > "$WORK/audits/evidence/threats/t-${i}.json" <<EOF
{"id":"t-${i}","caught":1,"survivors":[],"ran_at":"2026-05-08T00:00:00Z","timestamp_kind":"cargo-mutants-run","evidence_status":"cargo-mutants-run","mutation_evidence_status":"complete","promotion_status":"promoted","needs_real_run":false,"triage_status":"covered"}
EOF
done

# Bar 2 fixtures: current upstream fixture names + evidence markers.
mkdir -p "$WORK/crates/chio-conformance/tests"
for f in b1_capability_v2_single_entry_no_bypass.rs \
         b2_receipt_v2_failclosed_pre_dispatch.rs \
         b3_anchor_batch_sync_path_rejected_under_public_witness.rs; do
    printf '// Spec MUST fixture with reverts-to-fail proof\nfn main() {}\n' \
        > "$WORK/crates/chio-conformance/tests/$f"
done
# B4 is intentionally an interim source-branch fixture in the current upstream
# set, so the checker reports it as PARTIAL/PENDING rather than a full Claim B
# close.
printf '// signature-slice fixture; full DSSE PAE conformance pending\nfn main() {}\n' \
    > "$WORK/crates/chio-conformance/tests/b4_bilateral_dsse_signature_slice.rs"
# Companion async-witness script.
printf '#!/usr/bin/env bash\nexit 0\n' \
    > "$WORK/scripts/check-anchor-batch-async-witness.sh"
chmod +x "$WORK/scripts/check-anchor-batch-async-witness.sh"

# Bar 3 demo scaffolding.
mkdir -p "$WORK/examples/chiodome-bilateral/transcripts"
mkdir -p "$WORK/examples/chiodome-bilateral/golden"
mkdir -p "$WORK/examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome"
mkdir -p "$WORK/.planning/trajectory-5/lane-c-demo"
printf 'all:\n\t@echo demo\n' > "$WORK/examples/chiodome-bilateral/Makefile"
printf '{"transcript":"a"}\n' \
    > "$WORK/examples/chiodome-bilateral/transcripts/a.json"
printf '{"transcript":"b"}\n' \
    > "$WORK/examples/chiodome-bilateral/transcripts/b.json"
printf 'golden line\n' \
    > "$WORK/examples/chiodome-bilateral/golden/a.txt"
printf '{"receipt":"v0.1.0"}\n' \
    > "$WORK/examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json"
printf '{"envelope":"v0.1.0"}\n' \
    > "$WORK/examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/envelope.json"
printf '{"checkpoint":"v0.1.0"}\n' \
    > "$WORK/examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/checkpoint.json"
cat > "$WORK/.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml" <<'EOF'
[c5_selective_disclosure]
status = "deferred_to_v0_2"
deferral_target = "v0.2.0-bounded-chiodome"
implementation_crate = "deferred"
feature = "deferred"
proof_path = "deferred"
predicate_failed_path = "deferred"
release_claim_allowed = "no"
EOF

# releases.toml carries the bounded package release_status entry.
# Use the blocked status so Claim C fires PARTIAL too -- this
# strengthens the test by ensuring at least two PARTIAL rows are
# reported (chio-policy + package status), so the diagnostic-vs-strict
# gate flip is unambiguous.
cat > "$WORK/releases.toml" <<'EOF'
[v0_1_0_bounded_chiodome]
release_status = "blocked_pending_lane_b_integration"
integrated_merge_sha = "pending"
EOF

write_assurance_manifest() {
    python3 - "$WORK" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])

def digest(rel):
    path = root / rel
    return {"path": rel, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

manifest = {
    "schema": "chio.bounded-assurance-manifest.v1",
    "integrated_merge_sha": "0123456789abcdef0123456789abcdef01234567",
    "commands": [
        {
            "command": "bash scripts/check-threat-coverage-mutants.sh",
            "exit_code": 0,
            "artifacts": [
                digest("spec/security/chio-threat-model.v1.json"),
                digest("audits/evidence/threats/t-1.json"),
                digest("audits/evidence/mutants/banner.json"),
            ],
        },
        {
            "command": "bash scripts/check-anchor-batch-async-witness.sh",
            "exit_code": 0,
            "artifacts": [
                digest("scripts/check-anchor-batch-async-witness.sh"),
            ],
        },
    ],
    "fixture_hashes": [
        digest("crates/chio-conformance/tests/b1_capability_v2_single_entry_no_bypass.rs"),
        digest("crates/chio-conformance/tests/b2_receipt_v2_failclosed_pre_dispatch.rs"),
        digest("crates/chio-conformance/tests/b3_anchor_batch_sync_path_rejected_under_public_witness.rs"),
        digest("crates/chio-conformance/tests/b4_bilateral_dsse_signature_slice.rs"),
        digest("examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/receipt.json"),
        digest("examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/envelope.json"),
        digest("examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/checkpoint.json"),
    ],
}

out = root / "audits/evidence/bounded-assurance-manifest.json"
out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
PY
}

write_assurance_manifest

# ---------------------------------------------------------------------
# Stage 2: default (assurance-gate) mode -> exit 1.
# ---------------------------------------------------------------------
rc=0
bash "$GATE" >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 2 assurance-gate mode: expected rc=1 with PARTIAL fixture, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    echo "--- stderr ---" >&2; cat "$ERR" >&2
    exit 1
fi
if ! grep -q -E '^PARTIAL Claim A chio-policy' "$OUT"; then
    echo "FAIL: stage 2 missing PARTIAL Claim A chio-policy line" >&2
    cat "$OUT" >&2
    exit 1
fi
if ! grep -q -E '^PARTIAL Claim C5 selective-disclosure boundary is not release-complete' "$OUT"; then
    echo "FAIL: stage 2 missing PARTIAL Claim C5 selective-disclosure boundary line" >&2
    cat "$OUT" >&2
    exit 1
fi
if ! grep -q 'assurance-gate mode' "$OUT"; then
    echo "FAIL: stage 2 missing 'assurance-gate mode' summary line" >&2
    cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 2 assurance-gate mode exits 1 with PARTIAL fixture (rc=1)"

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
if ! grep -q -E '^WARN Claim A chio-policy' "$OUT"; then
    echo "FAIL: stage 3 missing 'WARN Claim A chio-policy' line (diagnostic-mode marker)" >&2
    cat "$OUT" >&2
    exit 1
fi
if ! grep -q -E '^WARN Claim C5 selective-disclosure boundary is not release-complete' "$OUT"; then
    echo "FAIL: stage 3 missing 'WARN Claim C5 selective-disclosure boundary' line" >&2
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
# Stage 4: a high-kill JSON that omits the explicit full-scope marker
# fails assurance-gate mode.
# ---------------------------------------------------------------------
cat > "$WORK/audits/evidence/mutants/chio-policy/2026-05-08-per-crate-baseline.json" <<'EOF'
{"crate":"chio-policy","kill_rate_percent":99.9,"caught":999,"viable":1000,"target_met":true,"run_status":"COMPLETE","evaluated":999,"total_discovered":999,"examine_scope":"full-crate"}
EOF
rc=0
bash "$GATE" >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 4 assurance-gate mode: expected rc=1 with missing full-scope marker, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    echo "--- stderr ---" >&2; cat "$ERR" >&2
    exit 1
fi
if ! grep -q 'result_label missing full-scope marker' "$OUT"; then
    echo "FAIL: stage 4 missing full-scope marker diagnostic" >&2
    cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 4 assurance-gate mode exits 1 when result_label full-scope marker is missing (rc=1)"

# Restore the original PARTIAL fixture for the final diagnostic-mode sanity
# check so the test keeps covering target_met=false plus result_label=PARTIAL.
cat > "$WORK/audits/evidence/mutants/chio-policy/2026-05-08-per-crate-baseline.json" <<'EOF'
{"crate":"chio-policy","kill_rate_percent":99.9,"caught":999,"viable":1000,"target_met":false,"result_label":"PARTIAL","run_status":"PARTIAL: interrupted at 1/999 by session budget","evaluated":1,"total_discovered":999,"examine_scope":"hand-picked subset"}
EOF
write_assurance_manifest

# ---------------------------------------------------------------------
# Stage 5: a stale evidence manifest exits 1 even in diagnostic mode.
# ---------------------------------------------------------------------
python3 - "$WORK/audits/evidence/bounded-assurance-manifest.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
doc = json.loads(path.read_text(encoding="utf-8"))
doc["commands"][0]["artifacts"][0]["sha256"] = "0" * 64
path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
PY
rc=0
bash "$GATE" --diagnostic >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 5 --diagnostic with stale evidence manifest: expected rc=1, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    exit 1
fi
if ! grep -q 'Bounded assurance evidence manifest missing or invalid' "$OUT"; then
    echo "FAIL: stage 5 missing stale manifest diagnostic" >&2
    cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 5 stale evidence manifest exits 1 even under --diagnostic (rc=1)"
write_assurance_manifest

# ---------------------------------------------------------------------
# Stage 6: sanity -- a real FAIL row exits 1 in either mode.
# Trigger by making the async-witness companion exit nonzero.
# ---------------------------------------------------------------------
printf '#!/usr/bin/env bash\nexit 7\n' \
    > "$WORK/scripts/check-anchor-batch-async-witness.sh"
chmod +x "$WORK/scripts/check-anchor-batch-async-witness.sh"
write_assurance_manifest
rc=0
bash "$GATE" --diagnostic >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 6 --diagnostic with real FAIL: expected rc=1, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 6 real FAIL row exits 1 even under --diagnostic (rc=1)"

# ---------------------------------------------------------------------
# Stage 7: a marker that claims C5 evidence_complete without real evidence
# is a release-truth failure, even in diagnostic mode.
# ---------------------------------------------------------------------
printf '#!/usr/bin/env bash\nexit 0\n' \
    > "$WORK/scripts/check-anchor-batch-async-witness.sh"
chmod +x "$WORK/scripts/check-anchor-batch-async-witness.sh"
write_assurance_manifest
cat > "$WORK/.planning/trajectory-5/lane-c-demo/c5-selective-disclosure-status.toml" <<'EOF'
[c5_selective_disclosure]
status = "evidence_complete"
implementation_crate = "crates/chio-zk-receipts"
feature = "zk"
proof_path = "examples/chiodome-bilateral/fixtures/auditor-view/proof.json"
predicate_failed_path = "examples/chiodome-bilateral/fixtures/auditor-view/predicate-failed.json"
release_claim_allowed = "yes"
EOF
rc=0
bash "$GATE" --diagnostic >"$OUT" 2>"$ERR" || rc=$?
if [ "$rc" -ne 1 ]; then
    echo "FAIL: stage 7 --diagnostic with false C5 evidence_complete: expected rc=1, got rc=$rc" >&2
    echo "--- stdout ---" >&2; cat "$OUT" >&2
    exit 1
fi
if ! grep -q 'Claim C5 marker claims evidence_complete but evidence is missing' "$OUT"; then
    echo "FAIL: stage 7 missing false C5 evidence_complete diagnostic" >&2
    cat "$OUT" >&2
    exit 1
fi
echo "ok: stage 7 false C5 evidence_complete marker exits 1 even under --diagnostic (rc=1)"

# Cleanup is implicit via `trap rm -rf $WORK`.
echo "PASS: check-bounded-ship-bar behavioral regression test"
