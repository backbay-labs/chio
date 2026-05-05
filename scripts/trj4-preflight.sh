#!/usr/bin/env bash
# trj4 pre-flight gate.
#
# Runs every check that has to be green before TRJ4-001 can begin. This is the
# automated half of the TRJ4-006 reconciliation gate: anything this script can
# verify mechanically, it does. The remaining manual items (release-tag policy
# ratified, scope-lock decision, owner assignment) are tracked in
# .planning/trajectory-4/EXECUTION-BOARD.md.
#
# Exits 0 only if every check passes; otherwise prints a summary of failures
# and exits with the count of failures.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

passes=()
fails=()

pass() {
    passes+=("$1")
    printf "  PASS  %s\n" "$1"
}
fail() {
    fails+=("$1")
    printf "  FAIL  %s\n" "$1"
}

section() {
    printf "\n[%s]\n" "$1"
}

#-- 1. Threat-coverage gate ----------------------------------------------------
section "threat-coverage gate"
if bash scripts/check-threat-coverage.sh > /tmp/trj4-preflight-threat.log 2>&1; then
    covered=$(grep -E '^  covered:' /tmp/trj4-preflight-threat.log | awk '{print $2}')
    pending=$(grep -E '^  pending:' /tmp/trj4-preflight-threat.log | awk '{print $2}')
    uncovered=$(grep -E '^  uncovered:' /tmp/trj4-preflight-threat.log | awk '{print $2}')
    pass "scripts/check-threat-coverage.sh PASS at ${covered}/${pending}/${uncovered} (covered/pending/uncovered)"
else
    fail "scripts/check-threat-coverage.sh did not return 0; see /tmp/trj4-preflight-threat.log"
fi

#-- 2. Required release workflows present --------------------------------------
section "release workflows"
for wf in release-binaries.yml slsa.yml reproducible-build.yml; do
    if [[ -f ".github/workflows/${wf}" ]]; then
        pass ".github/workflows/${wf} present"
    else
        fail ".github/workflows/${wf} missing"
    fi
done

#-- 3. Spec registries (the Evidence Gate substrate) --------------------------
section "spec registries"
for reg in claim-registry.v1.json proof-manifest.v1.json theorem-inventory.v1.json README.md; do
    if [[ -f "spec/registries/${reg}" ]]; then
        pass "spec/registries/${reg} present"
    else
        fail "spec/registries/${reg} missing - run TRJ4-000"
    fi
done

#-- 4. CI-DEBT.md exists at known path -----------------------------------------
section "CI-DEBT"
if [[ -f ".planning/trajectory-3/work/CI-DEBT.md" ]]; then
    pass ".planning/trajectory-3/work/CI-DEBT.md present"
    if grep -q 'requires-individual-replay-or-deferral' .planning/trajectory-3/work/CI-DEBT.md; then
        bucket_count=$(awk '/^## requires-individual-replay-or-deferral/,/^## /' .planning/trajectory-3/work/CI-DEBT.md | grep -cE '^- ' || true)
        if [[ "${bucket_count}" -eq 0 ]]; then
            pass "CI-DEBT.md requires-individual-replay-or-deferral bucket is empty"
        else
            fail "CI-DEBT.md requires-individual-replay-or-deferral bucket has ${bucket_count} entries (TRJ4-049 gate)"
        fi
    else
        pass "CI-DEBT.md has no requires-individual-replay-or-deferral bucket (already drained)"
    fi
else
    fail ".planning/trajectory-3/work/CI-DEBT.md missing"
fi

#-- 5. TRAJECTORY-FINAL.md present + no TODO markers ---------------------------
section "TRAJECTORY-FINAL.md"
if [[ -f ".planning/trajectory-3/TRAJECTORY-FINAL.md" ]]; then
    pass ".planning/trajectory-3/TRAJECTORY-FINAL.md present"
    todo_count=$(grep -c -E 'TODO|TBD|FIXME' .planning/trajectory-3/TRAJECTORY-FINAL.md || true)
    if [[ "${todo_count}" -eq 0 ]]; then
        pass "TRAJECTORY-FINAL.md has zero TODO/TBD/FIXME markers"
    else
        fail "TRAJECTORY-FINAL.md has ${todo_count} TODO/TBD/FIXME markers (TRJ4-004 gate)"
    fi
else
    fail ".planning/trajectory-3/TRAJECTORY-FINAL.md missing"
fi

#-- 6. releases.toml present ---------------------------------------------------
section "releases.toml"
if [[ -f "releases.toml" ]]; then
    pass "releases.toml present"
else
    fail "releases.toml missing"
fi

#-- 7. No open trj3.2/* PRs ----------------------------------------------------
section "trj3.2 PR cascade"
if command -v gh > /dev/null 2>&1; then
    open_count=$(gh pr list --state open --json headRefName --jq '[.[] | select(.headRefName | startswith("trj3.2/"))] | length' 2>/dev/null || echo "?")
    if [[ "${open_count}" == "0" ]]; then
        pass "zero open trj3.2/* PRs"
    elif [[ "${open_count}" == "?" ]]; then
        fail "could not query GitHub for open trj3.2 PRs (gh CLI not authenticated?)"
    else
        fail "${open_count} open trj3.2/* PR(s) remaining (TRJ4-001 gate)"
    fi
else
    fail "gh CLI not available; cannot verify trj3.2 PR cascade is drained"
fi

#-- 8. Audit doc set present ---------------------------------------------------
section "audit doc set"
expected=(
    "T0.A-substrate-closeout.md"
    "T0.B-substrate-hardening.md"
    "T0.C-mobile-attestation.md"
    "T0.D-threat-coverage.md"
    "T1.0-capability-negotiation.md"
    "T1.1-macaroon-attenuation.md"
    "T1.2-receipt-dag.md"
    "T1.3-anchor-batch.md"
    "T1.4-archaeology.md"
    "T1.5-sre-foundations.md"
    "T1.6-chio-explain.md"
    "T2.1-hybrid-pq-cross-surface.md"
)
for doc in "${expected[@]}"; do
    if [[ -f ".planning/trajectory-4/audits/${doc}" ]]; then
        pass ".planning/trajectory-4/audits/${doc} present"
    else
        fail ".planning/trajectory-4/audits/${doc} missing"
    fi
done

#-- 9. EXECUTION-BOARD + SYNTHESIS-V2 present ----------------------------------
section "core planning docs"
for doc in EXECUTION-BOARD.md SYNTHESIS-V2-INTEGRATED-PLAN.md README.md BRAINSTORM-V1-FEATURE-CATALOG.md REJECTED-IDEAS.md; do
    if [[ -f ".planning/trajectory-4/${doc}" ]]; then
        pass ".planning/trajectory-4/${doc} present"
    else
        fail ".planning/trajectory-4/${doc} missing"
    fi
done

#-- 10. Em-dash + trailing-whitespace gate -------------------------------------
section "doc-style gate"
em_total=0
ws_total=0
for f in .planning/trajectory-4/*.md .planning/trajectory-4/audits/*.md spec/registries/*.md; do
    [[ -f "$f" ]] || continue
    em=$(grep -c $'\xe2\x80\x94' "$f" 2>/dev/null || true)
    ws=$(grep -c '[[:space:]]$' "$f" 2>/dev/null || true)
    em_total=$((em_total + em))
    ws_total=$((ws_total + ws))
done
if [[ "${em_total}" -eq 0 ]]; then
    pass "zero em-dashes across trj4 docs"
else
    fail "${em_total} em-dash matches across trj4 docs (CLAUDE.md house rule)"
fi
if [[ "${ws_total}" -eq 0 ]]; then
    pass "zero trailing-whitespace lines across trj4 docs"
else
    fail "${ws_total} trailing-whitespace lines (git diff --check)"
fi

#-- summary --------------------------------------------------------------------
printf "\n[summary]\n"
printf "  passes: %d\n" "${#passes[@]}"
printf "  fails:  %d\n" "${#fails[@]}"

if [[ "${#fails[@]}" -gt 0 ]]; then
    printf "\nfailures:\n"
    for f in "${fails[@]}"; do
        printf "  - %s\n" "$f"
    done
    exit "${#fails[@]}"
fi

printf "\ntrj4 pre-flight: GREEN. TRJ4-001..006 may begin.\n"
exit 0
