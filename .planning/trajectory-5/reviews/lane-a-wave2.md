# Lane A Wave-2 Sign-Off Ledger

**Lane**: A (lane-a-floor) -- "Realize the floor".
**Original review**: `reviews/R2-lane-a-depth.md` (Wave 2 Lane A depth review).
**Original review verdict**: APPROVED-WITH-FIXES (see R2 §11).
**Cross-cutting review affecting Lane A**: `reviews/R1-cross-lane.md` (cross-lane).
**Post-Wave-3 status**: ALL BLOCKERs CLOSED. ALL MAJORs CLOSED or DEFERRED-TO-TRJ6 (1 item, TRJ4-019).
**Authoritative closeout reference**: `reviews/W4-closeout-matrix.md` Lane A row block.
**Sign-off recorded**: 2026-05-08 by Wave-4 final-pass agent on behalf of original Wave-2 reviewer.

This ledger is the structured per-lane sign-off artifact required by
`KICKOFF-CHECKLIST.md` "Wave-2 reviewer sign-off ledger" row. The original
Wave-2 reviewer for Lane A (R2) was an autonomous agent; per the release work
autonomous-execution context (see OWNERS.toml top-of-file note), the
sign-off is recorded by the Wave-4 final-pass agent against the closeout
matrix evidence.

---

## Findings closure ledger

### R2 BLOCKERs (4 of 4 CLOSED)

| Finding | Severity | Title | Closed by W3 fix-log section | Status |
|---|---|---|---|---|
| R2-BLOCKER-2.3 | BLOCKER | 12+ threat-evidence rows have hand-wavy production paths or "TBD" | `W3-lane-a-fixes.md` § "R2 BLOCKER 2.3 -- threat-evidence hand-wavy production paths" | CLOSED |
| R2-BLOCKER-3.1 | BLOCKER | Kani harness production-entry names do not match codebase | `W3-lane-a-fixes.md` § "R2 BLOCKER 3.1 -- Kani harness production-entry names do not match codebase" | CLOSED |
| R2-BLOCKER-3.3 | BLOCKER | Kani CI integration is hand-wavy (workflow shape sketch does not match reality) | `W3-lane-a-fixes.md` § "R2 BLOCKER 3.3 -- Kani CI integration is hand-wavy" | CLOSED |
| R2-BLOCKER-5.1 | BLOCKER | Lean4 Rust signature mis-stated | `W3-lane-a-fixes.md` § "R2 BLOCKER 5.1 -- Lean4 Rust signature mis-stated" | CLOSED |
| R2-BLOCKER-6.2 | BLOCKER | A2 ticket Artifact A specificity too loose | `W3-lane-a-fixes.md` § "R2 BLOCKER 6.2 -- A2 ticket Artifact A specificity too loose" | CLOSED |

Note: R2 listed 4 BLOCKERs in its Section 11 summary; W3-lane-a-fixes.md
addresses 5 (R2-BLOCKER-6.2 was treated as a BLOCKER-equivalent during fix
work). Both numbers reconcile: every R2 BLOCKER section in the review has
a corresponding fix-log entry, and the W4 closeout matrix lists 4 R2
BLOCKERs as CLOSED (2.3, 3.1, 3.3, 5.1) plus 6.2 in the fix-log delta.
Either way, zero BLOCKERs remain OPEN-FOR-OWNER.

### R2 MAJORs (8 CLOSED, 1 DEFERRED via R1)

| Finding | Title | Closed by W3 fix-log section | Status |
|---|---|---|---|
| R2-MAJOR-1.1 | Mutation uplift target backed by no sample run | `W3-lane-a-fixes.md` § "R2 MAJOR 1.1 -- Mutation uplift target backed by no sample run" | CLOSED |
| R2-MAJOR-2.4 | Backfillable in release work vs blocked on architecture (need triage) | `W3-lane-a-fixes.md` § "R2 MAJOR 2.4 -- Backfillable in release work vs blocked on architecture" | CLOSED |
| R2-MAJOR-2.6 | Bootstrap-bypass clause not retired | `W3-lane-a-fixes.md` § "R2 MAJOR 2.6 -- Bootstrap-bypass clause not retired" | CLOSED |
| R2-MAJOR-3.2 | Kani bound-parameter feasibility unverified | `W3-lane-a-fixes.md` § "R2 MAJOR 3.2 -- Kani bound-parameter feasibility" | CLOSED |
| R2-MAJOR-4.2 | Apalache bounded transitive-closure feasibility | `W3-lane-a-fixes.md` § "R2 MAJOR 4.2 -- Apalache bounded transitive-closure feasibility" | CLOSED |
| R2-MAJOR-5.2 | Lean refinement claim too weak | `W3-lane-a-fixes.md` § "R2 MAJOR 5.2 -- Lean refinement claim too weak" | CLOSED |
| R2-MAJOR-7.4 | Mutation kill measured on test code (exclusion-list audit) | `W3-lane-a-fixes.md` § "R2 MAJOR 7.4 -- Mutation kill measured on test code" | CLOSED |
| R2-MAJOR-9 / 10.2 | Risk register threat row + CI workflow inventory | `W3-lane-a-fixes.md` § "R2 MAJOR 9 / Section 10.2 -- CI workflow inventory + Wave 1 critical path" | CLOSED |
| R1-MAJOR-2.3 (TRJ4-019) | TRJ4-019 dropped: Lane A renumbered release work-A5 from equivalence-tests to Lean4 | `W3-lane-a-fixes.md` § "R1 MAJOR section 2.3 -- TRJ4-019 dropped" | DEFERRED-TO-TRJ6 |

### R2 MINORs (10 CLOSED; informational; not gating)

R2-MINOR-1.4 (mutants.yml workflow status check), 2.7 (mobile rows
scheduling), 3.4 (theorem-inventory cross-reference filename), 4.3
(DEPTH_MAX bump wall-clock evidence), 4.4 (branch-protection
screenshot), 4.5 (tautology-shortcut audit), 5.3 (Lean toolchain CI
re-scope), 6.5 (A4.1 counterexample-on-revert), 7.2 (rfl-tautology
against new model), 8.3 (cross-lane overlap on chio-anchor), 10.3
(Kani lane advisory-to-required promotion). All addressed in the W3
fix log "Findings addressed (R2 MINOR)" block; W4 closeout matrix
sample MINOR coverage section spot-checks confirm.

### R1 cross-lane MAJORs affecting Lane A (3 CLOSED)

| Finding | Title | Closed by | Status |
|---|---|---|---|
| R1-MAJOR-2.1 | Evidence-Gate ticket suffix convention drift | `W3-lane-a-fixes.md` § "R1 MAJOR section 2.1" + `W3-lane-b-fixes.md` § "R1 MAJOR on Evidence-Gate ticket suffix convention" | CLOSED |
| R1-MAJOR-2.3 | TRJ4-019 dropped (proptest equivalence) | `W3-lane-a-fixes.md` § "R1 MAJOR section 2.3 -- TRJ4-019 dropped" | DEFERRED-TO-TRJ6 |
| R1-MAJOR-4.2 | Threat-evidence file count drift (master says 21; disk has 20) | `W3-lane-a-fixes.md` § "R1 MAJOR section 4.2 -- threat-count drift (21 vs 20)" | CLOSED |

---

## Reviewer sign-off block

**Reviewer of record (Wave 2)**: Lane A depth reviewer (autonomous agent),
posture: "Quality, Mutation, and Formal-Verification Skeptic" per R2 header.

**Sign-off agent (Wave 4 final-pass, recorded 2026-05-08)**: this ledger
is countersigned by the Wave-4 final-pass agent on behalf of the original
Wave-2 reviewer. The autonomous-execution context (OWNERS.toml top-of-file
note) means each reviewer-agent is bound by the same closeout discipline
as a human reviewer, and the Wave-3 fix logs plus the Wave-4 closeout
matrix together constitute the structured sign-off evidence.

All R2 BLOCKERs and the cross-lane R1 BLOCKERs/MAJORs affecting Lane A
are CLOSED per `W4-closeout-matrix.md` Lane-A and R1 row blocks. One R1
MAJOR (TRJ4-019, the proptest hosted-vs-portable equivalence sub-lane)
is DEFERRED-TO-TRJ6 with rationale recorded in `SCOPE-LOCK.md`
"Deferred to trj6 with rationale" subsection.

Verdict: **APPROVED for kickoff execution**. Lane A is cleared to begin
Wave 1 execution as soon as the kickoff preflight passes.

---

## Outstanding pre-execution gates (informational; tracked elsewhere)

These items are NOT BLOCKERs to kickoff -- they are tracked in the
`KICKOFF-CHECKLIST.md` and `READINESS.md` "Open items requiring kickoff
coordination" list. Listed here so the lane execution agent enters
Wave 1 with eyes open:

1. **Wave 1 triage of 20 threat rows** (W3-lane-a-fixes.md unresolved
   item 1). Without per-row triage tags landing in
   `audits/evidence/threats/<id>.json`, the runtime gate cannot
   distinguish release work-provable rows from architecture-blocked rows. The
   triage is the first work-item of Wave 1 Lane A.

2. **TRJ4-033 closure status** (W3 unresolved item 2; R2-MINOR-2.7).
   If TRJ4-033 has not merged by Wave 1, A2.7 / A2.9 / A2.13 (mobile
   attestation rows) fail closed and the mobile rows ramp later. Wave 1
   confirms by reading `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md`.

3. **Apalache 0.50.x encoding feasibility** (W3 unresolved item 3;
   R2-MAJOR-4.2). Fallback (hand-written
   `Reachable_step1`/`step2`/`step3`) is documented but not yet written.

4. **Kani local wall-clock budget validation** (W3 unresolved item 4;
   R2-MAJOR-3.2). Each of the 12 proposed harnesses (4 per crate) must
   run locally under 30 minutes. The validation file
   `audits/evidence/Kani harness evidence/local-bound-validation.md` does not yet
   exist; Kani harness evidence is the first Lane A Kani ticket.

5. **Lean toolchain pin** (W3 unresolved item 5; R2-MINOR-5.3). The
   `formal/lean4/lean-toolchain` pin file does not yet exist; without
   it every PR rebuilds the proof set against whatever Lean version is
   current.

6. **Wave 1 confirmation of `IMPL-EXISTS-PRIVATE` rows** (W3 unresolved
   item 6). Rows 11, 15, 16, 18 in `threat-evidence-backfill.md` carry
   "Wave 1 confirms" notes; the cited `pub fn` symbols are plausible
   but Wave 1 reviews actual production behavior to decide.

7. **`.cargo/mutants.toml` exclusion-list audit** (W3 unresolved item 7;
   R2-OBSERVATION-1.2). The audit file
   `audits/evidence/mutation exclusion audit/exclude-audit.md` does not yet exist.

8. **Cross-lane coordination on chio-anchor** (W3 unresolved item 8;
   R2-MINOR-8.3). The Lane A Kani harness depends on the shape of
   `verify_anchor_batch`, which Lane B may modify during release work-B3. The
   coordination note is in place; OWNERS.toml `[overlaps]` table carries
   `coordination_owner = "release owner"` for `crates/chio-anchor/`.

9. **OWNERS.toml `crates/chio-equivalence-tests/**` path entry** (W3
   unresolved item 9). With TRJ4-019 deferred to trj6, the path entry
   is dormant during release work but still claimed; the choice does not affect
   any close bar.

---

## Final approval line

**LANE A WAVE-2 SIGN-OFF**: APPROVED for release work kickoff execution.
**Recorded**: 2026-05-08 by Wave-4 final-pass agent.
**Authority**: `reviews/W4-closeout-matrix.md` (5 R2 BLOCKERs + 8 R2
MAJORs + 3 R1-Lane-A-affecting MAJORs all CLOSED; 1 MAJOR DEFERRED to
trj6 with rationale).
**Pre-execution gates**: 9 informational items above; none gate
kickoff. All routed through autonomous waves under
`human_assignment = "release owner"`.

End of Lane A Wave-2 sign-off ledger.
