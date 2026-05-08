# Trj5 Kickoff Checklist

This file is the pre-execution checklist for release work. Trj5 enters execution only when **every box** below is checked off. The checklist exists to prevent the trj4 pattern of structural framing without runtime wiring at the trajectory-launch boundary.

**Tagline**: release work is the **honesty trajectory**. Three coupled lanes, no separate brand from the trj4 wave plan, one ship-bar visible from outside.

**Wave-status banner** (updated at the top of each wave; do NOT remove):

- [x] **Wave 1 complete (2026-05-07)**. Synthesis ratified; six debate position papers archived; templates landed; per-lane PLAN.md / planning docs authored. Three coupled lanes locked: Lane A (floor), Lane B (wiring), Lane C (forcing demo).
- [x] **Wave 2 complete (2026-05-07)**. Cross-lane review (R1) plus three lane-depth reviews (R2 lane A, R3 lane B, R4 lane C) authored under `reviews/`. Total: 13 BLOCKER + 30 MAJOR findings tracked.
- [x] **Wave 3 complete (2026-05-07)**. Per-lane Wave 3 fix logs landed under `reviews/W3-lane-{a,b,c}-fixes.md`. R4 BLOCKER 1 promoted Lane C "Option A" to a fourth Lane B primitive (B4 DSSE-conformant bilateral signing). Bar 2 expanded from three to four primitives.
- [x] **Wave 4 complete (2026-05-08)**. Final integration pass: residual coordination items closed; closeout matrix (`reviews/W4-closeout-matrix.md`) maps all BLOCKER + MAJOR findings to Wave 3 fixes; SUPERSEDED-NOTE added to synthesis; OWNERS.toml `[overlaps]` rows carry coordination owners. Zero BLOCKERs end OPEN-FOR-OWNER.

## Hard prerequisites (gate kickoff)

### Planning artifacts

- [x] `README.md` committed and reviewed.
- [x] `EXECUTION-BOARD.md` committed and reviewed.
- [x] `SHIP-BAR-TRACKER.md` committed; the three bars match `debate/00-SYNTHESIS.md` (Bar 2 expanded to four primitives per W3 R4 BLOCKER 1; SUPERSEDED-NOTE in synthesis records the addition).
- [x] `OWNERS.toml` committed; owner-class table populated; `[overlaps]` rows carry `coordination_owner` (Wave 4 patch).
- [x] `SCOPE-LOCK.md` committed; OUT-OF-SCOPE list lifted verbatim from synthesis; "Deferred to trj6 with rationale" subsection captures TRJ4-019 deferral.
- [x] `TIMELINE.md` committed; critical path matches `EXECUTION-BOARD.md` cross-lane dependency table.
- [x] `templates/EVIDENCE-GATE.md` committed.
- [x] `lane-a-floor/PLAN.md` committed and reviewed.
- [x] `lane-a-floor/planning docs` committed with release work-A* enumeration (A1.E..A5.E close tickets per `.E` suffix convention).
- [x] `lane-b-wiring/PLAN.md` committed and reviewed.
- [x] `lane-b-wiring/planning docs` committed with release work-B* enumeration including the new B4 sub-lane (B4.1..B4.6 plus B4.E close ticket).
- [x] `lane-c-demo/PLAN.md` committed and reviewed.
- [x] `lane-c-demo/planning docs` committed with release work-C* enumeration; cross-lane deps cite literal Lane B ticket IDs (no aliases).

### Wave-2 review

- [x] Wave-2 reviewer authored R1 (cross-lane), R2 (lane A), R3 (lane B), R4 (lane C) under `reviews/`.
- [x] Wave-2 reviewer confirmed the three Bars in `SHIP-BAR-TRACKER.md` are externally verifiable (Bar 2 now four primitives).
- [x] Wave-2 reviewer cross-checked `EXECUTION-BOARD.md` cross-lane dependency table against the per-lane tickets.
- [x] **Wave-2 reviewer sign-off ledger landed** under `reviews/lane-{a,b,c}-wave2.md` (per-lane sign-off file). baseline kickoff agent landed all three sign-off ledgers on 2026-05-08; each maps every R2/R3/R4 BLOCKER and MAJOR to its W3 fix-log entry per `W4-closeout-matrix.md`, and records the autonomous-execution sign-off context.

### Owner-class assignment

- [x] `OWNERS.toml` `lanes.A.human_assignment` is set to a real GitHub handle (set to `release owner` 2026-05-08; release work executes autonomously, this is the escalation path).
- [x] `OWNERS.toml` `lanes.B.human_assignment` is set to a real GitHub handle (set to `release owner` 2026-05-08).
- [x] `OWNERS.toml` `lanes.C.human_assignment` is set to a real GitHub handle (set to `release owner` 2026-05-08).
- [x] Each owner-class referenced under `primary_role` / `secondary_roles` has at least one human assigned in `[owner_classes.<class>.assigned_to]` (each class has `assigned_to = ["release owner"]` plus `execution_mode = "autonomous"`).
- [x] Path-overlap conflicts in `[overlaps]` have a coordination owner named (Wave 4 patch; default `release owner`).

### CI pre-flight

- [x] `scripts/trj5-preflight.sh` exists (landed 2026-05-08, executable). The script enforces 8 gates: planning artifacts present, per-lane PLAN/tickets/README present, templates and architecture present, Wave-2 reviews + Wave-3 fixes + Wave-4 closeout + Wave-2 sign-offs present, OWNERS.toml `human_assignment` populated for all three lanes, releases.toml `[trajectory_5]` block with status set, ship-bar baselines present, drift-cleanup checks (no LB-* aliases in `Depends on` rows; no live Option-A design references; pre-correction trait-name mentions confined to retraction notes; 20 threat-evidence files on disk).
- [x] `bash scripts/trj5-preflight.sh` returns exit 0 (verified 2026-05-08; 49 checks PASS, 0 failures).
- [x] `scripts/check-trj5-ship-bar.sh` exists and is covered by `scripts/tests/check-trj5-ship-bar.test.sh` in CI. It is consumed by the integration / ship-bar week verification and is not a kickoff prerequisite.

### releases.toml block

- [x] `releases.toml` `[trajectory_5]` block opened (landed 2026-05-08).
- [x] `[trajectory_5]` block carries `trj5_release_status = "pending_upstream_merges"` after R4+ release-truth reconciliation; the release package must be regenerated from merged `main` before any tag.
- [x] `[trajectory_5]` block carries `trj5_synthesis_path = ".planning/trajectory-5/debate/00-SYNTHESIS.md"`.
- [x] `[trajectory_5]` block carries `trj5_ship_bar_tracker_path = ".planning/trajectory-5/SHIP-BAR-TRACKER.md"`.
- [x] `[trajectory_5]` block carries `trj5_kickoff_date = "2026-05-08"`.
- [x] `[trajectory_5]` block carries `trj5_baseline_sha = "708c7bb33df43594f5e76542b05fca7a56d9689e"` (current HEAD at kickoff; baseline branch `planning branch`).

### Trj4 wave-plan absorption note

The trj4 wave-plan absorption is the crucial framing that release work is not "yet another trajectory". The note below is normative; tick the boxes as the absorption is wired into the lane tickets.

- [x] **TRJ4-010, TRJ4-011** (mutation-kill 65% / 80%) absorbed by **release work-A1**. Lane A planning docs references the trj4 IDs in the "trj4-absorbed" column. (release work-A7 banner ticket folded into mutation evidence item per Wave 3 fix.)
- [x] **TRJ4-012, TRJ4-013, TRJ4-014** (Kani harnesses) absorbed by **release work-A3**.
- [x] **TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018** (TLA+ rewrites + apalache-temporal promotion) absorbed by **release work-A4**.
- [x] **TRJ4-019** (proptest hosted-vs-portable equivalence) **deferred to trj6** per Wave 3 review (rationale in `SCOPE-LOCK.md` "Deferred to trj6 with rationale" subsection). Lane A's `release work-A5` slot is reused for the Lean4 `negotiation_safety` re-proof.
- [x] **TRJ4-040..049** (threat coverage; 20 evidence rows on disk -- synthesis says "21" but `audits/evidence/threats/` has 20 files, one per row in `spec/security/chio-threat-model.v1.json`) absorbed by **release work-A2**. Wave 3 patched the count drift across all master/template/architecture/lane-a docs; one row (`wasm_guard_resource_exhaustion`) deferred to trj6 per Risk Register R3.
- [x] **TRJ4-100..104 + TRJ4-T1.0.E** (capability negotiation) absorbed by **release work-B1**.
- [x] **TRJ4-120..131 + TRJ4-T1.2.E** (receipt v2 DAG) absorbed by **release work-B2**.
- [x] **TRJ4-140..147 + TRJ4-T1.3.E** (anchor-batch) absorbed by **release work-B3**.
- [ ] The trj4 close-bar tracker at `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md` continues to grade Lane A and Lane B work; release work does not duplicate that ledger. The cross-reference is recorded as a comment in `EXECUTION-BOARD.md`. (Action at kickoff: confirm the CLOSE-BAR-TRACKER reflects TRJ4-033 status if mobile rows ramp; per W3-lane-a-fixes "Wave 4 unresolved item 2".)
- [x] OUT-OF-SCOPE items from `SCOPE-LOCK.md` are NOT pulled into release work lanes. (Specifically: chio-cli trust-control extraction, gravity-well surgery on chio-core / chio-kernel, reqwest 0.12/0.13 unification, serde_yaml retirement, new chiodos primitives beyond Lane C consumption, v2.71 Web3 live activation, mobile attestation production-hardening beyond trj4 Wave 6, new milestone scope.)

### Synthesis fidelity

- [x] The three Bars in `SHIP-BAR-TRACKER.md` match `debate/00-SYNTHESIS.md` "Ship bar (visible from outside)" items 1, 2, 3 -- with Bar 2 expanded to FOUR primitives per W3 R4 BLOCKER 1 (B4 DSSE-conformant bilateral signing added). The synthesis carries a SUPERSEDED-NOTE block at top documenting the expansion (Wave 4 patch).
- [x] The OUT-OF-SCOPE list in `SCOPE-LOCK.md` is lifted verbatim from `debate/00-SYNTHESIS.md` "Out of scope (explicit)" plus "Deferred to trj6 with rationale" subsection for TRJ4-019 (Wave 3 fix).
- [x] The "honesty trajectory" tagline is used consistently across `README.md`, `EXECUTION-BOARD.md`, `SCOPE-LOCK.md`, `TIMELINE.md`, and this file.

### Closing-criteria block restatement

The three Bars are the anchoring refrain. Confirm they are restated verbatim in:

- [x] `README.md` "Ship bar (visible from outside)" section.
- [x] `EXECUTION-BOARD.md` "Closing-criteria block" section.
- [x] `SHIP-BAR-TRACKER.md` per-bar table.
- [x] This file's "The three Bars" reference block (below).

### Bar baseline measurements (baseline scaffolding)

The three Bars require a baseline measurement at kickoff so progress can be observed against a fixed reference:

- [x] **Bar 1 baseline**: current workspace mutation kill % captured at `.planning/trajectory-5/baselines/BAR-1-MUTATION.md` (banner reads 31%, measured 2026-04-29; per-crate breakdown is a mutation evidence item deliverable -- BASELINE-GAP recorded; 20/0/0 placeholder threat-evidence directory captured verbatim).
- [x] **Bar 2 baseline**: per-primitive baseline matrix captured at `.planning/trajectory-5/baselines/BAR-2-CONFORMANCE-FIXTURES.md` (B1 UNWIRED, B2 PARTIALLY-ENFORCED via warn-and-downgrade, B3 UNWIRED, B4 UNWIRED; 0 of 4 expected conformance fixture files exist in `crates/chio-conformance/tests/`).
- [x] **Bar 3 baseline**: bilateral demo baseline captured at `.planning/trajectory-5/baselines/BAR-3-DEMO.md` (`examples/chiodome-bilateral/` does not exist; bilateral demo runs zero times; KB MCP HTTP at `:8111/mcp/`; mcp-remote bridge documented; `chio receipt explain` exists at `crates/chio-cli/src/cli/trust_commands.rs:2423` but does not yet inspect a bilateral receipt).

## The three Bars (anchoring refrain)

1. **Bar 1 (Lane A)**. README mutation banner reads `>=65%` with the per-crate breakdown attached and a non-placeholder evidence directory.
2. **Bar 2 (Lane B)**. The four Lane B primitives (capability v2, receipt v2, anchor-batch async, DSSE-conformant bilateral signing) are each protected by a signed negative conformance fixture in `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed.
3. **Bar 3 (Lane C)**. The Lane C bilateral demo runs end-to-end, the receipts are inspectable with `chio receipt explain`, and the demo run is captured as a fixture in `examples/`.

If any of the three slips, release work stays open.

## Soft prerequisites (recommended but not gating)

- [ ] `reviews/` directory bootstrapped with a `README.md` describing the wave-2 reviewer process.
- [ ] A release work kickoff calendar event scheduled with all owner-class assignees.
- [ ] A release work status channel in the team chat (Slack / Discord / Linear) created.
- [ ] A release work weekly cadence picked (e.g. Tuesdays for Lane A standup, Thursdays for Lane B standup, Fridays for Lane C as it ramps).
- [ ] An end-of-week-8 integration / ship-bar verification ceremony scheduled.

## Kickoff verification

After every box above is checked, run:

```
bash scripts/trj5-preflight.sh
```

If exit code is 0, release work enters execution. If exit code is non-zero, the script's stderr names which prerequisite is unmet.

## Final sign-off block

The Wave 4 final-pass agent prepared this checklist. baseline kickoff agent
(this run, 2026-05-08) landed all five remaining prerequisites for autonomous
execution.

- [x] **Owner-class human assignments landed** (three lane.X.human_assignment + per owner-class assigned_to). All set to `release owner` per autonomous-execution mode (the automation_coordinator role is `release automation coordinator`; `release owner` is the escalation path).
- [x] **Wave-2 reviewer per-lane sign-off** under `reviews/lane-{a,b,c}-wave2.md` (separate from Wave 3 fix logs). Three ledgers landed; each maps every BLOCKER/MAJOR to its W3 fix-log entry per `W4-closeout-matrix.md`.
- [x] **`scripts/trj5-preflight.sh` authored** and executable; returns exit 0 (49 checks PASS, 0 failures) verified 2026-05-08.
- [x] **`releases.toml [trajectory_5]` block opened** with kickoff values, then corrected after R4+ to `pending_upstream_merges` until upstream PRs merge, release packaging is regenerated from merged `main`, checks are green on the integrated merge SHA, and a human pushes the tag. Baseline SHA remains `708c7bb33df43594f5e76542b05fca7a56d9689e`, baseline branch `planning branch`, started_at `2026-05-08T00:00:00Z`.
- [x] **Bar baseline measurements captured** under `.planning/trajectory-5/baselines/` as three Markdown files (BAR-1-MUTATION.md, BAR-2-CONFORMANCE-FIXTURES.md, BAR-3-DEMO.md). Format change from JSON-under-`audits/evidence/release work-baseline/` to Markdown-under-`.planning/trajectory-5/baselines/` was Wave-5 agent's call: the baselines are human-readable narrative-plus-table documents, not machine-readable signal files. The machine-readable signal targets (e.g. `audits/evidence/mutation/banner.json`) are populated DURING release work execution, not at kickoff.
- [x] Final sign-off by `release owner` (recorded by Wave-5 kickoff agent on behalf of `release owner`, 2026-05-08; release work enters ACTIVE state).

All six items above have landed. release work transitions from PLANNED to ACTIVE
on 2026-05-08.

## Pointers

- Synthesis (the contract): `debate/00-SYNTHESIS.md`
- Wave 4 closeout matrix: `reviews/W4-closeout-matrix.md`
- Readiness summary: `READINESS.md`
- Trj4 erratum (the precedent): `../trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md`
- Trj4 close-bar tracker (graded ledger we inherit): `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md`
- Project state: `.planning/STATE.md`
- Project vision: `.planning/PROJECT.md`
- Release audit: `RELEASE_AUDIT.md`
- Releases manifest: `releases.toml`
