# Wave 3 Lane A Fix Log

**Author**: Wave 3 Lane A fix agent.
**Date**: 2026-05-07.
**Source reviews addressed**: `R2-lane-a-depth.md` (primary) and
`R1-cross-lane.md` (Lane A-affecting items).

This log records each finding addressed, the files patched, the
findings explicitly deferred, and unresolved items the Wave 4 final-pass
should know about.

---

## Findings addressed (R2 BLOCKER)

### R2 BLOCKER 2.3 -- threat-evidence hand-wavy production paths (12+ rows)

- **Files**:
  `.planning/trajectory-5/lane-a-floor/threat-evidence-backfill.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: replaced every `TBD` and hand-wavy production path with a
  verified `pub fn` import path, drawn from grep against the workspace
  on 2026-05-07. Added a triage-status column ({IMPL-EXISTS-AND-PUBLIC,
  IMPL-EXISTS-PRIVATE, IMPL-PARTIAL, BLOCKED-BY-ARCHITECTURE}); rows
  whose production decision genuinely does not exist today are tagged
  `BLOCKED-BY-ARCHITECTURE` and deferred to trj6 with R3 escalation.
  Pre-Wave-1 estimate: 1 deferral
  (`wasm_guard_resource_exhaustion`); 4 rows pending Wave 1
  confirmation; 14-15 rows IMPL-EXISTS-AND-PUBLIC.
- **Tickets table**: each release work-A2.<n> ticket gains an "Artifact A
  (public symbol)" column citing the literal `pub fn` the test
  invokes.

### R2 BLOCKER 3.1 -- Kani harness production-entry names do not match codebase

- **Files**:
  `.planning/trajectory-5/lane-a-floor/kani-harness-design.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: rewrote tables (1), (2), (3) to cite real production
  entries verified by `grep -nE '^pub fn|^pub async fn'` on 2026-05-07.
  - chio-attest-verify: targets `expect_report_data` (free `pub fn`)
    plus three `<Verifier as QuoteVerifier>::verify_quote` impl
    methods (`NitroVerifier`, `SevSnpVerifier`, `TdxDcapVerifier` --
    publicly constructible types).
  - chio-anchor: replaced non-existent `verify_inclusion_proof` /
    `verify_witness` with `verify_anchor_batch`,
    `evaluate_witness_policy`, `batch_body_hash`.
  - chio-weights: replaced `card::verify`, `lineage::verify`,
    `bundle::verify`, `card::verify_signature` with
    `weights_hash_of`, `anchor_projection_bytes`,
    `verify_model_card_anchor`, `verify_model_card_bundle`.
- **Kani harness evidence / A3.2 / A3.3** ticket text updated to match. Each ticket
  now cites the file:line of the production entry.

### R2 BLOCKER 3.3 -- Kani CI integration is hand-wavy

- **Files**:
  `.planning/trajectory-5/lane-a-floor/kani-harness-design.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: removed the `strategy.matrix.crate` sketch (which does
  not match the actual workflow shape). Replaced with concrete diff
  shape against `.github/workflows/nightly.yml` lines 102-128 and
  `.github/workflows/ci.yml` `kani-public-pr` job lines 478-590. The
  workflow rewrite is split into Kani multi-crate manifesta (multi-crate manifest
  schema in `formal/rust-verification/kani-public-harnesses.toml`) and
  Kani multi-crate manifestb (per-workflow shell-loop change emitting
  `(crate, harness)` pairs). Added Kani harness evidence to promote the new
  multi-crate Kani lane from advisory to required after two
  consecutive green nightly runs (R2 MINOR 10.3).

### R2 BLOCKER 5.1 -- Lean4 Rust signature mis-stated

- **Files**: `.planning/trajectory-5/lane-a-floor/lean4-fix.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: rewrote lines 75-85 against the actual signature at
  `crates/chio-kernel-core/src/capability_verify.rs:226-232`. Three
  type fixes: `CapabilityCryptoFloor` (not `CryptoFloor`);
  `&CapabilityNegotiation` (not flat `Schema`);
  `Result<VerifiedCapability, _>` (not `Result<(), _>`). Added explicit
  field-mapping section (`token.schema` parsed via
  `CapabilitySchemaVersion::parse`; the three downstream Booleans
  abstract the embedded `verify_capability_with_floor` checks).

### R2 BLOCKER 6.2 -- A2 ticket Artifact A specificity too loose

- **Files**: `.planning/trajectory-5/lane-a-floor/planning docs`,
  `.planning/trajectory-5/lane-a-floor/threat-evidence-backfill.md`.
- **Change**: Lane A tickets file now opens with an "Artifact A" rule
  requiring each release work-A2.<n> ticket to name a literal `pub fn` import
  path. Each per-ticket row now has a dedicated "Artifact A (public
  symbol)" column. The Acceptance text rules out tests that import a
  test-local copy of a production type (Mock-not-runtime anti-pattern
  per Evidence Gate 2.3).

---

## Findings addressed (R2 MAJOR)

### R2 MAJOR 1.1 -- Mutation uplift target backed by no sample run

- **File**: `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: mutation evidence item split into mutation evidence item (run baseline) and
  mutation evidence item (publish per-crate numbers). Tightened R2 escalation
  criterion: if `chio-attest-verify` baseline is below 50%, escalate to
  Wave 2 IMMEDIATELY (not after two waves of test-surface expansion).

### R2 MAJOR 2.4 -- Backfillable in release work vs blocked on architecture

- **Files**:
  `.planning/trajectory-5/lane-a-floor/threat-evidence-backfill.md`,
  `.planning/trajectory-5/lane-a-floor/PLAN.md`,
  `.planning/trajectory-5/architecture/RISK-REGISTER.md`.
- **Change**: Wave 1 deliverable adds per-row triage as critical-path.
  R3 escalation criterion tightened from ">4 rows" to ">2 rows
  IMPL-PARTIAL + BLOCKED-BY-ARCHITECTURE combined". Triage tag
  recorded as a top-level `triage_status` field in the evidence JSON.

### R2 MAJOR 2.6 -- Bootstrap-bypass clause not retired

- **File**: `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: threat evidence item scope changed from doc-update to script-
  deletion. Acceptance: delete the `needs_real_run` clause from
  `scripts/check-threat-coverage-mutants.sh` after Lane A closes; the
  bypass code does not exist post-Lane A.

### R2 MAJOR 3.2 -- Kani bound-parameter feasibility

- **Files**:
  `.planning/trajectory-5/lane-a-floor/kani-harness-design.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: added Kani harness evidence (Kani feasibility spike). Each invariant
  is run locally before Kani harness evidence starts; if any harness exceeds 30
  minutes locally, escalate. Per-harness bound parameters and
  `#[kani::unwind(N)]` values explicit per crate.

### R2 MAJOR 4.2 -- Apalache bounded transitive-closure feasibility

- **File**: `.planning/trajectory-5/lane-a-floor/tla-rewrites.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: release work-A4.2 includes feasibility-spike sub-task (20-line
  TLA fragment run against Apalache 0.50.x standalone). Fallback
  documented: hand-written `Reachable_step1`/`step2`/`step3` chain.

### R2 MAJOR 5.2 -- Lean refinement claim too weak

- **File**: `.planning/trajectory-5/lane-a-floor/lean4-fix.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: release work-A5.3 expanded from one theorem to three:
  `negotiation_safety_admit_implies_le`,
  `negotiation_safety_reject_implies_not_le_or_other_failure`, and
  `negotiation_safety_schema_first` (the ordering theorem the
  docstring genuinely requires). The "after merge, replace executable-
  model term body and confirm Lean elaboration FAILS" close-bar
  exercise added.

### R2 MAJOR 7.4 -- Mutation kill measured on test code

- **Files**:
  `.planning/trajectory-5/lane-a-floor/mutation-budget.md`,
  `.planning/trajectory-5/lane-a-floor/planning docs`.
- **Change**: added mutation exclusion audit (`.cargo/mutants.toml` exclusion-list
  audit). Each exclusion is marked `OK` or `FOR-REMOVAL`; output to
  `audits/evidence/mutation exclusion audit/exclude-audit.md`.

### R2 MAJOR 9 / Section 10.2 -- CI workflow inventory + Wave 1 critical path

- **Files**: `.planning/trajectory-5/lane-a-floor/README.md`,
  `.planning/trajectory-5/lane-a-floor/PLAN.md`.
- **Change**: added "CI workflow inventory" subsection enumerating
  every workflow Lane A touches (mutants.yml, mutants-banner.yml,
  nightly.yml, ci.yml, apalache-safety.yml, apalache-temporal.yml,
  lean.yml, plus confirm-no-touch entries). Added "Wave 1 critical-
  path deliverables" subsection naming five Wave 1 deliverables.

---

## Findings addressed (R2 MINOR)

### R2 MINOR 1.4 -- mutants.yml workflow status check

- **File**: planning docs mutation evidence item acceptance.
- **Change**: verify `status_at_capture` of last 7 nightly runs;
  un-flake before per-crate measurement starts.

### R2 MINOR 2.7 -- Mobile rows scheduling

- **File**: planning docs threat evidence item / A2.9 / A2.13 acceptance.
- **Change**: each fails closed if TRJ4-033 is not in its `closed`
  bucket; Wave 1 confirms.

### R2 MINOR 3.4 -- Theorem-inventory cross-reference filename

- **File**: `kani-harness-design.md`, planning docs Kani harness evidence.
- **Change**: Kani harness evidence references the actual file
  `formal/rust-verification/kani-public-harnesses.toml`; mirror in
  `formal/proof-manifest.toml` only if that file references the
  relevant crate.

### R2 MINOR 4.3 -- DEPTH_MAX bump wall-clock evidence

- **File**: `tla-rewrites.md`, planning docs release work-A4.3.
- **Change**: record apalache wall-clock BEFORE and AFTER the bump in
  `audits/evidence/release work-A4.3/length-budget.md`. If post-bump >25
  minutes, fallback to DEPTH_MAX=5 or extend timeout.

### R2 MINOR 4.4 -- Branch-protection screenshot

- **File**: `tla-rewrites.md`, planning docs release work-A4.4.
- **Change**: capture
  `audits/evidence/release work-A4.4/branch-protection.png` (screenshot of
  GitHub branch-protection settings showing `apalache-temporal` in
  the required list).

### R2 MINOR 4.5 -- Tautology-shortcut audit

- **File**: `tla-rewrites.md`, planning docs release work-A4.5.
- **Change**: release work-A4.5 reviews `theorem-inventory.json` AND the
  `PublishAllow` definition for evidence of unfolding shortcuts.

### R2 MINOR 5.3 -- Lean toolchain CI re-scope

- **File**: `lean4-fix.md`, planning docs release work-A5.1.
- **Change**: re-scoped from M to L; pin Lean toolchain version in
  `formal/lean4/lean-toolchain` (or equivalent); document elaboration
  time + CI cache strategy.

### R2 MINOR 6.5 -- A4.1 counterexample-on-revert

- **File**: planning docs release work-A4.1 acceptance.
- **Change**: remove ReceiptBeforeAllow invariant from cfg and confirm
  apalache produces counterexample trace; capture to
  `audits/evidence/release work-A4.1/counterexample-on-revert.tla`.

### R2 MINOR 7.2 -- rfl-tautology against new model

- **File**: `lean4-fix.md`, planning docs release work-A5.3 acceptance.
- **Change**: proof body MUST include at least one of `cases`,
  `induction`, `split_ifs`, or `intro`-with-non-rfl. One-line `by ...`
  proofs that elaborate without case analysis fail the close bar.

### R2 MINOR 8.3 -- Cross-lane overlap on chio-anchor

- **File**: planning docs Kani harness evidence acceptance, also
  `kani-harness-design.md` "Lane B coordination note".
- **Change**: explicit Lane B coordination -- the harness is updated
  within the same PR or one wave behind, never more than one wave.

### R2 MINOR 10.3 -- Kani lane advisory-to-required promotion

- **File**: planning docs Kani harness evidence.
- **Change**: new ticket promoting the new multi-crate Kani lane to
  required after two consecutive green runs.

---

## Findings addressed (R1 cross-lane MAJOR)

### R1 MAJOR section 4.2 -- threat-count drift (21 vs 20)

- **Files patched** (all in `.planning/trajectory-5/`):
  - `SHIP-BAR-TRACKER.md` (Bar 1 row -- 21 -> 20 with footnote).
  - `EXECUTION-BOARD.md` (release work-A2 description -- 21 -> 20 with
    footnote; TRJ4-040..049 absorption count adjusted).
  - `SCOPE-LOCK.md` (release work-A2 row -- 21 -> 20 with footnote).
  - `README.md` (Bar 1 paragraph -- 21 -> 20 with footnote).
  - `KICKOFF-CHECKLIST.md` (TRJ4-040..049 line -- adds 20-files
    note).
  - `architecture/RISK-REGISTER.md` (R3 -- 21 -> 20; R3 escalation
    threshold tightened from >4 to >2).
  - `templates/EVIDENCE-GATE.md` (Anti-Pattern 2.1 -- 21 -> 20 with
    footnote).
  - `OWNERS.toml` (threat-modeling owner-class description -- 21 ->
    20).
  - `lane-a-floor/README.md` (Authoritative threat count footnote
    added).
- **Authoritative count**: 20, verified by
  `ls audits/evidence/threats/ | wc -l` and
  `grep -c '"id":' spec/security/chio-threat-model.v1.json`. The
  synthesis (which says "21") is treated as a minor arithmetic drift
  and is not re-opened; each patched location carries a footnote
  explaining the drift.

### R1 MAJOR section 2.3 -- TRJ4-019 dropped (proptest equivalence)

- **Decision**: defer to **trj6** with rationale.
- **Files patched**:
  - `SCOPE-LOCK.md` (TRJ4-019 row removed from Lane A; new "Deferred
    to trj6 with rationale" subsection added with the full deferral
    rationale).
  - `EXECUTION-BOARD.md` (release work-A5 description rewritten to be Lean
    work, formerly release work-A6; TRJ4-019 absorption-summary row reads
    "deferred to trj6").
  - `KICKOFF-CHECKLIST.md` (TRJ4-019 checkbox flipped to deferred;
    note records the slot reuse).
  - `TIMELINE.md` (Gantt updated; old `A5 = chio-equivalence-tests`
    and `A6 = Lean` flipped to `A5 = Lean`).
  - `lane-a-floor/README.md`,
    `lane-a-floor/planning docs` (release work-A5 sub-lane is Lean; "On the
    dropped TRJ4-019" section added to planning docs).

### R1 MAJOR section 2.1 -- Evidence-Gate ticket-ID suffix convention drift

- **Decision**: adopt `release work-A<n>.E` as the canonical Evidence Gate
  ticket suffix per `templates/TICKET-TEMPLATE.md` section 1.1.
- **File patched**:
  - `lane-a-floor/planning docs` (header section "Ticket-ID
    convention" added explicitly stating the `.E` suffix; one `.E`
    ticket per sub-lane added: `mutation evidence item`, `threat evidence item`,
    `release work-A3.E`, `release work-A4.E`, `release work-A5.E`).
  - `SHIP-BAR-TRACKER.md` Bar 1 cell release work-tickets now references
    `each sub-lane closes under its release work-A<n>.E Evidence Gate
    ticket`.
  - `EXECUTION-BOARD.md` "Detail rows beyond..." paragraph now
    names the five `.E` tickets.

---

## Findings explicitly deferred

### TRJ4-019 (proptest hosted-vs-portable equivalence) -> trj6

Lane A's 8-week horizon is already loaded with five sub-lanes (mutation
uplift, threat backfill, Kani harnesses, TLA+ rewrites, Lean
refinement) totaling 50+ tickets after Wave 3 expansion. Adding a sixth
sub-lane for proptest equivalence-tests at 10k/PR + 1M/nightly is real
engineering work (CI matrix, infrastructure spend, run-time budget) and
risks plateau on higher-priority Lane A work. The hosted-vs-portable
equivalence claim is currently informational; no synthesis ship-bar
depends on it. Captured in `SCOPE-LOCK.md` "Deferred to trj6 with
rationale".

### `wasm_guard_resource_exhaustion` (threat row 19) -> trj6

Per Risk Register R3, this row depends on `wasm-guard SDK v4` which is
out of scope for release work. Pre-Wave-1 estimate is `BLOCKED-BY-ARCHITECTURE`.
The release work banner reads "<n> of 20 covered, 1 deferred to trj6"; if Wave
1 confirms additional rows in `IMPL-PARTIAL`/`BLOCKED-BY-ARCHITECTURE`,
the deferral count grows and R3 escalation fires (>2 threshold).

### Architecture-blocked threat rows (Wave 1 confirms count)

Rows 11 (`passkey_credential_theft`), 15 (`resource_exhaustion_dos`),
18 (`tool_server_escape`) are tagged `IMPL-EXISTS-PRIVATE` /
`IMPL-PARTIAL` pending Wave 1 confirmation. If Wave 1 cannot identify a
production `pub fn` for any of these, the row defers to trj6. Risk
Register R3 captures the contingency.

---

## Unresolved items for the Wave 4 final-pass

1. **Wave 1 triage of 20 threat rows** must be the first work-item.
   Without the per-row triage tags landing in
   `audits/evidence/threats/<id>.json`, the runtime gate cannot
   distinguish release work-provable rows from architecture-blocked rows. The
   Wave 1 reviewer signs off on the triage in
   `reviews/lane-a-wave2.md`.

2. **TRJ4-033 closure status** (R2 MINOR 2.7). If TRJ4-033 has not
   merged by Wave 1, A2.7 / A2.9 / A2.13 fail closed and the mobile
   rows ramp later. Wave 4 must check `../trajectory-4/closeout/CLOSE-
   BAR-TRACKER.md` for TRJ4-033 status.

3. **Apalache encoding feasibility** for the bounded transitive-closure
   operator (R2 MAJOR 4.2). The fallback (hand-written
   `Reachable_step1`/`step2`/`step3`) is documented but the code is not
   yet written. If Wave 1 finds Apalache 0.50.x cannot encode the
   recursive operator, release work-A4.2 escalates.

4. **Kani local wall-clock budget validation** (R2 MAJOR 3.2). Each of
   the 12 proposed harnesses (4 per crate) must run locally under 30
   minutes. The validation file
   `audits/evidence/Kani harness evidence/local-bound-validation.md` does not yet
   exist. If any harness exceeds the budget, Kani harness evidence escalates.

5. **Lean toolchain pin** for CI (R2 MINOR 5.3). The
   `formal/lean4/lean-toolchain` pin file does not yet exist. Without
   the pin, every PR rebuilds the proof set against whatever Lean
   version is current.

6. **Wave 1 confirmation of `IMPL-EXISTS-PRIVATE` rows**. Rows 11, 15,
   16, 18 in `threat-evidence-backfill.md` carry "Wave 1 confirms"
   notes. The list of `pub fn` symbols cited is plausible but Wave 1
   reviews the actual production behavior to decide which `pub fn` is
   the closest-fit production decision for the threat-row attack
   class.

7. **`.cargo/mutants.toml` exclusion-list audit output** (R2
   OBSERVATION 1.2). The audit file
   `audits/evidence/mutation exclusion audit/exclude-audit.md` does not yet exist.
   Without the audit, the >=65% target is held against a pre-existing
   exclusion list whose justification has not been re-checked in the
   release work frame.

8. **Cross-lane coordination on chio-anchor** (R2 MINOR 8.3). Lane B
   may modify `crates/chio-anchor/src/batch.rs` during release work-B3 in ways
   that change the shape of `verify_anchor_batch`. The Lane A Kani
   harness depends on this shape. The coordination note is in place;
   Wave 4 verifies the Lane B reviewer accepts the constraint.

9. **OWNERS.toml `crates/chio-equivalence-tests/**` path entry**.
   With TRJ4-019 deferred to trj6, the path entry under `lane.A.paths`
   is technically dormant during release work but still claimed. Wave 4 may
   choose to remove the path or leave it; the choice does not affect
   any close bar.

---

End of fix log.
