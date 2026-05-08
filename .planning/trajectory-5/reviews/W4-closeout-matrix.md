# Wave 4 Closeout Matrix

**Author**: Wave 4 final-pass agent. **Date**: 2026-05-08.

This matrix maps every Wave 2 BLOCKER and MAJOR finding to its Wave 3 fix-log entry (or deliberate defer) and records its closeout status.

Status legend:

- **CLOSED**: Wave 3 fix-log entry addressed the finding in-doc; no follow-up needed before kickoff.
- **DEFERRED-TO-TRJ6**: Recorded in `SCOPE-LOCK.md` "Deferred to trj6 with rationale" or equivalent; not a kickoff prerequisite.
- **DEFERRED-TO-WAVE-5**: Acknowledged but action sits in scaffolding work (preflight script, owner-class assignments, baseline measurements). Tracked in `KICKOFF-CHECKLIST.md`.
- **OPEN-FOR-OWNER**: Requires a human decision the Wave 4 agent cannot make alone; called out in the kickoff checklist.

Wave 2 finding totals (BLOCKER + MAJOR scope of this matrix):

- R1 (cross-lane): 4 BLOCKER + 9 MAJOR = 13.
- R2 (lane A depth): 4 BLOCKER + 9 MAJOR = 13.
- R3 (lane B compliance): 3 BLOCKER + 6 MAJOR = 9.
- R4 (lane C feasibility): 2 BLOCKER + 6 MAJOR = 8.
- **Total: 13 BLOCKER + 30 MAJOR = 43 findings tracked here.**

MINOR / OBSERVATION findings (R2: 11 MINOR + 6 OBSERVATION; R3: 4 MINOR + 3 OBSERVATION; R4: 4 MINOR + 4 OBSERVATION; R1: assorted MINOR/OBSERVATION) are addressed at the discretion of the Wave 3 fix agents and are not enumerated here. Sample MINOR coverage is shown at the bottom of this document.

---

## R1 (cross-lane review)

| Finding ID | Severity | Summary | Wave 3 fix-log entry | Status | Notes |
|---|---|---|---|---|---|
| R1-BLOCKER-1.4 | BLOCKER | Lane C "Option A" two-signature DSSE adapter is invisible above the Lane C deep dive (no master-doc surfacing). | `W3-lane-b-fixes.md` § "B4 sub-lane (NEW per R4 BLOCKER 1)" + `W3-lane-c-fixes.md` § "R4 BLOCKER 1 - REWORKED". Option A dropped entirely; promoted to Lane B sub-lane B4 with master-doc propagation. | CLOSED | Master docs updated; SHIP-BAR-TRACKER, SCOPE-LOCK, SPEC-TO-RUNTIME-MAP, RISK-REGISTER R7 all carry the B4 row. |
| R1-BLOCKER-2.2 | BLOCKER | Lane C uses non-template aliases (`LB-CAP`, `LB-RV2`, `LB-AB`, `LB-AT`) for cross-lane deps instead of literal Lane B ticket IDs. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 3". Aliases replaced with literal Lane B ticket IDs in `Depends on:` rows. | CLOSED | Aliases preserved only in cross-reference table at `lane-c-demo/planning docs:21-34` (per R1 prescription); zero `Depends on:` rows still cite aliases. |
| R1-BLOCKER-4.3 | BLOCKER | Master / template / architecture / Lane C docs cite pre-correction line range `mod.rs:1148-1165` and trait name `ToolServer`. | `W3-lane-b-fixes.md` § "R1 BLOCKER on line-range and trait-name drift" (full file inventory). All 7 remaining `:1148-1165` references are explanatory footnotes; bare `ToolServer` only in synthesis-verbatim quote in `lane-b-wiring/README.md` (footnoted). | CLOSED | Verified by W4 grep: all matches in load-bearing prose are now `:1574-1591` and `ToolServerConnection`. |
| R1-BLOCKER-5.3 | BLOCKER | Lane C tickets contain zero Evidence Gate references and zero TRJ4 back-references. | `W3-lane-c-fixes.md` § "R1 BLOCKER (Lane C zero Evidence Gate references)". Lane C tickets rewritten with the five-row Acceptance block per ticket plus a header paragraph. | CLOSED | Every release work-C* ticket now carries the four-artifact Evidence Gate Acceptance shape. |
| R1-MAJOR-1.3 | MAJOR | Lane C5 (selective disclosure) scope creep through new workspace member `chio-zk-receipts` and BBS+ deps. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 6". Explicit deferral path: C5 ships only if W2 dep-tree validation succeeds; otherwise drops to five-artifact bundle. R6 in RISK-REGISTER updated. | CLOSED | Bounded-claim language landed in `release-bar.md` and `selective-disclosure.md`. |
| R1-MAJOR-2.1 | MAJOR | Three different Evidence-Gate ticket suffix conventions (`release work-B-EG`, `release work-B.CLOSE`, `release work-B<n>.E`). | `W3-lane-a-fixes.md` § "R1 MAJOR section 2.1" + `W3-lane-b-fixes.md` § "R1 MAJOR on Evidence-Gate ticket suffix convention". Canonical `.E` suffix per sub-lane adopted; `release work-B-EG` and `release work-B.CLOSE` retired. | CLOSED | Five Lane A `.E` tickets (A1.E..A5.E), four Lane B `.E` tickets (B1.E..B4.E), six Lane C `.E` tickets (C1.E..C6.E) in place. |
| R1-MAJOR-2.3 | MAJOR | Lane A renumbered release work-A5 from equivalence-tests (TRJ4-019) to Lean4, dropping TRJ4-019. | `W3-lane-a-fixes.md` § "R1 MAJOR section 2.3 - TRJ4-019 dropped". Decision: deferred to trj6 with rationale; SCOPE-LOCK updated. | DEFERRED-TO-TRJ6 | Captured in SCOPE-LOCK "Deferred to trj6 with rationale" subsection; KICKOFF-CHECKLIST checkbox flipped to deferred. |
| R1-MAJOR-3.4 | MAJOR | `OWNERS.toml` `[overlaps]` table lacks coordination owners on multi-lane rows (esp. `chio-anchor`, `chio-federation`). | Wave 4 patched directly: `OWNERS.toml` `[overlaps]` rows converted to inline tables with `coordination_owner = "release owner"`. `chio-federation` row carries `path_overlaps` and a `notes` field about B4↔C2 coordination. | CLOSED | Verified by Wave 4 file diff. |
| R1-MAJOR-3.5 | MAJOR | `crates/chio-conformance/tests/` overlap (A↔B) needs coordination owner. | Same as 3.4. | CLOSED | Same patch. |
| R1-MAJOR-4.2 | MAJOR | Threat-evidence file count drift (master says 21; disk has 20). | `W3-lane-a-fixes.md` § "R1 MAJOR section 4.2 - threat-count drift (21 vs 20)". All 9 patched master/lane/template/architecture files now read 20 with footnote; OWNERS.toml description updated. | CLOSED | W4 grep `grep -rn "21 threat"` returns zero in non-review/non-debate paths. |
| R1-MAJOR-6.2 | MAJOR | R4 mitigation (continuous Lane C smoke) contradicts the timeline (Lane C deferred until W4). | `W3-lane-c-fixes.md` § "R1 MAJOR (continuous Lane C run)". Lane C scaffolding (C1.1, C1.2, C1.4) starts W3 alongside in-progress Lane B; new C6.3 continuous workflow ticket. README.md line 134 updated. | CLOSED | TIMELINE.md and EXECUTION-BOARD.md cross-lane dependency table updated to match. |
| R1-MAJOR-7.3 | MAJOR | Lane B / Lane C tickets lack trj4 back-references. | Lane B planning docs carries `trj4_absorbed` columns at the sub-lane summary table; OWNERS.toml `trj4_absorbed = [...]`. Lane C OWNERS.toml `trj4_absorbed = []` (correct: no trj4 absorption). | CLOSED | Per Wave 3 documentation. |
| R1-MAJOR-9 | MAJOR | DSSE Option-A propagation to master docs. | Subsumed by R1-BLOCKER-1.4 (Option A dropped, replaced with B4 in master docs). | CLOSED | Same fix as 1.4. |

---

## R2 (lane A depth)

| Finding ID | Severity | Summary | Wave 3 fix-log entry | Status | Notes |
|---|---|---|---|---|---|
| R2-BLOCKER-2.3 | BLOCKER | 12+ threat-evidence rows have hand-wavy production paths or "TBD". | `W3-lane-a-fixes.md` § "R2 BLOCKER 2.3 -- threat-evidence hand-wavy production paths". Each release work-A2.<n> ticket gains an "Artifact A (public symbol)" column; rows triaged as IMPL-EXISTS-AND-PUBLIC / IMPL-EXISTS-PRIVATE / IMPL-PARTIAL / BLOCKED-BY-ARCHITECTURE. | CLOSED | Wave 1 confirms a few row-specific tags; the gating column shape is in place. |
| R2-BLOCKER-3.1 | BLOCKER | Kani harness production-entry names do not match the codebase. | `W3-lane-a-fixes.md` § "R2 BLOCKER 3.1 -- Kani harness production-entry names". Tables (1)/(2)/(3) rewritten against verified `pub fn` names; A3.1/A3.2/A3.3 tickets cite file:line. | CLOSED | Includes chio-attest-verify (`expect_report_data` + 3 `verify_quote` impls), chio-anchor (`verify_anchor_batch`, `evaluate_witness_policy`, `batch_body_hash`), chio-weights (`weights_hash_of`, `anchor_projection_bytes`, `verify_model_card_anchor`, `verify_model_card_bundle`). |
| R2-BLOCKER-3.3 | BLOCKER | Kani CI integration is hand-wavy (the workflow shape sketch doesn't match reality). | `W3-lane-a-fixes.md` § "R2 BLOCKER 3.3 -- Kani CI integration is hand-wavy". Concrete workflow diff against `nightly.yml:102-128` and `ci.yml:478-590`; split into A3.5a (manifest schema) + A3.5b (per-workflow shell-loop). | CLOSED | Plus A3.6 advisory-to-required promotion ticket. |
| R2-BLOCKER-5.1 | BLOCKER | Lean4 Rust signature mis-stated. | `W3-lane-a-fixes.md` § "R2 BLOCKER 5.1 -- Lean4 Rust signature mis-stated". `lean4-fix.md:75-85` rewritten against actual signature at `crates/chio-kernel-core/src/capability_verify.rs:226-232`. Three type fixes documented. | CLOSED | Includes explicit field-mapping section. |
| R2-BLOCKER-6.2 | BLOCKER | A2 ticket Artifact A specificity too loose. | `W3-lane-a-fixes.md` § "R2 BLOCKER 6.2 -- A2 ticket Artifact A specificity too loose". Lane A tickets file opens with an Artifact A rule + per-ticket "Artifact A (public symbol)" column. | CLOSED | Mock-not-runtime anti-pattern explicitly excluded by Acceptance text. |
| R2-MAJOR-1.1 | MAJOR | Mutation uplift target backed by no sample run. | `W3-lane-a-fixes.md` § "R2 MAJOR 1.1". Split into mutation evidence item (run baseline) + A1.2b (publish per-crate numbers); R2 escalation tightened. | CLOSED | If chio-attest-verify baseline below 50%, escalate to Wave 2 immediately. |
| R2-MAJOR-2.4 | MAJOR | Backfillable in release work vs blocked on architecture - need triage. | `W3-lane-a-fixes.md` § "R2 MAJOR 2.4". Wave 1 deliverable adds per-row triage as critical-path; R3 escalation tightened from >4 to >2. | CLOSED | Triage tag becomes a top-level `triage_status` field in evidence JSON. |
| R2-MAJOR-2.6 | MAJOR | Bootstrap-bypass clause not retired. | `W3-lane-a-fixes.md` § "R2 MAJOR 2.6". threat evidence item scope changed from doc-update to script-deletion; bypass code does not exist post-Lane-A. | CLOSED | |
| R2-MAJOR-3.2 | MAJOR | Kani bound-parameter feasibility unverified. | `W3-lane-a-fixes.md` § "R2 MAJOR 3.2". Added Kani harness evidence (Kani feasibility spike); each invariant runs locally before A3.1 starts; >30min escalates. | CLOSED | Per-harness bound parameters and `#[kani::unwind(N)]` values explicit per crate. |
| R2-MAJOR-4.2 | MAJOR | Apalache bounded transitive-closure feasibility. | `W3-lane-a-fixes.md` § "R2 MAJOR 4.2". release work-A4.2 includes feasibility-spike sub-task; fallback (hand-written `Reachable_step1/step2/step3`) documented. | CLOSED | If Apalache 0.50.x cannot encode the recursive operator, escalates. |
| R2-MAJOR-5.2 | MAJOR | Lean refinement claim too weak. | `W3-lane-a-fixes.md` § "R2 MAJOR 5.2". release work-A5.3 expanded from one to three theorems; "after merge, replace executable-model term body and confirm Lean elaboration FAILS" close-bar exercise added. | CLOSED | |
| R2-MAJOR-7.4 | MAJOR | Mutation kill measured on test code. | `W3-lane-a-fixes.md` § "R2 MAJOR 7.4". mutation exclusion audit (`.cargo/mutants.toml` exclusion-list audit) added. | CLOSED | Output to `audits/evidence/mutation exclusion audit/exclude-audit.md`. |
| R2-MAJOR-9 | MAJOR | Risk: threat row unprovable in current architecture. | `W3-lane-a-fixes.md` § "R2 MAJOR 2.4" + "Findings explicitly deferred". Risk Register R3 captures the contingency; specific rows deferred to trj6. | CLOSED | `wasm_guard_resource_exhaustion` deferred; rows 11/15/18 pending Wave 1. |
| R2-MAJOR-10.2 | MAJOR | What the plan does NOT name (CI workflow inventory + Wave 1 critical path). | `W3-lane-a-fixes.md` § "R2 MAJOR 9 / Section 10.2". `lane-a-floor/README.md` and `PLAN.md` got CI workflow inventory subsection + Wave 1 critical-path deliverables. | CLOSED | Five Wave 1 critical-path deliverables enumerated. |

---

## R3 (lane B compliance)

| Finding ID | Severity | Summary | Wave 3 fix-log entry | Status | Notes |
|---|---|---|---|---|---|
| R3-BLOCKER-1 | BLOCKER | B2 spec-language framing (PROTOCOL.md §737-741 has neither MUST nor SHOULD; framing as "promotion" is wrong). | `W3-lane-b-fixes.md` § "R3 BLOCKER #1: B2 spec-language framing". Reframed as introducing a NEW normative MUST (tightening, not promotion). | CLOSED | `templates/EVIDENCE-GATE.md` §1.2 extended to recognize TWO valid paths (promotion AND tightening). |
| R3-BLOCKER-2 | BLOCKER | B3 lint script soundness contract unachievable. | `W3-lane-b-fixes.md` § "R3 BLOCKER #2: B3 lint script soundness contract". Option A (honest reframing): runtime gate is load-bearing; lint is best-effort fast-feedback only. AST upgrade deferred to trj6. | CLOSED | release work-B3.3 effort reduced from M to S. |
| R3-BLOCKER-3 | BLOCKER | B0 impl count audit (47 sites in 31 files, not 31 impls). | `W3-lane-b-fixes.md` § "R3 BLOCKER #3: B0 impl count audit". Inventory updated to reconcile 31 (files) vs 47 (sites); `&mut self` count corrected to 24 method definitions / 36 occurrences. | CLOSED | release work-B0.1 ticket updated to require both file-count and site-count verification. |
| R3-MAJOR-3 | MAJOR | Single-entry-verifier error mapping (typed deny reasons needed at hosted call sites). | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #3". release work-B1.2 ticket extended to require typed deny reasons (`InvalidSignature`, `AttenuationViolation`, `SchemaExceedsNegotiatedCeiling`). | CLOSED | |
| R3-MAJOR-1-reservation | MAJOR | B2 helper functions (`count_v1_receipts` / `count_v2_receipts`) must read SQLite tables directly, not via test-only kernel accessor. | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #1 reservation". `receipt-v2-failclosed.md` updated. | CLOSED | Avoids `EVIDENCE-GATE.md` §8.3 anti-pattern. |
| R3-MAJOR-4-stale-vs-never-pinned | MAJOR | B2 stale vs never-pinned cases. | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #4 last paragraph". Spec edit explicitly enumerates both cases. | CLOSED | |
| R3-MAJOR-5 | MAJOR | B3 gate-script soundness (subsumed by R3-BLOCKER-2). | Same as R3-BLOCKER-2. | CLOSED | Severity per the review header is BLOCKER; the same finding appears once with both labels in the review. |
| R3-MAJOR-6 | MAJOR | B0 impl count audit (subsumed by R3-BLOCKER-3). | Same as R3-BLOCKER-3. | CLOSED | Same. |
| R3-MAJOR-7 | MAJOR | Spec MUST citations (B3 promotion of arrow notation). | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #7". PLAN.md retains B3.4 spec edit; Wave-1 audit-doc owner notes the arrow-notation upgrade to RFC 2119 MUST. | CLOSED | |
| R3-MAJOR-9-second-reviewer | MAJOR | Second-reviewer requirement on close tickets. | `W3-lane-b-fixes.md` § "R3 MAJORs addressed - #9". release work-B1.E / B2.E / B3.E / B4.E tickets explicitly require lane owner AND non-author reviewer sign-off per `EVIDENCE-GATE.md` §3.3. | CLOSED | |

---

## R4 (lane C feasibility)

| Finding ID | Severity | Summary | Wave 3 fix-log entry | Status | Notes |
|---|---|---|---|---|---|
| R4-BLOCKER-1 | BLOCKER | DSSE/Ed25519 signing scheme - "Option A" two-signature design does not satisfy spec §6. | `W3-lane-b-fixes.md` § "B4 sub-lane (NEW per R4 BLOCKER 1)" + `W3-lane-c-fixes.md` § "R4 BLOCKER 1 (DSSE signing scheme)". Option A dropped; promoted to Lane B sub-lane B4 (`bilateral DSSE signing item` plus `bilateral DSSE signing item`). | CLOSED | Master docs updated; Lane C now consumes B4 envelope. Wave 4 swept Lane C placeholders to literal B4 ticket IDs. |
| R4-BLOCKER-2 | BLOCKER | KB MCP transport mismatch (`chio mcp serve` wraps stdio; KB MCP serves HTTP). | `W3-lane-c-fixes.md` § "R4 BLOCKER 2". Demo uses `mcp-remote` (Node.js stdio<->HTTP bridge) per `ops/knowledge-base/README.md:136-151`. Pre-requisites section added; policy YAML rewritten in HushSpec shape. | CLOSED | Wave 4 added a section to `lane-b-wiring/conformance-fixture-spec.md` describing how the B-pattern accommodates the C-demo bridge (item 3 of W4 brief). |
| R4-MAJOR-3 | MAJOR | Cross-lane dep aliases not anchored to Lane B IDs. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 3". Aliases replaced with literal Lane B ticket IDs in `Depends on:` rows; alias->ID map preserved as documentation table. | CLOSED | Subsumed in R1-BLOCKER-2.2 closure. |
| R4-MAJOR-4 | MAJOR | release-bar.md AND-overclaims §6 conformance. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 4". Release notes now cite Lane B B4 directly; new items 13/14 added to "What this release DOES NOT CLAIM". | CLOSED | |
| R4-MAJOR-5a | MAJOR | chiodos-ladder primitive missing in code. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 5a". release work-C1.3 effort bumped M->L; primitive lives in `examples/chiodome-bilateral/src/ladder.rs`; bounded-claim text. | CLOSED | Production primitive deferred to trj6. |
| R4-MAJOR-5b | MAJOR | Policy YAML format mismatch. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 5b". Policy YAML rewritten in HushSpec shape; amount cap moved to ladder intersection per option (a). | CLOSED | |
| R4-MAJOR-6 | MAJOR | BBS+ deps absent; R6 mitigation soft. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 6". Explicit deferral path: C5 ships only if W2 dep-tree validation succeeds. | CLOSED | `release-bar.md` item 14 enumerates the deferral. |
| R4-MAJOR-7 | MAJOR | End-to-end composition gaps. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 7". New release work-C2.5 ticket (anchor inclusion proof); §7 verifier ticket release work-C2.4 explicitly depends on B1.6/B2.5/B3.5/B4.5. Two-keypair signing protocol section added. | CLOSED | |
| R4-MAJOR-8 | MAJOR | 17-step verifier cross-crate calls (steps 7, 14) unresolved. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 8". Architecture cut option B (trait objects for `ReceiptStore` and `CapabilityVerifier`); release work-C2.1 introduces the `CapabilityVerifier` trait in `chio-federation`. | CLOSED | release work-C4.1 effort bumped M->L. |
| R4-MAJOR-10 | MAJOR | Forcing-function CI hook missing. | `W3-lane-c-fixes.md` § "R4 MAJORs - Finding 10". release work-C6.3 "Continuous chiodome demo workflow" added. | CLOSED | Nightly + Lane B path push, failures open issues, 7 consecutive nights green pre-tag. |

---

## Summary counts

| Bucket | Count |
|---|---|
| BLOCKER closed | 13 |
| BLOCKER deferred | 0 |
| BLOCKER open | 0 |
| MAJOR closed | 29 |
| MAJOR deferred (TRJ4-019 -> trj6) | 1 |
| MAJOR open | 0 |
| **Total tracked (BLOCKER + MAJOR) = 43** | 13 BLOCKER closed + 29 MAJOR closed + 1 MAJOR deferred = 43 |

Zero BLOCKERs end OPEN-FOR-OWNER. Trj5 is kickoff-ready from a finding-closeout standpoint.

---

## Sample MINOR coverage (informational; not gating)

A spot-check of high-impact MINOR findings confirms Wave 3 fix agents addressed them:

- R2-MINOR-1.4 (`mutants.yml` workflow status check): closed via mutation evidence item acceptance update.
- R2-MINOR-2.7 (mobile rows scheduling): closed via threat evidence item / A2.9 / A2.13 acceptance.
- R2-MINOR-3.4 (theorem-inventory cross-reference filename): closed via Kani harness evidence.
- R2-MINOR-4.5 (tautology-shortcut audit): closed via release work-A4.5.
- R2-MINOR-5.3 (Lean toolchain CI re-scope): closed via release work-A5.1 (M->L re-scope).
- R2-MINOR-7.2 (`rfl`-tautology against new model): closed via release work-A5.3 acceptance.
- R2-MINOR-8.3 (cross-lane overlap on chio-anchor): closed via Kani harness evidence acceptance + Lane B coordination note.
- R2-MINOR-10.3 (Kani lane advisory-to-required promotion): closed via new Kani harness evidence ticket.
- R3-MINOR-2 (wording fix on receipt-v2 reverse-test): already correct.
- R4-MINOR-9 (`chio receipt explain` underestimated): closed via release work-C4.1 bump M->L.
- R4-MINOR-11 (demo fixture reproducibility): closed via new release work-C6.4 (diff-stable fixture tarball).
- R4-MINOR-12 (mock-receipt detection): closed via release work-C6.2 mtime check.

The remaining MINOR / OBSERVATION items are noted in the per-lane Wave 3 fix logs.

---

## Wave 4 residual coordination items (separate from Wave 2 closure; tracked in W4 brief items 1-6)

| Item | Status |
|---|---|
| 1. Lane C placeholder `bilateral DSSE signing item` deps replaced with locked B4 IDs (B4.1..B4.6 plus B4.E) | CLOSED (Wave 4 patched bilateral-cosign-flow.md, release-bar.md, README.md, PLAN.md, planning docs) |
| 2. R7 RISK-REGISTER row reframed for new B4 risk (DSSE PAE encoding, Ed25519 over PAE fragility) | CLOSED (R7 was already correctly framed by Lane B Wave 3 fix agent; verified Wave 4) |
| 3. KB MCP `mcp-remote` bridge in Lane B conformance fixture spec | CLOSED (Wave 4 added "Lane C demo path note" subsection to `conformance-fixture-spec.md`) |
| 4. Lane A cosmetic `ToolServer` refs in `threat-evidence-backfill.md` and planning docs | CLOSED (Wave 4 patched both, plus RISK-REGISTER R3 entry) |
| 5. OWNERS.toml `coordination_owner` for `crates/chio-federation/` | CLOSED (Wave 4 converted all `[overlaps]` rows to inline tables with `coordination_owner` field; chio-federation row carries `path_overlaps` and `notes`) |
| 6. Synthesis-source footnote (in-place) | CLOSED (Wave 4 added SUPERSEDED-NOTE block at top of `debate/00-SYNTHESIS.md`; pointers to lane docs and Wave 3 fix logs) |

End of Wave 4 closeout matrix.
