# Trajectory 5 Readiness Summary

**Author**: Wave 4 final-pass agent. **Date**: 2026-05-08.
**Baseline SHA**: `708c7bb33df43594f5e76542b05fca7a56d9689e`.
**Status**: R4 BLOCKED FOR RELEASE; planning ownership centralized in #620;
source integration must follow `R4-MERGE-TOPOLOGY.md`.

This document was the pre-execution readiness summary. R4 supersedes the
previous execution-complete framing for release purposes. The current
integration-coordination map, planning ownership rule, and merge simulation
log live in `R4-MERGE-TOPOLOGY.md`. The text below is preserved as the
historical pre-execution record.

## R4+ release truth

- Bar 1 is PARTIAL until full hosted-nightly mutation evidence is
  regenerated from merged `main`.
- Bar 2 is PARTIAL until the four conformance fixtures are regenerated
  and validated from merged `main`.
- Bar 3 is PARTIAL until the demo fixtures are regenerated from merged
  `main`; C3 default KB MCP mode emits mediation transcripts, not
  kernel-signed Chio receipts.
- Kani, TLA+, Lean, C2, and C5 are bounded or placeholder evidence.
  They are not production-proof-complete release evidence.
- `v0.1.0-bounded-chiodome` is not pushed by this branch. A human tag
  push is allowed only after upstream merges, regeneration, and green
  checks on the integrated merge SHA.

---

## Pre-execution status (historical)

**Status (at kickoff)**: READY-WITH-ASSIGNMENTS (kickoff prerequisites enumerated below).

---

## The three lanes

| Lane | Slug | Owner-classes | Duration | Tickets | Bar |
|---|---|---|---|---|---|
| A | `lane-a-floor` | substrate-rust + formal-tla / formal-lean / formal-kani + threat-modeling + quality-rust | 8 weeks | 57 | Bar 1 |
| B | `lane-b-wiring` | protocol-rust + kernel-rust + spec-rust | 7 weeks (was 6; B4 added) | 32 | Bar 2 |
| C | `lane-c-demo` | federation-rust + cli-rust + examples + spec-rust | 4 weeks (W3-W8 with W3 scaffolding) | 24 | Bar 3 |

**Total**: 113 tickets across three coupled lanes. All ticket IDs follow the `release work-X<sub>.<seq>` shape; per-sublane Evidence Gate close tickets use the `.E` suffix per `templates/TICKET-TEMPLATE.md` §38.

## The three ship bars

1. **Bar 1 -- realize the floor (Lane A)**. README mutation banner reads `>=65%` with the per-crate breakdown attached and a non-placeholder evidence directory. Machine-readable signal: `audits/evidence/mutation/banner.json` and 20 of 20 (or `n` of 20 with deferred row count) `audits/evidence/threats/*.json` files with real `caught >= 1` data.

2. **Bar 2 -- wire the spec hot path (Lane B)**. The four Lane B primitives -- capability v2, receipt v2, anchor-batch async, **and DSSE-conformant bilateral signing (B4 added W3)** -- are each protected by a signed negative conformance fixture in `crates/chio-conformance/tests/`. Machine-readable signal: four files exist (`b1_capability_v2_single_entry_no_bypass.rs`, `b2_receipt_v2_failclosed_under_negotiated_v2.rs`, `b3_anchor_batch_sync_path_rejected_under_public_witness.rs`, `b4_bilateral_dsse_pae_only_is_conformant.rs`) and each contains a `// negative-conformance: ...` annotation.

3. **Bar 3 -- one forcing demo (Lane C)**. The two-kernel cross-org bilateral cosigned invocation runs end-to-end, the receipts are inspectable with `chio receipt explain`, and the demo is captured as a fixture in `examples/chiodome-bilateral/fixtures/`. Machine-readable signal: `examples/chiodome-bilateral/` exists and `cargo run --example chiodome-bilateral` produces an `audits/evidence/c-bilateral-smoke.json` with all eight artifacts present.

## Wave 1 -> 2 -> 3 -> 4 narrative

Wave 1 (synthesis ratification + per-lane PLAN.md authoring) produced the three coupled lanes, six debate position papers, and the per-lane ticket enumeration. Wave 2 (review) generated four review documents (R1 cross-lane, R2 lane-A depth, R3 lane-B compliance, R4 lane-C feasibility) totaling 13 BLOCKER + 30 MAJOR + 19 MINOR + 13 OBSERVATION findings. Wave 3 (per-lane fix agents) addressed every BLOCKER and almost every MAJOR; the central restructure was R4 BLOCKER 1 promoting the Lane C "Option A" two-signature DSSE adapter to a fourth Lane B sub-lane (B4 DSSE-conformant bilateral signing). Wave 4 (this document's authoring pass) reconciled residual cross-lane coordination items, swept Lane C placeholder `bilateral DSSE signing item` deps to the locked B4 IDs, added a SUPERSEDED-NOTE to the synthesis, populated `OWNERS.toml` `[overlaps]` rows with `coordination_owner` fields, and produced the closeout matrix (`reviews/W4-closeout-matrix.md`).

## Findings statistics

- **Created (Wave 2)**: 13 BLOCKER + 30 MAJOR + 19 MINOR + 13 OBSERVATION = 75 findings.
- **Reviewed (Wave 3)**: all 75 findings reviewed; per-lane fix logs at `reviews/W3-lane-{a,b,c}-fixes.md` record the fix or deferral.
- **Fixed (Wave 3)**: 13 of 13 BLOCKERs closed; 29 of 30 MAJORs closed; 1 MAJOR (TRJ4-019 proptest equivalence) deferred to trj6 with rationale.
- **Closed (Wave 4)**: full BLOCKER + MAJOR closeout matrix at `reviews/W4-closeout-matrix.md`. Zero BLOCKERs end OPEN-FOR-OWNER.

## Open items requiring kickoff coordination

1. **Owner-class human assignments** (LARGEST GATE). `OWNERS.toml` `lanes.{A,B,C}.human_assignment = "TBD"` plus per `[owner_classes.<class>]` `assigned_to`. No code work can start until handles land.
2. **Wave-2 reviewer per-lane sign-off**. `reviews/lane-{a,b,c}-wave2.md` are the structured sign-off artifacts; the Wave 3 fix logs document the fixes but the reviewer's per-lane sign-off is a separate ledger expected by `KICKOFF-CHECKLIST.md`.
3. **`scripts/trj5-preflight.sh`**. The script does not yet exist. It will be authored as baseline scaffolding; the `KICKOFF-CHECKLIST.md` enumerates its required asserts.
4. **`releases.toml [trajectory_5]` block**. Draft block recommended values are in `KICKOFF-CHECKLIST.md`. The block is opened by the human kickoff agent.
5. **Bar baseline measurements**. `audits/evidence/release work-baseline/{bar1,bar2,bar3}-state.json` will record baselines so progress is observable against a fixed reference.
6. **TRJ4-033 confirmation** (small). If TRJ4-033 has not merged by Wave 1 of release work execution, the mobile-attestation rows (threat evidence item / A2.9 / A2.13) fail closed and ramp later. Per `W3-lane-a-fixes.md` unresolved item 2.

None of items 1-6 is a Wave-2 BLOCKER -- all Wave 2 BLOCKERs are CLOSED per the closeout matrix. Items 1-6 are pre-execution scaffolding.

## Recommended kickoff date

**READY-WITH-ASSIGNMENTS**: release work is ready to enter execution as soon as owner-class assignments land and the four scaffolding items above (preflight script, releases.toml block, baseline measurements, Wave-2 reviewer ledger) are completed. No new content review or planning work is required. Wave 4 closure leaves zero open BLOCKERs and zero open MAJORs requiring further design.

If owner-class assignments are decided synchronously with the kickoff conversation, release work can enter execution within one business day of those assignments.

## Pointers to all key docs

### Master / contract
- Synthesis (immutable contract + Wave-4 SUPERSEDED-NOTE): `debate/00-SYNTHESIS.md`
- Six debate position papers: `debate/01..06.md`
- Ship-bar tracker: `SHIP-BAR-TRACKER.md`
- Execution board: `EXECUTION-BOARD.md`
- Scope lock: `SCOPE-LOCK.md`
- Timeline: `TIMELINE.md`
- Owners: `OWNERS.toml`
- Kickoff checklist: `KICKOFF-CHECKLIST.md`

### Architecture
- Async-kernel migration plan: `architecture/ASYNC-KERNEL-MIGRATION.md`
- Spec-to-runtime map: `architecture/SPEC-TO-RUNTIME-MAP.md`
- Risk register (R1-R7): `architecture/RISK-REGISTER.md`

### Templates
- Evidence Gate: `templates/EVIDENCE-GATE.md`
- Conformance fixture pattern: `templates/CONFORMANCE-FIXTURE-PATTERN.md`
- Ticket template: `templates/TICKET-TEMPLATE.md`

### Lane A (floor)
- README, PLAN, tickets, mutation budget, threat-evidence backfill, Kani harness design, TLA+ rewrites, Lean4 fix: `lane-a-floor/`

### Lane B (wiring; four primitives)
- README, PLAN, tickets, async-trait migration, single-entry verifier, receipt-v2 fail-closed, anchor-batch async-only, **DSSE bilateral signing (B4 added W3)**, conformance-fixture spec: `lane-b-wiring/`

### Lane C (forcing demo)
- README, PLAN, tickets, architecture, bilateral-cosign flow, KB MCP integration, selective disclosure, release bar: `lane-c-demo/`

### Reviews
- reviews: `reviews/R1-cross-lane.md`, `reviews/R2-lane-a-depth.md`, `reviews/R3-lane-b-compliance.md`, `reviews/R4-lane-c-feasibility.md`
- Wave 3 fix logs: `reviews/W3-lane-{a,b,c}-fixes.md`
- Wave 4 closeout matrix: `reviews/W4-closeout-matrix.md`

### Closeout (per-wave summaries; populated during execution)
- `closeout/README.md` (stub; matches trj4 pattern)
- `closeout/wave-NN-summary.md` (filled in during execution)
