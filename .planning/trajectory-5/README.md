# Trajectory-5 Planning

**Status**: R4 topology corrected. PR #620 is the sole planning-truth owner for `.planning/trajectory-5/**`; release integration remains blocked until Lane B enforcement is merged from a clean source branch and #608/#616 threat topology is collapsed by the threat owner. See `R4-MERGE-TOPOLOGY.md`.

**Tagline**: release work is the **honesty trajectory**. It absorbs trj4 wave plan items and adds one forcing demo. There is no separate brand and no scope-widening.

## What release work is

Trj5 is three coupled lanes that close one ship-bar visible from outside the project. The shape comes from the six-position synthesis at `debate/00-SYNTHESIS.md`, which observed that trj4's "structural framing without runtime wiring" pattern (per `../trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md`) is the steady-state symptom of a substrate shipping faster than it is being proven.

Trj5 closes that gap by:

1. **Realizing the floor** -- mutation kill, threat-coverage evidence, Kani harnesses, TLA+ rewrites, Lean refinement (Lane A).
2. **Wiring the spec hot path** -- single-entry verifier, receipt v2 fail-closed, anchor-batch async-only when public witness required, and DSSE-conformant bilateral signing (Lane B; B4 added W3 per R4 BLOCKER 1).
3. **Forcing one demo** -- two-kernel cross-org bilateral cosigned invocation with capability lease + budget bond, anchored, dogfooded through `chio receipt explain` (Lane C).

If any of the three lanes fails to close, release work stays open. The bar is the kind a third party can verify.

## R4 topology update

The R4 audit invalidated the previous merge train. Do not run the old
planning-led sequence and do not tag `v0.1.0-bounded-chiodome` from the
current PR set.

The replacement plan is:

1. Keep #620 as the only `.planning/trajectory-5/**` owner.
2. Start release-source integration with Lane B enforcement from a clean branch.
3. Merge Lane A evidence only after branch ownership is clean.
4. Treat Lane C as canary/demo until Lane B is real and evidence is rerun.
5. Regenerate #618 release packaging from merged `main` last.

The current simulation log and exact remaining threat conflicts are recorded in
`R4-MERGE-TOPOLOGY.md`.

## Doc layout

| File | Purpose |
|---|---|
| `README.md` | This file. Trajectory overview and the three observable ship-bar items. |
| `R4-MERGE-TOPOLOGY.md` | R4 replacement merge strategy, planning ownership record, and local merge simulation log. |
| `EXECUTION-BOARD.md` | Master ticket board organized by lane and week. Cross-lane dependency table. Evidence Gate template reference. |
| `SHIP-BAR-TRACKER.md` | Per-bar state ledger: current state, target state, evidence required, machine-readable signal, validator. |
| `OWNERS.toml` | Per-lane owner-class manifest. Owner-classes (not human assignments) until Wave 2. |
| `SCOPE-LOCK.md` | IN-SCOPE / OUT-OF-SCOPE catalog. Lifts the synthesis out-of-scope list verbatim and elaborates target trajectory + WHY each item is deferred. |
| `TIMELINE.md` | Gantt-style ASCII timeline. Lane A weeks 1-8, Lane B weeks 1-6, Lane C weeks 5-8. Critical path marked. |
| `KICKOFF-CHECKLIST.md` | Pre-execution checklist. CI pre-flight, releases.toml block, trj4 wave-plan absorption note, owner-class assignment. |
| `debate/00-SYNTHESIS.md` | The contract. Six debate papers reconciled. The three ship-bar items live here in normative form. |
| `debate/01..06` | Independent debate position papers. |
| `lane-a-floor/PLAN.md` | Lane A plan. Substrate hardening realization. Owned by Wave 1 Lane A agent. |
| `lane-a-floor/planning docs` | Lane A ticket list (mutation evidence item?). |
| `lane-b-wiring/PLAN.md` | Lane B plan. Spec hot-path wiring + architectural prerequisite. Owned by Wave 1 Lane B agent. |
| `lane-b-wiring/planning docs` | Lane B ticket list (release work-B0..B?). |
| `lane-c-demo/PLAN.md` | Lane C plan. Bilateral demo + bounded chiodome v0.1.0. Owned by Wave 1 Lane C agent. |
| `lane-c-demo/planning docs` | Lane C ticket list (release work-C1..C?). |
| `templates/EVIDENCE-GATE.md` | Evidence Gate template (PROTOCOL.md + schemas + claim/proof/theorem registries + signed negative conformance). Reused from trj4. |
| `reviews/` | Wave-2 reviewer output (lands when Wave 2 runs). |

## Reading order

For a fast scan: `debate/00-SYNTHESIS.md`, then this README, then `EXECUTION-BOARD.md`.

For deep context: read the synthesis, then `SCOPE-LOCK.md`, then the per-lane PLAN.md for the slice you are working on, then `SHIP-BAR-TRACKER.md` for the current state of the bar your slice contributes to.

For implementers picking up a ticket: open the relevant `lane-{a-floor,b-wiring,c-demo}/PLAN.md` first; it lists the close bar for the ticket plus the Evidence Gate items.

## Status

R4 topology-corrected planning. Historical Wave 0 through Wave 4 planning
records remain in this directory, but current release truth is governed by
`R4-MERGE-TOPOLOGY.md`, not by older closeout prose. The release package is not
ready for tag.

`releases.toml` `[trajectory_5]` is `pending_upstream_merges` after R4+ release-truth reconciliation. It cannot be tagged until upstream PRs merge, release packaging is regenerated from merged `main`, checks are green on the integrated merge SHA, and a human pushes the tag.

## Lanes

| Lane | Slug | Owner-class | Approx duration | Depends on |
|---|---|---|---|---|
| **A** | `lane-a-floor` | substrate / formal-methods / threat-modeling | weeks 1-8 (parallelizable) | none (independent) |
| **B** | `lane-b-wiring` | protocol / kernel | weeks 1-7 (B0 weeks 1-2 architectural prerequisite, B1-B3 weeks 3-6, B4 weeks 5-6 DSSE signing) | B0 gates B1/B2/B3/B4 |
| **C** | `lane-c-demo` | federation / examples / cli | weeks 5-8 | B1 + B2 + B3 landed by week 5 |

Lane A and Lane B run in parallel from week 1. Lane C unlocks when the three Lane B primitives land. The integration / ship-bar week is week 8.

See `EXECUTION-BOARD.md` for the cross-lane dependency table.

## Ship bar (visible from outside)

Trj5 closes when **all three** are observably true. This block is the anchoring refrain across `EXECUTION-BOARD.md`, `SHIP-BAR-TRACKER.md`, and `KICKOFF-CHECKLIST.md`.

1. **Bar 1 (Lane A)**. README mutation banner reads `>=65%` with the per-crate breakdown attached and a non-placeholder evidence directory. Trust-boundary crates >= 65% per crate; `chio-attest-verify` >= 80%. README banner reflects observed kill rate, not target. All 20 `audits/evidence/threats/*.json` files contain real `caught >= 1` data with non-1970 `ran_at` (or "<n> of 20 covered, <m> deferred to trj6" if Wave 1 triage flips one or more rows to `BLOCKED-BY-ARCHITECTURE` per Risk Register R3). The placeholder PASS banner is replaced with production-call-path evidence. (Note: synthesis says "21" threat-evidence files; on-disk count is 20, one per row in `spec/security/chio-threat-model.v1.json`. Lane A targets the on-disk count of 20 as authoritative; see `lane-a-floor/README.md` "Authoritative threat count" footnote.)

2. **Bar 2 (Lane B)**. The four Lane B primitives are each protected by a signed negative conformance fixture under `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed:
   - **capability v2** -- `verify_capability_full` is the only production path; `verify_capability_full_without_budget_admit` is deleted; legacy `verify_capability_signature` callers migrated. PROTOCOL.md changes SHOULD -> MUST.
   - **receipt v2** -- the warn-and-downgrade in `kernel_receipt_version_for_remote` at `chio-kernel/src/kernel/mod.rs:1574-1591` is replaced with hard reject when negotiation indicated `chio.capability.v2`. PROTOCOL.md introduces a new MUST (lines 737-741 currently descriptive). (Note: synthesis line 31 cited `:1148-1165` which is the `KernelReceiptVersion::from_capabilities` resolver helper; the runtime downgrade is at `:1574-1591`.)
   - **anchor-batch async** -- `crates/chio-anchor/src/batch.rs:208-258` sync path is gated when `require_public_witness=true`. The runtime gate at `batch.rs:227-235` is the load-bearing defense; `scripts/check-anchor-batch-async-witness.sh` is best-effort fast-feedback documentation.
   - **DSSE-conformant bilateral signing (B4)** -- new sub-lane added per R4 BLOCKER 1. `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share zero bytes with the §6 DSSE PAE preimage. B4 wires DSSE PAE-over-in-toto-Statement Ed25519 signing as the production §6-conformant artifact; the legacy `DualSignedReceipt` either gets wrapped or coexists with explicit non-conformance discipline.

3. **Bar 3 (Lane C)**. The bounded bilateral demo runs end-to-end after the Lane C PRs merge, the receipt is inspectable with `chio receipt explain`, and the demo run is captured as pinned `receipt.json`, `envelope.json`, and `checkpoint.json` fixtures under `examples/chiodome-bilateral/fixtures/v0.1.0-bounded-chiodome/`. Uses existing Chio receipt/checkpoint substrates, the `chio-federation` `bbs-stub` placeholder for C5 (PARTIAL, not real BBS+), and a KB MCP wrapper whose default mode emits mediation transcripts rather than kernel-signed Chio receipts. The `v0.1.0-bounded-chiodome` tag is human-pushed only after upstream merges, regeneration, and green integrated checks.

If any of the three slips, release work stays open. No closeout erratum is needed because the bar is the kind a third party can verify.

## Out of scope (explicit)

Lifted verbatim from `debate/00-SYNTHESIS.md`. See `SCOPE-LOCK.md` for the elaboration (target trajectory + WHY each is deferred).

- `chio-cli` trust-control extraction (`crates/chio-cli/src/trust_control/`, ~18K LOC). Real, but pure refactor without a forcing function. Push to trj6.
- Gravity-well surgery on `chio-core` / `chio-kernel`. Same reason.
- Reqwest 0.12/0.13 unification, serde_yaml retirement. Push to trj6 unless a Lane A/B blocker.
- New chiodos primitives beyond what Lane C consumes; no new normative drafts.
- `v2.71` Web3 live activation (gated on external credentials).
- Mobile attestation production-hardening beyond Wave 6 of trj4 wave plan.
- New milestone scope of any kind.

## Trj4 wave-plan absorption

Trj5 is **not a separate brand from the trj4 wave plan**. It absorbs trj4 wave items and adds Lane C. The mapping is normative; see `KICKOFF-CHECKLIST.md` for the per-ticket absorption note.

| trj4 wave-plan item | release work lane |
|---|---|
| TRJ4-010, TRJ4-011 (mutation-kill 65% / 80%) | Lane A (release work-A1) |
| TRJ4-012, TRJ4-013, TRJ4-014 (Kani `chio-attest-verify`, `chio-anchor`, `chio-weights`) | Lane A (release work-A3) |
| TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018 (TLA+ rewrites; apalache-temporal promotion) | Lane A (release work-A4) |
| TRJ4-019 (proptest hosted-vs-portable equivalence) | Lane A (release work-A5) |
| TRJ4-040..049 (threat coverage closure; 20 evidence rows on disk) | Lane A (release work-A2) |
| TRJ4-100..104 + T1.0.E (capability negotiation hot path) | Lane B (release work-B1) |
| TRJ4-120..131 + T1.2.E (receipt v2 fail-closed under negotiated v2) | Lane B (release work-B2) |
| TRJ4-140..147 + T1.3.E (anchor-batch async-only when witness required) | Lane B (release work-B3) |
| Architectural prerequisite (`async_trait` on `ToolServerConnection` at `crates/chio-kernel/src/runtime.rs:254-306`; collapse dispatch sync hop) | Lane B (release work-B0) |
| DSSE-conformant bilateral signing (Ed25519 over DSSE PAE of in-toto Statement per `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6) | Lane B (release work-B4, new sub-lane per R4 BLOCKER 1) |
| `chio-federation::bilateral` two-kernel demo | Lane C (release work-C1) |
| `chio-credit` CREDIT_BOND_ARTIFACT_SCHEMA capability-lease + budget-bond | Lane C (release work-C2) |
| `chio-anchor::Web3CheckpointStatement` (no live deployment) | Lane C (release work-C3) |
| selective-disclosure placeholder behind `chio-federation` `bbs-stub` Cargo feature | Lane C (release work-C4) |
| `chio mcp serve --policy` over local KB MCP stack | Lane C (release work-C5) |
| `v0.1.0-bounded-chiodome` honest release tag | Lane C (release work-C6) |

The trj4 wave plan close-bar tracker at `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md` continues to grade the Lane A and Lane B work; release work does not duplicate that ledger. Trj5's closing signal is the three observable bars above plus the lane PLAN.md close.

## Why this shape

Per `debate/00-SYNTHESIS.md`:

- **It honors the Hawk and the Quality Skeptic**: the floor work is the primary lane, and it does not paper over placeholder evidence.
- **It honors the Protocol Realization Engineer**: hot-path wiring runs in parallel and uses the same Evidence Gate discipline.
- **It honors the Decomposition Advocate without taking the whole bait**: the smallest architectural cut that unblocks Lane B is in scope; the rest waits for trj6.
- **It honors the Productization Champion and Vision Strategist**: the forcing demo is the customer Chio does not have, and it forces the substrate to actually compose end-to-end. If Lane C breaks, Lanes A and B are not real either.
- **It rejects** seven-lane menus, parallel new milestones, and any framing that lets trj4's pattern repeat.

The honest framing for project memory and `RELEASE_AUDIT.md`: Chio's differentiator is the proof artifact. Until the proof artifact is real, every trajectory after trj4 is the same trajectory wearing a different name.

## Kickoff prerequisites

Before release work enters execution, the following must hold (full ledger in `KICKOFF-CHECKLIST.md`):

- All three lane `PLAN.md` files reviewed and Wave-2-approved under `reviews/`.
- `OWNERS.toml` owner-classes assigned to actual humans.
- CI pre-flight script `scripts/trj5-preflight.sh` returns exit 0.
- `releases.toml` `[trajectory_5]` block opened and now corrected to `trj5_release_status = "pending_upstream_merges"` until upstream merges, regeneration, green integrated checks, and human tag push.
- Trj4 wave-plan absorption note checked into `KICKOFF-CHECKLIST.md` confirming which trj4 tickets are subsumed.
- The three ship-bar items above are restated verbatim in `SHIP-BAR-TRACKER.md` and have machine-readable signals defined.

## Pointers

- Synthesis (the contract): `debate/00-SYNTHESIS.md`
- Trj4 erratum (the precedent we are closing): `../trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md`
- Trj4 close-bar tracker (graded ledger we inherit): `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md`
- PROTOCOL.md spec lines under negotiation: `spec/PROTOCOL.md` (sections 6, 408-418, 714-741, 982-991)
- Trj4 README pattern: `../trajectory-4/README.md`
- Project state: `.planning/STATE.md`
- Project vision: `.planning/PROJECT.md`
- Release audit: `RELEASE_AUDIT.md`
- Releases manifest: `releases.toml`

## Conventions

- Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, etc.).
- No em dashes (per repository CLAUDE.md). Use hyphens or parentheses.
- Evidence-first language. No "we will deliver" prose; use the trj4 erratum's evidentiary tone.
- Every Evidence Gate row closes with three artifacts: enforced call site + spec MUST citation + signed negative conformance test that fails when wiring is removed.
- Ticket-status conventions match trj4: `pending` -> `in_progress` (PR open) -> `review` (PR ready-for-review) -> `merged` -> `closed` (audit-doc signoff).
