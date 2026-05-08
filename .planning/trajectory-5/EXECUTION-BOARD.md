# Trajectory-5 Execution Board

**Status**: ticket scaffolding for the synthesis-locked plan in `debate/00-SYNTHESIS.md`. Per-lane ticket details land in `lane-{a-floor,b-wiring,c-demo}/tickets.md` (Wave 1 lane agents). Owner-classes per `OWNERS.toml`; humans TBD until kickoff.

**Tagline**: trj5 is the **honesty trajectory**. Three coupled lanes, no separate brand from the trj4 wave plan, one ship-bar visible from outside.

## Lanes

| Lane | Slug | Owner-class | Approx duration | Ticket prefix |
|---|---|---|---|---|
| **A** | `lane-a-floor` | substrate / formal-methods / threat-modeling | weeks 1-8 (parallelizable) | `TRJ5-A*` |
| **B** | `lane-b-wiring` | protocol / kernel | weeks 1-7 (B0 weeks 1-2; B1-B3 weeks 3-6; B4 weeks 5-6 DSSE signing) | `TRJ5-B*` |
| **C** | `lane-c-demo` | federation / examples / cli | weeks 5-8 | `TRJ5-C*` |

Total ticket count: TBD (sum of `lane-*/tickets.md` line items). Estimated 25-40 tickets across the three lanes.

## Evidence Gate (mandatory)

Every Lane B and Lane C primitive ticket closes with the three Evidence Gate artifacts (template at `templates/EVIDENCE-GATE.md`):

1. **Enforced call site** -- the production hot path executes the new code; sync helpers and bypass paths deleted or migrated.
2. **Spec MUST citation** -- `spec/PROTOCOL.md` section updated; relevant `spec/schemas/*.json` updated; claim registry, proof manifest, theorem inventory rows promoted.
3. **Signed negative conformance test** -- under `crates/chio-conformance/tests/`. Exercises the production call path. Fails when the enforcement is removed (the test must demonstrate the failure mode by inverting the patch under review).

No Evidence Gate row closes without all three. Lane A tickets follow the same discipline applied to mutation-survivor sweeps, threat-coverage rows, Kani harnesses, TLA+ rewrites, and the Lean refinement.

## Lane A: Realize the floor

Absorbs trj4 Wave 0 / Wave 1 / Wave 4 with real evidence requirements. Per `debate/00-SYNTHESIS.md` Lane A.

| Ticket | Title | Owner-class | Effort | Depends on | Trj4 wave-plan absorption |
|---|---|---|---|---|---|
| TRJ5-A1 | Mutation-kill: 31% -> >=65% trust-boundary crates; >=80% on `chio-attest-verify`. README banner reflects observed kill rate, not target. | substrate | L | TRJ5-A0 (preflight) | TRJ4-010, TRJ4-011 |
| TRJ5-A2 | All 20 `audits/evidence/threats/*.json` files contain real `caught >= 1` data with non-1970 `ran_at` (or "<n> of 20 covered, <m> deferred to trj6" per Risk Register R3 escalation). Replace placeholder fixture with the production call path executed under each threat row. Threat-coverage gate transitions from placeholder to 20/0/0 PASS with non-meta evidence. (Synthesis says "21"; on-disk count is 20. Lane A targets 20 as authoritative; see `lane-a-floor/README.md` "Authoritative threat count" footnote.) | threat-modeling | L | TRJ5-A1 | TRJ4-040..049 |
| TRJ5-A3 | Kani harnesses for `chio-attest-verify`, `chio-anchor`, `chio-weights`. Modeled on `chio-kernel-core::kani_public_harnesses.rs`. Each crate gains real `kani::` references. | formal-methods | M | none | TRJ4-012, TRJ4-013, TRJ4-014 |
| TRJ5-A4 | TLA+ rewrites: `ReceiptBeforeAllow` split (`Allow` -> `LogReceipt` + `PublishAllow`); `RevocationCutCompleteness` bounded transitive-closure unrolling; `EpochMax` 4 -> 6; apalache-temporal lane promoted from advisory to required. | formal-methods | L | TRJ5-A3 | TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018 |
| TRJ5-A5 | Lean4 `negotiation_safety` re-proved against the executable model (not by `rfl` against its own definition). `formal/theorem-inventory.json` row promoted from `proposed`/`assumed` to `proven` with file path. (Renumbered from `TRJ5-A6` per Wave 3 review; the prior `TRJ5-A5` slot for proptest hosted-vs-portable equivalence (TRJ4-019) is deferred to trj6, see `SCOPE-LOCK.md` "Deferred to trj6 with rationale".) | formal-methods | M | TRJ5-A4 | (synthesis Quality #3) |
| TRJ5-A7 | README mutation banner update: replace target-language banner with observed-kill-rate banner; per-crate breakdown table attached; evidence directory under `audits/evidence/mutation/` populated with non-placeholder per-crate run records. | substrate | S | TRJ5-A1 | (Bar 1 evidence) |
| TRJ5-A* | (additional rows per `lane-a-floor/tickets.md`; lane agent owns the full enumeration) | substrate | TBD | TBD | TBD |

Detail rows beyond `TRJ5-A1..A5, A7` (TRJ5-A6 is now `TRJ5-A5`) land
in `lane-a-floor/tickets.md`. Each sub-lane carries an Evidence Gate
ticket with the canonical `.E` suffix per `templates/TICKET-TEMPLATE.md`
section 1.1: `TRJ5-A1.E`, `TRJ5-A2.E`, `TRJ5-A3.E`, `TRJ5-A4.E`,
`TRJ5-A5.E`.

## Lane B: Wire the spec hot path

Adopts Protocol Realization Engineer R1-R3 plus the architectural prerequisite. Per `debate/00-SYNTHESIS.md` Lane B.

| Ticket | Title | Owner-class | Effort | Depends on | Trj4 wave-plan absorption |
|---|---|---|---|---|---|
| TRJ5-B0 | **Architectural prerequisite**: convert `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254-306` to `async_trait`; collapse the dispatch sync-helper hop in `chio-kernel/src/kernel/mod.rs:6402-6442`. Smallest decomposition cut that unblocks hot-path wiring; chio-cli trust-control extraction and gravity-well surgery stay out of trj5. | kernel | L | none | (decomposition advocate prerequisite) |
| TRJ5-B1 | **Single-entry verifier**: `verify_capability_full` becomes the only production path. Delete `verify_capability_full_without_budget_admit` (currently callable from `crates/chio-kernel/src/kernel/mod.rs:4035-4058`); legacy `verify_capability_signature` callers (currently at `:4005-4033`) migrate. PROTOCOL.md sections 408-418 SHOULD -> MUST. Closes with signed negative conformance test that fails when bypass call sites are reintroduced. | protocol | L | TRJ5-B0 | TRJ4-100..104 + T1.0.E |
| TRJ5-B2 | **Receipt v2 fail-closed under negotiated v2**: replace warn-and-downgrade in `kernel_receipt_version_for_remote` at `chio-kernel/src/kernel/mod.rs:1574-1591` with a hard reject when negotiation indicated `chio.capability.v2`. PROTOCOL.md section 6 lines 714-741 are rewritten to introduce a NEW normative MUST (current prose is descriptive: "the kernel falls back"; B2 makes this a tightening, not a SHOULD->MUST promotion). Signed negative conformance test asserts the hard-reject path. (Note: synthesis line 31 cited `:1148-1165` which is the `KernelReceiptVersion::from_capabilities` resolver helper; the runtime downgrade is at `:1574-1591`.) | protocol | M | TRJ5-B0 | TRJ4-120..131 + T1.2.E |
| TRJ5-B3 | **Anchor-batch async-only when public witness required**: gate `crates/chio-anchor/src/batch.rs:227-235` sync wrapper at runtime when `require_public_witness=true`. Add `scripts/check-anchor-batch-async-witness.sh` as best-effort fast-feedback documentation (NOT a soundness guarantee; the runtime gate is the load-bearing defense). Signed negative conformance test under `chio-conformance` exercises the gate. PROTOCOL.md section 982-991 enforced. | protocol | M | TRJ5-B0 | TRJ4-140..147 + T1.3.E |
| TRJ5-B4 | **DSSE-conformant bilateral signing**: per R4 BLOCKER 1, the existing `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) is signed over canonical-JSON bytes that share zero bytes with the spec §6 DSSE PAE preimage. B4 introduces Ed25519-over-DSSE-PAE-of-in-toto-Statement signing as the production §6-conformant artifact; legacy `DualSignedReceipt::verify` is either wrapped or coexists with explicit non-§6 disclaimer. Spec citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 (PAE) and §7 step 11-12 (signature verification). Signed negative conformance test asserts the DSSE envelope is the conformant artifact. | protocol | L | TRJ5-B0, TRJ5-B1 | R4 BLOCKER 1 promotion |
| TRJ5-B1.E, TRJ5-B2.E, TRJ5-B3.E, TRJ5-B4.E | **Lane B Evidence Gate (per primitive)**: each primitive's audit-doc evidence block flips from EVIDENCE-PENDING to EVIDENCE-COMPLETE when the four Evidence Gate artifacts are present (enforced call site, spec MUST citation, negative conformance fixture, production-call-path exercise). PROTOCOL.md sections updated; schemas under `spec/schemas/` updated; claim registry, proof manifest, theorem inventory rows landed; the four signed negative conformance fixtures committed under `crates/chio-conformance/tests/`. The previous `TRJ5-B-EG` aggregator is replaced by these four per-primitive Evidence Gate tickets per the canonical `.E` suffix convention (`templates/TICKET-TEMPLATE.md` §38). | protocol | M | TRJ5-B1, TRJ5-B2, TRJ5-B3, TRJ5-B4 | (Bar 2 closing artifact) |
| TRJ5-B* | (additional supporting rows per `lane-b-wiring/tickets.md`) | protocol | TBD | TBD | TBD |

Detail rows land in `lane-b-wiring/tickets.md`.

## Lane C: One forcing demo

Adopts the Vision Strategist's chiodome slice and the Productization Champion's KB-MCP dogfood. Per `debate/00-SYNTHESIS.md` Lane C.

| Ticket | Title | Owner-class | Effort | Depends on | Trj4 wave-plan absorption |
|---|---|---|---|---|---|
| TRJ5-C1 | **Two-kernel cross-org bilateral cosigned invocation** using existing `crates/chio-federation/src/bilateral.rs` (`CoSigningBody`, `DualSignedReceipt`). Per `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6. | federation | L | TRJ5-B1, TRJ5-B2, TRJ5-B3 | (synthesis Lane C) |
| TRJ5-C2 | **Capability lease + budget bond** via `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA`. Bond minted at lease issuance; consumed at receipt-write. | federation | M | TRJ5-C1 | (synthesis Lane C) |
| TRJ5-C3 | **Anchored** through `crates/chio-anchor::Web3CheckpointStatement`. No new Web3 live deployment required (bounded claim per v3.18 discipline). | federation | M | TRJ5-C1, TRJ5-B3 | (synthesis Lane C) |
| TRJ5-C4 | **Selective-disclosure auditor view** behind `zk` Cargo feature flag. No new spec ratification. Per `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` section 6. | federation | M | TRJ5-C1 | (synthesis Lane C) |
| TRJ5-C5 | **Wrapped at the user surface** by `chio mcp serve --policy` against the local KB MCP stack at `ops/knowledge-base/`. Receipts produced by the bilateral invocation are dogfooded through `chio receipt explain`. | cli | M | TRJ5-C1 | (synthesis Lane C) |
| TRJ5-C6 | `examples/chiodome-bilateral/` end-to-end fixture: demo run captured, two-kernel transcripts committed, `chio receipt explain` output recorded as golden file. Honest release tag `v0.1.0-bounded-chiodome` cut under v3.18 bounded-claim discipline. | examples | L | TRJ5-C1, TRJ5-C2, TRJ5-C3, TRJ5-C4, TRJ5-C5 | (Bar 3 closing artifact) |
| TRJ5-C* | (additional supporting rows per `lane-c-demo/tickets.md`) | federation/cli/examples | TBD | TBD | TBD |

Detail rows land in `lane-c-demo/tickets.md`.

## Cross-lane dependency table

| Source | Sink | Dependency type | Why |
|---|---|---|---|
| (none) | TRJ5-A* | independent | Lane A is parallelizable from week 1; Wave 0 preflight only. |
| TRJ5-B0 | TRJ5-B1 | hard | Single-entry verifier needs `async_trait` on `ToolServerConnection` to wire without sync-hop bouncing. |
| TRJ5-B0 | TRJ5-B2 | hard | Receipt v2 hard-reject path runs through the dispatch hot path. |
| TRJ5-B0 | TRJ5-B3 | hard | Anchor-batch async gate is in the same dispatch surface. |
| TRJ5-B0 | TRJ5-B4 | hard | DSSE bilateral signing wires through federation hot path; needs async dispatch. |
| TRJ5-B1 | TRJ5-B4 | soft | DSSE signing reuses single-entry verifier discipline for capability proofs; B1 is preferred-but-not-required for B4 to start. |
| TRJ5-B1 | TRJ5-C1 | hard | Bilateral demo requires single-entry verifier as the production path; demonstrating the demo over a bypass call would invalidate Bar 2. |
| TRJ5-B2 | TRJ5-C1 | hard | Bilateral receipts must mint as v2 under negotiated v2; the warn-and-downgrade path would silently weaken the demo. |
| TRJ5-B3 | TRJ5-C3 | hard | Anchored demo emits a checkpoint that requires the public-witness async gate. |
| TRJ5-B4 | TRJ5-C2 | hard | Lane C bilateral DSSE adapter consumes B4's PAE-conformant signing surface. C2 cannot start producing §6-conformant envelopes until B4 lands. |
| TRJ5-A2 | (Bar 1) | hard | Threat-coverage evidence directory is Bar 1's non-placeholder requirement. |
| TRJ5-A1, TRJ5-A7 | (Bar 1) | hard | Mutation banner shows observed kill rate; per-crate evidence under `audits/evidence/mutation/`. |
| TRJ5-B1.E, TRJ5-B2.E, TRJ5-B3.E, TRJ5-B4.E | (Bar 2) | hard | Four signed negative conformance fixtures are the externally-checkable artifact. |
| TRJ5-C6 | (Bar 3) | hard | `examples/chiodome-bilateral/` fixture + `chio receipt explain` golden file is the externally-checkable artifact. |

There is no Lane A -> Lane B or Lane A -> Lane C dependency. Lane A and Lane B run in parallel from week 1. Lane C unlocks at the end of week 4 once TRJ5-B1, TRJ5-B2, TRJ5-B3 land.

## Critical path

```
Week 1 -> 2: TRJ5-B0 (architectural prerequisite). Lane A ramp.
Week 3 -> 4: TRJ5-B1, TRJ5-B2, TRJ5-B3 land in parallel under TRJ5-B0.
Week 5 -> 6: TRJ5-B4 (DSSE bilateral signing) lands; C1/C2 scaffolding starts in parallel; per-primitive Evidence Gate tickets close.
Week 6 -> 7: Lane C consumes B4. TRJ5-C2..C5 (lease/bond, anchor, ZK, MCP) land.
Week 7 -> 8: TRJ5-C6 (example fixture + golden file).
Week 8: integration / ship-bar week. Bar 1 / Bar 2 / Bar 3 verified.
```

See `TIMELINE.md` for the Gantt-style view.

## Closing-criteria block (the three observable bars)

Trj5 closes when **all three** are observably true. This block is the anchoring refrain across `README.md`, `SHIP-BAR-TRACKER.md`, and `KICKOFF-CHECKLIST.md`.

1. **Bar 1 (Lane A)**. README mutation banner reads `>=65%` with the per-crate breakdown attached and a non-placeholder evidence directory.
2. **Bar 2 (Lane B)**. The four Lane B primitives (capability v2, receipt v2, anchor-batch async, DSSE-conformant bilateral signing) are each protected by a signed negative conformance fixture in `crates/chio-conformance/tests/` that exercises the production call site and fails when the enforcement is removed.
3. **Bar 3 (Lane C)**. The Lane C bilateral demo runs end-to-end, the receipts are inspectable with `chio receipt explain`, and the demo run is captured as a fixture in `examples/`.

If any of the three slips, trj5 stays open. No closeout erratum is needed because the bar is the kind a third party can verify.

## Trj4 wave-plan absorption summary

| trj4 wave-plan ticket(s) | Absorbed by |
|---|---|
| TRJ4-010, TRJ4-011 | TRJ5-A1, TRJ5-A7 |
| TRJ4-012, TRJ4-013, TRJ4-014 | TRJ5-A3 |
| TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018 | TRJ5-A4 |
| TRJ4-019 | (deferred to trj6 per Wave 3 review; see `SCOPE-LOCK.md` "Deferred to trj6 with rationale" subsection) |
| TRJ4-040..049 | TRJ5-A2 |
| TRJ4-100..104 + T1.0.E | TRJ5-B1 |
| TRJ4-120..131 + T1.2.E | TRJ5-B2 |
| TRJ4-140..147 + T1.3.E | TRJ5-B3 |

Note: the trj4 close-bar tracker at `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md` continues to grade Lane A and Lane B work. Trj5's closing signal is the three observable bars above plus per-lane PLAN.md sign-off; the trj4 tracker rows transition `PARTIAL` -> `DONE` as Lane A / B tickets land, but trj5 itself does not duplicate the row ledger.

## Status conventions

Each ticket starts in `pending`; transitions to `in_progress` on PR open, `review` on PR ready-for-review, `merged` on PR merge to main, `closed` on its parent lane PLAN.md signoff. Evidence Gate per-primitive tickets (`TRJ5-B1.E`, `TRJ5-B2.E`, `TRJ5-B3.E`, `TRJ5-B4.E`, `TRJ5-C1.E`, `TRJ5-C2.E`, `TRJ5-C3.E`, `TRJ5-C4.E`, `TRJ5-C5.E`, `TRJ5-C6.E`) are gating: their parent lane cannot be `closed` until each per-primitive Evidence Gate ticket is `merged` AND the Wave-2 reviewer has signed off under `reviews/`. The canonical suffix is `.E` per `templates/TICKET-TEMPLATE.md` §38; the previous shorthand `TRJ5-B-EG` and `TRJ5-B.CLOSE` are retired.
