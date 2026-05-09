# Trj5 Scope Lock

RW5 correction: scope is ordered Lane B integration first, Lane A assurance
regenerated from merged Lane B source second, Lane C canary after Lane B, and
#618 packaging last. This file does not define a product release, release
readiness state, or tag authorization.

This file is the IN-SCOPE / OUT-OF-SCOPE catalog for integration and assurance
work. The OUT-OF-SCOPE list is lifted verbatim from `debate/00-SYNTHESIS.md` and
elaborated with target trajectory and WHY each item is deferred. The IN-SCOPE
catalog maps to per-lane tickets, but future work listed here is non-blocking
for current Trajectory 5 closure.

**Tagline**: Trajectory 5 is the **honesty trajectory**. It absorbs trj4 wave
plan items and adds Lane C as an integration canary. It does not widen scope and
does not declare release readiness.

## In-scope

The in-scope catalog is normative in `debate/00-SYNTHESIS.md` and re-stated here for grep convenience. Each in-scope item is owned by a lane and tracked under that lane's planning docs.

### Lane A -- Realize the floor

| Item | Owner | Trj5 ticket(s) | Trj4 wave-plan absorbed |
|---|---|---|---|
| Mutation kill: 31% -> >=65% trust-boundary crates; >=80% on `chio-attest-verify`; README banner reflects observed kill rate, not target. | substrate | release work-A1, release work-A7 | TRJ4-010, TRJ4-011 |
| All 20 `audits/evidence/threats/*.json` files contain real `caught >= 1` data with non-1970 `ran_at`. Replace placeholder fixture with the production call path executed under each threat row. (Synthesis says "21"; on-disk count is 20, one per row in `spec/security/chio-threat-model.v1.json`. Lane A targets 20 as authoritative; see `lane-a-floor/README.md` "Authoritative threat count" footnote. If Wave 1 triage flips one or more rows to `BLOCKED-BY-ARCHITECTURE`, the close bar narrows accordingly.) | threat-modeling | release work-A2 | TRJ4-040..049 |
| Real Kani harnesses for `chio-attest-verify`, `chio-anchor`, `chio-weights`. | formal-methods | release work-A3 | TRJ4-012, TRJ4-013, TRJ4-014 |
| TLA+ rewrites: `ReceiptBeforeAllow` split, `RevocationCutCompleteness` bounded transitive-closure, apalache-temporal lane required, `EpochMax` 4 -> 6. | formal-methods | release work-A4 | TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018 |
| Lean4 `negotiation_safety` re-proved against the executable model, not by `rfl` against its own definition. (Lane A renumbered: this work is now `release work-A5`, not `release work-A6`. See `lane-a-floor/planning docs`.) | formal-methods | release work-A5 | (synthesis Quality #3) |

### Lane B -- Wire the spec hot path

| Item | Owner | Trj5 ticket(s) | Trj4 wave-plan absorbed |
|---|---|---|---|
| Architectural prerequisite: convert `ToolServerConnection` trait at `crates/chio-kernel/src/runtime.rs:254-306` to `async_trait`; collapse the dispatch sync-helper hop in `chio-kernel/src/kernel/mod.rs:6402-6442`. | kernel | release work-B0 | (decomposition advocate prerequisite) |
| Single-entry verifier: `verify_capability_full` becomes the only production path. Delete `verify_capability_full_without_budget_admit`; legacy `verify_capability_signature` callers migrate. PROTOCOL.md sections 408-418 SHOULD -> MUST. | protocol | release work-B1 | TRJ4-100..104 + T1.0.E |
| Receipt v2 fail-closed under negotiated v2: replace warn-and-downgrade in `kernel_receipt_version_for_remote` at `chio-kernel/src/kernel/mod.rs:1574-1591` with hard reject. PROTOCOL.md section 6 lines 737-741 are rewritten to introduce a NEW normative MUST (current prose "falls back" is descriptive; this is a tightening, not a SHOULD->MUST promotion). | protocol | release work-B2 | TRJ4-120..131 + T1.2.E |
| Anchor-batch async-only when public witness required: gate `crates/chio-anchor/src/batch.rs:227-235` sync wrapper at runtime (the load-bearing defense); add `scripts/check-anchor-batch-async-witness.sh` as best-effort fast-feedback documentation. | protocol | release work-B3 | TRJ4-140..147 + T1.3.E |
| **DSSE-conformant bilateral signing (B4 sub-lane added per R4 BLOCKER 1)**: introduce Ed25519-over-DSSE-PAE-of-in-toto-Statement signing as the production §6-conformant artifact. Adds new module `crates/chio-federation/src/bilateral_dsse.rs`. Existing `crates/chio-federation/src/bilateral.rs::DualSignedReceipt::verify` (line 108) is NOT replaced; it coexists with explicit non-§6 disclaimer (single-version transition or cohabitation, choice in `lane-b-wiring/dsse-bilateral-signing.md`). Spec citation: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 + §7 step 11-12. The R4 finding observed that the legacy `CoSigningBody` preimage (lines 41-77) shares zero bytes with the §6 DSSE PAE preimage; Lane C's prior "Option A two-signature" framing was insufficient. | protocol / federation | release work-B4 | (R4 BLOCKER 1 promotion) |

Each primitive closes with: enforced call site, spec MUST citation, and a
production-call-path conformance test that fails when wiring is removed. No
Evidence Gate row closes without all three.

### Lane C -- One forcing demo

| Item | Owner | Trj5 ticket(s) |
|---|---|---|
| Two-kernel cross-org bilateral cosigned invocation using existing `crates/chio-federation/src/bilateral.rs`. | federation | release work-C1 |
| Capability lease + budget bond via `chio-credit` `CREDIT_BOND_ARTIFACT_SCHEMA`. | federation | release work-C2 |
| Anchored through `crates/chio-anchor::Web3CheckpointStatement` (no new live deployment required). | federation | release work-C3 |
| Wrapped at the user surface by `chio mcp serve --policy` against the local KB MCP stack at `ops/knowledge-base/`. Receipts dogfooded through `chio receipt explain`. | cli | release work-C4 |
| `examples/chiodome-bilateral/` end-to-end canary fixture after Lane B integration; optional bounded package metadata under `[v0_1_0_bounded_chiodome]` only when the package owner regenerates from merged `main`. | examples | release work-C6 |

C5 selective disclosure is intentionally absent from the in-scope closure table.
It remains future work outside current trajectory closure.

## Out of scope (verbatim from synthesis, with elaboration)

The following items are **explicitly deferred**. Each entry lifts the synthesis line verbatim, then elaborates target trajectory and WHY the item is deferred.

### `chio-cli` trust-control extraction

> Verbatim (from `debate/00-SYNTHESIS.md`): "`chio-cli` trust-control extraction (`crates/chio-cli/src/trust_control/`, ~18K LOC). Real, but pure refactor without a forcing function. Push to trj6."

**Target trajectory**: trj6.

**WHY deferred**: ~18K LOC of pure refactor without a forcing function. The Decomposition Advocate (debate paper #3) made the cleanest case for refactor-first, but explicitly conceded that mounting a separate decomposition trajectory in parallel with an in-flight 16-wave closeout would double-fragment attention. Trj5 takes only the smallest decomposition cut needed to unblock Lane B (`async_trait` on `ToolServerConnection` at `crates/chio-kernel/src/runtime.rs:254-306`; sync-helper hop collapse; that is release work-B0). The full extraction waits.

### Gravity-well surgery on `chio-core` / `chio-kernel`

> Verbatim: "Gravity-well surgery on `chio-core` / `chio-kernel`. Same reason."

**Target trajectory**: trj6.

**WHY deferred**: Same reason as above -- pure refactor of large surfaces without a forcing function. The smallest cut that unblocks Lane B's hot-path wiring (release work-B0) is in scope; the rest of the gravity-well surgery (the 36 `&mut self` setters in the 6,757-LOC `mod.rs`, the umbrella re-export hygiene, etc.) waits for trj6.

### Reqwest 0.12/0.13 unification, serde_yaml retirement

> Verbatim: "Reqwest 0.12/0.13 unification, serde_yaml retirement. Push to trj6 unless a Lane A/B blocker."

**Target trajectory**: trj6 (conditional).

**WHY deferred**: dependency hygiene with no forcing function. Conditional caveat: if a Lane A or Lane B ticket discovers a hard blocker (a security advisory, a Lane B primitive that cannot ship without the unified reqwest, etc.), the orchestrator may pull the relevant slice into release work. Otherwise it ships in trj6.

### New chiodos primitives beyond what Lane C consumes

> Verbatim: "New chiodos primitives beyond what Lane C consumes; no new normative drafts."

**Target trajectory**: post-trj6.

**WHY deferred**: release work deliberately does not ratify new chiodos normative drafts. Lane C consumes existing drafts (`spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md`, `spec/CHIODOS_SELECTIVE_DISCLOSURE.md`) under their as-drafted shape. Adding new primitives during release work would re-create the trj4 pattern of structural framing without runtime wiring. New primitives wait until the existing ones have been forced through end-to-end.

### `v2.71` Web3 live activation

> Verbatim: "`v2.71` Web3 live activation (gated on external credentials)."

**Target trajectory**: on-hold (external dependency).

**WHY deferred**: gated on external credentials (Web3 RPC endpoint operator, signing key custody, network fees). Trj5 keeps Lane C's anchor lane bounded -- the demo runs through `crates/chio-anchor::Web3CheckpointStatement` against fixtures, not a live deployment. No Trajectory 5 release tag is authorized by this scope lock.

### C5 selective disclosure auditor view

**Target trajectory**: v0.2 or later protocol-owned work.

**WHY deferred**: the current branch does not carry the normative
`chio-zk-receipts` crate, default-off `zk` feature, BBS+/AnonCreds dependency
evidence, proof fixture, or negative fixture. C5 is not a release row and not a
closure row for Trajectory 5. The status TOML remains only for legacy checker
compatibility.

### Mobile attestation production-hardening beyond Wave 6 of trj4 wave plan

> Verbatim: "Mobile attestation production-hardening beyond Wave 6 of trj4 wave plan."

**Target trajectory**: trj6 (Wave 6 trj4-plan tail), or trj7 if trj4 Wave 6 fully closes.

**WHY deferred**: Apple App Attest and Play Integrity verifiers are tracked in trj4 Wave 6 (TRJ4-030, TRJ4-031, TRJ4-032, TRJ4-033). Trj5 does not duplicate this work. The trj4 wave-plan close-bar tracker at `../trajectory-4/closeout/CLOSE-BAR-TRACKER.md` continues to grade Wave 6.

### New milestone scope of any kind

> Verbatim: "New milestone scope of any kind."

**Target trajectory**: post-trj6.

**WHY deferred**: integration work is sized to the assurance matrix. Adding
milestones (M11+ in the trj3-style numbering, or new T-tier slices in the
trj4-style) would re-create the seven-lane menu the synthesis explicitly
rejects. New milestones wait until current planning/integration closure is
accepted and the substrate's proof-artifact differentiator is real.

## Synthesis-cited anti-patterns

The synthesis explicitly rejects:

- **seven-lane menus**: release work is three lanes, not five and not seven.
- **parallel new milestones**: release work is one trajectory absorbing trj4 wave plan items, not a sibling milestone.
- **any framing that lets trj4's pattern repeat**: every Lane B primitive closes with three Evidence Gate artifacts (enforced call site + spec MUST citation + signed negative conformance test). Lane A evidence is real (non-1970 timestamps, non-placeholder fixtures, observed mutation banner). Lane C is the forcing demo that breaks if A or B are not real.

## Trj4 wave-plan absorption summary

This block is also in `README.md` and `EXECUTION-BOARD.md` for grep convenience.

| trj4 wave-plan item | release work lane | release work ticket |
|---|---|---|
| TRJ4-010, TRJ4-011 | A | release work-A1, release work-A7 |
| TRJ4-012, TRJ4-013, TRJ4-014 | A | release work-A3 |
| TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018 | A | release work-A4 |
| TRJ4-019 | (deferred to trj6 per Wave 3 review) | (none) |
| TRJ4-040..049 | A | release work-A2 |
| TRJ4-100..104 + T1.0.E | B | release work-B1 |
| TRJ4-120..131 + T1.2.E | B | release work-B2 |
| TRJ4-140..147 + T1.3.E | B | release work-B3 |

## Deferred to trj6 with rationale

The following items were considered for release work inclusion but are
explicitly deferred to trj6 based on Wave 3 review.

### TRJ4-019 (`chio-equivalence-tests` proptest hosted-vs-portable equivalence)

> Verbatim (from `debate/00-SYNTHESIS.md` Lane A floor): "10k cases per
> PR + 1M nightly, zero divergence."

**Original assignment**: master `EXECUTION-BOARD.md` line 37 listed
TRJ4-019 as absorbed by `release work-A5`. Lane A subsequently re-purposed
`release work-A5` for the Lean4 `negotiation_safety` re-proof, leaving
TRJ4-019 without a release work home.

**Wave 3 decision**: defer to trj6.

**Target trajectory**: trj6.

**WHY deferred**: Lane A's 8-week horizon is already loaded with five
sub-lanes (mutation uplift, threat backfill, Kani harnesses, TLA+
rewrites, Lean refinement) totaling 50+ tickets after Wave 3 expansion.
Adding a sixth sub-lane for proptest equivalence-tests at
10k/PR + 1M/nightly is real engineering work (CI matrix, infrastructure
spend, run-time budget) and risks plateau on the higher-priority Lane A
work. The hosted-vs-portable equivalence claim is currently informational; no
active assurance-matrix claim depends on it. Deferral does not change current
closure.

The trj6 lane plan picks up TRJ4-019 as a first-week ticket.

## Why this scope-lock

Per the synthesis closing line: "Chio's differentiator is the proof artifact. Until the proof artifact is real, every trajectory after trj4 is the same trajectory wearing a different name."

Trj5's scope is locked to the claim-by-claim assurance matrix in the legacy-named
`SHIP-BAR-TRACKER.md` plus the architectural prerequisite needed to wire Lane B.
Anything that does not directly serve those claims is deferred outside current
closure. That is the discipline that makes this work different from trj4.
