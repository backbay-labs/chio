# M5: Challenge and audit lane

Executable plan for the M5 milestone (PLAN.md "M5 Challenge and audit lane",
ARCHITECTURE F4 and 4.3). Branch `codex/cognition-market-m5`, stacked on the
M4 wedge-purchase branch. Every seam reference below was verified against the
branch HEAD before this plan was written.

## Goal and boundary

M4 sells a finding and proves delivery. M5 makes the seller's bond mean
something: a buyer or a venue auditor presents exactly one class of mechanical
evidence, a pure fail-closed evaluator returns a signed verdict, an upheld
verdict blocks new sales and freezes a purchase cutoff, an appeal window runs,
and only then does a checked slash pay verified harmed buyers.

In scope: the seven artifact families, the pure three-class evaluator, the
durable challenge and liability state machines, the governance and penalty
composition wrapper, payout derivation, domain-keyed effect intents, the
dispute-fee lane, the audit scheduler artifacts, the CLI subcommand, and the
`finding_challenge_enforcement` exit test with its fail-closed negatives.

Out of scope, recorded by name rather than implied:

- **External broadcast and confirmation.** The impairment call is prepared,
  fenced, and verified, but the actual chain publication sits behind an
  injected publisher trait with no production adapter, exactly as M4 left the
  purchase HTTP routes. The plan itself concedes this is "an operator-mediated
  choke point, not an on-chain harmed-party theorem" until ADR-0015 follow-up A
  constrains destinations in the contract.
- **Status-feed retraction publication** (M6 owns it). M5 only durably
  enqueues the retraction intent and keeps it dispatch-ineligible.
- **Multi-batch payout allocation** beyond the 15 distinct buyer destinations
  the unbatched v1 profile caps, and any revenue vesting or clawback.
- **Post-impairment correction and restitution**, which the architecture
  defers to a future funded design.

## Design decisions

- **D1 (artifact home).** All seven families live in `chio-finding`
  (`challenge.rs`, `challenge_outcome.rs`, `challenge_enforcement.rs`,
  `finalized_bond_snapshot.rs`, `audit_epoch.rs`, `audit_report.rs`,
  `replay_observation.rs`), matching the M4 precedent: pure types, strict
  validators, signed envelopes, no kernel or store dependency.
- **D2 (evaluator home).** The pure evaluator is a new crate
  `crates/trust/chio-finding-challenge`, depending only on `chio-finding`,
  `chio-finding-verifier`, and `chio-core-types`. It performs no fetching,
  tool invocation, clock read, or storage access, so the coordinator cannot
  smuggle I/O into adjudication. Putting it beside the evidence verifier
  rather than inside an economy crate keeps the money-moving crates free of
  verification logic.
- **D3 (durable home).** A sibling `finding_challenge_store` in
  `chio-store-sqlite` holds challenges, dispute locks, liability heads, the
  governance case index, and claim snapshots. It opens on the same connection
  and serving-owner fence as the M4 purchase store, which is what makes the
  upheld transaction (liability CAS + sales block + cutoff freeze) one
  listing-scoped transaction with the M4 slot table.
- **D4 (coordinator).** `finding_challenge_coordinator` in the control plane,
  beside the M4 purchase coordinator, owns every clocked and durable step.
  Adjudication is delegated to D2; the coordinator never re-implements it.
- **D5 (case head).** Authoritative governance case-head resolution does not
  exist anywhere in the workspace (verified). M5 builds it as a durable
  finding-scoped case index in D3 that resolves the single latest
  non-superseded case and proves no other live Appeal or Sanction targets the
  same defect. It is a new primitive, not a reuse.
- **D6 (penalty wrapper).** `finding_penalty.rs` in `chio-open-market`
  composes, never bypasses: generic governance case evaluation first with an
  empty findings list, then the open-market penalty evaluation, then the three
  typed branches. `abuse_class` and `evidence_refs[].kind` are inert in the
  shipped evaluator, so every binding the plan requires (exactly one `External`
  ref, `reference_id == outcome_id`, `sha256 ==` the signed-outcome envelope
  digest, `FraudulentListing`, `bond_class = Listing`) is wrapper-owned.
- **D7 (effects).** Each domain-keyed semantic intent persists and fences
  before any dispatch, with the broadcast behind a `FindingEffectPublisher`
  trait mirroring the shipped `FindingRailObserver` seam. Identical retry
  reconciles; conflicting retry rejects; ambiguity quarantines.
- **D8 (dispute fee).** Both shipped fee event kinds are hard-pinned to the
  audit pool, deliberately, so a seller cannot redirect participation fees.
  M5 adds a third charge path for the dispute fee to the admission-pinned
  challenge-administration pool and leaves that pin untouched.
- **D9 (verdict types).** `Upheld | Rejected | Indeterminate` is a new enum;
  the shipped `FindingFacetOutcome` has no indeterminate arm and must not be
  reused. Only the replay facet carries
  `ConfirmedContradiction | Consistent | Indeterminate`, mapping onto the three
  top-level verdicts in that order.
- **D10 (identity derivations).** `outcome_id` derives from a
  domain-separated canonical body preimage excluding only `outcome_id` and the
  envelope signature. `defect_key = H("chio.finding.defect.v1", finding_id)`
  and `liability_key = H("chio.finding.liability.v1", defect_key, venue_id,
  listing_id, allocation_id, chain_id, vault_contract, vault_id)`. Challenge,
  class-evidence, and replay-run digests are dedup keys only and never
  authorize a slash.

## Invariants (repeated at every enforcement point)

1. Exactly one authorization branch and exactly one evidence class per
   challenge; every cross-branch or cross-class field rejects before
   evaluation, as does every pairing outside the closed compatibility matrix.
2. `Indeterminate`, never `Rejected`, whenever authority, retention, resolver,
   or infrastructure inputs cannot be established, in every class branch. An
   indeterminate result creates no hold, sanction, liability transition, audit
   reward, or forfeiture.
3. Only `Upheld` enters the penalty lane. Generic digest mismatch, wrong-media,
   and output-policy transform denials can never reach the seller sanction
   gate.
4. One defect and one liability span every class and evidence subset for the
   same backed listing; a second corroborating challenge never authorizes a
   second slash.
5. Money: the slash is `min(live_allocated_collateral, checked candidate)`,
   capped by the signed listing requirement, never silently clamped; the buyer
   pool is capped by verified realized spend and allocated pro rata with
   deterministic remainder order by `purchase_key`; the remainder goes only to
   the admission-pinned community fund. No challenger bounty comes from the
   slash. A qualified `digest_mismatch` has zero realized spend and therefore
   cannot manufacture a payout.
6. Signer roles are disjoint and pinned: evaluator, venue finalization
   authority, penalty authority, settlement observer, and each effect
   authority. A key valid in one role is rejected in another.
7. Nothing external is dispatched before its semantic intent is durably
   persisted and fenced, and purchases stay blocked while publication is
   pending.

## Files (verified seams)

- Penalty: `chio-open-market/src/penalty.rs:17,19-26,28-53,55-85,87-128,130`
  (frozen camelCase body, no `deny_unknown_fields`), evaluation gate at
  `evaluation.rs:356-451`, effective state at `:477-496`.
- Governance: `chio-governance/src/evaluation.rs:8-288`, `generic.rs:360-373`;
  no case persistence or head resolution anywhere.
- Settle: `chio-settle` `prepare_bond_impair`, `observe.rs` lifecycle
  observation, `outcome_store.rs` leased CAS store, `retry.rs` bounded-retry
  classification, `hook.rs` at-least-once contract.
- Evidence: `chio-market/src/insurance_flow.rs:390-414` (claim-style receipt
  re-verification), `chio-finding-verifier` public API and 13 facets,
  `verify_checkpoint_membership`, the M4 delivery blocks in
  `chio-core-types/src/receipt/metadata.rs`.
- M4 durable state: `chio-store-sqlite/src/finding_purchase_store.{rs,sql}`
  (slots are the cutoff line), `finding_purchase_coordinator.rs`.
- Fees and pools: `chio-fiscal/src/fee_schedule.rs:12-16` (`Dispute` class
  exists), `chio-finding/src/admission.rs:83-97,133-135` (both pools plus the
  community fund), audit-pool pin at `finding_handlers.rs:1006-1015`.
- Registration: `chio-core-types/src/signed_artifact.rs` allowlist and its
  two-way parity test, `spec/schemas/registry.json`, `MANIFEST.sha256`,
  `COVERAGE.md`, `PROTOCOL.md` 6.4.7.

## Task 1: Artifact families

Add all seven families in `chio-finding` with strict validators, closed serde
shapes, and signed envelopes, plus `chio.registry.market-penalty.v1`
registration (schema mirrors its existing camelCase, unknown-field-tolerant
shape exactly; no Rust field changes). Every family gets a schema file,
registry row, manifest entry, COVERAGE count, PROTOCOL 6.4.7 entry, and, where
signed, a signed-artifact allowlist row with its parity-table entry. The
challenge validator enforces both closed unions and the compatibility matrix;
the outcome validator enforces the nested-facet mapping.

## Task 2: Pure evaluator

New crate `chio-finding-challenge`. Consumes a signed challenge and a signed
finding through the strict-raw-first ingress plus exactly the evidence its
class selects. `digest_mismatch` verifies the failed-delivery record, the
checkpointed Deny, the marked grant, both delivery blocks, the kernel-proved
identity profile, the released hold, and zero realized spend.
`evidence_invalid` cross-checks the challenged subset and checkpoint against
the finding and reuses claim-style receipt re-verification; only affirmative
invalidity under the profile effective at publication supports fraud.
`replay_contradiction` strict-parses the recipe preimage, hashes it to
`Finding.replay_recipe_sha256`, verifies each role-scoped observation, and
applies the recipe's closed predicate. Each branch returns a typed nested
facet and the class-independent verdict.

## Task 3: Durable stores

`finding_challenge_store`: challenges (`Submitted -> Evaluating -> Rejected |
IndeterminateRetryable | IndeterminateClosed | Upheld`), dispute locks
(`locked -> returned | forfeited`, exclusive, exactly once), liability heads
(`Open -> UpheldPendingClaims -> PendingAppeal -> Finalizing -> Settled` plus
`ReversedBeforeImpairment`), the governance case index for D5, claim
snapshots, and effect intents keyed by their domain digests. Extend the M4
purchase store with the sales block, the frozen cutoff, and the pre-cutoff
slot-closure wait, all committing in one transaction with the liability CAS.

## Task 4: Coordinator, penalty wrapper, and payout

The coordinator drives submission, bond locking, evaluation dispatch, the
upheld transaction, the claim and appeal windows, and finalization. The
penalty wrapper implements D6's three branches with the checked amount
formula. Payout derives from the authoritative purchase-record index at the
frozen cutoff, reverifying each record, capped by verified harm and available
bond, summing exactly.

## Task 5: Effects, fee lane, settle verifier

Domain-keyed intents per D7; the D8 dispute-fee path; a `chio-settle`
enforcement verifier that consumes the enforcement artifact plus the finalized
bond snapshot, rechecks the observed block hash and operator qualification,
and refuses to treat `EvidenceAlreadyUsed` as success without a matching
stored transaction and finalized receipt.

## Task 6: Audit scheduler and CLI

`audit-epoch` precommit and `audit-report` result as two artifacts, never one
mutable one, with deterministic selection reproducible from the revealed seed.
`chio finding challenge` follows the M4 family pattern.

## Task 7: Exit test and gate

`finding_challenge_enforcement` plus fail-closed negatives: all three class
branches reaching a sanction; every cross-class and cross-branch rejection;
missing, non-canonical, and hash-mismatched recipe preimages; generic mismatch
and transform-policy denial unable to sanction; capped exact-sum harmed-buyer
allocation with no challenger bounty; a clean venue audit transferring
nothing; the three bond dispositions including bounded-retry success,
retry exhaustion, and exactly-once lock return; the nested replay mapping;
concurrent and post-restart duplicate challenges proving one slash and
at-most-once payout. Full qualified workspace gate, then a review fleet.

## M5 exit criteria

1. The named exit test and its negatives are green and prove every clause
   above.
2. No path lets an indeterminate, generic, or transform-policy denial reach a
   seller sanction, and no second challenge authorizes a second slash.
3. All seven families plus the market penalty are registered with full
   schema, registry, manifest, protocol, and allowlist parity.
4. Signer roles are disjoint and enforced; a key substituted across roles
   rejects.
5. The full qualified workspace gate passes at branch HEAD and the default
   build still links none of the market surface.
6. Every deferral above is recorded by name, with the external-publication
   boundary explicit.
