# Cognition Market Program Plan

> **For agentic workers:** This is the program-level plan. Execution happens
> per-milestone through bite-sized implementation plans under
> [plans/](plans/); the first one exists
> ([plans/2026-07-20-M0-M1-finding-artifact-family.md](plans/2026-07-20-M0-M1-finding-artifact-family.md))
> and is executable now with superpowers:subagent-driven-development or
> superpowers:executing-plans. Later milestone plans are authored fresh when
> their dependencies land (rule in section 6).

**Goal:** Ship the agent-to-agent cognition market on Chio - coding-agent
verified fixes first, R&D negative results second - as an extension of
shipped primitives, per [ARCHITECTURE.md](ARCHITECTURE.md).

**Architecture:** Finding artifacts listed through the existing registry,
reveal as a governed tool call with a kernel digest gate, settlement on
existing holds/escrow, fraud handled by bonded challenges plus published-rate
audits feeding the existing sanction/slash lane, retraction via a
revocation-oracle status feed. See ARCHITECTURE sections 3-8.

**Tech Stack:** Rust workspace (MSRV 1.93), existing Chio crates; no new
external dependencies anticipated before M7.

## Global Constraints

- No em dashes anywhere (CLAUDE.md); conventional commits; fail-closed
  everywhere; clippy `unwrap_used`/`expect_used` deny.
- Verification gate per change: `cargo build --workspace && cargo test
  --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --all
  -- --check`.
- Schema evolution: additive optional fields only; new enum variants on
  frozen `deny_unknown_fields`-style wire enums are forbidden (new `.v2`
  schemas instead). The `Constraint` vocabulary is the one deliberate
  exception this program proposes: it is adjacently tagged with
  hard-reject-on-unknown, so adding `OutputDigestSha256` is a fail-closed
  vocabulary extension (old kernels refuse the token rather than running
  the delivery unprotected), gated on ADR-A plus a PROTOCOL.md update and
  verdict-matrix rotation at M3. `Constraint::Custom` is rejected as the
  carrier because it is input-side and semantically ignored by old
  kernels (fail-open; `chio-kernel/src/request_matching.rs:420`). Every
  new schema id registers in `signed_artifact.rs` +
  `spec/schemas/registry.json` (cross-checked by `cargo test -p
  chio-core-types --test signed_artifact_schema` and
  `scripts/check-chio-schema-registry.sh`).
- Ship dark until qualified: new surfaces sit behind a cargo feature and
  outside the bounded operational profile until the M9 qualification work
  (`docs/release/QUALIFICATION.md`, bounded gate `cargo xtask qualify
  bounded-chio`).
- Proof-claim discipline: nothing listable under capabilities
  `ChioProofClaims` rejects; evidence classes never upgraded.

## 0. Baseline assumption: PR #974 merges first

The program baseline is main AFTER
[PR #974](https://github.com/bb-connor/arc/pull/974) ("complete the
agent-economy durability roadmap", 1,242 files) merges. None of this
design set's research assumed #974 - it was verified against pre-#974
main - so the dependency is stated here explicitly, with what a targeted
diff of #974's head (`worktree-chio-economy-research`) established on
2026-07-20:

- **Verified UNCHANGED by #974** (design rests on these safely): the
  `Constraint` carrier mechanics in `chio-core-types/src/capability/scope.rs`
  (one variant added, see below), the reveal-digest definition in
  `receipt_support/receipt_content.rs` (ARCHITECTURE 4.5 math intact),
  `chio-listing/src/trust_activation.rs` (the BondBacked seam),
  `chio-market` claim/settlement lanes, `chio-revocation-oracle`, and
  `chio-disclosure-lineage`.
- **Heavily reworked by #974** (facts must be RE-VERIFIED before the M3
  plan is authored): `kernel/validation.rs` (~1.8k lines changed),
  `budget_store.rs` (~1.6k), the response builders, plus a new explicit
  invocation-capture stage (`capture_invocation`,
  `cancel_captured_monetary_before_dispatch`) and a new pending-approval
  response kind (`responses/pending_responses.rs`).
  `reverse_pre_execution_budget_mutation` survives (validation.rs:1851 on
  the #974 head); `unwind_aborted_monetary_invocation` does NOT (replaced
  by the capture lifecycle), so ARCHITECTURE 6.2's citation of it is
  pre-#974 and the mismatch-refund arm must be re-anchored - likely onto
  the capture-cancellation path, which looks like a BETTER seam for the
  gate, not a worse one. The "single Allow choke point" topology claim
  must be reconfirmed against the new pending/capture arms.
- **Precedent gained**: #974 itself adds
  `Constraint::RequireCumulativeApprovalAbove` in place - the repo's own
  practice extends the constraint vocabulary within v1, which settles the
  ADR-A evolution-model question in favor of the `OutputDigestSha256`
  variant route (review round 2, comment on the frozen-enum rule).
- **Sequencing**: M0/M1 executes only after #974 merges and this branch
  rebases - #974 changes `spec/schemas/registry.json` by ~530 lines, so
  landing registry edits in parallel guarantees conflicts. M2's
  fee-collection claim must be re-checked first: #974 introduces
  `chio-open-market/src/fiscal_adapter.rs` and a `chio_fiscal` resolver,
  which may supersede the "fees are declarative-only" note (MECHANISMS 6).

## 1. Milestone ladder

Each milestone is independently shippable and independently stoppable; a
stop after any milestone leaves the repo strictly better documented and no
production surface half-wired.

| M | Name | One-line scope | Depends on | Plan status |
|---|---|---|---|---|
| M0 | Spec and registration | `chio.finding.v1` registered (challenge/status schemas deferred to M5/M6 per review); ADR-0017 amended | - | plan exists (with M1) |
| M1 | `chio-finding` crate | artifact types, validators, goldens | M0 | plan exists |
| M2 | Publish and discover | descriptor search surface; listing publish path; bond-proof admission gate | M1 | plan after M1 lands |
| M3 | Kernel delivery contract | `Constraint::OutputDigestSha256` + two-layer digest gate (every Allow path) + generic `chio.delivery-contract.v1` receipt block + verdict-matrix rotation | M1 | plan after M1; needs kernel-owner review of ARCHITECTURE 6.2 first |
| M4 | Wedge purchase E2E | reference finding server; MustPrepay purchase flow; `chio finding` CLI (publish/search/verify/buy) | M2, M3 | plan after M3 |
| M5 | Challenge and audit lane | `FabricatedFindingEvidence` abuse class; challenge evaluator; audit-scheduler convention; slash wiring | M4 | plan after M4 |
| M6 | Status feed and retraction | oracle instance; control-plane root/proof surfaces; purchase-time non-inclusion; quarantine guard rule; ops runbook | M4 | plan after M4 (parallel with M5) |
| M7 | Cross-org escrow path | delivery-receipt Merkle release wiring; bilateral evidence flow; escrow runbook | M4 | plan after M5+M6; only if bilateral demand exists |
| M8 | Pool purchasing and SDK | swarm purchasing convention; elicitation ceiling in SDKs; pheromone hint convention | M4 | plan after M4 |
| M9 | Qualification and claims | bounded-matrix entries; CLAIM_REGISTRY rows; RC guarantee entries; R&D-instance extensions | M5, M6 | plan after M6 |

## 2. Per-milestone definition

### M0 + M1 (plan written, executable now)

Deliverables and steps: [plans/2026-07-20-M0-M1-finding-artifact-family.md](plans/2026-07-20-M0-M1-finding-artifact-family.md).
Exit: workspace gate green (including
`scripts/check-chio-owned-v1-only.sh`); `chio.finding.v1` accepted by
`validate_signed_artifact_schema`; golden fixture validates against schema
and struct. Challenge and status-feed schemas are deliberately NOT
registered here - they land with M5/M6, and the status artifact must carry
the oracle's exact `SignedEpochRoot` (ARCHITECTURE 4.4).

### M2 Publish and discover

- Control-plane `POST /v1/findings/publish`: the REUSABLE `Finding`-ingress
  invariant (review finding) - FIRST schema-validate the raw request JSON
  against the registered `chio.finding.v1` schema (`chio-spec-validate`),
  THEN deserialize and run `verify_finding` (structure + content-addressed
  id + issuer signature), then index. Schema-first is load-bearing:
  `verify_finding` reserializes canonically, so `PublicKey::from_hex`
  tolerating `0x`/uppercase and `Option` fields accepting explicit `null`
  would otherwise pass `verify_finding` while failing the schema. This
  same ingress invariant applies at M4 (buyer-presented overlay `Finding`)
  and M5 (challenge-evaluator `Finding`), each with rejection coverage.
  `GET/POST /v1/findings/search` (topic prefix + `context_sha256` equality), following the three-step surface pattern
  (ARCHITECTURE 8.1; precedent
  `chio-control-plane/src/trust_control/certification_handlers.rs:143`).
- Listing publish path: finding server listed under `ToolServer` actor kind
  with `metadata_url` pointing at the finding artifact (ARCHITECTURE 7.3);
  pricing hint carries `capability_scope` = `finding:<finding_id>` (colon
  segments per `capability_scope_covers`, `bidding.rs:534`; verified
  end-to-end in the spec test).
- The generic bond-proof admission gate: clear `require_bond_backing` when
  a signed bond artifact matching the fee schedule's requirement is
  presented (`chio-listing/src/trust_activation.rs:558-572` seam). This is
  open-market-generic work, reviewed with that lane's owner.
- Publication-fee collection: the fee schedule is declarative today
  (MECHANISMS section 6 honesty note); admission settles the publication
  fee as a metered charge so the spam floor is real, not advisory.
- Liveness at publish/search time, BOTH bounds
  (`finding.issued_at <= now && now < finding.expires_at`, matching the
  marketplace helpers): publish rejects future-issued AND expired findings
  fail-closed and search filters them (a correctly signed but expired OR
  not-yet-live artifact must not be indexable or pairable with a fresh
  pricing hint; the M1 validator is clockless by design, so liveness
  belongs to these surfaces). Future-issued rejection test included.
- Exit: an integration test publishes a signed finding, searches it by
  context digest, sees `BondBacked` admission flip from review-only to
  admitted with a bond artifact, sees the publication fee settled in a
  receipt, and sees an expired-but-signed finding rejected at publish;
  gate green.

### M3 Kernel delivery contract (the heart; smallest possible diff)

- `Constraint::OutputDigestSha256(String)` in
  `chio-core-types/src/capability/scope.rs` with advisory-pass at
  `constraint_matches` (precedent `request_matching.rs:428`).
- Digest gate placement per ARCHITECTURE 6.2 (two layers: universal in
  the common Allow builder for soundness; charged-branch pre-reconcile
  for clawback). Mismatch: Deny receipt + reversal; match: reconcile +
  the GENERIC `chio.delivery-contract.v1` metadata block (struct in
  `chio-core-types/src/receipt/`, key const beside the signing-nonce
  const; the finding-specific overlay is M4).
- Digest gate semantics per ARCHITECTURE 4.5/6.2: commitment is over the
  canonical reveal envelope; `Stream` outputs deny fail-closed; the
  mismatch arm reverses the charge AND releases/refunds any payment
  authorization (mirroring `unwind_aborted_monetary_invocation`); the
  in-function reversal precedent is the no-measured-cost path
  (`validation.rs:1333-1349`).
- LAYERED coverage (review P1s): the universal check in
  `build_allow_response_with_metadata` gates EVERY Allow path for
  soundness, PLUS a money-correctness check before each irreversible
  settlement so the deny arm keeps its refund handle - before
  `reconcile_budget_charge` on the charged branch, AND before
  `settle_prepaid_authorization_without_charge` on the no-ceiling
  MustPrepay branch (`charge_result == None` with a payment
  authorization; it settles before `finalize_tool_output_with_metadata`,
  `validation.rs:~1290`, so a builder-only check would run post-capture
  with no handle to refund). On mismatch the no-ceiling branch RELEASES
  the authorization rather than captures. Explicit per-path bypass tests,
  each asserting the correct refund.
- Receipt metadata at M3 is the GENERIC `chio.delivery-contract.v1`
  block only (expected digest + digest_check, both kernel-sourced); the
  finding-specific `chio.finding.delivery.v1` overlay moves to M4 where
  the signed purchase artifacts give it a trustworthy carrier
  (ARCHITECTURE 4.2; review P1 on self-attested context).
- Verdict-matrix rotation: new `delivery_contract` scenario class,
  recomputed `scenario_index_hash` + `corpus_sha256`, doc update
  (ARCHITECTURE 7.4).
- Formal hooks (see section 3): Kani harness + Lean bounded model for
  delivery-contract soundness.
- Exit: kernel tests prove "Allow implies content_hash equals constraint
  digest" ON EVERY ALLOW PATH (charged, uncharged, MustPrepay-without-
  ceiling, unmeasured provisional - one bypass test each), "mismatch on
  the charged path implies Deny + hold reversed + no realized spend",
  "mismatch on the no-ceiling MustPrepay branch implies Deny +
  authorization RELEASED (refund) + not captured", and "stream output
  under the constraint implies Deny"; verdict matrix green across
  required drivers; gate green. The
  invariant's formal statement is kernel-attested reveal soundness
  (ARCHITECTURE 6.2) - it claims kernel acceptance of the preimage, not
  buyer delivery.
- Risk gate: this milestone's plan is written only after a kernel-lane
  review of ARCHITECTURE 6.2 (it touches `validation.rs`, the most
  invariant-dense file in the workspace).

### M4 Wedge purchase E2E

- Reference finding tool server (serves sealed payload bytes for
  `read_finding(finding_id)`; buyer-blind per ARCHITECTURE 6.3) under
  `examples/` or a small crate, registered via
  `register_tool_server`.
- Purchase flow glue: bid/ask/accept with the seller minting the token
  carrying `OutputDigestSha256` + `max_invocations: 1` +
  `max_total_cost`; MustPrepay reveal; refund-on-abort test. Includes the
  small open-market extension this requires: `bid()` mints grants with
  `constraints: Vec::new()` AND `dpop_required: None` hardcoded
  (`bidding.rs:396` region), so `BidMintContext` grows BOTH
  provider-supplied grant constraints and a `dpop_required` flag (review
  finding: without the flag, M7's DPoP-bound escrow grants cannot be
  minted and the no-buyer replay stays open); the buyer's accept path
  checks the token constraint equals the finding's `payload_sha256`.
- `chio finding publish|search|verify|buy` CLI following the documented
  family pattern (ARCHITECTURE 8.3).
- Delivery idempotency (ARCHITECTURE F3 step 6, load-bearing per review):
  the M4 DEFAULT is the seller re-serve policy keyed on the delivery
  receipt (no kernel change) - the `Operation::ReadResult`-on-the-grant
  option does NOT work today (`grant_matches_request` matches
  `Invoke`-only, `request_matching.rs:337-347`; no kernel ReadResult
  path), and a kernel-native receipt-keyed read-result matcher is a
  deferred kernel change. Test the buyer-crash-after-Allow path against
  the re-serve policy.
- `chio.finding.delivery.v1` overlay block (moved here from M3): fields
  sourced from FOUR buyer-presented signed artifacts, each verified
  before the kernel echoes anything (ARCHITECTURE 4.2), with the signed
  `Finding` as the ANCHOR that binds identity to commitment: (1) the
  signed `Finding` - issuer signature (`verify_finding`) + recomputed
  content-addressed id - with `finding.payload_sha256 == token
  OutputDigestSha256` and pricing scope's finding id ==
  `finding.finding_id` (this id-to-digest binding is the round-6 fix; a
  provider could otherwise scope a pricing hint to finding B while the
  token constraint commits to payload A and every signature still
  verifies); (2) `SignedAskResponse` (envelope signature against the
  token ISSUER; token id/subject/expiry and listing id against the
  token); (3) `SignedAcceptedBid` (envelope signature against the token
  SUBJECT; `canonical_digest(ask.body) == accepted.ask_digest`;
  agent_id, listing_id, quoted_price cross-bound); (4)
  `SignedListingPricingHint` (same signer as the token issuer;
  `pricing.listing_id == ask.listing_id`); (5) the funds RESERVATION -
  the accepted bid's `bid_receipt_id` is buyer-supplied text
  (`SignedAcceptedBid::sign` is public), NOT reservation-backed until
  checked, so the mediating kernel proves it from its OWN verified
  reservation state keyed by `bid_receipt_id` (single-operator wedge),
  and cross-org additionally presents a `SignedReservationReceipt`
  cross-bound on receipt id / ask digest / agent / listing / amount
  (ARCHITECTURE 4.2). `finding_id` is stamped from
  the anchor, never from caller-controlled request arguments. Malformed
  or missing artifacts on a finding purchase DENY (no silent omission).
  Includes registering the metadata block's schema id. The
  `status_proof` sub-block is NOT in M4 (review: this was an M4-to-M6
  cycle) - M6 completes the overlay additively.
- Liveness at buy time: the purchase path re-checks BOTH bounds
  (`finding.issued_at <= now && now < finding.expires_at`) fail-closed
  before minting/reveal (the M1 validator is pure and clockless; liveness
  is a caller check), with a future-issued rejection test.
- Media-type check (ARCHITECTURE 4.5): the buyer/CLI rejects the reveal
  when `envelope.media_type != finding.payload_media_type`, with a
  mismatch rejection test (a digest-valid reveal under a misleading
  advertised type must not auto-apply).
- Buyer ingress of the overlay `Finding` uses the schema-first invariant
  (schema-validate raw bytes then `verify_finding`), not `verify_finding`
  alone.
- Exit: one command-line round trip on a local kernel: publish, search,
  verify offline, buy, reveal, delivery receipt with `finding_delivery`
  block, budget reconciled; failure-path tests (digest mismatch, seller
  down, abort, buyer crash after Allow) all end with funds and payload in
  a documented state; gate green.

### M5 Challenge and audit lane

- Define and register `chio.finding.challenge.v1` (deferred from M1;
  carries the `ChallengeClassMismatch` guarantee-class gate,
  `challenger: PublicKey`, and the plan-file deferral stub's semantics).
- Bond sizing uses the corrected no-clawback model: bonds cover
  FINALIZED fraud exposure over the detection horizon (MECHANISMS 4);
  there is no revenue vesting in v1.
- `FabricatedFindingEvidence` abuse class + evidence kinds in
  `chio-open-market` (`penalty.rs:21`, `evidence.rs`).
- Challenge evaluator: pure fail-closed function consuming a signed
  `FindingChallenge` + a signed `Finding` (via the schema-first ingress
  invariant, not `verify_finding` alone) + reproduction receipts,
  reusing claim-style receipt re-verification
  (`chio-market/src/insurance_flow.rs:390-414` pattern), emitting a
  finding-code result that feeds the existing Sanction -> SlashBond gate
  (`evaluation.rs:356-451`).
- Audit-scheduler convention: a documented venue job (published rate,
  participation-fee funded) that files ordinary challenges; no new
  adjudication authority (MECHANISMS section 5).
- Dispute-fee collection at challenge submission (the schedule is
  declarative today; MECHANISMS section 6 honesty note), settled as a
  metered charge alongside the challenge bond.
- Cross-kernel receipt trust: the challenge evaluator verifies
  reproduction receipts against a configured trusted-kernel-key set
  (single-operator wedge: trivial; the config surface mirrors
  `chio-reputation`'s `trusted_kernel_keys` gating).
- `chio finding challenge` CLI.
- Exit: end-to-end test: fabricated evidence -> challenge -> enforced
  sanction case -> penalty artifact -> bond-impair preparation with
  distribution to the harmed buyer; failed challenge forfeits the
  challenge bond to the seller; gate green.

### M6 Status feed and retraction

- Finding-status oracle instance (generic `RevocationKey` reuse,
  `chio-revocation-oracle/src/api.rs:70`); control-plane surfaces
  `/v1/findings/status/{feed}/root` and `/proof/{finding_id}`
  (ARCHITECTURE 8.1).
- Define and register the status-feed artifact (deferred from M1): it
  contains/references the oracle's exact `SignedEpochRoot` plus feed
  metadata (`epoch.rs:12`, `api.rs:86-98`); signed-root verification
  carries over unchanged. The feed contract pins the fixed domain nonce
  `epoch_nonce = "chio.finding.status.v1"` so inserts and proofs use one
  key (ARCHITECTURE 4.4).
- Portable non-inclusion (review finding: today's `NonInclusionProof`
  carries no path bytes and is checked against local oracle state, so
  `/proof/{finding_id}` would be a trusted online answer): extend the
  oracle with sparse-Merkle non-inclusion paths verifiable against the
  signed root, or explicitly document the endpoint as a trusted-query
  surface backed by the operator bond. The portable proof is the
  required default; the trusted-query fallback needs its own risk-row.
- Purchase-time non-inclusion check wired into `chio finding buy` and the
  buyer SDK path; freshness-window enforcement fail-closed.
- Completes the `chio.finding.delivery.v1` overlay with the optional,
  signature-safe `status_proof` sub-block (additive per ARCHITECTURE 7.3;
  breaks the former M4 dependency on M6 infrastructure).
- Quarantine guard rule: `MemoryGovernanceGuard` extension denying reads
  whose provenance traces to a retracted finding (opt-in;
  `chio-guards/src/memory_governance.rs:60`).
- Ops: `docs/release/CHIO_FINDING_MARKET_RUNBOOK.md` covering epoch
  cadence via operator cron (the workspace has no job daemon -
  ARCHITECTURE 8.2), anchoring cadence, equivocation response.
- Exit: retract -> new epoch root -> next purchase attempt fails closed on
  non-inclusion; holder's guarded read flips to deny under the opt-in
  rule; enforced challenge outcome (M5) auto-inserts into the feed; gate
  green.

### M7 Cross-org escrow path (conditional)

- `chio-settle` thin extension: prepare escrow release from a
  delivery-receipt Merkle inclusion (existing `prepare_merkle_release`
  path) and the deadline-refund watchdog descriptor.
- Bilateral flow doc + test: evidence bundle export/import, escrow
  create/fund, reveal, release, refund-on-timeout.
- Escrow operator model per ARCHITECTURE F6 (review P1s): the escrow
  names a MUTUALLY TRUSTED / NEUTRAL mediating operator - DPoP-required
  grants prove buyer-initiated reveals but cannot prove response
  delivery, so a seller-aligned mediator leaves attest-and-withhold
  (paid non-delivery) open and the profile is disallowed rather than
  shipped unfair. Buyer-ack alternatives need a predeclared
  ack-vs-refund adjudication rule (M7 decision). Exit includes BOTH
  adversarial tests: withhold-root (refund lands; harms the withholder)
  and withhold-response (neutral mediator makes attest-and-suppress
  non-viable).
- Trigger condition: at least one real bilateral seller/buyer pair wants
  it; otherwise stays unbuilt (YAGNI).

### M8 Pool purchasing and SDK

- Elicitation ceiling (`finding_bid_ceiling`, spec-tested shape) in the
  TypeScript/Python SDK buyer helpers; planner convention doc for
  one-purchaser-per-pool with a purchasing allocation dimension
  (MECHANISMS section 7; zero kernel changes).
- Pheromone hint convention: deposit `indicator` carrying
  `{"finding_listing": <listing_id>}` (untyped today by design;
  typed field is a decision-backlog item).

### M9 Qualification, claims, and the R&D turn

- Bounded-matrix entries + feature-flag removal for qualified surfaces;
  CLAIM_REGISTRY approved-claim rows + two `audited_assumption` rows
  (status-feed operator, seller tool server); RC Supported-Guarantee
  entries; ADR-0017 Proposed -> Accepted.
- Proof-bundle integration (ARCHITECTURE 7.2): the finding verifier's
  claim ids (`claim.finding.delivery_digest_bound`,
  `claim.finding.evidence_bound`, `claim.finding.status_fresh`,
  `claim.finding.bond_backed`) bound through the existing `ClaimSet`
  role with digest pins, plus a transaction-passport golden.
- R&D-instance extensions begin only here: replication decision rules for
  stochastic recipes, descriptor taxonomy for experiment spaces,
  `evidence_cost` bucketing defaults (threat model X2), cross-org feed
  governance - each gated on wedge usage data.

## 3. Verification strategy (cross-cutting)

- Every milestone ends on the workspace gate plus its own integration
  test named in its exit criteria.
- Formal hooks, in order of value: (1) delivery-contract soundness - Kani
  harness over the gate function (public-API style, like
  `kani_public_harnesses.rs`) plus a bounded Lean model "Allow implies
  digest equality" wired into the theorem inventory; (2) challenge-outcome
  envelope (award never exceeds bond; distribution sums exactly) - Kani;
  (3) status-feed freshness monotonicity (epoch roots strictly advance;
  non-inclusion proofs never accepted past `valid_until`) - Lean bounded
  model. These follow the proof-manifest process
  (`formal/proof-manifest.toml`) and are scoped inside M3/M5/M6.
- Conformance: family goldens from M1 onward; verdict-matrix rotation
  exactly once, at M3.
- The spec-shaped ignored test
  (`crates/economy/chio-open-market/tests/cognition_market_flow.rs`)
  is the progress meter: M3 deletes seam (a) from its panic message, M7
  seam (b), M5 seam (c), M6 seam (d); when the ignored test can be
  un-ignored and passes, the wedge is functionally complete.

## 4. Decision backlog (future ADRs, written when their milestone starts)

| ADR | Decision | Milestone | Current lean (from ARCHITECTURE) |
|---|---|---|---|
| ADR-A | Delivery-binding carrier (Constraint variant vs capability .v2) + gate placement in the finalizer | M3 | `OutputDigestSha256` variant, pre-reconcile gate (6.2); `Custom` rejected as fail-open; `.v2` is the fallback if v1 constraint vocabulary is declared frozen |
| ADR-B | Status-feed governance: who operates feeds, epoch cadence, anchor lanes, equivocation slashing | M6 | venue-operated, anchored, operator-bonded (threat model O2/O3) |
| ADR-C | api-protect response-hash binding (zero-code seller hosting) | post-M7 | deferred; native tool server first (6.3) |
| ADR-D | Auction mechanism (batched uniform-price per topic) | only with M4+ demand data | posted-price holds until data says otherwise (MECHANISMS 3) |
| ADR-E | Receipt-metadata key registry (repo-wide hygiene found during research) | M3 rider | named consts + PROTOCOL 6.4 table (7.5) |
| ADR-F | Existence-tier product (paid dead-end check) | M8+ | one-bit reveal priced per MECHANISMS 3/9 |
| ADR-G | Capture-delay custody profile (revenue vesting) | post-wedge, data-driven | v1 has no clawback (MECHANISMS 4); pursue only if bonds alone underprice finalized fraud |

## 5. Risk register (program-level)

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Kernel owners reject the finalizer gate placement | medium | M3 slips | ARCHITECTURE 6.1 documents the constraint facts; review BEFORE writing the M3 plan; fallback is a dedicated non-monetary reveal profile (worse: loses single-call settlement) |
| Verdict-matrix rotation friction across 7+ drivers | medium | M3 tail | rotation is one scenario class; stage it with the kernel change, not after |
| Honest-cost fabrication on `metered_attested` (threat S2) | high for R&D | trust in vision instance | wedge ships `deterministic_replay` only; R&D gated to M9 with audit-rate data |
| No job daemon for epoch/audit cadence | certain | ops burden | operator cron per runbook (existing anchor/settle precedent); revisit only if ops data demands a daemon |
| Demand-side flop (nobody buys) | unknown | program value | M4 exit includes a dogfood loop on this repo's own CI failures; M7+ gated on demand evidence |
| Cross-org confidentiality objections (operator sees reveals, O1/T1) | medium | limits vision instance | documented posture + TEE-tier deployment guidance; no overclaim in CLAIM_REGISTRY |
| Post-reveal resale collapses prices (B2) | high by nature | seller participation | priced-in decay/versioning (MECHANISMS 3/7); wedge contexts are org-internal where resale is moot |
| Registry/schema churn with open PR #974 (~530-line registry.json diff; kernel rework) | certain if parallel | conflicts + stale anchors | section 0 sequencing: merge #974 first, rebase, re-verify M3 pipeline facts |

## 6. Plan maintenance rules

- One bite-sized implementation plan per milestone, authored with the
  target files open (never from memory of them), stored in
  [plans/](plans/) as `YYYY-MM-DD-M<N>-<name>.md`, following
  superpowers:writing-plans format.
- A milestone's plan is written only when its dependencies have landed and
  its ADR-backlog decisions are made; until then the milestone definition
  above is the spec.
- Every landed milestone updates: the ignored spec test's seam list, this
  file's ladder table, and (from M3 on) the PROTOCOL.md finding-family
  section.
