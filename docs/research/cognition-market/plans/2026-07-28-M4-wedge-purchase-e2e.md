# M4: Wedge purchase E2E

Executable plan for the M4 milestone (PLAN.md "M4 Wedge purchase E2E",
ARCHITECTURE 4.2/4.5/F3/8.3). Branch `codex/cognition-market-m4`, stacked on
the M3 delivery-contract branch. Every seam reference below was verified
against the branch HEAD before this plan was written.

## Goal and boundary

M3 shipped generic output-digest enforcement. M4 completes the wedge purchase:
a provider-signed `RequireFindingPurchase` marker on the minted grant, a
strict signed purchase-context carrier, an authoritative single-operator
purchase coordinator with atomic budget and seller-exposure reservations, the
finding-aware finalizer (media-type check, `chio.finding.delivery.v1` overlay,
purchase record, two-phase failed-delivery standing), a reference
`read_finding` tool server, the `chio finding` CLI family, and a
`finding_purchase` verdict-matrix class. Exit is the
`cognition_market_wedge_purchase_e2e` flow plus the failure lanes.

Out of scope, recorded as deferrals: cross-org escrow execution (the
`CrossOrgEscrow` selector shape is registered but denied until M7), the
`status_proof` overlay sub-block (M6), transform-aware delivery (versioned
future profile), a kernel-native receipt-keyed read-result path (the recovery
authorization is a market-side mint), and challenge evaluation (M5).

## Design decisions

- D1 (marker carrier). `Constraint::RequireFindingPurchase(Box<FindingPurchaseMarkerV1>)`
  in `chio-core-types` capability scope vocabulary. The marker binds
  `finding_id`, `listing_id`, and a closed
  `FindingSettlementSelector { LocalReversibleHold, CrossOrgEscrow { settlement_profile_sha256 } }`.
  Both selector shapes are registered; only `LocalReversibleHold` is
  admissible in this milestone, and an escrow-witness context key in local
  mode (or a missing one in cross-org mode) denies. Attenuation is exact
  equality with an explicit arm. The adjacently tagged enum with
  `deny_unknown_fields` makes older kernels reject the marker fail-closed.
- D2 (context transport). The purchase context rides
  `governed_intent.context.chio_finding_purchase_context_b64`: base64 of at
  most 256 KiB of strict canonical `chio.finding.purchase-context.v1` JSON,
  encoded-length bounded before decode, decoded-length bounded before strict
  raw-first parse. The tool arguments stay exactly `{"finding_id": "<id>"}`.
  Durable binding: `ImmutableToolAdmissionRequest` gains an optional
  purchase-context digest field (`skip_serializing_if = None`, so every
  existing admission hash is unchanged) that freezes the exact carrier bytes
  into the immutable request hash when present; replay under different
  carrier bytes fails closed.
- D3 (kernel boundary). The kernel cannot depend on the economy crates, so
  purchase verification is an injected seam following the `PaymentAdapter`
  precedent: a `FindingPurchaseVerifier` trait on `ChioKernel`
  (`set_finding_purchase_verifier`). The verifier strict-parses and
  cross-binds the full artifact web and returns a kernel-facing verified
  binding (ids, expected digest, media type, amounts, payer key, reservation
  and preallocated payment-operation ids, slot state). Fail-closed: a marked
  grant with no installed verifier, or any verifier error, denies before
  nonce, budget, payment, or dispatch mutation. The production implementation
  lives in `chio-open-market` and reads the authoritative coordinator store.
- D4 (media type). Only for marked requests, the finalizer strict-parses the
  resolved output as the exact two-field reveal envelope
  `{media_type, payload_b64}` (bounded base64) and requires
  `envelope.media_type == finding.payload_media_type` after the digest
  compare and before any money movement. A mismatch is a new
  `DeliveryDenialReason::MediaTypeMismatch` on the existing
  `DeniedAfterDelivery` terminal with the same release-only
  `ContractualZeroCharge` settlement. Wrong media is never seller-fraud
  evidence.
- D5 (slot close, wedge profile). The pending-purchase slot is reserved by
  the coordinator before reveal dispatch and closed by the coordinator after
  the kernel's replay-stable signed terminal exists, idempotently and
  recovery-driven (an open slot with a persisted kernel terminal is always
  re-closable deterministically on restart). Capture cannot bypass slot
  reservation because the kernel-side verifier requires the authoritative
  reservation to be in the slot-reserved state. Threading a purchase-slot
  participant through the kernel's atomic terminal projection is deferred;
  the M5 cutoff property (no capture after the cutoff freeze, none omitted)
  holds because a slot exists before any dispatch and every close is
  recovery-guaranteed.
- D6 (failed delivery, two phases). Phase one is kernel-owned: the signed
  Deny persists with its durable terminal, the coordinator closes the slot to
  that terminal, and the Deny is checkpointed. Only then does the purchase
  authority sign `chio.finding.failed-delivery.v1` binding buyer, accepted-bid
  envelope digest, authoritative reservation and preallocated
  payment-operation ids, hold attempt and release terminal, the checkpointed
  Deny, zero realized spend, and `payout_eligible: false`. Until phase two
  completes the failure carries no standing.
- D7 (recovery authorization). Buyer-crash-after-Allow recovery is a
  seller-minted no-charge grant to the original delivery-token subject:
  DPoP-bound, zero monetary ceilings, short expiry, bounded retries, the same
  `OutputDigestSha256`, and request constraints binding the original receipt
  id, original capability id, and finding id. It carries no purchase marker
  (it is not a purchase; it earns generic delivery metadata only). The mint
  function re-verifies the trusted-kernel receipt and every
  subject/capability/finding binding first. `Operation::ReadResult` on a
  grant is a dead end today (`grant_matches_request` is Invoke-only at
  `request_matching.rs:346`).
- D8 (coordinator authority). `FindingMarketConfig.purchase` and
  `.failed_delivery` pins exist but nothing signs under them; the config
  gains a purchase-authority signing seed (precedent:
  `admission_signing_seed_path`), the coordinator verifies the seed's public
  key equals the pin, and activation-time verification additionally
  cross-checks the admission's embedded purchase/failed-delivery key policies
  against the config pins (currently unchecked).
- D9 (encumbrance). Seller exposure is a new per-purchase encumbrance ledger
  against the consumed collateral allocation:
  `sum(open) + k * accepted_price <= maximum_sale_exposure_units` checked
  inside one Immediate transaction (concurrent overcommit rejects), released
  on unsuccessful sale, retained through the liability horizon after capture.
  The unbatched v1 payout profile caps one liability horizon at 15 distinct
  immutable rail-tagged buyer destinations, the sixteenth slot reserved for
  the admission-pinned community-fund destination; a repeat purchase to an
  already-admitted destination consumes nothing.

## Program constraints binding every task

- Ship dark: every surface stays behind `cognition-market-experimental`
  (control-plane, store, open-market already forward it; `chio-cli` gains the
  feature). The default build must not link the market.
- Fail-closed everywhere; no ambient lookup may fill an omitted authority
  artifact; strict raw-first ingress for every buyer-presented artifact.
- No em dashes. Clippy `unwrap_used`/`expect_used` deny. Conventional
  commits. Comments never reference plans, milestones, or tasks.
- All amounts equal in units and currency end to end; "refund"/"reversal"
  vocabulary is reserved for captured money (M4's mismatch path has none).
- Every metadata block the finalizer attaches must be reproduced
  byte-for-byte by the replay lane (`completed_durable_tool_response`).
- `umask 022` for every cargo invocation.

## Files (verified seams)

- Constraint vocabulary: `crates/core/chio-core-types/src/capability/scope.rs:331`
  (enum), `:469` (attenuation); kernel-core `normalized.rs:538,642` and
  `scope.rs:193,339`; kernel `request_matching.rs:337-473`;
  `governed_validation.rs:151-237`; issuance `scope.rs:94-107`.
- Mint seam: `crates/economy/chio-open-market/src/bidding.rs:287-303`
  (`BidMintContext`), `:397` (`constraints: Vec::new()`), `:410`
  (`dpop_required: None`), `finding_admission.rs:357`
  (`bid_with_finding_admission`), `accept()` at `:440`.
- Coordinator siting: `trust_control/finding_handlers.rs` (strict ingress
  `:145-201`, `finding_market_context` `:122`), `service_types/finding_market_config.rs:111-112`
  (unused purchase/failed-delivery pins), router `:707-748`, state wiring
  `service_runtime/init.rs:66-88`, store accessor `serving_owner.rs:726-733`.
- Purchase store: sibling module to
  `crates/platform/chio-store-sqlite/src/finding_market_store.{rs,sql}`
  (schema catalog `:1565-1591`, anchors `:40-41`, allocation lifecycle
  trigger forbids consumed transitions so encumbrance state is a new table).
- Kernel: pre-dispatch gates `async_evaluation_core.rs:904-947` (mirror
  `nested_flow_evaluation.rs:728+`), hook plan freeze
  `admission_coordinator.rs:259-288,961-1009` (`frozen_steps` step 0 is the
  synthetic materialization step, so "empty hook plan" is
  `hook_identities.is_empty()`), DPoP `async_evaluation_core.rs:289-307`,
  durable contract `terminal.rs:452-529`, finalizer decision `:1374-1410`,
  metadata merge-last + forge check `:1747-1796`, replay reproduction
  `:531-693`, `ImmutableToolAdmissionRequest` `admission_coordinator.rs:231-243`.
- Metadata registry: `chio-core-types/src/receipt/metadata.rs:200-278`;
  PROTOCOL 6.4 table; `spec/schemas/registry.json`;
  `signed_artifact.rs` SIGNED_ARTIFACT_SCHEMA_SPECS for signed families.
- Lineage: `chio-core-types/src/receipt/lineage.rs:211-367`,
  `receipt_store.rs:814-829` (default no-op persistence hook, sqlite impl
  exists), memory classification `memory_provenance.rs:485-520`.
- Verdict matrix: manifest counts 60 across 5 classes; M3 rotation commit
  `cf2c59e8e` is the exact file checklist; wasm stays capability-only.
- Exit harnesses: `finding_market_exit_tests.rs` (MarketWeb/MarketStack,
  bid leg at `:1674-1763`), `durable_admission_sqlite.rs` (three-lane M3
  test, payment adapters, restart pattern), open-market
  `tests/cognition_market_flow.rs` (ignored reveal spec to supersede).
- CLI: `cli/types.rs:289` (Commands enum), `dispatch/mod.rs:164-283`,
  family precedent `chio trust liability-market`; `chio-cli` needs the
  feature plus real market deps (open-market is dev-only today).

## Invariants (repeated at every enforcement point)

1. A marked reveal admits only under: exactly one matching DPoP-bound
   one-invocation grant carrying exactly one `OutputDigestSha256` equal to
   `finding.payload_sha256` and exactly one `RequireFindingPurchase` whose
   ids and selector match the verified context; a typed `finding_id` argument
   equal to the marker; an empty post-invocation hook plan; the qualified
   `HoldCapture` + `ReversibleHold` profile; a verified, slot-reserved
   authoritative reservation. Anything else denies before nonce, debit,
   authorization, or dispatch.
2. The signed `Finding` is the anchor: `finding.payload_sha256 ==` the token
   digest constraint, the pricing scope names `finding.finding_id`, the token
   presented is byte-identical to `ask.body.token_offer`, and every economic
   party is the Finding issuer or covered by the exact signed seller
   authorization.
3. Money: capture only after digest and media checks pass and the replayable
   Allow template is durably staged; mismatch releases the exact open hold,
   captures zero, and never calls it a refund; every failure terminal leaves
   funds, payload, nonce, budget, and collateral in a documented idempotent
   state.
4. Liveness is a caller check (`issued_at <= now < expires_at`) re-run at
   purchase time; a future-issued finding rejects.
5. Buyer ingress of any overlay artifact is strict-raw-first: bound, parse
   canonical bytes, schema-validate, typed round-trip, byte equality, then
   verify.

## Resolutions recorded during implementation

- D2 needed no new admission-hash field: `ImmutableToolAdmissionRequest`
  already includes `governed_intent`
  (`admission_coordinator.rs:238`), so the carrier is frozen into the
  immutable request hash and durably recoverable through the raw
  invocation blob's canonical request JSON with zero kernel schema
  changes. Replay under different carrier bytes already fails closed.
- The preallocated `purchase_intent_id` and
  `authoritative_payment_operation_id` derive deterministically from the
  reservation id under domain-separated digests
  (`chio.finding.purchase-intent.v1`, `chio.finding.payment-operation.v1`),
  fixed at reserve time. This keeps the finalizer's pure re-derivation
  self-sufficient while the coordinator store stays authoritative; the
  admission-time check verifies the store rows carry exactly the derived
  identities.
- The purchase verifier seam is split into a deterministic half (replayed
  by the finalizer from the frozen request; no clocks, no store reads)
  and an admission-time half (liveness bounds plus authoritative
  reservation state), so recovery can never diverge from admission on a
  frozen operation.

## Task 1: `RequireFindingPurchase` constraint carrier

- Add `FindingSettlementSelector` and `FindingPurchaseMarkerV1` plus the
  `Constraint::RequireFindingPurchase` variant with doc comments; explicit
  exact-equality attenuation arm.
- Fail-closed handling at every seam: normalized TryFrom unsupported list +
  name fn; portable scope matcher reject list + name fn; request_matching
  carrier arm (admission checks the typed `finding_id` argument equals the
  marker id: missing, wrong, duplicate, or wrong-typed fails the match) plus
  the `Custom("require_finding_purchase", _)` downgrade rejection;
  governed_validation explicit no-requirement arm; issuance
  economic-sensitivity list.
- PROTOCOL.md constraint vocabulary documentation.
- Regressions: attenuation identity, portable rejection, downgrade spelling,
  argument-equality matrix.

## Task 2: Purchase artifact and metadata types

- `chio-core-types`: `FINDING_DELIVERY_METADATA_KEY = "finding_delivery"`,
  `FINDING_DELIVERY_SCHEMA = "chio.finding.delivery.v1"`, typed overlay
  struct (`finding_id`, `listing_id`, `transform_profile: identity`,
  `digest_check`, `media_type_check`, purchase/reservation binding digests,
  settlement selector echo) with portable `validate()`; PROTOCOL 6.4 row;
  wire schema + registry entry.
- `chio-finding`: `chio.finding.purchase-context.v1` carrier (all fifteen
  members; token carried as canonical bytes so byte-identity to
  `ask.body.token_offer` is checkable; `deny_unknown_fields`; strict
  raw-first constructor with both size bounds),
  `chio.finding.purchase-record.v1` (purchase_key =
  `H("chio.finding.purchase.v1", accepted_bid_envelope_digest, authoritative_payment_operation_id)`,
  buyer/payer, admission envelope digest, accepted and realized spend,
  backing/encumbrance, delivery and payment evidence, immutable rail-tagged
  destination), and `chio.finding.failed-delivery.v1` (D6 fields). Schemas,
  registry rows, signed-artifact registration for the two signed families.
- Golden fixtures for the new artifacts following the deterministic-seed
  pattern.

## Task 3: Open-market mint and accept extension

- `BidMintContext` gains `grant_constraints: Vec<Constraint>` and
  `dpop_required: Option<bool>`; `bid()` threads both into the minted grant.
- Finding-aware mint validation in the admission seam: for a finding
  listing the provider mint must carry exactly one digest constraint equal to
  `finding.payload_sha256`, exactly one marker with the admitted
  finding/listing ids and the local selector, `dpop_required: Some(true)`,
  requested and minted `max_invocations == Some(1)`, and price ceilings equal
  to the accepted price. Missing, duplicate, conflicting, or out-of-profile
  mints reject.
- Finding-aware accept wrapper requiring exact amount equality and the
  Finding cross-bindings before delegating to the unchanged pure `accept()`.
- Buy-time liveness re-check (both bounds) with a future-issued rejection
  test.

## Task 4: Purchase store

- New sibling store module + schema (same `open_alongside` single-connection
  fenced-write shape): `purchase_reservations` (reservation id =
  compatibility receipt id, purchase_intent_id,
  authoritative_payment_operation_id, payer public key, canonical bid and
  ask digests, venue-admission envelope digest, listing/finding, amount,
  currency, expiry, state open/consumed/released/expired),
  `seller_exposure_encumbrances` (allocation-keyed, D9 checked sum, state
  open/released/retained), `pending_purchase_slots` (listing-scoped
  monotonic ordinal, state reserved/closed-record/closed-deny),
  `purchase_records` and `failed_delivery_records` (canonical signed
  artifacts, content-addressed), `payout_destinations` (liability-horizon
  slot cap with the reserved community-fund slot).
- Two-phase idempotency copied from the fee-event precedent: durable intent
  row before any effect, exact-parameter replay, conflicting parameters
  under the same key reject.
- Schema catalog GLOB list + anchors extension; allocation expiry and
  release transitions (states exist today with no writers).

## Task 5: FindingPurchaseCoordinator

- New feature-gated `trust_control` module + routes: reserve (after
  `bid()`, before `accept()`) and release/expire. Buyer-key authentication
  by signed request under the token-subject key; venue admission re-verified
  and its envelope digest frozen; D8 pin cross-checks; preallocated ids;
  atomic budget + exposure reservations; compatibility
  `SignedReservationReceipt` signed under the purchase authority only after
  the rich record commits.
- Reveal support: resolve-by-`bid_receipt_id` returning the same
  preallocated identities; slot reservation before dispatch; slot close
  (record or Deny) after the kernel terminal; D6 phase two signing.
- Idempotent cancel/release under every failure terminal and on expiry.

## Task 6: Kernel purchase gate and finding finalizer

- `FindingPurchaseVerifier` trait + setter + verified-binding type; D3
  fail-closed wiring in both evaluation lanes before nonce, budget, payment
  authorization, or dispatch: marked grant requires installed verifier,
  successful strict verification, marker/argument/digest equality, empty
  hook plan (`hook_identities.is_empty()`), DPoP, and the qualified
  reversible profile (the M3 gates already deny non-durable, non-reversible,
  mustprepay, and no-output lanes for digest carriers; extend the begin
  refusal to the marker).
- D2 durable carrier binding (optional digest field in
  `ImmutableToolAdmissionRequest`, replay fail-closed).
- Finalizer: D4 media check with the new denial reason; `finding_delivery`
  overlay built only from kernel-verified facts, merged last with the forge
  pre-check, reproduced byte-for-byte in the replay lane; the staged Allow
  template (validated output, frozen bindings, nonce, timestamp, signer
  epoch, metadata) persists before capture.
- Seller-origin envelope non-mutation assertion at finalization (frozen
  empty plan revalidation plus canonical-bytes equality of the resolved
  output with the recorded seller-origin blob).

## Task 7: Reference server, recovery mint, and ingestion lineage

- Reference `read_finding` tool server (small feature-gated module in the
  open-market crate) serving sealed payload bytes as the exact reveal
  envelope; buyer-blind; registered via `register_tool_server` in tests and
  the CLI local-kernel path.
- D7 recovery mint function verifying the checkpointed original Allow plus
  buyer DPoP binding before minting the zero-ceiling recovery grant;
  recovery-to-original-delivery lineage edge.
- Purchased-payload ingestion: governed memory write followed by a signed
  `ReceiptLineageStatement` (parent = delivery receipt, child = memory-write
  receipt, `LocalChild`) persisted through the existing store hook with the
  write-capability binding alongside.

## Task 8: `chio finding` CLI family

- New feature on `chio-cli` forwarding to the market crates;
  `Commands::Finding { publish | search | verify | buy }` following the
  liability-market precedent (types + dispatch + cmd fns). `verify` runs the
  M2 `FindingEvidenceVerifier` and prints every facet; `buy` drives
  bid/reserve/accept/reveal against the control plane plus a local kernel
  and repeats the digest and media checks client-side before interpreting
  bytes (usability backstop only).
- The module name avoids the existing guard-market `market` module.

## Task 9: `finding_purchase` verdict-matrix class

- Twelve scenarios: provider mint rejects an absent required marker;
  malformed marker fails closed; unknown selector fails closed;
  finding/listing mismatch; missing purchase artifacts with the marker
  present; alternate-token substitution; unmarked generic digest call earns
  no finding overlay; portable profile rejects the marker; argument
  mismatch; media mismatch deny; matched purchase Allow; mustprepay
  rejection.
- Full M3-precedent rotation checklist: scenarios + manifest counts and
  hash re-pins (60 -> 72), `ScenarioCategory::FindingPurchase`, driver
  script fields + pure evaluator (fail-closed deny for every driver without
  purchase-aware admission), reason URNs in `spec/errors/registry.yaml` +
  regenerated error codes, Python/Go drivers and SDK count tests, wasm
  exclusion preserved, docs (SCENARIOS.md, ARCHITECTURE.md, conformance
  doc).

## Task 10: Exit tests and gate

- `cognition_market_wedge_purchase_e2e` (control-plane, extends
  MarketWeb/MarketStack past the existing bid leg): publish -> collateral ->
  activate -> search -> verify facets offline -> reserve -> accept ->
  reveal on a real durable kernel with the reference server -> governed
  memory write + lineage -> delivery receipt carrying both blocks plus
  exact budget/hold/capture and encumbrance state.
- Failure lanes (kernel harness + coordinator harness): digest mismatch
  (failed-delivery standing, two phases, checkpoint-outage delay), wrong
  media, seller down, predispatch abort, postdispatch ambiguity (stays
  pending, never called a refund), buyer crash after Allow + recovery grant
  replay, underquoted price, wrong currency/payer/payee, alternate token,
  wrong request argument, copied listing, missing/stale admission,
  mustprepay/PrepaidFinal/legacy/x402 rejection, collateral overcommit,
  destination slot cap, cutoff/capture race, restart recovery replay
  byte-equality.
- One CLI round trip; the ignored open-market reveal spec superseded.
- Full qualified workspace gate at branch HEAD; feature-off build proves the
  market stays dark. Record exact results here under "Recorded results".
- Update the PLAN.md ladder row for M4.

## Recorded results

- All ten tasks landed on `codex/cognition-market-m4` (stacked on the M3
  branch). `cognition_market_wedge_purchase_e2e` plus eleven failure-lane
  tests are green: the full sale on one durable authority store (publish,
  collateral, activation, search, admission-gated provider mint,
  buyer-authenticated reservation with slot ordering, exact-amount
  accept, purchase-context carrier, DPoP-bound reveal on a real durable
  kernel, both kernel-owned receipt blocks, a single capture, the signed
  purchase record with retained exposure and an admitted payout
  destination, the governed memory write with its signed local-child
  lineage statement, and a byte-identical restart replay), and the
  digest, media, context, verifier, token, argument, and rail denials,
  buyer-signature and idempotent-reserve behavior, allocation
  overcommit, and the no-charge recovery redelivery.
- Gates at branch HEAD: chio-kernel lib 898 and durable suite 6;
  chio-store-sqlite feature lib 806; chio-control-plane feature lib 452;
  chio-open-market feature suites (75 across bins) and chio-finding 108;
  verdict matrix workspace 89 with the corpus at 72 across six classes
  and rust/python/go drivers plus SDK counts rotated; chio-cli feature
  suite 1146 with the default build linking none of the market crates;
  full default `cargo build --workspace` clean; clippy `-D warnings` and
  rustfmt clean on every touched crate. One store-suite failure during a
  concurrent-agent load spike did not reproduce on a quiet rerun.
- The M3-deferred pre-dispatch cancel defect was load-bearing here and is
  fixed: the payment-journal schema now accepts the closed state
  `CancelBeforeAuthorization` has always produced, and a pre-dispatch
  compensation validates its journal as cancelled or released instead of
  demanding a payment-terminal record. Two implementation defects the
  exit lanes caught were fixed with them: the purchase key now derives
  from the accepted-bid envelope digest, and the delivery finalizer
  resolves the exposure encumbrance by its reservation key.
- Documented deviations: the purchase coordinator is an in-process
  control-plane seam and the HTTP purchase routes are deferred, so
  `chio finding buy` registers its full surface but refuses cleanly until
  that wiring exists (the CLI round trip covers publish, search, and the
  thirteen-facet verify; the buy and reveal legs are proved by the
  in-process exit flow). Denial slot-close commits atomically with the
  signed standing artifact after the checkpoint, so a checkpoint outage
  delays the cutoff slot rather than leaving an unclosable one; closure
  stays recovery-guaranteed from the durable kernel terminal. A real
  deployment constraint surfaced by the lanes: the ask and token minter
  must be the finding issuer or the authorized seller named by the
  issuer-signed authorization.

## M4 exit criteria

1. `cognition_market_wedge_purchase_e2e` plus the CLI round trip are green
   and prove every clause above, including both failed-delivery phases and
   recovery replay.
2. Every kernel `Constraint` match is exhaustive; portable and downgrade
   spellings reject; the marker never rides an unqualified settlement lane.
3. The four new schema families are registered with
   schema/registry/manifest/PROTOCOL parity and strict-ingress validators.
4. The `finding_purchase` rotation is green across rust/python/go drivers
   and SDK counts, with wasm capability-only preserved.
5. The full qualified workspace gate passes at branch HEAD; the default
   build does not link the market.
6. Deferrals (cross-org, status_proof, transform-aware, kernel read-result)
   are recorded, not silently dropped.
