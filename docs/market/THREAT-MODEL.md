# Cognition Market Threat Model

- Status: threat model for the implemented single-operator market and
  hosted profile. Cross-organization escrow remains conditional and
  unbuilt; its sections analyze the conditional design.
- Scope: the finding market designed in [ARCHITECTURE.md](ARCHITECTURE.md) and
  [ADR-0017](../adr/ADR-0017-cognition-market-finding-artifacts.md), both
  instances (coding-agent verified fixes; R&D negative results)
- Method: assets -> trust assumptions -> adversaries -> attack catalog with
  mitigations mapped to shipped primitives (paths cited) -> residual-risk
  register. Severity is rated for the wedge instance first, vision instance in
  parentheses where different.

## 1. Assets

- A1. Finding content (the sealed payload) - confidentiality until paid
  reveal; integrity against substitution.
- A2. Buyer funds - target invariant: no capture without a kernel-attested
  reveal of the finding's committed digest (an Allow proves kernel
  acceptance of the preimage, not buyer receipt/retention - ARCHITECTURE
  6.2; the post-Allow crash window is F3 step 6). Artifact integrity alone
  does not enforce this invariant. The generic delivery contract establishes
  constraint-digest equality; the purchase chain binds that constraint and
  provider grant to the verified signed `Finding`. ADR-0019 excludes both
  reserve-for-caller `MustPrepay` and `PrepaidFinal` from the purchase
  profile. Any later compensated prepaid profile
  is a separate version and cannot weaken the v1 no-capture-on-mismatch rule.
- A3. Seller bond - no slash without a predeclared, evidence-gated rule.
- A4. Market truthfulness - listings, evidence bundles, and status feeds mean
  what they claim (evidence-class discipline).
- A5. Buyer memory/state - purchased content must not poison the buying
  agent's memory beyond what its ingestion policy allows.
- A6. Reputation capital - scorecards and tiers must not be inflatable below
  the cost of honest behavior.
- A7. Encumbered collateral and fee pools - one live bond allocation cannot
  back several listings or challenges, finalized fraud exposure cannot outrun
  remaining slashable collateral, and participation or dispute fees cannot be
  spent before they are actually collected.
- A8. Financial terminal state - every failure, timeout, mismatch, appeal,
  release, refund, compensation, and restitution path must be signed,
  replay-stable, and bound to the same purchase and payment evidence.

## 2. Trust assumptions (inherited and new)

Inherited from Chio and unchanged (the market adds no new crypto):

- The kernel is the TCB; receipts prove kernel-observed events, not world
  states (`spec/PROTOCOL.md:1001-1004`).
- The audited assumption registry applies (Ed25519, SHA-256, canonical JSON,
  clocks, SQLite atomicity, TLS, chain finality; `docs/reference/CLAIM_REGISTRY.md`).
- Guarantee levels and evidence classes are truthful or the artifact is
  rejected (`crates/core/chio-core-types/src/receipt/authoritative_spend.rs`,
  P10 never-upgrade discipline).

New trust roles the market introduces, stated explicitly:

- T1. **The mediating kernel sees revealed content.** WYSIWYS signing is
  constructed from the exact output preimage
  (`crates/core/chio-core-types/src/receipt/signing.rs:273`), so whichever
  kernel mediates the `read_finding` call observes the plaintext payload.
  Within one operator this is the existing trust model. Cross-org, the
  mediating operator learns purchased findings. A separately qualified
  TEE-hosted kernel can reduce but not eliminate operator exposure. Current
  TDX verification does not compare runtime measurements to an allowlist or
  provide a full vendor-attestation stack, and kernel boot exposes an injected
  verifier port rather than production backend wiring, so neither is a
  blanket confidentiality claim. This is a designed-in TTP, not an oversight.
- T2. The finding-status feed operator (revocation-oracle instance) is trusted
  for liveness and completeness of voluntary/cross-operator retractions.
  Root authenticity, equivocation, and staleness are checkable via
  signatures, freshness windows, and anchoring, but a fresh root alone cannot
  prove the operator included every authenticated intent
  (`crates/trust/chio-revocation-oracle/src/api.rs:86,116`,
  `src/freshness.rs`). The single-operator enforced-challenge path narrows
  this trust with a durable outbox and purchase-pending gate. The status
  feed also requires
  a live operator bond, signed inclusion SLA, monitoring, and a
  latest-observed `(map_epoch, epoch_id, root_hash)` floor; these make
  omission, rollback, and same-epoch equivocation punishable or detectable,
  not impossible.
- T3. The adjudication roster for non-mechanical disputes (ADR-0015 follow-up
  B; `crates/economy/chio-market/src/claim.rs:38-50`). Mechanical rules
  (digest mismatch, evidence re-verification, deterministic replay) minimize
  what this role decides.
- T4. The crypto-context signer for any future hidden-predicate claim
  (`crates/trust/chio-disclosure-lineage/src/types.rs:93`). The finding
  profile does not currently define a canonical predicate carrier or bind a
  capsule/report digest into `chio.finding.v1`, and the buyer proof boundary
  rejects hidden range predicates. Therefore integrity and admission treat
  descriptor
  fields such as `outcome_class` as public assertions backed only by the
  declared evidence class. No hidden-predicate claim is admissible until a
  future version defines the canonical predicate and capsule digest, pins
  the trusted signer and proof profile, and the buyer verifier resolves and
  validates that exact proof without upgrading its guarantee.
- T5. The challenge settlement operator is trusted to derive and enforce
  the harmed-party destination allowlist from frozen purchase records. Its
  signed Finding enforcement authorization makes the decision attributable
  and replay-stable, but the current bond-vault contract checks only
  distribution shape, at most 16 nonzero beneficiary addresses, amount
  bounds, and exact-sum shares. It does not recognize harmed buyers or the
  community fund. Until ADR-0015 follow-up A adds a structural contract
  restriction, a compromised operator can still authorize an otherwise
  well-formed wrong destination. Pre-sale market terms therefore pin the
  community-fund identity, rail destination, and governing registry or root,
  and the residual remains explicit.

## 3. Adversaries

- SELLER: wants payment for worthless, fabricated, stale, or stolen findings.
- BUYER: wants the finding without paying, or wants to damage sellers.
- COLLUDING RING: seller+buyer or seller+challenger pairs, or sybil clusters,
  gaming reputation/adjudication/price signals.
- MARKET OPERATOR: rational-but-greedy or compromised: front-running, leaking,
  censoring, equivocating.
- OBSERVER: outside party mining listings/receipts/lineage for competitive
  intelligence.

## 4. Attack catalog

Format: attack -> mitigation (mechanism, path) -> residual.

Implementation boundary: cited Chio primitives may already ship, but their
cognition-market compositions below are proposed unless explicitly marked.
Artifact integrity does not authenticate evidence or liveness, validate
bond or status
references, enforce reveal delivery or settlement, run challenges, or close
the seller, buyer, collusion, operator, or observer attacks cataloged here.
Its `verify_finding` boundary proves only strict artifact structure,
content-address integrity, and the inline issuer signature.

One explicit `FindingEvidenceVerifier` profile is required before any
listing is advertised as verified. Its raw-byte-first ingress rejects
duplicate-key/non-I-JSON input and schema/typed-model divergence, and rejects
noncanonical spelling only when the endpoint compares raw bytes with its
canonical form. It then independently
resolves and verifies receipt bodies and signatures, checkpoint membership,
trusted-kernel and revocation state, receipt attribution metadata,
authenticated signed capability snapshots and transport/provider identity,
artifact and evidence liveness, guarantee/evidence-class compatibility, the
replay recipe, and the live listing-bond allocation. A receipt-lineage
statement relates receipts, requests, and session anchors; it is not an
issuer, subject, or delegation proof. Seller authority therefore requires a
separate issuer-signed authorization or delegation carrier bound to the exact
Finding, listing, seller, scope, validity interval, and revocation state.
The verifier reports cost backing only in full-receipt mode after all
receipt-authenticity and checkpoint-membership facets pass.
`metered_exposure_backing` verifies the admitted kernel, mediated reconciled
exposure, matching signed nonce, and exact-currency checked sum.
`settled_spend_backing` additionally requires qualifying captured payment or
finalized settlement evidence. The first is a lower bound on kernel-accounted
metered exposure; the second is a lower bound on kernel-accounted settled
spend. Neither proves paid work, honest computation, or total effort.
A projected disclosure may authenticate its projection and disclosed fields,
but it cannot inherit the originals' receipt-authenticity,
checkpoint-membership, or either cost-backing facet; projected-mode cost
remains an assertion. A projection is authoritative only under the externally
pinned BBS issuer fingerprint/key, epoch, trusted registry, validity,
rotation, and revocation policy in the reusable verifier profile; its
embedded issuer key cannot self-authorize. An intent
reference earns its priced facet only after its atomic receipt/checkpoint
proof pre-dates production through a pinned log sequence or admitted anchored
cross-log relation, and its parameter hash commits to the versioned
descriptor, canonical context, replay-recipe digest, and protocol digest. The
verifier returns a facet report with distinct integrity, evidence,
metered-exposure, settled-spend, intent, collateral, and liveness results.
Missing facets fail the policy that requires them and are never silently
upgraded.

### Seller-side

- **S1. Fabricated evidence bundle** (invented receipts, wrong checkpoint).
  Without the evidence verifier this remains HIGH, and an integrity
  signature must not be described as evidence verification. Mitigation: the
  explicit
  `FindingEvidenceVerifier` above re-verifies receipt bodies and signatures,
  checkpoint inclusion, trusted-kernel and revocation state, receipt
  attribution against authenticated signed capability snapshots and validated
  transport/provider identity, the separate issuer-signed seller
  authorization, guarantee class, and liveness fail-closed, following the
  existing claim-verification pattern
  (`crates/economy/chio-market/src/insurance_flow.rs:390-414`; buyer boundary
  `crates/trust/chio-attest-buyer/src/api.rs`). Under the challenge lane,
  an enforced finding
  fraud outcome maps to the frozen v1 `FraudulentListing` class and carries
  exactly one `External` evidence reference to the signed
  `chio.finding.challenge-outcome.v1`. Its reference id equals the
  deterministic `outcome_id`, and its digest covers the complete canonical
  signed envelope. The finding-aware wrapper resolves and re-verifies that
  exact envelope, including the outcome signer role pinned by the admitted
  verifier profile, before a generic Sanction case is evaluated. Only a
  successful `evaluate_generic_governance_case` result with the expected
  effective state, admission block, and no findings may enter the ordinary
  penalty evaluator
  (`crates/economy/chio-open-market/src/evaluation.rs:356-451`). Missing,
  duplicate, wrong-kind, wrong-signer, or unrelated evidence references deny.
  Residual after verification and challenge: audited trust in the
  kernel/checkpoint/issuer key set
  and the evidence resolver. An authentic receipt proves a kernel-observed
  event, not that it semantically establishes the Finding's context or
  outcome; the evidence
  facet is positive only when the versioned recipe/context mapping binds the
  receipt action, inputs, and output evidence. Resolver unavailability is an
  availability-SLA failure, not seller fraud. Later key revocation or a later
  retraction is stale-status evidence, not proof the artifact was fabricated
  at publication. The mechanical fraud lane therefore requires affirmative
  cryptographic invalidity or proof that the referenced evidence was already
  invalid at publication. Current residual: high.
- **S2. Honest-cost fabrication** (seller really burns the compute, claims a
  wrong result). The unverified `evidence_cost` field is an issuer
  assertion. In full-receipt mode,
  a full-receipt listing can establish `metered_exposure_backing` after strict
  receipt-signature and checkpoint verification, semantic context/recipe
  binding, the complete authoritative-spend predicate, and verification of
  the matching kernel-signed nonce and mediated reconciled exposure. The
  verifier sums exact-currency financial fields with checked arithmetic. It
  establishes the stronger `settled_spend_backing` facet only when qualifying
  capture or finalized-settlement evidence also verifies. Realized tool cost
  can itself be server-reported, so neither facet is proof of paid work,
  honest computation, useful output, or total economic value burned.
  Projected evidence cannot claim the originals' receipt-authenticity,
  checkpoint, or cost facets and still asserts cost until an audit resolves
  and verifies the originals. Neither mode proves semantic correctness. A
  verified pre-outcome
  intent receipt proves only that one protocol/context commitment pre-dated
  the cited run; it does not prove publication completeness, stop many
  parallel commitments, or show that unfavorable results were published.

  For `deterministic_replay`, the challenge lane provides bonded challenge
  re-execution plus
  published-rate probabilistic audits sized so
  `audit_rate x slash >= expected fabrication profit` (MECHANISMS section 5).
  The canonical recipe must bind the purchased reveal-envelope digest and
  media type, the exact payload-application step, base/environment/corpus
  digests, runner/tool identity, bounds, and verdict predicate. The evaluator
  verifies checkpointed reproduction input/output receipts and emits the
  signed `chio.finding.challenge-outcome.v1`; a bare evaluation helper or an
  unbound rerun is not contradiction evidence.
  The venue must commit the eligible-set snapshot and randomness before
  selection and publish selection, attempt, success, and missed-audit
  receipts; otherwise the advertised rate is an operator assertion. Residual
  for `metered_attested` findings remains real and accepted, carried by
  bonds, guarantee-class discounts, and reputation rather than proof.
  Severity: medium for the deterministic instance under the challenge
  lane, high for the R&D instance and without it.
- **S3. Bait-and-switch payload** (serve bytes not matching the commitment).
  Mitigation: the generic delivery contract refuses an Allow receipt
  unless the final output hash equals its token constraint. Admission selects
  exactly one grant with exactly one `OutputDigestSha256` value, persists the
  `(grant_index, digest)` selection across restart, and rejects duplicate,
  conflicting, or multi-grant ambiguity. The purchase chain binds that
  provider-minted
  constraint to the strictly verified finding's `payload_sha256` and requires
  the marked v1 identity-output profile. It also checks that the canonical
  reveal envelope's `media_type` equals the Finding's
  `payload_media_type`; a digest-valid envelope with the wrong media type
  produces a persisted signed non-seller-fraud Deny and idempotently releases
  the budget/exposure reservation and reversible rail hold exactly once. It
  cannot Allow or capture funds. Because no capture occurred, this transition
  is not a refund or compensation.
  Because hooks have no static effect
  declaration, admission requires an empty post-invocation pipeline and pins
  that empty plan through finalization; every non-empty or changed plan is a
  signed non-slashable policy-incompatibility Deny with the same exact-once
  hold-release discipline. Tools without a defined output digest and
  side-effecting or unauthenticated tools reject before any budget/payment
  mutation. A digest mismatch itself must persist a signed Deny with the
  exact expected/observed digest metadata and exact-once reservation/hold
  release, never an Allow, capture, refund, or compensation.
  Only a kernel-authenticated seller-origin mismatch under that identity
  profile is `digest_mismatch` sanction evidence (ADR-0019 and
  ARCHITECTURE 4.3/6 define the terminal transition). The failed-delivery
  lane emits that signed Deny and exact-once hold release;
  `MustPrepay` and `PrepaidFinal` are therefore excluded from the v1 profile.
- **S4. Selling stale/retracted findings.** Mitigation: artifact expiry plus
  a registered portable non-inclusion proof whose bounded raw bytes the
  kernel verifies against the signed epoch, feed, nonce, finding, path, and
  freshness before reveal. Today's `NonInclusionProof` is checked against
  local oracle state and is not that portable proof
  (`crates/trust/chio-revocation-oracle/src/api.rs:110-116`). Artifact
  integrity has only expiry/status references. The status feed pins the
  outer and embedded root
  signers plus authenticated resolver to the same feed deployment and retains
  a per-feed/operator latest-observed
  `(map_epoch, epoch_id, root_hash)` floor, rejecting an older valid proof or
  an equal-epoch proof with a different id/root even inside its nominal
  freshness window. Residual with the status feed:
  retraction between proof and reveal (window-bounded), plus selective
  omission/completeness risk for external operators under O2; locally
  enforced outcomes remain purchase-blocked while their durable outbox is
  pending.
- **S5. Plagiarized finding** (listing someone else's payload). Target:
  Admission verifies receipt attribution metadata against authenticated signed
  capability snapshots and the validated transport/provider identity at the
  producing boundary. `ReceiptLineageStatementBody` carries receipt/request
  endpoints and session anchors, not a producing subject, capability
  delegation, or seller authorization, so it cannot establish this claim
  (`crates/core/chio-core-types/src/receipt/lineage.rs:228`). Listing
  activation records a separate issuer-signed seller authorization carrier
  that either names the exact Finding issuer as seller or delegates the exact
  finding, listing, delegate, scope, validity interval, and revocation domain.
  Purchase resolves current revocation state, re-checks that carrier, and requires
  the reveal provider, listing seller, and capability issuer to be the
  authorized issuer or delegate. The payment beneficiary must either be that
  same seller under `SellerExact` or exactly match an authenticated
  provider-signed seller-to-payee mapping bound to this listing. A copier
  cannot relist an unchanged signed Finding under its own provider or redirect
  proceeds.
  Residual: an authorized buyer can create a new wrapper Finding and new
  evidence over already revealed information. Descriptor and provenance
  collisions make that attributable, but information goods remain copyable.
  Medium residual.
- **S6. Listing spam / descriptor squatting.** Target mitigation:
  publication fee collection plus the live publication/listing allocation in
  S8. Fee and bond requirements already exist declaratively
  (`crates/economy/chio-fiscal/src/fee_schedule.rs:69`), but a declared
  fee has no spam cost until collection settles it and records the receipt. Existing
  `SpamPublication` penalties (`src/penalty.rs:21`) and namespace-owned
  listings (`crates/economy/chio-listing/src/listing.rs:103`) add enforcement.
  Current residual: high; after collection and allocation: low-medium,
  depending on fee and collateral sizing.
- **S7. Non-delivery after payment.** Single-operator profile: the
  purchase chain uses the ADR-0019 budget-reservation plus durable
  direct-evaluation `HoldCapture` / `ReversibleHold` profile. The
  reserve-for-caller
  `MustPrepay` path can capture a held payment before it returns the
  reservation, and `PrepaidFinal` is final; neither is a no-loss reveal rail.
  Reveal-time authorization/capture happens only after the final digest and
  media-type checks. Every crash/retry state is persisted and eventually
  reaches exactly one rail-hold terminal: exact-once release before capture
  on any Deny, or exact-once capture after a durably staged matched Allow.
  A mismatch cannot capture and its hold release is not a refund or
  compensation. A crash after capture resumes the staged Allow and recovery
  authorization rather than reversing the transfer. ACP-Client's local synthetic and x402 final prepayment do not qualify. Cross-org,
  the pre-accept authoritative reservation state
  binds the exact signed bid/ask, buyer, depositor or authorized sponsor,
  seller beneficiary, finding, listing, capability offer, preallocated
  purchase/payment ids, admission, settlement profile, consumed mediator
  backing, amount, currency/token mapping, chain, contract-derived escrow id,
  mediator, deadline, and finality policy. Only after `accept()` may the funded
  escrow witness add and bind the exact `SignedAcceptedBid` to that same state.
  The generic signed reservation receipt does not carry those facts. The
  settlement authority verifies the checkpointed
  delivery and signs its application decision, after which the profile-pinned
  kernel emits the standard settlement receipt and the typed escrow root is
  published. A delivery receipt alone is not a settlement-anchor receipt.
  With a seller-aligned
  mediating operator the attest-and-withhold attack (O5) remains HIGH, so the
  profile requires a neutral/mutually trusted mediator and operator bond or
  is disallowed (ARCHITECTURE F6). Escrow accepts only an unreleased escrow funded
  for the exact price and one full monetary terminal: release the full price
  or refund the full price after deadline. Partial or mixed terminals reject.
- **S8. Reused or undercollateralized listing bond.** A signed bond
  requirement or opaque `bond_ref` is not collateral. Activation must
  atomically create a live encumbrance bound to seller, listing, finding,
  requirement/class, currency, amount, and expiry, persist its allocation id,
  and reject stale, wrong-party, wrong-currency, or already-allocated
  collateral. A seller-signed liability policy sets nonzero claim, audit,
  appeal, and settlement horizons. Each captured sale retains
  `k * accepted_price`, with `k >= 1`, through that full horizon; concurrent
  purchase admission enforces
  `base_finding_stake + sum(open_encumbrances) <=
  min(locked_amount - slashed_amount,
  listing_requirement.required_amount)` atomically, separately enforces
  `sum(open_encumbrances) <= maximum_sale_exposure`, and requires bond expiry
  beyond sale time plus every liability horizon and buffer. Until
  deterministic batching exists, the EVM profile admits at most
  15 distinct immutable buyer payout destinations per liability horizon and
  reserves the sixteenth vault slot for a possible community-fund remainder.
  The admitted pre-sale terms pin that fund's identity, rail destination, and
  governing registry or root. Repeated purchases to one destination do not
  consume another slot.
  Residual: the chosen horizons and multiplier can understate tail risk,
  which must be disclosed rather than called fully bonded.
- **S9. Unsupported proof-profile upgrade.** A seller labels a public
  `outcome_class` or a disclosure capsule as a hidden, verified predicate even
  though the Finding commits to no canonical predicate/capsule digest and the
  buyer proof boundary does not support the claim. Admission rejects every such
  upgrade and reports only the facet it can verify. A future hidden-predicate
  profile must version the Finding schema, bind the canonical predicate and
  capsule/report digest, resolve the exact proof and signer policy, and reject
  unknown predicates or missing preimages. Residual today: no hidden claim is
  available, by design. Residual after an extension is trust in the pinned
  crypto-context signer unless new cryptography replaces it.

### Buyer-side

- **B1. Take the reveal, refuse payment.** Within one operator:
  target mitigation is a reveal that denies unless all purchase inputs arrive
  in the named, size-bounded
  `context.chio_finding_purchase_context_b64` carrier and strict raw parsing
  validates the exact signed Finding, venue admission, live bond allocation,
  seller liability/dispute terms, fee receipts, ask, bid, pricing,
  authorization, and reservation artifacts. The provider mint must name the
  exact `read_finding` server/tool, request one invocation, carry one digest
  and one `RequireFindingPurchase` marker with exact finding/listing ids plus
  a closed settlement selector, and bind the complete token offer from the
  signed ask, not merely token id/subject/expiry. Local mode rejects an escrow
  witness; cross-org mode requires its exact profile digest and witness key.
  Missing or conflicting rail evidence cannot fall back. The signed pricing
  hint's listing, provider, currency, and `finding:<finding_id>` scope, the
  ask digest, bid digest, listing price, ask quote, accepted quote, governed
  payment quote, budget reservation, authorization, and capture amount and
  currency all cross-bind by exact equality. Both capability ceilings are set
  to that price (`max_cost_per_invocation` and `max_total_cost`); a total-only
  ceiling can otherwise authorize a zero debit. Before any hold or dispatch,
  the actual request's typed `finding_id` must equal the marker and strictly
  verified Finding, and the listing/provider/payee must satisfy S5.

  The accepted-bid signer must be the token subject or resolve through one
  authenticated signer-to-subject mapping. The shipped
  `SignedReservationReceipt` body carries only `agent_id`, listing, ask digest,
  and reserved amount. It does not itself bind payer key, expiry, replay
  state, bid/finding identity, or funded state. A stronger authoritative
  reservation store and its authenticated finding-aware witness must bind the
  payer public key, original signed bid, listing, finding, ask, amount,
  currency, seller liability-policy digest, decision-rule refs, expiry,
  single-use state, and funding evidence. The signed generic receipt is only
  one input to that witness, not proof of the omitted facts.
  The grant has `dpop_required: Some(true)` and is one-shot. The current
  generic bid path leaves DPoP unset, so the purchase mint adds and
  requires that binding. A bounded recovery grant is separately
  bound to that buyer, purchase, delivery receipt, capability, and finding,
  has zero monetary ceiling and no capture authority, and permits only the
  predeclared retry count. Missing, wrong, alternate-token, duplicate-grant,
  replayed-reservation, or cross-purchase inputs deny before financial
  mutation. Today `bid()` mints a usable token before `accept()` verifies a
  reservation (`crates/economy/chio-open-market/src/bidding.rs:387-489`), so
  the current token alone proves none of these facts; the purchase
  profile supplies them.

  Cross-org fairness additionally requires the stronger authoritative
  reservation state, a configured settlement authority, a funded escrow
  witness, and the neutral mediating-operator profile in S7/O5. The generic
  reservation body is insufficient. A buyer-side operator can otherwise
  observe the reveal and withhold the checkpoint into a refund. Escrow
  remains blocked on its settlement ADR; even after a profile is selected,
  the residual is the
  mutually trusted mediator and settlement-authority model.
- **B2. Resale/republication after reveal.** NOT cryptographically
  preventable (information is copyable). Mitigations are economic and
  forensic only: provenance identifies the original producer (S5 logic);
  listing terms can declare license scope, enforced socially/legally, not by
  the protocol; pricing must assume post-sale leakage (see MECHANISMS on
  resale collapse). Residual: high by nature; the design prices it rather
  than denying it.
- **B3. Probing without purchase** (iterating descriptor searches or many
  cheap partial disclosures to reconstruct the finding). Mitigated: the
  descriptor is a deliberate, fixed leak (topic + context digest + outcome
  class only); anything richer must go through disclosure capsules with
  per-field leakage budgets and derived-inference ledger entries
  (`crates/trust/chio-disclosure-lineage/src/types.rs:63,205`). Residual:
  descriptor metadata itself has signal (existence of a dead end is
  information); sellers choose topic granularity accordingly. Medium.
- **B4. Malicious challenge to slash an honest seller.** Challenge admission
  is an exclusive `oneOf`. A buyer branch is signed by the buyer subject with
  class-specific purchase standing, locks a live Dispute-class allocation, and
  supplies the collected `dispute_fee` receipt. `evidence_invalid` and
  `replay_contradiction` require an authoritative finalized purchase record.
  `digest_mismatch` instead requires the purchase-authority-signed
  `chio.finding.failed-delivery.v1` binding the accepted bid, authoritative
  reservation/payment operation, released hold, checkpointed Deny, zero
  realized spend, and payout-ineligible state; no purchase record exists on
  that pre-capture terminal. The
  allocation authority, challenger, active schedule, class, amount, currency,
  expiry, and unspent state are verified and the lock is returned or
  forfeited exactly once. A venue-audit branch instead carries a signed
  authorization from the admitted scheduler and committed audit epoch and
  has no Dispute lock, dispute fee, forfeiture, or reward. Cross-branch fields
  reject; a string bond or audit reference is insufficient
  (`crates/economy/chio-fiscal/src/fee_schedule.rs:12`).

  Mechanical class rules and amount envelopes are predeclared. Every class
  uses the class-independent verdict `Upheld | Rejected | Indeterminate`.
  Only replay also carries the nested predicate result
  `ConfirmedContradiction | Consistent | Indeterminate`, mapped respectively
  to those top-level verdicts. The admitted outcome authority signs
  `chio.finding.challenge-outcome.v1` for every verdict so even a clean or
  unavailable result has a durable observation. Only an `Upheld`
  outcome may enter the penalty lane.
  `Indeterminate` produces no fraud, hold, Sanction, impairment, payout, or
  retraction and never forfeits for infrastructure or availability failure.
  It transitions to `IndeterminateRetryable` for at most one bounded signed
  retry window using the same challenge, fee, lock, profile, and evidence
  identity. Exhaustion or expiry produces the signed `IndeterminateClosed`
  terminal and returns the lock exactly once without a second fee.

  Every signed outcome is retained under its challenge and evidence dedup
  identities. Only an Upheld outcome contributes `External` evidence to one
  economic incident keyed by venue, chain/vault, concrete seller backing,
  listing, and Finding, rather than caller challenge/case, class, or evidence
  ids. Its `External`
  reference names the deterministic outcome id and digest of the complete
  canonical signed envelope; the admitted profile pins the buyer, audit,
  outcome, enforcement, purchase-record, and market-penalty signer roles. The
  penalty envelope signer, its `issued_by` identity, and
  `governing_operator_id` must all resolve to the one profile-pinned
  market-penalty authority and admitted governing operator. A generally
  trusted key with a different role or identity mapping rejects.
  Separate challenge/evidence dedup keys and a durable CAS incident head
  guarantee at most one seller impairment across classes while keeping
  challenge-bond disposition and external effects separately idempotent
  across duplicates, concurrency, and restart. The first Upheld transition
  linearizes, in the same authoritative transaction or CAS domain as purchase
  purchase finalization, the sales block, frozen purchase cutoff, and
  `Open -> UpheldPendingClaims` incident-head advance. Thus a concurrent
  purchase either finalizes before the cutoff and is included, or observes the
  sales block and cannot capture after the frozen snapshot.

  Buyer destinations and verified harm come only from the authoritative
  purchase records signed by the pinned purchase-record authority at the
  frozen cutoff, each cross-bound to delivery, original payment, realized
  spend, seller backing, and its immutable rail-tagged destination, never a
  caller address or newly resolved mutable mapping. Challenger-supplied
  victim refs are hints: the venue commits the
  authoritative eligible-purchase snapshot, accepts
  omission proofs during the claim window, and compensates each
  `purchase_key` at most once and never above authoritative realized spend. A
  venue without that index must disclose first-come and omitted
  victim risk. A failed buyer challenge can forfeit its bond to the harmed
  seller. A recognized venue audit is a separate signed authorization: it
  posts no Dispute bond, pays no dispute fee, and earns no reward. The
  restricted audit pool reimburses only checkpointed mediated re-execution
  cost. An independent successful buyer challenger may recover only capped,
  verified replay cost from an actually collected fee pool. Seller slash
  proceeds remain reserved for harmed buyers and the community fund.

  Appeals do not magically claw back a completed distribution:
  `ReverseSlash` changes penalty state but does not recover paid funds
  (`crates/economy/chio-open-market/src/evaluation.rs:385-431`). V1 therefore
  requires the new wrapper to compose exact typed transitions with successful
  generic governance evaluation: enforced Sanction plus `HoldBond` must
  produce `BondHeld`. A successful appeal must be an `Enforced` Appeal whose
  clean generic evaluation is effective `Appealed`, nonblocking, and has no
  findings. Both `appeal_of_case_id` and `supersedes_case_id` must name the
  exact original Sanction and current incident/admission head. The coordinator
  advances that head so the original Sanction no longer blocks admission, and
  `ReverseSlash` must supersede the exact held penalty for exactly the full
  unapplied hold. Appeal-final enforced Sanction plus `SlashBond` must produce
  `BondSlashed`. The generic penalty evaluator accepts Hold or Slash without
  enforcing the Finding branch's exact penalty-state compatibility and only
  caps amount at `required_amount`; the wrapper verifies the branch state,
  live allocation, and exact computed amount. A generic `Reversed` state is
  not enough.
  No appeal filing, a signed terminal `Denied` appeal, and an unresolved or
  expired appeal are three distinct states. Absence at the filing deadline
  must be proven from the authoritative appeal index; terminal `Denied`
  advances to finalization; `Open`, `Escalated`, unresolved, or merely expired
  appeal material blocks impairment until a signed terminal successor
  resolves it. The Sanction, `HoldBond`, and authority validity intervals must
  span the claim, appeal, and finalization horizons, or a signed successor
  protocol must extend them without changing the incident, allocation, and
  held-penalty bindings.
  At appeal-final upheld transition the coordinator first fences the signed
  enforcement state, `publication_pending`, and retraction outbox intent,
  then dispatches the separately idempotent impairment/distribution effect.
  The status outbox remains ineligible to publish until that exact impairment
  is confirmed final; failure, ambiguity, or quarantine keeps purchases
  blocked without appending an irreversible retraction.
  Post-impairment reversal rejects in v1; supporting a later correction
  requires a separate funded, idempotent restitution/compensation terminal
  and cannot restore an append-only retraction. Residual: griefing-cost
  tuning and the unsupported post-impairment correction case.
- **B5. Blame-the-seller memory poisoning** (buyer claims delivered content
  poisoned it). Target mitigation: the delivery receipt binds exactly what
  bytes were delivered (digest); ingestion is the buyer's own governed write
  under its own guards
  (`crates/guards/chio-guards/src/memory_governance.rs:60`). Delivery
  records a typed lineage edge from that memory-write receipt to the verified
  finding-delivery receipt. The quarantine resolver follows store/key
  to write receipt/capability, delivery receipt, Finding, and authenticated
  status, denying on broken lineage, stale/unavailable status, pending
  publication, or retraction
  (`crates/kernel/chio-kernel/src/memory_provenance.rs:63`). Residual:
  attribution depends on the typed edge and trusted local status cache;
  content-level harm remains buyer ingestion policy.

### Collusion and sybil

- **C1. Wash trading to inflate reputation** (self-dealing purchases).
  Target mitigation: activation and each audit epoch explicitly collect the
  seller's signed-schedule `market_participation_fee` into the restricted
  audit pool and emit its settlement receipt; declarative fee fields do not
  burn value. Only finalized, integrity-gated purchase and fee receipts count
  toward reputation
  (`crates/trust/chio-reputation/src/lib.rs:50-74`) and Tier3 requires two
  distinct evidence feeds (`src/tier.rs:98-139`); wash volume shows as
  self-referential lineage (same root budget holder,
  `delegation_depth`/`root_budget_holder` on financial metadata). Residual:
  a patient adversary can still buy reputation at the collected fee and trade
  cost. Projected `evidence_cost` and uncollected fees provide no floor,
  and even a verified full-receipt profile proves only kernel-accounted spend,
  not paid work, economic burn, or useful output. Medium-high until collection,
  medium afterward.
- **C2. Collusive challenge rings** (challenger and seller split slash
  proceeds). Mitigation: the challenge settlement coordinator derives slash
  destinations from verified harmed purchases or the registered community
  fund, never caller-selected payees (ADR-0015 D4; comptroller
  `market_slash` payee-check precedent,
  `crates/platform/chio-risk-comptroller/src/ledger.rs`). Exact-sum validation
  alone does not enforce this allowlist, so a signed Finding-specific operator
  authorization must apply it before impairment. The community-fund address
  and governing registry/root are pinned in pre-sale terms, and buyer
  destinations are frozen in signed purchase records. Challenge rewards
  come from a separate collected-fee pool under fixed destinations; venue
  audits earn no reward. The liability key prevents another seller
  impairment, and `purchase_key` caps each purchase payout.
  Effect-specific identities fence the single unbatched-v1 seller
  impairment by chain/vault/liability/allocation, challenge-bond effect by
  challenge/lock with disposition in a separately compared intent digest,
  fee challenge-or-audit-run/operation, and the pre-publication retraction
  intent by Finding/feed/`retraction_intent_id`. Epoch/root publication has
  a separate later publisher-attempt identity; one generic
  chain/vault/liability/effect-kind key is not reused across those domains.
  Residual: until ADR-0015 follow-up A, a compromised settlement operator can
  still sign an on-chain-valid but policy-wrong destination set because the
  vault does not structurally recognize harmed parties. Even with an honest
  operator, rings can manufacture apparent activity to capture fee-funded
  buyer replay reimbursements if audit selection or eligible purchase
  snapshots are operator-chosen; C4 closes that surface only under the
  challenge lane.
- **C3. Sybil seller farms** (many identities listing junk). Mitigated:
  per-identity live collateral allocations and collected publication fees;
  `BondBacked` admission class keeps unbacked listings review-only
  (`crates/economy/chio-listing/src/trust_activation.rs:565`). Residual:
  bounded by allocated bond capital only after S8's anti-double-pledge and
  exposure cap. Without admission those properties do not exist.
- **C4. Audit-selection gaming or subsidy extraction.** A venue can omit
  friendly listings, target rivals, claim a published rate it did not run, or
  use synthetic audits to drain a nominal fee pool. The audit lane requires an
  authenticated eligible-set snapshot, committed randomness, deterministic
  selection, and signed attempt/success/missed-deadline receipts. Audit
  spending is capped by a restricted pool of seller participation fees
  actually collected at activation and each audit epoch. A recognized audit
  carries no Dispute bond or dispute fee, transfers nothing on a clean result,
  and reimburses only verified execution cost, so it cannot create a
  failed-audit bond subsidy. Missed audits trigger the operator SLA rather
  than forfeiting a fabricated challenger bond. Residual: eligible-set
  completeness and randomness availability remain operator/governance
  assumptions unless externally witnessed.

### Operator-level

- **O1. Front-running / leakage by the mediating operator** (T1). Mitigated
  partially: a separately qualified measured-runtime deployment can shrink
  the operator's software-level access. The in-tree boot surface is an
  injected verifier port, and the current TDX backend lacks an
  expected-measurement policy, so those pieces alone do not earn that claim.
  Receipts and lineage make operator-side republication attributable (S5
  forensics). Residual: REAL for cross-org purchases
  mediated by an untrusted operator; the honest posture is that buyers with
  confidentiality-critical purchases keep them within trusted-operator or
  TEE-tier boundaries. Severity: medium (high for R&D instance with
  commercially explosive findings).
- **O2. Status-feed censorship or stall** (suppressing a retraction).
  The status-epoch artifact outer signature binds the feed, numeric nonce,
  operator, validity, anchors, `status_map_version`, and domain-separated root
  semantics. It reuses the existing signed-root envelope and signer type only,
  not the append-only tree's root meaning. Verification also pins the embedded
  root signer to that same operator. The strict portable proof binds the exact
  artifact digest, finding, root, sparse-map path, and freshness. Ordinary
  append-only Merkle roots and proofs from another map version/domain reject.
  The configured authenticated resolver must belong to that same pinned feed
  deployment. Stale roots fail buyers closed, and buyers/runtimes retain a
  monotonic latest-observed `(map_epoch, epoch_id, root_hash)` floor per
  feed/operator. A lower epoch rejects, and the same numeric epoch with a
  different id or root rejects, so an older valid proof or same-epoch fork
  cannot roll state back inside the freshness window. Signed, anchored roots
  make equivocation attributable.
  Neither an authentic root nor a valid non-inclusion path proves that the
  operator included every authenticated retraction.

  For locally enforced challenges, only the appeal-final upheld transaction
  persists an authenticated retraction outbox item and
  `publication_pending` gate before external effects; purchases deny until a
  signed epoch and inclusion proof clear it.
  Voluntary/cross-operator intents use signed retraction receipts, an
  inclusion SLA, monitoring, and the operator bond, but completeness remains
  an audited assumption. Residual: a dishonest external operator can publish
  fresh roots omitting an intent until detected; buyers can lose money during
  that window. Severity: high for the cross-operator profile, low for the
  durable single-operator outbox path.
- **O3. Status-feed equivocation** (different roots to different buyers).
  Mitigated: the outer and embedded signatures are cross-checked against one
  pinned operator, while feed, nonce, map version, domain, and validity are
  part of the signed artifact. Anchoring makes divergent roots globally
  detectable; signed roots make equivocation attributable and slashable
  under the operator bond. The latest-observed
  `(map_epoch, epoch_id, root_hash)` floor rejects rollback and same-epoch root
  substitution after either fork has been observed locally. Residual:
  first-observation clients can still accept an unanchored fresh fork until
  comparison, and detection lag equals anchor cadence.
- **O5. Seller-side mediating operator self-deals the reveal.** The
  minted token is bearer-shaped; a seller colluding with its own kernel
  operator could replay it, mint a "delivery" receipt with no buyer
  involved, and release escrow. Mitigated in part: escrowed purchases MUST mint
  `dpop_required: true` grants so the reveal requires the buyer's subject
  key (ADR-0007 profile) - closing the no-buyer replay. NOT closed by
  DPoP (review correction): attest-and-withhold - the mediator accepts a
  genuine buyer request, signs and checkpoints the Allow, suppresses the
  response, and releases escrow; DPoP proves the buyer signed the
  request, not that the response arrived. Therefore the escrow profile
  requires a neutral/mutually trusted mediator selected by the escrow's
  allowlist, plus the mediator's buyer allowlist, both cross-bound to
  `EscrowTerms`; with a seller-aligned mediator severity stays HIGH and the
  profile is rejected. Escrow is blocked on its settlement ADR. The
  current contract's alternative release methods can bypass an off-chain
  full-only and settlement-authority profile, so that ADR must choose a
  contract-gated profile
  or label the current path an audited, Experimental TTP profile without a
  non-discretionary guarantee. Neutrality alone gives the mediator no economic
  loss for withholding. The escrow profile therefore requires a governance-signed settlement
  profile and a bond-authority-signed, non-reusable mediator-backing
  allocation. They pin the mediator, contract path, token mapping, full-only
  terminal, objective checkpoint/root SLA, liability horizon, and penalty
  mapping. The bond can penalize objective checkpoint omission; it cannot
  mechanically prove response nonreceipt without a buyer acknowledgment that
  creates the inverse buyer-withholding problem. Response forwarding therefore
  remains an explicit trusted-mediator SLA.

  Before accept, the stronger reservation authority observes an initially
  unreleased, unrefunded, finally funded escrow for the exact bid and freezes
  that capital instruction. After the signed accepted bid exists, the
  settlement authority re-observes the escrow and signs the finding-aware
  witness. Across those two artifacts the flow binds the EVM depositor address
  or an explicitly authorized sponsor/delegation, capital instruction, refund
  destination exactly equal to the depositor and `createEscrow` caller,
  chain, contract-derived escrow id, finding, listing/purchase, capability,
  buyer, authorized seller beneficiary, mediator, amount,
  currency, token address/decimals/config epoch, deadline, and finality
  policy. Fee-on-transfer, rebasing, and other non-exact token behavior
  rejects. Absent, unfunded, wrong-binding, and reorged observations reject.
  The deadline lower bound covers grant validity and all three
  proof stages: delivery inclusion, settlement-authority receipt inclusion,
  and typed escrow-root publication, each through required finality, plus a
  safety margin. The escrow profile rejects `partialRelease*`, prior partial
  release, mixed or fractional terminal states, and amount drift: only full
  accepted-price release or full timeout refund qualifies. A separately
  operated timeout watchdog consumes trusted chain/time state and coordinates
  that terminal idempotently across restart and duplicate events. It is not
  implicit release authority: the contract requires the beneficiary caller,
  so that exact beneficiary address must submit the release; an operator
  settlement signature does not delegate caller authority. Timeout refund is
  permissionless only after the deadline. The shipped watchdog verifier also requires operator override, so
  it is not an independent liveness guarantee.
  A finding-aware settlement-authority decision binds the delivery proof to
  this escrow. The wrapper defines the standard receipt's
  `settlement_reference` as SHA-256 of the RFC 8785 canonical strict
  versioned preimage over the complete signed release envelope, funded
  witness, delivery proof, accepted bid, purchase context, settlement profile,
  and consumed mediator backing. A golden vector freezes that framing. The
  profile-pinned kernel then emits and
  checkpoints that standard settlement receipt, and the typed escrow root is
  published before beneficiary release. An admin pause can block release through the
  deadline while refund remains available, forcing seller loss. Rotation away
  from the operator key hash frozen in `EscrowTerms` likewise blocks release
  and drains only to deadline refund; the key must remain valid through
  terminal settlement or the event triggers the operator SLA/bond. A
  zero-value refund after full release may set the contract's refund flag;
  observers keep `released == deposited` as `FullReleased`, record the drift,
  and never authorize a second monetary terminal. Residual: the admin,
  mediator, settlement authority, chain finality, watchdog liveness, and
  operator-bond adequacy are explicit trust/economic assumptions; the
  escrow profile must test pause-through-deadline, key rotation,
  zero-refund drift, withhold-root, and withhold-response.
- **O4. Adjudicator compromise** (T3). Mitigated: predeclared rosters +
  decision-rule refs are validated fail-closed
  (`crates/economy/chio-market/src/claim.rs:38-50`), outcome sets and amount
  envelopes are fixed (ADR-0015 D5), and mechanical classes do not admit
  discretionary evidence substitution. A pending appeal blocks bond
  impairment. After distribution, reversal alone is not recovery; the
  correction is unsupported until the separate funded restitution design in
  B4 exists. Residual: roster governance and any future restitution solvency
  are institutional; minimized by keeping mechanical rules mechanical.

### Observer-level

- **X1. Competitive intelligence from public market surfaces** (who is
  buying which dead ends). Mitigated: listings reveal only descriptors;
  receipts are tenant-scoped with redaction and disclosure controls
  (`crates/observability/chio-log-redact`, leakage ledgers); cross-tenant
  reads fail closed (`--tenant`/`--admin-all` boundary, `README.md:113-118`).
  Residual: traffic analysis on public listings remains; sellers can list
  under coarse topics. Medium (low for wedge, where contexts are
  org-internal).
- **X2. Evidence-metadata side channel** (the generalized ZKCP lesson,
  MECHANISMS 8.1/8.6): the finding's public EVIDENCE leaks content - a
  tiny `evidence_cost` or short receipt chain screams "failed
  immediately", timing patterns can reveal which branch of an experiment
  space died, and cost profiles across a seller's listings map its search
  frontier. Mitigated: bucketed `evidence_cost` in public descriptors
  (exact values only inside the paid reveal), coarse timestamps, and
  leakage-ledger accounting for every descriptor field
  (`crates/trust/chio-disclosure-lineage/src/types.rs:205` vocabulary).
  Coupling caveat: full evidence receipts re-leak exact costs through
  their financial metadata, so sellers choose per listing between
  full-receipt and BBS-projected evidence modes (ARCHITECTURE F2 step 2);
  bucketing without projection is self-defeating. Projection can authenticate
  its own disclosed statement but cannot claim the concealed originals'
  receipt-authenticity, checkpoint-membership, or cost-backing facets.
  Residual: the existence of a listing is itself one bit that cannot be
  hidden; the existence tier (MECHANISMS section 3) prices that bit
  instead of denying it. Medium (higher for R&D).

## 5. Residual-risk register (ranked)

| Risk | Instance | Severity | Owner of residual |
|---|---|---|---|
| Fabricated evidence accepted without the evidence verifier (S1) | both | high | evidence-verifier profile; listing policy must not advertise integrity as evidence verification |
| Honest-cost fabrication of `metered_attested` nulls (S2) | R&D | high | pricing (guarantee-class discounts) + bonds; open research |
| Post-reveal resale/leakage (B2) | both | high-by-nature | pricing assumption; license terms out-of-protocol |
| Operator sees revealed content cross-org (O1/T1) | both | medium-high | deployment policy (TEE tier, trusted-operator scoping) |
| Purchase/token/reservation/payee bindings absent outside the purchase profile (B1/S5) | both | high | strict purchase profile and the ADR-0019 financial terminal |
| Listing collateral can be reused or outrun by exposure without admission (S8) | both | high | live allocation and atomic sales-exposure cap |
| Reputation purchasable at collected fee and trade cost (C1) | both | medium | economics tuning; Sybil gates |
| Descriptor metadata leakage (B3/X1) | R&D | medium | seller topic granularity; leakage budgets |
| Fresh status root selectively omits an external retraction (S4/O2) | cross-org | high | audited completeness, operator bond, inclusion SLA |
| Retraction race window after valid proof (S4) | both | low-medium | freshness-window tuning |
| No revenue clawback in v1 (fraud revenue finalizes; MECHANISMS 4) | both | medium | bonds sized for finalized exposure; capture-delay custody is a post-wedge design decision |
| `MustPrepay` or `PrepaidFinal` can settle before digest verification | both | high without the ADR-0019 rail rule | reject both rails from the v1 constrained-reveal profile; any compensated prepaid profile is a separate version |
| Paid non-delivery under a seller-aligned cross-org mediator (S7/O5 attest-and-withhold) | cross-org | high | escrow blocked on its settlement ADR; require contract-gated profile or disclose Experimental TTP; seller-aligned profile prohibited |
| Neutral mediator, escrow admin, or timeout watchdog defeats its SLA (O5) | cross-org | medium-high | mandatory settlement profile and mediator backing, full funded witness, beneficiary-authorized release, three-stage proof and pause/rotation tests |
| Compromised settlement operator signs policy-wrong payout destinations (T5/C2) | both | high | pre-sale pinned fund and frozen buyer destinations; ADR-0015 structural enforcement remains open |
| Post-distribution appeal cannot claw back funds or retract an append-only status entry (B4/O4) | both | medium | reject in v1; future funded idempotent restitution and correction-status design |
| Challenge griefing asymmetry (B4) | wedge | low-medium | bond-size tuning (MECHANISMS) |
| Authorized republication of revealed information (S5/B2) | both | medium | forensic + reputational only |

## 6. Invariant mapping

The market inherits and must not weaken: invariants 9/10 (slash proceeds
never to insiders; no discretionary settlement - ADR-0015), P1 attenuation
(purchase capabilities are narrow single-use grants), P4 receipt integrity
(delivery proofs), P10 truthfulness (evidence classes never upgraded, which
is what keeps `asserted` findings from masquerading as verified). New
invariant candidates the implementation should formalize are
delivery-contract soundness, status-feed freshness monotonicity, and the
challenge-outcome envelope. This threat pass adds the
load-bearing refinements: one strict evidence-verifier facet report; exact
Finding/ask/bid/token/request/reservation/payee binding before financial
mutation; one live collateral allocation with exposure bounded by remaining
slashable value; one defect/liability terminal and at-most-once,
realized-spend-capped payout per `purchase_key`; domain-specific effect
  identities; status proof domain separation and a latest
  `(map_epoch, epoch_id, root_hash)` floor without a completeness claim; and a
  signed, restart-stable terminal for every payment and appeal branch.
