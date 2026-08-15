# Cognition Market Mechanisms: Pricing, Elicitation, Bonds, Fees

- Status: research design merged through PR #1025; this execution branch
  implements only the M0/M1 finding-artifact foundation. Pricing, fee
  collection, custody, revenue vesting, challenges, and audits remain
  proposed.
- Scope: the economic design layered on [ARCHITECTURE.md](ARCHITECTURE.md);
  what is deterministic policy vs. tunable parameter vs. open research
- Section 8 carries the external prior-art survey with citations; sections
  1-7 are internal design and cite only this repo

## 1. The pricing problem, stated exactly

The true value of a finding to a buyer is a counterfactual it cannot
compute: `P(would have attempted) x cost-if-attempted x P(would have hit the
same dead end) x redundancy-across-siblings x decay`. No mechanism below
claims to compute this. The launch design instead lets the buyer use a
local estimate of its outside option:

- Re-deriving the result is a meterable action, so a buyer can construct a
  conservative estimate from its own recent metering history or a fresh
  quote for the same context and recipe. This is buyer-local policy, not a
  platform-computed fact. The shipped `MeteredBillingQuote`
  (`crates/core/chio-core-types/src/capability/governance.rs:67`) is a plain,
  caller-carried sub-block of `GovernedTransactionIntent`. It has no issuer
  signature and no binding to a finding context or replay recipe. The kernel
  checks shape, time, and currency consistency, but it does not authenticate
  the named provider or how the estimate was derived
  (`crates/kernel/chio-kernel/src/kernel/governed_validation.rs:595`).
  Therefore that type cannot, by itself, establish a market-wide or
  operator-verifiable substitute price.
- At M1, `evidence_cost` is an issuer assertion in every evidence mode. The
  artifact validator checks its shape, not the receipts or their semantic
  relationship to the finding. At M2, full-receipt mode (mode A in
  ARCHITECTURE F2) can establish typed lower bounds only after the offline
  verifier strictly validates canonical receipt
  signatures and complete checkpoint bindings, proves the receipt actions,
  context, replay recipe, issuer attribution, and currency belong to this
  finding. `metered_exposure_backing` requires an admitted kernel, mediated
  reconciled exposure, and a matching signed nonce;
  `settled_spend_backing` additionally requires qualifying capture or
  finalized settlement evidence. Add exact-currency values with checked
  arithmetic. Do not use
  the advisory saturating `CostMetadata` rollup
  (`crates/economy/chio-metering/src/cost.rs:69`) as financial authority.
  The first facet proves only kernel-accounted metered exposure, and the
  second proves only kernel-accounted settled spend represented by the
  supplied evidence. Neither proves paid honest work, physical compute burn,
  or truth of the finding. In projected-evidence mode (mode B), the projection authenticates
  only disclosed statements; full receipt, checkpoint, hidden semantic, and
  two cost facets remain unavailable until an audit supplies and verifies
  the full authority inputs. A dedicated authenticated cost projection is
  future engineering.
- M2 admission consumes a signed, registered
  `chio.finding.verifier-report.v1`, not an unsigned local rendering. The
  report authority is independently pinned by deployment governance and
  narrowed by the admitted verifier profile. The report binds the Finding,
  profile, trust-root/key-status snapshot, resolved evidence-bundle digest,
  evaluation time, live backing created before evaluation, and every facet
  result. Body authority and envelope signer must match. Unknown, expired, or
  revoked report keys reject under the profile's rotation policy. A buyer may
  rerun the verifier locally, but that unsigned result remains buyer policy
  and cannot substitute for the admitted report or authorize value movement.

Consequences: under the proposed buyer policy, the clearing band is
`0 < price <= buyer_local_ceiling`. A posted price above a buyer's ceiling
does not clear for that buyer. This does not prove that it re-derives, or
that every buyer forms comparable estimates. Production cost does NOT floor
the price: it is sunk, and marginal delivery cost is near zero. Sellers
recover cost only when enough buyers' private ceilings sit above their asks;
this is stated plainly rather than engineered away.

## 2. Buyer-side elicitation (deterministic policy)

The M8 ceiling function is implemented by the Rust reference helper in
`crates/economy/chio-open-market/src/finding_bid_policy.rs` and mirrored by
the TypeScript and Python SDKs:

```
ceiling = min(budget_remaining,
              buyer_rederivation_estimate
                x would_have_run_bps / 10^4
                x (10^4 - sibling_redundancy_bps) / 10^4
                x guarantee_class_bps / 10^4)
```

The helper accepts only canonical non-negative decimal integers bounded by
Rust `u64`, restricts each basis-point value to `0..=10_000`, checks exact
estimate-to-budget currency equality plus source/context/recipe provenance,
uses checked `u128` intermediates, and rounds down once after the combined
three-factor product. TypeScript rejects unsafe numeric `Number` inputs while
accepting decimal strings above `2^53`; Python and Rust accept the same full
decimal-string `u64` domain. Shared golden vectors and negative vectors fix
the cross-language behavior. The real marketplace fixture separately proves
that an at-ceiling bid clears and an above-ceiling bid rejects.

This M8 profile intentionally does not add a production quote source or an
authenticated bid-basis artifact. The existing signed `BidRequest` carries
only `max_price_per_call`; it does not carry the estimate or the three
multipliers. Consequently an operator can audit enforcement of the submitted
ceiling but cannot reconstruct why the buyer chose it. The estimate,
`would_have_run_bps`, and `sibling_redundancy_bps` remain private planner
policy. The shipped `MeteredBillingQuote` remains caller-carried and unsigned.

Any future quote an operator can authenticate requires a separate signed
quote-producer artifact. That artifact must bind the
producer key, finding context digest, replay-recipe digest, billing unit,
currency, amount, validity window, and source provenance. A bare
`MeteredBillingQuote` remains caller-carried context and earns no such
claim. The simpler launch profile keeps the basis buyer-local and makes no
operator truth claim about it.

Guarantee-class multipliers are policy defaults, suggested:
`deterministic_replay = 10_000` (full), `metered_attested = 5_000`,
`asserted = 500`. Rationale: the discount is the buyer's self-insurance
against the residual the class cannot exclude (threat model S2). These
parallel the existing reputation-tier discount table idiom
(`TIER_DISCOUNT_PER_HUNDRED`,
`crates/economy/chio-appraisal/src/marketplace_pricing.rs:148`).

## 3. Seller-side pricing (posted price, v1)

v1 keeps the shipped shape: unilateral posted price via the signed pricing
hint (`ListingPricingHint.price_per_call`,
`crates/economy/chio-listing/src/discovery.rs:48`), buyer ceiling check only
(`BidCeilingTooLow`, `crates/economy/chio-open-market/src/bidding.rs:365`).
Sellers price against demand signals already on the hint (receipt volume,
`recent_receipts_volume`) and their known production cost, but the volume is
provider-advertised rather than independently proved. No negotiation, no
auction in v1: the launch hypothesis is that buyer-local walkaway ceilings
and near-zero marginal delivery cost make posted prices adequate at wedge
scale. Efficiency remains empirical. Auction machinery is deferred to the
decision backlog in [PLAN.md](PLAN.md).

Three pricing structures adopted from the prior art (8.2, 8.5):

- **Anchored ordering, without an exclusivity claim.** Receipt timestamps
  are NOT a cross-operator total order (each kernel's clock is an audited
  assumption, and nothing tie-breaks across seller operators), so no
  listing slot is awarded by timestamp. At M2, listings with the same
  context may coexist and a UI may show an informational order from one
  named anchor's inclusion order. That is not global priority or proof of
  independent discovery. A context digest is a match key, not duplicate or
  semantic-similarity detection; sellers can publish distinct artifact ids
  for identical or near-identical payloads, and buyers can pay for them.
  v1 deliberately has no similarity-scaled payout and no uniqueness reward,
  but it also does not claim that duplicate work is never paid.
- **An existence tier is future product work.** A paid query that reveals
  only "this context has at least one committed finding" could address the
  bug-bounty duplicate problem. Current listing search exposes descriptor
  and pricing data, not a private one-bit oracle, and nothing currently
  prevents query-linkage or count leakage. Shipping this tier would require
  a governed query contract, explicit leakage accounting, response padding
  or a stated absence of it, and tests that define exactly what the buyer
  learns. Until then, no one-bit privacy or pricing claim is made.
- **Versioning and freshness over DRM.** Findings decay with the codebase
  or experiment space; sellers price the decay (`expires_at`), can scope a
  version to the buyer's context (commit-bound fixes are inherently
  buyer-versioned), and exclusivity, where offered, is a listing term with
  legal force only (Bergemann-Bonatti; threat model B2).

## 4. Time-structure of seller revenue (the anti-fraud lever)

Corrected on review: the shipped machinery OBSERVES dispute windows, it
does not enforce custody through them. `ChioEscrow.releaseWithProofDetailed`
transfers funds immediately on proof; `chio-settle`'s finality inspection
can label a transaction `AwaitingDisputeWindow` but cannot reverse it; the
kernel MustPrepay path settles and reconciles before any later challenge;
and M4/M5 do not retain seller revenue through the post-sale dispute window.
M4 proposes only a short-lived pre-delivery reversible hold that captures
immediately after a matched delivery. It is not dispute-window custody or a
clawback. So the current system has NO revenue clawback, and the target must
not pretend otherwise:

M4 also separates budget reservation from acceptance and payment. An
authoritative buyer/kernel coordinator persists a rich durable budget and
seller-exposure reservation with preallocated purchase/payment ids before
calling the existing pure `accept()`. The shipped
`SignedReservationReceipt` is only a minimal signed compatibility pointer;
`accept()` verifies that pointer, while reveal re-resolves the coordinator
record. Neither step creates or captures the external reveal-price hold.
Reveal-time hold and capture remain separate kernel finalizer transitions.

- **A bond requirement is not live collateral.** The shipped fee schedule
  declares a class, amount, currency, and `slashable` bit, and trust
  activation can label a listing `BondBacked`. It does not create an
  exclusive collateral allocation bound to one finding. M2 must resolve a
  live, unspent seller-collateral allocation from a trusted bond authority
  and bind it to seller key, listing id, finding id, schedule requirement
  and version, class, currency, amount, and expiry. The allocation reference
  persists through activation, every purchase, and M5 impairment; stale,
  wrong-owner, wrong-currency, and already-allocated collateral reject.
- **Collateral caps finalized exposure.** Because revenue can finalize
  before a challenge, admission and purchase must atomically reserve
  `encumbrance_per_sale = k * accepted_price`, with `k >= 1`, and enforce
  `base_finding_stake + sum(open_encumbrances) <=
  min(locked_amount - slashed_amount,
  listing_requirement.required_amount)` plus
  `sum(open_encumbrances) <= maximum_sale_exposure`, with checked arithmetic
  and exact currency. Exposure includes concurrent
  accepted or finalized sales within the detection horizon and falls only
  when the predeclared horizon closes without an actionable event. This is
  a hard concurrency-safe cap, not the former expectation
  `bond >= k x price x expected_sales`, which leaves an uncovered tail.
  The seller signs a cognition-liability policy with nonzero claim, audit,
  appeal, and settlement horizons; allocation expiry must extend beyond all
  of them. The generic amount-tiered `dispute_window_secs` cannot supply this
  invariant because its low tier may be zero, and it does not provide
  custody.
- **Post-sale capture-delay is a future custody option, not a v1 claim.**
  Holding seller revenue through a dispute window after successful delivery
  would need
  new escrow semantics or a custody profile - a decision-backlog ADR if
  wedge data shows bonds alone underprice fraud (PLAN section 4).
- **Slash distribution** goes to harmed buyers pro rata by purchase amount,
  with any remainder going to the registered community fund. Existing
  `validate_bond_impair_distribution` enforces exact sum
  (`crates/economy/chio-settle/src/evm/prepare.rs:1082-1113`, applied again in
  `prepare_bond_impair` at 1418-1521; the contract repeats the cap and
  exact-sum check at `contracts/src/ChioBondVault.sol:292-323`), but does not
  by itself enforce ADR-0015 D4's beneficiary allowlist. M5 must derive and
  enforce immutable destinations from authoritative purchase evidence and
  the community-fund destination pinned before sale. Challenger
  rewards, audit costs, operator fees, and adjudicator fees never come from
  the seller slash.
- **Appeal state is not a clawback.** `ReverseSlash` preserves the penalty
  state-machine path, but it does not retrieve funds already distributed by
  an impairment transaction. The target profile therefore needs a
  pre-execution appeal period that blocks impairment until finality. If
  policy also permits an appeal after distribution, it needs a separately
  funded, receipt-backed restitution or compensation terminal. A state
  transition alone must not be described as restoring the seller's money.

## 5. Challenge economics (griefing vs. deterrence)

- The challenge schema first requires an origin `oneOf`. A buyer branch is
  signed by the challenger and binds standing, a live Dispute lock, and the
  collected dispute-fee terminal. A venue-audit branch is signed by the
  admitted audit authority and binds its committed audit epoch, selection,
  and authorization; it has no challenger, standing, bond, fee, forfeiture,
  or reward fields. Cross-origin fields reject. A nested `oneOf` then admits
  exactly one mechanical evidence class.
- A buyer challenge names the Dispute-class bond
  (`OpenMarketBondClass::Dispute`,
  `crates/economy/chio-fiscal/src/fee_schedule.rs:12`) and the
  `dispute_fee`, but those shipped fields are declarative. M5 must resolve
  and atomically lock live collateral from a trusted bond authority. The
  allocation binds the challenger key, active schedule id and version,
  Dispute class, amount, currency, expiry, and unspent state to this
  challenge. A bond reference string is not proof of collateral; stale,
  reused, wrong-owner, wrong-class, wrong-currency, or underfunded
  allocations reject. The amount comes from admitted market terms and is
  bounded by the governance profile, never from a challenger or an ambient
  seller quote.
- Bond sizing is class-specific. Only `replay_contradiction` may use
  `challenge_bond ~= c x bounded_metered_replay_cost`, with `c` in `[1, 2]`
  and exact admitted currency. `digest_mismatch` and `evidence_invalid` use
  separately admitted fixed or class-specific governance-capped amounts;
  seller-asserted replay cost cannot size those classes. The bond makes
  spray-and-pray challenges negative-EV; it does not price seller
  inconvenience.
- Every class returns `Upheld | Rejected | Indeterminate`; replay additionally
  carries nested `ConfirmedContradiction | Consistent | Indeterminate`.
  `Upheld` returns the buyer lock. `Rejected` applies the signed
  class-specific return/forfeit rule. `Indeterminate` creates no seller hold
  or sanction and never forfeits for infrastructure or availability failure.
  It may retain the same lock only through one bounded signed retry using the
  same challenge, fee, lock, profile, and evidence identity, then returns it
  exactly once. A bounded challenger reward, if offered after `Upheld`,
  comes from the separately collected dispute-fee
  challenge-administration pool. It never comes from seller slash proceeds
  or the audit-only participation pool. Seller slash remains restricted to
  verified harmed buyers and the registered community fund under ADR-0015
  D4.
- A venue-selected audit is not a spray-and-pray accusation. It is authorized
  by the signed audit-epoch plan, carries no dispute bond or dispute fee, and
  pays no auditor reward. The restricted audit pool pays only verified
  selected-audit execution. A clean audit transfers nothing to the seller;
  fraud uses the same typed evaluator and Sanction lane. Operator failure to
  perform a selected audit belongs to the operator-SLA lane, not a fabricated
  buyer-challenge bond disposition.
- Griefing asymmetry to watch (threat model B4): a deep-pocketed rival can
  still force sellers to babysit challenges; mitigation is that replay
  challenges are targeted to auto-evaluate through a pure evaluator with no
  seller response required. This lowers, but does not prove zero, seller
  cost.

Compatibility boundary: M5 keeps the frozen v1 penalty and evidence enums
unchanged. An affirmatively `Upheld` mechanical evaluation produces
`chio.finding.challenge-outcome.v1`, signed by the outcome authority pinned in
the active governance profile after validity, rotation, and revocation
checks. It maps to the existing
`OpenMarketAbuseClass::FraudulentListing`, and carries exactly one existing
`OpenMarketEvidenceKind::External` reference whose `reference_id` equals the
outcome id and whose mandatory lowercase `sha256` equals the canonical signed
envelope digest. An optional URI must be profile-allowed, immutable, and
resolve to that digest. A finding-specific wrapper re-verifies the authority
and every typed binding before constructing the ordinary enforced Sanction; a
bare caller-selected, unresolved, digestless, substituted, or additional
External reference is never sufficient.

**Probabilistic audits (the theoretically required complement).** The
elicitation literature's decisive result (8.3) says buyer-initiated
challenges alone cannot deter fabrication of claims nobody re-buys or
re-checks; limited random ground-truth checks dominate every
peer-prediction scheme. So the venue (or a pool acting for its buyers)
must randomly audit listed `deterministic_replay` findings by running the
committed recipe. "Published rate" is not enough. Each audit epoch must
publish the eligible-listing snapshot, class-specific rate, deterministic
selection algorithm, and a committed randomness source that the venue
cannot choose after seeing the snapshot. Signed selection, attempt,
completion, and missed-deadline receipts let anyone recompute the sample
and detect omitted selected listings. Until this scheduler and the fee
collection in section 6 exist, audits are a target, not a shipped control.
The deterrence condition is sized per listing class:

```
audit_rate x slash_amount >= expected_fabrication_profit
```

where `expected_fabrication_profit ~= price x expected_sales_in_window`.
Audit outcomes use the ordinary challenge evidence and adjudication path,
with the bondless audit authorization above. Market/peer signals
(descriptor-overlap disagreement between sellers, replication-market-style
priors) may create an additional, separately disclosed risk-weighted sample,
but they never alter the committed random sample and never settle anything
(8.3's ~73% accuracy is prior-grade, not settlement-grade).

**Venue and mediator accountability.** The scheduler, status publisher,
and any neutral cross-org reveal/escrow mediator are trusted roles, not free
security assumptions. Before those profiles qualify, each operator must
post live operator collateral and sign a versioned SLA for observable
checkpoint, audit-attempt, settlement-root, and status-inclusion deadlines.
Missing a mechanically observable deadline feeds a predeclared operator
penalty and buyer refund/compensation path. For a neutral reveal mediator,
this makes attest-and-withhold costly when it manifests as a missing
required settlement checkpoint. It still cannot prove that response bytes
reached buyer memory, so mediator neutrality and response delivery remain
audited assumptions rather than cryptographic guarantees.

The M7 Finding escrow profile is full-only: the finalized deposit must equal
the accepted price, and the only economic terminals are a beneficiary-called
full release for that amount or a permissionless full refund of the entire
unreleased deposit after the deadline. `partialReleaseWithProof*`, mixed or
partial terminals, and amount drift reject. The watchdog can publish proof
and coordinate the seller beneficiary, but the current contract does not let
it release on that beneficiary's behalf. A pause can block release through
the deadline while leaving refund open. Because `operatorKeyHash` is frozen in
`EscrowTerms`, planned rotation drains qualified escrows before rotating;
otherwise they reach refund, and a new key requires a new witness. A
zero-value refund observed after a finalized full release does not reverse
value and is not classified as a mixed economic terminal.

## 6. Fees, spam, and admission

All four fee/bond fields exist in the shipped fee schedule artifact
(`OpenMarketFeeScheduleArtifact { publication_fee, dispute_fee,
market_participation_fee, bond_requirements }`,
defined in `crates/economy/chio-fiscal/src/fee_schedule.rs`; the
`chio-open-market` module is a consumer/re-export):

- Publication fee: the declared amount that becomes a spam floor only after
  M2 collection (threat model S6).
- Dispute fee: the declared buyer-challenge administration charge that becomes
  authoritative only after M5 exact-rail collection.
- Listing bond, `slashable: true`: the declared fraud-stake requirement.
  `BondBackingRequired` keeps unbacked listings review-only
  (`crates/economy/chio-listing/src/trust_activation.rs:565`), while section
  4 specifies the missing live exclusive allocation.
- Participation fee: a recurring seller-paid amount per active listing per
  audit epoch. M2 collects the first epoch at activation and later renewals
  are required for admission. In v1, 100 percent enters a segregated audit
  pool and may fund only verified selected-audit execution. Scheduler and
  operator overhead cannot be charged to that pool in v1.

Honesty note on shipped state: PR #974 landed as `51e46336b`. Its fiscal
adapter governs and resolves fee schedules, but the fee schedule remains
DECLARATIVE for these cognition-market events - the artifact carries the
amounts and validates their shape
(`crates/economy/chio-fiscal/src/fee_schedule.rs:69-112`), but nothing
collects a publication fee at
publish time or a dispute fee at challenge time (confirmed again against
post-#974 main). Fee COLLECTION is engineering the plan must carry: settle
the publication fee and first `market_participation_fee` epoch as part of
listing admission (M2), renew that participation fee before each later active
audit epoch, and collect the dispute fee as part of buyer challenge
submission (M5). Each collection must produce a signed payment/settlement
receipt bound to the active schedule version, payer, event, amount, and
currency. A durable domain/event idempotency key fences intent before rail
dispatch; the authority-authenticated terminal receipt and reconciliation are
persisted before the event is marked paid. Identical retry reconciles and a
conflicting payer, amount, currency, schedule, or event rejects.
Participation revenue enters the
audit-only pool. Dispute revenue enters a separate
challenge-administration pool from which an independent successful
challenger may receive only capped verified replay-cost reimbursement.
Governance and the venue admission pin separate pool principal ids,
rail-tagged beneficiary destinations, currencies, and authority epochs.
Every publication/participation collection receipt must name the exact
audit-pool destination, and every dispute-fee receipt must name the exact
challenge-administration destination; a venue-controlled substitute account
does not satisfy collection. Until that exact-destination collection lands,
the venue cannot claim that audits or reimbursements are fee funded.

Metering is a mode-bound evidence signal, not a spam proof or filter. Merely
referencing receipts or declaring `evidence_cost` does not prove burn, because
expensive unrelated receipts can be attached. At M2, mode-A full-receipt
evidence can establish a lower bound on kernel-accounted metered exposure
only after the verifier strictly authenticates every receipt and complete
checkpoint binding, verifies issuer attribution and context/replay-recipe
bindings, checks the signed reconciliation nonce, and adds exact-currency
amounts with checked arithmetic. A distinct settled-spend facet additionally
requires qualifying capture or finalized settlement evidence. Neither
proves paid honest work, physical burn, the conclusion true, or that
publication was expensive. A mode-B listing's `evidence_cost` remains an
assertion until audit. The enforceable spam floors are actually
collected publication/participation fees and live collateral; admission
policies must not treat a metered-cost facet as burned-work or truth proof.

## 7. Pool purchasing and redundancy

M8 retains `SwarmBudgetPool` as an unsigned planning object and adds
`chio.finding.pool-allocation.v1`, an authority-signed companion that binds
its canonical digest, graph and pool ids, one authority-selected qualified
ledger domain, one concrete ledger-store binding, one purchaser id and key,
currency, hard amount, nonce, authority, and validity window. The kernel
verifies that artifact against the installed ledger's persistent domain and
store binding before constructing a private authorized debit. Pool accounting,
projection count, identifier, and total-byte limits are checked before the
digest projection is materialized.

The shipped qualifying backend is durable SQLite. It uses `BEGIN IMMEDIATE`,
canonical decimal-text `u64` amounts, checked accumulation, one receipt
authority across the complete ledger, and durable exact purchase-id replay.
Its unique pool binding combines the canonical database identity with a live
proof from an external signing identity that is not stored in SQLite. A copied
database therefore cannot preserve the qualifying binding by itself. That
path makes one-purchaser-per-pool and never-exceed-signed-amount hard
invariants. An
in-memory backend and an advisory or eventually consistent remote budget view
do not implement the qualifying marker and therefore cannot make the hard
ceiling claim. Two disjoint qualified ledgers cannot each spend the same
allocation because each concrete SQLite store and external identity derive a
different binding, and the allocation authority signs the selected binding.

- Intra-pool: the planner should deduplicate an artifact request, buy once
  with retry-safe purchase identity, and distribute internally via governed
  memory writes. Its private `sibling_redundancy_bps` policy may then assign
  less redundancy discount than an uncoordinated buyer. The qualified ledger
  prevents overspend through its exact signed allocation, but it does not
  prove the planner's private redundancy prior or prevent purchases made
  outside that allocation.
- Inter-pool: pools are independent buyers; a seller's expected revenue is
  approximately the number of purchasing pools that independently clear
  times price. Sybils, wash purchases, and cross-pool coordination can
  distort observed volume, so it is demand telemetry, not an honesty proof.
- Cross-pool aggregation for expensive findings (many pools, each below the
  ask, jointly above it) is deliberately NOT mechanized in v1 - it is a
  combinatorial/public-goods problem (open problem list), and a wrong
  mechanism here invites collusion.

Resale and leakage (threat model B2): within a pool, "resale" is the
product working as intended. Cross-org, post-reveal diffusion is priced in:
findings are freshness-decaying goods (dead ends rot as the codebase or
experiment space moves), sellers set `expires_at` and price the decay, and
exclusivity, when wanted, is a listing term with legal rather than
cryptographic force. No DRM is attempted.

## 8. Prior art and external evidence

Survey run 2026-07-20. Sections below carry compressed author/year
pointers; the auditable bibliography (source type labels, stable URLs,
retrieval dates, and the novelty-sweep query corpus) is section 10, added
on review so no claim rests on an unlabeled fragment. Self-reported and
single-source figures are flagged both inline and in section 10.

### 8.1 Fair exchange and paying for secrets

- Strong two-party fair exchange without a TTP is impossible (Pagnia and
  Gartner 1999, FLP-style reduction). Kernel-as-TTP is theorem-mandated,
  not a design smell; the only freedom is when the TTP engages.
- Zero-Knowledge Contingent Payment was broken twice: buyer-chosen CRS let
  buyers extract information without paying (Campanelli et al., CCS 2017,
  eprint 2017/566), and the proposed fix for contingent services fell to
  Fuchsbauer 2019 (eprint 2019/964). Lessons adopted: verification
  parameters and harnesses must be generated or allowlisted by the mediated
  verifier, never accepted from one counterparty without authentication;
  and evidence-without-content is itself a leakage channel - see 8.6.
- FairSwap (CCS 2018) / OptiSwap (2020): proving misbehavior should be
  cheap (short Merkle proof to a judge) while the happy path stays thin;
  bond both sides against griefing. v2 option: Merkle-chunked payload
  commitments so a buyer can prove a specific delivered chunk violates the
  claim without revealing the rest.

### 8.2 Data marketplaces

- Shapley-style contribution payouts are structurally gameable by
  replication/sybils (Agarwal-Dahleh-Sarkar EC 2019
  robustness-to-replication axiom; Data Shapley manipulation line
  2019-2026). Adopted narrowly: do not introduce similarity-scaled
  contribution payouts or a timestamp-wins listing slot. Duplicate contexts
  may coexist with informational anchored ordering (section 3), but v1 has
  no semantic duplicate detector and makes no unique-artifact payment
  guarantee.
- Deployed privacy-tech marketplaces (Ocean compute-to-data, iExec, Oasis)
  shipped supply tech but found no demand (one academic count: 6,826 Ocean
  transactions May 2022 - June 2025; single source, flagged). Diagnosis:
  buyers could not value unseen data. A Chio buyer can form a local,
  metering-informed outside-option estimate (section 1). Whether that
  improves demand-side price discipline is the product hypothesis to test;
  the shipped caller-carried quote is not an authenticated valuation
  oracle.
- Bergemann-Bonatti (Annu. Rev. Econ. 2019): freely replicable information
  resells to zero; survivors sell versions, freshness, exclusivity.
  Adopted in section 7's decay framing and 3's versioning note.

### 8.3 Elicitation without verification (the decisive negative result)

Peer prediction (2005), Bayesian Truth Serum (2004), Dasgupta-Ghosh (2013)
all require multiple correlated reports. Gao-Wright-Leyton-Brown
(2016/AIJ 2019) show that WITHIN THEIR MODEL (costly evaluation,
coordinated low-cost signals) the analyzed class of peer-prediction
mechanisms admits low-effort/collusive equilibria while a simple
limited-ground-truth mechanism dominates. Scoped consequence (review
correction: this is strong support, not a universal impossibility): for
this design, settlement-grade fraud decisions come only from re-execution
audits plus slashing (8.5, section 5); peer/market signals (including
LLM-era peer elicitation, 2024-2026) only target the audits. Whether some
mechanism outside that model's assumptions could deter fabricated
singleton claims without re-execution remains an open research question
(section 9). Replication prediction markets hit ~73% accuracy (PLOS ONE
2021) - audit-prior grade, not settlement grade.

### 8.4 Scientific-knowledge markets

- Negative-results journals failed on supply: authors will not spend effort
  packaging negatives (JNRBM closed 2017; ~20% of null studies published,
  ~65% never written up). The design hypothesis is that tooling can derive
  much of a Finding from already-produced receipts and a replay recipe,
  reducing marginal packaging work. M1 does not automatically export runs,
  publish negatives, or pay at production.
- Registered Reports: hypothesis-support rates drop from ~96% (standard) to
  ~44% (pre-registered) in the cited comparison. The narrower protocol
  lesson is hindsight resistance: at M2, an optional
  `intent_commitment_receipt_id` earns a buyer-policy uplift only if its
  authenticated receipt and complete checkpoint proof predate all producing
  evidence through a pinned log sequence or admitted anchored cross-log
  relation, and its parameter hash binds the versioned descriptor, canonical
  context, replay-recipe digest, and protocol digest. M1 checks only that the
  string is non-empty. Even after M2 verification, the commitment says
  nothing about completeness: a seller can precommit many runs, abandon
  unfavorable ones, and publish only favorable findings. Chio has no
  registry of all initiated experiments, so it must not inherit
  Registered-Reports completeness or de-biasing claims.
- Kremer patent buyouts (QJE 1998): random execution of some bids at their
  stated price keeps stated valuations honest - the trick to reuse if
  cross-pool consortium buyouts (open problem) are ever mechanized.

### 8.5 The coding wedge's live analogs

- Bug bounties are the negative-result problem monetized badly: 50-70%
  invalid submissions, ~4-7% signal rates, duplicates worth $0 so hunters
  race with low-detail reports; triage, not payouts, is the cost center
  (Walshe-Simpson 2020). And in 2026 the AI-slop flood broke it publicly:
  kernel security list "almost entirely unmanageable" (Torvalds, May 2026),
  HackerOne Internet Bug Bounty cut payouts 76-89% (May 2026). Machine-
  checkable claims plus live bonded submission are the throttle this design
  proposes. The operational evidence supports testing the coding wedge; it
  does not establish that the unshipped mechanism will solve triage.
- Agent payment rails are commodity: x402 (100M+ transactions on Base
  independently confirmed by Chainalysis by Q1 2026; sub-$0.50 median),
  Google AP2 mandates, Stripe/OpenAI ACP. None verifies delivery. Position
  Chio receipts as the delivery-verification layer over those rails (the
  x402 adapter already exists, `crates/kernel/chio-kernel/src/payment.rs`).
  Sub-dollar medians confirm: dispute machinery must amortize off the hot
  path. Pure challenge evaluation, audit batching, and a detection horizon
  are targets; current dispute windows do not provide custody.
- Virtuals ACP self-reports 1.77M agent jobs with escrow lifecycle
  (PR figures, unverified) - but its evaluation step is an LLM opinion.
  The proposed wedge differentiator is a strict deterministic replay
  recipe and mediated re-execution receipts. That evaluator arrives at M5,
  not M1.
- Erlei-Meub (arXiv 2603.08853, 2026): LLM-agent credence-goods markets
  collapse in one-shot settings without liability institutions; reputation
  alone is empirically insufficient. Live, exclusively allocated
  per-finding collateral and an exposure cap are load-bearing target
  controls (section 4); a declarative per-identity bond reference is not.

### 8.6 Swarm scale and the side channel

- Market-based control: flat auctions break past small n (combinatorial
  winner determination, per-bid planning cost); markets scale when the
  mission decomposes into subteams with nested envelopes (Clearwater 1996;
  Wellman; Dias et al., Proc. IEEE 2006). 2025-26 LLM-orchestration work
  (COALESCE, ZEBRA) re-derives the same make-vs-buy-per-node conclusion.
  Section 7 proposes this purchasing convention on the shipped unsigned pool
  accounting structures; the kernel does not yet enforce one purchase per
  pool. M8 requires a signed or digest-bound pool companion plus coupling to
  an authoritative kernel ledger before calling it a budget tree.
- Side channel adopted into the threat model (X2): the ZKCP episode
  generalizes - metered cost, step counts, and timing in the EVIDENCE can
  leak the finding (a cheap run screams "failed early"). Mitigation:
  seller-chosen `evidence_cost` bucketing for projected evidence and
  leakage-ledger accounting for descriptor fields. Full receipts reveal
  exact cost metadata; projected receipts hide it but leave the public cost
  assertion unverifiable until audit. No mode claims content privacy beyond
  its explicitly disclosed fields.
- Novelty check (stated plainly): after multiple query formulations, no
  existing system or paper combines the proposed verified-negative-result
  artifact, agent principals, cryptographic delivery receipts, and bonded
  settlement.
  Components exist separately (x402 escrow lifecycles, AgentX's private
  failure cache, arXiv 2606.26859; execution receipts). The combination
  appears unclaimed as of 2026-07-20.

## 9. Open mechanism problems (delta over the spike memo)

One former open problem is NARROWED by the literature (not closed -
review correction): within Gao et al.'s costly-evaluation model, limited
ground truth dominates the analyzed peer-prediction class, which is why
section 5 settles fraud only by re-execution audits plus slashing. Whether
any mechanism outside that model can deter fabricated singletons without
re-execution stays open as problem 7 below.

1. `would_have_run` priors: can a planner's own historical receipt corpus
   calibrate them? The input is local and not a settlement claim, but it can
   still be strategically changed or seller-influenced; research.
2. Cross-pool demand aggregation without collusion surface: research. If
   ever mechanized, Kremer's random-execution trick (8.4) is the known
   honesty device for stated-valuation bids.
3. Audit-rate, exclusive collateral, exposure multiplier, and detection
   horizon tuning against real fraud-gain distributions:
   engineering-with-data once the wedge runs (the deterrence inequality and
   hard exposure cap in sections 4-5 are the frame).
4. Descriptor granularity economics (coarse topics leak less but match
   worse), now including evidence side-channel bucketing (8.6): what
   `evidence_cost` bucket widths and timing coarsening keep descriptors
   useful but non-leaky? engineering, with a leakage-ledger audit.
5. Whether failed-challenge forfeiture to the seller invites
   seller-initiated fake challenges against themselves to farm forfeits
   or a separate fee-funded reward (self-challenge wash). Subject and
   beneficial-owner controls, real fee collection, and net-flow simulation
   are required before enabling rewards; engineering.
6. Existence-tier pricing and privacy (section 3): the bit's value as a
   function of descriptor entropy, plus query linkage, result-count, timing,
   and padding leakage. This is a new governed product, not a listing-search
   flag; research plus engineering.
7. Elicitation without re-execution, outside the Gao et al. model
   assumptions (8.3): open research; audits remain the settlement design
   regardless of its resolution.
8. Verifiable cost proofs for projected-evidence listings (section 1's
   mode-B gap): engineering, likely a dedicated cost slot in a future
   receipt projection version.
9. Whether an authenticated re-derivation quote producer is worth its trust
   and privacy cost. The launch mechanism can keep bid formation local; if
   M8 adds a producer, it needs the context/recipe binding and normative
   checked arithmetic in section 2; product research plus engineering.
10. Operator collateral and restitution sizing: price observable missed
    audit/status/settlement SLAs and fund post-distribution appeal
    restitution without socializing unlimited operator or seller risk;
    mechanism design plus engineering.

## 10. References

All URLs retrieved 2026-07-20. Labels: [paper] peer-reviewed venue,
[preprint] arXiv/ePrint without confirmed venue, [report] institutional or
analyst research, [vendor] company blog/docs, [pr] press release or
self-reported metrics, [news] journalism, [tertiary] encyclopedic.

Fair exchange and contingent payment:

1. [report] Pagnia, Gartner. "On the impossibility of fair exchange
   without a trusted third party." TU Darmstadt TR TUD-BS-1999-02, 1999.
   http://lpdwww.epfl.ch/fgaertner/pubs/TUD-BS-1999-02.abstract.html
2. [paper] Campanelli, Gennaro, Goldfeder, Nizzardo. "Zero-knowledge
   contingent payments revisited." ACM CCS 2017.
   https://eprint.iacr.org/2017/566 ;
   https://dl.acm.org/doi/10.1145/3133956.3134060
3. [preprint] Fuchsbauer. "WI is not enough: zero-knowledge contingent
   (service) payments revisited." IACR ePrint 2019/964, 2019.
   https://eprint.iacr.org/2019/964.pdf
4. [paper] Dziembowski, Eckey, Faust. "FairSwap." ACM CCS 2018.
   https://eprint.iacr.org/2018/740
5. [paper] Eckey, Faust, Schlosser. "OptiSwap." AsiaCCS 2020.
   https://eprint.iacr.org/2019/1330.pdf
6. [preprint] "Airtnt: fair exchange payment for outsourced secure enclave
   computations." arXiv:1805.06411, 2018.
   https://arxiv.org/pdf/1805.06411
7. [preprint] "Recurring contingent service payment." arXiv:2208.00283,
   2022. https://arxiv.org/pdf/2208.00283

Data markets and valuation:

8. [paper] Agarwal, Dahleh, Sarkar. "A marketplace for data: an
   algorithmic solution." ACM EC 2019. https://arxiv.org/abs/1805.08125
9. [preprint] "Towards replication-robust data markets."
   arXiv:2310.06000, 2023. https://arxiv.org/html/2310.06000v2
10. [paper] Ghorbani, Zou. "Data Shapley." ICML 2019 (PMLR v97).
    https://proceedings.mlr.press/v97/ghorbani19c/ghorbani19c.pdf
11. [preprint] False-name-resistant quotient semivalues.
    arXiv:2605.07663, 2026. https://arxiv.org/pdf/2605.07663
12. [preprint, single-source figure - FLAGGED] Ocean Protocol on-chain
    activity measurement (6,826 transactions May 2022 - June 2025).
    arXiv:2511.13233, 2025. https://arxiv.org/pdf/2511.13233
13. [vendor] Ocean Protocol compute-to-data positioning, 2020.
    https://blog.oceanprotocol.com/how-does-ocean-compute-to-data-relate-to-other-privacy-preserving-approaches-b4e1c330483
14. [paper] Bergemann, Bonatti. "Markets for information: an
    introduction." Annual Review of Economics, 2019.
    https://www.annualreviews.org/content/journals/10.1146/annurev-economics-080315-015439

Elicitation without verification:

15. [paper] Miller, Resnick, Zeckhauser. "Eliciting informative feedback:
    the peer-prediction method." Management Science 2005 (Harvard DASH
    copy).
    https://dash.harvard.edu/server/api/core/bitstreams/7312037c-e29c-6bd4-e053-0100007fdf3b/content
16. [paper] Prelec. "A Bayesian truth serum for subjective data." Science
    2004 (mirror).
    https://www.researchgate.net/publication/8231017_A_Bayesian_Truth_Serum_for_Subjective_Data
17. [paper] Shnayder, Agarwal, Frongillo, Parkes. "Informed truthfulness
    in multi-task peer prediction." ACM EC 2016 (Dasgupta-Ghosh line).
    https://arxiv.org/abs/1603.03151
18. [paper] Gao, Wright, Leyton-Brown. "Incentivizing evaluation with
    peer prediction and limited access to ground truth" (earlier title:
    "peer-prediction makes things worse"). arXiv 2016; Artificial
    Intelligence (AIJ) 2019. https://arxiv.org/abs/1606.07042 ;
    https://www.sciencedirect.com/science/article/pii/S0004370219301559
19. [preprint] "Peer elicitation games." arXiv:2505.13636, 2025.
    https://arxiv.org/abs/2505.13636
20. [paper] GPPM/GSPPM LLM peer prediction. ACM EC 2024.
    https://arxiv.org/html/2405.15077
21. [preprint] "Truthfulness despite weak supervision."
    arXiv:2601.20299, 2026. https://arxiv.org/pdf/2601.20299

Scientific-knowledge markets:

22. [tertiary - closure motive contested, see 23] Journal of Negative
    Results in Biomedicine (2002-2017).
    https://en.wikipedia.org/wiki/Journal_of_Negative_Results_in_Biomedicine
23. [report] "Reevaluating the quest for negative results." CSE Science
    Editor, 2019.
    https://www.csescienceeditor.org/article/reevaluating-the-quest-for-negative-results/
24. [paper] Registered Reports adoption. Scientometrics, 2023.
    https://link.springer.com/article/10.1007/s11192-023-04896-y
25. [paper] Registered-Reports outcome rates follow-up. MIT QSS, 2024.
    https://direct.mit.edu/qss/article/doi/10.1162/qss_a_00364/128600
26. [paper] Replication prediction-market accuracy (75/103). PLOS ONE,
    2021.
    https://journals.plos.org/plosone/article?id=10.1371/journal.pone.0248780
27. [paper] Kremer. "Patent buyouts." QJE 1998.
    https://academic.oup.com/qje/article-abstract/113/4/1137/1916997 ;
    critique [report, 2011]:
    http://miter.mit.edu/articlekremerian-patent-buyouts-why-we-are-still-intrigued-after-13-years-and-why-they-cannot-work/

Coding-wedge analogs and agent commerce:

28. [vendor] HackerOne. "Improving signal over 10,000 bugs." 2016.
    https://www.hackerone.com/blog/improving-signal-over-10000-bugs
29. [paper] Walshe, Simpson. Bug-bounty economics. Oxford ORA, 2020.
    https://ora.ox.ac.uk/objects/uuid:3245c33c-3542-43c7-9611-257f6116b866
30. [news] The Register. "HackerOne takes an axe to its bug bounty
    rewards" (incl. Torvalds/Stenberg statements). May 2026.
    https://www.theregister.com/security/2026/05/21/hackerone-takes-an-axe-to-its-bug-bounty-rewards/5244458
31. [report] Chainalysis. x402 adoption measurement (100M+ tx on Base,
    Q1 2026). https://www.chainalysis.com/blog/x402-agentic-payments-adoption/
32. [vendor] Cloudflare on x402, 2025. https://blog.cloudflare.com/x402/
33. [vendor] Google Cloud. AP2 announcement, 2025.
    https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol
34. [pr] Stripe/OpenAI Instant Checkout, 2025.
    https://stripe.com/newsroom/news/stripe-openai-instant-checkout
35. [pr - self-reported figures, FLAGGED] Virtuals Protocol agent-commerce
    metrics, 2026.
    https://www.prnewswire.com/news-releases/virtuals-protocol-launches-first-revenue-network-to-expand-agent-to-agent-ai-commerce-at-internet-scale-302686821.html
36. [report] BlockScience/Gitcoin Grants Round 11 anti-fraud evaluation
    (2.1% fraud tax figure for Round 10), 2021.
    https://blog.block.science/gitcoin-grants-round-11-anti-fraud-evaluation-results/ ;
    [vendor] https://www.gitcoin.co/blog/how-to-attack-and-defend-quadratic-funding

Market-based control:

37. [book] Clearwater (ed.). Market-Based Control. World Scientific,
    1996. https://www.worldscientific.com/worldscibooks/10.1142/2741
38. [paper] Wellman. Market-oriented programming (WALRAS line; 1993-1998).
    https://link.springer.com/article/10.1023/A:1008654125853
39. [paper] Dias, Zlot, Kalra, Stentz. "Market-based multirobot
    coordination: a survey and analysis." Proceedings of the IEEE, 2006.
    https://www.ri.cmu.edu/pub_files/2006/7/01677943-1.pdf
40. [preprint] ZEBRA budget-aware orchestration. arXiv:2605.20485, 2026.
    https://arxiv.org/pdf/2605.20485
41. [preprint] COALESCE agent outsourcing. arXiv:2506.01900, 2025.
    https://arxiv.org/abs/2506.01900

2025-2026 sweep:

42. [preprint] AgentX exploration assets. arXiv:2606.26859, 2026.
    https://arxiv.org/pdf/2606.26859
43. [preprint] "LLMs have made failure worth publishing."
    arXiv:2604.06236, 2026. https://arxiv.org/abs/2604.06236
44. [preprint] Erlei, Meub. LLM-agent credence-goods markets.
    arXiv:2603.08853, 2026. https://arxiv.org/pdf/2603.08853
45. [preprint] MCP ecosystem measurement. arXiv:2603.23802, 2026;
    "When AI agents compete for jobs." arXiv:2512.04988, 2025;
    "Security risks of AI agents hiring humans." arXiv:2602.19514, 2026;
    agent-marketplace simulators. arXiv:2604.14256, 2026.

Novelty-sweep methodology (8.6's unclaimed-combination statement): web
searches on 2026-07-20 over these query families - "agent-to-agent
market", "knowledge market for AI agents", "negative results
marketplace", "AI agent economy protocol", "information asymmetry agent
commerce", "verified cognition market", plus citation-chasing from items
8, 14, 18, 42, 44. The claim is bounded by those queries and that date;
it is an absence-of-evidence statement, not an impossibility result.
BAMAS (Nov 2025) was reported by the survey agent without a stable URL
and is listed as UNVERIFIED.
