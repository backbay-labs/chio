# Cognition Market Mechanisms: Pricing, Elicitation, Bonds, Fees

- Status: research draft (branch `research/cognition-market`)
- Scope: the economic design layered on [ARCHITECTURE.md](ARCHITECTURE.md);
  what is deterministic policy vs. tunable parameter vs. open research
- Section 8 carries the external prior-art survey with citations; sections
  1-7 are internal design and cite only this repo

## 1. The pricing problem, stated exactly

The true value of a finding to a buyer is a counterfactual it cannot
compute: `P(would have attempted) x cost-if-attempted x P(would have hit the
same dead end) x redundancy-across-siblings x decay`. No mechanism below
claims to compute this. What IS computable, uniquely on this platform:

- The buyer's **outside option has a posted price.** Re-deriving the result
  is a meterable action with a pre-execution quote
  (`MeteredBillingQuote`, `crates/core/chio-core-types/src/capability/governance.rs:67`).
  Every buyer therefore has a personal, platform-computed substitute price
  for every finding. This is the market's central stabilizing property and
  most designs in the literature lack it (section 8).
- The seller's **production cost is signed evidence**, not a claim
  (`evidence_cost` rollup from receipt cost metadata,
  `crates/economy/chio-metering/src/cost.rs:69`).

Consequences: the clearing band for any trade is
`0 < price <= buyer_rederivation_ceiling`, and a posted price above every
plausible buyer's ceiling simply never clears (buyers re-derive). Production
cost does NOT floor the price - it is sunk, and marginal delivery cost is
near zero. Sellers recover cost only when enough buyers' ceilings sit above
their asks; this is stated plainly rather than engineered away.

## 2. Buyer-side elicitation (deterministic policy)

The ceiling function (spike memo 6.6, spec-tested in
`crates/economy/chio-open-market/tests/cognition_market_flow.rs`):

```
ceiling = min(budget_remaining,
              rederivation_quote
                x would_have_run_bps / 10^4
                x (10^4 - sibling_redundancy_bps) / 10^4
                x guarantee_class_bps / 10^4)
```

Properties, all checkable: deterministic and auditable (an operator can
reconstruct why an agent bid what it bid from signed inputs); hard-capped by
the purchasing allocation (`SwarmBudgetAllocation`,
`crates/kernel/chio-swarm-authority/src/types.rs:281`); monotone in the
quote; zero when the buyer would never have run the work. The two prior
terms (`would_have_run_bps`, `sibling_redundancy_bps`) are planner-owned
inputs - the open research lives THERE, explicitly, not hidden in a price
formula.

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
`recent_receipts_volume`) and their known production cost. No negotiation,
no auction in v1: with a per-buyer substitute ceiling and near-zero marginal
cost, posted-price-with-walkaway loses little efficiency at wedge scale, and
auction machinery is the single most speculative component we could build
(deferred; decision backlog in [PLAN.md](PLAN.md)).

Three pricing structures adopted from the prior art (8.2, 8.5):

- **First-commit priority.** When two sellers commit the same
  `context_sha256` dead end, priority (and the listing slot) goes to the
  earlier commitment timestamp - receipts give trusted timestamps for free.
  Late independent discoverers are not paid for duplication (the Shapley
  replication lesson) but gain the option below.
- **The existence tier.** A "dead-end check" is a separate, much cheaper
  product: pay a small fee to learn "this context digest has a committed
  finding" (the bug-bounty duplicate problem, priced instead of triaged).
  It leaks one bit by design; its price is that bit's value, and the full
  finding remains the paid reveal.
- **Versioning and freshness over DRM.** Findings decay with the codebase
  or experiment space; sellers price the decay (`expires_at`), can scope a
  version to the buyer's context (commit-bound fixes are inherently
  buyer-versioned), and exclusivity, where offered, is a listing term with
  legal force only (Bergemann-Bonatti; threat model B2).

## 4. Time-structure of seller revenue (the anti-fraud lever)

Rather than sizing bonds to cover unbounded fraud, structure revenue so
fraud claws back:

- **Vesting via dispute windows.** Seller revenue for a finding stays
  claw-backable until its dispute window passes. The amount-tiered window
  machinery exists (`dispute_window_secs` tiers in
  `crates/economy/chio-settle/src/config.rs:122`); the escrow path (F6)
  gives it teeth for cross-org sales, and within one operator the
  reconciliation sidecar records window state per receipt.
- **Bond covers the tail.** The listing bond then only needs to cover
  revenue already finalized when a late fraud proof lands, plus the harm
  premium. Suggested relation (policy parameter, not protocol):
  `bond >= k x max_outstanding_windowed_revenue`, k >= 1.
- **Slash distribution** goes to harmed buyers pro rata by purchase amount,
  community fund for the remainder - already the enforced shape
  (`validate_bond_impair_distribution` exact-sum,
  `crates/economy/chio-settle/src/evm/prepare.rs:989-1020`; ADR-0015 D4).

## 5. Challenge economics (griefing vs. deterrence)

- Challenger posts the Dispute-class bond (`OpenMarketBondClass::Dispute`,
  `crates/economy/chio-open-market/src/fee_schedule.rs:14`) plus the
  `dispute_fee`.
- Suggested sizing: `challenge_bond ~= c x metered_replay_cost`, c in
  [1, 2]. The challenger's real cost is the mediated re-execution itself
  (metered, unavoidable); the bond only needs to make spray-and-pray
  challenges negative-EV, not to price the seller's inconvenience.
- Failed challenge: bond forfeits to the challenged seller (the harmed
  party; invariant 9 compliant). Successful challenge: bond returns +
  challenger receives a predeclared bounty share of the slash (parameter;
  bounded by the harmed-parties-first rule).
- Griefing asymmetry to watch (threat model B4): a deep-pocketed rival can
  still force sellers to babysit challenges; mitigation is that replay
  challenges auto-evaluate (pure evaluator, no seller action needed) - the
  seller's cost of a frivolous replay challenge is zero attention, which is
  the real griefing defense.

**Probabilistic audits (the theoretically required complement).** The
elicitation literature's decisive result (8.3) says buyer-initiated
challenges alone cannot deter fabrication of claims nobody re-buys or
re-checks; limited random ground-truth checks dominate every
peer-prediction scheme. So the venue (or a pool acting for its buyers)
randomly audits listed `deterministic_replay` findings by running the
committed recipe, funded by a slice of the participation fee, at a
published rate. Deterrence condition, sized per listing class:

```
audit_rate x slash_amount >= expected_fabrication_profit
```

where `expected_fabrication_profit ~= price x expected_sales_in_window`.
Audit outcomes are ordinary challenge artifacts (the auditor is just a
bonded challenger whose bond the venue fronts). Market/peer signals
(descriptor-overlap disagreement between sellers, replication-market-style
priors) only PRIORITIZE audit targets - they never settle anything
(8.3's ~73% accuracy is prior-grade, not settlement-grade).

## 6. Fees, spam, and admission

All three fee/bond hooks exist in the shipped fee schedule artifact
(`OpenMarketFeeScheduleArtifact { publication_fee, dispute_fee,
market_participation_fee, bond_requirements }`,
`crates/economy/chio-open-market/src/fee_schedule.rs:71`):

- Publication fee: the spam floor for listings (threat model S6).
- Listing bond, `slashable: true`: the fraud stake (F1 admission requires
  it; `BondBackingRequired` keeps unbacked listings review-only,
  `crates/economy/chio-listing/src/trust_activation.rs:565`).
- Participation fee: venue sustainability; keep near zero for the wedge.

The deeper anti-spam economics is the metering floor: a listing that wants
to look credible must reference real burned compute (`evidence_cost`), so
junk listings are either evidence-free (filtered by buyer policy) or cost
approximately honest work to fake (threat model S2/C1).

## 7. Pool purchasing and redundancy

One purchasing principal per swarm budget pool (ARCHITECTURE F-flows;
`SwarmBudgetPool` fan-out,
`crates/kernel/chio-swarm-authority/src/types.rs:247`):

- Intra-pool: the pool buys once and distributes internally via governed
  memory writes; `sibling_redundancy_bps` inside the pool goes to ~0, which
  RAISES the pool's collective ceiling versus any single member's - the
  dedup surplus funds the purchase.
- Inter-pool: pools are independent buyers; a seller's expected revenue is
  (number of distinct pools hitting the context) x clearing price, which is
  the honest demand curve for a dead end.
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

Survey run 2026-07-20 (web-verified; flagged items noted). Full citations
inline; the design implications are folded into sections 2-7 and the
architecture.

### 8.1 Fair exchange and paying for secrets

- Strong two-party fair exchange without a TTP is impossible (Pagnia and
  Gartner 1999, FLP-style reduction). Kernel-as-TTP is theorem-mandated,
  not a design smell; the only freedom is when the TTP engages.
- Zero-Knowledge Contingent Payment was broken twice: buyer-chosen CRS let
  buyers extract information without paying (Campanelli et al., CCS 2017,
  eprint 2017/566), and the proposed fix for contingent services fell to
  Fuchsbauer 2019 (eprint 2019/964). Lessons adopted: verification
  parameters and harnesses are generated/pinned by the kernel, never by a
  counterparty; and evidence-without-content is itself a leakage channel -
  see 8.6 side-channel note.
- FairSwap (CCS 2018) / OptiSwap (2020): proving misbehavior should be
  cheap (short Merkle proof to a judge) while the happy path stays thin;
  bond both sides against griefing. v2 option: Merkle-chunked payload
  commitments so a buyer can prove a specific delivered chunk violates the
  claim without revealing the rest.

### 8.2 Data marketplaces

- Shapley-style contribution payouts are structurally gameable by
  replication/sybils (Agarwal-Dahleh-Sarkar EC 2019
  robustness-to-replication axiom; Data Shapley manipulation line
  2019-2026). Adopted: pay per unique committed artifact, first-commit
  priority by digest timestamp, never similarity-scaled payouts.
- Deployed privacy-tech marketplaces (Ocean compute-to-data, iExec, Oasis)
  shipped supply tech but found no demand (one academic count: 6,826 Ocean
  transactions May 2022 - June 2025; single source, flagged). Diagnosis:
  buyers could not value unseen data. Chio's buyer has a metered
  counterfactual (section 1) - that demand-side price cap is the moat and
  must be productized, not just documented.
- Bergemann-Bonatti (Annu. Rev. Econ. 2019): freely replicable information
  resells to zero; survivors sell versions, freshness, exclusivity.
  Adopted in section 7's decay framing and 3's versioning note.

### 8.3 Elicitation without verification (the decisive negative result)

Peer prediction (2005), Bayesian Truth Serum (2004), Dasgupta-Ghosh (2013)
all require multiple correlated reports; and Gao-Wright-Leyton-Brown
(2016/AIJ 2019) show that with costly evaluation these mechanisms create
low-effort/collusive equilibria, while even limited ground-truth spot
checks dominate. Direct answer to open problem "can elicitation make
fabricated nulls unprofitable without re-execution": **no**. Adopted
consequence: settlement-grade fraud decisions come only from re-execution
audits plus slashing (8.5, section 5); peer/market signals (including
LLM-era peer elicitation, 2024-2026) only target the audits. Replication
prediction markets hit ~73% accuracy (PLOS ONE 2021) - audit-prior grade,
not settlement grade.

### 8.4 Scientific-knowledge markets

- Negative-results journals failed on supply: authors will not spend effort
  packaging negatives (JNRBM closed 2017; ~20% of null studies published,
  ~65% never written up). The structural fix Chio makes: negatives are
  automatic exhaust of metered runs, paid at production, zero marginal
  authoring cost.
- Registered Reports: hypothesis-support rates drop from ~96% (standard) to
  ~44% (pre-registered) - commit-before-outcome massively de-biases
  reporting. Adopted into the artifact: the optional pre-outcome intent
  commitment (`intent_commitment_receipt_id`, ARCHITECTURE 4.1) chains the
  descriptor to a receipt that predates the outcome.
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
  checkable claims plus bonded submission is precisely the missing
  throttle - the strongest live evidence the wedge is real now.
- Agent payment rails are commodity: x402 (100M+ transactions on Base
  independently confirmed by Chainalysis by Q1 2026; sub-$0.50 median),
  Google AP2 mandates, Stripe/OpenAI ACP. None verifies delivery. Position
  Chio receipts as the delivery-verification layer over those rails (the
  x402 adapter already exists, `crates/kernel/chio-kernel/src/payment.rs`).
  Sub-dollar medians confirm: dispute machinery must amortize off the hot
  path (it does - pure-evaluator challenges, windowed finality).
- Virtuals ACP self-reports 1.77M agent jobs with escrow lifecycle
  (PR figures, unverified) - but its evaluation step is an LLM opinion.
  The differentiator to hold: Chio's evaluator is a deterministic re-run
  receipt.
- Erlei-Meub (arXiv 2603.08853, 2026): LLM-agent credence-goods markets
  collapse in one-shot settings without liability institutions; reputation
  alone is empirically insufficient. Bonds are load-bearing; size them
  per-listing (section 4), not per-identity.

### 8.6 Swarm scale and the side channel

- Market-based control: flat auctions break past small n (combinatorial
  winner determination, per-bid planning cost); markets scale when the
  mission decomposes into subteams with nested envelopes (Clearwater 1996;
  Wellman; Dias et al., Proc. IEEE 2006). 2025-26 LLM-orchestration work
  (COALESCE, ZEBRA) re-derives the same make-vs-buy-per-node conclusion.
  Section 7's pool-purchasing rule is this, on the shipped budget tree.
- Side channel adopted into the threat model (X2): the ZKCP episode
  generalizes - metered cost, step counts, and timing in the EVIDENCE can
  leak the finding (a cheap run screams "failed early"). Mitigation:
  bucketed `evidence_cost` disclosure in public descriptors, exact values
  inside the paid reveal; leakage-ledger accounting for descriptor fields.
- Novelty check (stated plainly): after multiple query formulations, no
  existing system or paper combines verified negative results, agent
  principals, cryptographic delivery receipts, and bonded settlement.
  Components exist separately (x402 escrow lifecycles, AgentX's private
  failure cache, arXiv 2606.26859; execution receipts). The combination
  appears unclaimed as of 2026-07-20.

## 9. Open mechanism problems (delta over the spike memo)

One former open problem is now CLOSED by the literature: "can elicitation
make fabricated nulls unprofitable without re-execution" - no (8.3); the
audit + slash design in section 5 is the answer, and only its parameters
remain open.

1. `would_have_run` priors: can a planner's own historical receipt corpus
   calibrate them (a local, non-tradeable statistic - safe from gaming by
   construction)? research.
2. Cross-pool demand aggregation without collusion surface: research. If
   ever mechanized, Kremer's random-execution trick (8.4) is the known
   honesty device for stated-valuation bids.
3. Audit-rate / bond / window parameter tuning against real fraud-gain
   distributions: engineering-with-data once the wedge runs (the deterrence
   inequality in section 5 is the frame).
4. Descriptor granularity economics (coarse topics leak less but match
   worse), now including evidence side-channel bucketing (8.6): what
   `evidence_cost` bucket widths and timing coarsening keep descriptors
   useful but non-leaky? engineering, with a leakage-ledger audit.
5. Whether failed-challenge forfeiture to the seller invites
   seller-initiated fake challenges against themselves to farm forfeits
   (self-challenge wash): analysis says no profit when `c >= 1` because the
   challenger's metered replay cost is real and the forfeit merely refunds
   the seller's own spend, but this deserves a formal writeup: engineering.
6. Existence-tier pricing (section 3): the one-bit reveal's price as a
   function of descriptor entropy; research-adjacent, low stakes at wedge
   scale.
