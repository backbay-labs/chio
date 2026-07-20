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
- The seller's **production cost is verifiable evidence in full-receipt
  mode only** (mode A in ARCHITECTURE F2): there the rollup can be checked
  against receipt cost metadata
  (`crates/economy/chio-metering/src/cost.rs:69`). In projected-evidence
  mode (mode B, the side-channel-preserving one) the receipts' metadata
  slot is hidden and no validator ties the rollup to the receipt sum
  before purchase, so `evidence_cost` is a SELLER ASSERTION until audit.
  Policies that lean on cost (admission floors, pricing, the
  "meter is the spam filter" argument) must either require mode A or
  treat mode-B cost as asserted; a verifiable cost proof for mode B (for
  example a dedicated cost slot in a future receipt projection) is an
  open engineering item.

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

- **First-commit ordering, without exclusivity.** Receipt timestamps are
  NOT a cross-operator total order (each kernel's clock is an audited
  assumption, and nothing tie-breaks across seller operators), so no
  listing slot is awarded by timestamp - that would invite clock gaming
  and suppress independently useful payloads sharing a context digest.
  Instead: duplicate-context listings coexist; buyers rank them; priority
  is an INFORMATIONAL ordering by anchored commitment (checkpoint/anchor
  inclusion of the intent commitment or evidence receipts, with the
  anchor's own order as the tie rule). The Shapley-replication lesson is
  preserved where it matters - nobody is PAID for duplication
  (per-unique-artifact purchases, no similarity-scaled payouts) - without
  minting a race-prone exclusive slot.
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

Corrected on review: the shipped machinery OBSERVES dispute windows, it
does not enforce custody through them. `ChioEscrow.releaseWithProofDetailed`
transfers funds immediately on proof; `chio-settle`'s finality inspection
can label a transaction `AwaitingDisputeWindow` but cannot reverse it; the
kernel MustPrepay path settles and reconciles before any later challenge;
and M4/M5 add no custody mechanism. So in v1 there is NO revenue clawback,
and the design must not pretend otherwise:

- **Bond covers finalized exposure.** The listing bond is sized for ALL
  fraud revenue that can finalize before detection, not a tail:
  `bond >= k x price x expected_sales_within_detection_horizon`, k >= 1.
  The amount-tiered `dispute_window_secs` values
  (`crates/economy/chio-settle/src/config.rs:122`) serve as the published
  DETECTION-HORIZON parameter (how long buyers/auditors have before the
  venue treats revenue as fraud-exposed history), not as custody.
- **Capture-delay is a future custody option, not a v1 claim.** Holding
  escrow release (or MustPrepay capture) until a window closes would need
  new escrow semantics or a custody profile - a decision-backlog ADR if
  wedge data shows bonds alone underprice fraud (PLAN section 4).
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

Honesty note on shipped state: as of pre-#974 main the fee schedule is
DECLARATIVE - the artifact carries the amounts and validates their shape
(`fee_schedule.rs:79-109`), but nothing collects a publication fee at
publish time or a dispute fee at challenge time (confirmed by source
sweep). PR #974 introduces `chio-open-market/src/fiscal_adapter.rs` and a
`chio_fiscal` resolver that rework this surface; M2 re-verifies whether
collection exists post-#974 before repeating this claim (PLAN section 0). Fee COLLECTION is engineering the plan must
carry: settle the publication fee as part of listing admission (M2) and
the dispute fee as part of challenge submission (M5), both as ordinary
metered/settled charges so the fee trail is receipts, not bookkeeping.

The deeper anti-spam economics is the metering floor: a listing that wants
to look credible must reference real burned compute, so junk listings are
either evidence-free (filtered by buyer policy) or cost approximately
honest work to fake (threat model S2/C1). Mode caveat (review finding):
this floor is load-bearing only where the cost is verifiable - mode A
full-receipt evidence, or post-audit. A mode-B listing's `evidence_cost`
is an assertion, and admission policies must not treat it as burned-work
proof (section 1).

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
  2019-2026). Adopted: pay per unique committed artifact, never
  similarity-scaled payouts; duplicate contexts coexist with
  informational anchored-commitment ordering (section 3 - kernel clocks
  are not a cross-operator order).
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

One former open problem is NARROWED by the literature (not closed -
review correction): within Gao et al.'s costly-evaluation model, limited
ground truth dominates the analyzed peer-prediction class, which is why
section 5 settles fraud only by re-execution audits plus slashing. Whether
any mechanism outside that model can deter fabricated singletons without
re-execution stays open as problem 7 below.

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
7. Elicitation without re-execution, outside the Gao et al. model
   assumptions (8.3): open research; audits remain the settlement design
   regardless of its resolution.
8. Verifiable cost proofs for projected-evidence listings (section 1's
   mode-B gap): engineering, likely a dedicated cost slot in a future
   receipt projection version.

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
