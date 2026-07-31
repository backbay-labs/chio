# Cognition Market Threat Model

- Status: research draft (branch `research/cognition-market`)
- Scope: the finding market designed in [ARCHITECTURE.md](ARCHITECTURE.md) and
  [ADR-0017](../../adr/ADR-0017-cognition-market-finding-artifacts.md), both
  instances (coding-agent verified fixes; R&D negative results)
- Method: assets -> trust assumptions -> adversaries -> attack catalog with
  mitigations mapped to shipped primitives (paths cited) -> residual-risk
  register. Severity is rated for the wedge instance first, vision instance in
  parentheses where different.

## 1. Assets

- A1. Finding content (the sealed payload) - confidentiality until paid
  reveal; integrity against substitution.
- A2. Buyer funds - no capture without a kernel-attested reveal of the
  committed digest (an Allow proves kernel acceptance of the preimage,
  not buyer receipt/retention - ARCHITECTURE 6.2; the post-Allow crash
  window is F3 step 6).
- A3. Seller bond - no slash without a predeclared, evidence-gated rule.
- A4. Market truthfulness - listings, evidence bundles, and status feeds mean
  what they claim (evidence-class discipline).
- A5. Buyer memory/state - purchased content must not poison the buying
  agent's memory beyond what its ingestion policy allows.
- A6. Reputation capital - scorecards and tiers must not be inflatable below
  the cost of honest behavior.

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
  mediating operator learns purchased findings; a TEE-hosted kernel
  (`crates/trust/chio-attest-verify` quote binding, `src/quote.rs:162`)
  reduces but does not eliminate operator exposure. This is a designed-in TTP,
  not an oversight; it is listed here so nobody claims otherwise.
- T2. The finding-status feed operator (revocation-oracle instance) is trusted
  for liveness; safety (equivocation, staleness) is checkable via signed epoch
  roots, freshness windows, and anchoring
  (`crates/trust/chio-revocation-oracle/src/api.rs:86,116`, `src/freshness.rs`).
- T3. The adjudication roster for non-mechanical disputes (ADR-0015 follow-up
  B; `crates/economy/chio-market/src/claim.rs:38-50`). Mechanical rules
  (digest mismatch, evidence re-verification, deterministic replay) minimize
  what this role decides.
- T4. The crypto-context signer for any hidden-predicate claims
  (`crates/trust/chio-disclosure-lineage/src/types.rs:93`).

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

### Seller-side

- **S1. Fabricated evidence bundle** (invented receipts, wrong checkpoint).
  Mitigated: buyers re-verify receipt signatures, checkpoint inclusion, and
  revocation state fail-closed, exactly as claims do
  (`crates/economy/chio-market/src/insurance_flow.rs:390-414`; buyer boundary
  `crates/trust/chio-attest-buyer/src/api.rs`). Slash lane:
  `FabricatedFindingEvidence` abuse class through the enforced-Sanction gate
  (`crates/economy/chio-open-market/src/evaluation.rs:356-451`). Residual: none
  beyond assumption registry. Severity if unmitigated: high; residual: low.
- **S2. Honest-cost fabrication** (seller really burns the compute, claims a
  wrong result). Mitigated for `deterministic_replay` findings by bonded
  challenge re-execution AND venue-funded probabilistic audits sized so
  `audit_rate x slash >= expected fabrication profit` (MECHANISMS section
  5; the elicitation literature proves spot-check re-execution is the only
  settlement-grade deterrent, MECHANISMS 8.3); the metering floor makes
  the attack cost approximately the honest cost
  (`crates/core/chio-core-types/src/receipt/economics.rs:33`), and the
  pre-outcome intent commitment (ARCHITECTURE 4.1) removes the
  selective-reporting variant (committing the protocol before the outcome
  is known, Registered-Reports logic). Residual for `metered_attested`
  findings: REAL AND ACCEPTED - carried by bonds, guarantee-class
  discounts, reputation, not by proof. Severity: medium (high for the R&D
  instance; this is its central open problem).
- **S3. Bait-and-switch payload** (serve bytes not matching the commitment).
  Mitigated structurally: the delivery contract refuses an Allow receipt
  unless output hash equals the committed `payload_sha256` (enforcement-point
  options in ARCHITECTURE; WYSIWYS gate at
  `crates/core/chio-core-types/src/receipt/body.rs:325`). A failed check is a
  Deny/Incomplete receipt and the pre-execution budget mutation reverses
  (`crates/kernel/chio-kernel/src/kernel/validation.rs:1102`). Residual: none.
- **S4. Selling stale/retracted findings.** Mitigated: expiry on the artifact;
  buyer demands a fresh non-inclusion proof from the status feed at purchase
  (`RevocationOracle::non_inclusion_proof`,
  `crates/trust/chio-revocation-oracle/src/api.rs:116`) inside the freshness
  window. Residual: retraction between proof and reveal (window-bounded).
- **S5. Plagiarized finding** (listing someone else's payload). Mitigated:
  the evidence receipts bind the producing subject and capability chain; a
  buyer checks `finding.issuer` consistency with the evidence receipts'
  subject/lineage (`crates/core/chio-core-types/src/receipt/lineage.rs:228`).
  Residual: cross-org copying of an ALREADY-REVEALED finding re-listed with
  the copier's own cheap wrapper receipts - detectable only by descriptor
  collision (same `context_sha256`, later timestamp) and priced by
  reputation. Medium residual, inherent to information goods.
- **S6. Listing spam / descriptor squatting.** Mitigated: publication fees +
  publication/listing bonds already exist
  (`crates/economy/chio-open-market/src/fee_schedule.rs:71`), plus
  `SpamPublication` penalties (`src/penalty.rs:21`) and namespace-owned
  listings (`crates/economy/chio-listing/src/listing.rs:103`). Residual: low.
- **S7. Non-delivery after payment.** Within one operator - mitigated:
  hold/escrow terminal states are release-on-proof or
  refund-after-deadline only (ADR-0015 D2; `contracts/src/ChioEscrow.sol`;
  MustPrepay refund path
  `crates/kernel/chio-kernel/src/kernel/dispatch.rs:170`); residual is
  buyer liquidity time-locked until the deadline, no loss. Cross-org
  (review correction): with a seller-aligned mediating operator the
  attest-and-withhold attack (O5) makes paid non-delivery a HIGH
  residual; the escrow profile requires a neutral/mutually trusted
  mediator or is disallowed (ARCHITECTURE F6).

### Buyer-side

- **B1. Take the reveal, refuse payment.** Within one operator:
  structurally prevented - funds are reserved before the capability is
  minted (reservation receipt gate,
  `crates/economy/chio-open-market/src/bidding.rs:210,439`) and the reveal
  settles from the pre-authorized hold. Cross-org (review correction: the
  earlier "structurally impossible" claim was false for one operator
  choice): fairness depends on the escrow naming the MEDIATING operator
  and on `dpop_required` grants (ARCHITECTURE F6); without those, a
  buyer-side escrow operator can observe the reveal and withhold the
  checkpoint into a refund. Residual: the F6 operator model plus the M7
  withhold-root test.
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
- **B4. Malicious challenge to slash an honest seller.** Mitigated: challenges
  post the existing Dispute-class bond (`fee_schedule.rs:14`), decision rules
  are predeclared and mechanical where possible, outcomes are a fixed enum
  with amount envelopes, appeal reverses wrongful slashes
  (`crates/economy/chio-open-market/src/evaluation.rs:385-431`), destinations
  cannot enrich the protocol (ADR-0015 D4, invariant 9). Residual: griefing
  cost asymmetry needs tuning (challenge bond vs. seller's time); tracked in
  MECHANISMS.
- **B5. Blame-the-seller memory poisoning** (buyer claims delivered content
  poisoned it). Mitigated: the delivery receipt binds exactly what bytes were
  delivered (digest); ingestion is the buyer's own governed write under its
  own guards (`crates/guards/chio-guards/src/memory_governance.rs:60`), with
  the provenance chain separating delivery from ingestion decisions
  (`crates/kernel/chio-kernel/src/memory_provenance.rs:63`). Residual: none
  for attribution; content-level harm is B2-adjacent buyer policy.

### Collusion and sybil

- **C1. Wash trading to inflate reputation** (self-dealing purchases).
  Mitigated: every trade burns real metered budget and fees; reputation
  scorecards only count integrity-gated receipts
  (`crates/trust/chio-reputation/src/lib.rs:50-74`) and Tier3 requires two
  distinct evidence feeds (`src/tier.rs:98-139`); wash volume shows as
  self-referential lineage (same root budget holder,
  `delegation_depth`/`root_budget_holder` on financial metadata). Residual:
  a patient adversary can still buy reputation at metering cost; the defense
  is that the purchase price of credibility equals honest work. Medium.
- **C2. Collusive challenge rings** (challenger and seller split slash
  proceeds). Mitigated: slash destinations are constrained to harmed parties
  or the community fund, never chooseable payees (ADR-0015 D4; comptroller
  `market_slash` payee check,
  `crates/platform/chio-risk-comptroller/src/ledger.rs`), removing the
  profit motive. Residual: low.
- **C3. Sybil seller farms** (many identities listing junk). Mitigated:
  per-identity bonds and fees; `BondBacked` admission class keeps unbacked
  listings review-only
  (`crates/economy/chio-listing/src/trust_activation.rs:565`). Residual:
  bounded by bond capital; acceptable.

### Operator-level

- **O1. Front-running / leakage by the mediating operator** (T1). Mitigated
  partially: TEE-bound kernels (boot self-quote gate,
  `crates/kernel/chio-kernel/src/boot.rs:114`) shrink the operator's
  software-level access; receipts + lineage make operator-side republication
  attributable (S5 forensics). Residual: REAL for cross-org purchases
  mediated by an untrusted operator; the honest posture is that buyers with
  confidentiality-critical purchases keep them within trusted-operator or
  TEE-tier boundaries. Severity: medium (high for R&D instance with
  commercially explosive findings).
- **O2. Status-feed censorship or stall** (suppressing a retraction).
  Mitigated: epoch roots are signed, freshness-windowed
  (`chio-revocation-oracle/src/freshness.rs`), and anchorable via the
  existing multi-lane anchor path (`crates/economy/chio-anchor/src/lib.rs`);
  a stale root fails buyers closed (they refuse purchase without a fresh
  non-inclusion proof). Residual: liveness denial = market pause, not loss.
- **O3. Status-feed equivocation** (different roots to different buyers).
  Mitigated: anchoring makes divergent roots globally detectable; signed
  roots make equivocation attributable and slashable (operator bond).
  Residual: detection lag equal to anchor cadence.
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
  requires a neutral/mutually trusted mediator (ARCHITECTURE F6); with a
  seller-aligned mediator severity stays HIGH (paid non-delivery), and
  M7 owns the operator-model decision plus the withhold-response
  adversarial test.
- **O4. Adjudicator compromise** (T3). Mitigated: predeclared rosters +
  decision-rule refs are validated fail-closed
  (`crates/economy/chio-market/src/claim.rs:38-50`), outcome sets and amount
  envelopes are fixed (ADR-0015 D5), appeals reverse. Residual: roster
  governance is institutional; minimized by keeping mechanical rules
  mechanical.

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
  bucketing without projection is self-defeating.
  Residual: the existence of a listing is itself one bit that cannot be
  hidden; the existence tier (MECHANISMS section 3) prices that bit
  instead of denying it. Medium (higher for R&D).

## 5. Residual-risk register (ranked)

| Risk | Instance | Severity | Owner of residual |
|---|---|---|---|
| Honest-cost fabrication of `metered_attested` nulls (S2) | R&D | high | pricing (guarantee-class discounts) + bonds; open research |
| Post-reveal resale/leakage (B2) | both | high-by-nature | pricing assumption; license terms out-of-protocol |
| Operator sees revealed content cross-org (O1/T1) | both | medium-high | deployment policy (TEE tier, trusted-operator scoping) |
| Reputation purchasable at metering cost (C1) | both | medium | economics tuning; Sybil gates |
| Descriptor metadata leakage (B3/X1) | R&D | medium | seller topic granularity; leakage budgets |
| Retraction race window (S4) | both | low-medium | freshness-window tuning |
| No revenue clawback in v1 (fraud revenue finalizes; MECHANISMS 4) | both | medium | bonds sized for finalized exposure; capture-delay custody is a backlog ADR |
| Paid non-delivery under a seller-aligned cross-org mediator (S7/O5 attest-and-withhold) | cross-org | high | F6 neutral-mediator requirement; M7 withhold-response test; profile disallowed otherwise |
| Challenge griefing asymmetry (B4) | wedge | low-medium | bond-size tuning (MECHANISMS) |
| Plagiarism of revealed findings (S5) | both | medium | forensic + reputational only |

## 6. Invariant mapping

The market inherits and must not weaken: invariants 9/10 (slash proceeds
never to insiders; no discretionary settlement - ADR-0015), P1 attenuation
(purchase capabilities are narrow single-use grants), P4 receipt integrity
(delivery proofs), P10 truthfulness (evidence classes never upgraded, which
is what keeps `asserted` findings from masquerading as verified). New
invariant candidates the implementation should formalize are listed in
[PLAN.md](PLAN.md) (delivery-contract soundness; status-feed freshness
monotonicity; challenge-outcome envelope).
