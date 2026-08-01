# Chio Economic Layer: Technical Overview

**Status:** Active technical documentation
**Scope:** The 7 economic crates, their composition, the money flow, insurance, settlement, and marketplace

---

## 0. Why Chio Has an Economic Layer

Chio is 80% of a payment authorization system. This is not metaphor. The core
protocol primitives map directly onto financial infrastructure:

| Chio Primitive | Financial Equivalent |
|---------------|---------------------|
| `CapabilityToken` | Spending authorization / corporate card |
| `ToolGrant.max_total_cost` | Pre-authorized spending limit |
| `DelegationLink` chain | Cost-responsibility chain / cost center hierarchy |
| `Attenuation::ReduceTotalCost` | Sub-budget allocation |
| `ChioReceipt` with `FinancialReceiptMetadata` | Billing ledger entry |
| `BudgetStore.try_charge_cost` | Real-time balance check |
| `GovernedTransactionIntent` + `GovernedApprovalToken` | Purchase order + approval workflow |

The remaining 20% -- metering, credit risk, underwriting, insurance placement,
on-chain settlement, and marketplace economics -- is what the 7 economic crates
provide. No competing agent governance protocol has typed risk taxonomies,
insurance underwriting, or on-chain settlement for agent behavior.

This document explains what each crate does, how they compose into a full
economic layer, and where the gaps remain.

---

## 1. The Seven Economic Crates

The economic layer is built as a stack. Each crate depends on the ones below
it. From bottom to top:

```
                         chio-open-market
                              |
                         chio-market
                        /          \
                chio-listing     chio-settle
                        \          /
                         chio-credit
                              |
                       chio-underwriting
                              |
                        chio-metering
                              |
                    chio-core (capability, receipt, crypto)
```

### 1.1 chio-metering: Cost Attribution and Budget Enforcement

**Purpose:** Per-receipt cost tracking, cumulative cost queries, monetary budget
enforcement, and billing-export-compatible cost records.

**Key types:**

- `CostMetadata` / `CostDimension` -- per-receipt cost attribution covering
  compute time, data volume, and API cost dimensions
- `BudgetEnforcer` / `BudgetPolicy` / `BudgetViolation` -- monetary budget
  enforcement with denominated currency support and configurable policy
- `CostQuery` / `CostQueryResult` / `CostSummary` -- CLI-style cost queries
  filterable by session, agent, tool, or time range
- `BillingExport` / `BillingRecord` -- billing-export-compatible cost records
  suitable for downstream invoicing or analytics systems

**Role in the stack:** chio-metering is the ground truth for "how much did this
cost." Every receipt that passes through the kernel can carry structured cost
metadata. The budget enforcement module checks spending limits before tool
execution proceeds. The export module produces records that external billing
systems can ingest.

### 1.2 chio-underwriting: Agent Risk Assessment

**Purpose:** Typed risk classification of agent behavior with evidence-based
decision logic, appeal workflows, and premium pricing.

**Key types:**

- `UnderwritingRiskClass` -- four-tier risk taxonomy: `Baseline`, `Guarded`,
  `Elevated`, `Critical`
- `UnderwritingReasonCode` -- 13 typed reasons for risk elevation, including
  `ProbationaryHistory`, `LowReputation`, `ImportedTrustDependency`,
  `MissingCertification`, `FailedCertification`, `RevokedCertification`,
  `MissingRuntimeAssurance`, `WeakRuntimeAssurance`,
  `PendingSettlementExposure`, `FailedSettlementExposure`,
  `MeteredBillingMismatch`, `DelegatedCallChain`, and
  `SharedEvidenceProofRequired`
- `UnderwritingDecisionOutcome` -- four possible outcomes: `Approve`,
  `ReduceCeiling`, `StepUp`, `Deny`
- `UnderwritingDecisionPolicy` -- configurable policy with thresholds for
  minimum receipt history, maximum receipt age, reputation score floors,
  runtime assurance tier requirements, certification requirements, and ceiling
  reduction factors
- `UnderwritingPolicyInput` -- the signed evidence package consumed by the
  decision evaluator, containing receipt evidence, reputation evidence,
  certification evidence, runtime assurance evidence, and derived risk signals
- `UnderwritingDecisionArtifact` -- the signed decision artifact carrying the
  evaluation report, review state, budget recommendation, and premium quote
- `UnderwritingBudgetRecommendation` -- typed budget action (`Preserve`,
  `Reduce`, `Hold`, `Deny`) derived from the decision outcome
- `UnderwritingPremiumQuote` -- risk-class-scaled premium in basis points with
  explicit state (`Quoted`, `Withheld`, `NotApplicable`)
- `UnderwritingAppealRecord` -- appeal workflow with explicit lifecycle
  (`Open`, `Accepted`, `Rejected`) and optional replacement decision linkage
- `UnderwritingSimulationReport` -- non-mutating what-if comparison of default
  vs. custom policy over the same evidence

**The evaluation logic:** `evaluate_underwriting_policy_input` is a pure
function that takes an evidence package and a policy, then produces a
deterministic decision report. It checks:

1. Sufficient receipt history (minimum count threshold)
2. Receipt freshness (maximum age window)
3. Reputation score against approve and deny thresholds
4. Runtime assurance tier against step-up and approve floors
5. All policy-relevant signals from the evidence package

The highest-severity finding determines the outcome. `Deny` beats `StepUp`
beats `ReduceCeiling` beats `Approve`. Each finding carries evidence
references back to concrete receipts, reconciliation rows, or reputation
inspections.

**Premium pricing:** When the outcome is `Approve` or `ReduceCeiling`, the
crate computes a premium in basis points scaled by risk class. Baseline
approval is 100 bps; critical approval is 300 bps. Ceiling-reduced decisions
carry higher premiums (150-600 bps). Step-up and deny outcomes withhold or
decline pricing.

**Role in the stack:** chio-underwriting sits between raw cost data
(chio-metering) and credit/insurance decisions (chio-credit, chio-market). It
answers the question: "Given this agent's history, what risk does it
represent, and what should we charge for coverage?"

### 1.3 chio-credit: Exposure, Credit Scoring, Facilities, Bonds, and Capital

**Purpose:** Credit risk management for agent economic activity. Tracks
exposure positions, produces credit scorecards, issues credit facilities,
manages collateral bonds, handles loss lifecycle events, and maintains capital
books.

This is the largest economic crate. It contains several interconnected
sub-systems:

**Exposure Ledger** (`ExposureLedgerReport`)

The signed economic-position projection over governed receipts and persisted
underwriting decisions. Partitions totals by currency (never nets across
currencies). Key fields per currency position:

- `governed_max_exposure_units` -- maximum authorized exposure
- `reserved_units` / `settled_units` / `pending_units` / `failed_units` --
  settlement state breakdown
- `provisional_loss_units` / `recovered_units` -- loss tracking
- `quoted_premium_units` / `active_quoted_premium_units` -- premium exposure

**Credit Scorecard** (`CreditScorecardReport`)

Subject-scoped credit posture over the exposure ledger plus local reputation
inspection. Key concepts:

- `CreditScorecardBand` -- five bands: `Prime`, `Standard`, `Guarded`,
  `Probationary`, `Restricted`
- `CreditScorecardConfidence` -- `Low`, `Medium`, `High`
- `CreditScorecardDimensionKind` -- four scoring dimensions:
  `ReputationSupport`, `SettlementDiscipline`, `LossPressure`,
  `ExposureStewardship`
- Explicit probation tracking with receipt count and span thresholds
- Anomaly detection with typed reason codes and severity levels

**Credit Facility** (`CreditFacilityArtifact`)

Bounded allocation recommendations based on scorecard posture:

- `CreditFacilityDisposition` -- `Grant`, `ManualReview`, `Deny`
- `CreditFacilityTerms` -- credit limit, utilization ceiling (bps), reserve
  ratio (bps), concentration cap (bps), TTL, and capital source
- `CreditFacilityPrerequisites` -- minimum runtime assurance tier,
  certification requirements
- Lifecycle management with supersession and expiry

**Credit Bond** (`CreditBondArtifact`)

Reserve posture evaluation:

- `CreditBondDisposition` -- `Lock`, `Hold`, `Release`, `Impair`
- `CreditBondTerms` -- facility linkage, credit limit, collateral amount,
  reserve requirement, outstanding exposure, reserve/coverage ratios
- Bond artifacts gate bounded autonomy tiers at runtime

**Credit Loss Lifecycle** (`CreditLossLifecycleArtifact`)

Explicit loss events: `Delinquency`, `Recovery`, `ReserveRelease`,
`ReserveSlash`, `WriteOff`. Each event is a signed artifact with explicit
authority chains, execution windows, custody rails, and appeal windows.
Accounting rules are strict:

- Recovery and write-off cannot exceed outstanding delinquency
- Reserve release cannot happen while delinquency remains open
- Reserve slash cannot exceed slashable reserve
- Mixed-currency adjustments fail closed

**Capital Book** (`CapitalBookReport`)

Signed live capital book tying facility commitment and reserve book to one
subject-scoped source-of-funds view. Tracks committed, held, drawn, disbursed,
released, repaid, and impaired state over canonical evidence.

**Capital Execution** (`CapitalExecutionInstructionArtifact`,
`CapitalAllocationDecisionArtifact`)

Custody-neutral instructions for reserve locks, holds, releases, fund
transfers, and cancellations. Each instruction carries:

- Authority chain with named role-based approvals
- Bounded execution window
- Rail descriptor (manual, API, ACH, wire, ledger, sandbox, web3)
- Intended vs. reconciled state
- Evidence references

Allocation decisions produce typed outcomes (`Allocate`, `Queue`,
`ManualReview`, `Deny`) with instruction drafts.

**Bonded Execution Simulation** (`CreditBondedExecutionSimulationReport`)

Operator-simulatable sandbox for testing bonded execution decisions against
different control policies before runtime use.

**Role in the stack:** chio-credit is the central nervous system of the economic
layer. It transforms raw receipt data and underwriting decisions into credit
posture, manages collateral, and produces the evidence packages that insurance
and marketplace systems consume.

### 1.4 chio-market: Liability Insurance Marketplace

**Purpose:** A typed liability marketplace where insurance providers can be
registered, quote requests can be issued against signed risk packages, coverage
can be bound, and claims can be adjudicated.

**Key concepts:**

**Provider Types:** `AdmittedCarrier`, `SurplusLine`, `Captive`, `RiskPool`

**Coverage Classes:** Five typed classes of agent liability coverage:
`ToolExecution`, `DataBreach`, `FinancialLoss`, `ProfessionalLiability`,
`RegulatoryResponse`

**Evidence Requirements:** Providers can require specific evidence types before
quoting: `BehavioralFeed`, `UnderwritingDecision`,
`CreditProviderRiskPackage`, `RuntimeAttestationAppraisal`,
`CertificationArtifact`, `CreditBond`, `AuthorizationReviewPack`

**Jurisdiction-scoped policies:** Each provider defines per-jurisdiction
policies specifying supported coverage classes, currencies, evidence
requirements, maximum coverage amounts, and quote TTLs.

**The quote/bind workflow:**

1. `LiabilityQuoteRequestArtifact` -- operator submits a signed risk package
   (from chio-credit) to a provider with requested coverage amount and period
2. `LiabilityQuoteResponseArtifact` -- provider returns quoted terms
   (coverage, premium, deductible, expiry) or declines with reason
3. `LiabilityPricingAuthorityArtifact` -- delegated pricing authority linked
   to quote request, facility, underwriting decision, and capital book
4. `LiabilityPlacementArtifact` -- operator selects a quote for placement
5. `LiabilityBoundCoverageArtifact` -- coverage is bound with explicit terms

**The claims workflow:**

1. `LiabilityClaimPackageArtifact` -- claim filed with exposure, bond,
   loss-lifecycle, capital-execution, and receipt evidence
2. `LiabilityClaimResponseArtifact` -- provider response
3. `LiabilityClaimDisputeArtifact` -- dispute if response is contested
4. `LiabilityClaimAdjudicationArtifact` -- adjudication decision
5. `LiabilityClaimPayoutInstructionArtifact` -- payout instruction
6. `LiabilityClaimPayoutReceiptArtifact` -- payout receipt
7. `LiabilityClaimSettlementInstructionArtifact` -- settlement instruction
8. `LiabilityClaimSettlementReceiptArtifact` -- settlement receipt

**Auto-bind:** The crate supports delegated pricing authority with explicit
provider-or-regulated-role-bounded envelopes, enabling automatic binding within
policy-defined envelopes.

**Role in the stack:** chio-market is where risk meets capital. It consumes
signed risk packages from chio-credit and underwriting decisions from
chio-underwriting, then produces binding coverage contracts that allocate
liability to insurance providers.

### 1.5 chio-settle: On-Chain Settlement

**Purpose:** Turns approved capital instructions into real contract calls on
EVM and Solana, projects on-chain state back into the Chio receipt family.

**Key modules:**

- `evm` -- EVM contract integration: escrow dispatch, bond lock/release/impair/
  expiry, dual-sign release, Merkle release, ERC-20 approval, gas estimation,
  transaction submission and confirmation, on-chain state reading
- `solana` -- Solana-native settlement with Ed25519-first parity checks,
  commitment comparison, and binding verification
- `ccip` -- Chainlink CCIP cross-chain messaging for cross-chain settlement
- `payments` -- x402 payment requirements, Circle nanopayment evaluation,
  EIP-3009 `transferWithAuthorization`, ERC-4337 paymaster compatibility
- `automation` -- settlement and bond watchdog jobs for monitoring on-chain
  state
- `observe` -- finality inspection, escrow execution projection, bond
  lifecycle observation, and recovery action classification
- `ops` -- settlement lane classification, emergency controls (kill switch,
  circuit breaker), indexer cursors, and runtime status reporting
- `config` -- chain configuration, devnet deployment support, policy
  configuration, oracle authority

**Settlement flow:**

1. A `CapitalExecutionInstruction` with `rail.kind = Web3` is produced by
   chio-credit
2. chio-settle prepares the contract call (`prepare_web3_escrow_dispatch`,
   `prepare_bond_lock`, etc.)
3. Static validation ensures the call is well-formed before submission
4. The call is submitted and confirmed on-chain
5. Finality is inspected and the execution receipt is projected back into the
   Chio receipt family
6. Watchdog automation monitors for expiry, state changes, and recovery
   opportunities

**Cross-chain:** CCIP settlement messages carry capability commitment, receipt
reference, operator identity, and settlement amount. Delivery reconciliation
checks message status and produces typed reconciliation outcomes.

**Emergency controls:** The ops module provides settlement-level circuit
breakers with typed emergency modes, alert severity levels, recovery records,
and change tracking. The `ensure_settlement_operation_allowed` function
enforces controls before any settlement operation proceeds.

**Role in the stack:** chio-settle is the bridge between Chio's internal
accounting and external financial reality. It is the only crate that touches
real money on real chains.

### 1.6 chio-listing: Registry and Discovery

**Purpose:** Generic registry for tool servers, credential issuers, credential
verifiers, and liability providers. Provides namespace ownership, listing
lifecycle, trust activation, and federated discovery.

**Key types:**

- `GenericListingActorKind` -- `ToolServer`, `CredentialIssuer`,
  `CredentialVerifier`, `LiabilityProvider`
- `GenericListingArtifact` -- signed listing with namespace, subject, status,
  compatibility reference, and boundary constraints
- `GenericNamespaceArtifact` -- namespace ownership with signer key binding
- `GenericTrustActivationArtifact` -- explicit trust activation with admission
  class (`BondBacked`, etc.), eligibility constraints, and review context
- `GenericListingBoundary` -- listings are visibility-only by default; trust
  activation is always explicit and never automatic

**Freshness and replication:** Listings carry freshness state (`Fresh`,
`Stale`, `Divergent`) with age tracking and max-age enforcement. Publishers
have typed roles (`Origin`, `Mirror`, `Indexer`) for federated registry
replication.

**Role in the stack:** chio-listing is the discovery layer. Agents find tool
servers through listings. Insurance providers are registered as listings.
The trust activation mechanism ensures that visibility does not imply
admission -- every listing requires explicit activation before it can
participate in economic workflows.

### 1.7 chio-open-market: Decentralized Marketplace Economics

**Purpose:** Fee schedules, bond requirements, abuse detection, and penalty
enforcement for a decentralized tool marketplace.

**Key types:**

- `OpenMarketFeeScheduleArtifact` -- signed fee schedule defining publication
  fees, dispute fees, market participation fees, and bond requirements per
  namespace scope
- `OpenMarketBondRequirement` -- per-bond-class collateral requirements with
  configurable slashability
- `OpenMarketPenaltyArtifact` -- signed penalty for marketplace abuse
  (spam publication, fraudulent listing, replay publication, unverifiable
  behavior) with explicit bond hold/slash/reverse-slash actions
- `OpenMarketPenaltyEvaluation` -- penalty evaluation with finding codes for
  every validation failure (unverifiable listings, expired fee schedules,
  scope mismatches, bond requirement gaps, currency mismatches, amount
  overflows)

**The evaluation logic:** `evaluate_open_market_penalty` verifies:

1. All signed artifacts (listing, fee schedule, charter, governance case,
   activation, penalty) have valid signatures
2. Namespace consistency across all artifacts
3. Operator authority consistency
4. Fee schedule scope matching (operator IDs, actor kinds, admission classes)
5. Temporal validity (fee schedule, charter, case, penalty not expired)
6. Bond requirement matching for the penalty's bond class
7. Governance case kind validity (sanctions require enforced sanction cases;
   reverse-slash requires appeal cases)
8. Prior penalty validity for reverse-slash operations
9. Currency and amount coherence

**Governance integration:** The crate integrates with chio-governance for
charter-based authority scoping and case management. Sanctions and appeals
flow through the governance layer before economic penalties are enforced.

**Role in the stack:** chio-open-market is the top of the economic stack. It
defines the rules for a decentralized marketplace where tool providers list
capabilities, agents purchase access, and misbehavior is economically
penalized through bond slashing.

---

## 2. The Money Flow

Here is the complete lifecycle of money through the Chio economic layer, from
capability acquisition through settlement and dispute resolution.

### 2.1 Authorization Phase

```
Enterprise/Operator
    |
    |  issues CapabilityToken with:
    |    - ToolGrant.max_total_cost (spending cap)
    |    - ToolGrant.max_cost_per_invocation (per-call cap)
    |    - Constraint::RequireApprovalAbove (approval threshold)
    |    - Constraint::GovernedIntentRequired (intent binding)
    |
    v
Agent Identity (subject key)
    |
    |  may delegate with Attenuation::ReduceTotalCost
    |  (sub-budget carved from parent's remaining balance)
    |
    v
Sub-Agent / Task Agent
```

### 2.2 Invocation Phase

```
Agent presents CapabilityToken + request
    |
    v
Chio Kernel
    |-- 1. Validate capability (signature, time, revocation, scope)
    |-- 2. BudgetStore.try_charge_cost (provisional debit)
    |-- 3. Governed transaction validation (intent binding, approval token)
    |-- 4. PaymentAdapter.authorize (external rail pre-authorization)
    |-- 5. Guard pipeline evaluation
    |-- 6. Tool server invocation
    |-- 7. Cost verification (reported cost vs. per-invocation cap)
    |-- 8. Budget reconciliation (actual cost vs. provisional debit)
    |-- 9. PaymentAdapter.capture or .release
    |-- 10. Receipt signing with FinancialReceiptMetadata
    |
    v
Signed ChioReceipt
    |-- cost_charged, currency, budget_remaining
    |-- settlement_status (not_applicable / pending / settled / failed)
    |-- payment_reference
    |-- delegation_depth, root_budget_holder
    |-- governed_transaction context (if applicable)
```

### 2.3 Metering and Accumulation

```
Receipt Store
    |-- tenant index: tenant_id, cost_currency, cost_charged_be, seq
    |-- global index: cost_currency, cost_charged_be, seq
    |
    |-- chio-metering: CostQuery by session/agent/tool/time-range
    |-- chio-metering: BillingExport for downstream invoicing
    |-- chio-metering: BudgetEnforcer for policy-level enforcement
    |
    v
Exposure Ledger (chio-credit)
    |-- Per-currency position tracking
    |-- Settlement state breakdown (reserved/settled/pending/failed)
    |-- Loss tracking (provisional loss / recovered)
    |-- Premium exposure tracking
```

### 2.4 Credit Assessment

```
Exposure Ledger + Reputation Inspection
    |
    v
Credit Scorecard (chio-credit)
    |-- 5 bands: Prime -> Restricted
    |-- 4 dimensions: Reputation, Settlement, Loss, Exposure
    |-- Probation tracking
    |-- Anomaly detection
    |
    v
Credit Facility (chio-credit)
    |-- Grant / ManualReview / Deny disposition
    |-- Credit limit, utilization ceiling, reserve ratio, concentration cap
    |-- Runtime assurance and certification prerequisites
    |
    v
Credit Bond (chio-credit)
    |-- Lock / Hold / Release / Impair
    |-- Collateral and reserve requirements
    |-- Gates bounded autonomy tiers
```

### 2.5 Insurance Placement

```
Provider Risk Package (chio-credit)
    |-- Signed exposure + scorecard
    |-- Facility posture + latest facility snapshot
    |-- Runtime assurance + certification state
    |-- Recent loss history
    |
    v
Liability Quote Request (chio-market)
    |-- Provider policy reference
    |-- Requested coverage amount and period
    |-- Signed risk package attached
    |
    v
Liability Quote Response (chio-market)
    |-- Quoted: coverage, premium, deductible, expiry
    |-- or Declined: reason
    |
    v
Placement + Bound Coverage (chio-market)
    |-- Coverage terms finalized
    |-- Premium obligation created
```

### 2.6 Settlement

```
Capital Allocation Decision (chio-credit)
    |-- Allocate / Queue / ManualReview / Deny
    |-- Instruction drafts for execution
    |
    v
Capital Execution Instruction (chio-credit)
    |-- Authority chain (treasury + custodian approvals)
    |-- Execution window (not_before / not_after)
    |-- Rail (manual / API / ACH / wire / ledger / web3)
    |
    v
On-Chain Settlement (chio-settle) -- when rail.kind = Web3
    |-- EVM: escrow dispatch, bond lock/release
    |-- Solana: Ed25519-native settlement
    |-- CCIP: cross-chain messaging
    |-- x402: HTTP payment protocol
    |-- Circle: managed-custody nanopayments
    |
    v
Settlement Reconciliation
    |-- Finality inspection
    |-- Watchdog automation
    |-- Recovery action classification
    |-- Receipt-linked settlement proof
```

### 2.7 Claims and Disputes

```
Loss Event (chio-credit loss lifecycle)
    |-- Delinquency / Recovery / ReserveRelease / ReserveSlash / WriteOff
    |
    v
Claim Package (chio-market)
    |-- Bound coverage reference
    |-- Exposure, bond, loss-lifecycle, capital-execution evidence
    |
    v
Provider Response -> Dispute -> Adjudication
    |
    v
Payout Instruction -> Payout Receipt -> Settlement Instruction -> Settlement Receipt
```

---

## 3. Insurance and Underwriting

This section describes what is genuinely novel about Chio's approach. No
competing agent protocol has typed risk taxonomies, evidence-based underwriting,
or insurance marketplace primitives.

### 3.1 The Risk Assessment Pipeline

The underwriting pipeline is a three-stage evidence funnel:

**Stage 1: Evidence Collection** (`UnderwritingPolicyInput`)

The kernel exports a signed evidence package containing:

- Receipt evidence: allow/deny/cancel/incomplete counts, governed receipts,
  runtime assurance receipts, settlement state, metering state, shared evidence
- Reputation evidence: effective score, probation status, imported signals
- Certification evidence: tool server certification state and artifact
- Runtime assurance evidence: highest tier, latest verifier family, evidence
  digest

**Stage 2: Signal Derivation** (`UnderwritingSignal`)

The evidence is scanned for risk signals. Each signal has a typed risk class
and reason code. For example, a failed settlement receipt produces a
`FailedSettlementExposure` signal at `Critical` risk class. A weak runtime
assurance tier produces a `WeakRuntimeAssurance` signal at `Guarded` class.

**Stage 3: Decision Evaluation** (`UnderwritingDecisionReport`)

The pure `evaluate_underwriting_policy_input` function applies the policy
thresholds against the evidence and signals. The output is a deterministic
decision with:

- Outcome: `Approve` / `ReduceCeiling` / `StepUp` / `Deny`
- Risk class: `Baseline` / `Guarded` / `Elevated` / `Critical`
- Explicit findings with evidence references
- Budget recommendation: `Preserve` / `Reduce` / `Hold` / `Deny`
- Premium quote in basis points (100-600 bps, scaled by risk class)
- Suggested ceiling factor (for `ReduceCeiling` outcomes)

### 3.2 How Insurance Placement Works

Chio's insurance marketplace operates over signed evidence rather than
self-reported data.

**Provider admission:** Operators register liability providers via
`LiabilityProviderReport`, specifying provider type (admitted carrier, surplus
line, captive, risk pool), jurisdiction policies, coverage classes, supported
currencies, and evidence requirements. Provider records are signed, versioned,
and support lifecycle management (active, suspended, superseded, retired).

**Quote requests:** An operator produces a `CreditProviderRiskPackage` --
a signed bundle containing the exposure ledger, credit scorecard, facility
posture, runtime assurance state, certification state, and recent loss
history. This package is attached to a `LiabilityQuoteRequestArtifact` sent
to a resolved provider.

**Quote responses:** Providers respond with quoted terms (coverage amount,
premium, optional deductible, expiry) or decline with reason. Quotes are
time-bounded by the provider's `quote_ttl_seconds`. Coverage amounts must
match the provider's currency. Premiums must match the provider's currency.

**Bound coverage:** Accepted quotes progress to placement and then to bound
coverage. The coverage artifact preserves the full quote chain for audit.

**Claims:** Claims are filed against bound coverage with evidence from the
exposure ledger, bond state, loss lifecycle events, capital execution
instructions, and receipts. The claim workflow supports provider response,
dispute, adjudication, payout instruction, payout receipt, and settlement --
each as a separate signed artifact.

### 3.3 Why This Matters

Traditional insurance underwriting for software systems relies on
questionnaires and manual audits. Chio's approach is different:

1. **Evidence is cryptographically signed.** The risk package that the
   underwriter evaluates is the same receipt data that the kernel produced.
   It cannot be modified after the fact.

2. **Risk assessment is algorithmic and auditable.** The underwriting decision
   is a pure function of evidence plus policy. The same inputs always produce
   the same outputs. Every finding carries evidence references.

3. **Claims are evidence-linked.** A claim references the specific receipts,
   settlement records, and loss events that triggered it. Dispute resolution
   can verify every piece of evidence independently.

4. **The cycle is closed.** Underwriting decisions flow back into the
   kernel as budget recommendations. Approved agents get wider spending
   authority. Risky agents get tighter ceilings. Denied agents are blocked.

---

## 4. On-Chain Settlement

chio-settle bridges the gap between Chio's internal accounting and external
financial reality. It supports three settlement substrates:

### 4.1 EVM Settlement

The EVM module provides typed functions for:

- **Escrow dispatch:** `prepare_web3_escrow_dispatch` + `finalize_escrow_dispatch`
  for creating and finalizing escrow contracts linked to Chio capabilities and
  receipts
- **Bond management:** `prepare_bond_lock` / `prepare_bond_release` /
  `prepare_bond_impair` / `prepare_bond_expiry` for on-chain collateral
  management
- **Dual-sign release:** `prepare_dual_sign_release` for escrows requiring
  both operator and counterparty signatures
- **Merkle release:** `prepare_merkle_release` for batch settlement using
  Merkle proof verification
- **ERC-20 integration:** `prepare_erc20_approval` for token approvals,
  `scale_chio_amount_to_token_minor_units` for denomination conversion

Each function produces a `PreparedEvmCall` with gas estimation and static
validation before any on-chain submission occurs.

### 4.2 Solana Settlement

The Solana module provides Ed25519-first parity:

- `prepare_solana_settlement` -- prepares a settlement transaction using the
  Ed25519 program for signature verification
- `verify_solana_binding_and_receipt` -- verifies that a Solana settlement
  matches the Chio receipt
- `compare_commitments` -- produces a `CommitmentConsistencyReport` comparing
  Chio-side and Solana-side commitment state

### 4.3 Cross-Chain Settlement (CCIP)

For cross-chain scenarios, the CCIP module provides:

- `prepare_ccip_settlement_message` -- creates a cross-chain settlement
  message carrying capability commitment, receipt reference, operator identity,
  and settlement amount
- `reconcile_ccip_delivery` -- checks message delivery status and produces
  typed reconciliation outcomes

### 4.4 Payment Protocol Adapters

chio-settle also provides adapters for HTTP-native payment protocols:

- **x402:** `build_x402_payment_requirements` -- projects governed settlement
  into x402 HTTP payment requirements
- **EIP-3009:** `prepare_transfer_with_authorization` -- prepares ERC-20
  meta-transaction authorization digests
- **Circle nanopayments:** `evaluate_circle_nanopayment` -- evaluates
  Circle-managed-custody nanopayment policies
- **ERC-4337:** `prepare_paymaster_compatibility` -- assesses paymaster
  compatibility for account-abstracted settlement

### 4.5 When On-Chain Matters

Not every Chio settlement goes on-chain. On-chain settlement is appropriate
when:

1. **Cross-organizational trust is limited.** On-chain escrow removes the need
   for a trusted intermediary between agent operators.
2. **Collateral is at stake.** Bond lock/release/impair operations require
   verifiable state that both parties can audit.
3. **Settlement amounts justify gas costs.** The `SettlementAmountTier`
   configuration in chio-settle defines thresholds for when on-chain settlement
   is economically rational.
4. **Regulatory requirements demand verifiable settlement.** On-chain receipts
   provide tamper-evident proof of payment.

For small, high-frequency settlements between trusted parties, off-chain
settlement through the kernel's `PaymentAdapter` trait (x402, ACP-Commerce, or direct
API) is more appropriate.

---

## 5. The Marketplace Vision

The full economic stack composes into a decentralized marketplace for agent
capabilities:

### 5.1 Listing and Discovery

Tool servers register as listings in chio-listing namespaces. Each listing
carries:

- Namespace ownership (who controls the registry)
- Subject identity (the tool server)
- Compatibility reference (certification check)
- Boundary constraints (visibility-only; trust activation required)

Listings are replicated across registries with typed publisher roles
(origin, mirror, indexer) and freshness tracking.

### 5.2 Trust Activation

Visibility does not imply admission. Before a listing can participate in
economic workflows, it requires an explicit `GenericTrustActivation` with:

- Admission class (e.g., `BondBacked`)
- Eligibility constraints (actor kinds, publisher roles, listing statuses)
- Review context (publisher identity, freshness assessment)
- Disposition (approved/denied)

### 5.3 Fee Schedules and Bonds

Marketplace operators define `OpenMarketFeeScheduleArtifact` per namespace:

- Publication fee -- paid to list in the marketplace
- Dispute fee -- paid to initiate a dispute
- Market participation fee -- ongoing participation cost
- Bond requirements -- per-bond-class collateral with slashability

### 5.4 Abuse Detection and Penalties

When marketplace abuse is detected (spam, fraud, replay, unverifiable
behavior), the governance layer produces a sanction case. The open-market
evaluator then produces a `OpenMarketPenaltyEvaluation` that can:

- Hold the participant's bond (reversible)
- Slash the participant's bond (reduces collateral)
- Reverse a prior slash (on successful appeal)

Penalty evaluation verifies 9 distinct validation conditions before
enforcement, ensuring that penalties cannot be issued against mismatched
namespaces, expired fee schedules, unauthorized operators, or non-slashable
bonds.

### 5.5 The Complete Marketplace Loop

```
Tool Server publishes listing -> Trust activation -> Bond posted
    |
Agent discovers listing -> Purchases capability token with spending cap
    |
Agent invokes tool -> Metering records cost -> Receipt signed
    |
Receipts accumulate -> Exposure ledger -> Credit scorecard
    |
Scorecard feeds underwriting -> Risk assessment -> Premium quoted
    |
Risk package sent to insurer -> Quote -> Bind coverage
    |
If loss occurs:
    Loss lifecycle event -> Claim against coverage -> Adjudication
    |
    If penalty warranted:
        Governance case -> Bond hold/slash -> Appeal if contested
```

---

## 6. Relationship to the Security Layer

The economic layer does not replace the security layer. It extends it. The
relationship is bidirectional:

### 6.1 Security Primitives the Economic Layer Depends On

| Security Primitive | Economic Use |
|-------------------|--------------|
| `CapabilityToken` signatures | Spending authorizations are unforgeable |
| `ChioReceipt` signatures | Billing records are tamper-evident |
| `SignedExportEnvelope` | All economic artifacts (exposure, scorecard, facility, bond, underwriting decision, risk package) are signed |
| `DelegationLink` chains | Cost-responsibility attribution follows cryptographic delegation |
| `GovernedTransactionIntent` + `GovernedApprovalToken` | Purchase orders and approvals are cryptographically bound |
| Guard pipeline | Guards can evaluate economic conditions (budget remaining, settlement status) before allowing execution |
| `BudgetStore` atomic transactions | Concurrent budget access is serialized |
| Receipt store indexing | Economic queries run against indexed, persisted state |

### 6.2 Economic Signals the Security Layer Consumes

| Economic Signal | Security Effect |
|----------------|-----------------|
| `BudgetViolation` | Kernel denies execution |
| Underwriting `Deny` outcome | Budget recommendation blocks the agent |
| Underwriting `ReduceCeiling` | Spending authority narrowed |
| Bond `Impair` disposition | Autonomy tier revoked |
| Outstanding delinquency | Bonded execution denied |
| Failed settlement backlog | Underwriting elevates risk class |
| Credit scorecard `Restricted` band | Credit facility denied |

### 6.3 The Trust Boundary

The kernel remains the trust boundary. Economic crates produce artifacts
(reports, decisions, instructions) but do not directly enforce policy. The
kernel reads those artifacts -- budget recommendations, bond dispositions,
autonomy tier requirements -- and makes the enforcement decision.

This separation matters: the kernel is small and auditable. The economic
layer is large and complex. If the economic layer has a bug, the kernel's
fail-closed defaults still protect the system.

---

## 7. Known Gaps

The review process identified five economic gaps. They are listed here for
completeness; none is currently being worked.

### 7.1 Hierarchical Budget Governance

The current budget model is per-capability-grant. Enterprises need per-team,
per-project, and per-department budget trees that aggregate across multiple
capability tokens. This requires a budget hierarchy data model above the
grant level.

### 7.2 Agent-to-Agent Payment Routing

chio-metering and the kernel's `PaymentAdapter` cover agent-to-tool-server
payments. Peer-to-peer agent payments (agent A pays agent B for a delegated
sub-task result) have no routing protocol. This matters for multi-agent swarm
economics.

### 7.3 Dynamic Pricing and Discovery

There is no price comparison, auction, or negotiation protocol for tool
access. An agent cannot discover that the same tool capability is available
from multiple providers at different prices and select the cheapest. This
limits marketplace efficiency.

### 7.4 Economic Threat Model

There is no formal analysis of:

- Budget exhaustion attacks (malicious tool server reporting inflated costs)
- Price manipulation (tool server cartel behavior)
- Sybil attacks against the credit scoring system
- Flash-settlement attacks (rapidly cycling bonds to game the loss lifecycle)
- Cross-currency arbitrage in mixed-currency books

### 7.5 Federated Fiscal Composition

The primitives exist for namespace-scoped fee schedules, trust activation,
bond requirements, governance charters, penalty enforcement, and federated
reputation sharing. But the composition guide describing how an operator would
assemble these primitives into a self-governing economic zone is missing. This
is the bridge between Chio's technical capabilities and autonomous agent
collectives operating as fiscal entities.

---

## 8. Crate Reference

Quick reference for navigating the codebase:

| Crate | Entry Point | Key Exports |
|-------|------------|-------------|
| `chio-metering` | `crates/economy/chio-metering/src/lib.rs` | `CostMetadata`, `BudgetEnforcer`, `CostQuery`, `BillingExport` |
| `chio-underwriting` | `crates/economy/chio-underwriting/src/lib.rs` | `evaluate_underwriting_policy_input`, `UnderwritingDecisionArtifact`, `UnderwritingRiskClass`, `UnderwritingPremiumQuote` |
| `chio-credit` | `crates/economy/chio-credit/src/lib.rs` | `ExposureLedgerReport`, `CreditScorecardReport`, `CreditFacilityArtifact`, `CreditBondArtifact`, `CreditLossLifecycleArtifact`, `CapitalBookReport`, `CapitalExecutionInstructionArtifact` |
| `chio-market` | `crates/economy/chio-market/src/lib.rs` | `LiabilityProviderReport`, `LiabilityQuoteRequestArtifact`, `LiabilityQuoteResponseArtifact`, `LiabilityBoundCoverageArtifact`, `LiabilityClaimPackageArtifact` |
| `chio-settle` | `crates/economy/chio-settle/src/lib.rs` | `prepare_web3_escrow_dispatch`, `prepare_bond_lock`, `prepare_solana_settlement`, `prepare_ccip_settlement_message`, `build_x402_payment_requirements` |
| `chio-listing` | `crates/economy/chio-listing/src/lib.rs` | `GenericListingArtifact`, `GenericNamespaceArtifact`, `GenericTrustActivationArtifact` |
| `chio-open-market` | `crates/economy/chio-open-market/src/fee_schedule.rs`, `crates/economy/chio-open-market/src/penalty.rs`, `crates/economy/chio-open-market/src/evaluation.rs` | `OpenMarketFeeScheduleArtifact`, `OpenMarketPenaltyArtifact`, `evaluate_open_market_penalty` |

See also: `docs/AGENT_ECONOMY.md` for the foundational design document
covering the kernel-level economic extensions (capability token spending
authorizations, budget store, payment adapter trait, governed transactions).
