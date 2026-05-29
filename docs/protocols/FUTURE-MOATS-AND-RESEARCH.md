# Future Moats and Research Agenda

> **Status**: Strategic research -- April 2026
> **Source**: Brainstorming review identified 12 future-looking ideas for Chio.
> Near-term items leverage existing primitives. Medium-term items (agent
> insurance, cross-kernel federation) represent the strongest competitive moats.
> Long-term items require cryptographic or hardware research.
>
> **Dependency map**: Near-term builds on shipped crates. Medium-term depends
> on `chio-kernel-core` (WASM kernel) and the economic layer (`chio-underwriting`,
> `chio-market`, `chio-settle`, `chio-credit`). Long-term depends on external
> research (ZK circuits, TEE vendor SDKs).

---

## 0. Summary Matrix

| # | Idea | Horizon | Effort | Defensibility | Key Dependency |
|---|------|---------|--------|---------------|----------------|
| 1 | Receipt as proof-of-safe-behavior | Near-term | Small | Strong | `chio-core-types` receipts, Merkle chain |
| 2 | Agent behavioral profiling | Near-term | Medium | Strong | Receipt store, velocity guards |
| 3 | Regulatory API | Near-term | Small | Medium | `SignedExportEnvelope`, receipt store |
| 4 | Agent passport | Medium-term | Large | Strong | `chio-kernel-core` WASM, `WorkloadIdentity` |
| 5 | Agent insurance protocol | Medium-term | Large | Very strong | `chio-underwriting`, `chio-market`, `chio-settle` |
| 6 | Cross-kernel federation | Medium-term | Large | Strong | Choreography receipts, DPoP, mTLS |
| 7 | Capability marketplace | Medium-term | Medium | Medium | `chio-market`, `chio-listing`, `chio-metering` |
| 8 | Natural language policies | Medium-term | Medium | Medium | HushSpec YAML, guard pipeline |
| 9 | Federated receipt verification (ZK) | Long-term | Very large | Very strong | Merkle receipts, ZK circuit design |
| 10 | Compute attestation (TEE) | Long-term | Large | Strong | Receipt signing, hardware vendor SDKs |

---

## 1. Receipt as Proof-of-Safe-Behavior

### Problem

Regulators, counterparties, and insurers need to answer: "Has this agent
behaved safely?" Today, the answer requires reading raw receipt logs. There
is no aggregate metric.

### Architecture

A `compliance_score()` function computes a numeric safety score from a
receipt chain. The score is consumed by underwriters (premium pricing),
regulators (continuous compliance), and counterparties (trust decisions).

```
Receipt chain (Merkle-committed, Ed25519-signed)
         |
         v
+---------------------+
| compliance_score()  |
|                     |
| Inputs:             |
|   receipts: &[ChioReceipt]
|   window: Duration  |
|   policy_hash: &str |
|                     |
| Scoring model:      |
|   base_score = 1000 |
|   - denial_penalty  |
|   - revocation_hit  |
|   - guard_failure   |
|   + clean_streak    |
|   + scope_discipline|
|   + budget_adherence|
|                     |
| Output:             |
|   ComplianceScore { |
|     score: u32,     |  // 0-1000
|     tier: Tier,     |  // Exemplary/Good/Marginal/Poor
|     window: (u64,u64),
|     receipt_count,  |
|     denial_rate,    |
|     evidence: Vec<ScoringEvidence>,
|     merkle_root,    |
|   }                 |
+---------------------+
         |
         v
  SignedExportEnvelope<ComplianceScore>
```

### Scoring Model

```rust
/// Compliance score over a receipt window. Range: 0-1000.
pub struct ComplianceScore {
    /// Numeric score. 1000 = perfect. 0 = catastrophic.
    pub score: u32,
    /// Qualitative tier derived from score.
    pub tier: ComplianceTier,
    /// Window start (unix seconds).
    pub window_start: u64,
    /// Window end (unix seconds).
    pub window_end: u64,
    /// Total receipts evaluated.
    pub receipt_count: u64,
    /// Denial rate in the window (0.0 - 1.0).
    pub denial_rate: f64,
    /// Per-factor evidence supporting the score.
    pub evidence: Vec<ScoringEvidence>,
    /// Merkle root of the receipt chain at window_end.
    pub merkle_root: String,
}

pub enum ComplianceTier {
    Exemplary,  // 900-1000
    Good,       // 700-899
    Marginal,   // 400-699
    Poor,       // 0-399
}

pub struct ScoringEvidence {
    pub factor: ScoringFactor,
    pub contribution: i32,  // positive = bonus, negative = penalty
    pub detail: String,
}

pub enum ScoringFactor {
    DenialRate,         // -100 per 1% denial rate above 2%
    RevocationEvents,   // -200 per revocation in window
    GuardFailures,      // -50 per guard pipeline error
    CleanStreak,        // +50 per 100 consecutive allows
    ScopeDiscipline,    // +100 if agent never exceeded granted scope
    BudgetAdherence,    // +100 if agent stayed within 80% of budget
    ReceiptContinuity,  // -300 if Merkle chain has gaps
    PolicyStability,    // +50 if policy_hash unchanged in window
}
```

**Penalty/bonus calibration.** The weights above are initial values. They
should be tunable per deployment via policy configuration. The key
invariant: a single revocation event drops the score below `Good`, and
a broken Merkle chain drops it below `Marginal`.

### Crate Location

> **Updated**: The raw reporting infrastructure already exists. 
> `ComplianceReport` lives in `chio-kernel/src/operator_report.rs`,
> backed by SQLite report queries in
> `chio-store-sqlite/src/receipt_store/reports.rs`. This work is
> productization (scoring model + API surface) on top of existing
> primitives, NOT a new crate. Add scoring logic to `chio-kernel` and
> expose via HTTP endpoint.

### Existing Primitive Dependencies

- `ComplianceReport` in `chio-kernel/src/operator_report.rs` -- shipped
- `ChioReceipt` with `Decision::Allow` / `Decision::Deny` -- shipped
- `MerkleTree` / `MerkleProof` in `chio-core-types::merkle` -- shipped
- `SignedExportEnvelope<T>` for signed score export -- shipped
- Receipt store report queries (SQLite) -- shipped

### Effort

Small. Pure computation over existing data structures. No new I/O, no new
storage. The scoring function is a fold over receipts.

### Competitive Defensibility

**Strong.** No competitor has per-invocation signed receipts, let alone
Merkle-committed receipt chains. The compliance score is only as credible
as the receipt data, and Chio is the only protocol producing it.

---

## 2. Agent Behavioral Profiling

### Problem

A compromised or misbehaving agent may stay within its granted scope but
exhibit anomalous patterns: sudden spike in call frequency, diversification
into rarely-used tools, cost acceleration. Current velocity guards are
static thresholds. They do not learn from the agent's own baseline.

### Architecture

A rolling statistical model over receipt streams, producing a behavioral
profile that feeds into the velocity guard as dynamic anomaly detection.

```
Receipt stream (real-time)
         |
         v
+---------------------------+
| BehavioralProfiler        |
|                           |
| Rolling windows:          |
|   1min, 5min, 1hr, 24hr  |
|                           |
| Tracked metrics:          |
|   calls_per_minute        |
|   scope_diversity_index   |  // Shannon entropy over scopes
|   denial_rate             |
|   cost_velocity_usd_min   |
|   tool_concentration      |  // Gini coefficient over tools
|   session_duration        |
|   delegation_depth        |
|   new_tool_rate           |  // tools never called before
|                           |
| Output:                   |
|   BehavioralProfile {     |
|     baseline: Metrics,    |  // EMA over 24h
|     current: Metrics,     |  // last 5min
|     anomaly_score: f64,   |  // 0.0 = normal, 1.0 = extreme
|     anomaly_factors: Vec, |
|   }                       |
+---------------------------+
         |
         v
  VelocityGuard (existing)
    if anomaly_score > threshold -> Deny
```

### Behavioral Model

```rust
/// Per-agent rolling behavioral profile.
pub struct BehavioralProfile {
    /// Agent identity (WorkloadIdentity URI).
    pub agent_uri: String,
    /// Baseline metrics (exponential moving average, 24h half-life).
    pub baseline: BehavioralMetrics,
    /// Current window metrics (last 5 minutes).
    pub current: BehavioralMetrics,
    /// Composite anomaly score (0.0 normal, 1.0 extreme anomaly).
    pub anomaly_score: f64,
    /// Which factors drove the anomaly score.
    pub anomaly_factors: Vec<AnomalyFactor>,
    /// Profile last updated (unix seconds).
    pub updated_at: u64,
}

pub struct BehavioralMetrics {
    pub calls_per_minute: f64,
    /// Shannon entropy over scope strings. High = diverse. Low = repetitive.
    pub scope_diversity: f64,
    /// Fraction of evaluations that resulted in denial.
    pub denial_rate: f64,
    /// USD cost per minute (from chio-metering).
    pub cost_velocity: f64,
    /// Gini coefficient over tool usage. 1.0 = all calls to one tool.
    pub tool_concentration: f64,
    /// Rate of calls to tools the agent has never called before.
    pub new_tool_rate: f64,
    /// Average delegation chain depth.
    pub avg_delegation_depth: f64,
}

pub struct AnomalyFactor {
    pub metric: String,        // e.g. "calls_per_minute"
    pub baseline_value: f64,
    pub current_value: f64,
    pub z_score: f64,          // standard deviations from baseline
    pub contribution: f64,     // fraction of total anomaly score
}
```

**Anomaly score computation.** For each metric, compute the z-score relative
to the baseline EMA. The composite anomaly score is the L2 norm of the
z-score vector, normalized to [0, 1] via a sigmoid. This avoids hard
thresholds for individual metrics while still producing a single
actionable signal.

**Guard integration.** The velocity guard already evaluates per-request.
Add an optional `anomaly_threshold` field to velocity guard configuration.
When present, the guard queries the profiler and denies if
`anomaly_score > threshold`. The denial receipt records the anomaly factors
as `GuardEvidence`.

### Crate Location

> **Updated**: The raw behavioral reporting already exists.
> `BehavioralFeedReport` and `SignedBehavioralFeed` live in
> `chio-kernel/src/operator_report.rs`, backed by SQLite report queries
> in `chio-store-sqlite/src/receipt_store/reports.rs`. This work adds
> EMA baselines, z-score anomaly detection, and guard integration on
> top of existing primitives. Add to `chio-guards`, NOT a new crate.

### Existing Primitive Dependencies

- `BehavioralFeedReport` in `chio-kernel/src/operator_report.rs` -- shipped
- Receipt store with reporting queries -- shipped
- `chio-metering` per-receipt cost attribution -- shipped
- Velocity guard pipeline -- shipped
- `GuardEvidence` in receipt for recording anomaly factors -- shipped

### Effort

Medium. The statistical model (EMA, z-score, entropy, Gini) is
straightforward. The integration point -- guard querying a profiler service
-- requires a new guard type or extension to the velocity guard. Rolling
window storage needs either in-memory ring buffers (ephemeral) or a time-
series table in the receipt SQLite database (persistent).

### Competitive Defensibility

**Strong.** The behavioral data is derived from Chio receipts, which no
competitor produces. Any behavioral profiling built on top of Chio inherits
the receipt chain's cryptographic integrity -- the profiler cannot be fed
fabricated data. Competitors building behavioral profiling over unattested
logs have a weaker foundation.

---

## 3. Regulatory API

### Problem

Compliance today means periodic audits: collect evidence, package reports,
submit to regulator, wait. Chio receipts enable continuous compliance --
regulators could query the receipt store in real time. But there is no
defined API surface for this.

### Architecture

A read-only HTTP API over the receipt store, exporting signed evidence
envelopes. The API is designed for regulator consumption, not agent
operation -- separate authentication, separate rate limits, separate
deployment (can be a read replica).

```
+------------------+        +------------------+
| Receipt Store    | -----> | Regulatory API   |
| (primary, r/w)   |  sync  | (read replica)   |
+------------------+        +------------------+
                                    |
                            +-------+-------+
                            |               |
                    GET /receipts    GET /compliance
                    GET /chains     GET /policies
                    GET /evidence   GET /export
                            |
                            v
                    Regulator / Auditor
```

### API Surface

```
Base path: /api/v1/regulatory

Authentication: mTLS with regulator certificate OR
                OAuth 2.0 with regulatory_read scope

Rate limit: 100 req/s (configurable per regulator)

Endpoints:

GET /receipts
  Query: agent_id, tool_name, decision, from_ts, to_ts, limit, cursor
  Response: SignedExportEnvelope<Vec<ChioReceipt>>

GET /receipts/{receipt_id}
  Response: SignedExportEnvelope<ChioReceipt>

GET /receipts/{receipt_id}/merkle-proof
  Response: SignedExportEnvelope<MerkleProof>

GET /chains/{chain_head_id}
  Query: direction (forward|backward), limit
  Response: SignedExportEnvelope<Vec<ChioReceipt>>
  Note: follows choreography receipt chains (section 9 of
        EVENT-STREAMING-INTEGRATION.md)

GET /compliance/score
  Query: agent_id, window_hours (default 24)
  Response: SignedExportEnvelope<ComplianceScore>
  Note: depends on compliance_score() from idea #1

GET /compliance/profile
  Query: agent_id
  Response: SignedExportEnvelope<BehavioralProfile>
  Note: depends on behavioral profiler from idea #2

GET /policies/active
  Query: agent_id (optional)
  Response: SignedExportEnvelope<Vec<PolicySummary>>

GET /policies/{policy_hash}
  Response: SignedExportEnvelope<PolicyDocument>

GET /evidence/guards
  Query: agent_id, guard_name, from_ts, to_ts
  Response: SignedExportEnvelope<Vec<GuardEvidence>>

GET /export/envelope
  Query: agent_id, from_ts, to_ts, format (json|cbor)
  Response: SignedExportEnvelope<ComplianceExport>
  Note: complete evidence package for a regulatory window

POST /export/schedule
  Body: { agent_ids, schedule_cron, destination_url, format }
  Response: { schedule_id }
  Note: push-based export for continuous compliance feeds
```

**Every response is a `SignedExportEnvelope<T>`.** The regulator can verify
the envelope signature against the kernel's published public key without
trusting the transport layer. This is the key property -- the API could be
served by a compromised intermediary and the regulator would still detect
tampering.

### Framework Alignment

- **EU AI Act** (Art. 12): requires logging. This API makes logs queryable.
- **Colorado SB 24-205**: requires impact assessments. Compliance scores
  and behavioral profiles serve as continuous impact evidence.
- **SOC 2 Type II**: requires continuous control monitoring. Push-based
  export schedule satisfies this.
- **NIST AI RMF**: MAP/MEASURE/MANAGE functions map to receipts/scores/
  profiles respectively.

### Crate Location

> **Updated**: Not a new crate. Add endpoints to `chio-http-core/src/routes.rs`
> using existing `SignedExportEnvelope` and receipt store queries.

Previously proposed as `chio-regulatory-api`. Depends on `chio-core-types` (receipts,
export envelopes), `chio-store-sqlite` (receipt queries), `chio-compliance`
(scoring), optionally `chio-behavioral` (profiling).

### Existing Primitive Dependencies

- `SignedExportEnvelope<T>` -- shipped
- Receipt store with query capabilities -- shipped
- MerkleProof generation -- shipped
- Choreography receipt chains (parent_receipt linkage) -- shipped in design

### Effort

Small. The API is a thin read-only HTTP layer over existing data. The
hardest part is the push-based export scheduler, which is optional for v1.

### Competitive Defensibility

**Medium.** The API surface itself is a packaging exercise. But the
underlying data -- signed, Merkle-committed, per-invocation receipts -- is
unique to Chio. A competitor could build the same API shape but would lack
the cryptographic integrity guarantees that make it credible to regulators.

---

## 4. Agent Passport

### Problem

An agent operating across platforms (cloud, edge, mobile, browser) needs a
portable identity. Today, `WorkloadIdentity` captures who the agent is, but
there is no portable bundle that carries the agent's history, trust tier,
and capability profile across kernel boundaries.

### Architecture

An Agent Passport is a signed, versioned bundle that an agent carries. It
is issued by the agent's home kernel and verified by any remote kernel.
The passport does not grant capabilities -- it provides evidence for
capability decisions.

```
+-------------------+
| Agent Passport    |
| (signed bundle)   |
|                   |
| identity:         |  WorkloadIdentity (SPIFFE URI, credential kind)
| trust_tier:       |  RuntimeAssuranceTier (from chio-core-types)
| capability_summary:|  aggregate of granted scopes (not individual tokens)
| receipt_summary:  |  ComplianceScore (from idea #1)
| behavioral_summary:| BehavioralProfile snapshot (from idea #2)
| certifications:   |  third-party attestations
| issued_at:        |  unix timestamp
| expires_at:       |  unix timestamp (short-lived, 1-24h)
| issuer_kernel:    |  PublicKey of issuing kernel
| signature:        |  Ed25519 over canonical JSON of above
+-------------------+
```

### Passport Format

```rust
/// Portable agent identity bundle. Signed by the issuing kernel.
pub struct AgentPassport {
    /// Version of the passport format.
    pub version: String,  // "chio.passport.v1"

    /// Core identity.
    pub identity: WorkloadIdentity,

    /// Runtime assurance tier at time of issuance.
    pub trust_tier: RuntimeAssuranceTier,

    /// Aggregate capability profile (not individual tokens).
    pub capability_summary: CapabilitySummary,

    /// Compliance score at time of issuance.
    pub compliance: ComplianceScore,

    /// Behavioral profile snapshot.
    pub behavioral: BehavioralSummary,

    /// Third-party certifications the agent holds.
    pub certifications: Vec<Certification>,

    /// Issuance metadata.
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer_kernel: PublicKey,

    /// Signature over canonical JSON of all fields above.
    pub signature: Signature,
}

/// Aggregate capability profile. Does not reveal individual tokens.
pub struct CapabilitySummary {
    /// Scope categories the agent has been granted (e.g., "tools:read",
    /// "events:consume"). Not individual tool names.
    pub scope_categories: Vec<String>,
    /// Total active grants at issuance time.
    pub active_grant_count: u32,
    /// Maximum delegation depth the agent has used.
    pub max_delegation_depth: u32,
    /// Whether the agent holds any standing (non-ephemeral) grants.
    pub has_standing_grants: bool,
}

/// Snapshot of behavioral profile for portability.
pub struct BehavioralSummary {
    /// Compliance tier at issuance.
    pub compliance_tier: ComplianceTier,
    /// Average calls per minute (24h baseline).
    pub avg_calls_per_minute: f64,
    /// Historical denial rate.
    pub historical_denial_rate: f64,
    /// Number of receipts in the backing chain.
    pub receipt_count: u64,
    /// Merkle root of the receipt chain at issuance.
    pub receipt_merkle_root: String,
}

/// Third-party certification (e.g., SOC 2, ISO 42001 audit).
pub struct Certification {
    pub standard: String,       // "soc2-type2", "iso-42001"
    pub issuer: String,         // certifying body
    pub issued_at: u64,
    pub expires_at: u64,
    pub evidence_hash: String,  // SHA-256 of the certification artifact
}
```

### Passport Lifecycle

```
1. Agent requests passport from home kernel
   POST /passport/issue
   Body: { agent_id, requested_ttl }

2. Home kernel collects:
   - WorkloadIdentity (from runtime attestation)
   - RuntimeAssuranceTier (from chio-appraisal)
   - ComplianceScore (from chio-compliance)
   - BehavioralProfile (from chio-behavioral)
   - Active grants (from capability authority)

3. Home kernel signs passport, returns to agent

4. Agent presents passport to remote kernel
   Header: X-Chio-Passport: <base64url(canonical_json(passport))>

5. Remote kernel verifies:
   a. Signature valid against issuer_kernel public key
   b. Not expired (expires_at > now)
   c. Issuer kernel is in the remote kernel's trust store
   d. Passport fields satisfy local policy (e.g., compliance_tier >= Good)

6. Remote kernel uses passport as input to capability decisions
   (passport is evidence, not authorization)
```

### Cross-Platform Portability

The passport format is JSON (canonical) and small (typically < 2KB). It
works across all deployment surfaces enabled by `chio-kernel-core`:

- **Cloud-to-cloud**: agent migrates between Kubernetes clusters
- **Cloud-to-edge**: agent runs on Cloudflare Worker, presents passport
  to cloud kernel for elevated operations
- **Browser-to-cloud**: agent in browser extension presents passport
  to backend API
- **Mobile-to-cloud**: agent on iOS/Android presents passport

**Critical dependency**: remote kernels must be able to verify passports.
This requires `chio-kernel-core` (WASM build) for non-server environments,
plus a shared trust store for kernel public keys.

### Crate Location

> **Updated**: Passport support already ships. `AgentPassport` is in
> `chio-credentials/src/passport.rs`. Challenge flows, OID4VCI/VP, and
> cross-issuer portfolio evaluation are in `chio-credentials/src/cross_issuer.rs`.
> CLI passport flows exist in `chio-cli/src/passport.rs`. This work adds
> trust-tier synthesis (from compliance scoring + behavioral profiling)
> and WASM-portable verification to the existing passport system.
> NOT a new crate.

Previously proposed as `chio-passport`. Depends on `chio-core-types` (identity,
crypto), compliance scoring (see section 1), behavioral profiling (see section 2),
`chio-appraisal` (trust tiers).

### Effort

Large. The passport format itself is straightforward. The hard parts are:
(a) trust store for cross-kernel key verification, (b) `chio-kernel-core`
must be functional for cross-platform verification, (c) policy integration
so remote kernels use passports as evidence.

### Competitive Defensibility

**Strong if Chio becomes a multi-organization standard.** The passport's
value scales with the number of kernels that accept it. If Chio achieves
cross-organization deployment, the passport becomes a network-effect moat.
A competitor would need to replicate the entire receipt infrastructure to
produce credible passports.

---

## 5. Agent Insurance Protocol

### Problem

Agent failures cause real financial damage: data breaches, incorrect
trades, regulatory fines. Organizations deploying agents need financial
protection. Today, there is no structured way to underwrite agent risk,
price coverage, or settle claims -- because there is no standard way to
measure agent behavior.

Chio changes this. The receipt chain provides the actuarial data that
insurance requires.

### Architecture

The full insurance protocol connects three existing crates into a
lifecycle:

```
chio-underwriting          chio-market               chio-settle
(risk assessment)  --->   (liability placement) -> (claims payout)
                    |
                    |     Pricing based on:
                    |       - UnderwritingRiskClass (4 tiers)
                    |       - ComplianceScore (from idea #1)
                    |       - BehavioralProfile (from idea #2)
                    |       - Receipt history depth
                    |
                    v
            Premium calculation
```

### Protocol Flow

```
Phase 1: ASSESSMENT (chio-underwriting)
  Input:
    - Agent WorkloadIdentity
    - Receipt chain (last N receipts, max 200 per MAX_UNDERWRITING_RECEIPT_LIMIT)
    - ComplianceScore
    - BehavioralProfile
    - RuntimeAssuranceTier
    - Certification artifacts

  Process:
    1. Classify agent: UnderwritingRiskClass (Baseline/Guarded/Elevated/Critical)
    2. Enumerate risk signals: Vec<UnderwritingSignal>
       Each signal has:
         - class: UnderwritingRiskClass
         - reason: UnderwritingReasonCode (13 codes: ProbationaryHistory,
           LowReputation, ImportedTrustDependency, MissingCertification, etc.)
         - evidence_refs: Vec<UnderwritingEvidenceReference>
    3. Produce: SignedUnderwritingDecision

  Output: SignedUnderwritingDecision
    - risk_class: UnderwritingRiskClass
    - signals: Vec<UnderwritingSignal>
    - recommended_coverage_classes: Vec<LiabilityCoverageClass>
    - premium_factor: f64 (multiplier based on risk)

Phase 2: PLACEMENT (chio-market)
  Input: SignedUnderwritingDecision

  Process:
    1. Query liability providers (LiabilityProviderType:
       AdmittedCarrier/SurplusLine/Captive/RiskPool)
    2. Match coverage classes (5 classes: ToolExecution, DataBreach,
       FinancialLoss, ProfessionalLiability, RegulatoryResponse)
    3. Collect required evidence per provider's LiabilityJurisdictionPolicy:
       - BehavioralFeed
       - UnderwritingDecision
       - CreditProviderRiskPackage
       - RuntimeAttestationAppraisal
       - CertificationArtifact
       - CreditBond
       - AuthorizationReviewPack
    4. Request quotes (LiabilityQuoteRequest -> LiabilityQuoteResponse)
    5. Select and bind coverage (LiabilityBoundCoverage)

  Output: Signed bound coverage with premium schedule

Phase 3: MONITORING (continuous)
  Input: Ongoing receipt stream

  Process:
    1. Continuous compliance scoring (idea #1)
    2. Behavioral profiling (idea #2)
    3. Premium adjustment triggers:
       - ComplianceTier drops below Good -> premium increase notification
       - UnderwritingRiskClass escalates -> coverage review
       - Anomaly score exceeds threshold -> claims monitoring alert
    4. Receipt-backed evidence for claims

Phase 4: CLAIMS (chio-market + chio-settle)
  Input: Incident report + receipt chain as evidence

  Process:
    1. Package claim (LiabilityClaimPackage):
       - Incident description
       - Causal receipt chain (which receipts led to the incident)
       - Financial impact assessment
       - Affected parties
    2. Provider adjudicates (LiabilityClaimAdjudication):
       - Verify receipt chain integrity (Merkle proofs)
       - Confirm agent was operating within coverage scope
       - Assess whether guards were properly configured
       - Determine payout
    3. Settlement (chio-settle):
       - EVM or Solana on-chain settlement
       - Escrow release via PreparedMerkleRelease
       - Receipt-backed proof of payout
    4. Dispute resolution (LiabilityClaimDispute):
       - Counter-evidence submission
       - Arbitration protocol

  Output:
    - LiabilityClaimPayoutInstruction (settlement instruction)
    - LiabilityClaimPayoutReceipt (proof of payout)
    - LiabilityClaimSettlementReceipt (on-chain confirmation)
```

### Premium Pricing Model

```
base_premium = coverage_amount * base_rate[coverage_class]

risk_multiplier = match risk_class {
    Baseline  -> 1.0,
    Guarded   -> 1.5,
    Elevated  -> 3.0,
    Critical  -> 8.0 (or decline),
}

compliance_discount = match compliance_tier {
    Exemplary -> 0.7,   // 30% discount
    Good      -> 0.9,   // 10% discount
    Marginal  -> 1.0,   // no discount
    Poor      -> 1.5,   // 50% surcharge
}

history_factor = match receipt_count {
    0..100    -> 1.3,   // insufficient data, surcharge
    100..1000 -> 1.0,   // baseline
    1000..    -> 0.85,  // deep history, discount
}

behavioral_factor = if anomaly_score > 0.5 { 1.4 } else { 1.0 }

final_premium = base_premium
    * risk_multiplier
    * compliance_discount
    * history_factor
    * behavioral_factor
```

**Base rates by coverage class:**

| Coverage Class | Base Rate (per $1M coverage) |
|----------------|----------------------------|
| ToolExecution | $2,000/year |
| DataBreach | $8,000/year |
| FinancialLoss | $12,000/year |
| ProfessionalLiability | $6,000/year |
| RegulatoryResponse | $4,000/year |

These are initial calibration points. Real actuarial data from receipt
chains will refine them over time. The receipt chain IS the actuarial data
source -- this is why agent insurance only becomes viable with Chio.

### Crate Dependencies

All three crates exist with typed schemas:
- `chio-underwriting`: 4-tier risk classification, 13 reason codes,
  evidence-based decisions -- shipped
- `chio-market`: 5 coverage classes, 4 provider types, quote/bind/claims
  workflow with full artifact schemas -- shipped
- `chio-settle`: EVM + Solana on-chain settlement, escrow,
  `PreparedMerkleRelease` -- shipped
- `chio-credit`: credit facilities, bonds, exposure ledger -- shipped

### What Needs Building

1. **Premium pricing engine** connecting underwriting decisions to market
   quotes (the pricing model above)
2. **Continuous monitoring bridge** from receipt stream to underwriting
   re-evaluation triggers
3. **Claims evidence packager** that assembles receipt chains into
   `LiabilityClaimPackage` with Merkle proofs
4. **Provider onboarding** protocol for liability carriers to register
   and configure jurisdiction policies

### Effort

Large. The individual crates are mature. The integration work -- pricing
engine, monitoring bridge, claims packager -- is the gap.

### Competitive Defensibility

**Very strong.** This is the single strongest moat in the Chio roadmap.
Agent insurance requires: (a) per-invocation behavioral data, (b) typed
risk taxonomies, (c) cryptographic evidence for claims. Chio is the only
protocol that provides all three. A competitor would need to rebuild the
entire receipt + underwriting + market + settlement stack. The typed schemas
alone (`UnderwritingRiskClass`, `LiabilityCoverageClass`,
`UnderwritingReasonCode`) represent domain modeling that took months.

---

## 6. Cross-Kernel Federation

### Problem

Organization A's agent needs to call a tool hosted by Organization B.
Today, this requires B to trust A's kernel entirely -- or operate outside
Chio. There is no protocol for two independent kernels to cooperatively
govern a cross-boundary tool invocation.

### Architecture

Federation means two Chio kernels, each maintaining their own policy,
cooperatively evaluating and receipting a cross-boundary tool call.
Neither kernel trusts the other fully. Both sign receipts. The result
is a bilateral receipt chain.

```
Org A                              Org B
+------------------+               +------------------+
| Kernel A         |               | Kernel B         |
| (agent's home)   |               | (tool's home)    |
|                  |               |                  |
| Policy A         |               | Policy B         |
| Receipt Store A  |               | Receipt Store B  |
| CA A             |               | CA B             |
+--------+---------+               +---------+--------+
         |                                   |
         |  Federation Protocol              |
         |  (mTLS + bilateral receipts)      |
         +-----------------------------------+
```

### Trust Establishment

```
Phase 0: KEY EXCHANGE (one-time setup)
  1. Kernel A and Kernel B exchange public keys out-of-band
     (or via a shared trust registry)
  2. Each kernel adds the other to its federation trust store:
     {
       kernel_id: "kernel-b.orgb.example",
       public_key: PublicKey,
       trust_level: FederationTrustLevel,  // Full, Scoped, Probationary
       allowed_scopes: Vec<String>,        // what tools B exposes to A
       established_at: u64,
       expires_at: u64,                    // federation agreement TTL
     }
  3. mTLS certificates provisioned for kernel-to-kernel channel

Phase 1: FEDERATION AGREEMENT
  Both kernels sign a FederationAgreement:
  {
    version: "chio.federation.v1",
    parties: [kernel_a_pubkey, kernel_b_pubkey],
    scopes: {
      "a_to_b": ["tools:search", "tools:summarize"],
      "b_to_a": ["tools:verify", "tools:attest"],
    },
    receipt_policy: BilateralReceiptPolicy,
    dispute_protocol: DisputeProtocol,
    effective_at: u64,
    expires_at: u64,
    signatures: [sig_a, sig_b],
  }
```

### Cross-Signing Protocol

```
Agent in Org A calls tool in Org B:

Step 1: Agent -> Kernel A
  "I want to call tools:search on Kernel B"
  Kernel A evaluates against Policy A
  Kernel A produces: FederatedCallIntent {
    caller_identity: WorkloadIdentity,
    requested_scope: "tools:search",
    caller_passport: AgentPassport,      // from idea #4
    caller_kernel: PublicKey,
    nonce: String,
    signature_a: Signature,              // Kernel A signs intent
  }

Step 2: Kernel A -> Kernel B (over mTLS)
  POST /federation/evaluate
  Body: FederatedCallIntent

Step 3: Kernel B evaluates
  a. Verify Kernel A signature on intent
  b. Verify Kernel A is in federation trust store
  c. Verify requested scope is in federation agreement
  d. Verify agent passport (if provided)
  e. Evaluate against Policy B (Org B's own guards)
  f. Produce: FederatedCallVerdict {
       intent_nonce: String,
       decision: Decision,
       tool_endpoint: Option<String>,     // if allowed
       execution_nonce: String,           // TOCTOU protection
       signature_b: Signature,            // Kernel B signs verdict
     }

Step 4: Tool execution (if allowed)
  Agent calls tool server in Org B with execution_nonce
  Tool server validates nonce with Kernel B

Step 5: Bilateral receipt creation
  Kernel B produces receipt_b (tool execution receipt)
  Kernel B sends receipt_b to Kernel A
  Kernel A produces receipt_a (federation call receipt)
  receipt_a.metadata contains:
    - receipt_b.id (cross-reference)
    - receipt_b.signature (proof of B's attestation)
    - federation_agreement_id

  Both receipts are Merkle-committed in their respective stores.

Step 6: Bilateral verification
  Either party can verify the complete chain:
    receipt_a (in Store A) <-> receipt_b (in Store B)
    Both reference the same nonce and federation agreement.
```

### Federation Receipt Format

```rust
/// Receipt metadata for a federated cross-kernel call.
pub struct FederationReceiptMeta {
    /// Federation agreement ID governing this call.
    pub agreement_id: String,
    /// The remote kernel's public key.
    pub remote_kernel: PublicKey,
    /// The remote kernel's receipt ID for the same call.
    pub remote_receipt_id: String,
    /// The remote kernel's signature over their receipt.
    pub remote_receipt_signature: Signature,
    /// Role: did this kernel initiate or receive the federated call?
    pub role: FederationRole,
}

pub enum FederationRole {
    Initiator,  // agent's home kernel
    Responder,  // tool's home kernel
}

pub enum FederationTrustLevel {
    /// Full trust: accept all scopes in the federation agreement.
    Full,
    /// Scoped trust: only accept specific scopes, evaluate each call.
    Scoped,
    /// Probationary: limited trust, enhanced monitoring, short TTL.
    Probationary,
}
```

### Relationship to Choreography Receipts

The cross-kernel federation protocol extends the choreography receipt
chain pattern from the event streaming design (EVENT-STREAMING-INTEGRATION,
section 9). In choreography, `parent_receipt_id` links receipts across
agents within one organization. In federation, `FederationReceiptMeta`
links receipts across organizations. The chain traversal logic is the
same -- follow the receipt links -- but the trust model adds kernel-level
signature verification at each boundary crossing.

### Crate Location

`chio-federation` -- new crate. Depends on `chio-core-types` (receipts,
crypto), `chio-passport` (agent passport verification), `chio-kernel`
(guard pipeline for evaluating federated intents).

### Effort

Large. Trust establishment, mTLS provisioning, bilateral receipt protocol,
federation agreement lifecycle, and dispute resolution are all substantial.
The choreography receipt chain pattern provides a starting point but
cross-organization trust is fundamentally harder than intra-organization
agent coordination.

### Competitive Defensibility

**Strong.** Bilateral receipt chains across independent kernels are unique
to Chio. No competitor has the receipt infrastructure to support cross-
organization cryptographic audit trails. Federation also creates network
effects -- each new organization that federates increases the value of
the Chio network.

---

## 7. Capability Marketplace

### Problem

Tool servers need discovery. Agents need to find tools. Today, tool
registration is static configuration. There is no dynamic discovery,
pricing, or competitive bidding for tool access.

### Architecture

A marketplace where tool servers advertise capabilities, agents discover
and bid, and receipts prove usage for billing. Built on `chio-listing`
(registry) and `chio-market` (pricing).

```
Tool Server A                 Marketplace                   Agent
(search provider)             (chio-listing + chio-market)    (consumer)
     |                              |                          |
     | register(manifest, pricing)  |                          |
     |---------------------------->|                          |
     |                              |                          |
     |                              | <-- discover(scope)  ---|
     |                              | --> listings[]        ---|
     |                              |                          |
     |                              | <-- bid(listing, price) -|
     |                              | --> grant(capability) ---|
     |                              |                          |
     | <----------- invoke(tool, capability, nonce) -----------|
     | ------------> result + receipt ---------------------->  |
     |                              |                          |
     |                              | <-- settle(receipts) ----|
     |                              | --> payout ------------->|
```

### Marketplace Protocol

```rust
/// Tool server listing in the capability marketplace.
pub struct ToolListing {
    /// Tool server manifest (from chio-manifest).
    pub manifest: ToolManifest,
    /// Pricing model.
    pub pricing: PricingModel,
    /// Quality of service guarantees.
    pub qos: QualityOfService,
    /// Provider reputation (derived from receipt history).
    pub reputation: ProviderReputation,
    /// Listing metadata.
    pub listed_at: u64,
    pub expires_at: u64,
    /// Provider's signature over the listing.
    pub signature: Signature,
}

pub enum PricingModel {
    /// Fixed price per invocation.
    PerCall { amount: MonetaryAmount },
    /// Price based on compute/data consumed.
    Metered { rate: MonetaryAmount, unit: MeteringUnit },
    /// Auction: agent bids, provider accepts/rejects.
    Auction { reserve_price: MonetaryAmount },
    /// Subscription: fixed price for time window.
    Subscription { amount: MonetaryAmount, period_seconds: u64 },
    /// Free tier with usage limits.
    FreeTier { max_calls: u64, then: Box<PricingModel> },
}

pub enum MeteringUnit {
    TokensProcessed,
    BytesTransferred,
    CpuSeconds,
    GpuSeconds,
}

pub struct QualityOfService {
    pub max_latency_ms: u64,
    pub availability_sla: f64,      // e.g., 0.999
    pub throughput_rps: u64,
}

pub struct ProviderReputation {
    pub total_receipts: u64,
    pub uptime_fraction: f64,
    pub avg_latency_ms: f64,
    pub dispute_rate: f64,
}
```

### Discovery and Bidding

```
Discovery query:
  POST /marketplace/discover
  Body: {
    scope_pattern: "tools:search:*",
    max_price: MonetaryAmount,
    min_qos: { max_latency_ms: 500, availability_sla: 0.99 },
    min_reputation: { total_receipts: 1000, dispute_rate: 0.01 },
  }
  Response: Vec<ToolListing>

Bidding (for auction pricing):
  POST /marketplace/bid
  Body: {
    listing_id: String,
    bid_amount: MonetaryAmount,
    agent_passport: AgentPassport,  // provider can evaluate agent risk
    requested_duration: u64,
  }
  Response: {
    accepted: bool,
    capability_token: Option<CapabilityToken>,
    execution_endpoint: Option<String>,
  }
```

### Receipt-Based Billing

Every tool invocation produces a receipt. Receipts are the billing records.
`chio-metering` already attributes cost per receipt. The marketplace adds
settlement:

1. Agent accumulates receipts during a billing period
2. Marketplace aggregates metering data from receipts
3. `chio-settle` handles payout (EVM/Solana escrow release)
4. Disputes reference specific receipts with Merkle proofs

### Crate Dependencies

- `chio-listing` -- tool server registry (shipped)
- `chio-market` -- pricing and placement workflows (shipped)
- `chio-metering` -- per-receipt cost attribution (shipped)
- `chio-settle` -- on-chain settlement (shipped)
- `chio-manifest` -- tool server manifests (shipped)

### Effort

Medium. The individual crates exist. The marketplace protocol (discovery,
bidding, settlement lifecycle) is the new work. The pricing engine and
reputation system require design iteration.

### Competitive Defensibility

**Medium.** Marketplace defensibility comes from network effects, not
technology. Chio's advantage is that receipts provide the trust and billing
infrastructure -- but a marketplace only works if both tool servers and
agents participate. This is a chicken-and-egg problem.

---

## 8. Natural Language Policies

### Problem

Writing HushSpec YAML policy files requires understanding Chio's scope
model, guard types, constraint syntax, and evaluation semantics. This is
a barrier for non-technical stakeholders (compliance officers, legal,
management) who need to express policy intent.

### Architecture

An LLM-based compiler that translates English policy statements into
HushSpec YAML. The compilation is verified -- the generated YAML is
validated against the HushSpec schema and optionally dry-run evaluated
against sample scenarios before deployment.

```
English input                       HushSpec YAML output
"Agents should not access           policy:
 customer PII without explicit        name: pii-consent-required
 consent from the data owner"         rules:
                                        - match:
        |                                   scope: "data:pii:*"
        v                                 require:
  +------------------+                      - guard: consent-verification
  | NL Policy        |                        config:
  | Compiler         |                          consent_type: explicit
  |                  |                          consent_holder: data_owner
  | Steps:           |                    deny_message: >
  |  1. Parse intent |                      PII access requires explicit
  |  2. Map to       |                      consent from the data owner
  |     Chio scopes   |
  |  3. Select       |
  |     guards       |
  |  4. Generate     |
  |     YAML         |
  |  5. Validate     |
  |  6. Dry-run      |
  +------------------+
```

### Compilation Approach

```
Step 1: INTENT EXTRACTION
  Input: English policy statement
  LLM prompt:
    "Extract structured policy intent from the following statement.
     Return JSON with:
     - subjects: who does this apply to? (agent types, roles)
     - actions: what actions are being constrained? (tool calls, scopes)
     - conditions: under what conditions? (time, consent, approval)
     - effect: allow or deny?
     - constraints: any limits? (rate, amount, scope)"

  Output:
    {
      "subjects": ["all agents"],
      "actions": ["data:pii:read", "data:pii:write"],
      "conditions": ["explicit consent from data_owner"],
      "effect": "deny_unless_condition",
      "constraints": []
    }

Step 2: SCOPE MAPPING
  Map extracted actions to Chio scope patterns.
  Use the tool manifest registry to resolve ambiguous tool references.
  "customer PII" -> scope pattern "data:pii:*"
  "file access" -> scope pattern "files:*"

Step 3: GUARD SELECTION
  Map conditions to existing guard types:
  "consent" -> consent-verification guard
  "approval" -> human-in-the-loop guard
  "rate limit" -> velocity guard
  "time window" -> temporal guard
  "cost limit" -> budget guard

Step 4: YAML GENERATION
  Generate HushSpec YAML from the structured intent + scope mappings
  + guard selections. Use the HushSpec schema as a constraint during
  generation.

Step 5: VALIDATION
  Parse the generated YAML with the HushSpec validator.
  Reject if schema validation fails.
  Report warnings if scopes reference non-existent tools.

Step 6: DRY-RUN (optional)
  Evaluate the generated policy against sample scenarios:
  - "Agent A reads customer PII without consent" -> should deny
  - "Agent A reads customer PII with consent" -> should allow
  - "Agent A reads non-PII data" -> should allow
  Report pass/fail for each scenario.
```

### Safety Properties

- **Generated YAML is always validated** against the HushSpec schema.
  Malformed output is rejected, never deployed.
- **Fail-closed by default.** If the LLM generates an ambiguous policy,
  the compiler errs toward deny. An unresolvable intent produces a
  `deny_all` rule with a comment explaining why.
- **Human review required.** The compiler produces a diff showing the
  generated policy alongside the original English statement. A human
  must approve before deployment.
- **Versioned.** Each compiled policy carries the English source, the
  compilation timestamp, and the compiler version. The English source is
  hashed and included in `policy_hash` for receipt attribution.

### Crate Location

`chio-nl-policy` -- new crate. Depends on `chio-policy` (HushSpec validator),
optionally on an LLM SDK (OpenAI, Anthropic, or local model).

### Effort

Medium. The LLM integration is straightforward. The hard part is robust
scope mapping -- translating informal English descriptions of tools and
data into Chio's formal scope hierarchy. This requires access to the
tool manifest registry and iterative prompt engineering.

### Competitive Defensibility

**Medium.** Any protocol with a policy language could build NL compilation.
Chio's advantage is that HushSpec is purpose-built for agent governance
(scopes, guards, capabilities), so the compilation target is richer than
generic access control policies. But the NL compiler itself is not a moat.

---

## 9. Federated Receipt Verification (ZK Proofs)

### Problem

A regulator or counterparty wants to verify: "This agent's last 1,000 calls
were all authorized." With the regulatory API (idea #3), they can query the
receipt chain directly -- but this reveals every tool name, every scope,
every timestamp. For privacy-sensitive deployments (healthcare, defense,
competitive intelligence), revealing the full receipt chain is unacceptable.

### Goal

Prove properties about receipt chains without revealing the receipts
themselves. Zero-knowledge proofs over Merkle-committed receipt data.

### Cryptographic Approach

```
Prover (agent's kernel)             Verifier (regulator/counterparty)
         |                                    |
         | has: receipt chain R[0..999]        |
         | has: Merkle tree M over R           |
         |                                    |
         | constructs ZK circuit:             |
         |   for each receipt r in R:         |
         |     assert r.signature valid       |
         |     assert r.decision == Allow     |
         |     assert r.timestamp in window   |
         |     assert r.capability_id valid   |
         |   assert MerkleRoot(R) == root     |
         |                                    |
         | generates proof pi                 |
         |------ pi, root -------------------->|
         |                                    |
         |                          verifies: |
         |                            pi valid against public inputs
         |                            root matches published commitment
         |                                    |
         |                          learns:   |
         |                            "1000 receipts, all authorized"
         |                          does NOT learn:
         |                            tool names, scopes, timestamps,
         |                            agent identities, arguments
```

### Circuit Design (Sketch)

The ZK circuit must verify, for each receipt in the batch:

1. **Signature verification**: Ed25519 signature over canonical JSON is
   valid against the kernel's public key. This is the most expensive
   operation in the circuit. Ed25519 in R1CS/Plonk is ~25K constraints
   per verification. For 1,000 receipts, this is ~25M constraints --
   feasible with modern proving systems (Halo2, Plonky2) but requires
   significant proving time (minutes, not seconds).

2. **Decision check**: `receipt.decision` field equals `Allow`. This is
   a simple equality check, negligible constraints.

3. **Temporal ordering**: `receipt[i].timestamp <= receipt[i+1].timestamp`.
   Simple comparison, negligible constraints.

4. **Merkle membership**: each receipt is a leaf in the committed Merkle
   tree. SHA-256 Merkle proof verification in ZK is ~27K constraints per
   proof (for a tree of depth 20). For 1,000 receipts, ~27M constraints.

**Total circuit size**: ~52M constraints for 1,000 receipts. This is at
the upper end of current ZK proving systems but within reach of GPU-
accelerated provers (Rapidsnark, Halo2 with GPU backend).

### Proof System Options

| System | Constraints | Proof Size | Verify Time | Setup |
|--------|-------------|------------|-------------|-------|
| Groth16 | ~52M | 128 bytes | ~1ms | Trusted setup per circuit |
| Halo2 | ~52M | ~10KB | ~10ms | No trusted setup |
| Plonky2 | ~52M | ~50KB | ~5ms | No trusted setup |
| SP1 (RISC-V ZK) | N/A (runs Rust directly) | ~200KB | ~50ms | No trusted setup |

**Recommendation**: SP1 (Succinct) is the most practical path. Instead of
hand-writing a ZK circuit, Chio's existing Rust receipt verification code
compiles to the SP1 RISC-V target. The prover runs the unmodified Rust
code inside a ZK virtual machine. This avoids the need for circuit design
expertise and reuses existing Chio verification logic.

### Privacy Levels

Different verification scenarios require different privacy levels:

```
Level 1: AGGREGATE COMPLIANCE
  Proves: "N receipts, all authorized, in time window [t1, t2]"
  Hides: everything else
  Use case: quarterly compliance certification

Level 2: SCOPED COMPLIANCE
  Proves: "N receipts matching scope pattern X, all authorized"
  Reveals: scope pattern (but not individual tool names)
  Use case: "prove you only accessed healthcare tools"

Level 3: STATISTICAL COMPLIANCE
  Proves: "denial rate < 2%, anomaly score < 0.3, over N receipts"
  Hides: individual receipts
  Use case: insurance underwriting without raw data access

Level 4: CHAIN INTEGRITY
  Proves: "Merkle chain is unbroken from receipt R_start to R_end"
  Hides: receipt contents
  Use case: auditor verifying no receipts were deleted
```

### Crate Location

`chio-zkp` -- new crate. Depends on `chio-core-types` (receipts, Merkle
proofs), a ZK proving library (sp1-sdk or halo2_proofs).

### Effort

Very large. Even with SP1, the proving infrastructure (prover deployment,
key management, proof caching, verifier integration) is substantial.
The circuit/program design is the easier part; the operational
infrastructure is the bottleneck.

### Competitive Defensibility

**Very strong.** ZK proofs over signed receipt chains are novel in the
agent governance space. The combination of per-invocation receipts + Merkle
commitment + ZK verification creates a compliance primitive that no
competitor can replicate without rebuilding the entire receipt
infrastructure. For regulated industries (healthcare, finance, defense),
this is a decisive differentiator.

---

## 10. Compute Attestation (TEE Integration)

### Problem

Chio receipts prove WHAT an agent did (which tool, which scope, allow/deny).
They do not prove WHERE the agent ran. A receipt signed by a kernel running
on a compromised machine is worthless. Trusted Execution Environments
(TEEs) provide hardware-backed proof that code ran in a specific, measured
environment.

### Architecture

Extend the receipt signing path to include TEE attestation quotes. The
receipt proves not just the kernel's decision but the integrity of the
environment that made the decision.

```
+----------------------------------------------------------+
| TEE Enclave (SGX, SEV-SNP, TDX, Nitro, CCA)             |
|                                                          |
|  +--------------------------------------------------+   |
|  | Chio Kernel (chio-kernel-core)                      |   |
|  |                                                   |   |
|  | evaluate() -> receipt                             |   |
|  |   receipt.attestation = tee_quote()               |   |
|  |                                                   |   |
|  | tee_quote() returns:                              |   |
|  |   platform: "sgx" | "sev-snp" | "tdx" | "nitro"  |   |
|  |   measurement: Hash,    // code measurement       |   |
|  |   report_data: Hash,    // binds to receipt hash  |   |
|  |   quote: Vec<u8>,       // hardware-signed quote  |   |
|  +--------------------------------------------------+   |
|                                                          |
+----------------------------------------------------------+
```

### Attestation Integration Points

```rust
/// TEE attestation evidence attached to a Chio receipt.
pub struct ComputeAttestation {
    /// TEE platform.
    pub platform: TeePlatform,
    /// Code measurement (hash of the kernel binary in the enclave).
    pub measurement: String,
    /// Report data: SHA-256 of the receipt body, binding the attestation
    /// to the specific receipt.
    pub report_data: String,
    /// Platform-specific attestation quote (opaque bytes, verified by
    /// the platform's attestation service).
    pub quote: Vec<u8>,
    /// Timestamp of the attestation.
    pub attested_at: u64,
}

pub enum TeePlatform {
    /// Intel SGX (DCAP attestation).
    IntelSgx,
    /// AMD SEV-SNP (VCEK-signed attestation report).
    AmdSevSnp,
    /// Intel TDX (trust domain extensions).
    IntelTdx,
    /// AWS Nitro Enclaves (PCR-based attestation via NSM).
    AwsNitro,
    /// Arm CCA (confidential compute architecture).
    ArmCca,
}

/// Extended receipt with compute attestation.
/// The attestation is optional -- receipts without it are still valid
/// but carry lower assurance.
pub struct AttestedReceipt {
    /// Standard Chio receipt.
    pub receipt: ChioReceipt,
    /// TEE attestation binding this receipt to a measured environment.
    pub attestation: Option<ComputeAttestation>,
}
```

### Binding Receipts to Attestation

The critical property: the TEE quote's `report_data` field MUST contain
the SHA-256 hash of the `ChioReceiptBody` (the receipt content before
signing). This binds the attestation to the specific receipt -- an
attacker cannot detach an attestation from one receipt and attach it to
another.

```
Receipt signing with attestation:

1. Kernel constructs ChioReceiptBody (all fields except signature)
2. receipt_hash = SHA-256(canonical_json(receipt_body))
3. tee_quote = platform.get_quote(report_data = receipt_hash)
4. receipt.attestation = ComputeAttestation { ..., report_data: receipt_hash, quote: tee_quote }
5. receipt.signature = Ed25519_sign(canonical_json(receipt_body + attestation))
```

### Verification

A verifier checks three things:
1. **Receipt signature** -- Ed25519 verification (existing Chio logic)
2. **Attestation binding** -- `attestation.report_data == SHA-256(receipt_body)`
3. **Attestation validity** -- verify the TEE quote against the platform's
   attestation service (Intel PCS, AMD KDS, AWS NSM, etc.)

Step 3 requires platform-specific verification libraries. Chio should
provide adapters for each platform behind a trait:

```rust
/// Trait for TEE attestation verification.
pub trait AttestationVerifier {
    /// Verify a TEE quote and return the verified measurement.
    fn verify_quote(
        &self,
        quote: &[u8],
        expected_report_data: &[u8],
    ) -> Result<VerifiedAttestation>;
}

pub struct VerifiedAttestation {
    pub platform: TeePlatform,
    pub measurement: String,
    pub report_data_matches: bool,
    pub verified_at: u64,
}
```

### Relationship to RuntimeAssuranceTier

The existing `RuntimeAssuranceTier` in `chio-core-types` classifies the
kernel's runtime environment. TEE attestation provides the hardware-backed
evidence for the highest assurance tiers:

```
RuntimeAssuranceTier::None      -> no attestation, software-only
RuntimeAssuranceTier::SelfSigned -> kernel attests its own environment
RuntimeAssuranceTier::Verified  -> platform verifier confirms environment
RuntimeAssuranceTier::Hardware  -> TEE quote proves measured execution
```

`ComputeAttestation` is the evidence artifact for the `Hardware` tier.

### Relationship to AttestationVerifierFamily

The existing `AttestationVerifierFamily` enum in `chio-appraisal` already
lists verifier categories. TEE platforms extend this:

```rust
// Existing (chio-appraisal)
pub enum AttestationVerifierFamily {
    // ... existing variants ...
}

// Extended for TEE
pub enum AttestationVerifierFamily {
    // ... existing variants ...
    IntelSgxDcap,
    AmdSevSnpVcek,
    IntelTdxQvl,
    AwsNitroNsm,
    ArmCcaCca,
}
```

### Deployment Considerations

- **Cloud**: AWS Nitro Enclaves are the most accessible path. The kernel
  runs in a Nitro Enclave, receipts carry NSM attestations. No hardware
  changes needed -- just deploy to Nitro-capable instances.
- **On-premises**: Intel SGX and AMD SEV-SNP require specific CPU
  generations. Most enterprise servers from 2020+ support one or both.
- **Edge/WASM**: TEE attestation is not available in WASM or browser
  environments. Edge deployments use software-only assurance tiers.

### Crate Location

`chio-tee` -- new crate. Depends on `chio-core-types` (receipts, crypto),
platform-specific SDKs (aws-nitro-enclaves-sdk, sgx-sdk, etc.) behind
feature flags.

### Effort

Large. The attestation data model and receipt integration are
straightforward. The hard parts are: (a) per-platform SDK integration
and testing (requires actual TEE hardware or emulators), (b) attestation
verification service deployment, (c) measurement management (tracking
which kernel binary hashes are valid).

### Competitive Defensibility

**Strong for regulated verticals.** Healthcare, finance, and defense
deployments increasingly require hardware-backed attestation. TEE
integration with Chio receipts creates a uniquely strong audit trail:
not just WHAT the agent did, but proof that the governance kernel ran in
a verified, tamper-resistant environment. Competitors would need both the
receipt infrastructure and the TEE integration.

---

## Dependency Graph

```
Near-term (no new crate dependencies):

  1. compliance_score()  <-- receipts (shipped)
          |
          v
  2. behavioral profiling  <-- receipts + metering (shipped)
          |
          v
  3. regulatory API  <-- 1 + 2 + receipts (shipped)

Medium-term (builds on near-term):

  4. agent passport  <-- 1 + 2 + chio-kernel-core (WASM)
          |
          v
  5. agent insurance  <-- 1 + 2 + chio-underwriting + chio-market + chio-settle
          |
          v
  6. cross-kernel federation  <-- 4 + choreography receipts
          |
          v
  7. capability marketplace  <-- chio-listing + chio-market + chio-metering

  8. NL policies  <-- chio-policy (HushSpec) (independent)

Long-term (research):

  9. ZK receipt verification  <-- receipts + Merkle (shipped) + ZK prover
  10. compute attestation  <-- receipts (shipped) + TEE hardware SDKs
```

### Recommended Build Order

1. **compliance_score()** -- unlocks 4, 5, and 3. Small effort, high leverage.
2. **behavioral profiling** -- unlocks 4, 5, and 3. Medium effort.
3. **regulatory API** -- packages 1 and 2 for external consumption.
4. **agent insurance protocol** -- strongest moat, depends on 1 and 2.
5. **agent passport** -- depends on 1, 2, and WASM kernel.
6. **cross-kernel federation** -- depends on 4.
7. **capability marketplace** -- independent but benefits from 4 and 5.
8. **NL policies** -- independent, can proceed in parallel.
9. **ZK proofs** -- research track, long lead time.
10. **TEE attestation** -- research track, hardware-dependent.

---

## Competitive Landscape Positioning

### What Competitors Cannot Replicate Quickly

| Moat | Why It Is Hard to Copy |
|------|----------------------|
| Per-invocation signed receipts | Requires kernel-level integration; bolt-on audit logs lack cryptographic binding |
| Merkle-committed receipt chains | Requires append-only structured storage with hash chaining from genesis |
| 4-tier underwriting taxonomy | Domain modeling (13 reason codes, evidence types) took months of design |
| 5-class liability coverage model | Insurance product design requires actuarial + legal + technical expertise |
| Bilateral federation receipts | Requires two independent kernels with compatible receipt formats |
| Compliance scoring over receipts | Only credible if the underlying receipts are tamper-evident |
| ZK proofs over receipt chains | Requires both the receipt infrastructure and ZK circuit/program design |

### What Competitors Could Build Independently

| Capability | Replication Path |
|------------|-----------------|
| NL policy compilation | Any policy engine + LLM integration |
| Behavioral profiling (over unattested data) | Log analysis, no receipt integrity |
| Regulatory API (over unattested data) | SIEM export, weaker guarantees |
| Capability marketplace (without receipts) | Service catalog + billing, no provenance |

### The Compounding Advantage

The ideas in this document are not independent. They compose:

- **Compliance scores** feed **insurance premiums** feed **marketplace reputation**
- **Behavioral profiles** feed **anomaly detection** feed **underwriting signals**
- **Agent passports** carry **compliance scores** across **federated kernels**
- **ZK proofs** prove **compliance scores** without revealing **receipt chains**
- **TEE attestation** strengthens **receipt integrity** which strengthens **everything above**

Each layer makes the next more credible. A competitor entering at any
single layer faces the full stack as a moat.
