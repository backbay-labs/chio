# Compliance Roadmap

**Scope:** Multi-framework compliance strategy, gap analysis, implementation plan

---

## 0. Purpose

Chio has strong EU AI Act and Colorado SB 24-205 coverage but gaps in FedRAMP
(FIPS crypto), PCI DSS, and NIST AI RMF / ISO 42001 mapping. This document
plans the path from current state to multi-framework compliance readiness.

This is a planning document, not a compliance mapping. Each framework section
below will produce its own standalone mapping document (modeled on the existing
`docs/compliance/eu-ai-act-article-19.md` and `colorado-sb-24-205.md`) once
the prerequisite technical work is complete.

---

## 1. Current Compliance State

### 1.1 What Exists

| Framework | Document | Status |
|-----------|----------|--------|
| EU AI Act (Article 19, Annex IV, Annex VIII) | `docs/compliance/eu-ai-act-article-19.md` | Complete. Clause-by-clause mapping with test function references. |
| Colorado SB 24-205 | `docs/compliance/colorado-sb-24-205.md` | Complete. Test-backed clause mapping. |
| Session Compliance Certificate | `docs/protocols/SESSION-COMPLIANCE-CERTIFICATE.md` | Shipped. `chio.session_compliance_certificate.v1` schema implemented. |
| Evidence Export | `crates/products/chio-cli` | Shipped. `SignedExportEnvelope` provides portable, signed evidence bundles. |
| Trust Model | `docs/protocols/TRUST-MODEL-AND-KEY-MANAGEMENT.md` | Draft. Key hierarchy, rotation domains, hosted signing. |

### 1.2 What Is Strong

Chio's compliance posture is unusually strong for an infrastructure-layer
protocol because it produces cryptographically signed, per-invocation audit
records by default. Most compliance frameworks require "adequate logging" --
Chio exceeds this with:

- **Signed receipts.** Every tool invocation (allow or deny) produces an
  Ed25519-signed `ChioReceipt` with capability ID, policy hash, content hash,
  guard evidence, and kernel key reference.
- **Merkle-committed checkpoints.** Receipt batches are committed to signed
  Merkle roots, enabling tamper-evident verification and individual inclusion
  proofs without replaying the full log.
- **Session compliance certificates.** A single signed artifact proving an
  entire agent session operated within its authorized scope, budget, and
  guard constraints.
- **DPoP proof-of-possession.** Per-invocation cryptographic binding between
  the invoking agent's keypair and each tool call, preventing replay and
  ensuring attribution.
- **Fail-closed evaluation.** Errors during guard evaluation produce deny
  receipts. The system never silently passes on error paths.
- **Budget enforcement.** Atomic monetary controls with per-invocation and
  per-grant limits, with financial metadata captured in every receipt.

### 1.3 What Is Missing

| Gap | Impact | Section |
|-----|--------|---------|
| Ed25519 is not FIPS 140-2/140-3 approved | Blocks FedRAMP, ITAR, some HIPAA deployments | Section 2 |
| No PCI DSS control mapping | Blocks payment/fintech agent deployments | Section 3 |
| No NIST AI RMF mapping document | Low effort, high impact for enterprise sales | Section 4 |
| No ISO 42001 mapping document | Required for EU-adjacent enterprise procurement | Section 5 |
| No SOC 2 Type II mapping | Table stakes for SaaS/enterprise | Section 6 |
| No HIPAA technical safeguard mapping | Blocks healthcare agent deployments | Section 7 |
| No OWASP LLM Top 10 coverage matrix | Expected by security-conscious buyers | Section 8 |
| No California SB 1047 mapping | Emerging requirement for frontier AI systems | Section 9 |
| No automated compliance evidence packaging | Manual evidence assembly does not scale | Section 10 |

---

## 2. FIPS 140-2/140-3 Cryptographic Path

### 2.1 The Problem

Chio uses Ed25519 exclusively for all cryptographic signing:

```rust
// crates/core/chio-core-types/src/capability
//! Capability tokens: Ed25519-signed, scoped, time-bounded authorizations.
```

Ed25519 (defined in RFC 8032) is widely used and well-regarded, but it is
not universally approved under FIPS 140-2 or FIPS 140-3. NIST added Ed25519
to FIPS 186-5 (Digital Signature Standard, February 2023), but validation
status depends on the specific cryptographic module implementation. FedRAMP
requires FIPS 140-2 Level 1 (minimum) validated cryptographic modules for
all cryptographic operations in federal information systems.

This blocks Chio adoption in:

- U.S. federal agencies (FedRAMP)
- Defense contractors (ITAR/DFARS)
- Some healthcare deployments (HIPAA Security Rule, where covered entities
  require FIPS-validated encryption)
- Financial institutions with FIPS-mandated security policies

### 2.2 Option A: NIST Curve Signing (P-256/P-384) Behind Feature Flag

Add P-256 (secp256r1) and P-384 (secp384r1) as alternative signing
algorithms. These are universally FIPS-approved and available in every
FIPS-validated cryptographic module.

**Implementation approach:**

1. Define a `SigningAlgorithm` enum in `chio-core-types`:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningAlgorithm {
    /// Ed25519 (RFC 8032). Default. Not universally FIPS-validated.
    Ed25519,
    /// ECDSA P-256 (FIPS 186-4/5). FIPS-validated in all major modules.
    EcdsaP256,
    /// ECDSA P-384 (FIPS 186-4/5). Required by some government profiles.
    EcdsaP384,
}
```

2. Gate behind a Cargo feature flag (`fips-signing`) so the default build
   remains Ed25519-only with no additional dependencies.

3. Update all signing/verification paths: `CapabilityToken`, `ChioReceipt`,
   `KernelCheckpoint`, `SessionComplianceCertificate`, `SignedExportEnvelope`,
   DPoP proofs.

4. Add algorithm identifier to signed artifacts so verifiers know which
   algorithm to use without trial-and-error.

**Impact on artifact formats:**

- `CapabilityToken.signature` and `ChioReceipt.signature` already carry the
  signature bytes. The algorithm identifier must be added as a new field or
  encoded in the signature structure.
- Canonical JSON serialization is algorithm-agnostic (it defines byte ordering,
  not signing). No changes needed.
- Receipt format gains an `algorithm` field. Old receipts without the field
  are assumed Ed25519 for backward compatibility.
- DPoP proofs gain an `algorithm` field in the proof body.

### 2.3 Option B: FIPS-Validated Cryptographic Module

Use a FIPS 140-2/140-3 validated implementation of Ed25519 itself, avoiding
the need for algorithm changes:

- **AWS-LC (aws-lc-rs):** AWS's fork of BoringSSL. FIPS 140-3 validated
  (Certificate #4631). Supports Ed25519. Available as a Rust crate.
- **BoringCrypto:** Google's FIPS module. Validated but harder to consume
  from Rust directly.
- **ring with FIPS module:** The `ring` crate (which Chio likely uses
  transitively) does not have FIPS validation, but `aws-lc-rs` is a
  drop-in replacement for many `ring` APIs.

**Implementation approach:**

1. Add `aws-lc-rs` as an optional dependency behind a `fips` feature flag.
2. Replace `ed25519-dalek` (or `ring`) signing/verification calls with
   `aws-lc-rs` equivalents when the `fips` flag is active.
3. No artifact format changes needed -- same algorithm, different module.

**Trade-offs:**

- Simpler than Option A (no new algorithm, no format changes).
- Depends on a single vendor's FIPS validation.
- `aws-lc-rs` is a C dependency (not pure Rust), which affects the WASM
  kernel compilation target.

### 2.4 Option C: HSM Integration for Key Storage

Regardless of the signing algorithm, regulated deployments require hardware
security module (HSM) or key management service (KMS) integration for key
storage. Private keys should never be extractable in plaintext.

**Target integrations:**

| KMS/HSM | Protocol | Priority |
|---------|----------|----------|
| HashiCorp Vault Transit | REST API | P1 -- most common in enterprise |
| AWS CloudHSM / KMS | AWS SDK | P1 -- required for FedRAMP on AWS |
| Azure Key Vault | REST API | P2 |
| GCP Cloud KMS | REST API | P2 |
| PKCS#11 (generic HSM) | C FFI | P3 -- covers Thales, Entrust, etc. |

**Implementation approach:**

1. Define a `SigningBackend` trait in `chio-core`:

```rust
#[async_trait]
pub trait SigningBackend: Send + Sync {
    /// Sign the given bytes and return the signature.
    async fn sign(&self, data: &[u8]) -> Result<Signature>;
    /// Return the public key for this backend.
    fn public_key(&self) -> &PublicKey;
    /// Return the signing algorithm.
    fn algorithm(&self) -> SigningAlgorithm;
}
```

2. Implement `LocalSigningBackend` (current behavior: in-memory Ed25519
   keypair) and `VaultTransitBackend`, `AwsKmsBackend`, etc.

3. The kernel accepts a `Box<dyn SigningBackend>` instead of a raw `Keypair`.
   All signing operations go through the trait.

4. Configuration in `chio.yaml`:

```yaml
signing:
  backend: vault_transit
  vault_address: "https://vault.internal:8200"
  key_name: "chio-kernel-prod"
  algorithm: ecdsa_p256
```

### 2.5 Recommended Path

Implement all three options in phases:

| Phase | Work | Outcome |
|-------|------|---------|
| Phase 1 | `SigningBackend` trait + `LocalSigningBackend` | Abstraction layer without behavior change |
| Phase 2 | `aws-lc-rs` backend behind `fips` feature flag | FIPS-validated Ed25519 for non-HSM deployments |
| Phase 3 | P-256/P-384 algorithm support | Full NIST curve support for strictest policies |
| Phase 4 | Vault Transit + AWS KMS backends | HSM-backed signing for production |

Phase 1 is prerequisite for all others and should ship first.

---

## 3. PCI DSS v4.0 Mapping

### 3.1 Overview

PCI DSS v4.0 (effective March 2025) defines 12 requirement groups for
protecting cardholder data. Chio does not process, store, or transmit
cardholder data itself, but agent systems governed by Chio may interact with
payment APIs, CRM systems containing card data, or financial tool servers.
Chio's controls reduce the PCI DSS scope for the agent layer.

### 3.2 Requirement Mapping

| PCI DSS v4.0 Requirement | Chio Coverage | Gap |
|---------------------------|-------------|-----|
| **Req 1: Network security controls** | Out of scope. Chio operates at application layer, not network layer. | Network segmentation is a deployment concern. Chio's sidecar architecture is compatible with network isolation but does not enforce it. |
| **Req 2: Secure configurations** | Partial. `chio.yaml` defines kernel configuration. Unified configuration doc covers secure defaults. | No configuration hardening benchmark. Need a PCI-specific secure baseline config. |
| **Req 3: Protect stored account data** | Partial. `QueryResultGuard` can redact PII patterns from tool results. Column constraints restrict which database columns agents can access. | Chio does not encrypt data at rest in its receipt store. Receipt content hashes do not contain raw cardholder data (SHA-256 of arguments), but guard evidence may contain tool output snippets. Need configurable redaction of guard evidence before persistence. |
| **Req 4: Protect data in transit** | Chio sidecar and kernel HTTP endpoints support TLS. mTLS is documented for tool server connections. | No enforcement of minimum TLS version in Chio configuration. Need `min_tls_version: 1.2` config option. |
| **Req 5: Protect from malicious software** | Out of scope. Chio governs tool access, not endpoint protection. | N/A |
| **Req 6: Develop secure systems** | Partial. Chio uses `clippy -D warnings`, `unwrap_used = "deny"`, `expect_used = "deny"`. Canonical JSON (RFC 8785) for all signed payloads. | No formal SDLC documentation for PCI compliance. Need vulnerability disclosure policy and secure coding guidelines doc. |
| **Req 7: Restrict access by business need** | Strong. Capability tokens scope access to specific tools, servers, and operations. Grants are time-bounded and revocable. Delegation chains enforce monotonic attenuation. | Need to document the mapping: capability tokens = logical access control, grants = role-based permissions, constraints = conditional access. |
| **Req 8: Identify users and authenticate access** | Strong. DPoP proof-of-possession binds agent identity to every invocation. Capability tokens identify the subject (agent). `WorkloadIdentity` provides agent metadata. | Agent identity is cryptographic (Ed25519 keypairs), not user-credential-based. Need to document how Chio agent identity maps to PCI's "user identification" concept. |
| **Req 9: Restrict physical access** | Out of scope. Chio is software infrastructure. | N/A |
| **Req 10: Log and monitor all access** | Strong. Every tool invocation produces a signed receipt. Merkle-committed checkpoints provide tamper evidence. Configurable retention with verifiable archival. Receipt dashboard (`chio trust serve`) provides monitoring. | Need real-time alerting integration (SIEM export). Receipt store supports reporting queries but no push-based alerting. |
| **Req 11: Test security regularly** | Partial. `cargo test --workspace` covers functional tests. Guard integration tests cover policy enforcement. | No penetration testing program documented. No vulnerability scanning pipeline. |
| **Req 12: Support information security with policies** | Out of scope for Chio as a protocol. This is an organizational requirement for the deploying entity. | Chio can provide evidence for the deployer's security program but cannot satisfy organizational policy requirements. |

### 3.3 Required Technical Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| Guard evidence redaction before persistence (configurable) | Medium | P1 |
| `min_tls_version` configuration option on HTTP endpoints | Small | P1 |
| SIEM export adapter (Splunk, Datadog, Elastic) for receipt stream | Medium | P2 |
| PCI-specific secure baseline configuration document | Small | P2 |
| PCI DSS v4.0 formal mapping document (modeled on EU AI Act doc) | Small | P1 |

---

## 4. NIST AI RMF Mapping

### 4.1 Overview

The NIST AI Risk Management Framework (AI RMF 1.0, January 2023) defines
four core functions: Govern, Map, Measure, and Manage. Each function
contains categories and subcategories. Chio's technical controls map well to
Map, partially to Govern and Manage, and weakly to Measure.

### 4.2 Function Mapping

#### Govern (organizational AI risk governance)

| Category | Chio Relevance | Chio Mechanism |
|----------|---------------|---------------|
| GV-1: Policies and procedures | Partial. Chio enforces policies but does not define organizational AI governance. | Policy files (`chio.yaml`, guard configurations) are the executable expression of organizational policy. Policy hash is recorded in every receipt. |
| GV-2: Accountability structures | Partial. Chio provides attribution (DPoP, agent identity) but does not define organizational accountability. | `WorkloadIdentity` captures agent metadata. `CapabilityToken.issuer` identifies the authority. Delegation chains provide provenance. |
| GV-3: Workforce diversity and AI expertise | Out of scope. Organizational concern. | N/A |
| GV-4: Organizational risk culture | Partial. Chio's fail-closed design embodies risk-averse defaults. | Guard pipeline defaults to deny. Budget enforcement is atomic. |
| GV-5: Processes to address AI risks | Partial. Chio provides the enforcement layer but not the risk assessment process. | Receipts provide evidence for risk review. Compliance certificates summarize session-level risk posture. |
| GV-6: Policies for third-party AI | Strong. Chio governs tool server access, which includes third-party AI services. | Capability scoping restricts which third-party services agents can access. Model constraints (proposed in ARCHITECTURAL-EXTENSIONS.md) restrict which LLMs can drive tool calls. |

#### Map (context and risk identification)

| Category | Chio Relevance | Chio Mechanism |
|----------|---------------|---------------|
| MP-1: Intended purposes and context | Partial. Chio does not define system purpose but records operational context. | `ToolManifest` describes tool capabilities. `WorkloadIdentity` captures agent purpose metadata. |
| MP-2: Categorize AI systems | Partial. Chio supports risk tiering. | `chio-underwriting` provides 4-tier agent risk classification with 13 reason codes. `GovernedAutonomyTier` in capability tokens. |
| MP-3: Benefits, costs, and risks | Partial. Chio tracks costs but not benefits. | `FinancialReceiptMetadata` tracks per-invocation costs. Budget enforcement limits aggregate cost. Benefits are outside Chio's scope. |
| MP-4: Positive and negative impacts | Partial. Chio records outcomes but does not assess impact. | Receipt decision (allow/deny) with guard evidence provides outcome data. Impact assessment requires domain-specific analysis. |
| MP-5: Likelihood and severity of risks | Weak. Chio records risk-relevant data but does not compute risk scores. | See section 4.3 (Risk Scoring Module proposal). |

#### Measure (risk assessment and analysis)

| Category | Chio Relevance | Chio Mechanism |
|----------|---------------|---------------|
| MS-1: Appropriate metrics identified | Weak. Chio produces raw data but no risk metrics. | Receipt store has reporting queries (counts, rates, budget utilization). No risk scoring. |
| MS-2: AI systems evaluated | Weak. Chio evaluates per-invocation but not system-level risk. | Per-invocation guard evaluation. No aggregate behavioral risk assessment. |
| MS-3: Risks and impacts tracked | Partial. Denial rates and budget consumption are tracked. | Receipt store supports time-series queries. `chio trust serve` dashboard. |
| MS-4: Feedback integrated | Weak. No feedback loop from risk measurement to policy adjustment. | Manual policy file updates. No automated policy tightening based on risk signals. |

#### Manage (risk response and monitoring)

| Category | Chio Relevance | Chio Mechanism |
|----------|---------------|---------------|
| MG-1: Risk prioritized and responded to | Partial. Chio enforces deny decisions but does not prioritize risks. | Guard pipeline produces allow/deny. No risk ranking. |
| MG-2: Strategies to maximize benefits and minimize risks | Strong. Chio's constraint system limits agent capability to what is authorized. | Capability scoping, budget limits, time bounds, model constraints, delegation attenuation. |
| MG-3: Risks and benefits monitored | Partial. Risks are monitored via receipt stream. Benefits are not tracked. | Receipt dashboard, retention, archival. |
| MG-4: Residual risks managed | Weak. Chio does not track residual risk. | Need risk register integration. |

### 4.3 Risk Scoring Module Proposal

The Measure function is the weakest mapping. Chio produces all the raw data
needed for risk measurement but does not compute risk metrics. A risk scoring
module would close this gap.

**Proposed `chio-risk` crate:**

```rust
/// Risk score for an agent session or time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Overall risk score (0.0 = no risk, 1.0 = maximum risk).
    pub score: f64,
    /// Risk category breakdown.
    pub categories: BTreeMap<RiskCategory, f64>,
    /// Inputs that drove the score.
    pub contributing_factors: Vec<RiskFactor>,
    /// Time window this score covers.
    pub time_range: TimeRange,
    /// Number of receipts analyzed.
    pub receipt_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskCategory {
    /// Denial rate anomaly (sudden spike in denied invocations).
    DenialRateAnomaly,
    /// Budget consumption velocity (burning budget faster than baseline).
    BudgetVelocity,
    /// Scope expansion (agent accessing tools it rarely uses).
    ScopeExpansion,
    /// Sensitive data exposure (PII guard triggers, column constraint hits).
    SensitiveDataExposure,
    /// Temporal anomaly (invocations outside normal operating hours).
    TemporalAnomaly,
    /// Model drift (different model driving tool calls than baseline).
    ModelDrift,
}
```

**Inputs (all available from existing receipt store):**

- Denial rate over sliding window vs. historical baseline
- Budget consumption velocity vs. historical average
- Unique tool/server combinations per session vs. baseline
- PII guard trigger count
- DPoP proof timing patterns
- Model metadata distribution (once ModelConstraint ships)

**Outputs:**

- Per-session risk score (attached to compliance certificate)
- Per-agent risk trend (time series for dashboard)
- Risk threshold alerts (configurable, for SIEM integration)
- NIST AI RMF Measure function evidence (exportable)

### 4.4 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| NIST AI RMF formal mapping document | Small | P1 |
| `chio-risk` crate with basic scoring (denial rate, budget velocity) | Medium | P2 |
| Risk score attachment to compliance certificates | Small | P2 (depends on `chio-risk`) |
| Feedback loop: risk score to policy tightening recommendations | Medium | P3 |

---

## 5. ISO 42001 Mapping

### 5.1 Overview

ISO/IEC 42001:2023 (Artificial Intelligence Management System) defines
requirements for establishing, implementing, maintaining, and continually
improving an AI management system. It follows the Annex SL structure common
to ISO management system standards (ISO 27001, ISO 9001, etc.).

Chio provides technical controls that support several ISO 42001 clauses, but
ISO 42001 is primarily an organizational management standard. Chio cannot
satisfy it alone -- it provides evidence and enforcement for the technical
controls that the organization's AI management system requires.

### 5.2 Clause Mapping

| ISO 42001 Clause | Requirement | Chio Relevance | Chio Mechanism |
|------------------|-------------|---------------|---------------|
| 4.1 -- Understanding the organization | Determine external/internal issues relevant to AI | Out of scope (organizational) | N/A |
| 4.2 -- Interested parties | Determine needs and expectations of interested parties | Out of scope (organizational) | N/A |
| 5.1 -- Leadership and commitment | Top management demonstrates commitment to AIMS | Out of scope (organizational) | N/A |
| 6.1 -- Actions to address risks | Determine risks and opportunities, plan actions | Partial. Chio enforces risk controls. | Capability scoping, guard pipeline, budget enforcement. Risk scoring (proposed) would strengthen this. |
| 6.1.4 -- AI risk assessment | Assess AI risks systematically | Partial. Chio records risk-relevant data. | Receipt store, denial rates, budget utilization. `chio-risk` scoring (proposed) closes the gap. |
| 7.5 -- Documented information | Maintain documented information required by AIMS | Strong. Chio produces signed, retained, verifiable documentation. | Receipts, checkpoints, compliance certificates, evidence export bundles. All signed and Merkle-committed. |
| 8.4 -- AI system lifecycle | Manage AI system development, deployment, monitoring | Partial. Chio governs the operational phase. | Guard pipeline, capability lifecycle (issue, delegate, revoke, expire). |
| 9.1 -- Monitoring, measurement, analysis | Monitor and measure AIMS performance | Partial. Chio monitors tool invocations. | Receipt store with reporting queries. Dashboard (`chio trust serve`). Compliance certificates. |
| 9.2 -- Internal audit | Conduct internal audits of AIMS | Partial. Chio provides audit evidence. | Evidence export bundles, compliance certificates, Merkle inclusion proofs. |
| 10.1 -- Continual improvement | Improve AIMS continually | Weak. Chio does not drive improvement. | Receipt data can inform improvement but Chio does not automate policy evolution. |
| Annex A -- AI controls reference | Reference set of AI-specific controls | Strong. Chio implements many Annex A controls. | See section 5.3 below. |
| Annex B -- Implementation guidance | Guidance on implementing AI controls | Partial. Chio's documentation covers implementation. | Protocol docs, guard docs, integration docs. |

### 5.3 Annex A Control Mapping

| Control | Description | Chio Mechanism |
|---------|-------------|---------------|
| A.2 -- AI impact assessment | Assess AI system impacts | `chio-underwriting` risk classification. Receipt-based impact data. |
| A.4 -- AI system documentation | Document AI system capabilities and limitations | `ToolManifest` with signed tool definitions. Protocol specification. |
| A.5 -- Data management | Manage data used by AI systems | Data layer guards (SQL, vector DB, warehouse, graph, cache). Column constraints. PII pattern matching. |
| A.6 -- Computing resources | Manage computing resources for AI | Budget enforcement (`max_total_cost`, `max_cost_per_invocation`). Metering (`chio-metering`). |
| A.7 -- AI system logging | Log AI system operations | Signed receipts. Merkle checkpoints. Configurable retention. |
| A.8 -- AI system monitoring | Monitor AI system behavior | Receipt dashboard. Compliance certificates. Evidence export. |
| A.9 -- AI system performance | Evaluate AI system performance | Receipt reporting queries (invocation counts, denial rates, latency). |
| A.10 -- Third-party management | Manage third-party AI components | Capability scoping for tool servers. Model constraints (proposed). Cloud guardrail interop (proposed). |

### 5.4 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| ISO 42001 formal mapping document | Medium | P1 |
| Annex A control-by-control mapping with evidence references | Medium | P1 |
| ISO 42001 Statement of Applicability template (pre-filled with Chio controls) | Small | P2 |

---

## 6. SOC 2 Type II

### 6.1 Overview

SOC 2 Type II reports evaluate an organization's controls over a period of
time (typically 6-12 months) against five trust service criteria. Chio is
infrastructure, not a service organization, so SOC 2 applies to organizations
deploying Chio, not to Chio itself. However, Chio's technical controls directly
support three of the five criteria and partially support a fourth.

### 6.2 Trust Service Criteria Mapping

#### CC (Common Criteria) / Security

| Criteria | Chio Provides | Customer Responsibility |
|----------|-------------|------------------------|
| CC1 -- Control environment | Policy files and guard configurations express control intent | Organizational governance, tone at the top |
| CC2 -- Communication and information | Receipt dashboard, compliance certificates | Internal reporting, stakeholder communication |
| CC3 -- Risk assessment | `chio-underwriting` risk classification, denial rate data | Formal risk assessment process, risk register |
| CC5 -- Control activities | Guard pipeline, capability scoping, budget enforcement | Monitoring control effectiveness, remediation |
| CC6 -- Logical and physical access | Capability tokens (access control), DPoP (authentication), delegation chains (authorization) | Physical access, network controls, identity provider |
| CC7 -- System operations | Receipt logging, Merkle checkpoints, retention | Incident response, change management, capacity planning |
| CC8 -- Change management | Policy hash in receipts tracks policy version | Formal change management process, approval workflows |
| CC9 -- Risk mitigation | Fail-closed evaluation, budget limits, time bounds, revocation | Risk acceptance decisions, residual risk management |

#### Availability

| Criteria | Chio Provides | Customer Responsibility |
|----------|-------------|------------------------|
| A1 -- System availability | Chio sidecar is stateless (restartable). Receipt store is SQLite (embedded, no external dependency for basic operation). | Deployment architecture, redundancy, disaster recovery, SLA management |

Chio contributes to availability through architectural simplicity (embedded
database, no required external services for core operation), but availability
is primarily a deployment and operations concern.

#### Processing Integrity

| Criteria | Chio Provides | Customer Responsibility |
|----------|-------------|------------------------|
| PI1 -- Processing integrity | Every tool call is evaluated against policy before execution. Receipts prove evaluation occurred. Guard evidence proves policy was applied. Content hash proves what was evaluated. | Defining correct policies, validating tool server behavior, end-to-end testing |

This is Chio's strongest SOC 2 contribution. The signed receipt with policy
hash, content hash, and guard evidence is direct evidence of processing
integrity for the governance layer.

#### Confidentiality

| Criteria | Chio Provides | Customer Responsibility |
|----------|-------------|------------------------|
| C1 -- Confidentiality | PII guards, column constraints, `QueryResultGuard` redaction, capability scoping restricts tool access | Data classification, encryption at rest, key management, network encryption |

Chio contributes access control and output filtering. Encryption at rest and
key management are customer responsibilities (or require the FIPS/HSM work
from section 2).

#### Privacy

| Criteria | Chio Provides | Customer Responsibility |
|----------|-------------|------------------------|
| P1-P8 -- Privacy criteria | PII guards detect and can block PII in tool arguments and results. Column constraints restrict database access to authorized fields. Guard evidence records PII detection events. | Privacy policy, data subject rights, consent management, data retention policy, privacy impact assessments |

### 6.3 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| SOC 2 Type II control mapping document | Medium | P1 |
| "Chio Controls for SOC 2" customer-facing guide (what Chio does vs. what you do) | Medium | P2 |
| Evidence export format for SOC 2 auditors | Small | P2 (depends on `chio certify` work in section 10) |

---

## 7. HIPAA Technical Safeguards (45 CFR 164.312)

### 7.1 Overview

HIPAA's Security Rule (45 CFR 164.312) defines technical safeguards for
protecting electronic protected health information (ePHI). Chio does not
store ePHI, but agent systems governed by Chio may access EHR systems,
patient databases, or clinical tool servers. Chio's controls map to several
164.312 requirements.

### 7.2 Technical Safeguard Mapping

| 164.312 Requirement | Standard | Chio Mechanism | Gap |
|---------------------|----------|---------------|-----|
| 164.312(a)(1) -- Access control | Unique user identification | `CapabilityToken.subject` uniquely identifies each agent. `WorkloadIdentity` captures agent metadata. DPoP binds cryptographic identity to each invocation. | Agent identity is not "user" identity. Need mapping guidance for covered entities. |
| 164.312(a)(1) -- Access control | Emergency access procedure | Capability tokens can be issued with elevated scope for break-glass scenarios. | No formal emergency access procedure documented. Need break-glass capability issuance workflow. |
| 164.312(a)(1) -- Access control | Automatic logoff | Capability tokens have `not_after` expiry. Session-scoped tokens expire with the session. | Expiry is time-based, not inactivity-based. Need idle-timeout revocation trigger. |
| 164.312(a)(1) -- Access control | Encryption and decryption | Chio does not encrypt ePHI. Chio's role is access governance, not data encryption. | Out of scope. Customer must encrypt ePHI at rest and in transit independently. |
| 164.312(b) -- Audit controls | Hardware, software, procedural mechanisms to record and examine access | Signed receipts for every tool invocation. Merkle-committed checkpoints. Configurable retention. Evidence export. Compliance certificates. | Receipt store is the audit mechanism. Need HIPAA-specific audit report format. |
| 164.312(c)(1) -- Integrity | Protect ePHI from improper alteration or destruction | Chio receipts are signed and Merkle-committed (tamper-evident). Content hash proves what was evaluated. Column constraints restrict write access. | Chio protects audit integrity, not ePHI integrity directly. ePHI integrity is the tool server's responsibility. |
| 164.312(c)(2) -- Integrity | Mechanism to authenticate ePHI | Receipt signatures provide authentication of audit records. DPoP provides authentication of agent actions. | Chio authenticates governance artifacts, not ePHI itself. |
| 164.312(d) -- Person or entity authentication | Verify identity of person/entity seeking access | DPoP proof-of-possession with Ed25519 keypair. Capability token issuer verification. Delegation chain validation. | "Person" authentication requires mapping agent identity to responsible human. Need agent-to-operator attribution chain. |
| 164.312(e)(1) -- Transmission security | Guard against unauthorized access to ePHI during transmission | Chio sidecar supports TLS for kernel-to-tool-server communication. mTLS documented for inter-service transport. | Chio does not inspect or govern the content of ePHI in transit. Tool server transport security is outside Chio's control. |
| 164.312(e)(2) -- Transmission security | Encryption | TLS on Chio HTTP endpoints. | Need to enforce minimum TLS 1.2. Same as PCI DSS requirement. |

### 7.3 PII Guards and Column Constraints

Chio's data layer guards provide ePHI-relevant protections:

- **`QueryResultGuard`**: Post-invocation guard that applies PII pattern
  matching (SSN, date of birth, medical record number patterns) to tool
  results. Can block or redact results containing detected ePHI patterns.
- **`SqlQueryGuard`**: Pre-invocation guard that restricts which database
  tables and columns agents can query. Column constraints can deny access
  to ePHI fields (e.g., `denied_columns: ["ssn", "dob", "diagnosis"]`).
- **Column-level access control**: Capability grants can restrict database
  operations to specific columns, preventing agents from accessing ePHI
  fields they are not authorized to see.

### 7.4 Business Associate Agreement Framework

Covered entities deploying Chio-governed agents that access ePHI need a BAA
framework that addresses:

1. **Chio as infrastructure provider.** Chio (the protocol and runtime) does
   not process or store ePHI. The kernel processes capability tokens,
   arguments hashes, and guard verdicts -- not ePHI content.
2. **Receipt store content.** Receipts contain content hashes (SHA-256 of
   arguments), not raw arguments. Guard evidence may contain snippets of
   tool output if post-invocation guards are configured. Redaction
   configuration (section 3.3) is critical for HIPAA deployments.
3. **Tool server BAAs.** Each tool server that accesses ePHI requires its
   own BAA with the covered entity. Chio's capability scoping restricts which
   tool servers agents can access, reducing the BAA surface area.
4. **Minimum necessary standard.** Chio's capability scoping and column
   constraints directly implement the HIPAA minimum necessary standard for
   agent access -- agents receive only the tool access and data columns they
   need.

### 7.5 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| HIPAA technical safeguard mapping document | Medium | P1 |
| Guard evidence redaction for HIPAA (overlaps with PCI DSS work) | Medium | P1 |
| Break-glass capability issuance workflow | Small | P2 |
| Idle-timeout capability revocation trigger | Small | P2 |
| Agent-to-operator attribution chain documentation | Small | P2 |
| HIPAA BAA template for Chio deployments | Small | P2 (legal review required) |

---

## 8. OWASP LLM Top 10 Coverage Matrix

### 8.1 Overview

The OWASP Top 10 for Large Language Model Applications (v1.1, October 2023)
identifies the ten most critical security risks for LLM-based applications.
Chio's tool-governance focus means it directly addresses risks at the tool
invocation boundary but has limited coverage of model-layer attacks.

### 8.2 Coverage Matrix

| # | Risk | Chio Coverage | What Chio Does | Gap | Scope |
|---|------|-------------|---------------|-----|-------|
| LLM01 | **Prompt Injection** | Partial | Content safety guards (jailbreak detection, prompt injection detection) in the guard pipeline. Cloud guardrail interop (Bedrock, Azure, Vertex) adds defense in depth. Guard evidence in receipts records detection events. | Chio guards inspect tool call arguments, not the full prompt. Prompt injection that manipulates the agent's reasoning without changing tool call parameters is invisible to Chio. | Chio scope: tool-call-level detection. Model-layer defense: out of scope. |
| LLM02 | **Insecure Output Handling** | Strong | `QueryResultGuard` inspects tool outputs post-invocation. PII pattern matching. Column redaction. `PostInvocationVerdict::Block` prevents unsafe outputs from reaching the agent. | Only covers outputs from governed tool servers. Direct LLM outputs (text generation without tool calls) are outside Chio's governance boundary. | Chio scope: tool output filtering. |
| LLM03 | **Training Data Poisoning** | Out of scope | Chio does not govern model training. | N/A | Model-layer attack. |
| LLM04 | **Model Denial of Service** | Out of scope | Chio does not govern inference compute. | Budget enforcement limits monetary cost of tool calls, which indirectly limits some DoS vectors (e.g., agent flooding an expensive API). | Model-layer attack. Chio provides indirect mitigation via budget controls. |
| LLM05 | **Supply Chain Vulnerabilities** | Partial | `ToolManifest` with Ed25519-signed tool definitions. Manifest verification before tool registration. WASM guard module signing (proposed, not yet implemented). | Tool server code integrity is not verified by Chio -- only the manifest is signed. Chio does not govern the agent framework's dependency chain. | Chio scope: tool manifest integrity. |
| LLM06 | **Sensitive Information Disclosure** | Strong | PII guards, column constraints, `QueryResultGuard` redaction, capability scoping (agents can only access authorized tools/servers). Guard evidence records sensitive data detection events. | Only covers governed tool interactions. Agent memory stores, conversation logs, and context windows are outside Chio's governance boundary (see REVIEW-FINDINGS section 1.2). | Chio scope: tool-boundary data leakage prevention. |
| LLM07 | **Insecure Plugin Design** | Strong | This is Chio's core value proposition. Capability tokens scope plugin (tool) access. Constraints enforce conditional access. Guards validate arguments and results. Budget limits prevent runaway consumption. Delegation chains prevent privilege escalation. | Chio governs tool access but not tool implementation quality. A tool server with SQL injection vulnerabilities is still vulnerable even under Chio governance. | Chio scope: tool access governance. Tool implementation security: tool server's responsibility. |
| LLM08 | **Excessive Agency** | Strong | Capability scoping limits what agents can do. Budget enforcement limits how much agents can spend. Time bounds limit how long agents can operate. Delegation attenuation prevents privilege escalation. Model constraints (proposed) limit which models can drive high-risk actions. | Plan-level evaluation (proposed in ARCHITECTURAL-EXTENSIONS.md) would further reduce excessive agency by validating multi-step plans before execution. Currently, evaluation is per-invocation. | Chio scope: per-invocation and session-level agency limits. |
| LLM09 | **Overreliance** | Partial | Chio receipts provide evidence of what tools were called and what was allowed/denied. Compliance certificates summarize session-level behavior. This data supports human oversight and reduces blind trust. | Chio does not detect overreliance patterns (e.g., agent accepting tool results without validation). Overreliance is a human/organizational risk, not a technical control. | Organizational concern. Chio provides evidence for oversight. |
| LLM10 | **Model Theft** | Out of scope | Chio does not protect model weights or inference infrastructure. | N/A | Model-layer attack. |

### 8.3 Summary

- **Strong coverage (3/10):** LLM02 (Insecure Output Handling), LLM07
  (Insecure Plugin Design), LLM08 (Excessive Agency). These are Chio's
  primary design targets.
- **Partial coverage (4/10):** LLM01 (Prompt Injection), LLM05 (Supply
  Chain), LLM06 (Sensitive Information Disclosure), LLM09 (Overreliance).
  Chio provides tool-boundary controls but not full coverage.
- **Out of scope (3/10):** LLM03 (Training Data Poisoning), LLM04 (Model
  DoS), LLM10 (Model Theft). These are model-layer attacks outside Chio's
  governance boundary.

### 8.4 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| OWASP LLM Top 10 formal coverage matrix document | Small | P1 |
| WASM guard module signing (LLM05 supply chain gap) | Medium | P1 (already identified as P1 in REVIEW-FINDINGS) |
| Agent memory governance (LLM06 data leakage gap) | Medium | P2 (already identified as P2 in REVIEW-FINDINGS) |

---

## 9. California SB 1047

### 9.1 What SB 1047 Requires

California SB 1047 (Safe and Secure Innovation for Frontier Artificial
Intelligence Models Act) was introduced in the 2023-2024 legislative session.
As of April 2026, the bill's status and final text may have changed from the
originally introduced version. The analysis below is based on the bill as
publicly discussed through 2024.

Key requirements (as proposed):

1. **Safety testing before deployment.** Developers of covered models (those
   exceeding compute thresholds) must conduct pre-deployment safety testing
   and document results.
2. **Kill switch capability.** Covered models must have the ability to fully
   shut down, including all running copies and derivatives.
3. **Reporting of safety incidents.** Developers must report critical
   capability discoveries and safety incidents.
4. **Third-party audits.** Covered models must undergo third-party safety
   audits.
5. **Reasonable care standard.** Developers must take "reasonable care" to
   prevent critical harms from covered models.

### 9.2 Chio Relevance

SB 1047 primarily targets model developers (labs training frontier models),
not infrastructure providers. Chio operates at the tool-governance layer, not
the model layer. However, Chio contributes to several SB 1047 objectives:

| SB 1047 Requirement | Chio Contribution | Gap |
|---------------------|------------------|-----|
| Safety testing | Chio's test suite verifies governance controls. Guard pipeline tests confirm policy enforcement. | Chio does not test model safety. Model safety testing is the model developer's responsibility. |
| Kill switch | Chio supports capability revocation (immediate, per-agent, per-token). An emergency kill switch (global circuit breaker) is proposed but not yet implemented. | Global kill switch is P1 in REVIEW-FINDINGS. Once implemented, Chio can immediately revoke all agent capabilities across a deployment. |
| Safety incident reporting | Chio receipt store provides a complete audit trail for incident investigation. Evidence export bundles can be generated for incident reports. | Chio does not automate incident detection or reporting. Need automated anomaly detection with configurable alert thresholds. |
| Third-party audits | Chio compliance certificates and evidence export bundles are designed for third-party verification. Merkle inclusion proofs enable selective disclosure without exposing the full receipt log. | No formal audit API for third-party auditors. `chio certify` and evidence export exist but need auditor-facing documentation. |
| Reasonable care | Chio's capability scoping, guard pipeline, budget enforcement, and signed audit trail constitute "reasonable care" for the tool-governance layer. | "Reasonable care" is a legal standard, not a technical one. Chio provides technical evidence that reasonable care was exercised. |

### 9.3 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| SB 1047 mapping document (once bill text is finalized) | Small | P2 (depends on legislative outcome) |
| Global kill switch implementation | Medium | P1 (already identified in REVIEW-FINDINGS) |
| Automated anomaly detection with alert thresholds | Medium | P2 (overlaps with NIST AI RMF Measure work) |

---

## 10. Compliance Evidence Automation

### 10.1 The Problem

Each compliance framework requires specific evidence artifacts. Manually
assembling evidence packages for EU AI Act, SOC 2, HIPAA, PCI DSS, and NIST
AI RMF audits does not scale. Chio already produces the raw evidence (receipts,
checkpoints, compliance certificates, evidence export bundles). The missing
piece is framework-specific packaging.

### 10.2 `chio certify` Command

The `chio certify` CLI command already exists and generates session compliance
certificates. This section proposes extending it to produce framework-specific
compliance evidence packages.

**Proposed subcommands:**

```
chio certify session          # (existing) Generate session compliance certificate
chio certify evidence-export  # (existing) Export evidence bundle
chio certify framework <fw>   # (new) Generate framework-specific compliance package
```

**Supported frameworks:**

```
chio certify framework eu-ai-act     # EU AI Act Article 19 evidence package
chio certify framework pci-dss       # PCI DSS v4.0 evidence package
chio certify framework hipaa         # HIPAA technical safeguard evidence
chio certify framework nist-ai-rmf   # NIST AI RMF evidence package
chio certify framework iso-42001     # ISO 42001 evidence package
chio certify framework soc2          # SOC 2 trust service criteria evidence
chio certify framework all           # Generate all framework packages
```

### 10.3 Evidence Package Structure

Each framework package is a signed directory containing:

```
evidence-package-eu-ai-act-2026-04-15/
  manifest.json              # Signed manifest listing all artifacts
  framework.json             # Framework metadata (name, version, clauses)
  control-mapping.json       # Clause-to-evidence mapping
  receipts/
    summary.json             # Receipt statistics (counts, denial rates, etc.)
    sample-receipts.json     # Representative receipt samples (configurable N)
  checkpoints/
    checkpoint-summary.json  # Checkpoint count, coverage, integrity status
    latest-checkpoint.json   # Most recent signed checkpoint
  certificates/
    session-certs/           # Session compliance certificates for the period
  retention/
    retention-config.json    # Active retention configuration
    archive-summary.json     # Archive status and verifiability
  guards/
    guard-summary.json       # Active guards, evaluation counts, denial rates
    guard-evidence-sample.json  # Sample guard evidence records
  signature.json             # Ed25519 signature over manifest.json
```

### 10.4 `SignedExportEnvelope` Integration

Framework evidence packages use the existing `SignedExportEnvelope` format
for the outer wrapper:

```rust
/// A framework-specific compliance evidence package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceEvidencePackage {
    /// Framework identifier (e.g., "eu-ai-act", "pci-dss-v4").
    pub framework: String,
    /// Framework version.
    pub framework_version: String,
    /// Time range covered by this evidence package.
    pub coverage_period: TimeRange,
    /// Control mapping: framework clause to Chio evidence.
    pub control_mapping: Vec<ControlEvidenceMapping>,
    /// Summary statistics.
    pub summary: EvidenceSummary,
    /// Chio kernel version that produced this evidence.
    pub kernel_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidenceMapping {
    /// Framework clause identifier (e.g., "Article 19(1)", "Req 10.2.1").
    pub clause: String,
    /// Clause description.
    pub description: String,
    /// Compliance status for this clause.
    pub status: ControlStatus,
    /// Evidence artifacts supporting this clause.
    pub evidence: Vec<EvidenceReference>,
    /// Notes or caveats.
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    /// Chio fully satisfies this control.
    Satisfied,
    /// Chio partially satisfies this control.
    PartiallySatisfied,
    /// Chio does not satisfy this control (customer responsibility).
    CustomerResponsibility,
    /// This control is not applicable to Chio.
    NotApplicable,
}
```

### 10.5 Continuous Compliance Monitoring

Beyond point-in-time evidence packages, Chio should support continuous
compliance monitoring:

1. **Compliance drift detection.** Compare current receipt patterns against
   framework requirements. Alert when coverage degrades (e.g., a guard is
   disabled that was required for a compliance control).
2. **Evidence freshness tracking.** Track when evidence was last generated
   for each framework. Alert when evidence is stale (e.g., > 30 days since
   last EU AI Act evidence package).
3. **Control gap detection.** When a new guard is deployed or a policy
   changes, re-evaluate control mappings and flag new gaps.

### 10.6 Required Work

| Work Item | Effort | Priority |
|-----------|--------|----------|
| `chio certify framework` subcommand scaffolding | Medium | P2 |
| EU AI Act evidence package format (first framework) | Medium | P2 |
| Framework-agnostic `ComplianceEvidencePackage` types in `chio-core-types` | Small | P2 |
| Additional framework packages (PCI DSS, HIPAA, SOC 2, NIST AI RMF, ISO 42001) | Medium each | P3 |
| Continuous compliance monitoring daemon | Large | P3 |

---

## 11. Implementation Priority Summary

### 11.1 P1 -- Required for Enterprise Adoption

These items unblock regulated-industry adoption and are prerequisites for
framework-specific mapping documents.

| Work Item | Section | Effort | Dependencies |
|-----------|---------|--------|--------------|
| `SigningBackend` trait abstraction | 2.5 | Small | None |
| `aws-lc-rs` FIPS backend | 2.3 | Medium | `SigningBackend` trait |
| Guard evidence redaction (configurable) | 3.3, 7.5 | Medium | None |
| `min_tls_version` configuration | 3.3 | Small | None |
| NIST AI RMF mapping document | 4.4 | Small | None |
| ISO 42001 mapping document | 5.4 | Medium | None |
| SOC 2 mapping document | 6.3 | Medium | None |
| HIPAA technical safeguard mapping document | 7.5 | Medium | None |
| OWASP LLM Top 10 coverage matrix document | 8.4 | Small | None |
| PCI DSS v4.0 mapping document | 3.3 | Small | None |
| Global kill switch | 9.3 | Medium | None (already P1 in REVIEW-FINDINGS) |

### 11.2 P2 -- Strengthens Compliance Posture

These items close gaps identified in the mappings and add automation.

| Work Item | Section | Effort | Dependencies |
|-----------|---------|--------|--------------|
| P-256/P-384 algorithm support | 2.2 | Medium | `SigningBackend` trait |
| Vault Transit + AWS KMS backends | 2.4 | Medium | `SigningBackend` trait |
| `chio-risk` crate (basic scoring) | 4.3 | Medium | None |
| Risk score on compliance certificates | 4.3 | Small | `chio-risk` crate |
| SIEM export adapter | 3.3 | Medium | None |
| Break-glass capability workflow | 7.5 | Small | None |
| Idle-timeout revocation trigger | 7.5 | Small | None |
| `chio certify framework` command | 10.6 | Medium | None |
| SB 1047 mapping document | 9.3 | Small | Legislative outcome |
| Anomaly detection with alert thresholds | 9.3 | Medium | `chio-risk` crate |

### 11.3 P3 -- Full Compliance Automation

| Work Item | Section | Effort | Dependencies |
|-----------|---------|--------|--------------|
| Framework-specific evidence packages (all) | 10.6 | Large | `chio certify framework` |
| Continuous compliance monitoring | 10.5 | Large | `chio-risk`, evidence packages |
| Risk-to-policy feedback loop | 4.4 | Medium | `chio-risk` |
| ISO 42001 Statement of Applicability template | 5.4 | Small | ISO 42001 mapping |

### 11.4 Sequencing

```
Phase 1 (immediate):
  SigningBackend trait --> aws-lc-rs backend
  Guard evidence redaction
  min_tls_version config
  Global kill switch (parallel, already planned)

Phase 2 (mapping documents, parallel):
  NIST AI RMF mapping doc
  ISO 42001 mapping doc
  SOC 2 mapping doc
  HIPAA technical safeguard mapping doc
  OWASP LLM Top 10 matrix doc
  PCI DSS v4.0 mapping doc

Phase 3 (scoring and automation):
  chio-risk crate
  SIEM export adapter
  chio certify framework command
  P-256/P-384 algorithm support
  HSM backends (Vault, AWS KMS)

Phase 4 (continuous compliance):
  Continuous monitoring daemon
  Evidence freshness tracking
  Compliance drift detection
  Risk-to-policy feedback loop
```

---

## 12. Success Criteria

This roadmap is complete when:

1. Chio ships with a FIPS-validated cryptographic backend behind a feature
   flag, and HSM integration for key storage in production deployments.
2. Formal mapping documents exist for all nine frameworks listed in section
   1.3, each with the same structure as the existing EU AI Act and Colorado
   SB 24-205 mapping documents.
3. `chio certify framework <fw>` generates signed, framework-specific evidence
   packages for at least EU AI Act, SOC 2, and HIPAA.
4. `chio-risk` produces per-session risk scores that close the NIST AI RMF
   Measure function gap.
5. An enterprise customer can produce a compliance evidence package for any
   supported framework without manual evidence assembly.
