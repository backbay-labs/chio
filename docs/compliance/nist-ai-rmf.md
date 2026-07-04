---
date: 2026-04-16
framework: NIST AI Risk Management Framework 1.0 (January 2023)
maintainer: Chio Protocol Team
---

# NIST AI RMF Compliance Mapping

## Metadata

| Field | Value |
|-------|-------|
| Framework | NIST AI Risk Management Framework (AI RMF 1.0) |
| Published | January 2023 (NIST AI 100-1) |
| Scope | Govern, Map, Measure, Manage functions and their subcategories |
| Chio Profile | Current v1-only pre-release profile |
| Document Date | 2026-04-16 |

---

## Executive Summary

NIST AI RMF 1.0 is a voluntary framework organized around four core functions: Govern (organizational culture and policies), Map (context and risk identification), Measure (risk analysis and tracking), and Manage (risk prioritization and response). The framework is process-oriented and requires both organizational and technical controls. Chio supplies technical controls for the tool-invocation boundary of an agent system and produces signed, tamper-evident evidence that can be referenced by an organization's AI risk program.

Chio's strongest NIST AI RMF contribution is to Map and Manage. Capability tokens, scoped grants, delegation chains, the guard pipeline, budgets, and per-invocation signed receipts map directly to context identification, third-party management, and risk-response controls. Chio also supplies the raw data a Measure function needs (denial rates, budget velocity, guard-evidence frequency, DPoP attribution), though the risk-scoring layer itself is not yet shipped and is tracked separately as the proposed `chio-risk` crate. Govern subcategories are largely organizational and sit outside Chio's boundary; Chio contributes where policy-as-code, executable policy hashes in receipts, and workload identity touch organizational artifacts.

This mapping covers every Govern/Map/Measure/Manage subcategory in AI RMF 1.0. Subcategories that depend on organizational processes (workforce composition, leadership commitment, communications to stakeholders) are marked customer-responsibility and do not claim Chio coverage.

---

## Coverage Legend

| Level | Meaning |
|-------|---------|
| strong | Chio's shipped controls directly implement the subcategory at the tool-governance layer |
| partial | Chio provides relevant evidence or partial enforcement; additional organizational work is required |
| customer-responsibility | The subcategory is organizational or process-level; Chio does not implement it |
| out-of-scope | The subcategory addresses concerns outside Chio's governance boundary (e.g., model training, workforce) |

---

## Function Mapping: GOVERN

| Subcategory | Requirement Summary | Chio Controls | Coverage | Gaps | Customer Responsibility |
|-------------|---------------------|--------------|----------|------|-------------------------|
| GV-1.1 | Legal/regulatory requirements involving AI are understood, managed, documented | Capability tokens carry `issuer`, `not_before`, `not_after`; policy hash in every receipt; compliance mappings at `docs/compliance/` | partial | Chio does not catalog applicable laws; mapping documents are per-framework | Maintain register of applicable regulations |
| GV-1.2 | Characteristics of trustworthy AI integrated into policies | Guard pipeline in `crates/kernel/chio-kernel/src/kernel/mod.rs` enforces fail-closed defaults; `chio-policy` crate defines policy artifacts | partial | Trustworthiness attributes are not labeled inside policy artifacts | Define trustworthiness characteristics for organization |
| GV-1.3 | Processes defined to determine risk tolerance | `VelocityConfig` (`crates/guards/chio-guards/src/velocity.rs`), `max_total_cost` / `max_cost_per_invocation` in `crates/kernel/chio-kernel/src/budget_store.rs` encode tolerance | partial | Tolerance is expressed as config, not derived from a risk process | Risk tolerance policy and review cycle |
| GV-1.4 | Risk management process is established | `chio-underwriting` crate produces 4-tier agent risk classification; receipt store feeds risk review | partial | Process documentation is per-deployment | Document AI risk management process |
| GV-1.5 | Ongoing monitoring and review mechanisms are in place | Receipt store (`crates/kernel/chio-kernel/src/receipt_store.rs`), checkpoint monitor, `chio trust serve` dashboard | strong | None at tool-governance layer | Organizational review cadence |
| GV-1.6 | Mechanisms to inventory AI systems | `ToolManifest` per tool server (`crates/platform/chio-manifest`), `WorkloadIdentity` metadata | partial | No cross-deployment AI inventory | Maintain AI system inventory |
| GV-1.7 | Decommissioning processes defined | Capability revocation via `crates/kernel/chio-kernel/src/revocation_runtime.rs` and `revocation_store.rs`; grant expiry | strong | None | Map decommissioning to organizational change control |
| GV-2.1 | Roles and responsibilities for AI risk are documented | `CapabilityToken.issuer`, delegation chain (`crates/core/chio-core-types/src/capability`) attribute authority | partial | Human roles live outside Chio | RACI for AI risk roles |
| GV-2.2 | Workforce equipped with AI knowledge | Out of scope | customer-responsibility | N/A | Training program |
| GV-2.3 | Executive leadership accountable for AI risk | Out of scope | customer-responsibility | N/A | Executive charter |
| GV-3.1 | Decision-making related to AI risks is inclusive | Out of scope | customer-responsibility | N/A | Stakeholder process |
| GV-3.2 | Policies on workforce diversity are applied | Out of scope | customer-responsibility | N/A | HR policy |
| GV-4.1 | Organizational risk culture supports AI risk management | Fail-closed evaluation throughout `crates/kernel/chio-kernel/src/kernel/`; deny receipts on error paths | partial | Culture is organizational | Culture program |
| GV-4.2 | Risks and benefits of AI are communicated | Compliance certificates (`crates/products/chio-cli/src/cert.rs`), evidence export (`crates/products/chio-cli`) | partial | Communication templates are per-org | Stakeholder communication plan |
| GV-4.3 | Information sharing across stakeholders is practiced | Signed evidence bundles via `SignedExportEnvelope` support portable audit exchange | partial | No built-in sharing workflow | Procedures for sharing evidence |
| GV-5.1 | Policies for addressing AI risk exist | `chio-policy` crate, guard configurations, `chio.yaml` | strong | None at enforcement layer | Policy authoring process |
| GV-5.2 | Mechanisms for communicating risks | `chio-siem` receipt streaming (`crates/observability/chio-siem/src/exporter.rs`) | partial | Delivery to stakeholders is external | Receiving-end SIEM configuration |
| GV-6.1 | Policies to address AI risks of third-party AI | Capability scoping (`ToolGrant.constraints`) restricts which third-party tools are reachable; delegation attenuation | strong | Chio does not audit third-party providers | Third-party risk due diligence |
| GV-6.2 | Contingency processes for failure of third parties | Circuit-breaker patterns live in the async guard runtime; Chio supports revocation for scope tightening | partial | Chio does not automate provider failover | Runbooks for third-party outages |

---

## Function Mapping: MAP

| Subcategory | Requirement Summary | Chio Controls | Coverage | Gaps | Customer Responsibility |
|-------------|---------------------|--------------|----------|------|-------------------------|
| MP-1.1 | Intended purposes and context are documented | `ToolManifest` tool descriptions, `WorkloadIdentity` metadata on capability tokens | partial | Agent purpose text is free-form | Purpose definition per deployment |
| MP-1.2 | Inter-disciplinary AI team established | Out of scope | customer-responsibility | N/A | Team composition |
| MP-1.3 | Mission and goals for AI are understood | Out of scope | customer-responsibility | N/A | Mission definition |
| MP-1.4 | Organization's business value aligned | Out of scope | customer-responsibility | N/A | Value alignment |
| MP-1.5 | Organizational risk tolerances determined | `VelocityConfig`, budget caps, `GovernedAutonomyTier` on capability tokens | partial | Tolerance selection is manual | Risk-tolerance decision process |
| MP-1.6 | System requirements are elicited and documented | `ToolManifest` parameter schemas (`crates/platform/chio-manifest/src/lib.rs`) | partial | Requirements docs are external | Requirements documentation |
| MP-2.1 | Task and method are identified and defined | `ToolDefinition` within `ToolManifest` | strong | None | Task ownership |
| MP-2.2 | Knowledge limits of AI system documented | Tool descriptions may express limits; `chio-underwriting` risk reasons encode known-risk patterns | partial | Limits text not machine-enforced | Limits statement for each tool |
| MP-2.3 | AI capabilities, targeted usage, assumptions documented | Tool manifests, agent passports (`docs/AGENT_PASSPORT_GUIDE.md`) | partial | Assumptions are free-text | Document assumptions |
| MP-3.1 | Benefits of intended system use are examined | Out of scope | customer-responsibility | N/A | Benefit analysis |
| MP-3.2 | Potential costs are examined | `FinancialReceiptMetadata` on every receipt; budget enforcement in `crates/kernel/chio-kernel/src/budget_store.rs` | strong | Non-monetary cost types not modeled | Broader cost modeling |
| MP-3.3 | Scientific integrity and TEVV considerations documented | Out of scope | customer-responsibility | N/A | TEVV plan |
| MP-3.4 | Processes for organization's human-AI configurations established | DPoP binds agent keypair to every invocation; capability subject identifies responsible agent | partial | Human-to-agent attribution chain is deployment-specific | Define human-in-loop structure |
| MP-3.5 | Processes for human oversight are defined | DPoP (`crates/kernel/chio-kernel/src/dpop.rs`), `GovernedApprovalToken` (`crates/kernel/chio-kernel/src/kernel/mod.rs`) for step-up review | strong | Oversight workflow is external | Oversight SOPs |
| MP-4.1 | Approaches for mapping AI risks are identified | Guard pipeline produces structured verdicts; receipt analytics in `crates/kernel/chio-kernel/src/receipt_analytics.rs` | partial | No standard risk taxonomy output | Risk taxonomy selection |
| MP-4.2 | Internal risk controls are identified and documented | All guards in `crates/guards/chio-guards/src/` (velocity, egress_allowlist, secret_leak, path_allowlist, etc.) | strong | None at tool layer | Document controls in risk register |
| MP-5.1 | Likelihood and magnitude of each impact are identified | Raw data is available (denial rates, guard triggers); scoring is not shipped | partial | No risk scoring module (proposed `chio-risk` crate) | Impact assessment |
| MP-5.2 | Practices and personnel for TEVV are defined | Out of scope | customer-responsibility | N/A | TEVV personnel |

---

## Function Mapping: MEASURE

| Subcategory | Requirement Summary | Chio Controls | Coverage | Gaps | Customer Responsibility |
|-------------|---------------------|--------------|----------|------|-------------------------|
| MS-1.1 | Approaches and metrics for measurement are selected | Receipt query API (`crates/kernel/chio-kernel/src/receipt_query.rs`) exposes counts, denial rates, cost aggregates | partial | No framework-level metric definitions | Metric selection |
| MS-1.2 | Appropriateness of metrics and effectiveness are assessed | Receipt analytics module returns aggregates | partial | No metric-effectiveness review | Periodic metric review |
| MS-1.3 | Internal experts and users consulted | Out of scope | customer-responsibility | N/A | Expert consultation |
| MS-2.1 | Test sets and metrics used are documented | `cargo test --workspace` covers protocol behavior; guard integration tests in `crates/kernel/chio-kernel/tests/` | partial | Chio tests are protocol-level, not AI behavior | AI test-set management |
| MS-2.2 | Evaluations conducted for representativeness | Out of scope | customer-responsibility | N/A | Representativeness studies |
| MS-2.3 | Performance metrics are tracked | Receipt store records timing, outcome, cost | partial | Latency percentiles not reported out of the box | Observability stack |
| MS-2.4 | Measurement results are documented | Evidence export (`crates/products/chio-cli`) and compliance certificates | strong | None | Reporting cadence |
| MS-2.5 | Robustness, reliability, resilience are evaluated | Fail-closed pipeline; checkpoint integrity (`crates/kernel/chio-kernel/src/checkpoint.rs`) | partial | Model-level robustness is out of scope | Model evaluations |
| MS-2.6 | Safety risks are evaluated | Content safety guards: jailbreak/prompt-injection detectors in the application-layer guard suite; `secret_leak`, `egress_allowlist`, `forbidden_path` in `crates/guards/chio-guards/src/` | strong | Model-inference safety out of scope | Model safety testing |
| MS-2.7 | Security and resilience are evaluated | Signed receipts, Merkle checkpoints, DPoP, capability revocation | strong | Penetration testing is not automated | Regular pen-testing |
| MS-2.8 | Risks of privacy violations are examined | PII-oriented `QueryResultGuard` / `response_sanitization.rs`, column constraints in data guards | partial | Not all privacy patterns covered | Privacy impact assessment |
| MS-2.9 | Risks of fairness violations are examined | Out of scope | customer-responsibility | N/A | Fairness evaluations |
| MS-2.10 | Environmental impact is assessed | Out of scope | customer-responsibility | N/A | Carbon accounting |
| MS-2.11 | Fairness and bias are evaluated | Out of scope | customer-responsibility | N/A | Bias evaluations |
| MS-2.12 | Environmental impact mitigations are tested | Out of scope | customer-responsibility | N/A | Mitigation strategy |
| MS-2.13 | Effectiveness of existing mitigations is assessed | Guard evidence recorded in receipts; denial counts per guard | partial | No automated effectiveness review | Mitigation review |
| MS-3.1 | Risks are measured and tracked | Receipt store with time-series queries | partial | Risk scores not computed (proposed `chio-risk`) | Risk register updates |
| MS-3.2 | Risks are tracked at scale | Merkle checkpoints allow scalable tamper-evident aggregation; receipt query pagination | strong | None | Scaled operations |
| MS-3.3 | Feedback about efficacy of measurement is gathered | Out of scope | customer-responsibility | N/A | Measurement review |
| MS-4.1 | Approaches for identifying AI risks are documented | `chio-underwriting` 4-tier reasoning; guard catalog | partial | Reasons are code, not policy docs | Document approaches |
| MS-4.2 | AI risks from deployment environments are evaluated | `internal_network.rs`, `egress_allowlist.rs` guards limit environment reach | partial | Environmental telemetry needs external integration | Deployment risk review |
| MS-4.3 | Feedback is integrated to improve AI risk management | Manual policy updates; no automated feedback loop | partial | No automated loop (proposed as part of `chio-risk` follow-on) | Feedback-to-policy process |

---

## Function Mapping: MANAGE

| Subcategory | Requirement Summary | Chio Controls | Coverage | Gaps | Customer Responsibility |
|-------------|---------------------|--------------|----------|------|-------------------------|
| MG-1.1 | Purpose and impacts are prioritized | `chio-underwriting` tiering; `GovernedAutonomyTier` on capability tokens | partial | Tiering is input, not output, of a prioritization | Priority setting |
| MG-1.2 | Treatment of documented risks is prioritized | Guard pipeline produces allow/deny verdicts; deny receipts are durable | partial | No automatic prioritization order | Treatment decisions |
| MG-1.3 | Responses are developed, planned, documented | Revocation runtime, scope reduction, grant expiry | partial | Runbooks are external | Response playbooks |
| MG-1.4 | Residual risks are documented | Not tracked | customer-responsibility | No residual-risk register in Chio | Residual risk register |
| MG-2.1 | Resources are allocated to risks | Budget enforcement (`chio-metering`) aligns resource spend with policy | strong | Non-monetary resources not modeled | Resource planning |
| MG-2.2 | Mechanisms to supersede, disengage, deactivate AI | Capability revocation, token expiry, delegation revocation (`crates/kernel/chio-kernel/src/revocation_runtime.rs`) | strong | Global kill-switch is proposed but not yet shipped | Deactivation procedures |
| MG-2.3 | Procedures to respond to risks | Guard pipeline deny; step-up approval via `GovernedApprovalToken` | strong | External ticketing integration is per-deployment | Incident procedures |
| MG-2.4 | Post-use processes and procedures are applied | Archival in `crates/platform/chio-store-sqlite/src/receipt_store/evidence_retention.rs` retains signed evidence after deactivation | strong | None | Post-use review |
| MG-3.1 | Resources are allocated to identified AI risks | `FinancialReceiptMetadata` tracks monetary allocation per risk | partial | Non-monetary allocation external | Resource allocation |
| MG-3.2 | Pre-trained models are monitored | Out of scope | out-of-scope | N/A | Model monitoring |
| MG-4.1 | Post-deployment AI system monitoring is applied | Receipt stream, checkpoint integrity checks | strong | None at tool layer | Monitoring program |
| MG-4.2 | Actionable feedback about AI risks is captured | Guard evidence in receipts, SIEM event stream | partial | No automated corrective action | Feedback intake process |
| MG-4.3 | AI risks and benefits are monitored | Risks monitored via receipts; benefits not tracked | partial | Benefits tracking out of scope | Benefit tracking |

---

## Gaps Summary

Items flagged as gaps or customer-responsibility that warrant reviewer attention:

1. Measure function is the weakest. Chio has the raw data but no risk scoring module. The proposed `chio-risk` crate (tracked in `docs/protocols/COMPLIANCE-ROADMAP.md` section 4.3) would close MP-5.1, MS-3.1, MS-4.3.
2. Global kill-switch (MG-2.2) is referenced in the roadmap but not yet shipped.
3. Residual-risk tracking (MG-1.4) has no structured representation in Chio artifacts.
4. Fairness, bias, environmental impact (MS-2.9, MS-2.10, MS-2.11, MS-2.12) are out of scope at the tool-governance layer.
5. Govern subcategories concerning workforce and leadership (GV-2.2, GV-2.3, GV-3.1, GV-3.2) are customer-responsibility and not implementable in code.

---

## Cross-References

- Capability tokens and delegation: `crates/core/chio-core-types/src/capability`
- Receipt signing and verification: `crates/core/chio-core-types`, `crates/kernel/chio-kernel/src/receipt_support`
- Guard pipeline: `crates/kernel/chio-kernel/src/kernel/mod.rs`, `crates/guards/chio-guards/src/pipeline.rs`
- Velocity and spend buckets: `crates/guards/chio-guards/src/velocity.rs`
- Budget store and metering: `crates/kernel/chio-kernel/src/budget_store.rs`, `crates/economy/chio-metering/src/budget.rs`
- DPoP proof-of-possession: `crates/kernel/chio-kernel/src/dpop.rs`
- Revocation runtime: `crates/kernel/chio-kernel/src/revocation_runtime.rs`, `crates/kernel/chio-kernel/src/revocation_store.rs`
- Checkpoints and inclusion proofs: `crates/kernel/chio-kernel/src/checkpoint.rs`
- Evidence export: `crates/kernel/chio-kernel/src/evidence_export.rs`, `crates/products/chio-cli`
- Session compliance certificate: `crates/products/chio-cli/src/cert.rs`, `docs/protocols/SESSION-COMPLIANCE-CERTIFICATE.md`
- SIEM export: `crates/observability/chio-siem/src/exporter.rs`
- Agent passport: `docs/AGENT_PASSPORT_GUIDE.md`
- Manifest signing: `crates/platform/chio-manifest/src/lib.rs`
- Underwriting risk tiering: `crates/economy/chio-underwriting/`
