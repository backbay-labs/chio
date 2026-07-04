---
date: 2026-04-16
framework: OWASP Top 10 for Large Language Model Applications 2025
maintainer: Chio Protocol Team
---

# OWASP LLM Top 10 (2025) Coverage Matrix

## Metadata

| Field | Value |
|-------|-------|
| Framework | OWASP Top 10 for Large Language Model Applications |
| Edition | 2025 |
| Scope | LLM01 through LLM10 |
| Chio Profile | Current v1-only pre-release profile |
| Document Date | 2026-04-16 |

---

## Executive Summary

The OWASP Top 10 for LLM Applications (2025 edition) identifies the ten most critical security risks for LLM-based software. Chio governs the tool-invocation boundary of an agent system. That boundary is where most "LLM does something in the real world" risks concentrate: tool selection, data egress, excessive authority, supply-chain integrity, and audit trails. Chio has strong coverage for the risks that live at that boundary (LLM02 output handling, LLM06 excessive agency, LLM08 vector and embedding weaknesses where retrieval data is fetched via tools, and several aspects of LLM05 supply chain and LLM07 system prompt leakage when prompts route through tool calls).

Risks that live entirely inside the model (training-data poisoning, model theft, inference-compute denial of service) are out of scope for a tool-governance protocol. Chio may provide indirect mitigations; for example, budget enforcement caps the monetary blast radius of an agent that is being driven to exhaust expensive inference calls, but it does not protect model weights or the inference plane itself.

The table below maps each 2025 risk to Chio controls with a coverage level and explicit gap notes. The 2025 edition expanded some categories (vector and embedding weaknesses, misinformation, and unbounded consumption) and renamed others; the mapping below uses the 2025 titles. If the reader is looking for the v1.1 (2023) list, the closest equivalents are called out in each row.

---

## Coverage Legend

| Level | Meaning |
|-------|---------|
| strong | Chio directly mitigates this risk at the tool-governance layer |
| partial | Chio provides meaningful tool-boundary controls but does not fully cover the risk |
| out-of-scope | The risk is inside the model or infrastructure outside Chio's boundary |

---

## Risk Mapping

| Risk | Title | Chio Controls | Coverage | Gaps | Customer Responsibility |
|------|-------|--------------|----------|------|-------------------------|
| **LLM01** | Prompt Injection | Content safety guards: jailbreak and prompt-injection detectors shipped as application-layer guards; `response_sanitization.rs` for output guarding; every triggered detection is recorded in `ChioReceipt.guard_evidence` via the pipeline in `crates/kernel/chio-kernel/src/kernel/mod.rs` | partial | Chio guards inspect tool-call arguments and results, not the full model context. Injection that alters the agent's reasoning without changing tool-call parameters is not observable at the tool boundary. | Model-layer prompt hardening; system-prompt design |
| **LLM02** | Sensitive Information Disclosure | Pre- and post-invocation guards: `secret_leak.rs`, `response_sanitization.rs`, data-flow guard `data_flow.rs`, column-level constraints on `SqlQueryGuard` and similar. `QueryResultGuard` can block or redact results. Capability scoping limits which tool servers an agent can touch. Every block is recorded in the signed receipt. | strong | Only covers governed tool interactions. Conversation memory, embedding stores, and prompt logs outside a tool boundary are not intercepted. | Memory store governance |
| **LLM03** | Supply Chain | `ToolManifest` with Ed25519-signed `ToolDefinition`; manifest verification before tool registration (`crates/platform/chio-manifest/src/lib.rs`); `patch_integrity.rs` guard for patch content; workload identity attestation (`crates/core/chio-core-types/src/runtime_attestation.rs`); WASM guard module signing tracked in roadmap | partial | Manifest signatures cover the tool definition, not the server binary. Agent-framework and model-weight supply chains are not audited by Chio. | SBOM for tool servers; model-weight attestation |
| **LLM04** | Data and Model Poisoning | Out of scope at the protocol layer. Closest proxy: data-layer guards (SQL/warehouse/vector) restrict what data a deployed agent can write back into a tool-accessible store. | out-of-scope | Chio does not observe training or fine-tuning. | Training-data curation and provenance |
| **LLM05** | Improper Output Handling | `response_sanitization.rs`, `QueryResultGuard` post-invocation guard, structured output schemas enforced by `request_matching.rs`. Post-invocation verdict `Block` stops unsafe output from reaching the agent or downstream tool. | strong | Chio inspects outputs from governed tool servers. Direct LLM text output (no tool call) is outside the boundary. | Output escaping in downstream consumers |
| **LLM06** | Excessive Agency | This is Chio's core value proposition. Capability tokens (`crates/core/chio-core-types/src/capability`) constrain what tools an agent may call; `ToolGrant.constraints` limit arguments; delegation chains attenuate monotonically; `VelocityGuard` (`crates/guards/chio-guards/src/velocity.rs`) caps rate; `max_cost_per_invocation` and `max_total_cost` in `crates/kernel/chio-kernel/src/budget_store.rs` cap spend; `GovernedAutonomyTier` and `GovernedApprovalToken` (`crates/kernel/chio-kernel/src/kernel/mod.rs`) enforce step-up review for sensitive tiers. | strong | Plan-level evaluation (validating multi-step plans before execution) is not yet shipped; evaluation is per-invocation. | Policy authoring to express desired bounds |
| **LLM07** | System Prompt Leakage | Where system prompts flow through tool calls (e.g., LLM gateway wrapped as a tool), `response_sanitization.rs` and `secret_leak.rs` can match on known prompt content. Capability scoping prevents agents from calling introspection tools that would reveal prompts. | partial | System prompt is not typically visible to Chio because it lives inside the model-invocation layer. | Prompt hygiene; use of dedicated prompt stores |
| **LLM08** | Vector and Embedding Weaknesses | Vector-DB data-layer guard (see `crates/guards/chio-guards/src/` data guards) restricts which embeddings an agent may read or write; `egress_allowlist.rs` limits retrieval endpoints; column constraints can deny sensitive fields before vectorization tools see them. Receipts log every retrieval. | partial | Chio does not validate embedding provenance or detect poisoned retrieval corpora. | Embedding-corpus curation |
| **LLM09** | Misinformation | Chio records what was returned (post-invocation guard evidence) and who it went to (DPoP attribution), producing audit evidence that supports correction workflows. | partial | Chio does not evaluate factuality. Hallucination detection is a model-layer concern. | Factuality evaluation |
| **LLM10** | Unbounded Consumption | Budget enforcement (`crates/kernel/chio-kernel/src/budget_store.rs`, `crates/economy/chio-metering/src/budget.rs`) caps monetary spend atomically per invocation and per grant; velocity guard (`crates/guards/chio-guards/src/velocity.rs`) caps invocation rate and spend rate; revocation is immediate (`crates/kernel/chio-kernel/src/revocation_runtime.rs`); grant expiry bounds time. | strong | Inference compute DoS (driving a model to exhaustion without paid tool calls) requires model-infra-layer defenses. | Inference-layer rate limits |

---

## Coverage Summary

| Coverage | Risks |
|----------|-------|
| strong | LLM02 Sensitive Information Disclosure, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM10 Unbounded Consumption |
| partial | LLM01 Prompt Injection, LLM03 Supply Chain, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation |
| out-of-scope | LLM04 Data and Model Poisoning |

Chio provides strong coverage for four of the ten risks, partial coverage for five, and is out of scope for one. The partial rows reflect the fundamental scope split: Chio governs the tool boundary, so risks whose root cause lives inside the model (prompt-injection reasoning effects, hallucination, training-data poisoning) need model-layer controls that Chio complements rather than replaces.

---

## Gaps Summary

Items that warrant explicit tracking:

1. **LLM01 Prompt Injection.** Tool-argument detection catches the externally observable symptoms of prompt injection, but Chio does not see the full prompt. Customers should pair Chio guards with a model-layer prompt-safety product. The content-safety guards referenced here are application-layer guards, not the core protocol crate set.
2. **LLM03 Supply Chain.** Manifest signing covers the published `ToolDefinition`. Tool-server binary integrity and agent-framework supply chain must be addressed by the deployer (SBOM attestation, signed container images, WASM guard module signing tracked in the roadmap).
3. **LLM06 Excessive Agency: plan-level evaluation.** Only per-invocation evaluation is currently shipped. A plan-level evaluator is future work tracked in `docs/protocols/ARCHITECTURAL-EXTENSIONS.md`.
4. **LLM07 System Prompt Leakage.** Chio does not manage system prompts unless they traverse a tool call.
5. **LLM08 Vector and Embedding Weaknesses.** Chio's data-layer guards gate retrieval calls but do not assess embedding-corpus integrity. Corpus curation is customer-responsibility.
6. **LLM09 Misinformation.** Chio provides evidence to support correction workflows but does not evaluate factual correctness.
7. **LLM10 Unbounded Consumption.** The monetary/rate dimension is covered. Inference-plane DoS requires model-infra controls outside Chio.

Customer-responsibility items that implementers must not assume Chio provides:

- Model-layer prompt hardening and system-prompt design
- Training-data curation and provenance
- Embedding-corpus integrity
- Factuality evaluation
- Inference-compute rate limits

---

## Cross-References

- Capability tokens, grants, delegation, attenuation: `crates/core/chio-core-types/src/capability`
- Receipt structure, signing, guard evidence: `crates/core/chio-core-types`, `crates/kernel/chio-kernel/src/receipt_support`
- Guard pipeline integration: `crates/kernel/chio-kernel/src/kernel/mod.rs`, `crates/guards/chio-guards/src/pipeline.rs`
- Velocity and spend buckets: `crates/guards/chio-guards/src/velocity.rs`, `crates/guards/chio-guards/src/agent_velocity.rs`
- Egress and path guards: `crates/guards/chio-guards/src/egress_allowlist.rs`, `crates/guards/chio-guards/src/path_allowlist.rs`, `crates/guards/chio-guards/src/forbidden_path.rs`, `crates/guards/chio-guards/src/path_normalization.rs`, `crates/guards/chio-guards/src/internal_network.rs`
- Secret and response sanitization: `crates/guards/chio-guards/src/secret_leak.rs`, `crates/guards/chio-guards/src/response_sanitization.rs`
- Patch integrity: `crates/guards/chio-guards/src/patch_integrity.rs`
- Behavioral sequence and data-flow guards: `crates/guards/chio-guards/src/behavioral_sequence.rs`, `crates/guards/chio-guards/src/data_flow.rs`
- Post-invocation pipeline: `crates/guards/chio-guards/src/post_invocation.rs`
- Budget and metering: `crates/kernel/chio-kernel/src/budget_store.rs`, `crates/economy/chio-metering/src/budget.rs`
- Revocation: `crates/kernel/chio-kernel/src/revocation_runtime.rs`, `crates/kernel/chio-kernel/src/revocation_store.rs`
- DPoP proof-of-possession: `crates/kernel/chio-kernel/src/dpop.rs`
- Manifest signing: `crates/platform/chio-manifest/src/lib.rs`
- Runtime attestation: `crates/core/chio-core-types/src/runtime_attestation.rs`
- Governed autonomy and approval tokens: `crates/kernel/chio-kernel/src/kernel/mod.rs`
- Policy artifacts and compiler: `crates/guards/chio-policy/`
- Architectural extensions (plan-level evaluation, model constraints): `docs/protocols/ARCHITECTURAL-EXTENSIONS.md`
