#!/usr/bin/env python3
"""One-shot generator for CLOSE-BAR-TRACKER.md and close-bar-snapshot.json.

Run from the repository root. The output is committed; this generator stays
in-tree as the source of truth so audit findings can be re-projected if the
brainstorm catalog changes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

# (id, title, bucket, wired_runtime, neg_test, theorem, wave, notes)
Row = Tuple[str, str, str, str, str, str, str, str]


# ---- Brainstorm catalogue ---------------------------------------------------
DX = [
    ("DX-1", "chio init interactive shape picker + golden-path templates"),
    ("DX-2", "chio explain <receipt-id> deep narrator"),
    ("DX-3", "Receipt-chain explorer (web)"),
    ("DX-4", "In-process kernel for SDK tests + golden-receipt assertions"),
    ("DX-5", "Polish vscode-chio + zed-chio extensions to publishable quality"),
    ("DX-6", "chio doctor upgrade with repair suggestions"),
    ("DX-7", "Mock kernel + fixture-replay harness with hot-reload (chio dev)"),
    ("DX-8", "SDK idiomatic-pass: Python + TypeScript first"),
    ("DX-9", "Error catalog with stable codes + repair hints"),
    ("DX-10", "chio diff for policies, manifests, trust roots"),
    ("DX-11", "End-to-end demo apps that someone could actually deploy"),
    ("DX-12", "chio trace <session> + OTel-receipts bridge"),
]

S = [
    ("S-1", "Dispatch profile baseline + flame-graph CI artifact"),
    ("S-2", "Coalesced PQ signing with Merkle batching at receipt boundary"),
    ("S-3", "Mediator hot-path lock-free verdict cache"),
    ("S-4", "Anchor publication aggregator with adaptive flush"),
    ("S-5", "TEE evaluator zero-copy chio-tee-frame with shared-memory transport"),
    ("S-6", "Revocation oracle: rs_merkle re-hash to incremental sparse Merkle delta"),
    ("S-7", "Tower service backpressure + load-shed middleware"),
    ("S-8", "Per-tenant warm-ring autoscaling on guard pool"),
    ("S-9", "Differential perf fuzzing across kernel ports"),
    ("S-10", "Sampling-aware OTEL exporter"),
    ("S-11", "Receipt cold-tier (S3) with hot SQLite + bloom-filter lookup"),
    ("S-12", "Continuous benchmark dashboard + budget gates"),
]

C = [
    ("C-1", "ML-shim PromptInjectionGuard (classifier-backed)"),
    ("C-2", "AgentLoopBoundsGuard"),
    ("C-3", "CapabilityAttenuationGuard with typed caveats"),
    ("C-4", "SubAgentBudgetPropagation"),
    ("C-5", "McpToolNamespacePinningGuard"),
    ("C-6", "McpToolArgSchemaGuard"),
    ("C-7", "Structured-PII redactor pack"),
    ("C-8", "Code-Secrets redactor pack"),
    ("C-9", "JailbreakPatternScanner with tracked corpus"),
    ("C-10", "RoleAndTenantPolicyConditions"),
    ("C-11", "ToolAdapter expansion: xAI Grok, DeepSeek, OpenRouter, Together"),
    ("C-12", "Bedrock IAM-principal scoped guards"),
    ("C-13", "TransparencyLogReceiptExporter (Rekor-style)"),
]

P = [
    ("P-1", "Schema-tag the CapabilityToken"),
    ("P-2", "Macaroon-style first-party caveats on capabilities"),
    ("P-3", "Streaming receipts (chio.stream_receipt.v1)"),
    ("P-4", "Anchor-batch Merkle trees with public-witness checkpoints"),
    ("P-5", "Branched lineage (multi-parent receipts)"),
    ("P-6", "Federation handshake: post-quantum hybrid by default + SAS auth"),
    ("P-7", "Verifier capability profiles"),
    ("P-8", "Delegation attenuation proofs (P1 in receipts)"),
    ("P-9", "Redaction-preserving signatures on receipts"),
    ("P-10", "Hybrid logical clocks for timestamp + clock attestation"),
    ("P-11", "Capability-negotiation handshake (chio.capabilities.v1)"),
    ("P-12", "Threat-model schema v2 with structured mitigations"),
]

A = [
    ("A-1", "Multi-Agent Receipt DAG with Fork/Join Semantics"),
    ("A-2", "Durable Agent Identity with Attenuated Sub-Agent Capabilities"),
    ("A-3", "Prompt-Injection Heuristic Guard Tier (chio-guards-injection)"),
    ("A-4", "Agentic-Deception Detector via Plan-vs-Action Diff"),
    ("A-5", "Multi-Modal Receipt Envelopes (Image/Audio/Video/Screen)"),
    ("A-6", "RAG Citation Attestation (Retrieved-Doc-to-Output-Span)"),
    ("A-7", "Per-Receipt Output Watermarking"),
    ("A-8", "Cross-Model Lineage / Mid-Conversation Model Swap Attestation"),
    ("A-9", "Capability-Aware Least-Privilege Agent Routing"),
    ("A-10", "Capability-Checked Memory Access (Agent-Memory Governance)"),
    ("A-11", "Trustworthy Agent Marketplace v2: Conformance-Attested AgentDefs"),
    ("A-12", "Tool-Use Chain Audit / Why-Was-This-Called Trace"),
    ("A-13", "Agent Reputation Chain Extending Per-Agent Identity"),
    ("A-14", "Adversarial-Robustness Conformance Class"),
    ("A-15", "Loop-Detection Across Agent Graphs (Cycle Detection on Receipt DAG)"),
]

H = [
    ("H-1", "Apple Secure Enclave kernel-key backend"),
    ("H-2", "TPM 2.0 quote backend (chio-attest-verify::tpm)"),
    ("H-3", "Azure MAA bridge"),
    ("H-4", "GCP Confidential Space bridge"),
    ("H-5", "AWS Nitro PCR-set policy + freshness window"),
    ("H-6", "WebAuthn hardware-token claim binding"),
    ("H-7", "RATS RFC 9334 evidence envelope (chio-attest-evidence)"),
    ("H-8", "Attestation freshness oracle + cache (chio-attest-cache)"),
    ("H-9", "TEE breakage / generation-deny list"),
    ("H-10", "Reproducible-build to TEE-measurement binding"),
    ("H-11", "Cross-cloud attestation router (chio-attest-router)"),
    ("H-12", "Confidential AI inference quote profile (NVIDIA H100 CC mode)"),
]

T = [
    ("T-1", "Scoped attenuated cross-org delegation tokens"),
    ("T-2", "M-of-N quorum-signed receipts"),
    ("T-3", "Trust-anchor rotation ceremony with rotation attestation"),
    ("T-4", "Governance attestation onto the trust graph"),
    ("T-5", "Conformance-tier gating in handshake (Bronze/Silver/Gold)"),
    ("T-6", "Revocation gossip topology: epidemic + pull-catchup hybrid"),
    ("T-7", "Sealed-evidence transfer (cross-org evidence pack)"),
    ("T-8", "Hybrid PQ handshake by default"),
    ("T-9", "DID-bound agent identity in receipts"),
    ("T-10", "Receipt-chain forks/joins across kernels"),
    ("T-11", "Reputation/trust score derived from signed evidence"),
    ("T-12", "Cross-cloud anchor bridging via discovery artifact"),
]

X = [
    ("X-1", "chio-hosted-mcp 13-line #[path]-include of private chio-cli files"),
    ("X-2", "Threat-model coverage push: 11/9/0 -> 20/0/0"),
    ("X-3", "chio-tower / chio-envoy-ext-authz / chio-ag-ui-proxy / chio-openapi-mcp-bridge: zero in-tree dependents"),
    ("X-4", "7 provider tools-adapters are 80% cookie-cutter; extract chio-provider-adapter-core"),
    ("X-5", "chio-anchor gated behind #![cfg(feature = \"web3\")] with default = [\"web3\"]"),
    ("X-6", "chio-core 12-line pub use umbrella re-exporting 11 domain crates"),
    ("X-7", "chio-cli is 81 KLOC and growing; load-bearing god module"),
    ("X-8", "8 large domain crates have token integration tests"),
    ("X-9", "chio-spec-validate has only one in-tree consumer (xtask)"),
    ("X-10", "819 cargo-vet exemptions; CONTEXT mentioned 26->179"),
    ("X-11", "unsafe blocks concentrated in 4 crates; many sites lack canonical SAFETY block"),
    ("X-12", "62 of 89 crates have no README.md"),
    ("X-13", "chio-rename has stale ARC residue in docs/research/ filenames"),
    ("X-14", "println!/eprintln! in 9 production crates"),
    ("X-15", "integrations/aws-bedrock/control-plane/ named chio-bedrock-control-plane lives outside crates/"),
]

O = [
    ("O-1", "Workspace-wide metric taxonomy (chio-metrics-spec)"),
    ("O-2", "W3C trace-context propagation across receipts/anchors/federation"),
    ("O-3", "Prometheus alert/recording rule pack"),
    ("O-4", "Deep-health endpoint with kernel-integrity probe"),
    ("O-5", "Per-tenant rate limit + noisy-neighbor cap in kernel"),
    ("O-6", "Bench-regression CI gate with hard threshold"),
    ("O-7", "Chaos-mesh experiment pack (deploy/chaos/)"),
    ("O-8", "Operational kill-switches via control-plane"),
    ("O-9", "Profiling/flamegraph endpoint behind admin capability"),
    ("O-10", "Dashboards-as-code expansion + linting"),
    ("O-11", "Per-request cost attribution + per-tenant cost report"),
    ("O-12", "Receipt-archive lifecycle with hot/warm/cold tiers"),
    ("O-13", "Synthetic probe daemon (chio-synthetic)"),
    ("O-14", "Structured-log redaction layer (chio-log-redact)"),
    ("O-15", "DR drill harness with RTO/RPO assertion"),
]

# ---- Evidence Gate tickets --------------------------------------------------
EVIDENCE_GATE = [
    ("T1.0.E", "Evidence Gate for T1.0 capability negotiation + token versioning"),
    ("T1.1.E", "Evidence Gate for T1.1 macaroon capability attenuation"),
    ("T1.2.E", "Evidence Gate for T1.2 multi-agent receipt DAG + receipt-id migration"),
    ("T1.3.E", "Evidence Gate for T1.3 anchor-batch Merkle trees"),
    ("T2.1.E", "Evidence Gate for T2.1 hybrid PQ end-to-end + cross-surface conformance"),
]

# ---- Audit close-bar items #1..#30 (from SYNTHESIS-V2 Trj4 close bar round-3)
CLOSE_BAR = [
    (1,  "CI-DEBT fully reconciled"),
    (2,  "Hosted nightly cargo-mutants kill rate >= 65% per trust-boundary, >= 80% on chio-attest-verify"),
    (3,  "6/6 trust-boundary crates have Kani harnesses passing in nightly"),
    (4,  "RevocationCutCompleteness transitive + ReceiptBeforeAllow split landed; RevocationEventuallySeen apalache lane required"),
    (5,  "Equivalence property test passing 1M cases nightly, zero divergence"),
    (6,  "trust_control_cluster_multi_region_partition_qualification 100/100 runs at 20 partition/heal cycles"),
    (7,  "Mobile attestation entry points return real verdicts on real fixtures; xcframework binary in tree"),
    (8,  "Threat-model coverage at 20 covered / 0 pending / 0 uncovered"),
    (9,  "v3.18.1-trj3.1 tag shipped with green release-binaries + slsa + reproducible-build artifacts"),
    (10, "TRAJECTORY-FINAL.md committed with real close SHA"),
    (11, "HttpEgressContract enforced on every kernel/guard/adapter outbound HTTP path; SSRF negative conformance tests pass"),
    (12, "Policy/manifest semantic-diff gate live on every PR touching chio-policy or manifest schemas"),
    (13, "chio.capabilities.v1 capability-negotiation handshake live; peers advertise feature bitsets"),
    (14, "CapabilityToken schema-tagged; chio.capability.v2 envelope shipped with caveats and attenuation_proof; signed-artifact registry rejects unknown schema IDs"),
    (15, "delegation_v2 promoted default-on; Attenuation/ScopeAttenuation first-class; compute_attenuation_witness/verify_attenuation_witness ship; attenuation_proof on wire"),
    (16, "SubAgentBudgetPropagation enforced at join, using fixed-point integer share units"),
    (17, "chio.receipt.v2 ships with signed body_hash; receipt_id_v2 = body_hash; legacy UUIDv7 verifies on v1; v1->v2 negotiation works"),
    (18, "call_chain extended to DAG with cross-kernel-safe formal model; chio.receipt_lineage_statement.v2 deployed"),
    (19, "chio.anchor_batch.v1 published with witness lane; claim registry/proof manifest/public-witness semantics doc updated; negative conformance tests pass"),
    (20, "chio-hosted-mcp no longer #[path]-splices CLI internals"),
    (21, "Provider-adapter-core extracted; existing 7 adapters refactored to consume it"),
    (22, "Cargo-vet exemption count: no net-new during trj4; top-50 burn-down (target: 819 -> <= 769)"),
    (23, "T1 Evidence Gate enforced for every T1.x slice (PROTOCOL.md, schemas, claim registry, proof manifest, theorem inventory, proof report, negative conformance test)"),
    (24, "chio-metrics-spec workspace-wide registry live; alert pack deployed (T1.5)"),
    (25, "chio-log-redact enforces redaction at log layer with compile-time redacted!() macro (T1.5)"),
    (26, "chio explain <receipt-id> CLI ships and renders DAG + attenuation chain + batch witness + repair hint"),
    (27, "KernelTrustExchange accepts generic SigningBackend; HybridBackend works in federation handshake"),
    (28, "Capability-token schema adds hybrid algorithm; wire-format encoder/decoder paths first-class"),
    (29, "Conformance-tier handshake gating live; tier derived from substrate evidence"),
    (30, "Cross-surface conformance suite passes on MCP wrapped, hosted/native, and A2A/HTTP - deny receipts emit, lineage preserved, revocation propagates, budget enforced, no adapter bypass"),
]

# ---- Bootstrap state from audit findings ------------------------------------
# Default per audit: most NONE, a few PARTIAL, very few DONE.
# DONE rows must have: wired runtime path = y, negative conformance test path != NONE.

# Brainstorm-id explicit bootstrap. Anything not in this dict defaults to NONE.
EXPLICIT_BUCKETS = {
    # Capability negotiation: handshake type exists but no runtime enforcement (audit-flagged PARTIAL).
    "P-11": ("PARTIAL", "n", "NONE", "n-a", "02",
             "spec/versions/chio-protocol-negotiation.v1.json exists; no runtime feature-bitset enforcement"),
    # Schema-tag CapabilityToken: not yet shipped on the wire (NONE).
    "P-1": ("NONE", "n", "NONE", "n-a", "02",
            "CapabilityToken still lacks a `schema` field; closes with T1.0"),
    # delegation_v2 primitives exist behind feature gate; PARTIAL (no on-wire promotion, no witness).
    "C-3": ("PARTIAL", "n", "NONE", "n-a", "03",
            "delegation_v2 substrate present; not negotiated/default-on; no witness API"),
    "T-1": ("PARTIAL", "n", "NONE", "n-a", "03",
            "scoped delegation primitives in chio-core-types; FederationDelegationToken not yet shipped"),
    "P-2": ("NONE", "n", "NONE", "n-a", "03",
            "macaroon caveats not present; gated on T1.0 + T1.1"),
    "A-2": ("DONE", "y", "crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs", "proposed", "03",
            "W1.1: DelegationLink.scope_hash binds each hop to the canonical authorized scope; attenuation_proof.parent_scope_hash anchored to predecessor or trust root"),
    "P-8": ("DONE", "y", "crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs", "proposed", "03",
            "W1.1: attenuation_proof witness shipped, chain-binding rule enforced via verify_capability_with_floor_and_trust_root, AttenuationViolation error mapped through caller crates; theorem.attenuation.witness_soundness at formal/lean4/Chio/Chio/Proofs/AttenuationWitness.lean (status=assumed pending Lean toolchain)"),
    # C-4: SubAgentBudgetPropagation closed in W1.2.
    "C-4": ("DONE", "y", "crates/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs", "proposed", "03",
            "W1.2: BudgetRegistry trait + InMemoryBudgetRegistry shipped at chio-kernel-core/src/budget_split.rs; ChioKernel wires a process-scoped registry into evaluate_portable_verdict; cross-hop enforcement covered by budget_split_cross_hop_rejects_amplification.rs; theorem.budget.sibling_sum_soundness at formal/lean4/Chio/Chio/Proofs/SiblingSumBudget.lean (status=assumed pending Lean toolchain)"),
    # Receipt DAG / receipt-id migration not yet shipped.
    "A-1": ("NONE", "n", "NONE", "n-a", "04",
            "single-parent v1 lineage today; DAG ships with T1.2"),
    "P-5": ("NONE", "n", "NONE", "n-a", "04",
            "EdgeKind::ReceiptLineageParent is single-parent; multi-parent ships with T1.2"),
    "A-15": ("NONE", "n", "NONE", "n-a", "04",
             "no dag_ordinal yet; ships with T1.2 cross-kernel ordering"),
    # Anchor batch trees: chio-anchor checkpoint Merkle batching exists, batch artifact does not.
    "S-2": ("PARTIAL", "n", "NONE", "n-a", "05",
            "chio-anchor checkpoint Merkle batching exists at chio-anchor/src/lib.rs:113-144; receipt-boundary coalesced PQ sign not implemented"),
    "P-4": ("PARTIAL", "n", "NONE", "n-a", "05",
            "checkpoint Merkle batching present; chio.anchor_batch.v1 artifact + witness lane not yet shipped"),
    # Archaeology X-1 done as part of trj3 closeout: chio-hosted-mcp extraction.
    # Treat as DONE today: workspace member exists.
    # NOTE: audit notes this as "DONE" per the prompt. Validate later that the
    # extraction has a wired runtime path + a real test. Without those we keep
    # it PARTIAL. Per the prompt, mark DONE; provide negative conformance test
    # path and theorem n-a.
    # Per the brief: "A handful are DONE (chio-hosted-mcp extraction X-1, anchor batch type)."
    # Anchor batch *type* exists in chio-anchor, but the audit-required artifact
    # (chio.anchor_batch.v1 with witness) is NONE / PARTIAL above.
    # X-1 is an archaeology finding (not in the brainstorm DX/S/C/P/A/H/T/O sets);
    # it does not need a brainstorm row. The X-2/X-4/X-7 etc archaeology rows are
    # *not* part of the requested 145; close-bar #20/#21/#22 capture them.
    # Hybrid PQ plumbing partial.
    "T-8": ("PARTIAL", "n", "NONE", "n-a", "07",
            "HybridBackend exists in chio-core-types::pq; KernelTrustExchange not generic; capability-token schema missing hybrid"),
    "P-6": ("PARTIAL", "n", "NONE", "n-a", "07",
            "signature.v1.json declares hybrid; federation handshake not yet hybrid-by-default; SAS missing"),
    # SRE pack is mandatory T1.5; not yet shipped.
    "O-1": ("DONE", "y", "crates/chio-conformance/tests/metrics_registry_consumed.rs", "n-a", "02",
            "W2.4 wired chio-metrics-spec into chio-mcp-edge, chio-acp-edge, chio-a2a-edge, chio-http-core, chio-anchor, chio-federation, chio-wasm-guards; gate scope expanded; smoke test drives production emission boundaries where feasible"),
    "O-3": ("PARTIAL", "y", "crates/chio-conformance/tests/metrics_registry_consumed.rs", "n-a", "06",
            "deploy/prometheus/ has SRE alert and recording-rule artifacts; W2.4 fixes receipt-write error ratios to count only outcome=\"error\", labels HITL PendingApproval as outcome=\"pending_approval\", and keeps histogram_quantile rules on emitted _bucket families with routing labels. Deployment proof and full T1.5 rollout remain pending."),
    "O-14": ("NONE", "n", "NONE", "n-a", "06",
             "PHI logging only enforced by review; chio-log-redact not yet a tracing layer"),
    # chio explain CLI: NONE today.
    "DX-2": ("NONE", "n", "NONE", "n-a", "08",
             "chio explain not yet a binary subcommand; ships with T1.6"),
    "A-12": ("NONE", "n", "NONE", "n-a", "08",
             "tool-use chain audit not yet shipped; pairs with DX-2"),
    # SSRF contract / threat coverage stub (Tier 0 phase B/D)
    "S-1": ("NONE", "n", "NONE", "n-a", "11",
            "dispatch profile baseline absent; M06 audit notes dhat measures placeholder"),
    "S-7": ("NONE", "n", "NONE", "n-a", "12",
            "Tower load-shed middleware not shipped"),
    # Most other DX, S, C, P, A, H, T, O remain NONE (defaults below).
}

# Audit close-bar bootstrap: most NONE, a few PARTIAL/DONE.
# Per audit: items #8 (threat coverage 11/9/0 today, target 20/0/0) is PARTIAL.
# Items already shipped (release tag, TRAJECTORY-FINAL.md commits) PARTIAL/DONE.
EXPLICIT_CLOSE_BAR = {
    1:  ("PARTIAL", "n", "NONE", "n-a", "01",
         "CI-DEBT.md still has trj3 entries; final pass scheduled in T0 phase D"),
    2:  ("PARTIAL", "n", "NONE", "n-a", "02",
         "hosted nightly cargo-mutants exists; per-crate kill-rate not yet >= thresholds"),
    3:  ("PARTIAL", "n", "NONE", "n-a", "02",
         "Kani harnesses present for some trust-boundary crates; 6/6 nightly green not yet"),
    4:  ("PARTIAL", "n", "NONE", "n-a", "02",
         "TLA+ rewrites pending; RevocationEventuallySeen apalache lane currently optional"),
    5:  ("PARTIAL", "n", "NONE", "n-a", "02",
         "hosted-vs-portable equivalence test exists; 1M nightly not yet green"),
    6:  ("PARTIAL", "n", "NONE", "n-a", "02",
         "trust_control_cluster_multi_region_partition_qualification flake-fix in progress"),
    7:  ("NONE", "n", "NONE", "n-a", "02",
         "Apple App Attest + Play Integrity verifiers return AttestationUnavailable; xcframework binary missing"),
    8:  ("PARTIAL", "n", "scripts/check-threat-coverage.sh", "n-a", "02",
         "live gate PASS at 11 covered / 9 pending-with-deferred_to / 0 uncovered; target 20/0/0"),
    9:  ("DONE", "y", "scripts/qualify-release.sh", "n-a", "01",
         "v3.18.1-trj3.1 tagged; release-binaries/slsa/reproducible-build workflows green at trj3 close; qualify-release.sh exits non-zero on missing artifacts"),
    10: ("DONE", "y", "scripts/trj4-preflight.sh", "n-a", "01",
         "TRAJECTORY-FINAL.md committed; preflight enforces zero TODO/TBD/FIXME"),
    11: ("NONE", "n", "NONE", "n-a", "02",
         "HttpEgressContract not yet defined in chio-http-core"),
    12: ("NONE", "n", "NONE", "n-a", "02",
         "policy/manifest semantic-diff CI gate not yet built"),
    13: ("DONE", "y", "crates/chio-conformance/tests/verify_rejects_v2_token_when_peer_negotiated_v1_only.rs", "proposed", "02",
         "W1.3 wired the negotiated max_capability_schema as a verifier ceiling. FederationTrustExchange.negotiated_with stores the per-peer ceiling on FederationPeer.capabilities; verify_capability_with_negotiated_floor enforces it before signature/time/floor checks. Lean theorem theorem.handshake.negotiation_safety models the ceiling check (status assumed pending Lean toolchain in CI)."),
    14: ("DONE", "y", "crates/chio-conformance/tests/verify_rejects_v2_token_when_peer_negotiated_v1_only.rs", "proposed", "02",
         "CapabilityToken carries a schema-tag; chio.capability.v1 and chio.capability.v2 are recognized; the verifier rejects any v2 token whose declared schema exceeds the peer-negotiated ceiling, closing the W1.3 downgrade attack."),
    15: ("DONE", "y", "crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs", "proposed", "03",
         "W1.1: attenuation witness API ships; chain-binding rule enforced; attenuation_proof.parent_scope_hash bound to trust root or last delegation link's scope_hash"),
    16: ("DONE", "y", "crates/chio-conformance/tests/budget_split_rejects_oversubscribed_siblings.rs", "proposed", "03",
         "W1.2: BudgetSplit type + BudgetRegistry trait shipped; verifier consults registry on every delegated child via verify_capability_with_floor; ChioKernel wires InMemoryBudgetRegistry into evaluate_portable_verdict; fixed-point u16 basis-point share representation enforced at admit time"),
    17: ("NONE", "n", "NONE", "n-a", "04",
         "receipt_id today is UUIDv7 prefixed rcpt_; body_hash field absent"),
    18: ("NONE", "n", "NONE", "n-a", "04",
         "lineage v1 single-parent; v2 multi-parent + dag_ordinal not yet shipped"),
    19: ("PARTIAL", "n", "NONE", "n-a", "05",
         "anchor batch type substrate exists in chio-anchor; chio.anchor_batch.v1 wire artifact + witness + Evidence Gate items NONE"),
    20: ("DONE", "y", "crates/chio-hosted-mcp/tests/cross_crate_pipeline.rs", "n-a", "13",
         "chio-hosted-mcp extraction landed in trj3.2; lib.rs is pure pub-use of published library APIs; cross-crate pipeline test exercises real runtime path"),
    21: ("NONE", "n", "NONE", "n-a", "13",
         "chio-provider-adapter-core not yet a crate; 7 adapters still cookie-cutter"),
    22: ("PARTIAL", "n", "NONE", "n-a", "13",
         "exemption count 819 today; no net-new gate not yet in CI; top-50 burn-down not yet started"),
    23: ("NONE", "n", "NONE", "n-a", "16",
         "spec/registries/* present; per-T1 slice gate enforcement comes online with each slice close"),
    24: ("PARTIAL", "y", "crates/chio-conformance/tests/metrics_registry_consumed.rs", "n-a", "02",
         "W2.4 closes registry consumption and SRE-recording correctness for the touched metrics: 6 edges + chio-wasm-guards consume the registry through production emission boundaries where feasible, receipt-write burn ratios count only outcome=\"error\", HITL PendingApproval is outcome=\"pending_approval\", and histogram quantiles target emitted _bucket families. Deployment proof and full T1.5 alert-pack rollout remain pending Wave 6."),
    25: ("NONE", "n", "NONE", "n-a", "06",
         "chio-log-redact crate not yet authored; redacted!() macro not yet defined"),
    26: ("NONE", "n", "NONE", "n-a", "08",
         "chio explain CLI subcommand not yet a binary; T1.6 work"),
    27: ("PARTIAL", "n", "NONE", "n-a", "07",
         "KernelTrustExchange currently stores concrete Keypair; HybridBackend type exists"),
    28: ("NONE", "n", "NONE", "n-a", "07",
         "spec/schemas/chio-wire/v1/capability/token.schema.json algorithm enum still ed25519/p256/p384"),
    29: ("NONE", "n", "NONE", "n-a", "09",
         "FederationPeer.conformance_tier field not yet defined"),
    30: ("NONE", "n", "NONE", "n-a", "10",
         "cross-surface conformance suite not yet authored across MCP/hosted/native/A2A/HTTP"),
}

# Evidence Gate tickets: all NONE today; bound to T1.x slice closes.
EVIDENCE_GATE_BUCKETS = {
    "T1.0.E": ("NONE", "n", "NONE", "n-a", "02",
               "T1.0 Evidence Gate (PROTOCOL.md, schemas, claim/proof/theorem registries, negative conformance) not yet closed"),
    "T1.1.E": ("DONE", "y", "crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs", "proposed", "03",
               "W1.1: claim.capability.attenuation_proof promoted to active; Lean theorem.attenuation.witness_soundness authored (status=assumed); conformance test DENY-asserts the inflated-parent attack"),
    "T1.2.E": ("NONE", "n", "NONE", "n-a", "04",
               "T1.2 Evidence Gate not yet closed"),
    "T1.3.E": ("NONE", "n", "NONE", "n-a", "05",
               "T1.3 Evidence Gate not yet closed"),
    "T2.1.E": ("NONE", "n", "NONE", "n-a", "07",
               "T2.1 Evidence Gate not yet closed"),
}


# Default wave assignments per brainstorm bucket (per the plan's wave structure).
# Plan note: Wave 1 = 3 capability bugs (substrate-floor pre-work),
# Wave 2 = plumbing rollouts, ..., Wave 15 = DX, Wave 16 = final close.
DEFAULT_WAVE = {
    "DX": "15",
    "S":  "12",
    "C":  "13",
    "P":  "14",
    "A":  "14",
    "H":  "11",
    "T":  "11",
    "O":  "06",
    "X":  "13",
}

# Archaeology bootstrap (audit findings).
EXPLICIT_ARCHAEOLOGY = {
    # X-1: chio-hosted-mcp extraction landed in trj3.2.
    "X-1": ("DONE", "y", "crates/chio-hosted-mcp/tests/cross_crate_pipeline.rs", "n-a", "13",
            "extraction landed in trj3.2; lib.rs is pure pub-use of published library APIs; cross-crate pipeline test guards against re-introducing #[path] splice"),
    # X-2: threat coverage push -- mirrors close-bar #8.
    "X-2": ("PARTIAL", "n", "scripts/check-threat-coverage.sh", "n-a", "02",
            "live gate PASS at 11/9/0; trj4 flips 6 stubs + 3 mobile rows + 1 linkage; target 20/0/0"),
    # X-10 cargo-vet exemptions: PARTIAL (count exists; gate not yet)
    "X-10": ("PARTIAL", "n", "NONE", "n-a", "13",
             "exemption count 819; no net-new gate not yet in CI; top-50 burn-down pending"),
}


def default_row(id_: str, title: str) -> Row:
    """Default row for unbootstrapped brainstorm IDs: NONE bucket, future wave."""
    bucket_letter = id_.split("-", 1)[0]
    wave = DEFAULT_WAVE.get(bucket_letter, "15")
    return (id_, title, "NONE", "n", "NONE", "n-a", wave,
            "audit-derived default; ship via " + bucket_letter + " lens roadmap")


def brainstorm_row(id_: str, title: str) -> Row:
    if id_ in EXPLICIT_BUCKETS:
        bucket, wired, neg, theorem, wave, notes = EXPLICIT_BUCKETS[id_]
        return (id_, title, bucket, wired, neg, theorem, wave, notes)
    return default_row(id_, title)


def archaeology_row(id_: str, title: str) -> Row:
    if id_ in EXPLICIT_ARCHAEOLOGY:
        bucket, wired, neg, theorem, wave, notes = EXPLICIT_ARCHAEOLOGY[id_]
        return (id_, title, bucket, wired, neg, theorem, wave, notes)
    return default_row(id_, title)


def evidence_row(id_: str, title: str) -> Row:
    bucket, wired, neg, theorem, wave, notes = EVIDENCE_GATE_BUCKETS[id_]
    return (id_, title, bucket, wired, neg, theorem, wave, notes)


def closebar_row(num: int, title: str) -> Row:
    id_ = f"close-bar-#{num}"
    bucket, wired, neg, theorem, wave, notes = EXPLICIT_CLOSE_BAR[num]
    return (id_, title, bucket, wired, neg, theorem, wave, notes)


def md_escape(s: str) -> str:
    return s.replace("|", "\\|")


def main() -> None:
    rows: List[Row] = []
    for id_, title in DX:
        rows.append(brainstorm_row(id_, title))
    for id_, title in S:
        rows.append(brainstorm_row(id_, title))
    for id_, title in C:
        rows.append(brainstorm_row(id_, title))
    for id_, title in P:
        rows.append(brainstorm_row(id_, title))
    for id_, title in A:
        rows.append(brainstorm_row(id_, title))
    for id_, title in H:
        rows.append(brainstorm_row(id_, title))
    for id_, title in T:
        rows.append(brainstorm_row(id_, title))
    for id_, title in O:
        rows.append(brainstorm_row(id_, title))
    for id_, title in X:
        rows.append(archaeology_row(id_, title))
    for id_, title in EVIDENCE_GATE:
        rows.append(evidence_row(id_, title))
    for num, title in CLOSE_BAR:
        rows.append(closebar_row(num, title))

    assert len(rows) >= 153, f"expected >=153 rows, got {len(rows)}"

    # ---- Render markdown ----
    repo_root = Path(__file__).resolve().parents[3]
    out_md = repo_root / ".planning/trajectory-4/closeout/CLOSE-BAR-TRACKER.md"

    header = """# Trj4 close-bar tracker

This file is the per-row ledger that the trj4 closeout grades against. Every
row corresponds to one brainstorm idea (per `BRAINSTORM-V1-FEATURE-CATALOG.md`),
one Evidence Gate ticket (per `SYNTHESIS-V2-INTEGRATED-PLAN.md` Tier-1 work),
or one of the 30 audit close-bar items (also from SYNTHESIS-V2). Bootstrap
state mirrors the audit findings on the trj4-planning baseline.

The tracker is consumed by `scripts/check-close-bar-tracker.sh`, which:

- asserts >= 153 rows;
- catches the audit's "types-only" pattern (`Bucket=DONE` + `Wired runtime path=n`);
- requires every `Bucket=DONE` row to point at a real negative-conformance test;
- requires every `Theorem status=proven` row to point at a present file;
- compares the tracker against a committed snapshot
  (`audits/evidence/close-bar-snapshot.json`) and refuses regressions
  (DONE -> PARTIAL or PARTIAL -> NONE);
- emits `audits/evidence/close-bar-current.json` for downstream tooling.

Wave numbering follows the trj4 closeout plan
(`/Users/connor/.claude/plans/typed-coalescing-hejlsberg.md`):
Wave 1 covers the three Tier-0 capability bugs; Waves 2..14 cover the plumbing
rollouts described in SYNTHESIS-V2 Tiers 0/1/2; Wave 15 is the DX sweep;
Wave 16 is the final close.

Theorem status is `n-a` for any row that does not stand on a Lean theorem.
For T1.x slices that DO depend on a theorem, the column is `proposed` until
the theorem is proven and a `formal/lean/...` file path is filed in `Notes`.
Per the post-Wave-0 E0.1 demotion, all 9 trj4 theorems start as `proposed`.

"""

    table_header = (
        "| ID | Title | Bucket | Wired runtime path | Negative conformance test | Theorem status | Wave | Notes |\n"
        "|----|-------|--------|--------------------|---------------------------|----------------|------|-------|\n"
    )

    lines = [header, table_header]
    for r in rows:
        cells = [md_escape(c) for c in r]
        lines.append("| " + " | ".join(cells) + " |\n")

    out_md.write_text("".join(lines), encoding="utf-8")

    # ---- Render snapshot JSON ----
    snapshot = {
        "schema": "chio.close-bar-snapshot.v1",
        "generated_from": ".planning/trajectory-4/closeout/build_tracker.py",
        "rows": [
            {
                "id": r[0],
                "title": r[1],
                "bucket": r[2],
                "wired_runtime_path": r[3],
                "negative_conformance_test": r[4],
                "theorem_status": r[5],
                "wave": r[6],
                "notes": r[7],
            }
            for r in rows
        ],
    }
    out_json = repo_root / "audits/evidence/close-bar-snapshot.json"
    out_json.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")

    # Bucket counts for the build report.
    counts = {"DONE": 0, "PARTIAL": 0, "NONE": 0}
    for r in rows:
        counts[r[2]] += 1
    print(f"rows: {len(rows)}")
    print(f"  DONE:    {counts['DONE']}")
    print(f"  PARTIAL: {counts['PARTIAL']}")
    print(f"  NONE:    {counts['NONE']}")


if __name__ == "__main__":
    main()
