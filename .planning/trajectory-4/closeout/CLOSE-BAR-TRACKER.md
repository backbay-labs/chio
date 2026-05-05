# Trj4 close-bar tracker

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

| ID | Title | Bucket | Wired runtime path | Negative conformance test | Theorem status | Wave | Notes |
|----|-------|--------|--------------------|---------------------------|----------------|------|-------|
| DX-1 | chio init interactive shape picker + golden-path templates | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-2 | chio explain <receipt-id> deep narrator | NONE | n | NONE | n-a | 08 | chio explain not yet a binary subcommand; ships with T1.6 |
| DX-3 | Receipt-chain explorer (web) | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-4 | In-process kernel for SDK tests + golden-receipt assertions | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-5 | Polish vscode-chio + zed-chio extensions to publishable quality | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-6 | chio doctor upgrade with repair suggestions | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-7 | Mock kernel + fixture-replay harness with hot-reload (chio dev) | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-8 | SDK idiomatic-pass: Python + TypeScript first | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-9 | Error catalog with stable codes + repair hints | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-10 | chio diff for policies, manifests, trust roots | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-11 | End-to-end demo apps that someone could actually deploy | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| DX-12 | chio trace <session> + OTel-receipts bridge | NONE | n | NONE | n-a | 15 | audit-derived default; ship via DX lens roadmap |
| S-1 | Dispatch profile baseline + flame-graph CI artifact | NONE | n | NONE | n-a | 11 | dispatch profile baseline absent; M06 audit notes dhat measures placeholder |
| S-2 | Coalesced PQ signing with Merkle batching at receipt boundary | PARTIAL | n | NONE | n-a | 05 | chio-anchor checkpoint Merkle batching exists at chio-anchor/src/lib.rs:113-144; receipt-boundary coalesced PQ sign not implemented |
| S-3 | Mediator hot-path lock-free verdict cache | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-4 | Anchor publication aggregator with adaptive flush | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-5 | TEE evaluator zero-copy chio-tee-frame with shared-memory transport | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-6 | Revocation oracle: rs_merkle re-hash to incremental sparse Merkle delta | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-7 | Tower service backpressure + load-shed middleware | NONE | n | NONE | n-a | 12 | Tower load-shed middleware not shipped |
| S-8 | Per-tenant warm-ring autoscaling on guard pool | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-9 | Differential perf fuzzing across kernel ports | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-10 | Sampling-aware OTEL exporter | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-11 | Receipt cold-tier (S3) with hot SQLite + bloom-filter lookup | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| S-12 | Continuous benchmark dashboard + budget gates | NONE | n | NONE | n-a | 12 | audit-derived default; ship via S lens roadmap |
| C-1 | ML-shim PromptInjectionGuard (classifier-backed) | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-2 | AgentLoopBoundsGuard | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-3 | CapabilityAttenuationGuard with typed caveats | PARTIAL | n | NONE | n-a | 03 | delegation_v2 substrate present; not negotiated/default-on; no witness API |
| C-4 | SubAgentBudgetPropagation | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-5 | McpToolNamespacePinningGuard | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-6 | McpToolArgSchemaGuard | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-7 | Structured-PII redactor pack | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-8 | Code-Secrets redactor pack | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-9 | JailbreakPatternScanner with tracked corpus | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-10 | RoleAndTenantPolicyConditions | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-11 | ToolAdapter expansion: xAI Grok, DeepSeek, OpenRouter, Together | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-12 | Bedrock IAM-principal scoped guards | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| C-13 | TransparencyLogReceiptExporter (Rekor-style) | NONE | n | NONE | n-a | 13 | audit-derived default; ship via C lens roadmap |
| P-1 | Schema-tag the CapabilityToken | NONE | n | NONE | n-a | 02 | CapabilityToken still lacks a `schema` field; closes with T1.0 |
| P-2 | Macaroon-style first-party caveats on capabilities | NONE | n | NONE | n-a | 03 | macaroon caveats not present; gated on T1.0 + T1.1 |
| P-3 | Streaming receipts (chio.stream_receipt.v1) | NONE | n | NONE | n-a | 14 | audit-derived default; ship via P lens roadmap |
| P-4 | Anchor-batch Merkle trees with public-witness checkpoints | PARTIAL | n | NONE | n-a | 05 | checkpoint Merkle batching present; chio.anchor_batch.v1 artifact + witness lane not yet shipped |
| P-5 | Branched lineage (multi-parent receipts) | NONE | n | NONE | n-a | 04 | EdgeKind::ReceiptLineageParent is single-parent; multi-parent ships with T1.2 |
| P-6 | Federation handshake: post-quantum hybrid by default + SAS auth | PARTIAL | n | NONE | n-a | 07 | signature.v1.json declares hybrid; federation handshake not yet hybrid-by-default; SAS missing |
| P-7 | Verifier capability profiles | NONE | n | NONE | n-a | 14 | audit-derived default; ship via P lens roadmap |
| P-8 | Delegation attenuation proofs (P1 in receipts) | DONE | y | crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs | proposed | 03 | W1.1: attenuation_proof witness shipped, chain-binding rule enforced via verify_capability_with_floor_and_trust_root, AttenuationViolation error mapped through caller crates; theorem.attenuation.witness_soundness at formal/lean4/Chio/Chio/Proofs/AttenuationWitness.lean (status=assumed pending Lean toolchain) |
| P-9 | Redaction-preserving signatures on receipts | NONE | n | NONE | n-a | 14 | audit-derived default; ship via P lens roadmap |
| P-10 | Hybrid logical clocks for timestamp + clock attestation | NONE | n | NONE | n-a | 14 | audit-derived default; ship via P lens roadmap |
| P-11 | Capability-negotiation handshake (chio.capabilities.v1) | PARTIAL | n | NONE | n-a | 02 | spec/versions/chio-protocol-negotiation.v1.json exists; no runtime feature-bitset enforcement |
| P-12 | Threat-model schema v2 with structured mitigations | NONE | n | NONE | n-a | 14 | audit-derived default; ship via P lens roadmap |
| A-1 | Multi-Agent Receipt DAG with Fork/Join Semantics | NONE | n | NONE | n-a | 04 | single-parent v1 lineage today; DAG ships with T1.2 |
| A-2 | Durable Agent Identity with Attenuated Sub-Agent Capabilities | DONE | y | crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs | proposed | 03 | W1.1: DelegationLink.scope_hash binds each hop to the canonical authorized scope; attenuation_proof.parent_scope_hash anchored to predecessor or trust root |
| A-3 | Prompt-Injection Heuristic Guard Tier (chio-guards-injection) | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-4 | Agentic-Deception Detector via Plan-vs-Action Diff | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-5 | Multi-Modal Receipt Envelopes (Image/Audio/Video/Screen) | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-6 | RAG Citation Attestation (Retrieved-Doc-to-Output-Span) | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-7 | Per-Receipt Output Watermarking | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-8 | Cross-Model Lineage / Mid-Conversation Model Swap Attestation | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-9 | Capability-Aware Least-Privilege Agent Routing | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-10 | Capability-Checked Memory Access (Agent-Memory Governance) | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-11 | Trustworthy Agent Marketplace v2: Conformance-Attested AgentDefs | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-12 | Tool-Use Chain Audit / Why-Was-This-Called Trace | NONE | n | NONE | n-a | 08 | tool-use chain audit not yet shipped; pairs with DX-2 |
| A-13 | Agent Reputation Chain Extending Per-Agent Identity | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-14 | Adversarial-Robustness Conformance Class | NONE | n | NONE | n-a | 14 | audit-derived default; ship via A lens roadmap |
| A-15 | Loop-Detection Across Agent Graphs (Cycle Detection on Receipt DAG) | NONE | n | NONE | n-a | 04 | no dag_ordinal yet; ships with T1.2 cross-kernel ordering |
| H-1 | Apple Secure Enclave kernel-key backend | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-2 | TPM 2.0 quote backend (chio-attest-verify::tpm) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-3 | Azure MAA bridge | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-4 | GCP Confidential Space bridge | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-5 | AWS Nitro PCR-set policy + freshness window | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-6 | WebAuthn hardware-token claim binding | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-7 | RATS RFC 9334 evidence envelope (chio-attest-evidence) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-8 | Attestation freshness oracle + cache (chio-attest-cache) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-9 | TEE breakage / generation-deny list | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-10 | Reproducible-build to TEE-measurement binding | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-11 | Cross-cloud attestation router (chio-attest-router) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| H-12 | Confidential AI inference quote profile (NVIDIA H100 CC mode) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via H lens roadmap |
| T-1 | Scoped attenuated cross-org delegation tokens | PARTIAL | n | NONE | n-a | 03 | scoped delegation primitives in chio-core-types; FederationDelegationToken not yet shipped |
| T-2 | M-of-N quorum-signed receipts | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-3 | Trust-anchor rotation ceremony with rotation attestation | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-4 | Governance attestation onto the trust graph | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-5 | Conformance-tier gating in handshake (Bronze/Silver/Gold) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-6 | Revocation gossip topology: epidemic + pull-catchup hybrid | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-7 | Sealed-evidence transfer (cross-org evidence pack) | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-8 | Hybrid PQ handshake by default | PARTIAL | n | NONE | n-a | 07 | HybridBackend exists in chio-core-types::pq; KernelTrustExchange not generic; capability-token schema missing hybrid |
| T-9 | DID-bound agent identity in receipts | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-10 | Receipt-chain forks/joins across kernels | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-11 | Reputation/trust score derived from signed evidence | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| T-12 | Cross-cloud anchor bridging via discovery artifact | NONE | n | NONE | n-a | 11 | audit-derived default; ship via T lens roadmap |
| O-1 | Workspace-wide metric taxonomy (chio-metrics-spec) | NONE | n | NONE | n-a | 06 | no compile-time const-string registry; ships with T1.5 |
| O-2 | W3C trace-context propagation across receipts/anchors/federation | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-3 | Prometheus alert/recording rule pack | NONE | n | NONE | n-a | 06 | no burn-rate alert pack in deploy/prometheus/; ships with T1.5 |
| O-4 | Deep-health endpoint with kernel-integrity probe | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-5 | Per-tenant rate limit + noisy-neighbor cap in kernel | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-6 | Bench-regression CI gate with hard threshold | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-7 | Chaos-mesh experiment pack (deploy/chaos/) | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-8 | Operational kill-switches via control-plane | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-9 | Profiling/flamegraph endpoint behind admin capability | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-10 | Dashboards-as-code expansion + linting | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-11 | Per-request cost attribution + per-tenant cost report | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-12 | Receipt-archive lifecycle with hot/warm/cold tiers | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-13 | Synthetic probe daemon (chio-synthetic) | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| O-14 | Structured-log redaction layer (chio-log-redact) | NONE | n | NONE | n-a | 06 | PHI logging only enforced by review; chio-log-redact not yet a tracing layer |
| O-15 | DR drill harness with RTO/RPO assertion | NONE | n | NONE | n-a | 06 | audit-derived default; ship via O lens roadmap |
| X-1 | chio-hosted-mcp 13-line #[path]-include of private chio-cli files | DONE | y | crates/chio-hosted-mcp/tests/cross_crate_pipeline.rs | n-a | 13 | extraction landed in trj3.2; lib.rs is pure pub-use of published library APIs; cross-crate pipeline test guards against re-introducing #[path] splice |
| X-2 | Threat-model coverage push: 11/9/0 -> 20/0/0 | PARTIAL | n | scripts/check-threat-coverage.sh | n-a | 02 | live gate PASS at 11/9/0; trj4 flips 6 stubs + 3 mobile rows + 1 linkage; target 20/0/0 |
| X-3 | chio-tower / chio-envoy-ext-authz / chio-ag-ui-proxy / chio-openapi-mcp-bridge: zero in-tree dependents | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-4 | 7 provider tools-adapters are 80% cookie-cutter; extract chio-provider-adapter-core | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-5 | chio-anchor gated behind #![cfg(feature = "web3")] with default = ["web3"] | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-6 | chio-core 12-line pub use umbrella re-exporting 11 domain crates | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-7 | chio-cli is 81 KLOC and growing; load-bearing god module | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-8 | 8 large domain crates have token integration tests | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-9 | chio-spec-validate has only one in-tree consumer (xtask) | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-10 | 819 cargo-vet exemptions; CONTEXT mentioned 26->179 | PARTIAL | n | NONE | n-a | 13 | exemption count 819; no net-new gate not yet in CI; top-50 burn-down pending |
| X-11 | unsafe blocks concentrated in 4 crates; many sites lack canonical SAFETY block | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-12 | 62 of 89 crates have no README.md | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-13 | chio-rename has stale ARC residue in docs/research/ filenames | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-14 | println!/eprintln! in 9 production crates | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| X-15 | integrations/aws-bedrock/control-plane/ named chio-bedrock-control-plane lives outside crates/ | NONE | n | NONE | n-a | 13 | audit-derived default; ship via X lens roadmap |
| T1.0.E | Evidence Gate for T1.0 capability negotiation + token versioning | NONE | n | NONE | n-a | 02 | T1.0 Evidence Gate (PROTOCOL.md, schemas, claim/proof/theorem registries, negative conformance) not yet closed |
| T1.1.E | Evidence Gate for T1.1 macaroon capability attenuation | DONE | y | crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs | proposed | 03 | W1.1: claim.capability.attenuation_proof promoted to active; Lean theorem.attenuation.witness_soundness authored (status=assumed); conformance test DENY-asserts the inflated-parent attack |
| T1.2.E | Evidence Gate for T1.2 multi-agent receipt DAG + receipt-id migration | NONE | n | NONE | n-a | 04 | T1.2 Evidence Gate not yet closed |
| T1.3.E | Evidence Gate for T1.3 anchor-batch Merkle trees | NONE | n | NONE | n-a | 05 | T1.3 Evidence Gate not yet closed |
| T2.1.E | Evidence Gate for T2.1 hybrid PQ end-to-end + cross-surface conformance | NONE | n | NONE | n-a | 07 | T2.1 Evidence Gate not yet closed |
| close-bar-#1 | CI-DEBT fully reconciled | PARTIAL | n | NONE | n-a | 01 | CI-DEBT.md still has trj3 entries; final pass scheduled in T0 phase D |
| close-bar-#2 | Hosted nightly cargo-mutants kill rate >= 65% per trust-boundary, >= 80% on chio-attest-verify | PARTIAL | n | NONE | n-a | 02 | hosted nightly cargo-mutants exists; per-crate kill-rate not yet >= thresholds |
| close-bar-#3 | 6/6 trust-boundary crates have Kani harnesses passing in nightly | PARTIAL | n | NONE | n-a | 02 | Kani harnesses present for some trust-boundary crates; 6/6 nightly green not yet |
| close-bar-#4 | RevocationCutCompleteness transitive + ReceiptBeforeAllow split landed; RevocationEventuallySeen apalache lane required | PARTIAL | n | NONE | n-a | 02 | TLA+ rewrites pending; RevocationEventuallySeen apalache lane currently optional |
| close-bar-#5 | Equivalence property test passing 1M cases nightly, zero divergence | PARTIAL | n | NONE | n-a | 02 | hosted-vs-portable equivalence test exists; 1M nightly not yet green |
| close-bar-#6 | trust_control_cluster_multi_region_partition_qualification 100/100 runs at 20 partition/heal cycles | PARTIAL | n | NONE | n-a | 02 | trust_control_cluster_multi_region_partition_qualification flake-fix in progress |
| close-bar-#7 | Mobile attestation entry points return real verdicts on real fixtures; xcframework binary in tree | NONE | n | NONE | n-a | 02 | Apple App Attest + Play Integrity verifiers return AttestationUnavailable; xcframework binary missing |
| close-bar-#8 | Threat-model coverage at 20 covered / 0 pending / 0 uncovered | PARTIAL | n | scripts/check-threat-coverage.sh | n-a | 02 | live gate PASS at 11 covered / 9 pending-with-deferred_to / 0 uncovered; target 20/0/0 |
| close-bar-#9 | v3.18.1-trj3.1 tag shipped with green release-binaries + slsa + reproducible-build artifacts | DONE | y | scripts/qualify-release.sh | n-a | 01 | v3.18.1-trj3.1 tagged; release-binaries/slsa/reproducible-build workflows green at trj3 close; qualify-release.sh exits non-zero on missing artifacts |
| close-bar-#10 | TRAJECTORY-FINAL.md committed with real close SHA | DONE | y | scripts/trj4-preflight.sh | n-a | 01 | TRAJECTORY-FINAL.md committed; preflight enforces zero TODO/TBD/FIXME |
| close-bar-#11 | HttpEgressContract enforced on every kernel/guard/adapter outbound HTTP path; SSRF negative conformance tests pass | NONE | n | NONE | n-a | 02 | HttpEgressContract not yet defined in chio-http-core |
| close-bar-#12 | Policy/manifest semantic-diff gate live on every PR touching chio-policy or manifest schemas | NONE | n | NONE | n-a | 02 | policy/manifest semantic-diff CI gate not yet built |
| close-bar-#13 | chio.capabilities.v1 capability-negotiation handshake live; peers advertise feature bitsets | PARTIAL | n | NONE | n-a | 02 | negotiation handshake type defined; runtime feature-bitset advertise/enforce not wired |
| close-bar-#14 | CapabilityToken schema-tagged; chio.capability.v2 envelope shipped with caveats and attenuation_proof; signed-artifact registry rejects unknown schema IDs | NONE | n | NONE | n-a | 02 | CapabilityToken schema field absent; signed-artifact registry not built |
| close-bar-#15 | delegation_v2 promoted default-on; Attenuation/ScopeAttenuation first-class; compute_attenuation_witness/verify_attenuation_witness ship; attenuation_proof on wire | DONE | y | crates/chio-conformance/tests/attenuation_witness_rejects_inflated_parent_scope.rs | proposed | 03 | W1.1: attenuation witness API ships; chain-binding rule enforced; attenuation_proof.parent_scope_hash bound to trust root or last delegation link's scope_hash |
| close-bar-#16 | SubAgentBudgetPropagation enforced at join, using fixed-point integer share units | NONE | n | NONE | n-a | 03 | BudgetSplit not in v2 token; integer-fixed-point representation not yet shipped |
| close-bar-#17 | chio.receipt.v2 ships with signed body_hash; receipt_id_v2 = body_hash; legacy UUIDv7 verifies on v1; v1->v2 negotiation works | NONE | n | NONE | n-a | 04 | receipt_id today is UUIDv7 prefixed rcpt_; body_hash field absent |
| close-bar-#18 | call_chain extended to DAG with cross-kernel-safe formal model; chio.receipt_lineage_statement.v2 deployed | NONE | n | NONE | n-a | 04 | lineage v1 single-parent; v2 multi-parent + dag_ordinal not yet shipped |
| close-bar-#19 | chio.anchor_batch.v1 published with witness lane; claim registry/proof manifest/public-witness semantics doc updated; negative conformance tests pass | PARTIAL | n | NONE | n-a | 05 | anchor batch type substrate exists in chio-anchor; chio.anchor_batch.v1 wire artifact + witness + Evidence Gate items NONE |
| close-bar-#20 | chio-hosted-mcp no longer #[path]-splices CLI internals | DONE | y | crates/chio-hosted-mcp/tests/cross_crate_pipeline.rs | n-a | 13 | chio-hosted-mcp extraction landed in trj3.2; lib.rs is pure pub-use of published library APIs; cross-crate pipeline test exercises real runtime path |
| close-bar-#21 | Provider-adapter-core extracted; existing 7 adapters refactored to consume it | NONE | n | NONE | n-a | 13 | chio-provider-adapter-core not yet a crate; 7 adapters still cookie-cutter |
| close-bar-#22 | Cargo-vet exemption count: no net-new during trj4; top-50 burn-down (target: 819 -> <= 769) | PARTIAL | n | NONE | n-a | 13 | exemption count 819 today; no net-new gate not yet in CI; top-50 burn-down not yet started |
| close-bar-#23 | T1 Evidence Gate enforced for every T1.x slice (PROTOCOL.md, schemas, claim registry, proof manifest, theorem inventory, proof report, negative conformance test) | NONE | n | NONE | n-a | 16 | spec/registries/* present; per-T1 slice gate enforcement comes online with each slice close |
| close-bar-#24 | chio-metrics-spec workspace-wide registry live; alert pack deployed (T1.5) | NONE | n | NONE | n-a | 06 | chio-metrics-spec crate not yet authored |
| close-bar-#25 | chio-log-redact enforces redaction at log layer with compile-time redacted!() macro (T1.5) | NONE | n | NONE | n-a | 06 | chio-log-redact crate not yet authored; redacted!() macro not yet defined |
| close-bar-#26 | chio explain <receipt-id> CLI ships and renders DAG + attenuation chain + batch witness + repair hint | NONE | n | NONE | n-a | 08 | chio explain CLI subcommand not yet a binary; T1.6 work |
| close-bar-#27 | KernelTrustExchange accepts generic SigningBackend; HybridBackend works in federation handshake | PARTIAL | n | NONE | n-a | 07 | KernelTrustExchange currently stores concrete Keypair; HybridBackend type exists |
| close-bar-#28 | Capability-token schema adds hybrid algorithm; wire-format encoder/decoder paths first-class | NONE | n | NONE | n-a | 07 | spec/schemas/chio-wire/v1/capability/token.schema.json algorithm enum still ed25519/p256/p384 |
| close-bar-#29 | Conformance-tier handshake gating live; tier derived from substrate evidence | NONE | n | NONE | n-a | 09 | FederationPeer.conformance_tier field not yet defined |
| close-bar-#30 | Cross-surface conformance suite passes on MCP wrapped, hosted/native, and A2A/HTTP - deny receipts emit, lineage preserved, revocation propagates, budget enforced, no adapter bypass | NONE | n | NONE | n-a | 10 | cross-surface conformance suite not yet authored across MCP/hosted/native/A2A/HTTP |
