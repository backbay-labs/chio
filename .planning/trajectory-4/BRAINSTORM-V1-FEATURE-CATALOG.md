# Trajectory-4 Brainstorm v1: Comprehensive Feature Catalog

**Companion to** `SYNTHESIS-V2-INTEGRATED-PLAN.md`.

**Source**: 9 parallel brainstorm agents covering DX, perf/scale, capability-extension, protocol-evolution, AI-frontier, TEE/HW, trust-graph, observability/SRE, codebase-archaeology. Each agent produced ~700-900 word position papers with per-proposal effort (S/M/L/XL) and impact (1-5 stars) ratings. **This catalog records every proposal, not only the top picks per agent**, so trj4 scope-lock can pull from the full surface.

For ideas explicitly rejected by their proposing agent, see `REJECTED-IDEAS.md`.

## Workspace ground truth (corrections from archaeology)

| Claim in prior planning | Actual |
|---|---|
| 119 workspace members | **89 chio-* crates** + xtask + bench/* + tests/* + formal/* + editors/zed-chio + 2 integrations + 7 examples |
| cargo-vet exemptions 26 -> 179 | **819** (767 `safe-to-deploy` + 52 `safe-to-run`) |
| Threat-model 17 of 17 covered | **20 threats**, gate-state per `scripts/check-threat-coverage.sh` on the trj4-planning branch: **PASS at 11 covered / 9 pending-with-`deferred_to` / 0 uncovered**. The 9 pending split into 6 `unimplemented!()` stub files (`agent_velocity_abuse`, `behavioral_sequence_attack`, `cumulative_data_exfiltration`, `pii_phi_exposure`, `ssrf_via_http_substrate`, `wasm_guard_resource_exhaustion`) plus 3 mobile rows (`mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`) all carrying `deferred_to: trajectory-4.M07.real-attestation`. Of the 11 covered, `pq_signature_downgrade` and `tee_quote_forgery` carry `covered_by_tests`; only `weights_hash_spoof` is `coverage_state: covered` with neither `covered_by_tests` nor `coveredBy` linkage. The trj4 work is to flip the 9 pending rows to covered and add the missing test linkage. |
| `crates/chio-tee/` is TEE attestation | **`chio-tee/` is the streaming-tap crate**; TEE attestation lives in `chio-attest-verify` (TDX + SEV-SNP + Nitro already implemented). Naming collision worth flagging. |
| `chio-core` is the core crate | `chio-core` is a 12-line `pub use` umbrella; `chio-core-types` (35 KLOC, 112 in-tree dependents) is the real substrate |

## Cross-cutting convergence

### 4-way consensus: macaroon-style capability attenuation

| Lens | Proposal |
|---|---|
| Capability-extension | C-3 CapabilityAttenuationGuard with typed caveats |
| AI-frontier | A-2 Durable Agent Identity with Attenuated Sub-Agent Capabilities |
| Protocol-evolution | P-2 Macaroon-style first-party caveats on capabilities |
| Trust-graph | T-1 Scoped attenuated cross-org delegation tokens |

**Strongest cross-cutting recommendation in the brainstorm.** The authority-bearing primitives already exist behind a `delegation_v2` feature gate: `CapabilityToken.delegation_chain`, `Attenuation` and `ScopeAttenuation` step structures (`crates/chio-core-types/src/delegation_receipt.rs:63-110`), `validate_attenuation` (`crates/chio-core-types/src/capability.rs:2452`), `validate_delegation_chain`. Promoting them through the negotiated `chio.capability.v2` schema with on-the-wire `attenuation_proof` is the multi-agent safety keystone, the federation delegation primitive, the protocol forward-compat lever, and the runtime guard preventing sub-agents from re-amplifying parent privileges. The `chio-a2a-edge` `caveats: Vec<String>` strings flagged in earlier rounds are advisory bridge-fidelity prose documenting what the A2A protocol cannot project; they are **not** authority-bearing primitives and not what T1.1 promotes.

### 2-way consensus: anchor-batch Merkle trees

| Lens | Proposal |
|---|---|
| Perf-scale | S-2 Coalesced PQ signing with Merkle batching |
| Protocol-evolution | P-4 Anchor-batch Merkle trees with public-witness checkpoints |

Same primitive, different motivations: CPU savings (ML-DSA-65 sign cost 200-400us; ~2 cores burned at 5k receipts/sec) vs evidence support for the `audit_only` / `transparency_preview` claim ceiling at PROTOCOL.md:657. Mirrors existing `chio-anchor` checkpoint Merkle batching at `chio-anchor/src/lib.rs:113-144`. **Framing per reviewer rounds**: this is *additive* over per-receipt signing, not a replacement; the immediate local receipt remains independently verifiable. The artifact alone **moves toward closure** of the publication / anti-equivocation / claim-completeness ceiling but does not by itself close it. SYNTHESIS-V2 T1.3 lists the Evidence Gate work that is required for closure: claim-registry update, proof-manifest update, public-witness semantics doc, and negative conformance tests for forged root, mis-ordered inclusion proof, witness-lane impersonation, and stale-witness fallback.

### Other convergence threads

- **Hybrid PQ as plumbing, not invention** (trust-graph T-8): `HybridBackend` exists in `chio-core-types::pq`; signature wire format already declared in `signature.v1.json` (algorithm enum `["ed25519","p256","p384","hybrid"]`; wire-value strings of the form `hybrid:<classical>:<pq>:<alg_set>`); `KernelTrustExchange` stores a concrete local `Keypair` and needs to accept generic `SigningBackend`. The capability-token schema (`spec/schemas/chio-wire/v1/capability/token.schema.json`) currently only enumerates `["ed25519","p256","p384"]` and is missing the `hybrid` variant; T2.1 adds it plus wire-pattern updates so the hybrid prefix is accepted on `issuer` / `subject` / signature fields.
- **Workspace-public surfaces with no dependents** (archaeology X-3): `chio-tower` (2738 LOC), `chio-envoy-ext-authz` (1434), `chio-ag-ui-proxy` (830), `chio-openapi-mcp-bridge` (815). Either ship example wiring or demote to `integrations/`.
- **Threat-model coverage gate is built and PASS at 11 covered / 9 pending-with-`deferred_to` / 0 uncovered** (archaeology + observability): the gate keys on `coverage_state` (not `coveredBy`); the 9 pending split into 6 `unimplemented!()` stubs and 3 mobile rows whose `deferred_to` already points at `trajectory-4.M07.real-attestation`. Concrete trj4 work to claim 100%: fill 6 stubs, land 3 mobile tests (Tier 0 Phase C), add `covered_by_tests` linkage to `weights_hash_spoof`.
- **Multi-modal / agentic-browser gap** (AI-frontier A-5, capability C-1): browser/mobile kernels are stubs (clock + rng only); current `ToolInvocation::arguments: Vec<u8>` for canonical JSON only.
- **Receipt explanation surface** (DX-2 + AI-frontier A-12): both lenses propose the same primitive - a tool that walks a receipt's policy clauses, guards, scope, parent chain, and produces human-readable rationale. CLI `chio explain` first; web explorer (DX-3) later.

---

## Lens 1: Developer experience (12 proposals)

### Top 3 bets per the DX agent

**DX-1. `chio init` interactive shape picker + verified golden-path templates** - M, *****
The current template at `crates/chio-cli/templates/init/` is a single skeleton. Replace with an interactive picker (mcp-server / fastapi-tenant / bedrock-tool / a2a-edge / langchain-app) that emits a project that builds + passes its own smoke on first try. Tied to existing `examples/hello-*` smokes so templates stay green automatically.

**DX-2. `chio explain <receipt-id>` deep narrator** - M, *****
Receipts are the unit of debugging in Chio but today an integrator stares at JSON. `chio explain rcpt_…` should print: which policy clause matched, which guards fired, scope diff, parent receipt, signed root, repair hint if denied. This single command replaces 80% of "why did my call fail" Slack threads.

**DX-3. Receipt-chain explorer (web)** - L, *****
A single-binary `chio ui receipts` opens a local web view of a receipt store with chain navigation, filter by policy clause, side-by-side policy diff, time-travel. Flagship demos already produce hundreds of receipts per smoke run; nobody is reading them today.

### Other DX proposals

**DX-4. In-process kernel for SDK tests + golden-receipt assertions** - M, ****
Ship `chio_kernel::testing::InProcessKernel` (Rust) + language-equivalents for Python, TS, Go, JVM with `assert_receipt_matches!(golden, actual)` helpers ignoring timestamps/nonces. Cuts new-SDK-feature dev loops minutes -> milliseconds.

**DX-5. Polish vscode-chio + zed-chio extensions to publishable quality** - M, ****
Today they are LSP wrappers. Add: receipt-id codelens that opens explorer, guard DSL playground command, `chio doctor` runner, snippets matching `editors/snippets/`. Publish to marketplaces. Cheapest way to make the LSP investment visible.

**DX-6. `chio doctor` upgrade with repair suggestions** - S, ****
`crates/chio-cli/src/doctor/` already probes toolchain/cosign/oci/otel. Make every failure print copy-pasteable fix. Add `--fix` for safe ones (re-fetch trust roots, regenerate dev keys, prune stale fixtures). 80/20 win on first-week frustration.

**DX-7. Mock kernel + fixture-replay harness with hot-reload (`chio dev`)** - L, ****
`chio dev` watches `chio.yaml`, policies, manifests, fixtures; on change, re-runs deny/allow expectations against the in-process kernel and prints one-line green/red. Today the loop is "edit, restart agent, re-run smoke."

**DX-8. SDK idiomatic-pass: Python + TypeScript first** - L, ****
`sdks/python/chio-sdk-python/` and `sdks/typescript/packages/` are mostly thin RPC. Add typed policy decorators (`@chio.governed(scope="...")`), pytest plugin with auto-fixture replay, TS `chio.test()` Vitest helper, idiomatic error types with `.repair_hint`.

**DX-9. Error catalog with stable codes + repair hints** - M, ****
Assign every error a stable `CHIO-EXXXX` code. One-line repair hint per code. Generate browsable `docs/reference/errors/` from source of truth. LSP diagnostics deep-link to catalog.

**DX-10. `chio diff` for policies, manifests, trust roots** - S, ***
Semantic diff (not textual) of two policy versions: which calls newly allow, which newly deny, which scope changes are widening. One weekend; changes how reviewers read PRs.

**DX-11. End-to-end demo apps that someone could actually deploy** - XL, ***
Build one polished healthcare-tenant demo (FastAPI + Chio + receipts + dashboard) in `examples/demo-healthcare/` with `docker compose up`. Reference, not a feature; no integrator believes a runtime works until they see one.

**DX-12. `chio trace <session>` + OTel-receipts bridge** - M, ***
Stream a session's tool calls + receipts as an OTel trace into Jaeger/Tempo. `sdks/python/chio-observability` is the seed. A flame graph of governed calls is the most powerful debugger we are not shipping.

---

## Lens 2: Performance and scale (12 proposals)

### Top 3 bets per the perf-scale agent

**S-1. Dispatch profile baseline + flame-graph CI artifact** - S, *****
M06 audit doc admits the dhat harness still measures the placeholder dispatch probe rather than the real path. Flying blind. `cargo flamegraph` artifact uploaded per merge to main from `dispatch_allow` bench; `pprof-rs` emits folded-stack file gated on `cfg(profile)`. KPI: top-5 frames named in `releases.toml` and tracked PR-over-PR.

**S-2. Coalesced PQ signing with Merkle batching at receipt boundary** - L, *****
M06 explicitly excluded chain-coalesced signing, deferring to M09. ML-DSA-65 sign cost ~200-400us; at 5k receipts/sec single-node = ~2 cores burned on signing. Mirror anchor checkpoint Merkle batching: build a tree over N receipts, sign once, attach inclusion proof per receipt. **Reframing per reviewer**: this is *additive* over per-receipt signatures, not a replacement; immediate local receipt remains verifiable.

**S-3. Mediator hot-path lock-free verdict cache** - M, ****
**Reviewer revised key spec**: cache key must be a **fully-specified composite** including cap_hash + scope + tool + guard-set hash + policy version + tenant/agent identity + caveat state + revocation epoch + trust-root epoch. Auto-invalidated on any component change. Targets <5us p99 on hit vs ~50us SLO. **Caution**: cache pure preflight decisions only with a fully specified invalidation contract; profile (S-1) first.

### Other perf proposals

**S-4. Anchor publication aggregator with adaptive flush** - M, ****
EVM gas + Bitcoin block time make per-checkpoint anchoring uneconomic. Publish one Merkle root spanning M checkpoints with deadline-driven flush. `chio_anchor_publish_batch_size`, `chio_anchor_publish_lag_ms` p95 < 60s.

**S-5. TEE evaluator zero-copy chio-tee-frame with shared-memory transport** - L, ***
For SGX/TDX a vsock-or-shmem transport with `Arc<CanonicalBytes>` slicing skips a copy in/out per receipt. New `tee_roundtrip_p99` bench; target overhead vs host < 25%; current is unknown.

**S-6. Revocation oracle: rs_merkle re-hash → incremental sparse Merkle delta** - M, ***
`crates/chio-revocation-oracle/src/sparse_merkle.rs` uses `rs_merkle::MerkleProof<Sha256>` with `layers: Vec<Vec<[u8;32]>>` - full re-layer on insert. At >1M revoked keys = O(n log n) per epoch. Switch to incremental Merkle Patricia / true sparse trie at O(log n) per update.

**S-7. Tower service backpressure + load-shed middleware** - S, ****
`crates/chio-tower/src/service.rs` (355 lines) - no shedding, no concurrency limit. At saturation the M06 receipt-signing channel blocks producers. Tower already provides `LoadShed` and `ConcurrencyLimit` layers; translate the block into 503/Retry-After before connections pile up.

**S-8. Per-tenant warm-ring autoscaling on guard pool** - M, ***
M06.P4.T3 ring buffer is fixed-capacity per tenant. With 100 tenants and skewed traffic, hot tenants evict cold tenants' instances. Adaptive ring sizing keyed on per-tenant call rate (EWMA).

**S-9. Differential perf fuzzing across kernel ports** - M, ***
`chio-kernel`, `chio-kernel-browser`, `chio-kernel-mobile`, `chio-kernel-core`, `chio-cpp-kernel-ffi` share dispatch path. Same fixture corpus through each port; flag >N% divergence. Catches port-specific regressions (e.g. wasm cold-start in browser).

**S-10. Sampling-aware OTEL exporter** - S, **
OTEL ingress already counts drops. Probabilistic sampling pre-exporter with `chio_otel_sample_rate` gauge gives operators a knob; head-based at high rate so dashboard never sees drops while keeping per-trace fidelity.

**S-11. Receipt cold-tier (S3) with hot SQLite + bloom-filter lookup** - L, ***
Receipt history grows unbounded. Move > 30 days to columnar parquet on object storage; in-process bloom answers existence queries without round-trip. Maps to "storage tiers: hot/warm/cold."

**S-12. Continuous benchmark dashboard + budget gates** - S, ****
Bench-regression gate is at PR level (10% diff) but no longitudinal dashboard. Drift over months is invisible. Push criterion JSON to small DB + Grafana panel; budget gates per metric in `releases.toml`.

### Existing bottlenecks no one is currently addressing (perf-scale agent commentary)

- No flame graph for `dispatch_allow` (audit doc concedes dhat measures placeholder)
- PQ-signing CPU is uncosted (no `pq_sign` bench)
- Anchor publication latency unmeasured (no `chio-anchor` bench)
- Tower edge has no shed
- TEE overhead unmeasured
- Sustained p99 nightly hasn't yet hit M06's required "seven consecutive greens"

---

## Lens 3: Capability extension (13 proposals)

### Top 3 bets per the capability agent

**C-3. CapabilityAttenuationGuard with typed caveats (4-way consensus keystone)** - L, *****
The substrate already has `CapabilityToken.delegation_chain`, `Attenuation` step structure (`crates/chio-core-types/src/delegation_receipt.rs:63-110`), `validate_attenuation` (`crates/chio-core-types/src/capability.rs:2452`), and `validate_delegation_chain`, all behind a `delegation_v2` feature gate. T1.1 in SYNTHESIS-V2 promotes these to default-on through the negotiated `chio.capability.v2` schema and lifts `Attenuation`/`ScopeAttenuation` into first-class wire fields. **Note (round-5 correction)**: the on-the-wire `attenuation_proof` is **not** something `validate_attenuation` already produces - the existing helper only checks `child.is_subset_of(parent)` and returns `Ok(())` or `Err`. T1.1 must add new `compute_attenuation_witness` / `verify_attenuation_witness` APIs alongside the existing checker; the `attenuation_proof` field carries that witness on the wire. The advisory `caveats: Vec<String>` strings in `chio-a2a-edge` are bridge-fidelity prose, not authority, and stay advisory; they are not what C-3 / T1.1 promotes. New typed-caveat language for the v2 token (e.g. `{op:"restrict_tool", arg:"fs.write"}`, `{op:"bind_session", arg: sess_id}`) ships in `chio-policy/src/capability.rs`; runtime enforcement uses the existing `validate_attenuation` plus the new witness-verification path. **Protocol bump.**

**C-7 + C-8. Structured-PII + Code-Secrets redactor packs** - L + M, ****
Default redactor is regex-only. C-7: FHIR Patient.identifier, US-Core, ISO-20022 IBAN/BIC, GDPR Article-9 special-categories. C-8: GitHub PATs, Slack tokens, Azure SAS, GCP service-account JSON, npm tokens, HuggingFace tokens, Anthropic `sk-ant-*`, OpenAI keys. New `crates/chio-data-guards/redactors/{structured,secrets}/`. Additive `RedactClass` flags; zero protocol risk.

**C-13. TransparencyLogReceiptExporter (Rekor-style)** - L, ****
Append-only public log of redacted receipts. `pub trait TransparencyLog { fn append(&self, redacted: &Receipt) -> LogProof; fn verify_inclusion(...) -> bool; }` with default `RekorClient` impl. New `crates/chio-transparency-log/`; hooks in `chio-eval-receipt/src/export.rs`. Strategic moat; foundation already in tree.

### Other capability proposals

**C-1. ML-shim PromptInjectionGuard (classifier-backed)** - L, *****
Heuristic `prompt_injection.rs` misses paraphrased / multilingual / encoded attacks. Pluggable trait `InjectionClassifier { fn score(&self, text:&str) -> f32 }` with default ONNX/candle impl in `chio-wasm-guards` for sandboxed inference. Advisory severity, promoted via existing `PromotionPolicy`.

**C-2. AgentLoopBoundsGuard** - S, ****
Velocity guards rate-limit calls; nothing bounds recursion depth, fan-out, or wall-clock per session. Top operational risk for multi-agent. `LoopBoundsGuard { max_depth: u8, max_fanout: u16, max_wall_seconds: u32, max_total_subcalls: u32 }`. Reads from session journal `tool_sequence`.

**C-4. SubAgentBudgetPropagation** - M, ****
`chio-store-sqlite/src/budget_store.rs` tracks budget but doesn't split across delegated sub-agents. Without this, parent's $5 cap can be multiplied 10x by 10 children. **Reviewer correction**: replace `BudgetSplit::PerChildShare(f32)` with **fixed-point integer units (basis points or micros)**; floats inside signed/canonical authority artifacts are a footgun. **Protocol bump.**

**C-5. McpToolNamespacePinningGuard** - S, ****
`mcp_tool.rs` allowlists tool names but MCP servers can rename or shadow tools. Pin to `(server_id, tool_id, manifest_hash)` to block tool-substitution attacks.

**C-6. McpToolArgSchemaGuard** - S, ***
Guards inspect names not schemas. Validate tool args against JSON-Schema declared in MCP manifest pre-dispatch. Reuse `chio-spec-validate`.

**C-9. JailbreakPatternScanner with tracked corpus** - M, ***
`jailbreak_detector.rs` is single-file regex. Corpus-backed scanner that hot-reloads from `chio-replay-corpus` enables shipping signature updates without a release.

**C-10. RoleAndTenantPolicyConditions** - M, ****
`chio-policy/src/conditions.rs` has time-window + context-match but lacks `role_in: [...]`, `tenant_quota_remaining > X`, `geo_in: [country_codes]`. Most-asked-for primitives in real deployments. `Condition::Role { in: Vec<String> }`, `Condition::Geo { allowed: Vec<CountryCode>, source: GeoSource }`, `Condition::TenantQuota { metric, op, threshold }`.

**C-11. ToolAdapter expansion: xAI Grok, DeepSeek, OpenRouter, Together** - M, ***
Eight vendors covered; long tail (Grok, DeepSeek-R1, OpenRouter aggregator, Together, Replicate) ships without a Chio path. OpenRouter especially leveraged because it fronts dozens of models. New `crates/chio-{xai,deepseek,openrouter,together}-tools-adapter/` mirroring `chio-mistral-tools-adapter`.

**C-12. Bedrock IAM-principal scoped guards** - S, ***
`chio-bedrock-converse-adapter/src/iam_principals.rs` exists but no guard enforces "this principal can only call model X." Dedicated `BedrockPrincipalGuard` closes the loop.

---

## Lens 4: Protocol evolution (12 proposals)

### Top 3 bets per the protocol agent

**P-11. Capability-negotiation handshake (`chio.capabilities.v1`)** - S, ****
**Reviewer-elevated to T1 ahead of caveats.** `spec/versions/chio-protocol-negotiation.v1.json` only negotiates wire version via exact-match. Capability bitset/feature-list at handshake unlocks every additive proposal here without flag-day breakage. Peer that does not advertise stays on v1.x defaults.

**P-1 + P-2. Schema-tag the `CapabilityToken` + macaroon caveats** - S + L, *****
P-1: `CapabilityToken` is the only major signed artifact lacking a `schema` field; this single gap blocks forward versioning and prevents the "unknown schema rejected" rule from firing. P-2: typed caveat list lets verifiers attenuate at presentation without re-issuance and lets adapters add transport-bound caveats (e.g., `cnf=dpop`). **Both must ship before or atomic with caveats per reviewer.**

**P-4. Anchor-batch Merkle trees with public-witness checkpoints** - M, *****
PROTOCOL.md:635-641 admits checkpoints support `audit_only` and `transparency_preview` only. Web3 anchor lanes (`chio-anchor` for EVM, OpenTimestamps, Solana memo) anchor individual checkpoints, not aggregated batches. New artifact `chio.anchor_batch.v1` carrying `{tree_root, checkpoint_ids[], witness: rekor|ots|solana_memo}`. **Reframing per reviewer**: per-receipt local sign stays; batch root is *additional* upgrade for continuity + non-repudiation.

### Other protocol proposals

**P-3. Streaming receipts (`chio.stream_receipt.v1`)** - M, ****
`tool_call_chunk` is a wire frame but receipts emit only at terminal state. Long-running tools / SSE flows have no signed mid-stream evidence; `Cancelled`/`Incomplete` is the only mid-stream signal. Streaming receipt with `chunk_index`, `running_content_hash` (rolling), `final_continuation_id`. v1.x additive.

**P-5. Branched lineage (multi-parent receipts)** - M, ****
`EdgeKind::ReceiptLineageParent` is single-parent. Sub-agent fan-in cannot be honestly modeled - second parent is silently asserted. Add `parent_receipt_ids: Vec<String>` to `chio.receipt_lineage_statement.v2`.

**P-6. Federation handshake: post-quantum hybrid by default + SAS auth** - L, *****
`signature.v1.json:12` already declares hybrid format. Federation handshake (`chio-federation/src/{bilateral,trust_establishment}.rs`) is the cleanest place to require hybrid-by-default and add Short Authentication String (SAS) verification for first-touch out-of-band confirmation.

**P-7. Verifier capability profiles** - S, ***
PROTOCOL.md rules require seven verification steps. Lightweight verifiers (mobile, edge) cannot afford full delegation-chain + revocation + DPoP. Define `verifier.profile.v1: { full | revocation_skipped | structural_only }`. Connects to `P10 report truthfulness`.

**P-8. Delegation attenuation proofs (P1 in receipts)** - M, ***
P1 is mechanically checked in Lean but a presented receipt does not carry the attenuation witness. Embed precomputed `attenuation_witness: { parent_scope_hash, child_scope_hash, normalized_subset_proof }` in capability so remote verifiers skip scope normalization.

**P-9. Redaction-preserving signatures on receipts** - XL, ****
Privacy export today must reveal `action.parameter_hash`-bound parameters or strip them and produce non-verifiable receipt. Merkle commitment over receipt fields lets each be redacted with proof of original-position. `field_commitments: { name -> hash }` plus existing top-level `signature`. **v2 breaking** (changes canonical signing input).

**P-10. Hybrid logical clocks for `timestamp` + clock attestation** - M, ***
Receipts carry single `timestamp`. Threat model already covers `clock_rewound`. Adversarial cases would benefit from HLC `(wall_seconds, logical, kernel_id)` tuple plus optional `clock_attestation` evidence kind (Roughtime / TPM tick).

**P-12. Threat-model schema v2 with structured `mitigations`** - M, ****
`spec/security/chio-threat-model.v1.json` has `mitigations[].control` as free-text. v2: `mitigations[].control = { kind: "code"|"policy"|"crypto", refs: [{file, symbol}], evidence_kind: "kani"|"lean"|"diff_test"|"adversarial_case" }`. Makes `chio-spec-validate` a real CI gate over claim-vs-evidence drift.

---

## Lens 5: AI-frontier (15 proposals)

### Top 4 "moves Chio from policy mediator to AI-trust infrastructure" per the AI-frontier agent

**A-5. Multi-Modal Receipt Envelopes (Image/Audio/Video/Screen)** - XL, *****
Computer-use and agentic-browser are exploding; `chio-kernel-browser` is a stub. Define `ToolInvocation::arguments_blob_ref` and `tool_output_blob_ref` with content-addressed hash + per-receipt redaction at vision layer (PII boxes elided before signing). Receipt commits to post-redaction blob hash; unredacted blob in sealed lane. **Protocol bump.**

**A-1. Multi-Agent Receipt DAG with Fork/Join Semantics** - L, *****
`parent_receipt_id` is a tree, not a DAG. Real agent graphs join (map-reduce sub-agents). Add `fan_out_id`, `join_receipt_id`, `siblings[]`. **Reviewer requires tightening formal model**: define node IDs, parent-set hashes, acyclicity invariants, fanout limits, join semantics, and replay rules; the originally-proposed sliding `recent_chain_signatures` loop guard is too local for what it protects.

**A-4. Agentic-Deception Detector via Plan-vs-Action Diff** - L, *****
Sleeper-agent and reward-hacking research is the safety frontier. If agent emits stated plan and a sub-receipt path executes a different tool family, that diff is high-signal. Plans already in tool-output; need typed `stated_plan` envelope and a guard that diffs against the receipt DAG of same `chain_id`.

**A-2. Durable Agent Identity with Attenuated Sub-Agent Capabilities (4-way consensus)** - M, *****
`chio-listing/authority.rs` and `chio-credentials` give primitives but capability tokens lack first-class attenuation when an agent forks a sub-agent. `derived_from`, `attenuation_proof` on capability; verifier rule that derived caps must be `subset(parent.scope)`.

### Other AI-frontier proposals

**A-3. Prompt-Injection Heuristic Guard Tier (`chio-guards-injection`)** - M, *****
`chio-arena/adversary/prompt_injection.rs` produces attacks; no symmetric guard. Heuristic family flagging untrusted-content tag boundary violations, per-agent baseline anomaly (token-distribution drift on sliding window), instruction-takeover keywords. ML version later.

**A-6. RAG Citation Attestation (Retrieved-Doc-to-Output-Span)** - L, ****
"Which retrieved chunk influenced which output span" is the open question for trustworthy RAG. `retrieval_evidence` field listing `(doc_hash, chunk_offset, span_in_output_token_range)` so verifier can re-execute retrieval and re-bind the citation.

**A-7. Per-Receipt Output Watermarking** - L, ****
Output provenance is the missing third leg of trust triangle (input receipt + model card + output watermark). Bind deterministic watermark seed `H(receipt_id || agent_id || timestamp)` either via cryptographic-text steganography or content-hash registration. Detector verifies via receipt log.

**A-8. Cross-Model Lineage / Mid-Conversation Model Swap Attestation** - M, ****
Frontier orchestrators swap models per turn. `chio-weights` does train-time M-class lineage; add inference-class `model_segment` array on receipt: each segment has `(token_range, model_card_id, weight_attestation_id)`.

**A-9. Capability-Aware Least-Privilege Agent Routing** - M, ****
Listings (`chio-listing`, `chio-market`) advertise capabilities. New `chio-router` crate that picks the minimum-scope agent from the marketplace.

**A-10. Capability-Checked Memory Access (Agent-Memory Governance)** - M, *****
`memory_provenance_store` is an append-only chain but access path is unrestricted. Persistent agent memory needs scoped read/write capabilities (`memory.scope:project_x`, `memory.read`, `memory.write_append`, `memory.forget`).

**A-11. Trustworthy Agent Marketplace v2: Conformance-Attested Agent Definitions** - L, *****
v2 needs signed `AgentDefinition` artifacts with `(adversarial_suite_pass_set, declared_capability_set, sandbox_evidence_id, weight_attestation)`. Marketplace listing failing the conformance suite is unlistable.

**A-12. Tool-Use Chain Audit / Why-Was-This-Called Trace** - S, ****
Auditor's first question. Receipt DAG knows parent receipts; combine with planner output (A-4) and user-instruction anchor to render deterministic trace: `user_msg -> plan_id -> sub_agent_id -> tool_call_id`. Mostly there; what's missing is a `chio-explain` crate that renders it. Pairs with DX-2.

**A-13. Agent Reputation Chain Extending Per-Agent Identity** - M, ***
`chio-reputation` is per-org. Per-agent durable-identity reputation (signed verdict aggregates over receipt DAGs) lets the marketplace and router (A-9) penalize agents tripping guards more often than baseline.

**A-14. Adversarial-Robustness Conformance Class** - M, ****
`chio-adversarial-suite` and `chio-arena` produce attacks; turn into a tiered conformance class an agent or guard must pass to claim `prompt_injection_resistant_v1`. Same shape as PCI-DSS levels.

**A-15. Loop-Detection Across Agent Graphs (Cycle Detection on Receipt DAG)** - S, ***
Multi-agent systems hit livelocks (A asks B asks A...). Original brainstorm proposal: kernel carries a sliding `recent_chain_signatures` set in the call-chain envelope and fails closed if a sub-agent's request normalizes to a previously-issued signature. **Reviewer follow-up**: that signature-set is local to one kernel and breaks cross-kernel; SYNTHESIS-V2 T1.2 replaces it with a signed `dag_ordinal` + HLC triple per receipt and the predicate `child.dag_ordinal > max(parent.dag_ordinal)`, which gives the same property without depending on a single kernel clock domain.

---

## Lens 6: TEE / hardware-attestation (12 proposals)

**Critical archaeology correction**: TDX, SEV-SNP, and Nitro are already implemented in `chio-attest-verify` with `QuoteVerifier` trait + `report_data = SHA256(kernel_pk_hex || receipt_root)` binding + `non_exhaustive` `TeeKind`. The trj4 work is *new* backends.

### Top 3 bets per the TEE agent

**H-1. Apple Secure Enclave kernel-key backend (`chio-custody-hw-secure-enclave`)** - M, *****
Desktop chio-cli users hold kernel signing material as raw bytes today. Sealing to SEP via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` + Touch ID gating produces hardware-rooted kernel signatures on every Mac. Apple's SEP attestation (`SecKeyCreateAttestation`) gives a P-256 chain back to Apple's root. Reuses `apple_root.rs` from App Attest.

**H-3 + H-4. Azure MAA + GCP Confidential Space bridges (combined)** - S, ****
H-3: Azure CVMs hand JWT from MAA service; thin verifier validates RS256 against MAA JWKS, pulls inner SEV-SNP/TDX quote claims, re-runs existing verifiers. H-4: GCP attestation tokens are OIDC-shaped (`https://confidentialcomputing.googleapis.com`); validate against Google JWKS, treat `eat_nonce` as `report_data`. Both reuse `josekit`/JWT plumbing.

**H-7. RATS RFC 9334 evidence envelope (`chio-attest-evidence`)** - M, ****
Today every backend takes raw bytes. EAT-shaped JSON/CBOR envelope (`eat_profile`, `nonce`, `evidence`) lets kernel ship one carrier across TDX/SEV-SNP/Nitro/TPM/Azure-MAA. Verifier dispatches on `eat_profile`. Aligns with NIST/IETF expectations; pairs with H-11.

### Other TEE proposals

**H-2. TPM 2.0 quote backend (`chio-attest-verify::tpm`)** - L, ****
Self-hosted Linux/Windows servers have TPM but no AMD/Intel confidential VM. PCR quote (`TPM2_Quote`) bound to AIK with EK-credential chain to manufacturer roots (Infineon, STMicro, NationZ). Bind `report_data` via `qualifyingData` (max 64 bytes - matches our shape).

**H-5. AWS Nitro PCR-set policy + freshness window** - S, ****
Existing `nitro.rs` checks PCR0 only. PCR1 (kernel cmdline) and PCR8 (image cert) are the standard production set. `NitroPcrPolicy { pcr0, pcr1?, pcr2?, pcr8? }` and `max_age: Duration` enforced against document `timestamp`. Closes a real gap.

**H-6. WebAuthn hardware-token claim binding** - M, ****
`PasskeyVerifier` exists. Extend `PasskeyCapability` with optional `attested_authenticator_aaguid` via WebAuthn attestation statement; accept FIDO MDS-published roots so a tenant policy can require a hardware authenticator (not synced passkey).

**H-8. Attestation freshness oracle + cache (`chio-attest-cache`)** - M, ****
Re-attesting on every receipt is expensive (TDX collateral fetch ~hundreds of ms). Keyed cache `(tee_kind, measurement, report_data) -> VerifiedQuote` with policy-driven TTL. Cache key includes `report_data` so stale entry can't be replayed under new receipt root.

**H-9. TEE breakage / generation-deny list (`chio-attest-verify::deny_list`)** - S, ****
Sigstore-signed JSON enumerating denied `(tee_kind, microcode_version_min, sev_fw_version_min)` ranges, loaded through `TenantPolicyLoader`. Mirrors how ct-log operators publish OUSL.

**H-10. Reproducible-build to TEE-measurement binding** - L, *****
Today PCR0/MRTD/measurement are pinned by an operator string. Tie those to the SLSA provenance Sigstore bundle that built the kernel: pre-launch tool emits `expected_pcr0 = SHA256(canonical_layout(slsa_bundle))`; verifier recomputes from bundle at boot. Closes the loop "the running TEE is the SLSA-attested binary."

**H-11. Cross-cloud attestation router (`chio-attest-router`)** - S after H-7, ****
Operators running Chio across AWS Nitro + Azure SEV-SNP + GCP TDX want one verifier surface. Router accepts EAT envelope (H-7) and dispatches to right backend, returning uniform `VerifiedQuote`. Threat-model `tee_quote_forgery` becomes "covered uniformly."

**H-12. Confidential AI inference quote profile (NVIDIA H100 CC mode)** - XL, **/*****
NVIDIA H100 confidential-compute mode emits attestation report covering GPU device measurement plus CPU TEE quote. `H100Verifier` checks NVIDIA NRAS-signed device cert chain and binds `report_data = SHA256(kernel_pk || receipt_root || gpu_uuid)`. Forward-looking but protocol is published. Impact 2/5 today, 5/5 long-term.

---

## Lens 7: Trust-graph / federation (12 proposals)

### Top 3 bets per the trust-graph agent

**T-2. M-of-N quorum-signed receipts** - M, *****
Generalize `bilateral::DualSignedReceipt` (currently exactly 2-of-2) to `QuorumSignedReceipt { body, signatures: Vec<KernelSig>, threshold: u32 }`. Reuse `CoSigningBody`. Verifier `QuorumPolicy { trust_anchors, threshold }`. Bilateral becomes degenerate case. Unlocks regulated workloads. **Protocol bump** (legacy dual stays as v1 for compat).

**T-1. Scoped attenuated cross-org delegation tokens (4-way consensus)** - M, *****
`FederationDelegationToken` separate from heavyweight `FederationActivationExchangeArtifact`. Short-lived, scoped, revocable, attenuation-only bearer signed by delegator's kernel key. Carries `(delegator_did, delegate_did, scope_namespace, allowed_actions, expires_at, parent_token_hash, max_remaining_hops)`. Delegate kernel attaches token to receipts so any verifier can re-derive the chain.

**T-3. Trust-anchor rotation ceremony with rotation attestation** - L, *****
`KernelTrustExchange::with_trusted_peer` is set-once. `TrustAnchorRotation { old_key, new_key, effective_at, signed_by_old_key, signed_by_new_key, rotation_attestation_ref }`. `TrustAnchorLedger` replicated across federation peers via existing `chio-anchor` lanes. Without rotation, every federation eventually fails closed when keys age out.

### Other trust-graph proposals

**T-4. Governance attestation onto the trust graph** - M, ****
`GovernanceAttestation { decision_id, governing_charter_ref, voters: Vec<{member_did, vote_signature}>, threshold_met, decision_payload }`. Hooks into `FederationActivationExchangeArtifact::governing_charter_ref` and trust-anchor rotation (T-3). Connects to `chio-governance`.

**T-5. Conformance-tier gating in handshake (Bronze/Silver/Gold)** - S, ****
`FederationPeer.conformance_tier` derived from threat-model coverage + mutation-kill score + Kani harness completeness (data already in `chio-spec-codegen::threat_model` + mutants budget). `QuorumPolicy` can require `min_tier=Silver`.

**T-6. Revocation gossip topology: epidemic + pull-catchup hybrid** - M, ****
Bilateral push is O(N²) at federation scale. Epidemic with K=3 fan-out per tick + LRU loop suppression. Existing `RevocationCatchupRequest` covers gap-fill side. Receivers already drop unverifiable frames fail-closed.

**T-7. Sealed-evidence transfer (cross-org evidence pack)** - L, ****
Redactable evidence bundle proves receipt chain integrity without revealing internals. Build on `chio-kernel::evidence_export::EvidenceExportBundle` plus salted-hash redaction tied via Merkle inclusion to public root recipient already pinned via revocation gossip.

**T-8. Hybrid PQ handshake by default** - S, ***
`HybridBackend` exists in `chio-core-types::pq`; `KernelTrustExchange` stores a concrete `Keypair`; `PublicKey::from_hybrid_parts` already supports hybrid encoding. Make the handshake accept generic `SigningBackend` and add `hybrid` to the capability-token algorithm enum (currently `["ed25519","p256","p384"]`); the wire-value alg-set string `<classical>+<pq>` lives inside the `hybrid:<classical>:<pq>:<alg_set>` self-describing key/signature fields, not in the algorithm enum. **Plumbing, not invention.**

**T-9. DID-bound agent identity in receipts** - M, ****
`did:chio` exists with `RECEIPT_LOG_SERVICE_TYPE` and `PASSPORT_STATUS_SERVICE_TYPE` defined but is not flowed into federation surface. Optional `agent_did: Option<DidChio>` to receipts/cosigning bodies; verifiers resolve to `DidDocument`.

**T-10. Receipt-chain forks/joins across kernels** - L, ****
Today `DualSignedReceipt` is per-receipt. `CrossOrgReceiptJoin { joining_org, joined_org, parent_local_seq, parent_remote_seq, joined_at }` so chain that fans to remote tool and rejoins is anchorable. Reuses `ReceiptInclusionProof`.

**T-11. Reputation/trust score derived from signed evidence** - M, ***
`FederationTrustScore { peer_did, score_bps, derived_from: { receipt_count, gossip_freshness_p95, conformance_tier, time_since_last_anchor_rotation, sybil_corroboration } }`, signed by trust-list publisher. Components exist as separate signals.

**T-12. Cross-cloud anchor bridging via discovery artifact** - M, ***
`CrossCloudAnchorBridge` proves "this same Merkle root is anchored in lane A AND lane B AND lane C" as single discovery artifact in `chio-anchor::discovery`. Federation peer accepts a peer's anchor only if discovery shows >= configured cross-cloud minimum.

---

## Lens 8: Observability / SRE / operability (15 proposals)

### Top 3 bets per the observability agent

**O-1 + O-3. Workspace-wide metric taxonomy (`chio-metrics-spec`) + Prometheus alert/recording rule pack** - M + M, *****
O-1: const-string registry (`chio_kernel_decision_latency_seconds`, `chio_receipt_write_total{outcome}`, `chio_guard_evaluations_total{guard,outcome}`, `chio_capability_revocation_lag_seconds`, `chio_anchor_round_latency_seconds`, `chio_federation_hop_total{result}`, `chio_dlq_depth{exporter}`). Compile-time enforced via `describe!` macro + golden snapshot. O-3: burn-rate alerts (14.4x/1h + 6x/6h dual-window per Google SRE workbook) for each SLO. Recording rules `chio:decision_latency:histogram_quantile_p95_5m`, `chio:receipt_write_error_ratio_5m`. Alerts named `ChioReceiptWriteErrorBudgetBurn1h`, `ChioFailOpenSuspected`. Routes to OpsGenie/PagerDuty already wired.

**O-2. W3C trace-context propagation across receipts, anchors, federation** - L, *****
`chio-kernel/src/otel.rs` defines `gen_ai.tool.call` semconv but `traceparent`/`tracestate` not in `chio-federation` or `chio-anchor`. `chio-trace` crate wrapping `opentelemetry::propagation::TraceContextPropagator`; embeds `traceparent` in receipt headers (signed but not authenticated, like AWS X-Amzn-Trace-Id); passes through federation hops.

**O-14. Structured-log redaction layer (`chio-log-redact`)** - M, *****
`phi-policy.md` warns never to log PHI, but enforcement is reviewer-vigilance. `tracing_subscriber::Layer` runs every log event through receipt's redaction tree. `redacted!("payload", payload)` rejects raw-string formatting. Eliminates an entire class of P0 (PHI in PagerDuty).

### Other SRE proposals

**O-4. Deep-health endpoint with kernel-integrity probe** - M, ****
`/livez` cheap (200 if process up), `/readyz` verifies policy load + capability store + anchor round-trip + receipt store writable, `/health/deep` verifies kernel hash matches expected (ties to `m05-freeze-guard.yml`), runs synthetic mediated tool call, confirms guards return deterministic verdicts. `/startupz` gates traffic until first policy reconciliation.

**O-5. Per-tenant rate limit + noisy-neighbor cap in kernel** - M, ****
`chio-siem/src/ratelimit.rs` is exporter-side only. Token-bucket per tenant in `chio-kernel-core`. Surface as `chio.policy.tenant_caps`; deny with `quota_exceeded` deny code. Without this, one tenant can starve receipt persistence.

**O-6. Bench-regression CI gate with hard threshold** - S, ****
`.github/workflows/bench-regression.yml` exists but doesn't fail PRs. Promote to required check: criterion compare with >5% p95 regression on `dispatch_fixture` fails the PR. Combined with `m06-sustained-p99-nightly.yml`, prevents drift.

**O-7. Chaos-mesh experiment pack (`deploy/chaos/`)** - L, ****
Three failure domains: anchor partition (network-loss between trust-control replicas), federation-hop latency injection, receipt-store disk-fill. Chaos YAMLs in-repo so DR drills are reproducible. Pair with `chio-chaos-validate` test asserting fail-closed under each injection. **Without this, the fail-closed property in CLAUDE.md is theoretical.**

**O-8. Operational kill-switches via control-plane** - M, ****
`chio-http-core/src/emergency.rs` hints at scaffolding. Typed kill-switches: `disable_external_guards`, `disable_otel_export`, `force_fail_closed`, `traffic_shed_percent`. Surfaced through `chio-control-plane` with signed admin capability (no plaintext flips). Receipt every flip with `chio.killswitch.toggle` operation.

**O-9. Profiling/flamegraph endpoint behind admin capability** - S, ***
Production hot-path debugging needs in-process pprof. Expose `/debug/pprof/profile` (CPU, 30s) + `/debug/pprof/heap` gated by admin capability and rate-limited (1/min). Use `pprof-rs`. Receipts written for every capture.

**O-10. Dashboards-as-code expansion + linting** - M, ***
Add `kernel-overview`, `tenant-attribution`, `error-budget-burn`, `federation-topology`. CI step `scripts/lint-dashboards.sh` asserts every panel references a metric in O-1 registry. Stops dashboard rot.

**O-11. Per-request cost attribution + per-tenant cost report** - M, ***
`chio_request_cost_units{tenant,model,operation}` counter computed from `gen_ai.usage.input_tokens` + `gen_ai.usage.output_tokens` (already locked semconv). Daily snapshot exported via `chio-eval-receipt` to `cost_report.json`. Without this, multi-tenant production has no chargeback story.

**O-12. Receipt-archive lifecycle with hot/warm/cold tiers** - L, ***
Healthcare pilot needs 6+ year retention. Tier-mover: SQLite (hot, 30d) -> Parquet on S3 (warm, 1y) -> Glacier (cold, 6y). Metric `chio_receipt_archive_lag_seconds{tier}`.

**O-13. Synthetic probe daemon (`chio-synthetic`)** - M, ****
End-to-end signed mediated tool call every 60s per tenant; asserts receipt produced + signature verifies + SOC export observed. Drives SLI for `synthetic_e2e_success_ratio`. Catches silent fail-open before customer does.

**O-15. DR drill harness with RTO/RPO assertion** - L, ****
`cargo xtask dr-drill` snapshots anchor DB + federation DB, restores into fresh cluster, replays last 1h of receipts via `chio-eval-receipt`, asserts identical verdicts. CI runs weekly. RTO target: 15min cold; RPO: 0 (receipt-write is fail-closed).

---

## Lens 9: Codebase archaeology

### 15 archaeology findings

**X-1. `chio-hosted-mcp` is a 13-line `#[path]`-include of private chio-cli files** - M, *****
Workspace public entrypoint (in `[workspace.metadata.chio.rust_public_entrypoints]`) is structurally a textual splice of CLI internals. Extract `remote_mcp/*.rs` into its own crate; both CLI and `chio-hosted-mcp` consume it normally.

**X-2. Threat-model coverage**: live gate is **PASS at 11 covered / 9 pending-with-`deferred_to` / 0 uncovered** (`scripts/check-threat-coverage.sh` keys on `coverage_state`). The 9 pending split into **6 `unimplemented!()` stub files** (`agent_velocity_abuse`, `behavioral_sequence_attack`, `cumulative_data_exfiltration`, `pii_phi_exposure`, `ssrf_via_http_substrate`, `wasm_guard_resource_exhaustion`) plus **3 mobile rows** (`mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`) whose `deferred_to` already points at `trajectory-4.M07.real-attestation`. Among the 11 covered, `pq_signature_downgrade` and `tee_quote_forgery` carry `covered_by_tests`; only `weights_hash_spoof` lacks any test linkage in JSON. Codegen + CI gate already enforce; trj4 work is concretely 6 stub fills + 3 mobile tests + 1 linkage add. - L, *****

**X-3. `chio-tower` (2738 LOC) has zero in-tree dependents** - Same with `chio-envoy-ext-authz` (1434 LOC), `chio-ag-ui-proxy` (830 LOC), `chio-openapi-mcp-bridge` (815 LOC, only fuzz refs it). Either land an `examples/hello-tower`, `examples/istio-tower`, `examples/ag-ui` integration, or move under `integrations/` with explicit "external-only" tag. - S per crate, ****

**X-4. 7 provider tools-adapters are 80% cookie-cutter** - `chio-cohere`, `chio-mistral`, `chio-groq`, `chio-ollama`, `chio-gemini`, `chio-anthropic`, `chio-bedrock-converse-adapter` share file layout `{lib, native, transport, streaming, loaded_weights}.rs`. Five adapters' `loaded_weights.rs` are 23-line near-clones differing only in `PROVIDER_NAME`. Extract `chio-provider-adapter-core` with SSE-gate orchestration + `LoadedWeights` impl + `Provider` trait. Each adapter becomes ~200 LOC. - L, *****

**X-5. `chio-anchor` gated behind `#![cfg(feature = "web3")]` with `default = ["web3"]`** - 4889 LOC compile only when default feature on. Either drop the gate or commit to no-web3 build path with CI lane. - S, ***

**X-6. `chio-core` is a 12-line `pub use` umbrella re-exporting 11 domain crates** - Every dependent that takes `chio-core` pulls full transitive graph. Most consumers want only `chio-core-types`. Strip umbrella or fork `chio-prelude`. - M, ****

**X-7. `chio-cli` is 81 KLOC and growing - workspace's load-bearing god module** - `policy.rs:3253`, `certify.rs:2574`, `passport.rs:2468`, `evidence_export.rs:2211`, `guard.rs:1552`, `passport_verifier.rs:1539`, `issuance.rs:1439`. `chio-hosted-mcp` had to `#[path]`-include into it. Each `*.rs >1000 LOC` is an extractable library. `passport*`, `certify`, `evidence_export` triplet looks like a `chio-attestation-export` crate waiting to happen. - XL, *****

**X-8. 8 large domain crates have token integration tests** - `chio-mercury-core` 9363/14 (worst offender), `chio-link` 3569/31, `chio-autonomy` 2193/26, `chio-appraisal` 4092/21, `chio-governance` 1770/18, `chio-did` 414/22, `chio-web3` 1990/17, `chio-underwriting` 2248/97. Pick top 3 by blast radius and require minimum 500 LOC of property/example tests each. - L per crate, ****

**X-9. `chio-spec-validate` only has one in-tree consumer: `xtask`** - Convert to `xtask/spec-validate` sub-bin or document as external CI artifact. - S, **

**X-10. 819 cargo-vet exemptions** - `supply-chain/config.toml` has 819 `[[exemptions.*]]` (767 `safe-to-deploy` + 52 `safe-to-run`). CONTEXT mentioned 26->179; actual is 819. Write xtask `vet-exemption-shrink` picking 50 high-traffic deps (alloy-*, aws-sdk-*, tokio-*) for real audits. - M, ****

**X-11. `unsafe` blocks concentrated in 4 crates and well-reasoned** - `chio-cpp-kernel-ffi` (2), `chio-bindings-ffi` (3), `chio-guard-sdk{,-macros}` (5), plus tests. All justified (FFI, WASM glue). Many sites lack canonical `// SAFETY:` block; add audit pass. - S, **

**X-12. 62 of 89 crates have no `README.md`** - Including `chio-policy`, `chio-kernel-core`, `chio-tee`, `chio-store-sqlite`, `chio-credentials`, `chio-mercury`, `chio-wall`, `chio-settle`. `// SECTION:` marker convention referenced in conventions appears in zero crates. Pick 15 `rust_public_entrypoints` plus products and add minimal README per template. - M, ***

**X-13. chio-rename has stale ARC residue in `docs/research/` filenames** - `ARC_{ANCHOR,LINK,SETTLE_PROTOCOL_DECISIONS,SETTLE,WEB3_CONTRACT_ARCHITECTURE,WEB3_TRUST_BOUNDARY_DECISIONS,ZK_RECEIPT_PROOFS_MEMO}_RESEARCH.md` plus `docs/archive/ARC_UPSTREAM_PROPOSAL.md` and `docs/protocols/ARCHITECTURAL-EXTENSIONS.md`. `ARC_LINK_FUTURE_TRACKS.md:23-27` still names crates `arc-link`, `arc-anchor`, `arc-settle`. Bulk rename + content sweep. - S, **

**X-14. `println!`/`eprintln!` in 9 production crates** - `chio-cli`, `chio-mercury`, `chio-wall`, `chio-tee`, `chio-spec-codegen`, `chio-spec-validate`, `chio-guards`, `chio-anchor`, `chio-api-protect`. 1585 hits across non-test code. `chio-guards` and `chio-anchor` hits suggest library-side I/O leakage. Ban outside `bin/` and `main.rs` via clippy lint or grep-based xtask. - S, ***

**X-15. `integrations/aws-bedrock/control-plane/` named `chio-bedrock-control-plane`** but lives outside `crates/`; uses `path = "../tests/post_listing_smoke.rs"` reaching across directory boundary. Move into `crates/chio-bedrock-control-plane`. - S, **

### Top 5 "finish what we started" (highest-leverage finishing moves)

1. **X-2 Threat-model coverage push**: gate is PASS at 11/9/0; trj4 flips 6 stubs + 3 mobile-deferral rows to `covered` and adds `covered_by_tests` linkage to `weights_hash_spoof`. Mobile rows land as part of Tier 0 Phase C mobile-attestation. End state: 20/0/0.
2. **X-4 Provider-adapter-core extraction**: cuts ~3 KLOC, makes Nth adapter a 1-day job.
3. **X-1 `chio-hosted-mcp` real extraction**: half-day surgical move.
4. **X-3 `chio-tower` example/integration**: 2738 LOC of Tower middleware with zero workspace consumers.
5. **X-8 `chio-mercury-core` test backfill**: 9363 LOC src / 14 LOC tests; property-test coverage of `proof_package.rs` (1176 LOC, largest single file) is one week of high-leverage work.

### Top 3 deprecation candidates

1. **`chio-core` umbrella**: rename `chio-core-types` -> `chio-core` and dissolve umbrella.
2. **`chio-spec-validate` as workspace member**: single consumer (xtask); convert to xtask sub-bin.
3. **`#[deprecated]` `handle_send_message` / `handle_jsonrpc` aliases on `chio-a2a-edge`** (lib.rs:1092, 1120): already explicitly deprecated; clean removal once callers move to `*_compatibility`.

### 3 surprising patterns

1. **The "core" crate is empty.** `chio-core` is a 12-line `pub use` umbrella; the actual core is `chio-core-types` (35 KLOC, 112 in-tree dependents). Naming inverts what newcomers expect; an in-progress extraction never completed cleanup.
2. **The "tools-adapter" pattern is implicit, not codified.** Seven crates follow `{lib, native, transport, streaming, loaded_weights}.rs` to the file. No shared trait crate. **Single biggest "we already half-built X" opportunity.**
3. **The threat-model codegen gate exists and is PASS** (11 covered / 9 pending-with-`deferred_to` / 0 uncovered) **but 9 of 20 threats are still placeholder rows**: 6 `unimplemented!()` stub files plus 3 mobile rows deferred to this trajectory. The cheap finishing-move work is concrete: 6 stub fills, 3 mobile tests, 1 linkage add.

---

## Idea inventory totals

| Lens | Proposals |
|---|---|
| DX | 12 |
| Perf/scale | 12 |
| Capability extension | 13 |
| Protocol evolution | 12 |
| AI-frontier | 15 |
| TEE / hardware-attestation | 12 |
| Trust-graph / federation | 12 |
| Observability / SRE | 15 |
| Codebase archaeology (findings) | 15 |
| Codebase archaeology (finishing moves) | 5 |
| Codebase archaeology (deprecations) | 3 |
| **Total distinct items** | **~126** (after merging the macaroon and anchor-batch convergences) |

For ideas the agents themselves rejected (with rationale), see `REJECTED-IDEAS.md`.
