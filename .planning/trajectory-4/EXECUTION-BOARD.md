# Trajectory-4 Execution Board

**Status**: ticket scaffolding for the round-6 scope-locked plan in `SYNTHESIS-V2-INTEGRATED-PLAN.md`. Owners and PR numbers are TBD until trj4 kicks off.

## Scope-locked tier set

Per the round-3 reviewer-recommended scope, refined through round-6:

- **Tier 0** (full floor including reconciliation gate, HTTP SSRF contract, semantic-diff gate; 8-10 wk).
- **T1.0** (capability negotiation + token versioning + signed-artifact compat gate; ~1.5 wk).
- **T1.1** (macaroon attenuation: promote `delegation_v2` + add witness API; ~3 wk).
- **T1.2** (receipt DAG + receipt-id migration to `body_hash`; ~3 wk).
- **T1.3** (anchor-batch Merkle trees with full Evidence Gate; ~2 wk).
- **T1.4** (archaeology finish-line + cargo-vet debt close; ~2 wk).
- **T1.5** (foundational SRE; **MANDATORY**; ~3 wk).
- **T1.6** (`chio explain` CLI; ~1 wk).
- **T2.1** (hybrid PQ end-to-end + cross-surface conformance).

**Stretch (ship if first half lands cleanly, otherwise slip to trj5)**: T2.2 hot-path cache + Tower load-shed; T2.3 trust-graph maturity; 1-2 T3 picks max.

Total: **14-18 weeks two-lane parallel** / **20-24 weeks single-track**. Optional split into trj4a (closeout, 8-10 wk) + trj4b (primitives, 6-8 wk) if staffing requires.

## Lanes

| Lane | Owner-class | Scope |
|---|---|---|
| **A** | Substrate eng | Tier 0 hardening, threat coverage, archaeology |
| **B** | Mobile / TEE eng | Tier 0 Phase C mobile attestation |
| **C** | Protocol + capability eng | T1.0, T1.1, T1.2, T1.3, T1.6 |
| **D** | SRE / observability eng | T1.5 |
| **E** | Refactor / supply-chain eng | T1.4 |
| **F** | Federation eng | T2.1 (cross-surface conformance, hybrid PQ) |

Lanes A and B run in Tier 0; C, D, E, F unlock after T0 reconciliation gate.

## Evidence Gate (mandatory for every T1.x ticket)

Every ticket whose ID has a `T1.x.E` suffix is the Evidence Gate ticket for that slice. It does not close until the slice has updated:

- `spec/PROTOCOL.md`
- The relevant JSON schemas under `spec/schemas/`
- Claim registry
- Proof manifest
- Theorem inventory
- Generated proof report
- At least one signed negative conformance test

The Evidence Gate ticket must close before its parent T1.x slice is considered complete.

---

## Tier 0 - The floor (Lane A + B)

### Phase A (W1-2): trj3 closeout + reconciliation gate

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-000 | **Bootstrap pre-flight infrastructure**: `spec/registries/{claim-registry,proof-manifest,theorem-inventory}.v1.json` + README seeded with existing trj1-3 claims/manifests/theorems; `.planning/trajectory-4/audits/evidence/` directory live; `scripts/trj4-preflight.sh` runnable. Pre-flight gate (the automated half of TRJ4-006) returns exit 0. | A | S | - |
| TRJ4-001 | Drive remaining trj3.2 PRs through CI cascade-merge (verify zero open `trj3.2/*` PRs) | A | S | TRJ4-000 |
| TRJ4-002 | **Ratify release-tag policy** (operator decision; see audit T0.A "release-tag policy" section), then tag `v<chosen-version>-trj3.1` and trigger `release-binaries.yml` + `slsa.yml` + `reproducible-build.yml` | A | S | TRJ4-001 |
| TRJ4-003 | Commit produced provenance / reproducible-build / checksum artifacts under `releases/provenance/<tag>.intoto.jsonl`, `releases/reproducible-builds/<tag>.json`, `supply-chain/checksums/<tag>.txt` | A | S | TRJ4-002 |
| TRJ4-004 | Replace TODO markers in `.planning/trajectory-3/TRAJECTORY-FINAL.md` + `.planning/trajectory-3/work/CI-DEBT.md` with real close SHA + run URLs | A | S | TRJ4-003 |
| TRJ4-005 | Drain remaining trj3.2 P2 backlog | A | M | - |
| TRJ4-006 | **T0 reconciliation gate**: `bash scripts/trj4-preflight.sh` returns exit 0 (machine half); trj3 carry-forward catalog re-stated in `SYNTHESIS-V2-INTEGRATED-PLAN.md` (manual half); deferred Kani/mutants/TLA tickets enumerated under TRJ4-012..018; release-tag policy ratified; scope-lock decision made; lane owners assigned | A | S | TRJ4-000..005 |

**Phase A bar**: TRJ4-006 passes. No T1 work begins until then.

### Phase B (W2-6): substrate hardening

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-010 | Unblock hosted nightly cargo-mutants (fuzz-budget warn-mode reaches full sweep) | A | M | TRJ4-006 |
| TRJ4-011 | Drive trust-boundary kill rate >= 65% per crate; >= 80% on `chio-attest-verify` with explicit `# unreachable: <justification>` annotations | A | L | TRJ4-010 |
| TRJ4-012 | Kani harness `chio-attest-verify` (modeled on `chio-kernel-core::kani_public_harnesses.rs`) | A | M | - |
| TRJ4-013 | Kani harness `chio-anchor` | A | M | - |
| TRJ4-014 | Kani harness `chio-weights` | A | M | - |
| TRJ4-015 | TLA+ rewrite `RevocationCutCompleteness` with bounded transitive-closure unrolling | A | M | - |
| TRJ4-016 | TLA+ split `Allow` into `LogReceipt` + `PublishAllow` so `ReceiptBeforeAllow` stops being tautological | A | M | - |
| TRJ4-017 | Bump `EpochMax` from 4 to 6 so length=6 fully utilizes apalache run budget | A | S | TRJ4-015, TRJ4-016 |
| TRJ4-018 | Fix `RevocationEventuallySeen` apalache 0.50.1 temporal-encoding bug; promote `apalache-temporal.yml` from advisory to required | A | M | TRJ4-017 |
| TRJ4-019 | New `crates/chio-equivalence-tests/` workspace member with proptest hosted-vs-portable equivalence (10k cases per PR + 1M nightly, zero divergence) | A | L | - |
| TRJ4-020 | `trust_control_cluster_multi_region_partition_qualification` root-cause fix (real concurrency / replication-lag fix; not a retry loop) | A | L | - |
| TRJ4-021 | `chio-tee-frame::validate` real cryptographic signature verification (currently regex-only) | A | M | - |
| TRJ4-022 | `chio-tee-frame::schema::validate_timestamp` real RFC-3339 parse + range validation | A | S | - |
| TRJ4-023 | `HttpEgressContract` typed SSRF guard in `chio-http-core` (allowed_schemes, allowed_authority, deny_loopback, deny_link_local, max_redirect, max_response_bytes) | A | M | - |
| TRJ4-024 | Policy/manifest semantic-diff CI gate (newly-allow / newly-deny / scope widening) on `chio-policy` and manifest-schema PRs | A | M | - |

### Phase C (W6-8): mobile attestation real verifiers (Lane B)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-030 | Apple App Attest real verifier in `chio-custody-hw/src/attestation/app_attest.rs`: CBOR + cert chain to pinned Apple App Attest root + counter monotonicity + nonce binding + KeyId binding. Replace `AttestationUnavailable` at `chio-kernel-mobile/src/lib.rs:433` | B | L | TRJ4-006 |
| TRJ4-031 | Play Integrity real verifier in `chio-custody-hw/src/attestation/play_integrity.rs`: JWS + Google JWKS rotation + audience + nonce + verdict. Replace `AttestationUnavailable` at `chio-kernel-mobile/src/lib.rs:454` | B | L | TRJ4-006 |
| TRJ4-032 | Build real `ChioKernel.xcframework` binary in `Frameworks/` with reproducible-build attestation | B | L | TRJ4-030 |
| TRJ4-033 | Mobile threat-coverage flip: tests for `mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`. JSON `coverage_state` flips `pending` -> `covered`; `deferred_to: trajectory-4.M07.real-attestation` is resolved | B | M | TRJ4-030, TRJ4-031 |

### Phase D (W8-10): threat coverage + meta

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-040 | Threat-coverage cargo-mutants per-row gate (every `coverage_state: covered` row gets a survivor sweep) | A | M | TRJ4-011 |
| TRJ4-041 | Fill `agent_velocity_abuse` stub with real conformance test | A | S | - |
| TRJ4-042 | Fill `behavioral_sequence_attack` stub | A | S | - |
| TRJ4-043 | Fill `cumulative_data_exfiltration` stub | A | S | - |
| TRJ4-044 | Fill `pii_phi_exposure` stub | A | M | - |
| TRJ4-045 | Fill `ssrf_via_http_substrate` stub (paired with TRJ4-023) | A | S | TRJ4-023 |
| TRJ4-046 | Fill `wasm_guard_resource_exhaustion` stub | A | S | - |
| TRJ4-047 | Add `covered_by_tests` JSON linkage for `weights_hash_spoof` (only currently-covered row missing it) | A | XS | - |
| TRJ4-048 | Fail-closed philosophy audit doc (every `?` propagation crossing trust boundary lands at `Deny`, not pass-through) | A | M | - |
| TRJ4-049 | CI-DEBT.md final pass; confirm zero `requires-individual-replay-or-deferral` entries | A | S | - |

**Tier 0 close bar**: TRJ4-001..049 all closed. Threat-coverage gate transitions from 11/9/0 PASS to **20/0/0 PASS**.

---

## Tier 1 - Multi-agent trust primitives (Lanes C, D, E)

### T1.0 - Capability negotiation + token versioning (~1.5 wk; the hinge)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-100 | `chio.capabilities.v1` capability-negotiation handshake schema + envelope + peer-feature-bitset advertise/parse | C | M | TRJ4-006 |
| TRJ4-101 | `CapabilityToken` schema-tag: add `schema` field; reject unknown schema IDs | C | S | - |
| TRJ4-102 | `chio.capability.v1` (current shape, frozen) + `chio.capability.v2` (with caveats, `attenuation_proof`, hybrid PQ) JSON schemas | C | M | TRJ4-101 |
| TRJ4-103 | Signed-artifact registry: catalog every signed artifact's schema ID; load-time + verify-time fail-closed on unknown schema | C | M | TRJ4-101 |
| TRJ4-104 | v1->v2 negotiation in `KernelTrustExchange` and `chio-federation` handshake (peers without `accepts_capability_v2` stay on v1) | C | S | TRJ4-100, TRJ4-102 |
| TRJ4-T1.0.E | **Evidence Gate**: PROTOCOL.md, schemas under `spec/schemas/`, claim registry, proof manifest, theorem inventory, proof report; one signed negative-conformance test | C | M | TRJ4-100..104 |

### T1.1 - Macaroon capability attenuation (~3 wk; gated on T1.0)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-110 | Promote `delegation_v2` from feature-gated to default-on | C | M | TRJ4-T1.0.E |
| TRJ4-111 | Lift `Attenuation` and `ScopeAttenuation` into `chio.capability.v2` schema as first-class fields | C | M | TRJ4-110 |
| TRJ4-112 | Typed caveats: `Vec<Caveat>` reachable from `ToolGrant`; each `Caveat { kind, predicate, sig? }` | C | L | TRJ4-111 |
| TRJ4-113 | NEW API: `compute_attenuation_witness(parent: &ChioScope, child: &ChioScope) -> Result<AttenuationWitness>` in `chio-core-types` (records normalized scope encoding + per-grant subset relation + restricted predicates) | C | M | TRJ4-110 |
| TRJ4-114 | NEW API: `verify_attenuation_witness(parent_hash, child_hash, witness) -> Result<()>` (faster than re-deriving subset normalization) | C | M | TRJ4-113 |
| TRJ4-115 | `attenuation_proof` field on `chio.capability.v2` carries the witness on the wire | C | S | TRJ4-113 |
| TRJ4-116 | `CapabilityAttenuationGuard`: runtime enforcement that `child.is_subset_of(parent)` AND `verify_attenuation_witness` passes | C | M | TRJ4-114 |
| TRJ4-117 | `chio-federation::delegation::issue_token` / `verify_chain` for cross-org scoped delegation (short-lived, action-scoped, revocable bearer; carries delegator_did, delegate_did, scope_namespace, allowed_actions, expires_at, parent_token_hash, max_remaining_hops) | C | L | TRJ4-115 |
| TRJ4-118 | `SubAgentBudgetPropagation`: fixed-point integer share field (basis points or micros) carried in child receipts and verified at join | C | M | TRJ4-111 |
| TRJ4-T1.1.E | **Evidence Gate** for T1.1 | C | M | TRJ4-110..118 |

### T1.2 - Multi-agent receipt DAG + receipt-id migration (~3 wk)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-120 | Define typed `ReceiptV2BodyHashInput` struct in `chio-core-types` (every v2 body field except `body_hash`, `signature`, legacy `receipt_id`) | C | M | TRJ4-T1.0.E |
| TRJ4-121 | Define typed `ReceiptV2SigningBody { body_hash, body }` wrapper; `body_hash := H(canonical_jcs(ReceiptV2BodyHashInput))` | C | S | TRJ4-120 |
| TRJ4-122 | `chio-spec-codegen` generates `ReceiptV2BodyHashInput` from JSON schema (so field set stays in sync with wire) | C | M | TRJ4-120 |
| TRJ4-123 | Sign v2 receipts via `keypair.sign_canonical(&ReceiptV2SigningBody)` matching `CapabilityTokenBody::sign` pattern at `chio-core-types/src/capability.rs:246-248` | C | M | TRJ4-121 |
| TRJ4-124 | `chio.receipt.v2` schema: `body_hash` + `signature` + `receipt_id` (legacy UUIDv7 alias) + DAG fields | C | M | TRJ4-122 |
| TRJ4-125 | Replay-store keys exclusively on `body_hash`. Legacy UUIDv7 `receipt_id` stays on wire as non-authoritative tooling alias; CLI and explorer use a separate alias index that never affects replay acceptance | C | L | TRJ4-124 |
| TRJ4-126 | `dag_ordinal: u64` + HLC `(wall_seconds, logical, kernel_id)` triple per receipt; both signed inputs | C | M | TRJ4-123 |
| TRJ4-127 | Verifier acyclicity invariant `child.dag_ordinal > max(parent.dag_ordinal)`; cross-kernel cycles rejected without single global clock | C | M | TRJ4-126 |
| TRJ4-128 | `chio.receipt_lineage_statement.v2` carries `parent_receipt_ids: Vec<String>` (each is a `body_hash`); canonical sort + dedupe | C | M | TRJ4-124 |
| TRJ4-129 | `parent_set_hash = H(canonical(sort(parent_receipt_ids)))` so verifiers can check parent-set integrity cheaply | C | S | TRJ4-128 |
| TRJ4-130 | Lean theorem pinning the body-hash input set (so it cannot drift) | C | M | TRJ4-120 |
| TRJ4-131 | `AgentLoopBoundsGuard { max_depth, max_fanout, max_wall_seconds, max_total_subcalls }` reading session journal `tool_sequence` | C | M | - |
| TRJ4-T1.2.E | **Evidence Gate** for T1.2 (incl. four negative conformance tests: mismatched body_hash, self-referential implementer error, tampered legacy receipt_id verifies + does not affect replay, signature without body_hash commit) | C | L | TRJ4-120..131 |

### T1.3 - Anchor-batch Merkle trees (~2 wk)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-140 | New artifact `chio.anchor_batch.v1`: `{tree_root, checkpoint_ids[], witness: rekor|ots|solana_memo}` schema + signer | C | M | TRJ4-T1.0.E |
| TRJ4-141 | Coalesced batch root: build Merkle tree over N receipts/checkpoints, attach inclusion proof per element | C | M | TRJ4-140 |
| TRJ4-142 | Per-receipt local sign stays unchanged; batch root is *additional*. Batch issuance lane non-blocking on the receipt write path | C | S | TRJ4-141 |
| TRJ4-143 | Witness lane integration: Rekor publish + verify | C | M | TRJ4-140 |
| TRJ4-144 | Witness lane integration: OTS publish + verify (operational alternative to Rekor) | C | M | TRJ4-140 |
| TRJ4-145 | Claim registry update: register `chio.anchor_batch.v1` claim shape | C | S | TRJ4-140 |
| TRJ4-146 | Proof manifest update tying claim to evidence | C | S | TRJ4-145 |
| TRJ4-147 | Public-witness semantics doc: anti-equivocation, claim-completeness, stale-witness fallback (what a missing or stale witness implies for receipts in the batch) | C | M | TRJ4-143, TRJ4-144 |
| TRJ4-T1.3.E | **Evidence Gate** for T1.3 (incl. negative conformance tests: forged batch root, mis-ordered inclusion proof, witness-lane impersonation, stale-witness fallback) | C | L | TRJ4-140..147 |

### T1.4 - Archaeology finish-line (~2 wk)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-150 | `chio-hosted-mcp` real extraction: lift `remote_mcp/*.rs` from `chio-cli` into its own crate; both CLI and `chio-hosted-mcp` consume normally | E | M | - |
| TRJ4-151 | New `crates/chio-provider-adapter-core/`: shared SSE-gate orchestration + `LoadedWeights` impl helper + `Provider` trait | E | L | - |
| TRJ4-152 | Refactor `chio-cohere-tools-adapter` to consume `chio-provider-adapter-core` | E | S | TRJ4-151 |
| TRJ4-153 | Refactor `chio-mistral-tools-adapter` to consume core | E | S | TRJ4-151 |
| TRJ4-154 | Refactor `chio-groq-tools-adapter` to consume core | E | S | TRJ4-151 |
| TRJ4-155 | Refactor `chio-ollama-tools-adapter` to consume core | E | S | TRJ4-151 |
| TRJ4-156 | Refactor `chio-gemini-tools-adapter` to consume core | E | S | TRJ4-151 |
| TRJ4-157 | Refactor `chio-anthropic-tools-adapter` to consume core | E | S | TRJ4-151 |
| TRJ4-158 | Refactor `chio-bedrock-converse-adapter` to consume core | E | S | TRJ4-151 |
| TRJ4-159 | Cargo-vet "no net-new exemptions" CI gate on `supply-chain/config.toml` | E | S | - |
| TRJ4-160 | Author real cargo-vet audits for top-50 highest-traffic dependencies (alloy-*, aws-sdk-*, tokio-*, hyper-*, tonic-*); target 819 -> <= 769 exemptions | E | XL | TRJ4-159 |

### T1.5 - Foundational SRE (~3 wk; MANDATORY)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-170 | New `crates/chio-metrics-spec/` workspace member with const-string registry: `chio_kernel_decision_latency_seconds`, `chio_receipt_write_total{outcome}`, `chio_guard_evaluations_total{guard,outcome}`, `chio_capability_revocation_lag_seconds`, `chio_anchor_round_latency_seconds`, `chio_federation_hop_total{result}`, `chio_dlq_depth{exporter}` | D | M | - |
| TRJ4-171 | `describe!` macro + `cargo test -p chio-metrics-spec` golden-snapshot CI gate that fails when names diverge | D | M | TRJ4-170 |
| TRJ4-172 | Wire `chio-metrics-spec` into all metric emission sites in `chio-kernel`, `chio-mcp-edge`, `chio-acp-edge`, `chio-a2a-edge`, `chio-http-core`, `chio-anchor`, `chio-federation`, `chio-siem` | D | L | TRJ4-171 |
| TRJ4-173 | Prometheus alert + recording rule pack at `deploy/prometheus/` (burn-rate alerts: 14.4x/1h + 6x/6h dual-window per Google SRE workbook) | D | M | TRJ4-170 |
| TRJ4-174 | Recording rules: `chio:decision_latency:histogram_quantile_p95_5m`, `chio:receipt_write_error_ratio_5m` | D | S | TRJ4-173 |
| TRJ4-175 | Alert routes wired to OpsGenie/PagerDuty via existing `chio-siem`; receipt-write-error-budget-burn, fail-open-suspected, dispatch-failure | D | M | TRJ4-173 |
| TRJ4-176 | `chio-log-redact`: `tracing_subscriber::Layer` runs every event through receipt's redaction tree | D | L | - |
| TRJ4-177 | `redacted!()` macro that rejects raw-string formatting of payloads; compile-time enforcement | D | M | TRJ4-176 |
| TRJ4-178 | Migrate existing `tracing::info!`/`error!` sites that touch user-content arms to `redacted!()`; CI grep-gate to prevent reintroduction | D | L | TRJ4-177 |

### T1.6 - `chio explain` CLI (~1 wk)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-180 | `chio explain <receipt-id>` accepts both UUIDv7 (legacy) and `body_hash` (v2) | C | S | TRJ4-125 |
| TRJ4-181 | Render: which policy clause matched, which guards fired, scope diff, parent receipt(s) (DAG-aware), batch witness lane, repair hint if denied | C | M | TRJ4-180 |
| TRJ4-182 | Render attenuation chain: parent->child caveats, witness, subset-of-parent assertion | C | M | TRJ4-181, TRJ4-115 |
| TRJ4-183 | "Why was this called?" trace: `user_msg -> plan_id -> sub_agent_id -> tool_call_id` (A-12) | C | M | TRJ4-181 |

---

## Tier 2 - Foundational improvements (Lane F)

### T2.1 - Hybrid PQ end-to-end + cross-surface conformance

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-200 | `KernelTrustExchange` accepts a generic `SigningBackend` (today stores concrete `Keypair`) | F | M | TRJ4-T1.0.E |
| TRJ4-201 | `spec/schemas/chio-wire/v1/capability/token.schema.json`: add `hybrid` to `algorithm` enum (currently `["ed25519", "p256", "p384"]`); matches `signature.v1.json` | F | S | - |
| TRJ4-202 | `issuer`, `subject`, signature-field regex patterns on the capability-token schema accept the hybrid wire prefix `hybrid:<classical>:<pq>:<alg_set>` | F | S | TRJ4-201 |
| TRJ4-203 | Wire-format encoder/decoder paths (capability token, federation handshake envelope, receipt signing) treat the hybrid string format as first-class (not feature-gated) | F | M | TRJ4-201 |
| TRJ4-204 | Conformance-tier handshake gating (`Bronze/Silver/Gold` derived from threat-coverage + mutation-kill + Kani harness completeness); `QuorumPolicy::min_tier` accepted | F | M | - |
| TRJ4-205 | Cross-surface conformance: MCP wrapped mode (`chio-hosted-mcp`) - deny receipts, lineage class, revocation, budget, no adapter bypass | F | L | TRJ4-T1.1.E, TRJ4-T1.2.E |
| TRJ4-206 | Cross-surface conformance: hosted/native edge (`chio-tower`, `chio-http-core`) - same suite | F | L | TRJ4-205 |
| TRJ4-207 | Cross-surface conformance: A2A or HTTP edge (`chio-a2a-edge`, `chio-acp-edge`) - same suite | F | L | TRJ4-205 |
| TRJ4-T2.1.E | **Evidence Gate** for T2.1 (cross-surface deny receipts, lineage, revocation, budget, no-bypass attestation across all advertised surfaces) | F | L | TRJ4-200..207 |

---

## Stretch (not in initial scope-lock; ship if first half lands cleanly)

### T2.2 - Mediator hot path

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-220 | Dispatch profile baseline + flame-graph CI artifact (`pprof-rs` folded-stack uploaded per merge to main from `dispatch_allow` bench) | A | S | - |
| TRJ4-221 | (gated on TRJ4-220) Bounded-LRU verdict cache keyed on fully-specified composite `(cap_hash, scope, tool, guard_set_hash, policy_version, tenant_id, agent_id, caveat_state_hash, revocation_epoch, trust_root_epoch)`; pure-preflight only | A | L | TRJ4-220 |
| TRJ4-222 | Tower load-shed + concurrency-limit middleware (`tower::LoadShed`, `tower::ConcurrencyLimit`) on `chio-tower` HTTP edge | A | S | - |

### T2.3 - Trust-graph maturity (stretch)

| Ticket | Title | Lane | Effort | Depends on |
|---|---|---|---|---|
| TRJ4-240 | M-of-N quorum-signed receipts: generalize `bilateral::DualSignedReceipt` to `QuorumSignedReceipt { body, signatures, threshold }` | F | M | - |
| TRJ4-241 | Trust-anchor rotation: `TrustAnchorRotation { old_key, new_key, effective_at, signed_by_old_key, signed_by_new_key, rotation_attestation_ref }` + replicated `TrustAnchorLedger` via `chio-anchor` lanes | F | L | TRJ4-T1.3.E |
| TRJ4-242 | DID-bound agent identity in receipts: optional `agent_did: Option<DidChio>` resolvable to `DidDocument` | F | M | - |

### T3 buffet

Catalog only; pick 1-2 if first half lands fast. Tickets stubbed under TRJ4-300+ when scoped.

| Ticket | Title | Effort |
|---|---|---|
| TRJ4-301 | T3.1 Multi-modal receipt envelopes | XL |
| TRJ4-302 | T3.2 Agentic-deception detector (plan-vs-action diff) | L |
| TRJ4-303 | T3.3 Apple Secure Enclave kernel-key backend | M |
| TRJ4-304 | T3.4 RATS RFC 9334 evidence envelope | M |
| TRJ4-305 | T3.5 W3C trace propagation across kernel/federation/anchor | L |
| TRJ4-306 | T3.6 Streaming receipts | M |
| TRJ4-307 | T3.7 Structured-PII + Code-Secrets redactor packs | L+M |
| TRJ4-308 | T3.8 TransparencyLogReceiptExporter (Rekor-style) | L |
| TRJ4-309 | T3.9 Chaos-mesh experiment pack | L |
| TRJ4-310 | T3.10 Receipt-chain web explorer (full UI for `chio explain`) | L |
| TRJ4-311 | T3.11 ML-shim PromptInjectionGuard | L |
| TRJ4-312 | T3.12 RAG citation attestation | L |
| TRJ4-313 | T3.13 Per-receipt output watermarking | L |

---

## Per-milestone audit docs

Each scope-locked milestone has an audit-doc skeleton in `audits/`. The audit doc is the unit of close: it accumulates evidence, references the close-bar items in `SYNTHESIS-V2-INTEGRATED-PLAN.md`, and is signed off when all referenced tickets close.

| Audit | Tickets covered |
|---|---|
| `audits/T0.A-substrate-closeout.md` | TRJ4-001..006 |
| `audits/T0.B-substrate-hardening.md` | TRJ4-010..024 |
| `audits/T0.C-mobile-attestation.md` | TRJ4-030..033 |
| `audits/T0.D-threat-coverage.md` | TRJ4-040..049 |
| `audits/T1.0-capability-negotiation.md` | TRJ4-100..104 + T1.0.E |
| `audits/T1.1-macaroon-attenuation.md` | TRJ4-110..118 + T1.1.E |
| `audits/T1.2-receipt-dag.md` | TRJ4-120..131 + T1.2.E |
| `audits/T1.3-anchor-batch.md` | TRJ4-140..147 + T1.3.E |
| `audits/T1.4-archaeology.md` | TRJ4-150..160 |
| `audits/T1.5-sre-foundations.md` | TRJ4-170..178 |
| `audits/T1.6-chio-explain.md` | TRJ4-180..183 |
| `audits/T2.1-hybrid-pq-cross-surface.md` | TRJ4-200..207 + T2.1.E |

Stretch audits added when scoped: `audits/T2.2-hot-path.md`, `audits/T2.3-trust-graph.md`, plus per-T3 picks.

---

## Close-bar mapping

The 30 close-bar items in `SYNTHESIS-V2-INTEGRATED-PLAN.md` Section "Trj4 close bar (round-3)" map to ticket sets as follows:

| Close-bar # | Tickets |
|---|---|
| 1 | TRJ4-049 |
| 2 | TRJ4-010, TRJ4-011 |
| 3 | TRJ4-012, TRJ4-013, TRJ4-014 |
| 4 | TRJ4-015, TRJ4-016, TRJ4-017, TRJ4-018 |
| 5 | TRJ4-019 |
| 6 | TRJ4-020 |
| 7 | TRJ4-030, TRJ4-031, TRJ4-032 |
| 8 | TRJ4-033, TRJ4-040..047 |
| 9 | TRJ4-002, TRJ4-003 |
| 10 | TRJ4-004 |
| 11 | TRJ4-023, TRJ4-045 |
| 12 | TRJ4-024 |
| 13 | TRJ4-100, TRJ4-104 |
| 14 | TRJ4-101, TRJ4-102, TRJ4-103 |
| 15 | TRJ4-110..116 |
| 16 | TRJ4-118 |
| 17 | TRJ4-120..125 |
| 18 | TRJ4-126..130 |
| 19 | TRJ4-140..147 + T1.3.E |
| 20 | TRJ4-150 |
| 21 | TRJ4-151..158 |
| 22 | TRJ4-159, TRJ4-160 |
| 23 | All `T1.x.E` Evidence Gate tickets |
| 24 | TRJ4-170..175 |
| 25 | TRJ4-176, TRJ4-177, TRJ4-178 |
| 26 | TRJ4-180..183 |
| 27 | TRJ4-200, TRJ4-203 |
| 28 | TRJ4-201, TRJ4-202 |
| 29 | TRJ4-204 |
| 30 | TRJ4-205, TRJ4-206, TRJ4-207, T2.1.E |

## Status conventions

Each ticket starts in `pending`; transitions to `in_progress` on PR open, `review` on PR ready-for-review, `merged` on PR merge to main, `closed` on its parent audit-doc signoff. The Evidence Gate tickets (`T1.x.E`, `T2.1.E`) are gating: their parent slice cannot be `closed` until the Evidence Gate ticket is `merged` AND the audit doc is signed off.
