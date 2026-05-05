# Trajectory-4 Synthesis v2 - Integrated Plan

**Status**: revised after three reviewer passes. Integrates `SYNTHESIS-V1-INTERNAL-ONLY.md` (substrate-hardening floor) with `BRAINSTORM-V1-FEATURE-CATALOG.md` (9-lens feature brainstorm) and the round-3 alignment / brainstorm tweaks.

## Reviewer-pass log

**Round-1 fixes (commit 8c510c15):**
- Threat-count language realigned to actual threat-model JSON.
- Capability negotiation + `CapabilityToken` schema-tag promoted to T1.0 (the hinge); macaroon caveats gated on it.
- Verdict cache key fully specified (composite); demoted to T2 stretch with profile-first ordering.
- Receipt-DAG formal model expanded.
- Anchor batching reframed as additive.
- `BudgetSplit::PerChildShare(f32)` -> fixed-point integer (basis points or micros).
- `chio explain <receipt-id>` CLI promoted to T1.6.
- Cargo-vet debt added with no-net-new + top-50 burn-down close bar.
- "Three tiers" -> four tiers throughout.

**Round-2 fixes (commit c5d19ab3):**
- Threat-count re-aligned with the live gate (`scripts/check-threat-coverage.sh` keys on the `coverage_state` field, not `coveredBy`).
- Cross-kernel DAG ordering: `(epoch, seq)` per-kernel predicate replaced with signed `dag_ordinal` + HLC triple.
- All 139 em-dash characters scrubbed.
- Trailing-whitespace cleanup.

**Round-5 fixes (this revision):**
- **Replay-store keys are `body_hash` only.** Previous wording said the legacy UUIDv7 `receipt_id` was retained for replay-store keys while also being non-cryptographic and tamper-tolerated. That is incoherent for v2: replay/dedup state now keys exclusively on `body_hash` (cryptographic identity); the legacy UUIDv7 is a non-authoritative tooling alias only. A tampered legacy `receipt_id` cannot affect replay acceptance because replay never reads it. Negative conformance test (c) updated to assert this.
- **Canonical signing input typed.** Previous `BODY_HASH_INPUT || body_hash` byte-concat was under-specified. T1.2 now defines a typed `ReceiptV2BodyHashInput` struct (every v2 body field except `body_hash`, `signature`, and legacy `receipt_id`) and a `ReceiptV2SigningBody { body_hash, body }` wrapper. `body_hash := H(canonical_jcs(ReceiptV2BodyHashInput))`; signature is `keypair.sign_canonical(&ReceiptV2SigningBody)` per the existing `CapabilityTokenBody::sign` pattern at `chio-core-types/src/capability.rs:246-248`. `chio-spec-codegen` generates the typed struct from the JSON schema so the field set stays in sync.
- **`attenuation_proof` requires new code.** Earlier wording said T1.1 just makes the witness `validate_attenuation` "already computes" an on-the-wire field. That overstated the substrate: `validate_attenuation(parent, child)` only checks `child.is_subset_of(parent)` and returns `Ok(())` or `Err`; it does not produce a witness. T1.1 ships a new `compute_attenuation_witness` / `verify_attenuation_witness` pair alongside the existing checker, and the `attenuation_proof` field carries that witness on the wire. Both the promotion of `delegation_v2` primitives and the new witness API are required for the v2 token.

**Round-4 fixes:**
- **[Superseded by round-5]** `body_hash` definition pinned to avoid self-reference. The round-4 wording defined `BODY_HASH_INPUT = canonical(receipt_body_v2_struct \ {body_hash, signature, receipt_id})` and signature input as the byte-concat `BODY_HASH_INPUT || body_hash`, and retained the legacy UUIDv7 `receipt_id` on replay-store keys. **Round-5 replaces both of those design choices**: the signing input is now a typed `ReceiptV2SigningBody { body_hash, body }` struct signed via `sign_canonical` (matching the existing kernel pattern), and replay-store keys are `body_hash` only - the legacy UUIDv7 is a non-authoritative tooling alias. Do not implement against this round-4 entry; see the round-5 entry above and the T1.2 spec body. Three negative conformance cases were defined in this entry; they remain valid (mismatched `body_hash`, self-referential implementer error, signature-without-body_hash-commit) and are extended in round-5.
- **Capability-token algorithm enum corrected**: T2.1 adds **`hybrid`** to the enum (matching `signature.v1.json` which already has it, and the Rust `SigningAlgorithm` serde shape), not the alg-set strings `ed25519+mldsa65`. The alg-set string lives inside the self-describing wire-value pattern `hybrid:<classical>:<pq>:<alg_set>` on `issuer` / `subject` / signature fields, which T2.1 also updates.
- **Catalog convergence + C-3 + T-8 entries** updated: substrate primitives are `CapabilityToken.delegation_chain` + `Attenuation` + `validate_attenuation` behind `delegation_v2` (not the A2A bridge-fidelity `caveats: Vec<String>` strings); backend type is `HybridBackend` (not `HybridSigningBackend`); anchor-batch framing softened to "moves toward closure" with Evidence Gate references.
- **Optional split clarified**: cargo-vet burn-down stays in T1.4 / trj4b unless explicitly lifted into Tier 0 at scope-lock time. trj4a description corrected so it does not double-count cargo-vet work.

**Round-3 fixes:**
- **Threat baseline corrected to live PASS state**: gate on the trj4-planning branch is now PASS at 11 covered / 9 pending-with-`deferred_to` / 0 uncovered. The 3 mobile rows already carry `deferred_to: trajectory-4.M07.real-attestation`, so they are pending-with-deferral, not uncovered. trj4 work is to flip 9 pending rows to covered and add one missing test linkage; gate already passes today.
- **T1.1 reframed**: substrate already has `CapabilityToken.delegation_chain`, `Attenuation` (`crates/chio-core-types/src/delegation_receipt.rs`), `validate_attenuation` (`crates/chio-core-types/src/capability.rs:2452`) and a `delegation_v2` feature gate. The `chio-a2a-edge` `caveats: Vec<String>` strings are advisory bridge-fidelity prose, not authority-bearing primitives. T1.1 promotes and unifies the existing delegation primitives into the negotiated token schema; it does not lift A2A bridge caveats into `ToolGrant`.
- **T1.2 receipt-id migration plan added**: kernel today uses `next_receipt_id("rcpt")` (UUIDv7), and lineage is v1 single-parent. T1.2 adds a signed `body_hash: H(canonical(receipt_body))` field and a content-addressed `receipt_id_v2` namespace, with legacy UUIDv7 IDs accepted in v1 receipts. Acyclicity invariants reference the new `body_hash`/`receipt_id_v2` lane.
- **T2.1 hybrid PQ scope expanded**: backend type is `HybridBackend` (not `HybridSigningBackend`); `KernelTrustExchange` stores a concrete local `Keypair`. `spec/schemas/chio-wire/v1/capability/token.schema.json` enumerates only `["ed25519", "p256", "p384"]` while `signature.v1.json` already enumerates `["ed25519", "p256", "p384", "hybrid"]`. T2.1 must include capability-token schema additions (the `hybrid` enum variant per round-4 correction; the alg-set string `<classical>+<pq>` belongs inside the self-describing wire-value pattern, not the algorithm enum) and wire-format sync, not just making `KernelTrustExchange` generic.
- **T1.3 anchor-batch overclaim softened**: changed from "closes the `audit_only` / `transparency_preview` ceiling" to "moves toward closure". Added explicit close-bar items for claim registry update, proof manifest update, public-witness semantics doc, and negative conformance tests.
- **Closeout-blocker continuity**: `.planning/trajectory-3/CLOSEOUT-BLOCKERS.md` currently has only the M10 entries (AWS Marketplace, MCP Registry); `TRAJECTORY-FINAL.md` references a 10-blocker catalog. trj4 declares this as a deliberate scope reset and inlines the carry-forward list (below) rather than restoring the 10-row file.
- **T0 reconciliation gate** added as mandatory prerequisite for any T1 work.
- **T1.5 SRE/log redaction promoted to mandatory**; T2.3 trust-graph quorum/rotation pushed to stretch.
- **Evidence Gate added for T1**: every T1 slice updates `spec/PROTOCOL.md`, schemas, claim registry, proof manifest, theorem inventory, generated proof report, and ships negative conformance tests before close.
- **Cross-surface conformance** added to T2.1: MCP wrapped mode, hosted/native edge, A2A or HTTP - deny receipts, lineage class, revocation, budget, no adapter bypass.
- Two cheap T0/T1 items added: policy/manifest semantic diff gate; HTTP SSRF contract.
- Signed-artifact registry / compat gate added: new signed artifacts fail closed on unknown schema IDs.
- **Optional split** noted: trj4a (substrate closeout) vs trj4b (multi-agent trust primitives) if a single 12-15 week trajectory is too wide for available staffing.

## Scope rule (unchanged)

Trajectory-4 is internal-only code work. Out of scope: design partners, vendor crypto review, HITRUST audit, AWS Marketplace publication, MCP Registry publication, real partner cosign-OIDC sig (M02), 30-day pilot, TestFlight cohort, external red-team. See `REJECTED-IDEAS.md` for the full list of considered-but-cut items.

### Carry-forward from trj3 (closeout-blocker reset)

`.planning/trajectory-3/CLOSEOUT-BLOCKERS.md` was reduced to the M10 entries; the prior "10-blocker catalog" referenced in `TRAJECTORY-FINAL.md` is not restored. trj4 declares this a deliberate scope reset and tracks the substantive carry-forward inline:

- M10.1 - AWS Marketplace listing publication (operator action, not engineering).
- M10.2 - MCP Registry entry publication (operator action, not engineering).
- M01 - 30-day production-traffic pilot (needs partner).
- M02 - real partner cosign-OIDC signature (needs partner).
- M07 - real mobile attestation verifiers (this trajectory, see Tier 0 Phase C).
- M08 - vendor crypto-protocol review (needs vendor SOW; defer to trj5+).
- M09 - HITRUST i1 cert (needs External Assessor; defer to trj5+).

Items the trj3 closeout posture filed under M01/M02/M08/M09/M10 that need engineering inputs (evidence packs, threat-model schema, equivalence proofs, etc.) are absorbed into Tier 0 + Tier 1 below as preparation work; the vendor-calendar items themselves stay external.

## Theme

**Multi-agent trust primitives, with substrate hardening as the floor.**

Two cross-cutting consensus moves drive trj4:

1. **4-way consensus**: macaroon-style capability attenuation. The substrate already has `CapabilityToken.delegation_chain`, `Attenuation` step structure, and `validate_attenuation`. trj4 promotes these from `delegation_v2` feature-gated primitives to negotiated, schema-tagged, on-the-wire token v2 with caveats and `attenuation_proof`.
2. **2-way consensus**: anchor-batch Merkle trees. Additive over per-receipt signing; the immediate local receipt remains independently verifiable. Closes per the Evidence Gate (claim registry + proof manifest + public-witness semantics + negative conformance), not on the strength of the artifact alone.

These two combine with the floor's mobile-attestation work to make the trust boundary multi-agent-aware, hardware-rooted, and publicly anchorable.

## Tiered scope (four tiers)

Each tier compounds on the prior. Tier 0 is mandatory for any close. Tiers 1+ are scope-locked separately.

### Tier 0 - The floor (8-10 weeks single-track)

Required for any trj4 close. Earns the right to add anything else.

**Phase A (W1-2): trj3 closeout finalization + reconciliation gate**

The reconciliation gate (new in round-3) is mandatory before Phase B. No T1 work begins until this passes:

- Drive remaining trj3.2 PRs through CI cascade-merge.
- Tag `v3.18.1-trj3.1`; trigger release-binaries + slsa + reproducible-build workflows.
- Commit produced artifacts to `releases/provenance/`, `releases/reproducible-builds/`, `supply-chain/checksums/`.
- Replace TODO markers in `TRAJECTORY-FINAL.md` + `.planning/trajectory-3/work/CI-DEBT.md` with real close SHA + run URLs.
- Drain remaining trj3.2 P2 backlog.
- **Reconciliation gate** (T0.gate): CI-DEBT TODOs at zero; trj3 carry-forward catalog re-stated in this plan; release anchors (`v3.18.1-trj3.1`) live; deferred Kani/mutants/TLA tickets enumerated; threat baseline confirmed at 11/9/0 PASS.

**Phase B (W2-6): substrate hardening**
- Unblock hosted nightly cargo-mutants. Drive each trust-boundary crate kill rate to >= 65%, >= 80% on `chio-attest-verify` with `# unreachable: <justification>` annotations.
- Three deferred Kani harnesses: `chio-attest-verify`, `chio-anchor`, `chio-weights`.
- TLA+ rewrites: `RevocationCutCompleteness` transitive closure, `ReceiptBeforeAllow` split into `LogReceipt` + `PublishAllow`. Bump `EpochMax` to 6. Fix `RevocationEventuallySeen` apalache temporal lane back to required.
- Hosted-vs-portable equivalence property test in CI: 10k cases per PR + 1M nightly, zero divergence.
- `trust_control_cluster_multi_region_partition_qualification` root-cause fix.
- `chio-tee-frame::validate` real signature verification. `chio-tee-frame::schema::validate_timestamp` real RFC-3339 parse.
- **NEW: HTTP SSRF contract** (cheap, high-value): typed `HttpEgressContract` enforced in `chio-http-core`. Outbound HTTP from kernel/guard/adapter code paths must declare `{tenant_egress_namespace, allowed_schemes, allowed_authority_set, deny_loopback, deny_link_local, deny_ipv6_ula, max_redirect_chain, max_response_bytes}`. Closes a fail-open class around tool-call-driven SSRF.
- **NEW: policy/manifest semantic diff gate** (cheap): for any PR touching `chio-policy` or manifest schemas, CI runs a structural diff (which calls newly allow / deny / widen scope) and posts the result on the PR; reviewers must explicitly acknowledge widenings.

**Phase C (W6-8): mobile attestation real verifiers**
- Apple App Attest real verifier (CBOR + cert chain + counter monotonicity + nonce binding + KeyId binding) replacing `AttestationUnavailable`.
- Play Integrity real verifier (JWS + Google JWKS rotation + audience + nonce + verdict).
- Real `ChioKernel.xcframework` binary in `Frameworks/` with reproducible-build attestation.
- Threat-coverage flip for `mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`. These move from `coverage_state: pending` (with `deferred_to: trajectory-4.M07.real-attestation`) to `coverage_state: covered` with real conformance tests. The deferral comes home in this trajectory by design.

**Phase D (W8-10): meta-improvements + threat-coverage push**

- Threat-coverage cargo-mutants per-row gate.
- **Threat-coverage finishing push** (X-2). Starting state per `scripts/check-threat-coverage.sh`: 11 covered / 9 pending-with-`deferred_to` / 0 uncovered, gate PASS. Concretely:
  - Fill the 6 `unimplemented!()` stubs (`agent_velocity_abuse`, `behavioral_sequence_attack`, `cumulative_data_exfiltration`, `pii_phi_exposure`, `ssrf_via_http_substrate`, `wasm_guard_resource_exhaustion`); flip their `coverage_state` from `pending` to `covered`.
  - The 3 mobile rows (`mobile_attestation_replay`, `device_key_extraction`, `play_integrity_token_replay`) flip in Phase C.
  - Add explicit `covered_by_tests` linkage for `weights_hash_spoof`, the only currently-covered row with no test reference in JSON.
  - End state: 20 covered / 0 pending / 0 uncovered. Gate stays PASS throughout.
- Fail-closed philosophy audit doc.
- CI-DEBT.md final pass.

### Tier 1 - Multi-agent trust primitives (4-6 additional weeks)

T1.0 is the hinge; T1.1, T1.2, T1.3 ship after T1.0 and on top of each other. T1.4, T1.5, T1.6 parallelize.

**Evidence Gate** (mandatory for every T1.x slice): each slice closes only when it has updated `spec/PROTOCOL.md`, the relevant JSON schemas under `spec/schemas/`, the claim registry, the proof manifest, the theorem inventory, and the generated proof report; and shipped at least one signed negative conformance test that demonstrates the gate fails closed on the now-defined bad input.

**T1.0 Capability negotiation + token versioning (the hinge, ~1.5 weeks)**

- `chio.capabilities.v1` capability-negotiation handshake (P-11): peer advertises feature bitset; without it every additive proposal forces flag-day rollouts.
- `CapabilityToken` schema-tag (P-1): adds the `schema` field on the only major signed artifact lacking one. Closes the "unknown schema rejected" gap.
- Capability-token versioning story: explicit `chio.capability.v1` (current shape, frozen) + `chio.capability.v2` (with caveats, `attenuation_proof`, hybrid PQ). v1 peers stay on default; v2-aware peers negotiate up.
- **NEW: Signed-artifact registry / compat gate** (cross-cutting). Catalog every signed artifact's schema ID in a single registry; load-time and verify-time both reject any signed artifact whose `schema` is unknown to the verifier. Pairs with the negotiation handshake to make negotiated upgrades explicit.

**T1.1 Macaroon capability attenuation, promoting existing primitives (~3 weeks, gated on T1.0)**

The substrate already has the authority-bearing primitives: `CapabilityToken.delegation_chain`, `Attenuation` step structure (`crates/chio-core-types/src/delegation_receipt.rs:63-110`), `validate_attenuation` (`crates/chio-core-types/src/capability.rs:2452`), and `validate_delegation_chain`, behind the `delegation_v2` feature gate. The `chio-a2a-edge` `caveats: Vec<String>` strings are advisory bridge-fidelity prose, not authority. T1.1 unifies the real primitives into the negotiated v2 schema; it does not lift A2A caveats into `ToolGrant`:

- Promote `delegation_v2` from feature-gated to default-on, behind `chio.capabilities.v1` negotiation.
- Lift `Attenuation` and `ScopeAttenuation` into the `chio.capability.v2` schema as first-class fields rather than feature-gated extensions.
- Encode typed caveats in the v2 token (`{kind, predicate, sig?}`); the kernel's existing `validate_attenuation` enforces subset-of-parent at runtime.
- `attenuation_proof: { parent_scope_hash, child_scope_hash, normalized_subset_proof }` embedded so verifiers skip scope normalization (P-8). **Note (round-5 correction)**: today's `validate_attenuation(parent, child)` only checks `child.is_subset_of(parent)` and returns `Ok(())` or `Err`; it does **not** produce a witness. T1.1 ships a new witness-generation API alongside it: `compute_attenuation_witness(parent: &ChioScope, child: &ChioScope) -> Result<AttenuationWitness>` records the normalized canonical encoding of each scope (the inputs `validate_attenuation` checks), the per-grant subset relation, and any restricted predicates. A symmetric `verify_attenuation_witness(parent_hash, child_hash, witness) -> Result<()>` is faster than re-deriving subset normalization. T1.1 promotes existing `delegation_v2` primitives **and** adds the witness API; both must land for the v2 token to make sense on the wire.
- `chio-federation::delegation::issue_token` / `verify_chain` for cross-org scoped delegation (T-1).
- `SubAgentBudgetPropagation` (C-4): `BudgetSplit` carried in child receipts and verified at join. **Use fixed-point integer units (basis points or micros) for the share field.** Floats inside signed/canonical authority artifacts are a footgun.
- **A2A bridge fidelity stays advisory**. The bridge-fidelity strings in `chio-a2a-edge` continue to document what the A2A protocol cannot project; T1.1 does not touch them.

Result: sub-agents cannot re-amplify parent privileges; multi-org delegation is short-lived/scoped/revocable; verifiers have a witness instead of having to re-derive; existing in-tree primitives become first-class wire fields.

**T1.2 Multi-agent receipt DAG with fork/join + receipt-id migration (~3 weeks; +1 week vs prior estimate for migration)**

Tighten the formal model first; otherwise the DAG is just a tree with extra fields.

**Receipt-id migration (new in round-3, refined in round-4)**: kernel today uses `next_receipt_id("rcpt")` which formats a UUIDv7 (`crates/chio-kernel/src/receipt_support.rs`); receipt lineage is currently v1 single-parent (`EdgeKind::ReceiptLineageParent`). The DAG and replay invariants below cannot rest on "receipt_id is already a content hash" - it isn't. Migration plan:

- Define a typed **`ReceiptV2BodyHashInput`** struct in `chio-core-types` containing every v2 receipt body field **except** `body_hash`, `signature`, and the legacy UUIDv7 `receipt_id`. `body_hash := H(canonical_jcs(ReceiptV2BodyHashInput))` where `canonical_jcs` is RFC 8785 over the typed struct (matches the existing kernel `sign_canonical` pattern). Documented in `spec/PROTOCOL.md` and pinned by a Lean theorem so the input set cannot drift; `chio-spec-codegen` generates `ReceiptV2BodyHashInput` from the JSON schema so the field set stays in sync.
- Define a typed **`ReceiptV2SigningBody`** struct that wraps the body-hash input plus the hash itself: `ReceiptV2SigningBody { body_hash, body: ReceiptV2BodyHashInput }`. The signature is `keypair.sign_canonical(&ReceiptV2SigningBody)` per the existing pattern (`CapabilityTokenBody::sign` uses the same shape at `crates/chio-core-types/src/capability.rs:246-248`). Equivalent ad-hoc byte concatenations are forbidden; verifiers reconstruct the typed struct and re-canonicalize before verifying.
- Replay/dedup state is keyed **only** on `body_hash` (cryptographic identity). The legacy UUIDv7 `receipt_id` field is retained on the v2 wire shape as a **non-authoritative tooling alias**: chio-cli and explorer surfaces can look up "rcpt_..." prefixes through a separate index, but the replay store, the DAG verifier, and the lineage layer accept and reject only on `body_hash`. A tampered legacy `receipt_id` cannot affect replay acceptance because replay never reads it. Index lookups that miss in the alias index fall back to `body_hash` exact match; the alias is best-effort.
- v1 receipts continue to verify on the legacy single-parent UUIDv7 lane. v2 receipts add the new content-addressed lane. The negotiation handshake in T1.0 lets peers advertise `accepts_receipt_v2`.
- Negative conformance tests: (a) v2 receipt where `body_hash` does not match `H(canonical_jcs(ReceiptV2BodyHashInput))` recomputed from the wire body must fail closed; (b) v2 receipt where `body_hash` is recomputed over the wrong field set (self-referential or includes signature) must fail closed against the canonical hash; (c) v2 receipt where the legacy `receipt_id` is tampered with but `body_hash` and signature remain valid must still verify (the alias is non-authoritative by design) and must NOT cause replay confusion (replay keys on `body_hash` only); (d) v2 receipt where signature is not `sign_canonical(&ReceiptV2SigningBody)` (e.g., signed only the body or used a different hash function) must fail closed.

Cross-kernel ordering: this plan is multi-agent and cross-kernel, so a per-kernel `(epoch, seq)` cannot be used as a global parent-before-child predicate. The ordering proof has to live above the kernel-local clock.

- **Node IDs (post-migration)**: `receipt_id_v2 = body_hash`. Equal `body_hash` implies equal canonical body.
- **Parent-set hash**: `parent_set_hash = H(canonical(sort(parent_receipt_ids)))` so a verifier can cheaply check parent-set integrity.
- **Per-kernel local sequence**: each kernel maintains its existing monotone `(epoch, seq)`; valid for in-kernel ordering only.
- **Cross-kernel ordering (DAG ordinal)**: each receipt carries a `dag_ordinal: u64` plus an HLC-shape `(wall_seconds, logical, kernel_id)` triple. When a kernel signs a receipt with parents from foreign kernels, it sets `dag_ordinal = 1 + max(parent.dag_ordinal for parent in parent_receipt_ids)` and `(wall_seconds, logical) = max(local_now, max(parent.hlc.advance_logical()))`. Both are signed inputs of the receipt body. Standard HLC pattern; gives a total order over the receipt DAG that respects causality across independent kernel clock domains.
- **Acyclicity invariant**: a verifier rejects any receipt whose `dag_ordinal <= max(parent.dag_ordinal)`. Cross-kernel cycles are rejected without requiring a single global clock.
- **Fanout limit**: per-call-chain `fanout_max` advisory in policy; `AgentLoopBoundsGuard` (C-2) enforces depth + fan-out.
- **Join semantics**: `chio.receipt_lineage_statement.v2` carries `parent_receipt_ids: Vec<String>` (each is a `body_hash`); canonical sort + dedupe; verifier requires every parent to exist (locally or via T-10 cross-org receipt-join), share a common `chain_id` ancestor, and satisfy DAG-ordinal acyclicity.
- **Replay rules**: receipt with same `(chain_id, kernel_id, epoch, seq)` is rejected at the local store; on the wire, a duplicate `body_hash` is dropped fail-closed. Cross-kernel duplicate detection uses `body_hash`, not `(kernel_id, epoch, seq)`.

A vector-clock variant `(map<kernel_id, seq>)` is more expressive but pays a per-receipt size cost that grows with federation participants; the HLC + `dag_ordinal` shape is the lighter-weight equivalent.

**T1.3 Anchor-batch Merkle trees with public-witness checkpoints (~2 weeks)**
- New artifact `chio.anchor_batch.v1` carrying `{tree_root, checkpoint_ids[], witness: rekor|ots|solana_memo}` (P-4).
- Coalesced batch root computation: build a Merkle tree over N receipts/checkpoints, attach inclusion proof per element (S-2).
- **Reframing**: per-receipt local sign stays. The local receipt remains independently verifiable. The batch root is *additional*: it upgrades continuity (the batch attests N receipts as a set) and non-repudiation (the witness lane gives third-party timestamping).
- **Round-3 framing correction**: this **moves toward closure** of the `audit_only` / `transparency_preview` ceiling at PROTOCOL.md:657, but does not by itself close the ceiling. Closure requires (per the Evidence Gate):
  - Update to the claim registry recording the new artifact and its claim shape.
  - Update to the proof manifest tying claim to evidence.
  - Public-witness semantics doc explaining anti-equivocation, claim-completeness, and what failure modes look like (including what a missing or stale witness implies for receipts in the batch).
  - Negative conformance tests: forged batch root, mis-ordered inclusion proof, witness-lane impersonation.
  - Documented fallback when a witness lane (Rekor / OTS / Solana memo) is unavailable for > N minutes.
- Close-bar item (#16 below) reflects this softened framing.

**T1.4 Archaeology finish-line (~2 weeks parallelizable)**
- Threat-model coverage push lands inside T0 Phase D; this T1.4 covers the rest of the archaeology debt.
- `chio-hosted-mcp` real extraction (X-1): lift `remote_mcp/*.rs` into its own crate; both CLI and chio-hosted-mcp consume it normally. Half-day surgical fix.
- Provider-adapter-core extraction (X-4): shared SSE-gate orchestration + `LoadedWeights` impl helper + `Provider` trait. Cuts ~3 KLOC across 7 adapters.
- **Cargo-vet debt close-bar (X-10)**: trj4 enforces "no net-new exemptions" gate in CI; ship real audits for the top 50 highest-traffic dependencies (alloy-*, aws-sdk-*, tokio-*, hyper-*, tonic-*) to burn the count down by at least that 50.

**T1.5 Foundational SRE (~3 weeks parallelizable, MANDATORY in round-3 scope)**

Promoted to mandatory in round-3 because the operability story is the load-bearing non-cryptographic safety property; PHI-in-PagerDuty is the only zero-tolerance failure mode for any healthcare deployment.

- `chio-metrics-spec` workspace-wide const-string registry (O-1). Compile-time enforced via `describe!` macro + CI golden snapshot.
- Prometheus alert + recording rule pack in `deploy/prometheus/` (O-3). Burn-rate alerts (14.4x/1h + 6x/6h dual-window) for `slo.md` targets. Routes to OpsGenie/PagerDuty already wired in `chio-siem`.
- `chio-log-redact` (O-14): `tracing_subscriber::Layer` running every event through receipt's redaction tree. `redacted!()` macro rejects raw-string formatting. Eliminates an entire class of P0 (PHI in PagerDuty).

**T1.6 `chio explain <receipt-id>` CLI (~1 week)**

CLI only; full web explorer (DX-3) stays in T3 buffet. Walks: which policy clause matched, which guards fired, scope diff, parent receipt(s) (DAG-aware after T1.2), batch witness lane (after T1.3), repair hint if denied. Pairs with A-12 ("why was this called?" trace).

In T1 because it makes the new receipt-DAG, attenuation failures, and close-bar evidence legible while the team is still building them. Without it, debugging T1.1/T1.2/T1.3 is a JSON-grep exercise.

### Tier 2 - Foundational improvements (2-4 additional weeks)

**T2.1 Trust-boundary plumbing + cross-surface conformance** *(in recommended scope-lock)*

- **Hybrid PQ end-to-end** (T-8 expanded per round-3, algorithm-enum corrected per round-4). Three coordinated changes:
  - `KernelTrustExchange` accepts a generic `SigningBackend` (today it stores a concrete `Keypair`); accept `HybridBackend` instances at the Federation layer.
  - `spec/schemas/chio-wire/v1/capability/token.schema.json` adds **`hybrid`** to its `algorithm` enum (currently `["ed25519", "p256", "p384"]`) so it matches `spec/schemas/signature.v1.json` (already `["ed25519", "p256", "p384", "hybrid"]`) and the Rust `SigningAlgorithm` serde shape. The alg-set string `ed25519+mldsa65` does **not** belong in the enum; it lives inside the self-describing wire values.
  - Capability-token wire patterns updated so `issuer`, `subject`, and signature fields accept the hybrid wire prefix `hybrid:<classical>:<pq>:<alg_set>` (per `signature.v1.json:12`) alongside the existing `ed25519` / `p256:<...>` / `p384:<...>` patterns. Today those regexes are `^([0-9a-f]{64}|p256:[0-9a-f]{130}|p384:[0-9a-f]{194})$` for keys and the analogous shape for signatures.
  - Wire-format encoder/decoder paths (capability token, federation handshake envelope, receipt signing) treat the hybrid string format as a first-class case rather than a feature-gated branch.
- Conformance-tier handshake gating (T-5, `Bronze/Silver/Gold`): derived from threat-coverage + mutation-kill + Kani harness completeness. Data already produced; bind into peer record.
- **Cross-surface conformance** (new in round-3). T2.1 closes only when conformance tests pass on every advertised surface, not just one:
  - MCP wrapped mode (`chio-hosted-mcp`).
  - Hosted/native edge (`chio-tower`, `chio-http-core`).
  - A2A or HTTP edge (`chio-a2a-edge`, `chio-acp-edge`, or whichever is in the trj4 promoted set).
  - For each surface: deny receipts emit, lineage class is preserved, revocation propagates, budget enforcement is real, and there is no adapter bypass for capability/scope/guard checks.

**T2.2 Mediator hot path** *(stretch per reviewer)*
- Dispatch profile baseline + flame-graph CI artifact (S-1). Profile must land before T2.2's cache work.
- Lock-free verdict cache on kernel hot path: bounded LRU keyed by **fully-specified composite** `(cap_hash, scope, tool, guard_set_hash, policy_version, tenant_id, agent_id, caveat_state_hash, revocation_epoch, trust_root_epoch)`. Auto-invalidated on any component change. Pure-preflight-only - never caches a decision derived from a guard whose verdict depends on session state. Targets <5us p99 on hit.
- Tower load-shed middleware (S-7).

**T2.3 Trust-graph maturity** *(STRETCH in round-3 scope - pushed out to make room for mandatory T1.5)*
- M-of-N quorum-signed receipts (T-2): generalize `DualSignedReceipt` (2-of-2) to `QuorumSignedReceipt`. Bilateral becomes a degenerate case.
- Trust-anchor rotation ceremony with rotation attestation (T-3).
- DID-bound agent identity in receipts (T-9).

### Tier 3 - Frontier features (stretch buffet)

Pick 1-2 only if the recommended scope-lock lands fast.

| Tier-3 item | Effort | Lens |
|---|---|---|
| T3.1 Multi-modal receipt envelopes | XL | A-5 |
| T3.2 Agentic-deception detector (plan-vs-action diff) | L | A-4 |
| T3.3 Apple Secure Enclave kernel-key backend | M | H-1 |
| T3.4 RATS RFC 9334 evidence envelope | M | H-7 |
| T3.5 W3C trace propagation across kernel/federation/anchor | L | O-2 |
| T3.6 Streaming receipts | M | P-3 |
| T3.7 Structured-PII + Code-Secrets redactor packs | L+M | C-7+C-8 |
| T3.8 TransparencyLogReceiptExporter (Rekor-style) | L | C-13 |
| T3.9 Chaos-mesh experiment pack | L | O-7 |
| T3.10 Receipt-chain web explorer (full UI for `chio explain`) | L | DX-3 |
| T3.11 ML-shim PromptInjectionGuard | L | C-1 |
| T3.12 RAG citation attestation | L | A-6 |
| T3.13 Per-receipt output watermarking | L | A-7 |

## Recommended scope-lock (round-3 narrowed)

- **Tier 0** (full floor including reconciliation gate, HTTP SSRF contract, semantic-diff gate; 8-10 wk).
- **T1.0** (capability negotiation + token versioning + signed-artifact compat gate; ~1.5 wk).
- **T1.1** (macaroon attenuation by promoting existing `delegation_v2` primitives; ~3 wk).
- **T1.2** (receipt DAG + receipt-id migration to `body_hash`; ~3 wk).
- **T1.3** (anchor-batch Merkle trees, additive, with full Evidence Gate close requirements; ~2 wk).
- **T1.4** (archaeology finish-line + cargo-vet debt close; ~2 wk).
- **T1.5** (foundational SRE; **MANDATORY**).
- **T1.6** (`chio explain` CLI; ~1 wk).
- **T2.1** (hybrid PQ end-to-end including capability-token schema + cross-surface conformance).

**Stretch (ship if first half lands cleanly, otherwise slip to trj5)**:
- T2.2 hot-path verdict cache + Tower load-shed.
- T2.3 trust-graph maturity (quorum receipts + trust-anchor rotation + DID-in-receipts).
- T3 picks: 1-2 max.

Total estimated calendar: **14-18 weeks with two parallel lanes** (substrate-hardening + trust-primitives), **20-24 weeks single-track**. Round-3 widened by ~2 weeks over round-2 because of the receipt-id migration in T1.2, the Evidence Gate work, and the cross-surface conformance work in T2.1.

### Optional split: trj4a vs trj4b

If 14-18 weeks is too wide given available staffing, split into:
- **trj4a (closeout, 8-10 wk)**: Tier 0 only - substrate-hardening, mobile attestation, threat-coverage push to 20/20. Cargo-vet burn-down stays in T1.4 and ships in trj4b unless explicitly lifted into Tier 0 at scope-lock time. Tags as `v3.19.0-trj4a`.
- **trj4b (multi-agent primitives, 6-8 wk)**: Tiers 1 + 2.1, gated on trj4a close. Tags as `v3.20.0-trj4b`.

The split lets each half close independently, makes trj4a's "we earned credibility" claim explicit before primitives ship, and lets trj4b's evidence gates run against a known-clean substrate. Recommended if a single trajectory cannot get full parallel-lane staffing.

## Trj4 close bar (round-3)

All must hold simultaneously, evidenced in `releases.toml` and reproducible from a cold checkout.

**From the floor (Tier 0)**:
1. CI-DEBT fully reconciled.
2. Hosted nightly cargo-mutants runs to completion; kill rate >= 65% per trust-boundary crate, >= 80% on `chio-attest-verify`.
3. 6/6 trust-boundary crates have Kani harnesses passing in nightly.
4. `RevocationCutCompleteness` transitive + `ReceiptBeforeAllow` split landed; `RevocationEventuallySeen` apalache lane back to required.
5. Equivalence property test passing 1M cases nightly, zero divergence.
6. `trust_control_cluster_multi_region_partition_qualification` 100/100 runs at 20 partition/heal cycles.
7. Mobile attestation entry points return real verdicts on real fixtures; xcframework binary in tree.
8. **Threat-model coverage at 20/20** per `scripts/check-threat-coverage.sh`. Starting from 11 covered / 9 pending-with-`deferred_to` / 0 uncovered (gate PASS today): trj4 fills the 6 `unimplemented!()` stubs (`pending -> covered`), lands tests for the 3 mobile rows (`pending -> covered`, deferral resolved this trajectory), and adds `covered_by_tests` linkage for `weights_hash_spoof`. End state: 20 covered / 0 pending / 0 uncovered, gate stays PASS.
9. `v3.18.1-trj3.1` tag shipped with green release-binaries + slsa + reproducible-build artifacts.
10. `TRAJECTORY-FINAL.md` committed with real close SHA.
11. `HttpEgressContract` enforced on every kernel/guard/adapter outbound HTTP path; SSRF negative conformance tests pass.
12. Policy/manifest semantic-diff gate live on every PR touching `chio-policy` or manifest schemas.

**From multi-agent primitives (T1.0 through T1.6)**:
13. `chio.capabilities.v1` capability-negotiation handshake live; peers advertise feature bitsets.
14. `CapabilityToken` schema-tagged; `chio.capability.v2` envelope shipped with caveats and `attenuation_proof`. Signed-artifact registry / compat gate rejects unknown schema IDs at load and verify time.
15. `delegation_v2` promoted to default-on; `Attenuation` and `ScopeAttenuation` are first-class fields in the negotiated v2 token. `validate_attenuation` enforces subset-of-parent at runtime; new `compute_attenuation_witness` / `verify_attenuation_witness` APIs ship alongside, and the `attenuation_proof` field on `chio.capability.v2` carries that witness on the wire.
16. `SubAgentBudgetPropagation` enforced at join, using fixed-point integer share units.
17. `chio.receipt.v2` ships with signed `body_hash` field; `receipt_id_v2 = body_hash`; legacy UUIDv7 `receipt_id` continues to verify on v1 receipts. v1->v2 negotiation works.
18. `call_chain` extended from tree to DAG with cross-kernel-safe formal model: parent-set hash, signed `dag_ordinal` + HLC triple, acyclicity invariant `child.dag_ordinal > max(parent.dag_ordinal)`, replay rules keyed on `body_hash`. `chio.receipt_lineage_statement.v2` deployed.
19. `chio.anchor_batch.v1` published with at least one witness lane (Rekor or OTS) - additive over per-receipt signing. Claim registry, proof manifest, and public-witness semantics doc updated; negative conformance tests for forged root, mis-ordered proof, witness-lane impersonation, and stale-witness fallback all pass.
20. `chio-hosted-mcp` no longer `#[path]`-splices CLI internals.
21. Provider-adapter-core extracted; existing 7 adapters refactored to consume it.
22. **Cargo-vet exemption count**: no net-new exemptions added during trj4; top-50 dependency burn-down completed (target: 819 -> <= 769 exemptions).
23. **T1 Evidence Gate**: every T1.x slice has updated `spec/PROTOCOL.md`, schemas, claim registry, proof manifest, theorem inventory, generated proof report; and shipped at least one signed negative conformance test.
24. `chio-metrics-spec` workspace-wide registry live; alert pack deployed (T1.5).
25. `chio-log-redact` enforces redaction at log layer with compile-time `redacted!()` macro (T1.5).
26. `chio explain <receipt-id>` CLI ships and renders DAG + attenuation chain + batch witness + repair hint.

**From foundational improvements (T2.1)**:
27. `KernelTrustExchange` accepts generic `SigningBackend`; `HybridBackend` works in the federation handshake.
28. Capability-token schema (`spec/schemas/chio-wire/v1/capability/token.schema.json`) adds the hybrid algorithm; wire-format encoder/decoder paths are first-class.
29. Conformance-tier handshake gating live; tier derived from substrate evidence.
30. Cross-surface conformance suite passes on MCP wrapped, hosted/native, and A2A or HTTP - deny receipts emit, lineage preserved, revocation propagates, budget enforced, no adapter bypass.

## Calendar

- **Recommended scope (T0 + T1.0/1/2/3/4/5/6 + T2.1)**: 14-18 weeks parallel; 20-24 weeks single-track.
- **+ T2.2 (verdict cache + Tower shed)**: +2-3 weeks if S-1 profile green-lights cache work.
- **+ T2.3 trust-graph maturity**: +3-4 weeks; stretch.
- **+ T3 picks**: +3-6 weeks per item; opt-in second half.

If split into trj4a + trj4b: 8-10 weeks + 6-8 weeks back-to-back.

## What this synthesis explicitly cuts

- Vendor-calendar items (HITRUST, NCC/ToB, AWS Marketplace, MCP Registry publication).
- Design partner / customer outreach.
- Real partner cosign-OIDC sig (M02) - needs partner.
- TestFlight / mobile alpha cohorts.
- Multi-cloud marketplace listings.
- Operator agent that watches its own metrics and remediates.
- AI-assisted policy authoring.
- ZK proofs of policy compliance (research spike, not trj4).
- Differential-privacy aggregate receipts.
- CBOR/HTTP-3 native wire (would invalidate Lean+Kani lane).
- OCSP-shape revocation.
- Custom executor / replace tokio.
- SIMD canonical JSON.
- Intel SGX backend.
- DataDog dashboard pack.
- CAPTCHA bypass.
- Real-time semantic ML prompt-injection classifier in hot path.

See `REJECTED-IDEAS.md` for full rationale.
