# Position 02 - Protocol Realization Engineer

**Author role:** Protocol Realization Engineer
**Date:** 2026-05-07
**Thesis:** Trj5 must close the spec-vs-runtime gap. `spec/PROTOCOL.md` is the normative artifact; the kernel and verifier hot paths systematically lag the schemas. Capability negotiation, attenuation witnesses, receipt DAG body-hash, anchor-batch Merkle, sibling-sum budgets, hybrid PQ -- the types exist, one or two callers are wired, but `chio-kernel-core` does not enforce these on every governed decision. This is the defect the trj4 erratum diagnosed but did not fix. Trj5 should be the **Protocol Realization Sprint**: finish the wiring, lock the spec to enforced behavior, ship one normative spec version with a conformance suite that fails any unwired implementation.

---

## 1. Five normative MUSTs whose hot path is not yet enforced

The trj4 erratum (`/.planning/trajectory-4/TRAJECTORY-4-CLOSEOUT-ERRATUM.md` line 11) is the load-bearing finding: "structural framing landed but runtime wiring did not." The W1.5 hot-path commit (`05fd0c56e`), the W2.2 egress-contract commit (`708c7bb33`), the W2.3 anchor-witness commit (`7ee1ddbcc`), and the W2.4 metrics commit (`75813d234`) prove the wiring lane works. But the spec contains several normative MUSTs whose enforcement runtime is still partial. Concretely:

### 1.1 W1.5 composite verifier exists but is not the only entry point

`spec/PROTOCOL.md` lines 408-418 say production kernels SHOULD prefer `chio_kernel_core::verify_capability_full(token, trusted_issuers, clock, crypto_floor, peer, trust_root, budgets)`. The composite is implemented at `crates/chio-kernel-core/src/capability_verify.rs:400-476` and chains W1.3 schema-ceiling, W1.1 chain-binding, W1.2 sibling-sum admission, signature, floor, and time-bound checks in one fail-closed pass. But `crates/chio-kernel/src/kernel/mod.rs:4035-4047` defines `verify_capability_full_without_budget_admit`, called at `mod.rs:2898` and `mod.rs:3403`, as the production hot-path entry. The W1.2 budget admit is split off, and the legacy `verify_capability_signature` at `mod.rs:4005` still has callers (`mod.rs:2452`, `mod.rs:2706`). One internal helper is **not** the same as one normative entry. The spec should be hardened to a MUST and `verify_capability_signature` declared a non-production helper.

### 1.2 Receipt v2 production mint is gated on a peer feature, not a normative invariant

`spec/PROTOCOL.md` lines 714-741 ("Receipt v2 body_hash addressing (W2.1)") say: "the kernel mints v2 receipts at production mint time when peer negotiation selects v2." Implemented at `crates/chio-kernel/src/kernel/mod.rs:1116-1542` (`receipt_v2_replay: Mutex<ReceiptV2ReplaySet>`, gated on `ACCEPTS_RECEIPT_V2` at `mod.rs:1152`). The downgrade path emits "a structured warning so operators can see receipt-version regressions" (PROTOCOL.md line 740). Warnings are not enforcement. The spec language permits receipt v1 indefinitely; the conformance suite (`crates/chio-conformance/tests/protocol_primitives_t1.rs`, `crates/chio-conformance/tests/v2_receipt_kernel_round_trip.rs`) does not have a negative test that fails when a kernel built without `ACCEPTS_RECEIPT_V2` advertisement signs a governed receipt. The spec should be tightened: in profiles where `chio.capability.v2` is the ceiling, the receipt MUST be v2; v1 is rejected fail-closed.

### 1.3 Anchor-batch verify-inclusion is async; producer wiring is sync-only on some lanes

`spec/PROTOCOL.md` lines 982-991 are explicit: "`require_public_witness: true`, `Witnessed` on the sync path -> reject; use the async verifier path so `AnchorWitnessClient::verify_inclusion` runs." The contract is in `crates/chio-anchor/src/batch.rs:227-258` (`verify_anchor_batch_with_witness_policy`, `_async`). But several producer call sites still run `verify_anchor_batch` (the bare sync form) at `batch.rs:208` and the unit-test path at `batch.rs:361-396`. The conformance tests `crates/chio-conformance/tests/anchor_batch_{forged_root, misordered_proof, witness_impersonation, stale_witness_fallback}_rejected.rs` exercise the `verify_anchor_batch` and `verify_anchor_batch_with_witness_policy` paths -- but not the rule that producers in `chio-anchor` and `chio-anchor`-consuming crates MUST route through the async path when `require_public_witness=true`. PROTOCOL.md mandates this; the conformance suite should fail any caller that does not.

### 1.4 Hybrid PQ wire-format is first-class in types, but the kernel keypair is still concrete

PROTOCOL.md sections 4.1, 4.4, 5 (lines 173-177, 233-238, 277-285) define the `hybrid:<classical>:<pq>:<alg_set>` wire prefix and require verifiers to "dispatch from the signature prefix, confirm any present `algorithm` hint matches that prefix, and reject mismatches fail-closed." Lane F evidence in `audits/T2.1-hybrid-pq-cross-surface.md` lines 70-74 says `KernelTrustExchange` was lifted to a `SigningBackend`. But `crates/chio-kernel/src/kernel/mod.rs:876-927` only mentions hybrid signing at the boot port (`Box<dyn chio_core::crypto::SigningBackend>` returned from `KernelBootError`). The concrete hot path -- the receipt signer in `chio_kernel_core::sign_receipt` (`crates/chio-kernel-core/src/receipts.rs`) -- still threads a single `Keypair`-shaped argument. The MUST in PROTOCOL.md 4.1 is "dispatch from the signature prefix"; the kernel hot path is still classical-by-default, hybrid-by-opt-in. The spec should be tightened: in the negotiated `accepts_hybrid_signatures` profile, every produced receipt MUST be hybrid-signed.

### 1.5 Metered-billing usage evidence and approval-token thresholds are framed but not gate-enforced

PROTOCOL.md lines 472-555 define `governed_intent`, `approval_token`, `metered_billing.quote`, and the verification rule (PROTOCOL.md lines 502-507): "the kernel requires a valid `approval_token` whenever the provisional charged amount meets or exceeds that threshold." There is a `governed_transaction.metered_billing` block in receipts and a `usageEvidence` field added post-execution (PROTOCOL.md lines 825-837). But there is no negative-conformance test that demonstrates: (a) a tool call whose pre-execution quote fits under `require_approval_above` but whose post-execution metered usage exceeds it is **denied or re-mediated** rather than silently allowed; (b) a tampered `usageEvidence` cannot rewrite the receipt's signed `financial.charge`. PROTOCOL.md says reconciliation state is "not written back into the signed receipt" but the runtime gate is implicit. Trj5 must add the negative tests and the explicit hot-path check.

### 1.6 (Bonus) Negotiated `maxCapabilitySchema` is enforced; `accepts_anchor_batch_v1` is not

PROTOCOL.md lines 296-303 enumerate the negotiation feature bitset: `accepts_capability_v2`, `accepts_receipt_v2`, `accepts_anchor_batch_v1`, `accepts_hybrid_signatures`. W1.3 schema-ceiling enforcement (capability_verify.rs:226-255, `verify_capability_with_negotiated_floor`) is the only one of the four that is hot-path-wired through `verify_capability_full`. `accepts_anchor_batch_v1` is checked at federation handshake but not at every batch-verification site. There is no symmetric ceiling-enforcement entry point for anchor-batch wire artifacts when a peer has not advertised support.

### 1.7 (Bonus) `attenuation_proof.parent_scope_hash` direct-issue case requires a `TrustRootResolver` that not all callers provide

PROTOCOL.md lines 396-401 mandate: "A direct-issue v2 token (empty `delegation_chain`) MUST have `attenuation_proof.parent_scope_hash` equal to the verifier's trust-root scope hash for the issuing authority." The portable entry point `verify_capability_with_floor_and_resolver` (capability_verify.rs:352-377) takes `&dyn TrustRootResolver`. The convenience wrapper `verify_capability_with_floor_and_trust_root` (line 327) takes a single `&ScopeHash`, which is **not** sufficient when the kernel has multiple registered authorities. Callers that wire the wrong entry point silently accept a v2 direct-issue token whose `parent_scope_hash` matches **some** trust root rather than the issuer-bound one. The spec should normatively require the resolver-bearing entry point in any kernel with more than one trust root.

---

## 2. Why this is more important than substrate hardening, WASM v4, or decomposition

The Substrate Hardening Hawk (Position 01) wants to drag Wave 0-7 of the typed-coalescing-hejlsberg plan to closure: 65% mutation kill on trust-boundary crates, six Kani harnesses nightly green, Apple App Attest real-device fixtures, exemption burn-down. **All correct**, but those are floor-level guarantees on individual primitives. The Decomposition Advocate (Position 03) wants `ToolServer` async-trait, builder-finalize, `chio-cli` decomposed. **All correct**, but those are surface-area improvements on the substrate.

Protocol realization is the **ceiling check**. Substrate hardening makes the existing `verify_capability_full` call provably correct. Decomposition makes new hot-path wiring less expensive. Neither answers the question that the trj4 erratum poses: when an external auditor reads `spec/PROTOCOL.md` and asks "where is the runtime that enforces section 5.1.3 chain-binding on every governed decision?", does the codebase have a single answer? Today it has five answers (`verify_capability`, `verify_capability_with_floor`, `verify_capability_with_negotiated_floor`, `verify_capability_with_floor_and_trust_root`, `verify_capability_full`) and the production hot path branches between them based on which `&mut self` setter the caller already configured. That is not a substrate problem. That is a spec-vs-runtime problem.

The brand of Chio is "auditable outcomes." An unwired MUST on the hot path is a falsifiable claim in the spec. Every MUST-without-test is an open invitation to a future erratum. Substrate hardening adds bricks; decomposition rearranges rooms; protocol realization is the load-bearing wall.

The WASM Guard v4 work (Position 05) is, frankly, a userland concern relative to this. A guard SDK that a customer can write and ship is great, but a guard SDK over a kernel where the spec's MUSTs are only sometimes enforced is a guard SDK over a non-conforming kernel. We don't have customers. We have one repo claiming a normative protocol. Closing the spec is the precondition for any user-facing claim, and certainly the precondition for any partner who wants to interop.

---

## 3. Protocol Realization Sprint structure (4-6 weeks)

**Lane R1 -- Single-entry verifier (1 week).** Promote `verify_capability_full` to the only production verifier. Make the partial entry points (`_with_negotiated_floor`, `_with_floor_and_trust_root`, `_with_floor_and_resolver`, `verify_capability_with_floor`) `#[doc(hidden)]` and crate-private wherever possible. PROTOCOL.md 5.4 changes from SHOULD to MUST. Evidence Gate: a workspace lint at `scripts/check-verify-capability-full.sh` that fails on any production caller using a partial entry; a negative-conformance test at `crates/chio-conformance/tests/verify_full_is_only_production_entry.rs` that compiles only when the partial entries are removed from the public API.

**Lane R2 -- Receipt v2 mandatory under v2 negotiation (1 week).** When the negotiated `maxCapabilitySchema` is `chio.capability.v2`, the kernel MUST mint receipt v2 for every governed dispatch. Currently the dual-mint at `crates/chio-kernel/src/kernel/mod.rs:1148-1165` is best-effort with a warning. Evidence Gate: spec section 6 amended from "the kernel falls back to minting only the v1 UUIDv7 receipt" to "fails closed when v2 was negotiated"; negative test at `crates/chio-conformance/tests/receipt_v2_required_under_v2_negotiation.rs` that fails when the mint path is patched out.

**Lane R3 -- Anchor-batch async-only when `require_public_witness=true` (1 week).** Producers MUST route through `verify_anchor_batch_with_witness_policy_async` whenever the policy is true. Evidence Gate: a `scripts/check-anchor-batch-async-witness.sh` lint; a negative-conformance test at `crates/chio-conformance/tests/anchor_batch_sync_path_rejected_under_public_witness.rs`. Spec section 6.4.1 promotes the existing language from descriptive to normative.

**Lane R4 -- Hybrid signing as default under `accepts_hybrid_signatures` (1.5 weeks).** When the negotiated profile has `accepts_hybrid_signatures=true`, every emitted capability, receipt, checkpoint, and anchor batch MUST be hybrid-signed. Today only the federation handshake is. Evidence Gate: `crates/chio-conformance/tests/hybrid_signature_required_under_negotiation.rs`; spec section 4.1 tightened.

**Lane R5 -- Metered-billing post-execution gate (1 week).** Add a hot-path check that compares post-execution `usageEvidence` against the approval-token threshold. If the actual exceeds the approved, the kernel MUST issue a `Cancelled { reason }` or `Incomplete { reason }` receipt rather than `Allow`. Evidence Gate: `crates/chio-conformance/tests/metered_billing_post_execution_threshold_enforced.rs`.

**Lane R6 -- Conformance suite freeze + spec v3.1 (0.5-1 week).** Bundle Lanes R1-R5 into a single normative spec version. Every primitive in the suite has: enforced call site + spec section reference + signed negative conformance test. Spec ID becomes `chio-protocol@3.1.0`. The conformance suite's signed corpus root is bound to this ID.

Each lane's Evidence Gate demands the trio: **enforced call site** in production code, **spec section reference** in the test docstring, **signed negative conformance test** that fails when wiring is removed. No structural framing without runtime wiring. No runtime wiring without conformance. No conformance without spec citation.

---

## 4. Scope cap (concession)

**Out of scope for release work:**

- **Chiodos pheromone, chiodos selective disclosure, chiodos ladder.** `spec/CHIODOS_PHEROMONE.md`, `spec/CHIODOS_SELECTIVE_DISCLOSURE.md`, `spec/CHIODOS_LADDER.md`, `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` are research drafts. They do not yet have one wired caller; trying to realize them is premature.
- **OID4VP / public identity network artifacts.** PROTOCOL.md section 10.1.x is a large surface that is mostly already at the "informational unless explicitly imported" boundary. No realization gap; leave it.
- **Underwriting / credit / facility / market discipline (PROTOCOL.md sections 9 partial).** Already shipped as bounded; no spec MUST that is unwired on the kernel hot path. Leave alone.
- **Third-party caveats with discharge** (audits/T1.1 line 19 explicitly punts these). Stay punted.
- **Hardware attestation buffet** (Apple Secure Enclave kernel-key, TPM 2.0, Azure MAA hot-binding). Already conceded by Position 01 to the customer-driven slice; release work protocol realization explicitly excludes.
- **`chio-cli` decomposition** (Position 03's main ask). Necessary, not load-bearing for protocol realization. Defer to trj6.

The cap is sharp: release work protocol realization is **the seven W*.x primitives that already have types and one or two callers**. Nothing else. If a primitive is at "design-only" or "one prototype caller", it is out.

---

## 5. Composition with the trj4 wave plan

The trj4 wave plan (`local trajectory-4 closeout plan`) is wave-by-wave closeout of the 30 P0/P1 issues. Lanes R1-R5 above are NOT a separate trajectory; they are **the natural continuation of W1.5-W2.4** that just landed. Specifically:

- W1.5 (commit `05fd0c56e`) wired chain-binding + negotiation + sibling-sum across 5 surfaces. Lane R1 promotes that wire to the only production entry.
- W2.1 wired receipt v2 production mint. Lane R2 makes it mandatory.
- W2.3 (commit `7ee1ddbcc`) wired AnchorWitnessClient. Lane R3 closes the sync-vs-async producer gap.
- W2.4 (commit `75813d234`) wired metrics. Composes with R1-R5: every realized primitive emits a metric.

**Recommendation:** absorb Lanes R1-R5 into Wave 3-7 of the existing trj4 wave plan. Do not start a separate release work with new branding. The trj4 erratum lost a credibility round; restoring credibility means **finishing the same plan with the same naming**, not pivoting to "release work protocol realization" as if it were new work. The spec v3.1.0 freeze (Lane R6) is the trj4 closeout deliverable that justifies removing the `reopened` status from `releases.toml`.

If the council insists on a separate release work, the structure stays identical -- but I would note that the Substrate Hardening Hawk's correct point in Position 01 section 7 is exactly this: "the trj4 erratum was a near-miss credibility incident." A second pivot would be the second over-claim. Lanes R1-R5 belong inside the wave plan.

---

## 6. Bottom line

The spec is the contract. The kernel hot path is the realization. The trj4 erratum names the gap. W1.5, W2.1, W2.3, W2.4 prove it can close. Trj5 (or trj4-Wave-3-through-7) finishes the close: one normative entry, one mandatory receipt version under negotiation, one async witness producer rule, one mandatory hybrid-signing rule, one post-execution metering gate. Five normative MUSTs, five negative-conformance tests, one spec freeze. That is what closes Chio's auditable-outcomes claim. Anything else inherits the same gap.
