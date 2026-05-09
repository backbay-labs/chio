# Trj5 Spec-to-Runtime Map

**Status**: cross-cutting inventory. Each row identifies a normative MUST in
`spec/PROTOCOL.md` (or a chiodos sub-spec for Lane C) and the production
call site that enforces it (or fails to enforce it). The fifth column
records the release work ticket that closes the gap. Items not in release work scope are
marked `DEFERRED-trj6`.

**Origin**: `.planning/trajectory-5/debate/02-protocol-realization-engineer.md`
sections 1.1 through 1.7, plus the synthesis at
`.planning/trajectory-5/debate/00-SYNTHESIS.md` Lane B.

**Methodology**: a row exists if the spec contains literal `MUST` (RFC 2119
sense) AND a runtime call site implements or fails to implement the rule.
Rows whose spec language is currently `SHOULD` are included; closing the
release work ticket promotes the language to `MUST`.

**Copyright note**: spec quotations are kept under 15 words per the project
copyright rule.

---

## 1. Capability Negotiation (Lane B1)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` 5.4 lines 408-418 | "production kernels SHOULD prefer the W1.5 composite entrypoint" (current SHOULD; release work promotes to MUST) | `crates/chio-kernel-core/src/capability_verify.rs:400-476` (composite exists); `crates/chio-kernel/src/kernel/mod.rs:4035-4047` (partial entry still callable) | structural-only (composite exists; not the only entry) | release work-B1.E |
| `spec/PROTOCOL.md` 5.x (TBD-from-W1) lines TBD | "verifier MUST reject unknown capability schema IDs" | `crates/chio-core-types/src/capability.rs` schema-tag check | enforced (W1.3 schema-ceiling) | already-closed; reaffirm in B1.E |
| `spec/PROTOCOL.md` 5.1.3 lines TBD-from-W1 | "chain-binding MUST be checked on every governed decision" | `crates/chio-kernel-core/src/capability_verify.rs:226-255` (`verify_capability_with_negotiated_floor`) | enforced through composite | reaffirm in B1.E |
| `spec/PROTOCOL.md` "Capability Negotiation" section starting line 286 | feature-bitset advertise/parse | `crates/chio-federation::trust_establishment` (TBD-from-W1: exact path) | enforced | already-closed |

---

## 2. Receipt v2 Body-Hash (Lane B2)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` section 6 lines 714-741 (specifically lines 737-741, the "Negotiation downgrade" prose) | "receipt v2 mint at production time when negotiation selected v2" (current prose is descriptive: "the kernel falls back"; B2 introduces a new normative MUST) | `crates/chio-kernel/src/kernel/mod.rs:1574-1591` (`kernel_receipt_version_for_remote`). Note: synthesis line 31 cited `:1148-1165` which is `KernelReceiptVersion::from_capabilities` (the resolver helper, not the runtime downgrade). | structural-only (warns, does not fail closed) | release work-B2.E |
| `spec/PROTOCOL.md` 6.x lines TBD | "body_hash addressing MUST be the replay key" | `crates/chio-kernel/src/kernel/mod.rs` (TBD-from-W1: replay-store key path) | enforced (W2.1) | reaffirm in B2.E |
| `spec/PROTOCOL.md` 6.x lines TBD | "tampered legacy `receipt_id` MUST NOT affect replay acceptance" | replay-store path TBD-from-W1 | enforced | reaffirm in B2.E |

---

## 3. Attenuation Witnesses (Lane B partial / DEFERRED-trj6 partial)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` lines 396-401 | "direct-issue v2 MUST have parent_scope_hash equal to verifier's trust-root scope" | `crates/chio-kernel-core/src/capability_verify.rs:352-377` (`_with_floor_and_resolver`) | structural-only (resolver-bearing entry exists; convenience wrapper at line 327 takes single ScopeHash and is unsafe with multiple trust roots) | DEFERRED-trj6 (not in synthesis-sanctioned Lane B set) |
| `spec/PROTOCOL.md` "Capability v2 Attenuation" section line 362 | typed caveats with predicate | TRJ4-112 partially landed; full enforcement TBD-from-W1 | structural-only | DEFERRED-trj6 |

---

## 4. Anchor-Batch Merkle (Lane B3)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` section 6.4.1 lines 982-991 | "require_public_witness=true on sync path MUST reject" | `crates/chio-anchor/src/batch.rs:227-258` (async path exists); `crates/chio-anchor/src/batch.rs:208` (sync path still callable) | structural-only (async path exists; sync path not gated) | release work-B3.E |
| `spec/PROTOCOL.md` 6.4.1 lines TBD | "tree.root() MUST equal body.tree_root" | `crates/chio-anchor/src/batch.rs::AnchorBatch::sign` (W2.3 commit `7ee1ddbcc`) | enforced | reaffirm in B3.E |
| `spec/PROTOCOL.md` 6.4.1 lines TBD | "inclusion proof MUST recompute the advertised root" | `crates/chio-anchor/src/batch.rs::verify_anchor_batch` | enforced | reaffirm in B3.E |
| `spec/PROTOCOL.md` 6.4.1 lines TBD | "stale-witness fallback policy" | TBD-from-W1: exact path | structural-only | DEFERRED-trj6 (out of synthesis-sanctioned set) |

---

## 5. Sibling-Sum Budget (Lane B partial)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` (TBD-from-W1: section/lines) | "sibling-sum admission MUST run on every governed decision" | `crates/chio-kernel-core/src/capability_verify.rs` W1.2 admission | enforced through composite (B1 close removes the partial entry that bypasses admission) | covered by release work-B1.E |
| `spec/PROTOCOL.md` lines TBD | "BasisPoints subset MUST be enforced at child issuance" | TRJ4-118 sub-agent budget propagation, TBD-from-W1 | structural-only | DEFERRED-trj6 partial; B1.E covers the verification side |

---

## 6. Hybrid PQ Wire Format (DEFERRED-trj6)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` 4.1 lines 173-177 | "verifiers MUST dispatch from the signature prefix" | `crates/chio-kernel/src/kernel/mod.rs:876-927` (boot-port hybrid awareness only) | structural-only (kernel hot path still single-keypair) | DEFERRED-trj6 (synthesis kept hybrid PQ end-to-end out of release work; receipt v2 fail-closed under v2 negotiation IS in scope as B2) |
| `spec/PROTOCOL.md` 4.4 lines 233-238 | "algorithm hint MUST match prefix; mismatches reject" | TBD | structural-only | DEFERRED-trj6 |
| `spec/PROTOCOL.md` 5 lines 277-285 | "hybrid wire prefix `hybrid:<classical>:<pq>:<alg_set>`" | `crates/chio-core-types/src/capability.rs` schema accepts hybrid | enforced | already-closed |

---

## 7. Metered Billing (DEFERRED-trj6)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` lines 472-555 | "approval_token MUST verify when charge >= threshold" | TBD-from-W1 | structural-only (threshold in receipt body; runtime check implicit) | DEFERRED-trj6 |
| `spec/PROTOCOL.md` lines 502-507 | "post-execution overshoot MUST re-mediate, not silently allow" | not implemented as a gate | unwired | DEFERRED-trj6 (Protocol Engineer's R5 is out of synthesis-sanctioned release work scope) |
| `spec/PROTOCOL.md` lines 825-837 | "tampered usageEvidence MUST NOT rewrite signed receipt" | implicit | structural-only | DEFERRED-trj6 |

---

## 8. Cross-Org Bilateral Cosign (Lane C1 + Lane B4)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` section 6 (TBD-from-W1: lines) | "DualSignedReceipt MUST carry both signers' attestations" | `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77), `DualSignedReceipt` (lines 91-100) | enforced (existing primitive) | release work-C1.E asserts the demo exercises this |
| same | "cross-org dispatch MUST not allow single-signer fast path" | TBD-from-W1 | structural-only | release work-C1.E |
| `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 (PAE encoding) | "Ed25519 over DSSE PAE of canonical-JSON in-toto Statement carrying §5 predicate body" | NEW: `crates/chio-federation/src/bilateral_dsse.rs` (per B4); legacy `bilateral.rs::DualSignedReceipt::verify` (line 108) is structural-only with respect to §6 | structural-only on the existing `DualSignedReceipt` (its preimage shares ZERO bytes with §6 PAE preimage); B4 introduces the §6-conformant module | bilateral DSSE signing item |
| `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §7 step 11-12 (signature verification) | "verifier MUST validate Ed25519 over DSSE PAE bytes" | B4 verifier-side hook in `bilateral_dsse.rs` | not-yet-enforced; B4 fixture is the conformance check | bilateral DSSE signing item |

---

## 9. Capability Lease + Budget Bond (Lane C2)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `crates/chio-credit::CREDIT_BOND_ARTIFACT_SCHEMA` (schema; spec citation TBD-from-W1) | "lease overdraft MUST settle against bond" | `crates/chio-credit/src/...` (TBD-from-W1) | structural-only | release work-C2.E |

---

## 10. Anchored Receipts via Web3 Checkpoint (Lane C3)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` 6.4 (Checkpoints) starting line 865 | "checkpoint statement MUST bind receipts to anchor" | `crates/chio-anchor::Web3CheckpointStatement` | enforced (no live deploy; bounded claim) | release work-C3.E |

---

## 11. Selective Disclosure (future work outside current closure)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/CHIODOS_SELECTIVE_DISCLOSURE.md` section 6 (TBD-from-W1: lines) | "auditor view MUST verify without revealing private fields" | Future implementation, expected to follow the normative crate/feature shape or an explicit protocol-owner update | deferred outside current closure | no current closure row |

---

## 12. Capability Token Negotiation Schema-Ceiling (already enforced)

| Spec citation | MUST text (short) | Production call site | Status | Trj5 ticket |
|---|---|---|---|---|
| `spec/PROTOCOL.md` "Signed-Artifact Registry" section line 331 | "load-time MUST reject unknown schema" | registry implementation TBD-from-W1 | enforced | already-closed (reaffirm in B1.E if relevant) |

---

## 13. Out-of-release work (explicit `DEFERRED-trj6`)

The following normative MUSTs are recognized as enforcement gaps but are
explicitly NOT in the release work scope per
`.planning/trajectory-5/debate/00-SYNTHESIS.md` "Out of scope (explicit)":

- `accepts_anchor_batch_v1` symmetric ceiling enforcement
  (`spec/PROTOCOL.md` lines 296-303). Defer to trj6.
- `attenuation_proof.parent_scope_hash` direct-issue resolver-only API
  hardening (`spec/PROTOCOL.md` lines 396-401). Defer to trj6.
- Hybrid signing under negotiated `accepts_hybrid_signatures` profile
  (`spec/PROTOCOL.md` 4.1, 4.4, 5). Defer to trj6.
- Metered-billing post-execution gate (`spec/PROTOCOL.md` lines 502-507).
  Defer to trj6.
- OID4VP / public identity network artifacts
  (`spec/PROTOCOL.md` section 10.1.x). Already informational-only.
- Underwriting / credit / facility / market discipline
  (`spec/PROTOCOL.md` section 9 partial). Already shipped as bounded.
- Third-party caveats with discharge
  (`audits/T1.1` line 19 punt). Stay punted.
- Hardware attestation buffet (Apple Secure Enclave kernel-key, TPM 2.0,
  Azure MAA hot-binding). Customer-driven.
- All `chiodos pheromone`, `chiodos ladder` primitives. Research drafts.

---

## 14. Read-In Order

For a Wave 1 reviewer auditing this map:

1. Read `.planning/trajectory-5/debate/00-SYNTHESIS.md` to confirm the Lane
   B set (B1, B2, B3) AND the Lane C set (C1-C4 demo).
2. Read sections 1, 2, 4 of this map (the original three Lane B rows) plus
   the bilateral-cosign rows under section 8 cited as bilateral DSSE signing item (the new
   sub-lane added per R4 BLOCKER 1). Each cites a ticket suffix
   (`release work-B1.E`, `release work-B2.E`, `release work-B3.E`, `bilateral DSSE signing item`).
3. Read sections 8, 9, 10, 11 (Lane C). Each cites a ticket suffix
   (`release work-C1.E` etc.). Note that section 8 now spans Lane C1 (consumer of
   the legacy `DualSignedReceipt`) AND Lane B4 (producer of the §6-conformant
   DSSE envelope).
4. Read section 13 (deferred). Confirm nothing on this list is silently
   in scope in any release work ticket file.

---

## 15. Maintenance

This map is a snapshot from 2026-05-07 plus W1 enumeration tasks. Any line
or section number marked `TBD-from-W{1,2}` MUST be filled in by the Wave 1
reviewer. The audit-doc owner for each sub-lane is responsible for
re-citing the spec MUST in the lane's `### release work-X.y` evidence block;
discrepancies between this map and the audit doc are caught by
`scripts/check-release work-evidence-gate.sh` (Wave 1 deliverable).

If a row's enforcement status changes (e.g. a partial entry is removed),
the row is updated in this map by the closing PR.
