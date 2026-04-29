# M03 Trust-Boundary Audit: PQ-Hybrid Signing + TEE Quote Verifier

**Trajectory:** trajectory-2
**Milestone:** M03
**Wave:** W2
**Status:** TEMPLATE (orchestrator fills as phases close)
**Audit start:** <fill at P0 wave-opener merge>
**Audit close:** <fill at P5 final ticket merge>

## 1. Audit scope

M03 consolidates two cryptographic gaps into one coherent surface inside
`crates/chio-attest-verify/`. The first gap is signature algorithm agility:
trajectory-1 shipped Ed25519/P256/P384 envelopes with no PQ-safe option,
leaving operators with no migration path before classical primitives are
deprecated. The second gap is TEE attestation depth: trajectory-1 M10
shipped the TEE container but the verifier crate cannot reconcile a
TDX/SEV-SNP/Nitro quote against the kernel signing key and receipt root.

The lens is cryptography and attestation. M03 adds `Signature::Hybrid` over
ML-DSA-65 (FIPS 204), a `policy.crypto_floor` policy enum, and three
`QuoteVerifier` backends (TDX DCAP, SEV-SNP VLEK/VCEK, Nitro NSM
COSE_Sign1) plus a pinned-fixture corpus and an end-to-end migration test
that drives a v3.18 receipt bundle through `allow_classical -> allow_hybrid
-> pq_required` with a key roll.

This is on the trajectory because M04 revocation-oracle epoch roots, M09
lineage anchor proofs, and M10 custody envelopes all consume this single
verifier surface. Without M03, none of those downstreams have a PQ-ready
signing path or a quote-binding step.

## 2. Pre-flight checklist (mark off at P0 close)

- [ ] Cargo.lock wave-opener ticket M03.P0.T1 merged
- [ ] freezes.yml entry `m03-attest-verify-pivot` is in effect (start_trigger M03.P1.T1 merged)
- [ ] freezes.yml entry `m03-pq-primitives-pivot` is in effect (start_trigger M03.P1.T1 merged)
- [ ] CODEOWNERS regen for `crates/chio-attest-verify/**`, `crates/chio-core/src/signature*.rs`, `crates/chio-core-types/src/canonical*.rs`
- [ ] Security x2 review reviewer instances configured (different seeds, no shared scratchpad)
- [ ] M05 threat-model registry rows `pq_signature_downgrade` and `tee_quote_forgery` appended (M03.P0.T4)
- [ ] `pq` cargo feature added to `chio-core-types` and `chio-attest-verify`, default-off (M03.P0.T2)
- [ ] M06 `CanonicalBytes` newtype landing tracked as soft dep for M03.P5.T3

## 3. Per-phase evidence

### P0 wave-opener
- Tickets merged:
  - M03.P0.T1 (Pin fips204, dcap-rs, sev, coset crates) merged_sha: <fill>
  - M03.P0.T2 (Add pq cargo feature default-off) merged_sha: <fill>
  - M03.P0.T3 (Open M03 audit doc with starting counts) merged_sha: <fill>
  - M03.P0.T4 (Append pq_signature_downgrade and tee_quote_forgery rows) merged_sha: <fill>
- Cargo.lock diff: <fill range>
- Build green: <fill ci link or commit>

### P1 PQ primitives and KAT vectors
- Tickets merged:
  - M03.P1.T1 (Signature::Hybrid + PublicKey::Hybrid variants) merged_sha: <fill>
  - M03.P1.T2 (MlDsa65Backend + HybridBackend behind pq feature) merged_sha: <fill>
  - M03.P1.T3 (FIPS 204 KAT vectors at chio-core/tests/pq_kats.rs) merged_sha: <fill>
  - M03.P1.T4 (Bit-flip property test on hybrid halves and alg_set) merged_sha: <fill>
  - M03.P1.T5 (Hybrid canonical-JSON round-trip golden vectors) merged_sha: <fill>
  - M03.P1.T6 (Document hybrid prefix in spec PROTOCOL and schemas) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P2 Hybrid signing in receipts, capability tokens, compliance certificates
- Tickets merged:
  - M03.P2.T1 (policy.crypto_floor enum with fail-closed load) merged_sha: <fill>
  - M03.P2.T2 (Receipt signer accepts dyn SigningBackend; HybridBackend wired) merged_sha: <fill>
  - M03.P2.T3 (Capability token signing branches on Signature algorithm) merged_sha: <fill>
  - M03.P2.T4 (SessionComplianceCertificate consumes HybridBackend) merged_sha: <fill>
  - M03.P2.T5 (v3.18 receipt migration test under three crypto_floor settings) merged_sha: <fill>
  - M03.P2.T6 (chio-guard-registry cosign regression test) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P3 TDX DCAP backend
- Tickets merged:
  - M03.P3.T1 (QuoteVerifier trait + VerifiedQuote shape) merged_sha: <fill>
  - M03.P3.T2 (TDX DCAP backend with Intel root CA chain) merged_sha: <fill>
  - M03.P3.T3 (expect_report_data binding helper, fail-closed) merged_sha: <fill>
  - M03.P3.T4 (TDX positive/negative fixture corpus pinned) merged_sha: <fill>
  - M03.P3.T5 (Integration test against M10 container fixture quote) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P4 SEV-SNP and Nitro NSM backends
- Tickets merged:
  - M03.P4.T1 (SEV-SNP backend with VLEK/VCEK chain) merged_sha: <fill>
  - M03.P4.T2 (SEV-SNP fixture corpus including stale TCB) merged_sha: <fill>
  - M03.P4.T3 (Nitro NSM COSE_Sign1 backend) merged_sha: <fill>
  - M03.P4.T4 (Nitro fixture corpus + root-rotation regression) merged_sha: <fill>
  - M03.P4.T5 (Cross-backend conformance test rejecting mislabelled quotes) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

### P5 Cross-cutting (PQ + TEE composition, migration, key roll)
- Tickets merged:
  - M03.P5.T1 (Kernel boot self-quote binds expect_report_data before PQ key load) merged_sha: <fill>
  - M03.P5.T2 (E2E migration: allow_classical -> allow_hybrid -> pq_required with key roll) merged_sha: <fill>
  - M03.P5.T3 (Receipt path consumes CanonicalBytes or shim) merged_sha: <fill>
  - M03.P5.T4 (Threat-model coverage handshake for two M03 threat IDs) merged_sha: <fill>
  - M03.P5.T5 (Audit-doc final pass with closing counts) merged_sha: <fill>
- Cargo.lock diff: <fill>
- Build green: <fill>

## 4. Trust-boundary attestations

For trust-boundary milestones, every PR was reviewed by:
- Security reviewer instance A: <fill handle or seed>
- Security reviewer instance B: <fill handle or seed>
- Human-side reviewer: @bb-connor

Per-phase PR attestation log (filled by orchestrator):

- P0 PRs reviewed: <fill PR numbers> -- attestation status: <fill>
- P1 PRs reviewed: <fill> -- attestation status: <fill>
- P2 PRs reviewed: <fill> -- attestation status: <fill>
- P3 PRs reviewed: <fill> -- attestation status: <fill>
- P4 PRs reviewed: <fill> -- attestation status: <fill>
- P5 PRs reviewed: <fill> -- attestation status: <fill>

Hot-fix bypass log (record any `hotfix/* + [trajectory-2]` overrides
during `m03-attest-verify-pivot` or `m03-pq-primitives-pivot`):
<fill or "no overrides">

## 5. Decisions in force

- D08 (PQ primitive: ML-DSA-65 via fips204 crate)
- D09 (No KEM / Kyber in trajectory-2)
- D10 (TEE quote backends: TDX + SEV-SNP + Nitro NSM)

## 6. Threat-model coverage at close

M03 owns two new threat IDs added in P0 to
`spec/security/chio-threat-model.v1.json`:

- `pq_signature_downgrade` -- covered by M03.P1.T4 (bit-flip on hybrid
  halves and alg_set field), M03.P2.T1 (crypto_floor load-time rejection),
  M03.P2.T5 (migration test rejects v3.18 bundle under pq_required).
- `tee_quote_forgery` -- covered by M03.P3.T2-T5 (TDX DCAP with Intel root
  CA), M03.P4.T1-T2 (SEV-SNP VLEK/VCEK with stale-TCB negative), M03.P4.T3-T4
  (Nitro NSM COSE_Sign1 with root-rotation regression), M03.P4.T5
  (cross-backend conformance rejecting mislabelled quotes).

Cross-reference: M05.P5 threat-model-coverage gate (M05 owns the
`spec/security/coverage.yaml` file shape; the two IDs above MUST be marked
covered before M03 closes per M03.P5.T4).

TEE backend coverage:
- Intel TDX DCAP: <fill positive/negative fixture counts>
- AMD SEV-SNP VLEK/VCEK: <fill positive/negative fixture counts>
- AWS Nitro NSM COSE_Sign1: <fill positive/negative fixture counts>

PQ migration coverage:
- v3.18 receipt bundle re-verifies under `crypto_floor=allow_classical`
  byte-identically: <fill pass/fail>
- Re-signed bundle re-verifies under `crypto_floor=pq_required` with key
  roll: <fill pass/fail>
- v3.18 bundle rejected under `crypto_floor=pq_required`: <fill pass/fail>

## 7. Cross-trajectory artifact handoffs

Produced by M03, consumed downstream:

- `chio-attest-verify` PQ + TEE-quote surface (extended, not forked) -- consumed
  by M04 (revocation-oracle epoch roots signed via HybridBackend per M03.P2.T2),
  M09 (lineage anchor proofs), M10 (PasskeyCapability mint signs through
  HybridBackend per M10.P2.T1).
- `Signature::Hybrid` variant + canonical-JSON `hybrid:` prefix in
  `chio-core-types` -- consumed by every downstream signed envelope under
  `crypto_floor=allow_hybrid|pq_required`.
- `expect_report_data(kernel_pk, receipt_root)` helper from M03.P3.T3 --
  consumed by M10 custody envelopes binding TEE-attested kernels.
- Two new threat IDs (`pq_signature_downgrade`, `tee_quote_forgery`) --
  consumed by M05.P5 threat-model-coverage gate.

Cross-doc invariants enforced (EXECUTION-BOARD section 3):
- M03 must NOT fork `chio-attest-verify`; the `AttestVerifier` trait surface is
  unchanged. Sibling `QuoteVerifier` trait and three backend modules are added
  next to existing surfaces.
- Cross-freeze ordering: `m03-attest-verify-pivot` must close before
  `m04-revocation-oracle-pivot` end_trigger so that revocation roots can be
  PQ-signed (carrying soft_dep on M04.P1.T3). Concrete HybridBackend lands
  in M03.P2.

## 8. Halt-and-resume events

If this milestone hit any halt triggers from AUTONOMOUS-PROMPT or
HANDOFF-PROMPT, the event log entry goes here. Examples that would trigger
a halt: PQ KAT vector divergence between fips204 patch versions; Intel TDX
collateral chain re-bake required mid-pivot; cosign bundle regression in
`chio-guard-registry`.

<fill or "no halt events">

## 9. Close-out signature

- Final commit on `main`: <fill 40hex sha>
- Final ticket merged: M03.P5.T5
- Audit closed by: @bb-connor
- Audit close date: <fill yyyy-mm-dd>
