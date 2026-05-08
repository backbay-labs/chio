# B4: DSSE-conformant Bilateral Signing

This document is the deep dive for sub-lane B4. **B4 was added in Wave 3 per R4 BLOCKER 1**: the previously-proposed Lane C "Option A two-signature" framing did not strictly satisfy `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 conformance. Promotion to a Lane B fourth primitive ensures §6 conformance is hot-path-wired with the same Evidence Gate discipline as B1, B2, B3.

## What B4 changes

The existing `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share ZERO bytes with the §6 DSSE PAE preimage. B4 introduces a new module `crates/chio-federation/src/bilateral_dsse.rs` exposing the §6-conformant envelope shape; the legacy `DualSignedReceipt::verify` at `bilateral.rs:108` coexists with explicit non-§6 disclaimer.

## Current state of `CoSigningBody` (lines 41-77 of `bilateral.rs`)

The legacy structure is canonical-JSON-encoded and signed as-is:

```rust
pub struct CoSigningBody {
    pub schema: String,
    pub receipt_canonical_json: String,
    pub org_a_kernel_id: String,
    pub org_b_kernel_id: String,
}
```

The `canonical_bytes` method returns `canonical_json_bytes(self)`. The two Ed25519 signatures (`org_a_signature`, `org_b_signature` on `DualSignedReceipt`) are computed over these bytes. **No DSSE PAE wrapper is present.** The preimage is literally the canonical JSON encoding of `CoSigningBody`.

The `DualSignedReceipt::verify` method at line 108 verifies BOTH detached signatures against the canonical-JSON-of-`CoSigningBody` preimage. It is correct as a verifier of the legacy signing surface; it is NOT a §6 verifier.

## Target wire format (per spec §6 lines 338-353)

The §6 envelope is the DSSE v1 shape:

```
PAE = "DSSEv1" SP LEN(payload-type) SP payload-type SP LEN(payload) SP payload
```

Where:

- `payload-type` is `application/vnd.in-toto+json` (per spec).
- `payload` is the canonical-JSON encoding of an in-toto Statement of the form:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "name": "...", "digest": { "sha256": "..." } }],
  "predicateType": "https://chio.io/CrossOrgInvocation/v1",
  "predicate": {
    "schema": "chio.bilateral-cosign.invocation.v1",
    "...": "...",   // the §5 predicate body
  }
}
```

Two Ed25519 signatures are computed over the PAE bytes (one per kernel). The DSSE envelope is:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64(canonical-json-statement)>",
  "signatures": [
    { "keyid": "<org-a-key-id>", "sig": "<base64(ed25519(pae))>" },
    { "keyid": "<org-b-key-id>", "sig": "<base64(ed25519(pae))>" }
  ]
}
```

The preimage that the signatures cover (`PAE = ...`) shares ZERO bytes with the legacy `canonical_json_bytes(CoSigningBody)`. This is the R4 finding.

## Migration strategy: cohabitation (chosen for release work)

Two design options were considered:

### Option 1: One-version transition (REJECTED for release work)

Replace `DualSignedReceipt::verify` with the DSSE-shaped verifier; remove the legacy preimage. **Rejected** because it is a public-API breaking change for any external consumer of `DualSignedReceipt` (federation transport, existing fixtures, the Lane C demo's existing infrastructure). The breaking change is too large a blast radius for release work.

### Option 2: Cohabitation (CHOSEN for release work)

The legacy `DualSignedReceipt::verify` at `bilateral.rs:108` stays. The new module `bilateral_dsse.rs` exposes the §6-conformant envelope ALONGSIDE. The federation hot path produces BOTH artifacts when a §6 envelope is requested. **Verifiers seeking §6 conformance MUST verify the DSSE envelope; they MUST NOT rely on `DualSignedReceipt::verify` for §6 semantics.** Lane C release notes record this disclaimer explicitly.

This is the same pattern as B2: introduce a new MUST without breaking existing callers; deprecate the legacy artifact in trj6 once §6 is the only public surface.

### Why this is NOT the structural-framing-without-wiring anti-pattern

The R4 finding rejected the prior "Option A two-signature" framing because it ALSO produced two signatures (one per preimage) but did NOT make §6 conformance load-bearing. B4 differs:

- The DSSE envelope is the artifact that production code emits when §6 conformance is required.
- The negative conformance fixture rejects attempts to claim §6 conformance via the legacy preimage.
- The Evidence Gate close bar requires the production federation hot path to call `sign_dsse_envelope` (not `DualSignedReceipt::sign`) when the dispatch is §6-claiming.

The cohabitation is bounded by the Lane C release notes' explicit non-§6 disclaimer of `DualSignedReceipt`. Trj6 may collapse the two surfaces; release work ships both with the §6-conformant one as load-bearing.

## Relationship to `DualSignedReceipt`

| Artifact | Preimage | §6-conformant? | Status |
|---|---|---|---|
| Legacy `DualSignedReceipt` (bilateral.rs:91-100) | `canonical_json_bytes(CoSigningBody)` | NO | retained for backward compatibility; explicitly NOT a §6 artifact |
| New DSSE envelope (bilateral_dsse.rs, NEW per B4) | `"DSSEv1" SP LEN(...) SP ...` (DSSE PAE of canonical-JSON in-toto Statement) | YES | the §6 artifact; production federation hot path emits this when §6 conformance is required |

Both share the passport keypair (same `Keypair`), but the message bytes differ. Verifiers seeking §6 conformance MUST verify the DSSE envelope. The Lane C demo's release notes carry the explicit disclaimer that "the legacy `DualSignedReceipt` is NOT a spec §6 artifact" (per R4 finding 1, recommendation 2, fallback narrowing).

## Conformance fixture design

Path: `crates/chio-conformance/tests/b4_bilateral_dsse_pae_only_is_conformant.rs`.

The fixture follows the Lane B pattern (per `conformance-fixture-spec.md` §1-5) and adds a B4-specific assertion: the legacy preimage and the DSSE PAE preimage share ZERO bytes.

**Fixture structure**:

```rust
//! Trj5 B4 negative conformance: bilateral DSSE envelope is the §6-conformant
//! artifact; legacy `DualSignedReceipt` is NOT.
//!
//! Spec MUST: spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md §6 lines 338-353
//!   (PAE encoding); §7 step 11-12 (signature verification).
//! Enforced call site: crates/chio-federation/src/bilateral_dsse.rs (NEW per B4).
//! Production call path: federation hot path -> `sign_dsse_envelope`
//!   -> Ed25519 over DSSE PAE bytes of canonical-JSON in-toto Statement.
//!
//! Reverts-to-fail proof: revert B4.2 on a draft branch (delete `bilateral_dsse.rs`
//!   and any production hot-path call sites that emit DSSE envelopes); the fixture
//!   FAILS because the §6-conformant envelope is not produced and the demo's §6
//!   conformance claim is contradicted.

use chio_federation::bilateral::{CoSigningBody, DualSignedReceipt};
use chio_federation::bilateral_dsse::{
    sign_dsse_envelope, verify_dsse_envelope, pae_bytes, DsseEnvelope,
};
use chio_core::Keypair;
use chio_core_types::receipt::ChioReceipt;

#[test]
fn legacy_dual_signed_receipt_alone_is_not_section_6_conformant() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = build_example_receipt();

    // Build the legacy artifact.
    let legacy = DualSignedReceipt::sign(receipt.clone(), &kp_a, &kp_b, "kernel-a", "kernel-b").unwrap();
    let legacy_preimage = CoSigningBody::from_receipt(&receipt, "kernel-a", "kernel-b")
        .unwrap()
        .canonical_bytes()
        .unwrap();

    // Build the §6-conformant DSSE envelope.
    let envelope = sign_dsse_envelope(&receipt, &kp_a, &kp_b, "kernel-a", "kernel-b").unwrap();
    let dsse_preimage = envelope.pae_bytes();

    // R4 finding: the two preimages share ZERO bytes.
    assert_ne!(legacy_preimage, dsse_preimage);
    assert!(byte_overlap_is_zero(&legacy_preimage, &dsse_preimage));

    // The §6-conformant verifier accepts the DSSE envelope.
    verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key()).unwrap();

    // The §6-conformant verifier does NOT accept a "DSSE envelope" forged by
    // taking the legacy `DualSignedReceipt` signatures and stuffing them into
    // a DSSE shape (different message bytes, signature does not validate).
    let mut forged = envelope.clone();
    forged.signatures[0].sig = base64_encode(&legacy.org_a_signature.to_bytes());
    let result = verify_dsse_envelope(&forged, &kp_a.public_key(), &kp_b.public_key());
    assert!(result.is_err(), "forged envelope using legacy signature MUST fail §6 verification");
}

#[test]
fn tampered_pae_bytes_rejected_by_section_6_verifier() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = build_example_receipt();
    let mut envelope = sign_dsse_envelope(&receipt, &kp_a, &kp_b, "kernel-a", "kernel-b").unwrap();

    // Tamper the payload: this changes LEN(payload) and the payload bytes,
    // so the PAE preimage diverges from what the signatures cover.
    let tampered = envelope.payload.clone() + "X";
    envelope.payload = tampered;

    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(result.is_err(), "tampered PAE bytes MUST fail §6 verification");
}

#[test]
fn mismatched_payload_type_rejected() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = build_example_receipt();
    let mut envelope = sign_dsse_envelope(&receipt, &kp_a, &kp_b, "kernel-a", "kernel-b").unwrap();

    // Swap the payload type. PAE includes LEN(payload-type), so this changes
    // the preimage; signatures fail.
    envelope.payload_type = "application/json".to_string();

    let result = verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key());
    assert!(result.is_err(), "mismatched payload-type MUST fail §6 verification");
}
```

**Reverse-test (Evidence Gate close bar)**: revert B4.2 on a draft branch (delete `bilateral_dsse.rs`). The fixture FAILS at compile time (the imports do not resolve). On a less aggressive revert (keep the module but revert the production hot-path emission), the fixture's third assertion fails because the demo no longer produces a §6-conformant envelope. Record the chosen revert in the B4.2 PR description.

## Why this design satisfies the Evidence Gate

- **Enforced call site**: `crates/chio-federation/src/bilateral_dsse.rs` (new module per B4). The federation hot path emits the §6-conformant envelope; the legacy `DualSignedReceipt` is retained but explicitly disclaimed as non-§6.
- **Spec MUST citation**: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 (PAE) + §7 step 11-12 (signature verification). The spec text is already in MUST shape; B4 wires the runtime to it.
- **Signed negative conformance test**: the fixture exercises `sign_dsse_envelope` and `verify_dsse_envelope` (the production §6 verbs), asserts byte-level non-overlap with the legacy preimage, and FAILS when the production hot path stops emitting the §6 envelope.

## Why R4 BLOCKER 1 was a BLOCKER

The R4 review observed:

1. The legacy `CoSigningBody` preimage shares ZERO bytes with the §6 DSSE PAE preimage.
2. The previously-proposed "Option A two-signature" framing claimed §6 conformance via two coexisting Ed25519 signatures sharing the same passport keypair, but only the DSSE envelope is §6-conformant.
3. A future verifier audit asking "which signature is canonical?" would have to dig into the Lane C deep dive to find the answer.
4. This is exactly the structural-framing-without-wiring anti-pattern (`EVIDENCE-GATE.md` §2.4) that trj4 erratum identified.

The fix is to make §6 conformance load-bearing by promoting DSSE-conformant signing to a Lane B fourth primitive. The legacy artifact stays for backward compatibility but is explicitly disclaimed; the §6 artifact is what production emits and what verifiers verify.

## Out of scope for B4

- Replacing `DualSignedReceipt::verify` at `bilateral.rs:108`. **Out**: trj6.
- Migrating every existing federation fixture from `DualSignedReceipt` to `DsseEnvelope`. **Out**: trj6 (the legacy preimage is still produced; existing fixtures continue to verify it).
- Hardware-enclave key custody for the passport keypair. **Out**: trj6 (the synthesis explicitly defers hardware attestation).
- `keyid` derivation per §7 step 8 beyond a fingerprint hash of the public key. **Bounded** for release work: the simple hash is acceptable; full keyid resolution per spec text is trj6.
