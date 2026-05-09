# B4: `chio.bilateral-signature-slice.v1` Bilateral Signing

This document is the deep dive for sub-lane B4. **B4 was added in Wave 3 per R4 BLOCKER 1**: the previously-proposed Lane C "Option A two-signature" framing did not use the DSSE PAE preimage. Promotion to a Lane B fourth primitive wires a bounded DSSE signature-slice profile with the same Evidence Gate discipline as B1, B2, B3.

B4 is not strict `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` predicate conformance. The implemented profile is `chio.bilateral-signature-slice.v1`: it binds one Chio receipt subject, the two peer key fingerprints, and two DSSE PAE signatures. Strict CHIODOS section 5 predicate conformance remains future work.

## What B4 changes

The existing `crates/chio-federation/src/bilateral.rs::CoSigningBody` (lines 41-77) signs canonical-JSON bytes that share ZERO bytes with the DSSE PAE preimage. B4 introduces `crates/chio-federation/src/bilateral_dsse.rs` for the `chio.bilateral-signature-slice.v1` envelope shape; the legacy `DualSignedReceipt::verify` at `bilateral.rs:108` coexists as a compatibility-only verifier for the old preimage.

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

The `DualSignedReceipt::verify` method at line 108 verifies BOTH detached signatures against the canonical-JSON-of-`CoSigningBody` preimage. It is correct as a verifier of the legacy signing surface; it is NOT a DSSE signature-slice verifier.

## Target wire format for the signature slice

The signature-slice envelope uses the DSSE v1 shape:

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

The legacy `DualSignedReceipt::verify` at `bilateral.rs:108` stays as a compatibility adapter. The new module `bilateral_dsse.rs` exposes the `chio.bilateral-signature-slice.v1` envelope alongside it. The federation fixture path produces both artifacts. **Verifiers for this signature-slice profile MUST verify the DSSE envelope; they MUST NOT rely on `DualSignedReceipt::verify` for DSSE semantics.** Strict CHIODOS predicate conformance is not claimed here.

This is the same pattern as B2: introduce a new signature-slice requirement without breaking existing callers; deprecate the legacy artifact in trj6 after a strict CHIODOS predicate implementation exists.

### Why this is NOT the structural-framing-without-wiring anti-pattern

The R4 finding rejected the prior "Option A two-signature" framing because it ALSO produced two signatures (one per preimage) but did NOT make the DSSE PAE preimage load-bearing. B4 differs:

- The DSSE envelope is the artifact that production code emits when this signature-slice profile is required.
- The negative conformance fixture rejects attempts to treat the legacy preimage as the DSSE signature slice.
- The Evidence Gate close bar requires the production federation hot path to call `sign_dsse_envelope` (not `DualSignedReceipt::sign`) when the dispatch claims signature-slice coverage.

The cohabitation is bounded by the explicit compatibility-only disclaimer on `DualSignedReceipt`. Trj6 may collapse the two surfaces after a strict CHIODOS predicate implementation exists.

## Relationship to `DualSignedReceipt`

| Artifact | Preimage | Signature-slice status | Status |
|---|---|---|---|
| Legacy `DualSignedReceipt` (bilateral.rs:91-100) | `canonical_json_bytes(CoSigningBody)` | NO | retained for backward compatibility; explicitly NOT a DSSE signature-slice artifact |
| DSSE envelope (`bilateral_dsse.rs`) | `"DSSEv1" SP LEN(...) SP ...` (DSSE PAE of canonical-JSON in-toto Statement) | YES for `chio.bilateral-signature-slice.v1` | bounded signature-slice artifact; not strict CHIODOS section 5 predicate conformance |

Both share the passport keypair (same `Keypair`), but the message bytes differ. Verifiers seeking signature-slice coverage MUST verify the DSSE envelope. The Lane C demo's release notes carry the explicit disclaimer that the legacy `DualSignedReceipt` is not a DSSE artifact.

## Conformance fixture design

Path: `crates/chio-conformance/tests/b4_bilateral_dsse_signature_slice.rs`.

The fixture follows the Lane B pattern (per `conformance-fixture-spec.md` §1-5) and adds a B4-specific assertion: the legacy preimage and the DSSE PAE preimage share ZERO bytes.

**Fixture structure**:

```rust
//! Trj5 B4 negative conformance: bilateral DSSE envelope is the
//! `chio.bilateral-signature-slice.v1` artifact; legacy `DualSignedReceipt`
//! is NOT.
//!
//! Profile requirement: spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md §6 DSSE
//! PAE shape, scoped to `chio.bilateral-signature-slice.v1`.
//!   (PAE encoding); §7 step 11-12 (signature verification).
//! Enforced call site: crates/chio-federation/src/bilateral_dsse.rs (NEW per B4).
//! Production call path: federation fixture path -> `sign_dsse_envelope`
//!   -> Ed25519 over DSSE PAE bytes of canonical-JSON in-toto Statement.
//!
//! Reverts-to-fail proof: revert B4.2 on a draft branch (delete `bilateral_dsse.rs`
//!   and any production hot-path call sites that emit DSSE envelopes); the fixture
//!   FAILS because the DSSE signature-slice envelope is not produced.

use chio_federation::bilateral::{CoSigningBody, DualSignedReceipt};
use chio_federation::bilateral_dsse::{
    sign_dsse_envelope, verify_dsse_envelope, pae_bytes, DsseEnvelope,
};
use chio_core::Keypair;
use chio_core_types::receipt::ChioReceipt;

#[test]
fn legacy_dual_signed_receipt_alone_is_not_signature_slice_artifact() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();
    let receipt = build_example_receipt();

    // Build the legacy artifact.
    let legacy = DualSignedReceipt::sign(receipt.clone(), &kp_a, &kp_b, "kernel-a", "kernel-b").unwrap();
    let legacy_preimage = CoSigningBody::from_receipt(&receipt, "kernel-a", "kernel-b")
        .unwrap()
        .canonical_bytes()
        .unwrap();

    // Build the DSSE signature-slice envelope.
    let envelope = sign_dsse_envelope(&receipt, &kp_a, &kp_b, "kernel-a", "kernel-b").unwrap();
    let dsse_preimage = envelope.pae_bytes();

    // R4 finding: the two preimages share ZERO bytes.
    assert_ne!(legacy_preimage, dsse_preimage);
    assert!(byte_overlap_is_zero(&legacy_preimage, &dsse_preimage));

    // The signature-slice verifier accepts the DSSE envelope.
    verify_dsse_envelope(&envelope, &kp_a.public_key(), &kp_b.public_key()).unwrap();

    // The signature-slice verifier does NOT accept a "DSSE envelope" forged by
    // taking the legacy `DualSignedReceipt` signatures and stuffing them into
    // a DSSE shape (different message bytes, signature does not validate).
    let mut forged = envelope.clone();
    forged.signatures[0].sig = base64_encode(&legacy.org_a_signature.to_bytes());
    let result = verify_dsse_envelope(&forged, &kp_a.public_key(), &kp_b.public_key());
    assert!(result.is_err(), "forged envelope using legacy signature MUST fail signature-slice verification");
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
    assert!(result.is_err(), "tampered PAE bytes MUST fail signature-slice verification");
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
    assert!(result.is_err(), "mismatched payload-type MUST fail signature-slice verification");
}
```

**Reverse-test (Evidence Gate close bar)**: revert B4.2 on a draft branch (delete `bilateral_dsse.rs`). The fixture FAILS at compile time (the imports do not resolve). On a less aggressive revert (keep the module but revert the signature-slice emission), the fixture's third assertion fails because the demo no longer produces a DSSE signature-slice envelope. Record the chosen revert in the B4.2 PR description.

## Why this design satisfies the Evidence Gate

- **Enforced call site**: `crates/chio-federation/src/bilateral_dsse.rs` (new module per B4). The fixture path emits the DSSE signature-slice envelope; the legacy `DualSignedReceipt` is retained but explicitly disclaimed as non-DSSE.
- **Spec citation**: `spec/CHIODOS_BILATERAL_COSIGN_INVOCATION.md` §6 lines 338-353 documents the DSSE PAE shape and §7 step 11-12 documents signature verification. B4 implements that signature-slice subset only.
- **Signed negative conformance test**: the fixture exercises `sign_dsse_envelope` and `verify_dsse_envelope`, asserts byte-level non-overlap with the legacy preimage, and FAILS when the fixture path stops emitting the DSSE signature-slice envelope.

## Why R4 BLOCKER 1 was a BLOCKER

The R4 review observed:

1. The legacy `CoSigningBody` preimage shares ZERO bytes with the DSSE PAE preimage.
2. The previously-proposed "Option A two-signature" framing claimed DSSE coverage via two coexisting Ed25519 signatures sharing the same passport keypair, but only the DSSE envelope uses the DSSE PAE preimage.
3. A future verifier audit asking "which signature is canonical?" would have to dig into the Lane C deep dive to find the answer.
4. This is exactly the structural-framing-without-wiring anti-pattern (`EVIDENCE-GATE.md` §2.4) that trj4 erratum identified.

The fix is to make the DSSE signature-slice preimage load-bearing by promoting `chio.bilateral-signature-slice.v1` signing to a Lane B fourth primitive. The legacy artifact stays for backward compatibility but is explicitly disclaimed; the DSSE signature-slice artifact is what new verifiers verify.

## Out of scope for B4

- Replacing `DualSignedReceipt::verify` at `bilateral.rs:108`. **Out**: trj6.
- Migrating every existing federation fixture from `DualSignedReceipt` to `DsseEnvelope`. **Out**: trj6 (the legacy preimage is still produced; existing fixtures continue to verify it).
- Hardware-enclave key custody for the passport keypair. **Out**: trj6 (the synthesis explicitly defers hardware attestation).
- `keyid` derivation per §7 step 8 beyond a fingerprint hash of the public key. **Bounded** for release work: the simple hash is acceptable; full keyid resolution per spec text is trj6.
