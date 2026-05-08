// Threat test for threat ID `tee_quote_forgery`.
//
// Threat: tee_quote_forgery (TEE quote forgery or misbinding).
// Surfaces: hosted_mcp, native_chio.
//
// Coverage strategy: import the production
// `chio_tee_frame::schema::{validate_signed, verify_tenant_sig}`
// functions directly. Build a `chio_tee_frame::Frame` and sign its
// canonical-JSON payload with a known tenant keypair. Then exercise
// three forgery deny branches:
//
//   1. Verifier-key swap. Present the genuinely-signed frame to a
//      verifier holding a different tenant public key. The
//      production `validate_signed` MUST return
//      `SchemaError::TenantSigVerification`.
//   2. Tampered body. Mutate `request_blob_sha256` after signing.
//      The canonical-JSON payload no longer matches the signature
//      and `validate_signed` MUST reject with
//      `SchemaError::TenantSigVerification`.
//   3. Forged signature. Replace `tenant_sig` with random 64-byte
//      data. `verify_tenant_sig` MUST reject with
//      `SchemaError::TenantSigVerification`.
//
// Production call sites:
//   `crates/chio-tee-frame/src/schema.rs:93` (`validate_signed`).
//   `crates/chio-tee-frame/src/schema.rs:117` (`verify_tenant_sig`).
//
// Revert-to-prove-it-fails recipe (trj5/A2 evidence backfill):
// In `crates/chio-tee-frame/src/schema.rs`, locate the body of
// `verify_tenant_sig`. Replace the
// `if public_key.verify(&payload, &signature) { Ok(()) } else {
// Err(SchemaError::TenantSigVerification(...)) }` block with a bare
// `Ok(())`. Re-run
// `cargo test -p chio-conformance --test threats -- tee_quote_forgery`
// and the
// `assert!(matches!(err, SchemaError::TenantSigVerification(_)))`
// arms MUST then fail because production now accepts forged
// signatures. That fault injection demonstrates each assertion is
// wired to the production tenant-signature deny branch.

use base64::Engine;
use chio_core::crypto::Keypair;
use chio_tee_frame::frame::{Frame, Otel, Provenance, Upstream, UpstreamSystem, Verdict};
use chio_tee_frame::schema::{
    signing_payload, validate_signed, verify_tenant_sig, SchemaError, SCHEMA_VERSION,
};

fn unsigned_frame() -> Frame {
    Frame {
        schema_version: SCHEMA_VERSION.to_string(),
        event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".to_string(),
        ts: "2026-05-08T00:00:00.000Z".to_string(),
        tee_id: "tee-prod-1".to_string(),
        upstream: Upstream {
            system: UpstreamSystem::Openai,
            operation: "responses.create".to_string(),
            api_version: "2026-05-01".to_string(),
        },
        invocation: serde_json::json!({"tool":"x"}),
        provenance: Provenance {
            otel: Otel {
                trace_id: "0".repeat(32),
                span_id: "0".repeat(16),
            },
            supply_chain: None,
        },
        request_blob_sha256: "a".repeat(64),
        response_blob_sha256: "b".repeat(64),
        redaction_pass_id: "trj5-a2-redactors@1.0.0".to_string(),
        verdict: Verdict::Allow,
        deny_reason: None,
        would_have_blocked: false,
        // Placeholder while we compute the canonical signing payload.
        tenant_sig: format!(
            "ed25519:{}",
            base64::engine::general_purpose::STANDARD.encode([0u8; 64])
        ),
    }
}

fn signed_frame() -> (Frame, [u8; 32]) {
    let keypair = Keypair::from_seed(&[0x42u8; 32]);
    let public_key = *keypair.public_key().as_bytes();
    let mut frame = unsigned_frame();
    let payload = match signing_payload(&frame) {
        Ok(payload) => payload,
        Err(err) => panic!("signing_payload: {err}"),
    };
    let signature = keypair.sign(&payload);
    frame.tenant_sig = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    );
    (frame, public_key)
}

#[test]
fn threat_tee_quote_forgery_wrong_tenant_key_rejected() {
    // covers: tee_quote_forgery
    //
    // Attacker scenario: the frame is genuinely signed by the legitimate
    // tenant key, but a misbinding causes the verifier to use a
    // different tenant's public key (e.g. tenant_id swap). The
    // production validate_signed MUST reject.
    let (frame, _genuine_pk) = signed_frame();
    let attacker_pk = *Keypair::from_seed(&[0xAAu8; 32]).public_key().as_bytes();
    assert_ne!(_genuine_pk, attacker_pk);

    let err = match validate_signed(&frame, &attacker_pk) {
        Ok(()) => panic!(
            "validate_signed MUST reject when the tenant public key does \
             not match the signing key (misbinding); got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on key mismatch, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_tampered_body_rejected() {
    // covers: tee_quote_forgery
    //
    // Attacker scenario: an attacker post-signing alters the request
    // blob hash to claim a different attestation payload. The
    // canonical-JSON signing payload no longer matches the signature.
    let (mut frame, public_key) = signed_frame();
    frame.request_blob_sha256 = "c".repeat(64);

    let err = match validate_signed(&frame, &public_key) {
        Ok(()) => panic!(
            "validate_signed MUST reject when the request_blob_sha256 \
             field has been tampered with after signing; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on tampered body, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_forged_signature_rejected() {
    // covers: tee_quote_forgery
    //
    // Attacker scenario: an attacker constructs a frame and substitutes
    // a 64-byte blob of their choosing for `tenant_sig`. The signature
    // surface MUST reject because no Ed25519 signature over the
    // canonical-JSON body can match a forged byte sequence under the
    // genuine tenant's public key.
    let (_legit_frame, public_key) = signed_frame();
    let mut forged = unsigned_frame();
    forged.tenant_sig = format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode([0xFFu8; 64])
    );

    let err = match verify_tenant_sig(&forged, &public_key) {
        Ok(()) => panic!(
            "verify_tenant_sig MUST reject a forged 64-byte signature; got Ok"
        ),
        Err(err) => err,
    };
    assert!(
        matches!(err, SchemaError::TenantSigVerification(_)),
        "expected SchemaError::TenantSigVerification on forged sig, got {err:?}"
    );
}

#[test]
fn threat_tee_quote_forgery_genuine_frame_round_trips() {
    // covers: tee_quote_forgery
    //
    // Sanity arm: a frame correctly signed by the legitimate tenant
    // key passes validate_signed under that same key. Guards against
    // a deny path that over-rejects valid evidence.
    let (frame, public_key) = signed_frame();
    if let Err(err) = validate_signed(&frame, &public_key) {
        panic!(
            "legitimate signed frame MUST validate (otherwise the deny \
             guard is over-rejecting); got {err:?}"
        );
    }
}
