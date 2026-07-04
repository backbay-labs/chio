#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Portable passport verification integration tests.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{Keypair, PublicKey, Signature};
use chio_kernel_core::passport_verify::{
    verify_parsed_passport, verify_passport, PortablePassportBody, PortablePassportEnvelope,
    VerifyError, PORTABLE_PASSPORT_SCHEMA,
};
use chio_kernel_core::FixedClock;

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;

fn build_envelope(
    issuer: &Keypair,
    subject: &str,
    issued_at: u64,
    expires_at: u64,
) -> PortablePassportEnvelope {
    let payload = serde_json::json!({
        "schema": "chio.agent-passport.v1",
        "subject": subject,
        "trustTier": "premier",
    });
    let payload_canonical_bytes = canonical_json_bytes(&payload).expect("canonical-JSON payload");
    let body = PortablePassportBody {
        schema: PORTABLE_PASSPORT_SCHEMA.to_string(),
        subject: subject.to_string(),
        issuer: issuer.public_key(),
        issued_at,
        expires_at,
        payload_canonical_bytes,
    };
    let (signature, _) = issuer.sign_canonical(&body).expect("sign canonical");
    PortablePassportEnvelope { body, signature }
}

fn serialize_envelope(envelope: &PortablePassportEnvelope) -> Vec<u8> {
    serde_json::to_vec(envelope).expect("serialize envelope")
}

#[test]
fn verify_passport_happy_path() {
    let issuer = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-1", ISSUED_AT, EXPIRES_AT);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let verified =
        verify_passport(&serialize_envelope(&envelope), &trusted, &clock).expect("verified");
    assert_eq!(verified.subject, "did:chio:agent-1");
    assert_eq!(verified.issuer, issuer.public_key());
    assert_eq!(verified.issued_at, ISSUED_AT);
    assert_eq!(verified.expires_at, EXPIRES_AT);
    assert_eq!(verified.evaluated_at, ISSUED_AT + 1);
    assert_eq!(
        verified.payload_canonical_bytes,
        envelope.body.payload_canonical_bytes
    );
}

#[test]
fn verify_passport_denies_expired_envelope() {
    let issuer = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-2", ISSUED_AT, EXPIRES_AT);
    let clock = FixedClock::new(EXPIRES_AT);
    let trusted = [issuer.public_key()];

    let err = verify_passport(&serialize_envelope(&envelope), &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::Expired);
}

#[test]
fn verify_passport_denies_not_yet_valid() {
    let issuer = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-3", ISSUED_AT, EXPIRES_AT);
    let clock = FixedClock::new(ISSUED_AT - 1);
    let trusted = [issuer.public_key()];

    let err = verify_passport(&serialize_envelope(&envelope), &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::NotYetValid);
}

#[test]
fn verify_passport_denies_untrusted_issuer() {
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-4", ISSUED_AT, EXPIRES_AT);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [other.public_key()];

    let err = verify_passport(&serialize_envelope(&envelope), &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::UntrustedIssuer);
}

#[test]
fn verify_passport_denies_tampered_subject() {
    let issuer = Keypair::generate();
    let mut envelope = build_envelope(&issuer, "did:chio:agent-5", ISSUED_AT, EXPIRES_AT);
    envelope.body.subject = "did:chio:mallory".to_string();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let err = verify_parsed_passport(&envelope, &trusted, &clock).unwrap_err();
    // Tampering with the signed body flips the canonical-JSON bytes so the
    // detached Ed25519 signature no longer verifies.
    assert_eq!(err, VerifyError::InvalidSignature);
}

#[test]
fn verify_passport_denies_wrong_signature() {
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let body = build_envelope(&issuer, "did:chio:agent-6", ISSUED_AT, EXPIRES_AT).body;
    let (foreign_signature, _) = other.sign_canonical(&body).expect("sign with other key");
    let envelope = PortablePassportEnvelope {
        body,
        signature: foreign_signature,
    };
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let err = verify_parsed_passport(&envelope, &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::InvalidSignature);
}

#[test]
fn verify_passport_denies_invalid_validity_window() {
    let issuer = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-7", EXPIRES_AT, ISSUED_AT);
    let clock = FixedClock::new(ISSUED_AT);
    let trusted = [issuer.public_key()];

    let err = verify_parsed_passport(&envelope, &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::InvalidValidityWindow);
}

#[test]
fn verify_passport_denies_missing_subject() {
    let issuer = Keypair::generate();
    let mut envelope = build_envelope(&issuer, "did:chio:agent-8", ISSUED_AT, EXPIRES_AT);
    envelope.body.subject.clear();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let err = verify_parsed_passport(&envelope, &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::MissingSubject);
}

#[test]
fn verify_passport_denies_invalid_schema() {
    let issuer = Keypair::generate();
    let mut envelope = build_envelope(&issuer, "did:chio:agent-9", ISSUED_AT, EXPIRES_AT);
    envelope.body.schema = "chio.fake.v9".to_string();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let err = verify_parsed_passport(&envelope, &trusted, &clock).unwrap_err();
    assert_eq!(err, VerifyError::InvalidSchema);
}

#[test]
fn verify_passport_rejects_invalid_envelope_bytes() {
    let issuer = Keypair::generate();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let err = verify_passport(b"not a json envelope", &trusted, &clock).unwrap_err();
    match err {
        VerifyError::InvalidEnvelope(_) => {}
        other => panic!("expected InvalidEnvelope, got {other:?}"),
    }
}

#[test]
fn verify_passport_rejects_unknown_envelope_and_body_fields() {
    let issuer = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-unknown", ISSUED_AT, EXPIRES_AT);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];

    let mut envelope_value = serde_json::to_value(&envelope).expect("envelope value");
    envelope_value
        .as_object_mut()
        .expect("envelope object")
        .insert("unsignedHint".to_string(), serde_json::json!("admin"));
    let envelope_bytes = serde_json::to_vec(&envelope_value).expect("unknown envelope bytes");
    assert!(matches!(
        verify_passport(&envelope_bytes, &trusted, &clock),
        Err(VerifyError::InvalidEnvelope(_))
    ));

    let mut body_value = serde_json::to_value(&envelope).expect("body value envelope");
    body_value
        .as_object_mut()
        .expect("envelope object")
        .get_mut("body")
        .expect("body field")
        .as_object_mut()
        .expect("body object")
        .insert("unsignedRole".to_string(), serde_json::json!("admin"));
    let body_bytes = serde_json::to_vec(&body_value).expect("unknown body bytes");
    assert!(matches!(
        verify_passport(&body_bytes, &trusted, &clock),
        Err(VerifyError::InvalidEnvelope(_))
    ));
}

#[test]
fn envelope_roundtrips_through_serde() {
    let issuer = Keypair::generate();
    let envelope = build_envelope(&issuer, "did:chio:agent-10", ISSUED_AT, EXPIRES_AT);
    let json = serde_json::to_vec(&envelope).expect("encode envelope");
    let decoded: PortablePassportEnvelope = serde_json::from_slice(&json).expect("decode envelope");
    assert_eq!(decoded, envelope);

    // the decoded envelope verifies end-to-end.
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted: [PublicKey; 1] = [issuer.public_key()];
    let _ = verify_parsed_passport(&decoded, &trusted, &clock).expect("verified");

    // Compilation witness for the imported Signature type: asserts
    // presence on the parsed envelope.
    let _: &Signature = &decoded.signature;
}
