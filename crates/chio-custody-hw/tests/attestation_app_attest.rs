use std::error::Error;

use chio_custody_hw::attestation::apple_root::{
    validate_pinned_apple_root, APPLE_APP_ATTEST_ROOT_SHA256,
};
use chio_custody_hw::{
    verify_app_attest, AppAttestVerificationInput, AttestationError, APP_ATTEST_FORMAT,
};
use coset::cbor::Value as CborValue;
use sha2::{Digest, Sha256};

const APP_ID: &str = "TEAMID1234.dev.chio.patient";
const KEY_ID: &str = "app-attest-key-1";
const CHALLENGE: &[u8] = b"fresh-server-challenge";
const PUBLIC_KEY: &[u8] = b"synthetic-credential-public-key";

#[test]
fn apple_root_pin_parses_and_matches_fingerprint() -> Result<(), Box<dyn Error>> {
    validate_pinned_apple_root()?;
    Ok(())
}

#[test]
fn app_attest_verifier_accepts_synthetic_cbor_fixture() -> Result<(), Box<dyn Error>> {
    let fixture = cbor_fixture(APP_ID, KEY_ID, CHALLENGE)?;

    let verified = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: KEY_ID,
        challenge: CHALLENGE,
        app_id: APP_ID,
    })?;

    assert_eq!(verified.key_id, KEY_ID);
    assert_eq!(verified.app_id, APP_ID);
    assert_eq!(
        verified.app_id_hash_hex,
        hex::encode(sha256(APP_ID.as_bytes()))
    );
    assert_eq!(verified.challenge_hash_hex, hex::encode(sha256(CHALLENGE)));
    assert_eq!(
        verified.root_fingerprint_sha256_hex,
        hex::encode(APPLE_APP_ATTEST_ROOT_SHA256)
    );
    assert_eq!(
        verified.credential_public_key_sha256_hex,
        hex::encode(sha256(PUBLIC_KEY))
    );
    Ok(())
}

#[test]
fn app_attest_verifier_rejects_wrong_challenge() -> Result<(), Box<dyn Error>> {
    let fixture = cbor_fixture(APP_ID, KEY_ID, CHALLENGE)?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: KEY_ID,
        challenge: b"replayed-challenge",
        app_id: APP_ID,
    })
    .err()
    .ok_or("expected challenge mismatch")?;

    assert_eq!(error, AttestationError::ChallengeMismatch);
    assert_eq!(
        error.urn(),
        "urn:chio:error:custody:app-attest-challenge-mismatch"
    );
    Ok(())
}

#[test]
fn app_attest_verifier_rejects_wrong_key_id() -> Result<(), Box<dyn Error>> {
    let fixture = cbor_fixture(APP_ID, KEY_ID, CHALLENGE)?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: "other-key",
        challenge: CHALLENGE,
        app_id: APP_ID,
    })
    .err()
    .ok_or("expected key mismatch")?;

    assert_eq!(error, AttestationError::KeyIdMismatch);
    Ok(())
}

fn cbor_fixture(app_id: &str, key_id: &str, challenge: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let entries = vec![
        (
            CborValue::Text("format".to_string()),
            CborValue::Text(APP_ATTEST_FORMAT.to_string()),
        ),
        (
            CborValue::Text("key_id".to_string()),
            CborValue::Text(key_id.to_string()),
        ),
        (
            CborValue::Text("app_id_hash".to_string()),
            CborValue::Bytes(sha256(app_id.as_bytes()).to_vec()),
        ),
        (
            CborValue::Text("challenge_hash".to_string()),
            CborValue::Bytes(sha256(challenge).to_vec()),
        ),
        (
            CborValue::Text("root_fingerprint_sha256".to_string()),
            CborValue::Bytes(APPLE_APP_ATTEST_ROOT_SHA256.to_vec()),
        ),
        (
            CborValue::Text("credential_public_key".to_string()),
            CborValue::Bytes(PUBLIC_KEY.to_vec()),
        ),
    ];
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut bytes)?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
