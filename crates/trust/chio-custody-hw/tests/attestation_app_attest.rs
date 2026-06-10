use std::error::Error;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
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
const APP_ATTEST_PRODUCTION_AAGUID: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";

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
        previous_counter: Some(0),
        allow_development_fixture: true,
    })?;

    assert_eq!(verified.key_id, KEY_ID);
    assert_eq!(verified.app_id, APP_ID);
    assert_eq!(verified.counter, 1);
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
        previous_counter: Some(0),
        allow_development_fixture: true,
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
        previous_counter: Some(0),
        allow_development_fixture: true,
    })
    .err()
    .ok_or("expected key mismatch")?;

    assert_eq!(error, AttestationError::KeyIdMismatch);
    Ok(())
}

#[test]
fn app_attest_verifier_rejects_fixture_shape_unless_enabled() -> Result<(), Box<dyn Error>> {
    let fixture = cbor_fixture(APP_ID, KEY_ID, CHALLENGE)?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: KEY_ID,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: Some(0),
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected disabled fixture rejection")?;

    assert!(matches!(error, AttestationError::InvalidCbor(_)));
    Ok(())
}

#[test]
fn app_attest_verifier_rejects_counter_rollback() -> Result<(), Box<dyn Error>> {
    let fixture = cbor_fixture(APP_ID, KEY_ID, CHALLENGE)?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: KEY_ID,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: Some(1),
        allow_development_fixture: true,
    })
    .err()
    .ok_or("expected counter rollback")?;

    assert_eq!(error, AttestationError::CounterRollback);
    assert_eq!(
        error.urn(),
        "urn:chio:error:custody:app-attest-counter-rollback"
    );
    Ok(())
}

#[test]
fn app_attest_webauthn_shape_rejects_missing_x5c_fail_closed() -> Result<(), Box<dyn Error>> {
    let credential_id = b"credential-id-1";
    let key_id = Base64::encode_string(credential_id);
    let fixture = webauthn_fixture(APP_ID, credential_id, CHALLENGE)?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: None,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected missing x5c rejection")?;

    assert_eq!(error, AttestationError::MissingField("attStmt.x5c"));
    Ok(())
}

#[test]
fn app_attest_webauthn_shape_rejects_unknown_aaguid() -> Result<(), Box<dyn Error>> {
    let credential_id = b"credential-id-1";
    let key_id = Base64UrlUnpadded::encode_string(credential_id);
    let fixture =
        webauthn_fixture_with_auth_data(APP_ID, credential_id, CHALLENGE, &[0_u8; 16], 0)?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: None,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected AAGUID rejection")?;

    assert!(matches!(error, AttestationError::InvalidCbor(_)));
    Ok(())
}

#[test]
fn app_attest_webauthn_shape_rejects_nonzero_initial_counter() -> Result<(), Box<dyn Error>> {
    let credential_id = b"credential-id-1";
    let key_id = Base64UrlUnpadded::encode_string(credential_id);
    let fixture = webauthn_fixture_with_auth_data(
        APP_ID,
        credential_id,
        CHALLENGE,
        APP_ATTEST_PRODUCTION_AAGUID,
        1,
    )?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: None,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected nonzero counter rejection")?;

    assert!(matches!(error, AttestationError::InvalidCbor(_)));
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
            CborValue::Text("counter".to_string()),
            CborValue::Integer(1.into()),
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

fn webauthn_fixture(
    app_id: &str,
    credential_id: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    webauthn_fixture_with_auth_data(
        app_id,
        credential_id,
        challenge,
        APP_ATTEST_PRODUCTION_AAGUID,
        0,
    )
}

fn webauthn_fixture_with_auth_data(
    app_id: &str,
    credential_id: &[u8],
    challenge: &[u8],
    aaguid: &[u8; 16],
    counter: u32,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&sha256(app_id.as_bytes()));
    auth_data.push(0x40);
    auth_data.extend_from_slice(&counter.to_be_bytes());
    auth_data.extend_from_slice(aaguid);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    auth_data.extend_from_slice(&cose_key()?);

    let entries = vec![
        (
            CborValue::Text("fmt".to_string()),
            CborValue::Text(APP_ATTEST_FORMAT.to_string()),
        ),
        (
            CborValue::Text("authData".to_string()),
            CborValue::Bytes(auth_data),
        ),
        (
            CborValue::Text("attStmt".to_string()),
            CborValue::Map(vec![(
                CborValue::Text("x5c".to_string()),
                CborValue::Array(vec![]),
            )]),
        ),
        (
            CborValue::Text("clientChallengeHash".to_string()),
            CborValue::Bytes(sha256(challenge).to_vec()),
        ),
    ];
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut bytes)?;
    Ok(bytes)
}

fn cose_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let value = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-7).into()),
        ),
    ]);
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
