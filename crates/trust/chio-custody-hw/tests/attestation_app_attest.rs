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
const APP_ATTEST_SANDBOX_AAGUID: &[u8; 16] = b"appattestsandbox";

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
        production: false,
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
        production: false,
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
        production: false,
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
        production: false,
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
        production: false,
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
        production: true,
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
        production: true,
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
        production: true,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected nonzero counter rejection")?;

    assert!(matches!(error, AttestationError::InvalidCbor(_)));
    Ok(())
}

#[test]
fn app_attest_webauthn_shape_rejects_sandbox_aaguid_in_production() -> Result<(), Box<dyn Error>> {
    // A sandbox-attested key must not be presentable as production custody
    // evidence: with `production: true` the sandbox AAGUID is rejected
    // before the chain is even examined.
    let credential_id = b"credential-id-1";
    let key_id = Base64UrlUnpadded::encode_string(credential_id);
    let fixture = webauthn_fixture_with_auth_data(
        APP_ID,
        credential_id,
        CHALLENGE,
        APP_ATTEST_SANDBOX_AAGUID,
        0,
    )?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: None,
        production: true,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected sandbox AAGUID rejection in production")?;

    match error {
        AttestationError::InvalidCbor(message) => assert!(
            message.contains("sandbox/development"),
            "sandbox rejection should name the non-production environment, got {message:?}"
        ),
        other => panic!("expected InvalidCbor for sandbox AAGUID, got {other:?}"),
    }
    Ok(())
}

#[test]
fn app_attest_webauthn_shape_allows_sandbox_aaguid_outside_production() -> Result<(), Box<dyn Error>>
{
    // Outside production the sandbox AAGUID is permitted, so verification
    // proceeds past the AAGUID gate and only later fails closed on the
    // (empty) x5c chain. This proves the AAGUID gate is the only thing the
    // `production` flag changes here.
    let credential_id = b"credential-id-1";
    let key_id = Base64UrlUnpadded::encode_string(credential_id);
    let fixture = webauthn_fixture_with_auth_data(
        APP_ID,
        credential_id,
        CHALLENGE,
        APP_ATTEST_SANDBOX_AAGUID,
        0,
    )?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: None,
        production: false,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected later x5c rejection")?;

    assert_eq!(error, AttestationError::MissingField("attStmt.x5c"));
    Ok(())
}

#[test]
fn app_attest_webauthn_shape_rejects_malformed_credential_key() -> Result<(), Box<dyn Error>> {
    // WebAuthn step 6 requires a usable credential public key. A credential
    // key that is not a COSE EC2 P-256 key is rejected before the chain is
    // examined, so an attacker cannot smuggle a non-bindable key past the
    // leaf-key binding.
    let credential_id = b"credential-id-1";
    let key_id = Base64UrlUnpadded::encode_string(credential_id);
    let fixture = webauthn_fixture_with_malformed_cose_key(
        APP_ID,
        credential_id,
        APP_ATTEST_PRODUCTION_AAGUID,
    )?;
    let error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &key_id,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: None,
        production: true,
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected malformed credential key rejection")?;

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

fn webauthn_fixture_with_malformed_cose_key(
    app_id: &str,
    credential_id: &[u8],
    aaguid: &[u8; 16],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&sha256(app_id.as_bytes()));
    auth_data.push(0x40);
    auth_data.extend_from_slice(&0_u32.to_be_bytes());
    auth_data.extend_from_slice(aaguid);
    auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    auth_data.extend_from_slice(credential_id);
    // A non-EC2 COSE key (kty=OKP) so the credential public key cannot be
    // bound to a P-256 attestation leaf.
    let mut malformed = Vec::new();
    coset::cbor::ser::into_writer(
        &CborValue::Map(vec![(
            CborValue::Integer(1.into()),
            CborValue::Integer(1.into()),
        )]),
        &mut malformed,
    )?;
    auth_data.extend_from_slice(&malformed);

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
    ];
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&CborValue::Map(entries), &mut bytes)?;
    Ok(bytes)
}

// Two distinct synthetic P-256 affine points used to drive the
// credential-public-key COSE key. They are arbitrary 32-byte values: the
// custody verifier only compares them against the attestation leaf key, so
// they need not be on-curve for these shape tests.
const COSE_POINT_X: [u8; 32] = [0x11; 32];
const COSE_POINT_Y: [u8; 32] = [0x22; 32];

fn cose_key() -> Result<Vec<u8>, Box<dyn Error>> {
    cose_p256_key(&COSE_POINT_X, &COSE_POINT_Y)
}

fn cose_p256_key(x: &[u8; 32], y: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    // COSE EC2 P-256 key: kty(1)=EC2(2), alg(3)=ES256(-7), crv(-1)=P-256(1),
    // x(-2), y(-3).
    let value = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(2.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Integer((-7).into()),
        ),
        (
            CborValue::Integer((-1).into()),
            CborValue::Integer(1.into()),
        ),
        (
            CborValue::Integer((-2).into()),
            CborValue::Bytes(x.to_vec()),
        ),
        (
            CborValue::Integer((-3).into()),
            CborValue::Bytes(y.to_vec()),
        ),
    ]);
    let mut bytes = Vec::new();
    coset::cbor::ser::into_writer(&value, &mut bytes)?;
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
