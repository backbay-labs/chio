use std::error::Error;

use chio_custody_hw::attestation::google_root::play_integrity_jwks_json;
use chio_custody_hw::{
    verify_app_attest, verify_play_integrity, AppAttestVerificationInput, AttestationError,
    PlayIntegrityVerificationInput,
};

use crate::mobile_attestation_common::{
    encoded_key_id, future_exp, signed_play_integrity_token, webauthn_fixture, APP_ID, AUDIENCE,
    CHALLENGE, NONCE, PACKAGE,
};

#[test]
fn device_key_extraction_is_rejected_by_key_and_device_binding() -> Result<(), Box<dyn Error>> {
    let credential_id = b"credential-id-1";
    let fixture = webauthn_fixture(APP_ID, credential_id, CHALLENGE)?;
    let other_key = encoded_key_id(b"credential-id-2");
    let app_attest_error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: &other_key,
        challenge: CHALLENGE,
        app_id: APP_ID,
        previous_counter: Some(0),
        allow_development_fixture: false,
    })
    .err()
    .ok_or("expected App Attest key-id rejection")?;
    assert_eq!(app_attest_error, AttestationError::KeyIdMismatch);
    assert_eq!(
        app_attest_error.urn(),
        "urn:chio:error:custody:app-attest-key-mismatch"
    );

    let token =
        signed_play_integrity_token(NONCE, AUDIENCE, &["MEETS_BASIC_INTEGRITY"], future_exp()?)?;
    let play_error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
    })
    .err()
    .ok_or("expected downgraded device rejection")?;
    assert_eq!(play_error, AttestationError::PlayIntegrityDeviceRejected);
    assert_eq!(
        play_error.urn(),
        "urn:chio:error:custody:play-integrity-device-rejected"
    );
    Ok(())
}
