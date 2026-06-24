// Threat test for threat ID `device_key_extraction`.
//
// Coverage strategy: present an App Attest fixture whose key id is bound
// to a different credential and a Play Integrity token whose verdict is
// downgraded; the production verifiers must reject both.
//
// Revert-to-prove-it-fails recipes:
//   (a) inside `verify_app_attest` in
//       `crates/chio-custody-hw/src/attestation/app_attest.rs`,
//       remove the `key_id` comparison branch (or replace its
//       `Err(AttestationError::KeyIdMismatch)` with `Ok(())`). The
//       App Attest deny-arm assertion below fails.
//   (b) inside `verify_play_integrity` in
//       `crates/chio-custody-hw/src/attestation/play_integrity.rs`,
//       drop the hardware-backed verdict check that returns
//       `Err(AttestationError::PlayIntegrityDeviceRejected)`. The
//       Play Integrity deny-arm assertion below fails.

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
        production: true,
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
        allow_caller_supplied_jwks: false,
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
