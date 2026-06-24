// Threat test for threat ID `mobile_attestation_replay`.
//
// Coverage strategy: present an App Attest fixture against a stale
// server challenge, and a Play Integrity token against a replayed nonce;
// both production verifiers must reject the replay.
//
// Revert-to-prove-it-fails recipes:
//   (a) inside `verify_app_attest` in
//       `crates/chio-custody-hw/src/attestation/app_attest.rs`,
//       remove the challenge-comparison branch that returns
//       `Err(AttestationError::ChallengeMismatch)`. The App Attest
//       deny-arm assertion below fails.
//   (b) inside `verify_play_integrity` in
//       `crates/chio-custody-hw/src/attestation/play_integrity.rs`,
//       remove the nonce comparison that returns
//       `Err(AttestationError::PlayIntegrityNonceMismatch)`. The Play
//       Integrity deny-arm assertion below fails.

use std::error::Error;

use chio_custody_hw::attestation::google_root::play_integrity_jwks_json;
use chio_custody_hw::{
    verify_app_attest, verify_play_integrity, AppAttestVerificationInput, AttestationError,
    PlayIntegrityVerificationInput, MEETS_DEVICE_INTEGRITY,
};

use crate::mobile_attestation_common::{
    app_attest_fixture, future_exp, signed_play_integrity_token, APP_ID, AUDIENCE, CHALLENGE,
    KEY_ID, NONCE, PACKAGE,
};

#[test]
fn mobile_attestation_replay_is_rejected_by_bound_challenges() -> Result<(), Box<dyn Error>> {
    let fixture = app_attest_fixture(APP_ID, KEY_ID, CHALLENGE)?;
    let app_attest_error = verify_app_attest(AppAttestVerificationInput {
        attestation_cbor: &fixture,
        key_id: KEY_ID,
        challenge: b"stale-server-challenge",
        app_id: APP_ID,
        previous_counter: Some(0),
        production: false,
        allow_development_fixture: true,
    })
    .err()
    .ok_or("expected App Attest replay rejection")?;
    assert_eq!(app_attest_error, AttestationError::ChallengeMismatch);
    assert_eq!(
        app_attest_error.urn(),
        "urn:chio:error:custody:app-attest-challenge-mismatch"
    );

    let token =
        signed_play_integrity_token(NONCE, AUDIENCE, &[MEETS_DEVICE_INTEGRITY], future_exp()?)?;
    let play_error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: "replayed-nonce",
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected Play Integrity nonce replay rejection")?;
    assert_eq!(play_error, AttestationError::PlayIntegrityNonceMismatch);
    assert_eq!(
        play_error.urn(),
        "urn:chio:error:custody:play-integrity-nonce-mismatch"
    );
    Ok(())
}
