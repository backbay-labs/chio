use std::error::Error;

use chio_custody_hw::attestation::google_root::{
    play_integrity_encoding_key, play_integrity_root_sha256_hex, GOOGLE_PLAY_INTEGRITY_ROOT_KID,
};
use chio_custody_hw::{
    verify_mobile_receipt_chain, verify_play_integrity, AttestationError,
    PlayIntegrityVerificationInput, MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED,
};
use jsonwebtoken::{encode, Algorithm, Header};
use serde::Serialize;

const PACKAGE: &str = "dev.chio.patient";
const NONCE: &str = "issuer-nonce-1";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestClaims {
    nonce: String,
    app_integrity: TestAppIntegrity,
    device_integrity: TestDeviceIntegrity,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestAppIntegrity {
    app_recognition_verdict: String,
    package_name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestDeviceIntegrity {
    device_recognition_verdict: Vec<String>,
}

#[test]
fn play_integrity_verifier_accepts_signed_fixture() -> Result<(), Box<dyn Error>> {
    let token = signed_token(NONCE, PACKAGE, PLAY_RECOGNIZED, &[MEETS_DEVICE_INTEGRITY])?;
    let verified = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
    })?;

    assert_eq!(verified.nonce, NONCE);
    assert_eq!(verified.package_name, PACKAGE);
    assert_eq!(verified.app_recognition_verdict, PLAY_RECOGNIZED);
    assert_eq!(
        verified.device_recognition_verdict,
        vec![MEETS_DEVICE_INTEGRITY.to_string()]
    );
    assert_eq!(
        GOOGLE_PLAY_INTEGRITY_ROOT_KID,
        "chio-play-integrity-fixture-root"
    );
    assert!(!play_integrity_root_sha256_hex().is_empty());
    Ok(())
}

#[test]
fn play_integrity_verifier_rejects_nonce_replay() -> Result<(), Box<dyn Error>> {
    let token = signed_token(NONCE, PACKAGE, PLAY_RECOGNIZED, &[MEETS_DEVICE_INTEGRITY])?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: "other-nonce",
        expected_package_name: PACKAGE,
    })
    .err()
    .ok_or("expected nonce mismatch")?;

    assert_eq!(error, AttestationError::PlayIntegrityNonceMismatch);
    assert_eq!(
        error.urn(),
        "urn:chio:error:custody:play-integrity-nonce-mismatch"
    );
    Ok(())
}

#[test]
fn play_integrity_verifier_rejects_unrecognized_app() -> Result<(), Box<dyn Error>> {
    let token = signed_token(NONCE, PACKAGE, "UNEVALUATED", &[MEETS_DEVICE_INTEGRITY])?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
    })
    .err()
    .ok_or("expected app rejection")?;

    assert_eq!(error, AttestationError::PlayIntegrityAppRejected);
    Ok(())
}

#[test]
fn receipt_chain_accepts_play_integrity_evidence_shape() -> Result<(), Box<dyn Error>> {
    let verified = verify_mobile_receipt_chain(
        r#"{"schema":"chio.mobile.receipt.v1"}"#,
        r#"{"schema":"chio.mobile.attestation-evidence.v1","platform":"play_integrity"}"#,
    )?;
    assert_eq!(verified.platform, "play_integrity");
    Ok(())
}

fn signed_token(
    nonce: &str,
    package_name: &str,
    app_verdict: &str,
    device_verdicts: &[&str],
) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(GOOGLE_PLAY_INTEGRITY_ROOT_KID.to_string());
    let claims = TestClaims {
        nonce: nonce.to_string(),
        app_integrity: TestAppIntegrity {
            app_recognition_verdict: app_verdict.to_string(),
            package_name: package_name.to_string(),
        },
        device_integrity: TestDeviceIntegrity {
            device_recognition_verdict: device_verdicts
                .iter()
                .map(|verdict| (*verdict).to_string())
                .collect(),
        },
    };
    encode(&header, &claims, &play_integrity_encoding_key()).map_err(Into::into)
}
