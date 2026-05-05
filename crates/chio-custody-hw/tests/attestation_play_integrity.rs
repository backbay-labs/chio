use std::error::Error;

use chio_custody_hw::attestation::google_root::{
    play_integrity_encoding_key, play_integrity_jwks_json, play_integrity_root_sha256_hex,
    GOOGLE_PLAY_INTEGRITY_ISSUER, GOOGLE_PLAY_INTEGRITY_ROOT_KID,
};
use chio_custody_hw::{
    verify_mobile_receipt_chain, verify_play_integrity, AttestationError,
    PlayIntegrityVerificationInput, MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED,
};
use jsonwebtoken::{encode, Algorithm, Header};
use serde::Serialize;

const PACKAGE: &str = "dev.chio.patient";
const NONCE: &str = "issuer-nonce-1";
const AUDIENCE: &str = "chio-mobile-issuer";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct TestClaims {
    nonce: String,
    app_integrity: TestAppIntegrity,
    device_integrity: TestDeviceIntegrity,
    aud: String,
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
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
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
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
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
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
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
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
    signed_token_with_exp(
        nonce,
        package_name,
        app_verdict,
        device_verdicts,
        Some(future_exp()?),
    )
}

fn signed_token_with_exp(
    nonce: &str,
    package_name: &str,
    app_verdict: &str,
    device_verdicts: &[&str],
    exp: Option<u64>,
) -> Result<String, Box<dyn Error>> {
    signed_token_with_alg(
        nonce,
        package_name,
        app_verdict,
        device_verdicts,
        exp,
        Algorithm::HS256,
    )
}

fn signed_token_with_alg(
    nonce: &str,
    package_name: &str,
    app_verdict: &str,
    device_verdicts: &[&str],
    exp: Option<u64>,
    algorithm: Algorithm,
) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(algorithm);
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
        aud: AUDIENCE.to_string(),
        iss: GOOGLE_PLAY_INTEGRITY_ISSUER.to_string(),
        exp,
    };
    encode(&header, &claims, &play_integrity_encoding_key()).map_err(Into::into)
}

#[test]
fn play_integrity_verifier_rejects_expired_token_fail_closed() -> Result<(), Box<dyn Error>> {
    // A token whose `exp` claim is in the past must be rejected even when
    // every other claim matches. This locks in the trj3.2 fix that closes
    // the previous "validate_exp = false" path: the fixture verifier no
    // longer silently accepts a stale token replayed past the issuer's
    // retention window.
    let token = signed_token_with_exp(
        NONCE,
        PACKAGE,
        PLAY_RECOGNIZED,
        &[MEETS_DEVICE_INTEGRITY],
        Some(1),
    )?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
    })
    .err()
    .ok_or("expected expired-token rejection")?;
    assert!(matches!(
        error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
    assert_eq!(
        error.urn(),
        "urn:chio:error:custody:play-integrity-invalid-token"
    );
    Ok(())
}

#[test]
fn play_integrity_verifier_accepts_future_exp() -> Result<(), Box<dyn Error>> {
    // A token whose `exp` claim is far in the future must still verify so
    // legitimate tokens with their own freshness window keep working.
    let token = signed_token_with_exp(
        NONCE,
        PACKAGE,
        PLAY_RECOGNIZED,
        &[MEETS_DEVICE_INTEGRITY],
        Some(future_exp()?),
    )?;
    let verified = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
    })?;
    assert_eq!(verified.nonce, NONCE);
    Ok(())
}

#[test]
fn play_integrity_verifier_rejects_wrong_audience() -> Result<(), Box<dyn Error>> {
    let token = signed_token(NONCE, PACKAGE, PLAY_RECOGNIZED, &[MEETS_DEVICE_INTEGRITY])?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: "other-audience",
        jwks_json: &play_integrity_jwks_json(),
    })
    .err()
    .ok_or("expected audience rejection")?;
    assert!(matches!(
        error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
    Ok(())
}

#[test]
fn play_integrity_verifier_rejects_alg_downgrade() -> Result<(), Box<dyn Error>> {
    let token = signed_token_with_alg(
        NONCE,
        PACKAGE,
        PLAY_RECOGNIZED,
        &[MEETS_DEVICE_INTEGRITY],
        Some(future_exp()?),
        Algorithm::HS384,
    )?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
    })
    .err()
    .ok_or("expected algorithm rejection")?;
    assert!(matches!(
        error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
    Ok(())
}

fn future_exp() -> Result<u64, Box<dyn Error>> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() + 3_600)
        .map_err(Into::into)
}

#[test]
fn receipt_chain_rejects_empty_evidence_schema_fail_closed() -> Result<(), Box<dyn Error>> {
    // Defence-in-depth: the receipt-chain shell is a shape-only verifier;
    // an empty evidence schema string is meaningless and must be rejected
    // rather than passed through to a downstream consumer that might
    // treat the absence of a schema marker as "schema-agnostic".
    let res = verify_mobile_receipt_chain(
        r#"{"schema":"chio.mobile.receipt.v1"}"#,
        r#"{"schema":"","platform":"play_integrity"}"#,
    );
    let err = res.err().ok_or("expected empty-schema rejection")?;
    assert!(matches!(err, AttestationError::InvalidCbor(_)));
    Ok(())
}

#[test]
fn receipt_chain_rejects_unknown_platform_fail_closed() -> Result<(), Box<dyn Error>> {
    // Only `app_attest` and `play_integrity` are accepted; an attacker
    // cannot label evidence with a made-up platform and pass the shell.
    let res = verify_mobile_receipt_chain(
        r#"{"schema":"chio.mobile.receipt.v1"}"#,
        r#"{"schema":"chio.mobile.attestation-evidence.v1","platform":"hand-rolled"}"#,
    );
    let err = res.err().ok_or("expected unknown-platform rejection")?;
    assert!(matches!(err, AttestationError::UnsupportedFormat(_)));
    Ok(())
}
