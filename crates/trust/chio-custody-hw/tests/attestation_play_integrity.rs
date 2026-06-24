use std::error::Error;

use base64ct::{Base64UrlUnpadded, Encoding};
use chio_custody_hw::attestation::google_root::{
    play_integrity_encoding_key, play_integrity_jwks_json, play_integrity_root_sha256_hex,
    GOOGLE_PLAY_INTEGRITY_ISSUER, GOOGLE_PLAY_INTEGRITY_ROOT_KID,
};
use chio_custody_hw::{
    verify_mobile_receipt_chain, verify_play_integrity, AttestationError,
    PlayIntegrityVerificationInput, MEETS_DEVICE_INTEGRITY, PLAY_RECOGNIZED,
};
use jsonwebtoken::{decode_header, encode, Algorithm, EncodingKey, Header};
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
    assert_eq!(decode_header(&token)?.alg, Algorithm::ES256);
    let verified = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
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
    assert!(!play_integrity_root_sha256_hex()?.is_empty());
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
        allow_caller_supplied_jwks: false,
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
        allow_caller_supplied_jwks: false,
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

const ATTACKER_KID: &str = "attacker-supplied-kid";

#[test]
fn play_integrity_pins_jwks_and_ignores_caller_supplied_keys() -> Result<(), Box<dyn Error>> {
    // The token is signed under an attacker-chosen `kid` and the caller
    // hands the verifier a JWKS that "trusts" that kid. With
    // `allow_caller_supplied_jwks: false` (the production behaviour) the
    // verifier uses the pinned Google JWKS instead, which has no such kid,
    // so the token is rejected. This is the core pinned-root guarantee: a
    // caller cannot bring its own verification key.
    let token = signed_token_with_kid(ATTACKER_KID)?;
    let attacker_jwks = caller_jwks_for_kid(ATTACKER_KID);
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &attacker_jwks,
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected pinned-root rejection of caller-supplied kid")?;
    match error {
        AttestationError::PlayIntegrityInvalidToken(message) => assert!(
            message.contains(ATTACKER_KID),
            "rejection should reference the missing attacker kid, got {message:?}"
        ),
        other => panic!("expected invalid-token rejection, got {other:?}"),
    }
    Ok(())
}

#[test]
fn play_integrity_caller_supplied_jwks_only_honoured_when_opted_in() -> Result<(), Box<dyn Error>> {
    // The exact same attacker-kid token + caller JWKS is honoured only when
    // the caller opts into caller-supplied JWKS (a test/dev-only switch).
    // This confirms the pinning toggle is the sole difference between the
    // two paths, and that the production path (above) is strictly the
    // pinned one.
    let token = signed_token_with_kid(ATTACKER_KID)?;
    let attacker_jwks = caller_jwks_for_kid(ATTACKER_KID);
    let verified = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &attacker_jwks,
        allow_caller_supplied_jwks: true,
    })?;
    assert_eq!(verified.nonce, NONCE);
    Ok(())
}

fn signed_token_with_kid(kid: &str) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    let claims = TestClaims {
        nonce: NONCE.to_string(),
        app_integrity: TestAppIntegrity {
            app_recognition_verdict: PLAY_RECOGNIZED.to_string(),
            package_name: PACKAGE.to_string(),
        },
        device_integrity: TestDeviceIntegrity {
            device_recognition_verdict: vec![MEETS_DEVICE_INTEGRITY.to_string()],
        },
        aud: AUDIENCE.to_string(),
        iss: GOOGLE_PLAY_INTEGRITY_ISSUER.to_string(),
        exp: Some(future_exp()?),
    };
    encode(&header, &claims, &play_integrity_encoding_key()?).map_err(Into::into)
}

// A caller-supplied JWKS that maps `kid` to the (fixture) public key. The
// pinned path ignores this document entirely; the opt-in path trusts it.
fn caller_jwks_for_kid(kid: &str) -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "kid": kid,
                "use": "sig",
                "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
                "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4"
            }
        ]
    })
    .to_string()
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
    let mut header = Header::new(Algorithm::ES256);
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
    encode(&header, &claims, &play_integrity_encoding_key()?).map_err(Into::into)
}

fn signed_token_with_issuer(issuer: &str) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(GOOGLE_PLAY_INTEGRITY_ROOT_KID.to_string());
    let claims = TestClaims {
        nonce: NONCE.to_string(),
        app_integrity: TestAppIntegrity {
            app_recognition_verdict: PLAY_RECOGNIZED.to_string(),
            package_name: PACKAGE.to_string(),
        },
        device_integrity: TestDeviceIntegrity {
            device_recognition_verdict: vec![MEETS_DEVICE_INTEGRITY.to_string()],
        },
        aud: AUDIENCE.to_string(),
        iss: issuer.to_string(),
        exp: Some(future_exp()?),
    };
    encode(&header, &claims, &play_integrity_encoding_key()?).map_err(Into::into)
}

#[test]
fn play_integrity_verifier_rejects_expired_token_fail_closed() -> Result<(), Box<dyn Error>> {
    // A token whose `exp` claim is in the past must be rejected even when
    // every other claim matches, so a stale token replayed past the
    // issuer's retention window cannot be silently accepted.
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
        allow_caller_supplied_jwks: false,
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
fn play_integrity_verifier_rejects_wrong_issuer() -> Result<(), Box<dyn Error>> {
    let token = signed_token_with_issuer("https://accounts.example.invalid")?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected issuer rejection")?;
    assert!(matches!(
        error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
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
        allow_caller_supplied_jwks: false,
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
        allow_caller_supplied_jwks: false,
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
fn play_integrity_verifier_rejects_non_es256_asymmetric_algs() -> Result<(), Box<dyn Error>> {
    let cases = [
        (
            "rsa",
            Algorithm::RS256,
            unsupported_alg_jwks_json("rsa", "RS256"),
        ),
        (
            "pss",
            Algorithm::PS256,
            unsupported_alg_jwks_json("pss", "PS256"),
        ),
        (
            "eddsa",
            Algorithm::EdDSA,
            unsupported_alg_jwks_json("eddsa", "EdDSA"),
        ),
        (
            "es384",
            Algorithm::ES384,
            unsupported_alg_jwks_json("es384", "ES384"),
        ),
    ];

    for (kid, algorithm, jwks_json) in cases {
        let token = token_with_header_alg(algorithm, kid)?;
        let error = verify_play_integrity(PlayIntegrityVerificationInput {
            token: &token,
            expected_nonce: NONCE,
            expected_package_name: PACKAGE,
            expected_audience: AUDIENCE,
            jwks_json: &jwks_json,
            allow_caller_supplied_jwks: true,
        })
        .err()
        .ok_or("expected unsupported asymmetric algorithm rejection")?;
        assert_invalid_token_contains(error, "unsupported Play Integrity JWKS signing alg", kid);
    }
    let jwks_json = p384_jwks_with_es256_alg("p384-es256");
    let token = token_with_header_alg(Algorithm::ES256, "p384-es256")?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &jwks_json,
        allow_caller_supplied_jwks: true,
    })
    .err()
    .ok_or("expected P-384 curve rejection")?;
    assert_invalid_token_contains(error, "must use P-256", "p384-es256");
    Ok(())
}

#[test]
fn play_integrity_verifier_rejects_symmetric_alg_downgrade() -> Result<(), Box<dyn Error>> {
    let token = signed_symmetric_token_with_alg(
        b"attacker-controlled-play-integrity-secret",
        GOOGLE_PLAY_INTEGRITY_ROOT_KID,
        Algorithm::HS384,
    )?;
    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &play_integrity_jwks_json(),
        allow_caller_supplied_jwks: false,
    })
    .err()
    .ok_or("expected algorithm rejection")?;
    assert!(matches!(
        error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
    Ok(())
}

#[test]
fn play_integrity_verifier_rejects_symmetric_jwks_fail_closed() -> Result<(), Box<dyn Error>> {
    let secret = b"attacker-controlled-play-integrity-secret";
    let kid = "attacker-hmac";
    let token = signed_symmetric_token(secret, kid)?;
    let jwks = serde_json::json!({
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "kid": kid,
                "use": "sig",
                "k": Base64UrlUnpadded::encode_string(secret)
            }
        ]
    })
    .to_string();

    let error = verify_play_integrity(PlayIntegrityVerificationInput {
        token: &token,
        expected_nonce: NONCE,
        expected_package_name: PACKAGE,
        expected_audience: AUDIENCE,
        jwks_json: &jwks,
        allow_caller_supplied_jwks: true,
    })
    .err()
    .ok_or("expected symmetric JWKS rejection")?;
    assert!(matches!(
        error,
        AttestationError::PlayIntegrityInvalidToken(_)
    ));
    Ok(())
}

fn signed_symmetric_token(secret: &[u8], kid: &str) -> Result<String, Box<dyn Error>> {
    signed_symmetric_token_with_alg(secret, kid, Algorithm::HS256)
}

fn signed_symmetric_token_with_alg(
    secret: &[u8],
    kid: &str,
    algorithm: Algorithm,
) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(algorithm);
    header.kid = Some(kid.to_string());
    let claims = TestClaims {
        nonce: NONCE.to_string(),
        app_integrity: TestAppIntegrity {
            app_recognition_verdict: PLAY_RECOGNIZED.to_string(),
            package_name: PACKAGE.to_string(),
        },
        device_integrity: TestDeviceIntegrity {
            device_recognition_verdict: vec![MEETS_DEVICE_INTEGRITY.to_string()],
        },
        aud: AUDIENCE.to_string(),
        iss: GOOGLE_PLAY_INTEGRITY_ISSUER.to_string(),
        exp: Some(future_exp()?),
    };
    encode(&header, &claims, &EncodingKey::from_secret(secret)).map_err(Into::into)
}

fn token_with_header_alg(algorithm: Algorithm, kid: &str) -> Result<String, Box<dyn Error>> {
    let mut header = Header::new(algorithm);
    header.kid = Some(kid.to_string());
    let header_b64 = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header)?);
    let claims_b64 = Base64UrlUnpadded::encode_string(br#"{}"#);
    Ok(format!("{header_b64}.{claims_b64}.signature"))
}

fn assert_invalid_token_contains(error: AttestationError, expected: &str, label: &str) {
    match error {
        AttestationError::PlayIntegrityInvalidToken(message) => assert!(
            message.contains(expected),
            "{label} should reject before signature verification with message containing {expected:?}, got {message:?}"
        ),
        other => panic!("{label} should fail as an invalid Play Integrity token, got {other:?}"),
    }
}

fn unsupported_alg_jwks_json(kid: &str, alg: &str) -> String {
    let key = match alg {
        "RS256" | "PS256" => serde_json::json!({
            "kty": "RSA",
            "alg": alg,
            "kid": kid,
            "use": "sig",
            "n": "AQAB",
            "e": "AQAB"
        }),
        "EdDSA" => serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": alg,
            "kid": kid,
            "use": "sig",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }),
        "ES384" => serde_json::json!({
            "kty": "EC",
            "crv": "P-384",
            "alg": alg,
            "kid": kid,
            "use": "sig",
            "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
            "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4"
        }),
        _ => serde_json::json!({
            "kty": "oct",
            "alg": alg,
            "kid": kid,
            "use": "sig",
            "k": "AA"
        }),
    };
    serde_json::json!({ "keys": [key] }).to_string()
}

fn p384_jwks_with_es256_alg(kid: &str) -> String {
    serde_json::json!({
        "keys": [
            {
                "kty": "EC",
                "crv": "P-384",
                "alg": "ES256",
                "kid": kid,
                "use": "sig",
                "x": "w7JAoU_gJbZJvV-zCOvU9yFJq0FNC_edCMRM78P8eQQ",
                "y": "wQg1EytcsEmGrM70Gb53oluoDbVhCZ3Uq3hHMslHVb4"
            }
        ]
    })
    .to_string()
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
