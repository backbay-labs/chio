//! Android Play Integrity verifier.
//!
//! # Trust contract
//!
//! The verifier validates the JWS against a **pinned** Google JWKS rather
//! than a caller-supplied one: a malicious or compromised caller cannot
//! swap in its own verification key. The pinned key material lives in
//! [`super::google_root`]. A caller-supplied JWKS is only honoured when the
//! crate is built with the `dev-fixtures` feature (or under `cfg(test)`)
//! and the caller explicitly opts in via
//! [`PlayIntegrityVerificationInput::allow_caller_supplied_jwks`]; in a
//! production build that flag has no effect and the pinned JWKS is always
//! used.
//!
//! While the pinned root is still the committed synthetic fixture key
//! (BAC-601), the production verification path fails CLOSED: it rejects every
//! token rather than trusting the fixture signer. See `production_pinned_jwks`
//! and [`super::google_root::assert_play_integrity_root_is_production_ready`].
//!
//! The verifier selects the JWK by token `kid`, validates the JWS under
//! ES256/P-256 key material, and then enforces the Play Integrity
//! claim contract:
//!
//! - `aud` must match `expected_audience`.
//! - `exp` is required and must be in the future.
//! - Server-supplied nonce must match `expected_nonce` byte-for-byte.
//! - `app_integrity.package_name` must match `expected_package_name`.
//! - `app_integrity.app_recognition_verdict` must equal [`PLAY_RECOGNIZED`].
//! - `device_integrity.device_recognition_verdict` must contain
//!   [`MEETS_DEVICE_INTEGRITY`].

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use super::errors::AttestationError;
use super::google_root::{play_integrity_pinned_jwks_json, GOOGLE_PLAY_INTEGRITY_ISSUER};

pub const PLAY_RECOGNIZED: &str = "PLAY_RECOGNIZED";
pub const MEETS_DEVICE_INTEGRITY: &str = "MEETS_DEVICE_INTEGRITY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayIntegrityVerificationInput<'a> {
    pub token: &'a str,
    pub expected_nonce: &'a str,
    pub expected_package_name: &'a str,
    pub expected_audience: &'a str,
    /// Caller-supplied JWKS. Ignored in production: the verifier uses the
    /// pinned Google JWKS unless the crate is built with `dev-fixtures`
    /// (or `cfg(test)`) and `allow_caller_supplied_jwks` is `true`.
    pub jwks_json: &'a str,
    /// Opt-in to verifying against `jwks_json` instead of the pinned JWKS.
    /// Has no effect in a production build (the pinned JWKS is always used).
    pub allow_caller_supplied_jwks: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPlayIntegrity {
    pub package_name: String,
    pub nonce: String,
    pub app_recognition_verdict: String,
    pub device_recognition_verdict: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayIntegrityClaims {
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub request_details: Option<RequestDetailsClaims>,
    pub app_integrity: AppIntegrityClaims,
    pub device_integrity: DeviceIntegrityClaims,
    pub aud: String,
    pub iss: String,
    pub exp: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppIntegrityClaims {
    pub app_recognition_verdict: String,
    pub package_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIntegrityClaims {
    pub device_recognition_verdict: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestDetailsClaims {
    pub nonce: String,
    #[serde(default)]
    pub request_package_name: Option<String>,
    #[serde(default)]
    pub timestamp_millis: Option<u64>,
}

pub fn verify_play_integrity(
    input: PlayIntegrityVerificationInput<'_>,
) -> Result<VerifiedPlayIntegrity, AttestationError> {
    if input.expected_audience.trim().is_empty() {
        return Err(AttestationError::PlayIntegrityInvalidToken(
            "expected audience must not be empty".to_string(),
        ));
    }
    let header = decode_header(input.token)
        .map_err(|error| AttestationError::PlayIntegrityInvalidToken(error.to_string()))?;
    let kid = header.kid.as_deref().ok_or_else(|| {
        AttestationError::PlayIntegrityInvalidToken("token header is missing kid".to_string())
    })?;
    let jwks_source = select_jwks(&input)?;
    let jwks: JwkSet = serde_json::from_str(&jwks_source)
        .map_err(|error| AttestationError::PlayIntegrityInvalidToken(format!("JWKS: {error}")))?;
    let jwk = jwks.find(kid).ok_or_else(|| {
        AttestationError::PlayIntegrityInvalidToken(format!("JWKS has no key for kid {kid}"))
    })?;
    let algorithm = jwk_algorithm(jwk)?;
    if header.alg != algorithm {
        return Err(AttestationError::PlayIntegrityInvalidToken(format!(
            "token alg {:?} does not match JWKS alg {:?}",
            header.alg, algorithm
        )));
    }

    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|error| AttestationError::PlayIntegrityInvalidToken(error.to_string()))?;
    let mut validation = Validation::new(algorithm);
    validation.set_audience(&[input.expected_audience]);
    validation.set_issuer(&[GOOGLE_PLAY_INTEGRITY_ISSUER]);
    validation.required_spec_claims.insert("aud".to_string());
    validation.required_spec_claims.insert("iss".to_string());
    validation.required_spec_claims.insert("exp".to_string());
    let token = decode::<PlayIntegrityClaims>(input.token, &decoding_key, &validation)
        .map_err(|error| AttestationError::PlayIntegrityInvalidToken(error.to_string()))?;
    let claims = token.claims;
    let nonce = claim_nonce(&claims)?.to_string();

    if nonce != input.expected_nonce {
        return Err(AttestationError::PlayIntegrityNonceMismatch);
    }
    if claims.app_integrity.package_name != input.expected_package_name {
        return Err(AttestationError::PlayIntegrityPackageMismatch);
    }
    if claims.app_integrity.app_recognition_verdict != PLAY_RECOGNIZED {
        return Err(AttestationError::PlayIntegrityAppRejected);
    }
    if !claims
        .device_integrity
        .device_recognition_verdict
        .iter()
        .any(|verdict| verdict == MEETS_DEVICE_INTEGRITY)
    {
        return Err(AttestationError::PlayIntegrityDeviceRejected);
    }

    Ok(VerifiedPlayIntegrity {
        package_name: claims.app_integrity.package_name,
        nonce,
        app_recognition_verdict: claims.app_integrity.app_recognition_verdict,
        device_recognition_verdict: claims.device_integrity.device_recognition_verdict,
    })
}

/// Choose which JWKS to verify against.
///
/// Production builds always return the pinned Google JWKS, ignoring any
/// caller-supplied document. Test/`dev-fixtures` builds may honour a
/// caller-supplied JWKS when the caller opts in, so deterministic tests can
/// drive negative cases (symmetric keys, wrong curve, etc.).
#[cfg(any(test, feature = "dev-fixtures"))]
fn select_jwks(input: &PlayIntegrityVerificationInput<'_>) -> Result<String, AttestationError> {
    // Test/`dev-fixtures` builds legitimately pin the synthetic fixture key, so
    // the production-readiness guard is intentionally NOT enforced here: the
    // fixture signer is the trust anchor these builds exercise.
    if input.allow_caller_supplied_jwks {
        Ok(input.jwks_json.to_string())
    } else {
        Ok(play_integrity_pinned_jwks_json())
    }
}

#[cfg(not(any(test, feature = "dev-fixtures")))]
fn select_jwks(_input: &PlayIntegrityVerificationInput<'_>) -> Result<String, AttestationError> {
    // SECURITY / PLACEHOLDER (BAC-601): the production path pins this JWKS, and
    // `production_pinned_jwks` fails CLOSED while the committed synthetic fixture
    // key is still pinned. The earlier `debug_assert!` only fired in debug builds
    // and was stripped from release, so a release binary would have accepted
    // tokens minted with the committed fixture private key. This branch is
    // compiled only in prod builds, so the test/`dev-fixtures` signing path is
    // unaffected.
    production_pinned_jwks()
}

/// Production trust anchor for Play Integrity: the pinned Google JWKS, gated by
/// the production-readiness guard.
///
/// Fails CLOSED (returns [`AttestationError::PlayIntegrityInvalidToken`]) while
/// the pinned root is still the committed SYNTHETIC FIXTURE key, so a release
/// build cannot silently trust the fixture signer (BAC-601). Once the real
/// Google root is provisioned, this returns the pinned JWKS.
///
/// This helper is compiled both in production builds (where `select_jwks` calls
/// it) and under `cfg(test)` (where the fail-closed unit test calls it
/// directly), so the contract is verifiable without a separate prod-only build.
#[cfg(any(test, not(feature = "dev-fixtures")))]
fn production_pinned_jwks() -> Result<String, AttestationError> {
    if let Err(reason) = super::google_root::assert_play_integrity_root_is_production_ready() {
        return Err(AttestationError::PlayIntegrityInvalidToken(reason));
    }
    Ok(play_integrity_pinned_jwks_json())
}

fn claim_nonce(claims: &PlayIntegrityClaims) -> Result<&str, AttestationError> {
    match (&claims.nonce, &claims.request_details) {
        (Some(top_level), Some(details)) if top_level != &details.nonce => {
            Err(AttestationError::PlayIntegrityInvalidToken(
                "top-level nonce and requestDetails.nonce differ".to_string(),
            ))
        }
        (Some(top_level), _) => Ok(top_level.as_str()),
        (None, Some(details)) => Ok(details.nonce.as_str()),
        (None, None) => Err(AttestationError::PlayIntegrityInvalidToken(
            "token has no nonce".to_string(),
        )),
    }
}

fn jwk_algorithm(jwk: &Jwk) -> Result<Algorithm, AttestationError> {
    let algorithm = jwk.common.key_algorithm.ok_or_else(|| {
        AttestationError::PlayIntegrityInvalidToken("JWKS key has no alg".to_string())
    })?;
    if algorithm != KeyAlgorithm::ES256 {
        return Err(AttestationError::PlayIntegrityInvalidToken(format!(
            "unsupported Play Integrity JWKS signing alg {:?}; expected ES256",
            algorithm
        )));
    }
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(params) if params.curve == EllipticCurve::P256 => {
            Ok(Algorithm::ES256)
        }
        AlgorithmParameters::EllipticCurve(params) => {
            Err(AttestationError::PlayIntegrityInvalidToken(format!(
                "Play Integrity ES256 JWKS key must use P-256, got {:?}",
                params.curve
            )))
        }
        AlgorithmParameters::OctetKey(_) => Err(AttestationError::PlayIntegrityInvalidToken(
            "Play Integrity JWKS must not contain symmetric keys".to_string(),
        )),
        _ => Err(AttestationError::PlayIntegrityInvalidToken(
            "Play Integrity JWKS key must be an ES256 P-256 EC key".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_path_fails_closed_while_fixture_root_is_pinned() {
        // SECURITY / PLACEHOLDER (BAC-601): the production trust anchor must
        // REJECT (not silently trust the fixture signer) while the committed
        // synthetic fixture key is still pinned. The earlier guard was a
        // `debug_assert!` stripped from release builds, so this proves the
        // fail-closed behaviour holds in both debug and release. When the real
        // Google root is provisioned (kid rotated off the `*-fixture-root`
        // sentinel) this test needs updating, which is the intended forcing
        // function.
        assert!(
            super::super::google_root::play_integrity_root_is_placeholder(),
            "pinned root is still the committed fixture key"
        );
        let Err(error) = production_pinned_jwks() else {
            panic!("production path must reject while the fixture root is pinned");
        };
        match error {
            AttestationError::PlayIntegrityInvalidToken(reason) => {
                assert!(
                    reason.contains("BAC-601"),
                    "rejection must reference BAC-601: {reason}"
                );
            }
            other => panic!("expected PlayIntegrityInvalidToken, got {other:?}"),
        }
    }
}
