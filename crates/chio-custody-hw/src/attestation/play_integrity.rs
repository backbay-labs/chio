//! Android Play Integrity verifier.
//!
//! # Trust contract
//!
//! The verifier takes the current Google JWKS document from the caller,
//! selects the JWK by token `kid`, validates the JWS under ES256/P-256
//! key material, and then enforces the Play Integrity
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
use super::google_root::GOOGLE_PLAY_INTEGRITY_ISSUER;

pub const PLAY_RECOGNIZED: &str = "PLAY_RECOGNIZED";
pub const MEETS_DEVICE_INTEGRITY: &str = "MEETS_DEVICE_INTEGRITY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayIntegrityVerificationInput<'a> {
    pub token: &'a str,
    pub expected_nonce: &'a str,
    pub expected_package_name: &'a str,
    pub expected_audience: &'a str,
    pub jwks_json: &'a str,
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
    let jwks: JwkSet = serde_json::from_str(input.jwks_json)
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
