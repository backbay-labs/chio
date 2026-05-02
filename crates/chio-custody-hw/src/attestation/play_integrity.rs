//! Android Play Integrity verifier.

use jsonwebtoken::{decode, Algorithm, Validation};
use serde::{Deserialize, Serialize};

use super::errors::AttestationError;
use super::google_root::play_integrity_decoding_key;

pub const PLAY_RECOGNIZED: &str = "PLAY_RECOGNIZED";
pub const MEETS_DEVICE_INTEGRITY: &str = "MEETS_DEVICE_INTEGRITY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayIntegrityVerificationInput<'a> {
    pub token: &'a str,
    pub expected_nonce: &'a str,
    pub expected_package_name: &'a str,
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
    pub nonce: String,
    pub app_integrity: AppIntegrityClaims,
    pub device_integrity: DeviceIntegrityClaims,
    #[serde(default)]
    pub exp: Option<u64>,
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

pub fn verify_play_integrity(
    input: PlayIntegrityVerificationInput<'_>,
) -> Result<VerifiedPlayIntegrity, AttestationError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let token =
        decode::<PlayIntegrityClaims>(input.token, &play_integrity_decoding_key(), &validation)
            .map_err(|error| AttestationError::PlayIntegrityInvalidToken(error.to_string()))?;
    let claims = token.claims;

    if claims.nonce != input.expected_nonce {
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
        nonce: claims.nonce,
        app_recognition_verdict: claims.app_integrity.app_recognition_verdict,
        device_recognition_verdict: claims.device_integrity.device_recognition_verdict,
    })
}
