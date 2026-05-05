//! Android Play Integrity verifier.
//!
//! # Trust contract
//!
//! The fixture verifier shipped here validates a JWS-shaped envelope against
//! a pinned symmetric key in [`super::google_root`]. Real production
//! deployments MUST swap the decoding key for Google's JWKS before this is
//! reachable from the FFI; the surface returns
//! [`AttestationError::PlayIntegrityInvalidToken`] on every parse failure so
//! the fail-closed path is identical regardless of which key is wired.
//!
//! Even with the fixture key, the verifier enforces:
//!
//! - `exp` claim, when present, must be in the future. A token whose `exp`
//!   has elapsed is rejected fail-closed; this keeps the fixture path from
//!   silently accepting a stale token replayed past the issuer's retention
//!   window.
//! - Server-supplied `nonce` must match `expected_nonce` byte-for-byte.
//! - `app_integrity.package_name` must match `expected_package_name`.
//! - `app_integrity.app_recognition_verdict` must equal [`PLAY_RECOGNIZED`].
//! - `device_integrity.device_recognition_verdict` must contain
//!   [`MEETS_DEVICE_INTEGRITY`].

use std::time::{SystemTime, UNIX_EPOCH};

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
    // `jsonwebtoken`'s built-in `exp` validator requires the claim to be
    // present and rejects future-skewed tokens with a non-stable error
    // shape. We do the check by hand against a fail-closed clock so the
    // rejection URN stays
    // `urn:chio:error:custody:play-integrity-invalid-token` for both
    // signature failures and stale tokens, and so the verifier still
    // accepts fixture tokens whose claim set omits `exp`.
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let token =
        decode::<PlayIntegrityClaims>(input.token, &play_integrity_decoding_key(), &validation)
            .map_err(|error| AttestationError::PlayIntegrityInvalidToken(error.to_string()))?;
    let claims = token.claims;

    if let Some(exp) = claims.exp {
        let now = current_unix_seconds()?;
        if exp < now {
            return Err(AttestationError::PlayIntegrityInvalidToken(format!(
                "token exp {exp} is before now {now}"
            )));
        }
    }

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

/// Resolve the current Unix time in seconds for the `exp` check.
///
/// Failure to read the system clock surfaces as
/// `PlayIntegrityInvalidToken` rather than a silently-accepted token; a
/// system clock that pre-dates the Unix epoch is fail-closed.
fn current_unix_seconds() -> Result<u64, AttestationError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| {
            AttestationError::PlayIntegrityInvalidToken(format!("system clock pre-1970: {err}"))
        })?;
    Ok(elapsed.as_secs())
}
