use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::sha256_hex;
use serde::{Deserialize, Serialize};

use crate::error::ChioPackageError;
use crate::validation::{canonical_sha256, lowercase_hex, validate_context_field};

pub const VERIFICATION_CONTEXT_SCHEMA: &str = "chio.federation.verification-context.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChioVerificationContext {
    pub schema: String,
    pub audience: String,
    pub challenge: String,
    pub proof_purpose: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerificationContextNoncePreimage<'a> {
    schema: &'a str,
    audience: &'a str,
    challenge: &'a str,
    proof_purpose: &'a str,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

impl ChioVerificationContext {
    pub fn validate(&self) -> Result<(), ChioPackageError> {
        if self.schema != VERIFICATION_CONTEXT_SCHEMA {
            return Err(ChioPackageError::VerificationContext(format!(
                "verification context schema {} is unsupported",
                self.schema
            )));
        }
        validate_context_field(&self.audience, "verificationContext.audience")?;
        validate_context_field(&self.challenge, "verificationContext.challenge")?;
        validate_context_field(&self.proof_purpose, "verificationContext.proofPurpose")?;
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(ChioPackageError::VerificationContext(
                "verification context expiry must be greater than issue time".to_string(),
            ));
        }
        Ok(())
    }

    fn nonce_preimage(&self) -> VerificationContextNoncePreimage<'_> {
        VerificationContextNoncePreimage {
            schema: &self.schema,
            audience: &self.audience,
            challenge: &self.challenge,
            proof_purpose: &self.proof_purpose,
            issued_at_unix_ms: self.issued_at_unix_ms,
            expires_at_unix_ms: self.expires_at_unix_ms,
        }
    }

    pub fn expected_bbs_proof_nonce(&self) -> Result<Vec<u8>, ChioPackageError> {
        self.validate()?;
        let bytes = canonical_json_bytes(&self.nonce_preimage())
            .map_err(|error| ChioPackageError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&bytes).into_bytes())
    }

    pub fn expected_bbs_proof_nonce_hex(&self) -> Result<String, ChioPackageError> {
        Ok(lowercase_hex(&self.expected_bbs_proof_nonce()?))
    }
}

pub fn verification_context_from_json(
    json: &str,
) -> Result<ChioVerificationContext, ChioPackageError> {
    let context: ChioVerificationContext =
        serde_json::from_str(json).map_err(|error| ChioPackageError::Json(error.to_string()))?;
    context.validate()?;
    Ok(context)
}

pub fn verification_context_json(
    context: &ChioVerificationContext,
) -> Result<String, ChioPackageError> {
    serde_json::to_string_pretty(context).map_err(|error| ChioPackageError::Json(error.to_string()))
}

pub fn verification_context_sha256(
    context: &ChioVerificationContext,
) -> Result<String, ChioPackageError> {
    canonical_sha256(context)
}
