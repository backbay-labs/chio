use serde::{Deserialize, Serialize};

use crate::crypto::{PublicKey, Signature};
use crate::error::Web3ContractError;
use crate::validation::{ensure_non_empty, ensure_unique_copy_values, ensure_unique_strings};

pub const CHIO_KEY_BINDING_CERTIFICATE_SCHEMA: &str = "chio.key-binding-certificate.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3KeyBindingPurpose {
    Anchor,
    Settle,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3IdentityBindingCertificate {
    pub schema: String,
    pub chio_identity: String,
    pub chio_public_key: PublicKey,
    pub chain_scope: Vec<String>,
    pub purpose: Vec<Web3KeyBindingPurpose>,
    pub settlement_address: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedWeb3IdentityBinding {
    pub certificate: Web3IdentityBindingCertificate,
    pub signature: Signature,
}

pub fn validate_web3_identity_binding(
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), Web3ContractError> {
    if binding.certificate.schema != CHIO_KEY_BINDING_CERTIFICATE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(
            binding.certificate.schema.clone(),
        ));
    }
    ensure_non_empty(&binding.certificate.chio_identity, "binding.chio_identity")?;
    ensure_non_empty(
        &binding.certificate.settlement_address,
        "binding.settlement_address",
    )?;
    ensure_non_empty(&binding.certificate.nonce, "binding.nonce")?;
    if binding.certificate.chain_scope.is_empty() {
        return Err(Web3ContractError::MissingField("binding.chain_scope"));
    }
    if binding.certificate.purpose.is_empty() {
        return Err(Web3ContractError::MissingField("binding.purpose"));
    }
    ensure_unique_strings(&binding.certificate.chain_scope, "binding.chain_scope")?;
    ensure_unique_copy_values(&binding.certificate.purpose, "binding.purpose")?;
    if binding.certificate.issued_at >= binding.certificate.expires_at {
        return Err(Web3ContractError::InvalidBinding(
            "identity binding issued_at must be earlier than expires_at".to_string(),
        ));
    }
    Ok(())
}

pub fn verify_web3_identity_binding(
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), Web3ContractError> {
    validate_web3_identity_binding(binding)?;
    let verified = binding
        .certificate
        .chio_public_key
        .verify_canonical(&binding.certificate, &binding.signature)
        .map_err(|error| Web3ContractError::InvalidBinding(error.to_string()))?;
    if !verified {
        return Err(Web3ContractError::InvalidBinding(
            "identity binding signature verification failed".to_string(),
        ));
    }
    Ok(())
}
