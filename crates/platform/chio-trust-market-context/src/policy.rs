use serde::Deserialize;

use chio_core_types::PublicKey;
use chio_transaction_passport::{TransactionPassportError, TRANSACTION_VERIFIER_POLICY_SCHEMA_ID};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustMarketVerifierPolicy {
    schema: String,
    id: String,
    issued_at: String,
    pub(super) required_claims: Vec<String>,
    omitted_claims: Vec<String>,
    pub(super) unsupported_claims: Vec<String>,
    pub(super) max_reputation_import_weight: u64,
    #[serde(default)]
    pub(super) trusted_market_authority_keys: Vec<PublicKey>,
}

pub(super) fn parse_policy(
    bytes: &[u8],
) -> Result<TrustMarketVerifierPolicy, TransactionPassportError> {
    let policy: TrustMarketVerifierPolicy = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
    })?;
    if policy.schema != TRANSACTION_VERIFIER_POLICY_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedVerifierPolicySchema(
            policy.schema,
        ));
    }
    require_non_empty(&policy.id, "verifier policy id")?;
    require_non_empty(&policy.issued_at, "verifier policy issued_at")?;
    for claim in &policy.required_claims {
        require_non_empty(claim, "required_claims")?;
    }
    for claim in &policy.unsupported_claims {
        require_non_empty(claim, "unsupported_claims")?;
    }
    if policy.max_reputation_import_weight > 100 {
        return Err(claim_failed(
            "max reputation import weight must not exceed 100",
        ));
    }
    if policy.trusted_market_authority_keys.is_empty() {
        return Err(claim_failed("trusted market authority keys missing"));
    }
    let _ = &policy.omitted_claims;
    Ok(policy)
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(claim_failed(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::TrustMarketClaimFailed(message.into())
}
