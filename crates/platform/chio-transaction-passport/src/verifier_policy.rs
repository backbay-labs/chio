use std::collections::BTreeSet;

use serde::Deserialize;

use super::error::TransactionPassportError;
use super::ids::TRANSACTION_VERIFIER_POLICY_SCHEMA_ID;
use super::validation::require_non_empty;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionVerifierPolicy {
    schema: String,
    id: String,
    issued_at: String,
    required_claims: Vec<String>,
    omitted_claims: Vec<String>,
    #[serde(default)]
    unsupported_claims: Vec<String>,
    #[serde(default)]
    max_reputation_import_weight: Option<u64>,
}

pub(super) fn validate_verifier_policy(
    policy: &TransactionVerifierPolicy,
) -> Result<(), TransactionPassportError> {
    if policy.schema != TRANSACTION_VERIFIER_POLICY_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedVerifierPolicySchema(
            policy.schema.clone(),
        ));
    }
    require_non_empty(&policy.id, "verifier policy id").map_err(|error| {
        TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
    })?;
    require_non_empty(&policy.issued_at, "verifier policy issued_at").map_err(|error| {
        TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
    })?;
    validate_claim_list(&policy.required_claims, "required_claims")?;
    validate_claim_list(&policy.omitted_claims, "omitted_claims")?;
    validate_claim_list(&policy.unsupported_claims, "unsupported_claims")?;
    if policy
        .max_reputation_import_weight
        .is_some_and(|weight| weight > 100)
    {
        return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
            "max reputation import weight must not exceed 100".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_verifier_policy_artifact(
    verifier_policy_bytes: &[u8],
) -> Result<(), TransactionPassportError> {
    let verifier_policy: TransactionVerifierPolicy = serde_json::from_slice(verifier_policy_bytes)
        .map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
    validate_verifier_policy(&verifier_policy)
}

pub(super) fn validate_standalone_transaction_claims(
    policy: &TransactionVerifierPolicy,
) -> Result<(), TransactionPassportError> {
    for claim in &policy.required_claims {
        if !claim.starts_with("claim.transaction.") {
            return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
                format!("standalone transaction verifier cannot satisfy required claim: {claim}"),
            ));
        }
    }
    Ok(())
}

fn validate_claim_list(
    claims: &[String],
    field: &'static str,
) -> Result<(), TransactionPassportError> {
    let mut seen = BTreeSet::new();
    for claim in claims {
        require_non_empty(claim, field).map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
        if !seen.insert(claim) {
            return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
                format!("duplicate verifier policy claim in {field}: {claim}"),
            ));
        }
    }
    Ok(())
}
