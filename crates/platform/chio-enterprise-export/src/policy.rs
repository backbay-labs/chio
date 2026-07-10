use serde::Deserialize;

use chio_transaction_passport::{TransactionPassportError, TRANSACTION_VERIFIER_POLICY_SCHEMA_ID};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnterpriseVerifierPolicy {
    schema: String,
    id: String,
    issued_at: String,
    pub(super) required_claims: Vec<String>,
    omitted_claims: Vec<String>,
}

pub(super) fn parse_policy(
    bytes: &[u8],
) -> Result<EnterpriseVerifierPolicy, TransactionPassportError> {
    let policy: EnterpriseVerifierPolicy = serde_json::from_slice(bytes).map_err(|error| {
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
    let _ = &policy.omitted_claims;
    Ok(policy)
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(TransactionPassportError::EnterpriseExportClaimFailed(
            format!("{field} must not be empty"),
        ))
    } else {
        Ok(())
    }
}
