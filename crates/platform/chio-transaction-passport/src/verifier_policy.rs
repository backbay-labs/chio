use std::collections::BTreeSet;

use serde::Deserialize;

use super::error::TransactionPassportError;
use super::ids::TRANSACTION_VERIFIER_POLICY_SCHEMA_ID;
use super::validation::require_non_empty;

const STANDALONE_TRANSACTION_REQUIRED_CLAIMS: &[&str] = &[
    "claim.transaction.passport_root_verified",
    "claim.transaction.evidence_graph_digest_bound",
    "claim.transaction.evidence_graph_structure_verified",
    "claim.transaction.claim_set_digest_bound",
    "claim.transaction.policy_digest_bound",
    "claim.transaction.omission_policy_bound",
];

const TRANSPARENCY_STATES: &[&str] = &["trust_anchored", "transparency_preview", "not_present"];

const COMMERCE_STATE_CLAIMS: &[(&str, &str)] = &[
    ("authorized", "claim.commerce.order_replay_consistent"),
    ("fulfilled", "claim.commerce.order_replay_consistent"),
    ("settled", "claim.commerce.settlement_lifecycle_bound"),
    ("disputed", "claim.commerce.settlement_lifecycle_bound"),
    ("refunded", "claim.commerce.payment_lifecycle_bound"),
];
const COMMERCE_STATES: &[&str] = &["authorized", "fulfilled", "settled", "disputed", "refunded"];

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
    #[serde(default)]
    trusted_market_authority_keys: Vec<String>,
    #[serde(default)]
    accepted_passport_issuers: Vec<String>,
    #[serde(default)]
    required_evidence_roles: Vec<String>,
    #[serde(default)]
    accepted_transparency_states: Vec<String>,
    #[serde(default)]
    required_commerce_states: Vec<String>,
}

impl TransactionVerifierPolicy {
    pub(super) fn omitted_claims(&self) -> &[String] {
        &self.omitted_claims
    }

    pub(super) fn accepted_passport_issuers(&self) -> &[String] {
        &self.accepted_passport_issuers
    }

    pub(super) fn required_evidence_roles(&self) -> &[String] {
        &self.required_evidence_roles
    }

    pub(super) fn accepted_transparency_states(&self) -> &[String] {
        &self.accepted_transparency_states
    }

    pub(super) fn effective_required_claims(&self) -> Vec<String> {
        let mut claims = self.required_claims.clone();
        let mut seen = claims.iter().cloned().collect::<BTreeSet<_>>();
        for state in &self.required_commerce_states {
            if let Some((_, claim)) = COMMERCE_STATE_CLAIMS
                .iter()
                .find(|(candidate, _)| *candidate == state.as_str())
            {
                if seen.insert((*claim).to_string()) {
                    claims.push((*claim).to_string());
                }
            }
        }
        claims
    }
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
    validate_claim_list(
        &policy.trusted_market_authority_keys,
        "trusted_market_authority_keys",
    )?;
    validate_string_list(
        &policy.accepted_passport_issuers,
        "accepted_passport_issuers",
    )?;
    validate_string_list(&policy.required_evidence_roles, "required_evidence_roles")?;
    validate_enum_list(
        &policy.accepted_transparency_states,
        "accepted_transparency_states",
        TRANSPARENCY_STATES,
    )?;
    validate_enum_list(
        &policy.required_commerce_states,
        "required_commerce_states",
        COMMERCE_STATES,
    )?;
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
        if !STANDALONE_TRANSACTION_REQUIRED_CLAIMS.contains(&claim.as_str()) {
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
    validate_string_list(claims, field)
}

fn validate_string_list(
    values: &[String],
    field: &'static str,
) -> Result<(), TransactionPassportError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, field).map_err(|error| {
            TransactionPassportError::InvalidVerifierPolicyArtifact(error.to_string())
        })?;
        if !seen.insert(value) {
            return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
                format!("duplicate verifier policy value in {field}: {value}"),
            ));
        }
    }
    Ok(())
}

fn validate_enum_list(
    values: &[String],
    field: &'static str,
    allowed: &[&str],
) -> Result<(), TransactionPassportError> {
    validate_string_list(values, field)?;
    for value in values {
        if !allowed.contains(&value.as_str()) {
            return Err(TransactionPassportError::InvalidVerifierPolicyArtifact(
                format!("unsupported verifier policy value in {field}: {value}"),
            ));
        }
    }
    Ok(())
}
