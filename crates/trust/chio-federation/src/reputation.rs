use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::artifacts::FederationArtifactReference;
use crate::error::FederationContractError;
use crate::listing::GenericTrustAdmissionClass;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::validation::{
    ensure_non_empty, ensure_unique_strings, validate_reputation_clearing_continuity,
    validate_reputation_input_reference, validate_sybil_control,
};

pub const CHIO_FEDERATION_REPUTATION_CLEARING_SCHEMA: &str =
    "chio.federation-reputation-clearing.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederatedReputationInputKind {
    ReputationSummary,
    NegativeEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedReputationInputReference {
    pub kind: FederatedReputationInputKind,
    pub artifact_ref: FederationArtifactReference,
    pub subject_key: String,
    pub issuer_operator_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_independence_group_id: Option<String>,
    pub weight_bps: u32,
    pub blocking: bool,
    pub published_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedSybilControl {
    pub minimum_independent_issuers: u32,
    pub maximum_inputs_per_issuer: u32,
    pub oracle_cap_bps: u32,
    pub local_weighting_required: bool,
    pub negative_event_corroboration_required: bool,
}

impl Default for FederatedSybilControl {
    fn default() -> Self {
        Self {
            minimum_independent_issuers: 2,
            maximum_inputs_per_issuer: 2,
            oracle_cap_bps: 4_000,
            local_weighting_required: true,
            negative_event_corroboration_required: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedReputationClearingContinuity {
    pub continuity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_clearing_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedReputationClearingArtifact {
    pub schema: String,
    pub clearing_id: String,
    pub generated_at: u64,
    pub subject_key: String,
    pub namespace: String,
    pub participating_operator_ids: Vec<String>,
    pub local_weighting_policy_ref: String,
    pub admission_policy_ref: String,
    pub inputs: Vec<FederatedReputationInputReference>,
    pub sybil_control: FederatedSybilControl,
    pub accepted_input_ids: Vec<String>,
    pub rejected_input_ids: Vec<String>,
    pub effective_admission_class: GenericTrustAdmissionClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuity: Option<FederatedReputationClearingContinuity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederatedReputationClearing =
    SignedExportEnvelope<FederatedReputationClearingArtifact>;

pub fn validate_federated_reputation_clearing(
    clearing: &FederatedReputationClearingArtifact,
) -> Result<(), FederationContractError> {
    if clearing.schema != CHIO_FEDERATION_REPUTATION_CLEARING_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            clearing.schema.clone(),
        ));
    }
    ensure_non_empty(&clearing.clearing_id, "federated_clearing.clearing_id")?;
    ensure_non_empty(&clearing.subject_key, "federated_clearing.subject_key")?;
    ensure_non_empty(&clearing.namespace, "federated_clearing.namespace")?;
    ensure_non_empty(
        &clearing.local_weighting_policy_ref,
        "federated_clearing.local_weighting_policy_ref",
    )?;
    ensure_non_empty(
        &clearing.admission_policy_ref,
        "federated_clearing.admission_policy_ref",
    )?;
    if clearing.participating_operator_ids.is_empty() {
        return Err(FederationContractError::MissingField(
            "federated_clearing.participating_operator_ids",
        ));
    }
    ensure_unique_strings(
        &clearing.participating_operator_ids,
        "federated_clearing.participating_operator_ids",
    )?;
    validate_sybil_control(&clearing.sybil_control)?;
    if let Some(continuity) = clearing.continuity.as_ref() {
        validate_reputation_clearing_continuity(continuity, &clearing.clearing_id)?;
    }
    if clearing.inputs.is_empty() {
        return Err(FederationContractError::MissingField(
            "federated_clearing.inputs",
        ));
    }

    let participating_operators = clearing
        .participating_operator_ids
        .iter()
        .map(String::as_str)
        .collect::<HashSet<_>>();
    let mut input_ids = HashSet::new();
    let mut accepted_ids = HashSet::new();
    let mut rejected_ids = HashSet::new();
    let mut issuer_counts = std::collections::BTreeMap::<String, u32>::new();
    let mut accepted_summary_issuers = HashSet::new();
    let mut accepted_independence_groups = HashSet::new();
    let mut accepted_negative_event_groups = HashSet::new();

    for id in &clearing.accepted_input_ids {
        ensure_non_empty(id, "federated_clearing.accepted_input_ids")?;
        if !accepted_ids.insert(id.as_str()) {
            return Err(FederationContractError::DuplicateValue(id.clone()));
        }
    }
    for id in &clearing.rejected_input_ids {
        ensure_non_empty(id, "federated_clearing.rejected_input_ids")?;
        if !rejected_ids.insert(id.as_str()) {
            return Err(FederationContractError::DuplicateValue(id.clone()));
        }
    }
    if accepted_ids.iter().any(|id| rejected_ids.contains(id)) {
        return Err(FederationContractError::InvalidClearing(
            "an input cannot be both accepted and rejected".to_string(),
        ));
    }

    for input in &clearing.inputs {
        validate_reputation_input_reference(input, clearing.generated_at, &clearing.subject_key)?;
        if input.artifact_ref.operator_id != input.issuer_operator_id {
            return Err(FederationContractError::InvalidClearing(
                "input artifact_ref operator_id must match issuer_operator_id".to_string(),
            ));
        }
        if !participating_operators.contains(input.issuer_operator_id.as_str()) {
            return Err(FederationContractError::InvalidClearing(
                "input issuer_operator_id must appear in participating_operator_ids".to_string(),
            ));
        }
        let input_id = input.artifact_ref.artifact_id.as_str();
        if !input_ids.insert(input_id) {
            return Err(FederationContractError::DuplicateValue(
                input.artifact_ref.artifact_id.clone(),
            ));
        }
        *issuer_counts
            .entry(input.issuer_operator_id.clone())
            .or_insert(0) += 1;
        if issuer_counts[&input.issuer_operator_id]
            > clearing.sybil_control.maximum_inputs_per_issuer
        {
            return Err(FederationContractError::InvalidClearing(
                "issuer exceeds maximum_inputs_per_issuer".to_string(),
            ));
        }
        if input.weight_bps > clearing.sybil_control.oracle_cap_bps {
            return Err(FederationContractError::InvalidClearing(
                "input weight_bps exceeds oracle_cap_bps".to_string(),
            ));
        }
        if accepted_ids.contains(input_id) {
            let independence_group = input
                .issuer_independence_group_id
                .as_deref()
                .unwrap_or(input.issuer_operator_id.as_str());
            accepted_independence_groups.insert(independence_group);
            match input.kind {
                FederatedReputationInputKind::ReputationSummary => {
                    if !accepted_summary_issuers.insert(input.issuer_operator_id.as_str()) {
                        return Err(FederationContractError::InvalidClearing(
                            "accepted reputation summaries must come from distinct issuers"
                                .to_string(),
                        ));
                    }
                }
                FederatedReputationInputKind::NegativeEvent => {
                    if input.blocking {
                        accepted_negative_event_groups.insert(independence_group);
                    }
                }
            }
        }
    }

    if input_ids.len() != clearing.accepted_input_ids.len() + clearing.rejected_input_ids.len() {
        return Err(FederationContractError::InvalidClearing(
            "each input must be classified as accepted or rejected".to_string(),
        ));
    }
    if !clearing.accepted_input_ids.is_empty()
        && accepted_independence_groups.len()
            < clearing.sybil_control.minimum_independent_issuers as usize
    {
        return Err(FederationContractError::InvalidClearing(
            "accepted inputs must meet the minimum_independent_issuers threshold".to_string(),
        ));
    }
    if clearing.sybil_control.negative_event_corroboration_required
        && accepted_negative_event_groups.len() == 1
    {
        return Err(FederationContractError::InvalidClearing(
            "blocking negative events require corroboration from independent issuers".to_string(),
        ));
    }
    if clearing.effective_admission_class != GenericTrustAdmissionClass::PublicUntrusted
        && clearing.accepted_input_ids.is_empty()
    {
        return Err(FederationContractError::InvalidClearing(
            "non-public admission classes require accepted inputs".to_string(),
        ));
    }

    Ok(())
}
