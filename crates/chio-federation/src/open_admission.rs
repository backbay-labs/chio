use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::artifacts::{FederationArtifactKind, FederationArtifactReference};
use crate::capability::scope::MonetaryAmount;
use crate::error::FederationContractError;
use crate::listing::GenericTrustAdmissionClass;
use crate::open_market::fee_schedule::OpenMarketBondClass;
use crate::receipt::lineage::SignedExportEnvelope;
use crate::validation::{
    ensure_non_empty, ensure_unique_copy_values, validate_federation_artifact_reference,
    validate_stake_requirement,
};

pub const CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA: &str =
    "chio.federation-open-admission-policy.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedStakeRequirement {
    pub admission_class: GenericTrustAdmissionClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_bond_class: Option<OpenMarketBondClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_bond_amount: Option<MonetaryAmount>,
    pub slashable: bool,
    pub governance_case_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederatedOpenAdmissionPolicyArtifact {
    pub schema: String,
    pub policy_id: String,
    pub issued_at: u64,
    pub namespace: String,
    pub governing_operator_id: String,
    pub allowed_admission_classes: Vec<GenericTrustAdmissionClass>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stake_requirements: Vec<FederatedStakeRequirement>,
    pub governing_charter_ref: FederationArtifactReference,
    pub fee_schedule_ref: FederationArtifactReference,
    pub explicit_local_review_required: bool,
    pub visibility_only_without_activation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub type SignedFederatedOpenAdmissionPolicy =
    SignedExportEnvelope<FederatedOpenAdmissionPolicyArtifact>;

pub fn validate_federated_open_admission_policy(
    policy: &FederatedOpenAdmissionPolicyArtifact,
) -> Result<(), FederationContractError> {
    if policy.schema != CHIO_FEDERATION_OPEN_ADMISSION_POLICY_SCHEMA {
        return Err(FederationContractError::UnsupportedSchema(
            policy.schema.clone(),
        ));
    }
    ensure_non_empty(&policy.policy_id, "federated_admission.policy_id")?;
    ensure_non_empty(&policy.namespace, "federated_admission.namespace")?;
    ensure_non_empty(
        &policy.governing_operator_id,
        "federated_admission.governing_operator_id",
    )?;
    if policy.allowed_admission_classes.is_empty() {
        return Err(FederationContractError::MissingField(
            "federated_admission.allowed_admission_classes",
        ));
    }
    ensure_unique_copy_values(
        &policy.allowed_admission_classes,
        "federated_admission.allowed_admission_classes",
    )?;
    validate_federation_artifact_reference(
        &policy.governing_charter_ref,
        "federated_admission.governing_charter_ref",
    )?;
    if policy.governing_charter_ref.kind != FederationArtifactKind::GovernanceCharter {
        return Err(FederationContractError::InvalidAdmission(
            "governing_charter_ref must reference a governance charter".to_string(),
        ));
    }
    validate_federation_artifact_reference(
        &policy.fee_schedule_ref,
        "federated_admission.fee_schedule_ref",
    )?;
    if policy.fee_schedule_ref.kind != FederationArtifactKind::OpenMarketFeeSchedule {
        return Err(FederationContractError::InvalidAdmission(
            "fee_schedule_ref must reference an open-market fee schedule".to_string(),
        ));
    }
    if !policy.explicit_local_review_required {
        return Err(FederationContractError::InvalidAdmission(
            "open admission must still require explicit local review".to_string(),
        ));
    }
    if !policy.visibility_only_without_activation {
        return Err(FederationContractError::InvalidAdmission(
            "open admission must remain visibility-only without activation".to_string(),
        ));
    }

    let mut requirement_classes = HashSet::new();
    for requirement in &policy.stake_requirements {
        validate_stake_requirement(requirement)?;
        if !policy
            .allowed_admission_classes
            .contains(&requirement.admission_class)
        {
            return Err(FederationContractError::InvalidAdmission(
                "stake requirement admission_class must be allowed by the policy".to_string(),
            ));
        }
        if !requirement_classes.insert(requirement.admission_class) {
            return Err(FederationContractError::DuplicateValue(format!(
                "{:?}",
                requirement.admission_class
            )));
        }
    }

    if policy
        .allowed_admission_classes
        .contains(&GenericTrustAdmissionClass::BondBacked)
        && !requirement_classes.contains(&GenericTrustAdmissionClass::BondBacked)
    {
        return Err(FederationContractError::InvalidAdmission(
            "bond_backed admission requires an explicit stake requirement".to_string(),
        ));
    }

    Ok(())
}
