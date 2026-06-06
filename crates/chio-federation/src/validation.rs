use std::collections::HashSet;

use crate::artifacts::{
    FederationArtifactKind, FederationArtifactReference, FederationDelegationControl,
    FederationImportControl, FederationTrustScope,
};
use crate::capability::scope::MonetaryAmount;
use crate::error::FederationContractError;
use crate::listing::GenericTrustAdmissionClass;
use crate::open_admission::FederatedStakeRequirement;
use crate::quorum::FederationAntiEclipsePolicy;
use crate::reputation::{
    FederatedReputationClearingContinuity, FederatedReputationInputKind,
    FederatedReputationInputReference, FederatedSybilControl,
};

pub(crate) fn validate_federation_artifact_reference(
    reference: &FederationArtifactReference,
    field: &'static str,
) -> Result<(), FederationContractError> {
    ensure_non_empty(&reference.schema, field)?;
    ensure_non_empty(&reference.artifact_id, field)?;
    ensure_non_empty(&reference.operator_id, field)?;
    validate_hex_digest(&reference.sha256, field)
}

pub(crate) fn validate_federation_scope(
    scope: &FederationTrustScope,
) -> Result<(), FederationContractError> {
    ensure_non_empty(&scope.namespace, "federation_scope.namespace")?;
    ensure_non_empty(
        &scope.subject_operator_id,
        "federation_scope.subject_operator_id",
    )?;
    if scope.allowed_actor_kinds.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_scope.allowed_actor_kinds",
        ));
    }
    if scope.allowed_admission_classes.is_empty() {
        return Err(FederationContractError::MissingField(
            "federation_scope.allowed_admission_classes",
        ));
    }
    ensure_unique_copy_values(
        &scope.allowed_actor_kinds,
        "federation_scope.allowed_actor_kinds",
    )?;
    ensure_unique_copy_values(
        &scope.allowed_admission_classes,
        "federation_scope.allowed_admission_classes",
    )?;
    if let Some(policy_reference) = scope.policy_reference.as_deref() {
        ensure_non_empty(policy_reference, "federation_scope.policy_reference")?;
    }
    Ok(())
}

pub(crate) fn validate_delegation_control(
    control: &FederationDelegationControl,
) -> Result<(), FederationContractError> {
    ensure_non_empty(
        &control.delegator_operator_id,
        "federation_delegation.delegator_operator_id",
    )?;
    ensure_non_empty(
        &control.delegate_operator_id,
        "federation_delegation.delegate_operator_id",
    )?;
    if control.delegator_operator_id == control.delegate_operator_id {
        return Err(FederationContractError::InvalidExchange(
            "delegator and delegate operators must differ".to_string(),
        ));
    }
    if control.max_hops == 0 {
        return Err(FederationContractError::InvalidExchange(
            "delegation max_hops must be non-zero".to_string(),
        ));
    }
    if !control.attenuation_required {
        return Err(FederationContractError::InvalidExchange(
            "federation delegation must require attenuation".to_string(),
        ));
    }
    if !control.visibility_only_until_local_activation {
        return Err(FederationContractError::InvalidExchange(
            "federation delegation must remain visibility-only until local activation".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_import_control(
    control: &FederationImportControl,
) -> Result<(), FederationContractError> {
    if !control.explicit_local_activation_required {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must require explicit local activation".to_string(),
        ));
    }
    if !control.manual_review_required {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must require manual review".to_string(),
        ));
    }
    if !control.reject_stale_inputs {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must reject stale inputs".to_string(),
        ));
    }
    if !control.allow_visibility_without_runtime_trust {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must preserve visibility without runtime trust".to_string(),
        ));
    }
    if !control.prohibit_ambient_runtime_admission {
        return Err(FederationContractError::InvalidExchange(
            "federation imports must prohibit ambient runtime admission".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_anti_eclipse_policy(
    policy: &FederationAntiEclipsePolicy,
) -> Result<(), FederationContractError> {
    if policy.minimum_distinct_operators == 0 {
        return Err(FederationContractError::InvalidQuorum(
            "minimum_distinct_operators must be non-zero".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_stake_requirement(
    requirement: &FederatedStakeRequirement,
) -> Result<(), FederationContractError> {
    match requirement.admission_class {
        GenericTrustAdmissionClass::PublicUntrusted | GenericTrustAdmissionClass::Reviewable => {
            if requirement.required_bond_class.is_some()
                || requirement.minimum_bond_amount.is_some()
            {
                return Err(FederationContractError::InvalidAdmission(
                    "public_untrusted and reviewable admission cannot require bond collateral"
                        .to_string(),
                ));
            }
        }
        GenericTrustAdmissionClass::BondBacked => {
            let amount = requirement.minimum_bond_amount.as_ref().ok_or_else(|| {
                FederationContractError::InvalidAdmission(
                    "bond_backed admission requires minimum_bond_amount".to_string(),
                )
            })?;
            if requirement.required_bond_class.is_none() {
                return Err(FederationContractError::InvalidAdmission(
                    "bond_backed admission requires required_bond_class".to_string(),
                ));
            }
            if !requirement.slashable {
                return Err(FederationContractError::InvalidAdmission(
                    "bond_backed admission requires slashable collateral".to_string(),
                ));
            }
            validate_positive_money(amount, "federated_admission.minimum_bond_amount")?;
        }
        GenericTrustAdmissionClass::RoleGated => {
            if !requirement.governance_case_required {
                return Err(FederationContractError::InvalidAdmission(
                    "role_gated admission requires governance_case_required".to_string(),
                ));
            }
            if requirement.required_bond_class.is_some()
                || requirement.minimum_bond_amount.is_some()
            {
                return Err(FederationContractError::InvalidAdmission(
                    "role_gated admission should not infer a bond requirement".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_reputation_input_reference(
    input: &FederatedReputationInputReference,
    generated_at: u64,
    subject_key: &str,
) -> Result<(), FederationContractError> {
    validate_federation_artifact_reference(&input.artifact_ref, "federated_clearing.inputs")?;
    ensure_non_empty(&input.subject_key, "federated_clearing.inputs.subject_key")?;
    ensure_non_empty(
        &input.issuer_operator_id,
        "federated_clearing.inputs.issuer_operator_id",
    )?;
    if let Some(group_id) = input.issuer_independence_group_id.as_deref() {
        ensure_non_empty(
            group_id,
            "federated_clearing.inputs.issuer_independence_group_id",
        )?;
    }
    if input.subject_key != subject_key {
        return Err(FederationContractError::InvalidClearing(
            "reputation clearing inputs must target the same subject_key".to_string(),
        ));
    }
    if input.weight_bps == 0 || input.weight_bps > 10_000 {
        return Err(FederationContractError::InvalidClearing(
            "reputation clearing weight_bps must be between 1 and 10000".to_string(),
        ));
    }
    if input.published_at > generated_at {
        return Err(FederationContractError::InvalidClearing(
            "reputation clearing inputs cannot be published in the future".to_string(),
        ));
    }
    if let Some(expires_at) = input.expires_at {
        if expires_at <= input.published_at {
            return Err(FederationContractError::InvalidClearing(
                "reputation clearing input expires_at must be greater than published_at"
                    .to_string(),
            ));
        }
        if expires_at <= generated_at {
            return Err(FederationContractError::InvalidClearing(
                "reputation clearing inputs cannot be expired at generated_at".to_string(),
            ));
        }
    }
    match input.kind {
        FederatedReputationInputKind::ReputationSummary => {
            if input.blocking {
                return Err(FederationContractError::InvalidClearing(
                    "reputation summaries cannot be marked blocking".to_string(),
                ));
            }
            if input.artifact_ref.kind != FederationArtifactKind::PortableReputationSummary {
                return Err(FederationContractError::InvalidClearing(
                    "reputation summary inputs must reference portable reputation summaries"
                        .to_string(),
                ));
            }
        }
        FederatedReputationInputKind::NegativeEvent => {
            if input.artifact_ref.kind != FederationArtifactKind::PortableNegativeEvent {
                return Err(FederationContractError::InvalidClearing(
                    "negative event inputs must reference portable negative events".to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_reputation_clearing_continuity(
    continuity: &FederatedReputationClearingContinuity,
    clearing_id: &str,
) -> Result<(), FederationContractError> {
    ensure_non_empty(
        &continuity.continuity_id,
        "federated_clearing.continuity.continuity_id",
    )?;
    if let Some(previous_clearing_id) = continuity.previous_clearing_id.as_deref() {
        ensure_non_empty(
            previous_clearing_id,
            "federated_clearing.continuity.previous_clearing_id",
        )?;
        if previous_clearing_id == clearing_id {
            return Err(FederationContractError::InvalidClearing(
                "continuity previous_clearing_id must differ from clearing_id".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_sybil_control(
    control: &FederatedSybilControl,
) -> Result<(), FederationContractError> {
    if control.minimum_independent_issuers == 0 {
        return Err(FederationContractError::InvalidClearing(
            "minimum_independent_issuers must be non-zero".to_string(),
        ));
    }
    if control.maximum_inputs_per_issuer == 0 {
        return Err(FederationContractError::InvalidClearing(
            "maximum_inputs_per_issuer must be non-zero".to_string(),
        ));
    }
    if control.oracle_cap_bps == 0 || control.oracle_cap_bps > 10_000 {
        return Err(FederationContractError::InvalidClearing(
            "oracle_cap_bps must be between 1 and 10000".to_string(),
        ));
    }
    if !control.local_weighting_required {
        return Err(FederationContractError::InvalidClearing(
            "federated reputation clearing must require local weighting".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn validate_positive_money(
    amount: &MonetaryAmount,
    field: &'static str,
) -> Result<(), FederationContractError> {
    if amount.units == 0 {
        return Err(FederationContractError::InvalidAdmission(format!(
            "{field} must be greater than zero"
        )));
    }
    if amount.currency.len() != 3
        || !amount
            .currency
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        return Err(FederationContractError::InvalidAdmission(format!(
            "{field} currency must be a 3-letter uppercase currency code"
        )));
    }
    Ok(())
}

pub(crate) fn validate_hex_digest(
    value: &str,
    field: &'static str,
) -> Result<(), FederationContractError> {
    ensure_non_empty(value, field)?;
    if !is_hex_digest_64(value) {
        return Err(FederationContractError::InvalidReference(format!(
            "{field} must be a 64-character lowercase-compatible hex digest"
        )));
    }
    Ok(())
}

pub(crate) fn is_hex_digest_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn ensure_non_empty(
    value: &str,
    field: &'static str,
) -> Result<(), FederationContractError> {
    if value.trim().is_empty() {
        return Err(FederationContractError::MissingField(field));
    }
    Ok(())
}

pub(crate) fn ensure_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<(), FederationContractError> {
    let mut seen = HashSet::new();
    for value in values {
        if value.trim().is_empty() {
            return Err(FederationContractError::MissingField(field));
        }
        if !seen.insert(value.as_str()) {
            return Err(FederationContractError::DuplicateValue(format!(
                "{field}:{value}"
            )));
        }
    }
    Ok(())
}

pub(crate) fn ensure_unique_copy_values<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), FederationContractError>
where
    T: Copy + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(*value) {
            return Err(FederationContractError::DuplicateValue(format!(
                "{field}:{value:?}"
            )));
        }
    }
    Ok(())
}
