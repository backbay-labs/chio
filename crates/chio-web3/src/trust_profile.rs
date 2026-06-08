use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::error::Web3ContractError;
use crate::identity::{validate_web3_identity_binding, SignedWeb3IdentityBinding};
use crate::validation::{ensure_non_empty, ensure_unique_strings};

pub const CHIO_WEB3_TRUST_PROFILE_SCHEMA: &str = "chio.web3-trust-profile.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3SettlementPath {
    DualSignature,
    MerkleProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3DisputePolicy {
    OffChainArbitration,
    TimeoutRefund,
    BondSlash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3FinalityMode {
    OptimisticL2,
    L1Finalized,
    SolanaConfirmed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3RegulatedRole {
    Operator,
    Custodian,
    PaymentInstitution,
    OracleOperator,
    Arbitrator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3DisputeWindow {
    pub settlement_path: Web3SettlementPath,
    pub challenge_window_secs: u64,
    pub recovery_window_secs: u64,
    pub dispute_policy: Web3DisputePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ChainFinalityRule {
    pub chain_id: String,
    pub mode: Web3FinalityMode,
    pub min_confirmations: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3RegulatedRoleAssumption {
    pub role: Web3RegulatedRole,
    pub actor_id: String,
    pub responsibility: String,
    pub custody_boundary_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3TrustProfile {
    pub schema: String,
    pub profile_id: String,
    pub chio_contract_version: String,
    pub primary_chain_id: String,
    pub secondary_chain_ids: Vec<String>,
    pub operator_binding: SignedWeb3IdentityBinding,
    pub proof_bundle_required: bool,
    pub dispute_windows: Vec<Web3DisputeWindow>,
    pub finality_rules: Vec<Web3ChainFinalityRule>,
    pub regulated_roles: Vec<Web3RegulatedRoleAssumption>,
    pub custody_boundary_note: String,
    pub local_policy_activation_required: bool,
}

pub fn validate_web3_trust_profile(profile: &Web3TrustProfile) -> Result<(), Web3ContractError> {
    if profile.schema != CHIO_WEB3_TRUST_PROFILE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(profile.schema.clone()));
    }
    ensure_non_empty(&profile.profile_id, "web3_trust_profile.profile_id")?;
    ensure_non_empty(
        &profile.chio_contract_version,
        "web3_trust_profile.chio_contract_version",
    )?;
    ensure_non_empty(
        &profile.primary_chain_id,
        "web3_trust_profile.primary_chain_id",
    )?;
    ensure_non_empty(
        &profile.custody_boundary_note,
        "web3_trust_profile.custody_boundary_note",
    )?;
    validate_web3_identity_binding(&profile.operator_binding)?;
    ensure_unique_strings(
        &profile.secondary_chain_ids,
        "web3_trust_profile.secondary_chain_ids",
    )?;
    if profile
        .secondary_chain_ids
        .iter()
        .any(|chain_id| chain_id == &profile.primary_chain_id)
    {
        return Err(Web3ContractError::DuplicateValue(
            profile.primary_chain_id.clone(),
        ));
    }

    let mut known_chains = HashSet::new();
    known_chains.insert(profile.primary_chain_id.as_str());
    for chain_id in &profile.secondary_chain_ids {
        known_chains.insert(chain_id.as_str());
    }
    for chain_id in &profile.operator_binding.certificate.chain_scope {
        known_chains.insert(chain_id.as_str());
    }
    if !profile
        .operator_binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain_id| chain_id == &profile.primary_chain_id)
    {
        return Err(Web3ContractError::InvalidBinding(format!(
            "binding does not cover primary chain {}",
            profile.primary_chain_id
        )));
    }
    for chain_id in &profile.secondary_chain_ids {
        if !profile
            .operator_binding
            .certificate
            .chain_scope
            .iter()
            .any(|candidate| candidate == chain_id)
        {
            return Err(Web3ContractError::InvalidBinding(format!(
                "binding does not cover secondary chain {}",
                chain_id
            )));
        }
    }

    if !profile.local_policy_activation_required {
        return Err(Web3ContractError::InvalidBinding(
            "web3 trust profile must require explicit local policy activation".to_string(),
        ));
    }

    if profile.dispute_windows.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_trust_profile.dispute_windows",
        ));
    }
    let mut seen_paths = HashSet::new();
    for window in &profile.dispute_windows {
        if !seen_paths.insert(window.settlement_path) {
            return Err(Web3ContractError::DuplicateValue(format!(
                "web3_trust_profile.dispute_windows:{:?}",
                window.settlement_path
            )));
        }
        if window.challenge_window_secs == 0 || window.recovery_window_secs == 0 {
            return Err(Web3ContractError::InvalidBinding(format!(
                "dispute window {:?} must have non-zero durations",
                window.settlement_path
            )));
        }
    }
    if profile.finality_rules.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_trust_profile.finality_rules",
        ));
    }
    let mut seen_finality = HashSet::new();
    for rule in &profile.finality_rules {
        ensure_non_empty(&rule.chain_id, "web3_trust_profile.finality_rules.chain_id")?;
        if rule.min_confirmations == 0 {
            return Err(Web3ContractError::InvalidBinding(format!(
                "finality rule {} must require at least one confirmation",
                rule.chain_id
            )));
        }
        if !seen_finality.insert(rule.chain_id.as_str()) {
            return Err(Web3ContractError::DuplicateValue(rule.chain_id.clone()));
        }
    }
    for chain_id in [&profile.primary_chain_id]
        .into_iter()
        .chain(profile.secondary_chain_ids.iter())
    {
        if !seen_finality.contains(chain_id.as_str()) {
            return Err(Web3ContractError::UnknownReference(chain_id.clone()));
        }
    }

    if profile.regulated_roles.is_empty() {
        return Err(Web3ContractError::MissingField(
            "web3_trust_profile.regulated_roles",
        ));
    }
    let mut saw_custodian = false;
    for role in &profile.regulated_roles {
        ensure_non_empty(
            &role.actor_id,
            "web3_trust_profile.regulated_roles.actor_id",
        )?;
        ensure_non_empty(
            &role.responsibility,
            "web3_trust_profile.regulated_roles.responsibility",
        )?;
        if !role.custody_boundary_explicit {
            return Err(Web3ContractError::InvalidBinding(format!(
                "regulated role {:?} must keep custody boundary explicit",
                role.role
            )));
        }
        if role.role == Web3RegulatedRole::Custodian {
            saw_custodian = true;
        }
    }
    if !saw_custodian {
        return Err(Web3ContractError::InvalidBinding(
            "web3 trust profile must record at least one custodian role".to_string(),
        ));
    }

    Ok(())
}
