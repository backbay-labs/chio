use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use super::registry::frost_action_registration;
use super::types::{
    validate_base_units, validate_digest, validate_identifier, validate_positive_base_units,
    validate_positive_safe_integer, validate_safe_integer, validate_text, FrostAuthorizationDomain,
    FrostAuthorizationError,
};

pub const CHIO_FROST_SETTLE_COMMITMENT_ACTION_SCHEMA: &str =
    "chio.frost.action.settle-commitment.v1";
pub const CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA: &str =
    "chio.frost.action.clearing-round-finalize.v1";
pub const CHIO_FROST_CHANNEL_CLOSE_ACTION_SCHEMA: &str = "chio.frost.action.channel-close.v1";
pub const CHIO_FROST_POUNCER_REVOKE_CREDENTIAL_ACTION_SCHEMA: &str =
    "chio.frost.action.pouncer-revoke-credential.v1";
pub const CHIO_FROST_GOVERNANCE_CASE_ENFORCE_SANCTION_ACTION_SCHEMA: &str =
    "chio.frost.action.governance-case-enforce-sanction.v1";
pub const CHIO_FROST_CREDENTIALS_PASSPORT_REVOKE_ACTION_SCHEMA: &str =
    "chio.frost.action.credentials-passport-revoke.v1";
pub const CHIO_FROST_ROSTER_ROTATE_ACTION_SCHEMA: &str = "chio.frost.action.roster-rotate.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostSettleCommitmentActionV1 {
    pub schema: String,
    pub settlement_body_digest: String,
    pub payer_id: String,
    pub payee_id: String,
    pub amount_base_units: String,
    pub asset_id: String,
    pub operation_id: String,
    pub rail_idempotency_key: String,
    pub resource_version: u64,
    pub resource_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostClearingRoundFinalizeActionV1 {
    pub schema: String,
    pub round_finalization_body_digest: String,
    pub output_manifest_root: String,
    pub acceptance_root: String,
    pub round_id: String,
    pub resource_version: u64,
    pub resource_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostChannelCloseActionV1 {
    pub schema: String,
    pub close_body_digest: String,
    pub effective_close_digest: String,
    pub channel_id: String,
    pub final_state_digest: String,
    pub final_state_sequence: u64,
    pub final_cumulative_owed: MonetaryAmount,
    pub channel_state_version: u64,
    pub escrow_reservation_version: u64,
    pub token_base_unit_release: String,
    pub publisher_fence: u64,
    pub lifecycle_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostPouncerRevokeCredentialActionV1 {
    pub schema: String,
    pub credential_body_digest: String,
    pub credential_id: String,
    pub issuer_id: String,
    pub subject_id: String,
    pub registry_epoch: u64,
    pub anchor_epoch: u64,
    pub reason: String,
    pub evidence_root: String,
    pub resource_version: u64,
    pub resource_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostGovernanceCaseEnforceSanctionActionV1 {
    pub schema: String,
    pub case_body_digest: String,
    pub case_id: String,
    pub subject_operator_id: String,
    pub sanction_body_digest: String,
    pub evidence_root: String,
    pub enforcement_target: String,
    pub resource_version: u64,
    pub resource_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCredentialsPassportRevokeActionV1 {
    pub schema: String,
    pub passport_body_digest: String,
    pub passport_id: String,
    pub issuer_id: String,
    pub subject_id: String,
    pub revocation_generation: u64,
    pub reason: String,
    pub evidence_root: String,
    pub resource_version: u64,
    pub resource_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostRosterRotateActionV1 {
    pub schema: String,
    pub predecessor_roster_digest: String,
    pub new_roster_digest: String,
    pub scope_id: String,
    pub current_key_epoch: u64,
    pub new_key_epoch: u64,
    pub current_checkpoint_sequence: u64,
    pub current_checkpoint_digest: String,
    pub activation_fence: u64,
    pub old_session_burn_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "domain", content = "action", deny_unknown_fields)]
pub enum FrostActionPreimageV1 {
    #[serde(rename = "chio.frost.settle-commitment.v1")]
    SettleCommitment(FrostSettleCommitmentActionV1),
    #[serde(rename = "chio.frost.clearing-round-finalize.v1")]
    ClearingRoundFinalize(FrostClearingRoundFinalizeActionV1),
    #[serde(rename = "chio.frost.channel-close.v1")]
    ChannelClose(FrostChannelCloseActionV1),
    #[serde(rename = "chio.frost.pouncer-revoke-credential.v1")]
    PouncerRevokeCredential(FrostPouncerRevokeCredentialActionV1),
    #[serde(rename = "chio.frost.governance-case-enforce-sanction.v1")]
    GovernanceCaseEnforceSanction(FrostGovernanceCaseEnforceSanctionActionV1),
    #[serde(rename = "chio.frost.credentials-passport-revoke.v1")]
    CredentialsPassportRevoke(FrostCredentialsPassportRevokeActionV1),
    #[serde(rename = "chio.frost.roster-rotate.v1")]
    RosterRotate(FrostRosterRotateActionV1),
}

impl FrostActionPreimageV1 {
    #[must_use]
    pub const fn domain(&self) -> FrostAuthorizationDomain {
        match self {
            Self::SettleCommitment(_) => FrostAuthorizationDomain::SettleCommitment,
            Self::ClearingRoundFinalize(_) => FrostAuthorizationDomain::ClearingRoundFinalize,
            Self::ChannelClose(_) => FrostAuthorizationDomain::ChannelClose,
            Self::PouncerRevokeCredential(_) => FrostAuthorizationDomain::PouncerRevokeCredential,
            Self::GovernanceCaseEnforceSanction(_) => {
                FrostAuthorizationDomain::GovernanceCaseEnforceSanction
            }
            Self::CredentialsPassportRevoke(_) => {
                FrostAuthorizationDomain::CredentialsPassportRevoke
            }
            Self::RosterRotate(_) => FrostAuthorizationDomain::RosterRotate,
        }
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        match self {
            Self::SettleCommitment(action) => &action.operation_id,
            Self::ClearingRoundFinalize(action) => &action.round_id,
            Self::ChannelClose(action) => &action.channel_id,
            Self::PouncerRevokeCredential(action) => &action.credential_id,
            Self::GovernanceCaseEnforceSanction(action) => &action.case_id,
            Self::CredentialsPassportRevoke(action) => &action.passport_id,
            Self::RosterRotate(action) => &action.scope_id,
        }
    }

    #[must_use]
    pub const fn resource_version(&self) -> u64 {
        match self {
            Self::SettleCommitment(action) => action.resource_version,
            Self::ClearingRoundFinalize(action) => action.resource_version,
            Self::ChannelClose(action) => action.channel_state_version,
            Self::PouncerRevokeCredential(action) => action.resource_version,
            Self::GovernanceCaseEnforceSanction(action) => action.resource_version,
            Self::CredentialsPassportRevoke(action) => action.resource_version,
            Self::RosterRotate(action) => action.current_key_epoch,
        }
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        match self {
            Self::SettleCommitment(action) => action.resource_fence,
            Self::ClearingRoundFinalize(action) => action.resource_fence,
            Self::ChannelClose(action) => action.lifecycle_fence,
            Self::PouncerRevokeCredential(action) => action.resource_fence,
            Self::GovernanceCaseEnforceSanction(action) => action.resource_fence,
            Self::CredentialsPassportRevoke(action) => action.resource_fence,
            Self::RosterRotate(action) => action.activation_fence,
        }
    }

    pub fn action_digest(&self) -> Result<String, FrostAuthorizationError> {
        self.validate()?;
        let canonical = canonical_json_bytes(self)
            .map_err(|error| FrostAuthorizationError::Canonical(error.to_string()))?;
        Ok(sha256_hex(&canonical))
    }

    pub fn validate(&self) -> Result<(), FrostAuthorizationError> {
        let registration = frost_action_registration(self.domain()).ok_or(
            FrostAuthorizationError::DisabledDomain(self.domain().as_str()),
        )?;
        if self.schema() != registration.action_preimage_schema {
            return Err(FrostAuthorizationError::UnsupportedSchema(
                self.schema().to_string(),
            ));
        }
        match self {
            Self::SettleCommitment(action) => validate_settlement(action),
            Self::ClearingRoundFinalize(action) => validate_clearing(action),
            Self::ChannelClose(action) => validate_channel_close(action),
            Self::PouncerRevokeCredential(action) => validate_credential_revocation(action),
            Self::GovernanceCaseEnforceSanction(action) => validate_sanction(action),
            Self::CredentialsPassportRevoke(action) => validate_passport_revocation(action),
            Self::RosterRotate(action) => validate_roster_rotation(action),
        }
    }

    fn schema(&self) -> &str {
        match self {
            Self::SettleCommitment(action) => &action.schema,
            Self::ClearingRoundFinalize(action) => &action.schema,
            Self::ChannelClose(action) => &action.schema,
            Self::PouncerRevokeCredential(action) => &action.schema,
            Self::GovernanceCaseEnforceSanction(action) => &action.schema,
            Self::CredentialsPassportRevoke(action) => &action.schema,
            Self::RosterRotate(action) => &action.schema,
        }
    }
}

fn validate_settlement(
    action: &FrostSettleCommitmentActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(&action.settlement_body_digest, "settlement_body_digest")?;
    validate_identifier(&action.payer_id, "payer_id")?;
    validate_identifier(&action.payee_id, "payee_id")?;
    if action.payer_id == action.payee_id {
        return Err(FrostAuthorizationError::InvalidField {
            field: "payee_id",
            detail: "must differ from payer_id",
        });
    }
    validate_positive_base_units(&action.amount_base_units, "amount_base_units")?;
    validate_identifier(&action.asset_id, "asset_id")?;
    validate_identifier(&action.operation_id, "operation_id")?;
    validate_identifier(&action.rail_idempotency_key, "rail_idempotency_key")?;
    validate_positive_safe_integer(action.resource_version, "resource_version")?;
    validate_positive_safe_integer(action.resource_fence, "resource_fence")
}

fn validate_clearing(
    action: &FrostClearingRoundFinalizeActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(
        &action.round_finalization_body_digest,
        "round_finalization_body_digest",
    )?;
    validate_digest(&action.output_manifest_root, "output_manifest_root")?;
    validate_digest(&action.acceptance_root, "acceptance_root")?;
    validate_identifier(&action.round_id, "round_id")?;
    validate_positive_safe_integer(action.resource_version, "resource_version")?;
    validate_positive_safe_integer(action.resource_fence, "resource_fence")
}

fn validate_channel_close(
    action: &FrostChannelCloseActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(&action.close_body_digest, "close_body_digest")?;
    validate_digest(&action.effective_close_digest, "effective_close_digest")?;
    validate_identifier(&action.channel_id, "channel_id")?;
    validate_digest(&action.final_state_digest, "final_state_digest")?;
    validate_safe_integer(action.final_state_sequence, "final_state_sequence")?;
    validate_safe_integer(action.final_cumulative_owed.units, "final_cumulative_owed")?;
    if action.final_cumulative_owed.currency.len() != 3
        || !action
            .final_cumulative_owed
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(FrostAuthorizationError::InvalidField {
            field: "final_cumulative_owed",
            detail: "currency must be a 3-letter uppercase code",
        });
    }
    validate_positive_safe_integer(action.channel_state_version, "channel_state_version")?;
    validate_positive_safe_integer(
        action.escrow_reservation_version,
        "escrow_reservation_version",
    )?;
    validate_base_units(&action.token_base_unit_release, "token_base_unit_release")?;
    validate_positive_safe_integer(action.publisher_fence, "publisher_fence")?;
    validate_positive_safe_integer(action.lifecycle_fence, "lifecycle_fence")
}

fn validate_credential_revocation(
    action: &FrostPouncerRevokeCredentialActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(&action.credential_body_digest, "credential_body_digest")?;
    validate_identifier(&action.credential_id, "credential_id")?;
    validate_identifier(&action.issuer_id, "issuer_id")?;
    validate_identifier(&action.subject_id, "subject_id")?;
    validate_positive_safe_integer(action.registry_epoch, "registry_epoch")?;
    validate_positive_safe_integer(action.anchor_epoch, "anchor_epoch")?;
    validate_text(&action.reason, "reason")?;
    validate_digest(&action.evidence_root, "evidence_root")?;
    validate_positive_safe_integer(action.resource_version, "resource_version")?;
    validate_positive_safe_integer(action.resource_fence, "resource_fence")
}

fn validate_sanction(
    action: &FrostGovernanceCaseEnforceSanctionActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(&action.case_body_digest, "case_body_digest")?;
    validate_identifier(&action.case_id, "case_id")?;
    validate_identifier(&action.subject_operator_id, "subject_operator_id")?;
    validate_digest(&action.sanction_body_digest, "sanction_body_digest")?;
    validate_digest(&action.evidence_root, "evidence_root")?;
    validate_identifier(&action.enforcement_target, "enforcement_target")?;
    validate_positive_safe_integer(action.resource_version, "resource_version")?;
    validate_positive_safe_integer(action.resource_fence, "resource_fence")
}

fn validate_passport_revocation(
    action: &FrostCredentialsPassportRevokeActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(&action.passport_body_digest, "passport_body_digest")?;
    validate_identifier(&action.passport_id, "passport_id")?;
    validate_identifier(&action.issuer_id, "issuer_id")?;
    validate_identifier(&action.subject_id, "subject_id")?;
    validate_positive_safe_integer(action.revocation_generation, "revocation_generation")?;
    validate_text(&action.reason, "reason")?;
    validate_digest(&action.evidence_root, "evidence_root")?;
    validate_positive_safe_integer(action.resource_version, "resource_version")?;
    validate_positive_safe_integer(action.resource_fence, "resource_fence")
}

fn validate_roster_rotation(
    action: &FrostRosterRotateActionV1,
) -> Result<(), FrostAuthorizationError> {
    validate_digest(
        &action.predecessor_roster_digest,
        "predecessor_roster_digest",
    )?;
    validate_digest(&action.new_roster_digest, "new_roster_digest")?;
    if action.predecessor_roster_digest == action.new_roster_digest {
        return Err(FrostAuthorizationError::InvalidField {
            field: "new_roster_digest",
            detail: "must differ from predecessor_roster_digest",
        });
    }
    validate_identifier(&action.scope_id, "scope_id")?;
    validate_positive_safe_integer(action.current_key_epoch, "current_key_epoch")?;
    validate_positive_safe_integer(action.new_key_epoch, "new_key_epoch")?;
    if action.current_key_epoch.checked_add(1) != Some(action.new_key_epoch) {
        return Err(FrostAuthorizationError::InvalidField {
            field: "new_key_epoch",
            detail: "must be current_key_epoch plus one",
        });
    }
    validate_positive_safe_integer(
        action.current_checkpoint_sequence,
        "current_checkpoint_sequence",
    )?;
    validate_digest(
        &action.current_checkpoint_digest,
        "current_checkpoint_digest",
    )?;
    validate_positive_safe_integer(action.activation_fence, "activation_fence")?;
    validate_digest(&action.old_session_burn_root, "old_session_burn_root")
}
