use chio_core_types::{canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use super::types::{validate_digest, validate_identifier};
use super::{
    FrostActionPreimageV1, FrostArtifactTrustStore, FrostAuthorizationDomain,
    FrostAuthorizationError, FrostEpochCheckpointV1, FrostRosterRotateActionV1, FrostRosterV1,
    FrostVerificationError, VerifiedFrostAuthorization,
};

pub const CHIO_FROST_SESSION_BURN_SUMMARY_SCHEMA: &str = "chio.frost.session-burn-summary.v1";
const CHIO_FROST_SESSION_BURN_ROOT_PREFIX: &[u8] = b"CHIO-FROST-SESSION-BURN-ROOT-V1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostSessionBurnSummaryV1 {
    pub schema: String,
    pub scope_id: String,
    pub key_epoch: u64,
    pub burned_session_ids: Vec<String>,
    pub live_session_count: u64,
    pub burn_root: String,
}

impl FrostSessionBurnSummaryV1 {
    pub fn new(
        scope_id: impl Into<String>,
        key_epoch: u64,
        mut burned_session_ids: Vec<String>,
    ) -> Result<Self, FrostEpochAdvanceError> {
        burned_session_ids.sort_unstable();
        if burned_session_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FrostEpochAdvanceError::InvalidBurnSummary(
                "burned session ids must be unique",
            ));
        }
        let scope_id = scope_id.into();
        let burn_root = session_burn_root(&scope_id, key_epoch, &burned_session_ids)?;
        let summary = Self {
            schema: CHIO_FROST_SESSION_BURN_SUMMARY_SCHEMA.to_string(),
            scope_id,
            key_epoch,
            burned_session_ids,
            live_session_count: 0,
            burn_root,
        };
        summary.validate()?;
        Ok(summary)
    }

    pub fn validate(&self) -> Result<(), FrostEpochAdvanceError> {
        if self.schema != CHIO_FROST_SESSION_BURN_SUMMARY_SCHEMA {
            return Err(FrostEpochAdvanceError::InvalidBurnSummary(
                "unsupported schema",
            ));
        }
        validate_identifier(&self.scope_id, "scope_id")?;
        if self.key_epoch == 0 {
            return Err(FrostEpochAdvanceError::InvalidBurnSummary(
                "key epoch must be non-zero",
            ));
        }
        if self.live_session_count != 0 {
            return Err(FrostEpochAdvanceError::LiveSessionsRemain);
        }
        if !self
            .burned_session_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        {
            return Err(FrostEpochAdvanceError::InvalidBurnSummary(
                "burned session ids must be sorted and unique",
            ));
        }
        for session_id in &self.burned_session_ids {
            validate_digest(session_id, "burned_session_id")?;
        }
        validate_digest(&self.burn_root, "burn_root")?;
        if session_burn_root(&self.scope_id, self.key_epoch, &self.burned_session_ids)?
            != self.burn_root
        {
            return Err(FrostEpochAdvanceError::InvalidBurnSummary(
                "burn root does not match the canonical session set",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrostEpochAdvanceError {
    #[error("invalid FROST epoch advance: {0}")]
    Invalid(&'static str),
    #[error("invalid FROST session burn summary: {0}")]
    InvalidBurnSummary(&'static str),
    #[error("FROST epoch advance still has live old-epoch sessions")]
    LiveSessionsRemain,
    #[error(transparent)]
    Authorization(#[from] FrostAuthorizationError),
    #[error(transparent)]
    Verification(#[from] FrostVerificationError),
    #[error("FROST artifact trust verification failed: {0}")]
    ArtifactTrust(String),
    #[error("FROST epoch advance canonical JSON failed: {0}")]
    Canonical(String),
}

#[derive(Debug, Clone)]
pub struct VerifiedFrostEpochAdvance {
    predecessor: FrostEpochCheckpointV1,
    target_roster: FrostRosterV1,
    rotation_authorization_digest: String,
    burn_summary: FrostSessionBurnSummaryV1,
    activation_fence: u64,
    clock_high_water: u64,
    expected_checkpoint_sequence: u64,
}

impl VerifiedFrostEpochAdvance {
    #[must_use]
    pub fn predecessor(&self) -> &FrostEpochCheckpointV1 {
        &self.predecessor
    }

    #[must_use]
    pub fn target_roster(&self) -> &FrostRosterV1 {
        &self.target_roster
    }

    #[must_use]
    pub fn rotation_authorization_digest(&self) -> &str {
        &self.rotation_authorization_digest
    }

    #[must_use]
    pub fn burn_summary(&self) -> &FrostSessionBurnSummaryV1 {
        &self.burn_summary
    }

    #[must_use]
    pub const fn activation_fence(&self) -> u64 {
        self.activation_fence
    }

    #[must_use]
    pub const fn clock_high_water(&self) -> u64 {
        self.clock_high_water
    }

    #[must_use]
    pub const fn expected_checkpoint_sequence(&self) -> u64 {
        self.expected_checkpoint_sequence
    }
}

pub trait FrostEpochAnchorWriter: super::FrostEpochAnchor {
    fn compare_and_swap_epoch(
        &self,
        expected_checkpoint_digest: &str,
        advance: &VerifiedFrostEpochAdvance,
    ) -> Result<FrostEpochCheckpointV1, super::FrostAnchorError>;
}

pub fn verify_frost_epoch_advance(
    predecessor: &FrostEpochCheckpointV1,
    target_roster: &FrostRosterV1,
    rotation_authorization: &VerifiedFrostAuthorization,
    action: &FrostRosterRotateActionV1,
    burn_summary: &FrostSessionBurnSummaryV1,
    artifact_trust: &FrostArtifactTrustStore,
    clock_high_water: u64,
) -> Result<VerifiedFrostEpochAdvance, FrostEpochAdvanceError> {
    artifact_trust
        .verify_epoch_checkpoint(predecessor)
        .map_err(|error| FrostEpochAdvanceError::ArtifactTrust(error.to_string()))?;
    artifact_trust
        .verify_roster(target_roster)
        .map_err(|error| FrostEpochAdvanceError::ArtifactTrust(error.to_string()))?;
    target_roster
        .validate_for_active_resolution()
        .map_err(|error| FrostEpochAdvanceError::ArtifactTrust(error.to_string()))?;
    burn_summary.validate()?;

    let expected_checkpoint_sequence =
        predecessor
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(FrostEpochAdvanceError::Invalid(
                "checkpoint sequence overflow",
            ))?;

    let action_preimage = FrostActionPreimageV1::RosterRotate(action.clone());
    rotation_authorization.verify_action_preimage(&action_preimage)?;
    if rotation_authorization.domain() != FrostAuthorizationDomain::RosterRotate
        || rotation_authorization.ladder_action_class() != "governance.roster_rotate"
        || rotation_authorization.quorum_n() != 3
        || rotation_authorization.quorum_m() != 5
        || rotation_authorization.quorum_scope() != "treaty"
    {
        return Err(FrostEpochAdvanceError::Invalid(
            "rotation authorization is not the registered 3-of-5 governance class",
        ));
    }
    if !rotation_authorization.is_current_at(clock_high_water) {
        return Err(FrostEpochAdvanceError::Invalid(
            "rotation authorization is not current at the anchor clock",
        ));
    }
    if target_roster.scope_id != predecessor.scope_id
        || action.scope_id != predecessor.scope_id
        || burn_summary.scope_id != predecessor.scope_id
    {
        return Err(FrostEpochAdvanceError::Invalid("target scope mismatch"));
    }
    if target_roster.key_epoch
        != predecessor
            .key_epoch
            .checked_add(1)
            .ok_or(FrostEpochAdvanceError::Invalid("key epoch overflow"))?
        || action.current_key_epoch != predecessor.key_epoch
        || action.new_key_epoch != target_roster.key_epoch
        || burn_summary.key_epoch != predecessor.key_epoch
    {
        return Err(FrostEpochAdvanceError::Invalid("key epoch discontinuity"));
    }
    if target_roster.predecessor_roster_digest.as_deref()
        != Some(predecessor.active_roster_digest.as_str())
        || action.predecessor_roster_digest != predecessor.active_roster_digest
        || action.new_roster_digest != target_roster.roster_digest
    {
        return Err(FrostEpochAdvanceError::Invalid(
            "roster predecessor relation mismatch",
        ));
    }
    if action.current_checkpoint_sequence != predecessor.checkpoint_sequence
        || action.current_checkpoint_digest != predecessor.checkpoint_digest
    {
        return Err(FrostEpochAdvanceError::Invalid(
            "checkpoint predecessor mismatch",
        ));
    }
    if action.old_session_burn_root != burn_summary.burn_root {
        return Err(FrostEpochAdvanceError::Invalid(
            "session burn root mismatch",
        ));
    }
    if action.activation_fence <= predecessor.activation_fence {
        return Err(FrostEpochAdvanceError::Invalid(
            "activation fence did not advance",
        ));
    }
    if clock_high_water < predecessor.clock_high_water
        || clock_high_water < target_roster.valid_from
        || clock_high_water >= target_roster.valid_until
    {
        return Err(FrostEpochAdvanceError::Invalid(
            "clock high-water is not valid for the target roster",
        ));
    }
    let target_group_key = decode_hex(&target_roster.group_public_key, "group_public_key")?;
    if sha256_hex(&target_group_key) == predecessor.group_public_key_digest {
        return Err(FrostEpochAdvanceError::Invalid("group key was reused"));
    }

    Ok(VerifiedFrostEpochAdvance {
        predecessor: predecessor.clone(),
        target_roster: target_roster.clone(),
        rotation_authorization_digest: rotation_authorization.proof_digest().to_string(),
        burn_summary: burn_summary.clone(),
        activation_fence: action.activation_fence,
        clock_high_water,
        expected_checkpoint_sequence,
    })
}

fn session_burn_root(
    scope_id: &str,
    key_epoch: u64,
    burned_session_ids: &[String],
) -> Result<String, FrostEpochAdvanceError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct BurnRoot<'a> {
        scope_id: &'a str,
        key_epoch: u64,
        burned_session_ids: &'a [String],
    }

    let canonical = canonical_json_bytes(&BurnRoot {
        scope_id,
        key_epoch,
        burned_session_ids,
    })
    .map_err(|error| FrostEpochAdvanceError::Canonical(error.to_string()))?;
    let mut bytes = Vec::with_capacity(CHIO_FROST_SESSION_BURN_ROOT_PREFIX.len() + canonical.len());
    bytes.extend_from_slice(CHIO_FROST_SESSION_BURN_ROOT_PREFIX);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

fn decode_hex(value: &str, _field: &'static str) -> Result<Vec<u8>, FrostEpochAdvanceError> {
    hex::decode(value).map_err(|_| FrostEpochAdvanceError::Invalid("group key is not hex"))
}
