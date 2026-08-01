use chio_core_types::sha256_hex;
use serde::Serialize;

use super::types::{validate_identifier, FrostAuthorizationBodyV1, FrostAuthorizationError};
use super::verify::{
    verify_completed_slot_artifact, verify_current_epoch, verify_group_signature,
    verify_roster_binding,
};
use super::{
    frost_authorization_session_id, frost_authorization_slot_id, FrostAnchorError,
    FrostAnchoredAuthorizationSlot, FrostArtifactTrustStore, FrostAuthorizationDomain,
    FrostAuthorizationSlotAnchor, FrostAuthorizationSlotCheckpointV1, FrostAuthorizationSlotState,
    FrostAuthorizationV1, FrostEpochAnchor, FrostVerificationError, VerifiedActiveFrostRoster,
};

#[derive(Debug, thiserror::Error)]
pub enum FrostAuthorizationSlotTransitionError {
    #[error(transparent)]
    Authorization(#[from] FrostAuthorizationError),
    #[error(transparent)]
    Verification(#[from] FrostVerificationError),
    #[error("FROST artifact trust verification failed: {0}")]
    ArtifactTrust(String),
    #[error("invalid FROST authorization slot transition: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrostAuthorizationSlotBind {
    scope_id: String,
    slot_id: String,
    domain: FrostAuthorizationDomain,
    ladder_action_class: String,
    resource_id: String,
    resource_version: u64,
    resource_fence: u64,
    authorization_id: String,
    signing_message_digest: String,
    action_digest: String,
    roster_digest: String,
    key_epoch: u64,
    session_id: String,
    clock_high_water: u64,
}

impl FrostAuthorizationSlotBind {
    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    #[must_use]
    pub fn slot_id(&self) -> &str {
        &self.slot_id
    }

    #[must_use]
    pub const fn clock_high_water(&self) -> u64 {
        self.clock_high_water
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFrostAuthorizationSlotBind {
    request: FrostAuthorizationSlotBind,
}

impl VerifiedFrostAuthorizationSlotBind {
    #[must_use]
    pub fn request(&self) -> &FrostAuthorizationSlotBind {
        &self.request
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrostAuthorizationSlotCompletion {
    expected_bound_checkpoint_digest: String,
    authorization_blob: Vec<u8>,
    aggregate_signature_digest: String,
    authorization_blob_digest: String,
    availability_receipt: String,
    clock_high_water: u64,
}

impl FrostAuthorizationSlotCompletion {
    #[must_use]
    pub fn expected_bound_checkpoint_digest(&self) -> &str {
        &self.expected_bound_checkpoint_digest
    }

    #[must_use]
    pub fn authorization_blob(&self) -> &[u8] {
        &self.authorization_blob
    }

    #[must_use]
    pub fn aggregate_signature_digest(&self) -> &str {
        &self.aggregate_signature_digest
    }

    #[must_use]
    pub fn authorization_blob_digest(&self) -> &str {
        &self.authorization_blob_digest
    }

    #[must_use]
    pub fn availability_receipt(&self) -> &str {
        &self.availability_receipt
    }

    #[must_use]
    pub const fn clock_high_water(&self) -> u64 {
        self.clock_high_water
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFrostAuthorizationSlotCompletion {
    request: FrostAuthorizationSlotCompletion,
}

impl VerifiedFrostAuthorizationSlotCompletion {
    #[must_use]
    pub fn request(&self) -> &FrostAuthorizationSlotCompletion {
        &self.request
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FrostAuthorizationSlotBurn {
    expected_bound_checkpoint_digest: String,
    clock_high_water: u64,
}

impl FrostAuthorizationSlotBurn {
    #[must_use]
    pub fn expected_bound_checkpoint_digest(&self) -> &str {
        &self.expected_bound_checkpoint_digest
    }

    #[must_use]
    pub const fn clock_high_water(&self) -> u64 {
        self.clock_high_water
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFrostAuthorizationSlotBurn {
    request: FrostAuthorizationSlotBurn,
}

#[derive(Debug, Clone)]
pub struct VerifiedBoundFrostAuthorizationSlot {
    checkpoint: FrostAuthorizationSlotCheckpointV1,
}

#[derive(Debug, Clone)]
pub struct VerifiedCompletedFrostAuthorizationSlot {
    checkpoint: FrostAuthorizationSlotCheckpointV1,
    proof: FrostAuthorizationV1,
}

#[derive(Debug, Clone)]
pub struct VerifiedBurnedFrostAuthorizationSlot {
    checkpoint: FrostAuthorizationSlotCheckpointV1,
}

impl VerifiedBoundFrostAuthorizationSlot {
    #[must_use]
    pub fn checkpoint(&self) -> &FrostAuthorizationSlotCheckpointV1 {
        &self.checkpoint
    }

    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint.checkpoint_digest
    }
}

impl VerifiedCompletedFrostAuthorizationSlot {
    #[must_use]
    pub fn checkpoint(&self) -> &FrostAuthorizationSlotCheckpointV1 {
        &self.checkpoint
    }

    #[must_use]
    pub fn proof(&self) -> &FrostAuthorizationV1 {
        &self.proof
    }
}

impl VerifiedBurnedFrostAuthorizationSlot {
    #[must_use]
    pub fn checkpoint(&self) -> &FrostAuthorizationSlotCheckpointV1 {
        &self.checkpoint
    }
}

impl VerifiedFrostAuthorizationSlotBurn {
    #[must_use]
    pub fn request(&self) -> &FrostAuthorizationSlotBurn {
        &self.request
    }
}

pub trait FrostAuthorizationSlotAnchorWriter: FrostAuthorizationSlotAnchor {
    fn compare_and_swap_bind(
        &self,
        bind: &VerifiedFrostAuthorizationSlotBind,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError>;

    fn compare_and_swap_complete(
        &self,
        completion: &VerifiedFrostAuthorizationSlotCompletion,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError>;

    fn compare_and_swap_burn(
        &self,
        burn: &VerifiedFrostAuthorizationSlotBurn,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError>;
}

pub fn verify_bound_frost_authorization_slot(
    body: &FrostAuthorizationBodyV1,
    active_roster: &VerifiedActiveFrostRoster,
    epoch_anchor: &dyn FrostEpochAnchor,
    anchored: &FrostAnchoredAuthorizationSlot,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<VerifiedBoundFrostAuthorizationSlot, FrostAuthorizationSlotTransitionError> {
    body.validate()?;
    if now < body.issued_at || now >= body.expires_at {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization is not current",
        ));
    }
    if body.scope_id != active_roster.roster.scope_id
        || body.roster_digest != active_roster.roster.roster_digest
        || body.key_epoch != active_roster.roster.key_epoch
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization does not use the active roster",
        ));
    }
    verify_current_epoch(active_roster, epoch_anchor, artifact_trust, now)?;
    let checkpoint = &anchored.checkpoint;
    artifact_trust
        .verify_authorization_slot_checkpoint(checkpoint)
        .map_err(|error| FrostAuthorizationSlotTransitionError::ArtifactTrust(error.to_string()))?;
    let signing_bytes = body.signing_bytes()?;
    if checkpoint.state != FrostAuthorizationSlotState::Bound
        || checkpoint.slot_version != 1
        || checkpoint.predecessor_digest.is_some()
        || anchored.authorization_blob.is_some()
        || checkpoint.aggregate_signature_digest.is_some()
        || checkpoint.authorization_blob_digest.is_some()
        || checkpoint.availability_receipt.is_some()
        || checkpoint.scope_id != body.scope_id
        || checkpoint.slot_id != frost_authorization_slot_id(body)?
        || checkpoint.domain != body.domain
        || checkpoint.ladder_action_class != body.ladder_action_class
        || checkpoint.resource_id != body.resource_id
        || checkpoint.resource_version != body.resource_version
        || checkpoint.resource_fence != body.resource_fence
        || checkpoint.authorization_id != body.authorization_id
        || checkpoint.signing_message_digest != sha256_hex(&signing_bytes)
        || checkpoint.action_digest != body.action_digest
        || checkpoint.roster_digest != body.roster_digest
        || checkpoint.key_epoch != body.key_epoch
        || checkpoint.session_id != frost_authorization_session_id(body)?
        || checkpoint.clock_high_water > now
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization slot is not the exact bound message",
        ));
    }
    Ok(VerifiedBoundFrostAuthorizationSlot {
        checkpoint: checkpoint.clone(),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_completed_frost_authorization_slot(
    body: &FrostAuthorizationBodyV1,
    active_roster: &VerifiedActiveFrostRoster,
    epoch_anchor: &dyn FrostEpochAnchor,
    anchored: &FrostAnchoredAuthorizationSlot,
    artifact_trust: &FrostArtifactTrustStore,
    expected_bound_checkpoint_digest: &str,
    now: u64,
) -> Result<VerifiedCompletedFrostAuthorizationSlot, FrostAuthorizationSlotTransitionError> {
    body.validate()?;
    let authorization_blob = anchored.authorization_blob.as_deref().ok_or(
        FrostAuthorizationSlotTransitionError::Invalid(
            "completed slot lacks rollback-independent authorization bytes",
        ),
    )?;
    let proof: FrostAuthorizationV1 = serde_json::from_slice(authorization_blob).map_err(|_| {
        FrostAuthorizationSlotTransitionError::Invalid(
            "completed slot authorization bytes are not valid JSON",
        )
    })?;
    proof.validate()?;
    if proof.body != *body {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "completed slot authorization differs from the signer message",
        ));
    }
    if now < body.issued_at
        || now >= body.expires_at
        || now < active_roster.roster.valid_from
        || now >= active_roster.roster.valid_until
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "completed slot authorization is not current",
        ));
    }
    verify_current_epoch(active_roster, epoch_anchor, artifact_trust, now)?;
    verify_roster_binding(&proof, &active_roster.roster)?;
    verify_group_signature(&proof, &active_roster.roster)?;
    verify_completed_slot_artifact(&proof, anchored, artifact_trust, now)?;
    if anchored.checkpoint.slot_version != 2
        || anchored.checkpoint.predecessor_digest.as_deref()
            != Some(expected_bound_checkpoint_digest)
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "completed slot is not the exact bound-checkpoint successor",
        ));
    }
    Ok(VerifiedCompletedFrostAuthorizationSlot {
        checkpoint: anchored.checkpoint.clone(),
        proof,
    })
}

pub fn verify_burned_frost_authorization_slot(
    bound: &FrostAuthorizationSlotCheckpointV1,
    anchored: &FrostAnchoredAuthorizationSlot,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<VerifiedBurnedFrostAuthorizationSlot, FrostAuthorizationSlotTransitionError> {
    artifact_trust
        .verify_authorization_slot_checkpoint(bound)
        .map_err(|error| FrostAuthorizationSlotTransitionError::ArtifactTrust(error.to_string()))?;
    artifact_trust
        .verify_authorization_slot_checkpoint(&anchored.checkpoint)
        .map_err(|error| FrostAuthorizationSlotTransitionError::ArtifactTrust(error.to_string()))?;
    let burned = &anchored.checkpoint;
    if bound.state != FrostAuthorizationSlotState::Bound
        || bound.slot_version != 1
        || bound.predecessor_digest.is_some()
        || bound.aggregate_signature_digest.is_some()
        || bound.authorization_blob_digest.is_some()
        || bound.availability_receipt.is_some()
        || burned.schema != bound.schema
        || burned.anchor_id != bound.anchor_id
        || burned.anchor_key_id != bound.anchor_key_id
        || burned.state != FrostAuthorizationSlotState::Burned
        || burned.slot_version != 2
        || burned.predecessor_digest.as_deref() != Some(bound.checkpoint_digest.as_str())
        || burned.scope_id != bound.scope_id
        || burned.slot_id != bound.slot_id
        || burned.domain != bound.domain
        || burned.ladder_action_class != bound.ladder_action_class
        || burned.resource_id != bound.resource_id
        || burned.resource_version != bound.resource_version
        || burned.resource_fence != bound.resource_fence
        || burned.authorization_id != bound.authorization_id
        || burned.signing_message_digest != bound.signing_message_digest
        || burned.action_digest != bound.action_digest
        || burned.roster_digest != bound.roster_digest
        || burned.key_epoch != bound.key_epoch
        || burned.session_id != bound.session_id
        || burned.aggregate_signature_digest.is_some()
        || burned.authorization_blob_digest.is_some()
        || burned.availability_receipt.is_some()
        || anchored.authorization_blob.is_some()
        || burned.clock_high_water < bound.clock_high_water
        || burned.clock_high_water > now
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization slot is not the exact burned successor",
        ));
    }
    Ok(VerifiedBurnedFrostAuthorizationSlot {
        checkpoint: burned.clone(),
    })
}

pub fn verify_frost_authorization_slot_bind(
    body: &FrostAuthorizationBodyV1,
    active_roster: &VerifiedActiveFrostRoster,
    epoch_anchor: &dyn FrostEpochAnchor,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<VerifiedFrostAuthorizationSlotBind, FrostAuthorizationSlotTransitionError> {
    body.validate()?;
    if body.scope_id != active_roster.roster.scope_id
        || body.roster_digest != active_roster.roster.roster_digest
        || body.key_epoch != active_roster.roster.key_epoch
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization does not use the active roster",
        ));
    }
    if now < body.issued_at || now >= body.expires_at {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization is not current",
        ));
    }
    verify_current_epoch(active_roster, epoch_anchor, artifact_trust, now)?;
    let signing_bytes = body.signing_bytes()?;
    Ok(VerifiedFrostAuthorizationSlotBind {
        request: FrostAuthorizationSlotBind {
            scope_id: body.scope_id.clone(),
            slot_id: frost_authorization_slot_id(body)?,
            domain: body.domain,
            ladder_action_class: body.ladder_action_class.clone(),
            resource_id: body.resource_id.clone(),
            resource_version: body.resource_version,
            resource_fence: body.resource_fence,
            authorization_id: body.authorization_id.clone(),
            signing_message_digest: sha256_hex(&signing_bytes),
            action_digest: body.action_digest.clone(),
            roster_digest: body.roster_digest.clone(),
            key_epoch: body.key_epoch,
            session_id: frost_authorization_session_id(body)?,
            clock_high_water: now,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_frost_authorization_slot_completion(
    bound: &FrostAuthorizationSlotCheckpointV1,
    proof: &FrostAuthorizationV1,
    active_roster: &VerifiedActiveFrostRoster,
    epoch_anchor: &dyn FrostEpochAnchor,
    artifact_trust: &FrostArtifactTrustStore,
    availability_receipt: impl Into<String>,
    now: u64,
) -> Result<VerifiedFrostAuthorizationSlotCompletion, FrostAuthorizationSlotTransitionError> {
    artifact_trust
        .verify_authorization_slot_checkpoint(bound)
        .map_err(|error| FrostAuthorizationSlotTransitionError::ArtifactTrust(error.to_string()))?;
    if bound.state != FrostAuthorizationSlotState::Bound {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "completion predecessor is not bound",
        ));
    }
    proof.validate()?;
    if now < proof.body.issued_at || now >= proof.body.expires_at {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization is not current",
        ));
    }
    verify_current_epoch(active_roster, epoch_anchor, artifact_trust, now)?;
    verify_roster_binding(proof, &active_roster.roster)?;
    verify_group_signature(proof, &active_roster.roster)?;
    let signing_bytes = proof.body.signing_bytes()?;
    if bound.scope_id != proof.body.scope_id
        || bound.slot_id != frost_authorization_slot_id(&proof.body)?
        || bound.domain != proof.body.domain
        || bound.ladder_action_class != proof.body.ladder_action_class
        || bound.resource_id != proof.body.resource_id
        || bound.resource_version != proof.body.resource_version
        || bound.resource_fence != proof.body.resource_fence
        || bound.authorization_id != proof.body.authorization_id
        || bound.signing_message_digest != sha256_hex(&signing_bytes)
        || bound.action_digest != proof.body.action_digest
        || bound.roster_digest != proof.body.roster_digest
        || bound.key_epoch != proof.body.key_epoch
        || bound.session_id != frost_authorization_session_id(&proof.body)?
    {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "authorization differs from the bound slot",
        ));
    }
    if now < bound.clock_high_water {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "clock regressed behind the bound slot",
        ));
    }
    let availability_receipt = availability_receipt.into();
    validate_identifier(&availability_receipt, "availability_receipt")?;
    let authorization_blob = proof.canonical_bytes()?;
    let signature = hex::decode(&proof.group_signature).map_err(|_| {
        FrostAuthorizationSlotTransitionError::Invalid("group signature is not hexadecimal")
    })?;
    Ok(VerifiedFrostAuthorizationSlotCompletion {
        request: FrostAuthorizationSlotCompletion {
            expected_bound_checkpoint_digest: bound.checkpoint_digest.clone(),
            aggregate_signature_digest: sha256_hex(&signature),
            authorization_blob_digest: sha256_hex(&authorization_blob),
            authorization_blob,
            availability_receipt,
            clock_high_water: now,
        },
    })
}

pub fn verify_frost_authorization_slot_burn(
    bound: &FrostAuthorizationSlotCheckpointV1,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<VerifiedFrostAuthorizationSlotBurn, FrostAuthorizationSlotTransitionError> {
    artifact_trust
        .verify_authorization_slot_checkpoint(bound)
        .map_err(|error| FrostAuthorizationSlotTransitionError::ArtifactTrust(error.to_string()))?;
    if bound.state != FrostAuthorizationSlotState::Bound {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "burn predecessor is not bound",
        ));
    }
    if now < bound.clock_high_water {
        return Err(FrostAuthorizationSlotTransitionError::Invalid(
            "clock regressed behind the bound slot",
        ));
    }
    Ok(VerifiedFrostAuthorizationSlotBurn {
        request: FrostAuthorizationSlotBurn {
            expected_bound_checkpoint_digest: bound.checkpoint_digest.clone(),
            clock_high_water: now,
        },
    })
}
