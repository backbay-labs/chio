use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use frost_ed25519::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::registry::frost_action_registration;
use super::roster::{
    ActiveFrostRosterResolver, FrostAnchorError, FrostEpochAnchor, FrostHistoricalRosterResolver,
    FrostRosterError, FrostRosterResolutionError, FrostRosterV1, VerifiedActiveFrostRoster,
    FROST_ED25519_SHA512_SUITE_ID,
};
use super::trust::FrostArtifactTrustStore;
use super::types::{
    validate_digest, validate_identifier, validate_positive_safe_integer, FrostAuthorizationBodyV1,
    FrostAuthorizationDomain, FrostAuthorizationError,
};

pub const CHIO_FROST_AUTHORIZATION_SCHEMA: &str = "chio.frost.authorization.v1";
pub const CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA: &str =
    "chio.frost.authorization-slot-checkpoint.v1";
const CHIO_FROST_AUTHORIZATION_SLOT_ID_PREFIX: &[u8] = b"chio.frost.authorization.slot.id.v1\0";
const CHIO_FROST_AUTHORIZATION_SESSION_ID_PREFIX: &[u8] =
    b"chio.frost.authorization.session.id.v1\0";
const CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_DIGEST_PREFIX: &[u8] =
    b"chio.frost.authorization-slot-checkpoint.digest.v1\0";
const CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SIGNING_PREFIX: &[u8] =
    b"CHIO-FROST-AUTHORIZATION-SLOT-CHECKPOINT-V1\0";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum FrostVerificationError {
    #[error(transparent)]
    Authorization(#[from] FrostAuthorizationError),
    #[error(transparent)]
    Roster(#[from] FrostRosterError),
    #[error("FROST roster resolution failed: {0}")]
    RosterResolution(String),
    #[error("FROST external anchor failed: {0}")]
    Anchor(String),
    #[error("FROST artifact trust verification failed: {0}")]
    ArtifactTrust(String),
    #[error("invalid FROST authorization proof: {0}")]
    InvalidProof(&'static str),
    #[error("FROST canonical JSON failed: {0}")]
    Canonical(String),
    #[error("FROST authorization does not match expected {0}")]
    ExpectedMismatch(&'static str),
    #[error("FROST active epoch mismatch: {0}")]
    EpochMismatch(&'static str),
    #[error("FROST authorization slot mismatch: {0}")]
    SlotMismatch(&'static str),
    #[error("FROST group signature is invalid")]
    InvalidGroupSignature,
    #[error("FROST authorization is not current: {0}")]
    NotCurrent(&'static str),
}

impl From<FrostRosterResolutionError> for FrostVerificationError {
    fn from(error: FrostRosterResolutionError) -> Self {
        Self::RosterResolution(error.to_string())
    }
}

impl From<FrostAnchorError> for FrostVerificationError {
    fn from(error: FrostAnchorError) -> Self {
        Self::Anchor(error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostAuthorizationV1 {
    pub schema: String,
    pub body: FrostAuthorizationBodyV1,
    pub suite_id: String,
    pub group_signature: String,
}

impl FrostAuthorizationV1 {
    pub fn validate(&self) -> Result<(), FrostVerificationError> {
        if self.schema != CHIO_FROST_AUTHORIZATION_SCHEMA {
            return Err(FrostVerificationError::InvalidProof(
                "unsupported authorization envelope schema",
            ));
        }
        self.body.validate()?;
        if self.suite_id != FROST_ED25519_SHA512_SUITE_ID {
            return Err(FrostVerificationError::InvalidProof(
                "unsupported FROST suite",
            ));
        }
        validate_fixed_hex(&self.group_signature, 128, "group_signature")
            .map_err(FrostVerificationError::Authorization)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, FrostVerificationError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map_err(|error| FrostVerificationError::Canonical(error.to_string()))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExpectedFrostAuthorization<'a> {
    pub domain: FrostAuthorizationDomain,
    pub ladder_action_class: &'a str,
    pub ladder_contract_digest: &'a str,
    pub scope_id: &'a str,
    pub resource_id: &'a str,
    pub resource_version: u64,
    pub resource_fence: u64,
    pub action_digest: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostAuthorizationSlotState {
    Bound,
    Completed,
    Burned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostAuthorizationSlotCheckpointV1 {
    pub schema: String,
    pub anchor_id: String,
    pub checkpoint_digest: String,
    pub scope_id: String,
    pub slot_id: String,
    pub slot_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_digest: Option<String>,
    pub domain: FrostAuthorizationDomain,
    pub ladder_action_class: String,
    pub resource_id: String,
    pub resource_version: u64,
    pub resource_fence: u64,
    pub authorization_id: String,
    pub signing_message_digest: String,
    pub action_digest: String,
    pub roster_digest: String,
    pub key_epoch: u64,
    pub session_id: String,
    pub state: FrostAuthorizationSlotState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate_signature_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_blob_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_receipt: Option<String>,
    pub clock_high_water: u64,
    pub anchor_key_id: String,
    pub anchor_signature: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostAuthorizationSlotCheckpointSigningPreimage<'a> {
    schema: &'a str,
    anchor_id: &'a str,
    scope_id: &'a str,
    slot_id: &'a str,
    slot_version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    predecessor_digest: Option<&'a str>,
    domain: FrostAuthorizationDomain,
    ladder_action_class: &'a str,
    resource_id: &'a str,
    resource_version: u64,
    resource_fence: u64,
    authorization_id: &'a str,
    signing_message_digest: &'a str,
    action_digest: &'a str,
    roster_digest: &'a str,
    key_epoch: u64,
    session_id: &'a str,
    state: FrostAuthorizationSlotState,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregate_signature_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_blob_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    availability_receipt: Option<&'a str>,
    clock_high_water: u64,
    anchor_key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostAuthorizationSlotCheckpointDigestPreimage<'a> {
    #[serde(flatten)]
    body: FrostAuthorizationSlotCheckpointSigningPreimage<'a>,
    anchor_signature: &'a str,
}

impl FrostAuthorizationSlotCheckpointV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, FrostVerificationError> {
        canonical_prefixed_bytes(
            CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SIGNING_PREFIX,
            &self.signing_preimage(),
        )
    }

    pub fn recompute_checkpoint_digest(&self) -> Result<String, FrostVerificationError> {
        Ok(sha256_hex(&canonical_prefixed_bytes(
            CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_DIGEST_PREFIX,
            &FrostAuthorizationSlotCheckpointDigestPreimage {
                body: self.signing_preimage(),
                anchor_signature: &self.anchor_signature,
            },
        )?))
    }

    pub fn validate(&self) -> Result<(), FrostVerificationError> {
        if self.schema != CHIO_FROST_AUTHORIZATION_SLOT_CHECKPOINT_SCHEMA {
            return Err(FrostVerificationError::SlotMismatch(
                "unsupported checkpoint schema",
            ));
        }
        validate_identifier(&self.anchor_id, "anchor_id")?;
        validate_digest(&self.checkpoint_digest, "checkpoint_digest")?;
        validate_identifier(&self.scope_id, "scope_id")?;
        validate_digest(&self.slot_id, "slot_id")?;
        validate_positive_safe_integer(self.slot_version, "slot_version")?;
        match (self.slot_version, self.predecessor_digest.as_deref()) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(FrostVerificationError::SlotMismatch(
                    "first checkpoint has a predecessor",
                ));
            }
            (_, Some(digest)) => validate_digest(digest, "predecessor_digest")?,
            (_, None) => {
                return Err(FrostVerificationError::SlotMismatch(
                    "checkpoint predecessor is missing",
                ));
            }
        }
        let registration = frost_action_registration(self.domain).ok_or(
            FrostVerificationError::SlotMismatch("checkpoint domain is disabled"),
        )?;
        if self.ladder_action_class != registration.ladder_action_class {
            return Err(FrostVerificationError::SlotMismatch(
                "checkpoint domain and ladder class",
            ));
        }
        validate_identifier(&self.resource_id, "resource_id")?;
        validate_positive_safe_integer(self.resource_version, "resource_version")?;
        validate_positive_safe_integer(self.resource_fence, "resource_fence")?;
        validate_digest(&self.authorization_id, "authorization_id")?;
        validate_digest(&self.signing_message_digest, "signing_message_digest")?;
        validate_digest(&self.action_digest, "action_digest")?;
        validate_digest(&self.roster_digest, "roster_digest")?;
        validate_positive_safe_integer(self.key_epoch, "key_epoch")?;
        validate_digest(&self.session_id, "session_id")?;
        validate_positive_safe_integer(self.clock_high_water, "clock_high_water")?;
        validate_identifier(&self.anchor_key_id, "anchor_key_id")?;
        validate_fixed_hex(&self.anchor_signature, 128, "anchor_signature")?;

        let expected_slot_id = slot_id_from_parts(
            self.domain,
            &self.scope_id,
            &self.resource_id,
            self.resource_version,
            self.resource_fence,
        )?;
        if self.slot_id != expected_slot_id {
            return Err(FrostVerificationError::SlotMismatch("checkpoint slot id"));
        }
        let expected_session_id = session_id_from_parts(
            &self.authorization_id,
            &self.signing_message_digest,
            &self.roster_digest,
        )?;
        if self.session_id != expected_session_id {
            return Err(FrostVerificationError::SlotMismatch(
                "checkpoint session id",
            ));
        }

        match self.state {
            FrostAuthorizationSlotState::Bound | FrostAuthorizationSlotState::Burned => {
                if self.aggregate_signature_digest.is_some()
                    || self.authorization_blob_digest.is_some()
                    || self.availability_receipt.is_some()
                {
                    return Err(FrostVerificationError::SlotMismatch(
                        "non-completed checkpoint carries completion data",
                    ));
                }
            }
            FrostAuthorizationSlotState::Completed => {
                validate_digest(
                    self.aggregate_signature_digest.as_deref().ok_or(
                        FrostVerificationError::SlotMismatch(
                            "completed checkpoint lacks signature digest",
                        ),
                    )?,
                    "aggregate_signature_digest",
                )?;
                validate_digest(
                    self.authorization_blob_digest.as_deref().ok_or(
                        FrostVerificationError::SlotMismatch(
                            "completed checkpoint lacks authorization blob digest",
                        ),
                    )?,
                    "authorization_blob_digest",
                )?;
                validate_identifier(
                    self.availability_receipt.as_deref().ok_or(
                        FrostVerificationError::SlotMismatch(
                            "completed checkpoint lacks availability receipt",
                        ),
                    )?,
                    "availability_receipt",
                )?;
            }
        }
        if self.recompute_checkpoint_digest()? != self.checkpoint_digest {
            return Err(FrostVerificationError::SlotMismatch(
                "checkpoint digest does not match canonical signed artifact",
            ));
        }
        Ok(())
    }

    fn signing_preimage(&self) -> FrostAuthorizationSlotCheckpointSigningPreimage<'_> {
        FrostAuthorizationSlotCheckpointSigningPreimage {
            schema: &self.schema,
            anchor_id: &self.anchor_id,
            scope_id: &self.scope_id,
            slot_id: &self.slot_id,
            slot_version: self.slot_version,
            predecessor_digest: self.predecessor_digest.as_deref(),
            domain: self.domain,
            ladder_action_class: &self.ladder_action_class,
            resource_id: &self.resource_id,
            resource_version: self.resource_version,
            resource_fence: self.resource_fence,
            authorization_id: &self.authorization_id,
            signing_message_digest: &self.signing_message_digest,
            action_digest: &self.action_digest,
            roster_digest: &self.roster_digest,
            key_epoch: self.key_epoch,
            session_id: &self.session_id,
            state: self.state,
            aggregate_signature_digest: self.aggregate_signature_digest.as_deref(),
            authorization_blob_digest: self.authorization_blob_digest.as_deref(),
            availability_receipt: self.availability_receipt.as_deref(),
            clock_high_water: self.clock_high_water,
            anchor_key_id: &self.anchor_key_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostAnchoredAuthorizationSlot {
    pub checkpoint: FrostAuthorizationSlotCheckpointV1,
    pub authorization_blob: Option<Vec<u8>>,
}

pub trait FrostAuthorizationSlotAnchor: Send + Sync {
    /// Return the current slot and its rollback-independent content.
    ///
    /// The caller verifies its pinned anchor authority and canonical content.
    fn resolve_authorization_slot(
        &self,
        scope_id: &str,
        slot_id: &str,
    ) -> Result<FrostAnchoredAuthorizationSlot, FrostAnchorError>;
}

#[derive(Debug, Clone)]
pub struct VerifiedFrostAuthorization {
    body: FrostAuthorizationBodyV1,
    authorization_slot_id: String,
    proof_digest: String,
}

impl VerifiedFrostAuthorization {
    #[must_use]
    pub fn authorization_id(&self) -> &str {
        &self.body.authorization_id
    }

    #[must_use]
    pub fn authorization_slot_id(&self) -> &str {
        &self.authorization_slot_id
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    #[must_use]
    pub fn ladder_action_class(&self) -> &str {
        &self.body.ladder_action_class
    }

    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.body.scope_id
    }

    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.body.resource_id
    }

    #[must_use]
    pub const fn domain(&self) -> FrostAuthorizationDomain {
        self.body.domain
    }

    #[must_use]
    pub const fn resource_version(&self) -> u64 {
        self.body.resource_version
    }

    #[must_use]
    pub const fn resource_fence(&self) -> u64 {
        self.body.resource_fence
    }

    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.body.action_digest
    }

    #[must_use]
    pub fn roster_digest(&self) -> &str {
        &self.body.roster_digest
    }

    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.body.key_epoch
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    #[must_use]
    pub const fn quorum_n(&self) -> u16 {
        self.body.quorum_n
    }

    #[must_use]
    pub const fn quorum_m(&self) -> u16 {
        self.body.quorum_m
    }

    #[must_use]
    pub fn quorum_scope(&self) -> &str {
        &self.body.quorum_scope
    }

    pub fn verify_action_preimage(
        &self,
        preimage: &super::action::FrostActionPreimageV1,
    ) -> Result<(), FrostAuthorizationError> {
        self.body.validate_action_preimage(preimage)
    }

    #[must_use]
    pub const fn is_current_at(&self, now: u64) -> bool {
        self.body.issued_at <= now && now < self.body.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct HistoricalFrostEvidence {
    body: FrostAuthorizationBodyV1,
    proof_digest: String,
}

impl HistoricalFrostEvidence {
    #[must_use]
    pub fn authorization_id(&self) -> &str {
        &self.body.authorization_id
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedHistoricalCompletedFrostAuthorization {
    body: FrostAuthorizationBodyV1,
    authorization_slot_id: String,
    proof_digest: String,
    completed_at: u64,
}

impl VerifiedHistoricalCompletedFrostAuthorization {
    #[must_use]
    pub fn authorization_id(&self) -> &str {
        &self.body.authorization_id
    }

    #[must_use]
    pub fn authorization_slot_id(&self) -> &str {
        &self.authorization_slot_id
    }

    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }

    #[must_use]
    pub fn scope_id(&self) -> &str {
        &self.body.scope_id
    }

    #[must_use]
    pub fn action_digest(&self) -> &str {
        &self.body.action_digest
    }

    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    #[must_use]
    pub const fn completed_at(&self) -> u64 {
        self.completed_at
    }

    pub fn verify_action_preimage(
        &self,
        preimage: &super::action::FrostActionPreimageV1,
    ) -> Result<(), FrostAuthorizationError> {
        self.body.validate_action_preimage(preimage)
    }
}

pub fn resolve_active_roster_for_execution(
    scope_id: &str,
    resolver: &dyn ActiveFrostRosterResolver,
    epoch_anchor: &dyn FrostEpochAnchor,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<VerifiedActiveFrostRoster, FrostVerificationError> {
    validate_identifier(scope_id, "scope_id")?;
    let roster =
        resolver
            .resolve_active_roster(scope_id)?
            .ok_or(FrostVerificationError::EpochMismatch(
                "active roster is absent",
            ))?;
    artifact_trust
        .verify_roster(&roster)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    roster.validate_for_active_resolution()?;
    if roster.scope_id != scope_id {
        return Err(FrostVerificationError::EpochMismatch(
            "resolver returned another scope",
        ));
    }
    if now < roster.valid_from || now >= roster.valid_until {
        return Err(FrostVerificationError::NotCurrent(
            "active roster validity window",
        ));
    }
    let scope_classification =
        resolver
            .classify_scope(scope_id)?
            .ok_or(FrostVerificationError::EpochMismatch(
                "scope classification is absent",
            ))?;
    if scope_classification != roster.authority_scope {
        return Err(FrostVerificationError::EpochMismatch(
            "trusted scope classification",
        ));
    }

    let checkpoint = epoch_anchor.resolve_epoch_checkpoint(scope_id)?;
    artifact_trust
        .verify_epoch_checkpoint(&checkpoint)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    if checkpoint.scope_id != roster.scope_id
        || checkpoint.active_roster_id != roster.roster_id
        || checkpoint.active_roster_digest != roster.roster_digest
        || checkpoint.key_epoch != roster.key_epoch
    {
        return Err(FrostVerificationError::EpochMismatch(
            "local roster and external checkpoint",
        ));
    }
    let group_key = decode_hex(&roster.group_public_key, "group_public_key")?;
    if checkpoint.group_public_key_digest != sha256_hex(&group_key) {
        return Err(FrostVerificationError::EpochMismatch(
            "group public key digest",
        ));
    }
    if now < checkpoint.clock_high_water {
        return Err(FrostVerificationError::NotCurrent(
            "clock is behind external epoch high-water",
        ));
    }
    Ok(VerifiedActiveFrostRoster { roster })
}

pub fn verify_for_execution(
    proof: &FrostAuthorizationV1,
    expected: &ExpectedFrostAuthorization<'_>,
    active_roster: &VerifiedActiveFrostRoster,
    epoch_anchor: &dyn FrostEpochAnchor,
    slot_anchor: &dyn FrostAuthorizationSlotAnchor,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<VerifiedFrostAuthorization, FrostVerificationError> {
    proof.validate()?;
    verify_expected(&proof.body, expected)?;
    if now < proof.body.issued_at || now >= proof.body.expires_at {
        return Err(FrostVerificationError::NotCurrent(
            "authorization validity window",
        ));
    }
    if now < active_roster.roster.valid_from || now >= active_roster.roster.valid_until {
        return Err(FrostVerificationError::NotCurrent(
            "active roster validity window",
        ));
    }
    verify_current_epoch(active_roster, epoch_anchor, artifact_trust, now)?;
    verify_roster_binding(proof, &active_roster.roster)?;
    verify_completed_slot(proof, slot_anchor, artifact_trust, now)?;
    verify_group_signature(proof, &active_roster.roster)?;
    let canonical = proof.canonical_bytes()?;
    Ok(VerifiedFrostAuthorization {
        body: proof.body.clone(),
        authorization_slot_id: frost_authorization_slot_id(&proof.body)?,
        proof_digest: sha256_hex(&canonical),
    })
}

pub fn verify_historical_evidence(
    proof: &FrostAuthorizationV1,
    resolver: &dyn FrostHistoricalRosterResolver,
    artifact_trust: &FrostArtifactTrustStore,
) -> Result<HistoricalFrostEvidence, FrostVerificationError> {
    proof.validate()?;
    let roster = resolver
        .resolve_historical_roster(
            &proof.body.roster_digest,
            proof.body.key_epoch,
            proof.body.issued_at,
        )?
        .ok_or(FrostVerificationError::EpochMismatch(
            "historical roster is absent",
        ))?;
    artifact_trust
        .verify_roster(&roster)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    if proof.body.issued_at < roster.valid_from || proof.body.issued_at >= roster.valid_until {
        return Err(FrostVerificationError::NotCurrent(
            "historical roster at authorization issuance",
        ));
    }
    verify_roster_binding(proof, &roster)?;
    verify_group_signature(proof, &roster)?;
    let canonical = proof.canonical_bytes()?;
    Ok(HistoricalFrostEvidence {
        body: proof.body.clone(),
        proof_digest: sha256_hex(&canonical),
    })
}

pub fn verify_historical_completed_authorization(
    proof: &FrostAuthorizationV1,
    bound: &FrostAuthorizationSlotCheckpointV1,
    completed: &FrostAnchoredAuthorizationSlot,
    resolver: &dyn FrostHistoricalRosterResolver,
    artifact_trust: &FrostArtifactTrustStore,
) -> Result<VerifiedHistoricalCompletedFrostAuthorization, FrostVerificationError> {
    proof.validate()?;
    let roster = resolver
        .resolve_historical_roster(
            &proof.body.roster_digest,
            proof.body.key_epoch,
            proof.body.issued_at,
        )?
        .ok_or(FrostVerificationError::EpochMismatch(
            "historical roster is absent",
        ))?;
    artifact_trust
        .verify_roster(&roster)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    if proof.body.issued_at < roster.valid_from || proof.body.issued_at >= roster.valid_until {
        return Err(FrostVerificationError::NotCurrent(
            "historical roster at authorization issuance",
        ));
    }
    let completed_at = completed.checkpoint.clock_high_water;
    if proof.body.issued_at > completed_at
        || completed_at >= proof.body.expires_at
        || completed_at < roster.valid_from
        || completed_at >= roster.valid_until
    {
        return Err(FrostVerificationError::NotCurrent(
            "historical authorization completion window",
        ));
    }
    verify_roster_binding(proof, &roster)?;
    verify_group_signature(proof, &roster)?;
    artifact_trust
        .verify_authorization_slot_checkpoint(bound)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    verify_completed_slot_artifact(proof, completed, artifact_trust, completed_at)?;
    let checkpoint = &completed.checkpoint;
    if bound.state != FrostAuthorizationSlotState::Bound
        || bound.slot_version != 1
        || bound.predecessor_digest.is_some()
        || bound.aggregate_signature_digest.is_some()
        || bound.authorization_blob_digest.is_some()
        || bound.availability_receipt.is_some()
        || checkpoint.slot_version != 2
        || checkpoint.predecessor_digest.as_deref() != Some(bound.checkpoint_digest.as_str())
        || checkpoint.schema != bound.schema
        || checkpoint.anchor_id != bound.anchor_id
        || checkpoint.anchor_key_id != bound.anchor_key_id
        || checkpoint.scope_id != bound.scope_id
        || checkpoint.slot_id != bound.slot_id
        || checkpoint.domain != bound.domain
        || checkpoint.ladder_action_class != bound.ladder_action_class
        || checkpoint.resource_id != bound.resource_id
        || checkpoint.resource_version != bound.resource_version
        || checkpoint.resource_fence != bound.resource_fence
        || checkpoint.authorization_id != bound.authorization_id
        || checkpoint.signing_message_digest != bound.signing_message_digest
        || checkpoint.action_digest != bound.action_digest
        || checkpoint.roster_digest != bound.roster_digest
        || checkpoint.key_epoch != bound.key_epoch
        || checkpoint.session_id != bound.session_id
        || checkpoint.clock_high_water < bound.clock_high_water
    {
        return Err(FrostVerificationError::SlotMismatch(
            "completed slot is not the exact bound-checkpoint successor",
        ));
    }
    let canonical = proof.canonical_bytes()?;
    Ok(VerifiedHistoricalCompletedFrostAuthorization {
        body: proof.body.clone(),
        authorization_slot_id: frost_authorization_slot_id(&proof.body)?,
        proof_digest: sha256_hex(&canonical),
        completed_at,
    })
}

pub fn frost_authorization_slot_id(
    body: &FrostAuthorizationBodyV1,
) -> Result<String, FrostVerificationError> {
    slot_id_from_parts(
        body.domain,
        &body.scope_id,
        &body.resource_id,
        body.resource_version,
        body.resource_fence,
    )
}

pub fn frost_authorization_session_id(
    body: &FrostAuthorizationBodyV1,
) -> Result<String, FrostVerificationError> {
    let signing_message = body.signing_bytes()?;
    session_id_from_parts(
        &body.authorization_id,
        &sha256_hex(&signing_message),
        &body.roster_digest,
    )
}

fn verify_expected(
    body: &FrostAuthorizationBodyV1,
    expected: &ExpectedFrostAuthorization<'_>,
) -> Result<(), FrostVerificationError> {
    let checks = [
        (body.domain == expected.domain, "domain"),
        (
            body.ladder_action_class == expected.ladder_action_class,
            "ladder_action_class",
        ),
        (
            body.ladder_contract_digest == expected.ladder_contract_digest,
            "ladder_contract_digest",
        ),
        (body.scope_id == expected.scope_id, "scope_id"),
        (body.resource_id == expected.resource_id, "resource_id"),
        (
            body.resource_version == expected.resource_version,
            "resource_version",
        ),
        (
            body.resource_fence == expected.resource_fence,
            "resource_fence",
        ),
        (
            body.action_digest == expected.action_digest,
            "action_digest",
        ),
    ];
    for (matches, field) in checks {
        if !matches {
            return Err(FrostVerificationError::ExpectedMismatch(field));
        }
    }
    Ok(())
}

pub(super) fn verify_roster_binding(
    proof: &FrostAuthorizationV1,
    roster: &FrostRosterV1,
) -> Result<(), FrostVerificationError> {
    if proof.suite_id != roster.suite_id
        || proof.body.scope_id != roster.scope_id
        || proof.body.roster_digest != roster.roster_digest
        || proof.body.key_epoch != roster.key_epoch
    {
        return Err(FrostVerificationError::EpochMismatch(
            "authorization and roster",
        ));
    }
    if !roster.allowed_domains.contains(&proof.body.domain) {
        return Err(FrostVerificationError::EpochMismatch(
            "roster does not allow authorization domain",
        ));
    }
    if proof.body.quorum_n != roster.threshold
        || proof.body.quorum_m != roster.participant_count
        || proof.body.quorum_scope != roster.authority_scope
    {
        return Err(FrostVerificationError::EpochMismatch(
            "authorization and roster quorum",
        ));
    }
    Ok(())
}

fn verify_completed_slot(
    proof: &FrostAuthorizationV1,
    slot_anchor: &dyn FrostAuthorizationSlotAnchor,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<(), FrostVerificationError> {
    let slot_id = frost_authorization_slot_id(&proof.body)?;
    let anchored = slot_anchor.resolve_authorization_slot(&proof.body.scope_id, &slot_id)?;
    verify_completed_slot_artifact(proof, &anchored, artifact_trust, now)
}

pub(super) fn verify_completed_slot_artifact(
    proof: &FrostAuthorizationV1,
    anchored: &FrostAnchoredAuthorizationSlot,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<(), FrostVerificationError> {
    let slot_id = frost_authorization_slot_id(&proof.body)?;
    artifact_trust
        .verify_authorization_slot_checkpoint(&anchored.checkpoint)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    let checkpoint = &anchored.checkpoint;
    if checkpoint.state != FrostAuthorizationSlotState::Completed {
        return Err(FrostVerificationError::SlotMismatch(
            "slot is not permanently completed",
        ));
    }
    if now < checkpoint.clock_high_water {
        return Err(FrostVerificationError::NotCurrent(
            "clock is behind authorization-slot high-water",
        ));
    }
    if checkpoint.scope_id != proof.body.scope_id
        || checkpoint.slot_id != slot_id
        || checkpoint.domain != proof.body.domain
        || checkpoint.ladder_action_class != proof.body.ladder_action_class
        || checkpoint.resource_id != proof.body.resource_id
        || checkpoint.resource_version != proof.body.resource_version
        || checkpoint.resource_fence != proof.body.resource_fence
        || checkpoint.authorization_id != proof.body.authorization_id
        || checkpoint.action_digest != proof.body.action_digest
        || checkpoint.roster_digest != proof.body.roster_digest
        || checkpoint.key_epoch != proof.body.key_epoch
    {
        return Err(FrostVerificationError::SlotMismatch(
            "completed slot and authorization body",
        ));
    }
    let signing_message = proof.body.signing_bytes()?;
    if checkpoint.signing_message_digest != sha256_hex(&signing_message) {
        return Err(FrostVerificationError::SlotMismatch(
            "signing message digest",
        ));
    }
    if checkpoint.session_id != frost_authorization_session_id(&proof.body)? {
        return Err(FrostVerificationError::SlotMismatch("session id"));
    }
    let signature = decode_hex(&proof.group_signature, "group_signature")?;
    let signature_digest = sha256_hex(&signature);
    if checkpoint.aggregate_signature_digest.as_deref() != Some(signature_digest.as_str()) {
        return Err(FrostVerificationError::SlotMismatch(
            "aggregate signature digest",
        ));
    }
    let canonical = proof.canonical_bytes()?;
    let blob =
        anchored
            .authorization_blob
            .as_deref()
            .ok_or(FrostVerificationError::SlotMismatch(
                "completed slot lacks rollback-independent authorization blob",
            ))?;
    if blob != canonical {
        return Err(FrostVerificationError::SlotMismatch(
            "anchored authorization blob is not exact canonical proof",
        ));
    }
    let blob_digest = sha256_hex(blob);
    if checkpoint.authorization_blob_digest.as_deref() != Some(blob_digest.as_str()) {
        return Err(FrostVerificationError::SlotMismatch(
            "authorization blob digest",
        ));
    }
    Ok(())
}

pub(super) fn verify_current_epoch(
    active_roster: &VerifiedActiveFrostRoster,
    epoch_anchor: &dyn FrostEpochAnchor,
    artifact_trust: &FrostArtifactTrustStore,
    now: u64,
) -> Result<(), FrostVerificationError> {
    let checkpoint = epoch_anchor.resolve_epoch_checkpoint(&active_roster.roster.scope_id)?;
    artifact_trust
        .verify_epoch_checkpoint(&checkpoint)
        .map_err(|error| FrostVerificationError::ArtifactTrust(error.to_string()))?;
    if checkpoint.scope_id != active_roster.roster.scope_id
        || checkpoint.active_roster_id != active_roster.roster.roster_id
        || checkpoint.active_roster_digest != active_roster.roster.roster_digest
        || checkpoint.key_epoch != active_roster.roster.key_epoch
    {
        return Err(FrostVerificationError::EpochMismatch(
            "active roster changed after resolution",
        ));
    }
    if now < checkpoint.clock_high_water {
        return Err(FrostVerificationError::NotCurrent(
            "clock is behind external epoch high-water",
        ));
    }
    Ok(())
}

pub(super) fn verify_group_signature(
    proof: &FrostAuthorizationV1,
    roster: &FrostRosterV1,
) -> Result<(), FrostVerificationError> {
    let verifying_key =
        VerifyingKey::deserialize(&decode_hex(&roster.group_public_key, "group_public_key")?)
            .map_err(|_| FrostVerificationError::InvalidGroupSignature)?;
    let signature = Signature::deserialize(&decode_hex(&proof.group_signature, "group_signature")?)
        .map_err(|_| FrostVerificationError::InvalidGroupSignature)?;
    let signing_message = proof.body.signing_bytes()?;
    verifying_key
        .verify(&signing_message, &signature)
        .map_err(|_| FrostVerificationError::InvalidGroupSignature)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostAuthorizationSlotIdPreimage<'a> {
    domain: FrostAuthorizationDomain,
    scope_id: &'a str,
    resource_id: &'a str,
    resource_version: u64,
    resource_fence: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FrostAuthorizationSessionIdPreimage<'a> {
    authorization_id: &'a str,
    signing_message_digest: &'a str,
    roster_digest: &'a str,
}

fn slot_id_from_parts(
    domain: FrostAuthorizationDomain,
    scope_id: &str,
    resource_id: &str,
    resource_version: u64,
    resource_fence: u64,
) -> Result<String, FrostVerificationError> {
    canonical_identifier(
        CHIO_FROST_AUTHORIZATION_SLOT_ID_PREFIX,
        &FrostAuthorizationSlotIdPreimage {
            domain,
            scope_id,
            resource_id,
            resource_version,
            resource_fence,
        },
    )
}

fn session_id_from_parts(
    authorization_id: &str,
    signing_message_digest: &str,
    roster_digest: &str,
) -> Result<String, FrostVerificationError> {
    canonical_identifier(
        CHIO_FROST_AUTHORIZATION_SESSION_ID_PREFIX,
        &FrostAuthorizationSessionIdPreimage {
            authorization_id,
            signing_message_digest,
            roster_digest,
        },
    )
}

fn canonical_identifier<T: Serialize>(
    prefix: &[u8],
    value: &T,
) -> Result<String, FrostVerificationError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|_| FrostVerificationError::InvalidProof("canonical identifier preimage"))?;
    let mut bytes = Vec::with_capacity(prefix.len() + canonical.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_hex(&bytes))
}

fn canonical_prefixed_bytes<T: Serialize>(
    prefix: &[u8],
    value: &T,
) -> Result<Vec<u8>, FrostVerificationError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| FrostVerificationError::Canonical(error.to_string()))?;
    let mut bytes = Vec::with_capacity(prefix.len() + canonical.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn decode_hex(value: &str, field: &'static str) -> Result<Vec<u8>, FrostVerificationError> {
    hex::decode(value).map_err(|_| FrostVerificationError::InvalidProof(field))
}

fn validate_fixed_hex(
    value: &str,
    length: usize,
    field: &'static str,
) -> Result<(), FrostAuthorizationError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FrostAuthorizationError::InvalidField {
            field,
            detail: "must have the required lowercase hexadecimal encoding",
        });
    }
    Ok(())
}
