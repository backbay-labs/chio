use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::canonical::canonical_json_bytes;
use chio_core::economic_continuity::{
    economic_effect_slot_from_head, verify_economic_completed_effect,
    verify_economic_state_batch_commit, EconomicAdmissionHandoffStateV1, EconomicContentV1,
    EconomicContinuityError, EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTerminalV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError,
    EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
    EconomicTerminalResultV1, VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView,
    MAX_ECONOMIC_BATCH_BYTES,
};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_credit::clearing::CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND;
use chio_kernel::admission_operation::{
    verify_economic_cancellation_terminal_advance, AdmissionOperationState, AdmissionOperationV1,
    AdmissionProjectionRecordKind, AdmissionRecoveryLease, PersistedAdmissionOperationV1,
    SignedAdmissionTerminalProjectionV1, VerifiedAdmissionTerminalProjectionV1,
};
use chio_kernel::ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND;
use chio_settle::channel::{
    CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY, CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
    CHANNEL_SERVICE_DISPATCH_EFFECT_KIND, CHANNEL_TRANSITION_REPLAY_FORMAT,
};
use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};

mod persistence;
pub(crate) use persistence::verify_cache_sql_invariants;
use persistence::*;
pub(crate) use persistence::{append_stage_commit, load_stage_tx, update_stage};

const ECONOMIC_STATE_CACHE_SCHEMA_KEY: &str = "economic_state_cache";
pub(crate) const ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION: i32 = 3;
const ECONOMIC_STATE_CACHE_SCHEMA_ANCHORS: &[&str] =
    &["economic_state_stages", "capability_grant_budgets"];
const MAX_REASON_BYTES: usize = 4 * 1024;
const MAX_VIEW_BYTES: usize = 4 * MAX_ECONOMIC_BATCH_BYTES;
const MAX_DESCRIPTOR_BYTES: usize = 4 * MAX_ECONOMIC_BATCH_BYTES;
const MAX_DESCRIPTOR_KIND_BYTES: usize = 128;
const MAX_DESCRIPTOR_KEY_BYTES: usize = 2_048;
const MAX_TRUSTED_UNIX_MS: u64 = (1_u64 << 53) - 1;
const GENESIS_STAGE_COMMIT_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
const ADMISSION_TERMINAL_EFFECT_RESULT_SCHEMA: &str = "chio.admission.terminal-effect-result.v1";

const ECONOMIC_STATE_CACHE_SCHEMA: &str = include_str!("economic_state_cache.sql");
const ECONOMIC_STATE_CACHE_DESCRIPTOR_MIGRATION: &str = r#"
ALTER TABLE economic_state_stages ADD COLUMN descriptor_kind TEXT
    CHECK (descriptor_kind IS NULL OR length(descriptor_kind) BETWEEN 1 AND 128);
ALTER TABLE economic_state_stages ADD COLUMN descriptor_key TEXT
    CHECK (descriptor_key IS NULL OR length(descriptor_key) BETWEEN 1 AND 2048);
ALTER TABLE economic_state_stages ADD COLUMN descriptor_digest TEXT
    CHECK (descriptor_digest IS NULL OR (
        length(descriptor_digest) = 64
        AND descriptor_digest NOT GLOB '*[^0-9a-f]*'
    ));
ALTER TABLE economic_state_stages ADD COLUMN descriptor_json BLOB
    CHECK (descriptor_json IS NULL OR length(descriptor_json) BETWEEN 1 AND 4194304);
DROP TRIGGER IF EXISTS economic_state_stage_identity_immutable;
CREATE TRIGGER economic_state_stage_identity_immutable
BEFORE UPDATE OF batch_id, checkpoint_sequence, checkpoint_digest,
    base_view_json, batch_json, operation_binding_json, descriptor_kind,
    descriptor_key, descriptor_digest, descriptor_json, created_at_unix_ms
ON economic_state_stages
BEGIN
    SELECT RAISE(ABORT, 'economic stage identity is immutable');
END;
"#;

#[derive(Debug, thiserror::Error)]
pub enum EconomicStateCacheError {
    #[error("economic state cache is unavailable: {0}")]
    Unavailable(String),
    #[error("economic state cache mutation was fenced")]
    Fenced,
    #[error("economic state stage was not found")]
    NotFound,
    #[error("economic state stage conflicts with retained state")]
    Conflict,
    #[error("economic state stage transition from {from:?} to {to:?} is invalid")]
    InvalidTransition {
        from: EconomicStateStageStatus,
        to: EconomicStateStageStatus,
    },
    #[error("economic state cache invariant failed: {0}")]
    Invariant(String),
    #[error("economic state cache durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error(transparent)]
    Continuity(#[from] EconomicContinuityError),
    #[error(transparent)]
    Anchor(#[from] EconomicStateAnchorError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EconomicStateStageStatus {
    DbStaged,
    EconomicAnchorAdvanced,
    DbFinalized,
    Discarded,
    Quarantined,
}

impl EconomicStateStageStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::DbStaged => "db_staged",
            Self::EconomicAnchorAdvanced => "economic_anchor_advanced",
            Self::DbFinalized => "db_finalized",
            Self::Discarded => "discarded",
            Self::Quarantined => "quarantined",
        }
    }

    fn parse(value: &str) -> Result<Self, EconomicStateCacheError> {
        match value {
            "db_staged" => Ok(Self::DbStaged),
            "economic_anchor_advanced" => Ok(Self::EconomicAnchorAdvanced),
            "db_finalized" => Ok(Self::DbFinalized),
            "discarded" => Ok(Self::Discarded),
            "quarantined" => Ok(Self::Quarantined),
            _ => Err(invariant("economic stage status is invalid")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EconomicOperationStageBinding {
    operation_id: String,
    operation_state: AdmissionOperationState,
    operation_version: u64,
    coordinator_lease_epoch: u64,
    coordinator_lease_id: String,
    recovery_claimant_id: String,
    recovery_expires_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_after_unix_ms: Option<u64>,
    store_fence: StoreMutationFence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicStateStageDescriptor {
    kind: String,
    key: String,
    digest: String,
    canonical_json: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionTerminalEffectRecordCommitment {
    kind: AdmissionProjectionRecordKind,
    record_id: String,
    record_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionTerminalEffectCommitment {
    schema: &'static str,
    descriptor_digest: String,
    operation_id: String,
    request_id: String,
    source_operation_digest: String,
    terminal_operation_digest: String,
    terminal_state: AdmissionOperationState,
    projection_digest: String,
    records: Vec<AdmissionTerminalEffectRecordCommitment>,
}

impl EconomicStateStageDescriptor {
    pub fn new<T: Serialize>(
        kind: impl Into<String>,
        key: impl Into<String>,
        value: &T,
    ) -> Result<Self, EconomicStateCacheError> {
        let descriptor = Self {
            kind: kind.into(),
            key: key.into(),
            digest: String::new(),
            canonical_json: canonical_bounded(value, MAX_DESCRIPTOR_BYTES, "stage descriptor")?,
        };
        descriptor.with_digest()
    }

    fn from_stored(
        kind: String,
        key: String,
        digest: String,
        canonical_json: Vec<u8>,
    ) -> Result<Self, EconomicStateCacheError> {
        let descriptor = Self {
            kind,
            key,
            digest,
            canonical_json,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    fn with_digest(mut self) -> Result<Self, EconomicStateCacheError> {
        self.digest = sha256_hex(&self.canonical_json);
        self.validate()?;
        Ok(self)
    }

    fn validate(&self) -> Result<(), EconomicStateCacheError> {
        validate_descriptor_text(
            &self.kind,
            MAX_DESCRIPTOR_KIND_BYTES,
            "stage descriptor kind",
        )?;
        validate_descriptor_text(&self.key, MAX_DESCRIPTOR_KEY_BYTES, "stage descriptor key")?;
        validate_digest(&self.digest, "stage descriptor digest")?;
        if self.canonical_json.is_empty()
            || self.canonical_json.len() > MAX_DESCRIPTOR_BYTES
            || sha256_hex(&self.canonical_json) != self.digest
        {
            return Err(invariant("economic stage descriptor is invalid"));
        }
        decode_exact::<serde_json::Value>(&self.canonical_json, "stage descriptor")?;
        Ok(())
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn decode<T: DeserializeOwned + Serialize>(&self) -> Result<T, EconomicStateCacheError> {
        self.validate()?;
        decode_exact(&self.canonical_json, "stage descriptor")
    }
}

impl EconomicOperationStageBinding {
    fn validate(&self) -> Result<(), EconomicStateCacheError> {
        if self.operation_id.is_empty()
            || self.coordinator_lease_id.is_empty()
            || self.recovery_claimant_id.is_empty()
            || self.store_fence.store_uuid.is_empty()
            || self.store_fence.lease_id.is_empty()
        {
            return Err(invariant("economic operation binding identity is invalid"));
        }
        if self.operation_version == 0 || self.operation_version > MAX_TRUSTED_UNIX_MS {
            return Err(invariant(
                "economic operation binding operation_version is invalid",
            ));
        }
        if self.coordinator_lease_epoch == 0 || self.coordinator_lease_epoch > MAX_TRUSTED_UNIX_MS {
            return Err(invariant(
                "economic operation binding coordinator_lease_epoch is invalid",
            ));
        }
        if self.recovery_expires_at_unix_ms == 0
            || self.recovery_expires_at_unix_ms > MAX_TRUSTED_UNIX_MS
        {
            return Err(invariant(
                "economic operation binding recovery_expires_at_unix_ms is invalid",
            ));
        }
        if self
            .not_after_unix_ms
            .is_some_and(|value| value == 0 || value > MAX_TRUSTED_UNIX_MS)
        {
            return Err(invariant(
                "economic operation binding not_after_unix_ms is invalid",
            ));
        }
        if self.store_fence.owner_epoch == 0 || self.store_fence.owner_epoch > MAX_TRUSTED_UNIX_MS {
            return Err(invariant(
                "economic operation binding store fence is invalid",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    #[must_use]
    pub fn operation_state(&self) -> AdmissionOperationState {
        self.operation_state
    }

    #[must_use]
    pub fn operation_version(&self) -> u64 {
        self.operation_version
    }

    #[must_use]
    pub fn coordinator_lease_epoch(&self) -> u64 {
        self.coordinator_lease_epoch
    }

    #[must_use]
    pub fn coordinator_lease_id(&self) -> &str {
        &self.coordinator_lease_id
    }

    #[must_use]
    pub fn recovery_claimant_id(&self) -> &str {
        &self.recovery_claimant_id
    }

    #[must_use]
    pub const fn recovery_expires_at_unix_ms(&self) -> u64 {
        self.recovery_expires_at_unix_ms
    }

    #[must_use]
    pub const fn not_after_unix_ms(&self) -> Option<u64> {
        self.not_after_unix_ms
    }

    #[must_use]
    pub const fn store_fence(&self) -> &StoreMutationFence {
        &self.store_fence
    }
}

#[derive(Clone, Copy)]
pub struct EconomicOperationStageContext<'a> {
    operation: &'a AdmissionOperationV1,
    recovery_lease: &'a AdmissionRecoveryLease,
    not_after_unix_ms: Option<u64>,
}

pub(crate) struct EconomicStageAdmissionCheckpoint<'a> {
    pub(crate) store_id: &'a str,
    pub(crate) sequence: u64,
    pub(crate) digest: &'a str,
}

struct EconomicStageOptions<'a> {
    operation: Option<EconomicOperationStageContext<'a>>,
    descriptor: Option<EconomicStateStageDescriptor>,
    admission_checkpoint: Option<EconomicStageAdmissionCheckpoint<'a>>,
    consumer_descriptor_kind: Option<&'static str>,
}

impl<'a> EconomicOperationStageContext<'a> {
    #[must_use]
    pub const fn new(
        operation: &'a AdmissionOperationV1,
        recovery_lease: &'a AdmissionRecoveryLease,
    ) -> Self {
        Self {
            operation,
            recovery_lease,
            not_after_unix_ms: None,
        }
    }

    pub fn with_not_after_unix_ms(
        mut self,
        not_after_unix_ms: u64,
    ) -> Result<Self, EconomicStateCacheError> {
        validate_trusted_time(not_after_unix_ms)?;
        self.not_after_unix_ms = Some(not_after_unix_ms);
        Ok(self)
    }

    #[must_use]
    pub const fn operation(&self) -> &'a AdmissionOperationV1 {
        self.operation
    }

    #[must_use]
    pub const fn recovery_lease(&self) -> &'a AdmissionRecoveryLease {
        self.recovery_lease
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicStateStageRecord {
    base_view: EconomicStateAnchorViewV1,
    batch: EconomicStateBatchV1,
    committed_view: Option<EconomicStateAnchorViewV1>,
    operation_binding: Option<EconomicOperationStageBinding>,
    descriptor: Option<EconomicStateStageDescriptor>,
    status: EconomicStateStageStatus,
    reason: Option<String>,
    version: u64,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    snapshot_digest: String,
}

impl EconomicStateStageRecord {
    #[must_use]
    pub fn base_view(&self) -> &EconomicStateAnchorViewV1 {
        &self.base_view
    }

    #[must_use]
    pub fn batch(&self) -> &EconomicStateBatchV1 {
        &self.batch
    }

    #[must_use]
    pub fn committed_view(&self) -> Option<&EconomicStateAnchorViewV1> {
        self.committed_view.as_ref()
    }

    #[must_use]
    pub fn operation_binding(&self) -> Option<&EconomicOperationStageBinding> {
        self.operation_binding.as_ref()
    }

    #[must_use]
    pub fn not_after_unix_ms(&self) -> Option<u64> {
        self.operation_binding
            .as_ref()
            .and_then(EconomicOperationStageBinding::not_after_unix_ms)
    }

    #[must_use]
    pub fn descriptor(&self) -> Option<&EconomicStateStageDescriptor> {
        self.descriptor.as_ref()
    }

    #[must_use]
    pub fn status(&self) -> EconomicStateStageStatus {
        self.status
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }
}

pub fn admission_terminal_projection_effect_result(
    envelope: &SignedAdmissionTerminalProjectionV1,
) -> Result<EconomicEffectTerminalV1, EconomicStateCacheError> {
    let verified = envelope
        .verify()
        .map_err(|_| EconomicStateCacheError::Conflict)?;
    let descriptor = admission_terminal_projection_descriptor(envelope, &verified)?;
    terminal_projection_effect_result(&descriptor, &verified)
}

fn admission_terminal_projection_descriptor(
    envelope: &SignedAdmissionTerminalProjectionV1,
    verified: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<EconomicStateStageDescriptor, EconomicStateCacheError> {
    EconomicStateStageDescriptor::new(
        ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND,
        verified
            .source_operation()
            .binding()
            .operation_id()
            .as_str(),
        envelope,
    )
}

fn terminal_projection_effect_result(
    descriptor: &EconomicStateStageDescriptor,
    verified: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<EconomicEffectTerminalV1, EconomicStateCacheError> {
    let source = verified.source_operation();
    let terminal = verified.terminal_operation();
    let projection_digest = terminal
        .terminal_replay()
        .ok_or(EconomicStateCacheError::Conflict)?
        .projection_digest()
        .as_str()
        .to_owned();
    let source_operation_digest =
        sha256_hex(&canonical_json_bytes(&source.to_persisted()).map_err(canonical_error)?);
    let terminal_operation_digest =
        sha256_hex(&canonical_json_bytes(&terminal.to_persisted()).map_err(canonical_error)?);
    let commitment = AdmissionTerminalEffectCommitment {
        schema: ADMISSION_TERMINAL_EFFECT_RESULT_SCHEMA,
        descriptor_digest: descriptor.digest().to_owned(),
        operation_id: source.binding().operation_id().as_str().to_owned(),
        request_id: source.replay_key().request_id.as_str().to_owned(),
        source_operation_digest,
        terminal_operation_digest,
        terminal_state: terminal.state(),
        projection_digest: projection_digest.clone(),
        records: verified
            .records()
            .iter()
            .map(|record| AdmissionTerminalEffectRecordCommitment {
                kind: record.kind(),
                record_id: record.record_id().as_str().to_owned(),
                record_digest: record.record_digest().as_str().to_owned(),
            })
            .collect(),
    };
    let result = EconomicContentV1::Inline {
        value: serde_json::to_value(commitment).map_err(canonical_error)?,
    };
    Ok(EconomicEffectTerminalV1::Completed {
        result_id: projection_digest,
        result_digest: result.digest()?,
        result,
    })
}

fn qualify_generic_terminal_projection_effect_slot(
    base_view: &EconomicStateAnchorViewV1,
    batch: &EconomicStateBatchV1,
    descriptor: &EconomicStateStageDescriptor,
    verified: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<EconomicEffectSlotV1, EconomicStateCacheError> {
    if batch.transitions.len() != 1
        || !batch.effect_slots.is_empty()
        || !batch.request_replays.is_empty()
        || batch.transitions[0].prepared_effect.is_some()
    {
        return Err(EconomicStateCacheError::Conflict);
    }
    let transition = &batch.transitions[0];
    if transition.resource_key.resource_family != "effect_slot" {
        return Err(EconomicStateCacheError::Conflict);
    }
    let current_head = base_view
        .head(&transition.resource_key)
        .ok_or(EconomicStateCacheError::Conflict)?;
    let current_slot = economic_effect_slot_from_head(current_head)
        .map_err(|_| EconomicStateCacheError::Conflict)?;
    let completed_slot = economic_effect_slot_from_head(&transition.next_head)
        .map_err(|_| EconomicStateCacheError::Conflict)?;
    current_slot
        .validate_successor(&completed_slot)
        .map_err(|_| EconomicStateCacheError::Conflict)?;
    if completed_slot.state == EconomicEffectStateV1::NoEffect {
        return verify_economic_cancellation_terminal_advance(base_view, batch, verified)
            .map_err(|_| EconomicStateCacheError::Conflict);
    }
    let source = verified.source_operation();
    let binding = source.binding();
    let dispatch_commit = source
        .dispatch_commit()
        .ok_or(EconomicStateCacheError::Conflict)?;
    let expected_terminal = terminal_projection_effect_result(descriptor, verified)?;
    let expected_result = match &expected_terminal {
        EconomicEffectTerminalV1::Completed {
            result_id,
            result_digest,
            result,
        } => EconomicTerminalResultV1 {
            result_id: result_id.clone(),
            result_digest: result_digest.clone(),
            result: result.clone(),
        },
        EconomicEffectTerminalV1::NoEffect { .. } => return Err(EconomicStateCacheError::Conflict),
    };
    if current_slot.state != EconomicEffectStateV1::DispatchCommitted
        && current_slot.state != EconomicEffectStateV1::Unknown
        || completed_slot.state != EconomicEffectStateV1::Completed
        || completed_slot.terminal.as_ref() != Some(&expected_terminal)
        || completed_slot.operation_id != binding.operation_id().as_str()
        || completed_slot.request.request_namespace_digest
            != binding.request_namespace_digest().as_str()
        || completed_slot.request.request_id != binding.request_id().as_str()
        || completed_slot.request.request_binding_digest != binding.request_binding_hash().as_str()
        || completed_slot.parameters_digest != binding.action_parameter_hash().as_str()
        || completed_slot.admission_handoff.state
            != EconomicAdmissionHandoffStateV1::DispatchCommitted
        || completed_slot.admission_handoff.operation_version != dispatch_commit.committed_version
        || completed_slot.admission_handoff.lifecycle_fence
            != dispatch_commit.coordinator_lease_epoch
        || completed_slot.admission_handoff.store_fence != dispatch_commit.store_fence
        || !current_fence_serves_historical(
            &dispatch_commit.store_fence,
            &verified.context().store_fence,
        )
        || batch.operation_id.as_deref() != Some(binding.operation_id().as_str())
        || transition.next_head.lifecycle_state != "completed"
        || transition.next_head.terminal_result.as_ref() != Some(&expected_result)
    {
        return Err(EconomicStateCacheError::Conflict);
    }
    Ok(completed_slot)
}

fn qualify_terminal_projection_advance(
    advance: &VerifiedEconomicStateBatchAdvance,
    descriptor: &EconomicStateStageDescriptor,
    verified: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<EconomicEffectSlotV1, EconomicStateCacheError> {
    match verified.channel_terminal() {
        Some(channel) => channel
            .qualify_anchored_advance(advance)
            .cloned()
            .map_err(|_| EconomicStateCacheError::Conflict),
        None => qualify_generic_terminal_projection_effect_slot(
            advance.current().view(),
            advance.batch(),
            descriptor,
            verified,
        ),
    }
}

fn qualify_retained_terminal_projection_advance(
    base_view: &EconomicStateAnchorViewV1,
    batch: &EconomicStateBatchV1,
    descriptor: &EconomicStateStageDescriptor,
    verified: &VerifiedAdmissionTerminalProjectionV1,
) -> Result<EconomicEffectSlotV1, EconomicStateCacheError> {
    match verified.channel_terminal() {
        Some(channel) => channel
            .qualify_retained_anchored_advance(base_view, batch)
            .cloned()
            .map_err(|_| EconomicStateCacheError::Conflict),
        None => {
            qualify_generic_terminal_projection_effect_slot(base_view, batch, descriptor, verified)
        }
    }
}

fn committed_view_matches_batch(
    committed: &EconomicStateAnchorViewV1,
    batch: &EconomicStateBatchV1,
) -> bool {
    batch
        .transitions
        .iter()
        .all(|transition| committed.head(&transition.resource_key) == Some(&transition.next_head))
}

fn batch_contains_channel_content(batch: &EconomicStateBatchV1) -> bool {
    batch.transitions.iter().any(|transition| {
        matches!(
            transition.resource_key.resource_family.as_str(),
            CHANNEL_LIFECYCLE_RESOURCE_FAMILY | CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY
        )
    }) || batch
        .effect_slots
        .iter()
        .any(|effect| effect.effect_kind == CHANNEL_SERVICE_DISPATCH_EFFECT_KIND)
}

fn is_protected_channel_stage(record: &EconomicStateStageRecord) -> bool {
    record
        .descriptor
        .as_ref()
        .is_some_and(|descriptor| descriptor.kind == CHANNEL_TRANSITION_REPLAY_FORMAT)
        || batch_contains_channel_content(&record.batch)
}

fn validate_stage_options(
    batch: &EconomicStateBatchV1,
    options: &EconomicStageOptions<'_>,
) -> Result<(), EconomicStateCacheError> {
    if let Some(descriptor) = &options.descriptor {
        descriptor.validate()?;
        let reserved = matches!(
            descriptor.kind(),
            CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND
                | ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
                | CHANNEL_TRANSITION_REPLAY_FORMAT
        );
        if reserved != (options.consumer_descriptor_kind == Some(descriptor.kind()))
            || options
                .consumer_descriptor_kind
                .is_some_and(|kind| kind != descriptor.kind())
        {
            return Err(EconomicStateCacheError::Conflict);
        }
    } else if options.consumer_descriptor_kind.is_some() {
        return Err(EconomicStateCacheError::Conflict);
    }
    let channel_content = batch_contains_channel_content(batch);
    let channel_consumer = matches!(
        options.consumer_descriptor_kind,
        Some(CHANNEL_TRANSITION_REPLAY_FORMAT | ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND)
    );
    let reservation_consumer =
        options.consumer_descriptor_kind == Some(CHANNEL_TRANSITION_REPLAY_FORMAT);
    if channel_content && !channel_consumer || !channel_content && reservation_consumer {
        return Err(EconomicStateCacheError::Conflict);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn stage_channel_batch_in_transaction(
    transaction: &Transaction<'_>,
    advance: &VerifiedEconomicStateBatchAdvance,
    operation: EconomicOperationStageContext<'_>,
    descriptor: EconomicStateStageDescriptor,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
    serving_owner: &SqliteServingOwner,
) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
    validate_trusted_time(trusted_now_unix_ms)?;
    let options = EconomicStageOptions {
        operation: Some(operation),
        descriptor: Some(descriptor),
        admission_checkpoint: None,
        consumer_descriptor_kind: Some(CHANNEL_TRANSITION_REPLAY_FORMAT),
    };
    validate_stage_options(advance.batch(), &options)?;
    stage_batch_in_transaction(
        transaction,
        advance,
        options,
        active_fence,
        trusted_now_unix_ms,
        serving_owner,
    )
}

pub(crate) fn record_channel_anchor_advanced_in_transaction(
    transaction: &Transaction<'_>,
    advance: &VerifiedEconomicStateBatchAdvance,
    committed: &VerifiedEconomicStateView,
    trusted_now_unix_ms: u64,
    serving_owner: &SqliteServingOwner,
) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
    validate_trusted_time(trusted_now_unix_ms)?;
    if !committed_view_matches_batch(committed.view(), advance.batch()) {
        return Err(EconomicStateCacheError::Conflict);
    }
    let committed_bytes = canonical_bounded(committed.view(), MAX_VIEW_BYTES, "committed view")?;
    let mut record = load_stage_tx(transaction, &advance.batch().batch_id)?
        .ok_or(EconomicStateCacheError::NotFound)?;
    if record.base_view != *advance.current().view()
        || record.batch != *advance.batch()
        || record
            .descriptor
            .as_ref()
            .is_none_or(|descriptor| descriptor.kind != CHANNEL_TRANSITION_REPLAY_FORMAT)
        || !is_protected_channel_stage(&record)
    {
        return Err(EconomicStateCacheError::Conflict);
    }
    if matches!(
        record.status,
        EconomicStateStageStatus::EconomicAnchorAdvanced | EconomicStateStageStatus::DbFinalized
    ) {
        return if record.committed_view.as_ref() == Some(committed.view()) {
            Ok(record)
        } else {
            Err(EconomicStateCacheError::Conflict)
        };
    }
    require_transition(
        record.status,
        EconomicStateStageStatus::EconomicAnchorAdvanced,
    )?;
    record.status = EconomicStateStageStatus::EconomicAnchorAdvanced;
    record.committed_view = Some(committed.view().clone());
    record.version = next_version(record.version)?;
    record.updated_at_unix_ms = monotonic_time(&record, trusted_now_unix_ms)?;
    record.snapshot_digest = stage_snapshot_digest(&record, &[])?;
    update_stage(
        transaction,
        &record,
        Some(committed_bytes),
        None,
        EconomicStateStageStatus::DbStaged,
    )?;
    append_stage_commit(
        transaction,
        &record,
        "channel_anchor_advanced",
        serving_owner,
    )?;
    Ok(record)
}

fn stage_batch_in_transaction(
    transaction: &Transaction<'_>,
    advance: &VerifiedEconomicStateBatchAdvance,
    options: EconomicStageOptions<'_>,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
    serving_owner: &SqliteServingOwner,
) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
    let EconomicStageOptions {
        operation,
        descriptor,
        admission_checkpoint,
        consumer_descriptor_kind: _,
    } = options;
    if let Some(existing) = load_stage_tx(transaction, &advance.batch().batch_id)? {
        if existing.base_view != *advance.current().view() || existing.batch != *advance.batch() {
            return Err(EconomicStateCacheError::Conflict);
        }
        let qualified = qualify_operation_binding(
            transaction,
            advance.batch(),
            operation,
            active_fence,
            trusted_now_unix_ms,
        )?;
        if qualified != existing.operation_binding || descriptor != existing.descriptor {
            return Err(EconomicStateCacheError::Conflict);
        }
        return Ok(existing);
    }
    if let Some(descriptor) = &descriptor {
        let retained_batch_id = transaction
            .query_row(
                r#"
                SELECT batch_id FROM economic_state_stages
                WHERE descriptor_kind = ?1 AND descriptor_key = ?2
                "#,
                params![descriptor.kind(), descriptor.key()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if retained_batch_id.is_some() {
            return Err(EconomicStateCacheError::Conflict);
        }
    }
    if let Some(checkpoint) = admission_checkpoint {
        verify_stage_admission_checkpoint(
            transaction,
            &checkpoint,
            active_fence,
            trusted_now_unix_ms,
        )?;
    }
    let operation_binding = qualify_operation_binding(
        transaction,
        advance.batch(),
        operation,
        active_fence,
        trusted_now_unix_ms,
    )?;
    let operation_binding_bytes = operation_binding
        .as_ref()
        .map(canonical_json_bytes)
        .transpose()
        .map_err(canonical_error)?;
    let mut record = EconomicStateStageRecord {
        base_view: advance.current().view().clone(),
        batch: advance.batch().clone(),
        committed_view: None,
        operation_binding,
        descriptor,
        status: EconomicStateStageStatus::DbStaged,
        reason: None,
        version: 1,
        created_at_unix_ms: trusted_now_unix_ms,
        updated_at_unix_ms: trusted_now_unix_ms,
        snapshot_digest: String::new(),
    };
    record.snapshot_digest = stage_snapshot_digest(&record, &[])?;
    let base_view_bytes = canonical_bounded(advance.current().view(), MAX_VIEW_BYTES, "base view")?;
    let batch_bytes = advance.batch().canonical_bytes()?;
    transaction
        .execute(
            r#"
            INSERT INTO economic_state_stages (
                batch_id, checkpoint_sequence, checkpoint_digest,
                base_view_json, batch_json, committed_view_json,
                operation_binding_json, descriptor_kind, descriptor_key,
                descriptor_digest, descriptor_json, status, reason,
                stage_version, snapshot_digest, created_at_unix_ms,
                updated_at_unix_ms
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, ?9, ?10,
                ?11, NULL, 1, ?12, ?13, ?13
            )
            "#,
            params![
                &record.batch.batch_id,
                sqlite_i64(record.batch.checkpoint_sequence, "checkpoint_sequence")?,
                &record.batch.checkpoint_digest,
                base_view_bytes,
                batch_bytes,
                operation_binding_bytes,
                record.descriptor.as_ref().map(|value| value.kind.as_str()),
                record.descriptor.as_ref().map(|value| value.key.as_str()),
                record
                    .descriptor
                    .as_ref()
                    .map(|value| value.digest.as_str()),
                record
                    .descriptor
                    .as_ref()
                    .map(|value| value.canonical_json.as_slice()),
                record.status.as_str(),
                &record.snapshot_digest,
                sqlite_i64(trusted_now_unix_ms, "trusted_now_unix_ms")?,
            ],
        )
        .map_err(sqlite_error)?;
    append_stage_commit(transaction, &record, "stage_batch", serving_owner)?;
    Ok(record)
}

#[derive(Clone)]
pub struct SqliteEconomicStateCache {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteEconomicStateCache {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, EconomicStateCacheError> {
        self.connection
            .lock()
            .map_err(|_| invariant("economic state cache lock is poisoned"))
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, EconomicStateCacheError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        verify_cache_sql_invariants(&transaction)?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: &StoreMutationFence,
    ) -> Result<Transaction<'a>, EconomicStateCacheError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence))?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(map_owner_error)?;
        verify_cache_sql_invariants(&transaction)?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), EconomicStateCacheError> {
        transaction.commit().map_err(|error| {
            map_owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite economic state cache commit outcome is unknown: {error}"
            )))
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), EconomicStateCacheError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(map_owner_error)
    }

    pub fn stage_batch(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        operation: Option<EconomicOperationStageContext<'_>>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        self.stage_batch_with_descriptor(
            advance,
            operation,
            None,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    pub fn stage_batch_with_descriptor(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        operation: Option<EconomicOperationStageContext<'_>>,
        descriptor: Option<EconomicStateStageDescriptor>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        self.stage_batch_inner(
            advance,
            EconomicStageOptions {
                operation,
                descriptor,
                admission_checkpoint: None,
                consumer_descriptor_kind: None,
            },
            active_fence,
            trusted_now_unix_ms,
        )
    }

    pub fn stage_admission_terminal_projection(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        operation: EconomicOperationStageContext<'_>,
        envelope: &SignedAdmissionTerminalProjectionV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let verified = envelope
            .verify()
            .map_err(|_| EconomicStateCacheError::Conflict)?;
        let descriptor = admission_terminal_projection_descriptor(envelope, &verified)?;
        let context = verified.context();
        let source = verified.source_operation();
        let lease = operation.recovery_lease;
        let expected_claimant = format!("kernel:{}", verified.signer_key().to_hex());
        if operation.operation != source
            || context.operation_id != *source.binding().operation_id()
            || context.request_id != source.replay_key().request_id
            || context.expected_operation_version != source.version()
            || context.coordinator_lease_id != *lease.coordinator_lease_id()
            || context.coordinator_lease_epoch != lease.coordinator_lease_epoch()
            || context.store_fence != *lease.store_fence()
            || lease.claimant_id().as_str() != expected_claimant
            || context.trusted_time_unix_ms > trusted_now_unix_ms
            || context.trusted_time_unix_ms >= lease.expires_at_unix_ms()
        {
            return Err(EconomicStateCacheError::Conflict);
        }
        qualify_terminal_projection_advance(advance, &descriptor, &verified)?;
        self.stage_batch_inner(
            advance,
            EconomicStageOptions {
                operation: Some(operation),
                descriptor: Some(descriptor),
                admission_checkpoint: None,
                consumer_descriptor_kind: Some(ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND),
            },
            active_fence,
            trusted_now_unix_ms,
        )
    }

    pub(crate) fn stage_clearing_lifecycle_batch(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        descriptor: EconomicStateStageDescriptor,
        checkpoint: Option<EconomicStageAdmissionCheckpoint<'_>>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        self.stage_batch_inner(
            advance,
            EconomicStageOptions {
                operation: None,
                descriptor: Some(descriptor),
                admission_checkpoint: checkpoint,
                consumer_descriptor_kind: Some(CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND),
            },
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn stage_batch_inner(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        options: EconomicStageOptions<'_>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        validate_stage_options(advance.batch(), &options)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence)?;
        let record = stage_batch_in_transaction(
            &transaction,
            advance,
            options,
            active_fence,
            trusted_now_unix_ms,
            &self.serving_owner,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }

    pub fn record_anchor_advanced(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        committed: &VerifiedEconomicStateView,
        pins: &EconomicStateAnchorPins,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        verify_economic_state_batch_commit(advance, committed, pins)?;
        if let Some(descriptor) = self
            .load_stage(&advance.batch().batch_id)?
            .and_then(|stage| stage.descriptor().cloned())
            .filter(|descriptor| descriptor.kind() == ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND)
        {
            let envelope = descriptor.decode::<SignedAdmissionTerminalProjectionV1>()?;
            let verified = envelope
                .verify()
                .map_err(|_| EconomicStateCacheError::Conflict)?;
            let terminal_slot =
                qualify_terminal_projection_advance(advance, &descriptor, &verified)?;
            if !committed_view_matches_batch(committed.view(), advance.batch()) {
                return Err(EconomicStateCacheError::Conflict);
            }
            if terminal_slot.state == EconomicEffectStateV1::Completed {
                verify_economic_completed_effect(committed, &terminal_slot)?;
            }
        }
        if self
            .load_stage(&advance.batch().batch_id)?
            .is_some_and(|stage| {
                stage
                    .descriptor()
                    .is_some_and(|descriptor| descriptor.kind() == CHANNEL_TRANSITION_REPLAY_FORMAT)
                    || (batch_contains_channel_content(stage.batch())
                        && stage.descriptor().is_none_or(|descriptor| {
                            descriptor.kind() != ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
                        }))
            })
        {
            return Err(EconomicStateCacheError::Conflict);
        }
        let committed_bytes =
            canonical_bounded(committed.view(), MAX_VIEW_BYTES, "committed view")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence)?;
        let mut record = load_stage_tx(&transaction, &advance.batch().batch_id)?
            .ok_or(EconomicStateCacheError::NotFound)?;
        if record.base_view != *advance.current().view() || record.batch != *advance.batch() {
            return Err(EconomicStateCacheError::Conflict);
        }
        if matches!(
            record.status,
            EconomicStateStageStatus::EconomicAnchorAdvanced
                | EconomicStateStageStatus::DbFinalized
        ) {
            if record.committed_view.as_ref() == Some(committed.view()) {
                transaction.commit().map_err(sqlite_error)?;
                return Ok(record);
            }
            return Err(EconomicStateCacheError::Conflict);
        }
        require_transition(
            record.status,
            EconomicStateStageStatus::EconomicAnchorAdvanced,
        )?;
        record.status = EconomicStateStageStatus::EconomicAnchorAdvanced;
        record.committed_view = Some(committed.view().clone());
        record.version = next_version(record.version)?;
        record.updated_at_unix_ms = monotonic_time(&record, trusted_now_unix_ms)?;
        record.snapshot_digest = stage_snapshot_digest(&record, &[])?;
        update_stage(
            &transaction,
            &record,
            Some(committed_bytes),
            None,
            EconomicStateStageStatus::DbStaged,
        )?;
        append_stage_commit(
            &transaction,
            &record,
            "anchor_advanced",
            &self.serving_owner,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }

    pub fn finalize_stage(
        &self,
        batch_id: &str,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        validate_digest(batch_id, "batch_id")?;
        validate_trusted_time(trusted_now_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence)?;
        if load_stage_tx(&transaction, batch_id)?.is_some_and(|record| {
            is_protected_channel_stage(&record)
                || record.descriptor.as_ref().is_some_and(|descriptor| {
                    descriptor.kind == ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
                })
        }) {
            return Err(EconomicStateCacheError::Conflict);
        }
        let record = finalize_stage_in_transaction(
            &transaction,
            batch_id,
            &self.serving_owner,
            trusted_now_unix_ms,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }

    pub fn discard_unanchored_stage(
        &self,
        batch_id: &str,
        reason: &str,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        self.close_stage(
            batch_id,
            reason,
            EconomicStateStageStatus::Discarded,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    pub fn quarantine_stage(
        &self,
        batch_id: &str,
        reason: &str,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        self.close_stage(
            batch_id,
            reason,
            EconomicStateStageStatus::Quarantined,
            active_fence,
            trusted_now_unix_ms,
        )
    }

    fn close_stage(
        &self,
        batch_id: &str,
        reason: &str,
        target: EconomicStateStageStatus,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
        validate_digest(batch_id, "batch_id")?;
        validate_reason(reason)?;
        validate_trusted_time(trusted_now_unix_ms)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection, active_fence)?;
        let mut record =
            load_stage_tx(&transaction, batch_id)?.ok_or(EconomicStateCacheError::NotFound)?;
        if is_protected_channel_stage(&record)
            || record.descriptor.as_ref().is_some_and(|descriptor| {
                descriptor.kind == ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
            })
        {
            return Err(EconomicStateCacheError::Conflict);
        }
        if record.status == target && record.reason.as_deref() == Some(reason) {
            transaction.commit().map_err(sqlite_error)?;
            return Ok(record);
        }
        let previous_status = record.status;
        require_transition(previous_status, target)?;
        record.status = target;
        record.reason = Some(reason.to_owned());
        record.version = next_version(record.version)?;
        record.updated_at_unix_ms = monotonic_time(&record, trusted_now_unix_ms)?;
        record.snapshot_digest = stage_snapshot_digest(&record, &[])?;
        update_stage(&transaction, &record, None, Some(reason), previous_status)?;
        append_stage_commit(
            &transaction,
            &record,
            if target == EconomicStateStageStatus::Discarded {
                "discard_stage"
            } else {
                "quarantine_stage"
            },
            &self.serving_owner,
        )?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(record)
    }

    pub fn load_stage(
        &self,
        batch_id: &str,
    ) -> Result<Option<EconomicStateStageRecord>, EconomicStateCacheError> {
        validate_digest(batch_id, "batch_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let record = load_stage_tx(&transaction, batch_id)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }

    pub(crate) fn load_stage_by_descriptor(
        &self,
        kind: &str,
        key: &str,
    ) -> Result<Option<EconomicStateStageRecord>, EconomicStateCacheError> {
        validate_descriptor_text(kind, MAX_DESCRIPTOR_KIND_BYTES, "stage descriptor kind")?;
        validate_descriptor_text(key, MAX_DESCRIPTOR_KEY_BYTES, "stage descriptor key")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let batch_id = transaction
            .query_row(
                r#"
                SELECT batch_id FROM economic_state_stages
                WHERE descriptor_kind = ?1 AND descriptor_key = ?2
                "#,
                params![kind, key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        let record = batch_id
            .as_deref()
            .map(|batch_id| load_stage_tx(&transaction, batch_id))
            .transpose()?
            .flatten();
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }

    pub fn list_pending(
        &self,
        limit: usize,
    ) -> Result<Vec<EconomicStateStageRecord>, EconomicStateCacheError> {
        if limit == 0 || limit > 256 {
            return Err(invariant("economic recovery limit must be within 1..=256"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT batch_id FROM economic_state_stages
                WHERE status IN ('db_staged', 'economic_anchor_advanced')
                ORDER BY checkpoint_sequence, batch_id LIMIT ?1
                "#,
            )
            .map_err(sqlite_error)?;
        let batch_ids = statement
            .query_map(
                [i64::try_from(limit).map_err(|_| invariant("limit overflow"))?],
                |row| row.get::<_, String>(0),
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        drop(statement);
        let records = batch_ids
            .iter()
            .map(|batch_id| {
                load_stage_tx(&transaction, batch_id)?
                    .ok_or_else(|| invariant("pending economic stage disappeared"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(records)
    }

    pub fn load_finalized_head(
        &self,
        key: &EconomicResourceKeyV1,
    ) -> Result<Option<EconomicResourceHeadV1>, EconomicStateCacheError> {
        key.validate()?;
        let key_bytes = canonical_json_bytes(key).map_err(canonical_error)?;
        let key_digest = sha256_hex(&key_bytes);
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let stored = transaction
            .query_row(
                r#"
                SELECT current.resource_key_json, current.head_digest,
                       current.head_json, current.source_batch_id,
                       staged.head_digest, staged.head_json
                FROM economic_state_heads AS current
                JOIN economic_state_stage_heads AS staged
                  ON staged.batch_id = current.source_batch_id
                 AND staged.resource_key_digest = current.resource_key_digest
                JOIN economic_state_stages AS stage
                  ON stage.batch_id = current.source_batch_id
                 AND stage.status = 'db_finalized'
                WHERE current.resource_key_digest = ?1
                "#,
                [&key_digest],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let result = stored
            .map(
                |(stored_key, current_digest, current_head, _batch, staged_digest, staged_head)| {
                    if stored_key != key_bytes
                        || current_digest != staged_digest
                        || current_head != staged_head
                    {
                        return Err(invariant(
                            "current economic head lost its finalized projection",
                        ));
                    }
                    let head: EconomicResourceHeadV1 =
                        decode_exact(&current_head, "resource head")?;
                    if head.resource_key != *key || head.digest()? != current_digest {
                        return Err(invariant("cached economic resource head is corrupt"));
                    }
                    Ok(head)
                },
            )
            .transpose()?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(result)
    }
}

pub(crate) fn load_anchored_terminal_projection_in_transaction(
    transaction: &Transaction<'_>,
    batch_id: &str,
    active_fence: &StoreMutationFence,
    require_anchored: bool,
) -> Result<
    (
        VerifiedAdmissionTerminalProjectionV1,
        EconomicOperationStageBinding,
    ),
    EconomicStateCacheError,
> {
    validate_digest(batch_id, "batch_id")?;
    verify_cache_sql_invariants(transaction)?;
    let record = load_stage_tx(transaction, batch_id)?.ok_or(EconomicStateCacheError::NotFound)?;
    if matches!(
        record.status,
        EconomicStateStageStatus::Discarded | EconomicStateStageStatus::Quarantined
    ) || require_anchored
        && !matches!(
            record.status,
            EconomicStateStageStatus::EconomicAnchorAdvanced
                | EconomicStateStageStatus::DbFinalized
        )
    {
        return Err(EconomicStateCacheError::Conflict);
    }
    let descriptor = record
        .descriptor
        .as_ref()
        .ok_or(EconomicStateCacheError::Conflict)?;
    let envelope = descriptor.decode::<SignedAdmissionTerminalProjectionV1>()?;
    let verified = envelope
        .verify()
        .map_err(|_| EconomicStateCacheError::Conflict)?;
    let context = verified.context();
    let source = verified.source_operation();
    let operation_id = source.binding().operation_id().as_str();
    let binding = record
        .operation_binding
        .as_ref()
        .ok_or(EconomicStateCacheError::Conflict)?;
    qualify_retained_terminal_projection_advance(
        &record.base_view,
        &record.batch,
        descriptor,
        &verified,
    )?;
    let committed_head_matches = match record.committed_view.as_ref() {
        Some(committed) => committed_view_matches_batch(committed, &record.batch),
        None => record.status == EconomicStateStageStatus::DbStaged,
    };
    let expected_claimant = format!("kernel:{}", verified.signer_key().to_hex());
    if descriptor.kind != ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
        || descriptor.key != operation_id
        || record.batch.operation_id.as_deref() != Some(operation_id)
        || binding.operation_id != operation_id
        || binding.operation_state != source.state()
        || binding.operation_version != source.version()
        || binding.coordinator_lease_epoch != source.coordinator_lease_epoch()
        || binding.coordinator_lease_id != context.coordinator_lease_id.as_str()
        || binding.recovery_claimant_id != expected_claimant
        || binding.recovery_expires_at_unix_ms <= context.trusted_time_unix_ms
        || !current_fence_serves_historical(&binding.store_fence, active_fence)
        || context.store_fence != binding.store_fence
        || context.trusted_time_unix_ms > record.created_at_unix_ms
        || !committed_head_matches
    {
        return Err(EconomicStateCacheError::Conflict);
    }
    Ok((verified, binding.clone()))
}

pub(crate) fn has_reserved_terminal_stage(
    transaction: &Transaction<'_>,
    operation_id: &str,
) -> Result<bool, EconomicStateCacheError> {
    transaction
        .query_row(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM economic_state_stages
                WHERE descriptor_kind = ?1
                  AND descriptor_key = ?2
            )
            "#,
            params![ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND, operation_id],
            |row| row.get(0),
        )
        .map_err(sqlite_error)
}

fn current_fence_serves_historical(
    historical: &StoreMutationFence,
    current: &StoreMutationFence,
) -> bool {
    historical.store_uuid == current.store_uuid
        && (historical == current || current.owner_epoch > historical.owner_epoch)
}

pub(crate) fn finalize_stage_in_transaction(
    transaction: &Transaction<'_>,
    batch_id: &str,
    serving_owner: &SqliteServingOwner,
    trusted_now_unix_ms: u64,
) -> Result<EconomicStateStageRecord, EconomicStateCacheError> {
    validate_digest(batch_id, "batch_id")?;
    validate_trusted_time(trusted_now_unix_ms)?;
    verify_cache_sql_invariants(transaction)?;
    let mut record =
        load_stage_tx(transaction, batch_id)?.ok_or(EconomicStateCacheError::NotFound)?;
    if record.status == EconomicStateStageStatus::DbFinalized {
        return Ok(record);
    }
    require_transition(record.status, EconomicStateStageStatus::DbFinalized)?;
    let committed = record
        .committed_view
        .as_ref()
        .ok_or_else(|| invariant("anchor-advanced stage omitted its committed view"))?;
    let mut head_digests = Vec::with_capacity(record.batch.transitions.len());
    for transition in &record.batch.transitions {
        let head = committed
            .heads
            .iter()
            .find(|head| head.resource_key == transition.resource_key)
            .ok_or_else(|| invariant("committed view omitted a staged resource head"))?;
        if head != &transition.next_head {
            return Err(invariant("committed resource head changed before finalize"));
        }
        let key_bytes = canonical_json_bytes(&head.resource_key).map_err(canonical_error)?;
        let key_digest = sha256_hex(&key_bytes);
        let head_bytes = canonical_json_bytes(head).map_err(canonical_error)?;
        let head_digest = head.digest()?;
        head_digests.push((key_digest.clone(), head_digest.clone()));
        transaction
            .execute(
                r#"
                INSERT INTO economic_state_stage_heads (
                    batch_id, resource_key_digest, resource_key_json,
                    head_digest, head_json
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                params![batch_id, &key_digest, &key_bytes, &head_digest, &head_bytes],
            )
            .map_err(sqlite_error)?;
        let checkpoint_sequence =
            sqlite_i64(record.batch.checkpoint_sequence, "checkpoint_sequence")?;
        let current = transaction
            .query_row(
                r#"
                SELECT resource_key_json, head_digest, head_json,
                       checkpoint_sequence, checkpoint_digest, source_batch_id
                FROM economic_state_heads WHERE resource_key_digest = ?1
                "#,
                [&key_digest],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let publish = match current {
            Some((
                current_key,
                current_head_digest,
                current_head,
                current_sequence,
                current_checkpoint,
                current_batch,
            )) if current_sequence == checkpoint_sequence => {
                if current_key != key_bytes
                    || current_head_digest != head_digest
                    || current_head != head_bytes
                    || current_checkpoint != record.batch.checkpoint_digest
                    || current_batch != batch_id
                {
                    return Err(invariant(
                        "equal economic checkpoint has conflicting cached state",
                    ));
                }
                false
            }
            Some((_, _, _, current_sequence, _, _)) if current_sequence > checkpoint_sequence => {
                false
            }
            _ => true,
        };
        if publish {
            transaction
                .execute(
                    r#"
                INSERT INTO economic_state_heads (
                    resource_key_digest, resource_key_json, head_digest,
                    head_json, checkpoint_sequence, checkpoint_digest,
                    source_batch_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                ON CONFLICT(resource_key_digest) DO UPDATE SET
                    resource_key_json = excluded.resource_key_json,
                    head_digest = excluded.head_digest,
                    head_json = excluded.head_json,
                    checkpoint_sequence = excluded.checkpoint_sequence,
                    checkpoint_digest = excluded.checkpoint_digest,
                    source_batch_id = excluded.source_batch_id
                WHERE economic_state_heads.checkpoint_sequence
                    < excluded.checkpoint_sequence
                "#,
                    params![
                        &key_digest,
                        &key_bytes,
                        &head_digest,
                        &head_bytes,
                        checkpoint_sequence,
                        &record.batch.checkpoint_digest,
                        batch_id,
                    ],
                )
                .map_err(sqlite_error)?;
        }
    }
    head_digests.sort();
    record.status = EconomicStateStageStatus::DbFinalized;
    record.version = next_version(record.version)?;
    record.updated_at_unix_ms = monotonic_time(&record, trusted_now_unix_ms)?;
    record.snapshot_digest = stage_snapshot_digest(&record, &head_digests)?;
    update_stage(
        transaction,
        &record,
        None,
        None,
        EconomicStateStageStatus::EconomicAnchorAdvanced,
    )?;
    append_stage_commit(transaction, &record, "finalize_stage", serving_owner)?;
    Ok(record)
}

pub(crate) fn initialize_economic_state_cache_schema(
    connection: &mut Connection,
) -> Result<(), EconomicStateCacheError> {
    let on_disk = crate::check_schema_version(
        connection,
        ECONOMIC_STATE_CACHE_SCHEMA_KEY,
        ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION,
        ECONOMIC_STATE_CACHE_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION {
        return verify_cache_sql_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    let stage_table_exists = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'economic_state_stages')",
            [],
            |row| row.get::<_, bool>(0),
        )
        .map_err(sqlite_error)?;
    let descriptor_column_exists = stage_table_exists
        && transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('economic_state_stages') WHERE name = 'descriptor_kind')",
                [],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_error)?;
    if stage_table_exists && !descriptor_column_exists {
        transaction
            .execute_batch(ECONOMIC_STATE_CACHE_DESCRIPTOR_MIGRATION)
            .map_err(sqlite_error)?;
    }
    transaction
        .execute_batch(ECONOMIC_STATE_CACHE_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        ECONOMIC_STATE_CACHE_SCHEMA_KEY,
        ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_cache_sql_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

fn qualify_operation_binding(
    transaction: &Transaction<'_>,
    batch: &EconomicStateBatchV1,
    context: Option<EconomicOperationStageContext<'_>>,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<Option<EconomicOperationStageBinding>, EconomicStateCacheError> {
    let Some(context) = context else {
        if batch.operation_id.is_some() {
            return Err(invariant(
                "operation-bound batch omitted recovery authority",
            ));
        }
        return Ok(None);
    };
    let operation = context.operation;
    let lease = context.recovery_lease;
    operation
        .validate()
        .map_err(|error| invariant(error.to_string()))?;
    if operation.state().is_terminal()
        || batch.operation_id.as_deref() != Some(operation.binding().operation_id().as_str())
        || lease.operation_id() != operation.binding().operation_id()
        || lease.claimed_version() != operation.version()
        || lease.coordinator_lease_epoch() != operation.coordinator_lease_epoch()
        || lease.store_fence() != active_fence
        || trusted_now_unix_ms >= lease.expires_at_unix_ms()
        || context
            .not_after_unix_ms
            .is_some_and(|not_after| trusted_now_unix_ms >= not_after)
    {
        return Err(EconomicStateCacheError::Fenced);
    }
    let persisted = transaction
        .query_row(
            r#"
            SELECT operation_json, recovery_claimant_id,
                   recovery_coordinator_lease_id, recovery_coordinator_lease_epoch,
                   recovery_claimed_version, recovery_expires_at_unix_ms,
                   recovery_store_uuid, recovery_store_lease_id,
                   recovery_store_owner_epoch
            FROM admission_operations WHERE operation_id = ?1 AND terminal = 0
            "#,
            [operation.binding().operation_id().as_str()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .ok_or(EconomicStateCacheError::Fenced)?;
    let stored: PersistedAdmissionOperationV1 = decode_exact(&persisted.0, "admission operation")?;
    let stored = AdmissionOperationV1::from_persisted(stored)
        .map_err(|error| invariant(error.to_string()))?;
    let exact_claim = persisted.1.as_deref() == Some(lease.claimant_id().as_str())
        && persisted.2.as_deref() == Some(lease.coordinator_lease_id().as_str())
        && optional_u64(persisted.3, "recovery_coordinator_lease_epoch")?
            == Some(lease.coordinator_lease_epoch())
        && optional_u64(persisted.4, "recovery_claimed_version")? == Some(lease.claimed_version())
        && optional_u64(persisted.5, "recovery_expires_at_unix_ms")?
            == Some(lease.expires_at_unix_ms())
        && persisted.6.as_deref() == Some(&active_fence.store_uuid)
        && persisted.7.as_deref() == Some(&active_fence.lease_id)
        && optional_u64(persisted.8, "recovery_store_owner_epoch")?
            == Some(active_fence.owner_epoch);
    if stored != *operation || !exact_claim {
        return Err(EconomicStateCacheError::Fenced);
    }
    let binding = EconomicOperationStageBinding {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        operation_state: operation.state(),
        operation_version: operation.version(),
        coordinator_lease_epoch: operation.coordinator_lease_epoch(),
        coordinator_lease_id: lease.coordinator_lease_id().as_str().to_owned(),
        recovery_claimant_id: lease.claimant_id().as_str().to_owned(),
        recovery_expires_at_unix_ms: lease.expires_at_unix_ms(),
        not_after_unix_ms: context.not_after_unix_ms,
        store_fence: active_fence.clone(),
    };
    binding.validate()?;
    Ok(Some(binding))
}

fn validate_descriptor_text(
    value: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), EconomicStateCacheError> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(invariant(format!("{field} is invalid")))
    } else {
        Ok(())
    }
}

fn verify_stage_admission_checkpoint(
    transaction: &Transaction<'_>,
    expected: &EconomicStageAdmissionCheckpoint<'_>,
    active_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> Result<(), EconomicStateCacheError> {
    validate_descriptor_text(
        expected.store_id,
        MAX_DESCRIPTOR_KEY_BYTES,
        "admission store id",
    )?;
    validate_digest(expected.digest, "admission commit digest")?;
    let current = crate::admission_operation_store::verify_admission_commit_chain(transaction)
        .map_err(|error| invariant(error.to_string()))?;
    if expected.store_id != active_fence.store_uuid
        || expected.sequence != current.head_sequence
        || expected.digest != current.chain_digest
        || trusted_now_unix_ms < current.trusted_time_high_water_unix_ms
    {
        return Err(EconomicStateCacheError::Conflict);
    }
    Ok(())
}

#[cfg(test)]
#[path = "economic_state_cache_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
