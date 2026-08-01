use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::canonical::canonical_json_bytes;
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_batch_commit,
    verify_economic_state_view, EconomicEffectStateV1, VerifiedEconomicStateBatchAdvance,
    VerifiedEconomicStateView,
};
use chio_core::{sha256_hex, StoreMutationFence};
use chio_kernel::admission_operation::{
    expected_dispatch_committed_version, AdmissionAttachment, AdmissionDigest,
    AdmissionOperationCommand, AdmissionOperationId, AdmissionOperationState,
    AdmissionOperationStoreError, AdmissionOperationV1, AdmissionRecoveryLease,
};
use chio_settle::channel::{
    derive_channel_reservation_id, ChannelEscrowReservationStatusV1, ChannelLifecycleStatusV1,
    ChannelPreparedReservationV1, ChannelTransitionReplayAuthorityPinsV1,
    ChannelTransitionReplayKindV1, ChannelTransitionReplayVerifierV1, RetainedChannelStateV1,
    SignedChannelReservationV1, VerifiedAdmittedChannelReservationV1,
    VerifiedChannelPreparedReservationV1, CHANNEL_SERVICE_DISPATCH_EFFECT_KIND,
    CHANNEL_TRANSITION_REPLAY_FORMAT,
};
use rusqlite::{
    params, Connection, ErrorCode, OptionalExtension, Row, Transaction, TransactionBehavior,
};
use serde::Serialize;

use crate::serving_owner::{SqliteServingOwner, SqliteServingOwnerError};
use crate::{
    EconomicOperationStageContext, EconomicStateCacheError, EconomicStateStageDescriptor,
    EconomicStateStageRecord, EconomicStateStageStatus,
};

mod prepared;
mod reservation;
mod schema;
mod terminal;

use prepared::*;
use reservation::*;
pub(crate) use schema::{initialize_channel_lifecycle_schema, verify_channel_lifecycle_invariants};
pub(crate) use terminal::{
    consume_channel_terminal_projection_tx, verify_consumed_channel_terminal_projection_tx,
};

const CHANNEL_LIFECYCLE_SCHEMA_KEY: &str = "channel_lifecycle";
pub(crate) const CHANNEL_LIFECYCLE_SUPPORTED_SCHEMA_VERSION: i32 = 1;
const CHANNEL_LIFECYCLE_SCHEMA_ANCHORS: &[&str] =
    &["channel_lifecycle_records", "admission_operations"];
const CHANNEL_LIFECYCLE_SCHEMA: &str = include_str!("channel_lifecycle_store.sql");
const MAX_CHANNEL_ARTIFACT_BYTES: usize = 1024 * 1024;
const MAX_CHANNEL_PREPARED_PLAN_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ChannelLifecycleStoreError {
    #[error("channel lifecycle store is unavailable: {0}")]
    Unavailable(String),
    #[error("channel lifecycle store mutation was fenced")]
    Fenced,
    #[error("channel lifecycle record was not found")]
    NotFound,
    #[error("channel lifecycle record conflicts with retained state")]
    Conflict,
    #[error("channel lifecycle invariant failed: {0}")]
    Invalid(String),
    #[error("channel lifecycle durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelPreparedAdmissionRecordV1 {
    operation: AdmissionOperationV1,
    plan: ChannelPreparedReservationV1,
    plan_digest: String,
    store_fence: StoreMutationFence,
    created_at_unix_ms: u64,
}

impl ChannelPreparedAdmissionRecordV1 {
    #[must_use]
    pub const fn operation(&self) -> &AdmissionOperationV1 {
        &self.operation
    }

    #[must_use]
    pub const fn plan(&self) -> &ChannelPreparedReservationV1 {
        &self.plan
    }

    #[must_use]
    pub fn plan_digest(&self) -> &str {
        &self.plan_digest
    }

    #[must_use]
    pub const fn store_fence(&self) -> &StoreMutationFence {
        &self.store_fence
    }

    #[must_use]
    pub const fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelPreparedBeginResult {
    Created(ChannelPreparedAdmissionRecordV1),
    ExactReplay(ChannelPreparedAdmissionRecordV1),
    Conflict {
        existing_operation_id: AdmissionOperationId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelReservationDispositionV1 {
    PendingAnchor,
    Live,
    Consumed,
    Cancelled,
    Incident,
}

impl ChannelReservationDispositionV1 {
    fn parse(value: &str) -> Result<Self, ChannelLifecycleStoreError> {
        match value {
            "pending_anchor" => Ok(Self::PendingAnchor),
            "live" => Ok(Self::Live),
            "consumed" => Ok(Self::Consumed),
            "cancelled" => Ok(Self::Cancelled),
            "incident" => Ok(Self::Incident),
            _ => Err(invalid(
                "retained channel reservation disposition is invalid",
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelReservationStageRecordV1 {
    operation: AdmissionOperationV1,
    reservation: SignedChannelReservationV1,
    authority_pins: ChannelTransitionReplayAuthorityPinsV1,
    replay_bytes: Vec<u8>,
    economic_stage: EconomicStateStageRecord,
    disposition: ChannelReservationDispositionV1,
    record_version: u64,
    updated_at_unix_ms: u64,
}

impl ChannelReservationStageRecordV1 {
    #[must_use]
    pub const fn operation(&self) -> &AdmissionOperationV1 {
        &self.operation
    }

    #[must_use]
    pub const fn reservation(&self) -> &SignedChannelReservationV1 {
        &self.reservation
    }

    #[must_use]
    pub const fn authority_pins(&self) -> &ChannelTransitionReplayAuthorityPinsV1 {
        &self.authority_pins
    }

    #[must_use]
    pub fn replay_bytes(&self) -> &[u8] {
        &self.replay_bytes
    }

    #[must_use]
    pub const fn economic_stage(&self) -> &EconomicStateStageRecord {
        &self.economic_stage
    }

    #[must_use]
    pub const fn disposition(&self) -> ChannelReservationDispositionV1 {
        self.disposition
    }

    #[must_use]
    pub const fn record_version(&self) -> u64 {
        self.record_version
    }

    #[must_use]
    pub const fn updated_at_unix_ms(&self) -> u64 {
        self.updated_at_unix_ms
    }
}

#[derive(Clone)]
pub struct SqliteChannelLifecycleStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

struct EncodedPreparedPlan {
    plan_digest: String,
    plan_json: Vec<u8>,
    open_intent_digest: String,
    open_intent_json: Vec<u8>,
    open_digest: String,
    open_json: Vec<u8>,
    prior_state_kind: &'static str,
    prior_state_digest: String,
    prior_sequence: u64,
    prior_state_json: Vec<u8>,
    reservation_proposal_digest: String,
    lifecycle_json: Vec<u8>,
    escrow_json: Vec<u8>,
}

struct StoredPreparedPlan {
    request_id: String,
    request_namespace_digest: String,
    request_binding_digest: String,
    provider_binding_digest: String,
    reservation_id: String,
    channel_id: String,
    open_digest: String,
    prior_state_digest: String,
    prior_sequence: u64,
    reservation_proposal_digest: String,
    lifecycle_state: String,
    state_version: u64,
    lifecycle_fence: u64,
    live_reservation_id: Option<String>,
    lifecycle_operation_id: Option<String>,
    channel_head_digest: String,
    escrow_head_digest: String,
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    plan_digest: String,
    plan_json: Vec<u8>,
    store_fence: StoreMutationFence,
    created_at_unix_ms: u64,
}

impl SqliteChannelLifecycleStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.serving_owner.fence.clone()
    }

    pub fn verify_invariants(&self) -> Result<(), ChannelLifecycleStoreError> {
        let connection = self.connection()?;
        verify_channel_lifecycle_invariants(&connection)
            .map_err(|error| ChannelLifecycleStoreError::Unavailable(error.to_string()))
    }

    pub fn begin_channel_prepared(
        &self,
        operation: &AdmissionOperationV1,
        prepared: &VerifiedChannelPreparedReservationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelPreparedBeginResult, ChannelLifecycleStoreError> {
        self.begin_channel_prepared_inner(
            operation,
            prepared.prepared(),
            fence,
            trusted_now_unix_ms,
        )
    }

    pub fn load_channel_prepared(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ChannelPreparedAdmissionRecordV1>, ChannelLifecycleStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        crate::admission_operation_store::verify_active_owner(
            &transaction,
            &self.serving_owner,
            None,
        )
        .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(owner_error)?;
        let operation = crate::admission_operation_store::load_operation_for_participant_tx(
            &transaction,
            operation_id,
        )
        .map_err(admission_error)?;
        let record = match operation {
            Some(operation) => {
                let requires_channel = operation.binding().participant_requirements().channel;
                let require_base_lifecycle = operation.channel_reservation_digest().is_none();
                let record = load_prepared_record(&transaction, operation, require_base_lifecycle)?;
                if requires_channel && record.is_none() {
                    return Err(ChannelLifecycleStoreError::NotFound);
                }
                record
            }
            None => None,
        };
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stage_channel_reservation(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        replay_bytes: &[u8],
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReservationStageRecordV1, ChannelLifecycleStoreError> {
        if fence != &self.serving_owner.fence || recovery_lease.store_fence() != fence {
            return Err(ChannelLifecycleStoreError::Fenced);
        }
        let authority_pins_json = expected_authority_pins
            .canonical_bytes()
            .map_err(channel_error)?;
        let authority_pins_digest = expected_authority_pins.digest().map_err(channel_error)?;
        let replay = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
            replay_bytes,
            expected_authority_pins,
        )
        .map_err(channel_error)?;
        if replay.descriptor().kind() != ChannelTransitionReplayKindV1::Reservation {
            return Err(invalid(
                "channel reservation stage requires a reservation replay",
            ));
        }
        verify_economic_state_batch_advance(
            advance.current(),
            advance.batch().clone(),
            &expected_authority_pins.anchor_pins(),
            &replay,
        )
        .map_err(|error| invalid(error.to_string()))?;
        let proposal = replay.verified_reservation_proposal();
        let reservation = proposal.artifact();
        let reservation_body = &reservation.body;
        let reservation_digest = reservation.digest().map_err(channel_error)?;
        let reservation_json = encode(
            reservation,
            MAX_CHANNEL_ARTIFACT_BYTES,
            "signed channel reservation",
        )?;
        let replay_protocol_digest = replay.descriptor().digest().to_owned();
        let replay_content_digest = sha256_hex(replay_bytes);
        let descriptor = EconomicStateStageDescriptor::new(
            CHANNEL_TRANSITION_REPLAY_FORMAT,
            replay.descriptor().key(),
            replay.descriptor(),
        )
        .map_err(economic_error)?;
        if descriptor.digest() != replay_content_digest
            || replay.descriptor().expected_batch_digest() != advance.batch().checkpoint_digest
            || replay.descriptor().request().request_id != reservation_body.request_id
            || reservation_body.operation_id != operation.binding().operation_id().as_str()
            || trusted_now_unix_ms < proposal.accepted_at_unix_ms()
            || trusted_now_unix_ms >= reservation_body.expires_at_unix_ms
        {
            return Err(invalid(
                "channel reservation replay binding is inconsistent",
            ));
        }
        let ready_effect_head_digest = exact_ready_effect_head_digest(
            advance,
            &reservation_body.operation_id,
            &reservation_digest,
        )?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        crate::admission_operation_store::verify_active_owner(
            &transaction,
            &self.serving_owner,
            Some(fence),
        )
        .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(owner_error)?;
        if let Some(existing) = load_channel_reservation_tx(
            &transaction,
            operation.binding().operation_id(),
            expected_authority_pins,
        )? {
            qualify_exact_staged_replay(
                &existing,
                operation,
                advance,
                replay_bytes,
                &reservation_digest,
            )?;
            qualify_exact_recovery_authority(&existing, recovery_lease, trusted_now_unix_ms)?;
            crate::admission_operation_store::verify_participant_recovery_tx(
                &transaction,
                &self.serving_owner,
                operation,
                recovery_lease,
                trusted_now_unix_ms,
            )
            .map_err(admission_error)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(existing);
        }
        let stored_operation = crate::admission_operation_store::load_operation_for_participant_tx(
            &transaction,
            operation.binding().operation_id(),
        )
        .map_err(admission_error)?
        .ok_or(ChannelLifecycleStoreError::NotFound)?;
        if stored_operation != *operation
            || !matches!(
                operation.state(),
                AdmissionOperationState::BudgetAuthorized
                    | AdmissionOperationState::ApprovalReserved
            )
            || operation.channel_reservation_digest().is_some()
        {
            return Err(ChannelLifecycleStoreError::Fenced);
        }
        let prepared = load_prepared_record(&transaction, stored_operation.clone(), true)?
            .ok_or(ChannelLifecycleStoreError::NotFound)?;
        qualify_reservation_against_prepared(
            &prepared,
            reservation,
            replay.descriptor().request(),
        )?;
        let operation_context = EconomicOperationStageContext::new(operation, recovery_lease)
            .with_not_after_unix_ms(reservation_body.expires_at_unix_ms)
            .map_err(economic_error)?;
        let economic_stage = crate::economic_state_cache::stage_channel_batch_in_transaction(
            &transaction,
            advance,
            operation_context,
            descriptor,
            fence,
            trusted_now_unix_ms,
            &self.serving_owner,
        )
        .map_err(economic_error)?;
        let participant_digest = channel_reservation_participant_digest(
            &prepared,
            &reservation_digest,
            &authority_pins_digest,
            &replay_protocol_digest,
            &replay_content_digest,
            &economic_stage,
            &ready_effect_head_digest,
        )?;
        insert_pending_reservation_tx(
            &transaction,
            &prepared,
            reservation,
            &reservation_digest,
            &reservation_json,
            &authority_pins_digest,
            &authority_pins_json,
            replay_bytes,
            &replay_protocol_digest,
            &replay_content_digest,
            &economic_stage,
            &ready_effect_head_digest,
            fence,
            trusted_now_unix_ms,
        )?;
        crate::admission_operation_store::append_participant_update_tx(
            &transaction,
            &self.serving_owner,
            operation,
            recovery_lease,
            &participant_digest,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?;
        transaction.commit().map_err(|error| {
            owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite channel reservation stage commit outcome is unknown: {error}"
            )))
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(owner_error)?;
        Ok(ChannelReservationStageRecordV1 {
            operation: operation.clone(),
            reservation: reservation.clone(),
            authority_pins: expected_authority_pins.clone(),
            replay_bytes: replay_bytes.to_vec(),
            economic_stage,
            disposition: ChannelReservationDispositionV1::PendingAnchor,
            record_version: 1,
            updated_at_unix_ms: trusted_now_unix_ms,
        })
    }

    pub fn load_channel_reservation(
        &self,
        operation_id: &AdmissionOperationId,
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
    ) -> Result<Option<ChannelReservationStageRecordV1>, ChannelLifecycleStoreError> {
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        crate::admission_operation_store::verify_active_owner(
            &transaction,
            &self.serving_owner,
            None,
        )
        .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(owner_error)?;
        let record =
            load_channel_reservation_tx(&transaction, operation_id, expected_authority_pins)?;
        transaction.commit().map_err(sqlite_error)?;
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_channel_anchor_advanced(
        &self,
        operation_id: &AdmissionOperationId,
        advance: &VerifiedEconomicStateBatchAdvance,
        committed: &VerifiedEconomicStateView,
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReservationStageRecordV1, ChannelLifecycleStoreError> {
        if fence != &self.serving_owner.fence {
            return Err(ChannelLifecycleStoreError::Fenced);
        }
        verify_economic_state_batch_commit(
            advance,
            committed,
            &expected_authority_pins.anchor_pins(),
        )
        .map_err(|error| invalid(error.to_string()))?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        crate::admission_operation_store::verify_active_owner(
            &transaction,
            &self.serving_owner,
            Some(fence),
        )
        .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(owner_error)?;
        let record =
            load_channel_reservation_tx(&transaction, operation_id, expected_authority_pins)?
                .ok_or(ChannelLifecycleStoreError::NotFound)?;
        if record.disposition() != ChannelReservationDispositionV1::PendingAnchor
            || record.economic_stage().base_view() != advance.current().view()
            || record.economic_stage().batch() != advance.batch()
        {
            return Err(ChannelLifecycleStoreError::Conflict);
        }
        let replay = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
            record.replay_bytes(),
            expected_authority_pins,
        )
        .map_err(channel_error)?;
        let admitted = replay
            .verify_committed_reservation(committed)
            .map_err(channel_error)?;
        if admitted.artifact() != record.reservation() {
            return Err(invalid(
                "committed channel reservation differs from staged evidence",
            ));
        }
        let already_advanced =
            record.economic_stage().status() == EconomicStateStageStatus::EconomicAnchorAdvanced;
        let economic_stage =
            crate::economic_state_cache::record_channel_anchor_advanced_in_transaction(
                &transaction,
                advance,
                committed,
                trusted_now_unix_ms,
                &self.serving_owner,
            )
            .map_err(economic_error)?;
        transaction.commit().map_err(|error| {
            owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite channel anchor record commit outcome is unknown: {error}"
            )))
        })?;
        if !already_advanced {
            self.serving_owner
                .sync_authority_anchor(&connection)
                .map_err(owner_error)?;
        }
        Ok(ChannelReservationStageRecordV1 {
            economic_stage,
            ..record
        })
    }

    pub fn finalize_channel_reservation(
        &self,
        operation_id: &AdmissionOperationId,
        recovery_lease: &AdmissionRecoveryLease,
        expected_authority_pins: &ChannelTransitionReplayAuthorityPinsV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelReservationStageRecordV1, ChannelLifecycleStoreError> {
        if fence != &self.serving_owner.fence || recovery_lease.store_fence() != fence {
            return Err(ChannelLifecycleStoreError::Fenced);
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        crate::admission_operation_store::verify_active_owner(
            &transaction,
            &self.serving_owner,
            Some(fence),
        )
        .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(owner_error)?;
        let current_operation =
            crate::admission_operation_store::load_operation_for_participant_tx(
                &transaction,
                operation_id,
            )
            .map_err(admission_error)?
            .ok_or(ChannelLifecycleStoreError::NotFound)?;
        crate::admission_operation_store::verify_participant_recovery_tx(
            &transaction,
            &self.serving_owner,
            &current_operation,
            recovery_lease,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?;
        let record =
            load_channel_reservation_tx(&transaction, operation_id, expected_authority_pins)?
                .ok_or(ChannelLifecycleStoreError::NotFound)?;
        let committed = record
            .economic_stage()
            .committed_view()
            .cloned()
            .ok_or_else(|| invalid("channel reservation anchor is not retained"))?;
        let committed =
            verify_economic_state_view(committed, &expected_authority_pins.anchor_pins())
                .map_err(|error| invalid(error.to_string()))?;
        let replay = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
            record.replay_bytes(),
            expected_authority_pins,
        )
        .map_err(channel_error)?;
        let admitted = replay
            .verify_committed_reservation(&committed)
            .map_err(channel_error)?;
        if admitted.artifact() != record.reservation() {
            return Err(invalid(
                "anchored channel reservation differs from retained evidence",
            ));
        }
        if record.disposition() == ChannelReservationDispositionV1::Live {
            qualify_finalized_channel_tx(&transaction, &record, &admitted)?;
            transaction.commit().map_err(sqlite_error)?;
            return Ok(record);
        }
        if record.disposition() != ChannelReservationDispositionV1::PendingAnchor
            || record.economic_stage().status() != EconomicStateStageStatus::EconomicAnchorAdvanced
        {
            return Err(ChannelLifecycleStoreError::Conflict);
        }
        let prepared = load_prepared_record(&transaction, record.operation().clone(), true)?
            .ok_or(ChannelLifecycleStoreError::NotFound)?;
        let reservation_digest = record.reservation().digest().map_err(channel_error)?;
        let participant_digest = channel_reservation_participant_digest(
            &prepared,
            &reservation_digest,
            &expected_authority_pins.digest().map_err(channel_error)?,
            replay.descriptor().digest(),
            &sha256_hex(record.replay_bytes()),
            record.economic_stage(),
            admitted.ready_effect_head_digest(),
        )?;
        let command = AdmissionOperationCommand::new(
            operation_id.clone(),
            record.operation().version(),
            recovery_lease.clone(),
            vec![AdmissionAttachment::ChannelReservationDigest(
                AdmissionDigest::try_new("channel_reservation_digest", reservation_digest)
                    .map_err(|error| invalid(error.to_string()))?,
            )],
            Some(AdmissionOperationState::ReadyToDispatch),
            None,
            None,
        )
        .map_err(|error| invalid(error.to_string()))?;
        let updated_operation =
            crate::admission_operation_store::finalize_channel_reservation_operation_tx(
                &transaction,
                &self.serving_owner,
                record.operation(),
                &command,
                &participant_digest,
                trusted_now_unix_ms,
            )
            .map_err(admission_error)?;
        publish_live_lifecycle_tx(
            &transaction,
            &prepared,
            &admitted,
            fence,
            trusted_now_unix_ms,
        )?;
        let changed = transaction
            .execute(
                r#"
                UPDATE channel_reservation_records
                SET disposition = 'live', record_version = record_version + 1,
                    store_uuid = ?1, store_lease_id = ?2, store_owner_epoch = ?3,
                    updated_at_unix_ms = ?4
                WHERE operation_id = ?5 AND reservation_id = ?6
                  AND disposition = 'pending_anchor' AND record_version = ?7
                  AND stage_batch_id = ?8
                "#,
                params![
                    &fence.store_uuid,
                    &fence.lease_id,
                    sqlite_i64(fence.owner_epoch, "store_owner_epoch")?,
                    sqlite_i64(trusted_now_unix_ms, "updated_at_unix_ms")?,
                    operation_id.as_str(),
                    &record.reservation().body.reservation_id,
                    sqlite_i64(record.record_version(), "record_version")?,
                    &record.economic_stage().batch().batch_id,
                ],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(ChannelLifecycleStoreError::Fenced);
        }
        let economic_stage = crate::economic_state_cache::finalize_stage_in_transaction(
            &transaction,
            &record.economic_stage().batch().batch_id,
            &self.serving_owner,
            trusted_now_unix_ms,
        )
        .map_err(economic_error)?;
        transaction.commit().map_err(|error| {
            owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite channel reservation finalization commit outcome is unknown: {error}"
            )))
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(owner_error)?;
        Ok(ChannelReservationStageRecordV1 {
            operation: updated_operation,
            economic_stage,
            disposition: ChannelReservationDispositionV1::Live,
            record_version: record
                .record_version()
                .checked_add(1)
                .ok_or_else(|| invalid("channel reservation version overflowed"))?,
            updated_at_unix_ms: trusted_now_unix_ms,
            ..record
        })
    }

    fn begin_channel_prepared_inner(
        &self,
        operation: &AdmissionOperationV1,
        prepared: &ChannelPreparedReservationV1,
        fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ChannelPreparedBeginResult, ChannelLifecycleStoreError> {
        if fence != &self.serving_owner.fence {
            return Err(ChannelLifecycleStoreError::Fenced);
        }
        if trusted_now_unix_ms < prepared.observed_at_unix_ms
            || trusted_now_unix_ms >= prepared.reservation.expires_at_unix_ms
        {
            return Err(invalid(
                "trusted time is outside the authenticated channel plan window",
            ));
        }
        let proposal_digest = prepared
            .reservation
            .proposal_digest()
            .map_err(channel_error)?;
        let operation = operation
            .clone()
            .with_initial_channel_reservation_proposal_digest(
                AdmissionDigest::try_new("channel_reservation_proposal_digest", proposal_digest)
                    .map_err(|error| invalid(error.to_string()))?,
            )
            .map_err(|error| invalid(error.to_string()))?;
        let encoded = encode_prepared_plan(&operation, prepared, fence)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        crate::admission_operation_store::verify_active_owner(
            &transaction,
            &self.serving_owner,
            Some(fence),
        )
        .map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(owner_error)?;
        match crate::admission_operation_store::begin_prepared_operation_tx(
            &transaction,
            &operation,
            fence,
            trusted_now_unix_ms,
        )
        .map_err(admission_error)?
        {
            crate::admission_operation_store::PreparedAdmissionBeginTxResult::Conflict {
                existing_operation_id,
            } => {
                transaction.commit().map_err(sqlite_error)?;
                return Ok(ChannelPreparedBeginResult::Conflict {
                    existing_operation_id,
                });
            }
            crate::admission_operation_store::PreparedAdmissionBeginTxResult::ExactReplay {
                operation: stored_operation,
                ..
            } => {
                let existing = load_prepared_record(&transaction, *stored_operation, true)?;
                let result = match existing {
                    Some(record)
                        if record.plan_digest == encoded.plan_digest
                            && record.plan == *prepared =>
                    {
                        ChannelPreparedBeginResult::ExactReplay(record)
                    }
                    Some(record) => ChannelPreparedBeginResult::Conflict {
                        existing_operation_id: record.operation.binding().operation_id().clone(),
                    },
                    None => ChannelPreparedBeginResult::Conflict {
                        existing_operation_id: operation.binding().operation_id().clone(),
                    },
                };
                transaction.commit().map_err(sqlite_error)?;
                return Ok(result);
            }
            crate::admission_operation_store::PreparedAdmissionBeginTxResult::Created {
                encoded: encoded_operation,
            } => {
                insert_or_verify_state(
                    &transaction,
                    prepared,
                    &encoded,
                    fence,
                    trusted_now_unix_ms,
                )?;
                insert_or_verify_lifecycle(
                    &transaction,
                    prepared,
                    &encoded,
                    fence,
                    trusted_now_unix_ms,
                )?;
                insert_prepared_plan(
                    &transaction,
                    &operation,
                    prepared,
                    &encoded,
                    fence,
                    trusted_now_unix_ms,
                )?;
                crate::admission_operation_store::append_operation_commit_with_participant(
                    &transaction,
                    &operation,
                    &encoded_operation,
                    None,
                    "begin",
                    Some(&encoded.plan_digest),
                    &self.serving_owner,
                    trusted_now_unix_ms,
                )
                .map_err(admission_error)?;
            }
        }
        transaction.commit().map_err(|error| {
            owner_error(self.serving_owner.outcome_unknown(format!(
                "sqlite channel prepared commit outcome is unknown: {error}"
            )))
        })?;
        self.serving_owner
            .sync_authority_anchor(&connection)
            .map_err(owner_error)?;
        Ok(ChannelPreparedBeginResult::Created(
            ChannelPreparedAdmissionRecordV1 {
                operation,
                plan: prepared.clone(),
                plan_digest: encoded.plan_digest,
                store_fence: fence.clone(),
                created_at_unix_ms: trusted_now_unix_ms,
            },
        ))
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ChannelLifecycleStoreError> {
        self.connection.lock().map_err(|_| {
            ChannelLifecycleStoreError::Unavailable(
                "sqlite channel lifecycle lock poisoned".to_owned(),
            )
        })
    }
}

fn encode(
    value: &impl Serialize,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, ChannelLifecycleStoreError> {
    let encoded = canonical_json_bytes(value)
        .map_err(|error| invalid(format!("{label} encoding failed: {error}")))?;
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(invalid(format!("{label} exceeds its size limit")));
    }
    Ok(encoded)
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, ChannelLifecycleStoreError> {
    i64::try_from(value).map_err(|_| invalid(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, ChannelLifecycleStoreError> {
    u64::try_from(value).map_err(|_| invalid(format!("{field} is negative")))
}

fn stored_u64_sql(value: i64, field: &'static str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Integer,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{field} is negative"),
            )
            .into(),
        )
    })
}

fn sqlite_error(error: rusqlite::Error) -> ChannelLifecycleStoreError {
    if error.sqlite_error_code() == Some(ErrorCode::ConstraintViolation) {
        ChannelLifecycleStoreError::Conflict
    } else {
        ChannelLifecycleStoreError::Unavailable(error.to_string())
    }
}

fn admission_error(error: AdmissionOperationStoreError) -> ChannelLifecycleStoreError {
    match error {
        AdmissionOperationStoreError::Unavailable(detail) => {
            ChannelLifecycleStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::Fenced => ChannelLifecycleStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => ChannelLifecycleStoreError::NotFound,
        AdmissionOperationStoreError::Invariant(detail) => invalid(detail),
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            ChannelLifecycleStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invalid(error.to_string()),
    }
}

fn channel_error(error: chio_settle::channel::ChannelError) -> ChannelLifecycleStoreError {
    invalid(error.to_string())
}

fn economic_error(error: EconomicStateCacheError) -> ChannelLifecycleStoreError {
    match error {
        EconomicStateCacheError::Unavailable(detail) => {
            ChannelLifecycleStoreError::Unavailable(detail)
        }
        EconomicStateCacheError::Fenced => ChannelLifecycleStoreError::Fenced,
        EconomicStateCacheError::NotFound => ChannelLifecycleStoreError::NotFound,
        EconomicStateCacheError::OutcomeUnknown(detail) => {
            ChannelLifecycleStoreError::OutcomeUnknown(detail)
        }
        error => invalid(error.to_string()),
    }
}

fn owner_error(error: SqliteServingOwnerError) -> ChannelLifecycleStoreError {
    match error {
        SqliteServingOwnerError::OutcomeUnknown(detail) => {
            ChannelLifecycleStoreError::OutcomeUnknown(detail)
        }
        error => ChannelLifecycleStoreError::Unavailable(error.to_string()),
    }
}

fn invalid(detail: impl Into<String>) -> ChannelLifecycleStoreError {
    ChannelLifecycleStoreError::Invalid(detail.into())
}

fn retained_projection_error(error: ChannelLifecycleStoreError) -> ChannelLifecycleStoreError {
    match error {
        ChannelLifecycleStoreError::Conflict | ChannelLifecycleStoreError::NotFound => {
            invalid("retained channel prepared projection is inconsistent")
        }
        error => error,
    }
}

#[cfg(test)]
#[path = "channel_lifecycle_store_tests.rs"]
mod tests;
