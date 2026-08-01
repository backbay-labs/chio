use std::sync::Arc;
use std::time::Duration;

use chio_core::economic_continuity::{
    economic_effect_slot_from_head, qualify_generic_economic_state_batch_advance,
    verify_economic_effect_cancellation_advance, verify_economic_idempotent_recovery,
    verify_economic_state_batch_advance, verify_economic_state_batch_commit,
    verify_economic_state_view, verify_economic_target_status, EconomicAdmissionHandoffStateV1,
    EconomicAdmissionHandoffV1, EconomicAdmissionHandoffVerifier, EconomicCheckpointReadQuery,
    EconomicEffectCancellationProofVerifier, EconomicEffectSlotV1, EconomicEffectStateV1,
    EconomicIdempotentTargetVerifier, EconomicRequestKeyV1, EconomicStateAnchor,
    EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateReadQuery,
    EconomicTargetStatusVerifier, EconomicTransitionProofVerifier,
    VerifiedEconomicIdempotentRecovery, VerifiedEconomicStateBatchAdvance,
    VerifiedEconomicTargetStatus,
};
use chio_kernel::admission_operation::{
    expected_dispatch_committed_version, verified_pre_dispatch_compensation_projection,
    AdmissionIdentifier, AdmissionMutationSequencer, AdmissionOperationError, AdmissionOperationId,
    AdmissionOperationKind, AdmissionOperationState, AdmissionOperationStoreError,
    AdmissionProjectionContext, AdmissionTerminal, QualifiedAdmissionOperationStore,
    QualifiedAdmissionOperationStoreExt, StoreMutationFence,
};
use chio_kernel::receipt_store::AnchoredAdmissionProjectionStore;
use chio_kernel::{ReceiptStoreError, ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND};
use chio_store_sqlite::{
    EconomicOperationStageBinding, EconomicStateCacheError, EconomicStateStageRecord,
    EconomicStateStageStatus, SqliteEconomicStateCache,
};

const MAX_RECOVERY_LEASE_DURATION: Duration = Duration::from_secs(5 * 60);
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum EconomicStateRecoveryError {
    #[error(transparent)]
    Cache(#[from] EconomicStateCacheError),
    #[error(transparent)]
    Anchor(#[from] EconomicStateAnchorError),
    #[error(transparent)]
    Admission(#[from] AdmissionOperationStoreError),
    #[error(transparent)]
    Projection(#[from] AdmissionOperationError),
    #[error(transparent)]
    Receipt(#[from] ReceiptStoreError),
    #[error("economic pre-dispatch compensation was rejected: {0}")]
    CompensationRejected(String),
    #[error("economic recovery configuration is invalid: {0}")]
    InvalidConfiguration(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicRecoveryOutcome {
    Finalized(EconomicStateStageRecord),
    Discarded(EconomicStateStageRecord),
    Quarantined(EconomicStateStageRecord),
    Pending(EconomicStateStageRecord),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicPreDispatchCompensation {
    terminal: AdmissionTerminal,
    stage: EconomicStateStageRecord,
}

impl EconomicPreDispatchCompensation {
    #[must_use]
    pub const fn terminal(&self) -> &AdmissionTerminal {
        &self.terminal
    }

    #[must_use]
    pub const fn stage(&self) -> &EconomicStateStageRecord {
        &self.stage
    }
}

#[derive(Debug)]
pub enum EconomicEffectRecoveryDecision {
    TargetStatus(VerifiedEconomicTargetStatus),
    IdempotentRetry(VerifiedEconomicIdempotentRecovery),
    LockedUnknown(Box<EconomicEffectRecoveryLock>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EconomicEffectRecoveryLock {
    current_slot: EconomicEffectSlotV1,
    next_slot: EconomicEffectSlotV1,
}

impl EconomicEffectRecoveryLock {
    #[must_use]
    pub fn current_slot(&self) -> &EconomicEffectSlotV1 {
        &self.current_slot
    }

    #[must_use]
    pub fn next_slot(&self) -> &EconomicEffectSlotV1 {
        &self.next_slot
    }
}

pub fn qualify_committed_effect_recovery(
    slot: &EconomicEffectSlotV1,
    target_status: Option<(&str, &dyn EconomicTargetStatusVerifier)>,
    idempotent_target: Option<&dyn EconomicIdempotentTargetVerifier>,
) -> Result<EconomicEffectRecoveryDecision, EconomicStateAnchorError> {
    slot.validate()?;
    if !matches!(
        slot.state,
        EconomicEffectStateV1::DispatchCommitted | EconomicEffectStateV1::Unknown
    ) || target_status.is_some() && idempotent_target.is_some()
    {
        return Err(EconomicStateAnchorError::IdempotentRecoveryRejected);
    }
    if let Some((evidence_digest, verifier)) = target_status {
        return Ok(
            match verify_economic_target_status(slot, evidence_digest, verifier) {
                Ok(status) => EconomicEffectRecoveryDecision::TargetStatus(status),
                Err(_) => {
                    EconomicEffectRecoveryDecision::LockedUnknown(Box::new(unknown_lock(slot)?))
                }
            },
        );
    }
    if let Some(verifier) = idempotent_target {
        return Ok(match verify_economic_idempotent_recovery(slot, verifier) {
            Ok(retry) => EconomicEffectRecoveryDecision::IdempotentRetry(retry),
            Err(_) => EconomicEffectRecoveryDecision::LockedUnknown(Box::new(unknown_lock(slot)?)),
        });
    }
    Ok(EconomicEffectRecoveryDecision::LockedUnknown(Box::new(
        unknown_lock(slot)?,
    )))
}

fn unknown_lock(
    slot: &EconomicEffectSlotV1,
) -> Result<EconomicEffectRecoveryLock, EconomicStateAnchorError> {
    let mut next_slot = slot.clone();
    if slot.state == EconomicEffectStateV1::DispatchCommitted {
        next_slot.state = EconomicEffectStateV1::Unknown;
        slot.validate_successor(&next_slot)?;
    }
    Ok(EconomicEffectRecoveryLock {
        current_slot: slot.clone(),
        next_slot,
    })
}

pub struct EconomicStateRecovery {
    cache: SqliteEconomicStateCache,
    anchor: Arc<dyn EconomicStateAnchor>,
    operations: Arc<dyn AnchoredAdmissionProjectionStore>,
    transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
    cancellation_verifier: Arc<dyn EconomicEffectCancellationProofVerifier>,
    admission_verifier: Arc<dyn EconomicAdmissionHandoffVerifier>,
    pins: EconomicStateAnchorPins,
    active_fence: StoreMutationFence,
    claimant_id: AdmissionIdentifier,
    recovery_lease_duration: Duration,
    mutation_sequencer: AdmissionMutationSequencer,
}

impl EconomicStateRecovery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cache: SqliteEconomicStateCache,
        anchor: Arc<dyn EconomicStateAnchor>,
        operations: Arc<dyn AnchoredAdmissionProjectionStore>,
        transition_verifier: Arc<dyn EconomicTransitionProofVerifier>,
        cancellation_verifier: Arc<dyn EconomicEffectCancellationProofVerifier>,
        admission_verifier: Arc<dyn EconomicAdmissionHandoffVerifier>,
        pins: EconomicStateAnchorPins,
        active_fence: StoreMutationFence,
        claimant_id: AdmissionIdentifier,
        recovery_lease_duration: Duration,
    ) -> Result<Self, EconomicStateRecoveryError> {
        pins.validate()?;
        if recovery_lease_duration.is_zero()
            || recovery_lease_duration > MAX_RECOVERY_LEASE_DURATION
            || active_fence.store_uuid.is_empty()
            || active_fence.lease_id.is_empty()
            || active_fence.owner_epoch == 0
        {
            return Err(EconomicStateRecoveryError::InvalidConfiguration(
                "pins, serving fence, and lease duration must be bounded and nonzero".to_owned(),
            ));
        }
        let mutation_sequencer = AdmissionMutationSequencer::for_fence(&active_fence)
            .map_err(|error| EconomicStateRecoveryError::InvalidConfiguration(error.to_string()))?;
        Ok(Self {
            cache,
            anchor,
            operations,
            transition_verifier,
            cancellation_verifier,
            admission_verifier,
            pins,
            active_fence,
            claimant_id,
            recovery_lease_duration,
            mutation_sequencer,
        })
    }

    pub fn recover_stage(
        &self,
        batch_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let _mutation_guard = self
            .mutation_sequencer
            .lock()
            .map_err(|error| EconomicStateRecoveryError::InvalidConfiguration(error.to_string()))?;
        validate_trusted_time(trusted_now_unix_ms)?;
        let stage = self
            .cache
            .load_stage(batch_id)?
            .ok_or(EconomicStateCacheError::NotFound)?;
        let anchored_terminal = stage.descriptor().is_some_and(|descriptor| {
            descriptor.kind() == ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
        });
        match stage.status() {
            EconomicStateStageStatus::DbFinalized if anchored_terminal => {
                return self.finalize(stage, trusted_now_unix_ms)
            }
            EconomicStateStageStatus::DbFinalized => {
                return Ok(EconomicRecoveryOutcome::Finalized(stage))
            }
            EconomicStateStageStatus::Discarded => {
                return Ok(EconomicRecoveryOutcome::Discarded(stage))
            }
            EconomicStateStageStatus::Quarantined => {
                return Ok(EconomicRecoveryOutcome::Quarantined(stage))
            }
            EconomicStateStageStatus::EconomicAnchorAdvanced => {
                return self.finalize(stage, trusted_now_unix_ms)
            }
            EconomicStateStageStatus::DbStaged => {}
        }

        let current = verify_economic_state_view(stage.base_view().clone(), &self.pins)?;
        let advance = verify_economic_state_batch_advance(
            &current,
            stage.batch().clone(),
            &self.pins,
            self.transition_verifier.as_ref(),
        )?;
        let cancellation_shape = effect_cancellation_batch_shape(&advance);
        if cancellation_shape == EffectCancellationBatchShape::Invalid {
            return self.quarantine(
                stage,
                "generic economic stage contains a mixed or malformed effect cancellation",
                trusted_now_unix_ms,
            );
        }
        if cancellation_shape == EffectCancellationBatchShape::Exact && !anchored_terminal {
            return self.quarantine(
                stage,
                "effect cancellation is missing anchored terminal authority",
                trusted_now_unix_ms,
            );
        }
        let cancellation = if cancellation_shape == EffectCancellationBatchShape::Exact {
            Some(verify_economic_effect_cancellation_advance(
                verify_economic_state_batch_advance(
                    &current,
                    stage.batch().clone(),
                    &self.pins,
                    self.transition_verifier.as_ref(),
                )?,
                self.cancellation_verifier.as_ref(),
                self.admission_verifier.as_ref(),
            )?)
        } else {
            None
        };
        let query = state_query(advance.batch());
        let observed = match self.anchor.read_state(&query) {
            Ok(observed) => observed,
            Err(_) => return Ok(EconomicRecoveryOutcome::Pending(stage)),
        };
        let base = advance.current().view();
        let batch = advance.batch();

        if observed.view().checkpoint_sequence == batch.checkpoint_sequence {
            if observed.view().checkpoint_digest != batch.checkpoint_digest {
                return self.quarantine(
                    stage,
                    "external anchor checkpoint conflicts with the staged batch",
                    trusted_now_unix_ms,
                );
            }
            return self.record_and_finalize(&advance, &observed, trusted_now_unix_ms);
        }

        if observed.view().checkpoint_sequence > batch.checkpoint_sequence {
            let retained_query = EconomicCheckpointReadQuery {
                checkpoint_sequence: batch.checkpoint_sequence,
                checkpoint_digest: batch.checkpoint_digest.clone(),
                query,
            };
            let retained = match self.anchor.read_checkpoint_state(&retained_query) {
                Ok(retained) => retained,
                Err(_) => return Ok(EconomicRecoveryOutcome::Pending(stage)),
            };
            return self.record_and_finalize(&advance, &retained, trusted_now_unix_ms);
        }

        if observed.view().checkpoint_sequence < base.checkpoint_sequence {
            return Ok(EconomicRecoveryOutcome::Pending(stage));
        }
        if observed.view().checkpoint_sequence != base.checkpoint_sequence
            || observed.view().checkpoint_digest != base.checkpoint_digest
        {
            return self.quarantine(
                stage,
                "external anchor predecessor diverges from the staged batch",
                trusted_now_unix_ms,
            );
        }

        if stage
            .not_after_unix_ms()
            .is_some_and(|not_after| trusted_now_unix_ms >= not_after)
        {
            return self.resolve_expired_unanchored_stage(stage, trusted_now_unix_ms);
        }

        if anchored_terminal {
            self.operations.qualify_anchored_terminal_projection(
                batch_id,
                &self.active_fence,
                trusted_now_unix_ms,
            )?;
        } else if let Some(binding) = stage.operation_binding() {
            if !self.operation_authorizes_retry(binding, trusted_now_unix_ms)? {
                let discarded = self.cache.discard_unanchored_stage(
                    batch_id,
                    "admission operation no longer authorizes the unanchored batch",
                    &self.active_fence,
                    trusted_now_unix_ms,
                )?;
                return Ok(EconomicRecoveryOutcome::Discarded(discarded));
            }
        }

        if let Some(cancellation) = cancellation {
            match self
                .anchor
                .compare_and_swap_effect_cancellation(cancellation)
            {
                Ok(committed) => {
                    self.record_and_finalize(&advance, committed.committed(), trusted_now_unix_ms)
                }
                Err(_) => self.resolve_uncertain_cas(stage, &advance, trusted_now_unix_ms),
            }
        } else {
            let generic = match qualify_generic_economic_state_batch_advance(&advance) {
                Ok(generic) => generic,
                Err(_) => {
                    return self.quarantine(
                        stage,
                        "generic economic stage contains a forbidden effect transition",
                        trusted_now_unix_ms,
                    )
                }
            };
            match self.anchor.compare_and_swap_batch(generic) {
                Ok(committed) => {
                    self.record_and_finalize(&advance, &committed, trusted_now_unix_ms)
                }
                Err(_) => self.resolve_uncertain_cas(stage, &advance, trusted_now_unix_ms),
            }
        }
    }

    pub fn recover_pending(
        &self,
        limit: usize,
        trusted_now_unix_ms: u64,
    ) -> Result<Vec<EconomicRecoveryOutcome>, EconomicStateRecoveryError> {
        let stages = self.cache.list_pending(limit)?;
        stages
            .iter()
            .map(|stage| self.recover_stage(&stage.batch().batch_id, trusted_now_unix_ms))
            .collect()
    }

    pub fn compensate_unanchored_stage_before_dispatch(
        &self,
        batch_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicPreDispatchCompensation, EconomicStateRecoveryError> {
        let _mutation_guard = self
            .mutation_sequencer
            .lock()
            .map_err(|error| EconomicStateRecoveryError::InvalidConfiguration(error.to_string()))?;
        validate_trusted_time(trusted_now_unix_ms)?;
        let stage = self
            .cache
            .load_stage(batch_id)?
            .ok_or(EconomicStateCacheError::NotFound)?;
        let current = verify_economic_state_view(stage.base_view().clone(), &self.pins)?;
        let advance = verify_economic_state_batch_advance(
            &current,
            stage.batch().clone(),
            &self.pins,
            self.transition_verifier.as_ref(),
        )?;
        let observed = self.anchor.read_state(&state_query(advance.batch()))?;
        if observed.view().checkpoint_sequence != current.view().checkpoint_sequence
            || observed.view().checkpoint_digest != current.view().checkpoint_digest
        {
            return Err(EconomicStateRecoveryError::CompensationRejected(
                "the external anchor no longer retains the staged predecessor".to_owned(),
            ));
        }
        self.compensate_verified_unanchored_stage(stage, trusted_now_unix_ms)
    }

    fn resolve_expired_unanchored_stage(
        &self,
        stage: EconomicStateStageRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        match self.compensate_verified_unanchored_stage(stage.clone(), trusted_now_unix_ms) {
            Ok(compensation) => Ok(EconomicRecoveryOutcome::Discarded(compensation.stage)),
            Err(
                EconomicStateRecoveryError::CompensationRejected(_)
                | EconomicStateRecoveryError::Projection(_),
            ) => self.quarantine(
                stage,
                "bounded economic stage expired without verified pre-dispatch compensation",
                trusted_now_unix_ms,
            ),
            Err(error) => Err(error),
        }
    }

    fn compensate_verified_unanchored_stage(
        &self,
        stage: EconomicStateStageRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicPreDispatchCompensation, EconomicStateRecoveryError> {
        if stage.status() != EconomicStateStageStatus::DbStaged {
            return Err(EconomicStateRecoveryError::CompensationRejected(
                "the staged batch is no longer unanchored".to_owned(),
            ));
        }
        if stage.descriptor().is_some_and(|descriptor| {
            descriptor.kind() == ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
        }) {
            return Err(EconomicStateRecoveryError::CompensationRejected(
                "the staged batch retains terminal projection authority".to_owned(),
            ));
        }
        let binding = stage.operation_binding().ok_or_else(|| {
            EconomicStateRecoveryError::CompensationRejected(
                "the staged batch is not bound to an admission operation".to_owned(),
            )
        })?;
        if !stage_effects_are_predispatch(&stage, binding)? {
            return Err(EconomicStateRecoveryError::CompensationRejected(
                "the staged batch retains post-dispatch effect authority".to_owned(),
            ));
        }
        let batch_id = stage.batch().batch_id.clone();

        let operation_id = AdmissionOperationId::from_persisted(binding.operation_id().to_owned())
            .map_err(|error| EconomicStateRecoveryError::InvalidConfiguration(error.to_string()))?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)?
            .ok_or(AdmissionOperationStoreError::NotFound)?;
        if operation.state().is_terminal() {
            let expected_version = binding.operation_version().checked_add(1).ok_or_else(|| {
                EconomicStateRecoveryError::CompensationRejected(
                    "the staged operation version overflowed".to_owned(),
                )
            })?;
            if operation.state() != AdmissionOperationState::CompensatedBeforeDispatch
                || operation.version() != expected_version
                || operation.coordinator_lease_epoch() != binding.coordinator_lease_epoch()
            {
                return Err(EconomicStateRecoveryError::CompensationRejected(
                    "the terminal operation is not the staged compensation successor".to_owned(),
                ));
            }
            let replay = operation.terminal_replay().cloned().ok_or_else(|| {
                EconomicStateRecoveryError::CompensationRejected(
                    "the compensated operation omitted terminal replay evidence".to_owned(),
                )
            })?;
            let discarded = self.cache.discard_unanchored_stage(
                &batch_id,
                "admission operation was compensated before economic dispatch",
                &self.active_fence,
                trusted_now_unix_ms,
            )?;
            return Ok(EconomicPreDispatchCompensation {
                terminal: AdmissionTerminal {
                    operation_id,
                    state: operation.state(),
                    replay,
                },
                stage: discarded,
            });
        }
        if operation.state() != binding.operation_state()
            || operation.version() != binding.operation_version()
            || operation.coordinator_lease_epoch() != binding.coordinator_lease_epoch()
            || binding.store_fence() != &self.active_fence
        {
            return Err(EconomicStateRecoveryError::CompensationRejected(
                "the admission operation changed after the batch was staged".to_owned(),
            ));
        }
        let (claimant_id, expires_at_unix_ms) =
            self.stage_recovery_claim(binding, trusted_now_unix_ms)?;
        let lease = self.operations.claim_recovery(
            &operation_id,
            operation.version(),
            &claimant_id,
            trusted_now_unix_ms,
            expires_at_unix_ms,
            &self.active_fence,
        )?;
        let context = AdmissionProjectionContext {
            operation_id: operation_id.clone(),
            request_id: operation.replay_key().request_id,
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            store_fence: self.active_fence.clone(),
        };
        let projection = verified_pre_dispatch_compensation_projection(&operation, context)?;
        let terminal = self.operations.commit_admission_projection(&projection)?;
        if terminal.operation_id != operation_id
            || terminal.state != AdmissionOperationState::CompensatedBeforeDispatch
        {
            return Err(EconomicStateRecoveryError::CompensationRejected(
                "the admission store returned a different terminal operation".to_owned(),
            ));
        }
        let discarded = self.cache.discard_unanchored_stage(
            &batch_id,
            "admission operation was compensated before economic dispatch",
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        Ok(EconomicPreDispatchCompensation {
            terminal,
            stage: discarded,
        })
    }

    fn operation_authorizes_retry(
        &self,
        binding: &EconomicOperationStageBinding,
        trusted_now_unix_ms: u64,
    ) -> Result<bool, EconomicStateRecoveryError> {
        let operation_id = AdmissionOperationId::from_persisted(binding.operation_id().to_owned())
            .map_err(|error| EconomicStateRecoveryError::InvalidConfiguration(error.to_string()))?;
        let Some(operation) = self.operations.load_by_operation_id(&operation_id)? else {
            return Ok(false);
        };
        if operation.state().is_terminal()
            || operation.state() != binding.operation_state()
            || operation.version() != binding.operation_version()
            || operation.coordinator_lease_epoch() != binding.coordinator_lease_epoch()
            || binding.store_fence() != &self.active_fence
        {
            return Ok(false);
        }
        let (claimant_id, expires_at) = self.stage_recovery_claim(binding, trusted_now_unix_ms)?;
        self.operations.claim_recovery(
            &operation_id,
            operation.version(),
            &claimant_id,
            trusted_now_unix_ms,
            expires_at,
            &self.active_fence,
        )?;
        let Some(revalidated) = self.operations.load_by_operation_id(&operation_id)? else {
            return Ok(false);
        };
        Ok(revalidated == operation)
    }

    fn stage_recovery_claim(
        &self,
        binding: &EconomicOperationStageBinding,
        trusted_now_unix_ms: u64,
    ) -> Result<(AdmissionIdentifier, u64), EconomicStateRecoveryError> {
        if binding.recovery_expires_at_unix_ms() > trusted_now_unix_ms {
            return Ok((
                AdmissionIdentifier::try_new(
                    "recovery_claimant_id",
                    binding.recovery_claimant_id().to_owned(),
                )?,
                binding.recovery_expires_at_unix_ms(),
            ));
        }
        let duration_ms =
            u64::try_from(self.recovery_lease_duration.as_millis()).map_err(|_| {
                EconomicStateRecoveryError::InvalidConfiguration(
                    "recovery lease duration overflowed u64".to_owned(),
                )
            })?;
        let expires_at = trusted_now_unix_ms
            .checked_add(duration_ms)
            .filter(|value| *value <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                EconomicStateRecoveryError::InvalidConfiguration(
                    "recovery lease expiry overflowed I-JSON".to_owned(),
                )
            })?;
        Ok((self.claimant_id.clone(), expires_at))
    }

    fn resolve_uncertain_cas(
        &self,
        stage: EconomicStateStageRecord,
        advance: &VerifiedEconomicStateBatchAdvance,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let query = state_query(advance.batch());
        let Ok(observed) = self.anchor.read_state(&query) else {
            return Ok(EconomicRecoveryOutcome::Pending(stage));
        };
        if observed.view().checkpoint_sequence == advance.batch().checkpoint_sequence
            && observed.view().checkpoint_digest == advance.batch().checkpoint_digest
        {
            return self.record_and_finalize(advance, &observed, trusted_now_unix_ms);
        }
        if observed.view().checkpoint_sequence > advance.batch().checkpoint_sequence {
            let retained_query = EconomicCheckpointReadQuery {
                checkpoint_sequence: advance.batch().checkpoint_sequence,
                checkpoint_digest: advance.batch().checkpoint_digest.clone(),
                query,
            };
            if let Ok(retained) = self.anchor.read_checkpoint_state(&retained_query) {
                return self.record_and_finalize(advance, &retained, trusted_now_unix_ms);
            }
        }
        Ok(EconomicRecoveryOutcome::Pending(stage))
    }

    fn record_and_finalize(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        committed: &chio_core::economic_continuity::VerifiedEconomicStateView,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        verify_economic_state_batch_commit(advance, committed, &self.pins)?;
        let advanced = self.cache.record_anchor_advanced(
            advance,
            committed,
            &self.pins,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        self.finalize(advanced, trusted_now_unix_ms)
    }

    fn finalize(
        &self,
        stage: EconomicStateStageRecord,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let batch_id = &stage.batch().batch_id;
        let finalized = if stage.descriptor().is_some_and(|descriptor| {
            descriptor.kind() == ADMISSION_TERMINAL_PROJECTION_DESCRIPTOR_KIND
        }) {
            self.operations.commit_anchored_terminal_projection(
                batch_id,
                &self.active_fence,
                trusted_now_unix_ms,
            )?;
            self.cache
                .load_stage(batch_id)?
                .filter(|record| record.status() == EconomicStateStageStatus::DbFinalized)
                .ok_or(EconomicStateCacheError::Conflict)?
        } else {
            self.cache
                .finalize_stage(batch_id, &self.active_fence, trusted_now_unix_ms)?
        };
        Ok(EconomicRecoveryOutcome::Finalized(finalized))
    }

    fn quarantine(
        &self,
        stage: EconomicStateStageRecord,
        reason: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<EconomicRecoveryOutcome, EconomicStateRecoveryError> {
        let quarantined = self.cache.quarantine_stage(
            &stage.batch().batch_id,
            reason,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        Ok(EconomicRecoveryOutcome::Quarantined(quarantined))
    }
}

fn stage_effects_are_predispatch(
    stage: &EconomicStateStageRecord,
    binding: &EconomicOperationStageBinding,
) -> Result<bool, EconomicStateRecoveryError> {
    for head in stage.base_view().heads.iter().filter(|head| {
        head.resource_key.resource_family == "effect_slot"
            && head.operation_id.as_deref() == Some(binding.operation_id())
    }) {
        let slot = economic_effect_slot_from_head(head).map_err(|_| {
            EconomicStateRecoveryError::CompensationRejected(
                "the staged effect authority is invalid".to_owned(),
            )
        })?;
        if slot.state != EconomicEffectStateV1::Ready {
            return Ok(false);
        }
    }
    Ok(true)
}

pub struct QualifiedEconomicAdmissionHandoffVerifier {
    operations: Arc<dyn QualifiedAdmissionOperationStore>,
    active_fence: StoreMutationFence,
}

impl QualifiedEconomicAdmissionHandoffVerifier {
    #[must_use]
    pub fn new(
        operations: Arc<dyn QualifiedAdmissionOperationStore>,
        active_fence: StoreMutationFence,
    ) -> Self {
        Self {
            operations,
            active_fence,
        }
    }
}

impl EconomicAdmissionHandoffVerifier for QualifiedEconomicAdmissionHandoffVerifier {
    fn verify_operation_active(&self, operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        let operation_id = AdmissionOperationId::from_persisted(operation_id.to_owned())
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?
            .ok_or(EconomicStateAnchorError::AdmissionHandoffRejected)?;
        if operation.state().is_terminal() {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        Ok(())
    }

    fn verify_prepared_effect(
        &self,
        slot: &EconomicEffectSlotV1,
    ) -> Result<(), EconomicStateAnchorError> {
        slot.validate()?;
        if slot.admission_handoff.store_fence != self.active_fence {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        let operation_id = AdmissionOperationId::from_persisted(slot.operation_id.clone())
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?
            .ok_or(EconomicStateAnchorError::AdmissionHandoffRejected)?;
        let kind = operation.binding().kind();
        let (handoff_state, expected_handoff_version, requires_genesis_version) = match kind {
            AdmissionOperationKind::ToolDispatch
            | AdmissionOperationKind::GovernedActiveResponse => (
                EconomicAdmissionHandoffStateV1::DispatchCommitted,
                expected_dispatch_committed_version(
                    kind,
                    operation.binding().participant_requirements(),
                    operation.version(),
                )
                .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?,
                false,
            ),
            AdmissionOperationKind::GovernedEconomicMutation => (
                EconomicAdmissionHandoffStateV1::MutationSubmitted,
                operation
                    .version()
                    .checked_add(2)
                    .ok_or(EconomicStateAnchorError::AdmissionHandoffRejected)?,
                true,
            ),
        };
        let binding = operation.binding();
        if operation.state() != AdmissionOperationState::Prepared
            || requires_genesis_version && operation.version() != 1
            || slot.operation_id != binding.operation_id().as_str()
            || slot.request.request_namespace_digest != binding.request_namespace_digest().as_str()
            || slot.request.request_id != binding.request_id().as_str()
            || slot.request.request_binding_digest != binding.request_binding_hash().as_str()
            || slot.parameters_digest != binding.action_parameter_hash().as_str()
            || slot.admission_handoff.state != handoff_state
            || slot.admission_handoff.operation_version != expected_handoff_version
            || slot.admission_handoff.lifecycle_fence != operation.coordinator_lease_epoch()
        {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        Ok(())
    }

    fn verify_handoff(
        &self,
        operation_id: &str,
        handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError> {
        handoff.validate()?;
        if !serves_historical_fence(&handoff.store_fence, &self.active_fence) {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        let operation_id = AdmissionOperationId::from_persisted(operation_id.to_owned())
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)
            .map_err(|_| EconomicStateAnchorError::AdmissionHandoffRejected)?
            .ok_or(EconomicStateAnchorError::AdmissionHandoffRejected)?;
        if operation.version() != handoff.operation_version
            || operation.coordinator_lease_epoch() != handoff.lifecycle_fence
        {
            return Err(EconomicStateAnchorError::AdmissionHandoffRejected);
        }
        let valid = match handoff.state {
            EconomicAdmissionHandoffStateV1::DispatchCommitted => {
                matches!(
                    operation.binding().kind(),
                    AdmissionOperationKind::ToolDispatch
                        | AdmissionOperationKind::GovernedActiveResponse
                ) && operation.state() == AdmissionOperationState::DispatchCommitted
                    && operation.dispatch_commit().is_some_and(|commit| {
                        commit.committed_version == operation.version()
                            && commit.store_fence == handoff.store_fence
                    })
            }
            EconomicAdmissionHandoffStateV1::MutationSubmitted => {
                operation.binding().kind() == AdmissionOperationKind::GovernedEconomicMutation
                    && operation.state() == AdmissionOperationState::MutationSubmitted
            }
        };
        if valid {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }
}

fn serves_historical_fence(historical: &StoreMutationFence, current: &StoreMutationFence) -> bool {
    historical.store_uuid == current.store_uuid
        && (historical == current || current.owner_epoch > historical.owner_epoch)
}

fn state_query(
    batch: &chio_core::economic_continuity::EconomicStateBatchV1,
) -> EconomicStateReadQuery {
    EconomicStateReadQuery {
        resource_keys: batch
            .transitions
            .iter()
            .map(|transition| transition.resource_key.clone())
            .collect(),
        request_keys: batch
            .request_replays
            .iter()
            .map(|replay| EconomicRequestKeyV1 {
                request_namespace_digest: replay.request.request_namespace_digest.clone(),
                request_id: replay.request.request_id.clone(),
            })
            .collect(),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EffectCancellationBatchShape {
    None,
    Exact,
    Invalid,
}

fn effect_cancellation_batch_shape(
    advance: &VerifiedEconomicStateBatchAdvance,
) -> EffectCancellationBatchShape {
    let batch = advance.batch();
    let mut contains_no_effect = false;
    for transition in &batch.transitions {
        if transition.resource_key.resource_family != "effect_slot" {
            continue;
        }
        if advance
            .current()
            .view()
            .head(&transition.resource_key)
            .is_some_and(|head| economic_effect_slot_from_head(head).is_err())
        {
            return EffectCancellationBatchShape::Invalid;
        }
        let Ok(next_slot) = economic_effect_slot_from_head(&transition.next_head) else {
            return EffectCancellationBatchShape::Invalid;
        };
        contains_no_effect |= next_slot.state == EconomicEffectStateV1::NoEffect;
    }
    if !contains_no_effect {
        return EffectCancellationBatchShape::None;
    }
    if batch.transitions.len() == 1
        && batch.effect_slots.is_empty()
        && batch.request_replays.is_empty()
        && batch.transitions[0].prepared_effect.is_none()
    {
        EffectCancellationBatchShape::Exact
    } else {
        EffectCancellationBatchShape::Invalid
    }
}

fn validate_trusted_time(value: u64) -> Result<(), EconomicStateRecoveryError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(EconomicStateRecoveryError::InvalidConfiguration(
            "trusted recovery time is outside the I-JSON range".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "economic_state_recovery_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
