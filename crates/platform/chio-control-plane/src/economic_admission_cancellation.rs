use std::sync::Arc;
use std::time::Duration;

use chio_core::crypto::Keypair;
use chio_core::economic_continuity::{
    EconomicNoEffectKindV1, EconomicStateAnchor, EconomicStateAnchorError, EconomicStateAnchorPins,
    VerifiedEconomicEffectCancellationAdvance,
};
use chio_kernel::admission_operation::{
    verified_economic_cancellation_projection, verify_economic_cancellation_terminal_replay,
    AdmissionIdentifier, AdmissionMutationSequencer, AdmissionOperationError, AdmissionOperationId,
    AdmissionOperationState, AdmissionProjectionContext, AdmissionTerminal,
    QualifiedAdmissionOperationStoreExt, SignedAdmissionTerminalProjectionV1, StoreMutationFence,
};
use chio_kernel::receipt_store::AnchoredAdmissionProjectionStore;
use chio_kernel::ReceiptStoreError;

const MAX_CANCELLATION_LEASE_DURATION: Duration = Duration::from_secs(5 * 60);
const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

#[derive(Debug, thiserror::Error)]
pub enum EconomicAdmissionCancellationError {
    #[error("economic admission cancellation configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error(transparent)]
    AdmissionStore(#[from] chio_kernel::admission_operation::AdmissionOperationStoreError),
    #[error(transparent)]
    Projection(#[from] AdmissionOperationError),
    #[error(transparent)]
    Anchor(#[from] EconomicStateAnchorError),
    #[error(transparent)]
    Receipt(#[from] ReceiptStoreError),
    #[error("paid economic cancellation requires the durable settlement coordinator")]
    PaymentSettlementRequired,
}

pub struct EconomicAdmissionCancellationCoordinator {
    anchor: Arc<dyn EconomicStateAnchor>,
    operations: Arc<dyn AnchoredAdmissionProjectionStore>,
    pins: EconomicStateAnchorPins,
    active_fence: StoreMutationFence,
    signer: Keypair,
    lease_duration: Duration,
    mutation_sequencer: AdmissionMutationSequencer,
}

impl EconomicAdmissionCancellationCoordinator {
    pub fn new(
        anchor: Arc<dyn EconomicStateAnchor>,
        operations: Arc<dyn AnchoredAdmissionProjectionStore>,
        pins: EconomicStateAnchorPins,
        active_fence: StoreMutationFence,
        signer: Keypair,
        lease_duration: Duration,
    ) -> Result<Self, EconomicAdmissionCancellationError> {
        pins.validate()?;
        if lease_duration.is_zero() || lease_duration > MAX_CANCELLATION_LEASE_DURATION {
            return Err(EconomicAdmissionCancellationError::InvalidConfiguration(
                "recovery lease duration must be bounded and nonzero".to_owned(),
            ));
        }
        let mutation_sequencer =
            AdmissionMutationSequencer::for_fence(&active_fence).map_err(|error| {
                EconomicAdmissionCancellationError::InvalidConfiguration(error.to_string())
            })?;
        Ok(Self {
            anchor,
            operations,
            pins,
            active_fence,
            signer,
            lease_duration,
            mutation_sequencer,
        })
    }

    pub fn cancel_after_handoff(
        &self,
        advance: VerifiedEconomicEffectCancellationAdvance,
        trusted_now_unix_ms: u64,
    ) -> Result<AdmissionTerminal, EconomicAdmissionCancellationError> {
        validate_trusted_time(trusted_now_unix_ms)?;
        let operation_id =
            AdmissionOperationId::from_persisted(advance.slot().operation_id.clone())?;
        let expected_state = expected_terminal_state(advance.kind())?;
        let _mutation_guard = self.mutation_sequencer.lock().map_err(|error| {
            EconomicAdmissionCancellationError::InvalidConfiguration(error.to_string())
        })?;
        let operation = self
            .operations
            .load_by_operation_id(&operation_id)?
            .ok_or(chio_kernel::admission_operation::AdmissionOperationStoreError::NotFound)?;
        verify_request_binding(&operation, &advance)?;
        if operation.state().is_terminal() {
            if operation.state() != expected_state {
                return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
            }
            verify_economic_cancellation_terminal_replay(&operation, &advance)?;
            let replay = operation
                .terminal_replay()
                .cloned()
                .ok_or(AdmissionOperationError::TerminalReplayMismatch)?;
            return Ok(AdmissionTerminal {
                operation_id,
                state: expected_state,
                replay,
            });
        }
        if operation.binding().participant_requirements().payment {
            return Err(EconomicAdmissionCancellationError::PaymentSettlementRequired);
        }
        let lease_ms = u64::try_from(self.lease_duration.as_millis()).map_err(|_| {
            EconomicAdmissionCancellationError::InvalidConfiguration(
                "recovery lease duration overflowed u64".to_owned(),
            )
        })?;
        let expires_at_unix_ms = trusted_now_unix_ms
            .checked_add(lease_ms)
            .filter(|value| *value <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or_else(|| {
                EconomicAdmissionCancellationError::InvalidConfiguration(
                    "recovery lease expiry overflowed I-JSON".to_owned(),
                )
            })?;
        let lease = self.operations.claim_recovery(
            &operation_id,
            operation.version(),
            &AdmissionIdentifier::try_new(
                "claimant_id",
                format!("kernel:{}", self.signer.public_key().to_hex()),
            )?,
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
        let projection = verified_economic_cancellation_projection(&operation, context, &advance)?;
        let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
            &operation,
            &projection,
            &self.operations.admission_projection_capabilities(),
            &self.signer,
        )?;
        let expected_terminal = envelope.verify()?.terminal()?;
        let batch_id = advance.batch().batch_id.clone();
        self.operations.stage_anchored_terminal_projection(
            advance.state_advance(),
            &lease,
            &envelope,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        self.operations.qualify_anchored_terminal_projection(
            &batch_id,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        let cancellation = self.anchor.compare_and_swap_effect_cancellation(advance)?;
        self.operations.record_anchored_terminal_projection(
            cancellation.cancellation().state_advance(),
            cancellation.committed(),
            &self.pins,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        let terminal = self.operations.commit_anchored_terminal_projection(
            &batch_id,
            &self.active_fence,
            trusted_now_unix_ms,
        )?;
        if terminal != expected_terminal
            || terminal.operation_id != operation_id
            || terminal.state != expected_state
        {
            return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
        }
        Ok(terminal)
    }
}

fn expected_terminal_state(
    kind: EconomicNoEffectKindV1,
) -> Result<AdmissionOperationState, EconomicAdmissionCancellationError> {
    match kind {
        EconomicNoEffectKindV1::VerifiedTransportNotAccepted => {
            Ok(AdmissionOperationState::NotAcceptedAfterDispatchCommit)
        }
        EconomicNoEffectKindV1::PermanentlyNotApplied => {
            Ok(AdmissionOperationState::EconomicMutationNotApplied)
        }
        EconomicNoEffectKindV1::PreDispatch => {
            Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into())
        }
    }
}

fn verify_request_binding(
    operation: &chio_kernel::admission_operation::AdmissionOperationV1,
    advance: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<(), EconomicAdmissionCancellationError> {
    let slot = advance.slot();
    if slot.operation_id != operation.binding().operation_id().as_str()
        || slot.request.request_namespace_digest
            != operation.replay_key().request_namespace_digest.as_str()
        || slot.request.request_id != operation.replay_key().request_id.as_str()
        || slot.request.request_binding_digest
            != operation.binding().request_binding_hash().as_str()
    {
        return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into());
    }
    Ok(())
}

fn validate_trusted_time(value: u64) -> Result<(), EconomicAdmissionCancellationError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(EconomicAdmissionCancellationError::InvalidConfiguration(
            "trusted cancellation time is outside the I-JSON range".to_owned(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::economic_continuity::{
        verify_economic_effect_cancellation_advance, verify_economic_effect_cancellation_commit,
        verify_economic_state_batch_advance, verify_economic_state_view,
        EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
        EconomicAdmissionHandoffVerifier, EconomicContentV1,
        EconomicEffectCancellationProofVerifier, EconomicEffectDispatchCommitV1,
        EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1,
        EconomicEffectTerminalV1, EconomicNoEffectKindV1, EconomicRequestBindingV1,
        EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchor,
        EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
        EconomicStateBatchV1, EconomicStateReadQuery, EconomicStateTransitionV1,
        EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
        VerifiedEconomicEffectCancellationAdvance, VerifiedEconomicEffectDispatch,
        VerifiedEconomicEffectDispatchAdvance, VerifiedEconomicEffectNotDispatched,
        VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
    };
    use chio_kernel::admission_operation::{
        AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
        AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
        AdmissionOperationState, AdmissionOperationStore, AdmissionOperationV1,
        AdmissionParticipantRequirements, AdmissionRequestBindingV1, AuthenticatedRequestNamespace,
        QualifiedAdmissionOperationStoreExt, SideEffectClass, StoreMutationFence,
    };
    use chio_kernel::ReceiptStore;
    use chio_store_sqlite::{
        EconomicStateStageStatus, SqliteAdmissionOperationStore, SqliteAuthorityStore,
        SqliteEconomicStateCache,
    };
    use serde_json::json;

    use crate::economic_state_recovery::{EconomicRecoveryOutcome, EconomicStateRecovery};

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        match mutex.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn id(field: &'static str, value: &str) -> AdmissionIdentifier {
        AdmissionIdentifier::try_new(field, value).expect("identifier")
    }

    fn admission_digest(field: &'static str, byte: char) -> AdmissionDigest {
        AdmissionDigest::try_new(field, byte.to_string().repeat(64)).expect("digest")
    }

    fn now_ms() -> u64 {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time")
                .as_millis(),
        )
        .expect("time fits u64")
    }

    fn submitted_operation(fence: &StoreMutationFence) -> AdmissionOperationV1 {
        submitted_operation_with_requirements(
            fence,
            AdmissionOperationKind::GovernedEconomicMutation,
            AdmissionParticipantRequirements::NONE,
        )
    }

    fn submitted_operation_with_requirements(
        fence: &StoreMutationFence,
        kind: AdmissionOperationKind,
        participant_requirements: AdmissionParticipantRequirements,
    ) -> AdmissionOperationV1 {
        let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
            kind,
            namespace: AuthenticatedRequestNamespace::for_local_system(id(
                "coordinator_authority_id",
                "economic-cancellation-test",
            ))
            .expect("namespace"),
            request_id: id("request_id", "mutation-cancellation"),
            capability_id: id("capability_id", "mutation-capability"),
            authorization_capability_hash: admission_digest("authorization_hash", 'a'),
            request_binding: AdmissionRequestBindingV1::new(
                admission_digest("request_hash", 'b'),
                participant_requirements,
            )
            .expect("request binding"),
            policy_hash: admission_digest("policy_hash", 'c'),
            effect_class: SideEffectClass::Monetary,
        })
        .expect("binding");
        AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("operation")
    }

    fn advance_operation(
        store: &chio_store_sqlite::SqliteAdmissionOperationStore,
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        state: AdmissionOperationState,
        now: u64,
    ) -> TestResult<AdmissionOperationV1> {
        let lease = store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &id("claimant_id", "setup"),
            now,
            now + 1_000,
            fence,
        )?;
        let command = AdmissionOperationCommand::new(
            operation.binding().operation_id().clone(),
            operation.version(),
            lease,
            Vec::new(),
            Some(state),
            None,
            None,
        )?;
        Ok(store.compare_and_swap(&command, now + 1)?.into_operation())
    }

    #[derive(Debug)]
    struct Direct;

    impl EconomicTransitionProofVerifier for Direct {
        fn verify_transition(
            &self,
            _current: Option<&EconomicResourceHeadV1>,
            _transition: &EconomicStateTransitionV1,
        ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
            Ok(EconomicTransitionAuthorizationV1::Direct)
        }
    }

    impl EconomicAdmissionHandoffVerifier for Direct {
        fn verify_operation_active(
            &self,
            _operation_id: &str,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }

        fn verify_handoff(
            &self,
            _operation_id: &str,
            _handoff: &EconomicAdmissionHandoffV1,
        ) -> Result<(), EconomicStateAnchorError> {
            Ok(())
        }
    }

    impl EconomicEffectCancellationProofVerifier for Direct {
        fn verify_cancellation(
            &self,
            _current: &EconomicEffectSlotV1,
            _next: &EconomicEffectSlotV1,
        ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
            Ok(EconomicNoEffectKindV1::PermanentlyNotApplied)
        }
    }

    fn pins(keypair: &Keypair) -> EconomicStateAnchorPins {
        EconomicStateAnchorPins {
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            signer_public_key: keypair.public_key(),
        }
    }

    fn signed_view(
        keypair: &Keypair,
        sequence: u64,
        checkpoint_digest: String,
        head: EconomicResourceHeadV1,
    ) -> TestResult<EconomicStateAnchorViewV1> {
        let mut view = EconomicStateAnchorViewV1 {
            schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence: sequence,
            checkpoint_digest,
            heads_root: String::new(),
            heads: vec![head],
            absent_resource_keys: Vec::new(),
            request_replays_root: String::new(),
            request_replays: Vec::new(),
            absent_request_keys: Vec::new(),
            observed_at: 100 + sequence,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        view.seal(keypair)?;
        Ok(view)
    }

    fn effect_head(
        slot: &EconomicEffectSlotV1,
        version: u64,
        predecessor_digest: Option<String>,
    ) -> TestResult<EconomicResourceHeadV1> {
        let state = EconomicContentV1::Inline {
            value: serde_json::to_value(slot)?,
        };
        Ok(EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: slot.anchor_id.clone(),
            namespace: slot.namespace.clone(),
            resource_key: slot.resource_head_key(),
            head_version: version,
            resource_version: version * 3 + 1,
            lifecycle_fence: version + 6,
            lifecycle_state: match slot.state {
                EconomicEffectStateV1::Ready => "ready",
                EconomicEffectStateV1::NoEffect => "no_effect",
                _ => "invalid",
            }
            .to_owned(),
            state_digest: state.digest()?,
            state,
            operation_id: Some(slot.operation_id.clone()),
            effect_idempotency_key: Some(slot.idempotency_key.clone()),
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: 100 + version,
            predecessor_digest,
        })
    }

    fn cancellation_pair(
        operation: &AdmissionOperationV1,
        fence: &StoreMutationFence,
        suffix: &str,
    ) -> TestResult<(
        VerifiedEconomicEffectCancellationAdvance,
        VerifiedEconomicEffectNotDispatched,
    )> {
        let keypair = Keypair::from_seed(&[0x63; 32]);
        let pins = pins(&keypair);
        let mut slot = EconomicEffectSlotV1 {
            schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
            slot_id: String::new(),
            anchor_id: pins.anchor_id.clone(),
            namespace: pins.namespace.clone(),
            resource_key: EconomicResourceKeyV1 {
                resource_family: "clearing_round".to_owned(),
                scope_id: "market-1".to_owned(),
                resource_id: format!("round-{suffix}"),
            },
            operation_id: operation.binding().operation_id().as_str().to_owned(),
            effect_kind: "clearing_finalize".to_owned(),
            request: EconomicRequestBindingV1 {
                request_namespace_digest: operation
                    .replay_key()
                    .request_namespace_digest
                    .as_str()
                    .to_owned(),
                request_id: operation.replay_key().request_id.as_str().to_owned(),
                request_binding_digest: operation
                    .binding()
                    .request_binding_hash()
                    .as_str()
                    .to_owned(),
            },
            admission_handoff: EconomicAdmissionHandoffV1 {
                state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
                operation_version: operation.version(),
                lifecycle_fence: operation.coordinator_lease_epoch(),
                store_fence: fence.clone(),
            },
            target: EconomicEffectTargetV1 {
                target_id: "clearing-engine".to_owned(),
                target_key_epoch: 1,
                qualification_digest: digest("target-qualification"),
            },
            action_digest: digest(&format!("action-{suffix}")),
            parameters_digest: operation
                .binding()
                .action_parameter_hash()
                .as_str()
                .to_owned(),
            resource_head_digest: digest(&format!("resource-head-{suffix}")),
            frost: None,
            idempotency_key: digest(&format!("idempotency-{suffix}")),
            state: EconomicEffectStateV1::Ready,
            terminal: None,
        };
        slot.slot_id = slot.recompute_slot_id()?;
        let ready_head = effect_head(&slot, 1, None)?;
        let ready_digest = ready_head.digest()?;
        let raw_current = signed_view(&keypair, 1, digest("checkpoint-1"), ready_head)?;
        let proof = EconomicContentV1::Inline {
            value: json!({"permanentlyNotApplied": true}),
        };
        slot.state = EconomicEffectStateV1::NoEffect;
        slot.terminal = Some(EconomicEffectTerminalV1::NoEffect {
            kind: EconomicNoEffectKindV1::PermanentlyNotApplied,
            proof_id: format!("mutation-cancellation-proof-{suffix}"),
            proof_digest: proof.digest()?,
            proof,
        });
        let cancelled_head = effect_head(&slot, 2, Some(ready_digest.clone()))?;
        let current = verify_economic_state_view(raw_current.clone(), &pins)?;
        let mut batch = EconomicStateBatchV1 {
            schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
            batch_id: String::new(),
            checkpoint_digest: String::new(),
            anchor_id: pins.anchor_id.clone(),
            namespace: pins.namespace.clone(),
            checkpoint_sequence: 2,
            previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
            expected_heads_root: String::new(),
            next_heads_root: String::new(),
            transitions: vec![EconomicStateTransitionV1 {
                resource_key: cancelled_head.resource_key.clone(),
                expected_head_digest: Some(ready_digest),
                next_head: cancelled_head.clone(),
                transition_proof_digest: digest("transition-proof"),
                prepared_effect: None,
            }],
            effect_slots: Vec::new(),
            request_replays: Vec::new(),
            operation_id: Some(slot.operation_id.clone()),
            issued_at: 102,
            signer_key_id: pins.signer_key_id.clone(),
            signer_key_epoch: pins.signer_key_epoch,
            anchor_signature: String::new(),
        };
        batch.seal(&keypair)?;
        let committed_raw =
            signed_view(&keypair, 2, batch.checkpoint_digest.clone(), cancelled_head)?;
        let coordinator_advance = verify_economic_effect_cancellation_advance(
            verify_economic_state_batch_advance(&current, batch.clone(), &pins, &Direct)?,
            &Direct,
            &Direct,
        )?;
        let authority_advance = verify_economic_effect_cancellation_advance(
            verify_economic_state_batch_advance(
                &verify_economic_state_view(raw_current, &pins)?,
                batch,
                &pins,
                &Direct,
            )?,
            &Direct,
            &Direct,
        )?;
        let committed = verify_economic_state_view(committed_raw, &pins)?;
        let authority =
            verify_economic_effect_cancellation_commit(authority_advance, &committed, &pins)?;
        Ok((coordinator_advance, authority))
    }

    struct CancellationAnchor {
        batch_id: String,
        authority: Mutex<Option<VerifiedEconomicEffectNotDispatched>>,
        base: VerifiedEconomicStateView,
        committed: VerifiedEconomicStateView,
        anchored: AtomicBool,
        stage_observed_before_cas: AtomicBool,
        cancellation_cas_calls: AtomicUsize,
        generic_cas_calls: AtomicUsize,
        cache: SqliteEconomicStateCache,
    }

    impl EconomicStateAnchor for CancellationAnchor {
        fn read_state(
            &self,
            _query: &EconomicStateReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Ok(if self.anchored.load(Ordering::SeqCst) {
                self.committed.clone()
            } else {
                self.base.clone()
            })
        }

        fn read_checkpoint_state(
            &self,
            _query: &chio_core::economic_continuity::EconomicCheckpointReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            if self.anchored.load(Ordering::SeqCst) {
                Ok(self.committed.clone())
            } else {
                Err(EconomicStateAnchorError::Unavailable(
                    "cancellation checkpoint is not committed".to_owned(),
                ))
            }
        }

        fn compare_and_swap_batch(
            &self,
            _advance: chio_core::economic_continuity::QualifiedGenericEconomicStateBatchAdvance<'_>,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            self.generic_cas_calls.fetch_add(1, Ordering::SeqCst);
            Err(EconomicStateAnchorError::Unavailable(
                "generic CAS must not commit a cancellation".to_owned(),
            ))
        }

        fn compare_and_swap_effect_dispatch(
            &self,
            _advance: VerifiedEconomicEffectDispatchAdvance,
        ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
            let _ = core::mem::size_of::<EconomicEffectDispatchCommitV1>();
            Err(EconomicStateAnchorError::Unavailable("unused".to_owned()))
        }

        fn compare_and_swap_effect_cancellation(
            &self,
            advance: VerifiedEconomicEffectCancellationAdvance,
        ) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
            self.cancellation_cas_calls.fetch_add(1, Ordering::SeqCst);
            if advance.batch().batch_id != self.batch_id {
                return Err(EconomicStateAnchorError::EffectCancellationRejected(
                    "wrong batch",
                ));
            }
            let staged = self
                .cache
                .load_stage(&self.batch_id)
                .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
            if staged.as_ref().map(|stage| stage.status())
                != Some(EconomicStateStageStatus::DbStaged)
            {
                return Err(EconomicStateAnchorError::Unavailable(
                    "cancellation CAS ran before its durable stage".to_owned(),
                ));
            }
            self.stage_observed_before_cas.store(true, Ordering::SeqCst);
            let authority = lock(&self.authority).take().ok_or_else(|| {
                EconomicStateAnchorError::Unavailable("authority already consumed".to_owned())
            })?;
            self.anchored.store(true, Ordering::SeqCst);
            Ok(authority)
        }
    }

    fn cancellation_anchor(
        advance: &VerifiedEconomicEffectCancellationAdvance,
        authority: VerifiedEconomicEffectNotDispatched,
        cache: SqliteEconomicStateCache,
    ) -> Arc<CancellationAnchor> {
        let committed = authority.committed().clone();
        Arc::new(CancellationAnchor {
            batch_id: advance.batch().batch_id.clone(),
            authority: Mutex::new(Some(authority)),
            base: advance.state_advance().current().clone(),
            committed,
            anchored: AtomicBool::new(false),
            stage_observed_before_cas: AtomicBool::new(false),
            cancellation_cas_calls: AtomicUsize::new(0),
            generic_cas_calls: AtomicUsize::new(0),
            cache,
        })
    }

    fn stage_cancellation(
        store: &SqliteAdmissionOperationStore,
        operation: &AdmissionOperationV1,
        advance: &VerifiedEconomicEffectCancellationAdvance,
        fence: &StoreMutationFence,
        signer: &Keypair,
        trusted_now_unix_ms: u64,
    ) -> TestResult<String> {
        let claimant = id(
            "claimant_id",
            &format!("kernel:{}", signer.public_key().to_hex()),
        );
        let lease = store.claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &claimant,
            trusted_now_unix_ms,
            trusted_now_unix_ms + 30_000,
            fence,
        )?;
        let context = AdmissionProjectionContext {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.replay_key().request_id,
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: trusted_now_unix_ms,
            coordinator_lease_id: lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            store_fence: fence.clone(),
        };
        let projection = verified_economic_cancellation_projection(operation, context, advance)?;
        let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
            operation,
            &projection,
            &store.admission_projection_capabilities(),
            signer,
        )?;
        store.stage_anchored_terminal_projection(
            advance.state_advance(),
            &lease,
            &envelope,
            fence,
            trusted_now_unix_ms,
        )?;
        Ok(advance.batch().batch_id.clone())
    }

    fn recovery(
        cache: SqliteEconomicStateCache,
        anchor: Arc<CancellationAnchor>,
        store: Arc<SqliteAdmissionOperationStore>,
        fence: StoreMutationFence,
    ) -> TestResult<EconomicStateRecovery> {
        Ok(EconomicStateRecovery::new(
            cache,
            anchor,
            store,
            Arc::new(Direct),
            Arc::new(Direct),
            Arc::new(Direct),
            pins(&Keypair::from_seed(&[0x63; 32])),
            fence,
            id("claimant_id", "economic-cancellation-recovery"),
            Duration::from_secs(30),
        )?)
    }

    #[test]
    fn paid_cancellation_fails_before_staging_or_external_cas() -> TestResult {
        let temp = tempfile::tempdir()?;
        crate::create_private_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        crate::create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let cache = authority_store.economic_state_cache();
        let store = Arc::new(authority_store.admission_operation_store());
        let now = now_ms();
        let prepared = submitted_operation_with_requirements(
            &fence,
            AdmissionOperationKind::ToolDispatch,
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                payment: true,
                ..AdmissionParticipantRequirements::NONE
            },
        );
        store.begin(&prepared, &fence, now)?;
        let (advance, cancellation) = cancellation_pair(&prepared, &fence, "paid")?;
        let batch_id = advance.batch().batch_id.clone();
        let anchor = cancellation_anchor(&advance, cancellation, cache.clone());
        let coordinator = EconomicAdmissionCancellationCoordinator::new(
            anchor.clone(),
            store,
            pins(&Keypair::from_seed(&[0x63; 32])),
            fence,
            Keypair::from_seed(&[0x64; 32]),
            Duration::from_secs(30),
        )?;

        assert!(matches!(
            coordinator.cancel_after_handoff(advance, now + 1),
            Err(EconomicAdmissionCancellationError::PaymentSettlementRequired)
        ));
        assert_eq!(anchor.cancellation_cas_calls.load(Ordering::SeqCst), 0);
        assert_eq!(anchor.generic_cas_calls.load(Ordering::SeqCst), 0);
        assert!(cache.load_stage(&batch_id)?.is_none());
        Ok(())
    }

    #[test]
    fn cancellation_coordinator_commits_the_external_and_local_terminal_lifecycle() -> TestResult {
        let temp = tempfile::tempdir()?;
        crate::create_private_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        crate::create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let cache = authority_store.economic_state_cache();
        let store = authority_store.admission_operation_store();
        let now = now_ms();
        let prepared = submitted_operation(&fence);
        store.begin(&prepared, &fence, now)?;
        let ready = advance_operation(
            &store,
            &prepared,
            &fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        let submitted = advance_operation(
            &store,
            &ready,
            &fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let (advance, cancellation) = cancellation_pair(&submitted, &fence, "1")?;
        let (replay_advance, _) = cancellation_pair(&submitted, &fence, "1")?;
        let batch_id = advance.batch().batch_id.clone();
        let anchor = cancellation_anchor(&advance, cancellation, cache.clone());
        let store = Arc::new(store);
        let coordinator = EconomicAdmissionCancellationCoordinator::new(
            anchor.clone(),
            store.clone(),
            pins(&Keypair::from_seed(&[0x63; 32])),
            fence,
            Keypair::from_seed(&[0x64; 32]),
            Duration::from_secs(30),
        )?;

        let terminal = coordinator.cancel_after_handoff(advance, now + 2_000)?;
        assert_eq!(
            terminal.state,
            AdmissionOperationState::EconomicMutationNotApplied
        );
        let persisted = store
            .load_by_operation_id(submitted.binding().operation_id())?
            .ok_or("terminal operation missing")?;
        assert_eq!(
            persisted.state(),
            AdmissionOperationState::EconomicMutationNotApplied
        );
        assert!(anchor.stage_observed_before_cas.load(Ordering::SeqCst));
        assert_eq!(anchor.cancellation_cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(anchor.generic_cas_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            cache.load_stage(&batch_id)?.map(|stage| stage.status()),
            Some(EconomicStateStageStatus::DbFinalized)
        );
        let replay = coordinator.cancel_after_handoff(replay_advance, now + 2_001)?;
        assert_eq!(replay, terminal);
        Ok(())
    }

    #[test]
    fn recovery_replays_a_staged_cancellation_through_the_typed_cas() -> TestResult {
        let temp = tempfile::tempdir()?;
        crate::create_private_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        crate::create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let cache = authority_store.economic_state_cache();
        let store = Arc::new(authority_store.admission_operation_store());
        let now = now_ms();
        let prepared = submitted_operation(&fence);
        store.begin(&prepared, &fence, now)?;
        let ready = advance_operation(
            &store,
            &prepared,
            &fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        let submitted = advance_operation(
            &store,
            &ready,
            &fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let (advance, cancellation) = cancellation_pair(&submitted, &fence, "recovery-before")?;
        let anchor = cancellation_anchor(&advance, cancellation, cache.clone());
        let signer = Keypair::from_seed(&[0x64; 32]);
        let batch_id =
            stage_cancellation(&store, &submitted, &advance, &fence, &signer, now + 2_000)?;

        let outcome = recovery(cache.clone(), anchor.clone(), store.clone(), fence.clone())?
            .recover_stage(&batch_id, now + 2_001)?;

        assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
        assert_eq!(anchor.cancellation_cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(anchor.generic_cas_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            cache.load_stage(&batch_id)?.map(|stage| stage.status()),
            Some(EconomicStateStageStatus::DbFinalized)
        );
        assert_eq!(
            store
                .load_by_operation_id(submitted.binding().operation_id())?
                .map(|operation| operation.state()),
            Some(AdmissionOperationState::EconomicMutationNotApplied)
        );
        Ok(())
    }

    #[test]
    fn recovery_finishes_a_cancellation_committed_before_local_finalization() -> TestResult {
        let temp = tempfile::tempdir()?;
        crate::create_private_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        crate::create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let cache = authority_store.economic_state_cache();
        let store = Arc::new(authority_store.admission_operation_store());
        let now = now_ms();
        let prepared = submitted_operation(&fence);
        store.begin(&prepared, &fence, now)?;
        let ready = advance_operation(
            &store,
            &prepared,
            &fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        let submitted = advance_operation(
            &store,
            &ready,
            &fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let (advance, cancellation) = cancellation_pair(&submitted, &fence, "recovery-after")?;
        let anchor = cancellation_anchor(&advance, cancellation, cache.clone());
        let signer = Keypair::from_seed(&[0x64; 32]);
        let batch_id =
            stage_cancellation(&store, &submitted, &advance, &fence, &signer, now + 2_000)?;
        let _committed = anchor.compare_and_swap_effect_cancellation(advance)?;

        let outcome = recovery(cache.clone(), anchor.clone(), store.clone(), fence.clone())?
            .recover_stage(&batch_id, now + 2_001)?;

        assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
        assert_eq!(anchor.cancellation_cas_calls.load(Ordering::SeqCst), 1);
        assert_eq!(anchor.generic_cas_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            cache.load_stage(&batch_id)?.map(|stage| stage.status()),
            Some(EconomicStateStageStatus::DbFinalized)
        );
        assert_eq!(
            store
                .load_by_operation_id(submitted.binding().operation_id())?
                .map(|operation| operation.state()),
            Some(AdmissionOperationState::EconomicMutationNotApplied)
        );
        Ok(())
    }

    #[test]
    fn terminal_replay_rejects_a_sibling_effect_cancellation() -> TestResult {
        let temp = tempfile::tempdir()?;
        crate::create_private_directory(temp.path())?;
        let database = temp.path().join("authority.db");
        let lock_root = temp.path().join("locks");
        crate::create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let authority_store = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
        let fence = authority_store.mutation_fence();
        let cache = authority_store.economic_state_cache();
        let store = authority_store.admission_operation_store();
        let now = now_ms();
        let prepared = submitted_operation(&fence);
        store.begin(&prepared, &fence, now)?;
        let ready = advance_operation(
            &store,
            &prepared,
            &fence,
            AdmissionOperationState::MutationReady,
            now + 1,
        )?;
        let submitted = advance_operation(
            &store,
            &ready,
            &fence,
            AdmissionOperationState::MutationSubmitted,
            now + 3,
        )?;
        let (first_advance, first_cancellation) = cancellation_pair(&submitted, &fence, "1")?;
        let (sibling_advance, _) = cancellation_pair(&submitted, &fence, "2")?;
        let anchor = cancellation_anchor(&first_advance, first_cancellation, cache);
        let coordinator = EconomicAdmissionCancellationCoordinator::new(
            anchor,
            Arc::new(store),
            pins(&Keypair::from_seed(&[0x63; 32])),
            fence,
            Keypair::from_seed(&[0x64; 32]),
            Duration::from_secs(30),
        )?;

        coordinator.cancel_after_handoff(first_advance, now + 2_000)?;
        let error = coordinator
            .cancel_after_handoff(sibling_advance, now + 2_001)
            .expect_err("a sibling effect must not replay another slot's terminal projection");
        assert!(matches!(
            error,
            EconomicAdmissionCancellationError::Projection(
                AdmissionOperationError::TerminalProjectionBindingMismatch
            )
        ));
        Ok(())
    }
}
