use std::sync::Arc;

use chio_core::economic_continuity::{
    economic_effect_slot_from_head, qualify_economic_effect_unknown_advance, EconomicEffectStateV1,
    EconomicStateAnchor, EconomicStateAnchorError, VerifiedEconomicEffectDispatch,
    VerifiedEconomicEffectDispatchAdvance, VerifiedEconomicStateBatchAdvance,
    VerifiedEconomicStateView,
};
use chio_kernel::admission_operation::{
    AdmissionMutationSequencer, AdmissionOperationError, StoreMutationFence,
};

use crate::economic_state_recovery::EconomicEffectRecoveryLock;

pub struct SequencedEconomicEffectCoordinator {
    anchor: Arc<dyn EconomicStateAnchor>,
    mutation_sequencer: AdmissionMutationSequencer,
}

impl SequencedEconomicEffectCoordinator {
    pub fn new(
        anchor: Arc<dyn EconomicStateAnchor>,
        active_fence: &StoreMutationFence,
    ) -> Result<Self, AdmissionOperationError> {
        Ok(Self {
            anchor,
            mutation_sequencer: AdmissionMutationSequencer::for_fence(active_fence)?,
        })
    }

    pub fn dispatch(
        &self,
        advance: VerifiedEconomicEffectDispatchAdvance,
    ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
        let _mutation_guard = self.lock()?;
        self.anchor.compare_and_swap_effect_dispatch(advance)
    }

    pub fn commit_unknown(
        &self,
        advance: &VerifiedEconomicStateBatchAdvance,
        recovery: &EconomicEffectRecoveryLock,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        let _mutation_guard = self.lock()?;
        let batch = advance.batch();
        if batch.transitions.len() != 1
            || !batch.effect_slots.is_empty()
            || !batch.request_replays.is_empty()
            || batch.transitions[0].prepared_effect.is_some()
        {
            return Err(EconomicStateAnchorError::EffectDispatchRejected(
                "unknown recovery must advance exactly one retained effect slot",
            ));
        }
        let transition = &batch.transitions[0];
        let current_head = advance
            .current()
            .view()
            .head(&transition.resource_key)
            .ok_or_else(|| {
                EconomicStateAnchorError::CurrentHeadMissing(transition.resource_key.clone())
            })?;
        let current_slot = economic_effect_slot_from_head(current_head)?;
        let next_slot = economic_effect_slot_from_head(&transition.next_head)?;
        if current_slot != *recovery.current_slot()
            || next_slot != *recovery.next_slot()
            || current_slot.state != EconomicEffectStateV1::DispatchCommitted
            || next_slot.state != EconomicEffectStateV1::Unknown
            || transition.next_head.lifecycle_state != "unknown"
            || batch.operation_id.as_deref() != Some(next_slot.operation_id.as_str())
        {
            return Err(EconomicStateAnchorError::EffectDispatchRejected(
                "unknown recovery does not match the qualified lock",
            ));
        }
        self.anchor
            .compare_and_swap_effect_unknown(qualify_economic_effect_unknown_advance(advance)?)
    }

    fn lock(
        &self,
    ) -> Result<
        chio_kernel::admission_operation::AdmissionMutationGuard<'_>,
        EconomicStateAnchorError,
    > {
        self.mutation_sequencer
            .lock()
            .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::economic_state_recovery::{
        qualify_committed_effect_recovery, EconomicEffectRecoveryDecision,
    };
    use chio_core::crypto::{sha256_hex, Keypair};
    use chio_core::economic_continuity::{
        qualify_generic_economic_state_batch_advance, verify_economic_state_batch_advance,
        verify_economic_state_batch_commit, verify_economic_state_view,
        EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicCheckpointReadQuery,
        EconomicContentV1, EconomicEffectSlotV1, EconomicEffectTargetV1, EconomicRequestBindingV1,
        EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorPins,
        EconomicStateAnchorViewV1, EconomicStateBatchV1, EconomicStateReadQuery,
        EconomicStateTransitionV1, EconomicTransitionAuthorizationV1,
        EconomicTransitionProofVerifier, VerifiedEconomicEffectDispatch,
        VerifiedEconomicEffectDispatchAdvance, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
        CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
        CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
    };

    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn digest(label: &str) -> String {
        sha256_hex(label.as_bytes())
    }

    fn keypair() -> Keypair {
        Keypair::from_seed(&[0x41; 32])
    }

    fn pins() -> EconomicStateAnchorPins {
        EconomicStateAnchorPins {
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            signer_public_key: keypair().public_key(),
        }
    }

    fn fence() -> StoreMutationFence {
        StoreMutationFence {
            store_uuid: "store-1".to_owned(),
            lease_id: "lease-1".to_owned(),
            owner_epoch: 3,
        }
    }

    fn slot(state: EconomicEffectStateV1) -> TestResult<EconomicEffectSlotV1> {
        let mut slot = EconomicEffectSlotV1 {
            schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
            slot_id: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            resource_key: EconomicResourceKeyV1 {
                resource_family: "clearing_round".to_owned(),
                scope_id: "market-1".to_owned(),
                resource_id: "round-1".to_owned(),
            },
            operation_id: digest("operation-1"),
            effect_kind: "settlement_dispatch".to_owned(),
            request: EconomicRequestBindingV1 {
                request_namespace_digest: digest("request-namespace"),
                request_id: "request-1".to_owned(),
                request_binding_digest: digest("request-binding"),
            },
            admission_handoff: EconomicAdmissionHandoffV1 {
                state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
                operation_version: 4,
                lifecycle_fence: 9,
                store_fence: fence(),
            },
            target: EconomicEffectTargetV1 {
                target_id: "settlement-rail".to_owned(),
                target_key_epoch: 2,
                qualification_digest: digest("target-qualification"),
            },
            action_digest: digest("action"),
            parameters_digest: digest("parameters"),
            resource_head_digest: digest("resource-head"),
            frost: None,
            idempotency_key: digest("idempotency-key"),
            state,
            terminal: None,
        };
        slot.slot_id = slot.recompute_slot_id()?;
        slot.validate()?;
        Ok(slot)
    }

    fn head(
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
            resource_version: version,
            lifecycle_fence: version,
            lifecycle_state: match slot.state {
                EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
                EconomicEffectStateV1::Unknown => "unknown",
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

    fn signed_view(
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
        view.seal(&keypair())?;
        Ok(view)
    }

    #[derive(Debug)]
    struct DirectVerifier;

    impl EconomicTransitionProofVerifier for DirectVerifier {
        fn verify_transition(
            &self,
            _current: Option<&EconomicResourceHeadV1>,
            _transition: &EconomicStateTransitionV1,
        ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
            Ok(EconomicTransitionAuthorizationV1::Direct)
        }
    }

    fn unknown_advance() -> TestResult<(
        VerifiedEconomicStateBatchAdvance,
        EconomicEffectSlotV1,
        EconomicStateAnchorViewV1,
    )> {
        let committed = slot(EconomicEffectStateV1::DispatchCommitted)?;
        let committed_head = head(&committed, 2, Some(digest("ready-head")))?;
        let committed_head_digest = committed_head.digest()?;
        let current = verify_economic_state_view(
            signed_view(2, digest("checkpoint-2"), committed_head)?,
            &pins(),
        )?;
        let unknown = slot(EconomicEffectStateV1::Unknown)?;
        let unknown_head = head(&unknown, 3, Some(committed_head_digest.clone()))?;
        let mut batch = EconomicStateBatchV1 {
            schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
            batch_id: String::new(),
            checkpoint_digest: String::new(),
            anchor_id: "anchor-1".to_owned(),
            namespace: "economy-prod".to_owned(),
            checkpoint_sequence: 3,
            previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
            expected_heads_root: String::new(),
            next_heads_root: String::new(),
            transitions: vec![EconomicStateTransitionV1 {
                resource_key: unknown_head.resource_key.clone(),
                expected_head_digest: Some(committed_head_digest),
                next_head: unknown_head.clone(),
                transition_proof_digest: digest("unknown-transition"),
                prepared_effect: None,
            }],
            effect_slots: Vec::new(),
            request_replays: Vec::new(),
            operation_id: Some(unknown.operation_id.clone()),
            issued_at: 103,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        batch.seal(&keypair())?;
        let advance =
            verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
        let committed_view =
            signed_view(3, advance.batch().checkpoint_digest.clone(), unknown_head)?;
        Ok((advance, committed, committed_view))
    }

    struct RecordingAnchor {
        committed: EconomicStateAnchorViewV1,
        batch_calls: AtomicUsize,
    }

    impl EconomicStateAnchor for RecordingAnchor {
        fn read_state(
            &self,
            _query: &EconomicStateReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Missing)
        }

        fn read_checkpoint_state(
            &self,
            _query: &EconomicCheckpointReadQuery,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Missing)
        }

        fn compare_and_swap_batch(
            &self,
            advance: chio_core::economic_continuity::QualifiedGenericEconomicStateBatchAdvance<'_>,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            let advance = advance.advance();
            self.batch_calls.fetch_add(1, Ordering::SeqCst);
            let committed = verify_economic_state_view(self.committed.clone(), &pins())?;
            verify_economic_state_batch_commit(advance, &committed, &pins())?;
            Ok(committed)
        }

        fn compare_and_swap_effect_dispatch(
            &self,
            _advance: VerifiedEconomicEffectDispatchAdvance,
        ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
            Err(EconomicStateAnchorError::Unavailable(
                "dispatch is not used by this fixture".to_owned(),
            ))
        }

        fn compare_and_swap_effect_unknown(
            &self,
            advance: chio_core::economic_continuity::QualifiedEconomicEffectUnknownAdvance<'_>,
        ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
            let advance = advance.advance();
            self.batch_calls.fetch_add(1, Ordering::SeqCst);
            let committed = verify_economic_state_view(self.committed.clone(), &pins())?;
            verify_economic_state_batch_commit(advance, &committed, &pins())?;
            Ok(committed)
        }
    }

    #[test]
    fn unqualified_recovery_commits_unknown_before_returning() -> TestResult {
        let (advance, committed, committed_view) = unknown_advance()?;
        assert!(qualify_generic_economic_state_batch_advance(&advance).is_err());
        let EconomicEffectRecoveryDecision::LockedUnknown(recovery) =
            qualify_committed_effect_recovery(&committed, None, None)?
        else {
            return Err("recovery did not produce an unknown lock".into());
        };
        let anchor = Arc::new(RecordingAnchor {
            committed: committed_view,
            batch_calls: AtomicUsize::new(0),
        });
        let coordinator = SequencedEconomicEffectCoordinator::new(anchor.clone(), &fence())?;
        let committed = coordinator.commit_unknown(&advance, &recovery)?;
        let effect = economic_effect_slot_from_head(&committed.view().heads[0])?;
        assert_eq!(effect.state, EconomicEffectStateV1::Unknown);
        assert_eq!(anchor.batch_calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn unknown_recovery_rejects_a_different_qualified_slot() -> TestResult {
        let (advance, committed, committed_view) = unknown_advance()?;
        let mut sibling = committed;
        sibling.idempotency_key = digest("different-idempotency-key");
        sibling.slot_id = sibling.recompute_slot_id()?;
        let EconomicEffectRecoveryDecision::LockedUnknown(recovery) =
            qualify_committed_effect_recovery(&sibling, None, None)?
        else {
            return Err("recovery did not produce an unknown lock".into());
        };
        let anchor = Arc::new(RecordingAnchor {
            committed: committed_view,
            batch_calls: AtomicUsize::new(0),
        });
        let coordinator = SequencedEconomicEffectCoordinator::new(anchor.clone(), &fence())?;
        assert!(coordinator.commit_unknown(&advance, &recovery).is_err());
        assert_eq!(anchor.batch_calls.load(Ordering::SeqCst), 0);
        Ok(())
    }
}
