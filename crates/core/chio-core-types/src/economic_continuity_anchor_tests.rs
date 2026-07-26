use alloc::string::ToString;
use alloc::vec;

use serde_json::json;

use crate::economic_continuity::*;
use crate::economic_continuity_tests::{
    digest, head, inline_content, ready_effect_slot, resource_key, schema_validator, transition,
    unsigned_batch, unsigned_prepared_effect_batch,
};
use crate::Keypair;

fn anchor_keypair() -> Keypair {
    Keypair::from_seed(&[0x41; 32])
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        signer_key_id: "anchor-key-1".to_string(),
        signer_key_epoch: 1,
        signer_public_key: anchor_keypair().public_key(),
    }
}

fn signed_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    mut heads: Vec<EconomicResourceHeadV1>,
    mut absent_resource_keys: Vec<EconomicResourceKeyV1>,
    mut request_replays: Vec<EconomicRequestReplayV1>,
    mut absent_request_keys: Vec<EconomicRequestKeyV1>,
) -> Result<EconomicStateAnchorViewV1, EconomicStateAnchorError> {
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    absent_resource_keys.sort_unstable();
    request_replays.sort_by(|left, right| left.request.key().cmp(&right.request.key()));
    absent_request_keys.sort_unstable();
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_string(),
        anchor_id: "anchor-1".to_string(),
        namespace: "economy-prod".to_string(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays,
        absent_request_keys,
        observed_at: 500,
        signer_key_id: "anchor-key-1".to_string(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&anchor_keypair())?;
    Ok(view)
}

#[derive(Debug)]
struct DirectTransitionVerifier;

impl EconomicTransitionProofVerifier for DirectTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        if transition.transition_proof_digest == digest("rejected-proof") {
            return Err(EconomicStateAnchorError::TransitionProofRejected(
                transition.resource_key.clone(),
            ));
        }
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

#[test]
fn signed_anchor_view_authenticates_values_absence_and_pins(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let missing = resource_key("round-2");
    let view = signed_view(
        1,
        digest("checkpoint-1"),
        vec![current],
        vec![missing],
        Vec::new(),
        Vec::new(),
    )?;
    let verified = verify_economic_state_view(view.clone(), &pins())?;
    assert_eq!(verified.view(), &view);

    let mut wrong_namespace = pins();
    wrong_namespace.namespace = "economy-staging".to_string();
    assert!(verify_economic_state_view(view.clone(), &wrong_namespace).is_err());
    let mut wrong_key = pins();
    wrong_key.signer_public_key = Keypair::from_seed(&[0x42; 32]).public_key();
    assert!(verify_economic_state_view(view, &wrong_key).is_err());
    Ok(())
}

fn verified_successor_advance() -> Result<
    (
        VerifiedEconomicStateView,
        VerifiedEconomicStateBatchAdvance,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let current_digest = current.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![current],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let next = head(resource_key("round-1"), 2, 2, Some(current_digest.clone()))?;
    let mut batch = unsigned_batch(vec![transition(next.clone(), Some(current_digest))]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &DirectTransitionVerifier,
    )?;
    Ok((current_view, advance, next))
}

#[test]
fn batch_advance_rechecks_current_heads_sequence_signature_and_consumer_proofs(
) -> Result<(), Box<dyn core::error::Error>> {
    let (current_view, advance, next) = verified_successor_advance()?;
    assert_eq!(advance.batch().checkpoint_sequence, 2);
    reverify_economic_state_batch_advance(&advance, &pins(), &DirectTransitionVerifier)?;

    let committed = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            vec![next],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    verify_economic_state_batch_commit(&advance, &committed, &pins())?;

    let unrelated = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            digest("unrelated-checkpoint"),
            committed.view().heads.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    assert!(verify_economic_state_batch_commit(&advance, &unrelated, &pins()).is_err());

    let mut stale = advance.batch().clone();
    stale.previous_checkpoint_digest = Some(digest("stale-checkpoint"));
    stale.seal(&anchor_keypair())?;
    assert!(verify_economic_state_batch_advance(
        &current_view,
        stale,
        &pins(),
        &DirectTransitionVerifier,
    )
    .is_err());

    let mut rejected = advance.batch().clone();
    rejected.transitions[0].transition_proof_digest = digest("rejected-proof");
    rejected.seal(&anchor_keypair())?;
    assert!(verify_economic_state_batch_advance(
        &current_view,
        rejected,
        &pins(),
        &DirectTransitionVerifier,
    )
    .is_err());
    Ok(())
}

#[test]
fn batch_commit_requires_exact_request_replays() -> Result<(), Box<dyn core::error::Error>> {
    let (mut batch, slot) = unsigned_prepared_effect_batch()?;
    let absent_resource_keys = batch
        .transitions
        .iter()
        .map(|transition| transition.resource_key.clone())
        .collect::<Vec<_>>();
    let current = verify_economic_state_view(
        signed_view(
            1,
            digest("request-replay-checkpoint-1"),
            Vec::new(),
            absent_resource_keys,
            Vec::new(),
            vec![slot.request.key()],
        )?,
        &pins(),
    )?;
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current.view().checkpoint_digest.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance =
        verify_economic_state_batch_advance(&current, batch, &pins(), &DirectTransitionVerifier)?;
    let committed_heads = advance
        .batch()
        .transitions
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let committed = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            committed_heads.clone(),
            Vec::new(),
            advance.batch().request_replays.clone(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    verify_economic_state_batch_commit(&advance, &committed, &pins())?;

    let omitted = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            committed_heads.clone(),
            Vec::new(),
            Vec::new(),
            vec![slot.request.key()],
        )?,
        &pins(),
    )?;
    assert!(verify_economic_state_batch_commit(&advance, &omitted, &pins()).is_err());

    let mut conflicting = advance.batch().request_replays.clone();
    conflicting[0].request.request_binding_digest = digest("conflicting-request-binding");
    let altered = verify_economic_state_view(
        signed_view(
            advance.batch().checkpoint_sequence,
            advance.batch().checkpoint_digest.clone(),
            committed_heads,
            Vec::new(),
            conflicting,
            Vec::new(),
        )?,
        &pins(),
    )?;
    assert!(verify_economic_state_batch_commit(&advance, &altered, &pins()).is_err());
    Ok(())
}

#[derive(Debug)]
struct CompleteBatchVerifier {
    required_keys: Vec<EconomicResourceKeyV1>,
}

impl EconomicTransitionProofVerifier for CompleteBatchVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        let present = batch
            .transitions
            .iter()
            .map(|transition| transition.resource_key.clone())
            .collect::<Vec<_>>();
        if present != self.required_keys
            || !self
                .required_keys
                .iter()
                .all(|key| current.view().head(key).is_some())
        {
            return Err(EconomicStateAnchorError::TransitionProofRejected(
                self.required_keys[0].clone(),
            ));
        }
        Ok(vec![
            EconomicTransitionAuthorizationV1::Direct;
            batch.transitions.len()
        ])
    }
}

#[test]
fn batch_verifier_rejects_an_incomplete_multi_resource_projection(
) -> Result<(), Box<dyn core::error::Error>> {
    let round_key = resource_key("round-1");
    let obligation_key = EconomicResourceKeyV1 {
        resource_family: "obligation_disposition".to_string(),
        scope_id: "scope-1".to_string(),
        resource_id: digest("obligation-1"),
    };
    let round = head(round_key.clone(), 1, 1, None)?;
    let obligation = head(obligation_key.clone(), 1, 1, None)?;
    let round_digest = round.digest()?;
    let obligation_digest = obligation.digest()?;
    let current = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![round, obligation],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let verifier = CompleteBatchVerifier {
        required_keys: vec![round_key.clone(), obligation_key.clone()],
    };

    let next_round = head(round_key, 2, 2, Some(round_digest.clone()))?;
    let mut incomplete = unsigned_batch(vec![transition(
        next_round.clone(),
        Some(round_digest.clone()),
    )]);
    incomplete.checkpoint_sequence = 2;
    incomplete.previous_checkpoint_digest = Some(current.view().checkpoint_digest.clone());
    incomplete.seal(&anchor_keypair())?;
    assert!(verify_economic_state_batch_advance(&current, incomplete, &pins(), &verifier).is_err());

    let next_obligation = head(obligation_key, 2, 2, Some(obligation_digest.clone()))?;
    let mut complete = unsigned_batch(vec![
        transition(next_round, Some(round_digest)),
        transition(next_obligation, Some(obligation_digest)),
    ]);
    complete
        .transitions
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    complete.checkpoint_sequence = 2;
    complete.previous_checkpoint_digest = Some(current.view().checkpoint_digest.clone());
    complete.seal(&anchor_keypair())?;
    verify_economic_state_batch_advance(&current, complete, &pins(), &verifier)?;
    Ok(())
}

#[test]
fn retained_request_mapping_rejects_conflict_before_batch_cas(
) -> Result<(), Box<dyn core::error::Error>> {
    let slot = ready_effect_slot()?;
    let retained = EconomicRequestReplayV1 {
        request: slot.request.clone(),
        operation_id: slot.operation_id.clone(),
        effect_slot_ids: vec![slot.slot_id.clone()],
    };
    let view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            Vec::new(),
            vec![resource_key("round-1")],
            vec![retained.clone()],
            Vec::new(),
        )?,
        &pins(),
    )?;
    assert_eq!(
        verify_economic_request_replay(&view, &retained)?,
        EconomicRequestReplayDisposition::Retained(retained.clone())
    );
    let mut conflict = retained.clone();
    conflict.request.request_binding_digest = digest("conflicting-request");
    assert!(matches!(
        verify_economic_request_replay(&view, &conflict),
        Err(EconomicStateAnchorError::RequestReplayConflict(_))
    ));

    let conflicting_view = signed_view(
        1,
        digest("checkpoint-1"),
        Vec::new(),
        vec![resource_key("round-1")],
        vec![conflict],
        Vec::new(),
    )?;
    assert_ne!(
        view.view().request_replays_root,
        conflicting_view.request_replays_root
    );
    Ok(())
}

#[derive(Debug)]
struct FrostTransitionVerifier {
    frost: EconomicFrostBindingV1,
}

impl EconomicTransitionProofVerifier for FrostTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::NOfM {
            frost: self.frost.clone(),
        })
    }
}

#[test]
fn n_of_m_transition_verifier_binds_the_complete_frost_authorization(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let current_digest = current.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![current],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let frost = EconomicFrostBindingV1 {
        authorization_slot_id: digest("authorization-slot"),
        authorization_id: digest("authorization"),
        action_digest: digest("action"),
        signed_envelope_digest: digest("signed-envelope"),
    };
    let mut next = head(resource_key("round-1"), 2, 2, Some(current_digest.clone()))?;
    next.frost = Some(frost.clone());
    let mut batch = unsigned_batch(vec![transition(next, Some(current_digest))]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.seal(&anchor_keypair())?;
    verify_economic_state_batch_advance(
        &current_view,
        batch.clone(),
        &pins(),
        &FrostTransitionVerifier {
            frost: frost.clone(),
        },
    )?;

    let mut mismatched = frost;
    mismatched.authorization_id = digest("different-authorization");
    assert!(verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &FrostTransitionVerifier { frost: mismatched },
    )
    .is_err());
    Ok(())
}

#[derive(Debug)]
struct MatchingAdmissionHandoff;

impl EconomicAdmissionHandoffVerifier for MatchingAdmissionHandoff {
    fn verify_operation_active(&self, operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        if operation_id == digest("operation-1") {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }

    fn verify_prepared_effect(
        &self,
        slot: &EconomicEffectSlotV1,
    ) -> Result<(), EconomicStateAnchorError> {
        if slot.operation_id == digest("operation-1") && slot.state == EconomicEffectStateV1::Ready
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }

    fn verify_handoff(
        &self,
        operation_id: &str,
        handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError> {
        if operation_id == digest("operation-1")
            && handoff.state == EconomicAdmissionHandoffStateV1::MutationSubmitted
            && handoff.operation_version == 4
            && handoff.lifecycle_fence == 9
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }
}

#[test]
fn prepared_effect_batches_require_explicit_admission_verification(
) -> Result<(), Box<dyn core::error::Error>> {
    let (mut batch, slot) = unsigned_prepared_effect_batch()?;
    let absent_resource_keys = batch
        .transitions
        .iter()
        .map(|transition| transition.resource_key.clone())
        .collect::<Vec<_>>();
    let current = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            Vec::new(),
            absent_resource_keys,
            Vec::new(),
            vec![slot.request.key()],
        )?,
        &pins(),
    )?;
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current.view().checkpoint_digest.clone());
    batch.seal(&anchor_keypair())?;
    let advance =
        verify_economic_state_batch_advance(&current, batch, &pins(), &DirectTransitionVerifier)?;

    verify_economic_admission_batch(&advance, &MatchingAdmissionHandoff)?;
    assert!(verify_economic_admission_batch(&advance, &RejectingAdmissionHandoff).is_err());
    Ok(())
}

fn dispatch_batch_advance(
    target_head: Option<EconomicResourceHeadV1>,
    resource_head_digest: String,
) -> Result<
    (
        VerifiedEconomicStateBatchAdvance,
        EconomicEffectSlotV1,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let mut ready = ready_effect_slot()?;
    ready.resource_head_digest = resource_head_digest;
    let ready_content = inline_content(serde_json::to_value(&ready)?);
    let ready_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: ready.anchor_id.clone(),
        namespace: ready.namespace.clone(),
        resource_key: ready.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "ready".to_string(),
        state_digest: ready_content.digest()?,
        state: ready_content,
        operation_id: Some(ready.operation_id.clone()),
        effect_idempotency_key: Some(ready.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    };
    let ready_head_digest = ready_head.digest()?;
    let mut current_heads = vec![ready_head];
    if let Some(target_head) = target_head {
        current_heads.push(target_head);
    }
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            current_heads,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let mut dispatched = ready;
    dispatched.state = EconomicEffectStateV1::DispatchCommitted;
    let dispatched_content = inline_content(serde_json::to_value(&dispatched)?);
    let dispatched_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: dispatched.anchor_id.clone(),
        namespace: dispatched.namespace.clone(),
        resource_key: dispatched.resource_head_key(),
        head_version: 2,
        resource_version: 2,
        lifecycle_fence: 2,
        lifecycle_state: "dispatch_committed".to_string(),
        state_digest: dispatched_content.digest()?,
        state: dispatched_content,
        operation_id: Some(dispatched.operation_id.clone()),
        effect_idempotency_key: Some(dispatched.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 501,
        predecessor_digest: Some(ready_head_digest.clone()),
    };
    let mut batch = unsigned_batch(vec![transition(
        dispatched_head.clone(),
        Some(ready_head_digest),
    )]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.operation_id = Some(dispatched.operation_id.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &DirectTransitionVerifier,
    )?;
    Ok((advance, dispatched, dispatched_head))
}

fn dispatch_advance() -> Result<
    (
        VerifiedEconomicEffectDispatchAdvance,
        EconomicEffectSlotV1,
        EconomicResourceHeadV1,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let target_head = head(resource_key("round-1"), 1, 1, None)?;
    let (advance, dispatched, dispatched_head) =
        dispatch_batch_advance(Some(target_head.clone()), target_head.digest()?)?;
    let dispatch = verify_economic_effect_dispatch_advance(advance, &MatchingAdmissionHandoff)?;
    Ok((dispatch, dispatched, dispatched_head, target_head))
}

#[test]
fn effect_dispatch_requires_the_exact_current_target_resource_head(
) -> Result<(), Box<dyn core::error::Error>> {
    let target_key = resource_key("round-1");
    let expected_target = head(target_key.clone(), 1, 1, None)?;
    let expected_digest = expected_target.digest()?;
    let (missing, _, _) = dispatch_batch_advance(None, expected_digest.clone())?;
    assert!(matches!(
        verify_economic_effect_dispatch_advance(missing, &MatchingAdmissionHandoff),
        Err(EconomicStateAnchorError::CurrentHeadMissing(key)) if key == target_key
    ));

    let substituted_target = head(target_key, 1, 2, None)?;
    let (substituted, _, _) = dispatch_batch_advance(Some(substituted_target), expected_digest)?;
    assert!(matches!(
        verify_economic_effect_dispatch_advance(substituted, &MatchingAdmissionHandoff),
        Err(EconomicStateAnchorError::EffectDispatchRejected(
            "effect slot target resource head changed"
        ))
    ));
    Ok(())
}

#[test]
fn only_signed_cas_commit_mints_effect_dispatch_authority(
) -> Result<(), Box<dyn core::error::Error>> {
    let (advance, dispatched, dispatched_head, target_head) = dispatch_advance()?;
    let committed_view = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![dispatched_head, target_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let commit = EconomicEffectDispatchCommitV1::sign(
        &advance,
        &committed_view,
        digest("cas-nonce"),
        502,
        "anchor-key-1",
        1,
        &anchor_keypair(),
    )?;
    let authority =
        verify_economic_effect_dispatch_commit(advance, &committed_view, commit, &pins())?;
    assert_eq!(authority.slot(), &dispatched);

    let (forged_advance, _, forged_head, forged_target_head) = dispatch_advance()?;
    let forged_view = verify_economic_state_view(
        signed_view(
            2,
            forged_advance.batch().checkpoint_digest.clone(),
            vec![forged_head, forged_target_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let forged = EconomicEffectDispatchCommitV1::sign(
        &forged_advance,
        &forged_view,
        digest("cas-nonce"),
        502,
        "anchor-key-1",
        1,
        &Keypair::from_seed(&[0x55; 32]),
    )?;
    assert!(
        verify_economic_effect_dispatch_commit(forged_advance, &forged_view, forged, &pins(),)
            .is_err()
    );
    Ok(())
}

#[test]
fn dispatch_commit_retains_the_exact_target_resource_head(
) -> Result<(), Box<dyn core::error::Error>> {
    for replacement in [None, Some(2_u64)] {
        let (advance, _, dispatched_head, target_head) = dispatch_advance()?;
        let mut committed_heads = vec![dispatched_head];
        if let Some(resource_version) = replacement {
            committed_heads.push(head(
                target_head.resource_key,
                target_head.head_version,
                resource_version,
                target_head.predecessor_digest,
            )?);
        }
        let committed_view = verify_economic_state_view(
            signed_view(
                2,
                advance.batch().checkpoint_digest.clone(),
                committed_heads,
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )?,
            &pins(),
        )?;
        let commit = EconomicEffectDispatchCommitV1::sign(
            &advance,
            &committed_view,
            digest("cas-nonce"),
            502,
            "anchor-key-1",
            1,
            &anchor_keypair(),
        )?;
        assert!(matches!(
            verify_economic_effect_dispatch_commit(advance, &committed_view, commit, &pins(),),
            Err(EconomicStateAnchorError::EffectDispatchRejected(
                "signed CAS commit does not match the effect advance"
            ))
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct CancellationVerifier {
    kind: EconomicNoEffectKindV1,
}

impl EconomicEffectCancellationProofVerifier for CancellationVerifier {
    fn verify_cancellation(
        &self,
        current: &EconomicEffectSlotV1,
        next: &EconomicEffectSlotV1,
    ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
        if current.slot_id != next.slot_id || current.state != EconomicEffectStateV1::Ready {
            return Err(EconomicStateAnchorError::EffectCancellationRejected(
                "cancellation slot binding changed",
            ));
        }
        Ok(self.kind)
    }
}

fn cancellation_advance(
    kind: EconomicNoEffectKindV1,
    admission: &dyn EconomicAdmissionHandoffVerifier,
) -> Result<
    (
        VerifiedEconomicEffectCancellationAdvance,
        EconomicEffectSlotV1,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    cancellation_advance_with_fence(kind, admission, 8)
}

fn cancellation_advance_with_fence(
    kind: EconomicNoEffectKindV1,
    admission: &dyn EconomicAdmissionHandoffVerifier,
    resulting_lifecycle_fence: u64,
) -> Result<
    (
        VerifiedEconomicEffectCancellationAdvance,
        EconomicEffectSlotV1,
        EconomicResourceHeadV1,
    ),
    Box<dyn core::error::Error>,
> {
    let ready = ready_effect_slot()?;
    let ready_content = inline_content(serde_json::to_value(&ready)?);
    let ready_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: ready.anchor_id.clone(),
        namespace: ready.namespace.clone(),
        resource_key: ready.resource_head_key(),
        head_version: 1,
        resource_version: 4,
        lifecycle_fence: 7,
        lifecycle_state: "ready".to_string(),
        state_digest: ready_content.digest()?,
        state: ready_content,
        operation_id: Some(ready.operation_id.clone()),
        effect_idempotency_key: Some(ready.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 500,
        predecessor_digest: None,
    };
    let ready_head_digest = ready_head.digest()?;
    let current_view = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-1"),
            vec![ready_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let proof = inline_content(json!({"cancellation": "anchor-cas"}));
    let mut cancelled = ready;
    cancelled.state = EconomicEffectStateV1::NoEffect;
    cancelled.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind,
        proof_id: "anchor-cancellation-1".to_string(),
        proof_digest: proof.digest()?,
        proof,
    });
    let cancelled_content = inline_content(serde_json::to_value(&cancelled)?);
    let cancelled_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: cancelled.anchor_id.clone(),
        namespace: cancelled.namespace.clone(),
        resource_key: cancelled.resource_head_key(),
        head_version: 2,
        resource_version: 9,
        lifecycle_fence: resulting_lifecycle_fence,
        lifecycle_state: "no_effect".to_string(),
        state_digest: cancelled_content.digest()?,
        state: cancelled_content,
        operation_id: Some(cancelled.operation_id.clone()),
        effect_idempotency_key: Some(cancelled.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 501,
        predecessor_digest: Some(ready_head_digest.clone()),
    };
    let mut batch = unsigned_batch(vec![transition(
        cancelled_head.clone(),
        Some(ready_head_digest),
    )]);
    batch.checkpoint_sequence = 2;
    batch.previous_checkpoint_digest = Some(current_view.view().checkpoint_digest.clone());
    batch.operation_id = Some(cancelled.operation_id.clone());
    batch.issued_at = 501;
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(
        &current_view,
        batch,
        &pins(),
        &DirectTransitionVerifier,
    )?;
    let cancellation = verify_economic_effect_cancellation_advance(
        advance,
        &CancellationVerifier { kind },
        admission,
    )?;
    Ok((cancellation, cancelled, cancelled_head))
}

#[test]
fn only_verified_cancellation_cas_mints_no_dispatch_authority(
) -> Result<(), Box<dyn core::error::Error>> {
    let (advance, cancelled, cancelled_head) = cancellation_advance(
        EconomicNoEffectKindV1::PermanentlyNotApplied,
        &MatchingAdmissionHandoff,
    )?;
    let committed = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![cancelled_head.clone()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let authority = verify_economic_effect_cancellation_commit(advance, &committed, &pins())?;
    assert_eq!(authority.slot(), &cancelled);
    assert_eq!(
        authority.kind(),
        EconomicNoEffectKindV1::PermanentlyNotApplied
    );
    assert_eq!(
        authority.checkpoint_digest(),
        committed.view().checkpoint_digest
    );
    assert_eq!(authority.expected_head_version(), 1);
    assert_eq!(authority.resulting_head_version(), 2);
    assert_eq!(authority.expected_resource_version(), 4);
    assert_eq!(authority.resulting_resource_version(), 9);
    assert_eq!(authority.expected_lifecycle_fence(), 7);
    assert_eq!(authority.resulting_lifecycle_fence(), 8);
    assert_eq!(
        authority.expected_head_digest(),
        cancelled_head
            .predecessor_digest
            .as_deref()
            .ok_or("predecessor")?
    );
    assert_eq!(authority.resulting_head_digest(), cancelled_head.digest()?);

    assert!(cancellation_advance(
        EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
        &RejectingAdmissionHandoff,
    )
    .is_err());
    assert!(cancellation_advance(
        EconomicNoEffectKindV1::PreDispatch,
        &RejectingAdmissionHandoff,
    )
    .is_err());
    Ok(())
}

#[test]
fn generic_batch_qualification_rejects_no_effect_transitions(
) -> Result<(), Box<dyn core::error::Error>> {
    let (advance, _, _) = cancellation_advance(
        EconomicNoEffectKindV1::PermanentlyNotApplied,
        &MatchingAdmissionHandoff,
    )?;

    assert!(matches!(
        qualify_generic_economic_state_batch_advance(advance.state_advance()),
        Err(EconomicStateAnchorError::EffectCancellationRejected(_))
    ));
    Ok(())
}

#[test]
fn generic_batch_qualification_rejects_effect_dispatch_transitions(
) -> Result<(), Box<dyn core::error::Error>> {
    let (advance, _, _, _) = dispatch_advance()?;

    assert!(matches!(
        qualify_generic_economic_state_batch_advance(advance.state_advance()),
        Err(EconomicStateAnchorError::EffectDispatchRejected(_))
    ));
    Ok(())
}

#[test]
fn cancellation_requires_a_strict_lifecycle_fence_advance() {
    assert!(cancellation_advance_with_fence(
        EconomicNoEffectKindV1::PermanentlyNotApplied,
        &MatchingAdmissionHandoff,
        7,
    )
    .is_err());
}

#[test]
fn effect_slot_decoder_binds_outer_anchor_namespace_and_lifecycle(
) -> Result<(), Box<dyn core::error::Error>> {
    let (_, _, head) = cancellation_advance(
        EconomicNoEffectKindV1::PermanentlyNotApplied,
        &MatchingAdmissionHandoff,
    )?;
    assert!(economic_effect_slot_from_head(&head).is_ok());

    let mut wrong_anchor = head.clone();
    wrong_anchor.anchor_id = "anchor-2".to_string();
    assert!(economic_effect_slot_from_head(&wrong_anchor).is_err());

    let mut wrong_namespace = head.clone();
    wrong_namespace.namespace = "economy-staging".to_string();
    assert!(economic_effect_slot_from_head(&wrong_namespace).is_err());

    let mut wrong_lifecycle = head;
    wrong_lifecycle.lifecycle_state = "completed".to_string();
    assert!(economic_effect_slot_from_head(&wrong_lifecycle).is_err());
    Ok(())
}

#[derive(Debug)]
struct RejectingAdmissionHandoff;

impl EconomicAdmissionHandoffVerifier for RejectingAdmissionHandoff {
    fn verify_operation_active(&self, _operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::AdmissionHandoffRejected)
    }

    fn verify_handoff(
        &self,
        _operation_id: &str,
        _handoff: &EconomicAdmissionHandoffV1,
    ) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::AdmissionHandoffRejected)
    }
}

#[test]
fn anchor_view_and_dispatch_commit_wire_schemas_match_signed_values(
) -> Result<(), Box<dyn core::error::Error>> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../spec/schemas/chio-economy")
        .canonicalize()?;
    let view_validator = schema_validator(&root, "anchor-view.v1.json")?;
    let dispatch_validator = schema_validator(&root, "effect-dispatch-commit.v1.json")?;
    let view = signed_view(
        1,
        digest("checkpoint-1"),
        vec![head(resource_key("round-1"), 1, 1, None)?],
        vec![resource_key("round-2")],
        Vec::new(),
        Vec::new(),
    )?;
    let view_json = serde_json::to_value(&view)?;
    assert!(view_validator.is_valid(&view_json));

    let (advance, _, dispatched_head, target_head) = dispatch_advance()?;
    let committed_view = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![dispatched_head, target_head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let commit = EconomicEffectDispatchCommitV1::sign(
        &advance,
        &committed_view,
        digest("cas-nonce"),
        502,
        "anchor-key-1",
        1,
        &anchor_keypair(),
    )?;
    let commit_json = serde_json::to_value(commit)?;
    assert!(dispatch_validator.is_valid(&commit_json));

    let mut unknown_view = view_json;
    unknown_view["schema"] = json!("chio.economy.anchor-view.v9");
    assert!(!view_validator.is_valid(&unknown_view));
    let mut tampered_commit = commit_json;
    tampered_commit["signerKeyEpoch"] = json!(0);
    assert!(!dispatch_validator.is_valid(&tampered_commit));
    Ok(())
}

#[derive(Debug)]
struct TargetEvidenceVerifier;

impl EconomicTargetStatusVerifier for TargetEvidenceVerifier {
    fn verify_status(
        &self,
        slot: &EconomicEffectSlotV1,
        evidence_digest: &str,
    ) -> Result<EconomicEffectTerminalV1, EconomicStateAnchorError> {
        if slot.target.target_id == "settlement-rail" && evidence_digest == digest("target-status")
        {
            let result = inline_content(json!({"transactionId": "tx-1"}));
            Ok(EconomicEffectTerminalV1::Completed {
                result_id: "tx-1".to_string(),
                result_digest: result.digest()?,
                result,
            })
        } else {
            Err(EconomicStateAnchorError::TargetStatusRejected)
        }
    }
}

#[derive(Debug)]
struct IdempotentTargetVerifier;

impl EconomicIdempotentTargetVerifier for IdempotentTargetVerifier {
    fn verify_qualification(
        &self,
        target: &EconomicEffectTargetV1,
        idempotency_key: &str,
    ) -> Result<(), EconomicStateAnchorError> {
        if target.qualification_digest == digest("target-qualification")
            && idempotency_key == digest("idempotency-key")
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
        }
    }
}

#[test]
fn target_status_and_idempotent_retry_require_separate_qualification(
) -> Result<(), Box<dyn core::error::Error>> {
    let mut slot = ready_effect_slot()?;
    slot.state = EconomicEffectStateV1::DispatchCommitted;
    let status =
        verify_economic_target_status(&slot, &digest("target-status"), &TargetEvidenceVerifier)?;
    assert_eq!(status.next_slot().state, EconomicEffectStateV1::Completed);
    let retry = verify_economic_idempotent_recovery(&slot, &IdempotentTargetVerifier)?;
    assert_eq!(retry.idempotency_key(), slot.idempotency_key);
    assert_eq!(retry.slot(), &slot);
    assert!(verify_economic_idempotent_recovery(&slot, &TargetEvidenceVerifier).is_err());
    Ok(())
}

#[test]
fn completed_effect_authority_requires_the_exact_anchored_slot(
) -> Result<(), Box<dyn core::error::Error>> {
    let mut dispatched = ready_effect_slot()?;
    dispatched.state = EconomicEffectStateV1::DispatchCommitted;
    let completed = verify_economic_target_status(
        &dispatched,
        &digest("target-status"),
        &TargetEvidenceVerifier,
    )?
    .next_slot()
    .clone();
    let terminal_result = match completed.terminal.as_ref() {
        Some(EconomicEffectTerminalV1::Completed {
            result_id,
            result_digest,
            result,
        }) => EconomicTerminalResultV1 {
            result_id: result_id.clone(),
            result_digest: result_digest.clone(),
            result: result.clone(),
        },
        _ => return Err("completed effect omitted its result".into()),
    };
    let state = inline_content(serde_json::to_value(&completed)?);
    let head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_string(),
        anchor_id: completed.anchor_id.clone(),
        namespace: completed.namespace.clone(),
        resource_key: completed.resource_head_key(),
        head_version: 3,
        resource_version: 3,
        lifecycle_fence: 3,
        lifecycle_state: "completed".to_string(),
        state_digest: state.digest()?,
        state,
        operation_id: Some(completed.operation_id.clone()),
        effect_idempotency_key: Some(completed.idempotency_key.clone()),
        frost: completed.frost.clone(),
        terminal_result: Some(terminal_result),
        trusted_clock_high_water: 502,
        predecessor_digest: Some(digest("dispatched-head")),
    };
    let expected_head_digest = head.digest()?;
    let view = verify_economic_state_view(
        signed_view(
            3,
            digest("checkpoint-3"),
            vec![head],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;

    let verified = verify_economic_completed_effect(&view, &completed)?;
    assert_eq!(verified.slot(), &completed);
    assert_eq!(verified.checkpoint_digest(), digest("checkpoint-3"));
    assert_eq!(verified.effect_head_digest(), expected_head_digest);
    assert_eq!(verified.observed_at(), 500);

    let mut substituted = completed.clone();
    substituted.parameters_digest = digest("substituted-parameters");
    assert!(verify_economic_completed_effect(&view, &substituted).is_err());
    assert!(verify_economic_completed_effect(&view, &dispatched).is_err());
    Ok(())
}

impl EconomicIdempotentTargetVerifier for TargetEvidenceVerifier {
    fn verify_qualification(
        &self,
        _target: &EconomicEffectTargetV1,
        _idempotency_key: &str,
    ) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
    }
}

#[test]
fn readiness_is_false_for_missing_behind_ahead_and_divergent_views(
) -> Result<(), Box<dyn core::error::Error>> {
    let current = head(resource_key("round-1"), 1, 1, None)?;
    let current_digest = current.digest()?;
    let view = verify_economic_state_view(
        signed_view(
            3,
            digest("checkpoint-3"),
            vec![current],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )?,
        &pins(),
    )?;
    let expectation = EconomicStateReadinessExpectation {
        checkpoint_sequence: 3,
        checkpoint_digest: digest("checkpoint-3"),
        heads: vec![EconomicExpectedHead {
            resource_key: resource_key("round-1"),
            head_digest: current_digest,
        }],
    };
    assert_eq!(
        assess_economic_state_readiness(&view, &expectation)?,
        EconomicStateReadiness::Ready
    );
    let mut behind = expectation.clone();
    behind.checkpoint_sequence = 4;
    assert_eq!(
        assess_economic_state_readiness(&view, &behind)?,
        EconomicStateReadiness::Behind
    );
    let mut ahead = expectation.clone();
    ahead.checkpoint_sequence = 2;
    assert_eq!(
        assess_economic_state_readiness(&view, &ahead)?,
        EconomicStateReadiness::Ahead
    );
    let mut divergent = expectation.clone();
    divergent.checkpoint_digest = digest("different-checkpoint");
    assert_eq!(
        assess_economic_state_readiness(&view, &divergent)?,
        EconomicStateReadiness::Divergent
    );
    let mut missing = expectation;
    missing.heads[0].resource_key = resource_key("round-2");
    assert_eq!(
        assess_economic_state_readiness(&view, &missing)?,
        EconomicStateReadiness::Missing
    );
    let oversized = EconomicStateReadinessExpectation {
        checkpoint_sequence: 3,
        checkpoint_digest: digest("checkpoint-3"),
        heads: (0..=MAX_ECONOMIC_TRANSITIONS)
            .map(|index| EconomicExpectedHead {
                resource_key: resource_key(&format!("round-{index:03}")),
                head_digest: digest(&format!("head-{index}")),
            })
            .collect(),
    };
    assert!(assess_economic_state_readiness(&view, &oversized).is_err());
    Ok(())
}
