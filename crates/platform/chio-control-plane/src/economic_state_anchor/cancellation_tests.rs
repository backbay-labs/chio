use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::economic_continuity::{
    verify_economic_effect_cancellation_advance, verify_economic_state_batch_advance,
    verify_economic_state_view, EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
    EconomicAdmissionHandoffVerifier, EconomicContentV1, EconomicEffectCancellationProofVerifier,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicNoEffectKindV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchor, EconomicStateAnchorError, EconomicStateAnchorPins,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, EconomicStateTransitionV1,
    EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicEffectCancellationAdvance, VerifiedEconomicStateView,
    CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA,
    CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA, CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_kernel::admission_operation::StoreMutationFence;
use serde_json::json;

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

fn config() -> RemoteEconomicStateAnchorConfig {
    RemoteEconomicStateAnchorConfig {
        base_url: "https://anchor.example".to_owned(),
        bearer_token: "anchor-token".to_owned(),
        timeout: Duration::from_secs(5),
        pins: pins(),
    }
}

#[derive(Debug, Default)]
struct CountingTransitionVerifier {
    calls: AtomicUsize,
}

impl EconomicTransitionProofVerifier for CountingTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

#[derive(Debug, Default)]
struct CountingAdmissionVerifier {
    calls: AtomicUsize,
}

impl EconomicAdmissionHandoffVerifier for CountingAdmissionVerifier {
    fn verify_operation_active(&self, operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if operation_id == digest("operation-1") {
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
        self.calls.fetch_add(1, Ordering::SeqCst);
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

#[derive(Debug, Default)]
struct CountingCancellationVerifier {
    calls: AtomicUsize,
}

impl EconomicEffectCancellationProofVerifier for CountingCancellationVerifier {
    fn verify_cancellation(
        &self,
        current: &EconomicEffectSlotV1,
        next: &EconomicEffectSlotV1,
    ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if current.slot_id == next.slot_id
            && matches!(
                &next.terminal,
                Some(EconomicEffectTerminalV1::NoEffect {
                    kind: EconomicNoEffectKindV1::PermanentlyNotApplied,
                    ..
                })
            )
        {
            Ok(EconomicNoEffectKindV1::PermanentlyNotApplied)
        } else {
            Err(EconomicStateAnchorError::EffectCancellationRejected(
                "fixture cancellation proof is not bound",
            ))
        }
    }
}

fn ready_slot() -> TestResult<EconomicEffectSlotV1> {
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "clearing_round".to_owned(),
            scope_id: "tenant-1".to_owned(),
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
            store_fence: StoreMutationFence {
                store_uuid: "store-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                owner_epoch: 3,
            },
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
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    Ok(slot)
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
        resource_version: version,
        lifecycle_fence: version,
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

fn cancellation_advance(
    transition_verifier: &dyn EconomicTransitionProofVerifier,
    cancellation_verifier: &dyn EconomicEffectCancellationProofVerifier,
    admission_verifier: &dyn EconomicAdmissionHandoffVerifier,
) -> TestResult<(
    VerifiedEconomicEffectCancellationAdvance,
    VerifiedEconomicStateView,
)> {
    let ready = ready_slot()?;
    let ready_head = effect_head(&ready, 1, None)?;
    let ready_head_digest = ready_head.digest()?;
    let current =
        verify_economic_state_view(signed_view(1, digest("checkpoint-1"), ready_head)?, &pins())?;
    let proof = EconomicContentV1::Inline {
        value: json!({"cancellation": "permanently-not-applied"}),
    };
    let mut cancelled = ready;
    cancelled.state = EconomicEffectStateV1::NoEffect;
    cancelled.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind: EconomicNoEffectKindV1::PermanentlyNotApplied,
        proof_id: "fixture-cancellation".to_owned(),
        proof_digest: proof.digest()?,
        proof,
    });
    let cancelled_head = effect_head(&cancelled, 2, Some(ready_head_digest.clone()))?;
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: vec![EconomicStateTransitionV1 {
            resource_key: cancelled_head.resource_key.clone(),
            expected_head_digest: Some(ready_head_digest),
            next_head: cancelled_head.clone(),
            transition_proof_digest: digest("cancellation-transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(cancelled.operation_id.clone()),
        issued_at: 102,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&keypair())?;
    let advance =
        verify_economic_state_batch_advance(&current, batch, &pins(), transition_verifier)?;
    let advance = verify_economic_effect_cancellation_advance(
        advance,
        cancellation_verifier,
        admission_verifier,
    )?;
    let committed = verify_economic_state_view(
        signed_view(2, advance.batch().checkpoint_digest.clone(), cancelled_head)?,
        &pins(),
    )?;
    Ok((advance, committed))
}

#[derive(Default)]
struct FixtureTransport {
    responses: Mutex<VecDeque<Result<Vec<u8>, EconomicStateAnchorError>>>,
    requests: Mutex<Vec<(String, Vec<u8>)>>,
}

impl EconomicStateAnchorTransport for FixtureTransport {
    fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, EconomicStateAnchorError> {
        lock(&self.requests).push((path.to_owned(), body.to_vec()));
        lock(&self.responses).pop_front().unwrap_or_else(|| {
            Err(EconomicStateAnchorError::Unavailable(
                "fixture response is missing".to_owned(),
            ))
        })
    }
}

#[test]
fn remote_effect_cancellation_rechecks_proof_handoff_and_signed_commit() -> TestResult {
    let transition_verifier = Arc::new(CountingTransitionVerifier::default());
    let admission_verifier = Arc::new(CountingAdmissionVerifier::default());
    let cancellation_verifier = Arc::new(CountingCancellationVerifier::default());
    let (advance, committed) = cancellation_advance(
        transition_verifier.as_ref(),
        cancellation_verifier.as_ref(),
        admission_verifier.as_ref(),
    )?;
    let expected_checkpoint = committed.view().checkpoint_digest.clone();
    let expected_batch = advance.batch().clone();
    let transport = Arc::new(FixtureTransport::default());
    lock(&transport.responses).push_back(Ok(serde_json::to_vec(committed.view())?));
    let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
        config(),
        transition_verifier.clone(),
        admission_verifier.clone(),
        cancellation_verifier.clone(),
        transport.clone(),
    )?;

    let cancellation = anchor.compare_and_swap_effect_cancellation(advance)?;
    assert_eq!(cancellation.checkpoint_digest(), expected_checkpoint);
    assert_eq!(
        cancellation.kind(),
        EconomicNoEffectKindV1::PermanentlyNotApplied
    );
    assert_eq!(transition_verifier.calls.load(Ordering::SeqCst), 2);
    assert_eq!(admission_verifier.calls.load(Ordering::SeqCst), 2);
    assert_eq!(cancellation_verifier.calls.load(Ordering::SeqCst), 2);
    let requests = lock(&transport.requests);
    let (path, body) = requests.first().ok_or("fixture request is missing")?;
    assert_eq!(path, ECONOMIC_EFFECT_CANCELLATION_PATH);
    assert_eq!(
        serde_json::from_slice::<EconomicStateBatchV1>(body)?,
        expected_batch
    );
    Ok(())
}

#[test]
fn remote_effect_cancellation_recovers_an_exact_committed_checkpoint_after_ack_loss() -> TestResult
{
    let transition_verifier = Arc::new(CountingTransitionVerifier::default());
    let admission_verifier = Arc::new(CountingAdmissionVerifier::default());
    let cancellation_verifier = Arc::new(CountingCancellationVerifier::default());
    let (advance, committed) = cancellation_advance(
        transition_verifier.as_ref(),
        cancellation_verifier.as_ref(),
        admission_verifier.as_ref(),
    )?;
    let expected_checkpoint = committed.view().checkpoint_digest.clone();
    let transport = Arc::new(FixtureTransport::default());
    lock(&transport.responses).push_back(Err(EconomicStateAnchorError::Unavailable(
        "cancellation acknowledgement was lost".to_owned(),
    )));
    lock(&transport.responses).push_back(Ok(serde_json::to_vec(committed.view())?));
    let anchor = RemoteEconomicStateAnchor::with_fixture_transport(
        config(),
        transition_verifier,
        admission_verifier,
        cancellation_verifier,
        transport.clone(),
    )?;

    let cancellation = anchor.compare_and_swap_effect_cancellation(advance)?;
    assert_eq!(cancellation.checkpoint_digest(), expected_checkpoint);

    let requests = lock(&transport.requests);
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].0, ECONOMIC_EFFECT_CANCELLATION_PATH);
    assert_eq!(requests[1].0, ECONOMIC_STATE_CHECKPOINT_READ_PATH);
    let query = serde_json::from_slice::<EconomicCheckpointReadQuery>(&requests[1].1)?;
    assert_eq!(query.checkpoint_sequence, 2);
    assert_eq!(query.checkpoint_digest, expected_checkpoint);
    assert_eq!(query.query.resource_keys.len(), 1);
    assert!(query.query.request_keys.is_empty());
    Ok(())
}
