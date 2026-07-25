use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::economic_continuity::{
    qualify_generic_economic_state_batch_advance, verify_economic_effect_cancellation_advance,
    verify_economic_effect_cancellation_commit, verify_economic_effect_dispatch_advance,
    verify_economic_effect_dispatch_commit, verify_economic_state_batch_advance,
    verify_economic_state_batch_commit, verify_economic_state_view,
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicAdmissionHandoffVerifier,
    EconomicCheckpointReadQuery, EconomicContentV1, EconomicEffectCancellationProofVerifier,
    EconomicEffectDispatchCommitV1, EconomicEffectSlotV1, EconomicEffectStateV1,
    EconomicEffectTargetV1, EconomicEffectTerminalV1, EconomicNoEffectKindV1,
    EconomicRequestBindingV1, EconomicRequestKeyV1, EconomicRequestReplayV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchor, EconomicStateAnchorError,
    EconomicStateAnchorPins, EconomicStateAnchorViewV1, EconomicStateBatchV1,
    EconomicStateReadQuery, EconomicStateTransitionV1, EconomicTransitionAuthorizationV1,
    EconomicTransitionProofVerifier, QualifiedGenericEconomicStateBatchAdvance,
    VerifiedEconomicEffectCancellationAdvance, VerifiedEconomicEffectDispatch,
    VerifiedEconomicEffectDispatchAdvance, VerifiedEconomicEffectNotDispatched,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_core::StoreMutationFence;
use proptest::prelude::*;
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn anchor_keypair() -> Keypair {
    Keypair::from_seed(&[0x41; 32])
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: anchor_keypair().public_key(),
    }
}

fn resource_key(index: usize) -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: "conformance_resource".to_owned(),
        scope_id: "scope-1".to_owned(),
        resource_id: format!("resource-{index:03}"),
    }
}

fn resource_head(
    key: EconomicResourceKeyV1,
    version: u64,
    marker: u16,
    predecessor_digest: Option<String>,
) -> TestResult<EconomicResourceHeadV1> {
    let state = EconomicContentV1::Inline {
        value: json!({"marker": marker, "resourceId": key.resource_id, "version": version}),
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: key,
        head_version: version,
        resource_version: version,
        lifecycle_fence: version,
        lifecycle_state: "active".to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 100 + version,
        predecessor_digest,
    })
}

fn signed_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    mut heads: Vec<EconomicResourceHeadV1>,
    mut absent_resource_keys: Vec<EconomicResourceKeyV1>,
    mut request_replays: Vec<EconomicRequestReplayV1>,
    mut absent_request_keys: Vec<EconomicRequestKeyV1>,
) -> TestResult<EconomicStateAnchorViewV1> {
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    absent_resource_keys.sort_unstable();
    request_replays.sort_by(|left, right| left.request.key().cmp(&right.request.key()));
    absent_request_keys.sort_unstable();
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence,
        checkpoint_digest,
        heads_root: String::new(),
        heads,
        absent_resource_keys,
        request_replays_root: String::new(),
        request_replays,
        absent_request_keys,
        observed_at: 1_000 + checkpoint_sequence,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&anchor_keypair())?;
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

#[derive(Debug)]
struct ExactHandoff;

impl EconomicAdmissionHandoffVerifier for ExactHandoff {
    fn verify_operation_active(&self, operation_id: &str) -> Result<(), EconomicStateAnchorError> {
        if operation_id == digest("effect-operation") {
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
        if operation_id == digest("effect-operation")
            && handoff.state == EconomicAdmissionHandoffStateV1::MutationSubmitted
            && handoff.operation_version == 3
            && handoff.lifecycle_fence == 7
            && handoff.store_fence
                == (StoreMutationFence {
                    store_uuid: "store-1".to_owned(),
                    lease_id: "lease-1".to_owned(),
                    owner_epoch: 3,
                })
        {
            Ok(())
        } else {
            Err(EconomicStateAnchorError::AdmissionHandoffRejected)
        }
    }
}

#[derive(Debug)]
struct ExactCancellation;

impl EconomicEffectCancellationProofVerifier for ExactCancellation {
    fn verify_cancellation(
        &self,
        current: &EconomicEffectSlotV1,
        next: &EconomicEffectSlotV1,
    ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
        if current.slot_id == next.slot_id
            && current.state == EconomicEffectStateV1::Ready
            && matches!(
                next.terminal,
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

#[derive(Clone)]
struct FixtureAnchor {
    state: Arc<Mutex<FixtureAnchorState>>,
}

struct FixtureAnchorState {
    current: EconomicStateAnchorViewV1,
    retained: BTreeMap<(u64, String), EconomicStateAnchorViewV1>,
    cas_nonce: u64,
}

impl FixtureAnchor {
    fn new(current: EconomicStateAnchorViewV1) -> Self {
        let mut retained = BTreeMap::new();
        retained.insert(
            (
                current.checkpoint_sequence,
                current.checkpoint_digest.clone(),
            ),
            current.clone(),
        );
        Self {
            state: Arc::new(Mutex::new(FixtureAnchorState {
                current,
                retained,
                cas_nonce: 0,
            })),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, FixtureAnchorState>, EconomicStateAnchorError> {
        self.state.lock().map_err(|_| {
            EconomicStateAnchorError::Unavailable("fixture anchor lock is poisoned".to_owned())
        })
    }

    fn current(&self) -> Result<EconomicStateAnchorViewV1, EconomicStateAnchorError> {
        Ok(self.lock()?.current.clone())
    }

    fn prepare_commit(
        state: &FixtureAnchorState,
        batch: &EconomicStateBatchV1,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        if batch.checkpoint_sequence != state.current.checkpoint_sequence + 1
            || batch.previous_checkpoint_digest.as_deref()
                != Some(state.current.checkpoint_digest.as_str())
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "fixture CAS predecessor conflicts",
            ));
        }
        let mut heads = state.current.heads.clone();
        for transition in &batch.transitions {
            let current = heads
                .iter()
                .find(|head| head.resource_key == transition.resource_key);
            let current_digest = current.map(EconomicResourceHeadV1::digest).transpose()?;
            if current_digest != transition.expected_head_digest {
                return Err(EconomicStateAnchorError::InvalidView(
                    "fixture CAS expected head conflicts",
                ));
            }
        }
        for transition in &batch.transitions {
            heads.retain(|head| head.resource_key != transition.resource_key);
            heads.push(transition.next_head.clone());
        }
        let mut replays = state.current.request_replays.clone();
        for replay in &batch.request_replays {
            let key = replay.request.key();
            if let Some(existing) = replays
                .iter()
                .find(|existing| existing.request.key() == key)
            {
                if existing != replay {
                    return Err(EconomicStateAnchorError::RequestReplayConflict(key));
                }
            } else {
                replays.push(replay.clone());
            }
        }
        let committed = signed_view(
            batch.checkpoint_sequence,
            batch.checkpoint_digest.clone(),
            heads,
            Vec::new(),
            replays,
            Vec::new(),
        )
        .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        verify_economic_state_view(committed, &pins())
    }

    fn install_commit(state: &mut FixtureAnchorState, committed: &VerifiedEconomicStateView) {
        state.current = committed.view().clone();
        state.retained.insert(
            (
                committed.view().checkpoint_sequence,
                committed.view().checkpoint_digest.clone(),
            ),
            committed.view().clone(),
        );
        state.cas_nonce += 1;
    }

    fn filtered_view(
        source: &EconomicStateAnchorViewV1,
        query: &EconomicStateReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        query.validate()?;
        let heads = query
            .resource_keys
            .iter()
            .filter_map(|key| source.head(key).cloned())
            .collect::<Vec<_>>();
        let absent_resource_keys = query
            .resource_keys
            .iter()
            .filter(|key| source.head(key).is_none())
            .cloned()
            .collect::<Vec<_>>();
        let request_replays = query
            .request_keys
            .iter()
            .filter_map(|key| source.request_replay(key).cloned())
            .collect::<Vec<_>>();
        let absent_request_keys = query
            .request_keys
            .iter()
            .filter(|key| source.request_replay(key).is_none())
            .cloned()
            .collect::<Vec<_>>();
        let view = signed_view(
            source.checkpoint_sequence,
            source.checkpoint_digest.clone(),
            heads,
            absent_resource_keys,
            request_replays,
            absent_request_keys,
        )
        .map_err(|error| EconomicStateAnchorError::Unavailable(error.to_string()))?;
        verify_economic_state_view(view, &pins())
    }
}

impl EconomicStateAnchor for FixtureAnchor {
    fn read_state(
        &self,
        query: &EconomicStateReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        Self::filtered_view(&self.lock()?.current, query)
    }

    fn read_checkpoint_state(
        &self,
        query: &EconomicCheckpointReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        query.validate()?;
        let state = self.lock()?;
        let source = state
            .retained
            .get(&(query.checkpoint_sequence, query.checkpoint_digest.clone()))
            .ok_or(EconomicStateAnchorError::Missing)?;
        Self::filtered_view(source, &query.query)
    }

    fn compare_and_swap_batch(
        &self,
        advance: QualifiedGenericEconomicStateBatchAdvance<'_>,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        let advance = advance.advance();
        let mut state = self.lock()?;
        if advance.current().view().checkpoint_sequence != state.current.checkpoint_sequence
            || advance.current().view().checkpoint_digest != state.current.checkpoint_digest
        {
            return Err(EconomicStateAnchorError::InvalidView(
                "fixture CAS current view conflicts",
            ));
        }
        let committed = Self::prepare_commit(&state, advance.batch())?;
        verify_economic_state_batch_commit(advance, &committed, &pins())?;
        Self::install_commit(&mut state, &committed);
        Ok(committed)
    }

    fn compare_and_swap_effect_dispatch(
        &self,
        advance: VerifiedEconomicEffectDispatchAdvance,
    ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
        let mut state = self.lock()?;
        let committed = Self::prepare_commit(&state, advance.batch())?;
        let commit = EconomicEffectDispatchCommitV1::sign(
            &advance,
            &committed,
            digest(&format!("fixture-cas-{}", state.cas_nonce + 1)),
            2_000 + state.cas_nonce,
            "anchor-key-1",
            1,
            &anchor_keypair(),
        )?;
        let dispatch =
            verify_economic_effect_dispatch_commit(advance, &committed, commit, &pins())?;
        Self::install_commit(&mut state, &committed);
        Ok(dispatch)
    }

    fn compare_and_swap_effect_cancellation(
        &self,
        advance: VerifiedEconomicEffectCancellationAdvance,
    ) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
        let mut state = self.lock()?;
        let committed = Self::prepare_commit(&state, advance.batch())?;
        let cancellation =
            verify_economic_effect_cancellation_commit(advance, &committed, &pins())?;
        Self::install_commit(&mut state, &committed);
        Ok(cancellation)
    }
}

fn genesis(count: usize) -> TestResult<EconomicStateAnchorViewV1> {
    let heads = (0..count)
        .map(|index| resource_head(resource_key(index), 1, 0, None))
        .collect::<TestResult<Vec<_>>>()?;
    signed_view(
        1,
        digest("genesis"),
        heads,
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

fn successor_advance(
    current: EconomicStateAnchorViewV1,
    marker: u16,
) -> TestResult<VerifiedEconomicStateBatchAdvance> {
    let current = verify_economic_state_view(current, &pins())?;
    let transitions = current
        .view()
        .heads
        .iter()
        .map(|head| {
            let predecessor = head.digest()?;
            let next = resource_head(
                head.resource_key.clone(),
                head.head_version + 1,
                marker,
                Some(predecessor.clone()),
            )?;
            Ok(EconomicStateTransitionV1 {
                resource_key: head.resource_key.clone(),
                expected_head_digest: Some(predecessor),
                next_head: next,
                transition_proof_digest: digest(&format!(
                    "transition-{marker}-{}",
                    head.resource_key.resource_id
                )),
                prepared_effect: None,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        checkpoint_sequence: current.view().checkpoint_sequence + 1,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: None,
        issued_at: 1_100 + u64::from(marker),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&anchor_keypair())?;
    Ok(verify_economic_state_batch_advance(
        &current,
        batch,
        &pins(),
        &DirectVerifier,
    )?)
}

fn marker(head: &EconomicResourceHeadV1) -> Option<u64> {
    match &head.state {
        EconomicContentV1::Inline { value } => value.get("marker")?.as_u64(),
        EconomicContentV1::Available { .. } => None,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn conflicting_multi_key_batches_commit_all_or_nothing(
        count in 2_usize..12,
        left_marker in 1_u16..u16::MAX,
        right_marker in 1_u16..u16::MAX,
    ) {
        prop_assume!(left_marker != right_marker);
        let initial = genesis(count).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let anchor = Arc::new(FixtureAnchor::new(initial.clone()));
        let left = successor_advance(initial.clone(), left_marker)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let right = successor_advance(initial, right_marker)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let left_anchor = anchor.clone();
        let right_anchor = anchor.clone();
        let left_thread = std::thread::spawn(move || {
            left_anchor.compare_and_swap_batch(qualify_generic_economic_state_batch_advance(&left)?)
        });
        let right_thread = std::thread::spawn(move || {
            right_anchor.compare_and_swap_batch(qualify_generic_economic_state_batch_advance(&right)?)
        });
        let left_result = left_thread.join().map_err(|_| TestCaseError::fail("left CAS panicked"))?;
        let right_result = right_thread.join().map_err(|_| TestCaseError::fail("right CAS panicked"))?;
        prop_assert_eq!(usize::from(left_result.is_ok()) + usize::from(right_result.is_ok()), 1);

        let current = anchor.current().map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(current.checkpoint_sequence, 2);
        let observed = current.heads.iter().filter_map(marker).collect::<Vec<_>>();
        prop_assert_eq!(observed.len(), count);
        prop_assert!(observed.iter().all(|value| *value == observed[0]));
        prop_assert!(observed[0] == u64::from(left_marker) || observed[0] == u64::from(right_marker));
    }

    #[test]
    fn malformed_order_and_stale_expected_heads_never_verify(
        count in 2_usize..12,
        marker_value in 1_u16..u16::MAX,
    ) {
        let initial = genesis(count).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let current = verify_economic_state_view(initial.clone(), &pins())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let advance = successor_advance(initial, marker_value)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;

        let mut misordered = advance.batch().clone();
        misordered.transitions.swap(0, 1);
        let mut misordered_reseal = misordered.clone();
        prop_assert!(misordered_reseal.seal(&anchor_keypair()).is_err());
        prop_assert!(verify_economic_state_batch_advance(
            &current,
            misordered,
            &pins(),
            &DirectVerifier,
        ).is_err());

        let mut stale = advance.batch().clone();
        stale.transitions[0].expected_head_digest = Some(digest("stale-head"));
        let mut stale_reseal = stale.clone();
        prop_assert!(stale_reseal.seal(&anchor_keypair()).is_err());
        prop_assert!(verify_economic_state_batch_advance(
            &current,
            stale,
            &pins(),
            &DirectVerifier,
        ).is_err());

        let mut regressing = advance.batch().clone();
        regressing.transitions[0].next_head.head_version = 1;
        regressing.transitions[0].next_head.resource_version = 1;
        regressing.transitions[0].next_head.lifecycle_fence = 1;
        let mut regressing_reseal = regressing.clone();
        prop_assert!(regressing_reseal.seal(&anchor_keypair()).is_err());
        prop_assert!(verify_economic_state_batch_advance(
            &current,
            regressing,
            &pins(),
            &DirectVerifier,
        ).is_err());
    }
}

fn ready_effect_slot() -> TestResult<EconomicEffectSlotV1> {
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: resource_key(0),
        operation_id: digest("effect-operation"),
        effect_kind: "conformance_dispatch".to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("request-namespace"),
            request_id: "request-1".to_owned(),
            request_binding_digest: digest("request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
            operation_version: 3,
            lifecycle_fence: 7,
            store_fence: StoreMutationFence {
                store_uuid: "store-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                owner_epoch: 3,
            },
        },
        target: EconomicEffectTargetV1 {
            target_id: "target-1".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("target-qualification"),
        },
        action_digest: digest("effect-action"),
        parameters_digest: digest("effect-parameters"),
        resource_head_digest: digest("parent-resource-head"),
        frost: None,
        idempotency_key: digest("effect-idempotency"),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    slot.resource_head_digest = resource_head(slot.resource_key.clone(), 1, 0, None)?.digest()?;
    slot.slot_id = slot.recompute_slot_id()?;
    slot.validate()?;
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
            EconomicEffectStateV1::DispatchCommitted => "dispatch_committed",
            EconomicEffectStateV1::NoEffect => "no_effect",
            EconomicEffectStateV1::Unknown => "unknown",
            _ => "terminal",
        }
        .to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 200 + version,
        predecessor_digest,
    })
}

fn effect_dispatch_advance(
    current_view: EconomicStateAnchorViewV1,
) -> TestResult<VerifiedEconomicEffectDispatchAdvance> {
    let current = verify_economic_state_view(current_view, &pins())?;
    let ready_head = current
        .view()
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == "effect_slot")
        .ok_or("ready head is absent")?;
    let ready_head_digest = ready_head.digest()?;
    let EconomicContentV1::Inline { value } = &ready_head.state else {
        return Err("ready effect slot is not inline".into());
    };
    let mut dispatched: EconomicEffectSlotV1 = serde_json::from_value(value.clone())?;
    dispatched.state = EconomicEffectStateV1::DispatchCommitted;
    let next_head = effect_head(&dispatched, 2, Some(ready_head_digest.clone()))?;
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
            resource_key: next_head.resource_key.clone(),
            expected_head_digest: Some(ready_head_digest),
            next_head,
            transition_proof_digest: digest("effect-dispatch-transition"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(dispatched.operation_id.clone()),
        issued_at: 1_200,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
    Ok(verify_economic_effect_dispatch_advance(
        advance,
        &ExactHandoff,
    )?)
}

fn effect_cancellation_advance(
    current_view: EconomicStateAnchorViewV1,
) -> TestResult<VerifiedEconomicEffectCancellationAdvance> {
    let current = verify_economic_state_view(current_view, &pins())?;
    let ready_head = current
        .view()
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == "effect_slot")
        .ok_or("ready head is absent")?;
    let ready_head_digest = ready_head.digest()?;
    let EconomicContentV1::Inline { value } = &ready_head.state else {
        return Err("ready effect slot is not inline".into());
    };
    let mut cancelled: EconomicEffectSlotV1 = serde_json::from_value(value.clone())?;
    let proof = EconomicContentV1::Inline {
        value: json!({"cancellation": "permanently-not-applied"}),
    };
    cancelled.state = EconomicEffectStateV1::NoEffect;
    cancelled.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind: EconomicNoEffectKindV1::PermanentlyNotApplied,
        proof_id: "conformance-cancellation".to_owned(),
        proof_digest: proof.digest()?,
        proof,
    });
    let next_head = effect_head(&cancelled, 2, Some(ready_head_digest.clone()))?;
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
            resource_key: next_head.resource_key.clone(),
            expected_head_digest: Some(ready_head_digest),
            next_head,
            transition_proof_digest: digest("effect-cancellation-transition"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(cancelled.operation_id.clone()),
        issued_at: 1_200,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&anchor_keypair())?;
    let advance = verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
    Ok(verify_economic_effect_cancellation_advance(
        advance,
        &ExactCancellation,
        &ExactHandoff,
    )?)
}

#[test]
fn concurrent_effect_dispatch_mints_exactly_one_authority() -> TestResult {
    let ready = ready_effect_slot()?;
    let ready_head = effect_head(&ready, 1, None)?;
    let target_head = resource_head(ready.resource_key.clone(), 1, 0, None)?;
    let current = signed_view(
        1,
        digest("effect-genesis"),
        vec![ready_head, target_head],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    let anchor = Arc::new(FixtureAnchor::new(current.clone()));
    let first = effect_dispatch_advance(current.clone())?;
    let second = effect_dispatch_advance(current)?;
    let first_anchor = anchor.clone();
    let second_anchor = anchor.clone();
    let first_thread =
        std::thread::spawn(move || first_anchor.compare_and_swap_effect_dispatch(first));
    let second_thread =
        std::thread::spawn(move || second_anchor.compare_and_swap_effect_dispatch(second));
    let first_result = first_thread.join().map_err(|_| "first dispatch panicked")?;
    let second_result = second_thread
        .join()
        .map_err(|_| "second dispatch panicked")?;

    assert_eq!(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
        1
    );
    let current = anchor.current()?;
    let head = current
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == "effect_slot")
        .ok_or("committed effect head is absent")?;
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err("committed effect slot is not inline".into());
    };
    let slot: EconomicEffectSlotV1 = serde_json::from_value(value.clone())?;
    assert_eq!(slot.state, EconomicEffectStateV1::DispatchCommitted);
    Ok(())
}

#[test]
fn cancellation_and_dispatch_have_one_linearization_winner() -> TestResult {
    let ready = ready_effect_slot()?;
    let target_head = resource_head(ready.resource_key.clone(), 1, 0, None)?;
    let current = signed_view(
        1,
        digest("effect-race-genesis"),
        vec![effect_head(&ready, 1, None)?, target_head],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )?;
    let anchor = Arc::new(FixtureAnchor::new(current.clone()));
    let dispatch = effect_dispatch_advance(current.clone())?;
    let cancellation = effect_cancellation_advance(current)?;
    let dispatch_anchor = anchor.clone();
    let cancellation_anchor = anchor.clone();
    let dispatch_thread =
        std::thread::spawn(move || dispatch_anchor.compare_and_swap_effect_dispatch(dispatch));
    let cancellation_thread = std::thread::spawn(move || {
        cancellation_anchor.compare_and_swap_effect_cancellation(cancellation)
    });
    let dispatch_result = dispatch_thread.join().map_err(|_| "dispatch panicked")?;
    let cancellation_result = cancellation_thread
        .join()
        .map_err(|_| "cancellation panicked")?;
    assert_eq!(
        usize::from(dispatch_result.is_ok()) + usize::from(cancellation_result.is_ok()),
        1
    );
    let current = anchor.current()?;
    let head = current
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == "effect_slot")
        .ok_or("effect head is absent")?;
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err("effect slot is not inline".into());
    };
    let slot: EconomicEffectSlotV1 = serde_json::from_value(value.clone())?;
    assert!(matches!(
        slot.state,
        EconomicEffectStateV1::DispatchCommitted | EconomicEffectStateV1::NoEffect
    ));
    assert_eq!(
        slot.state == EconomicEffectStateV1::DispatchCommitted,
        dispatch_result.is_ok()
    );
    assert_eq!(
        slot.state == EconomicEffectStateV1::NoEffect,
        cancellation_result.is_ok()
    );
    Ok(())
}
