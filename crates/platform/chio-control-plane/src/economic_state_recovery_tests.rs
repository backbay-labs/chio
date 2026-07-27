use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view,
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicAdmissionHandoffVerifier,
    EconomicContentV1, EconomicEffectCancellationProofVerifier, EconomicEffectDispatchCommitV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicNoEffectKindV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchor, EconomicStateAnchorError, EconomicStateAnchorPins,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, EconomicStateReadQuery,
    EconomicStateTransitionV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicEffectDispatch, VerifiedEconomicEffectDispatchAdvance,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_kernel::admission_operation::{
    AdmissionAttachment, AdmissionDigest, AdmissionIdentifier, AdmissionOperationBindingInputV1,
    AdmissionOperationBindingV1, AdmissionOperationCommand, AdmissionOperationKind,
    AdmissionOperationStore, AdmissionOperationV1, AdmissionParticipantRequirements,
    AdmissionRequestBindingV1, AuthenticatedRequestNamespace, ProviderAttemptBindingV1,
    QualifiedAdmissionOperationStoreExt, SideEffectClass,
};
use chio_kernel::ReceiptStore;
use chio_store_sqlite::{
    SqliteAdmissionOperationStore, SqliteAuthorityStore, SqliteEconomicStateCache,
};
use serde_json::json;
use tempfile::TempDir;

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Fixture {
    _temp: TempDir,
    _authority: SqliteAuthorityStore,
    cache: SqliteEconomicStateCache,
    operations: Arc<SqliteAdmissionOperationStore>,
    fence: StoreMutationFence,
}

fn fixture() -> Fixture {
    let temp = tempfile::tempdir().expect("tempdir");
    crate::create_private_directory(temp.path()).expect("secure database parent");
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    crate::create_private_directory(&lock_root).expect("create lock root");
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision authority");
    let authority =
        SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open authority");
    let fence = authority.mutation_fence();
    let cache = authority.economic_state_cache();
    let operations = Arc::new(authority.admission_operation_store());
    Fixture {
        _temp: temp,
        _authority: authority,
        cache,
        operations,
        fence,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn digest(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

fn pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: Keypair::from_seed(&[0x41; 32]).public_key(),
    }
}

fn key() -> EconomicResourceKeyV1 {
    EconomicResourceKeyV1 {
        resource_family: "clearing_round".to_owned(),
        scope_id: "market-1".to_owned(),
        resource_id: "round-1".to_owned(),
    }
}

fn head() -> TestResult<EconomicResourceHeadV1> {
    let state = EconomicContentV1::Inline {
        value: json!({"roundId": "round-1", "state": "open"}),
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: 1,
        lifecycle_state: "open".to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: 100,
        predecessor_digest: None,
    })
}

fn signed_view(
    checkpoint_sequence: u64,
    checkpoint_digest: String,
    heads: Vec<EconomicResourceHeadV1>,
    absent_resource_keys: Vec<EconomicResourceKeyV1>,
) -> TestResult<EconomicStateAnchorViewV1> {
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
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at: 100 + checkpoint_sequence,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&Keypair::from_seed(&[0x41; 32]))?;
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

impl EconomicEffectCancellationProofVerifier for DirectVerifier {
    fn verify_cancellation(
        &self,
        _current: &EconomicEffectSlotV1,
        next: &EconomicEffectSlotV1,
    ) -> Result<EconomicNoEffectKindV1, EconomicStateAnchorError> {
        match next.terminal.as_ref() {
            Some(EconomicEffectTerminalV1::NoEffect { kind, .. }) => Ok(*kind),
            _ => Err(EconomicStateAnchorError::EffectCancellationRejected(
                "fixture cancellation kind is missing",
            )),
        }
    }
}

impl EconomicAdmissionHandoffVerifier for DirectVerifier {
    fn verify_operation_active(&self, _operation_id: &str) -> Result<(), EconomicStateAnchorError> {
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

fn verified_advance() -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)>
{
    verified_advance_for_operation(None)
}

fn verified_advance_for_operation(
    operation_id: Option<String>,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let resource_head = head()?;
    let current = verify_economic_state_view(
        signed_view(1, digest("checkpoint-1"), Vec::new(), vec![key()])?,
        &pins(),
    )?;
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
            resource_key: key(),
            expected_head_digest: None,
            next_head: resource_head.clone(),
            transition_proof_digest: digest("transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id,
        issued_at: 101,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    let advance = verify_economic_state_batch_advance(&current, batch, &pins(), &DirectVerifier)?;
    let committed = verify_economic_state_view(
        signed_view(
            2,
            advance.batch().checkpoint_digest.clone(),
            vec![resource_head],
            Vec::new(),
        )?,
        &pins(),
    )?;
    Ok((advance, committed))
}

fn verified_advance_with_committed_base_effect(
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
) -> TestResult<VerifiedEconomicStateBatchAdvance> {
    let mut slot = prepared_effect_slot(
        operation,
        fence,
        EconomicAdmissionHandoffStateV1::DispatchCommitted,
        6,
    )?;
    slot.state = EconomicEffectStateV1::DispatchCommitted;
    slot.validate()?;
    let effect_state = EconomicContentV1::Inline {
        value: serde_json::to_value(&slot)?,
    };
    let effect_head = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: slot.resource_head_key(),
        head_version: 1,
        resource_version: 1,
        lifecycle_fence: operation.coordinator_lease_epoch(),
        lifecycle_state: "dispatch_committed".to_owned(),
        state_digest: effect_state.digest()?,
        state: effect_state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: slot.frost.clone(),
        terminal_result: None,
        trusted_clock_high_water: 100,
        predecessor_digest: None,
    };
    effect_head.validate()?;
    let resource_head = head()?;
    let current = verify_economic_state_view(
        signed_view(
            1,
            digest("checkpoint-with-committed-effect"),
            vec![effect_head],
            vec![key()],
        )?,
        &pins(),
    )?;
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
            resource_key: key(),
            expected_head_digest: None,
            next_head: resource_head,
            transition_proof_digest: digest("transition-proof"),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(operation.binding().operation_id().as_str().to_owned()),
        issued_at: 101,
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[0x41; 32]))?;
    Ok(verify_economic_state_batch_advance(
        &current,
        batch,
        &pins(),
        &DirectVerifier,
    )?)
}

fn identifier(field: &'static str, value: &str) -> AdmissionIdentifier {
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
    .expect("system time fits u64")
}

fn prepared_economic_operation(
    fence: &StoreMutationFence,
    request_id: &str,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "economic-recovery-test",
    ))
    .expect("namespace");
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedEconomicMutation,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", "economic-recovery-capability"),
        authorization_capability_hash: admission_digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("immutable_request_hash", 'b'),
            AdmissionParticipantRequirements::NONE,
        )
        .expect("request binding"),
        policy_hash: admission_digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("operation binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

fn prepared_dispatch_operation(
    fence: &StoreMutationFence,
    request_id: &str,
) -> AdmissionOperationV1 {
    prepared_dispatch_operation_with_requirements(
        fence,
        request_id,
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
    )
}

fn prepared_dispatch_operation_with_requirements(
    fence: &StoreMutationFence,
    request_id: &str,
    requirements: AdmissionParticipantRequirements,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "economic-recovery-test",
    ))
    .expect("namespace");
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: identifier("request_id", request_id),
        capability_id: identifier("capability_id", "economic-recovery-capability"),
        authorization_capability_hash: admission_digest("authorization_capability_hash", 'a'),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("immutable_request_hash", 'b'),
            requirements,
        )
        .expect("request binding"),
        policy_hash: admission_digest("policy_hash", 'c'),
        effect_class: SideEffectClass::Monetary,
    })
    .expect("operation binding");
    AdmissionOperationV1::prepare(binding, fence.owner_epoch).expect("prepared operation")
}

fn prepared_effect_slot(
    operation: &AdmissionOperationV1,
    fence: &StoreMutationFence,
    handoff_state: EconomicAdmissionHandoffStateV1,
    handoff_version: u64,
) -> TestResult<EconomicEffectSlotV1> {
    let binding = operation.binding();
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: key(),
        operation_id: binding.operation_id().as_str().to_owned(),
        effect_kind: "settlement_dispatch".to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: binding.request_namespace_digest().as_str().to_owned(),
            request_id: binding.request_id().as_str().to_owned(),
            request_binding_digest: binding.request_binding_hash().as_str().to_owned(),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: handoff_state,
            operation_version: handoff_version,
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: fence.clone(),
        },
        target: EconomicEffectTargetV1 {
            target_id: "settlement-rail".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("target-qualification"),
        },
        action_digest: digest("effect-action"),
        parameters_digest: binding.action_parameter_hash().as_str().to_owned(),
        resource_head_digest: digest("resource-head"),
        frost: None,
        idempotency_key: digest("idempotency-key"),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    slot.validate()?;
    Ok(slot)
}

fn advance_operation(
    operations: &dyn AnchoredAdmissionProjectionStore,
    operation: &AdmissionOperationV1,
    claimant: &AdmissionIdentifier,
    fence: &StoreMutationFence,
    next_state: AdmissionOperationState,
    trusted_now_unix_ms: u64,
) -> TestResult<AdmissionOperationV1> {
    advance_operation_with_attachments(
        operations,
        operation,
        claimant,
        fence,
        next_state,
        Vec::new(),
        trusted_now_unix_ms,
    )
}

fn advance_operation_with_attachments(
    operations: &dyn AnchoredAdmissionProjectionStore,
    operation: &AdmissionOperationV1,
    claimant: &AdmissionIdentifier,
    fence: &StoreMutationFence,
    next_state: AdmissionOperationState,
    attachments: Vec<AdmissionAttachment>,
    trusted_now_unix_ms: u64,
) -> TestResult<AdmissionOperationV1> {
    let lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        claimant,
        trusted_now_unix_ms,
        trusted_now_unix_ms + 1_000,
        fence,
    )?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(next_state),
        None,
        None,
    )?;
    Ok(operations
        .compare_and_swap(&command, trusted_now_unix_ms + 1)?
        .into_operation())
}

fn stage_bounded_operation(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    claimant: &AdmissionIdentifier,
    stage_at_unix_ms: u64,
    not_after_unix_ms: u64,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let lease = fixture.operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        claimant,
        stage_at_unix_ms - 1,
        stage_at_unix_ms + 1_000,
        &fixture.fence,
    )?;
    let advance = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    fixture.cache.stage_batch(
        &advance.0,
        Some(
            chio_store_sqlite::EconomicOperationStageContext::new(operation, &lease)
                .with_not_after_unix_ms(not_after_unix_ms)?,
        ),
        &fixture.fence,
        stage_at_unix_ms,
    )?;
    Ok(advance)
}

#[derive(Default)]
struct FixtureAnchor {
    reads: Mutex<VecDeque<Result<VerifiedEconomicStateView, EconomicStateAnchorError>>>,
    checkpoint_reads: Mutex<VecDeque<Result<VerifiedEconomicStateView, EconomicStateAnchorError>>>,
    commits: Mutex<VecDeque<Result<VerifiedEconomicStateView, EconomicStateAnchorError>>>,
    cas_calls: AtomicUsize,
}

impl EconomicStateAnchor for FixtureAnchor {
    fn read_state(
        &self,
        _query: &EconomicStateReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        lock(&self.reads).pop_front().ok_or_else(|| {
            EconomicStateAnchorError::Unavailable("fixture read is missing".to_owned())
        })?
    }

    fn read_checkpoint_state(
        &self,
        _query: &chio_core::economic_continuity::EconomicCheckpointReadQuery,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        lock(&self.checkpoint_reads).pop_front().ok_or_else(|| {
            EconomicStateAnchorError::Unavailable("fixture checkpoint read is missing".to_owned())
        })?
    }

    fn compare_and_swap_batch(
        &self,
        _advance: chio_core::economic_continuity::QualifiedGenericEconomicStateBatchAdvance<'_>,
    ) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
        self.cas_calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.commits).pop_front().ok_or_else(|| {
            EconomicStateAnchorError::Unavailable("fixture CAS is missing".to_owned())
        })?
    }

    fn compare_and_swap_effect_dispatch(
        &self,
        _advance: VerifiedEconomicEffectDispatchAdvance,
    ) -> Result<VerifiedEconomicEffectDispatch, EconomicStateAnchorError> {
        let _ = core::mem::size_of::<EconomicEffectDispatchCommitV1>();
        Err(EconomicStateAnchorError::Unavailable(
            "effect dispatch is not used by this fixture".to_owned(),
        ))
    }
}

fn recovery(fixture: &Fixture, anchor: Arc<FixtureAnchor>) -> EconomicStateRecovery {
    EconomicStateRecovery::new(
        fixture.cache.clone(),
        anchor,
        fixture.operations.clone(),
        Arc::new(DirectVerifier),
        Arc::new(DirectVerifier),
        Arc::new(DirectVerifier),
        pins(),
        fixture.fence.clone(),
        AdmissionIdentifier::try_new("claimant_id", "economic-recovery").expect("claimant"),
        Duration::from_secs(30),
    )
    .expect("recovery")
}

#[test]
fn unanchored_stage_retries_one_cas_then_finalizes() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    lock(&anchor.commits).push_back(Ok(committed));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, 1_001)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
    Ok(())
}

#[test]
fn lost_anchor_cas_acknowledgement_recovers_the_exact_committed_batch() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    lock(&anchor.commits).push_back(Err(EconomicStateAnchorError::Unavailable(
        "commit acknowledgement was lost".to_owned(),
    )));
    lock(&anchor.reads).push_back(Ok(committed));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, 1_001)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
    Ok(())
}

#[test]
fn anchor_advanced_marker_resumes_only_local_finalization() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let advanced = fixture.cache.record_anchor_advanced(
        &advance,
        &committed,
        &pins(),
        &fixture.fence,
        1_001,
    )?;
    assert_eq!(
        advanced.status(),
        chio_store_sqlite::EconomicStateStageStatus::EconomicAnchorAdvanced
    );
    let anchor = Arc::new(FixtureAnchor::default());
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, 1_002)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
    Ok(())
}

#[test]
fn bounded_stage_retries_before_expiry() -> TestResult {
    let fixture = fixture();
    let operation = prepared_dispatch_operation(&fixture.fence, "bounded-before-expiry");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    let (advance, committed) =
        stage_bounded_operation(&fixture, &operation, &claimant, now + 2, now + 10)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    lock(&anchor.commits).push_back(Ok(committed));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, now + 9)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 1);
    let retained = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(retained.state(), AdmissionOperationState::Prepared);
    Ok(())
}

#[test]
fn bounded_stage_compensates_at_the_exact_expiry_boundary() -> TestResult {
    let fixture = fixture();
    let operation = prepared_dispatch_operation(&fixture.fence, "bounded-at-expiry");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    let not_after = now + 3;
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    let (advance, _) =
        stage_bounded_operation(&fixture, &operation, &claimant, now + 2, not_after)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, not_after)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Discarded(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    let compensated = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(
        compensated.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    Ok(())
}

#[test]
fn bounded_stage_finalizes_an_observed_anchor_after_expiry() -> TestResult {
    let fixture = fixture();
    let operation = prepared_dispatch_operation(&fixture.fence, "bounded-anchored-expiry");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    let not_after = now + 3;
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    let (advance, committed) =
        stage_bounded_operation(&fixture, &operation, &claimant, now + 2, not_after)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(committed));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, not_after + 1)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    let retained = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(retained.state(), AdmissionOperationState::Prepared);
    Ok(())
}

#[test]
fn bounded_stage_quarantines_postdispatch_work_after_expiry() -> TestResult {
    let fixture = fixture();
    let mut operation = prepared_dispatch_operation(&fixture.fence, "bounded-postdispatch-expiry");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    operation = advance_operation_with_attachments(
        fixture.operations.as_ref(),
        &operation,
        &claimant,
        &fixture.fence,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(
            ProviderAttemptBindingV1 {
                operation_id: operation.binding().operation_id().as_str().to_owned(),
                attempt_id: "bounded-stage-attempt".to_owned(),
                transport_id: "bounded-stage-transport".to_owned(),
                transport_key_epoch: 1,
            },
        )],
        now + 2,
    )?;
    operation = advance_operation_with_attachments(
        fixture.operations.as_ref(),
        &operation,
        &claimant,
        &fixture.fence,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(identifier(
            "budget_hold_id",
            "bounded-stage-hold",
        ))],
        now + 4,
    )?;
    for (index, state) in [
        AdmissionOperationState::ReadyToDispatch,
        AdmissionOperationState::CapturePending,
        AdmissionOperationState::DispatchCommitted,
    ]
    .into_iter()
    .enumerate()
    {
        operation = advance_operation(
            fixture.operations.as_ref(),
            &operation,
            &claimant,
            &fixture.fence,
            state,
            now + 6 + u64::try_from(index)? * 2,
        )?;
    }
    let not_after = now + 13;
    let (advance, _) =
        stage_bounded_operation(&fixture, &operation, &claimant, now + 12, not_after)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, not_after)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Quarantined(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    let retained = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(retained.state(), AdmissionOperationState::DispatchCommitted);
    Ok(())
}

#[test]
fn bounded_stage_expired_anchor_read_outage_stays_pending() -> TestResult {
    let fixture = fixture();
    let operation = prepared_dispatch_operation(&fixture.fence, "bounded-expired-outage");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    let not_after = now + 3;
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    let (advance, _) =
        stage_bounded_operation(&fixture, &operation, &claimant, now + 2, not_after)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Err(EconomicStateAnchorError::Unavailable(
        "anchor read unavailable".to_owned(),
    )));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, not_after)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Pending(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    let retained = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(retained.state(), AdmissionOperationState::Prepared);
    Ok(())
}

#[test]
fn bounded_stage_expired_divergent_predecessor_quarantines() -> TestResult {
    let fixture = fixture();
    let operation = prepared_dispatch_operation(&fixture.fence, "bounded-expired-divergent");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    let not_after = now + 3;
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    let (advance, _) =
        stage_bounded_operation(&fixture, &operation, &claimant, now + 2, not_after)?;
    let divergent = verify_economic_state_view(
        signed_view(1, digest("divergent-checkpoint"), Vec::new(), vec![key()])?,
        &pins(),
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(divergent));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, not_after)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Quarantined(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    let retained = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(retained.state(), AdmissionOperationState::Prepared);
    Ok(())
}

#[test]
fn bounded_stage_expired_committed_effect_quarantines() -> TestResult {
    let fixture = fixture();
    let operation = prepared_dispatch_operation(&fixture.fence, "bounded-expired-effect");
    let claimant = identifier("claimant_id", "bounded-stage-owner");
    let now = now_ms();
    let not_after = now + 3;
    fixture.operations.begin(&operation, &fixture.fence, now)?;
    let lease = fixture.operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &claimant,
        now + 1,
        now + 1_002,
        &fixture.fence,
    )?;
    let advance = verified_advance_with_committed_base_effect(&operation, &fixture.fence)?;
    fixture.cache.stage_batch(
        &advance,
        Some(
            chio_store_sqlite::EconomicOperationStageContext::new(&operation, &lease)
                .with_not_after_unix_ms(not_after)?,
        ),
        &fixture.fence,
        now + 2,
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, not_after)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Quarantined(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    let retained = fixture
        .operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert_eq!(retained.state(), AdmissionOperationState::Prepared);
    Ok(())
}

#[test]
fn bounded_stage_expired_without_operation_binding_quarantines() -> TestResult {
    let fixture = fixture();
    let (advance, _) = verified_advance()?;
    let stage = fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let recovery = recovery(&fixture, Arc::new(FixtureAnchor::default()));

    let outcome = recovery.resolve_expired_unanchored_stage(stage, 1_001)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Quarantined(_)));
    Ok(())
}

#[test]
fn old_same_epoch_snapshot_cannot_erase_an_economic_stage() -> TestResult {
    let temp = tempfile::tempdir()?;
    crate::create_private_directory(temp.path())?;
    let database = temp.path().join("authority.db");
    let snapshot = temp.path().join("before-economic-stage.db");
    let lock_root = temp.path().join("locks");
    crate::create_private_directory(&lock_root)?;
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    fs::copy(&database, &snapshot)?;
    let fence = authority.mutation_fence();
    let cache = authority.economic_state_cache();
    let (advance, _) = verified_advance()?;
    cache.stage_batch(&advance, None, &fence, now_ms())?;
    drop(cache);
    drop(authority);

    let mut input = File::open(&snapshot)?;
    let mut output = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&database)?;
    io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", database.display()));
    }
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    Ok(())
}

#[test]
fn anchored_ahead_recovery_uses_retained_checkpoint_without_replaying_cas() -> TestResult {
    let fixture = fixture();
    let (advance, committed) = verified_advance()?;
    fixture
        .cache
        .stage_batch(&advance, None, &fixture.fence, 1_000)?;
    let ahead = verify_economic_state_view(
        signed_view(3, digest("checkpoint-3"), vec![head()?], Vec::new())?,
        &pins(),
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(ahead));
    lock(&anchor.checkpoint_reads).push_back(Ok(committed));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, 1_001)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Finalized(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.cache.load_finalized_head(&key())?, Some(head()?));
    Ok(())
}

#[test]
fn operation_version_race_discards_unanchored_stage_without_cas() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_economic_operation(&fixture.fence, "operation-race");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let stage_claimant = identifier("claimant_id", "stage-owner");
    let stage_lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &stage_claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    fixture.cache.stage_batch(
        &advance,
        Some(chio_store_sqlite::EconomicOperationStageContext::new(
            &operation,
            &stage_lease,
        )),
        &fixture.fence,
        now + 2,
    )?;
    advance_operation(
        &operations,
        &operation,
        &stage_claimant,
        &fixture.fence,
        AdmissionOperationState::MutationReady,
        now + 3,
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    let recovery = recovery(&fixture, anchor.clone());

    let outcome = recovery.recover_stage(&advance.batch().batch_id, now + 5)?;
    assert!(matches!(outcome, EconomicRecoveryOutcome::Discarded(_)));
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    assert!(fixture.cache.load_finalized_head(&key())?.is_none());
    Ok(())
}

#[test]
fn compensation_winner_discards_the_unanchored_stage_before_anchor_cas() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_dispatch_operation(&fixture.fence, "compensation-wins");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let stage_claimant = identifier("claimant_id", "stage-owner");
    let stage_lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &stage_claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    fixture.cache.stage_batch(
        &advance,
        Some(chio_store_sqlite::EconomicOperationStageContext::new(
            &operation,
            &stage_lease,
        )),
        &fixture.fence,
        now + 2,
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    let recovery = recovery(&fixture, anchor.clone());

    let compensated =
        recovery.compensate_unanchored_stage_before_dispatch(&advance.batch().batch_id, now + 3)?;

    assert_eq!(
        compensated.terminal().state,
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(
        compensated.stage().status(),
        EconomicStateStageStatus::Discarded
    );
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        recovery.recover_stage(&advance.batch().batch_id, now + 4)?,
        EconomicRecoveryOutcome::Discarded(_)
    ));
    Ok(())
}

#[test]
fn recovery_winner_rejects_late_pre_dispatch_compensation() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_dispatch_operation(&fixture.fence, "recovery-wins");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let stage_claimant = identifier("claimant_id", "stage-owner");
    let stage_lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &stage_claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, committed) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    fixture.cache.stage_batch(
        &advance,
        Some(chio_store_sqlite::EconomicOperationStageContext::new(
            &operation,
            &stage_lease,
        )),
        &fixture.fence,
        now + 2,
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    lock(&anchor.commits).push_back(Ok(committed));
    let recovery = recovery(&fixture, anchor.clone());

    assert!(matches!(
        recovery.recover_stage(&advance.batch().batch_id, now + 3)?,
        EconomicRecoveryOutcome::Finalized(_)
    ));
    assert!(recovery
        .compensate_unanchored_stage_before_dispatch(&advance.batch().batch_id, now + 4)
        .is_err());
    let retained = operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;
    assert!(!retained.state().is_terminal());
    assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn compensation_and_unanchored_recovery_have_exactly_one_lifecycle_winner() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_dispatch_operation(&fixture.fence, "concurrent-race");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let stage_claimant = identifier("claimant_id", "stage-owner");
    let stage_lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &stage_claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, committed) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    fixture.cache.stage_batch(
        &advance,
        Some(chio_store_sqlite::EconomicOperationStageContext::new(
            &operation,
            &stage_lease,
        )),
        &fixture.fence,
        now + 2,
    )?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    lock(&anchor.commits).push_back(Ok(committed));
    let recovery = Arc::new(recovery(&fixture, anchor.clone()));
    let barrier = Arc::new(Barrier::new(3));
    let batch_id = advance.batch().batch_id.clone();

    let compensation = {
        let recovery = recovery.clone();
        let barrier = barrier.clone();
        let batch_id = batch_id.clone();
        std::thread::spawn(move || {
            barrier.wait();
            recovery.compensate_unanchored_stage_before_dispatch(&batch_id, now + 3)
        })
    };
    let stage_recovery = {
        let recovery = recovery.clone();
        let barrier = barrier.clone();
        let batch_id = batch_id.clone();
        std::thread::spawn(move || {
            barrier.wait();
            recovery.recover_stage(&batch_id, now + 4)
        })
    };
    barrier.wait();
    let compensation = compensation.join().map_err(|_| "compensation panicked")?;
    let stage_recovery = stage_recovery.join().map_err(|_| "recovery panicked")??;
    let retained = operations
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("operation disappeared")?;

    match (compensation, stage_recovery) {
        (Ok(compensated), EconomicRecoveryOutcome::Discarded(discarded)) => {
            assert_eq!(
                compensated.terminal().state,
                AdmissionOperationState::CompensatedBeforeDispatch
            );
            assert_eq!(discarded.status(), EconomicStateStageStatus::Discarded);
            assert!(retained.state().is_terminal());
            assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 0);
        }
        (Err(_), EconomicRecoveryOutcome::Finalized(finalized)) => {
            assert_eq!(finalized.status(), EconomicStateStageStatus::DbFinalized);
            assert!(!retained.state().is_terminal());
            assert_eq!(anchor.cas_calls.load(Ordering::SeqCst), 1);
        }
        (compensation, recovery) => {
            return Err(format!(
                "invalid race result: compensation={compensation:?}, recovery={recovery:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn compensation_recovery_discards_a_stage_after_terminal_commit_ack_loss() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let operation = prepared_dispatch_operation(&fixture.fence, "compensation-ack-loss");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let stage_claimant = identifier("claimant_id", "stage-owner");
    let stage_lease = operations.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &stage_claimant,
        now + 1,
        now + 1_001,
        &fixture.fence,
    )?;
    let (advance, _) = verified_advance_for_operation(Some(
        operation.binding().operation_id().as_str().to_owned(),
    ))?;
    fixture.cache.stage_batch(
        &advance,
        Some(chio_store_sqlite::EconomicOperationStageContext::new(
            &operation,
            &stage_lease,
        )),
        &fixture.fence,
        now + 2,
    )?;
    let projection = verified_pre_dispatch_compensation_projection(
        &operation,
        AdmissionProjectionContext {
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.replay_key().request_id,
            expected_operation_version: operation.version(),
            trusted_time_unix_ms: now + 3,
            coordinator_lease_id: stage_lease.coordinator_lease_id().clone(),
            coordinator_lease_epoch: operation.coordinator_lease_epoch(),
            store_fence: fixture.fence.clone(),
        },
    )?;
    let terminal = operations.commit_admission_projection(&projection)?;
    let anchor = Arc::new(FixtureAnchor::default());
    lock(&anchor.reads).push_back(Ok(advance.current().clone()));
    let recovery = recovery(&fixture, anchor);

    let recovered =
        recovery.compensate_unanchored_stage_before_dispatch(&advance.batch().batch_id, now + 4)?;

    assert_eq!(recovered.terminal(), &terminal);
    assert_eq!(
        recovered.stage().status(),
        EconomicStateStageStatus::Discarded
    );
    Ok(())
}

#[test]
fn handoff_verifier_requires_exact_submitted_state_version_and_store_fence() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let mut operation = prepared_economic_operation(&fixture.fence, "handoff");
    let now = now_ms();
    operations.begin(&operation, &fixture.fence, now)?;
    let claimant = identifier("claimant_id", "handoff-owner");
    operation = advance_operation(
        &operations,
        &operation,
        &claimant,
        &fixture.fence,
        AdmissionOperationState::MutationReady,
        now + 1,
    )?;
    operation = advance_operation(
        &operations,
        &operation,
        &claimant,
        &fixture.fence,
        AdmissionOperationState::MutationSubmitted,
        now + 3,
    )?;
    let verifier = QualifiedEconomicAdmissionHandoffVerifier::new(
        fixture.operations.clone(),
        fixture.fence.clone(),
    );
    let handoff = EconomicAdmissionHandoffV1 {
        state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
        operation_version: operation.version(),
        lifecycle_fence: operation.coordinator_lease_epoch(),
        store_fence: fixture.fence.clone(),
    };

    verifier.verify_handoff(operation.binding().operation_id().as_str(), &handoff)?;
    let mut stale = handoff.clone();
    stale.operation_version -= 1;
    assert!(verifier
        .verify_handoff(operation.binding().operation_id().as_str(), &stale)
        .is_err());
    let mut wrong_lease = handoff;
    wrong_lease.store_fence.lease_id = "different-lease".to_owned();
    assert!(verifier
        .verify_handoff(operation.binding().operation_id().as_str(), &wrong_lease)
        .is_err());
    Ok(())
}

#[test]
fn prepared_effect_verifier_binds_operation_request_handoff_and_fences() -> TestResult {
    let fixture = fixture();
    let operations = fixture._authority.admission_operation_store();
    let mut mutation = prepared_economic_operation(&fixture.fence, "prepared-mutation");
    let dispatch = prepared_dispatch_operation(&fixture.fence, "prepared-dispatch");
    let approval = prepared_dispatch_operation_with_requirements(
        &fixture.fence,
        "prepared-approval-dispatch",
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            approval: true,
            ..AdmissionParticipantRequirements::NONE
        },
    );
    let now = now_ms();
    operations.begin(&mutation, &fixture.fence, now)?;
    operations.begin(&dispatch, &fixture.fence, now + 1)?;
    operations.begin(&approval, &fixture.fence, now + 2)?;
    let verifier = QualifiedEconomicAdmissionHandoffVerifier::new(
        fixture.operations.clone(),
        fixture.fence.clone(),
    );
    let mutation_slot = prepared_effect_slot(
        &mutation,
        &fixture.fence,
        EconomicAdmissionHandoffStateV1::MutationSubmitted,
        3,
    )?;
    verifier.verify_prepared_effect(&mutation_slot)?;
    let dispatch_slot = prepared_effect_slot(
        &dispatch,
        &fixture.fence,
        EconomicAdmissionHandoffStateV1::DispatchCommitted,
        6,
    )?;
    verifier.verify_prepared_effect(&dispatch_slot)?;
    let approval_slot = prepared_effect_slot(
        &approval,
        &fixture.fence,
        EconomicAdmissionHandoffStateV1::DispatchCommitted,
        7,
    )?;
    verifier.verify_prepared_effect(&approval_slot)?;
    let mut stale_approval_slot = approval_slot;
    stale_approval_slot.admission_handoff.operation_version = 6;
    assert!(verifier
        .verify_prepared_effect(&stale_approval_slot)
        .is_err());

    let mut wrong_request = mutation_slot.clone();
    wrong_request.request.request_binding_digest = digest("different-request");
    assert!(verifier.verify_prepared_effect(&wrong_request).is_err());
    let mut wrong_parameters = mutation_slot.clone();
    wrong_parameters.parameters_digest = digest("different-parameters");
    assert!(verifier.verify_prepared_effect(&wrong_parameters).is_err());
    let mut wrong_version = mutation_slot.clone();
    wrong_version.admission_handoff.operation_version += 1;
    assert!(verifier.verify_prepared_effect(&wrong_version).is_err());
    let mut wrong_fence = mutation_slot.clone();
    wrong_fence.admission_handoff.lifecycle_fence += 1;
    assert!(verifier.verify_prepared_effect(&wrong_fence).is_err());

    mutation = advance_operation(
        &operations,
        &mutation,
        &identifier("claimant_id", "prepared-effect-owner"),
        &fixture.fence,
        AdmissionOperationState::MutationReady,
        now + 5,
    )?;
    assert_eq!(mutation.state(), AdmissionOperationState::MutationReady);
    assert!(verifier.verify_prepared_effect(&mutation_slot).is_err());
    Ok(())
}

struct QualifiedIdempotentTarget;

impl EconomicIdempotentTargetVerifier for QualifiedIdempotentTarget {
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

struct RejectedIdempotentTarget;

impl EconomicIdempotentTargetVerifier for RejectedIdempotentTarget {
    fn verify_qualification(
        &self,
        _target: &EconomicEffectTargetV1,
        _idempotency_key: &str,
    ) -> Result<(), EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::IdempotentRecoveryRejected)
    }
}

fn committed_effect_slot() -> TestResult<EconomicEffectSlotV1> {
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        resource_key: key(),
        operation_id: digest("effect-operation"),
        effect_kind: "settlement_dispatch".to_owned(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("request-namespace"),
            request_id: "request-1".to_owned(),
            request_binding_digest: digest("request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
            operation_version: 3,
            lifecycle_fence: 1,
            store_fence: StoreMutationFence {
                store_uuid: "store-1".to_owned(),
                lease_id: "lease-1".to_owned(),
                owner_epoch: 1,
            },
        },
        target: EconomicEffectTargetV1 {
            target_id: "settlement-rail".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("target-qualification"),
        },
        action_digest: digest("effect-action"),
        parameters_digest: digest("effect-parameters"),
        resource_head_digest: digest("resource-head"),
        frost: None,
        idempotency_key: digest("idempotency-key"),
        state: EconomicEffectStateV1::DispatchCommitted,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    slot.validate()?;
    Ok(slot)
}

#[test]
fn committed_effect_recovery_never_returns_invocation_authority_without_qualification() -> TestResult
{
    let slot = committed_effect_slot()?;
    let locked = qualify_committed_effect_recovery(&slot, None, None)?;
    let EconomicEffectRecoveryDecision::LockedUnknown(locked) = locked else {
        return Err("unqualified recovery returned authority".into());
    };
    assert_eq!(locked.next_slot().state, EconomicEffectStateV1::Unknown);

    let rejected = qualify_committed_effect_recovery(&slot, None, Some(&RejectedIdempotentTarget))?;
    assert!(matches!(
        rejected,
        EconomicEffectRecoveryDecision::LockedUnknown(_)
    ));
    let qualified =
        qualify_committed_effect_recovery(&slot, None, Some(&QualifiedIdempotentTarget))?;
    assert!(matches!(
        qualified,
        EconomicEffectRecoveryDecision::IdempotentRetry(_)
    ));
    Ok(())
}
