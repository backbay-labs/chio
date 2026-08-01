use super::*;

use std::sync::Mutex;

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    metadata::GuardEvidence,
};
use chio_core_types::{provider_attempt::ProviderAttemptBindingV1, StoreMutationFence};
use serde_json::{json, Map};

use crate::admission_operation::{
    qualify_recovery_claim_for_test, AdmissionAttachment, AdmissionCommandResult,
    AdmissionCompensationStatus, AdmissionDigest, AdmissionIdentifier,
    AdmissionOperationBindingInputV1, AdmissionOperationBindingV1, AdmissionOperationCommand,
    AdmissionOperationId, AdmissionOperationKind, AdmissionOperationState,
    AdmissionParticipantRequirements, AdmissionProjectionContext, AdmissionReceiptMetadataV1,
    AdmissionReceiptSchema, AdmissionRecoveryLease, AdmissionRequestBindingV1,
    AuthenticatedRequestNamespace, SideEffectClass, UntrustedAdmissionRecoveryClaim,
    VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
};

fn sha(label: &str) -> String {
    sha256_hex(label.as_bytes())
}

pub(super) fn id(value: &str) -> AdmissionIdentifier {
    AdmissionIdentifier::try_new("test_identifier", value).unwrap()
}

pub(super) fn admission_digest(value: &str) -> AdmissionDigest {
    AdmissionDigest::try_new("test_digest", sha(value)).unwrap()
}

pub(super) fn fence() -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "store-1".to_owned(),
        lease_id: "store-lease-1".to_owned(),
        owner_epoch: 9,
    }
}

pub(super) fn successor_fence(owner_epoch: u64) -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "store-1".to_owned(),
        lease_id: format!("store-lease-{owner_epoch}"),
        owner_epoch,
    }
}

pub(super) fn advance(
    operation: &AdmissionOperationV1,
    next: AdmissionOperationState,
    attachments: Vec<AdmissionAttachment>,
) -> AdmissionOperationV1 {
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding().operation_id().clone(),
        id("claimant-1"),
        id("coordinator-lease-1"),
        operation.coordinator_lease_epoch(),
        operation.version(),
        10_000,
        fence(),
    )
    .unwrap();
    let lease = qualify_recovery_claim_for_test(operation, claim, 100, &fence()).unwrap();
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(next),
        None,
        None,
    )
    .unwrap();
    match operation.apply_command(&command, 100).unwrap() {
        AdmissionCommandResult::Applied(operation) => operation,
        AdmissionCommandResult::Idempotent(_) => panic!("test transition was not applied"),
    }
}

pub(super) fn provider_attempt(
    operation: &AdmissionOperationV1,
    attempt_id: &str,
) -> ProviderAttemptBindingV1 {
    ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: attempt_id.to_owned(),
        transport_id: "qualified-release-provider".to_owned(),
        transport_key_epoch: 7,
    }
}

fn prepared_operation_with_requirements(
    request_id: &str,
    requirements: AdmissionParticipantRequirements,
) -> AdmissionOperationV1 {
    let namespace = AuthenticatedRequestNamespace::for_local_system(id("coordinator-1")).unwrap();
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace,
        request_id: id(request_id),
        capability_id: id("capability-1"),
        authorization_capability_hash: admission_digest("authorization"),
        request_binding: AdmissionRequestBindingV1::new(
            AdmissionDigest::try_new("immutable_request_hash", sha256_hex(b"{}")).unwrap(),
            requirements,
        )
        .unwrap(),
        policy_hash: admission_digest("policy"),
        effect_class: SideEffectClass::SideEffecting,
    })
    .unwrap();
    AdmissionOperationV1::prepare(binding, 7).unwrap()
}

pub(super) fn prepared_operation(request_id: &str) -> AdmissionOperationV1 {
    prepared_operation_with_requirements(
        request_id,
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
    )
}

pub(super) fn committed_operation(request_id: &str) -> AdmissionOperationV1 {
    committed_broker_operation(request_id, "attempt-1")
}

pub(super) fn committed_broker_operation(
    request_id: &str,
    attempt_id: &str,
) -> AdmissionOperationV1 {
    let prepared = prepared_operation_with_requirements(
        request_id,
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
    );
    let broker = advance(
        &prepared,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &prepared, attempt_id,
        ))],
    );
    let budget = advance(
        &broker,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(id("hold-1"))],
    );
    let ready = advance(&budget, AdmissionOperationState::ReadyToDispatch, vec![]);
    let capture = advance(&ready, AdmissionOperationState::CapturePending, vec![]);
    advance(&capture, AdmissionOperationState::DispatchCommitted, vec![])
}

pub(super) fn projection_context(operation: &AdmissionOperationV1) -> AdmissionProjectionContext {
    let store_fence = operation
        .dispatch_commit()
        .map_or_else(fence, |commit| commit.store_fence.clone());
    AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: 1_000,
        coordinator_lease_id: id("coordinator-lease-1"),
        coordinator_lease_epoch: operation.coordinator_lease_epoch(),
        store_fence,
    }
}

pub(super) fn projection_context_under(
    operation: &AdmissionOperationV1,
    store_fence: StoreMutationFence,
) -> AdmissionProjectionContext {
    AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: 1_000,
        coordinator_lease_id: id("coordinator-lease-1"),
        coordinator_lease_epoch: operation.coordinator_lease_epoch(),
        store_fence,
    }
}

fn raw_for(operation: &AdmissionOperationV1, output: Value) -> RawInvocationOutcomeV1 {
    raw_for_attempt(operation, "attempt-1", output).unwrap()
}

fn stream_limits() -> InvocationStreamLimitsV1 {
    InvocationStreamLimitsV1 {
        max_total_bytes: 1024,
        max_chunks: 16,
        max_duration_secs: 30,
    }
}

fn raw_for_attempt(
    operation: &AdmissionOperationV1,
    attempt_id: &str,
    output: Value,
) -> Result<RawInvocationOutcomeV1, ToolOutcomeError> {
    RawInvocationOutcomeV1::from_committed_dispatch(
        operation,
        operation.dispatch_commit().unwrap(),
        id("server-1"),
        id("tool-1"),
        provider_attempt(operation, attempt_id),
        admission_digest("transport-terminal"),
        0,
        7,
        stream_limits(),
        InvocationOutputV1::Value { value: output },
        Some(MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
        None,
        Vec::new(),
    )
}

pub(super) fn returned(operation: &AdmissionOperationV1, output: Value) -> ToolOutcomeRecordV1 {
    returned_under(operation, output, fence(), 900)
}

fn returned_with_blob(
    operation: &AdmissionOperationV1,
    output: Value,
) -> (CanonicalInvocationBlobV1, ToolOutcomeRecordV1) {
    returned_with_blob_under(operation, output, fence(), 900)
}

fn returned_under(
    operation: &AdmissionOperationV1,
    output: Value,
    recording_fence: StoreMutationFence,
    recorded_at_unix_ms: u64,
) -> ToolOutcomeRecordV1 {
    returned_with_blob_under(operation, output, recording_fence, recorded_at_unix_ms).1
}

fn returned_with_blob_under(
    operation: &AdmissionOperationV1,
    output: Value,
    recording_fence: StoreMutationFence,
    recorded_at_unix_ms: u64,
) -> (CanonicalInvocationBlobV1, ToolOutcomeRecordV1) {
    let raw = raw_for(operation, output);
    let blob = raw.canonical_blob().unwrap();
    let record = ToolOutcomeRecordV1::record_tool_returned(
        operation,
        &raw,
        &blob,
        recording_fence,
        recorded_at_unix_ms,
    )
    .unwrap();
    (blob, record)
}

fn recovery_lease(
    operation: &AdmissionOperationV1,
    store_fence: &StoreMutationFence,
    trusted_now_unix_ms: u64,
) -> AdmissionRecoveryLease {
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding().operation_id().clone(),
        id("outcome-worker"),
        id("outcome-coordinator-lease"),
        operation.coordinator_lease_epoch(),
        operation.version(),
        trusted_now_unix_ms + 10_000,
        store_fence.clone(),
    )
    .unwrap();
    qualify_recovery_claim_for_test(operation, claim, trusted_now_unix_ms, store_fence).unwrap()
}

fn plan() -> Vec<FrozenEvaluationStepV1> {
    vec![
        FrozenEvaluationStepV1 {
            phase: EvaluationPhaseV1::OutputGuard,
            position: 0,
            component_id: id("guard-1"),
            component_version: id("1.0.0"),
            implementation_digest: admission_digest("guard-implementation"),
            mode: EvaluationModeV1::Pure,
        },
        FrozenEvaluationStepV1 {
            phase: EvaluationPhaseV1::Pricing,
            position: 0,
            component_id: id("pricing-1"),
            component_version: id("2.0.0"),
            implementation_digest: admission_digest("pricing-implementation"),
            mode: EvaluationModeV1::ExternalStateful {
                call_id: id("pricing-call-1"),
            },
        },
    ]
}

fn prepared_evaluation(
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
) -> PostReturnEvaluationRecordV1 {
    PostReturnEvaluationRecordV1::prepare(
        operation,
        outcome,
        plan(),
        1_000,
        PostReturnNormalizedRequestContextV1::from_verified_normalization(
            json!({"normalized_request": {"a": 1, "b": 2}}),
        )
        .unwrap(),
    )
    .unwrap()
}

fn record_pure(evaluation: &PostReturnEvaluationRecordV1) -> PostReturnEvaluationRecordV1 {
    let result = EvaluationStepResultV1::pure(
        0,
        evaluation.exact_inputs_digest.clone(),
        admission_digest("guard-result"),
    );
    evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(result),
        )
        .unwrap()
}

fn record_external(evaluation: &PostReturnEvaluationRecordV1) -> PostReturnEvaluationRecordV1 {
    let reference = ExternalEvaluationResultRefV1::new(
        1,
        &evaluation.frozen_steps[1],
        admission_digest("pricing-result"),
        id("pricing-verifier-1"),
        3,
        1_001,
    );
    let result = EvaluationStepResultV1::external(
        evaluation
            .step_results
            .last()
            .unwrap()
            .result_digest
            .clone(),
        reference.unwrap(),
    );
    evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(result),
        )
        .unwrap()
}

pub(super) fn resolve(
    operation: &AdmissionOperationV1,
    outcome: &ToolOutcomeRecordV1,
    disposition: SettlementDispositionV1,
) -> (ToolOutcomeRecordV1, PostReturnEvaluationRecordV1) {
    let evaluation = record_external(&record_pure(&prepared_evaluation(operation, outcome)));
    let resolution = PostReturnResolutionV1::from_output(
        &evaluation,
        &json!({"allowed": true}),
        admission_digest("guard-decision"),
        admission_digest("pricing-verdict"),
        disposition,
    )
    .unwrap();
    let evaluation = evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::Resolve(resolution),
        )
        .unwrap();
    let outcome = outcome
        .transition(
            outcome.version(),
            ToolOutcomeTransitionV1::Resolve(evaluation.terminal_evidence().unwrap()),
        )
        .unwrap();
    (outcome, evaluation)
}

#[test]
fn raw_outcome_has_one_canonical_bounded_encoding() {
    let mut reverse = Map::new();
    reverse.insert("z".to_owned(), json!(2));
    reverse.insert("a".to_owned(), json!(1));
    let operation_id = AdmissionOperationId::from_persisted(sha("op")).unwrap();
    let raw = RawInvocationOutcomeV1 {
        schema: RAW_INVOCATION_OUTCOME_SCHEMA,
        operation_id: operation_id.clone(),
        request_id: id("req"),
        dispatch_operation_version: 7,
        dispatch_fence: 8,
        tool_server: id("server"),
        tool_name: id("tool"),
        provider_attempt: ProviderAttemptBindingV1 {
            operation_id: operation_id.as_str().to_owned(),
            attempt_id: "attempt".to_owned(),
            transport_id: "transport".to_owned(),
            transport_key_epoch: 1,
        },
        transport_terminal_evidence_digest: AdmissionDigest::try_new(
            "transport_terminal_evidence_digest",
            "a".repeat(64),
        )
        .unwrap(),
        matched_grant_index: 0,
        elapsed_millis: 7,
        stream_limits: stream_limits(),
        output: InvocationOutputV1::Value {
            value: Value::Object(reverse),
        },
        reported_cost: None,
        receipt_metadata_snapshot: None,
        pre_invocation_guard_evidence: Vec::new(),
        request_canonical_json: None,
    };
    let blob = raw.canonical_blob().unwrap();
    let expected = format!(
        "{{\"dispatch_fence\":8,\"dispatch_operation_version\":7,\"elapsed_millis\":7,\"matched_grant_index\":0,\"operation_id\":\"{}\",\"output\":{{\"kind\":\"value\",\"value\":{{\"a\":1,\"z\":2}}}},\"pre_invocation_guard_evidence\":[],\"provider_attempt\":{{\"attempt_id\":\"attempt\",\"operation_id\":\"{}\",\"transport_id\":\"transport\",\"transport_key_epoch\":1}},\"receipt_metadata_snapshot\":null,\"reported_cost\":null,\"request_id\":\"req\",\"schema\":\"{}\",\"stream_limits\":{{\"max_chunks\":16,\"max_duration_secs\":30,\"max_total_bytes\":1024}},\"tool_name\":\"tool\",\"tool_server\":\"server\",\"transport_terminal_evidence_digest\":\"{}\"}}",
        operation_id.as_str(),
        operation_id.as_str(),
        RAW_INVOCATION_OUTCOME_SCHEMA,
        "a".repeat(64)
    );
    assert_eq!(blob.bytes(), expected.as_bytes());
    assert_eq!(
        blob.blob_ref().digest().as_str(),
        sha256_hex(expected.as_bytes())
    );
    assert_eq!(
        RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes()).unwrap(),
        raw
    );
    assert_eq!(
        RawInvocationOutcomeV1::from_persisted(raw.to_persisted()).unwrap(),
        raw
    );
    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(blob.bytes());
    assert!(RawInvocationOutcomeV1::from_canonical_bytes(&noncanonical).is_err());
    let mut wrong_schema = raw.to_persisted();
    wrong_schema.schema = "chio.raw-invocation-outcome.v0".to_owned();
    assert!(RawInvocationOutcomeV1::from_persisted(wrong_schema).is_err());
    assert!(matches!(
        raw.canonical_blob_bounded(32),
        Err(ToolOutcomeError::TooLarge { .. })
    ));

    assert!(AdmissionIdentifier::try_new("tool_name", " tool").is_err());
    let mut incomplete = raw;
    incomplete.output = InvocationOutputV1::IncompleteStream {
        chunks: vec![],
        reason: " ambiguous ".to_owned(),
    };
    assert!(incomplete.canonical_blob().is_err());
}

#[test]
fn raw_outcome_rejects_unsafe_recovery_fields() {
    let operation = committed_operation("request-raw-bounds");
    let raw = raw_for(&operation, json!({"ok": true}));

    let mut persisted = raw.to_persisted();
    persisted.matched_grant_index = I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(matches!(
        RawInvocationOutcomeV1::from_persisted(persisted),
        Err(ToolOutcomeError::Invalid("raw.matched_grant_index"))
    ));

    let mut persisted = raw.to_persisted();
    persisted.elapsed_millis = I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(matches!(
        RawInvocationOutcomeV1::from_persisted(persisted),
        Err(ToolOutcomeError::Invalid("raw.elapsed_millis"))
    ));

    for mutate in [
        |limits: &mut InvocationStreamLimitsV1| {
            limits.max_total_bytes = I_JSON_MAX_SAFE_INTEGER + 1;
        },
        |limits: &mut InvocationStreamLimitsV1| {
            limits.max_chunks = I_JSON_MAX_SAFE_INTEGER + 1;
        },
        |limits: &mut InvocationStreamLimitsV1| {
            limits.max_duration_secs = I_JSON_MAX_SAFE_INTEGER + 1;
        },
    ] {
        let mut persisted = raw.to_persisted();
        mutate(&mut persisted.stream_limits);
        assert!(matches!(
            RawInvocationOutcomeV1::from_persisted(persisted),
            Err(ToolOutcomeError::Invalid("raw.stream_limits"))
        ));
    }

    let evidence = GuardEvidence {
        guard_name: "input-guard".to_owned(),
        verdict: true,
        details: Some("bound to the returned invocation".to_owned()),
    };
    let mut persisted = raw.to_persisted();
    persisted.pre_invocation_guard_evidence = vec![evidence; MAX_RECEIPT_GUARD_EVIDENCE + 1];
    assert!(matches!(
        RawInvocationOutcomeV1::from_persisted(persisted),
        Err(ToolOutcomeError::TooLarge {
            field: "raw.pre_invocation_guard_evidence",
            actual,
            maximum: MAX_RECEIPT_GUARD_EVIDENCE,
        }) if actual == MAX_RECEIPT_GUARD_EVIDENCE + 1
    ));
}

#[test]
fn raw_outcome_round_trip_retains_finalization_inputs() {
    let operation = committed_operation("request-raw-finalization-inputs");
    let evidence = GuardEvidence {
        guard_name: "input-policy".to_owned(),
        verdict: true,
        details: Some("verified before dispatch".to_owned()),
    };
    let metadata = json!({
        "attribution": {"grant_index": 0},
        "governed_transaction": {"runtime_assurance": "verified"}
    });
    let raw = RawInvocationOutcomeV1::from_committed_dispatch(
        &operation,
        operation.dispatch_commit().unwrap(),
        id("server-1"),
        id("tool-1"),
        provider_attempt(&operation, "attempt-1"),
        admission_digest("transport-terminal"),
        0,
        17,
        stream_limits(),
        InvocationOutputV1::Value {
            value: json!({"ok": true}),
        },
        None,
        Some(metadata.clone()),
        vec![evidence.clone()],
    )
    .unwrap();

    let restored =
        RawInvocationOutcomeV1::from_canonical_bytes(raw.canonical_blob().unwrap().bytes())
            .unwrap();
    assert_eq!(restored.matched_grant_index().unwrap(), 0);
    assert_eq!(restored.elapsed_millis(), 17);
    assert_eq!(restored.stream_limits(), stream_limits());
    assert_eq!(restored.receipt_metadata_snapshot(), Some(&metadata));
    assert_eq!(restored.pre_invocation_guard_evidence(), &[evidence]);
}

#[test]
fn canonical_blob_and_admission_bindings_reject_substitution() {
    let operation = committed_operation("request-1");
    let other = committed_operation("request-2");
    let mut substituted_commit = other.dispatch_commit().unwrap().clone();
    substituted_commit.committed_version += 1;
    assert!(RawInvocationOutcomeV1::from_committed_dispatch(
        &operation,
        &substituted_commit,
        id("server"),
        id("tool"),
        operation.provider_attempt().unwrap().clone(),
        admission_digest("transport"),
        0,
        7,
        stream_limits(),
        InvocationOutputV1::Value { value: json!(1) },
        None,
        None,
        Vec::new(),
    )
    .is_err());

    let raw = raw_for(&operation, json!({"ok": true}));
    let mut blob = raw.canonical_blob().unwrap();
    blob.bytes.push(b' ');
    assert!(blob.verify(&raw).is_err());

    let outcome = returned(&operation, json!({"ok": true}));
    assert!(outcome.validate_against(&operation).is_ok());
    assert!(outcome.validate_against(&other).is_err());
    for mutation in ["dispatch_version", "dispatch_fence", "request"] {
        let mut changed = outcome.clone();
        match mutation {
            "dispatch_version" => changed.dispatch_operation_version += 1,
            "dispatch_fence" => changed.dispatch_fence += 1,
            "request" => changed.request_id = id("substituted"),
            _ => unreachable!(),
        }
        assert!(changed.validate_against(&operation).is_err(), "{mutation}");
    }
}

#[test]
fn broker_attempt_registration_binds_raw_outcome_creation_and_recording() {
    let operation = committed_broker_operation("request-broker-attempt", "attempt-1");
    let sibling = committed_broker_operation("request-broker-attempt", "attempt-2");
    assert_eq!(
        operation.binding().operation_id(),
        sibling.binding().operation_id()
    );
    assert_eq!(operation.replay_key(), sibling.replay_key());
    assert_ne!(operation.dispatch_commit(), sibling.dispatch_commit());

    let raw = raw_for_attempt(&operation, "attempt-1", json!({"ok": true})).unwrap();
    let blob = raw.canonical_blob().unwrap();
    ToolOutcomeRecordV1::record_tool_returned(&operation, &raw, &blob, fence(), 900).unwrap();

    assert_eq!(
        raw_for_attempt(&operation, "attempt-2", json!({"ok": true})).unwrap_err(),
        ToolOutcomeError::Binding("provider_attempt.registered_attempt")
    );

    let sibling_raw = raw_for_attempt(&sibling, "attempt-2", json!({"ok": true})).unwrap();
    let sibling_blob = sibling_raw.canonical_blob().unwrap();
    assert_eq!(
        ToolOutcomeRecordV1::record_tool_returned(
            &operation,
            &sibling_raw,
            &sibling_blob,
            fence(),
            900,
        )
        .unwrap_err(),
        ToolOutcomeError::Binding("provider_attempt.registered_attempt")
    );

    for mutate in ["transport", "key_epoch"] {
        let mut substituted = operation.provider_attempt().unwrap().clone();
        match mutate {
            "transport" => substituted.transport_id = "transport-2".to_owned(),
            "key_epoch" => substituted.transport_key_epoch += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            RawInvocationOutcomeV1::from_committed_dispatch(
                &operation,
                operation.dispatch_commit().unwrap(),
                id("server-1"),
                id("tool-1"),
                substituted,
                admission_digest("transport-terminal"),
                0,
                7,
                stream_limits(),
                InvocationOutputV1::Value { value: json!(1) },
                None,
                None,
                Vec::new(),
            )
            .unwrap_err(),
            ToolOutcomeError::Binding("provider_attempt.registered_attempt"),
            "{mutate} substitution was accepted"
        );
    }
}

#[test]
fn admission_receipt_derives_action_and_output_bindings_from_terminal_evidence() {
    let committed = committed_operation("request-receipt-binding");
    let returned = returned(&committed, json!({"raw": true}));
    let (outcome, evaluation) = resolve(
        &committed,
        &returned,
        SettlementDispositionV1::NotApplicable,
    );
    let operation = advance(
        &committed,
        AdmissionOperationState::Finalizing,
        vec![AdmissionAttachment::ToolOutcomeId(
            outcome.outcome_id().clone(),
        )],
    );
    let context = projection_context(&operation);
    let evidence =
        ToolOutcomeTerminalEvidenceV1::from_records(&operation, &context, &outcome, &evaluation)
            .unwrap();
    let metadata = AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        request_namespace_digest: operation.binding().request_namespace_digest().clone(),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        projected_operation_version: operation.version() + 1,
        projected_state: AdmissionOperationState::Completed,
        projected_dispatch_state: AdmissionDispatchState::Terminal,
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: context.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit().cloned(),
        compensation_status: AdmissionCompensationStatus::NotCompensated,
        tool_outcome_id: Some(evidence.outcome_id().clone()),
        tool_outcome_version: Some(evidence.outcome_version()),
    };
    let keypair = Keypair::generate();
    let sign = |parameters: Value, content_hash: String| {
        ChioReceipt::sign(
            ChioReceiptBody {
                id: "receipt-terminal-evidence".to_owned(),
                timestamp: context.trusted_time_unix_ms / 1_000,
                capability_id: operation.binding().capability_id().as_str().to_owned(),
                tool_server: evidence.tool_server().as_str().to_owned(),
                tool_name: evidence.tool_name().as_str().to_owned(),
                action: ToolCallAction::from_parameters(parameters).unwrap(),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash,
                policy_hash: operation.binding().policy_hash().as_str().to_owned(),
                evidence: Vec::new(),
                metadata: Some(json!({ ADMISSION_RECEIPT_METADATA_KEY: metadata.clone() })),
                trust_level: Default::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .unwrap()
    };

    VerifiedAdmissionReceipt::from_kernel_verified(
        sign(
            json!({}),
            evidence.resolved_output_digest().as_str().to_owned(),
        ),
        &keypair.public_key(),
        &operation,
        &context,
        &evidence,
    )
    .unwrap();
    assert!(VerifiedAdmissionReceipt::from_kernel_verified(
        sign(
            json!({}),
            admission_digest("substituted-content").as_str().to_owned(),
        ),
        &keypair.public_key(),
        &operation,
        &context,
        &evidence,
    )
    .is_err());
    assert!(VerifiedAdmissionReceipt::from_kernel_verified(
        sign(
            json!({"substituted": true}),
            evidence.resolved_output_digest().as_str().to_owned(),
        ),
        &keypair.public_key(),
        &operation,
        &context,
        &evidence,
    )
    .is_err());
}

struct MemoryOutcomeStore {
    outcome: Mutex<Option<ToolOutcomeRecordV1>>,
    active_fence: Mutex<StoreMutationFence>,
    trusted_time_high_water: Mutex<u64>,
}

impl Default for MemoryOutcomeStore {
    fn default() -> Self {
        Self::with_fence(fence())
    }
}

impl MemoryOutcomeStore {
    fn with_fence(active_fence: StoreMutationFence) -> Self {
        Self {
            outcome: Mutex::new(None),
            active_fence: Mutex::new(active_fence),
            trusted_time_high_water: Mutex::new(0),
        }
    }

    fn rotate_to(&self, next: StoreMutationFence) {
        *self.active_fence.lock().unwrap() = next;
    }

    fn authorize(
        &self,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), ToolOutcomeStoreError> {
        if active_fence != &*self.active_fence.lock().unwrap() {
            return Err(ToolOutcomeStoreError::Fenced);
        }
        if trusted_now_unix_ms == 0 || trusted_now_unix_ms > I_JSON_MAX_SAFE_INTEGER {
            return Err(ToolOutcomeStoreError::Invariant(
                "invalid trusted time".to_owned(),
            ));
        }
        let mut high_water = self.trusted_time_high_water.lock().unwrap();
        if trusted_now_unix_ms < *high_water {
            return Err(ToolOutcomeStoreError::Invariant(
                "trusted time regression".to_owned(),
            ));
        }
        *high_water = trusted_now_unix_ms;
        Ok(())
    }
}

impl ToolOutcomeStore for MemoryOutcomeStore {
    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError> {
        self.authorize(active_fence, trusted_now_unix_ms)?;
        record
            .validate_for_store_insert(operation, blob, active_fence, trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let command = finalizing_outcome_command(
            operation,
            recovery_lease.clone(),
            record.outcome_id().clone(),
        )
        .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        let finalizing = operation
            .apply_command(&command, trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?
            .into_operation();
        let mut stored = self.outcome.lock().unwrap();
        match stored.as_ref() {
            None => {
                *stored = Some(record.clone());
                Ok(ToolOutcomeInsertResultV1::Inserted {
                    outcome: record.clone(),
                    operation: finalizing,
                })
            }
            Some(existing) if existing.same_immutable_outcome(record) => {
                Ok(ToolOutcomeInsertResultV1::ExactReplay {
                    outcome: existing.clone(),
                    operation: finalizing,
                })
            }
            Some(_) => Err(ToolOutcomeStoreError::Conflict),
        }
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError> {
        Ok(self
            .outcome
            .lock()
            .unwrap()
            .as_ref()
            .filter(|record| record.operation_id() == operation_id)
            .cloned())
    }

    fn load_raw_invocation_by_operation(
        &self,
        _operation_id: &AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError> {
        Ok(None)
    }

    fn lookup_post_return_evaluation(
        &self,
        _operation_id: &AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError> {
        Ok(None)
    }

    fn begin_post_return_evaluation(
        &self,
        _recovery_lease: &AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.authorize(active_fence, trusted_now_unix_ms)?;
        record
            .validate_for_store_mutation(trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        Ok(record.clone())
    }

    fn stage_post_return_evaluation(
        &self,
        _operation_id: &AdmissionOperationId,
        _expected_version: u64,
        _recovery_lease: &AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError> {
        self.authorize(active_fence, trusted_now_unix_ms)?;
        next.validate_for_store_mutation(trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        Ok(next.clone())
    }

    fn finalize_post_return(
        &self,
        _operation_id: &AdmissionOperationId,
        _expected_evaluation_version: u64,
        _recovery_lease: &AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        _expected_outcome_version: u64,
        _terminal_outcome: &ToolOutcomeRecordV1,
        _resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError> {
        self.authorize(active_fence, trusted_now_unix_ms)?;
        terminal_evaluation
            .validate_for_store_mutation(trusted_now_unix_ms)
            .map_err(|error| ToolOutcomeStoreError::Invariant(error.to_string()))?;
        Err(ToolOutcomeStoreError::Unavailable("unused".to_owned()))
    }

    fn load_resolved_output_by_operation(
        &self,
        _operation_id: &AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError> {
        Ok(None)
    }
}

#[test]
fn store_insert_is_once_replay_or_conflict() {
    let operation = committed_operation("request-store");
    let (first_blob, first) = returned_with_blob(&operation, json!(1));
    let (conflicting_blob, conflicting) = returned_with_blob(&operation, json!(2));
    let lease = recovery_lease(&operation, &fence(), 900);
    let store = MemoryOutcomeStore::default();
    assert!(matches!(
        store
            .record_tool_returned(&operation, &lease, &first_blob, &first, &fence(), 900)
            .unwrap(),
        ToolOutcomeInsertResultV1::Inserted { operation, .. }
            if operation.state() == AdmissionOperationState::Finalizing
    ));
    assert!(matches!(
        store
            .record_tool_returned(&operation, &lease, &first_blob, &first, &fence(), 900)
            .unwrap(),
        ToolOutcomeInsertResultV1::ExactReplay { .. }
    ));
    assert_eq!(
        store.record_tool_returned(
            &operation,
            &lease,
            &conflicting_blob,
            &conflicting,
            &fence(),
            900,
        ),
        Err(ToolOutcomeStoreError::Conflict)
    );
}

#[test]
fn exact_replay_rejects_immutable_semantic_substitution() {
    let operation = committed_operation("request-replay-substitution");
    let (original_blob, original) = returned_with_blob(&operation, json!({"same": "bytes"}));
    let lease = recovery_lease(&operation, &fence(), 900);
    let store = MemoryOutcomeStore::default();
    store
        .record_tool_returned(&operation, &lease, &original_blob, &original, &fence(), 900)
        .unwrap();

    let substitutions = [
        (id("server-1"), id("tool-1"), 26, json!({"same": "bytes"})),
        (
            id("substituted-server"),
            id("tool-1"),
            25,
            json!({"same": "bytes"}),
        ),
        (
            id("server-1"),
            id("substituted-tool"),
            25,
            json!({"same": "bytes"}),
        ),
        (id("server-1"), id("tool-1"), 25, json!({"other": true})),
    ];
    for (server, tool, units, output) in substitutions {
        let raw = RawInvocationOutcomeV1::from_committed_dispatch(
            &operation,
            operation.dispatch_commit().unwrap(),
            server,
            tool,
            operation.provider_attempt().unwrap().clone(),
            admission_digest("transport-terminal"),
            0,
            7,
            stream_limits(),
            InvocationOutputV1::Value { value: output },
            Some(MonetaryAmount {
                units,
                currency: "USD".to_owned(),
            }),
            None,
            Vec::new(),
        )
        .unwrap();
        let blob = raw.canonical_blob().unwrap();
        let substituted =
            ToolOutcomeRecordV1::record_tool_returned(&operation, &raw, &blob, fence(), 900)
                .unwrap();
        assert_eq!(
            store.record_tool_returned(&operation, &lease, &blob, &substituted, &fence(), 900,),
            Err(ToolOutcomeStoreError::Conflict)
        );
    }
}

#[test]
fn recovered_return_keeps_identity_across_owner_rotation() {
    let operation = committed_operation("request-owner-rotation");
    let owner_n = operation.dispatch_commit().unwrap().store_fence.clone();
    let owner_n_plus_one = successor_fence(owner_n.owner_epoch + 1);
    assert!(validate_successor_fence(&owner_n, &owner_n).is_ok());
    let mut same_epoch_other_lease = owner_n.clone();
    same_epoch_other_lease.lease_id = "substituted-same-epoch-lease".to_owned();
    assert!(validate_successor_fence(&owner_n, &same_epoch_other_lease).is_err());
    let mut older = owner_n.clone();
    older.owner_epoch -= 1;
    assert!(validate_successor_fence(&owner_n, &older).is_err());
    let mut other_store = owner_n_plus_one.clone();
    other_store.store_uuid = "other-store".to_owned();
    assert!(validate_successor_fence(&owner_n, &other_store).is_err());
    let (recovered_blob, recovered) = returned_with_blob_under(
        &operation,
        json!({"completed": true}),
        owner_n_plus_one.clone(),
        900,
    );
    let owner_n_plus_one_lease = recovery_lease(&operation, &owner_n_plus_one, 900);
    let store = MemoryOutcomeStore::with_fence(owner_n_plus_one.clone());
    assert!(matches!(
        store
            .record_tool_returned(
                &operation,
                &owner_n_plus_one_lease,
                &recovered_blob,
                &recovered,
                &owner_n_plus_one,
                900,
            )
            .unwrap(),
        ToolOutcomeInsertResultV1::Inserted { .. }
    ));
    assert_eq!(
        store.record_tool_returned(
            &operation,
            &owner_n_plus_one_lease,
            &recovered_blob,
            &recovered,
            &owner_n,
            900,
        ),
        Err(ToolOutcomeStoreError::Fenced)
    );

    let owner_n_plus_two = successor_fence(owner_n.owner_epoch + 2);
    store.rotate_to(owner_n_plus_two.clone());
    let (replay_blob, replay) = returned_with_blob_under(
        &operation,
        json!({"completed": true}),
        owner_n_plus_two.clone(),
        901,
    );
    let owner_n_plus_two_lease = recovery_lease(&operation, &owner_n_plus_two, 901);
    assert_ne!(recovered.recording_fence(), replay.recording_fence());
    assert!(recovered.same_immutable_outcome(&replay));
    assert!(matches!(
        store
            .record_tool_returned(
                &operation,
                &owner_n_plus_two_lease,
                &replay_blob,
                &replay,
                &owner_n_plus_two,
                901,
            )
            .unwrap(),
        ToolOutcomeInsertResultV1::ExactReplay { outcome, .. }
            if outcome.recording_fence() == &owner_n_plus_one
    ));
}

#[test]
fn persisted_outcome_and_evaluation_reject_substitution() {
    let operation = committed_operation("request-persisted");
    let outcome = returned(&operation, json!({"ok": true}));
    assert_eq!(
        ToolOutcomeRecordV1::from_persisted(outcome.to_persisted()).unwrap(),
        outcome
    );
    let mut wrong_commit = outcome.to_persisted();
    wrong_commit.dispatch_commit.store_fence.lease_id = "other-lease".to_owned();
    assert!(ToolOutcomeRecordV1::from_persisted(wrong_commit).is_err());
    let mut wrong_returned_version = outcome.to_persisted();
    wrong_returned_version.version = 2;
    assert!(ToolOutcomeRecordV1::from_persisted(wrong_returned_version).is_err());
    let mut oversized = outcome.to_persisted();
    oversized.raw_output_size_bytes = MAX_RAW_INVOCATION_OUTCOME_BYTES as u64 + 1;
    assert!(ToolOutcomeRecordV1::from_persisted(oversized).is_err());

    let (resolved_outcome, terminal_evaluation) =
        resolve(&operation, &outcome, SettlementDispositionV1::NotApplicable);
    let resolved_persisted = resolved_outcome.to_persisted();
    let mut substituted_lifecycle = outcome.to_persisted();
    substituted_lifecycle.disposition = resolved_persisted.disposition;
    substituted_lifecycle.version = resolved_persisted.version;
    assert!(ToolOutcomeRecordV1::from_persisted(substituted_lifecycle).is_err());

    let evaluation = prepared_evaluation(&operation, &outcome);
    assert_eq!(
        PostReturnEvaluationRecordV1::from_persisted(evaluation.to_persisted()).unwrap(),
        evaluation
    );
    let mut persisted = serde_json::to_value(evaluation.to_persisted()).unwrap();
    persisted["exact_inputs"]["request_id"] = json!("substituted-request");
    let persisted: PersistedPostReturnEvaluationRecordV1 =
        serde_json::from_value(persisted).unwrap();
    assert!(PostReturnEvaluationRecordV1::from_persisted(persisted).is_err());
    let mut wrong_evaluation_version = evaluation.to_persisted();
    wrong_evaluation_version.version += 1;
    assert!(PostReturnEvaluationRecordV1::from_persisted(wrong_evaluation_version).is_err());
    let terminal_persisted = terminal_evaluation.to_persisted();
    let mut substituted_evaluation_lifecycle = evaluation.to_persisted();
    substituted_evaluation_lifecycle.step_results = terminal_persisted.step_results;
    substituted_evaluation_lifecycle.state = terminal_persisted.state;
    substituted_evaluation_lifecycle.version = terminal_persisted.version;
    assert!(
        PostReturnEvaluationRecordV1::from_persisted(substituted_evaluation_lifecycle).is_err()
    );
    let mut pre_dispatch_exact_inputs = evaluation.clone();
    pre_dispatch_exact_inputs.exact_inputs.operation_version = operation
        .dispatch_commit()
        .unwrap()
        .committed_version
        .saturating_sub(1);
    assert!(pre_dispatch_exact_inputs.validate().is_err());

    let other_operation = committed_operation("request-persisted-other");
    let other_outcome = returned(&other_operation, json!({"ok": true}));
    assert!(evaluation
        .validate_against(&other_operation, &other_outcome)
        .is_err());
}

#[test]
fn post_return_store_mutations_require_current_owner_fence() {
    let operation = committed_operation("request-fence");
    let outcome = returned(&operation, json!(1));
    let evaluation = prepared_evaluation(&operation, &outcome);
    let store = MemoryOutcomeStore::default();
    let mut stale = fence();
    stale.owner_epoch -= 1;
    let stale_lease = recovery_lease(&operation, &stale, 1_000);
    let lease = recovery_lease(&operation, &fence(), 1_000);
    assert_eq!(
        store.begin_post_return_evaluation(&stale_lease, &evaluation, &stale, 1_000),
        Err(ToolOutcomeStoreError::Fenced)
    );
    assert_eq!(
        store
            .begin_post_return_evaluation(&lease, &evaluation, &fence(), 1_000)
            .unwrap(),
        evaluation
    );
}

#[test]
fn step_results_are_ordered_dependency_bound_and_recovery_safe() {
    let operation = committed_operation("request-steps");
    let outcome = returned(&operation, json!(1));
    let mut duplicate_call_plan = plan();
    duplicate_call_plan.push(FrozenEvaluationStepV1 {
        phase: EvaluationPhaseV1::Pricing,
        position: 1,
        component_id: id("pricing-2"),
        component_version: id("2.0.0"),
        implementation_digest: admission_digest("pricing-implementation-2"),
        mode: EvaluationModeV1::ExternalStateful {
            call_id: id("pricing-call-1"),
        },
    });
    assert!(PostReturnEvaluationRecordV1::prepare(
        &operation,
        &outcome,
        duplicate_call_plan,
        1_000,
        PostReturnNormalizedRequestContextV1::from_verified_normalization(json!({"a": 1})).unwrap(),
    )
    .is_err());
    let evaluation = prepared_evaluation(&operation, &outcome);

    let external = ExternalEvaluationResultRefV1::new(
        1,
        &evaluation.frozen_steps[1],
        admission_digest("pricing-result"),
        id("verifier"),
        1,
        1_001,
    )
    .unwrap();
    let early = EvaluationStepResultV1::external(evaluation.exact_inputs_digest.clone(), external);
    assert!(evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(early),
        )
        .is_err());

    let wrong_dependency = EvaluationStepResultV1::pure(
        0,
        admission_digest("wrong"),
        admission_digest("guard-result"),
    );
    assert!(evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(wrong_dependency),
        )
        .is_err());
    assert_eq!(
        evaluation.replay_action(0).unwrap(),
        PostReturnReplayActionV1::ReplayPureFromFrozenInputs
    );
    assert!(evaluation.replay_action(1).is_err());

    let evaluation = record_pure(&evaluation);
    assert!(matches!(
        evaluation.replay_action(0).unwrap(),
        PostReturnReplayActionV1::UseRecordedStepResult { .. }
    ));
    assert_eq!(
        evaluation.replay_action(1).unwrap(),
        PostReturnReplayActionV1::LookupExternalResult {
            call_id: id("pricing-call-1")
        }
    );
    assert!(PostReturnResolutionV1::from_output(
        &evaluation,
        &json!(1),
        admission_digest("guard"),
        admission_digest("price"),
        SettlementDispositionV1::NotApplicable,
    )
    .is_err());

    let evaluation = record_external(&evaluation);
    let resolution = PostReturnResolutionV1::from_output(
        &evaluation,
        &json!(1),
        admission_digest("guard"),
        admission_digest("price"),
        SettlementDispositionV1::NotApplicable,
    )
    .unwrap();
    assert_eq!(
        resolution.terminal_dependency_root_digest,
        evaluation.step_result_root().unwrap()
    );
}

#[test]
fn external_results_are_bounded_by_frozen_and_store_time() {
    let operation = committed_operation("request-external-time");
    let outcome = returned(&operation, json!(1));
    let evaluation = record_pure(&prepared_evaluation(&operation, &outcome));
    let before_frozen_time = ExternalEvaluationResultRefV1::new(
        1,
        &evaluation.frozen_steps[1],
        admission_digest("before-frozen-time"),
        id("verifier-time"),
        1,
        999,
    )
    .unwrap();
    assert!(evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(EvaluationStepResultV1::external(
                evaluation
                    .step_results
                    .last()
                    .unwrap()
                    .result_digest
                    .clone(),
                before_frozen_time,
            ),),
        )
        .is_err());

    let future = ExternalEvaluationResultRefV1::new(
        1,
        &evaluation.frozen_steps[1],
        admission_digest("future-result"),
        id("verifier-time"),
        1,
        1_100,
    )
    .unwrap();
    let with_future = evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(EvaluationStepResultV1::external(
                evaluation
                    .step_results
                    .last()
                    .unwrap()
                    .result_digest
                    .clone(),
                future,
            )),
        )
        .unwrap();
    let store = MemoryOutcomeStore::default();
    let lease = recovery_lease(&operation, &fence(), 1_099);
    assert!(store
        .stage_post_return_evaluation(
            operation.binding().operation_id(),
            evaluation.version(),
            &lease,
            &with_future,
            &fence(),
            1_099,
        )
        .is_err());
    assert!(store
        .stage_post_return_evaluation(
            operation.binding().operation_id(),
            evaluation.version(),
            &lease,
            &with_future,
            &fence(),
            1_100,
        )
        .is_ok());
    assert!(store
        .begin_post_return_evaluation(&lease, &evaluation, &fence(), 1_099)
        .is_err());
    assert!(ExternalEvaluationResultRefV1::new(
        1,
        &evaluation.frozen_steps[1],
        admission_digest("unsafe-time"),
        id("verifier-time"),
        1,
        I_JSON_MAX_SAFE_INTEGER + 1,
    )
    .is_err());
}

#[test]
fn terminal_pair_binds_the_exact_resolved_signing_preimage() {
    let operation = committed_operation("request-resolved-signing-preimage");
    let outcome = returned(&operation, json!([]));
    let evaluation = record_external(&record_pure(&prepared_evaluation(&operation, &outcome)));
    let (resolution, empty_stream_preimage) = PostReturnResolutionV1::from_signing_preimage(
        &evaluation,
        Vec::new(),
        admission_digest("guard-decision"),
        admission_digest("pricing-verdict"),
        SettlementDispositionV1::NotApplicable,
    )
    .unwrap();
    assert_eq!(resolution.resolved_output_size_bytes, 0);
    let terminal_evaluation = evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::Resolve(resolution),
        )
        .unwrap();
    let terminal_outcome = outcome
        .transition(
            outcome.version(),
            ToolOutcomeTransitionV1::Resolve(terminal_evaluation.terminal_evidence().unwrap()),
        )
        .unwrap();

    validate_terminal_store_pair(
        &operation,
        &outcome,
        &evaluation,
        &terminal_evaluation,
        &terminal_outcome,
        Some(&empty_stream_preimage),
    )
    .unwrap();
    let substituted =
        CanonicalResolvedOutputBlobV1::from_signing_preimage(b"null".to_vec()).unwrap();
    assert!(validate_terminal_store_pair(
        &operation,
        &outcome,
        &evaluation,
        &terminal_evaluation,
        &terminal_outcome,
        Some(&substituted),
    )
    .is_err());
    assert!(validate_terminal_store_pair(
        &operation,
        &outcome,
        &evaluation,
        &terminal_evaluation,
        &terminal_outcome,
        None,
    )
    .is_err());
}

#[test]
fn cas_transitions_are_terminal_and_freeze_prevents_rerun() {
    let operation = committed_operation("request-cas");
    let outcome = returned(&operation, json!(1));
    let evaluation = prepared_evaluation(&operation, &outcome);
    let pure = EvaluationStepResultV1::pure(
        0,
        evaluation.exact_inputs_digest.clone(),
        admission_digest("guard-result"),
    );
    assert!(matches!(
        evaluation.transition(
            99,
            PostReturnEvaluationTransitionV1::RecordStepResult(pure.clone())
        ),
        Err(ToolOutcomeError::Cas { .. })
    ));
    let evaluation = evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::RecordStepResult(pure),
        )
        .unwrap();
    let freeze = EvaluationFreezeV1::AmbiguousExternalResult {
        step_index: 1,
        evidence_digest: admission_digest("ambiguous-provider-result"),
    };
    let frozen = evaluation
        .transition(
            evaluation.version(),
            PostReturnEvaluationTransitionV1::Freeze(freeze),
        )
        .unwrap();
    assert_eq!(
        frozen.replay_action(1).unwrap(),
        PostReturnReplayActionV1::DoNotRunFrozen
    );
    assert!(matches!(
        frozen.transition(
            frozen.version(),
            PostReturnEvaluationTransitionV1::Freeze(
                EvaluationFreezeV1::AuthenticatedResultUnavailable {
                    step_index: 1,
                    evidence_digest: admission_digest("again")
                }
            )
        ),
        Err(ToolOutcomeError::Transition { .. })
    ));
    let frozen_outcome = outcome
        .transition(
            outcome.version(),
            ToolOutcomeTransitionV1::Freeze(frozen.freeze_evidence().unwrap()),
        )
        .unwrap();
    validate_terminal_store_pair(
        &operation,
        &outcome,
        &evaluation,
        &frozen,
        &frozen_outcome,
        None,
    )
    .unwrap();
    let unexpected_blob = CanonicalResolvedOutputBlobV1::from_signing_preimage(Vec::new()).unwrap();
    assert!(validate_terminal_store_pair(
        &operation,
        &outcome,
        &evaluation,
        &frozen,
        &frozen_outcome,
        Some(&unexpected_blob),
    )
    .is_err());
    let mut wrong_frozen_version = frozen_outcome.to_persisted();
    wrong_frozen_version.version += 1;
    assert!(ToolOutcomeRecordV1::from_persisted(wrong_frozen_version).is_err());
    assert!(matches!(
        frozen_outcome.transition(
            frozen_outcome.version(),
            ToolOutcomeTransitionV1::Freeze(frozen.freeze_evidence().unwrap())
        ),
        Err(ToolOutcomeError::Transition { .. })
    ));
}

#[test]
fn terminal_evidence_is_exact_and_cas_bound() {
    let operation = committed_operation("request-terminal");
    let dispatch_epoch = operation.dispatch_commit().unwrap().store_fence.owner_epoch;
    let returned = returned_under(
        &operation,
        json!(1),
        successor_fence(dispatch_epoch + 1),
        900,
    );
    let (resolved, evaluation) = resolve(
        &operation,
        &returned,
        SettlementDispositionV1::NotApplicable,
    );
    let context = projection_context_under(&operation, successor_fence(dispatch_epoch + 2));
    let terminal =
        ToolOutcomeTerminalEvidenceV1::from_records(&operation, &context, &resolved, &evaluation)
            .unwrap();
    assert_eq!(terminal.outcome_id(), resolved.outcome_id());
    assert_eq!(terminal.outcome_version(), resolved.version());
    let mut same_epoch_other_lease =
        projection_context_under(&operation, returned.recording_fence().clone());
    same_epoch_other_lease.store_fence.lease_id = "other-same-epoch-lease".to_owned();
    assert!(ToolOutcomeTerminalEvidenceV1::from_records(
        &operation,
        &same_epoch_other_lease,
        &resolved,
        &evaluation,
    )
    .is_err());
    let mut wrong_store = context.clone();
    wrong_store.store_fence.store_uuid = "other-store".to_owned();
    assert!(terminal.validate_against(&operation, &wrong_store).is_err());
    let mut wrong_resolved_version = resolved.to_persisted();
    wrong_resolved_version.version += 1;
    assert!(ToolOutcomeRecordV1::from_persisted(wrong_resolved_version).is_err());
    let mut wrong_evaluation_version = evaluation.to_persisted();
    wrong_evaluation_version.version += 1;
    assert!(PostReturnEvaluationRecordV1::from_persisted(wrong_evaluation_version).is_err());

    let mut substituted = evaluation.terminal_evidence().unwrap();
    substituted.raw_output_digest = admission_digest("another-output");
    assert!(returned
        .transition(
            returned.version(),
            ToolOutcomeTransitionV1::Resolve(substituted),
        )
        .is_err());
    assert!(resolved
        .transition(
            resolved.version(),
            ToolOutcomeTransitionV1::Resolve(evaluation.terminal_evidence().unwrap()),
        )
        .is_err());
}
