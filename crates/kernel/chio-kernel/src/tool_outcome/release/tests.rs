use super::*;
use crate::admission_operation::{
    verified_pre_dispatch_compensation_projection, verify_economic_cancellation_terminal_advance,
    AdmissionOperationBindingInputV1, AdmissionOperationBindingV1, AdmissionOperationError,
    AdmissionOperationKind, AdmissionParticipantRequirements, AdmissionProjectionCapabilities,
    AdmissionRequestBindingV1, AuthenticatedRequestNamespace, SideEffectClass,
    SignedAdmissionTerminalProjectionV1,
};
use crate::dispatch_status::{
    qualify_dispatch_status_provider_for_test, resolve_dispatch_status,
    AuthenticatedProviderAcceptance, AuthenticatedProviderCompletedOutcome,
    AuthenticatedProviderNotAccepted, DispatchStatusProvider, DispatchStatusProviderError,
    ProviderDispatchStatusObservation, QualifiedDispatchStatusProvider, VerifiedDispatchStatus,
    VerifiedProviderNotAccepted,
};
use crate::tool_outcome::tests::{
    admission_digest, advance, committed_broker_operation, committed_operation, id,
    prepared_operation, projection_context, projection_context_under, provider_attempt, resolve,
    returned, successor_fence,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core_types::economic_continuity::{
    verify_economic_effect_cancellation_advance, verify_economic_state_batch_advance,
    verify_economic_state_view, EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
    EconomicAdmissionHandoffVerifier, EconomicContentV1, EconomicEffectCancellationProofVerifier,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicNoEffectKindV1, EconomicRequestBindingV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchorError, EconomicStateAnchorPins,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, EconomicStateTransitionV1,
    EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicEffectCancellationAdvance, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_core_types::provider_attempt::{
    ProviderAcceptanceBindingV1, ProviderAttemptPhaseV1, ProviderCancellationBindingV1,
    ProviderCompletionBindingV1, ProviderInvocationBlobBindingV1,
    PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA, PROVIDER_CANCELLATION_SCHEMA,
    PROVIDER_INVOCATION_BLOB_SCHEMA,
};
use std::sync::Arc;

fn query_record(
    name: &str,
    attachments: Vec<AdmissionAttachment>,
    observed_at_unix_ms: u64,
) -> ParticipantQueryRecordV1 {
    ParticipantQueryRecordV1::for_test(
        id(&format!("{name}-record")),
        admission_digest(name),
        attachments,
        observed_at_unix_ms,
    )
}

fn not_dispatched(operation: &AdmissionOperationV1) -> VerifiedParticipantNoEffectV1 {
    VerifiedParticipantNoEffectV1::not_dispatched(
        operation,
        query_record("transport-not-dispatched", Vec::new(), 1_000),
    )
    .unwrap()
}

fn no_effect_dispositions(
    operation: &AdmissionOperationV1,
) -> PreDispatchParticipantDispositionsV1 {
    let broker = match operation.provider_attempt() {
        Some(attempt) => VerifiedParticipantNoEffectV1::released_before_dispatch(
            operation,
            ReleaseParticipantV1::Broker,
            query_record(
                "broker-released",
                vec![AdmissionAttachment::BrokerAttempt(attempt.clone())],
                1_000,
            ),
        )
        .unwrap(),
        None => VerifiedParticipantNoEffectV1::never_acquired(
            operation,
            ReleaseParticipantV1::Broker,
            query_record("broker-never-acquired", Vec::new(), 1_000),
        )
        .unwrap(),
    };
    PreDispatchParticipantDispositionsV1::from_verified_parts(
        broker,
        VerifiedParticipantNoEffectV1::never_acquired(
            operation,
            ReleaseParticipantV1::Budget,
            query_record("budget-never-acquired", Vec::new(), 1_000),
        )
        .unwrap(),
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        not_dispatched(operation),
    )
}

fn predispatch_proof(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
) -> VerifiedPreDispatchNoEffect {
    VerifiedPreDispatchNoEffect::from_verified_snapshot(
        operation,
        context,
        no_effect_dispositions(operation),
        serde_json::json!({"policy": "release-v1"}),
    )
    .unwrap()
}

fn predispatch_bundle() -> (
    AdmissionOperationV1,
    AdmissionProjectionContext,
    MonetaryReleaseEvidenceV1,
) {
    let operation = prepared_operation("request-release");
    let context = projection_context(&operation);
    let proof = predispatch_proof(&operation, &context);
    let bundle = MonetaryReleaseAuthority::NoEffect(VerifiedNoEffectProof::BeforeDispatch(proof))
        .evidence_bundle()
        .unwrap();
    (operation, context, bundle)
}

fn prepared_channel_operation(
    request_id: &str,
) -> Result<AdmissionOperationV1, AdmissionOperationError> {
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(id(
            "channel-release-coordinator",
        ))?,
        request_id: id(request_id),
        capability_id: id("channel-release-capability"),
        authorization_capability_hash: admission_digest("channel-release-authorization"),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("channel-release-request"),
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                obligation: true,
                channel: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: admission_digest("channel-release-policy"),
        effect_class: SideEffectClass::Monetary,
    })?;
    AdmissionOperationV1::prepare(binding, 7)
}

#[test]
fn released_predispatch_manifest_covers_reserved_credit_exposure(
) -> Result<(), Box<dyn std::error::Error>> {
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::for_local_system(id(
            "credit-release-coordinator",
        ))?,
        request_id: id("request-credit-release"),
        capability_id: id("credit-release-capability"),
        authorization_capability_hash: admission_digest("credit-release-authorization"),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("credit-release-request"),
            AdmissionParticipantRequirements {
                broker_attempt: true,
                budget_capture: true,
                obligation: true,
                credit_exposure: true,
                ..AdmissionParticipantRequirements::NONE
            },
        )?,
        policy_hash: admission_digest("credit-release-policy"),
        effect_class: SideEffectClass::Monetary,
    })?;
    let prepared = AdmissionOperationV1::prepare(binding, 7)?;
    let broker = advance(
        &prepared,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &prepared,
            "credit-release-attempt",
        ))],
    );
    let attached = advance(
        &broker,
        AdmissionOperationState::BudgetAuthorized,
        vec![
            AdmissionAttachment::BudgetHoldId(id("credit-release-hold")),
            AdmissionAttachment::CreditExposureReservationDigest(admission_digest(
                "credit-release-reservation",
            )),
        ],
    );
    let proof = VerifiedPreDispatchNoEffect::from_qualified_released_operation_snapshot(
        &attached,
        &projection_context(&attached),
        serde_json::json!({"policy": "credit-release-v1"}),
    )?;

    assert!(proof
        .snapshot
        .participant_manifest
        .required_participants
        .contains(&ReleaseParticipantV1::CreditExposure));
    assert!(matches!(
        proof
            .snapshot
            .participant_manifest
            .participant_dispositions
            .credit_exposure,
        VerifiedParticipantNoEffectV1::ReleasedBeforeDispatch { .. }
    ));
    Ok(())
}

#[test]
fn channel_reservation_requires_typed_predispatch_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepared_channel_operation("request-channel-release")?;
    let prepared_context = projection_context(&prepared);
    let prepared_proof = VerifiedPreDispatchNoEffect::from_qualified_operation_snapshot(
        &prepared,
        &prepared_context,
    )?;
    assert!(prepared_proof
        .snapshot
        .participant_manifest
        .required_participants
        .contains(&ReleaseParticipantV1::Channel));
    assert!(matches!(
        &prepared_proof
            .snapshot
            .participant_manifest
            .participant_dispositions
            .channel,
        VerifiedParticipantNoEffectV1::NeverAcquired { .. }
    ));
    assert!(
        verified_pre_dispatch_compensation_projection(&prepared, prepared_context.clone()).is_ok()
    );

    let proposal = AdmissionAttachment::ChannelReservationProposalDigest(admission_digest(
        "channel-release-proposal",
    ));
    let broker = advance(
        &prepared,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![
            AdmissionAttachment::BrokerAttempt(provider_attempt(
                &prepared,
                "channel-release-attempt",
            )),
            proposal,
        ],
    );
    assert!(participant_attachments(&broker, ReleaseParticipantV1::Channel).is_empty());
    let budget = advance(
        &broker,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(id(
            "channel-release-hold",
        ))],
    );
    let reservation = AdmissionAttachment::ChannelReservationDigest(admission_digest(
        "channel-release-reservation",
    ));
    let ready = advance(
        &budget,
        AdmissionOperationState::ReadyToDispatch,
        vec![reservation.clone()],
    );
    assert_eq!(
        participant_attachments(&ready, ReleaseParticipantV1::Channel),
        vec![reservation]
    );
    let capture = advance(&ready, AdmissionOperationState::CapturePending, Vec::new());

    for operation in [&ready, &capture] {
        assert_eq!(
            VerifiedPreDispatchNoEffect::from_qualified_operation_snapshot(
                operation,
                &projection_context(operation),
            ),
            Err(ToolOutcomeError::Binding(
                "predispatch.channel_cancellation_required"
            ))
        );
        assert!(verified_pre_dispatch_compensation_projection(
            operation,
            projection_context(operation),
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn qualified_pre_dispatch_snapshot_rejects_an_acquired_participant() {
    let prepared = prepared_operation("request-qualified-predispatch");
    let prepared_context = projection_context(&prepared);
    assert!(
        VerifiedPreDispatchNoEffect::from_qualified_operation_snapshot(
            &prepared,
            &prepared_context
        )
        .is_ok()
    );

    let broker = advance(
        &prepared,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &prepared,
            "attempt-qualified-predispatch",
        ))],
    );
    assert!(
        VerifiedPreDispatchNoEffect::from_qualified_operation_snapshot(
            &broker,
            &projection_context(&broker)
        )
        .is_err()
    );
}

fn economic_cancellation(
    operation: &AdmissionOperationV1,
    kind: EconomicNoEffectKindV1,
) -> Result<VerifiedEconomicEffectCancellationAdvance, Box<dyn std::error::Error>> {
    struct Direct(EconomicNoEffectKindV1);
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
            Ok(self.0)
        }
    }

    fn signed_view(
        keypair: &Keypair,
        sequence: u64,
        checkpoint_digest: String,
        head: EconomicResourceHeadV1,
    ) -> Result<EconomicStateAnchorViewV1, Box<dyn std::error::Error>> {
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
            observed_at: 900 + sequence,
            signer_key_id: "anchor-key-1".to_owned(),
            signer_key_epoch: 1,
            anchor_signature: String::new(),
        };
        view.seal(keypair)?;
        Ok(view)
    }

    fn head(
        slot: &EconomicEffectSlotV1,
        version: u64,
        predecessor_digest: Option<String>,
    ) -> Result<EconomicResourceHeadV1, Box<dyn std::error::Error>> {
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
            trusted_clock_high_water: 900 + version,
            predecessor_digest,
        })
    }

    let context = projection_context(operation);
    let (target_id, target_key_epoch) = operation.provider_attempt().map_or_else(
        || ("economic-mutation-participant".to_owned(), 1),
        |attempt| (attempt.transport_id.clone(), attempt.transport_key_epoch),
    );
    let keypair = Keypair::from_seed(&[0x51; 32]);
    let pins = EconomicStateAnchorPins {
        anchor_id: "anchor-1".to_owned(),
        namespace: "economy-prod".to_owned(),
        signer_key_id: "anchor-key-1".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: PublicKey::from_bytes(keypair.public_key().as_bytes())?,
    };
    let mut slot = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: pins.anchor_id.clone(),
        namespace: pins.namespace.clone(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "tool_dispatch".to_owned(),
            scope_id: "local-system".to_owned(),
            resource_id: operation.binding().operation_id().as_str().to_owned(),
        },
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        effect_kind: "tool_dispatch".to_owned(),
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
            state: match operation.binding().kind() {
                AdmissionOperationKind::GovernedEconomicMutation => {
                    EconomicAdmissionHandoffStateV1::MutationSubmitted
                }
                _ => EconomicAdmissionHandoffStateV1::DispatchCommitted,
            },
            operation_version: operation.version(),
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: context.store_fence,
        },
        target: EconomicEffectTargetV1 {
            target_id,
            target_key_epoch,
            qualification_digest: admission_digest("economic-target").as_str().to_owned(),
        },
        action_digest: admission_digest("economic-action").as_str().to_owned(),
        parameters_digest: operation
            .binding()
            .action_parameter_hash()
            .as_str()
            .to_owned(),
        resource_head_digest: admission_digest("economic-resource").as_str().to_owned(),
        frost: None,
        idempotency_key: admission_digest("economic-idempotency").as_str().to_owned(),
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    slot.slot_id = slot.recompute_slot_id()?;
    let ready_head = head(&slot, 1, None)?;
    let ready_digest = ready_head.digest()?;
    let current = verify_economic_state_view(
        signed_view(
            &keypair,
            1,
            admission_digest("checkpoint-1").as_str().to_owned(),
            ready_head,
        )?,
        &pins,
    )?;
    let proof = EconomicContentV1::Inline {
        value: serde_json::json!({"notAccepted": true}),
    };
    slot.state = EconomicEffectStateV1::NoEffect;
    slot.terminal = Some(EconomicEffectTerminalV1::NoEffect {
        kind,
        proof_id: "economic-cancellation-1".to_owned(),
        proof_digest: proof.digest()?,
        proof,
    });
    let cancelled_head = head(&slot, 2, Some(ready_digest.clone()))?;
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
            transition_proof_digest: admission_digest("transition-proof").as_str().to_owned(),
            prepared_effect: None,
        }],
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(slot.operation_id.clone()),
        issued_at: 902,
        signer_key_id: pins.signer_key_id.clone(),
        signer_key_epoch: pins.signer_key_epoch,
        anchor_signature: String::new(),
    };
    batch.seal(&keypair)?;
    let verifier = Direct(kind);
    let advance = verify_economic_state_batch_advance(&current, batch, &pins, &verifier)?;
    Ok(verify_economic_effect_cancellation_advance(
        advance, &verifier, &verifier,
    )?)
}

#[test]
fn external_effect_cancellation_constructs_bound_transport_no_acceptance() {
    let operation = committed_operation("request-economic-cancellation");
    let context = projection_context(&operation);
    let cancellation = economic_cancellation(
        &operation,
        EconomicNoEffectKindV1::VerifiedTransportNotAccepted,
    )
    .unwrap();

    let proof = VerifiedTransportNotAccepted::from_verified_economic_effect(
        &cancellation,
        &operation,
        &context,
    )
    .unwrap();
    proof.validate_against(&operation, &context).unwrap();
    let projection = crate::admission_operation::verified_economic_cancellation_projection(
        &operation,
        context.clone(),
        &cancellation,
    )
    .unwrap();
    assert!(projection.requires_anchored_economic_commit());
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &AdmissionProjectionCapabilities {
            operation_terminal: true,
            incident_terminal: true,
            ..AdmissionProjectionCapabilities::default()
        },
        &Keypair::from_seed(&[0x52; 32]),
    )
    .unwrap();
    let verified = envelope.verify().unwrap();
    assert!(verified.requires_anchored_economic_commit());
    assert_eq!(
        verify_economic_cancellation_terminal_advance(
            cancellation.state_advance().current().view(),
            cancellation.batch(),
            &verified,
        )
        .unwrap(),
        cancellation.slot().clone()
    );
    let mut substituted_batch = cancellation.batch().clone();
    substituted_batch.checkpoint_digest = admission_digest("substituted-checkpoint")
        .as_str()
        .to_owned();
    assert!(verify_economic_cancellation_terminal_advance(
        cancellation.state_advance().current().view(),
        &substituted_batch,
        &verified,
    )
    .is_err());
    assert!(matches!(
        projection,
        crate::admission_operation::AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit { .. }
    ));

    let sibling = committed_operation("request-economic-cancellation-sibling");
    assert!(VerifiedTransportNotAccepted::from_verified_economic_effect(
        &cancellation,
        &sibling,
        &projection_context(&sibling),
    )
    .is_err());
}

#[test]
fn kernel_url_elicitation_constructs_a_bound_post_commit_no_effect_terminal() {
    let operation = committed_operation("request-kernel-url-elicitation");
    let context = projection_context(&operation);
    let elicitations = vec![crate::CreateElicitationOperation::Url {
        meta: None,
        message: "Authorize the provider URL".to_owned(),
        url: "https://provider.example/authorize".to_owned(),
        elicitation_id: "elicitation-1".to_owned(),
    }];

    let projection = crate::admission_operation::verified_url_elicitation_no_effect_projection(
        &operation,
        context.clone(),
        "URL elicitation required before tool execution",
        &elicitations,
    )
    .unwrap();
    let crate::admission_operation::AdmissionTerminalProjection::NotAcceptedAfterDispatchCommit {
        proof,
        ..
    } = projection
    else {
        panic!("URL elicitation must produce the post-commit no-effect terminal");
    };
    proof.validate_against(&operation, &context).unwrap();

    let sibling = committed_operation("request-kernel-url-elicitation-sibling");
    assert!(proof
        .validate_against(&sibling, &projection_context(&sibling))
        .is_err());

    let form_elicitation = [crate::CreateElicitationOperation::Form {
        meta: None,
        message: "not a URL result".to_owned(),
        requested_schema: serde_json::json!({"type": "object"}),
    }];
    assert!(VerifiedTransportNotAccepted::from_kernel_url_elicitation(
        "form elicitation",
        &form_elicitation,
        &operation,
        &context,
    )
    .is_err());

    assert!(VerifiedTransportNotAccepted::from_kernel_url_elicitation(
        &"m".repeat(MAX_KERNEL_URL_ELICITATION_MESSAGE_BYTES + 1),
        &elicitations,
        &operation,
        &context,
    )
    .is_err());
    let too_many = vec![elicitations[0].clone(); MAX_KERNEL_URL_ELICITATIONS + 1];
    assert!(VerifiedTransportNotAccepted::from_kernel_url_elicitation(
        "bounded count",
        &too_many,
        &operation,
        &context,
    )
    .is_err());
    let mut deep_meta = serde_json::Value::Null;
    for _ in 0..=MAX_KERNEL_URL_ELICITATION_META_DEPTH {
        deep_meta = serde_json::json!({"nested": deep_meta});
    }
    let deeply_nested = [crate::CreateElicitationOperation::Url {
        meta: Some(deep_meta),
        message: "Authorize the provider URL".to_owned(),
        url: "https://provider.example/authorize".to_owned(),
        elicitation_id: "elicitation-deep".to_owned(),
    }];
    assert!(VerifiedTransportNotAccepted::from_kernel_url_elicitation(
        "bounded metadata",
        &deeply_nested,
        &operation,
        &context,
    )
    .is_err());
}

fn submitted_mutation_operation(request_id: &str) -> AdmissionOperationV1 {
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedEconomicMutation,
        namespace: AuthenticatedRequestNamespace::for_local_system(id("coordinator-1")).unwrap(),
        request_id: id(request_id),
        capability_id: id("economic-mutation-capability"),
        authorization_capability_hash: admission_digest("economic-mutation-authorization"),
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("economic-mutation-request"),
            AdmissionParticipantRequirements::NONE,
        )
        .unwrap(),
        policy_hash: admission_digest("economic-mutation-policy"),
        effect_class: SideEffectClass::Monetary,
    })
    .unwrap();
    let prepared = AdmissionOperationV1::prepare(binding, 7).unwrap();
    let ready = advance(
        &prepared,
        AdmissionOperationState::MutationReady,
        Vec::new(),
    );
    advance(
        &ready,
        AdmissionOperationState::MutationSubmitted,
        Vec::new(),
    )
}

#[test]
fn external_effect_cancellation_constructs_bound_permanently_not_applied_result() {
    let operation = submitted_mutation_operation("request-mutation-cancellation");
    let context = projection_context(&operation);
    let cancellation =
        economic_cancellation(&operation, EconomicNoEffectKindV1::PermanentlyNotApplied).unwrap();

    let projection = crate::admission_operation::verified_economic_cancellation_projection(
        &operation,
        context,
        &cancellation,
    )
    .unwrap();
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &AdmissionProjectionCapabilities {
            operation_terminal: true,
            economic_mutation_terminal: true,
            ..AdmissionProjectionCapabilities::default()
        },
        &Keypair::from_seed(&[0x53; 32]),
    )
    .unwrap();
    assert!(verify_economic_cancellation_terminal_advance(
        cancellation.state_advance().current().view(),
        cancellation.batch(),
        &envelope.verify().unwrap(),
    )
    .is_ok());
    assert!(matches!(
        projection,
        crate::admission_operation::AdmissionTerminalProjection::EconomicMutationNotApplied { .. }
    ));
}

#[test]
fn release_evidence_has_one_owned_canonical_encoding() {
    let (_, _, bundle) = predispatch_bundle();
    let bytes = bundle.canonical_bytes().unwrap();
    assert_eq!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&bytes).unwrap(),
        bundle
    );

    let mut unknown_schema = bundle.to_persisted();
    unknown_schema.schema = "chio.monetary-release-evidence.v9".to_owned();
    assert!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&canonical(&unknown_schema).unwrap())
            .is_err()
    );

    let mut unknown_field = serde_json::to_value(bundle.to_persisted()).unwrap();
    unknown_field
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&canonical(&unknown_field).unwrap())
            .is_err()
    );

    let mut unknown_source = bundle.to_persisted();
    let source_bytes = BASE64
        .decode(&unknown_source.source_binding_base64)
        .unwrap();
    let mut source: Value = serde_json::from_slice(&source_bytes).unwrap();
    source
        .as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), Value::Bool(true));
    let source_bytes = canonical(&source).unwrap();
    unknown_source.source_binding_base64 = BASE64.encode(&source_bytes);
    unknown_source.source_binding_digest =
        digest_bytes("test_source_binding", &source_bytes).unwrap();
    assert!(MonetaryReleaseEvidenceV1::from_persisted(unknown_source).is_err());

    let mut noncanonical = vec![b' '];
    noncanonical.extend_from_slice(&bytes);
    assert!(MonetaryReleaseEvidenceV1::from_canonical_bytes(&noncanonical).is_err());
    assert!(matches!(
        MonetaryReleaseEvidenceV1::from_canonical_bytes(&vec![
            b' ';
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES
                + 1
        ]),
        Err(ToolOutcomeError::TooLarge { .. })
    ));
}

#[test]
fn release_evidence_kinds_and_artifacts_cannot_be_substituted() {
    let (_, _, bundle) = predispatch_bundle();
    let mut wrong_kind = bundle.clone();
    wrong_kind.evidence_kind = MonetaryReleaseEvidenceKindV1::NotAcceptedAfterDispatch;
    assert!(wrong_kind.validate().is_err());

    let mut changed_artifact = bundle;
    changed_artifact.source_artifacts[0].value = serde_json::json!({"substituted": true});
    assert!(changed_artifact.validate().is_err());
}

#[test]
fn persisted_release_recovery_enforces_fence_time_and_coordinator_lineage() {
    let (operation, context, bundle) = predispatch_bundle();
    bundle
        .validate_recovery_context(&operation, &context)
        .unwrap();

    let mut successor = projection_context_under(&operation, successor_fence(10));
    successor.coordinator_lease_id = id("coordinator-lease-2");
    successor.trusted_time_unix_ms = 1_100;
    bundle
        .validate_recovery_context(&operation, &successor)
        .unwrap();

    let mut lower = projection_context_under(&operation, successor_fence(8));
    lower.trusted_time_unix_ms = 1_100;
    assert!(bundle
        .validate_recovery_context(&operation, &lower)
        .is_err());

    let mut cross_store = successor.clone();
    cross_store.store_fence.store_uuid = "other-store".to_owned();
    assert!(bundle
        .validate_recovery_context(&operation, &cross_store)
        .is_err());

    let mut same_epoch_new_store_lease = context.clone();
    same_epoch_new_store_lease.store_fence.lease_id = "other-store-lease".to_owned();
    assert!(bundle
        .validate_recovery_context(&operation, &same_epoch_new_store_lease)
        .is_err());

    let mut same_fence_new_coordinator = context.clone();
    same_fence_new_coordinator.coordinator_lease_id = id("coordinator-lease-other");
    assert!(bundle
        .validate_recovery_context(&operation, &same_fence_new_coordinator)
        .is_err());

    let mut rolled_back_time = context.clone();
    rolled_back_time.trusted_time_unix_ms = 999;
    assert!(bundle
        .validate_recovery_context(&operation, &rolled_back_time)
        .is_err());

    let substituted_epoch = bundle
        .with_projection_epoch_for_test(context.coordinator_lease_epoch + 1)
        .unwrap();
    assert!(substituted_epoch
        .validate_recovery_context(&operation, &context)
        .is_err());
    let substituted_request = bundle
        .with_request_binding_hash_for_test(admission_digest("other-request-binding"))
        .unwrap();
    assert!(substituted_request
        .validate_recovery_context(&operation, &context)
        .is_err());

    assert!(matches!(
        bundle.revalidate_authority(&operation, &context),
        Err(ToolOutcomeError::ReleaseAuthorityUnavailable(_))
    ));
}

#[test]
fn predispatch_manifest_binds_required_participants_and_exact_attachments() {
    let prepared = prepared_operation("request-release-participants");
    let context = projection_context(&prepared);

    let mut extra_attachment = no_effect_dispositions(&prepared);
    extra_attachment.budget = VerifiedParticipantNoEffectV1::never_acquired(
        &prepared,
        ReleaseParticipantV1::Budget,
        query_record(
            "budget-extra",
            vec![AdmissionAttachment::BudgetHoldId(id("unbound-hold"))],
            1_000,
        ),
    )
    .unwrap();
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &prepared,
        &context,
        extra_attachment,
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());

    let broker = advance(
        &prepared,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &prepared,
            "attempt-release",
        ))],
    );
    let budget = advance(
        &broker,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(id("hold-release"))],
    );
    let budget_context = projection_context(&budget);
    let released = |attachments| {
        VerifiedParticipantNoEffectV1::released_before_dispatch(
            &budget,
            ReleaseParticipantV1::Budget,
            query_record("budget-released", attachments, 1_000),
        )
        .unwrap()
    };
    let dispositions = |budget_disposition| {
        PreDispatchParticipantDispositionsV1::from_verified_parts(
            no_effect_dispositions(&budget).broker,
            budget_disposition,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            VerifiedParticipantNoEffectV1::NotRequired,
            not_dispatched(&budget),
        )
    };

    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &budget,
        &budget_context,
        dispositions(released(Vec::new())),
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &budget,
        &budget_context,
        dispositions(released(vec![AdmissionAttachment::BrokerAttempt(
            provider_attempt(&budget, "wrong-slot"),
        )])),
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());

    let proof = VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &budget,
        &budget_context,
        dispositions(released(vec![AdmissionAttachment::BudgetHoldId(id(
            "hold-release",
        ))])),
        serde_json::json!({"policy": "release-v1"}),
    )
    .unwrap();
    let mut missing_required = proof.clone();
    missing_required
        .snapshot
        .participant_manifest
        .required_participants
        .retain(|participant| *participant != ReleaseParticipantV1::Transport);
    assert!(missing_required
        .validate_against(&budget, &budget_context)
        .is_err());

    let mut extra_required = proof;
    extra_required
        .snapshot
        .participant_manifest
        .required_participants
        .push(ReleaseParticipantV1::Payment);
    assert!(extra_required
        .validate_against(&budget, &budget_context)
        .is_err());
}

#[test]
fn predispatch_release_rejects_evidence_and_future_time_substitution() {
    let prepared = prepared_operation("request-release-substitution");
    let mut budget_evidence = VerifiedParticipantNoEffectV1::never_acquired(
        &prepared,
        ReleaseParticipantV1::Budget,
        query_record("budget-tampered", Vec::new(), 1_000),
    )
    .unwrap();
    let VerifiedParticipantNoEffectV1::NeverAcquired { evidence } = &mut budget_evidence else {
        unreachable!();
    };
    evidence.evidence_digest = admission_digest("tampered-participant-evidence");
    let dispositions = PreDispatchParticipantDispositionsV1::from_verified_parts(
        VerifiedParticipantNoEffectV1::NotRequired,
        budget_evidence,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        VerifiedParticipantNoEffectV1::NotRequired,
        not_dispatched(&prepared),
    );
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &prepared,
        &projection_context(&prepared),
        dispositions,
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());

    let mut future = no_effect_dispositions(&prepared);
    future.budget = VerifiedParticipantNoEffectV1::never_acquired(
        &prepared,
        ReleaseParticipantV1::Budget,
        query_record("budget-future", Vec::new(), 1_001),
    )
    .unwrap();
    assert!(VerifiedPreDispatchNoEffect::from_verified_snapshot(
        &prepared,
        &projection_context(&prepared),
        future,
        serde_json::json!({"policy": "release-v1"}),
    )
    .is_err());
}

#[test]
fn contractual_zero_charge_requires_exact_typed_terminal_records() {
    let operation = committed_operation("request-zero");
    let returned_record = returned(&operation, serde_json::json!(1));
    let (zero_outcome, zero_evaluation) = resolve(
        &operation,
        &returned_record,
        SettlementDispositionV1::ContractualZeroCharge {
            currency: "USD".to_owned(),
        },
    );
    let context = projection_context(&operation);
    let proof = VerifiedContractualZeroCharge::from_records(
        &operation,
        &context,
        &zero_outcome,
        &zero_evaluation,
    )
    .unwrap();
    let authority = MonetaryReleaseAuthority::ContractualZeroCharge(Box::new(proof));
    let bundle = authority.evidence_bundle().unwrap();
    MonetaryReleaseEvidenceV1::from_canonical_bytes(&bundle.canonical_bytes().unwrap()).unwrap();

    let mut substituted = bundle.clone();
    substituted.source_artifacts[0].value["request_id"] = Value::String("other-request".to_owned());
    substituted.source_artifacts[0].digest = digest_bytes(
        "substituted_artifact",
        &bounded(
            "substituted_artifact",
            &substituted.source_artifacts[0].value,
            MAX_EVIDENCE_ARTIFACT_BYTES,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(substituted.validate().is_err());

    let (capture_outcome, capture_evaluation) = resolve(
        &operation,
        &returned_record,
        SettlementDispositionV1::Capture {
            amount: MonetaryAmount {
                units: 1,
                currency: "USD".to_owned(),
            },
        },
    );
    assert!(VerifiedContractualZeroCharge::from_records(
        &operation,
        &context,
        &capture_outcome,
        &capture_evaluation,
    )
    .is_err());

    let other_operation = committed_operation("request-other");
    let other = returned(&other_operation, serde_json::json!(1));
    let (other_outcome, _) = resolve(
        &other_operation,
        &other,
        SettlementDispositionV1::NotApplicable,
    );
    assert!(VerifiedContractualZeroCharge::from_records(
        &operation,
        &context,
        &other_outcome,
        &zero_evaluation,
    )
    .is_err());
}

#[derive(Clone)]
struct ReleaseStatusProvider {
    checkpoints: Vec<ProviderAttemptCheckpointV1>,
    cancellation: ProviderCancellationBindingV1,
}

impl DispatchStatusProvider for ReleaseStatusProvider {
    fn transport_id(&self) -> &str {
        "qualified-release-provider"
    }

    fn transport_key_epoch(&self) -> u64 {
        7
    }

    fn status(
        &self,
        _query: &DispatchStatusQuery,
    ) -> Result<ProviderDispatchStatusObservation, DispatchStatusProviderError> {
        Ok(ProviderDispatchStatusObservation::Checkpoints(
            self.checkpoints.clone(),
        ))
    }

    fn fetch_acceptance(
        &self,
        _binding: &ProviderAcceptanceBindingV1,
    ) -> Result<AuthenticatedProviderAcceptance, DispatchStatusProviderError> {
        Err(DispatchStatusProviderError::new("unused acceptance"))
    }

    fn fetch_not_accepted(
        &self,
        _binding: &ProviderCancellationBindingV1,
    ) -> Result<AuthenticatedProviderNotAccepted, DispatchStatusProviderError> {
        Ok(AuthenticatedProviderNotAccepted {
            binding: self.cancellation.clone(),
            proof: b"cancelled".to_vec(),
        })
    }

    fn fetch_completed_outcome(
        &self,
        _binding: &ProviderCompletionBindingV1,
    ) -> Result<AuthenticatedProviderCompletedOutcome, DispatchStatusProviderError> {
        Err(DispatchStatusProviderError::new("unused completion"))
    }
}

fn verified_not_accepted_case(
    operation: &AdmissionOperationV1,
    attempt_id: &str,
    continuity_anchor: &str,
) -> (
    QualifiedDispatchStatusProvider,
    DispatchStatusQuery,
    VerifiedProviderNotAccepted,
) {
    let attempt = operation
        .provider_attempt()
        .filter(|attempt| attempt.attempt_id == attempt_id)
        .cloned()
        .expect("test operation must bind the requested provider attempt");
    let blob = ProviderInvocationBlobBindingV1 {
        schema: PROVIDER_INVOCATION_BLOB_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        request_digest: operation
            .binding()
            .request_binding_hash()
            .as_str()
            .to_owned(),
        idempotency_key: attempt.operation_id.clone(),
        blob_ref: format!("cas://release-invocation/{attempt_id}"),
        blob_sha256: sha256_hex(b"release-invocation"),
        blob_size_bytes: 18,
        availability_ref: format!("anchor://release-invocation/{attempt_id}"),
        availability_sha256: sha256_hex(b"release-availability"),
    };
    let cancellation = ProviderCancellationBindingV1 {
        schema: PROVIDER_CANCELLATION_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        cancellation_ref: format!("provider://release-cancelled/{attempt_id}"),
        cancelled_at: 900,
        cancellation_fence: 4,
        invocation_blob_digest: blob.digest().unwrap(),
        no_acceptance_proof_sha256: sha256_hex(b"cancelled"),
        no_acceptance_proof_size_bytes: 9,
    };
    let pending = ProviderAttemptCheckpointV1 {
        schema: PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        checkpoint_sequence: 1,
        previous_checkpoint_digest: None,
        phase: ProviderAttemptPhaseV1::Pending {
            invocation_blob: blob.clone(),
        },
    };
    let cancelled = ProviderAttemptCheckpointV1 {
        schema: PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA.to_owned(),
        attempt: attempt.clone(),
        checkpoint_sequence: 2,
        previous_checkpoint_digest: Some(pending.digest().unwrap()),
        phase: ProviderAttemptPhaseV1::Cancelled {
            invocation_blob: blob,
            cancellation: cancellation.clone(),
        },
    };
    let qualification = qualify_dispatch_status_provider_for_test(
        Arc::new(ReleaseStatusProvider {
            checkpoints: vec![pending, cancelled],
            cancellation,
        }),
        "release-ed25519-verifier",
        continuity_anchor,
        11,
        "chio.release-provider-status.v1",
    )
    .unwrap();
    let query = DispatchStatusQuery {
        attempt,
        last_checkpoint: None,
        observed_at: 950,
    };
    let VerifiedDispatchStatus::NotAccepted(status) =
        resolve_dispatch_status(Some(&qualification), &query).unwrap()
    else {
        panic!("test provider must return verified non-acceptance");
    };
    (qualification, query, status)
}

#[test]
fn transport_release_rejects_same_attempt_cancellation_substitution() {
    let operation = committed_broker_operation("request-transport-release", "attempt-release");
    let (first, query, status) =
        verified_not_accepted_case(&operation, "attempt-release", "continuity-anchor-a");
    let (second, _, _) =
        verified_not_accepted_case(&operation, "attempt-release", "continuity-anchor-b");
    let context = projection_context(&operation);
    let commit = operation.dispatch_commit().unwrap();
    let proof = VerifiedTransportNotAccepted::from_verified_provider(
        &status,
        &first,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .unwrap();
    let bundle = MonetaryReleaseAuthority::NoEffect(
        VerifiedNoEffectProof::NotAcceptedAfterDispatch(Box::new(proof)),
    )
    .evidence_bundle()
    .unwrap();
    MonetaryReleaseEvidenceV1::from_persisted(bundle.to_persisted()).unwrap();

    let mut substituted_cancellation = status.cancellation().clone();
    substituted_cancellation.cancellation_ref =
        "provider://same-attempt-substituted-cancellation".to_owned();
    let substituted_status = status.with_cancellation_for_test(substituted_cancellation.clone());
    assert!(VerifiedTransportNotAccepted::from_verified_provider(
        &substituted_status,
        &first,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .is_err());

    let mut persisted = bundle.to_persisted();
    let checkpoint = persisted.source_artifacts[1].clone();
    persisted.source_artifacts[0].evidence_id = id(&substituted_cancellation.cancellation_ref);
    persisted.source_artifacts[0].value["cancellation"] =
        serde_json::to_value(&substituted_cancellation).unwrap();
    persisted.source_artifacts[0].digest = digest_bytes(
        "release_artifact.digest",
        &bounded(
            "release_artifact.value",
            &persisted.source_artifacts[0].value,
            MAX_EVIDENCE_ARTIFACT_BYTES,
        )
        .unwrap(),
    )
    .unwrap();

    let cancellation_digest = imported_digest(
        "transport_release.signed_status_digest",
        substituted_cancellation.digest().unwrap(),
    )
    .unwrap();
    let source_bytes = BASE64.decode(&persisted.source_binding_base64).unwrap();
    let mut source: Value = serde_json::from_slice(&source_bytes).unwrap();
    source["binding"]["signed_status_digest"] = serde_json::to_value(cancellation_digest).unwrap();
    let source_bytes = canonical(&source).unwrap();
    persisted.source_binding_base64 = BASE64.encode(&source_bytes);
    persisted.source_binding_digest =
        digest_bytes("release.source_binding_digest", &source_bytes).unwrap();

    let body = serde_json::json!({
        "schema": persisted.schema,
        "evidence_kind": persisted.evidence_kind,
        "operation_id": persisted.operation_id,
        "operation_version": persisted.operation_version,
        "verifier_policy_digest": persisted.verifier_policy_digest,
        "source_binding_base64": persisted.source_binding_base64,
        "source_binding_digest": persisted.source_binding_digest,
        "source_artifacts": persisted.source_artifacts,
    });
    persisted.evidence_id =
        domain_digest("chio.monetary-release-evidence.identity.v1", &body).unwrap();
    persisted.bundle_digest = digest_bytes(
        "release.bundle_digest",
        &bounded(
            "monetary_release_evidence",
            &body,
            MAX_MONETARY_RELEASE_EVIDENCE_BYTES,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(persisted.source_artifacts[1], checkpoint);
    assert_eq!(
        MonetaryReleaseEvidenceV1::from_persisted(persisted).unwrap_err(),
        ToolOutcomeError::Binding("transport_release.artifacts")
    );

    assert!(VerifiedTransportNotAccepted::from_verified_provider(
        &status,
        &second,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .is_err());
}

#[test]
fn transport_release_binds_registered_broker_attempt() {
    let operation = committed_broker_operation("request-transport-broker", "attempt-release");
    let sibling = committed_broker_operation("request-transport-broker", "attempt-sibling");
    assert_eq!(
        operation.binding().operation_id(),
        sibling.binding().operation_id()
    );
    assert_eq!(operation.replay_key(), sibling.replay_key());
    assert_ne!(operation.dispatch_commit(), sibling.dispatch_commit());

    let context = projection_context(&operation);
    let commit = operation.dispatch_commit().unwrap();
    let (qualification, query, status) =
        verified_not_accepted_case(&operation, "attempt-release", "continuity-anchor-target");
    let proof = VerifiedTransportNotAccepted::from_verified_provider(
        &status,
        &qualification,
        &query,
        &operation,
        commit,
        &context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .unwrap();
    proof.validate_against(&operation, &context).unwrap();

    let sibling_context = projection_context(&sibling);
    let sibling_commit = sibling.dispatch_commit().unwrap();
    let (sibling_qualification, sibling_query, sibling_status) =
        verified_not_accepted_case(&sibling, "attempt-sibling", "continuity-anchor-sibling");
    assert_eq!(
        VerifiedTransportNotAccepted::from_verified_provider(
            &sibling_status,
            &sibling_qualification,
            &sibling_query,
            &operation,
            commit,
            &context,
            id("release-verifier"),
            serde_json::json!({"policy": "transport-release-v1"}),
        )
        .unwrap_err(),
        ToolOutcomeError::Binding("transport_not_accepted.provider")
    );

    let sibling_proof = VerifiedTransportNotAccepted::from_verified_provider(
        &sibling_status,
        &sibling_qualification,
        &sibling_query,
        &sibling,
        sibling_commit,
        &sibling_context,
        id("release-verifier"),
        serde_json::json!({"policy": "transport-release-v1"}),
    )
    .unwrap();
    assert_eq!(
        sibling_proof
            .validate_against(&operation, &context)
            .unwrap_err(),
        ToolOutcomeError::Binding("transport_not_accepted.artifacts")
    );
}
