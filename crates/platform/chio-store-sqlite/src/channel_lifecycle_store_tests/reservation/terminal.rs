use chio_core::economic_continuity::{
    EconomicContentV1, EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTerminalV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError,
    EconomicStateTransitionV1, EconomicTerminalResultV1, EconomicTransitionAuthorizationV1,
    EconomicTransitionProofVerifier,
};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::Decision;
use chio_core::receipt::economics::{
    ChannelReceiptMetadataV1, ChannelSettlementModeV1, FinancialReceiptMetadata, SettlementStatus,
    CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA,
};
use chio_core::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_credit::obligation::{
    ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1,
};
use chio_kernel::admission_operation::{
    AdmissionCompensationStatus, AdmissionCompletedProjection, AdmissionDispatchState,
    AdmissionIncident, AdmissionProjectionContext, AdmissionReceiptMetadataV1,
    AdmissionReceiptSchema, AdmissionTerminalProjection, ObservationAttemptZero,
    SignedAdmissionTerminalProjectionV1, VerifiedAdmissionReceipt, ADMISSION_RECEIPT_METADATA_KEY,
};
use chio_kernel::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve, returned_value,
};
use chio_kernel::tool_outcome::{
    sign_channel_terminal_outcome_commitment_for_test, ResolvedToolOutcomeV1,
    SettlementDispositionV1, ToolOutcomeTerminalEvidenceV1,
};
use chio_kernel::ReceiptStore;

use super::*;

const LIVE_AT: u64 = 1_605;
const CAPTURE_AT: u64 = 1_610;
const DISPATCH_AT: u64 = 1_620;
const DISPATCH_ANCHOR_AT: u64 = 1_640;
const OUTCOME_AT: u64 = 1_650;
const FINALIZING_AT: u64 = 1_656;
const TERMINAL_CONTEXT_AT: u64 = 1_660;
const TERMINAL_BATCH_AT: u64 = 1_670;
const TERMINAL_STAGE_AT: u64 = 1_671;
const TERMINAL_ANCHOR_AT: u64 = 1_672;
const TERMINAL_COMMIT_AT: u64 = 1_673;
const RECOVERY_EXPIRES_AT: u64 = 2_400;

struct DirectTransitionVerifier;

impl EconomicTransitionProofVerifier for DirectTransitionVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        _transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Ok(EconomicTransitionAuthorizationV1::Direct)
    }
}

struct StagedTerminal {
    operation: AdmissionOperationV1,
    advance: VerifiedEconomicStateBatchAdvance,
    batch_id: String,
}

fn advance_operation(
    fixture: &Fixture,
    operation: AdmissionOperationV1,
    claimant: &str,
    next_state: AdmissionOperationState,
    attachments: Vec<AdmissionAttachment>,
    at: u64,
) -> TestResult<AdmissionOperationV1> {
    let lease = claim(fixture, &operation, claimant, at - 1, RECOVERY_EXPIRES_AT)?;
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        lease,
        attachments,
        Some(next_state),
        None,
        None,
    )?;
    Ok(fixture
        .authority
        .admission_operation_store()
        .compare_and_swap(&command, at)?
        .into_operation())
}

fn live_dispatch_committed(
    fixture: &Fixture,
    flow: &ReservationFlow,
) -> TestResult<AdmissionOperationV1> {
    let claimant = format!("kernel:{}", flow.kernel_key.public_key().to_hex());
    let operation = stage_and_anchor_with_claimant(fixture, flow, &claimant)?;
    let lease = claim(
        fixture,
        &operation,
        &claimant,
        LIVE_AT - 1,
        RECOVERY_EXPIRES_AT,
    )?;
    let live = fixture.store.finalize_channel_reservation(
        operation.binding().operation_id(),
        &lease,
        &flow.authority_pins,
        &fixture.fence,
        LIVE_AT,
    )?;
    let operation = advance_operation(
        fixture,
        live.operation().clone(),
        &claimant,
        AdmissionOperationState::CapturePending,
        Vec::new(),
        CAPTURE_AT,
    )?;
    advance_operation(
        fixture,
        operation,
        &claimant,
        AdmissionOperationState::DispatchCommitted,
        Vec::new(),
        DISPATCH_AT,
    )
}

fn effect_head(
    effect: &EconomicEffectSlotV1,
    version: u64,
    predecessor_digest: String,
    observed_at_unix_ms: u64,
) -> TestResult<EconomicResourceHeadV1> {
    let (lifecycle_state, terminal_result) = match (&effect.state, &effect.terminal) {
        (EconomicEffectStateV1::DispatchCommitted, None) => ("dispatch_committed", None),
        (
            EconomicEffectStateV1::Completed,
            Some(EconomicEffectTerminalV1::Completed {
                result_id,
                result_digest,
                result,
            }),
        ) => (
            "completed",
            Some(EconomicTerminalResultV1 {
                result_id: result_id.clone(),
                result_digest: result_digest.clone(),
                result: result.clone(),
            }),
        ),
        _ => return Err("invalid terminal test effect state".into()),
    };
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(effect)?,
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: effect.anchor_id.clone(),
        namespace: effect.namespace.clone(),
        resource_key: effect.resource_head_key(),
        head_version: version,
        resource_version: version,
        lifecycle_fence: version,
        lifecycle_state: lifecycle_state.to_owned(),
        state_digest: state.digest()?,
        state,
        operation_id: Some(effect.operation_id.clone()),
        effect_idempotency_key: Some(effect.idempotency_key.clone()),
        frost: None,
        terminal_result,
        trusted_clock_high_water: observed_at_unix_ms,
        predecessor_digest: Some(predecessor_digest),
    })
}

fn state_head_successor<T: serde::Serialize>(
    current: &EconomicResourceHeadV1,
    state: &T,
    resource_version: u64,
    lifecycle_fence: u64,
) -> TestResult<EconomicResourceHeadV1> {
    let content = EconomicContentV1::Inline {
        value: serde_json::to_value(state)?,
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: current.head_version + 1,
        resource_version,
        lifecycle_fence,
        lifecycle_state: "open".to_owned(),
        state_digest: content.digest()?,
        state: content,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: TERMINAL_BATCH_AT,
        predecessor_digest: Some(current.digest()?),
    })
}

fn verified_batch(
    current: &VerifiedEconomicStateView,
    operation_id: &str,
    mut transitions: Vec<EconomicStateTransitionV1>,
    issued_at: u64,
) -> TestResult<VerifiedEconomicStateBatchAdvance> {
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: current.view().anchor_id.clone(),
        namespace: current.view().namespace.clone(),
        checkpoint_sequence: current.view().checkpoint_sequence + 1,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(operation_id.to_owned()),
        issued_at,
        signer_key_id: current.view().signer_key_id.clone(),
        signer_key_epoch: current.view().signer_key_epoch,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[61; 32]))?;
    Ok(verify_economic_state_batch_advance(
        current,
        batch,
        &anchor_pins(),
        &DirectTransitionVerifier,
    )?)
}

fn dispatch_advance(
    fixture: &Fixture,
    flow: &ReservationFlow,
    operation: &AdmissionOperationV1,
) -> TestResult<(VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView)> {
    let ready = flow.reservation.ready_effect();
    let ready_head = flow
        .committed
        .view()
        .head(&ready.resource_head_key())
        .ok_or("ready effect head is absent")?;
    let mut dispatch = ready.clone();
    dispatch.state = EconomicEffectStateV1::DispatchCommitted;
    let dispatch_head = effect_head(&dispatch, 2, ready_head.digest()?, DISPATCH_ANCHOR_AT)?;
    let advance = verified_batch(
        &flow.committed,
        operation.binding().operation_id().as_str(),
        vec![EconomicStateTransitionV1 {
            resource_key: dispatch.resource_head_key(),
            expected_head_digest: dispatch_head.predecessor_digest.clone(),
            next_head: dispatch_head,
            transition_proof_digest: digest("channel-dispatch-proof"),
            prepared_effect: None,
        }],
        DISPATCH_ANCHOR_AT,
    )?;
    let committed = committed_view(&flow.committed, advance.batch())?;
    let claimant = format!("kernel:{}", flow.kernel_key.public_key().to_hex());
    let lease = claim(
        fixture,
        operation,
        &claimant,
        DISPATCH_ANCHOR_AT - 3,
        RECOVERY_EXPIRES_AT,
    )?;
    let cache = fixture.authority.economic_state_cache();
    cache.stage_batch(
        &advance,
        Some(crate::economic_state_cache::EconomicOperationStageContext::new(operation, &lease)),
        &fixture.fence,
        DISPATCH_ANCHOR_AT - 2,
    )?;
    cache.record_anchor_advanced(
        &advance,
        &committed,
        &anchor_pins(),
        &fixture.fence,
        DISPATCH_ANCHOR_AT - 1,
    )?;
    cache.finalize_stage(
        &advance.batch().batch_id,
        &fixture.fence,
        DISPATCH_ANCHOR_AT,
    )?;
    Ok((advance, committed))
}

fn terminal_receipt(
    operation: &AdmissionOperationV1,
    context: &AdmissionProjectionContext,
    flow: &ReservationFlow,
    outcome: &chio_kernel::tool_outcome::ToolOutcomeRecordV1,
) -> TestResult<VerifiedAdmissionReceipt> {
    let persisted = outcome.to_persisted();
    let ResolvedToolOutcomeV1::Resolved {
        resolved_output, ..
    } = &persisted.disposition
    else {
        return Err("tool outcome is not resolved".into());
    };
    let actual_charge = MonetaryAmount {
        units: 7,
        currency: "USD".to_owned(),
    };
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
        tool_outcome_id: Some(persisted.outcome_id.clone()),
        tool_outcome_version: Some(persisted.version),
    };
    let channel_metadata = ChannelReceiptMetadataV1 {
        schema: CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA.to_owned(),
        channel_id: flow.reservation.artifact().body.channel_id.clone(),
        open_digest: flow.open.artifact().digest()?,
        reservation_id: flow.reservation.artifact().body.reservation_id.clone(),
        reservation_digest: flow.reservation.artifact().digest()?,
        sequence: flow.reservation.artifact().body.next_sequence,
        settlement_mode: ChannelSettlementModeV1::Channelized,
    };
    let raw = ChioReceipt::sign(
        ChioReceiptBody {
            id: "channel-terminal-receipt".to_owned(),
            timestamp: context.trusted_time_unix_ms / 1_000,
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: persisted.tool_server.as_str().to_owned(),
            tool_name: persisted.tool_name.as_str().to_owned(),
            action: channel_action()?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: resolved_output.digest().as_str().to_owned(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                ADMISSION_RECEIPT_METADATA_KEY: metadata,
                "channel": channel_metadata,
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: actual_charge.units,
                    currency: actual_charge.currency.clone(),
                    budget_remaining: 143,
                    budget_total: 150,
                    delegation_depth: 0,
                    root_budget_holder: flow.trust.payer_id.clone(),
                    payment_reference: None,
                    settlement_status: SettlementStatus::Pending,
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                },
            })),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: flow.kernel_key.public_key(),
            bbs_projection_version: None,
        },
        &flow.kernel_key,
    )?;
    Ok(VerifiedAdmissionReceipt::from_kernel_verified_for_test(
        raw,
        &flow.kernel_key.public_key(),
        &Decision::Allow,
        persisted.tool_server.as_str(),
        persisted.tool_name.as_str(),
        operation.binding().action_parameter_hash(),
        resolved_output.digest(),
        operation,
        context,
        AdmissionOperationState::Completed,
        AdmissionCompensationStatus::NotCompensated,
        Some((&persisted.outcome_id, persisted.version)),
    )?)
}

fn stage_terminal(fixture: &Fixture, flow: &ReservationFlow) -> TestResult<StagedTerminal> {
    let claimant = format!("kernel:{}", flow.kernel_key.public_key().to_hex());
    let operation = live_dispatch_committed(fixture, flow)?;
    let (_, dispatched) = dispatch_advance(fixture, flow, &operation)?;
    let (_, returned) = returned_value(
        &operation,
        fixture.fence.clone(),
        OUTCOME_AT,
        serde_json::json!({"result": "ok"}),
        None,
    )?;
    let evaluation = prepared_evaluation(&operation, &returned, OUTCOME_AT + 1)
        .and_then(|evaluation| record_pure_step(&evaluation))
        .and_then(|evaluation| record_external_step(&evaluation, OUTCOME_AT + 2))?;
    let (evaluation, outcome) = resolve(
        &returned,
        &evaluation,
        SettlementDispositionV1::Capture {
            amount: MonetaryAmount {
                units: 7,
                currency: "USD".to_owned(),
            },
        },
    )?;
    let outcome_id = outcome.to_persisted().outcome_id;
    let operation = advance_operation(
        fixture,
        operation,
        &claimant,
        AdmissionOperationState::Finalizing,
        vec![AdmissionAttachment::ToolOutcomeId(outcome_id)],
        FINALIZING_AT,
    )?;
    let lease = claim(
        fixture,
        &operation,
        &claimant,
        TERMINAL_CONTEXT_AT - 1,
        RECOVERY_EXPIRES_AT,
    )?;
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: TERMINAL_CONTEXT_AT,
        coordinator_lease_id: lease.coordinator_lease_id().clone(),
        coordinator_lease_epoch: lease.coordinator_lease_epoch(),
        store_fence: lease.store_fence().clone(),
    };
    let evidence = ToolOutcomeTerminalEvidenceV1::from_records_for_test(
        &operation,
        &context,
        &outcome,
        &evaluation,
    )?;
    let receipt = terminal_receipt(&operation, &context, flow, &outcome)?;
    let raw_receipt = receipt.receipt();
    let receipt_digest = chio_core::sha256_hex(&canonical_json_bytes(raw_receipt)?);
    let atom = ObligationAtomV1::new(ObligationAtomInputV1 {
        economic_intent_digest: flow.reservation.artifact().body.proposal_digest()?,
        source_receipt_id: raw_receipt.id.clone(),
        source_receipt_digest: receipt_digest,
        debtor_id: flow.open.intent().body.payer_id.clone(),
        original_creditor_id: flow.open.intent().body.payee_id.clone(),
        original_settlement_destination_ref: flow
            .open
            .intent()
            .body
            .payee_beneficiary_address
            .clone(),
        payee_binding_digest: derive_channel_payee_binding_digest(
            &flow.open.intent().body.payee_id,
            &flow.open.intent().body.payee_beneficiary_address,
        )?,
        amount: MonetaryAmount {
            units: 7,
            currency: "USD".to_owned(),
        },
        credit_election: ObligationCreditElectionV1::NotCredit,
        pre_action_authority_digest: flow.reservation.artifact().digest()?,
        created_at_unix_ms: TERMINAL_CONTEXT_AT,
        due_at_unix_ms: 2_000,
    })?;
    let channel_receipt = verify_channel_receipt_binding(
        raw_receipt,
        &flow.kernel_key.public_key(),
        &flow.reservation,
        &flow.open,
        Some(&atom),
    )?;
    let next_body = build_channel_state_transition(
        &flow.prior,
        &flow.reservation,
        &channel_receipt,
        &flow.open,
    )?;
    let signed_next = SignedChannelStateV1 {
        payee_signature: ChannelSignatureV1::sign(
            &next_body,
            flow.trust.payee_id.clone(),
            flow.trust.payee_key_epoch,
            &flow.payee_key,
        )?,
        body: next_body,
    };
    let next = verify_channel_state_transition(
        &signed_next,
        &flow.prior,
        &flow.reservation,
        &channel_receipt,
        &flow.open,
        &flow.trust,
    )?;
    let admitted_lifecycle = flow.reservation.snapshot().lifecycle();
    let admitted_escrow = flow.reservation.snapshot().escrow();
    let terminal_lifecycle = ChannelLifecycleViewV1 {
        latest_state_digest: next.digest()?,
        latest_sequence: next.body().seq,
        state_version: admitted_lifecycle.state_version + 1,
        lifecycle_fence: admitted_lifecycle.lifecycle_fence + 1,
        live_reservation_id: None,
        operation_id: None,
        ..admitted_lifecycle.clone()
    };
    let terminal_escrow = ChannelEscrowReservationViewV1 {
        version: admitted_escrow.version + 1,
        lifecycle_fence: admitted_lifecycle.lifecycle_fence + 1,
        ..admitted_escrow.clone()
    };
    let mut completed_effect = flow.reservation.ready_effect().clone();
    completed_effect.state = EconomicEffectStateV1::Completed;
    let result = EconomicContentV1::Inline {
        value: serde_json::to_value(&evidence)?,
    };
    completed_effect.terminal = Some(EconomicEffectTerminalV1::Completed {
        result_id: outcome.to_persisted().outcome_id.as_str().to_owned(),
        result_digest: result.digest()?,
        result,
    });
    let channel_key = completed_effect.resource_key.clone();
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: channel_key.scope_id.clone(),
        resource_id: channel_key.resource_id.clone(),
    };
    let effect_key = completed_effect.resource_head_key();
    let current_channel = dispatched
        .view()
        .head(&channel_key)
        .ok_or("dispatched channel head is absent")?;
    let current_escrow = dispatched
        .view()
        .head(&escrow_key)
        .ok_or("dispatched escrow head is absent")?;
    let current_effect = dispatched
        .view()
        .head(&effect_key)
        .ok_or("dispatched effect head is absent")?;
    let terminal_channel = state_head_successor(
        current_channel,
        &terminal_lifecycle,
        terminal_lifecycle.state_version,
        terminal_lifecycle.lifecycle_fence,
    )?;
    let terminal_escrow_head = state_head_successor(
        current_escrow,
        &terminal_escrow,
        terminal_escrow.version,
        terminal_escrow.lifecycle_fence,
    )?;
    let terminal_effect = effect_head(
        &completed_effect,
        3,
        current_effect.digest()?,
        TERMINAL_BATCH_AT,
    )?;
    let advance = verified_batch(
        &dispatched,
        operation.binding().operation_id().as_str(),
        vec![
            EconomicStateTransitionV1 {
                resource_key: channel_key,
                expected_head_digest: terminal_channel.predecessor_digest.clone(),
                next_head: terminal_channel,
                transition_proof_digest: digest("terminal-channel-proof"),
                prepared_effect: None,
            },
            EconomicStateTransitionV1 {
                resource_key: escrow_key,
                expected_head_digest: terminal_escrow_head.predecessor_digest.clone(),
                next_head: terminal_escrow_head,
                transition_proof_digest: digest("terminal-escrow-proof"),
                prepared_effect: None,
            },
            EconomicStateTransitionV1 {
                resource_key: effect_key,
                expected_head_digest: terminal_effect.predecessor_digest.clone(),
                next_head: terminal_effect,
                transition_proof_digest: digest("terminal-effect-proof"),
                prepared_effect: None,
            },
        ],
        TERMINAL_BATCH_AT,
    )?;
    let signed_outcome = sign_channel_terminal_outcome_commitment_for_test(
        &operation,
        &flow.reservation,
        &receipt,
        &evidence,
        &context,
        &flow.kernel_key,
    )?;
    let terminal_outcome = verify_channel_terminal_outcome_commitment(
        &signed_outcome,
        &flow.kernel_key.public_key(),
        &flow.reservation,
        raw_receipt,
    )?;
    let verified_advance = verify_channel_terminal_advance(
        &flow.open,
        &flow.reservation,
        &flow.prior,
        &next,
        &channel_receipt,
        &terminal_outcome,
        &advance,
    )?;
    let (channel, obligation) =
        chio_kernel::admission_operation::VerifiedChannelTerminalProjectionV1::from_verified_for_test(
            &operation,
            &context,
            &receipt,
            &evidence,
            &verified_advance,
        )?;
    let persisted_outcome = outcome.to_persisted();
    let observer_work = ObservationAttemptZero::from_verified_for_test(
        &operation,
        &context,
        &receipt,
        persisted_outcome.outcome_id,
        persisted_outcome.version,
    )?;
    let projection =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context,
            receipt,
            tool_outcome: Some(evidence),
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: Some(observer_work),
            obligation,
            channel_terminal: Some(channel),
        }));
    let store = fixture.authority.admission_operation_store();
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &store.admission_projection_capabilities(),
        &flow.kernel_key,
    )?;
    store.stage_anchored_terminal_projection(
        &advance,
        &lease,
        &envelope,
        &fixture.fence,
        TERMINAL_STAGE_AT,
    )?;
    let committed = committed_view(&dispatched, advance.batch())?;
    fixture
        .authority
        .economic_state_cache()
        .record_anchor_advanced(
            &advance,
            &committed,
            &anchor_pins(),
            &fixture.fence,
            TERMINAL_ANCHOR_AT,
        )?;
    Ok(StagedTerminal {
        operation,
        batch_id: advance.batch().batch_id.clone(),
        advance,
    })
}

fn projection_counts(
    fixture: &Fixture,
    operation_id: &str,
) -> TestResult<(i64, i64, i64, i64, i64)> {
    Ok(fixture.store.connection()?.query_row(
        r#"
        SELECT
            (SELECT COUNT(*) FROM admission_operation_terminal_projections
             WHERE operation_id = ?1),
            (SELECT COUNT(*) FROM admission_operation_terminal_records
             WHERE operation_id = ?1 AND record_kind = 'receipt'),
            (SELECT COUNT(*) FROM admission_operation_terminal_records
             WHERE operation_id = ?1 AND record_kind = 'tool_outcome'),
            (SELECT COUNT(*) FROM obligation_atoms
             WHERE operation_id = ?1),
            (SELECT COUNT(*) FROM admission_operation_observer_attempts
             WHERE operation_id = ?1)
        "#,
        [operation_id],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?)
}

#[test]
fn anchored_terminal_consumes_live_reservation_atomically_and_replays_exactly() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(2, std::iter::empty::<String>());
    let fixture = fixture()?;
    let flow = reservation_flow_with_state_version(&fixture.fence, "terminal-consumption", 5)?;
    let staged = stage_terminal(&fixture, &flow)?;
    let before: (i64, i64) = fixture.store.connection()?.query_row(
        "SELECT state_version, record_version FROM channel_lifecycle_records",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(before, (6, 2));

    let store = fixture.authority.admission_operation_store();
    let terminal = store.commit_anchored_terminal_projection(
        &staged.batch_id,
        &fixture.fence,
        TERMINAL_COMMIT_AT,
    )?;
    assert_eq!(terminal.state, AdmissionOperationState::Completed);
    assert_eq!(
        projection_counts(&fixture, staged.operation.binding().operation_id().as_str())?,
        (1, 1, 1, 1, 1)
    );
    let retained = fixture
        .store
        .load_channel_reservation(
            staged.operation.binding().operation_id(),
            &flow.authority_pins,
        )?
        .ok_or("consumed reservation is absent")?;
    assert_eq!(
        retained.disposition(),
        ChannelReservationDispositionV1::Consumed
    );
    let lifecycle: (i64, i64, Option<String>, Option<String>) =
        fixture.store.connection()?.query_row(
            "SELECT state_version, record_version, live_reservation_id, operation_id
             FROM channel_lifecycle_records",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    assert_eq!(lifecycle, (7, 3, None, None));

    let replay = store.commit_anchored_terminal_projection(
        &staged.batch_id,
        &fixture.fence,
        TERMINAL_COMMIT_AT + 1,
    )?;
    assert_eq!(replay, terminal);
    assert_eq!(
        projection_counts(&fixture, staged.operation.binding().operation_id().as_str())?,
        (1, 1, 1, 1, 1)
    );
    let state_count: i64 = fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM channel_state_records WHERE sequence = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(state_count, 1);
    Ok(())
}

#[test]
fn terminal_projection_conflict_rolls_back_every_local_projection() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(2, std::iter::empty::<String>());
    let fixture = fixture()?;
    let flow = reservation_flow(&fixture.fence, "terminal-rollback")?;
    let staged = stage_terminal(&fixture, &flow)?;
    let terminal_commit_at = i64::try_from(TERMINAL_COMMIT_AT)?;
    fixture.store.connection()?.execute(
        r#"
        INSERT INTO channel_state_records (
            channel_id, sequence, state_kind, state_digest,
            checkpoint_sequence, checkpoint_digest, state_json, operation_id,
            store_uuid, store_lease_id, store_owner_epoch, recorded_at_unix_ms
        ) VALUES (?1, 1, 'signed', ?2, ?3, ?4, X'7b7d', ?5, ?6, ?7, ?8, ?9)
        "#,
        params![
            &flow.reservation.artifact().body.channel_id,
            digest("conflicting-terminal-state"),
            i64::try_from(staged.advance.batch().checkpoint_sequence)?,
            &staged.advance.batch().checkpoint_digest,
            staged.operation.binding().operation_id().as_str(),
            &fixture.fence.store_uuid,
            &fixture.fence.lease_id,
            i64::try_from(fixture.fence.owner_epoch)?,
            terminal_commit_at,
        ],
    )?;
    assert!(fixture
        .authority
        .admission_operation_store()
        .commit_anchored_terminal_projection(
            &staged.batch_id,
            &fixture.fence,
            TERMINAL_COMMIT_AT + 1,
        )
        .is_err());
    assert_eq!(
        projection_counts(&fixture, staged.operation.binding().operation_id().as_str())?,
        (0, 0, 0, 0, 0)
    );
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(staged.operation.binding().operation_id())?
        .ok_or("rolled back operation is absent")?;
    assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
    let retained = fixture
        .store
        .load_channel_reservation(
            staged.operation.binding().operation_id(),
            &flow.authority_pins,
        )?
        .ok_or("live reservation is absent after rollback")?;
    assert_eq!(
        retained.disposition(),
        ChannelReservationDispositionV1::Live
    );
    Ok(())
}

#[test]
fn outcome_unknown_after_dispatch_keeps_the_reservation_live() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(2, std::iter::empty::<String>());
    let fixture = fixture()?;
    let flow = reservation_flow(&fixture.fence, "terminal-unknown")?;
    let claimant = format!("kernel:{}", flow.kernel_key.public_key().to_hex());
    let operation = live_dispatch_committed(&fixture, &flow)?;
    let operation = advance_operation(
        &fixture,
        operation,
        &claimant,
        AdmissionOperationState::Finalizing,
        vec![AdmissionAttachment::ToolOutcomeId(admission_digest(
            "tool_outcome_id",
            "unknown-channel-outcome",
        )?)],
        FINALIZING_AT,
    )?;
    let lease = claim(
        &fixture,
        &operation,
        &claimant,
        TERMINAL_CONTEXT_AT - 1,
        RECOVERY_EXPIRES_AT,
    )?;
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id,
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: TERMINAL_CONTEXT_AT,
        coordinator_lease_id: lease.coordinator_lease_id().clone(),
        coordinator_lease_epoch: lease.coordinator_lease_epoch(),
        store_fence: lease.store_fence().clone(),
    };
    let incident = AdmissionIncident::from_verified(
        &operation,
        &context,
        AdmissionOperationState::OutcomeUnknownAfterDispatch,
        identifier("incident_id", "channel-outcome-unknown")?,
        admission_digest("incident_digest", "channel-outcome-unknown")?,
    )?;
    let projection = AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
        context,
        incident: Box::new(incident),
    };
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &operation,
        &projection,
        &fixture
            .authority
            .admission_operation_store()
            .admission_projection_capabilities(),
        &flow.kernel_key,
    )?;
    let terminal = fixture
        .authority
        .admission_operation_store()
        .commit_signed_terminal_projection(&envelope)?;
    assert_eq!(
        terminal.state,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    let retained = fixture
        .store
        .load_channel_reservation(operation.binding().operation_id(), &flow.authority_pins)?
        .ok_or("unknown reservation is absent")?;
    assert_eq!(
        retained.disposition(),
        ChannelReservationDispositionV1::Live
    );
    Ok(())
}
