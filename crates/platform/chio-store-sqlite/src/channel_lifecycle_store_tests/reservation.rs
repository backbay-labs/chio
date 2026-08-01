use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_view,
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicRequestBindingV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorPins,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, VerifiedEconomicStateBatchAdvance,
    VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_kernel::admission_operation::{
    expected_dispatch_committed_version, AdmissionAttachment, AdmissionOperationCommand,
    AdmissionOperationKind, AdmissionOperationState, AdmissionParticipantRequirements,
    ProviderAttemptBindingV1, QualifiedAdmissionOperationStoreExt,
};
use chio_settle::channel::*;

use super::*;

const BEGIN_AT: u64 = 1_500;
const BROKER_AT: u64 = 1_502;
const BUDGET_AT: u64 = 1_552;
const STAGE_AT: u64 = 1_602;
const ANCHOR_AT: u64 = 1_603;
const RESERVATION_EXPIRES_AT: u64 = 2_500;
const TAKEOVER_AT: u64 = RESERVATION_EXPIRES_AT + 1;
const FINALIZE_AT: u64 = TAKEOVER_AT + 1;

fn evm_hash(label: &str) -> String {
    format!("0x{}", digest(label))
}

struct OpenFixture {
    payer_key: Keypair,
    payee_key: Keypair,
    trust: ChannelOpenTrustV1,
    funding: SignedChannelFundingEvidenceV1,
    funding_authority: ChannelFundingAuthorityV1,
    funding_acknowledgement: SignedChannelFundingAcknowledgementV1,
    dispute_policy: ChannelDisputePolicyV1,
    open: VerifiedChannelOpenConsentV1,
}

struct ReservationFlow {
    operation: AdmissionOperationV1,
    prepared: VerifiedChannelPreparedReservationV1,
    authority_pins: ChannelTransitionReplayAuthorityPinsV1,
    replay_bytes: Vec<u8>,
    advance: VerifiedEconomicStateBatchAdvance,
    committed: VerifiedEconomicStateView,
    provider: ProviderAttemptBindingV1,
    open: VerifiedChannelOpenConsentV1,
    prior: VerifiedChannelStateV1,
    reservation: VerifiedAdmittedChannelReservationV1,
    trust: ChannelOpenTrustV1,
    payee_key: Keypair,
    kernel_key: Keypair,
}

fn anchor_pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        signer_key_id: "channel-anchor-key".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: Keypair::from_seed(&[61; 32]).public_key(),
    }
}

fn asset_binding() -> ChannelAssetBindingV1 {
    ChannelAssetBindingV1 {
        schema: CHANNEL_ASSET_BINDING_SCHEMA.to_owned(),
        currency: "USD".to_owned(),
        protocol_minor_unit_decimals: 2,
        chain_id: "eip155:31337".to_owned(),
        token_address: "0x1111111111111111111111111111111111111111".to_owned(),
        token_symbol: "USDC".to_owned(),
        token_decimals: 6,
        settlement_policy_digest: digest("reservation-settlement-policy"),
    }
}

fn funding_body() -> ChannelFundingEvidenceBodyV1 {
    let depositor = "0x2222222222222222222222222222222222222222".to_owned();
    let beneficiary = "0x3333333333333333333333333333333333333333".to_owned();
    let operator = "0x4444444444444444444444444444444444444444".to_owned();
    let operator_key_hash = evm_hash("reservation-operator-key");
    let escrow_id = evm_hash("reservation-escrow-id");
    let escrow_contract = "0x5555555555555555555555555555555555555555".to_owned();
    let block_hash = evm_hash("reservation-funding-block");
    let terms = ChannelEscrowTermsV1 {
        capability_id: evm_hash("reservation-capability"),
        depositor: depositor.clone(),
        beneficiary: beneficiary.clone(),
        token_address: "0x1111111111111111111111111111111111111111".to_owned(),
        max_token_base_units: "1500000".to_owned(),
        deadline_unix_secs: 2_000,
        operator: operator.clone(),
        operator_key_hash: operator_key_hash.clone(),
    };
    ChannelFundingEvidenceBodyV1 {
        schema: CHANNEL_FUNDING_EVIDENCE_SCHEMA.to_owned(),
        escrow_reference: ChannelEscrowReferenceV1 {
            chain_id: "eip155:31337".to_owned(),
            escrow_contract: escrow_contract.clone(),
            escrow_id: escrow_id.clone(),
        },
        escrow_terms: terms.clone(),
        escrow_state: ChannelEscrowStateV1 {
            deposited_token_base_units: "1500000".to_owned(),
            released_token_base_units: "0".to_owned(),
            refunded_token_base_units: "0".to_owned(),
            refunded: false,
        },
        escrow_state_read: ChannelPinnedStateReadV1 {
            contract: escrow_contract.clone(),
            block_number: 100,
            block_hash: block_hash.clone(),
            call_data_digest: evm_hash("reservation-escrow-call"),
            return_data_digest: evm_hash("reservation-escrow-result"),
        },
        creation_event: ChannelEscrowCreatedEventV1 {
            transaction_hash: evm_hash("reservation-creation-transaction"),
            transaction_to: escrow_contract.clone(),
            transaction_succeeded: true,
            receipt_block_number: 100,
            receipt_block_hash: block_hash.clone(),
            log_emitter: escrow_contract.clone(),
            log_index: 0,
            event_signature: channel_escrow_created_event_signature(),
            escrow_id,
            capability_id: terms.capability_id.clone(),
            depositor,
            beneficiary,
            token_address: terms.token_address.clone(),
            max_token_base_units: terms.max_token_base_units.clone(),
            deadline_unix_secs: terms.deadline_unix_secs,
            operator: operator.clone(),
        },
        identity_observation: ChannelIdentityRegistryObservationV1 {
            registry_contract: "0x6666666666666666666666666666666666666666".to_owned(),
            operator,
            active: true,
            operator_key_hash,
            block_number: 100,
            block_hash: block_hash.clone(),
        },
        token_observation: ChannelTokenObservationV1 {
            token_address: terms.token_address.clone(),
            token_symbol: "USDC".to_owned(),
            token_decimals: 6,
            allowed: true,
            escrow_contract,
            block_number: 100,
            block_hash: block_hash.clone(),
        },
        asset_binding: asset_binding(),
        block_pin: ChannelBlockPinV1 {
            block_number: 100,
            block_hash,
            block_timestamp_unix_secs: 1,
            observed_at_unix_ms: 1_100,
            required_confirmations: 12,
            observed_confirmations: 12,
            finalized_head_number: 112,
            finalized_head_hash: evm_hash("reservation-finalized-head"),
            finality_mode: Web3FinalityMode::L1Finalized,
            finality_status: ChannelFinalityStatusV1::Finalized,
        },
        evidence_expires_at_unix_ms: 1_900,
    }
}

fn funding_authority(
    key: &Keypair,
    body: &ChannelFundingEvidenceBodyV1,
) -> ChannelFundingAuthorityV1 {
    ChannelFundingAuthorityV1 {
        authority_id: "funding-authority".to_owned(),
        authority_key_epoch: 4,
        authority_key: key.public_key(),
        trusted_time_unix_ms: BEGIN_AT,
        chain_id: body.escrow_reference.chain_id.clone(),
        escrow_contract: body.escrow_reference.escrow_contract.clone(),
        identity_registry_contract: body.identity_observation.registry_contract.clone(),
        token_address: body.asset_binding.token_address.clone(),
        token_symbol: body.asset_binding.token_symbol.clone(),
        currency: body.asset_binding.currency.clone(),
        protocol_minor_unit_decimals: body.asset_binding.protocol_minor_unit_decimals,
        token_decimals: body.asset_binding.token_decimals,
        settlement_policy_digest: body.asset_binding.settlement_policy_digest.clone(),
        minimum_confirmations: body.block_pin.required_confirmations,
        finality_mode: body.block_pin.finality_mode,
    }
}

fn open_fixture() -> TestResult<OpenFixture> {
    let payer_key = Keypair::from_seed(&[31; 32]);
    let payee_key = Keypair::from_seed(&[32; 32]);
    let funding_key = Keypair::from_seed(&[35; 32]);
    let dispute_policy = ChannelDisputePolicyV1 {
        schema: CHANNEL_DISPUTE_POLICY_SCHEMA.to_owned(),
        policy_id: "reservation-policy".to_owned(),
        fixed_finality_broadcast_margin_secs: 50,
        tiers: vec![
            ChannelDisputeTierV1 {
                upper_bound_units: 1_000,
                dispute_window_secs: 100,
                required_confirmations: 12,
                finality_mode: Web3FinalityMode::L1Finalized,
            },
            ChannelDisputeTierV1 {
                upper_bound_units: (1_u64 << 53) - 1,
                dispute_window_secs: 200,
                required_confirmations: 64,
                finality_mode: Web3FinalityMode::L1Finalized,
            },
        ],
    };
    let mut funding_body = funding_body();
    funding_body.asset_binding.settlement_policy_digest = dispute_policy.digest()?;
    let funding = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &funding_body,
            "funding-authority".to_owned(),
            4,
            &funding_key,
        )?,
        body: funding_body,
    };
    let funding_authority = funding_authority(&funding_key, &funding.body);
    let trust = ChannelOpenTrustV1 {
        payer_id: "channel-payer".to_owned(),
        payer_key: payer_key.public_key(),
        payer_key_epoch: 2,
        payee_id: "channel-payee".to_owned(),
        payee_key: payee_key.public_key(),
        payee_key_epoch: 3,
        settlement_authority_scope_id: "channel-settlement".to_owned(),
        original_web3_dispatch_digest: digest("reservation-web3-dispatch"),
        participant_snapshot_digest: digest("reservation-participants"),
        trusted_time_unix_ms: BEGIN_AT,
    };
    let intent_body = ChannelOpenIntentBodyV1 {
        schema: CHANNEL_OPEN_INTENT_SCHEMA.to_owned(),
        open_intent_id: digest("reservation-open-intent"),
        payer_id: trust.payer_id.clone(),
        payer_key: trust.payer_key.clone(),
        payer_key_epoch: trust.payer_key_epoch,
        payer_refund_address: funding.body.escrow_terms.depositor.clone(),
        payee_id: trust.payee_id.clone(),
        payee_key: trust.payee_key.clone(),
        payee_key_epoch: trust.payee_key_epoch,
        payee_beneficiary_address: funding.body.escrow_terms.beneficiary.clone(),
        settlement_authority_scope_id: trust.settlement_authority_scope_id.clone(),
        currency: "USD".to_owned(),
        bound: MonetaryAmount {
            units: 150,
            currency: "USD".to_owned(),
        },
        asset_binding: funding.body.asset_binding.clone(),
        bound_token_base_units: funding.body.escrow_terms.max_token_base_units.clone(),
        channel_expiry_unix_secs: 1_800,
        dispute_tier_upper_bound_units: 1_000,
        dispute_window_secs: 100,
        required_confirmations: 12,
        finality_mode: Web3FinalityMode::L1Finalized,
        fixed_finality_broadcast_margin_secs: 50,
        close_submission_cutoff_unix_secs: 1_950,
        original_web3_dispatch_digest: trust.original_web3_dispatch_digest.clone(),
        escrow_reference: funding.body.escrow_reference.clone(),
        funding_evidence_digest: funding.digest()?,
        original_operator: funding.body.escrow_terms.operator.clone(),
        original_operator_key_hash: funding.body.escrow_terms.operator_key_hash.clone(),
        participant_snapshot_digest: trust.participant_snapshot_digest.clone(),
    };
    let intent = SignedChannelOpenIntentV1 {
        payer_signature: ChannelSignatureV1::sign(
            &intent_body,
            trust.payer_id.clone(),
            trust.payer_key_epoch,
            &payer_key,
        )?,
        payee_signature: ChannelSignatureV1::sign(
            &intent_body,
            trust.payee_id.clone(),
            trust.payee_key_epoch,
            &payee_key,
        )?,
        body: intent_body,
    };
    let verified_intent = verify_channel_open_intent(
        &intent,
        &funding,
        &funding_authority,
        &dispute_policy,
        &trust,
    )?;
    let acknowledgement_body = ChannelFundingAcknowledgementBodyV1 {
        schema: CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
        open_intent_digest: intent.digest()?,
        escrow_reference: intent.body.escrow_reference.clone(),
        prior_state: ChannelEscrowReservationStateV1::Unreserved,
        prior_version: 1,
        prior_head_digest: digest("reservation-unreserved-head"),
        new_state: ChannelEscrowReservationStateV1::Opening,
        new_version: 2,
        anchored_head_digest: digest("reservation-opening-head"),
        reserved_at_unix_ms: 1_400,
        expires_at_unix_ms: 1_700,
    };
    let funding_acknowledgement = SignedChannelFundingAcknowledgementV1 {
        authority_signature: ChannelSignatureV1::sign(
            &acknowledgement_body,
            funding_authority.authority_id.clone(),
            funding_authority.authority_key_epoch,
            &funding_key,
        )?,
        body: acknowledgement_body,
    };
    let intent_digest = intent.digest()?;
    let acknowledgement_digest = funding_acknowledgement.digest()?;
    let channel_id = derive_channel_id(&intent_digest, &acknowledgement_digest)?;
    let initial_state = ChannelStateBodyV1::initial(
        channel_id.clone(),
        intent.body.currency.clone(),
        intent.body.asset_binding.digest()?,
    )?;
    let open_body = ChannelOpenBodyV1 {
        schema: CHANNEL_OPEN_SCHEMA.to_owned(),
        channel_id,
        open_intent_digest: intent_digest,
        funding_acknowledgement_digest: acknowledgement_digest,
        initial_state_digest: initial_state.digest()?,
        opened_at_unix_ms: 1_450,
    };
    let signed_open = SignedChannelOpenV1 {
        payer_signature: ChannelSignatureV1::sign(
            &open_body,
            trust.payer_id.clone(),
            trust.payer_key_epoch,
            &payer_key,
        )?,
        payee_signature: ChannelSignatureV1::sign(
            &open_body,
            trust.payee_id.clone(),
            trust.payee_key_epoch,
            &payee_key,
        )?,
        body: open_body,
    };
    let open = verify_channel_open_consent(
        &signed_open,
        &verified_intent,
        &funding_acknowledgement,
        &funding_authority,
        &trust,
    )?;
    Ok(OpenFixture {
        payer_key,
        payee_key,
        trust,
        funding,
        funding_authority,
        funding_acknowledgement,
        dispute_policy,
        open,
    })
}

fn anticipated_effect_key(
    reservation: &SignedChannelReservationV1,
    service: &ChannelServiceBindingV1,
    scope_id: &str,
) -> TestResult<EconomicResourceKeyV1> {
    let mut effect = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: String::new(),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
            scope_id: scope_id.to_owned(),
            resource_id: reservation.body.channel_id.clone(),
        },
        operation_id: reservation.body.operation_id.clone(),
        effect_kind: CHANNEL_SERVICE_DISPATCH_EFFECT_KIND.to_owned(),
        request: service.request.clone(),
        admission_handoff: service.admission_handoff.clone(),
        target: service.provider.clone(),
        action_digest: service.action_digest.clone(),
        parameters_digest: reservation.digest()?,
        resource_head_digest: digest("anticipated-channel-head"),
        frost: None,
        idempotency_key: derive_channel_service_dispatch_idempotency_key(
            &reservation.body.operation_id,
            &reservation.body.reservation_id,
            reservation.body.next_sequence,
        )?,
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    effect.slot_id = effect.recompute_slot_id()?;
    Ok(effect.resource_head_key())
}

fn available_view(
    lifecycle: &ChannelLifecycleViewV1,
    escrow: &ChannelEscrowReservationViewV1,
    scope_id: &str,
    effect_key: EconomicResourceKeyV1,
    request: &EconomicRequestBindingV1,
) -> TestResult<VerifiedEconomicStateView> {
    let channel_state = EconomicContentV1::Inline {
        value: serde_json::to_value(lifecycle)?,
    };
    let escrow_state = EconomicContentV1::Inline {
        value: serde_json::to_value(escrow)?,
    };
    let mut heads = vec![
        EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: "channel-anchor".to_owned(),
            namespace: "channel-namespace".to_owned(),
            resource_key: EconomicResourceKeyV1 {
                resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
                scope_id: scope_id.to_owned(),
                resource_id: lifecycle.channel_id.clone(),
            },
            head_version: 1,
            resource_version: lifecycle.state_version,
            lifecycle_fence: lifecycle.lifecycle_fence,
            lifecycle_state: "open".to_owned(),
            state_digest: channel_state.digest()?,
            state: channel_state,
            operation_id: None,
            effect_idempotency_key: None,
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: BEGIN_AT,
            predecessor_digest: None,
        },
        EconomicResourceHeadV1 {
            schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
            anchor_id: "channel-anchor".to_owned(),
            namespace: "channel-namespace".to_owned(),
            resource_key: EconomicResourceKeyV1 {
                resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
                scope_id: scope_id.to_owned(),
                resource_id: escrow.channel_id.clone(),
            },
            head_version: 1,
            resource_version: escrow.version,
            lifecycle_fence: escrow.lifecycle_fence,
            lifecycle_state: "open".to_owned(),
            state_digest: escrow_state.digest()?,
            state: escrow_state,
            operation_id: None,
            effect_idempotency_key: None,
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: BEGIN_AT,
            predecessor_digest: None,
        },
    ];
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        checkpoint_sequence: 1,
        checkpoint_digest: digest("reservation-base-checkpoint"),
        heads_root: String::new(),
        heads,
        absent_resource_keys: vec![effect_key],
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: vec![request.key()],
        observed_at: BEGIN_AT,
        signer_key_id: "channel-anchor-key".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&Keypair::from_seed(&[61; 32]))?;
    Ok(verify_economic_state_view(view, &anchor_pins())?)
}

fn signed_projection_batch(
    current: &VerifiedEconomicStateView,
    projection: &ChannelLifecycleProjectionV1,
) -> TestResult<EconomicStateBatchV1> {
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
        transitions: projection.transitions().to_vec(),
        effect_slots: projection.effect_slots().to_vec(),
        request_replays: projection.request_replays().to_vec(),
        operation_id: projection.operation_id().map(str::to_owned),
        issued_at: STAGE_AT,
        signer_key_id: current.view().signer_key_id.clone(),
        signer_key_epoch: current.view().signer_key_epoch,
        anchor_signature: String::new(),
    };
    batch.seal(&Keypair::from_seed(&[61; 32]))?;
    Ok(batch)
}

fn committed_view(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
) -> TestResult<VerifiedEconomicStateView> {
    let mut committed = current.view().clone();
    committed.checkpoint_sequence = batch.checkpoint_sequence;
    committed.checkpoint_digest = batch.checkpoint_digest.clone();
    committed.observed_at = batch.issued_at;
    for transition in &batch.transitions {
        committed
            .heads
            .retain(|head| head.resource_key != transition.resource_key);
        committed.heads.push(transition.next_head.clone());
        committed
            .absent_resource_keys
            .retain(|key| key != &transition.resource_key);
    }
    for replay in &batch.request_replays {
        let key = replay.request.key();
        committed
            .request_replays
            .retain(|current| current.request.key() != key);
        committed.request_replays.push(replay.clone());
        committed
            .absent_request_keys
            .retain(|absent| absent != &key);
    }
    committed
        .heads
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    committed
        .request_replays
        .sort_by_key(|replay| replay.request.key());
    committed.seal(&Keypair::from_seed(&[61; 32]))?;
    Ok(verify_economic_state_view(committed, &anchor_pins())?)
}

fn reservation_flow(fence: &StoreMutationFence, request_id: &str) -> TestResult<ReservationFlow> {
    reservation_flow_with_state_version(fence, request_id, 1)
}

fn reservation_flow_with_state_version(
    fence: &StoreMutationFence,
    request_id: &str,
    initial_state_version: u64,
) -> TestResult<ReservationFlow> {
    let operation = prepared_operation(fence, request_id)?;
    let open = open_fixture()?;
    let prior = open.open.initial_state().clone();
    let open_digest = open.open.artifact().digest()?;
    let prior_digest = prior.digest()?;
    let provider = ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: format!("attempt-{request_id}"),
        transport_id: format!("transport-{request_id}"),
        transport_key_epoch: 9,
    };
    let service = ChannelServiceBindingV1 {
        request: EconomicRequestBindingV1 {
            request_namespace_digest: operation
                .binding()
                .request_namespace_digest()
                .as_str()
                .to_owned(),
            request_id: operation.binding().request_id().as_str().to_owned(),
            request_binding_digest: operation
                .binding()
                .request_binding_hash()
                .as_str()
                .to_owned(),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: expected_dispatch_committed_version(
                operation.binding().kind(),
                operation.binding().participant_requirements(),
                operation.version(),
            )?,
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: fence.clone(),
        },
        provider: EconomicEffectTargetV1 {
            target_id: provider.transport_id.clone(),
            target_key_epoch: provider.transport_key_epoch,
            qualification_digest: digest("reservation-provider-qualification"),
        },
        action_digest: operation
            .binding()
            .action_parameter_hash()
            .as_str()
            .to_owned(),
    };
    let reservation_authority_key = Keypair::from_seed(&[33; 32]);
    let reservation_authority = ChannelReservationAuthorityV1 {
        authority_id: "channel-authority".to_owned(),
        authority_key_epoch: 7,
        authority_key: reservation_authority_key.public_key(),
        trusted_time_unix_ms: BEGIN_AT,
    };
    let trusted_kernel_key = Keypair::from_seed(&[36; 32]);
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: derive_channel_reservation_id(
            &open.open.artifact().body.channel_id,
            &open_digest,
            operation.binding().request_id().as_str(),
            1,
            &prior_digest,
        )?,
        channel_id: open.open.artifact().body.channel_id.clone(),
        open_digest: open_digest.clone(),
        request_id: operation.binding().request_id().as_str().to_owned(),
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        next_sequence: 1,
        prior_state_digest: prior_digest.clone(),
        service_binding_digest: service.digest()?,
        receipt_authority_digest: derive_channel_receipt_authority_digest(
            &trusted_kernel_key.public_key(),
        )?,
        maximum_charge: MonetaryAmount {
            units: 40,
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: "400000".to_owned(),
        expires_at_unix_ms: RESERVATION_EXPIRES_AT,
        disposition_expected_version: 1,
        channel_state_expected_version: initial_state_version,
        lifecycle_fence: 2,
    };
    let signed_reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            open.trust.payer_id.clone(),
            open.trust.payer_key_epoch,
            &open.payer_key,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &reservation_body,
            reservation_authority.authority_id.clone(),
            reservation_authority.authority_key_epoch,
            &reservation_authority_key,
        )?,
        body: reservation_body,
    };
    let lifecycle = ChannelLifecycleViewV1 {
        schema: chio_settle::channel::CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: open.open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: prior_digest,
        latest_sequence: prior.body().seq,
        state_version: initial_state_version,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: lifecycle.channel_id.clone(),
        open_digest,
        escrow_reference: open.open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 2,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
    };
    let effect_key = anticipated_effect_key(
        &signed_reservation,
        &service,
        &open.trust.settlement_authority_scope_id,
    )?;
    let current = available_view(
        &lifecycle,
        &escrow,
        &open.trust.settlement_authority_scope_id,
        effect_key,
        &service.request,
    )?;
    let admitted_open = verify_admitted_channel_open(&open.open, &current)?;
    let proposal = verify_channel_reservation_proposal(
        &signed_reservation,
        &admitted_open,
        &prior,
        &reservation_authority,
        &open.trust,
    )?;
    let prepared_artifact = prepare_channel_reservation(
        &admitted_open,
        &prior,
        &current,
        proposal.artifact().body.clone(),
        service.clone(),
    )?;
    let prepared = verify_channel_prepared_reservation(
        &prepared_artifact,
        &admitted_open,
        &prior,
        &current,
        &proposal.artifact().body,
        &service,
    )?;
    let context = ChannelReservationReplayContextV1::from_pre_anchor(&prepared, &proposal)?;
    let projection = compose_channel_reservation_transition(&prepared, &proposal, STAGE_AT)?;
    let batch = signed_projection_batch(&current, &projection)?;
    let authority_pins = ChannelTransitionReplayAuthorityPinsV1::new(
        open.trust.clone(),
        open.funding_authority.clone(),
        reservation_authority,
        Some(trusted_kernel_key.public_key()),
        &anchor_pins(),
    )?;
    let descriptor = ChannelTransitionReplayDescriptorV1::for_reservation(
        &context,
        &ChannelTransitionReplayOpenArtifactsV1 {
            funding_evidence: open.funding.clone(),
            funding_acknowledgement: open.funding_acknowledgement.clone(),
            dispute_policy: open.dispute_policy.clone(),
        },
        &authority_pins,
        &batch,
    )?;
    let replay_bytes = descriptor.canonical_bytes()?;
    let verifier =
        ChannelTransitionReplayVerifierV1::from_canonical_bytes(&replay_bytes, &authority_pins)?;
    let advance =
        verify_economic_state_batch_advance(&current, batch.clone(), &anchor_pins(), &verifier)?;
    let committed = committed_view(&current, &batch)?;
    let reservation = verifier.verify_committed_reservation(&committed)?;
    Ok(ReservationFlow {
        operation,
        prepared,
        authority_pins,
        replay_bytes,
        advance,
        committed,
        provider,
        open: open.open,
        prior,
        reservation,
        trust: open.trust,
        payee_key: open.payee_key,
        kernel_key: trusted_kernel_key,
    })
}

fn claim(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    claimant: &str,
    claimed_at: u64,
    expires_at: u64,
) -> TestResult<chio_kernel::admission_operation::AdmissionRecoveryLease> {
    Ok(fixture
        .authority
        .admission_operation_store()
        .claim_recovery(
            operation.binding().operation_id(),
            operation.version(),
            &identifier("claimant_id", claimant)?,
            claimed_at,
            expires_at,
            &fixture.fence,
        )?)
}

fn unrelated_operation(fence: &StoreMutationFence) -> TestResult<AdmissionOperationV1> {
    let namespace = AuthenticatedRequestNamespace::for_local_system(identifier(
        "coordinator_authority_id",
        "channel-unrelated-authority",
    )?)?;
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::GovernedEconomicMutation,
        namespace,
        request_id: identifier("request_id", "same-fence-unrelated-claim")?,
        capability_id: identifier("capability_id", "same-fence-unrelated-capability")?,
        authorization_capability_hash: admission_digest(
            "authorization_capability_hash",
            "same-fence-unrelated-authorization",
        )?,
        request_binding: AdmissionRequestBindingV1::new(
            admission_digest("immutable_request_hash", "same-fence-unrelated-request")?,
            AdmissionParticipantRequirements::NONE,
        )?,
        policy_hash: admission_digest("policy_hash", "same-fence-unrelated-policy")?,
        effect_class: SideEffectClass::SideEffecting,
    })?;
    Ok(AdmissionOperationV1::prepare(binding, fence.owner_epoch)?)
}

fn begin_and_authorize_budget(
    fixture: &Fixture,
    flow: &ReservationFlow,
) -> TestResult<AdmissionOperationV1> {
    let created = fixture.store.begin_channel_prepared(
        &flow.operation,
        &flow.prepared,
        &fixture.fence,
        BEGIN_AT,
    )?;
    let ChannelPreparedBeginResult::Created(record) = created else {
        return Err("channel prepared begin was not created".into());
    };
    let mut operation = record.operation().clone();
    let broker = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        claim(
            fixture,
            &operation,
            "reservation-worker",
            BEGIN_AT + 1,
            1_550,
        )?,
        vec![AdmissionAttachment::BrokerAttempt(flow.provider.clone())],
        Some(AdmissionOperationState::BrokerAttemptRegistered),
        None,
        None,
    )?;
    operation = fixture
        .authority
        .admission_operation_store()
        .compare_and_swap(&broker, BROKER_AT)?
        .into_operation();
    let budget = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        claim(fixture, &operation, "reservation-worker", 1_551, 1_600)?,
        vec![AdmissionAttachment::BudgetHoldId(identifier(
            "budget_hold_id",
            "reservation-budget-hold",
        )?)],
        Some(AdmissionOperationState::BudgetAuthorized),
        None,
        None,
    )?;
    Ok(fixture
        .authority
        .admission_operation_store()
        .compare_and_swap(&budget, BUDGET_AT)?
        .into_operation())
}

fn stage_and_anchor(fixture: &Fixture, flow: &ReservationFlow) -> TestResult<AdmissionOperationV1> {
    stage_and_anchor_with_claimant(fixture, flow, "reservation-worker")
}

fn stage_and_anchor_with_claimant(
    fixture: &Fixture,
    flow: &ReservationFlow,
    claimant: &str,
) -> TestResult<AdmissionOperationV1> {
    let operation = begin_and_authorize_budget(fixture, flow)?;
    let stage_lease = claim(fixture, &operation, claimant, 1_601, 1_650)?;
    fixture.store.stage_channel_reservation(
        &flow.advance,
        &operation,
        &stage_lease,
        &flow.replay_bytes,
        &flow.authority_pins,
        &fixture.fence,
        STAGE_AT,
    )?;
    fixture.store.record_channel_anchor_advanced(
        operation.binding().operation_id(),
        &flow.advance,
        &flow.committed,
        &flow.authority_pins,
        &fixture.fence,
        ANCHOR_AT,
    )?;
    Ok(operation)
}

fn finalize_after_expiry(
    fixture: &Fixture,
    flow: &ReservationFlow,
) -> TestResult<ChannelReservationStageRecordV1> {
    let operation = stage_and_anchor(fixture, flow)?;
    let takeover = claim(
        fixture,
        &operation,
        "post-expiry-takeover",
        TAKEOVER_AT,
        2_600,
    )?;
    Ok(fixture.store.finalize_channel_reservation(
        operation.binding().operation_id(),
        &takeover,
        &flow.authority_pins,
        &fixture.fence,
        FINALIZE_AT,
    )?)
}

#[test]
fn anchored_reservation_finalizes_after_expiry_under_a_new_serving_owner() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(2, std::iter::empty::<String>());
    let fixture = fixture()?;
    let flow = reservation_flow(&fixture.fence, "post-expiry-finalize")?;
    let operation = stage_and_anchor(&fixture, &flow)?;
    let historical_fence = fixture.fence.clone();
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);

    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.channel_lifecycle_store();
    let fence = authority.mutation_fence();
    assert_eq!(fence.store_uuid, historical_fence.store_uuid);
    assert!(fence.owner_epoch > historical_fence.owner_epoch);
    let fixture = Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    };
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("post-expiry operation was not retained across owner takeover")?;
    let takeover = claim(
        &fixture,
        &operation,
        "post-expiry-owner-takeover",
        TAKEOVER_AT,
        2_600,
    )?;
    let live = fixture.store.finalize_channel_reservation(
        operation.binding().operation_id(),
        &takeover,
        &flow.authority_pins,
        &fixture.fence,
        FINALIZE_AT,
    )?;

    assert!(FINALIZE_AT > live.reservation().body.expires_at_unix_ms);
    assert_eq!(live.disposition(), ChannelReservationDispositionV1::Live);
    assert_eq!(
        live.operation().state(),
        AdmissionOperationState::ReadyToDispatch
    );
    assert_eq!(
        live.economic_stage().status(),
        EconomicStateStageStatus::DbFinalized
    );
    fixture.store.verify_invariants()?;
    Ok(())
}

#[test]
fn live_replay_rejects_a_store_qualified_same_fence_claim_for_another_operation() -> TestResult {
    let _runtime =
        chio_kernel::scope_fixed_runtime_for_current_thread(2, std::iter::empty::<String>());
    let fixture = fixture()?;
    let flow = reservation_flow(&fixture.fence, "live-replay-authority")?;
    let live = finalize_after_expiry(&fixture, &flow)?;
    let unrelated = unrelated_operation(&fixture.fence)?;
    fixture.authority.admission_operation_store().begin(
        &unrelated,
        &fixture.fence,
        FINALIZE_AT + 1,
    )?;
    let unrelated = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(unrelated.binding().operation_id())?
        .ok_or("unrelated operation was not retained")?;
    let substituted_lease = claim(
        &fixture,
        &unrelated,
        "fabricated-finalizer",
        FINALIZE_AT + 2,
        2_600,
    )?;

    let substituted_result = fixture.store.finalize_channel_reservation(
        live.operation().binding().operation_id(),
        &substituted_lease,
        &flow.authority_pins,
        &fixture.fence,
        FINALIZE_AT + 3,
    );
    assert!(
        matches!(&substituted_result, Err(ChannelLifecycleStoreError::Fenced)),
        "same-fence substituted authority returned {substituted_result:?}"
    );

    let current = claim(
        &fixture,
        live.operation(),
        "live-replay-worker",
        2_601,
        2_700,
    )?;
    let replay = fixture.store.finalize_channel_reservation(
        live.operation().binding().operation_id(),
        &current,
        &flow.authority_pins,
        &fixture.fence,
        2_602,
    )?;
    assert_eq!(replay.disposition(), ChannelReservationDispositionV1::Live);
    assert_eq!(replay.record_version(), live.record_version());
    Ok(())
}

#[path = "reservation/terminal.rs"]
mod terminal;
