use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_batch_commit,
    verify_economic_state_view, EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1,
    EconomicContentV1, EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1,
    EconomicEffectTerminalV1, EconomicNoEffectKindV1, EconomicRequestBindingV1,
    EconomicRequestReplayV1, EconomicResourceHeadV1, EconomicResourceKeyV1,
    EconomicStateAnchorError, EconomicStateAnchorPins, EconomicStateAnchorViewV1,
    EconomicStateBatchV1, EconomicStateTransitionV1, EconomicTerminalResultV1,
    EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::{Decision, ToolCallAction};
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

use super::super::*;
use crate::SettlementError;

fn digest(label: &str) -> String {
    chio_core::crypto::sha256_hex(label.as_bytes())
}

fn evm_hash(label: &str) -> String {
    format!("0x{}", digest(label))
}

fn channel_anchor_pins() -> EconomicStateAnchorPins {
    EconomicStateAnchorPins {
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        signer_key_id: "channel-anchor-key".to_owned(),
        signer_key_epoch: 1,
        signer_public_key: Keypair::from_seed(&[61; 32]).public_key(),
    }
}

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

fn anchored_channel_view(
    scope_id: &str,
    lifecycle: &ChannelLifecycleViewV1,
    escrow: &ChannelEscrowReservationViewV1,
    observed_at_unix_ms: u64,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    anchored_channel_view_with_clocks(
        scope_id,
        lifecycle,
        escrow,
        observed_at_unix_ms,
        observed_at_unix_ms,
        observed_at_unix_ms,
    )
}

fn anchored_channel_view_with_clocks(
    scope_id: &str,
    lifecycle: &ChannelLifecycleViewV1,
    escrow: &ChannelEscrowReservationViewV1,
    channel_clock_high_water: u64,
    escrow_clock_high_water: u64,
    observed_at_unix_ms: u64,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    anchored_channel_view_with_heads(
        scope_id,
        lifecycle,
        escrow,
        ChannelViewClocks {
            channel_high_water: channel_clock_high_water,
            escrow_high_water: escrow_clock_high_water,
            observed_at: observed_at_unix_ms,
        },
        Vec::new(),
        &digest("channel-checkpoint"),
        None,
    )
}

struct ChannelViewClocks {
    channel_high_water: u64,
    escrow_high_water: u64,
    observed_at: u64,
}

impl ChannelViewClocks {
    const fn at(timestamp: u64) -> Self {
        Self {
            channel_high_water: timestamp,
            escrow_high_water: timestamp,
            observed_at: timestamp,
        }
    }
}

fn anchored_channel_view_with_heads(
    scope_id: &str,
    lifecycle: &ChannelLifecycleViewV1,
    escrow: &ChannelEscrowReservationViewV1,
    clocks: ChannelViewClocks,
    additional_heads: Vec<EconomicResourceHeadV1>,
    checkpoint_digest: &str,
    predecessor: Option<&VerifiedChannelLifecycleSnapshotV1>,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    let ChannelViewClocks {
        channel_high_water,
        escrow_high_water,
        observed_at,
    } = clocks;
    let anchor_key = Keypair::from_seed(&[61; 32]);
    let operation_id = lifecycle.operation_id.clone();
    let effect_idempotency_key = operation_id.as_ref().map(|value| digest(value));
    let channel_state = EconomicContentV1::Inline {
        value: serde_json::to_value(lifecycle)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    let escrow_state = EconomicContentV1::Inline {
        value: serde_json::to_value(escrow)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    let (channel_head_version, channel_predecessor_digest) = match predecessor {
        Some(snapshot) => (
            snapshot
                .channel_head()
                .head_version
                .checked_add(1)
                .ok_or(ChannelError::ArithmeticOverflow)?,
            Some(snapshot.channel_head_digest().to_owned()),
        ),
        None => (1, None),
    };
    let (escrow_head_version, escrow_predecessor_digest) = match predecessor {
        Some(snapshot) => (
            snapshot
                .escrow_head()
                .head_version
                .checked_add(1)
                .ok_or(ChannelError::ArithmeticOverflow)?,
            Some(snapshot.escrow_head_digest().to_owned()),
        ),
        None => (1, None),
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
            head_version: channel_head_version,
            resource_version: lifecycle.state_version,
            lifecycle_fence: lifecycle.lifecycle_fence,
            lifecycle_state: match lifecycle.status {
                ChannelLifecycleStatusV1::Open => "open",
                ChannelLifecycleStatusV1::ClosePending => "close_pending",
                ChannelLifecycleStatusV1::Closing => "closing",
                ChannelLifecycleStatusV1::Released => "released",
                ChannelLifecycleStatusV1::Refunded => "refunded",
                ChannelLifecycleStatusV1::Incident => "incident",
            }
            .to_owned(),
            state_digest: channel_state
                .digest()
                .map_err(|_| ChannelError::AuthorityVerification)?,
            state: channel_state,
            operation_id: operation_id.clone(),
            effect_idempotency_key: effect_idempotency_key.clone(),
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: channel_high_water,
            predecessor_digest: channel_predecessor_digest,
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
            head_version: escrow_head_version,
            resource_version: escrow.version,
            lifecycle_fence: escrow.lifecycle_fence,
            lifecycle_state: match escrow.status {
                ChannelEscrowReservationStatusV1::Open => "open",
                ChannelEscrowReservationStatusV1::Closing => "closing",
                ChannelEscrowReservationStatusV1::Released => "released",
                ChannelEscrowReservationStatusV1::Refunded => "refunded",
                ChannelEscrowReservationStatusV1::Incident => "incident",
            }
            .to_owned(),
            state_digest: escrow_state
                .digest()
                .map_err(|_| ChannelError::AuthorityVerification)?,
            state: escrow_state,
            operation_id,
            effect_idempotency_key,
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: escrow_high_water,
            predecessor_digest: escrow_predecessor_digest,
        },
    ];
    heads.extend(additional_heads);
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        checkpoint_sequence: 1,
        checkpoint_digest: checkpoint_digest.to_owned(),
        heads_root: String::new(),
        heads,
        absent_resource_keys: Vec::new(),
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at,
        signer_key_id: "channel-anchor-key".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&anchor_key)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_view(
        view,
        &EconomicStateAnchorPins {
            anchor_id: "channel-anchor".to_owned(),
            namespace: "channel-namespace".to_owned(),
            signer_key_id: "channel-anchor-key".to_owned(),
            signer_key_epoch: 1,
            signer_public_key: anchor_key.public_key(),
        },
    )
    .map_err(|_| ChannelError::AuthorityVerification)
}

fn anchored_channel_successor_view(
    scope_id: &str,
    lifecycle: &ChannelLifecycleViewV1,
    escrow: &ChannelEscrowReservationViewV1,
    observed_at_unix_ms: u64,
    predecessor: &VerifiedChannelLifecycleSnapshotV1,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    anchored_channel_view_with_heads(
        scope_id,
        lifecycle,
        escrow,
        ChannelViewClocks::at(observed_at_unix_ms),
        Vec::new(),
        &digest("channel-checkpoint"),
        Some(predecessor),
    )
}

fn effect_head(
    effect: &EconomicEffectSlotV1,
    head_version: u64,
    predecessor_digest: Option<String>,
    observed_at_unix_ms: u64,
) -> Result<EconomicResourceHeadV1, ChannelError> {
    let (lifecycle_state, terminal_result) = match (&effect.state, &effect.terminal) {
        (EconomicEffectStateV1::Ready, None) => ("ready", None),
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
        _ => return Err(ChannelError::AuthorityVerification),
    };
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(effect)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: effect.anchor_id.clone(),
        namespace: effect.namespace.clone(),
        resource_key: effect.resource_head_key(),
        head_version,
        resource_version: head_version,
        lifecycle_fence: head_version,
        lifecycle_state: lifecycle_state.to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        state,
        operation_id: Some(effect.operation_id.clone()),
        effect_idempotency_key: Some(effect.idempotency_key.clone()),
        frost: None,
        terminal_result,
        trusted_clock_high_water: observed_at_unix_ms,
        predecessor_digest,
    })
}

fn ready_channel_service(request_id: &str) -> Result<ChannelServiceBindingV1, ChannelError> {
    Ok(ChannelServiceBindingV1 {
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("ready-request-namespace"),
            request_id: request_id.to_owned(),
            request_binding_digest: digest("ready-request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: 4,
            lifecycle_fence: 5,
            store_fence: serde_json::from_value(serde_json::json!({
                "store_uuid": "ready-store",
                "lease_id": "ready-lease",
                "owner_epoch": 1,
            }))
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
        },
        provider: EconomicEffectTargetV1 {
            target_id: "ready-target".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("ready-target-qualification"),
        },
        action_digest: digest("ready-action"),
    })
}

fn ready_channel_effect(
    proposal: &VerifiedChannelReservationProposalV1,
    scope_id: &str,
    channel_head_digest: &str,
    observed_at_unix_ms: u64,
) -> Result<(EconomicEffectSlotV1, EconomicResourceHeadV1), ChannelError> {
    let body = &proposal.artifact().body;
    let service = ready_channel_service(&body.request_id)?;
    let mut effect = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: digest("ready-channel-effect-placeholder"),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
            scope_id: scope_id.to_owned(),
            resource_id: body.channel_id.clone(),
        },
        operation_id: body.operation_id.clone(),
        effect_kind: CHANNEL_SERVICE_DISPATCH_EFFECT_KIND.to_owned(),
        request: service.request,
        admission_handoff: service.admission_handoff,
        target: service.provider,
        action_digest: service.action_digest,
        parameters_digest: proposal.artifact().digest()?,
        resource_head_digest: channel_head_digest.to_owned(),
        frost: None,
        idempotency_key: derive_channel_service_dispatch_idempotency_key(
            &body.operation_id,
            &body.reservation_id,
            body.next_sequence,
        )?,
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    effect.slot_id = effect
        .recompute_slot_id()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let head = effect_head(&effect, 1, None, observed_at_unix_ms)?;
    Ok((effect, head))
}

fn retain_ready_request(
    current: &VerifiedEconomicStateView,
    effect: &EconomicEffectSlotV1,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    let mut view = current.view().clone();
    view.checkpoint_sequence = view
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    view.request_replays = vec![EconomicRequestReplayV1 {
        request: effect.request.clone(),
        operation_id: effect.operation_id.clone(),
        effect_slot_ids: vec![effect.slot_id.clone()],
    }];
    view.seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_view(view, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)
}

fn state_head_successor<T: serde::Serialize>(
    current: &EconomicResourceHeadV1,
    state: &T,
    resource_version: u64,
    lifecycle_fence: u64,
    lifecycle_state: &str,
    observed_at_unix_ms: u64,
) -> Result<EconomicResourceHeadV1, ChannelError> {
    let content = EconomicContentV1::Inline {
        value: serde_json::to_value(state)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: current
            .head_version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        resource_version,
        lifecycle_fence,
        lifecycle_state: lifecycle_state.to_owned(),
        state_digest: content
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        state: content,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: observed_at_unix_ms,
        predecessor_digest: Some(
            current
                .digest()
                .map_err(|_| ChannelError::AuthorityVerification)?,
        ),
    })
}

fn verified_terminal_batch(
    current: &VerifiedEconomicStateView,
    operation_id: &str,
    transitions: Vec<EconomicStateTransitionV1>,
    issued_at: u64,
) -> Result<VerifiedEconomicStateBatchAdvance, ChannelError> {
    let key = Keypair::from_seed(&[61; 32]);
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        checkpoint_sequence: current
            .view()
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: Some(operation_id.to_owned()),
        issued_at,
        signer_key_id: "channel-anchor-key".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    batch
        .seal(&key)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_batch_advance(
        current,
        batch,
        &channel_anchor_pins(),
        &DirectTransitionVerifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)
}

fn asset_binding(protocol_decimals: u8, token_decimals: u8) -> ChannelAssetBindingV1 {
    ChannelAssetBindingV1 {
        schema: CHANNEL_ASSET_BINDING_SCHEMA.to_owned(),
        currency: "USD".to_owned(),
        protocol_minor_unit_decimals: protocol_decimals,
        chain_id: "eip155:31337".to_owned(),
        token_address: "0x1111111111111111111111111111111111111111".to_owned(),
        token_symbol: "USDC".to_owned(),
        token_decimals,
        settlement_policy_digest: digest("settlement-policy"),
    }
}

fn funding_body() -> ChannelFundingEvidenceBodyV1 {
    let depositor = "0x2222222222222222222222222222222222222222".to_owned();
    let beneficiary = "0x3333333333333333333333333333333333333333".to_owned();
    let operator = "0x4444444444444444444444444444444444444444".to_owned();
    let operator_key_hash = evm_hash("operator-key");
    let escrow_id = evm_hash("escrow-id");
    let escrow_contract = "0x5555555555555555555555555555555555555555".to_owned();
    let block_hash = evm_hash("funding-block");
    let terms = ChannelEscrowTermsV1 {
        capability_id: evm_hash("capability-1"),
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
            call_data_digest: evm_hash("get-escrow-call"),
            return_data_digest: evm_hash("get-escrow-result"),
        },
        creation_event: ChannelEscrowCreatedEventV1 {
            transaction_hash: evm_hash("creation-transaction"),
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
        asset_binding: asset_binding(2, 6),
        block_pin: ChannelBlockPinV1 {
            block_number: 100,
            block_hash,
            block_timestamp_unix_secs: 1,
            observed_at_unix_ms: 1_100,
            required_confirmations: 12,
            observed_confirmations: 12,
            finalized_head_number: 112,
            finalized_head_hash: evm_hash("finalized-head"),
            finality_mode: chio_core::web3::trust_profile::Web3FinalityMode::L1Finalized,
            finality_status: ChannelFinalityStatusV1::Finalized,
        },
        evidence_expires_at_unix_ms: 1_900,
    }
}

fn funding_authority(
    key: &Keypair,
    trusted_time_unix_ms: u64,
    body: &ChannelFundingEvidenceBodyV1,
) -> ChannelFundingAuthorityV1 {
    ChannelFundingAuthorityV1 {
        authority_id: "funding-authority".to_owned(),
        authority_key_epoch: 4,
        authority_key: key.public_key(),
        trusted_time_unix_ms,
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

struct VerifiedChannelFixture {
    payer_key: Keypair,
    payee_key: Keypair,
    trust: ChannelOpenTrustV1,
    funding: SignedChannelFundingEvidenceV1,
    funding_authority: ChannelFundingAuthorityV1,
    funding_acknowledgement: SignedChannelFundingAcknowledgementV1,
    dispute_policy: ChannelDisputePolicyV1,
    open: VerifiedChannelOpenConsentV1,
}

fn verified_channel_fixture() -> Result<VerifiedChannelFixture, ChannelError> {
    verified_channel_fixture_with_intent("transition-open-intent")
}

fn verified_channel_fixture_with_intent(
    open_intent_label: &str,
) -> Result<VerifiedChannelFixture, ChannelError> {
    use chio_core::web3::trust_profile::Web3FinalityMode;

    let payer_key = Keypair::from_seed(&[31; 32]);
    let payee_key = Keypair::from_seed(&[32; 32]);
    let funding_key = Keypair::from_seed(&[35; 32]);
    let policy = ChannelDisputePolicyV1 {
        schema: CHANNEL_DISPUTE_POLICY_SCHEMA.to_owned(),
        policy_id: "transition-policy".to_owned(),
        fixed_finality_broadcast_margin_secs: 50,
        tiers: vec![
            ChannelDisputeTierV1 {
                upper_bound_units: 1_000,
                dispute_window_secs: 100,
                required_confirmations: 12,
                finality_mode: Web3FinalityMode::L1Finalized,
            },
            ChannelDisputeTierV1 {
                upper_bound_units: crate::channel::validation::I_JSON_MAX_SAFE_INTEGER,
                dispute_window_secs: 200,
                required_confirmations: 64,
                finality_mode: Web3FinalityMode::L1Finalized,
            },
        ],
    };
    let mut funding_body = funding_body();
    funding_body.asset_binding.settlement_policy_digest = policy.digest()?;
    let funding = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &funding_body,
            "funding-authority".to_owned(),
            4,
            &funding_key,
        )?,
        body: funding_body,
    };
    let funding_authority = funding_authority(&funding_key, 1_500, &funding.body);
    let trust = ChannelOpenTrustV1 {
        payer_id: "payer".to_owned(),
        payer_key: payer_key.public_key(),
        payer_key_epoch: 2,
        payee_id: "payee".to_owned(),
        payee_key: payee_key.public_key(),
        payee_key_epoch: 3,
        settlement_authority_scope_id: "channel-settlement".to_owned(),
        original_web3_dispatch_digest: digest("transition-web3-dispatch"),
        participant_snapshot_digest: digest("transition-participants"),
        trusted_time_unix_ms: 1_500,
    };
    let intent_body = ChannelOpenIntentBodyV1 {
        schema: CHANNEL_OPEN_INTENT_SCHEMA.to_owned(),
        open_intent_id: digest(open_intent_label),
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
    let verified_intent =
        verify_channel_open_intent(&intent, &funding, &funding_authority, &policy, &trust)?;
    let acknowledgement_body = ChannelFundingAcknowledgementBodyV1 {
        schema: CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
        open_intent_digest: intent.digest()?,
        escrow_reference: intent.body.escrow_reference.clone(),
        prior_state: ChannelEscrowReservationStateV1::Unreserved,
        prior_version: 1,
        prior_head_digest: digest("transition-unreserved-head"),
        new_state: ChannelEscrowReservationStateV1::Opening,
        new_version: 2,
        anchored_head_digest: digest("transition-opening-head"),
        reserved_at_unix_ms: 1_400,
        expires_at_unix_ms: 1_700,
    };
    let acknowledgement = SignedChannelFundingAcknowledgementV1 {
        authority_signature: ChannelSignatureV1::sign(
            &acknowledgement_body,
            funding_authority.authority_id.clone(),
            funding_authority.authority_key_epoch,
            &funding_key,
        )?,
        body: acknowledgement_body,
    };
    let intent_digest = intent.digest()?;
    let acknowledgement_digest = acknowledgement.digest()?;
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
    let open = SignedChannelOpenV1 {
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
        &open,
        &verified_intent,
        &acknowledgement,
        &funding_authority,
        &trust,
    )?;
    Ok(VerifiedChannelFixture {
        payer_key,
        payee_key,
        trust,
        funding,
        funding_authority,
        funding_acknowledgement: acknowledgement,
        dispute_policy: policy,
        open,
    })
}

struct TerminalAdvanceFixture {
    open: VerifiedChannelOpenConsentV1,
    open_trust: ChannelOpenTrustV1,
    funding: SignedChannelFundingEvidenceV1,
    funding_authority: ChannelFundingAuthorityV1,
    funding_acknowledgement: SignedChannelFundingAcknowledgementV1,
    dispute_policy: ChannelDisputePolicyV1,
    reservation_authority: ChannelReservationAuthorityV1,
    prepared: VerifiedChannelPreparedReservationV1,
    reservation: VerifiedAdmittedChannelReservationV1,
    ready_view: VerifiedEconomicStateView,
    prior: VerifiedChannelStateV1,
    next: VerifiedChannelStateV1,
    signed_next: SignedChannelStateV1,
    receipt: VerifiedChannelReceiptBindingV1,
    signed_receipt: ChioReceipt,
    trusted_kernel_key: chio_core::crypto::PublicKey,
    signed_terminal_outcome: SignedChannelTerminalOutcomeCommitmentV1,
    advance: VerifiedEconomicStateBatchAdvance,
    terminal_lifecycle: ChannelLifecycleViewV1,
    terminal_escrow: ChannelEscrowReservationViewV1,
    dispatch_effect: EconomicEffectSlotV1,
    completed_effect: EconomicEffectSlotV1,
    obligation: Option<ObligationAtomV1>,
}

fn terminal_advance_fixture() -> Result<TerminalAdvanceFixture, ChannelError> {
    terminal_advance_fixture_with_charge(25)
}

fn terminal_advance_fixture_with_charge(
    actual_charge_units: u64,
) -> Result<TerminalAdvanceFixture, ChannelError> {
    let fixture = verified_channel_fixture()?;
    let prior = fixture.open.initial_state().clone();
    let authority_key = Keypair::from_seed(&[33; 32]);
    let authority = ChannelReservationAuthorityV1 {
        authority_id: "channel-authority".to_owned(),
        authority_key_epoch: 7,
        authority_key: authority_key.public_key(),
        trusted_time_unix_ms: 1_500,
    };
    let open_digest = fixture.open.artifact().digest()?;
    let prior_digest = prior.digest()?;
    let operation_id = digest("terminal-operation");
    let request_id = "terminal-request".to_owned();
    let kernel_key = Keypair::from_seed(&[36; 32]);
    let service = ChannelServiceBindingV1 {
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("terminal-request-namespace"),
            request_id: request_id.clone(),
            request_binding_digest: digest("terminal-request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: 4,
            lifecycle_fence: 5,
            store_fence: serde_json::from_value(serde_json::json!({
                "store_uuid": "terminal-store",
                "lease_id": "terminal-lease",
                "owner_epoch": 1,
            }))
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
        },
        provider: EconomicEffectTargetV1 {
            target_id: "terminal-target".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("terminal-target-qualification"),
        },
        action_digest: digest("terminal-action"),
    };
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: derive_channel_reservation_id(
            &fixture.open.artifact().body.channel_id,
            &open_digest,
            &request_id,
            1,
            &prior_digest,
        )?,
        channel_id: fixture.open.artifact().body.channel_id.clone(),
        open_digest: open_digest.clone(),
        request_id,
        operation_id: operation_id.clone(),
        next_sequence: 1,
        prior_state_digest: prior_digest.clone(),
        service_binding_digest: service.digest()?,
        receipt_authority_digest: derive_channel_receipt_authority_digest(
            &kernel_key.public_key(),
        )?,
        maximum_charge: MonetaryAmount {
            units: 40,
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: "400000".to_owned(),
        expires_at_unix_ms: 1_700,
        disposition_expected_version: 1,
        channel_state_expected_version: 1,
        lifecycle_fence: 2,
    };
    let signed_reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            fixture.trust.payer_id.clone(),
            fixture.trust.payer_key_epoch,
            &fixture.payer_key,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &reservation_body,
            authority.authority_id.clone(),
            authority.authority_key_epoch,
            &authority_key,
        )?,
        body: reservation_body,
    };
    let available = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: fixture.open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: prior_digest.clone(),
        latest_sequence: prior.body().seq,
        state_version: 1,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let available_escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: available.channel_id.clone(),
        open_digest: open_digest.clone(),
        escrow_reference: fixture.open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 2,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
    };
    let available_view = anchored_channel_view(
        &fixture.trust.settlement_authority_scope_id,
        &available,
        &available_escrow,
        1_500,
    )?;
    let admitted_open = verify_admitted_channel_open(&fixture.open, &available_view)?;
    let proposal = verify_channel_reservation_proposal(
        &signed_reservation,
        &admitted_open,
        &prior,
        &authority,
        &fixture.trust,
    )?;
    let prepared_artifact = prepare_channel_reservation(
        &admitted_open,
        &prior,
        &available_view,
        proposal.artifact().body.clone(),
        service.clone(),
    )?;
    let prepared = verify_channel_prepared_reservation(
        &prepared_artifact,
        &admitted_open,
        &prior,
        &available_view,
        &proposal.artifact().body,
        &service,
    )?;
    let reserved = ChannelLifecycleViewV1 {
        state_version: 2,
        lifecycle_fence: 3,
        live_reservation_id: Some(proposal.artifact().body.reservation_id.clone()),
        operation_id: Some(operation_id),
        ..available.clone()
    };
    let reserved_escrow = ChannelEscrowReservationViewV1 {
        version: 3,
        lifecycle_fence: 3,
        ..available_escrow.clone()
    };
    let reserved_channel_view = anchored_channel_view_with_heads(
        &fixture.trust.settlement_authority_scope_id,
        &reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        Vec::new(),
        &digest("reserved-channel-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let reservation_digest = proposal.artifact().digest()?;
    let reserved_channel_head = reserved_channel_view
        .view()
        .head(&EconomicResourceKeyV1 {
            resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
            scope_id: fixture.trust.settlement_authority_scope_id.clone(),
            resource_id: fixture.open.artifact().body.channel_id.clone(),
        })
        .ok_or(ChannelError::AuthorityVerification)?;
    let mut ready_effect = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: digest("terminal-slot-placeholder"),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
            scope_id: fixture.trust.settlement_authority_scope_id.clone(),
            resource_id: fixture.open.artifact().body.channel_id.clone(),
        },
        operation_id: proposal.artifact().body.operation_id.clone(),
        effect_kind: CHANNEL_SERVICE_DISPATCH_EFFECT_KIND.to_owned(),
        request: service.request.clone(),
        admission_handoff: service.admission_handoff.clone(),
        target: service.provider.clone(),
        action_digest: service.action_digest.clone(),
        parameters_digest: reservation_digest.clone(),
        resource_head_digest: reserved_channel_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        frost: None,
        idempotency_key: derive_channel_service_dispatch_idempotency_key(
            &proposal.artifact().body.operation_id,
            &proposal.artifact().body.reservation_id,
            proposal.artifact().body.next_sequence,
        )?,
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    ready_effect.slot_id = ready_effect
        .recompute_slot_id()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let ready_head = effect_head(&ready_effect, 1, None, 1_500)?;
    let reservation_view = anchored_channel_view_with_heads(
        &fixture.trust.settlement_authority_scope_id,
        &reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        vec![ready_head.clone()],
        &digest("reservation-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let request_replay = EconomicRequestReplayV1 {
        request: ready_effect.request.clone(),
        operation_id: ready_effect.operation_id.clone(),
        effect_slot_ids: vec![ready_effect.slot_id.clone()],
    };
    let mut reservation_view = reservation_view.view().clone();
    reservation_view.checkpoint_sequence = 3;
    reservation_view.request_replays = vec![request_replay];
    reservation_view
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let reservation_view = verify_economic_state_view(reservation_view, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let reservation = verify_admitted_channel_reservation(&proposal, &prepared, &reservation_view)?;
    let mut dispatch_effect = ready_effect;
    dispatch_effect.state = EconomicEffectStateV1::DispatchCommitted;
    let dispatch_head = effect_head(
        &dispatch_effect,
        2,
        Some(
            ready_head
                .digest()
                .map_err(|_| ChannelError::AuthorityVerification)?,
        ),
        1_550,
    )?;
    let dispatch_advance = verified_terminal_batch(
        &reservation_view,
        &reservation.artifact().body.operation_id,
        vec![EconomicStateTransitionV1 {
            resource_key: dispatch_effect.resource_head_key(),
            expected_head_digest: dispatch_head.predecessor_digest.clone(),
            next_head: dispatch_head.clone(),
            transition_proof_digest: digest("dispatch-effect-proof"),
            prepared_effect: None,
        }],
        1_550,
    )?;
    let mut dispatched_view = reservation_view.view().clone();
    dispatched_view.checkpoint_sequence = dispatch_advance.batch().checkpoint_sequence;
    dispatched_view.checkpoint_digest = dispatch_advance.batch().checkpoint_digest.clone();
    dispatched_view.observed_at = 1_550;
    let dispatch_index = dispatched_view
        .heads
        .iter()
        .position(|head| head.resource_key == dispatch_effect.resource_head_key())
        .ok_or(ChannelError::AuthorityVerification)?;
    dispatched_view.heads[dispatch_index] = dispatch_head;
    dispatched_view
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let dispatched_view = verify_economic_state_view(dispatched_view, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_batch_commit(&dispatch_advance, &dispatched_view, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let actual_charge = MonetaryAmount {
        units: actual_charge_units,
        currency: "USD".to_owned(),
    };
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "terminal-receipt".to_owned(),
            timestamp: 1,
            capability_id: "capability-1".to_owned(),
            tool_server: "server-1".to_owned(),
            tool_name: "tool-1".to_owned(),
            action: ToolCallAction::from_parameters(serde_json::json!({"value": 1}))
                .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: digest("terminal-receipt-content"),
            policy_hash: digest("terminal-receipt-policy"),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "channel": ChannelReceiptMetadataV1 {
                    schema: CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA.to_owned(),
                    channel_id: fixture.open.artifact().body.channel_id.clone(),
                    open_digest: open_digest.clone(),
                    reservation_id: reservation.artifact().body.reservation_id.clone(),
                    reservation_digest: reservation_digest.clone(),
                    sequence: reservation.artifact().body.next_sequence,
                    settlement_mode: ChannelSettlementModeV1::Channelized,
                },
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: actual_charge.units,
                    currency: actual_charge.currency.clone(),
                    budget_remaining: 150_u64
                        .checked_sub(actual_charge.units)
                        .ok_or(ChannelError::ArithmeticOverflow)?,
                    budget_total: 150,
                    delegation_depth: 0,
                    root_budget_holder: fixture.trust.payer_id.clone(),
                    payment_reference: None,
                    settlement_status: if actual_charge.units == 0 {
                        SettlementStatus::NotApplicable
                    } else {
                        SettlementStatus::Pending
                    },
                    cost_breakdown: None,
                    oracle_evidence: None,
                    attempted_cost: None,
                },
            })),
            trust_level: TrustLevel::Mediated,
            tenant_id: None,
            kernel_key: kernel_key.public_key(),
            bbs_projection_version: None,
        },
        &kernel_key,
    )
    .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    let signed_receipt = receipt.clone();
    let receipt_digest = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&receipt)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    );
    let obligation = (actual_charge.units > 0)
        .then(|| {
            ObligationAtomV1::new(ObligationAtomInputV1 {
                economic_intent_digest: reservation.artifact().body.proposal_digest()?,
                source_receipt_id: receipt.id.clone(),
                source_receipt_digest: receipt_digest,
                debtor_id: fixture.open.intent().body.payer_id.clone(),
                original_creditor_id: fixture.open.intent().body.payee_id.clone(),
                original_settlement_destination_ref: fixture
                    .open
                    .intent()
                    .body
                    .payee_beneficiary_address
                    .clone(),
                payee_binding_digest: derive_channel_payee_binding_digest(
                    &fixture.open.intent().body.payee_id,
                    &fixture.open.intent().body.payee_beneficiary_address,
                )?,
                amount: actual_charge,
                credit_election: ObligationCreditElectionV1::NotCredit,
                pre_action_authority_digest: reservation_digest.clone(),
                created_at_unix_ms: 1_600,
                due_at_unix_ms: 2_000,
            })
            .map_err(|_| ChannelError::AuthorityVerification)
        })
        .transpose()?;
    let receipt = verify_channel_receipt_binding(
        &receipt,
        &kernel_key.public_key(),
        &reservation,
        &fixture.open,
        obligation.as_ref(),
    )?;
    let next_body = build_channel_state_transition(&prior, &reservation, &receipt, &fixture.open)?;
    let signed_next = SignedChannelStateV1 {
        payee_signature: ChannelSignatureV1::sign(
            &next_body,
            fixture.trust.payee_id.clone(),
            fixture.trust.payee_key_epoch,
            &fixture.payee_key,
        )?,
        body: next_body,
    };
    let next = verify_channel_state_transition(
        &signed_next,
        &prior,
        &reservation,
        &receipt,
        &fixture.open,
        &fixture.trust,
    )?;
    let terminal_lifecycle = ChannelLifecycleViewV1 {
        latest_state_digest: next.digest()?,
        latest_sequence: next.body().seq,
        state_version: 3,
        lifecycle_fence: 4,
        live_reservation_id: None,
        operation_id: None,
        ..reserved.clone()
    };
    let terminal_escrow = ChannelEscrowReservationViewV1 {
        version: 4,
        lifecycle_fence: 4,
        ..reserved_escrow
    };
    let result = EconomicContentV1::Inline {
        value: serde_json::json!({"outcomeId": digest("terminal-outcome")}),
    };
    let result_digest = result
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let terminal_result = EconomicTerminalResultV1 {
        result_id: "terminal-outcome".to_owned(),
        result_digest: result_digest.clone(),
        result: result.clone(),
    };
    let signed_terminal_outcome = SignedChannelTerminalOutcomeCommitmentV1::sign_for_test(
        &reservation,
        &signed_receipt,
        terminal_result.clone(),
        1_599,
        1_600,
        &kernel_key,
    )?;
    let mut completed_effect = dispatch_effect.clone();
    completed_effect.state = EconomicEffectStateV1::Completed;
    completed_effect.terminal = Some(EconomicEffectTerminalV1::Completed {
        result_id: terminal_result.result_id,
        result_digest: terminal_result.result_digest,
        result: terminal_result.result,
    });
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: fixture.trust.settlement_authority_scope_id.clone(),
        resource_id: terminal_lifecycle.channel_id.clone(),
    };
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: fixture.trust.settlement_authority_scope_id.clone(),
        resource_id: terminal_lifecycle.channel_id.clone(),
    };
    let current_channel_head = dispatched_view
        .view()
        .head(&channel_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let current_escrow_head = dispatched_view
        .view()
        .head(&escrow_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let current_effect_head = dispatched_view
        .view()
        .head(&dispatch_effect.resource_head_key())
        .ok_or(ChannelError::AuthorityVerification)?;
    let next_channel_head = state_head_successor(
        current_channel_head,
        &terminal_lifecycle,
        terminal_lifecycle.state_version,
        terminal_lifecycle.lifecycle_fence,
        "open",
        1_600,
    )?;
    let next_escrow_head = state_head_successor(
        current_escrow_head,
        &terminal_escrow,
        terminal_escrow.version,
        terminal_escrow.lifecycle_fence,
        "open",
        1_600,
    )?;
    let next_effect_head = effect_head(
        &completed_effect,
        current_effect_head
            .head_version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        Some(
            current_effect_head
                .digest()
                .map_err(|_| ChannelError::AuthorityVerification)?,
        ),
        1_600,
    )?;
    let mut transitions = vec![
        EconomicStateTransitionV1 {
            resource_key: channel_key,
            expected_head_digest: next_channel_head.predecessor_digest.clone(),
            next_head: next_channel_head,
            transition_proof_digest: digest("terminal-channel-proof"),
            prepared_effect: None,
        },
        EconomicStateTransitionV1 {
            resource_key: escrow_key,
            expected_head_digest: next_escrow_head.predecessor_digest.clone(),
            next_head: next_escrow_head,
            transition_proof_digest: digest("terminal-escrow-proof"),
            prepared_effect: None,
        },
        EconomicStateTransitionV1 {
            resource_key: dispatch_effect.resource_head_key(),
            expected_head_digest: next_effect_head.predecessor_digest.clone(),
            next_head: next_effect_head,
            transition_proof_digest: digest("terminal-effect-proof"),
            prepared_effect: None,
        },
    ];
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let advance = verified_terminal_batch(
        &dispatched_view,
        &reservation.artifact().body.operation_id,
        transitions,
        1_600,
    )?;
    Ok(TerminalAdvanceFixture {
        open: fixture.open,
        open_trust: fixture.trust,
        funding: fixture.funding,
        funding_authority: fixture.funding_authority,
        funding_acknowledgement: fixture.funding_acknowledgement,
        dispute_policy: fixture.dispute_policy,
        reservation_authority: authority,
        prepared,
        reservation,
        ready_view: reservation_view,
        prior,
        next,
        signed_next,
        receipt,
        signed_receipt,
        trusted_kernel_key: kernel_key.public_key(),
        signed_terminal_outcome,
        advance,
        terminal_lifecycle,
        terminal_escrow,
        dispatch_effect,
        completed_effect,
        obligation,
    })
}

struct PreparedReservationFixture {
    open: VerifiedAdmittedChannelOpenV1,
    open_trust: ChannelOpenTrustV1,
    funding: SignedChannelFundingEvidenceV1,
    funding_authority: ChannelFundingAuthorityV1,
    funding_acknowledgement: SignedChannelFundingAcknowledgementV1,
    dispute_policy: ChannelDisputePolicyV1,
    reservation_authority: ChannelReservationAuthorityV1,
    trusted_kernel_key: chio_core::crypto::PublicKey,
    prior: VerifiedChannelStateV1,
    current: VerifiedEconomicStateView,
    ready_view: VerifiedEconomicStateView,
    proposal: VerifiedChannelReservationProposalV1,
    request: EconomicRequestBindingV1,
    handoff: EconomicAdmissionHandoffV1,
    provider: EconomicEffectTargetV1,
    action_digest: String,
}

fn prepared_reservation_fixture() -> Result<PreparedReservationFixture, ChannelError> {
    let terminal = terminal_advance_fixture()?;
    let body = &terminal.reservation.artifact().body;
    let reserved = terminal.reservation.snapshot().lifecycle();
    let reserved_escrow = terminal.reservation.snapshot().escrow();
    let available = ChannelLifecycleViewV1 {
        state_version: body.channel_state_expected_version,
        lifecycle_fence: body.lifecycle_fence,
        live_reservation_id: None,
        operation_id: None,
        ..reserved.clone()
    };
    let available_escrow = ChannelEscrowReservationViewV1 {
        version: reserved_escrow
            .version
            .checked_sub(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        lifecycle_fence: body.lifecycle_fence,
        ..reserved_escrow.clone()
    };
    let current = anchored_channel_view(
        &terminal.open.intent().body.settlement_authority_scope_id,
        &available,
        &available_escrow,
        terminal.reservation.accepted_at_unix_ms(),
    )?;
    let mut current = current.view().clone();
    current.absent_resource_keys = vec![terminal.reservation.ready_effect().resource_head_key()];
    current.absent_request_keys = vec![terminal.reservation.ready_effect().request.key()];
    current
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let current = verify_economic_state_view(current, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let open = verify_admitted_channel_open(&terminal.open, &current)?;
    Ok(PreparedReservationFixture {
        open,
        open_trust: terminal.open_trust,
        funding: terminal.funding,
        funding_authority: terminal.funding_authority,
        funding_acknowledgement: terminal.funding_acknowledgement,
        dispute_policy: terminal.dispute_policy,
        reservation_authority: terminal.reservation_authority,
        trusted_kernel_key: terminal.trusted_kernel_key,
        prior: terminal.prior,
        current,
        ready_view: terminal.ready_view,
        proposal: terminal.reservation.proposal().clone(),
        request: terminal.reservation.ready_effect().request.clone(),
        handoff: terminal
            .reservation
            .ready_effect()
            .admission_handoff
            .clone(),
        provider: terminal.reservation.ready_effect().target.clone(),
        action_digest: terminal.reservation.ready_effect().action_digest.clone(),
    })
}

fn channel_service_binding(fixture: &PreparedReservationFixture) -> ChannelServiceBindingV1 {
    ChannelServiceBindingV1 {
        request: fixture.request.clone(),
        admission_handoff: fixture.handoff.clone(),
        provider: fixture.provider.clone(),
        action_digest: fixture.action_digest.clone(),
    }
}

fn verified_prepared_reservation(
    fixture: &PreparedReservationFixture,
) -> Result<VerifiedChannelPreparedReservationV1, ChannelError> {
    let body = fixture.proposal.artifact().body.clone();
    let service = channel_service_binding(fixture);
    let prepared = prepare_channel_reservation(
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        body.clone(),
        service.clone(),
    )?;
    verify_channel_prepared_reservation(
        &prepared,
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        &body,
        &service,
    )
}

enum ReadyServiceMutation {
    RequestNamespace,
    RequestId,
    RequestBinding,
    HandoffState,
    HandoffVersion,
    HandoffFence,
    HandoffStoreUuid,
    HandoffLeaseId,
    HandoffOwnerEpoch,
    TargetId,
    TargetEpoch,
    TargetQualification,
    Action,
    Parameters,
    ResourceHead,
}

fn forged_ready_service_view(
    current: &VerifiedEconomicStateView,
    effect_key: &EconomicResourceKeyV1,
    mutation: ReadyServiceMutation,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    let mut view = current.view().clone();
    let head = view
        .heads
        .iter_mut()
        .find(|head| &head.resource_key == effect_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(ChannelError::AuthorityVerification);
    };
    let mut effect: EconomicEffectSlotV1 =
        serde_json::from_value(value.clone()).map_err(|_| ChannelError::AuthorityVerification)?;
    match mutation {
        ReadyServiceMutation::RequestNamespace => {
            effect.request.request_namespace_digest = digest("forged-request-namespace");
        }
        ReadyServiceMutation::RequestId => effect.request.request_id = "forged-request".to_owned(),
        ReadyServiceMutation::RequestBinding => {
            effect.request.request_binding_digest = digest("forged-request-binding");
        }
        ReadyServiceMutation::HandoffState => {
            effect.admission_handoff.state = EconomicAdmissionHandoffStateV1::MutationSubmitted;
        }
        ReadyServiceMutation::HandoffVersion => {
            effect.admission_handoff.operation_version += 1;
        }
        ReadyServiceMutation::HandoffFence => {
            effect.admission_handoff.lifecycle_fence += 1;
        }
        ReadyServiceMutation::HandoffStoreUuid => {
            effect.admission_handoff.store_fence.store_uuid = "forged-store".to_owned();
        }
        ReadyServiceMutation::HandoffLeaseId => {
            effect.admission_handoff.store_fence.lease_id = "forged-lease".to_owned();
        }
        ReadyServiceMutation::HandoffOwnerEpoch => {
            effect.admission_handoff.store_fence.owner_epoch += 1;
        }
        ReadyServiceMutation::TargetId => effect.target.target_id = "forged-target".to_owned(),
        ReadyServiceMutation::TargetEpoch => effect.target.target_key_epoch += 1,
        ReadyServiceMutation::TargetQualification => {
            effect.target.qualification_digest = digest("forged-target-qualification");
        }
        ReadyServiceMutation::Action => effect.action_digest = digest("forged-action"),
        ReadyServiceMutation::Parameters => {
            effect.parameters_digest = digest("forged-reservation-parameters");
        }
        ReadyServiceMutation::ResourceHead => {
            effect.resource_head_digest = digest("forged-channel-head");
        }
    }
    let content = EconomicContentV1::Inline {
        value: serde_json::to_value(effect)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    head.state_digest = content
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    head.state = content;
    verified_modified_view(view)
}

fn signed_channel_projection_batch(
    current: &VerifiedEconomicStateView,
    projection: &ChannelLifecycleProjectionV1,
    issued_at: u64,
) -> Result<EconomicStateBatchV1, ChannelError> {
    let mut batch = EconomicStateBatchV1 {
        schema: CHIO_ECONOMIC_STATE_BATCH_SCHEMA.to_owned(),
        batch_id: String::new(),
        checkpoint_digest: String::new(),
        anchor_id: current.view().anchor_id.clone(),
        namespace: current.view().namespace.clone(),
        checkpoint_sequence: current
            .view()
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
        previous_checkpoint_digest: Some(current.view().checkpoint_digest.clone()),
        expected_heads_root: String::new(),
        next_heads_root: String::new(),
        transitions: projection.transitions().to_vec(),
        effect_slots: projection.effect_slots().to_vec(),
        request_replays: projection.request_replays().to_vec(),
        operation_id: projection.operation_id().map(str::to_owned),
        issued_at,
        signer_key_id: current.view().signer_key_id.clone(),
        signer_key_epoch: current.view().signer_key_epoch,
        anchor_signature: String::new(),
    };
    batch
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(batch)
}

fn committed_channel_projection_view(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
) -> Result<VerifiedEconomicStateView, ChannelError> {
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
    committed
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_view(committed, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)
}

fn verify_terminal_fixture(
    fixture: &TerminalAdvanceFixture,
) -> Result<VerifiedChannelTerminalAdvanceV1, ChannelError> {
    let outcome = verified_terminal_outcome(fixture)?;
    verify_channel_terminal_advance(
        &fixture.open,
        &fixture.reservation,
        &fixture.prior,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &fixture.advance,
    )
}

fn verified_terminal_outcome(
    fixture: &TerminalAdvanceFixture,
) -> Result<VerifiedChannelTerminalOutcomeCommitmentV1, ChannelError> {
    verify_channel_terminal_outcome_commitment(
        &fixture.signed_terminal_outcome,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
}

fn reseal_terminal_batch(
    fixture: &TerminalAdvanceFixture,
    mut batch: EconomicStateBatchV1,
) -> Result<VerifiedEconomicStateBatchAdvance, ChannelError> {
    batch
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_batch_advance(
        fixture.advance.current(),
        batch,
        &channel_anchor_pins(),
        &DirectTransitionVerifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)
}

fn verify_terminal_batch(
    fixture: &TerminalAdvanceFixture,
    advance: &VerifiedEconomicStateBatchAdvance,
) -> Result<VerifiedChannelTerminalAdvanceV1, ChannelError> {
    let outcome = verified_terminal_outcome(fixture)?;
    verify_channel_terminal_advance(
        &fixture.open,
        &fixture.reservation,
        &fixture.prior,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        advance,
    )
}

fn transition_index(
    batch: &EconomicStateBatchV1,
    resource_family: &str,
) -> Result<usize, ChannelError> {
    batch
        .transitions
        .iter()
        .position(|transition| transition.resource_key.resource_family == resource_family)
        .ok_or(ChannelError::AuthorityVerification)
}

fn replace_transition_state<T: serde::Serialize>(
    transition: &mut EconomicStateTransitionV1,
    state: &T,
) -> Result<(), ChannelError> {
    let content = EconomicContentV1::Inline {
        value: serde_json::to_value(state)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    transition.next_head.state_digest = content
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    transition.next_head.state = content;
    Ok(())
}

fn verify_substituted_batch(
    fixture: &TerminalAdvanceFixture,
    batch: EconomicStateBatchV1,
) -> Result<(), ChannelError> {
    let advance = reseal_terminal_batch(fixture, batch)?;
    assert!(verify_terminal_batch(fixture, &advance).is_err());
    Ok(())
}

fn verified_modified_view(
    mut view: EconomicStateAnchorViewV1,
) -> Result<VerifiedEconomicStateView, ChannelError> {
    view.seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_view(view, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)
}

fn terminal_advance_from_current(
    current: &VerifiedEconomicStateView,
    mut batch: EconomicStateBatchV1,
) -> Result<VerifiedEconomicStateBatchAdvance, ChannelError> {
    batch.checkpoint_sequence = current
        .view()
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    batch.previous_checkpoint_digest = Some(current.view().checkpoint_digest.clone());
    for transition in &mut batch.transitions {
        let current_head = current
            .view()
            .head(&transition.resource_key)
            .ok_or(ChannelError::AuthorityVerification)?;
        let current_digest = current_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?;
        transition.expected_head_digest = Some(current_digest.clone());
        transition.next_head.predecessor_digest = Some(current_digest);
    }
    batch
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    verify_economic_state_batch_advance(
        current,
        batch,
        &channel_anchor_pins(),
        &DirectTransitionVerifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)
}

fn current_effect_head_mut(
    view: &mut EconomicStateAnchorViewV1,
) -> Result<&mut EconomicResourceHeadV1, ChannelError> {
    view.heads
        .iter_mut()
        .find(|head| head.resource_key.resource_family == "effect_slot")
        .ok_or(ChannelError::AuthorityVerification)
}

fn verified_zero_effective_close() -> Result<VerifiedEffectiveChannelCloseV1, ChannelError> {
    let fixture = verified_channel_fixture()?;
    let open = fixture.open;
    let final_state = open.initial_state();
    let lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: final_state.digest()?,
        latest_sequence: final_state.body().seq,
        state_version: 1,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: lifecycle.channel_id.clone(),
        open_digest: open.artifact().digest()?,
        escrow_reference: open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 2,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
    };
    let current = anchored_channel_view(
        &fixture.trust.settlement_authority_scope_id,
        &lifecycle,
        &escrow,
        1_500,
    )?;
    let current = verify_channel_lifecycle_snapshot(
        &current,
        &fixture.trust.settlement_authority_scope_id,
        &lifecycle.channel_id,
    )?;
    let body = build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        final_state,
        &current,
        1_500,
    )?;
    let close = SignedChannelCloseV1 {
        payee_signature: ChannelSignatureV1::sign(
            &body,
            fixture.trust.payee_id.clone(),
            fixture.trust.payee_key_epoch,
            &fixture.payee_key,
        )?,
        payer_signature: None,
        body,
    };
    let close_body_digest = close.body.digest()?;
    let pending_lifecycle = ChannelLifecycleViewV1 {
        status: ChannelLifecycleStatusV1::ClosePending,
        state_version: close.body.channel_state_version,
        lifecycle_fence: close.body.lifecycle_fence,
        pending_close_body_digest: Some(close_body_digest.clone()),
        ..lifecycle
    };
    let pending_escrow = ChannelEscrowReservationViewV1 {
        version: close.body.escrow_reservation_version,
        lifecycle_fence: close.body.lifecycle_fence,
        pending_close_body_digest: Some(close_body_digest),
        ..escrow
    };
    let pending = anchored_channel_view(
        &fixture.trust.settlement_authority_scope_id,
        &pending_lifecycle,
        &pending_escrow,
        1_500,
    )?;
    let pending = verify_channel_lifecycle_snapshot(
        &pending,
        &fixture.trust.settlement_authority_scope_id,
        &pending_lifecycle.channel_id,
    )?;
    let close = verify_channel_close(&close, &open, final_state, &pending, &fixture.trust)?;
    verify_effective_channel_close(&close)
}

fn verified_effective_close_with_charge(
    actual_charge_units: u64,
) -> Result<VerifiedEffectiveChannelCloseV1, ChannelError> {
    let fixture = terminal_advance_fixture_with_charge(actual_charge_units)?;
    let mut close_trust = fixture.open_trust.clone();
    close_trust.trusted_time_unix_ms = 1_700;
    let open = fixture.open;
    let final_state = fixture.next;
    let lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: final_state.digest()?,
        latest_sequence: final_state.body().seq,
        state_version: 4,
        lifecycle_fence: 5,
        pending_close_body_digest: None,
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: lifecycle.channel_id.clone(),
        open_digest: open.artifact().digest()?,
        escrow_reference: open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 5,
        lifecycle_fence: 5,
        pending_close_body_digest: None,
    };
    let current = anchored_channel_view(
        &close_trust.settlement_authority_scope_id,
        &lifecycle,
        &escrow,
        1_700,
    )?;
    let current = verify_channel_lifecycle_snapshot(
        &current,
        &close_trust.settlement_authority_scope_id,
        &lifecycle.channel_id,
    )?;
    let body = build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        &final_state,
        &current,
        1_700,
    )?;
    let close = SignedChannelCloseV1 {
        payee_signature: ChannelSignatureV1::sign(
            &body,
            fixture.open_trust.payee_id.clone(),
            fixture.open_trust.payee_key_epoch,
            &Keypair::from_seed(&[32; 32]),
        )?,
        payer_signature: None,
        body,
    };
    let close_body_digest = close.body.digest()?;
    let pending_lifecycle = ChannelLifecycleViewV1 {
        status: ChannelLifecycleStatusV1::ClosePending,
        state_version: close.body.channel_state_version,
        lifecycle_fence: close.body.lifecycle_fence,
        pending_close_body_digest: Some(close_body_digest.clone()),
        ..lifecycle
    };
    let pending_escrow = ChannelEscrowReservationViewV1 {
        version: close.body.escrow_reservation_version,
        lifecycle_fence: close.body.lifecycle_fence,
        pending_close_body_digest: Some(close_body_digest),
        ..escrow
    };
    let pending = anchored_channel_view(
        &close_trust.settlement_authority_scope_id,
        &pending_lifecycle,
        &pending_escrow,
        1_700,
    )?;
    let pending = verify_channel_lifecycle_snapshot(
        &pending,
        &close_trust.settlement_authority_scope_id,
        &pending_lifecycle.channel_id,
    )?;
    let close = verify_channel_close(&close, &open, &final_state, &pending, &close_trust)?;
    verify_effective_channel_close(&close)
}

fn release_frost_facts(
    close: &VerifiedEffectiveChannelCloseV1,
    publisher_fence: u64,
    issued_at_unix_ms: u64,
) -> Result<ChannelReleaseFrostFacts, ChannelError> {
    let action = channel_close_frost_action(close, publisher_fence)?;
    Ok(ChannelReleaseFrostFacts {
        authorization_slot_id: digest("channel-release-frost-slot"),
        authorization_id: digest("channel-release-frost-authorization"),
        action_digest: action
            .action_digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        signed_envelope_digest: digest("channel-release-frost-envelope"),
        scope_id: close.snapshot().settlement_authority_scope_id().to_owned(),
        resource_id: close.close().artifact().body.channel_id.clone(),
        resource_version: close.snapshot().lifecycle().state_version,
        resource_fence: close.snapshot().lifecycle().lifecycle_fence,
        roster_digest: digest("channel-release-frost-roster"),
        key_epoch: 7,
        issued_at_unix_ms,
        current: true,
    })
}

fn release_preparation_facts(
    authorization: &VerifiedChannelReleaseAuthorizationV1,
) -> ChannelReleasePreparationFacts {
    let intent = &authorization.close().close().open().intent().body;
    ChannelReleasePreparationFacts {
        dispatch_digest: intent.original_web3_dispatch_digest.clone(),
        chain_id: intent.asset_binding.chain_id.clone(),
        escrow_contract: intent.escrow_reference.escrow_contract.clone(),
        escrow_id: intent.escrow_reference.escrow_id.clone(),
        token_address: intent.asset_binding.token_address.clone(),
        token_symbol: intent.asset_binding.token_symbol.clone(),
        beneficiary_address: intent.payee_beneficiary_address.clone(),
        operator: intent.original_operator.clone(),
        operator_key_hash: intent.original_operator_key_hash.clone(),
        protocol_minor_unit_decimals: intent.asset_binding.protocol_minor_unit_decimals,
        token_decimals: intent.asset_binding.token_decimals,
        escrow_bound: intent.bound.clone(),
        release_amount: authorization
            .close()
            .effective_state()
            .body()
            .cumulative_owed
            .clone(),
        release_token_base_units: authorization
            .binding()
            .expected_release_token_base_units()
            .to_owned(),
    }
}

#[path = "artifacts.rs"]
mod artifacts;
#[path = "close_and_rail.rs"]
mod close_and_rail;
#[path = "reservation.rs"]
mod reservation;
#[path = "state_and_dispute.rs"]
mod state_and_dispute;
#[path = "terminal_projection.rs"]
mod terminal_projection;
#[path = "terminal_rejection.rs"]
mod terminal_rejection;
