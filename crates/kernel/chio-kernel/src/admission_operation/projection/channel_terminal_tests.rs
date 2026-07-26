use std::collections::BTreeSet;
use std::error::Error;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_core::economic_continuity::{
    verify_economic_state_batch_advance, verify_economic_state_batch_commit,
    verify_economic_state_view, EconomicAdmissionHandoffV1, EconomicContentV1,
    EconomicEffectSlotV1, EconomicEffectStateV1, EconomicEffectTargetV1, EconomicEffectTerminalV1,
    EconomicRequestBindingV1, EconomicRequestReplayV1, EconomicResourceHeadV1,
    EconomicResourceKeyV1, EconomicStateAnchorError, EconomicStateAnchorPins,
    EconomicStateAnchorViewV1, EconomicStateBatchV1, EconomicStateTransitionV1,
    EconomicTerminalResultV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateBatchAdvance, VerifiedEconomicStateView, CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA,
    CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA,
    CHIO_ECONOMIC_STATE_BATCH_SCHEMA,
};
use chio_core::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core::receipt::decision::ToolCallAction;
use chio_core::receipt::economics::{
    ChannelReceiptMetadataV1, ChannelSettlementModeV1, FinancialReceiptMetadata, SettlementStatus,
    CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA,
};
use chio_core::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_core::web3::trust_profile::Web3FinalityMode;
use chio_core::{crypto::Keypair, receipt::decision::Decision};
use chio_credit::obligation::{
    ObligationAtomInputV1, ObligationAtomV1, ObligationCreditElectionV1, ObligationDispositionV1,
};
use chio_settle::channel::*;

use crate::tool_outcome::sign_channel_terminal_outcome_commitment;
use crate::tool_outcome::test_support::{
    prepared_evaluation, record_external_step, record_pure_step, resolve, returned_value,
};

use super::*;

#[path = "channel_terminal_tests/authority.rs"]
mod authority;

type TestResult<T> = Result<T, Box<dyn Error>>;

const I_JSON_MAX_SAFE_INTEGER: u64 = (1_u64 << 53) - 1;

fn id(field: &'static str, value: impl Into<String>) -> TestResult<AdmissionIdentifier> {
    Ok(AdmissionIdentifier::try_new(field, value.into())?)
}

fn admission_hash(field: &'static str, value: impl AsRef<[u8]>) -> TestResult<AdmissionDigest> {
    Ok(AdmissionDigest::try_new(
        field,
        chio_core::crypto::sha256_hex(value.as_ref()),
    )?)
}

fn channel_digest(label: impl AsRef<[u8]>) -> String {
    chio_core::crypto::sha256_hex(label.as_ref())
}

fn evm_hash(label: &str) -> String {
    format!("0x{}", channel_digest(label))
}

fn store_fence(owner_epoch: u64) -> StoreMutationFence {
    StoreMutationFence {
        store_uuid: "channel-store".to_owned(),
        lease_id: format!("channel-owner-{owner_epoch}"),
        owner_epoch,
    }
}

fn recovery_lease(
    operation: &AdmissionOperationV1,
    version: u64,
) -> TestResult<AdmissionRecoveryLease> {
    let fence = store_fence(3);
    let claim = UntrustedAdmissionRecoveryClaim::new(
        operation.binding().operation_id().clone(),
        id("claimant_id", "channel-worker")?,
        id("coordinator_lease_id", "channel-coordinator")?,
        operation.coordinator_lease_epoch(),
        version,
        3_000,
        fence.clone(),
    )?;
    Ok(qualify_recovery_claim_for_test(
        operation, claim, 1_000, &fence,
    )?)
}

fn transition(
    operation: AdmissionOperationV1,
    next: AdmissionOperationState,
    attachments: Vec<AdmissionAttachment>,
) -> TestResult<AdmissionOperationV1> {
    let command = AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        recovery_lease(&operation, operation.version())?,
        attachments,
        Some(next),
        None,
        None,
    )?;
    Ok(operation.apply_command(&command, 1_500)?.into_operation())
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
    additional_heads: Vec<EconomicResourceHeadV1>,
    checkpoint_label: &str,
) -> TestResult<VerifiedEconomicStateView> {
    let operation_id = lifecycle.operation_id.clone();
    let effect_idempotency_key = operation_id.as_ref().map(channel_digest);
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
            lifecycle_state: match lifecycle.status {
                ChannelLifecycleStatusV1::Open => "open",
                ChannelLifecycleStatusV1::ClosePending => "close_pending",
                ChannelLifecycleStatusV1::Closing => "closing",
                ChannelLifecycleStatusV1::Released => "released",
                ChannelLifecycleStatusV1::Refunded => "refunded",
                ChannelLifecycleStatusV1::Incident => "incident",
            }
            .to_owned(),
            state_digest: channel_state.digest()?,
            state: channel_state,
            operation_id: operation_id.clone(),
            effect_idempotency_key: effect_idempotency_key.clone(),
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: observed_at_unix_ms,
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
            lifecycle_state: match escrow.status {
                ChannelEscrowReservationStatusV1::Open => "open",
                ChannelEscrowReservationStatusV1::Closing => "closing",
                ChannelEscrowReservationStatusV1::Released => "released",
                ChannelEscrowReservationStatusV1::Refunded => "refunded",
                ChannelEscrowReservationStatusV1::Incident => "incident",
            }
            .to_owned(),
            state_digest: escrow_state.digest()?,
            state: escrow_state,
            operation_id,
            effect_idempotency_key,
            frost: None,
            terminal_result: None,
            trusted_clock_high_water: observed_at_unix_ms,
            predecessor_digest: None,
        },
    ];
    heads.extend(additional_heads);
    heads.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let mut view = EconomicStateAnchorViewV1 {
        schema: CHIO_ECONOMIC_STATE_ANCHOR_VIEW_SCHEMA.to_owned(),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        checkpoint_sequence: 1,
        checkpoint_digest: channel_digest(checkpoint_label),
        heads_root: String::new(),
        heads,
        absent_resource_keys: Vec::new(),
        request_replays_root: String::new(),
        request_replays: Vec::new(),
        absent_request_keys: Vec::new(),
        observed_at: observed_at_unix_ms,
        signer_key_id: "channel-anchor-key".to_owned(),
        signer_key_epoch: 1,
        anchor_signature: String::new(),
    };
    view.seal(&Keypair::from_seed(&[61; 32]))?;
    Ok(verify_economic_state_view(view, &anchor_pins())?)
}

fn effect_head(
    effect: &EconomicEffectSlotV1,
    head_version: u64,
    predecessor_digest: Option<String>,
    observed_at_unix_ms: u64,
) -> TestResult<EconomicResourceHeadV1> {
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
        _ => return Err(AdmissionOperationError::TerminalProjectionBindingMismatch.into()),
    };
    let state = EconomicContentV1::Inline {
        value: serde_json::to_value(effect)?,
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
        state_digest: state.digest()?,
        state,
        operation_id: Some(effect.operation_id.clone()),
        effect_idempotency_key: Some(effect.idempotency_key.clone()),
        frost: None,
        terminal_result,
        trusted_clock_high_water: observed_at_unix_ms,
        predecessor_digest,
    })
}

fn state_head_successor<T: serde::Serialize>(
    current: &EconomicResourceHeadV1,
    state: &T,
    resource_version: u64,
    lifecycle_fence: u64,
    observed_at_unix_ms: u64,
) -> TestResult<EconomicResourceHeadV1> {
    let content = EconomicContentV1::Inline {
        value: serde_json::to_value(state)?,
    };
    Ok(EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: current
            .head_version
            .checked_add(1)
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
        resource_version,
        lifecycle_fence,
        lifecycle_state: "open".to_owned(),
        state_digest: content.digest()?,
        state: content,
        operation_id: None,
        effect_idempotency_key: None,
        frost: None,
        terminal_result: None,
        trusted_clock_high_water: observed_at_unix_ms,
        predecessor_digest: Some(current.digest()?),
    })
}

fn verified_terminal_batch(
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
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        checkpoint_sequence: current
            .view()
            .checkpoint_sequence
            .checked_add(1)
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
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
    batch.seal(&Keypair::from_seed(&[61; 32]))?;
    Ok(verify_economic_state_batch_advance(
        current,
        batch,
        &anchor_pins(),
        &DirectTransitionVerifier,
    )?)
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
        settlement_policy_digest: channel_digest("settlement-policy"),
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
        asset_binding: asset_binding(),
        block_pin: ChannelBlockPinV1 {
            block_number: 100,
            block_hash,
            block_timestamp_unix_secs: 1,
            observed_at_unix_ms: 1_100,
            required_confirmations: 12,
            observed_confirmations: 12,
            finalized_head_number: 112,
            finalized_head_hash: evm_hash("finalized-head"),
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
        trusted_time_unix_ms: 1_500,
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
    open: VerifiedChannelOpenConsentV1,
}

fn verified_channel_fixture(suffix: &str) -> TestResult<VerifiedChannelFixture> {
    let payer_key = Keypair::from_seed(&[31; 32]);
    let payee_key = Keypair::from_seed(&[32; 32]);
    let funding_key = Keypair::from_seed(&[35; 32]);
    let policy = ChannelDisputePolicyV1 {
        schema: CHANNEL_DISPUTE_POLICY_SCHEMA.to_owned(),
        policy_id: format!("channel-policy-{suffix}"),
        fixed_finality_broadcast_margin_secs: 50,
        tiers: vec![
            ChannelDisputeTierV1 {
                upper_bound_units: 1_000,
                dispute_window_secs: 100,
                required_confirmations: 12,
                finality_mode: Web3FinalityMode::L1Finalized,
            },
            ChannelDisputeTierV1 {
                upper_bound_units: I_JSON_MAX_SAFE_INTEGER,
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
    let authority = funding_authority(&funding_key, &funding.body);
    let trust = ChannelOpenTrustV1 {
        payer_id: "channel-payer".to_owned(),
        payer_key: payer_key.public_key(),
        payer_key_epoch: 2,
        payee_id: "channel-payee".to_owned(),
        payee_key: payee_key.public_key(),
        payee_key_epoch: 3,
        settlement_authority_scope_id: "channel-settlement".to_owned(),
        original_web3_dispatch_digest: channel_digest(format!("web3-dispatch-{suffix}")),
        participant_snapshot_digest: channel_digest(format!("participants-{suffix}")),
        trusted_time_unix_ms: 1_500,
    };
    let intent_body = ChannelOpenIntentBodyV1 {
        schema: CHANNEL_OPEN_INTENT_SCHEMA.to_owned(),
        open_intent_id: channel_digest(format!("open-intent-{suffix}")),
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
        verify_channel_open_intent(&intent, &funding, &authority, &policy, &trust)?;
    let acknowledgement_body = ChannelFundingAcknowledgementBodyV1 {
        schema: CHANNEL_FUNDING_ACKNOWLEDGEMENT_SCHEMA.to_owned(),
        open_intent_digest: intent.digest()?,
        escrow_reference: intent.body.escrow_reference.clone(),
        prior_state: ChannelEscrowReservationStateV1::Unreserved,
        prior_version: 1,
        prior_head_digest: channel_digest(format!("unreserved-head-{suffix}")),
        new_state: ChannelEscrowReservationStateV1::Opening,
        new_version: 2,
        anchored_head_digest: channel_digest(format!("opening-head-{suffix}")),
        reserved_at_unix_ms: 1_400,
        expires_at_unix_ms: 1_700,
    };
    let acknowledgement = SignedChannelFundingAcknowledgementV1 {
        authority_signature: ChannelSignatureV1::sign(
            &acknowledgement_body,
            authority.authority_id.clone(),
            authority.authority_key_epoch,
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
        &authority,
        &trust,
    )?;
    Ok(VerifiedChannelFixture {
        payer_key,
        payee_key,
        trust,
        open,
    })
}

struct ChannelAdvanceFixture {
    operation: AdmissionOperationV1,
    context: AdmissionProjectionContext,
    receipt: VerifiedAdmissionReceipt,
    tool_outcome: ToolOutcomeTerminalEvidenceV1,
    open: VerifiedChannelOpenConsentV1,
    reservation: VerifiedAdmittedChannelReservationV1,
    atom: Option<ObligationAtomV1>,
    anchored_advance: VerifiedEconomicStateBatchAdvance,
    advance: VerifiedChannelTerminalAdvanceV1,
}

struct ChannelProjectionFixture {
    base: ChannelAdvanceFixture,
    obligation: Option<ObligationProjection>,
    channel: VerifiedChannelTerminalProjectionV1,
}

fn build_advance_fixture(
    actual_charge_units: u64,
    suffix: &str,
    receipt_variant: &str,
    return_value: serde_json::Value,
    effect_result_override: Option<serde_json::Value>,
) -> TestResult<ChannelAdvanceFixture> {
    let action = ToolCallAction::from_parameters(serde_json::json!({ "value": 1 }))?;
    let requirements = AdmissionParticipantRequirements {
        broker_attempt: true,
        budget_capture: true,
        obligation: true,
        channel: true,
        ..AdmissionParticipantRequirements::NONE
    };
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: AdmissionOperationKind::ToolDispatch,
        namespace: AuthenticatedRequestNamespace::from_authentication_context(
            id(
                "coordinator_authority_id",
                "https://channel-coordinator.example",
            )?,
            "channel-tenant",
        )?,
        request_id: id("request_id", format!("channel-request-{suffix}"))?,
        capability_id: id("capability_id", format!("channel-capability-{suffix}"))?,
        authorization_capability_hash: admission_hash(
            "authorization_capability_hash",
            format!("channel-authorization-{suffix}"),
        )?,
        request_binding: AdmissionRequestBindingV1::new_with_action_parameter_hash(
            admission_hash(
                "immutable_request_hash",
                format!("channel-request-body-{suffix}"),
            )?,
            AdmissionDigest::try_new("action_parameter_hash", action.parameter_hash.clone())?,
            requirements,
        )?,
        policy_hash: admission_hash("policy_hash", format!("channel-policy-{suffix}"))?,
        effect_class: SideEffectClass::Monetary,
    })?;
    let mut operation = AdmissionOperationV1::prepare(binding, 7)?;
    let channel_fixture = verified_channel_fixture(suffix)?;
    let prior = channel_fixture.open.initial_state().clone();
    let open_digest = channel_fixture.open.artifact().digest()?;
    let prior_digest = prior.digest()?;
    let kernel = Keypair::from_seed(&[36; 32]);
    let reservation_authority_key = Keypair::from_seed(&[33; 32]);
    let reservation_authority = ChannelReservationAuthorityV1 {
        authority_id: "channel-authority".to_owned(),
        authority_key_epoch: 7,
        authority_key: reservation_authority_key.public_key(),
        trusted_time_unix_ms: 1_500,
    };
    let provider = ProviderAttemptBindingV1 {
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        attempt_id: format!("channel-attempt-{suffix}"),
        transport_id: format!("channel-transport-{suffix}"),
        transport_key_epoch: 9,
    };
    let service = ChannelServiceBindingV1 {
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
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: expected_dispatch_committed_version(
                AdmissionOperationKind::ToolDispatch,
                requirements,
                operation.version(),
            )?,
            lifecycle_fence: operation.coordinator_lease_epoch(),
            store_fence: store_fence(3),
        },
        provider: EconomicEffectTargetV1 {
            target_id: provider.transport_id.clone(),
            target_key_epoch: provider.transport_key_epoch,
            qualification_digest: channel_digest(format!("provider-qualification-{suffix}")),
        },
        action_digest: operation
            .binding()
            .action_parameter_hash()
            .as_str()
            .to_owned(),
    };
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: derive_channel_reservation_id(
            &channel_fixture.open.artifact().body.channel_id,
            &open_digest,
            operation.replay_key().request_id.as_str(),
            1,
            &prior_digest,
        )?,
        channel_id: channel_fixture.open.artifact().body.channel_id.clone(),
        open_digest: open_digest.clone(),
        request_id: operation.replay_key().request_id.as_str().to_owned(),
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        next_sequence: 1,
        prior_state_digest: prior_digest.clone(),
        service_binding_digest: service.digest()?,
        receipt_authority_digest: derive_channel_receipt_authority_digest(&kernel.public_key())?,
        maximum_charge: MonetaryAmount {
            units: 40,
            currency: "USD".to_owned(),
        },
        maximum_token_base_units: "400000".to_owned(),
        expires_at_unix_ms: 2_500,
        disposition_expected_version: 1,
        channel_state_expected_version: 1,
        lifecycle_fence: 2,
    };
    let signed_reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            channel_fixture.trust.payer_id.clone(),
            channel_fixture.trust.payer_key_epoch,
            &channel_fixture.payer_key,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &reservation_body,
            reservation_authority.authority_id.clone(),
            reservation_authority.authority_key_epoch,
            &reservation_authority_key,
        )?,
        body: reservation_body,
    };
    let available_lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: channel_fixture.open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: prior_digest,
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
        channel_id: available_lifecycle.channel_id.clone(),
        open_digest: open_digest.clone(),
        escrow_reference: channel_fixture.open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 2,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
    };
    let available_view = anchored_channel_view(
        &channel_fixture.trust.settlement_authority_scope_id,
        &available_lifecycle,
        &available_escrow,
        1_500,
        Vec::new(),
        &format!("available-checkpoint-{suffix}"),
    )?;
    let admitted_open = verify_admitted_channel_open(&channel_fixture.open, &available_view)?;
    let proposal = verify_channel_reservation_proposal(
        &signed_reservation,
        &admitted_open,
        &prior,
        &reservation_authority,
        &channel_fixture.trust,
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
    let proposal_digest = AdmissionDigest::try_new(
        "channel_reservation_proposal_digest",
        proposal.artifact().body.proposal_digest()?,
    )?;
    let reservation_digest =
        AdmissionDigest::try_new("channel_reservation_digest", proposal.artifact().digest()?)?;
    operation = transition(
        operation,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![
            AdmissionAttachment::BrokerAttempt(provider.clone()),
            AdmissionAttachment::ChannelReservationProposalDigest(proposal_digest),
        ],
    )?;
    operation = transition(
        operation,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(id(
            "budget_hold_id",
            format!("channel-hold-{suffix}"),
        )?)],
    )?;
    operation = transition(
        operation,
        AdmissionOperationState::ReadyToDispatch,
        vec![AdmissionAttachment::ChannelReservationDigest(
            reservation_digest.clone(),
        )],
    )?;
    operation = transition(
        operation,
        AdmissionOperationState::CapturePending,
        Vec::new(),
    )?;
    operation = transition(
        operation,
        AdmissionOperationState::DispatchCommitted,
        Vec::new(),
    )?;
    let (_, returned) = returned_value(&operation, store_fence(4), 1_500, return_value, None)?;
    let evaluation = prepared_evaluation(&operation, &returned, 1_500)
        .and_then(|evaluation| record_pure_step(&evaluation))
        .and_then(|evaluation| record_external_step(&evaluation, 1_500))?;
    let disposition = if actual_charge_units == 0 {
        SettlementDispositionV1::ContractualZeroCharge {
            currency: "USD".to_owned(),
        }
    } else {
        SettlementDispositionV1::Capture {
            amount: MonetaryAmount {
                units: actual_charge_units,
                currency: "USD".to_owned(),
            },
        }
    };
    let (evaluation, outcome) = resolve(&returned, &evaluation, disposition)?;
    operation = transition(
        operation,
        AdmissionOperationState::Finalizing,
        vec![AdmissionAttachment::ToolOutcomeId(
            outcome.outcome_id().clone(),
        )],
    )?;
    let context = AdmissionProjectionContext {
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id.clone(),
        expected_operation_version: operation.version(),
        trusted_time_unix_ms: 1_600,
        coordinator_lease_id: id("coordinator_lease_id", "channel-projection")?,
        coordinator_lease_epoch: operation.coordinator_lease_epoch(),
        store_fence: store_fence(5),
    };
    let tool_outcome =
        ToolOutcomeTerminalEvidenceV1::from_records(&operation, &context, &outcome, &evaluation)?;

    let reserved_lifecycle = ChannelLifecycleViewV1 {
        state_version: 2,
        lifecycle_fence: 3,
        live_reservation_id: Some(proposal.artifact().body.reservation_id.clone()),
        operation_id: Some(operation.binding().operation_id().as_str().to_owned()),
        ..available_lifecycle
    };
    let reserved_escrow = ChannelEscrowReservationViewV1 {
        version: 3,
        lifecycle_fence: 3,
        ..available_escrow
    };
    let reserved_channel_view = anchored_channel_view(
        &channel_fixture.trust.settlement_authority_scope_id,
        &reserved_lifecycle,
        &reserved_escrow,
        1_500,
        Vec::new(),
        &format!("reserved-checkpoint-{suffix}"),
    )?;
    let mut reserved_channel_view = reserved_channel_view.view().clone();
    for head in &mut reserved_channel_view.heads {
        let predecessor = available_view
            .view()
            .head(&head.resource_key)
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
        head.head_version = predecessor
            .head_version
            .checked_add(1)
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
        head.predecessor_digest = Some(predecessor.digest()?);
    }
    reserved_channel_view.checkpoint_sequence = available_view
        .view()
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    reserved_channel_view.seal(&Keypair::from_seed(&[61; 32]))?;
    let reserved_channel_view = verify_economic_state_view(reserved_channel_view, &anchor_pins())?;
    let channel_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_LIFECYCLE_RESOURCE_FAMILY.to_owned(),
        scope_id: channel_fixture.trust.settlement_authority_scope_id.clone(),
        resource_id: reserved_lifecycle.channel_id.clone(),
    };
    let reserved_channel_head = reserved_channel_view
        .view()
        .head(&channel_key)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let commit = operation
        .dispatch_commit()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let mut ready_effect = EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: channel_digest("channel-effect-placeholder"),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        resource_key: channel_key.clone(),
        operation_id: operation.binding().operation_id().as_str().to_owned(),
        effect_kind: CHANNEL_SERVICE_DISPATCH_EFFECT_KIND.to_owned(),
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
            state: EconomicAdmissionHandoffStateV1::DispatchCommitted,
            operation_version: commit.committed_version,
            lifecycle_fence: commit.coordinator_lease_epoch,
            store_fence: commit.store_fence.clone(),
        },
        target: EconomicEffectTargetV1 {
            target_id: provider.transport_id.clone(),
            target_key_epoch: provider.transport_key_epoch,
            qualification_digest: channel_digest(format!("provider-qualification-{suffix}")),
        },
        action_digest: operation
            .binding()
            .action_parameter_hash()
            .as_str()
            .to_owned(),
        parameters_digest: reservation_digest.as_str().to_owned(),
        resource_head_digest: reserved_channel_head.digest()?,
        frost: None,
        idempotency_key: derive_channel_service_dispatch_idempotency_key(
            operation.binding().operation_id().as_str(),
            &proposal.artifact().body.reservation_id,
            proposal.artifact().body.next_sequence,
        )?,
        state: EconomicEffectStateV1::Ready,
        terminal: None,
    };
    ready_effect.slot_id = ready_effect.recompute_slot_id()?;
    let ready_head = effect_head(&ready_effect, 1, None, 1_500)?;
    let mut reservation_view = reserved_channel_view.view().clone();
    reservation_view.checkpoint_digest = channel_digest(format!("reservation-checkpoint-{suffix}"));
    reservation_view.heads.push(ready_head.clone());
    reservation_view
        .heads
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    reservation_view.request_replays = vec![EconomicRequestReplayV1 {
        request: ready_effect.request.clone(),
        operation_id: ready_effect.operation_id.clone(),
        effect_slot_ids: vec![ready_effect.slot_id.clone()],
    }];
    reservation_view.seal(&Keypair::from_seed(&[61; 32]))?;
    let reservation_view = verify_economic_state_view(reservation_view, &anchor_pins())?;
    let reservation = verify_admitted_channel_reservation(&proposal, &prepared, &reservation_view)?;
    let mut dispatch_effect = ready_effect;
    dispatch_effect.state = EconomicEffectStateV1::DispatchCommitted;
    let dispatch_head = effect_head(&dispatch_effect, 2, Some(ready_head.digest()?), 1_550)?;
    let dispatch_advance = verified_terminal_batch(
        &reservation_view,
        operation.binding().operation_id().as_str(),
        vec![EconomicStateTransitionV1 {
            resource_key: dispatch_effect.resource_head_key(),
            expected_head_digest: dispatch_head.predecessor_digest.clone(),
            next_head: dispatch_head.clone(),
            transition_proof_digest: channel_digest(format!("dispatch-proof-{suffix}")),
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
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    dispatched_view.heads[dispatch_index] = dispatch_head;
    dispatched_view.seal(&Keypair::from_seed(&[61; 32]))?;
    let dispatched_view = verify_economic_state_view(dispatched_view, &anchor_pins())?;
    verify_economic_state_batch_commit(&dispatch_advance, &dispatched_view, &anchor_pins())?;
    let actual_charge = MonetaryAmount {
        units: actual_charge_units,
        currency: "USD".to_owned(),
    };
    let channel_metadata = ChannelReceiptMetadataV1 {
        schema: CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA.to_owned(),
        channel_id: reservation.artifact().body.channel_id.clone(),
        open_digest: open_digest.clone(),
        reservation_id: reservation.artifact().body.reservation_id.clone(),
        reservation_digest: reservation_digest.as_str().to_owned(),
        sequence: reservation.artifact().body.next_sequence,
        settlement_mode: ChannelSettlementModeV1::Channelized,
    };
    let admission_metadata = AdmissionReceiptMetadataV1 {
        schema: AdmissionReceiptSchema::V1,
        operation_id: operation.binding().operation_id().clone(),
        request_id: operation.replay_key().request_id.clone(),
        request_namespace_digest: operation.binding().request_namespace_digest().clone(),
        request_binding_hash: operation.binding().request_binding_hash().clone(),
        projected_operation_version: next_version(operation.version())?,
        projected_state: AdmissionOperationState::Completed,
        projected_dispatch_state: dispatch_state_for(
            operation.binding().kind(),
            AdmissionOperationState::Completed,
        )?,
        trusted_time_unix_ms: context.trusted_time_unix_ms,
        coordinator_lease_id: context.coordinator_lease_id.clone(),
        coordinator_lease_epoch: context.coordinator_lease_epoch,
        store_fence: context.store_fence.clone(),
        retained_dispatch_commit: operation.dispatch_commit().cloned(),
        compensation_status: AdmissionCompensationStatus::NotCompensated,
        tool_outcome_id: Some(tool_outcome.outcome_id().clone()),
        tool_outcome_version: Some(tool_outcome.outcome_version()),
    };
    let raw_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: format!("channel-receipt-{suffix}-{receipt_variant}"),
            timestamp: context.trusted_time_unix_ms / 1_000,
            capability_id: operation.binding().capability_id().as_str().to_owned(),
            tool_server: tool_outcome.tool_server().as_str().to_owned(),
            tool_name: tool_outcome.tool_name().as_str().to_owned(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: tool_outcome.resolved_output_digest().as_str().to_owned(),
            policy_hash: operation.binding().policy_hash().as_str().to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                ADMISSION_RECEIPT_METADATA_KEY: admission_metadata,
                "channel": channel_metadata,
                "financial": FinancialReceiptMetadata {
                    grant_index: 0,
                    cost_charged: actual_charge.units,
                    currency: actual_charge.currency.clone(),
                    budget_remaining: 150_u64.checked_sub(actual_charge.units).ok_or(
                        AdmissionOperationError::TerminalProjectionBindingMismatch
                    )?,
                    budget_total: 150,
                    delegation_depth: 0,
                    root_budget_holder: channel_fixture.trust.payer_id.clone(),
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
            tenant_id: Some("channel-tenant".to_owned()),
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )?;
    let receipt = VerifiedAdmissionReceipt::from_kernel_verified(
        raw_receipt.clone(),
        &kernel.public_key(),
        &operation,
        &context,
        &tool_outcome,
    )?;
    let raw_receipt_digest = receipt_digest(&raw_receipt)?;
    let atom = (actual_charge.units > 0)
        .then(|| {
            ObligationAtomV1::new(ObligationAtomInputV1 {
                economic_intent_digest: reservation.artifact().body.proposal_digest()?,
                source_receipt_id: raw_receipt.id.clone(),
                source_receipt_digest: raw_receipt_digest.as_str().to_owned(),
                debtor_id: channel_fixture.open.intent().body.payer_id.clone(),
                original_creditor_id: channel_fixture.open.intent().body.payee_id.clone(),
                original_settlement_destination_ref: channel_fixture
                    .open
                    .intent()
                    .body
                    .payee_beneficiary_address
                    .clone(),
                payee_binding_digest: derive_channel_payee_binding_digest(
                    &channel_fixture.open.intent().body.payee_id,
                    &channel_fixture.open.intent().body.payee_beneficiary_address,
                )?,
                amount: actual_charge,
                credit_election: ObligationCreditElectionV1::NotCredit,
                pre_action_authority_digest: reservation_digest.as_str().to_owned(),
                created_at_unix_ms: context.trusted_time_unix_ms,
                due_at_unix_ms: 2_000,
            })
            .map_err(|error| -> Box<dyn Error> { Box::new(error) })
        })
        .transpose()?;
    let channel_receipt = verify_channel_receipt_binding(
        &raw_receipt,
        &kernel.public_key(),
        &reservation,
        &channel_fixture.open,
        atom.as_ref(),
    )?;
    let next_body = build_channel_state_transition(
        &prior,
        &reservation,
        &channel_receipt,
        &channel_fixture.open,
    )?;
    let signed_next = SignedChannelStateV1 {
        payee_signature: ChannelSignatureV1::sign(
            &next_body,
            channel_fixture.trust.payee_id.clone(),
            channel_fixture.trust.payee_key_epoch,
            &channel_fixture.payee_key,
        )?,
        body: next_body,
    };
    let next = verify_channel_state_transition(
        &signed_next,
        &prior,
        &reservation,
        &channel_receipt,
        &channel_fixture.open,
        &channel_fixture.trust,
    )?;
    let terminal_lifecycle = ChannelLifecycleViewV1 {
        latest_state_digest: next.digest()?,
        latest_sequence: next.body().seq,
        state_version: 3,
        lifecycle_fence: 4,
        live_reservation_id: None,
        operation_id: None,
        ..reserved_lifecycle
    };
    let terminal_escrow = ChannelEscrowReservationViewV1 {
        version: 4,
        lifecycle_fence: 4,
        ..reserved_escrow
    };
    let result = EconomicContentV1::Inline {
        value: match effect_result_override {
            Some(value) => value,
            None => serde_json::to_value(&tool_outcome)?,
        },
    };
    let result_digest = result.digest()?;
    let mut completed_effect = dispatch_effect.clone();
    completed_effect.state = EconomicEffectStateV1::Completed;
    completed_effect.terminal = Some(EconomicEffectTerminalV1::Completed {
        result_id: tool_outcome.outcome_id().as_str().to_owned(),
        result_digest,
        result,
    });
    let escrow_key = EconomicResourceKeyV1 {
        resource_family: CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY.to_owned(),
        scope_id: channel_fixture.trust.settlement_authority_scope_id.clone(),
        resource_id: terminal_lifecycle.channel_id.clone(),
    };
    let current_channel_head = dispatched_view
        .view()
        .head(&channel_key)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let current_escrow_head = dispatched_view
        .view()
        .head(&escrow_key)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let current_effect_head = dispatched_view
        .view()
        .head(&dispatch_effect.resource_head_key())
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let next_channel_head = state_head_successor(
        current_channel_head,
        &terminal_lifecycle,
        terminal_lifecycle.state_version,
        terminal_lifecycle.lifecycle_fence,
        1_600,
    )?;
    let next_escrow_head = state_head_successor(
        current_escrow_head,
        &terminal_escrow,
        terminal_escrow.version,
        terminal_escrow.lifecycle_fence,
        1_600,
    )?;
    let next_effect_head = effect_head(
        &completed_effect,
        current_effect_head
            .head_version
            .checked_add(1)
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
        Some(current_effect_head.digest()?),
        1_600,
    )?;
    let advance = verified_terminal_batch(
        &dispatched_view,
        operation.binding().operation_id().as_str(),
        vec![
            EconomicStateTransitionV1 {
                resource_key: channel_key,
                expected_head_digest: next_channel_head.predecessor_digest.clone(),
                next_head: next_channel_head,
                transition_proof_digest: channel_digest(format!("channel-proof-{suffix}")),
                prepared_effect: None,
            },
            EconomicStateTransitionV1 {
                resource_key: escrow_key,
                expected_head_digest: next_escrow_head.predecessor_digest.clone(),
                next_head: next_escrow_head,
                transition_proof_digest: channel_digest(format!("escrow-proof-{suffix}")),
                prepared_effect: None,
            },
            EconomicStateTransitionV1 {
                resource_key: dispatch_effect.resource_head_key(),
                expected_head_digest: next_effect_head.predecessor_digest.clone(),
                next_head: next_effect_head,
                transition_proof_digest: channel_digest(format!("effect-proof-{suffix}")),
                prepared_effect: None,
            },
        ],
        1_600,
    )?;
    let signed_terminal_outcome = sign_channel_terminal_outcome_commitment(
        &operation,
        &reservation,
        &receipt,
        &tool_outcome,
        &context,
        &kernel,
    )?;
    let terminal_outcome = verify_channel_terminal_outcome_commitment(
        &signed_terminal_outcome,
        &kernel.public_key(),
        &reservation,
        receipt.receipt(),
    )?;
    let verified_advance = verify_channel_terminal_advance(
        &channel_fixture.open,
        &reservation,
        &prior,
        &next,
        &channel_receipt,
        &terminal_outcome,
        &advance,
    )?;
    Ok(ChannelAdvanceFixture {
        operation,
        context,
        receipt,
        tool_outcome,
        open: channel_fixture.open,
        reservation,
        atom,
        anchored_advance: advance,
        advance: verified_advance,
    })
}

fn build_fixture(actual_charge_units: u64, suffix: &str) -> TestResult<ChannelProjectionFixture> {
    let base = build_advance_fixture(
        actual_charge_units,
        suffix,
        "primary",
        serde_json::json!({ "result": "ok" }),
        None,
    )?;
    let (channel, obligation) = VerifiedChannelTerminalProjectionV1::from_verified(
        &base.operation,
        &base.context,
        &base.receipt,
        &base.tool_outcome,
        &base.advance,
    )?;
    Ok(ChannelProjectionFixture {
        base,
        obligation,
        channel,
    })
}

fn capabilities() -> AdmissionProjectionCapabilities {
    AdmissionProjectionCapabilities {
        operation_terminal: true,
        incident_terminal: true,
        tool_outcome: true,
        payment_terminal: true,
        authorization_consumption: true,
        outcome_eligibility: true,
        observation_attempt_zero: true,
        obligation: true,
        channel_terminal: true,
        credit_exposure_terminal: true,
        economic_mutation_terminal: true,
    }
}

fn completed_projection(fixture: &ChannelProjectionFixture) -> AdmissionTerminalProjection {
    AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
        context: fixture.base.context.clone(),
        receipt: fixture.base.receipt.clone(),
        tool_outcome: Some(fixture.base.tool_outcome.clone()),
        payment_evidence: None,
        authorization: None,
        eligibility: None,
        observer_work: None,
        obligation: fixture.obligation.clone(),
        channel_terminal: Some(fixture.channel.clone()),
    }))
}

fn mutated_atom(
    atom: &ObligationAtomV1,
    field: &str,
    replacement: serde_json::Value,
) -> TestResult<ObligationAtomV1> {
    let mut encoded = serde_json::to_value(atom)?;
    encoded
        .as_object_mut()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?
        .insert(field.to_owned(), replacement);
    Ok(serde_json::from_value(encoded)?)
}

#[test]
fn channel_terminal_constructor_derives_exact_positive_and_zero_charge_records() -> TestResult<()> {
    for (units, obligation_expected, suffix) in
        [(7, true, "positive"), (0, false, "contractual-zero")]
    {
        let fixture = build_fixture(units, suffix)?;
        assert!(completed_projection(&fixture).requires_anchored_economic_commit());
        assert_eq!(fixture.obligation.is_some(), obligation_expected);
        assert_eq!(fixture.base.atom.is_some(), obligation_expected);
        assert_eq!(
            fixture.channel.operation_binding().operation_id(),
            fixture.base.operation.binding().operation_id()
        );
        assert_eq!(
            fixture.channel.operation_binding().request_id(),
            &fixture.base.operation.replay_key().request_id
        );
        assert_eq!(
            fixture.channel.operation_binding().request_binding_hash(),
            fixture.base.operation.binding().request_binding_hash()
        );
        assert_eq!(
            fixture.channel.predecessor_view(),
            fixture.base.anchored_advance.current().view()
        );
        assert_eq!(
            fixture.channel.terminal_batch(),
            fixture.base.anchored_advance.batch()
        );
        assert_eq!(
            fixture.channel.batch_id().as_str(),
            fixture.base.advance.batch_id()
        );
        assert_eq!(
            fixture.channel.previous_checkpoint_digest().as_str(),
            fixture.base.advance.previous_checkpoint_digest()
        );
        assert_eq!(
            fixture.channel.checkpoint_digest().as_str(),
            fixture.base.advance.checkpoint_digest()
        );
        assert_eq!(
            fixture.channel.batch_issued_at(),
            fixture.base.context.trusted_time_unix_ms
        );
        assert_eq!(
            fixture.channel.prior_channel_head_digest().as_str(),
            fixture.base.advance.prior_channel_head_digest()
        );
        assert_eq!(
            fixture.channel.prior_escrow_head_digest().as_str(),
            fixture.base.advance.prior_escrow_head_digest()
        );
        assert_eq!(
            fixture.channel.prior_effect_head_digest().as_str(),
            fixture.base.advance.prior_effect_head_digest()
        );
        assert_eq!(
            fixture.channel.terminal_channel_head_digest().as_str(),
            fixture.base.advance.terminal_channel_head_digest()
        );
        assert_eq!(
            fixture.channel.terminal_escrow_head_digest().as_str(),
            fixture.base.advance.terminal_escrow_head_digest()
        );
        assert_eq!(
            fixture.channel.terminal_effect_head_digest().as_str(),
            fixture.base.advance.effect_head_digest()
        );
        assert_eq!(
            fixture.channel.terminal_lifecycle(),
            fixture.base.advance.terminal_lifecycle()
        );
        assert_eq!(
            fixture.channel.terminal_escrow(),
            fixture.base.advance.terminal_escrow()
        );
        assert_eq!(
            fixture.channel.signed_reservation(),
            fixture.base.advance.reservation().artifact()
        );
        assert_eq!(
            fixture.channel.signed_next_state().body,
            *fixture.base.advance.next_state().body()
        );
        assert_eq!(
            fixture
                .channel
                .qualify_anchored_advance(&fixture.base.anchored_advance)?,
            fixture.channel.completed_effect_slot()
        );
        assert_eq!(
            fixture.channel.qualify_retained_anchored_advance(
                fixture.base.anchored_advance.current().view(),
                fixture.base.anchored_advance.batch(),
            )?,
            fixture.channel.completed_effect_slot()
        );
        if let (Some(obligation), Some(atom)) =
            (fixture.obligation.as_ref(), fixture.base.atom.as_ref())
        {
            assert_eq!(obligation.atom(), atom);
            assert_eq!(
                obligation.disposition_record().disposition(),
                &ObligationDispositionV1::Channelized {
                    channel_id: fixture.base.advance.channel_id().to_owned(),
                    reservation_id: fixture.base.advance.reservation_id().to_owned(),
                }
            );
        }

        let projection = completed_projection(&fixture);
        let canonical = projection.canonical_projection()?;
        let kinds = canonical
            .records()
            .iter()
            .map(|record| record.commitment().kind())
            .collect::<BTreeSet<_>>();
        assert!(kinds.contains(&AdmissionProjectionRecordKind::ChannelTerminal));
        assert_eq!(
            kinds.contains(&AdmissionProjectionRecordKind::Obligation),
            obligation_expected
        );
        let terminal = fixture
            .base
            .operation
            .apply_terminal_projection(&projection, &capabilities())?;
        assert_eq!(terminal.state(), AdmissionOperationState::Completed);
    }
    Ok(())
}

#[test]
fn kernel_terminal_outcome_adapter_derives_exact_private_evidence() -> TestResult<()> {
    let fixture = build_fixture(7, "kernel-outcome-adapter")?;
    let kernel = Keypair::from_seed(&[36; 32]);
    let signed = sign_channel_terminal_outcome_commitment(
        &fixture.base.operation,
        &fixture.base.reservation,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &fixture.base.context,
        &kernel,
    )?;
    let expected_result = EconomicContentV1::Inline {
        value: serde_json::to_value(&fixture.base.tool_outcome)?,
    };
    let encoded_evidence = serde_json::to_value(&fixture.base.tool_outcome)?;
    assert_eq!(
        signed.body.terminal_result.result_id,
        fixture.base.tool_outcome.outcome_id().as_str()
    );
    assert_eq!(signed.body.terminal_result.result, expected_result);
    assert_eq!(
        signed.body.terminal_result.result_digest,
        expected_result.digest()?
    );
    assert_eq!(
        signed.body.outcome_recorded_at_unix_ms,
        encoded_evidence["outcome_recorded_at_unix_ms"]
            .as_u64()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?
    );
    assert_eq!(
        signed.body.terminalized_at_unix_ms,
        fixture.base.context.trusted_time_unix_ms
    );
    verify_channel_terminal_outcome_commitment(
        &signed,
        &kernel.public_key(),
        &fixture.base.reservation,
        fixture.base.receipt.receipt(),
    )?;

    let alternate = build_fixture(7, "kernel-outcome-adapter-alternate")?;
    assert!(sign_channel_terminal_outcome_commitment(
        &fixture.base.operation,
        &fixture.base.reservation,
        &alternate.base.receipt,
        &alternate.base.tool_outcome,
        &fixture.base.context,
        &kernel,
    )
    .is_err());
    assert!(sign_channel_terminal_outcome_commitment(
        &fixture.base.operation,
        &alternate.base.reservation,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &fixture.base.context,
        &kernel,
    )
    .is_err());
    Ok(())
}

#[test]
fn channel_terminal_projection_rebases_immutable_evidence_over_a_later_checkpoint() -> TestResult<()>
{
    let fixture = build_fixture(7, "terminal-later-rebase")?;
    let kernel = Keypair::from_seed(&[36; 32]);
    let signed_outcome = sign_channel_terminal_outcome_commitment(
        &fixture.base.operation,
        &fixture.base.reservation,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &fixture.base.context,
        &kernel,
    )?;
    let outcome = verify_channel_terminal_outcome_commitment(
        &signed_outcome,
        &kernel.public_key(),
        &fixture.base.reservation,
        fixture.base.receipt.receipt(),
    )?;
    let mut later_view = fixture.base.advance.current_view().view().clone();
    later_view.checkpoint_sequence = later_view
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    later_view.checkpoint_digest = channel_digest("terminal-later-rebase-checkpoint");
    later_view.observed_at = 1_700;
    later_view.seal(&Keypair::from_seed(&[61; 32]))?;
    let later_view = verify_economic_state_view(later_view, &anchor_pins())?;
    let issued_at = 1_701;
    let transition = compose_channel_terminal_transition(
        fixture.base.advance.open(),
        &fixture.base.reservation,
        fixture.base.advance.next_state(),
        fixture.base.advance.receipt(),
        &outcome,
        &later_view,
        issued_at,
    )?;
    let anchored_advance = verified_terminal_batch(
        &later_view,
        fixture.base.operation.binding().operation_id().as_str(),
        transition.transitions().to_vec(),
        issued_at,
    )?;
    let advance = verify_channel_terminal_advance(
        fixture.base.advance.open(),
        &fixture.base.reservation,
        fixture.base.advance.prior_state(),
        fixture.base.advance.next_state(),
        fixture.base.advance.receipt(),
        &outcome,
        &anchored_advance,
    )?;
    assert_eq!(
        advance.obligation_atom(),
        fixture.base.advance.obligation_atom()
    );
    assert_eq!(advance.next_state(), fixture.base.advance.next_state());
    assert!(fixture.base.context.trusted_time_unix_ms < advance.batch_issued_at());

    let (channel, obligation) = VerifiedChannelTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &fixture.base.tool_outcome,
        &advance,
    )?;
    assert_eq!(
        obligation.as_ref().map(ObligationProjection::atom),
        fixture.base.atom.as_ref()
    );
    let projection =
        AdmissionTerminalProjection::Completed(Box::new(AdmissionCompletedProjection {
            context: fixture.base.context.clone(),
            receipt: fixture.base.receipt.clone(),
            tool_outcome: Some(fixture.base.tool_outcome.clone()),
            payment_evidence: None,
            authorization: None,
            eligibility: None,
            observer_work: None,
            obligation,
            channel_terminal: Some(channel),
        }));
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &projection,
        &capabilities(),
        &kernel,
    )?;
    let verified = envelope.verify()?;
    assert_eq!(
        verified
            .channel_terminal()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?
            .batch_issued_at(),
        issued_at
    );
    Ok(())
}

#[test]
fn channel_terminal_rejects_non_atomic_projection_time_and_substituted_advance() -> TestResult<()> {
    let fixture = build_fixture(7, "anchored-qualification")?;
    let mismatched_time = fixture
        .base
        .context
        .trusted_time_unix_ms
        .checked_sub(1)
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let mut mismatched_projection = serde_json::to_value(&fixture.channel)?;
    mismatched_projection["binding"]["trusted_time_unix_ms"] = serde_json::json!(mismatched_time);
    let mismatched_projection = canonical_json_bytes(&mismatched_projection)?;
    assert!(
        VerifiedChannelTerminalProjectionV1::from_canonical_record_verified(
            &mismatched_projection,
            &fixture.base.operation,
            &fixture.base.context,
        )
        .is_err()
    );

    let substituted = build_fixture(7, "substituted-anchor")?;
    assert!(fixture
        .channel
        .qualify_anchored_advance(&substituted.base.anchored_advance)
        .is_err());
    assert!(fixture
        .channel
        .qualify_retained_anchored_advance(
            substituted.base.anchored_advance.current().view(),
            substituted.base.anchored_advance.batch(),
        )
        .is_err());
    Ok(())
}

#[test]
fn signed_channel_terminal_preserves_typed_anchor_contract() -> TestResult<()> {
    let fixture = build_fixture(7, "signed-anchor")?;
    let projection = completed_projection(&fixture);
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &projection,
        &capabilities(),
        &Keypair::from_seed(&[36; 32]),
    )?;
    let verified = envelope.verify()?;
    assert!(verified.requires_anchored_economic_commit());
    let channel = verified
        .channel_terminal()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    assert_eq!(
        channel.predecessor_view(),
        fixture.channel.predecessor_view()
    );
    assert_eq!(channel.terminal_batch(), fixture.channel.terminal_batch());
    assert_eq!(
        channel.signed_reservation(),
        fixture.channel.signed_reservation()
    );
    assert_eq!(
        channel.signed_next_state(),
        fixture.channel.signed_next_state()
    );
    assert_eq!(
        channel.qualify_anchored_advance(&fixture.base.anchored_advance)?,
        fixture.channel.completed_effect_slot()
    );
    Ok(())
}

#[test]
fn resigned_terminal_envelope_rejects_substituted_obligation_record() -> TestResult<()> {
    let fixture = build_fixture(7, "signed-obligation-primary")?;
    let alternate = build_fixture(7, "signed-obligation-alternate")?;
    let kernel = Keypair::from_seed(&[36; 32]);
    let envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &completed_projection(&fixture),
        &capabilities(),
        &kernel,
    )?;
    let alternate_envelope = SignedAdmissionTerminalProjectionV1::from_verified(
        &alternate.base.operation,
        &completed_projection(&alternate),
        &capabilities(),
        &kernel,
    )?;
    let alternate_encoded = serde_json::to_value(alternate_envelope)?;
    let alternate_record = alternate_encoded["body"]["records"]
        .as_array()
        .and_then(|records| {
            records.iter().find(|record| {
                record.get("kind").and_then(serde_json::Value::as_str) == Some("obligation")
            })
        })
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let alternate_bytes = STANDARD.decode(
        alternate_record["canonical_json"]
            .as_str()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
    )?;
    let alternate_obligation: serde_json::Value = serde_json::from_slice(&alternate_bytes)?;

    let mut encoded = serde_json::to_value(envelope)?;
    let record = encoded["body"]["records"]
        .as_array_mut()
        .and_then(|records| {
            records.iter_mut().find(|record| {
                record.get("kind").and_then(serde_json::Value::as_str) == Some("obligation")
            })
        })
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    let primary_bytes = STANDARD.decode(
        record["canonical_json"]
            .as_str()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
    )?;
    let mut substituted: serde_json::Value = serde_json::from_slice(&primary_bytes)?;
    substituted["atom"] = alternate_obligation["atom"].clone();
    substituted["disposition_record"] = alternate_obligation["disposition_record"].clone();
    let substituted_bytes = canonical_json_bytes(&substituted)?;
    let substituted_digest = chio_core::crypto::sha256_hex(&substituted_bytes);
    record["canonical_json"] = serde_json::Value::String(STANDARD.encode(&substituted_bytes));
    record["record_digest"] = serde_json::Value::String(substituted_digest.clone());

    let manifest_bytes = STANDARD.decode(
        encoded["body"]["manifest_json"]
            .as_str()
            .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?,
    )?;
    let mut manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    let manifest_record = manifest["records"]
        .as_array_mut()
        .and_then(|records| {
            records.iter_mut().find(|record| {
                record.get("kind").and_then(serde_json::Value::as_str) == Some("obligation")
            })
        })
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    manifest_record["record_digest"] = serde_json::Value::String(substituted_digest);
    let manifest_bytes = canonical_json_bytes(&manifest)?;
    encoded["body"]["manifest_json"] = serde_json::Value::String(STANDARD.encode(&manifest_bytes));
    let projection_digest = chio_core::crypto::sha256_hex(&manifest_bytes);
    let replay_digest = encoded
        .pointer_mut("/body/terminal_operation/terminal_replay/receipt/projection_digest")
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    *replay_digest = serde_json::Value::String(projection_digest);

    let canonical_body = canonical_json_bytes(&encoded["body"])?;
    let mut preimage = b"chio.signed-admission-terminal-projection.v1\0".to_vec();
    preimage.extend_from_slice(&canonical_body);
    encoded["signature"] = serde_json::to_value(kernel.sign(&preimage))?;
    let substituted: SignedAdmissionTerminalProjectionV1 = serde_json::from_value(encoded)?;
    assert_eq!(
        substituted.verify(),
        Err(AdmissionOperationError::TerminalProjectionBindingMismatch)
    );
    Ok(())
}

#[test]
fn channel_receipt_rejects_every_substituted_obligation_binding() -> TestResult<()> {
    let fixture = build_fixture(7, "obligation-substitution")?;
    let atom = fixture
        .base
        .atom
        .as_ref()
        .ok_or(AdmissionOperationError::TerminalProjectionBindingMismatch)?;
    for (field, replacement) in [
        (
            "preActionAuthorityDigest",
            serde_json::Value::String(channel_digest("substituted-authority")),
        ),
        (
            "obligationId",
            serde_json::Value::String(channel_digest("substituted-obligation-id")),
        ),
        (
            "sourceReceiptDigest",
            serde_json::Value::String(channel_digest("substituted-receipt-digest")),
        ),
        (
            "amount",
            serde_json::json!({ "units": 8, "currency": "USD" }),
        ),
        (
            "originalCreditorId",
            serde_json::Value::String("substituted-creditor".to_owned()),
        ),
        (
            "debtorId",
            serde_json::Value::String("substituted-debtor".to_owned()),
        ),
    ] {
        let substituted = mutated_atom(atom, field, replacement)?;
        assert!(
            verify_channel_receipt_binding(
                fixture.base.receipt.receipt(),
                &fixture.base.receipt.receipt().kernel_key,
                &fixture.base.reservation,
                &fixture.base.open,
                Some(&substituted),
            )
            .is_err(),
            "substituted obligation field was accepted: {field}"
        );
    }
    Ok(())
}

#[test]
fn channel_terminal_constructor_rejects_receipt_and_tool_outcome_substitution() -> TestResult<()> {
    let fixture = build_fixture(7, "constructor-substitution")?;
    let alternate_receipt = build_advance_fixture(
        7,
        "constructor-substitution",
        "alternate",
        serde_json::json!({ "result": "ok" }),
        None,
    )
    .map_err(|error| std::io::Error::other(format!("alternate receipt: {error}")))?;
    assert!(VerifiedChannelTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &fixture.base.context,
        &alternate_receipt.receipt,
        &fixture.base.tool_outcome,
        &fixture.base.advance,
    )
    .is_err());

    let alternate_outcome = build_advance_fixture(
        7,
        "constructor-substitution",
        "outcome",
        serde_json::json!({ "result": "substituted" }),
        None,
    )
    .map_err(|error| std::io::Error::other(format!("alternate outcome: {error}")))?;
    assert!(VerifiedChannelTerminalProjectionV1::from_verified(
        &fixture.base.operation,
        &fixture.base.context,
        &fixture.base.receipt,
        &alternate_outcome.tool_outcome,
        &fixture.base.advance,
    )
    .is_err());

    Ok(())
}

#[test]
fn channel_authority_rejects_terminal_effect_substitution() -> TestResult<()> {
    let result = build_advance_fixture(
        7,
        "constructor-substitution",
        "primary",
        serde_json::json!({ "result": "ok" }),
        Some(serde_json::json!({ "outcome": "substituted" })),
    );
    assert_eq!(
        result.err().map(|error| error.to_string()).as_deref(),
        Some("channel authority verification failed")
    );
    Ok(())
}
