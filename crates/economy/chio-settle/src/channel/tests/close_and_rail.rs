use super::*;

#[test]
fn public_rail_amount_conversion_rejects_invalid_policy_currency_and_ijson_overflow(
) -> Result<(), SettlementError> {
    let mut config = crate::SettlementChainConfig {
        chain_id: "eip155:31337".to_owned(),
        network_name: "channel-rail-test".to_owned(),
        rpc_url: "http://127.0.0.1:8545".to_owned(),
        egress_contract: crate::settlement_devnet_rpc_egress_contract("http://127.0.0.1:8545")?,
        escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_owned(),
        bond_vault_contract: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_owned(),
        identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_owned(),
        root_registry_contract: "0x3a167ACFC3348a8f8df11BF383aF3cA86a8A2B42".to_owned(),
        operator_address: "0x8d6d63c22D114C18C2a0dA6Db0A8972Ed9C40343".to_owned(),
        settlement_token_symbol: "mUSDC".to_owned(),
        settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_owned(),
        oracle: crate::SettlementOracleConfig::default(),
        evidence_substrate: crate::SettlementEvidenceConfig::default(),
        policy: crate::SettlementPolicyConfig::default(),
    };
    let scaled = crate::scale_chio_amount_to_token_minor_units(
        &MonetaryAmount {
            units: 150,
            currency: "USD".to_owned(),
        },
        &config,
    )?;

    config.policy.tiers.clear();
    assert!(crate::scale_token_minor_units_to_chio_amount(scaled, "USD", &config).is_err());
    config.policy = crate::SettlementPolicyConfig::default();
    assert!(crate::scale_token_minor_units_to_chio_amount(scaled, "usd", &config).is_err());
    let unsafe_units = (u128::from((1_u64 << 53) - 1) + 1) * 10_000;
    assert!(crate::scale_token_minor_units_to_chio_amount(unsafe_units, "USD", &config).is_err());
    Ok(())
}

#[test]
fn close_fences_reservations_and_binds_zero_release_frost_action() -> Result<(), ChannelError> {
    let fixture = verified_channel_fixture()?;
    let open = fixture.open;
    let trust = fixture.trust;
    let final_state = open.initial_state();
    let pre_lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: final_state.body().digest()?,
        latest_sequence: 0,
        state_version: 1,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let pre_escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        open_digest: open.artifact().digest()?,
        escrow_reference: open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 2,
        lifecycle_fence: 2,
        pending_close_body_digest: None,
    };
    let serialized_lifecycle = serde_json::to_value(&pre_lifecycle)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    assert!(serialized_lifecycle.get("stateBatchDigest").is_none());
    assert!(serialized_lifecycle.get("externalHeadDigest").is_none());
    let pre_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &pre_lifecycle,
        &pre_escrow,
        1_500,
    )?;
    let pre_snapshot = verify_channel_lifecycle_snapshot(
        &pre_view,
        &trust.settlement_authority_scope_id,
        &pre_lifecycle.channel_id,
    )?;
    assert_ne!(
        pre_snapshot.channel_head_digest(),
        pre_snapshot.escrow_head_digest()
    );
    let cutoff_unix_ms = open
        .intent()
        .body
        .close_submission_cutoff_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let dispute_window_unix_ms = open
        .intent()
        .body
        .dispute_window_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    assert!(build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        final_state,
        &pre_snapshot,
        cutoff_unix_ms - dispute_window_unix_ms,
    )
    .is_err());
    let close_body = build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        final_state,
        &pre_snapshot,
        1_500,
    )?;
    assert_eq!(close_body.expected_release_token_base_units, "0");
    assert_eq!(
        close_body.expected_refund_after_release_token_base_units,
        open.intent().body.bound_token_base_units
    );
    let close = SignedChannelCloseV1 {
        payee_signature: ChannelSignatureV1::sign(
            &close_body,
            trust.payee_id.clone(),
            trust.payee_key_epoch,
            &fixture.payee_key,
        )?,
        payer_signature: None,
        body: close_body,
    };
    let mut shortened_window = close.clone();
    shortened_window.body.dispute_deadline_unix_ms = shortened_window.body.proposed_at_unix_ms + 1;
    shortened_window.payee_signature = ChannelSignatureV1::sign(
        &shortened_window.body,
        trust.payee_id.clone(),
        trust.payee_key_epoch,
        &fixture.payee_key,
    )?;
    let shortened_digest = shortened_window.body.digest()?;
    let close_body_digest = close.body.digest()?;
    let post_lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: close.body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::ClosePending,
        latest_state_digest: close.body.final_state_digest.clone(),
        latest_sequence: close.body.final_state_sequence,
        state_version: close.body.channel_state_version,
        lifecycle_fence: close.body.lifecycle_fence,
        pending_close_body_digest: Some(close_body_digest.clone()),
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let post_escrow = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: close.body.channel_id.clone(),
        open_digest: close.body.open_digest.clone(),
        escrow_reference: open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: close.body.escrow_reservation_version,
        lifecycle_fence: close.body.lifecycle_fence,
        pending_close_body_digest: Some(close_body_digest),
    };
    let mut shortened_lifecycle = post_lifecycle.clone();
    shortened_lifecycle.pending_close_body_digest = Some(shortened_digest.clone());
    let mut shortened_escrow = post_escrow.clone();
    shortened_escrow.pending_close_body_digest = Some(shortened_digest);
    let shortened_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &shortened_lifecycle,
        &shortened_escrow,
        1_500,
    )?;
    let shortened_snapshot = verify_channel_lifecycle_snapshot(
        &shortened_view,
        &trust.settlement_authority_scope_id,
        &shortened_lifecycle.channel_id,
    )?;
    assert!(verify_channel_close(
        &shortened_window,
        &open,
        final_state,
        &shortened_snapshot,
        &trust,
    )
    .is_err());
    let mut wrong_escrow = pre_escrow.clone();
    wrong_escrow.escrow_reference.escrow_id = evm_hash("other-close-escrow");
    let wrong_escrow_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &pre_lifecycle,
        &wrong_escrow,
        1_500,
    )?;
    assert!(verify_admitted_channel_open(&open, &wrong_escrow_view).is_err());
    let wrong_escrow_snapshot = verify_channel_lifecycle_snapshot(
        &wrong_escrow_view,
        &trust.settlement_authority_scope_id,
        &pre_lifecycle.channel_id,
    )?;
    assert!(build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        final_state,
        &wrong_escrow_snapshot,
        1_500,
    )
    .is_err());
    let post_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &post_lifecycle,
        &post_escrow,
        1_500,
    )?;
    let post_snapshot = verify_channel_lifecycle_snapshot(
        &post_view,
        &trust.settlement_authority_scope_id,
        &post_lifecycle.channel_id,
    )?;
    let close = verify_channel_close(&close, &open, final_state, &post_snapshot, &trust)?;
    let mut substituted_close_trust = trust.clone();
    substituted_close_trust.original_web3_dispatch_digest = digest("other-close-dispatch");
    assert!(verify_channel_close(
        close.artifact(),
        &open,
        final_state,
        &post_snapshot,
        &substituted_close_trust,
    )
    .is_err());
    let effective = verify_effective_channel_close(&close)?;
    let action = channel_close_frost_action(&effective, 4)?;
    let chio_core::federation::frost::FrostActionPreimageV1::ChannelClose(action_body) = &action
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    assert_eq!(
        action_body.effective_close_digest,
        effective.effective_close_digest()
    );
    assert_eq!(
        action_body.final_cumulative_owed,
        effective.effective_state().body().cumulative_owed
    );
    assert_eq!(action.resource_version(), 2);
    assert_eq!(action.resource_fence(), 3);

    let mut reserved = pre_lifecycle;
    reserved.live_reservation_id = Some(digest("live-reservation"));
    reserved.operation_id = Some(digest("operation-live"));
    let reserved_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &reserved,
        &pre_escrow,
        1_500,
    )?;
    let reserved_snapshot = verify_channel_lifecycle_snapshot(
        &reserved_view,
        &trust.settlement_authority_scope_id,
        &reserved.channel_id,
    )?;
    assert!(build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        final_state,
        &reserved_snapshot,
        1_500,
    )
    .is_err());

    let mut cooperative = close.artifact().clone();
    cooperative.body.close_kind = ChannelCloseKindV1::Cooperative;
    cooperative.payee_signature = ChannelSignatureV1::sign(
        &cooperative.body,
        trust.payee_id.clone(),
        trust.payee_key_epoch,
        &fixture.payee_key,
    )?;
    assert!(
        verify_channel_close(&cooperative, &open, final_state, &post_snapshot, &trust,).is_err()
    );
    Ok(())
}
#[test]
fn channel_release_authority_binds_close_frost_slot_deadlines_and_allocation(
) -> Result<(), ChannelError> {
    let close = verified_zero_effective_close()?;
    let publisher_fence = 4;
    let trusted_time_unix_ms = close.close().artifact().body.dispute_deadline_unix_ms;
    let facts = release_frost_facts(&close, publisher_fence, trusted_time_unix_ms)?;
    let verified = verify_channel_release_authorization_parts(
        &close,
        &facts,
        publisher_fence,
        trusted_time_unix_ms,
    )?;
    let body = verified.binding();

    assert_eq!(body.channel_id(), close.close().artifact().body.channel_id);
    assert_eq!(
        body.open_digest(),
        close.close().artifact().body.open_digest
    );
    assert_eq!(
        body.effective_close_digest(),
        close.effective_close_digest()
    );
    assert_eq!(body.final_state_digest(), close.effective_state().digest()?);
    assert_eq!(
        body.final_state_sequence(),
        close.effective_state().body().seq
    );
    assert_eq!(
        body.final_cumulative_owed(),
        &close.effective_state().body().cumulative_owed
    );
    assert_eq!(body.expected_release_token_base_units(), "0");
    assert_eq!(
        body.expected_refund_token_base_units(),
        close.close().open().intent().body.bound_token_base_units
    );
    assert_eq!(
        body.original_operator(),
        close.close().open().intent().body.original_operator
    );
    assert_eq!(
        body.original_operator_key_hash(),
        close
            .close()
            .open()
            .intent()
            .body
            .original_operator_key_hash
    );
    assert_eq!(
        body.escrow_reservation_version(),
        close.snapshot().escrow().version
    );
    assert_eq!(body.publisher_fence(), publisher_fence);
    assert_eq!(
        body.frost().authorization_slot_id,
        facts.authorization_slot_id
    );
    assert_eq!(body.frost().action_digest, facts.action_digest);
    assert_eq!(body.authorized_at_unix_ms(), trusted_time_unix_ms);
    assert!(body.close_submission_cutoff_unix_ms() > trusted_time_unix_ms);

    let mut alternate_slot = facts.clone();
    alternate_slot.authorization_slot_id = digest("alternate-channel-release-frost-slot");
    let alternate = verify_channel_release_authorization_parts(
        &close,
        &alternate_slot,
        publisher_fence,
        trusted_time_unix_ms,
    )?;
    assert_ne!(
        verified.authorization_digest(),
        alternate.authorization_digest()
    );
    Ok(())
}

#[test]
fn channel_release_authority_rejects_stale_or_substituted_authority() -> Result<(), ChannelError> {
    let close = verified_zero_effective_close()?;
    let publisher_fence = 4;
    let dispute_deadline = close.close().artifact().body.dispute_deadline_unix_ms;
    let cutoff = close
        .close()
        .artifact()
        .body
        .close_submission_cutoff_unix_secs
        .checked_mul(1_000)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let facts = release_frost_facts(&close, publisher_fence, dispute_deadline)?;

    assert!(verify_channel_release_authorization_parts(
        &close,
        &facts,
        publisher_fence,
        dispute_deadline - 1,
    )
    .is_err());
    assert!(
        verify_channel_release_authorization_parts(&close, &facts, publisher_fence, cutoff,)
            .is_err()
    );

    for mutation in ["scope", "resource", "version", "fence", "action", "current"] {
        let mut substituted = facts.clone();
        match mutation {
            "scope" => substituted.scope_id = "other-settlement-scope".to_owned(),
            "resource" => substituted.resource_id = digest("other-channel"),
            "version" => substituted.resource_version += 1,
            "fence" => substituted.resource_fence += 1,
            "action" => substituted.action_digest = digest("other-close-action"),
            "current" => substituted.current = false,
            _ => return Err(ChannelError::AuthorityVerification),
        }
        assert!(verify_channel_release_authorization_parts(
            &close,
            &substituted,
            publisher_fence,
            dispute_deadline,
        )
        .is_err());
    }

    assert!(verify_channel_release_authorization_parts(
        &close,
        &facts,
        publisher_fence + 1,
        dispute_deadline,
    )
    .is_err());
    Ok(())
}

#[test]
fn public_channel_release_authority_requires_production_frost_verification() {
    let _: fn(
        &VerifiedEffectiveChannelCloseV1,
        &chio_federation::frost::VerifiedFrostAuthorization,
        u64,
        u64,
    ) -> Result<VerifiedChannelReleaseAuthorizationV1, ChannelError> =
        verify_channel_release_authorization;
}
#[test]
fn channel_release_preparation_rejects_dispatch_operator_asset_and_amount_drift(
) -> Result<(), ChannelError> {
    let close = verified_zero_effective_close()?;
    let publisher_fence = 4;
    let trusted_time = close.close().artifact().body.dispute_deadline_unix_ms;
    let frost = release_frost_facts(&close, publisher_fence, trusted_time)?;
    let authorization =
        verify_channel_release_authorization_parts(&close, &frost, publisher_fence, trusted_time)?;
    let facts = release_preparation_facts(&authorization);
    verify_channel_release_preparation_parts(&authorization, &facts)?;

    for mutation in [
        "dispatch",
        "chain",
        "escrow_contract",
        "escrow_id",
        "token",
        "symbol",
        "beneficiary",
        "operator",
        "key",
        "protocol_decimals",
        "token_decimals",
        "bound",
        "amount",
        "base_units",
    ] {
        let mut substituted = facts.clone();
        match mutation {
            "dispatch" => substituted.dispatch_digest = digest("other-dispatch"),
            "chain" => substituted.chain_id = "eip155:1".to_owned(),
            "escrow_contract" => {
                substituted.escrow_contract =
                    "0x7777777777777777777777777777777777777777".to_owned();
            }
            "escrow_id" => substituted.escrow_id = evm_hash("other-escrow"),
            "token" => {
                substituted.token_address = "0x7777777777777777777777777777777777777777".to_owned();
            }
            "symbol" => substituted.token_symbol = "USDT".to_owned(),
            "beneficiary" => {
                substituted.beneficiary_address =
                    "0x7777777777777777777777777777777777777777".to_owned();
            }
            "operator" => {
                substituted.operator = "0x7777777777777777777777777777777777777777".to_owned();
            }
            "key" => substituted.operator_key_hash = evm_hash("other-operator-key"),
            "protocol_decimals" => substituted.protocol_minor_unit_decimals += 1,
            "token_decimals" => substituted.token_decimals += 1,
            "bound" => substituted.escrow_bound.units += 1,
            "amount" => substituted.release_amount.units += 1,
            "base_units" => substituted.release_token_base_units = "1".to_owned(),
            _ => return Err(ChannelError::AuthorityVerification),
        }
        assert!(verify_channel_release_preparation_parts(&authorization, &substituted).is_err());
    }
    Ok(())
}

#[test]
fn channel_release_preparation_uses_pinned_non_unit_asset_scaling() -> Result<(), ChannelError> {
    let close = verified_effective_close_with_charge(25)?;
    let publisher_fence = 4;
    let trusted_time = close.close().artifact().body.dispute_deadline_unix_ms;
    let frost = release_frost_facts(&close, publisher_fence, trusted_time)?;
    let authorization =
        verify_channel_release_authorization_parts(&close, &frost, publisher_fence, trusted_time)?;
    let facts = release_preparation_facts(&authorization);

    assert_eq!(facts.release_amount.units, 25);
    assert_eq!(facts.protocol_minor_unit_decimals, 2);
    assert_eq!(facts.token_decimals, 6);
    assert_eq!(facts.release_token_base_units, "250000");
    verify_channel_release_preparation_parts(&authorization, &facts)?;

    let mut decimal_drift = facts.clone();
    decimal_drift.token_decimals = 5;
    assert!(verify_channel_release_preparation_parts(&authorization, &decimal_drift).is_err());

    let mut base_unit_drift = facts;
    base_unit_drift.release_token_base_units = "25".to_owned();
    assert!(verify_channel_release_preparation_parts(&authorization, &base_unit_drift).is_err());

    assert_eq!(
        asset_binding(3, 2).token_base_units(&MonetaryAmount {
            units: 25,
            currency: "USD".to_owned(),
        }),
        Err(ChannelError::InexactAmount)
    );
    Ok(())
}

#[test]
fn authorized_channel_merkle_preparation_requires_verified_release_authority() {
    type PrepareAuthorizedChannelMerkleRelease = fn(
        &crate::SettlementChainConfig,
        &chio_core::web3::settlement::Web3SettlementDispatchArtifact,
        &chio_core::web3::anchors::AnchorInclusionProof,
        &crate::SettlementAnchorContentBinding,
        &VerifiedChannelReleaseAuthorizationV1,
    ) -> Result<
        Option<crate::PreparedAuthorizedChannelMerkleReleaseV1>,
        crate::SettlementError,
    >;
    let _: PrepareAuthorizedChannelMerkleRelease = crate::prepare_authorized_channel_merkle_release;
}

fn release_mutation_binding(label: &str, effect_kind: &str) -> ChannelReleaseMutationBindingV1 {
    ChannelReleaseMutationBindingV1 {
        operation_id: digest(&format!("{label}-operation")),
        effect_slot_id: digest(&format!("{label}-effect-slot")),
        scope_id: "channel-settlement".to_owned(),
        effect_kind: effect_kind.to_owned(),
        idempotency_key: digest(&format!("{label}-idempotency")),
        call_digest: digest(&format!("{label}-call")),
        resource_head_digest: digest(&format!("{label}-resource-head")),
    }
}

fn verified_signed_release_authorization() -> Result<
    (
        VerifiedSignedChannelReleaseAuthorizationV1,
        ChannelReleaseMutationBindingV1,
    ),
    ChannelError,
> {
    let close = verified_zero_effective_close()?;
    let publisher_fence = 4;
    let trusted_time = close.close().artifact().body.dispute_deadline_unix_ms;
    let frost = release_frost_facts(&close, publisher_fence, trusted_time)?;
    let authority =
        verify_channel_release_authorization_parts(&close, &frost, publisher_fence, trusted_time)?;
    let root = release_mutation_binding(
        "channel-release-root",
        CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND,
    );
    let release = release_mutation_binding(
        "channel-release-broadcast",
        CHANNEL_RELEASE_BROADCAST_EFFECT_KIND,
    );
    let body = build_channel_release_authorization_body(
        &authority,
        digest("channel-release-publication-root"),
        root,
        release.clone(),
    )?;
    let publisher_key = Keypair::from_seed(&[19; 32]);
    let signed = SignedChannelReleaseAuthorizationV1 {
        publisher_signature: ChannelSignatureV1::sign(
            &body,
            "channel-release-publisher".to_owned(),
            8,
            &publisher_key,
        )?,
        body,
    };
    let trust = ChannelReleasePublisherTrustV1 {
        publisher_id: "channel-release-publisher".to_owned(),
        publisher_key_epoch: 8,
        publisher_key: publisher_key.public_key(),
    };
    Ok((
        verify_signed_channel_release_authorization(&signed, &authority, &trust, trusted_time)?,
        release,
    ))
}

fn release_dispatch_slot(
    authorization: &VerifiedSignedChannelReleaseAuthorizationV1,
    release: &ChannelReleaseMutationBindingV1,
) -> EconomicEffectSlotV1 {
    let authority = authorization.authority().binding();
    EconomicEffectSlotV1 {
        schema: CHIO_ECONOMIC_EFFECT_SLOT_SCHEMA.to_owned(),
        slot_id: release.effect_slot_id.clone(),
        anchor_id: "channel-anchor".to_owned(),
        namespace: "channel-namespace".to_owned(),
        resource_key: EconomicResourceKeyV1 {
            resource_family: "channel_escrow_reservation".to_owned(),
            scope_id: release.scope_id.clone(),
            resource_id: authority.channel_id().to_owned(),
        },
        operation_id: release.operation_id.clone(),
        effect_kind: release.effect_kind.clone(),
        request: EconomicRequestBindingV1 {
            request_namespace_digest: digest("channel-release-request-namespace"),
            request_id: "channel-release-request".to_owned(),
            request_binding_digest: digest("channel-release-request-binding"),
        },
        admission_handoff: EconomicAdmissionHandoffV1 {
            state: EconomicAdmissionHandoffStateV1::MutationSubmitted,
            operation_version: 3,
            lifecycle_fence: 2,
            store_fence: chio_kernel::admission_operation::StoreMutationFence {
                store_uuid: "channel-release-store".to_owned(),
                lease_id: "channel-release-lease".to_owned(),
                owner_epoch: 2,
            },
        },
        target: EconomicEffectTargetV1 {
            target_id: "channel-release-rail".to_owned(),
            target_key_epoch: 1,
            qualification_digest: digest("channel-release-target"),
        },
        action_digest: authority.frost().action_digest.clone(),
        parameters_digest: release.call_digest.clone(),
        resource_head_digest: release.resource_head_digest.clone(),
        frost: Some(authority.frost().clone()),
        idempotency_key: release.idempotency_key.clone(),
        state: EconomicEffectStateV1::DispatchCommitted,
        terminal: None,
    }
}

#[test]
fn release_dispatch_authority_rejects_every_signed_binding_substitution() -> Result<(), ChannelError>
{
    let (authorization, release) = verified_signed_release_authorization()?;
    let slot = release_dispatch_slot(&authorization, &release);
    verify_channel_release_dispatch_slot(&authorization, &slot)?;

    for mutation in [
        "slot",
        "operation",
        "scope",
        "resource_family",
        "resource",
        "effect",
        "idempotency",
        "call",
        "head",
        "action",
        "frost_slot",
        "frost_authorization",
        "frost_action",
        "frost_envelope",
        "handoff",
        "state",
    ] {
        let mut substituted = slot.clone();
        match mutation {
            "slot" => substituted.slot_id = digest("substituted-slot"),
            "operation" => substituted.operation_id = digest("substituted-operation"),
            "scope" => substituted.resource_key.scope_id = "substituted-scope".to_owned(),
            "resource_family" => {
                substituted.resource_key.resource_family = "substituted_resource".to_owned();
            }
            "resource" => substituted.resource_key.resource_id = digest("substituted-resource"),
            "effect" => substituted.effect_kind = "substituted_effect".to_owned(),
            "idempotency" => substituted.idempotency_key = digest("substituted-idempotency"),
            "call" => substituted.parameters_digest = digest("substituted-call"),
            "head" => substituted.resource_head_digest = digest("substituted-head"),
            "action" => substituted.action_digest = digest("substituted-action"),
            "frost_slot" => {
                substituted
                    .frost
                    .as_mut()
                    .ok_or(ChannelError::AuthorityVerification)?
                    .authorization_slot_id = digest("substituted-frost-slot");
            }
            "frost_authorization" => {
                substituted
                    .frost
                    .as_mut()
                    .ok_or(ChannelError::AuthorityVerification)?
                    .authorization_id = digest("substituted-frost-authorization");
            }
            "frost_action" => {
                substituted
                    .frost
                    .as_mut()
                    .ok_or(ChannelError::AuthorityVerification)?
                    .action_digest = digest("substituted-frost-action");
            }
            "frost_envelope" => {
                substituted
                    .frost
                    .as_mut()
                    .ok_or(ChannelError::AuthorityVerification)?
                    .signed_envelope_digest = digest("substituted-frost-envelope");
            }
            "handoff" => {
                substituted.admission_handoff.state =
                    EconomicAdmissionHandoffStateV1::DispatchCommitted;
            }
            "state" => substituted.state = EconomicEffectStateV1::Ready,
            _ => return Err(ChannelError::AuthorityVerification),
        }
        assert!(verify_channel_release_dispatch_slot(&authorization, &substituted).is_err());
    }
    Ok(())
}

#[test]
fn signed_channel_release_authorization_binds_root_release_and_publisher_epoch(
) -> Result<(), ChannelError> {
    let (verified, release) = verified_signed_release_authorization()?;
    let authority = verified.authority();
    let root = release_mutation_binding(
        "channel-release-root",
        CHANNEL_RELEASE_ROOT_PUBLICATION_EFFECT_KIND,
    );

    assert_eq!(
        verified.authority().authorization_digest(),
        authority.authorization_digest()
    );
    assert_eq!(verified.body().root_publication(), &root);
    assert_eq!(verified.body().release_broadcast(), &release);
    assert_eq!(
        verified.body().publication_root(),
        digest("channel-release-publication-root")
    );
    assert_ne!(verified.digest(), authority.authorization_digest());

    let mut substituted = verified.artifact().clone();
    substituted.body.release_broadcast.call_digest = digest("substituted-release-call");
    assert!(verify_signed_channel_release_authorization(
        &substituted,
        authority,
        &ChannelReleasePublisherTrustV1 {
            publisher_id: "channel-release-publisher".to_owned(),
            publisher_key_epoch: 8,
            publisher_key: Keypair::from_seed(&[19; 32]).public_key(),
        },
        authority.binding().authorized_at_unix_ms(),
    )
    .is_err());

    let wrong_epoch = ChannelReleasePublisherTrustV1 {
        publisher_id: "channel-release-publisher".to_owned(),
        publisher_key_epoch: 9,
        publisher_key: Keypair::from_seed(&[19; 32]).public_key(),
    };
    assert!(verify_signed_channel_release_authorization(
        verified.artifact(),
        authority,
        &wrong_epoch,
        authority.binding().authorized_at_unix_ms(),
    )
    .is_err());
    Ok(())
}
