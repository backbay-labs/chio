use super::*;

#[test]
fn reservation_authorizes_payee_signed_post_service_state() -> Result<(), ChannelError> {
    let fixture = verified_channel_fixture()?;
    let payer_key = fixture.payer_key;
    let payee_key = fixture.payee_key;
    let trust = fixture.trust;
    let open = fixture.open;
    let prior = open.initial_state();
    let authority_key = Keypair::from_seed(&[33; 32]);
    let authority = ChannelReservationAuthorityV1 {
        authority_id: "channel-authority".to_owned(),
        authority_key_epoch: 7,
        authority_key: authority_key.public_key(),
        trusted_time_unix_ms: 1_500,
    };
    let prior_digest = prior.body().digest()?;
    let open_digest = open.artifact().digest()?;
    let channel_id = open.artifact().body.channel_id.clone();
    let kernel_key = Keypair::from_seed(&[36; 32]);
    let receipt_authority_digest =
        derive_channel_receipt_authority_digest(&kernel_key.public_key())?;
    let request_id = "request-1".to_owned();
    let operation_id = digest("operation-1");
    let service = ready_channel_service(&request_id)?;
    let reservation_body = ChannelReservationBodyV1 {
        schema: CHANNEL_RESERVATION_SCHEMA.to_owned(),
        reservation_id: derive_channel_reservation_id(
            &channel_id,
            &open_digest,
            &request_id,
            1,
            &prior_digest,
        )?,
        channel_id,
        open_digest,
        request_id,
        operation_id: operation_id.clone(),
        next_sequence: 1,
        prior_state_digest: prior_digest,
        service_binding_digest: service.digest()?,
        receipt_authority_digest,
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
    let reservation = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &reservation_body,
            trust.payer_id.clone(),
            trust.payer_key_epoch,
            &payer_key,
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
        channel_id: open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: prior.body().digest()?,
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
        channel_id: open.artifact().body.channel_id.clone(),
        open_digest: open.artifact().digest()?,
        escrow_reference: open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: 2,
        lifecycle_fence: available.lifecycle_fence,
        pending_close_body_digest: None,
    };
    let available_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &available,
        &available_escrow,
        1_500,
    )?;
    let admitted_open = verify_admitted_channel_open(&open, &available_view)?;
    let mut alternate_body = reservation.body.clone();
    alternate_body.request_id = "request-2".to_owned();
    alternate_body.operation_id = digest("operation-2");
    let alternate_service = ready_channel_service(&alternate_body.request_id)?;
    alternate_body.service_binding_digest = alternate_service.digest()?;
    alternate_body.reservation_id = derive_channel_reservation_id(
        &alternate_body.channel_id,
        &alternate_body.open_digest,
        &alternate_body.request_id,
        alternate_body.next_sequence,
        &alternate_body.prior_state_digest,
    )?;
    let alternate = SignedChannelReservationV1 {
        payer_signature: ChannelSignatureV1::sign(
            &alternate_body,
            trust.payer_id.clone(),
            trust.payer_key_epoch,
            &payer_key,
        )?,
        authority_signature: ChannelSignatureV1::sign(
            &alternate_body,
            authority.authority_id.clone(),
            authority.authority_key_epoch,
            &authority_key,
        )?,
        body: alternate_body,
    };
    let alternate =
        verify_channel_reservation_proposal(&alternate, &admitted_open, prior, &authority, &trust)?;
    let reservation = verify_channel_reservation_proposal(
        &reservation,
        &admitted_open,
        prior,
        &authority,
        &trust,
    )?;
    let prepared_artifact = prepare_channel_reservation(
        &admitted_open,
        prior,
        &available_view,
        reservation.artifact().body.clone(),
        service,
    )?;
    let prepared = verify_channel_prepared_reservation(
        &prepared_artifact,
        &admitted_open,
        prior,
        &available_view,
        &reservation.artifact().body,
        &prepared_artifact.service,
    )?;
    let alternate_prepared_artifact = prepare_channel_reservation(
        &admitted_open,
        prior,
        &available_view,
        alternate.artifact().body.clone(),
        alternate_service,
    )?;
    let alternate_prepared = verify_channel_prepared_reservation(
        &alternate_prepared_artifact,
        &admitted_open,
        prior,
        &available_view,
        &alternate.artifact().body,
        &alternate_prepared_artifact.service,
    )?;
    assert!(verify_admitted_channel_reservation(&reservation, &prepared, &available_view).is_err());
    let reserved = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: prior.body().digest()?,
        latest_sequence: prior.body().seq,
        state_version: 2,
        lifecycle_fence: 3,
        pending_close_body_digest: None,
        admitted_dispute_digest: None,
        live_reservation_id: Some(reservation.artifact().body.reservation_id.clone()),
        operation_id: Some(operation_id.clone()),
    };
    let reserved_escrow = ChannelEscrowReservationViewV1 {
        version: 3,
        lifecycle_fence: reserved.lifecycle_fence,
        ..available_escrow.clone()
    };
    let mut wrong_reserved_escrow = reserved_escrow.clone();
    wrong_reserved_escrow.escrow_reference.escrow_id = evm_hash("wrong-reserved-escrow");
    let wrong_reserved_view_without_effect = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &reserved,
        &wrong_reserved_escrow,
        ChannelViewClocks::at(1_500),
        Vec::new(),
        &digest("wrong-reserved-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let wrong_channel_head = wrong_reserved_view_without_effect
        .view()
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == CHANNEL_LIFECYCLE_RESOURCE_FAMILY)
        .ok_or(ChannelError::AuthorityVerification)?;
    let (wrong_ready_effect, wrong_ready_head) = ready_channel_effect(
        &reservation,
        &trust.settlement_authority_scope_id,
        &wrong_channel_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        1_500,
    )?;
    let wrong_reserved_view = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &reserved,
        &wrong_reserved_escrow,
        ChannelViewClocks::at(1_500),
        vec![wrong_ready_head],
        &digest("wrong-ready-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let wrong_reserved_view = retain_ready_request(&wrong_reserved_view, &wrong_ready_effect)?;
    assert!(
        verify_admitted_channel_reservation(&reservation, &prepared, &wrong_reserved_view).is_err()
    );
    let reserved_view_without_effect = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        Vec::new(),
        &digest("reserved-without-effect-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    assert!(verify_admitted_channel_reservation(
        &reservation,
        &prepared,
        &reserved_view_without_effect
    )
    .is_err());
    let reserved_channel_head = reserved_view_without_effect
        .view()
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == CHANNEL_LIFECYCLE_RESOURCE_FAMILY)
        .ok_or(ChannelError::AuthorityVerification)?;
    let (ready_effect, ready_head) = ready_channel_effect(
        &reservation,
        &trust.settlement_authority_scope_id,
        &reserved_channel_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        1_500,
    )?;
    let mut stale_ready_head = ready_head.clone();
    stale_ready_head.trusted_clock_high_water = 1_499;
    let stale_ready_view = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        vec![stale_ready_head],
        &digest("stale-ready-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let stale_ready_view = retain_ready_request(&stale_ready_view, &ready_effect)?;
    assert!(
        verify_admitted_channel_reservation(&reservation, &prepared, &stale_ready_view).is_err()
    );
    let reserved_view = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        vec![ready_head],
        &digest("ready-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let reserved_view = retain_ready_request(&reserved_view, &ready_effect)?;
    let reservation = verify_admitted_channel_reservation(&reservation, &prepared, &reserved_view)?;
    assert_eq!(
        reservation.snapshot().checkpoint_digest(),
        reserved_view.view().checkpoint_digest
    );
    let mut alternate_reserved = reserved.clone();
    alternate_reserved.live_reservation_id = Some(alternate.artifact().body.reservation_id.clone());
    alternate_reserved.operation_id = Some(alternate.artifact().body.operation_id.clone());
    let alternate_reserved_view_without_effect = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &alternate_reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        Vec::new(),
        &digest("alternate-reserved-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let alternate_channel_head = alternate_reserved_view_without_effect
        .view()
        .heads
        .iter()
        .find(|head| head.resource_key.resource_family == CHANNEL_LIFECYCLE_RESOURCE_FAMILY)
        .ok_or(ChannelError::AuthorityVerification)?;
    let (alternate_ready_effect, alternate_ready_head) = ready_channel_effect(
        &alternate,
        &trust.settlement_authority_scope_id,
        &alternate_channel_head
            .digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        1_500,
    )?;
    let alternate_reserved_view = anchored_channel_view_with_heads(
        &trust.settlement_authority_scope_id,
        &alternate_reserved,
        &reserved_escrow,
        ChannelViewClocks::at(1_500),
        vec![alternate_ready_head],
        &digest("alternate-ready-checkpoint"),
        Some(admitted_open.snapshot()),
    )?;
    let alternate_reserved_view =
        retain_ready_request(&alternate_reserved_view, &alternate_ready_effect)?;
    let alternate = verify_admitted_channel_reservation(
        &alternate,
        &alternate_prepared,
        &alternate_reserved_view,
    )?;

    let actual_charge = MonetaryAmount {
        units: 25,
        currency: "USD".to_owned(),
    };
    let channel_metadata = ChannelReceiptMetadataV1 {
        schema: CHIO_CHANNEL_RECEIPT_METADATA_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        open_digest: open.artifact().digest()?,
        reservation_id: reservation.artifact().body.reservation_id.clone(),
        reservation_digest: reservation.artifact().digest()?,
        sequence: reservation.artifact().body.next_sequence,
        settlement_mode: ChannelSettlementModeV1::Channelized,
    };
    assert!(channel_metadata.is_valid());
    let mut invalid_channel_metadata = channel_metadata.clone();
    invalid_channel_metadata.sequence = 0;
    assert!(!invalid_channel_metadata.is_valid());
    let sign_receipt =
        |id: &str, decision: Decision, cost_charged: u64, settlement_status: SettlementStatus| {
            let financial = FinancialReceiptMetadata {
                grant_index: 0,
                cost_charged,
                currency: actual_charge.currency.clone(),
                budget_remaining: 150_u64
                    .checked_sub(cost_charged)
                    .ok_or(ChannelError::ArithmeticOverflow)?,
                budget_total: 150,
                delegation_depth: 0,
                root_budget_holder: trust.payer_id.clone(),
                payment_reference: None,
                settlement_status,
                cost_breakdown: None,
                oracle_evidence: None,
                attempted_cost: None,
            };
            let action = ToolCallAction::from_parameters(serde_json::json!({"value": 1}))
                .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
            ChioReceipt::sign(
                ChioReceiptBody {
                    id: id.to_owned(),
                    timestamp: 1,
                    capability_id: "capability-1".to_owned(),
                    tool_server: "server-1".to_owned(),
                    tool_name: "tool-1".to_owned(),
                    action,
                    decision: Some(decision),
                    receipt_kind: ReceiptKind::MediatedDecision,
                    boundary_class: BoundaryClass::Prevent,
                    observation_outcome: None,
                    tool_origin: ToolOrigin::CallerExecuted,
                    redaction_mode: RedactionMode::None,
                    actor_chain: Vec::new(),
                    content_hash: digest("channel-receipt-content"),
                    policy_hash: digest("channel-receipt-policy"),
                    evidence: Vec::new(),
                    metadata: Some(serde_json::json!({
                        "channel": channel_metadata,
                        "financial": financial,
                    })),
                    trust_level: TrustLevel::Mediated,
                    tenant_id: None,
                    kernel_key: kernel_key.public_key(),
                    bbs_projection_version: None,
                },
                &kernel_key,
            )
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))
        };
    let obligation_for = |receipt: &ChioReceipt, amount: MonetaryAmount| {
        let receipt_digest = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(receipt)
                .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
        );
        ObligationAtomV1::new(ObligationAtomInputV1 {
            economic_intent_digest: reservation.artifact().body.proposal_digest()?,
            source_receipt_id: receipt.id.clone(),
            source_receipt_digest: receipt_digest,
            debtor_id: open.intent().body.payer_id.clone(),
            original_creditor_id: open.intent().body.payee_id.clone(),
            original_settlement_destination_ref: open
                .intent()
                .body
                .payee_beneficiary_address
                .clone(),
            payee_binding_digest: derive_channel_payee_binding_digest(
                &open.intent().body.payee_id,
                &open.intent().body.payee_beneficiary_address,
            )?,
            amount,
            credit_election: ObligationCreditElectionV1::NotCredit,
            pre_action_authority_digest: reservation.artifact().digest()?,
            created_at_unix_ms: 1_500,
            due_at_unix_ms: 2_000,
        })
        .map_err(|_| ChannelError::AuthorityVerification)
    };
    let receipt = sign_receipt(
        "channel-receipt-nonce",
        Decision::Allow,
        actual_charge.units,
        SettlementStatus::Pending,
    )?;
    let obligation = obligation_for(&receipt, actual_charge.clone())?;
    assert!(verify_channel_receipt_binding(
        &receipt,
        &kernel_key.public_key(),
        &reservation,
        &open,
        None,
    )
    .is_err());

    let denied_zero = sign_receipt(
        "channel-denied-zero",
        Decision::Deny {
            reason: "denied".to_owned(),
            guard: "G".to_owned(),
        },
        0,
        SettlementStatus::NotApplicable,
    )?;
    let denied_zero = verify_channel_receipt_binding(
        &denied_zero,
        &kernel_key.public_key(),
        &reservation,
        &open,
        None,
    )?;
    let denied_state = build_channel_state_transition(prior, &reservation, &denied_zero, &open)?;
    assert_eq!(denied_state.seq, 1);
    assert_eq!(denied_state.cumulative_owed.units, 0);
    assert_eq!(denied_state.receipt_count, 1);

    let allowed_zero = sign_receipt(
        "channel-allowed-zero",
        Decision::Allow,
        0,
        SettlementStatus::NotApplicable,
    )?;
    assert!(verify_channel_receipt_binding(
        &allowed_zero,
        &kernel_key.public_key(),
        &reservation,
        &open,
        None,
    )
    .is_ok());

    for decision in [
        Decision::Allow,
        Decision::Deny {
            reason: "denied".to_owned(),
            guard: "G".to_owned(),
        },
    ] {
        let wrong_status = sign_receipt(
            "channel-zero-pending",
            decision,
            0,
            SettlementStatus::Pending,
        )?;
        assert!(verify_channel_receipt_binding(
            &wrong_status,
            &kernel_key.public_key(),
            &reservation,
            &open,
            None,
        )
        .is_err());
    }

    for decision in [
        Decision::Cancelled {
            reason: "cancelled".to_owned(),
        },
        Decision::Incomplete {
            reason: "incomplete".to_owned(),
        },
    ] {
        let nonterminal = sign_receipt(
            "channel-nonterminal-zero",
            decision,
            0,
            SettlementStatus::NotApplicable,
        )?;
        assert!(verify_channel_receipt_binding(
            &nonterminal,
            &kernel_key.public_key(),
            &reservation,
            &open,
            None,
        )
        .is_err());
    }

    let wrong_positive_status = sign_receipt(
        "channel-positive-not-applicable",
        Decision::Allow,
        actual_charge.units,
        SettlementStatus::NotApplicable,
    )?;
    let wrong_positive_obligation = obligation_for(&wrong_positive_status, actual_charge.clone())?;
    assert!(verify_channel_receipt_binding(
        &wrong_positive_status,
        &kernel_key.public_key(),
        &reservation,
        &open,
        Some(&wrong_positive_obligation),
    )
    .is_err());
    assert!(verify_channel_receipt_binding(
        &allowed_zero,
        &kernel_key.public_key(),
        &reservation,
        &open,
        Some(&obligation),
    )
    .is_err());
    let alternate_open = verified_channel_fixture_with_intent("alternate-transition-open-intent")?;
    assert!(verify_channel_receipt_binding(
        &receipt,
        &kernel_key.public_key(),
        &reservation,
        &alternate_open.open,
        Some(&obligation),
    )
    .is_err());
    let receipt = verify_channel_receipt_binding(
        &receipt,
        &kernel_key.public_key(),
        &reservation,
        &open,
        Some(&obligation),
    )?;
    assert!(build_channel_state_transition(prior, &alternate, &receipt, &open).is_err());
    let state_body = build_channel_state_transition(prior, &reservation, &receipt, &open)?;
    let state = SignedChannelStateV1 {
        payee_signature: ChannelSignatureV1::sign(
            &state_body,
            trust.payee_id.clone(),
            trust.payee_key_epoch,
            &payee_key,
        )?,
        body: state_body,
    };
    let mut substituted_signature = state.clone();
    substituted_signature.payee_signature = ChannelSignatureV1::sign(
        &substituted_signature.body,
        "other-payee".to_owned(),
        trust.payee_key_epoch,
        &Keypair::from_seed(&[35; 32]),
    )?;
    assert_ne!(state.digest()?, substituted_signature.digest()?);
    let verified_state =
        verify_channel_state_transition(&state, prior, &reservation, &receipt, &open, &trust)?;
    let mut substituted_state_trust = trust.clone();
    substituted_state_trust.participant_snapshot_digest = digest("other-participants");
    assert!(verify_channel_state_transition(
        &state,
        prior,
        &reservation,
        &receipt,
        &open,
        &substituted_state_trust,
    )
    .is_err());
    let serialized = serde_json::to_value(&state)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    assert!(serialized.get("payerSignature").is_none());
    assert!(serialized.get("payeeSignature").is_some());

    let mut unsafe_cumulative = state.clone();
    unsafe_cumulative.body.cumulative_owed.units = super::validation::I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(unsafe_cumulative.body.validate().is_err());

    let mut excessive = state.clone();
    excessive.body.actual_charge = Some(MonetaryAmount {
        units: 41,
        currency: "USD".to_owned(),
    });
    excessive.payee_signature = ChannelSignatureV1::sign(
        &excessive.body,
        trust.payee_id.clone(),
        trust.payee_key_epoch,
        &payee_key,
    )?;
    assert!(verify_channel_state_transition(
        &excessive,
        prior,
        &reservation,
        &receipt,
        &open,
        &trust,
    )
    .is_err());

    let attacker_key = Keypair::from_seed(&[34; 32]);
    let mut wrong_payee = state;
    wrong_payee.payee_signature =
        ChannelSignatureV1::sign(&wrong_payee.body, "payee".to_owned(), 3, &attacker_key)?;
    assert!(verify_channel_state_transition(
        &wrong_payee,
        prior,
        &reservation,
        &receipt,
        &open,
        &trust,
    )
    .is_err());

    let stale_close_body = build_channel_close_body(
        ChannelCloseKindV1::Contested,
        &open,
        prior,
        admitted_open.snapshot(),
        1_500,
    )?;
    let stale_close = SignedChannelCloseV1 {
        payee_signature: ChannelSignatureV1::sign(
            &stale_close_body,
            trust.payee_id.clone(),
            trust.payee_key_epoch,
            &payee_key,
        )?,
        payer_signature: None,
        body: stale_close_body,
    };
    let stale_close_body_digest = stale_close.body.digest()?;
    let close_pending = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: stale_close.body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::ClosePending,
        latest_state_digest: stale_close.body.final_state_digest.clone(),
        latest_sequence: stale_close.body.final_state_sequence,
        state_version: stale_close.body.channel_state_version,
        lifecycle_fence: stale_close.body.lifecycle_fence,
        pending_close_body_digest: Some(stale_close_body_digest.clone()),
        admitted_dispute_digest: None,
        live_reservation_id: None,
        operation_id: None,
    };
    let escrow_pending = ChannelEscrowReservationViewV1 {
        schema: CHANNEL_ESCROW_RESERVATION_SCHEMA.to_owned(),
        channel_id: stale_close.body.channel_id.clone(),
        open_digest: stale_close.body.open_digest.clone(),
        escrow_reference: open.intent().body.escrow_reference.clone(),
        status: ChannelEscrowReservationStatusV1::Open,
        version: stale_close.body.escrow_reservation_version,
        lifecycle_fence: stale_close.body.lifecycle_fence,
        pending_close_body_digest: Some(stale_close_body_digest),
    };
    let close_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &close_pending,
        &escrow_pending,
        1_500,
    )?;
    let close_snapshot = verify_channel_lifecycle_snapshot(
        &close_view,
        &trust.settlement_authority_scope_id,
        &close_pending.channel_id,
    )?;
    let stale_close = verify_channel_close(&stale_close, &open, prior, &close_snapshot, &trust)?;
    let stale_effective = verify_effective_channel_close(&stale_close)?;
    let chain = build_channel_state_chain(prior, std::slice::from_ref(&verified_state))?;
    let dispute_body = build_channel_dispute_body(
        &stale_close,
        &chain,
        "newer contiguous admitted state".to_owned(),
        1_550,
    )?;
    let submitter = ChannelDisputeSubmitterV1 {
        submitter_id: trust.payer_id.clone(),
        submitter_key_epoch: trust.payer_key_epoch,
        submitter_key: trust.payer_key.clone(),
        trusted_time_unix_ms: 1_600,
    };
    let signed_dispute = SignedChannelDisputeV1 {
        submitter_signature: ChannelSignatureV1::sign(
            &dispute_body,
            submitter.submitter_id.clone(),
            submitter.submitter_key_epoch,
            &payer_key,
        )?,
        body: dispute_body,
    };
    let dispute = verify_channel_dispute(&signed_dispute, &stale_close, &chain, &submitter)?;
    let admitted_dispute_digest = dispute.artifact().digest()?;
    let disputed_lifecycle = ChannelLifecycleViewV1 {
        latest_state_digest: verified_state.digest()?,
        latest_sequence: verified_state.body().seq,
        state_version: close_pending.state_version + 1,
        lifecycle_fence: close_pending.lifecycle_fence + 1,
        admitted_dispute_digest: Some(admitted_dispute_digest.clone()),
        ..close_pending.clone()
    };
    let disputed_escrow = ChannelEscrowReservationViewV1 {
        version: escrow_pending.version + 1,
        lifecycle_fence: escrow_pending.lifecycle_fence + 1,
        ..escrow_pending.clone()
    };
    let disputed_view = anchored_channel_view(
        &trust.settlement_authority_scope_id,
        &disputed_lifecycle,
        &disputed_escrow,
        1_600,
    )?;
    let disputed_snapshot = verify_channel_lifecycle_snapshot(
        &disputed_view,
        &trust.settlement_authority_scope_id,
        &disputed_lifecycle.channel_id,
    )?;
    let linked_disputed_view = anchored_channel_successor_view(
        &trust.settlement_authority_scope_id,
        &disputed_lifecycle,
        &disputed_escrow,
        1_600,
        stale_effective.snapshot(),
    )?;
    let linked_disputed_snapshot = verify_channel_lifecycle_snapshot(
        &linked_disputed_view,
        &trust.settlement_authority_scope_id,
        &disputed_lifecycle.channel_id,
    )?;
    let mut substituted_dispute = dispute.artifact().clone();
    substituted_dispute.body.reason = "substituted dispute".to_owned();
    substituted_dispute.submitter_signature = ChannelSignatureV1::sign(
        &substituted_dispute.body,
        submitter.submitter_id.clone(),
        submitter.submitter_key_epoch,
        &payer_key,
    )?;
    let substituted_dispute =
        verify_channel_dispute(&substituted_dispute, &stale_close, &chain, &submitter)?;
    assert!(verify_effective_channel_dispute_advance(
        &stale_effective,
        &substituted_dispute,
        &linked_disputed_snapshot,
    )
    .is_err());
    assert!(verify_effective_channel_dispute_advance(
        &stale_effective,
        &dispute,
        &disputed_snapshot,
    )
    .is_err());
    for (state_version_delta, escrow_version_delta, fence_delta) in
        [(1_u64, 0_u64, 0_u64), (0, 1, 0), (0, 0, 1)]
    {
        let mut skipped_lifecycle = disputed_lifecycle.clone();
        skipped_lifecycle.state_version += state_version_delta;
        skipped_lifecycle.lifecycle_fence += fence_delta;
        let mut skipped_escrow = disputed_escrow.clone();
        skipped_escrow.version += escrow_version_delta;
        skipped_escrow.lifecycle_fence += fence_delta;
        let skipped_view = anchored_channel_successor_view(
            &trust.settlement_authority_scope_id,
            &skipped_lifecycle,
            &skipped_escrow,
            1_600,
            stale_effective.snapshot(),
        )?;
        let skipped_snapshot = verify_channel_lifecycle_snapshot(
            &skipped_view,
            &trust.settlement_authority_scope_id,
            &skipped_lifecycle.channel_id,
        )?;
        assert!(verify_effective_channel_dispute_advance(
            &stale_effective,
            &dispute,
            &skipped_snapshot,
        )
        .is_err());
    }
    let disputed_effective = verify_effective_channel_dispute_advance(
        &stale_effective,
        &dispute,
        &linked_disputed_snapshot,
    )?;
    assert_eq!(
        disputed_effective.effective_state().digest()?,
        verified_state.digest()?
    );
    assert_eq!(
        disputed_effective.admitted_dispute_digest(),
        Some(admitted_dispute_digest.as_str())
    );
    let stale_action = channel_close_frost_action(&stale_effective, 4)?;
    let disputed_action = channel_close_frost_action(&disputed_effective, 4)?;
    assert_eq!(
        disputed_action.domain(),
        chio_core::federation::frost::FrostAuthorizationDomain::ChannelClose
    );
    assert_ne!(
        stale_action
            .action_digest()
            .map_err(|_| ChannelError::AuthorityVerification)?,
        disputed_action
            .action_digest()
            .map_err(|_| ChannelError::AuthorityVerification)?
    );
    let chio_core::federation::frost::FrostActionPreimageV1::ChannelClose(disputed_action) =
        disputed_action
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    assert_eq!(disputed_action.final_state_digest, verified_state.digest()?);
    assert_eq!(
        disputed_action.final_cumulative_owed,
        verified_state.body().cumulative_owed
    );
    let mut deadline_submitter = submitter.clone();
    deadline_submitter.trusted_time_unix_ms = stale_close.artifact().body.dispute_deadline_unix_ms;
    assert!(
        verify_channel_dispute(&signed_dispute, &stale_close, &chain, &deadline_submitter).is_err()
    );

    let mut equal_sequence = signed_dispute;
    equal_sequence.body.competing_state_sequence = equal_sequence.body.close_state_sequence;
    equal_sequence.submitter_signature = ChannelSignatureV1::sign(
        &equal_sequence.body,
        submitter.submitter_id.clone(),
        submitter.submitter_key_epoch,
        &payer_key,
    )?;
    assert!(verify_channel_dispute(&equal_sequence, &stale_close, &chain, &submitter).is_err());
    Ok(())
}

#[test]
fn channel_signatures_bind_identity_metadata_and_evm_keys_are_canonical() -> Result<(), ChannelError>
{
    let key = Keypair::from_seed(&[41; 32]);
    let body = ChannelOpenBodyV1 {
        schema: CHANNEL_OPEN_SCHEMA.to_owned(),
        channel_id: digest("metadata-channel"),
        open_intent_digest: digest("metadata-intent"),
        funding_acknowledgement_digest: digest("metadata-ack"),
        initial_state_digest: digest("metadata-state"),
        opened_at_unix_ms: 1,
    };
    let mut signature = ChannelSignatureV1::sign(&body, "payer".to_owned(), 1, &key)?;
    signature.signer_id = "payee".to_owned();
    assert!(signature
        .verify(&body, "payee", 1, &key.public_key())
        .is_err());
    let mut epoch = ChannelSignatureV1::sign(&body, "payer".to_owned(), 1, &key)?;
    epoch.key_epoch = 2;
    assert!(epoch.verify(&body, "payer", 2, &key.public_key()).is_err());

    let mut funding = funding_body();
    funding.escrow_reference.escrow_contract =
        "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned();
    assert!(funding.validate().is_err());
    let mut numeric_chain = asset_binding(2, 6);
    numeric_chain.chain_id = "31337".to_owned();
    assert!(numeric_chain.validate().is_err());
    Ok(())
}

#[test]
fn channel_id_matches_the_protocol_preimage() -> Result<(), ChannelError> {
    let intent = "00".repeat(32);
    let acknowledgement = "11".repeat(32);
    assert_eq!(
        derive_channel_id(&intent, &acknowledgement)?,
        "64d70d0cfeda8954e6a70ab1eb97a2e488142682afde96f1334f372eb7b0c83d"
    );
    Ok(())
}

#[test]
fn channel_snapshot_rejects_resource_clocks_ahead_of_signed_view() -> Result<(), ChannelError> {
    let fixture = verified_channel_fixture()?;
    let open = fixture.open;
    let lifecycle = ChannelLifecycleViewV1 {
        schema: CHANNEL_LIFECYCLE_SCHEMA.to_owned(),
        channel_id: open.artifact().body.channel_id.clone(),
        status: ChannelLifecycleStatusV1::Open,
        latest_state_digest: open.initial_state().digest()?,
        latest_sequence: 0,
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
    for (channel_clock, escrow_clock) in [(1_501, 1_500), (1_500, 1_501)] {
        let view = anchored_channel_view_with_clocks(
            &fixture.trust.settlement_authority_scope_id,
            &lifecycle,
            &escrow,
            channel_clock,
            escrow_clock,
            1_500,
        )?;
        assert!(verify_channel_lifecycle_snapshot(
            &view,
            &fixture.trust.settlement_authority_scope_id,
            &lifecycle.channel_id,
        )
        .is_err());
    }
    Ok(())
}
