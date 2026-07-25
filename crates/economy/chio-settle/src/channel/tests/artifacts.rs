use super::*;

#[test]
fn channel_asset_conversion_is_exact_and_round_trippable() -> Result<(), SettlementError> {
    let binding = asset_binding(2, 6);
    let amount = MonetaryAmount {
        units: 150,
        currency: "USD".to_owned(),
    };
    let base_units = binding
        .token_base_units(&amount)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    assert_eq!(base_units, "1500000");
    binding
        .verify_round_trip(&amount, &base_units)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    assert_eq!(
        binding
            .monetary_amount(&base_units)
            .map_err(|error| SettlementError::Verification(error.to_string()))?,
        amount
    );
    Ok(())
}

#[test]
fn channel_asset_conversion_rejects_drift_and_noncanonical_units() {
    let binding = asset_binding(6, 2);
    let unrepresentable = MonetaryAmount {
        units: 1,
        currency: "USD".to_owned(),
    };
    assert_eq!(
        binding.token_base_units(&unrepresentable),
        Err(ChannelError::InexactAmount)
    );
    assert!(binding.monetary_amount("01").is_err());
    assert!(binding
        .token_base_units(&MonetaryAmount {
            units: 100,
            currency: "EUR".to_owned(),
        })
        .is_err());
    assert!(binding
        .token_base_units(&MonetaryAmount {
            units: super::validation::I_JSON_MAX_SAFE_INTEGER + 1,
            currency: "USD".to_owned(),
        })
        .is_err());
}

#[test]
fn funding_evidence_binds_terms_event_operator_asset_and_finality() -> Result<(), ChannelError> {
    let authority_key = Keypair::from_seed(&[11; 32]);
    let body = funding_body();
    let evidence = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &body,
            "funding-authority".to_owned(),
            4,
            &authority_key,
        )?,
        body,
    };
    let trust = funding_authority(&authority_key, 1_500, &evidence.body);
    verify_channel_funding_evidence(&evidence, &trust)?;

    let mut mismatched = evidence.clone();
    mismatched.body.creation_event.beneficiary =
        "0x7777777777777777777777777777777777777777".to_owned();
    assert!(verify_channel_funding_evidence(&mismatched, &trust).is_err());

    let mut stale = trust.clone();
    stale.trusted_time_unix_ms = 1_901;
    assert!(verify_channel_funding_evidence(&evidence, &stale).is_err());

    let mut exact_expiry = stale.clone();
    exact_expiry.trusted_time_unix_ms = 1_900;
    assert!(verify_channel_funding_evidence(&evidence, &exact_expiry).is_err());

    let mut wrong_contract_body = evidence.body.clone();
    wrong_contract_body.creation_event.transaction_to =
        "0x7777777777777777777777777777777777777777".to_owned();
    let wrong_contract = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &wrong_contract_body,
            trust.authority_id.clone(),
            trust.authority_key_epoch,
            &authority_key,
        )?,
        body: wrong_contract_body,
    };
    assert!(verify_channel_funding_evidence(&wrong_contract, &trust).is_err());

    let mut fabricated_finality_body = evidence.body.clone();
    fabricated_finality_body.block_pin.observed_confirmations = 13;
    let fabricated_finality = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &fabricated_finality_body,
            trust.authority_id.clone(),
            trust.authority_key_epoch,
            &authority_key,
        )?,
        body: fabricated_finality_body,
    };
    assert!(verify_channel_funding_evidence(&fabricated_finality, &trust).is_err());

    let mut relabeled_asset_body = evidence.body.clone();
    relabeled_asset_body.asset_binding.currency = "EUR".to_owned();
    let relabeled_asset = SignedChannelFundingEvidenceV1 {
        authority_signature: ChannelSignatureV1::sign(
            &relabeled_asset_body,
            trust.authority_id.clone(),
            trust.authority_key_epoch,
            &authority_key,
        )?,
        body: relabeled_asset_body,
    };
    assert!(verify_channel_funding_evidence(&relabeled_asset, &trust).is_err());

    let mut unsafe_log_index = evidence.body.clone();
    unsafe_log_index.creation_event.log_index = super::validation::I_JSON_MAX_SAFE_INTEGER + 1;
    assert!(unsafe_log_index.validate().is_err());

    let mut incomplete_refund = evidence.body.escrow_state.clone();
    incomplete_refund.refunded = true;
    assert!(incomplete_refund.validate().is_err());
    Ok(())
}

#[test]
fn open_digest_graph_binds_funding_and_immutable_bound_timing() -> Result<(), ChannelError> {
    use chio_core::web3::trust_profile::Web3FinalityMode;

    let payer_key = Keypair::from_seed(&[21; 32]);
    let payee_key = Keypair::from_seed(&[22; 32]);
    let authority_key = Keypair::from_seed(&[23; 32]);
    let policy = ChannelDisputePolicyV1 {
        schema: CHANNEL_DISPUTE_POLICY_SCHEMA.to_owned(),
        policy_id: "channel-policy".to_owned(),
        fixed_finality_broadcast_margin_secs: 50,
        tiers: vec![
            ChannelDisputeTierV1 {
                upper_bound_units: 1_000,
                dispute_window_secs: 100,
                required_confirmations: 12,
                finality_mode: Web3FinalityMode::L1Finalized,
            },
            ChannelDisputeTierV1 {
                upper_bound_units: super::validation::I_JSON_MAX_SAFE_INTEGER,
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
            &authority_key,
        )?,
        body: funding_body,
    };
    let authority = funding_authority(&authority_key, 1_700, &funding.body);
    let trust = ChannelOpenTrustV1 {
        payer_id: "payer".to_owned(),
        payer_key: payer_key.public_key(),
        payer_key_epoch: 2,
        payee_id: "payee".to_owned(),
        payee_key: payee_key.public_key(),
        payee_key_epoch: 3,
        settlement_authority_scope_id: "channel-settlement".to_owned(),
        original_web3_dispatch_digest: digest("web3-dispatch"),
        participant_snapshot_digest: digest("participant-snapshot"),
        trusted_time_unix_ms: 1_700,
    };
    let intent_body = ChannelOpenIntentBodyV1 {
        schema: CHANNEL_OPEN_INTENT_SCHEMA.to_owned(),
        open_intent_id: digest("open-intent"),
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
        bound_token_base_units: "1500000".to_owned(),
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
        prior_head_digest: digest("unreserved-head"),
        new_state: ChannelEscrowReservationStateV1::Opening,
        new_version: 2,
        anchored_head_digest: digest("opening-head"),
        reserved_at_unix_ms: 1_600,
        expires_at_unix_ms: 1_800,
    };
    let acknowledgement = SignedChannelFundingAcknowledgementV1 {
        authority_signature: ChannelSignatureV1::sign(
            &acknowledgement_body,
            authority.authority_id.clone(),
            authority.authority_key_epoch,
            &authority_key,
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
        opened_at_unix_ms: 1_700,
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
    let verified_open = verify_channel_open_consent(
        &open,
        &verified_intent,
        &acknowledgement,
        &authority,
        &trust,
    )?;
    assert_eq!(verified_open.initial_state().body(), &initial_state);

    let mut substituted_authority = authority.clone();
    substituted_authority.token_symbol = "USDT".to_owned();
    assert!(verify_channel_open_consent(
        &open,
        &verified_intent,
        &acknowledgement,
        &substituted_authority,
        &trust,
    )
    .is_err());

    let mut substituted_trust = trust.clone();
    substituted_trust.original_web3_dispatch_digest = digest("other-web3-dispatch");
    assert!(verify_channel_open_consent(
        &open,
        &verified_intent,
        &acknowledgement,
        &authority,
        &substituted_trust,
    )
    .is_err());

    let mut expired_authority = authority.clone();
    expired_authority.trusted_time_unix_ms = acknowledgement.body.expires_at_unix_ms;
    let mut expired_trust = trust.clone();
    expired_trust.trusted_time_unix_ms = acknowledgement.body.expires_at_unix_ms;
    assert!(verify_channel_open_consent(
        &open,
        &verified_intent,
        &acknowledgement,
        &expired_authority,
        &expired_trust,
    )
    .is_err());

    let mut regressing_policy = policy.clone();
    regressing_policy.tiers[1].dispute_window_secs = 50;
    assert!(regressing_policy.validate().is_err());

    let mut mutable_tier = intent.clone();
    mutable_tier.body.dispute_window_secs = 200;
    mutable_tier.payer_signature = ChannelSignatureV1::sign(
        &mutable_tier.body,
        trust.payer_id.clone(),
        trust.payer_key_epoch,
        &payer_key,
    )?;
    mutable_tier.payee_signature = ChannelSignatureV1::sign(
        &mutable_tier.body,
        trust.payee_id.clone(),
        trust.payee_key_epoch,
        &payee_key,
    )?;
    assert!(
        verify_channel_open_intent(&mutable_tier, &funding, &authority, &policy, &trust).is_err()
    );
    Ok(())
}
