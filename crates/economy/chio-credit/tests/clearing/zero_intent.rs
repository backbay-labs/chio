use super::*;

#[test]
fn zero_intent_round_requires_typed_reconciliation_before_satisfaction() -> TestResult {
    let participant_authority = Keypair::from_seed(&[31; 32]);
    let obligation_authority = Keypair::from_seed(&[32; 32]);
    let request = signed_request(
        vec![
            reserved_obligation(1, "A", "B", "USD", 100)?,
            reserved_obligation(2, "B", "A", "USD", 100)?,
        ],
        &participant_authority,
        &obligation_authority,
    )?;
    let mut authority_trust = trust(&participant_authority, &obligation_authority);
    let output = compute_netting_round(&request, &authority_trust)?;
    assert!(output.intents.is_empty());
    assert_eq!(output.output_manifest.settlement_intent_count, 0);
    let signed_output =
        sign_netting_round(&request, &output, &authority_trust, &participant_authority)?;
    let reserved = ClearingRoundLifecycleRecordV1::reserved(&output.core)?;
    let reserved_head = clearing_head(&reserved)?;
    let anchored = anchored_obligations(&request.obligations, &output.core.governance_scope_id)?;
    let proposed = compose_clearing_lifecycle_transition(
        &reserved_head,
        &anchored,
        ClearingRoundTransitionV1::Propose {
            output_manifest_digest: output.output_manifest.digest()?,
            authority_digest: signed_output.output_manifest.digest()?,
        },
        501,
    )?;
    let proposed_heads = proposed
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let proposed_head = proposed_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("proposal omitted the round head")?;
    let proposed_obligations = advance_anchored_obligations(&request.obligations, &proposed_heads)?;
    let finalizing = compose_clearing_lifecycle_transition(
        proposed_head,
        &proposed_obligations,
        ClearingRoundTransitionV1::BeginFinalization {
            acceptance_root: digest("zero-intent-acceptances"),
            acceptance_count: u64::try_from(output.participant_statements.len())?,
            authority_digest: digest("zero-intent-finalization-authority"),
        },
        502,
    )?;
    let finalizing_heads = finalizing
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let finalizing_head = finalizing_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("finalization omitted the round head")?;
    let finalizing_obligations =
        advance_anchored_obligations(&request.obligations, &finalizing_heads)?;
    let finalized = compose_clearing_lifecycle_transition(
        finalizing_head,
        &finalizing_obligations,
        ClearingRoundTransitionV1::Finalize {
            finalization_digest: digest("zero-intent-finalization"),
            frost: EconomicFrostBindingV1 {
                authorization_slot_id: digest("zero-intent-authorization-slot"),
                authorization_id: digest("zero-intent-authorization"),
                action_digest: digest("zero-intent-finalization-action"),
                signed_envelope_digest: digest("zero-intent-frost-envelope"),
            },
        },
        503,
    )?;
    let finalized_heads = finalized
        .transitions()
        .iter()
        .map(|transition| transition.next_head.clone())
        .collect::<Vec<_>>();
    let finalized_head = finalized_heads
        .iter()
        .find(|head| head.resource_key.resource_family == "clearing_round")
        .ok_or("finalized projection omitted the round head")?;
    let finalized_obligations =
        advance_anchored_obligations(&request.obligations, &finalized_heads)?;
    authority_trust.trusted_time_unix_ms = 504;
    let body = prepare_clearing_zero_intent_reconciliation(
        finalized_head,
        &finalized_obligations,
        &request,
        &signed_output,
        &authority_trust,
        digest("zero-intent-reconciliation-authority"),
        504,
    )?;
    let signed = SignedClearingZeroIntentReconciliationV1::sign(body, &obligation_authority)?;
    validate_schema("clearing-zero-intent-reconciliation.v1.json", &signed)?;
    let projection = compose_clearing_zero_intent_reconciliation_transition(
        finalized_head,
        &finalized_obligations,
        &request,
        &signed_output,
        &signed,
        &authority_trust,
    )?;
    assert_eq!(
        projection.transitions().len(),
        request.obligations.len() + 1
    );
    assert!(projection.transitions().iter().all(|transition| {
        transition.next_head.lifecycle_state == "satisfied"
            || transition.next_head.lifecycle_state == "clearing_satisfied"
    }));
    let replay = ClearingLifecycleReplayV1 {
        format: CLEARING_LIFECYCLE_REPLAY_FORMAT.to_owned(),
        proof: projection.proof().clone(),
        evidence: ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation {
            reconciliation: Box::new(ClearingZeroIntentReconciliationReplayV1 {
                request: request.clone(),
                signed_output: signed_output.clone(),
                signed_reconciliation: signed.clone(),
            }),
        },
    };
    let pins = lifecycle_pins(&authority_trust);
    assert_eq!(
        verify_clearing_lifecycle_replay_authority(finalized_head, &replay, &pins, None, None,)?,
        EconomicTransitionAuthorizationV1::Direct
    );
    let view = signed_anchor_view(finalized_heads.clone(), 504)?;
    let verified_view = verify_economic_state_view(view.clone(), &state_anchor_pins())?;
    let batch = signed_projection_batch(&projection, &view)?;
    let verifier = ClearingLifecycleReplayBatchVerifier::new(replay, pins, None, None)?;
    verify_economic_state_batch_advance(
        &verified_view,
        batch.clone(),
        &state_anchor_pins(),
        &verifier,
    )?;
    let mut substituted_clock = batch;
    substituted_clock.transitions[0]
        .next_head
        .trusted_clock_high_water += 1;
    substituted_clock.seal(&state_anchor_key())?;
    assert!(verify_economic_state_batch_advance(
        &verified_view,
        substituted_clock,
        &state_anchor_pins(),
        &verifier,
    )
    .is_err());
    let mut malformed = signed;
    malformed.body.empty_intent_root = digest("nonempty-intent-root");
    malformed =
        SignedClearingZeroIntentReconciliationV1::sign(malformed.body, &obligation_authority)?;
    assert!(compose_clearing_zero_intent_reconciliation_transition(
        finalized_head,
        &finalized_obligations,
        &request,
        &signed_output,
        &malformed,
        &authority_trust,
    )
    .is_err());
    Ok(())
}
