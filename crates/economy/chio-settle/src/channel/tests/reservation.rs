use super::*;

#[test]
fn prepared_reservation_round_trip_composes_the_exact_ready_batch() -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let body = fixture.proposal.artifact().body.clone();
    let service = channel_service_binding(&fixture);
    let prepared = prepare_channel_reservation(
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        body.clone(),
        service.clone(),
    )?;
    let canonical = chio_core::canonical::canonical_json_bytes(&prepared)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    let decoded: ChannelPreparedReservationV1 = serde_json::from_slice(&canonical)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    let verified = verify_channel_prepared_reservation(
        &decoded,
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        &body,
        &service,
    )?;
    let projection = compose_channel_reservation_transition(
        &verified,
        &fixture.proposal,
        fixture.proposal.accepted_at_unix_ms(),
    )?;
    assert_eq!(projection.transitions().len(), 3);
    let [ready] = projection.effect_slots() else {
        return Err(ChannelError::AuthorityVerification);
    };
    let [replay] = projection.request_replays() else {
        return Err(ChannelError::AuthorityVerification);
    };
    assert_eq!(ready.state, EconomicEffectStateV1::Ready);
    assert_eq!(ready.request, fixture.request);
    assert_eq!(ready.target, fixture.provider);
    assert_eq!(replay.request, ready.request);
    assert_eq!(replay.operation_id, body.operation_id);
    assert_eq!(replay.effect_slot_ids, vec![ready.slot_id.clone()]);
    let batch = signed_channel_projection_batch(
        &fixture.current,
        &projection,
        fixture.proposal.accepted_at_unix_ms(),
    )?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    verify_economic_state_batch_advance(&fixture.current, batch, &channel_anchor_pins(), &verifier)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(())
}

#[test]
fn prepared_reservation_rejects_replay_and_binding_substitution() -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let body = fixture.proposal.artifact().body.clone();
    let service = channel_service_binding(&fixture);
    let prepared = prepare_channel_reservation(
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        body.clone(),
        service.clone(),
    )?;
    let verified = verify_channel_prepared_reservation(
        &prepared,
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        &body,
        &service,
    )?;
    let projection = compose_channel_reservation_transition(
        &verified,
        &fixture.proposal,
        fixture.proposal.accepted_at_unix_ms(),
    )?;
    let mut batch = signed_channel_projection_batch(
        &fixture.current,
        &projection,
        fixture.proposal.accepted_at_unix_ms(),
    )?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    assert!(verifier
        .verify_transition(None, &batch.transitions[0])
        .is_err());
    batch.request_replays.clear();
    assert!(verifier.verify_batch(&fixture.current, &batch).is_err());

    let mut substituted_request = service.clone();
    substituted_request.request.request_binding_digest = digest("substituted-request-binding");
    assert!(verify_channel_prepared_reservation(
        &prepared,
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        &body,
        &substituted_request,
    )
    .is_err());
    let mut substituted_provider = service.clone();
    substituted_provider.provider.qualification_digest = digest("substituted-provider");
    assert!(verify_channel_prepared_reservation(
        &prepared,
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        &body,
        &substituted_provider,
    )
    .is_err());
    let mut substituted_body = body;
    substituted_body.receipt_authority_digest = digest("substituted-proposal");
    assert!(verify_channel_prepared_reservation(
        &prepared,
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        &substituted_body,
        &service,
    )
    .is_err());
    Ok(())
}

#[test]
fn prepared_reservation_digest_is_domain_separated_and_canonical() -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let prepared = prepare_channel_reservation(
        &fixture.open,
        &fixture.prior,
        &fixture.current,
        fixture.proposal.artifact().body.clone(),
        channel_service_binding(&fixture),
    )?;
    let prepared_digest = prepared.digest()?;
    assert_eq!(
        prepared_digest,
        super::validation::digest(b"chio.channel.prepared-reservation.digest.v1\0", &prepared,)?
    );
    let canonical = chio_core::canonical::canonical_json_bytes(&prepared)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    let decoded: ChannelPreparedReservationV1 = serde_json::from_slice(&canonical)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    assert_eq!(decoded.digest()?, prepared_digest);

    let mut changed_reservation = prepared.clone();
    changed_reservation.reservation.receipt_authority_digest =
        digest("changed-prepared-receipt-authority");
    assert_ne!(changed_reservation.digest()?, prepared_digest);
    let mut changed_request = prepared.clone();
    changed_request.service.request.request_binding_digest = digest("changed-prepared-request");
    assert_ne!(changed_request.digest()?, prepared_digest);
    let mut changed_provider = prepared.clone();
    changed_provider.service.provider.qualification_digest = digest("changed-prepared-provider");
    assert_ne!(changed_provider.digest()?, prepared_digest);
    let mut changed_checkpoint = prepared.clone();
    changed_checkpoint.checkpoint_digest = digest("changed-prepared-checkpoint");
    assert_ne!(changed_checkpoint.digest()?, prepared_digest);

    let mut wrong_schema = prepared;
    wrong_schema.schema = "chio.channel.prepared-reservation.v9".to_owned();
    assert!(wrong_schema.digest().is_err());
    Ok(())
}

#[test]
fn signed_reservation_binds_the_exact_service_and_proposal_intent() -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let service = channel_service_binding(&fixture);
    let service_digest = service.digest()?;
    assert_eq!(
        service_digest,
        super::validation::digest(b"chio.channel.service-binding.digest.v1\0", &service)?
    );
    assert_eq!(
        fixture.proposal.artifact().body.service_binding_digest,
        service_digest
    );
    let body_value = serde_json::to_value(&fixture.proposal.artifact().body)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    assert!(body_value.get("quoteDigest").is_none());
    assert_eq!(
        body_value
            .get("serviceBindingDigest")
            .and_then(serde_json::Value::as_str),
        Some(service_digest.as_str())
    );

    let terminal = terminal_advance_fixture()?;
    let obligation = terminal
        .obligation
        .as_ref()
        .ok_or(ChannelError::AuthorityVerification)?;
    assert_eq!(
        obligation.economic_intent_digest(),
        terminal.reservation.artifact().body.proposal_digest()?
    );
    Ok(())
}

#[test]
fn admitted_reservation_rejects_every_forged_ready_service_binding() -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let prepared = verified_prepared_reservation(&fixture)?;
    let admitted =
        verify_admitted_channel_reservation(&fixture.proposal, &prepared, &fixture.ready_view)?;
    assert_eq!(admitted.ready_effect().request, fixture.request);
    assert_eq!(admitted.ready_effect().target, fixture.provider);
    assert_eq!(admitted.ready_effect().action_digest, fixture.action_digest);
    let effect_key = admitted.ready_effect().resource_head_key();
    for mutation in [
        ReadyServiceMutation::RequestNamespace,
        ReadyServiceMutation::RequestId,
        ReadyServiceMutation::RequestBinding,
        ReadyServiceMutation::HandoffState,
        ReadyServiceMutation::HandoffVersion,
        ReadyServiceMutation::HandoffFence,
        ReadyServiceMutation::HandoffStoreUuid,
        ReadyServiceMutation::HandoffLeaseId,
        ReadyServiceMutation::HandoffOwnerEpoch,
        ReadyServiceMutation::TargetId,
        ReadyServiceMutation::TargetEpoch,
        ReadyServiceMutation::TargetQualification,
        ReadyServiceMutation::Action,
        ReadyServiceMutation::Parameters,
        ReadyServiceMutation::ResourceHead,
    ] {
        let forged = forged_ready_service_view(&fixture.ready_view, &effect_key, mutation)?;
        assert!(
            verify_admitted_channel_reservation(&fixture.proposal, &prepared, &forged).is_err()
        );
    }
    let reservation_projection = compose_channel_reservation_transition(
        &prepared,
        &fixture.proposal,
        fixture.proposal.accepted_at_unix_ms(),
    )?;
    assert_eq!(
        reservation_projection.not_after_unix_ms(),
        Some(fixture.proposal.artifact().body.expires_at_unix_ms)
    );
    Ok(())
}

#[test]
fn admitted_reservation_rejects_mixed_batch_clocks_and_skipped_successor_heads(
) -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let prepared = verified_prepared_reservation(&fixture)?;

    let mut mixed_clocks = fixture.ready_view.view().clone();
    mixed_clocks.observed_at = mixed_clocks
        .observed_at
        .checked_add(10)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let channel_head = mixed_clocks
        .heads
        .iter_mut()
        .find(|head| head.resource_key.resource_family == CHANNEL_LIFECYCLE_RESOURCE_FAMILY)
        .ok_or(ChannelError::AuthorityVerification)?;
    channel_head.trusted_clock_high_water = channel_head
        .trusted_clock_high_water
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mixed_clocks = verified_modified_view(mixed_clocks)?;
    assert!(
        verify_admitted_channel_reservation(&fixture.proposal, &prepared, &mixed_clocks).is_err()
    );

    for resource_family in [
        CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
        CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
    ] {
        let mut skipped_successor = fixture.ready_view.view().clone();
        let head = skipped_successor
            .heads
            .iter_mut()
            .find(|head| head.resource_key.resource_family == resource_family)
            .ok_or(ChannelError::AuthorityVerification)?;
        head.head_version = head
            .head_version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        let skipped_successor = verified_modified_view(skipped_successor)?;
        assert!(verify_admitted_channel_reservation(
            &fixture.proposal,
            &prepared,
            &skipped_successor,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn dispatch_composer_advances_the_exact_retained_ready_effect() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let issued_at = 1_550;
    let projection =
        compose_channel_dispatch_transition(&fixture.reservation, &fixture.ready_view, issued_at)?;
    let [transition] = projection.transitions() else {
        return Err(ChannelError::AuthorityVerification);
    };
    assert!(projection.effect_slots().is_empty());
    assert!(projection.request_replays().is_empty());
    assert_eq!(
        projection.not_after_unix_ms(),
        Some(fixture.reservation.artifact().body.expires_at_unix_ms)
    );
    assert_eq!(
        projection.operation_id(),
        Some(fixture.reservation.artifact().body.operation_id.as_str())
    );
    assert_eq!(
        transition.expected_head_digest.as_deref(),
        Some(fixture.reservation.ready_effect_head_digest())
    );
    assert_eq!(
        transition.next_head.predecessor_digest.as_deref(),
        Some(fixture.reservation.ready_effect_head_digest())
    );
    assert_eq!(transition.next_head.head_version, 2);
    assert_eq!(transition.next_head.resource_version, 2);
    assert_eq!(transition.next_head.lifecycle_fence, 2);
    assert_eq!(transition.next_head.lifecycle_state, "dispatch_committed");
    assert_eq!(transition.next_head.trusted_clock_high_water, issued_at);
    assert_eq!(
        transition.transition_proof_digest,
        projection.proof_digest()
    );
    let dispatched =
        chio_core::economic_continuity::economic_effect_slot_from_head(&transition.next_head)
            .map_err(|_| ChannelError::AuthorityVerification)?;
    assert_eq!(dispatched, fixture.dispatch_effect);
    let retained = fixture
        .ready_view
        .view()
        .request_replay(&fixture.reservation.ready_effect().request.key())
        .ok_or(ChannelError::AuthorityVerification)?;
    assert_eq!(retained.request, fixture.reservation.ready_effect().request);
    assert_eq!(
        retained.operation_id,
        fixture.reservation.artifact().body.operation_id
    );
    assert_eq!(
        retained.effect_slot_ids,
        vec![fixture.reservation.ready_effect().slot_id.clone()]
    );

    let batch = signed_channel_projection_batch(&fixture.ready_view, &projection, issued_at)?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection.clone());
    assert!(verifier
        .verify_transition(Some(&transition.next_head), transition)
        .is_err());
    let advance = verify_economic_state_batch_advance(
        &fixture.ready_view,
        batch,
        &channel_anchor_pins(),
        &verifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)?;
    let verified = verify_channel_dispatch_advance(&fixture.reservation, &advance)?;
    assert_eq!(verified.effect_slot(), &fixture.dispatch_effect);
    assert_eq!(verified.request_replay(), retained);
    assert_eq!(
        verified.reservation_digest(),
        fixture.reservation.artifact().digest()?
    );
    assert_eq!(
        verified.previous_checkpoint_digest(),
        fixture.ready_view.view().checkpoint_digest.as_str()
    );
    Ok(())
}

#[test]
fn dispatch_composer_rebases_over_a_newer_unchanged_checkpoint() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let admitted = fixture.reservation.snapshot();
    let mut later = fixture.ready_view.view().clone();
    later.checkpoint_sequence = later
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    later.checkpoint_digest = digest("later-unrelated-checkpoint");
    later.observed_at = later
        .observed_at
        .checked_add(25)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let later = verified_modified_view(later)?;
    let issued_at = 1_550;
    let projection = compose_channel_dispatch_transition(&fixture.reservation, &later, issued_at)?;
    let batch = signed_channel_projection_batch(&later, &projection, issued_at)?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    let advance =
        verify_economic_state_batch_advance(&later, batch, &channel_anchor_pins(), &verifier)
            .map_err(|_| ChannelError::AuthorityVerification)?;
    let verified = verify_channel_dispatch_advance(&fixture.reservation, &advance)?;
    assert_eq!(
        verified.previous_checkpoint_digest(),
        later.view().checkpoint_digest
    );

    let mut fork = fixture.ready_view.view().clone();
    fork.checkpoint_digest = digest("same-sequence-checkpoint-fork");
    let fork = verified_modified_view(fork)?;
    assert!(compose_channel_dispatch_transition(&fixture.reservation, &fork, issued_at).is_err());

    let mut older = fixture.ready_view.view().clone();
    older.checkpoint_sequence = older
        .checkpoint_sequence
        .checked_sub(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    older.checkpoint_digest = digest("older-checkpoint");
    let older = verified_modified_view(older)?;
    assert!(compose_channel_dispatch_transition(&fixture.reservation, &older, issued_at).is_err());

    let mut regressed_time = fixture.ready_view.view().clone();
    regressed_time.checkpoint_sequence = regressed_time
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    regressed_time.checkpoint_digest = digest("later-regressed-time-checkpoint");
    regressed_time.observed_at = admitted
        .observed_at_unix_ms()
        .checked_sub(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let regressed_time = verified_modified_view(regressed_time)?;
    assert!(
        compose_channel_dispatch_transition(&fixture.reservation, &regressed_time, issued_at,)
            .is_err()
    );
    Ok(())
}

#[test]
fn dispatch_composer_rejects_checkpoint_reservation_and_replay_substitution(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let issued_at = 1_550;

    let mut wrong_checkpoint = fixture.ready_view.view().clone();
    wrong_checkpoint.checkpoint_digest = digest("wrong-ready-checkpoint");
    let wrong_checkpoint = verified_modified_view(wrong_checkpoint)?;
    assert!(compose_channel_dispatch_transition(
        &fixture.reservation,
        &wrong_checkpoint,
        issued_at,
    )
    .is_err());

    let mut missing_replay = fixture.ready_view.view().clone();
    missing_replay.request_replays.clear();
    missing_replay.absent_request_keys = vec![fixture.reservation.ready_effect().request.key()];
    let missing_replay = verified_modified_view(missing_replay)?;
    assert!(
        compose_channel_dispatch_transition(&fixture.reservation, &missing_replay, issued_at,)
            .is_err()
    );

    let mut wrong_replay = fixture.ready_view.view().clone();
    wrong_replay.request_replays[0].operation_id = digest("wrong-replay-operation");
    let wrong_replay = verified_modified_view(wrong_replay)?;
    assert!(
        compose_channel_dispatch_transition(&fixture.reservation, &wrong_replay, issued_at,)
            .is_err()
    );

    let mut wrong_request = fixture.ready_view.view().clone();
    wrong_request.request_replays[0]
        .request
        .request_binding_digest = digest("wrong-replay-request");
    let wrong_request = verified_modified_view(wrong_request)?;
    assert!(
        compose_channel_dispatch_transition(&fixture.reservation, &wrong_request, issued_at,)
            .is_err()
    );

    let mut wrong_reservation = fixture.ready_view.view().clone();
    let effect_key = fixture.reservation.ready_effect().resource_head_key();
    let effect_index = wrong_reservation
        .heads
        .iter()
        .position(|head| head.resource_key == effect_key)
        .ok_or(ChannelError::AuthorityVerification)?;
    let mut substituted_effect = fixture.reservation.ready_effect().clone();
    substituted_effect.parameters_digest = digest("wrong-reservation-digest");
    let substituted_state = EconomicContentV1::Inline {
        value: serde_json::to_value(&substituted_effect)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    wrong_reservation.heads[effect_index].state_digest = substituted_state
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    wrong_reservation.heads[effect_index].state = substituted_state;
    let wrong_reservation = verified_modified_view(wrong_reservation)?;
    assert!(compose_channel_dispatch_transition(
        &fixture.reservation,
        &wrong_reservation,
        issued_at,
    )
    .is_err());

    let projection =
        compose_channel_dispatch_transition(&fixture.reservation, &fixture.ready_view, issued_at)?;
    let mut batch = signed_channel_projection_batch(&fixture.ready_view, &projection, issued_at)?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    batch.operation_id = Some(digest("generic-operation"));
    assert!(verifier.verify_batch(&fixture.ready_view, &batch).is_err());
    assert!(verifier
        .verify_transition(None, &batch.transitions[0])
        .is_err());
    Ok(())
}

#[test]
fn cancellation_composer_releases_ready_reservation_and_retains_replay() -> Result<(), ChannelError>
{
    let fixture = terminal_advance_fixture()?;
    let issued_at = 1_550;
    let retained_replay = fixture
        .ready_view
        .view()
        .request_replay(&fixture.reservation.ready_effect().request.key())
        .ok_or(ChannelError::AuthorityVerification)?
        .clone();
    let projection = compose_channel_cancellation_transition(
        &fixture.reservation,
        &fixture.ready_view,
        issued_at,
    )?;
    assert_eq!(projection.transitions().len(), 3);
    assert!(projection.effect_slots().is_empty());
    assert!(projection.request_replays().is_empty());

    let batch = signed_channel_projection_batch(&fixture.ready_view, &projection, issued_at)?;
    let verifier = ChannelCancellationTransitionVerifierV1::new(fixture.reservation.clone());
    let advance = verify_economic_state_batch_advance(
        &fixture.ready_view,
        batch,
        &channel_anchor_pins(),
        &verifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)?;
    let verified = verify_channel_cancellation_advance(&fixture.reservation, &advance)?;
    assert_eq!(verified.request_replay(), &retained_replay);
    assert_eq!(verified.lifecycle().status, ChannelLifecycleStatusV1::Open);
    assert_eq!(verified.lifecycle().state_version, 3);
    assert_eq!(verified.lifecycle().lifecycle_fence, 4);
    assert!(verified.lifecycle().live_reservation_id.is_none());
    assert!(verified.lifecycle().operation_id.is_none());
    assert_eq!(
        verified.escrow().status,
        ChannelEscrowReservationStatusV1::Open
    );
    assert_eq!(verified.escrow().version, 4);
    assert_eq!(verified.escrow().lifecycle_fence, 4);
    assert_eq!(
        verified.effect_slot().state,
        EconomicEffectStateV1::NoEffect
    );
    assert!(matches!(
        verified.effect_slot().terminal,
        Some(EconomicEffectTerminalV1::NoEffect {
            kind: EconomicNoEffectKindV1::PreDispatch,
            ..
        })
    ));
    assert_eq!(
        verified.evidence().operation_id,
        fixture.reservation.artifact().body.operation_id
    );
    assert_eq!(
        verified.evidence().reservation_id,
        fixture.reservation.artifact().body.reservation_id
    );
    assert_eq!(
        verified.evidence().request,
        fixture.reservation.ready_effect().request
    );
    assert_eq!(
        verified.evidence().provider,
        fixture.reservation.ready_effect().target
    );
    assert_eq!(verified.evidence().issued_at, issued_at);
    Ok(())
}

#[test]
fn cancellation_composer_allows_expired_ready_but_rejects_dispatched_and_invalid_clocks(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let after_expiry = fixture
        .reservation
        .artifact()
        .body
        .expires_at_unix_ms
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let projection = compose_channel_cancellation_transition(
        &fixture.reservation,
        &fixture.ready_view,
        after_expiry,
    )?;
    assert_eq!(projection.not_after_unix_ms(), None);
    assert!(compose_channel_cancellation_transition(
        &fixture.reservation,
        fixture.advance.current(),
        after_expiry,
    )
    .is_err());
    assert!(compose_channel_cancellation_transition(
        &fixture.reservation,
        &fixture.ready_view,
        fixture
            .ready_view
            .view()
            .observed_at
            .checked_sub(1)
            .ok_or(ChannelError::ArithmeticOverflow)?,
    )
    .is_err());
    assert!(compose_channel_cancellation_transition(
        &fixture.reservation,
        &fixture.ready_view,
        u64::MAX,
    )
    .is_err());
    Ok(())
}

#[test]
fn cancellation_typed_verifier_rejects_a_resigned_tampered_batch() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let issued_at = 1_550;
    let projection = compose_channel_cancellation_transition(
        &fixture.reservation,
        &fixture.ready_view,
        issued_at,
    )?;
    let mut batch = signed_channel_projection_batch(&fixture.ready_view, &projection, issued_at)?;
    batch.transitions[0].transition_proof_digest = digest("tampered-cancellation-proof");
    batch
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;

    let verifier = ChannelCancellationTransitionVerifierV1::new(fixture.reservation.clone());
    assert!(verify_economic_state_batch_advance(
        &fixture.ready_view,
        batch.clone(),
        &channel_anchor_pins(),
        &verifier,
    )
    .is_err());
    let permissive = verify_economic_state_batch_advance(
        &fixture.ready_view,
        batch,
        &channel_anchor_pins(),
        &DirectTransitionVerifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)?;
    assert!(verify_channel_cancellation_advance(&fixture.reservation, &permissive).is_err());
    Ok(())
}

#[test]
fn cancellation_composer_rejects_replay_and_checkpoint_substitution() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let issued_at = 1_550;
    let request_key = fixture.reservation.ready_effect().request.key();

    let mut missing_replay = fixture.ready_view.view().clone();
    missing_replay.request_replays.clear();
    missing_replay.absent_request_keys = vec![request_key];
    let missing_replay = verified_modified_view(missing_replay)?;
    assert!(compose_channel_cancellation_transition(
        &fixture.reservation,
        &missing_replay,
        issued_at,
    )
    .is_err());

    let mut altered_replay = fixture.ready_view.view().clone();
    altered_replay.request_replays[0].operation_id = digest("altered-cancellation-operation");
    let altered_replay = verified_modified_view(altered_replay)?;
    assert!(compose_channel_cancellation_transition(
        &fixture.reservation,
        &altered_replay,
        issued_at,
    )
    .is_err());

    let mut fork = fixture.ready_view.view().clone();
    fork.checkpoint_digest = digest("cancellation-same-sequence-fork");
    let fork = verified_modified_view(fork)?;
    assert!(
        compose_channel_cancellation_transition(&fixture.reservation, &fork, issued_at).is_err()
    );

    let mut invalid_later = fixture.ready_view.view().clone();
    invalid_later.checkpoint_sequence = invalid_later
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let invalid_later = verified_modified_view(invalid_later)?;
    assert!(compose_channel_cancellation_transition(
        &fixture.reservation,
        &invalid_later,
        issued_at,
    )
    .is_err());

    let mut older = fixture.ready_view.view().clone();
    older.checkpoint_sequence = older
        .checkpoint_sequence
        .checked_sub(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    older.checkpoint_digest = digest("cancellation-older-checkpoint");
    let older = verified_modified_view(older)?;
    assert!(
        compose_channel_cancellation_transition(&fixture.reservation, &older, issued_at).is_err()
    );
    Ok(())
}

#[test]
fn cancellation_composer_rejects_source_head_and_service_substitution() -> Result<(), ChannelError>
{
    let fixture = terminal_advance_fixture()?;
    let issued_at = 1_550;

    let mut mixed_clock = fixture.ready_view.view().clone();
    mixed_clock.observed_at = mixed_clock
        .observed_at
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let channel_head = mixed_clock
        .heads
        .iter_mut()
        .find(|head| head.resource_key.resource_family == CHANNEL_LIFECYCLE_RESOURCE_FAMILY)
        .ok_or(ChannelError::AuthorityVerification)?;
    channel_head.trusted_clock_high_water = channel_head
        .trusted_clock_high_water
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mixed_clock = verified_modified_view(mixed_clock)?;
    assert!(
        compose_channel_cancellation_transition(&fixture.reservation, &mixed_clock, issued_at,)
            .is_err()
    );

    for mutation in [
        ReadyServiceMutation::RequestNamespace,
        ReadyServiceMutation::RequestId,
        ReadyServiceMutation::RequestBinding,
        ReadyServiceMutation::HandoffState,
        ReadyServiceMutation::HandoffVersion,
        ReadyServiceMutation::HandoffFence,
        ReadyServiceMutation::HandoffStoreUuid,
        ReadyServiceMutation::HandoffLeaseId,
        ReadyServiceMutation::HandoffOwnerEpoch,
        ReadyServiceMutation::TargetId,
        ReadyServiceMutation::TargetEpoch,
        ReadyServiceMutation::TargetQualification,
        ReadyServiceMutation::Action,
        ReadyServiceMutation::Parameters,
        ReadyServiceMutation::ResourceHead,
    ] {
        let substituted = forged_ready_service_view(
            &fixture.ready_view,
            &fixture.reservation.ready_effect().resource_head_key(),
            mutation,
        )?;
        assert!(compose_channel_cancellation_transition(
            &fixture.reservation,
            &substituted,
            issued_at,
        )
        .is_err());
    }

    for resource_family in [
        CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
        CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
    ] {
        let mut skipped = fixture.ready_view.view().clone();
        let head = skipped
            .heads
            .iter_mut()
            .find(|head| head.resource_key.resource_family == resource_family)
            .ok_or(ChannelError::AuthorityVerification)?;
        head.head_version = head
            .head_version
            .checked_add(1)
            .ok_or(ChannelError::ArithmeticOverflow)?;
        let skipped = verified_modified_view(skipped)?;
        assert!(
            compose_channel_cancellation_transition(&fixture.reservation, &skipped, issued_at,)
                .is_err()
        );

        let mut wrong_predecessor = fixture.ready_view.view().clone();
        wrong_predecessor
            .heads
            .iter_mut()
            .find(|head| head.resource_key.resource_family == resource_family)
            .ok_or(ChannelError::AuthorityVerification)?
            .predecessor_digest = Some(digest("wrong-cancellation-predecessor"));
        let wrong_predecessor = verified_modified_view(wrong_predecessor)?;
        assert!(compose_channel_cancellation_transition(
            &fixture.reservation,
            &wrong_predecessor,
            issued_at,
        )
        .is_err());
    }
    Ok(())
}

#[test]
fn channel_transition_replay_round_trips_all_transition_kinds() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let pre_anchor = prepared_reservation_fixture()?;
    let pre_anchor_prepared = verified_prepared_reservation(&pre_anchor)?;
    assert_eq!(
        pre_anchor.proposal.artifact(),
        fixture.reservation.artifact()
    );
    let authorities = ChannelTransitionReplayAuthorityPinsV1::new(
        pre_anchor.open_trust.clone(),
        pre_anchor.funding_authority.clone(),
        pre_anchor.reservation_authority.clone(),
        Some(pre_anchor.trusted_kernel_key.clone()),
        &channel_anchor_pins(),
    )?;
    let open_artifacts = ChannelTransitionReplayOpenArtifactsV1 {
        funding_evidence: pre_anchor.funding.clone(),
        funding_acknowledgement: pre_anchor.funding_acknowledgement.clone(),
        dispute_policy: pre_anchor.dispute_policy.clone(),
    };
    let reservation_context = ChannelReservationReplayContextV1::from_pre_anchor(
        &pre_anchor_prepared,
        &pre_anchor.proposal,
    )?;

    let reservation_issued_at = pre_anchor.proposal.accepted_at_unix_ms();
    let reservation_projection = compose_channel_reservation_transition(
        &pre_anchor_prepared,
        &pre_anchor.proposal,
        reservation_issued_at,
    )?;
    let reservation_batch = signed_channel_projection_batch(
        &pre_anchor.current,
        &reservation_projection,
        reservation_issued_at,
    )?;
    let reservation_descriptor = ChannelTransitionReplayDescriptorV1::for_reservation(
        &reservation_context,
        &open_artifacts,
        &authorities,
        &reservation_batch,
    )?;

    let dispatch_issued_at = 1_550;
    let dispatch_projection = compose_channel_dispatch_transition(
        &fixture.reservation,
        &fixture.ready_view,
        dispatch_issued_at,
    )?;
    let dispatch_batch = signed_channel_projection_batch(
        &fixture.ready_view,
        &dispatch_projection,
        dispatch_issued_at,
    )?;
    let dispatch_descriptor = ChannelTransitionReplayDescriptorV1::for_dispatch(
        &reservation_context,
        &open_artifacts,
        &authorities,
        &fixture.ready_view,
        &dispatch_batch,
    )?;

    let cancellation_projection = compose_channel_cancellation_transition(
        &fixture.reservation,
        &fixture.ready_view,
        dispatch_issued_at,
    )?;
    let cancellation_batch = signed_channel_projection_batch(
        &fixture.ready_view,
        &cancellation_projection,
        dispatch_issued_at,
    )?;
    let cancellation_descriptor = ChannelTransitionReplayDescriptorV1::for_cancellation(
        &reservation_context,
        &open_artifacts,
        &authorities,
        &fixture.ready_view,
        &fixture.ready_view,
        &cancellation_batch,
    )?;

    let outcome = verified_terminal_outcome(&fixture)?;
    let terminal_projection = compose_channel_terminal_transition(
        &fixture.open,
        &fixture.reservation,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        fixture.advance.current(),
        fixture.advance.batch().issued_at,
    )?;
    let terminal_batch = signed_channel_projection_batch(
        fixture.advance.current(),
        &terminal_projection,
        fixture.advance.batch().issued_at,
    )?;
    let terminal_descriptor = ChannelTransitionReplayDescriptorV1::for_terminal(
        &reservation_context,
        &open_artifacts,
        &authorities,
        &fixture.ready_view,
        fixture.advance.current(),
        &fixture.signed_receipt,
        fixture.obligation.as_ref(),
        &fixture.signed_next,
        &outcome,
        &terminal_batch,
    )?;

    let replay_keys = [
        reservation_descriptor.key().to_owned(),
        dispatch_descriptor.key().to_owned(),
        cancellation_descriptor.key().to_owned(),
        terminal_descriptor.key().to_owned(),
    ];
    assert_eq!(
        replay_keys
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        replay_keys.len()
    );

    let cases = [
        (
            ChannelTransitionReplayKindV1::Reservation,
            reservation_descriptor,
            &pre_anchor.current,
            reservation_batch,
        ),
        (
            ChannelTransitionReplayKindV1::Dispatch,
            dispatch_descriptor,
            &fixture.ready_view,
            dispatch_batch,
        ),
        (
            ChannelTransitionReplayKindV1::Cancellation,
            cancellation_descriptor,
            &fixture.ready_view,
            cancellation_batch,
        ),
        (
            ChannelTransitionReplayKindV1::Terminal,
            terminal_descriptor,
            fixture.advance.current(),
            terminal_batch,
        ),
    ];
    for (kind, descriptor, current, batch) in cases {
        assert_eq!(descriptor.kind(), kind);
        let descriptor_key = descriptor.key().to_owned();
        let bytes = descriptor.canonical_bytes()?;
        let verifier =
            ChannelTransitionReplayVerifierV1::from_canonical_bytes(&bytes, &authorities)?;
        assert_eq!(verifier.descriptor().canonical_bytes()?, bytes);
        assert_eq!(verifier.descriptor().key(), descriptor_key);
        verify_economic_state_batch_advance(current, batch, &channel_anchor_pins(), &verifier)
            .map_err(|_| ChannelError::AuthorityVerification)?;
    }
    Ok(())
}

#[test]
fn channel_reservation_replay_context_is_constructible_before_anchor_commit(
) -> Result<(), ChannelError> {
    let fixture = prepared_reservation_fixture()?;
    let prepared = verified_prepared_reservation(&fixture)?;
    let authorities = ChannelTransitionReplayAuthorityPinsV1::new(
        fixture.open_trust.clone(),
        fixture.funding_authority.clone(),
        fixture.reservation_authority.clone(),
        Some(fixture.trusted_kernel_key.clone()),
        &channel_anchor_pins(),
    )?;
    let open_artifacts = ChannelTransitionReplayOpenArtifactsV1 {
        funding_evidence: fixture.funding.clone(),
        funding_acknowledgement: fixture.funding_acknowledgement.clone(),
        dispute_policy: fixture.dispute_policy.clone(),
    };
    let context = ChannelReservationReplayContextV1::from_pre_anchor(&prepared, &fixture.proposal)?;
    let issued_at = fixture.proposal.accepted_at_unix_ms();
    let projection =
        compose_channel_reservation_transition(&prepared, &fixture.proposal, issued_at)?;
    let batch = signed_channel_projection_batch(&fixture.current, &projection, issued_at)?;
    let descriptor = ChannelTransitionReplayDescriptorV1::for_reservation(
        &context,
        &open_artifacts,
        &authorities,
        &batch,
    )?;
    let verifier = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
        &descriptor.canonical_bytes()?,
        &authorities,
    )?;
    let actual_anchor_pins = authorities.anchor_pins();
    let expected_anchor_pins = channel_anchor_pins();
    assert_eq!(actual_anchor_pins.anchor_id, expected_anchor_pins.anchor_id);
    assert_eq!(actual_anchor_pins.namespace, expected_anchor_pins.namespace);
    assert_eq!(
        actual_anchor_pins.signer_key_id,
        expected_anchor_pins.signer_key_id
    );
    assert_eq!(
        actual_anchor_pins.signer_key_epoch,
        expected_anchor_pins.signer_key_epoch
    );
    assert_eq!(
        actual_anchor_pins.signer_public_key.to_hex(),
        expected_anchor_pins.signer_public_key.to_hex()
    );
    assert_eq!(
        verifier.verified_reservation_proposal().artifact(),
        fixture.proposal.artifact()
    );
    let advance = verify_economic_state_batch_advance(
        &fixture.current,
        batch.clone(),
        &channel_anchor_pins(),
        &verifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)?;
    let committed = committed_channel_projection_view(&fixture.current, &batch)?;
    verify_economic_state_batch_commit(&advance, &committed, &channel_anchor_pins())
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let admitted = verifier.verify_committed_reservation(&committed)?;
    assert_eq!(admitted.artifact(), fixture.proposal.artifact());
    Ok(())
}

#[test]
fn channel_terminal_replay_allows_completion_after_reservation_expiry() -> Result<(), ChannelError>
{
    let fixture = terminal_advance_fixture()?;
    let issued_at = fixture
        .reservation
        .artifact()
        .body
        .expires_at_unix_ms
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mut post_expiry = fixture.advance.current().view().clone();
    post_expiry.observed_at = issued_at;
    let post_expiry = verified_modified_view(post_expiry)?;
    let outcome = verified_terminal_outcome(&fixture)?;
    let projection = compose_channel_terminal_transition(
        &fixture.open,
        &fixture.reservation,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &post_expiry,
        issued_at,
    )?;
    assert_eq!(projection.not_after_unix_ms(), None);
    let batch = signed_channel_projection_batch(&post_expiry, &projection, issued_at)?;
    let authorities = ChannelTransitionReplayAuthorityPinsV1::new(
        fixture.open_trust.clone(),
        fixture.funding_authority.clone(),
        fixture.reservation_authority.clone(),
        Some(fixture.trusted_kernel_key.clone()),
        &channel_anchor_pins(),
    )?;
    let open_artifacts = ChannelTransitionReplayOpenArtifactsV1 {
        funding_evidence: fixture.funding.clone(),
        funding_acknowledgement: fixture.funding_acknowledgement.clone(),
        dispute_policy: fixture.dispute_policy.clone(),
    };
    let context =
        ChannelReservationReplayContextV1::from_verified(&fixture.prepared, &fixture.reservation)?;
    let descriptor = ChannelTransitionReplayDescriptorV1::for_terminal(
        &context,
        &open_artifacts,
        &authorities,
        &fixture.ready_view,
        &post_expiry,
        &fixture.signed_receipt,
        fixture.obligation.as_ref(),
        &fixture.signed_next,
        &outcome,
        &batch,
    )?;
    assert_eq!(descriptor.not_after_unix_ms(), None);
    let verifier = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
        &descriptor.canonical_bytes()?,
        &authorities,
    )?;
    verify_economic_state_batch_advance(&post_expiry, batch, &channel_anchor_pins(), &verifier)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(())
}

#[test]
fn channel_terminal_outcome_commitment_rejects_result_substitution() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let Some(EconomicEffectTerminalV1::Completed {
        result_id,
        result_digest,
        result,
    }) = fixture.completed_effect.terminal.as_ref()
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    let terminal_result = EconomicTerminalResultV1 {
        result_id: result_id.clone(),
        result_digest: result_digest.clone(),
        result: result.clone(),
    };
    let signed = SignedChannelTerminalOutcomeCommitmentV1::sign_for_test(
        &fixture.reservation,
        &fixture.signed_receipt,
        terminal_result.clone(),
        fixture.advance.batch().issued_at,
        fixture.advance.batch().issued_at,
        &Keypair::from_seed(&[36; 32]),
    )?;
    verify_channel_terminal_outcome_commitment(
        &signed,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )?;

    let wrong_signer = SignedChannelTerminalOutcomeCommitmentV1::sign_for_test(
        &fixture.reservation,
        &fixture.signed_receipt,
        terminal_result,
        fixture.advance.batch().issued_at,
        fixture.advance.batch().issued_at,
        &Keypair::from_seed(&[37; 32]),
    )?;
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_signer,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());

    let mut wrong_operation = signed.clone();
    wrong_operation.body.operation_id = digest("substituted-outcome-operation");
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_operation,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());

    let mut wrong_reservation = signed.clone();
    wrong_reservation.body.reservation_digest = digest("substituted-outcome-reservation");
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_reservation,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());

    let mut wrong_receipt = signed.clone();
    wrong_receipt.body.receipt_id = "substituted-receipt".to_owned();
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_receipt,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());

    let mut wrong_id = signed.clone();
    wrong_id.body.terminal_result.result_id = "substituted-result".to_owned();
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_id,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());

    let mut wrong_digest = signed.clone();
    wrong_digest.body.terminal_result.result_digest = digest("substituted-result-digest");
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_digest,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());

    let mut wrong_result = signed;
    wrong_result.body.terminal_result.result = EconomicContentV1::Inline {
        value: serde_json::json!({"substituted": true}),
    };
    assert!(verify_channel_terminal_outcome_commitment(
        &wrong_result,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )
    .is_err());
    Ok(())
}

#[test]
fn channel_terminal_outcome_orders_recording_terminalization_and_receipt_time(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let Some(EconomicEffectTerminalV1::Completed {
        result_id,
        result_digest,
        result,
    }) = fixture.completed_effect.terminal.as_ref()
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    let terminal_result = EconomicTerminalResultV1 {
        result_id: result_id.clone(),
        result_digest: result_digest.clone(),
        result: result.clone(),
    };
    let kernel = Keypair::from_seed(&[36; 32]);
    let mut receipt_body = fixture.signed_receipt.body();
    receipt_body.timestamp = 2;
    let receipt = ChioReceipt::sign(receipt_body, &kernel)
        .map_err(|error| ChannelError::Canonicalization(error.to_string()))?;
    let signed = SignedChannelTerminalOutcomeCommitmentV1::sign_for_test(
        &fixture.reservation,
        &receipt,
        terminal_result.clone(),
        1_000,
        2_000,
        &kernel,
    )?;
    verify_channel_terminal_outcome_commitment(
        &signed,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &receipt,
    )?;

    assert!(SignedChannelTerminalOutcomeCommitmentV1::sign_for_test(
        &fixture.reservation,
        &receipt,
        terminal_result,
        2_001,
        2_000,
        &kernel,
    )
    .is_err());

    let mut substituted_terminalization = signed;
    substituted_terminalization.body.terminalized_at_unix_ms = 1_999;
    assert!(verify_channel_terminal_outcome_commitment(
        &substituted_terminalization,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &receipt,
    )
    .is_err());
    Ok(())
}

#[test]
fn channel_terminal_rejects_same_second_obligation_before_exact_terminalization(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let Some(EconomicEffectTerminalV1::Completed {
        result_id,
        result_digest,
        result,
    }) = fixture.completed_effect.terminal.as_ref()
    else {
        return Err(ChannelError::AuthorityVerification);
    };
    let signed = SignedChannelTerminalOutcomeCommitmentV1::sign_for_test(
        &fixture.reservation,
        &fixture.signed_receipt,
        EconomicTerminalResultV1 {
            result_id: result_id.clone(),
            result_digest: result_digest.clone(),
            result: result.clone(),
        },
        1_600,
        1_699,
        &Keypair::from_seed(&[36; 32]),
    )?;
    let outcome = verify_channel_terminal_outcome_commitment(
        &signed,
        &fixture.trusted_kernel_key,
        &fixture.reservation,
        &fixture.signed_receipt,
    )?;
    let atom = fixture
        .obligation
        .as_ref()
        .ok_or(ChannelError::AuthorityVerification)?;
    assert!(fixture.receipt.receipt_timestamp_unix_ms() <= atom.created_at_unix_ms());
    assert!(outcome.terminalized_at_unix_ms() > atom.created_at_unix_ms());

    let mut later_batch = fixture.advance.batch().clone();
    later_batch.issued_at = 1_700;
    let later_advance = reseal_terminal_batch(&fixture, later_batch)?;
    assert!(verify_channel_terminal_advance(
        &fixture.open,
        &fixture.reservation,
        &fixture.prior,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &later_advance,
    )
    .is_err());
    Ok(())
}

#[test]
fn channel_cancellation_replay_uses_retained_ready_view_after_expiry() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let issued_at = fixture
        .reservation
        .artifact()
        .body
        .expires_at_unix_ms
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mut post_expiry = fixture.ready_view.view().clone();
    post_expiry.checkpoint_sequence = post_expiry
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    post_expiry.checkpoint_digest = digest("post-expiry-ready-checkpoint");
    post_expiry.observed_at = issued_at;
    let post_expiry = verified_modified_view(post_expiry)?;
    let projection =
        compose_channel_cancellation_transition(&fixture.reservation, &post_expiry, issued_at)?;
    let batch = signed_channel_projection_batch(&post_expiry, &projection, issued_at)?;
    let authorities = ChannelTransitionReplayAuthorityPinsV1::new(
        fixture.open_trust.clone(),
        fixture.funding_authority.clone(),
        fixture.reservation_authority.clone(),
        Some(fixture.trusted_kernel_key.clone()),
        &channel_anchor_pins(),
    )?;
    let open_artifacts = ChannelTransitionReplayOpenArtifactsV1 {
        funding_evidence: fixture.funding.clone(),
        funding_acknowledgement: fixture.funding_acknowledgement.clone(),
        dispute_policy: fixture.dispute_policy.clone(),
    };
    let context =
        ChannelReservationReplayContextV1::from_verified(&fixture.prepared, &fixture.reservation)?;
    let descriptor = ChannelTransitionReplayDescriptorV1::for_cancellation(
        &context,
        &open_artifacts,
        &authorities,
        &fixture.ready_view,
        &post_expiry,
        &batch,
    )?;
    assert_eq!(descriptor.not_after_unix_ms(), None);
    let verifier = ChannelTransitionReplayVerifierV1::from_canonical_bytes(
        &descriptor.canonical_bytes()?,
        &authorities,
    )?;
    verify_economic_state_batch_advance(&post_expiry, batch, &channel_anchor_pins(), &verifier)
        .map_err(|_| ChannelError::AuthorityVerification)?;
    Ok(())
}
