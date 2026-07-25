use super::*;

#[test]
fn terminal_advance_binds_the_anchored_state_receipt_and_completed_effect(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let outcome = verified_terminal_outcome(&fixture)?;
    let verified = verify_channel_terminal_advance(
        &fixture.open,
        &fixture.reservation,
        &fixture.prior,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &fixture.advance,
    )?;
    let obligation = fixture
        .obligation
        .as_ref()
        .ok_or(ChannelError::AuthorityVerification)?;
    assert_eq!(
        verified.channel_id(),
        fixture.open.artifact().body.channel_id
    );
    assert_eq!(
        verified.obligation_atom_id(),
        Some(obligation.obligation_id())
    );
    assert_eq!(
        verified.obligation_atom_digest(),
        Some(
            obligation
                .digest()
                .map_err(|_| ChannelError::AuthorityVerification)?
                .as_str()
        )
    );
    assert_eq!(verified.obligation_atom(), Some(obligation));
    assert_eq!(obligation.created_at_unix_ms(), verified.batch_issued_at());
    assert_eq!(verified.effect_result_id(), "terminal-outcome");
    assert_eq!(verified.effect_slot(), &fixture.completed_effect);
    assert_eq!(verified.batch(), fixture.advance.batch());
    assert_eq!(
        verified.current_view().view(),
        fixture.advance.current().view()
    );
    assert_eq!(verified.terminal_lifecycle(), &fixture.terminal_lifecycle);
    assert_eq!(verified.terminal_escrow(), &fixture.terminal_escrow);
    assert_ne!(
        verified.previous_checkpoint_digest(),
        fixture.reservation.snapshot().checkpoint_digest()
    );
    assert_eq!(
        verified.previous_checkpoint_digest(),
        fixture.advance.current().view().checkpoint_digest
    );
    Ok(())
}

#[test]
fn terminal_batch_composer_reproduces_the_verified_three_resource_advance(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let outcome = verified_terminal_outcome(&fixture)?;
    let projection = compose_channel_terminal_transition(
        &fixture.open,
        &fixture.reservation,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        fixture.advance.current(),
        fixture.advance.batch().issued_at,
    )?;
    assert_eq!(projection.transitions().len(), 3);
    assert!(projection.effect_slots().is_empty());
    assert!(projection.request_replays().is_empty());
    assert_eq!(
        projection.operation_id(),
        Some(fixture.reservation.artifact().body.operation_id.as_str())
    );
    assert!(projection
        .transitions()
        .iter()
        .all(|transition| transition.transition_proof_digest == projection.proof_digest()));

    let mut batch = fixture.advance.batch().clone();
    batch.transitions = projection.transitions().to_vec();
    batch.effect_slots = projection.effect_slots().to_vec();
    batch.request_replays = projection.request_replays().to_vec();
    batch.operation_id = projection.operation_id().map(str::to_owned);
    batch
        .seal(&Keypair::from_seed(&[61; 32]))
        .map_err(|_| ChannelError::AuthorityVerification)?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    assert!(verifier
        .verify_transition(None, &batch.transitions[0])
        .is_err());
    let advance = verify_economic_state_batch_advance(
        fixture.advance.current(),
        batch,
        &channel_anchor_pins(),
        &verifier,
    )
    .map_err(|_| ChannelError::AuthorityVerification)?;
    let verified = verify_channel_terminal_advance(
        &fixture.open,
        &fixture.reservation,
        &fixture.prior,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &advance,
    )?;
    assert_eq!(verified.terminal_lifecycle(), &fixture.terminal_lifecycle);
    assert_eq!(verified.terminal_escrow(), &fixture.terminal_escrow);
    assert_eq!(verified.effect_slot(), &fixture.completed_effect);
    Ok(())
}

#[test]
fn terminal_composer_rebases_over_a_newer_unchanged_checkpoint() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let mut later = fixture.advance.current().view().clone();
    later.checkpoint_sequence = later
        .checkpoint_sequence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    later.checkpoint_digest = digest("later-terminal-unrelated-checkpoint");
    later.observed_at = later
        .observed_at
        .checked_add(25)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let later = verified_modified_view(later)?;
    let outcome = verified_terminal_outcome(&fixture)?;
    let obligation_created_at = fixture
        .obligation
        .as_ref()
        .ok_or(ChannelError::AuthorityVerification)?
        .created_at_unix_ms();
    assert!(outcome.outcome_recorded_at_unix_ms() < outcome.terminalized_at_unix_ms());
    assert!(outcome.terminalized_at_unix_ms() <= obligation_created_at);
    let before_terminalization = outcome
        .terminalized_at_unix_ms()
        .checked_sub(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    assert!(compose_channel_terminal_transition(
        &fixture.open,
        &fixture.reservation,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &later,
        before_terminalization,
    )
    .is_err());
    let issued_at = fixture
        .advance
        .batch()
        .issued_at
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    assert!(fixture.advance.batch().issued_at < issued_at);
    assert!(obligation_created_at <= issued_at);
    let projection = compose_channel_terminal_transition(
        &fixture.open,
        &fixture.reservation,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &later,
        issued_at,
    )?;
    let batch = signed_channel_projection_batch(&later, &projection, issued_at)?;
    let verifier = ChannelLifecycleBatchVerifier::new(projection);
    let advance =
        verify_economic_state_batch_advance(&later, batch, &channel_anchor_pins(), &verifier)
            .map_err(|_| ChannelError::AuthorityVerification)?;
    let verified = verify_channel_terminal_advance(
        &fixture.open,
        &fixture.reservation,
        &fixture.prior,
        &fixture.next,
        &fixture.receipt,
        &outcome,
        &advance,
    )?;
    assert_eq!(
        verified.previous_checkpoint_digest(),
        later.view().checkpoint_digest
    );
    assert_eq!(verified.terminal_lifecycle(), &fixture.terminal_lifecycle);
    assert_eq!(verified.terminal_escrow(), &fixture.terminal_escrow);
    Ok(())
}
