use super::*;

#[test]
fn terminal_advance_rejects_substituted_completed_effect_bindings() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    for substitution in 0..7 {
        let mut batch = fixture.advance.batch().clone();
        let effect_index = transition_index(&batch, "effect_slot")?;
        let transition = &mut batch.transitions[effect_index];
        let EconomicContentV1::Inline { value } = &transition.next_head.state else {
            return Err(ChannelError::AuthorityVerification);
        };
        let mut effect: EconomicEffectSlotV1 = serde_json::from_value(value.clone())
            .map_err(|_| ChannelError::AuthorityVerification)?;
        match substitution {
            0 => effect.parameters_digest = digest("substituted-terminal-parameters"),
            1 => effect.resource_head_digest = digest("substituted-terminal-head"),
            2 => {
                effect.idempotency_key = digest("substituted-terminal-idempotency");
                transition.next_head.effect_idempotency_key = Some(effect.idempotency_key.clone());
            }
            3 => effect.request.request_id = "substituted-terminal-request".to_owned(),
            4 => effect.request.request_namespace_digest = digest("substituted-namespace"),
            5 => effect.action_digest = digest("substituted-terminal-action"),
            6 => {
                let result = EconomicContentV1::Inline {
                    value: serde_json::json!({"outcomeId": digest("substituted-outcome")}),
                };
                let result_digest = result
                    .digest()
                    .map_err(|_| ChannelError::AuthorityVerification)?;
                effect.terminal = Some(EconomicEffectTerminalV1::Completed {
                    result_id: "substituted-outcome".to_owned(),
                    result_digest,
                    result,
                });
            }
            _ => return Err(ChannelError::AuthorityVerification),
        }
        replace_transition_state(transition, &effect)?;
        verify_substituted_batch(&fixture, batch)?;
    }
    Ok(())
}

#[test]
fn terminal_advance_rejects_unconsumed_or_skipped_lifecycle_state() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    let mut uncleared = fixture.terminal_lifecycle.clone();
    uncleared.live_reservation_id =
        Some(fixture.reservation.artifact().body.reservation_id.clone());
    uncleared.operation_id = Some(fixture.reservation.artifact().body.operation_id.clone());
    let mut state_version = fixture.terminal_lifecycle.clone();
    state_version.state_version = state_version
        .state_version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mut escrow_version = fixture.terminal_escrow.clone();
    escrow_version.version = escrow_version
        .version
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mut lifecycle_fence = fixture.terminal_lifecycle.clone();
    lifecycle_fence.lifecycle_fence = lifecycle_fence
        .lifecycle_fence
        .checked_add(1)
        .ok_or(ChannelError::ArithmeticOverflow)?;
    let mut escrow_fence = fixture.terminal_escrow.clone();
    escrow_fence.lifecycle_fence = lifecycle_fence.lifecycle_fence;
    for (lifecycle, escrow) in [
        (uncleared, fixture.terminal_escrow.clone()),
        (state_version, fixture.terminal_escrow.clone()),
        (fixture.terminal_lifecycle.clone(), escrow_version),
        (lifecycle_fence, escrow_fence),
    ] {
        let mut batch = fixture.advance.batch().clone();
        let lifecycle_index = transition_index(&batch, CHANNEL_LIFECYCLE_RESOURCE_FAMILY)?;
        let escrow_index = transition_index(&batch, CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY)?;
        batch.transitions[lifecycle_index]
            .next_head
            .resource_version = lifecycle.state_version;
        batch.transitions[lifecycle_index].next_head.lifecycle_fence = lifecycle.lifecycle_fence;
        batch.transitions[lifecycle_index].next_head.operation_id = lifecycle.operation_id.clone();
        batch.transitions[lifecycle_index]
            .next_head
            .effect_idempotency_key = lifecycle
            .operation_id
            .as_ref()
            .map(|operation_id| digest(operation_id));
        replace_transition_state(&mut batch.transitions[lifecycle_index], &lifecycle)?;
        batch.transitions[escrow_index].next_head.resource_version = escrow.version;
        batch.transitions[escrow_index].next_head.lifecycle_fence = escrow.lifecycle_fence;
        replace_transition_state(&mut batch.transitions[escrow_index], &escrow)?;
        verify_substituted_batch(&fixture, batch)?;
    }
    Ok(())
}

#[test]
fn terminal_advance_rejects_non_exact_batch_shape_and_time() -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;
    for resource_family in [
        CHANNEL_LIFECYCLE_RESOURCE_FAMILY,
        CHANNEL_ESCROW_RESERVATION_RESOURCE_FAMILY,
        "effect_slot",
    ] {
        let mut batch = fixture.advance.batch().clone();
        let index = transition_index(&batch, resource_family)?;
        batch.transitions.remove(index);
        verify_substituted_batch(&fixture, batch)?;
    }

    for issued_at in [1_499, 1_601, 1_701] {
        let mut batch = fixture.advance.batch().clone();
        batch.issued_at = issued_at;
        verify_substituted_batch(&fixture, batch)?;
    }

    let mut side_array = fixture.advance.batch().clone();
    side_array
        .effect_slots
        .push(fixture.dispatch_effect.clone());
    assert!(side_array.seal(&Keypair::from_seed(&[61; 32])).is_err());

    let mut duplicate = fixture.advance.batch().clone();
    duplicate.transitions.push(duplicate.transitions[0].clone());
    assert!(duplicate.seal(&Keypair::from_seed(&[61; 32])).is_err());

    let mut reordered = fixture.advance.batch().clone();
    reordered.transitions.swap(0, 1);
    assert!(reordered.seal(&Keypair::from_seed(&[61; 32])).is_err());
    Ok(())
}

#[test]
fn terminal_advance_rejects_same_checkpoint_uncommitted_or_unlinked_dispatch(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture()?;

    let mut same_checkpoint_view = fixture.advance.current().view().clone();
    same_checkpoint_view.checkpoint_sequence = fixture.reservation.snapshot().checkpoint_sequence();
    same_checkpoint_view.checkpoint_digest = fixture
        .reservation
        .snapshot()
        .checkpoint_digest()
        .to_owned();
    same_checkpoint_view.observed_at = fixture.reservation.snapshot().observed_at_unix_ms();
    let same_checkpoint_view = verified_modified_view(same_checkpoint_view)?;
    let same_checkpoint =
        terminal_advance_from_current(&same_checkpoint_view, fixture.advance.batch().clone())?;
    assert!(verify_terminal_batch(&fixture, &same_checkpoint).is_err());

    let mut ready_view = fixture.advance.current().view().clone();
    let ready_head = current_effect_head_mut(&mut ready_view)?;
    let EconomicContentV1::Inline { value } = &ready_head.state else {
        return Err(ChannelError::AuthorityVerification);
    };
    let mut ready_effect: EconomicEffectSlotV1 =
        serde_json::from_value(value.clone()).map_err(|_| ChannelError::AuthorityVerification)?;
    ready_effect.state = EconomicEffectStateV1::Ready;
    ready_effect.terminal = None;
    let ready_content = EconomicContentV1::Inline {
        value: serde_json::to_value(&ready_effect)
            .map_err(|error| ChannelError::Canonicalization(error.to_string()))?,
    };
    ready_head.state_digest = ready_content
        .digest()
        .map_err(|_| ChannelError::AuthorityVerification)?;
    ready_head.state = ready_content;
    ready_head.lifecycle_state = "ready".to_owned();
    let ready_view = verified_modified_view(ready_view)?;
    let uncommitted = terminal_advance_from_current(&ready_view, fixture.advance.batch().clone())?;
    assert!(verify_terminal_batch(&fixture, &uncommitted).is_err());

    let mut wrong_predecessor_view = fixture.advance.current().view().clone();
    current_effect_head_mut(&mut wrong_predecessor_view)?.predecessor_digest =
        Some(digest("wrong-ready-effect-head"));
    let wrong_predecessor_view = verified_modified_view(wrong_predecessor_view)?;
    let wrong_predecessor =
        terminal_advance_from_current(&wrong_predecessor_view, fixture.advance.batch().clone())?;
    assert!(verify_terminal_batch(&fixture, &wrong_predecessor).is_err());

    let mut skipped_head_view = fixture.advance.current().view().clone();
    let skipped_head = current_effect_head_mut(&mut skipped_head_view)?;
    skipped_head.head_version = 3;
    skipped_head.resource_version = 3;
    skipped_head.lifecycle_fence = 3;
    let skipped_head_view = verified_modified_view(skipped_head_view)?;
    let mut skipped_batch = fixture.advance.batch().clone();
    let effect_index = transition_index(&skipped_batch, "effect_slot")?;
    skipped_batch.transitions[effect_index]
        .next_head
        .head_version = 4;
    skipped_batch.transitions[effect_index]
        .next_head
        .resource_version = 4;
    skipped_batch.transitions[effect_index]
        .next_head
        .lifecycle_fence = 4;
    let skipped = terminal_advance_from_current(&skipped_head_view, skipped_batch)?;
    assert!(verify_terminal_batch(&fixture, &skipped).is_err());
    Ok(())
}

#[test]
fn terminal_advance_zero_charge_consumes_the_reservation_without_an_obligation(
) -> Result<(), ChannelError> {
    let fixture = terminal_advance_fixture_with_charge(0)?;
    let verified = verify_terminal_fixture(&fixture)?;
    assert_eq!(verified.actual_charge().units, 0);
    assert!(verified.obligation_atom_id().is_none());
    assert!(verified.obligation_atom_digest().is_none());
    assert_eq!(verified.next_state().body().cumulative_owed.units, 0);
    Ok(())
}
