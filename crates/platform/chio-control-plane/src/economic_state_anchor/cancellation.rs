use super::*;

pub(super) fn compare_and_swap(
    anchor: &RemoteEconomicStateAnchor,
    advance: VerifiedEconomicEffectCancellationAdvance,
) -> Result<VerifiedEconomicEffectNotDispatched, EconomicStateAnchorError> {
    reverify_economic_effect_cancellation_advance(
        &advance,
        &anchor.pins,
        anchor.transition_verifier.as_ref(),
        anchor.cancellation_verifier.as_ref(),
        anchor.admission_verifier.as_ref(),
    )?;
    let committed = match anchor.post(ECONOMIC_EFFECT_CANCELLATION_PATH, advance.batch()) {
        Ok(view) => verify_economic_state_view(view, &anchor.pins)?,
        Err(_) => recover_exact_commit(anchor, &advance)?,
    };
    verify_economic_effect_cancellation_commit(advance, &committed, &anchor.pins)
}

fn recover_exact_commit(
    anchor: &RemoteEconomicStateAnchor,
    advance: &VerifiedEconomicEffectCancellationAdvance,
) -> Result<VerifiedEconomicStateView, EconomicStateAnchorError> {
    let batch = advance.batch();
    let query = EconomicCheckpointReadQuery {
        checkpoint_sequence: batch.checkpoint_sequence,
        checkpoint_digest: batch.checkpoint_digest.clone(),
        query: EconomicStateReadQuery {
            resource_keys: vec![advance.slot().resource_head_key()],
            request_keys: Vec::new(),
        },
    };
    anchor.read_checkpoint_state(&query)
}
