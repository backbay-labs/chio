use super::*;

pub(super) fn reconcile_participation_fee_intent(
    store: &SqliteFindingMarketStore,
    rail: &dyn FindingRailObserver,
    intent: &FindingFeeEventRecord,
) -> Result<u64, Response> {
    let FindingFeeEvent::ParticipationEpoch { epoch_index } = intent.event else {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "stored fee intent is not a participation renewal",
        ));
    };
    let instruction = FindingRailInstruction {
        idempotency_key: intent.idempotency_key.clone(),
        payer: intent.payer.clone(),
        amount_units: intent.amount_units,
        currency: intent.currency.clone(),
        pool_principal_id: intent.pool_principal_id.clone(),
        rail_destination: intent.rail_destination.clone(),
    };
    let instruction_sha256 = canonical_digest_of(&instruction)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error))?;
    if instruction_sha256 != intent.instruction_sha256 {
        return Err(plain_http_error(
            StatusCode::BAD_REQUEST,
            "stored participation intent does not match its rail instruction",
        ));
    }
    let observation = rail.dispatch(&instruction).map_err(|reason| {
        let _ = store.mark_fee_failed(&intent.idempotency_key);
        plain_http_error(
            StatusCode::BAD_GATEWAY,
            &format!("rail dispatch failed: {reason}"),
        )
    })?;
    if !super::super::finding_challenge_coordinator::rail_observation_matches(
        &instruction,
        &instruction_sha256,
        &observation,
    ) {
        let _ = store.mark_fee_failed(&intent.idempotency_key);
        return Err(plain_http_error(
            StatusCode::BAD_GATEWAY,
            "rail observation does not reconcile to the dispatched instruction",
        ));
    }
    let observation_sha256 = canonical_digest_of(&observation)
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error))?;
    let amount = MonetaryAmount {
        units: intent.amount_units,
        currency: intent.currency.clone(),
    };
    store
        .mark_fee_reconciled(
            &intent.idempotency_key,
            &observation_sha256,
            &amount,
            &intent.rail_destination,
        )
        .map_err(|error| plain_http_error(StatusCode::BAD_REQUEST, &error.to_string()))?;
    Ok(epoch_index)
}
