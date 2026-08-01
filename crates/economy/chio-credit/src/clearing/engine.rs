use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Clone)]
struct ParticipantRoute {
    participant_id: String,
    settlement_destination: String,
}

#[derive(Default)]
struct ParticipantTotals {
    gross_debit: u128,
    gross_credit: u128,
    bilateral_debit_cancelled: u128,
    bilateral_credit_cancelled: u128,
    atom_digests: BTreeSet<String>,
}

struct AggregatedRound {
    totals: BTreeMap<String, ParticipantTotals>,
    directed: DirectedAmounts,
    transformations: Vec<ClearingAtomTransformationV1>,
}

pub fn compute_netting_round(
    request: &ClearingRoundRequestV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<ClearingRoundOutputV1, ClearingError> {
    trust.validate()?;
    validate_request(request, trust)?;
    let identity_routes = participant_routes(&request.participant_snapshot.body)?;
    let mut obligations = request.obligations.iter().collect::<Vec<_>>();
    obligations.sort_by_key(|input| input.source_sequence);
    validate_obligations(request, &obligations)?;

    let participant_snapshot_digest =
        domain_digest(SNAPSHOT_DIGEST_DOMAIN, &request.participant_snapshot.body)?;
    let input_manifest_digest =
        domain_digest(INPUT_MANIFEST_DIGEST_DOMAIN, &request.input_manifest.body)?;
    let reservation_root = clearing_reservation_root(&request.obligations)?;
    let core = NettingRoundCoreV1 {
        schema: CLEARING_ROUND_CORE_SCHEMA.to_owned(),
        round_id: request.round_id.clone(),
        epoch: request.epoch,
        governance_scope_id: request.governance_scope_id.clone(),
        clearing_authority_id: trust.clearing_authority_id.clone(),
        clearing_authority_key_epoch: trust.clearing_authority_key_epoch,
        currency: request.currency.clone(),
        algorithm_version: request.algorithm_version.clone(),
        participant_snapshot_digest,
        input_manifest_digest,
        input_count: checked_count(obligations.len())?,
        reservation_root: reservation_root.clone(),
        dispute_window_ends_at_unix_ms: request.dispute_window_ends_at_unix_ms,
        generated_at_unix_ms: request.generated_at_unix_ms,
    };
    let round_core_digest = core.digest()?;

    let AggregatedRound {
        mut totals,
        directed,
        transformations,
    } = aggregate(
        &obligations,
        &identity_routes,
        &round_core_digest,
        &request.currency,
    )?;
    apply_bilateral_cancellation(&directed, &mut totals)?;
    let participant_statements = statements(&round_core_digest, totals)?;
    let intents = intents(
        &round_core_digest,
        &request.currency,
        &reservation_root,
        &participant_statements,
        &identity_routes,
    )?;
    let statement_digests = participant_statements
        .iter()
        .map(|statement| domain_digest(STATEMENT_DIGEST_DOMAIN, statement))
        .collect::<Result<Vec<_>, _>>()?;
    let intent_digests = intents
        .iter()
        .map(|intent| domain_digest(INTENT_DIGEST_DOMAIN, intent))
        .collect::<Result<Vec<_>, _>>()?;
    let transformation_digests = transformations
        .iter()
        .map(|transformation| domain_digest(TRANSFORMATION_DIGEST_DOMAIN, transformation))
        .collect::<Result<Vec<_>, _>>()?;
    let output_manifest = ClearingOutputManifestV1 {
        schema: CLEARING_OUTPUT_MANIFEST_SCHEMA.to_owned(),
        round_core_digest,
        participant_statement_root: domain_digest(STATEMENT_ROOT_DOMAIN, &statement_digests)?,
        participant_statement_count: checked_count(participant_statements.len())?,
        settlement_intent_root: domain_digest(INTENT_ROOT_DOMAIN, &intent_digests)?,
        settlement_intent_count: checked_count(intents.len())?,
        atom_transformation_root: domain_digest(
            TRANSFORMATION_ROOT_DOMAIN,
            &transformation_digests,
        )?,
        atom_transformation_count: checked_count(transformations.len())?,
    };
    Ok(ClearingRoundOutputV1 {
        core,
        participant_statements,
        intents,
        transformations,
        output_manifest,
    })
}

pub fn verify_netting_round(
    request: &ClearingRoundRequestV1,
    trust: &ClearingAuthorityTrustV1,
    output: &ClearingRoundOutputV1,
) -> Result<(), ClearingError> {
    if compute_netting_round(request, trust)? == *output {
        Ok(())
    } else {
        Err(ClearingError::InvalidField("round_output"))
    }
}

pub fn sign_netting_round(
    request: &ClearingRoundRequestV1,
    output: &ClearingRoundOutputV1,
    trust: &ClearingAuthorityTrustV1,
    signer: &Keypair,
) -> Result<SignedClearingRoundOutputV1, ClearingError> {
    trust.validate()?;
    verify_netting_round(request, trust, output)?;
    if signer.public_key() != trust.clearing_authority_key
        || output.core.clearing_authority_id != trust.clearing_authority_id
        || output.core.clearing_authority_key_epoch != trust.clearing_authority_key_epoch
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(SignedClearingRoundOutputV1 {
        core: SignedNettingRoundCoreV1::sign(output.core.clone(), signer)?,
        participant_statements: output
            .participant_statements
            .iter()
            .cloned()
            .map(|statement| SignedClearingParticipantStatementV1::sign(statement, signer))
            .collect::<Result<Vec<_>, _>>()?,
        intents: output
            .intents
            .iter()
            .cloned()
            .map(|intent| SignedClearingSettlementIntentV1::sign(intent, signer))
            .collect::<Result<Vec<_>, _>>()?,
        transformations: output
            .transformations
            .iter()
            .cloned()
            .map(|transformation| SignedClearingAtomTransformationV1::sign(transformation, signer))
            .collect::<Result<Vec<_>, _>>()?,
        output_manifest: SignedClearingOutputManifestV1::sign(
            output.output_manifest.clone(),
            signer,
        )?,
    })
}

pub fn verify_signed_netting_round(
    request: &ClearingRoundRequestV1,
    trust: &ClearingAuthorityTrustV1,
    signed: &SignedClearingRoundOutputV1,
) -> Result<ClearingRoundOutputV1, ClearingError> {
    trust.validate()?;
    let output = ClearingRoundOutputV1 {
        core: verified_body(&signed.core, &trust.clearing_authority_key)?,
        participant_statements: signed
            .participant_statements
            .iter()
            .map(|statement| verified_body(statement, &trust.clearing_authority_key))
            .collect::<Result<Vec<_>, _>>()?,
        intents: signed
            .intents
            .iter()
            .map(|intent| verified_body(intent, &trust.clearing_authority_key))
            .collect::<Result<Vec<_>, _>>()?,
        transformations: signed
            .transformations
            .iter()
            .map(|transformation| verified_body(transformation, &trust.clearing_authority_key))
            .collect::<Result<Vec<_>, _>>()?,
        output_manifest: verified_body(&signed.output_manifest, &trust.clearing_authority_key)?,
    };
    verify_netting_round(request, trust, &output)?;
    Ok(output)
}

fn verified_body<T>(
    envelope: &SignedClearingEnvelopeV1<T>,
    expected_key: &PublicKey,
) -> Result<T, ClearingError>
where
    T: Serialize + Clone,
{
    if &envelope.signer_key != expected_key || !envelope.verify_signature()? {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(envelope.body.clone())
}

fn validate_request(
    request: &ClearingRoundRequestV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<(), ClearingError> {
    validate_text("round_id", &request.round_id)?;
    validate_positive("epoch", request.epoch)?;
    validate_text("governance_scope_id", &request.governance_scope_id)?;
    validate_currency(&request.currency)?;
    if request.algorithm_version != CLEARING_ALGORITHM_V1 {
        return Err(ClearingError::InvalidField("algorithm_version"));
    }
    validate_positive(
        "dispute_window_ends_at_unix_ms",
        request.dispute_window_ends_at_unix_ms,
    )?;
    validate_positive("generated_at_unix_ms", request.generated_at_unix_ms)?;
    if request.generated_at_unix_ms > trust.trusted_time_unix_ms
        || request.dispute_window_ends_at_unix_ms <= request.generated_at_unix_ms
    {
        return Err(ClearingError::InvalidField("round_time"));
    }
    validate_participant_snapshot(&request.participant_snapshot, trust)?;
    validate_participant_acknowledgements(request, trust)?;
    validate_input_manifest(&request.input_manifest, trust)?;
    if request.participant_snapshot.body.algorithm_version != request.algorithm_version
        || request.input_manifest.body.epoch != request.epoch
        || request.generated_at_unix_ms < request.participant_snapshot.body.valid_from_unix_ms
        || request.generated_at_unix_ms < request.input_manifest.body.issued_at_unix_ms
        || request.dispute_window_ends_at_unix_ms
            > request.participant_snapshot.body.expires_at_unix_ms
    {
        return Err(ClearingError::InvalidField("round_binding"));
    }
    if request.obligations.is_empty() || request.obligations.len() > MAX_CLEARING_INPUTS {
        return Err(ClearingError::InvalidField("obligations"));
    }
    Ok(())
}

fn validate_participant_snapshot(
    snapshot: &SignedClearingParticipantSnapshotV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<(), ClearingError> {
    let body = &snapshot.body;
    if body.schema != CLEARING_PARTICIPANT_SNAPSHOT_SCHEMA
        || body.authority_id != trust.participant_authority_id
        || body.key_epoch != trust.participant_key_epoch
        || body.algorithm_version != CLEARING_ALGORITHM_V1
        || snapshot.signer_key != trust.participant_authority_key
    {
        return Err(ClearingError::AuthorityVerification);
    }
    if !snapshot
        .verify_signature()
        .map_err(|_| ClearingError::AuthorityVerification)?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    validate_positive("participant_key_epoch", body.key_epoch)?;
    validate_positive("snapshot_valid_from_unix_ms", body.valid_from_unix_ms)?;
    validate_positive("snapshot_expires_at_unix_ms", body.expires_at_unix_ms)?;
    if body.valid_from_unix_ms > trust.trusted_time_unix_ms
        || trust.trusted_time_unix_ms >= body.expires_at_unix_ms
        || body.participants.is_empty()
        || body.participants.len() > MAX_CLEARING_PARTICIPANTS
        || !strictly_sorted_by(&body.participants, |participant| {
            participant.participant_id.as_str()
        })
    {
        return Err(ClearingError::InvalidField("participant_snapshot"));
    }
    let mut identities = BTreeSet::new();
    for participant in &body.participants {
        validate_text("participant_id", &participant.participant_id)?;
        validate_text(
            "participant_settlement_destination",
            &participant.settlement_destination,
        )?;
        validate_positive(
            "participant_acknowledgement_key_epoch",
            participant.acknowledgement_key_epoch,
        )?;
        if participant.identities.is_empty()
            || participant.identities.len() > MAX_CLEARING_IDENTITIES_PER_PARTICIPANT
            || !strictly_sorted(&participant.identities)
        {
            return Err(ClearingError::InvalidField("participant_identities"));
        }
        for identity in &participant.identities {
            validate_text("participant_identity", identity)?;
            if !identities.insert(identity.as_str()) {
                return Err(ClearingError::ParticipantIdentity(identity.clone()));
            }
        }
    }
    Ok(())
}

fn validate_participant_acknowledgements(
    request: &ClearingRoundRequestV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<(), ClearingError> {
    let snapshot = &request.participant_snapshot.body;
    if request.participant_acknowledgements.len() != snapshot.participants.len()
        || !strictly_sorted_by(&request.participant_acknowledgements, |acknowledgement| {
            acknowledgement.body.participant_id.as_str()
        })
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let snapshot_digest = snapshot.digest()?;
    for (participant, acknowledgement) in snapshot
        .participants
        .iter()
        .zip(&request.participant_acknowledgements)
    {
        let body = &acknowledgement.body;
        if body.schema != CLEARING_PARTICIPANT_SNAPSHOT_ACKNOWLEDGEMENT_SCHEMA
            || body.participant_snapshot_digest != snapshot_digest
            || body.participant_id != participant.participant_id
            || body.algorithm_version != request.algorithm_version
            || body.key_epoch != participant.acknowledgement_key_epoch
            || acknowledgement.signer_key != participant.acknowledgement_key
            || body.accepted_at_unix_ms > trust.trusted_time_unix_ms
            || trust.trusted_time_unix_ms >= body.expires_at_unix_ms
            || body.expires_at_unix_ms > snapshot.expires_at_unix_ms
        {
            return Err(ClearingError::AuthorityVerification);
        }
        validate_positive("participant_acknowledged_at", body.accepted_at_unix_ms)?;
        validate_positive(
            "participant_acknowledgement_expires_at",
            body.expires_at_unix_ms,
        )?;
        if !acknowledgement
            .verify_signature()
            .map_err(|_| ClearingError::AuthorityVerification)?
        {
            return Err(ClearingError::AuthorityVerification);
        }
    }
    Ok(())
}

fn validate_input_manifest(
    manifest: &SignedClearingInputManifestV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<(), ClearingError> {
    let body = &manifest.body;
    if body.schema != CLEARING_INPUT_MANIFEST_SCHEMA
        || body.authority_id != trust.obligation_authority_id
        || body.key_epoch != trust.obligation_key_epoch
        || manifest.signer_key != trust.obligation_authority_key
    {
        return Err(ClearingError::AuthorityVerification);
    }
    if !manifest
        .verify_signature()
        .map_err(|_| ClearingError::AuthorityVerification)?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    validate_text("input_source_id", &body.source_id)?;
    validate_positive("input_epoch", body.epoch)?;
    validate_positive("range_start_sequence", body.range_start_sequence)?;
    validate_positive("range_end_sequence", body.range_end_sequence)?;
    validate_digest("start_checkpoint_digest", &body.start_checkpoint_digest)?;
    validate_digest("end_checkpoint_digest", &body.end_checkpoint_digest)?;
    validate_positive("input_key_epoch", body.key_epoch)?;
    validate_positive("input_issued_at_unix_ms", body.issued_at_unix_ms)?;
    validate_positive("input_expires_at_unix_ms", body.expires_at_unix_ms)?;
    if body.issued_at_unix_ms > trust.trusted_time_unix_ms
        || trust.trusted_time_unix_ms >= body.expires_at_unix_ms
        || body.issued_at_unix_ms >= body.expires_at_unix_ms
        || body.entries.is_empty()
        || body.entries.len() > MAX_CLEARING_INPUTS
        || body.has_more
        || body.next_cursor.is_some()
    {
        return Err(ClearingError::IncompleteManifest);
    }
    let span = body
        .range_end_sequence
        .checked_sub(body.range_start_sequence)
        .and_then(|distance| distance.checked_add(1))
        .ok_or(ClearingError::IncompleteManifest)?;
    if span != checked_count(body.entries.len())? {
        return Err(ClearingError::IncompleteManifest);
    }
    for (offset, entry) in body.entries.iter().enumerate() {
        let offset = u64::try_from(offset).map_err(|_| ClearingError::ArithmeticOverflow)?;
        let expected_sequence = body
            .range_start_sequence
            .checked_add(offset)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        if entry.source_sequence != expected_sequence {
            return Err(ClearingError::IncompleteManifest);
        }
        validate_digest("manifest_obligation_id", &entry.obligation_id)?;
        validate_digest("manifest_atom_digest", &entry.atom_digest)?;
        validate_digest("manifest_disposition_digest", &entry.disposition_digest)?;
        validate_positive("manifest_disposition_version", entry.disposition_version)?;
        validate_positive("manifest_lifecycle_fence", entry.lifecycle_fence)?;
        validate_text("manifest_round_id", &entry.round_id)?;
    }
    Ok(())
}

fn validate_obligations(
    request: &ClearingRoundRequestV1,
    obligations: &[&ClearingObligationInputV1],
) -> Result<(), ClearingError> {
    if obligations.len() != request.input_manifest.body.entries.len() {
        return Err(ClearingError::IncompleteManifest);
    }
    let mut obligation_ids = BTreeSet::new();
    let mut atom_digests = BTreeSet::new();
    for (input, expected) in obligations.iter().zip(&request.input_manifest.body.entries) {
        let actual = ClearingInputManifestEntryV1::from_reserved(input)?;
        if actual != *expected || actual.round_id != request.round_id {
            return Err(ClearingError::InvalidField("input_manifest_binding"));
        }
        if input.atom.amount().currency != request.currency {
            return Err(ClearingError::CurrencyMismatch);
        }
        if !obligation_ids.insert(input.atom.obligation_id())
            || !atom_digests.insert(actual.atom_digest)
        {
            return Err(ClearingError::DuplicateObligation);
        }
    }
    Ok(())
}

fn participant_routes(
    snapshot: &ClearingParticipantSnapshotBodyV1,
) -> Result<BTreeMap<String, ParticipantRoute>, ClearingError> {
    let mut routes = BTreeMap::new();
    for participant in &snapshot.participants {
        for identity in &participant.identities {
            let previous = routes.insert(
                identity.clone(),
                ParticipantRoute {
                    participant_id: participant.participant_id.clone(),
                    settlement_destination: participant.settlement_destination.clone(),
                },
            );
            if previous.is_some() {
                return Err(ClearingError::ParticipantIdentity(identity.clone()));
            }
        }
    }
    Ok(routes)
}

type DirectedAmounts = BTreeMap<(String, String), u128>;

fn aggregate(
    obligations: &[&ClearingObligationInputV1],
    routes: &BTreeMap<String, ParticipantRoute>,
    round_core_digest: &str,
    currency: &str,
) -> Result<AggregatedRound, ClearingError> {
    let mut totals = BTreeMap::<String, ParticipantTotals>::new();
    let mut directed = DirectedAmounts::new();
    let mut transformations = Vec::with_capacity(obligations.len());
    for input in obligations {
        let debtor = routes
            .get(input.atom.debtor_id())
            .ok_or_else(|| ClearingError::ParticipantIdentity(input.atom.debtor_id().to_owned()))?;
        let current_creditor = input.disposition.current_creditor(&input.atom)?;
        let creditor = routes.get(current_creditor.creditor_id()).ok_or_else(|| {
            ClearingError::ParticipantIdentity(current_creditor.creditor_id().to_owned())
        })?;
        if current_creditor.settlement_destination_ref() != creditor.settlement_destination {
            return Err(ClearingError::ParticipantIdentity(
                current_creditor.creditor_id().to_owned(),
            ));
        }
        let units = u128::from(input.atom.amount().units);
        checked_add(
            &mut totals
                .entry(debtor.participant_id.clone())
                .or_default()
                .gross_debit,
            units,
        )?;
        checked_add(
            &mut totals
                .entry(creditor.participant_id.clone())
                .or_default()
                .gross_credit,
            units,
        )?;
        let atom_digest = input.atom.digest()?;
        totals
            .entry(debtor.participant_id.clone())
            .or_default()
            .atom_digests
            .insert(atom_digest.clone());
        totals
            .entry(creditor.participant_id.clone())
            .or_default()
            .atom_digests
            .insert(atom_digest.clone());
        checked_add(
            directed
                .entry((
                    debtor.participant_id.clone(),
                    creditor.participant_id.clone(),
                ))
                .or_default(),
            units,
        )?;
        transformations.push(ClearingAtomTransformationV1 {
            schema: CLEARING_TRANSFORMATION_SCHEMA.to_owned(),
            round_core_digest: round_core_digest.to_owned(),
            source_sequence: input.source_sequence,
            obligation_id: input.atom.obligation_id().to_owned(),
            atom_digest,
            debtor_identity: input.atom.debtor_id().to_owned(),
            creditor_identity: current_creditor.creditor_id().to_owned(),
            debtor_participant_id: debtor.participant_id.clone(),
            creditor_participant_id: creditor.participant_id.clone(),
            amount: MonetaryAmount {
                currency: currency.to_owned(),
                units: input.atom.amount().units,
            },
        });
    }
    Ok(AggregatedRound {
        totals,
        directed,
        transformations,
    })
}

fn apply_bilateral_cancellation(
    directed: &DirectedAmounts,
    totals: &mut BTreeMap<String, ParticipantTotals>,
) -> Result<(), ClearingError> {
    let participants = totals.keys().cloned().collect::<Vec<_>>();
    for (index, left) in participants.iter().enumerate() {
        let self_flow = directed
            .get(&(left.clone(), left.clone()))
            .copied()
            .unwrap_or(0);
        if self_flow > 0 {
            let total = totals
                .get_mut(left)
                .ok_or_else(|| ClearingError::ParticipantIdentity(left.clone()))?;
            checked_add(&mut total.bilateral_debit_cancelled, self_flow)?;
            checked_add(&mut total.bilateral_credit_cancelled, self_flow)?;
        }
        for right in participants.iter().skip(index + 1) {
            let forward = directed
                .get(&(left.clone(), right.clone()))
                .copied()
                .unwrap_or(0);
            let reverse = directed
                .get(&(right.clone(), left.clone()))
                .copied()
                .unwrap_or(0);
            let cancelled = forward.min(reverse);
            if cancelled == 0 {
                continue;
            }
            for participant in [left, right] {
                let total = totals
                    .get_mut(participant)
                    .ok_or_else(|| ClearingError::ParticipantIdentity(participant.clone()))?;
                checked_add(&mut total.bilateral_debit_cancelled, cancelled)?;
                checked_add(&mut total.bilateral_credit_cancelled, cancelled)?;
            }
        }
    }
    Ok(())
}

fn statements(
    round_core_digest: &str,
    totals: BTreeMap<String, ParticipantTotals>,
) -> Result<Vec<ClearingParticipantStatementV1>, ClearingError> {
    totals
        .into_iter()
        .map(|(participant_id, total)| {
            let (direction, units) = if total.gross_debit > total.gross_credit {
                (
                    ClearingBalanceDirectionV1::Debit,
                    total
                        .gross_debit
                        .checked_sub(total.gross_credit)
                        .ok_or(ClearingError::ArithmeticOverflow)?,
                )
            } else if total.gross_credit > total.gross_debit {
                (
                    ClearingBalanceDirectionV1::Credit,
                    total
                        .gross_credit
                        .checked_sub(total.gross_debit)
                        .ok_or(ClearingError::ArithmeticOverflow)?,
                )
            } else {
                (ClearingBalanceDirectionV1::Zero, 0)
            };
            Ok(ClearingParticipantStatementV1 {
                schema: CLEARING_PARTICIPANT_STATEMENT_SCHEMA.to_owned(),
                round_core_digest: round_core_digest.to_owned(),
                participant_id,
                gross_debit_units: checked_u64(total.gross_debit)?,
                gross_credit_units: checked_u64(total.gross_credit)?,
                bilateral_debit_cancelled_units: checked_u64(total.bilateral_debit_cancelled)?,
                bilateral_credit_cancelled_units: checked_u64(total.bilateral_credit_cancelled)?,
                net_balance: ClearingBalanceV1 {
                    direction,
                    units: checked_u64(units)?,
                },
                contributing_atom_digests: total.atom_digests.into_iter().collect(),
            })
        })
        .collect()
}

fn intents(
    round_core_digest: &str,
    currency: &str,
    reservation_root: &str,
    statements: &[ClearingParticipantStatementV1],
    routes: &BTreeMap<String, ParticipantRoute>,
) -> Result<Vec<ClearingSettlementIntentV1>, ClearingError> {
    let mut debtors = Vec::<(String, u128)>::new();
    let mut creditors = Vec::<(String, u128)>::new();
    for statement in statements {
        match statement.net_balance.direction {
            ClearingBalanceDirectionV1::Debit => debtors.push((
                statement.participant_id.clone(),
                u128::from(statement.net_balance.units),
            )),
            ClearingBalanceDirectionV1::Credit => creditors.push((
                statement.participant_id.clone(),
                u128::from(statement.net_balance.units),
            )),
            ClearingBalanceDirectionV1::Zero => {}
        }
    }
    let total_debit = checked_sum(debtors.iter().map(|(_, units)| *units))?;
    let total_credit = checked_sum(creditors.iter().map(|(_, units)| *units))?;
    if total_debit != total_credit {
        return Err(ClearingError::ArithmeticOverflow);
    }
    let participant_destinations = routes
        .values()
        .map(|route| {
            (
                route.participant_id.clone(),
                route.settlement_destination.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut output = Vec::new();
    let (mut debtor_index, mut creditor_index) = (0, 0);
    while debtor_index < debtors.len() && creditor_index < creditors.len() {
        let (debtor_id, debtor_remaining) = &mut debtors[debtor_index];
        let (creditor_id, creditor_remaining) = &mut creditors[creditor_index];
        let units = (*debtor_remaining).min(*creditor_remaining);
        let ordinal = checked_count(output.len())?;
        let amount = MonetaryAmount {
            currency: currency.to_owned(),
            units: checked_u64(units)?,
        };
        let intent_id = domain_digest(
            INTENT_ID_DOMAIN,
            &(
                round_core_digest,
                ordinal,
                debtor_id.as_str(),
                creditor_id.as_str(),
                &amount,
            ),
        )?;
        output.push(ClearingSettlementIntentV1 {
            schema: CLEARING_SETTLEMENT_INTENT_SCHEMA.to_owned(),
            dispatch_idempotency_key: domain_digest(DISPATCH_KEY_DOMAIN, &intent_id)?,
            intent_id,
            round_core_digest: round_core_digest.to_owned(),
            ordinal,
            debtor_participant_id: debtor_id.clone(),
            creditor_participant_id: creditor_id.clone(),
            creditor_settlement_destination: participant_destinations
                .get(creditor_id)
                .cloned()
                .ok_or_else(|| ClearingError::ParticipantIdentity(creditor_id.clone()))?,
            amount,
            contributing_reservation_root: reservation_root.to_owned(),
        });
        *debtor_remaining = debtor_remaining
            .checked_sub(units)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        *creditor_remaining = creditor_remaining
            .checked_sub(units)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        if *debtor_remaining == 0 {
            debtor_index += 1;
        }
        if *creditor_remaining == 0 {
            creditor_index += 1;
        }
    }
    if debtor_index != debtors.len() || creditor_index != creditors.len() {
        return Err(ClearingError::ArithmeticOverflow);
    }
    Ok(output)
}

fn checked_add(target: &mut u128, value: u128) -> Result<(), ClearingError> {
    *target = target
        .checked_add(value)
        .ok_or(ClearingError::ArithmeticOverflow)?;
    Ok(())
}

fn checked_sum(mut values: impl Iterator<Item = u128>) -> Result<u128, ClearingError> {
    values.try_fold(0_u128, |sum, value| {
        sum.checked_add(value)
            .ok_or(ClearingError::ArithmeticOverflow)
    })
}

fn strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by<T>(values: &[T], key: impl Fn(&T) -> &str) -> bool {
    values.windows(2).all(|pair| key(&pair[0]) < key(&pair[1]))
}
