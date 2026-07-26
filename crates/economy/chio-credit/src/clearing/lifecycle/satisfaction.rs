use super::*;

pub const CLEARING_ROUND_SATISFACTION_SCHEMA: &str = "chio.clearing.round-satisfaction.v1";

const INTENT_PROGRESS_ROOT_DOMAIN: &[u8] = b"chio.clearing.intent-progress-root.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundSatisfactionBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub round_core_digest: String,
    pub output_manifest_digest: String,
    pub finalization_digest: String,
    pub settlement_intent_root: String,
    pub settlement_intent_count: u64,
    pub intent_progress_root: String,
    pub reservation_root: String,
    pub reservation_count: u64,
    pub reservation_head_root: String,
    pub source_lifecycle_head_digest: String,
    pub source_lifecycle_version: u64,
    pub source_lifecycle_fence: u64,
    pub next_lifecycle_version: u64,
    pub next_lifecycle_fence: u64,
    pub authority_digest: String,
    pub disposition_authority_id: String,
    pub disposition_authority_key_epoch: u64,
    pub satisfied_at_unix_ms: u64,
}

impl ClearingRoundSatisfactionBodyV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ROUND_SATISFACTION_SCHEMA {
            return Err(ClearingError::InvalidField("round_satisfaction_schema"));
        }
        validate_text("satisfaction_round_id", &self.round_id)?;
        for (field, value) in [
            ("satisfaction_round_core_digest", &self.round_core_digest),
            (
                "satisfaction_output_manifest_digest",
                &self.output_manifest_digest,
            ),
            (
                "satisfaction_finalization_digest",
                &self.finalization_digest,
            ),
            (
                "satisfaction_settlement_intent_root",
                &self.settlement_intent_root,
            ),
            (
                "satisfaction_intent_progress_root",
                &self.intent_progress_root,
            ),
            ("satisfaction_reservation_root", &self.reservation_root),
            (
                "satisfaction_reservation_head_root",
                &self.reservation_head_root,
            ),
            (
                "satisfaction_source_lifecycle_head_digest",
                &self.source_lifecycle_head_digest,
            ),
            ("satisfaction_authority_digest", &self.authority_digest),
        ] {
            validate_digest(field, value)?;
        }
        validate_positive(
            "satisfaction_settlement_intent_count",
            self.settlement_intent_count,
        )?;
        validate_positive("satisfaction_reservation_count", self.reservation_count)?;
        if usize::try_from(self.settlement_intent_count)
            .map_err(|_| ClearingError::ArithmeticOverflow)?
            > MAX_CLEARING_SETTLEMENT_INTENTS
            || usize::try_from(self.reservation_count)
                .map_err(|_| ClearingError::ArithmeticOverflow)?
                > MAX_CLEARING_INPUTS
        {
            return Err(ClearingError::InvalidField("round_satisfaction_count"));
        }
        validate_positive(
            "satisfaction_source_lifecycle_version",
            self.source_lifecycle_version,
        )?;
        validate_positive(
            "satisfaction_source_lifecycle_fence",
            self.source_lifecycle_fence,
        )?;
        validate_positive(
            "satisfaction_next_lifecycle_version",
            self.next_lifecycle_version,
        )?;
        validate_positive(
            "satisfaction_next_lifecycle_fence",
            self.next_lifecycle_fence,
        )?;
        validate_text(
            "satisfaction_disposition_authority_id",
            &self.disposition_authority_id,
        )?;
        validate_positive(
            "satisfaction_disposition_authority_key_epoch",
            self.disposition_authority_key_epoch,
        )?;
        validate_positive("satisfied_at_unix_ms", self.satisfied_at_unix_ms)?;
        let next = increment(self.source_lifecycle_version)?;
        if self.source_lifecycle_version != self.source_lifecycle_fence
            || self.next_lifecycle_version != next
            || self.next_lifecycle_fence != next
        {
            return Err(ClearingError::InvalidField("round_satisfaction_fence"));
        }
        Ok(())
    }
}

pub type SignedClearingRoundSatisfactionV1 =
    SignedClearingEnvelopeV1<ClearingRoundSatisfactionBodyV1>;

pub fn prepare_clearing_round_satisfaction(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    trust: &ClearingAuthorityTrustV1,
    authority_digest: String,
    satisfied_at_unix_ms: u64,
) -> Result<ClearingRoundSatisfactionBodyV1, ClearingError> {
    trust.validate()?;
    current_round_head
        .validate()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(current_round_head)?;
    record.validate()?;
    validate_round_head(current_round_head, &record)?;
    if !matches!(
        record.state,
        ClearingRoundLifecycleStateV1::Dispatching
            | ClearingRoundLifecycleStateV1::Reconciling
            | ClearingRoundLifecycleStateV1::Incident
    ) || satisfied_at_unix_ms < current_round_head.trusted_clock_high_water
        || satisfied_at_unix_ms > trust.trusted_time_unix_ms
        || reservations
            .iter()
            .any(|reservation| reservation.head.trusted_clock_high_water > satisfied_at_unix_ms)
    {
        return Err(ClearingError::IllegalLifecycleTransition);
    }
    let mut output_trust = trust.clone();
    output_trust.trusted_time_unix_ms = request.generated_at_unix_ms;
    let output = verify_signed_netting_round(request, &output_trust, signed_output)?;
    validate_completed_intents(&record, &output)?;
    let output_manifest_digest = output.output_manifest.digest()?;
    let finalization_digest = record
        .finalization_digest
        .clone()
        .ok_or(ClearingError::IllegalLifecycleTransition)?;
    if record.round_id != output.core.round_id
        || record.round_core_digest != output.core.digest()?
        || record.output_manifest_digest.as_deref() != Some(output_manifest_digest.as_str())
        || record.reservation_root != output.core.reservation_root
        || record.reservation_count != output.core.input_count
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let mut reservation_bindings = reservations
        .iter()
        .map(|reservation| reservation_binding(&record, reservation))
        .collect::<Result<Vec<_>, _>>()?;
    reservation_bindings.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let body = ClearingRoundSatisfactionBodyV1 {
        schema: CLEARING_ROUND_SATISFACTION_SCHEMA.to_owned(),
        round_id: record.round_id.clone(),
        round_core_digest: record.round_core_digest.clone(),
        output_manifest_digest,
        finalization_digest,
        settlement_intent_root: output.output_manifest.settlement_intent_root.clone(),
        settlement_intent_count: output.output_manifest.settlement_intent_count,
        intent_progress_root: intent_progress_root(&record.intent_progress)?,
        reservation_root: record.reservation_root.clone(),
        reservation_count: record.reservation_count,
        reservation_head_root: reservation_head_root(&reservation_bindings)?,
        source_lifecycle_head_digest: current_round_head
            .digest()
            .map_err(|_| ClearingError::InvalidField("current_round_head"))?,
        source_lifecycle_version: record.row_version,
        source_lifecycle_fence: record.fence,
        next_lifecycle_version: increment(record.row_version)?,
        next_lifecycle_fence: increment(record.fence)?,
        authority_digest,
        disposition_authority_id: trust.obligation_authority_id.clone(),
        disposition_authority_key_epoch: trust.obligation_key_epoch,
        satisfied_at_unix_ms,
    };
    body.validate()?;
    Ok(body)
}

pub fn compose_clearing_satisfaction_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    signed_satisfaction: &SignedClearingRoundSatisfactionV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    let body = &signed_satisfaction.body;
    let expected = prepare_clearing_round_satisfaction(
        current_round_head,
        reservations,
        request,
        signed_output,
        trust,
        body.authority_digest.clone(),
        body.satisfied_at_unix_ms,
    )?;
    if expected != *body
        || signed_satisfaction.signer_key != trust.obligation_authority_key
        || !signed_satisfaction.verify_signature()?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    compose_lifecycle_transition(
        current_round_head,
        reservations,
        ClearingRoundTransitionV1::Satisfy {
            satisfaction_digest: signed_satisfaction.digest()?,
            authority_digest: body.authority_digest.clone(),
        },
        body.satisfied_at_unix_ms,
    )
}

pub(super) fn validate_completed_intents(
    record: &ClearingRoundLifecycleRecordV1,
    output: &ClearingRoundOutputV1,
) -> Result<(), ClearingError> {
    if output.intents.is_empty()
        || output.intents.len() != record.intent_progress.len()
        || u64::try_from(record.intent_progress.len())
            .map_err(|_| ClearingError::ArithmeticOverflow)?
            != output.output_manifest.settlement_intent_count
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    for intent in &output.intents {
        let index = record
            .intent_progress
            .binary_search_by(|progress| progress.intent_id.cmp(&intent.intent_id))
            .map_err(|_| ClearingError::IncompleteLifecycleProjection)?;
        let progress = &record.intent_progress[index];
        if progress.intent_digest != intent.digest()?
            || progress.completed_effect_slot_id.is_none()
            || progress.active_effect_slot_id.is_some()
            || progress.unknown_effect_slot_id.is_some()
        {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
    }
    Ok(())
}

pub(super) fn intent_progress_root(
    progress: &[ClearingIntentProgressV1],
) -> Result<String, ClearingError> {
    if progress.is_empty() {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    domain_digest(INTENT_PROGRESS_ROOT_DOMAIN, &progress)
}
