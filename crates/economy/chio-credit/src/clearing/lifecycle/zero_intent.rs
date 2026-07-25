use super::*;

pub const CLEARING_ZERO_INTENT_RECONCILIATION_SCHEMA: &str =
    "chio.clearing.zero-intent-reconciliation.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingZeroIntentOutcomeV1 {
    NettedWithoutRail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingZeroIntentAtomBindingV1 {
    pub source_sequence: u64,
    pub obligation_id: String,
    pub expected_head_digest: String,
    pub expected_resource_version: u64,
    pub expected_lifecycle_fence: u64,
}

impl ClearingZeroIntentAtomBindingV1 {
    fn validate(&self) -> Result<(), ClearingError> {
        validate_positive("zero_intent_source_sequence", self.source_sequence)?;
        validate_digest("zero_intent_obligation_id", &self.obligation_id)?;
        validate_digest(
            "zero_intent_expected_head_digest",
            &self.expected_head_digest,
        )?;
        validate_positive(
            "zero_intent_expected_resource_version",
            self.expected_resource_version,
        )?;
        validate_positive(
            "zero_intent_expected_lifecycle_fence",
            self.expected_lifecycle_fence,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingZeroIntentReconciliationBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub round_core_digest: String,
    pub output_manifest_digest: String,
    pub finalization_digest: String,
    pub empty_intent_root: String,
    pub settlement_intent_count: u64,
    pub reservation_root: String,
    pub reservation_count: u64,
    pub atom_bindings: Vec<ClearingZeroIntentAtomBindingV1>,
    pub outcome: ClearingZeroIntentOutcomeV1,
    pub source_lifecycle_head_digest: String,
    pub source_lifecycle_version: u64,
    pub source_lifecycle_fence: u64,
    pub next_lifecycle_version: u64,
    pub next_lifecycle_fence: u64,
    pub authority_digest: String,
    pub disposition_authority_id: String,
    pub disposition_authority_key_epoch: u64,
    pub reconciled_at_unix_ms: u64,
}

impl ClearingZeroIntentReconciliationBodyV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ZERO_INTENT_RECONCILIATION_SCHEMA {
            return Err(ClearingError::InvalidField(
                "zero_intent_reconciliation_schema",
            ));
        }
        validate_text("zero_intent_round_id", &self.round_id)?;
        for (field, value) in [
            ("zero_intent_round_core_digest", &self.round_core_digest),
            (
                "zero_intent_output_manifest_digest",
                &self.output_manifest_digest,
            ),
            ("zero_intent_finalization_digest", &self.finalization_digest),
            ("zero_intent_empty_intent_root", &self.empty_intent_root),
            ("zero_intent_reservation_root", &self.reservation_root),
            (
                "zero_intent_source_lifecycle_head_digest",
                &self.source_lifecycle_head_digest,
            ),
            ("zero_intent_authority_digest", &self.authority_digest),
        ] {
            validate_digest(field, value)?;
        }
        if self.settlement_intent_count != 0 {
            return Err(ClearingError::InvalidField(
                "zero_intent_settlement_intent_count",
            ));
        }
        validate_positive("zero_intent_reservation_count", self.reservation_count)?;
        if usize::try_from(self.reservation_count).map_err(|_| ClearingError::ArithmeticOverflow)?
            > MAX_CLEARING_INPUTS
        {
            return Err(ClearingError::InvalidField("zero_intent_reservation_count"));
        }
        let source_sequences = self
            .atom_bindings
            .iter()
            .map(|binding| binding.source_sequence)
            .collect::<BTreeSet<_>>();
        if u64::try_from(self.atom_bindings.len()).map_err(|_| ClearingError::ArithmeticOverflow)?
            != self.reservation_count
            || source_sequences.len() != self.atom_bindings.len()
            || !self
                .atom_bindings
                .windows(2)
                .all(|pair| pair[0].obligation_id < pair[1].obligation_id)
        {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        for binding in &self.atom_bindings {
            binding.validate()?;
        }
        validate_positive(
            "zero_intent_source_lifecycle_version",
            self.source_lifecycle_version,
        )?;
        validate_positive(
            "zero_intent_source_lifecycle_fence",
            self.source_lifecycle_fence,
        )?;
        validate_positive(
            "zero_intent_next_lifecycle_version",
            self.next_lifecycle_version,
        )?;
        validate_positive(
            "zero_intent_next_lifecycle_fence",
            self.next_lifecycle_fence,
        )?;
        validate_text(
            "zero_intent_disposition_authority_id",
            &self.disposition_authority_id,
        )?;
        validate_positive(
            "zero_intent_disposition_authority_key_epoch",
            self.disposition_authority_key_epoch,
        )?;
        validate_positive(
            "zero_intent_reconciled_at_unix_ms",
            self.reconciled_at_unix_ms,
        )?;
        let next = increment(self.source_lifecycle_version)?;
        if self.source_lifecycle_version != self.source_lifecycle_fence
            || self.next_lifecycle_version != next
            || self.next_lifecycle_fence != next
        {
            return Err(ClearingError::InvalidField("zero_intent_fence"));
        }
        Ok(())
    }
}

pub type SignedClearingZeroIntentReconciliationV1 =
    SignedClearingEnvelopeV1<ClearingZeroIntentReconciliationBodyV1>;

pub fn prepare_clearing_zero_intent_reconciliation(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    trust: &ClearingAuthorityTrustV1,
    authority_digest: String,
    reconciled_at_unix_ms: u64,
) -> Result<ClearingZeroIntentReconciliationBodyV1, ClearingError> {
    trust.validate()?;
    current_round_head
        .validate()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(current_round_head)?;
    record.validate()?;
    validate_round_head(current_round_head, &record)?;
    if record.state != ClearingRoundLifecycleStateV1::Finalized
        || !record.intent_progress.is_empty()
        || record.first_dispatch_operation_id.is_some()
        || reconciled_at_unix_ms < current_round_head.trusted_clock_high_water
        || reconciled_at_unix_ms > trust.trusted_time_unix_ms
        || reservations
            .iter()
            .any(|reservation| reservation.head.trusted_clock_high_water > reconciled_at_unix_ms)
    {
        return Err(ClearingError::IllegalLifecycleTransition);
    }
    let mut output_trust = trust.clone();
    output_trust.trusted_time_unix_ms = request.generated_at_unix_ms;
    let output = verify_signed_netting_round(request, &output_trust, signed_output)?;
    let output_manifest_digest = output.output_manifest.digest()?;
    if !output.intents.is_empty()
        || output.output_manifest.settlement_intent_count != 0
        || record.round_id != output.core.round_id
        || record.round_core_digest != output.core.digest()?
        || record.output_manifest_digest.as_deref() != Some(output_manifest_digest.as_str())
        || record.reservation_root != output.core.reservation_root
        || record.reservation_count != output.core.input_count
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let mut atom_bindings = reservations
        .iter()
        .map(|reservation| {
            reservation_binding(&record, reservation)?;
            Ok(ClearingZeroIntentAtomBindingV1 {
                source_sequence: reservation.input.source_sequence,
                obligation_id: reservation.input.atom.obligation_id().to_owned(),
                expected_head_digest: reservation
                    .head
                    .digest()
                    .map_err(|_| ClearingError::InvalidField("obligation_head"))?,
                expected_resource_version: reservation.head.resource_version,
                expected_lifecycle_fence: reservation.head.lifecycle_fence,
            })
        })
        .collect::<Result<Vec<_>, ClearingError>>()?;
    atom_bindings.sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));
    let body = ClearingZeroIntentReconciliationBodyV1 {
        schema: CLEARING_ZERO_INTENT_RECONCILIATION_SCHEMA.to_owned(),
        round_id: record.round_id.clone(),
        round_core_digest: record.round_core_digest.clone(),
        output_manifest_digest,
        finalization_digest: record
            .finalization_digest
            .clone()
            .ok_or(ClearingError::IllegalLifecycleTransition)?,
        empty_intent_root: output.output_manifest.settlement_intent_root.clone(),
        settlement_intent_count: 0,
        reservation_root: record.reservation_root.clone(),
        reservation_count: record.reservation_count,
        atom_bindings,
        outcome: ClearingZeroIntentOutcomeV1::NettedWithoutRail,
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
        reconciled_at_unix_ms,
    };
    body.validate()?;
    Ok(body)
}

pub fn compose_clearing_zero_intent_reconciliation_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    signed_reconciliation: &SignedClearingZeroIntentReconciliationV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    let body = &signed_reconciliation.body;
    let expected = prepare_clearing_zero_intent_reconciliation(
        current_round_head,
        reservations,
        request,
        signed_output,
        trust,
        body.authority_digest.clone(),
        body.reconciled_at_unix_ms,
    )?;
    if expected != *body
        || signed_reconciliation.signer_key != trust.obligation_authority_key
        || !signed_reconciliation.verify_signature()?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    compose_zero_intent_lifecycle_transition(
        current_round_head,
        reservations,
        ClearingRoundTransitionV1::Satisfy {
            satisfaction_digest: signed_reconciliation.digest()?,
            authority_digest: body.authority_digest.clone(),
        },
        body.reconciled_at_unix_ms,
    )
}
