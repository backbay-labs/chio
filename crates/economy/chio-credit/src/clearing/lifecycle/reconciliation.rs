use chio_core_types::economic_continuity::{
    economic_effect_slot_from_head, EconomicEffectStateV1, EconomicEffectTerminalV1,
    EconomicNoEffectKindV1,
};

use super::*;

pub const CLEARING_SETTLEMENT_RECONCILIATION_SCHEMA: &str =
    "chio.clearing.settlement-reconciliation.v1";

const MAX_EXTERNAL_REFERENCES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingSettlementObservedStatusV1 {
    Settled,
    PermanentNoEffect,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingSettlementReconciliationBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub round_core_digest: String,
    pub output_manifest_digest: String,
    pub intent_id: String,
    pub intent_digest: String,
    pub effect_slot_id: String,
    pub source_effect_slot_digest: String,
    pub settlement_outcome_digest: String,
    pub external_references: Vec<String>,
    pub observed_status: ClearingSettlementObservedStatusV1,
    pub attempt_number: u64,
    pub source_lifecycle_head_digest: String,
    pub source_lifecycle_version: u64,
    pub source_lifecycle_fence: u64,
    pub next_lifecycle_version: u64,
    pub next_lifecycle_fence: u64,
    pub authority_digest: String,
    pub disposition_authority_id: String,
    pub disposition_authority_key_epoch: u64,
    pub observed_at_unix_ms: u64,
}

impl ClearingSettlementReconciliationBodyV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_SETTLEMENT_RECONCILIATION_SCHEMA {
            return Err(ClearingError::InvalidField(
                "settlement_reconciliation_schema",
            ));
        }
        validate_text("reconciliation_round_id", &self.round_id)?;
        validate_digest("reconciliation_round_core_digest", &self.round_core_digest)?;
        validate_digest(
            "reconciliation_output_manifest_digest",
            &self.output_manifest_digest,
        )?;
        validate_text("reconciliation_intent_id", &self.intent_id)?;
        validate_digest("reconciliation_intent_digest", &self.intent_digest)?;
        validate_digest("reconciliation_effect_slot_id", &self.effect_slot_id)?;
        validate_digest(
            "reconciliation_source_effect_slot_digest",
            &self.source_effect_slot_digest,
        )?;
        validate_digest(
            "reconciliation_settlement_outcome_digest",
            &self.settlement_outcome_digest,
        )?;
        if self.external_references.is_empty()
            || self.external_references.len() > MAX_EXTERNAL_REFERENCES
            || !self
                .external_references
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(ClearingError::InvalidField(
                "reconciliation_external_references",
            ));
        }
        for reference in &self.external_references {
            validate_text("reconciliation_external_reference", reference)?;
        }
        validate_positive("reconciliation_attempt_number", self.attempt_number)?;
        validate_digest(
            "reconciliation_source_lifecycle_head_digest",
            &self.source_lifecycle_head_digest,
        )?;
        validate_positive(
            "reconciliation_source_lifecycle_version",
            self.source_lifecycle_version,
        )?;
        validate_positive(
            "reconciliation_source_lifecycle_fence",
            self.source_lifecycle_fence,
        )?;
        validate_positive(
            "reconciliation_next_lifecycle_version",
            self.next_lifecycle_version,
        )?;
        validate_positive(
            "reconciliation_next_lifecycle_fence",
            self.next_lifecycle_fence,
        )?;
        validate_digest("reconciliation_authority_digest", &self.authority_digest)?;
        validate_text(
            "reconciliation_disposition_authority_id",
            &self.disposition_authority_id,
        )?;
        validate_positive(
            "reconciliation_disposition_authority_key_epoch",
            self.disposition_authority_key_epoch,
        )?;
        validate_positive(
            "reconciliation_observed_at_unix_ms",
            self.observed_at_unix_ms,
        )?;
        let next = self
            .source_lifecycle_version
            .checked_add(1)
            .filter(|version| *version <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        if self.source_lifecycle_version != self.source_lifecycle_fence
            || self.next_lifecycle_version != next
            || self.next_lifecycle_fence != next
        {
            return Err(ClearingError::InvalidField(
                "settlement_reconciliation_fence",
            ));
        }
        Ok(())
    }
}

pub type SignedClearingSettlementReconciliationV1 =
    SignedClearingEnvelopeV1<ClearingSettlementReconciliationBodyV1>;

pub trait ClearingSettlementOutcomeVerifier: Send + Sync {
    fn verify_outcome(
        &self,
        slot: &EconomicEffectSlotV1,
        settlement_outcome_digest: &str,
        external_references: &[String],
    ) -> Result<Option<EconomicEffectTerminalV1>, ClearingError>;
}

pub fn compose_clearing_reconciliation_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    current_effect_slot_head: &EconomicResourceHeadV1,
    signed_intent: &SignedClearingSettlementIntentV1,
    signed_reconciliation: &SignedClearingSettlementReconciliationV1,
    trust: &ClearingAuthorityTrustV1,
    outcome_verifier: &dyn ClearingSettlementOutcomeVerifier,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    let (current_slot, next_slot) = verify_reconciliation(
        current_round_head,
        current_effect_slot_head,
        signed_intent,
        signed_reconciliation,
        trust,
        outcome_verifier,
    )?;
    let body = &signed_reconciliation.body;
    let reconciliation_digest = signed_reconciliation.digest()?;
    let transition = match body.observed_status {
        ClearingSettlementObservedStatusV1::Settled
        | ClearingSettlementObservedStatusV1::PermanentNoEffect => {
            ClearingRoundTransitionV1::BeginReconciliation {
                reconciliation_digest,
                intent_id: body.intent_id.clone(),
                intent_digest: body.intent_digest.clone(),
                effect_slot_id: body.effect_slot_id.clone(),
                observed_status: body.observed_status,
                attempt_number: body.attempt_number,
                authority_digest: body.authority_digest.clone(),
            }
        }
        ClearingSettlementObservedStatusV1::Unknown => ClearingRoundTransitionV1::Incident {
            reconciliation_digest,
            intent_id: body.intent_id.clone(),
            intent_digest: body.intent_digest.clone(),
            effect_slot_id: body.effect_slot_id.clone(),
            attempt_number: body.attempt_number,
            authority_digest: body.authority_digest.clone(),
        },
    };
    let mut projection = compose_lifecycle_transition(
        current_round_head,
        reservations,
        transition,
        body.observed_at_unix_ms,
    )?;
    if projection.transitions.len() >= MAX_ECONOMIC_TRANSITIONS {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let proof_digest = projection.proof.digest()?;
    projection.transitions.push(EconomicStateTransitionV1 {
        resource_key: current_effect_slot_head.resource_key.clone(),
        expected_head_digest: Some(body.source_effect_slot_digest.clone()),
        next_head: next_effect_slot_head(
            current_effect_slot_head,
            &next_slot,
            body.observed_at_unix_ms,
        )?,
        transition_proof_digest: proof_digest,
        prepared_effect: None,
    });
    projection
        .transitions
        .sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    projection.operation_id = Some(current_slot.operation_id);
    Ok(projection)
}

pub(super) fn verify_reconciliation(
    current_round_head: &EconomicResourceHeadV1,
    current_effect_slot_head: &EconomicResourceHeadV1,
    signed_intent: &SignedClearingSettlementIntentV1,
    signed_reconciliation: &SignedClearingSettlementReconciliationV1,
    trust: &ClearingAuthorityTrustV1,
    outcome_verifier: &dyn ClearingSettlementOutcomeVerifier,
) -> Result<(EconomicEffectSlotV1, EconomicEffectSlotV1), ClearingError> {
    trust.validate()?;
    let body = &signed_reconciliation.body;
    body.validate()?;
    if signed_reconciliation.signer_key != trust.obligation_authority_key
        || body.disposition_authority_id != trust.obligation_authority_id
        || body.disposition_authority_key_epoch != trust.obligation_key_epoch
        || body.observed_at_unix_ms > trust.trusted_time_unix_ms
        || !signed_reconciliation.verify_signature()?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(current_round_head)?;
    record.validate()?;
    validate_round_head(current_round_head, &record)?;
    let current_slot = economic_effect_slot_from_head(current_effect_slot_head)
        .map_err(|_| ClearingError::AuthorityVerification)?;
    let intent_digest = signed_intent.body.digest()?;
    let signed_intent_digest = signed_intent.digest()?;
    if signed_intent.signer_key != trust.clearing_authority_key
        || !signed_intent.verify_signature()?
        || body.round_id != record.round_id
        || body.round_core_digest != record.round_core_digest
        || record.output_manifest_digest.as_deref() != Some(body.output_manifest_digest.as_str())
        || body.intent_id != signed_intent.body.intent_id
        || body.intent_digest != intent_digest
        || signed_intent.body.round_core_digest != record.round_core_digest
        || body.effect_slot_id != current_slot.slot_id
        || body.source_effect_slot_digest
            != current_effect_slot_head
                .digest()
                .map_err(|_| ClearingError::AuthorityVerification)?
        || body.source_lifecycle_head_digest
            != current_round_head
                .digest()
                .map_err(|_| ClearingError::AuthorityVerification)?
        || body.source_lifecycle_version != record.row_version
        || body.source_lifecycle_fence != record.fence
        || body.next_lifecycle_version
            != record
                .row_version
                .checked_add(1)
                .ok_or(ClearingError::ArithmeticOverflow)?
        || body.next_lifecycle_fence
            != record
                .fence
                .checked_add(1)
                .ok_or(ClearingError::ArithmeticOverflow)?
        || body.observed_at_unix_ms < current_round_head.trusted_clock_high_water
        || body.observed_at_unix_ms < current_effect_slot_head.trusted_clock_high_water
        || current_slot.resource_key != current_round_head.resource_key
        || current_slot.anchor_id != current_round_head.anchor_id
        || current_slot.namespace != current_round_head.namespace
        || current_slot.effect_kind != CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND
        || current_slot.action_digest != signed_intent_digest
        || current_slot.parameters_digest != intent_digest
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let progress = record
        .intent_progress
        .binary_search_by(|progress| progress.intent_id.cmp(&body.intent_id))
        .ok()
        .and_then(|index| record.intent_progress.get(index))
        .ok_or(ClearingError::AuthorityVerification)?;
    let expected_slot = match current_slot.state {
        EconomicEffectStateV1::DispatchCommitted => progress.active_effect_slot_id.as_deref(),
        EconomicEffectStateV1::Unknown => progress.unknown_effect_slot_id.as_deref(),
        _ => return Err(ClearingError::IllegalLifecycleTransition),
    };
    if progress.intent_digest != body.intent_digest
        || progress.attempt_count != body.attempt_number
        || expected_slot != Some(current_slot.slot_id.as_str())
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let terminal = outcome_verifier.verify_outcome(
        &current_slot,
        &body.settlement_outcome_digest,
        &body.external_references,
    )?;
    let mut next_slot = current_slot.clone();
    match (body.observed_status, terminal) {
        (
            ClearingSettlementObservedStatusV1::Settled,
            Some(terminal @ EconomicEffectTerminalV1::Completed { .. }),
        ) => {
            next_slot.state = EconomicEffectStateV1::Completed;
            next_slot.terminal = Some(terminal);
        }
        (
            ClearingSettlementObservedStatusV1::PermanentNoEffect,
            Some(terminal @ EconomicEffectTerminalV1::NoEffect { kind, .. }),
        ) if kind != EconomicNoEffectKindV1::PreDispatch => {
            next_slot.state = EconomicEffectStateV1::NoEffect;
            next_slot.terminal = Some(terminal);
        }
        (ClearingSettlementObservedStatusV1::Unknown, None)
            if current_slot.state == EconomicEffectStateV1::DispatchCommitted =>
        {
            next_slot.state = EconomicEffectStateV1::Unknown;
        }
        _ => return Err(ClearingError::AuthorityVerification),
    }
    current_slot
        .validate_successor(&next_slot)
        .map_err(|_| ClearingError::IllegalLifecycleTransition)?;
    Ok((current_slot, next_slot))
}

fn next_effect_slot_head(
    current: &EconomicResourceHeadV1,
    slot: &EconomicEffectSlotV1,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, ClearingError> {
    let state = inline_content(slot)?;
    let next = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: increment(current.head_version)?,
        resource_version: increment(current.resource_version)?,
        lifecycle_fence: increment(current.lifecycle_fence)?,
        lifecycle_state: match slot.state {
            EconomicEffectStateV1::Completed => "completed",
            EconomicEffectStateV1::NoEffect => "no_effect",
            EconomicEffectStateV1::Unknown => "unknown",
            _ => return Err(ClearingError::IllegalLifecycleTransition),
        }
        .to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ClearingError::InvalidField("reconciled_effect_slot"))?,
        state,
        operation_id: Some(slot.operation_id.clone()),
        effect_idempotency_key: Some(slot.idempotency_key.clone()),
        frost: slot.frost.clone(),
        terminal_result: None,
        trusted_clock_high_water,
        predecessor_digest: Some(
            current
                .digest()
                .map_err(|_| ClearingError::InvalidField("current_effect_slot"))?,
        ),
    };
    current
        .validate_successor(&next)
        .map_err(|_| ClearingError::InvalidField("next_effect_slot"))?;
    Ok(next)
}

pub(super) fn verify_reconciliation_projection(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
    proof: &ClearingRoundTransitionProofV1,
    expected_next_slot: Option<&EconomicEffectSlotV1>,
) -> Result<(), ClearingError> {
    let (intent_digest, effect_slot_id, status) = match &proof.transition {
        ClearingRoundTransitionV1::BeginReconciliation {
            intent_digest,
            effect_slot_id,
            observed_status,
            ..
        } => (intent_digest, effect_slot_id, *observed_status),
        ClearingRoundTransitionV1::Incident {
            intent_digest,
            effect_slot_id,
            ..
        } => (
            intent_digest,
            effect_slot_id,
            ClearingSettlementObservedStatusV1::Unknown,
        ),
        _ => return Err(ClearingError::IllegalLifecycleTransition),
    };
    let key = EconomicResourceKeyV1 {
        resource_family: "effect_slot".to_owned(),
        scope_id: proof.governance_scope_id.clone(),
        resource_id: effect_slot_id.clone(),
    };
    let transition = batch
        .transitions
        .iter()
        .find(|transition| transition.resource_key == key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    let current_head = current
        .view()
        .head(&key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    let current_slot = economic_effect_slot_from_head(current_head)
        .map_err(|_| ClearingError::IncompleteLifecycleProjection)?;
    let next_slot = economic_effect_slot_from_head(&transition.next_head)
        .map_err(|_| ClearingError::IncompleteLifecycleProjection)?;
    current_slot
        .validate_successor(&next_slot)
        .map_err(|_| ClearingError::IncompleteLifecycleProjection)?;
    let terminal_matches = matches!(
        (status, next_slot.state, next_slot.terminal.as_ref()),
        (
            ClearingSettlementObservedStatusV1::Settled,
            EconomicEffectStateV1::Completed,
            Some(EconomicEffectTerminalV1::Completed { .. })
        ) | (
            ClearingSettlementObservedStatusV1::PermanentNoEffect,
            EconomicEffectStateV1::NoEffect,
            Some(EconomicEffectTerminalV1::NoEffect { .. })
        ) | (
            ClearingSettlementObservedStatusV1::Unknown,
            EconomicEffectStateV1::Unknown,
            None
        )
    );
    if batch.operation_id.as_deref() != Some(current_slot.operation_id.as_str())
        || current_slot.slot_id != *effect_slot_id
        || current_slot.parameters_digest != *intent_digest
        || current_slot.effect_kind != CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND
        || transition.expected_head_digest.as_deref()
            != Some(
                current_head
                    .digest()
                    .map_err(|_| ClearingError::IncompleteLifecycleProjection)?
                    .as_str(),
            )
        || transition.prepared_effect.is_some()
        || next_slot.slot_id != *effect_slot_id
        || !terminal_matches
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    if expected_next_slot.is_some_and(|expected| expected != &next_slot) {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    Ok(())
}
