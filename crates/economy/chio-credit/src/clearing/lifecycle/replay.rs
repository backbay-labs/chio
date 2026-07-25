use std::sync::Arc;

use chio_federation::frost::{
    verify_burned_frost_authorization_slot, verify_historical_completed_authorization,
    FrostAnchoredAuthorizationSlot, FrostArtifactTrustStore, FrostAuthorizationSlotCheckpointV1,
    FrostAuthorizationV1, FrostHistoricalRosterResolver, FrostRosterResolutionError, FrostRosterV1,
};

use super::*;
use crate::clearing::finalization::verify_historical_clearing_round_finalization;

pub const CLEARING_LIFECYCLE_REPLAY_FORMAT: &str = "chio.clearing.lifecycle-replay.v1";
pub const CLEARING_LIFECYCLE_REPLAY_DESCRIPTOR_KIND: &str = "chio.clearing.lifecycle-replay.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingFinalizationBurnReplayV1 {
    pub finalization: SignedClearingRoundFinalizationV1,
    pub bound_slot: FrostAuthorizationSlotCheckpointV1,
    pub burned_slot: FrostAnchoredAuthorizationSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingAbortReplayV1 {
    pub request: ClearingRoundRequestV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_output: Option<SignedClearingRoundOutputV1>,
    pub zero_dispatch_proof: SignedClearingZeroDispatchProofV1,
    pub abort: SignedClearingRoundAbortV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalization_burn: Option<ClearingFinalizationBurnReplayV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingAcceptancesReplayV1 {
    pub request: ClearingRoundRequestV1,
    pub signed_output: SignedClearingRoundOutputV1,
    pub acceptances: Vec<SignedClearingParticipantAcceptanceV1>,
    pub dispute_status: ClearingDisputeWindowStatusV1,
    pub verified_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingFinalizationReplayV1 {
    pub begin_finalization_proof: ClearingRoundTransitionProofV1,
    pub acceptances: ClearingAcceptancesReplayV1,
    pub signed_finalization: SignedClearingRoundFinalizationV1,
    pub frost_authorization: FrostAuthorizationV1,
    pub historical_roster: FrostRosterV1,
    pub bound_slot: FrostAuthorizationSlotCheckpointV1,
    pub completed_slot: FrostAnchoredAuthorizationSlot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingDispatchReplayV1 {
    pub request: ClearingRoundRequestV1,
    pub signed_output: SignedClearingRoundOutputV1,
    pub intent_id: String,
    pub effect_slot: EconomicEffectSlotV1,
}

impl ClearingDispatchReplayV1 {
    fn signed_intent(&self) -> Result<&SignedClearingSettlementIntentV1, ClearingError> {
        unique_signed_intent(&self.signed_output, &self.intent_id)
    }

    fn validate(&self) -> Result<(), ClearingError> {
        self.effect_slot
            .validate()
            .map_err(|_| ClearingError::InvalidField("dispatch_effect_slot"))?;
        let intent = self.signed_intent()?;
        if self.effect_slot.action_digest != intent.digest()?
            || self.effect_slot.parameters_digest != intent.body.digest()?
            || self.effect_slot.idempotency_key != intent.body.dispatch_idempotency_key
        {
            return Err(ClearingError::AuthorityVerification);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingReconciliationReplayV1 {
    pub request: ClearingRoundRequestV1,
    pub signed_output: SignedClearingRoundOutputV1,
    pub intent_id: String,
    pub source_effect_slot_head: EconomicResourceHeadV1,
    pub signed_reconciliation: SignedClearingSettlementReconciliationV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingSatisfactionReplayV1 {
    pub request: ClearingRoundRequestV1,
    pub signed_output: SignedClearingRoundOutputV1,
    pub signed_satisfaction: SignedClearingRoundSatisfactionV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingZeroIntentReconciliationReplayV1 {
    pub request: ClearingRoundRequestV1,
    pub signed_output: SignedClearingRoundOutputV1,
    pub signed_reconciliation: SignedClearingZeroIntentReconciliationV1,
}

impl ClearingReconciliationReplayV1 {
    fn signed_intent(&self) -> Result<&SignedClearingSettlementIntentV1, ClearingError> {
        unique_signed_intent(&self.signed_output, &self.intent_id)
    }

    fn validate(&self) -> Result<(), ClearingError> {
        self.signed_reconciliation.body.validate()?;
        self.source_effect_slot_head
            .validate()
            .map_err(|_| ClearingError::InvalidField("reconciliation_effect_slot_head"))?;
        let intent = self.signed_intent()?;
        let body = &self.signed_reconciliation.body;
        if body.intent_id != self.intent_id
            || body.intent_digest != intent.body.digest()?
            || body.effect_slot_id != self.source_effect_slot_head.resource_key.resource_id
            || body.source_effect_slot_digest
                != self
                    .source_effect_slot_head
                    .digest()
                    .map_err(|_| ClearingError::AuthorityVerification)?
        {
            return Err(ClearingError::AuthorityVerification);
        }
        Ok(())
    }
}

fn unique_signed_intent<'a>(
    signed_output: &'a SignedClearingRoundOutputV1,
    intent_id: &str,
) -> Result<&'a SignedClearingSettlementIntentV1, ClearingError> {
    validate_text("dispatch_intent_id", intent_id)?;
    let mut intents = signed_output
        .intents
        .iter()
        .filter(|intent| intent.body.intent_id == intent_id);
    let intent = intents.next().ok_or(ClearingError::AuthorityVerification)?;
    if intents.next().is_some() {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(intent)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClearingLifecycleReplayEvidenceV1 {
    Proposal {
        request: Box<ClearingRoundRequestV1>,
        signed_output: Box<SignedClearingRoundOutputV1>,
    },
    BeginFinalization {
        acceptances: Box<ClearingAcceptancesReplayV1>,
    },
    Finalize {
        finalization: Box<ClearingFinalizationReplayV1>,
    },
    BeginDispatch {
        dispatch: Box<ClearingDispatchReplayV1>,
    },
    Reconciliation {
        reconciliation: Box<ClearingReconciliationReplayV1>,
    },
    Satisfaction {
        satisfaction: Box<ClearingSatisfactionReplayV1>,
    },
    ZeroIntentReconciliation {
        reconciliation: Box<ClearingZeroIntentReconciliationReplayV1>,
    },
    BeginAbort {
        abort: Box<ClearingAbortReplayV1>,
    },
    Abort {
        preabort_round_head: Box<EconomicResourceHeadV1>,
        begin_abort_proof: Box<ClearingRoundTransitionProofV1>,
        abort: Box<ClearingAbortReplayV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingLifecycleReplayV1 {
    pub format: String,
    pub proof: ClearingRoundTransitionProofV1,
    pub evidence: ClearingLifecycleReplayEvidenceV1,
}

impl ClearingLifecycleReplayV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.format != CLEARING_LIFECYCLE_REPLAY_FORMAT {
            return Err(ClearingError::InvalidField("lifecycle_replay_format"));
        }
        self.proof.validate()?;
        let matches = matches!(
            (&self.proof.transition, &self.evidence),
            (
                ClearingRoundTransitionV1::Propose { .. },
                ClearingLifecycleReplayEvidenceV1::Proposal { .. }
            ) | (
                ClearingRoundTransitionV1::BeginFinalization { .. },
                ClearingLifecycleReplayEvidenceV1::BeginFinalization { .. }
            ) | (
                ClearingRoundTransitionV1::Finalize { .. },
                ClearingLifecycleReplayEvidenceV1::Finalize { .. }
            ) | (
                ClearingRoundTransitionV1::BeginDispatch { .. },
                ClearingLifecycleReplayEvidenceV1::BeginDispatch { .. }
            ) | (
                ClearingRoundTransitionV1::BeginReconciliation { .. }
                    | ClearingRoundTransitionV1::Incident { .. },
                ClearingLifecycleReplayEvidenceV1::Reconciliation { .. }
            ) | (
                ClearingRoundTransitionV1::Satisfy { .. },
                ClearingLifecycleReplayEvidenceV1::Satisfaction { .. }
                    | ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation { .. }
            ) | (
                ClearingRoundTransitionV1::BeginAbort { .. },
                ClearingLifecycleReplayEvidenceV1::BeginAbort { .. }
            ) | (
                ClearingRoundTransitionV1::Abort { .. },
                ClearingLifecycleReplayEvidenceV1::Abort { .. }
            )
        );
        if !matches {
            return Err(ClearingError::IllegalLifecycleTransition);
        }
        if let ClearingLifecycleReplayEvidenceV1::BeginDispatch { dispatch } = &self.evidence {
            dispatch.validate()?;
        }
        if let ClearingLifecycleReplayEvidenceV1::Reconciliation { reconciliation } = &self.evidence
        {
            reconciliation.validate()?;
        }
        if let ClearingLifecycleReplayEvidenceV1::Satisfaction { satisfaction } = &self.evidence {
            satisfaction.signed_satisfaction.body.validate()?;
        }
        if let ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation { reconciliation } =
            &self.evidence
        {
            reconciliation.signed_reconciliation.body.validate()?;
        }
        Ok(())
    }

    pub fn proof_digest(&self) -> Result<String, ClearingError> {
        self.validate()?;
        self.proof.digest()
    }

    #[must_use]
    pub fn authorized_at_unix_ms(&self) -> u64 {
        match &self.evidence {
            ClearingLifecycleReplayEvidenceV1::Proposal { request, .. } => {
                request.generated_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::BeginFinalization { acceptances } => {
                acceptances.verified_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::Finalize { finalization } => {
                finalization.completed_slot.checkpoint.clock_high_water
            }
            ClearingLifecycleReplayEvidenceV1::BeginDispatch { dispatch } => {
                dispatch.request.generated_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::Reconciliation { reconciliation } => {
                reconciliation
                    .signed_reconciliation
                    .body
                    .observed_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::Satisfaction { satisfaction } => {
                satisfaction.signed_satisfaction.body.satisfied_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation { reconciliation } => {
                reconciliation
                    .signed_reconciliation
                    .body
                    .reconciled_at_unix_ms
            }
            ClearingLifecycleReplayEvidenceV1::BeginAbort { abort }
            | ClearingLifecycleReplayEvidenceV1::Abort { abort, .. } => {
                abort.abort.body.authorized_at_unix_ms
            }
        }
    }

    #[must_use]
    pub fn admission_checkpoint(&self) -> Option<(&str, u64, &str)> {
        let abort = match &self.evidence {
            ClearingLifecycleReplayEvidenceV1::BeginAbort { abort } => abort,
            ClearingLifecycleReplayEvidenceV1::Proposal { .. }
            | ClearingLifecycleReplayEvidenceV1::BeginFinalization { .. }
            | ClearingLifecycleReplayEvidenceV1::Finalize { .. }
            | ClearingLifecycleReplayEvidenceV1::BeginDispatch { .. }
            | ClearingLifecycleReplayEvidenceV1::Reconciliation { .. }
            | ClearingLifecycleReplayEvidenceV1::Satisfaction { .. }
            | ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation { .. }
            | ClearingLifecycleReplayEvidenceV1::Abort { .. } => return None,
        };
        Some((
            &abort.zero_dispatch_proof.body.admission_store_id,
            abort.zero_dispatch_proof.body.admission_commit_sequence,
            &abort.zero_dispatch_proof.body.admission_commit_digest,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingLifecycleAuthorityPinsV1 {
    pub clearing_authority_id: String,
    pub clearing_authority_key: PublicKey,
    pub clearing_authority_key_epoch: u64,
    pub participant_authority_id: String,
    pub participant_authority_key: PublicKey,
    pub participant_key_epoch: u64,
    pub obligation_authority_id: String,
    pub obligation_authority_key: PublicKey,
    pub obligation_key_epoch: u64,
    pub zero_dispatch_authority_id: String,
    pub zero_dispatch_authority_key: PublicKey,
    pub zero_dispatch_authority_key_epoch: u64,
    pub admission_store_id: String,
}

impl ClearingLifecycleAuthorityPinsV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        self.clearing_trust(1)?.validate()?;
        validate_text(
            "zero_dispatch_authority_id",
            &self.zero_dispatch_authority_id,
        )?;
        validate_positive(
            "zero_dispatch_authority_key_epoch",
            self.zero_dispatch_authority_key_epoch,
        )?;
        validate_text("admission_store_id", &self.admission_store_id)
    }

    fn clearing_trust(
        &self,
        trusted_time_unix_ms: u64,
    ) -> Result<ClearingAuthorityTrustV1, ClearingError> {
        let trust = ClearingAuthorityTrustV1 {
            clearing_authority_id: self.clearing_authority_id.clone(),
            clearing_authority_key: self.clearing_authority_key.clone(),
            clearing_authority_key_epoch: self.clearing_authority_key_epoch,
            participant_authority_id: self.participant_authority_id.clone(),
            participant_authority_key: self.participant_authority_key.clone(),
            participant_key_epoch: self.participant_key_epoch,
            obligation_authority_id: self.obligation_authority_id.clone(),
            obligation_authority_key: self.obligation_authority_key.clone(),
            obligation_key_epoch: self.obligation_key_epoch,
            trusted_time_unix_ms,
        };
        trust.validate()?;
        Ok(trust)
    }

    fn zero_dispatch_trust(
        &self,
        proof: &SignedClearingZeroDispatchProofV1,
        trusted_time_unix_ms: u64,
    ) -> Result<ClearingZeroDispatchTrustV1, ClearingError> {
        let trust = ClearingZeroDispatchTrustV1 {
            authority_id: self.zero_dispatch_authority_id.clone(),
            authority_key: self.zero_dispatch_authority_key.clone(),
            authority_key_epoch: self.zero_dispatch_authority_key_epoch,
            admission_store_id: self.admission_store_id.clone(),
            admission_commit_sequence: proof.body.admission_commit_sequence,
            admission_commit_digest: proof.body.admission_commit_digest.clone(),
            trusted_time_unix_ms,
        };
        trust.validate()?;
        Ok(trust)
    }
}

pub fn verify_clearing_lifecycle_replay(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    verify_clearing_lifecycle_replay_with_outcome(
        current,
        batch,
        replay,
        pins,
        frost_trust,
        dispute_resolver,
        None,
    )
}

pub fn verify_clearing_lifecycle_replay_with_outcome(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
    settlement_outcome_verifier: Option<&dyn ClearingSettlementOutcomeVerifier>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    replay.validate()?;
    pins.validate()?;
    let round_key = EconomicResourceKeyV1 {
        resource_family: CLEARING_ROUND_RESOURCE_FAMILY.to_owned(),
        scope_id: replay.proof.governance_scope_id.clone(),
        resource_id: replay.proof.round_id.clone(),
    };
    let source_round_head = current
        .view()
        .head(&round_key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    let verified = verify_replay_authority(
        source_round_head,
        replay,
        pins,
        frost_trust,
        dispute_resolver,
        settlement_outcome_verifier,
    )?;
    verify_projection(
        current,
        batch,
        &replay.proof,
        verified.expected_reconciliation_slot(),
        verified.verified_zero_intent(),
    )?;
    Ok(verified.authorization().clone())
}

pub fn verify_clearing_lifecycle_replay_authority(
    source_round_head: &EconomicResourceHeadV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    verify_clearing_lifecycle_replay_authority_with_outcome(
        source_round_head,
        replay,
        pins,
        frost_trust,
        dispute_resolver,
        None,
    )
}

pub fn verify_clearing_lifecycle_replay_authority_with_outcome(
    source_round_head: &EconomicResourceHeadV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
    settlement_outcome_verifier: Option<&dyn ClearingSettlementOutcomeVerifier>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    Ok(
        verify_clearing_lifecycle_replay_authority_verification_with_outcome(
            source_round_head,
            replay,
            pins,
            frost_trust,
            dispute_resolver,
            settlement_outcome_verifier,
        )?
        .authorization()
        .clone(),
    )
}

pub fn verify_clearing_lifecycle_replay_authority_verification_with_outcome(
    source_round_head: &EconomicResourceHeadV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
    settlement_outcome_verifier: Option<&dyn ClearingSettlementOutcomeVerifier>,
) -> Result<ClearingLifecycleAuthorityVerificationV1, ClearingError> {
    verify_replay_authority(
        source_round_head,
        replay,
        pins,
        frost_trust,
        dispute_resolver,
        settlement_outcome_verifier,
    )
}

fn verify_replay_authority(
    source_round_head: &EconomicResourceHeadV1,
    replay: &ClearingLifecycleReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
    settlement_outcome_verifier: Option<&dyn ClearingSettlementOutcomeVerifier>,
) -> Result<ClearingLifecycleAuthorityVerificationV1, ClearingError> {
    replay.validate()?;
    pins.validate()?;
    if source_round_head
        .digest()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?
        != replay.proof.source_round_head_digest
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let mut reconciliation_slot = None;
    let authorization = match &replay.evidence {
        ClearingLifecycleReplayEvidenceV1::Proposal {
            request,
            signed_output,
        } => {
            verify_proposal(&replay.proof, request, signed_output, pins)?;
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::BeginFinalization { acceptances } => {
            let resolver = dispute_resolver.ok_or(ClearingError::AuthorityVerification)?;
            let verified = verify_acceptances_replay(acceptances, pins, resolver)?;
            verify_begin_finalization(source_round_head, &replay.proof, &verified)?;
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::Finalize { finalization } => verify_finalization_replay(
            source_round_head,
            &replay.proof,
            finalization,
            pins,
            frost_trust,
            dispute_resolver,
        )?,
        ClearingLifecycleReplayEvidenceV1::BeginDispatch { dispatch } => {
            verify_dispatch_replay(source_round_head, &replay.proof, dispatch, pins)?;
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::Reconciliation { reconciliation } => {
            reconciliation_slot = Some(verify_reconciliation_replay(
                source_round_head,
                &replay.proof,
                reconciliation,
                pins,
                settlement_outcome_verifier.ok_or(ClearingError::AuthorityVerification)?,
            )?);
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::Satisfaction { satisfaction } => {
            verify_satisfaction_replay(source_round_head, &replay.proof, satisfaction, pins)?;
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation { reconciliation } => {
            verify_zero_intent_reconciliation_replay(
                source_round_head,
                &replay.proof,
                reconciliation,
                pins,
            )?;
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::BeginAbort { abort } => {
            let verified = verify_abort_replay(source_round_head, abort, pins, frost_trust)?;
            if replay.proof.transition != verified.begin_abort_transition() {
                return Err(ClearingError::AuthorityVerification);
            }
            EconomicTransitionAuthorizationV1::Direct
        }
        ClearingLifecycleReplayEvidenceV1::Abort {
            preabort_round_head,
            begin_abort_proof,
            abort,
        } => {
            let verified = verify_abort_replay(preabort_round_head, abort, pins, frost_trust)?;
            if replay.proof.transition
                != verified.abort_transition(source_round_head, begin_abort_proof)?
            {
                return Err(ClearingError::AuthorityVerification);
            }
            EconomicTransitionAuthorizationV1::Direct
        }
    };
    Ok(match (&replay.evidence, reconciliation_slot) {
        (ClearingLifecycleReplayEvidenceV1::ZeroIntentReconciliation { .. }, None) => {
            ClearingLifecycleAuthorityVerificationV1::zero_intent(authorization)
        }
        (_, Some(slot)) => {
            ClearingLifecycleAuthorityVerificationV1::reconciled(authorization, slot)
        }
        (_, None) => ClearingLifecycleAuthorityVerificationV1::direct(authorization),
    })
}

pub struct ClearingLifecycleReplayBatchVerifier {
    replay: ClearingLifecycleReplayV1,
    pins: ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<Arc<FrostArtifactTrustStore>>,
    dispute_resolver: Option<Arc<dyn ClearingDisputeWindowResolver>>,
    settlement_outcome_verifier: Option<Arc<dyn ClearingSettlementOutcomeVerifier>>,
}

impl ClearingLifecycleReplayBatchVerifier {
    pub fn new(
        replay: ClearingLifecycleReplayV1,
        pins: ClearingLifecycleAuthorityPinsV1,
        frost_trust: Option<Arc<FrostArtifactTrustStore>>,
        dispute_resolver: Option<Arc<dyn ClearingDisputeWindowResolver>>,
    ) -> Result<Self, ClearingError> {
        replay.validate()?;
        pins.validate()?;
        Ok(Self {
            replay,
            pins,
            frost_trust,
            dispute_resolver,
            settlement_outcome_verifier: None,
        })
    }

    #[must_use]
    pub fn with_settlement_outcome_verifier(
        mut self,
        verifier: Arc<dyn ClearingSettlementOutcomeVerifier>,
    ) -> Self {
        self.settlement_outcome_verifier = Some(verifier);
        self
    }
}

impl EconomicTransitionProofVerifier for ClearingLifecycleReplayBatchVerifier {
    fn verify_transition(
        &self,
        _current: Option<&EconomicResourceHeadV1>,
        transition: &EconomicStateTransitionV1,
    ) -> Result<EconomicTransitionAuthorizationV1, EconomicStateAnchorError> {
        Err(EconomicStateAnchorError::TransitionProofRejected(
            transition.resource_key.clone(),
        ))
    }

    fn verify_batch(
        &self,
        current: &VerifiedEconomicStateView,
        batch: &EconomicStateBatchV1,
    ) -> Result<Vec<EconomicTransitionAuthorizationV1>, EconomicStateAnchorError> {
        let authorization = verify_clearing_lifecycle_replay_with_outcome(
            current,
            batch,
            &self.replay,
            &self.pins,
            self.frost_trust.as_deref(),
            self.dispute_resolver.as_deref(),
            self.settlement_outcome_verifier.as_deref(),
        )
        .map_err(|_| rejected_batch(batch))?;
        Ok(vec![authorization; batch.transitions.len()])
    }
}

fn verify_proposal(
    proof: &ClearingRoundTransitionProofV1,
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
) -> Result<(), ClearingError> {
    let trust = pins.clearing_trust(request.generated_at_unix_ms)?;
    let output = verify_signed_netting_round(request, &trust, signed_output)?;
    let output_manifest_digest = output.output_manifest.digest()?;
    let authority_digest = signed_output.output_manifest.digest()?;
    let ClearingRoundTransitionV1::Propose {
        output_manifest_digest: expected_output,
        authority_digest: expected_authority,
    } = &proof.transition
    else {
        return Err(ClearingError::IllegalLifecycleTransition);
    };
    if output.core.round_id != proof.round_id
        || output.core.governance_scope_id != proof.governance_scope_id
        || output.core.digest()? != proof.round_core_digest
        || output.core.input_manifest_digest != proof.input_manifest_digest
        || output.core.reservation_root != proof.reservation_root
        || output.core.input_count != proof.reservation_count
        || output_manifest_digest != *expected_output
        || authority_digest != *expected_authority
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn verify_dispatch_replay(
    source_round_head: &EconomicResourceHeadV1,
    proof: &ClearingRoundTransitionProofV1,
    replay: &ClearingDispatchReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
) -> Result<(), ClearingError> {
    replay.validate()?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(source_round_head)?;
    record.validate()?;
    validate_round_head(source_round_head, &record)?;
    let trust = pins.clearing_trust(replay.request.generated_at_unix_ms)?;
    let output = verify_signed_netting_round(&replay.request, &trust, &replay.signed_output)?;
    let signed_intent = replay.signed_intent()?;
    let intent = output
        .intents
        .iter()
        .find(|intent| intent.intent_id == replay.intent_id)
        .ok_or(ClearingError::AuthorityVerification)?;
    let round_core_digest = output.core.digest()?;
    let output_manifest_digest = output.output_manifest.digest()?;
    let authority_digest = signed_intent.digest()?;
    super::dispatch::verify_dispatch_slot_binding(
        source_round_head,
        signed_intent,
        &replay.effect_slot,
        &authority_digest,
    )?;
    let expected_transition = ClearingRoundTransitionV1::BeginDispatch {
        operation_id: replay.effect_slot.operation_id.clone(),
        intent_id: intent.intent_id.clone(),
        intent_digest: intent.digest()?,
        effect_slot_id: replay.effect_slot.slot_id.clone(),
        effect_slot_digest: replay
            .effect_slot
            .digest()
            .map_err(|_| ClearingError::AuthorityVerification)?,
        authority_digest,
    };
    if signed_intent.body != *intent
        || record.round_id() != output.core.round_id
        || record.governance_scope_id() != output.core.governance_scope_id
        || record.round_core_digest() != round_core_digest
        || record.output_manifest_digest() != Some(output_manifest_digest.as_str())
        || proof.round_id != output.core.round_id
        || proof.governance_scope_id != output.core.governance_scope_id
        || proof.round_core_digest != round_core_digest
        || proof.input_manifest_digest != output.core.input_manifest_digest
        || proof.reservation_root != output.core.reservation_root
        || proof.reservation_count != output.core.input_count
        || proof.source_state != record.state()
        || proof.source_round_version != record.row_version()
        || proof.source_round_fence != record.fence()
        || proof.transition != expected_transition
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn verify_reconciliation_replay(
    source_round_head: &EconomicResourceHeadV1,
    proof: &ClearingRoundTransitionProofV1,
    replay: &ClearingReconciliationReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    outcome_verifier: &dyn ClearingSettlementOutcomeVerifier,
) -> Result<EconomicEffectSlotV1, ClearingError> {
    replay.validate()?;
    let body = &replay.signed_reconciliation.body;
    let output_trust = pins.clearing_trust(replay.request.generated_at_unix_ms)?;
    let output =
        verify_signed_netting_round(&replay.request, &output_trust, &replay.signed_output)?;
    let reconciliation_trust = pins.clearing_trust(body.observed_at_unix_ms)?;
    let signed_intent = replay.signed_intent()?;
    let intent = output
        .intents
        .iter()
        .find(|intent| intent.intent_id == replay.intent_id)
        .ok_or(ClearingError::AuthorityVerification)?;
    if signed_intent.body != *intent {
        return Err(ClearingError::AuthorityVerification);
    }
    let (_, next_slot) = reconciliation::verify_reconciliation(
        source_round_head,
        &replay.source_effect_slot_head,
        signed_intent,
        &replay.signed_reconciliation,
        &reconciliation_trust,
        outcome_verifier,
    )?;
    let reconciliation_digest = replay.signed_reconciliation.digest()?;
    let expected_transition = match body.observed_status {
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
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(source_round_head)?;
    if output.core.digest()? != proof.round_core_digest
        || output.output_manifest.digest()? != body.output_manifest_digest
        || record.round_id() != output.core.round_id
        || record.round_core_digest() != proof.round_core_digest
        || body.observed_at_unix_ms != proof.trusted_clock_high_water
        || proof.transition != expected_transition
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(next_slot)
}

fn verify_satisfaction_replay(
    source_round_head: &EconomicResourceHeadV1,
    proof: &ClearingRoundTransitionProofV1,
    replay: &ClearingSatisfactionReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
) -> Result<(), ClearingError> {
    let body = &replay.signed_satisfaction.body;
    body.validate()?;
    let output_trust = pins.clearing_trust(replay.request.generated_at_unix_ms)?;
    let output =
        verify_signed_netting_round(&replay.request, &output_trust, &replay.signed_output)?;
    let trust = pins.clearing_trust(body.satisfied_at_unix_ms)?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(source_round_head)?;
    record.validate()?;
    validate_round_head(source_round_head, &record)?;
    satisfaction::validate_completed_intents(&record, &output)?;
    let satisfaction_digest = replay.signed_satisfaction.digest()?;
    let expected_transition = ClearingRoundTransitionV1::Satisfy {
        satisfaction_digest,
        authority_digest: body.authority_digest.clone(),
    };
    if replay.signed_satisfaction.signer_key != trust.obligation_authority_key
        || body.disposition_authority_id != trust.obligation_authority_id
        || body.disposition_authority_key_epoch != trust.obligation_key_epoch
        || !replay.signed_satisfaction.verify_signature()?
        || body.satisfied_at_unix_ms < source_round_head.trusted_clock_high_water
        || body.round_id != record.round_id
        || body.round_core_digest != record.round_core_digest
        || body.output_manifest_digest != output.output_manifest.digest()?
        || record.output_manifest_digest.as_deref() != Some(body.output_manifest_digest.as_str())
        || record.finalization_digest.as_deref() != Some(body.finalization_digest.as_str())
        || body.settlement_intent_root != output.output_manifest.settlement_intent_root
        || body.settlement_intent_count != output.output_manifest.settlement_intent_count
        || body.intent_progress_root != satisfaction::intent_progress_root(&record.intent_progress)?
        || body.reservation_root != record.reservation_root
        || body.reservation_count != record.reservation_count
        || body.reservation_head_root != proof.reservation_head_root
        || body.source_lifecycle_head_digest != proof.source_round_head_digest
        || body.source_lifecycle_version != record.row_version
        || body.source_lifecycle_fence != record.fence
        || body.next_lifecycle_version != proof.next_round_version
        || body.next_lifecycle_fence != proof.next_round_fence
        || body.satisfied_at_unix_ms != proof.trusted_clock_high_water
        || proof.round_core_digest != output.core.digest()?
        || proof.transition != expected_transition
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn verify_zero_intent_reconciliation_replay(
    source_round_head: &EconomicResourceHeadV1,
    proof: &ClearingRoundTransitionProofV1,
    replay: &ClearingZeroIntentReconciliationReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
) -> Result<(), ClearingError> {
    let body = &replay.signed_reconciliation.body;
    body.validate()?;
    let output_trust = pins.clearing_trust(replay.request.generated_at_unix_ms)?;
    let output =
        verify_signed_netting_round(&replay.request, &output_trust, &replay.signed_output)?;
    let trust = pins.clearing_trust(body.reconciled_at_unix_ms)?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(source_round_head)?;
    record.validate()?;
    validate_round_head(source_round_head, &record)?;
    let expected_bindings = proof
        .reservations
        .iter()
        .map(|reservation| ClearingZeroIntentAtomBindingV1 {
            source_sequence: reservation.source_sequence,
            obligation_id: reservation.resource_key.resource_id.clone(),
            expected_head_digest: reservation.expected_head_digest.clone(),
            expected_resource_version: reservation.expected_resource_version,
            expected_lifecycle_fence: reservation.expected_lifecycle_fence,
        })
        .collect::<Vec<_>>();
    let reconciliation_digest = replay.signed_reconciliation.digest()?;
    let expected_transition = ClearingRoundTransitionV1::Satisfy {
        satisfaction_digest: reconciliation_digest,
        authority_digest: body.authority_digest.clone(),
    };
    if replay.signed_reconciliation.signer_key != trust.obligation_authority_key
        || body.disposition_authority_id != trust.obligation_authority_id
        || body.disposition_authority_key_epoch != trust.obligation_key_epoch
        || !replay.signed_reconciliation.verify_signature()?
        || body.reconciled_at_unix_ms < source_round_head.trusted_clock_high_water
        || record.state != ClearingRoundLifecycleStateV1::Finalized
        || !record.intent_progress.is_empty()
        || record.first_dispatch_operation_id.is_some()
        || !output.intents.is_empty()
        || output.output_manifest.settlement_intent_count != 0
        || body.settlement_intent_count != 0
        || body.round_id != record.round_id
        || body.round_core_digest != record.round_core_digest
        || body.output_manifest_digest != output.output_manifest.digest()?
        || record.output_manifest_digest.as_deref() != Some(body.output_manifest_digest.as_str())
        || record.finalization_digest.as_deref() != Some(body.finalization_digest.as_str())
        || body.empty_intent_root != output.output_manifest.settlement_intent_root
        || body.reservation_root != record.reservation_root
        || body.reservation_count != record.reservation_count
        || body.atom_bindings != expected_bindings
        || body.source_lifecycle_head_digest != proof.source_round_head_digest
        || body.source_lifecycle_version != record.row_version
        || body.source_lifecycle_fence != record.fence
        || body.next_lifecycle_version != proof.next_round_version
        || body.next_lifecycle_fence != proof.next_round_fence
        || body.reconciled_at_unix_ms != proof.trusted_clock_high_water
        || proof.round_core_digest != output.core.digest()?
        || proof.transition != expected_transition
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

struct ReplayDisputeWindowResolver<'a> {
    stored: &'a ClearingDisputeWindowStatusV1,
    resolver: &'a dyn ClearingDisputeWindowResolver,
}

impl ClearingDisputeWindowResolver for ReplayDisputeWindowResolver<'_> {
    fn resolve_closed_window(
        &self,
        round_id: &str,
        round_core_digest: &str,
        output_manifest_digest: &str,
        dispute_window_ends_at_unix_ms: u64,
    ) -> Result<ClearingDisputeWindowStatusV1, ClearingError> {
        let status = self.resolver.resolve_closed_window_checkpoint(
            round_id,
            round_core_digest,
            output_manifest_digest,
            dispute_window_ends_at_unix_ms,
            &self.stored.checkpoint_digest,
        )?;
        if status != *self.stored {
            return Err(ClearingError::AuthorityVerification);
        }
        Ok(status)
    }
}

fn verify_acceptances_replay(
    replay: &ClearingAcceptancesReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    resolver: &dyn ClearingDisputeWindowResolver,
) -> Result<VerifiedClearingParticipantAcceptancesV1, ClearingError> {
    let trust = pins.clearing_trust(replay.verified_at_unix_ms)?;
    verify_clearing_participant_acceptances(
        &replay.request,
        &replay.signed_output,
        &replay.acceptances,
        &ReplayDisputeWindowResolver {
            stored: &replay.dispute_status,
            resolver,
        },
        &trust,
    )
}

fn verify_begin_finalization(
    source_round_head: &EconomicResourceHeadV1,
    proof: &ClearingRoundTransitionProofV1,
    acceptances: &VerifiedClearingParticipantAcceptancesV1,
) -> Result<(), ClearingError> {
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(source_round_head)?;
    record.validate()?;
    validate_round_head(source_round_head, &record)?;
    if record.state() != ClearingRoundLifecycleStateV1::Proposed
        || record.round_id() != acceptances.round_id()
        || record.round_core_digest() != acceptances.round_core_digest()
        || record.output_manifest_digest() != Some(acceptances.output_manifest_digest())
        || proof.round_id != acceptances.round_id()
        || proof.governance_scope_id != record.governance_scope_id()
        || proof.round_core_digest != acceptances.round_core_digest()
        || proof.source_round_version != record.row_version()
        || proof.source_round_fence != record.fence()
        || proof.transition != acceptances.begin_finalization_transition()
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

struct ReplayHistoricalRosterResolver<'a> {
    roster: &'a FrostRosterV1,
}

impl FrostHistoricalRosterResolver for ReplayHistoricalRosterResolver<'_> {
    fn resolve_historical_roster(
        &self,
        roster_digest: &str,
        key_epoch: u64,
        _issued_at: u64,
    ) -> Result<Option<FrostRosterV1>, FrostRosterResolutionError> {
        Ok(
            (self.roster.roster_digest == roster_digest && self.roster.key_epoch == key_epoch)
                .then(|| self.roster.clone()),
        )
    }
}

fn verify_finalization_replay(
    source_round_head: &EconomicResourceHeadV1,
    proof: &ClearingRoundTransitionProofV1,
    replay: &ClearingFinalizationReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
    dispute_resolver: Option<&dyn ClearingDisputeWindowResolver>,
) -> Result<EconomicTransitionAuthorizationV1, ClearingError> {
    let dispute_resolver = dispute_resolver.ok_or(ClearingError::AuthorityVerification)?;
    let acceptances = verify_acceptances_replay(&replay.acceptances, pins, dispute_resolver)?;
    verify_begin_finalization_lineage(
        source_round_head,
        proof,
        &replay.begin_finalization_proof,
        &acceptances,
    )?;
    let frost_trust = frost_trust.ok_or(ClearingError::AuthorityVerification)?;
    let frost = verify_historical_completed_authorization(
        &replay.frost_authorization,
        &replay.bound_slot,
        &replay.completed_slot,
        &ReplayHistoricalRosterResolver {
            roster: &replay.historical_roster,
        },
        frost_trust,
    )
    .map_err(|_| ClearingError::AuthorityVerification)?;
    let clearing_trust = pins.clearing_trust(frost.completed_at())?;
    let finalization = verify_historical_clearing_round_finalization(
        source_round_head,
        &acceptances,
        &replay.signed_finalization,
        &frost,
        &clearing_trust,
    )?;
    let transition = finalization.finalize_transition();
    if proof.transition != transition {
        return Err(ClearingError::AuthorityVerification);
    }
    match transition {
        ClearingRoundTransitionV1::Finalize { frost, .. } => {
            Ok(EconomicTransitionAuthorizationV1::NOfM { frost })
        }
        _ => Err(ClearingError::IllegalLifecycleTransition),
    }
}

fn verify_begin_finalization_lineage(
    source_round_head: &EconomicResourceHeadV1,
    finalization_proof: &ClearingRoundTransitionProofV1,
    begin_finalization_proof: &ClearingRoundTransitionProofV1,
    acceptances: &VerifiedClearingParticipantAcceptancesV1,
) -> Result<(), ClearingError> {
    begin_finalization_proof.validate()?;
    let record: ClearingRoundLifecycleRecordV1 = decode_inline(source_round_head)?;
    record.validate()?;
    validate_round_head(source_round_head, &record)?;
    if record.state() != ClearingRoundLifecycleStateV1::Finalizing
        || record.round_id() != acceptances.round_id()
        || record.round_core_digest() != acceptances.round_core_digest()
        || record.output_manifest_digest() != Some(acceptances.output_manifest_digest())
        || record.participant_acceptance_root() != Some(acceptances.acceptance_root())
        || record.participant_acceptance_count() != Some(acceptances.acceptance_count())
        || record.last_transition_digest() != begin_finalization_proof.digest()?
        || source_round_head.predecessor_digest.as_deref()
            != Some(begin_finalization_proof.source_round_head_digest.as_str())
        || begin_finalization_proof.transition != acceptances.begin_finalization_transition()
        || begin_finalization_proof.round_id != finalization_proof.round_id
        || begin_finalization_proof.governance_scope_id != finalization_proof.governance_scope_id
        || begin_finalization_proof.round_core_digest != finalization_proof.round_core_digest
        || begin_finalization_proof.input_manifest_digest
            != finalization_proof.input_manifest_digest
        || begin_finalization_proof.reservation_root != finalization_proof.reservation_root
        || begin_finalization_proof.reservation_count != finalization_proof.reservation_count
        || begin_finalization_proof.next_round_version != finalization_proof.source_round_version
        || begin_finalization_proof.next_round_fence != finalization_proof.source_round_fence
        || finalization_proof.governance_scope_id != record.governance_scope_id()
        || finalization_proof.source_round_version != record.row_version()
        || finalization_proof.source_round_fence != record.fence()
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn verify_abort_replay(
    preabort_round_head: &EconomicResourceHeadV1,
    replay: &ClearingAbortReplayV1,
    pins: &ClearingLifecycleAuthorityPinsV1,
    frost_trust: Option<&FrostArtifactTrustStore>,
) -> Result<VerifiedClearingRoundAbortV1, ClearingError> {
    let authorized_at = replay.abort.body.authorized_at_unix_ms;
    let clearing_trust = pins.clearing_trust(authorized_at)?;
    let zero_dispatch_trust =
        pins.zero_dispatch_trust(&replay.zero_dispatch_proof, authorized_at)?;
    let zero_dispatch = verify_clearing_zero_dispatch_proof(
        preabort_round_head,
        &replay.request,
        replay.signed_output.as_ref(),
        &replay.zero_dispatch_proof,
        &clearing_trust,
        &zero_dispatch_trust,
    )?;
    match &replay.finalization_burn {
        Some(burn) => {
            let trust = frost_trust.ok_or(ClearingError::AuthorityVerification)?;
            let burned = verify_burned_frost_authorization_slot(
                &burn.bound_slot,
                &burn.burned_slot,
                trust,
                authorized_at,
            )
            .map_err(|_| ClearingError::AuthorityVerification)?;
            verify_clearing_round_abort(
                preabort_round_head,
                &zero_dispatch,
                &replay.abort,
                Some(ClearingFinalizationBurnEvidenceV1::new(
                    &burn.finalization,
                    &burned,
                )),
                &clearing_trust,
            )
        }
        None => verify_clearing_round_abort(
            preabort_round_head,
            &zero_dispatch,
            &replay.abort,
            None,
            &clearing_trust,
        ),
    }
}
