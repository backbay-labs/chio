use super::*;
use chio_core_types::economic_continuity::EconomicResourceHeadV1;
use chio_federation::frost::{
    frost_action_registration, FrostAuthorizationDomain, FrostAuthorizationSlotState,
    VerifiedBurnedFrostAuthorizationSlot,
};

const ZERO_DISPATCH_STATUS_ROOT_DOMAIN: &[u8] = b"chio.clearing.zero-dispatch-status-root.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingZeroDispatchTrustV1 {
    pub authority_id: String,
    pub authority_key: PublicKey,
    pub authority_key_epoch: u64,
    pub admission_store_id: String,
    pub admission_commit_sequence: u64,
    pub admission_commit_digest: String,
    pub trusted_time_unix_ms: u64,
}

impl ClearingZeroDispatchTrustV1 {
    pub(super) fn validate(&self) -> Result<(), ClearingError> {
        validate_text("zero_dispatch_authority_id", &self.authority_id)?;
        validate_positive(
            "zero_dispatch_authority_key_epoch",
            self.authority_key_epoch,
        )?;
        validate_text("admission_store_id", &self.admission_store_id)?;
        if self.admission_commit_sequence > I_JSON_MAX_SAFE_INTEGER {
            return Err(ClearingError::InvalidField("admission_commit_sequence"));
        }
        validate_digest("admission_commit_digest", &self.admission_commit_digest)?;
        validate_positive(
            "zero_dispatch_trusted_time_unix_ms",
            self.trusted_time_unix_ms,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClearingIntentDispatchDispositionV1 {
    Absent,
    CompensatedBeforeDispatch {
        operation_id: String,
        operation_version: u64,
        coordinator_lease_epoch: u64,
        terminal_evidence_digest: String,
    },
}

impl ClearingIntentDispatchDispositionV1 {
    fn validate(&self) -> Result<(), ClearingError> {
        match self {
            Self::Absent => Ok(()),
            Self::CompensatedBeforeDispatch {
                operation_id,
                operation_version,
                coordinator_lease_epoch,
                terminal_evidence_digest,
            } => {
                validate_digest("dispatch_operation_id", operation_id)?;
                validate_positive("dispatch_operation_version", *operation_version)?;
                validate_positive("dispatch_coordinator_lease_epoch", *coordinator_lease_epoch)?;
                validate_digest(
                    "dispatch_terminal_evidence_digest",
                    terminal_evidence_digest,
                )
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingIntentDispatchStatusV1 {
    pub intent_id: String,
    pub intent_digest: String,
    pub dispatch_idempotency_key: String,
    pub disposition: ClearingIntentDispatchDispositionV1,
}

impl ClearingIntentDispatchStatusV1 {
    pub fn absent(intent: &ClearingSettlementIntentV1) -> Result<Self, ClearingError> {
        Ok(Self {
            intent_id: intent.intent_id.clone(),
            intent_digest: domain_digest(INTENT_DIGEST_DOMAIN, intent)?,
            dispatch_idempotency_key: intent.dispatch_idempotency_key.clone(),
            disposition: ClearingIntentDispatchDispositionV1::Absent,
        })
    }

    fn validate(&self) -> Result<(), ClearingError> {
        validate_digest("dispatch_intent_id", &self.intent_id)?;
        validate_digest("dispatch_intent_digest", &self.intent_digest)?;
        validate_digest(
            "dispatch_intent_idempotency_key",
            &self.dispatch_idempotency_key,
        )?;
        self.disposition.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingZeroDispatchProofBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub round_core_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_manifest_digest: Option<String>,
    pub settlement_intent_root: String,
    pub settlement_intent_count: u64,
    pub source_lifecycle_head_digest: String,
    pub source_lifecycle_version: u64,
    pub source_lifecycle_fence: u64,
    pub admission_store_id: String,
    pub admission_commit_sequence: u64,
    pub admission_commit_digest: String,
    pub dispatch_status_root: String,
    pub dispatch_status_count: u64,
    pub dispatch_statuses: Vec<ClearingIntentDispatchStatusV1>,
    pub authority_id: String,
    pub authority_key_epoch: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl ClearingZeroDispatchProofBodyV1 {
    fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ZERO_DISPATCH_PROOF_SCHEMA {
            return Err(ClearingError::InvalidField("zero_dispatch_proof_schema"));
        }
        validate_text("round_id", &self.round_id)?;
        validate_digest("round_core_digest", &self.round_core_digest)?;
        validate_optional_digest(
            "output_manifest_digest",
            self.output_manifest_digest.as_deref(),
        )?;
        validate_digest("settlement_intent_root", &self.settlement_intent_root)?;
        validate_count(
            "settlement_intent_count",
            self.settlement_intent_count,
            self.dispatch_statuses.len(),
        )?;
        validate_digest(
            "source_lifecycle_head_digest",
            &self.source_lifecycle_head_digest,
        )?;
        validate_positive("source_lifecycle_version", self.source_lifecycle_version)?;
        validate_positive("source_lifecycle_fence", self.source_lifecycle_fence)?;
        validate_text("admission_store_id", &self.admission_store_id)?;
        if self.admission_commit_sequence > I_JSON_MAX_SAFE_INTEGER {
            return Err(ClearingError::InvalidField("admission_commit_sequence"));
        }
        validate_digest("admission_commit_digest", &self.admission_commit_digest)?;
        validate_digest("dispatch_status_root", &self.dispatch_status_root)?;
        validate_count(
            "dispatch_status_count",
            self.dispatch_status_count,
            self.dispatch_statuses.len(),
        )?;
        validate_text("zero_dispatch_authority_id", &self.authority_id)?;
        validate_positive(
            "zero_dispatch_authority_key_epoch",
            self.authority_key_epoch,
        )?;
        validate_positive("zero_dispatch_issued_at_unix_ms", self.issued_at_unix_ms)?;
        validate_positive("zero_dispatch_expires_at_unix_ms", self.expires_at_unix_ms)?;
        if self.source_lifecycle_version != self.source_lifecycle_fence
            || self.issued_at_unix_ms >= self.expires_at_unix_ms
            || !self
                .dispatch_statuses
                .windows(2)
                .all(|pair| pair[0].intent_id.as_bytes() < pair[1].intent_id.as_bytes())
        {
            return Err(ClearingError::InvalidField("zero_dispatch_proof"));
        }
        for status in &self.dispatch_statuses {
            status.validate()?;
        }
        let expected_root =
            domain_digest(ZERO_DISPATCH_STATUS_ROOT_DOMAIN, &self.dispatch_statuses)?;
        if expected_root != self.dispatch_status_root {
            return Err(ClearingError::InvalidField("dispatch_status_root"));
        }
        Ok(())
    }
}

pub type SignedClearingZeroDispatchProofV1 =
    SignedClearingEnvelopeV1<ClearingZeroDispatchProofBodyV1>;

#[derive(Debug, Clone)]
pub struct VerifiedClearingZeroDispatchProofV1 {
    proof_digest: String,
    round_id: String,
    round_core_digest: String,
    output_manifest_digest: Option<String>,
    source_lifecycle_head_digest: String,
    source_lifecycle_version: u64,
    source_lifecycle_fence: u64,
    verified_at_unix_ms: u64,
    valid_until_unix_ms: u64,
}

impl VerifiedClearingZeroDispatchProofV1 {
    #[must_use]
    pub fn proof_digest(&self) -> &str {
        &self.proof_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingRoundAbortReasonV1 {
    OperatorCancelled,
    ParticipantRejected,
    DisputeAccepted,
    QuorumUnavailable,
    RecoveryConflict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundAbortBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub governance_scope_id: String,
    pub round_core_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_manifest_digest: Option<String>,
    pub reservation_root: String,
    pub reservation_count: u64,
    pub reason: ClearingRoundAbortReasonV1,
    pub source_lifecycle_head_digest: String,
    pub source_lifecycle_version: u64,
    pub source_lifecycle_fence: u64,
    pub next_lifecycle_version: u64,
    pub next_lifecycle_fence: u64,
    pub zero_dispatch_proof_digest: String,
    pub authority_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frost_burn_checkpoint_digest: Option<String>,
    pub disposition_authority_id: String,
    pub disposition_authority_key_epoch: u64,
    pub authorized_at_unix_ms: u64,
}

impl ClearingRoundAbortBodyV1 {
    fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ROUND_ABORT_SCHEMA {
            return Err(ClearingError::InvalidField("round_abort_schema"));
        }
        validate_text("round_id", &self.round_id)?;
        validate_text("governance_scope_id", &self.governance_scope_id)?;
        validate_digest("round_core_digest", &self.round_core_digest)?;
        validate_optional_digest(
            "output_manifest_digest",
            self.output_manifest_digest.as_deref(),
        )?;
        validate_digest("reservation_root", &self.reservation_root)?;
        validate_positive("reservation_count", self.reservation_count)?;
        if usize::try_from(self.reservation_count).map_err(|_| ClearingError::ArithmeticOverflow)?
            > MAX_CLEARING_INPUTS
        {
            return Err(ClearingError::InvalidField("reservation_count"));
        }
        validate_digest(
            "source_lifecycle_head_digest",
            &self.source_lifecycle_head_digest,
        )?;
        validate_positive("source_lifecycle_version", self.source_lifecycle_version)?;
        validate_positive("source_lifecycle_fence", self.source_lifecycle_fence)?;
        validate_positive("next_lifecycle_version", self.next_lifecycle_version)?;
        validate_positive("next_lifecycle_fence", self.next_lifecycle_fence)?;
        validate_digest(
            "zero_dispatch_proof_digest",
            &self.zero_dispatch_proof_digest,
        )?;
        validate_digest("abort_authority_digest", &self.authority_digest)?;
        validate_optional_digest(
            "frost_burn_checkpoint_digest",
            self.frost_burn_checkpoint_digest.as_deref(),
        )?;
        validate_text("disposition_authority_id", &self.disposition_authority_id)?;
        validate_positive(
            "disposition_authority_key_epoch",
            self.disposition_authority_key_epoch,
        )?;
        validate_positive("abort_authorized_at_unix_ms", self.authorized_at_unix_ms)?;
        let expected_next = self
            .source_lifecycle_version
            .checked_add(1)
            .filter(|next| *next <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        if self.source_lifecycle_version != self.source_lifecycle_fence
            || self.next_lifecycle_version != expected_next
            || self.next_lifecycle_fence != expected_next
        {
            return Err(ClearingError::InvalidField("round_abort_fence"));
        }
        Ok(())
    }
}

pub type SignedClearingRoundAbortV1 = SignedClearingEnvelopeV1<ClearingRoundAbortBodyV1>;

#[derive(Clone, Copy)]
pub struct ClearingFinalizationBurnEvidenceV1<'a> {
    finalization: &'a SignedClearingRoundFinalizationV1,
    burned_slot: &'a VerifiedBurnedFrostAuthorizationSlot,
}

impl<'a> ClearingFinalizationBurnEvidenceV1<'a> {
    #[must_use]
    pub const fn new(
        finalization: &'a SignedClearingRoundFinalizationV1,
        burned_slot: &'a VerifiedBurnedFrostAuthorizationSlot,
    ) -> Self {
        Self {
            finalization,
            burned_slot,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedClearingRoundAbortV1 {
    abort_digest: String,
    zero_dispatch_proof_digest: String,
    authority_digest: String,
    frost_burn_checkpoint_digest: Option<String>,
    source_lifecycle_head_digest: String,
    source_lifecycle_version: u64,
    source_lifecycle_fence: u64,
    authorized_at_unix_ms: u64,
}

impl VerifiedClearingRoundAbortV1 {
    #[must_use]
    pub fn abort_digest(&self) -> &str {
        &self.abort_digest
    }

    #[must_use]
    pub fn begin_abort_transition(&self) -> ClearingRoundTransitionV1 {
        ClearingRoundTransitionV1::BeginAbort {
            abort_digest: self.abort_digest.clone(),
            zero_dispatch_proof_digest: self.zero_dispatch_proof_digest.clone(),
            authority_digest: self.authority_digest.clone(),
            frost_burn_checkpoint_digest: self.frost_burn_checkpoint_digest.clone(),
        }
    }

    pub fn abort_transition(
        &self,
        aborting_head: &EconomicResourceHeadV1,
        begin_abort_proof: &ClearingRoundTransitionProofV1,
    ) -> Result<ClearingRoundTransitionV1, ClearingError> {
        aborting_head
            .validate()
            .map_err(|_| ClearingError::InvalidField("aborting_round_head"))?;
        let record: ClearingRoundLifecycleRecordV1 =
            super::lifecycle::decode_inline(aborting_head)?;
        record.validate()?;
        super::lifecycle::validate_round_head(aborting_head, &record)?;
        let expected_version = self
            .source_lifecycle_version
            .checked_add(1)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        let expected_fence = self
            .source_lifecycle_fence
            .checked_add(1)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        begin_abort_proof.validate()?;
        let begin_abort_proof_digest = begin_abort_proof.digest()?;
        if record.state() != ClearingRoundLifecycleStateV1::Aborting
            || record.abort_digest() != Some(self.abort_digest.as_str())
            || record.last_transition_digest() != begin_abort_proof_digest
            || record.row_version() != expected_version
            || record.fence() != expected_fence
            || aborting_head.predecessor_digest.as_deref()
                != Some(self.source_lifecycle_head_digest.as_str())
            || aborting_head.trusted_clock_high_water < self.authorized_at_unix_ms
            || begin_abort_proof.source_round_head_digest != self.source_lifecycle_head_digest
            || begin_abort_proof.source_round_version != self.source_lifecycle_version
            || begin_abort_proof.source_round_fence != self.source_lifecycle_fence
            || begin_abort_proof.next_round_version != expected_version
            || begin_abort_proof.next_round_fence != expected_fence
            || begin_abort_proof.transition != self.begin_abort_transition()
        {
            return Err(ClearingError::IllegalLifecycleTransition);
        }
        Ok(ClearingRoundTransitionV1::Abort {
            abort_digest: self.abort_digest.clone(),
            zero_dispatch_proof_digest: self.zero_dispatch_proof_digest.clone(),
            authority_digest: self.authority_digest.clone(),
        })
    }
}

pub fn prepare_clearing_zero_dispatch_proof(
    current_round_head: &EconomicResourceHeadV1,
    request: &ClearingRoundRequestV1,
    signed_output: Option<&SignedClearingRoundOutputV1>,
    mut dispatch_statuses: Vec<ClearingIntentDispatchStatusV1>,
    clearing_trust: &ClearingAuthorityTrustV1,
    proof_trust: &ClearingZeroDispatchTrustV1,
    expires_at_unix_ms: u64,
) -> Result<ClearingZeroDispatchProofBodyV1, ClearingError> {
    clearing_trust.validate()?;
    proof_trust.validate()?;
    let context =
        zero_dispatch_context(current_round_head, request, signed_output, clearing_trust)?;
    dispatch_statuses.sort_by(|left, right| left.intent_id.cmp(&right.intent_id));
    verify_dispatch_statuses(&context.output.intents, &dispatch_statuses)?;
    let dispatch_status_count = checked_count(dispatch_statuses.len())?;
    let body = ClearingZeroDispatchProofBodyV1 {
        schema: CLEARING_ZERO_DISPATCH_PROOF_SCHEMA.to_owned(),
        round_id: request.round_id.clone(),
        round_core_digest: context.round_core_digest,
        output_manifest_digest: context.output_manifest_digest,
        settlement_intent_root: context.output.output_manifest.settlement_intent_root,
        settlement_intent_count: context.output.output_manifest.settlement_intent_count,
        source_lifecycle_head_digest: context.source_head_digest,
        source_lifecycle_version: current_round_head.resource_version,
        source_lifecycle_fence: current_round_head.lifecycle_fence,
        admission_store_id: proof_trust.admission_store_id.clone(),
        admission_commit_sequence: proof_trust.admission_commit_sequence,
        admission_commit_digest: proof_trust.admission_commit_digest.clone(),
        dispatch_status_root: domain_digest(ZERO_DISPATCH_STATUS_ROOT_DOMAIN, &dispatch_statuses)?,
        dispatch_status_count,
        dispatch_statuses,
        authority_id: proof_trust.authority_id.clone(),
        authority_key_epoch: proof_trust.authority_key_epoch,
        issued_at_unix_ms: proof_trust.trusted_time_unix_ms,
        expires_at_unix_ms,
    };
    body.validate()?;
    if body.issued_at_unix_ms < current_round_head.trusted_clock_high_water {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(body)
}

pub fn sign_clearing_zero_dispatch_proof(
    body: ClearingZeroDispatchProofBodyV1,
    trust: &ClearingZeroDispatchTrustV1,
    signer: &Keypair,
) -> Result<SignedClearingZeroDispatchProofV1, ClearingError> {
    trust.validate()?;
    body.validate()?;
    if body.authority_id != trust.authority_id
        || body.authority_key_epoch != trust.authority_key_epoch
        || body.admission_store_id != trust.admission_store_id
        || body.admission_commit_sequence != trust.admission_commit_sequence
        || body.admission_commit_digest != trust.admission_commit_digest
        || body.issued_at_unix_ms > trust.trusted_time_unix_ms
        || trust.trusted_time_unix_ms >= body.expires_at_unix_ms
        || signer.public_key() != trust.authority_key
    {
        return Err(ClearingError::AuthorityVerification);
    }
    SignedClearingZeroDispatchProofV1::sign(body, signer)
}

pub fn verify_clearing_zero_dispatch_proof(
    current_round_head: &EconomicResourceHeadV1,
    request: &ClearingRoundRequestV1,
    signed_output: Option<&SignedClearingRoundOutputV1>,
    signed_proof: &SignedClearingZeroDispatchProofV1,
    clearing_trust: &ClearingAuthorityTrustV1,
    proof_trust: &ClearingZeroDispatchTrustV1,
) -> Result<VerifiedClearingZeroDispatchProofV1, ClearingError> {
    clearing_trust.validate()?;
    proof_trust.validate()?;
    let context =
        zero_dispatch_context(current_round_head, request, signed_output, clearing_trust)?;
    let body = &signed_proof.body;
    body.validate()?;
    verify_dispatch_statuses(&context.output.intents, &body.dispatch_statuses)?;
    if body.round_id != request.round_id
        || body.round_core_digest != context.round_core_digest
        || body.output_manifest_digest != context.output_manifest_digest
        || body.settlement_intent_root != context.output.output_manifest.settlement_intent_root
        || body.settlement_intent_count != context.output.output_manifest.settlement_intent_count
        || body.source_lifecycle_head_digest != context.source_head_digest
        || body.source_lifecycle_version != current_round_head.resource_version
        || body.source_lifecycle_fence != current_round_head.lifecycle_fence
        || body.authority_id != proof_trust.authority_id
        || body.authority_key_epoch != proof_trust.authority_key_epoch
        || body.admission_store_id != proof_trust.admission_store_id
        || body.admission_commit_sequence != proof_trust.admission_commit_sequence
        || body.admission_commit_digest != proof_trust.admission_commit_digest
        || signed_proof.signer_key != proof_trust.authority_key
        || body.issued_at_unix_ms < current_round_head.trusted_clock_high_water
        || body.issued_at_unix_ms > proof_trust.trusted_time_unix_ms
        || proof_trust.trusted_time_unix_ms >= body.expires_at_unix_ms
        || !signed_proof.verify_signature()?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(VerifiedClearingZeroDispatchProofV1 {
        proof_digest: signed_proof.digest()?,
        round_id: body.round_id.clone(),
        round_core_digest: body.round_core_digest.clone(),
        output_manifest_digest: body.output_manifest_digest.clone(),
        source_lifecycle_head_digest: body.source_lifecycle_head_digest.clone(),
        source_lifecycle_version: body.source_lifecycle_version,
        source_lifecycle_fence: body.source_lifecycle_fence,
        verified_at_unix_ms: proof_trust.trusted_time_unix_ms,
        valid_until_unix_ms: body.expires_at_unix_ms,
    })
}

pub fn prepare_clearing_round_abort(
    current_round_head: &EconomicResourceHeadV1,
    zero_dispatch: &VerifiedClearingZeroDispatchProofV1,
    reason: ClearingRoundAbortReasonV1,
    authority_digest: String,
    burn: Option<ClearingFinalizationBurnEvidenceV1<'_>>,
    trust: &ClearingAuthorityTrustV1,
) -> Result<ClearingRoundAbortBodyV1, ClearingError> {
    trust.validate()?;
    let record = preabort_record(current_round_head)?;
    let source_head_digest = current_round_head
        .digest()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    validate_abort_inputs(
        current_round_head,
        &record,
        zero_dispatch,
        &source_head_digest,
        &authority_digest,
        trust,
    )?;
    let frost_burn_checkpoint_digest = verify_abort_burn(current_round_head, &record, burn, trust)?;
    let next_version = current_round_head
        .resource_version
        .checked_add(1)
        .filter(|next| *next <= I_JSON_MAX_SAFE_INTEGER)
        .ok_or(ClearingError::ArithmeticOverflow)?;
    let body = ClearingRoundAbortBodyV1 {
        schema: CLEARING_ROUND_ABORT_SCHEMA.to_owned(),
        round_id: record.round_id().to_owned(),
        governance_scope_id: record.governance_scope_id().to_owned(),
        round_core_digest: record.round_core_digest().to_owned(),
        output_manifest_digest: record.output_manifest_digest().map(str::to_owned),
        reservation_root: record.reservation_root().to_owned(),
        reservation_count: record.reservation_count(),
        reason,
        source_lifecycle_head_digest: source_head_digest,
        source_lifecycle_version: current_round_head.resource_version,
        source_lifecycle_fence: current_round_head.lifecycle_fence,
        next_lifecycle_version: next_version,
        next_lifecycle_fence: next_version,
        zero_dispatch_proof_digest: zero_dispatch.proof_digest.clone(),
        authority_digest,
        frost_burn_checkpoint_digest,
        disposition_authority_id: trust.obligation_authority_id.clone(),
        disposition_authority_key_epoch: trust.obligation_key_epoch,
        authorized_at_unix_ms: trust.trusted_time_unix_ms,
    };
    body.validate()?;
    Ok(body)
}

pub fn sign_clearing_round_abort(
    body: ClearingRoundAbortBodyV1,
    trust: &ClearingAuthorityTrustV1,
    signer: &Keypair,
) -> Result<SignedClearingRoundAbortV1, ClearingError> {
    trust.validate()?;
    body.validate()?;
    if body.disposition_authority_id != trust.obligation_authority_id
        || body.disposition_authority_key_epoch != trust.obligation_key_epoch
        || body.authorized_at_unix_ms > trust.trusted_time_unix_ms
        || signer.public_key() != trust.obligation_authority_key
    {
        return Err(ClearingError::AuthorityVerification);
    }
    SignedClearingRoundAbortV1::sign(body, signer)
}

pub fn verify_clearing_round_abort(
    current_round_head: &EconomicResourceHeadV1,
    zero_dispatch: &VerifiedClearingZeroDispatchProofV1,
    signed_abort: &SignedClearingRoundAbortV1,
    burn: Option<ClearingFinalizationBurnEvidenceV1<'_>>,
    trust: &ClearingAuthorityTrustV1,
) -> Result<VerifiedClearingRoundAbortV1, ClearingError> {
    trust.validate()?;
    let record = preabort_record(current_round_head)?;
    let source_head_digest = current_round_head
        .digest()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let body = &signed_abort.body;
    body.validate()?;
    validate_abort_inputs(
        current_round_head,
        &record,
        zero_dispatch,
        &source_head_digest,
        &body.authority_digest,
        trust,
    )?;
    let frost_burn_checkpoint_digest = verify_abort_burn(current_round_head, &record, burn, trust)?;
    if body.round_id != record.round_id()
        || body.governance_scope_id != record.governance_scope_id()
        || body.round_core_digest != record.round_core_digest()
        || body.output_manifest_digest.as_deref() != record.output_manifest_digest()
        || body.reservation_root != record.reservation_root()
        || body.reservation_count != record.reservation_count()
        || body.source_lifecycle_head_digest != source_head_digest
        || body.source_lifecycle_version != current_round_head.resource_version
        || body.source_lifecycle_fence != current_round_head.lifecycle_fence
        || body.zero_dispatch_proof_digest != zero_dispatch.proof_digest
        || body.frost_burn_checkpoint_digest != frost_burn_checkpoint_digest
        || body.disposition_authority_id != trust.obligation_authority_id
        || body.disposition_authority_key_epoch != trust.obligation_key_epoch
        || signed_abort.signer_key != trust.obligation_authority_key
        || body.authorized_at_unix_ms < zero_dispatch.verified_at_unix_ms
        || body.authorized_at_unix_ms < current_round_head.trusted_clock_high_water
        || body.authorized_at_unix_ms > trust.trusted_time_unix_ms
        || !signed_abort.verify_signature()?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(VerifiedClearingRoundAbortV1 {
        abort_digest: signed_abort.digest()?,
        zero_dispatch_proof_digest: zero_dispatch.proof_digest.clone(),
        authority_digest: body.authority_digest.clone(),
        frost_burn_checkpoint_digest,
        source_lifecycle_head_digest: source_head_digest,
        source_lifecycle_version: current_round_head.resource_version,
        source_lifecycle_fence: current_round_head.lifecycle_fence,
        authorized_at_unix_ms: body.authorized_at_unix_ms,
    })
}

pub fn verify_clearing_round_finalization_burn(
    finalization: &ClearingRoundFinalizationBodyV1,
    burned_slot: &VerifiedBurnedFrostAuthorizationSlot,
    trusted_time_unix_ms: u64,
) -> Result<String, ClearingError> {
    finalization.validate()?;
    validate_positive("trusted_time_unix_ms", trusted_time_unix_ms)?;
    let checkpoint = burned_slot.checkpoint();
    let registration = frost_action_registration(FrostAuthorizationDomain::ClearingRoundFinalize)
        .ok_or(ClearingError::AuthorityVerification)?;
    let action = finalization.frost_action_preimage()?;
    let action_digest = action
        .action_digest()
        .map_err(|_| ClearingError::AuthorityVerification)?;
    if checkpoint.state != FrostAuthorizationSlotState::Burned
        || checkpoint.domain != FrostAuthorizationDomain::ClearingRoundFinalize
        || checkpoint.ladder_action_class != registration.ladder_action_class
        || checkpoint.scope_id != finalization.governance_scope_id
        || checkpoint.resource_id != finalization.round_id
        || checkpoint.resource_version != finalization.source_lifecycle_version
        || checkpoint.resource_fence != finalization.source_lifecycle_fence
        || checkpoint.action_digest != action_digest
        || checkpoint.clock_high_water < finalization.finalized_at_unix_ms
        || checkpoint.clock_high_water > trusted_time_unix_ms
    {
        return Err(ClearingError::AuthorityVerification);
    }
    validate_digest(
        "frost_burn_checkpoint_digest",
        &checkpoint.checkpoint_digest,
    )?;
    Ok(checkpoint.checkpoint_digest.clone())
}

struct ZeroDispatchContext {
    output: ClearingRoundOutputV1,
    round_core_digest: String,
    output_manifest_digest: Option<String>,
    source_head_digest: String,
}

fn zero_dispatch_context(
    current_round_head: &EconomicResourceHeadV1,
    request: &ClearingRoundRequestV1,
    signed_output: Option<&SignedClearingRoundOutputV1>,
    trust: &ClearingAuthorityTrustV1,
) -> Result<ZeroDispatchContext, ClearingError> {
    let record = preabort_record(current_round_head)?;
    let mut admission_trust = trust.clone();
    admission_trust.trusted_time_unix_ms = request.generated_at_unix_ms;
    let output = if let Some(signed_output) = signed_output {
        verify_signed_netting_round(request, &admission_trust, signed_output)?
    } else {
        compute_netting_round(request, &admission_trust)?
    };
    let round_core_digest = output.core.digest()?;
    let computed_output_manifest_digest = output.output_manifest.digest()?;
    let output_manifest_digest = record.output_manifest_digest().map(str::to_owned);
    if record.round_id() != request.round_id
        || record.round_core_digest() != round_core_digest
        || record.reservation_root() != output.core.reservation_root
        || record.reservation_count() != output.core.input_count
        || match record.state() {
            ClearingRoundLifecycleStateV1::Reserved => output_manifest_digest.is_some(),
            ClearingRoundLifecycleStateV1::Proposed | ClearingRoundLifecycleStateV1::Finalizing => {
                signed_output.is_none()
                    || output_manifest_digest.as_deref()
                        != Some(computed_output_manifest_digest.as_str())
            }
            _ => true,
        }
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(ZeroDispatchContext {
        output,
        round_core_digest,
        output_manifest_digest,
        source_head_digest: current_round_head
            .digest()
            .map_err(|_| ClearingError::InvalidField("current_round_head"))?,
    })
}

fn verify_dispatch_statuses(
    intents: &[ClearingSettlementIntentV1],
    statuses: &[ClearingIntentDispatchStatusV1],
) -> Result<(), ClearingError> {
    if intents.len() != statuses.len() {
        return Err(ClearingError::AuthorityVerification);
    }
    let mut expected = intents.iter().collect::<Vec<_>>();
    expected.sort_by(|left, right| left.intent_id.cmp(&right.intent_id));
    for (intent, status) in expected.into_iter().zip(statuses) {
        status.validate()?;
        if status.intent_id != intent.intent_id
            || status.intent_digest != domain_digest(INTENT_DIGEST_DOMAIN, intent)?
            || status.dispatch_idempotency_key != intent.dispatch_idempotency_key
        {
            return Err(ClearingError::AuthorityVerification);
        }
    }
    Ok(())
}

fn validate_abort_inputs(
    current_round_head: &EconomicResourceHeadV1,
    record: &ClearingRoundLifecycleRecordV1,
    zero_dispatch: &VerifiedClearingZeroDispatchProofV1,
    source_head_digest: &str,
    authority_digest: &str,
    trust: &ClearingAuthorityTrustV1,
) -> Result<(), ClearingError> {
    validate_digest("abort_authority_digest", authority_digest)?;
    if zero_dispatch.round_id != record.round_id()
        || zero_dispatch.round_core_digest != record.round_core_digest()
        || zero_dispatch.output_manifest_digest.as_deref() != record.output_manifest_digest()
        || zero_dispatch.source_lifecycle_head_digest != source_head_digest
        || zero_dispatch.source_lifecycle_version != current_round_head.resource_version
        || zero_dispatch.source_lifecycle_fence != current_round_head.lifecycle_fence
        || trust.trusted_time_unix_ms < zero_dispatch.verified_at_unix_ms
        || trust.trusted_time_unix_ms >= zero_dispatch.valid_until_unix_ms
        || trust.trusted_time_unix_ms < current_round_head.trusted_clock_high_water
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

fn verify_abort_burn(
    current_round_head: &EconomicResourceHeadV1,
    record: &ClearingRoundLifecycleRecordV1,
    burn: Option<ClearingFinalizationBurnEvidenceV1<'_>>,
    trust: &ClearingAuthorityTrustV1,
) -> Result<Option<String>, ClearingError> {
    match (record.state(), burn) {
        (
            ClearingRoundLifecycleStateV1::Finalizing,
            Some(ClearingFinalizationBurnEvidenceV1 {
                finalization,
                burned_slot,
            }),
        ) => {
            let body = &finalization.body;
            body.validate()?;
            let source_digest = current_round_head
                .digest()
                .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
            if body.round_id != record.round_id()
                || body.governance_scope_id != record.governance_scope_id()
                || body.round_core_digest != record.round_core_digest()
                || record.output_manifest_digest() != Some(body.output_manifest_digest.as_str())
                || record.participant_acceptance_root()
                    != Some(body.participant_acceptance_root.as_str())
                || record.participant_acceptance_count() != Some(body.participant_acceptance_count)
                || body.source_lifecycle_head_digest != source_digest
                || body.source_lifecycle_version != current_round_head.resource_version
                || body.source_lifecycle_fence != current_round_head.lifecycle_fence
                || body.clearing_authority_id != trust.clearing_authority_id
                || body.clearing_authority_key_epoch != trust.clearing_authority_key_epoch
                || finalization.signer_key != trust.clearing_authority_key
                || body.finalized_at_unix_ms > trust.trusted_time_unix_ms
                || !finalization.verify_signature()?
            {
                return Err(ClearingError::AuthorityVerification);
            }
            verify_clearing_round_finalization_burn(body, burned_slot, trust.trusted_time_unix_ms)
                .map(Some)
        }
        (
            ClearingRoundLifecycleStateV1::Reserved | ClearingRoundLifecycleStateV1::Proposed,
            None,
        ) => Ok(None),
        _ => Err(ClearingError::AuthorityVerification),
    }
}

fn preabort_record(
    current_round_head: &EconomicResourceHeadV1,
) -> Result<ClearingRoundLifecycleRecordV1, ClearingError> {
    current_round_head
        .validate()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let record: ClearingRoundLifecycleRecordV1 =
        super::lifecycle::decode_inline(current_round_head)?;
    record.validate()?;
    super::lifecycle::validate_round_head(current_round_head, &record)?;
    if !matches!(
        record.state(),
        ClearingRoundLifecycleStateV1::Reserved
            | ClearingRoundLifecycleStateV1::Proposed
            | ClearingRoundLifecycleStateV1::Finalizing
    ) {
        return Err(ClearingError::IllegalLifecycleTransition);
    }
    Ok(record)
}

fn validate_count(field: &'static str, count: u64, actual: usize) -> Result<(), ClearingError> {
    if count > u64::try_from(MAX_CLEARING_INPUTS).map_err(|_| ClearingError::ArithmeticOverflow)?
        || usize::try_from(count).map_err(|_| ClearingError::ArithmeticOverflow)? != actual
    {
        return Err(ClearingError::InvalidField(field));
    }
    Ok(())
}

fn validate_optional_digest(field: &'static str, value: Option<&str>) -> Result<(), ClearingError> {
    value.map_or(Ok(()), |value| validate_digest(field, value))
}
