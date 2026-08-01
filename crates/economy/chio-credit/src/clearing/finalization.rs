use super::*;
use chio_core_types::economic_continuity::{EconomicFrostBindingV1, EconomicResourceHeadV1};
use chio_federation::frost::{
    FrostActionPreimageV1, FrostClearingRoundFinalizeActionV1, VerifiedFrostAuthorization,
    VerifiedHistoricalCompletedFrostAuthorization,
    CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA,
};

const ACCEPTANCE_ROOT_DOMAIN: &[u8] = b"chio.clearing.participant-acceptance-root.v1\0";
const ACCEPTANCE_SET_DOMAIN: &[u8] = b"chio.clearing.participant-acceptance-set.v1\0";
const ROUND_FINALIZATION_BODY_DOMAIN: &[u8] = b"chio.clearing.round-finalization.body.v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingParticipantAcceptanceBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub round_core_digest: String,
    pub output_manifest_digest: String,
    pub participant_statement_digest: String,
    pub participant_id: String,
    pub key_epoch: u64,
    pub accepted_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

pub type SignedClearingParticipantAcceptanceV1 =
    SignedClearingEnvelopeV1<ClearingParticipantAcceptanceBodyV1>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingDisputeWindowStatusV1 {
    pub round_id: String,
    pub round_core_digest: String,
    pub output_manifest_digest: String,
    pub dispute_window_ends_at_unix_ms: u64,
    pub observed_through_unix_ms: u64,
    pub unresolved_dispute_count: u64,
    pub checkpoint_digest: String,
}

pub trait ClearingDisputeWindowResolver: Send + Sync {
    fn resolve_closed_window(
        &self,
        round_id: &str,
        round_core_digest: &str,
        output_manifest_digest: &str,
        dispute_window_ends_at_unix_ms: u64,
    ) -> Result<ClearingDisputeWindowStatusV1, ClearingError>;

    fn resolve_closed_window_checkpoint(
        &self,
        round_id: &str,
        round_core_digest: &str,
        output_manifest_digest: &str,
        dispute_window_ends_at_unix_ms: u64,
        checkpoint_digest: &str,
    ) -> Result<ClearingDisputeWindowStatusV1, ClearingError> {
        let status = self.resolve_closed_window(
            round_id,
            round_core_digest,
            output_manifest_digest,
            dispute_window_ends_at_unix_ms,
        )?;
        if status.checkpoint_digest != checkpoint_digest {
            return Err(ClearingError::AuthorityVerification);
        }
        Ok(status)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedClearingParticipantAcceptancesV1 {
    round_id: String,
    round_core_digest: String,
    output_manifest_digest: String,
    acceptance_root: String,
    acceptance_count: u64,
    evidence_digest: String,
    verified_at_unix_ms: u64,
    valid_until_unix_ms: u64,
    clearing_authority_id: String,
    clearing_authority_key_epoch: u64,
    clearing_authority_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundFinalizationBodyV1 {
    pub schema: String,
    pub round_id: String,
    pub governance_scope_id: String,
    pub round_core_digest: String,
    pub output_manifest_digest: String,
    pub participant_acceptance_root: String,
    pub participant_acceptance_count: u64,
    pub source_lifecycle_head_digest: String,
    pub source_lifecycle_version: u64,
    pub source_lifecycle_fence: u64,
    pub clearing_authority_id: String,
    pub clearing_authority_key_epoch: u64,
    pub finalized_at_unix_ms: u64,
}

impl ClearingRoundFinalizationBodyV1 {
    pub fn digest(&self) -> Result<String, ClearingError> {
        self.validate()?;
        domain_digest(ROUND_FINALIZATION_BODY_DOMAIN, self)
    }

    pub fn frost_action_preimage(&self) -> Result<FrostActionPreimageV1, ClearingError> {
        let preimage =
            FrostActionPreimageV1::ClearingRoundFinalize(FrostClearingRoundFinalizeActionV1 {
                schema: CHIO_FROST_CLEARING_ROUND_FINALIZE_ACTION_SCHEMA.to_owned(),
                round_finalization_body_digest: self.digest()?,
                output_manifest_root: self.output_manifest_digest.clone(),
                acceptance_root: self.participant_acceptance_root.clone(),
                round_id: self.round_id.clone(),
                resource_version: self.source_lifecycle_version,
                resource_fence: self.source_lifecycle_fence,
            });
        preimage
            .validate()
            .map_err(|_| ClearingError::InvalidField("frost_action"))?;
        Ok(preimage)
    }

    pub(super) fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ROUND_FINALIZATION_SCHEMA {
            return Err(ClearingError::InvalidField("round_finalization_schema"));
        }
        validate_text("round_id", &self.round_id)?;
        validate_text("governance_scope_id", &self.governance_scope_id)?;
        validate_digest("round_core_digest", &self.round_core_digest)?;
        validate_digest("output_manifest_digest", &self.output_manifest_digest)?;
        validate_digest(
            "participant_acceptance_root",
            &self.participant_acceptance_root,
        )?;
        validate_positive(
            "participant_acceptance_count",
            self.participant_acceptance_count,
        )?;
        if usize::try_from(self.participant_acceptance_count)
            .map_err(|_| ClearingError::ArithmeticOverflow)?
            > MAX_CLEARING_PARTICIPANTS
        {
            return Err(ClearingError::InvalidField("participant_acceptance_count"));
        }
        validate_digest(
            "source_lifecycle_head_digest",
            &self.source_lifecycle_head_digest,
        )?;
        validate_positive("source_lifecycle_version", self.source_lifecycle_version)?;
        validate_positive("source_lifecycle_fence", self.source_lifecycle_fence)?;
        validate_text("clearing_authority_id", &self.clearing_authority_id)?;
        validate_positive(
            "clearing_authority_key_epoch",
            self.clearing_authority_key_epoch,
        )?;
        validate_positive("finalized_at_unix_ms", self.finalized_at_unix_ms)?;
        if self.source_lifecycle_version != self.source_lifecycle_fence {
            return Err(ClearingError::InvalidField("source_lifecycle_fence"));
        }
        Ok(())
    }
}

pub type SignedClearingRoundFinalizationV1 =
    SignedClearingEnvelopeV1<ClearingRoundFinalizationBodyV1>;

#[derive(Debug, Clone)]
pub struct VerifiedClearingRoundFinalizationV1 {
    body: ClearingRoundFinalizationBodyV1,
    finalization_digest: String,
    frost: EconomicFrostBindingV1,
}

impl VerifiedClearingRoundFinalizationV1 {
    #[must_use]
    pub fn body(&self) -> &ClearingRoundFinalizationBodyV1 {
        &self.body
    }

    #[must_use]
    pub fn finalization_digest(&self) -> &str {
        &self.finalization_digest
    }

    #[must_use]
    pub fn finalize_transition(&self) -> ClearingRoundTransitionV1 {
        ClearingRoundTransitionV1::Finalize {
            finalization_digest: self.finalization_digest.clone(),
            frost: self.frost.clone(),
        }
    }
}

impl VerifiedClearingParticipantAcceptancesV1 {
    #[must_use]
    pub fn round_id(&self) -> &str {
        &self.round_id
    }

    #[must_use]
    pub fn round_core_digest(&self) -> &str {
        &self.round_core_digest
    }

    #[must_use]
    pub fn output_manifest_digest(&self) -> &str {
        &self.output_manifest_digest
    }

    #[must_use]
    pub fn acceptance_root(&self) -> &str {
        &self.acceptance_root
    }

    #[must_use]
    pub const fn acceptance_count(&self) -> u64 {
        self.acceptance_count
    }

    #[must_use]
    pub const fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    #[must_use]
    pub fn begin_finalization_transition(&self) -> ClearingRoundTransitionV1 {
        ClearingRoundTransitionV1::BeginFinalization {
            acceptance_root: self.acceptance_root.clone(),
            acceptance_count: self.acceptance_count,
            authority_digest: self.evidence_digest.clone(),
        }
    }
}

pub fn verify_clearing_participant_acceptances(
    request: &ClearingRoundRequestV1,
    signed_output: &SignedClearingRoundOutputV1,
    acceptances: &[SignedClearingParticipantAcceptanceV1],
    dispute_resolver: &dyn ClearingDisputeWindowResolver,
    trust: &ClearingAuthorityTrustV1,
) -> Result<VerifiedClearingParticipantAcceptancesV1, ClearingError> {
    trust.validate()?;
    if trust.trusted_time_unix_ms < request.dispute_window_ends_at_unix_ms {
        return Err(ClearingError::InvalidField("dispute_window"));
    }
    let mut admission_trust = trust.clone();
    admission_trust.trusted_time_unix_ms = request.generated_at_unix_ms;
    let output = verify_signed_netting_round(request, &admission_trust, signed_output)?;
    if trust.trusted_time_unix_ms >= request.participant_snapshot.body.expires_at_unix_ms
        || acceptances.len() != output.participant_statements.len()
        || !acceptances.windows(2).all(|pair| {
            pair[0].body.participant_id.as_bytes() < pair[1].body.participant_id.as_bytes()
        })
    {
        return Err(ClearingError::AuthorityVerification);
    }

    let round_core_digest = output.core.digest()?;
    let output_manifest_digest = output.output_manifest.digest()?;
    let dispute_status = dispute_resolver.resolve_closed_window(
        &request.round_id,
        &round_core_digest,
        &output_manifest_digest,
        request.dispute_window_ends_at_unix_ms,
    )?;
    validate_digest(
        "dispute_checkpoint_digest",
        &dispute_status.checkpoint_digest,
    )?;
    if dispute_status.round_id != request.round_id
        || dispute_status.round_core_digest != round_core_digest
        || dispute_status.output_manifest_digest != output_manifest_digest
        || dispute_status.dispute_window_ends_at_unix_ms != request.dispute_window_ends_at_unix_ms
        || dispute_status.observed_through_unix_ms < request.dispute_window_ends_at_unix_ms
        || dispute_status.observed_through_unix_ms > trust.trusted_time_unix_ms
        || dispute_status.unresolved_dispute_count != 0
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let mut acceptance_digests = Vec::with_capacity(acceptances.len());
    let mut valid_until_unix_ms = request.participant_snapshot.body.expires_at_unix_ms;
    for (statement, acceptance) in output.participant_statements.iter().zip(acceptances) {
        let participant = request
            .participant_snapshot
            .body
            .participants
            .iter()
            .find(|participant| participant.participant_id == statement.participant_id)
            .ok_or(ClearingError::AuthorityVerification)?;
        let acknowledgement = request
            .participant_acknowledgements
            .iter()
            .find(|acknowledgement| acknowledgement.body.participant_id == statement.participant_id)
            .ok_or(ClearingError::AuthorityVerification)?;
        let body = &acceptance.body;
        if body.schema != CLEARING_PARTICIPANT_ACCEPTANCE_SCHEMA
            || body.round_id != request.round_id
            || body.round_core_digest != round_core_digest
            || body.output_manifest_digest != output_manifest_digest
            || body.participant_statement_digest != statement.digest()?
            || body.participant_id != statement.participant_id
            || body.key_epoch != participant.acknowledgement_key_epoch
            || acceptance.signer_key != participant.acknowledgement_key
            || body.accepted_at_unix_ms < request.generated_at_unix_ms
            || body.accepted_at_unix_ms > trust.trusted_time_unix_ms
            || trust.trusted_time_unix_ms >= body.expires_at_unix_ms
            || body.expires_at_unix_ms > request.participant_snapshot.body.expires_at_unix_ms
            || trust.trusted_time_unix_ms >= acknowledgement.body.expires_at_unix_ms
            || !acceptance.verify_signature()?
        {
            return Err(ClearingError::AuthorityVerification);
        }
        validate_positive("participant_acceptance_key_epoch", body.key_epoch)?;
        validate_positive("participant_accepted_at_unix_ms", body.accepted_at_unix_ms)?;
        validate_positive(
            "participant_acceptance_expires_at_unix_ms",
            body.expires_at_unix_ms,
        )?;
        valid_until_unix_ms = valid_until_unix_ms
            .min(body.expires_at_unix_ms)
            .min(acknowledgement.body.expires_at_unix_ms);
        acceptance_digests.push(acceptance.digest()?);
    }

    let acceptance_count = checked_count(acceptances.len())?;
    let acceptance_root = domain_digest(ACCEPTANCE_ROOT_DOMAIN, &acceptance_digests)?;
    let evidence_digest = domain_digest(
        ACCEPTANCE_SET_DOMAIN,
        &(
            request.round_id.as_str(),
            round_core_digest.as_str(),
            output_manifest_digest.as_str(),
            acceptance_root.as_str(),
            acceptance_count,
            dispute_status.checkpoint_digest.as_str(),
        ),
    )?;
    Ok(VerifiedClearingParticipantAcceptancesV1 {
        round_id: request.round_id.clone(),
        round_core_digest,
        output_manifest_digest,
        acceptance_root,
        acceptance_count,
        evidence_digest,
        verified_at_unix_ms: trust.trusted_time_unix_ms,
        valid_until_unix_ms,
        clearing_authority_id: output.core.clearing_authority_id,
        clearing_authority_key_epoch: output.core.clearing_authority_key_epoch,
        clearing_authority_key: trust.clearing_authority_key.clone(),
    })
}

pub fn prepare_clearing_round_finalization(
    current_round_head: &EconomicResourceHeadV1,
    acceptances: &VerifiedClearingParticipantAcceptancesV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<ClearingRoundFinalizationBodyV1, ClearingError> {
    trust.validate()?;
    let record = finalizing_record(current_round_head)?;
    if record.round_id() != acceptances.round_id
        || record.round_core_digest() != acceptances.round_core_digest
        || record.output_manifest_digest() != Some(acceptances.output_manifest_digest.as_str())
        || record.participant_acceptance_root() != Some(acceptances.acceptance_root.as_str())
        || record.participant_acceptance_count() != Some(acceptances.acceptance_count)
        || trust.clearing_authority_id != acceptances.clearing_authority_id
        || trust.clearing_authority_key_epoch != acceptances.clearing_authority_key_epoch
        || trust.clearing_authority_key != acceptances.clearing_authority_key
        || trust.trusted_time_unix_ms < acceptances.verified_at_unix_ms
        || trust.trusted_time_unix_ms >= acceptances.valid_until_unix_ms
        || trust.trusted_time_unix_ms < current_round_head.trusted_clock_high_water
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let body = ClearingRoundFinalizationBodyV1 {
        schema: CLEARING_ROUND_FINALIZATION_SCHEMA.to_owned(),
        round_id: record.round_id().to_owned(),
        governance_scope_id: record.governance_scope_id().to_owned(),
        round_core_digest: record.round_core_digest().to_owned(),
        output_manifest_digest: acceptances.output_manifest_digest.clone(),
        participant_acceptance_root: acceptances.acceptance_root.clone(),
        participant_acceptance_count: acceptances.acceptance_count,
        source_lifecycle_head_digest: current_round_head
            .digest()
            .map_err(|_| ClearingError::InvalidField("current_round_head"))?,
        source_lifecycle_version: current_round_head.resource_version,
        source_lifecycle_fence: current_round_head.lifecycle_fence,
        clearing_authority_id: trust.clearing_authority_id.clone(),
        clearing_authority_key_epoch: trust.clearing_authority_key_epoch,
        finalized_at_unix_ms: trust.trusted_time_unix_ms,
    };
    body.validate()?;
    Ok(body)
}

pub fn sign_clearing_round_finalization(
    body: ClearingRoundFinalizationBodyV1,
    trust: &ClearingAuthorityTrustV1,
    signer: &Keypair,
) -> Result<SignedClearingRoundFinalizationV1, ClearingError> {
    trust.validate()?;
    body.validate()?;
    if body.clearing_authority_id != trust.clearing_authority_id
        || body.clearing_authority_key_epoch != trust.clearing_authority_key_epoch
        || body.finalized_at_unix_ms > trust.trusted_time_unix_ms
        || signer.public_key() != trust.clearing_authority_key
    {
        return Err(ClearingError::AuthorityVerification);
    }
    SignedClearingRoundFinalizationV1::sign(body, signer)
}

pub fn verify_clearing_round_finalization(
    current_round_head: &EconomicResourceHeadV1,
    acceptances: &VerifiedClearingParticipantAcceptancesV1,
    signed: &SignedClearingRoundFinalizationV1,
    frost: &VerifiedFrostAuthorization,
    trust: &ClearingAuthorityTrustV1,
) -> Result<VerifiedClearingRoundFinalizationV1, ClearingError> {
    verify_clearing_round_finalization_envelope(current_round_head, acceptances, signed, trust)?;
    let body = &signed.body;
    let frost = verify_clearing_round_finalization_frost(body, frost, trust.trusted_time_unix_ms)?;
    Ok(VerifiedClearingRoundFinalizationV1 {
        body: body.clone(),
        finalization_digest: signed.digest()?,
        frost,
    })
}

pub(super) fn verify_historical_clearing_round_finalization(
    current_round_head: &EconomicResourceHeadV1,
    acceptances: &VerifiedClearingParticipantAcceptancesV1,
    signed: &SignedClearingRoundFinalizationV1,
    frost: &VerifiedHistoricalCompletedFrostAuthorization,
    trust: &ClearingAuthorityTrustV1,
) -> Result<VerifiedClearingRoundFinalizationV1, ClearingError> {
    verify_clearing_round_finalization_envelope(current_round_head, acceptances, signed, trust)?;
    let body = &signed.body;
    if frost.issued_at() < body.finalized_at_unix_ms
        || frost.completed_at() != trust.trusted_time_unix_ms
        || frost.scope_id() != body.governance_scope_id
        || frost
            .verify_action_preimage(&body.frost_action_preimage()?)
            .is_err()
    {
        return Err(ClearingError::AuthorityVerification);
    }
    let frost = frost_binding(
        frost.authorization_slot_id(),
        frost.authorization_id(),
        frost.action_digest(),
        frost.proof_digest(),
    )?;
    Ok(VerifiedClearingRoundFinalizationV1 {
        body: body.clone(),
        finalization_digest: signed.digest()?,
        frost,
    })
}

fn verify_clearing_round_finalization_envelope(
    current_round_head: &EconomicResourceHeadV1,
    acceptances: &VerifiedClearingParticipantAcceptancesV1,
    signed: &SignedClearingRoundFinalizationV1,
    trust: &ClearingAuthorityTrustV1,
) -> Result<(), ClearingError> {
    trust.validate()?;
    let record = finalizing_record(current_round_head)?;
    let body = &signed.body;
    body.validate()?;
    if record.round_id() != acceptances.round_id
        || record.round_core_digest() != acceptances.round_core_digest
        || record.output_manifest_digest() != Some(acceptances.output_manifest_digest.as_str())
        || record.participant_acceptance_root() != Some(acceptances.acceptance_root.as_str())
        || record.participant_acceptance_count() != Some(acceptances.acceptance_count)
        || body.round_id != acceptances.round_id
        || body.governance_scope_id != record.governance_scope_id()
        || body.round_core_digest != acceptances.round_core_digest
        || body.output_manifest_digest != acceptances.output_manifest_digest
        || body.participant_acceptance_root != acceptances.acceptance_root
        || body.participant_acceptance_count != acceptances.acceptance_count
        || body.source_lifecycle_head_digest
            != current_round_head
                .digest()
                .map_err(|_| ClearingError::InvalidField("current_round_head"))?
        || body.source_lifecycle_version != current_round_head.resource_version
        || body.source_lifecycle_fence != current_round_head.lifecycle_fence
        || body.clearing_authority_id != acceptances.clearing_authority_id
        || body.clearing_authority_key_epoch != acceptances.clearing_authority_key_epoch
        || body.clearing_authority_id != trust.clearing_authority_id
        || body.clearing_authority_key_epoch != trust.clearing_authority_key_epoch
        || signed.signer_key != acceptances.clearing_authority_key
        || signed.signer_key != trust.clearing_authority_key
        || body.finalized_at_unix_ms < acceptances.verified_at_unix_ms
        || body.finalized_at_unix_ms < current_round_head.trusted_clock_high_water
        || body.finalized_at_unix_ms > trust.trusted_time_unix_ms
        || trust.trusted_time_unix_ms >= acceptances.valid_until_unix_ms
        || !signed.verify_signature()?
    {
        return Err(ClearingError::AuthorityVerification);
    }
    Ok(())
}

pub fn verify_clearing_round_finalization_frost(
    body: &ClearingRoundFinalizationBodyV1,
    frost: &VerifiedFrostAuthorization,
    trusted_time_unix_ms: u64,
) -> Result<EconomicFrostBindingV1, ClearingError> {
    body.validate()?;
    validate_positive("trusted_time_unix_ms", trusted_time_unix_ms)?;
    if body.finalized_at_unix_ms > trusted_time_unix_ms
        || frost.issued_at() < body.finalized_at_unix_ms
        || !frost.is_current_at(trusted_time_unix_ms)
        || frost.scope_id() != body.governance_scope_id
        || frost
            .verify_action_preimage(&body.frost_action_preimage()?)
            .is_err()
    {
        return Err(ClearingError::AuthorityVerification);
    }
    frost_binding(
        frost.authorization_slot_id(),
        frost.authorization_id(),
        frost.action_digest(),
        frost.proof_digest(),
    )
}

fn frost_binding(
    authorization_slot_id: &str,
    authorization_id: &str,
    action_digest: &str,
    proof_digest: &str,
) -> Result<EconomicFrostBindingV1, ClearingError> {
    let binding = EconomicFrostBindingV1 {
        authorization_slot_id: authorization_slot_id.to_owned(),
        authorization_id: authorization_id.to_owned(),
        action_digest: action_digest.to_owned(),
        signed_envelope_digest: proof_digest.to_owned(),
    };
    binding
        .validate()
        .map_err(|_| ClearingError::AuthorityVerification)?;
    Ok(binding)
}

fn finalizing_record(
    current_round_head: &EconomicResourceHeadV1,
) -> Result<ClearingRoundLifecycleRecordV1, ClearingError> {
    current_round_head
        .validate()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let record: ClearingRoundLifecycleRecordV1 =
        super::lifecycle::decode_inline(current_round_head)?;
    record.validate()?;
    super::lifecycle::validate_round_head(current_round_head, &record)?;
    if record.state() != ClearingRoundLifecycleStateV1::Finalizing {
        return Err(ClearingError::IllegalLifecycleTransition);
    }
    Ok(record)
}
