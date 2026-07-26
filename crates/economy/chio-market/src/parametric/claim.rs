use serde::{Deserialize, Serialize};
use thiserror::Error;

use chio_core_types::economic_continuity::{
    EconomicAdmissionHandoffStateV1, EconomicAdmissionHandoffV1, EconomicEffectSlotV1,
    EconomicEffectStateV1, EconomicRequestBindingV1,
};

use super::*;
use crate::credit::{
    CapitalBookSourceKind, CapitalExecutionInstructionAction, CapitalExecutionInstructionArtifact,
    CapitalExecutionIntendedState, CapitalExecutionReconciledState, CapitalExecutionRole,
    SignedCapitalExecutionInstruction,
};

pub const PARAMETRIC_CLAIM_RECORD_SCHEMA: &str = "chio.parametric.claim-record.v1";
pub const PARAMETRIC_CONTEST_SCHEMA: &str = "chio.parametric.contest.v1";
pub const PARAMETRIC_PAYOUT_INTENT_SCHEMA: &str = "chio.parametric.payout-intent.v1";
pub const PARAMETRIC_PAYOUT_BINDING_SCHEMA: &str = "chio.parametric.payout-binding.v1";
pub const PARAMETRIC_CONTEST_ID_DOMAIN: &str = "chio.parametric.contest.id.v1";
pub const PARAMETRIC_PAYOUT_INTENT_ID_DOMAIN: &str = "chio.parametric.payout-intent.id.v1";
pub const PARAMETRIC_PAYOUT_DESTINATION_ACCOUNT_DIGEST_DOMAIN: &str =
    "chio.parametric.payout-destination-account.v1";
pub const PARAMETRIC_PAYOUT_SOURCE_ACCOUNT_DIGEST_DOMAIN: &str =
    "chio.parametric.payout-source-account.v1";
pub const PARAMETRIC_PAYOUT_PREPARATION_BINDING_SCHEMA: &str =
    "chio.parametric.payout-preparation-binding.v1";
pub const PARAMETRIC_PAYOUT_CAPITAL_INSTRUCTION_ID_DOMAIN: &str =
    "chio.parametric.payout-capital-instruction.id.v1";
pub const PARAMETRIC_PAYOUT_ACTION_DIGEST_DOMAIN: &str = "chio.parametric.payout-action.v1";
pub const PARAMETRIC_PAYOUT_TARGET_QUALIFICATION_DIGEST_DOMAIN: &str =
    "chio.parametric.payout-target-qualification.v1";
pub const PARAMETRIC_PAYOUT_EFFECT_IDEMPOTENCY_KEY_DOMAIN: &str =
    "chio.parametric.payout-effect-idempotency.v1";
pub const PARAMETRIC_PAYOUT_ECONOMIC_NAMESPACE: &str = "parametric";
pub const PARAMETRIC_LIABILITY_COVERAGE_RESOURCE_FAMILY: &str = "liability_coverage";
pub const PARAMETRIC_PAYOUT_EFFECT_KIND: &str = "parametric_payout";
pub const MAX_PARAMETRIC_CONTEST_EVIDENCE: usize = 64;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParametricClaimError {
    #[error(transparent)]
    Contract(#[from] ParametricContractError),
    #[error("parametric claim compare-and-swap conflict: {0}")]
    CompareAndSwapConflict(&'static str),
    #[error("parametric claim transition is invalid from state: {0}")]
    InvalidTransition(&'static str),
    #[error("parametric contest is outside its trusted receipt window")]
    ContestWindowClosed,
    #[error("parametric contest signer is not trusted")]
    UntrustedContestant,
    #[error("parametric contest signature is invalid")]
    InvalidContestSignature,
    #[error("parametric payout is not eligible")]
    PayoutNotEligible,
    #[error("parametric payout reservation requires the shared economic coordinator")]
    PayoutReservationRequiresCoordinator,
    #[error("parametric payout intent conflicts with the reserved intent")]
    PayoutIntentConflict,
    #[error("parametric payout capital instruction is invalid")]
    InvalidCapitalInstruction,
    #[error("parametric payout capital instruction signature is invalid")]
    InvalidCapitalInstructionSignature,
    #[error("parametric payout capital instruction trust does not match")]
    UntrustedCapitalInstruction,
    #[error("parametric payout capital instruction is outside its trusted execution window")]
    CapitalInstructionWindowClosed,
    #[error("parametric payout capital instruction does not support automatic dispatch")]
    AutomaticDispatchUnsupported,
    #[error("parametric payout intent signer is not trusted")]
    UntrustedPayoutIntentSigner,
    #[error("parametric payout intent signature is invalid")]
    InvalidPayoutIntentSignature,
    #[error("parametric claim arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParametricClaimStateV1 {
    Ready,
    ContestOpen,
    Contested,
    UncontestedReleased,
    PayoutReserved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricClaimRecordV1 {
    schema: String,
    identity: ParametricClaimIdentity,
    coverage_authority_id: String,
    payer_id: String,
    beneficiary_id: String,
    funding_facility_id: String,
    payout_rail: ParametricPayoutRail,
    payout_mode: ParametricPayoutMode,
    trigger_magnitude: TriggerMagnitude,
    payout_amount: MonetaryAmount,
    opened_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contest_deadline: Option<u64>,
    state: ParametricClaimStateV1,
    version: u64,
    lifecycle_fence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    contest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    payout_binding: Option<ParametricPayoutBindingV1>,
}

impl ParametricClaimRecordV1 {
    pub fn open(
        policy: &VerifiedParametricPolicy,
        trigger: &VerifiedFiredTriggerV1,
        trusted_opened_at: u64,
    ) -> Result<Self, ParametricClaimError> {
        policy.body().validate()?;
        trigger.ensure_policy(policy.body_digest())?;
        let identity = trigger.identity().clone();
        let trigger_magnitude = trigger.magnitude().clone();
        identity.validate()?;
        require_binding(
            identity.key.parametric_policy_body_digest == policy.body_digest(),
            "claim.policy_body_digest",
        )?;
        require_binding(
            identity.key.bound_coverage_body_digest == policy.body().bound_coverage_body_digest,
            "claim.bound_coverage_body_digest",
        )?;
        require_binding(
            identity.key.subject_key == policy.body().subject_key,
            "claim.subject_key",
        )?;
        if trusted_opened_at < identity.key.window_end {
            return Err(ParametricContractError::InvalidField("claim.opened_at").into());
        }
        let payout_amount = policy.body().payout_schedule.evaluate(
            &policy.body().predicate,
            &trigger_magnitude,
            &policy.body().coverage_amount,
        )?;
        let (state, contest_deadline) = match policy.body().payout_mode {
            ParametricPayoutMode::Automatic => (ParametricClaimStateV1::Ready, None),
            ParametricPayoutMode::Contestable { window_seconds } => (
                ParametricClaimStateV1::ContestOpen,
                Some(
                    trusted_opened_at
                        .checked_add(window_seconds)
                        .ok_or(ParametricClaimError::ArithmeticOverflow("contest_deadline"))?,
                ),
            ),
        };
        let record = Self {
            schema: PARAMETRIC_CLAIM_RECORD_SCHEMA.to_owned(),
            identity,
            coverage_authority_id: policy.body().coverage_authority_id.clone(),
            payer_id: policy.body().payer_id.clone(),
            beneficiary_id: policy.body().beneficiary_id.clone(),
            funding_facility_id: policy.body().funding_facility_id.clone(),
            payout_rail: policy.body().payout_rail.clone(),
            payout_mode: policy.body().payout_mode.clone(),
            trigger_magnitude,
            payout_amount,
            opened_at: trusted_opened_at,
            contest_deadline,
            state,
            version: 1,
            lifecycle_fence: 1,
            contest_digest: None,
            payout_binding: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_CLAIM_RECORD_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        self.identity.validate()?;
        validate_clean(&self.coverage_authority_id, "claim.coverage_authority_id")?;
        validate_clean(&self.payer_id, "claim.payer_id")?;
        validate_clean(&self.beneficiary_id, "claim.beneficiary_id")?;
        validate_clean(&self.funding_facility_id, "claim.funding_facility_id")?;
        self.payout_rail.validate()?;
        self.payout_mode.validate()?;
        validate_money(&self.payout_amount, "claim.payout_amount", false)?;
        if self.opened_at < self.identity.key.window_end {
            return Err(ParametricContractError::InvalidField("claim.opened_at").into());
        }
        if self.version == 0 || self.version != self.lifecycle_fence {
            return Err(ParametricContractError::InvalidField("claim.lifecycle_fence").into());
        }
        let deadline_matches = match (&self.payout_mode, self.contest_deadline) {
            (ParametricPayoutMode::Automatic, None) => true,
            (ParametricPayoutMode::Contestable { window_seconds }, Some(contest_deadline)) => self
                .opened_at
                .checked_add(*window_seconds)
                .is_some_and(|expected| expected == contest_deadline),
            _ => false,
        };
        if !deadline_matches {
            return Err(ParametricContractError::InvalidField("claim.contest_deadline").into());
        }
        let state_matches = match self.state {
            ParametricClaimStateV1::Ready => {
                matches!(self.payout_mode, ParametricPayoutMode::Automatic)
                    && self.contest_digest.is_none()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::ContestOpen => {
                matches!(self.payout_mode, ParametricPayoutMode::Contestable { .. })
                    && self.contest_digest.is_none()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::Contested => {
                matches!(self.payout_mode, ParametricPayoutMode::Contestable { .. })
                    && self.contest_digest.is_some()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::UncontestedReleased => {
                matches!(self.payout_mode, ParametricPayoutMode::Contestable { .. })
                    && self.contest_digest.is_none()
                    && self.payout_binding.is_none()
            }
            ParametricClaimStateV1::PayoutReserved => false,
        };
        if !state_matches {
            return if self.state == ParametricClaimStateV1::PayoutReserved {
                Err(ParametricClaimError::PayoutReservationRequiresCoordinator)
            } else {
                Err(ParametricContractError::InvalidField("claim.state").into())
            };
        }
        if let Some(binding) = self.payout_binding.as_ref() {
            binding.validate()?;
            let expected_version = binding
                .expected_claim_version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?;
            let expected_fence = binding.expected_lifecycle_fence.checked_add(1).ok_or(
                ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
            )?;
            if self.version != expected_version || self.lifecycle_fence != expected_fence {
                return Err(ParametricClaimError::CompareAndSwapConflict(
                    "payout_binding_head",
                ));
            }
            self.ensure_binding_matches(binding)?;
        }
        Ok(())
    }

    pub fn verify_semantic_replay(
        &self,
        policy: &VerifiedParametricPolicy,
        trigger: &VerifiedFiredTriggerV1,
    ) -> Result<(), ParametricClaimError> {
        self.validate()?;
        trigger.ensure_policy(policy.body_digest())?;
        let identity = trigger.identity();
        let magnitude = trigger.magnitude();
        identity.validate()?;
        let amount = policy.body().payout_schedule.evaluate(
            &policy.body().predicate,
            magnitude,
            &policy.body().coverage_amount,
        )?;
        if identity != &self.identity
            || policy.body_digest() != self.identity.key.parametric_policy_body_digest
            || policy.body().coverage_authority_id != self.coverage_authority_id
            || policy.body().payer_id != self.payer_id
            || policy.body().beneficiary_id != self.beneficiary_id
            || policy.body().funding_facility_id != self.funding_facility_id
            || policy.body().payout_rail != self.payout_rail
            || policy.body().payout_mode != self.payout_mode
            || magnitude != &self.trigger_magnitude
            || amount != self.payout_amount
        {
            return Err(ParametricClaimError::CompareAndSwapConflict(
                "semantic_replay",
            ));
        }
        Ok(())
    }

    pub fn file_contest(
        &self,
        expected_version: u64,
        expected_lifecycle_fence: u64,
        trusted_received_at: u64,
        contest: &VerifiedParametricContestV1,
    ) -> Result<Self, ParametricClaimError> {
        self.validate()?;
        let body = contest.body();
        if self.state == ParametricClaimStateV1::Contested {
            let replay_version = expected_version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?;
            let replay_fence = expected_lifecycle_fence.checked_add(1).ok_or(
                ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
            )?;
            if self.version == replay_version
                && self.lifecycle_fence == replay_fence
                && self.contest_digest.as_deref() == Some(contest.envelope_digest())
                && body.expected_claim_version == expected_version
                && body.expected_lifecycle_fence == expected_lifecycle_fence
            {
                return Ok(self.clone());
            }
            return Err(ParametricClaimError::CompareAndSwapConflict("contest"));
        }
        self.ensure_head(expected_version, expected_lifecycle_fence)?;
        if self.state != ParametricClaimStateV1::ContestOpen {
            return Err(ParametricClaimError::InvalidTransition("file_contest"));
        }
        if body.claim_id != self.identity.claim_id
            || body.parametric_policy_body_digest != self.identity.key.parametric_policy_body_digest
            || body.contestant_id != self.coverage_authority_id
            || body.expected_claim_version != expected_version
            || body.expected_lifecycle_fence != expected_lifecycle_fence
        {
            return Err(ParametricClaimError::CompareAndSwapConflict(
                "contest_binding",
            ));
        }
        let deadline = self
            .contest_deadline
            .ok_or(ParametricClaimError::InvalidTransition("file_contest"))?;
        if trusted_received_at >= deadline
            || trusted_received_at < body.issued_at
            || trusted_received_at >= body.expires_at
        {
            return Err(ParametricClaimError::ContestWindowClosed);
        }
        let (version, lifecycle_fence) = self.next_head()?;
        let mut next = self.clone();
        next.state = ParametricClaimStateV1::Contested;
        next.version = version;
        next.lifecycle_fence = lifecycle_fence;
        next.contest_digest = Some(contest.envelope_digest().to_owned());
        next.validate()?;
        Ok(next)
    }

    pub fn release_uncontested(
        &self,
        expected_version: u64,
        expected_lifecycle_fence: u64,
        trusted_now: u64,
    ) -> Result<Self, ParametricClaimError> {
        self.validate()?;
        if self.state == ParametricClaimStateV1::UncontestedReleased {
            let replay_version = expected_version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?;
            let replay_fence = expected_lifecycle_fence.checked_add(1).ok_or(
                ParametricClaimError::ArithmeticOverflow("claim.lifecycle_fence"),
            )?;
            if self.version == replay_version && self.lifecycle_fence == replay_fence {
                return Ok(self.clone());
            }
        }
        self.ensure_head(expected_version, expected_lifecycle_fence)?;
        if self.state != ParametricClaimStateV1::ContestOpen {
            return Err(ParametricClaimError::InvalidTransition(
                "release_uncontested",
            ));
        }
        if trusted_now
            < self
                .contest_deadline
                .ok_or(ParametricClaimError::InvalidTransition(
                    "release_uncontested",
                ))?
        {
            return Err(ParametricClaimError::ContestWindowClosed);
        }
        let (version, lifecycle_fence) = self.next_head()?;
        let mut next = self.clone();
        next.state = ParametricClaimStateV1::UncontestedReleased;
        next.version = version;
        next.lifecycle_fence = lifecycle_fence;
        next.validate()?;
        Ok(next)
    }

    fn ensure_head(
        &self,
        expected_version: u64,
        expected_lifecycle_fence: u64,
    ) -> Result<(), ParametricClaimError> {
        if self.version == expected_version && self.lifecycle_fence == expected_lifecycle_fence {
            Ok(())
        } else {
            Err(ParametricClaimError::CompareAndSwapConflict("claim_head"))
        }
    }

    fn next_head(&self) -> Result<(u64, u64), ParametricClaimError> {
        Ok((
            self.version
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow("claim.version"))?,
            self.lifecycle_fence
                .checked_add(1)
                .ok_or(ParametricClaimError::ArithmeticOverflow(
                    "claim.lifecycle_fence",
                ))?,
        ))
    }

    fn ensure_binding_matches(
        &self,
        binding: &ParametricPayoutBindingV1,
    ) -> Result<(), ParametricClaimError> {
        require_binding(
            binding.claim_id == self.identity.claim_id,
            "payout_binding.claim_id",
        )?;
        require_binding(
            binding.trigger_instance_id == self.identity.trigger_instance_id,
            "payout_binding.trigger_instance_id",
        )?;
        require_binding(
            binding.parametric_policy_body_digest
                == self.identity.key.parametric_policy_body_digest,
            "payout_binding.parametric_policy_body_digest",
        )?;
        require_binding(
            binding.bound_coverage_body_digest == self.identity.key.bound_coverage_body_digest,
            "payout_binding.bound_coverage_body_digest",
        )?;
        require_binding(binding.payer_id == self.payer_id, "payout_binding.payer_id")?;
        require_binding(
            binding.beneficiary_id == self.beneficiary_id,
            "payout_binding.beneficiary_id",
        )?;
        require_binding(
            binding.funding_facility_id == self.funding_facility_id,
            "payout_binding.funding_facility_id",
        )?;
        require_binding(
            binding.payout_rail.kind == self.payout_rail.kind,
            "payout_binding.rail_kind",
        )?;
        require_binding(
            binding.payout_rail.rail_id == self.payout_rail.rail_id,
            "payout_binding.rail_id",
        )?;
        require_binding(
            binding.payout_rail.destination_account_digest
                == self.payout_rail.destination_account_digest,
            "payout_binding.destination_account_digest",
        )?;
        require_binding(
            binding.amount == self.payout_amount,
            "payout_binding.amount",
        )?;
        Ok(())
    }

    #[must_use]
    pub const fn state(&self) -> ParametricClaimStateV1 {
        self.state
    }

    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    #[must_use]
    pub const fn lifecycle_fence(&self) -> u64 {
        self.lifecycle_fence
    }

    #[must_use]
    pub fn claim_id(&self) -> &str {
        &self.identity.claim_id
    }

    #[must_use]
    pub fn trigger_instance_id(&self) -> &str {
        &self.identity.trigger_instance_id
    }

    #[must_use]
    pub const fn contest_deadline(&self) -> Option<u64> {
        self.contest_deadline
    }

    #[must_use]
    pub const fn payout_amount(&self) -> &MonetaryAmount {
        &self.payout_amount
    }

    #[must_use]
    pub const fn trigger_magnitude(&self) -> &TriggerMagnitude {
        &self.trigger_magnitude
    }

    #[must_use]
    pub const fn opened_at(&self) -> u64 {
        self.opened_at
    }

    #[must_use]
    pub const fn payout_binding(&self) -> Option<&ParametricPayoutBindingV1> {
        self.payout_binding.as_ref()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParametricContestReasonCodeV1 {
    CorpusIntegrity,
    PredicateEvaluation,
    PolicyBinding,
    DuplicateEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricContestV1 {
    schema: String,
    contest_id: String,
    claim_id: String,
    parametric_policy_body_digest: String,
    expected_claim_version: u64,
    expected_lifecycle_fence: u64,
    contestant_id: String,
    issued_at: u64,
    expires_at: u64,
    reason_code: ParametricContestReasonCodeV1,
    evidence_digests: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParametricContestIdPreimage<'a> {
    claim_id: &'a str,
    parametric_policy_body_digest: &'a str,
    expected_claim_version: u64,
    expected_lifecycle_fence: u64,
    contestant_id: &'a str,
    issued_at: u64,
    expires_at: u64,
    reason_code: ParametricContestReasonCodeV1,
    evidence_digests: &'a [String],
}

impl ParametricContestV1 {
    pub fn new(
        claim: &ParametricClaimRecordV1,
        contestant_id: String,
        issued_at: u64,
        expires_at: u64,
        reason_code: ParametricContestReasonCodeV1,
        mut evidence_digests: Vec<String>,
    ) -> Result<Self, ParametricClaimError> {
        claim.validate()?;
        evidence_digests.sort_unstable();
        let mut contest = Self {
            schema: PARAMETRIC_CONTEST_SCHEMA.to_owned(),
            contest_id: String::new(),
            claim_id: claim.identity.claim_id.clone(),
            parametric_policy_body_digest: claim.identity.key.parametric_policy_body_digest.clone(),
            expected_claim_version: claim.version,
            expected_lifecycle_fence: claim.lifecycle_fence,
            contestant_id,
            issued_at,
            expires_at,
            reason_code,
            evidence_digests,
        };
        contest.contest_id = domain_digest(PARAMETRIC_CONTEST_ID_DOMAIN, &contest.id_preimage())?;
        contest.validate()?;
        Ok(contest)
    }

    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_CONTEST_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        validate_digest(&self.contest_id, "contest.contest_id")?;
        validate_digest(&self.claim_id, "contest.claim_id")?;
        validate_digest(
            &self.parametric_policy_body_digest,
            "contest.parametric_policy_body_digest",
        )?;
        if self.expected_claim_version == 0 || self.expected_lifecycle_fence == 0 {
            return Err(ParametricContractError::InvalidField("contest.claim_head").into());
        }
        validate_clean(&self.contestant_id, "contest.contestant_id")?;
        if self.issued_at == 0 || self.expires_at <= self.issued_at {
            return Err(ParametricContractError::InvalidField("contest.validity").into());
        }
        if self.evidence_digests.is_empty()
            || self.evidence_digests.len() > MAX_PARAMETRIC_CONTEST_EVIDENCE
            || !self
                .evidence_digests
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        {
            return Err(ParametricContractError::InvalidField("contest.evidence_digests").into());
        }
        for digest in &self.evidence_digests {
            validate_digest(digest, "contest.evidence_digest")?;
        }
        require_binding(
            self.contest_id == domain_digest(PARAMETRIC_CONTEST_ID_DOMAIN, &self.id_preimage())?,
            "contest.contest_id",
        )?;
        Ok(())
    }

    fn id_preimage(&self) -> ParametricContestIdPreimage<'_> {
        ParametricContestIdPreimage {
            claim_id: &self.claim_id,
            parametric_policy_body_digest: &self.parametric_policy_body_digest,
            expected_claim_version: self.expected_claim_version,
            expected_lifecycle_fence: self.expected_lifecycle_fence,
            contestant_id: &self.contestant_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            reason_code: self.reason_code,
            evidence_digests: &self.evidence_digests,
        }
    }
}

pub type SignedParametricContestV1 = SignedExportEnvelope<ParametricContestV1>;

#[derive(Debug, Clone)]
pub struct VerifiedParametricContestV1 {
    signed: SignedParametricContestV1,
    envelope_digest: String,
}

impl VerifiedParametricContestV1 {
    pub fn verify(
        signed: SignedParametricContestV1,
        trusted_contestant_id: &str,
        trusted_contestant_key: &PublicKey,
    ) -> Result<Self, ParametricClaimError> {
        signed.body.validate()?;
        validate_clean(trusted_contestant_id, "trusted.contestant_id")?;
        if signed.body.contestant_id != trusted_contestant_id
            || &signed.signer_key != trusted_contestant_key
        {
            return Err(ParametricClaimError::UntrustedContestant);
        }
        if !signed
            .verify_signature()
            .map_err(|error| ParametricContractError::Canonicalization(error.to_string()))?
        {
            return Err(ParametricClaimError::InvalidContestSignature);
        }
        Ok(Self {
            envelope_digest: canonical_digest(&signed)?,
            signed,
        })
    }

    #[must_use]
    pub const fn body(&self) -> &ParametricContestV1 {
        &self.signed.body
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedParametricContestV1 {
        &self.signed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPayoutPreparationBindingV1 {
    pub schema: String,
    pub claim_id: String,
    pub anchor_id: String,
    pub operation_id: String,
    pub request: EconomicRequestBindingV1,
    pub admission_handoff: EconomicAdmissionHandoffV1,
    pub bound_coverage_body_digest: String,
    pub coverage_reservation_id: String,
    pub coverage_reservation_version: u64,
    pub coverage_reservation_lifecycle_fence: u64,
    pub coverage_head_digest: String,
    pub target_id: String,
    pub target_key_epoch: u64,
    pub capital_instruction_template_digest: String,
    pub capital_instruction_id: String,
    pub capital_instruction_body_digest: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ParametricPayoutCapitalInstructionIdPreimage<'a> {
    claim_id: &'a str,
    anchor_id: &'a str,
    operation_id: &'a str,
    request: &'a EconomicRequestBindingV1,
    admission_handoff: &'a EconomicAdmissionHandoffV1,
    bound_coverage_body_digest: &'a str,
    coverage_reservation_id: &'a str,
    coverage_reservation_version: u64,
    coverage_reservation_lifecycle_fence: u64,
    coverage_head_digest: &'a str,
    target_id: &'a str,
    target_key_epoch: u64,
    capital_instruction_template_digest: &'a str,
}

impl ParametricPayoutPreparationBindingV1 {
    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_PAYOUT_PREPARATION_BINDING_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        validate_digest(&self.claim_id, "payout_preparation.claim_id")?;
        validate_clean(&self.anchor_id, "payout_preparation.anchor_id")?;
        validate_digest(&self.operation_id, "payout_preparation.operation_id")?;
        self.request
            .validate()
            .map_err(|_| ParametricContractError::InvalidField("payout_preparation.request"))?;
        self.admission_handoff.validate().map_err(|_| {
            ParametricContractError::InvalidField("payout_preparation.admission_handoff")
        })?;
        validate_digest(
            &self.bound_coverage_body_digest,
            "payout_preparation.bound_coverage_body_digest",
        )?;
        validate_digest(
            &self.coverage_reservation_id,
            "payout_preparation.coverage_reservation_id",
        )?;
        if self.coverage_reservation_version == 0
            || self.coverage_reservation_lifecycle_fence == 0
            || self.target_key_epoch == 0
        {
            return Err(ParametricContractError::InvalidField("payout_preparation.version").into());
        }
        validate_digest(
            &self.coverage_head_digest,
            "payout_preparation.coverage_head_digest",
        )?;
        validate_clean(&self.target_id, "payout_preparation.target_id")?;
        validate_digest(
            &self.capital_instruction_template_digest,
            "payout_preparation.capital_instruction_template_digest",
        )?;
        validate_digest(
            &self.capital_instruction_body_digest,
            "payout_preparation.capital_instruction_body_digest",
        )?;
        require_binding(
            self.capital_instruction_id == self.derived_capital_instruction_id()?,
            "payout_preparation.capital_instruction_id",
        )?;
        Ok(())
    }

    pub fn derived_capital_instruction_id(&self) -> Result<String, ParametricClaimError> {
        Ok(domain_digest(
            PARAMETRIC_PAYOUT_CAPITAL_INSTRUCTION_ID_DOMAIN,
            &ParametricPayoutCapitalInstructionIdPreimage {
                claim_id: &self.claim_id,
                anchor_id: &self.anchor_id,
                operation_id: &self.operation_id,
                request: &self.request,
                admission_handoff: &self.admission_handoff,
                bound_coverage_body_digest: &self.bound_coverage_body_digest,
                coverage_reservation_id: &self.coverage_reservation_id,
                coverage_reservation_version: self.coverage_reservation_version,
                coverage_reservation_lifecycle_fence: self.coverage_reservation_lifecycle_fence,
                coverage_head_digest: &self.coverage_head_digest,
                target_id: &self.target_id,
                target_key_epoch: self.target_key_epoch,
                capital_instruction_template_digest: &self.capital_instruction_template_digest,
            },
        )?)
    }

    pub fn action_digest(&self) -> Result<String, ParametricClaimError> {
        self.derived_digest(PARAMETRIC_PAYOUT_ACTION_DIGEST_DOMAIN)
    }

    pub fn target_qualification_digest(&self) -> Result<String, ParametricClaimError> {
        self.derived_digest(PARAMETRIC_PAYOUT_TARGET_QUALIFICATION_DIGEST_DOMAIN)
    }

    pub fn effect_idempotency_key(&self) -> Result<String, ParametricClaimError> {
        self.derived_digest(PARAMETRIC_PAYOUT_EFFECT_IDEMPOTENCY_KEY_DOMAIN)
    }

    fn derived_digest(&self, domain: &str) -> Result<String, ParametricClaimError> {
        self.validate()?;
        Ok(domain_digest(domain, self)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPayoutBindingV1 {
    pub schema: String,
    pub claim_id: String,
    pub trigger_instance_id: String,
    pub parametric_policy_body_digest: String,
    pub expected_claim_version: u64,
    pub expected_lifecycle_fence: u64,
    pub bound_coverage_body_digest: String,
    pub coverage_reservation_id: String,
    pub coverage_reservation_version: u64,
    pub coverage_reservation_lifecycle_fence: u64,
    pub coverage_head_digest: String,
    pub payer_id: String,
    pub beneficiary_id: String,
    pub funding_facility_id: String,
    pub payout_rail: ParametricPayoutRail,
    pub operation_id: String,
    pub request: EconomicRequestBindingV1,
    pub effect_slot_id: String,
    pub effect_idempotency_key: String,
    pub effect_slot: EconomicEffectSlotV1,
    pub capital_instruction_id: String,
    pub governed_receipt_id: String,
    pub completion_flow_row_id: String,
    pub source_account_digest: String,
    pub instruction_signer_key_epoch: u64,
    pub facility_authority_key_epoch: u64,
    pub custodian_authority_key_epoch: u64,
    pub capital_instruction_template_digest: String,
    pub capital_instruction_body_digest: String,
    pub capital_instruction_envelope_digest: String,
    pub amount: MonetaryAmount,
}

impl ParametricPayoutBindingV1 {
    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_PAYOUT_BINDING_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        validate_digest(&self.claim_id, "payout_binding.claim_id")?;
        validate_digest(
            &self.trigger_instance_id,
            "payout_binding.trigger_instance_id",
        )?;
        validate_digest(
            &self.parametric_policy_body_digest,
            "payout_binding.parametric_policy_body_digest",
        )?;
        if self.expected_claim_version == 0 || self.expected_lifecycle_fence == 0 {
            return Err(ParametricContractError::InvalidField("payout_binding.claim_head").into());
        }
        validate_digest(
            &self.bound_coverage_body_digest,
            "payout_binding.bound_coverage_body_digest",
        )?;
        validate_digest(
            &self.coverage_reservation_id,
            "payout_binding.coverage_reservation_id",
        )?;
        if self.coverage_reservation_version == 0 || self.coverage_reservation_lifecycle_fence == 0
        {
            return Err(ParametricContractError::InvalidField(
                "payout_binding.coverage_reservation_head",
            )
            .into());
        }
        validate_digest(
            &self.coverage_head_digest,
            "payout_binding.coverage_head_digest",
        )?;
        validate_clean(&self.payer_id, "payout_binding.payer_id")?;
        validate_clean(&self.beneficiary_id, "payout_binding.beneficiary_id")?;
        validate_clean(
            &self.funding_facility_id,
            "payout_binding.funding_facility_id",
        )?;
        self.payout_rail.validate()?;
        validate_digest(&self.operation_id, "payout_binding.operation_id")?;
        self.request
            .validate()
            .map_err(|_| ParametricContractError::InvalidField("payout_binding.request"))?;
        self.effect_slot
            .validate()
            .map_err(|_| ParametricContractError::InvalidField("payout_binding.effect_slot"))?;
        require_binding(
            self.effect_slot.operation_id == self.operation_id,
            "payout_binding.effect_slot.operation_id",
        )?;
        require_binding(
            self.effect_slot.request == self.request,
            "payout_binding.effect_slot.request",
        )?;
        validate_digest(&self.effect_slot_id, "payout_binding.effect_slot_id")?;
        validate_digest(
            &self.effect_idempotency_key,
            "payout_binding.effect_idempotency_key",
        )?;
        require_binding(
            self.effect_slot.slot_id == self.effect_slot_id
                && self.effect_slot.idempotency_key == self.effect_idempotency_key,
            "payout_binding.effect_slot.identity",
        )?;
        require_binding(
            self.effect_slot.namespace == PARAMETRIC_PAYOUT_ECONOMIC_NAMESPACE
                && self.effect_slot.resource_key.resource_family
                    == PARAMETRIC_LIABILITY_COVERAGE_RESOURCE_FAMILY
                && self.effect_slot.effect_kind == PARAMETRIC_PAYOUT_EFFECT_KIND,
            "payout_binding.effect_slot.effect_kind",
        )?;
        require_binding(
            self.effect_slot.resource_key.scope_id == self.bound_coverage_body_digest
                && self.effect_slot.resource_key.resource_id == self.coverage_reservation_id
                && self.effect_slot.resource_head_digest == self.coverage_head_digest,
            "payout_binding.effect_slot.coverage_head",
        )?;
        require_binding(
            self.effect_slot.admission_handoff.state
                == EconomicAdmissionHandoffStateV1::MutationSubmitted
                && self.effect_slot.state == EconomicEffectStateV1::Ready
                && self.effect_slot.terminal.is_none()
                && self.effect_slot.frost.is_none(),
            "payout_binding.effect_slot.state",
        )?;
        validate_clean(
            &self.capital_instruction_id,
            "payout_binding.capital_instruction_id",
        )?;
        validate_clean(
            &self.governed_receipt_id,
            "payout_binding.governed_receipt_id",
        )?;
        validate_clean(
            &self.completion_flow_row_id,
            "payout_binding.completion_flow_row_id",
        )?;
        validate_digest(
            &self.source_account_digest,
            "payout_binding.source_account_digest",
        )?;
        if self.instruction_signer_key_epoch == 0
            || self.facility_authority_key_epoch == 0
            || self.custodian_authority_key_epoch == 0
            || self.effect_slot.target.target_key_epoch != self.custodian_authority_key_epoch
        {
            return Err(ParametricContractError::InvalidField(
                "payout_binding.capital_authority_epoch",
            )
            .into());
        }
        validate_digest(
            &self.capital_instruction_template_digest,
            "payout_binding.capital_instruction_template_digest",
        )?;
        validate_digest(
            &self.capital_instruction_body_digest,
            "payout_binding.capital_instruction_body_digest",
        )?;
        validate_digest(
            &self.capital_instruction_envelope_digest,
            "payout_binding.capital_instruction_envelope_digest",
        )?;
        validate_money(&self.amount, "payout_binding.amount", false)?;
        let preparation = self.preparation_binding()?;
        require_binding(
            self.effect_slot.action_digest == preparation.action_digest()?,
            "payout_binding.effect_slot.action_digest",
        )?;
        require_binding(
            self.effect_slot.target.qualification_digest
                == preparation.target_qualification_digest()?,
            "payout_binding.effect_slot.target_qualification_digest",
        )?;
        require_binding(
            self.effect_idempotency_key == preparation.effect_idempotency_key()?,
            "payout_binding.effect_slot.idempotency_key",
        )?;
        Ok(())
    }

    pub fn preparation_binding(
        &self,
    ) -> Result<ParametricPayoutPreparationBindingV1, ParametricClaimError> {
        let preparation = ParametricPayoutPreparationBindingV1 {
            schema: PARAMETRIC_PAYOUT_PREPARATION_BINDING_SCHEMA.to_owned(),
            claim_id: self.claim_id.clone(),
            anchor_id: self.effect_slot.anchor_id.clone(),
            operation_id: self.operation_id.clone(),
            request: self.request.clone(),
            admission_handoff: self.effect_slot.admission_handoff.clone(),
            bound_coverage_body_digest: self.bound_coverage_body_digest.clone(),
            coverage_reservation_id: self.coverage_reservation_id.clone(),
            coverage_reservation_version: self.coverage_reservation_version,
            coverage_reservation_lifecycle_fence: self.coverage_reservation_lifecycle_fence,
            coverage_head_digest: self.coverage_head_digest.clone(),
            target_id: self.effect_slot.target.target_id.clone(),
            target_key_epoch: self.effect_slot.target.target_key_epoch,
            capital_instruction_template_digest: self.capital_instruction_template_digest.clone(),
            capital_instruction_id: self.capital_instruction_id.clone(),
            capital_instruction_body_digest: self.capital_instruction_body_digest.clone(),
        };
        preparation.validate()?;
        Ok(preparation)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ParametricPayoutIntentV1 {
    pub schema: String,
    pub payout_intent_id: String,
    pub binding: ParametricPayoutBindingV1,
    pub capital_instruction: SignedCapitalExecutionInstruction,
}

impl ParametricPayoutIntentV1 {
    pub fn validate(&self) -> Result<(), ParametricClaimError> {
        if self.schema != PARAMETRIC_PAYOUT_INTENT_SCHEMA {
            return Err(ParametricContractError::UnknownSchema(self.schema.clone()).into());
        }
        self.binding.validate()?;
        require_binding(
            self.payout_intent_id == parametric_payout_intent_id(&self.binding.claim_id)?,
            "payout_intent.payout_intent_id",
        )?;
        validate_capital_instruction_against(&self.capital_instruction, &self.binding, None)
    }

    pub fn validate_against_eligible_claim(
        &self,
        claim: &ParametricClaimRecordV1,
    ) -> Result<(), ParametricClaimError> {
        claim.validate()?;
        self.validate()?;
        if !matches!(
            claim.state,
            ParametricClaimStateV1::Ready | ParametricClaimStateV1::UncontestedReleased
        ) || claim.version != self.binding.expected_claim_version
            || claim.lifecycle_fence != self.binding.expected_lifecycle_fence
        {
            return Err(ParametricClaimError::PayoutIntentConflict);
        }
        claim.ensure_binding_matches(&self.binding)?;
        validate_capital_instruction_against(&self.capital_instruction, &self.binding, Some(claim))
    }
}

pub type SignedParametricPayoutIntentV1 = SignedExportEnvelope<ParametricPayoutIntentV1>;

#[derive(Debug, Clone)]
pub struct ParametricPayoutInstructionTrustInputV1 {
    pub trusted_now: u64,
    pub instruction_signer_key: PublicKey,
    pub instruction_signer_key_epoch: u64,
    pub funding_facility_id: String,
    pub facility_authority_key: PublicKey,
    pub facility_authority_key_epoch: u64,
    pub authorized_source_account_digest: String,
    pub custody_provider_id: String,
    pub custodian_authority_key: PublicKey,
    pub custodian_authority_key_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct ParametricPayoutInstructionTrustV1 {
    trusted_now: u64,
    instruction_signer_key: PublicKey,
    instruction_signer_key_epoch: u64,
    funding_facility_id: String,
    facility_authority_key: PublicKey,
    facility_authority_key_epoch: u64,
    authorized_source_account_digest: String,
    custody_provider_id: String,
    custodian_authority_key: PublicKey,
    custodian_authority_key_epoch: u64,
}

impl ParametricPayoutInstructionTrustV1 {
    pub fn new(
        input: ParametricPayoutInstructionTrustInputV1,
    ) -> Result<Self, ParametricClaimError> {
        let ParametricPayoutInstructionTrustInputV1 {
            trusted_now,
            instruction_signer_key,
            instruction_signer_key_epoch,
            funding_facility_id,
            facility_authority_key,
            facility_authority_key_epoch,
            authorized_source_account_digest,
            custody_provider_id,
            custodian_authority_key,
            custodian_authority_key_epoch,
        } = input;
        validate_clean(&funding_facility_id, "trusted.funding_facility_id")?;
        validate_digest(
            &authorized_source_account_digest,
            "trusted.authorized_source_account_digest",
        )?;
        validate_clean(&custody_provider_id, "trusted.custody_provider_id")?;
        if trusted_now == 0
            || instruction_signer_key_epoch == 0
            || facility_authority_key_epoch == 0
            || custodian_authority_key_epoch == 0
        {
            return Err(
                ParametricContractError::InvalidField("trusted.capital_instruction").into(),
            );
        }
        Ok(Self {
            trusted_now,
            instruction_signer_key,
            instruction_signer_key_epoch,
            funding_facility_id,
            facility_authority_key,
            facility_authority_key_epoch,
            authorized_source_account_digest,
            custody_provider_id,
            custodian_authority_key,
            custodian_authority_key_epoch,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedPreReservationParametricPayoutIntentV1 {
    signed: SignedParametricPayoutIntentV1,
    envelope_digest: String,
}

impl ValidatedPreReservationParametricPayoutIntentV1 {
    /// Validates preparation inputs only. This does not prove a reservation or dispatch authority.
    pub fn validate_pre_reservation(
        signed: SignedParametricPayoutIntentV1,
        trusted_intent_signer_key: &PublicKey,
        instruction_trust: &ParametricPayoutInstructionTrustV1,
        eligible_claim: &ParametricClaimRecordV1,
        expected_preparation: &ParametricPayoutPreparationBindingV1,
    ) -> Result<Self, ParametricClaimError> {
        signed
            .body
            .validate_against_eligible_claim(eligible_claim)?;
        expected_preparation.validate()?;
        if signed.body.binding.preparation_binding()? != *expected_preparation {
            return Err(ParametricClaimError::PayoutIntentConflict);
        }
        verify_capital_instruction_trust(
            &signed.body.capital_instruction,
            &signed.body.binding,
            instruction_trust,
        )?;
        if &signed.signer_key != trusted_intent_signer_key {
            return Err(ParametricClaimError::UntrustedPayoutIntentSigner);
        }
        if !signed
            .verify_signature()
            .map_err(|_| ParametricClaimError::InvalidPayoutIntentSignature)?
        {
            return Err(ParametricClaimError::InvalidPayoutIntentSignature);
        }
        Ok(Self {
            envelope_digest: canonical_digest(&signed)?,
            signed,
        })
    }

    #[must_use]
    pub const fn body(&self) -> &ParametricPayoutIntentV1 {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedParametricPayoutIntentV1 {
        &self.signed
    }

    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }
}

pub fn parametric_payout_destination_account_digest(
    destination_account_ref: &str,
) -> Result<String, ParametricClaimError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct DestinationAccountDigestPreimage<'a> {
        destination_account_ref: &'a str,
    }

    validate_clean(
        destination_account_ref,
        "payout_destination.destination_account_ref",
    )?;
    Ok(domain_digest(
        PARAMETRIC_PAYOUT_DESTINATION_ACCOUNT_DIGEST_DOMAIN,
        &DestinationAccountDigestPreimage {
            destination_account_ref,
        },
    )?)
}

pub fn parametric_payout_source_account_digest(
    source_account_ref: &str,
) -> Result<String, ParametricClaimError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SourceAccountDigestPreimage<'a> {
        source_account_ref: &'a str,
    }

    validate_clean(source_account_ref, "payout_source.source_account_ref")?;
    Ok(domain_digest(
        PARAMETRIC_PAYOUT_SOURCE_ACCOUNT_DIGEST_DOMAIN,
        &SourceAccountDigestPreimage { source_account_ref },
    )?)
}

fn validate_capital_instruction(
    instruction: &SignedCapitalExecutionInstruction,
) -> Result<(), ParametricClaimError> {
    instruction
        .body
        .validate()
        .map_err(|_| ParametricClaimError::InvalidCapitalInstruction)?;
    if !instruction
        .verify_signature()
        .map_err(|_| ParametricClaimError::InvalidCapitalInstructionSignature)?
    {
        return Err(ParametricClaimError::InvalidCapitalInstructionSignature);
    }
    Ok(())
}

fn capital_instruction_template_digest(
    body: &CapitalExecutionInstructionArtifact,
) -> Result<String, ParametricClaimError> {
    let mut template = body.clone();
    template.instruction_id.clear();
    Ok(canonical_digest(&template)?)
}

fn validate_capital_instruction_against(
    instruction: &SignedCapitalExecutionInstruction,
    binding: &ParametricPayoutBindingV1,
    claim: Option<&ParametricClaimRecordV1>,
) -> Result<(), ParametricClaimError> {
    validate_capital_instruction(instruction)?;
    let body = &instruction.body;
    require_binding(
        body.action == CapitalExecutionInstructionAction::TransferFunds,
        "payout_intent.capital_instruction.action",
    )?;
    require_binding(
        body.source_kind == CapitalBookSourceKind::FacilityCommitment,
        "payout_intent.capital_instruction.source_kind",
    )?;
    require_binding(
        body.source_id == binding.funding_facility_id,
        "payout_intent.capital_instruction.source_id",
    )?;
    require_binding(
        body.owner_role == CapitalExecutionRole::FacilityProvider,
        "payout_intent.capital_instruction.owner_role",
    )?;
    if let Some(claim) = claim {
        require_binding(
            body.subject_key == claim.identity.key.subject_key,
            "payout_intent.capital_instruction.subject_key",
        )?;
    }
    require_binding(
        body.subject_key == binding.beneficiary_id,
        "payout_intent.capital_instruction.subject_beneficiary",
    )?;
    require_binding(
        body.counterparty_role == CapitalExecutionRole::AgentCounterparty,
        "payout_intent.capital_instruction.counterparty_role",
    )?;
    require_binding(
        body.counterparty_id == binding.beneficiary_id,
        "payout_intent.capital_instruction.counterparty_id",
    )?;
    require_binding(
        body.amount.as_ref() == Some(&binding.amount),
        "payout_intent.capital_instruction.amount",
    )?;
    require_binding(
        body.rail.kind == binding.payout_rail.kind,
        "payout_intent.capital_instruction.rail_kind",
    )?;
    require_binding(
        body.rail.rail_id == binding.payout_rail.rail_id,
        "payout_intent.capital_instruction.rail_id",
    )?;
    require_binding(
        body.rail.custody_provider_id == binding.effect_slot.target.target_id,
        "payout_intent.capital_instruction.custody_provider_id",
    )?;
    require_binding(
        body.instruction_id == binding.capital_instruction_id,
        "payout_intent.capital_instruction.instruction_id",
    )?;
    require_binding(
        capital_instruction_template_digest(body)? == binding.capital_instruction_template_digest,
        "payout_intent.capital_instruction.template_digest",
    )?;
    require_binding(
        body.governed_receipt_id.as_deref() == Some(binding.governed_receipt_id.as_str()),
        "payout_intent.capital_instruction.governed_receipt_id",
    )?;
    require_binding(
        body.completion_flow_row_id.as_deref() == Some(binding.completion_flow_row_id.as_str()),
        "payout_intent.capital_instruction.completion_flow_row_id",
    )?;
    let source_account_ref = body
        .rail
        .source_account_ref
        .as_deref()
        .ok_or(ParametricClaimError::InvalidCapitalInstruction)?;
    require_binding(
        parametric_payout_source_account_digest(source_account_ref)?
            == binding.source_account_digest,
        "payout_intent.capital_instruction.source_account_ref",
    )?;
    let destination_account_ref = body
        .rail
        .destination_account_ref
        .as_deref()
        .ok_or(ParametricClaimError::InvalidCapitalInstruction)?;
    require_binding(
        parametric_payout_destination_account_digest(destination_account_ref)?
            == binding.payout_rail.destination_account_digest,
        "payout_intent.capital_instruction.destination_account_ref",
    )?;
    require_binding(
        body.intended_state == CapitalExecutionIntendedState::PendingExecution,
        "payout_intent.capital_instruction.intended_state",
    )?;
    require_binding(
        body.reconciled_state == CapitalExecutionReconciledState::NotObserved
            && body.observed_execution.is_none(),
        "payout_intent.capital_instruction.reconciliation",
    )?;
    require_binding(
        canonical_digest(body)? == binding.capital_instruction_body_digest,
        "payout_intent.capital_instruction.body_digest",
    )?;
    require_binding(
        binding.effect_slot.parameters_digest == binding.capital_instruction_body_digest,
        "payout_intent.effect_slot.parameters_digest",
    )?;
    require_binding(
        canonical_digest(instruction)? == binding.capital_instruction_envelope_digest,
        "payout_intent.capital_instruction.envelope_digest",
    )?;
    Ok(())
}

fn verify_capital_instruction_trust(
    instruction: &SignedCapitalExecutionInstruction,
    binding: &ParametricPayoutBindingV1,
    trust: &ParametricPayoutInstructionTrustV1,
) -> Result<(), ParametricClaimError> {
    let body = &instruction.body;
    let trusted_facility_key = trust.facility_authority_key.to_hex();
    let trusted_custodian_key = trust.custodian_authority_key.to_hex();
    if instruction.signer_key != trust.instruction_signer_key
        || binding.instruction_signer_key_epoch != trust.instruction_signer_key_epoch
        || binding.facility_authority_key_epoch != trust.facility_authority_key_epoch
        || binding.custodian_authority_key_epoch != trust.custodian_authority_key_epoch
        || binding.funding_facility_id != trust.funding_facility_id
        || binding.source_account_digest != trust.authorized_source_account_digest
        || body.source_id != trust.funding_facility_id
        || body.rail.custody_provider_id != trust.custody_provider_id
        || binding.effect_slot.target.target_id != trust.custody_provider_id
        || binding.effect_slot.target.target_key_epoch != trust.custodian_authority_key_epoch
    {
        return Err(ParametricClaimError::UntrustedCapitalInstruction);
    }
    if trust.trusted_now < body.execution_window.not_before
        || trust.trusted_now > body.execution_window.not_after
        || body.issued_at > trust.trusted_now
    {
        return Err(ParametricClaimError::CapitalInstructionWindowClosed);
    }
    if !body.support_boundary.automatic_dispatch_supported {
        return Err(ParametricClaimError::AutomaticDispatchUnsupported);
    }
    let exact_current_authority = |role, principal_id: &str| {
        body.authority_chain.iter().any(|step| {
            step.role == role
                && step.principal_id == principal_id
                && step.approved_at <= trust.trusted_now
                && trust.trusted_now <= step.expires_at
        })
    };
    if !exact_current_authority(
        CapitalExecutionRole::FacilityProvider,
        &trusted_facility_key,
    ) || !exact_current_authority(CapitalExecutionRole::Custodian, &trusted_custodian_key)
    {
        return Err(ParametricClaimError::UntrustedCapitalInstruction);
    }
    Ok(())
}

pub fn parametric_payout_intent_id(claim_id: &str) -> Result<String, ParametricClaimError> {
    validate_digest(claim_id, "payout_intent.claim_id")?;
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct PayoutIntentIdPreimage<'a> {
        claim_id: &'a str,
    }
    Ok(domain_digest(
        PARAMETRIC_PAYOUT_INTENT_ID_DOMAIN,
        &PayoutIntentIdPreimage { claim_id },
    )?)
}

#[cfg(test)]
mod payout_tests;
