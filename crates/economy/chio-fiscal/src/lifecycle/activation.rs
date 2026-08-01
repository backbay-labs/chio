use std::collections::BTreeSet;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::{
    fiscal_signer_key_id, FiscalDomain, FiscalError, SignedFiscalSchedule, VerifiedFiscalCharter,
    VerifiedFiscalSchedule,
};

use super::continuity::{FiscalStagedTransition, VerifiedFiscalActivationAuthority};
use super::proposal::{
    FiscalAdmissionTrustRegistry, FiscalProposalAdmissionState, FiscalProposalAdmissionStatus,
    FiscalProposalTarget, VerifiedFiscalProposal, VerifiedFiscalProposalAdmission,
};
use super::support::{
    lifecycle_digest, require_digest, require_positive, signed_envelope_digest, verify_envelope,
};

pub const FISCAL_APPROVAL_SCHEMA: &str = "chio.fiscal.approval.v1";
pub const FISCAL_ACTIVATION_SCHEMA: &str = "chio.fiscal.activation.v1";
pub const FISCAL_APPROVAL_ID_DOMAIN: &str = "chio.fiscal.approval.id.v1";
pub const FISCAL_ACTIVATION_ID_DOMAIN: &str = "chio.fiscal.activation.id.v1";
pub const FISCAL_APPROVAL_SET_DIGEST_DOMAIN: &str = "chio.fiscal.approval-set.digest.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalScheduleHead {
    pub schedule_id: String,
    pub schedule_digest: String,
    pub sequence: u64,
}

impl FiscalScheduleHead {
    pub fn from_signed(schedule: &SignedFiscalSchedule) -> Result<Self, FiscalError> {
        Ok(Self {
            schedule_id: schedule.body.schedule_id.clone(),
            schedule_digest: signed_envelope_digest(schedule)?,
            sequence: schedule.body.sequence,
        })
    }

    pub(super) fn validate(&self) -> Result<(), FiscalError> {
        require_digest(&self.schedule_id, "schedule_head.schedule_id")?;
        require_digest(&self.schedule_digest, "schedule_head.schedule_digest")?;
        require_positive(self.sequence, "schedule_head.sequence")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalApproval {
    pub schema: String,
    pub approval_id: String,
    pub signer_key_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub admission_id: String,
    pub admission_digest: String,
    pub approved_at: u64,
    pub approval_expires_at: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalApprovalIdPreimage<'a> {
    schema: &'a str,
    signer_key_id: &'a str,
    proposal_id: &'a str,
    proposal_digest: &'a str,
    admission_id: &'a str,
    admission_digest: &'a str,
    approved_at: u64,
    approval_expires_at: u64,
}

impl FiscalApproval {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_APPROVAL_ID_DOMAIN,
            &FiscalApprovalIdPreimage {
                schema: &self.schema,
                signer_key_id: &self.signer_key_id,
                proposal_id: &self.proposal_id,
                proposal_digest: &self.proposal_digest,
                admission_id: &self.admission_id,
                admission_digest: &self.admission_digest,
                approved_at: self.approved_at,
                approval_expires_at: self.approval_expires_at,
            },
        )
    }
}

pub type SignedFiscalApproval = SignedExportEnvelope<FiscalApproval>;

#[derive(Debug, Clone)]
pub struct FiscalApprovalBuilder {
    pub approved_at: u64,
}

impl FiscalApprovalBuilder {
    pub fn sign(
        self,
        proposal: &VerifiedFiscalProposal,
        admission: &VerifiedFiscalProposalAdmission,
        current_charter: &VerifiedFiscalCharter,
        keypair: &Keypair,
    ) -> Result<SignedFiscalApproval, FiscalError> {
        let approval_expires_at = self
            .approved_at
            .checked_add(current_charter.body().approval_ttl_seconds)
            .ok_or(FiscalError::InvalidField("approval.approval_expires_at"))?;
        let mut body = FiscalApproval {
            schema: FISCAL_APPROVAL_SCHEMA.to_owned(),
            approval_id: String::new(),
            signer_key_id: fiscal_signer_key_id(&keypair.public_key())?,
            proposal_id: proposal.body().proposal_id.clone(),
            proposal_digest: proposal.digest().to_owned(),
            admission_id: admission.body().admission_id.clone(),
            admission_digest: admission.digest().to_owned(),
            approved_at: self.approved_at,
            approval_expires_at,
        };
        body.approval_id = body.expected_id()?;
        SignedFiscalApproval::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalApproval {
    signed: SignedFiscalApproval,
    digest: String,
}

impl VerifiedFiscalApproval {
    pub fn verify(
        signed: SignedFiscalApproval,
        proposal: &VerifiedFiscalProposal,
        admission: &VerifiedFiscalProposalAdmission,
        current_charter: &VerifiedFiscalCharter,
        verify_at: u64,
    ) -> Result<Self, FiscalError> {
        let body = &signed.body;
        if body.schema != FISCAL_APPROVAL_SCHEMA {
            return Err(FiscalError::UnknownSchema(body.schema.clone()));
        }
        let member = current_charter
            .body()
            .signer_set
            .binary_search_by(|candidate| candidate.key_id.cmp(&body.signer_key_id))
            .ok()
            .and_then(|index| current_charter.body().signer_set.get(index))
            .ok_or(FiscalError::InvalidField("approval.nonmember"))?;
        let expected_expiry = body
            .approved_at
            .checked_add(current_charter.body().approval_ttl_seconds)
            .ok_or(FiscalError::InvalidField("approval.approval_expires_at"))?;
        if body.approval_id != body.expected_id()?
            || body.signer_key_id != fiscal_signer_key_id(&signed.signer_key)?
            || signed.signer_key != member.public_key
            || body.proposal_id != proposal.body().proposal_id
            || body.proposal_digest != proposal.digest()
            || body.admission_id != admission.body().admission_id
            || body.admission_digest != admission.digest()
            || body.approved_at < admission.body().admitted_at
            || body.approved_at > verify_at
            || body.approval_expires_at != expected_expiry
            || body.approval_expires_at > admission.body().proposal_expires_at
            || body.approval_expires_at > current_charter.body().expires_at
            || verify_at >= body.approval_expires_at
            || verify_at >= current_charter.body().expires_at
        {
            return Err(FiscalError::InvalidField("approval.binding"));
        }
        verify_envelope(&signed)?;
        let digest = signed_envelope_digest(&signed)?;
        Ok(Self { signed, digest })
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalApproval {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalApproval {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FiscalActivationTarget {
    Schedule {
        schedule_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        supersedes_schedule_id: Option<String>,
    },
    CharterRotation {
        successor_charter_digest: String,
        predecessor_charter_digest: String,
        successor_schedules: Vec<SignedFiscalSchedule>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FiscalActivation {
    pub schema: String,
    pub activation_id: String,
    pub proposal_id: String,
    pub proposal_digest: String,
    pub admission_id: String,
    pub admission_digest: String,
    pub charter_id: String,
    pub charter_digest: String,
    pub approval_set_digest: String,
    pub target: FiscalActivationTarget,
    pub approvals: Vec<SignedFiscalApproval>,
    pub activation_not_before: u64,
    pub activated_at: u64,
    pub issued_by: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalActivationIdPreimage<'a> {
    schema: &'a str,
    proposal_id: &'a str,
    proposal_digest: &'a str,
    admission_id: &'a str,
    admission_digest: &'a str,
    charter_id: &'a str,
    charter_digest: &'a str,
    approval_set_digest: &'a str,
    target: &'a FiscalActivationTarget,
    approvals: &'a [SignedFiscalApproval],
    activation_not_before: u64,
    activated_at: u64,
    issued_by: &'a str,
}

impl FiscalActivation {
    pub fn expected_id(&self) -> Result<String, FiscalError> {
        lifecycle_digest(
            FISCAL_ACTIVATION_ID_DOMAIN,
            &FiscalActivationIdPreimage {
                schema: &self.schema,
                proposal_id: &self.proposal_id,
                proposal_digest: &self.proposal_digest,
                admission_id: &self.admission_id,
                admission_digest: &self.admission_digest,
                charter_id: &self.charter_id,
                charter_digest: &self.charter_digest,
                approval_set_digest: &self.approval_set_digest,
                target: &self.target,
                approvals: &self.approvals,
                activation_not_before: self.activation_not_before,
                activated_at: self.activated_at,
                issued_by: &self.issued_by,
            },
        )
    }
}

pub type SignedFiscalActivation = SignedExportEnvelope<FiscalActivation>;

#[derive(Debug, Clone)]
pub struct FiscalActivationBuilder {
    pub target: FiscalActivationTarget,
    pub approvals: Vec<SignedFiscalApproval>,
    pub activated_at: u64,
}

impl FiscalActivationBuilder {
    pub fn sign(
        mut self,
        proposal: &VerifiedFiscalProposal,
        admission: &VerifiedFiscalProposalAdmission,
        current_charter: &VerifiedFiscalCharter,
        keypair: &Keypair,
    ) -> Result<SignedFiscalActivation, FiscalError> {
        self.approvals
            .sort_by(|left, right| left.body.signer_key_id.cmp(&right.body.signer_key_id));
        let approval_set_digest = approval_set_digest(&self.approvals)?;
        let activation_not_before = admission
            .body()
            .admitted_at
            .checked_add(current_charter.body().timelock_seconds)
            .ok_or(FiscalError::InvalidField(
                "activation.activation_not_before",
            ))?;
        let mut body = FiscalActivation {
            schema: FISCAL_ACTIVATION_SCHEMA.to_owned(),
            activation_id: String::new(),
            proposal_id: proposal.body().proposal_id.clone(),
            proposal_digest: proposal.digest().to_owned(),
            admission_id: admission.body().admission_id.clone(),
            admission_digest: admission.digest().to_owned(),
            charter_id: current_charter.body().charter_id.clone(),
            charter_digest: current_charter.digest().to_owned(),
            approval_set_digest,
            target: self.target,
            approvals: self.approvals,
            activation_not_before,
            activated_at: self.activated_at,
            issued_by: fiscal_signer_key_id(&keypair.public_key())?,
        };
        body.activation_id = body.expected_id()?;
        SignedFiscalActivation::sign(body, keypair)
            .map_err(|error| FiscalError::Canonicalization(error.to_string()))
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedFiscalActivation {
    signed: SignedFiscalActivation,
    digest: String,
    pub(super) admission_consumed: bool,
    pub(super) schedule_transition: Option<VerifiedFiscalScheduleTransition>,
    pub(super) rotation_predecessors: Vec<VerifiedFiscalRotationPredecessor>,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedFiscalScheduleTransition {
    pub(super) domain: FiscalDomain,
    pub(super) candidate: FiscalScheduleHead,
    pub(super) predecessor: Option<FiscalScheduleHead>,
}

#[derive(Debug, Clone)]
pub(super) struct VerifiedFiscalRotationPredecessor {
    pub(super) domain: FiscalDomain,
    pub(super) head: FiscalScheduleHead,
}

impl VerifiedFiscalActivation {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        signed: SignedFiscalActivation,
        proposal: &VerifiedFiscalProposal,
        admission: &VerifiedFiscalProposalAdmission,
        admission_state: &FiscalProposalAdmissionState,
        current_charter: &VerifiedFiscalCharter,
        admission_trust: &FiscalAdmissionTrustRegistry,
        predecessor_schedule: Option<&VerifiedFiscalSchedule>,
        rotation_predecessors: &[VerifiedFiscalSchedule],
        verify_at: u64,
    ) -> Result<Self, FiscalError> {
        let body = &signed.body;
        if body.schema != FISCAL_ACTIVATION_SCHEMA {
            return Err(FiscalError::UnknownSchema(body.schema.clone()));
        }
        if body.activation_id != body.expected_id()? {
            return Err(FiscalError::InvalidSelfId);
        }
        verify_envelope(&signed)?;
        let issuer = current_charter
            .body()
            .signer_set
            .binary_search_by(|candidate| candidate.key_id.cmp(&body.issued_by))
            .ok()
            .and_then(|index| current_charter.body().signer_set.get(index))
            .ok_or(FiscalError::InvalidField("activation.issuer"))?;
        if body.issued_by != fiscal_signer_key_id(&signed.signer_key)?
            || signed.signer_key != issuer.public_key
        {
            return Err(FiscalError::InvalidField("activation.issuer"));
        }
        let nested_admission = VerifiedFiscalProposalAdmission::verify(
            admission.signed().clone(),
            proposal,
            current_charter,
            admission_trust,
            verify_at,
        )?;
        if nested_admission.digest() != admission.digest() {
            return Err(FiscalError::InvalidField("activation.admission_digest"));
        }
        let activation_not_before = admission
            .body()
            .admitted_at
            .checked_add(current_charter.body().timelock_seconds)
            .ok_or(FiscalError::InvalidField(
                "activation.activation_not_before",
            ))?;
        if body.proposal_id != proposal.body().proposal_id
            || body.proposal_digest != proposal.digest()
            || body.admission_id != admission.body().admission_id
            || body.admission_digest != admission.digest()
            || body.charter_id != current_charter.body().charter_id
            || body.charter_digest != current_charter.digest()
            || body.activation_not_before != activation_not_before
            || body.activated_at != verify_at
            || verify_at < activation_not_before
            || verify_at >= admission.body().proposal_expires_at
            || verify_at >= current_charter.body().expires_at
            || admission_state.signed_admission != *admission.signed()
            || admission_state.admission_digest != admission.digest()
        {
            return Err(FiscalError::InvalidField("activation.binding"));
        }
        let mut signer_ids = BTreeSet::new();
        let mut approval_digests = BTreeSet::new();
        let mut previous_signer = None::<String>;
        for approval in &body.approvals {
            if previous_signer
                .as_deref()
                .is_some_and(|previous| previous >= approval.body.signer_key_id.as_str())
            {
                return Err(FiscalError::InvalidField("activation.approvals.order"));
            }
            let verified = VerifiedFiscalApproval::verify(
                approval.clone(),
                proposal,
                admission,
                current_charter,
                verify_at,
            )?;
            if !signer_ids.insert(verified.body().signer_key_id.clone())
                || !approval_digests.insert(verified.digest().to_owned())
            {
                return Err(FiscalError::InvalidField("activation.approvals.duplicate"));
            }
            previous_signer = Some(verified.body().signer_key_id.clone());
        }
        let approval_count = u32::try_from(signer_ids.len())
            .map_err(|_| FiscalError::InvalidField("activation.approvals.size"))?;
        if approval_count < current_charter.body().approval_threshold
            || body.approval_set_digest != approval_set_digest(&body.approvals)?
        {
            return Err(FiscalError::InvalidField("activation.threshold"));
        }
        verify_activation_target(
            &body.target,
            proposal,
            current_charter,
            predecessor_schedule,
            rotation_predecessors,
            verify_at,
        )?;
        let schedule_transition = match &proposal.body().target {
            FiscalProposalTarget::Schedule { candidate } => {
                Some(VerifiedFiscalScheduleTransition {
                    domain: candidate.body.domain,
                    candidate: FiscalScheduleHead::from_signed(candidate)?,
                    predecessor: predecessor_schedule
                        .map(|schedule| FiscalScheduleHead::from_signed(schedule.signed()))
                        .transpose()?,
                })
            }
            FiscalProposalTarget::CharterRotation { .. } => None,
        };
        let verified_rotation_predecessors = rotation_predecessors
            .iter()
            .map(|schedule| {
                Ok(VerifiedFiscalRotationPredecessor {
                    domain: schedule.body().domain,
                    head: FiscalScheduleHead::from_signed(schedule.signed())?,
                })
            })
            .collect::<Result<Vec<_>, FiscalError>>()?;
        let digest = signed_envelope_digest(&signed)?;
        let admission_consumed = match admission_state.status {
            FiscalProposalAdmissionStatus::Admitted => {
                if admission_state.activation_digest.is_some()
                    || admission_state.activated_sequence.is_some()
                {
                    return Err(FiscalError::InvalidField("activation.admission_state"));
                }
                false
            }
            FiscalProposalAdmissionStatus::Activated => {
                if admission_state.activation_digest.as_deref() != Some(digest.as_str())
                    || admission_state.activated_sequence
                        != Some(activation_sequence(&body.target, proposal)?)
                {
                    return Err(FiscalError::InvalidField("activation.admission_state"));
                }
                true
            }
        };
        Ok(Self {
            signed,
            digest,
            admission_consumed,
            schedule_transition,
            rotation_predecessors: verified_rotation_predecessors,
        })
    }

    #[must_use]
    pub const fn body(&self) -> &FiscalActivation {
        &self.signed.body
    }

    #[must_use]
    pub const fn signed(&self) -> &SignedFiscalActivation {
        &self.signed
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn schedule_transitions(&self) -> Result<Vec<VerifiedFiscalScheduleTransition>, FiscalError> {
        if let Some(transition) = &self.schedule_transition {
            return Ok(vec![transition.clone()]);
        }
        let FiscalActivationTarget::CharterRotation {
            successor_schedules,
            ..
        } = &self.signed.body.target
        else {
            return Err(FiscalError::InvalidLineage);
        };
        if successor_schedules.len() != self.rotation_predecessors.len() {
            return Err(FiscalError::InvalidLineage);
        }
        successor_schedules
            .iter()
            .zip(&self.rotation_predecessors)
            .map(|(candidate, predecessor)| {
                if candidate.body.domain != predecessor.domain {
                    return Err(FiscalError::InvalidLineage);
                }
                Ok(VerifiedFiscalScheduleTransition {
                    domain: candidate.body.domain,
                    candidate: FiscalScheduleHead::from_signed(candidate)?,
                    predecessor: Some(predecessor.head.clone()),
                })
            })
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct FiscalActivationHistory {
    activations: Vec<VerifiedFiscalActivation>,
}

impl FiscalActivationHistory {
    pub fn new(authorities: Vec<VerifiedFiscalActivationAuthority>) -> Result<Self, FiscalError> {
        let activations = authorities
            .into_iter()
            .map(VerifiedFiscalActivationAuthority::into_activation)
            .collect::<Vec<_>>();
        let mut activation_digests = BTreeSet::new();
        let mut candidates = BTreeSet::new();
        for activation in &activations {
            if !activation.admission_consumed {
                return Err(FiscalError::InvalidField(
                    "activation_history.unconsumed_admission",
                ));
            }
            if !activation_digests.insert(activation.digest().to_owned()) {
                return Err(FiscalError::InvalidField("activation_history.duplicate"));
            }
            for transition in activation.schedule_transitions()? {
                if !candidates.insert((
                    transition.domain,
                    transition.candidate.schedule_id,
                    transition.candidate.schedule_digest,
                )) {
                    return Err(FiscalError::InvalidField(
                        "activation_history.candidate_duplicate",
                    ));
                }
            }
        }
        Ok(Self { activations })
    }

    pub fn from_checkpoint_history(
        activations: Vec<VerifiedFiscalActivation>,
        checkpoints: &[super::continuity::VerifiedFiscalContinuityCheckpoint],
        current: &super::continuity::VerifiedFiscalContinuityCheckpoint,
    ) -> Result<Self, FiscalError> {
        let mut by_digest = checkpoints
            .iter()
            .map(|checkpoint| (checkpoint.digest(), checkpoint))
            .collect::<std::collections::BTreeMap<_, _>>();
        if by_digest.len() != checkpoints.len() {
            return Err(FiscalError::InvalidLineage);
        }
        by_digest
            .remove(current.digest())
            .ok_or(FiscalError::InvalidLineage)?;
        let mut chain = BTreeSet::new();
        let mut cursor = current;
        loop {
            if !chain.insert(cursor.digest().to_owned()) {
                return Err(FiscalError::InvalidLineage);
            }
            let Some(previous) = cursor.body().previous_checkpoint_digest.as_deref() else {
                break;
            };
            cursor = by_digest
                .remove(previous)
                .ok_or(FiscalError::InvalidLineage)?;
        }
        if !by_digest.is_empty() {
            return Err(FiscalError::InvalidLineage);
        }
        let authorities = activations
            .into_iter()
            .map(|activation| {
                let transition = FiscalStagedTransition::new(
                    activation.body().activation_id.clone(),
                    activation.digest().to_owned(),
                )?;
                let checkpoint = checkpoints
                    .iter()
                    .find(|checkpoint| {
                        chain.contains(checkpoint.digest())
                            && checkpoint.body().staged_transition.as_ref() == Some(&transition)
                            && checkpoint.body().trusted_clock_high_water
                                >= activation.body().activated_at
                    })
                    .ok_or(FiscalError::InvalidLineage)?;
                Ok(VerifiedFiscalActivationAuthority {
                    activation,
                    checkpoint_digest: checkpoint.digest().to_owned(),
                })
            })
            .collect::<Result<Vec<_>, FiscalError>>()?;
        Self::new(authorities)
    }

    pub(crate) fn verify_head(
        &self,
        head: &FiscalScheduleHead,
        domain: FiscalDomain,
        verify_at: u64,
    ) -> Result<(), FiscalError> {
        let mut current = head.clone();
        let mut visited = BTreeSet::new();
        loop {
            current.validate()?;
            if !visited.insert((current.schedule_id.clone(), current.schedule_digest.clone())) {
                return Err(FiscalError::InvalidLineage);
            }
            match self.predecessor_for_head(&current, domain, verify_at)? {
                None if current.sequence == 1 => return Ok(()),
                Some(predecessor) => {
                    let expected_sequence = predecessor
                        .sequence
                        .checked_add(1)
                        .ok_or(FiscalError::InvalidLineage)?;
                    if current.sequence != expected_sequence {
                        return Err(FiscalError::InvalidLineage);
                    }
                    current = predecessor;
                }
                None => return Err(FiscalError::InvalidLineage),
            }
        }
    }

    pub(crate) fn predecessor_for_head(
        &self,
        head: &FiscalScheduleHead,
        domain: FiscalDomain,
        verify_at: u64,
    ) -> Result<Option<FiscalScheduleHead>, FiscalError> {
        head.validate()?;
        let mut matched = None;
        for activation in &self.activations {
            for transition in activation.schedule_transitions()? {
                if transition.domain == domain && transition.candidate == *head {
                    if activation.body().activated_at > verify_at || matched.is_some() {
                        return Err(FiscalError::InvalidLineage);
                    }
                    matched = Some(transition.predecessor);
                }
            }
        }
        matched.ok_or(FiscalError::InvalidLineage)
    }
}

fn verify_activation_target(
    target: &FiscalActivationTarget,
    proposal: &VerifiedFiscalProposal,
    current_charter: &VerifiedFiscalCharter,
    predecessor_schedule: Option<&VerifiedFiscalSchedule>,
    rotation_predecessors: &[VerifiedFiscalSchedule],
    verify_at: u64,
) -> Result<(), FiscalError> {
    match (target, &proposal.body().target) {
        (
            FiscalActivationTarget::Schedule {
                schedule_id,
                supersedes_schedule_id,
            },
            FiscalProposalTarget::Schedule { candidate },
        ) => {
            let candidate = VerifiedFiscalSchedule::verify(
                candidate.as_ref().clone(),
                current_charter,
                predecessor_schedule,
            )?;
            if schedule_id != &candidate.body().schedule_id
                || supersedes_schedule_id != &candidate.body().supersedes_schedule_id
                || verify_at < candidate.body().valid_from
                || verify_at >= candidate.body().valid_until
            {
                return Err(FiscalError::InvalidField("activation.schedule_target"));
            }
        }
        (
            FiscalActivationTarget::CharterRotation {
                successor_charter_digest,
                predecessor_charter_digest,
                successor_schedules,
            },
            FiscalProposalTarget::CharterRotation { successor },
        ) => {
            let successor = VerifiedFiscalCharter::verify(successor.as_ref().clone())?;
            if successor_charter_digest != successor.digest()
                || predecessor_charter_digest != current_charter.digest()
                || successor_schedules.len() != rotation_predecessors.len()
                || successor_schedules
                    .windows(2)
                    .any(|pair| pair[0].body.domain >= pair[1].body.domain)
                || rotation_predecessors
                    .windows(2)
                    .any(|pair| pair[0].body().domain >= pair[1].body().domain)
                || verify_at >= successor.body().expires_at
            {
                return Err(FiscalError::InvalidField("activation.rotation_target"));
            }
            for (replacement, predecessor) in successor_schedules.iter().zip(rotation_predecessors)
            {
                verify_rotation_replacement(replacement, &successor, predecessor)?;
            }
        }
        _ => return Err(FiscalError::InvalidField("activation.target_kind")),
    }
    Ok(())
}

fn verify_rotation_replacement(
    signed: &SignedFiscalSchedule,
    successor_charter: &VerifiedFiscalCharter,
    predecessor: &VerifiedFiscalSchedule,
) -> Result<(), FiscalError> {
    signed.body.validate_against(successor_charter)?;
    verify_envelope(signed)?;
    let expected_sequence = predecessor
        .body()
        .sequence
        .checked_add(1)
        .ok_or(FiscalError::InvalidLineage)?;
    if signed.body.domain != predecessor.body().domain
        || signed.body.sequence != expected_sequence
        || signed.body.supersedes_schedule_id.as_deref()
            != Some(predecessor.body().schedule_id.as_str())
        || signed.body.params != predecessor.body().params
        || signed.body.valid_from != predecessor.body().valid_from
        || signed.body.valid_until != predecessor.body().valid_until
    {
        return Err(FiscalError::InvalidLineage);
    }
    Ok(())
}

fn activation_sequence(
    target: &FiscalActivationTarget,
    proposal: &VerifiedFiscalProposal,
) -> Result<u64, FiscalError> {
    match (target, &proposal.body().target) {
        (FiscalActivationTarget::Schedule { .. }, FiscalProposalTarget::Schedule { candidate }) => {
            Ok(candidate.body.sequence)
        }
        (
            FiscalActivationTarget::CharterRotation {
                successor_schedules,
                ..
            },
            FiscalProposalTarget::CharterRotation { .. },
        ) => successor_schedules
            .iter()
            .map(|schedule| schedule.body.sequence)
            .max()
            .ok_or(FiscalError::InvalidField("activation.rotation_schedules")),
        _ => Err(FiscalError::InvalidField("activation.target_kind")),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FiscalApprovalSetEntry<'a> {
    signer_key_id: &'a str,
    envelope_digest: String,
}

fn approval_set_digest(approvals: &[SignedFiscalApproval]) -> Result<String, FiscalError> {
    let mut previous = None;
    let mut signer_ids = BTreeSet::new();
    let mut envelope_digests = BTreeSet::new();
    let mut entries = Vec::with_capacity(approvals.len());
    for approval in approvals {
        if previous.is_some_and(|value| value >= approval.body.signer_key_id.as_str())
            || !signer_ids.insert(approval.body.signer_key_id.as_str())
        {
            return Err(FiscalError::InvalidField("approval_set.order"));
        }
        let envelope_digest = signed_envelope_digest(approval)?;
        if !envelope_digests.insert(envelope_digest.clone()) {
            return Err(FiscalError::InvalidField("approval_set.duplicate"));
        }
        entries.push(FiscalApprovalSetEntry {
            signer_key_id: &approval.body.signer_key_id,
            envelope_digest,
        });
        previous = Some(approval.body.signer_key_id.as_str());
    }
    lifecycle_digest(FISCAL_APPROVAL_SET_DIGEST_DOMAIN, &entries)
}
