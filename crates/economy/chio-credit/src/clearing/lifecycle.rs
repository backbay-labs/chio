use std::collections::BTreeSet;
use std::sync::Arc;

use chio_core_types::economic_continuity::{
    EconomicContentV1, EconomicEffectSlotV1, EconomicFrostBindingV1, EconomicRequestReplayV1,
    EconomicResourceHeadV1, EconomicResourceKeyV1, EconomicStateAnchorError, EconomicStateBatchV1,
    EconomicStateTransitionV1, EconomicTransitionAuthorizationV1, EconomicTransitionProofVerifier,
    VerifiedEconomicStateView, CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA, MAX_ECONOMIC_TRANSITIONS,
};
use serde::{Deserialize, Serialize};

use super::*;
use crate::obligation::ObligationDispositionTransitionV1;

mod dispatch;
mod reconciliation;
mod record;
mod replay;
mod satisfaction;
mod validation;
mod zero_intent;

pub use dispatch::compose_clearing_dispatch_transition;
pub use reconciliation::*;
pub use replay::*;
pub use satisfaction::*;
use validation::{checked_transition_count, reservation_head_root, reservation_root};
pub(super) use validation::{validate_round_core, validate_round_head};
pub use zero_intent::*;

pub const CLEARING_ROUND_LIFECYCLE_SCHEMA: &str = "chio.clearing.round-lifecycle.v1";
pub const CLEARING_ROUND_TRANSITION_PROOF_SCHEMA: &str = "chio.clearing.round-transition-proof.v1";
pub const CLEARING_ROUND_RESOURCE_FAMILY: &str = "clearing_round";
pub const CLEARING_OBLIGATION_RESOURCE_FAMILY: &str = "obligation_disposition";
pub const CLEARING_SETTLEMENT_DISPATCH_EFFECT_KIND: &str = "settlement_dispatch";

const ROUND_LIFECYCLE_GENESIS_DOMAIN: &[u8] = b"chio.clearing.round-lifecycle.genesis.v1\0";
const ROUND_TRANSITION_PROOF_DOMAIN: &[u8] = b"chio.clearing.round-transition-proof.digest.v1\0";
const RESERVATION_HEAD_ROOT_DOMAIN: &[u8] = b"chio.clearing.reservation-head-root.v1\0";
const INTENT_RECONCILIATION_CHAIN_DOMAIN: &[u8] = b"chio.clearing.intent-reconciliation-chain.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearingRoundLifecycleStateV1 {
    Reserved,
    Proposed,
    Finalizing,
    Finalized,
    Dispatching,
    Reconciling,
    Satisfied,
    Aborting,
    Aborted,
    Incident,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingIntentProgressV1 {
    intent_id: String,
    intent_digest: String,
    attempt_count: u64,
    no_effect_count: u64,
    ambiguity_count: u64,
    reconciliation_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconciliation_chain_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active_effect_slot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unknown_effect_slot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    completed_effect_slot_id: Option<String>,
}

impl ClearingIntentProgressV1 {
    fn dispatched(
        intent_id: String,
        intent_digest: String,
        effect_slot_id: String,
    ) -> Result<Self, ClearingError> {
        let progress = Self {
            intent_id,
            intent_digest,
            attempt_count: 1,
            no_effect_count: 0,
            ambiguity_count: 0,
            reconciliation_count: 0,
            reconciliation_chain_digest: None,
            active_effect_slot_id: Some(effect_slot_id),
            unknown_effect_slot_id: None,
            completed_effect_slot_id: None,
        };
        progress.validate()?;
        Ok(progress)
    }

    fn register_dispatch(&mut self, effect_slot_id: String) -> Result<(), ClearingError> {
        if self.active_effect_slot_id.is_some()
            || self.unknown_effect_slot_id.is_some()
            || self.completed_effect_slot_id.is_some()
        {
            return Err(ClearingError::IllegalLifecycleTransition);
        }
        self.attempt_count = self
            .attempt_count
            .checked_add(1)
            .filter(|count| *count <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        self.active_effect_slot_id = Some(effect_slot_id);
        self.validate()
    }

    fn reconcile(
        &mut self,
        effect_slot_id: &str,
        observed_status: ClearingSettlementObservedStatusV1,
        attempt_number: u64,
        reconciliation_digest: &str,
    ) -> Result<(), ClearingError> {
        if self.attempt_count != attempt_number {
            return Err(ClearingError::AuthorityVerification);
        }
        let active = self.active_effect_slot_id.as_deref() == Some(effect_slot_id);
        let unknown = self.unknown_effect_slot_id.as_deref() == Some(effect_slot_id);
        match observed_status {
            ClearingSettlementObservedStatusV1::Settled if active || unknown => {
                self.active_effect_slot_id = None;
                self.unknown_effect_slot_id = None;
                self.completed_effect_slot_id = Some(effect_slot_id.to_owned());
            }
            ClearingSettlementObservedStatusV1::PermanentNoEffect if active || unknown => {
                self.active_effect_slot_id = None;
                self.unknown_effect_slot_id = None;
                self.no_effect_count = self
                    .no_effect_count
                    .checked_add(1)
                    .filter(|count| *count <= I_JSON_MAX_SAFE_INTEGER)
                    .ok_or(ClearingError::ArithmeticOverflow)?;
            }
            ClearingSettlementObservedStatusV1::Unknown if active => {
                self.active_effect_slot_id = None;
                self.unknown_effect_slot_id = Some(effect_slot_id.to_owned());
                self.ambiguity_count = self
                    .ambiguity_count
                    .checked_add(1)
                    .filter(|count| *count <= I_JSON_MAX_SAFE_INTEGER)
                    .ok_or(ClearingError::ArithmeticOverflow)?;
            }
            _ => return Err(ClearingError::IllegalLifecycleTransition),
        }
        validate_digest("progress_reconciliation_digest", reconciliation_digest)?;
        self.reconciliation_count = self
            .reconciliation_count
            .checked_add(1)
            .filter(|count| *count <= I_JSON_MAX_SAFE_INTEGER)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        self.reconciliation_chain_digest = Some(domain_digest(
            INTENT_RECONCILIATION_CHAIN_DOMAIN,
            &(
                self.reconciliation_chain_digest.as_deref(),
                reconciliation_digest,
            ),
        )?);
        self.validate()
    }

    fn validate(&self) -> Result<(), ClearingError> {
        validate_text("progress_intent_id", &self.intent_id)?;
        validate_digest("progress_intent_digest", &self.intent_digest)?;
        validate_positive("progress_attempt_count", self.attempt_count)?;
        if self.no_effect_count > I_JSON_MAX_SAFE_INTEGER
            || self.ambiguity_count > I_JSON_MAX_SAFE_INTEGER
        {
            return Err(ClearingError::InvalidField("progress_no_effect_count"));
        }
        if self.reconciliation_count > I_JSON_MAX_SAFE_INTEGER
            || self.reconciliation_chain_digest.is_some() != (self.reconciliation_count != 0)
        {
            return Err(ClearingError::InvalidField("progress_reconciliation"));
        }
        validate_optional_digest(
            "progress_reconciliation_chain_digest",
            self.reconciliation_chain_digest.as_deref(),
        )?;
        for slot_id in [
            self.active_effect_slot_id.as_deref(),
            self.unknown_effect_slot_id.as_deref(),
            self.completed_effect_slot_id.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_digest("progress_effect_slot_id", slot_id)?;
        }
        let unresolved = u64::from(
            self.active_effect_slot_id.is_some() || self.unknown_effect_slot_id.is_some(),
        );
        let completed = u64::from(self.completed_effect_slot_id.is_some());
        if self.active_effect_slot_id.is_some() && self.unknown_effect_slot_id.is_some()
            || completed != 0 && unresolved != 0
            || self
                .reconciliation_count
                .checked_add(u64::from(self.active_effect_slot_id.is_some()))
                != self
                    .attempt_count
                    .checked_add(self.ambiguity_count)
                    .and_then(|count| {
                        count.checked_sub(u64::from(self.unknown_effect_slot_id.is_some()))
                    })
            || self.no_effect_count > self.reconciliation_count
            || self.ambiguity_count > self.reconciliation_count
            || self
                .no_effect_count
                .checked_add(unresolved)
                .and_then(|count| count.checked_add(completed))
                != Some(self.attempt_count)
        {
            return Err(ClearingError::InvalidField("intent_progress"));
        }
        Ok(())
    }
}

impl ClearingRoundLifecycleStateV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Proposed => "proposed",
            Self::Finalizing => "finalizing",
            Self::Finalized => "finalized",
            Self::Dispatching => "dispatching",
            Self::Reconciling => "reconciling",
            Self::Satisfied => "satisfied",
            Self::Aborting => "aborting",
            Self::Aborted => "aborted",
            Self::Incident => "incident",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundLifecycleRecordV1 {
    schema: String,
    round_id: String,
    governance_scope_id: String,
    round_core_digest: String,
    input_manifest_digest: String,
    reservation_root: String,
    reservation_count: u64,
    state: ClearingRoundLifecycleStateV1,
    row_version: u64,
    fence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    output_manifest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    participant_acceptance_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    participant_acceptance_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    finalization_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    abort_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_dispatch_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    intent_progress: Vec<ClearingIntentProgressV1>,
    last_transition_digest: String,
}

impl ClearingRoundLifecycleRecordV1 {
    pub fn reserved(core: &NettingRoundCoreV1) -> Result<Self, ClearingError> {
        validate_round_core(core)?;
        let record = Self {
            schema: CLEARING_ROUND_LIFECYCLE_SCHEMA.to_owned(),
            round_id: core.round_id.clone(),
            governance_scope_id: core.governance_scope_id.clone(),
            round_core_digest: core.digest()?,
            input_manifest_digest: core.input_manifest_digest.clone(),
            reservation_root: core.reservation_root.clone(),
            reservation_count: core.input_count,
            state: ClearingRoundLifecycleStateV1::Reserved,
            row_version: 1,
            fence: 1,
            output_manifest_digest: None,
            participant_acceptance_root: None,
            participant_acceptance_count: None,
            finalization_digest: None,
            abort_digest: None,
            first_dispatch_operation_id: None,
            intent_progress: Vec::new(),
            last_transition_digest: domain_digest(ROUND_LIFECYCLE_GENESIS_DOMAIN, core)?,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ROUND_LIFECYCLE_SCHEMA {
            return Err(ClearingError::InvalidField("round_lifecycle_schema"));
        }
        validate_text("round_id", &self.round_id)?;
        validate_text("governance_scope_id", &self.governance_scope_id)?;
        validate_digest("round_core_digest", &self.round_core_digest)?;
        validate_digest("input_manifest_digest", &self.input_manifest_digest)?;
        validate_digest("reservation_root", &self.reservation_root)?;
        validate_positive("reservation_count", self.reservation_count)?;
        let transition_count = checked_transition_count(self.reservation_count)?;
        if transition_count > MAX_ECONOMIC_TRANSITIONS {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        validate_positive("round_row_version", self.row_version)?;
        validate_positive("round_fence", self.fence)?;
        validate_digest("last_transition_digest", &self.last_transition_digest)?;
        if self.row_version != self.fence {
            return Err(ClearingError::InvalidField("round_fence"));
        }
        validate_optional_digest(
            "output_manifest_digest",
            self.output_manifest_digest.as_deref(),
        )?;
        validate_optional_digest(
            "participant_acceptance_root",
            self.participant_acceptance_root.as_deref(),
        )?;
        if let Some(count) = self.participant_acceptance_count {
            validate_positive("participant_acceptance_count", count)?;
            if usize::try_from(count).map_err(|_| ClearingError::ArithmeticOverflow)?
                > MAX_CLEARING_PARTICIPANTS
            {
                return Err(ClearingError::InvalidField("participant_acceptance_count"));
            }
        }
        if self.participant_acceptance_root.is_some() != self.participant_acceptance_count.is_some()
        {
            return Err(ClearingError::InvalidField("participant_acceptance"));
        }
        validate_optional_digest("finalization_digest", self.finalization_digest.as_deref())?;
        validate_optional_digest("abort_digest", self.abort_digest.as_deref())?;
        if let Some(operation_id) = self.first_dispatch_operation_id.as_deref() {
            validate_digest("first_dispatch_operation_id", operation_id)?;
        }
        if self.intent_progress.len() > MAX_CLEARING_SETTLEMENT_INTENTS
            || !self
                .intent_progress
                .windows(2)
                .all(|pair| pair[0].intent_id < pair[1].intent_id)
        {
            return Err(ClearingError::InvalidField("intent_progress"));
        }
        for progress in &self.intent_progress {
            progress.validate()?;
        }
        let valid = match self.state {
            ClearingRoundLifecycleStateV1::Reserved => {
                self.output_manifest_digest.is_none()
                    && self.participant_acceptance_root.is_none()
                    && self.finalization_digest.is_none()
                    && self.abort_digest.is_none()
                    && self.first_dispatch_operation_id.is_none()
                    && self.intent_progress.is_empty()
            }
            ClearingRoundLifecycleStateV1::Proposed => {
                self.output_manifest_digest.is_some()
                    && self.participant_acceptance_root.is_none()
                    && self.finalization_digest.is_none()
                    && self.abort_digest.is_none()
                    && self.first_dispatch_operation_id.is_none()
                    && self.intent_progress.is_empty()
            }
            ClearingRoundLifecycleStateV1::Finalizing => {
                self.output_manifest_digest.is_some()
                    && self.participant_acceptance_root.is_some()
                    && self.finalization_digest.is_none()
                    && self.abort_digest.is_none()
                    && self.first_dispatch_operation_id.is_none()
                    && self.intent_progress.is_empty()
            }
            ClearingRoundLifecycleStateV1::Finalized => {
                self.output_manifest_digest.is_some()
                    && self.participant_acceptance_root.is_some()
                    && self.finalization_digest.is_some()
                    && self.abort_digest.is_none()
                    && self.first_dispatch_operation_id.is_none()
                    && self.intent_progress.is_empty()
            }
            ClearingRoundLifecycleStateV1::Dispatching
            | ClearingRoundLifecycleStateV1::Reconciling
            | ClearingRoundLifecycleStateV1::Incident => {
                self.output_manifest_digest.is_some()
                    && self.participant_acceptance_root.is_some()
                    && self.finalization_digest.is_some()
                    && self.abort_digest.is_none()
                    && self.first_dispatch_operation_id.is_some()
                    && !self.intent_progress.is_empty()
            }
            ClearingRoundLifecycleStateV1::Satisfied => {
                self.output_manifest_digest.is_some()
                    && self.participant_acceptance_root.is_some()
                    && self.finalization_digest.is_some()
                    && self.abort_digest.is_none()
                    && self.first_dispatch_operation_id.is_some() != self.intent_progress.is_empty()
                    && self.intent_progress.iter().all(|progress| {
                        progress.active_effect_slot_id.is_none()
                            && progress.unknown_effect_slot_id.is_none()
                            && progress.completed_effect_slot_id.is_some()
                    })
            }
            ClearingRoundLifecycleStateV1::Aborting | ClearingRoundLifecycleStateV1::Aborted => {
                self.finalization_digest.is_none()
                    && self.abort_digest.is_some()
                    && self.first_dispatch_operation_id.is_none()
                    && self.intent_progress.is_empty()
            }
        };
        if valid {
            Ok(())
        } else {
            Err(ClearingError::InvalidField("round_lifecycle_state"))
        }
    }

    fn advance(
        &self,
        transition: &ClearingRoundTransitionV1,
        proof_digest: String,
    ) -> Result<Self, ClearingError> {
        self.advance_inner(transition, proof_digest, false)
    }

    fn advance_zero_intent(
        &self,
        transition: &ClearingRoundTransitionV1,
        proof_digest: String,
    ) -> Result<Self, ClearingError> {
        self.advance_inner(transition, proof_digest, true)
    }

    fn advance_inner(
        &self,
        transition: &ClearingRoundTransitionV1,
        proof_digest: String,
        verified_zero_intent: bool,
    ) -> Result<Self, ClearingError> {
        self.validate()?;
        transition.validate()?;
        let state = if verified_zero_intent
            && self.state == ClearingRoundLifecycleStateV1::Finalized
            && self.intent_progress.is_empty()
            && self.first_dispatch_operation_id.is_none()
            && matches!(transition, ClearingRoundTransitionV1::Satisfy { .. })
        {
            ClearingRoundLifecycleStateV1::Satisfied
        } else {
            transition.target_state(self.state)?
        };
        let row_version = self
            .row_version
            .checked_add(1)
            .ok_or(ClearingError::ArithmeticOverflow)?;
        let mut next = self.clone();
        next.state = state;
        next.row_version = row_version;
        next.fence = row_version;
        next.last_transition_digest = proof_digest;
        match transition {
            ClearingRoundTransitionV1::Propose {
                output_manifest_digest,
                ..
            } => next.output_manifest_digest = Some(output_manifest_digest.clone()),
            ClearingRoundTransitionV1::BeginFinalization {
                acceptance_root,
                acceptance_count,
                ..
            } => {
                next.participant_acceptance_root = Some(acceptance_root.clone());
                next.participant_acceptance_count = Some(*acceptance_count);
            }
            ClearingRoundTransitionV1::Finalize {
                finalization_digest,
                ..
            } => next.finalization_digest = Some(finalization_digest.clone()),
            ClearingRoundTransitionV1::BeginAbort { abort_digest, .. } => {
                next.abort_digest = Some(abort_digest.clone())
            }
            ClearingRoundTransitionV1::Abort { abort_digest, .. } => {
                if next.abort_digest.as_deref() != Some(abort_digest) {
                    return Err(ClearingError::IllegalLifecycleTransition);
                }
            }
            ClearingRoundTransitionV1::BeginDispatch {
                operation_id,
                intent_id,
                intent_digest,
                effect_slot_id,
                ..
            } => {
                if next.first_dispatch_operation_id.is_none() {
                    next.first_dispatch_operation_id = Some(operation_id.clone());
                }
                match next
                    .intent_progress
                    .binary_search_by(|progress| progress.intent_id.cmp(intent_id))
                {
                    Ok(index) => {
                        if next.intent_progress[index].intent_digest != *intent_digest {
                            return Err(ClearingError::AuthorityVerification);
                        }
                        next.intent_progress[index].register_dispatch(effect_slot_id.clone())?;
                    }
                    Err(index) => next.intent_progress.insert(
                        index,
                        ClearingIntentProgressV1::dispatched(
                            intent_id.clone(),
                            intent_digest.clone(),
                            effect_slot_id.clone(),
                        )?,
                    ),
                }
            }
            ClearingRoundTransitionV1::BeginReconciliation {
                reconciliation_digest,
                intent_id,
                intent_digest,
                effect_slot_id,
                observed_status,
                attempt_number,
                ..
            } => next.reconcile_intent(
                intent_id,
                intent_digest,
                effect_slot_id,
                *observed_status,
                *attempt_number,
                reconciliation_digest,
            )?,
            ClearingRoundTransitionV1::Incident {
                reconciliation_digest,
                intent_id,
                intent_digest,
                effect_slot_id,
                attempt_number,
                ..
            } => next.reconcile_intent(
                intent_id,
                intent_digest,
                effect_slot_id,
                ClearingSettlementObservedStatusV1::Unknown,
                *attempt_number,
                reconciliation_digest,
            )?,
            ClearingRoundTransitionV1::Satisfy { .. } => {}
        }
        next.validate()?;
        Ok(next)
    }

    fn reconcile_intent(
        &mut self,
        intent_id: &str,
        intent_digest: &str,
        effect_slot_id: &str,
        observed_status: ClearingSettlementObservedStatusV1,
        attempt_number: u64,
        reconciliation_digest: &str,
    ) -> Result<(), ClearingError> {
        let index = self
            .intent_progress
            .binary_search_by(|progress| progress.intent_id.as_str().cmp(intent_id))
            .map_err(|_| ClearingError::AuthorityVerification)?;
        let progress = &mut self.intent_progress[index];
        if progress.intent_digest != intent_digest {
            return Err(ClearingError::AuthorityVerification);
        }
        progress.reconcile(
            effect_slot_id,
            observed_status,
            attempt_number,
            reconciliation_digest,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClearingRoundTransitionV1 {
    Propose {
        output_manifest_digest: String,
        authority_digest: String,
    },
    BeginFinalization {
        acceptance_root: String,
        acceptance_count: u64,
        authority_digest: String,
    },
    Finalize {
        finalization_digest: String,
        frost: EconomicFrostBindingV1,
    },
    BeginAbort {
        abort_digest: String,
        zero_dispatch_proof_digest: String,
        authority_digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frost_burn_checkpoint_digest: Option<String>,
    },
    Abort {
        abort_digest: String,
        zero_dispatch_proof_digest: String,
        authority_digest: String,
    },
    BeginDispatch {
        operation_id: String,
        intent_id: String,
        intent_digest: String,
        effect_slot_id: String,
        effect_slot_digest: String,
        authority_digest: String,
    },
    BeginReconciliation {
        reconciliation_digest: String,
        intent_id: String,
        intent_digest: String,
        effect_slot_id: String,
        observed_status: ClearingSettlementObservedStatusV1,
        attempt_number: u64,
        authority_digest: String,
    },
    Satisfy {
        satisfaction_digest: String,
        authority_digest: String,
    },
    Incident {
        reconciliation_digest: String,
        intent_id: String,
        intent_digest: String,
        effect_slot_id: String,
        attempt_number: u64,
        authority_digest: String,
    },
}

impl ClearingRoundTransitionV1 {
    fn validate(&self) -> Result<(), ClearingError> {
        match self {
            Self::Propose {
                output_manifest_digest,
                authority_digest,
            } => {
                validate_digest("output_manifest_digest", output_manifest_digest)?;
                validate_digest("proposal_authority_digest", authority_digest)
            }
            Self::BeginFinalization {
                acceptance_root,
                acceptance_count,
                authority_digest,
            } => {
                validate_digest("acceptance_root", acceptance_root)?;
                validate_positive("acceptance_count", *acceptance_count)?;
                if usize::try_from(*acceptance_count)
                    .map_err(|_| ClearingError::ArithmeticOverflow)?
                    > MAX_CLEARING_PARTICIPANTS
                {
                    return Err(ClearingError::InvalidField("acceptance_count"));
                }
                validate_digest("finalization_authority_digest", authority_digest)
            }
            Self::Finalize {
                finalization_digest,
                frost,
            } => {
                validate_digest("finalization_digest", finalization_digest)?;
                frost
                    .validate()
                    .map_err(|_| ClearingError::InvalidField("frost_binding"))
            }
            Self::BeginAbort {
                abort_digest,
                zero_dispatch_proof_digest,
                authority_digest,
                frost_burn_checkpoint_digest,
            } => {
                validate_digest("abort_digest", abort_digest)?;
                validate_digest("zero_dispatch_proof_digest", zero_dispatch_proof_digest)?;
                validate_digest("abort_authority_digest", authority_digest)?;
                validate_optional_digest(
                    "frost_burn_checkpoint_digest",
                    frost_burn_checkpoint_digest.as_deref(),
                )
            }
            Self::Abort {
                abort_digest,
                zero_dispatch_proof_digest,
                authority_digest,
            } => {
                validate_digest("abort_digest", abort_digest)?;
                validate_digest("zero_dispatch_proof_digest", zero_dispatch_proof_digest)?;
                validate_digest("abort_authority_digest", authority_digest)
            }
            Self::BeginDispatch {
                operation_id,
                intent_id,
                intent_digest,
                effect_slot_id,
                effect_slot_digest,
                authority_digest,
            } => {
                validate_digest("operation_id", operation_id)?;
                validate_text("dispatch_intent_id", intent_id)?;
                validate_digest("dispatch_intent_digest", intent_digest)?;
                validate_digest("dispatch_effect_slot_id", effect_slot_id)?;
                validate_digest("effect_slot_digest", effect_slot_digest)?;
                validate_digest("dispatch_authority_digest", authority_digest)
            }
            Self::BeginReconciliation {
                reconciliation_digest,
                intent_id,
                intent_digest,
                effect_slot_id,
                observed_status,
                attempt_number,
                authority_digest,
            } => {
                validate_digest("reconciliation_digest", reconciliation_digest)?;
                validate_text("reconciliation_intent_id", intent_id)?;
                validate_digest("reconciliation_intent_digest", intent_digest)?;
                validate_digest("reconciliation_effect_slot_id", effect_slot_id)?;
                validate_positive("reconciliation_attempt_number", *attempt_number)?;
                if *observed_status == ClearingSettlementObservedStatusV1::Unknown {
                    return Err(ClearingError::InvalidField("reconciliation_status"));
                }
                validate_digest("reconciliation_authority_digest", authority_digest)
            }
            Self::Satisfy {
                satisfaction_digest,
                authority_digest,
            } => {
                validate_digest("satisfaction_digest", satisfaction_digest)?;
                validate_digest("satisfaction_authority_digest", authority_digest)
            }
            Self::Incident {
                reconciliation_digest,
                intent_id,
                intent_digest,
                effect_slot_id,
                attempt_number,
                authority_digest,
            } => {
                validate_digest("incident_reconciliation_digest", reconciliation_digest)?;
                validate_text("incident_intent_id", intent_id)?;
                validate_digest("incident_intent_digest", intent_digest)?;
                validate_digest("incident_effect_slot_id", effect_slot_id)?;
                validate_positive("incident_attempt_number", *attempt_number)?;
                validate_digest("incident_authority_digest", authority_digest)
            }
        }
    }

    fn target_state(
        &self,
        source: ClearingRoundLifecycleStateV1,
    ) -> Result<ClearingRoundLifecycleStateV1, ClearingError> {
        match (source, self) {
            (ClearingRoundLifecycleStateV1::Reserved, Self::Propose { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Proposed)
            }
            (ClearingRoundLifecycleStateV1::Proposed, Self::BeginFinalization { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Finalizing)
            }
            (ClearingRoundLifecycleStateV1::Finalizing, Self::Finalize { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Finalized)
            }
            (
                ClearingRoundLifecycleStateV1::Reserved | ClearingRoundLifecycleStateV1::Proposed,
                Self::BeginAbort {
                    frost_burn_checkpoint_digest: None,
                    ..
                },
            ) => Ok(ClearingRoundLifecycleStateV1::Aborting),
            (
                ClearingRoundLifecycleStateV1::Finalizing,
                Self::BeginAbort {
                    frost_burn_checkpoint_digest: Some(_),
                    ..
                },
            ) => Ok(ClearingRoundLifecycleStateV1::Aborting),
            (ClearingRoundLifecycleStateV1::Aborting, Self::Abort { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Aborted)
            }
            (
                ClearingRoundLifecycleStateV1::Finalized
                | ClearingRoundLifecycleStateV1::Dispatching
                | ClearingRoundLifecycleStateV1::Reconciling,
                Self::BeginDispatch { .. },
            ) => Ok(ClearingRoundLifecycleStateV1::Dispatching),
            (ClearingRoundLifecycleStateV1::Incident, Self::BeginDispatch { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Incident)
            }
            (
                ClearingRoundLifecycleStateV1::Dispatching
                | ClearingRoundLifecycleStateV1::Reconciling,
                Self::BeginReconciliation { .. },
            ) => Ok(ClearingRoundLifecycleStateV1::Reconciling),
            (ClearingRoundLifecycleStateV1::Incident, Self::BeginReconciliation { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Incident)
            }
            (
                ClearingRoundLifecycleStateV1::Dispatching
                | ClearingRoundLifecycleStateV1::Reconciling,
                Self::Satisfy { .. },
            ) => Ok(ClearingRoundLifecycleStateV1::Satisfied),
            (ClearingRoundLifecycleStateV1::Incident, Self::Satisfy { .. }) => {
                Ok(ClearingRoundLifecycleStateV1::Satisfied)
            }
            (
                ClearingRoundLifecycleStateV1::Dispatching
                | ClearingRoundLifecycleStateV1::Reconciling,
                Self::Incident { .. },
            ) => Ok(ClearingRoundLifecycleStateV1::Incident),
            _ => Err(ClearingError::IllegalLifecycleTransition),
        }
    }

    fn frost(&self) -> Option<&EconomicFrostBindingV1> {
        match self {
            Self::Finalize { frost, .. } => Some(frost),
            _ => None,
        }
    }

    fn releases_reservations(&self) -> bool {
        matches!(self, Self::Abort { .. })
    }

    fn satisfies_reservations(&self) -> bool {
        matches!(self, Self::Satisfy { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingReservationHeadBindingV1 {
    pub source_sequence: u64,
    pub resource_key: EconomicResourceKeyV1,
    pub expected_head_digest: String,
    pub expected_resource_version: u64,
    pub expected_lifecycle_fence: u64,
    pub atom: ObligationAtomV1,
    pub disposition: ObligationDispositionRecordV1,
}

impl ClearingReservationHeadBindingV1 {
    fn validate(&self, round_id: &str, scope_id: &str) -> Result<(), ClearingError> {
        validate_positive("source_sequence", self.source_sequence)?;
        self.resource_key
            .validate()
            .map_err(|_| ClearingError::InvalidField("obligation_resource_key"))?;
        validate_digest(
            "expected_obligation_head_digest",
            &self.expected_head_digest,
        )?;
        validate_positive(
            "expected_obligation_resource_version",
            self.expected_resource_version,
        )?;
        validate_positive(
            "expected_obligation_lifecycle_fence",
            self.expected_lifecycle_fence,
        )?;
        self.atom.validate()?;
        self.disposition.validate_against(&self.atom)?;
        if self.resource_key.resource_family != CLEARING_OBLIGATION_RESOURCE_FAMILY
            || self.resource_key.scope_id != scope_id
            || self.resource_key.resource_id != self.atom.obligation_id()
            || !matches!(
                self.disposition.disposition(),
                ObligationDispositionV1::ClearingReserved { round_id: reserved } if reserved == round_id
            )
        {
            return Err(ClearingError::InvalidField(
                "obligation_reservation_binding",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClearingRoundTransitionProofV1 {
    pub schema: String,
    pub round_id: String,
    pub governance_scope_id: String,
    pub round_core_digest: String,
    pub input_manifest_digest: String,
    pub source_state: ClearingRoundLifecycleStateV1,
    pub target_state: ClearingRoundLifecycleStateV1,
    pub source_round_head_digest: String,
    pub source_round_version: u64,
    pub source_round_fence: u64,
    pub next_round_version: u64,
    pub next_round_fence: u64,
    pub trusted_clock_high_water: u64,
    pub reservation_root: String,
    pub reservation_count: u64,
    pub reservation_head_root: String,
    pub reservations: Vec<ClearingReservationHeadBindingV1>,
    pub transition: ClearingRoundTransitionV1,
}

impl ClearingRoundTransitionProofV1 {
    pub fn validate(&self) -> Result<(), ClearingError> {
        if self.schema != CLEARING_ROUND_TRANSITION_PROOF_SCHEMA {
            return Err(ClearingError::InvalidField("round_transition_proof_schema"));
        }
        validate_text("round_id", &self.round_id)?;
        validate_text("governance_scope_id", &self.governance_scope_id)?;
        validate_digest("round_core_digest", &self.round_core_digest)?;
        validate_digest("input_manifest_digest", &self.input_manifest_digest)?;
        validate_digest("source_round_head_digest", &self.source_round_head_digest)?;
        validate_positive("source_round_version", self.source_round_version)?;
        validate_positive("source_round_fence", self.source_round_fence)?;
        validate_positive("next_round_version", self.next_round_version)?;
        validate_positive("next_round_fence", self.next_round_fence)?;
        validate_positive(
            "transition_trusted_clock_high_water",
            self.trusted_clock_high_water,
        )?;
        validate_digest("reservation_root", &self.reservation_root)?;
        validate_positive("reservation_count", self.reservation_count)?;
        validate_digest("reservation_head_root", &self.reservation_head_root)?;
        self.transition.validate()?;
        let target_matches = match self.transition.target_state(self.source_state) {
            Ok(target) => target == self.target_state,
            Err(ClearingError::IllegalLifecycleTransition) => {
                self.source_state == ClearingRoundLifecycleStateV1::Finalized
                    && self.target_state == ClearingRoundLifecycleStateV1::Satisfied
                    && matches!(self.transition, ClearingRoundTransitionV1::Satisfy { .. })
            }
            Err(error) => return Err(error),
        };
        if !target_matches
            || self.next_round_version
                != self
                    .source_round_version
                    .checked_add(1)
                    .ok_or(ClearingError::ArithmeticOverflow)?
            || self.next_round_fence
                != self
                    .source_round_fence
                    .checked_add(1)
                    .ok_or(ClearingError::ArithmeticOverflow)?
            || self.next_round_version != self.next_round_fence
            || self.reservations.len() + 2 > MAX_ECONOMIC_TRANSITIONS
            || usize::try_from(self.reservation_count)
                .map_err(|_| ClearingError::ArithmeticOverflow)?
                != self.reservations.len()
        {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        let mut resource_keys = BTreeSet::new();
        let mut sequences = BTreeSet::new();
        if !self
            .reservations
            .windows(2)
            .all(|pair| pair[0].resource_key < pair[1].resource_key)
        {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        for reservation in &self.reservations {
            reservation.validate(&self.round_id, &self.governance_scope_id)?;
            if !resource_keys.insert(reservation.resource_key.clone())
                || !sequences.insert(reservation.source_sequence)
            {
                return Err(ClearingError::IncompleteLifecycleProjection);
            }
        }
        if reservation_root(&self.reservations)? != self.reservation_root
            || reservation_head_root(&self.reservations)? != self.reservation_head_root
        {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ClearingError> {
        self.validate()?;
        domain_digest(ROUND_TRANSITION_PROOF_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchoredClearingObligationV1 {
    pub input: ClearingObligationInputV1,
    pub head: EconomicResourceHeadV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingLifecycleProjectionV1 {
    proof: ClearingRoundTransitionProofV1,
    transitions: Vec<EconomicStateTransitionV1>,
    effect_slots: Vec<EconomicEffectSlotV1>,
    request_replays: Vec<EconomicRequestReplayV1>,
    operation_id: Option<String>,
}

impl ClearingLifecycleProjectionV1 {
    #[must_use]
    pub fn proof(&self) -> &ClearingRoundTransitionProofV1 {
        &self.proof
    }

    #[must_use]
    pub fn transitions(&self) -> &[EconomicStateTransitionV1] {
        &self.transitions
    }

    #[must_use]
    pub fn effect_slots(&self) -> &[EconomicEffectSlotV1] {
        &self.effect_slots
    }

    #[must_use]
    pub fn request_replays(&self) -> &[EconomicRequestReplayV1] {
        &self.request_replays
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }
}

pub fn compose_clearing_lifecycle_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    transition: ClearingRoundTransitionV1,
    trusted_clock_high_water: u64,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    if matches!(
        transition,
        ClearingRoundTransitionV1::BeginDispatch { .. }
            | ClearingRoundTransitionV1::BeginReconciliation { .. }
            | ClearingRoundTransitionV1::Satisfy { .. }
            | ClearingRoundTransitionV1::Incident { .. }
    ) {
        return Err(ClearingError::IllegalLifecycleTransition);
    }
    compose_lifecycle_transition(
        current_round_head,
        reservations,
        transition,
        trusted_clock_high_water,
    )
}

fn compose_lifecycle_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    transition: ClearingRoundTransitionV1,
    trusted_clock_high_water: u64,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    compose_lifecycle_transition_inner(
        current_round_head,
        reservations,
        transition,
        trusted_clock_high_water,
        false,
    )
}

fn compose_zero_intent_lifecycle_transition(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    transition: ClearingRoundTransitionV1,
    trusted_clock_high_water: u64,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    compose_lifecycle_transition_inner(
        current_round_head,
        reservations,
        transition,
        trusted_clock_high_water,
        true,
    )
}

fn compose_lifecycle_transition_inner(
    current_round_head: &EconomicResourceHeadV1,
    reservations: &[AnchoredClearingObligationV1],
    transition: ClearingRoundTransitionV1,
    trusted_clock_high_water: u64,
    verified_zero_intent: bool,
) -> Result<ClearingLifecycleProjectionV1, ClearingError> {
    current_round_head
        .validate()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let current_record: ClearingRoundLifecycleRecordV1 = decode_inline(current_round_head)?;
    current_record.validate()?;
    validate_round_head(current_round_head, &current_record)?;
    validate_positive("trusted_clock_high_water", trusted_clock_high_water)?;
    if trusted_clock_high_water < current_round_head.trusted_clock_high_water {
        return Err(ClearingError::InvalidField("trusted_clock_high_water"));
    }
    let mut bindings = reservations
        .iter()
        .map(|reservation| reservation_binding(&current_record, reservation))
        .collect::<Result<Vec<_>, _>>()?;
    bindings.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    let source_digest = current_round_head
        .digest()
        .map_err(|_| ClearingError::InvalidField("current_round_head"))?;
    let target_state = if verified_zero_intent
        && current_record.state == ClearingRoundLifecycleStateV1::Finalized
        && matches!(transition, ClearingRoundTransitionV1::Satisfy { .. })
    {
        ClearingRoundLifecycleStateV1::Satisfied
    } else {
        transition.target_state(current_record.state)?
    };
    let next_round_version = current_record
        .row_version
        .checked_add(1)
        .ok_or(ClearingError::ArithmeticOverflow)?;
    let proof = ClearingRoundTransitionProofV1 {
        schema: CLEARING_ROUND_TRANSITION_PROOF_SCHEMA.to_owned(),
        round_id: current_record.round_id.clone(),
        governance_scope_id: current_record.governance_scope_id.clone(),
        round_core_digest: current_record.round_core_digest.clone(),
        input_manifest_digest: current_record.input_manifest_digest.clone(),
        source_state: current_record.state,
        target_state,
        source_round_head_digest: source_digest,
        source_round_version: current_record.row_version,
        source_round_fence: current_record.fence,
        next_round_version,
        next_round_fence: next_round_version,
        trusted_clock_high_water,
        reservation_root: current_record.reservation_root.clone(),
        reservation_count: current_record.reservation_count,
        reservation_head_root: reservation_head_root(&bindings)?,
        reservations: bindings,
        transition,
    };
    proof.validate()?;
    let proof_digest = proof.digest()?;
    let next_record = if verified_zero_intent {
        current_record.advance_zero_intent(&proof.transition, proof_digest.clone())?
    } else {
        current_record.advance(&proof.transition, proof_digest.clone())?
    };
    let frost = proof.transition.frost().cloned();
    let mut transitions = Vec::with_capacity(proof.reservations.len() + 1);
    transitions.push(EconomicStateTransitionV1 {
        resource_key: current_round_head.resource_key.clone(),
        expected_head_digest: Some(proof.source_round_head_digest.clone()),
        next_head: next_round_head(
            current_round_head,
            &next_record,
            frost.clone(),
            trusted_clock_high_water,
        )?,
        transition_proof_digest: proof_digest.clone(),
        prepared_effect: None,
    });
    for binding in &proof.reservations {
        let current = reservations
            .iter()
            .find(|reservation| reservation.head.resource_key == binding.resource_key)
            .ok_or(ClearingError::IncompleteLifecycleProjection)?;
        let next_head = if proof.transition.releases_reservations() {
            released_obligation_head(
                current,
                &proof.transition,
                frost.clone(),
                trusted_clock_high_water,
            )?
        } else if proof.transition.satisfies_reservations() {
            satisfied_obligation_head(
                current,
                &proof.transition,
                frost.clone(),
                trusted_clock_high_water,
            )?
        } else {
            preserved_obligation_head(&current.head, frost.clone(), trusted_clock_high_water)?
        };
        transitions.push(EconomicStateTransitionV1 {
            resource_key: binding.resource_key.clone(),
            expected_head_digest: Some(binding.expected_head_digest.clone()),
            next_head,
            transition_proof_digest: proof_digest.clone(),
            prepared_effect: None,
        });
    }
    transitions.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    Ok(ClearingLifecycleProjectionV1 {
        proof,
        transitions,
        effect_slots: Vec::new(),
        request_replays: Vec::new(),
        operation_id: None,
    })
}

pub trait ClearingLifecycleProofResolver: Send + Sync {
    fn resolve(&self, proof_digest: &str) -> Result<ClearingRoundTransitionProofV1, ClearingError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearingLifecycleAuthorityVerificationV1 {
    authorization: EconomicTransitionAuthorizationV1,
    expected_reconciliation_slot: Option<EconomicEffectSlotV1>,
    verified_zero_intent: bool,
}

impl ClearingLifecycleAuthorityVerificationV1 {
    #[must_use]
    pub const fn direct(authorization: EconomicTransitionAuthorizationV1) -> Self {
        Self {
            authorization,
            expected_reconciliation_slot: None,
            verified_zero_intent: false,
        }
    }

    #[must_use]
    pub const fn zero_intent(authorization: EconomicTransitionAuthorizationV1) -> Self {
        Self {
            authorization,
            expected_reconciliation_slot: None,
            verified_zero_intent: true,
        }
    }

    #[must_use]
    pub const fn reconciled(
        authorization: EconomicTransitionAuthorizationV1,
        expected_reconciliation_slot: EconomicEffectSlotV1,
    ) -> Self {
        Self {
            authorization,
            expected_reconciliation_slot: Some(expected_reconciliation_slot),
            verified_zero_intent: false,
        }
    }

    #[must_use]
    pub const fn authorization(&self) -> &EconomicTransitionAuthorizationV1 {
        &self.authorization
    }

    #[must_use]
    pub const fn expected_reconciliation_slot(&self) -> Option<&EconomicEffectSlotV1> {
        self.expected_reconciliation_slot.as_ref()
    }

    #[must_use]
    pub const fn verified_zero_intent(&self) -> bool {
        self.verified_zero_intent
    }
}

pub trait ClearingLifecycleAuthorityVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &ClearingRoundTransitionProofV1,
    ) -> Result<ClearingLifecycleAuthorityVerificationV1, ClearingError>;
}

pub struct ClearingLifecycleBatchVerifier {
    proof_resolver: Arc<dyn ClearingLifecycleProofResolver>,
    authority_verifier: Arc<dyn ClearingLifecycleAuthorityVerifier>,
}

impl ClearingLifecycleBatchVerifier {
    #[must_use]
    pub fn new(
        proof_resolver: Arc<dyn ClearingLifecycleProofResolver>,
        authority_verifier: Arc<dyn ClearingLifecycleAuthorityVerifier>,
    ) -> Self {
        Self {
            proof_resolver,
            authority_verifier,
        }
    }
}

impl EconomicTransitionProofVerifier for ClearingLifecycleBatchVerifier {
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
        let round_transition = batch
            .transitions
            .iter()
            .find(|transition| {
                transition.resource_key.resource_family == CLEARING_ROUND_RESOURCE_FAMILY
            })
            .ok_or_else(|| rejected_batch(batch))?;
        let proof = self
            .proof_resolver
            .resolve(&round_transition.transition_proof_digest)
            .map_err(|_| rejected_batch(batch))?;
        let verified = self
            .authority_verifier
            .verify(&proof)
            .map_err(|_| rejected_batch(batch))?;
        let reconciliation = matches!(
            proof.transition,
            ClearingRoundTransitionV1::BeginReconciliation { .. }
                | ClearingRoundTransitionV1::Incident { .. }
        );
        if reconciliation && verified.expected_reconciliation_slot().is_none() {
            return Err(rejected_batch(batch));
        }
        verify_projection(
            current,
            batch,
            &proof,
            verified.expected_reconciliation_slot(),
            verified.verified_zero_intent(),
        )
        .map_err(|_| rejected_batch(batch))?;
        Ok(vec![
            verified.authorization().clone();
            batch.transitions.len()
        ])
    }
}

pub fn clearing_reservation_root(
    obligations: &[ClearingObligationInputV1],
) -> Result<String, ClearingError> {
    let mut obligations = obligations.iter().collect::<Vec<_>>();
    obligations.sort_by_key(|obligation| obligation.source_sequence);
    let obligation_ids = obligations
        .iter()
        .map(|obligation| obligation.atom.obligation_id())
        .collect::<BTreeSet<_>>();
    if obligations.is_empty()
        || obligations.len() + 2 > MAX_ECONOMIC_TRANSITIONS
        || obligation_ids.len() != obligations.len()
        || !obligations
            .windows(2)
            .all(|pair| pair[0].source_sequence < pair[1].source_sequence)
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let digests = obligations
        .iter()
        .map(|obligation| {
            obligation
                .disposition
                .digest(&obligation.atom)
                .map_err(ClearingError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    domain_digest(RESERVATION_ROOT_DOMAIN, &digests)
}

fn reservation_binding(
    record: &ClearingRoundLifecycleRecordV1,
    reservation: &AnchoredClearingObligationV1,
) -> Result<ClearingReservationHeadBindingV1, ClearingError> {
    reservation
        .head
        .validate()
        .map_err(|_| ClearingError::InvalidField("obligation_head"))?;
    reservation
        .input
        .disposition
        .validate_against(&reservation.input.atom)?;
    let expected_state = serde_json::to_value(&reservation.input.disposition)
        .map_err(|error| ClearingError::Canonicalization(error.to_string()))?;
    if reservation.head.resource_key.resource_family != CLEARING_OBLIGATION_RESOURCE_FAMILY
        || reservation.head.resource_key.scope_id != record.governance_scope_id
        || reservation.head.resource_key.resource_id != reservation.input.atom.obligation_id()
        || reservation.head.resource_version < reservation.input.disposition.version()
        || reservation.head.lifecycle_state != "clearing_reserved"
        || reservation.head.lifecycle_fence != reservation.input.disposition.lifecycle_fence()
        || !matches!(&reservation.head.state, EconomicContentV1::Inline { value } if value == &expected_state)
        || reservation.head.operation_id.is_some()
        || reservation.head.effect_idempotency_key.is_some()
        || reservation.head.terminal_result.is_some()
        || !matches!(
            reservation.input.disposition.disposition(),
            ObligationDispositionV1::ClearingReserved { round_id } if round_id == &record.round_id
        )
    {
        return Err(ClearingError::InvalidField("obligation_head"));
    }
    Ok(ClearingReservationHeadBindingV1 {
        source_sequence: reservation.input.source_sequence,
        resource_key: reservation.head.resource_key.clone(),
        expected_head_digest: reservation
            .head
            .digest()
            .map_err(|_| ClearingError::InvalidField("obligation_head"))?,
        expected_resource_version: reservation.head.resource_version,
        expected_lifecycle_fence: reservation.head.lifecycle_fence,
        atom: reservation.input.atom.clone(),
        disposition: reservation.input.disposition.clone(),
    })
}

fn next_round_head(
    current: &EconomicResourceHeadV1,
    record: &ClearingRoundLifecycleRecordV1,
    frost: Option<EconomicFrostBindingV1>,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, ClearingError> {
    let state = inline_content(record)?;
    let next = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.anchor_id.clone(),
        namespace: current.namespace.clone(),
        resource_key: current.resource_key.clone(),
        head_version: increment(current.head_version)?,
        resource_version: record.row_version,
        lifecycle_fence: record.fence,
        lifecycle_state: record.state.as_str().to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ClearingError::InvalidField("round_state"))?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost,
        terminal_result: None,
        trusted_clock_high_water,
        predecessor_digest: Some(
            current
                .digest()
                .map_err(|_| ClearingError::InvalidField("current_round_head"))?,
        ),
    };
    current
        .validate_successor(&next)
        .map_err(|_| ClearingError::InvalidField("next_round_head"))?;
    Ok(next)
}

fn preserved_obligation_head(
    current: &EconomicResourceHeadV1,
    frost: Option<EconomicFrostBindingV1>,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, ClearingError> {
    let mut next = current.clone();
    next.head_version = increment(current.head_version)?;
    next.resource_version = increment(current.resource_version)?;
    next.predecessor_digest = Some(
        current
            .digest()
            .map_err(|_| ClearingError::InvalidField("obligation_head"))?,
    );
    next.frost = frost;
    next.trusted_clock_high_water = trusted_clock_high_water;
    current
        .validate_successor(&next)
        .map_err(|_| ClearingError::InvalidField("next_obligation_head"))?;
    Ok(next)
}

fn released_obligation_head(
    current: &AnchoredClearingObligationV1,
    transition: &ClearingRoundTransitionV1,
    frost: Option<EconomicFrostBindingV1>,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, ClearingError> {
    let ClearingRoundTransitionV1::Abort {
        abort_digest,
        zero_dispatch_proof_digest,
        authority_digest,
    } = transition
    else {
        return Err(ClearingError::IllegalLifecycleTransition);
    };
    let round_id = match current.input.disposition.disposition() {
        ObligationDispositionV1::ClearingReserved { round_id } => round_id.clone(),
        _ => return Err(ClearingError::InvalidField("obligation_disposition")),
    };
    let disposition = current.input.disposition.advance(
        &current.input.atom,
        ObligationDispositionTransitionV1::ReleaseClearing {
            round_id,
            abort_digest: abort_digest.clone(),
            zero_dispatch_proof_digest: zero_dispatch_proof_digest.clone(),
            authority_digest: authority_digest.clone(),
        },
    )?;
    let state = inline_content(&disposition)?;
    let next = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.head.anchor_id.clone(),
        namespace: current.head.namespace.clone(),
        resource_key: current.head.resource_key.clone(),
        head_version: increment(current.head.head_version)?,
        resource_version: increment(current.head.resource_version)?,
        lifecycle_fence: disposition.lifecycle_fence(),
        lifecycle_state: "per_call".to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ClearingError::InvalidField("obligation_disposition"))?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost,
        terminal_result: None,
        trusted_clock_high_water,
        predecessor_digest: Some(
            current
                .head
                .digest()
                .map_err(|_| ClearingError::InvalidField("obligation_head"))?,
        ),
    };
    current
        .head
        .validate_successor(&next)
        .map_err(|_| ClearingError::InvalidField("next_obligation_head"))?;
    Ok(next)
}

fn satisfied_obligation_head(
    current: &AnchoredClearingObligationV1,
    transition: &ClearingRoundTransitionV1,
    frost: Option<EconomicFrostBindingV1>,
    trusted_clock_high_water: u64,
) -> Result<EconomicResourceHeadV1, ClearingError> {
    let ClearingRoundTransitionV1::Satisfy {
        satisfaction_digest,
        authority_digest,
    } = transition
    else {
        return Err(ClearingError::IllegalLifecycleTransition);
    };
    let round_id = match current.input.disposition.disposition() {
        ObligationDispositionV1::ClearingReserved { round_id } => round_id.clone(),
        _ => return Err(ClearingError::InvalidField("obligation_disposition")),
    };
    let disposition = current.input.disposition.advance(
        &current.input.atom,
        ObligationDispositionTransitionV1::SatisfyClearing {
            round_id,
            satisfaction_digest: satisfaction_digest.clone(),
            authority_digest: authority_digest.clone(),
        },
    )?;
    let state = inline_content(&disposition)?;
    let next = EconomicResourceHeadV1 {
        schema: CHIO_ECONOMIC_RESOURCE_HEAD_SCHEMA.to_owned(),
        anchor_id: current.head.anchor_id.clone(),
        namespace: current.head.namespace.clone(),
        resource_key: current.head.resource_key.clone(),
        head_version: increment(current.head.head_version)?,
        resource_version: increment(current.head.resource_version)?,
        lifecycle_fence: disposition.lifecycle_fence(),
        lifecycle_state: "clearing_satisfied".to_owned(),
        state_digest: state
            .digest()
            .map_err(|_| ClearingError::InvalidField("obligation_disposition"))?,
        state,
        operation_id: None,
        effect_idempotency_key: None,
        frost,
        terminal_result: None,
        trusted_clock_high_water,
        predecessor_digest: Some(
            current
                .head
                .digest()
                .map_err(|_| ClearingError::InvalidField("obligation_head"))?,
        ),
    };
    current
        .head
        .validate_successor(&next)
        .map_err(|_| ClearingError::InvalidField("next_obligation_head"))?;
    Ok(next)
}

fn verify_projection(
    current: &VerifiedEconomicStateView,
    batch: &EconomicStateBatchV1,
    proof: &ClearingRoundTransitionProofV1,
    expected_reconciliation_slot: Option<&EconomicEffectSlotV1>,
    verified_zero_intent: bool,
) -> Result<(), ClearingError> {
    proof.validate()?;
    let proof_digest = proof.digest()?;
    let dispatch = matches!(
        proof.transition,
        ClearingRoundTransitionV1::BeginDispatch { .. }
    );
    let reconciliation = matches!(
        proof.transition,
        ClearingRoundTransitionV1::BeginReconciliation { .. }
            | ClearingRoundTransitionV1::Incident { .. }
    );
    let expected_transition_count = proof
        .reservations
        .len()
        .checked_add(if dispatch || reconciliation { 2 } else { 1 })
        .ok_or(ClearingError::ArithmeticOverflow)?;
    if batch.transitions.len() != expected_transition_count
        || batch.transitions.iter().any(|transition| {
            transition.transition_proof_digest != proof_digest
                || transition.next_head.trusted_clock_high_water != proof.trusted_clock_high_water
        })
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let round_key = EconomicResourceKeyV1 {
        resource_family: CLEARING_ROUND_RESOURCE_FAMILY.to_owned(),
        scope_id: proof.governance_scope_id.clone(),
        resource_id: proof.round_id.clone(),
    };
    let round_transition = batch
        .transitions
        .iter()
        .find(|transition| transition.resource_key == round_key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    let current_round = current
        .view()
        .head(&round_key)
        .ok_or(ClearingError::IncompleteLifecycleProjection)?;
    if current_round
        .digest()
        .map_err(|_| ClearingError::IncompleteLifecycleProjection)?
        != proof.source_round_head_digest
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let source_record: ClearingRoundLifecycleRecordV1 = decode_inline(current_round)?;
    validate_round_head(current_round, &source_record)?;
    if source_record.round_id != proof.round_id
        || source_record.governance_scope_id != proof.governance_scope_id
        || source_record.round_core_digest != proof.round_core_digest
        || source_record.input_manifest_digest != proof.input_manifest_digest
        || source_record.state != proof.source_state
        || source_record.row_version != proof.source_round_version
        || source_record.fence != proof.source_round_fence
        || source_record.reservation_root != proof.reservation_root
        || source_record.reservation_count != proof.reservation_count
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    let expected_next = if verified_zero_intent {
        source_record.advance_zero_intent(&proof.transition, proof_digest.clone())?
    } else {
        source_record.advance(&proof.transition, proof_digest.clone())?
    };
    let actual_next: ClearingRoundLifecycleRecordV1 = decode_inline(&round_transition.next_head)?;
    if actual_next != expected_next
        || round_transition.expected_head_digest.as_deref()
            != Some(proof.source_round_head_digest.as_str())
        || validate_round_head(&round_transition.next_head, &actual_next).is_err()
        || round_transition.next_head.frost.as_ref() != proof.transition.frost()
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    if dispatch {
        dispatch::verify_dispatch_projection(
            batch,
            proof,
            current_round,
            round_transition,
            &source_record,
        )?;
    } else if reconciliation {
        reconciliation::verify_reconciliation_projection(
            current,
            batch,
            proof,
            expected_reconciliation_slot,
        )?;
    } else if !batch.effect_slots.is_empty()
        || !batch.request_replays.is_empty()
        || batch
            .transitions
            .iter()
            .any(|transition| transition.prepared_effect.is_some())
    {
        return Err(ClearingError::IncompleteLifecycleProjection);
    }
    for reservation in &proof.reservations {
        let transition = batch
            .transitions
            .iter()
            .find(|transition| transition.resource_key == reservation.resource_key)
            .ok_or(ClearingError::IncompleteLifecycleProjection)?;
        let current_head = current
            .view()
            .head(&reservation.resource_key)
            .ok_or(ClearingError::IncompleteLifecycleProjection)?;
        if current_head
            .digest()
            .map_err(|_| ClearingError::IncompleteLifecycleProjection)?
            != reservation.expected_head_digest
            || current_head.resource_version != reservation.expected_resource_version
            || current_head.lifecycle_fence != reservation.expected_lifecycle_fence
            || transition.expected_head_digest.as_deref()
                != Some(reservation.expected_head_digest.as_str())
        {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        let expected = AnchoredClearingObligationV1 {
            input: ClearingObligationInputV1 {
                source_sequence: reservation.source_sequence,
                atom: reservation.atom.clone(),
                disposition: reservation.disposition.clone(),
            },
            head: current_head.clone(),
        };
        if reservation_binding(&source_record, &expected)? != *reservation {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
        let expected_next_head = if proof.transition.releases_reservations() {
            released_obligation_head(
                &expected,
                &proof.transition,
                proof.transition.frost().cloned(),
                transition.next_head.trusted_clock_high_water,
            )?
        } else if proof.transition.satisfies_reservations() {
            satisfied_obligation_head(
                &expected,
                &proof.transition,
                proof.transition.frost().cloned(),
                transition.next_head.trusted_clock_high_water,
            )?
        } else {
            preserved_obligation_head(
                current_head,
                proof.transition.frost().cloned(),
                transition.next_head.trusted_clock_high_water,
            )?
        };
        if transition.next_head != expected_next_head {
            return Err(ClearingError::IncompleteLifecycleProjection);
        }
    }
    Ok(())
}

pub(super) fn decode_inline<T>(head: &EconomicResourceHeadV1) -> Result<T, ClearingError>
where
    T: for<'de> Deserialize<'de>,
{
    let EconomicContentV1::Inline { value } = &head.state else {
        return Err(ClearingError::InvalidField("inline_state"));
    };
    serde_json::from_value(value.clone())
        .map_err(|error| ClearingError::Canonicalization(error.to_string()))
}

fn inline_content(value: &impl Serialize) -> Result<EconomicContentV1, ClearingError> {
    Ok(EconomicContentV1::Inline {
        value: serde_json::to_value(value)
            .map_err(|error| ClearingError::Canonicalization(error.to_string()))?,
    })
}

fn increment(value: u64) -> Result<u64, ClearingError> {
    value
        .checked_add(1)
        .filter(|next| *next <= I_JSON_MAX_SAFE_INTEGER)
        .ok_or(ClearingError::ArithmeticOverflow)
}

fn validate_optional_digest(field: &'static str, value: Option<&str>) -> Result<(), ClearingError> {
    value.map_or(Ok(()), |value| validate_digest(field, value))
}

fn rejected_batch(batch: &EconomicStateBatchV1) -> EconomicStateAnchorError {
    EconomicStateAnchorError::TransitionProofRejected(
        batch
            .transitions
            .first()
            .map(|transition| transition.resource_key.clone())
            .unwrap_or(EconomicResourceKeyV1 {
                resource_family: CLEARING_ROUND_RESOURCE_FAMILY.to_owned(),
                scope_id: "invalid".to_owned(),
                resource_id: "invalid".to_owned(),
            }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_transition_count_rejects_input_padding_overflow() {
        assert!(matches!(
            checked_transition_count(u64::MAX),
            Err(ClearingError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn finalized_round_cannot_satisfy_without_zero_intent_reconciliation() {
        let transition = ClearingRoundTransitionV1::Satisfy {
            satisfaction_digest: "0".repeat(64),
            authority_digest: "1".repeat(64),
        };

        assert!(matches!(
            transition.target_state(ClearingRoundLifecycleStateV1::Finalized),
            Err(ClearingError::IllegalLifecycleTransition)
        ));
    }
}
