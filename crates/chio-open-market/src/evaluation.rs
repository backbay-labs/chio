use serde::{Deserialize, Serialize};

use crate::authority::{
    ensure_open_market_evaluation_authority_signers, verify_signed_activation, verify_signed_case,
    verify_signed_charter, verify_signed_fee_schedule, verify_signed_listing,
    verify_signed_penalty,
};
use crate::capability::MonetaryAmount;
use crate::crypto::PublicKey;
use crate::evidence::{OpenMarketFinding, OpenMarketFindingCode};
use crate::fee_schedule::{
    OpenMarketBondRequirement, OpenMarketFeeScheduleArtifact, SignedOpenMarketFeeSchedule,
};
use crate::governance::generic::{
    GenericGovernanceCaseKind, GenericGovernanceCaseState, SignedGenericGovernanceCase,
    SignedGenericGovernanceCharter,
};
use crate::listing::{
    normalize_namespace, GenericRegistryPublisher, SignedGenericListing,
    SignedGenericTrustActivation,
};
use crate::penalty::{
    OpenMarketPenaltyAction, OpenMarketPenaltyEffectiveState, OpenMarketPenaltyState,
    SignedOpenMarketPenalty,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketPenaltyEvaluationRequest {
    pub fee_schedule: SignedOpenMarketFeeSchedule,
    pub listing: SignedGenericListing,
    pub current_publisher: GenericRegistryPublisher,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation: Option<SignedGenericTrustActivation>,
    pub charter: SignedGenericGovernanceCharter,
    pub case: SignedGenericGovernanceCase,
    pub penalty: SignedOpenMarketPenalty,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_penalty: Option<SignedOpenMarketPenalty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluated_at: Option<u64>,
}

impl OpenMarketPenaltyEvaluationRequest {
    pub fn validate(&self) -> Result<(), String> {
        self.listing.body.validate()?;
        self.current_publisher.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenMarketPenaltyEvaluation {
    pub listing_id: String,
    pub namespace: String,
    pub fee_schedule_id: String,
    pub charter_id: String,
    pub case_id: String,
    pub penalty_id: String,
    pub governing_operator_id: String,
    pub action: OpenMarketPenaltyAction,
    pub state: OpenMarketPenaltyState,
    pub effective_state: OpenMarketPenaltyEffectiveState,
    pub evaluated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publication_fee: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_fee: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub market_participation_fee: Option<MonetaryAmount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond_requirement: Option<OpenMarketBondRequirement>,
    pub blocks_admission: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<OpenMarketFinding>,
}

pub fn evaluate_open_market_penalty(
    request: &OpenMarketPenaltyEvaluationRequest,
    now: u64,
    trusted_local_operator_signer: &PublicKey,
) -> Result<OpenMarketPenaltyEvaluation, String> {
    evaluate_open_market_penalty_with_trusted_signers(
        request,
        now,
        std::slice::from_ref(trusted_local_operator_signer),
    )
}

pub fn evaluate_open_market_penalty_with_trusted_signers(
    request: &OpenMarketPenaltyEvaluationRequest,
    now: u64,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<OpenMarketPenaltyEvaluation, String> {
    request.validate()?;
    let evaluated_at = request.evaluated_at.unwrap_or(now);

    if let Err(error) = verify_signed_listing(&request.listing, "penalty listing") {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::ListingUnverifiable,
            &error,
            None,
        ));
    }
    if let Err(error) = verify_signed_fee_schedule(&request.fee_schedule) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleUnverifiable,
            &error,
            None,
        ));
    }
    if let Some(activation) = request.activation.as_ref() {
        if let Err(error) = verify_signed_activation(activation) {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationUnverifiable,
                &error,
                Some(&request.fee_schedule.body),
            ));
        }
    }
    if let Err(error) = verify_signed_charter(&request.charter) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }
    if let Err(error) = verify_signed_case(&request.case) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }
    if let Err(error) = verify_signed_penalty(&request.penalty) {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyUnverifiable,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }
    if let Some(prior_penalty) = request.prior_penalty.as_ref() {
        if let Err(error) = verify_signed_penalty(prior_penalty) {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::PriorPenaltyInvalid,
                &error,
                Some(&request.fee_schedule.body),
            ));
        }
    }
    if let Err(error) =
        ensure_open_market_evaluation_authority_signers(request, trusted_local_operator_signers)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            &error,
            Some(&request.fee_schedule.body),
        ));
    }

    let listing = &request.listing.body;
    let fee_schedule = &request.fee_schedule.body;
    let charter = &request.charter.body;
    let governance_case = &request.case.body;
    let penalty = &request.penalty.body;
    let namespace = normalize_namespace(&listing.namespace);

    if let Some(activation) = request.activation.as_ref() {
        if activation.body.local_operator_id != fee_schedule.governing_operator_id {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMismatch,
                "open-market penalties require a trust activation issued by the governing operator",
                Some(fee_schedule),
            ));
        }
    }

    if normalize_namespace(&fee_schedule.namespace) != namespace
        || normalize_namespace(&fee_schedule.scope.namespace) != namespace
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleScopeMismatch,
            "fee schedule namespace does not match the current listing namespace",
            Some(fee_schedule),
        ));
    }
    if normalize_namespace(&charter.authority_scope.namespace) != namespace
        || normalize_namespace(&governance_case.namespace) != namespace
        || normalize_namespace(&penalty.namespace) != namespace
        || governance_case.listing_id != listing.listing_id
        || penalty.listing_id != listing.listing_id
        || penalty.case_id != governance_case.case_id
        || penalty.charter_id != charter.charter_id
        || penalty.fee_schedule_id != fee_schedule.fee_schedule_id
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            "governance or penalty authority does not match the current listing, namespace, or fee schedule",
            Some(fee_schedule),
        ));
    }
    if fee_schedule.governing_operator_id != charter.governing_operator_id
        || fee_schedule.governing_operator_id != governance_case.governing_operator_id
        || fee_schedule.governing_operator_id != penalty.governing_operator_id
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseAuthorityInvalid,
            "fee schedule, governance, and penalty operators must match",
            Some(fee_schedule),
        ));
    }

    if fee_schedule
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleExpired,
            "open-market fee schedule has expired",
            Some(fee_schedule),
        ));
    }
    if charter
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
        || governance_case
            .expires_at
            .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::GovernanceCaseExpired,
            "governance authority has expired",
            Some(fee_schedule),
        ));
    }
    if penalty
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyExpired,
            "open-market penalty has expired",
            Some(fee_schedule),
        ));
    }
    if !fee_schedule.scope.allowed_listing_operator_ids.is_empty()
        && !fee_schedule
            .scope
            .allowed_listing_operator_ids
            .contains(&request.current_publisher.operator_id)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleScopeMismatch,
            "current listing publisher falls outside the fee schedule scope",
            Some(fee_schedule),
        ));
    }
    if !fee_schedule.scope.allowed_actor_kinds.is_empty()
        && !fee_schedule
            .scope
            .allowed_actor_kinds
            .contains(&listing.subject.actor_kind)
    {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::FeeScheduleScopeMismatch,
            "listing actor kind falls outside the fee schedule scope",
            Some(fee_schedule),
        ));
    }
    if !fee_schedule.scope.allowed_admission_classes.is_empty() {
        let Some(activation) = request.activation.as_ref() else {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMissing,
                "fee schedule requires an explicit trust activation class",
                Some(fee_schedule),
            ));
        };
        if governance_case.activation_id.as_deref() != Some(activation.body.activation_id.as_str())
            || penalty.activation_id.as_deref() != Some(activation.body.activation_id.as_str())
        {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMismatch,
                "governance case or penalty activation does not match the current trust activation",
                Some(fee_schedule),
            ));
        }
        if !fee_schedule
            .scope
            .allowed_admission_classes
            .contains(&activation.body.admission_class)
        {
            return Ok(open_market_failure(
                request,
                evaluated_at,
                OpenMarketFindingCode::ActivationMismatch,
                "trust activation admission class falls outside the fee schedule scope",
                Some(fee_schedule),
            ));
        }
    }

    let bond_requirement = fee_schedule
        .bond_requirements
        .iter()
        .find(|requirement| requirement.bond_class == penalty.bond_class)
        .cloned();
    let Some(bond_requirement) = bond_requirement else {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::BondRequirementMissing,
            "fee schedule does not define the required bond class for this penalty",
            Some(fee_schedule),
        ));
    };

    match penalty.action {
        OpenMarketPenaltyAction::HoldBond | OpenMarketPenaltyAction::SlashBond => {
            if !matches!(
                (governance_case.kind, governance_case.state),
                (
                    GenericGovernanceCaseKind::Sanction,
                    GenericGovernanceCaseState::Enforced
                )
            ) {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::GovernanceCaseKindInvalid,
                    "bond hold or slash requires an enforced sanction case",
                    Some(fee_schedule),
                ));
            }
            if matches!(penalty.action, OpenMarketPenaltyAction::SlashBond)
                && !bond_requirement.slashable
            {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::BondRequirementNotSlashable,
                    "selected bond requirement is not slashable",
                    Some(fee_schedule),
                ));
            }
        }
        OpenMarketPenaltyAction::ReverseSlash => {
            if !matches!(governance_case.kind, GenericGovernanceCaseKind::Appeal) {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::GovernanceCaseKindInvalid,
                    "reverse slash requires an appeal governance case",
                    Some(fee_schedule),
                ));
            }
            let Some(prior_penalty) = request.prior_penalty.as_ref() else {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::PriorPenaltyMissing,
                    "reverse slash requires prior_penalty",
                    Some(fee_schedule),
                ));
            };
            let Some(supersedes_penalty_id) = penalty.supersedes_penalty_id.as_deref() else {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::PriorPenaltyInvalid,
                    "reverse slash must reference the prior penalty id",
                    Some(fee_schedule),
                ));
            };
            if prior_penalty.body.penalty_id != supersedes_penalty_id
                || prior_penalty.body.listing_id != listing.listing_id
                || prior_penalty.body.fee_schedule_id != fee_schedule.fee_schedule_id
                || prior_penalty.body.bond_class != penalty.bond_class
                || !matches!(
                    prior_penalty.body.action,
                    OpenMarketPenaltyAction::HoldBond | OpenMarketPenaltyAction::SlashBond
                )
                || !matches!(prior_penalty.body.state, OpenMarketPenaltyState::Enforced)
            {
                return Ok(open_market_failure(
                    request,
                    evaluated_at,
                    OpenMarketFindingCode::PriorPenaltyInvalid,
                    "prior penalty does not match the reverse-slash target",
                    Some(fee_schedule),
                ));
            }
        }
    }

    if bond_requirement.required_amount.currency != penalty.penalty_amount.currency {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyCurrencyMismatch,
            "penalty currency must match the configured bond currency",
            Some(fee_schedule),
        ));
    }
    if penalty.penalty_amount.units > bond_requirement.required_amount.units {
        return Ok(open_market_failure(
            request,
            evaluated_at,
            OpenMarketFindingCode::PenaltyAmountExceedsBond,
            "penalty amount exceeds the configured bond requirement",
            Some(fee_schedule),
        ));
    }

    let (effective_state, blocks_admission) =
        open_market_effective_state(penalty.action, penalty.state);

    Ok(OpenMarketPenaltyEvaluation {
        listing_id: listing.listing_id.clone(),
        namespace,
        fee_schedule_id: fee_schedule.fee_schedule_id.clone(),
        charter_id: charter.charter_id.clone(),
        case_id: governance_case.case_id.clone(),
        penalty_id: penalty.penalty_id.clone(),
        governing_operator_id: penalty.governing_operator_id.clone(),
        action: penalty.action,
        state: penalty.state,
        effective_state,
        evaluated_at,
        publication_fee: Some(fee_schedule.publication_fee.clone()),
        dispute_fee: Some(fee_schedule.dispute_fee.clone()),
        market_participation_fee: Some(fee_schedule.market_participation_fee.clone()),
        bond_requirement: Some(bond_requirement),
        blocks_admission,
        findings: Vec::new(),
    })
}

fn open_market_effective_state(
    action: OpenMarketPenaltyAction,
    state: OpenMarketPenaltyState,
) -> (OpenMarketPenaltyEffectiveState, bool) {
    match state {
        OpenMarketPenaltyState::Proposed
        | OpenMarketPenaltyState::Denied
        | OpenMarketPenaltyState::Superseded => (OpenMarketPenaltyEffectiveState::Clear, false),
        OpenMarketPenaltyState::Reversed => (OpenMarketPenaltyEffectiveState::Reversed, false),
        OpenMarketPenaltyState::Enforced => match action {
            OpenMarketPenaltyAction::HoldBond => (OpenMarketPenaltyEffectiveState::BondHeld, true),
            OpenMarketPenaltyAction::SlashBond => {
                (OpenMarketPenaltyEffectiveState::BondSlashed, true)
            }
            OpenMarketPenaltyAction::ReverseSlash => {
                (OpenMarketPenaltyEffectiveState::Reversed, false)
            }
        },
    }
}

fn open_market_failure(
    request: &OpenMarketPenaltyEvaluationRequest,
    evaluated_at: u64,
    code: OpenMarketFindingCode,
    message: &str,
    fee_schedule: Option<&OpenMarketFeeScheduleArtifact>,
) -> OpenMarketPenaltyEvaluation {
    OpenMarketPenaltyEvaluation {
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        fee_schedule_id: request.penalty.body.fee_schedule_id.clone(),
        charter_id: request.penalty.body.charter_id.clone(),
        case_id: request.penalty.body.case_id.clone(),
        penalty_id: request.penalty.body.penalty_id.clone(),
        governing_operator_id: request.penalty.body.governing_operator_id.clone(),
        action: request.penalty.body.action,
        state: request.penalty.body.state,
        effective_state: OpenMarketPenaltyEffectiveState::Clear,
        evaluated_at,
        publication_fee: fee_schedule.map(|schedule| schedule.publication_fee.clone()),
        dispute_fee: fee_schedule.map(|schedule| schedule.dispute_fee.clone()),
        market_participation_fee: fee_schedule
            .map(|schedule| schedule.market_participation_fee.clone()),
        bond_requirement: None,
        blocks_admission: false,
        findings: vec![OpenMarketFinding {
            code,
            message: message.to_string(),
        }],
    }
}
