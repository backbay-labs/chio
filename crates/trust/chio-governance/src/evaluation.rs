use crate::generic::{
    GenericGovernanceCaseArtifact, GenericGovernanceCaseEvaluation,
    GenericGovernanceCaseEvaluationRequest, GenericGovernanceCaseKind, GenericGovernanceCaseState,
    GenericGovernanceEffectiveState, GenericGovernanceFinding, GenericGovernanceFindingCode,
};
use crate::listing::normalize_namespace;

pub fn evaluate_generic_governance_case(
    request: &GenericGovernanceCaseEvaluationRequest,
    now: u64,
) -> Result<GenericGovernanceCaseEvaluation, String> {
    request.validate()?;
    let evaluated_at = request.evaluated_at.unwrap_or(now);

    if !request
        .listing
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::ListingUnverifiable,
            "listing signature is invalid",
        ));
    }
    if !request
        .charter
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterUnverifiable,
            "governance charter signature is invalid",
        ));
    }
    if let Err(error) = request.charter.body.validate() {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterUnverifiable,
            &error,
        ));
    }
    if !request
        .case
        .verify_signature()
        .map_err(|error| error.to_string())?
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseUnverifiable,
            "governance case signature is invalid",
        ));
    }
    if let Err(error) = request.case.body.validate() {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseUnverifiable,
            &error,
        ));
    }
    if let Some(activation) = request.activation.as_ref() {
        if !activation
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationUnverifiable,
                "trust activation signature is invalid",
            ));
        }
        if let Err(error) = activation.body.validate() {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationUnverifiable,
                &error,
            ));
        }
    }
    if let Some(prior_case) = request.prior_case.as_ref() {
        if !prior_case
            .verify_signature()
            .map_err(|error| error.to_string())?
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::PriorCaseUnverifiable,
                "prior governance case signature is invalid",
            ));
        }
        if let Err(error) = prior_case.body.validate() {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::PriorCaseUnverifiable,
                &error,
            ));
        }
    }
    if let Some(activation) = request.activation.as_ref() {
        if activation.body.local_operator_id != request.charter.body.governing_operator_id {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationMismatch,
                "governance cases require a trust activation issued by the governing operator",
            ));
        }
    }

    let charter = &request.charter.body;
    let case = &request.case.body;
    let listing = &request.listing.body;
    let namespace = normalize_namespace(&listing.namespace);

    if charter.governing_operator_id != case.governing_operator_id
        || charter.charter_id != case.charter_id
        || normalize_namespace(&charter.authority_scope.namespace) != namespace
        || normalize_namespace(&case.namespace) != namespace
        || case.listing_id != listing.listing_id
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseMismatch,
            "governance charter or case does not match the current listing identity or namespace",
        ));
    }

    if charter
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterExpired,
            "governance charter has expired",
        ));
    }
    if case
        .expires_at
        .is_some_and(|expires_at| expires_at <= evaluated_at)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CaseExpired,
            "governance case has expired",
        ));
    }
    if !charter.allowed_case_kinds.contains(&case.kind) {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterKindUnsupported,
            "governance charter does not authorize this case kind",
        ));
    }
    if !charter
        .authority_scope
        .allowed_listing_operator_ids
        .is_empty()
        && !charter
            .authority_scope
            .allowed_listing_operator_ids
            .contains(&request.current_publisher.operator_id)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterScopeMismatch,
            "current listing publisher falls outside the charter authority scope",
        ));
    }
    if !charter.authority_scope.allowed_actor_kinds.is_empty()
        && !charter
            .authority_scope
            .allowed_actor_kinds
            .contains(&listing.subject.actor_kind)
    {
        return Ok(governance_failure(
            request,
            evaluated_at,
            GenericGovernanceFindingCode::CharterScopeMismatch,
            "listing actor kind falls outside the charter authority scope",
        ));
    }

    if matches!(
        case.kind,
        GenericGovernanceCaseKind::Freeze | GenericGovernanceCaseKind::Sanction
    ) {
        let Some(activation) = request.activation.as_ref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::MissingActivation,
                "freeze or sanction cases require an explicit local trust activation",
            ));
        };
        if case.activation_id.as_deref() != Some(activation.body.activation_id.as_str()) {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::ActivationMismatch,
                "governance case activation does not match the provided trust activation",
            ));
        }
    }

    if let Some(supersedes_case_id) = case.supersedes_case_id.as_deref() {
        let Some(prior_case) = request.prior_case.as_ref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::SupersessionTargetMissing,
                "superseding governance case requires prior_case",
            ));
        };
        if prior_case.body.case_id != supersedes_case_id
            || normalize_namespace(&prior_case.body.namespace) != namespace
            || prior_case.body.listing_id != listing.listing_id
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::SupersessionTargetInvalid,
                "supersession target does not match the referenced prior governance case",
            ));
        }
    }

    if matches!(case.kind, GenericGovernanceCaseKind::Appeal) {
        let Some(appeal_of_case_id) = case.appeal_of_case_id.as_deref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::AppealTargetMissing,
                "appeal case requires appeal_of_case_id",
            ));
        };
        let Some(prior_case) = request.prior_case.as_ref() else {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::AppealTargetMissing,
                "appeal case requires prior_case",
            ));
        };
        if prior_case.body.case_id != appeal_of_case_id
            || normalize_namespace(&prior_case.body.namespace) != namespace
            || prior_case.body.listing_id != listing.listing_id
            || matches!(prior_case.body.kind, GenericGovernanceCaseKind::Appeal)
        {
            return Ok(governance_failure(
                request,
                evaluated_at,
                GenericGovernanceFindingCode::AppealTargetInvalid,
                "appeal target does not match a valid prior governance case",
            ));
        }
    }

    let (effective_state, blocks_admission) = effective_state_for_case(case);
    Ok(GenericGovernanceCaseEvaluation {
        listing_id: listing.listing_id.clone(),
        namespace,
        charter_id: charter.charter_id.clone(),
        case_id: case.case_id.clone(),
        governing_operator_id: case.governing_operator_id.clone(),
        kind: case.kind,
        state: case.state,
        effective_state,
        evaluated_at,
        blocks_admission,
        findings: Vec::new(),
    })
}

pub(crate) fn effective_state_for_case(
    case: &GenericGovernanceCaseArtifact,
) -> (GenericGovernanceEffectiveState, bool) {
    match case.state {
        GenericGovernanceCaseState::Resolved
        | GenericGovernanceCaseState::Denied
        | GenericGovernanceCaseState::Superseded => (GenericGovernanceEffectiveState::Clear, false),
        GenericGovernanceCaseState::Open | GenericGovernanceCaseState::Escalated => match case.kind
        {
            GenericGovernanceCaseKind::Dispute => {
                (GenericGovernanceEffectiveState::Disputed, false)
            }
            GenericGovernanceCaseKind::Appeal => (GenericGovernanceEffectiveState::Appealed, false),
            GenericGovernanceCaseKind::Freeze => (GenericGovernanceEffectiveState::Frozen, false),
            GenericGovernanceCaseKind::Sanction => {
                (GenericGovernanceEffectiveState::Sanctioned, false)
            }
        },
        GenericGovernanceCaseState::Enforced => match case.kind {
            GenericGovernanceCaseKind::Dispute => {
                (GenericGovernanceEffectiveState::Disputed, false)
            }
            GenericGovernanceCaseKind::Appeal => (GenericGovernanceEffectiveState::Appealed, false),
            GenericGovernanceCaseKind::Freeze => (GenericGovernanceEffectiveState::Frozen, true),
            GenericGovernanceCaseKind::Sanction => {
                (GenericGovernanceEffectiveState::Sanctioned, true)
            }
        },
    }
}

pub(crate) fn governance_failure(
    request: &GenericGovernanceCaseEvaluationRequest,
    evaluated_at: u64,
    code: GenericGovernanceFindingCode,
    message: &str,
) -> GenericGovernanceCaseEvaluation {
    GenericGovernanceCaseEvaluation {
        listing_id: request.listing.body.listing_id.clone(),
        namespace: request.listing.body.namespace.clone(),
        charter_id: request.case.body.charter_id.clone(),
        case_id: request.case.body.case_id.clone(),
        governing_operator_id: request.case.body.governing_operator_id.clone(),
        kind: request.case.body.kind,
        state: request.case.body.state,
        effective_state: GenericGovernanceEffectiveState::Clear,
        evaluated_at,
        blocks_admission: false,
        findings: vec![GenericGovernanceFinding {
            code,
            message: message.to_string(),
        }],
    }
}
