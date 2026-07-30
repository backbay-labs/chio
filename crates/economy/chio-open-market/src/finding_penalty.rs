//! Finding-specific wrapper over the generic penalty lane.
//!
//! The generic evaluator proves that a penalty artifact is well formed and
//! that its governance case authorizes the requested action. It does not
//! know what a finding is: it never reads `abuse_class`, never inspects
//! evidence-reference kinds, accepts any penalty amount at or below the
//! bond requirement, and lets a reverse-slash target a prior slash as
//! readily as a prior hold. Every one of those degrees of freedom is a way
//! to move a seller's collateral for the wrong reason, so this wrapper
//! narrows them before a clean generic result counts as authorization.
//!
//! The wrapper composes; it never bypasses. Callers hand it the same
//! request the generic evaluator takes, plus the finding-specific facts,
//! and it runs the generic evaluation first, refuses any result carrying
//! findings, and then applies the branch rules below.
//!
//! Compiled only under the `cognition-market-experimental` feature.

use chio_core_types::capability::scope::MonetaryAmount;

use crate::crypto::PublicKey;
use crate::evaluation::{
    evaluate_open_market_penalty_with_trusted_signers, OpenMarketPenaltyEvaluation,
    OpenMarketPenaltyEvaluationRequest,
};
use crate::evidence::OpenMarketEvidenceKind;
use crate::penalty::{
    OpenMarketAbuseClass, OpenMarketPenaltyAction, OpenMarketPenaltyEffectiveState,
    OpenMarketPenaltyState,
};
use chio_fiscal::fee_schedule::OpenMarketBondClass;

/// The branch of the finding liability lane a penalty is being evaluated
/// for. Each branch has its own required shape; a penalty that satisfies
/// one branch is rejected under the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPenaltyBranch {
    /// A passing challenge holds the bond while the appeal window runs.
    /// Requires an enforced sanction and produces `BondHeld`.
    PendingAppeal,
    /// A timely successful appeal reverses the unapplied hold. Requires an
    /// enforced appeal naming the original sanction, and produces
    /// `Reversed`.
    SuccessfulAppeal,
    /// Appeal finality with no reversal impairs the bond. Requires an
    /// enforced sanction and produces `BondSlashed`.
    AppealFinalImpairment,
}

/// The finding facts the wrapper binds a penalty to. Every field comes
/// from artifacts the caller has already verified; none is caller
/// narrative.
pub struct FindingPenaltyContext<'a> {
    /// Identity of the signed challenge outcome that authorized this lane.
    pub outcome_id: &'a str,
    /// Canonical digest of the signed outcome envelope, which the
    /// penalty's sole evidence reference must carry.
    pub outcome_envelope_sha256: &'a str,
    /// The checked slash amount, computed by the caller from the
    /// predeclared formula. The penalty must equal it exactly.
    pub checked_amount: &'a MonetaryAmount,
    /// Governance case id of the sanction this lane opened with. The
    /// appeal branches must name it.
    pub sanction_case_id: &'a str,
    /// Penalty id of the hold this lane opened with, for the two branches
    /// that supersede it.
    pub hold_penalty_id: Option<&'a str>,
}

/// Typed rejections. Every variant refuses to authorize the penalty.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum FindingPenaltyError {
    #[error("generic penalty evaluation failed: {0}")]
    Generic(String),
    #[error("generic penalty evaluation reported findings")]
    GenericFindings,
    #[error("finding penalties settle only the Listing bond class")]
    BondClass,
    #[error("finding penalties carry the fraudulent-listing abuse class")]
    AbuseClass,
    #[error("penalty must carry exactly one external evidence reference")]
    EvidenceShape,
    #[error("evidence reference does not name the signed challenge outcome")]
    EvidenceBinding,
    #[error("penalty amount is not the checked finding amount")]
    AmountMismatch,
    #[error("penalty action does not match the liability branch")]
    BranchAction,
    #[error("penalty state does not match the liability branch")]
    BranchState,
    #[error("penalty does not supersede the exact prior hold")]
    Supersession,
    #[error("appeal does not name the sanction it appeals")]
    AppealTarget,
    #[error("reverse slash may only clear an unapplied hold")]
    ReverseTarget,
    #[error("branch produced the wrong effective state: {0:?}")]
    EffectiveState(OpenMarketPenaltyEffectiveState),
}

/// Evaluate a finding penalty through the generic lane and the branch
/// rules, returning the generic evaluation only when every binding holds.
///
/// The order matters: the generic evaluation runs first so that a
/// malformed artifact, an unauthorized signer, or an unenforced case is
/// refused by the shipped evaluator rather than by this wrapper's weaker
/// view of the same facts.
pub fn evaluate_finding_penalty(
    request: &OpenMarketPenaltyEvaluationRequest,
    branch: FindingPenaltyBranch,
    context: &FindingPenaltyContext<'_>,
    now: u64,
    trusted_local_operator_signers: &[PublicKey],
) -> Result<OpenMarketPenaltyEvaluation, FindingPenaltyError> {
    let evaluation = evaluate_open_market_penalty_with_trusted_signers(
        request,
        now,
        trusted_local_operator_signers,
    )
    .map_err(FindingPenaltyError::Generic)?;
    if !evaluation.findings.is_empty() {
        return Err(FindingPenaltyError::GenericFindings);
    }

    let penalty = &request.penalty.body;
    if penalty.bond_class != OpenMarketBondClass::Listing {
        return Err(FindingPenaltyError::BondClass);
    }
    if penalty.abuse_class != OpenMarketAbuseClass::FraudulentListing {
        return Err(FindingPenaltyError::AbuseClass);
    }

    // The outcome is the only thing that authorizes a finding penalty, so
    // it is the only evidence the penalty may carry: a second reference,
    // an untyped one, or a body-only digest would each let a different
    // artifact stand in for the adjudicated verdict.
    let [evidence] = penalty.evidence_refs.as_slice() else {
        return Err(FindingPenaltyError::EvidenceShape);
    };
    if evidence.kind != OpenMarketEvidenceKind::External {
        return Err(FindingPenaltyError::EvidenceShape);
    }
    if evidence.reference_id != context.outcome_id
        || evidence.sha256.as_deref() != Some(context.outcome_envelope_sha256)
    {
        return Err(FindingPenaltyError::EvidenceBinding);
    }

    // The generic lane accepts any amount at or below the bond
    // requirement. A finding penalty is the exact checked amount or
    // nothing: a smaller slash silently under-delivers the promised
    // coverage.
    if penalty.penalty_amount.units != context.checked_amount.units
        || penalty.penalty_amount.currency != context.checked_amount.currency
    {
        return Err(FindingPenaltyError::AmountMismatch);
    }

    let case = &request.case.body;
    match branch {
        FindingPenaltyBranch::PendingAppeal => {
            if penalty.action != OpenMarketPenaltyAction::HoldBond {
                return Err(FindingPenaltyError::BranchAction);
            }
            if penalty.state != OpenMarketPenaltyState::Enforced {
                return Err(FindingPenaltyError::BranchState);
            }
            if case.case_id != context.sanction_case_id {
                return Err(FindingPenaltyError::AppealTarget);
            }
            expect_effective(&evaluation, OpenMarketPenaltyEffectiveState::BondHeld)?;
        }
        FindingPenaltyBranch::SuccessfulAppeal => {
            if penalty.action != OpenMarketPenaltyAction::ReverseSlash {
                return Err(FindingPenaltyError::BranchAction);
            }
            if penalty.state != OpenMarketPenaltyState::Reversed {
                return Err(FindingPenaltyError::BranchState);
            }
            // The appeal must name the sanction it appeals in both the
            // appeal and supersession fields, so the case graph has one
            // unambiguous head.
            if case.appeal_of_case_id.as_deref() != Some(context.sanction_case_id)
                || case.supersedes_case_id.as_deref() != Some(context.sanction_case_id)
            {
                return Err(FindingPenaltyError::AppealTarget);
            }
            // The generic lane lets a reverse-slash target a prior slash.
            // An applied slash cannot be reversed by ledger entry, so this
            // branch narrows the target to the unapplied hold.
            let prior = request
                .prior_penalty
                .as_ref()
                .ok_or(FindingPenaltyError::ReverseTarget)?;
            if prior.body.action != OpenMarketPenaltyAction::HoldBond {
                return Err(FindingPenaltyError::ReverseTarget);
            }
            expect_supersedes(penalty.supersedes_penalty_id.as_deref(), context)?;
            expect_effective(&evaluation, OpenMarketPenaltyEffectiveState::Reversed)?;
        }
        FindingPenaltyBranch::AppealFinalImpairment => {
            if penalty.action != OpenMarketPenaltyAction::SlashBond {
                return Err(FindingPenaltyError::BranchAction);
            }
            if penalty.state != OpenMarketPenaltyState::Enforced {
                return Err(FindingPenaltyError::BranchState);
            }
            if case.case_id != context.sanction_case_id {
                return Err(FindingPenaltyError::AppealTarget);
            }
            // The generic validator only requires a supersession id for a
            // reverse slash, so the impairment's link back to its hold is
            // enforced here.
            expect_supersedes(penalty.supersedes_penalty_id.as_deref(), context)?;
            expect_effective(&evaluation, OpenMarketPenaltyEffectiveState::BondSlashed)?;
        }
    }
    Ok(evaluation)
}

fn expect_supersedes(
    supersedes: Option<&str>,
    context: &FindingPenaltyContext<'_>,
) -> Result<(), FindingPenaltyError> {
    match (supersedes, context.hold_penalty_id) {
        (Some(named), Some(expected)) if named == expected => Ok(()),
        _ => Err(FindingPenaltyError::Supersession),
    }
}

fn expect_effective(
    evaluation: &OpenMarketPenaltyEvaluation,
    expected: OpenMarketPenaltyEffectiveState,
) -> Result<(), FindingPenaltyError> {
    if evaluation.effective_state == expected {
        return Ok(());
    }
    Err(FindingPenaltyError::EffectiveState(
        evaluation.effective_state,
    ))
}
