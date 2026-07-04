#[path = "capital_and_execution/bonded_execution.rs"]
mod bonded_execution;
#[path = "capital_and_execution/capital_allocation.rs"]
mod capital_allocation;
#[path = "capital_and_execution/capital_book.rs"]
mod capital_book;
#[path = "capital_book_query.rs"]
mod capital_book_query;
#[path = "capital_and_execution/capital_execution.rs"]
mod capital_execution;
#[path = "capital_execution_authority.rs"]
mod capital_execution_authority;

pub use bonded_execution::{
    CreditBondedExecutionControlPolicy, CreditBondedExecutionDecision,
    CreditBondedExecutionEvaluation, CreditBondedExecutionFinding,
    CreditBondedExecutionFindingCode, CreditBondedExecutionSimulationDelta,
    CreditBondedExecutionSimulationQuery, CreditBondedExecutionSimulationReport,
    CreditBondedExecutionSimulationRequest, CreditBondedExecutionSupportBoundary,
};
pub use capital_allocation::{
    CapitalAllocationDecisionArtifact, CapitalAllocationDecisionFinding,
    CapitalAllocationDecisionOutcome, CapitalAllocationDecisionReasonCode,
    CapitalAllocationDecisionSupportBoundary, CapitalAllocationInstructionDraft,
    SignedCapitalAllocationDecision,
};
pub use capital_book::{
    CapitalBookEvent, CapitalBookEventKind, CapitalBookEvidenceKind,
    CapitalBookEvidenceReference, CapitalBookReport, CapitalBookRole, CapitalBookSource,
    CapitalBookSourceKind, CapitalBookSummary, CapitalBookSupportBoundary,
    SignedCapitalBookReport,
};
pub use capital_book_query::CapitalBookQuery;
pub use capital_execution::{
    ensure_capital_execution_custodian_authority, ensure_capital_execution_owner_authority,
    validate_capital_execution_envelope, CapitalExecutionInstructionAction,
    CapitalExecutionInstructionArtifact, CapitalExecutionInstructionSupportBoundary,
    CapitalExecutionIntendedState, CapitalExecutionObservation, CapitalExecutionRail,
    CapitalExecutionRailKind, CapitalExecutionReconciledState, CapitalExecutionRole,
    CapitalExecutionWindow, SignedCapitalExecutionInstruction,
};
pub use capital_execution_authority::{
    validate_capital_execution_authority_step_proof, CapitalExecutionAuthorityStep,
    CapitalExecutionAuthorityStepProofBody, SignedCapitalExecutionAuthorityStepProof,
};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "capital_and_execution/tests.rs"]
mod tests;
