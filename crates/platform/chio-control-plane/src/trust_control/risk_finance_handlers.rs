//! HTTP handlers for the risk-and-finance surface: exposure, credit, and
//! capital reports and issuance; the liability insurance market and claims
//! workflows; underwriting; runtime-attestation appraisal; and reputation.

use super::report_validation::validate_service_auth;
use super::reports::{
    build_exposure_ledger_report_with_context, build_runtime_attestation_appraisal_import_report,
    build_signed_runtime_attestation_appraisal_report,
    build_signed_runtime_attestation_appraisal_result,
    issue_signed_capital_allocation_decision_detailed,
    issue_signed_capital_execution_instruction_detailed,
};
use super::*;

#[path = "risk_finance_handlers/attestation.rs"]
mod attestation;
#[path = "risk_finance_handlers/capital.rs"]
mod capital;
#[path = "risk_finance_handlers/credit.rs"]
mod credit;
#[path = "risk_finance_handlers/exposure.rs"]
mod exposure;
#[path = "risk_finance_handlers/liability.rs"]
mod liability;
#[path = "risk_finance_handlers/reputation.rs"]
mod reputation_handlers;
#[path = "risk_finance_handlers/underwriting.rs"]
mod underwriting;

pub(crate) use self::attestation::{
    handle_runtime_attestation_appraisal_import, handle_runtime_attestation_appraisal_report,
    handle_runtime_attestation_appraisal_result_export,
};
pub(crate) use self::capital::{
    handle_capital_book_report, handle_issue_capital_allocation_decision,
    handle_issue_capital_execution_instruction,
};
pub(crate) use self::credit::{
    handle_credit_backtest_report, handle_credit_bond_report,
    handle_credit_bonded_execution_simulation_report, handle_credit_facility_report,
    handle_credit_loss_lifecycle_report, handle_credit_provider_risk_package_report,
    handle_credit_scorecard_report, handle_issue_credit_bond, handle_issue_credit_facility,
    handle_issue_credit_loss_lifecycle, handle_query_credit_bonds, handle_query_credit_facilities,
    handle_query_credit_loss_lifecycle,
};
pub(crate) use self::exposure::handle_exposure_ledger_report;
pub(crate) use self::liability::{
    handle_issue_liability_auto_bind, handle_issue_liability_bound_coverage,
    handle_issue_liability_claim_adjudication, handle_issue_liability_claim_dispute,
    handle_issue_liability_claim_package, handle_issue_liability_claim_payout_instruction,
    handle_issue_liability_claim_payout_receipt, handle_issue_liability_claim_response,
    handle_issue_liability_claim_settlement_instruction,
    handle_issue_liability_claim_settlement_receipt, handle_issue_liability_placement,
    handle_issue_liability_pricing_authority, handle_issue_liability_provider,
    handle_issue_liability_quote_request, handle_issue_liability_quote_response,
    handle_query_liability_claim_workflows, handle_query_liability_market_workflows,
    handle_query_liability_providers, handle_resolve_liability_provider,
};
pub(crate) use self::reputation_handlers::{
    handle_evaluate_portable_reputation, handle_issue_portable_negative_event,
    handle_issue_portable_reputation_summary, handle_local_reputation, handle_reputation_compare,
};
pub(crate) use self::underwriting::{
    handle_create_underwriting_appeal, handle_issue_underwriting_decision,
    handle_query_underwriting_decisions, handle_resolve_underwriting_appeal,
    handle_underwriting_decision_report, handle_underwriting_policy_input,
    handle_underwriting_simulation_report,
};
