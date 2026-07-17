use super::*;

#[path = "claim_log/authorization.rs"]
mod authorization;
#[path = "claim_log/metadata.rs"]
mod metadata;
#[path = "claim_log/query_matching.rs"]
mod query_matching;
#[path = "claim_log/schema.rs"]
mod schema;
#[path = "claim_log/state_converters.rs"]
mod state_converters;
#[path = "claim_log/validation.rs"]
mod validation;

pub(crate) use self::authorization::{
    chain_is_complete, compliance_export_scope_note, derive_authorization_sender_constraint,
    ratio_option, validate_chio_oauth_authorization_row, AuthorizationSenderConstraintArgs,
};
pub(crate) use self::metadata::{
    analyze_metered_billing_reconciliation, authorization_details_from_governed_metadata,
    authorization_transaction_context_from_governed_metadata,
    extract_economic_authorization_metadata, extract_financial_metadata,
    extract_governed_transaction_metadata, extract_receipt_attribution,
    metered_billing_evidence_record_from_columns, parse_settlement_status,
    settlement_reconciliation_action_required, LeafAggregate, RootAggregate,
};
pub(crate) use self::query_matching::{
    credit_bond_matches_query, credit_facility_matches_query,
    effective_credit_bond_lifecycle_state, effective_credit_facility_lifecycle_state,
    liability_claim_workflow_matches_query, liability_market_workflow_matches_query,
    liability_provider_matches_query, liability_provider_policy_matches_resolution,
    load_underwriting_appeal_rows, query_underwriting_appeal, underwriting_decision_matches_query,
    unix_now,
};
pub(crate) use self::schema::{
    backfill_tool_receipt_attribution_columns, ensure_receipt_lineage_statement_columns,
    ensure_tool_receipt_attribution_columns,
};
pub(crate) use self::state_converters::{
    credit_bond_disposition_label, credit_bond_lifecycle_state_label,
    credit_facility_disposition_label, credit_facility_lifecycle_state_label,
    credit_loss_lifecycle_event_kind_label, liability_auto_bind_disposition_label,
    liability_provider_lifecycle_state_label, liability_quote_disposition_label,
    metered_billing_reconciliation_state_text, parse_credit_bond_lifecycle_state,
    parse_credit_facility_lifecycle_state, parse_liability_provider_lifecycle_state,
    parse_metered_billing_reconciliation_state, parse_settlement_reconciliation_state,
    parse_underwriting_lifecycle_state, settlement_reconciliation_state_text,
    underwriting_appeal_status_label, underwriting_decision_outcome_label,
    underwriting_lifecycle_state_label, underwriting_review_state_label,
    underwriting_risk_class_label,
};
pub(crate) use self::validation::{
    backfill_claim_receipt_log_entries, validate_claim_receipt_log_entries,
};
// Reachable in the lib build only through `backfill_claim_receipt_log_entries`
// / `validate_claim_receipt_log_entries` above; this re-export exists so
// tests can drive the fail-closed guard directly.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use self::validation::validate_or_backfill_claim_receipt_log_entries;
