use serde::{Deserialize, Serialize};

use chio_core::appraisal::AttestationVerifierFamily;
use chio_core::capability::{
    governance::{GovernedCallChainProvenance, MeteredSettlementMode},
    runtime_attestation::RuntimeAssuranceTier,
    scope::MonetaryAmount,
};
use chio_core::receipt::{
    body::ChioReceipt, decision::Decision, economics::EconomicAuthorizationReceiptMetadata,
    economics::FinancialBudgetAuthorityReceiptMetadata, economics::SettlementStatus,
    governance::GovernedTransactionReceiptMetadata,
    governance::MeteredUsageEvidenceReceiptMetadata, lineage::SignedExportEnvelope,
};
use chio_core::session::ChioIdentityAssertion;
use chio_core::{
    ChioGovernedAuthorizationBinding, ChioPortableClaimCatalog, ChioPortableIdentityBinding,
};
use chio_credit::{
    CreditBondDisposition, CreditBondListReport, CreditFacilityDisposition,
    CreditFacilityListReport, ExposureLedgerQuery,
};
use chio_underwriting::{UnderwritingDecisionListReport, UnderwritingDecisionOutcome};

use crate::cost_attribution::CostAttributionQuery;
use crate::evidence_export::{
    EvidenceChildReceiptScope, EvidenceExportQuery, EvidenceLineageReferences,
};
use crate::receipt_analytics::{AnalyticsTimeBucket, ReceiptAnalyticsResponse};
use crate::receipt_query::{ReceiptQuery, ReceiptReadBoundary, ReceiptReadContext};
use crate::receipt_store::FederatedEvidenceShareSummary;
use crate::CostAttributionReport;

mod authorization_context;
mod behavioral_analysis;
mod budget_report;
mod comptroller_surface;
mod constants;
mod operator_report_types;
mod queries;
mod settlement_report;

pub use authorization_context::{
    AuthorizationContextReport, AuthorizationContextRow, AuthorizationContextSenderConstraint,
    AuthorizationContextSummary, ChioOAuthArtifactBoundary,
    ChioOAuthAuthorizationDiscoveryMetadata, ChioOAuthAuthorizationExampleMapping,
    ChioOAuthAuthorizationMetadataReport, ChioOAuthAuthorizationProfile,
    ChioOAuthAuthorizationReviewPack, ChioOAuthAuthorizationReviewPackRecord,
    ChioOAuthAuthorizationReviewPackSummary, ChioOAuthAuthorizationSupportBoundary,
    ChioOAuthRequestTimeContract, ChioOAuthResourceBinding, ChioOAuthSenderConstraintProfile,
    GovernedAuthorizationCommerceDetail, GovernedAuthorizationDetail,
    GovernedAuthorizationMeteredBillingDetail, GovernedAuthorizationTransactionContext,
    GovernedTransactionDiagnostics,
};
pub use behavioral_analysis::{
    behavioral_anomaly_score, BehavioralAnomalyScore, BehavioralFeedDecisionSummary,
    BehavioralFeedGovernedActionSummary, BehavioralFeedMeteredBillingRow,
    BehavioralFeedMeteredBillingSummary, BehavioralFeedPrivacyBoundary, BehavioralFeedReceiptRow,
    BehavioralFeedReceiptSelection, BehavioralFeedReport, BehavioralFeedReputationSummary,
    BehavioralFeedSettlementSummary, EmaBaselineState, SignedBehavioralFeed,
};
pub use budget_report::{
    BudgetDimensionProfile, BudgetDimensionUsage, BudgetUtilizationReport, BudgetUtilizationRow,
    BudgetUtilizationSummary, ComplianceReport,
};
pub use comptroller_surface::{
    ComptrollerDecisionSummary, ComptrollerSurfaceReport, ComptrollerSurfaceSourceRefs,
    COMPTROLLER_SURFACE_REPORT_SCHEMA,
};
pub use constants::{
    BEHAVIORAL_FEED_SCHEMA, CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA, CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA,
    CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_PROFILE_ID,
    CHIO_OAUTH_AUTHORIZATION_PROFILE_SCHEMA, CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA,
    CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE, CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_AUTHORIZATION_DETAILS_PARAMETER,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_CLAIM,
    CHIO_OAUTH_REQUEST_TIME_TRANSACTION_CONTEXT_PARAMETER,
    CHIO_OAUTH_SENDER_BINDING_CAPABILITY_SUBJECT, CHIO_OAUTH_SENDER_CONSTRAINT_SCHEMA,
    CHIO_OAUTH_SENDER_PROOF_CHIO_ATTESTATION, CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP,
    CHIO_OAUTH_SENDER_PROOF_CHIO_MTLS, ECONOMIC_COMPLETION_FLOW_SCHEMA,
    MAX_AUTHORIZATION_CONTEXT_LIMIT, MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT, MAX_ECONOMIC_RECEIPT_LIMIT,
    MAX_METERED_BILLING_LIMIT, MAX_OPERATOR_BUDGET_LIMIT, MAX_SETTLEMENT_BACKLOG_LIMIT,
    MAX_SHARED_EVIDENCE_LIMIT,
};
pub use operator_report_types::{
    OperatorReport, SharedEvidenceReferenceReport, SharedEvidenceReferenceRow,
    SharedEvidenceReferenceSummary,
};
pub use queries::{BehavioralFeedQuery, OperatorReportQuery, SharedEvidenceQuery};
pub use settlement_report::{
    EconomicCompletionFlowReport, EconomicCompletionFlowSummary, EconomicReceiptMeteringProjection,
    EconomicReceiptProjectionReport, EconomicReceiptProjectionRow,
    EconomicReceiptProjectionSummary, EconomicReceiptSettlementProjection,
    MeteredBillingEvidenceRecord, MeteredBillingReconciliationReport,
    MeteredBillingReconciliationRow, MeteredBillingReconciliationState,
    MeteredBillingReconciliationSummary, SettlementReconciliationReport,
    SettlementReconciliationRow, SettlementReconciliationState, SettlementReconciliationSummary,
};

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core::capability::governance::{
        GovernedCallChainContext, GovernedProvenanceEvidenceClass,
    };
    use chio_core::receipt::{
        economics::FinancialBudgetAuthorityReceiptMetadata,
        economics::FinancialBudgetAuthorizeReceiptMetadata,
        economics::FinancialBudgetHoldAuthorityMetadata,
        economics::FinancialBudgetTerminalReceiptMetadata,
    };

    #[test]
    fn operator_report_behavioral_feed_query_clamps_limit_and_translates_filters() {
        let query = BehavioralFeedQuery {
            capability_id: Some("cap-1".to_string()),
            agent_subject: Some("subject-1".to_string()),
            tool_server: Some("shell".to_string()),
            tool_name: Some("bash".to_string()),
            since: Some(10),
            until: Some(20),
            receipt_limit: Some(5_000),
            read_context: Some(ReceiptReadContext::local_operator_admin_all()),
        };

        assert_eq!(
            query.receipt_limit_or_default(),
            MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT
        );
        assert_eq!(
            query.normalized().receipt_limit,
            Some(MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT)
        );

        let operator_query = query.to_operator_report_query();
        assert_eq!(operator_query.capability_id.as_deref(), Some("cap-1"));
        assert_eq!(operator_query.agent_subject.as_deref(), Some("subject-1"));
        assert_eq!(operator_query.tool_server.as_deref(), Some("shell"));
        assert_eq!(operator_query.tool_name.as_deref(), Some("bash"));
        assert_eq!(operator_query.since, Some(10));
        assert_eq!(operator_query.until, Some(20));
        assert_eq!(operator_query.metered_limit_or_default(), 50);

        let receipt_query = query.to_receipt_query();
        assert_eq!(receipt_query.limit, MAX_BEHAVIORAL_FEED_RECEIPT_LIMIT);
        assert_eq!(receipt_query.agent_subject.as_deref(), Some("subject-1"));
    }

    #[test]
    fn operator_report_query_requires_read_context_for_evidence_export() {
        let query = OperatorReportQuery::default();
        let err = query
            .to_evidence_export_query()
            .expect_err("evidence export must require explicit read authority");

        assert_eq!(
            err,
            "operator report evidence export requires an explicit read context"
        );
    }

    #[test]
    fn operator_report_query_maps_admin_read_context_to_evidence_export() {
        let query = OperatorReportQuery {
            capability_id: Some("cap-1".to_string()),
            since: Some(10),
            read_context: Some(ReceiptReadContext::admin_service()),
            ..OperatorReportQuery::default()
        };

        let export = query
            .to_evidence_export_query()
            .expect("admin read context should authorize evidence export");

        assert_eq!(export.capability_id.as_deref(), Some("cap-1"));
        assert_eq!(export.since, Some(10));
        assert!(export.tenant.is_none());
        assert_eq!(export.read_boundary, Some(ReceiptReadBoundary::AdminAll));
    }

    #[test]
    fn operator_report_query_maps_tenant_read_context_to_evidence_export() {
        let query = OperatorReportQuery {
            read_context: Some(ReceiptReadContext::authenticated_tenant("tenant-a")),
            ..OperatorReportQuery::default()
        };

        let export = query
            .to_evidence_export_query()
            .expect("tenant read context should authorize evidence export");

        assert_eq!(export.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(
            export.read_boundary,
            Some(ReceiptReadBoundary::TenantScoped {
                tenant: "tenant-a".to_string(),
            })
        );
    }

    #[test]
    fn operator_report_query_direct_export_support_requires_no_tool_filters() {
        let unrestricted = OperatorReportQuery::default();
        assert!(unrestricted.direct_evidence_export_supported());

        let with_tool_filter = OperatorReportQuery {
            tool_server: Some("shell".to_string()),
            ..OperatorReportQuery::default()
        };
        assert!(!with_tool_filter.direct_evidence_export_supported());
    }

    #[test]
    fn operator_report_query_clamps_metered_limit() {
        let query = OperatorReportQuery {
            metered_limit: Some(5_000),
            ..OperatorReportQuery::default()
        };

        assert_eq!(query.metered_limit_or_default(), MAX_METERED_BILLING_LIMIT);
    }

    #[test]
    fn operator_report_query_clamps_authorization_limit() {
        let query = OperatorReportQuery {
            authorization_limit: Some(5_000),
            ..OperatorReportQuery::default()
        };

        assert_eq!(
            query.authorization_limit_or_default(),
            MAX_AUTHORIZATION_CONTEXT_LIMIT
        );
    }

    #[test]
    fn operator_report_query_clamps_economic_limit() {
        let query = OperatorReportQuery {
            economic_limit: Some(5_000),
            ..OperatorReportQuery::default()
        };

        assert_eq!(
            query.economic_limit_or_default(),
            MAX_ECONOMIC_RECEIPT_LIMIT
        );
    }

    #[test]
    fn governed_transaction_diagnostics_serialization_omits_empty_fields() {
        let diagnostics = GovernedTransactionDiagnostics::default();

        assert!(diagnostics.is_empty());
        assert_eq!(
            serde_json::to_value(diagnostics).unwrap(),
            serde_json::json!({})
        );
    }

    #[test]
    fn governed_transaction_diagnostics_preserves_asserted_call_chain_and_lineage_references() {
        let diagnostics = GovernedTransactionDiagnostics {
            asserted_call_chain: Some(GovernedCallChainProvenance::asserted(
                GovernedCallChainContext {
                    chain_id: "chain-1".to_string(),
                    parent_request_id: "req-parent-1".to_string(),
                    parent_receipt_id: Some("rcpt-parent-1".to_string()),
                    origin_subject: "origin".to_string(),
                    delegator_subject: "delegator".to_string(),
                },
            )),
            lineage_references: EvidenceLineageReferences {
                session_anchor_id: Some("anchor-1".to_string()),
                request_lineage_id: Some("req-lineage-1".to_string()),
                receipt_lineage_statement_id: Some("stmt-1".to_string()),
            },
        };

        let value = serde_json::to_value(&diagnostics).unwrap();

        assert_eq!(
            value["assertedCallChain"]["evidenceClass"],
            serde_json::json!("asserted")
        );
        assert_eq!(value["lineageReferences"]["sessionAnchorId"], "anchor-1");
        assert_eq!(
            diagnostics
                .asserted_call_chain
                .as_ref()
                .map(|call_chain| call_chain.evidence_class),
            Some(GovernedProvenanceEvidenceClass::Asserted)
        );
    }

    #[test]
    fn settlement_reconciliation_row_serialization_preserves_budget_authority_metadata() {
        let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "ha".to_string(),
            metering_profile: "metered".to_string(),
            hold_id: "hold-1".to_string(),
            budget_term: Some("term-7".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-a".to_string(),
                lease_id: "lease-7".to_string(),
                lease_epoch: 7,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some("hold-1:authorize".to_string()),
                budget_commit_index: Some(41),
                exposure_units: 120,
                committed_cost_units_after: 120,
            },
            terminal: Some(FinancialBudgetTerminalReceiptMetadata {
                disposition: "reconciled".to_string(),
                event_id: Some("hold-1:reconcile".to_string()),
                budget_commit_index: Some(42),
                exposure_units: 120,
                realized_spend_units: 75,
                committed_cost_units_after: 75,
            }),
        };
        let row = SettlementReconciliationRow {
            receipt_id: "rcpt-1".to_string(),
            timestamp: 42,
            capability_id: "cap-1".to_string(),
            subject_key: Some("subject-1".to_string()),
            tool_server: "payments".to_string(),
            tool_name: "charge".to_string(),
            payment_reference: Some("payref-1".to_string()),
            settlement_status: SettlementStatus::Pending,
            cost_charged: Some(75),
            currency: Some("usd".to_string()),
            budget_authority: Some(budget_authority.clone()),
            reconciliation_state: SettlementReconciliationState::Open,
            action_required: true,
            note: None,
            updated_at: None,
        };

        let value = serde_json::to_value(&row).unwrap();

        assert_eq!(
            value["budgetAuthority"]["guarantee_level"],
            serde_json::json!("ha_quorum_commit")
        );
        assert_eq!(
            value["budgetAuthority"]["hold_id"],
            serde_json::json!("hold-1")
        );
        assert_eq!(
            value["budgetAuthority"]["authority"]["authority_id"],
            serde_json::json!("http://leader-a")
        );
    }

    #[test]
    fn metered_and_behavioral_rows_serialize_budget_authority_metadata() {
        let budget_authority = FinancialBudgetAuthorityReceiptMetadata {
            guarantee_level: "ha_quorum_commit".to_string(),
            authority_profile: "ha".to_string(),
            metering_profile: "metered".to_string(),
            hold_id: "hold-2".to_string(),
            budget_term: Some("term-8".to_string()),
            authority: Some(FinancialBudgetHoldAuthorityMetadata {
                authority_id: "http://leader-b".to_string(),
                lease_id: "lease-8".to_string(),
                lease_epoch: 8,
            }),
            authorize: FinancialBudgetAuthorizeReceiptMetadata {
                event_id: Some("hold-2:authorize".to_string()),
                budget_commit_index: Some(51),
                exposure_units: 150,
                committed_cost_units_after: 150,
            },
            terminal: None,
        };

        let metered = MeteredBillingReconciliationRow {
            receipt_id: "rcpt-2".to_string(),
            timestamp: 99,
            capability_id: "cap-2".to_string(),
            subject_key: None,
            tool_server: "meter".to_string(),
            tool_name: "bill".to_string(),
            settlement_mode: MeteredSettlementMode::AllowThenSettle,
            provider: "provider-1".to_string(),
            quote_id: "quote-1".to_string(),
            billing_unit: "tokens".to_string(),
            quoted_units: 10,
            quoted_cost: MonetaryAmount {
                units: 50,
                currency: "USD".to_string(),
            },
            max_billed_units: Some(10),
            financial_cost_charged: Some(50),
            financial_currency: Some("USD".to_string()),
            budget_authority: Some(budget_authority.clone()),
            evidence: None,
            reconciliation_state: MeteredBillingReconciliationState::Open,
            action_required: true,
            evidence_missing: true,
            exceeds_quoted_units: false,
            exceeds_max_billed_units: false,
            exceeds_quoted_cost: false,
            financial_mismatch: false,
            note: None,
            updated_at: None,
        };
        let behavioral = BehavioralFeedReceiptRow {
            receipt_id: "rcpt-3".to_string(),
            timestamp: 100,
            capability_id: "cap-3".to_string(),
            subject_key: None,
            issuer_key: None,
            tool_server: "meter".to_string(),
            tool_name: "bill".to_string(),
            decision: Some(Decision::Allow),
            authorized: true,
            settlement_status: SettlementStatus::Settled,
            reconciliation_state: SettlementReconciliationState::Reconciled,
            action_required: false,
            cost_charged: Some(50),
            attempted_cost: Some(60),
            currency: Some("USD".to_string()),
            budget_authority: Some(budget_authority),
            governed: None,
            governed_transaction_diagnostics: None,
            metered_reconciliation: None,
        };

        let metered_value = serde_json::to_value(&metered).unwrap();
        let behavioral_value = serde_json::to_value(&behavioral).unwrap();

        assert_eq!(
            metered_value["budgetAuthority"]["guarantee_level"],
            serde_json::json!("ha_quorum_commit")
        );
        assert_eq!(
            behavioral_value["budgetAuthority"]["hold_id"],
            serde_json::json!("hold-2")
        );
    }
}
