use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::{canonical_json_bytes, CanonicalBytes};
use chio_core::capability::{CapabilityToken, ChioScope};
use chio_core::crypto::{sha256_hex, Signature};
use chio_core::receipt::{
    ChildRequestReceipt, ChioReceipt, Decision, FinancialReceiptMetadata,
    GovernedTransactionReceiptMetadata, ReceiptAttributionMetadata, SettlementStatus,
};
use chio_core::session::OperationTerminalState;
use chio_kernel::checkpoint::{KernelCheckpoint, KernelCheckpointBody};
use chio_kernel::cost_attribution::{
    CostAttributionChainHop, CostAttributionQuery, CostAttributionReceiptRow,
    CostAttributionReport, CostAttributionSummary, LeafCostAttributionRow, RootCostAttributionRow,
    MAX_COST_ATTRIBUTION_LIMIT,
};
use chio_kernel::dpop::DPOP_SCHEMA;
use chio_kernel::operator_report::{
    AuthorizationContextReport, AuthorizationContextRow, AuthorizationContextSenderConstraint,
    AuthorizationContextSummary, BehavioralFeedGovernedActionSummary,
    BehavioralFeedMeteredBillingRow, BehavioralFeedMeteredBillingSummary, BehavioralFeedQuery,
    BehavioralFeedReceiptRow, BehavioralFeedReceiptSelection, BehavioralFeedSettlementSummary,
    ChioOAuthAuthorizationDiscoveryMetadata, ChioOAuthAuthorizationExampleMapping,
    ChioOAuthAuthorizationMetadataReport, ChioOAuthAuthorizationProfile,
    ChioOAuthAuthorizationReviewPack, ChioOAuthAuthorizationReviewPackRecord,
    ChioOAuthAuthorizationReviewPackSummary, ChioOAuthAuthorizationSupportBoundary,
    ComplianceReport, EconomicCompletionFlowReport, EconomicCompletionFlowSummary,
    EconomicReceiptMeteringProjection, EconomicReceiptProjectionReport,
    EconomicReceiptProjectionRow, EconomicReceiptProjectionSummary,
    EconomicReceiptSettlementProjection, GovernedAuthorizationCommerceDetail,
    GovernedAuthorizationDetail, GovernedAuthorizationMeteredBillingDetail,
    GovernedAuthorizationTransactionContext, MeteredBillingEvidenceRecord,
    MeteredBillingReconciliationReport, MeteredBillingReconciliationRow,
    MeteredBillingReconciliationState, MeteredBillingReconciliationSummary, OperatorReportQuery,
    SettlementReconciliationReport, SettlementReconciliationRow, SettlementReconciliationState,
    SettlementReconciliationSummary, SharedEvidenceQuery, SharedEvidenceReferenceReport,
    SharedEvidenceReferenceRow, SharedEvidenceReferenceSummary,
    CHIO_OAUTH_AUTHORIZATION_COMMERCE_DETAIL_TYPE, CHIO_OAUTH_AUTHORIZATION_CONTEXT_REPORT_SCHEMA,
    CHIO_OAUTH_AUTHORIZATION_METADATA_SCHEMA, CHIO_OAUTH_AUTHORIZATION_METERED_BILLING_DETAIL_TYPE,
    CHIO_OAUTH_AUTHORIZATION_REVIEW_PACK_SCHEMA, CHIO_OAUTH_AUTHORIZATION_TOOL_DETAIL_TYPE,
    CHIO_OAUTH_SENDER_PROOF_CHIO_DPOP, ECONOMIC_COMPLETION_FLOW_SCHEMA,
};
use chio_kernel::receipt_analytics::{
    AgentAnalyticsRow, AnalyticsTimeBucket, ReceiptAnalyticsMetrics, ReceiptAnalyticsQuery,
    ReceiptAnalyticsResponse, TimeAnalyticsRow, ToolAnalyticsRow, MAX_ANALYTICS_GROUP_LIMIT,
};
use chio_kernel::receipt_query::{ReceiptQuery, ReceiptQueryResult, MAX_QUERY_LIMIT};
use chio_kernel::receipt_store::{ReceiptLineageStatementLink, ReceiptLineageVerification};
use chio_kernel::{
    CapabilitySnapshot, CreditBondDisposition, CreditBondLifecycleState, CreditBondListQuery,
    CreditBondListReport, CreditBondListSummary, CreditBondRow, CreditFacilityDisposition,
    CreditFacilityLifecycleState, CreditFacilityListQuery, CreditFacilityListReport,
    CreditFacilityListSummary, CreditFacilityRow, CreditLossLifecycleEventKind,
    CreditLossLifecycleListQuery, CreditLossLifecycleListReport, CreditLossLifecycleListSummary,
    CreditLossLifecycleRow, EvidenceChildReceiptScope, EvidenceExportQuery, ExposureLedgerQuery,
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, LiabilityAutoBindDisposition,
    LiabilityClaimPayoutReconciliationState, LiabilityClaimResponseDisposition,
    LiabilityClaimSettlementReconciliationState, LiabilityClaimWorkflowQuery,
    LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow, LiabilityClaimWorkflowSummary,
    LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport, LiabilityMarketWorkflowRow,
    LiabilityMarketWorkflowSummary, LiabilityProviderLifecycleState, LiabilityProviderListQuery,
    LiabilityProviderListReport, LiabilityProviderListSummary, LiabilityProviderResolutionQuery,
    LiabilityProviderResolutionReport, LiabilityProviderRow, LiabilityQuoteDisposition,
    ReceiptStore, ReceiptStoreError, RetentionConfig, SignedCreditBond, SignedCreditFacility,
    SignedCreditLossLifecycle, SignedLiabilityAutoBindDecision, SignedLiabilityBoundCoverage,
    SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute, SignedLiabilityClaimPackage,
    SignedLiabilityClaimPayoutInstruction, SignedLiabilityClaimPayoutReceipt,
    SignedLiabilityClaimResponse, SignedLiabilityClaimSettlementInstruction,
    SignedLiabilityClaimSettlementReceipt, SignedLiabilityPlacement,
    SignedLiabilityPricingAuthority, SignedLiabilityProvider, SignedLiabilityQuoteRequest,
    SignedLiabilityQuoteResponse, SignedUnderwritingDecision, StoredChildReceipt,
    StoredToolReceipt, UnderwritingAppealCreateRequest, UnderwritingAppealRecord,
    UnderwritingAppealResolution, UnderwritingAppealResolveRequest, UnderwritingAppealStatus,
    UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
    UnderwritingDecisionOutcome, UnderwritingDecisionQuery, UnderwritingDecisionRow,
    UnderwritingDecisionSummary, CREDIT_BOND_LIST_REPORT_SCHEMA,
    CREDIT_FACILITY_LIST_REPORT_SCHEMA, CREDIT_LOSS_LIFECYCLE_LIST_REPORT_SCHEMA,
    LIABILITY_CLAIM_WORKFLOW_REPORT_SCHEMA, LIABILITY_MARKET_WORKFLOW_REPORT_SCHEMA,
    LIABILITY_PROVIDER_LIST_REPORT_SCHEMA, LIABILITY_PROVIDER_RESOLUTION_REPORT_SCHEMA,
};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, OptionalExtension};

pub struct SqliteReceiptStore {
    pub(crate) pool: Pool<SqliteConnectionManager>,
    /// Phase 1.5 multi-tenant receipt isolation: when true, tenant-
    /// scoped queries exclude the pre-multitenant NULL-tagged set. When
    /// false, queries with `tenant_filter = Some(id)` return rows where
    /// `tenant_id = id OR tenant_id IS NULL`, which keeps legacy
    /// (pre-1.5) receipts visible during explicit compatibility mode.
    pub(crate) strict_tenant_isolation: std::sync::atomic::AtomicBool,
}

type FederatedShareSubjectCorpus = (
    FederatedEvidenceShareSummary,
    Vec<StoredToolReceipt>,
    Vec<CapabilitySnapshot>,
);
pub(crate) type SqliteStoreConnection = PooledConnection<SqliteConnectionManager>;

#[path = "receipt_store/bootstrap.rs"]
mod bootstrap;
#[path = "receipt_store/evidence_retention.rs"]
mod evidence_retention;
#[path = "receipt_store/liability_claims.rs"]
mod liability_claims;
#[path = "receipt_store/liability_market.rs"]
mod liability_market;
#[path = "receipt_store/reports.rs"]
mod reports;
#[path = "receipt_store/support.rs"]
mod support;
#[cfg(test)]
#[path = "receipt_store/tests.rs"]
mod tests;
#[path = "receipt_store/underwriting_credit.rs"]
mod underwriting_credit;

use support::*;
pub(crate) use support::{decode_verified_child_receipt, decode_verified_chio_receipt};

impl SqliteReceiptStore {
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    /// Phase 1.5 multi-tenant receipt isolation: toggle strict-isolation
    /// mode on tenant-scoped queries.
    ///
    /// When `strict = true`, a `tenant_filter = Some(id)` query returns
    /// ONLY rows whose `tenant_id = id`. Legacy pre-1.5 receipts with
    /// `tenant_id IS NULL` are excluded.
    ///
    /// When `strict = false`, the same query also includes rows where
    /// `tenant_id IS NULL` -- the pre-multitenant "public" fallback
    /// set -- so legacy receipts remain visible during an explicit
    /// compatibility window.
    ///
    /// A `tenant_filter = None` admin / compat query always returns
    /// every row regardless of this setting.
    pub fn with_strict_tenant_isolation(&self, strict: bool) {
        self.strict_tenant_isolation
            .store(strict, std::sync::atomic::Ordering::SeqCst);
    }

    /// Read the current strict-tenant-isolation setting.
    #[must_use]
    pub fn strict_tenant_isolation_enabled(&self) -> bool {
        self.strict_tenant_isolation
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn append_chio_receipt_canonical(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
            .map(|_| ())
    }

    pub fn append_chio_receipt_canonical_bytes(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_canonical(canonical)
    }

    pub fn append_chio_receipt_canonical_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        let receipt = decode_canonical_chio_receipt(canonical.as_ref())?;
        let raw_json = canonical_receipt_json(canonical.as_ref())?;
        self.append_chio_receipt_canonical_record(&receipt, raw_json)
    }

    pub fn append_chio_receipt_canonical_bytes_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
    }

    fn append_chio_receipt_canonical_record(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut subject_key = attribution.subject_key;
        let mut issuer_key = attribution.issuer_key;
        if subject_key.is_none() || issuer_key.is_none() {
            if let Some((lineage_subject_key, lineage_issuer_key)) = tx
                .query_row(
                    "SELECT subject_key, issuer_key FROM capability_lineage WHERE capability_id = ?1",
                    params![receipt.capability_id.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                        ))
                    },
                )
                .optional()?
            {
                if subject_key.is_none() {
                    subject_key = lineage_subject_key;
                }
                if issuer_key.is_none() {
                    issuer_key = lineage_issuer_key;
                }
            }
        }
        let inserted = tx.execute(
            r#"
            INSERT INTO chio_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                tenant_id,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id.as_str(),
                sqlite_i64(receipt.timestamp, "receipt timestamp")?,
                receipt.capability_id.as_str(),
                subject_key,
                issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server.as_str(),
                receipt.tool_name.as_str(),
                decision_kind(&receipt.decision),
                receipt.policy_hash.as_str(),
                receipt.content_hash.as_str(),
                receipt.tenant_id.as_deref(),
                raw_json,
            ],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(0);
        }
        let source_seq = tx.query_row(
            "SELECT seq FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt.id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        let source_seq = sqlite_u64(source_seq, "tool receipt source_seq")?;
        let entry_seq = tx.query_row(
            r#"
            SELECT entry_seq
            FROM claim_receipt_log_entries
            WHERE receipt_kind = 'tool_receipt' AND source_seq = ?1
            "#,
            params![sqlite_i64(source_seq, "tool receipt source_seq")?],
            |row| row.get::<_, i64>(0),
        )?;
        tx.commit()?;
        sqlite_u64(entry_seq, "tool receipt claim log entry_seq")
    }
}

fn decode_canonical_chio_receipt(
    canonical: &CanonicalBytes,
) -> Result<ChioReceipt, ReceiptStoreError> {
    let receipt: ChioReceipt =
        serde_json::from_slice(canonical.as_bytes()).map_err(ReceiptStoreError::from)?;
    let expected = canonical_json_bytes(&receipt)
        .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
    if expected.as_slice() != canonical.as_bytes() {
        return Err(ReceiptStoreError::Canonical(
            "canonical receipt bytes do not match ChioReceipt serialization".to_string(),
        ));
    }
    Ok(receipt)
}

fn canonical_receipt_json(canonical: &CanonicalBytes) -> Result<&str, ReceiptStoreError> {
    std::str::from_utf8(canonical.as_bytes()).map_err(|error| {
        ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
    })
}
