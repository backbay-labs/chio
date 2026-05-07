use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
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
    receipt_commit_actor: ReceiptCommitActor,
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

const RECEIPT_GROUP_COMMIT_MAX_BATCH: usize = 64;
const RECEIPT_GROUP_COMMIT_FLUSH_DELAY: Duration = Duration::from_micros(500);
const RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY: usize = RECEIPT_GROUP_COMMIT_MAX_BATCH * 16;

struct ReceiptCommitActor {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
}

struct ReceiptCommitRequest {
    receipt: ChioReceipt,
    raw_json: String,
    response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
}

enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
}

impl ReceiptCommitActor {
    fn start(pool: Pool<SqliteConnectionManager>) -> Self {
        let (sender, receiver) = receipt_commit_channel();
        thread::spawn(move || receipt_commit_actor_loop(pool, receiver));
        Self { sender }
    }

    fn append(&self, receipt: ChioReceipt, raw_json: String) -> Result<u64, ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(ReceiptCommitCommand::Append(Box::new(
                ReceiptCommitRequest {
                    receipt,
                    raw_json,
                    response,
                },
            )))
            .map_err(|_| receipt_actor_unavailable_error())?;
        result
            .recv()
            .map_err(|_| receipt_actor_unavailable_error())?
    }

    fn flush(&self) -> Result<(), ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        self.sender
            .send(ReceiptCommitCommand::Flush(response))
            .map_err(|_| receipt_actor_unavailable_error())?;
        result
            .recv()
            .map_err(|_| receipt_actor_unavailable_error())?
    }
}

fn receipt_commit_channel() -> (
    mpsc::SyncSender<ReceiptCommitCommand>,
    mpsc::Receiver<ReceiptCommitCommand>,
) {
    mpsc::sync_channel(RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY)
}

fn receipt_actor_unavailable_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit actor is unavailable".to_string())
}

fn receipt_commit_actor_loop(
    pool: Pool<SqliteConnectionManager>,
    receiver: mpsc::Receiver<ReceiptCommitCommand>,
) {
    let mut pending_flush_error: Option<ReceiptStoreError> = None;
    while let Ok(command) = receiver.recv() {
        match command {
            ReceiptCommitCommand::Append(request) => {
                let mut requests = vec![*request];
                let mut flushes = Vec::new();
                while requests.len() < RECEIPT_GROUP_COMMIT_MAX_BATCH {
                    match receiver.recv_timeout(RECEIPT_GROUP_COMMIT_FLUSH_DELAY) {
                        Ok(ReceiptCommitCommand::Append(request)) => requests.push(*request),
                        Ok(ReceiptCommitCommand::Flush(response)) => {
                            flushes.push(response);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                pending_flush_error = commit_receipt_batch(&pool, requests, flushes);
            }
            ReceiptCommitCommand::Flush(response) => {
                let result = match &pending_flush_error {
                    Some(error) => Err(receipt_store_error_snapshot(error)),
                    None => Ok(()),
                };
                let _ = response.send(result);
            }
        }
    }
}

fn commit_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    requests: Vec<ReceiptCommitRequest>,
    flushes: Vec<mpsc::SyncSender<Result<(), ReceiptStoreError>>>,
) -> Option<ReceiptStoreError> {
    let results = append_receipt_batch(pool, &requests);
    let flush_error = results
        .iter()
        .find_map(|result| result.as_ref().err().map(receipt_store_error_snapshot));
    for (request, result) in requests.into_iter().zip(results) {
        let _ = request.response.send(result);
    }
    for response in flushes {
        let result = match &flush_error {
            Some(error) => Err(receipt_store_error_snapshot(error)),
            None => Ok(()),
        };
        let _ = response.send(result);
    }
    flush_error
}

fn append_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    requests: &[ReceiptCommitRequest],
) -> Vec<Result<u64, ReceiptStoreError>> {
    let mut connection = match pool.get() {
        Ok(connection) => connection,
        Err(error) => {
            return receipt_batch_error_results(
                requests.len(),
                ReceiptStoreError::Pool(error.to_string()),
            );
        }
    };
    let tx = match connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => {
            return receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error));
        }
    };
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        match append_chio_receipt_tx(&tx, &request.receipt, &request.raw_json) {
            Ok(seq) => results.push(Ok(seq)),
            Err(error) => return receipt_batch_error_results(requests.len(), error),
        }
    }
    match tx.commit() {
        Ok(()) => results,
        Err(error) => receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error)),
    }
}

fn receipt_batch_error_results(
    count: usize,
    error: ReceiptStoreError,
) -> Vec<Result<u64, ReceiptStoreError>> {
    let snapshot = receipt_store_error_snapshot(&error);
    let mut original = Some(error);
    (0..count)
        .map(|_| {
            Err(original
                .take()
                .unwrap_or_else(|| receipt_store_error_snapshot(&snapshot)))
        })
        .collect()
}

fn receipt_store_error_snapshot(error: &ReceiptStoreError) -> ReceiptStoreError {
    match error {
        ReceiptStoreError::Sqlite(error) => {
            ReceiptStoreError::Sqlite(rusqlite::Error::ToSqlConversionFailure(Box::new(
                std::io::Error::other(error.to_string()),
            )))
        }
        ReceiptStoreError::Pool(message) => ReceiptStoreError::Pool(message.clone()),
        ReceiptStoreError::Json(error) => ReceiptStoreError::Json(serde_json::Error::io(
            std::io::Error::other(error.to_string()),
        )),
        ReceiptStoreError::Io(error) => {
            ReceiptStoreError::Io(std::io::Error::new(error.kind(), error.to_string()))
        }
        ReceiptStoreError::CryptoDecode(message) => {
            ReceiptStoreError::CryptoDecode(message.clone())
        }
        ReceiptStoreError::Canonical(message) => ReceiptStoreError::Canonical(message.clone()),
        ReceiptStoreError::InvalidOutcome(message) => {
            ReceiptStoreError::InvalidOutcome(message.clone())
        }
        ReceiptStoreError::Conflict(message) => ReceiptStoreError::Conflict(message.clone()),
        ReceiptStoreError::NotFound(message) => ReceiptStoreError::NotFound(message.clone()),
    }
}

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
        self.append_verified_chio_receipt_record(&receipt, raw_json)
    }

    pub fn append_chio_receipt_canonical_bytes_returning_seq(
        &self,
        canonical: Arc<CanonicalBytes>,
    ) -> Result<u64, ReceiptStoreError> {
        self.append_chio_receipt_canonical_returning_seq(canonical)
    }

    fn append_verified_chio_receipt_record(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor
            .append(receipt.clone(), raw_json.to_string())
    }

    pub fn flush_receipt_writes(&self) -> Result<(), ReceiptStoreError> {
        self.receipt_commit_actor.flush()
    }

    /// W2.1 Step 2: append a `ChioReceiptV2` keyed on `body_hash`.
    ///
    /// `legacy_receipt_id_alias` is a non-authoritative tooling alias
    /// (UUIDv7) preserved for cross-version correlation; tampering with
    /// it must NOT change replay decisions because replay keys
    /// exclusively on `body_hash`.
    pub fn append_chio_receipt_v2_internal(
        &self,
        receipt: &chio_core::receipt::ChioReceiptV2,
        legacy_receipt_id_alias: Option<&str>,
    ) -> Result<u64, ReceiptStoreError> {
        if !receipt
            .verify_signature()
            .map_err(|e| ReceiptStoreError::Canonical(e.to_string()))?
        {
            return Err(ReceiptStoreError::Canonical(
                "receipt v2 signature verification failed".into(),
            ));
        }
        let raw_json = serde_json::to_string(receipt)?;
        let timestamp = sqlite_i64(receipt.body.timestamp, "v2 receipt timestamp")?;
        let dag_ordinal = sqlite_i64(receipt.body.dag_ordinal, "v2 receipt dag_ordinal")?;
        let connection = self.connection()?;
        let inserted_seq = connection
            .query_row(
                r#"
                INSERT INTO chio_receipts_v2 (
                    body_hash, legacy_receipt_id, timestamp, capability_id,
                    tool_server, tool_name, decision_kind, policy_hash,
                    content_hash, chain_id, dag_ordinal, tenant_id, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(body_hash) DO NOTHING
                RETURNING seq
                "#,
                params![
                    receipt.body_hash.as_str(),
                    legacy_receipt_id_alias,
                    timestamp,
                    receipt.body.capability_id.as_str(),
                    receipt.body.tool_server.as_str(),
                    receipt.body.tool_name.as_str(),
                    decision_kind(&receipt.body.decision),
                    receipt.body.policy_hash.as_str(),
                    receipt.body.content_hash.as_str(),
                    receipt.body.chain_id.as_str(),
                    dag_ordinal,
                    receipt.body.tenant_id.as_deref(),
                    raw_json,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        match inserted_seq {
            Some(seq) => sqlite_u64(seq, "v2 receipt seq"),
            None => Err(ReceiptStoreError::Conflict(format!(
                "v2 receipt replay rejected: body_hash {} already exists",
                receipt.body_hash
            ))),
        }
    }

    /// W2.1 Step 3 helper: probe whether a v2 receipt body_hash has
    /// already been admitted to the persistent store.
    pub fn contains_chio_receipt_v2_body_hash_internal(
        &self,
        body_hash: &str,
    ) -> Result<bool, ReceiptStoreError> {
        let connection = self.connection()?;
        let row: Option<i64> = connection
            .query_row(
                "SELECT 1 FROM chio_receipts_v2 WHERE body_hash = ?1",
                params![body_hash],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        Ok(row.is_some())
    }
}

fn append_chio_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt: &ChioReceipt,
    raw_json: &str,
) -> Result<u64, ReceiptStoreError> {
    let attribution = extract_receipt_attribution(receipt);
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
    let source_seq = tx
        .query_row(
            r#"
        INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, subject_key, issuer_key, grant_index, tool_server, tool_name, decision_kind, policy_hash, content_hash, tenant_id, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(receipt_id) DO NOTHING RETURNING seq
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
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(source_seq) = source_seq else {
        return Ok(0);
    };
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
    sqlite_u64(entry_seq, "tool receipt claim log entry_seq")
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

#[cfg(test)]
mod receipt_commit_actor_tests {
    use super::*;

    #[test]
    fn receipt_commit_actor_channel_has_fixed_capacity() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }

        let (response, _result) = mpsc::sync_channel(1);
        match sender.try_send(ReceiptCommitCommand::Flush(response)) {
            Err(mpsc::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(_)) => {
                Err("commit actor channel disconnected unexpectedly".into())
            }
            Ok(()) => Err("commit actor channel accepted beyond fixed capacity".into()),
        }
    }
}
