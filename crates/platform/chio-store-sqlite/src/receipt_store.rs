use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::canonical::{canonical_json_bytes, CanonicalBytes};
use chio_core::capability::{scope::ChioScope, token::CapabilityToken};
use chio_core::crypto::{sha256_hex, Keypair, Signature};
use chio_core::receipt::{
    body::ChioReceipt, crypto_floor::ReceiptCryptoFloor, decision::Decision,
    economics::FinancialReceiptMetadata, economics::SettlementStatus,
    governance::GovernedTransactionReceiptMetadata, lineage::ChildRequestReceipt,
    metadata::ReceiptAttributionMetadata,
};
use chio_core::session::{
    OperationTerminalState, RequestLineageMode, RequestLineageRecord, SessionAnchorReference,
};
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
use chio_kernel::receipt_query::{
    ReceiptQuery, ReceiptQueryResult, ReceiptReadBoundary, ReceiptReadContext, MAX_QUERY_LIMIT,
};
use chio_kernel::receipt_store::{ReceiptLineageStatementLink, ReceiptLineageVerification};
use chio_kernel::{
    AuthorizationReceiptConsumption, CapabilitySnapshot, CreditBondDisposition,
    CreditBondLifecycleState, CreditBondListQuery, CreditBondListReport, CreditBondListSummary,
    CreditBondRow, CreditFacilityDisposition, CreditFacilityLifecycleState,
    CreditFacilityListQuery, CreditFacilityListReport, CreditFacilityListSummary,
    CreditFacilityRow, CreditLossLifecycleEventKind, CreditLossLifecycleListQuery,
    CreditLossLifecycleListReport, CreditLossLifecycleListSummary, CreditLossLifecycleRow,
    EvidenceChildReceiptScope, EvidenceExportQuery, ExposureLedgerQuery,
    FederatedEvidenceShareImport, FederatedEvidenceShareSummary, LiabilityAutoBindDisposition,
    LiabilityClaimPayoutReconciliationState, LiabilityClaimResponseDisposition,
    LiabilityClaimSettlementReconciliationState, LiabilityClaimWorkflowQuery,
    LiabilityClaimWorkflowReport, LiabilityClaimWorkflowRow, LiabilityClaimWorkflowSummary,
    LiabilityMarketWorkflowQuery, LiabilityMarketWorkflowReport, LiabilityMarketWorkflowRow,
    LiabilityMarketWorkflowSummary, LiabilityProviderLifecycleState, LiabilityProviderListQuery,
    LiabilityProviderListReport, LiabilityProviderListSummary, LiabilityProviderResolutionQuery,
    LiabilityProviderResolutionReport, LiabilityProviderRow, LiabilityQuoteDisposition,
    ReceiptCheckpointCreateReport, ReceiptCheckpointRange, ReceiptCheckpointStatusReport,
    ReceiptFlushReport, ReceiptStore, ReceiptStoreError, ReceiptStoreHealthReport,
    ReceiptWalCheckpointReport, ReceiptWriterCounters, RetentionConfig, SignedCreditBond,
    SignedCreditFacility, SignedCreditLossLifecycle, SignedLiabilityAutoBindDecision,
    SignedLiabilityBoundCoverage, SignedLiabilityClaimAdjudication, SignedLiabilityClaimDispute,
    SignedLiabilityClaimPackage, SignedLiabilityClaimPayoutInstruction,
    SignedLiabilityClaimPayoutReceipt, SignedLiabilityClaimResponse,
    SignedLiabilityClaimSettlementInstruction, SignedLiabilityClaimSettlementReceipt,
    SignedLiabilityPlacement, SignedLiabilityPricingAuthority, SignedLiabilityProvider,
    SignedLiabilityQuoteRequest, SignedLiabilityQuoteResponse, SignedUnderwritingDecision,
    StoredChildReceipt, StoredToolReceipt, UnderwritingAppealCreateRequest,
    UnderwritingAppealRecord, UnderwritingAppealResolution, UnderwritingAppealResolveRequest,
    UnderwritingAppealStatus, UnderwritingDecisionLifecycleState, UnderwritingDecisionListReport,
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
    /// Multi-tenant receipt isolation: when true, tenant-
    /// scoped queries exclude the pre-multitenant NULL-tagged set. When
    /// false, queries with `tenant_filter = Some(id)` return rows where
    /// `tenant_id = id OR tenant_id IS NULL`, which keeps pre-multitenant
    /// (NULL-tagged) receipts visible during explicit compatibility mode.
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
    health: Arc<ReceiptCommitWriterHealth>,
}

#[derive(Default)]
struct ReceiptCommitWriterHealth {
    accepted_total: AtomicU64,
    committed_total: AtomicU64,
    failed_total: AtomicU64,
    saturated_total: AtomicU64,
    inflight: AtomicU64,
    last_commit_unix_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
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
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor_health = Arc::clone(&health);
        thread::spawn(move || receipt_commit_actor_loop(pool, receiver, actor_health));
        Self { sender, health }
    }

    fn append(&self, receipt: ChioReceipt, raw_json: String) -> Result<u64, ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        let command = ReceiptCommitCommand::Append(Box::new(ReceiptCommitRequest {
            receipt,
            raw_json,
            response,
        }));
        // Increment `inflight` BEFORE handing the command to the worker. If we
        // wait until after `try_send`, the worker can dequeue, commit, and run
        // `atomic_saturating_sub(&health.inflight, n)` (see
        // `commit_receipt_batch`) before this thread observes the send result.
        // That race saturates `inflight` to 0 and leaks the increment, leaving
        // `health.writer.inflight` permanently misreporting drained writes.
        // The worker decrements unconditionally on dequeue, so the pre-send
        // increment pairs correctly. Any failure of `try_send` undoes the
        // speculative increment before returning.
        self.health.inflight.fetch_add(1, Ordering::SeqCst);
        match self.sender.try_send(command) {
            Ok(()) => {
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                return Err(receipt_actor_unavailable_error());
            }
        }
        match result.recv() {
            Ok(result) => result,
            Err(_) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    fn flush(&self) -> Result<(), ReceiptStoreError> {
        self.flush_with_receiver(|receiver| {
            receiver
                .recv()
                .map_err(|_| receipt_actor_unavailable_error())?
        })
    }

    fn flush_with_timeout(&self, timeout: Duration) -> Result<(), ReceiptStoreError> {
        self.flush_with_receiver(|receiver| match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(receipt_actor_flush_timeout_error(timeout)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(receipt_actor_unavailable_error()),
        })
    }

    fn flush_with_receiver(
        &self,
        receive: impl FnOnce(
            mpsc::Receiver<Result<(), ReceiptStoreError>>,
        ) -> Result<(), ReceiptStoreError>,
    ) -> Result<(), ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        match self.sender.try_send(ReceiptCommitCommand::Flush(response)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(receipt_actor_unavailable_error());
            }
        }
        receive(result)
    }

    fn writer_counters(&self) -> ReceiptWriterCounters {
        let last_commit_unix_ms = match self.health.last_commit_unix_ms.load(Ordering::SeqCst) {
            0 => None,
            value => Some(value),
        };
        let last_error = self
            .health
            .last_error
            .lock()
            .map(|error| error.clone())
            .unwrap_or_else(|_| Some("receipt commit writer health lock poisoned".to_string()));
        ReceiptWriterCounters {
            accepted_total: self.health.accepted_total.load(Ordering::SeqCst),
            committed_total: self.health.committed_total.load(Ordering::SeqCst),
            failed_total: self.health.failed_total.load(Ordering::SeqCst),
            saturated_total: self.health.saturated_total.load(Ordering::SeqCst),
            inflight: self.health.inflight.load(Ordering::SeqCst),
            last_commit_unix_ms,
            last_error,
        }
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

fn receipt_actor_saturated_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit queue saturated".to_string())
}

fn receipt_actor_flush_timeout_error(timeout: Duration) -> ReceiptStoreError {
    ReceiptStoreError::Timeout {
        operation: "sqlite receipt commit flush".to_string(),
        timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
    }
}

fn receipt_commit_actor_loop(
    pool: Pool<SqliteConnectionManager>,
    receiver: mpsc::Receiver<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
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
                pending_flush_error = commit_receipt_batch(&pool, requests, flushes, &health);
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
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let results = append_receipt_batch(pool, &requests);
    let flush_error = results
        .iter()
        .find_map(|result| result.as_ref().err().map(receipt_store_error_snapshot));
    let committed = results.iter().filter(|result| result.is_ok()).count() as u64;
    let failed = results.iter().filter(|result| result.is_err()).count() as u64;
    if committed > 0 {
        health
            .committed_total
            .fetch_add(committed, Ordering::SeqCst);
        health
            .last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    }
    if failed > 0 {
        health.failed_total.fetch_add(failed, Ordering::SeqCst);
    }
    atomic_saturating_sub(&health.inflight, results.len() as u64);
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = flush_error.as_ref().map(ToString::to_string);
    }
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

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn atomic_saturating_sub(value: &AtomicU64, amount: u64) {
    let mut current = value.load(Ordering::SeqCst);
    loop {
        let next = current.saturating_sub(amount);
        match value.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
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
    if let Err(error) = ensure_checkpoint_transparency_guards(&connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    if let Err(error) = validate_claim_receipt_log_entries(&connection) {
        return receipt_batch_error_results(requests.len(), error);
    }
    let tx = match connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(error) => {
            return receipt_batch_error_results(requests.len(), ReceiptStoreError::Sqlite(error));
        }
    };
    if let Err(error) = verify_latest_checkpoint_integrity(&tx) {
        return receipt_batch_error_results(requests.len(), error);
    }
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
        ReceiptStoreError::Timeout {
            operation,
            timeout_ms,
        } => ReceiptStoreError::Timeout {
            operation: operation.clone(),
            timeout_ms: *timeout_ms,
        },
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
        ReceiptStoreError::ReadBoundary(message) => {
            ReceiptStoreError::ReadBoundary(message.clone())
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
pub(crate) use support::{decode_verified_child_receipt, decode_verified_chio_receipt, sqlite_u64};

impl SqliteReceiptStore {
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    /// Highest tool-receipt replication seq, or 0 on an empty store. Single
    /// indexed MAX read; does not materialize the store.
    pub fn max_tool_receipt_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Highest child-receipt replication seq, or 0 on an empty store.
    pub fn max_child_receipt_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_child_receipts",
            [],
            |row| row.get(0),
        )?;
        Ok(seq.max(0) as u64)
    }

    /// Multi-tenant receipt isolation: toggle strict-isolation
    /// mode on tenant-scoped queries.
    ///
    /// When `strict = true`, a `tenant_filter = Some(id)` query returns
    /// ONLY rows whose `tenant_id = id`. Pre-multitenant receipts with
    /// `tenant_id IS NULL` are excluded.
    ///
    /// When `strict = false`, the same query also includes rows where
    /// `tenant_id IS NULL` -- the pre-multitenant "public" fallback
    /// set -- so pre-multitenant (NULL-tagged) receipts remain visible during
    /// an explicit compatibility window.
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

    pub fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        if receipt.id != consumption.consumer_receipt_id {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption consumer receipt id does not match appended receipt"
                    .to_string(),
            ));
        }
        if receipt.tenant_id.as_deref() != consumption.tenant_id.as_deref() {
            return Err(ReceiptStoreError::Conflict(
                "authorization consumption tenant id does not match appended receipt".to_string(),
            ));
        }
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        let raw_json = canonical_json_bytes(receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        let raw_json = std::str::from_utf8(raw_json.as_slice()).map_err(|error| {
            ReceiptStoreError::Canonical(format!("canonical receipt bytes are not UTF-8: {error}"))
        })?;
        let mut connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        validate_claim_receipt_log_entries(&connection)?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        verify_latest_checkpoint_integrity(&tx)?;
        consume_authorization_receipt_tx(&tx, consumption)?;
        append_chio_receipt_tx(&tx, receipt, raw_json)?;
        ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
        tx.commit()?;
        Ok(())
    }

    pub fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush()?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    pub fn flush_receipt_writes_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush_with_timeout(timeout)?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    pub fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let status = self.receipt_checkpoint_status(Some(1))?;
        if status.latest_committed_entry_seq > status.latest_checkpointed_entry_seq {
            let connection = self.connection()?;
            let start_seq = status.latest_checkpointed_entry_seq + 1;
            load_claim_tree_canonical_bytes_range(
                &connection,
                start_seq,
                status.latest_committed_entry_seq,
            )?;
        }
        let healthy = status.healthy
            && self
                .receipt_commit_actor
                .writer_counters()
                .last_error
                .is_none();
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) = uncheckpointed_range(
            status.latest_checkpointed_entry_seq,
            status.latest_committed_entry_seq,
        );
        Ok(ReceiptStoreHealthReport {
            healthy,
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq: status.latest_committed_entry_seq,
            latest_checkpoint_seq: status.latest_checkpoint_seq,
            latest_checkpointed_entry_seq: status.latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            checkpoint_error: status.checkpoint_error,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    pub fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_claim_log_entry_seq(&connection)
    }

    pub fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        latest_checkpointed_entry_seq(&connection)
    }

    pub fn next_checkpoint_range(
        &self,
        max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        let connection = self.connection()?;
        next_checkpoint_range_for_connection(&connection, max_batch)
    }

    pub fn receipt_checkpoint_status(
        &self,
        max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let connection = self.connection()?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                if latest_committed_entry_seq > latest_checkpointed_entry_seq {
                    let start_seq = latest_checkpointed_entry_seq + 1;
                    if let Err(error) = ensure_claim_log_range_contiguous(
                        &connection,
                        start_seq,
                        latest_committed_entry_seq,
                        "uncheckpointed range",
                    ) {
                        return Ok(ReceiptCheckpointStatusReport {
                            healthy: false,
                            latest_committed_entry_seq,
                            latest_checkpoint_seq,
                            latest_checkpointed_entry_seq,
                            next_range: None,
                            checkpoint_error: Some(error.to_string()),
                        });
                    }
                }
                let next_range = match max_batch {
                    Some(max_batch) => {
                        next_checkpoint_range_for_connection(&connection, max_batch)?
                    }
                    None => None,
                };
                Ok(ReceiptCheckpointStatusReport {
                    healthy: true,
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    next_range,
                    checkpoint_error: None,
                })
            }
            Err(error) => Ok(ReceiptCheckpointStatusReport {
                healthy: false,
                latest_committed_entry_seq,
                latest_checkpoint_seq: None,
                latest_checkpointed_entry_seq: 0,
                next_range: None,
                checkpoint_error: Some(error.to_string()),
            }),
        }
    }

    pub fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        let mut connection = self.connection()?;
        validate_claim_receipt_log_entries(&connection)?;
        create_next_receipt_checkpoint_atomic(&mut connection, max_batch, keypair)
    }

    fn flush_report(
        &self,
        wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.validate_claim_receipt_log_projection_current()?;
        let latest_committed_entry_seq = self.latest_committed_entry_seq()?;
        let latest = self.load_latest_checkpoint()?;
        let latest_checkpoint_seq = latest
            .as_ref()
            .map(|checkpoint| checkpoint.body.checkpoint_seq);
        let latest_checkpointed_entry_seq = latest
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
            uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
        Ok(ReceiptFlushReport {
            writer: self.receipt_commit_actor.writer_counters(),
            latest_committed_entry_seq,
            latest_checkpoint_seq,
            latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            wal_checkpoint,
            db_size_bytes: self.db_size_bytes().ok(),
        })
    }

    fn validate_claim_receipt_log_projection_current(&self) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        validate_claim_receipt_log_entries(&connection)
    }

    fn wal_checkpoint_passive(&self) -> Result<ReceiptWalCheckpointReport, ReceiptStoreError> {
        let connection = self.connection()?;
        let (busy, log_frames, checkpointed_frames) =
            connection.query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?;
        Ok(ReceiptWalCheckpointReport {
            busy: sqlite_u64(busy, "wal checkpoint busy")?,
            log_frames: sqlite_u64(log_frames, "wal checkpoint log frames")?,
            checkpointed_frames: sqlite_u64(checkpointed_frames, "wal checkpointed frames")?,
        })
    }
}

fn uncheckpointed_range(checkpointed: u64, committed: u64) -> (Option<u64>, Option<u64>) {
    if committed > checkpointed {
        (Some(checkpointed + 1), Some(committed))
    } else {
        (None, None)
    }
}

fn latest_claim_log_entry_seq(connection: &Connection) -> Result<u64, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT COALESCE(MAX(entry_seq), 0) FROM claim_receipt_log_entries",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(ReceiptStoreError::from)
        .and_then(|value| sqlite_u64(value, "latest claim receipt log entry_seq"))
}

fn latest_checkpointed_entry_seq(connection: &Connection) -> Result<u64, ReceiptStoreError> {
    verify_checkpoint_chain_integrity(connection)
        .map(|latest| latest.map_or(0, |checkpoint| checkpoint.body.batch_end_seq))
}

fn next_checkpoint_range_for_connection(
    connection: &Connection,
    max_batch: u64,
) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
    if max_batch == 0 {
        return Err(ReceiptStoreError::Conflict(
            "checkpoint max_batch must be greater than zero".to_string(),
        ));
    }
    let latest_committed = latest_claim_log_entry_seq(connection)?;
    let latest_checkpointed = latest_checkpointed_entry_seq(connection)?;
    if latest_committed <= latest_checkpointed {
        return Ok(None);
    }
    let start_seq = latest_checkpointed + 1;
    let end_seq = latest_committed.min(start_seq.saturating_add(max_batch - 1));
    ensure_claim_log_range_contiguous(connection, start_seq, end_seq, "checkpoint range")?;
    Ok(Some(ReceiptCheckpointRange { start_seq, end_seq }))
}

fn ensure_claim_log_range_contiguous(
    connection: &Connection,
    start_seq: u64,
    end_seq: u64,
    context: &str,
) -> Result<(), ReceiptStoreError> {
    if end_seq < start_seq {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log {context} end {end_seq} is before start {start_seq}"
        )));
    }
    let (count, min_seq, max_seq) = connection.query_row(
        r#"
        SELECT COUNT(*), MIN(entry_seq), MAX(entry_seq)
        FROM claim_receipt_log_entries
        WHERE entry_seq >= ?1 AND entry_seq <= ?2
        "#,
        params![
            sqlite_i64(start_seq, "claim log range start_seq")?,
            sqlite_i64(end_seq, "claim log range end_seq")?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
            ))
        },
    )?;
    let expected = end_seq - start_seq + 1;
    let count = sqlite_u64(count, "claim receipt log range count")?;
    let min_seq = min_seq
        .map(|value| sqlite_u64(value, "claim receipt log range min_seq"))
        .transpose()?;
    let max_seq = max_seq
        .map(|value| sqlite_u64(value, "claim receipt log range max_seq"))
        .transpose()?;
    if count != expected || min_seq != Some(start_seq) || max_seq != Some(end_seq) {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log has a gap in {context} {start_seq}..={end_seq}"
        )));
    }
    Ok(())
}

fn claim_log_entry_seq_for_source_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_kind: &str,
    source_seq: u64,
) -> Result<u64, ReceiptStoreError> {
    let source_seq_i64 = sqlite_i64(source_seq, "claim receipt source_seq")?;
    let (entry_seq, log_receipt_id, log_raw_json, source_receipt_id, source_raw_json) =
        match receipt_kind {
            "tool_receipt" => tx.query_row(
                r#"
                SELECT l.entry_seq, l.receipt_id, l.raw_json, r.receipt_id, r.raw_json
                FROM claim_receipt_log_entries l
                JOIN chio_tool_receipts r ON r.seq = l.source_seq
                WHERE l.receipt_kind = ?1 AND l.source_seq = ?2
                "#,
                params![receipt_kind, source_seq_i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            ),
            "child_receipt" => tx.query_row(
                r#"
                SELECT l.entry_seq, l.receipt_id, l.raw_json, r.receipt_id, r.raw_json
                FROM claim_receipt_log_entries l
                JOIN chio_child_receipts r ON r.seq = l.source_seq
                WHERE l.receipt_kind = ?1 AND l.source_seq = ?2
                "#,
                params![receipt_kind, source_seq_i64],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            ),
            other => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "unsupported claim receipt log kind `{other}`"
                )));
            }
        }
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "claim receipt log entry missing for {receipt_kind} source seq {source_seq}"
            ))
        })?;
    if log_receipt_id != source_receipt_id || log_raw_json != source_raw_json {
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log entry for {receipt_kind} source seq {source_seq} diverges from source row"
        )));
    }
    sqlite_positive_u64(entry_seq, "claim receipt log entry_seq")
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
                receipt_decision_kind(receipt),
                receipt.policy_hash.as_str(),
                receipt.content_hash.as_str(),
                receipt.tenant_id.as_deref(),
                raw_json,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?;
    let Some(source_seq) = source_seq else {
        let (existing_source_seq, existing_raw_json) = tx.query_row(
            "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt.id.as_str()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;
        let existing_source_seq =
            sqlite_positive_u64(existing_source_seq, "tool receipt source_seq")?;
        if existing_raw_json != raw_json {
            return Err(ReceiptStoreError::Conflict(format!(
                "tool receipt `{}` already exists with different content",
                receipt.id
            )));
        }
        decode_verified_chio_receipt(
            &existing_raw_json,
            "persisted duplicate tool receipt",
            Some(existing_source_seq),
        )?;
        return claim_log_entry_seq_for_source_tx(tx, "tool_receipt", existing_source_seq);
    };
    let source_seq = sqlite_positive_u64(source_seq, "tool receipt source_seq")?;
    claim_log_entry_seq_for_source_tx(tx, "tool_receipt", source_seq)
}

fn consume_authorization_receipt_tx(
    tx: &rusqlite::Transaction<'_>,
    consumption: &AuthorizationReceiptConsumption,
) -> Result<(), ReceiptStoreError> {
    if consumption.authorization_receipt_id.trim().is_empty()
        || consumption.consumer_receipt_id.trim().is_empty()
        || consumption.request_id.trim().is_empty()
        || consumption.session_id.trim().is_empty()
        || consumption.tool_call_id.trim().is_empty()
        || consumption.parameter_hash.trim().is_empty()
    {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt consumption requires non-empty binding fields".to_string(),
        ));
    }
    // Tenant id may be `None` for non-enterprise / single-tenant deployments,
    // but if it is `Some(_)` it must not be an empty / whitespace-only string.
    if matches!(&consumption.tenant_id, Some(tenant) if tenant.trim().is_empty()) {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt consumption tenant id must not be empty when present"
                .to_string(),
        ));
    }
    let consumed_at = sqlite_i64(
        consumption.consumed_at_unix_ms,
        "authorization receipt consumed_at_unix_ms",
    )?;
    let authorization_tenant = tx
        .query_row(
            "SELECT tenant_id FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![consumption.authorization_receipt_id.as_str()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::NotFound(format!(
                "authorization receipt {} was not found",
                consumption.authorization_receipt_id
            ))
        })?;
    if authorization_tenant.as_deref() != consumption.tenant_id.as_deref() {
        return Err(ReceiptStoreError::Conflict(
            "authorization receipt tenant id does not match consumption tenant".to_string(),
        ));
    }
    match tx.execute(
        r#"
        INSERT INTO chio_authorization_receipt_consumptions (
            authorization_receipt_id,
            consumer_receipt_id,
            request_id,
            session_id,
            tool_call_id,
            tenant_id,
            parameter_hash,
            consumed_at_unix_ms
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "#,
        params![
            consumption.authorization_receipt_id.as_str(),
            consumption.consumer_receipt_id.as_str(),
            consumption.request_id.as_str(),
            consumption.session_id.as_str(),
            consumption.tool_call_id.as_str(),
            consumption.tenant_id.as_deref(),
            consumption.parameter_hash.as_str(),
            consumed_at,
        ],
    ) {
        Ok(_) => Ok(()),
        Err(error)
            if matches!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::ConstraintViolation)
            ) =>
        {
            Err(ReceiptStoreError::Conflict(
                "authorization receipt already consumed".to_string(),
            ))
        }
        Err(error) => Err(ReceiptStoreError::Sqlite(error)),
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

#[cfg(test)]
mod receipt_commit_actor_tests {
    use super::*;

    fn actor_test_receipt() -> Result<ChioReceipt, ReceiptStoreError> {
        let keypair = chio_core::crypto::Keypair::generate();
        ChioReceipt::sign(
            chio_core::receipt::body::ChioReceiptBody {
                id: "rcpt-actor-test".to_string(),
                timestamp: 1,
                capability_id: "cap-actor".to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                    serde_json::json!({}),
                )
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?,
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: "content".to_string(),
                policy_hash: "policy".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .map_err(|error| ReceiptStoreError::CryptoDecode(error.to_string()))
    }

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

    #[test]
    fn receipt_commit_actor_append_fails_closed_when_queue_is_full(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }
        let actor = ReceiptCommitActor { sender, health };

        let error = actor.append(actor_test_receipt()?, "{}".to_string());

        assert!(error
            .err()
            .ok_or("expected queue saturation error")?
            .to_string()
            .contains("sqlite receipt commit queue saturated"));
        Ok(())
    }

    #[test]
    fn receipt_commit_actor_flush_honors_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor { sender, health };

        let error = actor.flush_with_timeout(Duration::from_millis(1));

        match error.err().ok_or("expected flush timeout error")? {
            ReceiptStoreError::Timeout {
                operation,
                timeout_ms,
            } => {
                assert_eq!(operation, "sqlite receipt commit flush");
                assert_eq!(timeout_ms, 1);
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        Ok(())
    }
}
