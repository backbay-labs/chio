use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::sync::Mutex;
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
use chio_supervisor::{HealthLevel, SupervisedOutcome, SupervisedThread, SupervisorConfig};
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
    /// Staged-rollout flag: read-only after open.
    pub(crate) incremental_verification: bool,
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
    /// Retains the writer thread's join handle and its supervised health flag. The
    /// flag is TCB-critical: any writer death or degradation trips it, and the kernel
    /// pre-dispatch gate reads it to fail closed before a tool executes.
    writer: SupervisedThread,
}

struct ReceiptCommitWriterHealth {
    accepted_total: AtomicU64,
    committed_total: AtomicU64,
    failed_total: AtomicU64,
    saturated_total: AtomicU64,
    inflight: AtomicU64,
    /// Commands currently sitting in the commit-actor channel, not yet pulled
    /// for processing. Incremented before every send and decremented when the
    /// actor pulls a command, so it tracks true channel occupancy rather than
    /// `inflight`, which stays elevated through the commit of a drained batch.
    /// The saturation gate reads this: a drained but still-committing batch must
    /// not read as a full channel when the next send would in fact succeed.
    queue_depth: AtomicU64,
    last_commit_unix_ms: AtomicU64,
    /// Wall-clock (unix-ms) of the first accepted append, set once (0 = unset).
    /// Retained for operator display of when this writer first did work.
    first_accept_unix_ms: AtomicU64,
    /// Wall-clock (unix-ms) at which the CURRENT unserviced backlog began, i.e.
    /// the enqueue that took `inflight` from 0 to 1 (0 = no backlog yet). The
    /// wedged-writer stall clock anchors here so a writer that was merely idle
    /// (an old last commit) is not judged wedged the instant fresh work arrives;
    /// it re-stamps on each new backlog and a growing backlog keeps its start.
    backlog_started_unix_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    // Verified-head snapshot, written only by the actor thread; read by
    // flush_report / receipt_store_health / kernel counters.
    head_checkpoint_seq: AtomicU64,
    head_checkpointed_entry_seq: AtomicU64,
    head_claim_log_count: AtomicU64,
    head_claim_log_max_seq: AtomicU64,
    // Mirror of the actor thread's `WriterHeadState` poison bit. The head lives
    // only on the actor thread, so a poisoned head (every append rejected with a
    // Conflict) is invisible to the supervised thread flag: the writer thread is
    // still alive. Publishing it here lets `writer_serving_closed` deny at the
    // pre-dispatch gate, so a tool is never executed against a store that cannot
    // persist its receipt.
    head_poisoned: AtomicBool,
}

impl Default for ReceiptCommitWriterHealth {
    fn default() -> Self {
        Self {
            accepted_total: AtomicU64::new(0),
            committed_total: AtomicU64::new(0),
            failed_total: AtomicU64::new(0),
            saturated_total: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            queue_depth: AtomicU64::new(0),
            last_commit_unix_ms: AtomicU64::new(0),
            first_accept_unix_ms: AtomicU64::new(0),
            backlog_started_unix_ms: AtomicU64::new(0),
            last_error: Mutex::new(None),
            head_checkpoint_seq: AtomicU64::new(0),
            head_checkpointed_entry_seq: AtomicU64::new(0),
            head_claim_log_count: AtomicU64::new(0),
            head_claim_log_max_seq: AtomicU64::new(0),
            // Fail closed until the actor thread seeds a verified head. The head
            // is seeded asynchronously after construction, so starting open would
            // let a corrupt or still-attaching store pass the pre-dispatch gate
            // and run a tool before the first append could reject. The seed path
            // clears this the moment it succeeds.
            head_poisoned: AtomicBool::new(true),
        }
    }
}

impl ReceiptCommitWriterHealth {
    /// Record accept-time liveness anchors. `first_accept_unix_ms` is set once,
    /// for operator display. `backlog_started_unix_ms` is (re)stamped whenever an
    /// enqueue takes `inflight` from 0 to 1 (`previous_inflight == 0`), marking
    /// the start of the current unserviced backlog. A backlog that only grows
    /// keeps its original start; the next backlog after the writer fully drains
    /// resets it. The stall clock reads this so a writer that wedges before its
    /// first commit is still caught, while a writer resuming after an idle period
    /// is measured from the fresh work rather than a stale last commit.
    fn note_accept(&self, previous_inflight: u64) {
        let now = current_unix_ms();
        let _ =
            self.first_accept_unix_ms
                .compare_exchange(0, now, Ordering::SeqCst, Ordering::SeqCst);
        if previous_inflight == 0 {
            self.backlog_started_unix_ms.store(now, Ordering::SeqCst);
        }
    }

    /// Record that the commit actor has disconnected so the liveness classifier
    /// reports the writer `Dead`. The classifier keys the dead verdict on the
    /// "unavailable" marker in `last_error`, so an actor observed gone at enqueue
    /// time must set it: otherwise the next liveness sample can still read
    /// `Healthy` and admit a tool side effect whose receipt can never be
    /// persisted.
    fn note_writer_unavailable(&self) {
        if let Ok(mut last_error) = self.last_error.lock() {
            *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
        }
    }

    /// Count a command as occupying a channel slot. Called before every
    /// `try_send`; a rejected send undoes it with `note_channel_send_rejected`,
    /// and the actor calls `note_channel_dequeue` once when it pulls the
    /// command. Incrementing before the send (not after) keeps the actor from
    /// dequeuing and decrementing before this increment lands, which would leak
    /// the count, mirroring the `inflight` accounting.
    fn note_channel_send(&self) {
        self.queue_depth.fetch_add(1, Ordering::SeqCst);
    }

    fn note_channel_send_rejected(&self) {
        atomic_saturating_sub(&self.queue_depth, 1);
    }

    fn note_channel_dequeue(&self) {
        atomic_saturating_sub(&self.queue_depth, 1);
    }

    /// Publish whether the writer head is poisoned. Written only by the actor
    /// thread at every head-state transition (seed, post-write resync, reseed)
    /// and read by `writer_serving_closed` from other threads.
    fn set_head_poisoned(&self, poisoned: bool) {
        self.head_poisoned.store(poisoned, Ordering::SeqCst);
    }

    fn store_head_snapshot(&self, head: &VerifiedHead) {
        self.head_checkpoint_seq
            .store(head.checkpoint_seq(), Ordering::SeqCst);
        self.head_checkpointed_entry_seq
            .store(head.checkpointed_entry_seq(), Ordering::SeqCst);
        self.head_claim_log_count
            .store(head.claim_log_count, Ordering::SeqCst);
        self.head_claim_log_max_seq
            .store(head.claim_log_max_seq, Ordering::SeqCst);
    }
}

struct ReceiptCommitRequest {
    receipt: ChioReceipt,
    raw_json: String,
    /// When true, `ensure_receipt_lineage_statement_for_receipt_id_tx` runs
    /// inside the same batch transaction as the receipt insert (trait-append
    /// paths). Canonical inherent paths pass `false`.
    ensure_lineage: bool,
    response: mpsc::SyncSender<Result<u64, ReceiptStoreError>>,
}

/// Deferred response sender for a `Write` job. The
/// actor invokes it AFTER `resync_head_after_write` so a committed write whose
/// head resync then fails returns the resync error instead of a stale `Ok`.
/// Called with `Ok(())` when resync succeeded (or never ran) to send the job's
/// own outcome, or `Err(resync_error)` to override a committed job's `Ok` with
/// the resync failure.
///
/// Returns `true` when the job's FINAL outcome (after any resync override) was
/// `Ok`, so the actor can reconcile `committed_total` / `failed_total` for
/// writer-routed receipts. This responder is the
/// only place that knows the resync-adjusted outcome, so it reports the signal
/// out of band (the actual `Result` still travels to the caller's channel).
type WriterResponder = Box<dyn FnOnce(Result<(), ReceiptStoreError>) -> bool + Send + 'static>;

/// A single-writer job. Runs the caller's closure on the writer connection and
/// returns a [`WriterResponder`] so the ACTOR controls when the caller's result
/// is sent: the response is withheld until the post-write head resync outcome
/// is known.
type WriterClosure = Box<
    dyn FnOnce(Result<&mut SqliteStoreConnection, ReceiptStoreError>) -> WriterResponder
        + Send
        + 'static,
>;

enum ReceiptCommitCommand {
    Append(Box<ReceiptCommitRequest>),
    Flush(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    /// Generic single-writer job. Runs on the writer connection after any
    /// in-flight append batch has committed. The closure receives `Err` when
    /// the actor cannot provide a healthy writer connection (fail-closed).
    ///
    /// `appends_receipts` is true for jobs that insert tool/child receipt rows
    /// (child receipts, authorization-consuming appends), which populate
    /// `claim_receipt_log_entries` via the projection triggers. On a
    /// non-incremental (full-verification) store, the pre-write check runs the
    /// full claim-log validation for these. Metadata-only Write jobs leave it
    /// false and skip the O(N) scan.
    Write {
        job: WriterClosure,
        appends_receipts: bool,
    },
    /// Rerun the full verification on the writer connection and, on success,
    /// adopt the fresh head (clears a poisoned head). Audit-repair path.
    ReseedHead(mpsc::SyncSender<Result<(), ReceiptStoreError>>),
    /// Install (or replace) the background checkpoint signer on the actor
    /// thread. Delivered over the command channel: no shared state, no lock.
    InstallSigner(BackgroundCheckpointSigner),
}

impl ReceiptCommitActor {
    fn start(pool: Pool<SqliteConnectionManager>, incremental_verification: bool) -> Self {
        let (sender, receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor_health = Arc::clone(&health);
        let config = SupervisorConfig {
            name: "chio-receipt-writer",
            // Durable receipt persistence is on the money path: a degraded writer must
            // fail evaluations closed rather than execute tools without a receipt.
            tcb_critical: true,
            // Any writer fault is immediately operator-visible on this surface.
            trip_after: 1,
            max_restarts: 5,
            base_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
        };
        // The loop body borrows the receiver so it survives a restart with the same
        // still-open channel; the caller's sender stays valid across restarts. The
        // pool and health handle are cheap to clone (an Arc bump each) per attempt.
        let writer = SupervisedThread::spawn(config, move |_shutdown| {
            receipt_commit_actor_loop(
                pool.clone(),
                &receiver,
                Arc::clone(&actor_health),
                incremental_verification,
            );
            // The loop returns only once every command sender has dropped: an orderly
            // store shutdown, not a fault. Do not restart or trip the flag.
            SupervisedOutcome::Shutdown
        });
        Self {
            sender,
            health,
            writer,
        }
    }

    /// Typed error for a commit writer that is no longer serving, carrying the
    /// supervisor's restart count and last recorded reason so the condition is
    /// inspectable rather than an opaque pool-error string.
    fn writer_dead_error(&self) -> ReceiptStoreError {
        let snapshot = self.writer.health().snapshot();
        ReceiptStoreError::WriterDead {
            restarts: snapshot.restart_total,
            last_error: snapshot
                .reason
                .unwrap_or_else(|| "receipt commit writer channel disconnected".to_string()),
        }
    }

    /// True when durable persistence can no longer be trusted, so the kernel
    /// pre-dispatch gate must fail closed. This is either the supervised writer
    /// thread leaving the healthy state, or a poisoned verified head: the thread
    /// is alive but every append is rejected with a Conflict until an operator
    /// reseeds, which the thread flag alone cannot see.
    fn writer_serving_closed(&self) -> bool {
        self.writer.health().is_serving_closed() || self.health.head_poisoned.load(Ordering::SeqCst)
    }

    /// The supervised writer's severity and cumulative restart count, for the
    /// health report.
    fn writer_health_summary(&self) -> (HealthLevel, u64) {
        let snapshot = self.writer.health().snapshot();
        (snapshot.level, snapshot.restart_total)
    }

    fn append(
        &self,
        receipt: ChioReceipt,
        raw_json: String,
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        let command = ReceiptCommitCommand::Append(Box::new(ReceiptCommitRequest {
            receipt,
            raw_json,
            ensure_lineage,
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
        let previous_inflight = self.health.inflight.fetch_add(1, Ordering::SeqCst);
        self.health.note_channel_send();
        match self.sender.try_send(command) {
            Ok(()) => {
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_accept(previous_inflight);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(self.writer_dead_error());
            }
        }
        match result.recv() {
            Ok(result) => result,
            Err(_) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_writer_unavailable();
                Err(self.writer_dead_error())
            }
        }
    }

    /// Bounded variant of `append`: identical up to the response wait, which is
    /// capped at `timeout`. On expiry it does NOT decrement `inflight`. The
    /// `try_send` succeeded, so the command is still queued or running on the
    /// worker, which owns `inflight` and decrements it exactly once when it
    /// drains the batch. Decrementing here too would double-count a slow-but-live
    /// append and, under concurrency, could drive `inflight` to zero while work
    /// is still queued, making writer health look drained before the actor
    /// catches up. The timeout still fails this caller loudly and trips health
    /// via `failed_total` / `last_error`; a genuinely wedged writer keeps
    /// `inflight` elevated, which is the honest signal the liveness probe reads.
    fn append_with_timeout(
        &self,
        receipt: ChioReceipt,
        raw_json: String,
        ensure_lineage: bool,
        timeout: Duration,
    ) -> Result<u64, ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        let command = ReceiptCommitCommand::Append(Box::new(ReceiptCommitRequest {
            receipt,
            raw_json,
            ensure_lineage,
            response,
        }));
        let previous_inflight = self.health.inflight.fetch_add(1, Ordering::SeqCst);
        self.health.note_channel_send();
        match self.sender.try_send(command) {
            Ok(()) => {
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_accept(previous_inflight);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(receipt_actor_unavailable_error());
            }
        }
        match result.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit append timed out".to_string());
                }
                Err(receipt_actor_append_timeout_error(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    fn flush(&self) -> Result<(), ReceiptStoreError> {
        let dead = self.writer_dead_error();
        self.flush_with_receiver(|receiver| receiver.recv().map_err(|_| dead)?)
    }

    fn flush_with_timeout(&self, timeout: Duration) -> Result<(), ReceiptStoreError> {
        let dead = self.writer_dead_error();
        self.flush_with_receiver(|receiver| match receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(receipt_actor_flush_timeout_error(timeout)),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(dead),
        })
    }

    fn flush_with_receiver(
        &self,
        receive: impl FnOnce(
            mpsc::Receiver<Result<(), ReceiptStoreError>>,
        ) -> Result<(), ReceiptStoreError>,
    ) -> Result<(), ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        self.health.note_channel_send();
        match self.sender.try_send(ReceiptCommitCommand::Flush(response)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(self.writer_dead_error());
            }
        }
        receive(result)
    }

    /// Wall-clock (unix-ms) at which the current unserviced backlog began, or
    /// `None` when no backlog has started. The liveness classifier anchors its
    /// stall clock here so idle-then-fresh work is not mistaken for a wedge.
    fn backlog_started_unix_ms(&self) -> Option<u64> {
        match self.health.backlog_started_unix_ms.load(Ordering::SeqCst) {
            0 => None,
            value => Some(value),
        }
    }

    fn writer_counters(&self) -> ReceiptWriterCounters {
        let last_commit_unix_ms = match self.health.last_commit_unix_ms.load(Ordering::SeqCst) {
            0 => None,
            value => Some(value),
        };
        let first_accept_unix_ms = match self.health.first_accept_unix_ms.load(Ordering::SeqCst) {
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
            queue_depth: self.health.queue_depth.load(Ordering::SeqCst),
            last_commit_unix_ms,
            first_accept_unix_ms,
            last_error,
        }
    }
}

/// Cloneable handle for running arbitrary write transactions on the single
/// writer connection. Closures MUST NOT call back into `SqliteReceiptStore`
/// methods that enqueue writer commands (that would deadlock the actor on
/// itself); they receive the writer connection directly instead.
pub(crate) struct WriterHandle {
    sender: mpsc::SyncSender<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
}

impl WriterHandle {
    /// Run one write job on the single writer connection and return its
    /// typed result. Fail-closed on saturation or a dead writer. Use for
    /// metadata-only writes (capability, liability, underwriting, IOU,
    /// session anchors) that do not insert receipt rows.
    pub(crate) fn run_write<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind(job, false)
    }

    /// Run one receipt-appending write job (child receipts,
    /// authorization-consuming appends). These insert `claim_receipt_log_entries`
    /// rows via the projection triggers, so the non-incremental fallback
    /// pre-check runs the full claim-log validation (fail-closed).
    pub(crate) fn run_write_receipt<T, F>(&self, job: F) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind(job, true)
    }

    /// Bounded variant of [`run_write_receipt`]: identical up to the response
    /// wait, which is capped at `timeout`. On expiry it fails this caller loudly
    /// without decrementing `inflight` (the actor still owns the queued job and
    /// decrements it exactly once when it drains). A genuinely wedged writer
    /// therefore keeps `inflight` elevated, which is the signal the liveness
    /// probe reads, and this caller does not pin the kernel-wide receipt write
    /// lock waiting on it.
    pub(crate) fn run_write_receipt_with_timeout<T, F>(
        &self,
        job: F,
        timeout: Duration,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind_with_timeout(job, true, timeout)
    }

    /// Bounded variant of [`run_write`]: a metadata-only write (capability
    /// lineage, session anchors) whose response wait is capped at `timeout`.
    /// Fail-closed and inflight-preserving on expiry exactly like
    /// [`run_write_receipt_with_timeout`], so a hot-path metadata write cannot
    /// hang the caller on a wedged writer.
    pub(crate) fn run_write_with_timeout<T, F>(
        &self,
        job: F,
        timeout: Duration,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        self.run_write_kind_with_timeout(job, false, timeout)
    }

    fn run_write_kind_with_timeout<T, F>(
        &self,
        job: F,
        appends_receipts: bool,
        timeout: Duration,
    ) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let result = self.enqueue_write_job(job, appends_receipts)?;
        match result.recv_timeout(timeout) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit write timed out".to_string());
                }
                Err(receipt_actor_write_timeout_error(timeout))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                // Record the writer death so the next liveness sample reports the
                // writer Dead. The classifier keys the Dead verdict on the
                // "unavailable" marker, so without setting it a disconnected
                // writer with `inflight` compensated and `failed_total` matching
                // `accepted_total` would sample as Healthy and admit a tool side
                // effect before receipt persistence fails.
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    fn run_write_kind<T, F>(&self, job: F, appends_receipts: bool) -> Result<T, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let result = self.enqueue_write_job(job, appends_receipts)?;
        match result.recv() {
            Ok(outcome) => outcome,
            Err(_) => {
                // Accepted-then-lost: the actor took the command but exited
                // before delivering a response (actor death; job panics are
                // caught and answered above). The job-completion decrement (the
                // `WriterInflightGuard` in the actor's `Write` arm) may never
                // have run - the command could have been
                // lost while still queued, before the arm was entered - so undo
                // the speculative pre-send increment and record the failure,
                // mirroring the append path's recv-Err handling, so
                // writer.inflight does not report a permanently-stuck write. If
                // the actor instead died mid-arm and the guard already fired,
                // `atomic_saturating_sub` keeps this compensating release from
                // underflowing.
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.failed_total.fetch_add(1, Ordering::SeqCst);
                // Record the writer death so the next liveness sample reports the
                // writer Dead rather than Healthy (see the bounded-write arm).
                if let Ok(mut last_error) = self.health.last_error.lock() {
                    *last_error = Some("sqlite receipt commit actor is unavailable".to_string());
                }
                Err(receipt_actor_unavailable_error())
            }
        }
    }

    /// Box a write job, speculatively account it as in-flight, and enqueue it on
    /// the commit actor. Returns the response receiver on a successful enqueue;
    /// the caller decides how long to wait. A `Full`/`Disconnected` send undoes
    /// the speculative `inflight` increment before returning (fail-closed).
    fn enqueue_write_job<T, F>(
        &self,
        job: F,
        appends_receipts: bool,
    ) -> Result<mpsc::Receiver<Result<T, ReceiptStoreError>>, ReceiptStoreError>
    where
        F: FnOnce(&mut SqliteStoreConnection) -> Result<T, ReceiptStoreError> + Send + 'static,
        T: Send + 'static,
    {
        let (response, result) = mpsc::sync_channel(1);
        let boxed: WriterClosure = Box::new(move |connection| {
            let outcome = match connection {
                // Panic isolation: `job` is one of the many rerouted write
                // families (lineage, liability,
                // underwriting, reconciliation, capability, federated, IOU,
                // checkpoint, reseed) now running on the single writer
                // thread. `AssertUnwindSafe` is sound here because the
                // writer actor re-acquires a fresh connection from the pool
                // for every command (see `handle_non_append_command`); a
                // caught panic fails only THIS job (fail-closed) and no
                // state from the panicking closure is reused afterward.
                Ok(connection) => {
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(connection)))
                        .unwrap_or_else(|payload| Err(receipt_writer_job_panic_error(&payload)))
                }
                Err(error) => Err(error),
            };
            // Defer the send: the actor calls this
            // responder with the post-write head resync outcome. A resync
            // failure overrides a committed job's `Ok` with the resync error; a
            // job that already failed keeps its own error.
            let responder: WriterResponder =
                Box::new(move |resync: Result<(), ReceiptStoreError>| {
                    let final_outcome = match (outcome, resync) {
                        (job_outcome, Ok(())) => job_outcome,
                        (Err(job_error), Err(_)) => Err(job_error),
                        (Ok(_), Err(resync_error)) => Err(resync_error),
                    };
                    // Report the resync-adjusted outcome to the actor so it can
                    // reconcile committed/failed for this writer-routed job,
                    // then send the caller's result.
                    let committed = final_outcome.is_ok();
                    let _ = response.send(final_outcome);
                    committed
                });
            responder
        });
        // Pre-send increment: same race-avoidance invariant as
        // `ReceiptCommitActor::append` (see the comment at the `inflight`
        // increment in `append`). The actor decrements unconditionally on
        // dequeue; any send failure undoes the speculative increment.
        let previous_inflight = self.health.inflight.fetch_add(1, Ordering::SeqCst);
        self.health.note_channel_send();
        match self.sender.try_send(ReceiptCommitCommand::Write {
            job: boxed,
            appends_receipts,
        }) {
            Ok(()) => {
                // Count writer-routed writes in health. A successful enqueue
                // mirrors the Append path's
                // `accepted_total` bump (see `append`): child receipts and
                // authorization-consuming receipts now go through
                // `run_write_receipt`, so without this a store dominated by
                // writer-routed receipts would advance the log while
                // `receipt_store_health().writer.accepted_total` stayed at zero.
                // O(1), fail-closed unchanged (a Full/Disconnected send still
                // returns before counting).
                self.health.accepted_total.fetch_add(1, Ordering::SeqCst);
                self.health.note_accept(previous_inflight);
            }
            Err(mpsc::TrySendError::Full(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.note_channel_send_rejected();
                self.health.saturated_total.fetch_add(1, Ordering::SeqCst);
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                atomic_saturating_sub(&self.health.inflight, 1);
                self.health.note_channel_send_rejected();
                self.health.note_writer_unavailable();
                return Err(receipt_actor_unavailable_error());
            }
        }
        Ok(result)
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

fn receipt_actor_append_timeout_error(timeout: Duration) -> ReceiptStoreError {
    ReceiptStoreError::Timeout {
        operation: "sqlite receipt commit append".to_string(),
        timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
    }
}

fn receipt_actor_write_timeout_error(timeout: Duration) -> ReceiptStoreError {
    ReceiptStoreError::Timeout {
        operation: "sqlite receipt commit write".to_string(),
        timeout_ms: timeout.as_millis().min(u128::from(u64::MAX)) as u64,
    }
}

/// Last verified position of the writer connection's view of the receipt
/// chain, owned exclusively by the commit-actor thread.
enum WriterHeadState {
    // Boxed: `VerifiedHead` embeds an `Option<KernelCheckpoint>`, which makes
    // this variant far larger than `Poisoned(String)` (clippy::large_enum_variant).
    Verified(Box<VerifiedHead>),
    /// Seeding or resync failed: every write is rejected with Conflict until
    /// `chio receipt audit --repair` reseeds (fail-closed).
    Poisoned(String),
}

fn poisoned_head_error(message: &str) -> ReceiptStoreError {
    ReceiptStoreError::Conflict(format!(
        "receipt store verified head is unavailable ({message}); run `chio receipt audit --repair`"
    ))
}

fn receipt_commit_actor_loop(
    pool: Pool<SqliteConnectionManager>,
    receiver: &mpsc::Receiver<ReceiptCommitCommand>,
    health: Arc<ReceiptCommitWriterHealth>,
    incremental_verification: bool,
) {
    let mut head_state = match pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
        .and_then(|connection| {
            if incremental_verification {
                seed_verified_head(&connection)
            } else {
                seed_head_snapshot(&connection)
            }
        }) {
        Ok(head) => {
            health.store_head_snapshot(&head);
            // Seeding is authoritative: clear any poison a prior thread run (a
            // panic-then-restart of the supervised writer) may have published.
            health.set_head_poisoned(false);
            WriterHeadState::Verified(Box::new(head))
        }
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
            health.set_head_poisoned(true);
            WriterHeadState::Poisoned(error.to_string())
        }
    };

    let mut pending_flush_error: Option<ReceiptStoreError> = None;
    let mut checkpoint_signer: Option<BackgroundCheckpointSigner> = None;
    while let Ok(command) = receiver.recv() {
        // The command has left the channel; free its slot for the saturation
        // gate. Every command exits the channel through this recv or the batch
        // drain below, so both decrement exactly once per command.
        health.note_channel_dequeue();
        match command {
            ReceiptCommitCommand::Append(request) => {
                let mut requests = vec![*request];
                let mut flushes = Vec::new();
                let mut deferred: Option<ReceiptCommitCommand> = None;
                while requests.len() < RECEIPT_GROUP_COMMIT_MAX_BATCH {
                    let next = receiver.recv_timeout(RECEIPT_GROUP_COMMIT_FLUSH_DELAY);
                    if next.is_ok() {
                        health.note_channel_dequeue();
                    }
                    match next {
                        Ok(ReceiptCommitCommand::Append(request)) => requests.push(*request),
                        Ok(ReceiptCommitCommand::Flush(response)) => {
                            flushes.push(response);
                            break;
                        }
                        Ok(other) => {
                            // Non-append commands (Write, InstallSigner,
                            // ReseedHead) execute strictly after the batch
                            // they interrupted commits.
                            deferred = Some(other);
                            break;
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => break,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
                // Panic isolation: `commit_receipt_batch` runs on the single
                // writer thread. A
                // panic anywhere inside it (the append transaction, the
                // lineage fold) must fail THIS batch, not kill the thread.
                // Clone the response channels before handing `requests` /
                // `flushes` to the panicking call: if it unwinds, those
                // values are dropped mid-function and the only way left to
                // answer every caller is through these pre-cloned senders.
                let request_responses: Vec<_> = requests
                    .iter()
                    .map(|request| request.response.clone())
                    .collect();
                // The co-drained Flush waiters are NOT passed into
                // `commit_receipt_batch`; they are released below, AFTER the
                // checkpoint build, so a flush is a genuine checkpoint
                // barrier. Keeping them in the loop lets the
                // success and panic paths fan them out at one point, and
                // because they are not moved into the panicking call they
                // survive an unwind untouched.
                pending_flush_error =
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        commit_receipt_batch(
                            &pool,
                            &mut head_state,
                            incremental_verification,
                            requests,
                            &health,
                        )
                    })) {
                        Ok(flush_error) => flush_error,
                        Err(payload) => {
                            // A panic inside the append or lineage commit is at
                            // least as serious as the store-wide append faults
                            // `commit_receipt_batch` already poisons on: the
                            // batch's durable position can no longer be trusted.
                            // Poison the head so the pre-dispatch gate fails closed
                            // rather than admitting more tools whose receipts may
                            // not persist, until an operator reseeds.
                            let panic_error = receipt_writer_job_panic_error(&payload);
                            health.set_head_poisoned(true);
                            head_state = WriterHeadState::Poisoned(panic_error.to_string());
                            Some(fan_out_batch_panic_error(
                                &health,
                                request_responses,
                                panic_error,
                            ))
                        }
                    };
                // Checkpoint construction runs AFTER commit_receipt_batch has
                // already sent every APPEND durability response, so ADR-0013
                // append latency is not extended by checkpoint building; but it
                // runs BEFORE the co-drained Flush waiters are released, so a
                // flush cannot return until the owed checkpoints for the drained
                // appends are built (the flush-as-checkpoint barrier). A
                // build failure is recorded via `last_error` and does not poison
                // the head, and is surfaced to the co-drained Flush waiters of
                // THIS batch via `flush_barrier_error`. It is deliberately NOT
                // written back into `pending_flush_error`: that keeps the build
                // error scoped to this batch's barrier and preserves the
                // established contract of a later STANDALONE flush (which
                // reflects append durability; background-build health is already
                // surfaced through `last_error`/`receipt_store_health`).
                let mut flush_barrier_error = pending_flush_error
                    .as_ref()
                    .map(receipt_store_error_snapshot);
                if pending_flush_error.is_none() {
                    if let WriterHeadState::Verified(head) = &mut head_state {
                        if let Some(error) = build_due_checkpoints_and_record(
                            &pool,
                            head,
                            &checkpoint_signer,
                            &health,
                        ) {
                            flush_barrier_error = Some(error);
                        }
                    }
                }
                // Release the co-drained Flush waiters now that owed checkpoints
                // are built (the checkpoint barrier). An append error or a
                // checkpoint-build failure reaches them as an Err; otherwise Ok.
                for response in flushes {
                    let result = match &flush_barrier_error {
                        Some(error) => Err(receipt_store_error_snapshot(error)),
                        None => Ok(()),
                    };
                    let _ = response.send(result);
                }
                if let Some(command) = deferred {
                    handle_non_append_command(
                        &pool,
                        &mut head_state,
                        incremental_verification,
                        &health,
                        &mut checkpoint_signer,
                        &mut pending_flush_error,
                        command,
                    );
                }
            }
            ReceiptCommitCommand::Flush(response) => {
                let result = match &pending_flush_error {
                    Some(error) => Err(receipt_store_error_snapshot(error)),
                    None => Ok(()),
                };
                let _ = response.send(result);
            }
            other => handle_non_append_command(
                &pool,
                &mut head_state,
                incremental_verification,
                &health,
                &mut checkpoint_signer,
                &mut pending_flush_error,
                other,
            ),
        }
    }
}

fn handle_non_append_command(
    pool: &Pool<SqliteConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    health: &ReceiptCommitWriterHealth,
    checkpoint_signer: &mut Option<BackgroundCheckpointSigner>,
    pending_flush_error: &mut Option<ReceiptStoreError>,
    command: ReceiptCommitCommand,
) {
    match command {
        ReceiptCommitCommand::Write {
            job,
            appends_receipts,
        } => {
            // Hold the writer `inflight` count for the DURATION of this Write
            // job rather than releasing it immediately on dequeue, so a health
            // poll during a slow or stuck liability/checkpoint write reports
            // `inflight > 0`. The pre-send increment in
            // `WriterHandle::run_write_kind` is adopted by this RAII guard.
            //
            // The guard is released (`drop`) IMMEDIATELY BEFORE each
            // `respond(...)` on every exit path, so a caller that observes its
            // own response never sees itself still counted inflight. This
            // mirrors the Append path, which decrements in `commit_receipt_batch`
            // BEFORE fanning out its responses. The decrement stays deferred
            // until each respond, so inflight remains up through the job body and
            // the head resync (the response itself is deferred until then). The
            // guard's Drop still backstops any exit that panics before a respond
            // runs; `atomic_saturating_sub` keeps a rare overlap with the
            // caller's recv-Err compensation (actor-thread death) from
            // underflowing.
            let inflight_guard = WriterInflightGuard::new(&health.inflight);
            let mut connection = match pool.get() {
                Ok(connection) => connection,
                Err(error) => {
                    // No write ran (no connection), so there is no resync to
                    // gate on: send the pool error now (`Ok(())` = nothing to
                    // override). Count the failed outcome.
                    let respond = job(Err(ReceiptStoreError::Pool(error.to_string())));
                    // Decrement before the response reaches the caller.
                    drop(inflight_guard);
                    record_write_job_outcome(health, respond(Ok(())));
                    return;
                }
            };
            match head_state {
                WriterHeadState::Poisoned(message) => {
                    let respond = job(Err(poisoned_head_error(message)));
                    // Decrement before the response reaches the caller.
                    drop(inflight_guard);
                    record_write_job_outcome(health, respond(Ok(())));
                }
                WriterHeadState::Verified(head) => {
                    // Pre-check (fail-closed): same predecessor check the
                    // append path runs, so writer-routed appends (child
                    // receipts, consuming auth) are equally protected. On the
                    // non-incremental (full-verification) fallback, a
                    // receipt-appending job also runs the full claim-log
                    // validation, so uncheckpointed projection drift is caught
                    // before the
                    // write commits. Metadata-only Write jobs skip the O(N)
                    // scan.
                    let pre_check = if incremental_verification {
                        // Verify the checkpoint head, THEN validate the adopted
                        // claim-log delta before the job commits: a
                        // receipt-appending writer job must reject a
                        // stale/invalid baseline BEFORE its durable insert, the
                        // same way the append path does, not durably write and
                        // only poison the head in the post-write resync.
                        match verify_head_against_latest_checkpoint(&connection, head) {
                            Ok(()) => validate_writer_adopted_claim_log_baseline(
                                &connection,
                                head,
                                appends_receipts,
                            ),
                            Err(error) => Err(error),
                        }
                    } else {
                        verify_latest_checkpoint_integrity(&connection).and_then(|()| {
                            if appends_receipts {
                                validate_claim_receipt_log_entries(&connection)
                            } else {
                                Ok(())
                            }
                        })
                    };
                    if let Err(error) = pre_check {
                        let respond = job(Err(error));
                        // Decrement before the response reaches the caller.
                        drop(inflight_guard);
                        record_write_job_outcome(health, respond(Ok(())));
                        return;
                    }
                    // Capture the head's checkpoint position BEFORE the job
                    // runs: a writer-routed recovery
                    // (`create_next_receipt_checkpoint`) that creates/adopts the
                    // missing checkpoint advances this during the resync below.
                    let pre_checkpoint_seq = head.checkpoint_seq();
                    // Run the job but DEFER its response: the caller must not
                    // observe `Ok` until
                    // `resync_head_after_write` confirms the head. A committed
                    // write whose resync then fails receives the resync error,
                    // not a stale `Ok`.
                    let respond = job(Ok(&mut connection));
                    // Post-resync: absorb whatever the closure committed
                    // (claim-log rows via projection triggers, checkpoint
                    // rows via the manual path) so the next append's
                    // cross-check cannot false-Conflict.
                    match resync_head_after_write(&connection, head) {
                        Ok(()) => {
                            // Reconcile committed/failed for this writer-routed
                            // job using the responder's resync-adjusted outcome
                            // signal. Decrement before the response reaches the
                            // caller; the post-response catch-up build below
                            // reads no inflight state.
                            drop(inflight_guard);
                            record_write_job_outcome(health, respond(Ok(())));
                            health.store_head_snapshot(head);
                            // Clear a stale checkpoint error after a manual
                            // recovery: a writer-routed
                            // op such as `create_next_receipt_checkpoint` can
                            // build/adopt the missing checkpoint inside the job,
                            // advancing the head's checkpoint seq during the resync
                            // above. `build_due_checkpoints_and_record` below then
                            // finds nothing due (`Ok(false)`) and would leave a
                            // prior background-build `last_error` in place, so
                            // `receipt_store_health` keeps reporting the store
                            // unhealthy after the repair. Clear it here when the
                            // checkpoint chain actually advanced (clear only on
                            // an actual advance, never on an idle refresh); a
                            // real later build failure re-sets it below.
                            if head.checkpoint_seq() > pre_checkpoint_seq {
                                if let Ok(mut last_error) = health.last_error.lock() {
                                    *last_error = None;
                                }
                            }
                            // Writer-routed appends (child receipts, consuming
                            // auth) can cross the threshold too; no
                            // pending_flush_error guard here since a Write job is
                            // not part of a batch. The writer pool holds exactly
                            // one connection (DEFAULT_WRITER_POOL_MAX_SIZE = 1):
                            // drop this one before build_due_checkpoints_and_record
                            // acquires its own, or `pool.get()` would block on
                            // itself.
                            drop(connection);
                            // Gate the catch-up build on a full-verified head,
                            // mirroring the InstallSigner defer. On a
                            // non-incremental (suspect)
                            // store `seed_head_snapshot` leaves the head
                            // UNVALIDATED; only a receipt-appending Write reran the
                            // full claim-log validation in the pre-check above, so
                            // a metadata-only `run_write` did NOT. Building here
                            // would checkpoint unaudited claim-log rows before the
                            // deferred full validation ever runs (fail-closed
                            // violation). Build only when the head is genuinely
                            // verified: incremental mode (seed_verified_head +
                            // per-append verify) OR a receipt-appending job that
                            // just ran the full validation.
                            if incremental_verification || appends_receipts {
                                build_due_checkpoints_and_record(
                                    pool,
                                    head,
                                    checkpoint_signer,
                                    health,
                                );
                            }
                        }
                        Err(error) => {
                            if let Ok(mut last_error) = health.last_error.lock() {
                                *last_error = Some(error.to_string());
                            }
                            let poison_message = error.to_string();
                            // Surface the resync failure to the caller: a write
                            // that returned `Ok` from its closure must NOT report
                            // success when the head is now poisoned. Count the
                            // failed outcome. Decrement before the response
                            // reaches the caller.
                            drop(inflight_guard);
                            record_write_job_outcome(health, respond(Err(error)));
                            health.set_head_poisoned(true);
                            *head_state = WriterHeadState::Poisoned(poison_message);
                        }
                    }
                }
            }
        }
        ReceiptCommitCommand::InstallSigner(signer) => {
            *checkpoint_signer = Some(signer);
            // Install-time catch-up. The store can
            // open on a DB that already has >= max_batch uncheckpointed
            // claim-log entries (a crash between the durable append response and
            // the background build, or enabling checkpointing on an existing
            // store). Without building here, the owed checkpoint waits for some
            // future Append/Write, so a quiet restarted store stays
            // uncheckpointed indefinitely despite checkpointing being enabled.
            // Run the existing bounded builder now so any already-owed
            // checkpoints (head.claim_log_max_seq - checkpointed_entry_seq >=
            // max_batch) are built at install time (O(b) per checkpoint, loops
            // until caught up; NOT a full verify). Fail-closed:
            // build_due_checkpoints_and_record records last_error and never
            // panics the actor.
            //
            // Deferred-seed gate: only build at
            // install when the head has actually been VALIDATED. With
            // `incremental_verification = false` the actor seeds via
            // `seed_head_snapshot`, which INTENTIONALLY skips the full claim-log
            // + checkpoint-chain audit (deferred to the next append/verify), so
            // the seeded head is `Verified` but UNVALIDATED. Building catch-up
            // checkpoints over that range would checkpoint unaudited data (a
            // fail-closed violation), so defer it in that mode: the next
            // receipt-appending append/Write runs the deferred full validation
            // and THEN builds the owed checkpoints. In the normal incremental
            // mode the seeded head is genuinely verified, so the owed
            // checkpoints still build here.
            if incremental_verification {
                if let WriterHeadState::Verified(head) = head_state {
                    build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                }
            }
        }
        ReceiptCommitCommand::ReseedHead(response) => {
            let outcome = pool
                .get()
                .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
                .and_then(|connection| {
                    // Reseed always runs the FULL verification. This is the
                    // `chio receipt audit --repair`
                    // recovery path: it clears a poisoned head and must establish
                    // a genuinely CLEAN, fully-verified head, so it runs
                    // `seed_verified_head` (full claim-log validation +
                    // checkpoint-chain audit) regardless of the hot-path
                    // `incremental_verification` mode. Using the cheap
                    // `seed_head_snapshot` here would let `--repair` clear
                    // `last_error` and mark the head `Verified` while the on-disk
                    // log is still corrupt (repair theater). This is the recovery
                    // path, not per-append, so it is a recovery-path cost. NOTE
                    // the deliberate difference from the InstallSigner catch-up:
                    // that path DEFERS in
                    // `incremental_verification = false` because `seed_head_snapshot`
                    // leaves the head UNVALIDATED; reseed full-verifies, so it does
                    // not defer.
                    seed_verified_head(&connection)
                });
            let result = match outcome {
                Ok(head) => {
                    health.store_head_snapshot(&head);
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = None;
                    }
                    // Clear the actor loop's stale flush error: a prior append
                    // poisoned the head and set
                    // `pending_flush_error`, but this reseed has just revalidated
                    // the DB and replaced the head. Without clearing it, a
                    // subsequent STANDALONE `flush_receipt_writes()` (no queued
                    // writes) would keep returning the stale append error even
                    // though the store recovered. Fail-closed is unaffected: a
                    // real later batch failure re-sets `pending_flush_error`.
                    *pending_flush_error = None;
                    health.set_head_poisoned(false);
                    *head_state = WriterHeadState::Verified(Box::new(head));
                    // Build owed checkpoints after a successful reseed. If the
                    // background signer was installed
                    // while the head was poisoned, its install-time catch-up
                    // was skipped, so a quiet store with >= max_batch
                    // uncheckpointed claim-log entries would stay uncheckpointed
                    // until some future write. Run the SAME bounded builder now.
                    // Unlike the InstallSigner catch-up (which gates on
                    // `incremental_verification` because its deferred seed is
                    // unvalidated), this is unconditional: the reseed just
                    // full-verified the head, so building over that range never
                    // checkpoints unaudited data. Bounded (O(b) per owed
                    // checkpoint), a recovery-path build (not per-append).
                    // No-op when no signer is present. Fail-closed:
                    // `build_due_checkpoints_and_record` records `last_error` on a
                    // build failure and never re-poisons the freshly verified head.
                    if let WriterHeadState::Verified(head) = head_state {
                        build_due_checkpoints_and_record(pool, head, checkpoint_signer, health);
                    }
                    Ok(())
                }
                Err(error) => {
                    if let Ok(mut last_error) = health.last_error.lock() {
                        *last_error = Some(error.to_string());
                    }
                    health.set_head_poisoned(true);
                    *head_state = WriterHeadState::Poisoned(error.to_string());
                    Err(error)
                }
            };
            let _ = response.send(result);
        }
        // Append/Flush are handled by the main loop; reaching here is
        // impossible by construction but must stay fail-safe.
        ReceiptCommitCommand::Append(request) => {
            let _ = request
                .response
                .send(Err(receipt_actor_unavailable_error()));
        }
        ReceiptCommitCommand::Flush(response) => {
            let _ = response.send(Err(receipt_actor_unavailable_error()));
        }
    }
}

/// Build every checkpoint the head owes and, on success, refresh the health
/// head snapshot; on failure, record the error without poisoning the head or
/// failing the append/write that triggered it (checkpoint construction never
/// blocks an already-durable commit). Returns the recorded
/// error (if any) so a flush-as-checkpoint-barrier caller can surface it to its
/// co-drained flush waiters; the durable append/write path ignores the return
/// and stays fail-closed via `last_error`.
fn build_due_checkpoints_and_record(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    checkpoint_signer: &Option<BackgroundCheckpointSigner>,
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let signer = checkpoint_signer.as_ref()?;
    // Panic isolation: a panic mid-build
    // (Merkle build, Ed25519 sign, serde) must not kill the writer thread.
    // `head.latest_checkpoint` is only ever assigned AFTER the per-checkpoint
    // transaction commits (see `maybe_build_checkpoint`), so a panic
    // anywhere before that leaves `head` exactly as it was; a caught panic
    // is therefore handled identically to a non-panicking `Err`: record
    // `last_error`, leave the head untouched, keep the thread alive.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_due_checkpoints(pool, head, signer)
    }))
    .unwrap_or_else(|payload| Err(receipt_writer_job_panic_error(&payload)));
    match result {
        Ok(built) => {
            health.store_head_snapshot(head);
            // Recovery signal: a prior background
            // checkpoint build may have set `last_error`. A later SUCCESSFUL
            // build is reached here through a writer-routed op (a `Write` job
            // crossing the threshold), which does NOT run the append batch's
            // `last_error` reset, so without this the store keeps reporting
            // unhealthy after it has recovered. Clear the stale error only on an
            // ACTUAL build (`built`), never on a no-op due-check, so a genuinely
            // current error is not masked by an idle refresh.
            if built {
                if let Ok(mut last_error) = health.last_error.lock() {
                    *last_error = None;
                }
            }
            None
        }
        Err(error) => {
            if let Ok(mut last_error) = health.last_error.lock() {
                *last_error = Some(error.to_string());
            }
            Some(error)
        }
    }
}

fn build_due_checkpoints(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<bool, ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(false); // ADR-0008: batch_size 0 disables checkpointing
    }
    let mut connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    // Shared-file freshness: on a shared receipt DB
    // another writer can commit a checkpoint AFTER this actor's append
    // pre-check but BEFORE its batch tx. `append_receipt_batch` then adopts that
    // writer's claim-log rows via the baseline delta yet leaves
    // `head.latest_checkpoint` stale, so building from the stale position would
    // try to rebuild an already-committed checkpoint and fail with "already
    // exists with different content" (the clock-skew case the idempotent-
    // identical guard does not cover). Refresh the head against the latest
    // persisted checkpoint first so that checkpoint is ADOPTED, not rebuilt.
    // This is an O(1) latest-row read + digest adopt (plus bounded catch-up),
    // NOT a full chain verify, so the incremental hot path stays flat per
    // append.
    verify_head_against_latest_checkpoint(&connection, head)?;
    maybe_build_checkpoint(&mut connection, head, signer)
}

/// Build every checkpoint the head owes: count-based ADR-0008 trigger, range
/// derived from the cached head (NOT next_checkpoint_range_for_connection,
/// which runs a full chain verify), O(b) work per checkpoint.
fn maybe_build_checkpoint(
    connection: &mut SqliteStoreConnection,
    head: &mut VerifiedHead,
    signer: &BackgroundCheckpointSigner,
) -> Result<bool, ReceiptStoreError> {
    if signer.max_batch == 0 {
        return Ok(false);
    }
    let mut built = false;
    while head
        .claim_log_max_seq
        .saturating_sub(head.checkpointed_entry_seq())
        >= signer.max_batch
    {
        let start_seq = head.checkpointed_entry_seq().saturating_add(1);
        let end_seq = start_seq.saturating_add(signer.max_batch - 1);
        ensure_claim_log_range_contiguous(connection, start_seq, end_seq, "checkpoint range")?;
        let receipt_bytes = load_claim_tree_canonical_bytes_range(connection, start_seq, end_seq)?
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = head
            .checkpoint_seq()
            .checked_add(1)
            .ok_or_else(|| ReceiptStoreError::Conflict("checkpoint_seq overflow".to_string()))?;
        // O(b) Merkle build; predecessor digest comes from the cached head.
        let checkpoint = chio_kernel::build_checkpoint_with_previous(
            checkpoint_seq,
            start_seq,
            end_seq,
            &receipt_bytes,
            &signer.keypair,
            head.latest_checkpoint.as_ref(),
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        #[cfg(test)]
        if test_hooks::panic_during_checkpoint_build(signer.max_batch) {
            panic!("injected test panic during background checkpoint build");
        }
        #[cfg(test)]
        if test_hooks::fail_checkpoint_build(signer.max_batch) {
            return Err(ReceiptStoreError::Conflict(
                "injected test checkpoint build failure".to_string(),
            ));
        }
        ensure_checkpoint_transparency_guards(connection)?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // The insert returns the checkpoint now persisted at this seq: either
        // the one we just built, or a concurrently committed winner (clock-skew
        // sibling) it validated and adopted. Catch the cached head up to THAT
        // checkpoint so a later verify_head_against_latest_checkpoint does not
        // see our discarded byte-different build diverge from the persisted row.
        let adopted =
            insert_checkpoint_incremental_tx(&tx, head.latest_checkpoint.as_ref(), &checkpoint)?;
        tx.commit()?;
        head.latest_checkpoint = Some(adopted);
        built = true;
    }
    Ok(built)
}

/// Head-resync rule: one indexed delta aggregate plus one
/// latest-checkpoint row read after every Write closure.
fn resync_head_after_write(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let pre_resync_max = head.claim_log_max_seq;
    let (delta_count, post_max) = claim_log_delta_count_and_max_seq(connection, pre_resync_max)?;
    // Validate the ADOPTED resync delta before advancing the head. A Write
    // closure can commit claim_receipt_log_entries rows
    // past this actor's head (another shared-DB writer, or a receipt-appending
    // Write job), and this resync absorbs them via COUNT/MAX. Without
    // validating them, an orphan/divergent row would be trusted and later
    // appends would skip it as already-verified, so a background checkpoint
    // could cover an unaudited entry. Re-validate JUST the
    // (pre_resync_max, post_max] delta against the source receipt tables
    // (O(delta)); the full-log validator is NOT called. Single-writer common
    // case: no other writer, empty delta, no-op. Fail-closed: an
    // orphan/divergent delta returns the error, which the Write arm turns into
    // a poisoned head.
    if delta_count > 0 {
        validate_adopted_claim_log_delta(connection, pre_resync_max, post_max)?;
    }
    head.claim_log_count = head.claim_log_count.saturating_add(delta_count);
    head.claim_log_max_seq = post_max;
    verify_head_against_latest_checkpoint(connection, head)
}

fn commit_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    head_state: &mut WriterHeadState,
    incremental_verification: bool,
    requests: Vec<ReceiptCommitRequest>,
    health: &ReceiptCommitWriterHealth,
) -> Option<ReceiptStoreError> {
    let batch_outcome = match head_state {
        WriterHeadState::Verified(head) => {
            match append_receipt_batch(pool, head, incremental_verification, &requests) {
                Ok(results) => {
                    health.store_head_snapshot(head);
                    Ok(results)
                }
                Err(error) => Err(error),
            }
        }
        WriterHeadState::Poisoned(message) => Ok(receipt_batch_error_results(
            requests.len(),
            poisoned_head_error(message),
        )),
    };
    let results = match batch_outcome {
        Ok(results) => results,
        Err(error) => {
            // A store-wide append fault (a failed checkpoint or predecessor
            // verification, a transaction that will not open, a disk-full commit)
            // rejects every receipt in this batch and will reject every future
            // append until an operator reseeds. Poison the head so the
            // pre-dispatch gate fails closed rather than letting tools run against
            // a store that can no longer persist their receipts.
            let message = error.to_string();
            let results = receipt_batch_error_results(requests.len(), error);
            health.set_head_poisoned(true);
            *head_state = WriterHeadState::Poisoned(message);
            results
        }
    };
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
    // APPEND durability responses fan out here (ADR-0013): a durable append
    // response is never delayed by checkpoint construction. The co-drained
    // Flush waiters are released by the caller AFTER the checkpoint build, so a
    // flush is a genuine checkpoint barrier.
    for (request, result) in requests.into_iter().zip(results) {
        let _ = request.response.send(result);
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

/// Classify commit-writer liveness from a counter snapshot. Kept pure so the
/// wedged / saturated / dead transitions are unit-testable without a live actor.
///
/// - `Dead`: the actor channel has disconnected (its last error reports the
///   writer unavailable). Nothing can drain, so admission must stop.
/// - `Wedged`: work is still queued or running (`inflight > 0`, or more appends
///   were accepted than have completed) and no progress has been made within
///   `stall_threshold_ms`. The stall clock is anchored to the more recent of the
///   last commit and the start of the current backlog, so a writer that wedges
///   before its first commit is caught, while a writer resuming after an idle
///   period (an old last commit but freshly enqueued work) is measured from that
///   fresh work rather than judged wedged the instant it accepts. A timed-out
///   append leaves `inflight` elevated without advancing `failed_total` past
///   `accepted_total`, which is exactly the `inflight` signal this reads.
/// - `Saturated`: the commit channel is full right now (`queue_depth` has
///   reached the channel capacity), so the next send would be rejected. This
///   reads `queue_depth` rather than `inflight` so a drained but still-committing
///   batch, whose slots are already free, does not read as a full channel and
///   deny admission when the next append would in fact be accepted. Deny
///   admission rather than run a side effect whose receipt cannot be enqueued.
/// - `Healthy`: none of the above.
fn classify_writer_liveness(
    counters: &ReceiptWriterCounters,
    stall_threshold_ms: u64,
    channel_capacity: u64,
    backlog_started_unix_ms: Option<u64>,
    now_unix_ms: u64,
) -> chio_kernel::ReceiptWriterLiveness {
    use chio_kernel::ReceiptWriterLiveness as Liveness;
    if counters
        .last_error
        .as_deref()
        .is_some_and(|error| error.contains("unavailable"))
    {
        return Liveness::Dead;
    }
    // A bounded receipt operation that exceeded its budget is direct evidence the
    // writer did not drain within budget, and it leaves `inflight` elevated. That
    // is a stronger, earlier signal than the heuristic stall clock, so a still
    // backlogged writer that has recorded a timeout is wedged immediately rather
    // than admitted during the window between the operation budget and the stall
    // threshold. A later successful batch flush clears `last_error`, so this
    // self-heals once the writer catches up.
    if counters.inflight > 0
        && counters
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("timed out"))
    {
        return Liveness::Wedged;
    }
    let backlogged = counters.inflight > 0
        || counters.accepted_total
            > counters
                .committed_total
                .saturating_add(counters.failed_total);
    // Anchor to the more recent of the last commit and the current backlog
    // start. Using the last commit alone marks a writer wedged after any idle
    // period (its last commit is naturally old); using the backlog start alone
    // would ignore progress a busy writer is still making.
    let progress_reference = counters
        .last_commit_unix_ms
        .into_iter()
        .chain(backlog_started_unix_ms)
        .max();
    let stalled = match progress_reference {
        Some(reference) => now_unix_ms.saturating_sub(reference) >= stall_threshold_ms,
        None => false,
    };
    if backlogged && stalled {
        return Liveness::Wedged;
    }
    if counters.queue_depth >= channel_capacity {
        return Liveness::Saturated;
    }
    Liveness::Healthy
}

/// Fold the writer-liveness verdict into the store's top-level health boolean.
/// A wedged, saturated, or dead writer makes the store unhealthy even when the
/// checkpoint chain is intact and no error has been recorded yet: the
/// pre-dispatch gate is already denying tool calls against that writer, so a
/// health surface that stayed green would contradict it. `Healthy` and the
/// permissive `Unknown` (no async writer, or a read-only observer that cannot
/// see writer liveness) do not downgrade health.
fn receipt_store_healthy(
    checkpoint_healthy: bool,
    writer_last_error: Option<&str>,
    writer_liveness: chio_kernel::ReceiptWriterLiveness,
) -> bool {
    use chio_kernel::ReceiptWriterLiveness as Liveness;
    checkpoint_healthy
        && writer_last_error.is_none()
        && !matches!(
            writer_liveness,
            Liveness::Wedged | Liveness::Saturated | Liveness::Dead
        )
}

#[cfg(test)]
mod writer_liveness_classifier_tests {
    use super::*;
    use chio_kernel::ReceiptWriterLiveness as Liveness;

    const CAPACITY: u64 = RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64;
    const NOW: u64 = 1_000_000;
    const STALL_MS: u64 = 10_000;

    #[test]
    fn timed_out_inflight_append_reports_wedged() {
        // A caller-timed-out append bumps `failed_total` and leaves `inflight`
        // elevated (the actor still owns the queued command), so `accepted_total`
        // equals `failed_total`. The naive `accepted > committed + failed`
        // backlog test misses this; the `inflight` signal must catch it.
        let counters = ReceiptWriterCounters {
            accepted_total: 1,
            failed_total: 1,
            inflight: 1,
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
            Liveness::Wedged
        );
    }

    #[test]
    fn recorded_append_timeout_reports_wedged_before_the_stall_threshold() {
        // A bounded append that exceeded its budget records a "timed out" error
        // and leaves inflight elevated, but the first accept is only 6s old under
        // a 10s stall threshold. The stall clock alone would still report this
        // healthy for the 4s window between the append budget and the stall
        // threshold; the recorded timeout must deny admission on its own, because
        // receipts are known not to be committing durably.
        let counters = ReceiptWriterCounters {
            accepted_total: 1,
            failed_total: 1,
            inflight: 1,
            last_commit_unix_ms: None,
            last_error: Some("sqlite receipt commit append timed out".to_string()),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 6_000), NOW),
            Liveness::Wedged
        );
    }

    #[test]
    fn never_committed_backlog_reports_wedged() {
        // Wedged before the first commit: `last_commit_unix_ms` is `None`, so the
        // stall clock must fall back to the current backlog start.
        let counters = ReceiptWriterCounters {
            accepted_total: 1,
            inflight: 1,
            last_commit_unix_ms: None,
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
            Liveness::Wedged
        );
    }

    #[test]
    fn honors_configured_stall_threshold() {
        // Same backlog with a commit 600ms ago: wedged under a fail-fast 500ms
        // threshold, healthy under a lenient 10s threshold. Proves the threshold
        // is a parameter, not a hardcoded constant.
        let counters = ReceiptWriterCounters {
            accepted_total: 2,
            committed_total: 1,
            inflight: 1,
            last_commit_unix_ms: Some(NOW - 600),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, 500, CAPACITY, None, NOW),
            Liveness::Wedged
        );
        assert_eq!(
            classify_writer_liveness(&counters, 10_000, CAPACITY, None, NOW),
            Liveness::Healthy
        );
    }

    #[test]
    fn full_commit_channel_reports_saturated() {
        // Channel full right now but still committing (recent commit): a new send
        // would be rejected, so admission must be denied even though the writer
        // is not wedged.
        let counters = ReceiptWriterCounters {
            accepted_total: CAPACITY + 5,
            committed_total: 4,
            inflight: CAPACITY,
            queue_depth: CAPACITY,
            last_commit_unix_ms: Some(NOW - 100),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, None, NOW),
            Liveness::Saturated
        );
        assert!(!Liveness::Saturated.healthy());
    }

    #[test]
    fn a_drained_but_committing_batch_is_not_reported_saturated() {
        // The actor has drained a full batch out of the channel and is committing
        // it: `inflight` still counts that batch, but its channel slots are
        // already free, so the next send would succeed. Saturation reads
        // `queue_depth`, so this must classify Healthy rather than Saturated.
        // Reading `inflight` here wrongly denied admission under heavy but
        // healthy load.
        let counters = ReceiptWriterCounters {
            accepted_total: CAPACITY + RECEIPT_GROUP_COMMIT_MAX_BATCH as u64,
            committed_total: 0,
            inflight: CAPACITY,
            queue_depth: CAPACITY - RECEIPT_GROUP_COMMIT_MAX_BATCH as u64,
            last_commit_unix_ms: Some(NOW - 100),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 100), NOW),
            Liveness::Healthy
        );
    }

    #[test]
    fn idle_writer_with_fresh_backlog_is_not_wedged() {
        // After a long idle period the last commit is naturally old, but a newly
        // enqueued write has only just started. The stall clock must anchor to the
        // fresh backlog start, not the stale last commit, or the writer is marked
        // wedged and admission denied the instant it accepts work after a quiet
        // period.
        let counters = ReceiptWriterCounters {
            accepted_total: 6,
            committed_total: 5,
            inflight: 1,
            last_commit_unix_ms: Some(NOW - 60_000),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 100), NOW),
            Liveness::Healthy,
            "fresh work after idle must not be judged wedged by the stale last commit"
        );
        // The same stale commit WITH a backlog that has itself gone unserviced
        // past the threshold is a genuine wedge.
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, Some(NOW - 20_000), NOW),
            Liveness::Wedged,
            "a backlog stalled past the threshold must still report wedged"
        );
    }

    #[test]
    fn unavailable_writer_reports_dead() {
        let counters = ReceiptWriterCounters {
            last_error: Some("sqlite receipt commit actor is unavailable".to_string()),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, None, NOW),
            Liveness::Dead
        );
    }

    #[test]
    fn drained_writer_reports_healthy() {
        let counters = ReceiptWriterCounters {
            accepted_total: 10,
            committed_total: 10,
            inflight: 0,
            last_commit_unix_ms: Some(NOW - 50),
            ..ReceiptWriterCounters::default()
        };
        assert_eq!(
            classify_writer_liveness(&counters, STALL_MS, CAPACITY, None, NOW),
            Liveness::Healthy
        );
    }

    #[test]
    fn a_non_healthy_writer_makes_the_store_unhealthy() {
        // Checkpoint chain intact and no recorded error, but the writer is not
        // making progress: the pre-dispatch gate is denying tool calls, so the
        // top-level health boolean must not stay green.
        assert!(!receipt_store_healthy(true, None, Liveness::Wedged));
        assert!(!receipt_store_healthy(true, None, Liveness::Saturated));
        assert!(!receipt_store_healthy(true, None, Liveness::Dead));
    }

    #[test]
    fn healthy_and_unknown_writers_do_not_downgrade_store_health() {
        assert!(receipt_store_healthy(true, None, Liveness::Healthy));
        // Unknown is the permissive verdict (no async writer, or a read-only
        // observer that cannot see writer liveness).
        assert!(receipt_store_healthy(true, None, Liveness::Unknown));
        // A recorded writer error or an unhealthy checkpoint chain still fails
        // closed regardless of a healthy liveness verdict.
        assert!(!receipt_store_healthy(false, None, Liveness::Healthy));
        assert!(!receipt_store_healthy(
            true,
            Some("checkpoint build failed"),
            Liveness::Healthy
        ));
    }
}

/// Holds the writer `inflight` count for the DURATION of a writer-routed `Write`
/// job. The pre-send increment in `WriterHandle::run_write_kind` is ADOPTED by
/// this guard, so `receipt_store_health` reports `inflight > 0` while a slow or
/// stuck writer-routed op (pool acquire, pre-check, closure, resync) is actually
/// running. The `Write` arm releases it (`drop`) IMMEDIATELY BEFORE each
/// `respond(...)`, so a caller that observes its own response never sees itself
/// still counted inflight, mirroring the Append path, which decrements in
/// `commit_receipt_batch` BEFORE fanning out its results. Still Drop-based, so
/// any exit that panics before a respond runs releases exactly once; a release
/// overlap with the caller's recv-Err compensation under actor-thread death
/// saturates at zero via `atomic_saturating_sub` rather than underflowing.
struct WriterInflightGuard<'a> {
    inflight: &'a AtomicU64,
}

impl<'a> WriterInflightGuard<'a> {
    fn new(inflight: &'a AtomicU64) -> Self {
        Self { inflight }
    }
}

impl Drop for WriterInflightGuard<'_> {
    fn drop(&mut self) {
        atomic_saturating_sub(self.inflight, 1);
    }
}

/// Reconcile a writer-routed `Write` job's health counters. Child receipts
/// and authorization-consuming appends run through
/// `WriterHandle::run_write_receipt`, and metadata-only writes through
/// `run_write`; both are `accepted_total`-counted at enqueue, but their
/// success/failure OUTCOME was never folded into `committed_total` /
/// `failed_total`, so accepted / committed / failed did not reconcile and a
/// store dominated by writer-routed receipts undercounted commits. The actor
/// calls this exactly once per `Write` with the responder's resync-adjusted
/// signal (O(1) per write). A committed outcome also refreshes
/// `last_commit_unix_ms`, mirroring the Append path (`commit_receipt_batch`).
fn record_write_job_outcome(health: &ReceiptCommitWriterHealth, committed: bool) {
    if committed {
        health.committed_total.fetch_add(1, Ordering::SeqCst);
        health
            .last_commit_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        // A committed write proves the writer drained again, so clear a stale
        // bounded-timeout marker exactly as a committed append batch resets
        // `last_error`. A write-dominated store never runs an append batch, so
        // without this the "timed out" marker left by an earlier bounded write
        // lingers and the liveness classifier reports every later merely
        // in-flight write Wedged on that stale marker alone. A genuine writer
        // fault (poisoned head, checkpoint-build failure) does not carry the
        // timeout marker and is left untouched.
        if let Ok(mut last_error) = health.last_error.lock() {
            if last_error
                .as_deref()
                .is_some_and(|error| error.contains("timed out"))
            {
                *last_error = None;
            }
        }
    } else {
        health.failed_total.fetch_add(1, Ordering::SeqCst);
    }
}

/// Background checkpoint signer, installed once by the kernel after `open`
/// and before serving. `max_batch = 0` disables
/// checkpointing (ADR-0008 semantics).
#[derive(Clone)]
pub struct BackgroundCheckpointSigner {
    pub keypair: Arc<Keypair>,
    pub max_batch: u64,
}

/// Last verified position of the receipt chain. Owned exclusively by the
/// commit-actor thread; never shared, never locked.
#[derive(Clone, Debug, Default)]
pub(crate) struct VerifiedHead {
    /// The newest checkpoint the actor has verified, already parsed and
    /// signature-checked once. `None` before the first checkpoint.
    latest_checkpoint: Option<KernelCheckpoint>,
    /// Row count of `claim_receipt_log_entries` as last verified.
    claim_log_count: u64,
    /// MAX(entry_seq) of `claim_receipt_log_entries` as last verified.
    claim_log_max_seq: u64,
}

impl VerifiedHead {
    pub(crate) fn checkpoint_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.checkpoint_seq)
    }

    pub(crate) fn checkpointed_entry_seq(&self) -> u64 {
        self.latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq)
    }
}

/// Writer-actor head snapshot exposed to `flush_report` and diagnostics.
/// Values are read from the health struct's atomics, written
/// only by the actor thread.
pub(crate) struct WriterHeadSnapshot {
    pub(crate) checkpoint_seq: u64,
    pub(crate) checkpointed_entry_seq: u64,
    // Read only by tests (`incremental_append_updates_the_head_and_stays_correct`,
    // `writer_routed_inserts_do_not_false_conflict_the_next_append`): they
    // cross-check the actor-maintained head against a full re-verification.
    // `flush_report` does not need the claim-log counters today.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) claim_log_count: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) claim_log_max_seq: u64,
}

/// Seed the verified head by running the existing FULL verification exactly
/// once (the startup path for the O(N) check; also the audit-repair path).
fn seed_verified_head(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    validate_claim_receipt_log_entries(connection)?;
    let latest_checkpoint = verify_checkpoint_chain_integrity(connection)?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}

/// Cheap head snapshot for `incremental_verification = false` stores: the
/// full per-append verification still runs on that path, so seeding only
/// parses the single latest checkpoint row (one signature check) plus two
/// aggregates. This keeps a suspect database openable for A/B verification.
fn seed_head_snapshot(connection: &Connection) -> Result<VerifiedHead, ReceiptStoreError> {
    let latest_checkpoint = load_latest_persisted_checkpoint_row(connection)?
        .map(parse_persisted_checkpoint_row)
        .transpose()?;
    let (claim_log_count, claim_log_max_seq) = claim_log_delta_count_and_max_seq(connection, 0)?;
    Ok(VerifiedHead {
        latest_checkpoint,
        claim_log_count,
        claim_log_max_seq,
    })
}

/// COUNT/MAX over `entry_seq > floor_entry_seq`: an indexed range scan over
/// the delta only (O(b)). An unscoped COUNT(*) would rescan the whole index
/// and reintroduce O(N). Returns `(delta_count, max_entry_seq)` where the max
/// falls back to `floor_entry_seq` for an empty delta.
fn claim_log_delta_count_and_max_seq(
    connection: &Connection,
    floor_entry_seq: u64,
) -> Result<(u64, u64), ReceiptStoreError> {
    let floor = sqlite_i64(floor_entry_seq, "claim log delta floor entry_seq")?;
    let (count, max_seq) = connection.query_row(
        "SELECT COUNT(*), COALESCE(MAX(entry_seq), ?1) FROM claim_receipt_log_entries WHERE entry_seq > ?1",
        params![floor],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
    )?;
    Ok((
        sqlite_u64(count, "claim log delta count")?,
        sqlite_u64(max_seq, "claim log delta max entry_seq")?,
    ))
}

/// Fail-closed pre-job guard for a RECEIPT-APPENDING writer-routed job (child
/// receipts, authorization-consuming appends). The
/// incremental writer pre-check only re-verified the checkpoint HEAD; it did
/// NOT validate the `claim_receipt_log_entries` rows an out-of-band writer (a
/// second store instance, an operator repair) may have committed AHEAD of this
/// actor's head. Without this guard the job would DURABLY insert its receipt
/// and only afterwards, in `resync_head_after_write`, discover the bad/orphan
/// adopted row and poison the head - a fail-OPEN durable write. Validate the
/// ADOPTED delta (head.claim_log_max_seq, current_max] with the SAME bounded
/// `validate_adopted_claim_log_delta` the append path runs, BEFORE the job
/// commits, so a stale/invalid baseline denies the write with no durable
/// insert. Delta-bounded: single-writer no-stale-head case has an EMPTY delta
/// (pre_delta = 0) and is a no-op, and the full-log validator is NEVER called,
/// so the flat per-append cost holds. Metadata-only writes insert no
/// claim-log rows, so they skip this (appends_receipts = false).
fn validate_writer_adopted_claim_log_baseline(
    connection: &Connection,
    head: &VerifiedHead,
    appends_receipts: bool,
) -> Result<(), ReceiptStoreError> {
    if !appends_receipts {
        return Ok(());
    }
    let (pre_delta, baseline_max) =
        claim_log_delta_count_and_max_seq(connection, head.claim_log_max_seq)?;
    if pre_delta > 0 {
        validate_adopted_claim_log_delta(connection, head.claim_log_max_seq, baseline_max)?;
    }
    Ok(())
}

/// O(1) predecessor check: the persisted latest checkpoint must still match
/// the verified head (one indexed row read + RFC 8785 canonical body digest
/// compare). When the persisted chain has moved FORWARD, verify only the new
/// checkpoints (bounded catch-up); every other divergence is a fail-closed
/// `Conflict` pointing at `chio receipt audit`.
fn verify_head_against_latest_checkpoint(
    connection: &Connection,
    head: &mut VerifiedHead,
) -> Result<(), ReceiptStoreError> {
    let persisted = load_latest_persisted_checkpoint_row(connection)?;
    let cached_seq = head.checkpoint_seq();
    match persisted {
        None if head.latest_checkpoint.is_none() => Ok(()),
        None => Err(ReceiptStoreError::Conflict(
            "latest checkpoint disappeared behind the verified head; run `chio receipt audit`"
                .to_string(),
        )),
        Some(row) if row.checkpoint_seq < cached_seq => Err(ReceiptStoreError::Conflict(format!(
            "checkpoint chain regressed from verified head {cached_seq} to {}; run `chio receipt audit`",
            row.checkpoint_seq
        ))),
        Some(row) if row.checkpoint_seq == cached_seq => {
            let Some(cached) = head.latest_checkpoint.as_ref() else {
                return Err(ReceiptStoreError::Conflict(
                    "checkpoint presence diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            };
            // Body-only deserialize: parse_persisted_checkpoint_row would run
            // chio_kernel::checkpoint::validate_checkpoint and re-verify the
            // signature, putting one Ed25519 verify back on every append. The
            // cached head was signature-checked at seed time.
            let persisted_body: KernelCheckpointBody = serde_json::from_str(&row.statement_json)?;
            let persisted_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&persisted_body)
                .map_err(checkpoint_error_to_receipt_store)?;
            let cached_digest = chio_kernel::checkpoint::checkpoint_body_sha256(&cached.body)
                .map_err(checkpoint_error_to_receipt_store)?;
            if persisted_digest != cached_digest {
                return Err(ReceiptStoreError::Conflict(
                    "latest checkpoint diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            }
            // Full-column tamper catch: the body digest above covers ONLY what
            // statement_json serializes. The kernel_checkpoints row also stores
            // batch_start_seq/batch_end_seq/tree_size/merkle_root/issued_at/
            // kernel_key as their own columns; any one of them corrupted out of
            // band (immutability trigger bypassed) while statement_json is
            // untouched would pass the digest check yet leave a signed-body-bound
            // column diverged. `ensure_checkpoint_columns_match_body` reconciles
            // every such column against the (signature-verified) signed body it
            // is meant to mirror. This is O(1) int/string equality over the one
            // already-read row, NOT a per-append Ed25519 re-verify.
            ensure_checkpoint_columns_match_body(&row, &persisted_body)?;
            // The `signature` column is the signature OVER the body, not a body
            // field, so it is not covered above; compare it against the cached
            // head, which was signature-verified at seed/catch-up time (O(1)
            // string equality, no crypto).
            if row.signature_hex != cached.signature.to_hex() {
                return Err(ReceiptStoreError::Conflict(
                    "latest checkpoint signature column diverged from verified head; run `chio receipt audit`"
                        .to_string(),
                ));
            }
            // Recheck the latest checkpoint's transparency projection rows.
            // The body-digest / column / signature
            // checks above re-verify the `kernel_checkpoints` row on every
            // append, but the projection rows (`checkpoint_tree_heads`,
            // `checkpoint_predecessor_witnesses`,
            // `checkpoint_publication_metadata`) were validated only when this
            // checkpoint was first adopted (seed or catch-up). A projection row
            // tampered out of band (immutability guards momentarily absent, then
            // restored) while the checkpoint seq is UNCHANGED would otherwise be
            // trusted as verified until the next open/health/audit. Rechecking it
            // here closes that gap symmetrically with the per-append column
            // recheck: O(1) (three indexed single-row projection lookups plus an
            // O(1) derivation from the already-parsed checkpoint body, NO
            // batch/leaf scan and NO full-history walk), so the incremental
            // hot path stays flat per append. Fail-closed on any divergence.
            validate_checkpoint_projection_rows(connection, &row, cached)?;
            Ok(())
        }
        Some(row) => catch_up_verified_head_to(connection, head, row.checkpoint_seq),
    }
}

/// Verify and adopt checkpoints `head.checkpoint_seq()+1 ..= latest_seq`.
/// O(new checkpoints): each row is parsed (one signature check), predecessor-
/// linked to the cached head, range-checked against the claim log, AND its
/// transparency projection rows validated before it
/// advances the head. Used when another writer instance (second kernel on the
/// same file, operator CLI) legitimately extended the chain. In the single-
/// writer hot path the head is never behind, so this loop body does not run
/// (zero added per-append cost); each caught-up checkpoint is O(b) for its own
/// batch, never a full-history walk.
fn catch_up_verified_head_to(
    connection: &Connection,
    head: &mut VerifiedHead,
    latest_seq: u64,
) -> Result<(), ReceiptStoreError> {
    let mut cursor = head.checkpoint_seq();
    while cursor < latest_seq {
        let next_seq = cursor.saturating_add(1);
        let Some(row) = load_persisted_checkpoint_row(connection, next_seq)? else {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint chain gap at {next_seq} behind latest {latest_seq}; run `chio receipt audit`"
            )));
        };
        let checkpoint = parse_persisted_checkpoint_row(row.clone())?;
        match head.latest_checkpoint.as_ref() {
            Some(predecessor) => {
                chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                    .map_err(checkpoint_error_to_receipt_store)?;
            }
            None => validate_checkpoint_base(&checkpoint)?,
        }
        validate_checkpoint_against_claim_log(connection, &checkpoint)?;
        // Projection validation before adoption: the
        // catch-up path verified signature + predecessor + claim-log range but
        // not the transparency projection rows that full
        // `verify_checkpoint_chain_integrity` rejects. Adopting a checkpoint with
        // missing/divergent projection rows would advance `head.latest_checkpoint`
        // and let subsequent appends build on an audit-invalid chain. Validate ONLY
        // this adopted checkpoint's projection rows (O(b) for its batch, not full
        // history), fail closed on any divergence.
        validate_checkpoint_projection_rows(connection, &row, &checkpoint)?;
        head.latest_checkpoint = Some(checkpoint);
        cursor = next_seq;
    }
    Ok(())
}

/// Insert one receipt (and, when requested, its lineage statement) within the
/// caller's transaction, returning the claim-log `entry_seq`. Split out of
/// `append_receipt_batch` so each record can run inside its own SAVEPOINT: a
/// per-receipt failure is returned as this record's `Err`
/// instead of aborting the whole coalesced batch. Receipt + lineage stay one
/// unit - a lineage failure returns `Err`, and the caller's savepoint rollback
/// undoes the receipt too, so no receipt-without-lineage state is possible.
fn append_single_receipt_record(
    tx: &rusqlite::Transaction<'_>,
    request: &ReceiptCommitRequest,
) -> Result<u64, ReceiptStoreError> {
    let seq = append_chio_receipt_tx(tx, &request.receipt, &request.raw_json)?;
    if request.ensure_lineage {
        #[cfg(test)]
        if test_hooks::fail_between_receipt_and_lineage() {
            return Err(ReceiptStoreError::Conflict(
                "injected failure between receipt insert and lineage insert".to_string(),
            ));
        }
        ensure_receipt_lineage_statement_for_receipt_id_tx(tx, &request.receipt.id)?;
    }
    Ok(seq)
}

/// Append a coalesced group-commit batch.
///
/// `Err` is a STORE-WIDE fault (pool acquisition, checkpoint or predecessor
/// verification, transaction open/commit, projection drift, a disk-full commit)
/// that rejected the whole batch and will reject every future append until an
/// operator reseeds: the caller poisons the head. `Ok` carries one result per
/// request; a single malformed receipt fails only its own slot via its
/// per-record savepoint and leaves the head intact.
fn append_receipt_batch(
    pool: &Pool<SqliteConnectionManager>,
    head: &mut VerifiedHead,
    incremental_verification: bool,
    requests: &[ReceiptCommitRequest],
) -> Result<Vec<Result<u64, ReceiptStoreError>>, ReceiptStoreError> {
    let mut connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    ensure_checkpoint_transparency_guards(&connection)?;
    if incremental_verification {
        // O(1) predecessor check (+ bounded catch-up), not a chain rebuild.
        verify_head_against_latest_checkpoint(&connection, head)?;
    } else {
        validate_claim_receipt_log_entries(&connection)?;
    }
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(ReceiptStoreError::Sqlite)?;
    if !incremental_verification {
        verify_latest_checkpoint_integrity(&tx)?;
    }
    // Baseline inside the IMMEDIATE tx: rows another store instance committed
    // since our last look are adopted as pre-existing, so the cross-check
    // below measures exactly what THIS batch inserted.
    let (pre_delta, baseline_max) = claim_log_delta_count_and_max_seq(&tx, head.claim_log_max_seq)?;
    // Validate the ADOPTED baseline delta before trusting it. Rows another
    // store instance committed since our last look
    // (head.claim_log_max_seq + 1 ..= baseline_max) are absorbed as
    // pre-existing baseline. A full per-append validation would reject an
    // out-of-band mismatched/orphan claim_receipt_log_entries row
    // in that range. Re-validate JUST that bounded delta against the source
    // receipt tables (O(delta)); the full-log validator is NOT called. In the
    // single-writer hot path the head is never stale, so pre_delta is 0 and
    // this is a no-op (zero added cost).
    if pre_delta > 0 {
        validate_adopted_claim_log_delta(&tx, head.claim_log_max_seq, baseline_max)?;
    }
    let mut results = Vec::with_capacity(requests.len());
    for request in requests {
        #[cfg(test)]
        if test_hooks::panic_during_append_batch(&request.receipt.content_hash) {
            panic!("injected test panic during append batch");
        }
        // Per-record SAVEPOINT: a coalesced group-commit
        // batch mixes independent producers. A per-receipt failure (a conflicting
        // duplicate raw JSON, a lineage insert failure) must fail ONLY that
        // record, not roll back and error every unrelated valid append sharing
        // the same group-commit window. Wrap each record so a failure ROLLBACK TO
        // the savepoint undoes JUST this record's partial work - its receipt row,
        // its projection-trigger claim-log row, and its AUTOINCREMENT entry_seq,
        // which SQLite restores with the savepoint so surviving rows stay
        // contiguous - and the loop continues with the others. Two extra SQL
        // statements per record: O(1) per record, O(b) per batch, never a
        // full-history scan, so the flat per-append cost holds.
        tx.execute_batch("SAVEPOINT chio_append_record")
            .map_err(ReceiptStoreError::Sqlite)?;
        match append_single_receipt_record(&tx, request) {
            Ok(seq) => {
                tx.execute_batch("RELEASE chio_append_record")
                    .map_err(ReceiptStoreError::Sqlite)?;
                results.push(Ok(seq));
            }
            Err(error) => {
                // Fail THIS record closed and undo only its work, then keep going
                // for the others. A savepoint that will not unwind is a
                // transaction-integrity fault, so fail the whole batch closed in
                // that (unexpected) case.
                tx.execute_batch("ROLLBACK TO chio_append_record; RELEASE chio_append_record")
                    .map_err(ReceiptStoreError::Sqlite)?;
                results.push(Err(error));
            }
        }
    }
    // Idempotent duplicates return the existing entry_seq without adding a
    // projection row (append_chio_receipt_tx: ON CONFLICT(receipt_id) DO
    // NOTHING at receipt_store.rs:972, byte-identical duplicate branch at
    // :992-1011). Only entry_seqs beyond the baseline count as new rows, and
    // only DISTINCT ones: two byte-identical receipts landing in a single
    // group-commit batch (a concurrent duplicate append) both return the SAME
    // entry_seq from the idempotent branch while inserting exactly one
    // projection row. Deduplicating the new seqs keeps `inserted` equal to the
    // distinct row count so the cross-check below does not false-trigger the
    // projection-drift Conflict and roll back a valid idempotent batch.
    let inserted = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .filter(|seq| **seq > baseline_max)
        .copied()
        .collect::<std::collections::BTreeSet<u64>>()
        .len() as u64;
    // O(b) projection cross-check over the delta only: the claim-log
    // projection triggers (bootstrap/open.rs:676 tool, :711 child) must have
    // advanced the projection by exactly the rows this batch inserted.
    let (delta_count, post_max) = claim_log_delta_count_and_max_seq(&tx, baseline_max)?;
    if delta_count != inserted || post_max < baseline_max {
        return Err(ReceiptStoreError::Conflict(
            "claim receipt log projection drift on append; run `chio receipt audit`".to_string(),
        ));
    }
    // Validate the NEWLY-projected rows before advancing the head. The
    // count/MAX cross-check above only proves the projection
    // advanced by the right NUMBER of rows; `append_chio_receipt_tx` verifies
    // only the projected `receipt_id`/`raw_json`, so a tampered projection
    // trigger could emit one row per insert whose `timestamp`, `tool_name`, or
    // attribution columns diverge from the source receipt and still pass here.
    // A full per-append validation would reject that drift on the next
    // append; without validating it now the head advances and future
    // appends treat the bad row as already verified. Re-validate JUST the
    // (baseline_max, post_max] delta this batch projected with the same
    // full-field validator (O(delta): the batch inserts a bounded number of
    // rows, so the flat per-append cost holds and the full-log validator is
    // NEVER called). Gated on a non-empty delta (an all-idempotent
    // batch projects nothing, so this is a no-op). Fail-closed: a divergent row
    // returns the Conflict before `tx.commit()`, so the head never advances.
    if delta_count > 0 {
        validate_adopted_claim_log_delta(&tx, baseline_max, post_max)?;
    }
    tx.commit().map_err(ReceiptStoreError::Sqlite)?;
    head.claim_log_count = head
        .claim_log_count
        .saturating_add(pre_delta)
        .saturating_add(delta_count);
    head.claim_log_max_seq = post_max.max(baseline_max);
    Ok(results)
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
        ReceiptStoreError::WriterDead {
            restarts,
            last_error,
        } => ReceiptStoreError::WriterDead {
            restarts: *restarts,
            last_error: last_error.clone(),
        },
    }
}

/// Convert a caught panic payload into a typed, fail-closed error. Panic
/// payloads are almost always `&'static str` (a `panic!("literal")`) or
/// `String` (a formatted `panic!("{}", ..)`); anything else degrades to a
/// generic message rather than unwrapping (house rule: no unwrap/expect in
/// non-test code).
fn receipt_writer_job_panic_error(payload: &(dyn std::any::Any + Send)) -> ReceiptStoreError {
    let message = payload
        .downcast_ref::<&str>()
        .map(|message| (*message).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".to_string());
    ReceiptStoreError::Canonical(format!("receipt writer job panicked: {message}"))
}

/// Panic isolation: `commit_receipt_batch`
/// runs on the single writer thread, so a panic anywhere inside it (append
/// transaction, lineage fold) must not kill that thread. By the time this
/// runs, `requests` has already been moved into the panicking call and dropped
/// during unwind, so the pre-cloned request response senders are the only way
/// left to answer every appender in the batch. The co-drained Flush waiters are
/// NOT moved into the panicking call: they survive
/// the unwind in the actor loop, which fans out the returned error to them
/// after this. This mirrors `receipt_batch_error_results`'s uniform fan-out and
/// the health bookkeeping `commit_receipt_batch` would otherwise have performed
/// itself.
fn fan_out_batch_panic_error(
    health: &ReceiptCommitWriterHealth,
    request_responses: Vec<mpsc::SyncSender<Result<u64, ReceiptStoreError>>>,
    error: ReceiptStoreError,
) -> ReceiptStoreError {
    let batch_len = request_responses.len() as u64;
    health.failed_total.fetch_add(batch_len, Ordering::SeqCst);
    atomic_saturating_sub(&health.inflight, batch_len);
    if let Ok(mut last_error) = health.last_error.lock() {
        *last_error = Some(error.to_string());
    }
    for response in request_responses {
        let _ = response.send(Err(receipt_store_error_snapshot(&error)));
    }
    error
}

#[cfg(test)]
pub(crate) mod test_hooks {
    use std::sync::atomic::{AtomicBool, Ordering};

    /// When set, `append_receipt_batch` fails the batch between the receipt
    /// insert and the lineage ensure, proving the fold is one transaction.
    pub(crate) static FAIL_BETWEEN_RECEIPT_AND_LINEAGE: AtomicBool = AtomicBool::new(false);

    pub(crate) fn fail_between_receipt_and_lineage() -> bool {
        FAIL_BETWEEN_RECEIPT_AND_LINEAGE.load(Ordering::SeqCst)
    }

    /// When set, `maybe_build_checkpoint` panics after computing the
    /// checkpoint body but before opening its write transaction, proving the
    /// background-checkpoint catch_unwind wrap keeps the writer actor alive
    /// and leaves `head.latest_checkpoint` unadvanced. Tests run in parallel
    /// within this binary and this flag is process-global, so the panic is
    /// additionally gated on `PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH`
    /// (a `max_batch` value no other test in this crate uses): a test whose
    /// signer does not use that exact batch size never panics, even if the
    /// flag happens to be `true` while it runs.
    pub(crate) static PANIC_DURING_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

    pub(crate) const PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 5;

    pub(crate) fn panic_during_checkpoint_build(max_batch: u64) -> bool {
        max_batch == PANIC_DURING_CHECKPOINT_BUILD_MARKER_MAX_BATCH
            && PANIC_DURING_CHECKPOINT_BUILD.load(Ordering::SeqCst)
    }

    /// When set, `maybe_build_checkpoint` returns a fail-closed `Err` (a
    /// NON-panic checkpoint-build failure) for a signer using
    /// `FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH`, proving a build failure is
    /// surfaced to a co-drained flush waiter (the flush-as-checkpoint
    /// barrier). It uses a DISTINCT marker from
    /// `PANIC_DURING_CHECKPOINT_BUILD` so the two process-global flags cannot
    /// interfere across the crate's parallel tests.
    pub(crate) static FAIL_CHECKPOINT_BUILD: AtomicBool = AtomicBool::new(false);

    pub(crate) const FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH: u64 = 7;

    pub(crate) fn fail_checkpoint_build(max_batch: u64) -> bool {
        max_batch == FAIL_CHECKPOINT_BUILD_MARKER_MAX_BATCH
            && FAIL_CHECKPOINT_BUILD.load(Ordering::SeqCst)
    }

    /// When set, `append_receipt_batch` panics before inserting the next
    /// request in the batch, proving the append-batch catch_unwind wrap in
    /// `receipt_commit_actor_loop` keeps the writer actor alive and fans out
    /// a typed error to every request in the interrupted batch. Gated on a
    /// `content_hash` marker for the same cross-test isolation reason as
    /// `PANIC_DURING_CHECKPOINT_BUILD` above (this flag is process-global,
    /// and other tests append receipts concurrently in the same binary).
    /// `content_hash`, not `receipt.id`, is the marker: `ChioReceipt::sign`
    /// always overwrites `id` with a content-derived hash
    /// (`prepare_receipt_body_for_signing`), so a caller-chosen `id` string
    /// does not survive signing, but a caller-chosen `content_hash` does.
    pub(crate) static PANIC_DURING_APPEND_BATCH: AtomicBool = AtomicBool::new(false);

    pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID: &str =
        "rcpt-test-hook-panic-during-append-batch";

    /// `sample_receipt_with_id(id)` sets `content_hash: format!("content-{id}")`;
    /// this must match that pattern for `PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID`.
    pub(crate) const PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH: &str =
        "content-rcpt-test-hook-panic-during-append-batch";

    pub(crate) fn panic_during_append_batch(content_hash: &str) -> bool {
        content_hash == PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH
            && PANIC_DURING_APPEND_BATCH.load(Ordering::SeqCst)
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
    /// Reader-pool connection. READS ONLY: every write transaction must go
    /// through `writer_handle().run_write` (single-writer discipline). The
    /// reader pool is asserted read-only by
    /// `reader_pool_never_begins_a_write_transaction` in tests.
    pub(crate) fn connection(&self) -> Result<SqliteStoreConnection, ReceiptStoreError> {
        self.pool
            .get()
            .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
    }

    pub(crate) fn writer_handle(&self) -> WriterHandle {
        WriterHandle {
            sender: self.receipt_commit_actor.sender.clone(),
            health: Arc::clone(&self.receipt_commit_actor.health),
        }
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

    /// Read-only after open (staged-rollout flag).
    #[must_use]
    pub fn incremental_verification_enabled(&self) -> bool {
        self.incremental_verification
    }

    pub(crate) fn writer_head_snapshot(&self) -> WriterHeadSnapshot {
        let health = &self.receipt_commit_actor.health;
        WriterHeadSnapshot {
            checkpoint_seq: health.head_checkpoint_seq.load(Ordering::SeqCst),
            checkpointed_entry_seq: health.head_checkpointed_entry_seq.load(Ordering::SeqCst),
            claim_log_count: health.head_claim_log_count.load(Ordering::SeqCst),
            claim_log_max_seq: health.head_claim_log_max_seq.load(Ordering::SeqCst),
        }
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
        self.append_verified_chio_receipt_record(&receipt, raw_json, false)
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
        ensure_lineage: bool,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor
            .append(receipt.clone(), raw_json.to_string(), ensure_lineage)
    }

    fn append_verified_chio_receipt_record_with_timeout(
        &self,
        receipt: &ChioReceipt,
        raw_json: &str,
        ensure_lineage: bool,
        timeout: Duration,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        self.receipt_commit_actor.append_with_timeout(
            receipt.clone(),
            raw_json.to_string(),
            ensure_lineage,
            timeout,
        )
    }

    /// Best-effort writer liveness derived from the commit-actor counters,
    /// assessed against the operator-configured `stall_threshold`. See
    /// [`classify_writer_liveness`] for the transition rules.
    pub fn writer_liveness(&self, stall_threshold: Duration) -> chio_kernel::ReceiptWriterLiveness {
        classify_writer_liveness(
            &self.receipt_commit_actor.writer_counters(),
            u64::try_from(stall_threshold.as_millis()).unwrap_or(u64::MAX),
            RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64,
            self.receipt_commit_actor.backlog_started_unix_ms(),
            current_unix_ms(),
        )
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
        let raw_json = raw_json.to_string();
        let receipt = receipt.clone();
        let consumption = consumption.clone();
        self.writer_handle().run_write_receipt(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            consume_authorization_receipt_tx(&tx, &consumption)?;
            append_chio_receipt_tx(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        self.receipt_commit_actor.flush()?;
        let wal_checkpoint = Some(self.wal_checkpoint_passive()?);
        self.flush_report(wal_checkpoint)
    }

    /// Rerun the one-time full verification on the writer connection and
    /// adopt the resulting head. This is the `chio receipt audit --repair`
    /// entry point; it is also safe to call on a healthy store.
    pub fn reseed_verified_head(&self) -> Result<(), ReceiptStoreError> {
        let (response, result) = mpsc::sync_channel(1);
        self.receipt_commit_actor.health.note_channel_send();
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::ReseedHead(response))
        {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                self.receipt_commit_actor
                    .health
                    .note_channel_send_rejected();
                return Err(receipt_actor_saturated_error());
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.receipt_commit_actor
                    .health
                    .note_channel_send_rejected();
                // A disconnected admin send is the first observation that the
                // writer is gone. Record the unavailable marker so the next
                // liveness sample reports the writer Dead immediately, rather
                // than staying Healthy until a later append also disconnects.
                self.receipt_commit_actor.health.note_writer_unavailable();
                return Err(receipt_actor_unavailable_error());
            }
        }
        result
            .recv()
            .map_err(|_| receipt_actor_unavailable_error())?
    }

    /// Install the background checkpoint signer. Idempotent per store (a
    /// second call replaces the signer). Until called, the store appends
    /// without producing checkpoints.
    pub fn enable_background_checkpoints(
        &self,
        signer: BackgroundCheckpointSigner,
    ) -> Result<(), ReceiptStoreError> {
        self.receipt_commit_actor.health.note_channel_send();
        match self
            .receipt_commit_actor
            .sender
            .try_send(ReceiptCommitCommand::InstallSigner(signer))
        {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                self.receipt_commit_actor
                    .health
                    .note_channel_send_rejected();
                Err(receipt_actor_saturated_error())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                self.receipt_commit_actor
                    .health
                    .note_channel_send_rejected();
                // See `reseed_verified_head`: a disconnected admin send must
                // flip liveness to Dead now, not on a later append.
                self.receipt_commit_actor.health.note_writer_unavailable();
                Err(receipt_actor_unavailable_error())
            }
        }
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
        let writer_counters = self.receipt_commit_actor.writer_counters();
        let (writer_level, writer_restart_total) =
            self.receipt_commit_actor.writer_health_summary();
        // The authoritative pre-dispatch gate reads the watchdog verdict against
        // the operator-configured stall threshold; this report has no config in
        // scope, so it both labels and folds health against the shipped default.
        let writer_liveness = self.writer_liveness(std::time::Duration::from_millis(
            chio_kernel::DEFAULT_RECEIPT_WRITER_STALL_MS,
        ));
        // A writer that cannot be trusted to persist can never read green. This is
        // the same predicate the pre-dispatch gate denies on, so readiness and the
        // gate never disagree: it covers a wedged, saturated, or dead writer by
        // liveness, a dead or degraded supervised thread by level, and a poisoned
        // verified head via `writer_serving_closed`, where the thread is still
        // Healthy and no batch recorded a `last_error` yet every append is already
        // rejected.
        let healthy = receipt_store_healthy(
            status.healthy,
            writer_counters.last_error.as_deref(),
            writer_liveness,
        ) && !self.receipt_commit_actor.writer_serving_closed()
            && matches!(writer_level, HealthLevel::Healthy);
        let (uncheckpointed_start_seq, uncheckpointed_end_seq) = uncheckpointed_range(
            status.latest_checkpointed_entry_seq,
            status.latest_committed_entry_seq,
        );
        Ok(ReceiptStoreHealthReport {
            healthy,
            writer: writer_counters,
            writer_liveness: writer_liveness.as_label().to_string(),
            latest_committed_entry_seq: status.latest_committed_entry_seq,
            latest_checkpoint_seq: status.latest_checkpoint_seq,
            latest_checkpointed_entry_seq: status.latest_checkpointed_entry_seq,
            uncheckpointed_start_seq,
            uncheckpointed_end_seq,
            checkpoint_error: status.checkpoint_error,
            db_size_bytes: self.db_size_bytes().ok(),
            writer_level,
            writer_restart_total,
        })
    }

    /// Whether the commit writer can no longer be trusted to persist receipts, so
    /// the kernel pre-dispatch gate must deny before a tool executes. True when the
    /// supervised writer thread has left the healthy state, and also when the
    /// writer's verified head is poisoned: the thread is alive but every append is
    /// rejected until an operator reseeds.
    pub fn writer_serving_closed(&self) -> bool {
        self.receipt_commit_actor.writer_serving_closed()
    }

    /// Sample receipt-store health from a READ-ONLY connection.
    ///
    /// The SIEM serve-mode watchdog observes a receipt DB the kernel owns; it
    /// must not create it, switch it to WAL, or spin a writer pool on it,
    /// matching the read-only receipt-polling contract. `open` does all three, so
    /// it cannot be used on a read-only mount and would create an empty DB on a
    /// mistyped path. This opens a single READ_ONLY connection instead: a missing
    /// file reports `NotFound` rather than being created, and a read-only mount
    /// is sampled without any write attempt.
    ///
    /// A read-only observer cannot see the owning writer's in-memory counters, so
    /// `writer` is defaulted; the checkpoint-progress fields the watchdog gauges
    /// consume (committed/checkpointed seqs and the uncheckpointed range) are
    /// computed from the read connection with the same helpers as
    /// `receipt_store_health`.
    pub fn receipt_store_health_read_only(
        path: &Path,
    ) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        let connection = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::CannotOpen) {
                ReceiptStoreError::NotFound(format!(
                    "receipt database {} does not exist",
                    path.display()
                ))
            } else {
                ReceiptStoreError::Sqlite(error)
            }
        })?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        // Catch a checkpoint-chain-integrity failure into a report with the
        // checkpoint_error set rather than propagating Err. The watchdog samples
        // this on a fixed interval; if corruption made this return Err, the
        // sampler would log-and-skip with NO gauge update, so a corrupt store
        // would look silent instead of alarming. Mirror the
        // fail-open shape of `receipt_checkpoint_status` so the watchdog still
        // emits a large-backlog gauge (checkpointed defaults to 0 -> the
        // uncheckpointed range spans the whole committed log) with the
        // checkpoint_error attached.
        match verify_checkpoint_chain_integrity(&connection) {
            Ok(latest) => {
                let latest_checkpoint_seq = latest
                    .as_ref()
                    .map(|checkpoint| checkpoint.body.checkpoint_seq);
                let latest_checkpointed_entry_seq = latest
                    .as_ref()
                    .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
                let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
                    uncheckpointed_range(latest_checkpointed_entry_seq, latest_committed_entry_seq);
                Ok(ReceiptStoreHealthReport {
                    healthy: latest_committed_entry_seq >= latest_checkpointed_entry_seq,
                    writer: ReceiptWriterCounters::default(),
                    // A read-only observer cannot see the owning writer's
                    // in-memory liveness, so it is reported as unknown.
                    writer_liveness: chio_kernel::ReceiptWriterLiveness::Unknown
                        .as_label()
                        .to_string(),
                    latest_committed_entry_seq,
                    latest_checkpoint_seq,
                    latest_checkpointed_entry_seq,
                    uncheckpointed_start_seq,
                    uncheckpointed_end_seq,
                    checkpoint_error: None,
                    db_size_bytes: None,
                    // A read-only observer cannot see the owning writer's supervisor.
                    writer_level: HealthLevel::default(),
                    writer_restart_total: 0,
                })
            }
            Err(error) => {
                let (uncheckpointed_start_seq, uncheckpointed_end_seq) =
                    uncheckpointed_range(0, latest_committed_entry_seq);
                Ok(ReceiptStoreHealthReport {
                    healthy: false,
                    writer: ReceiptWriterCounters::default(),
                    writer_liveness: chio_kernel::ReceiptWriterLiveness::Unknown
                        .as_label()
                        .to_string(),
                    latest_committed_entry_seq,
                    latest_checkpoint_seq: None,
                    latest_checkpointed_entry_seq: 0,
                    uncheckpointed_start_seq,
                    uncheckpointed_end_seq,
                    checkpoint_error: Some(error.to_string()),
                    db_size_bytes: None,
                    writer_level: HealthLevel::default(),
                    writer_restart_total: 0,
                })
            }
        }
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
        let keypair = keypair.clone();
        self.writer_handle().run_write(move |connection| {
            validate_claim_receipt_log_entries(connection)?;
            create_next_receipt_checkpoint_atomic(connection, max_batch, &keypair)
        })
    }

    fn flush_report(
        &self,
        wal_checkpoint: Option<ReceiptWalCheckpointReport>,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        let head = self.writer_head_snapshot();
        let connection = self.connection()?;
        let latest_committed_entry_seq = latest_claim_log_entry_seq(&connection)?;
        // The writer head snapshot is only refreshed by this handle's own
        // appends/writes. When another store instance or the operator CLI
        // extends the checkpoint chain and this handle has had no intervening
        // local write, the head atomics are stale and would overstate the
        // uncheckpointed range. Read the persisted checkpoint head from the DB
        // (read-only reader-pool query, not a writer-head mutation) and take
        // the higher of the two so the report reflects the current chain.
        // Only trust the persisted latest checkpoint if its signed body
        // VERIFIES: `parse_persisted_checkpoint_row` checks
        // column/body agreement AND the signature, so a tampered or out-of-band
        // row with an inflated `batch_end_seq` cannot make the flush report a
        // false `checkpointed_entry_seq` and hide the uncheckpointed range. On a
        // verification failure fall back to ONLY the actor's verified head (via
        // the `.max` below). Reader-pool READ, no write; single latest-row
        // body verification, not a full chain verify.
        //
        // Chain-connectivity guard: a single-row parse
        // does NOT catch a latest checkpoint that individually verifies yet is
        // DISCONNECTED from the chain (skipped `checkpoint_seq` or wrong
        // predecessor), which a full `verify_checkpoint_chain_integrity`
        // catches. Additionally require
        // the latest checkpoint to link to its immediate predecessor before
        // trusting its `batch_end_seq`; a disconnected latest is dropped (fall
        // back to the actor's verified head). This is a bounded O(1) predecessor
        // read on the operator/health surface, NOT a full O(N) chain walk on the
        // per-append hot path.
        //
        // Claim-log content guard: a separate process
        // advancing `kernel_checkpoints` on a shared DB can persist a latest row
        // that parses (columns match its signed body) AND links to its predecessor
        // yet whose `merkle_root`/`tree_size`/`batch_end_seq` describe a batch this
        // database's `claim_receipt_log_entries` never actually contained (an
        // imported/foreign checkpoint). A full `verify_checkpoint_chain_integrity`
        // rebuilds the checkpoint Merkle range from the local claim log; without
        // that content check here an
        // inflated `batch_end_seq` would make this report advertise a false
        // `checkpointed_entry_seq` and hide the uncheckpointed range. Rebuild the
        // latest checkpoint's Merkle range from the LOCAL claim log and drop it on
        // mismatch (fall back to the actor's verified head). Bounded O(b) over the
        // single latest checkpoint's own batch on the operator/health surface, NOT
        // a full O(N) chain walk on the per-append hot path.
        let verified_persisted = load_latest_persisted_checkpoint_row(&connection)?
            .and_then(|row| parse_persisted_checkpoint_row(row).ok())
            .filter(|checkpoint| {
                latest_checkpoint_is_chain_connected(&connection, checkpoint).is_ok()
                    && validate_checkpoint_against_claim_log(&connection, checkpoint).is_ok()
            });
        let persisted_checkpoint_seq = verified_persisted
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.checkpoint_seq);
        let persisted_checkpointed_entry_seq = verified_persisted
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        let checkpoint_seq = head.checkpoint_seq.max(persisted_checkpoint_seq);
        let latest_checkpointed_entry_seq = head
            .checkpointed_entry_seq
            .max(persisted_checkpointed_entry_seq);
        let latest_checkpoint_seq = (checkpoint_seq > 0).then_some(checkpoint_seq);
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
            log_frames: wal_checkpoint_frame_count(log_frames, "wal checkpoint log frames")?,
            checkpointed_frames: wal_checkpoint_frame_count(
                checkpointed_frames,
                "wal checkpointed frames",
            )?,
        })
    }
}

/// `PRAGMA wal_checkpoint` reports -1 for the log/checkpointed frame columns
/// when there is nothing to checkpoint (an already-empty WAL). Under
/// concurrent `flush_receipt_writes()` callers this is routine: one caller's
/// PASSIVE checkpoint truncates the WAL, and a second caller racing right
/// behind it observes the now-empty WAL and gets -1/-1 from SQLite even
/// though `busy` is 0 (success). That is success-with-nothing-to-do, not an
/// error, so it is normalized to 0 rather than rejected by `sqlite_u64`.
fn wal_checkpoint_frame_count(value: i64, field: &str) -> Result<u64, ReceiptStoreError> {
    if value == -1 {
        return Ok(0);
    }
    sqlite_u64(value, field)
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

    #[test]
    fn writer_health_starts_with_a_poisoned_head_until_seeding_clears_it() {
        // The commit writer seeds its verified head asynchronously on the actor
        // thread. Until that seed succeeds, durable persistence is unproven, so a
        // freshly constructed health mirror must report a poisoned head. Starting
        // open would let a corrupt or still-attaching store pass
        // `writer_serving_closed` and execute a tool before its first append can
        // reject, which is exactly the fail-open window the pre-dispatch gate
        // exists to prevent.
        let health = ReceiptCommitWriterHealth::default();
        assert!(
            health.head_poisoned.load(Ordering::SeqCst),
            "writer health must start head-poisoned (serving closed) until a seeded head clears it"
        );
    }

    /// A supervised writer that parks until shutdown, for actor send-path tests that
    /// drive the channel directly and do not need a real commit loop consuming it.
    fn idle_writer() -> SupervisedThread {
        SupervisedThread::spawn(
            SupervisorConfig {
                name: "test-idle-writer",
                tcb_critical: true,
                trip_after: 1,
                max_restarts: 1,
                base_backoff: Duration::from_millis(1),
                max_backoff: Duration::from_millis(1),
            },
            |shutdown| {
                while !shutdown.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                SupervisedOutcome::Shutdown
            },
        )
    }

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
        let actor = ReceiptCommitActor {
            sender,
            health,
            writer: idle_writer(),
        };

        let error = actor.append(actor_test_receipt()?, "{}".to_string(), false);

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
        let actor = ReceiptCommitActor {
            sender,
            health,
            writer: idle_writer(),
        };

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

    #[test]
    fn append_with_timeout_maps_to_timeout_and_keeps_inflight_elevated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A commit actor whose worker never drains: try_send queues the command,
        // but no reply ever arrives, so the bounded wait elapses.
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor {
            sender,
            health,
            writer: idle_writer(),
        };
        let inflight_before = actor.health.inflight.load(Ordering::SeqCst);

        let start = std::time::Instant::now();
        let error = actor.append_with_timeout(
            actor_test_receipt()?,
            "{}".to_string(),
            false,
            Duration::from_millis(250),
        );
        assert!(start.elapsed() < Duration::from_secs(2));

        match error.err().ok_or("expected append timeout error")? {
            ReceiptStoreError::Timeout { operation, .. } => {
                assert_eq!(operation, "sqlite receipt commit append");
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        // The timeout side must not decrement inflight; ownership stays with the
        // actor, so a genuinely wedged writer keeps inflight elevated.
        assert_eq!(
            actor.health.inflight.load(Ordering::SeqCst),
            inflight_before + 1
        );
        assert!(actor.health.failed_total.load(Ordering::SeqCst) >= 1);
        Ok(())
    }

    #[test]
    fn enqueue_on_a_disconnected_actor_records_writer_dead(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The commit actor has exited, so its receiver is gone and `try_send`
        // fails Disconnected before any response channel exists. That enqueue
        // path must record the writer death, or the next liveness sample keeps
        // reporting the writer Healthy and admits a tool side effect whose
        // receipt can never be persisted.
        let (sender, receiver) = receipt_commit_channel();
        drop(receiver);
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let actor = ReceiptCommitActor {
            sender,
            health,
            writer: idle_writer(),
        };

        let error = actor.append_with_timeout(
            actor_test_receipt()?,
            "{}".to_string(),
            false,
            Duration::from_millis(250),
        );
        assert!(error
            .err()
            .ok_or("expected writer-unavailable error")?
            .to_string()
            .contains("unavailable"));

        let counters = actor.writer_counters();
        assert!(
            counters
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("unavailable")),
            "the disconnected enqueue must record the writer death"
        );
        assert_eq!(
            classify_writer_liveness(
                &counters,
                10_000,
                RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64,
                None,
                1_000_000,
            ),
            chio_kernel::ReceiptWriterLiveness::Dead,
            "a disconnected writer must classify as Dead so admission stops"
        );
        Ok(())
    }

    #[test]
    fn note_accept_restamps_backlog_start_only_on_a_fresh_backlog() {
        let health = ReceiptCommitWriterHealth::default();

        // 0 -> 1 begins a backlog and stamps a real start time.
        health.note_accept(0);
        assert_ne!(
            health.backlog_started_unix_ms.load(Ordering::SeqCst),
            0,
            "the first enqueue of a backlog must stamp its start"
        );

        // 1 -> 2 grows an ongoing backlog and must NOT move its start.
        health.backlog_started_unix_ms.store(1, Ordering::SeqCst);
        health.note_accept(1);
        assert_eq!(
            health.backlog_started_unix_ms.load(Ordering::SeqCst),
            1,
            "a growing backlog must keep its original start"
        );

        // 0 -> 1 after the writer drained begins a NEW backlog and restamps.
        health.backlog_started_unix_ms.store(1, Ordering::SeqCst);
        health.note_accept(0);
        assert_ne!(
            health.backlog_started_unix_ms.load(Ordering::SeqCst),
            1,
            "a fresh backlog after draining must restamp the start"
        );
    }

    #[test]
    fn committed_write_clears_a_stale_bounded_timeout_marker() {
        let health = ReceiptCommitWriterHealth::default();
        // An earlier bounded writer-routed op timed out and left the marker set
        // while its work was still in flight.
        if let Ok(mut last_error) = health.last_error.lock() {
            *last_error = Some("sqlite receipt commit write timed out".to_string());
        }
        // The writer catches up and a later write commits.
        record_write_job_outcome(&health, true);
        let cleared = match health.last_error.lock() {
            Ok(guard) => guard.is_none(),
            Err(_) => false,
        };
        assert!(
            cleared,
            "a committed write must clear the stale timeout marker so a later merely in-flight write is not misclassified Wedged"
        );
        assert_eq!(health.committed_total.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn committed_write_preserves_a_genuine_writer_error() {
        let health = ReceiptCommitWriterHealth::default();
        // A poisoned-head / checkpoint fault is not a stall marker and must
        // survive a later commit so the store keeps reporting the real fault.
        if let Ok(mut last_error) = health.last_error.lock() {
            *last_error = Some("receipt store verified head is unavailable".to_string());
        }
        record_write_job_outcome(&health, true);
        let preserved = match health.last_error.lock() {
            Ok(guard) => guard.as_deref() == Some("receipt store verified head is unavailable"),
            Err(_) => false,
        };
        assert!(
            preserved,
            "a committed write must not clear an unrelated writer error"
        );
    }

    #[test]
    fn run_write_receipt_with_timeout_fails_closed_when_writer_never_drains(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Child receipts persist through `run_write_receipt`. Its bounded variant
        // must fail closed on a wedged writer instead of blocking the caller (and
        // the kernel-wide receipt write lock it holds) forever.
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
        };
        let inflight_before = health.inflight.load(Ordering::SeqCst);

        let start = std::time::Instant::now();
        let error =
            handle.run_write_receipt_with_timeout(|_connection| Ok(()), Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(2));

        match error.err().ok_or("expected write timeout error")? {
            ReceiptStoreError::Timeout { operation, .. } => {
                assert_eq!(operation, "sqlite receipt commit write");
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        // Ownership of the queued job stays with the actor, so the timeout side
        // must leave inflight elevated (the honest wedged-writer signal).
        assert_eq!(health.inflight.load(Ordering::SeqCst), inflight_before + 1);
        assert!(health.failed_total.load(Ordering::SeqCst) >= 1);
        Ok(())
    }

    #[test]
    fn run_write_with_timeout_fails_closed_when_writer_never_drains(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The hot-path capability snapshot persists through `run_write_with_timeout`.
        // Its bounded metadata variant must fail closed on a wedged writer instead
        // of blocking the caller forever.
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
        };
        let inflight_before = health.inflight.load(Ordering::SeqCst);

        let start = std::time::Instant::now();
        let error = handle.run_write_with_timeout(|_connection| Ok(()), Duration::from_millis(250));
        assert!(start.elapsed() < Duration::from_secs(2));

        match error.err().ok_or("expected write timeout error")? {
            ReceiptStoreError::Timeout { operation, .. } => {
                assert_eq!(operation, "sqlite receipt commit write");
            }
            other => {
                return Err(
                    std::io::Error::other(format!("expected timeout error, got {other}")).into(),
                );
            }
        }
        // Ownership of the queued job stays with the actor, so the timeout side
        // must leave inflight elevated (the honest wedged-writer signal).
        assert_eq!(health.inflight.load(Ordering::SeqCst), inflight_before + 1);
        assert!(health.failed_total.load(Ordering::SeqCst) >= 1);
        Ok(())
    }

    #[test]
    fn disconnected_bounded_write_records_writer_death_for_liveness(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // The commit actor accepts a bounded child-receipt write, then dies
        // without responding, disconnecting the caller's response channel. The
        // write must record the writer death so the next pre-dispatch liveness
        // sample reports the writer Dead and denies admission, instead of
        // sampling Healthy once inflight is compensated and failed_total matches
        // accepted_total.
        let (sender, receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
        };
        // Actor thread: take the one queued command and drop it (die mid-flight),
        // which drops the deferred responder and disconnects the caller.
        let actor = std::thread::spawn(move || {
            if let Ok(command) = receiver.recv() {
                drop(command);
            }
            drop(receiver);
        });

        let error =
            handle.run_write_receipt_with_timeout(|_connection| Ok(()), Duration::from_secs(5));
        actor.join().map_err(|_| "actor thread panicked")?;
        assert!(error.is_err(), "a disconnected writer must fail closed");

        let counters = ReceiptCommitActor {
            sender: receipt_commit_channel().0,
            health: Arc::clone(&health),
            writer: idle_writer(),
        }
        .writer_counters();
        assert!(
            counters
                .last_error
                .as_deref()
                .is_some_and(|reason| reason.contains("unavailable")),
            "writer death must be recorded for the liveness probe"
        );
        assert_eq!(
            classify_writer_liveness(
                &counters,
                10_000,
                RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY as u64,
                None,
                current_unix_ms(),
            ),
            chio_kernel::ReceiptWriterLiveness::Dead
        );
        Ok(())
    }

    #[test]
    fn disconnected_reseed_flips_writer_liveness_dead_immediately(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A disconnected admin send (reseed after the commit actor has already
        // exited) is the first observation that the writer is gone. It must flip
        // liveness to Dead now, so the pre-dispatch gate denies admission before
        // a later append reconfirms the death.
        let path = std::env::temp_dir().join(format!(
            "chio-reseed-dead-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut store = SqliteReceiptStore::open(&path)?;

        // Replace the live commit actor with one whose receiver is dropped, so
        // the next admin send observes a dead actor. Overwriting the field drops
        // the original sender, letting the original actor thread exit cleanly.
        let (sender, receiver) = receipt_commit_channel();
        drop(receiver);
        store.receipt_commit_actor = ReceiptCommitActor {
            sender,
            health: Arc::new(ReceiptCommitWriterHealth::default()),
            writer: idle_writer(),
        };

        let error = match store.reseed_verified_head() {
            Ok(()) => return Err("reseed against a dead actor must fail closed".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unavailable"));

        assert_eq!(
            store.writer_liveness(Duration::from_secs(60)),
            chio_kernel::ReceiptWriterLiveness::Dead,
            "a disconnected reseed must flip writer liveness to Dead immediately"
        );

        let _ = std::fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn run_write_executes_jobs_serially_on_the_writer_thread(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-run-write-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        let first_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;
        let second_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;

        assert_eq!(
            first_thread, second_thread,
            "all write jobs must run on the single writer thread"
        );
        assert_ne!(
            first_thread,
            std::thread::current().id(),
            "write jobs must not run on the caller thread"
        );

        // The closure really gets a usable writer connection.
        let journal_mode = writer.run_write(|connection| {
            connection
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .map_err(ReceiptStoreError::from)
        })?;
        assert!(journal_mode.eq_ignore_ascii_case("wal"));

        // Inflight accounting drains back to zero after the jobs complete.
        assert_eq!(
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst),
            0
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn run_write_fails_closed_when_queue_is_full() -> Result<(), Box<dyn std::error::Error>> {
        let (sender, _receiver) = receipt_commit_channel();
        let health = Arc::new(ReceiptCommitWriterHealth::default());
        for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
            let (response, _result) = mpsc::sync_channel(1);
            sender.try_send(ReceiptCommitCommand::Flush(response))?;
        }
        let handle = WriterHandle {
            sender,
            health: Arc::clone(&health),
        };

        let error = handle.run_write(|_connection| Ok(()));

        assert!(error
            .err()
            .ok_or("expected queue saturation error")?
            .to_string()
            .contains("sqlite receipt commit queue saturated"));
        assert_eq!(
            health.inflight.load(Ordering::SeqCst),
            0,
            "speculative inflight increment must be undone on saturation"
        );
        assert_eq!(health.saturated_total.load(Ordering::SeqCst), 1);
        Ok(())
    }

    /// A writer-routed `Write` job (liability write, manual checkpoint creation)
    /// must keep `writer_inflight` nonzero for the DURATION of the job, not just
    /// at enqueue, so a health poll during a slow or stuck Write does not report
    /// `inflight: 0` and hide active writer work. The `WriterInflightGuard`
    /// holds the count until the job completes, mirroring the Append path.
    #[test]
    fn write_job_holds_inflight_for_its_duration() -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-write-inflight-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        // Drain any open-time writer activity to a known baseline before running
        // the coordinated job.
        let drained_baseline = wait_until(|| {
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst)
                == 0
        });
        assert!(drained_baseline, "writer failed to drain to baseline");

        // Coordinate a Write job that blocks inside its closure until released.
        let (started_tx, started_rx) = mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
        let worker = std::thread::spawn(move || {
            writer.run_write(move |_connection| {
                // Signal that the job is now executing on the writer thread, then
                // block until the test releases it.
                let _ = started_tx.send(());
                let _ = release_rx.recv();
                Ok(())
            })
        });

        // The job is running: inflight must be nonzero for the DURATION of the
        // Write, not merely at enqueue.
        started_rx.recv().map_err(|_| "write job never started")?;
        assert_eq!(
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst),
            1,
            "a running Write job must report inflight > 0"
        );

        // Release the job and confirm inflight drains back to baseline. The
        // `WriterInflightGuard` decrements just BEFORE the caller's response is
        // delivered, so this is already at baseline once the worker join
        // returns; poll defensively regardless.
        release_tx.send(())?;
        worker
            .join()
            .map_err(|_| "write worker thread panicked")??;
        let drained = wait_until(|| {
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst)
                == 0
        });
        assert!(
            drained,
            "inflight must return to baseline after the Write completes"
        );

        let _ = fs::remove_file(path);
        Ok(())
    }

    /// The `WriterInflightGuard` decrement must be SYNCHRONOUS with
    /// caller-return: the guard drops IMMEDIATELY BEFORE each `respond(...)`,
    /// matching the Append path's decrement-then-fan-out ordering
    /// (`commit_receipt_batch`), so caller-return implies the decrement already
    /// happened. If the guard instead dropped at the END of the Write arm (after
    /// `respond(...)` unblocked `run_write`), a caller could return while
    /// `inflight` was still counted, the exact window that would make
    /// `run_write_executes_jobs_serially_on_the_writer_thread` intermittently
    /// observe `inflight == 1`. This asserts the guarantee DIRECTLY and
    /// deterministically (no `wait_until`): right after `run_write` returns,
    /// `inflight` reads 0 on every one of many iterations.
    #[test]
    fn write_decrements_inflight_before_returning_to_caller(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "chio-write-inflight-order-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = SqliteReceiptStore::open(&path)?;
        let writer = store.writer_handle();

        // Drain any open-time writer activity to a known baseline first.
        let drained_baseline = wait_until(|| {
            store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst)
                == 0
        });
        assert!(drained_baseline, "writer failed to drain to baseline");

        // Many iterations to expose the ordering race: if the guard dropped
        // AFTER the response reached the caller (while the writer thread still
        // had the head snapshot, error clear, connection drop and catch-up build
        // to run), this load could intermittently observe 1. Because the
        // decrement precedes the response, caller-return happens-before this
        // load and it must read 0 on EVERY iteration with no polling.
        for iteration in 0..512 {
            writer.run_write(|_connection| Ok(()))?;
            let observed = store
                .receipt_commit_actor
                .health
                .inflight
                .load(Ordering::SeqCst);
            assert_eq!(
                observed, 0,
                "caller returned from run_write with inflight still counted \
                 (iteration {iteration}); the decrement must precede the response"
            );
        }

        let _ = fs::remove_file(path);
        Ok(())
    }

    /// Poll `predicate` for up to ~1s (1ms steps), returning whether it held.
    fn wait_until(predicate: impl Fn() -> bool) -> bool {
        for _ in 0..1_000 {
            if predicate() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        predicate()
    }
}
