use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::Keypair;
use chio_core::receipt::body::ChioReceipt;
use chio_core::receipt::lineage::ChildRequestReceipt;
use chio_core::session::{
    CreateElicitationOperation, CreateElicitationResult, CreateMessageOperation,
    CreateMessageResult, OperationContext, RequestId, RootDefinition, ToolCallOperation,
};
use chio_kernel::budget_store::{
    BudgetAuthorizeMutationOutcome, BudgetEventAuthority, BudgetMutationKind, BudgetMutationRecord,
};
use chio_kernel::{
    BudgetStore, BudgetStoreError, BudgetUsageRecord, ChioKernel, InMemoryBudgetStore,
    KernelConfig, KernelError, NestedFlowBridge, NestedFlowClient, PeerCapabilities, ReceiptStore,
    ReceiptStoreError, RuntimeAdmissionContext, RuntimeAdmissionDecision, RuntimeAdmissionHook,
    ToolCallRequest, ToolCallResponse, ToolServerConnection, Verdict,
    DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
};
use chio_store_sqlite::{SqliteBudgetStore, SqliteReceiptStore};

const SERVER_ID: &str = "dst-server";
const TOOL_NAME: &str = "mutate";
const GRANT_INDEX: usize = 0;
const PRE_DISPATCH_DROP_REASON: &str =
    "tool evaluation future dropped before dispatch with cleanup fault";
const POST_DISPATCH_DROP_REASON: &str = "tool evaluation future dropped after admission";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EpisodeClass {
    PreDispatchClean,
    PreDispatchAdmissionReleaseFault,
    PreDispatchBudgetReversalFault,
    PostDispatchClean,
    PostDispatchLongServerWait,
    CompleteAllow,
    CompleteReceiptFault,
    BudgetAdmissionFault,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EvaluationMode {
    DropAfterPolls(u32),
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultPlan {
    pub seed: u64,
    pub class: EpisodeClass,
    mode: EvaluationMode,
    server_pending_polls: u32,
    fail_receipt_append: Option<u64>,
    fail_budget_mutation: Option<u64>,
    fail_admission_release: bool,
}

impl FaultPlan {
    #[must_use]
    pub fn from_seed(seed: u64) -> Self {
        let mixed = splitmix64(seed);
        let server_pending_polls = 1 + ((mixed >> 8) % 4) as u32;
        let class = match seed % 8 {
            0 => EpisodeClass::PreDispatchClean,
            1 => EpisodeClass::PreDispatchAdmissionReleaseFault,
            2 => EpisodeClass::PreDispatchBudgetReversalFault,
            3 => EpisodeClass::PostDispatchClean,
            4 => EpisodeClass::PostDispatchLongServerWait,
            5 => EpisodeClass::CompleteAllow,
            6 => EpisodeClass::CompleteReceiptFault,
            _ => EpisodeClass::BudgetAdmissionFault,
        };
        match class {
            EpisodeClass::PreDispatchClean => Self {
                seed,
                class,
                mode: EvaluationMode::DropAfterPolls(1),
                server_pending_polls,
                fail_receipt_append: None,
                fail_budget_mutation: None,
                fail_admission_release: false,
            },
            EpisodeClass::PreDispatchAdmissionReleaseFault => Self {
                seed,
                class,
                mode: EvaluationMode::DropAfterPolls(1),
                server_pending_polls,
                fail_receipt_append: None,
                fail_budget_mutation: None,
                fail_admission_release: true,
            },
            EpisodeClass::PreDispatchBudgetReversalFault => Self {
                seed,
                class,
                mode: EvaluationMode::DropAfterPolls(1),
                server_pending_polls,
                fail_receipt_append: None,
                fail_budget_mutation: Some(2),
                fail_admission_release: false,
            },
            EpisodeClass::PostDispatchClean | EpisodeClass::PostDispatchLongServerWait => Self {
                seed,
                class,
                mode: EvaluationMode::DropAfterPolls(2),
                server_pending_polls: if class == EpisodeClass::PostDispatchLongServerWait {
                    server_pending_polls + 4
                } else {
                    server_pending_polls
                },
                fail_receipt_append: None,
                fail_budget_mutation: None,
                fail_admission_release: false,
            },
            EpisodeClass::CompleteAllow => Self {
                seed,
                class,
                mode: EvaluationMode::Complete,
                server_pending_polls,
                fail_receipt_append: None,
                fail_budget_mutation: None,
                fail_admission_release: false,
            },
            EpisodeClass::CompleteReceiptFault => Self {
                seed,
                class,
                mode: EvaluationMode::Complete,
                server_pending_polls,
                fail_receipt_append: Some(1),
                fail_budget_mutation: None,
                fail_admission_release: false,
            },
            EpisodeClass::BudgetAdmissionFault => Self {
                seed,
                class,
                mode: EvaluationMode::Complete,
                server_pending_polls,
                fail_receipt_append: None,
                fail_budget_mutation: Some(1),
                fail_admission_release: false,
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TraceKind {
    ReceiptPersisted { allow: bool },
    ResponseReturned { verdict: Verdict },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TraceEvent {
    tick: u64,
    kind: TraceKind,
}

#[derive(Default)]
struct LogicalTrace {
    clock: AtomicU64,
    events: Mutex<Vec<TraceEvent>>,
}

impl LogicalTrace {
    fn record(&self, kind: TraceKind) -> Result<(), String> {
        let tick = self.clock.fetch_add(1, Ordering::SeqCst) + 1;
        let mut events = self
            .events
            .lock()
            .map_err(|_| "DST trace lock poisoned".to_string())?;
        events.push(TraceEvent { tick, kind });
        Ok(())
    }

    fn snapshot(&self) -> Result<Vec<TraceEvent>, String> {
        self.events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| "DST trace lock poisoned".to_string())
    }
}

struct FaultingReceiptStore {
    trace: Arc<LogicalTrace>,
    receipts: Mutex<Vec<ChioReceipt>>,
    child_receipts: Mutex<Vec<ChildRequestReceipt>>,
    append_count: AtomicU64,
    fail_nth_append: Option<u64>,
    suppress_child_append: bool,
}

impl FaultingReceiptStore {
    fn new(
        trace: Arc<LogicalTrace>,
        fail_nth_append: Option<u64>,
        suppress_child_append: bool,
    ) -> Self {
        Self {
            trace,
            receipts: Mutex::new(Vec::new()),
            child_receipts: Mutex::new(Vec::new()),
            append_count: AtomicU64::new(0),
            fail_nth_append,
            suppress_child_append,
        }
    }

    fn receipts(&self) -> Result<Vec<ChioReceipt>, String> {
        self.receipts
            .lock()
            .map(|receipts| receipts.clone())
            .map_err(|_| "DST receipt store lock poisoned".to_string())
    }

    fn child_receipt_count(&self) -> Result<usize, String> {
        self.child_receipts
            .lock()
            .map(|receipts| receipts.len())
            .map_err(|_| "DST child receipt store lock poisoned".to_string())
    }
}

impl ReceiptStore for FaultingReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt).map(|_| ())
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let append = self.append_count.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_nth_append == Some(append) {
            return Err(ReceiptStoreError::Conflict(format!(
                "DST injected receipt append failure at mutation {append}"
            )));
        }
        let seq = {
            let mut receipts = self.receipts.lock().map_err(|_| {
                ReceiptStoreError::Conflict("DST receipt store lock poisoned".to_string())
            })?;
            receipts.push(receipt.clone());
            receipts.len() as u64
        };
        self.trace
            .record(TraceKind::ReceiptPersisted {
                allow: receipt.is_allowed(),
            })
            .map_err(ReceiptStoreError::Conflict)?;
        Ok(Some(seq))
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        if self.suppress_child_append {
            return Ok(());
        }
        self.child_receipts
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("DST child receipt store lock poisoned".to_string())
            })?
            .push(receipt.clone());
        Ok(())
    }
}

struct FaultingBudgetStore {
    inner: Arc<dyn BudgetStore>,
    mutation_count: AtomicU64,
    fail_nth_mutation: Option<u64>,
}

impl FaultingBudgetStore {
    fn new(inner: Arc<dyn BudgetStore>, fail_nth_mutation: Option<u64>) -> Self {
        Self {
            inner,
            mutation_count: AtomicU64::new(0),
            fail_nth_mutation,
        }
    }

    fn mutation(&self, operation: &str) -> Result<(), BudgetStoreError> {
        let mutation = self.mutation_count.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_nth_mutation == Some(mutation) {
            return Err(BudgetStoreError::Invariant(format!(
                "DST injected budget failure at mutation {mutation} ({operation})"
            )));
        }
        Ok(())
    }
}

impl BudgetStore for FaultingBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        self.mutation("try_increment")?;
        self.inner
            .try_increment(capability_id, grant_index, max_invocations)
    }

    fn try_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        self.mutation("try_charge_cost")?;
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn try_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<bool, BudgetStoreError> {
        self.mutation("try_charge_cost_with_ids")?;
        self.inner.try_charge_cost_with_ids(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
        )
    }

    fn try_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
        self.mutation("try_charge_cost_with_ids_and_authority")?;
        self.inner.try_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn try_charge_cost_with_ids_and_authority_outcome(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
        cost_units: u64,
        max_cost_per_invocation: Option<u64>,
        max_total_cost_units: Option<u64>,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<BudgetAuthorizeMutationOutcome, BudgetStoreError> {
        self.mutation("try_charge_cost_with_ids_and_authority_outcome")?;
        self.inner.try_charge_cost_with_ids_and_authority_outcome(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("reverse_charge_cost")?;
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reverse_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("reverse_charge_cost_with_ids")?;
        self.inner.reverse_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("reverse_charge_cost_with_ids_and_authority")?;
        self.inner.reverse_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("reduce_charge_cost")?;
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("reduce_charge_cost_with_ids")?;
        self.inner.reduce_charge_cost_with_ids(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
        )
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("reduce_charge_cost_with_ids_and_authority")?;
        self.inner.reduce_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("settle_charge_cost")?;
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    fn settle_charge_cost_with_ids(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("settle_charge_cost_with_ids")?;
        self.inner.settle_charge_cost_with_ids(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
        )
    }

    fn settle_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("settle_charge_cost_with_ids_and_authority")?;
        self.inner.settle_charge_cost_with_ids_and_authority(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
            hold_id,
            event_id,
            authority,
        )
    }

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        self.inner.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<BudgetMutationRecord>, BudgetStoreError> {
        self.inner
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn budget_guarantee_level(&self) -> chio_kernel::budget_store::BudgetGuaranteeLevel {
        self.inner.budget_guarantee_level()
    }

    fn budget_authority_profile(&self) -> chio_kernel::budget_store::BudgetAuthorityProfile {
        self.inner.budget_authority_profile()
    }

    fn budget_metering_profile(&self) -> chio_kernel::budget_store::BudgetMeteringProfile {
        self.inner.budget_metering_profile()
    }

    fn list_open_holds_older_than(
        &self,
        older_than_unix_ms: u64,
        limit: usize,
    ) -> Result<Vec<chio_kernel::budget_store::OpenHoldSummary>, BudgetStoreError> {
        self.inner
            .list_open_holds_older_than(older_than_unix_ms, limit)
    }

    fn expire_open_hold(&self, hold_id: &str) -> Result<bool, BudgetStoreError> {
        self.mutation("expire_open_hold")?;
        self.inner.expire_open_hold(hold_id)
    }

    fn open_hold_count(&self) -> Result<u64, BudgetStoreError> {
        self.inner.open_hold_count()
    }

    fn record_payment_journal(
        &self,
        entry: &chio_kernel::payment::PaymentJournalRecord,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("record_payment_journal")?;
        self.inner.record_payment_journal(entry)
    }

    fn advance_payment_journal(
        &self,
        request_id: &str,
        expected: chio_kernel::payment::PaymentJournalState,
        next: chio_kernel::payment::PaymentJournalState,
        authorization_id: Option<&str>,
        transaction_id: Option<&str>,
        settle: Option<chio_kernel::payment::PaymentSettleIntent>,
    ) -> Result<(), BudgetStoreError> {
        self.mutation("advance_payment_journal")?;
        self.inner.advance_payment_journal(
            request_id,
            expected,
            next,
            authorization_id,
            transaction_id,
            settle,
        )
    }

    fn close_payment_journal(&self, request_id: &str) -> Result<bool, BudgetStoreError> {
        self.mutation("close_payment_journal")?;
        self.inner.close_payment_journal(request_id)
    }

    fn list_incomplete_payment_journal(
        &self,
        older_than_unix_ms: u64,
    ) -> Result<Vec<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
        self.inner
            .list_incomplete_payment_journal(older_than_unix_ms)
    }

    fn get_payment_journal(
        &self,
        request_id: &str,
    ) -> Result<Option<chio_kernel::payment::PaymentJournalRecord>, BudgetStoreError> {
        self.inner.get_payment_journal(request_id)
    }

    fn payment_journal_reconcile_failed_rail(
        &self,
        request_id: &str,
    ) -> Result<Option<String>, BudgetStoreError> {
        self.inner.payment_journal_reconcile_failed_rail(request_id)
    }
}

pub fn assert_wrapped_budget_replay_outcome() -> Result<(), String> {
    let store = FaultingBudgetStore::new(Arc::new(InMemoryBudgetStore::new()), None);
    let authorize = || {
        store.try_charge_cost_with_ids_and_authority_outcome(
            "dst-replay-capability",
            0,
            Some(1),
            1,
            Some(1),
            Some(1),
            Some("dst-replay-hold"),
            Some("dst-replay-event"),
            None,
        )
    };

    let first = authorize().map_err(|error| format!("first wrapped authorization: {error}"))?;
    if !first.allowed || first.replayed_event {
        return Err(format!(
            "first wrapped authorization had unexpected outcome: {first:?}"
        ));
    }

    let replay = authorize().map_err(|error| format!("replayed wrapped authorization: {error}"))?;
    if !replay.allowed || !replay.replayed_event {
        return Err(format!("wrapped store erased replay metadata: {replay:?}"));
    }
    Ok(())
}

pub fn assert_wrapped_budget_hold_sweep() -> Result<(), String> {
    let files = CrashFiles::new(CrashBoundary::BeforeReceiptPersist);
    let inner = Arc::new(
        SqliteBudgetStore::open(&files.budget)
            .map_err(|error| format!("open wrapped hold-sweep budget database: {error}"))?,
    );
    let store = FaultingBudgetStore::new(inner, None);
    let authorized = store
        .try_charge_cost_with_ids_and_authority_outcome(
            "dst-hold-sweep-capability",
            0,
            Some(1),
            10,
            Some(10),
            Some(10),
            Some("dst-hold-sweep-hold"),
            Some("dst-hold-sweep-authorize"),
            None,
        )
        .map_err(|error| format!("authorize wrapped hold-sweep hold: {error}"))?;
    require(
        authorized.allowed,
        "wrapped hold-sweep authorization denied",
    )?;
    require(
        store
            .open_hold_count()
            .map_err(|error| format!("count wrapped open holds: {error}"))?
            == 1,
        "wrapped hold count did not reach one",
    )?;
    let open = store
        .list_open_holds_older_than(u64::MAX, 8)
        .map_err(|error| format!("list wrapped open holds: {error}"))?;
    require(
        open.len() == 1 && open[0].hold_id == "dst-hold-sweep-hold",
        "wrapped hold listing lost the open hold",
    )?;
    require(
        store
            .expire_open_hold("dst-hold-sweep-hold")
            .map_err(|error| format!("expire wrapped open hold: {error}"))?,
        "wrapped hold expiration did not apply",
    )?;
    require(
        store
            .open_hold_count()
            .map_err(|error| format!("count wrapped holds after expiration: {error}"))?
            == 0,
        "wrapped hold remained open after expiration",
    )?;
    Ok(())
}

struct FaultingAdmissionHook {
    evaluations: Arc<AtomicU64>,
    releases: Arc<AtomicU64>,
    readiness_polls: Arc<AtomicU64>,
    fail_release: bool,
}

#[derive(Default)]
struct DstPaymentRailState {
    authorizations: AtomicU64,
    capture_attempts: AtomicU64,
    capture_effects: AtomicU64,
    captured_references: Mutex<HashMap<(String, String), (u64, String)>>,
}

struct DstPaymentAdapter {
    state: Arc<DstPaymentRailState>,
}

impl chio_kernel::PaymentAdapter for DstPaymentAdapter {
    fn rail_id(&self) -> &str {
        "dst-payment"
    }

    fn authorize(
        &self,
        request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        self.state.authorizations.fetch_add(1, Ordering::SeqCst);
        Ok(chio_kernel::PaymentAuthorization {
            authorization_id: format!("dst-auth-{}", request.reference),
            settled: false,
            settlement_transaction_id: None,
            metadata: serde_json::json!({}),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        amount_units: u64,
        currency: &str,
        reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        self.state.capture_attempts.fetch_add(1, Ordering::SeqCst);
        let key = (authorization_id.to_string(), reference.to_string());
        let mut captured = self.state.captured_references.lock().map_err(|_| {
            chio_kernel::PaymentError::RailError(
                "DST payment adapter capture state lock poisoned".to_string(),
            )
        })?;
        if let Some((recorded_amount, recorded_currency)) = captured.get(&key) {
            if *recorded_amount != amount_units || recorded_currency != currency {
                return Err(chio_kernel::PaymentError::RailError(
                    "DST payment adapter received a conflicting idempotent capture".to_string(),
                ));
            }
        } else {
            captured.insert(key, (amount_units, currency.to_string()));
            self.state.capture_effects.fetch_add(1, Ordering::SeqCst);
        }
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("dst-txn-{authorization_id}"),
            settlement_status: chio_kernel::RailSettlementStatus::Settled,
            metadata: serde_json::json!({}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("dst-release-{authorization_id}"),
            settlement_status: chio_kernel::RailSettlementStatus::Released,
            metadata: serde_json::json!({}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Ok(chio_kernel::PaymentResult {
            transaction_id: format!("dst-refund-{transaction_id}"),
            settlement_status: chio_kernel::RailSettlementStatus::Refunded,
            metadata: serde_json::json!({}),
        })
    }

    fn settlement_state(
        &self,
        _reference: &str,
        authorization_id: Option<&str>,
    ) -> Result<chio_kernel::RailSettlementState, chio_kernel::PaymentError> {
        Ok(chio_kernel::RailSettlementState::Held {
            authorization_id: authorization_id.unwrap_or("dst-auth-recovered").to_string(),
        })
    }
}

impl RuntimeAdmissionHook for FaultingAdmissionHook {
    fn name(&self) -> &str {
        "dst-runtime-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.evaluations.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "accepted": true,
                "admission_id": format!("dst-admission-{}", context.request.request_id),
                "reserved_destructive_lease_id": format!("dst-lease-{}", context.request.request_id),
                "failure_code": null
            }
        }))))
    }

    fn poll_ready_before_dispatch_with_token(
        &self,
        _request: &ToolCallRequest,
        _token: chio_kernel::RuntimeAdmissionReadinessToken,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        let poll = self.readiness_polls.fetch_add(1, Ordering::SeqCst);
        if poll == 0 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        if self.fail_release {
            Err(KernelError::Internal(
                "DST injected runtime admission release failure".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &chio_kernel::RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        Ok(())
    }
}

struct YieldingServer {
    starts: Arc<AtomicU64>,
    pending_polls: u32,
    child_operation: bool,
}

#[async_trait::async_trait]
impl ToolServerConnection for YieldingServer {
    fn server_id(&self) -> &str {
        SERVER_ID
    }

    fn tool_names(&self) -> Vec<String> {
        vec![TOOL_NAME.to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.starts.fetch_add(1, Ordering::SeqCst);
        if self.child_operation {
            let bridge = nested_flow_bridge.ok_or_else(|| {
                KernelError::Internal("DST nested-flow bridge missing".to_string())
            })?;
            let _ = bridge.list_roots()?;
        }
        let mut remaining = self.pending_polls;
        std::future::poll_fn(move |cx| {
            if remaining == 0 {
                Poll::Ready(())
            } else {
                remaining -= 1;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        Ok(serde_json::json!({"status": "applied"}))
    }
}

#[derive(Debug)]
pub struct EpisodeSummary {
    pub plan: FaultPlan,
}

pub fn run_episode(seed: u64) -> Result<EpisodeSummary, String> {
    let plan = FaultPlan::from_seed(seed);
    let trace = Arc::new(LogicalTrace::default());
    let receipt_store = Arc::new(FaultingReceiptStore::new(
        Arc::clone(&trace),
        plan.fail_receipt_append,
        false,
    ));
    let concrete_budget = Arc::new(InMemoryBudgetStore::new());
    let budget_inner: Arc<dyn BudgetStore> = concrete_budget.clone();
    let budget_store = Arc::new(FaultingBudgetStore::new(
        budget_inner,
        plan.fail_budget_mutation,
    ));
    let admission_evaluations = Arc::new(AtomicU64::new(0));
    let admission_releases = Arc::new(AtomicU64::new(0));
    let readiness_polls = Arc::new(AtomicU64::new(0));
    let server_starts = Arc::new(AtomicU64::new(0));

    let mut kernel = ChioKernel::new(kernel_config());
    let receipt_handle: Arc<dyn ReceiptStore> = receipt_store.clone();
    kernel
        .set_receipt_store_handle(receipt_handle)
        .map_err(|error| format!("install receipt store: {error}"))?;
    let budget_handle: Arc<dyn BudgetStore> = budget_store.clone();
    kernel.set_budget_store_handle(budget_handle);
    kernel.set_runtime_admission_hook(Arc::new(FaultingAdmissionHook {
        evaluations: Arc::clone(&admission_evaluations),
        releases: Arc::clone(&admission_releases),
        readiness_polls: Arc::clone(&readiness_polls),
        fail_release: plan.fail_admission_release,
    }));
    kernel.register_tool_server(Box::new(YieldingServer {
        starts: Arc::clone(&server_starts),
        pending_polls: plan.server_pending_polls,
        child_operation: false,
    }));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(&agent.public_key(), scope(), 300)
        .map_err(|error| format!("issue capability: {error}"))?;
    let request = request(seed, &capability);
    let response = drive_evaluation(&kernel, &request, plan.mode)?;
    if let Some(Ok(response)) = response.as_ref() {
        trace.record(TraceKind::ResponseReturned {
            verdict: response.verdict,
        })?;
    }

    let receipts = receipt_store.receipts()?;
    oracle_receipt_before_allow(&trace.snapshot()?)?;
    oracle_drop_disposition(
        plan,
        response.as_ref(),
        &receipts,
        admission_evaluations.load(Ordering::SeqCst),
        admission_releases.load(Ordering::SeqCst),
        server_starts.load(Ordering::SeqCst),
    )?;
    oracle_conservation(concrete_budget.as_ref(), &capability.id, GRANT_INDEX)?;

    Ok(EpisodeSummary { plan })
}

pub fn run_payment_journal_episode(inject_record_failure: bool) -> Result<(), String> {
    let files = CrashFiles::new(CrashBoundary::BeforeReceiptPersist);
    let receipt_store = Arc::new(
        SqliteReceiptStore::open(&files.receipts)
            .map_err(|error| format!("open journal episode receipt database: {error}"))?,
    );
    let concrete_budget = Arc::new(
        SqliteBudgetStore::open(&files.budget)
            .map_err(|error| format!("open journal episode budget database: {error}"))?,
    );
    let budget_inner: Arc<dyn BudgetStore> = concrete_budget.clone();
    let budget_store = Arc::new(FaultingBudgetStore::new(
        budget_inner,
        inject_record_failure.then_some(2),
    ));
    let rail_state = Arc::new(DstPaymentRailState::default());
    let server_starts = Arc::new(AtomicU64::new(0));

    let mut config = kernel_config();
    config.dispatch_intent_journal = chio_kernel::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = ChioKernel::new(config);
    let receipt_handle: Arc<dyn ReceiptStore> = receipt_store.clone();
    kernel
        .set_receipt_store_handle(receipt_handle)
        .map_err(|error| format!("install journal episode receipt store: {error}"))?;
    let budget_handle: Arc<dyn BudgetStore> = budget_store;
    kernel.set_budget_store_handle(budget_handle);
    kernel
        .set_payment_adapter(Box::new(DstPaymentAdapter {
            state: Arc::clone(&rail_state),
        }))
        .map_err(|error| format!("install journal episode payment adapter: {error}"))?;
    kernel.register_tool_server(Box::new(YieldingServer {
        starts: Arc::clone(&server_starts),
        pending_polls: 0,
        child_operation: false,
    }));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(&agent.public_key(), scope(), 300)
        .map_err(|error| format!("issue journal episode capability: {error}"))?;
    let seed = if inject_record_failure {
        110_001
    } else {
        110_000
    };
    let request = request(seed, &capability);
    let response = drive_evaluation(&kernel, &request, EvaluationMode::Complete)?
        .ok_or_else(|| "journal episode did not complete".to_string())?
        .map_err(|error| format!("journal episode evaluation failed: {error}"))?;

    if inject_record_failure {
        require(
            response.verdict == Verdict::Deny,
            "payment-journal write fault did not deny before dispatch",
        )?;
        require(
            rail_state.authorizations.load(Ordering::SeqCst) == 0,
            "payment-journal write fault reached the rail",
        )?;
        require(
            server_starts.load(Ordering::SeqCst) == 0,
            "payment-journal write fault reached the tool server",
        )?;
    } else {
        require(
            response.verdict == Verdict::Allow,
            &format!(
                "journal-enabled episode did not allow: reason={:?}, terminal_state={:?}",
                response.reason, response.terminal_state
            ),
        )?;
        require(
            rail_state.authorizations.load(Ordering::SeqCst) == 1,
            "journal-enabled episode did not authorize exactly once",
        )?;
        require(
            rail_state.capture_attempts.load(Ordering::SeqCst) == 1,
            "journal-enabled episode did not capture exactly once",
        )?;
        require(
            rail_state.capture_effects.load(Ordering::SeqCst) == 1,
            "journal-enabled episode did not apply exactly one capture effect",
        )?;
        require(
            server_starts.load(Ordering::SeqCst) == 1,
            "journal-enabled episode did not dispatch exactly once",
        )?;
    }

    let incomplete = concrete_budget
        .list_incomplete_payment_journal(u64::MAX)
        .map_err(|error| format!("list journal episode rows: {error}"))?;
    require(
        incomplete.is_empty(),
        "journal episode left an unexpected incomplete payment row",
    )?;
    oracle_conservation(concrete_budget.as_ref(), &capability.id, GRANT_INDEX)?;
    Ok(())
}

pub fn run_payment_journal_restart_recovery_episode() -> Result<(), String> {
    let files = CrashFiles::new(CrashBoundary::AfterReceiptPersist);
    let receipt_store = Arc::new(
        SqliteReceiptStore::open(&files.receipts)
            .map_err(|error| format!("open recovery episode receipt database: {error}"))?,
    );
    let concrete_budget = Arc::new(
        SqliteBudgetStore::open(&files.budget)
            .map_err(|error| format!("open recovery episode budget database: {error}"))?,
    );
    let budget_inner: Arc<dyn BudgetStore> = concrete_budget.clone();
    let budget_store = Arc::new(FaultingBudgetStore::new(budget_inner, Some(5)));
    let rail_state = Arc::new(DstPaymentRailState::default());
    let server_starts = Arc::new(AtomicU64::new(0));

    let mut config = kernel_config();
    config.dispatch_intent_journal = chio_kernel::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = ChioKernel::new(config);
    let receipt_handle: Arc<dyn ReceiptStore> = receipt_store.clone();
    kernel
        .set_receipt_store_handle(receipt_handle)
        .map_err(|error| format!("install recovery episode receipt store: {error}"))?;
    let budget_handle: Arc<dyn BudgetStore> = budget_store;
    kernel.set_budget_store_handle(budget_handle);
    kernel
        .set_payment_adapter(Box::new(DstPaymentAdapter {
            state: Arc::clone(&rail_state),
        }))
        .map_err(|error| format!("install recovery episode payment adapter: {error}"))?;
    kernel.register_tool_server(Box::new(YieldingServer {
        starts: Arc::clone(&server_starts),
        pending_polls: 0,
        child_operation: false,
    }));

    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(&agent.public_key(), scope(), 300)
        .map_err(|error| format!("issue recovery episode capability: {error}"))?;
    let request = request(110_002, &capability);
    let response = drive_evaluation(&kernel, &request, EvaluationMode::Complete)?
        .ok_or_else(|| "recovery episode did not complete".to_string())?;
    let error = response
        .err()
        .ok_or_else(|| "post-capture journal fault unexpectedly allowed".to_string())?;
    require(
        error
            .to_string()
            .contains("DST injected budget failure at mutation 5 (advance_payment_journal)"),
        "post-capture journal fault did not fail the Settling advance",
    )?;
    require(
        rail_state.authorizations.load(Ordering::SeqCst) == 1,
        "recovery episode did not authorize exactly once",
    )?;
    require(
        rail_state.capture_attempts.load(Ordering::SeqCst) == 1,
        "recovery episode did not make exactly one initial capture attempt",
    )?;
    require(
        rail_state.capture_effects.load(Ordering::SeqCst) == 1,
        "recovery episode did not apply exactly one initial capture effect",
    )?;
    require(
        server_starts.load(Ordering::SeqCst) == 1,
        "recovery episode did not dispatch exactly once before restart",
    )?;

    let incomplete = concrete_budget
        .list_incomplete_payment_journal(u64::MAX)
        .map_err(|error| format!("list pre-restart recovery journal rows: {error}"))?;
    let settling = incomplete
        .iter()
        .find(|row| row.request_id == request.request_id)
        .ok_or_else(|| "post-capture fault did not leave a durable journal row".to_string())?;
    require(
        settling.state == chio_kernel::payment::PaymentJournalState::Settling,
        "post-capture fault did not leave the journal in Settling",
    )?;
    require(
        settling.settle_action == Some(chio_kernel::payment::PaymentSettleAction::Capture),
        "post-capture fault lost the committed capture action",
    )?;
    require(
        settling.authorization_id.is_some(),
        "post-capture fault lost the durable authorization identifier",
    )?;
    let receipts_before_restart = receipt_store
        .max_tool_receipt_seq()
        .map_err(|error| format!("read pre-restart receipt sequence: {error}"))?;

    drop(kernel);
    drop(receipt_store);
    drop(concrete_budget);

    let reopened_budget = Arc::new(
        SqliteBudgetStore::open(&files.budget)
            .map_err(|error| format!("reopen recovery episode budget database: {error}"))?,
    );
    let reopened_budget_inner: Arc<dyn BudgetStore> = reopened_budget.clone();
    let reopened_budget_wrapper = Arc::new(FaultingBudgetStore::new(reopened_budget_inner, None));
    let reopened_receipts = Arc::new(
        SqliteReceiptStore::open_existing(&files.receipts)
            .map_err(|error| format!("reopen recovery episode receipt database: {error}"))?,
    );

    let mut recovered_config = kernel_config();
    recovered_config.dispatch_intent_journal =
        chio_kernel::DispatchIntentJournalMode::SideEffecting;
    let mut recovered_kernel = ChioKernel::new(recovered_config);
    let reopened_budget_handle: Arc<dyn BudgetStore> = reopened_budget_wrapper;
    recovered_kernel.set_budget_store_handle(reopened_budget_handle);
    recovered_kernel
        .set_payment_adapter(Box::new(DstPaymentAdapter {
            state: Arc::clone(&rail_state),
        }))
        .map_err(|error| format!("install reopened payment adapter: {error}"))?;
    let reopened_receipt_handle: Arc<dyn ReceiptStore> = reopened_receipts.clone();
    recovered_kernel
        .set_receipt_store_handle(reopened_receipt_handle)
        .map_err(|error| format!("install reopened receipt store: {error}"))?;

    require(
        rail_state.authorizations.load(Ordering::SeqCst) == 1,
        "restart reconciliation performed a second authorization",
    )?;
    require(
        rail_state.capture_attempts.load(Ordering::SeqCst) == 2,
        "restart reconciliation did not replay the committed capture exactly once",
    )?;
    require(
        rail_state.capture_effects.load(Ordering::SeqCst) == 1,
        "restart reconciliation applied a duplicate capture effect",
    )?;
    require(
        server_starts.load(Ordering::SeqCst) == 1,
        "restart reconciliation dispatched the tool a second time",
    )?;
    let remaining = reopened_budget
        .list_incomplete_payment_journal(u64::MAX)
        .map_err(|error| format!("list post-restart recovery journal rows: {error}"))?;
    require(
        remaining.is_empty(),
        "restart reconciliation did not close the payment journal",
    )?;
    let receipts_after_restart = reopened_receipts
        .max_tool_receipt_seq()
        .map_err(|error| format!("read post-restart receipt sequence: {error}"))?;
    require(
        receipts_after_restart == receipts_before_restart.saturating_add(1),
        "restart reconciliation did not append exactly one recovery receipt",
    )?;
    let recovery_receipts = reopened_receipts
        .list_tool_receipts(
            8,
            Some(&capability.id),
            Some("dst-payment"),
            Some("payment.reconcile"),
            None,
        )
        .map_err(|error| format!("read restart reconciliation receipts: {error}"))?;
    require(
        recovery_receipts.len() == 1 && recovery_receipts[0].is_allowed(),
        "restart reconciliation did not persist one signed allow receipt",
    )?;
    oracle_conservation(reopened_budget.as_ref(), &capability.id, GRANT_INDEX)?;
    Ok(())
}

fn drive_evaluation(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    mode: EvaluationMode,
) -> Result<Option<Result<ToolCallResponse, KernelError>>, String> {
    let mut future = Box::pin(kernel.evaluate_tool_call(request));
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    match mode {
        EvaluationMode::DropAfterPolls(polls) => {
            for poll_index in 0..polls {
                if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                    return Err(format!(
                        "evaluation completed before injected drop at poll {poll_index}: {result:?}"
                    ));
                }
            }
            drop(future);
            Ok(None)
        }
        EvaluationMode::Complete => {
            for _ in 0..64 {
                if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
                    return Ok(Some(result));
                }
            }
            Err("evaluation did not complete within 64 deterministic polls".to_string())
        }
    }
}

fn oracle_receipt_before_allow(events: &[TraceEvent]) -> Result<(), String> {
    let first_allow_persist = events.iter().find_map(|event| match event.kind {
        TraceKind::ReceiptPersisted { allow: true } => Some(event.tick),
        _ => None,
    });
    for event in events {
        if matches!(
            event.kind,
            TraceKind::ResponseReturned {
                verdict: Verdict::Allow
            }
        ) {
            let persist = first_allow_persist.ok_or_else(|| {
                "ReceiptBeforeAllow violated: allow returned without a persisted allow receipt"
                    .to_string()
            })?;
            if persist >= event.tick {
                return Err(format!(
                    "ReceiptBeforeAllow violated: persist tick {persist} is not before response tick {}",
                    event.tick
                ));
            }
        }
    }
    Ok(())
}

fn oracle_drop_disposition(
    plan: FaultPlan,
    response: Option<&Result<ToolCallResponse, KernelError>>,
    receipts: &[ChioReceipt],
    admission_evaluations: u64,
    admission_releases: u64,
    server_starts: u64,
) -> Result<(), String> {
    match plan.class {
        EpisodeClass::PreDispatchClean => {
            require(response.is_none(), "pre-dispatch drop returned a response")?;
            require(
                admission_evaluations == 1,
                "pre-dispatch admission count drift",
            )?;
            require(
                admission_releases == 1,
                "pre-dispatch reservation was not released",
            )?;
            require(
                server_starts == 0,
                "pre-dispatch drop reached the tool server",
            )?;
            require(
                receipts.is_empty(),
                "clean pre-dispatch drop recorded a receipt",
            )?;
        }
        EpisodeClass::PreDispatchAdmissionReleaseFault
        | EpisodeClass::PreDispatchBudgetReversalFault => {
            require(
                response.is_none(),
                "faulted pre-dispatch drop returned a response",
            )?;
            require(
                admission_evaluations == 1,
                "faulted pre-dispatch admission count drift",
            )?;
            require(
                admission_releases == 1,
                "faulted pre-dispatch release was not attempted",
            )?;
            require(
                server_starts == 0,
                "faulted pre-dispatch drop reached the server",
            )?;
            require(
                receipts.len() == 1,
                "cleanup fault did not record exactly one receipt",
            )?;
            let receipt = &receipts[0];
            require(
                receipt.is_cancelled(),
                "cleanup fault receipt is not cancelled",
            )?;
            require(
                cancelled_reason(receipt) == Some(PRE_DISPATCH_DROP_REASON),
                "cleanup fault receipt reason drift",
            )?;
            let cleanup_failed = receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/chio_runtime/pre_dispatch_cleanup_failed"))
                .and_then(serde_json::Value::as_bool);
            require(cleanup_failed == Some(true), "cleanup fault marker missing")?;
            let expected_step = if plan.class == EpisodeClass::PreDispatchAdmissionReleaseFault {
                "runtime_admission_release"
            } else {
                "budget_reversal"
            };
            let has_expected_step = receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata.pointer("/chio_runtime/pre_dispatch_cleanup_faults"))
                .and_then(serde_json::Value::as_array)
                .is_some_and(|faults| {
                    faults.iter().any(|fault| {
                        fault.get("step").and_then(serde_json::Value::as_str) == Some(expected_step)
                    })
                });
            require(
                has_expected_step,
                "cleanup fault step does not match the plan",
            )?;
        }
        EpisodeClass::PostDispatchClean | EpisodeClass::PostDispatchLongServerWait => {
            require(response.is_none(), "post-dispatch drop returned a response")?;
            require(
                admission_evaluations == 1,
                "post-dispatch admission count drift",
            )?;
            require(
                admission_releases == 0,
                "post-dispatch reservation was released",
            )?;
            require(
                server_starts == 1,
                "post-dispatch drop missed the tool server",
            )?;
            require(
                receipts.len() == 1,
                "post-dispatch drop did not persist one receipt",
            )?;
            let receipt = &receipts[0];
            require(
                receipt.is_cancelled(),
                "post-dispatch receipt is not cancelled",
            )?;
            require(
                cancelled_reason(receipt) == Some(POST_DISPATCH_DROP_REASON),
                "post-dispatch receipt reason drift",
            )?;
            let retained = receipt
                .metadata
                .as_ref()
                .and_then(|metadata| {
                    metadata.pointer("/chio_runtime/reservations_retained_fail_closed")
                })
                .and_then(serde_json::Value::as_bool);
            require(
                retained == Some(true),
                "post-dispatch retention marker missing",
            )?;
        }
        EpisodeClass::CompleteAllow => {
            let response = response
                .and_then(|result| result.as_ref().ok())
                .ok_or_else(|| "complete episode did not return a response".to_string())?;
            require(
                response.verdict == Verdict::Allow,
                "complete episode was not allowed",
            )?;
            require(
                server_starts == 1,
                "complete episode did not dispatch exactly once",
            )?;
            require(
                receipts.len() == 1,
                "complete episode did not persist one receipt",
            )?;
            require(receipts[0].is_allowed(), "complete receipt is not allow")?;
        }
        EpisodeClass::CompleteReceiptFault => {
            require(
                response.is_some_and(Result::is_err),
                "receipt fault surfaced an allow response",
            )?;
            require(
                server_starts == 1,
                "receipt fault did not follow a real dispatch",
            )?;
            require(
                receipts.is_empty(),
                "failed receipt append was reported durable",
            )?;
        }
        EpisodeClass::BudgetAdmissionFault => {
            require(
                server_starts == 0,
                "budget admission fault reached the server",
            )?;
            require(
                admission_evaluations == 0,
                "budget fault ran runtime admission",
            )?;
            let response = response
                .and_then(|result| result.as_ref().ok())
                .ok_or_else(|| "budget fault did not return a fail-closed response".to_string())?;
            require(
                response.verdict == Verdict::Deny,
                "budget fault did not deny",
            )?;
            require(
                receipts.len() == 1,
                "budget fault did not persist its deny receipt",
            )?;
        }
    }
    Ok(())
}

fn cancelled_reason(receipt: &ChioReceipt) -> Option<&str> {
    match receipt.decision.as_ref() {
        Some(chio_core::receipt::decision::Decision::Cancelled { reason }) => Some(reason),
        _ => None,
    }
}

pub fn oracle_conservation(
    store: &dyn BudgetStore,
    capability_id: &str,
    grant_index: usize,
) -> Result<(), String> {
    let events = store
        .list_mutation_events(usize::MAX, Some(capability_id), Some(grant_index))
        .map_err(|error| format!("load budget journal: {error}"))?;
    let mut invocations = 0u64;
    let mut reserved = 0u128;
    let mut outstanding = 0u128;
    let mut committed = 0u128;
    let mut released = 0u128;
    let mut holds = HashMap::<String, u64>::new();
    let mut unnamed_outstanding = 0u128;

    for event in &events {
        match event.kind {
            BudgetMutationKind::IncrementInvocation if event.allowed == Some(true) => {
                invocations = invocations
                    .checked_add(1)
                    .ok_or_else(|| "invocation count overflow".to_string())?;
            }
            BudgetMutationKind::AuthorizeExposure if event.allowed == Some(true) => {
                invocations = invocations
                    .checked_add(1)
                    .ok_or_else(|| "invocation count overflow".to_string())?;
                let exposure = u128::from(event.exposure_units);
                reserved += exposure;
                outstanding += exposure;
                if let Some(hold_id) = event.hold_id.as_ref() {
                    if holds
                        .insert(hold_id.clone(), event.exposure_units)
                        .is_some()
                    {
                        return Err(format!("duplicate budget hold {hold_id}"));
                    }
                } else {
                    unnamed_outstanding += exposure;
                }
            }
            BudgetMutationKind::ReverseExposure | BudgetMutationKind::ExpireHold => {
                invocations = invocations
                    .checked_sub(1)
                    .ok_or_else(|| format!("{} reversed without admission", event.event_id))?;
                dispose_exposure(
                    event,
                    &mut outstanding,
                    &mut released,
                    &mut holds,
                    &mut unnamed_outstanding,
                    true,
                )?;
            }
            BudgetMutationKind::ReleaseExposure => {
                dispose_exposure(
                    event,
                    &mut outstanding,
                    &mut released,
                    &mut holds,
                    &mut unnamed_outstanding,
                    false,
                )?;
            }
            BudgetMutationKind::ReconcileSpend => {
                if event.realized_spend_units > event.exposure_units {
                    return Err(format!("{} realized more than exposed", event.event_id));
                }
                outstanding = outstanding
                    .checked_sub(u128::from(event.exposure_units))
                    .ok_or_else(|| format!("{} over-disposed exposure", event.event_id))?;
                committed += u128::from(event.realized_spend_units);
                released += u128::from(event.exposure_units - event.realized_spend_units);
                consume_hold(event, &mut holds, &mut unnamed_outstanding, true)?;
            }
            BudgetMutationKind::IncrementInvocation | BudgetMutationKind::AuthorizeExposure => {}
        }
        if reserved != outstanding + committed + released {
            return Err(format!("reservation partition drift at {}", event.event_id));
        }
        let named_outstanding = holds.values().map(|value| u128::from(*value)).sum::<u128>();
        if outstanding != named_outstanding + unnamed_outstanding {
            return Err(format!(
                "reservation hold identity drift at {}",
                event.event_id
            ));
        }
        if u64::from(event.invocation_count_after) != invocations
            || u128::from(event.total_cost_exposed_after) != outstanding
            || u128::from(event.total_cost_realized_spend_after) != committed
        {
            return Err(format!("budget snapshot drift at {}", event.event_id));
        }
    }

    let usage = store
        .get_usage(capability_id, grant_index)
        .map_err(|error| format!("load final budget usage: {error}"))?;
    match usage {
        Some(usage) => {
            require(
                u64::from(usage.invocation_count) == invocations,
                "final invocation count drift",
            )?;
            require(
                u128::from(usage.total_cost_exposed) == outstanding,
                "final exposed cost drift",
            )?;
            require(
                u128::from(usage.total_cost_realized_spend) == committed,
                "final realized spend drift",
            )?;
        }
        None => require(
            invocations == 0 && outstanding == 0 && committed == 0,
            "budget journal exists without final usage",
        )?,
    }
    Ok(())
}

fn dispose_exposure(
    event: &BudgetMutationRecord,
    outstanding: &mut u128,
    released: &mut u128,
    holds: &mut HashMap<String, u64>,
    unnamed_outstanding: &mut u128,
    terminal: bool,
) -> Result<(), String> {
    let exposure = u128::from(event.exposure_units);
    *outstanding = outstanding
        .checked_sub(exposure)
        .ok_or_else(|| format!("{} over-disposed exposure", event.event_id))?;
    *released += exposure;
    consume_hold(event, holds, unnamed_outstanding, terminal)
}

fn consume_hold(
    event: &BudgetMutationRecord,
    holds: &mut HashMap<String, u64>,
    unnamed_outstanding: &mut u128,
    terminal: bool,
) -> Result<(), String> {
    let Some(hold_id) = event.hold_id.as_ref() else {
        *unnamed_outstanding = unnamed_outstanding
            .checked_sub(u128::from(event.exposure_units))
            .ok_or_else(|| format!("{} over-disposed unnamed exposure", event.event_id))?;
        return Ok(());
    };
    let remaining = holds
        .get_mut(hold_id)
        .ok_or_else(|| format!("{} names unknown hold {hold_id}", event.event_id))?;
    *remaining = remaining
        .checked_sub(event.exposure_units)
        .ok_or_else(|| format!("{} over-disposed hold {hold_id}", event.event_id))?;
    if terminal && *remaining != 0 {
        return Err(format!(
            "{} terminally disposed only part of hold {hold_id}",
            event.event_id
        ));
    }
    if *remaining == 0 {
        holds.remove(hold_id);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CrashBoundary {
    BeforeReceiptPersist,
    AfterReceiptPersist,
}

struct CrashReceiptStore {
    inner: Arc<SqliteReceiptStore>,
    boundary: CrashBoundary,
    append_count: AtomicU64,
}

impl ReceiptStore for CrashReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt).map(|_| ())
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let append = self.append_count.fetch_add(1, Ordering::SeqCst) + 1;
        if self.boundary == CrashBoundary::BeforeReceiptPersist && append == 1 {
            return Err(ReceiptStoreError::Conflict(
                "DST crash before receipt persist".to_string(),
            ));
        }
        let seq = self.inner.append_chio_receipt_returning_seq(receipt)?;
        if self.boundary == CrashBoundary::AfterReceiptPersist && append == 1 {
            return Err(ReceiptStoreError::Conflict(
                "DST crash after receipt persist".to_string(),
            ));
        }
        Ok(Some(seq))
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.inner.append_child_receipt(receipt)
    }

    fn load_latest_checkpoint(
        &self,
    ) -> Result<Option<chio_kernel::KernelCheckpoint>, ReceiptStoreError> {
        self.inner.load_latest_checkpoint()
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.inner
            .record_capability_snapshot(token, parent_capability_id)
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        self.inner.supports_kernel_signed_checkpoints()
    }
}

pub fn run_crash_reopen(boundary: CrashBoundary) -> Result<(), String> {
    let files = CrashFiles::new(boundary);
    let sqlite_receipts = Arc::new(
        SqliteReceiptStore::open(&files.receipts)
            .map_err(|error| format!("open receipt database: {error}"))?,
    );
    let sqlite_budget = Arc::new(
        SqliteBudgetStore::open(&files.budget)
            .map_err(|error| format!("open budget database: {error}"))?,
    );
    let mut kernel = ChioKernel::new(kernel_config());
    let crash_store: Arc<dyn ReceiptStore> = Arc::new(CrashReceiptStore {
        inner: Arc::clone(&sqlite_receipts),
        boundary,
        append_count: AtomicU64::new(0),
    });
    kernel
        .set_receipt_store_handle(crash_store)
        .map_err(|error| format!("install crash receipt store: {error}"))?;
    let budget_handle: Arc<dyn BudgetStore> = sqlite_budget.clone();
    kernel.set_budget_store_handle(budget_handle);
    let evaluations = Arc::new(AtomicU64::new(0));
    let releases = Arc::new(AtomicU64::new(0));
    let readiness = Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(Arc::new(FaultingAdmissionHook {
        evaluations,
        releases,
        readiness_polls: readiness,
        fail_release: false,
    }));
    let server_starts = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(YieldingServer {
        starts: Arc::clone(&server_starts),
        pending_polls: 1,
        child_operation: false,
    }));
    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(&agent.public_key(), scope(), 300)
        .map_err(|error| format!("issue crash capability: {error}"))?;
    let request = request(90_000 + boundary as u64, &capability);
    let response = drive_evaluation(&kernel, &request, EvaluationMode::Complete)?;
    require(
        response.is_some_and(|result| result.is_err()),
        "crash boundary surfaced an allow response",
    )?;
    require(
        server_starts.load(Ordering::SeqCst) == 1,
        "crash episode did not execute the real tool server",
    )?;

    drop(kernel);
    drop(sqlite_receipts);
    drop(sqlite_budget);

    let reopened_receipts = SqliteReceiptStore::open_existing(&files.receipts)
        .map_err(|error| format!("reopen receipt database: {error}"))?;
    let recovered = reopened_receipts
        .list_tool_receipts(8, Some(&capability.id), None, None, None)
        .map_err(|error| format!("read recovered receipts: {error}"))?;
    let expected = if boundary == CrashBoundary::BeforeReceiptPersist {
        0
    } else {
        1
    };
    require(
        recovered.len() == expected,
        "recovered receipt count disagrees with crash boundary",
    )?;
    if let Some(receipt) = recovered.first() {
        require(
            receipt.is_allowed(),
            "recovered post-persist receipt is not allow",
        )?;
    }
    drop(reopened_receipts);

    let reopened_budget = SqliteBudgetStore::open(&files.budget)
        .map_err(|error| format!("reopen budget database: {error}"))?;
    oracle_conservation(&reopened_budget, &capability.id, GRANT_INDEX)?;
    let usage = reopened_budget
        .get_usage(&capability.id, GRANT_INDEX)
        .map_err(|error| format!("read recovered budget usage: {error}"))?;
    require(
        usage.is_some_and(|usage| {
            usage.invocation_count == 1
                && usage.total_cost_exposed == 0
                && usage.total_cost_realized_spend == 5
        }),
        "recovered budget lost the dispatched five-unit reconciliation",
    )?;
    Ok(())
}

pub fn run_child_flush_mutation(seed: u64, suppress_child_append: bool) -> Result<(), String> {
    let trace = Arc::new(LogicalTrace::default());
    let receipt_store = Arc::new(FaultingReceiptStore::new(
        trace,
        None,
        suppress_child_append,
    ));
    let budget = Arc::new(InMemoryBudgetStore::new());
    let mut kernel = ChioKernel::new(kernel_config());
    let receipt_handle: Arc<dyn ReceiptStore> = receipt_store.clone();
    kernel
        .set_receipt_store_handle(receipt_handle)
        .map_err(|error| format!("install child receipt store: {error}"))?;
    let budget_handle: Arc<dyn BudgetStore> = budget.clone();
    kernel.set_budget_store_handle(budget_handle);
    kernel.set_runtime_admission_hook(Arc::new(FaultingAdmissionHook {
        evaluations: Arc::new(AtomicU64::new(0)),
        releases: Arc::new(AtomicU64::new(0)),
        readiness_polls: Arc::new(AtomicU64::new(0)),
        fail_release: false,
    }));
    let server_starts = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(YieldingServer {
        starts: Arc::clone(&server_starts),
        pending_polls: 32,
        child_operation: true,
    }));
    let agent = Keypair::generate();
    let capability = kernel
        .issue_capability(&agent.public_key(), scope(), 300)
        .map_err(|error| format!("issue child capability: {error}"))?;
    let session_id = kernel
        .open_session(agent.public_key().to_hex(), vec![capability.clone()])
        .map_err(|error| format!("open child session: {error}"))?;
    kernel
        .activate_session(&session_id)
        .map_err(|error| format!("activate child session: {error}"))?;
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_roots: true,
                ..PeerCapabilities::default()
            },
        )
        .map_err(|error| format!("negotiate child roots: {error}"))?;
    let request_id = format!("dst-child-flush-{seed}");
    let context = OperationContext::new(
        session_id,
        RequestId::new(request_id),
        agent.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: capability.clone(),
        server_id: SERVER_ID.to_string(),
        tool_name: TOOL_NAME.to_string(),
        arguments: serde_json::json!({"child": true, "seed": seed}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: None,
        extra_metadata: None,
    };
    let mut client = NoopNestedClient;
    let mut future = Box::pin(
        kernel.evaluate_tool_call_operation_with_nested_flow_client_async(
            &context,
            &operation,
            &mut client,
        ),
    );
    let waker = Waker::from(Arc::new(NoopWake));
    let mut task_context = Context::from_waker(&waker);
    for poll_index in 0..2 {
        if let Poll::Ready(result) = future.as_mut().poll(&mut task_context) {
            return Err(format!(
                "nested evaluation completed before drop at poll {poll_index}: {result:?}"
            ));
        }
    }
    drop(future);
    require(
        server_starts.load(Ordering::SeqCst) == 1,
        "nested mutation never reached the tool server",
    )?;
    let parent_receipts = receipt_store.receipts()?;
    require(
        parent_receipts.len() == 1 && parent_receipts[0].is_cancelled(),
        "nested drop did not persist its parent cancellation",
    )?;
    let child_count = receipt_store.child_receipt_count()?;
    require(
        child_count == 1,
        "ChildReceiptsFlushed violated: completed nested child receipt was not durable",
    )?;
    oracle_conservation(budget.as_ref(), &capability.id, GRANT_INDEX)
}

struct NoopNestedClient;

impl NestedFlowClient for NoopNestedClient {
    fn list_roots(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(Vec::new())
    }

    fn create_message(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        Err(KernelError::Internal(
            "DST does not service create_message".to_string(),
        ))
    }

    fn create_elicitation(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Err(KernelError::Internal(
            "DST does not service create_elicitation".to_string(),
        ))
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        _elicitation_id: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        _uri: &str,
    ) -> Result<(), KernelError> {
        Ok(())
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        Ok(())
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

struct CrashFiles {
    receipts: PathBuf,
    budget: PathBuf,
}

impl CrashFiles {
    fn new(boundary: CrashBoundary) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, Ordering::SeqCst);
        let base = std::env::temp_dir().join(format!(
            "chio-dst-{}-{}-{boundary:?}",
            std::process::id(),
            nonce
        ));
        Self {
            receipts: base.with_extension("receipts.db"),
            budget: base.with_extension("budget.db"),
        }
    }
}

impl Drop for CrashFiles {
    fn drop(&mut self) {
        remove_sqlite_files(&self.receipts);
        remove_sqlite_files(&self.budget);
    }
}

fn remove_sqlite_files(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        let _ = std::fs::remove_file(candidate);
    }
}

fn kernel_config() -> KernelConfig {
    KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "dst-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: 0,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
        dispatch_intent_journal: chio_kernel::DispatchIntentJournalMode::Off,
    }
}

fn scope() -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: SERVER_ID.to_string(),
            tool_name: TOOL_NAME.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: Some(MonetaryAmount {
                units: 5,
                currency: "USD".to_string(),
            }),
            max_total_cost: Some(MonetaryAmount {
                units: 20,
                currency: "USD".to_string(),
            }),
            dpop_required: None,
        }],
        ..ChioScope::default()
    }
}

fn request(seed: u64, capability: &CapabilityToken) -> ToolCallRequest {
    ToolCallRequest {
        request_id: format!("dst-request-{seed}"),
        capability: capability.clone(),
        tool_name: TOOL_NAME.to_string(),
        server_id: SERVER_ID.to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({"seed": seed}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn require(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
