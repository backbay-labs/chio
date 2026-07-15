//! Kernel-surface tests for the durable dispatch-intent journal: fail-closed
//! trait defaults, the class gate, same-transaction consume, the money-path
//! rail reference, and boot reconciliation.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};
use chio_kernel::receipt_store::{
    DispatchIntentKey, DispatchIntentReconciler, DispatchIntentRecord, DispatchIntentResolution,
    ReceiptStore, ReceiptStoreError, SideEffectClass,
};

mod support {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        scope::{ChioScope, Operation, ToolGrant},
        token::CapabilityToken,
    };
    use chio_core::crypto::Keypair;
    use chio_kernel::{
        ChioKernel, DispatchIntentJournalMode, KernelConfig, KernelError, NestedFlowBridge,
        ReceiptStore, ToolCallRequest, ToolServerConnection, DEFAULT_CHECKPOINT_BATCH_SIZE,
        DEFAULT_MAX_STREAM_DURATION_SECS, DEFAULT_MAX_STREAM_TOTAL_BYTES,
    };
    use chio_store_sqlite::SqliteReceiptStore;

    /// (rail, rail_authorization_id) pairs observed on open intents from
    /// inside a tool invocation.
    pub type ObservedRailRefs = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

    pub fn unique_kernel_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{}-{nonce}.sqlite3", std::process::id()))
    }

    /// Tool server that probes the journal from INSIDE `invoke`, capturing the
    /// open-intent count at the moment the effect runs. The pre-dispatch write
    /// must be durable before dispatch, so a side-effecting invoke observes
    /// its own intent row and a read-only invoke observes none.
    pub struct ProbeServer {
        store: Arc<SqliteReceiptStore>,
        pub invoked: Arc<AtomicUsize>,
        pub open_intents_seen_at_invoke: Arc<Mutex<Vec<u64>>>,
        pub rail_refs_seen_at_invoke: ObservedRailRefs,
        /// When set, `invoke` fails AFTER recording the probe, modeling a tool
        /// whose side effect ran and then errored.
        pub fail_after_effect: bool,
    }

    #[async_trait::async_trait]
    impl ToolServerConnection for ProbeServer {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["write_file".to_string(), "read_file".to_string()]
        }

        fn tool_is_read_only(&self, tool_name: &str) -> bool {
            tool_name == "read_file"
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            self.invoked.fetch_add(1, Ordering::SeqCst);
            let open = self
                .store
                .open_dispatch_intent_count()
                .expect("count open intents from inside the tool");
            self.open_intents_seen_at_invoke
                .lock()
                .expect("probe lock")
                .push(open);
            for intent in self
                .store
                .open_dispatch_intents()
                .expect("list open intents from inside the tool")
            {
                self.rail_refs_seen_at_invoke
                    .lock()
                    .expect("rail probe lock")
                    .push((intent.rail, intent.rail_authorization_id));
            }
            if self.fail_after_effect {
                return Err(KernelError::Internal(
                    "tool failed after its side effect".to_string(),
                ));
            }
            Ok(serde_json::json!({ "ok": true }))
        }
    }

    /// Store decorator whose intent writes fail while `reject_intent_writes`
    /// is set; everything else delegates to the real SQLite store so deny
    /// receipts still persist durably.
    pub struct IntentRejectingStore {
        pub inner: Arc<SqliteReceiptStore>,
        pub reject_intent_writes: AtomicBool,
    }

    impl ReceiptStore for IntentRejectingStore {
        fn append_chio_receipt(
            &self,
            receipt: &chio_core::receipt::body::ChioReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            self.inner.as_ref().append_chio_receipt(receipt)
        }

        fn append_chio_receipt_returning_seq(
            &self,
            receipt: &chio_core::receipt::body::ChioReceipt,
        ) -> Result<Option<u64>, chio_kernel::ReceiptStoreError> {
            ReceiptStore::append_chio_receipt_returning_seq(self.inner.as_ref(), receipt)
        }

        fn append_chio_receipt_with_timeout(
            &self,
            receipt: &chio_core::receipt::body::ChioReceipt,
            budget: std::time::Duration,
        ) -> Result<Option<u64>, chio_kernel::ReceiptStoreError> {
            self.inner
                .as_ref()
                .append_chio_receipt_with_timeout(receipt, budget)
        }

        fn append_child_receipt(
            &self,
            receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            self.inner.as_ref().append_child_receipt(receipt)
        }

        fn supports_durable_dispatch_intent_journal(&self) -> bool {
            self.inner
                .as_ref()
                .supports_durable_dispatch_intent_journal()
        }

        fn record_dispatch_intent(
            &self,
            intent: &chio_kernel::DispatchIntentRecord,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            if self.reject_intent_writes.load(Ordering::SeqCst) {
                self.reject_intent_writes.store(false, Ordering::SeqCst);
                return Err(chio_kernel::ReceiptStoreError::Pool(
                    "intent writer wedged".to_string(),
                ));
            }
            self.inner.as_ref().record_dispatch_intent(intent)
        }

        fn record_dispatch_intent_with_timeout(
            &self,
            intent: &chio_kernel::DispatchIntentRecord,
            budget: std::time::Duration,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            if self.reject_intent_writes.load(Ordering::SeqCst) {
                self.reject_intent_writes.store(false, Ordering::SeqCst);
                return Err(chio_kernel::ReceiptStoreError::Pool(
                    "intent writer wedged".to_string(),
                ));
            }
            self.inner
                .as_ref()
                .record_dispatch_intent_with_timeout(intent, budget)
        }

        fn append_chio_receipt_consuming_intent(
            &self,
            receipt: &chio_core::receipt::body::ChioReceipt,
            intent: &chio_kernel::DispatchIntentKey,
        ) -> Result<Option<u64>, chio_kernel::ReceiptStoreError> {
            self.inner
                .as_ref()
                .append_chio_receipt_consuming_intent(receipt, intent)
        }

        fn append_chio_receipt_consuming_intent_with_timeout(
            &self,
            receipt: &chio_core::receipt::body::ChioReceipt,
            intent: &chio_kernel::DispatchIntentKey,
            budget: std::time::Duration,
        ) -> Result<Option<u64>, chio_kernel::ReceiptStoreError> {
            self.inner
                .as_ref()
                .append_chio_receipt_consuming_intent_with_timeout(receipt, intent, budget)
        }

        fn reconcile_dispatch_intents(
            &self,
            reconciler: &dyn chio_kernel::DispatchIntentReconciler,
        ) -> Result<chio_kernel::DispatchIntentReconcileReport, chio_kernel::ReceiptStoreError>
        {
            self.inner.as_ref().reconcile_dispatch_intents(reconciler)
        }

        fn open_dispatch_intent_count(&self) -> Result<u64, chio_kernel::ReceiptStoreError> {
            self.inner.as_ref().open_dispatch_intent_count()
        }

        fn dead_letter_dispatch_intent_count(&self) -> Result<u64, chio_kernel::ReceiptStoreError> {
            self.inner.as_ref().dead_letter_dispatch_intent_count()
        }
    }

    /// Payment rail whose authorize hands out a fixed reference; capture,
    /// release, and refund settle locally so monetary evaluations complete.
    pub struct RecordingRail;

    impl chio_kernel::PaymentAdapter for RecordingRail {
        fn rail_id(&self) -> &str {
            "x402"
        }

        fn authorize(
            &self,
            _request: &chio_kernel::PaymentAuthorizeRequest,
        ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
            Ok(chio_kernel::PaymentAuthorization {
                authorization_id: "auth-42".to_string(),
                settled: false,
                metadata: serde_json::json!({}),
            })
        }

        fn capture(
            &self,
            authorization_id: &str,
            _amount_units: u64,
            _currency: &str,
            _reference: &str,
        ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
            Ok(chio_kernel::PaymentResult {
                transaction_id: authorization_id.to_string(),
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
                transaction_id: authorization_id.to_string(),
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
                transaction_id: transaction_id.to_string(),
                settlement_status: chio_kernel::RailSettlementStatus::Refunded,
                metadata: serde_json::json!({}),
            })
        }
    }

    pub struct JournalHarness {
        pub kernel: ChioKernel,
        pub store: Arc<SqliteReceiptStore>,
        pub capability: CapabilityToken,
        pub invoked: Arc<AtomicUsize>,
        pub open_intents_seen_at_invoke: Arc<Mutex<Vec<u64>>>,
        pub rail_refs_seen_at_invoke: ObservedRailRefs,
        pub db_path: std::path::PathBuf,
    }

    impl JournalHarness {
        pub fn request(&self, tool_name: &str) -> ToolCallRequest {
            self.request_with_id(tool_name, &format!("req-{tool_name}"))
        }

        pub fn request_with_id(&self, tool_name: &str, request_id: &str) -> ToolCallRequest {
            ToolCallRequest {
                request_id: request_id.to_string(),
                capability: self.capability.clone(),
                tool_name: tool_name.to_string(),
                server_id: "srv".to_string(),
                agent_id: self.capability.subject.to_hex(),
                arguments: serde_json::json!({ "payload": "hello" }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            }
        }
    }

    pub fn journal_config(keypair: Keypair) -> KernelConfig {
        KernelConfig {
            keypair,
            ca_public_keys: vec![],
            max_delegation_depth: 5,
            policy_hash: "test-policy-hash".to_string(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: false,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
            retention_config: None,
            memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
            deadlines: chio_kernel::HotPathDeadlineConfig::default(),
            dispatch_intent_journal: DispatchIntentJournalMode::SideEffecting,
        }
    }

    fn tool_scope(max_invocations: Option<u32>, monetary: bool) -> ChioScope {
        let cost = |units: u64| {
            monetary.then(|| chio_core::capability::scope::MonetaryAmount {
                units,
                currency: "USD".to_string(),
            })
        };
        let grant = |tool_name: &str| ToolGrant {
            server_id: "srv".to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations,
            max_cost_per_invocation: cost(100),
            max_total_cost: cost(10_000),
            dpop_required: None,
        };
        ChioScope {
            grants: vec![grant("write_file"), grant("read_file")],
            ..ChioScope::default()
        }
    }

    pub fn journal_harness(prefix: &str) -> Result<JournalHarness, Box<dyn std::error::Error>> {
        journal_harness_with(prefix, None, false, false, false)
    }

    pub fn journal_harness_failing_tool(
        prefix: &str,
    ) -> Result<JournalHarness, Box<dyn std::error::Error>> {
        journal_harness_with(prefix, None, false, true, false)
    }

    pub fn journal_harness_rejecting_first_intent_write(
        prefix: &str,
        max_invocations: Option<u32>,
    ) -> Result<JournalHarness, Box<dyn std::error::Error>> {
        journal_harness_with(prefix, max_invocations, true, false, false)
    }

    pub fn monetary_journal_harness(
        prefix: &str,
    ) -> Result<JournalHarness, Box<dyn std::error::Error>> {
        journal_harness_with(prefix, None, false, false, true)
    }

    fn journal_harness_with(
        prefix: &str,
        max_invocations: Option<u32>,
        reject_first_intent_write: bool,
        fail_after_effect: bool,
        monetary: bool,
    ) -> Result<JournalHarness, Box<dyn std::error::Error>> {
        let db_path = unique_kernel_db_path(prefix);
        let store = Arc::new(SqliteReceiptStore::open(&db_path)?);
        let invoked = Arc::new(AtomicUsize::new(0));
        let open_intents_seen_at_invoke = Arc::new(Mutex::new(Vec::new()));
        let rail_refs_seen_at_invoke = Arc::new(Mutex::new(Vec::new()));

        let mut kernel = ChioKernel::new(journal_config(Keypair::generate()));
        kernel.register_tool_server(Box::new(ProbeServer {
            store: Arc::clone(&store),
            invoked: Arc::clone(&invoked),
            open_intents_seen_at_invoke: Arc::clone(&open_intents_seen_at_invoke),
            rail_refs_seen_at_invoke: Arc::clone(&rail_refs_seen_at_invoke),
            fail_after_effect,
        }));
        if monetary {
            kernel.set_payment_adapter(Box::new(RecordingRail));
        }
        if reject_first_intent_write {
            kernel.set_receipt_store_handle(Arc::new(IntentRejectingStore {
                inner: Arc::clone(&store),
                reject_intent_writes: AtomicBool::new(true),
            }))?;
        } else {
            kernel.set_receipt_store_handle(Arc::clone(&store) as Arc<dyn ReceiptStore>)?;
        }

        let agent_keypair = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent_keypair.public_key(),
            tool_scope(max_invocations, monetary),
            300,
        )?;
        Ok(JournalHarness {
            kernel,
            store,
            capability,
            invoked,
            open_intents_seen_at_invoke,
            rail_refs_seen_at_invoke,
            db_path,
        })
    }
}

/// A minimal append-only store: every journal method must fail closed (or
/// no-op empty for reconciliation and counts) by default, so a store that
/// never opted into the journal can never silently accept an intent.
struct UnsupportedStore;

impl ReceiptStore for UnsupportedStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

struct DeadLetterEverything;

impl DispatchIntentReconciler for DeadLetterEverything {
    fn resolve(
        &self,
        _intent: &DispatchIntentRecord,
    ) -> Result<DispatchIntentResolution, ReceiptStoreError> {
        Ok(DispatchIntentResolution::DeadLetter {
            detail: "outcome unknown".to_string(),
        })
    }
}

fn sample_intent_record(request_id: &str) -> DispatchIntentRecord {
    DispatchIntentRecord {
        request_id: request_id.to_string(),
        capability_id: "cap-1".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        parameter_hash: "hash".to_string(),
        side_effect_class: SideEffectClass::SideEffecting,
        monetary: false,
        rail: None,
        rail_authorization_id: None,
        tenant_id: None,
        created_at_unix_ms: 1,
    }
}

fn sample_receipt() -> ChioReceipt {
    let keypair = Keypair::from_seed(&[0x17; 32]);
    let action =
        ToolCallAction::from_parameters(serde_json::json!({"k": "v"})).expect("hash parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "rcpt-journal-default".to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign receipt")
}

#[test]
fn journal_mode_defaults_to_side_effecting_and_serializes_snake_case() {
    use chio_kernel::DispatchIntentJournalMode;
    assert_eq!(
        DispatchIntentJournalMode::default(),
        DispatchIntentJournalMode::SideEffecting
    );
    assert_eq!(
        serde_json::to_string(&DispatchIntentJournalMode::Off).unwrap(),
        "\"off\""
    );
    assert_eq!(
        serde_json::to_string(&DispatchIntentJournalMode::SideEffecting).unwrap(),
        "\"side_effecting\""
    );
    assert_eq!(
        serde_json::to_string(&DispatchIntentJournalMode::All).unwrap(),
        "\"all\""
    );
}

/// An adapter that never authorizes; used only to observe trait defaults.
struct InertPaymentAdapter;

impl chio_kernel::PaymentAdapter for InertPaymentAdapter {
    fn authorize(
        &self,
        _request: &chio_kernel::PaymentAuthorizeRequest,
    ) -> Result<chio_kernel::PaymentAuthorization, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::Unavailable("inert".to_string()))
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::Unavailable("inert".to_string()))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::Unavailable("inert".to_string()))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<chio_kernel::PaymentResult, chio_kernel::PaymentError> {
        Err(chio_kernel::PaymentError::Unavailable("inert".to_string()))
    }
}

struct UnannotatedServer;

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for UnannotatedServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["tool".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        Ok(serde_json::json!({}))
    }
}

/// Single-tool server that only counts invocations, for asserting that a
/// denied dispatch never reached the tool.
struct CountingServer {
    invoked: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[async_trait::async_trait]
impl chio_kernel::ToolServerConnection for CountingServer {
    fn server_id(&self) -> &str {
        "srv"
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["tool".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn chio_kernel::NestedFlowBridge>,
    ) -> Result<serde_json::Value, chio_kernel::KernelError> {
        self.invoked
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({}))
    }
}

fn single_tool_scope(server_id: &str, tool_name: &str) -> chio_core::capability::scope::ChioScope {
    chio_core::capability::scope::ChioScope {
        grants: vec![chio_core::capability::scope::ToolGrant {
            server_id: server_id.to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![chio_core::capability::scope::Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..Default::default()
    }
}

fn tool_request(
    request_id: &str,
    capability: &chio_core::capability::token::CapabilityToken,
) -> chio_kernel::ToolCallRequest {
    chio_kernel::ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "tool".to_string(),
        server_id: "srv".to_string(),
        agent_id: capability.subject.to_hex(),
        arguments: serde_json::json!({ "payload": "hello" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

/// Store that accepts every journal write into process memory. Attached
/// directly to a kernel it passes the store-attached check, yet its rows
/// die with the process - exactly the loss the journal exists to prevent.
/// It deliberately keeps the default (false) durability claim.
struct VolatileJournalStore {
    open_intents: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl VolatileJournalStore {
    fn new() -> Self {
        Self {
            open_intents: std::sync::Mutex::new(std::collections::HashSet::new()),
        }
    }
}

impl ReceiptStore for VolatileJournalStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &chio_core::receipt::lineage::ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_dispatch_intent(
        &self,
        intent: &DispatchIntentRecord,
    ) -> Result<(), ReceiptStoreError> {
        self.open_intents
            .lock()
            .expect("volatile journal lock")
            .insert(intent.request_id.clone());
        Ok(())
    }

    fn append_chio_receipt_consuming_intent(
        &self,
        _receipt: &ChioReceipt,
        key: &DispatchIntentKey,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        if self
            .open_intents
            .lock()
            .expect("volatile journal lock")
            .remove(&key.request_id)
        {
            Ok(None)
        } else {
            Err(ReceiptStoreError::Conflict(format!(
                "dispatch intent for request `{}` not found",
                key.request_id
            )))
        }
    }
}

#[test]
fn non_durable_store_denies_side_effecting_dispatch_when_journal_on(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::Verdict;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // With the journal on, side-effecting dispatch must fail closed against
    // a store that accepts the intent write without claiming it survives a
    // crash: the write would "succeed" and the marker would still be gone
    // exactly when reconciliation needs it.
    let invoked = Arc::new(AtomicUsize::new(0));
    let mut kernel = chio_kernel::ChioKernel::new(support::journal_config(Keypair::generate()));
    kernel.register_tool_server(Box::new(CountingServer {
        invoked: Arc::clone(&invoked),
    }));
    kernel.set_receipt_store_handle(Arc::new(VolatileJournalStore::new()))?;
    let agent = Keypair::generate();
    let capability =
        kernel.issue_capability(&agent.public_key(), single_tool_scope("srv", "tool"), 300)?;

    let denied = kernel.evaluate_tool_call_blocking(&tool_request("req-volatile", &capability))?;
    assert!(
        matches!(denied.verdict, Verdict::Deny),
        "a non-durable journal store must deny side-effecting dispatch, got {:?}: {:?}",
        denied.verdict,
        denied.reason
    );
    let reason = denied.reason.unwrap_or_default();
    assert!(
        reason.contains("across a crash"),
        "the deny names the durability gap: {reason}"
    );
    assert_eq!(
        invoked.load(Ordering::SeqCst),
        0,
        "the tool must not run without a durable intent"
    );

    // Journal Off writes no intents, so the same store keeps serving
    // side-effecting calls.
    let mut config = support::journal_config(Keypair::generate());
    config.dispatch_intent_journal = chio_kernel::DispatchIntentJournalMode::Off;
    let mut kernel = chio_kernel::ChioKernel::new(config);
    kernel.register_tool_server(Box::new(CountingServer {
        invoked: Arc::clone(&invoked),
    }));
    kernel.set_receipt_store_handle(Arc::new(VolatileJournalStore::new()))?;
    let agent = Keypair::generate();
    let capability =
        kernel.issue_capability(&agent.public_key(), single_tool_scope("srv", "tool"), 300)?;
    let allowed =
        kernel.evaluate_tool_call_blocking(&tool_request("req-journal-off", &capability))?;
    assert!(
        matches!(allowed.verdict, Verdict::Allow),
        "journal Off keeps a non-durable store serving: {:?}",
        allowed.reason
    );
    assert_eq!(invoked.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn unannotated_tools_read_as_side_effecting_and_rails_name_themselves() {
    use chio_kernel::{PaymentAdapter, ToolServerConnection};

    // Fail-safe: a connection that does not annotate its tools reports every
    // tool as NOT read-only, so unknown tools get a durable intent.
    assert!(!UnannotatedServer.tool_is_read_only("tool"));
    assert!(!UnannotatedServer.tool_is_read_only("anything-else"));

    // Rails name themselves so a monetary intent can record which rail to
    // reconcile against; adapters that do not override keep a generic label.
    assert_eq!(InertPaymentAdapter.rail_id(), "payment");
    assert_eq!(
        chio_kernel::X402PaymentAdapter::new("http://localhost:9").rail_id(),
        "x402"
    );
    assert_eq!(
        chio_kernel::AcpPaymentAdapter::new("http://localhost:9").rail_id(),
        "acp"
    );
}

#[test]
fn side_effecting_dispatch_sees_durable_intent_and_read_only_pays_nothing(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::Verdict;

    let harness = support::journal_harness("chio-intent-classgate")?;

    // Side-effecting call: by the time the tool runs, its intent row is
    // already durably committed (the write happens strictly before dispatch).
    let response = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request("write_file"))?;
    assert!(matches!(response.verdict, Verdict::Allow));
    let seen = harness
        .open_intents_seen_at_invoke
        .lock()
        .expect("probe lock")
        .clone();
    assert_eq!(
        seen,
        vec![1],
        "the side-effecting tool must observe its own durable intent"
    );

    // Read-only call: no intent row exists at invoke time, and none is ever
    // written for it.
    let response = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request("read_file"))?;
    assert!(matches!(response.verdict, Verdict::Allow));
    let seen = harness
        .open_intents_seen_at_invoke
        .lock()
        .expect("probe lock")
        .clone();
    assert!(
        seen.len() == 2 && seen[1] <= 1,
        "a read-only call must not add an intent row (saw {seen:?})"
    );

    let _ = std::fs::remove_file(&harness.db_path);
    Ok(())
}

#[test]
fn intent_write_failure_denies_before_dispatch_without_leaking_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::Verdict;

    // The store rejects exactly the FIRST intent write. The capability grants
    // a single invocation, so a leaked pre-execution hold would starve the
    // retry: the second call succeeding proves the deny reversed everything.
    let harness = support::journal_harness_rejecting_first_intent_write(
        "chio-intent-write-failure",
        Some(1),
    )?;

    let denied = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request_with_id("write_file", "req-denied"))?;
    assert!(
        matches!(denied.verdict, Verdict::Deny),
        "an intent-write failure must deny before dispatch"
    );
    assert_eq!(
        harness.invoked.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the tool must not run when its intent could not be journaled"
    );
    let reason = denied.reason.unwrap_or_default();
    assert!(
        reason.contains("dispatch intent"),
        "deny names the intent-write failure: {reason}"
    );

    let retried = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request_with_id("write_file", "req-retried"))?;
    assert!(
        matches!(retried.verdict, Verdict::Allow),
        "the denied call must not burn the single invocation slot: {:?}",
        retried.reason
    );
    assert_eq!(
        harness.invoked.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the retry dispatches exactly once"
    );

    let _ = std::fs::remove_file(&harness.db_path);
    Ok(())
}

#[test]
fn allow_receipt_consumes_the_intent_leaving_no_orphan() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::Verdict;

    // Drive a full side-effecting evaluate to Allow: committing the receipt
    // must consume the intent in the same transaction, so a later boot
    // reconciliation finds nothing to dead-letter.
    let harness = support::journal_harness("chio-intent-consume-on-allow")?;
    let response = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request("write_file"))?;
    assert!(matches!(response.verdict, Verdict::Allow));
    harness.store.flush_receipt_writes()?;
    assert_eq!(
        harness.store.open_dispatch_intent_count()?,
        0,
        "the committed receipt consumed the intent"
    );
    assert_eq!(harness.store.dead_letter_dispatch_intent_count()?, 0);
    assert!(harness.store.receipt_store_health()?.healthy);

    let _ = std::fs::remove_file(&harness.db_path);
    Ok(())
}

#[test]
fn post_dispatch_tool_error_still_consumes_the_intent() -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::Verdict;

    // A tool that fails AFTER its side effect ends in a post-dispatch deny
    // receipt; committing that receipt must also consume the intent so an
    // effecting call that ends in a deny never leaves a false orphan.
    let harness = support::journal_harness_failing_tool("chio-intent-consume-on-deny")?;
    let response = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request("write_file"))?;
    assert!(matches!(response.verdict, Verdict::Deny));
    harness.store.flush_receipt_writes()?;
    assert_eq!(
        harness.store.open_dispatch_intent_count()?,
        0,
        "the deny receipt consumed the intent"
    );

    let _ = std::fs::remove_file(&harness.db_path);
    Ok(())
}

#[test]
fn monetary_intent_carries_rail_and_authorization_id_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::Verdict;

    // A monetary call authorizes on the rail before dispatch; by invoke time
    // the open intent must already name both the rail and the authorization
    // id, so a crash after this point leaves an orphan an operator can
    // reconcile against the rail without guessing.
    let harness = support::monetary_journal_harness("chio-intent-rail-ref")?;
    let response = harness
        .kernel
        .evaluate_tool_call_blocking(&harness.request("write_file"))?;
    assert!(
        matches!(response.verdict, Verdict::Allow),
        "monetary evaluate allows: {:?}",
        response.reason
    );

    let refs = harness
        .rail_refs_seen_at_invoke
        .lock()
        .expect("rail probe lock")
        .clone();
    assert_eq!(
        refs,
        vec![(Some("x402".to_string()), Some("auth-42".to_string()))],
        "the open monetary intent names its rail and authorization id"
    );

    // The allow receipt still consumes the monetary intent.
    harness.store.flush_receipt_writes()?;
    assert_eq!(harness.store.open_dispatch_intent_count()?, 0);

    let _ = std::fs::remove_file(&harness.db_path);
    Ok(())
}

#[test]
fn boot_reconciliation_dead_letters_a_surviving_orphan() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    // Simulate a crash: an intent is durably open in the store file with no
    // receipt, and the process (the store handle) goes away.
    let path = support::unique_kernel_db_path("chio-intent-boot-reconcile");
    {
        let store = chio_store_sqlite::SqliteReceiptStore::open(&path)?;
        let mut orphan = sample_intent_record("orphan-boot");
        orphan.side_effect_class = SideEffectClass::Monetary;
        orphan.monetary = true;
        orphan.rail = Some("x402".to_string());
        orphan.rail_authorization_id = Some("auth-9".to_string());
        store.record_dispatch_intent(&orphan)?;
    }

    // A fresh kernel attaching the same file must reconcile before serving:
    // the orphan becomes a durable dead-letter incident and the store reads
    // unhealthy until an operator resolves it.
    let store = Arc::new(chio_store_sqlite::SqliteReceiptStore::open(&path)?);
    let mut kernel = chio_kernel::ChioKernel::new(support::journal_config(Keypair::generate()));
    kernel.set_receipt_store_handle(Arc::clone(&store) as Arc<dyn chio_kernel::ReceiptStore>)?;

    assert_eq!(store.open_dispatch_intent_count()?, 0);
    assert_eq!(store.dead_letter_dispatch_intent_count()?, 1);
    let health = store.receipt_store_health()?;
    assert!(!health.healthy, "a surviving orphan flips health");
    assert_eq!(health.dead_letter_dispatch_intents, 1);

    // The incident names the rail and its authorization id.
    let store_for_detail = chio_store_sqlite::SqliteReceiptStore::open_existing(&path)?;
    let report = store_for_detail.reconcile_dispatch_intents(&DeadLetterEverything)?;
    assert_eq!(report.open, 0, "nothing is left open after boot");

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn journal_trait_methods_fail_closed_by_default() {
    let store = UnsupportedStore;

    let record = sample_intent_record("req-1");
    assert!(store.record_dispatch_intent(&record).is_err());
    assert!(store
        .record_dispatch_intent_with_timeout(&record, std::time::Duration::from_millis(50))
        .is_err());

    let key = DispatchIntentKey {
        request_id: "req-1".to_string(),
        parameter_hash: "hash".to_string(),
        tenant_id: None,
    };
    let receipt = sample_receipt();
    assert!(store
        .append_chio_receipt_consuming_intent(&receipt, &key)
        .is_err());
    assert!(store
        .append_chio_receipt_consuming_intent_with_timeout(
            &receipt,
            &key,
            std::time::Duration::from_millis(50),
        )
        .is_err());
    assert!(store
        .attach_dispatch_intent_rail_ref("req-1", None, "auth-1")
        .is_err());

    // Reconcile is a no-op default: a store without the journal has no orphans.
    let report = store
        .reconcile_dispatch_intents(&DeadLetterEverything)
        .expect("default reconcile is a no-op");
    assert_eq!(report.open, 0);
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(report.replayed, 0);
    assert_eq!(report.monetary_reconciled, 0);
    assert_eq!(store.open_dispatch_intent_count().unwrap_or(0), 0);
    assert_eq!(store.dead_letter_dispatch_intent_count().unwrap_or(0), 0);
}
