// Dispatch-intent journal wiring across the evaluator paths.
//
// Included by `src/kernel/tests.rs`. Shares helper items from
// `tests/support.rs` via the surrounding `include!`s.
//
// These tests anchor the crash-window contract at the evaluation level:
//   * the tenant recorded on a journaled intent always equals the tenant the
//     terminal receipt resolves for the same request, so the consuming append
//     can never strand an intent behind a tenant mismatch;
//   * a scope guard left alive by a sibling task on the resuming worker
//     thread never leaks its tenant into another request's intent or receipt.

/// Guard that parks the named request on the blocking pool until released,
/// creating a deterministic suspension point between the evaluation's
/// tenant-scope install and its dispatch-intent write. Every other request
/// passes straight through.
struct HoldRequestGuard {
    request_id: String,
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl Guard for HoldRequestGuard {
    fn name(&self) -> &str {
        "hold-request"
    }

    fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        if ctx.request.request_id == self.request_id {
            let _ = self.entered.send(());
            if let Ok(release) = self.release.lock() {
                let _ = release.recv_timeout(std::time::Duration::from_secs(30));
            }
        }
        Ok(GuardDecision::allow())
    }
}

/// (open-intent count, journaled tenant) pairs observed from inside a tool
/// invocation.
type ObservedIntentJournal = std::sync::Arc<Mutex<Vec<(i64, Option<String>)>>>;

/// Tool server that inspects the dispatch-intent journal from INSIDE
/// `invoke`, capturing the number of open rows and the journaled tenant for
/// its own request at the moment the effect runs. Reads the store file over
/// its own connection so it observes exactly what would survive a crash.
struct IntentProbeServer {
    id: String,
    tools: Vec<String>,
    db_path: PathBuf,
    seen: ObservedIntentJournal,
}

#[async_trait::async_trait]
impl ToolServerConnection for IntentProbeServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let connection = Connection::open(&self.db_path)
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let open: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'open'",
                [],
                |row| row.get(0),
            )
            .map_err(|error| KernelError::Internal(error.to_string()))?;
        let tenant: Option<String> = connection
            .query_row(
                "SELECT tenant_id FROM chio_dispatch_intents WHERE state = 'open' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| KernelError::Internal(error.to_string()))?
            .flatten();
        if let Ok(mut seen) = self.seen.lock() {
            seen.push((open, tenant));
        }
        Ok(serde_json::json!({"status": "ok"}))
    }
}

#[test]
fn nested_flow_dispatch_journals_a_durable_intent_and_consumes_it_on_allow(
) -> Result<(), Box<dyn std::error::Error>> {
    // The nested-flow evaluator shares the crash-window contract with the
    // top-level path: a side-effecting nested dispatch must observe its own
    // durable intent (written before the tool runs, tagged with the
    // request-scoped tenant) and the terminal allow receipt must consume it.
    let path = unique_receipt_db_path("chio-intent-nested-journal");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;

    let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
    kernel.register_tool_server(Box::new(IntentProbeServer {
        id: "srv-nested".to_string(),
        tools: vec!["destructive_update".to_string()],
        db_path: path.clone(),
        seen: std::sync::Arc::clone(&seen),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-nested", "destructive_update")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.set_session_auth_context(&session_id, oauth_auth_with_enterprise_tenant("tenant-A"))?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-nested-intent",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request("req-nested-intent", &cap, "destructive_update", "srv-nested");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    })?;

    assert!(
        matches!(response.verdict, Verdict::Allow),
        "expected Allow, got {:?}: {:?}",
        response.verdict,
        response.reason
    );
    let seen = seen.lock().map_err(|_| "probe lock poisoned")?.clone();
    assert_eq!(
        seen,
        vec![(1, Some("tenant-A".to_string()))],
        "the nested dispatch must observe its own durable intent, tagged \
         with the session tenant"
    );
    assert_eq!(
        response.receipt.tenant_id.as_deref(),
        Some("tenant-A"),
        "the nested terminal receipt carries the request-scoped tenant"
    );
    assert_eq!(
        ReceiptStore::open_dispatch_intent_count(store.as_ref())?,
        0,
        "the nested allow receipt consumed the intent"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Minimal append-only store whose boot reconciliation always fails.
struct ReconcileFailingStore;

impl crate::receipt_store::ReceiptStore for ReconcileFailingStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn reconcile_dispatch_intents(
        &self,
        _reconciler: &dyn crate::receipt_store::DispatchIntentReconciler,
    ) -> Result<crate::receipt_store::DispatchIntentReconcileReport, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "boot reconciliation failed".to_string(),
        ))
    }
}

#[test]
fn failed_boot_reconciliation_leaves_no_store_attached() -> Result<(), Box<dyn std::error::Error>>
{
    // Boot reconciliation must complete BEFORE the store serves: if it
    // fails, the attach is refused and the kernel keeps no store handle, so
    // no new dispatch can interleave with (or run ahead of) an incomplete
    // reconcile pass.
    let mut kernel = make_kernel(make_config());
    let result = kernel.set_receipt_store_handle(std::sync::Arc::new(ReconcileFailingStore));
    assert!(
        result.is_err(),
        "a failed boot reconcile must refuse the attach"
    );
    assert!(
        kernel.with_receipt_store(|_| Ok(()))?.is_none(),
        "the store must not serve after a failed boot reconciliation"
    );
    Ok(())
}

/// Minimal store that counts reconcile passes, reporting sibling-writer
/// recovery support (or not) per test.
struct RecoveryProbeStore {
    reconciles: std::sync::atomic::AtomicU64,
    supports_recovery: bool,
}

impl RecoveryProbeStore {
    fn new(supports_recovery: bool) -> Self {
        Self {
            reconciles: std::sync::atomic::AtomicU64::new(0),
            supports_recovery,
        }
    }
}

impl crate::receipt_store::ReceiptStore for RecoveryProbeStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn reconcile_dispatch_intents(
        &self,
        _reconciler: &dyn crate::receipt_store::DispatchIntentReconciler,
    ) -> Result<crate::receipt_store::DispatchIntentReconcileReport, ReceiptStoreError> {
        self.reconciles
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::receipt_store::DispatchIntentReconcileReport::default())
    }

    fn supports_dispatch_intent_recovery(&self) -> bool {
        self.supports_recovery
    }

    fn load_latest_checkpoint(
        &self,
    ) -> Result<Option<checkpoint::KernelCheckpoint>, ReceiptStoreError> {
        Ok(None)
    }
}

#[test]
fn recovery_worker_reruns_reconciliation_until_dropped() -> Result<(), Box<dyn std::error::Error>>
{
    // A sibling writer can crash at any point after this kernel attaches,
    // so the recovery worker must keep re-running reconciliation for the
    // store's whole life, not just once; dropping the handle joins the
    // thread so a shutting-down kernel never leaves a stray reconciler
    // behind.
    let store = std::sync::Arc::new(RecoveryProbeStore::new(true));
    let handle = crate::receipt_store::DispatchIntentRecoveryHandle::spawn(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>,
        std::time::Duration::from_millis(10),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < deadline
        && store.reconciles.load(std::sync::atomic::Ordering::SeqCst) < 2
    {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    // Joins the worker thread; a wedged worker would hang the test here.
    drop(handle);
    assert!(
        store.reconciles.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "the recovery worker must re-run reconciliation on its cadence"
    );
    Ok(())
}

#[test]
fn attach_spawns_the_recovery_worker_only_for_capable_stores(
) -> Result<(), Box<dyn std::error::Error>> {
    // A store that coordinates sibling writers gets the background worker;
    // one that cannot have siblings (or does not support re-running
    // reconciliation while serving) must not, since its attach-time pass is
    // already complete.
    let mut kernel = make_kernel(make_config());
    let store = std::sync::Arc::new(RecoveryProbeStore::new(true));
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    assert!(
        kernel.dispatch_intent_recovery.is_some(),
        "a sibling-coordinating store must get the background recovery worker"
    );
    let attach_passes = store.reconciles.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        attach_passes >= 1,
        "the attach itself still runs the boot pass"
    );

    let mut kernel = make_kernel(make_config());
    let store = std::sync::Arc::new(RecoveryProbeStore::new(false));
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    assert!(
        kernel.dispatch_intent_recovery.is_none(),
        "a store without sibling writers needs no background worker"
    );
    Ok(())
}

/// Tool server whose dispatch always requires URL elicitations, so the
/// evaluation returns to the caller WITHOUT any tool side effect and without
/// recording a terminal receipt.
struct UrlElicitingServer {
    id: String,
    tools: Vec<String>,
}

#[async_trait::async_trait]
impl ToolServerConnection for UrlElicitingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::UrlElicitationsRequired {
            message: "URL elicitation required before dispatch side effect".to_string(),
            elicitations: Vec::new(),
        })
    }
}

fn url_elicitation_journal_kernel(
    db_path: &Path,
) -> Result<(ChioKernel, std::sync::Arc<SqliteReceiptStore>), Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(db_path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    kernel.register_tool_server(Box::new(UrlElicitingServer {
        id: "srv-elicit".to_string(),
        tools: vec!["write_file".to_string()],
    }));
    Ok((kernel, store))
}

#[test]
fn url_elicitation_exit_clears_the_journaled_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // UrlElicitationsRequired precedes any tool side effect and records no
    // terminal receipt, so the pre-dispatch intent must be cleared on this
    // exit: an intent left open would dead-letter as a false orphan at the
    // next boot even though nothing executed.
    let path = unique_receipt_db_path("chio-intent-elicitation-clear");
    let (kernel, store) = url_elicitation_journal_kernel(&path)?;

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-elicit", "write_file")]),
        300,
    );
    let request = make_request("req-elicit-clear", &cap, "write_file", "srv-elicit");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(kernel.evaluate_tool_call(&request));
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the elicitation error must propagate to the caller"
    );
    assert_eq!(
        ReceiptStore::open_dispatch_intent_count(store.as_ref())?,
        0,
        "a non-dispatch elicitation exit must not leave an open intent"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn nested_flow_url_elicitation_exit_clears_the_journaled_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // Same contract on the nested-flow evaluator: its elicitation arm also
    // returns without dispatching or recording a terminal receipt, so it
    // must clear the intent it journaled.
    let path = unique_receipt_db_path("chio-intent-elicitation-clear-nested");
    let (kernel, store) = url_elicitation_journal_kernel(&path)?;

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-elicit", "write_file")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-elicit-clear-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request("req-elicit-clear-nested", &cap, "write_file", "srv-elicit");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the elicitation error must propagate to the caller"
    );
    assert_eq!(
        ReceiptStore::open_dispatch_intent_count(store.as_ref())?,
        0,
        "a nested non-dispatch elicitation exit must not leave an open intent"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn a_failed_pre_dispatch_cleanup_clears_the_journaled_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // A dispatch error that precedes any tool side effect routes through the
    // pre-dispatch cleanup denial. When a cleanup step itself fails (here:
    // the pre-execution budget reversal), the evaluation exits with an error
    // before any receipt is recorded. The journaled intent must be cleared on
    // that exit: the tool never ran, so an open row would dead-letter at the
    // next boot as a false orphan.
    let path = unique_receipt_db_path("chio-intent-cleanup-abort-clear");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));
    kernel.set_budget_store_handle(std::sync::Arc::new(FailingReverseBudgetStore::new()));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request(
        "req-cleanup-abort-clear",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        result.is_err(),
        "the failed budget reversal must surface as an error, got {result:?}"
    );
    store.flush_receipt_writes()?;
    assert_eq!(
        store.open_dispatch_intent_count()?,
        0,
        "an aborted pre-dispatch cleanup must not leave an open intent for a \
         tool that never ran"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn nested_flow_failed_pre_dispatch_cleanup_clears_the_journaled_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // Nested-flow mirror of the cleanup-abort clear: its pre-dispatch denial
    // arms route through the same cleanup builder and share the contract.
    let path = unique_receipt_db_path("chio-intent-cleanup-abort-clear-nested");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    kernel.register_tool_server(Box::new(ToolNotRegisteredDispatchServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
    )));
    kernel.set_budget_store_handle(std::sync::Arc::new(FailingReverseBudgetStore::new()));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-cleanup-abort-clear-nested",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request(
        "req-cleanup-abort-clear-nested",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        kernel
            .evaluate_tool_call_with_nested_flow_client_async(&context, &request, &mut client, None)
            .await
    });
    assert!(
        result.is_err(),
        "the failed budget reversal must surface as an error, got {result:?}"
    );
    store.flush_receipt_writes()?;
    assert_eq!(
        store.open_dispatch_intent_count()?,
        0,
        "a nested aborted pre-dispatch cleanup must not leave an open intent \
         for a tool that never ran"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn a_second_cleanup_fault_receipt_persists_after_the_first_consumes_the_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // A URL-elicitation unwind can legitimately record more than one signed
    // fault receipt for the same request (here: a failed runtime-admission
    // release followed by a failed budget reversal). With the journal
    // enabled, the first fault receipt consumes the dispatch intent inside
    // its own append; the later fault receipt must then append plainly
    // instead of retrying the consume against the deleted row and losing its
    // audit record.
    let path = unique_receipt_db_path("chio-intent-second-fault-receipt");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    let stream_attempts = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "srv-chio-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&stream_attempts),
    )));
    kernel.set_budget_store_handle(std::sync::Arc::new(FailingReverseBudgetStore::new()));
    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(FailingReleaseRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
        releases: std::sync::Arc::clone(&releases),
        expected_request_id: "req-second-fault-receipt",
        admission_id: "adm-second-fault-receipt",
        lease_id: "lease-second-fault-receipt",
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_invocation_limited_grant(
            "srv-chio-runtime",
            "destructive_update",
            1,
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-second-fault-receipt",
        &cap,
        "destructive_update",
        "srv-chio-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "the cleanup faults must not mask the elicitation error: {result:?}"
    );
    // First fault: the failed runtime-admission release. Its receipt lands
    // while the intent row is still open, so its append consumes the intent.
    assert_url_elicitation_release_fault_recorded(&kernel, "lease-second-fault-receipt")?;
    // Second fault: the failed budget reversal, recorded for the SAME request
    // after the intent row is already gone. It must persist as a plain
    // append, not vanish behind a missing-intent conflict.
    assert_url_elicitation_budget_cleanup_fault_recorded(
        &kernel,
        "url_elicitation_budget_reversal",
        &cap.id,
    )?;
    store.flush_receipt_writes()?;
    assert_eq!(
        store.open_dispatch_intent_count()?,
        0,
        "the first fault receipt consumed the intent exactly once"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Store whose consuming append COMMITS (receipt recorded, intent consumed)
/// but reports a timeout: the writer-queued job outran the caller's bounded
/// wait. A later consuming append for the same request finds the intent gone
/// and rejects, mirroring the durable store's key-guarded delete.
struct TimedOutConsumeStore {
    receipts: Mutex<Vec<String>>,
    intent_open: std::sync::atomic::AtomicBool,
}

impl TimedOutConsumeStore {
    fn new() -> Self {
        Self {
            receipts: Mutex::new(Vec::new()),
            intent_open: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn receipt_ids(&self) -> Vec<String> {
        self.receipts
            .lock()
            .map(|receipts| receipts.clone())
            .unwrap_or_default()
    }
}

impl crate::receipt_store::ReceiptStore for TimedOutConsumeStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if let Ok(mut receipts) = self.receipts.lock() {
            receipts.push(receipt.id.clone());
        }
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_chio_receipt_consuming_intent(
        &self,
        receipt: &ChioReceipt,
        _intent: &crate::receipt_store::DispatchIntentKey,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        if !self
            .intent_open
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ReceiptStoreError::Conflict(
                "dispatch intent not found; refusing to commit the receipt".to_string(),
            ));
        }
        if let Ok(mut receipts) = self.receipts.lock() {
            receipts.push(receipt.id.clone());
        }
        Err(ReceiptStoreError::Timeout {
            operation: "receipt consuming append".to_string(),
            timeout_ms: 25,
        })
    }
}

#[test]
fn a_receipt_after_a_timed_out_consume_appends_plainly() -> Result<(), Box<dyn std::error::Error>>
{
    // A timed-out consuming append is an UNCERTAIN consume: the queued job
    // can still commit and delete the intent row after the caller's bounded
    // wait expired (here it already has). The first receipt's timeout must
    // propagate unchanged, but the request's intent handle must not outlive
    // it: a later receipt for the same request (a second cleanup fault, for
    // example) would otherwise retry the consume against the missing row and
    // lose its audit record.
    let mut kernel = make_kernel(make_config());
    let store = std::sync::Arc::new(TimedOutConsumeStore::new());
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;

    let kp = make_keypair();
    let first = make_signed_receipt(&kp, "receipt-uncertain-consume-1");
    let second = make_signed_receipt(&kp, "receipt-uncertain-consume-2");
    let _intent_scope = kernel.scope_dispatch_intent_for_request(
        "req-uncertain-consume",
        Some(crate::receipt_store::DispatchIntentHandle {
            request_id: "req-uncertain-consume".to_string(),
            parameter_hash: first.action.parameter_hash.clone(),
            tenant_id: None,
        }),
    );

    let error =
        kernel.record_chio_receipt_consuming_optional_intent(&first, Some("req-uncertain-consume"));
    assert!(
        matches!(
            error,
            Err(KernelError::ReceiptPersistence(
                ReceiptStoreError::Timeout { .. }
            ))
        ),
        "the first receipt's timeout must still propagate: {error:?}"
    );

    kernel.record_chio_receipt_consuming_optional_intent(&second, Some("req-uncertain-consume"))?;
    assert_eq!(
        store.receipt_ids(),
        vec![first.id.clone(), second.id.clone()],
        "the receipt recorded after the uncertain consume must persist"
    );
    Ok(())
}

#[test]
fn intent_and_receipt_tenant_ignore_a_foreign_thread_scope(
) -> Result<(), Box<dyn std::error::Error>> {
    // A tenant-scoped sibling task can hold its thread-local scope guard
    // across an await, so the worker that resumes THIS evaluation after its
    // guard-pipeline suspension may carry a foreign tenant in the thread
    // local. The request-scoped tenant resolution must win on both the
    // intent write and the terminal receipt: a sessionless call stays
    // untagged and its intent is consumed by its receipt.
    let path = unique_receipt_db_path("chio-intent-tenant-isolation");
    let mut config = make_config();
    config.dispatch_intent_journal = crate::DispatchIntentJournalMode::SideEffecting;
    // Force the guard pipeline onto the blocking pool so the evaluation
    // genuinely suspends (and can resume under a foreign scope) even on a
    // current-thread runtime.
    config.deadlines.always_offload_guards = true;
    let mut kernel = make_kernel(config);
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["write_file"])));

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    kernel.add_guard(Box::new(HoldRequestGuard {
        request_id: "req-tenant-isolated".to_string(),
        entered: entered_tx,
        release: std::sync::Mutex::new(release_rx),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "write_file")]),
        300,
    );
    let request = make_request("req-tenant-isolated", &cap, "write_file", "srv-a");

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let response: Result<_, Box<dyn std::error::Error>> = rt.block_on(async {
        let evaluation = kernel.evaluate_tool_call(&request);
        tokio::pin!(evaluation);
        // Drive the evaluation until it parks inside its guard on the
        // blocking pool; the entered signal proves it suspended after
        // installing its own (empty) tenant scopes.
        let entered = tokio::task::spawn_blocking(move || entered_rx.recv());
        tokio::pin!(entered);
        tokio::select! {
            _ = &mut evaluation => panic!("the evaluation must park in the guard"),
            joined = &mut entered => {
                joined??;
            }
        }
        // Model the sibling task: a foreign tenant scope alive on the very
        // thread that resumes the parked evaluation.
        let _foreign = scope_receipt_tenant_id(Some("tenant-foreign".to_string()));
        release_tx.send(())?;
        evaluation.await.map_err(Into::into)
    });
    let response = response?;

    assert!(
        matches!(response.verdict, Verdict::Allow),
        "expected Allow, got {:?}: {:?}",
        response.verdict,
        response.reason
    );
    assert!(
        response.receipt.tenant_id.is_none(),
        "a sessionless call must not adopt a foreign task's tenant scope \
         (got {:?})",
        response.receipt.tenant_id
    );
    store.flush_receipt_writes()?;
    assert_eq!(
        store.open_dispatch_intent_count()?,
        0,
        "the terminal receipt consumed the intent under the same tenant"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Store whose next consuming append parks until released, holding its
/// caller inside the kernel-wide receipt write lock so a second receipt for
/// the same request can race the intent-handle lookup. Consumes are keyed on
/// request id alone: the test asserts WHICH path each receipt takes, not the
/// store-side key match.
struct ParkedConsumeStore {
    open_intents: Mutex<std::collections::HashSet<String>>,
    consumed: Mutex<Vec<String>>,
    plain_appends: std::sync::atomic::AtomicU64,
    park_next_consume: std::sync::atomic::AtomicBool,
    entered_consume: std::sync::mpsc::Sender<()>,
    release_consume: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl crate::receipt_store::ReceiptStore for ParkedConsumeStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.plain_appends
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_chio_receipt_consuming_intent(
        &self,
        _receipt: &ChioReceipt,
        key: &crate::receipt_store::DispatchIntentKey,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        if self
            .park_next_consume
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let _ = self.entered_consume.send(());
            if let Ok(release) = self.release_consume.lock() {
                let _ = release.recv_timeout(std::time::Duration::from_secs(30));
            }
        }
        let mut open = self
            .open_intents
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("open-intent lock poisoned".to_string()))?;
        if open.remove(&key.request_id) {
            self.consumed
                .lock()
                .map_err(|_| ReceiptStoreError::Conflict("consumed lock poisoned".to_string()))?
                .push(key.request_id.clone());
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
fn concurrent_receipts_for_one_request_consume_once_and_append_plainly(
) -> Result<(), Box<dyn std::error::Error>> {
    // A request can persist more than one receipt (a cleanup-fault receipt
    // racing the terminal outcome). Exactly one may take the consuming
    // append; the other must observe the handle removal under the receipt
    // write lock and append plainly, so BOTH audit records persist and the
    // handle does not linger for later attempts.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let store = std::sync::Arc::new(ParkedConsumeStore {
        open_intents: Mutex::new(std::collections::HashSet::from([
            "req-two-receipts".to_string()
        ])),
        consumed: Mutex::new(Vec::new()),
        plain_appends: std::sync::atomic::AtomicU64::new(0),
        park_next_consume: std::sync::atomic::AtomicBool::new(true),
        entered_consume: entered_tx,
        release_consume: Mutex::new(release_rx),
    });
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store_handle(
        std::sync::Arc::clone(&store) as std::sync::Arc<dyn crate::receipt_store::ReceiptStore>
    )?;

    let kp = make_keypair();
    let receipt_a = make_signed_receipt(&kp, "rcpt-race-a");
    let receipt_b = make_signed_receipt(&kp, "rcpt-race-b");
    let handle = crate::receipt_store::DispatchIntentHandle {
        request_id: "req-two-receipts".to_string(),
        parameter_hash: receipt_a.action.parameter_hash.clone(),
        tenant_id: None,
    };
    let _intent_scope = kernel.scope_dispatch_intent_for_request("req-two-receipts", Some(handle));

    let (first, second) = std::thread::scope(|threads| {
        let kernel = &kernel;
        let receipt_a = &receipt_a;
        let receipt_b = &receipt_b;
        let first = threads.spawn(move || {
            kernel.record_chio_receipt_consuming_optional_intent(receipt_a, Some("req-two-receipts"))
        });
        // The first persist is now parked inside the consuming append,
        // holding the receipt write lock.
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("first persist reaches the consuming append");
        let second = threads.spawn(move || {
            kernel.record_chio_receipt_consuming_optional_intent(receipt_b, Some("req-two-receipts"))
        });
        // Give the second persist time to enter and block on the receipt
        // write lock while the first still holds it; releasing then drives
        // the full contended interleaving. A slower spawn only makes the
        // race narrower, never the assertions wrong.
        std::thread::sleep(std::time::Duration::from_millis(200));
        release_tx.send(()).expect("release the parked consume");
        (
            first.join().expect("first persist thread"),
            second.join().expect("second persist thread"),
        )
    });

    first?;
    second.map_err(|error| {
        format!("the second receipt must append plainly once the intent is consumed: {error}")
    })?;
    let consumed = store
        .consumed
        .lock()
        .map_err(|_| "consumed lock poisoned")?
        .clone();
    assert_eq!(
        consumed,
        vec!["req-two-receipts".to_string()],
        "exactly one receipt consumes the intent"
    );
    assert_eq!(
        store
            .plain_appends
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the losing receipt persists through the plain append"
    );
    assert!(
        kernel
            .dispatch_intent_for_request(Some("req-two-receipts"))
            .is_none(),
        "the consumed handle must not linger for later receipts"
    );
    Ok(())
}
