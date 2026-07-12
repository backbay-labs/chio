// Hot-path deadline and writer-watchdog behavior: a hung guard or tool server
// fails closed within budget without pinning a worker, a dispatch deadline runs
// the full cancellation unwind, and a wedged writer denies before any tool side
// effect.

/// A guard whose `evaluate` blocks well past any budget, modeling a guard doing
/// synchronous blocking I/O.
struct SleepingGuard {
    label: String,
}

impl Guard for SleepingGuard {
    fn name(&self) -> &str {
        &self.label
    }
    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        // Well past any test budget, but bounded so the detached blocking thread
        // does not stall tokio runtime teardown after the deadline has fired.
        std::thread::sleep(Duration::from_secs(2));
        Ok(GuardDecision {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        })
    }
}

/// A guard that records it ran and always allows, to prove non-targeted guards
/// still execute under per-guard budgeting.
struct RecordingGuard {
    label: String,
    ran: Arc<AtomicU64>,
}

impl Guard for RecordingGuard {
    fn name(&self) -> &str {
        &self.label
    }
    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        self.ran.fetch_add(1, Ordering::SeqCst);
        Ok(GuardDecision {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        })
    }
}

/// A tool server whose `invoke` never returns, modeling a wedged tool server.
struct HangingToolServer {
    id: String,
    tools: Vec<String>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for HangingToolServer {
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
        self.invocations.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<()>().await;
        unreachable!("hanging tool server never returns")
    }
}

/// A tool server whose `invoke` performs synchronous blocking work *before* its
/// first `.await`, modeling a connection doing blocking I/O in its poll. Polled
/// inline on the async worker it pins the worker so the dispatch timeout never
/// fires; only offloading the call to a blocking thread keeps the deadline live.
struct BlockingToolServer {
    id: String,
    tools: Vec<String>,
    invocations: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl ToolServerConnection for BlockingToolServer {
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
        self.invocations.fetch_add(1, Ordering::SeqCst);
        // Synchronous blocking work before the first `.await`. Bounded so the
        // offloaded blocking thread does not stall runtime teardown after the
        // deadline has fired.
        std::thread::sleep(Duration::from_secs(2));
        Ok(serde_json::json!({ "ok": true }))
    }
}

/// A store double that reports a wedged writer, to drive the pre-dispatch gate
/// without a real stuck sqlite writer.
struct WedgedLivenessStore;

impl ReceiptStore for WedgedLivenessStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Wedged
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guard_pipeline_budget_denies_hung_guard_and_frees_worker(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = make_config();
    config.deadlines.guard_pipeline_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(SleepingGuard {
        label: "sleeping".to_string(),
    }));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-hpd", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-hpd", "noop")]),
        300,
    );
    let request = make_request("req-hpd-guard", &cap, "noop", "srv-hpd");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    let elapsed = start.elapsed();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        elapsed < Duration::from_secs(1),
        "deadline should fire near 200ms, well before the 2s guard sleep, took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn per_guard_budget_bounds_single_guard_not_pipeline(
) -> Result<(), Box<dyn std::error::Error>> {
    let fast_ran = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    // No pipeline budget; only the slow guard gets a 200ms override.
    config
        .deadlines
        .per_guard_budget_ms
        .insert("slow".to_string(), 200);
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(RecordingGuard {
        label: "fast".to_string(),
        ran: Arc::clone(&fast_ran),
    }));
    kernel.add_guard(Box::new(SleepingGuard {
        label: "slow".to_string(),
    }));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-pg", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-pg", "noop")]),
        300,
    );
    let request = make_request("req-pg", &cap, "noop", "srv-pg");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(start.elapsed() < Duration::from_secs(1));
    // The fast guard ran before the slow guard tripped its override.
    assert_eq!(fast_ran.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_budget_bounds_the_per_guard_loop(
) -> Result<(), Box<dyn std::error::Error>> {
    // With per-guard budgets configured, the whole guard loop must still honor
    // the pipeline budget. A single guard whose own budget is generous but whose
    // work exceeds the pipeline budget must trip the pipeline deadline rather
    // than running to completion.
    let mut config = make_config();
    config.deadlines.guard_pipeline_budget_ms = 300;
    // A generous per-guard override forces the per-guard offloaded path yet never
    // fires on its own, so only the pipeline deadline can stop the slow guard.
    config
        .deadlines
        .per_guard_budget_ms
        .insert("slow".to_string(), 5_000);
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(SleepingGuard {
        label: "slow".to_string(),
    }));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-pipeline", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-pipeline", "noop")]),
        300,
    );
    let request = make_request("req-pipeline", &cap, "noop", "srv-pipeline");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    let elapsed = start.elapsed();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        elapsed < Duration::from_secs(1),
        "the pipeline deadline must fire near 300ms, well before the 2s guard sleep, took {elapsed:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_budget_expiry_runs_full_unwind_and_emits_cancelled_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let invocations = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.dispatch_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(HangingToolServer {
        id: "srv-hang".to_string(),
        tools: vec!["noop".to_string()],
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-hang", "noop")]),
        300,
    );
    let request = make_request("req-dispatch-deadline", &cap, "noop", "srv-hang");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "deadline must fire near 200ms"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1, "dispatch did start");
    assert_eq!(response.verdict, Verdict::Deny);

    // Exactly one signed Cancelled receipt was persisted, via the same path as a
    // cancellation.
    assert_eq!(
        kernel.receipt_log().len(),
        1,
        "one Cancelled receipt persisted"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_writer_watchdog_denies_before_side_effect(
) -> Result<(), Box<dyn std::error::Error>> {
    let invocations = Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(WedgedLivenessStore))?;
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-wedged",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    kernel.refresh_receipt_writer_liveness_for_test();
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-wedged", "noop")]),
        300,
    );
    let request = make_request("req-wedged", &cap, "noop", "srv-wedged");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "no tool side effect may occur while the writer is wedged"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_writer_denies_before_dispatch_without_a_running_watchdog(
) -> Result<(), Box<dyn std::error::Error>> {
    // No watchdog is started and no test refresh is published, mirroring a
    // freshly attached durable store on an edge that never calls
    // `spawn_receipt_writer_watchdog`. The gate must still sample the writer's
    // liveness directly and fail closed on a wedged writer, rather than admitting
    // on the not-yet-probed `Unknown` verdict and reaching a tool side effect.
    let invocations = Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(WedgedLivenessStore))?;
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-no-watchdog",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-no-watchdog", "noop")]),
        300,
    );
    let request = make_request("req-no-watchdog", &cap, "noop", "srv-no-watchdog");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "no tool side effect may occur while the writer is wedged"
    );
    Ok(())
}

/// A wedged store that also counts capability-snapshot writes, to prove the
/// snapshot path denies before entering the (unbounded) writer-backed write.
struct SnapshotCountingWedgedStore {
    snapshot_writes: Arc<AtomicU64>,
}

impl ReceiptStore for SnapshotCountingWedgedStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.snapshot_writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Wedged
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wedged_writer_denies_before_evaluation_capability_snapshot(
) -> Result<(), Box<dyn std::error::Error>> {
    // The observed-capability snapshot in the evaluation hot path is a
    // writer-backed write with an unbounded wait. A wedged writer must be denied
    // before that write is entered, not after it has already hung the request.
    let invocations = Arc::new(AtomicU64::new(0));
    let snapshot_writes = Arc::new(AtomicU64::new(0));
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(SnapshotCountingWedgedStore {
        snapshot_writes: Arc::clone(&snapshot_writes),
    }))?;
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-snapshot",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-snapshot", "noop")]),
        300,
    );
    // Publish the wedged verdict only now, so the snapshot that capability
    // issuance above records is not what this test measures.
    kernel.refresh_receipt_writer_liveness_for_test();
    let snapshots_before_dispatch = snapshot_writes.load(Ordering::SeqCst);
    let request = make_request("req-snapshot", &cap, "noop", "srv-snapshot");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        snapshot_writes.load(Ordering::SeqCst),
        snapshots_before_dispatch,
        "evaluation must deny before entering the capability snapshot write"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "no tool side effect may occur while the writer is wedged"
    );
    Ok(())
}

/// A healthy store that records how the evaluation hot path invokes the
/// observed-capability snapshot: the budget passed to the bounded writer path,
/// and any use of the unbounded path.
struct SnapshotBudgetStore {
    bounded_budget_ms: Arc<AtomicU64>,
    unbounded_calls: Arc<AtomicU64>,
}

impl ReceiptStore for SnapshotBudgetStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.unbounded_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn record_capability_snapshot_with_timeout(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
        budget: std::time::Duration,
    ) -> Result<(), ReceiptStoreError> {
        self.bounded_budget_ms
            .store(budget.as_millis() as u64, Ordering::SeqCst);
        Ok(())
    }
    fn writer_liveness(&self, _stall_threshold: std::time::Duration) -> ReceiptWriterLiveness {
        ReceiptWriterLiveness::Healthy
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_writer_records_capability_snapshot_through_the_bounded_path(
) -> Result<(), Box<dyn std::error::Error>> {
    // A writer that is healthy at the pre-dispatch gate can still stall on the
    // observed-capability snapshot, which commits through the receipt writer.
    // The hot path must take that write through the bounded writer path with the
    // append budget, not the unbounded one, so it fails closed rather than hangs.
    let bounded_budget_ms = Arc::new(AtomicU64::new(0));
    let unbounded_calls = Arc::new(AtomicU64::new(0));
    let config = make_config();
    let expected_budget_ms =
        u64::try_from(config.deadlines.receipt_append_budget().as_millis()).unwrap_or(u64::MAX);
    let mut kernel = make_kernel(config);
    kernel.set_receipt_store(Box::new(SnapshotBudgetStore {
        bounded_budget_ms: Arc::clone(&bounded_budget_ms),
        unbounded_calls: Arc::clone(&unbounded_calls),
    }))?;
    kernel.register_tool_server(Box::new(EchoServer::new("srv-snap-budget", vec!["noop"])));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-snap-budget", "noop")]),
        300,
    );
    // Isolate the dispatch-time snapshot from the issuance-time snapshot above.
    bounded_budget_ms.store(0, Ordering::SeqCst);
    unbounded_calls.store(0, Ordering::SeqCst);
    let request = make_request("req-snap-budget", &cap, "noop", "srv-snap-budget");
    let kernel = Arc::new(kernel);

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        bounded_budget_ms.load(Ordering::SeqCst),
        expected_budget_ms,
        "the observed-capability snapshot must use the bounded writer path with the append budget"
    );
    assert_eq!(
        unbounded_calls.load(Ordering::SeqCst),
        0,
        "the hot-path snapshot must not use the unbounded writer path"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn phase_dispatch_honors_the_configured_dispatch_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    // The `ToolEvaluator::dispatch` phase entry point is reachable by custom
    // evaluators independently of the full evaluate path. With a dispatch budget
    // configured it must enforce the deadline too, so a wedged tool server fails
    // closed within budget rather than hanging the caller indefinitely.
    use crate::kernel::evaluator::{BlockingToolEvaluator, ToolEvaluator};

    let invocations = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.dispatch_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(HangingToolServer {
        id: "srv-phase-hang".to_string(),
        tools: vec!["noop".to_string()],
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-phase-hang", "noop")]),
        300,
    );
    let request = make_request("req-phase-dispatch", &cap, "noop", "srv-phase-hang");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let result = BlockingToolEvaluator
        .dispatch(&kernel, &request, false)
        .await;
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "the phase dispatch deadline must fire near 200ms, well before a hung server"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1, "dispatch did start");
    match result {
        Err(KernelError::HotPathDeadlineExceeded { stage, .. }) => {
            assert_eq!(stage, HotPathStage::Dispatch);
        }
        other => panic!("expected a dispatch deadline error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_budget_bounds_a_connection_that_blocks_before_awaiting(
) -> Result<(), Box<dyn std::error::Error>> {
    // A connection that performs synchronous blocking work before its first
    // `.await` must still be bounded by the dispatch budget. Wrapping the call in
    // `timeout` alone does not help: the blocking poll pins the async worker and
    // the timer never fires. Offloading the call onto a blocking thread keeps the
    // worker free so the deadline fires near the budget.
    let invocations = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.dispatch_budget_ms = 200;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(BlockingToolServer {
        id: "srv-blocking".to_string(),
        tools: vec!["noop".to_string()],
        invocations: Arc::clone(&invocations),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-blocking", "noop")]),
        300,
    );
    let request = make_request("req-blocking-dispatch", &cap, "noop", "srv-blocking");
    let kernel = Arc::new(kernel);

    let start = std::time::Instant::now();
    let response = kernel.evaluate_tool_call(&request).await?;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "a connection that blocks before awaiting must be bounded near the 200ms dispatch budget, took {elapsed:?}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "dispatch did start the blocking connection"
    );
    assert_eq!(response.verdict, Verdict::Deny);
    Ok(())
}

/// A guard that records the thread it ran on, to observe whether the pipeline
/// offloaded it onto a blocking thread or ran it inline on the async worker.
struct ThreadRecordingGuard {
    label: String,
    thread: Arc<std::sync::Mutex<Option<std::thread::ThreadId>>>,
}

impl Guard for ThreadRecordingGuard {
    fn name(&self) -> &str {
        &self.label
    }
    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        *self.thread.lock().expect("record guard thread") = Some(std::thread::current().id());
        Ok(GuardDecision {
            verdict: Verdict::Allow,
            evidence: Vec::new(),
        })
    }
}

#[test]
fn always_offload_moves_guards_off_the_async_worker_without_a_timer(
) -> Result<(), Box<dyn std::error::Error>> {
    // `always_offload_guards` asks to move blocking guards onto spawn_blocking so
    // they cannot pin the async worker. That offload needs no time driver, only
    // the (absent) timeout wrapping does, so it must still take effect in a
    // timerless runtime rather than silently degrading to inline.
    let mut config = make_config();
    config.deadlines.always_offload_guards = true;
    let mut kernel = make_kernel(config);
    let guard_thread = Arc::new(std::sync::Mutex::new(None));
    kernel.add_guard(Box::new(ThreadRecordingGuard {
        label: "recording".to_string(),
        thread: Arc::clone(&guard_thread),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-offload", "noop")]),
        300,
    );
    let request = make_request("req-offload", &cap, "noop", "srv-offload");
    let scope = make_scope(vec![make_grant("srv-offload", "noop")]);

    // A current-thread runtime built without a time driver: dispatch timeouts
    // would panic, so the pipeline must degrade the timeout, not the offload.
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        assert!(
            !super::dispatch::dispatch_timer_available(),
            "the test runtime must be timerless"
        );
        let worker = std::thread::current().id();
        let outcome = kernel
            .run_guards_within_budget(&request, &scope, None, None)
            .await;
        assert!(outcome.is_ok(), "the recording guard allows");
        let guard = guard_thread.lock().expect("read guard thread").expect("guard ran");
        assert_ne!(
            guard, worker,
            "always_offload must move the guard off the async worker even without a timer"
        );
    });
    Ok(())
}

#[test]
fn always_offload_moves_guards_off_the_worker_without_a_timer_even_with_a_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    // A guard budget configured alongside `always_offload_guards` must not defeat
    // the offload in a timerless runtime. The budget alone is unenforceable
    // without a time driver, but the operator still asked to keep a blocking guard
    // off the async worker, so the pipeline must offload onto spawn_blocking and
    // skip only the (unenforceable) timeout rather than degrading to inline.
    let mut config = make_config();
    config.deadlines.always_offload_guards = true;
    config.deadlines.guard_pipeline_budget_ms = 200;
    let mut kernel = make_kernel(config);
    let guard_thread = Arc::new(std::sync::Mutex::new(None));
    kernel.add_guard(Box::new(ThreadRecordingGuard {
        label: "recording".to_string(),
        thread: Arc::clone(&guard_thread),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-offload", "noop")]),
        300,
    );
    let request = make_request("req-offload-budget", &cap, "noop", "srv-offload");
    let scope = make_scope(vec![make_grant("srv-offload", "noop")]);

    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        assert!(
            !super::dispatch::dispatch_timer_available(),
            "the test runtime must be timerless"
        );
        let worker = std::thread::current().id();
        let outcome = kernel
            .run_guards_within_budget(&request, &scope, None, None)
            .await;
        assert!(outcome.is_ok(), "the recording guard allows");
        let guard = guard_thread
            .lock()
            .expect("read guard thread")
            .expect("guard ran");
        assert_ne!(
            guard, worker,
            "a configured budget must not defeat always_offload in a timerless runtime"
        );
    });
    Ok(())
}

#[test]
fn always_offload_runs_guards_inline_without_a_tokio_runtime(
) -> Result<(), Box<dyn std::error::Error>> {
    // A synchronous host bridges dispatch through `futures::executor::block_on`,
    // so no Tokio runtime is entered. `always_offload_guards` must degrade to
    // running the guards inline: `spawn_blocking` panics without a runtime, so
    // taking the offload path here would abort the whole dispatch.
    let ran = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.always_offload_guards = true;
    let mut kernel = make_kernel(config);
    kernel.add_guard(Box::new(RecordingGuard {
        label: "recording".to_string(),
        ran: Arc::clone(&ran),
    }));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-offload", "noop")]),
        300,
    );
    let request = make_request("req-offload-no-runtime", &cap, "noop", "srv-offload");
    let scope = make_scope(vec![make_grant("srv-offload", "noop")]);

    // Drive the future with the futures executor: no Tokio runtime is entered.
    let outcome = futures::executor::block_on(kernel.run_guards_within_budget(
        &request,
        &scope,
        None,
        None,
    ));

    assert!(
        outcome.is_ok(),
        "guards must run inline without a runtime instead of panicking in spawn_blocking"
    );
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "the guard must still execute on the inline fallback"
    );
    Ok(())
}

#[test]
fn nested_dispatch_isolates_a_synchronously_blocking_call_from_the_async_pool(
) -> Result<(), Box<dyn std::error::Error>> {
    // A nested-flow tool-server call that blocks synchronously before its first
    // `.await` must not starve the async worker pool. The nested path cannot
    // move the call onto `spawn_blocking` (its future borrows the flow bridge),
    // so it drives budgeted calls under `block_in_place`, which promotes a
    // replacement worker. A bare inline `timeout` (what the nested path used
    // before) pins the polling worker instead. On a single-worker runtime the
    // difference is stark: a concurrent heartbeat keeps ticking under the helper
    // but stalls under the inline timeout.
    let budget = Duration::from_millis(50);
    let block = Duration::from_millis(400);
    const HEARTBEAT_MS: u64 = 5;

    async fn count_heartbeats_while<F, Fut>(make_call: F) -> u64
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let ticks = Arc::new(AtomicU64::new(0));
        let ticks_beat = Arc::clone(&ticks);
        let beat = tokio::spawn(async move {
            loop {
                ticks_beat.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;
            }
        });
        let blocking = tokio::spawn(make_call());
        let _ = blocking.await;
        beat.abort();
        ticks.load(Ordering::SeqCst)
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;

    // The inline timeout the nested path used before: it pins the sole worker.
    let inline_ticks = runtime.block_on(count_heartbeats_while(|| async move {
        let _ = tokio::time::timeout(budget, async {
            std::thread::sleep(block);
            Ok::<_, KernelError>(ToolServerOutput::Value(serde_json::json!({ "ok": true })))
        })
        .await;
    }));

    // The shared helper: `block_in_place` keeps the async pool alive, and the
    // borrowed-bridge call still runs to completion on this thread.
    let helper_ticks = runtime.block_on(count_heartbeats_while(|| async move {
        let call = async {
            std::thread::sleep(block);
            Ok::<_, KernelError>(ToolServerOutput::Value(serde_json::json!({ "ok": true })))
        };
        let output = crate::kernel::dispatch::dispatch_nested_call_within_budget(call, budget).await;
        assert!(
            matches!(output, Ok(ToolServerOutput::Value(_))),
            "the blocking nested call completes through the helper"
        );
    }));

    // The heartbeat sleeps `HEARTBEAT_MS` between ticks, so a pool that keeps
    // running for the whole `block` records roughly `block / HEARTBEAT_MS` ticks.
    let expected_live = block.as_millis() as u64 / HEARTBEAT_MS;
    assert!(
        inline_ticks <= 2,
        "the inline timeout pins the sole worker, starving the heartbeat (ticks={inline_ticks})"
    );
    assert!(
        helper_ticks >= expected_live / 4,
        "block_in_place must keep the async pool alive while the nested call blocks (ticks={helper_ticks}, expected ~{expected_live})"
    );
    Ok(())
}

#[test]
fn timed_out_dispatch_aborts_a_queued_blocking_task_before_it_runs_the_tool(
) -> Result<(), Box<dyn std::error::Error>> {
    // When the dispatch deadline fires while the blocking pool is saturated, the
    // offloaded call may still be queued (not yet started). Dropping its join
    // handle only detaches the task, so without an explicit abort it would later
    // run the tool after the kernel has already returned a timed-out response and
    // unwound its charges. The timeout arm must abort the queued task so the
    // side effect never happens.
    let invocations = Arc::new(AtomicU64::new(0));
    let mut config = make_config();
    config.deadlines.dispatch_budget_ms = 100;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-abort",
        vec!["noop"],
        Arc::clone(&invocations),
    )));
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-abort", "noop")]),
        300,
    );
    let request = make_request("req-abort", &cap, "noop", "srv-abort");
    let kernel = Arc::new(kernel);

    // A multi-thread runtime with a single blocking thread: occupying it forces
    // the dispatch offload to queue behind the blocker rather than start.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let blocker_started = Arc::new(AtomicBool::new(false));
        let started = Arc::clone(&blocker_started);
        // Hold the sole blocking thread well past the 100ms dispatch budget so
        // the dispatch task cannot start until after the deadline has fired.
        let _blocker = tokio::task::spawn_blocking(move || {
            started.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(800));
        });
        while !blocker_started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let start = std::time::Instant::now();
        let response = kernel
            .evaluate_tool_call(&request)
            .await
            .unwrap_or_else(|e| panic!("evaluate should return a deny response, not error: {e}"));
        assert!(
            start.elapsed() < Duration::from_millis(600),
            "the dispatch deadline must fire near 100ms, well before the 800ms blocker frees the pool"
        );
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "the queued dispatch must not have started before the deadline fired"
        );

        // Let the blocker release the pool; the aborted dispatch must never run
        // the tool afterwards.
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        assert_eq!(
            invocations.load(Ordering::SeqCst),
            0,
            "a timed-out dispatch must be aborted, not left to run the tool after the deadline"
        );
    });
    Ok(())
}

#[test]
fn watchdog_does_not_start_without_a_timer() -> Result<(), Box<dyn std::error::Error>> {
    // Starting the watchdog in a runtime with no time driver would panic when its
    // poll interval is constructed. It must degrade to not starting instead, and
    // the pre-dispatch gate keeps sampling the store directly.
    let kernel = Arc::new(make_kernel(make_config()));
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        assert!(
            !super::dispatch::dispatch_timer_available(),
            "the test runtime must be timerless"
        );
        kernel.spawn_receipt_writer_watchdog();
        assert!(
            !kernel.receipt_writer_watchdog_is_running(),
            "no watchdog poll task may start without a time driver"
        );
    });
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn watchdog_does_not_keep_the_kernel_alive() {
    // The kernel owns the watchdog task's join handle. If the task held a strong
    // reference back to the kernel, dropping the last external Arc without
    // calling shutdown() would leave the kernel (and its receipt store) alive
    // forever. The task must hold only a weak reference between ticks so the
    // kernel drops when its last external owner does.
    let mut config = make_config();
    // A long poll so the task takes its first (immediate) sample and then parks,
    // holding only the weak reference while this test drops the kernel.
    config.deadlines.receipt_writer_poll_ms = 60_000;
    let kernel = Arc::new(make_kernel(config));
    let weak = Arc::downgrade(&kernel);
    kernel.spawn_receipt_writer_watchdog();

    // Let the watchdog run its immediate first tick and park on the next.
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(kernel);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(
        weak.upgrade().is_none(),
        "the watchdog task must not keep the kernel alive after its last external Arc is dropped"
    );
}
