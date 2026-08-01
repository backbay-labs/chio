use super::*;

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
    configure_ephemeral_dst_kernel(&mut kernel)?;
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
    configure_ephemeral_dst_kernel(&mut kernel)?;
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
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
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
