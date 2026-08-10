use super::*;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum PostCommitBudgetFailure {
    #[default]
    Capture,
    Cancellation,
    Reverse,
}

struct CommittingCaptureErrorBudgetStore {
    inner: crate::budget_store::InMemoryBudgetStore,
    failure: PostCommitBudgetFailure,
}

impl Default for CommittingCaptureErrorBudgetStore {
    fn default() -> Self {
        Self {
            inner: crate::budget_store::InMemoryBudgetStore::new(),
            failure: PostCommitBudgetFailure::Capture,
        }
    }
}

impl CommittingCaptureErrorBudgetStore {
    fn cancellation() -> Self {
        Self {
            inner: crate::budget_store::InMemoryBudgetStore::new(),
            failure: PostCommitBudgetFailure::Cancellation,
        }
    }

    fn reverse() -> Self {
        Self {
            inner: crate::budget_store::InMemoryBudgetStore::new(),
            failure: PostCommitBudgetFailure::Reverse,
        }
    }
}

impl crate::budget_store::BudgetStore for CommittingCaptureErrorBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
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
    ) -> Result<bool, crate::budget_store::BudgetStoreError> {
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
        )
    }

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)?;
        if self.failure == PostCommitBudgetFailure::Reverse {
            return Err(crate::budget_store::BudgetStoreError::Io(
                std::io::Error::other("reverse acknowledgement lost"),
            ));
        }
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn settle_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        exposed_cost_units: u64,
        realized_cost_units: u64,
    ) -> Result<(), crate::budget_store::BudgetStoreError> {
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
        )
    }

    delegate_authority_fenced_budget_methods!(inner);

    fn list_usages(
        &self,
        limit: usize,
        capability_id: Option<&str>,
    ) -> Result<Vec<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError>
    {
        self.inner.list_usages(limit, capability_id)
    }

    fn get_usage(
        &self,
        capability_id: &str,
        grant_index: usize,
    ) -> Result<Option<crate::budget_store::BudgetUsageRecord>, crate::budget_store::BudgetStoreError>
    {
        self.inner.get_usage(capability_id, grant_index)
    }

    fn list_mutation_events(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        grant_index: Option<usize>,
    ) -> Result<Vec<crate::budget_store::BudgetMutationRecord>, crate::budget_store::BudgetStoreError>
    {
        self.inner
            .list_mutation_events(limit, capability_id, grant_index)
    }

    fn authorize_budget_hold(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<
        crate::budget_store::BudgetAuthorizeHoldDecision,
        crate::budget_store::BudgetStoreError,
    > {
        self.inner.authorize_budget_hold(request)
    }

    fn reverse_budget_hold(
        &self,
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, crate::budget_store::BudgetStoreError>
    {
        let decision = self.inner.reverse_budget_hold(request)?;
        if self.failure == PostCommitBudgetFailure::Reverse {
            return Err(crate::budget_store::BudgetStoreError::Io(
                std::io::Error::other("reverse acknowledgement lost"),
            ));
        }
        Ok(decision)
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<
        crate::budget_store::BudgetInvocationCaptureDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision = self.inner.capture_invocation_reservations(request)?;
        if self.failure == PostCommitBudgetFailure::Capture {
            Err(crate::budget_store::BudgetStoreError::Io(
                std::io::Error::other("capture acknowledgement lost"),
            ))
        } else {
            Ok(decision)
        }
    }

    fn cancel_captured_before_dispatch(
        &self,
        request: crate::budget_store::BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<
        crate::budget_store::BudgetCapturedBeforeDispatchCancellationDecision,
        crate::budget_store::BudgetStoreError,
    > {
        let decision = self.inner.cancel_captured_before_dispatch(request)?;
        if self.failure == PostCommitBudgetFailure::Cancellation {
            Err(crate::budget_store::BudgetStoreError::Io(
                std::io::Error::other("cancellation acknowledgement lost"),
            ))
        } else {
            Ok(decision)
        }
    }
}

#[derive(Clone, Copy)]
enum AuthorizationFailureCase {
    Declined,
    InsufficientFunds,
    Unavailable,
    LostAcknowledgement,
}

impl AuthorizationFailureCase {
    fn error(self) -> PaymentError {
        match self {
            Self::Declined => PaymentError::Declined("test decline".to_string()),
            Self::InsufficientFunds => PaymentError::InsufficientFunds,
            Self::Unavailable => PaymentError::Unavailable("test unavailable".to_string()),
            Self::LostAcknowledgement => {
                PaymentError::RailError("test lost acknowledgement".to_string())
            }
        }
    }

    fn is_definite_denial(self) -> bool {
        matches!(self, Self::Declined | Self::InsufficientFunds)
    }

    fn label(self) -> &'static str {
        match self {
            Self::Declined => "declined",
            Self::InsufficientFunds => "insufficient-funds",
            Self::Unavailable => "unavailable",
            Self::LostAcknowledgement => "lost-ack",
        }
    }
}

#[derive(Clone)]
struct FailingAuthorizationPaymentAdapter {
    failure: AuthorizationFailureCase,
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl PaymentAdapter for FailingAuthorizationPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(self.failure.error())
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("unexpected capture".to_string()))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("unexpected release".to_string()))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("unexpected refund".to_string()))
    }
}

struct BlockingAuthorizationState {
    attempts: std::sync::atomic::AtomicUsize,
    released: std::sync::Mutex<bool>,
    wake: std::sync::Condvar,
}

#[derive(Clone)]
struct BlockingAuthorizationPaymentAdapter {
    state: std::sync::Arc<BlockingAuthorizationState>,
}

impl BlockingAuthorizationPaymentAdapter {
    fn new() -> Self {
        Self {
            state: std::sync::Arc::new(BlockingAuthorizationState {
                attempts: std::sync::atomic::AtomicUsize::new(0),
                released: std::sync::Mutex::new(false),
                wake: std::sync::Condvar::new(),
            }),
        }
    }

    fn attempts(&self) -> usize {
        self.state
            .attempts
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn release_authorizations(&self) {
        let mut released = match self.state.released.lock() {
            Ok(released) => released,
            Err(poisoned) => poisoned.into_inner(),
        };
        *released = true;
        self.state.wake.notify_all();
    }
}

impl PaymentAdapter for BlockingAuthorizationPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.state
            .attempts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut released = match self.state.released.lock() {
            Ok(released) => released,
            Err(poisoned) => poisoned.into_inner(),
        };
        while !*released {
            released = match self.state.wake.wait(released) {
                Ok(released) => released,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        Ok(PaymentAuthorization {
            authorization_id: "auth_concurrent_same_request".to_string(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "adapter": "blocking" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "blocking" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "blocking" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "blocking" }),
        })
    }
}

#[derive(Clone, Copy)]
enum NonceCleanupReleaseCase {
    Error,
    Pending,
}

#[derive(Clone)]
struct NonceCleanupPaymentAdapter {
    release_case: NonceCleanupReleaseCase,
}

impl PaymentAdapter for NonceCleanupPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "auth_nonce_cleanup".to_string(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({ "adapter": "nonce-cleanup" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("unexpected capture".to_string()))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        match self.release_case {
            NonceCleanupReleaseCase::Error => Err(PaymentError::RailError(
                "release acknowledgement lost".to_string(),
            )),
            NonceCleanupReleaseCase::Pending => Ok(PaymentResult {
                transaction_id: "release_pending_reference".to_string(),
                settlement_status: RailSettlementStatus::Pending,
                metadata: serde_json::json!({ "adapter": "nonce-cleanup" }),
            }),
        }
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("unexpected refund".to_string()))
    }
}

fn signed_nonce_for_request(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    config: &crate::execution_nonce::ExecutionNonceConfig,
) -> Result<crate::execution_nonce::SignedExecutionNonce, Box<dyn std::error::Error>> {
    let parameter_hash =
        chio_core::receipt::decision::ToolCallAction::from_parameters(request.arguments.clone())?
            .parameter_hash;
    let binding = crate::execution_nonce::NonceBinding {
        subject_id: request.capability.subject.to_hex(),
        request_id: request.request_id.clone(),
        capability_id: request.capability.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash,
    };
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
    )?;
    Ok(crate::execution_nonce::mint_execution_nonce(
        &kernel.config.keypair,
        binding,
        config,
        now,
    )?)
}

fn consumed_nonce_for_request(
    kernel: &ChioKernel,
    request: &ToolCallRequest,
    config: &crate::execution_nonce::ExecutionNonceConfig,
) -> Result<crate::execution_nonce::SignedExecutionNonce, Box<dyn std::error::Error>> {
    let nonce = signed_nonce_for_request(kernel, request, config)?;
    kernel.verify_presented_execution_nonce(&nonce, &nonce.nonce.bound_to)?;
    Ok(nonce)
}

async fn evaluate_top_or_nested(
    kernel: &ChioKernel,
    capability: &CapabilityToken,
    request: &ToolCallRequest,
    nested: bool,
) -> Result<ToolCallResponse, Box<dyn std::error::Error>> {
    if !nested {
        return Ok(kernel.evaluate_tool_call(request).await?);
    }
    let session_id = kernel.open_session(request.agent_id.clone(), vec![capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;
    Ok(kernel
        .evaluate_tool_call_with_nested_flow_client_async(&context, request, &mut client, None)
        .await?)
}

struct ConcurrentLeaseRuntimeAdmissionHook {
    admissions: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    releases: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    admission_barrier: std::sync::Arc<std::sync::Barrier>,
}

impl RuntimeAdmissionHook for ConcurrentLeaseRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "concurrent-lease-test"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.admissions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.admission_barrier.wait();
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": context.request.request_id,
                "accepted": true,
                "reserved_destructive_lease_id": "lease-concurrent-same-request"
            }
        }))))
    }

    fn release_reserved(&self, _metadata: &serde_json::Value) -> Result<(), KernelError> {
        self.releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

fn assert_monetary_capture_receipt_metadata(
    receipt: &ChioReceipt,
    capability_id: &str,
    request_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let hold_id = format!("budget-hold:{request_id}:{capability_id}:0");
    let metadata = receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("monetary receipt metadata missing"))?;
    let budget = metadata
        .get("budget_authority")
        .ok_or_else(|| std::io::Error::other("budget authority metadata missing"))?;
    assert_eq!(budget["hold_id"].as_str(), Some(hold_id.as_str()));
    assert_eq!(
        budget["authorize"]["event_id"].as_str(),
        Some(format!("{hold_id}:authorize").as_str())
    );
    let authorize_commit_index = budget["authorize"]["budget_commit_index"]
        .as_u64()
        .ok_or_else(|| std::io::Error::other("authorize commit index missing"))?;
    assert_eq!(
        budget["invocation_capture"]["event_id"].as_str(),
        Some(format!("{hold_id}:capture-invocation:{authorize_commit_index}").as_str())
    );
    assert!(
        budget["invocation_capture"]["budget_commit_index"]
            .as_u64()
            .is_some(),
        "capture commit index missing from signed receipt: {budget:?}"
    );
    Ok(())
}

mod drop_durability {
    include!("support_monetary_drop_durability.rs");
}

fn assert_payment_authorization_retained(
    receipt: &ChioReceipt,
) -> Result<(), Box<dyn std::error::Error>> {
    let financial = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .ok_or_else(|| std::io::Error::other("financial receipt metadata missing"))?;
    assert!(financial["payment_reference"]
        .as_str()
        .is_some_and(|reference| !reference.is_empty()));
    assert_eq!(
        financial["payment_authorization_retained"].as_bool(),
        Some(true)
    );
    Ok(())
}

#[test]
fn payment_authorization_errors_cancel_capture_only_for_definite_denials(
) -> Result<(), Box<dyn std::error::Error>> {
    for failure in [
        AuthorizationFailureCase::Declined,
        AuthorizationFailureCase::InsufficientFunds,
        AuthorizationFailureCase::Unavailable,
        AuthorizationFailureCase::LostAcknowledgement,
    ] {
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = make_kernel(make_monetary_config());
        kernel.set_payment_adapter(Box::new(FailingAuthorizationPaymentAdapter {
            failure,
            attempts: std::sync::Arc::clone(&attempts),
        }));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }));
        let agent_kp = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )?;
        let request = make_request_with_arguments(
            &format!("req-payment-{}", failure.label()),
            &capability,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        );

        let response = kernel.evaluate_tool_call_blocking(&request)?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert_monetary_capture_receipt_metadata(
            &response.receipt,
            &capability.id,
            &request.request_id,
        )?;
        let usage = kernel
            .budget_store
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("payment failure usage missing"))?;
        if failure.is_definite_denial() {
            assert_eq!(usage.invocation_count, 0);
            assert_eq!(usage.committed_cost_units()?, 0);
            assert!(kernel
                .budget_store
                .list_mutation_events(10, Some(&capability.id), Some(0))?
                .iter()
                .any(|event| event.kind.as_str() == "cancel_captured_before_dispatch"));
        } else {
            assert_eq!(usage.invocation_count, 1);
            assert_eq!(usage.committed_cost_units()?, 100);
            assert_eq!(
                response
                    .receipt
                    .metadata
                    .as_ref()
                    .and_then(
                        |metadata| metadata["financial"]["payment_authorization_ambiguous"]
                            .as_bool()
                    ),
                Some(true)
            );
        }
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum MonetaryFailureCase {
    Cancellation,
    Deadline,
    Incomplete,
    Generic,
    ToolNotRegistered,
}

const MONETARY_FAILURE_CASES: [MonetaryFailureCase; 5] = [
    MonetaryFailureCase::Cancellation,
    MonetaryFailureCase::Deadline,
    MonetaryFailureCase::Incomplete,
    MonetaryFailureCase::Generic,
    MonetaryFailureCase::ToolNotRegistered,
];

impl MonetaryFailureCase {
    fn label(self) -> &'static str {
        match self {
            Self::Cancellation => "cancellation",
            Self::Deadline => "deadline",
            Self::Incomplete => "incomplete",
            Self::Generic => "generic",
            Self::ToolNotRegistered => "tool-not-registered",
        }
    }

    fn server(
        self,
        executions: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Box<dyn ToolServerConnection> {
        match self {
            Self::Cancellation => Box::new(CancellationAfterSideEffectServer::new(
                "cost-srv",
                vec!["compute"],
                executions,
            )),
            Self::Deadline => Box::new(HangingToolServer {
                id: "cost-srv".to_string(),
                tools: vec!["compute".to_string()],
                invocations: executions,
            }),
            Self::Incomplete => Box::new(IncompleteAfterSideEffectServer::new(
                "cost-srv",
                vec!["compute"],
                executions,
            )),
            Self::Generic => Box::new(FailingAfterSideEffectServer::new(
                "cost-srv",
                vec!["compute"],
                executions,
            )),
            Self::ToolNotRegistered => Box::new(ToolNotRegisteredDispatchServer::new(
                "cost-srv",
                vec!["compute"],
                executions,
            )),
        }
    }
}

struct MonetaryFailureFixture {
    kernel: ChioKernel,
    payment: TrackingPaymentAdapter,
    capability: CapabilityToken,
    request: ToolCallRequest,
    executions: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl MonetaryFailureFixture {
    fn new(case: MonetaryFailureCase, path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let executions = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let payment = TrackingPaymentAdapter::new();
        let mut config = make_monetary_config();
        if matches!(case, MonetaryFailureCase::Deadline) {
            config.deadlines.dispatch_budget_ms = 20;
        }
        let mut kernel = make_kernel(config);
        kernel.set_payment_adapter(Box::new(payment.clone()));
        kernel.register_tool_server(case.server(std::sync::Arc::clone(&executions)));

        let agent_kp = Keypair::generate();
        let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
        grant.max_invocations = Some(1);
        let capability =
            kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
        let request = make_request_with_arguments(
            &format!("req-monetary-{path}-{}", case.label()),
            &capability,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        );

        Ok(Self {
            kernel,
            payment,
            capability,
            request,
            executions,
        })
    }

    fn assert_retained(&self) -> Result<(), Box<dyn std::error::Error>> {
        let usage = self
            .kernel
            .budget_store
            .get_usage(&self.capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("monetary usage missing after dispatch"))?;
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.committed_cost_units()?, 100);
        assert_eq!(
            self.payment
                .authorized
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            self.payment
                .released
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            self.payment
                .refunded
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            self.executions.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_durable_monetary_terminal_failures_retain_top_level_funds(
) -> Result<(), Box<dyn std::error::Error>> {
    for case in MONETARY_FAILURE_CASES {
        let fixture = MonetaryFailureFixture::new(case, "top-level")?;
        let first = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
        assert_eq!(first.verdict, Verdict::Deny);
        assert_monetary_capture_receipt_metadata(
            &first.receipt,
            &fixture.capability.id,
            &fixture.request.request_id,
        )?;
        fixture.assert_retained()?;

        let mut fresh = fixture.request.clone();
        fresh.request_id = format!("{}-fresh", fresh.request_id);
        let retry = fixture.kernel.evaluate_tool_call(&fresh).await?;
        assert_eq!(retry.verdict, Verdict::Deny);
        fixture.assert_retained()?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_durable_monetary_terminal_failures_retain_nested_funds(
) -> Result<(), Box<dyn std::error::Error>> {
    for case in MONETARY_FAILURE_CASES {
        let fixture = MonetaryFailureFixture::new(case, "nested")?;
        let session_id = fixture.kernel.open_session(
            fixture.request.agent_id.clone(),
            vec![fixture.capability.clone()],
        )?;
        fixture.kernel.activate_session(&session_id)?;
        let context = make_operation_context(
            &session_id,
            &fixture.request.request_id,
            &fixture.request.agent_id,
        );
        fixture
            .kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)?;
        let mut client = NoopNestedFlowClient;

        let first = fixture
            .kernel
            .evaluate_tool_call_with_nested_flow_client_async(
                &context,
                &fixture.request,
                &mut client,
                None,
            )
            .await?;
        assert_eq!(first.verdict, Verdict::Deny);
        assert_monetary_capture_receipt_metadata(
            &first.receipt,
            &fixture.capability.id,
            &fixture.request.request_id,
        )?;
        fixture.assert_retained()?;

        let mut fresh = fixture.request.clone();
        fresh.request_id = format!("{}-fresh", fresh.request_id);
        let replay_session_id = fixture
            .kernel
            .open_session(fresh.agent_id.clone(), vec![fixture.capability.clone()])?;
        fixture.kernel.activate_session(&replay_session_id)?;
        let replay_context =
            make_operation_context(&replay_session_id, &fresh.request_id, &fresh.agent_id);
        fixture
            .kernel
            .begin_session_request(&replay_context, OperationKind::ToolCall, true)?;
        let retry = fixture
            .kernel
            .evaluate_tool_call_with_nested_flow_client_async(
                &replay_context,
                &fresh,
                &mut client,
                None,
            )
            .await?;
        assert_eq!(retry.verdict, Verdict::Deny);
        fixture.assert_retained()?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_capture_acknowledgement_records_ambiguity_and_blocks_replay(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let store = std::sync::Arc::new(CommittingCaptureErrorBudgetStore::default());
        let payment = TrackingPaymentAdapter::new();
        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = make_kernel(make_monetary_config());
        kernel.set_budget_store_handle(store.clone());
        kernel.set_payment_adapter(Box::new(payment.clone()));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: std::sync::Arc::clone(&invocations),
        }));
        let agent_kp = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )?;
        let request = make_request_with_arguments(
            if nested {
                "req-capture-lost-ack-nested"
            } else {
                "req-capture-lost-ack-top"
            },
            &capability,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        );

        let first = if nested {
            let session_id =
                kernel.open_session(request.agent_id.clone(), vec![capability.clone()])?;
            kernel.activate_session(&session_id)?;
            let context =
                make_operation_context(&session_id, &request.request_id, &request.agent_id);
            kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    &request,
                    &mut client,
                    None,
                )
                .await?
        } else {
            kernel.evaluate_tool_call(&request).await?
        };
        assert_eq!(first.verdict, Verdict::Deny);
        assert_eq!(
            first.reason.as_deref(),
            Some("budget invocation capture could not be confirmed")
        );
        assert!(!first
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capture acknowledgement lost")));
        let capture = first
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["budget_authority"]["invocation_capture"].as_object())
            .ok_or_else(|| std::io::Error::other("ambiguous capture metadata missing"))?;
        assert_eq!(
            capture
                .get("invocation_capture_ambiguous")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            capture
                .get("admission_retained")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(capture.get("budget_commit_index").is_none());
        let capture_event = store
            .list_mutation_events(10, Some(&capability.id), Some(0))?
            .into_iter()
            .find(|event| event.kind == BudgetMutationKind::CaptureInvocation)
            .ok_or_else(|| std::io::Error::other("durable capture event missing"))?;
        assert_eq!(
            capture.get("event_id").and_then(serde_json::Value::as_str),
            Some(capture_event.event_id.as_str())
        );

        let replay = if nested {
            let session_id =
                kernel.open_session(request.agent_id.clone(), vec![capability.clone()])?;
            kernel.activate_session(&session_id)?;
            let context =
                make_operation_context(&session_id, &request.request_id, &request.agent_id);
            kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    &request,
                    &mut client,
                    None,
                )
                .await?
        } else {
            kernel.evaluate_tool_call(&request).await?
        };
        assert_eq!(replay.verdict, Verdict::Deny);
        let usage = store
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("retained capture usage missing"))?;
        assert_eq!(usage.invocation_count, 1);
        assert_eq!(usage.committed_cost_units()?, 100);
        assert_eq!(
            payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_preflight_cleanup_lost_ack_denies_without_minting_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let store = std::sync::Arc::new(CommittingCaptureErrorBudgetStore::reverse());
        let mut kernel = make_kernel(make_config());
        kernel.set_budget_store_handle(store.clone());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
        let config = crate::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 1024,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
        );
        let agent_kp = Keypair::generate();
        let mut grant = make_grant("srv-a", "read_file");
        grant.max_invocations = Some(1);
        let capability =
            kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
        let request = make_request_with_arguments(
            if nested {
                "req-preflight-cleanup-nested"
            } else {
                "req-preflight-cleanup-top"
            },
            &capability,
            "read_file",
            "srv-a",
            serde_json::json!({}),
        );

        let response = evaluate_top_or_nested(&kernel, &capability, &request, nested).await?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response.execution_nonce.is_none());
        assert_eq!(
            response.reason.as_deref(),
            Some("execution nonce preflight cleanup could not be confirmed")
        );
        assert_eq!(
            response
                .receipt
                .metadata
                .as_ref()
                .and_then(|metadata| metadata["execution_nonce"]["cleanup_unconfirmed"].as_bool()),
            Some(true)
        );
        let budget_metadata = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["budget_authority"].as_object())
            .ok_or_else(|| std::io::Error::other("preflight budget metadata missing"))?;
        let hold_id = format!(
            "nonce-preflight-budget-hold:{}:{}:0",
            request.request_id, capability.id
        );
        assert_eq!(
            budget_metadata
                .get("cleanup_mutation_kind")
                .and_then(serde_json::Value::as_str),
            Some("invocation")
        );
        assert_eq!(
            budget_metadata
                .get("cleanup_hold_id")
                .and_then(serde_json::Value::as_str),
            Some(hold_id.as_str())
        );
        assert!(budget_metadata
            .get("cleanup_attempt_event_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|event_id| {
                event_id.starts_with(&format!("{hold_id}:authorize:"))
                    && event_id.contains(":rollback:")
            }));
        assert_eq!(
            budget_metadata
                .get("cleanup_attempt_event_id_available")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        let events = store.list_mutation_events(10, Some(&capability.id), Some(0))?;
        assert!(events.iter().any(|event| {
            event.kind == BudgetMutationKind::ReserveInvocation
                && event.hold_id.as_deref() == Some(hold_id.as_str())
        }));
        assert!(events.iter().any(|event| {
            event.kind == BudgetMutationKind::ReverseInvocation
                && event.hold_id.as_deref() == Some(hold_id.as_str())
        }));
        assert!(!events
            .iter()
            .any(|event| event.kind == BudgetMutationKind::IncrementInvocation));
        let replay = evaluate_top_or_nested(&kernel, &capability, &request, nested).await?;
        assert_eq!(replay.verdict, Verdict::Deny);
        assert!(replay.execution_nonce.is_none());
        assert_eq!(
            store
                .list_mutation_events(10, Some(&capability.id), Some(0))?
                .len(),
            events.len()
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_preflight_runtime_release_failure_denies_without_minting_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let request_id = if nested {
            "req-preflight-runtime-release-nested"
        } else {
            "req-preflight-runtime-release-top"
        };
        let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
        let releases = std::sync::Arc::new(AtomicU64::new(0));
        let mut kernel = make_kernel(make_config());
        kernel.set_runtime_admission_hook(std::sync::Arc::new(
            FailingReleaseRuntimeAdmissionHook {
                calls: std::sync::Arc::clone(&admission_calls),
                releases: std::sync::Arc::clone(&releases),
                expected_request_id: request_id,
                admission_id: "adm-preflight-runtime-release",
                lease_id: "lease-preflight-runtime-release",
            },
        ));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
        let config = crate::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 1024,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
        );
        let agent_kp = Keypair::generate();
        let mut grant = make_grant("srv-a", "read_file");
        grant.max_invocations = Some(1);
        let capability =
            kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
        let request = make_request_with_arguments(
            request_id,
            &capability,
            "read_file",
            "srv-a",
            serde_json::json!({}),
        );

        let response = evaluate_top_or_nested(&kernel, &capability, &request, nested).await?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(
            response.reason.as_deref(),
            Some("execution nonce preflight cleanup could not be confirmed")
        );
        assert!(response.execution_nonce.is_none());
        assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
        assert_eq!(releases.load(Ordering::SeqCst), 1);
        let metadata = response
            .receipt
            .metadata
            .as_ref()
            .ok_or_else(|| std::io::Error::other("preflight release metadata missing"))?;
        assert_eq!(metadata["chio_runtime"]["reservation_release_failed"], true);
        assert_eq!(metadata["chio_runtime"]["reservation_retained"], true);
        assert!(metadata["chio_runtime"]
            .get("reservation_release_failure_reason")
            .is_none());
    }
    Ok(())
}

#[test]
fn predispatch_unwind_requires_confirmed_payment_release_status(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = std::sync::Arc::new(InMemoryBudgetStore::new());
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_budget_store_handle(store.clone());
    kernel.set_payment_adapter(Box::new(NonceCleanupPaymentAdapter {
        release_case: NonceCleanupReleaseCase::Pending,
    }));
    let agent_kp = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent_kp.public_key(),
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1000, "USD",
        )]),
        3600,
    )?;
    let request = make_request_with_arguments(
        "req-predispatch-unwind-pending",
        &capability,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );
    let matching = resolve_required_matching_grants(
        &capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )?;
    let (_, mutation) = kernel
        .check_and_increment_budget(
            &request,
            &capability,
            &matching,
            false,
            None,
            current_unix_timestamp_ms(),
        )?
        .into_authorized()?;
    let authorization = PaymentAuthorization {
        authorization_id: "auth-predispatch-unwind-pending".to_string(),
        state: PaymentAuthorizationState::Held,
        metadata: serde_json::json!({}),
    };

    assert!(kernel
        .unwind_pre_dispatch_monetary_invocation(
            &request,
            &capability,
            mutation.charge_result(),
            Some(&authorization),
        )
        .is_err());
    let usage = store
        .get_usage(&capability.id, 0)?
        .ok_or_else(|| std::io::Error::other("retained unwind usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.committed_cost_units()?, 100);
    assert!(!store
        .list_mutation_events(20, Some(&capability.id), Some(0))?
        .into_iter()
        .any(|event| event.kind == BudgetMutationKind::ReverseExposure));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonmonetary_nonce_cleanup_signs_post_commit_reverse_ambiguity(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let store = std::sync::Arc::new(CommittingCaptureErrorBudgetStore::reverse());
        let mut kernel = make_kernel(make_config());
        kernel.set_budget_store_handle(store.clone());
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
        let config = crate::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 1024,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
        );
        let agent_kp = Keypair::generate();
        let mut grant = make_grant("srv-a", "read_file");
        grant.max_invocations = Some(1);
        let capability =
            kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
        let original = make_request_with_arguments(
            "req-nonmonetary-cleanup-original",
            &capability,
            "read_file",
            "srv-a",
            serde_json::json!({}),
        );
        let mut changed = original.clone();
        changed.request_id = if nested {
            "req-nonmonetary-cleanup-nested"
        } else {
            "req-nonmonetary-cleanup-top"
        }
        .to_string();
        changed.execution_nonce = Some(signed_nonce_for_request(&kernel, &original, &config)?);

        let response = evaluate_top_or_nested(&kernel, &capability, &changed, nested).await?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("pre-dispatch cleanup could not be confirmed")));
        let cleanup = response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata["budget_authority"].as_object())
            .ok_or_else(|| std::io::Error::other("nonmonetary cleanup metadata missing"))?;
        assert_eq!(
            cleanup
                .get("cleanup_mutation_kind")
                .and_then(serde_json::Value::as_str),
            Some("invocation")
        );
        assert_eq!(
            cleanup
                .get("cleanup_capability_id")
                .and_then(serde_json::Value::as_str),
            Some(capability.id.as_str())
        );
        assert_eq!(
            cleanup
                .get("cleanup_grant_index")
                .and_then(serde_json::Value::as_u64),
            Some(0)
        );
        assert_eq!(
            cleanup
                .get("cleanup_attempt_event_id_available")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        let usage = store
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("nonmonetary cleanup usage missing"))?;
        assert_eq!(usage.invocation_count, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_request_id_mismatch_precedes_payment_and_capture_top_and_nested(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let store = std::sync::Arc::new(CommittingCaptureErrorBudgetStore::reverse());
        let payment = TrackingPaymentAdapter::new();
        let mut kernel = make_kernel(make_monetary_config());
        kernel.set_budget_store_handle(store.clone());
        kernel.set_payment_adapter(Box::new(payment.clone()));
        kernel.register_tool_server(Box::new(MonetaryCostServer {
            id: "cost-srv".to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: 50,
                currency: "USD".to_string(),
                breakdown: None,
            }),
        }));
        let config = crate::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 1024,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
        );
        let agent_kp = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )?;
        let original = make_request_with_arguments(
            "req-nonce-id-bound-original",
            &capability,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        );
        let mut changed = original.clone();
        changed.request_id = if nested {
            "req-nonce-id-bound-nested"
        } else {
            "req-nonce-id-bound-top"
        }
        .to_string();
        changed.execution_nonce = Some(signed_nonce_for_request(&kernel, &original, &config)?);

        let response = evaluate_top_or_nested(&kernel, &capability, &changed, nested).await?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("pre-dispatch cleanup could not be confirmed")));
        assert_eq!(
            response.receipt.metadata.as_ref().and_then(|metadata| {
                metadata["budget_authority"]["pre_dispatch_cleanup_unconfirmed"].as_bool()
            }),
            Some(true)
        );
        assert_eq!(
            payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            store
                .list_mutation_events(100, Some(&capability.id), Some(0))?
                .into_iter()
                .filter(|event| event.kind == BudgetMutationKind::CaptureInvocation)
                .count(),
            0
        );
        let usage = store
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("post-commit reverse usage missing"))?;
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.committed_cost_units()?, 0);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_replay_precedes_payment_and_capture_when_release_would_be_unconfirmed(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        for release_case in [
            NonceCleanupReleaseCase::Error,
            NonceCleanupReleaseCase::Pending,
        ] {
            let mut kernel = make_kernel(make_monetary_config());
            kernel.set_payment_adapter(Box::new(NonceCleanupPaymentAdapter { release_case }));
            kernel.register_tool_server(Box::new(MonetaryCostServer {
                id: "cost-srv".to_string(),
                reported_cost: Some(ToolInvocationCost {
                    units: 50,
                    currency: "USD".to_string(),
                    breakdown: None,
                }),
            }));
            let config = crate::execution_nonce::ExecutionNonceConfig {
                nonce_ttl_secs: 30,
                nonce_store_capacity: 1024,
                require_nonce: true,
            };
            kernel.set_execution_nonce_store(
                config.clone(),
                Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
            );
            let agent_kp = Keypair::generate();
            let capability = kernel.issue_capability(
                &agent_kp.public_key(),
                make_scope(vec![make_monetary_grant(
                    "cost-srv", "compute", 100, 1000, "USD",
                )]),
                3600,
            )?;
            let mut request = make_request_with_arguments(
                if nested {
                    "req-nonce-release-unconfirmed-nested"
                } else {
                    "req-nonce-release-unconfirmed-top"
                },
                &capability,
                "compute",
                "cost-srv",
                serde_json::json!({}),
            );
            request.execution_nonce = Some(consumed_nonce_for_request(&kernel, &request, &config)?);

            let response = evaluate_top_or_nested(&kernel, &capability, &request, nested).await?;
            assert_eq!(response.verdict, Verdict::Deny);
            let metadata = response
                .receipt
                .metadata
                .as_ref()
                .ok_or_else(|| std::io::Error::other("nonce cleanup metadata missing"))?;
            let financial = &metadata["financial"];
            assert!(financial
                .get("payment_reference")
                .is_none_or(serde_json::Value::is_null));
            assert!(financial["cost_breakdown"]
                .get("payment")
                .is_none());
            assert!(metadata["budget_authority"]
                .get("invocation_capture")
                .is_none());
            let usage = kernel
                .budget_store
                .get_usage(&capability.id, 0)?
                .ok_or_else(|| std::io::Error::other("retained nonce cleanup usage missing"))?;
            assert_eq!(usage.invocation_count, 0);
            assert_eq!(usage.committed_cost_units()?, 0);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonce_replay_precedes_payment_and_captured_cancellation(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let store = std::sync::Arc::new(CommittingCaptureErrorBudgetStore::cancellation());
        let payment = TrackingPaymentAdapter::new();
        let mut kernel = make_kernel(make_monetary_config());
        kernel.set_budget_store_handle(store.clone());
        kernel.set_payment_adapter(Box::new(payment.clone()));
        kernel.register_tool_server(Box::new(MonetaryCostServer {
            id: "cost-srv".to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: 50,
                currency: "USD".to_string(),
                breakdown: None,
            }),
        }));
        let config = crate::execution_nonce::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 1024,
            require_nonce: true,
        };
        kernel.set_execution_nonce_store(
            config.clone(),
            Box::new(crate::execution_nonce::InMemoryExecutionNonceStore::from_config(&config)),
        );
        let agent_kp = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )?;
        let mut request = make_request_with_arguments(
            if nested {
                "req-nonce-cancel-unconfirmed-nested"
            } else {
                "req-nonce-cancel-unconfirmed-top"
            },
            &capability,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        );
        request.execution_nonce = Some(consumed_nonce_for_request(&kernel, &request, &config)?);

        let response = evaluate_top_or_nested(&kernel, &capability, &request, nested).await?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert_eq!(
            payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            payment.released.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        let cancellation = store
            .list_mutation_events(20, Some(&capability.id), Some(0))?
            .into_iter()
            .find(|event| event.kind == BudgetMutationKind::CancelCapturedBeforeDispatch);
        assert!(cancellation.is_none());
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_cancellation_acknowledgement_records_ambiguity_and_blocks_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    for nested in [false, true] {
        let store = std::sync::Arc::new(CommittingCaptureErrorBudgetStore::cancellation());
        let payment_attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut kernel = make_kernel(make_monetary_config());
        kernel.set_budget_store_handle(store.clone());
        kernel.set_payment_adapter(Box::new(FailingAuthorizationPaymentAdapter {
            failure: AuthorizationFailureCase::Declined,
            attempts: std::sync::Arc::clone(&payment_attempts),
        }));
        kernel.register_tool_server(Box::new(CountingMonetaryServer {
            id: "cost-srv".to_string(),
            invocations: std::sync::Arc::clone(&invocations),
        }));
        let agent_kp = Keypair::generate();
        let capability = kernel.issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![make_monetary_grant(
                "cost-srv", "compute", 100, 1000, "USD",
            )]),
            3600,
        )?;
        let request = make_request_with_arguments(
            if nested {
                "req-cancellation-lost-ack-nested"
            } else {
                "req-cancellation-lost-ack-top"
            },
            &capability,
            "compute",
            "cost-srv",
            serde_json::json!({}),
        );

        let first = if nested {
            let session_id =
                kernel.open_session(request.agent_id.clone(), vec![capability.clone()])?;
            kernel.activate_session(&session_id)?;
            let context =
                make_operation_context(&session_id, &request.request_id, &request.agent_id);
            kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    &request,
                    &mut client,
                    None,
                )
                .await?
        } else {
            kernel.evaluate_tool_call(&request).await?
        };
        assert_eq!(first.verdict, Verdict::Deny);
        assert_eq!(
            first.reason.as_deref(),
            Some("captured budget cancellation could not be confirmed")
        );
        let cancellation = first
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| {
                metadata["budget_authority"]["cancel_captured_before_dispatch"].as_object()
            })
            .ok_or_else(|| std::io::Error::other("ambiguous cancellation metadata missing"))?;
        assert_eq!(
            cancellation
                .get("cancellation_ambiguous")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert!(cancellation.get("budget_commit_index").is_none());
        let cancellation_event = store
            .list_mutation_events(10, Some(&capability.id), Some(0))?
            .into_iter()
            .find(|event| event.kind == BudgetMutationKind::CancelCapturedBeforeDispatch)
            .ok_or_else(|| std::io::Error::other("durable cancellation event missing"))?;
        assert_eq!(
            cancellation
                .get("event_id")
                .and_then(serde_json::Value::as_str),
            Some(cancellation_event.event_id.as_str())
        );
        assert_eq!(
            payment_attempts.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);

        let usage = store
            .get_usage(&capability.id, 0)?
            .ok_or_else(|| std::io::Error::other("cancelled usage missing"))?;
        assert_eq!(usage.invocation_count, 0);
        assert_eq!(usage.committed_cost_units()?, 0);
    }
    Ok(())
}

#[test]
fn non_durable_monetary_url_elicitation_retains_admission_fail_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = TrackingPaymentAdapter::new();
    let side_effects = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(UrlElicitationBeforeSideEffectServer::new(
        "cost-srv",
        vec!["compute"],
        std::sync::Arc::clone(&side_effects),
    )));

    let agent_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let capability =
        kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
    let request = make_request_with_arguments(
        "req-monetary-url-ambiguous",
        &capability,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let first = kernel.evaluate_tool_call_blocking(&request);
    let Err(KernelError::UrlElicitationsRequired { message, .. }) = first else {
        return Err(std::io::Error::other(format!(
            "URL elicitation payload was not preserved: {first:?}"
        ))
        .into());
    };
    assert_eq!(
        message,
        "URL elicitation required before dispatch side effect"
    );
    let usage = kernel
        .budget_store
        .get_usage(&capability.id, 0)?
        .ok_or_else(|| std::io::Error::other("URL ambiguity usage missing"))?;
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.committed_cost_units()?, 100);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("URL ambiguity receipt missing"))?;
    assert!(receipt.is_cancelled());
    assert_monetary_capture_receipt_metadata(receipt, &capability.id, &request.request_id)?;

    let exact_replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(exact_replay.verdict, Verdict::Deny);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 1);

    let mut fresh = request;
    fresh.request_id = "req-monetary-url-ambiguous-fresh".to_string();
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&fresh)?.verdict,
        Verdict::Deny
    );
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        payment.released.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(side_effects.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn captured_monetary_replay_cannot_fall_through_to_overlapping_unlimited_grant(
) -> Result<(), Box<dyn std::error::Error>> {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));

    let agent_kp = Keypair::generate();
    let monetary = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let unlimited = make_grant("cost-srv", "compute");
    let capability = kernel.issue_capability(
        &agent_kp.public_key(),
        make_scope(vec![monetary, unlimited]),
        3600,
    )?;
    let request = make_request_with_arguments(
        "req-captured-overlapping-grant",
        &capability,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    assert_eq!(
        kernel.evaluate_tool_call_blocking(&request)?.verdict,
        Verdict::Allow
    );
    let replay = kernel.evaluate_tool_call_blocking(&request)?;
    assert_eq!(replay.verdict, Verdict::Deny, "{:?}", replay.reason);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn direct_monetary_dispatch_without_capture_proof_fails_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    let agent_kp = Keypair::generate();
    let capability = kernel.issue_capability(
        &agent_kp.public_key(),
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1000, "USD",
        )]),
        3600,
    )?;
    let request = make_request_with_arguments(
        "req-direct-monetary-dispatch",
        &capability,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    for caller_claim in [true, false] {
        let result = kernel
            .dispatch_tool_call_with_cost(&request, caller_claim)
            .await;
        assert!(matches!(
            result,
            Err(KernelError::DirectDispatchUnavailable)
        ));
    }
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_identical_monetary_requests_capture_before_payment_and_release_loser_leases(
) -> Result<(), Box<dyn std::error::Error>> {
    let SiblingSumMonetaryFixture {
        mut kernel,
        child_a,
        child_b,
        child_a_kp: _,
        path: _path,
        ..
    } = make_sibling_sum_monetary_fixture("concurrent-identical-capture");
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    let payment = BlockingAuthorizationPaymentAdapter::new();
    kernel.set_payment_adapter(Box::new(payment.clone()));
    let admissions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let releases = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(ConcurrentLeaseRuntimeAdmissionHook {
        admissions: std::sync::Arc::clone(&admissions),
        releases: std::sync::Arc::clone(&releases),
        admission_barrier: std::sync::Arc::new(std::sync::Barrier::new(2)),
    }));
    let request = make_request_with_arguments(
        "req-concurrent-identical-capture",
        &child_a,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );
    let kernel = std::sync::Arc::new(kernel);

    let first = {
        let kernel = std::sync::Arc::clone(&kernel);
        let request = request.clone();
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };
    let second = {
        let kernel = std::sync::Arc::clone(&kernel);
        let request = request.clone();
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
        while payment.attempts() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| std::io::Error::other("first payment authorization did not start"))?;
    tokio::time::timeout(Duration::from_secs(1), async {
        while releases.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| std::io::Error::other("capture loser did not release its runtime lease"))?;
    payment.release_authorizations();

    let first_response = first.await??;
    let second_response = second.await??;
    let verdicts = [first_response.verdict, second_response.verdict];
    assert_eq!(
        verdicts
            .iter()
            .filter(|verdict| **verdict == Verdict::Allow)
            .count(),
        1
    );
    assert_eq!(
        verdicts
            .iter()
            .filter(|verdict| **verdict == Verdict::Deny)
            .count(),
        1
    );
    assert_eq!(payment.attempts(), 1);
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(admissions.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(releases.load(std::sync::atomic::Ordering::SeqCst), 1);

    kernel
        .release_admitted_capability_budget(&child_a)
        .map_err(std::io::Error::other)?;
    assert!(
        kernel.admit_capability_budget(&child_b).is_ok(),
        "the losing evaluation leaked its delegated-budget holder lease"
    );
    Ok(())
}
