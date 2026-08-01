#[derive(Clone, Copy)]
enum PaymentAmbiguityMode {
    AuthorizeUnavailable,
    AuthorizeRailError,
    AuthorizePanic,
    AuthorizeDeclined,
    AuthorizeEmptyId,
    AuthorizePaddedId,
    SettledWithoutTransactionId,
    ReleaseError,
    ReleasePending,
    ReleaseEmptyTransactionId,
    ReleaseThenBudgetReversalError,
    RefundAcknowledged,
    RefundPanic,
    RefundFailed,
    RefundPaddedTransactionId,
}

#[derive(Clone, Default)]
struct PaymentAmbiguityCounters {
    authorizations: std::sync::Arc<std::sync::atomic::AtomicU64>,
    authorization_returned: std::sync::Arc<std::sync::atomic::AtomicBool>,
    captures: std::sync::Arc<std::sync::atomic::AtomicU64>,
    releases: std::sync::Arc<std::sync::atomic::AtomicU64>,
    refunds: std::sync::Arc<std::sync::atomic::AtomicU64>,
    refund_inputs: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

struct PaymentAmbiguityAdapter {
    mode: PaymentAmbiguityMode,
    counters: PaymentAmbiguityCounters,
}

impl PaymentAdapter for PaymentAmbiguityAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.counters
            .authorizations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match self.mode {
            PaymentAmbiguityMode::AuthorizeUnavailable => Err(PaymentError::Unavailable(
                "authorization acknowledgement missing".to_string(),
            )),
            PaymentAmbiguityMode::AuthorizeRailError => Err(PaymentError::RailError(
                "authorization commit outcome unknown".to_string(),
            )),
            PaymentAmbiguityMode::AuthorizePanic => {
                panic!("payment adapter panicked after a possible authorization commit")
            }
            PaymentAmbiguityMode::AuthorizeDeclined => Err(PaymentError::Declined(
                "authorization was cleanly declined".to_string(),
            )),
            PaymentAmbiguityMode::ReleaseError
            | PaymentAmbiguityMode::ReleasePending
            | PaymentAmbiguityMode::ReleaseEmptyTransactionId
            | PaymentAmbiguityMode::ReleaseThenBudgetReversalError
            | PaymentAmbiguityMode::RefundAcknowledged
            | PaymentAmbiguityMode::RefundPanic
            | PaymentAmbiguityMode::RefundFailed
            | PaymentAmbiguityMode::RefundPaddedTransactionId
            | PaymentAmbiguityMode::AuthorizeEmptyId
            | PaymentAmbiguityMode::AuthorizePaddedId
            | PaymentAmbiguityMode::SettledWithoutTransactionId => {
                self.counters
                    .authorization_returned
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(PaymentAuthorization {
                    authorization_id: match self.mode {
                        PaymentAmbiguityMode::AuthorizeEmptyId => String::new(),
                        PaymentAmbiguityMode::AuthorizePaddedId => {
                            " payment-ambiguity-auth ".to_string()
                        }
                        _ => "payment-ambiguity-auth".to_string(),
                    },
                    state: if matches!(
                        self.mode,
                        PaymentAmbiguityMode::RefundAcknowledged
                            | PaymentAmbiguityMode::RefundPanic
                            | PaymentAmbiguityMode::RefundFailed
                            | PaymentAmbiguityMode::RefundPaddedTransactionId
                            | PaymentAmbiguityMode::SettledWithoutTransactionId
                    ) {
                        PaymentAuthorizationState::PrepaidFinal
                    } else {
                        PaymentAuthorizationState::Held
                    },
                    metadata: serde_json::json!({"adapter": "payment-ambiguity-test"}),
                })
            }
        }
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.counters
            .captures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({"adapter": "payment-ambiguity-test"}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.counters
            .releases
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if matches!(self.mode, PaymentAmbiguityMode::ReleaseError) {
            return Err(PaymentError::RailError(
                "release acknowledgement missing".to_string(),
            ));
        }
        let settlement_status = if matches!(self.mode, PaymentAmbiguityMode::ReleasePending) {
            RailSettlementStatus::Pending
        } else {
            RailSettlementStatus::Released
        };
        Ok(PaymentResult {
            transaction_id: if matches!(self.mode, PaymentAmbiguityMode::ReleaseEmptyTransactionId)
            {
                String::new()
            } else {
                authorization_id.to_string()
            },
            settlement_status,
            metadata: serde_json::json!({"adapter": "payment-ambiguity-test"}),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.counters
            .refunds
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.counters
            .refund_inputs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(transaction_id.to_string());
        if matches!(self.mode, PaymentAmbiguityMode::RefundPanic) {
            panic!("payment adapter panicked after a possible refund commit");
        }
        let settlement_status = if matches!(self.mode, PaymentAmbiguityMode::RefundFailed) {
            RailSettlementStatus::Failed
        } else {
            RailSettlementStatus::Refunded
        };
        Ok(PaymentResult {
            transaction_id: if matches!(self.mode, PaymentAmbiguityMode::RefundPaddedTransactionId)
            {
                format!(" {transaction_id} ")
            } else {
                transaction_id.to_string()
            },
            settlement_status,
            metadata: serde_json::json!({"adapter": "payment-ambiguity-test"}),
        })
    }
}

struct PaymentAmbiguityFailingReverseBudgetStore {
    inner: InMemoryBudgetStore,
}

impl PaymentAmbiguityFailingReverseBudgetStore {
    fn new() -> Self {
        Self {
            inner: InMemoryBudgetStore::new(),
        }
    }
}

impl BudgetStore for PaymentAmbiguityFailingReverseBudgetStore {
    fn try_increment(
        &self,
        capability_id: &str,
        grant_index: usize,
        max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
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
        self.inner.try_charge_cost(
            capability_id,
            grant_index,
            max_invocations,
            cost_units,
            max_cost_per_invocation,
            max_total_cost_units,
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
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<bool, BudgetStoreError> {
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

    fn reverse_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "injected budget reversal failure".to_string(),
        ))
    }

    fn reverse_charge_cost_with_ids_and_authority(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
        _hold_id: Option<&str>,
        _event_id: Option<&str>,
        _authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "injected budget reversal failure".to_string(),
        ))
    }

    fn reduce_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reduce_charge_cost(capability_id, grant_index, cost_units)
    }

    fn reduce_charge_cost_with_ids_and_authority(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
        hold_id: Option<&str>,
        event_id: Option<&str>,
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
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
        self.inner.settle_charge_cost(
            capability_id,
            grant_index,
            exposed_cost_units,
            realized_cost_units,
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
        authority: Option<&crate::budget_store::BudgetEventAuthority>,
    ) -> Result<(), BudgetStoreError> {
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

    fn authorize_budget_hold(
        &self,
        request: crate::budget_store::BudgetAuthorizeHoldRequest,
    ) -> Result<crate::budget_store::BudgetAuthorizeHoldDecision, BudgetStoreError> {
        self.inner.authorize_budget_hold(request)
    }

    fn reverse_budget_hold(
        &self,
        _request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "injected budget reversal failure".to_string(),
        ))
    }

    fn capture_invocation_reservations(
        &self,
        request: BudgetCaptureInvocationRequest,
    ) -> Result<BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.inner.capture_invocation_reservations(request)
    }

    fn cancel_captured_before_dispatch(
        &self,
        _request: BudgetCancelCapturedBeforeDispatchRequest,
    ) -> Result<BudgetCapturedBeforeDispatchCancellationDecision, BudgetStoreError> {
        Err(BudgetStoreError::Invariant(
            "injected budget reversal failure".to_string(),
        ))
    }
}

struct PaymentUnwindDenialGuard {
    authorization_returned: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, Copy)]
enum ApprovalReplayFailureMode {
    CommitFalse,
    CommitError,
    RollbackError,
}

struct FailingApprovalReplayStore {
    mode: ApprovalReplayFailureMode,
}

impl GovernedApprovalReplayStore for FailingApprovalReplayStore {
    fn reserve_for_dispatch(
        &self,
        _subject_id: &str,
        _request_id: &str,
        _intent_hash: &str,
        _expires_at: u64,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        Ok(true)
    }

    fn commit_dispatch_reservation(
        &self,
        _subject_id: &str,
        _request_id: &str,
        _intent_hash: &str,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        match self.mode {
            ApprovalReplayFailureMode::CommitFalse => Ok(false),
            ApprovalReplayFailureMode::CommitError => Err(KernelError::GovernedTransactionDenied(
                "injected governed approval commit failure".to_string(),
            )),
            ApprovalReplayFailureMode::RollbackError => Ok(true),
        }
    }

    fn rollback_dispatch_reservation(
        &self,
        _subject_id: &str,
        _request_id: &str,
        _intent_hash: &str,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        if matches!(self.mode, ApprovalReplayFailureMode::RollbackError) {
            Err(KernelError::GovernedTransactionDenied(
                "injected governed approval rollback failure".to_string(),
            ))
        } else {
            Ok(true)
        }
    }
}

impl Guard for PaymentUnwindDenialGuard {
    fn name(&self) -> &str {
        "payment-unwind-denial"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn requires_dispatch_revalidation(&self) -> bool {
        true
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        if self
            .authorization_returned
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(KernelError::GuardDenied(
                "payment unwind test denied before dispatch".to_string(),
            ));
        }
        Ok(())
    }
}

struct PaymentAmbiguityFixture {
    kernel: ChioKernel,
    capability: CapabilityToken,
    request: ToolCallRequest,
    counters: PaymentAmbiguityCounters,
    invocations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

fn make_payment_ambiguity_fixture(
    request_id: &str,
    mode: PaymentAmbiguityMode,
) -> PaymentAmbiguityFixture {
    let counters = PaymentAmbiguityCounters::default();
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );
    if matches!(mode, PaymentAmbiguityMode::ReleaseThenBudgetReversalError) {
        kernel.set_budget_store(Box::new(PaymentAmbiguityFailingReverseBudgetStore::new()));
    }
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "payment-ambiguity-server".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    kernel.set_payment_adapter(Box::new(PaymentAmbiguityAdapter {
        mode,
        counters: counters.clone(),
    }));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_monetary_grant(
            "payment-ambiguity-server",
            "compute",
            100,
            200,
            "USD",
        )]),
        300,
    );
    let mut request = make_request(
        request_id,
        &capability,
        "compute",
        "payment-ambiguity-server",
    );
    request.execution_nonce = Some(mint_nonce_for_request(
        &kernel,
        &capability,
        &request,
        &nonce_config,
    ));
    PaymentAmbiguityFixture {
        kernel,
        capability,
        request,
        counters,
        invocations,
    }
}

fn make_governed_payment_failure_fixture(
    request_id: &str,
    payment_mode: PaymentAmbiguityMode,
    replay_mode: ApprovalReplayFailureMode,
) -> PaymentAmbiguityFixture {
    let counters = PaymentAmbiguityCounters::default();
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_governed_approval_replay_store(Box::new(FailingApprovalReplayStore {
        mode: replay_mode,
    }));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "governed-payment-failure-server".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    kernel.set_payment_adapter(Box::new(PaymentAmbiguityAdapter {
        mode: payment_mode,
        counters: counters.clone(),
    }));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_governed_monetary_grant(
            "governed-payment-failure-server",
            "compute",
            100,
            500,
            "USD",
            50,
        )]),
        300,
    );
    let intent = make_governed_intent(
        &format!("intent-{request_id}"),
        "governed-payment-failure-server",
        "compute",
        "exercise governed payment replay-store failure handling",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent.public_key(),
        &intent,
        request_id,
    );
    let mut request = make_request(
        request_id,
        &capability,
        "compute",
        "governed-payment-failure-server",
    );
    request.governed_intent = Some(intent);
    request.approval_token = Some(approval_token);
    PaymentAmbiguityFixture {
        kernel,
        capability,
        request,
        counters,
        invocations,
    }
}

fn make_governed_dispatch_commit_failure_fixture(
    request_id: &str,
    replay_mode: ApprovalReplayFailureMode,
) -> PaymentAmbiguityFixture {
    let counters = PaymentAmbiguityCounters::default();
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_governed_approval_replay_store(Box::new(FailingApprovalReplayStore {
        mode: replay_mode,
    }));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "governed-dispatch-failure-server".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant(
            "governed-dispatch-failure-server",
            "compute",
        )]),
        300,
    );
    let mut intent = make_governed_intent(
        &format!("intent-{request_id}"),
        "governed-dispatch-failure-server",
        "compute",
        "exercise governed replay-store failure after dispatch",
        1,
        "USD",
    );
    intent.max_amount = None;
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent.public_key(),
        &intent,
        request_id,
    );
    let mut request = make_request(
        request_id,
        &capability,
        "compute",
        "governed-dispatch-failure-server",
    );
    request.governed_intent = Some(intent);
    request.approval_token = Some(approval_token);
    PaymentAmbiguityFixture {
        kernel,
        capability,
        request,
        counters,
        invocations,
    }
}

async fn evaluate_nested_payment_ambiguity_request(
    kernel: &ChioKernel,
    session_id: &SessionId,
    request: &ToolCallRequest,
    parent_request_id: &str,
) -> Result<ToolCallResponse, KernelError> {
    let context = make_operation_context(session_id, parent_request_id, &request.agent_id);
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;
    kernel
        .evaluate_tool_call_with_nested_flow_client_async(&context, request, &mut client, None)
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_strict_dpop_only_payment_requests_reach_the_external_rail(
) -> Result<(), Box<dyn std::error::Error>> {
    let counters = PaymentAmbiguityCounters::default();
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "dpop-only-payment-server".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    kernel.set_payment_adapter(Box::new(PaymentAmbiguityAdapter {
        mode: PaymentAmbiguityMode::AuthorizeDeclined,
        counters: counters.clone(),
    }));
    kernel.set_dpop_store(
        dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300)),
        dpop::DpopConfig::default(),
    );

    let agent = make_keypair();
    let mut grant = make_monetary_grant("dpop-only-payment-server", "compute", 100, 500, "USD");
    grant.dpop_required = Some(true);
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);

    for (request_id, proof_nonce) in [
        ("dpop-only-payment-one", "dpop-only-payment-proof-one"),
        ("dpop-only-payment-two", "dpop-only-payment-proof-two"),
    ] {
        let mut request = make_request(
            request_id,
            &capability,
            "compute",
            "dpop-only-payment-server",
        );
        request.dpop_proof = Some(make_dpop_proof(
            &agent,
            &capability,
            &request.server_id,
            &request.tool_name,
            &request.arguments,
            proof_nonce,
        ));

        let response = kernel.evaluate_tool_call(&request).await?;
        assert_eq!(response.verdict, Verdict::Deny);
        assert!(response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("payment authorization failed")));
    }

    assert_eq!(
        counters
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
    let usage = kernel
        .budget_store
        .get_usage(&capability.id, 0)?
        .ok_or_else(|| std::io::Error::other("DPoP-only budget usage missing"))?;
    assert_eq!(usage.committed_cost_units()?, 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn strict_nonce_mode_still_preflights_before_the_external_rail(
) -> Result<(), Box<dyn std::error::Error>> {
    let counters = PaymentAmbiguityCounters::default();
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "strict-payment-server".to_string(),
        invocations: std::sync::Arc::clone(&invocations),
    }));
    kernel.set_payment_adapter(Box::new(PaymentAmbiguityAdapter {
        mode: PaymentAmbiguityMode::AuthorizeDeclined,
        counters: counters.clone(),
    }));

    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_monetary_grant(
            "strict-payment-server",
            "compute",
            100,
            500,
            "USD",
        )]),
        300,
    );
    let request = make_request(
        "strict-payment-missing-nonce",
        &capability,
        "compute",
        "strict-payment-server",
    );

    let response = kernel.evaluate_tool_call(&request).await?;
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.output.is_none());
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(response.execution_nonce.is_some());
    assert_eq!(
        counters
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn settled_legacy_authorization_uses_authorization_id_as_payment_reference() {
    let fixture = make_payment_ambiguity_fixture(
        "settled-legacy-authorization",
        PaymentAmbiguityMode::SettledWithoutTransactionId,
    );

    let response = fixture
        .kernel
        .evaluate_tool_call_blocking(&fixture.request)
        .expect("legacy settled authorization must remain usable");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let financial = &response
        .receipt
        .metadata
        .as_ref()
        .expect("financial metadata must be present")["financial"];
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["payment_reference"], "payment-ambiguity-auth");
    assert!(financial["cost_breakdown"]["payment"]
        .get("settlement_transaction_id")
        .is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_governed_commit_false_after_authorization_is_signed_as_retention_unknown(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_governed_payment_failure_fixture(
        "hosted-governed-commit-false",
        PaymentAmbiguityMode::ReleaseThenBudgetReversalError,
        ApprovalReplayFailureMode::CommitFalse,
    );
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture
            .counters
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture
            .counters
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(response.receipt.verify_signature()?);
    let runtime = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("commit-false receipt metadata missing"))?
        ["chio_runtime"];
    assert_eq!(
        runtime["dispatch_credential_retention_outcome_unknown"],
        true
    );
    assert_eq!(
        runtime["dispatch_credential_disposition"],
        "retention_outcome_unknown"
    );
    assert_eq!(
        runtime["pre_dispatch_payment_unwind"]["credential_disposition"],
        "retention_outcome_unknown"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_governed_commit_error_during_ambiguous_authorization_is_signed_unknown(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_governed_payment_failure_fixture(
        "nested-governed-commit-error",
        PaymentAmbiguityMode::AuthorizeRailError,
        ApprovalReplayFailureMode::CommitError,
    );
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-governed-commit-error-parent",
    )
    .await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    let runtime = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("commit-error receipt metadata missing"))?
        ["chio_runtime"];
    assert_eq!(
        response.receipt.metadata.as_ref().and_then(|metadata| metadata
            ["financial"]["payment_authorization_ambiguous"]
            .as_bool()),
        Some(true)
    );
    assert_eq!(
        runtime["payment_credential_disposition"],
        "retention_outcome_unknown"
    );
    assert_eq!(
        runtime["dispatch_credential_retention_outcome_unknown"],
        true
    );
    assert_eq!(
        fixture
            .counters
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_governed_commit_error_after_dispatch_records_terminal_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_governed_dispatch_commit_failure_fixture(
        "hosted-governed-post-dispatch-commit-error",
        ApprovalReplayFailureMode::CommitError,
    );

    let result = fixture.kernel.evaluate_tool_call(&fixture.request).await;
    assert!(result.is_err(), "credential commit failure must surface");
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "tool dispatch must complete before the injected commit failure"
    );
    let receipts = fixture.kernel.receipt_log();
    assert_eq!(
        receipts.len(),
        1,
        "post-dispatch credential failure must record one terminal receipt"
    );
    let receipt = receipts
        .get(0)
        .ok_or_else(|| std::io::Error::other("terminal receipt missing"))?;
    assert!(receipt.is_cancelled());
    assert!(receipt.verify_signature()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_governed_commit_error_after_dispatch_records_terminal_receipt(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_governed_dispatch_commit_failure_fixture(
        "nested-governed-post-dispatch-commit-error",
        ApprovalReplayFailureMode::CommitError,
    );
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;

    let result = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-governed-post-dispatch-commit-error-parent",
    )
    .await;
    assert!(result.is_err(), "credential commit failure must surface");
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "nested tool dispatch must complete before the injected commit failure"
    );
    let receipts = fixture.kernel.receipt_log();
    assert_eq!(
        receipts.len(),
        1,
        "nested post-dispatch credential failure must record one terminal receipt"
    );
    let receipt = receipts
        .get(0)
        .ok_or_else(|| std::io::Error::other("terminal receipt missing"))?;
    assert!(receipt.is_cancelled());
    assert!(receipt.verify_signature()?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_clean_decline_with_governed_rollback_error_is_signed_retention_unknown(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_governed_payment_failure_fixture(
        "hosted-governed-rollback-error",
        PaymentAmbiguityMode::AuthorizeDeclined,
        ApprovalReplayFailureMode::RollbackError,
    );
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.verify_signature()?);
    let runtime = &response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("rollback-error receipt metadata missing"))?
        ["chio_runtime"];
    assert_eq!(
        runtime["dispatch_credential_retention_outcome_unknown"],
        true
    );
    assert_eq!(
        runtime["dispatch_credential_disposition"],
        "retention_outcome_unknown"
    );
    assert_eq!(
        fixture
            .counters
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    Ok(())
}

fn assert_payment_ambiguity_retained(
    fixture: &PaymentAmbiguityFixture,
    response: &ToolCallResponse,
    _fault_step: &str,
    outcome_flag: &str,
    expected_authorization: Option<(&str, bool)>,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(response.receipt.verify_signature()?);

    let usage = fixture
        .kernel
        .budget_store
        .get_usage(&fixture.capability.id, 0)?
        .ok_or_else(|| std::io::Error::other("retained payment usage missing"))?;
    assert_eq!(usage.total_cost_exposed, 100);
    assert_eq!(usage.total_cost_realized_spend, 0);
    assert_eq!(usage.committed_cost_units()?, 100);

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("payment fault metadata missing"))?;
    let budget = &metadata["budget_authority"];
    let hold_id = budget["hold_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("retained budget hold id missing"))?;
    assert!(!hold_id.is_empty());
    match outcome_flag {
        "payment_authorization_outcome_unknown" => {
            let financial = &metadata["financial"];
            assert_eq!(financial["payment_authorization_ambiguous"], true);
            assert!(financial.get("payment_reference").is_none());
            assert!(expected_authorization.is_none());
        }
        "payment_unwind_outcome_unknown" => {
            assert_eq!(budget["pre_dispatch_cleanup_unconfirmed"], true);
            let financial = &metadata["financial"];
            assert_eq!(financial["payment_unwind_unconfirmed"], true);
            let (authorization_id, _) = expected_authorization.ok_or_else(|| {
                std::io::Error::other("payment unwind omitted its authorization")
            })?;
            assert_eq!(financial["payment_reference"], authorization_id);
        }
        "budget_reversal_outcome_unknown" => {
            assert_eq!(
                budget["pre_dispatch_cleanup_unconfirmed"], true,
                "unexpected budget reversal metadata: {metadata:#}"
            );
            assert!(expected_authorization.is_none());
            let unwind = &metadata["chio_runtime"]["pre_dispatch_payment_unwind"];
            assert_eq!(
                unwind["credential_disposition"],
                "retained_after_authorization"
            );
        }
        unexpected => panic!("unexpected payment ambiguity outcome flag: {unexpected}"),
    }
    Ok(())
}

fn assert_payment_retry_blocked(fixture: &PaymentAmbiguityFixture, response: &ToolCallResponse) {
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| {
                reason.contains("execution nonce")
                    || reason.contains("pre-dispatch cleanup")
                    || reason.contains("budget")
            }),
        "expected retained authority to block retry, got: {:?}",
        response.reason
    );
    assert_eq!(
        fixture
            .counters
            .authorizations
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "retained exposure must block a second payment authorization"
    );
    assert_eq!(
        fixture
            .invocations
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_payment_ambiguity_rail_error_retains_budget_without_fabricated_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_payment_ambiguity_fixture(
        "hosted-authorization-rail-error",
        PaymentAmbiguityMode::AuthorizeRailError,
    );
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "payment_authorization",
        "payment_authorization_outcome_unknown",
        None,
    )?;

    let mut retry = fixture.request.clone();
    retry.request_id = "hosted-authorization-rail-error-retry".to_string();
    let retry_response = fixture.kernel.evaluate_tool_call(&retry).await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_payment_ambiguity_panic_retains_budget_without_fabricated_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_payment_ambiguity_fixture(
        "hosted-authorization-panic",
        PaymentAmbiguityMode::AuthorizePanic,
    );
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "payment_authorization",
        "payment_authorization_outcome_unknown",
        None,
    )?;

    let mut retry = fixture.request.clone();
    retry.request_id = "hosted-authorization-panic-retry".to_string();
    let retry_response = fixture.kernel.evaluate_tool_call(&retry).await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_empty_payment_authorization_id_is_outcome_unknown_without_fabricated_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_payment_ambiguity_fixture(
        "hosted-empty-authorization-id",
        PaymentAmbiguityMode::AuthorizeEmptyId,
    );
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "payment_authorization",
        "payment_authorization_outcome_unknown",
        None,
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_payment_ambiguity_unavailable_retains_budget_without_fabricated_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_payment_ambiguity_fixture(
        "nested-authorization-unavailable",
        PaymentAmbiguityMode::AuthorizeUnavailable,
    );
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-authorization-unavailable-parent",
    )
    .await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "payment_authorization",
        "payment_authorization_outcome_unknown",
        None,
    )?;

    let mut retry = fixture.request.clone();
    retry.request_id = "nested-authorization-unavailable-retry".to_string();
    let retry_response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &retry,
        "nested-authorization-unavailable-retry-parent",
    )
    .await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_payment_ambiguity_panic_retains_budget_without_fabricated_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_payment_ambiguity_fixture(
        "nested-authorization-panic",
        PaymentAmbiguityMode::AuthorizePanic,
    );
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-authorization-panic-parent",
    )
    .await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "payment_authorization",
        "payment_authorization_outcome_unknown",
        None,
    )?;

    let mut retry = fixture.request.clone();
    retry.request_id = "nested-authorization-panic-retry".to_string();
    let retry_response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &retry,
        "nested-authorization-panic-retry-parent",
    )
    .await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_padded_payment_authorization_id_is_outcome_unknown_without_fabricated_id(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = make_payment_ambiguity_fixture(
        "nested-padded-authorization-id",
        PaymentAmbiguityMode::AuthorizePaddedId,
    );
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-padded-authorization-id-parent",
    )
    .await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "payment_authorization",
        "payment_authorization_outcome_unknown",
        None,
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_payment_ambiguity_release_error_retains_authorization_and_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture =
        make_payment_ambiguity_fixture("hosted-release-error", PaymentAmbiguityMode::ReleaseError);
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "monetary_unwind",
        "payment_unwind_outcome_unknown",
        Some(("payment-ambiguity-auth", false)),
    )?;
    assert_eq!(
        fixture
            .counters
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut retry = fixture.request.clone();
    retry.request_id = "hosted-release-error-retry".to_string();
    let retry_response = fixture.kernel.evaluate_tool_call(&retry).await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_payment_ambiguity_pending_release_retains_authorization_and_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = make_payment_ambiguity_fixture(
        "hosted-release-pending",
        PaymentAmbiguityMode::ReleasePending,
    );
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "monetary_unwind",
        "payment_unwind_outcome_unknown",
        Some(("payment-ambiguity-auth", false)),
    )?;
    assert_eq!(
        fixture
            .counters
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut retry = fixture.request.clone();
    retry.request_id = "hosted-release-pending-retry".to_string();
    let retry_response = fixture.kernel.evaluate_tool_call(&retry).await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_empty_release_transaction_id_is_not_reported_as_clean_unwind(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = make_payment_ambiguity_fixture(
        "hosted-empty-release-transaction-id",
        PaymentAmbiguityMode::ReleaseEmptyTransactionId,
    );
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "monetary_unwind",
        "payment_unwind_outcome_unknown",
        Some(("payment-ambiguity-auth", false)),
    )?;
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("release ambiguity metadata missing"))?;
    assert!(metadata["chio_runtime"]
        .get("pre_dispatch_payment_unwind")
        .is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_payment_ambiguity_successful_release_then_budget_reversal_failure_retains_only_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = make_payment_ambiguity_fixture(
        "hosted-release-budget-reversal-error",
        PaymentAmbiguityMode::ReleaseThenBudgetReversalError,
    );
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "budget_reversal",
        "budget_reversal_outcome_unknown",
        None,
    )?;
    assert_eq!(
        fixture
            .counters
            .releases
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("budget reversal fault metadata missing"))?;
    assert!(metadata["chio_runtime"]
        .get("payment_unwind_outcome_unknown")
        .is_none());
    let unwind = &metadata["chio_runtime"]["pre_dispatch_payment_unwind"];
    assert_eq!(unwind["authorization_id"], "payment-ambiguity-auth");
    assert_eq!(unwind["transaction_id"], "payment-ambiguity-auth");
    assert_eq!(unwind["settlement_status"], "released");
    assert_eq!(
        unwind["credential_disposition"],
        "retained_after_authorization"
    );

    let mut retry = fixture.request.clone();
    retry.request_id = "hosted-release-budget-reversal-error-retry".to_string();
    let retry_response = fixture.kernel.evaluate_tool_call(&retry).await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hosted_settled_payment_unwind_refunds_the_authorization_reference(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = make_payment_ambiguity_fixture(
        "hosted-settled-refund-identity",
        PaymentAmbiguityMode::RefundAcknowledged,
    );
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));

    let response = fixture.kernel.evaluate_tool_call(&fixture.request).await?;
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        fixture
            .counters
            .refunds
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let refund_inputs = fixture
        .counters
        .refund_inputs
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(refund_inputs.as_slice(), ["payment-ambiguity-auth"]);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("settled refund metadata missing"))?;
    let unwind = &metadata["chio_runtime"]["pre_dispatch_payment_unwind"];
    assert_eq!(unwind["authorization_id"], "payment-ambiguity-auth");
    assert_eq!(unwind["transaction_id"], "payment-ambiguity-auth");
    assert_eq!(unwind["settlement_status"], "refunded");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_payment_ambiguity_refund_panic_retains_authorization_and_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture =
        make_payment_ambiguity_fixture("nested-refund-panic", PaymentAmbiguityMode::RefundPanic);
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-refund-panic-parent",
    )
    .await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "monetary_unwind",
        "payment_unwind_outcome_unknown",
        Some(("payment-ambiguity-auth", true)),
    )?;
    assert_eq!(
        fixture
            .counters
            .refunds
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut retry = fixture.request.clone();
    retry.request_id = "nested-refund-panic-retry".to_string();
    let retry_response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &retry,
        "nested-refund-panic-retry-parent",
    )
    .await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_payment_ambiguity_failed_refund_retains_authorization_and_budget(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture =
        make_payment_ambiguity_fixture("nested-refund-failed", PaymentAmbiguityMode::RefundFailed);
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-refund-failed-parent",
    )
    .await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "monetary_unwind",
        "payment_unwind_outcome_unknown",
        Some(("payment-ambiguity-auth", true)),
    )?;
    assert_eq!(
        fixture
            .counters
            .refunds
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let mut retry = fixture.request.clone();
    retry.request_id = "nested-refund-failed-retry".to_string();
    let retry_response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &retry,
        "nested-refund-failed-retry-parent",
    )
    .await?;
    assert_payment_retry_blocked(&fixture, &retry_response);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_padded_refund_transaction_id_is_not_reported_as_clean_unwind(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = make_payment_ambiguity_fixture(
        "nested-padded-refund-transaction-id",
        PaymentAmbiguityMode::RefundPaddedTransactionId,
    );
    fixture.kernel.add_guard(Box::new(PaymentUnwindDenialGuard {
        authorization_returned: std::sync::Arc::clone(&fixture.counters.authorization_returned),
    }));
    let session_id = fixture.kernel.open_session(
        fixture.request.agent_id.clone(),
        vec![fixture.capability.clone()],
    )?;
    fixture.kernel.activate_session(&session_id)?;
    let response = evaluate_nested_payment_ambiguity_request(
        &fixture.kernel,
        &session_id,
        &fixture.request,
        "nested-padded-refund-transaction-id-parent",
    )
    .await?;
    assert_payment_ambiguity_retained(
        &fixture,
        &response,
        "monetary_unwind",
        "payment_unwind_outcome_unknown",
        Some(("payment-ambiguity-auth", true)),
    )?;
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("refund ambiguity metadata missing"))?;
    assert!(metadata["chio_runtime"]
        .get("pre_dispatch_payment_unwind")
        .is_none());
    Ok(())
}
