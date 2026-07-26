struct MutatingPaymentAdapter {
    mutable_state: std::sync::Arc<AtomicBool>,
    authorizations: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
}

impl PaymentAdapter for MutatingPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        self.mutable_state.store(true, Ordering::SeqCst);
        Ok(PaymentAuthorization {
            authorization_id: "post-payment-revalidation".to_string(),
            state: PaymentAuthorizationState::Held,
            metadata: serde_json::json!({"adapter": "mutating-test"}),
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
            metadata: serde_json::json!({"adapter": "mutating-test"}),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({"adapter": "mutating-test"}),
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
            metadata: serde_json::json!({"adapter": "mutating-test"}),
        })
    }
}

struct PostPaymentMutationGuard {
    mutable_state: std::sync::Arc<AtomicBool>,
    revalidations: std::sync::Arc<AtomicU64>,
}

impl Guard for PostPaymentMutationGuard {
    fn name(&self) -> &str {
        "post-payment-mutation-guard"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        self.revalidations.fetch_add(1, Ordering::SeqCst);
        if self.mutable_state.load(Ordering::SeqCst) {
            return Err(KernelError::GuardDenied(
                "payment authorization invalidated mutable guard state".to_string(),
            ));
        }
        Ok(())
    }
}

struct PostPaymentMutationRuntimeHook {
    mutable_state: std::sync::Arc<AtomicBool>,
    evaluations: std::sync::Arc<AtomicU64>,
    revalidations: std::sync::Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for PostPaymentMutationRuntimeHook {
    fn name(&self) -> &str {
        "post-payment-mutation-runtime-hook"
    }

    fn evaluate(
        &self,
        _context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.evaluations.fetch_add(1, Ordering::SeqCst);
        Ok(RuntimeAdmissionDecision::allow(None))
    }

    fn revalidate_before_dispatch(
        &self,
        _context: &RuntimeAdmissionRevalidationContext<'_>,
    ) -> Result<(), KernelError> {
        self.revalidations.fetch_add(1, Ordering::SeqCst);
        if self.mutable_state.load(Ordering::SeqCst) {
            return Err(KernelError::GuardDenied(
                "payment authorization invalidated mutable runtime admission state".to_string(),
            ));
        }
        Ok(())
    }
}

fn make_post_payment_mutation_fixture(
    request_id: &str,
    mutable_state: std::sync::Arc<AtomicBool>,
    authorizations: std::sync::Arc<AtomicU64>,
    releases: std::sync::Arc<AtomicU64>,
) -> (
    ChioKernel,
    CapabilityToken,
    ToolCallRequest,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut kernel = make_kernel(make_monetary_config());
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "post-payment-server".to_string(),
        invocations: invocations.clone(),
    }));
    kernel.set_payment_adapter(Box::new(MutatingPaymentAdapter {
        mutable_state,
        authorizations,
        releases,
    }));

    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_monetary_grant(
            "post-payment-server",
            "compute",
            100,
            1_000,
            "USD",
        )]),
        300,
    );
    let request = make_request(request_id, &capability, "compute", "post-payment-server");
    (kernel, capability, request, invocations)
}

fn assert_clean_payment_unwind_receipt(
    response: &ToolCallResponse,
    expected_credential_disposition: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(response.receipt.verify_signature()?);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .ok_or_else(|| std::io::Error::other("clean payment unwind metadata missing"))?;
    let unwind = &metadata["chio_runtime"]["pre_dispatch_payment_unwind"];
    assert_eq!(unwind["authorization_id"], "post-payment-revalidation");
    assert_eq!(unwind["transaction_id"], "post-payment-revalidation");
    assert_eq!(unwind["settlement_status"], "released");
    assert_eq!(
        unwind["credential_disposition"],
        expected_credential_disposition
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_payment_mutation_is_revalidated_by_guard_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mutable_state = std::sync::Arc::new(AtomicBool::new(false));
    let authorizations = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let revalidations = std::sync::Arc::new(AtomicU64::new(0));
    let (mut kernel, capability, mut request, invocations) = make_post_payment_mutation_fixture(
        "async-post-payment-mutation",
        mutable_state.clone(),
        authorizations.clone(),
        releases.clone(),
    );
    kernel.add_guard(Box::new(PostPaymentMutationGuard {
        mutable_state,
        revalidations: revalidations.clone(),
    }));
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );
    request.execution_nonce = Some(mint_nonce_for_request(
        &kernel,
        &capability,
        &request,
        &nonce_config,
    ));

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(revalidations.load(Ordering::SeqCst), 2);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(
        |reason| reason.contains("payment authorization invalidated mutable guard state")
    ));
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_clean_payment_unwind_receipt(&response, "retained_after_authorization")?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nested_payment_mutation_is_revalidated_by_runtime_hook_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mutable_state = std::sync::Arc::new(AtomicBool::new(false));
    let authorizations = std::sync::Arc::new(AtomicU64::new(0));
    let releases = std::sync::Arc::new(AtomicU64::new(0));
    let evaluations = std::sync::Arc::new(AtomicU64::new(0));
    let revalidations = std::sync::Arc::new(AtomicU64::new(0));
    let (mut kernel, capability, mut request, invocations) = make_post_payment_mutation_fixture(
        "nested-post-payment-mutation",
        mutable_state.clone(),
        authorizations.clone(),
        releases.clone(),
    );
    kernel.set_runtime_admission_hook(std::sync::Arc::new(PostPaymentMutationRuntimeHook {
        mutable_state,
        evaluations: evaluations.clone(),
        revalidations: revalidations.clone(),
    }));
    let nonce_config = ExecutionNonceConfig {
        nonce_ttl_secs: 300,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        nonce_config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&nonce_config)),
    );
    request.execution_nonce = Some(mint_nonce_for_request(
        &kernel,
        &capability,
        &request,
        &nonce_config,
    ));
    let session_id = kernel.open_session(request.agent_id.clone(), vec![capability])?;
    kernel.activate_session(&session_id)?;
    let parent_context =
        make_operation_context(&session_id, "nested-post-payment-parent", &request.agent_id);
    kernel.begin_session_request(&parent_context, OperationKind::ToolCall, true)?;
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client_async(
            &parent_context,
            &request,
            &mut client,
            None,
        )
        .await?;

    assert_eq!(authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(revalidations.load(Ordering::SeqCst), 2);
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| reason
        .contains("payment authorization invalidated mutable runtime admission state")));
    assert_eq!(evaluations.load(Ordering::SeqCst), 1);
    assert_eq!(releases.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_clean_payment_unwind_receipt(&response, "retained_after_authorization")?;
    Ok(())
}
