#[test]
fn allow_verdict_carries_signed_execution_nonce_and_verifies() {
    let (kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let signed = response
        .execution_nonce
        .expect("allow verdict must carry an execution nonce");

    let expected = binding_for_request(&cap, &request);
    kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap();
}

#[test]
fn stale_nonce_is_rejected_after_ttl() {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = InMemoryExecutionNonceStore::from_config(&cfg);
    let kp = Keypair::generate();
    let binding = NonceBinding {
        subject_id: "s".into(),
        request_id: "request-stale".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();

    let err = verify_execution_nonce(
        &signed,
        &kp.public_key(),
        &binding,
        now + cfg.nonce_ttl_secs as i64 + 1,
        &store,
    )
    .unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::Expired { .. }),
        "expected Expired, got {err:?}"
    );
}

#[test]
fn replayed_nonce_is_rejected_by_store() {
    let (kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-replay", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let signed = response
        .execution_nonce
        .expect("allow verdict must carry an execution nonce");
    let expected = binding_for_request(&cap, &request);

    // First verification consumes the nonce.
    kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap();
    // Second verification with the same nonce must be rejected as replay.
    let err = kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::Replayed),
        "expected Replayed, got {err:?}"
    );
}

#[test]
fn mismatched_binding_is_rejected() {
    let (kernel, agent_kp, scope, _cfg) = kernel_with_nonce();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-bind", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let signed = response
        .execution_nonce
        .expect("allow verdict must carry an execution nonce");

    // Corrupt the expected tool name -- the kernel was bound to read_file
    // but the caller claims write_file.
    let mut expected = binding_for_request(&cap, &request);
    expected.tool_name = "write_file".to_string();
    let err = kernel
        .verify_presented_execution_nonce(&signed, &expected)
        .unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::BindingMismatch { .. }),
        "expected BindingMismatch, got {err:?}"
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = InMemoryExecutionNonceStore::from_config(&cfg);
    let kp = Keypair::generate();
    let binding = NonceBinding {
        subject_id: "s".into(),
        request_id: "request-tampered".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let mut signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
    // Mutate a signed field after signing. Caller also mutates the
    // expected binding so the code path reaches signature verify.
    signed.nonce.bound_to.tool_name = "write_file".to_string();
    let expected = NonceBinding {
        tool_name: "write_file".to_string(),
        ..binding
    };
    let err =
        verify_execution_nonce(&signed, &kp.public_key(), &expected, now + 1, &store).unwrap_err();
    assert!(
        matches!(err, ExecutionNonceError::InvalidSignature),
        "expected InvalidSignature, got {err:?}"
    );
}

#[test]
fn disabled_mode_allows_tool_calls_without_nonce() {
    // A kernel with no execution_nonce_config installed: the allow
    // response must still succeed and the nonce slot must be absent.
    // This is the backward-compat guarantee for existing deployments.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-no-nonce-config", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.execution_nonce.is_none(),
        "legacy deployments should carry no execution nonce"
    );
}

#[test]
fn strict_nonce_mode_denies_dispatch_without_presented_nonce() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-required", &cap, "read_file", "srv-a");

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();

    assert!(
        err.to_string().contains("execution nonce"),
        "expected execution nonce denial, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_denies_missing_nonce_before_server_lookup() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-before-lookup", &cap, "read_file", "missing-srv");
    request.server_id = "missing-srv".to_string();

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();

    assert!(
        err.to_string().contains("execution nonce"),
        "expected nonce denial before server lookup, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_dispatches_once_with_presented_nonce() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-dispatch-once", &cap, "read_file", "srv-a");
    request.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &request, &cfg));

    let (output, cost) =
        block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false)).unwrap();
    assert!(cost.is_none());
    let ToolServerOutput::Value(value) = output else {
        panic!("expected value output");
    };
    assert_eq!(value["tool"], "read_file");

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "expected replay denial, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_nested_flow_operation_forwards_presented_nonce(
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request_id = "req-nonce-nested-operation";
    let request = make_request(request_id, &cap, "read_file", "srv-a");
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(&session_id, request_id, &agent_kp.public_key().to_hex());
    let operation = ToolCallOperation {
        capability: cap,
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        arguments: request.arguments.clone(),
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        execution_nonce: Some(serde_json::to_value(&nonce)?),
        model_metadata: None,
        extra_metadata: None,
    };
    let mut client = NoopNestedFlowClient;

    let response = kernel.evaluate_tool_call_operation_with_nested_flow_client(
        &context,
        &operation,
        &mut client,
    )?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.output.is_some(),
        "valid nonce on nested-flow operation must reach dispatch"
    );
    Ok(())
}

#[test]
fn strict_nonce_mode_preflights_nonce_then_executes_once() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        invocations.clone(),
    )));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let agent_kp = make_keypair();
    let mut grant = make_grant("srv-a", "read_file");
    grant.max_invocations = Some(1);
    let scope = make_scope(vec![grant]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-nonce-preflight", &cap, "read_file", "srv-a");

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);
    assert!(
        preflight.output.is_none(),
        "strict preflight must not invoke the tool server"
    );
    assert!(matches!(
        &preflight.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        matches!(
            preflight.receipt.decision.as_ref(),
            Some(Decision::Incomplete { reason })
                if reason.contains("execution nonce preflight")
        ),
        "nonce preflight receipt must not claim executed Allow"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let nonce = *preflight
        .execution_nonce
        .expect("strict preflight must return an execution nonce");
    let preflight_hold_id = format!(
        "nonce-preflight-budget-hold:{}:{}:0",
        request.request_id, cap.id
    );
    let preflight_events = kernel
        .budget_store
        .list_mutation_events(10, Some(&cap.id), Some(0))
        .unwrap();
    assert!(preflight_events.iter().any(|event| {
        event.kind == BudgetMutationKind::ReserveInvocation
            && event.hold_id.as_deref() == Some(preflight_hold_id.as_str())
            && event.event_id == format!("{preflight_hold_id}:authorize")
    }));
    assert!(preflight_events.iter().any(|event| {
        event.kind == BudgetMutationKind::ReverseInvocation
            && event.hold_id.as_deref() == Some(preflight_hold_id.as_str())
    }));
    assert!(!preflight_events
        .iter()
        .any(|event| event.kind == BudgetMutationKind::IncrementInvocation));

    let preflight_replay = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight_replay.verdict, Verdict::Deny);
    assert!(preflight_replay.execution_nonce.is_none());

    let mut execution_request = request.clone();
    execution_request.execution_nonce = Some(nonce);
    let executed = kernel
        .evaluate_tool_call_blocking(&execution_request)
        .unwrap();
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(
        executed.output.is_some(),
        "execution request must return tool output"
    );
    assert!(
        executed.execution_nonce.is_none(),
        "executed calls must not mint another nonce for the same request"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let execution_events = kernel
        .budget_store
        .list_mutation_events(10, Some(&cap.id), Some(0))
        .unwrap();
    assert!(execution_events.iter().any(|event| {
        event.kind == BudgetMutationKind::IncrementInvocation && event.hold_id.is_none()
    }));

    let replay = kernel
        .evaluate_tool_call_blocking(&execution_request)
        .unwrap();
    assert_eq!(replay.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn strict_nonce_mode_payment_denial_does_not_consume_nonce() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let mut request = ToolCallRequest {
        request_id: "req-nonce-payment-deny".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);
    request.execution_nonce = Some(
        *preflight
            .execution_nonce
            .expect("strict preflight must return an execution nonce"),
    );

    let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("payment authorization failed")),
        "expected payment denial, got: {:?}",
        denied.reason
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 0);
    kernel
        .reserve_presented_execution_nonce(&request)
        .expect("definite payment denial must leave the nonce unconsumed");

    kernel.set_payment_adapter(Box::new(StubPaymentAdapter));
    let mut retry_request = request.clone();
    retry_request.request_id = "req-nonce-payment-retry".to_string();
    retry_request.execution_nonce = None;
    let retry_preflight = kernel.evaluate_tool_call_blocking(&retry_request).unwrap();
    assert_eq!(retry_preflight.verdict, Verdict::Allow);
    retry_request.execution_nonce = Some(
        *retry_preflight
            .execution_nonce
            .expect("a new operation must receive its own execution nonce"),
    );
    let allowed = kernel.evaluate_tool_call_blocking(&retry_request).unwrap();
    assert_eq!(allowed.verdict, Verdict::Allow);
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn strict_nonce_mode_request_id_mismatch_precedes_monetary_side_effects(
) -> Result<(), Box<dyn std::error::Error>> {
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(MonetaryCostServer {
        id: "cost-srv".to_string(),
        reported_cost: Some(ToolInvocationCost {
            units: 50,
            currency: "USD".to_string(),
            breakdown: None,
        }),
    }));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let agent_kp = Keypair::generate();
    let cap = kernel.issue_capability(
        &agent_kp.public_key(),
        make_scope(vec![make_monetary_grant(
            "cost-srv", "compute", 100, 1000, "USD",
        )]),
        3600,
    )?;
    let request = ToolCallRequest {
        request_id: "req-nonce-bound-a".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let preflight = kernel.evaluate_tool_call_blocking(&request)?;
    let nonce = preflight
        .execution_nonce
        .ok_or_else(|| std::io::Error::other("strict preflight nonce missing"))?;
    let mut changed = request.clone();
    changed.request_id = "req-nonce-bound-b".to_string();
    changed.execution_nonce = Some(*nonce);

    let denied = kernel.evaluate_tool_call_blocking(&changed)?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let captures = kernel
        .budget_store
        .list_mutation_events(100, None, None)?
        .into_iter()
        .filter(|event| event.kind == BudgetMutationKind::CaptureInvocation)
        .count();
    assert_eq!(captures, 0);
    Ok(())
}

#[test]
fn strict_nonce_mode_denies_dispatch_with_stale_nonce() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-stale-dispatch", &cap, "read_file", "srv-a");
    let stale_issued_at =
        i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX) - cfg.nonce_ttl_secs as i64 - 1;
    request.execution_nonce = Some(
        mint_execution_nonce(
            &kernel.config.keypair,
            binding_for_request(&cap, &request),
            &cfg,
            stale_issued_at,
        )
        .unwrap(),
    );

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "expected stale nonce denial, got: {err}"
    );
}

#[test]
fn strict_nonce_mode_denies_dispatch_with_mismatched_binding() {
    let (mut kernel, agent_kp, scope, mut cfg) = kernel_with_nonce();
    cfg.require_nonce = true;
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-nonce-binding-dispatch", &cap, "read_file", "srv-a");
    let mut wrong_binding = binding_for_request(&cap, &request);
    wrong_binding.tool_name = "write_file".to_string();
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    request.execution_nonce =
        Some(mint_execution_nonce(&kernel.config.keypair, wrong_binding, &cfg, now).unwrap());

    let err = block_on_async_tool_dispatch(kernel.dispatch_tool_call_with_cost(&request, false))
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "expected binding denial, got: {err}"
    );
}

#[test]
fn require_presented_nonce_denies_when_missing_in_strict_mode() {
    // Build a kernel in strict mode and then call the gate helper
    // directly to prove that missing nonces fail closed.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let store = Box::new(InMemoryExecutionNonceStore::from_config(&cfg));
    kernel.set_execution_nonce_store(cfg, store);
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-strict-missing", &cap, "read_file", "srv-a");

    assert!(kernel.execution_nonce_required());
    let err = kernel
        .require_presented_execution_nonce(&request, &cap)
        .unwrap_err();
    assert!(matches!(err, KernelError::Internal(_)), "{err:?}");
}

#[test]
fn require_presented_nonce_passes_when_valid() {
    let (kernel, agent_kp, scope, cfg) = kernel_with_nonce();
    // Flip strict mode after initial construction via a fresh config.
    let _ = cfg; // cfg borrow -- silence unused warning
    let strict_cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let strict_store = Box::new(InMemoryExecutionNonceStore::from_config(&strict_cfg));
    // Rebuild kernel with strict mode set.
    let mut kernel = kernel;
    kernel.set_execution_nonce_store(strict_cfg.clone(), strict_store);

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-strict-ok", &cap, "read_file", "srv-a");
    request.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &request, &strict_cfg));

    kernel
        .require_presented_execution_nonce(&request, &cap)
        .unwrap();
}

#[test]
fn kernel_ttl_enforces_30s_default() {
    // A tool call presented >30s after evaluation is rejected. We
    // cannot "sleep 30s" in a unit test, so we mint a nonce at a
    // specific timestamp and re-verify with an explicit clock.
    let cfg = ExecutionNonceConfig::default();
    assert_eq!(cfg.nonce_ttl_secs, 30);
    let store = InMemoryExecutionNonceStore::from_config(&cfg);
    let kp = Keypair::generate();
    let binding = NonceBinding {
        subject_id: "s".into(),
        request_id: "request-expiry".into(),
        capability_id: "c".into(),
        tool_server: "t".into(),
        tool_name: "n".into(),
        parameter_hash: "h".into(),
    };
    let now = 1_000_000;
    let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
    // exactly on the boundary -> rejected (strict < check).
    let err =
        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 30, &store).unwrap_err();
    assert!(matches!(err, ExecutionNonceError::Expired { .. }));
}

#[test]
fn in_memory_store_ttl_grace_period_does_not_regress() {
    // Round-trip: a short TTL expires entries but the signed body still
    // blocks a real replay because expires_at was already checked.
    let store = InMemoryExecutionNonceStore::new(1024, std::time::Duration::from_millis(1));
    use crate::execution_nonce::ExecutionNonceStore;
    assert!(store.reserve("a").unwrap());
    std::thread::sleep(Duration::from_millis(5));
    // After TTL the slot is reclaimed; that is intentional. The signed
    // body's `expires_at` is what prevents the actual replay.
    assert!(store.reserve("a").unwrap());
}

#[test]
fn mediated_allow_receipt_records_bound_execution_nonce_id() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-nonce-link".to_string(),
        capability: cap,
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let nonce = response
        .execution_nonce
        .as_ref()
        .expect("mediated allow mints a nonce");
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    let recorded = metadata["budget_authority"]["execution_nonce_id"]
        .as_str()
        .expect("execution_nonce_id recorded on budget_authority metadata");
    assert_eq!(recorded, nonce.nonce_id());
    assert_eq!(
        metadata["budget_authority"]["mediated_spend"]["profile"],
        "chio.mediated_spend.v1"
    );
}

#[test]
fn reserving_authorization_keeps_hold_open_and_blocks_oversubscription() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    // max_cost_per_invocation == max_total_cost == 100: one authorization
    // reserves the entire grant budget.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let first = ToolCallRequest {
        request_id: "req-reserve-1".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    // The reserving authorization returns an allow verdict, an incomplete
    // terminal (no dispatch), and a freshly minted execution nonce.
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    assert!(matches!(
        &authorized.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(
        authorized.output.is_none(),
        "an authorization gate must not dispatch the tool"
    );
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("authorization mints a nonce");

    // The receipt records the reserved hold's authorize block with no terminal
    // reconcile, so it is truthfully non-authoritative.
    let metadata = authorized
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["authorize"]["exposure_units"], 100,
        "the reserved hold must record the authorized exposure"
    );
    assert!(
        metadata["budget_authority"].get("terminal").is_none(),
        "a reserved (not reconciled) hold must carry no terminal disposition"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert!(
        is_authoritative_spend_receipt(&authorized.receipt, &admitted, nonce.as_ref()).is_err(),
        "a reserved authorization receipt must not be an authoritative spend"
    );

    // The hold stayed reserved (not reversed), so a second
    // authorization for the same fully-reserved grant is denied. No
    // over-subscription past max_total_cost.
    let mut second = first.clone();
    second.request_id = "req-reserve-2".to_string();
    let denied = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied.verdict,
        Verdict::Deny,
        "the reserved hold must block a second authorization: {:?}",
        denied.reason
    );
}

#[test]
fn strict_retry_mediated_spend_receipt_names_presented_nonce() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let mut request = ToolCallRequest {
        request_id: "req-strict-retry-nonce".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    // The strict retry presents a nonce from a prior allow (the nonce binds the
    // capability/server/tool/parameter-hash, not the request id), so no nonce is
    // preminted during this completion.
    let nonce = mint_nonce_for_request(&kernel, &cap, &request, &cfg);
    request.execution_nonce = Some(nonce.clone());
    let executed = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(executed.verdict, Verdict::Allow);
    assert!(
        executed.output.is_some(),
        "strict retry must return tool output"
    );
    assert!(
        executed.execution_nonce.is_none(),
        "strict retry must not mint another nonce"
    );

    // The completed receipt must name the presented nonce id, not drop it.
    let metadata = executed
        .receipt
        .metadata
        .as_ref()
        .expect("receipt metadata present");
    assert_eq!(
        metadata["budget_authority"]["execution_nonce_id"]
            .as_str()
            .expect("execution_nonce_id recorded on budget_authority metadata"),
        nonce.nonce_id()
    );

    // The reconciled receipt is an authoritative mediated-spend receipt bound to
    // the presented nonce: no NonceLinkMissing.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&executed.receipt, &admitted, &nonce),
        Ok(())
    );
}

// ---------------------------------------------------------------------------
// Reconcile-by-nonce: mediated spend becomes authoritative at the realized cost.
// ---------------------------------------------------------------------------

fn reconcile_kernel_and_cap() -> (ChioKernel, Keypair, CapabilityToken, ExecutionNonceConfig) {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    // max_cost_per_invocation 100, max_total 150: one authorization reserves the
    // worst-case 100; a second (needing 100 more -> 200 > 150) is blocked until
    // the first frees its unspent slack.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    (kernel, agent_kp, cap, cfg)
}

fn reserve_request(request_id: &str, cap: &CapabilityToken, agent_kp: &Keypair) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn reconcile_by_nonce_settles_reserved_hold_and_frees_difference() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-1", &cap, &agent_kp);

    // Reserving authorization: hold H stays open, a nonce bound to H is minted.
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    assert!(
        nonce.reserved_hold_id().is_some(),
        "the reserving nonce must name the reserved hold"
    );
    assert_eq!(nonce.reserving_request_id(), Some("req-recon-1"));

    // A second authorization is blocked while the slack is reserved.
    let second = reserve_request("req-recon-2", &cap, &agent_kp);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "reserved hold must block the second authorization: {:?}",
        blocked.reason
    );

    // Reconcile H at realized 30 (< reserved 100): settle down, free 70.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    // The receipt is an authoritative mediated spend bound to the presented nonce.
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["disposition"], "reconciled",
        "the reserved hold must be reconciled, not released"
    );
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"],
        30
    );
    assert_eq!(meta["budget_authority"]["authorize"]["exposure_units"], 100);
    assert_eq!(
        meta["budget_authority"]["execution_nonce_id"]
            .as_str()
            .unwrap(),
        nonce.nonce_id()
    );

    // The freed difference admits a subsequent authorization that was blocked.
    let third = reserve_request("req-recon-3", &cap, &agent_kp);
    let now_allowed = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        now_allowed.verdict,
        Verdict::Allow,
        "the freed budget must admit a new authorization: {:?}",
        now_allowed.reason
    );
}

#[test]
fn reconcile_by_nonce_receipt_binds_reserved_hold_into_authoritative_predicate() {
    use chio_core_types::receipt::authoritative_spend::{
        is_authoritative_spend_receipt, BudgetAuthorityReceiptRef, PresentedNonceView,
    };

    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-bind", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    // The reconcile-by-nonce receipt commits the exact hold the nonce reserved,
    // so the nonce's signed reserved hold id equals the receipt's committed hold.
    let budget = BudgetAuthorityReceiptRef::from_receipt(&reconciled.receipt)
        .expect("reconciled receipt carries budget authority");
    assert_eq!(
        PresentedNonceView::bound_reserved_hold_id(&nonce),
        Some(budget.hold_id.as_str()),
        "the reconciled hold must equal the hold the nonce reserved"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reconcile_by_nonce_second_time_is_rejected_as_replay() {
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-replay", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };

    kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("nonce"),
        "second reconcile of the same nonce must be rejected as replay, got: {err}"
    );
}

#[test]
fn reconcile_by_nonce_rejects_forged_nonce() {
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-forge", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Repoint the signed hold id at an attacker-chosen hold without re-signing.
    let mut forged = nonce.clone();
    forged.nonce.reserved_hold_id = Some("budget-hold:attacker:cap:0".to_string());
    let realized = ToolInvocationCost {
        units: 10,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&forged, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("nonce"),
        "a tampered nonce must be rejected, got: {err}"
    );

    // The genuine hold is untouched: the real nonce still reconciles.
    let ok = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(ok.verdict, Verdict::Allow);
}

#[test]
fn reconcile_by_nonce_clamps_realized_above_reserved() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    // Reserve the whole grant (max_per == max_total == 100).
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let first = reserve_request("req-recon-clamp", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Realized cost 250 exceeds the reserved worst-case 100: clamp to 100.
    let realized = ToolInvocationCost {
        units: 250,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"], 100,
        "realized cost above the reserved worst-case must clamp to the reserved amount"
    );
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(())
    );
}

#[test]
fn reserved_hold_ttl_reaper_settles_expired_authorization_at_worst_case() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    // Whole grant reserved by one authorization.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let first = reserve_request("req-reap-1", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    let hold_id = nonce
        .reserved_hold_id()
        .expect("reserving nonce names the reserved hold")
        .to_string();

    // Not yet expired: the reaper leaves the still-valid reserved hold in place.
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    assert_eq!(kernel.reap_expired_reserved_budget_holds(now).unwrap(), 0);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(
            &reserve_request("req-reap-2", &cap, &agent_kp),
            None,
        )
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "a still-valid reserved hold must keep blocking: {:?}",
        blocked.reason
    );

    // Past expiry: the reaper SETTLES the abandoned reserved hold at its reserved
    // worst-case (forfeit). The only evidence a spend occurred is a reconcile the
    // caller never sent, so an expired-and-unreconciled hold is treated as fully
    // spent: realized spend advances by the reserved amount and the difference is
    // NOT refunded. This is fail-closed for a cumulative spend cap.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.total_cost_realized_spend, 100,
        "the forfeited reserved worst-case becomes realized spend"
    );
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "committed spend stays at the worst-case, not released back to 0"
    );
    let settled = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the reaped hold is still present");
    assert_eq!(
        settled.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reconciled,
        "an expired reserved hold is settled at worst-case, not released"
    );

    // The forfeited worst-case stays consumed: a new authorization is DENIED, not
    // admitted by the freed difference the old release behavior used to give back.
    let forfeited = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(
            &reserve_request("req-reap-3", &cap, &agent_kp),
            None,
        )
        .unwrap();
    assert_eq!(
        forfeited.verdict,
        Verdict::Deny,
        "the forfeited reserved worst-case must stay consumed after reaping: {:?}",
        forfeited.reason
    );
}

#[test]
fn reserved_hold_ttl_matches_minted_nonce_expiry() {
    // The reserved-hold TTL deadline must be derived from the exact
    // instant the nonce is minted (its signed `expires_at`), so a valid nonce can
    // never expire after its hold has already been reaped. Guarantees the caller
    // can always reconcile-before-reaper while the nonce is still valid.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let request = reserve_request("req-ttl-match", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("reserving authorization mints a nonce");
    let hold_id = nonce
        .reserved_hold_id()
        .expect("reserving nonce names the reserved hold");
    let hold = kernel
        .budget_store
        .get_budget_hold(hold_id)
        .unwrap()
        .expect("reserved hold is present");
    assert_eq!(
        hold.reserved_until,
        Some(nonce.expires_at()),
        "the reserved-hold TTL deadline must equal the minted nonce's expiry, never earlier"
    );
}

#[test]
fn reconcile_by_nonce_rejects_mismatched_realized_currency() {
    // Reconcile must reject a realized cost whose currency differs from
    // the currency the hold/grant was authorized in, before settling or signing.
    // A caller-supplied currency is never stamped onto a signed authoritative
    // receipt unchecked.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-currency", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Reconcile with a currency the grant was NOT authorized in (grant is USD).
    let mismatched = ToolInvocationCost {
        units: 30,
        currency: "EUR".to_string(),
        breakdown: None,
    };
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &mismatched)
        .unwrap_err();
    assert!(
        err.to_string().contains("currency"),
        "a realized currency that differs from the reserved grant currency must be rejected, got: {err}"
    );

    // Fail-closed: no settle occurred, so the reserved worst-case still blocks a
    // second authorization (the whole slack is still reserved, not consumed).
    let second = reserve_request("req-recon-currency-2", &cap, &agent_kp);
    let blocked = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        blocked.verdict,
        Verdict::Deny,
        "a rejected reconcile must not settle the reserved hold: {:?}",
        blocked.reason
    );

    // The nonce was not burned by the rejected reconcile, so the matching-currency
    // reconcile still succeeds and frees the difference.
    let matching = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let ok = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &matching)
        .unwrap();
    assert_eq!(ok.verdict, Verdict::Allow);
}

#[test]
fn reconcile_by_nonce_normalizes_currency_for_zero_exposure_invocation() {
    // A non-monetary invocation reserve carries zero exposure and no reserved
    // currency, so its realized currency is never validated (step 3). The
    // unchecked, caller-supplied currency must not reach the signed receipt: it is
    // normalized to the canonical inert value instead.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_invocation_limited_grant("cost-srv", "compute", 1);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-recon-invocation-currency", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // Reconcile with an arbitrary, attacker-controlled currency string. The
    // invocation reserve has zero exposure, so the currency is not validated and
    // the realized cost is clamped to zero.
    let realized = ToolInvocationCost {
        units: 0,
        currency: "ATTACKER-CONTROLLED".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    // The signed receipt carries the canonical inert currency, never the caller
    // string, on any field.
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["financial"]["currency"], "",
        "a zero-exposure invocation reconcile must normalize the receipt currency to the inert value"
    );
    let serialized = serde_json::to_string(&reconciled.receipt).unwrap();
    assert!(
        !serialized.contains("ATTACKER-CONTROLLED"),
        "the unchecked caller-supplied currency must never reach the signed receipt"
    );
}

#[test]
fn reserving_authorization_succeeds_for_unregistered_tool_server() {
    // The reserve-for-caller authorization path never dispatches a tool
    // on this kernel, so it must NOT require the caller's tool server to be
    // registered. This lets the sidecar stop registering caller-arbitrary server
    // ids (unbounded growth) into the kernel.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Deliberately do NOT register "unreg-srv".
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-reserve".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(
        authorized.verdict,
        Verdict::Allow,
        "the reserve path must not require tool-server registration: {:?}",
        authorized.reason
    );
    let nonce = authorized
        .execution_nonce
        .as_ref()
        .expect("the reserve authorization mints a nonce even for an unregistered server");
    assert!(
        nonce.reserved_hold_id().is_some(),
        "the reserve path reserves a hold and binds it into the nonce"
    );
}

#[test]
fn dispatch_for_unregistered_tool_server_still_denies() {
    // The dispatch path (and every non-reserve disposition) must still require the
    // tool server to be registered: only the reserve-for-caller path is relaxed.
    let kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Non-strict kernel so the normal dispatch path (not the reserve preflight) runs.
    let grant = make_monetary_grant("unreg-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = ToolCallRequest {
        request_id: "req-unreg-dispatch".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "unreg-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "invoice": "inv-1" }),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let denied = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(
        denied
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("not registered")),
        "dispatch to an unregistered server must deny ToolNotRegistered, got: {:?}",
        denied.reason
    );
}

// ---------------------------------------------------------------------------
// Preflight terminal-state reasons stay consistent with their receipt decision.
// ---------------------------------------------------------------------------

#[test]
fn reserving_authorization_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let request = reserve_request("req-reserve-reason", &cap, &agent_kp);

    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);

    let terminal_reason = match &authorized.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("reserving authorization must be incomplete, got {other:?}"),
    };
    let decision_reason = match authorized.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("reserving authorization receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the reserve path terminal_state reason must match its receipt decision reason"
    );
    assert!(
        decision_reason.contains("reserved")
            && decision_reason.contains("present the minted execution nonce"),
        "the reserve path must report the reservation reason, got: {decision_reason}"
    );
    assert!(
        !terminal_reason.contains("retry with presented nonce"),
        "the reserve path must not borrow the retry-path terminal reason"
    );
}

#[test]
fn preflight_retry_terminal_state_matches_receipt_decision_reason() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-preflight-reason", &cap, "read_file", "srv-a");

    let preflight = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(preflight.verdict, Verdict::Allow);

    let terminal_reason = match &preflight.terminal_state {
        OperationTerminalState::Incomplete { reason } => reason.clone(),
        other => panic!("strict preflight must be incomplete, got {other:?}"),
    };
    let decision_reason = match preflight.receipt.decision.as_ref() {
        Some(Decision::Incomplete { reason }) => reason.clone(),
        other => panic!("strict preflight receipt must be incomplete, got {other:?}"),
    };
    assert_eq!(
        terminal_reason, decision_reason,
        "the retry path terminal_state reason must match its receipt decision reason"
    );
    assert_eq!(
        terminal_reason, "execution nonce preflight requires retry with presented nonce",
        "the reverse-for-retry preflight reason must be unchanged"
    );
}

#[test]
fn reserving_authorization_rejects_presented_execution_nonce() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // No presented nonce: the mint-only reserve entry point authorizes.
    let clean = reserve_request("req-reserve-clean", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&clean, None)
        .unwrap();
    assert_eq!(authorized.verdict, Verdict::Allow);

    // A presented nonce is a settlement artifact. The mint-only reserve entry
    // point must fail closed rather than silently skip the reserve path and fall
    // through to dispatch (the documented MUST-NOT invariant).
    let mut presented = reserve_request("req-reserve-presented", &cap, &agent_kp);
    presented.execution_nonce = Some(mint_nonce_for_request(&kernel, &cap, &presented, &cfg));
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&presented, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("execution nonce"),
        "presenting a nonce at the reserve entry point must fail closed, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Delegated reserve-for-caller: an outstanding reservation keeps its child's
// sibling-sum share admitted, so a sibling cannot over-subscribe the parent
// while the reservation is open. The share is freed only when the hold closes
// (reconcile-by-nonce or TTL reap).
// ---------------------------------------------------------------------------

fn delegated_reserve_request(
    request_id: &str,
    child: &CapabilityToken,
    child_kp: &Keypair,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: child.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: child_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn install_strict_nonce_store(kernel: &mut ChioKernel) {
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
}

#[test]
fn delegated_reserving_child_holds_sibling_share_until_reconciled() {
    // Parent share 5000 bps, child A and child B each 4000 bps: either child
    // fits alone, but A+B (8000) over-subscribes the parent. While child A's
    // reservation hold is open, child A's admitted share must still count so a
    // second delegated child under the same parent is denied.
    let fixture = make_sibling_sum_monetary_fixture("delegated-reserve-reconcile");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A reservation should be admitted: {:?}",
        reserved_a.reason
    );
    let nonce = *reserved_a
        .execution_nonce
        .clone()
        .expect("child A reservation mints a nonce");

    let second = delegated_reserve_request("req-b-reserve", &fixture.child_b, &fixture.child_b_kp);
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's reservation is open: {:?}",
        denied_b.reason
    );
    assert!(
        denied_b.reason.as_deref().is_some_and(|reason| {
            reason.contains("sibling-sum") || reason.contains("sibling sum")
        }),
        "child B denial must cite sibling-sum over-subscription: {:?}",
        denied_b.reason
    );

    // Reconcile child A's hold: closing it releases child A's sibling share.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    let third = delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's reservation is reconciled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn delegated_reserving_child_sibling_share_freed_after_ttl_reap() {
    let fixture = make_sibling_sum_monetary_fixture("delegated-reserve-reap");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A reservation should be admitted: {:?}",
        reserved_a.reason
    );

    let second = delegated_reserve_request("req-b-reserve", &fixture.child_b, &fixture.child_b_kp);
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's reservation is open: {:?}",
        denied_b.reason
    );

    // The TTL reaper forfeits child A's abandoned reservation, closing the hold
    // and freeing child A's sibling-sum share back to the parent.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1,
        "the reaper settles child A's expired reserved hold"
    );

    let third = delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's reservation is reaped: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

// ---------------------------------------------------------------------------
// Restart durability: a delegated reserve-for-caller hold left open in the
// durable budget store keeps its child's sibling-sum share admitted against the
// parent. That admission is in-memory only, so a mediation kernel built fresh
// over the same store (a process restart) loses it. The kernel must not admit a
// second delegated child against the parent as if the still-open reservation
// consumed nothing; it denies delegated admission fail-closed until the prior
// process's hold is reconciled or reaped, then resumes.
// ---------------------------------------------------------------------------

#[test]
fn restart_gate_blocks_sibling_over_subscription_against_open_delegated_reserve() {
    let receipt_path = unique_receipt_db_path("restart-reserved-sibling-gate");

    // One shared, durable-style budget store both kernels reserve holds against,
    // exactly as the sidecar shares a single budget store across a restart.
    let budget: Arc<dyn BudgetStore> = Arc::new(InMemoryBudgetStore::new());

    // The sidecar reloads its persistent signing key on restart, so both kernels
    // issue and trust the same capability tokens.
    let config_before = make_monetary_config();
    let signer = config_before.keypair.clone();

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_monetary_grant(
        "cost-srv", "compute", 100, 1_000, "USD",
    )]);

    // Kernel before the restart: reserve child A, opening a delegated hold that
    // consumes 4000 bps of the parent's 5000 bps sibling budget.
    let mut kernel_before = make_kernel(config_before);
    kernel_before.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    kernel_before.set_budget_store_handle(Arc::clone(&budget));
    let parent = make_capability(&kernel_before, &parent_kp, parent_scope.clone(), 300);
    {
        let seed_store = SqliteReceiptStore::open(&receipt_path).unwrap();
        seed_store
            .record_capability_snapshot(&parent, None)
            .unwrap();
    }
    kernel_before
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&receipt_path).unwrap()))
        .unwrap();
    kernel_before
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel_before
        .set_capability_trust_root(signer.public_key(), scope_hash(&parent_scope).unwrap());
    install_strict_nonce_store(&mut kernel_before);

    let child_a = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel_before,
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_a_kp,
        parent_scope: &parent_scope,
        child_scope: child_scope.clone(),
        id: "cap-restart-child-a",
        share_bps: 4_000,
    });
    let child_b = make_v2_delegated_child(V2DelegatedChildInput {
        kernel: &kernel_before,
        parent: &parent,
        parent_kp: &parent_kp,
        child_kp: &child_b_kp,
        parent_scope: &parent_scope,
        child_scope,
        id: "cap-restart-child-b",
        share_bps: 4_000,
    });

    let reserve_a = delegated_reserve_request("req-a-reserve", &child_a, &child_a_kp);
    let reserved_a = kernel_before
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_a, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A reservation should be admitted before the restart: {:?}",
        reserved_a.reason
    );
    drop(kernel_before);

    // Kernel after the restart: fresh in-memory sibling-sum map and registry over
    // the SAME durable budget store, which still carries child A's open hold.
    let mut config_after = make_monetary_config();
    config_after.keypair = signer.clone();
    let mut kernel_after = make_kernel(config_after);
    kernel_after.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    kernel_after.set_budget_store_handle(Arc::clone(&budget));
    kernel_after
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&receipt_path).unwrap()))
        .unwrap();
    kernel_after
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel_after.set_capability_trust_root(signer.public_key(), scope_hash(&parent_scope).unwrap());
    install_strict_nonce_store(&mut kernel_after);
    kernel_after.arm_restart_reserved_hold_gate().unwrap();

    // Child B's 4000 bps would over-subscribe the parent's 5000 bps because child
    // A's reservation still holds 4000 bps. Without the restart gate the fresh
    // registry admits it; the gate denies fail-closed instead.
    let reserve_b = delegated_reserve_request("req-b-reserve", &child_b, &child_b_kp);
    let denied_b = kernel_after
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_b, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied fail-closed while child A's restart-carried reservation is open: {:?}",
        denied_b.reason
    );
    assert!(
        denied_b
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("prior process")),
        "child B denial must cite the unaccounted prior-process reservation: {:?}",
        denied_b.reason
    );

    // Settle child A's abandoned reservation in the shared store. Closing it drops
    // the last unaccounted delegated reserve hold, so the gate clears.
    assert_eq!(
        kernel_after
            .reap_expired_reserved_budget_holds(i64::MAX)
            .unwrap(),
        1,
        "the reaper settles child A's expired restart-carried hold"
    );

    let reserve_b_again = delegated_reserve_request("req-b-reserve-2", &child_b, &child_b_kp);
    let admitted_b = kernel_after
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_b_again, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted once child A's restart-carried reservation is settled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(receipt_path);
}

fn delegated_invocation_reserve_request(
    request_id: &str,
    child: &CapabilityToken,
    child_kp: &Keypair,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: child.clone(),
        tool_name: "compute".to_string(),
        server_id: "limited-srv".to_string(),
        agent_id: child_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        approval_tokens: Vec::new(),
        threshold_approval_proposal: None,
        supplemental_authorization: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

#[test]
fn delegated_reserving_child_with_non_monetary_grant_holds_sibling_share_until_reconciled() {
    // A non-monetary grant (max_invocations only, no cost ceiling) adopts its
    // debited invocation into a durable zero-exposure reserved hold on the
    // reserve-for-caller path. That hold is real and stays open until the caller
    // executes downstream, so child A's admitted sibling-sum share must be
    // RETAINED and recorded against the hold, exactly as a monetary reserve does.
    // A second delegated child under the same parent must be denied while child
    // A's invocation hold is open, or the parent's sibling budget is
    // over-subscribed. The share is freed only when the hold closes.
    let fixture = make_sibling_sum_invocation_fixture("delegated-reserve-invocation-reconcile");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_invocation_reserve_request(
        "req-a-reserve",
        &fixture.child_a,
        &fixture.child_a_kp,
    );
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A non-monetary reservation should be admitted: {:?}",
        reserved_a.reason
    );
    let nonce = *reserved_a
        .execution_nonce
        .clone()
        .expect("child A invocation reservation mints a nonce");

    let second = delegated_invocation_reserve_request(
        "req-b-reserve",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's invocation reservation is open: {:?}",
        denied_b.reason
    );
    assert!(
        denied_b.reason.as_deref().is_some_and(|reason| {
            reason.contains("sibling-sum") || reason.contains("sibling sum")
        }),
        "child B denial must cite sibling-sum over-subscription: {:?}",
        denied_b.reason
    );

    // Reconcile child A's zero-exposure invocation hold at zero realized cost:
    // closing it releases child A's retained sibling share.
    let realized = ToolInvocationCost {
        units: 0,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();
    assert_eq!(reconciled.verdict, Verdict::Allow);

    let third = delegated_invocation_reserve_request(
        "req-b-reserve-2",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's invocation reservation is reconciled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn delegated_reserving_child_with_non_monetary_grant_sibling_share_freed_after_ttl_reap() {
    // The invocation-only reserve-for-caller hold retains child A's sibling share
    // for the life of the hold. If the caller never executes, the TTL reaper
    // forfeits the expired hold and releases the share back to the parent, so a
    // sibling can then be admitted. Confirms the reaper's per-hold-id share
    // release covers the zero-exposure invocation hold.
    let fixture = make_sibling_sum_invocation_fixture("delegated-reserve-invocation-reap");
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_invocation_reserve_request(
        "req-a-reserve",
        &fixture.child_a,
        &fixture.child_a_kp,
    );
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    assert_eq!(
        reserved_a.verdict,
        Verdict::Allow,
        "child A non-monetary reservation should be admitted: {:?}",
        reserved_a.reason
    );

    let second = delegated_invocation_reserve_request(
        "req-b-reserve",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must be denied while child A's invocation reservation is open: {:?}",
        denied_b.reason
    );

    // The TTL reaper forfeits child A's abandoned invocation reservation, closing
    // the zero-exposure hold and freeing child A's retained sibling share.
    assert_eq!(
        kernel.reap_expired_reserved_budget_holds(i64::MAX).unwrap(),
        1,
        "the reaper settles child A's expired invocation reserved hold"
    );

    let third = delegated_invocation_reserve_request(
        "req-b-reserve-2",
        &fixture.child_b,
        &fixture.child_b_kp,
    );
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's invocation reservation is reaped: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(fixture.path);
}

// ---------------------------------------------------------------------------
// A failed reservation stamp must reverse the authorized hold, not strand it
// open-and-unstamped where the TTL reaper (which only settles stamped holds)
// would never reclaim it.
// ---------------------------------------------------------------------------

struct StampFailingBudgetStore {
    inner: InMemoryBudgetStore,
    fail_mark: std::sync::Arc<AtomicBool>,
}

impl BudgetStore for StampFailingBudgetStore {
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

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
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

    delegate_authority_fenced_budget_methods!(inner);

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
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        self.inner.reverse_budget_hold(request)
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.inner.capture_invocation_reservations(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<crate::budget_store::BudgetReconcileHoldDecision, BudgetStoreError> {
        self.inner.reconcile_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        self.inner.release_budget_hold(request)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        self.inner.get_budget_hold(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        if self.fail_mark.load(Ordering::SeqCst) {
            return Err(BudgetStoreError::Invariant(
                "reservation stamp write failed (test double)".to_string(),
            ));
        }
        self.inner.mark_hold_reserved(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.inner.reap_expired_reserved_holds(now_unix_secs)
    }
}

#[test]
fn reserving_stamp_failure_reverses_authorized_hold() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }));
    install_strict_nonce_store(&mut kernel);

    // The whole grant is reservable by one authorization, so a stranded hold
    // would block every later reservation on the grant.
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = reserve_request("req-stamp-fail", &cap, &agent_kp);
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("stamp") || err.to_string().contains("reservation"),
        "the reservation stamp failure must surface: {err}"
    );

    // The authorized hold was reversed, not left open-and-unstamped.
    let hold_id = format!("nonce-preflight-budget-hold:req-stamp-fail:{}:0", cap.id);
    let hold = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the authorized hold is recorded");
    assert_eq!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Reversed,
        "a failed reservation stamp must reverse the hold, not strand it open"
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "the reversed hold leaves no committed exposure"
    );

    // Once the stamp write recovers, a later reservation on the same fully-bounded
    // grant succeeds: nothing was stranded by the failed stamp.
    fail_mark.store(false, Ordering::SeqCst);
    let retry = reserve_request("req-stamp-recover", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&retry, None)
        .unwrap();
    assert_eq!(
        reserved.verdict,
        Verdict::Allow,
        "a later reservation must succeed after the failed stamp was unwound: {:?}",
        reserved.reason
    );
}

// A failed reservation stamp reverses the hold, so the reserved preflight receipt
// must not have been persisted first: a `hold_disposition: reserved` receipt with
// no terminal event standing over a reversed hold is a corrupted audit view. The
// receipt is persisted only after the hold is successfully stamped.
#[test]
fn reserving_stamp_failure_persists_no_reserved_receipt() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail_mark = std::sync::Arc::new(AtomicBool::new(true));
    kernel.set_budget_store(Box::new(StampFailingBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_mark: std::sync::Arc::clone(&fail_mark),
    }));
    install_strict_nonce_store(&mut kernel);

    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = reserve_request("req-stamp-no-receipt", &cap, &agent_kp);
    let err = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .unwrap_err();
    assert!(
        err.to_string().contains("stamp") || err.to_string().contains("reservation"),
        "the reservation stamp failure must surface: {err}"
    );

    // No orphaned reserved receipt: the stamp failed and reversed the hold, so the
    // preflight receipt must never have been persisted.
    assert_eq!(
        kernel.receipt_log().len(),
        0,
        "a failed reservation stamp must leave no persisted reserved receipt"
    );

    // Once the stamp write recovers, the success path persists exactly one reserved
    // receipt: the persist follows a successfully stamped hold.
    fail_mark.store(false, Ordering::SeqCst);
    let retry = reserve_request("req-stamp-receipt-ok", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&retry, None)
        .unwrap();
    assert_eq!(reserved.verdict, Verdict::Allow);
    assert_eq!(
        kernel.receipt_log().len(),
        1,
        "a successful reservation persists exactly one reserved receipt"
    );
}

// ---------------------------------------------------------------------------
// A durable receipt persist failure AFTER a successful reservation stamp must
// reverse the stamped hold and release the sibling-sum share, mirroring the
// stamp-failure cleanup. Otherwise the open, stamped hold burns budget for an
// authorization the caller never received until the TTL reaper forfeits it.
// ---------------------------------------------------------------------------

/// A receipt store whose `append` fails on demand, so a reservation stamp lands
/// but the durable receipt persist that follows it fails.
struct TogglingAppendReceiptStore {
    fail: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for TogglingAppendReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "receipt append failed (test double)".to_string(),
            ));
        }
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

/// A receipt store that forwards capability-snapshot reads to a real store (so
/// delegation validation still resolves ancestors) but fails receipt `append` on
/// demand, so a delegated reservation stamp lands and its durable persist fails.
struct TogglingSnapshotReceiptStore {
    inner: SqliteReceiptStore,
    fail: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for TogglingSnapshotReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(ReceiptStoreError::Conflict(
                "receipt append failed (test double)".to_string(),
            ));
        }
        self.inner.append_chio_receipt(receipt)
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        self.inner.append_child_receipt(receipt)
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        self.inner
            .record_capability_snapshot(token, parent_capability_id)
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        self.inner.get_capability_snapshot(capability_id)
    }
}

#[test]
fn reserving_receipt_persist_failure_is_nonfatal_and_reservation_reconcilable() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    kernel
        .set_receipt_store(Box::new(TogglingAppendReceiptStore {
            fail: std::sync::Arc::clone(&fail),
        }))
        .unwrap();
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );

    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // The reserve preflight's durable receipt persist fails. The reservation is
    // already durable in the budget store and the caller receives the minted nonce
    // to reconcile downstream, so a persistence-log failure must NOT void the
    // reservation: the response is a normal Allow carrying the nonce.
    let request = reserve_request("req-persist-fail", &cap, &agent_kp);
    let reserved = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&request, None)
        .expect("a reserve receipt persist failure must not void the durable reservation");
    assert_eq!(reserved.verdict, Verdict::Allow);
    let nonce = *reserved
        .execution_nonce
        .clone()
        .expect("the caller receives the minted nonce to reconcile the durable reservation");

    // The stamped hold stays OPEN (reserved), never reversed: it is reconcilable
    // and its worst-case exposure stays committed against the grant.
    let hold_id = nonce
        .reserved_hold_id()
        .expect("the reconcile nonce names the durable reservation")
        .to_string();
    let hold = kernel
        .budget_store
        .get_budget_hold(&hold_id)
        .unwrap()
        .expect("the reserved hold is recorded");
    assert_eq!(
        hold.disposition,
        crate::budget_store::BudgetHoldDispositionView::Open,
        "a receipt persist failure must NOT reverse the durable reservation"
    );
    assert!(
        hold.reserved_until.is_some(),
        "the hold stays stamped/reserved so the TTL reaper can settle it if abandoned"
    );
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        100,
        "the reserved worst-case exposure stays committed"
    );

    // The caller reconciles the durable reservation with the returned nonce once
    // the receipt store recovers, proving the reservation was never lost.
    fail.store(false, Ordering::SeqCst);
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &request.arguments, &realized)
        .expect("the durable reservation must be reconcilable by the returned nonce");
    assert_eq!(reconciled.verdict, Verdict::Allow);
}

#[test]
fn reserving_receipt_persist_failure_keeps_delegated_reservation_and_share() {
    let fixture = make_sibling_sum_monetary_fixture("reserve-persist-sibling");
    let path = fixture.path.clone();
    let mut kernel = fixture.kernel;
    let fail = std::sync::Arc::new(AtomicBool::new(true));
    kernel
        .set_receipt_store(Box::new(TogglingSnapshotReceiptStore {
            inner: SqliteReceiptStore::open(&path).unwrap(),
            fail: std::sync::Arc::clone(&fail),
        }))
        .unwrap();
    install_strict_nonce_store(&mut kernel);

    // Child A's reserve stamps a monetary hold and records its sibling-sum share,
    // then the durable receipt persist fails. That persistence-log failure is
    // NON-FATAL: child A's reservation is durable in the budget store and child A
    // receives the nonce to reconcile, so the hold is NOT reversed and its share
    // stays held.
    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let reserved_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .expect("a reserve receipt persist failure must not void child A's reservation");
    assert_eq!(reserved_a.verdict, Verdict::Allow);
    let nonce_a = *reserved_a
        .execution_nonce
        .clone()
        .expect("child A receives its reconcile nonce");

    // The receipt store recovers, but child B stays denied: child A's share is
    // still held by its durable reservation, not released by the failed persist.
    fail.store(false, Ordering::SeqCst);
    let second = delegated_reserve_request("req-b-reserve", &fixture.child_b, &fixture.child_b_kp);
    let denied_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&second, None)
        .unwrap();
    assert_eq!(
        denied_b.verdict,
        Verdict::Deny,
        "child B must stay denied while child A's persisted-but-unreceipted reservation holds its share: {:?}",
        denied_b.reason
    );

    // Reconciling child A's reservation by its nonce closes the hold and releases
    // the share, after which child B is admitted: the reservation lifecycle is
    // intact, the persist failure neither lost it nor leaked its share.
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce_a, &first.arguments, &realized)
        .expect("child A's durable reservation must reconcile by its nonce");
    assert_eq!(reconciled.verdict, Verdict::Allow);

    let third = delegated_reserve_request("req-b-reserve-2", &fixture.child_b, &fixture.child_b_kp);
    let admitted_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&third, None)
        .unwrap();
    assert_eq!(
        admitted_b.verdict,
        Verdict::Allow,
        "child B must be admitted after child A's reservation is reconciled: {:?}",
        admitted_b.reason
    );

    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Reconcile-by-nonce stamps the GRANT budget and delegation lineage recorded on
// the reserved hold, not the reservation exposure and a lost lineage.
// ---------------------------------------------------------------------------

#[test]
fn reconcile_by_nonce_stamps_grant_budget_not_reservation_exposure() {
    // Grant: max_cost_per_invocation 100, max_total 150. One reserve exposes 100
    // but the grant ceiling is 150. Reconcile at realized 30 must stamp
    // budget_total == 150 (grant ceiling) and budget_remaining == 150 - 30.
    let (kernel, agent_kp, cap, _cfg) = reconcile_kernel_and_cap();
    let first = reserve_request("req-recon-grant-total", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    assert_eq!(
        parsed.budget_total, 150,
        "budget_total must reflect the grant ceiling, not the reservation exposure"
    );
    assert_eq!(
        parsed.budget_remaining, 120,
        "budget_remaining must be the grant ceiling minus the grant's committed spend \
         after settle (a single reservation settled at 30 leaves 150 - 30)"
    );
    assert_eq!(parsed.cost_charged, 30);
    // A root reservation carries no delegation: depth 0, root is the grant holder.
    assert_eq!(parsed.delegation_depth, 0);
    assert_eq!(parsed.root_budget_holder, cap.issuer.to_hex());
}

#[test]
fn reconcile_by_nonce_budget_remaining_accounts_for_other_committed_spend() {
    // Grant: max_cost_per_invocation 40, max_total 150. Two reservations coexist
    // (40 + 40 = 80 <= 150). Reconciling the first at realized 10 must report
    // budget_remaining against the grant's TOTAL committed spend after settle
    // (150 - (80 - 40 + 10) = 100), NOT the grant ceiling minus this reconcile's
    // realized cost (150 - 10 = 140), which would ignore reservation B's held 40.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 40, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let reserve_a = reserve_request("req-recon-a", &cap, &agent_kp);
    let authorized_a = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_a, None)
        .unwrap();
    let nonce_a = *authorized_a.execution_nonce.clone().unwrap();

    // Reservation B stays open, committing another 40 against the grant.
    let reserve_b = reserve_request("req-recon-b", &cap, &agent_kp);
    let authorized_b = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve_b, None)
        .unwrap();
    assert_eq!(authorized_b.verdict, Verdict::Allow);

    let realized = ToolInvocationCost {
        units: 10,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce_a, &reserve_a.arguments, &realized)
        .unwrap();
    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    assert_eq!(parsed.budget_total, 150);
    assert_eq!(
        parsed.budget_remaining, 100,
        "budget_remaining must subtract the grant's total committed spend after \
         settle (50), not just this reconcile's realized cost (10)"
    );
    assert_eq!(parsed.cost_charged, 10);
}

#[test]
fn reconcile_by_nonce_no_total_cap_grant_does_not_stamp_sentinel() {
    // A grant with a per-invocation cap but NO max_total_cost carries no monetary
    // ceiling; the budget layer records u64::MAX as its sentinel ceiling. That
    // sentinel must never surface on a signed authoritative receipt as
    // budget_total / budget_remaining.
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = {
        use chio_core::capability::scope::MonetaryAmount;
        let mut grant = make_monetary_grant("cost-srv", "compute", 100, 999, "USD");
        grant.max_cost_per_invocation = Some(MonetaryAmount {
            units: 100,
            currency: "USD".to_string(),
        });
        grant.max_total_cost = None;
        grant
    };
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let reserve = reserve_request("req-recon-no-cap", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&reserve, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &reserve.arguments, &realized)
        .unwrap();
    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    assert_ne!(
        parsed.budget_total,
        u64::MAX,
        "a no-total-cap grant must not stamp the u64::MAX sentinel as budget_total"
    );
    assert_ne!(
        parsed.budget_remaining,
        u64::MAX,
        "budget_remaining must not carry the u64::MAX sentinel"
    );
    // With no real ceiling the receipt falls back to this reservation's bounded
    // exposure (100), settled at realized 30.
    assert_eq!(parsed.budget_total, 100);
    assert_eq!(parsed.budget_remaining, 70);
    assert_eq!(parsed.cost_charged, 30);
}

#[test]
fn reconcile_by_nonce_stamps_delegated_lineage() {
    // A delegated reservation must stamp its true delegation depth and root
    // budget holder, not depth 0 with the nonce subject as root.
    let fixture = make_sibling_sum_monetary_fixture("reconcile-lineage");
    let path = fixture.path.clone();
    let mut kernel = fixture.kernel;
    install_strict_nonce_store(&mut kernel);

    let first = delegated_reserve_request("req-a-reserve", &fixture.child_a, &fixture.child_a_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap();

    let financial = reconciled
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("financial"))
        .expect("reconciled receipt carries financial metadata")
        .clone();
    let parsed: crate::FinancialReceiptMetadata = serde_json::from_value(financial).unwrap();
    let expected_depth = fixture.child_a.delegation_chain.len() as u32;
    assert!(
        expected_depth > 0,
        "the fixture child must actually be delegated"
    );
    assert_eq!(
        parsed.delegation_depth, expected_depth,
        "a delegated reservation must stamp its true delegation depth, not zero"
    );
    assert_eq!(
        parsed.root_budget_holder,
        fixture.child_a.issuer.to_hex(),
        "a delegated reservation must stamp the true root budget holder"
    );

    let _ = std::fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// A durable receipt persist failure AFTER an irreversible reconcile settlement
// must still return the signed authoritative receipt (the nonce is already
// consumed and the hold closed, so a retry cannot recreate it), while a
// forged/replayed nonce still fails closed BEFORE settlement.
// ---------------------------------------------------------------------------

#[test]
fn reconcile_by_nonce_receipt_persist_failure_still_returns_authoritative_receipt() {
    use chio_core_types::receipt::authoritative_spend::is_authoritative_spend_receipt;

    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let fail = std::sync::Arc::new(AtomicBool::new(false));
    kernel
        .set_receipt_store(Box::new(TogglingAppendReceiptStore {
            fail: std::sync::Arc::clone(&fail),
        }))
        .unwrap();
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    // Reserve succeeds (persist not failing yet), minting a nonce bound to the hold.
    let first = reserve_request("req-recon-persist-fail", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized.execution_nonce.clone().unwrap();

    // The durable receipt persist fails during reconcile, AFTER the nonce is
    // consumed and the hold settled (irreversible). The signed authoritative
    // receipt must still be returned rather than surfacing only the persist error.
    fail.store(true, Ordering::SeqCst);
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .expect("a persist failure after settlement must still return the signed receipt");
    assert_eq!(reconciled.verdict, Verdict::Allow);
    let admitted = [kernel.config.keypair.public_key()];
    assert_eq!(
        is_authoritative_spend_receipt(&reconciled.receipt, &admitted, &nonce),
        Ok(()),
        "the returned receipt must be an authoritative spend receipt"
    );

    // The settlement is irreversible: a second reconcile of the same nonce is a
    // replay and still fails closed.
    fail.store(false, Ordering::SeqCst);
    let replay = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        replay.to_string().contains("nonce"),
        "a second reconcile of the settled nonce must fail closed as replay: {replay}"
    );
}

// ---------------------------------------------------------------------------
// The TTL reaper must release the sibling-sum share for holds the store closed
// before it errored partway through the sweep, then propagate the store error.
// A closed hold that keeps its share admitted would leak headroom and wrongly
// deny valid sibling reservations until restart; a still-open hold keeps its
// share because the store did not settle it.
// ---------------------------------------------------------------------------

/// A budget store whose reaper closes exactly one named hold and then fails, so
/// the sweep settles some holds before erroring. `get_budget_hold` reflects the
/// post-reap disposition so the reaper can re-query which holds actually closed.
struct PartialReapBudgetStore {
    holds: std::sync::Mutex<
        std::collections::HashMap<String, crate::budget_store::BudgetHoldDispositionView>,
    >,
    close_on_reap: String,
    fail_next_closed_lookup: AtomicBool,
}

impl PartialReapBudgetStore {
    fn new(close_on_reap: &str) -> Self {
        let mut holds = std::collections::HashMap::new();
        holds.insert(
            "h1".to_string(),
            crate::budget_store::BudgetHoldDispositionView::Open,
        );
        holds.insert(
            "h2".to_string(),
            crate::budget_store::BudgetHoldDispositionView::Open,
        );
        Self {
            holds: std::sync::Mutex::new(holds),
            close_on_reap: close_on_reap.to_string(),
            fail_next_closed_lookup: AtomicBool::new(false),
        }
    }

    fn with_post_reap_read_failure(close_on_reap: &str) -> Self {
        let store = Self::new(close_on_reap);
        store.fail_next_closed_lookup.store(true, Ordering::SeqCst);
        store
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        std::collections::HashMap<String, crate::budget_store::BudgetHoldDispositionView>,
    > {
        match self.holds.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl BudgetStore for PartialReapBudgetStore {
    fn try_increment(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
    ) -> Result<bool, BudgetStoreError> {
        Ok(true)
    }

    fn try_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _max_invocations: Option<u32>,
        _cost_units: u64,
        _max_cost_per_invocation: Option<u64>,
        _max_total_cost_units: Option<u64>,
    ) -> Result<bool, BudgetStoreError> {
        Ok(true)
    }

    fn reverse_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Ok(())
    }

    fn reduce_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Ok(())
    }

    fn settle_charge_cost(
        &self,
        _capability_id: &str,
        _grant_index: usize,
        _exposed_cost_units: u64,
        _realized_cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        Ok(())
    }

    reject_authority_fenced_budget_methods!(
        "partial reaper store does not support authority-fenced budget mutations"
    );

    fn list_usages(
        &self,
        _limit: usize,
        _capability_id: Option<&str>,
    ) -> Result<Vec<BudgetUsageRecord>, BudgetStoreError> {
        Ok(Vec::new())
    }

    fn get_usage(
        &self,
        _capability_id: &str,
        _grant_index: usize,
    ) -> Result<Option<BudgetUsageRecord>, BudgetStoreError> {
        Ok(None)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        let disposition = self.lock().get(hold_id).copied();
        if disposition.is_some_and(|value| !value.is_open())
            && self.fail_next_closed_lookup.swap(false, Ordering::SeqCst)
        {
            return Err(BudgetStoreError::Invariant(
                "transient post-reap read failure".to_string(),
            ));
        }
        Ok(
            disposition.map(|disposition| crate::budget_store::BudgetHoldSnapshot {
                hold_id: hold_id.to_string(),
                capability_id: "cap".to_string(),
                grant_index: 0,
                authorized_exposure_units: 100,
                remaining_exposure_units: 100,
                disposition,
                reserved_until: Some(0),
                reserved_currency: Some("USD".to_string()),
                reserved_payment_reference: None,
                reserved_budget_total: Some(100),
                reserved_delegation_depth: Some(1),
                reserved_root_budget_holder: Some("root".to_string()),
                authority: None,
            }),
        )
    }

    fn reap_expired_reserved_holds(&self, _now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        // Close exactly one hold, then fail: models a store that settled some
        // holds before erroring partway through the sweep.
        if let Some(disposition) = self.lock().get_mut(&self.close_on_reap) {
            *disposition = crate::budget_store::BudgetHoldDispositionView::Reconciled;
        }
        Err(BudgetStoreError::Invariant(
            "reap failed after settling one hold (test double)".to_string(),
        ))
    }
}

#[test]
fn reaper_releases_shares_for_holds_closed_before_a_store_error() {
    let mut kernel = make_kernel(make_config());
    kernel.set_budget_store(Box::new(
        PartialReapBudgetStore::with_post_reap_read_failure("h1"),
    ));
    {
        let mut shares = match kernel.reserved_sibling_shares.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        shares.insert(
            "h1".to_string(),
            ReservedSiblingShare {
                parent_token_id: "parent".to_string(),
                child_token_id: "child-1".to_string(),
                share_bps: 4000,
            },
        );
        shares.insert(
            "h2".to_string(),
            ReservedSiblingShare {
                parent_token_id: "parent".to_string(),
                child_token_id: "child-2".to_string(),
                share_bps: 4000,
            },
        );
    }

    // The store closes h1, errors on the sweep, then transiently fails the
    // post-reap read. The share stays held fail-closed on that first pass.
    let result = kernel.reap_expired_reserved_budget_holds(1_000);
    assert!(result.is_err(), "the store reap error must still propagate");
    let mut remaining = kernel.tracked_reserved_sibling_hold_ids();
    remaining.sort();
    assert_eq!(remaining, vec!["h1".to_string(), "h2".to_string()]);

    // The next sweep notices h1 is already closed and releases its share.
    assert!(kernel.reap_expired_reserved_budget_holds(1_000).is_err());
    let mut remaining = kernel.tracked_reserved_sibling_hold_ids();
    remaining.sort();
    assert_eq!(
        remaining,
        vec!["h2".to_string()],
        "only the still-open hold retains its share; the closed hold's share is released"
    );
}

// ---------------------------------------------------------------------------
// A transient store error while settling a reconcile must NOT consume the
// nonce. The single-use mark lands only after settlement, so a trusted caller
// that hit a transient error can re-present the same signed nonce and settle at
// realized cost instead of forfeiting the reservation.
// ---------------------------------------------------------------------------

/// A budget store that fails `reconcile_budget_hold` while a flag is armed,
/// simulating a transient settle error, and otherwise delegates to a real store.
struct TransientReconcileFailBudgetStore {
    inner: InMemoryBudgetStore,
    fail_reconcile: std::sync::Arc<AtomicBool>,
}

impl BudgetStore for TransientReconcileFailBudgetStore {
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

    fn reverse_charge_cost(
        &self,
        capability_id: &str,
        grant_index: usize,
        cost_units: u64,
    ) -> Result<(), BudgetStoreError> {
        self.inner
            .reverse_charge_cost(capability_id, grant_index, cost_units)
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

    delegate_authority_fenced_budget_methods!(inner);

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
        request: crate::budget_store::BudgetReverseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReverseHoldDecision, BudgetStoreError> {
        self.inner.reverse_budget_hold(request)
    }

    fn capture_invocation_reservations(
        &self,
        request: crate::budget_store::BudgetCaptureInvocationRequest,
    ) -> Result<crate::budget_store::BudgetInvocationCaptureDecision, BudgetStoreError> {
        self.inner.capture_invocation_reservations(request)
    }

    fn reconcile_budget_hold(
        &self,
        request: crate::budget_store::BudgetReconcileHoldRequest,
    ) -> Result<crate::budget_store::BudgetReconcileHoldDecision, BudgetStoreError> {
        // A transient settle failure: the nonce must survive it so the caller can
        // retry the same reconcile once the store recovers.
        if self.fail_reconcile.load(Ordering::SeqCst) {
            return Err(BudgetStoreError::Invariant(
                "reconcile settle failed (test double)".to_string(),
            ));
        }
        self.inner.reconcile_budget_hold(request)
    }

    fn release_budget_hold(
        &self,
        request: crate::budget_store::BudgetReleaseHoldRequest,
    ) -> Result<crate::budget_store::BudgetReleaseHoldDecision, BudgetStoreError> {
        self.inner.release_budget_hold(request)
    }

    fn get_budget_hold(
        &self,
        hold_id: &str,
    ) -> Result<Option<crate::budget_store::BudgetHoldSnapshot>, BudgetStoreError> {
        self.inner.get_budget_hold(hold_id)
    }

    fn mark_hold_reserved(
        &self,
        hold_id: &str,
        reserved_until_unix_secs: i64,
        currency: &str,
        payment_reference: Option<&str>,
        envelope: &crate::budget_store::ReservedHoldEnvelope,
    ) -> Result<(), BudgetStoreError> {
        self.inner.mark_hold_reserved(
            hold_id,
            reserved_until_unix_secs,
            currency,
            payment_reference,
            envelope,
        )
    }

    fn reap_expired_reserved_holds(&self, now_unix_secs: i64) -> Result<usize, BudgetStoreError> {
        self.inner.reap_expired_reserved_holds(now_unix_secs)
    }
}

#[test]
fn reconcile_by_nonce_transient_settle_error_preserves_nonce_for_retry() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        cfg.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&cfg)),
    );
    let fail_reconcile = std::sync::Arc::new(AtomicBool::new(false));
    kernel.set_budget_store(Box::new(TransientReconcileFailBudgetStore {
        inner: InMemoryBudgetStore::new(),
        fail_reconcile: std::sync::Arc::clone(&fail_reconcile),
    }));
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let first = reserve_request("req-recon-transient", &cap, &agent_kp);
    let authorized = kernel
        .authorize_tool_call_reserving_blocking_with_metadata(&first, None)
        .unwrap();
    let nonce = *authorized
        .execution_nonce
        .clone()
        .expect("reserving authorization mints a nonce");
    let realized = ToolInvocationCost {
        units: 30,
        currency: "USD".to_string(),
        breakdown: None,
    };

    // Arm a transient settle failure: the nonce is verified but the hold settle
    // errors, so the nonce must NOT be consumed and the reserved hold stays open.
    fail_reconcile.store(true, Ordering::SeqCst);
    let err = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .unwrap_err();
    assert!(
        err.to_string().contains("test double"),
        "the transient settle error must surface: {err}"
    );

    // Clear the failure and re-present the SAME signed nonce: it settles now,
    // proving the failed attempt did not burn the nonce.
    fail_reconcile.store(false, Ordering::SeqCst);
    let reconciled = kernel
        .reconcile_reserved_authorization_by_nonce(&nonce, &first.arguments, &realized)
        .expect("the same nonce must reconcile after the transient error clears");
    assert_eq!(reconciled.verdict, Verdict::Allow);
    let meta = reconciled.receipt.metadata.as_ref().unwrap();
    assert_eq!(
        meta["budget_authority"]["terminal"]["realized_spend_units"], 30,
        "the retry settles at the realized cost"
    );
}
