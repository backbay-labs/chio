use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_async_evaluate_after_monetary_dispatch_retains_budget_and_payment_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
        invocations: std::sync::Arc::clone(&invocations),
    }));

    struct AbortEvidenceGuard;
    impl Guard for AbortEvidenceGuard {
        fn name(&self) -> &str {
            "abort-evidence"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow_with_evidence(vec![GuardEvidence {
                guard_name: "abort-evidence".to_string(),
                verdict: true,
                details: Some("pre-invocation evidence recorded before abort".to_string()),
            }]))
        }
    }
    kernel.add_guard(Box::new(AbortEvidenceGuard));

    let agent_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
    let request = ToolCallRequest {
        request_id: "req-drop-after-admission".to_string(),
        capability: cap.clone(),
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
    let kernel = std::sync::Arc::new(kernel);
    let eval = {
        let kernel = std::sync::Arc::clone(&kernel);
        let request = request.clone();
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .map_err(|_| std::io::Error::other("pending monetary tool was not invoked before abort"))?;
    eval.abort();
    let join = eval.await;
    assert!(
        matches!(join, Err(error) if error.is_cancelled()),
        "aborted evaluation should not complete"
    );

    let usage = kernel
        .budget_store
        .get_usage(&cap.id, 0)?
        .ok_or_else(|| std::io::Error::other("monetary usage missing after dispatch"))?;
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
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("post-dispatch cancellation receipt missing"))?;
    assert!(receipt.is_cancelled());
    assert_eq!(receipt.evidence.len(), 1);
    assert_eq!(receipt.evidence[0].guard_name, "abort-evidence");
    assert_monetary_capture_receipt_metadata(receipt, &cap.id, &request.request_id)?;
    assert_payment_authorization_retained(receipt)?;
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);

    let retry = tokio::time::timeout(Duration::from_secs(1), kernel.evaluate_tool_call(&request))
        .await
        .map_err(|_| std::io::Error::other("retry reached the pending monetary tool server"))??;
    assert!(
        retry.receipt.is_denied(),
        "a confirmed dispatch must consume the single invocation"
    );
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn dropping_nested_evaluate_after_monetary_dispatch_retains_budget_and_payment_hold(
) -> Result<(), Box<dyn std::error::Error>> {
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let payment = TrackingPaymentAdapter::new();
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(payment.clone()));
    kernel.register_tool_server(Box::new(PendingMonetaryServer {
        id: "cost-srv".to_string(),
        started: std::sync::Arc::clone(&started),
        invocations: std::sync::Arc::clone(&invocations),
    }));

    let agent_kp = Keypair::generate();
    let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    grant.max_invocations = Some(1);
    let cap = kernel.issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)?;
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(
        &session_id,
        "req-nested-drop-after-dispatch",
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&context, OperationKind::ToolCall, true)?;
    let request = make_request_with_arguments(
        "req-nested-drop-after-dispatch",
        &cap,
        "compute",
        "cost-srv",
        serde_json::json!({}),
    );

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut client = NoopNestedFlowClient;
        let eval = kernel.evaluate_tool_call_with_nested_flow_client_async(
            &context,
            &request,
            &mut client,
            None,
        );
        tokio::pin!(eval);
        tokio::select! {
            _ = started.notified() => Ok(()),
            result = &mut eval => Err(std::io::Error::other(format!(
                "nested monetary evaluation completed before confirmed tool entry: {result:?}"
            ))),
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                Err(std::io::Error::other("nested monetary tool was not invoked before timeout"))
            }
        }
    })?;

    let usage = kernel
        .budget_store
        .get_usage(&cap.id, 0)?
        .ok_or_else(|| std::io::Error::other("nested monetary usage missing after dispatch"))?;
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
    assert_eq!(
        payment.refunded.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 1);
    let receipt = receipt_log
        .get(0)
        .ok_or_else(|| std::io::Error::other("nested drop cancellation receipt missing"))?;
    assert!(receipt.is_cancelled());
    assert_monetary_capture_receipt_metadata(receipt, &cap.id, &request.request_id)?;
    assert_payment_authorization_retained(receipt)?;

    let replay_session_id =
        kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()])?;
    kernel.activate_session(&replay_session_id)?;
    let replay_context = make_operation_context(
        &replay_session_id,
        &request.request_id,
        &agent_kp.public_key().to_hex(),
    );
    kernel.begin_session_request(&replay_context, OperationKind::ToolCall, true)?;
    let retry = rt
        .block_on(async {
            let mut client = NoopNestedFlowClient;
            tokio::time::timeout(
                Duration::from_secs(1),
                kernel.evaluate_tool_call_with_nested_flow_client_async(
                    &replay_context,
                    &request,
                    &mut client,
                    None,
                ),
            )
            .await
        })
        .map_err(|_| std::io::Error::other("retry reached the pending monetary tool server"))??;
    assert!(
        retry.receipt.is_denied(),
        "a nested confirmed dispatch must consume the single invocation"
    );
    assert_eq!(
        payment.authorized.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}
