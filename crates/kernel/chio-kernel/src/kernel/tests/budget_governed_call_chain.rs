#[test]
fn governed_monetary_allow_receipt_contains_approval_metadata() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-allow";
    let intent = make_governed_intent(
        "intent-governed-allow",
        "cost-srv",
        "compute",
        "settle approved invoice",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("allow receipt should carry metadata");
    let governed = metadata
        .get("governed_transaction")
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["intent_hash"], intent.binding_hash().unwrap());
    assert_eq!(governed["purpose"], intent.purpose);
    assert_eq!(governed["approval"]["approved"], true);
    assert_eq!(
        governed["approval"]["approver_key"],
        kernel.config.keypair.public_key().to_hex()
    );

    let financial = metadata
        .get("financial")
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(75));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(925));
}

#[test]
fn governed_monetary_allow_receipt_preserves_metered_billing_quote_context() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-metered-allow";
    let mut intent = make_governed_intent(
        "intent-governed-metered-allow",
        "cost-srv",
        "compute",
        "execute governed metered compute",
        100,
        "USD",
    );
    intent.metered_billing = Some(make_metered_billing_context(
        "quote-governed-1",
        "billing.chio",
        12,
        "USD",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed["metered_billing"]["quote"]["quoteId"],
        serde_json::Value::String("quote-governed-1".to_string())
    );
    assert_eq!(
        governed["metered_billing"]["quote"]["provider"],
        serde_json::Value::String("billing.chio".to_string())
    );
    assert_eq!(
        governed["metered_billing"]["settlementMode"],
        serde_json::Value::String("allow_then_settle".to_string())
    );
    assert_eq!(
        governed["metered_billing"]["maxBilledUnits"].as_u64(),
        Some(16)
    );
    assert!(governed["metered_billing"]["usageEvidence"].is_null());
}

#[test]
fn governed_request_rejects_empty_metered_billing_provider() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-metered-invalid";
    let mut intent = make_governed_intent(
        "intent-governed-metered-invalid",
        "cost-srv",
        "compute",
        "execute governed metered compute",
        100,
        "USD",
    );
    intent.metered_billing = Some(make_metered_billing_context(
        "quote-governed-2",
        "",
        8,
        "USD",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("metered billing provider must not be empty")));

    let usage = kernel

        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn governed_monetary_allow_receipt_preserves_call_chain_context() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-allow";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-allow",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-ops-1",
        "req-parent-1",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed["call_chain"]["chainId"],
        serde_json::Value::String("chain-ops-1".to_string())
    );
    assert_eq!(
        governed["call_chain"]["parentRequestId"],
        serde_json::Value::String("req-parent-1".to_string())
    );
    assert_eq!(
        governed["intent_hash"],
        serde_json::Value::String(intent.binding_hash().unwrap())
    );
}

#[test]
fn governed_call_chain_receipt_observes_local_parent_receipt_linkage() {
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let prior_response = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "req-local-parent-receipt",
            &capability,
            "delegate",
            "srv-echo",
            serde_json::json!({ "stage": "parent" }),
        ))
        .unwrap();

    let request_id = "req-governed-local-parent-receipt";
    let intent = GovernedTransactionIntent {
        id: "intent-local-parent-receipt".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(chio_core::capability::governance::GovernedCallChainContext {
            chain_id: "chain-local-parent-receipt".to_string(),
            parent_request_id: "req-upstream-local".to_string(),
            parent_receipt_id: Some(prior_response.receipt.id.clone()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        }),
        autonomy: None,
        context: None,
    };

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "child" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["local_parent_receipt_linkage"])
    );
}

#[test]
fn governed_call_chain_receipt_observes_capability_lineage_subjects() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-capability-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_scope = make_scope(vec![root_grant.clone()]);
    let root_capability = make_capability(&kernel, &root_kp, root_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &root_scope);
    kernel
        .register_budget_parent(root_capability.id.clone(), 10_000)
        .unwrap();

    let child_scope = make_scope(vec![make_grant("srv-echo", "delegate")]);
    let link = make_chain_bound_delegation_link(
        &root_capability.id,
        &root_kp,
        &child_kp.public_key(),
        &root_scope,
        current_unix_timestamp(),
    );
    let delegated_capability = make_chain_bound_capability(
        &kernel,
        "cap-governed-child",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &root_scope,
        None,
    );

    let request_id = "req-governed-capability-lineage";
    let root_subject = root_kp.public_key().to_hex();
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-capability-lineage".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "continue delegated workflow".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(chio_core::capability::governance::GovernedCallChainContext {
                    chain_id: "chain-capability-lineage".to_string(),
                    parent_request_id: "req-upstream-capability".to_string(),
                    parent_receipt_id: None,
                    origin_subject: root_subject.clone(),
                    delegator_subject: root_subject,
                }),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["capability_delegator_subject", "capability_origin_subject"])
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_call_chain_receipt_verifies_signed_upstream_delegator_proof() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-upstream-proof");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_scope = make_scope(vec![root_grant]);
    let root_capability = make_capability(&kernel, &root_kp, root_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &root_scope);
    kernel
        .register_budget_parent(root_capability.id.clone(), 10_000)
        .unwrap();

    let child_scope = make_scope(vec![make_grant("srv-echo", "delegate")]);
    let link = make_chain_bound_delegation_link(
        &root_capability.id,
        &root_kp,
        &child_kp.public_key(),
        &root_scope,
        current_unix_timestamp(),
    );
    let delegated_capability = make_chain_bound_capability(
        &kernel,
        "cap-governed-upstream-proof",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &root_scope,
        None,
    );

    let root_subject = root_kp.public_key().to_hex();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-upstream-proof".to_string(),
        parent_request_id: "req-upstream-proof-parent".to_string(),
        parent_receipt_id: Some("rc-upstream-proof-parent".to_string()),
        origin_subject: root_subject.clone(),
        delegator_subject: root_subject,
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-upstream-proof".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with signed upstream provenance".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: Some(serde_json::json!({ "workflow": "delegated-proof" })),
    };
    let upstream_proof =
        make_governed_upstream_call_chain_proof(&root_kp, &child_kp.public_key(), &call_chain);
    attach_governed_upstream_call_chain_proof(&mut intent, &upstream_proof);

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-upstream-proof".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(
        response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "verified");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!([
            "capability_delegator_subject",
            "capability_origin_subject",
            "upstream_delegator_proof"
        ])
    );
    assert_eq!(
        governed["call_chain"]["upstreamProof"]["signer"],
        serde_json::Value::String(root_kp.public_key().to_hex())
    );
    assert_eq!(
        governed["call_chain"]["upstreamProof"]["subject"],
        serde_json::Value::String(child_kp.public_key().to_hex())
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_call_chain_receipt_follows_asserted_observed_verified_execution_order() {
    let mut asserted_kernel = make_kernel(make_config());
    let asserted_agent_kp = make_keypair();
    asserted_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));
    let asserted_capability = make_capability(
        &asserted_kernel,
        &asserted_agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let asserted_response = asserted_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-asserted-order".to_string(),
            capability: asserted_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: asserted_agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "asserted" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-asserted-order".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "preserve caller-supplied delegated context".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(make_governed_call_chain_context(
                    "chain-asserted-order",
                    "req-upstream-asserted-order",
                )),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    let asserted_governed = asserted_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("asserted receipt should carry governed transaction metadata");
    assert_eq!(asserted_governed["call_chain"]["evidenceClass"], "asserted");
    assert!(asserted_governed["call_chain"]["evidenceSources"].is_null());
    assert!(asserted_governed["call_chain"]["upstreamProof"].is_null());

    let mut observed_kernel = make_kernel(make_config());
    let observed_agent_kp = make_keypair();
    observed_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));
    let observed_capability = make_capability(
        &observed_kernel,
        &observed_agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let parent_response = observed_kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "req-observed-parent-order",
            &observed_capability,
            "delegate",
            "srv-echo",
            serde_json::json!({ "stage": "parent" }),
        ))
        .unwrap();
    let observed_response = observed_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-observed-order".to_string(),
            capability: observed_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: observed_agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "observed" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-observed-order".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "upgrade local delegated context from receipt linkage".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(GovernedCallChainContext {
                    chain_id: "chain-observed-order".to_string(),
                    parent_request_id: "req-upstream-observed-order".to_string(),
                    parent_receipt_id: Some(parent_response.receipt.id.clone()),
                    origin_subject: "subject-origin".to_string(),
                    delegator_subject: "subject-delegator".to_string(),
                }),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    let observed_governed = observed_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("observed receipt should carry governed transaction metadata");
    assert_eq!(observed_governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        observed_governed["call_chain"]["evidenceSources"],
        serde_json::json!(["local_parent_receipt_linkage"])
    );
    assert!(observed_governed["call_chain"]["upstreamProof"].is_null());

    let path = unique_receipt_db_path("chio-kernel-call-chain-execution-order");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut verified_kernel = make_kernel(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    verified_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_scope = make_scope(vec![root_grant]);
    let root_capability = make_capability(
        &verified_kernel,
        &root_kp,
        root_scope.clone(),
        300,
    );
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    verified_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&verified_kernel, &root_scope);
    verified_kernel
        .register_budget_parent(root_capability.id.clone(), 10_000)
        .unwrap();

    let child_scope = make_scope(vec![make_grant("srv-echo", "delegate")]);
    let link = make_chain_bound_delegation_link(
        &root_capability.id,
        &root_kp,
        &child_kp.public_key(),
        &root_scope,
        current_unix_timestamp(),
    );
    let delegated_capability = make_chain_bound_capability(
        &verified_kernel,
        "cap-governed-execution-order",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &root_scope,
        None,
    );

    let root_subject = root_kp.public_key().to_hex();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-verified-order".to_string(),
        parent_request_id: "req-upstream-verified-order".to_string(),
        parent_receipt_id: Some("rc-upstream-verified-order".to_string()),
        origin_subject: root_subject.clone(),
        delegator_subject: root_subject,
    };
    let mut verified_intent = GovernedTransactionIntent {
        id: "intent-verified-order".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "upgrade delegated context with signed upstream provenance".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
    };
    let upstream_proof =
        make_governed_upstream_call_chain_proof(&root_kp, &child_kp.public_key(), &call_chain);
    attach_governed_upstream_call_chain_proof(&mut verified_intent, &upstream_proof);

    let verified_response = verified_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-verified-order".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "verified" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(verified_intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    let verified_governed = verified_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("verified receipt should carry governed transaction metadata");
    assert_eq!(verified_governed["call_chain"]["evidenceClass"], "verified");
    assert_eq!(
        verified_governed["call_chain"]["evidenceSources"],
        serde_json::json!([
            "capability_delegator_subject",
            "capability_origin_subject",
            "upstream_delegator_proof"
        ])
    );
    assert_eq!(
        verified_governed["call_chain"]["upstreamProof"]["signer"],
        serde_json::Value::String(root_kp.public_key().to_hex())
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_request_rejects_upstream_call_chain_proof_subject_mismatch() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-upstream-proof-subject-mismatch");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_scope = make_scope(vec![root_grant]);
    let root_capability = make_capability(&kernel, &root_kp, root_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();

    set_capability_trust_root_for_scope(&kernel, &root_scope);
    kernel
        .register_budget_parent(root_capability.id.clone(), 10_000)
        .unwrap();
    let child_scope = make_scope(vec![make_grant("srv-echo", "delegate")]);
    let link = make_chain_bound_delegation_link(
        &root_capability.id,
        &root_kp,
        &child_kp.public_key(),
        &root_scope,
        current_unix_timestamp(),
    );
    let delegated_capability = make_chain_bound_capability(
        &kernel,
        "cap-governed-upstream-proof-subject-mismatch",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &root_scope,
        None,
    );

    let root_subject = root_kp.public_key().to_hex();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-upstream-proof-subject-mismatch".to_string(),
        parent_request_id: "req-upstream-proof-subject-parent".to_string(),
        parent_receipt_id: Some("rc-upstream-proof-subject-parent".to_string()),
        origin_subject: root_subject.clone(),
        delegator_subject: root_subject,
    };
    let wrong_subject = make_keypair();
    let mut intent = GovernedTransactionIntent {
        id: "intent-upstream-proof-subject-mismatch".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with mismatched proof subject".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: Some(serde_json::json!({ "workflow": "delegated-proof" })),
    };
    let upstream_proof =
        make_governed_upstream_call_chain_proof(&root_kp, &wrong_subject.public_key(), &call_chain);
    attach_governed_upstream_call_chain_proof(&mut intent, &upstream_proof);

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-upstream-proof-subject-mismatch".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("call_chain upstream proof subject")
            && reason.contains("capability subject")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_request_rejects_call_chain_delegator_subject_that_conflicts_with_capability_lineage() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-delegator-mismatch");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = make_kernel(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_scope = make_scope(vec![root_grant]);
    let root_capability = make_capability(&kernel, &root_kp, root_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();

    set_capability_trust_root_for_scope(&kernel, &root_scope);
    kernel
        .register_budget_parent(root_capability.id.clone(), 10_000)
        .unwrap();
    let child_scope = make_scope(vec![make_grant("srv-echo", "delegate")]);
    let link = make_chain_bound_delegation_link(
        &root_capability.id,
        &root_kp,
        &child_kp.public_key(),
        &root_scope,
        current_unix_timestamp(),
    );
    let delegated_capability = make_chain_bound_capability(
        &kernel,
        "cap-governed-child-mismatch",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &root_scope,
        None,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-capability-lineage-deny".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-capability-lineage-deny".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "continue delegated workflow".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(chio_core::capability::governance::GovernedCallChainContext {
                    chain_id: "chain-capability-lineage-deny".to_string(),
                    parent_request_id: "req-upstream-capability-deny".to_string(),
                    parent_receipt_id: None,
                    origin_subject: root_kp.public_key().to_hex(),
                    delegator_subject: "subject-wrong".to_string(),
                }),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("call_chain.delegator_subject")
            && reason.contains("validated capability delegation source")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_call_chain_receipt_observes_session_parent_request_lineage() {
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context = make_operation_context(
        &session_id,
        "req-parent-session-lineage",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-child-session-lineage".to_string(),
                capability,
                tool_name: "delegate".to_string(),
                server_id: "srv-echo".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "stage": "child" }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: Some(GovernedTransactionIntent {
                    id: "intent-session-lineage".to_string(),
                    server_id: "srv-echo".to_string(),
                    tool_name: "delegate".to_string(),
                    purpose: "continue nested delegated workflow".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    runtime_attestation: None,
                    call_chain: Some(chio_core::capability::governance::GovernedCallChainContext {
                        chain_id: "chain-session-lineage".to_string(),
                        parent_request_id: parent_context.request_id.to_string(),
                        parent_receipt_id: None,
                        origin_subject: "origin-subject".to_string(),
                        delegator_subject: "delegator-subject".to_string(),
                    }),
                    autonomy: None,
                    context: None,
                }),
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            },
            &mut client,
            None,
        )
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["session_parent_request_lineage"])
    );
}

#[test]
fn cross_kernel_continuation_token_verifies_parent_receipt_hash_and_session_anchor() {
    let parent_kernel = make_kernel(make_config());
    let mut child_config = make_config();
    child_config.ca_public_keys.push(parent_kernel.public_key());
    let mut child_kernel = make_kernel(child_config);
    let child_kp = make_keypair();
    child_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let delegated_capability = make_capability(
        &child_kernel,
        &child_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );

    let parent_session_id = parent_kernel.open_session(child_kp.public_key().to_hex(), Vec::new()).unwrap();
    parent_kernel.activate_session(&parent_session_id).unwrap();
    parent_kernel
        .with_session_mut(&parent_session_id, |session| {
            assert!(
                session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                    "static-bearer:parent",
                    "token-parent",
                    Some("https://parent.example".to_string()),
                ))
                .0
            );
            Ok(())
        })
        .unwrap();
    let parent_anchor = parent_kernel
        .with_session(&parent_session_id, |session| {
            Ok(session.session_anchor().reference())
        })
        .unwrap();

    let parent_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rc-parent-continuation".to_string(),
            timestamp: current_unix_timestamp(),
            capability_id: "cap-parent-continuation".to_string(),
            tool_server: "srv-echo".to_string(),
            tool_name: "delegate".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({ "stage": "parent" }))
                .unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy-parent-continuation".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "lineageReferences": {
                    "sessionAnchorId": parent_anchor.session_anchor_id.clone(),
                    "sessionAnchorHash": parent_anchor.session_anchor_hash.clone(),
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: parent_kernel.public_key(),
            bbs_projection_version: None,
        },
        &parent_kernel.config.keypair,
    )
    .unwrap();
    let parent_receipt_hash = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&parent_receipt).unwrap(),
    );
    child_kernel.record_chio_receipt(&parent_receipt).unwrap();

    let call_chain = GovernedCallChainContext {
        chain_id: "chain-cross-kernel-continuation".to_string(),
        parent_request_id: "req-parent-continuation".to_string(),
        parent_receipt_id: Some(parent_receipt.id.clone()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-continuation".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with continuation token".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
    };
    let continuation_token =
        make_governed_call_chain_continuation_token(GovernedCallChainContinuationTokenFixture {
            signer: &parent_kernel.config.keypair,
            subject: &child_kp.public_key(),
            call_chain: &call_chain,
            parent_session_anchor: parent_anchor.clone(),
            parent_receipt_hash: &parent_receipt_hash,
            server_id: "srv-echo",
            tool_name: "delegate",
            governed_intent_hash: None,
        });
    attach_governed_call_chain_continuation_token(&mut intent, &continuation_token);

    let response = child_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-child-continuation".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "child" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "cross-kernel continuation token should allow; reason: {:?}",
        response.reason
    );
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["continuationTokenId"],
        serde_json::json!("continuation-token-1")
    );
    assert_eq!(
        governed["call_chain"]["sessionAnchorId"],
        serde_json::json!(parent_anchor.session_anchor_id.clone())
    );
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["local_parent_receipt_linkage"])
    );
}

#[test]
fn governed_request_rejects_self_referential_call_chain_parent_request() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-invalid";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-invalid",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    intent.call_chain = Some(make_governed_call_chain_context("chain-ops-2", request_id));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_ref().is_some_and(|reason| {
        reason.contains("call_chain.parent_request_id must not equal the current request_id")
    }));
}

#[test]
fn governed_request_rejects_empty_call_chain_chain_id() {
    let mut kernel = make_kernel(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-empty";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-empty",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    let mut call_chain = make_governed_call_chain_context("chain-ops-3", "req-parent-3");
    call_chain.chain_id.clear();
    intent.call_chain = Some(call_chain);
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_ref()
        .is_some_and(|reason| reason.contains("call_chain.chain_id must not be empty")));
}

#[test]
fn governed_call_chain_evidence_store_error_reverses_pre_execution_budget() {
    // A receipt-store READ error while resolving the parent call-chain receipt
    // fails closed, but check_and_increment_budget has already consumed the
    // invocation count and monetary hold. The error must be routed through the same
    // reversal + deny path the governed/guard denials use, never propagated raw, so
    // a transient store failure never burns quota or holds funds for a call that
    // never dispatches.
    let mut kernel = make_kernel(make_monetary_config());
    // Appends fine (so the request's own receipt persists) but errors on every
    // point load; the governed call-chain evidence lookup is the first (and
    // only) admission-path store read for this request, so it fails closed here.
    kernel.set_receipt_store(Box::new(ErroringReceiptStore)).unwrap();
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-store-error";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-store-error",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    // parent_receipt_id = Some(..) forces has_local_receipt_id() inside the
    // evidence lookup, which the erroring store fails.
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-store-error",
        "req-parent-store-error",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-store-error" }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        // The evidence-lookup store error must fail closed as a clean deny here,
        // not propagate out of evaluate.
        .expect("evidence-lookup store error must fail closed as a deny, not propagate");

    assert_eq!(response.verdict, Verdict::Deny);

    // The pre-execution budget mutation must have been reversed: neither the
    // invocation count nor the committed monetary cost may survive a call that
    // never dispatched.
    let usage = kernel.budget_store.get_usage(&cap.id, 0).unwrap().unwrap();
    assert_eq!(
        usage.invocation_count, 0,
        "invocation budget must be reversed on an evidence-lookup store error"
    );
    assert_eq!(
        usage.committed_cost_units().unwrap(),
        0,
        "monetary hold must be released on an evidence-lookup store error"
    );
}

#[test]
fn nested_governed_call_chain_evidence_store_error_reverses_pre_execution_budget() {
    // The nested-flow admission path has the same evidence-lookup `?` as the
    // top-level evaluate. A store read error there must reverse the pre-execution
    // budget before denying, on the nested arm too, so a transient store failure
    // never burns invocation quota.
    let mut kernel = make_kernel(make_config());
    kernel.set_receipt_store(Box::new(ErroringReceiptStore)).unwrap();
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    // An invocation-limited grant so the budget store tracks (and can reverse)
    // an invocation count.
    let grant = make_invocation_limited_grant("srv-echo", "delegate", 5);
    let capability = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let cap_id = capability.id.clone();
    let session_id = kernel
        .open_session(agent_kp.public_key().to_hex(), vec![capability.clone()])
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let parent_context = make_operation_context(
        &session_id,
        "req-parent-nested-store-error",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-child-nested-store-error".to_string(),
                capability,
                tool_name: "delegate".to_string(),
                server_id: "srv-echo".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "stage": "child" }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: Some(GovernedTransactionIntent {
                    id: "intent-nested-store-error".to_string(),
                    server_id: "srv-echo".to_string(),
                    tool_name: "delegate".to_string(),
                    purpose: "continue nested delegated workflow".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    runtime_attestation: None,
                    // parent_request_id matches the locally authenticated parent
                    // so validate_governed_transaction passes and we reach the
                    // evidence lookup; parent_receipt_id = Some(..) then forces
                    // the erroring store read there.
                    call_chain: Some(chio_core::capability::governance::GovernedCallChainContext {
                        chain_id: "chain-nested-store-error".to_string(),
                        parent_request_id: parent_context.request_id.to_string(),
                        parent_receipt_id: Some("rc-nested-missing".to_string()),
                        origin_subject: "origin-subject".to_string(),
                        delegator_subject: "delegator-subject".to_string(),
                    }),
                    autonomy: None,
                    context: None,
                }),
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            },
            &mut client,
            None,
        )
        // The nested evidence-lookup store error must fail closed as a clean deny
        // here, not propagate.
        .expect("nested evidence-lookup store error must fail closed as a deny, not propagate");

    assert_eq!(response.verdict, Verdict::Deny);
    // Pin that the deny comes from the evidence-lookup store read (not some
    // earlier validation), so the test actually exercises that path.
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("simulated receipt store read failure")),
        "nested deny must be the evidence-lookup store error, got reason {:?}",
        response.reason
    );

    let usage = kernel.budget_store.get_usage(&cap_id, 0).unwrap();
    // The invocation reservation must have been released on the nested arm too.
    assert!(
        usage.as_ref().map_or(0, |usage| usage.invocation_count) == 0,
        "nested evidence-lookup store error must reverse the invocation reservation, got {usage:?}"
    );
}

#[test]
fn nested_missing_session_roots_lookup_reverses_pre_execution_budget() {
    // On the nested-flow admission path the session filesystem-roots lookup
    // (session_enforceable_filesystem_root_paths_owned) sits AFTER
    // check_and_increment_budget and BEFORE dispatch. A parent session closed or
    // evicted concurrently surfaces as UnknownSession there. That error must
    // reverse the pre-execution budget and fail closed as a deny, never propagate,
    // so a transient session-lookup failure never burns invocation quota for a call
    // that never dispatched.
    let mut kernel = make_kernel(make_config());
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    // An invocation-limited grant so the budget store tracks (and can reverse)
    // an invocation count.
    let grant = make_invocation_limited_grant("srv-echo", "delegate", 5);
    let capability = make_capability(&kernel, &agent_kp, make_scope(vec![grant]), 300);
    let cap_id = capability.id.clone();

    // A parent context whose session was never opened (models a session closed
    // or evicted concurrently between admission and the roots lookup). No
    // governed_intent, so validate_governed_transaction and the call-chain
    // evidence lookup short-circuit without touching the session, and the
    // roots lookup is the first (and only) session-dependent step to fail.
    let parent_context = make_operation_context(
        &SessionId::new("sess-nested-missing-roots"),
        "req-parent-missing-roots",
        &agent_kp.public_key().to_hex(),
    );

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-child-missing-roots".to_string(),
                capability,
                tool_name: "delegate".to_string(),
                server_id: "srv-echo".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "stage": "child" }),
                dpop_proof: None,
                execution_nonce: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            },
            &mut client,
            None,
        )
        // The roots-lookup UnknownSession error must fail closed as a clean deny
        // here, not propagate out of evaluate.
        .expect("missing-session roots lookup must fail closed as a deny, not propagate");

    assert_eq!(response.verdict, Verdict::Deny);
    // Pin that the deny comes from the session-roots lookup (UnknownSession), so
    // the test actually exercises that line.
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("unknown session")),
        "nested deny must be the session-roots lookup UnknownSession error, got {:?}",
        response.reason
    );

    let usage = kernel.budget_store.get_usage(&cap_id, 0).unwrap();
    // The invocation reservation must have been released: no quota burned for a
    // call that never dispatched.
    assert!(
        usage.as_ref().map_or(0, |usage| usage.invocation_count) == 0,
        "missing-session roots lookup must reverse the invocation reservation, got {usage:?}"
    );
}
