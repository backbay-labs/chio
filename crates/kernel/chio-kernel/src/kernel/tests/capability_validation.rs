#[test]
fn kernel_rejects_classical_capability_under_pq_required_floor() {
    let keypair = make_keypair();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-classical-floor".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
        },
        &keypair,
    )
    .expect("sign classical capability");
    let mut config = make_config();
    config.keypair = keypair;
    let mut kernel = make_kernel(config);
    kernel.set_capability_crypto_floor(KernelCryptoFloor::PqRequired);

    let error = kernel
        .verify_capability_full_pre_admit(&token, None, 150)
        .expect_err("classical capability must fail under pq_required");

    assert!(
        error.contains("crypto_floor=pq_required"),
        "expected crypto floor rejection, got {error}"
    );
}

#[test]
fn production_evaluate_rejects_direct_attenuated_without_trust_root_resolver() {
    let issuer = make_keypair();
    let subject = make_keypair();
    let mut config = make_config();
    config.ca_public_keys = vec![issuer.public_key()];
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let capability = make_direct_attenuated_capability(
        &issuer,
        &subject.public_key(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
    );
    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-direct-attenuated",
            &capability,
            "read_file",
            "srv-a",
        ))
        .expect("attenuated rejection should produce a deny receipt");

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("chain-binding") && reason.contains("trust-root"),
        "expected chain-binding deny, got: {reason}"
    );
}

#[test]
fn local_default_without_store_invokes_tool() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));

    let subject = make_keypair();
    let capability = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        60,
    );
    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-local-no-store",
            &capability,
            "read_file",
            "srv-a",
        ))
        .expect("local default without a receipt store should invoke the tool");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        1,
        "ordinary local dispatch must not require a receipt store"
    );
    assert_eq!(kernel.receipt_log().len(), 1);
}

#[test]
fn admit_capability_budget_fails_closed_on_a_poisoned_registry() {
    let kernel = make_kernel(make_config());

    // Poison the monetary lock by panicking while it is held: the exact hazard a
    // panicking critical section leaves behind.
    let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = kernel.budget_registry.lock().expect("uncontended lock");
        panic!("poison the budget registry");
    }));
    assert!(poison.is_err());
    assert!(
        kernel.budget_registry.lock().is_err(),
        "the budget registry lock must now be poisoned"
    );

    // A delegated capability drives admission through the poisoned lock. It must
    // fail closed with an error rather than recover the half-mutated guard, and
    // the kernel-wide degraded flag must trip.
    let subject = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_chain_bound_delegation_link(
        "cap-parent",
        &kernel.config.keypair,
        &subject.public_key(),
        &scope,
        1,
    );
    let delegated = make_chain_bound_capability(
        &kernel,
        "cap-delegated-poison",
        subject.public_key(),
        scope.clone(),
        vec![link],
        &scope,
        Some(5_000),
    );

    let result = kernel.admit_capability_budget(&delegated);
    assert!(
        result.is_err(),
        "a poisoned monetary lock must deny admission, got {result:?}"
    );
    assert!(kernel.ensure_tcb_locks_healthy().is_err());
}

#[test]
fn poisoned_tcb_lock_denies_at_the_pre_dispatch_gate() {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));

    let subject = make_keypair();
    let capability = make_capability(
        &kernel,
        &subject,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        60,
    );

    // A prior panic poisoned a TCB lock; the kernel recorded it.
    kernel.record_tcb_lock_poison("budget_registry");

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-poisoned-gate",
            &capability,
            "read_file",
            "srv-a",
        ))
        .expect("evaluation returns a verdict rather than an error");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "a poisoned TCB lock must deny before the tool executes"
    );
}

#[test]
fn issue_and_use_capability() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );
    assert!(matches!(response.output, Some(ToolCallOutput::Value(_))));
    assert!(response.reason.is_none());

    // Receipt was logged.
    assert_eq!(kernel.receipt_log().len(), 1);

    // Receipt signature verifies.
    let receipt_log = kernel.receipt_log();
    let r = receipt_log.get(0).unwrap();
    assert!(r.verify_signature().unwrap());
}

#[test]
fn kernel_accepts_capabilities_from_configured_authority() {
    let authority_keypair = make_keypair();
    let mut kernel = make_kernel(make_config());
    kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
        authority_keypair.clone(),
    )));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-authority-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(cap.issuer, authority_keypair.public_key());
    assert_eq!(
        response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );
}

#[test]
fn kernel_reports_capability_issuer_trust() {
    let authority_keypair = make_keypair();
    let untrusted_keypair = make_keypair();
    let mut kernel = make_kernel(make_config());
    kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
        authority_keypair.clone(),
    )));

    assert!(kernel.capability_issuer_is_trusted(&authority_keypair.public_key()));
    assert!(kernel.capability_issuer_is_trusted(&kernel.public_key()));
    assert!(!kernel.capability_issuer_is_trusted(&untrusted_keypair.public_key()));
}

#[test]
fn expired_capability_denied() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    // TTL=0 means it expires at the same second it was issued.
    let cap = make_capability(&kernel, &agent_kp, scope, 0);
    let request = make_request("req-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("expired"), "reason was: {reason}");

    // Denial also produces a receipt.
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(kernel.receipt_log().get(0).unwrap().is_denied());
}

#[test]
fn revoked_capability_denied() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    kernel.revoke_capability(&cap.id).unwrap();

    let request = make_request("req-1", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("revoked"), "reason was: {reason}");
}

#[test]
fn sqlite_revocation_store_survives_kernel_restart() {
    let path = unique_receipt_db_path("chio-kernel-revocations");
    let authority_keypair = make_keypair();
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);

    let cap = {
        let mut kernel = make_kernel(make_config());
        kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
            authority_keypair.clone(),
        )));
        kernel.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let cap = make_capability(&kernel, &agent_kp, scope.clone(), 300);
        kernel.revoke_capability(&cap.id).unwrap();
        cap
    };

    let mut restarted = make_kernel(make_config());
    restarted.set_capability_authority(Box::new(LocalCapabilityAuthority::new(authority_keypair)));
    restarted.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
    restarted.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let request = make_request("req-revoked-after-restart", &cap, "read_file", "srv-a");
    let response = restarted.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.reason.as_deref().unwrap_or("").contains("revoked"),
        "reason was: {:?}",
        response.reason
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn out_of_scope_tool_denied() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file"],
    )));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Request write_file, but capability only grants read_file.
    let request = make_request("req-1", &cap, "write_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("not in capability scope"),
        "reason was: {reason}"
    );
}

#[test]
fn subject_mismatch_denied() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-1", &cap, "read_file", "srv-a");
    request.agent_id = make_keypair().public_key().to_hex();

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("does not match capability subject"));
}

#[test]
fn path_prefix_constraint_is_enforced() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::PathPrefix("/app/src".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let allowed = make_request_with_arguments(
        "req-allow",
        &cap,
        "read_file",
        "srv-a",
        serde_json::json!({"path": "/app/src/lib.rs"}),
    );
    let denied = make_request_with_arguments(
        "req-deny",
        &cap,
        "read_file",
        "srv-a",
        serde_json::json!({"path": "/etc/passwd"}),
    );

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&allowed)
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    let denied_response = kernel.evaluate_tool_call_blocking(&denied).unwrap();
    assert_eq!(denied_response.verdict, Verdict::Deny);
    assert!(denied_response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("not in capability scope"));
}

#[test]
fn domain_exact_constraint_is_enforced() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["fetch"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "fetch".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::DomainExact("api.example.com".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let allowed = make_request_with_arguments(
        "req-allow",
        &cap,
        "fetch",
        "srv-a",
        serde_json::json!({"url": "https://api.example.com/v1/data"}),
    );
    let denied = make_request_with_arguments(
        "req-deny",
        &cap,
        "fetch",
        "srv-a",
        serde_json::json!({"url": "https://evil.example.com/v1/data"}),
    );

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&allowed)
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&denied).unwrap().verdict,
        Verdict::Deny
    );
}

#[test]
fn unregistered_server_denied() {
    let kernel = make_kernel(make_config());
    // No tool servers registered.

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-missing", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "read_file", "srv-missing");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("not registered"), "reason was: {reason}");
}

#[test]
fn untrusted_issuer_denied() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let rogue_kp = make_keypair();
    let agent_kp = make_keypair();

    // Sign a capability with the rogue key (not trusted by this kernel).
    let body = CapabilityTokenBody {
        id: "cap-rogue".to_string(),
        issuer: rogue_kp.public_key(),
        subject: agent_kp.public_key(),
        scope: make_scope(vec![make_grant("srv-a", "read_file")]),
        issued_at: current_unix_timestamp(),
        expires_at: current_unix_timestamp() + 300,
        delegation_chain: vec![],
    };
    let cap = CapabilityToken::sign(body, &rogue_kp).unwrap();

    let request = ToolCallRequest {
        request_id: "req-rogue".to_string(),
        capability: cap,
        tool_name: "read_file".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("not found among trusted") || reason.contains("not a trusted CA"),
        "reason was: {reason}"
    );
}

#[test]
fn wildcard_server_grant_allows_real_server() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("filesystem", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("*", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request("req-1", &cap, "read_file", "filesystem");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
}

#[test]
fn revoked_ancestor_capability_denies_descendant() {
    let path = unique_receipt_db_path("chio-kernel-revoked-ancestor-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let link = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &scope,
        current_unix_timestamp(),
    );
    let child = make_chain_bound_capability(
        &kernel,
        "cap-child",
        child_kp.public_key(),
        scope.clone(),
        vec![link],
        &scope,
        None,
    );

    kernel.revoke_capability(&parent.id).unwrap();

    let request = make_request("req-1", &child, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains(&parent.id));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_records_observed_capability_lineage() {
    let path = unique_receipt_db_path("chio-kernel-observed-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);

    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &parent_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let link_timestamp = current_unix_timestamp();
    let link = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &parent_scope,
        link_timestamp,
    );
    let child = make_chain_bound_capability(
        &kernel,
        "cap-observed-child",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &parent_scope,
        None,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("req-observed", &child, "read_file", "srv-a"))
        .unwrap();
    assert_eq!(
        response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    let chain = reopened.get_delegation_chain(&child.id).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].capability_id, parent.id);
    assert_eq!(chain[0].delegation_depth, 0);
    assert_eq!(chain[1].capability_id, child.id);
    assert_eq!(
        chain[1].parent_capability_id.as_deref(),
        Some(parent.id.as_str())
    );
    assert_eq!(chain[1].delegation_depth, 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_without_parent_snapshot_denies() {
    let path = unique_receipt_db_path("chio-kernel-missing-parent-lineage");
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &parent_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &parent_scope,
        current_unix_timestamp(),
    );
    let child = make_chain_bound_capability(
        &kernel,
        "cap-missing-parent",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &parent_scope,
        None,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-missing-parent",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("missing capability snapshot"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_without_delegate_operation_denies() {
    let path = unique_receipt_db_path("chio-kernel-missing-delegate-op");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let parent_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &parent_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &parent_scope,
        current_unix_timestamp(),
    );
    let child = make_chain_bound_capability(
        &kernel,
        "cap-missing-delegate",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &parent_scope,
        None,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-missing-delegate",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("does not authorize delegated tool grant"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_with_scope_escalation_denies() {
    let path = unique_receipt_db_path("chio-kernel-scope-escalation");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let parent_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &parent_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link_timestamp = current_unix_timestamp();
    let link = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &parent_scope,
        link_timestamp,
    );
    let child = make_chain_bound_plain_capability(
        &kernel,
        "cap-escalated-child",
        child_kp.public_key(),
        child_scope.clone(),
        vec![link],
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-escalated-child",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("does not authorize delegated tool grant"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_with_delegatee_subject_mismatch_denies() {
    let path = unique_receipt_db_path("chio-kernel-delegatee-mismatch");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let other_child_kp = make_keypair();
    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &parent_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &other_child_kp.public_key(),
        &parent_scope,
        current_unix_timestamp(),
    );
    let child = make_chain_bound_capability(
        &kernel,
        "cap-delegatee-mismatch",
        child_kp.public_key(),
        child_scope,
        vec![link],
        &parent_scope,
        None,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-delegatee-mismatch",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("delegatee"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_exceeding_configured_max_depth_denies() {
    let path = unique_receipt_db_path("chio-kernel-max-delegation-depth");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut config = make_config();
    config.max_delegation_depth = 1;
    let mut kernel = make_kernel(config);
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let root_kp = make_keypair();
    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let mut delegable_grant = make_grant("srv-a", "read_file");
    delegable_grant.operations.push(Operation::Delegate);
    let delegable_scope = make_scope(vec![delegable_grant.clone()]);
    let root = make_capability(&kernel, &root_kp, delegable_scope.clone(), 300);
    seed_store.record_capability_snapshot(&root, None).unwrap();

    let root_to_parent = make_chain_bound_delegation_link(
        &root.id,
        &root_kp,
        &parent_kp.public_key(),
        &delegable_scope,
        current_unix_timestamp(),
    );
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-max-depth-parent".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: parent_kp.public_key(),
            scope: delegable_scope.clone(),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![root_to_parent.clone()],
        },
        &kernel.config.keypair,
    )
    .unwrap();
    seed_store
        .record_capability_snapshot(&parent, Some(root.id.as_str()))
        .unwrap();
    drop(seed_store);

    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &delegable_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent_to_child = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &delegable_scope,
        current_unix_timestamp(),
    );
    let child = make_chain_bound_plain_capability(
        &kernel,
        "cap-max-depth-child",
        child_kp.public_key(),
        child_scope,
        vec![root_to_parent, parent_to_child],
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("req-max-depth", &child, "read_file", "srv-a"))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("delegation depth 2 exceeds maximum 1"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_with_truncated_ancestor_chain_denies() {
    let path = unique_receipt_db_path("chio-kernel-truncated-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let root_kp = make_keypair();
    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let mut delegable_grant = make_grant("srv-a", "read_file");
    delegable_grant.operations.push(Operation::Delegate);
    let delegable_scope = make_scope(vec![delegable_grant.clone()]);
    let root = make_capability(&kernel, &root_kp, delegable_scope.clone(), 300);
    seed_store.record_capability_snapshot(&root, None).unwrap();

    let root_to_parent = make_chain_bound_delegation_link(
        &root.id,
        &root_kp,
        &parent_kp.public_key(),
        &delegable_scope,
        current_unix_timestamp(),
    );
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-truncated-parent".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: parent_kp.public_key(),
            scope: delegable_scope.clone(),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![root_to_parent],
        },
        &kernel.config.keypair,
    )
    .unwrap();
    seed_store
        .record_capability_snapshot(&parent, Some(root.id.as_str()))
        .unwrap();
    drop(seed_store);

    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
    set_capability_trust_root_for_scope(&kernel, &delegable_scope);
    kernel.register_budget_parent(parent.id.clone(), 10_000).unwrap();

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent_to_child = make_chain_bound_delegation_link(
        &parent.id,
        &parent_kp,
        &child_kp.public_key(),
        &delegable_scope,
        current_unix_timestamp(),
    );
    let child = make_chain_bound_capability(
        &kernel,
        "cap-truncated-child",
        child_kp.public_key(),
        child_scope,
        vec![parent_to_child],
        &delegable_scope,
        None,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-truncated-lineage",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("stored depth"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn wildcard_tool_grant_allows_any_tool() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["anything"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "*")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request("req-1", &cap, "anything", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict, Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );
}

#[test]
fn in_memory_revocation_store() {
    let store = InMemoryRevocationStore::default();
    assert!(!store.is_revoked("cap-1").unwrap());
    assert!(store.revoke("cap-1").unwrap());
    assert!(store.is_revoked("cap-1").unwrap());
    assert!(!store.revoke("cap-1").unwrap());
}

#[test]
fn dpop_required_grant_allows_when_valid_proof_provided() {
    let agent_kp = Keypair::generate();
    let server = "dpop-srv";
    let tool = "secure_op";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

    let arguments = serde_json::json!({"action": "read"});
    let proof = make_dpop_proof(&agent_kp, &cap, server, tool, &arguments, "nonce-abc-001");

    let request = ToolCallRequest {
        request_id: "req-dpop-allow".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments,
        dpop_proof: Some(proof),
                execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "valid DPoP proof should allow; reason: {:?}",
        response.reason
    );
}

#[test]
fn dpop_required_grant_denies_when_no_proof_provided() {
    let agent_kp = Keypair::generate();
    let server = "dpop-srv";
    let tool = "secure_op";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

    let request = ToolCallRequest {
        request_id: "req-dpop-deny-no-proof".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({"action": "read"}),
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "missing DPoP proof should deny"
    );
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("DPoP proof"),
        "denial reason should mention DPoP; got: {reason}"
    );
}

#[test]
fn dpop_required_grant_denies_when_proof_has_wrong_tool_name() {
    let agent_kp = Keypair::generate();
    let server = "dpop-srv";
    let tool = "secure_op";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

    let arguments = serde_json::json!({"action": "read"});
    // Proof claims wrong tool name -- binding check should fail.
    let proof = make_dpop_proof(
        &agent_kp,
        &cap,
        server,
        "other_tool",
        &arguments,
        "nonce-bad-001",
    );

    let request = ToolCallRequest {
        request_id: "req-dpop-deny-wrong-tool".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments,
        dpop_proof: Some(proof),
                execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "proof with wrong tool name should deny"
    );
}

#[test]
fn dpop_not_required_grant_allows_without_proof() {
    // Verify non-DPoP grants are unaffected.
    let mut kernel = make_kernel(make_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = make_request("req-no-dpop", &cap, "echo", "srv");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "non-DPoP grant should allow without proof"
    );
}

#[test]
fn kernel_error_report_includes_out_of_scope_context() {
    let report = KernelError::OutOfScope {
        tool: "read_file".to_string(),
        server: "fs".to_string(),
    }
    .report();

    assert_eq!(report.code, "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
    assert_eq!(report.context["tool"], "read_file");
    assert_eq!(report.context["server"], "fs");
    assert!(report
        .suggested_fix
        .contains("Issue a capability that grants this tool"));
}

#[test]
fn kernel_error_report_includes_request_cancel_context() {
    let report = KernelError::RequestCancelled {
        request_id: "req-123".to_string().into(),
        reason: "operator cancelled".to_string(),
    }
    .report();

    assert_eq!(report.code, "CHIO-KERNEL-REQUEST-CANCELLED");
    assert_eq!(report.context["request_id"], "req-123");
    assert_eq!(report.context["reason"], "operator cancelled");
    assert!(report.suggested_fix.contains("cancelled request ID"));
}
