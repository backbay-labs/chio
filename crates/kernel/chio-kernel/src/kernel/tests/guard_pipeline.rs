#[test]
fn guard_denies_request() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["dangerous"])));

    struct DenyAll;
    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "deny-all"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }
    kernel.add_guard(Box::new(DenyAll));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "dangerous")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "dangerous", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("deny-all"), "reason was: {reason}");
}

#[test]
fn allowing_guard_evidence_is_signed_into_success_receipt() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    struct EvidenceGuard;
    impl Guard for EvidenceGuard {
        fn name(&self) -> &str {
            "evidence-allow"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow_with_evidence(vec![GuardEvidence {
                guard_name: "evidence-allow".to_string(),
                verdict: true,
                details: Some("pre-invocation guard observed read request".to_string()),
            }]))
        }
    }
    kernel.add_guard(Box::new(EvidenceGuard));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-evidence", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "unexpected deny reason: {:?}",
        response.reason
    );
    assert_eq!(response.receipt.evidence.len(), 1);
    assert_eq!(response.receipt.evidence[0].guard_name, "evidence-allow");
    assert!(response.receipt.evidence[0].verdict);
    assert_eq!(
        response.receipt.evidence[0].details.as_deref(),
        Some("pre-invocation guard observed read request")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_allowing_guard_evidence_is_signed_into_success_receipt() {
    struct YieldingServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for YieldingServer {
        fn server_id(&self) -> &str {
            "srv-a"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["read_file".to_string()]
        }

        async fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            tokio::task::yield_now().await;
            Ok(serde_json::json!({
                "tool": tool_name,
                "echo": arguments,
            }))
        }
    }

    struct EvidenceGuard;
    impl Guard for EvidenceGuard {
        fn name(&self) -> &str {
            "async-evidence-allow"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow_with_evidence(vec![GuardEvidence {
                guard_name: "async-evidence-allow".to_string(),
                verdict: true,
                details: Some("pre-invocation evidence survived async dispatch".to_string()),
            }]))
        }
    }

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(YieldingServer));
    kernel.add_guard(Box::new(EvidenceGuard));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-async-evidence", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call(&request).await.unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(response.receipt.evidence.len(), 1);
    assert_eq!(
        response.receipt.evidence[0].guard_name,
        "async-evidence-allow"
    );
}

#[test]
fn denying_guard_evidence_is_signed_into_deny_receipt() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["dangerous"])));

    struct EvidenceDenyGuard;
    impl Guard for EvidenceDenyGuard {
        fn name(&self) -> &str {
            "evidence-deny"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(vec![GuardEvidence {
                guard_name: "evidence-deny".to_string(),
                verdict: false,
                details: Some("pre-invocation guard denied dangerous request".to_string()),
            }]))
        }
    }
    kernel.add_guard(Box::new(EvidenceDenyGuard));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "dangerous")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-deny-evidence", &cap, "dangerous", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.receipt.evidence.len(), 1);
    assert_eq!(response.receipt.evidence[0].guard_name, "evidence-deny");
    assert!(!response.receipt.evidence[0].verdict);
}

#[test]
fn unlimited_grant_guard_denial_does_not_reverse_budget_store() {
    struct NoopUnlimitedBudgetStore {
        inner: InMemoryBudgetStore,
        reverse_calls: std::sync::atomic::AtomicUsize,
    }

    impl NoopUnlimitedBudgetStore {
        fn new() -> Self {
            Self {
                inner: InMemoryBudgetStore::new(),
                reverse_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl BudgetStore for NoopUnlimitedBudgetStore {
        fn try_increment(
            &self,
            capability_id: &str,
            grant_index: usize,
            max_invocations: Option<u32>,
        ) -> Result<bool, BudgetStoreError> {
            if max_invocations.is_none() {
                return Ok(true);
            }
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
            self.reverse_calls.fetch_add(1, Ordering::SeqCst);
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

        fn reverse_charge_cost_with_ids_and_authority(
            &self,
            capability_id: &str,
            grant_index: usize,
            cost_units: u64,
            hold_id: Option<&str>,
            event_id: Option<&str>,
            authority: Option<&crate::budget_store::BudgetEventAuthority>,
        ) -> Result<(), BudgetStoreError> {
            self.inner.reverse_charge_cost_with_ids_and_authority(
                capability_id,
                grant_index,
                cost_units,
                hold_id,
                event_id,
                authority,
            )
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
    }

    let mut kernel = make_kernel(make_config());
    let budget_store = std::sync::Arc::new(NoopUnlimitedBudgetStore::new());
    kernel.set_budget_store_handle(budget_store.clone());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["dangerous"])));

    struct DenyAll;
    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "deny-all"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }
    kernel.add_guard(Box::new(DenyAll));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "dangerous")]),
        300,
    );
    let request = make_request("req-unlimited-deny", &cap, "dangerous", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("deny-all"), "reason was: {reason}");
    assert_eq!(budget_store.reverse_calls.load(Ordering::SeqCst), 0);
    assert!(budget_store.get_usage(&cap.id, 0).unwrap().is_none());
}

#[test]
fn guard_error_treated_as_deny() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["tool"])));

    struct BrokenGuard;
    impl Guard for BrokenGuard {
        fn name(&self) -> &str {
            "broken"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Err(KernelError::Internal("guard crashed".to_string()))
        }
    }
    kernel.add_guard(Box::new(BrokenGuard));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "tool")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "tool", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("fail-closed"), "reason was: {reason}");
}

#[test]
fn kernel_guard_registration() {
    let mut kernel = make_kernel(make_config());
    assert_eq!(kernel.guard_count(), 0);
    assert_eq!(kernel.ca_count(), 0);

    struct TestGuard;
    impl Guard for TestGuard {
        fn name(&self) -> &str {
            "test-guard"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::allow())
        }
    }

    kernel.add_guard(Box::new(TestGuard));
    assert_eq!(kernel.guard_count(), 1);
}

#[test]
fn matched_grant_index_populated_in_guard_context() {
    // A guard that records the matched_grant_index from its context.
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct IndexCapturingGuard {
        captured: Arc<Mutex<Option<usize>>>,
    }

    impl Guard for IndexCapturingGuard {
        fn name(&self) -> &str {
            "index-capture"
        }

        fn evaluate(&self, ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            let mut lock = self.captured.lock().unwrap();
            *lock = ctx.matched_grant_index;
            Ok(GuardDecision::allow())
        }
    }

    let captured = Arc::new(Mutex::new(None::<usize>));
    let guard = IndexCapturingGuard {
        captured: captured.clone(),
    };

    let mut kernel = make_kernel(make_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["tool1", "tool2"])));
    kernel.add_guard(Box::new(guard));

    // Two grants; first matches "tool1", second matches "tool2".
    let grant0 = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool1".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let grant1 = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool2".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![grant0, grant1]),
            3600,
        )
        .unwrap();

    // Request tool2 -- matched grant should be at index 1.
    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap.clone(),
            tool_name: "tool2".to_string(),
            server_id: "srv".to_string(),
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
        })
        .unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);

    let idx = *captured.lock().unwrap();
    assert_eq!(
        idx,
        Some(1),
        "guard should see matched_grant_index=Some(1) for tool2 (second grant)"
    );
}

#[test]
fn velocity_guard_denial_produces_signed_deny_receipt_no_panic() {
    // Simulate a velocity-style guard with a simple counter that denies
    // after N invocations. This tests the kernel's handling of guard denials
    // (producing a signed deny receipt without panic) without importing chio-guards.
    use std::sync::{Arc, Mutex};

    struct CountingRateLimitGuard {
        count: Arc<Mutex<u32>>,
        max: u32,
    }

    impl Guard for CountingRateLimitGuard {
        fn name(&self) -> &str {
            "counting-rate-limit"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
            let mut count = self.count.lock().unwrap();
            *count += 1;
            if *count > self.max {
                Ok(GuardDecision::deny(Vec::new()))
            } else {
                Ok(GuardDecision::allow())
            }
        }
    }

    let counter = Arc::new(Mutex::new(0u32));
    let guard = CountingRateLimitGuard {
        count: counter.clone(),
        max: 2,
    };

    let mut kernel = make_kernel(make_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    kernel.add_guard(Box::new(guard));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let make_req = |id: &str| ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
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

    // First two invocations allowed.
    let r1 = kernel
        .evaluate_tool_call_blocking(&make_req("req-1"))
        .unwrap();
    assert_eq!(r1.verdict, Verdict::Allow);
    let r2 = kernel
        .evaluate_tool_call_blocking(&make_req("req-2"))
        .unwrap();
    assert_eq!(r2.verdict, Verdict::Allow);

    // Third invocation should be denied by the counting guard.
    let r3 = kernel
        .evaluate_tool_call_blocking(&make_req("req-3"))
        .unwrap();
    assert_eq!(
        r3.verdict,
        Verdict::Deny,
        "counting guard should deny 3rd invocation"
    );
    // Verify it's a properly signed deny receipt (not a panic/unwrap).
    assert_content_addressed_receipt_id(&r3.receipt.id);
    assert!(r3.reason.is_some(), "denial should have a reason");
}

#[test]
fn sync_bridge_current_thread_diagnostic_only_advertises_multithread_runtime() {
    let report = KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime.report();

    assert_eq!(report.code, "CHIO-KERNEL-SYNC-BRIDGE-INCOMPATIBLE");
    assert!(report.message.contains("multi-thread Tokio runtime"));
    assert!(!report.message.contains("evaluate_tool_call"));
    assert!(report.suggested_fix.contains("multi-thread Tokio runtime"));
    assert!(!report.suggested_fix.contains("API directly"));
}

#[test]
fn async_evaluate_current_thread_runtime_bypasses_sync_bridge() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut kernel = make_kernel(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
        let cap = kernel
            .issue_capability(
                &agent_kp.public_key(),
                make_scope(vec![make_grant("srv", "echo")]),
                3600,
            )
            .unwrap();
        let request = make_request("req-async-current-thread", &cap, "echo", "srv");

        let response = kernel.evaluate_tool_call(&request).await.unwrap();

        assert_eq!(response.verdict, Verdict::Allow);
        assert_eq!(kernel.receipt_log().len(), 1);
    });
}

#[test]
fn blocking_evaluate_current_thread_runtime_fails_before_receipt_side_effects() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut kernel = make_kernel(make_config());
        let agent_kp = Keypair::generate();
        kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
        let cap = kernel
            .issue_capability(
                &agent_kp.public_key(),
                make_scope(vec![make_grant("srv", "echo")]),
                3600,
            )
            .unwrap();
        let request = make_request("req-blocking-current-thread", &cap, "echo", "srv");

        let error = kernel.evaluate_tool_call_blocking(&request).unwrap_err();

        assert!(matches!(
            error,
            KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime
        ));
        assert_eq!(kernel.receipt_log().len(), 0);
    });
}

#[test]
fn async_tool_server_event_drain_current_thread_preserves_events() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut kernel = make_kernel(make_config());
        kernel.register_tool_server(Box::new(EventDrainServer::new(
            "events",
            vec![ToolServerEvent::ResourcesListChanged],
        )));

        let events = kernel.drain_tool_server_events_async().await.unwrap();

        assert_eq!(events, vec![ToolServerEvent::ResourcesListChanged]);
    });
}

#[test]
fn async_tool_server_event_drain_preserves_partial_events_after_error() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut kernel = ChioKernel::new(make_config());
        kernel.register_tool_server(Box::new(EventDrainServer::new(
            "events",
            vec![ToolServerEvent::ResourcesListChanged],
        )));
        kernel.register_tool_server(Box::new(FailingEventDrainServer::new("fails")));

        let events = kernel.drain_tool_server_events_async().await.unwrap();

        assert_eq!(events, vec![ToolServerEvent::ResourcesListChanged]);
    });
}

#[test]
fn sync_tool_server_event_queue_current_thread_returns_error_not_empty_success() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let mut kernel = make_kernel(make_config());
        kernel.register_tool_server(Box::new(EventDrainServer::new(
            "events",
            vec![ToolServerEvent::ResourcesListChanged],
        )));
        let session_id = kernel
            .open_session("agent".to_string(), Vec::new())
            .unwrap();
        kernel.activate_session(&session_id).unwrap();

        let error = kernel
            .queue_session_tool_server_events(&session_id)
            .unwrap_err();

        assert!(matches!(
            error,
            KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime
        ));
        assert!(kernel
            .drain_session_late_events(&session_id)
            .unwrap()
            .is_empty());
    });
}
