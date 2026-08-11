use super::*;

struct ToggleExactOutputGuard {
    live: std::sync::Arc<std::sync::atomic::AtomicBool>,
    calls: std::sync::Arc<AtomicU64>,
}

impl Guard for ToggleExactOutputGuard {
    fn name(&self) -> &str {
        "toggle-exact-output"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn validate_output_before_release(
        &self,
        _ctx: &GuardContext<'_>,
        output: &ToolServerOutput,
    ) -> Result<(), KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if !self.live.load(Ordering::SeqCst) {
            return Err(KernelError::GuardDenied(
                "durable output is no longer live".to_owned(),
            ));
        }
        if output
            != &ToolServerOutput::Value(serde_json::json!({"replacement": "filtered"}))
        {
            return Err(KernelError::GuardDenied(
                "durable output validation ran before the frozen transform".to_owned(),
            ));
        }
        Ok(())
    }

    fn requires_exact_released_output(&self, _ctx: &GuardContext<'_>) -> bool {
        true
    }
}

#[test]
fn durable_exact_output_guard_runs_after_transform_and_again_at_replay_release() {
    let (mut kernel, request, _store, invocations) =
        durable_admission_fixture("durable-exact-output-revalidation");
    let live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.add_guard(Box::new(ToggleExactOutputGuard {
        live: std::sync::Arc::clone(&live),
        calls: std::sync::Arc::clone(&calls),
    }));
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "filtered",
    }));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("post-transform output passes at initial release");
    assert_eq!(
        response.output,
        Some(ToolCallOutput::Value(
            serde_json::json!({"replacement": "filtered"})
        ))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    live.store(false, Ordering::SeqCst);
    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("completed replay must revalidate immediately before release");
    assert!(error.to_string().contains("no longer live"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn durable_server_url_elicitation_terminalizes_as_outcome_unknown() {
    let (mut kernel, request, store, _invocations) =
        durable_admission_fixture("durable-url-elicit");
    kernel.register_tool_server(Box::new(DurableUrlElicitationServer {
        store: store.clone(),
    }));

    let result = kernel.evaluate_tool_call_blocking(&request);
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "unexpected durable URL elicitation result: {result:?}"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(!kernel.receipt_log().receipts().is_empty());
}

#[cfg(feature = "cognition-market-experimental")]
#[test]
fn durable_server_url_elicitation_finalizes_the_pool_claim() {
    use crate::finding_pool::tests::RecordingLedger;
    use crate::finding_pool::FindingPoolLedger;

    let (mut kernel, request, store, _invocations) =
        durable_admission_fixture("durable-url-elicit-pool-release-crash");
    kernel.register_tool_server(Box::new(DurableUrlElicitationServer {
        store: store.clone(),
    }));
    kernel
        .set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))
        .expect("pool mutation receipt store");
    kernel
        .set_finding_pool_receipt_authority(Keypair::from_seed(&[93; 32]))
        .expect("pool mutation receipt authority");
    let ledger = std::sync::Arc::new(RecordingLedger::default());
    kernel
        .set_finding_pool_ledger(ledger.clone())
        .expect("qualified finding pool ledger");

    let error = kernel.evaluate_tool_call_blocking(&request);
    assert!(matches!(
        error,
        Err(KernelError::UrlElicitationsRequired { .. })
    ));
    let terminal = store.operation();
    assert_eq!(
        terminal.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(ledger
        .list_claimed_admission_operations(None, 10)
        .expect("read finalized pool claims")
        .is_empty());
    assert_eq!(
        ledger.unknown_dispatch_finalizations(),
        vec![terminal.binding().operation_id().as_str().to_owned()]
    );
}

#[cfg(feature = "cognition-market-experimental")]
#[test]
fn durable_startup_reconciliation_rejects_late_pool_ledger_installation() {
    use crate::finding_pool::tests::RecordingLedger;
    use crate::finding_pool::FindingPoolLedgerError;

    let (mut kernel, _request, _store, _invocations) =
        durable_admission_fixture("late-pool-ledger-installation");
    kernel
        .set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))
        .expect("pool mutation receipt store");
    kernel
        .set_finding_pool_receipt_authority(Keypair::from_seed(&[95; 32]))
        .expect("pool mutation receipt authority");
    kernel
        .reconcile_durable_admission_startup()
        .expect("complete startup reconciliation before pool configuration");

    let ledger = std::sync::Arc::new(RecordingLedger::default());
    assert_eq!(
        kernel.set_finding_pool_ledger(ledger.clone()),
        Err(FindingPoolLedgerError::StartupAlreadyReconciled)
    );
    assert_eq!(ledger.receipt_sink_id(), None);
}

#[cfg(feature = "cognition-market-experimental")]
#[test]
fn configured_pool_ledger_freezes_the_durable_admission_runtime() {
    use crate::admission_operation::AdmissionOperationError;
    use crate::finding_pool::tests::RecordingLedger;

    let (mut kernel, _request, store, _invocations) =
        durable_admission_fixture("pool-freezes-durable-admission-runtime");
    kernel
        .set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))
        .expect("pool mutation receipt store");
    kernel
        .set_finding_pool_receipt_authority(Keypair::from_seed(&[96; 32]))
        .expect("pool mutation receipt authority");
    kernel
        .set_finding_pool_ledger(std::sync::Arc::new(RecordingLedger::default()))
        .expect("qualified finding pool ledger");

    assert_eq!(
        kernel.set_durable_admission_store(
            store.clone(),
            store,
            admission_test_fence(),
        ),
        Err(AdmissionOperationError::FindingPoolLedgerAlreadyConfigured)
    );
}

#[cfg(feature = "cognition-market-experimental")]
#[test]
fn pool_ledger_allows_the_initial_durable_admission_runtime() {
    use crate::admission_operation::AdmissionOperationError;
    use crate::finding_pool::tests::RecordingLedger;

    let mut config = make_config();
    config.policy_hash = sha256_hex(b"pool-before-durable-runtime");
    let mut kernel = make_kernel(config);
    kernel
        .set_receipt_store(Box::new(AdmissionReceiptProjectionStore::default()))
        .expect("pool mutation receipt store");
    kernel
        .set_finding_pool_receipt_authority(Keypair::from_seed(&[97; 32]))
        .expect("pool mutation receipt authority");
    kernel
        .set_finding_pool_ledger(std::sync::Arc::new(RecordingLedger::default()))
        .expect("qualified finding pool ledger");
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("initial durable runtime after the pool ledger");
    assert_eq!(
        kernel.set_durable_admission_store(
            store.clone(),
            store,
            admission_test_fence(),
        ),
        Err(AdmissionOperationError::FindingPoolLedgerAlreadyConfigured)
    );
}

#[test]
fn nested_durable_url_elicitation_terminalizes_as_outcome_unknown() {
    let (mut kernel, request, store, _invocations) =
        durable_admission_fixture("nested-durable-url-elicit");
    kernel.register_tool_server(Box::new(DurableUrlElicitationServer {
        store: store.clone(),
    }));
    let session_id = kernel
        .open_session("nested-url-elicit-parent".to_owned(), Vec::new())
        .expect("parent session");
    kernel
        .activate_session(&session_id)
        .expect("activate parent session");
    let parent_context = make_operation_context(
        &session_id,
        "nested-url-elicit-parent-request",
        "nested-url-elicit-parent",
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .expect("begin parent request");
    let mut client = NoopNestedFlowClient;

    let result = kernel.evaluate_tool_call_with_nested_flow_client(
        &parent_context,
        &request,
        &mut client,
        None,
    );
    assert!(
        matches!(result, Err(KernelError::UrlElicitationsRequired { .. })),
        "unexpected nested durable URL elicitation result: {result:?}"
    );
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert!(!kernel.receipt_log().receipts().is_empty());
}

#[test]
fn durable_terminal_receipt_uses_the_admitted_tenant() {
    let request_id = "durable-tenant-receipt";
    let (kernel, request, store, invocations) = durable_admission_fixture(request_id);
    let session_id = kernel
        .open_session(
            request.capability.subject.to_hex(),
            vec![request.capability.clone()],
        )
        .expect("tenant session");
    kernel
        .set_session_auth_context(
            &session_id,
            oauth_auth_with_enterprise_tenant("tenant-durable"),
        )
        .expect("tenant authentication");
    kernel
        .activate_session(&session_id)
        .expect("active tenant session");
    let context = make_operation_context(
        &session_id,
        request_id,
        &request.capability.subject.to_hex(),
    );
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .expect("tenant request");

    let response = kernel
        .evaluate_tool_call_sync_with_session_context(&request, Some(&[]), None, Some(&session_id))
        .expect("tenant-scoped durable dispatch");
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "unexpected durable tenant denial: {:?}",
        response.reason
    );
    assert_eq!(
        response.receipt.tenant_id.as_deref(),
        Some("tenant-durable")
    );
    assert!(response.receipt.verify_signature().expect("signed receipt"));
    assert_eq!(
        store
            .operation()
            .binding()
            .to_persisted()
            .authenticated_tenant_id
            .as_str(),
        "tenant-durable"
    );

    let replay = kernel
        .evaluate_tool_call_sync_with_session_context(&request, Some(&[]), None, Some(&session_id))
        .expect("tenant-scoped durable replay");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.receipt.tenant_id.as_deref(), Some("tenant-durable"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    kernel
        .complete_session_request(&session_id, &context.request_id)
        .expect("complete tenant request");
}

#[test]
fn startup_recovery_rejects_a_changed_post_return_plan() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-startup-post-hook-change");
    kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "first",
    }));
    store.fail_next_evaluation_begin();
    kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("injected finalization crash");
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );

    // Recovery runs under a rotated store lease, exactly as a restarted process
    // takes over: the crashed operation's recovery lease belongs to the prior
    // owner, so the sweep sees it as recoverable rather than actively leased.
    let rotated_fence = StoreMutationFence {
        store_uuid: admission_test_fence().store_uuid,
        lease_id: "test-admission-lease-2".to_owned(),
        owner_epoch: 2,
    };
    store.rotate_fence(rotated_fence.clone());
    let mut recovered_config = make_config();
    recovered_config.keypair = kernel.config.keypair.clone();
    recovered_config.policy_hash = sha256_hex(b"durable-admission-test-policy");
    let mut recovered_kernel = make_kernel(recovered_config);
    recovered_kernel
        .set_durable_admission_store(store.clone(), store.clone(), rotated_fence)
        .expect("qualified admission store");
    recovered_kernel.add_post_invocation_hook(Box::new(StableRedactingPostInvocationHook {
        replacement: "second",
    }));

    let error = recovered_kernel
        .reconcile_recoverable_admissions()
        .expect_err("changed recovery plan must fail closed");
    assert!(error
        .to_string()
        .contains("recovered post-return plan does not match durable admission"));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn an_unrelated_cumulative_grant_does_not_withdraw_an_exempt_admission() {
    struct MixedEffectServer;

    #[async_trait::async_trait]
    impl ToolServerConnection for MixedEffectServer {
        fn server_id(&self) -> &str {
            "mixed-effect-server"
        }

        fn tool_names(&self) -> Vec<String> {
            vec![
                "lookup".to_owned(),
                "write".to_owned(),
                "escrow".to_owned(),
                "audit".to_owned(),
            ]
        }

        fn tool_is_read_only(&self, tool_name: &str) -> bool {
            tool_name == "lookup" || tool_name == "audit"
        }

        async fn invoke(
            &self,
            _tool_name: &str,
            _arguments: serde_json::Value,
            _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            Ok(serde_json::json!({"ok": true}))
        }
    }

    fn cumulative_grant(tool: &str, budget_id: &str) -> ToolGrant {
        let mut grant = make_grant("mixed-effect-server", tool);
        grant
            .constraints
            .push(Constraint::RequireCumulativeApprovalAbove {
                threshold: MonetaryAmount {
                    units: 100,
                    currency: "USD".to_owned(),
                },
                approval_budget_id: budget_id.to_owned(),
                approval_budget_epoch: 1,
                cumulative_approval_root_binding: None,
            });
        grant
    }

    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(MixedEffectServer));
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![
            make_grant("mixed-effect-server", "lookup"),
            make_grant("mixed-effect-server", "write"),
            cumulative_grant("escrow", "budget-escrow"),
            cumulative_grant("audit", "budget-audit"),
        ]),
        300,
    );

    let admission_is_exempt = |tool: &str| -> Result<bool, KernelError> {
        let request = make_request(
            &format!("durable-unrelated-cumulative-{tool}"),
            &capability,
            tool,
            "mixed-effect-server",
        );
        let matching = resolve_required_matching_grants(
            &capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .expect("matching grant");
        kernel
            .begin_durable_tool_admission(&request, &matching, current_unix_timestamp_ms())
            .map(|admission| admission.is_none())
    };

    // Neither exempt tool matches a cumulative grant, so the cumulative grants
    // elsewhere in the capability leave both admissions alone: the read-only tool
    // stays outside side-effecting coverage, and the side-effecting tool still
    // falls back to the ephemeral receipt log.
    assert!(admission_is_exempt("lookup").expect("read-only admission"));
    assert!(admission_is_exempt("write").expect("side-effecting admission"));

    // The tools whose own matching grant carries the constraint still demand the
    // durable path, on both the coverage and the store gate.
    let uncovered = admission_is_exempt("audit")
        .expect_err("cumulative read-only tool must not stay exempt");
    assert!(
        uncovered
            .to_string()
            .contains("requires durable admission coverage"),
        "unexpected coverage denial: {uncovered}"
    );
    let unstored =
        admission_is_exempt("escrow").expect_err("cumulative tool must require a durable store");
    assert!(
        unstored
            .to_string()
            .contains("no qualified admission operation store is configured"),
        "unexpected store denial: {unstored}"
    );
}

#[test]
fn a_missing_nested_session_root_compensates_the_durable_admission() {
    let (kernel, request, store, invocations) =
        durable_admission_fixture("durable-nested-missing-session-root");
    // A parent session that was never opened models one closed or evicted between
    // the durable admission and the roots lookup.
    let parent_context = make_operation_context(
        &SessionId::new("sess-durable-nested-missing-root"),
        "req-parent-durable-missing-root",
        &request.agent_id,
    );
    let mut client = NoopNestedFlowClient;

    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(&parent_context, &request, &mut client, None)
        .expect("missing session roots must fail closed as a deny, not propagate");

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("unknown session")),
        "deny must come from the session roots lookup, got {:?}",
        response.reason
    );
    // The operation must not be left registered against a dispatch that never ran.
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}
