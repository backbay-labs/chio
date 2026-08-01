use super::*;

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

    let response = kernel
        .evaluate_tool_call_sync_with_session_context(&request, None, None, Some(&session_id))
        .expect("tenant-scoped durable dispatch");
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
        .evaluate_tool_call_sync_with_session_context(&request, None, None, Some(&session_id))
        .expect("tenant-scoped durable replay");
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.receipt.tenant_id.as_deref(), Some("tenant-durable"));
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
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
