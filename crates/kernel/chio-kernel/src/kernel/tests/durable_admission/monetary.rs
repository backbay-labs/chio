use super::*;

#[test]
fn budget_backend_error_compensates_durable_admission_before_dispatch() {
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_invocations = Some(1);
    let (kernel, request, store, invocations) = durable_admission_fixture_with_grants(
        "durable-budget-authorization-error",
        vec![grant],
    );
    store.fail_next_budget_authorization();

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("budget backend failure should produce a deny receipt");

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("authorization backend unavailable")));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn durable_monetary_guard_denial_closes_unstarted_payment() {
    struct DenyAll;

    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "durable-monetary-deny-all"
        }

        fn evaluate(&self, _context: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
            Ok(GuardDecision::deny(Vec::new()))
        }
    }

    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-monetary-guard-denial-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    let authorization_references = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references: authorization_references.clone(),
        settlement_actions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    }));
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    kernel.add_guard(Box::new(DenyAll));
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let request = make_request(
        "durable-monetary-guard-denial",
        &capability,
        "mutate",
        "durable-server",
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("terminal durable monetary guard denial");

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(store.payment_journal().is_none());
    assert!(authorization_references
        .lock()
        .expect("authorization references")
        .is_empty());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn unsupported_durable_participants_fail_before_dispatch() {
    let (mut kernel, request, store, invocations) =
        durable_admission_fixture("durable-versionless-post-hook");
    kernel.add_post_invocation_hook(Box::new(VersionlessPostInvocationHook));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("versionless post hook denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("has no durable implementation identity")));
    assert!(!store.has_operation());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    let mut monetary_grant = make_grant("durable-server", "mutate");
    monetary_grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    monetary_grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let (kernel, request, store, invocations) =
        durable_admission_fixture_with_grants("durable-unqualified-payment", vec![monetary_grant]);

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("unqualified payment denial");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("qualified payment adapter")));
    assert!(!store.has_operation());
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

#[test]
fn free_matching_grant_does_not_inherit_paid_grant_requirements() {
    let mut paid = make_grant("durable-server", "mutate");
    paid.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    paid.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let free = make_grant("durable-server", "mutate");
    let (kernel, request, store, invocations) = durable_admission_fixture_with_grants(
        "durable-free-grant-fallback",
        vec![paid, free],
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("free fallback dispatch");

    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(!store.operation().binding().participant_requirements().payment);
    assert!(store
        .operation()
        .budget_hold_id()
        .expect("bound budget hold")
        .as_str()
        .ends_with(":1"));
}

// The pre-execution hold debits the per-invocation ceiling, so a grant declaring
// only a cumulative ceiling can fund no hold at all. Selection must pass over it
// and bind a grant that can, rather than binding the unusable one and failing the
// whole dispatch on a zero-amount payment journal.
#[test]
fn durable_monetary_selection_skips_a_cumulative_only_grant() {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-cumulative-only-selection-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        settlement_actions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    }));
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let mut total_only = make_grant("durable-server", "mutate");
    total_only.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let mut per_call = make_grant("durable-server", "mutate");
    per_call.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    per_call.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![total_only, per_call]), 300);
    let request = make_request(
        "durable-cumulative-only-selection",
        &capability,
        "mutate",
        "durable-server",
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("per-invocation fallback durable dispatch");

    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(store
        .operation()
        .budget_hold_id()
        .expect("bound budget hold")
        .as_str()
        .ends_with(":1"));
}

#[test]
fn durable_monetary_lifecycle_uses_the_qualified_projection_store() {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-monetary-authorization-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    // Durable monetary state is owned by the qualified projection store. A
    // detached legacy store must never be consulted by this lifecycle.
    kernel.set_budget_store_handle(std::sync::Arc::new(
        crate::budget_store::InMemoryBudgetStore::new(),
    ));
    let authorization_references = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let settlement_actions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references: authorization_references.clone(),
        settlement_actions,
    }));
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let request = make_request(
        "durable-monetary-authorization",
        &capability,
        "mutate",
        "durable-server",
    );
    let matching = resolve_required_matching_grants(
        &capability,
        &request.tool_name,
        &request.server_id,
        &request.arguments,
        request.model_metadata.as_ref(),
    )
    .expect("matching grants");
    let now = current_unix_timestamp_ms();
    let mut admission = kernel
        .begin_durable_tool_admission(&request, &matching, now)
        .expect("durable monetary admission")
        .expect("covered durable admission");

    let (_, mutation) = kernel
        .check_and_increment_budget(
            &request,
            &capability,
            &matching,
            false,
            Some(&mut admission),
            now,
        )
        .expect("combined budget authorization")
        .into_authorized()
        .expect("authorized budget outcome");

    assert!(mutation.durable_hold_result().is_some());
    assert_eq!(admission.state(), AdmissionOperationState::BudgetAuthorized);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::BudgetAuthorized
    );
    let journal = store.payment_journal().expect("durable payment journal");
    assert_eq!(journal.state, PaymentJournalState::HoldPlaced);
    assert_eq!(journal.amount_units, 10);
    assert_eq!(journal.rail, "test-reversible");

    let authorization = kernel
        .authorize_payment_if_needed(
            &request,
            mutation.charge_result(),
            Some(&admission),
            now + 1,
            None,
        )
        .expect("durable payment authorization")
        .expect("payment authorization");
    assert_eq!(authorization.authorization_id, "authorization-durable");
    let authorized_journal = store.payment_journal().expect("authorized payment journal");
    assert_eq!(authorized_journal.state, PaymentJournalState::Authorized);
    assert_eq!(authorized_journal.journal_version, 2);
    assert_eq!(
        authorization_references
            .lock()
            .expect("authorization references")
            .as_slice(),
        [admission.operation_id()]
    );

    let replayed_authorization = kernel
        .authorize_payment_if_needed(
            &request,
            mutation.charge_result(),
            Some(&admission),
            now + 2,
            None,
        )
        .expect("replay durable payment authorization")
        .expect("replayed payment authorization");
    assert_eq!(
        replayed_authorization.authorization_id,
        authorization.authorization_id
    );
    assert_eq!(store.payment_journal(), Some(authorized_journal.clone()));
    assert_eq!(
        authorization_references
            .lock()
            .expect("authorization references")
            .len(),
        1
    );

    let mut resumed = kernel
        .begin_durable_tool_admission(&request, &matching, now + 3)
        .expect("resume durable monetary admission")
        .expect("covered resumed admission");
    let (_, replayed_mutation) = kernel
        .check_and_increment_budget(
            &request,
            &capability,
            &matching,
            false,
            Some(&mut resumed),
            now + 3,
        )
        .expect("replay combined budget authorization")
        .into_authorized()
        .expect("authorized replay outcome");

    assert!(replayed_mutation.durable_hold_result().is_some());
    assert_eq!(resumed.operation(), admission.operation());
    assert_eq!(store.payment_journal(), Some(authorized_journal));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("complete durable monetary dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let settled = store.payment_journal().expect("settled payment journal");
    assert_eq!(settled.state, PaymentJournalState::Settled);
    assert_eq!(settled.settle_action, Some(PaymentSettleAction::Capture));
    assert_eq!(settled.settle_amount_units, Some(10));
    assert_eq!(
        settled.transaction_id.as_deref(),
        Some("authorization-durable")
    );
    assert!(response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .is_some());
}

#[test]
fn durable_recovery_captures_after_tool_return_and_never_releases_from_authorized() {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-payment-crash-window-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    let settlement_actions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        settlement_actions: settlement_actions.clone(),
    }));
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_owned(),
        tools: vec!["mutate".to_owned()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let mut grant = make_grant("durable-server", "mutate");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let request = make_request(
        "durable-payment-crash-window",
        &capability,
        "mutate",
        "durable-server",
    );
    store.fail_next_payment_settlement_intent();

    let error = kernel
        .evaluate_tool_call_blocking(&request)
        .expect_err("settlement intent crash must fail closed");
    assert!(matches!(
        error,
        KernelError::DurableAdmission(ref reason)
            if reason.contains("injected payment settlement intent failure")
    ));
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Finalizing
    );
    assert_eq!(
        store.payment_journal().map(|journal| journal.state),
        Some(PaymentJournalState::Authorized)
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(settlement_actions
        .lock()
        .expect("settlement actions")
        .is_empty());

    let replay = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("recover captured payment from durable outcome");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        settlement_actions
            .lock()
            .expect("settlement actions")
            .as_slice(),
        ["capture"]
    );
    let journal = store.payment_journal().expect("settled recovery journal");
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_action, Some(PaymentSettleAction::Capture));
}

#[test]
fn durable_zero_charge_commits_release_evidence_before_releasing_payment() {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-zero-charge-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    let authorization_references = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    kernel.set_payment_adapter(Box::new(QualifiedDurablePaymentAdapter {
        authorization_references,
        settlement_actions: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    }));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "durable-zero-server",
        0,
        "USD",
    )));
    let mut grant = make_grant("durable-zero-server", "compute");
    grant.max_cost_per_invocation = Some(MonetaryAmount {
        units: 10,
        currency: "USD".to_owned(),
    });
    grant.max_total_cost = Some(MonetaryAmount {
        units: 100,
        currency: "USD".to_owned(),
    });
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![grant]), 300);
    let request = make_request(
        "durable-zero-charge",
        &capability,
        "compute",
        "durable-zero-server",
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("complete zero-charge durable dispatch");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    let journal = store.payment_journal().expect("released payment journal");
    assert_eq!(journal.state, PaymentJournalState::Settled);
    assert_eq!(journal.settle_action, Some(PaymentSettleAction::Release));
    assert_eq!(journal.settle_amount_units, None);
    assert_eq!(
        journal
            .release_authority
            .as_ref()
            .map(|authority| authority.kind),
        Some(PaymentReleaseAuthorityKind::ContractualZeroCharge)
    );
    let evidence = store
        .payment_release_evidence()
        .expect("canonical payment release evidence");
    assert_eq!(
        evidence.evidence_kind,
        crate::tool_outcome::MonetaryReleaseEvidenceKindV1::ContractualZeroCharge
    );
    assert_eq!(evidence.operation_id.as_str(), journal.operation_id);
    assert_eq!(
        response
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("financial"))
            .and_then(|financial| financial.get("cost_charged"))
            .and_then(serde_json::Value::as_u64),
        Some(0)
    );
}

#[test]
fn durable_admission_binds_the_first_budget_eligible_matching_grant() {
    let mut config = make_config();
    config.policy_hash = sha256_hex(b"durable-admission-grant-test-policy");
    let mut kernel = make_kernel(config);
    let fence = admission_test_fence();
    let store = std::sync::Arc::new(TestAdmissionOperationStore::new(fence.clone()));
    kernel
        .set_durable_admission_store(store.clone(), store.clone(), fence)
        .expect("qualified admission store");
    kernel.set_budget_store_handle(store.budget_store());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(DurableAdmissionCheckingServer {
        id: "durable-server".to_string(),
        tools: vec!["mutate".to_string()],
        invocations: invocations.clone(),
        store: store.clone(),
    }));
    let mut exhausted = make_grant("durable-server", "mutate");
    exhausted.max_invocations = Some(1);
    let fallback = make_grant("durable-server", "mutate");
    let agent = make_keypair();
    let capability = make_capability(&kernel, &agent, make_scope(vec![exhausted, fallback]), 300);
    assert!(kernel
        .with_budget_store(|budget| Ok(budget.try_increment(&capability.id, 0, Some(1))?))
        .expect("exhaust first matching grant"));
    let request = make_request(
        "durable-grant-fallback",
        &capability,
        "mutate",
        "durable-server",
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("fallback grant dispatch");

    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert!(store
        .operation()
        .budget_hold_id()
        .expect("bound budget hold")
        .as_str()
        .ends_with(":1"));
}

#[test]
fn nested_durable_admission_commits_before_dispatch_and_blocks_replay() {
    let (kernel, request, store, invocations) = durable_admission_fixture("durable-nested");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("nested test runtime");

    let evaluate = |request: &ToolCallRequest| {
        let session_id = kernel
            .open_session(request.agent_id.clone(), vec![request.capability.clone()])
            .expect("nested test session");
        kernel
            .activate_session(&session_id)
            .expect("active session");
        let context = make_operation_context(&session_id, &request.request_id, &request.agent_id);
        kernel
            .begin_session_request(&context, OperationKind::ToolCall, true)
            .expect("active nested request");
        runtime.block_on(async {
            let mut client = NoopNestedFlowClient;
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    request,
                    &mut client,
                    None,
                )
                .await
        })
    };

    let response = evaluate(&request).expect("first nested durable dispatch");
    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        store.operation().state(),
        AdmissionOperationState::Completed
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);

    let replay = evaluate(&request).expect("nested replay delivery");
    assert_eq!(replay.verdict, Verdict::Allow);
    assert_eq!(replay.receipt.id, response.receipt.id);
    assert_eq!(replay.output, response.output);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}
