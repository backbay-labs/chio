// Execution-nonce integration tests.
//
// Included by `src/kernel/tests.rs`, which already imported `super::*`
// and all helper items from `tests/all.rs` (`make_config`, `make_scope`,
// `make_grant`, `make_keypair`, `make_capability`, `make_request`,
// `EchoServer`).
//
// The tests cover six behaviours:
//   (a) a fresh nonce on Allow verifies
//   (b) a stale nonce (>TTL) is rejected
//   (c) a replayed nonce is rejected
//   (d) mismatched binding is rejected
//   (e) tampered signature is rejected
//   (f) disabled mode lets tool calls through without a nonce (back-compat)

use crate::execution_nonce::{
    mint_execution_nonce, verify_execution_nonce, ExecutionNonceConfig, ExecutionNonceError,
    ExecutionNonceStore, InMemoryExecutionNonceStore, NonceBinding,
};

struct BlockingExecutionNonceStore {
    inner: InMemoryExecutionNonceStore,
    entered: std::sync::Arc<tokio::sync::Notify>,
    released: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mutable_state: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

struct DelayedReturnExecutionNonceStore {
    inner: InMemoryExecutionNonceStore,
    entered: std::sync::Arc<tokio::sync::Notify>,
    released: std::sync::Arc<std::sync::atomic::AtomicBool>,
    rollback_calls: std::sync::Arc<AtomicU64>,
}

struct ExecutionNonceReleaseGuard {
    released: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ExecutionNonceReleaseGuard {
    fn release(&self) {
        self.released.store(true, Ordering::Release);
    }
}

impl Drop for ExecutionNonceReleaseGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl ExecutionNonceStore for BlockingExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.reserve_until(nonce_id, i64::MAX)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.entered.notify_one();
        while !self.released.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        self.inner.reserve_until(nonce_id, nonce_expires_at)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.entered.notify_one();
        while !self.released.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        if let Some(mutable_state) = &self.mutable_state {
            mutable_state.store(true, Ordering::Release);
        }
        self.inner
            .reserve_for_dispatch(nonce_id, nonce_expires_at, reservation_id)
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.inner
            .rollback_dispatch_reservation(nonce_id, reservation_id)
    }
}

impl ExecutionNonceStore for DelayedReturnExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.inner.reserve(nonce_id)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.inner.reserve_until(nonce_id, nonce_expires_at)
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let reservation =
            self.inner
                .reserve_for_dispatch(nonce_id, nonce_expires_at, reservation_id);
        self.entered.notify_one();
        while !self.released.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(1));
        }
        reservation
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.rollback_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .rollback_dispatch_reservation(nonce_id, reservation_id)
    }
}

struct ReservationMutationGuard {
    mutable_state: std::sync::Arc<std::sync::atomic::AtomicBool>,
    revalidations: std::sync::Arc<AtomicU64>,
}

impl Guard for ReservationMutationGuard {
    fn name(&self) -> &str {
        "reservation-mutation-guard"
    }

    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn revalidate_before_dispatch(&self, _ctx: &GuardContext<'_>) -> Result<(), KernelError> {
        self.revalidations.fetch_add(1, Ordering::SeqCst);
        if self.mutable_state.load(Ordering::Acquire) {
            return Err(KernelError::GuardDenied(
                "credential reservation invalidated mutable guard state".to_string(),
            ));
        }
        Ok(())
    }
}

fn kernel_with_nonce() -> (ChioKernel, Keypair, ChioScope, ExecutionNonceConfig) {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));
    let cfg = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: false,
    };
    let store = Box::new(InMemoryExecutionNonceStore::from_config(&cfg));
    kernel.set_execution_nonce_store(cfg.clone(), store);
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    (kernel, agent_kp, scope, cfg)
}

fn binding_for_request(cap: &CapabilityToken, request: &ToolCallRequest) -> NonceBinding {
    let parameter_hash =
        chio_core::receipt::decision::ToolCallAction::from_parameters(request.arguments.clone())
            .unwrap()
            .parameter_hash;
    NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash,
    }
}

fn mint_nonce_for_request(
    kernel: &ChioKernel,
    cap: &CapabilityToken,
    request: &ToolCallRequest,
    cfg: &ExecutionNonceConfig,
) -> crate::execution_nonce::SignedExecutionNonce {
    let now = i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX);
    mint_execution_nonce(
        &kernel.config.keypair,
        binding_for_request(cap, request),
        cfg,
        now,
    )
    .unwrap()
}

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

    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };
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
    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };

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
    let expected = NonceBinding {
        subject_id: cap.subject.to_hex(),
        capability_id: cap.id.clone(),
        tool_server: request.server_id.clone(),
        tool_name: "write_file".to_string(),
        parameter_hash: response.receipt.action.parameter_hash.clone(),
    };
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_nonce_reservation_rolls_back_when_session_dispatch_claim_fails(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_guard = ExecutionNonceReleaseGuard {
        released: std::sync::Arc::clone(&released),
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(BlockingExecutionNonceStore {
            inner: InMemoryExecutionNonceStore::from_config(&config),
            entered: std::sync::Arc::clone(&entered),
            released: std::sync::Arc::clone(&released),
            mutable_state: None,
        }),
    );

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request_id = "req-nonce-dispatch-claim";
    let request = make_request(request_id, &capability, "read_file", "srv-a");
    let binding = binding_for_request(&capability, &request);
    let nonce = mint_nonce_for_request(&kernel, &capability, &request, &config);
    let session_id =
        kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()])?;
    kernel.activate_session(&session_id)?;
    let context = make_operation_context(&session_id, request_id, &agent_kp.public_key().to_hex());
    let operation = ToolCallOperation {
        capability,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: request.arguments,
        governed_intent: None,
        execution_nonce: Some(serde_json::to_value(&nonce)?),
        model_metadata: None,
        extra_metadata: None,
    };
    let kernel = std::sync::Arc::new(kernel);
    let evaluation_kernel = std::sync::Arc::clone(&kernel);
    let evaluation = tokio::spawn(async move {
        let mut client = NoopNestedFlowClient;
        evaluation_kernel
            .evaluate_tool_call_operation_with_nested_flow_client_async(
                &context,
                &operation,
                &mut client,
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
    let cancellation =
        kernel.request_session_cancellation(&session_id, &RequestId::from(request_id));
    release_guard.release();

    let response = tokio::time::timeout(Duration::from_secs(5), evaluation).await???;
    assert!(cancellation.is_ok());
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    kernel.verify_presented_execution_nonce(&nonce, &binding)?;
    assert!(kernel
        .session(&session_id)
        .is_some_and(|session| session.inflight().is_empty()));
    assert!(matches!(
        kernel.request_session_cancellation(&session_id, &RequestId::from(request_id)),
        Err(KernelError::Session(
            SessionError::RequestNotInflight { .. }
        ))
    ));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_nonce_expiring_during_reservation_is_denied_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 1,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let released = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_guard = ExecutionNonceReleaseGuard {
        released: std::sync::Arc::clone(&released),
    };
    let rollback_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(DelayedReturnExecutionNonceStore {
            inner: InMemoryExecutionNonceStore::from_config(&config),
            entered: std::sync::Arc::clone(&entered),
            released,
            rollback_calls: std::sync::Arc::clone(&rollback_calls),
        }),
    );

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let mut request = make_request(
        "req-nonce-expires-during-reservation",
        &capability,
        "read_file",
        "srv-a",
    );
    let nonce = mint_nonce_for_request(&kernel, &capability, &request, &config);
    let expires_at = nonce.expires_at();
    request.execution_nonce = Some(nonce);
    let kernel = std::sync::Arc::new(kernel);
    let evaluation_kernel = std::sync::Arc::clone(&kernel);
    let evaluation =
        tokio::spawn(async move { evaluation_kernel.evaluate_tool_call(&request).await });

    tokio::time::timeout(Duration::from_secs(5), entered.notified()).await?;
    while i64::try_from(current_unix_timestamp()).unwrap_or(i64::MAX) < expires_at {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    release_guard.release();

    let response = tokio::time::timeout(Duration::from_secs(5), evaluation).await???;
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("execution nonce expired")));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(rollback_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execution_nonce_reservation_mutation_is_revalidated_before_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-a",
        vec!["read_file"],
        std::sync::Arc::clone(&invocations),
    )));
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let mutable_state = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let revalidations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(BlockingExecutionNonceStore {
            inner: InMemoryExecutionNonceStore::from_config(&config),
            entered: std::sync::Arc::new(tokio::sync::Notify::new()),
            released: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            mutable_state: Some(std::sync::Arc::clone(&mutable_state)),
        }),
    );
    kernel.add_guard(Box::new(ReservationMutationGuard {
        mutable_state,
        revalidations: std::sync::Arc::clone(&revalidations),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let mut request = make_request(
        "req-nonce-reservation-mutation",
        &capability,
        "read_file",
        "srv-a",
    );
    let binding = binding_for_request(&capability, &request);
    let nonce = mint_nonce_for_request(&kernel, &capability, &request, &config);
    request.execution_nonce = Some(nonce.clone());

    let response = kernel.evaluate_tool_call(&request).await?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(
        |reason| reason.contains("credential reservation invalidated mutable guard state")
    ));
    assert_eq!(revalidations.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    kernel.verify_presented_execution_nonce(&nonce, &binding)?;
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
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
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

    let replay = kernel
        .evaluate_tool_call_blocking(&execution_request)
        .unwrap();
    assert_eq!(replay.verdict, Verdict::Deny);
    assert!(
        replay
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("execution nonce")),
        "expected replay denial, got: {:?}",
        replay.reason
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
}

#[test]
fn strict_nonce_mode_payment_denial_does_not_consume_nonce() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = make_kernel(make_monetary_config());
    kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter)).expect("install payment adapter");
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

    kernel.set_payment_adapter(Box::new(StubPaymentAdapter)).expect("install payment adapter");
    request.request_id = "req-nonce-payment-allow".to_string();
    let allowed = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(allowed.verdict, Verdict::Allow);
    assert_eq!(invocations.load(std::sync::atomic::Ordering::SeqCst), 1);
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
