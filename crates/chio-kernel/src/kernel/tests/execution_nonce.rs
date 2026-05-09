// Phase 1.1 execution-nonce integration tests.
//
// Included by `src/kernel/tests.rs`, which already imported `super::*`
// and all helper items from `tests/all.rs` (`make_config`, `make_scope`,
// `make_grant`, `make_keypair`, `make_capability`, `make_request`,
// `EchoServer`).
//
// The tests cover the six acceptance checks called out in the Phase 1.1
// plan:
//   (a) a fresh nonce on Allow verifies
//   (b) a stale nonce (>TTL) is rejected
//   (c) a replayed nonce is rejected
//   (d) mismatched binding is rejected
//   (e) tampered signature is rejected
//   (f) disabled mode lets tool calls through without a nonce (back-compat)

use crate::execution_nonce::{
    mint_execution_nonce, verify_execution_nonce, ExecutionNonceConfig, ExecutionNonceError,
    InMemoryExecutionNonceStore, NonceBinding,
};

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
    let request = make_request("req-legacy", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.execution_nonce.is_none(),
        "legacy deployments should carry no execution nonce"
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
        .require_presented_execution_nonce(&request, &cap, None)
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
    kernel.set_execution_nonce_store(strict_cfg, strict_store);

    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-strict-ok", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    let signed = response
        .execution_nonce
        .expect("allow must carry nonce in strict mode");

    kernel
        .require_presented_execution_nonce(&request, &cap, Some(&signed))
        .unwrap();
}

#[test]
fn kernel_ttl_enforces_30s_default() {
    // The roadmap's acceptance clause: a tool call presented >30s after
    // evaluation is rejected. The unit-level assertion lives here; we
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
