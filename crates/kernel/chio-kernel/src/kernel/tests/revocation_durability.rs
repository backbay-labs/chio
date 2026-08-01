// The kernel denies at dispatch when the revocation store is ephemeral and the
// operator has not opted in, mirroring the receipt-persistence admission gate.

#[test]
fn in_memory_revocation_store_is_ephemeral_by_default() {
    let store = crate::InMemoryRevocationStore::new();
    assert!(crate::RevocationStore::is_ephemeral(&store));
}

#[test]
fn revocation_gate_denies_ephemeral_store_without_optin() {
    let mut config = make_config();
    config.allow_ephemeral_revocation_store = false;
    let kernel = make_kernel(config);
    // ChioKernel::new installs an in-memory (ephemeral) revocation store.
    assert!(kernel.ensure_revocation_durability_ready().is_err());
}

#[test]
fn revocation_gate_allows_ephemeral_store_with_optin() {
    let mut config = make_config();
    config.allow_ephemeral_revocation_store = true;
    let kernel = make_kernel(config);
    assert!(kernel.ensure_revocation_durability_ready().is_ok());
}

#[test]
fn revocation_gate_allows_an_installed_view_without_a_durable_store() {
    let mut config = make_config();
    // No ephemeral opt-in, and only the default in-memory per-row store.
    config.allow_ephemeral_revocation_store = false;
    let mut kernel = make_kernel(config);
    // A federation/oracle revocation view is a durable remote source consulted on
    // every delegated dispatch, so installing one satisfies the gate without also
    // wiring an otherwise-unused durable per-row store.
    kernel.set_revocation_view(std::sync::Arc::new(chio_kernel_core::RevocationView::new()));
    assert!(kernel.ensure_revocation_durability_ready().is_ok());
}

#[test]
fn poisoned_runtime_trace_lock_does_not_disable_revocation_or_admission() {
    let kernel = make_kernel(make_config());
    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("srv-a", "read_file")]),
        300,
    );
    let request = make_request(
        "runtime-trace-poison-recovery",
        &capability,
        "read_file",
        "srv-a",
    );
    let poison_transition_lock = || {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = kernel
                .runtime_trace_transition_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            panic!("inject runtime trace transition panic");
        }));
        assert!(panic.is_err());
        assert!(kernel.runtime_trace_transition_lock.is_poisoned());
    };

    poison_transition_lock();
    let receipt = make_signed_receipt(&kernel.config.keypair, "runtime-trace-poison-receipt");
    kernel
        .record_chio_receipt(&receipt)
        .expect("receipt persistence should recover a poisoned ordering lock");
    assert!(!kernel.runtime_trace_transition_lock.is_poisoned());
    assert!(kernel
        .receipt_log()
        .iter()
        .any(|persisted| persisted.id == receipt.id));

    poison_transition_lock();
    kernel
        .check_tool_call_revocation_admission(&request)
        .expect("admission should recover a poisoned ordering lock");
    assert!(!kernel.runtime_trace_transition_lock.is_poisoned());

    poison_transition_lock();
    kernel
        .revoke_capability(&capability.id)
        .expect("revocation should recover a poisoned ordering lock");
    assert!(!kernel.runtime_trace_transition_lock.is_poisoned());
    assert!(matches!(
        kernel.check_tool_call_revocation_admission(&request),
        Err(KernelError::CapabilityRevoked(id)) if id == capability.id
    ));
}
