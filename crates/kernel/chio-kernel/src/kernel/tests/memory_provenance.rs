// Memory-provenance tests.
//
// Included by `src/kernel/tests.rs`. Shares helper items from
// `tests/all.rs` via the surrounding `tests.rs` `include!`s
// (`make_config`, `make_keypair`, `make_scope`, `make_grant`,
// `make_capability`, `EchoServer`, etc.).
//
// Coverage:
//   * governed writes append provenance entries,
//   * governed reads surface provenance metadata on the receipt,
//   * reads of entries with no provenance are flagged as unverified,
//   * hash-chain tamper is detected by verify_entry.
//
// `std::sync::Arc` is already brought into scope by the sibling
// `tests/emergency.rs` include.

fn install_provenance_store(
    kernel: &mut ChioKernel,
) -> Arc<crate::memory_provenance::InMemoryMemoryProvenanceStore> {
    let store = Arc::new(crate::memory_provenance::InMemoryMemoryProvenanceStore::new());
    kernel.set_memory_provenance_store(
        store.clone() as Arc<dyn crate::memory_provenance::MemoryProvenanceStore>,
    );
    store
}

fn kernel_with_memory_tools() -> (
    ChioKernel,
    Keypair,
    ChioScope,
    Arc<crate::memory_provenance::InMemoryMemoryProvenanceStore>,
) {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-mem",
        vec!["memory_write", "memory_read"],
    )));
    let store = install_provenance_store(&mut kernel);
    let agent_kp = make_keypair();
    let scope = make_scope(vec![
        make_grant("srv-mem", "memory_write"),
        make_grant("srv-mem", "memory_read"),
    ]);
    (kernel, agent_kp, scope, store)
}

fn memory_write_request(request_id: &str, cap: &CapabilityToken, key: &str) -> ToolCallRequest {
    make_request_with_arguments(
        request_id,
        cap,
        "memory_write",
        "srv-mem",
        serde_json::json!({
            "collection": "agent-context",
            "id": key,
            "content": "important context",
        }),
    )
}

fn memory_read_request(request_id: &str, cap: &CapabilityToken, key: &str) -> ToolCallRequest {
    make_request_with_arguments(
        request_id,
        cap,
        "memory_read",
        "srv-mem",
        serde_json::json!({
            "collection": "agent-context",
            "id": key,
        }),
    )
}

#[test]
fn memory_write_appends_provenance_entry_linked_to_receipt() {
    let (kernel, agent_kp, scope, store) = kernel_with_memory_tools();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let response = kernel
        .evaluate_tool_call_blocking(&memory_write_request("req-write-1", &cap, "doc-42"))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let entry = store
        .latest_for_key("agent-context", "doc-42")
        .unwrap()
        .expect("write should have appended a provenance entry");
    assert_eq!(entry.capability_id, cap.id);
    assert_eq!(entry.receipt_id, response.receipt.id);
    assert_eq!(entry.written_at, response.receipt.timestamp);
    assert_eq!(
        entry.prev_hash,
        crate::memory_provenance::MEMORY_PROVENANCE_GENESIS_PREV_HASH,
        "the first entry in a fresh chain should point at the genesis marker"
    );
    // Chain digest advanced to the tail hash.
    assert_eq!(store.chain_digest().unwrap(), entry.hash);
}

#[test]
fn memory_read_surfaces_verified_provenance_metadata_on_receipt() {
    let (kernel, agent_kp, scope, _store) = kernel_with_memory_tools();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let write_response = kernel
        .evaluate_tool_call_blocking(&memory_write_request("req-write-2", &cap, "doc-99"))
        .unwrap();
    assert_eq!(write_response.verdict, Verdict::Allow);

    let read_response = kernel
        .evaluate_tool_call_blocking(&memory_read_request("req-read-2", &cap, "doc-99"))
        .unwrap();
    assert_eq!(read_response.verdict, Verdict::Allow);

    let metadata = read_response
        .receipt
        .metadata
        .as_ref()
        .expect("read receipt should carry metadata");
    let provenance = metadata
        .get("memory_provenance")
        .expect("memory_provenance evidence should be attached to the read receipt");
    assert_eq!(provenance["status"], serde_json::json!("verified"));
    assert_eq!(provenance["capability_id"], serde_json::json!(cap.id));
    assert_eq!(
        provenance["receipt_id"],
        serde_json::json!(write_response.receipt.id)
    );
    assert_eq!(provenance["store"], serde_json::json!("agent-context"));
    assert_eq!(provenance["key"], serde_json::json!("doc-99"));
    // `written_at` mirrors the signed write receipt timestamp.
    assert_eq!(
        provenance["written_at"],
        serde_json::json!(write_response.receipt.timestamp)
    );
}

#[test]
fn memory_read_without_prior_write_is_flagged_unverified() {
    let (kernel, agent_kp, scope, _store) = kernel_with_memory_tools();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let response = kernel
        .evaluate_tool_call_blocking(&memory_read_request("req-read-ghost", &cap, "doc-ghost"))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let provenance = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("memory_provenance"))
        .expect("reads without provenance still record a memory_provenance stanza");
    assert_eq!(provenance["status"], serde_json::json!("unverified"));
    assert_eq!(provenance["reason"], serde_json::json!("no_provenance"));
    assert_eq!(provenance["store"], serde_json::json!("agent-context"));
    assert_eq!(provenance["key"], serde_json::json!("doc-ghost"));
}

#[test]
fn memory_read_flags_chain_tamper_as_unverified() {
    let (kernel, agent_kp, scope, store) = kernel_with_memory_tools();
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let write_response = kernel
        .evaluate_tool_call_blocking(&memory_write_request("req-write-tamper", &cap, "doc-tamper"))
        .unwrap();
    let entry = store
        .latest_for_key("agent-context", "doc-tamper")
        .unwrap()
        .expect("entry should exist after the write");
    assert_eq!(entry.receipt_id, write_response.receipt.id);

    // Flip a hash byte in place to simulate cold-storage tamper.
    let forged_hash = "a".repeat(64);
    store
        .tamper_entry_hash(&entry.entry_id, &forged_hash)
        .expect("test helper should overwrite the entry");

    let read_response = kernel
        .evaluate_tool_call_blocking(&memory_read_request("req-read-tamper", &cap, "doc-tamper"))
        .unwrap();
    assert_eq!(read_response.verdict, Verdict::Allow);
    let provenance = read_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("memory_provenance"))
        .expect("tampered reads still record a memory_provenance stanza");
    assert_eq!(provenance["status"], serde_json::json!("unverified"));
    assert_eq!(provenance["reason"], serde_json::json!("chain_tampered"));
}

#[test]
fn memory_provenance_hook_is_noop_when_store_absent() {
    // memory-shaped tool calls keep working in backward-
    // compatible mode (no provenance store installed) and produce no
    // memory_provenance metadata on either write or read receipts.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-mem",
        vec!["memory_write", "memory_read"],
    )));
    let agent_kp = make_keypair();
    let scope = make_scope(vec![
        make_grant("srv-mem", "memory_write"),
        make_grant("srv-mem", "memory_read"),
    ]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let write_response = kernel
        .evaluate_tool_call_blocking(&memory_write_request("req-write-noop", &cap, "doc-noop"))
        .unwrap();
    assert_eq!(write_response.verdict, Verdict::Allow);
    assert!(write_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("memory_provenance"))
        .is_none());

    let read_response = kernel
        .evaluate_tool_call_blocking(&memory_read_request("req-read-noop", &cap, "doc-noop"))
        .unwrap();
    assert_eq!(read_response.verdict, Verdict::Allow);
    assert!(read_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|m| m.get("memory_provenance"))
        .is_none());
}
