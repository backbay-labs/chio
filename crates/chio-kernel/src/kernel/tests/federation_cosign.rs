// Phase 20.3 cross-kernel federation bilateral co-signing tests.
//
// Included by `src/kernel/tests.rs`; shares helpers (`make_config`,
// `make_keypair`, `make_scope`, `make_grant`, `make_capability`,
// `make_request_with_arguments`, `EchoServer`) with the sibling
// test files.
//
// Acceptance coverage:
//   * post-sign hook fires on federated requests and persists a
//     DualSignedReceipt that verifies against both pinned peer keys,
//   * non-federated requests still work and leave no dual-signed
//     artifact behind,
//   * missing peer pin fails closed.

use chio_federation::{
    FederationPeer, InProcessCoSigner, KernelTrustExchange, PeerHandshakeEnvelope,
};

fn handshake_and_pin(
    local: &KernelTrustExchange,
    remote_kernel_id: &str,
    remote_keypair: &Keypair,
    now: u64,
) -> FederationPeer {
    let envelope = PeerHandshakeEnvelope::sign(
        remote_kernel_id,
        local.local_kernel_id(),
        "nonce-cosign",
        now,
        remote_keypair,
    )
    .expect("remote envelope signs");
    local
        .accept_envelope(&envelope, remote_kernel_id, now)
        .expect("local accepts envelope and pins peer")
}

#[test]
fn federated_request_produces_dual_signed_receipt_verifiable_by_both_orgs() {
    // Org A holds the origin kernel; Org B hosts the tool.
    let origin_kp = Keypair::generate(); // Org A (origin) kernel key
    let origin_kernel_id = "kernel.org-a";

    // Build the tool-host kernel (Org B) on the test-local keypair.
    let mut kernel = make_kernel(make_config());
    let tool_host_public_key = kernel.config.keypair.public_key();
    let tool_host_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);

    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-fed",
        vec!["file_read"],
    )));

    // Pin Org A as a trusted peer on Org B's side. Use wall-clock now so
    // the freshness window stays open when the kernel's post-sign hook
    // queries `current_unix_timestamp()` during evaluation.
    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let kernel = kernel.with_federation_peers(vec![peer.clone()]);

    // Install the in-process bilateral cosigner: the test holds Org A's
    // signing key directly so we can exercise the full cryptographic
    // path without an actual mTLS transport.
    let mut kernel = kernel;
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_public_key.clone(),
    )));

    // Build a federated tool call request (agent in Org A calling a tool
    // hosted by Org B).
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-1",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    // The post-sign hook fired and a DualSignedReceipt was stashed.
    let dual = kernel
        .dual_signed_receipt(&response.receipt.id)
        .expect("dual-signed receipt must exist for federated request");
    assert_eq!(dual.org_a_kernel_id, origin_kernel_id);
    assert_eq!(dual.org_b_kernel_id, tool_host_kernel_id);
    assert_eq!(dual.body.id, response.receipt.id);

    // Either org can independently verify the receipt chain.
    dual.verify(&origin_kp.public_key(), &tool_host_public_key)
        .expect("dual-signed receipt must verify against both pinned peer keys");
}

#[test]
fn non_federated_request_leaves_no_dual_signed_artifact_behind() {
    let mut kernel = make_kernel(make_config());
    let path = unique_receipt_db_path("non-federated-no-dual-signed");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-local",
        vec!["file_read"],
    )));
    // No peers declared; no cosigner installed.
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-local", "file_read")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-local-1",
        &cap,
        "file_read",
        "srv-local",
        serde_json::json!({ "path": "/data/local.txt" }),
    );
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(kernel.dual_signed_receipt(&response.receipt.id).is_none());
}

#[test]
fn federated_request_without_pinned_peer_fails_closed() {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id("kernel.org-b");
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-fed",
        vec!["file_read"],
    )));
    // Cosigner is installed, but no peer is pinned -- must fail closed.
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        kernel.config.keypair.public_key(),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-missing-peer",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    // The named-peer-not-pinned-fresh case is a structured pre-dispatch
    // Deny verdict rather than a propagated `Err`. The deny receipt is
    // signed and persisted.
    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("federated request with no pinned peer must produce a Deny response");
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("not pinned") || reason.contains("stale") || reason.contains("downgrade"),
        "unexpected deny reason: {reason}"
    );
}

#[test]
fn federated_request_without_pinned_peer_fails_closed_pre_dispatch() {
    // With no pinned peer, the pre-dispatch negotiation gate fires first.
    // The missing-cosigner-with-fresh-peer scenario is exercised by the
    // sibling test below.
    let origin_kernel_id = "kernel.org-a";
    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id("kernel.org-b");
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-fed",
        vec!["file_read"],
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-no-peer",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("federated request with no pinned peer must produce a Deny response");
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("not pinned")
            || reason.contains("stale")
            || reason.contains("downgrade"),
        "unexpected deny reason: {reason}"
    );
}

#[test]
fn federated_request_with_fresh_peer_but_missing_cosigner_fails_closed_post_dispatch() {
    // Covers the "fresh peer pinned but no BilateralCoSigningProtocol
    // installed" branch. Pin Org A, but deliberately do NOT install a
    // cosigner; the pre-dispatch gate must pass and the post-dispatch
    // federation hop must surface the missing-cosigner failure.
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-fed",
        vec!["file_read"],
    )));

    // Pin Org A as a fresh trusted peer.
    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let kernel = kernel.with_federation_peers(vec![peer]);

    // NOTE: deliberately do NOT call `set_federation_cosigner` here.
    // The pre-dispatch gate sees a fresh peer pin and passes; the
    // post-dispatch federation hop must then refuse fail-closed.

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-no-cosigner",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    // The kernel may surface this as either a Deny response with a
    // structured reason or a typed KernelError; both are acceptable
    // fail-closed shapes. Map the Err arm into a synthetic Deny so
    // the assertion below covers either path.
    let result = kernel.evaluate_tool_call_blocking(&request);
    let (verdict, reason) = match result {
        Ok(resp) => (resp.verdict, resp.reason.unwrap_or_default()),
        Err(err) => (Verdict::Deny, err.to_string()),
    };
    assert_eq!(verdict, Verdict::Deny);
    assert!(
        reason.contains("federation cosigner missing")
            || reason.contains("cosigner")
            || reason.contains("federation"),
        "unexpected deny reason for missing-cosigner-with-fresh-peer scenario: {reason}"
    );
}
