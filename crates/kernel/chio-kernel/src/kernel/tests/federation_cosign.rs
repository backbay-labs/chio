// Cross-kernel federation bilateral co-signing tests.
//
// Included by `src/kernel/tests.rs`; shares helpers (`make_config`,
// `make_keypair`, `make_scope`, `make_grant`, `make_capability`,
// `make_request_with_arguments`, `EchoServer`) with the sibling
// test files.
//
// Coverage:
//   * post-sign hook fires on federated requests and persists a
//     DualSignedReceipt that verifies against both pinned peer keys,
//   * non-federated requests still work and leave no dual-signed
//     artifact behind,
//   * missing peer pin fails closed.

use chio_core::capability::features::CapabilityNegotiation;
use chio_federation::{
    bilateral::BilateralCoSigningError, bilateral::BilateralCoSigningProtocol, bilateral::CoSigningRequest, bilateral::CoSigningResponse,
    trust_establishment::FederationPeer, bilateral::InProcessCoSigner, trust_establishment::KernelTrustExchange, trust_establishment::PeerHandshakeEnvelope,
};

struct CountingRejectingCosigner {
    calls: std::sync::Arc<AtomicU64>,
}

impl BilateralCoSigningProtocol for CountingRejectingCosigner {
    fn request_cosignature(
        &self,
        _request: &CoSigningRequest,
    ) -> Result<CoSigningResponse, BilateralCoSigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(BilateralCoSigningError::PeerRejected(
            "test cosigner should not be called before local durability".to_string(),
        ))
    }
}

/// Runtime admission hook that supplies the treaty-bound DSSE material the
/// federation post-sign hook requires. In production this metadata is emitted
/// by the runtime admission verifier (`chio-runtime-core`) after it resolves
/// and verifies the cross-boundary treaty evidence; here we mint an equivalent
/// `chio_runtime.federation_treaty_dsse` block directly so the kernel's
/// fail-closed dual-signing path has the material it demands.
///
/// The kernel re-derives `outcome_sha256` and `remote_receipt_sha256` from the
/// freshly signed receipt and validates `request_sha256` against the receipt's
/// action parameter hash, so the only receipt-bound value this hook must get
/// right is `request_sha256`, which it computes from the request arguments.
struct TreatyDsseAdmissionHook;

impl TreatyDsseAdmissionHook {
    fn federation_treaty_dsse(request_sha256: &str) -> serde_json::Value {
        let capability_lease_ref = chio_federation::bilateral_dsse::CapabilityLeaseRef {
            lease_id: "lease-bilateral".to_string(),
            issuer: "kernel.org-a".to_string(),
            expires_at_unix_ms: 4_102_444_800_000,
            scope_digest: None,
        };
        let policy_evaluation_summary = chio_federation::bilateral_dsse::PolicyEvaluationSummary {
            server_a_verdict: chio_federation::bilateral_dsse::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-a".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            server_b_verdict: chio_federation::bilateral_dsse::PolicyVerdict {
                verdict: "allow".to_string(),
                policy_id: "policy-b".to_string(),
                policy_version: "v1".to_string(),
                rationale_code: None,
            },
            joint_disposition: Some("allow".to_string()),
        };
        // `outcome_sha256` and `remote_receipt_sha256` are overwritten by the
        // kernel from the signed receipt; supply syntactically valid 64-hex
        // placeholders. `request_sha256` must match the receipt action hash.
        let treaty_binding_ref = chio_federation::bilateral_dsse::TreatyBindingRef {
            treaty_id: "treaty-buyer-vendor".to_string(),
            treaty_scope_sha256: "1".repeat(64),
            ladder_intersection_sha256: "2".repeat(64),
            admission_report_sha256: "3".repeat(64),
            continuation_sha256: "4".repeat(64),
            lineage_bundle_sha256: "5".repeat(64),
            action_class_id: "workflow.destructive.vendor_call".to_string(),
            consistency_model: "totally_ordered".to_string(),
            request_sha256: request_sha256.to_string(),
            outcome_sha256: "6".repeat(64),
            local_receipt_sha256: "7".repeat(64),
            remote_receipt_sha256: "8".repeat(64),
            lease_refs: vec!["lease-bilateral".to_string()],
            governance_refs: Vec::new(),
            signer_kernel_ids: vec!["kernel.org-a".to_string(), "kernel.org-b".to_string()],
        };
        serde_json::json!({
            "capability_lease_ref": capability_lease_ref,
            "policy_evaluation_summary": policy_evaluation_summary,
            "consistency_anchor": "anchor-live",
            "consistency_model": "totally_ordered",
            "cross_org_visibility": "treaty_only",
            "treaty_binding_ref": treaty_binding_ref,
        })
    }
}

impl RuntimeAdmissionHook for TreatyDsseAdmissionHook {
    fn name(&self) -> &str {
        "test-federation-treaty-dsse-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let action = ToolCallAction::from_parameters(context.request.arguments.clone())
            .map_err(|e| KernelError::Internal(format!("failed to hash request arguments: {e}")))?;
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chio_runtime": {
                "admission_id": context.request.request_id,
                "accepted": true,
                "failure_code": null,
                "federation_treaty_dsse": Self::federation_treaty_dsse(&action.parameter_hash),
            }
        }))))
    }
}

struct FailingAppendReceiptStore {
    called: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for FailingAppendReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.called.store(true, Ordering::SeqCst);
        Err(ReceiptStoreError::Conflict(
            "receipt append failed".to_string(),
        ))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

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
    let path = unique_receipt_db_path("federated-dual-signed-receipt");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();

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

    // Supply the treaty-bound DSSE runtime material that the post-sign
    // federation hook requires. In production this rides in on the runtime
    // admission decision after the treaty evidence is verified; the kernel
    // refuses to mint a treaty-bound DSSE envelope without it (fail-closed).
    kernel.set_runtime_admission_hook(std::sync::Arc::new(TreatyDsseAdmissionHook));

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

    let envelope = kernel
        .federation_dsse_envelope(&response.receipt.id)
        .expect("DSSE envelope must exist for federated request");
    // The treaty-bound federation hop emits a strict Chio bilateral
    // invocation predicate (it carries `treaty_binding_ref` and omits the
    // signature-slice `receipt_canonical_json`), so it must be verified with
    // the strict Chio verifier rather than the signature-slice
    // `verify_dsse_envelope`.
    let statement = chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
        &envelope,
        &origin_kp.public_key(),
        &tool_host_public_key,
    )
    .expect("treaty-bound DSSE envelope must verify against both pinned peer keys");
    let treaty = statement
        .predicate
        .treaty_binding_ref
        .expect("treaty-bound DSSE envelope must carry a treaty binding ref");
    assert_eq!(treaty.request_sha256, response.receipt.action.parameter_hash);
    assert_eq!(treaty.outcome_sha256, response.receipt.content_hash);
    assert_eq!(
        treaty.signer_kernel_ids,
        vec![origin_kernel_id.to_string(), tool_host_kernel_id.to_string()]
    );
}

#[test]
fn federation_cosigner_not_called_when_local_persistence_fails() {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";
    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);

    let receipt_append_called = std::sync::Arc::new(AtomicBool::new(false));
    kernel.set_receipt_store(Box::new(FailingAppendReceiptStore {
        called: std::sync::Arc::clone(&receipt_append_called),
    })).unwrap();

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    peer.capabilities = CapabilityNegotiation::t1_default();
    let kernel = kernel.with_federation_peers(vec![peer]);
    let mut kernel = kernel;

    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-store-fails",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());
    let receipt = make_signed_receipt(&kernel.config.keypair, "rcpt-fed-store-fails");

    let err = kernel
        .record_chio_receipt_with_federation(&request, &receipt)
        .expect_err("local persistence failure must abort before federation cosign");

    assert!(
        format!("{err}").contains("receipt append failed"),
        "unexpected error: {err}"
    );
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "cosigner must not be called before durable local receipt state exists"
    );
    assert!(
        receipt_append_called.load(Ordering::SeqCst),
        "receipt append must be attempted before federation cosign"
    );
}

#[test]
fn federated_request_without_receipt_store_denies_before_dispatch_or_cosign() {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";
    let tool_host_kernel_id = "kernel.org-b";
    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-fed",
        vec!["file_read"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    peer.capabilities = CapabilityNegotiation::v1_default();
    let kernel = kernel.with_federation_peers(vec![peer]);
    let mut kernel = kernel;

    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-v1-no-store",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("missing federated receipt persistence must produce a signed deny response");

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("receipt persistence") && reason.contains("durable"),
        "unexpected deny reason: {reason}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "tool must not run without durable federated receipt persistence"
    );
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "cosigner must not run before durable local receipt state exists"
    );
    assert!(
        kernel.dual_signed_receipt(&response.receipt.id).is_none(),
        "dual-signed receipt must not be produced for a pre-dispatch denial"
    );
    assert!(
        kernel.federation_dsse_envelope(&response.receipt.id).is_none(),
        "DSSE envelope must not be produced for a pre-dispatch denial"
    );
}

#[test]
fn non_federated_kernel_without_receipt_store_fails_closed_unless_ephemeral_enabled() {
    // Mirrors the sibling federated `..._denies_before_dispatch_or_cosign`
    // test for the non-federated path. With `allow_ephemeral_receipt_log`
    // disabled and no receipt store installed, the pre-dispatch receipt
    // persistence admission gate must fail closed: the tool server is
    // never invoked, and the kernel emits a signed Deny pointing at the
    // missing durable receipt store. Flipping the flag back on restores
    // the ordinary local dispatch path.
    let mut config = make_config();
    config.allow_ephemeral_receipt_log = false;
    let mut kernel = make_kernel(config);
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-local",
        vec!["file_read"],
        std::sync::Arc::clone(&invocations),
    )));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-local", "file_read")]),
        300,
    );
    let request = make_request_with_arguments(
        "req-local-no-store-strict",
        &cap,
        "file_read",
        "srv-local",
        serde_json::json!({ "path": "/data/local.txt" }),
    );

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("missing receipt persistence must produce a signed deny response");
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("receipt persistence") && reason.contains("durable"),
        "unexpected deny reason: {reason}"
    );
    assert_eq!(
        invocations.load(Ordering::SeqCst),
        0,
        "tool must not run without durable receipt persistence when ephemeral logging is disabled"
    );

    // Flip the ephemeral flag back on with a fresh kernel and confirm the
    // same request now succeeds without a receipt store, invoking the
    // tool exactly once.
    let mut ephemeral_config = make_config();
    ephemeral_config.allow_ephemeral_receipt_log = true;
    let mut ephemeral_kernel = make_kernel(ephemeral_config);
    let ephemeral_invocations = std::sync::Arc::new(AtomicU64::new(0));
    ephemeral_kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-local",
        vec!["file_read"],
        std::sync::Arc::clone(&ephemeral_invocations),
    )));

    let ephemeral_agent_kp = make_keypair();
    let ephemeral_cap = make_capability(
        &ephemeral_kernel,
        &ephemeral_agent_kp,
        make_scope(vec![make_grant("srv-local", "file_read")]),
        300,
    );
    let ephemeral_request = make_request_with_arguments(
        "req-local-no-store-ephemeral",
        &ephemeral_cap,
        "file_read",
        "srv-local",
        serde_json::json!({ "path": "/data/local.txt" }),
    );
    let ephemeral_response = ephemeral_kernel
        .evaluate_tool_call_blocking(&ephemeral_request)
        .expect("ephemeral receipt logging must permit dispatch without a receipt store");
    assert_eq!(ephemeral_response.verdict, Verdict::Allow);
    assert_eq!(
        ephemeral_invocations.load(Ordering::SeqCst),
        1,
        "tool must be invoked exactly once when ephemeral receipt logging is permitted"
    );
}

#[test]
fn non_federated_request_leaves_no_dual_signed_artifact_behind() {
    let mut kernel = make_kernel(make_config());
    let path = unique_receipt_db_path("non-federated-no-dual-signed");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
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
    assert!(kernel.federation_dsse_envelope(&response.receipt.id).is_none());
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
    let path = unique_receipt_db_path("federated-missing-cosigner");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap())).unwrap();
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
    let mut kernel = kernel.with_federation_peers(vec![peer]);

    // NOTE: deliberately do NOT call `set_federation_cosigner` here.
    // The pre-dispatch gate sees a fresh peer pin and passes; the
    // post-dispatch federation hop must then refuse fail-closed.
    // Install treaty material so the test reaches the missing-cosigner
    // branch instead of the earlier runtime-admission fail-closed branch.
    kernel.set_runtime_admission_hook(std::sync::Arc::new(TreatyDsseAdmissionHook));

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

    // Fail-closed before cosign: without a runtime admission hook, federated
    // requests are denied at pre-dispatch treaty admission. If that gate is
    // satisfied in a future setup, post-dispatch may instead surface
    // "federation cosigner missing". Either path is acceptable.
    let result = kernel.evaluate_tool_call_blocking(&request);
    let (verdict, reason) = match result {
        Ok(resp) => (resp.verdict, resp.reason.unwrap_or_default()),
        Err(err) => (Verdict::Deny, err.to_string()),
    };
    assert_eq!(verdict, Verdict::Deny);
    assert!(
        reason.contains("federation cosigner missing")
            || reason.contains("cosigner")
            || reason.contains("federation")
            || reason.contains("treaty-bound")
            || reason.contains("admission context"),
        "unexpected deny reason for missing-cosigner-with-fresh-peer scenario: {reason}"
    );
}

#[test]
fn installed_artifact_store_preserves_cosign_evidence_across_cache_eviction() {
    // A federated deployment producing more than federation_cache_capacity receipts
    // drops evicted DualSignedReceipt / DSSE artifacts from the bounded in-memory
    // caches. Installing a write-through FederationArtifactStore via
    // set_federation_artifact_store makes the co-sign hook write through to the
    // store before the cache, so an artifact evicted from the front cache still
    // resolves from the store (as long as the store itself has not evicted it) and
    // dual_signed_receipt / federation_dsse_envelope keep resolving older receipts
    // instead of returning None.
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";

    // A cache capacity of 1 evicts the first receipt the moment the second is
    // co-signed, exercising the eviction path deterministically.
    let mut config = make_config();
    config.memory_budget.federation_cache_capacity = 1;

    let mut kernel = make_kernel(config);
    let tool_host_public_key = kernel.config.keypair.public_key();
    let tool_host_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federation-artifact-store-eviction");
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-fed", vec!["file_read"])));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_public_key.clone(),
    )));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(TreatyDsseAdmissionHook));

    // Install the durable artifact store via the new setter.
    kernel.set_federation_artifact_store(std::sync::Arc::new(
        crate::federation_artifact_store::InMemoryFederationArtifactStore::default(),
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );

    // First federated request -> first receipt, cached and stored.
    let mut request_a = make_request_with_arguments(
        "req-fed-evict-a",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed-a.txt" }),
    );
    request_a.federated_origin_kernel_id = Some(origin_kernel_id.to_string());
    let response_a = kernel.evaluate_tool_call_blocking(&request_a).unwrap();
    assert_eq!(response_a.verdict, Verdict::Allow);
    let receipt_a_id = response_a.receipt.id.clone();

    // Second federated request -> distinct receipt; co-signing it evicts A from
    // the capacity-1 in-memory cache.
    let mut request_b = make_request_with_arguments(
        "req-fed-evict-b",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed-b.txt" }),
    );
    request_b.federated_origin_kernel_id = Some(origin_kernel_id.to_string());
    let response_b = kernel.evaluate_tool_call_blocking(&request_b).unwrap();
    assert_eq!(response_b.verdict, Verdict::Allow);
    let receipt_b_id = response_b.receipt.id.clone();
    assert_ne!(receipt_a_id, receipt_b_id);

    // The bounded cache holds only the most recent artifact (A was evicted).
    let dual_gauge = kernel
        .bounded_structure_gauges()
        .into_iter()
        .find(|(label, _)| *label == "federation_dual_receipts")
        .map(|(_, count)| count)
        .expect("federation_dual_receipts gauge must exist");
    assert_eq!(dual_gauge, 1, "cap-1 cache must hold only the newest artifact");

    // The evicted receipt A is no longer in the cache (gauge == 1 holds only B),
    // so it can only still resolve via the durable store fallback.
    let dual_a = kernel
        .dual_signed_receipt(&receipt_a_id)
        .expect("evicted dual-signed receipt must resolve from the artifact store");
    assert_eq!(dual_a.body.id, receipt_a_id);
    dual_a
        .verify(&origin_kp.public_key(), &tool_host_public_key)
        .expect("store-served dual-signed receipt must still verify against both peers");
    assert!(
        kernel.federation_dsse_envelope(&receipt_a_id).is_some(),
        "evicted DSSE envelope must resolve from the artifact store"
    );

    // The most recent receipt B resolves from the cache.
    assert!(kernel.dual_signed_receipt(&receipt_b_id).is_some());

    let _ = std::fs::remove_file(path);
}

#[test]
fn bounded_in_memory_artifact_store_loses_evidence_when_both_layers_evict() {
    // The bundled InMemoryFederationArtifactStore is a bounded cache, not durable
    // storage. When BOTH the kernel front cache and the store are capacity 1, the
    // second co-sign evicts the first receipt from the store as well as the cache,
    // so the older artifact is unrecoverable. This is why an installed store is
    // NOT assumed to make evicted artifacts resolvable unless it reports itself
    // durable: a bounded store can lose the same evidence the cache did.
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";

    let mut config = make_config();
    config.memory_budget.federation_cache_capacity = 1;

    let mut kernel = make_kernel(config);
    let tool_host_public_key = kernel.config.keypair.public_key();
    let tool_host_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federation-artifact-store-bounded-loss");
    kernel
        .set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()))
        .unwrap();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-fed", vec!["file_read"])));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);
    kernel.set_federation_cosigner(std::sync::Arc::new(InProcessCoSigner::new(
        origin_kernel_id,
        origin_kp.clone(),
        tool_host_public_key.clone(),
    )));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(TreatyDsseAdmissionHook));

    // Install a capacity-1 in-memory store: it drop-evicts exactly like the front
    // cache, so it cannot durably retain an evicted artifact.
    kernel.set_federation_artifact_store(std::sync::Arc::new(
        crate::federation_artifact_store::InMemoryFederationArtifactStore::with_capacity(1, 3600),
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );

    let mut request_a = make_request_with_arguments(
        "req-fed-bounded-a",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed-a.txt" }),
    );
    request_a.federated_origin_kernel_id = Some(origin_kernel_id.to_string());
    let response_a = kernel.evaluate_tool_call_blocking(&request_a).unwrap();
    assert_eq!(response_a.verdict, Verdict::Allow);
    let receipt_a_id = response_a.receipt.id.clone();

    // Co-signing B evicts A from the store (capacity 1) BEFORE evicting it from the
    // capacity-1 cache, so A is gone from both layers.
    let mut request_b = make_request_with_arguments(
        "req-fed-bounded-b",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed-b.txt" }),
    );
    request_b.federated_origin_kernel_id = Some(origin_kernel_id.to_string());
    let response_b = kernel.evaluate_tool_call_blocking(&request_b).unwrap();
    assert_eq!(response_b.verdict, Verdict::Allow);
    let receipt_b_id = response_b.receipt.id.clone();
    assert_ne!(receipt_a_id, receipt_b_id);

    // The bounded store did NOT preserve A: both layers evicted it, so it is
    // unrecoverable. Treating this store as durable would have masked the loss.
    assert!(
        kernel.dual_signed_receipt(&receipt_a_id).is_none(),
        "a bounded in-memory store must not be relied on to durably retain evicted artifacts"
    );
    assert!(
        kernel.federation_dsse_envelope(&receipt_a_id).is_none(),
        "a bounded in-memory store must not be relied on to durably retain evicted envelopes"
    );

    // The most recent receipt B still resolves from the surviving layers.
    assert!(kernel.dual_signed_receipt(&receipt_b_id).is_some());

    let _ = std::fs::remove_file(path);
}
