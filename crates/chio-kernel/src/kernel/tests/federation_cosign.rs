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

use chio_core::capability::CapabilityNegotiation;
use chio_federation::{
    BilateralCoSigningError, BilateralCoSigningProtocol, CoSigningRequest, CoSigningResponse,
    FederationPeer, InProcessCoSigner, KernelTrustExchange, PeerHandshakeEnvelope,
};

struct CountingRejectingCosigner {
    calls: std::sync::Arc<AtomicU64>,
}

struct TreatyBindingRuntimeAdmissionHook {
    metadata: serde_json::Value,
    bind_request_hash: bool,
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

impl RuntimeAdmissionHook for TreatyBindingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "treaty-binding-runtime-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        let mut metadata = self.metadata.clone();
        let request_hash = chio_core::crypto::sha256_hex(
            &chio_core::canonical::canonical_json_bytes(&context.request.arguments).unwrap(),
        );
        if self.bind_request_hash {
            metadata["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
                ["request_sha256"] = serde_json::json!(request_hash);
        }
        Ok(RuntimeAdmissionDecision::allow(Some(metadata)))
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

fn treaty_binding_runtime_metadata(
    origin_kernel_id: &str,
    tool_host_kernel_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "chio_runtime": {
            "federation_treaty_dsse": {
                "capability_lease_ref": {
                    "lease_id": "lease-kernel-strict-1",
                    "issuer": origin_kernel_id,
                    "expires_at_unix_ms": 4_102_444_800_000u64
                },
                "policy_evaluation_summary": {
                    "server_a_verdict": {
                        "verdict": "allow",
                        "policy_id": "origin-runtime-policy",
                        "policy_version": "v1"
                    },
                    "server_b_verdict": {
                        "verdict": "allow",
                        "policy_id": "host-runtime-policy",
                        "policy_version": "v1"
                    },
                    "joint_disposition": "allow"
                },
                "governance_receipt_ref": {
                    "receipt_id": "governance-receipt-kernel-strict-1",
                    "kernel_id": tool_host_kernel_id,
                    "digest": {
                        "alg": "sha256",
                        "value": "d".repeat(64)
                    }
                },
                "consistency_anchor": "anchor:kernel-strict:1",
                "consistency_model": "totally_ordered",
                "cross_org_visibility": "federated",
                "treaty_binding_ref": {
                    "treaty_id": "treaty-kernel-strict",
                    "treaty_scope_sha256": "a".repeat(64),
                    "ladder_intersection_sha256": "b".repeat(64),
                    "admission_report_sha256": "c".repeat(64),
                    "continuation_sha256": "e".repeat(64),
                    "lineage_bundle_sha256": "f".repeat(64),
                    "action_class_id": "workflow.destructive.vendor_call",
                    "consistency_model": "totally_ordered",
                    "request_sha256": "0".repeat(64),
                    "outcome_sha256": "1".repeat(64),
                    "local_receipt_sha256": "2".repeat(64),
                    "remote_receipt_sha256": "3".repeat(64),
                    "lease_refs": ["lease-kernel-strict-1"],
                    "governance_refs": ["governance-receipt-kernel-strict-1"],
                    "signer_kernel_ids": [origin_kernel_id, tool_host_kernel_id]
                }
            }
        }
    })
}

#[test]
fn federated_request_without_runtime_treaty_material_fails_closed() {
    // Org A holds the origin kernel; Org B hosts the tool.
    let origin_kp = Keypair::generate(); // Org A (origin) kernel key
    let origin_kernel_id = "kernel.org-a";

    // Build the tool-host kernel (Org B) on the test-local keypair.
    let mut kernel = make_kernel(make_config());
    let tool_host_public_key = kernel.config.keypair.public_key();
    let tool_host_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federated-dual-signed-receipt");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

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

    let result = kernel.evaluate_tool_call_blocking(&request);
    let (verdict, reason, receipt_id) = match result {
        Ok(response) => (
            response.verdict,
            response.reason.unwrap_or_default(),
            Some(response.receipt.id),
        ),
        Err(error) => (Verdict::Deny, error.to_string(), None),
    };

    assert_eq!(
        verdict,
        Verdict::Deny,
        "federated requests must not emit DSSE without runtime treaty material"
    );
    assert!(
        reason.contains("runtime treaty"),
        "denial must identify missing runtime treaty material, got: {reason}"
    );
    if let Some(receipt_id) = receipt_id {
        assert!(
            kernel.federation_dsse_envelope(&receipt_id).is_none(),
            "denied missing-treaty requests must not persist federation DSSE"
        );
    }
}

#[test]
fn federated_request_with_runtime_treaty_material_produces_buyer_verifiable_strict_dsse() {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";

    let mut kernel = make_kernel(make_config());
    let tool_host_public_key = kernel.config.keypair.public_key();
    let tool_host_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federated-strict-treaty-dsse");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-fed",
        vec!["file_read"],
    )));

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
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        TreatyBindingRuntimeAdmissionHook {
            metadata: treaty_binding_runtime_metadata(origin_kernel_id, tool_host_kernel_id),
            bind_request_hash: true,
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-strict-1",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed-strict.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let envelope = kernel
        .federation_dsse_envelope(&response.receipt.id)
        .expect("DSSE envelope must exist for federated request");
    let (statement, _) = envelope.decode_statement().expect("statement decodes");
    assert_eq!(
        statement.predicate_type,
        chio_federation::PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
    );
    let mut expected_treaty = statement
        .predicate
        .treaty_binding_ref
        .clone()
        .expect("strict DSSE carries treaty binding");
    expected_treaty.request_sha256 = response.receipt.action.parameter_hash.clone();
    expected_treaty.outcome_sha256 = response.receipt.content_hash.clone();
    expected_treaty.remote_receipt_sha256 = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&response.receipt).unwrap(),
    );
    let expected_subject_name = chio_federation::receipt_subject_name(&response.receipt.id);
    let expected_subject_sha256 = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&response.receipt.body()).unwrap(),
    );
    let lease = statement
        .predicate
        .capability_lease_ref
        .as_ref()
        .expect("strict DSSE carries lease ref");
    let governance = statement
        .predicate
        .governance_receipt_ref
        .as_ref()
        .expect("strict DSSE carries governance ref");
    let anchor = statement
        .predicate
        .consistency_anchor
        .as_deref()
        .expect("strict DSSE carries consistency anchor");
    let signer_public_keys = std::collections::BTreeMap::from([
        (origin_kernel_id.to_string(), origin_kp.public_key()),
        (tool_host_kernel_id.to_string(), tool_host_public_key),
    ]);
    let review = chio_federation::TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: lease,
        expected_governance_receipt_ref: governance,
        expected_consistency_anchor: anchor,
        signer_public_keys: &signer_public_keys,
    };
    chio_federation::verify_treaty_bound_chio_bilateral_invocation(&envelope, &review)
        .expect("kernel-produced strict DSSE verifies under buyer review");
}

#[test]
fn federated_request_with_runtime_treaty_material_preserves_original_metadata_refs() {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.org-a";

    let mut kernel = make_kernel(make_config());
    let tool_host_public_key = kernel.config.keypair.public_key();
    let tool_host_kernel_id = "kernel.org-b";
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("federated-strict-treaty-dsse-metadata");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-fed",
        vec!["file_read"],
    )));

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
        tool_host_public_key,
    )));

    let metadata = treaty_binding_runtime_metadata(origin_kernel_id, tool_host_kernel_id);
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        TreatyBindingRuntimeAdmissionHook {
            metadata: metadata.clone(),
            bind_request_hash: true,
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-fed", "file_read")]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-fed-strict-metadata",
        &cap,
        "file_read",
        "srv-fed",
        serde_json::json!({ "path": "/data/fed-strict-metadata.txt" }),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    let envelope = kernel
        .federation_dsse_envelope(&response.receipt.id)
        .expect("DSSE envelope must exist for federated request");
    let (statement, _) = envelope.decode_statement().expect("statement decodes");
    let material = &metadata["chio_runtime"]["federation_treaty_dsse"];
    let expected_lease: chio_federation::CapabilityLeaseRef =
        serde_json::from_value(material["capability_lease_ref"].clone()).unwrap();
    let expected_policy: chio_federation::PolicyEvaluationSummary =
        serde_json::from_value(material["policy_evaluation_summary"].clone()).unwrap();
    let expected_governance: chio_federation::GovernanceReceiptRef =
        serde_json::from_value(material["governance_receipt_ref"].clone()).unwrap();
    let mut expected_treaty: chio_federation::TreatyBindingRef =
        serde_json::from_value(material["treaty_binding_ref"].clone()).unwrap();
    expected_treaty.request_sha256 = response.receipt.action.parameter_hash.clone();
    expected_treaty.outcome_sha256 = response.receipt.content_hash.clone();
    expected_treaty.remote_receipt_sha256 = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&response.receipt).unwrap(),
    );

    assert_eq!(
        statement.predicate.capability_lease_ref.as_ref(),
        Some(&expected_lease)
    );
    assert_eq!(
        statement.predicate.policy_evaluation_summary.as_ref(),
        Some(&expected_policy)
    );
    assert_eq!(
        statement.predicate.governance_receipt_ref.as_ref(),
        Some(&expected_governance)
    );
    assert_eq!(
        statement.predicate.consistency_anchor.as_deref(),
        material["consistency_anchor"].as_str()
    );
    assert_eq!(
        statement.predicate.consistency_model,
        material["consistency_model"].as_str().unwrap()
    );
    assert_eq!(
        statement.predicate.cross_org_visibility,
        material["cross_org_visibility"].as_str().unwrap()
    );
    assert_eq!(
        statement.predicate.treaty_binding_ref.as_ref(),
        Some(&expected_treaty)
    );
}

#[test]
fn federated_request_with_mismatched_runtime_treaty_material_fails_closed() {
    for (case, expected) in [
        ("request", "request hash"),
        ("signers", "signer"),
        ("lease", "lease"),
        ("governance", "governance"),
        ("consistency", "consistency"),
        ("missing_consistency", "consistency"),
    ] {
        let origin_kp = Keypair::generate();
        let origin_kernel_id = "kernel.org-a";
        let mut kernel = make_kernel(make_config());
        let tool_host_public_key = kernel.config.keypair.public_key();
        let tool_host_kernel_id = "kernel.org-b";
        kernel.set_federation_local_kernel_id(tool_host_kernel_id);
        let path = unique_receipt_db_path(&format!("federated-strict-treaty-dsse-bad-{case}"));
        kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(EchoServer::new(
            "srv-fed",
            vec!["file_read"],
        )));

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
            tool_host_public_key,
        )));

        let mut metadata = treaty_binding_runtime_metadata(origin_kernel_id, tool_host_kernel_id);
        match case {
            "request" => {
                metadata["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
                    ["request_sha256"] = serde_json::json!("9".repeat(64));
            }
            "signers" => {
                metadata["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
                    ["signer_kernel_ids"] =
                    serde_json::json!(["kernel.org-a", "kernel.unpinned"]);
            }
            "lease" => {
                metadata["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
                    ["lease_refs"] = serde_json::json!(["lease-other"]);
            }
            "governance" => {
                metadata["chio_runtime"]["federation_treaty_dsse"]["treaty_binding_ref"]
                    ["governance_refs"] = serde_json::json!(["governance-other"]);
            }
            "consistency" => {
                metadata["chio_runtime"]["federation_treaty_dsse"]["consistency_model"] =
                    serde_json::json!("causal");
            }
            "missing_consistency" => {
                metadata["chio_runtime"]["federation_treaty_dsse"]
                    .as_object_mut()
                    .unwrap()
                    .remove("consistency_model");
            }
            _ => unreachable!("unknown mismatch case"),
        }
        kernel.set_runtime_admission_hook(std::sync::Arc::new(
            TreatyBindingRuntimeAdmissionHook {
                metadata,
                bind_request_hash: case != "request",
            },
        ));

        let agent_kp = make_keypair();
        let cap = make_capability(
            &kernel,
            &agent_kp,
            make_scope(vec![make_grant("srv-fed", "file_read")]),
            300,
        );
        let mut request = make_request_with_arguments(
            &format!("req-fed-strict-bad-{case}"),
            &cap,
            "file_read",
            "srv-fed",
            serde_json::json!({ "path": format!("/data/fed-strict-bad-{case}.txt") }),
        );
        request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

        let result = kernel.evaluate_tool_call_blocking(&request);
        let (verdict, reason) = match result {
            Ok(resp) => (resp.verdict, resp.reason.unwrap_or_default()),
            Err(err) => (Verdict::Deny, err.to_string()),
        };
        assert_eq!(verdict, Verdict::Deny, "case {case} must fail closed");
        assert!(
            reason.contains(expected),
            "case {case} should mention {expected}, got: {reason}"
        );
    }
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
    }));

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
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
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
