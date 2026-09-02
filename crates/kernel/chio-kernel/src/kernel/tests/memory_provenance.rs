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

#[test]
fn finding_memory_binding_denies_before_tool_dispatch() {
    let mut kernel = make_kernel(make_config());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-mem",
        vec!["memory_write"],
        Arc::clone(&invocations),
    )));
    install_provenance_store(&mut kernel);
    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-mem", "memory_write")]),
        300,
    );
    let mut request = memory_write_request("req-finding-binding-deny", &cap, "finding-1");
    request.arguments[crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT] =
        serde_json::json!("missing-delivery-receipt");
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-finding-memory-write".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "retain an authenticated Finding delivery".to_owned(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });
    let admission_error = kernel
        .validate_finding_memory_write_admission(&request)
        .expect_err("missing delivery receipt must fail admission");
    assert!(admission_error
        .to_string()
        .contains("durable receipt"));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("invalid Finding write returns a signed deny");
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
}

struct RequiredFindingStatusFeedGuard(&'static str);

impl Guard for RequiredFindingStatusFeedGuard {
    fn name(&self) -> &str {
        "required-finding-status-feed"
    }

    fn evaluate(&self, _ctx: &GuardContext) -> Result<GuardDecision, KernelError> {
        Ok(GuardDecision::allow())
    }

    fn required_finding_status_feed_id(
        &self,
        _ctx: &GuardContext,
    ) -> Result<Option<String>, KernelError> {
        Ok(Some(self.0.to_owned()))
    }
}

struct RetractedFindingStatusVerifier;

impl crate::finding_purchase::FindingStatusProofVerifier for RetractedFindingStatusVerifier {
    fn verify_status_proof(
        &self,
        _view: &crate::finding_purchase::FindingStatusProofContextView<'_>,
    ) -> Result<
        crate::finding_purchase::VerifiedFindingStatusProof,
        crate::finding_denial::FindingDenial,
    > {
        Err(crate::finding_denial::FindingDenial::unavailable(
            "portable proof verification is not used by this test",
        ))
    }

    fn verify_status_admission(
        &self,
        _view: &crate::finding_purchase::FindingStatusProofContextView<'_>,
        _verified: &crate::finding_purchase::VerifiedFindingStatusProof,
        _now_unix_secs: u64,
    ) -> Result<(), crate::finding_denial::FindingDenial> {
        Err(crate::finding_denial::FindingDenial::unavailable(
            "portable proof admission is not used by this test",
        ))
    }

    fn verify_current_status_admission(
        &self,
        _view: &crate::finding_purchase::FindingCurrentStatusContextView<'_>,
        _now_unix_secs: u64,
    ) -> Result<(), crate::finding_denial::FindingDenial> {
        Err(crate::finding_denial::FindingDenial::status_denied(
            "finding is retracted",
        ))
    }
}

struct CheckpointRaceStatusVerifier {
    retracted: Arc<std::sync::atomic::AtomicBool>,
}

impl crate::finding_purchase::FindingStatusProofVerifier for CheckpointRaceStatusVerifier {
    fn verify_status_proof(
        &self,
        _view: &crate::finding_purchase::FindingStatusProofContextView<'_>,
    ) -> Result<
        crate::finding_purchase::VerifiedFindingStatusProof,
        crate::finding_denial::FindingDenial,
    > {
        Err(crate::finding_denial::FindingDenial::unavailable(
            "portable proof verification is not used by this test",
        ))
    }

    fn verify_status_admission(
        &self,
        _view: &crate::finding_purchase::FindingStatusProofContextView<'_>,
        _verified: &crate::finding_purchase::VerifiedFindingStatusProof,
        _now_unix_secs: u64,
    ) -> Result<(), crate::finding_denial::FindingDenial> {
        Err(crate::finding_denial::FindingDenial::unavailable(
            "portable proof admission is not used by this test",
        ))
    }

    fn verify_current_status_admission(
        &self,
        _view: &crate::finding_purchase::FindingCurrentStatusContextView<'_>,
        _now_unix_secs: u64,
    ) -> Result<(), crate::finding_denial::FindingDenial> {
        if self.retracted.load(std::sync::atomic::Ordering::SeqCst) {
            Err(crate::finding_denial::FindingDenial::status_denied(
                "finding retracted during checkpoint preflight",
            ))
        } else {
            Ok(())
        }
    }
}

fn signed_finding_delivery_receipt(
    feed_id: &str,
) -> (chio_core::receipt::body::ChioReceipt, Keypair) {
    use chio_core::receipt::metadata::{
        DeliveryContract, DeliveryResult, FindingDelivery, FindingDeliverySettlementMode,
        FindingMediaTypeCheck, FindingStatusProofMetadata, FindingTransformProfile,
        DELIVERY_CONTRACT_METADATA_KEY, DELIVERY_CONTRACT_SCHEMA, FINDING_DELIVERY_METADATA_KEY,
        FINDING_DELIVERY_SCHEMA, FINDING_STATUS_KEY_DOMAIN_NONCE,
    };

    let delivery_key = make_keypair();
    let content = serde_json::json!("important context");
    let content_digest = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&content)
            .expect("memory content is canonicalizable"),
    );
    let receipt = chio_core::receipt::body::ChioReceipt::sign(
        chio_core::receipt::body::ChioReceiptBody {
            id: "placeholder-finding-delivery".to_owned(),
            timestamp: current_unix_timestamp(),
            capability_id: "cap-finding-delivery".to_owned(),
            tool_server: "finding-server".to_owned(),
            tool_name: "finding.reveal".to_owned(),
            action: chio_core::receipt::decision::ToolCallAction::from_parameters(
                serde_json::json!({"finding_id": "finding-1"}),
            )
            .expect("valid delivery action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: content_digest.clone(),
            policy_hash: "finding-delivery-policy".to_owned(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                DELIVERY_CONTRACT_METADATA_KEY: DeliveryContract {
                    schema: DELIVERY_CONTRACT_SCHEMA.to_owned(),
                    expected_digest: content_digest.clone(),
                    observed_digest: content_digest,
                    result: DeliveryResult::Matched,
                },
                FINDING_DELIVERY_METADATA_KEY: FindingDelivery {
                    schema: FINDING_DELIVERY_SCHEMA.to_owned(),
                    finding_id: "finding-1".to_owned(),
                    listing_id: "listing-1".to_owned(),
                    transform_profile: FindingTransformProfile::Identity,
                    digest_check: DeliveryResult::Matched,
                    media_type_check: FindingMediaTypeCheck::Matched,
                    settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
                    accepted_bid_envelope_sha256: "1".repeat(64),
                    venue_admission_envelope_sha256: "2".repeat(64),
                    reservation_id: "reservation-1".to_owned(),
                    purchase_intent_id: "purchase-intent-1".to_owned(),
                    authoritative_payment_operation_id: "payment-operation-1".to_owned(),
                    status_proof: Some(FindingStatusProofMetadata {
                        feed_id: feed_id.to_owned(),
                        key_domain_nonce: FINDING_STATUS_KEY_DOMAIN_NONCE,
                        map_epoch: 1,
                        status_epoch_artifact_sha256: "3".repeat(64),
                        proof_sha256: "4".repeat(64),
                        root_hash: "5".repeat(64),
                        non_inclusion_checked_at: current_unix_timestamp(),
                    }),
                },
            })),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: delivery_key.public_key(),
            bbs_projection_version: None,
        },
        &delivery_key,
    )
    .expect("sign finding delivery receipt");
    (receipt, delivery_key)
}

#[test]
fn finding_memory_status_is_rechecked_after_checkpoint_preflight() {
    let mut config = make_config();
    config.checkpoint_batch_size = 1;
    let mut kernel = make_kernel(config);
    install_provenance_store(&mut kernel);
    kernel.add_guard(Box::new(RequiredFindingStatusFeedGuard(
        "status-feed/delivery",
    )));
    let (parent, delivery_key) = signed_finding_delivery_receipt("status-feed/delivery");
    let retracted = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let directory = tempfile::tempdir().expect("receipt store directory");
    let store = SqliteReceiptStore::open(directory.path().join("receipts.db"))
        .expect("open checkpointing receipt store");
    store.flip_status_on_checkpoint(Arc::clone(&retracted));
    store
        .append_chio_receipt(&parent)
        .expect("seed delivery receipt");
    kernel
        .set_receipt_store(Box::new(store))
        .expect("install receipt store");
    kernel.set_finding_delivery_receipt_authorities(vec![delivery_key.public_key()]);
    kernel.set_finding_status_proof_verifier(Arc::new(CheckpointRaceStatusVerifier {
        retracted: Arc::clone(&retracted),
    }));

    let agent = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent,
        make_scope(vec![make_grant("srv-mem", "memory_write")]),
        300,
    );
    let mut request = memory_write_request("finding-memory-checkpoint-race", &capability, "finding-1");
    request.arguments[crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT] =
        serde_json::json!(parent.id);
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-finding-memory-checkpoint-race".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "retain an authenticated Finding delivery".to_owned(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });

    let error = kernel
        .revalidate_finding_memory_write_status_before_dispatch(
            &request,
            current_unix_timestamp(),
        )
        .expect_err("a retraction during checkpoint preflight must deny dispatch");
    assert!(
        error
            .to_string()
            .contains("retracted during checkpoint preflight"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn finding_memory_write_rejects_a_delivery_from_another_status_feed_before_dispatch() {
    let mut kernel = make_kernel(make_config());
    let invocations = Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-mem",
        vec!["memory_write"],
        Arc::clone(&invocations),
    )));
    install_provenance_store(&mut kernel);
    kernel.add_guard(Box::new(RequiredFindingStatusFeedGuard(
        "status-feed/quarantine",
    )));

    let (parent, delivery_key) = signed_finding_delivery_receipt("status-feed/delivery");
    let store = PointLookupReceiptStore::default();
    store
        .append_chio_receipt(&parent)
        .expect("seed delivery receipt");
    kernel
        .set_receipt_store(Box::new(store))
        .expect("install receipt store");
    kernel.set_finding_delivery_receipt_authorities(vec![delivery_key.public_key()]);

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-mem", "memory_write")]),
        300,
    );
    let mut request = memory_write_request("req-finding-feed-mismatch", &cap, "finding-1");
    request.arguments[crate::memory_provenance::FINDING_DELIVERY_RECEIPT_ID_ARGUMENT] =
        serde_json::json!(parent.id);
    request.governed_intent = Some(GovernedTransactionIntent {
        id: "intent-finding-feed-mismatch".to_owned(),
        server_id: request.server_id.clone(),
        tool_name: request.tool_name.clone(),
        purpose: "reject a delivery outside the quarantine feed".to_owned(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: None,
        body: Default::default(),
    });

    kernel.set_finding_status_proof_verifier(Arc::new(RetractedFindingStatusVerifier));
    let status_error = kernel
        .revalidate_finding_memory_write_status_before_dispatch(
            &request,
            current_unix_timestamp(),
        )
        .expect_err("a different delivery feed must fail dispatch revalidation");
    assert!(status_error.to_string().contains("quarantine resolver"));

    let response = kernel
        .evaluate_tool_call_blocking(&request)
        .expect("feed mismatch returns a signed deny");
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("quarantine resolver")));
    assert_eq!(invocations.load(Ordering::SeqCst), 0);

    kernel.set_finding_delivery_receipt_authorities(vec![make_keypair().public_key()]);
    let authentication_error = kernel
        .revalidate_finding_memory_write_status_before_dispatch(
            &request,
            current_unix_timestamp(),
        )
        .expect_err("dispatch revalidation must authenticate the latest retained receipt");
    assert!(authentication_error
        .to_string()
        .contains("not an authentic allow receipt"));
}
