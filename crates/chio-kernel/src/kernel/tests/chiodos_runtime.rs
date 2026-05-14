// Chiodos runtime admission hook tests.
//
// These cover the generic pre-dispatch hook that Chiodos 7.0 uses to deny
// cross-vendor workflow steps before tool execution or federation side effects.

struct DenyingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct AllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

struct LiveReceiptAllowingRuntimeAdmissionHook {
    calls: std::sync::Arc<AtomicU64>,
}

impl RuntimeAdmissionHook for DenyingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chiodos-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, "req-chiodos-runtime-deny");
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::deny(
            "chiodos runtime admission denied",
            Some(serde_json::json!({
                "chiodos_runtime": {
                    "admission_id": "adm-denied",
                    "accepted": false,
                    "failure_code": "test_runtime_deny"
                }
            })),
        ))
    }
}

impl RuntimeAdmissionHook for AllowingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chiodos-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(context.request.request_id, "req-chiodos-runtime-allow");
        assert_eq!(context.matched_grant_index, Some(0));
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chiodos_runtime": {
                "admission_id": "adm-allowed",
                "accepted": true,
                "failure_code": null,
                "observe_only": true
            }
        }))))
    }
}

impl RuntimeAdmissionHook for LiveReceiptAllowingRuntimeAdmissionHook {
    fn name(&self) -> &str {
        "test-chiodos-live-receipt-admission"
    }

    fn evaluate(
        &self,
        context: &RuntimeAdmissionContext<'_>,
    ) -> Result<RuntimeAdmissionDecision, KernelError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(context.matched_grant_index.is_some());
        Ok(RuntimeAdmissionDecision::allow(Some(serde_json::json!({
            "chiodos_runtime": {
                "admission_id": context.request.request_id,
                "accepted": true,
                "failure_code": null,
                "live_receipt_capture": true
            }
        }))))
    }
}

fn assert_package_valid_allow_receipt(
    response: &ToolCallResponse,
    request: &ToolCallRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(response.request_id, request.request_id);
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(response.receipt.is_allowed());
    assert_eq!(response.receipt.capability_id, request.capability.id);
    assert_eq!(response.receipt.tool_server, request.server_id);
    assert_eq!(response.receipt.tool_name, request.tool_name);
    assert!(
        response.receipt.verify_signature()?,
        "response receipt signature must verify"
    );

    let package = serde_json::to_vec(&response.receipt)?;
    let unpacked: ChioReceipt = serde_json::from_slice(&package)?;
    assert_eq!(unpacked.id, response.receipt.id);
    assert!(
        unpacked.verify_signature()?,
        "serialized receipt package must verify"
    );
    Ok(())
}

#[test]
fn chiodos_runtime_admission_hook_denies_before_tool_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chiodos-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chiodos-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chiodos-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chiodos-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some("chiodos runtime admission denied"));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("deny metadata missing"))?;
    assert_eq!(metadata["chiodos_runtime"]["admission_id"], "adm-denied");
    assert_eq!(metadata["chiodos_runtime"]["accepted"], false);
    assert_eq!(
        metadata["chiodos_runtime"]["failure_code"],
        "test_runtime_deny"
    );
    Ok(())
}

#[test]
fn chiodos_runtime_admission_hook_denies_federated_call_before_dispatch_or_cosign(
) -> Result<(), Box<dyn std::error::Error>> {
    let origin_kp = Keypair::generate();
    let origin_kernel_id = "kernel.chiodos-buyer";
    let tool_host_kernel_id = "kernel.chiodos-vendor";

    let mut kernel = make_kernel(make_config());
    kernel.set_federation_local_kernel_id(tool_host_kernel_id);
    let path = unique_receipt_db_path("chiodos-runtime-deny-no-cosign");
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path)?));

    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chiodos-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let trust = KernelTrustExchange::new(tool_host_kernel_id, kernel.config.keypair.clone())
        .with_trusted_peer(origin_kernel_id, origin_kp.public_key());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())?;
    let peer = handshake_and_pin(&trust, origin_kernel_id, &origin_kp, now);
    let mut kernel = kernel.with_federation_peers(vec![peer]);

    let cosigner_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_federation_cosigner(std::sync::Arc::new(CountingRejectingCosigner {
        calls: std::sync::Arc::clone(&cosigner_calls),
    }));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(DenyingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chiodos-runtime",
            "destructive_update",
        )]),
        300,
    );
    let mut request = make_request_with_arguments(
        "req-chiodos-runtime-deny",
        &cap,
        "destructive_update",
        "srv-chiodos-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );
    request.federated_origin_kernel_id = Some(origin_kernel_id.to_string());

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some("chiodos runtime admission denied"));
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(
        cosigner_calls.load(Ordering::SeqCst),
        0,
        "runtime admission denial must not request federation cosign"
    );
    assert!(
        response.receipt.verify_signature()?,
        "deny response receipt signature must verify"
    );
    assert!(response.receipt.is_denied());
    assert_eq!(kernel.receipt_log().len(), 1);
    assert_eq!(kernel.receipt_log().receipts()[0].id, response.receipt.id);
    Ok(())
}

#[test]
fn chiodos_runtime_admission_hook_allows_dispatch_and_records_metadata(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chiodos-runtime",
        vec!["destructive_update"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(AllowingRuntimeAdmissionHook {
        calls: std::sync::Arc::clone(&admission_calls),
    }));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant(
            "srv-chiodos-runtime",
            "destructive_update",
        )]),
        300,
    );
    let request = make_request_with_arguments(
        "req-chiodos-runtime-allow",
        &cap,
        "destructive_update",
        "srv-chiodos-runtime",
        serde_json::json!({"record": "vendor-ledger-7", "value": "closed"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request)?;

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(admission_calls.load(Ordering::SeqCst), 1);
    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    let output = tool_call_value_output(response.output)
        .ok_or_else(|| std::io::Error::other("tool output missing"))?;
    assert_eq!(output["tool"], "destructive_update");
    let metadata = response
        .receipt
        .metadata
        .ok_or_else(|| std::io::Error::other("allow metadata missing"))?;
    assert_eq!(metadata["chiodos_runtime"]["admission_id"], "adm-allowed");
    assert_eq!(metadata["chiodos_runtime"]["accepted"], true);
    assert_eq!(metadata["chiodos_runtime"]["observe_only"], true);
    Ok(())
}

#[test]
fn chiodos_runtime_live_parent_and_vendor_calls_expose_package_valid_receipts(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut kernel = make_kernel(make_config());
    let invocations = std::sync::Arc::new(AtomicU64::new(0));
    kernel.register_tool_server(Box::new(SideEffectServer::new(
        "srv-chiodos-live",
        vec!["parent_decision", "vendor_quote"],
        std::sync::Arc::clone(&invocations),
    )));

    let admission_calls = std::sync::Arc::new(AtomicU64::new(0));
    kernel.set_runtime_admission_hook(std::sync::Arc::new(
        LiveReceiptAllowingRuntimeAdmissionHook {
            calls: std::sync::Arc::clone(&admission_calls),
        },
    ));

    let agent_kp = make_keypair();
    let cap = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![
            make_grant("srv-chiodos-live", "parent_decision"),
            make_grant("srv-chiodos-live", "vendor_quote"),
        ]),
        300,
    );
    let parent_request = make_request_with_arguments(
        "req-chiodos-live-parent",
        &cap,
        "parent_decision",
        "srv-chiodos-live",
        serde_json::json!({"workflow": "chiodos-7.8", "step": "parent"}),
    );
    let vendor_request = make_request_with_arguments(
        "req-chiodos-live-vendor-a",
        &cap,
        "vendor_quote",
        "srv-chiodos-live",
        serde_json::json!({"workflow": "chiodos-7.8", "step": "vendor-a"}),
    );

    let parent_response = kernel.evaluate_tool_call_blocking(&parent_request)?;
    let vendor_response = kernel.evaluate_tool_call_blocking(&vendor_request)?;

    assert_eq!(admission_calls.load(Ordering::SeqCst), 2);
    assert_eq!(invocations.load(Ordering::SeqCst), 2);
    assert_package_valid_allow_receipt(&parent_response, &parent_request)?;
    assert_package_valid_allow_receipt(&vendor_response, &vendor_request)?;

    let receipt_log = kernel.receipt_log();
    assert_eq!(receipt_log.len(), 2);
    assert_eq!(receipt_log.receipts()[0].id, parent_response.receipt.id);
    assert_eq!(receipt_log.receipts()[1].id, vendor_response.receipt.id);
    assert_ne!(parent_response.receipt.id, vendor_response.receipt.id);
    Ok(())
}
