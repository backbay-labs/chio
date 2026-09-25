#[test]
fn nested_early_refusals_retain_trace_context_without_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    for case in ["scope", "unregistered", "subject", "expiry"] {
        let config = make_config();
        let signer = config.keypair.clone();
        let mut kernel = make_kernel(config);
        let invocations = std::sync::Arc::new(AtomicU64::new(0));
        kernel.register_tool_server(Box::new(SideEffectServer::new(
            "srv-a",
            vec!["read_file"],
            std::sync::Arc::clone(&invocations),
        )));
        let subject = make_keypair();
        let scope = make_scope(vec![
            make_grant("srv-a", "read_file"),
            make_grant("srv-a", "unregistered"),
        ]);
        let capability = make_capability(&kernel, &subject, scope, 300);
        let session =
            kernel.open_session(subject.public_key().to_hex(), vec![capability.clone()])?;
        kernel.activate_session(&session)?;
        let mut request = make_request(&format!("trace-{case}"), &capability, "read_file", "srv-a");
        match case {
            "scope" => request.tool_name = "delete_file".into(),
            "unregistered" => request.tool_name = "unregistered".into(),
            "subject" => request.agent_id = make_keypair().public_key().to_hex(),
            "expiry" => {
                let mut body = capability.body();
                body.issued_at = current_unix_timestamp().saturating_sub(60);
                body.expires_at = current_unix_timestamp().saturating_sub(1);
                request.capability = CapabilityToken::sign(body, &signer)?;
            }
            _ => unreachable!(),
        }
        let context = make_operation_context(
            &session,
            &request.request_id,
            &subject.public_key().to_hex(),
        );
        let metadata = serde_json::json!({
            "trace_id": "a2eb22a353cc4f0a9b1520da3233bb53", "span_id": "a5e6d7250a734d22",
            "receipt_context": {"request_id": "untrusted-override"},
        });
        let response = runtime.block_on(async {
            kernel
                .evaluate_tool_call_with_nested_flow_client_async(
                    &context,
                    &request,
                    &mut NoopNestedFlowClient,
                    Some(metadata),
                )
                .await
        })?;
        assert_eq!(response.verdict, Verdict::Deny, "{case}");
        assert_eq!(invocations.load(Ordering::SeqCst), 0, "{case}");
        assert!(response.receipt.verify_signature()?);
        let retained = response
            .receipt
            .metadata
            .as_ref()
            .ok_or("Missing receipt metadata")?;
        assert_eq!(
            retained["trace_id"], "a2eb22a353cc4f0a9b1520da3233bb53",
            "{case}"
        );
        assert_eq!(retained["span_id"], "a5e6d7250a734d22", "{case}");
        assert_eq!(
            retained["receipt_context"]["request_id"], request.request_id,
            "{case}"
        );
        assert!(kernel
            .receipt_log()
            .receipts()
            .iter()
            .any(|receipt| receipt.id == response.receipt.id));
    }
    Ok(())
}
