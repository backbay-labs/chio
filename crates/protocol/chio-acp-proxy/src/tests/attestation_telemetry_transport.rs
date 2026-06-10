#[test]
fn telemetry_helpers_map_receipts_and_certificates() {
    let signer = Keypair::generate();
    let receipt = make_receipt(
        &signer,
        "receipt-telemetry",
        123,
        "fs/write_text_file",
        Decision::Deny {
            reason: "blocked".to_string(),
            guard: "fs_guard".to_string(),
        },
        vec![GuardEvidence {
            guard_name: "fs_guard".to_string(),
            verdict: false,
            details: Some("denied".to_string()),
        }],
    );
    let trace_id = derive_trace_id("session-telemetry");
    let span = receipt_to_span(&receipt, &trace_id, None);

    assert_eq!(trace_id.len(), 32);
    assert_eq!(span.trace_id, trace_id);
    assert_eq!(span.span_id.len(), 16);
    assert_eq!(span.tool_name, "fs/write_text_file");
    assert_eq!(span.verdict, "deny");
    assert_eq!(span.start_time_nanos, 123_000_000_000);
    assert_eq!(span.events.len(), 1);
    assert!(span
        .attributes
        .iter()
        .any(|attr| attr.key == "chio.deny_reason" && attr.value == "blocked"));
    assert_eq!(span.events[0].name, "guard.fs_guard");

    let cert_body = ComplianceCertificateBody {
        schema: COMPLIANCE_CERTIFICATE_SCHEMA.to_string(),
        session_id: "session-telemetry".to_string(),
        issued_at: 456,
        receipt_count: 2,
        first_receipt_at: 123,
        last_receipt_at: 124,
        all_signatures_valid: true,
        chain_continuous: true,
        scope_compliant: true,
        budget_compliant: true,
        guards_compliant: true,
        anomalies: Vec::new(),
        kernel_key: signer.public_key(),
    };
    let cert_event = compliance_certificate_event(&cert_body);
    assert_eq!(cert_event.name, "chio.compliance.certificate");
    assert_eq!(cert_event.timestamp_nanos, 456_000_000_000);
    assert!(cert_event
        .attributes
        .iter()
        .any(|attr| attr.key == "cert.receipt_count" && attr.value == "2"));

    let root = session_root_span("session-telemetry", &trace_id, 100, 200);
    assert_eq!(root.tool_name, "chio.session");
    assert_eq!(root.verdict, "session");
    assert_eq!(root.start_time_nanos, 100_000_000_000);
    assert_eq!(root.end_time_nanos, 200_000_000_000);

    let config = TelemetryConfig::default();
    assert!(!config.enabled);
    assert_eq!(config.service_name, "chio-acp-proxy");
}

#[test]
fn telemetry_exporters_write_and_fail_cleanly() {
    let span = ReceiptSpan {
        trace_id: derive_trace_id("session-export"),
        span_id: "0123456789abcdef".to_string(),
        parent_span_id: String::new(),
        tool_name: "terminal/create".to_string(),
        verdict: "allow".to_string(),
        capability_id: "capability-1".to_string(),
        start_time_nanos: 1,
        end_time_nanos: 1,
        attributes: vec![SpanAttribute {
            key: "chio.test".to_string(),
            value: "true".to_string(),
        }],
        events: Vec::new(),
    };

    let logger = LoggingSpanExporter;
    assert_eq!(
        logger
            .export(std::slice::from_ref(&span))
            .expect("logging export should work"),
        1
    );
    logger.flush().expect("flush should succeed");
    logger.shutdown().expect("shutdown should succeed");

    let output_path =
        std::env::temp_dir().join(format!("chio-acp-proxy-telemetry-{}.jsonl", now_secs()));
    let exporter = JsonFileExporter::new(output_path.to_string_lossy().into_owned());
    assert_eq!(
        exporter
            .export(std::slice::from_ref(&span))
            .expect("json export should work"),
        1
    );
    exporter.flush().expect("flush should succeed");
    exporter.shutdown().expect("shutdown should succeed");

    let contents = fs::read_to_string(&output_path).expect("jsonl output should exist");
    assert!(contents.contains("\"toolName\":\"terminal/create\""));
    let _ = fs::remove_file(&output_path);

    let bad_exporter =
        JsonFileExporter::new(std::env::temp_dir().to_string_lossy().into_owned());
    let error = bad_exporter
        .export(std::slice::from_ref(&span))
        .expect_err("directory path should fail");
    assert!(matches!(error, TelemetryExportError::ExportFailed(_)));
}

#[test]
fn transport_round_trips_json_and_lifecycle() {
    let mut transport = AcpTransport::spawn(
        "sh",
        &["-c".to_string(), "cat".to_string()],
        &[("CHIO_PROXY_TEST_ENV".to_string(), "1".to_string())],
    )
    .expect("transport should spawn");

    let message = json!({
        "jsonrpc": "2.0",
        "method": "ping",
        "params": {"ok": true}
    });
    transport.send(&message).expect("send should succeed");
    let received = transport.recv().expect("recv should succeed");
    assert_eq!(received, Some(message));

    transport.kill().expect("kill should succeed");
    let status = transport.wait().expect("wait should succeed");
    assert!(status.is_none());
}

#[test]
fn transport_handles_eof_and_invalid_json() {
    let mut eof_transport =
        AcpTransport::spawn("sh", &["-c".to_string(), "exit 0".to_string()], &[])
            .expect("transport should spawn");
    assert_eq!(eof_transport.recv().expect("recv should succeed"), None);
    assert_eq!(eof_transport.wait().expect("wait should succeed"), Some(0));

    let mut invalid_transport = AcpTransport::spawn(
        "sh",
        &["-c".to_string(), "printf 'not-json\\n'".to_string()],
        &[],
    )
    .expect("transport should spawn");
    let error = invalid_transport
        .recv()
        .expect_err("invalid json should return protocol error");
    assert!(matches!(error, AcpProxyError::Protocol(_)));
    assert_eq!(
        invalid_transport.wait().expect("wait should succeed"),
        Some(0)
    );
}

#[test]
fn proxy_with_kernel_wraps_transport_and_interceptor() {
    let config = AcpProxyConfig::new("sh", "deadbeef")
        .with_agent_args(vec!["-c".to_string(), "cat".to_string()])
        .with_allowed_path_prefix("/workspace")
        .with_allowed_command("cargo")
        .with_server_id("proxy-test");

    let mut proxy = AcpProxy::start_with_kernel(
        config.clone(),
        Some(Box::new(DummySigner(Keypair::generate()))),
        Some(Box::new(DummyChecker)),
        AcpAttestationMode::Required,
    )
    .expect("proxy should start");

    assert_eq!(proxy.config().server_id(), "proxy-test");
    let _ = proxy.interceptor();

    let client_message = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });
    match proxy
        .process_client_message(&client_message)
        .expect("client message should process")
    {
        InterceptResult::Forward(value) => assert_eq!(value, client_message),
        other => panic!("expected Forward, got {:?}", other),
    }

    let agent_message = json!({
        "jsonrpc": "2.0",
        "method": "session/update",
        "params": {
            "sessionId": "s1",
            "update": {
                "toolCallId": "tool-1",
                "title": "Build",
                "kind": "execute",
                "status": "running"
            }
        }
    });
    match proxy
        .process_agent_message(&agent_message)
        .expect("agent message should process")
    {
        InterceptResult::ForwardWithReceipt(value, receipt) => {
            assert_eq!(value, agent_message);
            assert_eq!(receipt.tool_call_id, "tool-1");
        }
        other => panic!("expected ForwardWithReceipt, got {:?}", other),
    }

    let echoed = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "echo",
        "params": {"value": 1}
    });
    proxy.send_to_agent(&echoed).expect("send should succeed");
    let received = proxy.recv_from_agent().expect("recv should succeed");
    assert_eq!(received, Some(echoed));

    proxy.shutdown().expect("shutdown should succeed");
}
