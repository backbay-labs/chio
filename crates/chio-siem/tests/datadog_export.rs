// Integration tests for DatadogExporter against a wiremock mock server.

use std::collections::BTreeSet;

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction};
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportError;
use chio_siem::exporters::datadog::{DatadogConfig, DatadogExporter};
use chio_siem::Exporter;
use chio_test_support::prelude::*;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn allow_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
        .test_expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-dd-allow".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c1".to_string(),
            policy_hash: "p1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .test_expect("sign allow")
}

fn deny_receipt(id: &str, guard: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(serde_json::json!({"cmd": "cat /etc/shadow"}))
        .test_expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_001,
            capability_id: "cap-dd-deny".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Deny {
                reason: "file not permitted".to_string(),
                guard: guard.to_string(),
            }),
            receipt_kind: chio_core::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c2".to_string(),
            policy_hash: "p2".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: guard.to_string(),
                verdict: false,
                details: Some("forbidden path match".to_string()),
            }],
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .test_expect("sign deny")
}

#[tokio::test]
async fn datadog_posts_log_array_with_api_key_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/logs"))
        .and(header("DD-API-KEY", "dd-key-test"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;

    let config = DatadogConfig {
        api_key: "dd-key-test".to_string(),
        site: "datadoghq.com".to_string(),
        service: "chio".to_string(),
        source: "chio".to_string(),
        tags: vec!["env:test".to_string()],
        hostname: Some("test-host".to_string()),
        ..DatadogConfig::default()
    };
    let exporter =
        DatadogExporter::new_with_base_url_for_tests(config, &server.uri()).test_expect("builds");

    let allow = allow_receipt("dd-001");
    let trusted = BTreeSet::from([allow.kernel_key.to_hex()]);
    let events = vec![
        SiemEvent::from_receipt_with_trusted_kernel_keys(allow, Some(&trusted)),
        SiemEvent::from_receipt(deny_receipt("dd-002", "ForbiddenPathGuard")),
    ];

    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch ok: {result:?}");
    assert_eq!(result.test_unwrap(), 2);

    let received = server.received_requests().await.test_unwrap();
    assert_eq!(received.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&received[0].body).test_expect("json");
    let arr = body.as_array().test_expect("array");
    assert_eq!(arr.len(), 2);

    // First entry is an allow.
    assert_eq!(arr[0].get("status").and_then(|v| v.as_str()), Some("info"));
    assert_eq!(
        arr[0].get("ddsource").and_then(|v| v.as_str()),
        Some("chio")
    );
    assert_eq!(arr[0].get("service").and_then(|v| v.as_str()), Some("chio"));
    let tags0 = arr[0]
        .get("ddtags")
        .and_then(|v| v.as_str())
        .test_expect("ddtags str");
    assert!(tags0.contains("env:test"));
    assert!(tags0.contains("outcome:allow"));

    // Second entry is a deny on a High-severity guard.
    assert_eq!(arr[1].get("status").and_then(|v| v.as_str()), Some("error"));
    let tags1 = arr[1]
        .get("ddtags")
        .and_then(|v| v.as_str())
        .test_expect("ddtags str");
    assert!(tags1.contains("outcome:mediated_decision"));
    assert!(tags1.contains("receipt_kind:mediated_decision"));
    assert!(tags1.contains("boundary_class:prevent"));
    assert!(tags1.contains("severity:high"));
    assert!(tags1.contains("guard:ForbiddenPathGuard"));
    assert!(tags1.contains("evidence_guard:ForbiddenPathGuard"));
    assert_eq!(
        arr[1].get("result").and_then(|v| v.as_str()),
        Some("Denied")
    );
    assert_eq!(
        arr[1].get("authorized").and_then(|v| v.as_bool()),
        Some(false)
    );
}

#[tokio::test]
async fn datadog_returns_http_error_on_500() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/logs"))
        .respond_with(ResponseTemplate::new(500).set_body_raw("upstream", "text/plain"))
        .mount(&server)
        .await;

    let config = DatadogConfig {
        api_key: "dd-key".to_string(),
        ..DatadogConfig::default()
    };
    let exporter =
        DatadogExporter::new_with_base_url_for_tests(config, &server.uri()).test_expect("builds");

    let events = vec![SiemEvent::from_receipt(allow_receipt("dd-500"))];
    let result = exporter.export_batch(&events).await;

    match result.test_unwrap_err() {
        ExportError::HttpError(msg) => {
            assert!(msg.contains("500"), "should mention 500, got {msg}");
        }
        other => panic!("expected HttpError, got {other:?}"),
    }
}

#[tokio::test]
async fn datadog_rejects_empty_api_key() {
    let config = DatadogConfig {
        api_key: "".to_string(),
        ..DatadogConfig::default()
    };
    assert!(DatadogExporter::new(config).is_err());
}
