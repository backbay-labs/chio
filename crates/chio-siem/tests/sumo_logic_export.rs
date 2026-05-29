// Integration tests for SumoLogicExporter against a wiremock mock server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_siem::event::SiemEvent;
use chio_siem::exporters::sumo_logic::{SumoLogicConfig, SumoLogicExporter, SumoLogicFormat};
use chio_siem::Exporter;
use std::collections::BTreeSet;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-sumo".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
                .expect("action parameters serialize"),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign")
}

fn trusted_event(receipt: ChioReceipt) -> SiemEvent {
    let trusted_kernel_keys = BTreeSet::from([receipt.kernel_key.to_hex()]);
    SiemEvent::from_receipt_with_trusted_kernel_keys(receipt, Some(&trusted_kernel_keys))
}

#[tokio::test]
async fn sumo_json_posts_ndjson_with_sumo_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/receiver"))
        .and(header("Content-Type", "application/json"))
        .and(header("X-Sumo-Category", "security/chio"))
        .and(header("X-Sumo-Name", "chio"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = SumoLogicConfig {
        http_source_url: format!("{}/receiver", server.uri()),
        source_category: "security/chio".to_string(),
        source_name: "chio".to_string(),
        source_host: Some("test-host".to_string()),
        format: SumoLogicFormat::Json,
        ..SumoLogicConfig::default()
    };
    let exporter = SumoLogicExporter::new_plaintext_for_tests(config).expect("builds");

    let first = sample_receipt("sumo-001");
    let first_id = first.id.clone();
    let second = sample_receipt("sumo-002");
    let events = vec![
        SiemEvent::from_receipt(first),
        SiemEvent::from_receipt(second),
    ];
    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch ok: {result:?}");
    assert_eq!(result.unwrap(), 2);

    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8(received[0].body.clone()).expect("utf8");
    let lines: Vec<&str> = body.split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "should be 2 NDJSON lines");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json");
    assert_eq!(
        parsed
            .get("receipt")
            .and_then(|r| r.get("id"))
            .and_then(|v| v.as_str()),
        Some(first_id.as_str())
    );
}

#[tokio::test]
async fn sumo_keyvalue_emits_kv_lines() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/receiver"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = SumoLogicConfig {
        http_source_url: format!("{}/receiver", server.uri()),
        format: SumoLogicFormat::KeyValue,
        ..SumoLogicConfig::default()
    };
    let exporter = SumoLogicExporter::new_plaintext_for_tests(config).expect("builds");
    let receipt = sample_receipt("sumo-kv-1");
    let receipt_id = receipt.id.clone();
    let events = vec![trusted_event(receipt)];
    let _ = exporter.export_batch(&events).await.expect("ok");

    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8(received[0].body.clone()).expect("utf8");
    assert!(body.contains(&format!("receipt_id={receipt_id}")));
    assert!(body.contains("decision=allow"));
}

#[tokio::test]
async fn sumo_rejects_plaintext_http_in_production_new() {
    let cfg = SumoLogicConfig {
        http_source_url: "http://collectors.sumologic.com/receiver/v1/xyz".to_string(),
        ..SumoLogicConfig::default()
    };
    assert!(SumoLogicExporter::new(cfg).is_err());
}

/// Regression: case-sensitive `starts_with("http://")` allowed `HTTP://`
/// (uppercase) URLs to slip past the cleartext check. URL schemes are
/// case-insensitive per RFC 3986; cased variants must be rejected.
#[tokio::test]
async fn sumo_rejects_uppercase_and_mixed_case_http_scheme() {
    for plaintext in [
        "HTTP://collectors.sumologic.com/receiver/v1/xyz",
        "Http://collectors.sumologic.com/receiver/v1/xyz",
    ] {
        let cfg = SumoLogicConfig {
            http_source_url: plaintext.to_string(),
            ..SumoLogicConfig::default()
        };
        assert!(
            SumoLogicExporter::new(cfg).is_err(),
            "SumoLogicExporter::new must reject {plaintext} (case-insensitive scheme)"
        );
    }
}
