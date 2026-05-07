// Integration tests for ElasticsearchExporter against a wiremock mock server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, FinancialReceiptMetadata, SettlementStatus,
    ToolCallAction,
};
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportError;
use chio_siem::exporters::elastic::{ElasticAuthConfig, ElasticConfig, ElasticsearchExporter};
use chio_siem::Exporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// -- Helpers ------------------------------------------------------------------

fn sample_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-elastic-test".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
                .expect("action parameters serialize"),
            decision: Decision::Allow,
            content_hash: "content-hash-test".to_string(),
            policy_hash: "policy-hash-test".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("ChioReceipt::sign must succeed in tests")
}

fn sample_receipt_with_financial(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let financial = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 750,
        currency: "USD".to_string(),
        budget_remaining: 9_250,
        budget_total: 10_000,
        delegation_depth: 0,
        root_budget_holder: "billing-root".to_string(),
        payment_reference: Some("ref-abc".to_string()),
        settlement_status: SettlementStatus::Pending,
        cost_breakdown: None,
        oracle_evidence: None,
        attempted_cost: None,
    };
    let metadata = serde_json::json!({
        "financial": serde_json::to_value(&financial).expect("financial metadata serializes")
    });
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_002,
            capability_id: "cap-elastic-financial".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "python".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"script": "main.py"}))
                .expect("action parameters serialize"),
            decision: Decision::Allow,
            content_hash: "content-hash-financial".to_string(),
            policy_hash: "policy-hash-financial".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("ChioReceipt::sign must succeed in tests")
}

fn api_key_config(endpoint: &str) -> ElasticConfig {
    ElasticConfig {
        endpoint: endpoint.to_string(),
        index_name: "chio-receipts".to_string(),
        auth: ElasticAuthConfig::ApiKey("test-api-key".to_string()),
        ..ElasticConfig::default()
    }
}

// -- Tests --------------------------------------------------------------------

/// ElasticsearchExporter sends correctly formatted NDJSON and receives 200 OK with no errors.
#[tokio::test]
async fn elastic_bulk_sends_correct_ndjson() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/_bulk"))
        .and(header("Content-Type", "application/x-ndjson"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(r#"{"errors":false,"items":[]}"#, "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = api_key_config(&server.uri());
    let exporter = ElasticsearchExporter::new_plaintext_for_tests(config).expect("exporter builds");

    let receipt1 = sample_receipt("es-rcpt-001");
    let receipt2 = sample_receipt("es-rcpt-002");
    let events = vec![
        SiemEvent::from_receipt(receipt1),
        SiemEvent::from_receipt(receipt2),
    ];

    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch should return Ok: {result:?}");
    assert_eq!(result.unwrap(), 2, "should report 2 events exported");

    // Verify NDJSON format: 4 non-empty lines (2 action + 2 document lines).
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "should receive exactly 1 HTTP request");

    let body_str = String::from_utf8(received[0].body.clone()).expect("body is valid UTF-8");
    let lines: Vec<&str> = body_str.split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        4,
        "should have 4 non-empty NDJSON lines (2 action + 2 document)"
    );

    // Parse first action line.
    let action0: serde_json::Value = serde_json::from_str(lines[0]).expect("line 0 is valid JSON");
    let index0 = action0.get("index").expect("action must have 'index' key");
    assert_eq!(
        index0.get("_index").and_then(|v| v.as_str()),
        Some("chio-receipts"),
        "_index must be 'chio-receipts'"
    );
    assert_eq!(
        index0.get("_id").and_then(|v| v.as_str()),
        Some("es-rcpt-001"),
        "_id must match first receipt id"
    );

    // Parse first document line.
    let doc0: serde_json::Value = serde_json::from_str(lines[1]).expect("line 1 is valid JSON");
    assert_eq!(
        doc0.get("id").and_then(|v| v.as_str()),
        Some("es-rcpt-001"),
        "document id must match receipt id"
    );
    assert!(
        doc0.get("timestamp").is_some(),
        "document must include timestamp field"
    );

    // Parse second action line.
    let action1: serde_json::Value = serde_json::from_str(lines[2]).expect("line 2 is valid JSON");
    let index1 = action1
        .get("index")
        .expect("second action must have 'index' key");
    assert_eq!(
        index1.get("_id").and_then(|v| v.as_str()),
        Some("es-rcpt-002"),
        "_id must match second receipt id"
    );
}

/// ElasticsearchExporter detects partial failure from bulk response body (HTTP 200 + errors:true).
#[tokio::test]
async fn elastic_bulk_detects_partial_failure() {
    let server = MockServer::start().await;

    // ES returns HTTP 200 even for partial failures; errors field signals the problem.
    let partial_failure_body = serde_json::json!({
        "errors": true,
        "items": [
            {"index": {"_id": "es-rcpt-pf-001", "status": 201, "_index": "chio-receipts"}},
            {
                "index": {
                    "_id": "es-rcpt-pf-002",
                    "status": 400,
                    "_index": "chio-receipts",
                    "error": {
                        "type": "mapper_parsing_exception",
                        "reason": "failed to parse field"
                    }
                }
            }
        ]
    });

    Mock::given(method("POST"))
        .and(path("/_bulk"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(partial_failure_body.to_string(), "application/json"),
        )
        .mount(&server)
        .await;

    let config = api_key_config(&server.uri());
    let exporter = ElasticsearchExporter::new_plaintext_for_tests(config).expect("exporter builds");

    let events = vec![
        SiemEvent::from_receipt(sample_receipt("es-rcpt-pf-001")),
        SiemEvent::from_receipt(sample_receipt("es-rcpt-pf-002")),
    ];

    let result = exporter.export_batch(&events).await;
    assert!(
        result.is_err(),
        "export_batch should return Err for partial failure"
    );

    match result.unwrap_err() {
        ExportError::PartialFailure {
            succeeded, failed, ..
        } => {
            assert_eq!(succeeded, 1, "1 event should succeed");
            assert_eq!(failed, 1, "1 event should fail");
        }
        other => panic!("expected ExportError::PartialFailure, got: {other:?}"),
    }
}

/// ElasticsearchExporter includes FinancialReceiptMetadata in exported document payloads.
#[tokio::test]
async fn elastic_financial_metadata_in_payload() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/_bulk"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(r#"{"errors":false,"items":[]}"#, "application/json"),
        )
        .mount(&server)
        .await;

    let config = api_key_config(&server.uri());
    let exporter = ElasticsearchExporter::new_plaintext_for_tests(config).expect("exporter builds");

    let receipt = sample_receipt_with_financial("es-rcpt-fin-001");
    let events = vec![SiemEvent::from_receipt(receipt)];

    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch should return Ok: {result:?}");

    // Capture request body and find the document line (line index 1).
    let received = server.received_requests().await.unwrap();
    let body_str = String::from_utf8(received[0].body.clone()).expect("body is valid UTF-8");
    let lines: Vec<&str> = body_str.split('\n').filter(|l| !l.is_empty()).collect();
    assert!(lines.len() >= 2, "must have at least 2 NDJSON lines");

    // Line 1 is the document.
    let doc: serde_json::Value =
        serde_json::from_str(lines[1]).expect("document line is valid JSON");

    let cost = doc
        .get("metadata")
        .and_then(|m| m.get("financial"))
        .and_then(|f| f.get("cost_charged"))
        .and_then(|c| c.as_u64());

    assert_eq!(
        cost,
        Some(750),
        "metadata.financial.cost_charged should be 750 in exported document"
    );
}

/// ElasticsearchExporter::new rejects plaintext http:// endpoints to keep API
/// keys and Basic credentials off the cleartext wire.
#[test]
fn elastic_new_rejects_plaintext_http() {
    let config = ElasticConfig {
        endpoint: "http://es.example.com:9200".to_string(),
        index_name: "chio-receipts".to_string(),
        auth: ElasticAuthConfig::ApiKey("must-not-leak".to_string()),
        ..ElasticConfig::default()
    };

    let result = ElasticsearchExporter::new(config);
    assert!(
        matches!(result, Err(ExportError::HttpError(_))),
        "ElasticsearchExporter::new must reject http:// endpoints"
    );
    if let Err(ExportError::HttpError(message)) = result {
        assert!(
            message.contains("https://"),
            "rejection message should mention the https:// requirement, got: {message}"
        );
    }
}

/// ElasticsearchExporter::new accepts https:// endpoints (build-time check
/// only; no network call).
#[test]
fn elastic_new_accepts_https() {
    let config = ElasticConfig {
        endpoint: "https://es.example.com:9200".to_string(),
        index_name: "chio-receipts".to_string(),
        auth: ElasticAuthConfig::ApiKey("test-api-key".to_string()),
        egress_contract: Some(
            chio_egress_contract::HttpEgressContract::permissive_for_tests("es.example.com:9200"),
        ),
        ..ElasticConfig::default()
    };

    let result = ElasticsearchExporter::new(config);
    assert!(
        result.is_ok(),
        "ElasticsearchExporter::new must accept https:// endpoints"
    );
}

/// Regression for the case-sensitive scheme check that allowed `HTTP://`
/// (uppercase) endpoints to bypass TLS enforcement. URL schemes are
/// case-insensitive per RFC 3986, so any cased variant of `http` must be
/// rejected. We exercise both `HTTP://` and `Http://`.
#[test]
fn elastic_new_rejects_uppercase_and_mixed_case_http_scheme() {
    for plaintext in ["HTTP://es.example.com:9200", "Http://es.example.com:9200"] {
        let config = ElasticConfig {
            endpoint: plaintext.to_string(),
            index_name: "chio-receipts".to_string(),
            auth: ElasticAuthConfig::ApiKey("must-not-leak".to_string()),
            ..ElasticConfig::default()
        };
        let result = ElasticsearchExporter::new(config);
        assert!(
            matches!(result, Err(ExportError::HttpError(_))),
            "ElasticsearchExporter::new must reject {plaintext} (case-insensitive scheme)"
        );
    }
}

/// HTTPS schemes are case-insensitive too, so `HTTPS://` must be accepted.
#[test]
fn elastic_new_accepts_uppercase_https_scheme() {
    let config = ElasticConfig {
        endpoint: "HTTPS://es.example.com:9200".to_string(),
        index_name: "chio-receipts".to_string(),
        auth: ElasticAuthConfig::ApiKey("test-api-key".to_string()),
        egress_contract: Some(
            chio_egress_contract::HttpEgressContract::permissive_for_tests("es.example.com:9200"),
        ),
        ..ElasticConfig::default()
    };
    let result = ElasticsearchExporter::new(config);
    assert!(
        result.is_ok(),
        "ElasticsearchExporter::new must accept HTTPS:// (case-insensitive)"
    );
}
