// Integration tests for WebhookExporter against a wiremock mock server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportError;
use chio_siem::exporters::webhook::{WebhookAuth, WebhookConfig, WebhookExporter, WebhookRetry};
use chio_siem::AlertSeverity;
use chio_siem::Exporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
use zeroize::Zeroizing;

fn allow_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action =
        ToolCallAction::from_parameters(serde_json::json!({})).expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap".to_string(),
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
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign")
}

fn deny_receipt(id: &str, guard: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    let action =
        ToolCallAction::from_parameters(serde_json::json!({})).expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_001,
            capability_id: "cap".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Some(Decision::Deny {
                reason: "denied".to_string(),
                guard: guard.to_string(),
            }),
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
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign")
}

#[tokio::test]
async fn webhook_posts_with_bearer_auth() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header("Authorization", "Bearer secret-token"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = WebhookConfig {
        url: format!("{}/hook", server.uri()),
        auth: WebhookAuth::Bearer(Zeroizing::new("secret-token".to_string())),
        retry: WebhookRetry {
            max_retries: 0,
            base_backoff_ms: 0,
        },
        ..WebhookConfig::default()
    };
    let exporter = WebhookExporter::new_plaintext_for_tests(config).expect("builds");

    let events = vec![SiemEvent::from_receipt(allow_receipt("wh-001"))];
    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch ok: {result:?}");
    assert_eq!(result.unwrap(), 1);
}

/// Retries on 503, then succeeds on second attempt.
struct FlakyResponder {
    calls: Arc<AtomicUsize>,
    fail_times: usize,
}

impl Respond for FlakyResponder {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n < self.fail_times {
            ResponseTemplate::new(503)
        } else {
            ResponseTemplate::new(200)
        }
    }
}

#[tokio::test]
async fn webhook_retries_on_5xx_then_succeeds() {
    let server = MockServer::start().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let responder = FlakyResponder {
        calls: calls.clone(),
        fail_times: 1,
    };

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(responder)
        .mount(&server)
        .await;

    let config = WebhookConfig {
        url: format!("{}/hook", server.uri()),
        retry: WebhookRetry {
            max_retries: 2,
            base_backoff_ms: 5,
        },
        ..WebhookConfig::default()
    };
    let exporter = WebhookExporter::new_plaintext_for_tests(config).expect("builds");

    let events = vec![SiemEvent::from_receipt(allow_receipt("wh-retry"))];
    let result = exporter.export_batch(&events).await;
    assert!(
        result.is_ok(),
        "export_batch should succeed after retry: {result:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "should have retried once");
}

#[tokio::test]
async fn webhook_fails_fast_on_400() {
    let server = MockServer::start().await;

    let calls = Arc::new(AtomicUsize::new(0));
    let calls_clone = calls.clone();

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(move |_: &Request| {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            ResponseTemplate::new(400)
        })
        .mount(&server)
        .await;

    let config = WebhookConfig {
        url: format!("{}/hook", server.uri()),
        retry: WebhookRetry {
            max_retries: 5,
            base_backoff_ms: 1,
        },
        ..WebhookConfig::default()
    };
    let exporter = WebhookExporter::new_plaintext_for_tests(config).expect("builds");

    let events = vec![SiemEvent::from_receipt(allow_receipt("wh-400"))];
    let result = exporter.export_batch(&events).await;

    match result.unwrap_err() {
        ExportError::HttpError(msg) => assert!(msg.contains("400"), "message: {msg}"),
        other => panic!("expected HttpError, got {other:?}"),
    }
    // No retries on non-transient 4xx.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn webhook_errors_redact_url_secrets() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;

    let config = WebhookConfig {
        url: format!(
            "{}/hook?token=supersecret&client_secret=alsosensitive",
            server.uri()
        ),
        retry: WebhookRetry {
            max_retries: 0,
            base_backoff_ms: 0,
        },
        ..WebhookConfig::default()
    };
    let exporter = WebhookExporter::new_plaintext_for_tests(config).expect("builds");

    let events = vec![SiemEvent::from_receipt(allow_receipt("wh-redact-url"))];
    let result = exporter.export_batch(&events).await;
    let err = result.expect_err("400 response should fail");
    let message = err.to_string();

    assert!(
        !message.contains("supersecret") && !message.contains("alsosensitive"),
        "webhook error must not contain query secrets: {message}"
    );
    assert!(
        !message.contains("token=") && !message.contains("client_secret="),
        "webhook error must not contain secret-bearing query keys: {message}"
    );
    assert!(
        message.contains("webhook endpoint returned 400"),
        "message should keep useful failure context: {message}"
    );
}

#[tokio::test]
async fn webhook_filters_by_min_severity() {
    let server = MockServer::start().await;

    // No expectation means zero requests are allowed; any POST will fail the test.
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let config = WebhookConfig {
        url: format!("{}/hook", server.uri()),
        min_severity: Some(AlertSeverity::High),
        retry: WebhookRetry {
            max_retries: 0,
            base_backoff_ms: 0,
        },
        ..WebhookConfig::default()
    };
    let exporter = WebhookExporter::new_plaintext_for_tests(config).expect("builds");

    // Allow receipts sit at Info severity, below the High threshold.
    let events = vec![SiemEvent::from_receipt(allow_receipt("wh-filtered"))];
    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 1, "filtered events count as successful");
}

#[tokio::test]
async fn webhook_exclude_guards_drops_matching_events() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;

    let config = WebhookConfig {
        url: format!("{}/hook", server.uri()),
        exclude_guards: vec!["NoisyGuard".to_string()],
        retry: WebhookRetry {
            max_retries: 0,
            base_backoff_ms: 0,
        },
        ..WebhookConfig::default()
    };
    let exporter = WebhookExporter::new_plaintext_for_tests(config).expect("builds");

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "wh-excl",
        "NoisyGuard",
    ))];
    let result = exporter.export_batch(&events).await.expect("ok");
    assert_eq!(result, 1);
}

#[test]
fn webhook_new_rejects_empty_url() {
    let cfg = WebhookConfig {
        url: String::new(),
        ..WebhookConfig::default()
    };
    assert!(WebhookExporter::new(cfg).is_err());
}
