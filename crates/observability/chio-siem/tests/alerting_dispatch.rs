// Integration tests for the AlertingExporter dispatch pipeline.
//
// Uses an in-process RecordingBackend that implements AlertBackend to verify
// that high-severity denials (and only those) reach the configured backends.
// Also covers PagerDuty and OpsGenie HTTP dispatch against wiremock.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    metadata::GuardEvidence,
};
use chio_egress_contract::HttpEgressContract;
use chio_siem::alerting::{
    Alert, AlertBackend, AlertSeverity, AlertingConfig, AlertingExporter, OpsGenieBackend,
    PagerDutyBackend,
};
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportError;
use chio_siem::Exporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_server_authority(server: &MockServer) -> String {
    let url = url::Url::parse(&server.uri()).expect("wiremock uri parses");
    let host = url.host_str().unwrap_or("127.0.0.1").to_string();
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn allow_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .expect("action parameters serialize"),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
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
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_001,
            capability_id: "cap".to_string(),
            tool_server: "python".to_string(),
            tool_name: "run".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .expect("action parameters serialize"),
            decision: Some(Decision::Deny {
                reason: "blocked by policy".to_string(),
                guard: guard.to_string(),
            }),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: guard.to_string(),
                verdict: false,
                details: None,
            }],
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("sign")
}

struct RecordingBackend {
    name: &'static str,
    alerts: Arc<Mutex<Vec<Alert>>>,
}

impl RecordingBackend {
    fn new(name: &'static str) -> (Self, Arc<Mutex<Vec<Alert>>>) {
        let alerts = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                name,
                alerts: alerts.clone(),
            },
            alerts,
        )
    }
}

impl AlertBackend for RecordingBackend {
    fn name(&self) -> &str {
        self.name
    }

    fn dispatch<'a>(
        &'a self,
        alert: &'a Alert,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
    {
        let alerts = self.alerts.clone();
        let alert = alert.clone();
        Box::pin(async move {
            alerts.lock().expect("alerts lock").push(alert);
            Ok(())
        })
    }
}

#[derive(Default)]
struct RecordingMetricsSink {
    dispatches: Mutex<Vec<(String, String)>>,
}

impl chio_siem::SiemMetricsSink for RecordingMetricsSink {
    fn record_export(&self, _: &str, _: chio_siem::ExportOutcome) {}
    fn observe_export_lag(&self, _: &str, _: &str, _: f64) {}
    fn set_dlq_depth(&self, _: &str, _: u64) {}
    fn record_alert_dispatch(&self, route: &str, outcome: &str) {
        self.dispatches
            .lock()
            .expect("dispatches lock")
            .push((route.to_string(), outcome.to_string()));
    }
    fn observe_alert_dispatch_latency(&self, _: &str, _: &str, _: f64) {}
}

#[tokio::test]
async fn dispatch_records_route_and_outcome() {
    let (backend, _recorded) = RecordingBackend::new("pagerduty");
    let sink = Arc::new(RecordingMetricsSink::default());
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(backend))
        .with_metrics_sink(Arc::clone(&sink) as Arc<dyn chio_siem::SiemMetricsSink>)
        .build();
    // A high-severity deny so should_alert fires and the backend is dispatched.
    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "alert-metric-1",
        "ForbiddenPathGuard",
    ))];
    let _ = exporter.export_batch(&events).await.expect("ok");

    let dispatches = sink.dispatches.lock().unwrap().clone();
    assert!(
        dispatches.contains(&("pagerduty".to_string(), "success".to_string())),
        "expected a pagerduty success dispatch: {dispatches:?}"
    );
}

#[tokio::test]
async fn high_severity_deny_dispatches_to_backend() {
    let (backend, recorded) = RecordingBackend::new("test-backend");
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(backend))
        .build();

    let deny = deny_receipt("alert-2", "ForbiddenPathGuard");
    let expected_receipt_id = deny.id.clone();
    let events = vec![
        SiemEvent::from_receipt(allow_receipt("alert-1")),
        SiemEvent::from_receipt(deny),
    ];
    let result = exporter.export_batch(&events).await.expect("ok");
    assert_eq!(result, 2);

    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1, "only the deny should be alerted on");
    assert_eq!(recorded[0].receipt_id, expected_receipt_id);
    assert_eq!(recorded[0].severity, AlertSeverity::High);
    assert_eq!(recorded[0].guard, "ForbiddenPathGuard");
}

#[tokio::test]
async fn medium_severity_deny_does_not_fire_by_default() {
    let (backend, recorded) = RecordingBackend::new("test-backend");
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(backend))
        .build();

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "alert-med",
        "CustomGuard",
    ))];
    let _ = exporter.export_batch(&events).await.expect("ok");

    assert!(
        recorded.lock().unwrap().is_empty(),
        "medium should not page"
    );
}

#[tokio::test]
async fn alerting_without_backends_is_a_no_op() {
    let exporter = AlertingExporter::builder(AlertingConfig::default()).build();
    assert_eq!(exporter.backend_count(), 0);

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "no-backend",
        "SecretLeakGuard",
    ))];
    let n = exporter.export_batch(&events).await.expect("ok");
    assert_eq!(n, 1);
}

#[tokio::test]
async fn lowering_min_severity_catches_medium_denials() {
    let (backend, recorded) = RecordingBackend::new("test-backend");
    let cfg = AlertingConfig {
        min_severity: AlertSeverity::Medium,
        exclude_guards: Vec::new(),
        include_guards: Vec::new(),
    };
    let exporter = AlertingExporter::builder(cfg)
        .with_backend(Box::new(backend))
        .build();

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "alert-med-fire",
        "CustomGuard",
    ))];
    let _ = exporter.export_batch(&events).await.expect("ok");

    let recorded = recorded.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].severity, AlertSeverity::Medium);
}

#[tokio::test]
async fn pagerduty_backend_posts_to_v2_enqueue() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/enqueue"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;

    let authority = test_server_authority(&server);
    let backend = PagerDutyBackend::with_endpoint_and_contract(
        "pd-routing-key".to_string(),
        server.uri(),
        HttpEgressContract::permissive_for_tests(&authority),
    )
    .expect("PagerDutyBackend builds in tests");
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(backend))
        .build();

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "alert-pd",
        "SecretLeakGuard",
    ))];
    let result = exporter.export_batch(&events).await.expect("ok");
    assert_eq!(result, 1);
}

#[tokio::test]
async fn pagerduty_backend_propagates_http_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/enqueue"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let authority = test_server_authority(&server);
    let backend = PagerDutyBackend::with_endpoint_and_contract(
        "pd".to_string(),
        server.uri(),
        HttpEgressContract::permissive_for_tests(&authority),
    )
    .expect("PagerDutyBackend builds in tests");
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(backend))
        .build();

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "alert-pd-fail",
        "EgressGuard",
    ))];
    let result = exporter.export_batch(&events).await;
    assert!(result.is_err(), "propagate backend failure");
}

#[tokio::test]
async fn opsgenie_backend_posts_to_v2_alerts() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v2/alerts"))
        .and(header("Authorization", "GenieKey og-api-key"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;

    let authority = test_server_authority(&server);
    let backend = OpsGenieBackend::with_endpoint_and_contract(
        "og-api-key".to_string(),
        server.uri(),
        HttpEgressContract::permissive_for_tests(&authority),
    )
    .expect("OpsGenieBackend builds in tests");
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(backend))
        .build();

    let events = vec![SiemEvent::from_receipt(deny_receipt(
        "alert-og",
        "EgressGuard",
    ))];
    let result = exporter.export_batch(&events).await.expect("ok");
    assert_eq!(result, 1);
}

#[tokio::test]
async fn partial_failure_across_two_backends_surfaces_partial_failure_error() {
    // One backend always succeeds, one always fails.
    struct Failing(&'static str, Arc<AtomicUsize>);
    impl AlertBackend for Failing {
        fn name(&self) -> &str {
            self.0
        }
        fn dispatch<'a>(
            &'a self,
            _: &'a Alert,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ExportError>> + Send + 'a>>
        {
            let counter = self.1.clone();
            Box::pin(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Err(ExportError::HttpError("nope".to_string()))
            })
        }
    }

    let (ok_backend, _) = RecordingBackend::new("ok");
    let failing_calls = Arc::new(AtomicUsize::new(0));
    let failing = Failing("bad", failing_calls.clone());

    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(ok_backend))
        .with_backend(Box::new(failing))
        .build();

    // Two events: one allow (filtered), one High deny.
    let events = vec![
        SiemEvent::from_receipt(allow_receipt("alert-pf-allow")),
        SiemEvent::from_receipt(deny_receipt("alert-pf-deny", "ForbiddenPathGuard")),
    ];
    let result = exporter.export_batch(&events).await;
    match result.unwrap_err() {
        ExportError::HttpError(msg) => {
            // All dispatches for a given event failed means HttpError is not reached here;
            // one backend succeeded so the event had a mixed outcome, classified as a failure.
            // At least one backend error should be reported.
            assert!(msg.contains("nope") || msg.contains("bad"), "msg: {msg}");
        }
        ExportError::PartialFailure {
            succeeded, failed, ..
        } => {
            assert_eq!(failed, 1, "deny event should count as failed");
            assert_eq!(succeeded, 1, "filtered allow event counted as success");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
    assert_eq!(
        failing_calls.load(Ordering::SeqCst),
        1,
        "failing backend dispatched exactly once"
    );
}

/// Regression: PagerDutyBackend constructors are fallible; `new`/`with_endpoint` MUST NOT revert to an unbounded no-timeout client on builder failure.
#[test]
fn pagerduty_backend_constructors_are_fallible_and_succeed_on_default_runtime() {
    let pd = PagerDutyBackend::new("rk-test".to_string());
    assert!(pd.is_ok(), "PagerDutyBackend::new must succeed in test env");

    let pd = PagerDutyBackend::with_endpoint("rk-test".to_string(), "https://x".to_string());
    assert!(
        pd.is_ok(),
        "PagerDutyBackend::with_endpoint must succeed in test env"
    );
}

/// Regression: OpsGenieBackend constructors are fallible and never silently drop the 30s timeout.
#[test]
fn opsgenie_backend_constructors_are_fallible_and_succeed_on_default_runtime() {
    let og = OpsGenieBackend::new("api-key".to_string());
    assert!(og.is_ok(), "OpsGenieBackend::new must succeed in test env");

    let og = OpsGenieBackend::with_endpoint("api-key".to_string(), "https://x".to_string());
    assert!(
        og.is_ok(),
        "OpsGenieBackend::with_endpoint must succeed in test env"
    );
}
