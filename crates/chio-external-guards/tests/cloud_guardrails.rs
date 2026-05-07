//! Integration tests for the phase-13.2 cloud guardrail adapters.
//!
//! Each test stands up a [`wiremock::MockServer`], points the guard at
//! the mock, wraps the guard in an [`AsyncGuardAdapter`], and verifies
//! the end-to-end verdict.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use chio_external_guards::external::{
    AsyncGuardAdapter, AzureContentSafetyConfig, AzureContentSafetyGuard, BackoffStrategy,
    BedrockGuardrailConfig, BedrockGuardrailGuard, ExternalGuard, GuardCallContext, RetryConfig,
    VertexProbability, VertexSafetyConfig, VertexSafetyGuard,
};
use chio_kernel::Verdict;
use serde_json::json;
use wiremock::matchers::{header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn fast_retry() -> RetryConfig {
    RetryConfig {
        max_retries: 1,
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
        jitter_fraction: 0.0,
        strategy: BackoffStrategy::Exponential,
    }
}

fn make_ctx(tool: &str, args: serde_json::Value) -> GuardCallContext {
    GuardCallContext {
        tool_name: tool.to_string(),
        agent_id: "agent-x".to_string(),
        server_id: "srv".to_string(),
        arguments_json: args.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Bedrock
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bedrock_denies_on_guardrail_intervened() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/guardrail/[^/]+/version/[^/]+/apply$"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "action": "GUARDRAIL_INTERVENED",
            "assessments": [
                {"contentPolicy": {"filters": [{"type": "SEXUAL", "confidence": "HIGH"}]}}
            ]
        })))
        .mount(&server)
        .await;

    let cfg = BedrockGuardrailConfig::new("test-token", "us-east-1", "gr-123", "DRAFT")
        .with_endpoint(server.uri());
    let guard = BedrockGuardrailGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    let ctx = make_ctx("send_email", json!({"subject": "hi"}));
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
}

#[tokio::test]
async fn bedrock_allows_on_action_none() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/guardrail/[^/]+/version/[^/]+/apply$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "action": "NONE",
            "assessments": []
        })))
        .mount(&server)
        .await;

    let cfg = BedrockGuardrailConfig::new("test-token", "us-east-1", "gr-123", "1")
        .with_endpoint(server.uri());
    let guard = BedrockGuardrailGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("chat", json!({"text": "hi"})))
            .await,
        Verdict::Allow
    );
}

#[tokio::test]
async fn bedrock_fails_closed_on_5xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(r"^/guardrail/[^/]+/version/[^/]+/apply$"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal"))
        .mount(&server)
        .await;

    let cfg = BedrockGuardrailConfig::new("test-token", "us-east-1", "gr-123", "1")
        .with_endpoint(server.uri());
    let guard = BedrockGuardrailGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter.evaluate(&make_ctx("x", json!({}))).await,
        Verdict::Deny,
        "5xx must fail closed"
    );
}

#[tokio::test]
async fn cloud_guardrails_recheck_runtime_endpoints_before_send() {
    let bedrock = BedrockGuardrailGuard::new(
        BedrockGuardrailConfig::new("test-token", "us-east-1", "gr-123", "1")
            .with_endpoint("https://224.0.0.1"),
    )
    .expect("guard build");
    let error = bedrock
        .eval(&make_ctx("chat", json!({"text": "hi"})))
        .await
        .expect_err("multicast endpoint should fail closed before HTTP send");
    assert!(error
        .to_string()
        .contains("must not target localhost, link-local, or private-network hosts"));

    let vertex = VertexSafetyGuard::new(
        VertexSafetyConfig::new("test-token", "proj", "us-central1", "gemini-1.5-pro")
            .with_endpoint("https://224.0.0.1"),
    )
    .expect("guard build");
    let error = vertex
        .eval(&make_ctx("chat", json!({"text": "hi"})))
        .await
        .expect_err("multicast endpoint should fail closed before HTTP send");
    assert!(error
        .to_string()
        .contains("must not target localhost, link-local, or private-network hosts"));
}

#[test]
fn bedrock_constructor_rejects_default_hostname_without_dns_pinning() {
    let error = match BedrockGuardrailGuard::new(BedrockGuardrailConfig::new(
        "test-token",
        "us-east-1",
        "gr-123",
        "1",
    )) {
        Ok(_) => panic!("default Bedrock hostname must fail before dispatch"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("bedrock-runtime.us-east-1.amazonaws.com")
            && message.contains("hostname egress requires DNS pinning"),
        "unexpected default Bedrock hostname denial: {message}"
    );
}

#[tokio::test]
async fn bedrock_evidence_captures_action() {
    use chio_external_guards::external::BedrockDecisionDetails;

    let cfg = BedrockGuardrailConfig::new("test-token", "us-east-1", "gr-123", "1")
        .with_endpoint("http://localhost");
    let guard = BedrockGuardrailGuard::new(cfg).expect("guard build");
    let details = BedrockDecisionDetails {
        action: "GUARDRAIL_INTERVENED".to_string(),
        intervened: true,
        assessments: vec![json!({"type": "SEXUAL"})],
    };
    let evidence = guard.evidence_from_decision(Verdict::Deny, Some(&details));
    assert_eq!(evidence.guard_name, "bedrock-guardrail");
    assert!(!evidence.verdict);
    let raw = evidence.details.as_deref().expect("details");
    let decoded: serde_json::Value = serde_json::from_str(raw).expect("json");
    assert_eq!(decoded["action"], "GUARDRAIL_INTERVENED");
    assert_eq!(decoded["intervened"], true);
}

// ---------------------------------------------------------------------------
// Azure Content Safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn azure_denies_when_severity_above_threshold() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contentsafety/text:analyze"))
        .and(header("Ocp-Apim-Subscription-Key", "k"))
        .and(query_param("api-version", "2023-10-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "categoriesAnalysis": [
                {"category": "Hate", "severity": 6},
                {"category": "Violence", "severity": 0}
            ]
        })))
        .mount(&server)
        .await;

    let cfg = AzureContentSafetyConfig::new("k", server.uri()).with_severity_threshold(4);
    let guard = AzureContentSafetyGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("t", json!({"text": "bad"})))
            .await,
        Verdict::Deny
    );
}

#[tokio::test]
async fn azure_allows_when_severity_below_threshold() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contentsafety/text:analyze"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "categoriesAnalysis": [
                {"category": "Hate", "severity": 2}
            ]
        })))
        .mount(&server)
        .await;

    let cfg = AzureContentSafetyConfig::new("k", server.uri()).with_severity_threshold(4);
    let guard = AzureContentSafetyGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("t", json!({"text": "mild"})))
            .await,
        Verdict::Allow
    );
}

#[tokio::test]
async fn azure_fails_closed_on_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/contentsafety/text:analyze"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;

    let cfg = AzureContentSafetyConfig::new("bad-key", server.uri());
    let guard = AzureContentSafetyGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter.evaluate(&make_ctx("t", json!({}))).await,
        Verdict::Deny
    );
}

// ---------------------------------------------------------------------------
// Vertex AI safety
// ---------------------------------------------------------------------------

#[tokio::test]
async fn vertex_denies_on_high_probability_rating() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(
            r"^/v1/projects/[^/]+/locations/[^/]+/publishers/google/models/[^/]+:generateContent$",
        ))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [
                {
                    "safetyRatings": [
                        {"category": "HARM_CATEGORY_HARASSMENT", "probability": "HIGH"}
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;

    let cfg = VertexSafetyConfig::new("test-token", "proj", "us-central1", "gemini-1.5-pro")
        .with_endpoint(server.uri())
        .with_threshold(VertexProbability::Medium);
    let guard = VertexSafetyGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("send", json!({"text": "bad"})))
            .await,
        Verdict::Deny
    );
}

#[tokio::test]
async fn vertex_denies_on_prompt_feedback_block() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(
            r"^/v1/projects/[^/]+/locations/[^/]+/publishers/google/models/[^/]+:generateContent$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [],
            "promptFeedback": {"blockReason": "SAFETY"}
        })))
        .mount(&server)
        .await;

    let cfg = VertexSafetyConfig::new("test-token", "proj", "us-central1", "gemini-1.5-pro")
        .with_endpoint(server.uri());
    let guard = VertexSafetyGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter.evaluate(&make_ctx("x", json!({}))).await,
        Verdict::Deny
    );
}

#[tokio::test]
async fn vertex_allows_when_all_ratings_below_threshold() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path_regex(
            r"^/v1/projects/[^/]+/locations/[^/]+/publishers/google/models/[^/]+:generateContent$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "candidates": [
                {
                    "safetyRatings": [
                        {"category": "HARM_CATEGORY_HARASSMENT", "probability": "NEGLIGIBLE"},
                        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "LOW"}
                    ]
                }
            ]
        })))
        .mount(&server)
        .await;

    let cfg = VertexSafetyConfig::new("test-token", "proj", "us-central1", "gemini-1.5-pro")
        .with_endpoint(server.uri())
        .with_threshold(VertexProbability::Medium);
    let guard = VertexSafetyGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter.evaluate(&make_ctx("x", json!({}))).await,
        Verdict::Allow
    );
}

// ---------------------------------------------------------------------------
// Evidence capture
// ---------------------------------------------------------------------------

#[tokio::test]
async fn evidence_records_capture_structured_details() {
    use chio_external_guards::external::{AzureCategoryBreakdown, AzureDecisionDetails};

    let cfg = AzureContentSafetyConfig::new("k", "http://localhost");
    let guard = AzureContentSafetyGuard::new(cfg).expect("guard build");
    let details = AzureDecisionDetails {
        max_severity: 6,
        severity_threshold: 4,
        categories: vec![AzureCategoryBreakdown {
            category: "Hate".to_string(),
            severity: 6,
        }],
    };
    let ev = guard.evidence_from_decision(Verdict::Deny, Some(&details));
    assert_eq!(ev.guard_name, "azure-content-safety");
    assert!(!ev.verdict);
    let body: serde_json::Value =
        serde_json::from_str(ev.details.as_deref().expect("details")).expect("json");
    assert_eq!(body["max_severity"], 6);
    assert_eq!(body["severity_threshold"], 4);
}
