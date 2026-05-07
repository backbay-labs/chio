//! Integration tests for the phase-13.3 threat-intel adapters.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_external_guards::external::{
    AsyncGuardAdapter, BackoffStrategy, ExternalGuard, GuardCallContext, RetryConfig,
    SafeBrowsingConfig, SafeBrowsingGuard, SnykConfig, SnykGuard, SnykSeverity, VirusTotalConfig,
    VirusTotalGuard,
};
use chio_kernel::Verdict;
use serde_json::json;
use wiremock::matchers::{any, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KNOWN_BAD_HASH: &str = "44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f";

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
// VirusTotal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn virustotal_denies_known_malicious_hash() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .and(header("x-apikey", "vt-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 3
                    }
                }
            }
        })))
        .mount(&server)
        .await;

    let cfg = VirusTotalConfig::new("vt-key")
        .with_base_url(server.uri())
        .with_min_detections(5);
    let guard = VirusTotalGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    let ctx = make_ctx("write_file", json!({"hash": KNOWN_BAD_HASH}));
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
}

#[tokio::test]
async fn virustotal_allows_clean_hash() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0}
                }
            }
        })))
        .mount(&server)
        .await;

    let cfg = VirusTotalConfig::new("vt-key").with_base_url(server.uri());
    let guard = VirusTotalGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("w", json!({"hash": KNOWN_BAD_HASH})))
            .await,
        Verdict::Allow
    );
}

#[tokio::test]
async fn threat_intel_rechecks_runtime_endpoints_before_send() {
    let safe_browsing = SafeBrowsingGuard::new(
        SafeBrowsingConfig::new("sb-key").with_base_url("https://224.0.0.1"),
    )
    .expect("guard build");
    let error = safe_browsing
        .eval(&make_ctx(
            "visit_url",
            json!({"url": "https://example.com"}),
        ))
        .await
        .expect_err("multicast endpoint should fail closed before HTTP send");
    assert!(error
        .to_string()
        .contains("must not target localhost, link-local, or private-network hosts"));

    let virustotal =
        VirusTotalGuard::new(VirusTotalConfig::new("vt-key").with_base_url("https://224.0.0.1"))
            .expect("guard build");
    let error = virustotal
        .eval(&make_ctx("scan", json!({"hash": KNOWN_BAD_HASH})))
        .await
        .expect_err("multicast endpoint should fail closed before HTTP send");
    assert!(error
        .to_string()
        .contains("must not target localhost, link-local, or private-network hosts"));

    let snyk =
        SnykGuard::new(SnykConfig::new("snyk-token", "org-123").with_base_url("https://224.0.0.1"))
            .expect("guard build");
    let error = snyk
        .eval(&make_ctx(
            "install",
            json!({"package": "lodash", "version": "4.17.21", "ecosystem": "npm"}),
        ))
        .await
        .expect_err("multicast endpoint should fail closed before HTTP send");
    assert!(error
        .to_string()
        .contains("must not target localhost, link-local, or private-network hosts"));
}

#[tokio::test]
async fn virustotal_allows_on_404() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let cfg = VirusTotalConfig::new("vt-key").with_base_url(server.uri());
    let guard = VirusTotalGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("w", json!({"hash": KNOWN_BAD_HASH})))
            .await,
        Verdict::Allow
    );
}

#[tokio::test]
async fn virustotal_denies_url_lookup() {
    let server = MockServer::start().await;
    let target = "https://malicious.example/payload";
    let encoded = URL_SAFE_NO_PAD.encode(target.as_bytes());

    Mock::given(method("GET"))
        .and(path(format!("/urls/{encoded}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 10, "suspicious": 2}
                }
            }
        })))
        .mount(&server)
        .await;

    let cfg = VirusTotalConfig::new("vt-key").with_base_url(server.uri());
    let guard = VirusTotalGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("fetch", json!({"url": target})))
            .await,
        Verdict::Deny
    );
}

#[tokio::test]
async fn virustotal_fails_closed_on_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .respond_with(ResponseTemplate::new(502).set_body_string("bad gateway"))
        .mount(&server)
        .await;

    let cfg = VirusTotalConfig::new("vt-key").with_base_url(server.uri());
    let guard = VirusTotalGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("w", json!({"hash": KNOWN_BAD_HASH})))
            .await,
        Verdict::Deny
    );
}

// ---------------------------------------------------------------------------
// Safe Browsing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn safe_browsing_denies_listed_url() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/threatMatches:find"))
        .and(query_param("key", "sb-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "matches": [
                {
                    "threatType": "MALWARE",
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    "threat": {"url": "https://malicious.example/bad"}
                }
            ]
        })))
        .mount(&server)
        .await;

    let cfg = SafeBrowsingConfig::new("sb-key").with_base_url(server.uri());
    let guard = SafeBrowsingGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    let ctx = make_ctx("fetch", json!({"url": "https://malicious.example/bad"}));
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
}

#[tokio::test]
async fn safe_browsing_allows_clean_url() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/threatMatches:find"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&server)
        .await;

    let cfg = SafeBrowsingConfig::new("sb-key").with_base_url(server.uri());
    let guard = SafeBrowsingGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    assert_eq!(
        adapter
            .evaluate(&make_ctx("fetch", json!({"url": "https://example.com"})))
            .await,
        Verdict::Allow
    );
}

#[tokio::test]
async fn safe_browsing_with_default_client_rejects_redirect_before_target_contact() {
    let target = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&target)
        .await;

    let redirect_target = format!("{}/forbidden", target.uri());
    let start = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/threatMatches:find"))
        .and(query_param("key", "sb-key"))
        .respond_with(ResponseTemplate::new(302).insert_header("Location", redirect_target))
        .mount(&start)
        .await;

    let cfg = SafeBrowsingConfig::new("sb-key").with_base_url(start.uri());
    let guard = SafeBrowsingGuard::with_client(cfg, reqwest::Client::new()).expect("guard build");

    let error = guard
        .eval(&make_ctx(
            "fetch",
            json!({"url": "https://example.com/payload"}),
        ))
        .await
        .expect_err("redirect target should be denied before follow");
    let message = error.to_string();
    assert!(
        message.contains("HttpEgressContract rejects external guard dispatch")
            && message.contains("authority"),
        "unexpected redirect denial: {message}"
    );

    let target_requests = target
        .received_requests()
        .await
        .expect("target request log");
    assert!(
        target_requests.is_empty(),
        "forbidden redirect target received a request"
    );
}

// ---------------------------------------------------------------------------
// Snyk
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snyk_denies_on_known_cve() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/test/npm/lodash/4\.17\.20$"))
        .and(header("Authorization", "token snyk-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-LODASH-1040724",
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "isUpgradable": true
                }
            ]
        })))
        .mount(&server)
        .await;

    let cfg = SnykConfig::new("snyk-token", "org-123")
        .with_base_url(server.uri())
        .with_severity_threshold(SnykSeverity::High);
    let guard = SnykGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    let ctx = make_ctx(
        "install",
        json!({
            "package": "lodash",
            "version": "4.17.20",
            "ecosystem": "npm"
        }),
    );
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
}

#[tokio::test]
async fn snyk_allows_when_below_threshold() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/test/npm/lodash/4\.17\.20$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vulnerabilities": [
                {
                    "id": "SNYK-LOW-1",
                    "severity": "low",
                    "isUpgradable": true
                }
            ]
        })))
        .mount(&server)
        .await;

    let cfg = SnykConfig::new("snyk-token", "org-123")
        .with_base_url(server.uri())
        .with_severity_threshold(SnykSeverity::High);
    let guard = SnykGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    let ctx = make_ctx(
        "install",
        json!({"package": "lodash", "version": "4.17.20", "ecosystem": "npm"}),
    );
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Allow);
}

#[tokio::test]
async fn snyk_allows_when_no_vulns() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/test/npm/lodash/4\.17\.21$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "vulnerabilities": []
        })))
        .mount(&server)
        .await;

    let cfg = SnykConfig::new("snyk-token", "org-123").with_base_url(server.uri());
    let guard = SnykGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(5))
        .build();

    let ctx = make_ctx(
        "install",
        json!({"package": "lodash", "version": "4.17.21", "ecosystem": "npm"}),
    );
    assert_eq!(adapter.evaluate(&ctx).await, Verdict::Allow);
}

// ---------------------------------------------------------------------------
// Adapter composition (cache + circuit breaker) exercised end-to-end
// ---------------------------------------------------------------------------

#[tokio::test]
async fn virustotal_cache_dedupes_repeat_lookups() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "attributes": {"last_analysis_stats": {"malicious": 10, "suspicious": 0}}
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = VirusTotalConfig::new("vt-key").with_base_url(server.uri());
    let guard = VirusTotalGuard::new(cfg).expect("guard build");
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 10)
        .cache_ttl(Duration::from_secs(60))
        .build();

    for _ in 0..2 {
        let ctx = make_ctx("w", json!({"hash": KNOWN_BAD_HASH}));
        assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
    }
}
