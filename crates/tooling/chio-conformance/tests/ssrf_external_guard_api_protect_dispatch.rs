//! SSRF negative-conformance tests for production reqwest dispatchers.
//!
//! These tests drive real external-guard and api-protect forwarding paths so
//! so that raw reqwest-level bypasses also fail, not only direct contract probes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use chio_api_protect::{ProtectConfig, ProtectProxy, DEFAULT_UPSTREAM_REQUEST_TIMEOUT};
use chio_external_guards::external::bedrock::{BedrockGuardrailConfig, BedrockGuardrailGuard};
use chio_external_guards::external::{ExternalGuard, GuardCallContext};
use tiny_http::{Header, Response, Server};

const MINIMAL_OPENAPI_SPEC: &str = r#"{
  "openapi": "3.0.0",
  "info": { "title": "T", "version": "1.0" },
  "paths": {
    "/pets": {
      "get": {
        "operationId": "listPets",
        "responses": { "200": { "description": "ok" } }
      }
    }
  }
}"#;
const API_PROTECT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

fn spawn_single_response_server<F>(respond: F) -> (SocketAddr, thread::JoinHandle<()>)
where
    F: FnOnce(tiny_http::Request) + Send + 'static,
{
    spawn_response_server_with_timeout(Duration::from_secs(5), respond)
}

fn spawn_response_server_with_timeout<F>(
    recv_timeout: Duration,
    respond: F,
) -> (SocketAddr, thread::JoinHandle<()>)
where
    F: FnOnce(tiny_http::Request) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let local_addr = listener.local_addr().expect("local addr");
    let server = Server::from_listener(listener, None).expect("build tiny_http server");
    let (ready_tx, ready_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        ready_tx.send(()).ok();
        if let Ok(Some(request)) = server.recv_timeout(recv_timeout) {
            respond(request);
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server ready");
    (local_addr, handle)
}

fn spawn_forbidden_target_server() -> (SocketAddr, mpsc::Receiver<()>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let local_addr = listener.local_addr().expect("local addr");
    let server = Server::from_listener(listener, None).expect("build tiny_http server");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (seen_tx, seen_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        ready_tx.send(()).ok();
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_millis(500)) {
            let _ = seen_tx.send(());
            let _ = request.respond(Response::from_string("forbidden target reached"));
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server ready");
    (local_addr, seen_rx, handle)
}

fn bedrock_guard_for_loopback(base_url: &str) -> BedrockGuardrailGuard {
    let mut cfg = BedrockGuardrailConfig::new("guard-token", "us-east-1", "guardrail-1", "1")
        .with_endpoint(base_url);
    cfg.timeout = Duration::from_secs(2);
    BedrockGuardrailGuard::new(cfg).expect("build Bedrock guard")
}

#[tokio::test]
async fn external_guard_dispatch_rejects_redirect_to_link_local() {
    let (addr, handle) = spawn_single_response_server(|request| {
        let location = Header::from_bytes(&b"Location"[..], &b"http://169.254.169.254/latest"[..])
            .expect("build Location header");
        let _ = request.respond(Response::empty(302).with_header(location));
    });
    let guard = bedrock_guard_for_loopback(&format!("http://{addr}"));
    let err = guard
        .eval(&GuardCallContext {
            tool_name: "tool".to_string(),
            arguments_json: r#"{"prompt":"test"}"#.to_string(),
            ..GuardCallContext::default()
        })
        .await
        .expect_err("external guard redirect to link-local must be denied");
    let _ = handle.join();

    let message = err.to_string();
    assert!(
        message.contains("HttpEgressContract")
            && (message.contains("link-local") || message.contains("169.254")),
        "expected link-local contract denial, got: {message}"
    );
}

#[tokio::test]
async fn external_guard_dispatch_rejects_redirect_to_loopback_authority() {
    let (target_addr, target_handle) =
        spawn_response_server_with_timeout(Duration::from_millis(500), |request| {
            let _ = request.respond(Response::from_string(
                r#"{"action":"NONE","assessments":[]}"#,
            ));
        });
    let (addr, handle) = spawn_single_response_server(move |request| {
        let location = Header::from_bytes(
            &b"Location"[..],
            format!("http://{target_addr}/internal").as_bytes(),
        )
        .expect("build Location header");
        let _ = request.respond(Response::empty(302).with_header(location));
    });
    let guard = bedrock_guard_for_loopback(&format!("http://{addr}"));
    let err = guard
        .eval(&GuardCallContext {
            tool_name: "tool".to_string(),
            arguments_json: r#"{"prompt":"test"}"#.to_string(),
            ..GuardCallContext::default()
        })
        .await
        .expect_err("external guard loopback redirect target must be denied");
    let _ = handle.join();
    let _ = target_handle.join();

    let message = err.to_string();
    assert!(
        message.contains("HttpEgressContract") && message.contains(&target_addr.to_string()),
        "expected loopback redirect target contract denial, got: {message}"
    );
}

#[tokio::test]
async fn external_guard_dispatch_rejects_oversized_response() {
    let (addr, handle) = spawn_single_response_server(|request| {
        let body = "x".repeat(1024 * 1024 + 1);
        let _ = request.respond(Response::from_string(body));
    });
    let guard = bedrock_guard_for_loopback(&format!("http://{addr}"));
    let err = guard
        .eval(&GuardCallContext {
            tool_name: "tool".to_string(),
            arguments_json: r#"{"prompt":"test"}"#.to_string(),
            ..GuardCallContext::default()
        })
        .await
        .expect_err("external guard oversized response must be denied");
    let _ = handle.join();

    let message = err.to_string();
    assert!(
        message.contains("HttpEgressContract")
            && (message.contains("response size") || message.contains("ResponseTooLarge")),
        "expected response-size contract denial, got: {message}"
    );
}

fn reserve_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port");
    listener.local_addr().expect("reserved local addr")
}

// The api-protect upstream proxy reaches the kernel through Chio's sync
// tool-dispatch bridge, which requires a multi-thread runtime (the documented
// host requirement); a current-thread runtime cannot drive the async tool
// server and the proxy returns a 500 instead of the expected 502.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_protect_upstream_proxy_rejects_redirect_to_link_local() {
    let (upstream_addr, upstream_handle) = spawn_single_response_server(|request| {
        let location = Header::from_bytes(&b"Location"[..], &b"http://169.254.169.254/latest"[..])
            .expect("build Location header");
        let _ = request.respond(Response::empty(302).with_header(location));
    });
    let proxy_addr = reserve_loopback_addr();
    let config = ProtectConfig {
        upstream: format!("http://{upstream_addr}"),
        spec_content: Some(MINIMAL_OPENAPI_SPEC.to_string()),
        spec_path: None,
        listen_addr: proxy_addr.to_string(),
        receipt_db: None,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let proxy_task = tokio::spawn(async move { ProtectProxy::new(config).run().await });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    let proxy_url = format!("http://{proxy_addr}/pets");
    let response = loop {
        match client.get(&proxy_url).send().await {
            Ok(response) => break response,
            Err(error) if error.is_connect() => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("unexpected proxy request error: {error}"),
        }
    };

    assert_eq!(response.status().as_u16(), 502);
    let body = response.text().await.expect("read proxy response");
    assert!(
        body.contains("upstream error: link-local egress target denied")
            && body.contains("169.254.169.254"),
        "expected specific link-local contract denial, got: {body}"
    );

    proxy_task.abort();
    let _ = upstream_handle.join();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_protect_upstream_proxy_rejects_redirect_to_loopback_authority() {
    let (target_addr, target_seen_rx, target_handle) = spawn_forbidden_target_server();
    let (upstream_addr, upstream_handle) = spawn_single_response_server(move |request| {
        let location = Header::from_bytes(
            &b"Location"[..],
            format!("http://{target_addr}/internal").as_bytes(),
        )
        .expect("build Location header");
        let _ = request.respond(Response::empty(302).with_header(location));
    });
    let proxy_addr = reserve_loopback_addr();
    let config = ProtectConfig {
        upstream: format!("http://{upstream_addr}"),
        spec_content: Some(MINIMAL_OPENAPI_SPEC.to_string()),
        spec_path: None,
        listen_addr: proxy_addr.to_string(),
        receipt_db: None,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let proxy_task = tokio::spawn(async move { ProtectProxy::new(config).run().await });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    let proxy_url = format!("http://{proxy_addr}/pets");
    let response = loop {
        match client.get(&proxy_url).send().await {
            Ok(response) => break response,
            Err(error) if error.is_connect() => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("unexpected proxy request error: {error}"),
        }
    };

    assert_eq!(response.status().as_u16(), 502);
    let body = response.text().await.expect("read proxy response");
    assert!(
        body.contains("upstream error:")
            && body.contains("authority")
            && body.contains(&target_addr.to_string())
            && body.contains("not allowed by the HttpEgressContract"),
        "expected specific loopback redirect contract denial, got: {body}"
    );

    proxy_task.abort();
    let _ = upstream_handle.join();
    let _ = target_handle.join();
    assert!(
        target_seen_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err(),
        "forbidden redirect target received a request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_protect_upstream_proxy_rejects_oversized_response() {
    let (upstream_addr, upstream_handle) = spawn_single_response_server(|request| {
        let body = vec![b'x'; API_PROTECT_MAX_RESPONSE_BYTES + 1];
        let _ = request.respond(Response::from_data(body));
    });
    let proxy_addr = reserve_loopback_addr();
    let config = ProtectConfig {
        upstream: format!("http://{upstream_addr}"),
        spec_content: Some(MINIMAL_OPENAPI_SPEC.to_string()),
        spec_path: None,
        listen_addr: proxy_addr.to_string(),
        receipt_db: None,
        sidecar_control_token: None,
        signer_seed_hex: None,
        trusted_capability_issuers: Vec::new(),
        upstream_request_timeout: DEFAULT_UPSTREAM_REQUEST_TIMEOUT,
    };
    let proxy_task = tokio::spawn(async move { ProtectProxy::new(config).run().await });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build reqwest client");
    let proxy_url = format!("http://{proxy_addr}/pets");
    let response = loop {
        match client.get(&proxy_url).send().await {
            Ok(response) => break response,
            Err(error) if error.is_connect() => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("unexpected proxy request error: {error}"),
        }
    };

    assert_eq!(response.status().as_u16(), 502);
    let body = response.text().await.expect("read proxy response");
    assert!(
        body.contains("upstream error: response size") && body.contains("exceeds maximum"),
        "expected specific contract-backed oversized response denial, got: {body}"
    );

    proxy_task.abort();
    let _ = upstream_handle.join();
}
