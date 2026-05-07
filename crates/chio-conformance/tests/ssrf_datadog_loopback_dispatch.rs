//! SSRF negative-conformance tests for loopback-backed Datadog dispatches.
//!
//! These tests drive a real `DatadogExporter` over a local HTTP server so the
//! redirect and response-size checks run on the production `send_with_contract`
//! path, not just on direct contract probes.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_egress_contract::HttpEgressContract;
use chio_siem::event::SiemEvent;
use chio_siem::exporters::datadog::{DatadogConfig, DatadogExporter};
use chio_siem::Exporter;
use tiny_http::{Header, Response, Server};

fn loopback_contract(
    authority: &str,
    max_redirect_chain: u8,
    max_response_bytes: u64,
) -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["http".to_string()]),
        allowed_authority_set: BTreeSet::from([authority.to_ascii_lowercase()]),
        deny_loopback: false,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain,
        max_response_bytes,
    }
}

fn allow_event(id: &str) -> SiemEvent {
    let keypair = Keypair::generate();
    let action = ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
        .expect("hash receipt parameters");
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-dd-allow".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action,
            decision: Decision::Allow,
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
    .expect("sign receipt");
    SiemEvent::from_receipt(receipt)
}

fn datadog_for_loopback(base_url: &str, contract: HttpEgressContract) -> DatadogExporter {
    DatadogExporter::new_with_base_url_for_tests(
        DatadogConfig {
            api_key: "dd-key-test".to_string(),
            timeout: Duration::from_secs(2),
            egress_contract: Some(contract),
            ..DatadogConfig::default()
        },
        base_url,
    )
    .expect("build Datadog exporter")
}

#[tokio::test]
async fn datadog_loopback_dispatch_rejects_redirect_before_following() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let local_addr = listener.local_addr().expect("local addr");
    let server = Server::from_listener(listener, None).expect("build tiny_http server");
    let (ready_tx, ready_rx) = mpsc::channel();
    let server_handle = thread::spawn(move || {
        ready_tx.send(()).ok();
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(5)) {
            let location =
                Header::from_bytes(&b"Location"[..], &b"http://127.0.0.1:9/internal"[..])
                    .expect("build Location header");
            let _ = request.respond(Response::empty(302).with_header(location));
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server ready");

    let authority = format!("127.0.0.1:{}", local_addr.port());
    let base_url = format!("http://{authority}");
    let exporter = datadog_for_loopback(&base_url, loopback_contract(&authority, 0, 64 * 1024));
    let events = vec![allow_event("dd-redirect")];

    let err = exporter
        .export_batch(&events)
        .await
        .expect_err("redirect must be rejected before follow");
    let _ = server_handle.join();
    let message = err.to_string();
    assert!(
        message.contains("redirect chain") || message.contains("RedirectLimitExceeded"),
        "expected redirect denial, got: {message}"
    );
}

#[tokio::test]
async fn datadog_loopback_dispatch_rejects_oversize_response_body() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let local_addr = listener.local_addr().expect("local addr");
    let server = Server::from_listener(listener, None).expect("build tiny_http server");
    let (ready_tx, ready_rx) = mpsc::channel();
    let server_handle = thread::spawn(move || {
        ready_tx.send(()).ok();
        if let Ok(Some(request)) = server.recv_timeout(Duration::from_secs(5)) {
            let body = "x".repeat(128);
            let _ = request.respond(Response::from_string(body).with_status_code(500));
        }
    });
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("server ready");

    let authority = format!("127.0.0.1:{}", local_addr.port());
    let base_url = format!("http://{authority}");
    let exporter = datadog_for_loopback(&base_url, loopback_contract(&authority, 1, 32));
    let events = vec![allow_event("dd-oversize")];

    let err = exporter
        .export_batch(&events)
        .await
        .expect_err("oversize response must be rejected");
    let _ = server_handle.join();
    let message = err.to_string();
    assert!(
        message.contains("response size") || message.contains("ResponseTooLarge"),
        "expected response-size denial, got: {message}"
    );
}
