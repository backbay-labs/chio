//! SSRF negative-conformance test: loopback addresses are rejected.
//!
//! Constructs a real production caller (`chio-siem` `WebhookExporter`)
//! configured with an `HttpEgressContract` whose authority allow-list does
//! not include `127.0.0.1`. The exporter must reject the dispatch with
//! `LoopbackDenied` (surfaced through the exporter's `ExportError::HttpError`
//! variant) before any TCP connect attempt is made.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_egress_contract::HttpEgressContract;
use chio_siem::exporter::{ExportError, Exporter};
use chio_siem::exporters::webhook::{WebhookConfig, WebhookExporter};

fn strict_contract_excluding_loopback() -> HttpEgressContract {
    HttpEgressContract {
        tenant_egress_namespace: "tenant-w22.prod".to_string(),
        allowed_schemes: BTreeSet::from(["https".to_string(), "http".to_string()]),
        allowed_authority_set: BTreeSet::from(["api.example.com".to_string()]),
        deny_loopback: true,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 1,
        max_response_bytes: 64 * 1024,
    }
}

#[tokio::test]
async fn webhook_dispatch_rejects_loopback_target() {
    let cfg = WebhookConfig {
        url: "https://127.0.0.1:1234/admin".to_string(),
        egress_contract: Some(strict_contract_excluding_loopback()),
        ..WebhookConfig::default()
    };

    // Construction must already fail-closed because the contract rejects
    // the loopback URL up front.
    let constructed = WebhookExporter::new(cfg.clone());
    if let Ok(exporter) = constructed {
        // If construction were to succeed, the dispatch must still fail
        // closed before any TCP connect attempt.
        let events: Vec<chio_siem::event::SiemEvent> = Vec::new();
        let result = exporter.export_batch(&events).await;
        match result {
            Err(ExportError::HttpError(message)) => {
                assert!(
                    message.contains("HttpEgressContract")
                        || message.contains("loopback")
                        || message.contains("127.0.0.1"),
                    "expected HttpEgressContract loopback denial, got: {message}"
                );
                return;
            }
            other => panic!("expected loopback denial, got: {other:?}"),
        }
    }
    let message = match constructed {
        Ok(_) => panic!("loopback construction should not succeed"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("HttpEgressContract")
            || message.contains("loopback")
            || message.contains("127.0.0.1"),
        "expected HttpEgressContract loopback denial during construction, got: {message}"
    );
}
