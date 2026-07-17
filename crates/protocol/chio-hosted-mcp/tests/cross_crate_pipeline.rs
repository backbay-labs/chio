#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chio_core::receipt::decision::Decision;
use chio_siem::event::SiemEvent;
use chio_siem::exporter::ExportFuture;
use chio_siem::{Exporter, ExporterManager, SiemConfig};
use serde_json::{json, Value};

use support::start_http_server;

#[derive(Clone, Default)]
struct CapturingExporter {
    events: Arc<Mutex<Vec<SiemEvent>>>,
}

impl CapturingExporter {
    fn events(&self) -> Vec<SiemEvent> {
        self.events.lock().expect("events lock").clone()
    }
}

impl Exporter for CapturingExporter {
    fn name(&self) -> &str {
        "capturing-exporter"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        let sink = self.events.clone();
        let owned = events.to_vec();
        Box::pin(async move {
            sink.lock().expect("events lock").extend(owned.clone());
            Ok(owned.len())
        })
    }
}

fn tool_receipts(server: &support::TestServer) -> Vec<Value> {
    let receipts = server.get_admin_tool_receipts(&[("limit", "20")]);
    assert_eq!(receipts.status(), reqwest::StatusCode::OK);
    let receipts: Value = receipts.json().expect("tool receipts json");
    receipts["receipts"]
        .as_array()
        .expect("tool receipts array")
        .clone()
}

fn wait_for_receipt_count(server: &support::TestServer, expected: usize) {
    for _ in 0..20 {
        if tool_receipts(server).len() == expected {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }

    panic!("expected {expected} tool receipts to be visible");
}

fn export_receipts(
    receipt_db_path: std::path::PathBuf,
    exporter: CapturingExporter,
) -> ExporterManager {
    let runtime = tokio::runtime::Runtime::new().expect("build tokio runtime");
    runtime.block_on(async move {
        let mut manager = ExporterManager::new(SiemConfig {
            db_path: receipt_db_path,
            poll_interval: Duration::from_millis(25),
            batch_size: 100,
            max_retries: 0,
            base_backoff_ms: 0,
            dlq_capacity: 100,
            rate_limit: None,
            trusted_kernel_keys: std::collections::BTreeSet::new(),
            read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
            cursor_db_path: None,
        })
        .expect("open ExporterManager");
        manager.add_exporter(Box::new(exporter));

        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let run_handle = tokio::spawn(async move {
            manager.run(cancel_rx).await;
            manager
        });

        tokio::time::sleep(Duration::from_millis(200)).await;
        cancel_tx.send(true).expect("cancel signal sends");
        run_handle.await.expect("manager task completes")
    })
}

#[test]
fn hosted_mcp_receipts_flow_into_chio_siem_export() {
    let server = start_http_server("test-token");
    let session = server.initialize_session();

    let response = server.call_echo_json_with_token("test-token", &session, 11, "cross-crate");
    assert_eq!(
        response["result"]["structuredContent"]["echo"],
        "cross-crate"
    );

    wait_for_receipt_count(&server, 1);

    let exporter = CapturingExporter::default();
    let manager = export_receipts(server.receipt_db_path.clone(), exporter.clone());

    let events = exporter.events();
    assert_eq!(events.len(), 1, "one hosted receipt should be exported");
    assert_eq!(events[0].receipt.tool_name, "echo_json");
    assert_eq!(events[0].receipt.tool_server, "wrapped-http-mock");
    assert!(matches!(events[0].receipt.decision, Some(Decision::Allow)));
    assert_eq!(manager.dlq_len(), 0, "successful export should not DLQ");
}

#[test]
fn hosted_mcp_fail_closed_errors_emit_no_receipt_or_siem_export() {
    let server = start_http_server("test-token");
    let session = server.initialize_session();

    assert!(
        tool_receipts(&server).is_empty(),
        "initialization should not create tool receipts"
    );

    let unauthorized = server.post_json_with_token(
        "wrong-token",
        Some(&session.id),
        Some(&session.protocol_version),
        &json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "echo_json",
                "arguments": {"message": "should fail"}
            }
        }),
    );
    assert_eq!(unauthorized.status(), reqwest::StatusCode::UNAUTHORIZED);

    thread::sleep(Duration::from_millis(100));
    assert!(
        tool_receipts(&server).is_empty(),
        "fail-closed auth errors must not emit partial receipts"
    );

    let exporter = CapturingExporter::default();
    let manager = export_receipts(server.receipt_db_path.clone(), exporter.clone());

    assert!(
        exporter.events().is_empty(),
        "chio-siem should have nothing to export when hosted-mcp rejected the call"
    );
    assert_eq!(manager.dlq_len(), 0, "no receipts means no DLQ activity");
}
