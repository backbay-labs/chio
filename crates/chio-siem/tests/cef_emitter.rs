#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction, TrustLevel,
};
use chio_siem::{CefExporter, CefExporterConfig, SiemEvent};

fn deny_receipt() -> ChioReceipt {
    let keypair = Keypair::generate();
    let body = ChioReceiptBody {
        id: "rc-deny-1".to_string(),
        timestamp: 1_712_345_678,
        capability_id: "cap-xyz".to_string(),
        tool_server: "srv-shell".to_string(),
        tool_name: "bash".to_string(),
        action: ToolCallAction {
            parameters: serde_json::json!({"cmd": "ls"}),
            parameter_hash: "param-hash".to_string(),
        },
        decision: Decision::Deny {
            reason: "forbidden path".to_string(),
            guard: "ForbiddenPathGuard".to_string(),
        },
        content_hash: "content-hash".to_string(),
        policy_hash: "policy-hash".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "ForbiddenPathGuard".to_string(),
            verdict: false,
            details: Some("path matches deny-list".to_string()),
        }],
        metadata: Some(serde_json::json!({
            "actor_subject": "partner-subject-7",
            "redaction_status": "redacted",
            "checkpoint_id": "checkpoint-2026-05-02"
        })),
        trust_level: TrustLevel::Mediated,
        tenant_id: Some("healthcare-pilot".to_string()),
        kernel_key: keypair.public_key(),
    };
    ChioReceipt::sign(body, &keypair).unwrap()
}

#[test]
fn formats_expected_cef_golden() {
    let exporter = CefExporter::default();
    let event = SiemEvent::from_receipt(deny_receipt());
    let line = exporter.format_event(&event).unwrap();
    let expected = include_str!("../src/exporters/cef.golden.txt").trim();
    assert_eq!(line, expected);
}

#[test]
fn custom_config_changes_cef_header() {
    let exporter = CefExporter::new(CefExporterConfig {
        device_vendor: "Backbay".to_string(),
        device_product: "ChioPilot".to_string(),
        device_version: "v1".to_string(),
    });
    let event = SiemEvent::from_receipt(deny_receipt());
    let line = exporter.format_event(&event).unwrap();
    assert!(line.starts_with("CEF:0|Backbay|ChioPilot|v1|"));
}
