use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};

pub(super) fn unique_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
}

fn valid_tool_action(parameters: serde_json::Value) -> ToolCallAction {
    ToolCallAction::from_parameters(parameters).unwrap()
}

pub(super) fn make_receipt_with_metadata(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    timestamp: u64,
    metadata: Option<serde_json::Value>,
) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: tool_server.to_string(),
            tool_name: tool_name.to_string(),
            action: valid_tool_action(serde_json::json!({})),
            decision: Some(decision),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .unwrap()
}

/// Build a receipt with given fields. cost populates financial metadata.
pub(super) fn make_receipt(
    id: &str,
    capability_id: &str,
    tool_server: &str,
    tool_name: &str,
    decision: Decision,
    timestamp: u64,
    cost: Option<u64>,
) -> ChioReceipt {
    let metadata = cost.map(|c| {
        serde_json::json!({
            "financial": {
                "grant_index": 0u32,
                "cost_charged": c,
                "currency": "USD",
                "budget_remaining": 1000u64,
                "budget_total": 2000u64,
                "delegation_depth": 0u32,
                "root_budget_holder": "root-agent",
                "settlement_status": "pending"
            }
        })
    });
    make_receipt_with_metadata(
        id,
        capability_id,
        tool_server,
        tool_name,
        decision,
        timestamp,
        metadata,
    )
}
