//! Multi-tenant receipt isolation -- serde contract for the
//! `tenant_id` field added to `ChioReceipt` / `ChioReceiptBody`.
//!
//! These tests anchor two invariants:
//!
//! 1. Setting `tenant_id` survives a serde roundtrip intact.
//! 2. Omitting `tenant_id` (i.e. `None`) produces a JSON document that is
//!    byte-identical to receipts issued before this field existed -- so
//!    single-tenant deployments on the wire are unaffected.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
    kinds::TrustLevel,
};

fn action() -> ToolCallAction {
    ToolCallAction::from_parameters(serde_json::json!({
        "path": "/app/src/main.rs"
    }))
    .unwrap()
}

fn body_with(kp: &Keypair, tenant_id: Option<String>) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-phase15".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "cap-001".to_string(),
        tool_server: "srv-files".to_string(),
        tool_name: "file_read".to_string(),
        action: action(),
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: sha256_hex(br#"{"ok":true}"#),
        policy_hash: "abc123def456".to_string(),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    }
}

#[test]
fn tenant_id_serde_roundtrip_present() {
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(body_with(&kp, Some("tenant-a".to_string())), &kp).unwrap();
    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-a"));

    let json = serde_json::to_string(&receipt).unwrap();
    // ChioReceipt serializes with snake_case field names (no rename_all
    // on the struct), so the multi-tenant tag is emitted as `tenant_id`.
    assert!(
        json.contains("\"tenant_id\":\"tenant-a\""),
        "expected tenant_id in serialized receipt, got: {json}"
    );

    let restored: ChioReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.tenant_id.as_deref(), Some("tenant-a"));
    assert!(
        restored.verify_signature().unwrap(),
        "signature must still verify after tenant_id roundtrip"
    );
}

#[test]
fn tenant_id_absent_is_byte_identical_on_the_wire() {
    // A receipt produced without tenant_id must serialize without the field,
    // so upgrades remain byte-identical for single-tenant deployments.
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(body_with(&kp, None), &kp).unwrap();
    assert!(receipt.tenant_id.is_none());

    let json = serde_json::to_string(&receipt).unwrap();
    assert!(
        !json.contains("tenant_id"),
        "serialized receipt must not emit the tenant_id key when None, got: {json}"
    );

    // Round-trip: absence stays absence.
    let restored: ChioReceipt = serde_json::from_str(&json).unwrap();
    assert!(restored.tenant_id.is_none());
    assert!(restored.verify_signature().unwrap());
}

#[test]
fn receipt_body_serde_omits_tenant_id_when_none() {
    let kp = Keypair::generate();
    let body = body_with(&kp, None);
    let json = serde_json::to_string(&body).unwrap();
    assert!(
        !json.contains("tenant_id"),
        "receipt body must omit tenant_id key when None: {json}"
    );
}

#[test]
fn receipt_body_serde_emits_tenant_id_when_set() {
    let kp = Keypair::generate();
    let body = body_with(&kp, Some("ten-xyz".to_string()));
    let json = serde_json::to_string(&body).unwrap();
    assert!(
        json.contains("\"tenant_id\":\"ten-xyz\""),
        "receipt body must emit tenant_id when set: {json}"
    );
}

#[test]
fn deserializing_receipt_without_tenant_id_defaults_to_none() {
    // A receipt that omits tenant_id must deserialize with tenant_id defaulting to None.
    let kp = Keypair::generate();
    let receipt = ChioReceipt::sign(body_with(&kp, None), &kp).unwrap();
    let json = serde_json::to_string(&receipt).unwrap();
    assert!(!json.contains("tenant_id"));

    let restored: ChioReceipt = serde_json::from_str(&json).unwrap();
    assert!(restored.tenant_id.is_none());
}
