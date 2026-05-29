//! HTTP integration tests for `GET /regulatory/receipts`.
//!
//! Exercise the wire contract:
//!   1. Returned envelope verifies against the kernel public key.
//!   2. Stale / inverted time windows are rejected with 400.
//!   3. Unauthorized callers are rejected with 401.
//!   4. Tampered envelopes fail verification.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::crypto::Keypair;
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction};
use chio_http_core::{
    handle_regulatory_receipts_signed, verify_regulatory_export, RegulatorIdentity,
    RegulatoryApiError, RegulatoryReceiptQueryResult, RegulatoryReceiptSource,
    RegulatoryReceiptsQuery, REGULATORY_RECEIPT_EXPORT_SCHEMA,
};

fn make_receipt(keypair: &Keypair, id: &str, timestamp: u64) -> ChioReceipt {
    let action =
        ToolCallAction::from_parameters(serde_json::json!({})).expect("hash receipt parameters");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: "cap-test".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "t".to_string(),
            action,
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "ch".to_string(),
            policy_hash: "ph".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::TrustLevel::default(),
            kernel_key: keypair.public_key(),
            tenant_id: None,
        },
        keypair,
    )
    .unwrap()
}

struct FixedSource {
    receipts: Vec<ChioReceipt>,
}

impl RegulatoryReceiptSource for FixedSource {
    fn query_receipts(
        &self,
        _query: &RegulatoryReceiptsQuery,
        _read_context: &chio_kernel::ReceiptReadContext,
    ) -> Result<RegulatoryReceiptQueryResult, RegulatoryApiError> {
        Ok(RegulatoryReceiptQueryResult {
            matching_receipts: self.receipts.len() as u64,
            receipts: self.receipts.clone(),
        })
    }
}

#[test]
fn signed_envelope_verifies_against_kernel_public_key() {
    let kernel_keypair = Keypair::generate();
    let source = FixedSource {
        receipts: vec![
            make_receipt(&kernel_keypair, "r-1", 1_000),
            make_receipt(&kernel_keypair, "r-2", 1_001),
        ],
    };
    let identity = RegulatorIdentity {
        id: "regulator-a".to_string(),
    };

    let envelope = handle_regulatory_receipts_signed(
        &source,
        Some(&identity),
        &RegulatoryReceiptsQuery {
            agent: Some("agent-1".to_string()),
            after: Some(0),
            before: Some(2_000),
            ..Default::default()
        },
        &kernel_keypair,
        42,
    )
    .unwrap();

    assert_eq!(envelope.body.schema, REGULATORY_RECEIPT_EXPORT_SCHEMA);
    assert_eq!(envelope.body.matching_receipts, 2);
    assert_eq!(envelope.body.generated_at, 42);
    assert_eq!(envelope.body.receipts.len(), 2);

    let verified = verify_regulatory_export(&envelope, &kernel_keypair.public_key()).unwrap();
    assert!(verified, "envelope must verify against kernel public key");
}

#[test]
fn wrong_signer_key_fails_verification() {
    let kernel_keypair = Keypair::generate();
    let other_keypair = Keypair::generate();
    let source = FixedSource { receipts: vec![] };
    let identity = RegulatorIdentity {
        id: "regulator-b".to_string(),
    };

    let envelope = handle_regulatory_receipts_signed(
        &source,
        Some(&identity),
        &RegulatoryReceiptsQuery::default(),
        &kernel_keypair,
        0,
    )
    .unwrap();

    let verified = verify_regulatory_export(&envelope, &other_keypair.public_key()).unwrap();
    assert!(!verified, "verification must fail for a different key");
}

#[test]
fn unauthorized_caller_rejected_with_401() {
    let keypair = Keypair::generate();
    let source = FixedSource { receipts: vec![] };
    let err = handle_regulatory_receipts_signed(
        &source,
        None,
        &RegulatoryReceiptsQuery::default(),
        &keypair,
        0,
    )
    .unwrap_err();
    assert_eq!(err.status(), 401);
}

#[test]
fn inverted_time_window_rejected_with_400() {
    let keypair = Keypair::generate();
    let source = FixedSource { receipts: vec![] };
    let identity = RegulatorIdentity {
        id: "r".to_string(),
    };
    let err = handle_regulatory_receipts_signed(
        &source,
        Some(&identity),
        &RegulatoryReceiptsQuery {
            after: Some(200),
            before: Some(100),
            ..Default::default()
        },
        &keypair,
        0,
    )
    .unwrap_err();
    assert_eq!(err.status(), 400);
}
