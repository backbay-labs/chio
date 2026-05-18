//! Legacy receipt migration test.
//!
//! M09.P1.T5: Existing receipts (no manifest price / no financial
//! metadata) re-process under M09 with zero IOUs minted, and the
//! receipt bytes are unchanged. The trajectory-1 M04 deterministic
//! corpus shape is the soft-dep fixture; we model that shape here
//! with a hand-built receipt that carries no `financial` metadata
//! key. P1.T5 asserts:
//!
//! - The credit hook returns `Ok(None)` for every legacy receipt
//!   shape (Allow, Deny, Cancelled, Incomplete; with arbitrary
//!   non-financial metadata; with no metadata at all).
//! - The receipt's canonical bytes are byte-identical before and
//!   after the hook runs. The hook MUST NOT mutate or re-serialize
//!   the receipt.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_credit::crypto::{canonical_json_bytes, sha256_hex, Ed25519Backend, Keypair};
use chio_credit::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, GuardEvidence, ToolCallAction, TrustLevel,
};
use chio_credit::{CreditEvaluatorHook, LocalCreditAccount};

fn legacy_receipt(decision: Decision, metadata: Option<serde_json::Value>) -> ChioReceipt {
    let kp = Keypair::generate();
    let body = ChioReceiptBody {
        id: "legacy-rcpt".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "legacy-cap".to_string(),
        tool_server: "legacy-srv".to_string(),
        tool_name: "legacy-tool".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"k": "v"})).unwrap(),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        decision: Some(decision),
        content_hash: sha256_hex(b"{}"),
        policy_hash: "policy-v0".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "G".to_string(),
            verdict: true,
            details: None,
        }],
        metadata,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
    };
    ChioReceipt::sign(body, &kp).unwrap()
}

fn account_for(receipt: &ChioReceipt) -> LocalCreditAccount<Ed25519Backend> {
    // The legacy fixtures sign their own receipts, so the account's
    // signing identity is intentionally distinct. The hook must
    // verify the receipt against its embedded kernel_key, not
    // against the account's identity.
    LocalCreditAccount::new_with_trusted_kernel_keys(
        Ed25519Backend::new(Keypair::generate()),
        [receipt.kernel_key.clone()],
    )
}

fn assert_zero_iou_and_byte_stable(receipt: ChioReceipt) {
    let before = canonical_json_bytes(&receipt).unwrap();
    let account = account_for(&receipt);
    let outcome = account.evaluate(&receipt).unwrap();
    assert!(
        outcome.is_none(),
        "legacy receipt without manifest price must mint zero IOUs"
    );
    let after = canonical_json_bytes(&receipt).unwrap();
    assert_eq!(
        before, after,
        "receipt canonical bytes must be unchanged after hook evaluation"
    );
}

#[test]
fn legacy_allow_receipt_with_no_metadata_mints_zero() {
    assert_zero_iou_and_byte_stable(legacy_receipt(Decision::Allow, None));
}

#[test]
fn legacy_allow_receipt_with_non_financial_metadata_mints_zero() {
    let metadata = serde_json::json!({
        "sandbox": {"enforced": true},
        "trace_id": "abc-123"
    });
    assert_zero_iou_and_byte_stable(legacy_receipt(Decision::Allow, Some(metadata)));
}

#[test]
fn legacy_deny_receipt_mints_zero() {
    assert_zero_iou_and_byte_stable(legacy_receipt(
        Decision::Deny {
            reason: "blocked".to_string(),
            guard: "G".to_string(),
        },
        None,
    ));
}

#[test]
fn legacy_cancelled_receipt_mints_zero() {
    assert_zero_iou_and_byte_stable(legacy_receipt(
        Decision::Cancelled {
            reason: "cancelled".to_string(),
        },
        None,
    ));
}

#[test]
fn legacy_incomplete_receipt_mints_zero() {
    assert_zero_iou_and_byte_stable(legacy_receipt(
        Decision::Incomplete {
            reason: "incomplete".to_string(),
        },
        None,
    ));
}

#[test]
fn re_evaluation_keeps_canonical_bytes_identical() {
    let receipt = legacy_receipt(Decision::Allow, None);
    let baseline = canonical_json_bytes(&receipt).unwrap();
    let account = account_for(&receipt);
    for _ in 0..5 {
        assert!(account.evaluate(&receipt).unwrap().is_none());
    }
    assert_eq!(baseline, canonical_json_bytes(&receipt).unwrap());
}
