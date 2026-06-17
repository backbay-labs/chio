use std::path::{Path, PathBuf};

use chio_test_support::prelude::*;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .and_then(|workspace| workspace.parent())
        .test_expect("workspace root is parent of crates/platform/chio-commerce-order")
        .to_path_buf()
}

fn fixture_dir(case_name: &str) -> PathBuf {
    workspace_root().join(format!("fixtures/proof-room/commerce-payments/{case_name}"))
}

fn read_fixture(dir: &Path, name: &str) -> Vec<u8> {
    let case_path = dir.join(name);
    let path = if case_path.is_file() {
        case_path
    } else {
        fixture_dir("offline-psp-valid").join(name)
    };
    std::fs::read(path).test_expect("fixture file reads")
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    hex::encode(Sha256::digest(bytes))
}

fn load_bundle(case_name: &str) -> chio_commerce_order::CommerceOrderVerificationBundle {
    let dir = fixture_dir(case_name);
    let context_bytes = read_fixture(&dir, "order-context.json");
    let order_context = serde_json::from_slice(&context_bytes).test_expect("order context parses");

    chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes: read_fixture(&dir, "event-log.json"),
        payment_lifecycle_bytes: read_fixture(&dir, "payment-lifecycle.json"),
        mandate_ledger_bytes: read_fixture(&dir, "mandate-allowance-ledger.json"),
    }
}

fn mutate_event_log(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut event_log: serde_json::Value =
        serde_json::from_slice(&bundle.event_log_bytes).test_expect("event log parses");
    mutate(&mut event_log);
    bundle.event_log_bytes = serde_json::to_vec(&event_log).test_expect("event log serializes");
    bundle.order_context.event_log_sha256 = sha256_hex(&bundle.event_log_bytes);
}

fn mutate_payment_lifecycle(
    bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut payment_lifecycle: serde_json::Value =
        serde_json::from_slice(&bundle.payment_lifecycle_bytes)
            .test_expect("payment lifecycle parses");
    mutate(&mut payment_lifecycle);
    bundle.payment_lifecycle_bytes =
        serde_json::to_vec(&payment_lifecycle).test_expect("payment lifecycle serializes");
    bundle.order_context.payment_lifecycle_sha256 = sha256_hex(&bundle.payment_lifecycle_bytes);
}

fn truncate_to_payment_verified(bundle: &mut chio_commerce_order::CommerceOrderVerificationBundle) {
    mutate_event_log(bundle, |event_log| {
        let events = event_log["events"]
            .as_array_mut()
            .test_expect("event log events array");
        let payment_event_index = events
            .iter()
            .position(|event| event["next_state"] == "payment_verified")
            .test_expect("payment verification event exists");
        events.truncate(payment_event_index + 1);
    });
    bundle.order_context.current_state = "payment_verified".to_string();
}

#[test]
fn commerce_order_replay_accepts_offline_psp_fixture() {
    let bundle = load_bundle("offline-psp-valid");

    let report = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect("valid offline PSP commerce fixture should verify");

    assert_eq!(report.schema, "chio.commerce.order-passport.v1");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.order_id, "order-commerce-001");
    assert_eq!(report.current_state, "completed");
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.order_replay_consistent".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.payment_lifecycle_bound".to_string()));
    assert!(report
        .verified_claims
        .contains(&"claim.commerce.mandate_allowance_bound".to_string()));
}

#[test]
fn commerce_order_replay_rejects_payment_wrong_merchant() {
    let bundle = load_bundle("payment-wrong-merchant");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment bound to wrong merchant must fail");

    assert!(error.to_string().contains("payment merchant mismatch"));
}

#[test]
fn commerce_order_replay_rejects_payment_wrong_transfer_group() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["transfer_group"] = serde_json::json!("order-commerce-other");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment transfer group must bind the same order");

    assert!(error
        .to_string()
        .contains("payment transfer group mismatch"));
}

#[test]
fn commerce_order_replay_rejects_payment_before_budget_reservation() {
    let bundle = load_bundle("payment-before-budget");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("payment before budget reservation must fail");

    assert!(error.to_string().contains("unknown commerce transition"));
}

#[test]
fn commerce_order_replay_rejects_expired_mandate() {
    let bundle = load_bundle("expired-mandate");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("expired mandate must fail");

    assert!(error
        .to_string()
        .contains("mandate expired before payment capture"));
}

#[test]
fn commerce_order_replay_rejects_completed_order_with_open_dispute() {
    let bundle = load_bundle("open-dispute-completed");

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("completed order with open dispute must fail");

    assert!(error
        .to_string()
        .contains("unresolved payment recovery state"));
}

#[test]
fn commerce_order_replay_rejects_quote_evidence_mismatch() {
    let mut bundle = load_bundle("offline-psp-valid");
    mutate_event_log(&mut bundle, |event_log| {
        if let Some(events) = event_log["events"].as_array_mut() {
            for event in events {
                if event["transition"] == "bind_quote" {
                    event["evidence_refs"] = serde_json::json!(["quote-commerce-replayed-other"]);
                }
            }
        }
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("quote event bound to wrong quote must fail");

    assert!(error
        .to_string()
        .contains("quote event missing quote evidence"));
}

#[test]
fn commerce_order_replay_rejects_unknown_recovery_status_before_completion() {
    let mut bundle = load_bundle("offline-psp-valid");
    truncate_to_payment_verified(&mut bundle);
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["refund_status"] = serde_json::json!("merchant_claimed");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("unknown payment recovery status must fail closed");

    assert!(error.to_string().contains("unsupported refund_status"));
}

#[test]
fn commerce_order_replay_rejects_refund_before_completion() {
    let mut bundle = load_bundle("offline-psp-valid");
    truncate_to_payment_verified(&mut bundle);
    mutate_payment_lifecycle(&mut bundle, |payment_lifecycle| {
        payment_lifecycle["refund_status"] = serde_json::json!("succeeded");
    });

    let error = chio_commerce_order::verify_commerce_order(&bundle)
        .test_expect_err("refunded payment must not verify before completion");

    assert!(error
        .to_string()
        .contains("unresolved payment recovery state"));
}
