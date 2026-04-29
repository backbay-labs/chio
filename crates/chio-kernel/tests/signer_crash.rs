//! Integration test for the receipt-signer crash path.
//!
//! The graceful shutdown path is covered by `receipt_signing_async.rs`.
//! This file models a harder runtime loss: the signing task is aborted after
//! a request is queued; subsequent producers must fail closed inside a short
//! deadline rather than hanging on the channel.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel};
use chio_kernel::KernelError;
use serde_json::json;

#[allow(dead_code)]
#[path = "../src/kernel/signing_task.rs"]
mod signing_task;

const KERNEL_SEED: [u8; 32] = [
    0x51, 0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E, 0x3F, 0x40,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE, 0xCF, 0xD0, 0xE1, 0xF2, 0x03,
];

fn make_keypair() -> Keypair {
    Keypair::from_seed(&KERNEL_SEED)
}

fn make_body(n: usize, kernel_key: &Keypair) -> ChioReceiptBody {
    let nonce = format!("crash-{n:04}");
    let action = ToolCallAction::from_parameters(json!({
        "n": n,
        "label": nonce,
    }))
    .expect("payload canonicalises");
    let content_hash = sha256_hex(action.parameter_hash.as_bytes());
    let policy_hash = sha256_hex(format!("policy:{nonce}").as_bytes());
    ChioReceiptBody {
        id: format!("rcpt-{nonce}"),
        timestamp: 1_700_100_000 + (n as u64),
        capability_id: format!("cap-{nonce}"),
        tool_server: "tool.example".to_string(),
        tool_name: "echo".to_string(),
        action,
        decision: Decision::Allow,
        content_hash,
        policy_hash,
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn aborted_signing_task_fails_closed_without_hanging() {
    let keypair = make_keypair();
    let handle = Arc::new(signing_task::SigningTaskHandle::with_capacity(
        keypair.clone(),
        1,
    ));

    let queued = handle
        .try_sign(make_body(1, &keypair))
        .expect("first request queues before task runs");
    assert!(handle.is_spawned());

    let blocked_handle = Arc::clone(&handle);
    let blocked_keypair = keypair.clone();
    let blocked_producer =
        tokio::spawn(async move { blocked_handle.sign(make_body(2, &blocked_keypair)).await });

    handle.abort_for_crash_recovery_test();

    let queued_result = tokio::time::timeout(Duration::from_secs(1), queued)
        .await
        .expect("queued producer resolves after abort");
    assert!(
        queued_result.is_err(),
        "queued producer should observe dropped reply after abort"
    );

    let blocked_result = tokio::time::timeout(Duration::from_secs(1), blocked_producer)
        .await
        .expect("blocked producer resolves after abort")
        .expect("blocked producer task does not panic");
    assert!(
        blocked_result.is_err(),
        "blocked producer should fail closed after abort"
    );

    let post_abort =
        tokio::time::timeout(Duration::from_secs(1), handle.sign(make_body(3, &keypair)))
            .await
            .expect("post-abort producer resolves without hanging");
    assert!(
        post_abort.is_err(),
        "post-abort signing should fail closed, got Ok(_)"
    );
}
