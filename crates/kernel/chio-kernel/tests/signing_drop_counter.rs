//! Integration test for signing-task backpressure telemetry.
//!
//! The signing channel remains bounded and backpressured. This test asserts
//! that a producer attempting to submit while the queue is full increments
//! `chio_signing_queue_block_total` rather than dropping the request.
//!
//! (case 2): a producer that hits a full queue no longer PARKS
//! holding the preimage; it signs INLINE through the same WYSIWYS primitive and
//! completes immediately. The block counter still increments (the queue bound was
//! hit), but the request is neither dropped nor blocked: it is served off-queue,
//! so retained memory stays bounded.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    body::chio_receipt_id, body::ChioReceipt, body::ChioReceiptBody, decision::Decision,
    decision::ToolCallAction, kinds::TrustLevel, signing::CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY,
};
// `DEFAULT_MAX_STREAM_TOTAL_BYTES` is consumed by the `#[path]`-included
// `signing_task.rs` via `crate::DEFAULT_MAX_STREAM_TOTAL_BYTES`.
use chio_kernel::{KernelError, DEFAULT_MAX_STREAM_TOTAL_BYTES};
use serde_json::json;

#[allow(dead_code)]
#[path = "../src/kernel/signing_task.rs"]
pub(crate) mod signing_task;

const KERNEL_SEED: [u8; 32] = [
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28, 0x19, 0x0A, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06,
    0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06,
];

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWake))
}

fn make_keypair() -> Keypair {
    Keypair::from_seed(&KERNEL_SEED)
}

/// Returns a signable body together with the exact canonical-content preimage
/// its `content_hash` was derived from, so the signing-task WYSIWYS recompute
/// accepts it.
fn make_body(n: usize, kernel_key: &Keypair) -> Result<(ChioReceiptBody, Vec<u8>), String> {
    let nonce = format!("block-counter-{n:04}");
    let action = ToolCallAction::from_parameters(json!({
        "n": n,
        "label": nonce,
    }))
    .map_err(|error| format!("payload canonicalisation failed: {error}"))?;
    let canonical_content = action.parameter_hash.as_bytes().to_vec();
    let content_hash = sha256_hex(&canonical_content);
    let policy_hash = sha256_hex(format!("policy:{nonce}").as_bytes());
    // The input body carries the producer's pre-binding id.
    // `sign_one_with_backend` (via `chio_kernel_core::sign_receipt`) binds the
    // `chio_receipt_signing_nonce` metadata key to this id and recomputes the
    // canonical id over the nonce-bound body before signing, so the emitted id
    // differs from this one. Post-sign assertions reconstruct the expected
    // post-binding id via `expected_signed_id`.
    let mut body = ChioReceiptBody {
        id: format!("rcpt-{nonce}"),
        timestamp: 1_700_200_000 + (n as u64),
        capability_id: format!("cap-{nonce}"),
        tool_server: "tool.example".to_string(),
        tool_name: "echo".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash,
        policy_hash,
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
        bbs_projection_version: None,
    };
    body.id =
        chio_receipt_id(&body).map_err(|error| format!("canonical receipt id failed: {error}"))?;
    Ok((body, canonical_content))
}

/// Bind the `chio_receipt_signing_nonce` metadata key to the pre-binding
/// receipt id, mirroring `chio_core_types::receipt::signing::bind_receipt_signing_nonce`
/// (the private step `chio_kernel_core::sign_receipt` runs before computing the
/// content-addressed id). The nonce is the trimmed pre-binding `body.id`; an
/// existing non-object metadata value is preserved under `original_metadata`.
fn bind_signing_nonce(body: &mut ChioReceiptBody) {
    let nonce = body.id.trim();
    if nonce.is_empty() {
        return;
    }
    let mut metadata = match body.metadata.take() {
        Some(serde_json::Value::Object(map)) => map,
        Some(value) => {
            let mut map = serde_json::Map::new();
            map.insert("original_metadata".to_string(), value);
            map
        }
        None => serde_json::Map::new(),
    };
    metadata.insert(
        CHIO_RECEIPT_SIGNING_NONCE_METADATA_KEY.to_string(),
        serde_json::Value::String(nonce.to_string()),
    );
    body.metadata = Some(serde_json::Value::Object(metadata));
}

/// The authoritative receipt id the signing pipeline emits for `body`:
/// bind the signing nonce, then recompute `chio_receipt_id` over the
/// nonce-bound body (the exact transform `sign_receipt` applies before
/// signing).
fn expected_signed_id(body: &ChioReceiptBody) -> Result<String, String> {
    let mut bound = body.clone();
    bind_signing_nonce(&mut bound);
    chio_receipt_id(&bound).map_err(|error| format!("canonical receipt id failed: {error}"))
}

fn rendered_signing_queue_block_total() -> Result<u64, String> {
    // The signing-queue block counter carries a `reason` label; a full bounded
    // channel records reason="channel_full". An absent series means zero blocks
    // so far (the runtime family only renders series that exist).
    let body = chio_kernel::render_guard_metrics_prometheus();
    match body.lines().find_map(|line| {
        line.strip_prefix("chio_signing_queue_block_total{reason=\"channel_full\"} ")
            .map(str::parse::<u64>)
    }) {
        Some(parsed) => parsed.map_err(|error| {
            format!("rendered chio_signing_queue_block_total was invalid: {error}")
        }),
        None => Ok(0),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn full_signing_queue_increments_block_counter_without_dropping() -> Result<(), String> {
    let keypair = make_keypair();
    let handle = signing_task::SigningTaskHandle::with_capacity(keypair.clone(), 1);

    let (queued_body, queued_content) = make_body(1, &keypair)?;
    // The signer binds the signing nonce and recomputes the id before
    // signing, so capture the expected post-binding id (not `body.id`) for the
    // post-sign assertions below. This keeps the test from hardcoding the
    // SHA-256 hash of the fixture.
    let queued_expected_id = expected_signed_id(&queued_body)?;
    let queued = handle
        .try_sign(queued_body, queued_content)
        .map_err(|_| "first request should queue before spawned task runs".to_string())?;
    let before = rendered_signing_queue_block_total()?;

    let (blocked_body, blocked_content) = make_body(2, &keypair)?;
    let blocked_expected_id = expected_signed_id(&blocked_body)?;
    let mut blocked = Box::pin(handle.sign(blocked_body, blocked_content));
    let waker = noop_waker();
    let mut context = Context::from_waker(&waker);
    // (case 2): a full queue routes the producer to the INLINE
    // fallback instead of parking. The future therefore resolves on the FIRST
    // poll (Ready) rather than returning Pending. The request is served off-queue,
    // so it neither blocks holding the preimage nor is dropped.
    let inline_signed = match Pin::new(&mut blocked).poll(&mut context) {
        Poll::Ready(result) => {
            result.map_err(|error| format!("full-queue inline fallback failed: {error}"))?
        }
        Poll::Pending => {
            return Err(
                "producer must inline-sign when the bounded queue is full, not park".to_string(),
            )
        }
    };
    assert_eq!(
        inline_signed.id, blocked_expected_id,
        "inline-served request emits the same authoritative id as the queued path",
    );
    assert!(inline_signed
        .verify_signature()
        .map_err(|error| format!("inline-served signature check failed: {error}"))?);

    assert_eq!(
        rendered_signing_queue_block_total()?,
        before + 1,
        "a full queue still increments chio_signing_queue_block_total (the bound was hit)",
    );

    // The queued request still drains and signs normally; the inline fallback did
    // not disturb the in-flight queued request.
    let signed = queued
        .await
        .map_err(|error| format!("queued signer reply channel closed: {error}"))?
        .map_err(|error| format!("queued request failed to sign: {error}"))?;
    assert_eq!(signed.id, queued_expected_id);

    handle.shutdown().await;
    Ok(())
}
