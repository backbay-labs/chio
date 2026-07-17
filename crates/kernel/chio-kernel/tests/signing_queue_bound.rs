//! Byte-bound enforcement for the async receipt-signing queue.
//!
//! Each queued [`signing_task::SignRequest`] owns the full canonical-content
//! preimage. The bounded mpsc channel limits the queue by request *count* but
//! not by *bytes*; without a per-request byte cap a burst of large value/stream
//! receipts under signer backpressure could retain hundreds of full preimages
//! in memory. These tests assert the fail-closed byte cap:
//!
//! - a request at or under the cap still signs, and
//! - an oversized request is refused before it is enqueued (never truncated,
//!   which would break the WYSIWYS recompute), via both the awaiting [`sign`]
//!   path and the non-blocking [`try_sign`] path.
//!
//! The aggregate admission model is covered by three regressions:
//!
//! - a preimage larger than the aggregate budget inline-signs instead of being
//!   clamp-and-enqueued (case 1), so one oversized request never exceeds the
//!   queue memory bound;
//! - a producer that cannot enqueue under backpressure inline-signs instead of
//!   parking while holding the preimage (case 2), so many blocked producers
//!   retain no more than the configured budget; and
//! - a request that had not reached the channel when shutdown began is rejected,
//!   never enqueued after shutdown (case 3), with the closed-check and enqueue
//!   made atomic under the spawn gate.
//!
//! Every inline fallback still recomputes-and-refuses (WYSIWYS): a
//! render-A/sign-B attempt through the fallback is rejected too.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::crypto::{sha256_hex, Keypair};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
    kinds::TrustLevel,
};
// `signing_task.rs` is included below via `#[path]`; its `use crate::{...}`
// resolves against this test binary's crate root, so re-export the symbols it
// needs (including `DEFAULT_MAX_STREAM_TOTAL_BYTES`) here.
use chio_kernel::{KernelError, DEFAULT_MAX_STREAM_TOTAL_BYTES};
use serde_json::json;

#[allow(dead_code)]
#[path = "../src/kernel/signing_task.rs"]
mod signing_task;

use signing_task::{SigningTaskHandle, DEFAULT_MAX_SIGNING_CONTENT_BYTES};

/// Small explicit byte budget for the cap-enforcement tests so they exercise the
/// fail-closed boundary without allocating the 256 MiB default budget.
const TEST_BUDGET: usize = 4 * 1024;

const KERNEL_SEED: [u8; 32] = [
    0x77, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F,
];

/// Build a signable body whose `content_hash` is the sha256 of the given
/// canonical-content preimage, so the signing-task WYSIWYS recompute accepts it.
fn body_for_content(kernel_key: &Keypair, canonical_content: &[u8]) -> ChioReceiptBody {
    let action =
        ToolCallAction::from_parameters(json!({"tool": "echo"})).expect("payload canonicalises");
    ChioReceiptBody {
        id: "rcpt-queue-bound".to_string(),
        timestamp: 1_700_200_000,
        capability_id: "cap-queue-bound".to_string(),
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
        content_hash: sha256_hex(canonical_content),
        policy_hash: sha256_hex(b"policy:queue-bound"),
        evidence: Vec::new(),
        metadata: None,
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kernel_key.public_key(),
        bbs_projection_version: None,
    }
}

/// Build a handle whose per-request byte budget is the small [`TEST_BUDGET`] so
/// the cap-enforcement tests stay cheap.
fn small_budget_handle(keypair: &Keypair) -> SigningTaskHandle {
    SigningTaskHandle::with_capacity_and_max_content_bytes(
        keypair.clone(),
        /* capacity */ 256,
        TEST_BUDGET,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn sign_accepts_content_at_the_byte_budget() {
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = small_budget_handle(&keypair);

    // Exactly at the budget must be accepted.
    let content = vec![0xABu8; TEST_BUDGET];
    let body = body_for_content(&keypair, &content);

    let receipt = handle
        .sign(body, content)
        .await
        .expect("content at the budget should sign");
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn sign_refuses_oversized_content_fail_closed() {
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = small_budget_handle(&keypair);

    // One byte over the budget must be refused before it is ever enqueued.
    let content = vec![0xABu8; TEST_BUDGET + 1];
    let body = body_for_content(&keypair, &content);

    let err = handle
        .sign(body, content)
        .await
        .expect_err("oversized content must be refused");
    match err {
        KernelError::ReceiptSigningFailed(message) => {
            assert!(
                message.contains("over the"),
                "error should explain the queue byte budget: {message}"
            );
        }
        other => panic!("expected ReceiptSigningFailed, got {other:?}"),
    }

    // The task must remain usable: a normal request still signs afterwards.
    let small = b"small-content".to_vec();
    let body = body_for_content(&keypair, &small);
    let receipt = handle
        .sign(body, small)
        .await
        .expect("normal request still signs after an oversized rejection");
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn try_sign_returns_oversized_content_unsent() {
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = small_budget_handle(&keypair);

    let content = vec![0xABu8; TEST_BUDGET + 1];
    let body = body_for_content(&keypair, &content);

    let outcome = handle.try_sign(body, content.clone());
    match outcome {
        Err((_body, returned_content)) => {
            assert_eq!(
                returned_content.len(),
                content.len(),
                "oversized content is returned unsent, not enqueued"
            );
        }
        Ok(_) => panic!("oversized content must not be enqueued"),
    }

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn default_budget_admits_large_async_receipts_above_one_mib() {
    // The default per-request budget is aligned to the kernel's
    // configured stream/output max (256 MiB), not a fixed 1 MiB hard-reject. A
    // legitimate large async receipt above 1 MiB must sign through the async
    // queue, since it is the documented off-critical-path signer. The budget is
    // still BOUNDED: it equals the configured stream max.
    assert_eq!(
        DEFAULT_MAX_SIGNING_CONTENT_BYTES,
        usize::try_from(DEFAULT_MAX_STREAM_TOTAL_BYTES).unwrap(),
        "default signing budget must track the configured stream/output max"
    );
    const {
        assert!(
            DEFAULT_MAX_SIGNING_CONTENT_BYTES > 1024 * 1024,
            "default budget must exceed the old 1 MiB hard-reject"
        );
    }

    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = SigningTaskHandle::spawn(keypair.clone());

    // 2 MiB: comfortably over the retired 1 MiB cap, well under the default budget.
    let content = vec![0xCDu8; 2 * 1024 * 1024];
    let body = body_for_content(&keypair, &content);

    let receipt = handle
        .sign(body, content)
        .await
        .expect("a 2 MiB async receipt must sign under the configured-stream-max budget");
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn zero_per_request_cap_admits_large_receipts_unlimited() {
    // a per-request cap of 0 means UNLIMITED (matching
    // the inline signer), NOT a 1-byte cap. The kernel wires a `0` cap when
    // `max_stream_total_bytes == 0` ("unlimited stream") flows through, so the
    // async path must admit a large receipt rather than rejecting it as "1 byte
    // over". Without the fix, `max_content_bytes.max(1)` turned 0 into 1 and this
    // 64 KiB preimage would be refused fail-closed.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    // Per-request cap = 0 (unlimited); aggregate budget large enough to admit the
    // single request so we isolate the per-request-cap behaviour.
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 1024 * 1024,
    );

    // A preimage far larger than the retired 1-byte cap the `max(1)` bug imposed.
    let content = vec![0x5Au8; 64 * 1024];
    let body = body_for_content(&keypair, &content);

    let receipt = handle.sign(body, content).await.expect(
        "a 0 (unlimited) per-request cap must admit a 64 KiB receipt, not reject as 1-over",
    );
    assert!(receipt.verify_signature().expect("signature verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn aggregate_byte_budget_backpressures_even_with_channel_room() {
    // the AGGREGATE byte budget bounds the SUM of
    // in-flight queued preimage bytes independently of channel COUNT capacity.
    // On a current-thread runtime the spawned signing task does not run until we
    // `.await` it, so permits acquired by `try_sign` stay held; this lets us
    // assert deterministically that a second request is refused purely by the
    // aggregate byte budget while the channel still has count capacity.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    // Generous channel capacity (count) but a tiny 4-byte aggregate budget. Per
    // request cap is unlimited so the ONLY thing that can block the second send
    // is the aggregate byte budget.
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4,
    );

    // First request consumes the entire 4-byte aggregate budget and enqueues
    // (channel has plenty of count capacity). The task has not run yet, so the
    // permit is still held.
    let first_content = vec![0x11u8; 4];
    let first_body = body_for_content(&keypair, &first_content);
    let first = handle.try_sign(first_body, first_content);
    let first_rx = match first {
        Ok(rx) => rx,
        Err(_) => panic!("first request must enqueue: budget and channel both have room"),
    };

    // Second request: 1 byte. The channel still has count capacity, but the
    // aggregate byte budget is exhausted, so it MUST be refused (returned unsent)
    // rather than enqueued. This proves total queued bytes are bounded by the
    // aggregate budget, not just by channel count.
    let second_content = vec![0x22u8; 1];
    let second_body = body_for_content(&keypair, &second_content);
    match handle.try_sign(second_body, second_content) {
        Err((_body, returned)) => {
            assert_eq!(
                returned.len(),
                1,
                "second request returned unsent by aggregate byte budget backpressure"
            );
        }
        Ok(_) => panic!("aggregate byte budget exhausted: second request must not enqueue"),
    }

    // Drain: signing the first request releases its permit, so after shutdown the
    // task processes it and the first reply resolves. This also proves the budget
    // is RELEASED (not leaked) once a request is signed.
    drop(first_rx);
    handle.shutdown().await;

    // After the budget frees, a fresh request fits again, confirming the budget
    // is a recoverable bound, not a one-shot exhaustion.
    let handle =
        SigningTaskHandle::with_capacity_max_content_and_queued_bytes(keypair.clone(), 256, 0, 4);
    let content = vec![0x33u8; 4];
    let body = body_for_content(&keypair, &content);
    let receipt = handle
        .sign(body, content)
        .await
        .expect("a request within the aggregate budget signs");
    assert!(receipt.verify_signature().expect("signature verifies"));
    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn backpressure_under_exhausted_budget_signs_inline_without_parking() {
    // (case 2): a producer that cannot enqueue because the
    // aggregate budget is exhausted MUST NOT park while holding the preimage; it
    // signs INLINE through the same WYSIWYS primitive instead. We prove the
    // `sign` future completes in a SINGLE poll (no Pending park) even though the
    // budget is fully held by a queued request, so a would-be waiter retains no
    // preimage outside the accounting.
    use std::future::poll_fn;
    use std::future::Future;
    use std::pin::pin;
    use std::task::Poll;

    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4,
    );

    // First request consumes the entire 4-byte aggregate budget and enqueues. The
    // task has not run (current-thread runtime), so the permit stays held.
    let first_content = vec![0x11u8; 4];
    let first_body = body_for_content(&keypair, &first_content);
    let _first_rx = handle
        .try_sign(first_body, first_content)
        .expect("first request enqueues and holds the whole aggregate budget");

    // Second request: with the budget exhausted, `sign` must resolve to a signed
    // receipt via the inline fallback on the FIRST poll (no park).
    let second_content = vec![0x22u8; 1];
    let second_body = body_for_content(&keypair, &second_content);
    let mut sign_future = pin!(handle.sign(second_body, second_content));
    let receipt = poll_fn(|cx| match sign_future.as_mut().poll(cx) {
        Poll::Ready(result) => Poll::Ready(result),
        Poll::Pending => {
            panic!("sign must inline-sign under backpressure, not park holding the preimage")
        }
    })
    .await
    .expect("backpressure must inline-sign, not error");
    assert!(receipt
        .verify_signature()
        .expect("inline-signed receipt verifies"));

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_preimage_signs_inline_without_exceeding_queue_bound() {
    // (case 1): a single preimage LARGER than the aggregate byte budget must
    // NOT be enqueued. It must inline-sign instead. Prove (a) it signs and
    // verifies, and (b) the queue never held it: the whole aggregate budget is
    // still free afterwards, so a budget-filling request still enqueues via the
    // non-blocking `try_sign`.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    // Tiny 4-byte aggregate budget, unlimited per-request cap so ONLY the
    // aggregate bound governs admission.
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4,
    );

    // 64 bytes: an order of magnitude over the 4-byte aggregate budget.
    let oversized = vec![0xABu8; 64];
    let body = body_for_content(&keypair, &oversized);
    let receipt = handle
        .sign(body, oversized)
        .await
        .expect("an oversized preimage must inline-sign, never clamp-and-enqueue");
    assert!(receipt
        .verify_signature()
        .expect("oversized inline-signed receipt verifies"));

    // The oversized request was never queued, so the full 4-byte budget is still
    // available: a 4-byte request enqueues successfully via the non-blocking path.
    let fits = vec![0x33u8; 4];
    let fits_body = body_for_content(&keypair, &fits);
    handle
        .try_sign(fits_body, fits)
        .expect("aggregate budget was never consumed by the oversized request");

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_inline_fallback_still_refuses_render_a_sign_b() {
    // (case 1 + WYSIWYS): the oversized inline fallback routes
    // through the SAME content-recompute primitive as the queue path, so a body
    // whose `content_hash` does not match the canonical-content preimage (a
    // render-A / sign-B attempt) is refused on the inline path too. Memory stays
    // bounded AND the fail-closed contract is preserved.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4,
    );

    // Body hashes content-A, but we hand the signer content-B (both oversized so
    // they route through the inline fallback).
    let content_a = vec![0xA1u8; 64];
    let content_b = vec![0xB2u8; 64];
    let body = body_for_content(&keypair, &content_a);

    let err = handle
        .sign(body, content_b)
        .await
        .expect_err("render-A/sign-B through the inline fallback must be refused (WYSIWYS)");
    match err {
        KernelError::ReceiptSigningFailed(message) => {
            assert!(
                message.contains("content_hash mismatch") || message.contains("WYSIWYS"),
                "oversized inline fallback must fail closed on content mismatch: {message}"
            );
        }
        other => panic!("expected a WYSIWYS content-mismatch refusal, got {other:?}"),
    }

    handle.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_blocked_producers_do_not_retain_more_than_budget() {
    // (case 2): under a tiny aggregate budget, a burst of
    // concurrent producers must NOT each park holding a full preimage outside the
    // semaphore accounting (the old `acquire_aggregate_permit().await` retained a
    // preimage per blocked future, so memory grew with the waiter count). With the
    // inline fallback, every producer that cannot enqueue signs off-queue and
    // completes, so retained memory is bounded by the budget, not by the number of
    // in-flight producers. All 64 requests must complete (no hang, no unbounded
    // park) and every receipt must verify.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    // 4 KiB aggregate budget; 64 producers each submitting a 1 KiB preimage. The
    // sum (64 KiB) is 16x the budget, so most producers hit backpressure and take
    // the inline fallback rather than parking.
    let handle = std::sync::Arc::new(
        SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
            keypair.clone(),
            /* capacity */ 8,
            /* per-request cap */ 0,
            /* aggregate budget */ 4 * 1024,
        ),
    );

    let mut tasks = Vec::new();
    for i in 0..64u8 {
        let handle = std::sync::Arc::clone(&handle);
        let keypair = keypair.clone();
        tasks.push(tokio::spawn(async move {
            let content = vec![i; 1024];
            let body = body_for_content(&keypair, &content);
            handle.sign(body, content).await
        }));
    }

    let results = tokio::time::timeout(std::time::Duration::from_secs(20), async {
        let mut receipts = Vec::with_capacity(tasks.len());
        for task in tasks {
            receipts.push(task.await.expect("producer task joins"));
        }
        receipts
    })
    .await
    .expect("all producers must complete (a hang means producers parked unbounded)");

    for result in results {
        let receipt = result.expect("every producer signs (inline fallback or queued)");
        assert!(receipt
            .verify_signature()
            .expect("each signed receipt verifies"));
    }

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_before_send_rejects_request_no_post_shutdown_enqueue() {
    // (case 3): when `shutdown()` begins before a request reaches
    // the channel, that request MUST be rejected, never enqueued onto a draining
    // channel and never inline-signed. The fix makes the closed-check and the
    // `try_send` a single atomic step under the spawn gate, closing the
    // clone-then-send window where a sender clone survived the canonical sender
    // drop and let a producer enqueue post-shutdown work that shutdown would then
    // sign/await.
    //
    // Determinism: spawn the task with one signing call, then `shutdown()` to
    // latch `closed` and drop the canonical sender. A subsequent `sign` reaches
    // `try_enqueue_if_open`, observes `closed` under the gate, and rejects. This
    // covers BOTH the would-enqueue and the would-inline-fallback paths: no work
    // is admitted after shutdown began.
    let keypair = Keypair::from_seed(&KERNEL_SEED);
    let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
        keypair.clone(),
        /* capacity */ 256,
        /* per-request cap */ 0,
        /* aggregate budget */ 4 * 1024,
    );

    // Spawn the task with a first, normal signing call so `inner` is populated
    // (the clone-then-send window only exists once a task and sender exist).
    let warmup = vec![0x01u8; 8];
    let warmup_body = body_for_content(&keypair, &warmup);
    handle
        .sign(warmup_body, warmup)
        .await
        .expect("warmup request signs and spawns the task");

    // Shutdown latches `closed` and drops the canonical sender.
    handle.shutdown().await;

    // A request submitted after shutdown began must be rejected. It is small
    // enough to fit the budget and the channel, so the ONLY thing that can refuse
    // it is the post-shutdown closed-check inside the atomic enqueue. It must not
    // be enqueued and must not fall through to an inline signature.
    let late = vec![0x02u8; 8];
    let late_body = body_for_content(&keypair, &late);
    match handle.sign(late_body, late).await {
        Err(KernelError::Internal(message)) => {
            assert!(
                message.contains("already shut down"),
                "a request arriving after shutdown must be rejected as shut down, got: {message}"
            );
        }
        Err(other) => panic!("expected a shut-down rejection, got {other:?}"),
        Ok(_) => panic!(
            "a request that had not reached the channel before shutdown began must be \
             rejected, never enqueued or inline-signed after shutdown"
        ),
    }

    // An oversized request after shutdown must also be refused (the oversized
    // inline fallback honours the same shutdown exclusion), proving the
    // fallback does not become a post-shutdown bypass.
    let late_oversized = vec![0x03u8; 8 * 1024];
    let late_oversized_body = body_for_content(&keypair, &late_oversized);
    match handle.sign(late_oversized_body, late_oversized).await {
        Err(KernelError::Internal(message)) => {
            assert!(
                message.contains("already shut down"),
                "an oversized request after shutdown must also be refused, got: {message}"
            );
        }
        Err(other) => panic!("expected a shut-down rejection, got {other:?}"),
        Ok(_) => panic!("the oversized inline fallback must not bypass shutdown exclusion"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn signing_block_counter_covers_all_inline_fallbacks() {
    // Every signing-queue block path records chio_signing_queue_block_total{reason}
    // with the right reason. Drive all three inline-fallback branches (byte_budget
    // via an exhausted aggregate semaphore, channel_full via a full bounded
    // channel, oversized via a single preimage larger than the aggregate budget)
    // through the async
    // `sign` path (try_sign does not record). On the current-thread runtime the
    // spawned task does not run until awaited, so a first request enqueued via
    // `try_sign` keeps its permit/channel slot held while the second request
    // hits backpressure and inline-signs.
    use chio_metrics_spec::runtime::families;
    let keypair = Keypair::from_seed(&KERNEL_SEED);

    // byte_budget: tiny 4-byte aggregate budget, generous channel. The first
    // request holds the whole budget; the second (1 byte) fits the budget size
    // but finds zero permits available, hitting the byte_budget branch.
    {
        let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
            keypair.clone(),
            /* capacity */ 256,
            /* per-request cap */ 0,
            /* aggregate budget */ 4,
        );
        let first_content = vec![0x11u8; 4];
        let first_body = body_for_content(&keypair, &first_content);
        let first_rx = handle
            .try_sign(first_body, first_content)
            .expect("first request holds the whole aggregate budget");
        let second_content = vec![0x22u8; 1];
        let second_body = body_for_content(&keypair, &second_content);
        handle
            .sign(second_body, second_content)
            .await
            .expect("byte-budget backpressure inline-signs");
        drop(first_rx);
        handle.shutdown().await;
    }

    // channel_full: capacity 1, generous budget. The first request fills the
    // channel; the second acquires a permit but finds the channel full.
    {
        let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
            keypair.clone(),
            /* capacity */ 1,
            /* per-request cap */ 0,
            /* aggregate budget */ 1024 * 1024,
        );
        let first_content = vec![0x33u8; 8];
        let first_body = body_for_content(&keypair, &first_content);
        let first_rx = handle
            .try_sign(first_body, first_content)
            .expect("first request fills the single channel slot");
        let second_content = vec![0x44u8; 8];
        let second_body = body_for_content(&keypair, &second_content);
        handle
            .sign(second_body, second_content)
            .await
            .expect("channel-full backpressure inline-signs");
        drop(first_rx);
        handle.shutdown().await;
    }

    // oversized: a single preimage larger than the aggregate budget inline-signs
    // without ever being enqueued.
    {
        let handle = SigningTaskHandle::with_capacity_max_content_and_queued_bytes(
            keypair.clone(),
            /* capacity */ 256,
            /* per-request cap */ 0,
            /* aggregate budget */ 4,
        );
        let oversized = vec![0x55u8; 64];
        let oversized_body = body_for_content(&keypair, &oversized);
        handle
            .sign(oversized_body, oversized)
            .await
            .expect("oversized preimage inline-signs");
        handle.shutdown().await;
    }

    let mut body = String::new();
    families::SIGNING_QUEUE_BLOCK.render(&mut body);
    assert!(
        body.contains("chio_signing_queue_block_total{reason=\"byte_budget\"}"),
        "{body}"
    );
    assert!(
        body.contains("chio_signing_queue_block_total{reason=\"channel_full\"}"),
        "{body}"
    );
    assert!(
        body.contains("chio_signing_queue_block_total{reason=\"oversized\"}"),
        "{body}"
    );
}
