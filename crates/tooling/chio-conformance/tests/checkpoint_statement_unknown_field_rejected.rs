//! Negative conformance test: checkpoint statement field smuggling.
//!
//! Threat: because the checkpoint signature is computed over canonical
//! bytes re-serialized from the parsed struct, a body that tolerated
//! unknown fields would parse a smuggled field, drop it, recompute the
//! same digest, and verify. Two byte-different documents would then
//! both present as the same valid signed checkpoint, breaking any
//! consumer that assumes one canonical byte representation (dedup
//! keys, content-addressed stores, fork detectors comparing blobs).
//!
//! `KernelCheckpointBody` and `KernelCheckpoint` deny unknown fields,
//! so the smuggled document MUST fail to parse at all.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core::Keypair;
use chio_kernel::checkpoint::{build_checkpoint, KernelCheckpoint, KernelCheckpointBody};

#[test]
fn checkpoint_statement_with_smuggled_field_is_rejected_at_parse() {
    let kp = Keypair::generate();
    let checkpoint = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &kp).unwrap();

    let mut body_value = serde_json::to_value(&checkpoint.body).unwrap();
    body_value["smuggled"] = serde_json::json!("payload");
    let error = serde_json::from_value::<KernelCheckpointBody>(body_value).unwrap_err();
    assert!(
        error.to_string().contains("smuggled"),
        "unexpected error: {error}"
    );

    let mut statement_value = serde_json::to_value(&checkpoint).unwrap();
    statement_value["smuggled"] = serde_json::json!("payload");
    let error = serde_json::from_value::<KernelCheckpoint>(statement_value).unwrap_err();
    assert!(
        error.to_string().contains("smuggled"),
        "unexpected error: {error}"
    );
}
