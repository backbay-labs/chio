//! Settlement observer byte-identity integration test.
//!
//! Drives ten finalized receipts through the kernel settlement observer
//! slot and asserts:
//!
//! 1. Every observation invokes the registered hook exactly once.
//! 2. All ten outcomes are `Accepted` (none retryable, none permanent,
//!    none skipped because each receipt carries a non-zero price).
//! 3. The canonical bytes of every receipt are byte-identical to the
//!    no-settlement baseline. Settlement is observer-only relative to
//!    the receipt path: registering or not registering a hook MUST NOT
//!    change a single receipt byte.
//! 4. The hook receives observations whose `(finalized_at, receipt_id)`
//!    keys match the kernel's input order, demonstrating the
//!    deterministic ordering documented on the trait.
//!
//! The deterministic-replay byte-identity goldens are the receipt-byte
//! oracle; this test reuses the same
//! `chio_core::canonical::canonical_json_bytes` encoding the goldens
//! were minted under, so the assertion lives on the same byte oracle.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::chio_receipt_id, body::ChioReceipt, body::ChioReceiptBody, decision::Decision,
    decision::ToolCallAction, kinds::TrustLevel, metadata::GuardEvidence,
};
use chio_kernel::settlement_observer::{
    self, SettlementObserverStatus, SETTLEMENT_OBSERVER_STATUS_SCHEMA,
};
use chio_settle::{SettlementHook, SettlementHookError, SettlementObservation, SettlementOutcome};

/// Hook that records every observation it sees and always accepts.
struct RecordingHook {
    observations: Mutex<Vec<SettlementObservation>>,
}

impl RecordingHook {
    fn new() -> Self {
        Self {
            observations: Mutex::new(Vec::new()),
        }
    }

    fn snapshot(&self) -> Vec<SettlementObservation> {
        self.observations
            .lock()
            .expect("recording hook lock")
            .clone()
    }
}

impl SettlementHook for RecordingHook {
    fn observe(
        &self,
        observation: &SettlementObservation,
    ) -> Result<SettlementOutcome, SettlementHookError> {
        self.observations
            .lock()
            .expect("recording hook lock")
            .push(observation.clone());
        Ok(SettlementOutcome::accepted(format!(
            "ts-{}",
            observation.receipt_id
        )))
    }
}

/// Build a signed receipt for the test batch. Returns the signed receipt
/// paired with the content-addressed id the signing pipeline computes for
/// the body. The caller can use the returned id to assert observation
/// ordering without having to hardcode the canonical hash.
fn build_receipt(index: u64, kp: &Keypair) -> (ChioReceipt, String) {
    let metadata = serde_json::json!({
        "financial": {
            "cost_charged": 100 + index, "currency": "USD"
        }
    });
    let action = ToolCallAction::from_parameters(serde_json::json!({"i": index}))
        .expect("test action constructs");
    let mut body = ChioReceiptBody {
        id: format!("rcpt-{index:03}"),
        timestamp: 1_000 + index,
        capability_id: format!("cap-{index}"),
        tool_server: "srv".to_string(),
        tool_name: "tool".to_string(),
        action,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: format!("ch-{index}"),
        policy_hash: "policy-1".to_string(),
        evidence: vec![GuardEvidence {
            guard_name: "G".to_string(),
            verdict: true,
            details: None,
        }],
        metadata: Some(metadata),
        trust_level: TrustLevel::default(),
        tenant_id: None,
        kernel_key: kp.public_key(),
        bbs_projection_version: None,
    };
    // Seed the body id, then sign. `ChioReceipt::sign` binds the canonical
    // signing nonce into metadata and recomputes the content-addressed id over
    // that nonce-augmented input, so the authoritative id is the one carried by
    // the signed receipt; read it back rather than recomputing it here.
    body.id = chio_receipt_id(&body).expect("canonical receipt id computes");
    let receipt = ChioReceipt::sign(body, kp).expect("test receipt signs");
    let canonical_id = receipt.id.clone();
    (receipt, canonical_id)
}

#[test]
fn ten_receipts_produce_ten_settlements_with_byte_identical_receipts() {
    let kp = Keypair::generate();
    let signed: Vec<(ChioReceipt, String)> = (0..10).map(|i| build_receipt(i, &kp)).collect();
    let receipts: Vec<&ChioReceipt> = signed.iter().map(|(r, _)| r).collect();
    let expected_ids: Vec<&str> = signed.iter().map(|(_, id)| id.as_str()).collect();

    // Baseline canonical bytes computed BEFORE any hook is invoked.
    let baseline_bytes: Vec<Vec<u8>> = receipts
        .iter()
        .map(|receipt| canonical_json_bytes(*receipt).expect("baseline canonical bytes"))
        .collect();

    let hook = Arc::new(RecordingHook::new());
    let hook_handle: Arc<dyn SettlementHook> = hook.clone();

    let mut statuses = Vec::with_capacity(receipts.len());
    for receipt in &receipts {
        statuses.push(settlement_observer::run_observer(
            Some(&hook_handle),
            receipt,
            std::slice::from_ref(&receipt.kernel_key),
        ));
    }

    // Invariant 1: ten observations, ten outcomes, each one accepted.
    assert_eq!(statuses.len(), 10);
    let observed = hook.snapshot();
    assert_eq!(observed.len(), 10);

    let mut accepted_transcripts = Vec::new();
    for status in &statuses {
        match status {
            SettlementObserverStatus::Observed {
                outcome: SettlementOutcome::Accepted { transcript_id, .. },
            } => accepted_transcripts.push(transcript_id.clone()),
            other => panic!("expected accepted outcome, got {other:?}"),
        }
    }
    assert_eq!(accepted_transcripts.len(), 10);

    // Invariant 2: receipts are byte-identical pre and post observer.
    for (receipt, baseline) in receipts.iter().zip(baseline_bytes.iter()) {
        let after = canonical_json_bytes(*receipt).expect("post-observer canonical bytes");
        assert_eq!(
            &after, baseline,
            "settlement hook must NEVER mutate receipt bytes"
        );
    }

    // Invariant 3: observation order matches receipt order, and the
    // documented `(finalized_at, receipt_id)` ordering key sorts the
    // same as input order (here strictly increasing finalized_at). The
    // observed `receipt_id` is the canonical content-addressed id that
    // `ChioReceipt::sign` derives from the body; we pull it from
    // `expected_ids` so the assertion stays decoupled from the SHA-256
    // hash of the body fixture.
    for (i, observation) in observed.iter().enumerate() {
        assert_eq!(observation.receipt_id, expected_ids[i]);
        assert_eq!(observation.finalized_at, 1_000 + i as u64);
        let key = observation.ordering_key();
        assert_eq!(key.0, observation.finalized_at);
        assert_eq!(key.1, observation.receipt_id.as_str());
    }

    // Invariant 4: the schema constants stay pinned; this is a thin
    // belt-and-suspenders check so a refactor that re-tags the
    // observer-status frame trips the integration test before it
    // reaches a downstream subscriber.
    assert_eq!(
        SETTLEMENT_OBSERVER_STATUS_SCHEMA,
        "chio.settle.observer-status.v1"
    );
}

#[test]
fn no_settlement_baseline_matches_with_settlement_canonical_bytes() {
    // Drive the same ten receipts through TWO kernels: one with a
    // recording hook, one with no hook. The receipt bytes must match
    // pairwise. This is the "byte-equivalent of the no-settlement
    // baseline" assertion.
    let kp = Keypair::generate();
    let receipts_no_hook: Vec<ChioReceipt> = (0..10).map(|i| build_receipt(i, &kp).0).collect();
    let receipts_with_hook: Vec<ChioReceipt> = (0..10).map(|i| build_receipt(i, &kp).0).collect();

    let hook: Arc<dyn SettlementHook> = Arc::new(RecordingHook::new());

    // Run the observer for the with-hook variant only.
    for receipt in &receipts_with_hook {
        let _status = settlement_observer::run_observer(
            Some(&hook),
            receipt,
            std::slice::from_ref(&receipt.kernel_key),
        );
    }

    for (no_hook, with_hook) in receipts_no_hook.iter().zip(receipts_with_hook.iter()) {
        let baseline = canonical_json_bytes(no_hook).expect("baseline canonical bytes");
        let observed = canonical_json_bytes(with_hook).expect("observed canonical bytes");
        assert_eq!(
            baseline, observed,
            "receipts byte-equivalent under no-settlement vs with-settlement"
        );
    }
}
