//! chio-reputation: deterministic local reputation scoring for Chio agents.
//!
//! This crate is intentionally pure and storage-agnostic. It scores an agent
//! from a caller-provided local corpus assembled from persisted receipts,
//! capability-lineage snapshots, and budget-usage records. It does not depend
//! on `chio-kernel`, which keeps the scoring model reusable and avoids a future
//! dependency cycle when kernel-side issuance hooks begin consuming it.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};

use chio_core::capability::{ChioScope, Operation, ToolGrant};
use chio_core::chio_receipt_id;
use chio_core::receipt::{ChioReceipt, Decision, ReceiptAttributionMetadata};
use serde::{Deserialize, Serialize};

const SECONDS_PER_DAY: u64 = 86_400;
const DEFAULT_HISTORY_RECEIPT_TARGET: u64 = 1_000;
const DEFAULT_HISTORY_DAY_TARGET: u64 = 30;
const DEFAULT_INCIDENT_PENALTY: f64 = 0.20;

/// One-shot guard so an empty trusted-kernel-key set only logs a warning the
/// first time integrity is evaluated. Repeated entries would otherwise flood
/// the log when callers iterate a large corpus of receipts.
static EMPTY_TRUSTED_KEYS_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_empty_trusted_keys_once() {
    if EMPTY_TRUSTED_KEYS_WARNED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        tracing::warn!(
            target: "chio_reputation",
            "ReputationConfig has no trusted_kernel_keys configured; all receipts will fail \
             integrity validation and reputation scoring will be unknown or zero. Populate via \
             ReputationConfig::with_trusted_kernel_keys before scoring."
        );
    }
}

#[cfg(test)]
fn reset_empty_trusted_keys_warning_for_tests() {
    EMPTY_TRUSTED_KEYS_WARNED.store(false, Ordering::Release);
}

fn receipt_integrity_valid(receipt: &ChioReceipt, config: &ReputationConfig) -> bool {
    if config.trusted_kernel_keys.is_empty() {
        warn_empty_trusted_keys_once();
        return false;
    }
    if !config
        .trusted_kernel_keys
        .contains(&receipt.kernel_key.to_hex())
    {
        return false;
    }
    if !chio_receipt_id(&receipt.body())
        .map(|id| id == receipt.id)
        .unwrap_or(false)
    {
        return false;
    }
    if !receipt.verify_signature().unwrap_or(false) {
        return false;
    }
    if !receipt.action.verify_hash().unwrap_or(false) {
        return false;
    }
    true
}

fn receipt_authority_valid(receipt: &ChioReceipt, config: &ReputationConfig) -> bool {
    receipt_integrity_valid(receipt, config) && receipt.is_allowed()
}

include!("model.rs");
include!("score.rs");
include!("compare.rs");
include!("issuance.rs");
include!("tests.rs");

pub mod feed;
pub mod feeds;
pub mod tier;
pub use feed::{compose_deltas, min_delta, ReputationFeed, ScoreDelta, MAX_FEED_DELTA};
pub use tier::{
    satisfies_floor, tier_from_deltas, tier_threshold, ReputationTier, MAX_COMPOSED_SCORE,
    TIER_1_THRESHOLD, TIER_2_THRESHOLD, TIER_3_PER_FEED_THRESHOLD, TIER_3_THRESHOLD,
};
