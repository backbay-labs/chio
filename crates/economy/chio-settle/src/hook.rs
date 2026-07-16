//! Settlement hook trait routing finalized Chio receipts through the
//! existing `chio-settle/ops.rs` pipeline.
//!
//! This exposes a kernel-evaluator observer surface for the
//! `chio-settle` crate (the async-kernel post-dispatch slot). The hook
//! is invoked once a receipt has been
//! signed and durably stored; failure-to-settle never blocks dispatch
//! (the kernel observer slot consumes the [`SettlementHookError`] and
//! routes it to the retry/dead-letter machinery when a settlement
//! retry store is installed; otherwise the outcome is logged and
//! counted, never dropped).
//!
//! Settlement ordering is deterministic: implementers MUST process
//! observations sorted first by [`SettlementObservation::finalized_at`]
//! ascending and then by [`SettlementObservation::receipt_id`] lexically.
//!
//! Fail-closed semantics: signature-invalid, malformed, or unpriced
//! receipts return [`SettlementOutcome::Skipped`] without touching the
//! ops pipeline. The dispatch path is never rolled back by a
//! settlement failure.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use chio_core::capability::scope::MonetaryAmount;

use crate::SettlementError;

/// Schema string emitted on the wire for [`SettlementObservation`] frames.
pub const SETTLEMENT_OBSERVATION_SCHEMA: &str = "chio.settle.observation.v1";

/// Schema string emitted on the wire for [`SettlementOutcome`] frames.
pub const SETTLEMENT_OUTCOME_SCHEMA: &str = "chio.settle.outcome.v1";

/// Observation handed to a [`SettlementHook`] by the kernel observer
/// slot once a receipt has been signed and persisted. The structure is
/// deliberately storage-agnostic: it carries the finalized-receipt
/// identity plus the financial coordinates required to route the
/// settlement through `chio-settle/ops.rs`.
///
/// The kernel sets [`finalized_at`] to the receipt timestamp so a hook
/// implementation can sort by `(finalized_at, receipt_id)` to guarantee
/// the deterministic ordering the integration tests enforce.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementObservation {
    /// Schema tag (`chio.settle.observation.v1`).
    pub schema: String,
    /// `id` of the finalized [`chio_core::receipt::body::ChioReceipt`].
    pub receipt_id: String,
    /// `timestamp` carried over from the receipt (deterministic sort key).
    pub finalized_at: u64,
    /// Cluster operator (tenant) that owes the obligation, or `None`
    /// for single-tenant deployments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Tool server invoked.
    pub tool_server: String,
    /// Tool name invoked.
    pub tool_name: String,
    /// Capability id matched at evaluation time.
    pub capability_id: String,
    /// Settlement amount derived from the manifest pricing context. The
    /// kernel skips the hook entirely for zero-priced receipts; the
    /// amount on this struct is therefore always strictly positive.
    pub amount: MonetaryAmount,
    /// Receipt content hash, carried verbatim so a downstream auditor
    /// can confirm the settlement references the same bytes the kernel
    /// signed.
    pub content_hash: String,
    /// Receipt policy hash, carried verbatim for the same reason.
    pub policy_hash: String,
}

impl SettlementObservation {
    /// Construct a fresh observation, stamping the canonical schema tag.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        receipt_id: impl Into<String>,
        finalized_at: u64,
        tool_server: impl Into<String>,
        tool_name: impl Into<String>,
        capability_id: impl Into<String>,
        amount: MonetaryAmount,
        content_hash: impl Into<String>,
        policy_hash: impl Into<String>,
    ) -> Self {
        Self {
            schema: SETTLEMENT_OBSERVATION_SCHEMA.to_string(),
            receipt_id: receipt_id.into(),
            finalized_at,
            tenant_id: None,
            tool_server: tool_server.into(),
            tool_name: tool_name.into(),
            capability_id: capability_id.into(),
            amount,
            content_hash: content_hash.into(),
            policy_hash: policy_hash.into(),
        }
    }

    /// Attach a tenant identifier. Single-tenant deployments may leave
    /// this unset.
    #[must_use]
    pub fn with_tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Return the deterministic sort key used by hook implementations.
    /// Tuples sort lexicographically by `(finalized_at, receipt_id)`.
    #[must_use]
    pub fn ordering_key(&self) -> (u64, &str) {
        (self.finalized_at, self.receipt_id.as_str())
    }
}

/// Successful outcome of a hook invocation. Hooks classify each
/// observation into one of four shapes; the kernel observer slot
/// records the classification without altering the receipt path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum SettlementOutcome {
    /// The hook accepted the observation and routed it through the
    /// existing `chio-settle/ops.rs` pipeline. The opaque transcript
    /// id lets operators correlate the kernel-side observation with
    /// the downstream settlement record.
    Accepted {
        /// Schema tag (`chio.settle.outcome.v1`).
        schema: String,
        /// Stable transcript identifier produced by the ops pipeline.
        transcript_id: String,
    },
    /// The receipt was below the price threshold or otherwise outside
    /// the marketplace surface. Skipped outcomes are not retried.
    Skipped {
        /// Schema tag (`chio.settle.outcome.v1`).
        schema: String,
        /// Reason string for operator visibility.
        reason: String,
    },
    /// The hook rejected the observation but the failure is recoverable;
    /// callers MUST route the carried [`SettlementError`] through the
    /// retry policy in [`crate::retry`].
    Retryable {
        /// Schema tag (`chio.settle.outcome.v1`).
        schema: String,
        /// Failure reason carried for retry classification.
        reason: String,
    },
    /// The hook rejected the observation permanently; callers MUST
    /// route the carried [`SettlementError`] to the `settle_dead_letters`
    /// table without further retries.
    Permanent {
        /// Schema tag (`chio.settle.outcome.v1`).
        schema: String,
        /// Failure reason carried for the dead-letter row.
        reason: String,
    },
}

impl SettlementOutcome {
    /// Construct an `Accepted` outcome with the canonical schema tag.
    #[must_use]
    pub fn accepted(transcript_id: impl Into<String>) -> Self {
        Self::Accepted {
            schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
            transcript_id: transcript_id.into(),
        }
    }

    /// Construct a `Skipped` outcome with the canonical schema tag.
    #[must_use]
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self::Skipped {
            schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
            reason: reason.into(),
        }
    }

    /// Construct a `Retryable` outcome with the canonical schema tag.
    #[must_use]
    pub fn retryable(reason: impl Into<String>) -> Self {
        Self::Retryable {
            schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
            reason: reason.into(),
        }
    }

    /// Construct a `Permanent` outcome with the canonical schema tag.
    #[must_use]
    pub fn permanent(reason: impl Into<String>) -> Self {
        Self::Permanent {
            schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
            reason: reason.into(),
        }
    }

    /// Return `true` for outcomes that the retry policy must replay.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable { .. })
    }

    /// Return `true` for outcomes that land directly in the dead-letter
    /// table without further retries.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent { .. })
    }
}

/// Errors that may surface from a [`SettlementHook`]. All variants are
/// fail-closed: the kernel observer slot logs the error and routes it
/// through the retry/dead-letter pipeline; the dispatch path is never
/// rolled back.
#[derive(Debug, Error)]
pub enum SettlementHookError {
    /// The supplied observation was malformed.
    #[error("invalid observation: {0}")]
    InvalidObservation(String),
    /// The downstream settlement pipeline reported a transient error.
    /// Implementations SHOULD prefer [`SettlementOutcome::Retryable`]
    /// over surfacing this variant; it is provided for hooks that
    /// cannot classify the failure synchronously.
    #[error("transient settlement failure: {0}")]
    Transient(String),
    /// The downstream settlement pipeline reported a permanent error.
    #[error("permanent settlement failure: {0}")]
    Permanent(String),
    /// A lower-level [`SettlementError`] surfaced from the ops pipeline.
    #[error("settlement pipeline error: {0}")]
    Pipeline(#[from] SettlementError),
}

/// Hook routing finalized receipts through `chio-settle/ops.rs`.
///
/// The trait is dyn-compatible so the kernel observer slot can hold a
/// `Arc<dyn SettlementHook>`. Implementations MUST:
///
/// - Treat `observe` as observer-only relative to receipt bytes:
///   the receipt is already signed and persisted before this method
///   runs, and a hook MUST NOT mutate the receipt store.
/// - Process observations in `(finalized_at, receipt_id)` order when
///   batching is necessary (see [`SettlementObservation::ordering_key`]).
/// - Be safe to call concurrently from a tokio runtime; the kernel
///   observer slot does not serialize calls.
pub trait SettlementHook: Send + Sync {
    /// Observe a finalized receipt and route it through the settlement
    /// pipeline. See the trait-level docs for ordering and failure
    /// semantics.
    fn observe(
        &self,
        observation: &SettlementObservation,
    ) -> Result<SettlementOutcome, SettlementHookError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn require_ok<T, E>(result: Result<T, E>, context: &'static str) -> T
    where
        E: std::fmt::Debug,
    {
        result.unwrap_or_else(|error| panic!("{context}: {error:?}"))
    }

    fn sample_amount() -> MonetaryAmount {
        MonetaryAmount {
            currency: "USD".to_string(),
            units: 100,
        }
    }

    #[test]
    fn observation_schema_is_stable() {
        assert_eq!(SETTLEMENT_OBSERVATION_SCHEMA, "chio.settle.observation.v1");
    }

    #[test]
    fn outcome_schema_is_stable() {
        assert_eq!(SETTLEMENT_OUTCOME_SCHEMA, "chio.settle.outcome.v1");
    }

    #[test]
    fn ordering_key_sorts_by_finalized_at_then_receipt_id() {
        let a = SettlementObservation::new(
            "rcpt-b",
            10,
            "srv",
            "tool",
            "cap",
            sample_amount(),
            "ch",
            "ph",
        );
        let b = SettlementObservation::new(
            "rcpt-a",
            10,
            "srv",
            "tool",
            "cap",
            sample_amount(),
            "ch",
            "ph",
        );
        let c = SettlementObservation::new(
            "rcpt-c",
            5,
            "srv",
            "tool",
            "cap",
            sample_amount(),
            "ch",
            "ph",
        );
        let mut frames = [a.clone(), b.clone(), c.clone()];
        frames.sort_by(|left, right| left.ordering_key().cmp(&right.ordering_key()));
        assert_eq!(frames[0].receipt_id, "rcpt-c");
        assert_eq!(frames[1].receipt_id, "rcpt-a");
        assert_eq!(frames[2].receipt_id, "rcpt-b");
    }

    #[test]
    fn outcome_classifiers_match_constructors() {
        let retry = SettlementOutcome::retryable("rpc lag");
        assert!(retry.is_retryable());
        assert!(!retry.is_permanent());

        let dead = SettlementOutcome::permanent("policy denied");
        assert!(!dead.is_retryable());
        assert!(dead.is_permanent());

        let skip = SettlementOutcome::skipped("zero-price receipt");
        assert!(!skip.is_retryable());
        assert!(!skip.is_permanent());

        let ok = SettlementOutcome::accepted("ts-1");
        assert!(!ok.is_retryable());
        assert!(!ok.is_permanent());
    }

    /// `&dyn SettlementHook` must remain object-safe so kernel observer
    /// slots can hold a heterogeneous handle.
    #[test]
    fn settlement_hook_is_object_safe() {
        struct NoopHook;
        impl SettlementHook for NoopHook {
            fn observe(
                &self,
                observation: &SettlementObservation,
            ) -> Result<SettlementOutcome, SettlementHookError> {
                if observation.amount.units == 0 {
                    return Ok(SettlementOutcome::skipped("zero amount"));
                }
                Ok(SettlementOutcome::accepted(format!(
                    "ts-{}",
                    observation.receipt_id
                )))
            }
        }
        let hook: std::sync::Arc<dyn SettlementHook> = std::sync::Arc::new(NoopHook);
        let observation = SettlementObservation::new(
            "rcpt-1",
            42,
            "srv",
            "tool",
            "cap",
            sample_amount(),
            "ch",
            "ph",
        );
        let outcome = require_ok(hook.observe(&observation), "hook returns observed outcome");
        assert!(matches!(outcome, SettlementOutcome::Accepted { .. }));
    }
}
