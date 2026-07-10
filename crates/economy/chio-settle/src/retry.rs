//! Bounded exponential retry policy for [`SettlementHook`] failures.
//!
//! Binds settlement failures to a documented retry envelope
//! plus a `settle_dead_letters` table. The policy is a pure function:
//! it does not own any clock or storage, leaving observability and
//! persistence to the kernel observer slot and the SQLite store
//! (see `chio-store-sqlite::dead_letters`).
//!
//! Fail-closed: once the bounded number of attempts has been exhausted,
//! the next decision is [`RetryDecision::DeadLetter`] and the caller
//! MUST persist a `settle_dead_letters` row instead of replaying.
//! Permanent outcomes short-circuit the retry envelope on the first
//! attempt.
//!
//! [`SettlementHook`]: crate::hook::SettlementHook

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::hook::SettlementOutcome;
use crate::SettlementError;

/// Schema string emitted on the wire for [`DeadLetterRecord`] frames.
pub const SETTLE_DEAD_LETTER_SCHEMA: &str = "chio.settle.dead-letter.v1";

/// Bound on the number of retries before a transient failure is
/// downgraded to a permanent dead-letter row. The total attempt count
/// is `max_retries + 1` (the original call plus the retries).
pub const DEFAULT_MAX_RETRIES: u32 = 5;

/// Initial backoff for the first retry attempt.
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 250;

/// Multiplier applied to the previous backoff to produce the next.
pub const DEFAULT_BACKOFF_MULTIPLIER: u32 = 2;

/// Hard cap on a single backoff interval (avoids unbounded growth).
pub const DEFAULT_BACKOFF_CAP_MS: u64 = 60_000;

/// Documented retry envelope for the settlement observer slot.
///
/// All fields are policy inputs; the runtime evaluation is a pure
/// function. The defaults match the bounds documented in the settlement
/// audit doc and are wired into [`crate::hook::SettlementHook`]
/// callers via [`classify_attempt`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    /// Maximum number of retries before the failure is dead-lettered.
    /// `0` means the original call is the only attempt.
    pub max_retries: u32,
    /// Initial backoff applied between attempt 0 and attempt 1.
    pub initial_backoff_ms: u64,
    /// Multiplier on the previous backoff when computing the next.
    pub backoff_multiplier: u32,
    /// Hard cap on a single backoff interval, in milliseconds.
    pub backoff_cap_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff_ms: DEFAULT_INITIAL_BACKOFF_MS,
            backoff_multiplier: DEFAULT_BACKOFF_MULTIPLIER,
            backoff_cap_ms: DEFAULT_BACKOFF_CAP_MS,
        }
    }
}

impl RetryPolicy {
    /// Compute the backoff applied before the `attempt`-th retry.
    /// `attempt = 0` returns the configured initial backoff.
    /// Caps at [`Self::backoff_cap_ms`].
    #[must_use]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let multiplier = u64::from(self.backoff_multiplier).max(1);
        // Saturating arithmetic: very large attempt counts must not
        // panic; they land on the cap.
        let mut delay = self.initial_backoff_ms;
        for _ in 0..attempt {
            delay = delay.saturating_mul(multiplier);
            if delay >= self.backoff_cap_ms {
                delay = self.backoff_cap_ms;
                break;
            }
        }
        Duration::from_millis(delay.min(self.backoff_cap_ms))
    }
}

/// Decision returned by [`classify_attempt`] for one observed failure.
///
/// Variants:
///
/// - `Retry`: the caller MUST sleep [`backoff`] and replay the hook.
///   `attempt` records the retry index that the next call represents
///   (0 means the first retry, i.e. the second total attempt).
/// - `DeadLetter`: the caller MUST persist a [`DeadLetterRecord`] and
///   MUST NOT retry again. This is the only sink for permanent
///   failures and for transients that exhaust the envelope.
/// - `Skip`: the failure was actually a [`SettlementOutcome::Skipped`]
///   passthrough; nothing to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    Retry { attempt: u32, backoff: Duration },
    DeadLetter { reason: String },
    Skip { reason: String },
}

/// Classify one attempt's outcome under the supplied policy.
///
/// `attempt` is the zero-indexed retry counter for the current
/// observation. Pass `0` on the first failure; on the next failure
/// pass `1`, etc. The returned [`RetryDecision`] tells the caller
/// whether to sleep and replay or to land a dead-letter row.
///
/// Permanent outcomes short-circuit: no retry envelope is consumed,
/// and the call returns `DeadLetter` immediately with the carried
/// reason string. Skipped outcomes are passed through verbatim.
#[must_use]
pub fn classify_attempt(
    policy: &RetryPolicy,
    attempt: u32,
    outcome: &SettlementOutcome,
) -> RetryDecision {
    match outcome {
        SettlementOutcome::Accepted { .. } => RetryDecision::Skip {
            reason: "accepted outcomes do not consume the retry envelope".to_string(),
        },
        SettlementOutcome::Skipped { reason, .. } => RetryDecision::Skip {
            reason: reason.clone(),
        },
        SettlementOutcome::Permanent { reason, .. } => RetryDecision::DeadLetter {
            reason: reason.clone(),
        },
        SettlementOutcome::Retryable { reason, .. } => {
            if attempt >= policy.max_retries {
                RetryDecision::DeadLetter {
                    reason: format!(
                        "retry envelope exhausted after {attempts} attempts: {reason}",
                        attempts = attempt + 1,
                    ),
                }
            } else {
                RetryDecision::Retry {
                    attempt: attempt + 1,
                    backoff: policy.backoff_for(attempt),
                }
            }
        }
    }
}

/// Permanent record persisted in the `settle_dead_letters` table.
///
/// Wire-stable: the canonical-JSON bytes of this struct are the
/// row contents for offline review. The kernel observer slot
/// constructs one of these on either a permanent outcome or an
/// exhausted retry envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadLetterRecord {
    /// Schema tag (`chio.settle.dead-letter.v1`).
    pub schema: String,
    /// `id` of the originating receipt.
    pub receipt_id: String,
    /// Receipt finalization timestamp at the time of dead-lettering.
    pub finalized_at: u64,
    /// Number of attempts that ran before the failure was sealed in.
    /// Always at least one (the original call).
    pub attempts: u32,
    /// Operator-visible reason, lifted verbatim from the outcome.
    pub reason: String,
    /// Optional structured error string from the underlying pipeline.
    /// Populated when the dead letter was triggered by a
    /// [`SettlementError`]; otherwise `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline_error: Option<String>,
}

impl DeadLetterRecord {
    /// Build a new dead-letter record stamped with the canonical schema.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        finalized_at: u64,
        attempts: u32,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            schema: SETTLE_DEAD_LETTER_SCHEMA.to_string(),
            receipt_id: receipt_id.into(),
            finalized_at,
            attempts: attempts.max(1),
            reason: reason.into(),
            pipeline_error: None,
        }
    }

    /// Attach a structured pipeline error string. Useful when the
    /// dead letter is triggered by a [`SettlementError`] surfaced from
    /// `chio-settle/ops.rs`.
    #[must_use]
    pub fn with_pipeline_error(mut self, error: &SettlementError) -> Self {
        self.pipeline_error = Some(error.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn require_some<T>(value: Option<T>, context: &'static str) -> T {
        value.unwrap_or_else(|| panic!("{context}"))
    }

    #[test]
    fn schema_is_stable() {
        assert_eq!(SETTLE_DEAD_LETTER_SCHEMA, "chio.settle.dead-letter.v1");
    }

    #[test]
    fn default_policy_matches_documented_bounds() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, DEFAULT_MAX_RETRIES);
        assert_eq!(policy.initial_backoff_ms, DEFAULT_INITIAL_BACKOFF_MS);
        assert_eq!(policy.backoff_multiplier, DEFAULT_BACKOFF_MULTIPLIER);
        assert_eq!(policy.backoff_cap_ms, DEFAULT_BACKOFF_CAP_MS);
    }

    #[test]
    fn backoff_grows_exponentially_until_cap() {
        let policy = RetryPolicy {
            max_retries: 8,
            initial_backoff_ms: 100,
            backoff_multiplier: 2,
            backoff_cap_ms: 1000,
        };
        assert_eq!(policy.backoff_for(0), Duration::from_millis(100));
        assert_eq!(policy.backoff_for(1), Duration::from_millis(200));
        assert_eq!(policy.backoff_for(2), Duration::from_millis(400));
        assert_eq!(policy.backoff_for(3), Duration::from_millis(800));
        // After the cap engages further attempts saturate at the cap.
        assert_eq!(policy.backoff_for(4), Duration::from_millis(1000));
        assert_eq!(policy.backoff_for(50), Duration::from_millis(1000));
    }

    #[test]
    fn permanent_outcomes_skip_the_retry_envelope() {
        let policy = RetryPolicy::default();
        let outcome = SettlementOutcome::permanent("policy denied");
        match classify_attempt(&policy, 0, &outcome) {
            RetryDecision::DeadLetter { reason } => assert_eq!(reason, "policy denied"),
            other => panic!("expected dead letter, got {other:?}"),
        }
    }

    #[test]
    fn skipped_outcomes_pass_through() {
        let policy = RetryPolicy::default();
        let outcome = SettlementOutcome::skipped("zero amount");
        assert!(matches!(
            classify_attempt(&policy, 0, &outcome),
            RetryDecision::Skip { .. }
        ));
    }

    #[test]
    fn accepted_outcomes_pass_through() {
        let policy = RetryPolicy::default();
        let outcome = SettlementOutcome::accepted("ts-1");
        assert!(matches!(
            classify_attempt(&policy, 0, &outcome),
            RetryDecision::Skip { .. }
        ));
    }

    #[test]
    fn retryable_outcomes_consume_the_envelope_then_dead_letter() {
        let policy = RetryPolicy {
            max_retries: 2,
            initial_backoff_ms: 10,
            backoff_multiplier: 2,
            backoff_cap_ms: 100,
        };
        let outcome = SettlementOutcome::retryable("rpc lag");
        match classify_attempt(&policy, 0, &outcome) {
            RetryDecision::Retry { attempt, .. } => assert_eq!(attempt, 1),
            other => panic!("expected retry, got {other:?}"),
        }
        match classify_attempt(&policy, 1, &outcome) {
            RetryDecision::Retry { attempt, .. } => assert_eq!(attempt, 2),
            other => panic!("expected retry, got {other:?}"),
        }
        match classify_attempt(&policy, 2, &outcome) {
            RetryDecision::DeadLetter { reason } => {
                assert!(reason.contains("retry envelope exhausted"));
            }
            other => panic!("expected dead letter, got {other:?}"),
        }
    }

    #[test]
    fn dead_letter_record_with_pipeline_error_carries_error_string() {
        let record = DeadLetterRecord::new("rcpt-1", 100, 3, "policy denied")
            .with_pipeline_error(&SettlementError::Rpc("connection refused".to_string()));
        assert_eq!(record.attempts, 3);
        assert_eq!(record.schema, SETTLE_DEAD_LETTER_SCHEMA);
        let pipeline = require_some(record.pipeline_error.as_deref(), "pipeline error attached");
        assert!(pipeline.contains("connection refused"));
    }

    #[test]
    fn dead_letter_record_attempts_floor_is_one() {
        let record = DeadLetterRecord::new("rcpt-x", 0, 0, "permanent");
        assert_eq!(record.attempts, 1);
    }
}
