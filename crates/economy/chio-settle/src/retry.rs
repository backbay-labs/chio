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

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::hook::{
    SettlementFailureClass, SettlementFailureCode, SettlementFailureReason, SettlementSkipReason,
};
use crate::outcome_store::SettlementRoutingInput;

/// Schema string emitted on the wire for [`DeadLetterRecord`] frames.
pub const SETTLE_DEAD_LETTER_SCHEMA: &str = "chio.settle.dead-letter.v1";

fn deserialize_dead_letter_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let schema = String::deserialize(deserializer)?;
    if schema == SETTLE_DEAD_LETTER_SCHEMA {
        Ok(schema)
    } else {
        Err(serde::de::Error::custom(
            "unsupported settlement dead-letter schema",
        ))
    }
}

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

const MAX_RETRIES: u32 = 32;
const MAX_BACKOFF_CAP_MS: u64 = 86_400_000;
const MAX_BACKOFF_MULTIPLIER: u32 = 16;

/// Invalid bounded retry policy.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicyError {
    #[error("max_retries exceeds 32: {max_retries}")]
    MaxRetriesTooHigh { max_retries: u32 },
    #[error("initial_backoff_ms must be nonzero")]
    InitialBackoffZero,
    #[error("backoff_cap_ms must be nonzero")]
    BackoffCapZero,
    #[error("initial_backoff_ms {initial_backoff_ms} exceeds backoff_cap_ms {backoff_cap_ms}")]
    InitialBackoffExceedsCap {
        initial_backoff_ms: u64,
        backoff_cap_ms: u64,
    },
    #[error("backoff_cap_ms exceeds 86400000: {backoff_cap_ms}")]
    BackoffCapTooHigh { backoff_cap_ms: u64 },
    #[error("backoff_multiplier must be in 1..=16: {backoff_multiplier}")]
    BackoffMultiplierOutOfRange { backoff_multiplier: u32 },
}

/// Bounded retry envelope for settlement routing.
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
    /// Validate the bounded retry envelope.
    pub const fn validate(&self) -> Result<(), RetryPolicyError> {
        if self.max_retries > MAX_RETRIES {
            return Err(RetryPolicyError::MaxRetriesTooHigh {
                max_retries: self.max_retries,
            });
        }
        if self.initial_backoff_ms == 0 {
            return Err(RetryPolicyError::InitialBackoffZero);
        }
        if self.backoff_cap_ms == 0 {
            return Err(RetryPolicyError::BackoffCapZero);
        }
        if self.backoff_cap_ms > MAX_BACKOFF_CAP_MS {
            return Err(RetryPolicyError::BackoffCapTooHigh {
                backoff_cap_ms: self.backoff_cap_ms,
            });
        }
        if self.initial_backoff_ms > self.backoff_cap_ms {
            return Err(RetryPolicyError::InitialBackoffExceedsCap {
                initial_backoff_ms: self.initial_backoff_ms,
                backoff_cap_ms: self.backoff_cap_ms,
            });
        }
        if self.backoff_multiplier == 0 || self.backoff_multiplier > MAX_BACKOFF_MULTIPLIER {
            return Err(RetryPolicyError::BackoffMultiplierOutOfRange {
                backoff_multiplier: self.backoff_multiplier,
            });
        }
        Ok(())
    }

    /// Compute the backoff applied before the `attempt`-th retry.
    /// `attempt = 0` returns the configured initial backoff.
    /// Caps at [`Self::backoff_cap_ms`].
    #[must_use]
    pub fn backoff_for(&self, attempt: u32) -> Duration {
        let factor = u64::from(self.backoff_multiplier)
            .max(1)
            .saturating_pow(attempt);
        Duration::from_millis(
            self.initial_backoff_ms
                .saturating_mul(factor)
                .min(self.backoff_cap_ms),
        )
    }
}

/// Decision returned by [`classify_attempt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryDecision {
    /// The accepted outcome requires no retry work.
    Accepted,
    /// The skipped outcome requires no retry work.
    Skip {
        /// Closed skip reason from the routing input.
        reason: SettlementSkipReason,
    },
    /// Replay the hook after the bounded backoff.
    Retry {
        /// Persisted attempt number for the next invocation.
        attempt: u32,
        /// Delay before the next invocation.
        backoff: Duration,
        /// Bounded failure reason preserved for the retry row.
        reason: SettlementFailureReason,
    },
    /// Persist a terminal dead letter without further retries.
    DeadLetter {
        /// Bounded terminal failure reason.
        reason: SettlementFailureReason,
    },
}

/// Classify one attempt's outcome under the supplied policy.
///
/// `attempt` is the zero-indexed retry counter for the current
/// observation. Pass `0` on the first failure; on the next failure
/// pass `1`, etc. The returned [`RetryDecision`] tells the caller
/// whether to sleep and replay or to land a dead-letter row.
///
/// Permanent outcomes short-circuit and typed reasons are preserved.
#[must_use]
pub fn classify_attempt(
    policy: &RetryPolicy,
    attempt: u32,
    outcome: &SettlementRoutingInput,
) -> RetryDecision {
    match outcome {
        SettlementRoutingInput::Accepted => RetryDecision::Accepted,
        SettlementRoutingInput::Skipped { reason } => RetryDecision::Skip { reason: *reason },
        SettlementRoutingInput::Permanent { reason } => RetryDecision::DeadLetter {
            reason: reason.clone(),
        },
        SettlementRoutingInput::Retryable { reason } => {
            if reason.effective_class(SettlementFailureClass::Retryable)
                == SettlementFailureClass::Permanent
                || attempt >= policy.max_retries
            {
                RetryDecision::DeadLetter {
                    reason: reason.clone(),
                }
            } else {
                RetryDecision::Retry {
                    attempt: attempt + 1,
                    backoff: policy.backoff_for(attempt),
                    reason: reason.clone(),
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// Bounded terminal failure reason.
    pub reason: SettlementFailureReason,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TypedDeadLetterRecord {
    #[serde(deserialize_with = "deserialize_dead_letter_schema")]
    schema: String,
    receipt_id: String,
    finalized_at: u64,
    attempts: u32,
    reason: SettlementFailureReason,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDeadLetterRecord {
    #[serde(deserialize_with = "deserialize_dead_letter_schema")]
    schema: String,
    receipt_id: String,
    finalized_at: u64,
    attempts: u32,
    reason: String,
    #[serde(default)]
    pipeline_error: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DeadLetterRecordWire {
    Typed(TypedDeadLetterRecord),
    Legacy(LegacyDeadLetterRecord),
}

impl<'de> Deserialize<'de> for DeadLetterRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match DeadLetterRecordWire::deserialize(deserializer)? {
            DeadLetterRecordWire::Typed(record) => Ok(Self {
                schema: record.schema,
                receipt_id: record.receipt_id,
                finalized_at: record.finalized_at,
                attempts: record.attempts,
                reason: record.reason,
            }),
            DeadLetterRecordWire::Legacy(record) => {
                let detail = record.pipeline_error.as_deref().unwrap_or(&record.reason);
                Ok(Self {
                    schema: record.schema,
                    receipt_id: record.receipt_id,
                    finalized_at: record.finalized_at,
                    attempts: record.attempts,
                    reason: SettlementFailureReason::from_detail(
                        SettlementFailureCode::Backend,
                        detail,
                    ),
                })
            }
        }
    }
}

impl DeadLetterRecord {
    /// Return whether this record uses the schema understood by this build.
    #[must_use]
    pub fn has_supported_schema(&self) -> bool {
        self.schema == SETTLE_DEAD_LETTER_SCHEMA
    }

    /// Build a new dead-letter record stamped with the canonical schema.
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        finalized_at: u64,
        attempts: u32,
        reason: SettlementFailureReason,
    ) -> Self {
        Self {
            schema: SETTLE_DEAD_LETTER_SCHEMA.to_string(),
            receipt_id: receipt_id.into(),
            finalized_at,
            attempts: attempts.max(1),
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure(detail: &str) -> SettlementFailureReason {
        SettlementFailureReason::from_detail(SettlementFailureCode::Rpc, detail)
    }

    fn serialize<T: Serialize>(value: &T) -> String {
        match serde_json::to_string(value) {
            Ok(encoded) => encoded,
            Err(error) => panic!("value must serialize: {error}"),
        }
    }

    #[test]
    fn schema_is_stable() {
        assert_eq!(SETTLE_DEAD_LETTER_SCHEMA, "chio.settle.dead-letter.v1");
    }

    #[test]
    fn string_reason_v1_schema_decodes_to_a_bounded_reason() {
        let decoded = serde_json::from_value::<DeadLetterRecord>(serde_json::json!({
            "schema": "chio.settle.dead-letter.v1",
            "receipt_id": "receipt-1",
            "finalized_at": 1,
            "attempts": 1,
            "reason": "rpc unavailable",
            "pipeline_error": "settlement pipeline error: rpc unavailable",
        }));
        let record = match decoded {
            Ok(record) => record,
            Err(error) => panic!("legacy dead-letter record must decode: {error}"),
        };

        let expected = SettlementFailureReason::from_detail(
            SettlementFailureCode::Backend,
            "settlement pipeline error: rpc unavailable",
        );
        assert_eq!(record.reason, expected);
    }

    #[test]
    fn dead_letter_deserialization_rejects_an_unsupported_schema() {
        let result = serde_json::from_value::<DeadLetterRecord>(serde_json::json!({
            "schema": "chio.settle.dead-letter.v99",
            "receipt_id": "receipt-1",
            "finalized_at": 1,
            "attempts": 1,
            "reason": {
                "code": "backend",
                "detail_sha256": vec![0_u8; 32],
            },
        }));

        assert!(result.is_err());
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
        assert_eq!(policy.backoff_for(4), Duration::from_millis(1000));
        assert_eq!(policy.backoff_for(50), Duration::from_millis(1000));
    }

    #[test]
    fn permanent_outcomes_skip_the_retry_envelope() {
        let policy = RetryPolicy::default();
        let reason = failure("policy denied");
        let outcome = SettlementRoutingInput::Permanent {
            reason: reason.clone(),
        };
        match classify_attempt(&policy, 0, &outcome) {
            RetryDecision::DeadLetter { reason: actual } => assert_eq!(actual, reason),
            other => panic!("expected dead letter, got {other:?}"),
        }
    }

    #[test]
    fn skipped_outcomes_pass_through() {
        let policy = RetryPolicy::default();
        let outcome = SettlementRoutingInput::Skipped {
            reason: SettlementSkipReason::ZeroCharge,
        };
        assert_eq!(
            classify_attempt(&policy, 0, &outcome),
            RetryDecision::Skip {
                reason: SettlementSkipReason::ZeroCharge,
            }
        );
    }

    #[test]
    fn accepted_outcomes_pass_through() {
        let policy = RetryPolicy::default();
        assert_eq!(
            classify_attempt(&policy, 0, &SettlementRoutingInput::Accepted),
            RetryDecision::Accepted
        );
    }

    #[test]
    fn retryable_outcomes_consume_the_envelope_then_dead_letter() {
        let policy = RetryPolicy {
            max_retries: 2,
            initial_backoff_ms: 10,
            backoff_multiplier: 2,
            backoff_cap_ms: 100,
        };
        let reason = failure("rpc lag");
        let outcome = SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        };
        match classify_attempt(&policy, 0, &outcome) {
            RetryDecision::Retry {
                attempt,
                backoff,
                reason: actual,
            } => {
                assert_eq!(attempt, 1);
                assert_eq!(backoff, Duration::from_millis(10));
                assert_eq!(actual, reason);
            }
            other => panic!("expected retry, got {other:?}"),
        }
        match classify_attempt(&policy, 1, &outcome) {
            RetryDecision::Retry { attempt, .. } => assert_eq!(attempt, 2),
            other => panic!("expected retry, got {other:?}"),
        }
        match classify_attempt(&policy, 2, &outcome) {
            RetryDecision::DeadLetter { reason: actual } => assert_eq!(actual, reason),
            other => panic!("expected dead letter, got {other:?}"),
        }
    }

    #[test]
    fn dead_letter_record_contains_only_bounded_failure_detail() {
        let record = DeadLetterRecord::new("rcpt-1", 100, 3, failure("connection refused"));
        let encoded = serialize(&record);

        assert_eq!(record.attempts, 3);
        assert_eq!(record.schema, SETTLE_DEAD_LETTER_SCHEMA);
        assert_eq!(record.reason.code(), SettlementFailureCode::Rpc);
        assert!(!encoded.contains("connection refused"));
        assert!(!encoded.contains("pipeline_error"));
    }

    #[test]
    fn dead_letter_record_attempts_floor_is_one() {
        let record = DeadLetterRecord::new("rcpt-x", 0, 0, failure("permanent"));
        assert_eq!(record.attempts, 1);
    }

    #[test]
    fn retry_policy_accepts_every_boundary() {
        let default = RetryPolicy::default();
        let valid = [
            RetryPolicy {
                max_retries: 0,
                ..default
            },
            RetryPolicy {
                max_retries: 32,
                ..default
            },
            RetryPolicy {
                initial_backoff_ms: 1,
                ..default
            },
            RetryPolicy {
                initial_backoff_ms: 1,
                backoff_cap_ms: 1,
                ..default
            },
            RetryPolicy {
                backoff_cap_ms: 86_400_000,
                ..default
            },
            RetryPolicy {
                backoff_multiplier: 1,
                ..default
            },
            RetryPolicy {
                backoff_multiplier: 16,
                ..default
            },
        ];

        for policy in valid {
            assert_eq!(policy.validate(), Ok(()));
        }
    }

    #[test]
    fn retry_policy_rejects_every_out_of_bounds_value() {
        let default = RetryPolicy::default();
        let invalid = [
            (
                RetryPolicy {
                    max_retries: 33,
                    ..default
                },
                RetryPolicyError::MaxRetriesTooHigh { max_retries: 33 },
            ),
            (
                RetryPolicy {
                    initial_backoff_ms: 0,
                    ..default
                },
                RetryPolicyError::InitialBackoffZero,
            ),
            (
                RetryPolicy {
                    backoff_cap_ms: 0,
                    ..default
                },
                RetryPolicyError::BackoffCapZero,
            ),
            (
                RetryPolicy {
                    initial_backoff_ms: default.backoff_cap_ms + 1,
                    ..default
                },
                RetryPolicyError::InitialBackoffExceedsCap {
                    initial_backoff_ms: default.backoff_cap_ms + 1,
                    backoff_cap_ms: default.backoff_cap_ms,
                },
            ),
            (
                RetryPolicy {
                    backoff_cap_ms: 86_400_001,
                    ..default
                },
                RetryPolicyError::BackoffCapTooHigh {
                    backoff_cap_ms: 86_400_001,
                },
            ),
            (
                RetryPolicy {
                    backoff_multiplier: 0,
                    ..default
                },
                RetryPolicyError::BackoffMultiplierOutOfRange {
                    backoff_multiplier: 0,
                },
            ),
            (
                RetryPolicy {
                    backoff_multiplier: 17,
                    ..default
                },
                RetryPolicyError::BackoffMultiplierOutOfRange {
                    backoff_multiplier: 17,
                },
            ),
        ];

        for (policy, expected) in invalid {
            assert_eq!(policy.validate(), Err(expected));
        }
    }

    #[test]
    fn typed_retry_reason_survives_exhaustion() {
        let reason = failure("upstream unavailable");
        let input = SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        };
        let policy = RetryPolicy {
            max_retries: 0,
            ..RetryPolicy::default()
        };

        assert!(matches!(
            classify_attempt(&policy, 0, &input),
            RetryDecision::DeadLetter { reason: actual } if actual == reason
        ));
    }

    #[test]
    fn known_permanent_code_never_enters_the_retry_envelope() {
        let reason = SettlementFailureReason::from_detail(
            SettlementFailureCode::InvalidReceiptSignature,
            "invalid signature",
        );
        let input = SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        };

        assert_eq!(
            classify_attempt(&RetryPolicy::default(), 0, &input),
            RetryDecision::DeadLetter { reason }
        );
    }

    #[test]
    fn backoff_with_unit_multiplier_is_constant_for_any_attempt() {
        let policy = RetryPolicy {
            backoff_multiplier: 1,
            ..RetryPolicy::default()
        };

        assert_eq!(
            policy.backoff_for(u32::MAX),
            Duration::from_millis(policy.initial_backoff_ms)
        );
    }
}
