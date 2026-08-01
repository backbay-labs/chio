//! Settlement hook trait routing finalized Chio receipts through the
//! existing `chio-settle/ops.rs` pipeline.
//!
//! This exposes a kernel-evaluator observer surface for the
//! `chio-settle` crate. The hook is invoked once a receipt has been
//! signed and durably stored. A paired observer runtime is responsible
//! for persisting hook outcomes and routing retries or dead letters.
//!
//! Settlement ordering is deterministic: implementers MUST process
//! observations sorted first by [`SettlementObservation::finalized_at`]
//! ascending and then by [`SettlementObservation::receipt_id`] lexically.
//!
//! Integrity and malformed-data failures are permanent. Only denied,
//! non-economic, and zero-charge receipts may be skipped. The dispatch
//! path is never rolled back by a settlement failure.

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use chio_core::{capability::scope::MonetaryAmount, hashing::sha256};

use crate::SettlementError;

/// Schema string emitted on the wire for [`SettlementObservation`] frames.
pub const SETTLEMENT_OBSERVATION_SCHEMA: &str = "chio.settle.observation.v1";

/// Schema string emitted on the wire for [`SettlementOutcome`] frames.
pub const SETTLEMENT_OUTCOME_SCHEMA: &str = "chio.settle.outcome.v1";

fn deserialize_schema<'de, D>(
    deserializer: D,
    expected: &'static str,
    error: &'static str,
) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let schema = String::deserialize(deserializer)?;
    if schema == expected {
        Ok(schema)
    } else {
        Err(serde::de::Error::custom(error))
    }
}

fn deserialize_observation_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_schema(
        deserializer,
        SETTLEMENT_OBSERVATION_SCHEMA,
        "unsupported settlement observation schema",
    )
}

fn deserialize_outcome_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_schema(
        deserializer,
        SETTLEMENT_OUTCOME_SCHEMA,
        "unsupported settlement outcome schema",
    )
}

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
    #[serde(deserialize_with = "deserialize_observation_schema")]
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

/// Durable identity and claim fence for one at-least-once hook invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementIdempotencyKey {
    /// Stable effect identity. Hooks must deduplicate durable effects by this id.
    pub receipt_id: String,
    /// Store row version claimed for this invocation.
    pub row_version: u64,
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

/// Closed reason for an observation that requires no settlement work.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementSkipReason {
    /// The receipt records a denied invocation.
    Denied,
    /// The receipt carries no authorized economic intent.
    NoEconomicIntent,
    Channelized,
    /// The authorized invocation has no charge.
    ZeroCharge,
}

/// Retry disposition for a settlement failure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementFailureClass {
    /// The operation may succeed when replayed.
    Retryable,
    /// Replaying the same operation cannot succeed.
    Permanent,
}

/// Closed settlement failure taxonomy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementFailureCode {
    InvalidReceiptSignature,
    InvalidActionHash,
    UntrustedReceiptSigner,
    MalformedFinancialMetadata,
    InvalidObservation,
    Rpc,
    InvalidInput,
    InvalidDispatch,
    InvalidBinding,
    Unsupported,
    Serialization,
    Signature,
    Verification,
    Backend,
}

/// Unknown durable settlement failure code.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("unknown settlement failure code")]
pub struct SettlementFailureCodeParseError;

impl SettlementFailureCode {
    /// Return the stable snake-case label used by durable stores.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidReceiptSignature => "invalid_receipt_signature",
            Self::InvalidActionHash => "invalid_action_hash",
            Self::UntrustedReceiptSigner => "untrusted_receipt_signer",
            Self::MalformedFinancialMetadata => "malformed_financial_metadata",
            Self::InvalidObservation => "invalid_observation",
            Self::Rpc => "rpc",
            Self::InvalidInput => "invalid_input",
            Self::InvalidDispatch => "invalid_dispatch",
            Self::InvalidBinding => "invalid_binding",
            Self::Unsupported => "unsupported",
            Self::Serialization => "serialization",
            Self::Signature => "signature",
            Self::Verification => "verification",
            Self::Backend => "backend",
        }
    }

    const fn allows_retry(self) -> bool {
        matches!(self, Self::Rpc | Self::Backend)
    }
}

impl TryFrom<&str> for SettlementFailureCode {
    type Error = SettlementFailureCodeParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "invalid_receipt_signature" => Ok(Self::InvalidReceiptSignature),
            "invalid_action_hash" => Ok(Self::InvalidActionHash),
            "untrusted_receipt_signer" => Ok(Self::UntrustedReceiptSigner),
            "malformed_financial_metadata" => Ok(Self::MalformedFinancialMetadata),
            "invalid_observation" => Ok(Self::InvalidObservation),
            "rpc" => Ok(Self::Rpc),
            "invalid_input" => Ok(Self::InvalidInput),
            "invalid_dispatch" => Ok(Self::InvalidDispatch),
            "invalid_binding" => Ok(Self::InvalidBinding),
            "unsupported" => Ok(Self::Unsupported),
            "serialization" => Ok(Self::Serialization),
            "signature" => Ok(Self::Signature),
            "verification" => Ok(Self::Verification),
            "backend" => Ok(Self::Backend),
            _ => Err(SettlementFailureCodeParseError),
        }
    }
}

/// Bounded failure reason safe for durable storage and telemetry labels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementFailureReason {
    code: SettlementFailureCode,
    detail_sha256: [u8; 32],
}

impl SettlementFailureReason {
    /// Hash an unbounded failure detail into its durable representation.
    #[must_use]
    pub fn from_detail(code: SettlementFailureCode, detail: impl AsRef<[u8]>) -> Self {
        Self::from_digest(code, *sha256(detail.as_ref()).as_bytes())
    }

    /// Restore a reason from a persisted digest.
    #[must_use]
    pub const fn from_digest(code: SettlementFailureCode, detail_sha256: [u8; 32]) -> Self {
        Self {
            code,
            detail_sha256,
        }
    }

    /// Return the bounded failure code.
    #[must_use]
    pub const fn code(&self) -> SettlementFailureCode {
        self.code
    }

    /// Return the SHA-256 digest of the original detail.
    #[must_use]
    pub const fn detail_sha256(&self) -> &[u8; 32] {
        &self.detail_sha256
    }

    /// Enforce the retry disposition permitted by this failure code.
    #[must_use]
    pub const fn effective_class(
        &self,
        requested: SettlementFailureClass,
    ) -> SettlementFailureClass {
        match requested {
            SettlementFailureClass::Retryable if self.code.allows_retry() => {
                SettlementFailureClass::Retryable
            }
            SettlementFailureClass::Retryable | SettlementFailureClass::Permanent => {
                SettlementFailureClass::Permanent
            }
        }
    }
}

/// Outcome returned by a settlement hook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum SettlementOutcome {
    /// The hook accepted the observation and routed it through the
    /// existing `chio-settle/ops.rs` pipeline. The opaque transcript
    /// id lets operators correlate the kernel-side observation with
    /// the downstream settlement record.
    Accepted {
        /// Schema tag (`chio.settle.outcome.v1`).
        #[serde(deserialize_with = "deserialize_outcome_schema")]
        schema: String,
        /// Stable transcript identifier produced by the ops pipeline.
        transcript_id: String,
    },
    /// The receipt requires no settlement work.
    Skipped {
        /// Schema tag (`chio.settle.outcome.v1`).
        #[serde(deserialize_with = "deserialize_outcome_schema")]
        schema: String,
        /// Closed reason for skipping settlement.
        reason: SettlementSkipReason,
    },
    /// The hook rejected the observation with a recoverable failure.
    Retryable {
        /// Schema tag (`chio.settle.outcome.v1`).
        #[serde(deserialize_with = "deserialize_outcome_schema")]
        schema: String,
        /// Bounded failure reason carried across retries.
        reason: SettlementFailureReason,
    },
    /// The hook rejected the observation permanently.
    Permanent {
        /// Schema tag (`chio.settle.outcome.v1`).
        #[serde(deserialize_with = "deserialize_outcome_schema")]
        schema: String,
        /// Bounded failure reason carried into the dead letter.
        reason: SettlementFailureReason,
    },
}

impl SettlementOutcome {
    /// Return whether this outcome uses the schema understood by this build.
    #[must_use]
    pub fn has_supported_schema(&self) -> bool {
        let schema = match self {
            Self::Accepted { schema, .. }
            | Self::Skipped { schema, .. }
            | Self::Retryable { schema, .. }
            | Self::Permanent { schema, .. } => schema,
        };
        schema == SETTLEMENT_OUTCOME_SCHEMA
    }

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
    pub fn skipped(reason: SettlementSkipReason) -> Self {
        Self::Skipped {
            schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
            reason,
        }
    }

    /// Construct a retryable outcome with the canonical schema tag.
    ///
    /// Deterministic failure codes are coerced to [`Self::Permanent`].
    #[must_use]
    pub fn retryable(reason: SettlementFailureReason) -> Self {
        match reason.effective_class(SettlementFailureClass::Retryable) {
            SettlementFailureClass::Retryable => Self::Retryable {
                schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
                reason,
            },
            SettlementFailureClass::Permanent => Self::permanent(reason),
        }
    }

    /// Construct a `Permanent` outcome with the canonical schema tag.
    #[must_use]
    pub fn permanent(reason: SettlementFailureReason) -> Self {
        Self::Permanent {
            schema: SETTLEMENT_OUTCOME_SCHEMA.to_string(),
            reason,
        }
    }

    /// Return `true` for outcomes that the retry policy must replay.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Retryable { reason, .. }
                if reason.effective_class(SettlementFailureClass::Retryable)
                    == SettlementFailureClass::Retryable
        )
    }

    /// Return `true` for outcomes that land directly in the dead-letter
    /// table without further retries.
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        match self {
            Self::Permanent { .. } => true,
            Self::Retryable { reason, .. } => {
                reason.effective_class(SettlementFailureClass::Retryable)
                    == SettlementFailureClass::Permanent
            }
            Self::Accepted { .. } | Self::Skipped { .. } => false,
        }
    }
}

/// Errors that may surface from a [`SettlementHook`]. All variants are
/// fail-closed: the paired observer runtime preserves their typed disposition
/// for durable routing, while the dispatch path is never rolled back.
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

impl SettlementHookError {
    /// Return the retry disposition and bounded reason for this error.
    #[must_use]
    pub fn classification(&self) -> (SettlementFailureClass, SettlementFailureReason) {
        let (class, code, detail) = match self {
            Self::InvalidObservation(detail) => (
                SettlementFailureClass::Permanent,
                SettlementFailureCode::InvalidObservation,
                detail.as_str(),
            ),
            Self::Transient(detail) => (
                SettlementFailureClass::Retryable,
                SettlementFailureCode::Backend,
                detail.as_str(),
            ),
            Self::Permanent(detail) => (
                SettlementFailureClass::Permanent,
                SettlementFailureCode::Backend,
                detail.as_str(),
            ),
            Self::Pipeline(error) => match error {
                SettlementError::Rpc(detail) => (
                    SettlementFailureClass::Retryable,
                    SettlementFailureCode::Rpc,
                    detail.as_str(),
                ),
                SettlementError::InvalidInput(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::InvalidInput,
                    detail.as_str(),
                ),
                SettlementError::InvalidDispatch(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::InvalidDispatch,
                    detail.as_str(),
                ),
                SettlementError::InvalidBinding(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::InvalidBinding,
                    detail.as_str(),
                ),
                SettlementError::Unsupported(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::Unsupported,
                    detail.as_str(),
                ),
                SettlementError::Serialization(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::Serialization,
                    detail.as_str(),
                ),
                SettlementError::Signature(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::Signature,
                    detail.as_str(),
                ),
                SettlementError::Verification(detail) => (
                    SettlementFailureClass::Permanent,
                    SettlementFailureCode::Verification,
                    detail.as_str(),
                ),
            },
        };

        (class, SettlementFailureReason::from_detail(code, detail))
    }
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
/// - Keep `observe` bounded and local. An accepted outcome must follow a
///   durable local write, not unbounded network I/O.
/// - Make durable effects idempotent by receipt id. Lease recovery may replay
///   an observation after a process exits or an invocation exceeds its lease.
///   The supplied key makes the receipt identity and claim version explicit;
///   hooks MUST deduplicate effects by `receipt_id` across row versions.
pub trait SettlementHook: Send + Sync {
    /// Observe a finalized receipt and route it through the settlement
    /// pipeline. See the trait-level docs for ordering and failure
    /// semantics.
    fn observe(
        &self,
        observation: &SettlementObservation,
        idempotency_key: &SettlementIdempotencyKey,
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

    fn failure(code: SettlementFailureCode, detail: &str) -> SettlementFailureReason {
        SettlementFailureReason::from_detail(code, detail)
    }

    fn serialize<T: Serialize>(value: &T) -> String {
        match serde_json::to_string(value) {
            Ok(encoded) => encoded,
            Err(error) => panic!("value must serialize: {error}"),
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
    fn outcome_deserialization_rejects_an_unsupported_schema() {
        let result = serde_json::from_value::<SettlementOutcome>(serde_json::json!({
            "kind": "accepted",
            "schema": "chio.settle.outcome.v99",
            "transcript_id": "transcript-1",
        }));

        assert!(result.is_err());
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
        let retry = SettlementOutcome::retryable(failure(SettlementFailureCode::Rpc, "rpc lag"));
        assert!(retry.is_retryable());
        assert!(!retry.is_permanent());

        let dead = SettlementOutcome::permanent(failure(
            SettlementFailureCode::InvalidObservation,
            "policy denied",
        ));
        assert!(!dead.is_retryable());
        assert!(dead.is_permanent());

        let skip = SettlementOutcome::skipped(SettlementSkipReason::ZeroCharge);
        assert!(!skip.is_retryable());
        assert!(!skip.is_permanent());

        let ok = SettlementOutcome::accepted("ts-1");
        assert!(!ok.is_retryable());
        assert!(!ok.is_permanent());
    }

    #[test]
    fn retryable_constructor_rejects_a_known_permanent_code() {
        let outcome = SettlementOutcome::retryable(failure(
            SettlementFailureCode::InvalidReceiptSignature,
            "invalid signature",
        ));

        assert!(matches!(outcome, SettlementOutcome::Permanent { .. }));
    }

    #[test]
    fn outcome_predicates_reject_a_forged_retryable_shape() {
        let outcome = match serde_json::from_value::<SettlementOutcome>(serde_json::json!({
            "kind": "retryable",
            "schema": SETTLEMENT_OUTCOME_SCHEMA,
            "reason": {
                "code": "invalid_receipt_signature",
                "detail_sha256": vec![0_u8; 32],
            },
        })) {
            Ok(outcome) => outcome,
            Err(error) => panic!("test outcome deserialization failed: {error}"),
        };

        assert!(!outcome.is_retryable());
        assert!(outcome.is_permanent());
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
                _idempotency_key: &SettlementIdempotencyKey,
            ) -> Result<SettlementOutcome, SettlementHookError> {
                if observation.amount.units == 0 {
                    return Ok(SettlementOutcome::skipped(SettlementSkipReason::ZeroCharge));
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
        let outcome = require_ok(
            hook.observe(
                &observation,
                &SettlementIdempotencyKey {
                    receipt_id: observation.receipt_id.clone(),
                    row_version: 1,
                },
            ),
            "hook returns observed outcome",
        );
        assert!(matches!(outcome, SettlementOutcome::Accepted { .. }));
    }

    #[test]
    fn hook_errors_have_typed_bounded_classification() {
        let cases = [
            (
                SettlementHookError::InvalidObservation("secret".to_string()),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::InvalidObservation,
            ),
            (
                SettlementHookError::Transient("secret".to_string()),
                SettlementFailureClass::Retryable,
                SettlementFailureCode::Backend,
            ),
            (
                SettlementHookError::Permanent("secret".to_string()),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::Backend,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::Rpc("secret".to_string())),
                SettlementFailureClass::Retryable,
                SettlementFailureCode::Rpc,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::InvalidInput("secret".to_string())),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::InvalidInput,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::InvalidDispatch(
                    "secret".to_string(),
                )),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::InvalidDispatch,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::InvalidBinding(
                    "secret".to_string(),
                )),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::InvalidBinding,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::Unsupported("secret".to_string())),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::Unsupported,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::Serialization("secret".to_string())),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::Serialization,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::Signature("secret".to_string())),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::Signature,
            ),
            (
                SettlementHookError::Pipeline(SettlementError::Verification("secret".to_string())),
                SettlementFailureClass::Permanent,
                SettlementFailureCode::Verification,
            ),
        ];

        for (error, expected_class, expected_code) in cases {
            let (class, reason) = error.classification();
            assert_eq!(class, expected_class);
            assert_eq!(reason.code(), expected_code);
            assert_eq!(
                reason.detail_sha256(),
                chio_core::hashing::sha256(b"secret").as_bytes()
            );
            let encoded = serialize(&reason);
            assert!(!encoded.contains("secret"));
        }
    }

    #[test]
    fn failure_reason_digest_is_deterministic_and_private() {
        let reason = failure(SettlementFailureCode::Rpc, "sensitive detail");
        let restored = SettlementFailureReason::from_digest(reason.code(), *reason.detail_sha256());

        assert_eq!(reason, restored);
        assert_eq!(
            reason.detail_sha256(),
            chio_core::hashing::sha256(b"sensitive detail").as_bytes()
        );
        assert!(!serialize(&reason).contains("sensitive detail"));
    }

    #[test]
    fn failure_code_labels_match_the_serialized_contract() {
        let cases = [
            SettlementFailureCode::InvalidReceiptSignature,
            SettlementFailureCode::InvalidActionHash,
            SettlementFailureCode::UntrustedReceiptSigner,
            SettlementFailureCode::MalformedFinancialMetadata,
            SettlementFailureCode::InvalidObservation,
            SettlementFailureCode::Rpc,
            SettlementFailureCode::InvalidInput,
            SettlementFailureCode::InvalidDispatch,
            SettlementFailureCode::InvalidBinding,
            SettlementFailureCode::Unsupported,
            SettlementFailureCode::Serialization,
            SettlementFailureCode::Signature,
            SettlementFailureCode::Verification,
            SettlementFailureCode::Backend,
        ];

        for code in cases {
            let serialized = match serde_json::to_value(code) {
                Ok(serialized) => serialized,
                Err(error) => panic!("failure code serialization failed: {error}"),
            };
            assert_eq!(
                serialized,
                serde_json::Value::String(code.as_str().to_string())
            );
            assert_eq!(SettlementFailureCode::try_from(code.as_str()), Ok(code));
        }
    }

    #[test]
    fn failure_code_parser_rejects_unknown_labels() {
        for label in ["", "RPC", "rpc ", "unknown"] {
            assert_eq!(
                SettlementFailureCode::try_from(label),
                Err(SettlementFailureCodeParseError)
            );
        }
        assert_eq!(
            SettlementFailureCodeParseError.to_string(),
            "unknown settlement failure code"
        );
    }
}
