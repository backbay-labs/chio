//! Canonical bindings for a qualified provider's durable invocation attempt.
//!
//! These values are signable protocol bodies. Authentication is supplied by a
//! qualified provider adapter; this module validates their shape, binding, and
//! monotonic lifecycle before the kernel treats an adapter result as evidence.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{canonical_json_bytes, sha256_hex};

pub const PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA: &str = "chio.provider-attempt-checkpoint.v1";
pub const PROVIDER_INVOCATION_BLOB_SCHEMA: &str = "chio.provider-invocation-blob.v1";
pub const PROVIDER_ACCEPTANCE_SCHEMA: &str = "chio.provider-acceptance.v1";
pub const PROVIDER_CANCELLATION_SCHEMA: &str = "chio.provider-cancellation.v1";
pub const PROVIDER_EXECUTION_LEASE_SCHEMA: &str = "chio.provider-execution-lease.v1";
pub const PROVIDER_COMPLETION_SCHEMA: &str = "chio.provider-completion.v1";

pub const MAX_PROVIDER_ID_BYTES: usize = 512;
pub const MAX_PROVIDER_REF_BYTES: usize = 2 * 1024;
pub const MAX_PROVIDER_INVOCATION_BLOB_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PROVIDER_OUTCOME_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_PROVIDER_TERMINAL_EVIDENCE_BYTES: u64 = 1024 * 1024;
pub const MAX_PROVIDER_CHECKPOINT_CHAIN: usize = 4;

const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

const CHECKPOINT_DIGEST_DOMAIN: &str = "chio.provider-attempt-checkpoint.v1";
const INVOCATION_BLOB_DIGEST_DOMAIN: &str = "chio.provider-invocation-blob.v1";
const ACCEPTANCE_DIGEST_DOMAIN: &str = "chio.provider-acceptance.v1";
const CANCELLATION_DIGEST_DOMAIN: &str = "chio.provider-cancellation.v1";
const EXECUTION_LEASE_DIGEST_DOMAIN: &str = "chio.provider-execution-lease.v1";
const COMPLETION_DIGEST_DOMAIN: &str = "chio.provider-completion.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAttemptValidationError {
    UnsupportedSchema {
        field: &'static str,
        value: String,
    },
    EmptyField(&'static str),
    FieldTooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    InvalidDigest(&'static str),
    InvalidValue {
        field: &'static str,
        reason: String,
    },
    BindingMismatch(&'static str),
    IllegalTransition {
        from: ProviderAttemptState,
        to: ProviderAttemptState,
    },
    Canonicalization(String),
}

impl fmt::Display for ProviderAttemptValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema { field, value } => {
                write!(formatter, "unsupported {field} schema `{value}`")
            }
            Self::EmptyField(field) => {
                write!(formatter, "provider attempt field `{field}` is empty")
            }
            Self::FieldTooLarge {
                field,
                actual,
                maximum,
            } => write!(
                formatter,
                "provider attempt field `{field}` is {actual} bytes (maximum {maximum})"
            ),
            Self::InvalidDigest(field) => {
                write!(
                    formatter,
                    "provider attempt field `{field}` is not lowercase SHA-256"
                )
            }
            Self::InvalidValue { field, reason } => {
                write!(
                    formatter,
                    "provider attempt field `{field}` is invalid: {reason}"
                )
            }
            Self::BindingMismatch(field) => {
                write!(formatter, "provider attempt binding mismatch on `{field}`")
            }
            Self::IllegalTransition { from, to } => {
                write!(
                    formatter,
                    "illegal provider attempt transition {from:?} -> {to:?}"
                )
            }
            Self::Canonicalization(error) => {
                write!(
                    formatter,
                    "provider attempt canonicalization failed: {error}"
                )
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProviderAttemptValidationError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttemptBindingV1 {
    pub operation_id: String,
    pub attempt_id: String,
    pub transport_id: String,
    pub transport_key_epoch: u64,
}

impl ProviderAttemptBindingV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_sha256("operation_id", &self.operation_id)?;
        ensure_id("attempt_id", &self.attempt_id)?;
        ensure_id("transport_id", &self.transport_id)?;
        ensure_positive("transport_key_epoch", self.transport_key_epoch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInvocationBlobBindingV1 {
    pub schema: String,
    pub attempt: ProviderAttemptBindingV1,
    pub request_digest: String,
    pub idempotency_key: String,
    pub blob_ref: String,
    pub blob_sha256: String,
    pub blob_size_bytes: u64,
    pub availability_ref: String,
    pub availability_sha256: String,
}

impl ProviderInvocationBlobBindingV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_schema(
            "invocation_blob",
            &self.schema,
            PROVIDER_INVOCATION_BLOB_SCHEMA,
        )?;
        self.attempt.validate()?;
        ensure_sha256("request_digest", &self.request_digest)?;
        ensure_sha256("idempotency_key", &self.idempotency_key)?;
        if self.idempotency_key != self.attempt.operation_id {
            return Err(ProviderAttemptValidationError::BindingMismatch(
                "idempotency_key",
            ));
        }
        ensure_ref("blob_ref", &self.blob_ref)?;
        ensure_sha256("blob_sha256", &self.blob_sha256)?;
        ensure_size(
            "blob_size_bytes",
            self.blob_size_bytes,
            MAX_PROVIDER_INVOCATION_BLOB_BYTES,
        )?;
        ensure_ref("availability_ref", &self.availability_ref)?;
        ensure_sha256("availability_sha256", &self.availability_sha256)
    }

    pub fn digest(&self) -> Result<String, ProviderAttemptValidationError> {
        self.validate()?;
        domain_digest(INVOCATION_BLOB_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAcceptanceBindingV1 {
    pub schema: String,
    pub attempt: ProviderAttemptBindingV1,
    pub acceptance_ref: String,
    pub accepted_at: u64,
    pub cancellation_fence: u64,
    pub invocation_blob_digest: String,
    pub acceptance_envelope_sha256: String,
    pub acceptance_envelope_size_bytes: u64,
}

impl ProviderAcceptanceBindingV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_schema("acceptance", &self.schema, PROVIDER_ACCEPTANCE_SCHEMA)?;
        self.attempt.validate()?;
        ensure_ref("acceptance_ref", &self.acceptance_ref)?;
        ensure_positive("accepted_at", self.accepted_at)?;
        ensure_positive("cancellation_fence", self.cancellation_fence)?;
        ensure_sha256("invocation_blob_digest", &self.invocation_blob_digest)?;
        ensure_sha256(
            "acceptance_envelope_sha256",
            &self.acceptance_envelope_sha256,
        )?;
        ensure_size(
            "acceptance_envelope_size_bytes",
            self.acceptance_envelope_size_bytes,
            MAX_PROVIDER_TERMINAL_EVIDENCE_BYTES,
        )
    }

    pub fn digest(&self) -> Result<String, ProviderAttemptValidationError> {
        self.validate()?;
        domain_digest(ACCEPTANCE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCancellationBindingV1 {
    pub schema: String,
    pub attempt: ProviderAttemptBindingV1,
    pub cancellation_ref: String,
    pub cancelled_at: u64,
    pub cancellation_fence: u64,
    pub invocation_blob_digest: String,
    pub no_acceptance_proof_sha256: String,
    pub no_acceptance_proof_size_bytes: u64,
}

impl ProviderCancellationBindingV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_schema("cancellation", &self.schema, PROVIDER_CANCELLATION_SCHEMA)?;
        self.attempt.validate()?;
        ensure_ref("cancellation_ref", &self.cancellation_ref)?;
        ensure_positive("cancelled_at", self.cancelled_at)?;
        ensure_positive("cancellation_fence", self.cancellation_fence)?;
        ensure_sha256("invocation_blob_digest", &self.invocation_blob_digest)?;
        ensure_sha256(
            "no_acceptance_proof_sha256",
            &self.no_acceptance_proof_sha256,
        )?;
        ensure_size(
            "no_acceptance_proof_size_bytes",
            self.no_acceptance_proof_size_bytes,
            MAX_PROVIDER_TERMINAL_EVIDENCE_BYTES,
        )
    }

    pub fn digest(&self) -> Result<String, ProviderAttemptValidationError> {
        self.validate()?;
        domain_digest(CANCELLATION_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecutionLeaseBindingV1 {
    pub schema: String,
    pub attempt: ProviderAttemptBindingV1,
    pub lease_id: String,
    pub executor_id: String,
    pub lease_epoch: u64,
    pub execution_fence: u64,
    pub invocation_blob_digest: String,
    pub acceptance_digest: String,
    pub acquired_at: u64,
    pub expires_at: u64,
}

impl ProviderExecutionLeaseBindingV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_schema(
            "execution_lease",
            &self.schema,
            PROVIDER_EXECUTION_LEASE_SCHEMA,
        )?;
        self.attempt.validate()?;
        ensure_id("lease_id", &self.lease_id)?;
        ensure_id("executor_id", &self.executor_id)?;
        ensure_positive("lease_epoch", self.lease_epoch)?;
        ensure_positive("execution_fence", self.execution_fence)?;
        ensure_sha256("invocation_blob_digest", &self.invocation_blob_digest)?;
        ensure_sha256("acceptance_digest", &self.acceptance_digest)?;
        ensure_positive("acquired_at", self.acquired_at)?;
        ensure_positive("expires_at", self.expires_at)?;
        if self.expires_at <= self.acquired_at {
            return Err(invalid(
                "expires_at",
                "must be later than the lease acquisition time",
            ));
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProviderAttemptValidationError> {
        self.validate()?;
        domain_digest(EXECUTION_LEASE_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCompletionBindingV1 {
    pub schema: String,
    pub attempt: ProviderAttemptBindingV1,
    pub tool_outcome_ref: String,
    pub completed_at: u64,
    pub invocation_blob_digest: String,
    pub acceptance_digest: String,
    pub execution_lease_digest: String,
    pub outcome_sha256: String,
    pub outcome_size_bytes: u64,
    pub cost_units: u64,
    pub currency: String,
    pub terminal_evidence_sha256: String,
    pub terminal_evidence_size_bytes: u64,
}

impl ProviderCompletionBindingV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_schema("completion", &self.schema, PROVIDER_COMPLETION_SCHEMA)?;
        self.attempt.validate()?;
        ensure_ref("tool_outcome_ref", &self.tool_outcome_ref)?;
        ensure_positive("completed_at", self.completed_at)?;
        ensure_sha256("invocation_blob_digest", &self.invocation_blob_digest)?;
        ensure_sha256("acceptance_digest", &self.acceptance_digest)?;
        ensure_sha256("execution_lease_digest", &self.execution_lease_digest)?;
        ensure_sha256("outcome_sha256", &self.outcome_sha256)?;
        ensure_bounded_size(
            "outcome_size_bytes",
            self.outcome_size_bytes,
            MAX_PROVIDER_OUTCOME_BYTES,
        )?;
        if self.cost_units > I_JSON_MAX_SAFE_INTEGER {
            return Err(invalid("cost_units", "must be an I-JSON safe integer"));
        }
        ensure_currency("currency", &self.currency)?;
        ensure_sha256("terminal_evidence_sha256", &self.terminal_evidence_sha256)?;
        ensure_size(
            "terminal_evidence_size_bytes",
            self.terminal_evidence_size_bytes,
            MAX_PROVIDER_TERMINAL_EVIDENCE_BYTES,
        )
    }

    pub fn digest(&self) -> Result<String, ProviderAttemptValidationError> {
        self.validate()?;
        domain_digest(COMPLETION_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAttemptState {
    Pending,
    Accepted,
    Cancelled,
    Executing,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProviderAttemptPhaseV1 {
    Pending {
        invocation_blob: ProviderInvocationBlobBindingV1,
    },
    Accepted {
        invocation_blob: ProviderInvocationBlobBindingV1,
        acceptance: ProviderAcceptanceBindingV1,
    },
    Cancelled {
        invocation_blob: ProviderInvocationBlobBindingV1,
        cancellation: ProviderCancellationBindingV1,
    },
    Executing {
        invocation_blob: ProviderInvocationBlobBindingV1,
        acceptance: ProviderAcceptanceBindingV1,
        execution_lease: ProviderExecutionLeaseBindingV1,
    },
    Completed {
        invocation_blob: ProviderInvocationBlobBindingV1,
        acceptance: ProviderAcceptanceBindingV1,
        execution_lease: ProviderExecutionLeaseBindingV1,
        completion: Box<ProviderCompletionBindingV1>,
    },
}

impl ProviderAttemptPhaseV1 {
    #[must_use]
    pub const fn state(&self) -> ProviderAttemptState {
        match self {
            Self::Pending { .. } => ProviderAttemptState::Pending,
            Self::Accepted { .. } => ProviderAttemptState::Accepted,
            Self::Cancelled { .. } => ProviderAttemptState::Cancelled,
            Self::Executing { .. } => ProviderAttemptState::Executing,
            Self::Completed { .. } => ProviderAttemptState::Completed,
        }
    }

    #[must_use]
    pub fn invocation_blob(&self) -> &ProviderInvocationBlobBindingV1 {
        match self {
            Self::Pending { invocation_blob }
            | Self::Accepted {
                invocation_blob, ..
            }
            | Self::Cancelled {
                invocation_blob, ..
            }
            | Self::Executing {
                invocation_blob, ..
            }
            | Self::Completed {
                invocation_blob, ..
            } => invocation_blob,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAttemptCheckpointV1 {
    pub schema: String,
    pub attempt: ProviderAttemptBindingV1,
    pub checkpoint_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_digest: Option<String>,
    pub phase: ProviderAttemptPhaseV1,
}

impl ProviderAttemptCheckpointV1 {
    pub fn validate(&self) -> Result<(), ProviderAttemptValidationError> {
        ensure_schema(
            "checkpoint",
            &self.schema,
            PROVIDER_ATTEMPT_CHECKPOINT_SCHEMA,
        )?;
        self.attempt.validate()?;
        ensure_positive("checkpoint_sequence", self.checkpoint_sequence)?;
        match (
            self.checkpoint_sequence,
            self.previous_checkpoint_digest.as_deref(),
        ) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(invalid(
                    "previous_checkpoint_digest",
                    "the genesis checkpoint must not name a predecessor",
                ));
            }
            (_, Some(digest)) => ensure_sha256("previous_checkpoint_digest", digest)?,
            (_, None) => {
                return Err(invalid(
                    "previous_checkpoint_digest",
                    "a non-genesis checkpoint must name its predecessor",
                ));
            }
        }

        let invocation_blob = self.phase.invocation_blob();
        ensure_attempt(
            "checkpoint invocation blob",
            &self.attempt,
            &invocation_blob.attempt,
        )?;
        let blob_digest = invocation_blob.digest()?;
        match &self.phase {
            ProviderAttemptPhaseV1::Pending { .. } => {}
            ProviderAttemptPhaseV1::Accepted { acceptance, .. } => {
                validate_acceptance(&self.attempt, &blob_digest, acceptance)?;
            }
            ProviderAttemptPhaseV1::Cancelled { cancellation, .. } => {
                cancellation.validate()?;
                ensure_attempt("cancellation", &self.attempt, &cancellation.attempt)?;
                ensure_equal_digest(
                    "cancellation invocation_blob_digest",
                    &cancellation.invocation_blob_digest,
                    &blob_digest,
                )?;
            }
            ProviderAttemptPhaseV1::Executing {
                acceptance,
                execution_lease,
                ..
            } => {
                validate_acceptance(&self.attempt, &blob_digest, acceptance)?;
                validate_execution_lease(&self.attempt, &blob_digest, acceptance, execution_lease)?;
            }
            ProviderAttemptPhaseV1::Completed {
                acceptance,
                execution_lease,
                completion,
                ..
            } => {
                validate_acceptance(&self.attempt, &blob_digest, acceptance)?;
                validate_execution_lease(&self.attempt, &blob_digest, acceptance, execution_lease)?;
                completion.validate()?;
                ensure_attempt("completion", &self.attempt, &completion.attempt)?;
                ensure_equal_digest(
                    "completion invocation_blob_digest",
                    &completion.invocation_blob_digest,
                    &blob_digest,
                )?;
                ensure_equal_digest(
                    "completion acceptance_digest",
                    &completion.acceptance_digest,
                    &acceptance.digest()?,
                )?;
                ensure_equal_digest(
                    "completion execution_lease_digest",
                    &completion.execution_lease_digest,
                    &execution_lease.digest()?,
                )?;
                if completion.completed_at < execution_lease.acquired_at
                    || completion.completed_at >= execution_lease.expires_at
                {
                    return Err(invalid(
                        "completed_at",
                        "completion must be committed by the active execution lease",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String, ProviderAttemptValidationError> {
        self.validate()?;
        domain_digest(CHECKPOINT_DIGEST_DOMAIN, self)
    }
}

pub fn validate_provider_checkpoint_transition(
    previous: &ProviderAttemptCheckpointV1,
    next: &ProviderAttemptCheckpointV1,
) -> Result<(), ProviderAttemptValidationError> {
    previous.validate()?;
    next.validate()?;
    ensure_attempt("checkpoint", &previous.attempt, &next.attempt)?;
    let expected_sequence = previous
        .checkpoint_sequence
        .checked_add(1)
        .ok_or_else(|| invalid("checkpoint_sequence", "sequence overflow"))?;
    if next.checkpoint_sequence != expected_sequence {
        return Err(invalid(
            "checkpoint_sequence",
            format!(
                "expected {expected_sequence}, got {}",
                next.checkpoint_sequence
            ),
        ));
    }
    if next.previous_checkpoint_digest.as_deref() != Some(previous.digest()?.as_str()) {
        return Err(ProviderAttemptValidationError::BindingMismatch(
            "previous_checkpoint_digest",
        ));
    }

    let legal = match (&previous.phase, &next.phase) {
        (
            ProviderAttemptPhaseV1::Pending {
                invocation_blob: old_blob,
            },
            ProviderAttemptPhaseV1::Accepted {
                invocation_blob: new_blob,
                ..
            }
            | ProviderAttemptPhaseV1::Cancelled {
                invocation_blob: new_blob,
                ..
            },
        ) => old_blob == new_blob,
        (
            ProviderAttemptPhaseV1::Accepted {
                invocation_blob: old_blob,
                acceptance: old_acceptance,
            },
            ProviderAttemptPhaseV1::Executing {
                invocation_blob: new_blob,
                acceptance: new_acceptance,
                ..
            },
        ) => old_blob == new_blob && old_acceptance == new_acceptance,
        (
            ProviderAttemptPhaseV1::Executing {
                invocation_blob: old_blob,
                acceptance: old_acceptance,
                execution_lease: old_lease,
            },
            ProviderAttemptPhaseV1::Completed {
                invocation_blob: new_blob,
                acceptance: new_acceptance,
                execution_lease: new_lease,
                ..
            },
        ) => old_blob == new_blob && old_acceptance == new_acceptance && old_lease == new_lease,
        _ => false,
    };
    if legal {
        Ok(())
    } else {
        Err(ProviderAttemptValidationError::IllegalTransition {
            from: previous.phase.state(),
            to: next.phase.state(),
        })
    }
}

pub fn validate_provider_checkpoint_chain(
    anchor: Option<&ProviderAttemptCheckpointV1>,
    checkpoints: &[ProviderAttemptCheckpointV1],
) -> Result<(), ProviderAttemptValidationError> {
    if checkpoints.len() > MAX_PROVIDER_CHECKPOINT_CHAIN {
        return Err(ProviderAttemptValidationError::FieldTooLarge {
            field: "checkpoint_chain",
            actual: checkpoints.len(),
            maximum: MAX_PROVIDER_CHECKPOINT_CHAIN,
        });
    }
    if anchor.is_none() && checkpoints.is_empty() {
        return Err(invalid(
            "checkpoint_chain",
            "an unanchored response must include the genesis checkpoint",
        ));
    }
    if let Some(anchor) = anchor {
        anchor.validate()?;
    }
    let mut previous = anchor;
    for checkpoint in checkpoints {
        if let Some(previous) = previous {
            validate_provider_checkpoint_transition(previous, checkpoint)?;
        } else {
            checkpoint.validate()?;
            if checkpoint.checkpoint_sequence != 1
                || checkpoint.phase.state() != ProviderAttemptState::Pending
            {
                return Err(invalid(
                    "checkpoint_chain",
                    "the first checkpoint must be genesis Pending",
                ));
            }
        }
        previous = Some(checkpoint);
    }
    Ok(())
}

fn validate_acceptance(
    attempt: &ProviderAttemptBindingV1,
    blob_digest: &str,
    acceptance: &ProviderAcceptanceBindingV1,
) -> Result<(), ProviderAttemptValidationError> {
    acceptance.validate()?;
    ensure_attempt("acceptance", attempt, &acceptance.attempt)?;
    ensure_equal_digest(
        "acceptance invocation_blob_digest",
        &acceptance.invocation_blob_digest,
        blob_digest,
    )
}

fn validate_execution_lease(
    attempt: &ProviderAttemptBindingV1,
    blob_digest: &str,
    acceptance: &ProviderAcceptanceBindingV1,
    execution_lease: &ProviderExecutionLeaseBindingV1,
) -> Result<(), ProviderAttemptValidationError> {
    execution_lease.validate()?;
    ensure_attempt("execution lease", attempt, &execution_lease.attempt)?;
    ensure_equal_digest(
        "execution lease invocation_blob_digest",
        &execution_lease.invocation_blob_digest,
        blob_digest,
    )?;
    ensure_equal_digest(
        "execution lease acceptance_digest",
        &execution_lease.acceptance_digest,
        &acceptance.digest()?,
    )?;
    if execution_lease.acquired_at < acceptance.accepted_at {
        return Err(invalid(
            "acquired_at",
            "execution lease predates provider acceptance",
        ));
    }
    if execution_lease.execution_fence <= acceptance.cancellation_fence {
        return Err(invalid(
            "execution_fence",
            "execution fence must advance the immutable cancellation fence",
        ));
    }
    Ok(())
}

fn ensure_attempt(
    field: &'static str,
    expected: &ProviderAttemptBindingV1,
    actual: &ProviderAttemptBindingV1,
) -> Result<(), ProviderAttemptValidationError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ProviderAttemptValidationError::BindingMismatch(field))
    }
}

fn ensure_equal_digest(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), ProviderAttemptValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProviderAttemptValidationError::BindingMismatch(field))
    }
}

fn ensure_schema(
    field: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), ProviderAttemptValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ProviderAttemptValidationError::UnsupportedSchema {
            field,
            value: actual.to_string(),
        })
    }
}

fn ensure_id(field: &'static str, value: &str) -> Result<(), ProviderAttemptValidationError> {
    ensure_text(field, value, MAX_PROVIDER_ID_BYTES)
}

fn ensure_ref(field: &'static str, value: &str) -> Result<(), ProviderAttemptValidationError> {
    ensure_text(field, value, MAX_PROVIDER_REF_BYTES)
}

fn ensure_currency(field: &'static str, value: &str) -> Result<(), ProviderAttemptValidationError> {
    if value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(invalid(field, "must be an uppercase ISO-4217 code"))
    }
}

fn ensure_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), ProviderAttemptValidationError> {
    if value.is_empty() {
        return Err(ProviderAttemptValidationError::EmptyField(field));
    }
    if value.len() > maximum {
        return Err(ProviderAttemptValidationError::FieldTooLarge {
            field,
            actual: value.len(),
            maximum,
        });
    }
    if value.trim() != value {
        return Err(invalid(
            field,
            "leading or trailing whitespace is forbidden",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(field, "control characters are forbidden"));
    }
    Ok(())
}

fn ensure_sha256(field: &'static str, value: &str) -> Result<(), ProviderAttemptValidationError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProviderAttemptValidationError::InvalidDigest(field))
    }
}

fn ensure_positive(field: &'static str, value: u64) -> Result<(), ProviderAttemptValidationError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        Err(invalid(field, "must be a positive I-JSON safe integer"))
    } else {
        Ok(())
    }
}

fn ensure_size(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ProviderAttemptValidationError> {
    if value == 0 || value > maximum {
        Err(invalid(
            field,
            format!("must be in 1..={maximum}, got {value}"),
        ))
    } else {
        Ok(())
    }
}

fn ensure_bounded_size(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ProviderAttemptValidationError> {
    if value > maximum {
        Err(invalid(
            field,
            format!("must be at most {maximum}, got {value}"),
        ))
    } else {
        Ok(())
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ProviderAttemptValidationError {
    ProviderAttemptValidationError::InvalidValue {
        field,
        reason: reason.into(),
    }
}

fn domain_digest<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<String, ProviderAttemptValidationError> {
    let canonical = canonical_json_bytes(value)
        .map_err(|error| ProviderAttemptValidationError::Canonicalization(error.to_string()))?;
    let mut message = Vec::with_capacity(domain.len() + 1 + canonical.len());
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical);
    Ok(sha256_hex(&message))
}

#[cfg(test)]
#[path = "provider_attempt_tests.rs"]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
