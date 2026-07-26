//! Closed verification boundary for provider-side dispatch recovery.
//!
//! Provider DTOs are untrusted until this module validates a monotonic attempt
//! chain and any referenced bytes. With no internally qualified provider, the
//! only result is `Unknown`; no generic tool transport is qualified by default.

use std::{fmt, sync::Arc};

#[cfg(test)]
use chio_core_types::canonical_json_bytes;
use chio_core_types::provider_attempt::{
    validate_provider_checkpoint_chain, ProviderAcceptanceBindingV1, ProviderAttemptBindingV1,
    ProviderAttemptCheckpointV1, ProviderAttemptPhaseV1, ProviderCancellationBindingV1,
    ProviderCompletionBindingV1, ProviderExecutionLeaseBindingV1,
};
use chio_core_types::sha256_hex;
#[cfg(test)]
use serde::Serialize;

#[cfg(test)]
const PROVIDER_QUALIFICATION_DOMAIN: &str = "chio.dispatch-status-provider-qualification.v1";
const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchStatusProviderError {
    message: String,
}

impl DispatchStatusProviderError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DispatchStatusProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for DispatchStatusProviderError {}

#[derive(Debug, thiserror::Error)]
pub enum DispatchStatusError {
    #[error("invalid dispatch status query: {0}")]
    InvalidQuery(String),
    #[error("invalid provider qualification: {0}")]
    InvalidQualification(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchStatusQuery {
    pub attempt: ProviderAttemptBindingV1,
    /// Untrusted continuity hint. This is never promoted to provider evidence.
    pub last_checkpoint: Option<ProviderAttemptCheckpointV1>,
    pub observed_at: u64,
}

impl DispatchStatusQuery {
    pub fn validate(&self) -> Result<(), DispatchStatusError> {
        self.attempt
            .validate()
            .map_err(|error| DispatchStatusError::InvalidQuery(error.to_string()))?;
        if self.observed_at == 0 || self.observed_at > I_JSON_MAX_SAFE_INTEGER {
            return Err(DispatchStatusError::InvalidQuery(
                "observed_at must be a positive I-JSON safe integer".to_string(),
            ));
        }
        if let Some(checkpoint) = &self.last_checkpoint {
            checkpoint
                .validate()
                .map_err(|error| DispatchStatusError::InvalidQuery(error.to_string()))?;
            if checkpoint.attempt != self.attempt {
                return Err(DispatchStatusError::InvalidQuery(
                    "last checkpoint is bound to another provider attempt".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// An observation claimed by a provider adapter.
///
/// A checkpoint response contains every checkpoint strictly after the query's
/// `last_checkpoint`, or the full chain starting at genesis when no local
/// checkpoint exists. An empty response contains no verifiable provider state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderDispatchStatusObservation {
    Checkpoints(Vec<ProviderAttemptCheckpointV1>),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedProviderAcceptance {
    pub binding: ProviderAcceptanceBindingV1,
    pub envelope: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedProviderNotAccepted {
    pub binding: ProviderCancellationBindingV1,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedProviderCompletedOutcome {
    pub binding: ProviderCompletionBindingV1,
    pub outcome_bytes: Vec<u8>,
    pub cost_units: u64,
    pub currency: String,
    pub terminal_evidence: Vec<u8>,
}

/// Untrusted provider transport surface.
///
/// Implementing this trait does not qualify an adapter. Only the private,
/// provider-owning qualification boundary below can make these responses
/// eligible for verification.
pub trait DispatchStatusProvider: Send + Sync {
    fn transport_id(&self) -> &str;
    fn transport_key_epoch(&self) -> u64;

    fn status(
        &self,
        query: &DispatchStatusQuery,
    ) -> Result<ProviderDispatchStatusObservation, DispatchStatusProviderError>;

    fn fetch_acceptance(
        &self,
        binding: &ProviderAcceptanceBindingV1,
    ) -> Result<AuthenticatedProviderAcceptance, DispatchStatusProviderError>;

    fn fetch_not_accepted(
        &self,
        binding: &ProviderCancellationBindingV1,
    ) -> Result<AuthenticatedProviderNotAccepted, DispatchStatusProviderError>;

    /// Fetch the exact authenticated bytes, cost, currency, and terminal
    /// evidence bound by a completed checkpoint. A reference alone is never a
    /// completed result.
    fn fetch_completed_outcome(
        &self,
        binding: &ProviderCompletionBindingV1,
    ) -> Result<AuthenticatedProviderCompletedOutcome, DispatchStatusProviderError>;
}

/// Sealed composition point for a concrete qualified adapter.
///
/// An implementation belongs in this module only after its constructor pins a
/// transport key epoch and signed-message domain, owns the corresponding
/// signature verifier, and reads a rollback-independent continuity anchor and
/// high-water mark. A public `DispatchStatusProvider` implementation alone is
/// deliberately insufficient.
trait QualifiedDispatchStatusAdapter: DispatchStatusProvider {}

/// Opaque authority to query one qualified provider instance.
///
/// The token owns the adapter it qualifies, is not deserializable, and has no
/// public constructor. This prevents substituting a self-asserted provider with
/// the same transport id and epoch.
///
/// ```compile_fail
/// let _: Result<chio_kernel::dispatch_status::QualifiedDispatchStatusProvider, _> =
///     serde_json::from_str("{}");
/// ```
pub struct QualifiedDispatchStatusProvider {
    provider: Arc<dyn QualifiedDispatchStatusAdapter>,
    transport_id: String,
    transport_key_epoch: u64,
    qualification_digest: String,
}

impl fmt::Debug for QualifiedDispatchStatusProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedDispatchStatusProvider")
            .field("transport_id", &self.transport_id)
            .field("transport_key_epoch", &self.transport_key_epoch)
            .field("qualification_digest", &self.qualification_digest)
            .finish_non_exhaustive()
    }
}

impl QualifiedDispatchStatusProvider {
    #[must_use]
    pub fn transport_id(&self) -> &str {
        &self.transport_id
    }

    #[must_use]
    pub const fn transport_key_epoch(&self) -> u64 {
        self.transport_key_epoch
    }

    #[must_use]
    pub fn qualification_digest(&self) -> &str {
        &self.qualification_digest
    }
}

#[cfg(test)]
#[derive(Serialize)]
struct TestQualificationBinding<'a> {
    transport_id: &'a str,
    transport_key_epoch: u64,
    signature_verifier_id: &'a str,
    continuity_anchor_id: &'a str,
    continuity_high_water: u64,
    signed_message_domain: &'a str,
}

#[cfg(test)]
struct TestQualifiedDispatchStatusAdapter(Arc<dyn DispatchStatusProvider>);

#[cfg(test)]
impl DispatchStatusProvider for TestQualifiedDispatchStatusAdapter {
    fn transport_id(&self) -> &str {
        self.0.transport_id()
    }

    fn transport_key_epoch(&self) -> u64 {
        self.0.transport_key_epoch()
    }

    fn status(
        &self,
        query: &DispatchStatusQuery,
    ) -> Result<ProviderDispatchStatusObservation, DispatchStatusProviderError> {
        self.0.status(query)
    }

    fn fetch_acceptance(
        &self,
        binding: &ProviderAcceptanceBindingV1,
    ) -> Result<AuthenticatedProviderAcceptance, DispatchStatusProviderError> {
        self.0.fetch_acceptance(binding)
    }

    fn fetch_not_accepted(
        &self,
        binding: &ProviderCancellationBindingV1,
    ) -> Result<AuthenticatedProviderNotAccepted, DispatchStatusProviderError> {
        self.0.fetch_not_accepted(binding)
    }

    fn fetch_completed_outcome(
        &self,
        binding: &ProviderCompletionBindingV1,
    ) -> Result<AuthenticatedProviderCompletedOutcome, DispatchStatusProviderError> {
        self.0.fetch_completed_outcome(binding)
    }
}

#[cfg(test)]
impl QualifiedDispatchStatusAdapter for TestQualifiedDispatchStatusAdapter {}

#[cfg(test)]
pub(crate) fn qualify_dispatch_status_provider_for_test(
    provider: Arc<dyn DispatchStatusProvider>,
    signature_verifier_id: &str,
    continuity_anchor_id: &str,
    continuity_high_water: u64,
    signed_message_domain: &str,
) -> Result<QualifiedDispatchStatusProvider, DispatchStatusError> {
    qualify_sealed_dispatch_status_provider_for_test(
        Arc::new(TestQualifiedDispatchStatusAdapter(provider)),
        signature_verifier_id,
        continuity_anchor_id,
        continuity_high_water,
        signed_message_domain,
    )
}

#[cfg(test)]
fn qualify_sealed_dispatch_status_provider_for_test(
    provider: Arc<dyn QualifiedDispatchStatusAdapter>,
    signature_verifier_id: &str,
    continuity_anchor_id: &str,
    continuity_high_water: u64,
    signed_message_domain: &str,
) -> Result<QualifiedDispatchStatusProvider, DispatchStatusError> {
    let transport_id = provider.transport_id().to_string();
    let transport_key_epoch = provider.transport_key_epoch();
    validate_transport_binding(&transport_id, transport_key_epoch)?;
    if !valid_qualification_id(signature_verifier_id)
        || !valid_qualification_id(continuity_anchor_id)
        || continuity_high_water == 0
        || continuity_high_water > I_JSON_MAX_SAFE_INTEGER
        || !valid_qualification_id(signed_message_domain)
    {
        return Err(DispatchStatusError::InvalidQualification(
            "test qualification binding is invalid".to_string(),
        ));
    }
    let canonical = canonical_json_bytes(&TestQualificationBinding {
        transport_id: &transport_id,
        transport_key_epoch,
        signature_verifier_id,
        continuity_anchor_id,
        continuity_high_water,
        signed_message_domain,
    })
    .map_err(|error| DispatchStatusError::InvalidQualification(error.to_string()))?;
    let mut bytes = Vec::with_capacity(PROVIDER_QUALIFICATION_DOMAIN.len() + 1 + canonical.len());
    bytes.extend_from_slice(PROVIDER_QUALIFICATION_DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&canonical);
    Ok(QualifiedDispatchStatusProvider {
        provider,
        transport_id,
        transport_key_epoch,
        qualification_digest: sha256_hex(&bytes),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchUnknownReason {
    UnqualifiedProvider,
    QualificationMismatch,
    ProviderUnavailable,
    ProviderReportedUnknown,
    InvalidProviderEvidence,
    AcceptanceUnavailable,
    NotAcceptedProofUnavailable,
    CompletedOutcomeUnavailable,
    StaleExecutionLease,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderPending {
    qualification_digest: String,
    checkpoint: ProviderAttemptCheckpointV1,
    checkpoint_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderNotAccepted {
    qualification_digest: String,
    checkpoint: ProviderAttemptCheckpointV1,
    checkpoint_digest: String,
    cancellation: ProviderCancellationBindingV1,
    proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderAccepted {
    qualification_digest: String,
    checkpoint: ProviderAttemptCheckpointV1,
    checkpoint_digest: String,
    acceptance: ProviderAcceptanceBindingV1,
    acceptance_envelope: Vec<u8>,
    execution_lease: Option<ProviderExecutionLeaseBindingV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderCompleted {
    qualification_digest: String,
    checkpoint: ProviderAttemptCheckpointV1,
    checkpoint_digest: String,
    completion: ProviderCompletionBindingV1,
    outcome_bytes: Vec<u8>,
    cost_units: u64,
    currency: String,
    terminal_evidence: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProviderUnknown {
    attempt: ProviderAttemptBindingV1,
    reason: DispatchUnknownReason,
    last_checkpoint_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedDispatchStatus {
    NotAccepted(VerifiedProviderNotAccepted),
    Pending(VerifiedProviderPending),
    Accepted(VerifiedProviderAccepted),
    Completed(VerifiedProviderCompleted),
    Unknown(VerifiedProviderUnknown),
}

macro_rules! checkpoint_accessors {
    ($type:ty) => {
        impl $type {
            #[must_use]
            pub fn qualification_digest(&self) -> &str {
                &self.qualification_digest
            }

            #[must_use]
            pub fn checkpoint(&self) -> &ProviderAttemptCheckpointV1 {
                &self.checkpoint
            }

            #[must_use]
            pub fn checkpoint_digest(&self) -> &str {
                &self.checkpoint_digest
            }
        }
    };
}

checkpoint_accessors!(VerifiedProviderPending);
checkpoint_accessors!(VerifiedProviderNotAccepted);
checkpoint_accessors!(VerifiedProviderAccepted);
checkpoint_accessors!(VerifiedProviderCompleted);

impl VerifiedProviderNotAccepted {
    #[must_use]
    pub fn cancellation(&self) -> &ProviderCancellationBindingV1 {
        &self.cancellation
    }

    #[must_use]
    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    #[cfg(test)]
    pub(crate) fn with_cancellation_for_test(
        &self,
        cancellation: ProviderCancellationBindingV1,
    ) -> Self {
        Self {
            cancellation,
            ..self.clone()
        }
    }
}

impl VerifiedProviderAccepted {
    #[must_use]
    pub fn acceptance(&self) -> &ProviderAcceptanceBindingV1 {
        &self.acceptance
    }

    #[must_use]
    pub fn acceptance_envelope(&self) -> &[u8] {
        &self.acceptance_envelope
    }

    #[must_use]
    pub fn execution_lease(&self) -> Option<&ProviderExecutionLeaseBindingV1> {
        self.execution_lease.as_ref()
    }
}

impl VerifiedProviderCompleted {
    #[must_use]
    pub fn completion(&self) -> &ProviderCompletionBindingV1 {
        &self.completion
    }

    #[must_use]
    pub fn outcome_bytes(&self) -> &[u8] {
        &self.outcome_bytes
    }

    #[must_use]
    pub const fn cost_units(&self) -> u64 {
        self.cost_units
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub fn terminal_evidence(&self) -> &[u8] {
        &self.terminal_evidence
    }
}

impl VerifiedProviderUnknown {
    #[must_use]
    pub fn attempt(&self) -> &ProviderAttemptBindingV1 {
        &self.attempt
    }

    #[must_use]
    pub const fn reason(&self) -> DispatchUnknownReason {
        self.reason
    }

    #[must_use]
    pub fn last_checkpoint_digest(&self) -> Option<&str> {
        self.last_checkpoint_digest.as_deref()
    }
}

pub fn resolve_dispatch_status(
    qualification: Option<&QualifiedDispatchStatusProvider>,
    query: &DispatchStatusQuery,
) -> Result<VerifiedDispatchStatus, DispatchStatusError> {
    query.validate()?;
    let Some(qualification) = qualification else {
        return Ok(unknown(query, DispatchUnknownReason::UnqualifiedProvider));
    };
    let provider = qualification.provider.as_ref();
    if qualification.transport_id != query.attempt.transport_id
        || qualification.transport_key_epoch != query.attempt.transport_key_epoch
        || provider.transport_id() != query.attempt.transport_id
        || provider.transport_key_epoch() != query.attempt.transport_key_epoch
    {
        return Ok(unknown(query, DispatchUnknownReason::QualificationMismatch));
    }

    let observation = match provider.status(query) {
        Ok(observation) => observation,
        Err(_) => return Ok(unknown(query, DispatchUnknownReason::ProviderUnavailable)),
    };
    let ProviderDispatchStatusObservation::Checkpoints(checkpoints) = observation else {
        return Ok(unknown(
            query,
            DispatchUnknownReason::ProviderReportedUnknown,
        ));
    };
    if validate_provider_checkpoint_chain(query.last_checkpoint.as_ref(), &checkpoints).is_err() {
        return Ok(unknown(
            query,
            DispatchUnknownReason::InvalidProviderEvidence,
        ));
    }
    let Some(checkpoint) = checkpoints.last().cloned() else {
        return Ok(unknown(
            query,
            DispatchUnknownReason::InvalidProviderEvidence,
        ));
    };
    if checkpoint.attempt != query.attempt {
        return Ok(unknown(
            query,
            DispatchUnknownReason::InvalidProviderEvidence,
        ));
    }
    let Ok(checkpoint_digest) = checkpoint.digest() else {
        return Ok(unknown(
            query,
            DispatchUnknownReason::InvalidProviderEvidence,
        ));
    };

    let phase = checkpoint.phase.clone();
    if phase_observed_after(&phase, query.observed_at) {
        return Ok(unknown(
            query,
            DispatchUnknownReason::InvalidProviderEvidence,
        ));
    }
    match phase {
        ProviderAttemptPhaseV1::Pending { .. } => {
            Ok(VerifiedDispatchStatus::Pending(VerifiedProviderPending {
                qualification_digest: qualification.qualification_digest.clone(),
                checkpoint,
                checkpoint_digest,
            }))
        }
        ProviderAttemptPhaseV1::Cancelled { cancellation, .. } => {
            let fetched = match provider.fetch_not_accepted(&cancellation) {
                Ok(fetched) => fetched,
                Err(_) => {
                    return Ok(unknown(
                        query,
                        DispatchUnknownReason::NotAcceptedProofUnavailable,
                    ));
                }
            };
            if fetched.binding != cancellation
                || !bytes_match(
                    &fetched.proof,
                    cancellation.no_acceptance_proof_size_bytes,
                    &cancellation.no_acceptance_proof_sha256,
                )
            {
                return Ok(unknown(
                    query,
                    DispatchUnknownReason::InvalidProviderEvidence,
                ));
            }
            Ok(VerifiedDispatchStatus::NotAccepted(
                VerifiedProviderNotAccepted {
                    qualification_digest: qualification.qualification_digest.clone(),
                    checkpoint,
                    checkpoint_digest,
                    cancellation,
                    proof: fetched.proof,
                },
            ))
        }
        ProviderAttemptPhaseV1::Accepted { acceptance, .. } => verified_accepted(
            provider,
            query,
            qualification.qualification_digest(),
            checkpoint,
            checkpoint_digest,
            acceptance,
            None,
        ),
        ProviderAttemptPhaseV1::Executing {
            acceptance,
            execution_lease,
            ..
        } => {
            if query.observed_at >= execution_lease.expires_at {
                return Ok(unknown(query, DispatchUnknownReason::StaleExecutionLease));
            }
            verified_accepted(
                provider,
                query,
                qualification.qualification_digest(),
                checkpoint,
                checkpoint_digest,
                acceptance,
                Some(execution_lease),
            )
        }
        ProviderAttemptPhaseV1::Completed { completion, .. } => {
            let completion = *completion;
            let fetched = match provider.fetch_completed_outcome(&completion) {
                Ok(fetched) => fetched,
                Err(_) => {
                    return Ok(unknown(
                        query,
                        DispatchUnknownReason::CompletedOutcomeUnavailable,
                    ));
                }
            };
            if fetched.binding != completion
                || fetched.cost_units != completion.cost_units
                || fetched.currency != completion.currency
                || !bytes_match(
                    &fetched.outcome_bytes,
                    completion.outcome_size_bytes,
                    &completion.outcome_sha256,
                )
                || !bytes_match(
                    &fetched.terminal_evidence,
                    completion.terminal_evidence_size_bytes,
                    &completion.terminal_evidence_sha256,
                )
            {
                return Ok(unknown(
                    query,
                    DispatchUnknownReason::InvalidProviderEvidence,
                ));
            }
            Ok(VerifiedDispatchStatus::Completed(
                VerifiedProviderCompleted {
                    qualification_digest: qualification.qualification_digest.clone(),
                    checkpoint,
                    checkpoint_digest,
                    completion,
                    outcome_bytes: fetched.outcome_bytes,
                    cost_units: fetched.cost_units,
                    currency: fetched.currency,
                    terminal_evidence: fetched.terminal_evidence,
                },
            ))
        }
    }
}

fn phase_observed_after(phase: &ProviderAttemptPhaseV1, observed_at: u64) -> bool {
    match phase {
        ProviderAttemptPhaseV1::Pending { .. } => false,
        ProviderAttemptPhaseV1::Accepted { acceptance, .. } => acceptance.accepted_at > observed_at,
        ProviderAttemptPhaseV1::Cancelled { cancellation, .. } => {
            cancellation.cancelled_at > observed_at
        }
        ProviderAttemptPhaseV1::Executing {
            acceptance,
            execution_lease,
            ..
        } => acceptance.accepted_at > observed_at || execution_lease.acquired_at > observed_at,
        ProviderAttemptPhaseV1::Completed {
            acceptance,
            execution_lease,
            completion,
            ..
        } => {
            acceptance.accepted_at > observed_at
                || execution_lease.acquired_at > observed_at
                || completion.completed_at > observed_at
        }
    }
}

fn verified_accepted(
    provider: &dyn DispatchStatusProvider,
    query: &DispatchStatusQuery,
    qualification_digest: &str,
    checkpoint: ProviderAttemptCheckpointV1,
    checkpoint_digest: String,
    acceptance: ProviderAcceptanceBindingV1,
    execution_lease: Option<ProviderExecutionLeaseBindingV1>,
) -> Result<VerifiedDispatchStatus, DispatchStatusError> {
    let fetched = match provider.fetch_acceptance(&acceptance) {
        Ok(fetched) => fetched,
        Err(_) => return Ok(unknown(query, DispatchUnknownReason::AcceptanceUnavailable)),
    };
    if fetched.binding != acceptance
        || !bytes_match(
            &fetched.envelope,
            acceptance.acceptance_envelope_size_bytes,
            &acceptance.acceptance_envelope_sha256,
        )
    {
        return Ok(unknown(
            query,
            DispatchUnknownReason::InvalidProviderEvidence,
        ));
    }
    Ok(VerifiedDispatchStatus::Accepted(VerifiedProviderAccepted {
        qualification_digest: qualification_digest.to_string(),
        checkpoint,
        checkpoint_digest,
        acceptance,
        acceptance_envelope: fetched.envelope,
        execution_lease,
    }))
}

fn unknown(query: &DispatchStatusQuery, reason: DispatchUnknownReason) -> VerifiedDispatchStatus {
    VerifiedDispatchStatus::Unknown(VerifiedProviderUnknown {
        attempt: query.attempt.clone(),
        reason,
        last_checkpoint_digest: query
            .last_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.digest().ok()),
    })
}

fn bytes_match(bytes: &[u8], expected_size: u64, expected_sha256: &str) -> bool {
    u64::try_from(bytes.len()) == Ok(expected_size) && sha256_hex(bytes) == expected_sha256
}

#[cfg(test)]
fn validate_transport_binding(
    transport_id: &str,
    transport_key_epoch: u64,
) -> Result<(), DispatchStatusError> {
    if transport_id.is_empty()
        || transport_id.trim() != transport_id
        || transport_id.len() > 512
        || transport_id.chars().any(char::is_control)
    {
        return Err(DispatchStatusError::InvalidQualification(
            "transport_id is empty, padded, invalid, or oversized".to_string(),
        ));
    }
    if transport_key_epoch == 0 {
        return Err(DispatchStatusError::InvalidQualification(
            "transport_key_epoch must be positive".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn valid_qualification_id(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= 512
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
#[path = "dispatch_status_tests.rs"]
mod tests;
