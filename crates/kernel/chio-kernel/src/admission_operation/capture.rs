use std::{fmt, sync::Arc};

use serde::Serialize;

use crate::budget_store::{
    BudgetEventAuthority, BudgetGuaranteeLevel, BudgetInvocationQuotaUsage, BudgetQuotaProfile,
    MAX_INVOCATION_QUOTAS_PER_ADMISSION,
};
use crate::supplemental_quota::CanonicalRevocationSet;

use super::*;

pub const ADMISSION_CAPTURE_GLOBAL_GENESIS_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
pub const ADMISSION_CAPTURE_MUTATION_KIND: &str = "combined_admission_capture";
const ADMISSION_CAPTURE_RESPONSE_DOMAIN: &[u8] = b"chio.admission-capture-response.v1\0";
#[cfg(test)]
const ADMISSION_CAPTURE_QUALIFICATION_DOMAIN: &[u8] = b"chio.admission-capture-qualification.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionCaptureDenialReason {
    Revoked,
    AuthorizationExpired,
    InvocationQuotaExhausted,
    MonetaryLimitExceeded,
    ApprovalNotAuthorized,
    ParticipantBindingMismatch,
}

impl AdmissionCaptureDenialReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::AuthorizationExpired => "authorization_expired",
            Self::InvocationQuotaExhausted => "invocation_quota_exhausted",
            Self::MonetaryLimitExceeded => "monetary_limit_exceeded",
            Self::ApprovalNotAuthorized => "approval_not_authorized",
            Self::ParticipantBindingMismatch => "participant_binding_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureRequestV1 {
    pub operation_id: AdmissionOperationId,
    pub expected_operation_version: u64,
    pub coordinator_lease_epoch: u64,
    pub capability_id: AdmissionIdentifier,
    pub grant_index: u32,
    pub hold_id: AdmissionIdentifier,
    pub event_id: AdmissionIdentifier,
    pub revocation_set: CanonicalRevocationSet,
    pub authorization_artifact_digests: Vec<AdmissionDigest>,
    pub authorization_expires_at_unix_ms: u64,
    pub expected_invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub authority: BudgetEventAuthority,
    pub previous_global_commit_sequence: u64,
    pub previous_global_commit_digest: AdmissionDigest,
    pub store_fence: StoreMutationFence,
}

impl AdmissionCaptureRequestV1 {
    pub fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_positive_ijson(
            "expected_operation_version",
            self.expected_operation_version,
        )?;
        validate_positive_ijson("coordinator_lease_epoch", self.coordinator_lease_epoch)?;
        validate_positive_ijson(
            "authorization_expires_at_unix_ms",
            self.authorization_expires_at_unix_ms,
        )?;
        validate_store_fence(&self.store_fence)?;
        validate_artifact_digests(&self.authorization_artifact_digests)?;
        validate_authority_binding(&self.authority, &self.store_fence)?;
        validate_global_predecessor(
            self.previous_global_commit_sequence,
            &self.previous_global_commit_digest,
        )?;
        validate_quota_usages(
            &self.expected_invocation_quota_usages,
            &self.capability_id,
            self.grant_index,
        )
    }

    pub fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(), AdmissionOperationError> {
        self.validate()?;
        operation.validate()?;
        if operation.state != AdmissionOperationState::CapturePending
            || operation.version != self.expected_operation_version
            || operation.coordinator_lease_epoch != self.coordinator_lease_epoch
        {
            return Err(AdmissionOperationError::CapturePreconditionMismatch);
        }
        if operation.binding.operation_id != self.operation_id
            || operation.binding.capability_id != self.capability_id
            || operation
                .attachments
                .existing_matches(&AdmissionAttachment::BudgetHoldId(self.hold_id.clone()))
                != Some(true)
        {
            return Err(AdmissionOperationError::CaptureBindingMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCaptureDisposition {
    Captured,
    Denied(AdmissionCaptureDenialReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCombinedCaptureCommit {
    pub authority: BudgetEventAuthority,
    pub guarantee_level: BudgetGuaranteeLevel,
    pub previous_global_commit_sequence: u64,
    pub previous_global_commit_digest: AdmissionDigest,
    pub global_commit_sequence: u64,
    pub global_commit_digest: AdmissionDigest,
    pub store_fence: StoreMutationFence,
}

impl AdmissionCombinedCaptureCommit {
    pub fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_authority_binding(&self.authority, &self.store_fence)?;
        validate_global_predecessor(
            self.previous_global_commit_sequence,
            &self.previous_global_commit_digest,
        )?;
        validate_positive_ijson("global_commit_sequence", self.global_commit_sequence)?;
        if self.guarantee_level != BudgetGuaranteeLevel::SingleNodeAtomic
            || self.global_commit_sequence
                != self
                    .previous_global_commit_sequence
                    .checked_add(1)
                    .ok_or(AdmissionOperationError::CaptureCommitMismatch)?
            || self.global_commit_digest == self.previous_global_commit_digest
        {
            return Err(AdmissionOperationError::CaptureCommitMismatch);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureRecordV1 {
    pub operation_id: AdmissionOperationId,
    pub operation_version: u64,
    pub coordinator_lease_epoch: u64,
    pub capability_id: AdmissionIdentifier,
    pub grant_index: u32,
    pub hold_id: AdmissionIdentifier,
    pub event_id: AdmissionIdentifier,
    pub revocation_set: CanonicalRevocationSet,
    pub authorization_artifact_digests: Vec<AdmissionDigest>,
    pub invocation_quota_usages: Vec<BudgetInvocationQuotaUsage>,
    pub authorization_expires_at_unix_ms: u64,
    pub authority_time_unix_ms: u64,
    pub combined_commit: AdmissionCombinedCaptureCommit,
    pub disposition: AdmissionCaptureDisposition,
}

impl AdmissionCaptureRecordV1 {
    /// Checks structure and internal consistency only. The record remains
    /// untrusted until returned as a `QualifiedAdmissionCaptureDecision`.
    pub fn validate(&self) -> Result<(), AdmissionOperationError> {
        validate_positive_ijson("operation_version", self.operation_version)?;
        validate_positive_ijson("coordinator_lease_epoch", self.coordinator_lease_epoch)?;
        validate_positive_ijson(
            "authorization_expires_at_unix_ms",
            self.authorization_expires_at_unix_ms,
        )?;
        validate_positive_ijson("authority_time_unix_ms", self.authority_time_unix_ms)?;
        validate_artifact_digests(&self.authorization_artifact_digests)?;
        validate_quota_usages(
            &self.invocation_quota_usages,
            &self.capability_id,
            self.grant_index,
        )?;
        self.combined_commit.validate()?;
        let expired = self.authority_time_unix_ms >= self.authorization_expires_at_unix_ms;
        let expiry_disposition_matches = match self.disposition {
            AdmissionCaptureDisposition::Captured => !expired,
            AdmissionCaptureDisposition::Denied(
                AdmissionCaptureDenialReason::AuthorizationExpired,
            ) => expired,
            AdmissionCaptureDisposition::Denied(_) => !expired,
        };
        if !expiry_disposition_matches {
            return Err(AdmissionOperationError::CaptureExpiryMismatch);
        }
        Ok(())
    }

    fn matches_request(&self, request: &AdmissionCaptureRequestV1) -> bool {
        self.operation_id == request.operation_id
            && self.operation_version == request.expected_operation_version
            && self.coordinator_lease_epoch == request.coordinator_lease_epoch
            && self.capability_id == request.capability_id
            && self.grant_index == request.grant_index
            && self.hold_id == request.hold_id
            && self.event_id == request.event_id
            && self.revocation_set == request.revocation_set
            && self.authorization_artifact_digests == request.authorization_artifact_digests
            && self.authorization_expires_at_unix_ms == request.authorization_expires_at_unix_ms
            && self.combined_commit.authority == request.authority
            && self.combined_commit.previous_global_commit_sequence
                == request.previous_global_commit_sequence
            && self.combined_commit.previous_global_commit_digest
                == request.previous_global_commit_digest
            && self.combined_commit.store_fence == request.store_fence
    }

    fn quota_effect_matches_request(&self, request: &AdmissionCaptureRequestV1) -> bool {
        match self.disposition {
            AdmissionCaptureDisposition::Captured => {
                request
                    .expected_invocation_quota_usages
                    .iter()
                    .zip(&self.invocation_quota_usages)
                    .all(|(before, after)| {
                        before.quota == after.quota
                            && before.reserved_invocations.checked_sub(1)
                                == Some(after.reserved_invocations)
                            && before.captured_invocations.checked_add(1)
                                == Some(after.captured_invocations)
                    })
                    && self.invocation_quota_usages.len()
                        == request.expected_invocation_quota_usages.len()
            }
            AdmissionCaptureDisposition::Denied(_) => {
                self.invocation_quota_usages == request.expected_invocation_quota_usages
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmissionCaptureResponseKind {
    Captured,
    AlreadyCaptured,
    Denied,
}

impl AdmissionCaptureResponseKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::AlreadyCaptured => "already_captured",
            Self::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionCaptureAuthorityResponseV1 {
    record: AdmissionCaptureRecordV1,
    response_digest: AdmissionDigest,
}

impl AdmissionCaptureAuthorityResponseV1 {
    fn record(&self) -> &AdmissionCaptureRecordV1 {
        &self.record
    }

    fn response_digest(&self) -> &AdmissionDigest {
        &self.response_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionCaptureDecision {
    Captured(AdmissionCaptureAuthorityResponseV1),
    AlreadyCaptured(AdmissionCaptureAuthorityResponseV1),
    Denied(AdmissionCaptureAuthorityResponseV1),
}

impl AdmissionCaptureDecision {
    /// Builds a structurally valid but unauthenticated authority response.
    pub fn untrusted_captured(
        record: AdmissionCaptureRecordV1,
    ) -> Result<Self, AdmissionOperationError> {
        Self::build(AdmissionCaptureResponseKind::Captured, record)
    }

    /// Builds a structurally valid but unauthenticated replay response.
    pub fn untrusted_already_captured(
        record: AdmissionCaptureRecordV1,
    ) -> Result<Self, AdmissionOperationError> {
        Self::build(AdmissionCaptureResponseKind::AlreadyCaptured, record)
    }

    /// Builds a structurally valid but unauthenticated denial response.
    pub fn untrusted_denied(
        record: AdmissionCaptureRecordV1,
    ) -> Result<Self, AdmissionOperationError> {
        Self::build(AdmissionCaptureResponseKind::Denied, record)
    }

    fn build(
        kind: AdmissionCaptureResponseKind,
        record: AdmissionCaptureRecordV1,
    ) -> Result<Self, AdmissionOperationError> {
        record.validate()?;
        validate_disposition(kind, &record.disposition)?;
        let response = AdmissionCaptureAuthorityResponseV1 {
            response_digest: capture_response_digest(kind, &record)?,
            record,
        };
        Ok(match kind {
            AdmissionCaptureResponseKind::Captured => Self::Captured(response),
            AdmissionCaptureResponseKind::AlreadyCaptured => Self::AlreadyCaptured(response),
            AdmissionCaptureResponseKind::Denied => Self::Denied(response),
        })
    }

    fn validate_for(
        &self,
        request: &AdmissionCaptureRequestV1,
    ) -> Result<(), AdmissionOperationError> {
        request.validate()?;
        self.record().validate()?;
        validate_disposition(self.kind(), &self.record().disposition)?;
        if capture_response_digest(self.kind(), self.record())? != *self.response_digest() {
            return Err(AdmissionOperationError::CaptureResponseDigestMismatch);
        }
        if !self.record().matches_request(request) {
            return Err(AdmissionOperationError::CaptureBindingMismatch);
        }
        if !self.record().quota_effect_matches_request(request) {
            return Err(AdmissionOperationError::CaptureQuotaMismatch);
        }
        Ok(())
    }

    fn kind(&self) -> AdmissionCaptureResponseKind {
        match self {
            Self::Captured(_) => AdmissionCaptureResponseKind::Captured,
            Self::AlreadyCaptured(_) => AdmissionCaptureResponseKind::AlreadyCaptured,
            Self::Denied(_) => AdmissionCaptureResponseKind::Denied,
        }
    }

    fn response(&self) -> &AdmissionCaptureAuthorityResponseV1 {
        match self {
            Self::Captured(response) | Self::AlreadyCaptured(response) | Self::Denied(response) => {
                response
            }
        }
    }

    fn record(&self) -> &AdmissionCaptureRecordV1 {
        self.response().record()
    }

    fn response_digest(&self) -> &AdmissionDigest {
        self.response().response_digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionCaptureError {
    #[error("combined admission capture is unavailable: {0}")]
    Unavailable(String),
    #[error("combined admission capture was fenced")]
    Fenced,
    #[error("combined admission capture durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
    #[error("combined admission capture invariant failed: {0}")]
    Invariant(String),
    #[error(transparent)]
    Operation(#[from] AdmissionOperationError),
}

/// Untrusted capture transport. Calling this trait never confers authority on
/// its response; use the qualified verifier functions below.
pub trait AdmissionCaptureAuthority: Send + Sync {
    fn capture(
        &self,
        request: &AdmissionCaptureRequestV1,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError>;

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionCaptureRecordV1>, AdmissionCaptureError>;
}

trait QualifiedAdmissionCaptureAdapter: AdmissionCaptureAuthority {
    fn trusted_time_unix_ms(&self) -> Result<u64, AdmissionCaptureError>;

    fn verifies_global_commit_link(
        &self,
        binding: &CaptureCommitVerification<'_>,
    ) -> Result<bool, AdmissionCaptureError>;
}

struct CaptureCommitVerification<'a> {
    mutation_kind: &'static str,
    operation_id: &'a AdmissionOperationId,
    event_id: &'a AdmissionIdentifier,
    response_digest: &'a AdmissionDigest,
    previous_sequence: u64,
    previous_digest: &'a AdmissionDigest,
    sequence: u64,
    digest: &'a AdmissionDigest,
}

impl CaptureCommitVerification<'_> {
    fn is_well_formed(&self) -> bool {
        self.mutation_kind == ADMISSION_CAPTURE_MUTATION_KIND
            && !self.operation_id.as_str().is_empty()
            && !self.event_id.as_str().is_empty()
            && !self.response_digest.as_str().is_empty()
            && self.previous_sequence <= I_JSON_MAX_SAFE_INTEGER
            && self.previous_sequence.checked_add(1) == Some(self.sequence)
            && self.previous_digest != self.digest
    }
}

pub struct QualifiedAdmissionCaptureVerifier {
    authority: Arc<dyn QualifiedAdmissionCaptureAdapter>,
    authority_binding: BudgetEventAuthority,
    store_fence: StoreMutationFence,
    qualification_digest: AdmissionDigest,
}

impl fmt::Debug for QualifiedAdmissionCaptureVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedAdmissionCaptureVerifier")
            .field("authority_binding", &self.authority_binding)
            .field("store_fence", &self.store_fence)
            .field("qualification_digest", &self.qualification_digest)
            .finish_non_exhaustive()
    }
}

impl QualifiedAdmissionCaptureVerifier {
    #[must_use]
    pub fn qualification_digest(&self) -> &AdmissionDigest {
        &self.qualification_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedAdmissionCaptureDecision {
    decision: AdmissionCaptureDecision,
    qualification_digest: AdmissionDigest,
    verified_at_unix_ms: u64,
    replayed: bool,
}

impl QualifiedAdmissionCaptureDecision {
    #[must_use]
    pub fn record(&self) -> &AdmissionCaptureRecordV1 {
        self.decision.record()
    }

    #[must_use]
    pub fn response_digest(&self) -> &AdmissionDigest {
        self.decision.response_digest()
    }

    #[must_use]
    pub fn qualification_digest(&self) -> &AdmissionDigest {
        &self.qualification_digest
    }

    #[must_use]
    pub fn disposition(&self) -> &AdmissionCaptureDisposition {
        &self.decision.record().disposition
    }

    #[must_use]
    pub fn was_replay(&self) -> bool {
        self.replayed
    }

    #[must_use]
    pub fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }
}

pub fn capture_with_qualified_verifier(
    operation: &AdmissionOperationV1,
    request: &AdmissionCaptureRequestV1,
    verifier: &QualifiedAdmissionCaptureVerifier,
) -> Result<QualifiedAdmissionCaptureDecision, AdmissionCaptureError> {
    validate_qualified_request(operation, request, verifier)?;
    let decision = verifier.authority.capture(request)?;
    let replayed = matches!(decision, AdmissionCaptureDecision::AlreadyCaptured(_));
    qualify_capture_decision(request, verifier, decision, replayed)
}

pub fn lookup_capture_with_qualified_verifier(
    operation: &AdmissionOperationV1,
    request: &AdmissionCaptureRequestV1,
    verifier: &QualifiedAdmissionCaptureVerifier,
) -> Result<Option<QualifiedAdmissionCaptureDecision>, AdmissionCaptureError> {
    validate_qualified_request(operation, request, verifier)?;
    let Some(record) = verifier
        .authority
        .lookup_by_operation(&request.operation_id)?
    else {
        return Ok(None);
    };
    let decision = match record.disposition {
        AdmissionCaptureDisposition::Captured => {
            AdmissionCaptureDecision::untrusted_already_captured(record)?
        }
        AdmissionCaptureDisposition::Denied(_) => {
            AdmissionCaptureDecision::untrusted_denied(record)?
        }
    };
    qualify_capture_decision(request, verifier, decision, true).map(Some)
}

fn validate_qualified_request(
    operation: &AdmissionOperationV1,
    request: &AdmissionCaptureRequestV1,
    verifier: &QualifiedAdmissionCaptureVerifier,
) -> Result<(), AdmissionCaptureError> {
    request.validate_against(operation)?;
    if request.authority != verifier.authority_binding
        || request.store_fence != verifier.store_fence
    {
        return Err(AdmissionOperationError::CaptureAuthorityMismatch.into());
    }
    Ok(())
}

fn qualify_capture_decision(
    request: &AdmissionCaptureRequestV1,
    verifier: &QualifiedAdmissionCaptureVerifier,
    decision: AdmissionCaptureDecision,
    replayed: bool,
) -> Result<QualifiedAdmissionCaptureDecision, AdmissionCaptureError> {
    decision.validate_for(request)?;
    let record = decision.record();
    let verified_at_unix_ms = verifier.authority.trusted_time_unix_ms()?;
    validate_positive_ijson("capture_verified_at_unix_ms", verified_at_unix_ms)?;
    if record.authority_time_unix_ms > verified_at_unix_ms {
        return Err(AdmissionOperationError::CaptureAuthorityTimeMismatch.into());
    }
    let commit = &record.combined_commit;
    let commit_verification = CaptureCommitVerification {
        mutation_kind: ADMISSION_CAPTURE_MUTATION_KIND,
        operation_id: &record.operation_id,
        event_id: &record.event_id,
        response_digest: decision.response_digest(),
        previous_sequence: commit.previous_global_commit_sequence,
        previous_digest: &commit.previous_global_commit_digest,
        sequence: commit.global_commit_sequence,
        digest: &commit.global_commit_digest,
    };
    if !commit_verification.is_well_formed()
        || !verifier
            .authority
            .verifies_global_commit_link(&commit_verification)?
    {
        return Err(AdmissionOperationError::CaptureCommitMismatch.into());
    }
    Ok(QualifiedAdmissionCaptureDecision {
        decision,
        qualification_digest: verifier.qualification_digest.clone(),
        verified_at_unix_ms,
        replayed,
    })
}

fn validate_disposition(
    kind: AdmissionCaptureResponseKind,
    disposition: &AdmissionCaptureDisposition,
) -> Result<(), AdmissionOperationError> {
    let valid = match kind {
        AdmissionCaptureResponseKind::Captured | AdmissionCaptureResponseKind::AlreadyCaptured => {
            *disposition == AdmissionCaptureDisposition::Captured
        }
        AdmissionCaptureResponseKind::Denied => {
            matches!(disposition, AdmissionCaptureDisposition::Denied(_))
        }
    };
    if valid {
        Ok(())
    } else {
        Err(AdmissionOperationError::CaptureDispositionMismatch)
    }
}

fn validate_authority_binding(
    authority: &BudgetEventAuthority,
    store_fence: &StoreMutationFence,
) -> Result<(), AdmissionOperationError> {
    authority
        .validate()
        .map_err(|_| AdmissionOperationError::CaptureAuthorityMismatch)?;
    validate_positive_ijson("capture_authority_epoch", authority.lease_epoch)?;
    validate_store_fence(store_fence)?;
    if authority.authority_id != store_fence.store_uuid
        || authority.lease_id != store_fence.lease_id
        || authority.lease_epoch != store_fence.owner_epoch
    {
        return Err(AdmissionOperationError::CaptureAuthorityMismatch);
    }
    Ok(())
}

fn validate_global_predecessor(
    sequence: u64,
    digest: &AdmissionDigest,
) -> Result<(), AdmissionOperationError> {
    if sequence > I_JSON_MAX_SAFE_INTEGER
        || (sequence == 0) != (digest.as_str() == ADMISSION_CAPTURE_GLOBAL_GENESIS_DIGEST)
    {
        return Err(AdmissionOperationError::CaptureCommitMismatch);
    }
    Ok(())
}

fn validate_quota_usages(
    usages: &[BudgetInvocationQuotaUsage],
    capability_id: &AdmissionIdentifier,
    grant_index: u32,
) -> Result<(), AdmissionOperationError> {
    if usages.len() > MAX_INVOCATION_QUOTAS_PER_ADMISSION
        || usages
            .windows(2)
            .any(|pair| pair[0].quota.key >= pair[1].quota.key)
    {
        return Err(AdmissionOperationError::CaptureQuotaMismatch);
    }
    for usage in usages {
        usage
            .validate()
            .map_err(|_| AdmissionOperationError::CaptureQuotaMismatch)?;
        AdmissionIdentifier::try_new("capture_quota_owner_id", usage.quota.key.owner_id.clone())
            .map_err(|_| AdmissionOperationError::CaptureQuotaMismatch)?;
        if usage.quota.key.profile == BudgetQuotaProfile::GrantInvocation
            && (usage.quota.key.owner_id != capability_id.as_str()
                || usage.quota.key.grant_index != Some(grant_index))
        {
            return Err(AdmissionOperationError::CaptureQuotaMismatch);
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct CaptureQuotaUsageBody<'a> {
    profile: &'static str,
    owner_id: &'a str,
    grant_index: Option<u32>,
    max_invocations: u32,
    reserved_invocations: u32,
    captured_invocations: u32,
}

#[derive(Serialize)]
struct CaptureResponseBody<'a> {
    response_kind: &'static str,
    operation_id: &'a AdmissionOperationId,
    operation_version: u64,
    coordinator_lease_epoch: u64,
    capability_id: &'a AdmissionIdentifier,
    grant_index: u32,
    hold_id: &'a AdmissionIdentifier,
    event_id: &'a AdmissionIdentifier,
    revocation_ids: &'a [String],
    revocation_digest: &'a str,
    authorization_artifact_digests: &'a [AdmissionDigest],
    invocation_quota_usages: Vec<CaptureQuotaUsageBody<'a>>,
    authorization_expires_at_unix_ms: u64,
    authority_time_unix_ms: u64,
    authority_id: &'a str,
    authority_lease_id: &'a str,
    authority_epoch: u64,
    guarantee_level: &'static str,
    previous_global_commit_sequence: u64,
    previous_global_commit_digest: &'a AdmissionDigest,
    global_commit_sequence: u64,
    global_commit_digest: &'a AdmissionDigest,
    store_fence: &'a StoreMutationFence,
    disposition: &'static str,
    denial_reason: Option<&'static str>,
}

fn capture_response_digest(
    kind: AdmissionCaptureResponseKind,
    record: &AdmissionCaptureRecordV1,
) -> Result<AdmissionDigest, AdmissionOperationError> {
    let invocation_quota_usages = record
        .invocation_quota_usages
        .iter()
        .map(|usage| CaptureQuotaUsageBody {
            profile: usage.quota.key.profile.as_str(),
            owner_id: &usage.quota.key.owner_id,
            grant_index: usage.quota.key.grant_index,
            max_invocations: usage.quota.max_invocations,
            reserved_invocations: usage.reserved_invocations,
            captured_invocations: usage.captured_invocations,
        })
        .collect();
    let (disposition, denial_reason) = match record.disposition {
        AdmissionCaptureDisposition::Captured => ("captured", None),
        AdmissionCaptureDisposition::Denied(reason) => ("denied", Some(reason.as_str())),
    };
    let commit = &record.combined_commit;
    let canonical = canonical_json_bytes(&CaptureResponseBody {
        response_kind: kind.as_str(),
        operation_id: &record.operation_id,
        operation_version: record.operation_version,
        coordinator_lease_epoch: record.coordinator_lease_epoch,
        capability_id: &record.capability_id,
        grant_index: record.grant_index,
        hold_id: &record.hold_id,
        event_id: &record.event_id,
        revocation_ids: record.revocation_set.ids(),
        revocation_digest: record.revocation_set.digest(),
        authorization_artifact_digests: &record.authorization_artifact_digests,
        invocation_quota_usages,
        authorization_expires_at_unix_ms: record.authorization_expires_at_unix_ms,
        authority_time_unix_ms: record.authority_time_unix_ms,
        authority_id: &commit.authority.authority_id,
        authority_lease_id: &commit.authority.lease_id,
        authority_epoch: commit.authority.lease_epoch,
        guarantee_level: commit.guarantee_level.as_str(),
        previous_global_commit_sequence: commit.previous_global_commit_sequence,
        previous_global_commit_digest: &commit.previous_global_commit_digest,
        global_commit_sequence: commit.global_commit_sequence,
        global_commit_digest: &commit.global_commit_digest,
        store_fence: &commit.store_fence,
        disposition,
        denial_reason,
    })
    .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut bytes = Vec::with_capacity(ADMISSION_CAPTURE_RESPONSE_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_CAPTURE_RESPONSE_DOMAIN);
    bytes.extend_from_slice(&canonical);
    AdmissionDigest::try_new("capture_response_digest", sha256_hex(&bytes))
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct TestCaptureQualification {
    pub(crate) authority: BudgetEventAuthority,
    pub(crate) store_fence: StoreMutationFence,
    pub(crate) verified_at_unix_ms: u64,
    pub(crate) operation_id: AdmissionOperationId,
    pub(crate) event_id: AdmissionIdentifier,
    pub(crate) response_digest: AdmissionDigest,
    pub(crate) previous_global_commit_sequence: u64,
    pub(crate) previous_global_commit_digest: AdmissionDigest,
    pub(crate) global_commit_sequence: u64,
    pub(crate) global_commit_digest: AdmissionDigest,
}

#[cfg(test)]
struct TestQualifiedAdmissionCaptureAdapter {
    authority: Arc<dyn AdmissionCaptureAuthority>,
    qualification: TestCaptureQualification,
}

#[cfg(test)]
impl AdmissionCaptureAuthority for TestQualifiedAdmissionCaptureAdapter {
    fn capture(
        &self,
        request: &AdmissionCaptureRequestV1,
    ) -> Result<AdmissionCaptureDecision, AdmissionCaptureError> {
        self.authority.capture(request)
    }

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<AdmissionCaptureRecordV1>, AdmissionCaptureError> {
        self.authority.lookup_by_operation(operation_id)
    }
}

#[cfg(test)]
impl QualifiedAdmissionCaptureAdapter for TestQualifiedAdmissionCaptureAdapter {
    fn trusted_time_unix_ms(&self) -> Result<u64, AdmissionCaptureError> {
        Ok(self.qualification.verified_at_unix_ms)
    }

    fn verifies_global_commit_link(
        &self,
        binding: &CaptureCommitVerification<'_>,
    ) -> Result<bool, AdmissionCaptureError> {
        Ok(binding.mutation_kind == ADMISSION_CAPTURE_MUTATION_KIND
            && binding.operation_id == &self.qualification.operation_id
            && binding.event_id == &self.qualification.event_id
            && binding.response_digest == &self.qualification.response_digest
            && binding.previous_sequence == self.qualification.previous_global_commit_sequence
            && binding.previous_digest == &self.qualification.previous_global_commit_digest
            && binding.sequence == self.qualification.global_commit_sequence
            && binding.digest == &self.qualification.global_commit_digest)
    }
}

#[cfg(test)]
pub(crate) fn qualify_capture_authority_for_test(
    authority: Arc<dyn AdmissionCaptureAuthority>,
    qualification: TestCaptureQualification,
) -> Result<QualifiedAdmissionCaptureVerifier, AdmissionOperationError> {
    validate_authority_binding(&qualification.authority, &qualification.store_fence)?;
    validate_positive_ijson(
        "capture_verified_at_unix_ms",
        qualification.verified_at_unix_ms,
    )?;
    validate_global_predecessor(
        qualification.previous_global_commit_sequence,
        &qualification.previous_global_commit_digest,
    )?;
    if qualification.global_commit_sequence
        != qualification
            .previous_global_commit_sequence
            .checked_add(1)
            .ok_or(AdmissionOperationError::CaptureCommitMismatch)?
        || qualification.global_commit_digest == qualification.previous_global_commit_digest
    {
        return Err(AdmissionOperationError::CaptureCommitMismatch);
    }
    #[derive(Serialize)]
    struct QualificationBody<'a> {
        authority_id: &'a str,
        authority_lease_id: &'a str,
        authority_epoch: u64,
        store_fence: &'a StoreMutationFence,
        verifier_id: &'static str,
        rollback_anchor_id: &'static str,
        trusted_clock_id: &'static str,
    }
    let canonical = canonical_json_bytes(&QualificationBody {
        authority_id: &qualification.authority.authority_id,
        authority_lease_id: &qualification.authority.lease_id,
        authority_epoch: qualification.authority.lease_epoch,
        store_fence: &qualification.store_fence,
        verifier_id: "test-combined-capture-verifier",
        rollback_anchor_id: "test-global-authority-anchor",
        trusted_clock_id: "test-authority-clock",
    })
    .map_err(|error| AdmissionOperationError::CanonicalJson(error.to_string()))?;
    let mut bytes =
        Vec::with_capacity(ADMISSION_CAPTURE_QUALIFICATION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(ADMISSION_CAPTURE_QUALIFICATION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(QualifiedAdmissionCaptureVerifier {
        authority: Arc::new(TestQualifiedAdmissionCaptureAdapter {
            authority,
            qualification: qualification.clone(),
        }),
        authority_binding: qualification.authority,
        store_fence: qualification.store_fence,
        qualification_digest: AdmissionDigest::try_new(
            "capture_qualification_digest",
            sha256_hex(&bytes),
        )?,
    })
}

#[cfg(test)]
#[path = "capture_tests.rs"]
mod tests;
