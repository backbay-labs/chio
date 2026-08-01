//! Durable tool-return and post-return evaluation contracts.

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::sha256_hex;
use chio_core::receipt::metadata::GuardEvidence;
use chio_core_types::{provider_attempt::ProviderAttemptBindingV1, StoreMutationFence};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::admission_operation::{
    AdmissionAttachment, AdmissionDigest, AdmissionDispatchCommitBindingV1, AdmissionDispatchState,
    AdmissionIdentifier, AdmissionOperationCommand, AdmissionOperationId, AdmissionOperationState,
    AdmissionOperationV1, AdmissionProjectionContext, AdmissionRecoveryLease,
};
use crate::dispatch_status::{
    DispatchStatusQuery, QualifiedDispatchStatusProvider, VerifiedProviderNotAccepted,
};
use crate::runtime::ToolCallRequest;

pub const RAW_INVOCATION_OUTCOME_SCHEMA: &str = "chio.raw-invocation-outcome.v1";
pub const RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA: &str =
    "chio.raw-invocation-outcome-with-request.v1";
pub const TOOL_OUTCOME_SCHEMA: &str = "chio.tool-outcome.v1";
pub const POST_RETURN_EVALUATION_SCHEMA: &str = "chio.post-return-evaluation.v1";
pub const POST_RETURN_EXACT_INPUTS_SCHEMA: &str = "chio.post-return-exact-inputs.v1";
pub const MONETARY_RELEASE_EVIDENCE_SCHEMA: &str = "chio.monetary-release-evidence.v1";

pub const MAX_RAW_INVOCATION_OUTCOME_BYTES: usize = 257 * 1024 * 1024;
pub const MAX_RESOLVED_OUTPUT_BYTES: usize = 257 * 1024 * 1024;
pub const MAX_FROZEN_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_EVIDENCE_ARTIFACT_BYTES: usize = 256 * 1024;
pub const MAX_MONETARY_RELEASE_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_STREAM_CHUNKS: usize = 1_048_576;
pub const MAX_EVALUATION_STEPS: usize = 128;
pub const MAX_RECEIPT_GUARD_EVIDENCE: usize = 1_024;

const MAX_REASON_BYTES: usize = 1024;
const I_JSON_MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolOutcomeError {
    #[error("canonical JSON failed: {0}")]
    Canonical(String),
    #[error("invalid field: {0}")]
    Invalid(&'static str),
    #[error("{field} has size {actual}; maximum is {maximum}")]
    TooLarge {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("binding mismatch: {0}")]
    Binding(&'static str),
    #[error("qualified release authority unavailable: {0}")]
    ReleaseAuthorityUnavailable(&'static str),
    #[error("CAS conflict: expected version {expected}, found {actual}")]
    Cas { expected: u64, actual: u64 },
    #[error("transition {transition} is illegal from {state}")]
    Transition {
        state: &'static str,
        transition: &'static str,
    },
    #[error("version overflow: {0}")]
    Overflow(&'static str),
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, ToolOutcomeError> {
    canonical_json_bytes(value).map_err(|error| ToolOutcomeError::Canonical(error.to_string()))
}

fn bounded<T: Serialize>(
    field: &'static str,
    value: &T,
    maximum: usize,
) -> Result<Vec<u8>, ToolOutcomeError> {
    let bytes = canonical(value)?;
    if bytes.len() > maximum {
        return Err(ToolOutcomeError::TooLarge {
            field,
            actual: bytes.len(),
            maximum,
        });
    }
    Ok(bytes)
}

fn domain_digest<T: Serialize>(
    domain: &'static str,
    value: &T,
) -> Result<AdmissionDigest, ToolOutcomeError> {
    #[derive(Serialize)]
    struct Bound<'a, T> {
        domain: &'static str,
        value: &'a T,
    }
    digest_bytes("derived_digest", &canonical(&Bound { domain, value })?)
}

fn digest_bytes(field: &'static str, bytes: &[u8]) -> Result<AdmissionDigest, ToolOutcomeError> {
    AdmissionDigest::try_new(field, sha256_hex(bytes))
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))
}

fn positive(field: &'static str, value: u64) -> Result<(), ToolOutcomeError> {
    if value == 0 || value > I_JSON_MAX_SAFE_INTEGER {
        return Err(ToolOutcomeError::Invalid(field));
    }
    Ok(())
}

fn validate_store_fence(fence: &StoreMutationFence) -> Result<(), ToolOutcomeError> {
    positive("store_fence.owner_epoch", fence.owner_epoch)?;
    AdmissionIdentifier::try_new("store_fence.store_uuid", fence.store_uuid.clone())
        .and_then(|_| AdmissionIdentifier::try_new("store_fence.lease_id", fence.lease_id.clone()))
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    Ok(())
}

fn validate_successor_fence(
    historical: &StoreMutationFence,
    current: &StoreMutationFence,
) -> Result<(), ToolOutcomeError> {
    validate_store_fence(historical)?;
    validate_store_fence(current)?;
    if historical.store_uuid != current.store_uuid
        || current.owner_epoch < historical.owner_epoch
        || (current.owner_epoch == historical.owner_epoch && current != historical)
    {
        return Err(ToolOutcomeError::Binding("store_fence.lineage"));
    }
    Ok(())
}

fn amount(value: &MonetaryAmount) -> Result<(), ToolOutcomeError> {
    if value.units > I_JSON_MAX_SAFE_INTEGER
        || value.currency.len() != 3
        || !value.currency.bytes().all(|byte| byte.is_ascii_uppercase())
    {
        return Err(ToolOutcomeError::Invalid("monetary_amount"));
    }
    Ok(())
}

fn validate_committed_operation(
    operation: &AdmissionOperationV1,
    commit: &AdmissionDispatchCommitBindingV1,
) -> Result<(), ToolOutcomeError> {
    validate_retained_dispatch_commit(operation, commit)?;
    if !matches!(
        operation.dispatch_state(),
        AdmissionDispatchState::Committed | AdmissionDispatchState::Finalizing
    ) {
        return Err(ToolOutcomeError::Binding(
            "admission_operation.outcome_recording_state",
        ));
    }
    Ok(())
}

fn validate_registered_provider_attempt(
    operation: &AdmissionOperationV1,
    provider_attempt: &ProviderAttemptBindingV1,
) -> Result<(), ToolOutcomeError> {
    provider_attempt
        .validate()
        .map_err(|_| ToolOutcomeError::Binding("provider_attempt.shape"))?;
    if operation.provider_attempt() != Some(provider_attempt)
        || operation
            .dispatch_commit()
            .and_then(|commit| commit.provider_attempt.as_ref())
            != Some(provider_attempt)
    {
        return Err(ToolOutcomeError::Binding(
            "provider_attempt.registered_attempt",
        ));
    }
    Ok(())
}

fn validate_retained_dispatch_commit(
    operation: &AdmissionOperationV1,
    commit: &AdmissionDispatchCommitBindingV1,
) -> Result<(), ToolOutcomeError> {
    operation
        .validate()
        .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
    if operation.dispatch_commit() != Some(commit)
        || !matches!(
            operation.dispatch_state(),
            AdmissionDispatchState::Committed
                | AdmissionDispatchState::Finalizing
                | AdmissionDispatchState::Terminal
        )
        || commit.committed_version == 0
        || commit.store_fence.owner_epoch == 0
    {
        return Err(ToolOutcomeError::Binding(
            "admission_operation.dispatch_commit",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentAddressedBlobRefV1 {
    digest: AdmissionDigest,
    uri: String,
}

impl ContentAddressedBlobRefV1 {
    fn new(digest: AdmissionDigest) -> Self {
        Self {
            uri: format!("sha256:{}", digest.as_str()),
            digest,
        }
    }

    pub fn digest(&self) -> &AdmissionDigest {
        &self.digest
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        if self.uri != format!("sha256:{}", self.digest.as_str()) {
            return Err(ToolOutcomeError::Binding("blob_ref.uri"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvocationOutputV1 {
    Value { value: Value },
    CompleteStream { chunks: Vec<Value> },
    IncompleteStream { chunks: Vec<Value>, reason: String },
}

impl InvocationOutputV1 {
    fn validate(&self) -> Result<(), ToolOutcomeError> {
        let (chunks, reason) = match self {
            Self::Value { .. } => return Ok(()),
            Self::CompleteStream { chunks } => (chunks, None),
            Self::IncompleteStream { chunks, reason } => (chunks, Some(reason)),
        };
        if chunks.len() > MAX_STREAM_CHUNKS {
            return Err(ToolOutcomeError::TooLarge {
                field: "output.chunks",
                actual: chunks.len(),
                maximum: MAX_STREAM_CHUNKS,
            });
        }
        if reason.is_some_and(|value| {
            value.is_empty()
                || value.len() > MAX_REASON_BYTES
                || value.trim() != value
                || value.chars().any(char::is_control)
        }) {
            return Err(ToolOutcomeError::Invalid("output.reason"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationStreamLimitsV1 {
    pub max_total_bytes: u64,
    pub max_chunks: u64,
    pub max_duration_secs: u64,
}

impl InvocationStreamLimitsV1 {
    pub(crate) fn new(
        max_total_bytes: u64,
        max_chunks: u64,
        max_duration_secs: u64,
    ) -> Result<Self, ToolOutcomeError> {
        let limits = Self {
            max_total_bytes,
            max_chunks,
            max_duration_secs,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        if self.max_total_bytes > I_JSON_MAX_SAFE_INTEGER
            || self.max_chunks > I_JSON_MAX_SAFE_INTEGER
            || self.max_duration_secs > I_JSON_MAX_SAFE_INTEGER
        {
            return Err(ToolOutcomeError::Invalid("raw.stream_limits"));
        }
        Ok(())
    }
}

/// The only canonical representation of a returned invocation.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RawInvocationOutcomeV1 {
    schema: &'static str,
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    dispatch_operation_version: u64,
    dispatch_fence: u64,
    tool_server: AdmissionIdentifier,
    tool_name: AdmissionIdentifier,
    provider_attempt: ProviderAttemptBindingV1,
    transport_terminal_evidence_digest: AdmissionDigest,
    matched_grant_index: u64,
    elapsed_millis: u64,
    stream_limits: InvocationStreamLimitsV1,
    output: InvocationOutputV1,
    reported_cost: Option<MonetaryAmount>,
    receipt_metadata_snapshot: Option<Value>,
    pre_invocation_guard_evidence: Vec<GuardEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_canonical_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedRawInvocationOutcomeV1 {
    pub schema: String,
    pub operation_id: AdmissionOperationId,
    pub request_id: AdmissionIdentifier,
    pub dispatch_operation_version: u64,
    pub dispatch_fence: u64,
    pub tool_server: AdmissionIdentifier,
    pub tool_name: AdmissionIdentifier,
    pub provider_attempt: ProviderAttemptBindingV1,
    pub transport_terminal_evidence_digest: AdmissionDigest,
    pub matched_grant_index: u64,
    pub elapsed_millis: u64,
    pub stream_limits: InvocationStreamLimitsV1,
    pub output: InvocationOutputV1,
    pub reported_cost: Option<MonetaryAmount>,
    pub receipt_metadata_snapshot: Option<Value>,
    pub pre_invocation_guard_evidence: Vec<GuardEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_json: Option<String>,
}

impl RawInvocationOutcomeV1 {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_committed_dispatch(
        operation: &AdmissionOperationV1,
        commit: &AdmissionDispatchCommitBindingV1,
        tool_server: AdmissionIdentifier,
        tool_name: AdmissionIdentifier,
        provider_attempt: ProviderAttemptBindingV1,
        transport_terminal_evidence_digest: AdmissionDigest,
        matched_grant_index: u64,
        elapsed_millis: u64,
        stream_limits: InvocationStreamLimitsV1,
        output: InvocationOutputV1,
        reported_cost: Option<MonetaryAmount>,
        receipt_metadata_snapshot: Option<Value>,
        pre_invocation_guard_evidence: Vec<GuardEvidence>,
    ) -> Result<Self, ToolOutcomeError> {
        Self::from_committed_dispatch_parts(
            RAW_INVOCATION_OUTCOME_SCHEMA,
            operation,
            commit,
            tool_server,
            tool_name,
            provider_attempt,
            transport_terminal_evidence_digest,
            matched_grant_index,
            elapsed_millis,
            stream_limits,
            output,
            reported_cost,
            receipt_metadata_snapshot,
            pre_invocation_guard_evidence,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_committed_dispatch_with_request(
        operation: &AdmissionOperationV1,
        commit: &AdmissionDispatchCommitBindingV1,
        tool_server: AdmissionIdentifier,
        tool_name: AdmissionIdentifier,
        provider_attempt: ProviderAttemptBindingV1,
        transport_terminal_evidence_digest: AdmissionDigest,
        matched_grant_index: u64,
        elapsed_millis: u64,
        stream_limits: InvocationStreamLimitsV1,
        output: InvocationOutputV1,
        reported_cost: Option<MonetaryAmount>,
        receipt_metadata_snapshot: Option<Value>,
        pre_invocation_guard_evidence: Vec<GuardEvidence>,
        request: &ToolCallRequest,
    ) -> Result<Self, ToolOutcomeError> {
        let request_canonical_json = String::from_utf8(canonical(request)?)
            .map_err(|_| ToolOutcomeError::Invalid("raw.request_canonical_json"))?;
        Self::from_committed_dispatch_parts(
            RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA,
            operation,
            commit,
            tool_server,
            tool_name,
            provider_attempt,
            transport_terminal_evidence_digest,
            matched_grant_index,
            elapsed_millis,
            stream_limits,
            output,
            reported_cost,
            receipt_metadata_snapshot,
            pre_invocation_guard_evidence,
            Some(request_canonical_json),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_committed_dispatch_parts(
        schema: &'static str,
        operation: &AdmissionOperationV1,
        commit: &AdmissionDispatchCommitBindingV1,
        tool_server: AdmissionIdentifier,
        tool_name: AdmissionIdentifier,
        provider_attempt: ProviderAttemptBindingV1,
        transport_terminal_evidence_digest: AdmissionDigest,
        matched_grant_index: u64,
        elapsed_millis: u64,
        stream_limits: InvocationStreamLimitsV1,
        output: InvocationOutputV1,
        reported_cost: Option<MonetaryAmount>,
        receipt_metadata_snapshot: Option<Value>,
        pre_invocation_guard_evidence: Vec<GuardEvidence>,
        request_canonical_json: Option<String>,
    ) -> Result<Self, ToolOutcomeError> {
        validate_committed_operation(operation, commit)?;
        validate_registered_provider_attempt(operation, &provider_attempt)?;
        let raw = Self {
            schema,
            operation_id: operation.binding().operation_id().clone(),
            request_id: operation.replay_key().request_id,
            dispatch_operation_version: commit.committed_version,
            dispatch_fence: commit.store_fence.owner_epoch,
            tool_server,
            tool_name,
            provider_attempt,
            transport_terminal_evidence_digest,
            matched_grant_index,
            elapsed_millis,
            stream_limits,
            output,
            reported_cost,
            receipt_metadata_snapshot,
            pre_invocation_guard_evidence,
            request_canonical_json,
        };
        raw.canonical_blob()?;
        Ok(raw)
    }

    pub fn canonical_blob(&self) -> Result<CanonicalInvocationBlobV1, ToolOutcomeError> {
        self.canonical_blob_bounded(MAX_RAW_INVOCATION_OUTCOME_BYTES)
    }

    pub fn to_persisted(&self) -> PersistedRawInvocationOutcomeV1 {
        PersistedRawInvocationOutcomeV1 {
            schema: self.schema.to_owned(),
            operation_id: self.operation_id.clone(),
            request_id: self.request_id.clone(),
            dispatch_operation_version: self.dispatch_operation_version,
            dispatch_fence: self.dispatch_fence,
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            provider_attempt: self.provider_attempt.clone(),
            transport_terminal_evidence_digest: self.transport_terminal_evidence_digest.clone(),
            matched_grant_index: self.matched_grant_index,
            elapsed_millis: self.elapsed_millis,
            stream_limits: self.stream_limits,
            output: self.output.clone(),
            reported_cost: self.reported_cost.clone(),
            receipt_metadata_snapshot: self.receipt_metadata_snapshot.clone(),
            pre_invocation_guard_evidence: self.pre_invocation_guard_evidence.clone(),
            request_canonical_json: self.request_canonical_json.clone(),
        }
    }

    pub fn from_persisted(
        value: PersistedRawInvocationOutcomeV1,
    ) -> Result<Self, ToolOutcomeError> {
        let schema = match (
            value.schema.as_str(),
            value.request_canonical_json.is_some(),
        ) {
            (RAW_INVOCATION_OUTCOME_SCHEMA, false) => RAW_INVOCATION_OUTCOME_SCHEMA,
            (RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA, true) => {
                RAW_INVOCATION_OUTCOME_WITH_REQUEST_SCHEMA
            }
            _ => return Err(ToolOutcomeError::Invalid("raw.schema")),
        };
        if value.request_canonical_json.as_deref() == Some("") {
            return Err(ToolOutcomeError::Invalid("raw.schema"));
        }
        let raw = Self {
            schema,
            operation_id: value.operation_id,
            request_id: value.request_id,
            dispatch_operation_version: value.dispatch_operation_version,
            dispatch_fence: value.dispatch_fence,
            tool_server: value.tool_server,
            tool_name: value.tool_name,
            provider_attempt: value.provider_attempt,
            transport_terminal_evidence_digest: value.transport_terminal_evidence_digest,
            matched_grant_index: value.matched_grant_index,
            elapsed_millis: value.elapsed_millis,
            stream_limits: value.stream_limits,
            output: value.output,
            reported_cost: value.reported_cost,
            receipt_metadata_snapshot: value.receipt_metadata_snapshot,
            pre_invocation_guard_evidence: value.pre_invocation_guard_evidence,
            request_canonical_json: value.request_canonical_json,
        };
        raw.canonical_blob()?;
        Ok(raw)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ToolOutcomeError> {
        if bytes.len() > MAX_RAW_INVOCATION_OUTCOME_BYTES {
            return Err(ToolOutcomeError::TooLarge {
                field: "raw_invocation_outcome",
                actual: bytes.len(),
                maximum: MAX_RAW_INVOCATION_OUTCOME_BYTES,
            });
        }
        let persisted: PersistedRawInvocationOutcomeV1 = serde_json::from_slice(bytes)
            .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))?;
        let raw = Self::from_persisted(persisted)?;
        if raw.canonical_blob()?.bytes() != bytes {
            return Err(ToolOutcomeError::Invalid("raw.noncanonical_bytes"));
        }
        Ok(raw)
    }

    fn canonical_blob_bounded(
        &self,
        maximum: usize,
    ) -> Result<CanonicalInvocationBlobV1, ToolOutcomeError> {
        positive(
            "raw.dispatch_operation_version",
            self.dispatch_operation_version,
        )?;
        positive("raw.dispatch_fence", self.dispatch_fence)?;
        if self.matched_grant_index > I_JSON_MAX_SAFE_INTEGER {
            return Err(ToolOutcomeError::Invalid("raw.matched_grant_index"));
        }
        if self.elapsed_millis > I_JSON_MAX_SAFE_INTEGER {
            return Err(ToolOutcomeError::Invalid("raw.elapsed_millis"));
        }
        self.stream_limits.validate()?;
        self.output.validate()?;
        if let Some(cost) = &self.reported_cost {
            amount(cost)?;
        }
        if self.pre_invocation_guard_evidence.len() > MAX_RECEIPT_GUARD_EVIDENCE {
            return Err(ToolOutcomeError::TooLarge {
                field: "raw.pre_invocation_guard_evidence",
                actual: self.pre_invocation_guard_evidence.len(),
                maximum: MAX_RECEIPT_GUARD_EVIDENCE,
            });
        }
        if let Some(request_canonical_json) = &self.request_canonical_json {
            let request: ToolCallRequest = serde_json::from_str(request_canonical_json)
                .map_err(|_| ToolOutcomeError::Invalid("raw.request_canonical_json"))?;
            if canonical(&request)? != request_canonical_json.as_bytes()
                || request.request_id != self.request_id.as_str()
                || request.server_id != self.tool_server.as_str()
                || request.tool_name != self.tool_name.as_str()
            {
                return Err(ToolOutcomeError::Binding("raw.request"));
            }
        }
        CanonicalInvocationBlobV1::new(bounded("raw_invocation_outcome", self, maximum)?)
    }

    pub(crate) fn output(&self) -> &InvocationOutputV1 {
        &self.output
    }

    pub(crate) fn matched_grant_index(&self) -> Result<usize, ToolOutcomeError> {
        usize::try_from(self.matched_grant_index)
            .map_err(|_| ToolOutcomeError::Invalid("raw.matched_grant_index"))
    }

    pub(crate) fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }

    pub(crate) fn stream_limits(&self) -> InvocationStreamLimitsV1 {
        self.stream_limits
    }

    pub(crate) fn receipt_metadata_snapshot(&self) -> Option<&Value> {
        self.receipt_metadata_snapshot.as_ref()
    }

    pub(crate) fn reported_cost(&self) -> Option<&MonetaryAmount> {
        self.reported_cost.as_ref()
    }

    pub(crate) fn pre_invocation_guard_evidence(&self) -> &[GuardEvidence] {
        &self.pre_invocation_guard_evidence
    }

    pub(crate) fn recovery_request(&self) -> Result<Option<ToolCallRequest>, ToolOutcomeError> {
        self.request_canonical_json
            .as_deref()
            .map(|request| {
                serde_json::from_str(request)
                    .map_err(|_| ToolOutcomeError::Invalid("raw.request_canonical_json"))
            })
            .transpose()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalInvocationBlobV1 {
    blob_ref: ContentAddressedBlobRefV1,
    bytes: Vec<u8>,
}

impl CanonicalInvocationBlobV1 {
    fn new(bytes: Vec<u8>) -> Result<Self, ToolOutcomeError> {
        Ok(Self {
            blob_ref: ContentAddressedBlobRefV1::new(digest_bytes("blob_digest", &bytes)?),
            bytes,
        })
    }

    pub fn blob_ref(&self) -> &ContentAddressedBlobRefV1 {
        &self.blob_ref
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[allow(dead_code)]
    fn verify(&self, raw: &RawInvocationOutcomeV1) -> Result<(), ToolOutcomeError> {
        if *self != raw.canonical_blob()? {
            return Err(ToolOutcomeError::Binding("raw_invocation_blob"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalResolvedOutputBlobV1 {
    blob_ref: ContentAddressedBlobRefV1,
    bytes: Vec<u8>,
}

impl CanonicalResolvedOutputBlobV1 {
    pub fn from_signing_preimage(bytes: Vec<u8>) -> Result<Self, ToolOutcomeError> {
        if bytes.len() > MAX_RESOLVED_OUTPUT_BYTES {
            return Err(ToolOutcomeError::TooLarge {
                field: "resolved_output",
                actual: bytes.len(),
                maximum: MAX_RESOLVED_OUTPUT_BYTES,
            });
        }
        Ok(Self {
            blob_ref: ContentAddressedBlobRefV1::new(digest_bytes(
                "resolved_output_digest",
                &bytes,
            )?),
            bytes,
        })
    }

    pub fn blob_ref(&self) -> &ContentAddressedBlobRefV1 {
        &self.blob_ref
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn verify(
        &self,
        expected: &ContentAddressedBlobRefV1,
        expected_size_bytes: u64,
    ) -> Result<(), ToolOutcomeError> {
        if &self.blob_ref != expected
            || u64::try_from(self.bytes.len()).ok() != Some(expected_size_bytes)
        {
            return Err(ToolOutcomeError::Binding("resolved_output_blob"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SettlementDispositionV1 {
    Capture { amount: MonetaryAmount },
    ContractualZeroCharge { currency: String },
    NotApplicable,
}

impl SettlementDispositionV1 {
    fn validate(&self) -> Result<(), ToolOutcomeError> {
        match self {
            Self::Capture { amount: value } => amount(value),
            Self::ContractualZeroCharge { currency } => amount(&MonetaryAmount {
                units: 0,
                currency: currency.clone(),
            }),
            Self::NotApplicable => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResolvedToolOutcomeV1 {
    Returned,
    Resolved {
        evaluation_id: AdmissionDigest,
        resolved_output: ContentAddressedBlobRefV1,
        resolved_output_size_bytes: u64,
        terminal_dependency_root_digest: AdmissionDigest,
        post_guard_decision_digest: AdmissionDigest,
        pricing_verdict_digest: AdmissionDigest,
        settlement_disposition: SettlementDispositionV1,
    },
    Frozen {
        evaluation_id: AdmissionDigest,
        freeze_evidence_digest: AdmissionDigest,
    },
}

impl ResolvedToolOutcomeV1 {
    #[allow(dead_code)]
    fn name(&self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Resolved { .. } => "resolved",
            Self::Frozen { .. } => "frozen",
        }
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        match self {
            Self::Returned => Ok(()),
            Self::Resolved {
                resolved_output,
                resolved_output_size_bytes,
                settlement_disposition,
                ..
            } => {
                resolved_output.validate()?;
                if usize::try_from(*resolved_output_size_bytes)
                    .map_or(true, |size| size > MAX_RESOLVED_OUTPUT_BYTES)
                {
                    return Err(ToolOutcomeError::Invalid(
                        "outcome.resolved_output_size_bytes",
                    ));
                }
                settlement_disposition.validate()
            }
            Self::Frozen { .. } => Ok(()),
        }
    }
}

/// Valid records can only be built through insert-once or a CAS transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ToolOutcomeRecordV1 {
    schema: &'static str,
    outcome_id: AdmissionDigest,
    operation_id: AdmissionOperationId,
    request_id: AdmissionIdentifier,
    dispatch_operation_version: u64,
    dispatch_fence: u64,
    dispatch_commit: AdmissionDispatchCommitBindingV1,
    tool_server: AdmissionIdentifier,
    tool_name: AdmissionIdentifier,
    provider_attempt: ProviderAttemptBindingV1,
    transport_terminal_evidence_digest: AdmissionDigest,
    raw_output: ContentAddressedBlobRefV1,
    raw_output_size_bytes: u64,
    reported_cost: Option<MonetaryAmount>,
    disposition: ResolvedToolOutcomeV1,
    recording_fence: StoreMutationFence,
    recorded_at_unix_ms: u64,
    version: u64,
    lifecycle_digest: AdmissionDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedToolOutcomeRecordV1 {
    pub schema: String,
    pub outcome_id: AdmissionDigest,
    pub operation_id: AdmissionOperationId,
    pub request_id: AdmissionIdentifier,
    pub dispatch_operation_version: u64,
    pub dispatch_fence: u64,
    pub dispatch_commit: AdmissionDispatchCommitBindingV1,
    pub tool_server: AdmissionIdentifier,
    pub tool_name: AdmissionIdentifier,
    pub provider_attempt: ProviderAttemptBindingV1,
    pub transport_terminal_evidence_digest: AdmissionDigest,
    pub raw_output: ContentAddressedBlobRefV1,
    pub raw_output_size_bytes: u64,
    pub reported_cost: Option<MonetaryAmount>,
    pub disposition: ResolvedToolOutcomeV1,
    pub recording_fence: StoreMutationFence,
    pub recorded_at_unix_ms: u64,
    pub version: u64,
    pub lifecycle_digest: AdmissionDigest,
}

#[derive(Serialize)]
struct OutcomeIdentity<'a> {
    operation_id: &'a AdmissionOperationId,
    request_id: &'a AdmissionIdentifier,
    dispatch_operation_version: u64,
    dispatch_fence: u64,
    dispatch_commit: &'a AdmissionDispatchCommitBindingV1,
    tool_server: &'a AdmissionIdentifier,
    tool_name: &'a AdmissionIdentifier,
    provider_attempt: &'a ProviderAttemptBindingV1,
    transport_terminal_evidence_digest: &'a AdmissionDigest,
    raw_output: &'a ContentAddressedBlobRefV1,
    raw_output_size_bytes: u64,
    reported_cost: &'a Option<MonetaryAmount>,
}

#[derive(Serialize)]
struct OutcomeLifecycle<'a> {
    outcome_id: &'a AdmissionDigest,
    disposition: &'a ResolvedToolOutcomeV1,
    recording_fence: &'a StoreMutationFence,
    recorded_at_unix_ms: u64,
    version: u64,
}

fn outcome_lifecycle_digest(
    outcome_id: &AdmissionDigest,
    disposition: &ResolvedToolOutcomeV1,
    recording_fence: &StoreMutationFence,
    recorded_at_unix_ms: u64,
    version: u64,
) -> Result<AdmissionDigest, ToolOutcomeError> {
    domain_digest(
        "chio.tool-outcome.lifecycle.v1",
        &OutcomeLifecycle {
            outcome_id,
            disposition,
            recording_fence,
            recorded_at_unix_ms,
            version,
        },
    )
}

impl ToolOutcomeRecordV1 {
    pub fn to_persisted(&self) -> PersistedToolOutcomeRecordV1 {
        PersistedToolOutcomeRecordV1 {
            schema: self.schema.to_owned(),
            outcome_id: self.outcome_id.clone(),
            operation_id: self.operation_id.clone(),
            request_id: self.request_id.clone(),
            dispatch_operation_version: self.dispatch_operation_version,
            dispatch_fence: self.dispatch_fence,
            dispatch_commit: self.dispatch_commit.clone(),
            tool_server: self.tool_server.clone(),
            tool_name: self.tool_name.clone(),
            provider_attempt: self.provider_attempt.clone(),
            transport_terminal_evidence_digest: self.transport_terminal_evidence_digest.clone(),
            raw_output: self.raw_output.clone(),
            raw_output_size_bytes: self.raw_output_size_bytes,
            reported_cost: self.reported_cost.clone(),
            disposition: self.disposition.clone(),
            recording_fence: self.recording_fence.clone(),
            recorded_at_unix_ms: self.recorded_at_unix_ms,
            version: self.version,
            lifecycle_digest: self.lifecycle_digest.clone(),
        }
    }

    pub fn from_persisted(value: PersistedToolOutcomeRecordV1) -> Result<Self, ToolOutcomeError> {
        if value.schema != TOOL_OUTCOME_SCHEMA {
            return Err(ToolOutcomeError::Invalid("outcome.schema"));
        }
        let record = Self {
            schema: TOOL_OUTCOME_SCHEMA,
            outcome_id: value.outcome_id,
            operation_id: value.operation_id,
            request_id: value.request_id,
            dispatch_operation_version: value.dispatch_operation_version,
            dispatch_fence: value.dispatch_fence,
            dispatch_commit: value.dispatch_commit,
            tool_server: value.tool_server,
            tool_name: value.tool_name,
            provider_attempt: value.provider_attempt,
            transport_terminal_evidence_digest: value.transport_terminal_evidence_digest,
            raw_output: value.raw_output,
            raw_output_size_bytes: value.raw_output_size_bytes,
            reported_cost: value.reported_cost,
            disposition: value.disposition,
            recording_fence: value.recording_fence,
            recorded_at_unix_ms: value.recorded_at_unix_ms,
            version: value.version,
            lifecycle_digest: value.lifecycle_digest,
        };
        record.validate()?;
        Ok(record)
    }

    #[allow(dead_code)]
    pub(crate) fn record_tool_returned(
        operation: &AdmissionOperationV1,
        raw: &RawInvocationOutcomeV1,
        blob: &CanonicalInvocationBlobV1,
        recording_fence: StoreMutationFence,
        recorded_at_unix_ms: u64,
    ) -> Result<Self, ToolOutcomeError> {
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding("outcome.dispatch_commit"))?;
        validate_committed_operation(operation, commit)?;
        validate_successor_fence(&commit.store_fence, &recording_fence)?;
        positive("outcome.recorded_at", recorded_at_unix_ms)?;
        if raw.operation_id != *operation.binding().operation_id()
            || raw.request_id != operation.replay_key().request_id
            || raw.dispatch_operation_version != commit.committed_version
            || raw.dispatch_fence != commit.store_fence.owner_epoch
        {
            return Err(ToolOutcomeError::Binding("raw.admission_operation"));
        }
        validate_registered_provider_attempt(operation, &raw.provider_attempt)?;
        blob.verify(raw)?;
        let raw_output_size_bytes = u64::try_from(blob.bytes().len())
            .map_err(|_| ToolOutcomeError::Overflow("raw_output_size_bytes"))?;
        let identity = OutcomeIdentity {
            operation_id: &raw.operation_id,
            request_id: &raw.request_id,
            dispatch_operation_version: raw.dispatch_operation_version,
            dispatch_fence: raw.dispatch_fence,
            dispatch_commit: commit,
            tool_server: &raw.tool_server,
            tool_name: &raw.tool_name,
            provider_attempt: &raw.provider_attempt,
            transport_terminal_evidence_digest: &raw.transport_terminal_evidence_digest,
            raw_output: blob.blob_ref(),
            raw_output_size_bytes,
            reported_cost: &raw.reported_cost,
        };
        let outcome_id = domain_digest("chio.tool-outcome.identity.v1", &identity)?;
        let disposition = ResolvedToolOutcomeV1::Returned;
        let version = 1;
        let lifecycle_digest = outcome_lifecycle_digest(
            &outcome_id,
            &disposition,
            &recording_fence,
            recorded_at_unix_ms,
            version,
        )?;
        let record = Self {
            schema: TOOL_OUTCOME_SCHEMA,
            outcome_id,
            operation_id: raw.operation_id.clone(),
            request_id: raw.request_id.clone(),
            dispatch_operation_version: raw.dispatch_operation_version,
            dispatch_fence: raw.dispatch_fence,
            dispatch_commit: commit.clone(),
            tool_server: raw.tool_server.clone(),
            tool_name: raw.tool_name.clone(),
            provider_attempt: raw.provider_attempt.clone(),
            transport_terminal_evidence_digest: raw.transport_terminal_evidence_digest.clone(),
            raw_output: blob.blob_ref().clone(),
            raw_output_size_bytes,
            reported_cost: raw.reported_cost.clone(),
            disposition,
            recording_fence,
            recorded_at_unix_ms,
            version,
            lifecycle_digest,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn operation_id(&self) -> &AdmissionOperationId {
        &self.operation_id
    }

    pub fn outcome_id(&self) -> &AdmissionDigest {
        &self.outcome_id
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn disposition(&self) -> &ResolvedToolOutcomeV1 {
        &self.disposition
    }

    pub fn raw_output_digest(&self) -> &AdmissionDigest {
        self.raw_output.digest()
    }

    pub fn resolved_output_ref(&self) -> Option<(&ContentAddressedBlobRefV1, u64)> {
        match &self.disposition {
            ResolvedToolOutcomeV1::Resolved {
                resolved_output,
                resolved_output_size_bytes,
                ..
            } => Some((resolved_output, *resolved_output_size_bytes)),
            ResolvedToolOutcomeV1::Returned | ResolvedToolOutcomeV1::Frozen { .. } => None,
        }
    }

    pub fn recording_fence(&self) -> &StoreMutationFence {
        &self.recording_fence
    }

    pub fn recorded_at_unix_ms(&self) -> u64 {
        self.recorded_at_unix_ms
    }

    pub fn lifecycle_digest(&self) -> &AdmissionDigest {
        &self.lifecycle_digest
    }

    pub fn validate_against(
        &self,
        operation: &AdmissionOperationV1,
    ) -> Result<(), ToolOutcomeError> {
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding("outcome.dispatch_commit"))?;
        validate_retained_dispatch_commit(operation, commit)?;
        if self.operation_id != *operation.binding().operation_id()
            || self.request_id != operation.replay_key().request_id
            || self.dispatch_operation_version != commit.committed_version
            || self.dispatch_fence != commit.store_fence.owner_epoch
            || self.dispatch_commit != *commit
        {
            return Err(ToolOutcomeError::Binding("outcome.admission_operation"));
        }
        validate_registered_provider_attempt(operation, &self.provider_attempt)?;
        self.validate()
    }

    pub fn validate_for_store_insert(
        &self,
        operation: &AdmissionOperationV1,
        blob: &CanonicalInvocationBlobV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(), ToolOutcomeError> {
        let commit = operation
            .dispatch_commit()
            .ok_or(ToolOutcomeError::Binding("outcome.dispatch_commit"))?;
        validate_committed_operation(operation, commit)?;
        self.validate_canonical_blob(operation, blob)?;
        validate_store_fence(active_fence)?;
        positive("outcome.store_trusted_now", trusted_now_unix_ms)?;
        if active_fence != &self.recording_fence || trusted_now_unix_ms < self.recorded_at_unix_ms {
            return Err(ToolOutcomeError::Binding("outcome.store_mutation_context"));
        }
        Ok(())
    }

    pub fn validate_canonical_blob(
        &self,
        operation: &AdmissionOperationV1,
        blob: &CanonicalInvocationBlobV1,
    ) -> Result<(), ToolOutcomeError> {
        self.validate_against(operation)?;
        let raw = RawInvocationOutcomeV1::from_canonical_bytes(blob.bytes())?;
        blob.verify(&raw)?;
        let raw = raw.to_persisted();
        if raw.operation_id != self.operation_id
            || raw.request_id != self.request_id
            || raw.dispatch_operation_version != self.dispatch_operation_version
            || raw.dispatch_fence != self.dispatch_fence
            || raw.tool_server != self.tool_server
            || raw.tool_name != self.tool_name
            || raw.provider_attempt != self.provider_attempt
            || raw.transport_terminal_evidence_digest != self.transport_terminal_evidence_digest
            || raw.reported_cost != self.reported_cost
            || blob.blob_ref() != &self.raw_output
            || u64::try_from(blob.bytes().len()).ok() != Some(self.raw_output_size_bytes)
        {
            return Err(ToolOutcomeError::Binding("outcome.raw_invocation_blob"));
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ToolOutcomeError> {
        positive(
            "outcome.dispatch_operation_version",
            self.dispatch_operation_version,
        )?;
        positive("outcome.dispatch_fence", self.dispatch_fence)?;
        positive("outcome.recorded_at", self.recorded_at_unix_ms)?;
        positive("outcome.version", self.version)?;
        positive(
            "outcome.dispatch_commit.coordinator_lease_epoch",
            self.dispatch_commit.coordinator_lease_epoch,
        )?;
        validate_store_fence(&self.dispatch_commit.store_fence)?;
        validate_successor_fence(&self.dispatch_commit.store_fence, &self.recording_fence)?;
        if self.dispatch_commit.committed_version != self.dispatch_operation_version
            || self.dispatch_commit.store_fence.owner_epoch != self.dispatch_fence
        {
            return Err(ToolOutcomeError::Binding("outcome.dispatch_commit"));
        }
        positive("outcome.raw_output_size_bytes", self.raw_output_size_bytes)?;
        if self.raw_output_size_bytes > MAX_RAW_INVOCATION_OUTCOME_BYTES as u64 {
            return Err(ToolOutcomeError::TooLarge {
                field: "outcome.raw_output_size_bytes",
                actual: usize::try_from(self.raw_output_size_bytes).unwrap_or(usize::MAX),
                maximum: MAX_RAW_INVOCATION_OUTCOME_BYTES,
            });
        }
        self.raw_output.validate()?;
        if let Some(cost) = &self.reported_cost {
            amount(cost)?;
        }
        self.disposition.validate()?;
        let expected_version = match &self.disposition {
            ResolvedToolOutcomeV1::Returned => 1,
            ResolvedToolOutcomeV1::Resolved { .. } | ResolvedToolOutcomeV1::Frozen { .. } => 2,
        };
        if self.version != expected_version {
            return Err(ToolOutcomeError::Binding("outcome.lifecycle_version"));
        }
        let expected = domain_digest(
            "chio.tool-outcome.identity.v1",
            &OutcomeIdentity {
                operation_id: &self.operation_id,
                request_id: &self.request_id,
                dispatch_operation_version: self.dispatch_operation_version,
                dispatch_fence: self.dispatch_fence,
                dispatch_commit: &self.dispatch_commit,
                tool_server: &self.tool_server,
                tool_name: &self.tool_name,
                provider_attempt: &self.provider_attempt,
                transport_terminal_evidence_digest: &self.transport_terminal_evidence_digest,
                raw_output: &self.raw_output,
                raw_output_size_bytes: self.raw_output_size_bytes,
                reported_cost: &self.reported_cost,
            },
        )?;
        if self.outcome_id != expected {
            return Err(ToolOutcomeError::Binding("outcome.outcome_id"));
        }
        if self.lifecycle_digest
            != outcome_lifecycle_digest(
                &self.outcome_id,
                &self.disposition,
                &self.recording_fence,
                self.recorded_at_unix_ms,
                self.version,
            )?
        {
            return Err(ToolOutcomeError::Binding("outcome.lifecycle_digest"));
        }
        Ok(())
    }

    pub fn same_immutable_outcome(&self, other: &Self) -> bool {
        self.outcome_id == other.outcome_id
    }

    #[allow(dead_code)]
    pub(crate) fn transition(
        &self,
        expected_version: u64,
        transition: ToolOutcomeTransitionV1,
    ) -> Result<Self, ToolOutcomeError> {
        self.validate()?;
        if self.version != expected_version {
            return Err(ToolOutcomeError::Cas {
                expected: expected_version,
                actual: self.version,
            });
        }
        if !matches!(self.disposition, ResolvedToolOutcomeV1::Returned) {
            return Err(ToolOutcomeError::Transition {
                state: self.disposition.name(),
                transition: transition.name(),
            });
        }
        let disposition = match transition {
            ToolOutcomeTransitionV1::Resolve(evidence) => {
                evidence.binds(self)?;
                ResolvedToolOutcomeV1::Resolved {
                    evaluation_id: evidence.evaluation_id,
                    resolved_output: evidence.resolved_output,
                    resolved_output_size_bytes: evidence.resolved_output_size_bytes,
                    terminal_dependency_root_digest: evidence.terminal_dependency_root_digest,
                    post_guard_decision_digest: evidence.post_guard_decision_digest,
                    pricing_verdict_digest: evidence.pricing_verdict_digest,
                    settlement_disposition: evidence.settlement_disposition,
                }
            }
            ToolOutcomeTransitionV1::Freeze(evidence) => {
                evidence.binds(self)?;
                ResolvedToolOutcomeV1::Frozen {
                    evaluation_id: evidence.evaluation_id,
                    freeze_evidence_digest: evidence.freeze_evidence_digest,
                }
            }
        };
        let mut next = self.clone();
        next.version = next
            .version
            .checked_add(1)
            .ok_or(ToolOutcomeError::Overflow("outcome.version"))?;
        next.disposition = disposition;
        next.lifecycle_digest = outcome_lifecycle_digest(
            &next.outcome_id,
            &next.disposition,
            &next.recording_fence,
            next.recorded_at_unix_ms,
            next.version,
        )?;
        next.validate()?;
        Ok(next)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum ToolOutcomeTransitionV1 {
    Resolve(PostReturnTerminalEvidenceV1),
    Freeze(PostReturnFreezeEvidenceV1),
}

impl ToolOutcomeTransitionV1 {
    #[allow(dead_code)]
    fn name(&self) -> &'static str {
        match self {
            Self::Resolve(_) => "resolve",
            Self::Freeze(_) => "freeze",
        }
    }
}

mod post_return;
pub use post_return::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ToolOutcomeInsertResultV1 {
    Inserted {
        outcome: ToolOutcomeRecordV1,
        operation: AdmissionOperationV1,
    },
    ExactReplay {
        outcome: ToolOutcomeRecordV1,
        operation: AdmissionOperationV1,
    },
}

impl ToolOutcomeInsertResultV1 {
    #[must_use]
    pub fn outcome(&self) -> &ToolOutcomeRecordV1 {
        match self {
            Self::Inserted { outcome, .. } | Self::ExactReplay { outcome, .. } => outcome,
        }
    }

    #[must_use]
    pub fn operation(&self) -> &AdmissionOperationV1 {
        match self {
            Self::Inserted { operation, .. } | Self::ExactReplay { operation, .. } => operation,
        }
    }

    #[must_use]
    pub fn into_parts(self) -> (ToolOutcomeRecordV1, AdmissionOperationV1) {
        match self {
            Self::Inserted { outcome, operation } | Self::ExactReplay { outcome, operation } => {
                (outcome, operation)
            }
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ToolOutcomeStoreError {
    #[error("tool outcome store is unavailable: {0}")]
    Unavailable(String),
    #[error("tool outcome mutation was fenced")]
    Fenced,
    #[error("tool outcome was not found")]
    NotFound,
    #[error("tool outcome insert conflicts with an existing operation")]
    Conflict,
    #[error("tool outcome CAS conflict")]
    CasConflict,
    #[error("tool outcome invariant failed: {0}")]
    Invariant(String),
}

/// Storage boundary for insert-once return recording and atomic finalization.
pub trait ToolOutcomeStore: Send + Sync {
    fn record_tool_returned(
        &self,
        operation: &AdmissionOperationV1,
        recovery_lease: &AdmissionRecoveryLease,
        blob: &CanonicalInvocationBlobV1,
        record: &ToolOutcomeRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<ToolOutcomeInsertResultV1, ToolOutcomeStoreError>;

    fn lookup_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<ToolOutcomeRecordV1>, ToolOutcomeStoreError>;

    fn load_raw_invocation_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<RawInvocationOutcomeV1>, ToolOutcomeStoreError>;

    fn lookup_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<PostReturnEvaluationRecordV1>, ToolOutcomeStoreError>;

    fn begin_post_return_evaluation(
        &self,
        recovery_lease: &AdmissionRecoveryLease,
        record: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError>;

    fn stage_post_return_evaluation(
        &self,
        operation_id: &AdmissionOperationId,
        expected_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        next: &PostReturnEvaluationRecordV1,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<PostReturnEvaluationRecordV1, ToolOutcomeStoreError>;

    /// Atomically commits the matching terminal evaluation and outcome.
    #[allow(clippy::too_many_arguments)]
    fn finalize_post_return(
        &self,
        operation_id: &AdmissionOperationId,
        expected_evaluation_version: u64,
        recovery_lease: &AdmissionRecoveryLease,
        terminal_evaluation: &PostReturnEvaluationRecordV1,
        expected_outcome_version: u64,
        terminal_outcome: &ToolOutcomeRecordV1,
        resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
        active_fence: &StoreMutationFence,
        trusted_now_unix_ms: u64,
    ) -> Result<(PostReturnEvaluationRecordV1, ToolOutcomeRecordV1), ToolOutcomeStoreError>;

    fn load_resolved_output_by_operation(
        &self,
        operation_id: &AdmissionOperationId,
    ) -> Result<Option<CanonicalResolvedOutputBlobV1>, ToolOutcomeStoreError>;
}

/// Explicit trust boundary for stores that atomically bind a returned tool
/// outcome to the durable admission operation.
///
/// Implementations must persist the canonical blob and outcome record in the
/// same fenced commit that attaches the outcome ID and advances the operation
/// from `DispatchCommitted` to `Finalizing`. Exact replay must return the
/// already-bound operation without mutating it.
pub trait QualifiedToolOutcomeStore: ToolOutcomeStore {}

pub fn validate_evaluation_store_successor(
    current: &PostReturnEvaluationRecordV1,
    next: &PostReturnEvaluationRecordV1,
) -> Result<(), ToolOutcomeError> {
    current.validate()?;
    next.validate()?;
    let current_persisted = current.to_persisted();
    let next_persisted = next.to_persisted();
    if next.version()
        != current
            .version()
            .checked_add(1)
            .ok_or(ToolOutcomeError::Overflow("post_return_evaluation.version"))?
        || current_persisted.schema != next_persisted.schema
        || current_persisted.evaluation_id != next_persisted.evaluation_id
        || current_persisted.operation_id != next_persisted.operation_id
        || current_persisted.tool_outcome_id != next_persisted.tool_outcome_id
        || current_persisted.tool_outcome_version != next_persisted.tool_outcome_version
        || current_persisted.raw_output_digest != next_persisted.raw_output_digest
        || current_persisted.plan_digest != next_persisted.plan_digest
        || current_persisted.trusted_time_unix_ms != next_persisted.trusted_time_unix_ms
        || current_persisted.exact_inputs_digest != next_persisted.exact_inputs_digest
        || current_persisted.exact_inputs != next_persisted.exact_inputs
        || current_persisted.frozen_steps != next_persisted.frozen_steps
    {
        return Err(ToolOutcomeError::Binding(
            "evaluation.store_successor_identity",
        ));
    }
    let valid_transition = match (&current_persisted.state, &next_persisted.state) {
        (PostReturnEvaluationStateV1::Evaluating, PostReturnEvaluationStateV1::Evaluating) => {
            next_persisted.step_results.len() == current_persisted.step_results.len() + 1
                && next_persisted
                    .step_results
                    .starts_with(&current_persisted.step_results)
        }
        (
            PostReturnEvaluationStateV1::Evaluating,
            PostReturnEvaluationStateV1::Resolved { .. }
            | PostReturnEvaluationStateV1::Frozen { .. },
        ) => next_persisted.step_results == current_persisted.step_results,
        _ => false,
    };
    if !valid_transition {
        return Err(ToolOutcomeError::Transition {
            state: "post_return_evaluation",
            transition: "store_successor",
        });
    }
    Ok(())
}

pub fn validate_terminal_store_pair(
    operation: &AdmissionOperationV1,
    current_outcome: &ToolOutcomeRecordV1,
    current_evaluation: &PostReturnEvaluationRecordV1,
    terminal_evaluation: &PostReturnEvaluationRecordV1,
    terminal_outcome: &ToolOutcomeRecordV1,
    resolved_output: Option<&CanonicalResolvedOutputBlobV1>,
) -> Result<(), ToolOutcomeError> {
    current_outcome.validate_against(operation)?;
    current_evaluation.validate_against(operation, current_outcome)?;
    validate_evaluation_store_successor(current_evaluation, terminal_evaluation)?;
    terminal_outcome.validate_against(operation)?;
    terminal_evaluation.validate_against(operation, terminal_outcome)?;
    let transition = match terminal_evaluation.state() {
        PostReturnEvaluationStateV1::Resolved { .. } => {
            ToolOutcomeTransitionV1::Resolve(terminal_evaluation.terminal_evidence()?)
        }
        PostReturnEvaluationStateV1::Frozen { .. } => {
            ToolOutcomeTransitionV1::Freeze(terminal_evaluation.freeze_evidence()?)
        }
        PostReturnEvaluationStateV1::Evaluating => {
            return Err(ToolOutcomeError::Invalid("terminal_store_pair.evaluation"));
        }
    };
    let expected = current_outcome.transition(current_outcome.version(), transition)?;
    if expected != *terminal_outcome {
        return Err(ToolOutcomeError::Binding("terminal_store_pair.outcome"));
    }
    match terminal_outcome.resolved_output_ref() {
        Some((expected, expected_size)) => resolved_output
            .ok_or(ToolOutcomeError::Binding(
                "terminal_store_pair.resolved_output",
            ))?
            .verify(expected, expected_size)?,
        None if resolved_output.is_none() => {}
        None => {
            return Err(ToolOutcomeError::Binding(
                "terminal_store_pair.unexpected_resolved_output",
            ));
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn finalizing_outcome_command(
    operation: &AdmissionOperationV1,
    recovery_lease: AdmissionRecoveryLease,
    outcome_id: AdmissionDigest,
) -> Result<AdmissionOperationCommand, ToolOutcomeError> {
    AdmissionOperationCommand::new(
        operation.binding().operation_id().clone(),
        operation.version(),
        recovery_lease,
        vec![AdmissionAttachment::ToolOutcomeId(outcome_id)],
        Some(AdmissionOperationState::Finalizing),
        None,
        None,
    )
    .map_err(|error| ToolOutcomeError::Canonical(error.to_string()))
}

mod release;
pub use release::*;

#[cfg(any(test, feature = "admission-test-support"))]
pub mod test_support;

#[cfg(test)]
#[path = "tool_outcome_tests.rs"]
mod tests;
