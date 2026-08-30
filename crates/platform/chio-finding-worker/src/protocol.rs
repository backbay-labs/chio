use std::collections::BTreeSet;

use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex, PublicKey, SigningBackend};
use serde::{Deserialize, Serialize};

use chio_finding_market_store_postgres::HostedMarketJob;

pub const FINDING_WORKER_CAPABILITY_SCHEMA: &str = "chio.finding.worker-capability.v1";
pub const FINDING_WORKER_JOB_SCHEMA: &str = "chio.finding.worker-job.v1";
pub const FINDING_WORKER_REQUEST_SCHEMA: &str = "chio.finding.worker-request.v1";
pub const FINDING_WORKER_RESULT_SCHEMA: &str = "chio.finding.worker-result.v1";
pub const FINDING_WORKER_ATTESTED_RESULT_SCHEMA: &str = "chio.finding.worker-attested-result.v1";
pub const FINDING_WORKER_GUEST_ENFORCEMENT_SCHEMA: &str =
    "chio.finding.worker-guest-enforcement.v1";
pub const FINDING_WORKER_INPUT_SCHEMA: &str = "chio.finding.worker-input.v1";
pub const FINDING_WORKER_INPUT_END_SCHEMA: &str = "chio.finding.worker-input-end.v1";

const MAX_COMMAND_ARGUMENTS: usize = 64;
const MAX_COMMAND_ARGUMENT_BYTES: usize = 4_096;
const MAX_INPUT_ARTIFACTS: usize = 256;
const MAX_OUTPUT_ARTIFACTS: usize = 256;
const MAX_DIAGNOSTICS: usize = 64;
const MAX_DIAGNOSTIC_BYTES: usize = 1_024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerCapabilityBody {
    pub schema: String,
    pub capability_id: String,
    pub tenant_id: String,
    pub job_id: String,
    pub job_kind: String,
    pub request_sha256: String,
    pub job_spec_sha256: String,
    pub not_before_unix_secs: u64,
    pub expires_at_unix_secs: u64,
    pub max_attempts: u32,
}

pub type SignedFindingWorkerCapability = SignedExportEnvelope<FindingWorkerCapabilityBody>;

impl FindingWorkerCapabilityBody {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_CAPABILITY_SCHEMA
            || !valid_identifier(&self.capability_id, 256)
            || !valid_identifier(&self.tenant_id, 128)
            || !valid_identifier(&self.job_id, 256)
            || !valid_identifier(&self.job_kind, 96)
            || !valid_digest(&self.request_sha256)
            || !valid_digest(&self.job_spec_sha256)
            || self.not_before_unix_secs == 0
            || self.expires_at_unix_secs <= self.not_before_unix_secs
            || !(1..=20).contains(&self.max_attempts)
        {
            return Err("worker_capability_invalid");
        }
        Ok(())
    }
}

pub fn sign_job_capability(
    body: FindingWorkerCapabilityBody,
    signer: &dyn SigningBackend,
) -> Result<SignedFindingWorkerCapability, &'static str> {
    body.validate()?;
    SignedExportEnvelope::sign_with_backend(body, signer)
        .map_err(|_| "worker_capability_signing_failed")
}

pub fn verify_job_capability(
    capability: &SignedFindingWorkerCapability,
    expected_signer: &PublicKey,
    now: u64,
) -> Result<(), &'static str> {
    capability.body.validate()?;
    if &capability.signer_key != expected_signer {
        return Err("worker_capability_signer_mismatch");
    }
    if !capability
        .verify_signature()
        .map_err(|_| "worker_capability_signature_invalid")?
    {
        return Err("worker_capability_signature_invalid");
    }
    if now < capability.body.not_before_unix_secs || now > capability.body.expires_at_unix_secs {
        return Err("worker_capability_expired");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingWorkerRepositoryKind {
    GitCommit,
    ContentSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerRepository {
    pub kind: FindingWorkerRepositoryKind,
    pub immutable_reference: String,
    pub archive_sha256: String,
    pub archive_size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerArtifact {
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingWorkerInputKind {
    Repository,
    Artifact,
}

/// Header sent before one content-addressed input byte stream.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerInputDescriptor {
    pub schema: String,
    pub kind: FindingWorkerInputKind,
    pub name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

impl FindingWorkerInputDescriptor {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_INPUT_SCHEMA
            || !valid_artifact_name(&self.name)
            || !valid_digest(&self.sha256)
            || self.size_bytes == 0
        {
            return Err("worker_input_descriptor_invalid");
        }
        Ok(())
    }
}

/// Terminal input marker binding the complete ordered transfer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerInputEnd {
    pub schema: String,
    pub input_count: u32,
    pub total_size_bytes: u64,
}

impl FindingWorkerInputEnd {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_INPUT_END_SCHEMA
            || self.input_count == 0
            || self.input_count > u32::try_from(MAX_INPUT_ARTIFACTS + 1).unwrap_or(u32::MAX)
            || self.total_size_bytes == 0
        {
            return Err("worker_input_end_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerResourceLimits {
    pub wall_time_millis: u64,
    pub cpu_time_millis: u64,
    pub memory_bytes: u64,
    pub workspace_bytes: u64,
    pub output_bytes: u64,
    pub process_count: u32,
    pub open_files: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerJobSpec {
    pub schema: String,
    pub repository: FindingWorkerRepository,
    pub manifest: serde_json::Value,
    pub manifest_sha256: String,
    pub command: Vec<String>,
    pub resource_limits: FindingWorkerResourceLimits,
    pub input_artifacts: Vec<FindingWorkerArtifact>,
}

impl FindingWorkerJobSpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_JOB_SCHEMA
            || !valid_text(&self.repository.immutable_reference, 256)
            || !valid_digest(&self.repository.archive_sha256)
            || self.repository.archive_size_bytes == 0
            || !valid_digest(&self.manifest_sha256)
            || self.command.is_empty()
            || self.command.len() > MAX_COMMAND_ARGUMENTS
            || self.input_artifacts.len() > MAX_INPUT_ARTIFACTS
        {
            return Err("worker_job_invalid");
        }
        match self.repository.kind {
            FindingWorkerRepositoryKind::GitCommit
                if !matches!(self.repository.immutable_reference.len(), 40 | 64)
                    || !self
                        .repository
                        .immutable_reference
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
            {
                return Err("worker_repository_reference_invalid")
            }
            FindingWorkerRepositoryKind::ContentSnapshot
                if self.repository.immutable_reference != self.repository.archive_sha256 =>
            {
                return Err("worker_repository_reference_invalid")
            }
            _ => {}
        }
        if self
            .command
            .iter()
            .any(|argument| !valid_text(argument, MAX_COMMAND_ARGUMENT_BYTES))
        {
            return Err("worker_command_invalid");
        }
        let manifest = canonical_json_bytes(&self.manifest).map_err(|_| "manifest_invalid")?;
        if sha256_hex(&manifest) != self.manifest_sha256 {
            return Err("manifest_digest_mismatch");
        }
        self.resource_limits.validate()?;
        validate_artifacts(&self.input_artifacts, MAX_INPUT_ARTIFACTS)?;
        let input_size = self
            .input_artifacts
            .iter()
            .try_fold(0_u64, |total, artifact| {
                total.checked_add(artifact.size_bytes)
            });
        let staged_size =
            input_size.and_then(|size| size.checked_add(self.repository.archive_size_bytes));
        if staged_size.is_none_or(|size| size > self.resource_limits.workspace_bytes) {
            return Err("worker_input_capacity_exceeded");
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String, &'static str> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| "worker_job_encoding_invalid")
    }
}

impl FindingWorkerResourceLimits {
    fn validate(&self) -> Result<(), &'static str> {
        if !(1_000..=3_600_000).contains(&self.wall_time_millis)
            || self.cpu_time_millis == 0
            || self.cpu_time_millis > self.wall_time_millis.saturating_mul(32)
            || !(128 * 1024 * 1024..=128 * 1024 * 1024 * 1024).contains(&self.memory_bytes)
            || !(1024 * 1024..=64 * 1024 * 1024 * 1024).contains(&self.workspace_bytes)
            || self.output_bytes == 0
            || self.output_bytes > self.workspace_bytes
            || !(1..=4_096).contains(&self.process_count)
            || !(32..=4_096).contains(&self.open_files)
        {
            return Err("worker_resource_limits_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerJobPayload {
    pub capability: SignedFindingWorkerCapability,
    pub job: FindingWorkerJobSpec,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerRequest {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub job_kind: String,
    pub request_sha256: String,
    pub payload_sha256: String,
    pub capability: SignedFindingWorkerCapability,
    pub job: FindingWorkerJobSpec,
    pub attempt: u64,
    pub deadline_unix_secs: u64,
}

impl FindingWorkerRequest {
    pub(crate) fn from_job(
        job: &HostedMarketJob,
        deadline: u64,
        capability_authority: &PublicKey,
        now: u64,
    ) -> Result<Self, &'static str> {
        let payload: FindingWorkerJobPayload =
            serde_json::from_slice(&job.payload_json).map_err(|_| "payload_invalid")?;
        let request = Self {
            schema: FINDING_WORKER_REQUEST_SCHEMA.to_owned(),
            tenant_id: job.tenant_id.as_str().to_owned(),
            job_id: job.job_id.clone(),
            job_kind: job.job_kind.clone(),
            request_sha256: job.request_sha256.clone(),
            payload_sha256: job.payload_sha256.clone(),
            capability: payload.capability,
            job: payload.job,
            attempt: job.attempt_count,
            deadline_unix_secs: deadline,
        };
        request.validate_authorized(capability_authority, now)?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_REQUEST_SCHEMA
            || !valid_identifier(&self.tenant_id, 128)
            || !valid_identifier(&self.job_id, 256)
            || !valid_identifier(&self.job_kind, 96)
            || !valid_digest(&self.request_sha256)
            || !valid_digest(&self.payload_sha256)
            || self.attempt == 0
            || self.deadline_unix_secs == 0
        {
            return Err("request_binding_invalid");
        }
        self.job.validate()?;
        let payload = FindingWorkerJobPayload {
            capability: self.capability.clone(),
            job: self.job.clone(),
        };
        let payload = canonical_json_bytes(&payload).map_err(|_| "payload_invalid")?;
        if sha256_hex(&payload) != self.payload_sha256 {
            return Err("payload_digest_mismatch");
        }
        Ok(())
    }

    pub fn validate_authorized(
        &self,
        expected_signer: &PublicKey,
        now: u64,
    ) -> Result<(), &'static str> {
        self.validate()?;
        verify_job_capability(&self.capability, expected_signer, now)?;
        let body = &self.capability.body;
        if body.tenant_id != self.tenant_id
            || body.job_id != self.job_id
            || body.job_kind != self.job_kind
            || body.request_sha256 != self.request_sha256
            || body.job_spec_sha256 != self.job.sha256()?
            || self.attempt > u64::from(body.max_attempts)
            || self.deadline_unix_secs > body.expires_at_unix_secs
        {
            return Err("worker_capability_binding_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingWorkerExitClassification {
    Succeeded,
    PolicyDenied,
    CommandFailed,
    ResourceExhausted,
    TimedOut,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerResourceUsage {
    pub wall_time_millis: u64,
    pub cpu_time_millis: u64,
    pub peak_memory_bytes: u64,
    pub workspace_bytes: u64,
    pub output_bytes: u64,
    pub process_peak: u32,
    pub open_files_peak: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerDiagnostic {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingWorkerGuestProcessBoundary {
    CgroupV2,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingWorkerGuestOpenFilesBoundary {
    RlimitNofile,
}

/// Kernel-authored enforcement evidence from the trusted guest supervisor.
///
/// The untrusted workload runs below that supervisor and cannot access the
/// virtio-vsock endpoint used to emit this frame. The host binds these exact
/// values to the authorized request before signing the result.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerGuestEnforcement {
    pub schema: String,
    pub process_boundary: FindingWorkerGuestProcessBoundary,
    pub process_limit: u32,
    pub process_limit_probe_passed: bool,
    pub process_limit_hits: u32,
    pub open_files_boundary: FindingWorkerGuestOpenFilesBoundary,
    pub open_files_soft_limit: u32,
    pub open_files_hard_limit: u32,
    pub open_files_limit_probe_passed: bool,
    pub open_files_limit_hits: u32,
}

impl FindingWorkerGuestEnforcement {
    fn validate_for(
        &self,
        limits: &FindingWorkerResourceLimits,
        classification: FindingWorkerExitClassification,
        usage: &FindingWorkerResourceUsage,
    ) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_GUEST_ENFORCEMENT_SCHEMA
            || self.process_boundary != FindingWorkerGuestProcessBoundary::CgroupV2
            || self.process_limit != limits.process_count
            || !self.process_limit_probe_passed
            || self.open_files_boundary != FindingWorkerGuestOpenFilesBoundary::RlimitNofile
            || self.open_files_soft_limit != limits.open_files
            || self.open_files_hard_limit != limits.open_files
            || !self.open_files_limit_probe_passed
        {
            return Err("guest_enforcement_binding_invalid");
        }
        let process_limit_hit = self.process_limit_hits != 0;
        let open_files_limit_hit = self.open_files_limit_hits != 0;
        if (process_limit_hit && usage.process_peak != limits.process_count)
            || (open_files_limit_hit && usage.open_files_peak != limits.open_files)
            || ((process_limit_hit || open_files_limit_hit)
                && classification != FindingWorkerExitClassification::ResourceExhausted)
        {
            return Err("guest_enforcement_accounting_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerResult {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub request_sha256: String,
    pub classification: FindingWorkerExitClassification,
    pub finding_artifact_sha256: Option<String>,
    pub output_artifacts: Vec<FindingWorkerArtifact>,
    pub diagnostics: Vec<FindingWorkerDiagnostic>,
    pub guest_enforcement: FindingWorkerGuestEnforcement,
    pub resource_usage: FindingWorkerResourceUsage,
}

impl FindingWorkerResult {
    pub(crate) fn validate_for(&self, request: &FindingWorkerRequest) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_RESULT_SCHEMA
            || self.tenant_id != request.tenant_id
            || self.job_id != request.job_id
            || self.request_sha256 != request.request_sha256
            || self.output_artifacts.len() > MAX_OUTPUT_ARTIFACTS
            || self.diagnostics.len() > MAX_DIAGNOSTICS
        {
            return Err("result_binding_invalid");
        }
        validate_artifacts(&self.output_artifacts, MAX_OUTPUT_ARTIFACTS)?;
        if self.diagnostics.iter().any(|diagnostic| {
            !valid_identifier(&diagnostic.code, 128)
                || !valid_text(&diagnostic.message, MAX_DIAGNOSTIC_BYTES)
        }) {
            return Err("result_diagnostic_invalid");
        }
        let succeeded = self.classification == FindingWorkerExitClassification::Succeeded;
        if succeeded != self.finding_artifact_sha256.is_some()
            || self
                .finding_artifact_sha256
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
            || (!succeeded && !self.output_artifacts.is_empty())
        {
            return Err("result_shape_invalid");
        }
        if self
            .finding_artifact_sha256
            .as_deref()
            .is_some_and(|digest| {
                !self
                    .output_artifacts
                    .iter()
                    .any(|artifact| artifact.sha256 == digest)
            })
        {
            return Err("finding_artifact_not_returned");
        }
        self.resource_usage
            .validate_for(&request.job.resource_limits)?;
        self.guest_enforcement.validate_for(
            &request.job.resource_limits,
            self.classification,
            &self.resource_usage,
        )?;
        if self.classification != FindingWorkerExitClassification::PolicyDenied
            && (self.resource_usage.process_peak == 0 || self.resource_usage.open_files_peak == 0)
        {
            return Err("result_resource_accounting_invalid");
        }
        let output_artifact_bytes = self
            .output_artifacts
            .iter()
            .try_fold(0_u64, |total, artifact| {
                total.checked_add(artifact.size_bytes)
            });
        if output_artifact_bytes.is_none_or(|size| size > self.resource_usage.output_bytes) {
            return Err("result_resource_accounting_invalid");
        }
        Ok(())
    }
}

impl FindingWorkerResourceUsage {
    fn validate_for(&self, limits: &FindingWorkerResourceLimits) -> Result<(), &'static str> {
        if self.wall_time_millis > limits.wall_time_millis
            || self.cpu_time_millis > limits.cpu_time_millis
            || self.peak_memory_bytes > limits.memory_bytes
            || self.workspace_bytes > limits.workspace_bytes
            || self.output_bytes > limits.output_bytes
            || self.process_peak > limits.process_count
            || self.open_files_peak > limits.open_files
        {
            return Err("result_resource_limit_exceeded");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerAttestedResult {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub request_sha256: String,
    pub guest_result_sha256: String,
    pub worker_binary_sha256: String,
    pub firecracker_sha256: String,
    pub jailer_sha256: String,
    pub kernel_sha256: String,
    pub rootfs_sha256: String,
    pub completed_at_unix_secs: u64,
    pub result: FindingWorkerResult,
}

pub type SignedFindingWorkerResult = SignedExportEnvelope<FindingWorkerAttestedResult>;

impl FindingWorkerAttestedResult {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_guest(
        request: &FindingWorkerRequest,
        result: FindingWorkerResult,
        worker_binary_sha256: String,
        firecracker_sha256: String,
        jailer_sha256: String,
        kernel_sha256: String,
        rootfs_sha256: String,
        completed_at_unix_secs: u64,
    ) -> Result<Self, &'static str> {
        result.validate_for(request)?;
        let guest_result_sha256 =
            sha256_hex(&canonical_json_bytes(&result).map_err(|_| "result_encoding_invalid")?);
        let attested = Self {
            schema: FINDING_WORKER_ATTESTED_RESULT_SCHEMA.to_owned(),
            tenant_id: request.tenant_id.clone(),
            job_id: request.job_id.clone(),
            request_sha256: request.request_sha256.clone(),
            guest_result_sha256,
            worker_binary_sha256,
            firecracker_sha256,
            jailer_sha256,
            kernel_sha256,
            rootfs_sha256,
            completed_at_unix_secs,
            result,
        };
        attested.validate_for(request)?;
        Ok(attested)
    }

    pub fn validate_for(&self, request: &FindingWorkerRequest) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_ATTESTED_RESULT_SCHEMA
            || self.tenant_id != request.tenant_id
            || self.job_id != request.job_id
            || self.request_sha256 != request.request_sha256
            || !valid_digest(&self.guest_result_sha256)
            || !valid_digest(&self.worker_binary_sha256)
            || !valid_digest(&self.firecracker_sha256)
            || !valid_digest(&self.jailer_sha256)
            || !valid_digest(&self.kernel_sha256)
            || !valid_digest(&self.rootfs_sha256)
            || self.completed_at_unix_secs == 0
            || self.completed_at_unix_secs > request.deadline_unix_secs
        {
            return Err("attested_result_binding_invalid");
        }
        self.result.validate_for(request)?;
        let encoded = canonical_json_bytes(&self.result).map_err(|_| "result_encoding_invalid")?;
        if sha256_hex(&encoded) != self.guest_result_sha256 {
            return Err("guest_result_digest_mismatch");
        }
        Ok(())
    }
}

pub(crate) fn sign_attested_result(
    result: FindingWorkerAttestedResult,
    signer: &dyn SigningBackend,
) -> Result<SignedFindingWorkerResult, &'static str> {
    SignedExportEnvelope::sign_with_backend(result, signer)
        .map_err(|_| "worker_result_signing_failed")
}

pub fn verify_attested_result(
    envelope: &SignedFindingWorkerResult,
    request: &FindingWorkerRequest,
    expected_signer: &PublicKey,
) -> Result<(), &'static str> {
    if &envelope.signer_key != expected_signer {
        return Err("worker_signer_mismatch");
    }
    if !envelope
        .verify_signature()
        .map_err(|_| "worker_signature_invalid")?
    {
        return Err("worker_signature_invalid");
    }
    envelope.body.validate_for(request)
}

fn validate_artifacts(
    artifacts: &[FindingWorkerArtifact],
    maximum: usize,
) -> Result<(), &'static str> {
    if artifacts.len() > maximum {
        return Err("artifact_count_exceeded");
    }
    let mut names = BTreeSet::new();
    let mut digests = BTreeSet::new();
    for artifact in artifacts {
        if !valid_artifact_name(&artifact.name)
            || !valid_digest(&artifact.sha256)
            || artifact.size_bytes == 0
            || !names.insert(artifact.name.as_str())
            || !digests.insert(artifact.sha256.as_str())
        {
            return Err("artifact_invalid");
        }
    }
    Ok(())
}

fn valid_artifact_name(value: &str) -> bool {
    valid_text(value, 256)
        && !value.starts_with('/')
        && !value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::Ed25519Backend;

    fn limits() -> FindingWorkerResourceLimits {
        FindingWorkerResourceLimits {
            wall_time_millis: 30_000,
            cpu_time_millis: 60_000,
            memory_bytes: 512 * 1024 * 1024,
            workspace_bytes: 32 * 1024 * 1024,
            output_bytes: 4 * 1024 * 1024,
            process_count: 32,
            open_files: 128,
        }
    }

    #[test]
    fn input_transfer_headers_are_closed() {
        let descriptor = FindingWorkerInputDescriptor {
            schema: FINDING_WORKER_INPUT_SCHEMA.to_owned(),
            kind: FindingWorkerInputKind::Repository,
            name: "repository.archive".to_owned(),
            sha256: "a".repeat(64),
            size_bytes: 1,
        };
        assert!(descriptor.validate().is_ok());
        let mut invalid = descriptor;
        invalid.name = "../escape".to_owned();
        assert!(invalid.validate().is_err());
        assert!(FindingWorkerInputEnd {
            schema: FINDING_WORKER_INPUT_END_SCHEMA.to_owned(),
            input_count: 1,
            total_size_bytes: 1,
        }
        .validate()
        .is_ok());
    }

    fn job_spec() -> FindingWorkerJobSpec {
        let manifest = serde_json::json!({"schema":"chio.finding.worker-manifest.v1"});
        let manifest_sha256 = canonical_json_bytes(&manifest)
            .map(|bytes| sha256_hex(&bytes))
            .unwrap_or_default();
        FindingWorkerJobSpec {
            schema: FINDING_WORKER_JOB_SCHEMA.to_owned(),
            repository: FindingWorkerRepository {
                kind: FindingWorkerRepositoryKind::GitCommit,
                immutable_reference: "0123456789abcdef0123456789abcdef01234567".to_owned(),
                archive_sha256: "1".repeat(64),
                archive_size_bytes: 1_024,
            },
            manifest,
            manifest_sha256,
            command: vec!["cargo".to_owned(), "test".to_owned(), "--locked".to_owned()],
            resource_limits: limits(),
            input_artifacts: vec![],
        }
    }

    fn request() -> Option<(FindingWorkerRequest, Ed25519Backend)> {
        let authority = Ed25519Backend::generate();
        let job = job_spec();
        let job_spec_sha256 = job.sha256().ok()?;
        let capability = sign_job_capability(
            FindingWorkerCapabilityBody {
                schema: FINDING_WORKER_CAPABILITY_SCHEMA.to_owned(),
                capability_id: "capability-a".to_owned(),
                tenant_id: "tenant-a".to_owned(),
                job_id: "job-a".to_owned(),
                job_kind: "finding.verify".to_owned(),
                request_sha256: "2".repeat(64),
                job_spec_sha256,
                not_before_unix_secs: 1,
                expires_at_unix_secs: 20,
                max_attempts: 3,
            },
            &authority,
        )
        .ok()?;
        let payload = FindingWorkerJobPayload {
            capability: capability.clone(),
            job: job.clone(),
        };
        let payload_sha256 = canonical_json_bytes(&payload)
            .map(|bytes| sha256_hex(&bytes))
            .ok()?;
        Some((
            FindingWorkerRequest {
                schema: FINDING_WORKER_REQUEST_SCHEMA.to_owned(),
                tenant_id: "tenant-a".to_owned(),
                job_id: "job-a".to_owned(),
                job_kind: "finding.verify".to_owned(),
                request_sha256: "2".repeat(64),
                payload_sha256,
                capability,
                job,
                attempt: 1,
                deadline_unix_secs: 20,
            },
            authority,
        ))
    }

    fn successful_result(request: &FindingWorkerRequest) -> FindingWorkerResult {
        FindingWorkerResult {
            schema: FINDING_WORKER_RESULT_SCHEMA.to_owned(),
            tenant_id: request.tenant_id.clone(),
            job_id: request.job_id.clone(),
            request_sha256: request.request_sha256.clone(),
            classification: FindingWorkerExitClassification::Succeeded,
            finding_artifact_sha256: Some("3".repeat(64)),
            output_artifacts: vec![FindingWorkerArtifact {
                name: "finding.json".to_owned(),
                sha256: "3".repeat(64),
                size_bytes: 512,
            }],
            diagnostics: vec![],
            guest_enforcement: FindingWorkerGuestEnforcement {
                schema: FINDING_WORKER_GUEST_ENFORCEMENT_SCHEMA.to_owned(),
                process_boundary: FindingWorkerGuestProcessBoundary::CgroupV2,
                process_limit: request.job.resource_limits.process_count,
                process_limit_probe_passed: true,
                process_limit_hits: 0,
                open_files_boundary: FindingWorkerGuestOpenFilesBoundary::RlimitNofile,
                open_files_soft_limit: request.job.resource_limits.open_files,
                open_files_hard_limit: request.job.resource_limits.open_files,
                open_files_limit_probe_passed: true,
                open_files_limit_hits: 0,
            },
            resource_usage: FindingWorkerResourceUsage {
                wall_time_millis: 1_000,
                cpu_time_millis: 500,
                peak_memory_bytes: 64 * 1024 * 1024,
                workspace_bytes: 2_048,
                output_bytes: 512,
                process_peak: 2,
                open_files_peak: 8,
            },
        }
    }

    #[test]
    fn capability_binds_exact_job_and_deadline() {
        let prepared = request();
        assert!(prepared.is_some());
        if let Some((mut request, authority)) = prepared {
            assert!(request
                .validate_authorized(&authority.public_key(), 10)
                .is_ok());
            request.job.command.push("--release".to_owned());
            assert_eq!(
                request.validate_authorized(&authority.public_key(), 10),
                Err("payload_digest_mismatch")
            );
        }
    }

    #[test]
    fn failed_result_cannot_smuggle_output_artifacts() {
        let prepared = request();
        assert!(prepared.is_some());
        if let Some((request, _)) = prepared {
            let mut result = successful_result(&request);
            result.classification = FindingWorkerExitClassification::CommandFailed;
            result.finding_artifact_sha256 = None;
            assert_eq!(result.validate_for(&request), Err("result_shape_invalid"));
        }
    }

    #[test]
    fn result_requires_exact_in_guest_kernel_limits() {
        let prepared = request();
        assert!(prepared.is_some());
        if let Some((request, _)) = prepared {
            let mut result = successful_result(&request);
            result.guest_enforcement.process_limit -= 1;
            assert_eq!(
                result.validate_for(&request),
                Err("guest_enforcement_binding_invalid")
            );

            let mut result = successful_result(&request);
            result.guest_enforcement.process_limit_hits = 1;
            assert_eq!(
                result.validate_for(&request),
                Err("guest_enforcement_accounting_invalid")
            );
        }
    }

    #[test]
    fn artifact_paths_are_relative_and_normalized() {
        let prepared = request();
        assert!(prepared.is_some());
        if let Some((request, _)) = prepared {
            let mut result = successful_result(&request);
            result.output_artifacts[0].name = "../escape".to_owned();
            assert_eq!(result.validate_for(&request), Err("artifact_invalid"));
        }
    }

    #[test]
    fn attested_result_binds_guest_digest_images_and_signer() {
        let prepared = request();
        assert!(prepared.is_some());
        if let Some((request, _)) = prepared {
            let guest = successful_result(&request);
            let signer = Ed25519Backend::generate();
            let body = FindingWorkerAttestedResult::from_guest(
                &request,
                guest,
                "4".repeat(64),
                "5".repeat(64),
                "6".repeat(64),
                "7".repeat(64),
                "8".repeat(64),
                10,
            );
            assert!(body.is_ok());
            if let Ok(body) = body {
                let envelope = sign_attested_result(body, &signer);
                assert!(envelope.is_ok());
                if let Ok(mut envelope) = envelope {
                    assert!(
                        verify_attested_result(&envelope, &request, &signer.public_key()).is_ok()
                    );
                    envelope.body.kernel_sha256 = "9".repeat(64);
                    assert_eq!(
                        verify_attested_result(&envelope, &request, &signer.public_key()),
                        Err("worker_signature_invalid")
                    );
                }
            }
        }
    }
}
