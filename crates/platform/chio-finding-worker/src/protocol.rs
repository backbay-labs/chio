use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{canonical_json_bytes, sha256_hex, PublicKey, SigningBackend};
use serde::{Deserialize, Serialize};

use chio_finding_market_store_postgres::HostedMarketJob;

pub const FINDING_WORKER_REQUEST_SCHEMA: &str = "chio.finding.worker-request.v1";
pub const FINDING_WORKER_RESULT_SCHEMA: &str = "chio.finding.worker-result.v1";
pub const FINDING_WORKER_ATTESTED_RESULT_SCHEMA: &str = "chio.finding.worker-attested-result.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerRequest {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub job_kind: String,
    pub request_sha256: String,
    pub payload_sha256: String,
    pub payload: serde_json::Value,
    pub attempt: u64,
    pub deadline_unix_secs: u64,
}

impl FindingWorkerRequest {
    pub(crate) fn from_job(job: &HostedMarketJob, deadline: u64) -> Result<Self, &'static str> {
        let payload = serde_json::from_slice(&job.payload_json).map_err(|_| "payload_invalid")?;
        let request = Self {
            schema: FINDING_WORKER_REQUEST_SCHEMA.to_owned(),
            tenant_id: job.tenant_id.as_str().to_owned(),
            job_id: job.job_id.clone(),
            job_kind: job.job_kind.clone(),
            request_sha256: job.request_sha256.clone(),
            payload_sha256: job.payload_sha256.clone(),
            payload,
            attempt: job.attempt_count,
            deadline_unix_secs: deadline,
        };
        request.validate()?;
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
        let payload = canonical_json_bytes(&self.payload).map_err(|_| "payload_invalid")?;
        if sha256_hex(&payload) != self.payload_sha256 {
            return Err("payload_digest_mismatch");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingWorkerResultStatus {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerResult {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub request_sha256: String,
    pub status: FindingWorkerResultStatus,
    pub result: Option<serde_json::Value>,
    pub error_code: Option<String>,
}

impl FindingWorkerResult {
    pub(crate) fn validate_for(&self, request: &FindingWorkerRequest) -> Result<(), &'static str> {
        if self.schema != FINDING_WORKER_RESULT_SCHEMA
            || self.tenant_id != request.tenant_id
            || self.job_id != request.job_id
            || self.request_sha256 != request.request_sha256
        {
            return Err("result_binding_invalid");
        }
        match self.status {
            FindingWorkerResultStatus::Succeeded
                if self.result.is_some() && self.error_code.is_none() => {}
            FindingWorkerResultStatus::Failed
                if self.result.is_none()
                    && self
                        .error_code
                        .as_deref()
                        .is_some_and(|code| valid_identifier(code, 128)) => {}
            _ => return Err("result_shape_invalid"),
        }
        Ok(())
    }
}

/// Host-attested result accepted by durable market storage.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingWorkerAttestedResult {
    pub schema: String,
    pub tenant_id: String,
    pub job_id: String,
    pub request_sha256: String,
    pub guest_result_sha256: String,
    pub kernel_sha256: String,
    pub rootfs_sha256: String,
    pub completed_at_unix_secs: u64,
    pub result: FindingWorkerResult,
}

pub type SignedFindingWorkerResult = SignedExportEnvelope<FindingWorkerAttestedResult>;

impl FindingWorkerAttestedResult {
    pub(crate) fn from_guest(
        request: &FindingWorkerRequest,
        result: FindingWorkerResult,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_result_cannot_smuggle_success_payload() {
        let request = FindingWorkerRequest {
            schema: FINDING_WORKER_REQUEST_SCHEMA.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            job_id: "job-a".to_owned(),
            job_kind: "verify".to_owned(),
            request_sha256: "1".repeat(64),
            payload_sha256: sha256_hex(b"{}"),
            payload: serde_json::json!({}),
            attempt: 1,
            deadline_unix_secs: 10,
        };
        let result = FindingWorkerResult {
            schema: FINDING_WORKER_RESULT_SCHEMA.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            job_id: "job-a".to_owned(),
            request_sha256: "1".repeat(64),
            status: FindingWorkerResultStatus::Failed,
            result: Some(serde_json::json!({"forged": true})),
            error_code: Some("guest_failed".to_owned()),
        };
        assert_eq!(result.validate_for(&request), Err("result_shape_invalid"));
    }

    #[test]
    fn attested_result_binds_guest_digest_image_and_signer() {
        let request = FindingWorkerRequest {
            schema: FINDING_WORKER_REQUEST_SCHEMA.to_owned(),
            tenant_id: "tenant-a".to_owned(),
            job_id: "job-a".to_owned(),
            job_kind: "verify".to_owned(),
            request_sha256: "1".repeat(64),
            payload_sha256: sha256_hex(b"{}"),
            payload: serde_json::json!({}),
            attempt: 1,
            deadline_unix_secs: 20,
        };
        let guest = FindingWorkerResult {
            schema: FINDING_WORKER_RESULT_SCHEMA.to_owned(),
            tenant_id: request.tenant_id.clone(),
            job_id: request.job_id.clone(),
            request_sha256: request.request_sha256.clone(),
            status: FindingWorkerResultStatus::Succeeded,
            result: Some(serde_json::json!({"verified": true})),
            error_code: None,
        };
        let signer = chio_core_types::Ed25519Backend::generate();
        let body = FindingWorkerAttestedResult::from_guest(
            &request,
            guest,
            "2".repeat(64),
            "3".repeat(64),
            10,
        );
        assert!(body.is_ok());
        if let Ok(body) = body {
            let envelope = sign_attested_result(body, &signer);
            assert!(envelope.is_ok());
            if let Ok(mut envelope) = envelope {
                assert!(verify_attested_result(&envelope, &request, &signer.public_key()).is_ok());
                envelope.body.kernel_sha256 = "4".repeat(64);
                assert_eq!(
                    verify_attested_result(&envelope, &request, &signer.public_key()),
                    Err("worker_signature_invalid")
                );
            }
        }
    }
}
