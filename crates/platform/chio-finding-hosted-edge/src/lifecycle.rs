use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{
    canonical_json_bytes, sha256_hex, PublicKey, SigningAlgorithm, SigningBackend,
};
use chio_finding_market_store_postgres::{
    HostedJobWriteOutcome, HostedMarketStoreError, HostedTenantId, PostgresFindingMarketStore,
};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{ApiKeyPepper, HostedEdgeError};

pub const HOSTED_API_KEY_LIFECYCLE_SCHEMA: &str = "chio.finding.hosted-api-key-lifecycle.v1";
const API_KEY_ISSUED_EVENT_KIND: &str = "hosted.api_key.issued";
const API_KEY_REVOKED_EVENT_KIND: &str = "hosted.api_key.revoked";
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_ACTION_BYTES: usize = 96;
const MAX_ACTIONS: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostedApiKeyLifecycleEvent {
    pub schema: String,
    pub event_id: String,
    pub tenant_id: String,
    pub key_id: String,
    pub operation: HostedApiKeyLifecycleOperation,
    pub occurred_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum HostedApiKeyLifecycleOperation {
    Issued {
        principal_id: String,
        allowed_actions: BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<String>,
    },
    Revoked,
}

pub type SignedHostedApiKeyLifecycleEvent = SignedExportEnvelope<HostedApiKeyLifecycleEvent>;

pub fn verify_signed_hosted_api_key_lifecycle_event(
    receipt: &SignedHostedApiKeyLifecycleEvent,
    pinned_signer: &PublicKey,
) -> Result<(), HostedEdgeError> {
    if pinned_signer.algorithm() != SigningAlgorithm::Ed25519
        || pinned_signer.is_weak_ed25519()
        || receipt.signer_key != *pinned_signer
    {
        return Err(HostedEdgeError::AuthenticationFailed);
    }
    validate_event(&receipt.body)?;
    match pinned_signer.verify_canonical_strict(&receipt.body, &receipt.signature) {
        Ok(true) => Ok(()),
        _ => Err(HostedEdgeError::AuthenticationFailed),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedApiKeyIssueRequest {
    pub tenant_id: HostedTenantId,
    pub key_id: String,
    pub principal_id: String,
    pub allowed_actions: BTreeSet<String>,
    pub active_from: u64,
    pub expires_at: u64,
    pub rotated_from_key_id: Option<String>,
    pub issued_at: u64,
}

pub struct HostedApiKeySecret(String);

impl HostedApiKeySecret {
    /// Expose the one-time secret to the authorized provisioning response.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HostedApiKeySecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HostedApiKeySecret([REDACTED])")
    }
}

impl Drop for HostedApiKeySecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug)]
pub struct HostedIssuedApiKey {
    pub secret: HostedApiKeySecret,
    pub receipt: SignedHostedApiKeyLifecycleEvent,
}

#[async_trait]
pub trait HostedApiKeyLifecycleRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn issue_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        principal_id: &str,
        verifier_sha256: &str,
        allowed_actions: &BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<&str>,
        event_id: &str,
        artifact_json: &[u8],
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError>;

    async fn revoke_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        revoked_at: u64,
        event_id: &str,
        artifact_json: &[u8],
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError>;
}

#[async_trait]
impl HostedApiKeyLifecycleRepository for PostgresFindingMarketStore {
    async fn issue_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        principal_id: &str,
        verifier_sha256: &str,
        allowed_actions: &BTreeSet<String>,
        active_from: u64,
        expires_at: u64,
        rotated_from_key_id: Option<&str>,
        event_id: &str,
        artifact_json: &[u8],
        now: u64,
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.put_api_key_with_security_event(
            tenant,
            key_id,
            principal_id,
            verifier_sha256,
            allowed_actions,
            active_from,
            expires_at,
            rotated_from_key_id,
            event_id,
            API_KEY_ISSUED_EVENT_KIND,
            artifact_json,
            now,
        )
        .await
    }

    async fn revoke_with_event(
        &self,
        tenant: &HostedTenantId,
        key_id: &str,
        revoked_at: u64,
        event_id: &str,
        artifact_json: &[u8],
    ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
        self.revoke_api_key_with_security_event(
            tenant,
            key_id,
            revoked_at,
            event_id,
            API_KEY_REVOKED_EVENT_KIND,
            artifact_json,
        )
        .await
    }
}

pub struct HostedApiKeyManager {
    repository: Arc<dyn HostedApiKeyLifecycleRepository>,
    pepper: Arc<dyn ApiKeyPepper>,
    signer: Arc<dyn SigningBackend>,
}

impl HostedApiKeyManager {
    pub fn new(
        repository: Arc<dyn HostedApiKeyLifecycleRepository>,
        pepper: Arc<dyn ApiKeyPepper>,
        signer: Arc<dyn SigningBackend>,
    ) -> Result<Self, HostedEdgeError> {
        let public_key = signer.public_key();
        if signer.algorithm() != SigningAlgorithm::Ed25519
            || public_key.algorithm() != SigningAlgorithm::Ed25519
            || public_key.is_weak_ed25519()
        {
            return Err(HostedEdgeError::Configuration);
        }
        Ok(Self {
            repository,
            pepper,
            signer,
        })
    }

    pub async fn issue(
        &self,
        request: HostedApiKeyIssueRequest,
    ) -> Result<HostedIssuedApiKey, HostedEdgeError> {
        validate_issue(&request)?;
        let mut random = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(random.as_mut());
        let secret = HostedApiKeySecret(URL_SAFE_NO_PAD.encode(random.as_ref()));
        let verifier =
            self.pepper
                .hmac_verifier(&request.tenant_id, &request.key_id, random.as_ref())?;
        let receipt = self.sign_event(HostedApiKeyLifecycleEvent {
            schema: HOSTED_API_KEY_LIFECYCLE_SCHEMA.to_owned(),
            event_id: String::new(),
            tenant_id: request.tenant_id.as_str().to_owned(),
            key_id: request.key_id.clone(),
            operation: HostedApiKeyLifecycleOperation::Issued {
                principal_id: request.principal_id.clone(),
                allowed_actions: request.allowed_actions.clone(),
                active_from: request.active_from,
                expires_at: request.expires_at,
                rotated_from_key_id: request.rotated_from_key_id.clone(),
            },
            occurred_at: request.issued_at,
        })?;
        let artifact_json =
            canonical_json_bytes(&receipt).map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        let outcome = self
            .repository
            .issue_with_event(
                &request.tenant_id,
                &request.key_id,
                &request.principal_id,
                &verifier,
                &request.allowed_actions,
                request.active_from,
                request.expires_at,
                request.rotated_from_key_id.as_deref(),
                &receipt.body.event_id,
                &artifact_json,
                request.issued_at,
            )
            .await
            .map_err(map_store)?;
        if outcome != HostedJobWriteOutcome::Inserted {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(HostedIssuedApiKey { secret, receipt })
    }

    pub async fn revoke(
        &self,
        tenant_id: HostedTenantId,
        key_id: String,
        revoked_at: u64,
    ) -> Result<SignedHostedApiKeyLifecycleEvent, HostedEdgeError> {
        if !valid_bounded_identifier(&key_id, MAX_KEY_ID_BYTES) || revoked_at == 0 {
            return Err(HostedEdgeError::InvalidRequest);
        }
        let receipt = self.sign_event(HostedApiKeyLifecycleEvent {
            schema: HOSTED_API_KEY_LIFECYCLE_SCHEMA.to_owned(),
            event_id: String::new(),
            tenant_id: tenant_id.as_str().to_owned(),
            key_id: key_id.clone(),
            operation: HostedApiKeyLifecycleOperation::Revoked,
            occurred_at: revoked_at,
        })?;
        let artifact_json =
            canonical_json_bytes(&receipt).map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        self.repository
            .revoke_with_event(
                &tenant_id,
                &key_id,
                revoked_at,
                &receipt.body.event_id,
                &artifact_json,
            )
            .await
            .map_err(map_store)?;
        Ok(receipt)
    }

    fn sign_event(
        &self,
        mut event: HostedApiKeyLifecycleEvent,
    ) -> Result<SignedHostedApiKeyLifecycleEvent, HostedEdgeError> {
        event.event_id = compute_event_id(&event)?;
        let receipt = SignedExportEnvelope::sign_with_backend(event, self.signer.as_ref())
            .map_err(|_| HostedEdgeError::DependencyUnavailable)?;
        match receipt
            .signer_key
            .verify_canonical_strict(&receipt.body, &receipt.signature)
        {
            Ok(true) => Ok(receipt),
            _ => Err(HostedEdgeError::DependencyUnavailable),
        }
    }
}

fn compute_event_id(event: &HostedApiKeyLifecycleEvent) -> Result<String, HostedEdgeError> {
    let mut body = event.clone();
    body.event_id.clear();
    canonical_json_bytes(&body)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| HostedEdgeError::InvalidRequest)
}

fn validate_event(event: &HostedApiKeyLifecycleEvent) -> Result<(), HostedEdgeError> {
    if event.schema != HOSTED_API_KEY_LIFECYCLE_SCHEMA
        || !valid_identifier(&event.tenant_id)
        || !valid_identifier(&event.key_id)
        || event.occurred_at == 0
        || compute_event_id(event)? != event.event_id
    {
        return Err(HostedEdgeError::InvalidRequest);
    }
    let tenant_id = HostedTenantId::new(event.tenant_id.clone())
        .map_err(|_| HostedEdgeError::InvalidRequest)?;
    if let HostedApiKeyLifecycleOperation::Issued {
        principal_id,
        allowed_actions,
        active_from,
        expires_at,
        rotated_from_key_id,
    } = &event.operation
    {
        validate_issue(&HostedApiKeyIssueRequest {
            tenant_id,
            key_id: event.key_id.clone(),
            principal_id: principal_id.clone(),
            allowed_actions: allowed_actions.clone(),
            active_from: *active_from,
            expires_at: *expires_at,
            rotated_from_key_id: rotated_from_key_id.clone(),
            issued_at: event.occurred_at,
        })?;
    }
    Ok(())
}

fn validate_issue(request: &HostedApiKeyIssueRequest) -> Result<(), HostedEdgeError> {
    if !valid_bounded_identifier(&request.key_id, MAX_KEY_ID_BYTES)
        || !valid_identifier(&request.principal_id)
        || request.allowed_actions.is_empty()
        || request.allowed_actions.len() > MAX_ACTIONS
        || request
            .allowed_actions
            .iter()
            .any(|action| !valid_bounded_identifier(action, MAX_ACTION_BYTES))
        || request.active_from == 0
        || request.expires_at <= request.active_from
        || request.issued_at == 0
        || request.issued_at > request.active_from
        || request
            .rotated_from_key_id
            .as_deref()
            .is_some_and(|previous| {
                !valid_bounded_identifier(previous, MAX_KEY_ID_BYTES) || previous == request.key_id
            })
    {
        return Err(HostedEdgeError::InvalidRequest);
    }
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    valid_bounded_identifier(value, MAX_IDENTIFIER_BYTES)
}

fn valid_bounded_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn map_store(error: HostedMarketStoreError) -> HostedEdgeError {
    match error {
        HostedMarketStoreError::Capacity => HostedEdgeError::CapacityUnavailable,
        HostedMarketStoreError::Unavailable => HostedEdgeError::DependencyUnavailable,
        _ => HostedEdgeError::InvalidRequest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::Ed25519Backend;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockRepository {
        artifacts: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl HostedApiKeyLifecycleRepository for MockRepository {
        async fn issue_with_event(
            &self,
            _tenant: &HostedTenantId,
            _key_id: &str,
            _principal_id: &str,
            _verifier_sha256: &str,
            _allowed_actions: &BTreeSet<String>,
            _active_from: u64,
            _expires_at: u64,
            _rotated_from_key_id: Option<&str>,
            _event_id: &str,
            artifact_json: &[u8],
            _now: u64,
        ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
            self.artifacts
                .lock()
                .map_err(|_| HostedMarketStoreError::Unavailable)?
                .push(artifact_json.to_vec());
            Ok(HostedJobWriteOutcome::Inserted)
        }

        async fn revoke_with_event(
            &self,
            _tenant: &HostedTenantId,
            _key_id: &str,
            _revoked_at: u64,
            _event_id: &str,
            artifact_json: &[u8],
        ) -> Result<HostedJobWriteOutcome, HostedMarketStoreError> {
            self.artifacts
                .lock()
                .map_err(|_| HostedMarketStoreError::Unavailable)?
                .push(artifact_json.to_vec());
            Ok(HostedJobWriteOutcome::Inserted)
        }
    }

    #[tokio::test]
    async fn issue_and_revocation_emit_verified_secret_free_receipts(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tenant = HostedTenantId::new("tenant-a")?;
        let repository = Arc::new(MockRepository::default());
        let pepper = Arc::new(crate::StaticApiKeyPepper::new(vec![9; 32])?);
        let signer = Arc::new(Ed25519Backend::generate());
        let manager = HostedApiKeyManager::new(repository.clone(), pepper, signer)?;
        let issued = manager
            .issue(HostedApiKeyIssueRequest {
                tenant_id: tenant.clone(),
                key_id: "key-2".to_owned(),
                principal_id: "buyer-a".to_owned(),
                allowed_actions: ["finding.purchase".to_owned()].into_iter().collect(),
                active_from: 101,
                expires_at: 1_000,
                rotated_from_key_id: Some("key-1".to_owned()),
                issued_at: 100,
            })
            .await?;
        assert_eq!(issued.secret.expose().len(), 43);
        assert!(issued.receipt.verify_signature()?);
        verify_signed_hosted_api_key_lifecycle_event(&issued.receipt, &issued.receipt.signer_key)?;
        let serialized = canonical_json_bytes(&issued.receipt)?;
        assert!(!serialized
            .windows(issued.secret.expose().len())
            .any(|window| window == issued.secret.expose().as_bytes()));
        let revoked = manager.revoke(tenant, "key-2".to_owned(), 200).await?;
        assert!(revoked.verify_signature()?);
        assert_eq!(
            repository.artifacts.lock().map_err(|_| "poisoned")?.len(),
            2
        );
        Ok(())
    }
}
