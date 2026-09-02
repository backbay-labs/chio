use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_core_types::{
    canonical_json_bytes, sha256_hex, PublicKey, SigningAlgorithm, SigningBackend,
};
use chio_finding_market_port::{HostedMarketPortError, HostedPortWriteOutcome, HostedTenantId};
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{ApiKeyPepper, HostedEdgeError};

/// Schema identifier pinned by every API-key lifecycle event.
pub const HOSTED_API_KEY_LIFECYCLE_SCHEMA: &str = "chio.finding.hosted-api-key-lifecycle.v1";
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_ACTION_BYTES: usize = 96;
const MAX_ACTIONS: usize = 64;
const API_KEY_SECRET_BYTES: usize = 32;

/// Signed record of one API-key issue or revoke, chained to the
/// previous event for the same key.
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

/// Lifecycle operations a signed event can record.
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

/// Signed lifecycle event envelope.
pub type SignedHostedApiKeyLifecycleEvent = SignedExportEnvelope<HostedApiKeyLifecycleEvent>;

/// Fail closed unless the envelope verifies under the expected signer
/// and carries the pinned schema.
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

/// Everything one key issuance fixes: tenant, principal, allowed
/// actions, and the validity window.
#[derive(Debug)]
pub struct HostedApiKeyIssueRequest {
    pub tenant_id: HostedTenantId,
    pub key_id: String,
    pub principal_id: String,
    pub allowed_actions: BTreeSet<String>,
    pub active_from: u64,
    pub expires_at: u64,
    pub rotated_from_key_id: Option<String>,
    pub issued_at: u64,
    /// Caller-held secret. The caller must retain this value until it receives
    /// a successful response so an exact retry can recover from response loss.
    pub secret: HostedApiKeySecret,
}

/// A freshly generated or parsed API-key secret; exposure is explicit
/// and Debug output is redacted.
pub struct HostedApiKeySecret(String);

impl HostedApiKeySecret {
    /// Generate a secret for a caller-held issuance request.
    #[must_use]
    pub fn generate() -> Self {
        let mut random = Zeroizing::new([0_u8; API_KEY_SECRET_BYTES]);
        OsRng.fill_bytes(random.as_mut());
        Self(URL_SAFE_NO_PAD.encode(random.as_ref()))
    }

    /// Parse a canonical caller-held secret for an exact issuance retry.
    pub fn parse(encoded: String) -> Result<Self, HostedEdgeError> {
        let secret = Self(encoded);
        secret.decoded()?;
        Ok(secret)
    }

    /// Expose the one-time secret to the authorized provisioning response.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    fn decoded(&self) -> Result<Zeroizing<Vec<u8>>, HostedEdgeError> {
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(self.0.as_bytes())
                .map_err(|_| HostedEdgeError::InvalidRequest)?,
        );
        if decoded.len() != API_KEY_SECRET_BYTES
            || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != self.0
        {
            return Err(HostedEdgeError::InvalidRequest);
        }
        Ok(decoded)
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

/// The stored record and one-time secret returned by an issuance.
#[derive(Debug)]
pub struct HostedIssuedApiKey {
    pub secret: HostedApiKeySecret,
    pub receipt: SignedHostedApiKeyLifecycleEvent,
}

pub use chio_finding_market_port::HostedApiKeyLifecyclePort as HostedApiKeyLifecycleRepository;

/// Issues and revokes API keys through the durable lifecycle port,
/// signing a lifecycle event for every mutation.
pub struct HostedApiKeyManager {
    repository: Arc<dyn HostedApiKeyLifecycleRepository>,
    pepper: Arc<dyn ApiKeyPepper>,
    signer: Arc<dyn SigningBackend>,
}

impl HostedApiKeyManager {
    /// Fail closed unless the manager configuration and signer validate.
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

    /// Issue one key: persist the record, then sign and store its
    /// lifecycle event.
    pub async fn issue(
        &self,
        request: HostedApiKeyIssueRequest,
    ) -> Result<HostedIssuedApiKey, HostedEdgeError> {
        validate_issue(&request)?;
        let secret_bytes = request.secret.decoded()?;
        let verifier = self.pepper.hmac_verifier(
            &request.tenant_id,
            &request.key_id,
            secret_bytes.as_slice(),
        )?;
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
        if !matches!(
            outcome,
            HostedPortWriteOutcome::Inserted | HostedPortWriteOutcome::ExactReplay
        ) {
            return Err(HostedEdgeError::DependencyUnavailable);
        }
        Ok(HostedIssuedApiKey {
            secret: request.secret,
            receipt,
        })
    }

    /// Revoke one key and sign the revocation event.
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
    HostedTenantId::new(event.tenant_id.clone()).map_err(|_| HostedEdgeError::InvalidRequest)?;
    if let HostedApiKeyLifecycleOperation::Issued {
        principal_id,
        allowed_actions,
        active_from,
        expires_at,
        rotated_from_key_id,
    } = &event.operation
    {
        validate_issue_fields(
            &event.key_id,
            principal_id,
            allowed_actions,
            *active_from,
            *expires_at,
            rotated_from_key_id.as_deref(),
            event.occurred_at,
        )?;
    }
    Ok(())
}

fn validate_issue(request: &HostedApiKeyIssueRequest) -> Result<(), HostedEdgeError> {
    validate_issue_fields(
        &request.key_id,
        &request.principal_id,
        &request.allowed_actions,
        request.active_from,
        request.expires_at,
        request.rotated_from_key_id.as_deref(),
        request.issued_at,
    )?;
    request.secret.decoded().map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn validate_issue_fields(
    key_id: &str,
    principal_id: &str,
    allowed_actions: &BTreeSet<String>,
    active_from: u64,
    expires_at: u64,
    rotated_from_key_id: Option<&str>,
    issued_at: u64,
) -> Result<(), HostedEdgeError> {
    if !valid_bounded_identifier(key_id, MAX_KEY_ID_BYTES)
        || !valid_identifier(principal_id)
        || allowed_actions.is_empty()
        || allowed_actions.len() > MAX_ACTIONS
        || allowed_actions
            .iter()
            .any(|action| !valid_bounded_identifier(action, MAX_ACTION_BYTES))
        || active_from == 0
        || expires_at <= active_from
        || issued_at == 0
        || issued_at > active_from
        || rotated_from_key_id.is_some_and(|previous| {
            !valid_bounded_identifier(previous, MAX_KEY_ID_BYTES) || previous == key_id
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

fn map_store(error: HostedMarketPortError) -> HostedEdgeError {
    match error {
        HostedMarketPortError::Capacity => HostedEdgeError::CapacityUnavailable,
        HostedMarketPortError::Unavailable => HostedEdgeError::DependencyUnavailable,
        _ => HostedEdgeError::InvalidRequest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chio_core::Ed25519Backend;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MockRepository {
        artifacts: Mutex<Vec<Vec<u8>>>,
        issued: Mutex<Option<(String, Vec<u8>)>>,
    }

    #[async_trait]
    impl HostedApiKeyLifecycleRepository for MockRepository {
        async fn issue_with_event(
            &self,
            _tenant: &HostedTenantId,
            _key_id: &str,
            _principal_id: &str,
            verifier_sha256: &str,
            _allowed_actions: &BTreeSet<String>,
            _active_from: u64,
            _expires_at: u64,
            _rotated_from_key_id: Option<&str>,
            _event_id: &str,
            artifact_json: &[u8],
            _now: u64,
        ) -> Result<HostedPortWriteOutcome, HostedMarketPortError> {
            let candidate = (verifier_sha256.to_owned(), artifact_json.to_vec());
            let mut issued = self
                .issued
                .lock()
                .map_err(|_| HostedMarketPortError::Unavailable)?;
            if let Some(existing) = issued.as_ref() {
                return if existing == &candidate {
                    Ok(HostedPortWriteOutcome::ExactReplay)
                } else {
                    Err(HostedMarketPortError::Conflict)
                };
            }
            *issued = Some(candidate);
            self.artifacts
                .lock()
                .map_err(|_| HostedMarketPortError::Unavailable)?
                .push(artifact_json.to_vec());
            Ok(HostedPortWriteOutcome::Inserted)
        }

        async fn revoke_with_event(
            &self,
            _tenant: &HostedTenantId,
            _key_id: &str,
            _revoked_at: u64,
            _event_id: &str,
            artifact_json: &[u8],
        ) -> Result<HostedPortWriteOutcome, HostedMarketPortError> {
            self.artifacts
                .lock()
                .map_err(|_| HostedMarketPortError::Unavailable)?
                .push(artifact_json.to_vec());
            Ok(HostedPortWriteOutcome::Inserted)
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
                secret: HostedApiKeySecret::generate(),
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

    #[tokio::test]
    async fn caller_held_secret_makes_response_loss_retry_exact(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let tenant = HostedTenantId::new("tenant-a")?;
        let repository = Arc::new(MockRepository::default());
        let pepper = Arc::new(crate::StaticApiKeyPepper::new(vec![9; 32])?);
        let signer = Arc::new(Ed25519Backend::generate());
        let manager = HostedApiKeyManager::new(repository.clone(), pepper, signer)?;
        let caller_secret = HostedApiKeySecret::generate().expose().to_owned();
        let request = |secret| HostedApiKeyIssueRequest {
            tenant_id: tenant.clone(),
            key_id: "key-retry".to_owned(),
            principal_id: "buyer-a".to_owned(),
            allowed_actions: ["finding.purchase".to_owned()].into_iter().collect(),
            active_from: 101,
            expires_at: 1_000,
            rotated_from_key_id: None,
            issued_at: 100,
            secret,
        };

        let first = manager
            .issue(request(HostedApiKeySecret::parse(caller_secret.clone())?))
            .await?;
        let retry = manager
            .issue(request(HostedApiKeySecret::parse(caller_secret.clone())?))
            .await?;

        assert_eq!(first.secret.expose(), caller_secret);
        assert_eq!(retry.secret.expose(), caller_secret);
        assert_eq!(first.receipt, retry.receipt);
        assert_eq!(
            repository.artifacts.lock().map_err(|_| "poisoned")?.len(),
            1
        );
        Ok(())
    }
}
