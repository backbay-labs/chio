use chio_core::capability::{
    runtime_attestation::RuntimeAttestationEvidence,
    scope::ChioScope,
    token::{CapabilityToken, CapabilityTokenBody},
};
use chio_core::crypto::{Keypair, PublicKey};
use uuid::Uuid;

use crate::KernelError;

pub trait CapabilityAuthority: Send + Sync {
    fn authority_public_key(&self) -> PublicKey;

    fn trusted_public_keys(&self) -> Vec<PublicKey> {
        vec![self.authority_public_key()]
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError>;

    fn issue_capability_with_attestation(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
        _runtime_attestation: Option<RuntimeAttestationEvidence>,
    ) -> Result<CapabilityToken, KernelError> {
        self.issue_capability(subject, scope, ttl_seconds)
    }
}

pub struct LocalCapabilityAuthority {
    keypair: Keypair,
}

impl LocalCapabilityAuthority {
    pub fn new(keypair: Keypair) -> Self {
        Self { keypair }
    }
}

impl CapabilityAuthority for LocalCapabilityAuthority {
    fn authority_public_key(&self) -> PublicKey {
        self.keypair.public_key()
    }

    fn issue_capability(
        &self,
        subject: &PublicKey,
        scope: ChioScope,
        ttl_seconds: u64,
    ) -> Result<CapabilityToken, KernelError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let body = CapabilityTokenBody {
            id: format!("cap-{}", Uuid::now_v7()),
            issuer: self.keypair.public_key(),
            subject: subject.clone(),
            scope,
            issued_at: now,
            expires_at: now.saturating_add(ttl_seconds),
            delegation_chain: vec![],
        };

        CapabilityToken::sign(body, &self.keypair)
            .map_err(|error| KernelError::CapabilityIssuanceFailed(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityStatus {
    pub public_key: PublicKey,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_public_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustedKeySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub activated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritySnapshot {
    pub public_key_hex: String,
    pub generation: u64,
    pub rotated_at: u64,
    pub trusted_keys: Vec<AuthorityTrustedKeySnapshot>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorityStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("failed to prepare authority store directory: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid authority seed: {0}")]
    Core(#[from] chio_core::error::Error),

    #[error("authority fence rejected mutation: {0}")]
    Fence(String),

    #[error("{0}")]
    Schema(String),
}
