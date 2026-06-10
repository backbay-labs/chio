use serde::{Deserialize, Serialize};

pub type Result<T> = core::result::Result<T, RevocationOracleError>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevocationOracleError {
    #[error("revocation key already exists")]
    AlreadyRevoked,
    #[error("revocation key not found")]
    NotRevoked,
    #[error("proof does not match oracle root")]
    InvalidProof,
    #[error("oracle root is stale")]
    StaleRoot,
    #[error("signer rejected epoch root")]
    SignerRejected,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("invalid epoch transition")]
    InvalidEpochTransition,
    #[error("invalid revocation key: {0}")]
    InvalidRevocationKey(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SubjectId(String);

impl SubjectId {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for SubjectId {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for SubjectId {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EpochNonce(u64);

impl EpochNonce {
    #[must_use]
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RevocationKey {
    pub subject_id: SubjectId,
    pub epoch_nonce: EpochNonce,
}

impl RevocationKey {
    #[must_use]
    pub fn new(subject_id: impl Into<SubjectId>, epoch_nonce: EpochNonce) -> Self {
        Self {
            subject_id: subject_id.into(),
            epoch_nonce,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRoot {
    pub epoch: u64,
    pub root_hash: [u8; 32],
    pub leaf_count: usize,
    pub issued_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootSignature {
    pub signer_id: String,
    pub algorithm: String,
    pub signature_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub key: RevocationKey,
    pub epoch_root: EpochRoot,
    pub leaf_index: usize,
    pub leaf_hash: [u8; 32],
    pub proof_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonInclusionProof {
    pub key: RevocationKey,
    pub epoch_root: EpochRoot,
    pub checked_at_unix_ms: u64,
}

pub trait RevocationOracle {
    fn insert(&mut self, key: RevocationKey, now_unix_ms: u64) -> Result<EpochRoot>;
    fn contains(&self, key: &RevocationKey) -> bool;
    fn epoch_root(&self) -> EpochRoot;
    fn inclusion_proof(&self, key: &RevocationKey) -> Result<InclusionProof>;
    fn non_inclusion_proof(
        &self,
        key: RevocationKey,
        now_unix_ms: u64,
    ) -> Result<NonInclusionProof>;
}
