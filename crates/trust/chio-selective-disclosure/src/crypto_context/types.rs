use serde::{Deserialize, Serialize};

use crate::SelectiveDisclosureError;

pub use chio_disclosure_lineage::{
    DisclosureVerifierPrivacyProfile, TransparencyState,
    DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
};

pub const CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1: &str = "chio.crypto.verification-context.v1";
pub const TRUST_KEY_STATE_SCHEMA_V1: &str = "chio.trust.key-state.v1";
pub const TRUST_REVOCATION_SNAPSHOT_SCHEMA_V1: &str = "chio.trust.revocation-snapshot.v1";
pub use chio_disclosure_lineage::{
    DisclosureContextCheck, DisclosureContextVerdict, DisclosureCryptoContextReport,
    DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DisclosureCryptoContextError {
    #[error("{0}")]
    SelectiveDisclosure(#[from] SelectiveDisclosureError),
    #[error("invalid disclosure crypto context: {0}")]
    InvalidContext(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CryptoVerificationContext {
    pub schema: String,
    pub context_id: String,
    pub artifact_ref: String,
    pub proof_mechanism: String,
    pub issuer: String,
    pub issuer_key_ref: String,
    pub key_state: DisclosureKeyState,
    pub algorithm: String,
    pub suite: String,
    pub hash_algorithm: String,
    pub canonicalization: String,
    pub signature_ref: String,
    pub verification_time: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_snapshot: Option<DisclosureRevocationSnapshot>,
    pub audience: String,
    pub nonce_hex: String,
    pub nonce_replay_status: NonceReplayStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder_binding_ref: Option<String>,
    pub holder_binding_status: HolderBindingStatus,
    pub transparency_state: TransparencyState,
    pub presentation_created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureKeyState {
    pub schema: String,
    pub key_ref: String,
    pub status: KeyStateStatus,
    pub epoch: u64,
    pub valid_from: u64,
    pub valid_until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DisclosureRevocationSnapshot {
    pub schema: String,
    pub snapshot_ref: String,
    pub status: RevocationSnapshotStatus,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStateStatus {
    Active,
    Stale,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RevocationSnapshotStatus {
    Fresh,
    Stale,
    Revoked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NonceReplayStatus {
    Fresh,
    Replayed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HolderBindingStatus {
    Bound,
    Missing,
    Mismatch,
}
