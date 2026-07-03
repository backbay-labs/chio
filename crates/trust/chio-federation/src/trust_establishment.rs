//! Cross-kernel trust establishment via mTLS-style handshake.
//!
//! Two kernels bootstrap mutual trust by exchanging signed challenges and
//! pinning each other's kernel signing public keys. Once pinned, the
//! [`FederationPeer`] set lives alongside the other federation-state
//! primitives (activation, governance, and reputation artifacts) and shares
//! their persistence semantics: in-memory by default, pluggable store.
//!
//! ## Handshake summary
//!
//! 1. Each side builds a [`HandshakeChallenge`] binding `(local_kernel_id,
//!    remote_kernel_id, nonce, timestamp)` and signs it with its own
//!    kernel key. The `nonce` is a per-handshake unique value bound into
//!    the signature so two handshake envelopes are never byte-identical;
//!    this crate does NOT itself track previously-seen nonces, so
//!    transport-layer replay protection (e.g., the mTLS finished message
//!    or an idempotency window upstream of [`KernelTrustExchange::accept_envelope`])
//!    is what prevents an attacker from re-presenting a captured envelope
//!    inside the freshness window. The local-clock-derived
//!    `rotation_due` enforces the freshness ceiling regardless.
//! 2. Peers exchange their [`PeerHandshakeEnvelope`] (challenge + signature
//!    + declared public key).
//! 3. Each side verifies the remote envelope's signature against the
//!    declared public key, checks freshness (`timestamp` skew against the
//!    local clock), verifies that the key matches either a pre-configured
//!    trust anchor or an already-pinned peer, and then pins the remote
//!    public key as a [`FederationPeer`] with a rotation deadline derived
//!    from the configured freshness window.
//!
//! ## Freshness rotation
//!
//! A [`FederationPeer`] carries a `rotation_due` timestamp. After that
//! timestamp the peer is considered stale and is refused fail-closed by
//! [`KernelTrustExchange::resolve`]; the two kernels must re-run the
//! handshake to re-pin the key. Rotation never silently renews: the
//! caller must explicitly issue a new handshake.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::features::CapabilityNegotiation;
use chio_core_types::crypto::{Ed25519Backend, Keypair, PublicKey, Signature, SigningBackend};
use serde::{Deserialize, Serialize};

pub const FEDERATION_HANDSHAKE_SCHEMA: &str = "chio.federation-kernel-handshake.v1";

/// Default freshness window applied to newly-pinned peers when the caller
/// does not override it. Twelve hours strikes a balance between operator
/// ergonomics (no paging at 3am to re-handshake) and the bounded-trust
/// guarantee the federation layer promises.
pub const DEFAULT_ROTATION_WINDOW_SECS: u64 = 12 * 60 * 60;

/// Maximum clock skew tolerated between the two kernels during a
/// handshake. Envelopes older or further-in-the-future than this window
/// are rejected.
pub const DEFAULT_HANDSHAKE_MAX_SKEW_SECS: u64 = 5 * 60;

/// Basis-point denominator used for conformance evidence percentages.
pub const CONFORMANCE_BPS_DENOMINATOR: u32 = 10_000;
/// Minimum threat-coverage score for the Silver federation conformance tier.
pub const SILVER_MIN_THREAT_COVERAGE_BPS: u32 = 9_000;
/// Minimum mutation-kill score for the Silver federation conformance tier.
pub const SILVER_MIN_MUTATION_KILL_BPS: u32 = 6_500;
/// Minimum Kani trust-boundary crate count for Silver.
pub const SILVER_MIN_KANI_TRUST_BOUNDARY_CRATES: u32 = 4;
/// Minimum threat-coverage score for the Gold federation conformance tier.
pub const GOLD_MIN_THREAT_COVERAGE_BPS: u32 = CONFORMANCE_BPS_DENOMINATOR;
/// Minimum mutation-kill score for the Gold federation conformance tier.
pub const GOLD_MIN_MUTATION_KILL_BPS: u32 = 8_000;
/// Minimum Kani trust-boundary crate count for Gold.
pub const GOLD_MIN_KANI_TRUST_BOUNDARY_CRATES: u32 = 8;

/// Signed handshake reference to the ladder manifest a peer will enforce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderManifestRef {
    pub manifest_id: String,
    pub sha256: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

impl LadderManifestRef {
    pub fn validate(&self) -> Result<(), PeerHandshakeError> {
        if self.manifest_id.trim().is_empty() {
            return Err(PeerHandshakeError::InvalidLadderManifestRef(
                "manifest_id must not be empty".to_string(),
            ));
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PeerHandshakeError::InvalidLadderManifestRef(
                "sha256 must be a 64-character SHA-256 hex digest".to_string(),
            ));
        }
        if self.expires_at_unix_ms <= self.issued_at_unix_ms {
            return Err(PeerHandshakeError::InvalidLadderManifestRef(
                "expires_at_unix_ms must be greater than issued_at_unix_ms".to_string(),
            ));
        }
        Ok(())
    }

    pub fn is_fresh(&self, now_unix_ms: u64) -> bool {
        self.issued_at_unix_ms <= now_unix_ms && now_unix_ms < self.expires_at_unix_ms
    }
}

/// Cross-surface conformance tier advertised during federation handshakes.
///
/// The order is intentional: `Gold > Silver > Bronze`, so policy checks can
/// use ordinary ordering to fail closed when a peer is below the configured
/// floor.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceTier {
    /// Schema-valid evidence is present but the peer does not meet Silver.
    #[default]
    Bronze,
    /// Threat coverage >= 90%, mutation kill >= 65%, and >= 4 Kani
    /// trust-boundary crate harnesses.
    Silver,
    /// Threat coverage = 100%, mutation kill >= 80%, and >= 8 Kani
    /// trust-boundary crate harnesses.
    Gold,
}

/// Evidence inputs used to derive a federation conformance tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConformanceEvidence {
    pub threat_coverage_bps: u32,
    pub mutation_kill_bps: u32,
    pub kani_trust_boundary_crates: u32,
}

impl ConformanceEvidence {
    /// Derive a stable Bronze/Silver/Gold tier from the evidence metrics.
    pub fn derive_tier(&self) -> Result<ConformanceTier, PeerHandshakeError> {
        if self.threat_coverage_bps > CONFORMANCE_BPS_DENOMINATOR {
            return Err(PeerHandshakeError::InvalidConformanceEvidence(format!(
                "threat_coverage_bps must be <= {CONFORMANCE_BPS_DENOMINATOR}"
            )));
        }
        if self.mutation_kill_bps > CONFORMANCE_BPS_DENOMINATOR {
            return Err(PeerHandshakeError::InvalidConformanceEvidence(format!(
                "mutation_kill_bps must be <= {CONFORMANCE_BPS_DENOMINATOR}"
            )));
        }

        if self.threat_coverage_bps >= GOLD_MIN_THREAT_COVERAGE_BPS
            && self.mutation_kill_bps >= GOLD_MIN_MUTATION_KILL_BPS
            && self.kani_trust_boundary_crates >= GOLD_MIN_KANI_TRUST_BOUNDARY_CRATES
        {
            return Ok(ConformanceTier::Gold);
        }
        if self.threat_coverage_bps >= SILVER_MIN_THREAT_COVERAGE_BPS
            && self.mutation_kill_bps >= SILVER_MIN_MUTATION_KILL_BPS
            && self.kani_trust_boundary_crates >= SILVER_MIN_KANI_TRUST_BOUNDARY_CRATES
        {
            return Ok(ConformanceTier::Silver);
        }
        Ok(ConformanceTier::Bronze)
    }
}

/// Policy applied when admitting a federation peer into a quorum set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QuorumPolicy {
    pub min_tier: ConformanceTier,
}

impl Default for QuorumPolicy {
    fn default() -> Self {
        Self {
            min_tier: ConformanceTier::Bronze,
        }
    }
}

impl QuorumPolicy {
    /// Return true when `actual` satisfies this policy's tier floor.
    #[must_use]
    pub fn accepts_tier(&self, actual: ConformanceTier) -> bool {
        actual >= self.min_tier
    }
}

/// Pinned federation peer entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationPeer {
    pub kernel_id: String,
    pub public_key: PublicKey,
    /// Cross-surface conformance tier that was signed into the peer's most
    /// recent accepted handshake.
    #[serde(default)]
    pub conformance_tier: ConformanceTier,
    /// Unix seconds at which the peer was last pinned via a successful
    /// handshake.
    pub established_at: u64,
    /// Unix seconds at which the pin expires. After this timestamp the
    /// peer is treated as stale and MUST be re-handshaked before any
    /// federation-level operation is accepted against it.
    pub rotation_due: u64,
    /// Peer-advertised protocol feature bitset. Missing on compatibility peers
    /// defaults to current capability semantics without optional features.
    #[serde(default)]
    pub capabilities: CapabilityNegotiation,
    /// Optional signed ladder manifest reference accepted during handshake.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ladder_manifest_ref: Option<LadderManifestRef>,
}

impl FederationPeer {
    /// Returns `true` when the peer's pin is still within its freshness
    /// window relative to `now`.
    pub fn is_fresh(&self, now: u64) -> bool {
        now < self.rotation_due
    }
}

/// Challenge body signed by one kernel during the handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeChallenge {
    pub schema: String,
    pub local_kernel_id: String,
    pub remote_kernel_id: String,
    pub nonce: String,
    pub timestamp: u64,
    #[serde(default, skip_serializing_if = "is_default_capability_negotiation")]
    pub capabilities: CapabilityNegotiation,
    #[serde(default, skip_serializing_if = "is_default_conformance_tier")]
    pub conformance_tier: ConformanceTier,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ladder_manifest_ref: Option<LadderManifestRef>,
}

impl HandshakeChallenge {
    pub fn new(
        local_kernel_id: impl Into<String>,
        remote_kernel_id: impl Into<String>,
        nonce: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self::new_with_conformance_tier(
            local_kernel_id,
            remote_kernel_id,
            nonce,
            timestamp,
            ConformanceTier::Bronze,
        )
    }

    pub fn new_with_conformance_tier(
        local_kernel_id: impl Into<String>,
        remote_kernel_id: impl Into<String>,
        nonce: impl Into<String>,
        timestamp: u64,
        conformance_tier: ConformanceTier,
    ) -> Self {
        Self {
            schema: FEDERATION_HANDSHAKE_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.into(),
            remote_kernel_id: remote_kernel_id.into(),
            nonce: nonce.into(),
            timestamp,
            capabilities: CapabilityNegotiation::v1_default(),
            conformance_tier,
            ladder_manifest_ref: None,
        }
    }

    #[must_use]
    pub fn with_capabilities(mut self, capabilities: CapabilityNegotiation) -> Self {
        self.capabilities = capabilities;
        self
    }

    #[must_use]
    pub fn with_ladder_manifest_ref(mut self, ladder_manifest_ref: LadderManifestRef) -> Self {
        self.ladder_manifest_ref = Some(ladder_manifest_ref);
        self
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PeerHandshakeError> {
        self.capabilities
            .validate()
            .map_err(|e| PeerHandshakeError::CapabilityNegotiation(e.to_string()))?;
        if let Some(ladder_manifest_ref) = &self.ladder_manifest_ref {
            ladder_manifest_ref.validate()?;
        }
        canonical_json_bytes(self).map_err(|e| PeerHandshakeError::CanonicalJson(e.to_string()))
    }
}

fn is_default_capability_negotiation(capabilities: &CapabilityNegotiation) -> bool {
    *capabilities == CapabilityNegotiation::v1_default()
}

fn is_default_conformance_tier(tier: &ConformanceTier) -> bool {
    *tier == ConformanceTier::Bronze
}

/// Envelope one kernel sends to the other during a handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerHandshakeEnvelope {
    pub challenge: HandshakeChallenge,
    pub declared_public_key: PublicKey,
    pub signature: Signature,
}

impl PeerHandshakeEnvelope {
    /// Build a signed handshake envelope from `local` addressed to `remote`.
    pub fn sign(
        local_kernel_id: &str,
        remote_kernel_id: &str,
        nonce: &str,
        timestamp: u64,
        local_keypair: &Keypair,
    ) -> Result<Self, PeerHandshakeError> {
        let backend = Ed25519Backend::new(local_keypair.clone());
        Self::sign_with_backend(
            local_kernel_id,
            remote_kernel_id,
            nonce,
            timestamp,
            ConformanceTier::Bronze,
            &backend,
        )
    }

    /// Build a signed handshake envelope from `local` addressed to `remote`
    /// using any Chio signing backend.
    pub fn sign_with_backend(
        local_kernel_id: &str,
        remote_kernel_id: &str,
        nonce: &str,
        timestamp: u64,
        conformance_tier: ConformanceTier,
        local_backend: &dyn SigningBackend,
    ) -> Result<Self, PeerHandshakeError> {
        Self::sign_with_backend_and_capabilities(
            local_kernel_id,
            remote_kernel_id,
            nonce,
            timestamp,
            conformance_tier,
            local_backend,
            CapabilityNegotiation::v1_default(),
        )
    }

    /// Build a signed handshake envelope with a signing backend, conformance
    /// tier, and explicit feature bitset.
    pub fn sign_with_backend_and_capabilities(
        local_kernel_id: &str,
        remote_kernel_id: &str,
        nonce: &str,
        timestamp: u64,
        conformance_tier: ConformanceTier,
        local_backend: &dyn SigningBackend,
        capabilities: CapabilityNegotiation,
    ) -> Result<Self, PeerHandshakeError> {
        Self::sign_with_backend_capabilities_and_ladder_ref(
            local_kernel_id,
            remote_kernel_id,
            nonce,
            timestamp,
            conformance_tier,
            local_backend,
            capabilities,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_backend_capabilities_and_ladder_ref(
        local_kernel_id: &str,
        remote_kernel_id: &str,
        nonce: &str,
        timestamp: u64,
        conformance_tier: ConformanceTier,
        local_backend: &dyn SigningBackend,
        capabilities: CapabilityNegotiation,
        ladder_manifest_ref: Option<LadderManifestRef>,
    ) -> Result<Self, PeerHandshakeError> {
        capabilities
            .validate()
            .map_err(|e| PeerHandshakeError::CapabilityNegotiation(e.to_string()))?;
        let mut challenge = HandshakeChallenge::new_with_conformance_tier(
            local_kernel_id,
            remote_kernel_id,
            nonce,
            timestamp,
            conformance_tier,
        )
        .with_capabilities(capabilities);
        if let Some(ladder_manifest_ref) = ladder_manifest_ref {
            challenge = challenge.with_ladder_manifest_ref(ladder_manifest_ref);
        }
        let bytes = challenge.canonical_bytes()?;
        let signature = local_backend
            .sign_bytes(&bytes)
            .map_err(|e| PeerHandshakeError::SigningFailed(e.to_string()))?;
        Ok(Self {
            challenge,
            declared_public_key: local_backend.public_key(),
            signature,
        })
    }

    /// Build a signed handshake envelope with an explicit feature bitset.
    pub fn sign_with_capabilities(
        local_kernel_id: &str,
        remote_kernel_id: &str,
        nonce: &str,
        timestamp: u64,
        local_keypair: &Keypair,
        capabilities: CapabilityNegotiation,
    ) -> Result<Self, PeerHandshakeError> {
        let backend = Ed25519Backend::new(local_keypair.clone());
        Self::sign_with_backend_and_capabilities(
            local_kernel_id,
            remote_kernel_id,
            nonce,
            timestamp,
            ConformanceTier::Bronze,
            &backend,
            capabilities,
        )
    }

    /// Verify this envelope in isolation (signature valid for declared
    /// public key; schema is the expected version). Callers still need to
    /// confirm the envelope targets them and fits within the freshness
    /// window: [`KernelTrustExchange::accept_envelope`] is the convenient
    /// one-shot version that enforces all of that.
    pub fn verify_signature(&self) -> Result<(), PeerHandshakeError> {
        if self.challenge.schema != FEDERATION_HANDSHAKE_SCHEMA {
            return Err(PeerHandshakeError::UnsupportedSchema(
                self.challenge.schema.clone(),
            ));
        }
        self.challenge
            .capabilities
            .validate()
            .map_err(|e| PeerHandshakeError::CapabilityNegotiation(e.to_string()))?;
        let bytes = self.challenge.canonical_bytes()?;
        if !self.declared_public_key.verify(&bytes, &self.signature) {
            return Err(PeerHandshakeError::InvalidSignature);
        }
        Ok(())
    }
}

/// Errors raised by the trust-establishment primitives. Every variant is
/// fail-closed: callers MUST refuse to pin a peer when any step fails.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PeerHandshakeError {
    #[error("unsupported handshake schema: {0}")]
    UnsupportedSchema(String),

    #[error("canonical JSON encoding failed: {0}")]
    CanonicalJson(String),

    #[error("handshake signing failed: {0}")]
    SigningFailed(String),

    #[error("remote handshake signature is invalid")]
    InvalidSignature,

    #[error("capability negotiation failed closed: {0}")]
    CapabilityNegotiation(String),

    #[error("remote envelope is addressed to kernel_id {addressed_to} but we are {actual}")]
    AddressMismatch {
        addressed_to: String,
        actual: String,
    },

    #[error("remote envelope declares self as kernel_id {declared} but we expected {expected}")]
    KernelIdMismatch { declared: String, expected: String },

    #[error("remote envelope timestamp {envelope} drifts from local clock {local} beyond {skew}s")]
    ClockSkewExceeded {
        envelope: u64,
        local: u64,
        skew: u64,
    },

    #[error("peer {0} is not pinned; run a handshake before resolving")]
    PeerNotPinned(String),

    #[error("peer {0} is stale and must be re-handshaked before use")]
    PeerStale(String),

    #[error("peer {0} is not trusted for first contact; configure a trust anchor before accepting handshakes")]
    MissingTrustAnchor(String),

    #[error("peer {kernel_id} declared unexpected public key; expected {expected}, got {actual}")]
    UnexpectedPeerKey {
        kernel_id: String,
        expected: String,
        actual: String,
    },

    #[error("peer {kernel_id} conformance tier {actual:?} is below required {minimum:?}")]
    ConformanceTierBelowMinimum {
        kernel_id: String,
        actual: ConformanceTier,
        minimum: ConformanceTier,
    },

    #[error("invalid conformance evidence: {0}")]
    InvalidConformanceEvidence(String),

    #[error("invalid ladder manifest reference: {0}")]
    InvalidLadderManifestRef(String),

    #[error("trust store is poisoned and cannot service requests")]
    StorePoisoned,
}

impl<T> From<PoisonError<T>> for PeerHandshakeError {
    fn from(_: PoisonError<T>) -> Self {
        PeerHandshakeError::StorePoisoned
    }
}

/// In-memory pinned-peer store used by [`KernelTrustExchange`]. A runtime
/// embedding can replace it with a persistent backing store by dropping a
/// new impl of the same trait in place; this crate keeps the default
/// lightweight for test-plane and single-host deployments.
pub trait FederationPeerStore: Send + Sync {
    fn insert(&self, peer: FederationPeer) -> Result<(), PeerHandshakeError>;
    fn get(&self, kernel_id: &str) -> Result<Option<FederationPeer>, PeerHandshakeError>;
    fn remove(&self, kernel_id: &str) -> Result<Option<FederationPeer>, PeerHandshakeError>;
    fn snapshot(&self) -> Result<Vec<FederationPeer>, PeerHandshakeError>;
}

/// Default in-memory peer store.
#[derive(Debug, Default)]
pub struct InMemoryPeerStore {
    inner: Mutex<HashMap<String, FederationPeer>>,
}

impl InMemoryPeerStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FederationPeerStore for InMemoryPeerStore {
    fn insert(&self, peer: FederationPeer) -> Result<(), PeerHandshakeError> {
        let mut guard = self.inner.lock()?;
        guard.insert(peer.kernel_id.clone(), peer);
        Ok(())
    }

    fn get(&self, kernel_id: &str) -> Result<Option<FederationPeer>, PeerHandshakeError> {
        let guard = self.inner.lock()?;
        Ok(guard.get(kernel_id).cloned())
    }

    fn remove(&self, kernel_id: &str) -> Result<Option<FederationPeer>, PeerHandshakeError> {
        let mut guard = self.inner.lock()?;
        Ok(guard.remove(kernel_id))
    }

    fn snapshot(&self) -> Result<Vec<FederationPeer>, PeerHandshakeError> {
        let guard = self.inner.lock()?;
        Ok(guard.values().cloned().collect())
    }
}

/// Configuration knobs for a [`KernelTrustExchange`]. Defaults match the
/// module-level constants.
#[derive(Debug, Clone, Copy)]
pub struct KernelTrustExchangeConfig {
    pub rotation_window_secs: u64,
    pub max_handshake_skew_secs: u64,
}

impl Default for KernelTrustExchangeConfig {
    fn default() -> Self {
        Self {
            rotation_window_secs: DEFAULT_ROTATION_WINDOW_SECS,
            max_handshake_skew_secs: DEFAULT_HANDSHAKE_MAX_SKEW_SECS,
        }
    }
}

/// Primitive that drives the mTLS-style key exchange between two kernels.
///
/// One [`KernelTrustExchange`] lives per local kernel. It owns the local
/// kernel's identity + signing keypair, a peer store, and a clock source.
/// Callers use [`KernelTrustExchange::local_envelope`] to build a
/// challenge envelope to send to the remote, and
/// [`KernelTrustExchange::accept_envelope`] to verify an incoming envelope
/// and pin the remote peer.
pub struct KernelTrustExchange {
    local_kernel_id: String,
    local_signing_backend: Box<dyn SigningBackend>,
    local_conformance_tier: ConformanceTier,
    config: KernelTrustExchangeConfig,
    store: Box<dyn FederationPeerStore>,
    trusted_peers: HashMap<String, PublicKey>,
    local_capabilities: CapabilityNegotiation,
    local_ladder_manifest_ref: Option<LadderManifestRef>,
}

impl core::fmt::Debug for KernelTrustExchange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelTrustExchange")
            .field("local_kernel_id", &self.local_kernel_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl KernelTrustExchange {
    pub fn new(local_kernel_id: impl Into<String>, local_keypair: Keypair) -> Self {
        Self::new_with_backend(
            local_kernel_id,
            Box::new(Ed25519Backend::new(local_keypair)),
        )
    }

    pub fn new_with_backend(
        local_kernel_id: impl Into<String>,
        local_signing_backend: Box<dyn SigningBackend>,
    ) -> Self {
        Self {
            local_kernel_id: local_kernel_id.into(),
            local_signing_backend,
            local_conformance_tier: ConformanceTier::Bronze,
            config: KernelTrustExchangeConfig::default(),
            store: Box::new(InMemoryPeerStore::new()),
            trusted_peers: HashMap::new(),
            local_capabilities: CapabilityNegotiation::v1_default(),
            local_ladder_manifest_ref: None,
        }
    }

    pub fn with_config(mut self, config: KernelTrustExchangeConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_store(mut self, store: Box<dyn FederationPeerStore>) -> Self {
        self.store = store;
        self
    }

    pub fn with_conformance_tier(mut self, conformance_tier: ConformanceTier) -> Self {
        self.local_conformance_tier = conformance_tier;
        self
    }

    pub fn with_trusted_peer(
        mut self,
        kernel_id: impl Into<String>,
        public_key: PublicKey,
    ) -> Self {
        self.trusted_peers.insert(kernel_id.into(), public_key);
        self
    }

    pub fn with_capabilities(mut self, capabilities: CapabilityNegotiation) -> Self {
        self.local_capabilities = capabilities;
        self
    }

    pub fn with_ladder_manifest_ref(mut self, ladder_manifest_ref: LadderManifestRef) -> Self {
        self.local_ladder_manifest_ref = Some(ladder_manifest_ref);
        self
    }

    pub fn local_kernel_id(&self) -> &str {
        &self.local_kernel_id
    }

    pub fn local_public_key(&self) -> PublicKey {
        self.local_signing_backend.public_key()
    }

    pub fn local_conformance_tier(&self) -> ConformanceTier {
        self.local_conformance_tier
    }

    pub fn local_capabilities(&self) -> &CapabilityNegotiation {
        &self.local_capabilities
    }

    pub fn rotation_window_secs(&self) -> u64 {
        self.config.rotation_window_secs
    }

    /// Build the local kernel's signed envelope addressed to `remote_kernel_id`.
    pub fn local_envelope(
        &self,
        remote_kernel_id: &str,
        nonce: &str,
        now: u64,
    ) -> Result<PeerHandshakeEnvelope, PeerHandshakeError> {
        PeerHandshakeEnvelope::sign_with_backend_capabilities_and_ladder_ref(
            &self.local_kernel_id,
            remote_kernel_id,
            nonce,
            now,
            self.local_conformance_tier,
            self.local_signing_backend.as_ref(),
            self.local_capabilities.clone(),
            self.local_ladder_manifest_ref.clone(),
        )
    }

    /// Build the local kernel's signed envelope with explicit capabilities.
    pub fn local_envelope_with_capabilities(
        &self,
        remote_kernel_id: &str,
        nonce: &str,
        now: u64,
        capabilities: CapabilityNegotiation,
    ) -> Result<PeerHandshakeEnvelope, PeerHandshakeError> {
        PeerHandshakeEnvelope::sign_with_backend_capabilities_and_ladder_ref(
            &self.local_kernel_id,
            remote_kernel_id,
            nonce,
            now,
            self.local_conformance_tier,
            self.local_signing_backend.as_ref(),
            capabilities,
            self.local_ladder_manifest_ref.clone(),
        )
    }

    /// Accept an envelope received from `expected_remote_kernel_id` at
    /// local clock `now`. Verifies the signature, the addressee, the
    /// claimed remote kernel ID, the clock skew, and the expected remote
    /// public key; on success, pins the remote public key as a fresh
    /// [`FederationPeer`].
    pub fn accept_envelope(
        &self,
        envelope: &PeerHandshakeEnvelope,
        expected_remote_kernel_id: &str,
        now: u64,
    ) -> Result<FederationPeer, PeerHandshakeError> {
        self.accept_envelope_with_policy(
            envelope,
            expected_remote_kernel_id,
            now,
            &QuorumPolicy::default(),
        )
    }

    /// Accept an envelope while enforcing a federation quorum tier floor.
    pub fn accept_envelope_with_policy(
        &self,
        envelope: &PeerHandshakeEnvelope,
        expected_remote_kernel_id: &str,
        now: u64,
        quorum_policy: &QuorumPolicy,
    ) -> Result<FederationPeer, PeerHandshakeError> {
        envelope.verify_signature()?;

        if envelope.challenge.remote_kernel_id != self.local_kernel_id {
            return Err(PeerHandshakeError::AddressMismatch {
                addressed_to: envelope.challenge.remote_kernel_id.clone(),
                actual: self.local_kernel_id.clone(),
            });
        }
        if envelope.challenge.local_kernel_id != expected_remote_kernel_id {
            return Err(PeerHandshakeError::KernelIdMismatch {
                declared: envelope.challenge.local_kernel_id.clone(),
                expected: expected_remote_kernel_id.to_string(),
            });
        }

        let envelope_ts = envelope.challenge.timestamp;
        let skew = self.config.max_handshake_skew_secs;
        let drift = envelope_ts.abs_diff(now);
        if drift > skew {
            return Err(PeerHandshakeError::ClockSkewExceeded {
                envelope: envelope_ts,
                local: now,
                skew,
            });
        }

        let pinned_peer = self.store.get(expected_remote_kernel_id)?;
        let expected_public_key = self
            .trusted_peers
            .get(expected_remote_kernel_id)
            .cloned()
            .or_else(|| pinned_peer.as_ref().map(|peer| peer.public_key.clone()))
            .ok_or_else(|| {
                PeerHandshakeError::MissingTrustAnchor(expected_remote_kernel_id.to_string())
            })?;
        if envelope.declared_public_key != expected_public_key {
            return Err(PeerHandshakeError::UnexpectedPeerKey {
                kernel_id: expected_remote_kernel_id.to_string(),
                expected: expected_public_key.to_hex(),
                actual: envelope.declared_public_key.to_hex(),
            });
        }

        if !quorum_policy.accepts_tier(envelope.challenge.conformance_tier) {
            return Err(PeerHandshakeError::ConformanceTierBelowMinimum {
                kernel_id: expected_remote_kernel_id.to_string(),
                actual: envelope.challenge.conformance_tier,
                minimum: quorum_policy.min_tier,
            });
        }

        let peer = FederationPeer {
            kernel_id: expected_remote_kernel_id.to_string(),
            public_key: envelope.declared_public_key.clone(),
            conformance_tier: envelope.challenge.conformance_tier,
            established_at: now,
            rotation_due: now.saturating_add(self.config.rotation_window_secs),
            capabilities: self
                .local_capabilities
                .negotiated_with(&envelope.challenge.capabilities)
                .map_err(|e| PeerHandshakeError::CapabilityNegotiation(e.to_string()))?,
            ladder_manifest_ref: envelope.challenge.ladder_manifest_ref.clone(),
        };
        self.store.insert(peer.clone())?;
        Ok(peer)
    }

    /// Resolve a pinned peer, refusing stale pins fail-closed.
    pub fn resolve(&self, kernel_id: &str, now: u64) -> Result<FederationPeer, PeerHandshakeError> {
        let Some(peer) = self.store.get(kernel_id)? else {
            return Err(PeerHandshakeError::PeerNotPinned(kernel_id.to_string()));
        };
        if !peer.is_fresh(now) {
            return Err(PeerHandshakeError::PeerStale(kernel_id.to_string()));
        }
        Ok(peer)
    }

    /// Remove a pinned peer without waiting for rotation.
    pub fn forget(&self, kernel_id: &str) -> Result<Option<FederationPeer>, PeerHandshakeError> {
        self.store.remove(kernel_id)
    }

    /// Snapshot of all currently-pinned peers. Order is unspecified.
    pub fn peers(&self) -> Result<Vec<FederationPeer>, PeerHandshakeError> {
        self.store.snapshot()
    }
}
