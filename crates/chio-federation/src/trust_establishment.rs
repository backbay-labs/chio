//! Cross-kernel trust establishment via mTLS-style handshake.
//!
//! Two kernels bootstrap mutual trust by exchanging signed challenges and
//! pinning each other's kernel signing public keys. Once pinned, the
//! [`FederationPeer`] set lives alongside the existing federation-state
//! primitives (`chio-federation` already persists activation, governance, and
//! reputation artifacts; the peer set is a new surface with the same
//! persistence semantics: in-memory by default, pluggable store).
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

/// Pinned federation peer entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationPeer {
    pub kernel_id: String,
    pub public_key: PublicKey,
    /// Unix seconds at which the peer was last pinned via a successful
    /// handshake.
    pub established_at: u64,
    /// Unix seconds at which the pin expires. After this timestamp the
    /// peer is treated as stale and MUST be re-handshaked before any
    /// federation-level operation is accepted against it.
    pub rotation_due: u64,
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
}

impl HandshakeChallenge {
    pub fn new(
        local_kernel_id: impl Into<String>,
        remote_kernel_id: impl Into<String>,
        nonce: impl Into<String>,
        timestamp: u64,
    ) -> Self {
        Self {
            schema: FEDERATION_HANDSHAKE_SCHEMA.to_string(),
            local_kernel_id: local_kernel_id.into(),
            remote_kernel_id: remote_kernel_id.into(),
            nonce: nonce.into(),
            timestamp,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PeerHandshakeError> {
        canonical_json_bytes(self).map_err(|e| PeerHandshakeError::CanonicalJson(e.to_string()))
    }
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
        let challenge =
            HandshakeChallenge::new(local_kernel_id, remote_kernel_id, nonce, timestamp);
        let bytes = challenge.canonical_bytes()?;
        let backend = Ed25519Backend::new(local_keypair.clone());
        let signature = backend
            .sign_bytes(&bytes)
            .map_err(|e| PeerHandshakeError::SigningFailed(e.to_string()))?;
        Ok(Self {
            challenge,
            declared_public_key: local_keypair.public_key(),
            signature,
        })
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
    local_keypair: Keypair,
    config: KernelTrustExchangeConfig,
    store: Box<dyn FederationPeerStore>,
    trusted_peers: HashMap<String, PublicKey>,
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
        Self {
            local_kernel_id: local_kernel_id.into(),
            local_keypair,
            config: KernelTrustExchangeConfig::default(),
            store: Box::new(InMemoryPeerStore::new()),
            trusted_peers: HashMap::new(),
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

    pub fn with_trusted_peer(
        mut self,
        kernel_id: impl Into<String>,
        public_key: PublicKey,
    ) -> Self {
        self.trusted_peers.insert(kernel_id.into(), public_key);
        self
    }

    pub fn local_kernel_id(&self) -> &str {
        &self.local_kernel_id
    }

    pub fn local_public_key(&self) -> PublicKey {
        self.local_keypair.public_key()
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
        PeerHandshakeEnvelope::sign(
            &self.local_kernel_id,
            remote_kernel_id,
            nonce,
            now,
            &self.local_keypair,
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

        let peer = FederationPeer {
            kernel_id: expected_remote_kernel_id.to_string(),
            public_key: envelope.declared_public_key.clone(),
            established_at: now,
            rotation_due: now.saturating_add(self.config.rotation_window_secs),
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
