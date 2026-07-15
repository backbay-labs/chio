//! DPoP (Demonstration of Proof-of-Possession) for Chio tool invocations.
//!
//! A DPoP proof is a signed canonical JSON object that binds a single tool
//! invocation to the agent's keypair. It prevents stolen-token replay by
//! requiring the agent to prove possession of the private key corresponding
//! to `capability.subject` on every invocation.
//!
//! Proof fields:
//! - `schema`:        constant `"chio.dpop_proof.v1"`
//! - `capability_id`: token ID of the capability being invoked
//! - `tool_server`:   server_id of the target tool server
//! - `tool_name`:     name of the tool being called
//! - `action_hash`:   SHA-256 hash of the serialized tool arguments
//! - `nonce`:         caller-chosen random string (replay prevention)
//! - `issued_at`:     Unix seconds when the proof was created
//! - `agent_key`:     hex-encoded public key of the signer (Ed25519 by default;
//!   `p256:` / `p384:` prefix under the FIPS crypto path)
//!
//! Verification steps (in order):
//! 1. Schema check -- must equal `DPOP_SCHEMA`
//! 2. Sender constraint -- `agent_key` must equal `capability.subject`
//! 3. Binding fields -- capability_id, tool_server, tool_name, action_hash all match
//! 4. Freshness -- `issued_at + proof_ttl_secs >= now` and `issued_at <= now + max_clock_skew_secs`
//! 5. Signature -- verified through the signing backend negotiated between
//!    agent and kernel; dispatches off the algorithm carried by `agent_key`
//!    and the proof's `signature` field
//! 6. Nonce replay -- nonce must not have been seen during the proof's signed validity window

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::token::CapabilityToken;
use chio_core::crypto::{
    sign_canonical_with_backend, Keypair, PublicKey, Signature, SigningBackend,
};
use chio_kernel_core::{dpop_freshness_valid, nonce_admits};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::replay_retention::ReplayRetention;
use crate::KernelError;

/// Schema identifier for Chio DPoP proofs.
pub const DPOP_SCHEMA: &str = "chio.dpop_proof.v1";

#[must_use]
pub fn is_supported_dpop_schema(schema: &str) -> bool {
    schema == DPOP_SCHEMA
}

// ---------------------------------------------------------------------------
// DpopProofBody
// ---------------------------------------------------------------------------

/// The signable body of a DPoP proof.
///
/// This is the canonical-JSON-serialized message that the agent signs.
/// All fields are included in the signature; none are mutable after signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProofBody {
    /// Schema identifier. Must equal `DPOP_SCHEMA`.
    pub schema: String,
    /// ID of the capability token being used for this invocation.
    pub capability_id: String,
    /// `server_id` of the tool server being called.
    pub tool_server: String,
    /// Name of the tool being invoked.
    pub tool_name: String,
    /// SHA-256 hex of the serialized tool arguments (action binding).
    pub action_hash: String,
    /// Caller-chosen random string; must be unique within the TTL window.
    pub nonce: String,
    /// Unix seconds when this proof was created.
    pub issued_at: u64,
    /// Hex-encoded Ed25519 public key of the signer (must equal capability.subject).
    pub agent_key: PublicKey,
}

// ---------------------------------------------------------------------------
// DpopProof
// ---------------------------------------------------------------------------

/// A signed DPoP proof ready for transmission.
///
/// The `signature` covers the canonical JSON of `body`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpopProof {
    /// The proof body that was signed.
    pub body: DpopProofBody,
    /// Ed25519 signature over `canonical_json_bytes(&body)`.
    pub signature: Signature,
}

impl DpopProof {
    /// Sign a proof body with the agent's Ed25519 keypair.
    ///
    /// The `keypair` must be the one corresponding to `body.agent_key`.
    /// The signature covers the canonical JSON of the body.
    pub fn sign(body: DpopProofBody, keypair: &Keypair) -> Result<DpopProof, KernelError> {
        let body_bytes = canonical_json_bytes(&body).map_err(|e| {
            KernelError::DpopVerificationFailed(format!("failed to serialize proof body: {e}"))
        })?;
        let signature = keypair.sign(&body_bytes);
        Ok(DpopProof { body, signature })
    }

    /// Sign a proof body with an arbitrary [`SigningBackend`].
    ///
    /// The backend's public key must equal `body.agent_key`. Use this entry
    /// point when the agent's signing identity is served by a FIPS backend
    /// (P-256 / P-384) rather than a direct Ed25519 keypair.
    pub fn sign_with_backend(
        body: DpopProofBody,
        backend: &dyn SigningBackend,
    ) -> Result<DpopProof, KernelError> {
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body).map_err(|e| {
            KernelError::DpopVerificationFailed(format!("failed to sign proof body: {e}"))
        })?;
        Ok(DpopProof { body, signature })
    }
}

// ---------------------------------------------------------------------------
// DpopConfig
// ---------------------------------------------------------------------------

/// Configuration for DPoP proof verification.
#[derive(Debug, Clone)]
pub struct DpopConfig {
    /// How many seconds a proof is valid after `issued_at`. Default: 300.
    pub proof_ttl_secs: u64,
    /// How many seconds of future-dated clock skew to tolerate. Default: 30.
    pub max_clock_skew_secs: u64,
    /// Maximum number of entries in the nonce replay cache. Default: 8192.
    pub nonce_store_capacity: usize,
}

impl Default for DpopConfig {
    fn default() -> Self {
        Self {
            proof_ttl_secs: 300,
            max_clock_skew_secs: 30,
            nonce_store_capacity: 8192,
        }
    }
}

// ---------------------------------------------------------------------------
// DpopNonceStore
// ---------------------------------------------------------------------------

/// In-memory LRU nonce replay store.
///
/// Keys are `(nonce, capability_id)` pairs. Entries retain their replay
/// horizon and, for pre-dispatch transactions, the reservation owner. Signed
/// artifacts use their absolute validity horizon; the configured TTL is only
/// a fallback for callers that do not provide one.
///
/// This is intentionally synchronous (no async) and uses `std::sync::Mutex`
/// so it integrates cleanly into the `Guard` pipeline.
pub struct DpopNonceStore {
    inner: Mutex<DpopNonceState>,
    ttl: Duration,
}

struct DpopNonceState {
    cache: LruCache<(String, String), DpopNonceEntry>,
    wall_clock_high_water: SystemTime,
}

struct DpopNonceEntry {
    retention: ReplayRetention,
    dispatch_reservation_id: Option<String>,
}

/// Project production clock and configuration inputs into the verified DPoP
/// freshness predicate.
#[must_use]
pub fn dpop_freshness_admits(now_secs: u64, issued_at: u64, config: &DpopConfig) -> bool {
    dpop_freshness_valid(
        now_secs,
        issued_at,
        config.proof_ttl_secs,
        config.max_clock_skew_secs,
    )
}

impl DpopNonceStore {
    /// Create a new nonce store.
    ///
    /// `capacity` is the maximum number of (nonce, capability_id) pairs to
    /// remember. `ttl` is fallback retention for calls to
    /// [`Self::check_and_insert`] that do not supply a signed horizon.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let nz = match NonZeroUsize::new(capacity) {
            Some(capacity) => capacity,
            None => panic!("DPoP nonce store capacity must be greater than zero"),
        };
        Self {
            inner: Mutex::new(DpopNonceState {
                cache: LruCache::new(nz),
                wall_clock_high_water: SystemTime::now(),
            }),
            ttl,
        }
    }

    /// Check a nonce using the store's local fallback TTL.
    ///
    /// Signed artifacts should use [`Self::check_and_insert_through`] or an
    /// artifact-specific verifier so retention follows their actual validity.
    ///
    /// Returns `Ok(true)` if the nonce is fresh (accepted).
    /// Returns `Ok(false)` if the nonce was already used within the TTL window
    /// (rejected -- replay detected).
    /// Returns `Err` if the internal mutex is poisoned (fail-closed: deny).
    pub fn check_and_insert(&self, nonce: &str, capability_id: &str) -> Result<bool, KernelError> {
        self.check_and_insert_entry(nonce, capability_id, ReplayRetention::local(self.ttl), None)
    }

    /// Check and retain a nonce until an exclusive signed Unix-second expiry.
    pub fn check_and_insert_until(
        &self,
        nonce: &str,
        capability_id: &str,
        expires_at: u64,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayRetention::signed_until_unix_secs(expires_at),
            None,
        )
    }

    /// Check and retain a DPoP nonce through its inclusive freshness horizon.
    pub fn check_and_insert_through(
        &self,
        nonce: &str,
        capability_id: &str,
        valid_through: u64,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayRetention::signed_through_unix_secs(valid_through),
            None,
        )
    }

    fn check_and_insert_entry(
        &self,
        nonce: &str,
        capability_id: &str,
        retention: ReplayRetention,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry_at(
            nonce,
            capability_id,
            retention,
            dispatch_reservation_id,
            SystemTime::now(),
            Instant::now(),
        )
    }

    fn check_and_insert_entry_at(
        &self,
        nonce: &str,
        capability_id: &str,
        retention: ReplayRetention,
        dispatch_reservation_id: Option<&str>,
        now_wall: SystemTime,
        now_monotonic: Instant,
    ) -> Result<bool, KernelError> {
        let key = (nonce.to_string(), capability_id.to_string());
        let mut state = self.inner.lock().map_err(|_| {
            error!("DPoP nonce store mutex is poisoned; denying proof as fail-closed");
            KernelError::DpopVerificationFailed(
                "nonce store mutex poisoned; cannot verify replay safety".to_string(),
            )
        })?;
        let clock_rolled_back = now_wall < state.wall_clock_high_water;
        if now_wall > state.wall_clock_high_water {
            state.wall_clock_high_water = now_wall;
        }
        let wall_clock_high_water = state.wall_clock_high_water;

        let already_live = state.cache.peek(&key).is_some_and(|entry| {
            !entry
                .retention
                .is_expired_at(wall_clock_high_water, now_monotonic)
        });
        if !nonce_admits(already_live) {
            return Ok(false);
        }

        let expired_keys = state
            .cache
            .iter()
            .filter(|(_, entry)| {
                entry
                    .retention
                    .is_expired_at(wall_clock_high_water, now_monotonic)
            })
            .map(|(expired_key, _)| expired_key.clone())
            .collect::<Vec<_>>();
        for expired_key in expired_keys {
            state.cache.pop(&expired_key);
        }
        if retention.is_signed()
            && (clock_rolled_back || retention.signed_horizon_elapsed_at(wall_clock_high_water))
        {
            error!("wall-clock rollback or elapsed signed horizon; denying replay reservation");
            return Ok(false);
        }
        if state.cache.len() >= state.cache.cap().get() {
            error!(
                capacity = state.cache.cap().get(),
                "DPoP nonce store capacity exhausted; denying proof as fail-closed"
            );
            return Err(KernelError::DpopVerificationFailed(
                "nonce store capacity exhausted; cannot verify replay safety".to_string(),
            ));
        }

        state.cache.put(
            key,
            DpopNonceEntry {
                retention,
                dispatch_reservation_id: dispatch_reservation_id.map(str::to_string),
            },
        );
        Ok(true)
    }

    /// Reserve a DPoP nonce through its inclusive signed freshness horizon.
    pub(crate) fn reserve_for_dispatch_through(
        &self,
        nonce: &str,
        capability_id: &str,
        valid_through: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayRetention::signed_through_unix_secs(valid_through),
            Some(reservation_id),
        )
    }

    /// Reserve a nonce until an exclusive signed Unix-second expiry.
    #[cfg(test)]
    pub(crate) fn reserve_for_dispatch_until(
        &self,
        nonce: &str,
        capability_id: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.check_and_insert_entry(
            nonce,
            capability_id,
            ReplayRetention::signed_until_unix_secs(expires_at),
            Some(reservation_id),
        )
    }

    pub(crate) fn rollback_dispatch_reservation(
        &self,
        nonce: &str,
        capability_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let key = (nonce.to_string(), capability_id.to_string());
        let mut state = self.inner.lock().map_err(|_| {
            error!("DPoP nonce store mutex is poisoned; dispatch reservation rollback failed");
            KernelError::DpopVerificationFailed(
                "nonce store mutex poisoned; cannot roll back dispatch reservation".to_string(),
            )
        })?;
        let owned = state
            .cache
            .peek(&key)
            .is_some_and(|entry| entry.dispatch_reservation_id.as_deref() == Some(reservation_id));
        if owned {
            state.cache.pop(&key);
        }
        Ok(owned)
    }
}

// ---------------------------------------------------------------------------
// verify_dpop_proof
// ---------------------------------------------------------------------------

/// Verify the stateless parts of a DPoP proof against an invocation context.
///
/// This validates schema, sender binding, invocation binding, freshness, and
/// signature, but deliberately does not consult or mutate the replay nonce
/// store. Use this only for preview paths that must not burn a nonce before the
/// authoritative invocation. Runtime execution must call [`verify_dpop_proof`].
///
/// # Arguments
///
/// * `proof` - the signed DPoP proof from the agent
/// * `capability` - the capability token being used for this invocation
/// * `expected_tool_server` - `server_id` the kernel expects
/// * `expected_tool_name` - tool name the kernel expects
/// * `expected_action_hash` - SHA-256 hex of the serialized tool arguments
/// * `config` - TTL and clock-skew bounds
pub fn verify_dpop_proof_stateless(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    config: &DpopConfig,
) -> Result<(), KernelError> {
    // Step 1: Schema check.
    if !is_supported_dpop_schema(&proof.body.schema) {
        return Err(KernelError::DpopVerificationFailed(format!(
            "unknown DPoP schema: expected {DPOP_SCHEMA}, got {}",
            proof.body.schema
        )));
    }

    // Step 2: Sender constraint -- agent_key must equal capability.subject.
    if proof.body.agent_key != capability.subject {
        return Err(KernelError::DpopVerificationFailed(
            "agent_key does not match capability subject (sender constraint violated)".to_string(),
        ));
    }

    // Step 3: Binding fields.
    if proof.body.capability_id != capability.id
        || proof.body.tool_server != expected_tool_server
        || proof.body.tool_name != expected_tool_name
        || proof.body.action_hash != expected_action_hash
    {
        return Err(KernelError::DpopVerificationFailed(
            "binding fields do not match: capability_id, tool_server, tool_name, or action_hash mismatch".to_string(),
        ));
    }

    // Step 4: Freshness check.
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Proof must not be future-dated beyond clock skew tolerance: issued_at <= now + skew.
    // Check this first so that an astronomically large issued_at (e.g. u64::MAX) is
    // rejected here before the expiry arithmetic below can overflow.
    if !dpop_freshness_admits(now_secs, proof.body.issued_at, config) {
        if proof.body.issued_at > now_secs.saturating_add(config.max_clock_skew_secs) {
            return Err(KernelError::DpopVerificationFailed(format!(
                "proof issued_at={} is too far in the future (now={}, skew={})",
                proof.body.issued_at, now_secs, config.max_clock_skew_secs
            )));
        }
        return Err(KernelError::DpopVerificationFailed(format!(
            "proof expired: issued_at={} ttl={} now={}",
            proof.body.issued_at, config.proof_ttl_secs, now_secs
        )));
    }

    // Proof must not be too far in the past beyond TTL + clock skew.
    // A valid proof satisfies: issued_at >= now - (proof_ttl_secs + max_clock_skew_secs).
    // This guards against proofs with timestamps so old they predate any plausible clock skew.
    let stale_threshold = now_secs.saturating_sub(
        config
            .proof_ttl_secs
            .saturating_add(config.max_clock_skew_secs),
    );
    if proof.body.issued_at < stale_threshold {
        return Err(KernelError::DpopVerificationFailed(format!(
            "proof issued_at={} is too far in the past (now={}, ttl={}, skew={})",
            proof.body.issued_at, now_secs, config.proof_ttl_secs, config.max_clock_skew_secs
        )));
    }

    // Step 5: Signature verification.
    let body_bytes = canonical_json_bytes(&proof.body).map_err(|e| {
        KernelError::DpopVerificationFailed(format!("failed to serialize proof body: {e}"))
    })?;
    if !proof.body.agent_key.verify(&body_bytes, &proof.signature) {
        return Err(KernelError::DpopVerificationFailed(
            "proof signature verification failed".to_string(),
        ));
    }

    Ok(())
}

/// Verify a DPoP proof against the given capability and invocation context.
///
/// All six verification steps must pass; the first failure returns an error.
///
/// # Arguments
///
/// * `proof` - the signed DPoP proof from the agent
/// * `capability` - the capability token being used for this invocation
/// * `expected_tool_server` - `server_id` the kernel expects
/// * `expected_tool_name` - tool name the kernel expects
/// * `expected_action_hash` - SHA-256 hex of the serialized tool arguments
/// * `nonce_store` - shared replay-rejection store
/// * `config` - TTL and clock-skew bounds
pub fn verify_dpop_proof(
    proof: &DpopProof,
    capability: &CapabilityToken,
    expected_tool_server: &str,
    expected_tool_name: &str,
    expected_action_hash: &str,
    nonce_store: &DpopNonceStore,
    config: &DpopConfig,
) -> Result<(), KernelError> {
    verify_dpop_proof_stateless(
        proof,
        capability,
        expected_tool_server,
        expected_tool_name,
        expected_action_hash,
        config,
    )?;

    // Step 6: Nonce replay check.
    let valid_through = proof.body.issued_at.saturating_add(config.proof_ttl_secs);
    if !nonce_store.check_and_insert_through(
        &proof.body.nonce,
        &proof.body.capability_id,
        valid_through,
    )? {
        return Err(KernelError::DpopVerificationFailed(
            "nonce replayed: this nonce has already been used during the proof validity window"
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod backend_tests {
    use super::*;
    use chio_core::crypto::Ed25519Backend;

    #[test]
    #[should_panic(expected = "DPoP nonce store capacity must be greater than zero")]
    fn zero_capacity_is_rejected() {
        let _store = DpopNonceStore::new(0, Duration::from_secs(1));
    }

    #[test]
    fn ed25519_backend_produces_equivalent_dpop_proof() {
        // Signing via `DpopProof::sign_with_backend(..., &Ed25519Backend)` must
        // be verifier-equivalent to the `DpopProof::sign(..., &Keypair)`
        // path. The stored `agent_key.verify(...)` pathway already dispatches
        // on algorithm tag, so either signing entry point must produce a proof
        // whose verification succeeds.
        let kp = Keypair::generate();
        let backend = Ed25519Backend::new(kp.clone());
        let body = DpopProofBody {
            schema: DPOP_SCHEMA.to_string(),
            capability_id: "cap-1".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "tool".to_string(),
            action_hash: "hash".to_string(),
            nonce: "nonce-1".to_string(),
            issued_at: 1_000,
            agent_key: kp.public_key(),
        };
        let proof = DpopProof::sign_with_backend(body.clone(), &backend).unwrap();
        let bytes = canonical_json_bytes(&proof.body).unwrap();
        assert!(proof.body.agent_key.verify(&bytes, &proof.signature));
    }

    #[test]
    fn dispatch_reservation_rolls_back_only_for_its_owner() {
        let store = DpopNonceStore::new(4, Duration::from_secs(60));
        assert!(store
            .reserve_for_dispatch_until("nonce", "capability", u64::MAX, "owner-a")
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("nonce", "capability", "owner-b")
            .unwrap());
        assert!(!store.check_and_insert("nonce", "capability").unwrap());
        assert!(store
            .rollback_dispatch_reservation("nonce", "capability", "owner-a")
            .unwrap());
        assert!(store.check_and_insert("nonce", "capability").unwrap());
    }

    #[test]
    fn shared_dpop_and_approval_store_capacity_pressure_does_not_evict_live_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = DpopNonceStore::new(2, Duration::from_secs(60));
        assert!(store.reserve_for_dispatch_until("nonce-a", "capability", u64::MAX, "owner-a")?);
        assert!(store.reserve_for_dispatch_until("nonce-b", "capability", u64::MAX, "owner-b")?);
        assert!(store
            .reserve_for_dispatch_until("nonce-c", "capability", u64::MAX, "owner-c")
            .is_err());
        assert!(!store.check_and_insert("nonce-a", "capability")?);
        assert!(!store.check_and_insert("nonce-b", "capability")?);
        assert!(store.rollback_dispatch_reservation("nonce-a", "capability", "owner-a")?);
        assert!(store.reserve_for_dispatch_until("nonce-c", "capability", u64::MAX, "owner-c")?);
        Ok(())
    }

    #[test]
    fn shared_dpop_and_approval_store_capacity_pressure_retains_consumed_key_until_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = DpopNonceStore::new(1, Duration::from_secs(60));
        assert!(store.check_and_insert("nonce-a", "capability")?);
        assert!(store.check_and_insert("nonce-b", "capability").is_err());
        assert!(!store.check_and_insert("nonce-a", "capability")?);

        let expired_store = DpopNonceStore::new(1, Duration::ZERO);
        assert!(expired_store.check_and_insert("nonce-a", "capability")?);
        assert!(expired_store.check_and_insert("nonce-b", "capability")?);
        Ok(())
    }

    #[test]
    fn signed_expiry_overrides_local_ttl_under_pressure_and_rejects_expired_input(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let store = DpopNonceStore::new(1, Duration::ZERO);
        assert!(store.check_and_insert_until("approval-a", "intent", now + 60)?);
        assert!(!store.check_and_insert_until("approval-a", "intent", now + 60)?);
        assert!(store
            .check_and_insert_until("approval-b", "intent", now + 60)
            .is_err());

        let expired_store = DpopNonceStore::new(1, Duration::from_secs(60));
        assert!(!expired_store.check_and_insert_until("approval-a", "intent", 0)?);
        assert!(expired_store.check_and_insert_until("approval-b", "intent", now + 60)?);
        Ok(())
    }

    #[test]
    fn signed_replay_stays_closed_after_reclamation_and_clock_rollback(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start_wall = UNIX_EPOCH.checked_add(Duration::from_secs(10_000)).unwrap();
        let start_monotonic = Instant::now();
        let store = DpopNonceStore::new(3, Duration::from_secs(60));
        store.inner.lock().unwrap().wall_clock_high_water = start_wall;

        let used_deadline = start_wall.checked_add(Duration::from_secs(10)).unwrap();
        let used_retention =
            ReplayRetention::signed_until_at(Some(used_deadline), start_wall, start_monotonic);
        assert!(store.check_and_insert_entry_at(
            "used",
            "intent",
            used_retention,
            None,
            start_wall,
            start_monotonic,
        )?);

        let forward_wall = start_wall.checked_add(Duration::from_secs(20)).unwrap();
        let forward_monotonic = start_monotonic
            .checked_add(Duration::from_secs(20))
            .unwrap();
        let other_retention = ReplayRetention::signed_until_at(
            start_wall.checked_add(Duration::from_secs(40)),
            forward_wall,
            forward_monotonic,
        );
        assert!(store.check_and_insert_entry_at(
            "other",
            "intent",
            other_retention,
            None,
            forward_wall,
            forward_monotonic,
        )?);
        assert!(store
            .inner
            .lock()
            .unwrap()
            .cache
            .peek(&("used".to_string(), "intent".to_string()))
            .is_none());

        let rollback_wall = start_wall.checked_add(Duration::from_secs(5)).unwrap();
        let rollback_monotonic = forward_monotonic
            .checked_add(Duration::from_secs(1))
            .unwrap();
        assert!(!store.check_and_insert_entry_at(
            "used",
            "intent",
            used_retention,
            None,
            rollback_wall,
            rollback_monotonic,
        )?);

        let later_horizon = ReplayRetention::signed_until_at(
            start_wall.checked_add(Duration::from_secs(60)),
            rollback_wall,
            rollback_monotonic,
        );
        assert!(!store.check_and_insert_entry_at(
            "new-signed",
            "intent",
            later_horizon,
            None,
            rollback_wall,
            rollback_monotonic,
        )?);
        assert!(store.check_and_insert_entry_at(
            "local-only",
            "intent",
            ReplayRetention::local(Duration::from_secs(60)),
            None,
            rollback_wall,
            rollback_monotonic,
        )?);
        Ok(())
    }

    // The P-256 / P-384 DPoP signing round-trip is exercised in
    // `chio-core-types` where the `fips` feature is directly in scope
    // (see `capability.rs` tests). The DPoP verifier path ultimately calls
    // `PublicKey::verify`, so algorithm dispatch is fully covered there.
}
