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
//! 6. Nonce replay -- nonce must not have been seen within the TTL window

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::canonical::canonical_json_bytes;
use chio_core::capability::CapabilityToken;
use chio_core::crypto::{
    sign_canonical_with_backend, Keypair, PublicKey, Signature, SigningBackend,
};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::error;

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
    /// (P-256 / P-384) rather than a historical Ed25519 keypair.
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
/// Keys are `(nonce, capability_id)` pairs. Values are the `Instant` when
/// the nonce was first seen. A nonce is rejected if it is still within the
/// TTL window when seen a second time.
///
/// This is intentionally synchronous (no async) and uses `std::sync::Mutex`
/// so it integrates cleanly into the `Guard` pipeline.
pub struct DpopNonceStore {
    inner: Mutex<LruCache<(String, String), Instant>>,
    ttl: Duration,
}

impl DpopNonceStore {
    /// Create a new nonce store.
    ///
    /// `capacity` is the maximum number of (nonce, capability_id) pairs to
    /// remember. `ttl` is how long a nonce is considered "live" after first
    /// use. After the TTL elapses, the same nonce can be used again.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        // NonZeroUsize::new returns None for 0; fall back to 1024 in that case.
        let nz = NonZeroUsize::new(capacity).unwrap_or_else(|| {
            // SAFETY: 1024 is a compile-time constant greater than zero.
            NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN)
        });
        Self {
            inner: Mutex::new(LruCache::new(nz)),
            ttl,
        }
    }

    /// Check a nonce and insert it if not already live.
    ///
    /// Returns `Ok(true)` if the nonce is fresh (accepted).
    /// Returns `Ok(false)` if the nonce was already used within the TTL window
    /// (rejected -- replay detected).
    /// Returns `Err` if the internal mutex is poisoned (fail-closed: deny).
    pub fn check_and_insert(&self, nonce: &str, capability_id: &str) -> Result<bool, KernelError> {
        let key = (nonce.to_string(), capability_id.to_string());
        let mut cache = self.inner.lock().map_err(|_| {
            error!("DPoP nonce store mutex is poisoned; denying proof as fail-closed");
            KernelError::DpopVerificationFailed(
                "nonce store mutex poisoned; cannot verify replay safety".to_string(),
            )
        })?;

        if let Some(first_seen) = cache.peek(&key) {
            if first_seen.elapsed() < self.ttl {
                // Nonce is still live -- replay detected.
                return Ok(false);
            }
            // TTL has elapsed; remove the stale entry so we can re-insert.
            cache.pop(&key);
        }

        cache.put(key, Instant::now());
        Ok(true)
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
    if proof.body.issued_at > now_secs.saturating_add(config.max_clock_skew_secs) {
        return Err(KernelError::DpopVerificationFailed(format!(
            "proof issued_at={} is too far in the future (now={}, skew={})",
            proof.body.issued_at, now_secs, config.max_clock_skew_secs
        )));
    }

    // Proof must not be expired: issued_at + ttl >= now.
    // Use saturating_add as a defence-in-depth measure; the future-dated check
    // above ensures issued_at is near now, so saturation should never trigger
    // in practice for well-formed proofs.
    if proof.body.issued_at.saturating_add(config.proof_ttl_secs) < now_secs {
        return Err(KernelError::DpopVerificationFailed(format!(
            "proof expired: issued_at={} ttl={} now={}",
            proof.body.issued_at, config.proof_ttl_secs, now_secs
        )));
    }

    // Proof must not be too far in the past beyond TTL + clock skew.
    // A valid proof satisfies: issued_at >= now - (proof_ttl_secs + max_clock_skew_secs).
    // This guards against proofs with timestamps so old they predate any plausible clock skew.
    let stale_threshold =
        now_secs.saturating_sub(config.proof_ttl_secs + config.max_clock_skew_secs);
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
    if !nonce_store.check_and_insert(&proof.body.nonce, &proof.body.capability_id)? {
        return Err(KernelError::DpopVerificationFailed(
            "nonce replayed: this nonce has already been used within the TTL window".to_string(),
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
    fn ed25519_backend_produces_equivalent_dpop_proof() {
        // Signing via `DpopProof::sign_with_backend(..., &Ed25519Backend)` must
        // be verifier-equivalent to the historical `DpopProof::sign(..., &Keypair)`
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

    // The P-256 / P-384 DPoP signing round-trip is exercised in
    // `chio-core-types` where the `fips` feature is directly in scope
    // (see `capability.rs` tests). The DPoP verifier path ultimately calls
    // `PublicKey::verify`, so algorithm dispatch is fully covered there.
}
