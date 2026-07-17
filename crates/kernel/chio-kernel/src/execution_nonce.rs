//! Execution nonces prevent TOCTOU races between capability evaluation and tool-server dispatch.
//!
//! An `ExecutionNonce` is a short-lived, single-use token that the kernel
//! attaches to every `Verdict::Allow` response. Tool servers MUST present
//! the nonce before executing; the kernel rejects stale (>`nonce_ttl_secs`,
//! default 30s) or replayed nonces. This closes the time-of-check /
//! time-of-use window between `evaluate()` and tool-server execution that
//! DPoP alone cannot close.
//!
//! # Design
//!
//! * The nonce body is an opaque `nonce_id` plus a `NonceBinding` that
//!   binds the nonce to the exact `(subject, capability, server, tool,
//!   parameter_hash)` tuple. Substituting a nonce between unrelated tool
//!   calls therefore fails the binding check.
//! * The kernel signs the full body (nonce id + binding + expires_at)
//!   with its receipt-signing key, so downstream tool servers can
//!   cryptographically verify authenticity without a round trip.
//! * Replay is prevented by an `ExecutionNonceStore`: the first
//!   `reserve(nonce_id)` returns true and consumes the nonce; any
//!   subsequent reservation returns false and the verify path rejects.
//!
//! # Backward compatibility
//!
//! The whole feature is opt-in by installing an `ExecutionNonceConfig`.
//! With no config installed, no nonce is minted and non-nonce callers keep
//! working. With a config installed and `require_nonce == false`, allow
//! responses carry nonces and dispatch verifies any nonce that is presented,
//! but callers that omit the nonce remain backward-compatible. New strict
//! deployments flip `require_nonce` to make every execution-bound dispatch
//! present a fresh nonce.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::{Keypair, PublicKey, Signature};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use uuid::Uuid;

use crate::replay_retention::{
    advance_replay_clock, PendingReplayClockRebaseline, ReplayRetention,
};
use crate::KernelError;

/// Schema identifier for Chio execution nonces.
pub const EXECUTION_NONCE_SCHEMA: &str = "chio.execution_nonce.v1";

/// Default TTL for a freshly minted execution nonce.
pub const DEFAULT_EXECUTION_NONCE_TTL_SECS: u64 = 30;

/// Default capacity for the in-memory replay-prevention LRU cache.
///
/// This provides shared operational headroom for roughly 2,000 reservations
/// per second across the default 30-second nonce lifetime, plus short bursts.
pub const DEFAULT_EXECUTION_NONCE_STORE_CAPACITY: usize = 65_536;

const EXECUTION_NONCE_CAPABILITY_FAIR_SHARE_DIVISOR: usize = 8;

#[must_use]
pub fn is_supported_execution_nonce_schema(schema: &str) -> bool {
    schema == EXECUTION_NONCE_SCHEMA
}

// ---------------------------------------------------------------------------
// NonceBinding
// ---------------------------------------------------------------------------

/// Fields that tie a nonce to one specific tool invocation.
///
/// All five fields are in the signed body, so any mismatch during verify
/// means either the nonce was minted for a different call or the nonce was
/// tampered with after issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceBinding {
    /// Hex-encoded subject (agent) public key, taken from `capability.subject`.
    pub subject_id: String,
    /// ID of the capability that authorized this invocation.
    pub capability_id: String,
    /// Tool server that is expected to execute the call.
    pub tool_server: String,
    /// Tool name that is expected to execute.
    pub tool_name: String,
    /// SHA-256 hex of the canonical JSON of the evaluated arguments. Taken
    /// directly from the `ToolCallAction::parameter_hash` that the kernel
    /// embedded in the allow receipt.
    pub parameter_hash: String,
}

// ---------------------------------------------------------------------------
// ExecutionNonce (signable body)
// ---------------------------------------------------------------------------

/// The signable body of an execution nonce.
///
/// This is the canonical-JSON-serialized message the kernel signs. Every
/// field is covered by the signature; none are mutable after issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionNonce {
    /// Schema identifier. Must equal `EXECUTION_NONCE_SCHEMA`.
    pub schema: String,
    /// Unique nonce identifier (UUIDv7 hex).
    pub nonce_id: String,
    /// Unix timestamp (seconds) when the kernel issued this nonce.
    pub issued_at: i64,
    /// Unix timestamp (seconds) when this nonce expires.
    /// Default: `issued_at + 30`. Configurable via `ExecutionNonceConfig`.
    pub expires_at: i64,
    /// Invocation binding: subject, capability, server, tool, parameter hash.
    pub bound_to: NonceBinding,
}

// ---------------------------------------------------------------------------
// SignedExecutionNonce
// ---------------------------------------------------------------------------

/// A kernel-signed execution nonce ready for transmission on an allow verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedExecutionNonce {
    /// The nonce body that was signed.
    pub nonce: ExecutionNonce,
    /// Ed25519 signature over `canonical_json_bytes(&nonce)` produced by the
    /// kernel's receipt-signing key.
    pub signature: Signature,
}

impl SignedExecutionNonce {
    /// Convenience accessor for the nonce identifier.
    #[must_use]
    pub fn nonce_id(&self) -> &str {
        &self.nonce.nonce_id
    }

    /// Convenience accessor for the expiry.
    #[must_use]
    pub fn expires_at(&self) -> i64 {
        self.nonce.expires_at
    }
}

// ---------------------------------------------------------------------------
// ExecutionNonceConfig
// ---------------------------------------------------------------------------

/// Configuration for execution nonce issuance and verification.
#[derive(Debug, Clone)]
pub struct ExecutionNonceConfig {
    /// How many seconds a nonce is valid after issuance. Default: 30.
    pub nonce_ttl_secs: u64,
    /// Maximum entries in the replay-prevention LRU cache. Default: 65,536.
    pub nonce_store_capacity: usize,
    /// When `true`, the kernel's strict-mode verify paths reject any call
    /// that does not present a signed nonce. Default: `false` (opt-in).
    pub require_nonce: bool,
}

impl Default for ExecutionNonceConfig {
    fn default() -> Self {
        Self {
            nonce_ttl_secs: DEFAULT_EXECUTION_NONCE_TTL_SECS,
            nonce_store_capacity: DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
            require_nonce: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ExecutionNonceStore trait
// ---------------------------------------------------------------------------

/// Persistence boundary for replay-prevention of execution nonces.
///
/// Implementations MUST ensure that `reserve(nonce_id)` returns `true` only
/// once while its local marker remains active. Signed callers use
/// [`ExecutionNonceStore::reserve_until`] so that active window follows the
/// artifact's absolute expiry. Fail-closed: any internal error is returned via
/// `KernelError` so the caller can deny the request.
pub trait ExecutionNonceStore: Send + Sync {
    /// Attempt to reserve (consume) the given nonce identifier.
    ///
    /// * `Ok(true)`  -- nonce was fresh; it is now marked consumed.
    /// * `Ok(false)` -- nonce has already been consumed (replay detected).
    /// * `Err(_)`    -- the store is unreachable or corrupted; fail-closed.
    ///
    /// Prefer [`Self::reserve_until`] when the caller knows the signed
    /// expiry of the nonce: durable stores need to retain the consumed
    /// marker at least as long as the signed nonce is valid, otherwise
    /// the row may be pruned and the nonce can be replayed within its
    /// remaining validity window.
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError>;

    /// Reserve a nonce while telling the store when the nonce stops
    /// being cryptographically valid. Durable implementations (SQLite,
    /// remote KV stores) MUST retain the consumed marker until at least
    /// `nonce_expires_at` so replay protection covers the nonce's full
    /// validity window.
    ///
    /// The default preserves compatibility with legacy stores whose local
    /// retention policy already spans the nonce validity window. Durable
    /// stores should override this method to bind retention to the signed
    /// absolute expiry.
    fn reserve_until(&self, nonce_id: &str, _nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.reserve(nonce_id)
    }

    /// Reserve a nonce within the capability that presented it.
    ///
    /// The provided implementation preserves compatibility with existing
    /// stores. Stores that enforce tenant fairness can override this method
    /// and account for the verified capability without changing legacy
    /// unscoped reservations.
    fn reserve_until_for_capability(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        _capability_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_until(nonce_id, nonce_expires_at)
    }

    /// Whether this store can create and conditionally roll back an owned
    /// reservation before tool dispatch begins.
    fn supports_dispatch_reservations(&self) -> bool {
        false
    }

    /// Reserve a nonce for one dispatch attempt. Implementations that return
    /// `true` from [`Self::supports_dispatch_reservations`] must retain the
    /// reservation owner and remove the marker only when the same owner calls
    /// [`Self::rollback_dispatch_reservation`].
    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_until(nonce_id, nonce_expires_at)
    }

    /// Reserve a capability-scoped nonce for one dispatch attempt.
    ///
    /// The default delegates to the existing dispatch-reservation contract so
    /// third-party stores keep their owner-aware rollback behavior.
    fn reserve_for_dispatch_for_capability(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        _capability_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_for_dispatch(nonce_id, nonce_expires_at, reservation_id)
    }

    /// Remove an owned reservation after a failure known to precede any tool
    /// side effect. Returns `true` only when this reservation owned the marker.
    fn rollback_dispatch_reservation(
        &self,
        _nonce_id: &str,
        _reservation_id: &str,
    ) -> Result<bool, KernelError> {
        Err(KernelError::Internal(
            "execution nonce store does not support dispatch reservation rollback".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// InMemoryExecutionNonceStore
// ---------------------------------------------------------------------------

/// In-memory LRU-backed execution nonce store.
///
/// Mirrors the shape of `dpop::DpopNonceStore` but keys on the nonce_id
/// alone because the full binding lives inside the signed body and is
/// checked separately by `verify_execution_nonce`.
pub struct InMemoryExecutionNonceStore {
    inner: Mutex<ExecutionNonceState>,
    ttl: Duration,
}

struct ExecutionNonceState {
    cache: LruCache<String, ExecutionNonceEntry>,
    capability_counts: HashMap<String, usize>,
    per_capability_capacity: usize,
    wall_clock_high_water: SystemTime,
    monotonic_high_water: Instant,
    pending_clock_rebaseline: Option<PendingReplayClockRebaseline>,
}

struct ExecutionNonceEntry {
    retention: ReplayRetention,
    dispatch_reservation_id: Option<String>,
    capability_id: Option<String>,
}

impl InMemoryExecutionNonceStore {
    /// Create a new in-memory store.
    ///
    /// `capacity` is the maximum number of recently consumed nonces to
    /// remember. `ttl` is the fallback retention for callers that do not
    /// provide a signed expiry. Horizon-aware calls retain each marker through
    /// the nonce body's actual `expires_at`, regardless of this local TTL.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let nz = match NonZeroUsize::new(capacity) {
            Some(capacity) => capacity,
            None => panic!("execution nonce store capacity must be greater than zero"),
        };
        Self {
            inner: Mutex::new(ExecutionNonceState {
                cache: LruCache::new(nz),
                capability_counts: HashMap::new(),
                per_capability_capacity: execution_nonce_capability_capacity(capacity),
                wall_clock_high_water: SystemTime::now(),
                monotonic_high_water: Instant::now(),
                pending_clock_rebaseline: None,
            }),
            ttl,
        }
    }

    /// Build a store with the TTL and capacity from `config`.
    #[must_use]
    pub fn from_config(config: &ExecutionNonceConfig) -> Self {
        Self::new(
            config.nonce_store_capacity,
            Duration::from_secs(config.nonce_ttl_secs),
        )
    }

    /// Return `(occupied_entries, capacity)` for local utilization monitoring.
    pub fn utilization(&self) -> Result<(usize, usize), KernelError> {
        let state = self.inner.lock().map_err(|_| {
            KernelError::Internal(
                "execution nonce store mutex poisoned; cannot report utilization".to_string(),
            )
        })?;
        Ok((state.cache.len(), state.cache.cap().get()))
    }
}

impl Default for InMemoryExecutionNonceStore {
    fn default() -> Self {
        Self::new(
            DEFAULT_EXECUTION_NONCE_STORE_CAPACITY,
            Duration::from_secs(DEFAULT_EXECUTION_NONCE_TTL_SECS),
        )
    }
}

impl ExecutionNonceStore for InMemoryExecutionNonceStore {
    fn reserve(&self, nonce_id: &str) -> Result<bool, KernelError> {
        self.reserve_entry(nonce_id, ReplayRetention::local(self.ttl), None)
    }

    fn reserve_until(&self, nonce_id: &str, nonce_expires_at: i64) -> Result<bool, KernelError> {
        self.reserve_entry(
            nonce_id,
            ReplayRetention::signed_until_unix_i64(nonce_expires_at),
            None,
        )
    }

    fn reserve_until_for_capability(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        capability_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_entry_for_capability(
            nonce_id,
            ReplayRetention::signed_until_unix_i64(nonce_expires_at),
            capability_id,
            None,
        )
    }

    fn supports_dispatch_reservations(&self) -> bool {
        true
    }

    fn reserve_for_dispatch(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_entry(
            nonce_id,
            ReplayRetention::signed_until_unix_i64(nonce_expires_at),
            Some(reservation_id),
        )
    }

    fn reserve_for_dispatch_for_capability(
        &self,
        nonce_id: &str,
        nonce_expires_at: i64,
        capability_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_entry_for_capability(
            nonce_id,
            ReplayRetention::signed_until_unix_i64(nonce_expires_at),
            capability_id,
            Some(reservation_id),
        )
    }

    fn rollback_dispatch_reservation(
        &self,
        nonce_id: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let mut state = self.inner.lock().map_err(|_| {
            error!("execution nonce store mutex poisoned; dispatch reservation rollback failed");
            KernelError::Internal(
                "execution nonce store mutex poisoned; dispatch reservation rollback failed"
                    .to_string(),
            )
        })?;

        let owned = state
            .cache
            .peek(nonce_id)
            .is_some_and(|entry| entry.dispatch_reservation_id.as_deref() == Some(reservation_id));
        if owned {
            if let Some(entry) = state.cache.pop(nonce_id) {
                if let Some(capability_id) = entry.capability_id {
                    decrement_capability_count(&mut state.capability_counts, &capability_id);
                }
            }
        }
        Ok(owned)
    }
}

impl InMemoryExecutionNonceStore {
    fn reserve_entry(
        &self,
        nonce_id: &str,
        retention: ReplayRetention,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, KernelError> {
        self.reserve_entry_with_capability(nonce_id, retention, None, dispatch_reservation_id)
    }

    fn reserve_entry_for_capability(
        &self,
        nonce_id: &str,
        retention: ReplayRetention,
        capability_id: &str,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, KernelError> {
        self.reserve_entry_with_capability(
            nonce_id,
            retention,
            Some(capability_id),
            dispatch_reservation_id,
        )
    }

    fn reserve_entry_with_capability(
        &self,
        nonce_id: &str,
        retention: ReplayRetention,
        capability_id: Option<&str>,
        dispatch_reservation_id: Option<&str>,
    ) -> Result<bool, KernelError> {
        self.reserve_entry_at_with_capability(
            nonce_id,
            retention,
            capability_id,
            dispatch_reservation_id,
            SystemTime::now(),
            Instant::now(),
        )
    }

    #[cfg(test)]
    fn reserve_entry_at(
        &self,
        nonce_id: &str,
        retention: ReplayRetention,
        dispatch_reservation_id: Option<&str>,
        now_wall: SystemTime,
        now_monotonic: Instant,
    ) -> Result<bool, KernelError> {
        self.reserve_entry_at_with_capability(
            nonce_id,
            retention,
            None,
            dispatch_reservation_id,
            now_wall,
            now_monotonic,
        )
    }

    fn reserve_entry_at_with_capability(
        &self,
        nonce_id: &str,
        retention: ReplayRetention,
        capability_id: Option<&str>,
        dispatch_reservation_id: Option<&str>,
        now_wall: SystemTime,
        now_monotonic: Instant,
    ) -> Result<bool, KernelError> {
        let mut state = self.inner.lock().map_err(|_| {
            error!("execution nonce store mutex poisoned; denying fail-closed");
            KernelError::Internal("execution nonce store mutex poisoned; fail-closed".to_string())
        })?;
        let mut wall_clock_high_water = state.wall_clock_high_water;
        let mut monotonic_high_water = state.monotonic_high_water;
        let mut pending_clock_rebaseline = state.pending_clock_rebaseline;
        let clock_result = advance_replay_clock(
            "execution_nonce",
            &mut wall_clock_high_water,
            &mut monotonic_high_water,
            &mut pending_clock_rebaseline,
            now_wall,
            now_monotonic,
        );
        state.wall_clock_high_water = wall_clock_high_water;
        state.monotonic_high_water = monotonic_high_water;
        state.pending_clock_rebaseline = pending_clock_rebaseline;
        let validated_high_water = clock_result?;

        let key = nonce_id.to_string();
        if let Some(entry) = state.cache.peek(&key) {
            if !entry
                .retention
                .is_expired_at(validated_high_water, now_monotonic)
            {
                return Ok(false);
            }
        }

        let expired_keys = state
            .cache
            .iter()
            .filter(|(_, entry)| {
                entry
                    .retention
                    .is_expired_at(validated_high_water, now_monotonic)
            })
            .map(|(expired_key, _)| expired_key.clone())
            .collect::<Vec<_>>();
        for expired_key in expired_keys {
            if let Some(entry) = state.cache.pop(&expired_key) {
                if let Some(capability_id) = entry.capability_id {
                    decrement_capability_count(&mut state.capability_counts, &capability_id);
                }
            }
        }
        if retention.is_signed() && retention.signed_horizon_elapsed_at(validated_high_water) {
            error!("elapsed signed horizon; denying replay reservation");
            return Ok(false);
        }
        if state.cache.len() >= state.cache.cap().get() {
            error!(
                capacity = state.cache.cap().get(),
                "execution nonce store capacity exhausted; denying fail-closed"
            );
            return Err(KernelError::Internal(
                "execution nonce store capacity exhausted; fail-closed".to_string(),
            ));
        }

        if let Some(capability_id) = capability_id {
            let capability_entries = state
                .capability_counts
                .get(capability_id)
                .copied()
                .unwrap_or(0);
            if capability_entries >= state.per_capability_capacity {
                warn!(
                    capability_id,
                    capability_entries,
                    per_capability_capacity = state.per_capability_capacity,
                    "execution nonce store capability quota exhausted; preserving capacity for other capabilities"
                );
                return Err(KernelError::Internal(
                    "execution nonce store per-capability quota exhausted; fail-closed".to_string(),
                ));
            }
        }

        state.cache.put(
            key,
            ExecutionNonceEntry {
                retention,
                dispatch_reservation_id: dispatch_reservation_id.map(str::to_string),
                capability_id: capability_id.map(str::to_string),
            },
        );
        if let Some(capability_id) = capability_id {
            *state
                .capability_counts
                .entry(capability_id.to_string())
                .or_insert(0) += 1;
        }
        warn_on_high_utilization(
            "execution nonce",
            state.cache.len(),
            state.cache.cap().get(),
        );
        Ok(true)
    }
}

fn execution_nonce_capability_capacity(capacity: usize) -> usize {
    capacity.div_ceil(EXECUTION_NONCE_CAPABILITY_FAIR_SHARE_DIVISOR)
}

fn decrement_capability_count(counts: &mut HashMap<String, usize>, capability_id: &str) {
    let Some(count) = counts.get_mut(capability_id) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        counts.remove(capability_id);
    }
}

fn warn_on_high_utilization(store: &'static str, live_entries: usize, capacity: usize) {
    let alert_threshold = capacity.saturating_sub(capacity / 5);
    if live_entries >= alert_threshold {
        warn!(
            store,
            live_entries, capacity, "replay store utilization reached 80 percent"
        );
    }
}

// ---------------------------------------------------------------------------
// Minting
// ---------------------------------------------------------------------------

/// Mint a fresh signed execution nonce.
///
/// The kernel calls this on every `Verdict::Allow` so tool servers can
/// verify that a call was authorized by the kernel at a known, recent
/// time. The returned nonce is signed by `kernel_keypair`; downstream
/// verifiers check the signature with the kernel's public key.
pub fn mint_execution_nonce(
    kernel_keypair: &Keypair,
    binding: NonceBinding,
    config: &ExecutionNonceConfig,
    now: i64,
) -> Result<SignedExecutionNonce, KernelError> {
    let ttl = i64::try_from(config.nonce_ttl_secs).unwrap_or(i64::MAX);
    let expires_at = now.saturating_add(ttl);
    let nonce = ExecutionNonce {
        schema: EXECUTION_NONCE_SCHEMA.to_string(),
        nonce_id: Uuid::now_v7().as_hyphenated().to_string(),
        issued_at: now,
        expires_at,
        bound_to: binding,
    };
    let (signature, _bytes) = kernel_keypair.sign_canonical(&nonce).map_err(|e| {
        KernelError::ReceiptSigningFailed(format!("failed to sign execution nonce: {e}"))
    })?;
    Ok(SignedExecutionNonce { nonce, signature })
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// All the reasons an execution nonce can fail verification.
///
/// Every variant is a hard deny on the kernel side. The nonce flow is
/// fail-closed: schema, expiry, binding, signature, and replay checks all
/// execute on every presented nonce and any failure short-circuits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionNonceError {
    /// Schema did not equal `EXECUTION_NONCE_SCHEMA`.
    BadSchema { got: String },
    /// Nonce has expired (now >= expires_at).
    Expired { now: i64, expires_at: i64 },
    /// Binding fields did not match the presented invocation.
    BindingMismatch { field: &'static str },
    /// Ed25519 signature did not verify under the kernel's public key.
    InvalidSignature,
    /// Nonce was already consumed (single-use).
    Replayed,
    /// Canonical JSON serialization failed during verification.
    Encoding(String),
    /// Replay store was unreachable; fail-closed.
    Store(String),
}

impl std::fmt::Display for ExecutionNonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSchema { got } => write!(
                f,
                "execution nonce has unsupported schema: expected {EXECUTION_NONCE_SCHEMA}, got {got}"
            ),
            Self::Expired { now, expires_at } => write!(
                f,
                "execution nonce expired (now={now}, expires_at={expires_at})"
            ),
            Self::BindingMismatch { field } => {
                write!(f, "execution nonce binding mismatch on field {field}")
            }
            Self::InvalidSignature => write!(f, "execution nonce signature is invalid"),
            Self::Replayed => write!(f, "execution nonce has already been consumed"),
            Self::Encoding(e) => write!(f, "execution nonce canonical encoding failed: {e}"),
            Self::Store(e) => write!(f, "execution nonce store error: {e}"),
        }
    }
}

impl std::error::Error for ExecutionNonceError {}

impl From<ExecutionNonceError> for KernelError {
    fn from(err: ExecutionNonceError) -> Self {
        KernelError::Internal(format!("execution nonce verification failed: {err}"))
    }
}

/// Verify a signed execution nonce against the expected binding.
///
/// Steps, in order:
/// 1. Schema check.
/// 2. Expiry check -- `now < nonce.expires_at`.
/// 3. Binding check -- subject, capability, server, tool, parameter_hash.
/// 4. Signature check -- canonical JSON under the kernel's pubkey.
/// 5. Replay check -- `nonce_store.reserve(nonce_id)` must return `true`.
pub fn verify_execution_nonce(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
    nonce_store: &dyn ExecutionNonceStore,
) -> Result<(), ExecutionNonceError> {
    verify_execution_nonce_stateless(presented, kernel_pubkey, expected, now)?;

    // Pass the nonce's signed expiry so durable stores retain the
    // consumed marker for the full validity window - otherwise the row
    // can be pruned while the nonce is still cryptographically valid,
    // allowing replay within the remaining window.
    match nonce_store.reserve_until_for_capability(
        &presented.nonce.nonce_id,
        presented.nonce.expires_at,
        &presented.nonce.bound_to.capability_id,
    ) {
        Ok(true) => Ok(()),
        Ok(false) => {
            warn!(
                nonce_id = %presented.nonce.nonce_id,
                "rejecting replayed execution nonce"
            );
            Err(ExecutionNonceError::Replayed)
        }
        Err(e) => Err(ExecutionNonceError::Store(e.to_string())),
    }
}

/// Verify an execution nonce without mutating its replay store.
pub(crate) fn verify_execution_nonce_stateless(
    presented: &SignedExecutionNonce,
    kernel_pubkey: &PublicKey,
    expected: &NonceBinding,
    now: i64,
) -> Result<(), ExecutionNonceError> {
    if !is_supported_execution_nonce_schema(&presented.nonce.schema) {
        warn!(
            schema = %presented.nonce.schema,
            "rejecting execution nonce with unsupported schema"
        );
        return Err(ExecutionNonceError::BadSchema {
            got: presented.nonce.schema.clone(),
        });
    }

    if now >= presented.nonce.expires_at {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            now,
            expires_at = presented.nonce.expires_at,
            "rejecting stale execution nonce"
        );
        return Err(ExecutionNonceError::Expired {
            now,
            expires_at: presented.nonce.expires_at,
        });
    }

    let bound = &presented.nonce.bound_to;
    if bound.subject_id != expected.subject_id {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "subject_id",
        });
    }
    if bound.capability_id != expected.capability_id {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "capability_id",
        });
    }
    if bound.tool_server != expected.tool_server {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "tool_server",
        });
    }
    if bound.tool_name != expected.tool_name {
        return Err(ExecutionNonceError::BindingMismatch { field: "tool_name" });
    }
    if bound.parameter_hash != expected.parameter_hash {
        return Err(ExecutionNonceError::BindingMismatch {
            field: "parameter_hash",
        });
    }

    let signed_bytes = canonical_json_bytes(&presented.nonce)
        .map_err(|e| ExecutionNonceError::Encoding(e.to_string()))?;
    if !kernel_pubkey.verify(&signed_bytes, &presented.signature) {
        warn!(
            nonce_id = %presented.nonce.nonce_id,
            "execution nonce signature verification failed"
        );
        return Err(ExecutionNonceError::InvalidSignature);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct LegacyExecutionNonceStore;

    #[test]
    #[should_panic(expected = "execution nonce store capacity must be greater than zero")]
    fn zero_capacity_is_rejected() {
        let _store = InMemoryExecutionNonceStore::new(0, Duration::from_secs(1));
    }

    impl ExecutionNonceStore for LegacyExecutionNonceStore {
        fn reserve(&self, _nonce_id: &str) -> Result<bool, KernelError> {
            Ok(true)
        }
    }

    fn sample_binding() -> NonceBinding {
        NonceBinding {
            subject_id: "subject-abc".to_string(),
            capability_id: "cap-123".to_string(),
            tool_server: "fs".to_string(),
            tool_name: "read_file".to_string(),
            parameter_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        }
    }

    #[test]
    fn mint_then_verify_roundtrip() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        assert_eq!(signed.nonce.schema, EXECUTION_NONCE_SCHEMA);
        assert_eq!(signed.nonce.expires_at, now + cfg.nonce_ttl_secs as i64);

        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store).unwrap();
    }

    #[test]
    fn stale_nonce_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();

        let now = 1_000_000;
        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        let err = verify_execution_nonce(
            &signed,
            &kp.public_key(),
            &binding,
            now + cfg.nonce_ttl_secs as i64 + 1,
            &store,
        )
        .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::Expired { .. }));
    }

    #[test]
    fn replayed_nonce_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();

        let signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store).unwrap();
        let err = verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 2, &store)
            .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::Replayed));
    }

    #[test]
    fn mismatched_binding_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let minted_binding = sample_binding();
        let now = 1_000_000;

        let signed = mint_execution_nonce(&kp, minted_binding.clone(), &cfg, now).unwrap();
        let mut wrong = minted_binding;
        wrong.tool_name = "write_file".to_string();

        let err =
            verify_execution_nonce(&signed, &kp.public_key(), &wrong, now + 1, &store).unwrap_err();
        assert!(matches!(
            err,
            ExecutionNonceError::BindingMismatch { field: "tool_name" }
        ));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::default();
        let cfg = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = 1_000_000;

        let mut signed = mint_execution_nonce(&kp, binding.clone(), &cfg, now).unwrap();
        // Mutate a signed field without re-signing: signature must no longer verify.
        signed.nonce.bound_to.tool_name = "write_file".to_string();
        // Revert the binding mismatch check by also mutating the presented binding.
        let mut expected = binding;
        expected.tool_name = "write_file".to_string();

        let err = verify_execution_nonce(&signed, &kp.public_key(), &expected, now + 1, &store)
            .unwrap_err();
        assert!(matches!(err, ExecutionNonceError::InvalidSignature));
    }

    #[test]
    fn store_reserves_each_nonce_exactly_once() {
        let store = InMemoryExecutionNonceStore::default();
        assert!(store.reserve("a").unwrap());
        assert!(!store.reserve("a").unwrap());
        assert!(store.reserve("b").unwrap());
    }

    #[test]
    fn legacy_store_falls_back_to_its_reserve_contract() {
        let kp = Keypair::generate();
        let config = ExecutionNonceConfig::default();
        let binding = sample_binding();
        let now = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
        let signed = mint_execution_nonce(&kp, binding.clone(), &config, now).unwrap();

        verify_execution_nonce(
            &signed,
            &kp.public_key(),
            &binding,
            now,
            &LegacyExecutionNonceStore,
        )
        .unwrap();
    }

    #[test]
    fn in_memory_dispatch_reservation_rolls_back_only_for_its_owner() {
        let store = InMemoryExecutionNonceStore::default();
        assert!(store
            .reserve_for_dispatch("dispatch-owned", i64::MAX, "owner-a")
            .unwrap());
        assert!(!store
            .rollback_dispatch_reservation("dispatch-owned", "owner-b")
            .unwrap());
        assert!(!store.reserve("dispatch-owned").unwrap());
        assert!(store
            .rollback_dispatch_reservation("dispatch-owned", "owner-a")
            .unwrap());
        assert!(store.reserve("dispatch-owned").unwrap());
    }

    #[test]
    fn in_memory_capacity_pressure_does_not_evict_live_dispatch_reservation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryExecutionNonceStore::new(2, Duration::from_secs(60));
        assert!(store.reserve_for_dispatch("nonce-a", i64::MAX, "owner-a")?);
        assert!(store.reserve_for_dispatch("nonce-b", i64::MAX, "owner-b")?);
        assert!(store
            .reserve_for_dispatch("nonce-c", i64::MAX, "owner-c")
            .is_err());
        assert!(!store.reserve("nonce-a")?);
        assert!(!store.reserve("nonce-b")?);
        assert!(store.rollback_dispatch_reservation("nonce-a", "owner-a")?);
        assert!(store.reserve_for_dispatch("nonce-c", i64::MAX, "owner-c")?);
        Ok(())
    }

    #[test]
    fn in_memory_capacity_pressure_retains_consumed_nonce_until_expiry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryExecutionNonceStore::new(1, Duration::from_secs(60));
        assert!(store.reserve("nonce-a")?);
        assert!(store.reserve("nonce-b").is_err());
        assert!(!store.reserve("nonce-a")?);

        let expired_store = InMemoryExecutionNonceStore::new(1, Duration::ZERO);
        assert!(expired_store.reserve("nonce-a")?);
        assert!(expired_store.reserve("nonce-b")?);
        Ok(())
    }

    #[test]
    fn in_memory_utilization_reports_live_entries_and_capacity(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = InMemoryExecutionNonceStore::new(5, Duration::from_secs(60));
        assert_eq!(store.utilization()?, (0, 5));
        assert!(store.reserve("nonce-a")?);
        assert!(store.reserve("nonce-b")?);
        assert_eq!(store.utilization()?, (2, 5));
        Ok(())
    }

    #[test]
    fn verification_quota_preserves_capacity_for_other_capabilities(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let keypair = Keypair::generate();
        let config = ExecutionNonceConfig {
            nonce_ttl_secs: 120,
            nonce_store_capacity: 8,
            require_nonce: true,
        };
        let store = InMemoryExecutionNonceStore::from_config(&config);
        assert_eq!(store.inner.lock().unwrap().per_capability_capacity, 1);
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;

        let capability_a = sample_binding();
        let first = mint_execution_nonce(&keypair, capability_a.clone(), &config, now)?;
        let second = mint_execution_nonce(&keypair, capability_a.clone(), &config, now)?;
        verify_execution_nonce(&first, &keypair.public_key(), &capability_a, now, &store)?;
        assert!(matches!(
            verify_execution_nonce(
                &second,
                &keypair.public_key(),
                &capability_a,
                now,
                &store,
            ),
            Err(ExecutionNonceError::Store(message))
                if message.contains("per-capability quota exhausted")
        ));

        let mut capability_b = capability_a;
        capability_b.capability_id = "cap-456".to_string();
        let other = mint_execution_nonce(&keypair, capability_b.clone(), &config, now)?;
        verify_execution_nonce(&other, &keypair.public_key(), &capability_b, now, &store)?;
        assert_eq!(store.utilization()?, (2, 8));
        Ok(())
    }

    #[test]
    fn scoped_dispatch_rollback_releases_capability_quota() -> Result<(), KernelError> {
        let store = InMemoryExecutionNonceStore::new(8, Duration::from_secs(60));
        assert!(store.reserve_for_dispatch_for_capability(
            "nonce-a",
            i64::MAX,
            "capability-a",
            "owner-a",
        )?);
        assert!(store
            .reserve_for_dispatch_for_capability("nonce-b", i64::MAX, "capability-a", "owner-b",)
            .is_err());
        assert!(!store.rollback_dispatch_reservation("nonce-a", "owner-b")?);
        assert!(store
            .reserve_for_dispatch_for_capability("nonce-b", i64::MAX, "capability-a", "owner-b",)
            .is_err());
        assert!(store.rollback_dispatch_reservation("nonce-a", "owner-a")?);
        assert!(store.reserve_for_dispatch_for_capability(
            "nonce-b",
            i64::MAX,
            "capability-a",
            "owner-b",
        )?);
        Ok(())
    }

    #[test]
    fn expired_scoped_entry_releases_capability_quota() -> Result<(), KernelError> {
        let start_wall = UNIX_EPOCH.checked_add(Duration::from_secs(10_000)).unwrap();
        let start_monotonic = Instant::now();
        let store = InMemoryExecutionNonceStore::new(8, Duration::from_secs(60));
        {
            let mut state = store.inner.lock().unwrap();
            state.wall_clock_high_water = start_wall;
            state.monotonic_high_water = start_monotonic;
        }
        let expired_retention = ReplayRetention::signed_until_at(
            start_wall.checked_add(Duration::from_secs(1)),
            start_wall,
            start_monotonic,
        );
        assert!(store.reserve_entry_at_with_capability(
            "nonce-a",
            expired_retention,
            Some("capability-a"),
            None,
            start_wall,
            start_monotonic,
        )?);

        let later_wall = start_wall.checked_add(Duration::from_secs(2)).unwrap();
        let later_monotonic = start_monotonic.checked_add(Duration::from_secs(2)).unwrap();
        let live_retention = ReplayRetention::signed_until_at(
            later_wall.checked_add(Duration::from_secs(60)),
            later_wall,
            later_monotonic,
        );
        assert!(store.reserve_entry_at_with_capability(
            "nonce-b",
            live_retention,
            Some("capability-a"),
            None,
            later_wall,
            later_monotonic,
        )?);
        assert_eq!(
            store
                .inner
                .lock()
                .unwrap()
                .capability_counts
                .get("capability-a"),
            Some(&1)
        );
        Ok(())
    }

    #[test]
    fn signed_expiry_overrides_shorter_local_ttl_under_pressure(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let kp = Keypair::generate();
        let store = InMemoryExecutionNonceStore::new(1, Duration::ZERO);
        let config = ExecutionNonceConfig {
            nonce_ttl_secs: 120,
            nonce_store_capacity: 1,
            require_nonce: true,
        };
        let binding = sample_binding();
        let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
        let signed = mint_execution_nonce(&kp, binding.clone(), &config, now)?;

        verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 1, &store)?;
        assert!(matches!(
            verify_execution_nonce(&signed, &kp.public_key(), &binding, now + 2, &store),
            Err(ExecutionNonceError::Replayed)
        ));

        let other = mint_execution_nonce(&kp, binding.clone(), &config, now)?;
        assert!(matches!(
            verify_execution_nonce(&other, &kp.public_key(), &binding, now + 2, &store),
            Err(ExecutionNonceError::Store(_))
        ));

        let expired_store = InMemoryExecutionNonceStore::new(1, Duration::from_secs(60));
        assert!(!expired_store.reserve_until("expired", 0)?);
        assert!(expired_store.reserve_until("fresh", now + 60)?);
        Ok(())
    }

    #[test]
    fn signed_replay_stays_closed_after_reclamation_and_tolerated_clock_skew(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start_wall = UNIX_EPOCH.checked_add(Duration::from_secs(10_000)).unwrap();
        let start_monotonic = Instant::now();
        let store = InMemoryExecutionNonceStore::new(3, Duration::from_secs(60));
        store.inner.lock().unwrap().wall_clock_high_water = start_wall;

        let used_retention = ReplayRetention::signed_until_at(
            start_wall.checked_add(Duration::from_secs(10)),
            start_wall,
            start_monotonic,
        );
        assert!(store.reserve_entry_at(
            "used",
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
        assert!(store.reserve_entry_at(
            "other",
            other_retention,
            None,
            forward_wall,
            forward_monotonic,
        )?);
        assert!(store.inner.lock().unwrap().cache.peek("used").is_none());

        let rollback_wall = start_wall.checked_add(Duration::from_secs(5)).unwrap();
        let rollback_monotonic = forward_monotonic
            .checked_add(Duration::from_secs(1))
            .unwrap();
        assert!(!store.reserve_entry_at(
            "used",
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
        assert!(store.reserve_entry_at(
            "new-signed",
            later_horizon,
            None,
            rollback_wall,
            rollback_monotonic,
        )?);
        assert!(store.reserve_entry_at(
            "local-only",
            ReplayRetention::local(Duration::from_secs(60)),
            None,
            rollback_wall,
            rollback_monotonic,
        )?);
        Ok(())
    }

    #[test]
    fn suspicious_clock_jump_is_typed_and_does_not_latch_high_water(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let start_wall = UNIX_EPOCH.checked_add(Duration::from_secs(10_000)).unwrap();
        let start_monotonic = Instant::now();
        let store = InMemoryExecutionNonceStore::new(2, Duration::from_secs(60));
        {
            let mut state = store.inner.lock().unwrap();
            state.wall_clock_high_water = start_wall;
            state.monotonic_high_water = start_monotonic;
        }
        let retention = ReplayRetention::signed_until_at(
            start_wall.checked_add(Duration::from_secs(1_000)),
            start_wall,
            start_monotonic,
        );
        let jumped_wall = start_wall.checked_add(Duration::from_secs(302)).unwrap();
        let next_monotonic = start_monotonic.checked_add(Duration::from_secs(1)).unwrap();
        let error = store
            .reserve_entry_at("jumped", retention, None, jumped_wall, next_monotonic)
            .unwrap_err();
        assert!(matches!(
            error,
            KernelError::ReplayClockAnomaly {
                direction: crate::ReplayClockDirection::ForwardJump,
                ..
            }
        ));

        let recovered_wall = start_wall.checked_add(Duration::from_secs(2)).unwrap();
        let recovered_monotonic = start_monotonic.checked_add(Duration::from_secs(2)).unwrap();
        assert!(store.reserve_entry_at(
            "recovered",
            retention,
            None,
            recovered_wall,
            recovered_monotonic,
        )?);
        Ok(())
    }

    #[test]
    fn store_does_not_stall_between_threads() {
        let store = std::sync::Arc::new(InMemoryExecutionNonceStore::default());
        let mut handles = Vec::new();
        for i in 0..4 {
            let store = std::sync::Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let id = format!("t-{i}");
                store.reserve(&id).unwrap()
            }));
        }
        for h in handles {
            assert!(h.join().unwrap());
        }
    }
}
