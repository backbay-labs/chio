//! Replay prevention for governed approval tokens at the dispatch boundary.

use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use lru::LruCache;
use tracing::error;

use crate::replay_retention::{
    advance_replay_clock, PendingReplayClockRebaseline, ReplayRetention,
};
use crate::KernelError;

/// Default number of live governed approvals retained by the in-memory store.
pub const DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY: usize = 8192;

/// Atomic reservation store for single-use governed approvals.
///
/// A reservation is owned until it is either committed or rolled back. Commit
/// retains the replay marker but clears rollback ownership. Implementations
/// must leave the marker replay-blocking when commit returns `false` or an
/// error because a dispatch or external payment may already have happened.
/// Embedding hosts must explicitly install a store before accepting governed
/// requests; use a durable implementation when replay protection must survive
/// process restart.
pub trait GovernedApprovalReplayStore: Send + Sync {
    /// Reserve a `(subject_id, request_id, intent_hash)` tuple until its signed
    /// expiry. Capacity is store-global; multi-tenant hosts should isolate
    /// tenants in separate kernels or enforce upstream admission limits.
    fn reserve_for_dispatch(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;

    /// Commit a reservation owned by `reservation_id` without removing it.
    fn commit_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;

    /// Remove a reservation only when `reservation_id` still owns it.
    fn rollback_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError>;
}

/// Process-scoped governed approval replay store.
///
/// This implementation must be explicitly installed on the kernel. Use a
/// durable implementation when replay protection must survive restart.
pub struct InMemoryGovernedApprovalReplayStore {
    inner: Mutex<ApprovalReplayState>,
}

struct ApprovalReplayState {
    cache: LruCache<(String, String, String), ApprovalReplayEntry>,
    wall_clock_high_water: SystemTime,
    monotonic_high_water: Instant,
    pending_clock_rebaseline: Option<PendingReplayClockRebaseline>,
}

struct ApprovalReplayEntry {
    retention: ReplayRetention,
    reservation_id: Option<String>,
}

impl InMemoryGovernedApprovalReplayStore {
    /// # Panics
    ///
    /// Panics when `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = match NonZeroUsize::new(capacity) {
            Some(capacity) => capacity,
            None => panic!("governed approval replay capacity must be greater than zero"),
        };
        Self {
            inner: Mutex::new(ApprovalReplayState {
                cache: LruCache::new(capacity),
                wall_clock_high_water: SystemTime::now(),
                monotonic_high_water: Instant::now(),
                pending_clock_rebaseline: None,
            }),
        }
    }

    fn reserve_at(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
        now: (SystemTime, Instant),
    ) -> Result<bool, KernelError> {
        let (now_wall, now_monotonic) = now;
        validate_key_part("subject_id", subject_id)?;
        validate_key_part("request_id", request_id)?;
        validate_key_part("intent_hash", intent_hash)?;
        validate_key_part("reservation_id", reservation_id)?;

        let key = (
            subject_id.to_string(),
            request_id.to_string(),
            intent_hash.to_string(),
        );
        let retention = ReplayRetention::signed_until_unix_secs(expires_at);
        let mut state = self.inner.lock().map_err(|_| {
            error!("governed approval replay store mutex poisoned; denying fail-closed");
            KernelError::GovernedTransactionDenied(
                "approval replay store unavailable; denying fail-closed".to_string(),
            )
        })?;

        let mut wall_clock_high_water = state.wall_clock_high_water;
        let mut monotonic_high_water = state.monotonic_high_water;
        let mut pending_clock_rebaseline = state.pending_clock_rebaseline;
        let clock_result = advance_replay_clock(
            "governed_approval",
            &mut wall_clock_high_water,
            &mut monotonic_high_water,
            &mut pending_clock_rebaseline,
            now_wall,
            now_monotonic,
        );
        state.wall_clock_high_water = wall_clock_high_water;
        state.monotonic_high_water = monotonic_high_water;
        state.pending_clock_rebaseline = pending_clock_rebaseline;
        let high_water = clock_result?;

        if state
            .cache
            .peek(&key)
            .is_some_and(|entry| !entry.retention.is_expired_at(high_water, now_monotonic))
        {
            return Ok(false);
        }

        let expired_keys = state
            .cache
            .iter()
            .filter(|(_, entry)| entry.retention.is_expired_at(high_water, now_monotonic))
            .map(|(expired_key, _)| expired_key.clone())
            .collect::<Vec<_>>();
        for expired_key in expired_keys {
            state.cache.pop(&expired_key);
        }

        if retention.signed_horizon_elapsed_at(high_water) {
            error!("elapsed approval horizon; denying replay reservation");
            return Ok(false);
        }
        if state.cache.len() >= state.cache.cap().get() {
            error!(
                capacity = state.cache.cap().get(),
                "governed approval replay store capacity exhausted; denying fail-closed"
            );
            return Err(KernelError::GovernedTransactionDenied(
                "approval replay store capacity exhausted; denying fail-closed".to_string(),
            ));
        }

        state.cache.put(
            key,
            ApprovalReplayEntry {
                retention,
                reservation_id: Some(reservation_id.to_string()),
            },
        );
        Ok(true)
    }
}

impl Default for InMemoryGovernedApprovalReplayStore {
    fn default() -> Self {
        Self::new(DEFAULT_GOVERNED_APPROVAL_REPLAY_CAPACITY)
    }
}

impl GovernedApprovalReplayStore for InMemoryGovernedApprovalReplayStore {
    fn reserve_for_dispatch(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        expires_at: u64,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        self.reserve_at(
            subject_id,
            request_id,
            intent_hash,
            expires_at,
            reservation_id,
            (SystemTime::now(), Instant::now()),
        )
    }

    fn commit_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let key = (
            subject_id.to_string(),
            request_id.to_string(),
            intent_hash.to_string(),
        );
        let mut state = self.inner.lock().map_err(|_| {
            KernelError::GovernedTransactionDenied(
                "approval replay store unavailable during commit; marker retained fail-closed"
                    .to_string(),
            )
        })?;
        let Some(entry) = state.cache.peek_mut(&key) else {
            return Ok(false);
        };
        if entry.reservation_id.as_deref() != Some(reservation_id) {
            return Ok(false);
        }
        entry.reservation_id = None;
        Ok(true)
    }

    fn rollback_dispatch_reservation(
        &self,
        subject_id: &str,
        request_id: &str,
        intent_hash: &str,
        reservation_id: &str,
    ) -> Result<bool, KernelError> {
        let key = (
            subject_id.to_string(),
            request_id.to_string(),
            intent_hash.to_string(),
        );
        let mut state = self.inner.lock().map_err(|_| {
            KernelError::GovernedTransactionDenied(
                "approval replay store unavailable during rollback; marker retained fail-closed"
                    .to_string(),
            )
        })?;
        let owned = state
            .cache
            .peek(&key)
            .is_some_and(|entry| entry.reservation_id.as_deref() == Some(reservation_id));
        if owned {
            state.cache.pop(&key);
        }
        Ok(owned)
    }
}

fn validate_key_part(name: &str, value: &str) -> Result<(), KernelError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(KernelError::GovernedTransactionDenied(format!(
            "approval replay {name} must be non-empty and unpadded"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    #[should_panic(expected = "governed approval replay capacity must be greater than zero")]
    fn zero_capacity_is_rejected() {
        let _store = InMemoryGovernedApprovalReplayStore::new(0);
    }

    #[test]
    fn commit_retains_marker_and_disables_owner_rollback() {
        let store = InMemoryGovernedApprovalReplayStore::new(2);
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(60);
        assert!(store
            .reserve_for_dispatch("subject", "request", "intent", expires_at, "owner")
            .unwrap_or(false));
        assert!(store
            .commit_dispatch_reservation("subject", "request", "intent", "owner")
            .unwrap_or(false));
        assert!(!store
            .rollback_dispatch_reservation("subject", "request", "intent", "owner")
            .unwrap_or(true));
        assert!(!store
            .reserve_for_dispatch("subject", "request", "intent", expires_at, "other")
            .unwrap_or(true));
    }

    #[test]
    fn rollback_is_owner_qualified() {
        let store = InMemoryGovernedApprovalReplayStore::new(2);
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(60);
        assert!(store
            .reserve_for_dispatch("subject", "request", "intent", expires_at, "owner")
            .unwrap_or(false));
        assert!(!store
            .rollback_dispatch_reservation("subject", "request", "intent", "other")
            .unwrap_or(true));
        assert!(store
            .rollback_dispatch_reservation("subject", "request", "intent", "owner")
            .unwrap_or(false));
    }

    #[test]
    fn live_capacity_is_not_evicted() {
        let store = InMemoryGovernedApprovalReplayStore::new(1);
        let now = SystemTime::now();
        let expires_at = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(60);
        assert!(store
            .reserve_at(
                "subject",
                "request-a",
                "intent-a",
                expires_at,
                "owner-a",
                (now, Instant::now()),
            )
            .unwrap_or(false));
        assert!(store
            .reserve_at(
                "subject",
                "request-b",
                "intent-b",
                expires_at,
                "owner-b",
                (now + Duration::from_secs(1), Instant::now()),
            )
            .is_err());
        assert!(!store
            .reserve_for_dispatch("subject", "request-a", "intent-a", expires_at, "other",)
            .unwrap_or(true));
    }

    #[test]
    fn identical_request_and_intent_are_scoped_by_subject() {
        let store = InMemoryGovernedApprovalReplayStore::new(2);
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(60);
        assert!(store
            .reserve_for_dispatch("subject-a", "request", "intent", expires_at, "owner-a")
            .unwrap_or(false));
        assert!(store
            .reserve_for_dispatch("subject-b", "request", "intent", expires_at, "owner-b")
            .unwrap_or(false));
    }
}
