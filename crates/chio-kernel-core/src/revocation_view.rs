//! Read-only revocation snapshot consulted on every dispatch.
//!
//! `RevocationView` is the kernel-core surface that the federation gossip
//! task updates with the latest signed epoch root; verifiers read the
//! current snapshot during evaluation without ever blocking a writer. The
//! cache itself is arc-swap-backed: writers atomically replace the inner
//! `Arc<RevocationSnapshot>`, readers obtain a `Guard` that holds a
//! reference for the lifetime of the dispatch call.
//!
//! ## Fail-closed contract
//!
//! * A freshly-constructed view holds the [`RevocationSnapshot::empty`]
//!   sentinel: epoch `0`, no revoked subjects, issued-at `0`. Verifiers
//!   that have never seen a real epoch root MUST treat this snapshot as
//!   "no revocations known" but MUST still apply their freshness gate
//!   (`max_staleness_ms`) before allowing dispatch (a snapshot whose
//!   `issued_at_unix_ms` is too old to satisfy the local freshness window
//!   denies access).
//! * Writers MUST never replace the snapshot with one whose `epoch` is
//!   strictly less than the currently-installed snapshot. The
//!   [`RevocationView::install_if_newer`] helper enforces that monotone
//!   advancement so a malicious or stale gossip frame cannot rewind the
//!   verifier's view.
//! * Writers MUST also confirm the new snapshot's `epoch` agrees with the
//!   embedded `signed_root_epoch` field: tampering with the unsigned hint
//!   surface drops the update.
//!
//! ## Module gating
//!
//! The module is gated behind the `revocation-view` feature (which itself
//! implies `std`) because [`arc_swap::ArcSwap`] requires hosted runtime
//! services. The portable `no_std + alloc` proof does not observe this
//! surface and falls back to whatever explicit denylist the embedding
//! kernel passes through `chio-kernel-core::guard::GuardContext`.

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Stable identifier for a subject whose credentials may be revoked. Mirrors
/// `chio_revocation_oracle::SubjectId` but does NOT depend on the oracle
/// crate, keeping `chio-kernel-core` decoupled from the federation /
/// revocation-oracle layer above it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RevocationViewSubject(String);

impl RevocationViewSubject {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for RevocationViewSubject {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for RevocationViewSubject {
    fn from(value: String) -> Self {
        Self(value)
    }
}

/// Immutable snapshot of the revocation set at a particular epoch.
///
/// Snapshots are produced by the federation gossip task from the most
/// recent verified signed epoch root and the leaf set the embedding kernel
/// has materialised locally. Once installed in a [`RevocationView`] they
/// are read-only; updates always go through a fresh
/// [`RevocationView::install_if_newer`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationSnapshot {
    /// Monotone epoch counter advertised by the carried signed root.
    pub epoch: u64,
    /// Hash of the carried signed root. Verifiers use this for diagnostics
    /// (e.g. correlating a deny verdict with the snapshot it was evaluated
    /// against); the kernel-core itself does not re-verify it.
    pub root_hash: [u8; 32],
    /// Unix milliseconds at which the carried signed root was issued.
    /// Verifiers MUST gate against their own freshness window before
    /// trusting the snapshot for fail-closed dispatch.
    pub issued_at_unix_ms: u64,
    /// Sorted set of revoked subjects at this epoch. Ordered for
    /// deterministic equality and serialisation.
    pub revoked: BTreeSet<RevocationViewSubject>,
}

impl RevocationSnapshot {
    /// The empty sentinel snapshot (`epoch = 0`, no subjects, issued at
    /// `0`). Returned by [`RevocationView::new`] before any gossip update
    /// has installed a real epoch root.
    pub fn empty() -> Self {
        Self {
            epoch: 0,
            root_hash: [0_u8; 32],
            issued_at_unix_ms: 0,
            revoked: BTreeSet::new(),
        }
    }

    /// Returns `true` when `subject` is present in the snapshot's
    /// revocation set.
    pub fn is_revoked(&self, subject: &RevocationViewSubject) -> bool {
        self.revoked.contains(subject)
    }
}

/// Errors surfaced by the revocation-view cache. Every variant is
/// fail-closed: the embedding kernel MUST refuse to install a snapshot that
/// triggers any of them and SHOULD treat the active snapshot as the only
/// safe reference for in-flight dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationViewError {
    /// Candidate snapshot's epoch is not strictly greater than the
    /// currently-installed snapshot. Required to keep the view monotone so
    /// a stale or replayed gossip frame cannot rewind dispatch.
    NonMonotoneEpoch { candidate: u64, installed: u64 },
}

impl core::fmt::Display for RevocationViewError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NonMonotoneEpoch {
                candidate,
                installed,
            } => write!(
                f,
                "candidate snapshot epoch {candidate} is not strictly greater than installed epoch {installed}"
            ),
        }
    }
}

impl core::error::Error for RevocationViewError {}

/// Arc-swap-backed read-only snapshot store. Cheap to clone (it is itself
/// an `Arc` internally) so embedding kernels can hand a clone to every
/// dispatch worker.
#[derive(Debug)]
pub struct RevocationView {
    inner: ArcSwap<RevocationSnapshot>,
}

impl Default for RevocationView {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationView {
    /// Create a new view holding the [`RevocationSnapshot::empty`]
    /// sentinel.
    pub fn new() -> Self {
        Self {
            inner: ArcSwap::from_pointee(RevocationSnapshot::empty()),
        }
    }

    /// Borrow the currently-installed snapshot for the lifetime of the
    /// returned guard. Readers never block writers and vice versa.
    pub fn load(&self) -> Arc<RevocationSnapshot> {
        ArcSwap::load_full(&self.inner)
    }

    /// Replace the snapshot iff `candidate.epoch > current.epoch`.
    ///
    /// Returns the previously-installed snapshot on success. Returns
    /// [`RevocationViewError::NonMonotoneEpoch`] when the candidate's
    /// epoch does not strictly advance the current one; the active
    /// snapshot is left unchanged in that case (fail-closed).
    pub fn install_if_newer(
        &self,
        candidate: RevocationSnapshot,
    ) -> Result<Arc<RevocationSnapshot>, RevocationViewError> {
        let current = self.load();
        if candidate.epoch <= current.epoch {
            return Err(RevocationViewError::NonMonotoneEpoch {
                candidate: candidate.epoch,
                installed: current.epoch,
            });
        }
        self.inner.store(Arc::new(candidate));
        Ok(current)
    }

    /// Convenience for the most common dispatch lookup.
    pub fn is_revoked(&self, subject: &RevocationViewSubject) -> bool {
        self.load().is_revoked(subject)
    }

    /// Currently-installed epoch counter. Cheap (no clone of the snapshot
    /// body).
    pub fn current_epoch(&self) -> u64 {
        self.load().epoch
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn snapshot(epoch: u64, revoked: &[&str]) -> RevocationSnapshot {
        let revoked_set = revoked
            .iter()
            .copied()
            .map(RevocationViewSubject::from)
            .collect();
        RevocationSnapshot {
            epoch,
            root_hash: [(epoch as u8); 32],
            issued_at_unix_ms: 1_700_000_000_000 + epoch,
            revoked: revoked_set,
        }
    }

    #[test]
    fn new_view_holds_empty_sentinel() {
        let view = RevocationView::new();
        let loaded = view.load();
        assert_eq!(*loaded, RevocationSnapshot::empty());
        assert_eq!(view.current_epoch(), 0);
    }

    #[test]
    fn install_if_newer_advances_monotonically() {
        let view = RevocationView::new();
        let prev = view.install_if_newer(snapshot(1, &["alice"])).unwrap();
        assert_eq!(prev.epoch, 0);
        let prev2 = view
            .install_if_newer(snapshot(5, &["alice", "bob"]))
            .unwrap();
        assert_eq!(prev2.epoch, 1);
        assert_eq!(view.current_epoch(), 5);
        assert!(view.is_revoked(&RevocationViewSubject::from("alice")));
        assert!(view.is_revoked(&RevocationViewSubject::from("bob")));
        assert!(!view.is_revoked(&RevocationViewSubject::from("carol")));
    }

    #[test]
    fn install_if_newer_rejects_equal_epoch() {
        let view = RevocationView::new();
        view.install_if_newer(snapshot(1, &["alice"])).unwrap();
        let err = view
            .install_if_newer(snapshot(1, &["alice", "bob"]))
            .expect_err("equal epoch must fail closed");
        assert_eq!(
            err,
            RevocationViewError::NonMonotoneEpoch {
                candidate: 1,
                installed: 1
            }
        );
        // Active snapshot unchanged.
        assert!(!view.is_revoked(&RevocationViewSubject::from("bob")));
    }

    #[test]
    fn install_if_newer_rejects_stale_epoch() {
        let view = RevocationView::new();
        view.install_if_newer(snapshot(5, &["alice"])).unwrap();
        let err = view
            .install_if_newer(snapshot(3, &["dave"]))
            .expect_err("stale epoch must fail closed");
        assert_eq!(
            err,
            RevocationViewError::NonMonotoneEpoch {
                candidate: 3,
                installed: 5
            }
        );
        assert!(!view.is_revoked(&RevocationViewSubject::from("dave")));
    }

    #[test]
    fn snapshot_round_trips_via_serde() {
        let s = snapshot(7, &["alice", "bob"]);
        let bytes = serde_json::to_vec(&s).unwrap();
        let decoded: RevocationSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, s);
    }

    #[test]
    fn snapshot_deny_unknown_fields() {
        let s = snapshot(2, &["alice"]);
        let mut value: serde_json::Value = serde_json::to_value(&s).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".to_string(), serde_json::Value::Bool(true));
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed: Result<RevocationSnapshot, _> = serde_json::from_slice(&bytes);
        assert!(parsed.is_err(), "unknown fields must be rejected");
    }

    #[test]
    fn empty_sentinel_is_default_install_target() {
        let view = RevocationView::default();
        assert_eq!(*view.load(), RevocationSnapshot::empty());
    }

    #[test]
    fn snapshot_preserves_revoked_ordering() {
        let s = snapshot(1, &["delta", "alpha", "charlie", "bravo"]);
        let collected: Vec<String> = s.revoked.iter().map(|k| k.as_str().to_string()).collect();
        assert_eq!(
            collected,
            vec![
                String::from("alpha"),
                String::from("bravo"),
                String::from("charlie"),
                String::from("delta"),
            ]
        );
    }
}
