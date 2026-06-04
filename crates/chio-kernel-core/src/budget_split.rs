//! Sibling-sum budget enforcement for delegated capability tokens.
//!
//! `CapabilityToken::validate_schema` already enforces the per-token cap
//! `budget_share_bps <= 10_000`. That check is necessary but not sufficient:
//! it does not see siblings. A parent at `5_000` bps could mint two children
//! at `5_000` bps each, and per-token validation would happily accept both,
//! letting the children jointly claim 100% of the parent's authority while
//! the parent itself only owns 50%.
//!
//! [`BudgetSplit`] and the [`BudgetRegistry`] trait close that gap. When a
//! verifier admits a freshly delegated child, it asks the registry whether
//! the parent has enough remaining headroom. If the running sum of admitted
//! sibling shares plus the new child's share would exceed the parent's
//! share, the registry rejects the child and verification fails closed.
//!
//! The split type is intentionally pure: it owns no clock, no I/O, and no
//! revocation state. Callers that need a hosted in-memory registry use
//! [`InMemoryBudgetRegistry`] (gated behind the crate `std` feature).
//! `no_std` consumers can implement the [`BudgetRegistry`] trait against
//! their own storage.
//!
//! ## Overflow safety
//!
//! [`BudgetSplit::current_total_child_bps`] returns a `u32` and the admit
//! check uses `u32` arithmetic so two `u16::MAX` siblings cannot overflow
//! into a wraparound that silently passes the cap. The parent share itself
//! is bounded by [`MAX_BUDGET_SHARE_BPS`] which the per-token validator
//! enforces at load time.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use core::fmt;

/// Hard ceiling on any single token's budget share in basis points.
///
/// 10000 bps = 100%. Per-token validation already rejects values above this
/// threshold; the constant is re-exported so registry implementations can
/// share the same bound.
pub const MAX_BUDGET_SHARE_BPS: u16 = 10_000;

/// A live record of how much of a parent's budget has already been delegated
/// to admitted children.
///
/// The struct is owned by a [`BudgetRegistry`] implementation. Each verified
/// delegation either admits a new child (incrementing the running sum) or
/// fails closed because the proposed share would push the sum past the
/// parent's own share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetSplit {
    /// Capability ID of the parent token whose budget is being split.
    pub parent_token_id: String,
    /// The parent's own share in basis points. Bounded by
    /// [`MAX_BUDGET_SHARE_BPS`].
    pub parent_share_bps: u16,
    /// Map from child capability ID to the share that child claimed when it
    /// was admitted.
    pub children: BTreeMap<String, u16>,
}

/// Errors raised by [`BudgetSplit`] admission and release operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetSplitError {
    /// The proposed child share alone exceeds the per-token cap of
    /// [`MAX_BUDGET_SHARE_BPS`]. Per-token validation usually catches this
    /// first; the registry repeats the check so a bypass cannot widen the
    /// surface.
    ChildShareExceedsCap {
        /// The child capability ID that was rejected.
        child_id: String,
        /// The proposed child share in basis points.
        share_bps: u16,
    },
    /// Admitting this child would push the sum of sibling shares past the
    /// parent's own share. The first sibling that hits this branch is
    /// rejected; previously admitted siblings are not retroactively evicted.
    OversubscribedSiblings {
        /// The child capability ID that was rejected.
        child_id: String,
        /// The proposed child share in basis points.
        share_bps: u16,
        /// The sum of already-admitted siblings, in basis points.
        current_total_child_bps: u32,
        /// The parent's own share, in basis points.
        parent_share_bps: u16,
    },
    /// The parent token is unknown to the registry. This happens when the
    /// verifier sees a delegation chain whose root was never registered, or
    /// after a parent has been evicted.
    UnknownParent {
        /// The parent capability ID that was looked up.
        parent_token_id: String,
    },
    /// The child token has already been admitted under this parent. The
    /// registry is idempotent: re-admitting the same child with the same
    /// share is a silent success, but a different share is a hard failure
    /// because it would let an attacker rewrite the split after the fact.
    DuplicateChild {
        /// The child capability ID that was already present.
        child_id: String,
    },
    /// The release path was asked to remove a child with a different share
    /// than the one originally admitted. This is a hard failure because it
    /// means the caller is no longer unwinding the same delegation edge.
    ReleaseShareMismatch {
        /// The child capability ID whose admitted share differed.
        child_id: String,
        /// The share supplied by the caller during release.
        expected_share_bps: u16,
        /// The share recorded during admission.
        actual_share_bps: u16,
    },
}

impl fmt::Display for BudgetSplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BudgetSplitError::ChildShareExceedsCap {
                child_id,
                share_bps,
            } => write!(
                f,
                "child {child_id} share {share_bps} bps exceeds the {} bps per-token cap",
                MAX_BUDGET_SHARE_BPS
            ),
            BudgetSplitError::OversubscribedSiblings {
                child_id,
                share_bps,
                current_total_child_bps,
                parent_share_bps,
            } => write!(
                f,
                "child {child_id} share {share_bps} bps + sibling sum {current_total_child_bps} bps > parent share {parent_share_bps} bps"
            ),
            BudgetSplitError::UnknownParent { parent_token_id } => {
                write!(f, "parent capability {parent_token_id} is not registered")
            }
            BudgetSplitError::DuplicateChild { child_id } => write!(
                f,
                "child capability {child_id} already admitted under this parent with a different share"
            ),
            BudgetSplitError::ReleaseShareMismatch {
                child_id,
                expected_share_bps,
                actual_share_bps,
            } => write!(
                f,
                "child capability {child_id} release share {expected_share_bps} bps does not match admitted share {actual_share_bps} bps"
            ),
        }
    }
}

impl BudgetSplit {
    /// Build an empty split for `parent_token_id` with the given parent
    /// share. The parent share is clamped to [`MAX_BUDGET_SHARE_BPS`] by the
    /// per-token validator before this constructor is called; it is the
    /// caller's responsibility not to fabricate a higher value here.
    #[must_use]
    pub fn new(parent_token_id: String, parent_share_bps: u16) -> Self {
        Self {
            parent_token_id,
            parent_share_bps,
            children: BTreeMap::new(),
        }
    }

    /// Return the running sum of admitted sibling shares as a `u32` to avoid
    /// overflow even on a maximally adversarial set of admitted children.
    #[must_use]
    pub fn current_total_child_bps(&self) -> u32 {
        self.children.values().map(|share| u32::from(*share)).sum()
    }

    /// Try to admit a new child under this parent.
    ///
    /// Returns `Ok(())` when the child is admitted. The child is recorded in
    /// the children map. Re-admitting the same child id with the same share
    /// is idempotent and returns `Ok(())` without mutating the running sum.
    ///
    /// Returns [`BudgetSplitError`] when the child share alone exceeds the
    /// per-token cap, when the proposed share would oversubscribe the
    /// parent, or when a different share has already been recorded for this
    /// child id.
    pub fn try_admit_child(
        &mut self,
        child_id: String,
        share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        if share_bps > MAX_BUDGET_SHARE_BPS {
            return Err(BudgetSplitError::ChildShareExceedsCap {
                child_id,
                share_bps,
            });
        }
        if let Some(existing) = self.children.get(&child_id) {
            if *existing == share_bps {
                return Ok(());
            }
            return Err(BudgetSplitError::DuplicateChild { child_id });
        }
        let running = self.current_total_child_bps();
        let proposed_total = running.saturating_add(u32::from(share_bps));
        if proposed_total > u32::from(self.parent_share_bps) {
            return Err(BudgetSplitError::OversubscribedSiblings {
                child_id,
                share_bps,
                current_total_child_bps: running,
                parent_share_bps: self.parent_share_bps,
            });
        }
        self.children.insert(child_id, share_bps);
        Ok(())
    }

    /// Release a child admission previously recorded under this parent.
    ///
    /// Missing children are treated as already released so pre-dispatch
    /// cleanup paths can call this after both admission failures and later
    /// denial failures without branching on partial state. A mismatched share
    /// is still rejected because it indicates the caller is trying to unwind
    /// a different child edge.
    pub fn release_child(
        &mut self,
        child_id: &str,
        expected_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        let Some(actual_share_bps) = self.children.get(child_id).copied() else {
            return Ok(());
        };
        if actual_share_bps != expected_share_bps {
            return Err(BudgetSplitError::ReleaseShareMismatch {
                child_id: child_id.to_string(),
                expected_share_bps,
                actual_share_bps,
            });
        }
        let _ = self.children.remove(child_id);
        Ok(())
    }
}

/// A registry of live [`BudgetSplit`]s, keyed by parent capability id.
///
/// The verifier calls [`BudgetRegistry::try_admit_child`] before issuing a
/// `VerifiedCapability` for any token whose `delegation_chain` is non-empty.
/// `register_parent` is called when a new parent token enters the system,
/// and `evict_parent` is called when a parent is revoked or expires.
///
/// A federated registry that gossips splits across kernels has the same
/// trait surface; the in-memory implementation in this crate only models
/// single-process enforcement.
pub trait BudgetRegistry {
    /// Register a parent token's share so subsequent delegations can be
    /// admitted against it. Re-registering the same parent with the same
    /// share is idempotent. Re-registering with a different share is a hard
    /// failure: the caller probably fed two distinct tokens with the same
    /// id, which is a delegation-graph bug.
    fn register_parent(
        &mut self,
        parent_token_id: String,
        parent_share_bps: u16,
    ) -> Result<(), BudgetSplitError>;

    /// Try to admit a child token under the given parent.
    ///
    /// Unknown parents fail closed. Callers that have verifier-owned parent
    /// lineage or a parent snapshot must call [`BudgetRegistry::register_parent`]
    /// before admitting children. This prevents a verifier from fabricating a
    /// missing parent share at [`MAX_BUDGET_SHARE_BPS`].
    fn try_admit_child(
        &mut self,
        parent_token_id: &str,
        child_token_id: String,
        share_bps: u16,
    ) -> Result<(), BudgetSplitError>;

    /// Release a previously admitted child token under the given parent.
    ///
    /// Unknown parents and missing children are idempotent no-ops so cleanup
    /// can safely run after revocation or after an admission attempt that
    /// failed before mutating the registry. Share mismatches fail closed.
    fn release_child(
        &mut self,
        parent_token_id: &str,
        child_token_id: &str,
        expected_share_bps: u16,
    ) -> Result<(), BudgetSplitError>;

    /// Drop the parent's split from the registry. Idempotent; calling
    /// `evict_parent` on an unregistered parent is a no-op so revocation
    /// races do not abort verification.
    fn evict_parent(&mut self, parent_token_id: &str);
}

/// A no-op [`BudgetRegistry`] used by callers that have not yet wired the
/// budget plumbing.
///
/// `register_parent` and `try_admit_child` always return `Ok(())` and the
/// registry never tracks state. This is suitable for legacy entry points
/// that only check signature, issuer trust, and time bounds; new code
/// should use a real registry so sibling oversubscription is rejected.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBudgetRegistry;

impl BudgetRegistry for NoopBudgetRegistry {
    fn register_parent(
        &mut self,
        _parent_token_id: String,
        _parent_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        Ok(())
    }

    fn try_admit_child(
        &mut self,
        _parent_token_id: &str,
        _child_token_id: String,
        _share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        Ok(())
    }

    fn release_child(
        &mut self,
        _parent_token_id: &str,
        _child_token_id: &str,
        _expected_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        Ok(())
    }

    fn evict_parent(&mut self, _parent_token_id: &str) {}
}

/// Pure in-memory [`BudgetRegistry`] backed by a [`BTreeMap`].
///
/// This implementation is `no_std` friendly: it keeps a deterministic map
/// keyed by parent capability id and never reaches for clocks, locks, or
/// allocators outside `alloc`. Hosted callers that need shared mutable
/// access across threads should wrap it in their own `Mutex` / `RwLock`.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBudgetRegistry {
    splits: BTreeMap<String, BudgetSplit>,
}

impl InMemoryBudgetRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            splits: BTreeMap::new(),
        }
    }

    /// Borrow the live split for `parent_token_id`, if any. Useful for
    /// tests and operator dashboards that want to inspect headroom.
    #[must_use]
    pub fn split(&self, parent_token_id: &str) -> Option<&BudgetSplit> {
        self.splits.get(parent_token_id)
    }
}

impl BudgetRegistry for InMemoryBudgetRegistry {
    fn register_parent(
        &mut self,
        parent_token_id: String,
        parent_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        if parent_share_bps > MAX_BUDGET_SHARE_BPS {
            return Err(BudgetSplitError::ChildShareExceedsCap {
                child_id: parent_token_id,
                share_bps: parent_share_bps,
            });
        }
        if let Some(existing) = self.splits.get(&parent_token_id) {
            if existing.parent_share_bps == parent_share_bps {
                return Ok(());
            }
            return Err(BudgetSplitError::DuplicateChild {
                child_id: parent_token_id,
            });
        }
        self.splits.insert(
            parent_token_id.clone(),
            BudgetSplit::new(parent_token_id, parent_share_bps),
        );
        Ok(())
    }

    fn try_admit_child(
        &mut self,
        parent_token_id: &str,
        child_token_id: String,
        share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        match self.splits.get_mut(parent_token_id) {
            Some(split) => split.try_admit_child(child_token_id, share_bps),
            None => Err(BudgetSplitError::UnknownParent {
                parent_token_id: parent_token_id.into(),
            }),
        }
    }

    fn release_child(
        &mut self,
        parent_token_id: &str,
        child_token_id: &str,
        expected_share_bps: u16,
    ) -> Result<(), BudgetSplitError> {
        match self.splits.get_mut(parent_token_id) {
            Some(split) => split.release_child(child_token_id, expected_share_bps),
            None => Ok(()),
        }
    }

    fn evict_parent(&mut self, parent_token_id: &str) {
        let _ = self.splits.remove(parent_token_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn empty_split_total_is_zero() {
        let split = BudgetSplit::new("parent".to_string(), 5_000);
        assert_eq!(split.current_total_child_bps(), 0);
    }

    #[test]
    fn admit_first_child_under_parent_succeeds() {
        let mut split = BudgetSplit::new("parent".to_string(), 5_000);
        split
            .try_admit_child("child-a".to_string(), 4_000)
            .expect("first child fits");
        assert_eq!(split.current_total_child_bps(), 4_000);
    }

    #[test]
    fn second_oversubscribed_sibling_is_rejected() {
        let mut split = BudgetSplit::new("parent".to_string(), 5_000);
        split
            .try_admit_child("child-a".to_string(), 4_000)
            .expect("first child fits");
        let err = split
            .try_admit_child("child-b".to_string(), 4_000)
            .expect_err("second child must oversubscribe");
        match err {
            BudgetSplitError::OversubscribedSiblings {
                child_id,
                share_bps,
                current_total_child_bps,
                parent_share_bps,
            } => {
                assert_eq!(child_id, "child-b");
                assert_eq!(share_bps, 4_000);
                assert_eq!(current_total_child_bps, 4_000);
                assert_eq!(parent_share_bps, 5_000);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Failed child must not be recorded.
        assert_eq!(split.current_total_child_bps(), 4_000);
    }

    #[test]
    fn child_share_exceeding_cap_is_rejected() {
        let mut split = BudgetSplit::new("parent".to_string(), MAX_BUDGET_SHARE_BPS);
        let err = split
            .try_admit_child("child-a".to_string(), MAX_BUDGET_SHARE_BPS + 1)
            .expect_err("over-cap share must fail");
        assert!(matches!(err, BudgetSplitError::ChildShareExceedsCap { .. }));
    }

    #[test]
    fn duplicate_child_with_same_share_is_idempotent() {
        let mut split = BudgetSplit::new("parent".to_string(), 5_000);
        split
            .try_admit_child("child-a".to_string(), 4_000)
            .expect("first admit");
        split
            .try_admit_child("child-a".to_string(), 4_000)
            .expect("idempotent re-admit");
        assert_eq!(split.current_total_child_bps(), 4_000);
    }

    #[test]
    fn duplicate_child_with_different_share_fails() {
        let mut split = BudgetSplit::new("parent".to_string(), 5_000);
        split
            .try_admit_child("child-a".to_string(), 2_000)
            .expect("first admit");
        let err = split
            .try_admit_child("child-a".to_string(), 3_000)
            .expect_err("different share must fail");
        assert!(matches!(err, BudgetSplitError::DuplicateChild { .. }));
        // Original share is preserved.
        assert_eq!(split.current_total_child_bps(), 2_000);
    }

    #[test]
    fn release_child_restores_parent_headroom() {
        let mut split = BudgetSplit::new("parent".to_string(), 5_000);
        split
            .try_admit_child("child-a".to_string(), 4_000)
            .expect("child admits");
        assert_eq!(split.current_total_child_bps(), 4_000);

        split
            .release_child("child-a", 4_000)
            .expect("matching release succeeds");
        assert_eq!(split.current_total_child_bps(), 0);

        split
            .try_admit_child("child-b".to_string(), 5_000)
            .expect("released child should restore full headroom");
    }

    #[test]
    fn release_child_rejects_share_mismatch() {
        let mut split = BudgetSplit::new("parent".to_string(), 5_000);
        split
            .try_admit_child("child-a".to_string(), 4_000)
            .expect("child admits");

        let error = split
            .release_child("child-a", 3_000)
            .expect_err("mismatched release must fail");
        assert!(matches!(
            error,
            BudgetSplitError::ReleaseShareMismatch { .. }
        ));
        assert_eq!(split.current_total_child_bps(), 4_000);
    }

    #[test]
    fn in_memory_registry_rejects_unknown_parent() {
        let mut registry = InMemoryBudgetRegistry::new();
        let err = registry
            .try_admit_child("missing", "child".to_string(), 1_000)
            .expect_err("unknown parent must fail closed");
        assert!(matches!(err, BudgetSplitError::UnknownParent { .. }));
        assert!(registry.split("missing").is_none());
    }

    #[test]
    fn registered_parent_enforces_sibling_sum_across_calls() {
        let mut registry = InMemoryBudgetRegistry::new();
        registry
            .register_parent("p".to_string(), MAX_BUDGET_SHARE_BPS)
            .expect("register parent snapshot");
        registry
            .try_admit_child("p", "child-a".to_string(), 6_000)
            .expect("first child admits under registered parent");
        let err = registry
            .try_admit_child("p", "child-b".to_string(), 5_000)
            .expect_err("second sibling must oversubscribe (6_000 + 5_000 > 10_000)");
        assert!(matches!(
            err,
            BudgetSplitError::OversubscribedSiblings { .. }
        ));
    }

    #[test]
    fn in_memory_registry_release_is_idempotent_and_restores_headroom() {
        let mut registry = InMemoryBudgetRegistry::new();
        registry
            .register_parent("p".to_string(), 5_000)
            .expect("register parent snapshot");
        registry
            .try_admit_child("p", "child-a".to_string(), 4_000)
            .expect("child admits");
        registry
            .release_child("p", "child-a", 4_000)
            .expect("matching release succeeds");
        registry
            .release_child("p", "child-a", 4_000)
            .expect("missing child release is idempotent");
        registry
            .release_child("missing-parent", "child-a", 4_000)
            .expect("missing parent release is idempotent");
        registry
            .try_admit_child("p", "child-b".to_string(), 5_000)
            .expect("released child should restore full headroom");
    }

    #[test]
    fn in_memory_registry_evict_is_idempotent() {
        let mut registry = InMemoryBudgetRegistry::new();
        registry
            .register_parent("p".to_string(), 5_000)
            .expect("register");
        registry.evict_parent("p");
        registry.evict_parent("p");
        assert!(registry.split("p").is_none());
    }

    #[test]
    fn in_memory_registry_admits_under_registered_parent() {
        let mut registry = InMemoryBudgetRegistry::new();
        registry
            .register_parent("p".to_string(), 5_000)
            .expect("register");
        registry
            .try_admit_child("p", "c1".to_string(), 4_000)
            .expect("first child fits");
        let err = registry
            .try_admit_child("p", "c2".to_string(), 4_000)
            .expect_err("second child must oversubscribe");
        assert!(matches!(
            err,
            BudgetSplitError::OversubscribedSiblings { .. }
        ));
    }

    #[test]
    fn registered_parent_share_takes_precedence_over_default() {
        // When the parent is already registered, the auto-register
        // default is ignored: the registered share is the ceiling.
        let mut registry = InMemoryBudgetRegistry::new();
        registry
            .register_parent("p".to_string(), 5_000)
            .expect("register");
        let err = registry
            .try_admit_child("p", "c1".to_string(), 6_000)
            .expect_err("child larger than registered parent share must fail");
        assert!(matches!(
            err,
            BudgetSplitError::OversubscribedSiblings { .. }
        ));
    }

    #[test]
    fn noop_registry_admits_anything() {
        let mut registry = NoopBudgetRegistry;
        registry
            .register_parent("p".to_string(), MAX_BUDGET_SHARE_BPS)
            .expect("noop register");
        registry
            .try_admit_child("p", "c1".to_string(), MAX_BUDGET_SHARE_BPS)
            .expect("noop admit 1");
        registry
            .try_admit_child("p", "c2".to_string(), MAX_BUDGET_SHARE_BPS)
            .expect("noop admit 2");
    }

    #[test]
    fn current_total_avoids_u16_overflow() {
        let mut split = BudgetSplit {
            parent_token_id: "parent".to_string(),
            parent_share_bps: MAX_BUDGET_SHARE_BPS,
            children: BTreeMap::new(),
        };
        // Synthetic stress: two MAX_BUDGET_SHARE_BPS siblings would sum past
        // u16::MAX. The registry would never admit both, but the running
        // sum itself must compute in u32 without wraparound.
        split
            .children
            .insert("c1".to_string(), MAX_BUDGET_SHARE_BPS);
        split
            .children
            .insert("c2".to_string(), MAX_BUDGET_SHARE_BPS);
        assert_eq!(
            split.current_total_child_bps(),
            u32::from(MAX_BUDGET_SHARE_BPS) * 2
        );
    }
}
