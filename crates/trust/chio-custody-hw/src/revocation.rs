//! Revocation cascade through the sparse-Merkle revocation oracle.
//!
//! Revoking a WebAuthn credential at the issuer (e.g. operator pulls a
//! stolen authenticator) MUST deny the next custody mint within the
//! current oracle epoch. This module wires the
//! [`chio_revocation_oracle::RevocationOracle`] surface into the issuer
//! mint path:
//!
//! 1. The issuer holds an [`Arc<dyn CredentialRevocationOracle>`]
//!    consulted before signing the capability.
//! 2. Operator-side credential revocation calls
//!    [`CredentialRevocationOracle::revoke_credential`], which inserts a
//!    leaf keyed on the WebAuthn credential id into the oracle AND
//!    cascades to every dependent subject registered under that
//!    credential (see the cascade contract below).
//! 3. The next mint observes the new epoch root, finds the credential
//!    revoked, and fails-closed with
//!    [`crate::CustodyError::CredentialRevoked`].
//!
//! # Cascade contract
//!
//! A custody credential can act as a PARENT for derived capabilities or
//! child credentials (for example a delegated session credential minted
//! from a hardware authenticator). Revoking the parent MUST propagate to
//! every dependent the issuer registered through
//! [`CredentialRevocationOracle::register_dependency`]. The cascade is
//! transitive: revoking A revokes B and, if B was itself a parent of C,
//! revokes C as well. The cascade is computed synchronously inside
//! `revoke_credential` so a single operator revocation atomically denies
//! the parent and the whole dependent subtree within one oracle epoch.
//!
//! Fail-closed: if the dependency graph cannot be evaluated (a poisoned
//! lock, or an oracle insert error mid-cascade), `revoke_credential`
//! returns [`crate::CustodyError`] and the issuer treats the credential
//! as deny-by-default. [`CredentialRevocationOracle::is_revoked`]
//! likewise surfaces lock failures as errors so the issuer never mints
//! while the revocation state is unknown.
//!
//! # Trust contract
//!
//! - Revocation MUST be observable before the next custody mint completes.
//!   The cascade is therefore synchronous from the issuer's point of view:
//!   `mint_capability` calls `is_revoked` and refuses to mint if it returns
//!   `true`.
//! - The `RevocationOracle` trait operates on
//!   `(SubjectId, EpochNonce)`; for credentials we encode the WebAuthn
//!   credential id (already base64url-no-pad) as the subject id and use a
//!   fixed `EpochNonce(0)` so a single revocation per credential is
//!   sufficient.
//! - This module owns its own keying convention so the oracle does not
//!   need to know about WebAuthn semantics.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use chio_revocation_oracle::{
    EpochNonce, EpochRoot, InMemoryRevocationOracle, RevocationKey, RevocationOracle, SubjectId,
};

use crate::error::CustodyError;

/// Fixed epoch-nonce numeric used for credential revocation leaves.
///
/// We use a single nonce per credential id so the cascade has at most
/// one leaf per WebAuthn credential. The sparse-Merkle layer accepts
/// arbitrary `EpochNonce` values; the issuer-side cascade does not need
/// the additional dimension. The constant is a `u64` because
/// [`EpochNonce::new`] is not currently `const fn`; see
/// [`credential_revocation_nonce`].
pub const CREDENTIAL_REVOCATION_NONCE_VALUE: u64 = 0;

/// Build the fixed [`EpochNonce`] used for credential revocation leaves.
#[must_use]
pub fn credential_revocation_nonce() -> EpochNonce {
    EpochNonce::new(CREDENTIAL_REVOCATION_NONCE_VALUE)
}

/// Issuer-side revocation surface keyed on WebAuthn credential id.
///
/// The custody surface owns this trait; the sparse-Merkle oracle
/// implements [`chio_revocation_oracle::RevocationOracle`] under the
/// hood. We translate between the two so callers do not have to know
/// about `(SubjectId, EpochNonce)`.
pub trait CredentialRevocationOracle: Send + Sync {
    /// Register `dependent` as derived from `parent`. Revoking `parent`
    /// (now or later) MUST cascade to `dependent`. Idempotent: repeated
    /// registration of the same edge is a no-op.
    ///
    /// The cascade is transitive, so a dependent may itself be the parent
    /// of further dependents. Implementations MUST guard against cycles so
    /// a self-referential or mutually-dependent registration cannot wedge
    /// the cascade in an unbounded loop.
    ///
    /// Fail-closed: if the dependency graph cannot be mutated (poisoned
    /// lock), this returns [`CustodyError`] and the edge is NOT recorded;
    /// the caller must treat registration failure as a revocation-state
    /// fault, not silently proceed.
    fn register_dependency(&self, parent: &str, dependent: &str) -> Result<(), CustodyError>;

    /// Mark `credential_id` revoked AND cascade to every dependent
    /// registered (transitively) under it. Subsequent calls to
    /// [`Self::is_revoked`] for the credential or any of its dependents
    /// MUST return `true`.
    ///
    /// Returns the oracle epoch root after the insertion(s) so the operator
    /// can correlate the revocation with the appropriate epoch in
    /// downstream receipts.
    ///
    /// Fail-closed: if any leaf in the cascade cannot be inserted the call
    /// returns [`CustodyError`]; the issuer denies by default rather than
    /// minting against a partially-applied revocation.
    fn revoke_credential(
        &self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError>;

    /// True if the credential (or a parent that cascaded to it) is in the
    /// revoked set under the current epoch root. Fail-closed:
    /// implementations MUST return `true` when the subject is present and
    /// MUST surface lock/evaluation failures as `Err(_)` so the issuer
    /// never mints while the revocation state is unknown.
    fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError>;

    /// Snapshot the current oracle epoch root. Surfaced for observability.
    fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError>;
}

/// Internal state guarded by a single `Mutex`: the sparse-Merkle
/// oracle plus the parent -> dependents adjacency used by the cascade.
/// Both live under one lock so a revocation and its cascade are applied
/// atomically with respect to a concurrent `is_revoked` consultation.
struct CascadeState {
    oracle: InMemoryRevocationOracle,
    dependents: HashMap<String, HashSet<String>>,
}

/// In-memory cascade backed by [`InMemoryRevocationOracle`].
///
/// Wraps the sparse-Merkle oracle (and the parent -> dependents
/// adjacency) in a `Mutex` so the credential revocation surface is
/// `Send + Sync` and consumable behind
/// `Arc<dyn CredentialRevocationOracle>`. Production deployments swap
/// this for a sled / SQLite-backed oracle without changing call sites.
pub struct InMemoryCredentialRevocationOracle {
    inner: Mutex<CascadeState>,
}

impl Default for InMemoryCredentialRevocationOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryCredentialRevocationOracle {
    /// Build a fresh cascade.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CascadeState {
                oracle: InMemoryRevocationOracle::new(),
                dependents: HashMap::new(),
            }),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, CascadeState>, CustodyError> {
        self.inner.lock().map_err(|err| {
            CustodyError::Encoding(format!("revocation oracle mutex poisoned: {err}"))
        })
    }

    fn key_for(credential_id: &str) -> RevocationKey {
        RevocationKey::new(
            SubjectId::from(credential_id),
            credential_revocation_nonce(),
        )
    }

    /// Revoke `root_subject` and every subject reachable from it through
    /// the dependency adjacency. Cycle-safe via a visited set; idempotent
    /// per subject (already-revoked leaves are skipped). Returns the epoch
    /// root after the (possibly empty) batch of insertions.
    fn cascade_revoke(
        state: &mut CascadeState,
        root_subject: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError> {
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = vec![root_subject.to_string()];

        while let Some(subject) = stack.pop() {
            if !visited.insert(subject.clone()) {
                // Already processed this subject in the current cascade;
                // skip to keep cycles bounded.
                continue;
            }

            let key = Self::key_for(&subject);
            if !state.oracle.contains(&key) {
                // Idempotency: only insert subjects not already revoked
                // so an operator retry (or a diamond-shaped dependency
                // graph) does not advance the epoch more than necessary.
                state.oracle.insert(key, now_unix_ms).map_err(|err| {
                    CustodyError::Encoding(format!(
                        "sparse-merkle revocation oracle insert failed: {err}"
                    ))
                })?;
            }

            if let Some(children) = state.dependents.get(&subject) {
                for child in children {
                    if !visited.contains(child) {
                        stack.push(child.clone());
                    }
                }
            }
        }

        Ok(state.oracle.epoch_root())
    }
}

impl CredentialRevocationOracle for InMemoryCredentialRevocationOracle {
    fn register_dependency(&self, parent: &str, dependent: &str) -> Result<(), CustodyError> {
        if parent == dependent {
            // A subject cannot depend on itself; reject so the adjacency
            // never contains a degenerate self-edge.
            return Err(CustodyError::Encoding(
                "revocation dependency parent and dependent must differ".into(),
            ));
        }
        let mut guard = self.lock()?;
        guard
            .dependents
            .entry(parent.to_string())
            .or_default()
            .insert(dependent.to_string());

        // If the parent is already revoked, registering a new dependent
        // must immediately cascade so a late-registered child cannot
        // outlive its already-revoked parent.
        if guard.oracle.contains(&Self::key_for(parent)) {
            let _ = Self::cascade_revoke(&mut guard, dependent, 0)?;
        }
        Ok(())
    }

    fn revoke_credential(
        &self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError> {
        let mut guard = self.lock()?;
        // Idempotency: if the credential is already revoked, we return
        // the current epoch root rather than failing. The custody
        // surface treats double-revocation as a no-op so an operator
        // retrying a failed control-plane call does not surface a
        // false-positive error. The cascade is still re-walked so a
        // dependent registered AFTER the parent's first revocation is
        // picked up on a subsequent revoke call; already-revoked leaves
        // are skipped inside the walk, so this stays epoch-stable when
        // nothing new needs revoking.
        Self::cascade_revoke(&mut guard, credential_id, now_unix_ms)
    }

    fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError> {
        let guard = self.lock()?;
        Ok(guard.oracle.contains(&Self::key_for(credential_id)))
    }

    fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError> {
        Ok(self.lock()?.oracle.epoch_root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_then_is_revoked_round_trip() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        let cred = "cred-AAAA";
        let revoked_pre = match oracle.is_revoked(cred) {
            Ok(b) => b,
            Err(e) => panic!("is_revoked pre: {e}"),
        };
        assert!(!revoked_pre);
        if let Err(e) = oracle.revoke_credential(cred, 1_000) {
            panic!("revoke must succeed: {e}");
        }
        let revoked_post = match oracle.is_revoked(cred) {
            Ok(b) => b,
            Err(e) => panic!("is_revoked post: {e}"),
        };
        assert!(revoked_post, "cascade must observe revocation");
    }

    #[test]
    fn double_revoke_is_idempotent() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        let cred = "cred-double";
        let r1 = match oracle.revoke_credential(cred, 1_000) {
            Ok(r) => r,
            Err(e) => panic!("first revoke: {e}"),
        };
        let r2 = match oracle.revoke_credential(cred, 2_000) {
            Ok(r) => r,
            Err(e) => panic!("second revoke must be idempotent: {e}"),
        };
        // Epoch advances exactly once; the second call returns the
        // existing root so the custody surface is operationally tolerant
        // to retries on the control-plane revocation endpoint.
        assert_eq!(r1, r2);
    }

    #[test]
    fn distinct_credentials_revoke_independently() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.revoke_credential("cred-A", 1_000) {
            panic!("revoke A: {e}");
        }
        let a = match oracle.is_revoked("cred-A") {
            Ok(b) => b,
            Err(e) => panic!("is_revoked A: {e}"),
        };
        let b = match oracle.is_revoked("cred-B") {
            Ok(v) => v,
            Err(e) => panic!("is_revoked B: {e}"),
        };
        assert!(a);
        assert!(!b, "revoking cred-A must NOT cascade to cred-B");
    }

    #[test]
    fn revoking_parent_cascades_to_registered_child() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("parent", "child") {
            panic!("register: {e}");
        }
        // Child is not revoked until the parent is.
        match oracle.is_revoked("child") {
            Ok(b) => assert!(!b, "child must not be revoked before the parent"),
            Err(e) => panic!("is_revoked child pre: {e}"),
        }
        if let Err(e) = oracle.revoke_credential("parent", 1_000) {
            panic!("revoke parent: {e}");
        }
        match oracle.is_revoked("parent") {
            Ok(b) => assert!(b, "parent must be revoked"),
            Err(e) => panic!("is_revoked parent: {e}"),
        }
        match oracle.is_revoked("child") {
            Ok(b) => assert!(b, "revoking the parent MUST cascade to the child"),
            Err(e) => panic!("is_revoked child post: {e}"),
        }
    }

    #[test]
    fn cascade_is_transitive_across_a_chain() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("a", "b") {
            panic!("register a->b: {e}");
        }
        if let Err(e) = oracle.register_dependency("b", "c") {
            panic!("register b->c: {e}");
        }
        if let Err(e) = oracle.revoke_credential("a", 1_000) {
            panic!("revoke a: {e}");
        }
        for subject in ["a", "b", "c"] {
            match oracle.is_revoked(subject) {
                Ok(b) => assert!(b, "transitive cascade must revoke {subject}"),
                Err(e) => panic!("is_revoked {subject}: {e}"),
            }
        }
    }

    #[test]
    fn cascade_terminates_on_cycle() {
        // A <-> B mutual dependency must not wedge the cascade.
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("a", "b") {
            panic!("register a->b: {e}");
        }
        if let Err(e) = oracle.register_dependency("b", "a") {
            panic!("register b->a: {e}");
        }
        if let Err(e) = oracle.revoke_credential("a", 1_000) {
            panic!("revoke a (cycle) must terminate: {e}");
        }
        for subject in ["a", "b"] {
            match oracle.is_revoked(subject) {
                Ok(b) => assert!(b, "cyclic cascade must still revoke {subject}"),
                Err(e) => panic!("is_revoked {subject}: {e}"),
            }
        }
    }

    #[test]
    fn registering_child_after_parent_revoked_cascades_immediately() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.revoke_credential("parent", 1_000) {
            panic!("revoke parent: {e}");
        }
        if let Err(e) = oracle.register_dependency("parent", "late-child") {
            panic!("register late child: {e}");
        }
        match oracle.is_revoked("late-child") {
            Ok(b) => assert!(
                b,
                "a child registered after the parent was revoked must be revoked immediately"
            ),
            Err(e) => panic!("is_revoked late-child: {e}"),
        }
    }

    #[test]
    fn self_dependency_is_rejected_fail_closed() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        let res = oracle.register_dependency("self", "self");
        assert!(
            matches!(res, Err(CustodyError::Encoding(_))),
            "a self-referential dependency must be rejected"
        );
    }

    #[test]
    fn sibling_dependents_do_not_cross_cascade() {
        let oracle = InMemoryCredentialRevocationOracle::new();
        if let Err(e) = oracle.register_dependency("parent-1", "child-1") {
            panic!("register p1: {e}");
        }
        if let Err(e) = oracle.register_dependency("parent-2", "child-2") {
            panic!("register p2: {e}");
        }
        if let Err(e) = oracle.revoke_credential("parent-1", 1_000) {
            panic!("revoke p1: {e}");
        }
        match oracle.is_revoked("child-1") {
            Ok(b) => assert!(b, "child-1 must be revoked"),
            Err(e) => panic!("is_revoked child-1: {e}"),
        }
        match oracle.is_revoked("child-2") {
            Ok(b) => assert!(!b, "child-2 under a different parent must NOT be revoked"),
            Err(e) => panic!("is_revoked child-2: {e}"),
        }
    }
}
