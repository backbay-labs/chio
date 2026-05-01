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
//!    leaf keyed on the WebAuthn credential id into the oracle.
//! 3. The next mint observes the new epoch root, finds the credential
//!    revoked, and fails-closed with
//!    [`crate::CustodyError::CredentialRevoked`].
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

use std::sync::Mutex;

use chio_revocation_oracle::{
    EpochNonce, EpochRoot, InMemoryRevocationOracle, RevocationKey, RevocationOracle, SubjectId,
};

use crate::error::CustodyError;

/// Fixed epoch-nonce numeric used for credential revocation leaves.
///
/// We use a single nonce per credential id so the cascade has at most
/// one leaf per WebAuthn credential. The M04 sparse-Merkle layer accepts
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
/// The custody surface owns this trait; the M04 sparse-Merkle oracle
/// implements [`chio_revocation_oracle::RevocationOracle`] under the
/// hood. We translate between the two so callers do not have to know
/// about `(SubjectId, EpochNonce)`.
pub trait CredentialRevocationOracle: Send + Sync {
    /// Mark `credential_id` revoked. Subsequent calls to
    /// [`Self::is_revoked`] for the same id MUST return `true`.
    ///
    /// Returns the M04 epoch root after the insertion so the operator
    /// can correlate the revocation with the appropriate epoch in
    /// downstream receipts.
    fn revoke_credential(
        &self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError>;

    /// True if the credential is in the revoked set under the current
    /// epoch root. Fail-closed: implementations MUST return `true` when
    /// the credential is present.
    fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError>;

    /// Snapshot the current M04 epoch root. Surfaced for observability.
    fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError>;
}

/// In-memory cascade backed by [`InMemoryRevocationOracle`].
///
/// Wraps the M04 sparse-Merkle oracle in a `Mutex` so the credential
/// revocation surface is `Send + Sync` and consumable behind
/// `Arc<dyn CredentialRevocationOracle>`. Production deployments swap
/// this for a sled / SQLite-backed oracle without changing call sites.
pub struct InMemoryCredentialRevocationOracle {
    inner: Mutex<InMemoryRevocationOracle>,
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
            inner: Mutex::new(InMemoryRevocationOracle::new()),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, InMemoryRevocationOracle>, CustodyError> {
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
}

impl CredentialRevocationOracle for InMemoryCredentialRevocationOracle {
    fn revoke_credential(
        &self,
        credential_id: &str,
        now_unix_ms: u64,
    ) -> Result<EpochRoot, CustodyError> {
        let mut guard = self.lock()?;
        let key = Self::key_for(credential_id);
        // Idempotency: if the credential is already revoked, we return
        // the current epoch root rather than failing. The custody
        // surface treats double-revocation as a no-op so an operator
        // retrying a failed control-plane call does not surface a
        // false-positive error.
        if guard.contains(&key) {
            return Ok(guard.epoch_root());
        }
        guard
            .insert(key, now_unix_ms)
            .map_err(|err| CustodyError::Encoding(format!("M04 oracle insert failed: {err}")))
    }

    fn is_revoked(&self, credential_id: &str) -> Result<bool, CustodyError> {
        let guard = self.lock()?;
        Ok(guard.contains(&Self::key_for(credential_id)))
    }

    fn current_epoch_root(&self) -> Result<EpochRoot, CustodyError> {
        Ok(self.lock()?.epoch_root())
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
}
