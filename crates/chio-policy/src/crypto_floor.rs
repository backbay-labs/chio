//! `policy.crypto_floor` enum for the Chio runtime.
//!
//! `crypto_floor` declares the minimum cryptographic posture the kernel
//! enforces on signed artifacts (receipts, capability tokens, compliance
//! certificates). It is loaded once at kernel start and threaded through the
//! receipt signer, capability validator, and compliance certificate issuer.
//!
//! ## Variants
//!
//! - [`CryptoFloor::AllowClassical`] -- accept classical-only envelopes
//!   (Ed25519, P-256, P-384). Default. PQ keys are NOT required.
//! - [`CryptoFloor::AllowHybrid`] -- accept either classical-only or hybrid
//!   classical-plus-ML-DSA-65 envelopes. Operators that opt in to hybrid
//!   signing MUST provision a PQ key.
//! - [`CryptoFloor::PqRequired`] -- reject classical-only envelopes; every
//!   signed artifact MUST be hybrid. Operators MUST provision a PQ key.
//!
//! ## Fail-closed loading
//!
//! [`CryptoFloor::validate_with_pq_key`] inspects the loaded floor against
//! the operator's PQ key provisioning state and rejects invalid combinations
//! at load time. The two invalid combinations are
//! [`CryptoFloor::AllowHybrid`] and [`CryptoFloor::PqRequired`] without a
//! PQ key present. They are caught BEFORE any signing call is issued so a
//! misconfigured deployment does not brick at first signing.
//!
//! ## Wire format
//!
//! The enum is serialized as a snake_case string in YAML / JSON for parity
//! with the rest of `chio-policy`'s schema. The textual form is stable and
//! checked into the threat model and the audit doc:
//!
//! - `"allow_classical"` -- [`CryptoFloor::AllowClassical`]
//! - `"allow_hybrid"`    -- [`CryptoFloor::AllowHybrid`]
//! - `"pq_required"`     -- [`CryptoFloor::PqRequired`]

use serde::{Deserialize, Serialize};

/// Minimum cryptographic posture enforced by the kernel on signed artifacts.
///
/// See module documentation for the full state table. The variants are
/// strictly ordered: `AllowClassical < AllowHybrid < PqRequired`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CryptoFloor {
    /// Accept classical-only envelopes (no post-quantum key required). Default.
    AllowClassical,
    /// Accept either classical-only or hybrid classical-plus-ML-DSA-65
    /// envelopes. Requires a PQ key to be provisioned.
    AllowHybrid,
    /// Reject classical-only envelopes; require hybrid signing on every
    /// signed artifact. Requires a PQ key to be provisioned.
    PqRequired,
}

impl Default for CryptoFloor {
    /// Default crypto floor is [`CryptoFloor::AllowClassical`].
    ///
    /// The default is `AllowClassical` so deployments that have not
    /// provisioned a PQ key operate without an explicit policy update.
    fn default() -> Self {
        Self::AllowClassical
    }
}

impl CryptoFloor {
    /// Stable wire-format identifier for this variant.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AllowClassical => "allow_classical",
            Self::AllowHybrid => "allow_hybrid",
            Self::PqRequired => "pq_required",
        }
    }

    /// Whether the floor permits hybrid envelopes to ride the wire.
    ///
    /// Returns `true` for [`Self::AllowHybrid`] and [`Self::PqRequired`].
    #[must_use]
    pub fn allows_hybrid(&self) -> bool {
        matches!(self, Self::AllowHybrid | Self::PqRequired)
    }

    /// Whether the floor mandates hybrid envelopes (rejects classical-only).
    ///
    /// Returns `true` for [`Self::PqRequired`] only.
    #[must_use]
    pub fn requires_pq(&self) -> bool {
        matches!(self, Self::PqRequired)
    }

    /// Whether the floor permits classical-only envelopes on the wire.
    ///
    /// Returns `true` for [`Self::AllowClassical`] and [`Self::AllowHybrid`].
    /// Operators that have flipped to [`Self::PqRequired`] reject any
    /// classical-only envelope fail-closed.
    #[must_use]
    pub fn allows_classical_only(&self) -> bool {
        matches!(self, Self::AllowClassical | Self::AllowHybrid)
    }

    /// Validate the floor against the operator's PQ key provisioning state.
    ///
    /// `pq_key_present` is `true` iff the kernel boot path has loaded a
    /// rolled ML-DSA-65 key. The valid combinations are:
    ///
    /// | floor             | pq_key_present | result    |
    /// | ----------------- | -------------- | --------- |
    /// | `allow_classical` | any            | accept    |
    /// | `allow_hybrid`    | true           | accept    |
    /// | `allow_hybrid`    | false          | **reject**|
    /// | `pq_required`     | true           | accept    |
    /// | `pq_required`     | false          | **reject**|
    ///
    /// Rejection is fail-closed: callers MUST surface the error and refuse
    /// to start the kernel. Validation runs once at policy load, never on a
    /// signing call.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoFloorLoadError::HybridFloorRequiresPqKey`] if the
    /// configured floor needs a PQ key but none is provisioned.
    pub fn validate_with_pq_key(&self, pq_key_present: bool) -> Result<(), CryptoFloorLoadError> {
        match (self, pq_key_present) {
            (Self::AllowClassical, _) => Ok(()),
            (Self::AllowHybrid, true) | (Self::PqRequired, true) => Ok(()),
            (Self::AllowHybrid, false) | (Self::PqRequired, false) => {
                Err(CryptoFloorLoadError::HybridFloorRequiresPqKey { floor: *self })
            }
        }
    }
}

/// Errors raised when a `crypto_floor` policy is loaded against a kernel boot
/// state that cannot satisfy it.
///
/// These errors fire at load time (i.e. before the kernel accepts traffic),
/// not at first signing. The kernel boot path MUST surface the error and
/// refuse to start.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoFloorLoadError {
    /// `crypto_floor=allow_hybrid` or `crypto_floor=pq_required` was
    /// configured but no ML-DSA-65 key is provisioned. Fail-closed.
    #[error(
        "policy.crypto_floor={} requires a post-quantum (ML-DSA-65) signing key but none was \
         provisioned at kernel boot",
        floor.as_str()
    )]
    HybridFloorRequiresPqKey {
        /// The floor that triggered the rejection.
        floor: CryptoFloor,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_allow_classical() {
        assert_eq!(CryptoFloor::default(), CryptoFloor::AllowClassical);
    }

    #[test]
    fn allows_hybrid_matches_table() {
        assert!(!CryptoFloor::AllowClassical.allows_hybrid());
        assert!(CryptoFloor::AllowHybrid.allows_hybrid());
        assert!(CryptoFloor::PqRequired.allows_hybrid());
    }

    #[test]
    fn requires_pq_only_for_pq_required() {
        assert!(!CryptoFloor::AllowClassical.requires_pq());
        assert!(!CryptoFloor::AllowHybrid.requires_pq());
        assert!(CryptoFloor::PqRequired.requires_pq());
    }

    #[test]
    fn allows_classical_only_matches_table() {
        assert!(CryptoFloor::AllowClassical.allows_classical_only());
        assert!(CryptoFloor::AllowHybrid.allows_classical_only());
        assert!(!CryptoFloor::PqRequired.allows_classical_only());
    }

    #[test]
    fn as_str_round_trip() {
        for variant in [
            CryptoFloor::AllowClassical,
            CryptoFloor::AllowHybrid,
            CryptoFloor::PqRequired,
        ] {
            let s = variant.as_str();
            let json = serde_json::to_string(&variant).unwrap_or_default();
            assert!(json.contains(s), "json {json} should contain {s}");
        }
    }

    #[test]
    fn validate_with_pq_key_classical_always_ok() {
        assert!(CryptoFloor::AllowClassical
            .validate_with_pq_key(false)
            .is_ok());
        assert!(CryptoFloor::AllowClassical
            .validate_with_pq_key(true)
            .is_ok());
    }

    #[test]
    fn validate_with_pq_key_hybrid_requires_key() {
        assert!(CryptoFloor::AllowHybrid.validate_with_pq_key(true).is_ok());
        let err = CryptoFloor::AllowHybrid
            .validate_with_pq_key(false)
            .expect_err("missing PQ key under allow_hybrid must reject");
        assert_eq!(
            err,
            CryptoFloorLoadError::HybridFloorRequiresPqKey {
                floor: CryptoFloor::AllowHybrid,
            }
        );
    }

    #[test]
    fn validate_with_pq_key_pq_required_requires_key() {
        assert!(CryptoFloor::PqRequired.validate_with_pq_key(true).is_ok());
        let err = CryptoFloor::PqRequired
            .validate_with_pq_key(false)
            .expect_err("missing PQ key under pq_required must reject");
        assert_eq!(
            err,
            CryptoFloorLoadError::HybridFloorRequiresPqKey {
                floor: CryptoFloor::PqRequired,
            }
        );
    }
}
