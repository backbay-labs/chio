//! Audience-pinned passkey capability envelope.
//!
//! A [`PasskeyCapability`] is the short-lived artifact the issuer mints
//! after a successful WebAuthn assertion. The envelope is canonical-JSON
//! encoded so the issuer-side signature (via the `HybridBackend`) stays
//! bit-stable across implementations.
//!
//! # Trust contract
//!
//! - `audience` is pinned to the verifier (kernel) identity. Re-presenting
//!   a capability minted for audience A to audience B fails-closed at the
//!   kernel verifier (audience-confusion proptest).
//! - `exp` is fixed at five minutes from `iat` and is computed off the
//!   verifier clock, not the issuer clock. The risk register names
//!   issuer-clock drift as the central reason for this asymmetry.
//! - `challenge_nonce` is the WebAuthn challenge bound to this assertion.
//!   The issuer's nonce store keys on `(credential_id, challenge_nonce)`
//!   to detect replay.
//! - `signature` is a detached signature over the canonical-JSON encoding
//!   of every other field, produced by the issuer's signing backend
//!   (`Ed25519Backend`, the FIPS P-256/P-384 backends, or `HybridBackend`
//!   under the `pq` feature). It is empty ONLY in the pre-signing
//!   canonical form (the message the signature covers); the issuer always
//!   fills it before returning a capability.
//!
//! Capabilities with empty signatures never verify against a kernel
//! verifier; the kernel rejects any `PasskeyCapability` whose `signature`
//! is empty.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::CustodyError;

/// Fixed capability lifetime, pinned to five minutes to keep the
/// audience-pinned envelope short-lived enough that revocation cascade
/// through the revocation oracle is operationally sufficient.
pub const CAPABILITY_LIFETIME_SECONDS: i64 = 300;

/// Sorted set of capability scopes. Encoded as a JSON array of unique
/// strings in canonical (sorted) order. The set semantics are enforced at
/// construction time so the canonical-JSON encoding is deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScopeSet(BTreeSet<String>);

impl ScopeSet {
    /// Build a [`ScopeSet`] from any iterable. Duplicates are deduplicated;
    /// final order is lexicographic per `BTreeSet`.
    pub fn new<I, S>(scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self(scopes.into_iter().map(Into::into).collect())
    }

    /// True if every scope in `subset` is also in `self`.
    #[must_use]
    pub fn covers(&self, subset: &ScopeSet) -> bool {
        subset.0.is_subset(&self.0)
    }

    /// Iterate the scopes in canonical (lexicographic) order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    /// Number of distinct scopes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if no scopes are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Audience-pinned capability envelope.
///
/// Canonical-JSON encoding rules (RFC 8785 / JCS, via
/// [`chio_core_types::canonical::canonical_json_bytes`]):
///
/// - object keys sorted lexicographically by UTF-16 code units,
/// - timestamps are RFC 3339 UTC with `Z` suffix,
/// - `scope_set` is a sorted JSON array of unique strings,
/// - `signature` is base64url-no-pad,
/// - no inter-token whitespace.
///
/// The serde field declaration order is therefore irrelevant to the
/// on-the-wire byte layout; signatures are computed over the RFC 8785 form
/// so any compliant implementation (Rust, TypeScript, Python, Go) produces
/// the same bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCapability {
    /// Logical audience pin (kernel identity URI). Mismatch is fail-closed.
    pub audience: String,
    /// Base64url-no-pad WebAuthn credential id the assertion was bound to.
    pub credential_id: String,
    /// Capability scope set (canonical sorted).
    pub scope_set: ScopeSet,
    /// Issued-at timestamp, verifier clock.
    pub iat: DateTime<Utc>,
    /// Expiry timestamp, fixed at `iat + 5 minutes`.
    pub exp: DateTime<Utc>,
    /// Base64url-no-pad WebAuthn challenge nonce. Keyed for replay detection.
    pub challenge_nonce: String,
    /// Hex-encoded detached signature over the canonical-JSON encoding of
    /// every other field. Empty only in the pre-signing canonical form
    /// (the signed message); the issuer always populates it via its
    /// signing backend before returning the capability.
    pub signature: String,
}

impl PasskeyCapability {
    /// Build the unsigned capability envelope (the pre-signing form).
    ///
    /// `iat` is the verifier's current UTC instant; `exp = iat + 5 minutes`.
    /// `signature` is the empty string: this is the exact byte sequence the
    /// issuer's signing backend signs over. [`crate::mint::sign_capability`]
    /// consumes the envelope produced here and fills the `signature` slot;
    /// no caller ships the output of this constructor without signing it.
    #[must_use]
    pub fn new_stub_unsigned(
        audience: impl Into<String>,
        credential_id: impl Into<String>,
        scope_set: ScopeSet,
        challenge_nonce: impl Into<String>,
        iat: DateTime<Utc>,
    ) -> Self {
        let exp = iat + Duration::seconds(CAPABILITY_LIFETIME_SECONDS);
        Self {
            audience: audience.into(),
            credential_id: credential_id.into(),
            scope_set,
            iat,
            exp,
            challenge_nonce: challenge_nonce.into(),
            signature: String::new(),
        }
    }

    /// True if `now` is strictly less than `exp`.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        now < self.exp
    }

    /// Encode to canonical JSON bytes (RFC 8785 / JCS).
    ///
    /// Deterministic: identical inputs produce byte-identical outputs across
    /// any RFC 8785 compliant implementation. Object keys are sorted by
    /// UTF-16 code units, so the byte layout does not depend on the serde
    /// struct field declaration order. The issuer signature is taken over
    /// these bytes.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, CustodyError> {
        chio_core_types::canonical::canonical_json_bytes(self)
            .map_err(|err| CustodyError::Encoding(format!("canonical-json encode: {err}")))
    }

    /// Decode from canonical JSON bytes. Round-trip with
    /// [`Self::to_canonical_json`].
    ///
    /// `serde_json::from_slice` is used because RFC 8785 output is itself a
    /// valid JSON byte sequence; canonicalization is a property of the
    /// encoder, not the decoder.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, CustodyError> {
        serde_json::from_slice(bytes)
            .map_err(|err| CustodyError::Encoding(format!("canonical-json decode: {err}")))
    }

    /// Verifier-side audience check. Fail-closed mismatch.
    pub fn require_audience(&self, expected: &str) -> Result<(), CustodyError> {
        if self.audience == expected {
            Ok(())
        } else {
            Err(CustodyError::AudienceMismatch {
                expected: expected.to_string(),
                found: self.audience.clone(),
            })
        }
    }

    /// Verifier-side expiry check. Fail-closed if `now >= exp`.
    pub fn require_live(&self, now: DateTime<Utc>) -> Result<(), CustodyError> {
        if self.is_live(now) {
            Ok(())
        } else {
            Err(CustodyError::CapabilityExpired)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_iat() -> DateTime<Utc> {
        // Fixed instant for byte-stable encodings. 2026-04-29T00:00:00Z.
        match Utc.with_ymd_and_hms(2026, 4, 29, 0, 0, 0) {
            chrono::LocalResult::Single(t) => t,
            _ => panic!("fixed_iat fixture must construct"),
        }
    }

    fn fixture_cap() -> PasskeyCapability {
        PasskeyCapability::new_stub_unsigned(
            "urn:chio:audience:kernel",
            "AAAA",
            ScopeSet::new(["tool:read", "tool:write"]),
            "nonce-abc",
            fixed_iat(),
        )
    }

    #[test]
    fn lifetime_pinned_to_five_minutes() {
        let cap = fixture_cap();
        assert_eq!(
            (cap.exp - cap.iat).num_seconds(),
            CAPABILITY_LIFETIME_SECONDS
        );
    }

    #[test]
    fn unsigned_envelope_constructor_leaves_signature_empty() {
        // The pre-signing envelope carries an empty signature slot; this
        // is the message `sign_capability` signs over.
        let cap = fixture_cap();
        assert_eq!(cap.signature, "");
    }

    #[test]
    fn audience_mismatch_returns_typed_error() {
        let cap = fixture_cap();
        let err = cap.require_audience("urn:chio:audience:other");
        assert!(matches!(err, Err(CustodyError::AudienceMismatch { .. })));
    }

    #[test]
    fn expiry_check_rejects_past_exp() {
        let cap = fixture_cap();
        let later = cap.exp + Duration::seconds(1);
        assert!(matches!(
            cap.require_live(later),
            Err(CustodyError::CapabilityExpired)
        ));
    }

    #[test]
    fn scope_set_dedupes_and_orders() {
        let s = ScopeSet::new(["b", "a", "a"]);
        let collected: Vec<_> = s.iter().collect();
        assert_eq!(collected, vec!["a", "b"]);
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn scope_set_subset_check() {
        let big = ScopeSet::new(["a", "b", "c"]);
        let small = ScopeSet::new(["a", "b"]);
        assert!(big.covers(&small));
        assert!(!small.covers(&big));
    }
}
