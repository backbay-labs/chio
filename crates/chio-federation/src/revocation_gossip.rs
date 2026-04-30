//! Revocation root gossip message types and bilateral push/pull paths.
//!
//! This module is the federation-side surface that carries signed
//! [`chio_revocation_oracle::SignedEpochRoot`] artifacts between bilateral
//! peers. The oracle itself owns the sparse-Merkle-tree state and signing;
//! `chio-federation` only owns the wire envelope, the batched push tick,
//! and the catch-up gap-fill protocol. Verifiers consult their kernel-core
//! `RevocationView` cache (M04.P2.T4) which gossip updates fail-closed:
//! an unverifiable, malformed, or out-of-order gossip frame is dropped and
//! never silently merged into the cache.
//!
//! ## Wire envelope (T1)
//!
//! [`RevocationRootGossip`] wraps a single signed epoch root with the
//! signer identity, signer-id-pinning, and a millisecond timestamp the
//! receiver can use for freshness gating. The on-the-wire schema is
//! [`REVOCATION_ROOT_GOSSIP_SCHEMA`].
//!
//! Future tickets in this phase add:
//! * push path (T2) -- bilateral peer subscription + 250ms batched broadcast,
//! * pull / catch-up path (T3) -- gap-fill request/response,
//! * RevocationView cache wiring (T4 -- in `chio-kernel-core`),
//! * passport-revocation bridge (T6 -- in `chio-revocation-oracle`).

use chio_revocation_oracle::{EpochRoot, RootSignature, SignedEpochRoot};
use serde::{Deserialize, Serialize};

/// Wire schema identifier for [`RevocationRootGossip`]. Versioned so future
/// gossip envelopes can be introduced without ambiguity.
pub const REVOCATION_ROOT_GOSSIP_SCHEMA: &str = "chio.federation-revocation-root-gossip.v1";

/// A single signed revocation-oracle epoch root, gossiped from one bilateral
/// peer to another.
///
/// Receivers MUST verify [`Self::signed_root`] against a pinned signer key
/// before merging the carried [`EpochRoot`] into any local cache. The
/// `signer_id` field SHOULD agree with [`RootSignature::signer_id`] inside
/// the contained signature; mismatches MUST be treated fail-closed (drop
/// the frame, never accept the root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationRootGossip {
    /// Schema tag, always [`REVOCATION_ROOT_GOSSIP_SCHEMA`] for v1.
    pub schema: String,
    /// Monotone epoch counter as advertised by the carried [`EpochRoot`].
    /// Duplicated outside the signature for cheap routing/dedup before the
    /// receiver runs signature verification. Receivers MUST still confirm
    /// `epoch == signed_root.root.epoch` before trusting the value.
    pub epoch: u64,
    /// The signed epoch root produced by the local revocation oracle. Carries
    /// both the [`EpochRoot`] body and the [`RootSignature`].
    pub signed_root: SignedEpochRoot,
    /// Pinned signer identity for the broadcasting kernel/oracle. MUST match
    /// the inner [`RootSignature::signer_id`].
    pub signer_id: String,
    /// Unix milliseconds at which the sender emitted this gossip frame.
    /// Receivers use this for freshness gating and to age-out stalled feeds.
    pub ts_unix_ms: u64,
}

impl RevocationRootGossip {
    /// Build a gossip frame from a freshly-signed epoch root.
    ///
    /// The carried [`EpochRoot::epoch`] is mirrored into the top-level
    /// `epoch` field for cheap routing; the signer-id pin is taken from the
    /// inner [`RootSignature`] so the two cannot drift.
    #[must_use]
    pub fn from_signed(signed_root: SignedEpochRoot, ts_unix_ms: u64) -> Self {
        let epoch = signed_root.root.epoch;
        let signer_id = signed_root.signature.signer_id.clone();
        Self {
            schema: REVOCATION_ROOT_GOSSIP_SCHEMA.to_string(),
            epoch,
            signed_root,
            signer_id,
            ts_unix_ms,
        }
    }

    /// Borrow the carried [`EpochRoot`].
    #[must_use]
    pub fn epoch_root(&self) -> &EpochRoot {
        &self.signed_root.root
    }

    /// Borrow the carried [`RootSignature`].
    #[must_use]
    pub fn signature(&self) -> &RootSignature {
        &self.signed_root.signature
    }

    /// Cheap schema + signer + epoch consistency gate.
    ///
    /// Returns `Err` when:
    /// * the schema tag is not [`REVOCATION_ROOT_GOSSIP_SCHEMA`],
    /// * the top-level `epoch` disagrees with `signed_root.root.epoch`,
    /// * the top-level `signer_id` disagrees with the embedded signature's
    ///   `signer_id`.
    ///
    /// This check is purely structural: it does NOT verify the cryptographic
    /// signature. Callers MUST still run [`SignedEpochRoot::verify`] against
    /// a pinned signer before trusting the carried root.
    pub fn validate_envelope(&self) -> Result<(), RevocationGossipError> {
        if self.schema != REVOCATION_ROOT_GOSSIP_SCHEMA {
            return Err(RevocationGossipError::UnsupportedSchema(self.schema.clone()));
        }
        if self.epoch != self.signed_root.root.epoch {
            return Err(RevocationGossipError::EpochMismatch {
                envelope: self.epoch,
                signed: self.signed_root.root.epoch,
            });
        }
        if self.signer_id != self.signed_root.signature.signer_id {
            return Err(RevocationGossipError::SignerIdMismatch {
                envelope: self.signer_id.clone(),
                signed: self.signed_root.signature.signer_id.clone(),
            });
        }
        Ok(())
    }
}

/// Errors produced by the revocation-gossip envelope and its push/pull
/// machinery. Every variant is fail-closed: the receiver MUST drop the
/// offending frame and refuse to merge it into any local cache.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RevocationGossipError {
    #[error("unsupported revocation gossip schema: {0}")]
    UnsupportedSchema(String),

    #[error("envelope epoch {envelope} disagrees with signed-root epoch {signed}")]
    EpochMismatch { envelope: u64, signed: u64 },

    #[error(
        "envelope signer_id `{envelope}` disagrees with signed-root signer_id `{signed}`"
    )]
    SignerIdMismatch { envelope: String, signed: String },
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_revocation_oracle::{DigestRootSigner, EpochRoot, RootSignature, SignedEpochRoot};

    fn signed_root(signer_id: &str, epoch: u64) -> SignedEpochRoot {
        let signer = DigestRootSigner::new(signer_id, b"unit-test-secret".to_vec());
        let root = EpochRoot {
            epoch,
            root_hash: [0xAB; 32],
            leaf_count: 1,
            issued_at_unix_ms: 1_700_000_000_000,
        };
        SignedEpochRoot::sign(root, &signer).expect("digest signer never fails")
    }

    #[test]
    fn from_signed_mirrors_epoch_and_signer() {
        let signed = signed_root("oracle-a", 7);
        let gossip = RevocationRootGossip::from_signed(signed.clone(), 1_700_000_000_500);
        assert_eq!(gossip.schema, REVOCATION_ROOT_GOSSIP_SCHEMA);
        assert_eq!(gossip.epoch, 7);
        assert_eq!(gossip.signer_id, "oracle-a");
        assert_eq!(gossip.signed_root, signed);
        assert_eq!(gossip.ts_unix_ms, 1_700_000_000_500);
    }

    #[test]
    fn validate_envelope_accepts_well_formed_frame() {
        let signed = signed_root("oracle-a", 12);
        let gossip = RevocationRootGossip::from_signed(signed, 1_700_000_001_000);
        assert!(gossip.validate_envelope().is_ok());
    }

    #[test]
    fn validate_envelope_rejects_bad_schema() {
        let signed = signed_root("oracle-a", 1);
        let mut gossip = RevocationRootGossip::from_signed(signed, 0);
        gossip.schema = "chio.federation-something-else.v9".to_string();
        let err = gossip
            .validate_envelope()
            .expect_err("schema mismatch must fail closed");
        match err {
            RevocationGossipError::UnsupportedSchema(s) => {
                assert!(s.contains("something-else"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn validate_envelope_rejects_epoch_mismatch() {
        let signed = signed_root("oracle-a", 3);
        let mut gossip = RevocationRootGossip::from_signed(signed, 0);
        gossip.epoch = 99;
        let err = gossip
            .validate_envelope()
            .expect_err("epoch tampering must fail closed");
        assert_eq!(
            err,
            RevocationGossipError::EpochMismatch {
                envelope: 99,
                signed: 3
            }
        );
    }

    #[test]
    fn validate_envelope_rejects_signer_id_mismatch() {
        let signed = signed_root("oracle-a", 4);
        let mut gossip = RevocationRootGossip::from_signed(signed, 0);
        gossip.signer_id = "oracle-impostor".to_string();
        let err = gossip
            .validate_envelope()
            .expect_err("signer-id tampering must fail closed");
        match err {
            RevocationGossipError::SignerIdMismatch { envelope, signed } => {
                assert_eq!(envelope, "oracle-impostor");
                assert_eq!(signed, "oracle-a");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn round_trip_serde_preserves_fields() {
        let signed = signed_root("oracle-a", 11);
        let gossip = RevocationRootGossip::from_signed(signed, 1_700_000_002_000);
        let encoded = serde_json::to_vec(&gossip).expect("serialize");
        let decoded: RevocationRootGossip = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(decoded, gossip);
        assert!(decoded.validate_envelope().is_ok());
    }

    #[test]
    fn deny_unknown_fields_blocks_extra_keys() {
        // Defence-in-depth: protocol upgrades must go through schema bumps,
        // not silent extra keys that downstream verifiers ignore at the
        // envelope level. We round-trip a real gossip frame, splice an
        // extra top-level field into the JSON object, and confirm that the
        // re-parse fails closed.
        let signed = signed_root("oracle-a", 5);
        let gossip = RevocationRootGossip::from_signed(signed, 1_700_000_003_000);
        let mut value: serde_json::Value =
            serde_json::to_value(&gossip).expect("serialize gossip");
        let map = value
            .as_object_mut()
            .expect("envelope serializes to a JSON object");
        map.insert(
            "extraField".to_string(),
            serde_json::Value::String("must be rejected".to_string()),
        );
        let payload = serde_json::to_vec(&value).expect("serialize tampered envelope");
        let parsed: Result<RevocationRootGossip, _> = serde_json::from_slice(&payload);
        assert!(parsed.is_err(), "extra envelope fields must be rejected");
    }
}
