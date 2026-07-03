//! Revocation root gossip message types and bilateral push/pull paths.
//!
//! This module is the federation-side surface that carries signed
//! [`chio_revocation_oracle::SignedEpochRoot`] artifacts between bilateral
//! peers. The oracle itself owns the sparse-Merkle-tree state and signing;
//! `chio-federation` only owns the wire envelope, the batched push queue,
//! and the catch-up gap-fill protocol. Verifiers consult their kernel-core
//! `RevocationView` cache, which gossip updates fail-closed: an
//! unverifiable, malformed, or out-of-order gossip frame is dropped and
//! never silently merged into the cache.
//!
//! ## Wire envelope
//!
//! [`RevocationRootGossip`] wraps a single signed epoch root with the
//! signer identity, signer-id-pinning, and a millisecond timestamp the
//! receiver can use for freshness gating. The on-the-wire schema is
//! [`REVOCATION_ROOT_GOSSIP_SCHEMA`].
//!
//! ## Push path
//!
//! [`RevocationGossipPushQueue`] owns a bilateral peer registry plus a
//! per-peer FIFO ring of pending signed roots. The oracle's epoch tick
//! calls [`RevocationGossipPushQueue::enqueue_signed_root`] every time it
//! advances; the federation transport calls
//! [`RevocationGossipPushQueue::flush_batches_at`] every
//! [`chio_revocation_oracle::DEFAULT_EPOCH_TICK_MS`] to drain accumulated
//! roots into per-peer [`RevocationGossipBatch`] frames it can hand to the
//! transport. Coalescing inside a tick keeps the gossip storm bounded under
//! high revoke rates (only the latest root per epoch survives a flush, and
//! an empty queue produces no batch at all).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};

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
            return Err(RevocationGossipError::UnsupportedSchema(
                self.schema.clone(),
            ));
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

    #[error("envelope signer_id `{envelope}` disagrees with signed-root signer_id `{signed}`")]
    SignerIdMismatch { envelope: String, signed: String },

    #[error("peer {0} is not subscribed to revocation-root gossip")]
    UnknownPeer(String),

    #[error("invalid revocation gossip configuration: {0}")]
    InvalidConfiguration(String),

    #[error("revocation gossip push queue is poisoned and cannot service requests")]
    QueuePoisoned,

    #[error("catch-up request range inverted: from_epoch {from_epoch} > to_epoch {to_epoch}")]
    CatchupRangeInverted { from_epoch: u64, to_epoch: u64 },

    #[error("catch-up request range too wide: requested {requested} epochs, hard cap is {max}")]
    CatchupRangeTooWide { requested: u64, max: u64 },

    #[error(
        "catch-up response monotone ordering violated: expected epoch {expected}, got {observed}"
    )]
    CatchupGap { expected: u64, observed: u64 },
}

impl<T> From<PoisonError<T>> for RevocationGossipError {
    fn from(_: PoisonError<T>) -> Self {
        RevocationGossipError::QueuePoisoned
    }
}

/// Schema tag for [`RevocationGossipBatch`].
pub const REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA: &str =
    "chio.federation-revocation-root-gossip-batch.v1";

/// Schema tag for [`RevocationCatchupRequest`].
pub const REVOCATION_CATCHUP_REQUEST_SCHEMA: &str = "chio.federation-revocation-catchup-request.v1";

/// Schema tag for [`RevocationCatchupResponse`].
pub const REVOCATION_CATCHUP_RESPONSE_SCHEMA: &str =
    "chio.federation-revocation-catchup-response.v1";

/// Hard cap on the number of epochs a single catch-up exchange will carry.
/// Larger gaps must be chunked across multiple round-trips so a single
/// stalled peer cannot force the responder to materialise an unbounded
/// history slice.
pub const REVOCATION_CATCHUP_MAX_EPOCHS: u64 = 4_096;

/// A coalesced batch of [`RevocationRootGossip`] frames addressed to a
/// single bilateral peer.
///
/// The push queue produces one batch per subscribed peer per flush. Each
/// frame inside the batch carries the [`SignedEpochRoot`] verbatim, so the
/// receiver still verifies signatures individually before merging the
/// implied root into its [`crate::revocation_gossip::RevocationRootGossip`]
/// cache. Empty batches are never emitted; a peer with no pending roots is
/// omitted from the flush result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationGossipBatch {
    pub schema: String,
    pub recipient_kernel_id: String,
    pub frames: Vec<RevocationRootGossip>,
    pub flushed_at_unix_ms: u64,
}

impl RevocationGossipBatch {
    /// Cheap structural sanity check on a received batch. The receiver MUST
    /// also `validate_envelope()` and signature-verify every frame before
    /// merging it into a local cache.
    pub fn validate_envelope(&self) -> Result<(), RevocationGossipError> {
        if self.schema != REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA {
            return Err(RevocationGossipError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        for frame in &self.frames {
            frame.validate_envelope()?;
        }
        Ok(())
    }
}

/// In-memory bilateral push queue.
///
/// Each subscribed peer has its own FIFO ring of pending signed roots.
/// Inside a single tick, [`RevocationGossipPushQueue::enqueue_signed_root`]
/// coalesces by epoch: a newer root for the same epoch replaces an older
/// one, and a strictly higher epoch evicts every queued lower epoch. This
/// keeps the gossip storm bounded under high revoke rates without losing
/// the latest verifier-relevant root.
///
/// [`RevocationGossipPushQueue::flush_batches_at`] drains every peer's
/// queue into a [`RevocationGossipBatch`] tagged with the supplied
/// `now_unix_ms`. The transport layer is then responsible for delivering
/// each batch to its recipient. Empty queues yield no batch.
#[derive(Debug)]
pub struct RevocationGossipPushQueue {
    capacity_per_peer: usize,
    inner: Mutex<HashMap<String, VecDeque<SignedEpochRoot>>>,
}

impl RevocationGossipPushQueue {
    /// Build a new push queue. `capacity_per_peer` bounds the FIFO ring per
    /// subscriber; zero is rejected fail-closed so a misconfigured queue
    /// cannot silently drop every root.
    pub fn new(capacity_per_peer: usize) -> Result<Self, RevocationGossipError> {
        if capacity_per_peer == 0 {
            return Err(RevocationGossipError::InvalidConfiguration(
                "capacity_per_peer must be > 0".to_string(),
            ));
        }
        Ok(Self {
            capacity_per_peer,
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Subscribe a bilateral peer. Idempotent: subscribing the same peer
    /// twice is a no-op and never resets the existing queue.
    pub fn subscribe(&self, peer_kernel_id: &str) -> Result<(), RevocationGossipError> {
        let mut guard = self.inner.lock()?;
        guard
            .entry(peer_kernel_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(self.capacity_per_peer));
        Ok(())
    }

    /// Unsubscribe a bilateral peer. Returns `true` if the peer was present.
    pub fn unsubscribe(&self, peer_kernel_id: &str) -> Result<bool, RevocationGossipError> {
        let mut guard = self.inner.lock()?;
        Ok(guard.remove(peer_kernel_id).is_some())
    }

    /// Snapshot of every currently-subscribed peer kernel id, sorted for
    /// determinism in tests and tracing.
    pub fn subscribers(&self) -> Result<BTreeSet<String>, RevocationGossipError> {
        let guard = self.inner.lock()?;
        Ok(guard.keys().cloned().collect())
    }

    /// Enqueue a freshly-signed epoch root for every subscribed peer.
    ///
    /// Coalescing rule: within each peer's queue, any pending entry with an
    /// epoch strictly lower than the new root's epoch is discarded, and any
    /// pending entry with the same epoch is replaced. A root older than a
    /// peer's newest pending epoch is dropped instead of being enqueued. The
    /// queue is also bounded: once `capacity_per_peer` is reached, the oldest
    /// entry is evicted to make room (the catch-up path covers any peer that
    /// fell behind).
    pub fn enqueue_signed_root(
        &self,
        signed: SignedEpochRoot,
    ) -> Result<usize, RevocationGossipError> {
        let mut guard = self.inner.lock()?;
        let mut delivered = 0_usize;
        for queue in guard.values_mut() {
            let new_epoch = signed.root.epoch;
            if queue.iter().any(|existing| existing.root.epoch > new_epoch) {
                continue;
            }
            queue.retain(|existing| existing.root.epoch > new_epoch);
            if queue.len() == self.capacity_per_peer {
                queue.pop_front();
            }
            queue.push_back(signed.clone());
            delivered = delivered.saturating_add(1);
        }
        Ok(delivered)
    }

    /// Drain pending roots into per-peer [`RevocationGossipBatch`] frames.
    ///
    /// `now_unix_ms` is stamped both onto every produced
    /// [`RevocationRootGossip`] envelope and onto the enclosing batch's
    /// `flushed_at_unix_ms` field. Peers with empty queues are omitted from
    /// the result. Output order is sorted by recipient for deterministic
    /// transport-side handling.
    pub fn flush_batches_at(
        &self,
        now_unix_ms: u64,
    ) -> Result<Vec<RevocationGossipBatch>, RevocationGossipError> {
        let mut guard = self.inner.lock()?;
        let mut batches = Vec::new();
        let mut peer_ids: Vec<String> = guard.keys().cloned().collect();
        peer_ids.sort();
        for peer in peer_ids {
            if let Some(queue) = guard.get_mut(&peer) {
                if queue.is_empty() {
                    continue;
                }
                let frames: Vec<RevocationRootGossip> = queue
                    .drain(..)
                    .map(|signed| RevocationRootGossip::from_signed(signed, now_unix_ms))
                    .collect();
                batches.push(RevocationGossipBatch {
                    schema: REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA.to_string(),
                    recipient_kernel_id: peer,
                    frames,
                    flushed_at_unix_ms: now_unix_ms,
                });
            }
        }
        Ok(batches)
    }

    /// Number of pending signed roots queued for a specific peer. Returns
    /// `Ok(None)` if the peer is not subscribed. Primarily a test affordance.
    pub fn pending_for(
        &self,
        peer_kernel_id: &str,
    ) -> Result<Option<usize>, RevocationGossipError> {
        let guard = self.inner.lock()?;
        Ok(guard.get(peer_kernel_id).map(VecDeque::len))
    }
}

/// Request a peer that has fallen behind by `N` epochs sends to fill the
/// gap with a sequence of signed roots.
///
/// The receiver MUST reject any request where:
/// * `from_epoch > to_epoch`,
/// * `to_epoch - from_epoch + 1 > REVOCATION_CATCHUP_MAX_EPOCHS`,
/// * the schema tag does not match [`REVOCATION_CATCHUP_REQUEST_SCHEMA`].
///
/// `requester_kernel_id` is informational and used by the responder for
/// scoping/audit; it is not a substitute for a transport-level identity
/// pin (the bilateral peer set in `KernelTrustExchange` is the source of
/// truth for who is allowed to ask).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationCatchupRequest {
    pub schema: String,
    pub requester_kernel_id: String,
    /// First epoch (inclusive) the requester is missing.
    pub from_epoch: u64,
    /// Last epoch (inclusive) the requester wants. Equal to `from_epoch`
    /// for a single-epoch fetch.
    pub to_epoch: u64,
    pub requested_at_unix_ms: u64,
}

impl RevocationCatchupRequest {
    /// Build a well-formed request. Returns `Err` if the requested range is
    /// inverted or larger than [`REVOCATION_CATCHUP_MAX_EPOCHS`].
    pub fn new(
        requester_kernel_id: impl Into<String>,
        from_epoch: u64,
        to_epoch: u64,
        requested_at_unix_ms: u64,
    ) -> Result<Self, RevocationGossipError> {
        let req = Self {
            schema: REVOCATION_CATCHUP_REQUEST_SCHEMA.to_string(),
            requester_kernel_id: requester_kernel_id.into(),
            from_epoch,
            to_epoch,
            requested_at_unix_ms,
        };
        req.validate_envelope()?;
        Ok(req)
    }

    pub fn validate_envelope(&self) -> Result<(), RevocationGossipError> {
        if self.schema != REVOCATION_CATCHUP_REQUEST_SCHEMA {
            return Err(RevocationGossipError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        if self.from_epoch > self.to_epoch {
            return Err(RevocationGossipError::CatchupRangeInverted {
                from_epoch: self.from_epoch,
                to_epoch: self.to_epoch,
            });
        }
        let span = self
            .to_epoch
            .saturating_sub(self.from_epoch)
            .saturating_add(1);
        if span > REVOCATION_CATCHUP_MAX_EPOCHS {
            return Err(RevocationGossipError::CatchupRangeTooWide {
                requested: span,
                max: REVOCATION_CATCHUP_MAX_EPOCHS,
            });
        }
        Ok(())
    }
}

/// Response carrying the contiguous run of signed roots a responder
/// produced for a [`RevocationCatchupRequest`].
///
/// The frames are emitted in strictly increasing epoch order with no gaps
/// within the responder's known history. If the responder cannot cover the
/// full requested range (because its own history starts later than
/// `request.from_epoch`), the response carries the suffix it does have and
/// surfaces the truncation through [`Self::validate_response`]: callers
/// use the returned coverage span to decide whether to issue a follow-up
/// request to a different peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RevocationCatchupResponse {
    pub schema: String,
    /// Echoed back from [`RevocationCatchupRequest::requester_kernel_id`].
    pub requester_kernel_id: String,
    pub responder_kernel_id: String,
    pub frames: Vec<RevocationRootGossip>,
    pub responded_at_unix_ms: u64,
}

impl RevocationCatchupResponse {
    /// Validate the response in isolation: schema, every frame's envelope,
    /// strict monotone epoch ordering with no internal gaps. Callers MUST
    /// also signature-verify every frame against the responder's pinned
    /// signer before merging into their cache.
    pub fn validate_response(&self) -> Result<(), RevocationGossipError> {
        if self.schema != REVOCATION_CATCHUP_RESPONSE_SCHEMA {
            return Err(RevocationGossipError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        let mut prev: Option<u64> = None;
        for frame in &self.frames {
            frame.validate_envelope()?;
            if let Some(previous) = prev {
                let expected = previous.saturating_add(1);
                if frame.epoch != expected {
                    return Err(RevocationGossipError::CatchupGap {
                        expected,
                        observed: frame.epoch,
                    });
                }
            }
            prev = Some(frame.epoch);
        }
        Ok(())
    }
}

/// Backing-store contract that produces signed roots for a contiguous epoch
/// range. The oracle (or the federation layer's persistent history shim)
/// implements this so the catch-up responder can serve gap-fill requests
/// without taking a dependency on the live oracle's mutable state.
pub trait RevocationCatchupHistory {
    /// Return the signed root at `epoch`, or `None` if the responder no
    /// longer retains it (history may be pruned). The responder MUST never
    /// fabricate a root: returning `None` is the only legitimate way to
    /// say "I do not have this epoch".
    fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot>;
}

/// Drive a catch-up exchange.
///
/// The function walks `[request.from_epoch, request.to_epoch]` against the
/// supplied history, collecting the contiguous suffix the responder
/// actually retains. Internal gaps inside the requested range cause the
/// walk to stop at the first missing epoch (the responder cannot
/// fabricate frames). The result is wrapped in a
/// [`RevocationCatchupResponse`] tagged with `responded_at_unix_ms`.
pub fn respond_to_catchup<H: RevocationCatchupHistory>(
    request: &RevocationCatchupRequest,
    responder_kernel_id: &str,
    history: &H,
    responded_at_unix_ms: u64,
) -> Result<RevocationCatchupResponse, RevocationGossipError> {
    request.validate_envelope()?;
    let mut frames: Vec<RevocationRootGossip> = Vec::new();
    let mut started = false;
    for epoch in request.from_epoch..=request.to_epoch {
        match history.signed_root_at(epoch) {
            Some(signed) => {
                frames.push(RevocationRootGossip::from_signed(
                    signed,
                    responded_at_unix_ms,
                ));
                started = true;
            }
            None => {
                if started {
                    // Gap inside the responder's known history: stop so the
                    // monotone-ordering invariant of the response holds.
                    break;
                }
                // Pre-history skip: keep scanning so a responder whose
                // retained window starts mid-range can still serve the
                // suffix it does have.
            }
        }
    }
    let response = RevocationCatchupResponse {
        schema: REVOCATION_CATCHUP_RESPONSE_SCHEMA.to_string(),
        requester_kernel_id: request.requester_kernel_id.clone(),
        responder_kernel_id: responder_kernel_id.to_string(),
        frames,
        responded_at_unix_ms,
    };
    response.validate_response()?;
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_revocation_oracle::{Ed25519RootSigner, EpochRoot, SignedEpochRoot};

    fn signed_root(signer_id: &str, epoch: u64) -> SignedEpochRoot {
        let signer =
            Ed25519RootSigner::from_signing_key(signer_id, "generate").expect("unit test signer");
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
        let mut value: serde_json::Value = serde_json::to_value(&gossip).expect("serialize gossip");
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

    #[test]
    fn push_queue_zero_capacity_rejected_fail_closed() {
        let err = RevocationGossipPushQueue::new(0)
            .expect_err("zero capacity must fail closed at construction");
        match err {
            RevocationGossipError::InvalidConfiguration(msg) => {
                assert!(msg.contains("capacity_per_peer"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn push_queue_subscribe_is_idempotent() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue.subscribe("peer-b").unwrap();
        let subs = queue.subscribers().unwrap();
        assert_eq!(subs.len(), 1);
        assert!(subs.contains("peer-b"));
    }

    #[test]
    fn push_queue_unsubscribe_reports_presence() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        assert!(queue.unsubscribe("peer-b").unwrap());
        assert!(!queue.unsubscribe("peer-b").unwrap());
    }

    #[test]
    fn push_queue_enqueues_to_every_subscriber() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue.subscribe("peer-c").unwrap();
        let signed = signed_root("oracle-a", 1);
        let delivered = queue.enqueue_signed_root(signed.clone()).unwrap();
        assert_eq!(delivered, 2);
        assert_eq!(queue.pending_for("peer-b").unwrap(), Some(1));
        assert_eq!(queue.pending_for("peer-c").unwrap(), Some(1));
        assert_eq!(queue.pending_for("peer-z").unwrap(), None);
    }

    #[test]
    fn push_queue_coalesces_lower_epochs() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 1))
            .unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 2))
            .unwrap();
        // Replace same epoch with newer signed-root.
        queue
            .enqueue_signed_root(signed_root("oracle-a", 2))
            .unwrap();
        // Strictly higher epoch evicts every prior queued root.
        queue
            .enqueue_signed_root(signed_root("oracle-a", 3))
            .unwrap();
        assert_eq!(queue.pending_for("peer-b").unwrap(), Some(1));
        let batches = queue.flush_batches_at(1_700_000_010_000).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].frames.len(), 1);
        assert_eq!(batches[0].frames[0].epoch, 3);
    }

    #[test]
    fn push_queue_flush_omits_empty_peers() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue.subscribe("peer-c").unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 5))
            .unwrap();
        // Drain peer-b explicitly by removing it before flush; peer-c keeps
        // its entry. Only peer-c should produce a batch.
        let _ = queue.unsubscribe("peer-b").unwrap();
        let batches = queue.flush_batches_at(1_700_000_011_000).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].recipient_kernel_id, "peer-c");
        assert_eq!(batches[0].schema, REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA);
        assert_eq!(batches[0].flushed_at_unix_ms, 1_700_000_011_000);
        assert!(batches[0].validate_envelope().is_ok());
        // Re-flush after drain returns nothing.
        let again = queue.flush_batches_at(1_700_000_012_000).unwrap();
        assert!(again.is_empty());
    }

    #[test]
    fn push_queue_capacity_eviction_drops_oldest() {
        // Capacity 1: feed in two non-monotone-coalescable epochs by feeding
        // descending epochs (so the coalescing rule keeps the older one and
        // the newer enqueue must evict via the capacity bound).
        let queue = RevocationGossipPushQueue::new(1).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 5))
            .unwrap();
        // Lower epoch: coalesce drops it (epoch 5 already in queue).
        queue
            .enqueue_signed_root(signed_root("oracle-a", 4))
            .unwrap();
        // Same epoch with refreshed signature replaces.
        queue
            .enqueue_signed_root(signed_root("oracle-a", 5))
            .unwrap();
        assert_eq!(queue.pending_for("peer-b").unwrap(), Some(1));
        let batches = queue.flush_batches_at(0).unwrap();
        assert_eq!(batches[0].frames[0].epoch, 5);
    }

    #[test]
    fn push_queue_drops_stale_epochs_per_peer() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        assert_eq!(
            queue
                .enqueue_signed_root(signed_root("oracle-a", 8))
                .unwrap(),
            1
        );
        assert_eq!(
            queue
                .enqueue_signed_root(signed_root("oracle-a", 7))
                .unwrap(),
            0
        );
        assert_eq!(queue.pending_for("peer-b").unwrap(), Some(1));
        let batches = queue.flush_batches_at(0).unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].frames.len(), 1);
        assert_eq!(batches[0].frames[0].epoch, 8);
    }

    #[test]
    fn push_queue_flush_stamps_now_into_envelope() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 9))
            .unwrap();
        let batches = queue.flush_batches_at(1_700_000_020_000).unwrap();
        let frame = &batches[0].frames[0];
        assert_eq!(frame.ts_unix_ms, 1_700_000_020_000);
        // Round-trip through validate_envelope to ensure no fields were
        // dropped during the construction.
        assert!(frame.validate_envelope().is_ok());
    }

    #[test]
    fn batch_envelope_rejects_bad_inner_frame() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 1))
            .unwrap();
        let mut batches = queue.flush_batches_at(0).unwrap();
        // Tamper with the inner frame's epoch hint to simulate a corrupted
        // batch on the wire; validate_envelope must surface the inner error.
        batches[0].frames[0].epoch = 99;
        let err = batches[0]
            .validate_envelope()
            .expect_err("inner frame mismatch must fail closed");
        assert_eq!(
            err,
            RevocationGossipError::EpochMismatch {
                envelope: 99,
                signed: 1
            }
        );
    }

    #[test]
    fn batch_envelope_rejects_bad_schema() {
        let queue = RevocationGossipPushQueue::new(8).unwrap();
        queue.subscribe("peer-b").unwrap();
        queue
            .enqueue_signed_root(signed_root("oracle-a", 1))
            .unwrap();
        let mut batches = queue.flush_batches_at(0).unwrap();
        batches[0].schema = "chio.federation-bogus.v1".to_string();
        let err = batches[0]
            .validate_envelope()
            .expect_err("bad batch schema must fail closed");
        match err {
            RevocationGossipError::UnsupportedSchema(s) => assert!(s.contains("bogus")),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// Test-only history shim that holds a sparse map of signed roots by
    /// epoch. Mirrors the catch-up responder's contract that returning
    /// `None` means "I do not have this epoch" without ever fabricating.
    struct InMemoryHistory {
        roots: std::collections::HashMap<u64, SignedEpochRoot>,
    }

    impl InMemoryHistory {
        fn from_range(signer_id: &str, range: std::ops::RangeInclusive<u64>) -> Self {
            let mut roots = std::collections::HashMap::new();
            for epoch in range {
                roots.insert(epoch, signed_root(signer_id, epoch));
            }
            Self { roots }
        }
    }

    impl RevocationCatchupHistory for InMemoryHistory {
        fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
            self.roots.get(&epoch).cloned()
        }
    }

    #[test]
    fn catchup_request_new_rejects_inverted_range() {
        let err = RevocationCatchupRequest::new("peer-a", 9, 5, 0)
            .expect_err("inverted range must fail closed");
        assert_eq!(
            err,
            RevocationGossipError::CatchupRangeInverted {
                from_epoch: 9,
                to_epoch: 5
            }
        );
    }

    #[test]
    fn catchup_request_new_rejects_oversized_range() {
        let max = REVOCATION_CATCHUP_MAX_EPOCHS;
        let err = RevocationCatchupRequest::new("peer-a", 0, max, 0)
            .expect_err("oversized range must fail closed");
        match err {
            RevocationGossipError::CatchupRangeTooWide {
                requested,
                max: cap,
            } => {
                assert_eq!(cap, REVOCATION_CATCHUP_MAX_EPOCHS);
                assert_eq!(requested, max + 1);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn catchup_request_validate_rejects_bad_schema() {
        let mut req = RevocationCatchupRequest::new("peer-a", 1, 3, 0).unwrap();
        req.schema = "chio.federation-bogus.v1".to_string();
        let err = req
            .validate_envelope()
            .expect_err("bad schema must fail closed");
        match err {
            RevocationGossipError::UnsupportedSchema(_) => {}
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn catchup_responder_emits_full_range_in_order() {
        let history = InMemoryHistory::from_range("oracle-a", 5..=8);
        let req = RevocationCatchupRequest::new("peer-a", 5, 8, 0).unwrap();
        let resp = respond_to_catchup(&req, "oracle-a-host", &history, 1_700_000_030_000).unwrap();
        assert_eq!(resp.frames.len(), 4);
        let epochs: Vec<u64> = resp.frames.iter().map(|f| f.epoch).collect();
        assert_eq!(epochs, vec![5, 6, 7, 8]);
        assert_eq!(resp.responded_at_unix_ms, 1_700_000_030_000);
        assert_eq!(resp.schema, REVOCATION_CATCHUP_RESPONSE_SCHEMA);
        assert!(resp.validate_response().is_ok());
    }

    #[test]
    fn catchup_responder_skips_pre_history_then_serves_suffix() {
        // Responder retained 7..=10 only; requester asks for 4..=10.
        let history = InMemoryHistory::from_range("oracle-a", 7..=10);
        let req = RevocationCatchupRequest::new("peer-a", 4, 10, 0).unwrap();
        let resp = respond_to_catchup(&req, "oracle-a-host", &history, 0).unwrap();
        let epochs: Vec<u64> = resp.frames.iter().map(|f| f.epoch).collect();
        assert_eq!(epochs, vec![7, 8, 9, 10]);
    }

    #[test]
    fn catchup_responder_stops_at_internal_gap() {
        // Responder has 5,6,7,9,10 but requester asks 5..=10. The walk must
        // stop at the gap so the response stays strictly monotone.
        let mut history = InMemoryHistory::from_range("oracle-a", 5..=10);
        history.roots.remove(&8);
        let req = RevocationCatchupRequest::new("peer-a", 5, 10, 0).unwrap();
        let resp = respond_to_catchup(&req, "oracle-a-host", &history, 0).unwrap();
        let epochs: Vec<u64> = resp.frames.iter().map(|f| f.epoch).collect();
        assert_eq!(epochs, vec![5, 6, 7]);
        assert!(resp.validate_response().is_ok());
    }

    #[test]
    fn catchup_responder_emits_empty_response_when_history_missing() {
        let history = InMemoryHistory::from_range("oracle-a", 100..=110);
        let req = RevocationCatchupRequest::new("peer-a", 5, 8, 0).unwrap();
        let resp = respond_to_catchup(&req, "oracle-a-host", &history, 0).unwrap();
        assert!(resp.frames.is_empty());
        assert!(resp.validate_response().is_ok());
    }

    #[test]
    fn catchup_response_validate_detects_internal_gap() {
        let history = InMemoryHistory::from_range("oracle-a", 1..=3);
        let req = RevocationCatchupRequest::new("peer-a", 1, 3, 0).unwrap();
        let mut resp = respond_to_catchup(&req, "oracle-a-host", &history, 0).unwrap();
        // Splice an out-of-order frame to simulate corrupted-on-the-wire.
        resp.frames[1] = RevocationRootGossip::from_signed(signed_root("oracle-a", 99), 0);
        let err = resp
            .validate_response()
            .expect_err("monotone violation must fail closed");
        match err {
            RevocationGossipError::CatchupGap { expected, observed } => {
                assert_eq!(expected, 2);
                assert_eq!(observed, 99);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn catchup_response_validate_rejects_bad_schema() {
        let history = InMemoryHistory::from_range("oracle-a", 1..=2);
        let req = RevocationCatchupRequest::new("peer-a", 1, 2, 0).unwrap();
        let mut resp = respond_to_catchup(&req, "oracle-a-host", &history, 0).unwrap();
        resp.schema = "chio.federation-bogus.v1".to_string();
        let err = resp
            .validate_response()
            .expect_err("bad schema must fail closed");
        match err {
            RevocationGossipError::UnsupportedSchema(_) => {}
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn catchup_responder_propagates_request_validation_failure() {
        let history = InMemoryHistory::from_range("oracle-a", 1..=2);
        let bogus = RevocationCatchupRequest {
            schema: REVOCATION_CATCHUP_REQUEST_SCHEMA.to_string(),
            requester_kernel_id: "peer-a".to_string(),
            from_epoch: 9,
            to_epoch: 5,
            requested_at_unix_ms: 0,
        };
        let err = respond_to_catchup(&bogus, "oracle-a-host", &history, 0)
            .expect_err("inverted request must fail closed");
        assert_eq!(
            err,
            RevocationGossipError::CatchupRangeInverted {
                from_epoch: 9,
                to_epoch: 5
            }
        );
    }
}
