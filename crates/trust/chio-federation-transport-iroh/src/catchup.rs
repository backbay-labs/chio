//! Content-addressed anti-entropy catch-up (ADAPTER-SPEC section 3.4 + lane e).
//!
//! The paired substrate for lane b (`crate::lanes::revocation`). The CONTROL
//! envelope ([`RevocationCatchupRequest`] /
//! [`chio_federation::revocation_gossip::RevocationCatchupResponse`]) rides lane
//! b's QUIC stream; the BULK signed-root bytes ride iroh-blobs, content
//! addressed and capped at
//! [`REVOCATION_CATCHUP_MAX_EPOCHS`](chio_federation::revocation_gossip::REVOCATION_CATCHUP_MAX_EPOCHS).
//!
//! ## Integrity is not authenticity
//!
//! iroh-blobs gives BLAKE3 verified streaming: the bytes match the requested
//! hash (integrity), but NOT who signed the root (authenticity, ADAPTER-SPEC
//! 2.2). So every fetched blob is deserialized as a
//! [`chio_revocation_oracle::SignedEpochRoot`] and signature-verified against the
//! PINNED signer ([`crate::lanes::revocation::VerifiedSignerDirectory`]) before it
//! is trusted, with strict monotone epoch ordering / gap detection mirroring
//! [`RevocationCatchupResponse::validate_response`](chio_federation::revocation_gossip::RevocationCatchupResponse::validate_response).
//! Any failure leaves the caught-up set EMPTY (all-or-nothing).
//!
//! ## Gating
//!
//! The downloader runs behind the accept-time admission gate: the authority
//! serves [`BlobsProtocol`] on an endpoint that also installs the
//! [`DirectoryGate`](crate::admission::DirectoryGate) hooks, so an unadmitted
//! follower is rejected at `after_handshake` before any blob byte transfers
//! (ADAPTER-SPEC 6 item 1, validated by the PoC `three_way.rs`). As additional
//! defense in depth, the follower only pulls from the endpoint that its pinned
//! signer binding names, so it can never fetch roots from an impostor authority.
//!
//! Store is [`FsStore`] so caught-up history survives a restart (ADAPTER-SPEC 3.4).

use std::collections::HashMap;
use std::sync::Arc;

use chio_federation::revocation_gossip::RevocationCatchupHistory;
use chio_federation::revocation_gossip::RevocationGossipError;
use chio_federation::revocation_gossip::REVOCATION_CATCHUP_MAX_EPOCHS;
use chio_revocation_oracle::EpochRootVerifier;
use chio_revocation_oracle::SignedEpochRoot;
use iroh::Endpoint;
use iroh::EndpointId;
use iroh_blobs::api::downloader::Shuffled;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::Hash;

use crate::lanes::revocation::SignerBinding;
use crate::lanes::revocation::VerifiedSignerDirectory;

/// Errors surfaced by the blobs catch-up substrate. Every variant is
/// fail-closed: on any failure the caught-up set is empty and nothing is merged.
#[derive(Debug, thiserror::Error)]
pub enum CatchupError {
    /// An iroh-blobs transport error (download, add, or read).
    #[error("blobs transport error: {0}")]
    Blob(String),
    /// The signer named for the fetch is not pinned.
    #[error("no pinned signer binding for signer_id `{0}`")]
    UnknownSigner(String),
    /// The named authority endpoint is not the one the pinned signer is bound to.
    #[error("signer `{signer_id}` is not pinned to authority endpoint {endpoint}")]
    SignerEndpointMismatch {
        /// The opaque signer identity requested.
        signer_id: String,
        /// The authority endpoint (short form) the caller tried to pull from.
        endpoint: String,
    },
    /// The fetched bytes do not hash to the requested content address. BLAKE3
    /// verified streaming should make this unreachable; re-checked fail-closed.
    #[error("fetched blob content hash {actual} does not match requested address {expected}")]
    IntegrityMismatch {
        /// Recomputed BLAKE3 address of the fetched bytes.
        actual: String,
        /// The address the follower requested.
        expected: String,
    },
    /// The pinned-signer signature check over the fetched root failed.
    #[error("epoch root signature failed pinned-signer verification (signer_id `{0}`)")]
    BadSignature(String),
    /// A monotone ordering / gap / cap violation from the contract layer.
    #[error("catch-up ordering error: {0}")]
    Ordering(#[from] RevocationGossipError),
    /// The catch-up manifest exceeds the hard epoch cap.
    #[error("catch-up manifest too wide: {requested} > {max}")]
    ManifestTooWide {
        /// Number of requested epochs.
        requested: u64,
        /// The hard cap.
        max: u64,
    },
    /// A JSON (de)serialization failure.
    #[error("wire codec error: {0}")]
    Codec(String),
}

/// A follower's caught-up, signature-verified history, keyed by epoch. Backs the
/// contract's [`RevocationCatchupHistory`] so a follower that just filled a gap
/// over blobs can immediately serve those roots to the next peer.
#[derive(Debug, Clone, Default)]
pub struct BlobBackedHistory {
    roots: HashMap<u64, SignedEpochRoot>,
}

impl BlobBackedHistory {
    /// Build from a strictly-ordered, already-verified run of signed roots (the
    /// output of [`BlobCatchupClient::fetch_range`]).
    #[must_use]
    pub fn from_verified(roots: Vec<SignedEpochRoot>) -> Self {
        Self {
            roots: roots
                .into_iter()
                .map(|signed| (signed.root.epoch, signed))
                .collect(),
        }
    }

    /// Number of retained roots.
    #[must_use]
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Whether the history holds no roots.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
}

impl RevocationCatchupHistory for BlobBackedHistory {
    fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
        self.roots.get(&epoch).cloned()
    }
}

/// The blobs catch-up client. Holds a durable [`FsStore`], the gated
/// [`Endpoint`] used to build a `Downloader`, and the pinned signer directory.
#[derive(Debug, Clone)]
pub struct BlobCatchupClient {
    store: FsStore,
    endpoint: Endpoint,
    signers: Arc<VerifiedSignerDirectory>,
}

impl BlobCatchupClient {
    /// Load (or create) the durable blob store at `store_path` and build the
    /// client. The `endpoint` MUST already have the admission gate installed via
    /// `Endpoint::builder(..).hooks(gate)`; catch-up pulls only from the endpoint
    /// its pinned signer binding names.
    pub async fn load(
        store_path: impl AsRef<std::path::Path>,
        endpoint: Endpoint,
        signers: Arc<VerifiedSignerDirectory>,
    ) -> Result<Self, CatchupError> {
        let store = FsStore::load(store_path)
            .await
            .map_err(|error| CatchupError::Blob(error.to_string()))?;
        Ok(Self {
            store,
            endpoint,
            signers,
        })
    }

    /// Build the [`BlobsProtocol`] handler to mount on the AUTHORITY's gated
    /// endpoint: `Router::builder(ep).accept(iroh_blobs::ALPN, client.blobs_protocol())`.
    #[must_use]
    pub fn blobs_protocol(&self) -> BlobsProtocol {
        BlobsProtocol::new(self.store.as_ref(), None)
    }

    /// AUTHORITY side: publish one signed root as a content-addressed blob,
    /// returning its stable BLAKE3 address. The address is the manifest entry a
    /// follower fetches over blobs; the (epoch -> hash) manifest is the small
    /// control that rides lane b.
    pub async fn publish_signed_root(
        &self,
        signed: &SignedEpochRoot,
    ) -> Result<Hash, CatchupError> {
        publish_signed_root(&self.store, signed).await
    }

    /// FOLLOWER side: fetch and verify a strict monotone run of signed roots over
    /// blobs.
    ///
    /// `manifest` is the `(epoch, content-address)` list obtained via the lane-b
    /// control response. The walk:
    /// 1. rejects an over-cap manifest fail-closed,
    /// 2. resolves the pinned signer and asserts `authority` is its bound
    ///    endpoint (only pull from the pinned authority),
    /// 3. two-step downloads each blob into the follower store then reads it,
    /// 4. re-checks BLAKE3 integrity and pinned-signer authenticity per blob,
    /// 5. enforces strict monotone contiguous epochs (mirrors `validate_response`).
    ///
    /// All-or-nothing: ANY failure returns `Err` and yields no partial history.
    pub async fn fetch_range(
        &self,
        signer_id: &str,
        authority: EndpointId,
        manifest: &[(u64, Hash)],
    ) -> Result<Vec<SignedEpochRoot>, CatchupError> {
        check_manifest_cap(manifest.len())?;
        let binding = self
            .signers
            .resolve(signer_id)
            .ok_or_else(|| CatchupError::UnknownSigner(signer_id.to_string()))?;
        if binding.endpoint != authority {
            return Err(CatchupError::SignerEndpointMismatch {
                signer_id: signer_id.to_string(),
                endpoint: authority.fmt_short().to_string(),
            });
        }

        let downloader = self.store.downloader(&self.endpoint);
        let mut verified: Vec<SignedEpochRoot> = Vec::with_capacity(manifest.len());
        for (epoch, hash) in manifest {
            // Two-step download (ADAPTER-SPEC 3.4): fetch INTO the follower store
            // from the pinned authority only, then read the bytes back.
            downloader
                .download(*hash, Shuffled::new(vec![authority]))
                .await
                .map_err(|error| CatchupError::Blob(error.to_string()))?;
            let bytes = self
                .store
                .blobs()
                .get_bytes(*hash)
                .await
                .map_err(|error| CatchupError::Blob(error.to_string()))?;
            let signed = decode_and_verify_root(&bytes, *hash, binding)?;
            // Per-entry epoch pin: the manifest epoch must match the signed root.
            if signed.root.epoch != *epoch {
                return Err(CatchupError::Ordering(RevocationGossipError::CatchupGap {
                    expected: *epoch,
                    observed: signed.root.epoch,
                }));
            }
            verified.push(signed);
        }
        // Strict monotone contiguous ordering across the run (mirror semantics).
        order_check(&verified)?;
        Ok(verified)
    }
}

/// AUTHORITY side, store-only: publish one signed root as a content-addressed
/// blob. Separated from [`BlobCatchupClient`] so it is exercisable without an
/// [`Endpoint`]. The blob content is the RFC-8785 canonical JSON of the root, so
/// the address is stable and dedups naturally.
pub async fn publish_signed_root(
    store: &FsStore,
    signed: &SignedEpochRoot,
) -> Result<Hash, CatchupError> {
    let bytes = chio_core_types::canonical_json_bytes(signed)
        .map_err(|error| CatchupError::Codec(error.to_string()))?;
    let expected = Hash::new(&bytes);
    let tag = store
        .blobs()
        .add_bytes(bytes)
        .await
        .map_err(|error| CatchupError::Blob(error.to_string()))?;
    if tag.hash != expected {
        return Err(CatchupError::IntegrityMismatch {
            actual: tag.hash.to_string(),
            expected: expected.to_string(),
        });
    }
    Ok(tag.hash)
}

/// Reject an over-cap catch-up manifest fail-closed
/// ([`REVOCATION_CATCHUP_MAX_EPOCHS`]).
fn check_manifest_cap(len: usize) -> Result<(), CatchupError> {
    let requested = len as u64;
    if requested > REVOCATION_CATCHUP_MAX_EPOCHS {
        return Err(CatchupError::ManifestTooWide {
            requested,
            max: REVOCATION_CATCHUP_MAX_EPOCHS,
        });
    }
    Ok(())
}

/// Verify one fetched blob's bytes as a [`SignedEpochRoot`]: BLAKE3 integrity
/// against the requested content address, then pinned-signer authenticity.
fn decode_and_verify_root(
    bytes: &[u8],
    expected_hash: Hash,
    binding: &SignerBinding,
) -> Result<SignedEpochRoot, CatchupError> {
    // Integrity: re-check the BLAKE3 address (defense in depth over blobs' own
    // verified streaming).
    let actual = Hash::new(bytes);
    if actual != expected_hash {
        return Err(CatchupError::IntegrityMismatch {
            actual: actual.to_string(),
            expected: expected_hash.to_string(),
        });
    }
    let signed: SignedEpochRoot =
        serde_json::from_slice(bytes).map_err(|error| CatchupError::Codec(error.to_string()))?;
    // Authenticity: BLAKE3 gives integrity, not authenticity. Verify against the
    // pinned signer's verify-only key.
    signed
        .verify(&binding.verifier)
        .map_err(|_| CatchupError::BadSignature(binding.verifier.signer_id().to_string()))?;
    Ok(signed)
}

/// Enforce strict monotone contiguous epoch ordering across an already-verified
/// run, raising [`RevocationGossipError::CatchupGap`] on a hole. Byte-identical
/// to the contract's `validate_response` monotone rule.
fn order_check(roots: &[SignedEpochRoot]) -> Result<(), CatchupError> {
    let mut prev: Option<u64> = None;
    for signed in roots {
        if let Some(previous) = prev {
            let expected = previous.saturating_add(1);
            if signed.root.epoch != expected {
                return Err(CatchupError::Ordering(RevocationGossipError::CatchupGap {
                    expected,
                    observed: signed.root.epoch,
                }));
            }
        }
        prev = Some(signed.root.epoch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core_types::canonical_json_bytes;
    use chio_revocation_oracle::Ed25519RootSigner;
    use chio_revocation_oracle::EpochRoot;
    use iroh::SecretKey;

    const SEED_A: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const SEED_B: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    fn signer(signer_id: &str, seed: &str) -> Ed25519RootSigner {
        Ed25519RootSigner::from_signing_key(signer_id, seed).expect("valid seed")
    }

    fn signed_root(signer: &Ed25519RootSigner, epoch: u64) -> SignedEpochRoot {
        let root = EpochRoot {
            epoch,
            root_hash: [epoch as u8; 32],
            leaf_count: epoch as usize,
            issued_at_unix_ms: 1_700_000_000_000 + epoch,
        };
        SignedEpochRoot::sign(root, signer).expect("sign never fails")
    }

    fn binding(endpoint: EndpointId, signer: &Ed25519RootSigner) -> SignerBinding {
        SignerBinding {
            endpoint,
            verifier: signer.verifier(),
        }
    }

    /// The bytes + stable content address a follower would fetch for a root.
    fn blob_of(signed: &SignedEpochRoot) -> (Vec<u8>, Hash) {
        let bytes = canonical_json_bytes(signed).unwrap();
        let hash = Hash::new(&bytes);
        (bytes, hash)
    }

    #[test]
    fn signed_root_accepted_from_pinned_signer() {
        let endpoint = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let bind = binding(endpoint, &oracle);
        let signed = signed_root(&oracle, 5);
        let (bytes, hash) = blob_of(&signed);

        let got = decode_and_verify_root(&bytes, hash, &bind).expect("pinned signer accepts");
        assert_eq!(got, signed);
    }

    #[test]
    fn tampered_signature_is_rejected_bad_signature() {
        let endpoint = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let bind = binding(endpoint, &oracle);
        // Tamper the signature, THEN re-address the tampered bytes so integrity
        // passes and only authenticity can fail (isolating the crypto check).
        let mut signed = signed_root(&oracle, 5);
        signed.signature.signature_bytes[0] ^= 0x01;
        let (bytes, hash) = blob_of(&signed);

        let err = decode_and_verify_root(&bytes, hash, &bind)
            .expect_err("tampered signature must fail closed");
        assert!(matches!(err, CatchupError::BadSignature(ref id) if id == "oracle-a"));
    }

    #[test]
    fn wrong_signer_key_is_rejected_bad_signature() {
        let endpoint = endpoint_from_seed(10);
        // Pinned key is SEED_A; the blob was signed by a different key claiming
        // the same signer_id.
        let pinned = signer("oracle-a", SEED_A);
        let impostor = signer("oracle-a", SEED_B);
        let bind = binding(endpoint, &pinned);
        let (bytes, hash) = blob_of(&signed_root(&impostor, 5));

        let err = decode_and_verify_root(&bytes, hash, &bind)
            .expect_err("wrong signing key must fail closed");
        assert!(matches!(err, CatchupError::BadSignature(_)));
    }

    #[test]
    fn integrity_mismatch_is_rejected() {
        let endpoint = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let bind = binding(endpoint, &oracle);
        let (bytes, _hash) = blob_of(&signed_root(&oracle, 5));
        // Request under a DIFFERENT content address than the bytes hash to.
        let wrong = Hash::new(b"a different blob entirely");

        let err = decode_and_verify_root(&bytes, wrong, &bind)
            .expect_err("content address mismatch must fail closed");
        assert!(matches!(err, CatchupError::IntegrityMismatch { .. }));
    }

    #[test]
    fn epoch_gap_is_detected() {
        let oracle = signer("oracle-a", SEED_A);
        // A dropped epoch 3 between 2 and 4.
        let run = vec![
            signed_root(&oracle, 1),
            signed_root(&oracle, 2),
            signed_root(&oracle, 4),
        ];
        let err = order_check(&run).expect_err("dropped epoch must fail closed");
        match err {
            CatchupError::Ordering(RevocationGossipError::CatchupGap { expected, observed }) => {
                assert_eq!(expected, 3);
                assert_eq!(observed, 4);
            }
            other => panic!("expected CatchupGap, got {other:?}"),
        }
    }

    #[test]
    fn contiguous_run_passes_ordering() {
        let oracle = signer("oracle-a", SEED_A);
        let run = vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 6),
            signed_root(&oracle, 7),
        ];
        assert!(order_check(&run).is_ok());
    }

    #[test]
    fn manifest_over_cap_is_rejected() {
        let over = usize::try_from(REVOCATION_CATCHUP_MAX_EPOCHS).unwrap() + 1;
        let err = check_manifest_cap(over).expect_err("over-cap manifest must fail closed");
        match err {
            CatchupError::ManifestTooWide { requested, max } => {
                assert_eq!(max, REVOCATION_CATCHUP_MAX_EPOCHS);
                assert_eq!(requested, REVOCATION_CATCHUP_MAX_EPOCHS + 1);
            }
            other => panic!("expected ManifestTooWide, got {other:?}"),
        }
        assert!(
            check_manifest_cap(usize::try_from(REVOCATION_CATCHUP_MAX_EPOCHS).unwrap()).is_ok()
        );
    }

    #[test]
    fn blob_backed_history_serves_verified_roots() {
        let oracle = signer("oracle-a", SEED_A);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 6),
        ]);
        assert_eq!(history.len(), 2);
        assert!(!history.is_empty());
        assert_eq!(history.signed_root_at(5).unwrap().root.epoch, 5);
        assert!(history.signed_root_at(9).is_none());
    }

    /// End-to-end over the REAL durable FsStore (single node, no network):
    /// publish a signed root as a content-addressed blob, read it back, and
    /// verify it against the pinned signer. Exercises the corrected iroh-blobs
    /// 0.103 APIs (`add_bytes -> TagInfo.hash`, `get_bytes`, `Hash::new`, `FsStore`).
    #[tokio::test]
    async fn fsstore_publish_read_verify_round_trip() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "chio-catchup-blob-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = FsStore::load(&dir).await.expect("load fs store");

        let endpoint = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let bind = binding(endpoint, &oracle);
        let signed = signed_root(&oracle, 5);

        let hash = publish_signed_root(&store, &signed)
            .await
            .expect("publish blob");
        // Content address is the stable BLAKE3 of the canonical bytes.
        assert_eq!(hash, blob_of(&signed).1);

        let bytes = store.blobs().get_bytes(hash).await.expect("read blob back");
        let got = decode_and_verify_root(&bytes, hash, &bind).expect("verify fetched root");
        assert_eq!(got, signed);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
