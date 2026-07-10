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
//! PINNED signer before it is trusted. The [`BlobCatchupClient`] holds the one
//! issuer-signed [`VerifiedDirectory`](crate::identity::VerifiedDirectory) and
//! resolves the signer binding structurally via
//! [`VerifiedDirectory::resolve_signer`](crate::identity::VerifiedDirectory::resolve_signer),
//! exactly as the direct push lane
//! ([`RevocationHandler`](crate::lanes::revocation::RevocationHandler)) does. So
//! the signer's pinned key and its pull-endpoint originate from ONE issuer-signed
//! entry and inherit that bundle's body-hash pin, issuer signature, validity
//! window, and anti-rollback machinery; because the client holds the live
//! directory, a bundle rotation is tracked rather than going stale on a detached
//! clone. Verification uses strict monotone epoch ordering / gap
//! detection mirroring
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
use chio_federation::revocation_gossip::RevocationCatchupRequest;
use chio_federation::revocation_gossip::RevocationGossipError;
use chio_federation::revocation_gossip::REVOCATION_CATCHUP_MAX_EPOCHS;
use chio_revocation_oracle::EpochRootVerifier;
use chio_revocation_oracle::SignedEpochRoot;
use iroh::Endpoint;
use iroh::EndpointId;
use iroh_blobs::api::blobs::BlobStatus;
use iroh_blobs::api::downloader::Shuffled;
use iroh_blobs::store::fs::FsStore;
use iroh_blobs::BlobsProtocol;
use iroh_blobs::Hash;
use serde::Deserialize;
use serde::Serialize;

use crate::identity::VerifiedDirectory;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptPhase;
use crate::lanes::revocation::SignerBinding;

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
    /// The manifest mixes more than one `signer_id`. A manifest is bound to a
    /// SINGLE signer so a follower resolves exactly one pinned verifier/authority
    /// for the whole range; a mixed-signer manifest is rejected fail-closed.
    #[error("catch-up manifest mixes signer ids `{first}` and `{other}`")]
    ManifestSignerMismatch {
        /// The first `signer_id` the manifest declared.
        first: String,
        /// A later, conflicting `signer_id`.
        other: String,
    },
    /// A JSON (de)serialization failure.
    #[error("wire codec error: {0}")]
    Codec(String),
}

impl CatchupError {
    /// Stable, bounded metric/log reason for this catch-up failure. Feeds the
    /// `reason` label on `chio_federation_transport_verify_failures_total`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Blob(_) => "blob-transport",
            Self::UnknownSigner(_) => "unknown-signer",
            Self::SignerEndpointMismatch { .. } => "signer-endpoint-mismatch",
            Self::IntegrityMismatch { .. } => "integrity-mismatch",
            Self::BadSignature(_) => "bad-signature",
            Self::Ordering(inner) => match inner {
                RevocationGossipError::CatchupGap { .. } => "catchup-gap",
                _ => "ordering",
            },
            Self::ManifestTooWide { .. } => "manifest-too-wide",
            Self::ManifestSignerMismatch { .. } => "manifest-signer-mismatch",
            Self::Codec(_) => "codec",
        }
    }
}

/// OBSERVE-ONLY: count + log a catch-up rejection alongside the unchanged
/// fail-closed error. An epoch gap also bumps the epoch-gap family (the
/// revocation-freshness health metric that was entirely dark). Never alters the
/// `Err` the caller returns.
fn note_catchup_failure(error: &CatchupError) {
    let reason = error.code();
    crate::metrics::record_verify_failure(crate::metrics::SEAM_CATCHUP, reason);
    if reason == "catchup-gap" {
        crate::metrics::record_catchup_epoch_gap(crate::metrics::CATCHUP_SOURCE_CATCHUP);
    }
    tracing::warn!(
        target: crate::observability::TARGET_CATCHUP,
        seam = crate::metrics::SEAM_CATCHUP,
        reason = reason,
        "revocation catch-up rejected"
    );
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
/// [`Endpoint`] used to build a `Downloader`, and the one issuer-signed
/// [`VerifiedDirectory`] the pinned signer binding is DERIVED from (structural,
/// rotation-tracking), mirroring how
/// [`RevocationHandler`](crate::lanes::revocation::RevocationHandler) consumes it.
#[derive(Debug, Clone)]
pub struct BlobCatchupClient {
    store: FsStore,
    endpoint: Endpoint,
    directory: Arc<VerifiedDirectory>,
}

impl BlobCatchupClient {
    /// Load (or create) the durable blob store at `store_path` and build the
    /// client. The `endpoint` MUST already have the admission gate installed via
    /// `Endpoint::builder(..).hooks(gate)`; catch-up pulls only from the endpoint
    /// its pinned signer binding names.
    ///
    /// `directory` is the one issuer-signed [`VerifiedDirectory`]; the catch-up
    /// signer binding is DERIVED from it via
    /// [`VerifiedDirectory::resolve_signer`](crate::identity::VerifiedDirectory::resolve_signer),
    /// so lane e inherits the same issuer signature, body-hash pin, validity
    /// window, and anti-rollback anchoring as the direct push lane, and tracks a
    /// bundle rotation because it holds the live directory. A free-standing
    /// [`VerifiedSignerDirectory`](crate::lanes::revocation::VerifiedSignerDirectory)
    /// (for example one built by
    /// [`from_bindings`](crate::lanes::revocation::VerifiedSignerDirectory::from_bindings))
    /// is NOT accepted on this production path. The issuer-signed directory is
    /// accepted (positive control, identical scaffolding):
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use chio_federation_transport_iroh::catchup::BlobCatchupClient;
    /// use chio_federation_transport_iroh::identity::VerifiedDirectory;
    ///
    /// async fn accepted(endpoint: iroh::Endpoint, directory: Arc<VerifiedDirectory>) {
    ///     let _ = BlobCatchupClient::load("/tmp/blobs", endpoint, directory).await;
    /// }
    /// ```
    ///
    /// A free-standing signer directory is a type error (only the `signers`
    /// argument differs from the accepted form above):
    ///
    /// ```compile_fail
    /// use std::sync::Arc;
    /// use chio_federation_transport_iroh::catchup::BlobCatchupClient;
    /// use chio_federation_transport_iroh::lanes::revocation::VerifiedSignerDirectory;
    ///
    /// async fn rejected(endpoint: iroh::Endpoint) {
    ///     let free_standing = Arc::new(VerifiedSignerDirectory::default());
    ///     // Type error: `load` requires an `Arc<VerifiedDirectory>`, never an
    ///     // `Arc<VerifiedSignerDirectory>`, so `from_bindings` can no longer be
    ///     // the lane-e production entry point.
    ///     let _ = BlobCatchupClient::load("/tmp/blobs", endpoint, free_standing).await;
    /// }
    /// ```
    pub async fn load(
        store_path: impl AsRef<std::path::Path>,
        endpoint: Endpoint,
        directory: Arc<VerifiedDirectory>,
    ) -> Result<Self, CatchupError> {
        let store = FsStore::load(store_path)
            .await
            .map_err(|error| CatchupError::Blob(error.to_string()))?;
        Ok(Self {
            store,
            endpoint,
            directory,
        })
    }

    /// Build the [`BlobsProtocol`] handler to mount on the AUTHORITY's gated
    /// endpoint: `Router::builder(ep).accept(iroh_blobs::ALPN, client.blobs_protocol())`.
    #[must_use]
    pub fn blobs_protocol(&self) -> BlobsProtocol {
        BlobsProtocol::new(self.store.as_ref(), None)
    }

    /// AUTHORITY side: a [`RevocationRootPublisher`] backed by the SAME [`FsStore`]
    /// this client mounts as its [`BlobsProtocol`] (via
    /// [`blobs_protocol`](Self::blobs_protocol)). Wire it into the revocation lane
    /// handler with
    /// [`RevocationHandler::with_blob_publisher`](crate::lanes::revocation::RevocationHandler::with_blob_publisher)
    /// so every root a catch-up manifest advertises is first WRITTEN to this store and
    /// is therefore actually fetchable over blobs. Sharing one store is exactly what
    /// makes "advertised == stored" hold; do NOT publish into a store other than the
    /// one `blobs_protocol` serves from, or the authority would advertise hashes it
    /// cannot serve.
    #[must_use]
    pub fn publisher(&self) -> RevocationRootPublisher {
        RevocationRootPublisher {
            store: self.store.clone(),
        }
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
    /// 2. resolves the pinned signer from the DERIVED signer directory of the
    ///    issuer-signed [`VerifiedDirectory`] and asserts `authority` is its bound
    ///    endpoint (only pull from the pinned authority),
    /// 3. two-step downloads each blob into the follower store then reads it,
    /// 4. re-checks BLAKE3 integrity and pinned-signer authenticity per blob,
    /// 5. enforces strict monotone contiguous epochs (mirrors `validate_response`).
    ///
    /// All-or-nothing: ANY failure returns `Err` and yields no partial history.
    ///
    /// Uses the generous default client bounds ([`AcceptLimitConfig::default`]); see
    /// [`fetch_range_with_limits`](Self::fetch_range_with_limits) to tune them.
    pub async fn fetch_range(
        &self,
        signer_id: &str,
        authority: EndpointId,
        manifest: &[(u64, Hash)],
    ) -> Result<Vec<SignedEpochRoot>, CatchupError> {
        self.fetch_range_with_limits(
            signer_id,
            authority,
            manifest,
            &AcceptLimitConfig::default(),
        )
        .await
    }

    /// Same as [`fetch_range`](Self::fetch_range), with explicit client-side bounds.
    ///
    /// Client-side liveness defense (mirrors the direct client lanes' `client_bounded`
    /// in [`revocation`](crate::lanes::revocation) and [`bilateral`](crate::lanes::bilateral)):
    /// every peer-dependent await - the per-blob `download` from the authority and the
    /// read-back - is bounded by the corresponding [`AcceptLimitConfig`] phase timeout.
    /// A stalled authority that accepts the pull but never serves (or completes) the
    /// blob no longer hangs the follower's catch-up forever; the walk fails closed to
    /// [`CatchupError::Blob`] and yields no partial history (all-or-nothing), exactly
    /// as any other blob-transport failure does.
    pub async fn fetch_range_with_limits(
        &self,
        signer_id: &str,
        authority: EndpointId,
        manifest: &[(u64, Hash)],
        limits: &AcceptLimitConfig,
    ) -> Result<Vec<SignedEpochRoot>, CatchupError> {
        check_manifest_cap(manifest.len())?;
        let binding = resolve_pinned_signer(&self.directory, signer_id, authority)?;

        let downloader = self.store.downloader(&self.endpoint);
        let mut verified: Vec<SignedEpochRoot> = Vec::with_capacity(manifest.len());
        for (epoch, hash) in manifest {
            // Two-step download (ADAPTER-SPEC 3.4): fetch INTO the follower store
            // from the pinned authority only, then read the bytes back. Both awaits
            // are peer-/store-dependent and bounded fail-closed: a stalled authority
            // cannot hang catch-up (fail-OPEN on liveness) the way an unbounded await
            // would.
            client_bounded(limits, AcceptPhase::AcceptStream, async {
                downloader
                    .download(*hash, Shuffled::new(vec![authority]))
                    .await
            })
            .await?
            .map_err(|error| CatchupError::Blob(error.to_string()))?;
            // Bound the blob BEFORE materializing it: `get_bytes` reads the WHOLE blob
            // into memory, so a valid manifest hash pointing at a huge blob would
            // exhaust follower RAM. The store now holds the downloaded blob; read its
            // completed size (no full read) and reject fail-closed above the per-blob
            // cap so the whole-blob read below never runs.
            let status = client_bounded(limits, AcceptPhase::ReadFrame, async {
                self.store.blobs().status(*hash).await
            })
            .await?
            .map_err(|error| CatchupError::Blob(error.to_string()))?;
            check_blob_size_cap(&status, *hash)?;
            let bytes = client_bounded(limits, AcceptPhase::ReadFrame, async {
                self.store.blobs().get_bytes(*hash).await
            })
            .await?
            .map_err(|error| CatchupError::Blob(error.to_string()))?;
            let signed = decode_and_verify_root(&bytes, *hash, binding)?;
            // Per-entry epoch pin: the manifest epoch must match the signed root.
            if signed.root.epoch != *epoch {
                let error = CatchupError::Ordering(RevocationGossipError::CatchupGap {
                    expected: *epoch,
                    observed: signed.root.epoch,
                });
                note_catchup_failure(&error);
                return Err(error);
            }
            verified.push(signed);
        }
        // Strict monotone contiguous ordering across the run (mirror semantics).
        order_check(&verified)?;
        Ok(verified)
    }

    /// FOLLOWER side: fetch and verify the roots a MANIFEST advertises, resolving the
    /// pinned signer FROM THE MANIFEST (each entry carries its `signer_id`) instead
    /// of requiring the caller to supply it out of band.
    ///
    /// Validates the manifest first (schema, cap, strict monotone contiguity, and the
    /// single-signer binding), then delegates to [`fetch_range`](Self::fetch_range)
    /// with the manifest's bound signer and its `(epoch, hash)` list. An empty
    /// manifest yields no roots (nothing to fetch). Fail-closed and all-or-nothing,
    /// exactly as [`fetch_range`](Self::fetch_range).
    ///
    /// Uses the generous default client bounds ([`AcceptLimitConfig::default`]); see
    /// [`fetch_from_manifest_with_limits`](Self::fetch_from_manifest_with_limits).
    pub async fn fetch_from_manifest(
        &self,
        authority: EndpointId,
        manifest: &RevocationCatchupManifest,
    ) -> Result<Vec<SignedEpochRoot>, CatchupError> {
        self.fetch_from_manifest_with_limits(authority, manifest, &AcceptLimitConfig::default())
            .await
    }

    /// Same as [`fetch_from_manifest`](Self::fetch_from_manifest), with explicit
    /// client-side bounds on every peer-dependent await.
    pub async fn fetch_from_manifest_with_limits(
        &self,
        authority: EndpointId,
        manifest: &RevocationCatchupManifest,
        limits: &AcceptLimitConfig,
    ) -> Result<Vec<SignedEpochRoot>, CatchupError> {
        // Re-validate the manifest fail-closed (schema, cap, monotone contiguity,
        // single-signer) before trusting the signer it names.
        manifest.validate()?;
        let Some(signer_id) = manifest.signer_id() else {
            // An empty manifest advertises nothing; there is no signer to resolve
            // and no blob to fetch.
            return Ok(Vec::new());
        };
        let fetch = manifest.fetch_manifest();
        self.fetch_range_with_limits(signer_id, authority, &fetch, limits)
            .await
    }
}

/// Bound one peer-/store-dependent catch-up await by the phase's timeout, mirroring
/// the direct client lanes' `client_bounded` (revocation / bilateral) and the
/// accept-side [`AcceptLimiter::bounded`](crate::lanes::limits::AcceptLimiter). On
/// timeout this fails closed with [`CatchupError::Blob`] so a stalled authority that
/// never serves (or completes) a blob can no longer hang the follower's catch-up
/// forever. The inner transport `Result` flows through unchanged on success.
async fn client_bounded<T, F>(
    limits: &AcceptLimitConfig,
    phase: AcceptPhase,
    fut: F,
) -> Result<T, CatchupError>
where
    F: std::future::Future<Output = T>,
{
    let bound = limits.phase_timeout(phase);
    match tokio::time::timeout(bound, fut).await {
        Ok(output) => Ok(output),
        Err(_elapsed) => Err(CatchupError::Blob(format!(
            "blob catch-up {phase} exceeded its {}ms bound",
            u64::try_from(bound.as_millis()).unwrap_or(u64::MAX)
        ))),
    }
}

/// The stable content address a follower fetches for `signed`: the BLAKE3 hash of
/// its RFC-8785 canonical JSON.
///
/// This is the SINGLE derivation shared by the authority publish path
/// ([`publish_signed_root`], which stores those exact bytes), the manifest
/// advertised over lane b ([`build_catchup_manifest`]), and the follower's per-blob
/// integrity re-check in [`BlobCatchupClient::fetch_range`]. Because all three use
/// this one formula, the `(epoch -> hash)` manifest a responder advertises is
/// exactly the address the follower downloads and BLAKE3-verifies.
pub fn signed_root_blob_address(signed: &SignedEpochRoot) -> Result<Hash, CatchupError> {
    let bytes = chio_core_types::canonical_json_bytes(signed)
        .map_err(|error| CatchupError::Codec(error.to_string()))?;
    Ok(Hash::new(&bytes))
}

/// AUTHORITY side, store-only: publish one signed root as a content-addressed
/// blob. Separated from [`BlobCatchupClient`] so it is exercisable without an
/// [`Endpoint`]. The blob content is the RFC-8785 canonical JSON of the root, so
/// the address is stable and dedups naturally, and it matches
/// [`signed_root_blob_address`] (the address advertised in a catch-up manifest).
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

/// AUTHORITY-side publisher that writes an advertised catch-up root into the blob
/// [`FsStore`] the authority serves over [`BlobsProtocol`], returning the stored
/// root's content address.
///
/// This is the seam that closes the "advertise a hash the store never held" gap:
/// [`publish_and_build_catchup_manifest`] pushes every root through this publisher
/// BEFORE putting its hash in the manifest, so a follower can always fetch every
/// advertised hash. Construct it from the client that also mounts the matching
/// [`BlobsProtocol`] via [`BlobCatchupClient::publisher`] so both share the SAME
/// store; the address returned is exactly [`signed_root_blob_address`], the hash the
/// follower re-derives and BLAKE3-verifies.
#[derive(Debug, Clone)]
pub struct RevocationRootPublisher {
    store: FsStore,
}

impl RevocationRootPublisher {
    /// Wrap the store the authority serves blobs from. Prefer
    /// [`BlobCatchupClient::publisher`], which guarantees the store matches the
    /// mounted [`BlobsProtocol`].
    #[must_use]
    pub fn new(store: FsStore) -> Self {
        Self { store }
    }

    /// Publish one signed root into the store, returning its content address
    /// (== [`signed_root_blob_address`]). After this resolves the blob is stored, so
    /// the mounted [`BlobsProtocol`] can serve it. Fail-closed: a store write failure
    /// or an address mismatch surfaces as [`CatchupError`] and nothing is advertised.
    pub async fn publish(&self, signed: &SignedEpochRoot) -> Result<Hash, CatchupError> {
        publish_signed_root(&self.store, signed).await
    }
}

/// Schema pin for the lane-b blob catch-up MANIFEST control response.
pub const REVOCATION_CATCHUP_MANIFEST_SCHEMA: &str =
    "chio.federation.transport.iroh.revocation-catchup-manifest.v1";

/// One `(signer_id, epoch, blob content-address)` manifest entry: the address the
/// follower fetches over iroh-blobs (lane e) for that epoch's signed root, plus the
/// opaque `signer_id` whose root it carries.
///
/// The `signer_id` is carried so a follower can resolve the pinned
/// verifier/authority endpoint FROM THE MANIFEST (fed to
/// [`BlobCatchupClient::fetch_from_manifest`]) instead of out of band: the lane-b
/// [`RevocationCatchupResponse`](chio_federation::revocation_gossip::RevocationCatchupResponse)
/// binds the signer per inline frame, but the earlier manifest shape carried only
/// `(epoch, blob_hash)`, so `fetch_range` needed the `signer_id` supplied
/// separately. Carrying it here closes that gap. It is NOT a trust input: the
/// follower still resolves the signer against the issuer-signed directory and
/// pinned-signer-verifies every fetched root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationCatchupManifestEntry {
    /// The opaque signer identity whose signed root this blob carries (copied from
    /// the root's [`RootSignature::signer_id`](chio_revocation_oracle::RootSignature)).
    pub signer_id: String,
    /// The epoch this blob carries the signed root for.
    pub epoch: u64,
    /// Content address of the epoch's signed root (see [`signed_root_blob_address`]).
    pub blob_hash: Hash,
}

/// The blob catch-up MANIFEST a responder advertises over the lane-b control
/// exchange (ADAPTER-SPEC lane e).
///
/// The lane-b [`RevocationCatchupResponse`](chio_federation::revocation_gossip::RevocationCatchupResponse)
/// inlines full signed-root FRAMES, so a large history either never rides blobs or
/// overruns the bounded lane-b frame. This manifest instead carries only the small
/// `(signer_id, epoch, content-address)` list a follower feeds to
/// [`BlobCatchupClient::fetch_from_manifest`], making the bulk blob path
/// discoverable from the control exchange AND self-describing about its signer (the
/// follower no longer needs the `signer_id` out of band). The manifest is bound to a
/// SINGLE signer (`validate` rejects a mixed-signer manifest fail-closed). Integrity
/// / authenticity are NOT asserted by the manifest: the follower still downloads each
/// blob, BLAKE3-re-checks its address, and pinned-signer-verifies the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevocationCatchupManifest {
    /// Schema pin (must equal [`REVOCATION_CATCHUP_MANIFEST_SCHEMA`]).
    pub schema: String,
    /// Echoed from the request's `requester_kernel_id`.
    pub requester_kernel_id: String,
    /// The responder that produced the manifest.
    pub responder_kernel_id: String,
    /// `(epoch, blob content-address)` entries, in strictly increasing contiguous
    /// epoch order (the contiguous suffix the responder retains).
    pub entries: Vec<RevocationCatchupManifestEntry>,
    /// Responder clock stamp.
    pub responded_at_unix_ms: u64,
}

impl RevocationCatchupManifest {
    /// Validate the manifest in isolation: schema, cap, and strict monotone
    /// contiguous epochs (no internal gap), mirroring
    /// [`RevocationCatchupResponse::validate_response`](chio_federation::revocation_gossip::RevocationCatchupResponse::validate_response).
    /// The follower MUST STILL fetch each blob and re-check BLAKE3 integrity and
    /// pinned-signer authenticity; a manifest is only a discovery aid.
    pub fn validate(&self) -> Result<(), CatchupError> {
        if self.schema != REVOCATION_CATCHUP_MANIFEST_SCHEMA {
            return Err(CatchupError::Codec(format!(
                "unexpected catch-up manifest schema: {}",
                self.schema
            )));
        }
        check_manifest_cap(self.entries.len())?;
        let mut prev: Option<u64> = None;
        let mut signer: Option<&str> = None;
        for entry in &self.entries {
            // Bind the manifest to a SINGLE signer: every entry must name the same
            // signer_id, so a follower resolves exactly one pinned verifier/authority
            // endpoint for the whole range (the fetch path resolves one binding). A
            // manifest that mixes signers is rejected fail-closed.
            match signer {
                None => signer = Some(entry.signer_id.as_str()),
                Some(bound) if bound != entry.signer_id.as_str() => {
                    let error = CatchupError::ManifestSignerMismatch {
                        first: bound.to_string(),
                        other: entry.signer_id.clone(),
                    };
                    note_catchup_failure(&error);
                    return Err(error);
                }
                Some(_) => {}
            }
            if let Some(previous) = prev {
                let expected = previous.saturating_add(1);
                if entry.epoch != expected {
                    let error = CatchupError::Ordering(RevocationGossipError::CatchupGap {
                        expected,
                        observed: entry.epoch,
                    });
                    note_catchup_failure(&error);
                    return Err(error);
                }
            }
            prev = Some(entry.epoch);
        }
        Ok(())
    }

    /// The single `signer_id` this manifest is bound to (shared by every entry), or
    /// `None` when the manifest is empty. [`validate`](Self::validate) guarantees
    /// every entry agrees, so this is the signer a follower resolves the pinned
    /// verifier/authority from and feeds to
    /// [`BlobCatchupClient::fetch_range`]. Prefer
    /// [`BlobCatchupClient::fetch_from_manifest`], which threads it automatically.
    #[must_use]
    pub fn signer_id(&self) -> Option<&str> {
        self.entries.first().map(|entry| entry.signer_id.as_str())
    }

    /// The `(epoch, content-address)` list to feed
    /// [`BlobCatchupClient::fetch_range`], consuming the manifest.
    #[must_use]
    pub fn into_fetch_manifest(self) -> Vec<(u64, Hash)> {
        self.entries
            .into_iter()
            .map(|entry| (entry.epoch, entry.blob_hash))
            .collect()
    }

    /// Borrowing form of [`into_fetch_manifest`](Self::into_fetch_manifest).
    #[must_use]
    pub fn fetch_manifest(&self) -> Vec<(u64, Hash)> {
        self.entries
            .iter()
            .map(|entry| (entry.epoch, entry.blob_hash))
            .collect()
    }
}

/// Walk the SAME contiguous suffix
/// [`respond_to_catchup`](chio_federation::revocation_gossip::respond_to_catchup)
/// serves: skip pre-history epochs, stop at the first internal gap, and never
/// fabricate a root (a missing epoch simply ends the run). Shared by the address-only
/// manifest builder ([`build_catchup_manifest`]) and the publish-then-advertise
/// builder ([`publish_and_build_catchup_manifest`]) so both advertise exactly the
/// same retained suffix.
fn catchup_suffix<H: RevocationCatchupHistory>(
    request: &RevocationCatchupRequest,
    history: &H,
) -> Vec<SignedEpochRoot> {
    let mut roots: Vec<SignedEpochRoot> = Vec::new();
    let mut started = false;
    for epoch in request.from_epoch..=request.to_epoch {
        match history.signed_root_at(epoch) {
            Some(signed) => {
                roots.push(signed);
                started = true;
            }
            None => {
                if started {
                    // Gap inside the retained history: stop so the manifest's
                    // monotone-contiguous invariant holds (never fabricate).
                    break;
                }
                // Pre-history skip: keep scanning for the retained suffix.
            }
        }
    }
    roots
}

/// AUTHORITY side: build the `(epoch -> blob content-address)` MANIFEST for a
/// catch-up `request`, to advertise over the lane-b control response so a follower
/// can fetch a large history over blobs (lane e) instead of inlining full
/// signed-root frames.
///
/// Walks the SAME contiguous suffix
/// [`respond_to_catchup`](chio_federation::revocation_gossip::respond_to_catchup)
/// serves: it skips pre-history epochs, stops at the first internal gap, and never
/// fabricates a root (a missing epoch simply ends the run). Each entry's address is
/// derived deterministically via [`signed_root_blob_address`], the exact address
/// the follower re-derives and BLAKE3-verifies in
/// [`BlobCatchupClient::fetch_range`]. The requested range is capped by
/// [`RevocationCatchupRequest::validate_envelope`], so the manifest is bounded.
///
/// # Address-only: does NOT publish the blobs
///
/// This computes each entry's deterministic BLAKE3 address but does NOT write the
/// root into any blob store. Advertising an address the authority's mounted
/// [`BlobsProtocol`] never stored makes a follower fetch a hash that cannot be served
/// and catch-up fails even though inline catch-up would have worked. Any caller that
/// ADVERTISES this manifest over the wire MUST therefore have already published every
/// advertised root into the same store the `BlobsProtocol` serves from. Prefer
/// [`publish_and_build_catchup_manifest`], which publishes each root as it advertises
/// it so every advertised hash is guaranteed fetchable; the revocation lane handler
/// uses that path when a blob publisher is wired and falls back to inline catch-up
/// when it is not, so it never advertises a hash it cannot serve.
///
/// # Errors
/// [`CatchupError::Ordering`] if the request range is invalid, else
/// [`CatchupError::Codec`] on a canonical-JSON failure.
pub fn build_catchup_manifest<H: RevocationCatchupHistory>(
    request: &RevocationCatchupRequest,
    responder_kernel_id: &str,
    history: &H,
    responded_at_unix_ms: u64,
) -> Result<RevocationCatchupManifest, CatchupError> {
    request.validate_envelope()?;
    let mut entries: Vec<RevocationCatchupManifestEntry> = Vec::new();
    for signed in catchup_suffix(request, history) {
        entries.push(RevocationCatchupManifestEntry {
            signer_id: signed.signature.signer_id.clone(),
            epoch: signed.root.epoch,
            blob_hash: signed_root_blob_address(&signed)?,
        });
    }
    let manifest = RevocationCatchupManifest {
        schema: REVOCATION_CATCHUP_MANIFEST_SCHEMA.to_string(),
        requester_kernel_id: request.requester_kernel_id.clone(),
        responder_kernel_id: responder_kernel_id.to_string(),
        entries,
        responded_at_unix_ms,
    };
    manifest.validate()?;
    Ok(manifest)
}

/// AUTHORITY side: build the catch-up MANIFEST AND publish every advertised root into
/// the blob store, so every hash the manifest advertises is guaranteed fetchable over
/// iroh-blobs (lane e).
///
/// This is the SAFE counterpart to [`build_catchup_manifest`]: it walks the SAME
/// contiguous suffix but writes each root through `publisher` BEFORE putting its hash
/// in the manifest. Because [`RevocationRootPublisher::publish`] stores the exact
/// canonical bytes whose BLAKE3 is [`signed_root_blob_address`], the advertised
/// address is both stable and confirmed-stored: a follower can never be pointed at a
/// hash the authority's [`BlobsProtocol`] cannot serve. The `publisher` MUST wrap the
/// SAME store the authority mounts as its [`BlobsProtocol`] (use
/// [`BlobCatchupClient::publisher`]).
///
/// Fail-closed: if any publish fails the whole manifest fails (no partial or
/// unfetchable advertisement).
///
/// # Errors
/// [`CatchupError::Ordering`] if the request range is invalid,
/// [`CatchupError::Blob`] if a root cannot be written to the store, else
/// [`CatchupError::Codec`] on a canonical-JSON failure.
pub async fn publish_and_build_catchup_manifest<H: RevocationCatchupHistory>(
    request: &RevocationCatchupRequest,
    responder_kernel_id: &str,
    history: &H,
    responded_at_unix_ms: u64,
    publisher: &RevocationRootPublisher,
) -> Result<RevocationCatchupManifest, CatchupError> {
    request.validate_envelope()?;
    let mut entries: Vec<RevocationCatchupManifestEntry> = Vec::new();
    for signed in catchup_suffix(request, history) {
        // Publish BEFORE advertising: the returned address is the exact hash the
        // follower will fetch, and the blob is now stored, so the BlobsProtocol can
        // serve it. This is the invariant that closes the "advertise a hash the store
        // never held" gap. `publish` re-checks the stored hash equals the deterministic
        // address, so the advertised hash is confirmed-stored, not merely computed.
        let blob_hash = publisher.publish(&signed).await?;
        entries.push(RevocationCatchupManifestEntry {
            signer_id: signed.signature.signer_id.clone(),
            epoch: signed.root.epoch,
            blob_hash,
        });
    }
    let manifest = RevocationCatchupManifest {
        schema: REVOCATION_CATCHUP_MANIFEST_SCHEMA.to_string(),
        requester_kernel_id: request.requester_kernel_id.clone(),
        responder_kernel_id: responder_kernel_id.to_string(),
        entries,
        responded_at_unix_ms,
    };
    manifest.validate()?;
    Ok(manifest)
}

/// Resolve `signer_id` to its pinned binding from the DERIVED signer directory of
/// the issuer-signed [`VerifiedDirectory`], asserting `authority` is the endpoint
/// the binding names (only ever pull a signer's roots from its pinned authority).
///
/// This mirrors the direct push lane
/// ([`RevocationHandler::verify_batch`](crate::lanes::revocation::RevocationHandler)):
/// the binding is structural (issuer-signed + anti-rollback), never a free-standing
/// map, and tracks a bundle rotation because the directory is the live one. Both
/// checks are fail-closed.
fn resolve_pinned_signer<'a>(
    directory: &'a VerifiedDirectory,
    signer_id: &str,
    authority: EndpointId,
) -> Result<&'a SignerBinding, CatchupError> {
    // OBSERVE-ONLY tail: count a failure alongside the unchanged fail-closed
    // resolution (the inner fn's `Err` is returned verbatim).
    let result = resolve_pinned_signer_inner(directory, signer_id, authority);
    if let Err(error) = &result {
        note_catchup_failure(error);
    }
    result
}

fn resolve_pinned_signer_inner<'a>(
    directory: &'a VerifiedDirectory,
    signer_id: &str,
    authority: EndpointId,
) -> Result<&'a SignerBinding, CatchupError> {
    let binding = directory
        .resolve_signer(signer_id)
        .ok_or_else(|| CatchupError::UnknownSigner(signer_id.to_string()))?;
    if binding.endpoint != authority {
        return Err(CatchupError::SignerEndpointMismatch {
            signer_id: signer_id.to_string(),
            endpoint: authority.fmt_short().to_string(),
        });
    }
    Ok(binding)
}

/// Reject an over-cap catch-up manifest fail-closed
/// ([`REVOCATION_CATCHUP_MAX_EPOCHS`]).
fn check_manifest_cap(len: usize) -> Result<(), CatchupError> {
    let requested = len as u64;
    if requested > REVOCATION_CATCHUP_MAX_EPOCHS {
        let error = CatchupError::ManifestTooWide {
            requested,
            max: REVOCATION_CATCHUP_MAX_EPOCHS,
        };
        note_catchup_failure(&error);
        return Err(error);
    }
    Ok(())
}

/// Hard per-blob byte cap for catch-up. A single [`SignedEpochRoot`] is tiny (an
/// epoch, a Merkle root, a signer id, and a signature), so a blob larger than this is
/// treated as a memory-exhaustion attempt and rejected fail-closed BEFORE it is read
/// into memory. The cap is generous headroom over any legitimate root and mirrors the
/// order of magnitude of the relay peer directory's per-peer `maxCatchupBytes`.
///
/// Content-address integrity (BLAKE3) constrains WHAT the bytes are, never HOW MANY:
/// a compromised or admitted authority can advertise a valid manifest hash for an
/// arbitrarily large blob, so the manifest entry-count cap alone does not bound the
/// bytes a follower loads. This is the byte-size backstop.
const MAX_CATCHUP_BLOB_SIZE: u64 = 1_048_576;

/// Reject a downloaded catch-up blob whose stored size exceeds
/// [`MAX_CATCHUP_BLOB_SIZE`] BEFORE it is materialized into memory by `get_bytes`.
///
/// The two-step download writes the blob into the follower store; its completed-blob
/// [`BlobStatus::Complete`] carries the size WITHOUT a full read, so this is the
/// "check the size iroh-blobs exposes before the full read" path. A non-`Complete`
/// status after a download the transport reported as successful is itself anomalous
/// and fails closed. Every rejection is [`CatchupError::Blob`], so it folds into the
/// same all-or-nothing catch-up failure as any other blob-transport error.
fn check_blob_size_cap(status: &BlobStatus, hash: Hash) -> Result<(), CatchupError> {
    let size = match status {
        BlobStatus::Complete { size } => *size,
        _ => {
            let error = CatchupError::Blob(format!(
                "catch-up blob {hash} is not completely stored after download"
            ));
            note_catchup_failure(&error);
            return Err(error);
        }
    };
    if size > MAX_CATCHUP_BLOB_SIZE {
        let error = CatchupError::Blob(format!(
            "catch-up blob {hash} of {size} bytes exceeds the \
             {MAX_CATCHUP_BLOB_SIZE}-byte per-blob cap"
        ));
        note_catchup_failure(&error);
        return Err(error);
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
    // OBSERVE-ONLY tail: count integrity/authenticity failures alongside the
    // unchanged fail-closed verification (the inner `Err` is returned verbatim).
    let result = decode_and_verify_root_inner(bytes, expected_hash, binding);
    if let Err(error) = &result {
        note_catchup_failure(error);
    }
    result
}

fn decode_and_verify_root_inner(
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
                let error = CatchupError::Ordering(RevocationGossipError::CatchupGap {
                    expected,
                    observed: signed.root.epoch,
                });
                note_catchup_failure(&error);
                return Err(error);
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
    fn epoch_gap_bumps_gap_counter_and_is_still_rejected() {
        // OBSERVE-ONLY proof: a dropped epoch still fails closed AND bumps both the
        // verify-failure and the dedicated epoch-gap family (the revocation-
        // freshness health signal that was entirely dark before).
        let oracle = signer("oracle-a", SEED_A);
        let run = vec![
            signed_root(&oracle, 1),
            signed_root(&oracle, 2),
            signed_root(&oracle, 4),
        ];
        let before_gap =
            crate::metrics::catchup_epoch_gap_total(crate::metrics::CATCHUP_SOURCE_CATCHUP);
        let before_verify =
            crate::metrics::verify_failures_total(crate::metrics::SEAM_CATCHUP, "catchup-gap");

        let err = order_check(&run).expect_err("dropped epoch still fails closed");
        assert!(matches!(
            err,
            CatchupError::Ordering(RevocationGossipError::CatchupGap { .. })
        ));
        assert!(
            crate::metrics::catchup_epoch_gap_total(crate::metrics::CATCHUP_SOURCE_CATCHUP)
                > before_gap,
            "the epoch gap must be counted (observe-only)"
        );
        assert!(
            crate::metrics::verify_failures_total(crate::metrics::SEAM_CATCHUP, "catchup-gap")
                > before_verify
        );
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
    fn over_cap_blob_size_is_rejected_before_read() {
        let hash = Hash::new(b"any blob");
        // A blob just over the cap is rejected fail-closed (memory-exhaustion guard).
        let over = BlobStatus::Complete {
            size: MAX_CATCHUP_BLOB_SIZE + 1,
        };
        let err = check_blob_size_cap(&over, hash)
            .expect_err("an over-cap blob must be rejected before it is read into memory");
        assert!(matches!(err, CatchupError::Blob(_)));
        assert_eq!(err.code(), "blob-transport");
        // A blob exactly at the cap is accepted (inclusive).
        assert!(check_blob_size_cap(
            &BlobStatus::Complete {
                size: MAX_CATCHUP_BLOB_SIZE
            },
            hash
        )
        .is_ok());
        // A non-Complete status after a "successful" download is itself fail-closed.
        assert!(check_blob_size_cap(&BlobStatus::NotFound, hash).is_err());
        assert!(check_blob_size_cap(&BlobStatus::Partial { size: Some(10) }, hash).is_err());
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

    // -- Derived-binding tests: the lane-e production path resolves its signer
    // -- from the issuer-signed VerifiedDirectory, mirroring the direct push lane.

    use crate::identity::revocation_signer_endorsement_preimage;
    use crate::identity::transport_endorsement_preimage;
    use crate::identity::RevocationSignerEntry;
    use crate::identity::TransportDirectoryBundleBody;
    use crate::identity::TransportDirectoryBundleDocument;
    use crate::identity::TransportDirectoryBundleTrust;
    use crate::identity::TransportDirectoryDocument;
    use crate::identity::TransportDirectoryEntry;
    use crate::identity::TrustedTransportDirectoryIssuer;
    use crate::identity::VerifiedDirectory;
    use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
    use chio_core_types::sha256_hex;
    use chio_core_types::Keypair;

    const BUNDLE_NOW: u64 = 2_000_000;

    /// Build an issuer-signed, load-time-verified directory admitting one operator
    /// at `transport_seed` that declares oracle signer `signer_id` (key `seed`).
    /// The derived projection binds that signer to the operator's endpoint exactly
    /// as production does, so the catch-up client resolves it structurally.
    fn issuer_signed_directory(
        transport_seed: u8,
        signer_id: &str,
        seed: &str,
    ) -> Arc<VerifiedDirectory> {
        let issuer = Keypair::from_seed(&[240; 32]);
        let passport = Keypair::from_seed(&[7; 32]);
        let transport = endpoint_from_seed(transport_seed);
        let oracle = signer(signer_id, seed);
        let oracle_public_key = oracle.public_key();
        let entry = TransportDirectoryEntry {
            kernel_id: "did:chio:authority".to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport.sign(&transport_endorsement_preimage(
                "did:chio:authority",
                &transport,
            )),
            revocation_signers: vec![RevocationSignerEntry {
                signer_id: signer_id.to_string(),
                oracle_public_key: oracle_public_key.clone(),
                oracle_endorsement: passport.sign(&revocation_signer_endorsement_preimage(
                    "did:chio:authority",
                    signer_id,
                    &oracle_public_key,
                )),
            }],
            removed: false,
        };
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:local".to_string(),
            peers: vec![entry],
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version: 1,
            previous_version_sha256: None,
            issued_at_unix_ms: BUNDLE_NOW - 1,
            expires_at_unix_ms: BUNDLE_NOW + 1,
        };
        let (signature, _) = issuer.sign_canonical(&body).unwrap();
        let bundle = TransportDirectoryBundleDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            body,
            directory,
            signature,
        };
        let trust = TransportDirectoryBundleTrust {
            issuers: vec![TrustedTransportDirectoryIssuer {
                issuer: "did:chio:issuer".to_string(),
                key_id: "issuer-key-1".to_string(),
                public_key: issuer.public_key(),
            }],
            version_floor: 0,
            expected_previous_version_sha256: None,
            now_unix_ms: BUNDLE_NOW,
        };
        Arc::new(bundle.verify_bundle(&trust).expect("bundle verifies"))
    }

    #[test]
    fn derived_binding_resolves_and_verifies_a_root() {
        // The production lane-e resolution: the pinned signer is DERIVED from the
        // issuer-signed directory (not a free-standing map), and a real root signed
        // by that oracle verifies through the derived binding.
        let authority = endpoint_from_seed(41);
        let directory = issuer_signed_directory(41, "oracle-a", SEED_A);

        let binding = resolve_pinned_signer(&directory, "oracle-a", authority)
            .expect("oracle-a resolves through the derived projection");
        assert_eq!(binding.endpoint, authority);

        let oracle = signer("oracle-a", SEED_A);
        let (bytes, hash) = blob_of(&signed_root(&oracle, 5));
        let got = decode_and_verify_root(&bytes, hash, binding)
            .expect("root verifies through the derived binding");
        assert_eq!(got.root.epoch, 5);
    }

    #[test]
    fn derived_binding_rejects_unknown_signer_and_wrong_authority() {
        let authority = endpoint_from_seed(41);
        let directory = issuer_signed_directory(41, "oracle-a", SEED_A);

        // Unknown signer id: fail-closed.
        let err = resolve_pinned_signer(&directory, "oracle-z", authority)
            .expect_err("unknown signer must fail closed");
        assert!(matches!(err, CatchupError::UnknownSigner(ref id) if id == "oracle-z"));

        // Known signer, but pulled from the WRONG authority endpoint: fail-closed
        // (only pull a signer's roots from its pinned authority).
        let wrong = endpoint_from_seed(99);
        let err = resolve_pinned_signer(&directory, "oracle-a", wrong)
            .expect_err("wrong authority endpoint must fail closed");
        assert!(matches!(err, CatchupError::SignerEndpointMismatch { .. }));
    }

    // -- Client-side liveness bound (adversarial: a stalled authority) --

    #[tokio::test(start_paused = true)]
    async fn blob_transfer_that_never_completes_fails_closed_at_the_bound() {
        // A never-completing peer-dependent await (a stalled authority that accepts
        // the pull but never serves the blob) must fail CLOSED at the client bound,
        // not hang catch-up forever. Drive client_bounded - the same helper
        // fetch_range_with_limits wraps every download / read-back in - with a future
        // that never resolves under a tight bound.
        let limits = AcceptLimitConfig {
            accept_stream_timeout: std::time::Duration::from_millis(50),
            ..AcceptLimitConfig::default()
        };
        let error = client_bounded(&limits, AcceptPhase::AcceptStream, async {
            // Models downloader.download(..) from an authority that never serves.
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        })
        .await
        .expect_err("a never-completing download must be bounded out fail-closed");
        assert!(
            matches!(error, CatchupError::Blob(_)),
            "a stalled transfer must fail closed to Blob, got {error:?}"
        );
        assert_eq!(error.code(), "blob-transport");
    }

    #[test]
    fn manifest_advertises_the_blob_addresses_the_follower_will_fetch() {
        // The manifest a responder advertises carries exactly the (epoch, address)
        // pairs a follower feeds to fetch_range, and each address is the one the
        // follower re-derives and BLAKE3-verifies per blob (single-sourced).
        let oracle = signer("oracle-a", SEED_A);
        let roots = vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 6),
            signed_root(&oracle, 7),
        ];
        let history = BlobBackedHistory::from_verified(roots.clone());
        let request =
            RevocationCatchupRequest::new("did:chio:follower", 5, 7, 1_700_000_000_000).unwrap();

        let manifest =
            build_catchup_manifest(&request, "did:chio:authority", &history, 1_700_000_000_500)
                .expect("manifest builds");
        manifest.validate().expect("manifest is well-formed");
        assert_eq!(manifest.entries.len(), 3);
        assert_eq!(manifest.requester_kernel_id, "did:chio:follower");
        assert_eq!(manifest.responder_kernel_id, "did:chio:authority");
        for (entry, root) in manifest.entries.iter().zip(roots.iter()) {
            assert_eq!(entry.epoch, root.root.epoch);
            let (_bytes, expected) = blob_of(root);
            assert_eq!(entry.blob_hash, expected);
            assert_eq!(signed_root_blob_address(root).unwrap(), expected);
        }
        // The fetch manifest feeds fetch_range directly.
        let fetch = manifest.fetch_manifest();
        let expected: Vec<(u64, Hash)> = roots
            .iter()
            .map(|root| (root.root.epoch, blob_of(root).1))
            .collect();
        assert_eq!(fetch, expected);
    }

    #[test]
    fn manifest_serves_the_contiguous_suffix_and_stops_at_a_gap() {
        // Missing epoch 6 (history has 5 and 7): requesting 5..=7 yields only epoch
        // 5, stopping at the first internal gap (never fabricating).
        let oracle = signer("oracle-a", SEED_A);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 7),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 5, 7, 1).unwrap();
        let manifest = build_catchup_manifest(&request, "did:chio:authority", &history, 2).unwrap();
        assert_eq!(
            manifest.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
            vec![5]
        );
    }

    #[test]
    fn manifest_skips_pre_history_and_serves_the_retained_suffix() {
        // History starts at epoch 6: requesting 4..=7 skips the pre-history epochs
        // 4,5 and serves the retained suffix 6,7.
        let oracle = signer("oracle-a", SEED_A);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 6),
            signed_root(&oracle, 7),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 4, 7, 1).unwrap();
        let manifest = build_catchup_manifest(&request, "did:chio:authority", &history, 2).unwrap();
        assert_eq!(
            manifest.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
            vec![6, 7]
        );
    }

    #[test]
    fn manifest_json_round_trips_and_validate_rejects_a_gap() {
        let oracle = signer("oracle-a", SEED_A);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 1),
            signed_root(&oracle, 2),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 1, 2, 1).unwrap();
        let manifest = build_catchup_manifest(&request, "did:chio:authority", &history, 2).unwrap();

        // The manifest rides the lane-b JSON control response: round-trip it.
        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: RevocationCatchupManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, manifest);

        // A hand-built manifest with an internal epoch gap fails validate fail-closed.
        let mut broken = manifest;
        broken.entries[1].epoch = 5; // 1 then 5: a gap
        assert!(matches!(
            broken.validate(),
            Err(CatchupError::Ordering(
                RevocationGossipError::CatchupGap { .. }
            ))
        ));
    }

    #[test]
    fn manifest_carries_signer_id_and_binds_to_one_signer() {
        // Each entry carries the signer_id of the root it addresses (copied from the
        // signed root's signature), so a follower resolves the pinned verifier FROM
        // the manifest instead of out of band, and the manifest exposes its single
        // bound signer via `signer_id()`. The signer id is on the wire.
        let oracle = signer("oracle-a", SEED_A);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 6),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 5, 6, 1).unwrap();
        let manifest = build_catchup_manifest(&request, "did:chio:authority", &history, 2).unwrap();

        for entry in &manifest.entries {
            assert_eq!(entry.signer_id, "oracle-a");
        }
        assert_eq!(manifest.signer_id(), Some("oracle-a"));

        // The signer id rides the lane-b JSON control response (camelCase `signerId`).
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(
            json.contains("signerId") && json.contains("oracle-a"),
            "the manifest wire form must carry the signer id: {json}"
        );

        // An empty manifest is bound to no signer.
        let empty = RevocationCatchupManifest {
            schema: REVOCATION_CATCHUP_MANIFEST_SCHEMA.to_string(),
            requester_kernel_id: "did:chio:follower".to_string(),
            responder_kernel_id: "did:chio:authority".to_string(),
            entries: Vec::new(),
            responded_at_unix_ms: 2,
        };
        empty.validate().expect("an empty manifest is well-formed");
        assert_eq!(empty.signer_id(), None);
    }

    #[test]
    fn manifest_mixing_signer_ids_is_rejected_fail_closed() {
        // A contiguous range whose roots are signed by DIFFERENT signers cannot ride
        // the single-signer fetch path (one resolved verifier/authority), so the
        // manifest is rejected fail-closed at build time by its own `validate`.
        let oracle_a = signer("oracle-a", SEED_A);
        let oracle_b = signer("oracle-b", SEED_B);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle_a, 5),
            signed_root(&oracle_b, 6),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 5, 6, 1).unwrap();

        let err = build_catchup_manifest(&request, "did:chio:authority", &history, 2)
            .expect_err("a mixed-signer manifest must be rejected");
        match err {
            CatchupError::ManifestSignerMismatch { first, other } => {
                assert_eq!(first, "oracle-a");
                assert_eq!(other, "oracle-b");
            }
            other => panic!("expected ManifestSignerMismatch, got {other:?}"),
        }
        assert_eq!(
            CatchupError::ManifestSignerMismatch {
                first: "oracle-a".to_string(),
                other: "oracle-b".to_string(),
            }
            .code(),
            "manifest-signer-mismatch"
        );
    }

    /// The bytes + stable content address a follower would fetch, using a temp
    /// FsStore whose path is unique to this process + timestamp.
    async fn temp_fs_store(tag: &str) -> (FsStore, std::path::PathBuf) {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "chio-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let store = FsStore::load(&dir).await.expect("load fs store");
        (store, dir)
    }

    #[tokio::test]
    async fn publish_and_build_manifest_publishes_every_advertised_root() {
        // A manifest built for a history whose roots are not yet in the store must
        // still be fetchable. The publishing builder writes each advertised root into
        // the SAME FsStore the BlobsProtocol serves from, so every advertised hash is
        // confirmed-stored rather than a deterministic address the store never held -
        // an address BlobsProtocol cannot serve, which would fail catch-up.
        let (store, dir) = temp_fs_store("catchup-publish-manifest").await;
        let publisher = RevocationRootPublisher::new(store.clone());

        let oracle = signer("oracle-a", SEED_A);
        // History holds epochs 5..=7 but nothing is in the store yet.
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 6),
            signed_root(&oracle, 7),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 5, 7, 1).unwrap();

        // BEFORE publishing, the deterministic addresses the address-only builder
        // computes are NOT stored: advertising them here would be unfetchable.
        let address_only =
            build_catchup_manifest(&request, "did:chio:authority", &history, 2).unwrap();
        for entry in &address_only.entries {
            assert!(
                !matches!(
                    store.blobs().status(entry.blob_hash).await.unwrap(),
                    BlobStatus::Complete { .. }
                ),
                "address-only build must NOT have stored epoch {}",
                entry.epoch
            );
        }

        // The publishing builder advertises the SAME addresses AND stores each one.
        let manifest = publish_and_build_catchup_manifest(
            &request,
            "did:chio:authority",
            &history,
            2,
            &publisher,
        )
        .await
        .expect("publish-then-build succeeds");
        manifest.validate().expect("manifest is well-formed");
        assert_eq!(
            manifest.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
            vec![5, 6, 7]
        );
        assert_eq!(
            manifest.entries, address_only.entries,
            "publishing must advertise exactly the same addresses as the address-only builder"
        );

        // Every advertised hash is now Complete in the store the BlobsProtocol serves,
        // and the stored bytes hash back to exactly the advertised address: no
        // advertised hash can be unfetchable.
        for entry in &manifest.entries {
            match store.blobs().status(entry.blob_hash).await.unwrap() {
                BlobStatus::Complete { .. } => {}
                other => {
                    panic!(
                        "advertised epoch {} hash is not stored: {other:?}",
                        entry.epoch
                    )
                }
            }
            let bytes = store.blobs().get_bytes(entry.blob_hash).await.unwrap();
            assert_eq!(Hash::new(&bytes), entry.blob_hash);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn publish_manifest_stops_at_gap_and_only_publishes_served_roots() {
        // History has 5 and 7 (gap at 6). Requesting 5..=7 serves only epoch 5, and
        // ONLY epoch 5 is published: the builder never stores (or advertises) a root
        // past the first internal gap, so the "advertised == stored" set stays the
        // served contiguous suffix.
        let (store, dir) = temp_fs_store("catchup-publish-gap").await;
        let publisher = RevocationRootPublisher::new(store.clone());

        let oracle = signer("oracle-a", SEED_A);
        let history = BlobBackedHistory::from_verified(vec![
            signed_root(&oracle, 5),
            signed_root(&oracle, 7),
        ]);
        let request = RevocationCatchupRequest::new("did:chio:follower", 5, 7, 1).unwrap();
        let manifest = publish_and_build_catchup_manifest(
            &request,
            "did:chio:authority",
            &history,
            2,
            &publisher,
        )
        .await
        .unwrap();
        assert_eq!(
            manifest.entries.iter().map(|e| e.epoch).collect::<Vec<_>>(),
            vec![5]
        );
        // The un-advertised epoch 7 was NOT published (never store/advertise past a gap).
        let addr7 = signed_root_blob_address(&signed_root(&oracle, 7)).unwrap();
        assert!(
            !matches!(
                store.blobs().status(addr7).await.unwrap(),
                BlobStatus::Complete { .. }
            ),
            "a root past the gap must not be published"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
