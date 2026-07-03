//! Lane b: revocation epoch roots over a direct per-peer QUIC stream.
//! ADAPTER-SPEC section 4 row (b) + IROH-LANES-BLUEPRINT "LANE B".
//!
//! This lane carries two message kinds over one direct, admission-gated,
//! per-peer QUIC stream (`open_bi` / `accept_bi`):
//!
//! - a pushed [`RevocationGossipBatch`] of signed epoch roots, and
//! - a [`RevocationCatchupRequest`] whose [`RevocationCatchupResponse`] rides the
//!   same stream (the CONTROL envelope for the catch-up lane; the bulk root bytes
//!   ride iroh-blobs in [`crate::catchup`], ADAPTER-SPEC 4 lane e).
//!
//! ## Authenticity model (different from lane a)
//!
//! Revocation has NO `authenticated_sender_kernel_id` seam. The receiver verifies
//! each [`chio_revocation_oracle::SignedEpochRoot`] against a PINNED signer key it
//! already holds (revocation carries no directory in its wire types). The
//! transport contributes origin + ordering + reliability only (ADAPTER-SPEC 4
//! row b; blueprint B.3).
//!
//! ## The net-new binding this lane introduces
//!
//! Revocation wire types carry only an opaque `signer_id`
//! ([`revocation_gossip.rs:65`](chio_federation::revocation_gossip)); there is no
//! endpoint or public key on the wire. So this lane needs a
//! [`VerifiedSignerDirectory`] mapping `signer_id -> (EndpointId, verifying-key)`.
//! In production that directory is a DERIVED PROJECTION of the one issuer-signed
//! [`VerifiedDirectory`]: each [`crate::identity::RevocationSignerEntry`] binds
//! `signer_id -> oracle_public_key` to an operator via a domain-separated passport
//! endorsement, and the transport `EndpointId` that may originate the signer's
//! roots IS that operator's `transport_endpoint_id`. So the origin pin is
//! STRUCTURAL: signer and endpoint come from one issuer-signed entry, inheriting
//! the body-hash pin, issuer signature, validity window, and rollback machinery.
//!
//! At accept time the handler (1) REJECTS at the admission gate any transport
//! `EndpointId` not bound to an admitted kernel (defense in depth), (2) asserts
//! each frame's `signer_id` is pinned to the SAME authenticated `EndpointId`
//! (transport origin pin, now structurally guaranteed by the derived directory),
//! and (3) signature-verifies the [`SignedEpochRoot`] against the bound verifying
//! key (authenticity). All three are mandatory and independent (ADAPTER-SPEC 5
//! "feeds the verifier, not replaces it"; blueprint B.4).

use std::collections::HashMap;
use std::sync::Arc;

use chio_federation::revocation_gossip::respond_to_catchup;
use chio_federation::revocation_gossip::RevocationCatchupHistory;
use chio_federation::revocation_gossip::RevocationCatchupRequest;
use chio_federation::revocation_gossip::RevocationCatchupResponse;
use chio_federation::revocation_gossip::RevocationGossipBatch;
use chio_federation::revocation_gossip::RevocationGossipError;
use chio_revocation_oracle::Ed25519RootVerifier;
use chio_revocation_oracle::EpochRootVerifier;
use chio_revocation_oracle::SignedEpochRoot;
use iroh::endpoint::Connection;
use iroh::endpoint::RecvStream;
use iroh::endpoint::SendStream;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::Endpoint;
use iroh::EndpointId;
use serde::Deserialize;
use serde::Serialize;

use crate::identity::VerifiedDirectory;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptLimitError;
use crate::lanes::limits::AcceptLimiter;
use crate::lanes::limits::AcceptPhase;
use crate::lanes::limits::LANE_RESET_CLOSE_CODE;

/// ALPN for the revocation-root lane. Distinct, versioned, mounted on its own
/// `Router` accept (blueprint B.2).
pub const ALPN_REVOCATION_ROOT: &[u8] = b"chio/federation/revocation-root/1";

/// Hard cap on a single length-delimited lane frame. Revocation batches and
/// catch-up responses are small (bounded by
/// [`chio_federation::revocation_gossip::REVOCATION_CATCHUP_MAX_EPOCHS`]); this
/// bounds a hostile peer's per-message allocation fail-closed.
pub const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;

/// A single pinned signer binding: an opaque `signer_id` cross-linked to the
/// transport `EndpointId` that is allowed to originate its roots AND to the
/// pinned verifying key that authenticates those roots.
///
/// The verifier already carries the `signer_id` and the public key; the
/// `endpoint` is the transport-origin pin the wire types lack.
#[derive(Debug, Clone)]
pub struct SignerBinding {
    /// Transport `EndpointId` allowed to originate this signer's roots.
    pub endpoint: EndpointId,
    /// Pinned verify-only counterpart of the signer's oracle key. Holds no
    /// private material, so it can never forge a root.
    pub verifier: Ed25519RootVerifier,
}

/// The `signer_id -> (EndpointId, verifying-key)` directory this lane requires
/// (blueprint B.4), keyed on the opaque revocation `signer_id` since revocation
/// wire types carry no endpoint or public key.
///
/// In production this is a DERIVED PROJECTION of the issuer-signed
/// [`VerifiedDirectory`], built by
/// [`TransportDirectoryBundleDocument::verify_bundle`](crate::identity::TransportDirectoryBundleDocument::verify_bundle)
/// and read back via
/// [`VerifiedDirectory::signer_directory`](crate::identity::VerifiedDirectory::signer_directory).
/// The duplicate-`signer_id` and `signer_id`-vs-key consistency rules are enforced
/// during bundle verification (consistent by construction, since the verifier is
/// built from the same `signer_id`). The `from_bindings` constructor is
/// crate-internal (test / explicit construction only) and re-checks both rules
/// fail-closed; production directories come solely from `verify_bundle`.
#[derive(Debug, Clone, Default)]
pub struct VerifiedSignerDirectory {
    by_signer: HashMap<String, SignerBinding>,
}

impl VerifiedSignerDirectory {
    /// Build a pinned signer directory from `(signer_id, binding)` pairs.
    ///
    /// Rejects a duplicate `signer_id` fail-closed and rejects a binding whose
    /// pinned verifier `signer_id` disagrees with its map key (the two identify
    /// the same signer and must not drift).
    // Retained as a crate-internal explicit/test constructor (used by the unit
    // tests below). Production directories come solely from `verify_bundle` via
    // `from_verified_map`, so this has no non-test caller: allow dead_code rather
    // than expose it publicly again.
    #[allow(dead_code)]
    pub(crate) fn from_bindings(
        bindings: impl IntoIterator<Item = (String, SignerBinding)>,
    ) -> Result<Self, RevocationLaneError> {
        let mut by_signer: HashMap<String, SignerBinding> = HashMap::new();
        for (signer_id, binding) in bindings {
            if binding.verifier.signer_id() != signer_id {
                return Err(RevocationLaneError::SignerIdMismatch {
                    key: signer_id,
                    pinned: binding.verifier.signer_id().to_string(),
                });
            }
            if by_signer.insert(signer_id.clone(), binding).is_some() {
                return Err(RevocationLaneError::DuplicateSigner(signer_id));
            }
        }
        Ok(Self { by_signer })
    }

    /// Wrap an already-validated `signer_id -> binding` map produced by the
    /// issuer-signed directory verifier (`verify_bundle`), where duplicate
    /// detection and `signer_id`-vs-key consistency are enforced during bundle
    /// verification. This is the production constructor; the map's provenance is
    /// the one issuer-signed transport directory.
    pub(crate) fn from_verified_map(by_signer: HashMap<String, SignerBinding>) -> Self {
        Self { by_signer }
    }

    /// Resolve an opaque `signer_id` to its pinned binding, or `None`
    /// (fail-closed) when the signer is not pinned.
    #[must_use]
    pub fn resolve(&self, signer_id: &str) -> Option<&SignerBinding> {
        self.by_signer.get(signer_id)
    }

    /// Number of pinned signer bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_signer.len()
    }

    /// Whether no signer is pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_signer.is_empty()
    }
}

/// Errors surfaced by the revocation lane. Every variant is fail-closed: the
/// receiver merges nothing and either resets the stream or writes back a typed
/// [`RevocationLaneResponse::Rejected`] (blueprint B.7).
#[derive(Debug, thiserror::Error)]
pub enum RevocationLaneError {
    /// A structural / ordering error from the `chio-federation` envelope layer.
    #[error("revocation gossip error: {0}")]
    Gossip(#[from] RevocationGossipError),
    /// The authenticated transport `EndpointId` resolves to no admitted kernel.
    /// Should be unreachable past the admission gate; treated as a hard reset.
    #[error("unbound transport endpoint reached revocation handler")]
    UnboundEndpoint,
    /// A frame's `signer_id` is not present in the pinned signer directory.
    #[error("no pinned signer binding for signer_id `{0}`")]
    UnknownSigner(String),
    /// A frame's `signer_id` is pinned, but to a DIFFERENT transport endpoint
    /// than the one that authenticated this connection (origin-pin violation).
    #[error("signer `{signer_id}` is not pinned to transport endpoint {endpoint}")]
    SignerEndpointMismatch {
        /// The opaque signer identity carried by the frame.
        signer_id: String,
        /// The authenticated transport endpoint (short form) that presented it.
        endpoint: String,
    },
    /// The pinned-signer signature check over a [`SignedEpochRoot`] failed
    /// (BLAKE3/transport integrity is NOT authenticity, ADAPTER-SPEC 2.2).
    #[error("epoch root signature failed pinned-signer verification (signer_id `{0}`)")]
    BadSignature(String),
    /// A pinned binding's verifier `signer_id` disagrees with its directory key.
    #[error("pinned signer key `{key}` disagrees with verifier signer_id `{pinned}`")]
    SignerIdMismatch {
        /// The directory map key.
        key: String,
        /// The `signer_id` carried by the pinned verifier.
        pinned: String,
    },
    /// The same `signer_id` was pinned more than once.
    #[error("duplicate signer binding for signer_id `{0}`")]
    DuplicateSigner(String),
    /// The caller's revocation-root sink rejected a verified root.
    #[error("revocation sink rejected merge: {0}")]
    SinkRejected(String),
    /// A JSON (de)serialization failure on the wire.
    #[error("wire codec error: {0}")]
    Codec(String),
    /// A QUIC stream read/write/finish failure.
    #[error("transport error: {0}")]
    Transport(String),
    /// A peer-dependent accept step exceeded its bound (slowloris) or the
    /// in-flight cap shed the connection. Fail-closed: the connection is reset
    /// and NOTHING is merged or served.
    #[error(transparent)]
    AcceptLimit(#[from] AcceptLimitError),
}

/// Caller-provided sink for verified epoch roots (blueprint B.6
/// `RevocationRootSink`). Called only AFTER a root has passed pinned-signer
/// verification and the transport-origin pin. The merge is all-or-nothing at the
/// batch level: a batch with any unverifiable frame merges nothing.
pub trait RevocationRootSink: std::fmt::Debug + Send + Sync {
    /// Merge one verified signed root into the caller's `RevocationView` cache.
    /// Fail-closed: an `Err` aborts the batch.
    fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError>;
}

/// One lane request. Externally tagged so the inner `deny_unknown_fields`
/// contract types keep their own object shape (an internally-tagged enum would
/// inject the discriminant key into the batch object and break the contract).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RevocationLaneRequest {
    /// A pushed batch of signed roots (per-peer FIFO drain).
    Push(RevocationGossipBatch),
    /// A catch-up gap-fill request; its response rides this same stream.
    Catchup(RevocationCatchupRequest),
}

/// One lane response, correlated to the request by stream identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RevocationLaneResponse {
    /// A push batch verified and merged; carries the merged epochs for audit.
    PushAccepted {
        /// The epochs merged into the receiver cache, in wire order.
        merged_epochs: Vec<u64>,
    },
    /// A catch-up response (may be a partial suffix; see `validate_response`).
    Catchup(RevocationCatchupResponse),
    /// A typed rejection. Fail-closed: NOTHING was merged and no root was served.
    Rejected {
        /// Stable machine code for the deny reason.
        code: String,
        /// Human-readable detail.
        message: String,
    },
}

impl RevocationLaneError {
    /// Stable machine code for a typed [`RevocationLaneResponse::Rejected`].
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            RevocationLaneError::Gossip(inner) => match inner {
                RevocationGossipError::UnsupportedSchema(_) => "unsupported-schema",
                RevocationGossipError::EpochMismatch { .. } => "epoch-mismatch",
                RevocationGossipError::SignerIdMismatch { .. } => "signer-id-mismatch",
                RevocationGossipError::UnknownPeer(_) => "unknown-peer",
                RevocationGossipError::InvalidConfiguration(_) => "invalid-configuration",
                RevocationGossipError::QueuePoisoned => "queue-poisoned",
                RevocationGossipError::CatchupRangeInverted { .. } => "catchup-range-inverted",
                RevocationGossipError::CatchupRangeTooWide { .. } => "catchup-range-too-wide",
                RevocationGossipError::CatchupGap { .. } => "catchup-gap",
            },
            RevocationLaneError::UnboundEndpoint => "unbound-endpoint",
            RevocationLaneError::UnknownSigner(_) => "unknown-signer",
            RevocationLaneError::SignerEndpointMismatch { .. } => "signer-endpoint-mismatch",
            RevocationLaneError::BadSignature(_) => "bad-signature",
            RevocationLaneError::SignerIdMismatch { .. } => "signer-id-mismatch",
            RevocationLaneError::DuplicateSigner(_) => "duplicate-signer",
            RevocationLaneError::SinkRejected(_) => "sink-rejected",
            RevocationLaneError::Codec(_) => "codec",
            RevocationLaneError::Transport(_) => "transport",
            RevocationLaneError::AcceptLimit(error) => error.code(),
        }
    }

    /// QUIC application close code for a fail-closed reset. Accept-limit outcomes
    /// (slowloris timeout / saturation shed) carry their own distinct codes; every
    /// other lane error is a generic reset.
    fn close_code(&self) -> u32 {
        match self {
            RevocationLaneError::AcceptLimit(error) => error.close_code(),
            _ => LANE_RESET_CLOSE_CODE,
        }
    }

    fn as_rejected(&self) -> RevocationLaneResponse {
        RevocationLaneResponse::Rejected {
            code: self.code().to_string(),
            message: self.to_string(),
        }
    }
}

/// The revocation-root [`ProtocolHandler`]. Mount on
/// `Router::builder(ep).accept(ALPN_REVOCATION_ROOT, handler)`.
#[derive(Clone)]
pub struct RevocationHandler {
    /// The one issuer-signed directory. It resolves the admission re-check
    /// (`EndpointId -> kernel_id`, defense in depth above the accept-time gate)
    /// AND carries the derived `signer_id -> (EndpointId, verifying-key)` pinning,
    /// so both originate from the same issuer-signed material.
    directory: Arc<VerifiedDirectory>,
    /// Catch-up history the responder serves via `respond_to_catchup`.
    history: Arc<dyn RevocationCatchupHistory + Send + Sync>,
    /// Caller cache updater for verified push roots.
    sink: Arc<dyn RevocationRootSink>,
    /// This responder's kernel id, echoed into catch-up responses.
    responder_kernel_id: String,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
}

impl std::fmt::Debug for RevocationHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevocationHandler")
            .field("responder_kernel_id", &self.responder_kernel_id)
            .field("directory_version", &self.directory.version())
            .field("pinned_signers", &self.directory.signer_directory().len())
            .finish_non_exhaustive()
    }
}

/// Adapts an `Arc<dyn RevocationCatchupHistory>` to the sized `H:
/// RevocationCatchupHistory` bound `respond_to_catchup` requires.
struct DynHistory(Arc<dyn RevocationCatchupHistory + Send + Sync>);

impl RevocationCatchupHistory for DynHistory {
    fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
        self.0.signed_root_at(epoch)
    }
}

impl RevocationHandler {
    /// Build a revocation-root handler. The signer pinning is DERIVED from the
    /// issuer-signed `directory` ([`VerifiedDirectory::signer_directory`]), so the
    /// handler can never be fed a signer map that disagrees with the admitted
    /// endpoints: the transport-origin pin is structural, not conventional.
    #[must_use]
    pub fn new(
        directory: Arc<VerifiedDirectory>,
        history: Arc<dyn RevocationCatchupHistory + Send + Sync>,
        sink: Arc<dyn RevocationRootSink>,
        responder_kernel_id: impl Into<String>,
    ) -> Self {
        Self {
            directory,
            history,
            sink,
            responder_kernel_id: responder_kernel_id.into(),
            limiter: AcceptLimiter::default(),
        }
    }

    /// Override the default accept-hardening bounds (per-phase timeouts + the
    /// in-flight concurrency cap). The [`Default`] preserves the historical
    /// (generous) behavior; the wiring can tune it in one place.
    #[must_use]
    pub fn with_accept_limits(mut self, config: AcceptLimitConfig) -> Self {
        self.limiter = AcceptLimiter::new(config);
        self
    }

    /// Verify EVERY frame of a pushed batch against the pinned signer directory
    /// and the transport-origin pin, returning the verified roots WITHOUT
    /// merging. All-or-nothing: any unverifiable frame fails the whole batch so
    /// the cache/history is left untouched (blueprint B.5).
    ///
    /// `endpoint` is the authenticated transport `EndpointId` of the connection
    /// carrying the batch.
    pub fn verify_batch(
        &self,
        endpoint: EndpointId,
        batch: &RevocationGossipBatch,
    ) -> Result<Vec<SignedEpochRoot>, RevocationLaneError> {
        // Defense in depth: the admission gate already rejected unbound
        // endpoints before any accept ran. Re-resolve fail-closed anyway.
        if self.directory.authorize(&endpoint).is_none() {
            return Err(RevocationLaneError::UnboundEndpoint);
        }
        // Cheap structural gate: schema + per-frame envelope consistency.
        batch.validate_envelope()?;

        let mut verified: Vec<SignedEpochRoot> = Vec::with_capacity(batch.frames.len());
        for frame in &batch.frames {
            // (a) resolve the opaque signer_id to its pinned binding in the
            // directory's derived signer projection.
            let binding = self
                .directory
                .resolve_signer(&frame.signer_id)
                .ok_or_else(|| RevocationLaneError::UnknownSigner(frame.signer_id.clone()))?;
            // (b) transport-origin pin: the signer must be bound to the SAME
            // authenticated endpoint that presented this frame. Structurally
            // guaranteed by the derived directory, re-checked fail-closed.
            if binding.endpoint != endpoint {
                return Err(RevocationLaneError::SignerEndpointMismatch {
                    signer_id: frame.signer_id.clone(),
                    endpoint: endpoint.fmt_short().to_string(),
                });
            }
            // (c) envelope consistency (epoch/signer agreement) BEFORE crypto.
            frame.validate_envelope()?;
            // (d) authenticity: pinned-signer signature over the root. BLAKE3 /
            // transport integrity is not authenticity.
            frame
                .signed_root
                .verify(&binding.verifier)
                .map_err(|_| RevocationLaneError::BadSignature(frame.signer_id.clone()))?;
            verified.push(frame.signed_root.clone());
        }
        Ok(verified)
    }

    /// Serve a catch-up request from the pinned history via the contract's
    /// `respond_to_catchup` (strict monotone, gap-truncating, never fabricating).
    pub fn respond_catchup(
        &self,
        request: &RevocationCatchupRequest,
        responded_at_unix_ms: u64,
    ) -> Result<RevocationCatchupResponse, RevocationLaneError> {
        let history = DynHistory(self.history.clone());
        let response = respond_to_catchup(
            request,
            &self.responder_kernel_id,
            &history,
            responded_at_unix_ms,
        )?;
        Ok(response)
    }

    /// Handle one decoded lane request, producing the response to write back.
    /// Verification failures become a typed [`RevocationLaneResponse::Rejected`]
    /// (never a silent drop) and NOTHING is merged / served (fail-closed).
    fn handle_request(
        &self,
        endpoint: EndpointId,
        request: RevocationLaneRequest,
        now_unix_ms: u64,
    ) -> RevocationLaneResponse {
        match request {
            RevocationLaneRequest::Push(batch) => match self.verify_batch(endpoint, &batch) {
                Ok(roots) => {
                    // Only now merge, all-or-nothing having verified every root.
                    let mut merged = Vec::with_capacity(roots.len());
                    for root in &roots {
                        if let Err(error) = self.sink.merge_root(root) {
                            note_revocation_failure(&error);
                            return error.as_rejected();
                        }
                        merged.push(root.root.epoch);
                    }
                    RevocationLaneResponse::PushAccepted {
                        merged_epochs: merged,
                    }
                }
                Err(error) => {
                    note_revocation_failure(&error);
                    error.as_rejected()
                }
            },
            RevocationLaneRequest::Catchup(request) => {
                match self.respond_catchup(&request, now_unix_ms) {
                    Ok(response) => RevocationLaneResponse::Catchup(response),
                    Err(error) => {
                        note_revocation_failure(&error);
                        error.as_rejected()
                    }
                }
            }
        }
    }
}

/// OBSERVE-ONLY: count + log a revocation-lane rejection alongside the unchanged
/// fail-closed response. Reads the error's bounded `code()`; a `catchup-gap` also
/// bumps the epoch-gap family (a core revocation-freshness health signal that was
/// entirely dark before). Never alters the response the caller returns.
fn note_revocation_failure(error: &RevocationLaneError) {
    let reason = error.code();
    crate::metrics::record_verify_failure(crate::metrics::SEAM_REVOCATION, reason);
    if reason == "catchup-gap" {
        crate::metrics::record_catchup_epoch_gap(crate::metrics::CATCHUP_SOURCE_REVOCATION);
    }
    tracing::warn!(
        target: crate::observability::TARGET_VERIFY,
        seam = crate::metrics::SEAM_REVOCATION,
        reason = reason,
        "revocation lane rejected request"
    );
}

impl RevocationHandler {
    /// One bounded request/response exchange over the accepted connection. Every
    /// peer-dependent await is bounded (accept_bi, the request-frame read, the
    /// response write); a verification failure is still delivered IN-BAND as a
    /// typed [`RevocationLaneResponse::Rejected`] (produced by `handle_request`,
    /// so this returns `Ok`), and only transport / codec / timeout failures reset.
    async fn serve(&self, conn: &Connection) -> Result<(), RevocationLaneError> {
        let endpoint = conn.remote_id();
        // Defense in depth: unreachable past the admission gate. Reset closed.
        if self.directory.authorize(&endpoint).is_none() {
            return Err(RevocationLaneError::UnboundEndpoint);
        }
        // Bound accept_bi: a connected-but-silent peer is dropped here.
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, conn.accept_bi())
            .await?
            .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
        // Bound the request-frame read: the primary slowloris surface.
        let request: RevocationLaneRequest = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        // Verification runs on the fully received frame; timeouts never weaken it.
        let response = self.handle_request(endpoint, request, now_unix_ms());
        // Bound the response write: a peer that stops reading is dropped here.
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &response),
            )
            .await??;
        Ok(())
    }
}

impl ProtocolHandler for RevocationHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        use tracing::Instrument;
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code.
        let _permit = match self.limiter.admit().await {
            Ok(permit) => permit,
            Err(error) => {
                // OBSERVE-ONLY: the slowloris saturation shed is now countable.
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_REVOCATION,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "revocation lane shed accept (saturated)"
                );
                conn.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        // OBSERVE-ONLY: the in-flight gauge (slowloris detector) and accept span.
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_REVOCATION);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_REVOCATION);
        let started = std::time::Instant::now();
        let result = self.serve(&conn).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_REVOCATION,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_REVOCATION,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                // Bounded linger: keep the connection open until the dialer has
                // read the finished response and closed (so the finished stream
                // is not reset on drop; without this the response can be lost as
                // "connection lost" on real QUIC), but never past the linger bound.
                self.limiter.linger(&conn).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_REVOCATION, outcome);
                crate::observability::record_outcome(&span, outcome);
                tracing::warn!(code = error.code(), error = %error, "revocation lane reset");
                conn.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

/// Client half: dial an authority and push a batch of signed roots, returning
/// the authority's typed response. The admission gate on the authority endpoint
/// rejects an unadmitted dialer before this stream is accepted.
pub async fn push_batch_over_iroh(
    endpoint: &Endpoint,
    authority: EndpointId,
    batch: &RevocationGossipBatch,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_over_iroh(
        endpoint,
        authority,
        &RevocationLaneRequest::Push(batch.clone()),
    )
    .await
}

/// Client half: dial an authority and request a catch-up range; the response
/// (control envelope) rides this lane-b stream while the bulk root bytes are
/// available over iroh-blobs ([`crate::catchup`]).
pub async fn request_catchup_over_iroh(
    endpoint: &Endpoint,
    authority: EndpointId,
    request: &RevocationCatchupRequest,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    request_over_iroh(
        endpoint,
        authority,
        &RevocationLaneRequest::Catchup(request.clone()),
    )
    .await
}

async fn request_over_iroh(
    endpoint: &Endpoint,
    authority: EndpointId,
    request: &RevocationLaneRequest,
) -> Result<RevocationLaneResponse, RevocationLaneError> {
    let conn = endpoint
        .connect(authority, ALPN_REVOCATION_ROOT)
        .await
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    write_frame(&mut send, request).await?;
    let response = read_frame(&mut recv).await?;
    Ok(response)
}

/// Write a length-delimited canonical-JSON frame and half-close the send half so
/// the reader's `read_to_end` terminates.
async fn write_frame<T: Serialize>(
    send: &mut SendStream,
    value: &T,
) -> Result<(), RevocationLaneError> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| RevocationLaneError::Codec(error.to_string()))?;
    send.write_all(&bytes)
        .await
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    send.finish()
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    Ok(())
}

/// Read a single frame written by [`write_frame`] (the peer half-closes after
/// one message), capped at [`MAX_WIRE_BYTES`] fail-closed.
async fn read_frame<T: for<'de> Deserialize<'de>>(
    recv: &mut RecvStream,
) -> Result<T, RevocationLaneError> {
    let bytes = recv
        .read_to_end(MAX_WIRE_BYTES)
        .await
        .map_err(|error| RevocationLaneError::Transport(error.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|error| RevocationLaneError::Codec(error.to_string()))
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::sha256_hex;
    use chio_core_types::Keypair;
    use chio_federation::revocation_gossip::RevocationRootGossip;
    use chio_federation::revocation_gossip::REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA;
    use chio_revocation_oracle::Ed25519RootSigner;
    use chio_revocation_oracle::EpochRoot;
    use iroh::SecretKey;
    use std::sync::Mutex;

    use crate::identity::revocation_signer_endorsement_preimage;
    use crate::identity::transport_endorsement_preimage;
    use crate::identity::RevocationSignerEntry;
    use crate::identity::TransportDirectoryBundleBody;
    use crate::identity::TransportDirectoryBundleDocument;
    use crate::identity::TransportDirectoryBundleTrust;
    use crate::identity::TransportDirectoryDocument;
    use crate::identity::TransportDirectoryEntry;
    use crate::identity::TrustedTransportDirectoryIssuer;
    use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;

    const NOW: u64 = 2_000_000;
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

    fn batch(frames: Vec<RevocationRootGossip>) -> RevocationGossipBatch {
        RevocationGossipBatch {
            schema: REVOCATION_ROOT_GOSSIP_BATCH_SCHEMA.to_string(),
            recipient_kernel_id: "did:chio:receiver".to_string(),
            frames,
            flushed_at_unix_ms: NOW,
        }
    }

    /// A peer for the test directory builder: admitted at a transport endpoint,
    /// optionally declaring oracle revocation signers via its passport. The
    /// derived signer directory is a projection of the verified bundle, so a
    /// signer's endpoint is STRUCTURALLY this peer's `transport_seed`.
    struct PeerSpec {
        kernel_id: &'static str,
        passport_seed: u8,
        transport_seed: u8,
        /// (signer_id, oracle seed hex) declared by this peer's passport.
        signers: Vec<(&'static str, &'static str)>,
        removed: bool,
    }

    impl PeerSpec {
        fn admitted(kernel_id: &'static str, passport_seed: u8, transport_seed: u8) -> Self {
            Self {
                kernel_id,
                passport_seed,
                transport_seed,
                signers: Vec::new(),
                removed: false,
            }
        }

        fn with_signer(mut self, signer_id: &'static str, oracle_seed: &'static str) -> Self {
            self.signers.push((signer_id, oracle_seed));
            self
        }
    }

    fn build_peer_entry(spec: &PeerSpec) -> TransportDirectoryEntry {
        let passport = Keypair::from_seed(&[spec.passport_seed; 32]);
        let transport = endpoint_from_seed(spec.transport_seed);
        let passport_endorsement =
            passport.sign(&transport_endorsement_preimage(spec.kernel_id, &transport));
        let revocation_signers = spec
            .signers
            .iter()
            .map(|(signer_id, seed)| {
                let oracle = signer(signer_id, seed);
                let oracle_public_key = oracle.public_key();
                let oracle_endorsement = passport.sign(&revocation_signer_endorsement_preimage(
                    spec.kernel_id,
                    signer_id,
                    &oracle_public_key,
                ));
                RevocationSignerEntry {
                    signer_id: signer_id.to_string(),
                    oracle_public_key,
                    oracle_endorsement,
                }
            })
            .collect();
        TransportDirectoryEntry {
            kernel_id: spec.kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement,
            revocation_signers,
            removed: spec.removed,
        }
    }

    /// Build a load-time-verified directory admitting the given peers; each peer's
    /// declared oracle signers are projected into the derived signer directory.
    fn verified_directory_of(peers: &[PeerSpec]) -> Arc<VerifiedDirectory> {
        let issuer = Keypair::from_seed(&[240; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:local".to_string(),
            peers: peers.iter().map(build_peer_entry).collect(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: "did:chio:issuer".to_string(),
            key_id: "issuer-key-1".to_string(),
            directory_sha256,
            version: 1,
            previous_version_sha256: None,
            issued_at_unix_ms: NOW - 1,
            expires_at_unix_ms: NOW + 1,
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
            now_unix_ms: NOW,
        };
        Arc::new(bundle.verify_bundle(&trust).expect("bundle verifies"))
    }

    /// A single-peer directory admitting `kernel_id` at `transport_seed` and
    /// declaring `signer_id` (oracle `seed`) bound to that same endpoint.
    fn directory_with_signer(
        kernel_id: &'static str,
        transport_seed: u8,
        signer_id: &'static str,
        seed: &'static str,
    ) -> Arc<VerifiedDirectory> {
        verified_directory_of(&[
            PeerSpec::admitted(kernel_id, 7, transport_seed).with_signer(signer_id, seed)
        ])
    }

    /// A recording sink so tests can assert exactly what was merged.
    #[derive(Debug, Default)]
    struct RecordingSink {
        merged: Mutex<Vec<u64>>,
    }

    impl RevocationRootSink for RecordingSink {
        fn merge_root(&self, signed: &SignedEpochRoot) -> Result<(), RevocationLaneError> {
            self.merged
                .lock()
                .expect("sink lock")
                .push(signed.root.epoch);
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct EmptyHistory;
    impl RevocationCatchupHistory for EmptyHistory {
        fn signed_root_at(&self, _epoch: u64) -> Option<SignedEpochRoot> {
            None
        }
    }

    fn handler(directory: Arc<VerifiedDirectory>) -> (RevocationHandler, Arc<RecordingSink>) {
        let sink = Arc::new(RecordingSink::default());
        let handler = RevocationHandler::new(
            directory,
            Arc::new(EmptyHistory),
            sink.clone(),
            "did:chio:responder",
        );
        (handler, sink)
    }

    #[test]
    fn signed_root_accepted_through_derived_binding() {
        // A real SignedEpochRoot verifies through the DERIVED signer binding: the
        // directory declares oracle-a bound (structurally) to the peer's endpoint.
        let transport = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, sink) = handler(directory);

        let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
        let response = handler.handle_request(
            transport,
            RevocationLaneRequest::Push(batch(vec![frame])),
            NOW,
        );
        match response {
            RevocationLaneResponse::PushAccepted { merged_epochs } => {
                assert_eq!(merged_epochs, vec![5]);
            }
            other => panic!("expected PushAccepted, got {other:?}"),
        }
        assert_eq!(*sink.merged.lock().unwrap(), vec![5]);
    }

    #[test]
    fn forged_root_bumps_verify_failure_counter_and_is_still_rejected() {
        // OBSERVE-ONLY proof: a forged (tampered) root drives handle_request to a
        // typed Rejected AND bumps verify_failures{revocation,bad-signature}. The
        // response and the empty sink are byte-identical to before instrumentation.
        let transport = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, sink) = handler(directory);

        let mut signed = signed_root(&oracle, 5);
        signed.signature.signature_bytes[0] ^= 0x01;
        let frame = RevocationRootGossip::from_signed(signed, NOW);

        let before =
            crate::metrics::verify_failures_total(crate::metrics::SEAM_REVOCATION, "bad-signature");
        let response = handler.handle_request(
            transport,
            RevocationLaneRequest::Push(batch(vec![frame])),
            NOW,
        );
        assert!(matches!(response, RevocationLaneResponse::Rejected { .. }));
        assert!(sink.merged.lock().unwrap().is_empty(), "nothing merged");
        assert!(
            crate::metrics::verify_failures_total(crate::metrics::SEAM_REVOCATION, "bad-signature")
                > before,
            "the verify failure must be counted (observe-only)"
        );
    }

    #[test]
    fn tampered_signature_is_rejected_bad_signature() {
        let transport = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, sink) = handler(directory);

        let mut signed = signed_root(&oracle, 5);
        // Flip a signature byte: integrity of the wire object is intact, but the
        // pinned-signer authenticity check must fail closed.
        signed.signature.signature_bytes[0] ^= 0x01;
        let frame = RevocationRootGossip::from_signed(signed, NOW);

        let err = handler
            .verify_batch(transport, &batch(vec![frame]))
            .expect_err("tampered signature must fail closed");
        assert!(matches!(err, RevocationLaneError::BadSignature(ref id) if id == "oracle-a"));
        // Nothing merged (all-or-nothing).
        assert!(sink.merged.lock().unwrap().is_empty());
    }

    #[test]
    fn forged_root_rejected_through_derived_binding() {
        // Pinned "oracle-a" holds SEED_A (declared in the directory); the frame is
        // signed by an impostor that CLAIMS "oracle-a" but holds SEED_B. The
        // derived binding's verifier rejects it fail-closed.
        let transport = endpoint_from_seed(10);
        let impostor = signer("oracle-a", SEED_B);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, _sink) = handler(directory);

        let frame = RevocationRootGossip::from_signed(signed_root(&impostor, 5), NOW);
        let err = handler
            .verify_batch(transport, &batch(vec![frame]))
            .expect_err("wrong signing key must fail closed");
        assert!(matches!(err, RevocationLaneError::BadSignature(_)));
    }

    #[test]
    fn unpinned_signer_id_is_rejected() {
        let transport = endpoint_from_seed(10);
        let oracle_b = signer("oracle-b", SEED_B);
        // Only oracle-a is declared in the directory.
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, _sink) = handler(directory);

        let frame = RevocationRootGossip::from_signed(signed_root(&oracle_b, 5), NOW);
        let err = handler
            .verify_batch(transport, &batch(vec![frame]))
            .expect_err("unpinned signer must fail closed");
        assert!(matches!(err, RevocationLaneError::UnknownSigner(ref id) if id == "oracle-b"));
    }

    #[test]
    fn signer_pinned_to_other_endpoint_is_rejected() {
        // oracle-a is declared by peer-a (structurally bound to endpoint(10)), but
        // the frame arrives authenticated as peer-b's endpoint(11). peer-b is
        // itself admitted, so this exercises the signer/endpoint origin pin, not
        // the admission reject.
        let arriving = endpoint_from_seed(11);
        let oracle = signer("oracle-a", SEED_A);
        let directory = verified_directory_of(&[
            PeerSpec::admitted("did:chio:peer-a", 7, 10).with_signer("oracle-a", SEED_A),
            PeerSpec::admitted("did:chio:peer-b", 8, 11),
        ]);
        let (handler, _sink) = handler(directory);

        let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
        let err = handler
            .verify_batch(arriving, &batch(vec![frame]))
            .expect_err("signer bound to another endpoint must fail closed");
        assert!(matches!(
            err,
            RevocationLaneError::SignerEndpointMismatch { .. }
        ));
    }

    #[test]
    fn unbound_endpoint_is_rejected_at_the_gate() {
        // The connection's endpoint is bound to NO admitted kernel: the handler's
        // defense-in-depth re-resolve rejects before any signer work.
        let intruder = endpoint_from_seed(200);
        let oracle = signer("oracle-a", SEED_A);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, _sink) = handler(directory);

        let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
        let err = handler
            .verify_batch(intruder, &batch(vec![frame]))
            .expect_err("unbound endpoint must fail closed at the gate");
        assert!(matches!(err, RevocationLaneError::UnboundEndpoint));
    }

    #[test]
    fn one_bad_frame_rejects_whole_batch_all_or_nothing() {
        let transport = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let (handler, sink) = handler(directory);

        let good = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
        let mut bad_signed = signed_root(&oracle, 6);
        bad_signed.signature.signature_bytes[0] ^= 0x01;
        let bad = RevocationRootGossip::from_signed(bad_signed, NOW);

        let response = handler.handle_request(
            transport,
            RevocationLaneRequest::Push(batch(vec![good, bad])),
            NOW,
        );
        assert!(matches!(response, RevocationLaneResponse::Rejected { .. }));
        // The good frame must NOT have been merged: all-or-nothing.
        assert!(sink.merged.lock().unwrap().is_empty());
    }

    #[test]
    fn derived_signer_directory_resolves_binding() {
        // The projection consumed by the handler resolves the declared signer to
        // the peer's endpoint, and rejects an undeclared signer fail-closed.
        let transport = endpoint_from_seed(10);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let binding = directory
            .resolve_signer("oracle-a")
            .expect("oracle-a resolves through the derived projection");
        assert_eq!(binding.endpoint, transport);
        assert_eq!(directory.signer_directory().len(), 1);
        assert!(directory.resolve_signer("oracle-b").is_none());
    }

    #[test]
    fn catchup_request_serves_from_history() {
        // A history holding epochs 5..=7 served through respond_to_catchup.
        #[derive(Debug)]
        struct MapHistory(HashMap<u64, SignedEpochRoot>);
        impl RevocationCatchupHistory for MapHistory {
            fn signed_root_at(&self, epoch: u64) -> Option<SignedEpochRoot> {
                self.0.get(&epoch).cloned()
            }
        }
        let transport = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        let directory = directory_with_signer("did:chio:peer", 10, "oracle-a", SEED_A);
        let mut roots = HashMap::new();
        for epoch in 5..=7 {
            roots.insert(epoch, signed_root(&oracle, epoch));
        }
        let handler = RevocationHandler::new(
            directory,
            Arc::new(MapHistory(roots)),
            Arc::new(RecordingSink::default()),
            "did:chio:responder",
        );

        let request = RevocationCatchupRequest::new("did:chio:peer", 5, 7, NOW).unwrap();
        let response =
            handler.handle_request(transport, RevocationLaneRequest::Catchup(request), NOW);
        match response {
            RevocationLaneResponse::Catchup(catchup) => {
                let epochs: Vec<u64> = catchup.frames.iter().map(|frame| frame.epoch).collect();
                assert_eq!(epochs, vec![5, 6, 7]);
                assert!(catchup.validate_response().is_ok());
            }
            other => panic!("expected Catchup, got {other:?}"),
        }
    }

    #[test]
    fn signer_directory_rejects_duplicate_and_key_mismatch() {
        let transport = endpoint_from_seed(10);
        let oracle = signer("oracle-a", SEED_A);
        // Duplicate signer_id.
        let dup = VerifiedSignerDirectory::from_bindings(vec![
            (
                "oracle-a".to_string(),
                SignerBinding {
                    endpoint: transport,
                    verifier: oracle.verifier(),
                },
            ),
            (
                "oracle-a".to_string(),
                SignerBinding {
                    endpoint: transport,
                    verifier: oracle.verifier(),
                },
            ),
        ]);
        assert!(matches!(dup, Err(RevocationLaneError::DuplicateSigner(_))));

        // Key/verifier signer_id disagrees with the map key.
        let mismatch = VerifiedSignerDirectory::from_bindings(vec![(
            "oracle-z".to_string(),
            SignerBinding {
                endpoint: transport,
                verifier: oracle.verifier(),
            },
        )]);
        assert!(matches!(
            mismatch,
            Err(RevocationLaneError::SignerIdMismatch { .. })
        ));
    }

    #[test]
    fn lane_request_round_trips_externally_tagged() {
        // The externally-tagged envelope preserves the inner deny_unknown_fields
        // contract types unchanged.
        let oracle = signer("oracle-a", SEED_A);
        let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
        let request = RevocationLaneRequest::Push(batch(vec![frame]));
        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: RevocationLaneRequest = serde_json::from_slice(&encoded).unwrap();
        match decoded {
            RevocationLaneRequest::Push(batch) => assert!(batch.validate_envelope().is_ok()),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    // -- End-to-end over real loopback QUIC, driving the REAL RevocationHandler --
    //
    // The deterministic tests above drive `verify_batch` / `handle_request` in
    // isolation. These bind two endpoints over loopback QUIC, mount the REAL
    // `RevocationHandler` on its ALPN, and push through the genuine `accept()`
    // path: transport auth -> directory `authorize` -> pinned-signer verify ->
    // sink merge. A forged-signer root is rejected ON THE WIRE and reaches
    // NOTHING (the sink stays empty), proving the real handler fails closed.

    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::EndpointAddr;
    use iroh::TransportAddr;
    use std::time::Duration;

    async fn bind_endpoint(seed: u8) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .bind_addr("127.0.0.1:0")
            .expect("loopback bind address parses")
            .bind()
            .await
            .expect("endpoint binds on loopback")
    }

    fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
        EndpointAddr::from_parts(
            endpoint.id(),
            endpoint.bound_sockets().into_iter().map(TransportAddr::Ip),
        )
    }

    /// Drive the client half by hand (the shipped `push_batch_over_iroh` takes a
    /// bare `EndpointId` and needs discovery to resolve; on raw loopback we dial a
    /// full `EndpointAddr`). Reuses the lane's own `write_frame` / `read_frame`
    /// so the wire codec under test is the real one.
    async fn push_batch_over_quic(
        dialer: &Endpoint,
        acceptor: EndpointAddr,
        batch: RevocationGossipBatch,
    ) -> RevocationLaneResponse {
        let conn = dialer
            .connect(acceptor, ALPN_REVOCATION_ROOT)
            .await
            .expect("dialer connects to acceptor over loopback");
        let (mut send, mut recv) = conn.open_bi().await.expect("open bi stream");
        write_frame(&mut send, &RevocationLaneRequest::Push(batch))
            .await
            .expect("write push request");
        let response: RevocationLaneResponse =
            read_frame(&mut recv).await.expect("read lane response");
        conn.close(0u32.into(), b"ok");
        response
    }

    #[tokio::test]
    async fn real_handler_accepts_pinned_signer_over_quic() {
        let dialer_seed = 20u8;
        let oracle = signer("oracle-a", SEED_A);
        // The directory declares oracle-a bound (structurally) to the dialer's
        // endpoint (transport_seed == dialer_seed), so the derived binding both
        // admits the dialer and pins oracle-a to it.
        let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
        let (handler, sink) = handler(directory);

        let acceptor = bind_endpoint(21).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_REVOCATION_ROOT, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed).await;
        let frame = RevocationRootGossip::from_signed(signed_root(&oracle, 5), NOW);
        let response = tokio::time::timeout(
            Duration::from_secs(15),
            push_batch_over_quic(&dialer, acceptor_addr, batch(vec![frame])),
        )
        .await
        .expect("push completes before timeout");

        match response {
            RevocationLaneResponse::PushAccepted { merged_epochs } => {
                assert_eq!(merged_epochs, vec![5]);
            }
            other => panic!("expected PushAccepted, got {other:?}"),
        }
        assert_eq!(*sink.merged.lock().unwrap(), vec![5]);
        router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn real_handler_rejects_forged_signer_root_before_merge_over_quic() {
        let dialer_seed = 20u8;
        // Declared "oracle-a" holds SEED_A and is bound to the dialer endpoint, so
        // the admission gate and the transport-origin pin BOTH pass; the batch is
        // signed by an IMPOSTOR that claims "oracle-a" but holds SEED_B.
        // Authenticity must fail closed on the wire, before any merge.
        let impostor = signer("oracle-a", SEED_B);
        let directory = directory_with_signer("did:chio:peer", dialer_seed, "oracle-a", SEED_A);
        let (handler, sink) = handler(directory);

        let acceptor = bind_endpoint(22).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_REVOCATION_ROOT, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed).await;
        let forged = RevocationRootGossip::from_signed(signed_root(&impostor, 5), NOW);
        let response = tokio::time::timeout(
            Duration::from_secs(15),
            push_batch_over_quic(&dialer, acceptor_addr, batch(vec![forged])),
        )
        .await
        .expect("push completes before timeout");

        match response {
            RevocationLaneResponse::Rejected { code, .. } => {
                assert_eq!(code, "bad-signature");
            }
            other => panic!("expected Rejected(bad-signature), got {other:?}"),
        }
        // Fail-closed: the forged root reached the sink NOWHERE (nothing merged).
        assert!(sink.merged.lock().unwrap().is_empty());
        router.shutdown().await.ok();
    }
}
