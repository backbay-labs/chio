//! Lane d: bilateral DSSE co-sign over a dedicated-ALPN bidirectional QUIC RPC.
//!
//! ADAPTER-SPEC section 4 row (d) + 4.2. This lane is an interactive
//! request/response exchange, categorically NOT gossip: broadcasting an in-flight
//! DSSE statement would leak it to non-parties. It is the transport implementation
//! of [`chio_federation::bilateral::BilateralCoSigningProtocol`], dialing over iroh
//! instead of running in-process; the request/response CONTRACT above the transport
//! is unchanged (it replaces [`chio_federation::bilateral::InProcessCoSigner`]).
//!
//! ## The five-step flow (ADAPTER-SPEC 4.2)
//!
//! 1. Org B ([`IrohBilateralCoSigner`]) resolves Org A's [`EndpointAddr`] from
//!    `request.org_a_kernel_id` and dials [`ALPN_BILATERAL`]; QUIC/TLS
//!    authenticates both `EndpointId`s.
//! 2. Org A's `after_handshake` admission gate ([`crate::admission::DirectoryGate`])
//!    Rejects (403) any Org B `EndpointId` not bound to an admitted, non-removed
//!    `kernel_id` BEFORE any [`ProtocolHandler::accept`] runs (DoS rejection /
//!    defense in depth, NOT a replacement for the signature check).
//! 3. Org B `open_bi()`, writes one length-delimited canonical
//!    [`WireDsseCoSigningRequest`], then half-closes its send half (`finish()`).
//! 4. Org A ([`BilateralCoSignHandler`]) asserts its directory-resolved
//!    `EndpointId == request.org_b_kernel_id`, verifies `org_b_signature` over the
//!    exact `pae_bytes` against Org B's DIRECTORY-BOUND passport key (the key the
//!    same verified directory snapshot binds for that peer; a separately-pinned
//!    map must AGREE with it or the co-sign is refused, so a rotated-away key is
//!    never accepted), algorithm-agnostic, above iroh, via
//!    [`chio_core_types::PublicKey::verify`], and re-checks trust / rotation-window
//!    through the same directory resolution. On ANY failure it writes a typed error
//!    mirroring [`BilateralCoSigningError`] and terminates WITHOUT signing.
//! 5. On success Org A signs the SAME `pae_bytes` (mirroring
//!    `InProcessCoSigner::request_dsse_cosignature`) and writes the response frame
//!    on the same stream.
//!
//! ## Wire mirror (the KNOWN GOTCHA)
//!
//! [`DsseCoSigningRequest`] and [`DsseCoSigningResponse`] are deliberately NOT
//! `Serialize`/`Deserialize` in the contracts crate. Rather than modify
//! `chio-federation`, this lane defines ADAPTER-LOCAL serde mirror types that map
//! field-for-field:
//!
//! | contracts type ([`chio_federation::bilateral`]) | adapter wire mirror |
//! | --- | --- |
//! | `DsseCoSigningRequest { schema, org_a_kernel_id, org_b_kernel_id, pae_bytes, org_b_signature }` | [`WireDsseCoSigningRequest`] with the identical five fields |
//! | `DsseCoSigningResponse { schema, org_a_signature }` | [`WireReply::Ok`] `{ schema, org_a_signature }` |
//! | `BilateralCoSigningError` (server-produced subset) | [`WireReply::Err`] `{ code, detail }` tagged by [`WireErrorCode`] |
//!
//! [`chio_core_types::Signature`] already implements serde (algorithm-tagged hex
//! via `to_hex`/`from_hex`), so the mirror carries it verbatim and every passport
//! algorithm (Ed25519, P-256, P-384, ML-DSA-65, Hybrid) round-trips. NOTE:
//! `Signature::to_bytes()` is Ed25519-only (it returns zeros for other algorithms),
//! so the wire path MUST use the serde/hex encoding, never `to_bytes`. `pae_bytes`
//! maps 1:1 as opaque bytes and is NEVER re-derived server-side (ADAPTER-SPEC 4.2:
//! sign/verify the exact bytes received).

use std::collections::HashMap;
use std::sync::Arc;

use chio_core_types::Ed25519Backend;
use chio_core_types::Keypair;
use chio_core_types::PublicKey;
use chio_core_types::Signature;
use chio_core_types::SigningBackend;
use chio_federation::bilateral::BilateralCoSigningError;
use chio_federation::bilateral::BilateralCoSigningProtocol;
use chio_federation::bilateral::DsseCoSigningRequest;
use chio_federation::bilateral::DsseCoSigningResponse;
use chio_federation::bilateral::BILATERAL_DSSE_COSIGNING_SCHEMA;
use iroh::endpoint::Connection;
use iroh::endpoint::RecvStream;
use iroh::endpoint::SendStream;
use iroh::endpoint::VarInt;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use serde::Deserialize;
use serde::Serialize;

use crate::admission::DirectoryGate;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptLimitError;
use crate::lanes::limits::AcceptLimiter;
use crate::lanes::limits::AcceptPhase;
use crate::lanes::limits::LANE_RESET_CLOSE_CODE;

/// SPEC-FIXED ALPN for the bilateral DSSE co-sign lane (ADAPTER-SPEC 4.2).
pub const ALPN_BILATERAL: &[u8] = b"chio/federation/bilateral-dsse-cosign/1";

/// Hard cap on a single length-delimited frame. A DSSE PAE preimage wraps an
/// in-toto Statement (with an embedded receipt), so a few KiB is typical; the cap
/// is a fail-closed anti-DoS bound, not a tuning knob.
const MAX_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// QUIC application close code used when the exchange completes normally.
const CLOSE_OK: u32 = 0;

// ---------------------------------------------------------------------------
// Directory-facing seams (kept above iroh, algorithm-agnostic)
// ---------------------------------------------------------------------------

/// Client-side (Org B) resolver from an Org A `kernel_id` to a dialable
/// [`EndpointAddr`].
///
/// In production this is backed by discovery (an `EndpointId` alone is dialable
/// once discovery/relay is configured); in relay-disabled / loopback deployments
/// it carries the direct socket addresses. It is intentionally distinct from the
/// server's [`crate::identity::VerifiedDirectory`] (which resolves the reverse
/// direction, `EndpointId -> kernel_id`).
pub trait OrgAddressBook: Send + Sync {
    /// The dialable address for a peer `kernel_id`, or `None` when unknown.
    fn address_of(&self, kernel_id: &str) -> Option<EndpointAddr>;
}

impl OrgAddressBook for HashMap<String, EndpointAddr> {
    fn address_of(&self, kernel_id: &str) -> Option<EndpointAddr> {
        self.get(kernel_id).cloned()
    }
}

/// Server-side (Org A) pinned passport keys for the counterparties it may
/// co-sign for, keyed by `kernel_id`.
///
/// This mirrors `InProcessCoSigner`'s single `tool_host_public_key` and serves as
/// Org A's co-signing ALLOWLIST (which admitted peers it will co-sign for). It is
/// NO LONGER the authoritative verification key: Org A verifies Org B's signature
/// over `pae_bytes` against the DIRECTORY-BOUND passport key
/// ([`crate::identity::VerifiedDirectory::resolve_passport_key`]) so verification
/// is pinned to the same issuer-signed snapshot the admission gate authorized on.
/// The key pinned here MUST agree with that binding; a pinned key that lags the
/// signed directory is refused before signing (fail-closed on mismatch/lag). The
/// passport key is deliberately NOT the ed25519 transport `EndpointId` (Option B:
/// a non-ed25519 passport cannot be an `EndpointId`).
pub trait PinnedPassportKeys: Send + Sync {
    /// The pinned passport public key for a peer `kernel_id`, or `None` when the
    /// peer is not a co-signing counterparty.
    fn passport_key(&self, kernel_id: &str) -> Option<PublicKey>;
}

impl PinnedPassportKeys for HashMap<String, PublicKey> {
    fn passport_key(&self, kernel_id: &str) -> Option<PublicKey> {
        self.get(kernel_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Wire mirror types (serde; adapter-local, contracts crate untouched)
// ---------------------------------------------------------------------------

/// Serde mirror of [`DsseCoSigningRequest`] (see module docs). Field-for-field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireDsseCoSigningRequest {
    schema: String,
    org_a_kernel_id: String,
    org_b_kernel_id: String,
    /// Opaque DSSE PAE preimage; signed/verified verbatim, never re-derived.
    pae_bytes: Vec<u8>,
    /// Algorithm-tagged (serde hex); round-trips every passport algorithm.
    org_b_signature: Signature,
}

impl WireDsseCoSigningRequest {
    fn from_request(request: &DsseCoSigningRequest) -> Self {
        Self {
            schema: request.schema.clone(),
            org_a_kernel_id: request.org_a_kernel_id.clone(),
            org_b_kernel_id: request.org_b_kernel_id.clone(),
            pae_bytes: request.pae_bytes.clone(),
            org_b_signature: request.org_b_signature.clone(),
        }
    }

    fn into_request(self) -> DsseCoSigningRequest {
        DsseCoSigningRequest {
            schema: self.schema,
            org_a_kernel_id: self.org_a_kernel_id,
            org_b_kernel_id: self.org_b_kernel_id,
            pae_bytes: self.pae_bytes,
            org_b_signature: self.org_b_signature,
        }
    }
}

/// The single reply frame Org A writes back: either the co-signature or a typed
/// error mirroring [`BilateralCoSigningError`]. A typed error is a valid reply
/// (the peer is reachable and answered), NOT a transport failure.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum WireReply {
    /// Org A co-signed the exact `pae_bytes`. Mirrors [`DsseCoSigningResponse`].
    Ok {
        schema: String,
        org_a_signature: Signature,
    },
    /// Org A refused (WITHOUT signing). `detail` carries the offending id / reason.
    Err { code: WireErrorCode, detail: String },
}

/// Wire tag mirroring the server-producible [`BilateralCoSigningError`] variants.
/// Every variant is fail-closed; there is no "accepted" error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireErrorCode {
    UnsupportedSchema,
    UnknownPeer,
    PeerExpired,
    OrgBSignatureInvalid,
    /// Any other server-side rejection (folds `TransportFailure`, `PeerRejected`).
    PeerRejected,
}

impl WireErrorCode {
    /// Stable, bounded metric/log reason for this wire error code. Feeds the
    /// `reason` label on `chio_federation_transport_verify_failures_total`.
    fn as_reason(self) -> &'static str {
        match self {
            WireErrorCode::UnsupportedSchema => "unsupported-schema",
            WireErrorCode::UnknownPeer => "unknown-peer",
            WireErrorCode::PeerExpired => "peer-expired",
            WireErrorCode::OrgBSignatureInvalid => "org-b-signature-invalid",
            WireErrorCode::PeerRejected => "peer-rejected",
        }
    }
}

/// OBSERVE-ONLY reason for a co-sign rejection, reusing the exhaustive
/// [`WireReply::err`] mapping so any [`BilateralCoSigningError`] variant folds to
/// one bounded code (never a high-cardinality label).
fn bilateral_reason(error: &BilateralCoSigningError) -> &'static str {
    if let WireReply::Err { code, .. } = WireReply::err(error) {
        code.as_reason()
    } else {
        "peer-rejected"
    }
}

impl WireReply {
    /// Encode a successful co-signature.
    fn ok(response: &DsseCoSigningResponse) -> Self {
        Self::Ok {
            schema: response.schema.clone(),
            org_a_signature: response.org_a_signature.clone(),
        }
    }

    /// Encode a server-side rejection as a typed error frame (no signature).
    fn err(error: &BilateralCoSigningError) -> Self {
        let (code, detail) = match error {
            BilateralCoSigningError::UnsupportedSchema(schema) => {
                (WireErrorCode::UnsupportedSchema, schema.clone())
            }
            BilateralCoSigningError::UnknownPeer(peer) => {
                (WireErrorCode::UnknownPeer, peer.clone())
            }
            BilateralCoSigningError::PeerExpired(peer) => {
                (WireErrorCode::PeerExpired, peer.clone())
            }
            BilateralCoSigningError::OrgBSignatureInvalid => {
                (WireErrorCode::OrgBSignatureInvalid, String::new())
            }
            // Everything else is surfaced to the peer as a rejection with context.
            other => (WireErrorCode::PeerRejected, other.to_string()),
        };
        Self::Err { code, detail }
    }

    /// Client-side: fold the reply frame back into the contract's Result.
    fn into_result(self) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        match self {
            Self::Ok {
                schema,
                org_a_signature,
            } => {
                if schema != BILATERAL_DSSE_COSIGNING_SCHEMA {
                    return Err(BilateralCoSigningError::UnsupportedSchema(schema));
                }
                Ok(DsseCoSigningResponse {
                    schema,
                    org_a_signature,
                })
            }
            Self::Err { code, detail } => Err(match code {
                WireErrorCode::UnsupportedSchema => {
                    BilateralCoSigningError::UnsupportedSchema(detail)
                }
                WireErrorCode::UnknownPeer => BilateralCoSigningError::UnknownPeer(detail),
                WireErrorCode::PeerExpired => BilateralCoSigningError::PeerExpired(detail),
                WireErrorCode::OrgBSignatureInvalid => {
                    BilateralCoSigningError::OrgBSignatureInvalid
                }
                WireErrorCode::PeerRejected => BilateralCoSigningError::PeerRejected(detail),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Length-delimited framing over one bidi stream
// ---------------------------------------------------------------------------

/// Transport/codec failures on the raw stream. Kept separate from
/// [`BilateralCoSigningError`] so it can bridge to both an [`AcceptError`]
/// (server) and `TransportFailure` (client).
#[derive(Debug, thiserror::Error)]
enum WireError {
    #[error("bilateral stream io failed: {0}")]
    Io(String),
    #[error("bilateral frame length {0} exceeds the {max}-byte cap", max = MAX_WIRE_BYTES)]
    FrameTooLarge(usize),
}

/// Fail-closed accept-side failures that RESET the bilateral stream (as opposed
/// to a co-sign rejection, which is delivered in-band as a typed [`WireReply::Err`]
/// and is NOT an error here). Groups the raw framing, codec, transport, and
/// accept-limit (slowloris timeout / saturation shed) failures so the accept
/// handler can close with the right code in one place.
#[derive(Debug, thiserror::Error)]
enum BilateralAcceptError {
    /// A raw length-delimited framing failure.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A request could not be decoded / a reply could not be encoded.
    #[error("bilateral codec error: {0}")]
    Codec(#[from] serde_json::Error),
    /// A QUIC accept/finish transport failure.
    #[error("bilateral transport error: {0}")]
    Transport(String),
    /// A peer-dependent accept step exceeded its bound (slowloris) or the
    /// in-flight cap shed the connection.
    #[error(transparent)]
    AcceptLimit(#[from] AcceptLimitError),
}

impl BilateralAcceptError {
    /// Stable, log- and reason-string-friendly code.
    fn code(&self) -> &'static str {
        match self {
            BilateralAcceptError::Wire(_) => "wire",
            BilateralAcceptError::Codec(_) => "codec",
            BilateralAcceptError::Transport(_) => "transport",
            BilateralAcceptError::AcceptLimit(error) => error.code(),
        }
    }

    /// QUIC application close code. Accept-limit outcomes carry their own distinct
    /// codes; every other failure is a generic reset.
    fn close_code(&self) -> u32 {
        match self {
            BilateralAcceptError::AcceptLimit(error) => error.close_code(),
            _ => LANE_RESET_CLOSE_CODE,
        }
    }
}

/// Write one length-delimited frame: a 4-byte big-endian length prefix followed
/// by the payload bytes. The caller `finish()`es the send half afterwards.
async fn write_frame(send: &mut SendStream, bytes: &[u8]) -> Result<(), WireError> {
    let len = u32::try_from(bytes.len()).map_err(|_| WireError::FrameTooLarge(bytes.len()))?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(WireError::FrameTooLarge(bytes.len()));
    }
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
    send.write_all(bytes)
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
    Ok(())
}

/// Read exactly one length-delimited frame written by [`write_frame`].
/// Fail-closed on an over-cap length before allocating.
async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>, WireError> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_WIRE_BYTES {
        return Err(WireError::FrameTooLarge(len));
    }
    // Incremental read: grow as bytes arrive, never pre-commit the declared len.
    // `recv` is an iroh (noq) RecvStream, whose inherent `read` yields
    // `Option<usize>` (None == stream finished / EOF).
    const READ_CHUNK: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK));
    let mut remaining = len;
    let mut chunk = [0u8; READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK);
        match recv
            .read(&mut chunk[..want])
            .await
            .map_err(|error| WireError::Io(error.to_string()))?
        {
            Some(0) | None => {
                return Err(WireError::Io(
                    "unexpected eof reading frame body".to_string(),
                ));
            }
            Some(n) => {
                buf.extend_from_slice(&chunk[..n]);
                remaining -= n;
            }
        }
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// Client side (Org B): the transport impl of the federation trait
// ---------------------------------------------------------------------------

/// Org B's transport implementation of
/// [`chio_federation::bilateral::BilateralCoSigningProtocol`]. Dials Org A over
/// iroh on [`ALPN_BILATERAL`] and runs the one-shot request/response exchange.
#[derive(Clone)]
pub struct IrohBilateralCoSigner {
    endpoint: Endpoint,
    address_book: Arc<dyn OrgAddressBook>,
    /// Client-side slowloris bounds: every peer-dependent await (connect, open,
    /// write, the reply read) is bounded by the matching phase timeout so an Org A
    /// that accepts but never replies cannot hang the caller forever. Generous by
    /// default; tune via [`IrohBilateralCoSigner::with_accept_limits`].
    limits: AcceptLimitConfig,
}

impl core::fmt::Debug for IrohBilateralCoSigner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IrohBilateralCoSigner")
            .field("endpoint", &self.endpoint.id().fmt_short().to_string())
            .finish_non_exhaustive()
    }
}

impl IrohBilateralCoSigner {
    /// Build the co-signer over a bound iroh [`Endpoint`] and an Org A address
    /// resolver. The client-side waits use the generous [`AcceptLimitConfig::default`]
    /// bounds; tune them via [`Self::with_accept_limits`].
    #[must_use]
    pub fn new(endpoint: Endpoint, address_book: Arc<dyn OrgAddressBook>) -> Self {
        Self {
            endpoint,
            address_book,
            limits: AcceptLimitConfig::default(),
        }
    }

    /// Override the default client-side slowloris bounds (per-phase timeouts on
    /// connect / open / write / the reply read). The [`Default`] preserves the
    /// generous behavior; a caller can tighten them in one place.
    #[must_use]
    pub fn with_accept_limits(mut self, limits: AcceptLimitConfig) -> Self {
        self.limits = limits;
        self
    }

    /// Async transport of the co-signing exchange (the recommended entry point).
    ///
    /// Dials Org A, writes the length-delimited request, half-closes, and reads
    /// the reply. Transport/codec failures fold into
    /// [`BilateralCoSigningError::TransportFailure`]; a typed error frame folds
    /// into the mirrored [`BilateralCoSigningError`] variant. The caller verifies
    /// `org_a_signature` over `pae_bytes` (as `sign_dsse_envelope_with_cosigner`
    /// already does), consistent with the in-process contract.
    pub async fn request_dsse_cosignature_over_iroh(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        let addr = self
            .address_book
            .address_of(&request.org_a_kernel_id)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_a_kernel_id.clone()))?;

        let connection = client_bounded(
            &self.limits,
            AcceptPhase::AcceptStream,
            self.endpoint.connect(addr, ALPN_BILATERAL),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let result = self.exchange(&connection, request).await;
        connection.close(VarInt::from_u32(CLOSE_OK), b"done");
        result
    }

    /// The bidi write-request / read-reply half, factored out so the connection
    /// is always closed exactly once by the caller regardless of outcome.
    async fn exchange(
        &self,
        connection: &Connection,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        let (mut send, mut recv) = client_bounded(
            &self.limits,
            AcceptPhase::AcceptStream,
            connection.open_bi(),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let request_bytes = serde_json::to_vec(&WireDsseCoSigningRequest::from_request(request))
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        client_bounded(
            &self.limits,
            AcceptPhase::WriteResponse,
            write_frame(&mut send, &request_bytes),
        )
        .await?
        .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        send.finish()
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        // The primary client-side hang surface: an Org A that accepts the request but
        // never returns the reply frame is dropped here at the read bound.
        let reply_bytes =
            client_bounded(&self.limits, AcceptPhase::ReadFrame, read_frame(&mut recv))
                .await?
                .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        let reply: WireReply = serde_json::from_slice(&reply_bytes)
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        reply.into_result()
    }
}

/// Bound one peer-dependent client await by the phase's timeout, mirroring the
/// accept-side [`AcceptLimiter::bounded`]. On timeout this fails closed with a
/// [`BilateralCoSigningError::TransportFailure`] so an Org A that accepts but never
/// replies can no longer hang the caller forever.
async fn client_bounded<T, F>(
    limits: &AcceptLimitConfig,
    phase: AcceptPhase,
    fut: F,
) -> Result<T, BilateralCoSigningError>
where
    F: std::future::Future<Output = T>,
{
    let bound = limits.phase_timeout(phase);
    match tokio::time::timeout(bound, fut).await {
        Ok(output) => Ok(output),
        Err(_elapsed) => Err(BilateralCoSigningError::TransportFailure(format!(
            "bilateral co-sign {phase} exceeded its {}ms client bound",
            bound.as_millis()
        ))),
    }
}

impl BilateralCoSigningProtocol for IrohBilateralCoSigner {
    fn request_cosignature(
        &self,
        request: &chio_federation::bilateral::CoSigningRequest,
    ) -> Result<chio_federation::bilateral::CoSigningResponse, BilateralCoSigningError> {
        // This lane implements the DSSE PAE profile only; the legacy detached
        // CoSigningBody profile is out of scope and rejected fail-closed.
        let _ = request;
        Err(BilateralCoSigningError::UnsupportedSchema(
            chio_federation::bilateral::BILATERAL_COSIGNING_SCHEMA.to_string(),
        ))
    }

    /// Synchronous contract entry point. Bridges to
    /// [`Self::request_dsse_cosignature_over_iroh`]. Works from a multi-threaded
    /// tokio runtime (uses `block_in_place`) or from a plain non-async thread
    /// (spins a private current-thread runtime). On a CURRENT-THREAD tokio runtime
    /// it returns a `TransportFailure` error instead of panicking (`block_in_place`
    /// is unsupported there). Prefer the async method inside async code.
    fn request_dsse_cosignature(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => match handle.runtime_flavor() {
                tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                    handle.block_on(self.request_dsse_cosignature_over_iroh(request))
                }),
                // `block_in_place` panics on a current-thread runtime; fail closed with a
                // typed error instead of crashing during DSSE co-signing. A caller on a
                // current-thread runtime must use the async method directly.
                _ => Err(BilateralCoSigningError::TransportFailure(
                    "request_dsse_cosignature invoked on a current-thread tokio runtime; \
                     call request_dsse_cosignature_over_iroh (async) instead of blocking"
                        .to_string(),
                )),
            },
            Err(_) => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        BilateralCoSigningError::TransportFailure(error.to_string())
                    })?;
                runtime.block_on(self.request_dsse_cosignature_over_iroh(request))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server side (Org A): the ProtocolHandler behind the admission gate
// ---------------------------------------------------------------------------

/// Org A's accept-side handler. Mounted on a `Router` at [`ALPN_BILATERAL`]
/// behind the [`DirectoryGate`] hook. Performs exactly the verification
/// `InProcessCoSigner::request_dsse_cosignature` does, plus the transport-origin
/// binding (the authenticated `EndpointId` must resolve to the claimed
/// `org_b_kernel_id`).
pub struct BilateralCoSignHandler {
    /// Resolves the authenticated `EndpointId` to its admitted `kernel_id`
    /// (shares the exact resolution the accept-time gate admitted on).
    gate: DirectoryGate,
    /// This server's own (Org A) `kernel_id`.
    origin_kernel_id: String,
    /// Org A's co-signing keypair. Mirrors `InProcessCoSigner::origin_keypair`;
    /// Org A signs `pae_bytes` with `Ed25519Backend`.
    origin_keypair: Keypair,
    /// Pinned Org B passport keys (algorithm-agnostic), keyed by `kernel_id`.
    passport_keys: Arc<dyn PinnedPassportKeys>,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
}

impl core::fmt::Debug for BilateralCoSignHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never render key material.
        f.debug_struct("BilateralCoSignHandler")
            .field("origin_kernel_id", &self.origin_kernel_id)
            .finish_non_exhaustive()
    }
}

impl BilateralCoSignHandler {
    /// Build the handler from the shared admission gate, Org A's identity + signing
    /// key, and the pinned Org B passport keys.
    #[must_use]
    pub fn new(
        gate: DirectoryGate,
        origin_kernel_id: impl Into<String>,
        origin_keypair: Keypair,
        passport_keys: Arc<dyn PinnedPassportKeys>,
    ) -> Self {
        Self {
            gate,
            origin_kernel_id: origin_kernel_id.into(),
            origin_keypair,
            passport_keys,
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

    /// Pure verification + co-signature, decoupled from the stream so the
    /// fail-closed no-signature paths are unit-testable without a live handshake.
    ///
    /// Mirrors `InProcessCoSigner::request_dsse_cosignature` (schema, origin,
    /// Org B signature, sign the same bytes) and adds step-4's transport-origin
    /// binding: the authenticated `remote` `EndpointId` must resolve, through the
    /// verified directory, to the request's declared `org_b_kernel_id`.
    fn cosign(
        &self,
        remote: &EndpointId,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        // OBSERVE-ONLY wrapper: the verification + co-signature logic is unchanged
        // in `cosign_inner`; here we count + log a rejection (OrgBSignatureInvalid,
        // UnknownPeer origin/endpoint mismatch, PeerExpired) ALONGSIDE it and
        // return the SAME `Result` the caller folds into a typed WireReply::Err.
        let result = self.cosign_inner(remote, request);
        if let Err(error) = &result {
            let reason = bilateral_reason(error);
            crate::metrics::record_verify_failure(crate::metrics::SEAM_BILATERAL, reason);
            tracing::warn!(
                target: crate::observability::TARGET_VERIFY,
                seam = crate::metrics::SEAM_BILATERAL,
                reason = reason,
                "bilateral co-sign refused without signing"
            );
        }
        result
    }

    fn cosign_inner(
        &self,
        remote: &EndpointId,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        if request.schema != BILATERAL_DSSE_COSIGNING_SCHEMA {
            return Err(BilateralCoSigningError::UnsupportedSchema(
                request.schema.clone(),
            ));
        }
        // This server must be the origin (Org A) the request is addressed to.
        if request.org_a_kernel_id != self.origin_kernel_id {
            return Err(BilateralCoSigningError::UnknownPeer(
                request.org_a_kernel_id.clone(),
            ));
        }
        // ONE directory snapshot for the WHOLE verification. Load the current verified
        // directory ONCE and use it for BOTH the transport-origin
        // authorization AND the passport-key lookup. Consulting the gate twice (a
        // `resolve` for the endpoint, then a separate `directory()` for the key) could
        // straddle a live directory reload: the endpoint might authorize against the OLD
        // directory while the key is read from the NEW one. In the endpoint-rotation case
        // where the new directory keeps the same passport key for that kernel but no longer
        // binds its `EndpointId`, the co-signature would verify even though the CURRENT
        // directory no longer authorizes the remote endpoint. Holding one owned snapshot Arc
        // (ArcSwap `load_full`) also keeps the backing directory alive for the borrowed key.
        let directory = self.gate.directory();
        // Transport-origin binding: the authenticated EndpointId must resolve to the claimed
        // Org B kernel id IN THIS SNAPSHOT. `authorize` returns None for unbound/removed
        // peers (trust + rotation window at the directory layer); the gate should already
        // have rejected those at handshake, so None here is defense in depth. A
        // resolved-but-mismatched id means the caller claimed to be a different peer than it
        // authenticated as: fail closed.
        let resolved = directory
            .authorize(remote)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_b_kernel_id.clone()))?;
        if resolved != request.org_b_kernel_id.as_str() {
            return Err(BilateralCoSigningError::UnknownPeer(
                request.org_b_kernel_id.clone(),
            ));
        }
        // Org B's passport key (any algorithm), read from the SAME issuer-signed snapshot
        // the endpoint was just authorized against. Sourcing the DSSE-verification key from
        // the verified directory (not only a separately-fed pinned map that can lag it) means
        // a rotated-away / revoked passport - one the current directory no longer binds - can
        // never be used to obtain Org A's co-signature. Fail-closed: an unknown or removed
        // peer has no directory-bound passport key.
        let directory_key = directory
            .resolve_passport_key(&request.org_b_kernel_id)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_b_kernel_id.clone()))?;
        // The pinned map is Org A's co-signing allowlist (which admitted peers it
        // will co-sign for): the peer MUST be pinned. Defense in depth: the pinned
        // key MUST also agree with the directory's current binding. A pinned key
        // that lags the signed directory (differs from the current binding) is
        // refused BEFORE signing rather than silently overriding the verified
        // snapshot - fail-closed on mismatch/lag.
        let pinned_key = self
            .passport_keys
            .passport_key(&request.org_b_kernel_id)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_b_kernel_id.clone()))?;
        if pinned_key != *directory_key {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }
        // Verify Org B's signature over the exact pae_bytes against the
        // directory-bound key (above iroh; the pinned map having been proven to
        // match it).
        if !directory_key.verify(&request.pae_bytes, &request.org_b_signature) {
            return Err(BilateralCoSigningError::OrgBSignatureInvalid);
        }

        // Success: sign the SAME opaque pae_bytes (never re-derived).
        let backend = Ed25519Backend::new(self.origin_keypair.clone());
        let signature = backend
            .sign_bytes(&request.pae_bytes)
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        Ok(DsseCoSigningResponse {
            schema: BILATERAL_DSSE_COSIGNING_SCHEMA.to_string(),
            org_a_signature: signature,
        })
    }
}

impl BilateralCoSignHandler {
    /// One bounded request/response exchange. Every peer-dependent await is
    /// bounded (accept_bi, the request-frame read, the reply write). A co-sign
    /// REJECTION is delivered IN-BAND as a typed [`WireReply::Err`] (never a
    /// signature) and returns `Ok`; only genuine transport / codec / timeout
    /// failures return `Err` and reset the stream.
    async fn serve(&self, connection: &Connection) -> Result<(), BilateralAcceptError> {
        // Infallible after the handshake; the gate hook has already run.
        let remote = connection.remote_id();
        // Bound accept_bi: a connected-but-silent peer is dropped here.
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, connection.accept_bi())
            .await?
            .map_err(|error| BilateralAcceptError::Transport(error.to_string()))?;

        // Step 3: read the single length-delimited request (bounded: the primary
        // slowloris surface).
        let request_bytes = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_frame(&mut recv))
            .await??;
        let wire_request: WireDsseCoSigningRequest = serde_json::from_slice(&request_bytes)?;
        let request = wire_request.into_request();

        // Step 4/5: verify + co-sign (or a typed error mirroring the contract).
        // Verification runs on the fully received request; timeouts never weaken it.
        let reply = match self.cosign(&remote, &request) {
            Ok(response) => WireReply::ok(&response),
            Err(error) => WireReply::err(&error),
        };
        let reply_bytes = serde_json::to_vec(&reply)?;
        // Bound the reply write: a peer that stops reading is dropped here.
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_frame(&mut send, &reply_bytes),
            )
            .await??;
        send.finish()
            .map_err(|error| BilateralAcceptError::Transport(error.to_string()))?;
        Ok(())
    }
}

impl ProtocolHandler for BilateralCoSignHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        use tracing::Instrument;
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code.
        let _permit = match self.limiter.admit_peer(&connection.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_BILATERAL,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "bilateral lane shed accept (saturated)"
                );
                connection.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_BILATERAL);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_BILATERAL);
        let started = std::time::Instant::now();
        let result = self.serve(&connection).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_BILATERAL,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_BILATERAL,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                // Bounded linger: keep the connection until the client has read
                // the reply and closed (so the framed response is not truncated
                // by an early drop), but never past the linger bound.
                self.limiter.linger(&connection).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_BILATERAL, outcome);
                crate::observability::record_outcome(&span, outcome);
                tracing::warn!(code = error.code(), error = %error, "bilateral lane reset");
                connection.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::identity::transport_endorsement_preimage;
    use crate::identity::TransportDirectoryBundleBody;
    use crate::identity::TransportDirectoryBundleDocument;
    use crate::identity::TransportDirectoryBundleTrust;
    use crate::identity::TransportDirectoryDocument;
    use crate::identity::TransportDirectoryEntry;
    use crate::identity::TrustedTransportDirectoryIssuer;
    use crate::identity::VerifiedDirectory;
    use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::sha256_hex;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;
    use iroh::RelayMode;
    use iroh::SecretKey;
    use std::net::Ipv4Addr;

    const NOW: u64 = 2_000_000;
    const TOOL_HOST_KERNEL: &str = "did:chio:org-b";
    const ORIGIN_KERNEL: &str = "did:chio:org-a";
    const ISSUER: &str = "did:chio:issuer";
    const KEY_ID: &str = "issuer-key-1";

    /// A federation participant: an ed25519 transport identity plus a long-term
    /// passport keypair (the co-signing key material).
    struct Peer {
        kernel_id: String,
        transport_secret: SecretKey,
        transport_id: EndpointId,
        passport: Keypair,
    }

    impl Peer {
        fn new(kernel_id: &str, transport_seed: u8, passport_seed: u8) -> Self {
            let transport_secret = SecretKey::from_bytes(&[transport_seed; 32]);
            let transport_id = transport_secret.public();
            Self {
                kernel_id: kernel_id.to_string(),
                transport_secret,
                transport_id,
                passport: Keypair::from_seed(&[passport_seed; 32]),
            }
        }

        fn entry(&self) -> TransportDirectoryEntry {
            TransportDirectoryEntry {
                kernel_id: self.kernel_id.clone(),
                passport_public_key: self.passport.public_key(),
                transport_endpoint_id: self.transport_id,
                passport_endorsement: self.passport.sign(&transport_endorsement_preimage(
                    &self.kernel_id,
                    &self.transport_id,
                )),
                revocation_signers: Vec::new(),
                removed: false,
            }
        }
    }

    /// Build a load-time-verified directory admitting the given peers.
    fn verified_directory(peers: &[&Peer]) -> Arc<VerifiedDirectory> {
        let issuer = Keypair::from_seed(&[240; 32]);
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: ORIGIN_KERNEL.to_string(),
            peers: peers.iter().map(|peer| peer.entry()).collect(),
            treaties: Vec::new(),
        };
        let directory_sha256 = sha256_hex(&canonical_json_bytes(&directory).unwrap());
        let body = TransportDirectoryBundleBody {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            issuer: ISSUER.to_string(),
            key_id: KEY_ID.to_string(),
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
                issuer: ISSUER.to_string(),
                key_id: KEY_ID.to_string(),
                public_key: issuer.public_key(),
            }],
            version_floor: 0,
            expected_previous_version_sha256: None,
            now_unix_ms: NOW,
        };
        Arc::new(bundle.verify_bundle(&trust).expect("bundle verifies"))
    }

    /// Spin up Org A: a loopback endpoint with the gate hook installed and the
    /// bilateral handler mounted on a `Router`. Returns the endpoint address, the
    /// live router (kept alive by the caller), and the gate.
    async fn spawn_org_a(
        org_a: &Peer,
        gate: DirectoryGate,
        passport_keys: Arc<dyn PinnedPassportKeys>,
    ) -> (EndpointAddr, Router) {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(org_a.transport_secret.clone())
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .hooks(gate.clone())
            .bind()
            .await
            .expect("org a endpoint binds");

        let socket = endpoint.bound_sockets()[0];
        let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);

        let handler = BilateralCoSignHandler::new(
            gate,
            org_a.kernel_id.clone(),
            org_a.passport.clone(),
            passport_keys,
        );
        let router = Router::builder(endpoint)
            .accept(ALPN_BILATERAL, handler)
            .spawn();
        (addr, router)
    }

    /// Build Org B: a loopback client endpoint plus a co-signer that dials `addr`
    /// for `org_a_kernel_id`.
    async fn spawn_org_b(
        org_b: &Peer,
        org_a_kernel_id: &str,
        addr: EndpointAddr,
    ) -> IrohBilateralCoSigner {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(org_b.transport_secret.clone())
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("org b endpoint binds");
        let mut book: HashMap<String, EndpointAddr> = HashMap::new();
        book.insert(org_a_kernel_id.to_string(), addr);
        IrohBilateralCoSigner::new(endpoint, Arc::new(book))
    }

    /// Org B signs the PAE bytes with its passport key and assembles the request.
    fn org_b_request(
        org_b: &Peer,
        org_a_kernel_id: &str,
        pae_bytes: &[u8],
    ) -> DsseCoSigningRequest {
        let org_b_signature = org_b.passport.sign(pae_bytes);
        DsseCoSigningRequest::new(
            org_a_kernel_id.to_string(),
            org_b.kernel_id.clone(),
            pae_bytes.to_vec(),
            org_b_signature,
        )
    }

    fn pinned_org_b(org_b: &Peer) -> Arc<dyn PinnedPassportKeys> {
        let mut keys: HashMap<String, PublicKey> = HashMap::new();
        keys.insert(org_b.kernel_id.clone(), org_b.passport.public_key());
        Arc::new(keys)
    }

    #[tokio::test]
    async fn full_cosign_succeeds_and_response_verifies_over_pae_bytes() {
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

        let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

        let pae_bytes = b"DSSEv1 opaque bilateral pae preimage".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

        let response = cosigner
            .request_dsse_cosignature_over_iroh(&request)
            .await
            .expect("co-sign succeeds");

        assert_eq!(response.schema, BILATERAL_DSSE_COSIGNING_SCHEMA);
        // The contract: Org A's signature verifies over the exact pae_bytes
        // against Org A's pinned passport key.
        assert!(org_a
            .passport
            .public_key()
            .verify(&pae_bytes, &response.org_a_signature));
        // And it does NOT verify over different bytes (sanity).
        assert!(!org_a
            .passport
            .public_key()
            .verify(b"other bytes", &response.org_a_signature));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cosign_over_the_sync_protocol_trait_contract() {
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

        let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

        let pae_bytes = b"DSSEv1 trait-path pae preimage".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

        // Drive the SYNC BilateralCoSigningProtocol contract (block_in_place path).
        let cosigner_for_call = cosigner.clone();
        let request_for_call = request.clone();
        let response = tokio::task::spawn(async move {
            cosigner_for_call.request_dsse_cosignature(&request_for_call)
        })
        .await
        .expect("join")
        .expect("trait co-sign succeeds");

        assert!(org_a
            .passport
            .public_key()
            .verify(&pae_bytes, &response.org_a_signature));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sync_cosign_on_current_thread_runtime_fails_closed_without_panicking() {
        // On a CURRENT-THREAD tokio runtime `block_in_place` would panic. The sync
        // BilateralCoSigningProtocol entry point must instead fail closed with a
        // TransportFailure (mirrors the multi-thread sync-trait test, which
        // succeeds via `block_in_place`). No live server is needed: the
        // current-thread guard trips before any dial.
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(org_b.transport_secret.clone())
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("org b endpoint binds");
        // An empty address book is fine: the guard returns before resolving Org A.
        let book: HashMap<String, EndpointAddr> = HashMap::new();
        let cosigner = IrohBilateralCoSigner::new(endpoint, Arc::new(book));

        let pae_bytes = b"pae on a current-thread runtime".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

        // Must NOT panic; must return a typed TransportFailure fail-closed.
        let result = cosigner.request_dsse_cosignature(&request);
        assert!(
            matches!(result, Err(BilateralCoSigningError::TransportFailure(_))),
            "sync co-sign on a current-thread runtime must fail closed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn mismatched_org_b_kernel_id_is_rejected_without_signing() {
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

        let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

        // Org B is admitted as `did:chio:org-b`, but CLAIMS to be someone else.
        let pae_bytes = b"pae for a spoofed org_b".to_vec();
        let org_b_signature = org_b.passport.sign(&pae_bytes);
        let request = DsseCoSigningRequest::new(
            ORIGIN_KERNEL.to_string(),
            "did:chio:evil-impersonator".to_string(),
            pae_bytes,
            org_b_signature,
        );

        let result = cosigner.request_dsse_cosignature_over_iroh(&request).await;
        assert_eq!(
            result,
            Err(BilateralCoSigningError::UnknownPeer(
                "did:chio:evil-impersonator".to_string()
            )),
            "the authenticated endpoint must match the claimed org_b_kernel_id"
        );
    }

    #[tokio::test]
    async fn bad_org_b_signature_is_rejected_without_signing() {
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

        let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

        // The signature is over DIFFERENT bytes than the pae_bytes carried, so the
        // server's verify(pae_bytes, org_b_signature) fails.
        let pae_bytes = b"the bytes org a is asked to co-sign".to_vec();
        let wrong_signature = org_b.passport.sign(b"a different message entirely");
        let request = DsseCoSigningRequest::new(
            ORIGIN_KERNEL.to_string(),
            org_b.kernel_id.clone(),
            pae_bytes,
            wrong_signature,
        );

        let result = cosigner.request_dsse_cosignature_over_iroh(&request).await;
        assert_eq!(
            result,
            Err(BilateralCoSigningError::OrgBSignatureInvalid),
            "a bad org_b signature must be refused without producing org_a's signature"
        );
    }

    #[tokio::test]
    async fn unbound_endpoint_is_rejected_at_the_gate() {
        // The server's directory admits only org_a; the client (org_b) is NOT in
        // it, so the accept-time gate 403-rejects at handshake and no handler runs.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a]));

        let (addr, _router) = spawn_org_a(&org_a, gate, pinned_org_b(&org_b)).await;
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

        let pae_bytes = b"pae from an unadmitted peer".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

        let result = cosigner.request_dsse_cosignature_over_iroh(&request).await;
        assert!(
            matches!(result, Err(BilateralCoSigningError::TransportFailure(_))),
            "an unadmitted endpoint is rejected by the gate; got {result:?}"
        );
    }

    #[test]
    fn cosign_unit_rejects_wrong_origin_without_signing() {
        // Pure (no-network) proof of the fail-closed origin check: a request
        // addressed to a different Org A yields UnknownPeer and no signature.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let handler = BilateralCoSignHandler::new(
            gate,
            ORIGIN_KERNEL,
            org_a.passport.clone(),
            pinned_org_b(&org_b),
        );

        let pae_bytes = b"pae".to_vec();
        let request = DsseCoSigningRequest::new(
            "did:chio:some-other-origin".to_string(),
            org_b.kernel_id.clone(),
            pae_bytes.clone(),
            org_b.passport.sign(&pae_bytes),
        );
        assert_eq!(
            handler.cosign(&org_b.transport_id, &request),
            Err(BilateralCoSigningError::UnknownPeer(
                "did:chio:some-other-origin".to_string()
            ))
        );
    }

    #[test]
    fn wrong_origin_bumps_verify_failure_counter_and_is_still_rejected() {
        // OBSERVE-ONLY proof: a request addressed to a different Org A is refused
        // WITHOUT signing (byte-identical Err) AND bumps verify_failures{bilateral}.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let handler = BilateralCoSignHandler::new(
            gate,
            ORIGIN_KERNEL,
            org_a.passport.clone(),
            pinned_org_b(&org_b),
        );

        let pae_bytes = b"pae".to_vec();
        let request = DsseCoSigningRequest::new(
            "did:chio:some-other-origin".to_string(),
            org_b.kernel_id.clone(),
            pae_bytes.clone(),
            org_b.passport.sign(&pae_bytes),
        );

        let before =
            crate::metrics::verify_failures_total(crate::metrics::SEAM_BILATERAL, "unknown-peer");
        let result = handler.cosign(&org_b.transport_id, &request);
        assert_eq!(
            result,
            Err(BilateralCoSigningError::UnknownPeer(
                "did:chio:some-other-origin".to_string()
            ))
        );
        assert!(
            crate::metrics::verify_failures_total(crate::metrics::SEAM_BILATERAL, "unknown-peer")
                > before,
            "the co-sign rejection must be counted (observe-only)"
        );
    }

    #[test]
    fn cosign_unit_verifies_against_the_directory_bound_passport_key() {
        // The happy path of the directory-bound key: when the pinned map AGREES
        // with the verified directory's current binding for Org B, a request
        // signed with that key is co-signed. Pure (no network) proof that
        // verification now flows through the directory snapshot.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let handler = BilateralCoSignHandler::new(
            gate,
            ORIGIN_KERNEL,
            org_a.passport.clone(),
            pinned_org_b(&org_b),
        );

        let pae_bytes = b"pae bound to the directory passport".to_vec();
        let request = DsseCoSigningRequest::new(
            ORIGIN_KERNEL.to_string(),
            org_b.kernel_id.clone(),
            pae_bytes.clone(),
            org_b.passport.sign(&pae_bytes),
        );
        let response = handler
            .cosign(&org_b.transport_id, &request)
            .expect("a request signed with the directory-bound passport co-signs");
        assert!(org_a
            .passport
            .public_key()
            .verify(&pae_bytes, &response.org_a_signature));
    }

    #[test]
    fn cosign_unit_rejects_endpoint_absent_from_the_current_directory_snapshot() {
        // Single-snapshot verification. Endpoint authorization AND the passport-key
        // lookup are read from ONE `directory()` snapshot, so a directory
        // reload can never authorize the endpoint against one directory while reading the key
        // from another. This locks in that authorization is sourced from the CURRENT
        // directory snapshot: if that snapshot no longer binds the remote endpoint (rotated
        // away / removed), cosign fails closed even for an otherwise-valid, correctly-signed
        // request whose key is still pinned - the key is looked up from the SAME snapshot that
        // failed to authorize the endpoint, so a rotated-away peer can never co-sign.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        // The CURRENT directory admits only org_a; org_b's endpoint is NOT bound here.
        let gate = DirectoryGate::new(verified_directory(&[&org_a]));
        let handler = BilateralCoSignHandler::new(
            gate,
            ORIGIN_KERNEL,
            org_a.passport.clone(),
            // org_b's key is still pinned, so the rejection is due ONLY to the current
            // snapshot not authorizing the endpoint, not a pinned-map miss.
            pinned_org_b(&org_b),
        );
        let pae_bytes = b"pae from a rotated-away peer".to_vec();
        let request = DsseCoSigningRequest::new(
            ORIGIN_KERNEL.to_string(),
            org_b.kernel_id.clone(),
            pae_bytes.clone(),
            org_b.passport.sign(&pae_bytes),
        );
        assert_eq!(
            handler.cosign(&org_b.transport_id, &request),
            Err(BilateralCoSigningError::UnknownPeer(
                org_b.kernel_id.clone()
            )),
            "a peer the current directory snapshot does not authorize cannot co-sign"
        );
    }

    #[test]
    fn lagging_pinned_passport_key_is_rejected_without_signing() {
        // The DSSE-verification key must be bound to the same verified
        // directory the gate admitted on. If an out-of-band pinned map LAGS the
        // signed directory (pins a different passport key than the directory's
        // current binding for Org B), Org A must refuse to co-sign - otherwise an
        // authenticated peer could obtain a co-signature under a passport the
        // current directory no longer pins. Fail-closed, before signing.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        // The directory binds org_b's CURRENT passport (seed 2 via `Peer::new`).
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));

        // The pinned map lags: it still pins a STALE/rotated-away key (seed 99),
        // not the key the verified directory currently binds for org_b.
        let stale_passport = Keypair::from_seed(&[99u8; 32]);
        assert_ne!(stale_passport.public_key(), org_b.passport.public_key());
        let mut stale: HashMap<String, PublicKey> = HashMap::new();
        stale.insert(org_b.kernel_id.clone(), stale_passport.public_key());
        let handler = BilateralCoSignHandler::new(
            gate,
            ORIGIN_KERNEL,
            org_a.passport.clone(),
            Arc::new(stale),
        );

        // Org B signs with its CURRENT (directory-bound) passport. Even a
        // perfectly valid signature is refused because the pinned map disagrees
        // with the signed directory: the lag is caught before any co-signature.
        let pae_bytes = b"pae under a lagging pinned map".to_vec();
        let request = DsseCoSigningRequest::new(
            ORIGIN_KERNEL.to_string(),
            org_b.kernel_id.clone(),
            pae_bytes.clone(),
            org_b.passport.sign(&pae_bytes),
        );
        assert_eq!(
            handler.cosign(&org_b.transport_id, &request),
            Err(BilateralCoSigningError::OrgBSignatureInvalid),
            "a pinned passport key that lags the signed directory must be refused without signing"
        );
    }

    // -- Production-robustness: bounded accept over real loopback QUIC --
    //
    // These drive the REAL `BilateralCoSignHandler::accept` (through its bounded
    // `serve` + concurrency cap) against deliberately misbehaving dialers. The
    // bounds only limit WAITING; a slow/stalled/never-closing peer is dropped
    // fail-closed, and a legitimate exchange within the bounds is still fully
    // verified and co-signed (timeouts never weaken the trust path).

    use std::time::Duration;

    /// Spin up Org A exactly like [`spawn_org_a`] but with explicit accept bounds.
    async fn spawn_org_a_with_limits(
        org_a: &Peer,
        gate: DirectoryGate,
        passport_keys: Arc<dyn PinnedPassportKeys>,
        limits: AcceptLimitConfig,
    ) -> (EndpointAddr, Router) {
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(org_a.transport_secret.clone())
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .hooks(gate.clone())
            .bind()
            .await
            .expect("org a endpoint binds");
        let socket = endpoint.bound_sockets()[0];
        let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);
        let handler = BilateralCoSignHandler::new(
            gate,
            org_a.kernel_id.clone(),
            org_a.passport.clone(),
            passport_keys,
        )
        .with_accept_limits(limits);
        let router = Router::builder(endpoint)
            .accept(ALPN_BILATERAL, handler)
            .spawn();
        (addr, router)
    }

    /// A raw admitted dialer endpoint (for hand-driven, misbehaving clients).
    async fn bind_peer(peer: &Peer) -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .secret_key(peer.transport_secret.clone())
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("peer endpoint binds")
    }

    /// Small per-phase bounds so an INFINITE stall trips promptly; the concurrency
    /// cap stays at the generous default (not exercised by the slowloris tests).
    fn stall_bounds() -> AcceptLimitConfig {
        AcceptLimitConfig {
            accept_stream_timeout: Duration::from_millis(300),
            read_timeout: Duration::from_millis(300),
            write_timeout: Duration::from_millis(300),
            linger_timeout: Duration::from_millis(300),
            ..AcceptLimitConfig::default()
        }
    }

    #[tokio::test]
    async fn legit_cosign_within_tight_bounds_is_still_fully_verified_and_accepted() {
        // The CRITICAL trust-path test: with real (tight but sufficient) bounds
        // active, a valid request is still fully verified and co-signed, and the
        // response verifies over the exact pae_bytes. Timeouts bound waiting only.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let limits = AcceptLimitConfig {
            accept_stream_timeout: Duration::from_secs(4),
            read_timeout: Duration::from_secs(4),
            write_timeout: Duration::from_secs(4),
            linger_timeout: Duration::from_secs(4),
            ..AcceptLimitConfig::default()
        };

        let (addr, _router) =
            spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), limits).await;
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr).await;

        let pae_bytes = b"DSSEv1 opaque bilateral pae preimage (bounded path)".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);

        let response = cosigner
            .request_dsse_cosignature_over_iroh(&request)
            .await
            .expect("a legitimate exchange within the bounds still co-signs");
        assert_eq!(response.schema, BILATERAL_DSSE_COSIGNING_SCHEMA);
        assert!(
            org_a
                .passport
                .public_key()
                .verify(&pae_bytes, &response.org_a_signature),
            "the co-signature verifies over the exact pae_bytes: verification was not weakened"
        );
    }

    #[tokio::test]
    async fn peer_that_never_opens_a_stream_is_dropped_within_accept_bi_bound() {
        // An admitted peer connects (handshake completes, handler runs) but never
        // opens its bidi stream. The bounded accept_bi drops it fail-closed.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let (addr, _router) =
            spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), stall_bounds()).await;

        let dialer = bind_peer(&org_b).await;
        let conn = dialer
            .connect(addr, ALPN_BILATERAL)
            .await
            .expect("admitted dialer connects");
        // Never open_bi. The server must close within the accept_bi bound; give a
        // wide outer window so only a genuine hang (not scheduling jitter) fails.
        let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        assert!(
            closed.is_ok(),
            "server must drop a peer that never opens a stream, not hang on accept_bi"
        );
    }

    #[tokio::test]
    async fn slowloris_length_prefix_without_body_is_dropped_within_read_bound() {
        // THE key slowloris test: the peer opens its stream and sends a length
        // prefix declaring a body it never sends. The bounded frame read drops it
        // fail-closed rather than blocking the handler task on read_exact forever.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let (addr, _router) =
            spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), stall_bounds()).await;

        let dialer = bind_peer(&org_b).await;
        let conn = dialer
            .connect(addr, ALPN_BILATERAL)
            .await
            .expect("admitted dialer connects");
        let (mut send, _recv) = conn.open_bi().await.expect("dialer opens bi stream");
        // Declare a 4096-byte frame, then send NOTHING more and never finish.
        send.write_all(&4096u32.to_be_bytes())
            .await
            .expect("dialer writes only the length prefix");
        // Deliberately no body, no finish(): the classic slowloris dribble.

        let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        assert!(
            closed.is_ok(),
            "server must drop a peer that sends a length prefix then withholds the body"
        );
    }

    #[tokio::test]
    async fn peer_that_completes_exchange_but_never_closes_does_not_hang_past_linger() {
        // The peer runs a full, valid exchange (and gets a real co-signature) but
        // then never closes the connection. The bounded linger releases the
        // handler task instead of pinning it on conn.closed() forever.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b]));
        let (addr, _router) =
            spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), stall_bounds()).await;

        let dialer = bind_peer(&org_b).await;
        let conn = dialer
            .connect(addr, ALPN_BILATERAL)
            .await
            .expect("admitted dialer connects");
        let (mut send, mut recv) = conn.open_bi().await.expect("dialer opens bi stream");

        let pae_bytes = b"pae for the never-close linger test".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);
        let request_bytes =
            serde_json::to_vec(&WireDsseCoSigningRequest::from_request(&request)).unwrap();
        write_frame(&mut send, &request_bytes)
            .await
            .expect("write request frame");
        send.finish().expect("half-close the request stream");

        let reply_bytes = read_frame(&mut recv).await.expect("read the reply frame");
        let reply: WireReply = serde_json::from_slice(&reply_bytes).unwrap();
        let response = reply
            .into_result()
            .expect("the full exchange yields a real co-signature");
        assert!(
            org_a
                .passport
                .public_key()
                .verify(&pae_bytes, &response.org_a_signature),
            "the co-signature is valid: the exchange genuinely completed"
        );

        // Now hold the connection open (never close). The server must stop
        // lingering within its linger bound and drop the connection, which the
        // dialer observes as `closed()` resolving. A hang would time out here.
        let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        assert!(
            closed.is_ok(),
            "server must not hang past the linger bound waiting for a peer that never closes"
        );
    }

    #[tokio::test]
    async fn saturated_concurrency_cap_sheds_an_additional_dialer_over_quic() {
        // Cap = 1. Dialer A opens a stream and stalls the read, holding the sole
        // in-flight permit. While it is held, dialer C is shed after the bounded
        // wait: one peer cannot starve the lane, and back-pressure is bounded.
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let org_c = Peer::new("did:chio:org-c", 12, 3);
        let gate = DirectoryGate::new(verified_directory(&[&org_a, &org_b, &org_c]));
        let limits = AcceptLimitConfig {
            max_in_flight: 1,
            accept_stream_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(3),
            shed_wait: Duration::from_millis(150),
            ..AcceptLimitConfig::default()
        };
        let (addr, _router) =
            spawn_org_a_with_limits(&org_a, gate, pinned_org_b(&org_b), limits).await;

        // A holds the single permit by stalling in the bounded read.
        let dialer_a = bind_peer(&org_b).await;
        let conn_a = dialer_a
            .connect(addr.clone(), ALPN_BILATERAL)
            .await
            .expect("dialer A connects");
        let (mut send_a, _recv_a) = conn_a.open_bi().await.expect("A opens bi stream");
        send_a
            .write_all(&512u32.to_be_bytes())
            .await
            .expect("A sends a length prefix then stalls");
        // Let A's accept task acquire the sole permit and enter the bounded read.
        tokio::time::sleep(Duration::from_millis(400)).await;

        // C dials for a full co-sign, but the cap is saturated: it is shed.
        let cosigner_c = spawn_org_b(&org_c, ORIGIN_KERNEL, addr).await;
        let request_c = org_b_request(&org_c, ORIGIN_KERNEL, b"pae from a shed dialer");
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            cosigner_c.request_dsse_cosignature_over_iroh(&request_c),
        )
        .await
        .expect("the shed dialer resolves quickly (bounded wait, not unbounded)");
        assert!(
            result.is_err(),
            "a dialer must be shed while the single in-flight permit is held, got {result:?}"
        );

        drop(conn_a);
    }

    // -- Client-side slowloris bound: a silent Org A must not hang the caller --
    //
    // An Org A that accepts the connection and reads the request but never returns
    // the reply frame must not hang the dialer forever. This handler is that
    // admitted-but-silent Org A.

    #[derive(Debug, Clone)]
    struct SilentAfterReadBilateralHandler;

    impl ProtocolHandler for SilentAfterReadBilateralHandler {
        async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
            let (mut _send, mut recv) = connection.accept_bi().await?;
            // Read the request frame, then deliberately never write the reply.
            let _request = read_frame(&mut recv).await.map_err(AcceptError::from_err)?;
            connection.closed().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn client_read_bound_drops_an_org_a_that_never_replies() {
        // No admission gate installed: this isolates the CLIENT read bound (Org A
        // handshakes and reads the request, then goes silent).
        let org_a = Peer::new(ORIGIN_KERNEL, 10, 1);
        let org_b = Peer::new(TOOL_HOST_KERNEL, 11, 2);
        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(org_a.transport_secret.clone())
            .relay_mode(RelayMode::Disabled)
            .bind_addr((Ipv4Addr::LOCALHOST, 0))
            .expect("valid loopback bind addr")
            .bind()
            .await
            .expect("org a endpoint binds");
        let socket = endpoint.bound_sockets()[0];
        let addr = EndpointAddr::new(org_a.transport_id).with_ip_addr(socket);
        let router = Router::builder(endpoint)
            .accept(ALPN_BILATERAL, SilentAfterReadBilateralHandler)
            .spawn();

        // A tight read bound; connect/open/write keep their generous defaults so only
        // the (hung) reply read trips.
        let cosigner = spawn_org_b(&org_b, ORIGIN_KERNEL, addr)
            .await
            .with_accept_limits(AcceptLimitConfig {
                read_timeout: Duration::from_millis(200),
                ..AcceptLimitConfig::default()
            });

        let pae_bytes = b"pae for a silent org a".to_vec();
        let request = org_b_request(&org_b, ORIGIN_KERNEL, &pae_bytes);
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            cosigner.request_dsse_cosignature_over_iroh(&request),
        )
        .await
        .expect("the client read bound must fire well before the outer test timeout");
        assert!(
            matches!(result, Err(BilateralCoSigningError::TransportFailure(_))),
            "a silent org a must fail closed at the client read bound, got {result:?}"
        );

        router.shutdown().await.ok();
    }
}
