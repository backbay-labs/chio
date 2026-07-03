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
//!    exact `pae_bytes` against Org B's pinned passport key (algorithm-agnostic,
//!    above iroh, via [`chio_core_types::PublicKey::verify`]), and re-checks trust /
//!    rotation-window through the same directory resolution. On ANY failure it
//!    writes a typed error mirroring [`BilateralCoSigningError`] and terminates
//!    WITHOUT signing.
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
/// This mirrors `InProcessCoSigner`'s single `tool_host_public_key`: Org A
/// verifies Org B's signature over `pae_bytes` against the algorithm-agnostic
/// passport key pinned here (above iroh, via [`PublicKey::verify`]). The passport
/// key is deliberately NOT the ed25519 transport `EndpointId` (Option B: a
/// non-ed25519 passport cannot be an `EndpointId`).
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
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf)
        .await
        .map_err(|error| WireError::Io(error.to_string()))?;
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
    /// resolver.
    #[must_use]
    pub fn new(endpoint: Endpoint, address_book: Arc<dyn OrgAddressBook>) -> Self {
        Self {
            endpoint,
            address_book,
        }
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

        let connection = self
            .endpoint
            .connect(addr, ALPN_BILATERAL)
            .await
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
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let request_bytes = serde_json::to_vec(&WireDsseCoSigningRequest::from_request(request))
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        write_frame(&mut send, &request_bytes)
            .await
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        send.finish()
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;

        let reply_bytes = read_frame(&mut recv)
            .await
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        let reply: WireReply = serde_json::from_slice(&reply_bytes)
            .map_err(|error| BilateralCoSigningError::TransportFailure(error.to_string()))?;
        reply.into_result()
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
    /// [`Self::request_dsse_cosignature_over_iroh`]. MUST be called either from a
    /// multi-threaded tokio runtime (uses `block_in_place`) or from a plain
    /// (non-async) thread (spins a private current-thread runtime). Prefer the
    /// async method inside async code.
    fn request_dsse_cosignature(
        &self,
        request: &DsseCoSigningRequest,
    ) -> Result<DsseCoSigningResponse, BilateralCoSigningError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(self.request_dsse_cosignature_over_iroh(request))
            }),
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
        }
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
        // Transport-origin binding: the authenticated EndpointId must resolve to
        // the claimed Org B kernel id. `resolve` returns None for unbound/removed
        // peers (trust + rotation window at the directory layer); the gate should
        // already have rejected those at handshake, so None here is defense in
        // depth. A resolved-but-mismatched id means the caller claimed to be a
        // different peer than it authenticated as: fail closed.
        let resolved = self
            .gate
            .resolve(remote)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_b_kernel_id.clone()))?;
        if resolved != request.org_b_kernel_id {
            return Err(BilateralCoSigningError::UnknownPeer(
                request.org_b_kernel_id.clone(),
            ));
        }
        // Org B's pinned passport key (any algorithm), verified above iroh.
        let org_b_key = self
            .passport_keys
            .passport_key(&request.org_b_kernel_id)
            .ok_or_else(|| BilateralCoSigningError::UnknownPeer(request.org_b_kernel_id.clone()))?;
        if !org_b_key.verify(&request.pae_bytes, &request.org_b_signature) {
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

impl ProtocolHandler for BilateralCoSignHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        // Infallible after the handshake; the gate hook has already run.
        let remote = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await?;

        // Step 3: read the single length-delimited request.
        let request_bytes = read_frame(&mut recv).await.map_err(AcceptError::from_err)?;
        let wire_request: WireDsseCoSigningRequest =
            serde_json::from_slice(&request_bytes).map_err(AcceptError::from_err)?;
        let request = wire_request.into_request();

        // Step 4/5: verify + co-sign (or a typed error mirroring the contract).
        // A rejection is delivered IN-BAND as a typed error frame and never
        // carries a signature; only genuine transport failures reset the stream.
        let reply = match self.cosign(&remote, &request) {
            Ok(response) => WireReply::ok(&response),
            Err(error) => WireReply::err(&error),
        };
        let reply_bytes = serde_json::to_vec(&reply).map_err(AcceptError::from_err)?;
        write_frame(&mut send, &reply_bytes)
            .await
            .map_err(AcceptError::from_err)?;
        send.finish()?;

        // Keep the connection until the client has read the reply and closed, so
        // the framed response is not truncated by an early drop.
        connection.closed().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
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
                passport_endorsement: self.passport.sign(self.transport_id.as_bytes()),
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
}
