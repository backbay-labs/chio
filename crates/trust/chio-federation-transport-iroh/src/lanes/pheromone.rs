//! Lane a: pheromone directed batches over a direct per-peer QUIC stream.
//! ADAPTER-SPEC section 4 row (a) + section 3.3; blueprint LANE A.
//!
//! This is the iroh migration of the shipped `chio-pheromone-relay` HTTP
//! transport. It swaps exactly one hop: on the shipped HTTP path the
//! `authenticated_sender_kernel_id` handed to
//! [`RelayBatchReceiver::receive_batch`] comes from HTTP-signature verification;
//! here it comes from the admission-resolved `kernel_id` bound to the
//! cryptographically authenticated iroh `EndpointId` (`conn.remote_id()`).
//! Everything below that seam (`receive_batch` -> receiver config -> per-frame
//! `chio-federation` verifier) is REUSED byte-for-byte, so the per-frame checks
//! at `pheromone_gossip.rs:236` (`gossiping_peer_kernel_id == authenticated
//! sender`) and `:244` (direct `origin_kernel_id == authenticated sender`) run
//! ABOVE the transport, unchanged.
//!
//! Defense in depth (ADAPTER-SPEC section 5, ADR-0014 Drop-In Seam step 3): the
//! accept-time [`DirectoryGate`](crate::admission::DirectoryGate) rejects
//! unbound endpoints at `after_handshake` BEFORE any handler runs, AND the
//! handler re-resolves `conn.remote_id()` (fail-closed) before feeding the
//! per-frame verifier. Both layers are kept.
//!
//! Store-and-forward reuses the shipped `SqlitePheromoneRelayStore` outbox/inbox
//! verbatim (blueprint LANE A.3): [`enqueue_batch_for_delivery`] enqueues on
//! flush, [`drain_outbox_over_iroh`] mirrors `deliver_due_batches`
//! (`service.rs:609`) with the ONLY substitution being an iroh `open_bi` write
//! in place of the HTTP `post_batch`, and the handler records the inbox for
//! idempotent dedup.
//!
//! Note on the seam boundary: `PheromoneReceiveReport` lives in
//! `chio-pheromone-runtime`, which is not a direct dependency of this adapter
//! (only `chio-pheromone-relay` is). The handler therefore never names that type
//! (it flows through by inference from [`RelayBatchReceiver::receive_batch`]),
//! and the dial side exposes the peer's report as raw canonical bytes plus the
//! parsed `accepted` flag ([`BatchDeliveryOutcome`]).

use std::fmt;
use std::sync::Arc;

use chio_core_types::canonical_json_bytes;
use chio_core_types::sha256_hex;
use chio_federation::pheromone_gossip::PheromoneGossipBatch;
use chio_pheromone_relay::PheromoneRelayError;
use chio_pheromone_relay::RelayBatchReceiver;
use chio_pheromone_relay::RelayOutboxBatch;
use chio_pheromone_relay::SqlitePheromoneRelayStore;
use iroh::endpoint::Connection;
use iroh::protocol::AcceptError;
use iroh::protocol::ProtocolHandler;
use iroh::protocol::Router;
use iroh::Endpoint;
use iroh::EndpointAddr;
use iroh::EndpointId;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;

use crate::admission::DirectoryGate;
use crate::lanes::limits::AcceptLimitConfig;
use crate::lanes::limits::AcceptLimitError;
use crate::lanes::limits::AcceptLimiter;
use crate::lanes::limits::AcceptPhase;

/// ALPN for the pheromone directed-batch lane. Distinct, versioned, mounted on
/// its own `Router` accept (ADAPTER-SPEC 4 lane a, blueprint A.2).
pub const ALPN_PHEROMONE_BATCH: &[u8] = b"chio/federation/pheromone-batch/1";

/// Hard cap on a single length-delimited frame (request batch or response
/// report). Fail-closed: a larger declared length is rejected before any
/// allocation, so a peer cannot force an unbounded buffer.
pub const MAX_PHEROMONE_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// QUIC application close code used when the handler resets a stream after a
/// fail-closed lane error (distinct from the admission gate's 403).
pub const LANE_RESET_ERROR_CODE: u32 = 1;

/// QUIC application close code used on a clean dial-side teardown.
const LANE_OK_CODE: u32 = 0;

/// Errors raised inside the pheromone lane. Every variant is fail-closed: an
/// error denies the batch (handler side resets the stream; sender side folds
/// into the durable outbox retry/dead-letter path via [`IrohLaneError::code`]).
#[derive(Debug, thiserror::Error)]
pub enum IrohLaneError {
    /// An endpoint that the admission gate should already have rejected reached
    /// the handler and did not resolve to an admitted, non-removed `kernel_id`.
    /// Unreachable past the gate; treated as a defense-in-depth reset.
    #[error("unadmitted endpoint reached pheromone lane handler: {0}")]
    Unadmitted(String),
    /// A length-delimited frame declared or carried more than
    /// [`MAX_PHEROMONE_BATCH_BYTES`] bytes.
    #[error("pheromone batch frame of {0} bytes exceeds the transport cap")]
    FrameTooLarge(usize),
    /// A stream read/write (framing) io error.
    #[error("pheromone lane io error: {0}")]
    Io(#[from] std::io::Error),
    /// A batch or report failed JSON (de)serialization.
    #[error("pheromone lane codec error: {0}")]
    Codec(#[from] serde_json::Error),
    /// Canonical-JSON encoding of an outbound value failed.
    #[error("pheromone lane canonical-json error: {0}")]
    CanonicalJson(String),
    /// An iroh transport failure (connect, open/accept stream, finish, reset).
    #[error("pheromone lane transport error: {0}")]
    Transport(String),
    /// The reused relay receiver / store rejected the batch (the per-frame
    /// verifier and inbox dedup live behind this seam).
    #[error("pheromone relay error: {0}")]
    Relay(#[from] PheromoneRelayError),
    /// A peer-dependent accept step exceeded its bound (slowloris) or the
    /// in-flight cap shed the connection. Fail-closed: the connection is reset
    /// and NOTHING is verified or accepted.
    #[error(transparent)]
    AcceptLimit(#[from] AcceptLimitError),
}

impl IrohLaneError {
    /// Stable, log- and outbox-friendly code for this error. Relay failures
    /// delegate to [`PheromoneRelayError::code`] so the durable queue records
    /// the same code the shipped HTTP path would.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unadmitted(_) => "unadmitted",
            Self::FrameTooLarge(_) => "frame_too_large",
            Self::Io(_) => "io",
            Self::Codec(_) => "codec",
            Self::CanonicalJson(_) => "canonical_json",
            Self::Transport(_) => "transport",
            Self::Relay(error) => error.code(),
            Self::AcceptLimit(error) => error.code(),
        }
    }

    /// QUIC application close code for a fail-closed reset. Accept-limit outcomes
    /// (slowloris timeout / saturation shed) carry their own distinct codes so a
    /// stalled or shed peer is diagnosable on the wire; every other lane error is
    /// a generic reset.
    #[must_use]
    pub fn close_code(&self) -> u32 {
        match self {
            Self::AcceptLimit(error) => error.close_code(),
            _ => LANE_RESET_ERROR_CODE,
        }
    }
}

/// Re-resolve the authenticated `EndpointId` to its admitted `kernel_id`.
///
/// The admission gate has already guaranteed (fail-closed, at `after_handshake`)
/// that only bound, non-removed endpoints reach a handler, so this normally
/// yields `Some`; a `None` here is an unreachable defense-in-depth reset. The
/// returned string is the ONLY value the transport contributes to the per-frame
/// verifier's `authenticated_sender_kernel_id`.
fn resolve_authenticated_sender(
    gate: &DirectoryGate,
    remote: &EndpointId,
) -> Result<String, IrohLaneError> {
    gate.resolve(remote)
        .ok_or_else(|| IrohLaneError::Unadmitted(remote.fmt_short().to_string()))
}

/// Deterministic inbox nonce for a batch, so redelivery of the same batch dedups
/// idempotently at `record_inbox` (keyed on `(sender_kernel_id, nonce)`). Uses
/// the canonical batch hash, matching the store's own `batch_sha256`.
fn inbox_nonce(batch_bytes: &[u8]) -> String {
    format!("iroh-pheromone-batch:{}", sha256_hex(batch_bytes))
}

/// Read a `u32` big-endian length prefix followed by exactly that many bytes,
/// rejecting an over-cap declared length before allocating (fail-closed).
async fn read_len_delimited<R>(reader: &mut R) -> Result<Vec<u8>, IrohLaneError>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > MAX_PHEROMONE_BATCH_BYTES {
        return Err(IrohLaneError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a `u32` big-endian length prefix followed by the bytes. Does not
/// `finish()` the stream: the caller half-closes when appropriate.
async fn write_len_delimited<W>(writer: &mut W, bytes: &[u8]) -> Result<(), IrohLaneError>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(bytes.len()).map_err(|_| IrohLaneError::FrameTooLarge(bytes.len()))?;
    if bytes.len() > MAX_PHEROMONE_BATCH_BYTES {
        return Err(IrohLaneError::FrameTooLarge(bytes.len()));
    }
    writer.write_u32(len).await?;
    writer.write_all(bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Receiver side of lane a: a [`ProtocolHandler`] mounted on
/// [`ALPN_PHEROMONE_BATCH`].
///
/// On accept it re-resolves the authenticated sender from `conn.remote_id()`,
/// reads one length-delimited canonical [`PheromoneGossipBatch`], feeds the
/// reused [`RelayBatchReceiver::receive_batch`] with that resolved `kernel_id`
/// as the `authenticated_sender_kernel_id` (so the unchanged per-frame verifier
/// runs above the transport), records the inbox for idempotent dedup, and writes
/// the peer's report back on the same bidi stream.
#[derive(Clone)]
pub struct PheromoneBatchHandler {
    gate: DirectoryGate,
    receiver: Arc<dyn RelayBatchReceiver>,
    store: Arc<SqlitePheromoneRelayStore>,
    now: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
}

impl fmt::Debug for PheromoneBatchHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PheromoneBatchHandler")
            .field("gate", &self.gate)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

impl PheromoneBatchHandler {
    /// Build the handler from the admission gate (for re-resolution), the reused
    /// relay receiver seam, the shipped SQLite store (inbox dedup), and a clock.
    #[must_use]
    pub fn new(
        gate: DirectoryGate,
        receiver: Arc<dyn RelayBatchReceiver>,
        store: Arc<SqlitePheromoneRelayStore>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self {
            gate,
            receiver,
            store,
            now,
            limiter: AcceptLimiter::default(),
        }
    }

    /// Override the default accept-hardening bounds (per-phase timeouts + the
    /// in-flight concurrency cap). The [`Default`] preserves the historical
    /// (generous) behavior; the wiring can tighten or loosen it in one place.
    #[must_use]
    pub fn with_accept_limits(mut self, config: AcceptLimitConfig) -> Self {
        self.limiter = AcceptLimiter::new(config);
        self
    }

    async fn handle(&self, conn: &Connection) -> Result<(), IrohLaneError> {
        // The ONE hop that replaces the HTTP-signed sender: the authenticated
        // EndpointId, resolved through the load-time-verified directory.
        let authenticated_sender = resolve_authenticated_sender(&self.gate, &conn.remote_id())?;

        // Bound accept_bi: a connected-but-silent peer is dropped here.
        let (mut send, mut recv) = self
            .limiter
            .bounded(AcceptPhase::AcceptStream, conn.accept_bi())
            .await?
            .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

        // Bound the request-frame read: the primary slowloris surface (a large
        // declared length then a dribble of bytes is dropped here). Timeouts only
        // bound waiting; the verifier below runs on the fully received frame.
        let raw = self
            .limiter
            .bounded(AcceptPhase::ReadFrame, read_len_delimited(&mut recv))
            .await??;
        let batch: PheromoneGossipBatch = serde_json::from_slice(&raw)?;

        let now = (self.now)();
        // The report type (chio-pheromone-runtime PheromoneReceiveReport) is not
        // nameable here; it flows through by inference. The per-frame verifier
        // (pheromone_gossip.rs:236/244) runs inside this call, unchanged.
        let report = self
            .receiver
            .receive_batch(batch.clone(), authenticated_sender.clone(), now)
            .await?;

        let batch_bytes = canonical_json_bytes(&batch)
            .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;
        let nonce = inbox_nonce(&batch_bytes);
        self.store
            .record_inbox(&authenticated_sender, &nonce, &batch, &report)?;

        let report_bytes = canonical_json_bytes(&report)
            .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;
        // Bound the response write: a peer that stops reading is dropped here.
        self.limiter
            .bounded(
                AcceptPhase::WriteResponse,
                write_len_delimited(&mut send, &report_bytes),
            )
            .await??;
        send.finish()
            .map_err(|error| IrohLaneError::Transport(error.to_string()))?;
        Ok(())
    }
}

impl ProtocolHandler for PheromoneBatchHandler {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code, so one
        // hostile peer cannot spawn unbounded accept tasks.
        let _permit = match self.limiter.admit().await {
            Ok(permit) => permit,
            Err(error) => {
                tracing::warn!(
                    code = error.code(),
                    "pheromone lane shed accept (saturated)"
                );
                conn.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        match self.handle(&conn).await {
            Ok(()) => {
                // Bounded linger: keep the connection open until the dialer has
                // read the report and closed (so the finished stream is not reset
                // on drop), but never past the linger bound.
                self.limiter.linger(&conn).await;
                Ok(())
            }
            Err(error) => {
                tracing::warn!(code = error.code(), error = %error, "pheromone lane reset batch");
                conn.close(error.close_code().into(), error.code().as_bytes());
                Err(AcceptError::from_err(error))
            }
        }
    }
}

/// Mount the pheromone lane on its own ALPN. The admission
/// [`DirectoryGate`](crate::admission::DirectoryGate) must already be installed
/// on `endpoint` via `Endpoint::builder(..).hooks(gate)` so unbound endpoints
/// are rejected at `after_handshake` before this handler runs.
#[must_use]
pub fn mount_pheromone_lane(endpoint: Endpoint, handler: PheromoneBatchHandler) -> Router {
    Router::builder(endpoint)
        .accept(ALPN_PHEROMONE_BATCH, handler)
        .spawn()
}

/// Outcome of a single dial-side delivery: the peer's `accepted` verdict (parsed
/// from its report; fail-closed to `false` if absent) plus the raw canonical
/// report bytes for callers that hold the runtime report type.
#[derive(Debug, Clone)]
pub struct BatchDeliveryOutcome {
    /// Whether the receiving peer accepted the whole batch.
    pub accepted: bool,
    /// Canonical JSON bytes of the peer's `PheromoneReceiveReport`.
    pub report_json: Vec<u8>,
}

/// Sender side of lane a: dial a peer over [`ALPN_PHEROMONE_BATCH`], write one
/// length-delimited canonical [`PheromoneGossipBatch`], and read back the report.
///
/// The iroh replacement for `PheromoneRelayClient::post_batch`
/// (`service.rs:652`). `recipient_addr` is the peer resolved from its
/// `kernel_id` via the directory (an [`EndpointId`] in production with
/// discovery, or a full [`EndpointAddr`] for direct addressing).
pub async fn deliver_batch_over_iroh(
    endpoint: &Endpoint,
    recipient_addr: impl Into<EndpointAddr>,
    batch: &PheromoneGossipBatch,
) -> Result<BatchDeliveryOutcome, IrohLaneError> {
    let batch_bytes = canonical_json_bytes(batch)
        .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;

    let conn = endpoint
        .connect(recipient_addr, ALPN_PHEROMONE_BATCH)
        .await
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

    write_len_delimited(&mut send, &batch_bytes).await?;
    send.finish()
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

    let report_json = read_len_delimited(&mut recv).await?;
    conn.close(LANE_OK_CODE.into(), b"ok");

    // Parse only the `accepted` flag; the full report is returned as bytes so
    // this crate does not need to name the runtime report type.
    let value: serde_json::Value = serde_json::from_slice(&report_json)?;
    let accepted = value
        .get("accepted")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);

    Ok(BatchDeliveryOutcome {
        accepted,
        report_json,
    })
}

/// Enqueue a batch into the shipped SQLite outbox for durable store-and-forward
/// (blueprint A.3, "enqueue on flush"). Idempotent on the canonical batch hash.
pub fn enqueue_batch_for_delivery(
    store: &SqlitePheromoneRelayStore,
    sender_kernel_id: &str,
    recipient_kernel_id: &str,
    treaty_id: &str,
    batch: &PheromoneGossipBatch,
    queued_at_unix_ms: u64,
) -> Result<String, IrohLaneError> {
    store
        .enqueue_batch(
            sender_kernel_id,
            recipient_kernel_id,
            treaty_id,
            batch,
            queued_at_unix_ms,
        )
        .map_err(IrohLaneError::from)
}

/// Counts from one [`drain_outbox_over_iroh`] tick, mirroring the shape of the
/// shipped `RelayTickReport`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutboxDrainReport {
    /// Batches accepted by their recipient and marked delivered.
    pub delivered: u64,
    /// Batches that failed and were scheduled for a later retry.
    pub retried: u64,
    /// Batches that exhausted their attempts and were dead-lettered.
    pub dead_lettered: u64,
    /// Per-entry `outbox_id: code` failure lines.
    pub failures: Vec<String>,
}

/// Drain due outbox batches and deliver each over iroh, mirroring
/// `deliver_due_batches` (`service.rs:609`) with the single substitution of an
/// iroh `open_bi` write for the HTTP `post_batch`. Leasing, retry/backoff, and
/// dead-lettering all reuse the shipped `SqlitePheromoneRelayStore`.
///
/// `resolve_addr` maps a recipient `kernel_id` to its dialable
/// [`EndpointAddr`]; an unresolvable recipient folds into the retry path rather
/// than aborting the tick (fail-closed).
pub async fn drain_outbox_over_iroh<F>(
    store: &SqlitePheromoneRelayStore,
    endpoint: &Endpoint,
    resolve_addr: F,
    sender_kernel_id: &str,
    now_unix_ms: u64,
    max_batches: usize,
) -> Result<OutboxDrainReport, IrohLaneError>
where
    F: Fn(&str) -> Option<EndpointAddr>,
{
    let due = store.lease_due_batches(now_unix_ms, max_batches)?;
    let mut report = OutboxDrainReport::default();
    for entry in due {
        if entry.sender_kernel_id != sender_kernel_id {
            record_delivery_failure(store, &entry, "sender_mismatch", now_unix_ms, &mut report)?;
            continue;
        }
        let Some(addr) = resolve_addr(&entry.recipient_kernel_id) else {
            record_delivery_failure(store, &entry, "unknown_peer", now_unix_ms, &mut report)?;
            continue;
        };
        match deliver_batch_over_iroh(endpoint, addr, &entry.batch).await {
            Ok(outcome) if outcome.accepted => {
                store.mark_delivered(&entry.outbox_id)?;
                report.delivered = report.delivered.saturating_add(1);
            }
            Ok(_) => {
                record_delivery_failure(
                    store,
                    &entry,
                    "receiver_rejected",
                    now_unix_ms,
                    &mut report,
                )?;
            }
            Err(error) => {
                record_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
            }
        }
    }
    Ok(report)
}

/// Fold a delivery failure into the durable outbox: retry with linear backoff
/// until the attempt cap, then dead-letter. Mirrors `mark_delivery_failure`
/// (`service.rs:751`): 3 attempts, `60_000 * (attempts + 1)` ms backoff.
fn record_delivery_failure(
    store: &SqlitePheromoneRelayStore,
    entry: &RelayOutboxBatch,
    code: &str,
    now_unix_ms: u64,
    report: &mut OutboxDrainReport,
) -> Result<(), IrohLaneError> {
    report.failures.push(format!("{}: {code}", entry.outbox_id));
    if entry.attempts.saturating_add(1) >= 3 {
        store.mark_dead_letter(&entry.outbox_id, code)?;
        report.dead_lettered = report.dead_lettered.saturating_add(1);
    } else {
        let backoff_ms = 60_000u64.saturating_mul(entry.attempts.saturating_add(1));
        store.mark_retry(
            &entry.outbox_id,
            code,
            now_unix_ms.saturating_add(backoff_ms),
        )?;
        report.retried = report.retried.saturating_add(1);
    }
    Ok(())
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
    use crate::identity::TRANSPORT_DIRECTORY_BUNDLE_SCHEMA;
    use chio_core_types::canonical_json_bytes;
    use chio_core_types::sha256_hex as core_sha256_hex;
    use chio_core_types::Keypair;
    use chio_federation::pheromone_gossip::verify_pheromone_gossip_batch;
    use chio_federation::pheromone_gossip::PheromoneDepositGossip;
    use chio_federation::pheromone_gossip::PheromoneGossipBatchVerificationContext;
    use chio_federation::pheromone_gossip::PheromoneGossipError;
    use chio_federation::pheromone_gossip::PheromoneTransitPolicy;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_BATCH_SCHEMA;
    use chio_federation::pheromone_gossip::PHEROMONE_GOSSIP_SCHEMA;
    use chio_federation::pheromone_gossip::PHEROMONE_TRANSIT_POLICY_SCHEMA;
    use iroh::SecretKey;

    const NOW: u64 = 1_766_000_000_500;
    const RECIPIENT: &str = "did:chio:buyer-kernel";
    const TREATY: &str = "treaty:buyer-llamaworks:support-ops";
    const NAMESPACE: &str = "dev.chio.support";

    fn endpoint_from_seed(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// Build a load-time-verified directory admitting `kernel_id` at the
    /// transport endpoint derived from `transport_seed`; `removed` tombstones it.
    /// Mirrors the admission-module fixture.
    fn verified_gate(
        kernel_id: &str,
        passport_seed: u8,
        transport_seed: u8,
        removed: bool,
    ) -> DirectoryGate {
        let passport = Keypair::from_seed(&[passport_seed; 32]);
        let issuer = Keypair::from_seed(&[240; 32]);
        let transport = endpoint_from_seed(transport_seed);
        let entry = TransportDirectoryEntry {
            kernel_id: kernel_id.to_string(),
            passport_public_key: passport.public_key(),
            transport_endpoint_id: transport,
            passport_endorsement: passport
                .sign(&transport_endorsement_preimage(kernel_id, &transport)),
            revocation_signers: Vec::new(),
            removed,
        };
        let directory = TransportDirectoryDocument {
            schema: TRANSPORT_DIRECTORY_BUNDLE_SCHEMA.to_string(),
            local_kernel_id: "did:chio:local".to_string(),
            peers: vec![entry],
        };
        let directory_sha256 = core_sha256_hex(&canonical_json_bytes(&directory).unwrap());
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
        DirectoryGate::new(Arc::new(bundle.verify_bundle(&trust).unwrap()))
    }

    /// A parseable `chio_core_types::Signature` (as its hex JSON form). The
    /// direct-frame verifier does not check the deposit signature, so any
    /// well-formed signature suffices to exercise the sender-equality checks.
    fn signature_value() -> serde_json::Value {
        let sig = Keypair::from_seed(&[9; 32]).sign(b"pheromone-lane-fixture");
        serde_json::to_value(sig).unwrap()
    }

    /// A single-frame direct batch authored by `author` (both `origin` and
    /// `gossiping_peer`), scoped to `TREATY`. The nested `PheromoneDeposit` is
    /// built by deserialization so this crate need not depend on chio-pheromone.
    fn direct_batch(author: &str) -> PheromoneGossipBatch {
        let frame = serde_json::json!({
            "schema": PHEROMONE_GOSSIP_SCHEMA,
            "deposit": {
                "schema": "chio.pheromone-deposit.v1",
                "kernel_id": author,
                "agent_passport_key_hash": "a".repeat(64),
                "agent_passport_jwk_thumbprint": "b".repeat(43),
                "subject_class": "support.prompt_injection",
                "subject_class_namespace": NAMESPACE,
                "indicator": {"digest": "c".repeat(64)},
                "severity": "high",
                "confidence": 0.8,
                "timestamp_unix_ms": NOW,
                "decay_half_life_secs": 3_600.0,
                "nonce": "nonce-live-relay-001",
                "treaty_scope": [TREATY],
                "signature": signature_value(),
            },
            "origin_kernel_id": author,
            "gossiping_peer_kernel_id": author,
            "treaty_id": TREATY,
            "ts_unix_ms": NOW,
        });
        let frame: PheromoneDepositGossip =
            serde_json::from_value(frame).expect("frame fixture deserializes");
        PheromoneGossipBatch {
            schema: PHEROMONE_GOSSIP_BATCH_SCHEMA.to_string(),
            recipient_kernel_id: RECIPIENT.to_string(),
            treaty_id: TREATY.to_string(),
            frames: vec![frame],
            flushed_at_unix_ms: NOW,
        }
    }

    fn live_policy() -> PheromoneTransitPolicy {
        PheromoneTransitPolicy {
            schema: PHEROMONE_TRANSIT_POLICY_SCHEMA.to_string(),
            accepted_hubs: Vec::new(),
            allowed_ingress_treaties: vec![TREATY.to_string()],
            allowed_egress_treaties: vec![TREATY.to_string()],
            allowed_subject_class_namespaces: vec![NAMESPACE.to_string()],
            valid_from_unix_ms: NOW - 1_000,
            valid_until_unix_ms: NOW + 1_000,
            max_hops: 4,
            required_action_class_id: "action:demo".to_string(),
            pinned_ladder_refs: Vec::new(),
        }
    }

    #[test]
    fn admitted_endpoint_resolves_to_its_kernel_id() {
        let gate = verified_gate("did:chio:llamaworks", 1, 10, false);
        assert_eq!(
            resolve_authenticated_sender(&gate, &endpoint_from_seed(10)).unwrap(),
            "did:chio:llamaworks"
        );
    }

    #[test]
    fn unbound_endpoint_is_rejected_fail_closed() {
        let gate = verified_gate("did:chio:llamaworks", 1, 10, false);
        let error = resolve_authenticated_sender(&gate, &endpoint_from_seed(200)).unwrap_err();
        assert!(matches!(error, IrohLaneError::Unadmitted(_)));
        assert_eq!(error.code(), "unadmitted");
    }

    #[test]
    fn removed_endpoint_is_rejected_fail_closed() {
        let gate = verified_gate("did:chio:ghost", 3, 12, true);
        let error = resolve_authenticated_sender(&gate, &endpoint_from_seed(12)).unwrap_err();
        assert!(matches!(error, IrohLaneError::Unadmitted(_)));
    }

    #[test]
    fn resolved_sender_feeds_verifier_and_batch_is_accepted() {
        // The transport resolves the admitted endpoint to its kernel_id; that
        // exact string, used as authenticated_sender_kernel_id, makes the
        // unchanged per-frame verifier accept the peer-authored batch.
        let gate = verified_gate("did:chio:llamaworks", 1, 10, false);
        let authenticated_sender =
            resolve_authenticated_sender(&gate, &endpoint_from_seed(10)).unwrap();
        let batch = direct_batch(&authenticated_sender);
        let context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: NOW,
            recipient_kernel_id: RECIPIENT.to_string(),
            authenticated_sender_kernel_id: authenticated_sender.clone(),
        };
        verify_pheromone_gossip_batch(&batch, &live_policy(), &context)
            .expect("resolved sender's batch verifies (pheromone_gossip.rs:236/244)");
        assert_eq!(authenticated_sender, "did:chio:llamaworks");
    }

    #[test]
    fn verifier_rejects_when_authenticated_sender_differs() {
        // Same peer-authored batch, but the transport-sourced sender does not
        // match the frame author: the :236 check fails (fail-closed). This is
        // the load-bearing binding the whole lane exists to populate.
        let batch = direct_batch("did:chio:llamaworks");
        let context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: NOW,
            recipient_kernel_id: RECIPIENT.to_string(),
            authenticated_sender_kernel_id: "did:chio:mallory".to_string(),
        };
        let error = verify_pheromone_gossip_batch(&batch, &live_policy(), &context).unwrap_err();
        assert!(matches!(
            error,
            PheromoneGossipError::AuthenticatedSenderMismatch(_)
        ));
    }

    #[tokio::test]
    async fn len_delimited_frame_round_trips() {
        let batch = direct_batch("did:chio:llamaworks");
        let bytes = canonical_json_bytes(&batch).unwrap();

        let mut out: Vec<u8> = Vec::new();
        write_len_delimited(&mut out, &bytes).await.unwrap();

        let mut reader: &[u8] = &out;
        let read = read_len_delimited(&mut reader).await.unwrap();
        let decoded: PheromoneGossipBatch = serde_json::from_slice(&read).unwrap();
        assert_eq!(decoded, batch);
    }

    #[tokio::test]
    async fn over_cap_frame_is_rejected_before_allocation() {
        let mut framed: Vec<u8> = Vec::new();
        let oversized = (MAX_PHEROMONE_BATCH_BYTES as u32).saturating_add(1);
        framed.extend_from_slice(&oversized.to_be_bytes());
        let mut reader: &[u8] = &framed;
        let error = read_len_delimited(&mut reader).await.unwrap_err();
        assert!(matches!(error, IrohLaneError::FrameTooLarge(_)));
        assert_eq!(error.code(), "frame_too_large");
    }

    #[test]
    fn outbox_reuse_enqueues_leases_and_dead_letters() {
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let batch = direct_batch("did:chio:llamaworks");
        let outbox_id = enqueue_batch_for_delivery(
            &store,
            "did:chio:llamaworks",
            RECIPIENT,
            TREATY,
            &batch,
            NOW,
        )
        .unwrap();

        let due = store.lease_due_batches(NOW, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].outbox_id, outbox_id);

        // Enqueue is idempotent on the canonical batch hash.
        let again = enqueue_batch_for_delivery(
            &store,
            "did:chio:llamaworks",
            RECIPIENT,
            TREATY,
            &batch,
            NOW,
        )
        .unwrap();
        assert_eq!(again, outbox_id);

        // Three failures retry twice then dead-letter, matching
        // mark_delivery_failure's attempt cap.
        let mut entry = due.into_iter().next().unwrap();
        let mut report = OutboxDrainReport::default();
        for attempts in 0..3u64 {
            entry.attempts = attempts;
            record_delivery_failure(&store, &entry, "transport", NOW, &mut report).unwrap();
        }
        assert_eq!(report.retried, 2);
        assert_eq!(report.dead_lettered, 1);
        assert_eq!(report.failures.len(), 3);
    }

    // -- End-to-end over real loopback QUIC (mirrors the validated PoC shape) --
    //
    // The real receiver seam (RelayBatchReceiver, whose report type is not
    // nameable here) is stubbed by a canned-report handler that still exercises
    // the genuine transport path: the admission gate on the endpoint, the
    // handler's re-resolution of conn.remote_id(), the ALPN, and the
    // length-delimited bidi codec. The deterministic tests above prove the
    // verifier seam; these prove the wire path and the accept-time gate.

    use iroh::endpoint::presets;
    use iroh::TransportAddr;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    struct CannedReportHandler {
        gate: DirectoryGate,
    }

    impl ProtocolHandler for CannedReportHandler {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let sender = resolve_authenticated_sender(&self.gate, &conn.remote_id())
                .map_err(AcceptError::from_err)?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            let raw = read_len_delimited(&mut recv)
                .await
                .map_err(AcceptError::from_err)?;
            // Prove the received bytes decode to the real wire type.
            let _batch: PheromoneGossipBatch =
                serde_json::from_slice(&raw).map_err(AcceptError::from_err)?;
            let report = serde_json::json!({
                "schema": "chio.pheromone-receive-report.v1",
                "accepted": true,
                "authenticatedSenderKernelId": sender,
            });
            let bytes = serde_json::to_vec(&report).map_err(AcceptError::from_err)?;
            write_len_delimited(&mut send, &bytes)
                .await
                .map_err(AcceptError::from_err)?;
            send.finish()?;
            conn.closed().await;
            Ok(())
        }
    }

    async fn bind_endpoint(seed: u8, gate: Option<DirectoryGate>) -> Endpoint {
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[seed; 32]))
            .bind_addr("127.0.0.1:0")
            .expect("loopback bind address parses");
        if let Some(gate) = gate {
            builder = builder.hooks(gate);
        }
        builder.bind().await.expect("endpoint binds on loopback")
    }

    fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
        EndpointAddr::from_parts(
            endpoint.id(),
            endpoint.bound_sockets().into_iter().map(TransportAddr::Ip),
        )
    }

    #[tokio::test]
    async fn admitted_dialer_batch_accepted_over_quic() {
        let dialer_seed = 20u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
        let acceptor = bind_endpoint(21, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, CannedReportHandler { gate })
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let batch = direct_batch("did:chio:bob");
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("admitted dialer delivers its batch");
        assert!(outcome.accepted, "admitted dialer's batch is accepted");

        router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn unbound_dialer_is_rejected_at_handshake() {
        // Directory admits only the endpoint derived from seed 20.
        let gate = verified_gate("did:chio:bob", 1, 20, false);
        let acceptor = bind_endpoint(21, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, CannedReportHandler { gate })
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        // Seed 99 is not bound in the directory: the accept-time gate rejects it.
        let unbound = bind_endpoint(99, None).await;
        let batch = direct_batch("did:chio:bob");
        let result = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&unbound, acceptor_addr, &batch),
        )
        .await
        .expect("dial resolves before timeout");
        assert!(
            result.is_err(),
            "unbound endpoint must be rejected, got {result:?}"
        );

        router.shutdown().await.ok();
    }

    // -- Driving the REAL per-frame verifier over loopback QUIC --
    //
    // The `CannedReportHandler` above proves the wire path and the accept-time
    // gate, but (like a stub) it never runs the verifier. Wiring the actual
    // `PheromoneBatchHandler` is not possible here without a Cargo.toml change:
    // `RelayBatchReceiver::receive_batch` returns
    // `chio_pheromone_runtime::PheromoneReceiveReport`, and chio-pheromone-runtime
    // is neither a (dev-)dependency of this crate nor re-exported by any current
    // dependency, so no `RelayBatchReceiver` double (real OR recording) can even
    // name its return type. So instead this handler resolves the sender through
    // the REAL admission gate (exactly as `PheromoneBatchHandler::handle` does)
    // and feeds that gate-resolved kernel_id - never an attacker value - into the
    // REAL `verify_pheromone_gossip_batch` (pheromone_gossip.rs:236/244), the same
    // per-frame verifier the production handler runs behind the receiver seam.
    // This drives the verifier the canned stub skips, over genuine QUIC.

    #[derive(Debug, Clone)]
    struct VerifyingBatchHandler {
        gate: DirectoryGate,
        policy: Arc<PheromoneTransitPolicy>,
        recipient_kernel_id: String,
        now_unix_ms: u64,
    }

    impl ProtocolHandler for VerifyingBatchHandler {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            // The one transport-sourced value, resolved exactly as the real
            // handler does. Everything else feeds the unchanged verifier.
            let sender = resolve_authenticated_sender(&self.gate, &conn.remote_id())
                .map_err(AcceptError::from_err)?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            let raw = read_len_delimited(&mut recv)
                .await
                .map_err(AcceptError::from_err)?;
            let batch: PheromoneGossipBatch =
                serde_json::from_slice(&raw).map_err(AcceptError::from_err)?;

            let context = PheromoneGossipBatchVerificationContext {
                now_unix_ms: self.now_unix_ms,
                recipient_kernel_id: self.recipient_kernel_id.clone(),
                authenticated_sender_kernel_id: sender.clone(),
            };
            let accepted = verify_pheromone_gossip_batch(&batch, &self.policy, &context).is_ok();

            let report = serde_json::json!({
                "schema": "chio.pheromone-receive-report.v1",
                "accepted": accepted,
                "authenticatedSenderKernelId": sender,
            });
            let bytes = serde_json::to_vec(&report).map_err(AcceptError::from_err)?;
            write_len_delimited(&mut send, &bytes)
                .await
                .map_err(AcceptError::from_err)?;
            send.finish()?;
            conn.closed().await;
            Ok(())
        }
    }

    fn verifying_handler(gate: DirectoryGate) -> VerifyingBatchHandler {
        VerifyingBatchHandler {
            gate,
            policy: Arc::new(live_policy()),
            recipient_kernel_id: RECIPIENT.to_string(),
            now_unix_ms: NOW,
        }
    }

    #[tokio::test]
    async fn real_verifier_accepts_admitted_senders_own_batch_over_quic() {
        let dialer_seed = 24u8;
        // The gate resolves the dialer endpoint to did:chio:bob.
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
        let acceptor = bind_endpoint(25, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, verifying_handler(gate))
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        // Batch authored by did:chio:bob == the gate-resolved authenticated sender.
        let batch = direct_batch("did:chio:bob");
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("delivery round-trips");
        assert!(
            outcome.accepted,
            "the real verifier, fed the gate-resolved sender, accepts the admitted sender's own batch"
        );

        router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn real_verifier_rejects_batch_whose_author_is_not_the_authenticated_sender_over_quic() {
        let dialer_seed = 26u8;
        // The dialer endpoint is admitted, resolving to did:chio:bob...
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
        let acceptor = bind_endpoint(27, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, verifying_handler(gate))
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        // ...but the batch's gossiping_peer_kernel_id is did:chio:mallory, not the
        // gate-resolved did:chio:bob. The REAL verifier's :236 check fails closed,
        // so the transport CANNOT launder an attacker-chosen author.
        let batch = direct_batch("did:chio:mallory");
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("delivery round-trips");
        assert!(
            !outcome.accepted,
            "a batch whose gossiping_peer != the authenticated sender must be rejected by the real verifier"
        );

        router.shutdown().await.ok();
    }
}
