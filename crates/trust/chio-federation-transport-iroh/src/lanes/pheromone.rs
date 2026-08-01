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

/// Bounded wait, on the LOSER of a concurrent receive-slot reservation, for the
/// winner to record its durable verdict. The loser never re-runs the receiver; it
/// polls the inbox this many times, sleeping [`DEDUP_WAIT_BACKOFF`] between tries,
/// then fails closed (the peer retries and hits the recorded verdict). The product
/// (a few seconds) comfortably covers one `receive_batch` + `record_inbox`.
const DEDUP_WAIT_ATTEMPTS: u32 = 150;

/// Backoff between inbox polls while the loser waits for the winner's verdict.
const DEDUP_WAIT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(20);

/// Inbound directory-scope gate applied on the iroh ingress path BEFORE
/// [`RelayBatchReceiver::receive_batch`], mirroring the HTTP relay's
/// `enforce_peer_batch_directory_scope` (`service.rs`). Supplied by the wiring so
/// this crate never names `PeerDirectory`; it MUST be evaluated against the CURRENT
/// peer directory and fail closed on any out-of-scope sender (not an `Origin`/`Hub`,
/// over its per-peer frame cap, unsubscribed from the batch treaty, or carrying an
/// unpinned transit ladder). Its `Err` folds into [`IrohLaneError::Relay`] and
/// resets the stream, exactly as the HTTP path rejects the same peer.
pub type InboundBatchScopeCheck =
    Arc<dyn Fn(&str, &PheromoneGossipBatch) -> Result<(), PheromoneRelayError> + Send + Sync>;

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
    /// A concurrent connection holds the receive slot for this exact batch and had
    /// not yet recorded its verdict within the bounded dedup wait. Fail-closed: the
    /// stream is reset WITHOUT re-running the receiver (re-running would double-
    /// mutate the runtime replay window); the peer retries and hits the recorded
    /// verdict via the durable inbox.
    #[error("pheromone batch dedup in-flight: {0}")]
    DedupInFlight(String),
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
            Self::DedupInFlight(_) => "dedup_in_flight",
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

/// RAII holder for an inbox receive-slot reservation (`reserve_inbox_slot`).
///
/// The reservation is the dedup primitive that makes concurrent delivery of the
/// SAME batch receive it exactly once. Its lifecycle is subtle because
/// [`RelayBatchReceiver::receive_batch`] SELF-COMMITS its runtime mutation
/// (admitting the deposits) internally, so the instant of commit sits BETWEEN the
/// reservation and the durable inbox record:
///
/// - While ARMED (before the receive commits), dropping this guard RELEASES the
///   slot. This covers the receive-failed `?`-return AND an accept-task
///   cancel/panic (a `Router` shutdown or connection close cancels the accept
///   future): nothing was committed, so a redelivery may re-claim and re-receive.
///   Without this, a cancelled/panicked pre-commit accept would LEAK the row and
///   make that `(sender, nonce)` un-receivable (losers fail closed as
///   [`IrohLaneError::DedupInFlight`]) until a restart's DELETE-at-open.
/// - Once the receive commits, the caller [`commit`](Self::commit)s. That disarms the
///   guard (a drop/cancel/panic must NOT release: re-receiving an already-admitted
///   batch would re-enter the runtime replay window and reject its already-accepted
///   deposits, a spurious "rejected" durable verdict) AND persists a durable
///   `committed` marker on the reservation so that a PROCESS crash in this window
///   leaves a row that SURVIVES the store's clear-at-open (which reclaims only
///   provably-pre-commit rows); a redelivery then loses the reservation and takes the
///   fail-closed loser path instead of re-receiving.
/// - On a recorded durable verdict the caller [`release`](Self::release)s
///   explicitly: the verdict now short-circuits redelivery at `lookup_inbox_report`
///   BEFORE the reservation is consulted, so the row is redundant and releasing it
///   bounds reservation-table growth.
struct InboxSlotGuard {
    store: Arc<SqlitePheromoneRelayStore>,
    sender_kernel_id: String,
    nonce: String,
    armed: bool,
}

impl InboxSlotGuard {
    /// Arm a guard over a freshly-won reservation.
    fn new(store: Arc<SqlitePheromoneRelayStore>, sender_kernel_id: String, nonce: String) -> Self {
        Self {
            store,
            sender_kernel_id,
            nonce,
            armed: true,
        }
    }

    /// Commit the slot after the receive has self-committed its runtime deposits, the
    /// instant BEFORE the durable verdict is recorded.
    ///
    /// Two effects, both fail-closed:
    /// - Disarms the guard so a subsequent drop/cancel/panic does NOT release (see the
    ///   type docs); done FIRST so that even if the durable marker write below errors,
    ///   the slot stays HELD rather than being released. Re-receiving an
    ///   already-committed batch must never happen.
    /// - Persists the durable `committed` marker so a PROCESS crash in the
    ///   committed-but-unrecorded window leaves a reservation that survives the store's
    ///   clear-at-open reclaim (which clears only provably-pre-commit `committed = 0`
    ///   rows); a redelivery then loses the reservation and takes the fail-closed loser
    ///   path instead of re-receiving.
    fn commit(&mut self) -> Result<(), IrohLaneError> {
        self.armed = false;
        self.store
            .mark_inbox_reservation_committed(&self.sender_kernel_id, &self.nonce)?;
        Ok(())
    }

    /// Explicitly release the (now redundant) reservation after the durable verdict
    /// is recorded, disarming so a later drop does not release again. Fail-closed:
    /// propagates the store error.
    fn release(&mut self) -> Result<(), IrohLaneError> {
        self.armed = false;
        self.store
            .release_inbox_slot(&self.sender_kernel_id, &self.nonce)?;
        Ok(())
    }
}

impl Drop for InboxSlotGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Pre-commit exit (receive failed, or the accept future was cancelled /
        // panicked before commit): release so a redelivery can re-claim and
        // re-receive. Best-effort - Drop cannot propagate - so a store error is
        // logged, leaving the slot HELD (fail-closed) until a restart's
        // DELETE-at-open reclaims it.
        if let Err(error) = self
            .store
            .release_inbox_slot(&self.sender_kernel_id, &self.nonce)
        {
            tracing::warn!(
                sender = %self.sender_kernel_id,
                nonce = %self.nonce,
                error = %error,
                "failed to release inbox receive slot on drop (slot held fail-closed)"
            );
        }
    }
}

/// Read a `u32` big-endian length prefix followed by exactly that many bytes,
/// rejecting an over-cap declared length before allocating (fail-closed).
///
/// `max_bytes` is the caller's effective cap and MUST never exceed the transport
/// hard cap [`MAX_PHEROMONE_BATCH_BYTES`]. The ingress handler passes the configured
/// relay body-size limit (256 KiB production / 1 MiB local-dev) so the iroh path is
/// no laxer than the HTTP relay's `DefaultBodyLimit`; internal reads (the dialer's
/// own response) pass the transport cap.
async fn read_len_delimited<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, IrohLaneError>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > max_bytes {
        return Err(IrohLaneError::FrameTooLarge(len));
    }
    // Grow the buffer as bytes actually arrive instead of committing `len` up
    // front: a peer that declares a large length then dribbles holds only what it
    // has sent (the per-phase ReadFrame timeout still bounds the dribble).
    const READ_CHUNK: usize = 64 * 1024;
    let mut buf: Vec<u8> = Vec::with_capacity(len.min(READ_CHUNK));
    let mut remaining = len;
    let mut chunk = [0u8; READ_CHUNK];
    while remaining > 0 {
        let want = remaining.min(READ_CHUNK);
        let n = reader.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Err(IrohLaneError::Io(std::io::Error::from(
                std::io::ErrorKind::UnexpectedEof,
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
        remaining -= n;
    }
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
    /// Inbound per-peer directory-scope gate (the SAME `enforce_peer_batch_directory_scope`
    /// the HTTP relay runs before receiving). Evaluated fail-closed BEFORE the batch
    /// reaches the receiver, so an out-of-scope sender is rejected on the iroh path
    /// exactly as it is over HTTP.
    scope_check: InboundBatchScopeCheck,
    /// Shared slowloris / resource-exhaustion bounds (per-phase timeouts + an
    /// in-flight concurrency cap). Defaults are generous; see [`AcceptLimiter`].
    limiter: AcceptLimiter,
    /// Effective ingress body-size cap. Defaults to the transport hard cap
    /// [`MAX_PHEROMONE_BATCH_BYTES`]; the wiring lowers it to the relay profile's
    /// configured body limit (mirroring the HTTP relay's `DefaultBodyLimit`) so the
    /// iroh ingress is never a laxer surface than HTTP. Applied to the request-frame
    /// read BEFORE deserialization, fail-closed to [`IrohLaneError::FrameTooLarge`].
    max_batch_bytes: usize,
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
    /// relay receiver seam, the shipped SQLite store (inbox dedup), a clock, and the
    /// inbound directory-scope gate (the SAME `enforce_peer_batch_directory_scope`
    /// the HTTP relay runs before receiving, supplied by the wiring against the
    /// current peer directory).
    #[must_use]
    pub fn new(
        gate: DirectoryGate,
        receiver: Arc<dyn RelayBatchReceiver>,
        store: Arc<SqlitePheromoneRelayStore>,
        now: Arc<dyn Fn() -> u64 + Send + Sync>,
        scope_check: InboundBatchScopeCheck,
    ) -> Self {
        Self {
            gate,
            receiver,
            store,
            now,
            scope_check,
            limiter: AcceptLimiter::default(),
            max_batch_bytes: MAX_PHEROMONE_BATCH_BYTES,
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

    /// Lower the ingress body-size cap to the relay profile's configured body limit
    /// so the iroh ingress path is no laxer than the HTTP relay's `DefaultBodyLimit`
    /// (256 KiB production / 1 MiB local-dev). Fail-closed: the effective cap is the
    /// MIN of the requested limit and the transport hard cap
    /// [`MAX_PHEROMONE_BATCH_BYTES`], so this can only tighten, never widen, the
    /// ceiling. A batch declaring more than the effective cap is rejected before any
    /// allocation or deserialization.
    #[must_use]
    pub fn with_max_batch_bytes(mut self, max_batch_bytes: usize) -> Self {
        self.max_batch_bytes = max_batch_bytes.min(MAX_PHEROMONE_BATCH_BYTES);
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
            .bounded(
                AcceptPhase::ReadFrame,
                read_len_delimited(&mut recv, self.max_batch_bytes),
            )
            .await??;
        let batch: PheromoneGossipBatch = serde_json::from_slice(&raw)?;

        // ENFORCE INBOUND PEER SCOPE (fail-closed): mirror the HTTP handle_batch_relay,
        // which runs enforce_peer_batch_directory_scope BEFORE receive_batch. A sender
        // that is not an Origin/Hub, exceeds its per-peer frame cap, is unsubscribed
        // from the batch treaty, or carries an unpinned transit ladder is rejected here
        // on the iroh path exactly as over HTTP, BEFORE any receiver/inbox state is
        // consulted or mutated. Runs on EVERY batch (even a dedup redelivery), matching
        // the HTTP path, so a sender that has since fallen out of scope cannot replay.
        (self.scope_check)(&authenticated_sender, &batch)?;

        // RE-RESOLVE AGAINST THE CURRENT DIRECTORY BEFORE TOUCHING RECEIVER STATE
        // (fail-closed). The admission gate authorized this endpoint at `after_handshake`,
        // but the directory reloader can publish a deny-all (expiry, revoked local binding,
        // below-minVersion, or an untrusted signing issuer) - or a successor that tombstones
        // this sender - DURING the accept_bi + request-frame read this handler just awaited.
        // Resolving the sender only once at accept would let a peer that connected just
        // before that swap still deliver a batch under a directory that is no longer valid.
        // Resolve again now, immediately before any receiver/inbox mutation: an endpoint the
        // current directory no longer admits (or now binds to a different kernel) is reset
        // here rather than received under a stale directory.
        let remote = conn.remote_id();
        if resolve_authenticated_sender(&self.gate, &remote)? != authenticated_sender {
            return Err(IrohLaneError::Unadmitted(remote.fmt_short().to_string()));
        }

        // DEDUP BEFORE RECEIVE (fail-closed idempotency): compute the deterministic
        // inbox nonce and consult the store BEFORE mutating receiver state. On a
        // retry of an already-admitted batch, re-running receive_batch would re-enter
        // the runtime replay window and reject the already-accepted deposits, dead-
        // lettering a batch the peer already holds. Returning the stored report keeps
        // redelivery idempotent, exactly as the shipped HTTP inbox does.
        let batch_bytes = canonical_json_bytes(&batch)
            .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;
        let nonce = inbox_nonce(&batch_bytes);
        let report = match self
            .store
            .lookup_inbox_report(&authenticated_sender, &nonce)?
        {
            // Already fully admitted: return the durable verdict verbatim.
            Some(stored) => stored,
            None => {
                // RESERVE BEFORE RECEIVE (fail-closed concurrency): the lookup ->
                // receive -> record sequence is NOT atomic, so two connections
                // delivering the SAME batch could both read None and both re-run
                // receive_batch, double-mutating the runtime replay window. Atomically
                // claim the (sender, nonce) receive slot first; only the sole winner
                // receives.
                if self
                    .store
                    .reserve_inbox_slot(&authenticated_sender, &nonce)?
                    .won
                {
                    // Hold the freshly-won reservation via an RAII guard, ARMED. While
                    // armed, ANY early exit - the receive `?`-return below, an
                    // accept-task cancel (Router shutdown / connection close cancels the
                    // accept future), or a panic - drops the guard and RELEASES the slot,
                    // so a batch that committed NOTHING never leaks its reservation (a
                    // leaked row would make that (sender, nonce) un-receivable until a
                    // restart's DELETE-at-open). Once the receive COMMITS we DISARM, so
                    // from there a drop/cancel/panic leaves the slot HELD (fail-closed):
                    // re-receiving an already-admitted batch would re-enter the runtime
                    // replay window and reject its already-accepted deposits.
                    let mut slot = InboxSlotGuard::new(
                        Arc::clone(&self.store),
                        authenticated_sender.clone(),
                        nonce.clone(),
                    );
                    // RE-READ AFTER WINNING THE RESERVATION (fail-closed): our first
                    // lookup_inbox_report returned None, but winning the slot does NOT
                    // prove the batch is unreceived. A concurrent handler can record its
                    // durable verdict AND release its reservation (release_inbox_slot runs
                    // only AFTER record_inbox, to bound table growth) in the window between
                    // our None-read and our winning here, so we may have re-claimed a slot
                    // for an ALREADY-admitted batch. Re-read the durable inbox now, holding
                    // the freshly-won slot: if the verdict is already recorded, return it
                    // verbatim and RELEASE the (now redundant) slot - NEVER re-run
                    // receive_batch, which would re-enter the runtime replay window and
                    // reject the already-accepted deposits (a spurious "rejected" verdict).
                    // This closes the "reservation won after another handler recorded+
                    // released" race and mirrors the HTTP path's nonce-before-receive
                    // idempotency. Only a still-absent verdict proceeds to receive.
                    if let Some(stored) = self
                        .store
                        .lookup_inbox_report(&authenticated_sender, &nonce)?
                    {
                        slot.release()?;
                        stored
                    } else {
                        // WINNER-PATH DURABLE-VERDICT RECOVERY (symmetric with the loser
                        // path below). Winning the reservation and finding no
                        // recorded inbox verdict does NOT prove the batch is unreceived across
                        // the two-store boundary. receive_batch self-commits its runtime
                        // mutation (deposits + receive-report) in the RUNTIME store; slot.commit()
                        // marks the RELAY reservation committed in a SEPARATE durable write, with
                        // a cross-store fsync between the two. A hard crash (SIGKILL / OOM /
                        // power) in that window leaves the batch ADMITTED in the runtime store
                        // but the relay reservation committed = 0, which the store reclaims at
                        // open; a redelivery then re-wins the reservation and reaches HERE.
                        // Consult the runtime store by batch hash BEFORE re-running
                        // receive_batch: if it already holds a committed receive-report, ADOPT
                        // that durable verdict rather than re-running the receiver (which would
                        // re-enter the runtime replay window and reject the already-admitted
                        // deposits - a spurious "rejected" verdict that dead-letters an accepted
                        // batch). The hash is sha256_hex over the same canonical batch bytes the
                        // runtime store keys on (batch_sha256 == sha256_hex(canonical_json_bytes)),
                        // identical to the loser path.
                        let batch_sha256 = sha256_hex(&batch_bytes);
                        // SCOPE THE RECOVERED VERDICT TO THE AUTHENTICATED SENDER
                        // (fail-closed): a batch hash is NOT sender-unique. A DIFFERENT
                        // authenticated sender can durably record a verdict for these exact
                        // batch bytes - either an envelope-rejected report (any peer that
                        // replays the bytes with the WRONG identity trips
                        // gossiping_peer_kernel_id != authenticated_sender), or, for a batch
                        // whose gossiping_peer_kernel_id it legitimately owns, an accepted
                        // one. Adopting it verbatim would attribute that sender's verdict to
                        // OUR (authenticated_sender, nonce) inbox key, bypassing the
                        // per-frame verifier's gossiping_peer_kernel_id == authenticated_sender
                        // binding: a wrong sender could POISON this batch hash with a rejected
                        // verdict before the real sender arrives, or RECEIVE an accepted verdict
                        // for another sender's batch. The runtime-store lookup is now itself
                        // sender-scoped at the query level, so it returns THIS sender's row (or
                        // None); the `.filter` re-checks the deserialized sender as
                        // belt-and-suspenders. Any non-matching (or absent) report falls through
                        // to receive_batch, which re-runs that verifier under THIS sender.
                        if let Some(recovered) = self
                            .receiver
                            .recorded_report_for_batch(&batch_sha256, &authenticated_sender)
                            .await?
                            .filter(|recovered| {
                                recovered.authenticated_sender_kernel_id == authenticated_sender
                            })
                        {
                            // Adopt the durable verdict as the inbox record so both peers
                            // converge. record_inbox is idempotent (ON CONFLICT), so a
                            // concurrent handler recording first is harmless. RELEASE the
                            // committed residual reservation via the guard (disarming it so the
                            // Drop does not release again) now that the durable inbox row
                            // short-circuits any later redelivery at lookup_inbox_report before
                            // the reservation is consulted. NEVER re-run receive_batch. The lane
                            // accept counter is NOT incremented here: `handle` returns Ok on this
                            // recovery, and `accept` counts LANE_OUTCOME_ACCEPT once for every
                            // Ok(()), exactly as it does for a fresh delivery or an inbox hit.
                            // Counting here too would emit TWO accept samples for one recovered
                            // redelivery (metric dedupe).
                            let _ = self.store.record_inbox(
                                &authenticated_sender,
                                &nonce,
                                &batch,
                                &recovered,
                            )?;
                            slot.release()?;
                            recovered
                        } else {
                            let now = (self.now)();
                            // The report type (chio-pheromone-runtime PheromoneReceiveReport)
                            // is not nameable here; it flows through by inference. The per-frame
                            // verifier (pheromone_gossip.rs:236/244) runs inside this call,
                            // unchanged, and only ever on a batch neither already in the inbox
                            // nor durably committed in the runtime store.
                            let fresh = match self
                                .receiver
                                .receive_batch(batch.clone(), authenticated_sender.clone(), now)
                                .await
                            {
                                // receive_batch self-commits its runtime mutation only on Ok; an
                                // Err admitted nothing. The still-ARMED guard drops on this
                                // `?`-return and RELEASES the slot so a redelivery can re-claim
                                // and re-receive. Fail-closed.
                                Err(error) => return Err(error.into()),
                                Ok(fresh) => fresh,
                            };
                            // Deposits are now committed. COMMIT the slot: disarm (a cancel/panic
                            // in the committed-but-unrecorded window below must NOT release, or a
                            // redelivery would re-receive an already-admitted batch, yielding a
                            // spurious "rejected" durable verdict for deposits that were in fact
                            // admitted) AND persist the durable commit marker so a PROCESS crash
                            // in this window leaves a reservation that survives the store's
                            // clear-at-open, forcing redelivery down the fail-closed loser path.
                            slot.commit()?;
                            match self.store.record_inbox(
                                &authenticated_sender,
                                &nonce,
                                &batch,
                                &fresh,
                            ) {
                                // Durable verdict recorded: it now short-circuits any redelivery
                                // at lookup_inbox_report BEFORE the reservation is consulted, so
                                // the reservation is redundant. Release it to bound
                                // reservation-table growth (fail-closed on the store error; the
                                // recorded verdict still short-circuits the peer's retry).
                                Ok(_) => slot.release()?,
                                // A committed batch whose verdict failed to record must NOT be
                                // re-received. Leave the slot HELD (already disarmed): a
                                // redelivery loses the reservation and takes the loser /
                                // fail-closed path, never re-running the receiver. The peer retry
                                // fail-closes pending operational recovery.
                                Err(error) => return Err(error.into()),
                            }
                            fresh
                        }
                    }
                } else {
                    // Loser: a concurrent handler is receiving this exact batch. Do
                    // NOT receive (that is the double-mutation this dedup closes); wait,
                    // bounded, for the winner's durable verdict and return it. The
                    // report type is unnameable in this crate (see the module note), so
                    // the wait is inlined and flows the verdict through by inference.
                    let mut verdict = None;
                    for _ in 0..DEDUP_WAIT_ATTEMPTS {
                        if let Some(stored) = self
                            .store
                            .lookup_inbox_report(&authenticated_sender, &nonce)?
                        {
                            verdict = Some(stored);
                            break;
                        }
                        tokio::time::sleep(DEDUP_WAIT_BACKOFF).await;
                    }
                    match verdict {
                        Some(stored) => stored,
                        None => {
                            // Durable-verdict recovery: the bounded poll found no recorded
                            // inbox verdict, but the runtime store may
                            // have durably committed this batch before a crash in the
                            // commit-to-record window (receive_batch self-committed the
                            // deposits; the process died before record_inbox wrote the
                            // durable verdict, leaving the reservation committed=1). A
                            // redelivery then lost the slot and reached this loser path.
                            // Consult the runtime store by batch hash: the hash is
                            // sha256_hex over the same canonical batch bytes the runtime
                            // store keys on (batch_sha256 == sha256_hex(canonical_json_bytes)).
                            let batch_sha256 = sha256_hex(&batch_bytes);
                            // SCOPE THE RECOVERED VERDICT TO THE AUTHENTICATED SENDER
                            // (fail-closed), identically to the winner path above: a batch hash
                            // is NOT sender-unique, so a report the store holds for these bytes
                            // may belong to a DIFFERENT authenticated sender. Adopting it would
                            // attribute another sender's verdict to OUR (authenticated_sender,
                            // nonce), bypassing the per-frame gossiping_peer_kernel_id ==
                            // authenticated_sender binding. The runtime-store lookup is now itself
                            // sender-scoped at the query level; the `.filter` re-checks the
                            // deserialized sender as belt-and-suspenders. A wrong-sender (or
                            // absent) report denies here so the peer retries and the durable inbox
                            // short-circuits once THIS sender's own verdict is recorded.
                            if let Some(recovered) = self
                                .receiver
                                .recorded_report_for_batch(&batch_sha256, &authenticated_sender)
                                .await?
                                .filter(|recovered| {
                                    recovered.authenticated_sender_kernel_id == authenticated_sender
                                })
                            {
                                // Adopt the durable verdict as the inbox record so both
                                // peers converge. record_inbox is idempotent (ON CONFLICT),
                                // so a concurrent winner recording first is harmless.
                                let _ = self.store.record_inbox(
                                    &authenticated_sender,
                                    &nonce,
                                    &batch,
                                    &recovered,
                                )?;
                                // Release the committed residual reservation now that the
                                // durable inbox row short-circuits any later redelivery at
                                // lookup_inbox_report before the reservation is consulted.
                                // The lane accept counter is NOT incremented here: `handle`
                                // returns Ok on this recovery and `accept` counts
                                // LANE_OUTCOME_ACCEPT once for every Ok(()), so counting here too
                                // would double-count one recovered redelivery (metric dedupe).
                                self.store
                                    .release_inbox_slot(&authenticated_sender, &nonce)?;
                                recovered
                            } else {
                                // Fail-closed if there is no durable verdict FOR THIS SENDER
                                // to recover: the peer retries and the durable inbox
                                // short-circuits the retry once the winner records.
                                return Err(IrohLaneError::DedupInFlight(format!(
                                    "sender {authenticated_sender} nonce {nonce} still receiving"
                                )));
                            }
                        }
                    }
                }
            }
        };

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
        use tracing::Instrument;
        // Concurrency cap: acquire one in-flight permit (held for the whole
        // handler) or shed under saturation with a distinct busy code, so one
        // hostile peer cannot spawn unbounded accept tasks.
        let _permit = match self.limiter.admit_peer(&conn.remote_id()).await {
            Ok(permit) => permit,
            Err(error) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_PHEROMONE,
                    crate::metrics::LANE_OUTCOME_BUSY,
                );
                tracing::warn!(
                    code = error.code(),
                    "pheromone lane shed accept (saturated)"
                );
                conn.close(error.close_code().into(), error.code().as_bytes());
                return Err(AcceptError::from_err(error));
            }
        };
        let span = crate::observability::lane_accept_span(crate::metrics::LANE_PHEROMONE);
        let _open = crate::metrics::AcceptOpenGuard::enter(crate::metrics::LANE_PHEROMONE);
        let started = std::time::Instant::now();
        let result = self.handle(&conn).instrument(span.clone()).await;
        crate::metrics::observe_accept_duration_nanos(
            crate::metrics::LANE_PHEROMONE,
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
        );
        match result {
            Ok(()) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_PHEROMONE,
                    crate::metrics::LANE_OUTCOME_ACCEPT,
                );
                crate::observability::record_outcome(&span, crate::metrics::LANE_OUTCOME_ACCEPT);
                // Bounded linger: keep the connection open until the dialer has
                // read the report and closed (so the finished stream is not reset
                // on drop), but never past the linger bound.
                self.limiter.linger(&conn).await;
                Ok(())
            }
            Err(error) => {
                let outcome = crate::metrics::accept_outcome_for_code(error.code());
                crate::metrics::record_lane_frame(crate::metrics::LANE_PHEROMONE, outcome);
                crate::observability::record_outcome(&span, outcome);
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

/// Outcome of a single dial-side delivery: the peer's `accepted` verdict (read from
/// a fully validated receive report; a partial/malformed report is rejected before
/// this is ever produced) plus the raw canonical report bytes for callers that hold
/// the runtime report type.
#[derive(Debug, Clone)]
pub struct BatchDeliveryOutcome {
    /// Whether the receiving peer accepted the whole batch.
    pub accepted: bool,
    /// Canonical JSON bytes of the peer's `PheromoneReceiveReport`.
    pub report_json: Vec<u8>,
}

/// The batch-level verdict enum mirrored from the runtime `PheromoneReceiveReport`,
/// so an unknown or absent outcome string is rejected fail-closed alongside a missing
/// field when a receive report is validated.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiveReportOutcome {
    Accepted,
    Partial,
    Rejected,
}

/// The set of fields a COMPLETE `PheromoneReceiveReport` (the runtime relay's receive
/// verdict) carries on the wire, deserialized on the dial side to REJECT a partial or
/// malformed report BEFORE a batch is marked durably delivered (see
/// [`deliver_batch_over_iroh_with_limits`]). Every field is required, so serde rejects
/// a report that omits any of them (for example a buggy or misrouted ALPN handler
/// answering `{"accepted":true}`); it is deliberately NOT `deny_unknown_fields` so a
/// forward-compatible report that ADDS fields still verifies. This crate mirrors the
/// runtime report's shape rather than depending on the runtime type (the same reason
/// the batch itself is exchanged as canonical bytes).
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct ReceiveReportShape {
    schema: String,
    accepted: bool,
    batch_outcome: ReceiveReportOutcome,
    accepted_frame_count: u64,
    rejected_frame_count: u64,
    batch_sha256: String,
    recipient_kernel_id: String,
    authenticated_sender_kernel_id: String,
    received_at_unix_ms: u64,
    frames: Vec<serde_json::Value>,
}

/// Bound one peer-dependent client await by the phase's timeout, mirroring the
/// accept-side [`AcceptLimiter::bounded`]. On timeout this fails closed with the
/// same [`AcceptLimitError::Timeout`] the accept side raises, so a stalled dial
/// folds into the durable outbox retry/dead-letter path via [`IrohLaneError::code`]
/// (`accept_timeout`) rather than hanging the sequential drain forever.
async fn client_bounded<T, F>(
    limits: &AcceptLimitConfig,
    phase: AcceptPhase,
    fut: F,
) -> Result<T, IrohLaneError>
where
    F: std::future::Future<Output = T>,
{
    let bound = limits.phase_timeout(phase);
    match tokio::time::timeout(bound, fut).await {
        Ok(output) => Ok(output),
        Err(_elapsed) => Err(IrohLaneError::AcceptLimit(AcceptLimitError::Timeout {
            phase,
            timeout_ms: u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
        })),
    }
}

/// Sender side of lane a: dial a peer over [`ALPN_PHEROMONE_BATCH`], write one
/// length-delimited canonical [`PheromoneGossipBatch`], and read back the report.
///
/// The iroh replacement for `PheromoneRelayClient::post_batch`
/// (`service.rs:652`). `recipient_addr` is the peer resolved from its
/// `kernel_id` via the directory (an [`EndpointId`] in production with
/// discovery, or a full [`EndpointAddr`] for direct addressing).
///
/// Uses the generous default client bounds
/// ([`AcceptLimitConfig::default`]); see [`deliver_batch_over_iroh_with_limits`]
/// to tune them.
pub async fn deliver_batch_over_iroh(
    endpoint: &Endpoint,
    recipient_addr: impl Into<EndpointAddr>,
    batch: &PheromoneGossipBatch,
) -> Result<BatchDeliveryOutcome, IrohLaneError> {
    deliver_batch_over_iroh_with_limits(
        endpoint,
        recipient_addr,
        batch,
        &AcceptLimitConfig::default(),
    )
    .await
}

/// Same as [`deliver_batch_over_iroh`], with explicit client-side bounds.
///
/// Client-side slowloris defense (mirrors the accept-side [`AcceptLimiter`]):
/// every peer-dependent await (connect, open, write, and the report read) is
/// bounded by the corresponding [`AcceptLimitConfig`] phase timeout. A recipient
/// that connects but never returns the report frame no longer hangs the caller
/// forever; the dial fails closed (`accept_timeout`) and the durable outbox lease
/// retries or dead-letters normally, so one stalled peer cannot block the
/// sequential drain of later batches.
pub async fn deliver_batch_over_iroh_with_limits(
    endpoint: &Endpoint,
    recipient_addr: impl Into<EndpointAddr>,
    batch: &PheromoneGossipBatch,
    limits: &AcceptLimitConfig,
) -> Result<BatchDeliveryOutcome, IrohLaneError> {
    let batch_bytes = canonical_json_bytes(batch)
        .map_err(|error| IrohLaneError::CanonicalJson(error.to_string()))?;

    let conn = client_bounded(
        limits,
        AcceptPhase::AcceptStream,
        endpoint.connect(recipient_addr, ALPN_PHEROMONE_BATCH),
    )
    .await?
    .map_err(|error| IrohLaneError::Transport(error.to_string()))?;
    let (mut send, mut recv) = client_bounded(limits, AcceptPhase::AcceptStream, conn.open_bi())
        .await?
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

    client_bounded(
        limits,
        AcceptPhase::WriteResponse,
        write_len_delimited(&mut send, &batch_bytes),
    )
    .await??;
    send.finish()
        .map_err(|error| IrohLaneError::Transport(error.to_string()))?;

    // The primary client-side hang surface: a peer that accepts the batch but
    // never returns the report frame is dropped here at the read bound. The report
    // is our own peer's response, so it is bounded by the transport hard cap.
    let report_json = client_bounded(
        limits,
        AcceptPhase::ReadFrame,
        read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES),
    )
    .await??;
    conn.close(LANE_OK_CODE.into(), b"ok");

    // Fail-closed durable-delivery gate: a batch is only ever marked delivered (and
    // its durable outbox row discarded by `drain_outbox_over_iroh`) once the recipient
    // returns a COMPLETE, well-typed receive report - not merely any JSON carrying
    // `accepted: true`. A buggy or misrouted ALPN handler answering `{"accepted":true}`
    // deserializes here as a PARTIAL report (missing the required fields) and is
    // REJECTED with a typed [`IrohLaneError::Codec`], so the drain retries or
    // dead-letters the batch rather than dropping it. This mirrors the HTTP relay tick,
    // which deserializes the full `PheromoneReceiveReport` type before trusting
    // `accepted`. `report_json` is still surfaced verbatim for callers that hold the
    // runtime report type.
    let report: ReceiveReportShape = serde_json::from_slice(&report_json)?;

    Ok(BatchDeliveryOutcome {
        accepted: report.accepted,
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
///
/// `scope_check` mirrors the HTTP tick's `enforce_outbound_peer_batch_directory_scope`
/// and MUST be applied against the CURRENT directory: a queued row whose recipient
/// was removed or is otherwise outside the recipient's directory scope is rejected
/// BEFORE it is dialed, so stale-or-unauthorized queued work is never leaked over
/// the new transport. Its `Err` folds into the durable retry/dead-letter path with
/// the mirrored scope code (fail-closed); the wiring supplies the shipped check so
/// the two transports enforce the same scope.
pub async fn drain_outbox_over_iroh<F, S>(
    store: &SqlitePheromoneRelayStore,
    endpoint: &Endpoint,
    resolve_addr: F,
    scope_check: S,
    sender_kernel_id: &str,
    now_unix_ms: u64,
    max_batches: usize,
) -> Result<OutboxDrainReport, IrohLaneError>
where
    F: Fn(&str) -> Option<EndpointAddr>,
    S: Fn(&str, &PheromoneGossipBatch) -> Result<(), PheromoneRelayError>,
{
    let due = store.lease_due_batches(now_unix_ms, max_batches)?;
    let mut report = OutboxDrainReport::default();
    for entry in due {
        if entry.sender_kernel_id != sender_kernel_id {
            // A row leased for a DIFFERENT sender is re-queued, NOT routed through
            // record_delivery_failure (which dead-letters after 3 attempts). Mirror
            // the HTTP deliver tick (service.rs deliver_due_batches): the row belongs
            // to another sender's drain, so it must stay available for that sender
            // rather than being permanently dead-lettered here.
            store.mark_retry(
                &entry.outbox_id,
                "sender_mismatch",
                now_unix_ms.saturating_add(60_000),
            )?;
            report.retried = report.retried.saturating_add(1);
            report
                .failures
                .push(format!("{}: sender_mismatch", entry.outbox_id));
            continue;
        }
        // ENFORCE OUTBOUND PEER SCOPE (fail-closed): mirror the HTTP deliver tick.
        // A recipient removed from / outside the current directory scope must not be
        // dialed over iroh even if `resolve_addr` still yields an address; the row
        // folds into the durable retry/dead-letter path with the scope code.
        if let Err(error) = scope_check(&entry.recipient_kernel_id, &entry.batch) {
            record_delivery_failure(store, &entry, error.code(), now_unix_ms, &mut report)?;
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
                // Observe-only: the iroh outbox drain emits the delivery outcome the
                // shipped HTTP relay already meters.
                crate::metrics::record_outbox(crate::metrics::OUTBOX_DELIVERED);
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
        // OBSERVE-ONLY: a dead-lettered batch is an operator-actionable signal
        // (delivery has permanently failed for this batch). Counted + logged with
        // the durable outbox `code`; the retry/dead-letter decision is unchanged.
        crate::metrics::record_outbox(crate::metrics::OUTBOX_DEAD_LETTERED);
        tracing::warn!(
            target: crate::observability::TARGET_OUTBOX,
            outbox_id = %entry.outbox_id,
            code = code,
            "pheromone outbox batch dead-lettered"
        );
    } else {
        let backoff_ms = 60_000u64.saturating_mul(entry.attempts.saturating_add(1));
        store.mark_retry(
            &entry.outbox_id,
            code,
            now_unix_ms.saturating_add(backoff_ms),
        )?;
        report.retried = report.retried.saturating_add(1);
        crate::metrics::record_outbox(crate::metrics::OUTBOX_RETRIED);
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
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;

    const NOW: u64 = 1_766_000_000_500;
    const RECIPIENT: &str = "did:chio:buyer-kernel";
    const TREATY: &str = "treaty:buyer-llamaworks:support-ops";
    const NAMESPACE: &str = "dev.chio.support";

    /// Serializes every test that records a pheromone-lane ACCEPT so the double-count
    /// tests can assert an EXACT delta on the process-global metric
    /// statics. Without it, the ~8 parallel accept-counting tests in this module would
    /// perturb the shared counter between a test's before/after reads. Any NEW test that
    /// drives a successful delivery (a lane ACCEPT) MUST acquire this guard.
    static COUNTED_ACCEPT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Read the pheromone-lane ACCEPT counter once it stops advancing. The acceptor
    /// records the metric in `accept()` AFTER `handle` returns - i.e. after the dialer has
    /// already read the report and `deliver_batch_over_iroh` returned - so a naive read
    /// right after delivery can miss it. Serialized by [`COUNTED_ACCEPT_SERIAL`], only
    /// this test's own delivery can advance the counter, so waiting for it to reach
    /// `at_least` and then hold steady is deterministic.
    async fn settled_pheromone_accept_total(before: u64, at_least: u64) -> u64 {
        let read = || {
            crate::metrics::lane_total(
                crate::metrics::LANE_PHEROMONE,
                crate::metrics::LANE_OUTCOME_ACCEPT,
            )
        };
        let mut last = read();
        let mut stable = 0u32;
        for _ in 0..400 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let now = read();
            if now == last && now >= before + at_least {
                stable += 1;
                if stable >= 4 {
                    return now;
                }
            } else if now != last {
                stable = 0;
                last = now;
            }
        }
        last
    }

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
            treaties: Vec::new(),
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

    /// A complete receive report round-trips through the dial-side validation shape
    /// and yields its `accepted` verdict.
    #[test]
    fn full_receive_report_validates_and_carries_accepted() {
        let report = serde_json::json!({
            "schema": "chio.pheromone.receive-report.v1",
            "accepted": true,
            "batchOutcome": "accepted",
            "acceptedFrameCount": 2,
            "rejectedFrameCount": 0,
            "batchSha256": "a".repeat(64),
            "recipientKernelId": "did:chio:relay",
            "authenticatedSenderKernelId": "did:chio:origin",
            "receivedAtUnixMs": NOW,
            "frames": [],
        });
        let bytes = serde_json::to_vec(&report).unwrap();
        let shape: ReceiveReportShape =
            serde_json::from_slice(&bytes).expect("a complete report must validate");
        assert!(shape.accepted, "the validated report carries accepted=true");
    }

    /// Fail-closed: a response that merely asserts `{"accepted":true}` (a buggy or
    /// misrouted ALPN handler) is NOT a full receive report and MUST be rejected so a
    /// batch is never marked durably delivered on it.
    #[test]
    fn partial_accepted_response_is_rejected_before_delivery() {
        let rejected = serde_json::from_slice::<ReceiveReportShape>(br#"{"accepted":true}"#);
        assert!(
            rejected.is_err(),
            "a partial report carrying only accepted:true must fail validation"
        );
        // An otherwise-complete report with an unknown batchOutcome is also rejected.
        let bad_outcome = serde_json::json!({
            "schema": "chio.pheromone.receive-report.v1",
            "accepted": true,
            "batchOutcome": "totally-unknown",
            "acceptedFrameCount": 0,
            "rejectedFrameCount": 0,
            "batchSha256": "a".repeat(64),
            "recipientKernelId": "did:chio:relay",
            "authenticatedSenderKernelId": "did:chio:origin",
            "receivedAtUnixMs": NOW,
            "frames": [],
        });
        let bytes = serde_json::to_vec(&bad_outcome).unwrap();
        assert!(
            serde_json::from_slice::<ReceiveReportShape>(&bytes).is_err(),
            "an unknown batchOutcome must fail validation fail-closed"
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
        let read = read_len_delimited(&mut reader, MAX_PHEROMONE_BATCH_BYTES)
            .await
            .unwrap();
        let decoded: PheromoneGossipBatch = serde_json::from_slice(&read).unwrap();
        assert_eq!(decoded, batch);
    }

    #[tokio::test]
    async fn over_cap_frame_is_rejected_before_allocation() {
        let mut framed: Vec<u8> = Vec::new();
        let oversized = (MAX_PHEROMONE_BATCH_BYTES as u32).saturating_add(1);
        framed.extend_from_slice(&oversized.to_be_bytes());
        let mut reader: &[u8] = &framed;
        let error = read_len_delimited(&mut reader, MAX_PHEROMONE_BATCH_BYTES)
            .await
            .unwrap_err();
        assert!(matches!(error, IrohLaneError::FrameTooLarge(_)));
        assert_eq!(error.code(), "frame_too_large");
    }

    #[tokio::test]
    async fn read_len_delimited_enforces_the_configured_ingress_cap() {
        // A frame WITHIN the transport hard cap but OVER the configured body limit is
        // rejected before allocation, so the iroh ingress is no laxer than the HTTP
        // relay's DefaultBodyLimit.
        let configured = 256_000usize; // production relay max_body_bytes
        let mut framed: Vec<u8> = Vec::new();
        let over_configured = (configured as u32).saturating_add(1);
        framed.extend_from_slice(&over_configured.to_be_bytes());
        let mut reader: &[u8] = &framed;
        let error = read_len_delimited(&mut reader, configured)
            .await
            .unwrap_err();
        match error {
            IrohLaneError::FrameTooLarge(len) => assert_eq!(len as u32, over_configured),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn incremental_read_holds_only_delivered_bytes() {
        // A frame that declares a large length but is fully delivered still reads
        // back byte-for-byte, and the buffer never pre-commits the declared length.
        let payload = vec![7u8; 200 * 1024];
        let mut framed = Vec::new();
        framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        framed.extend_from_slice(&payload);
        let mut reader = std::io::Cursor::new(framed);
        let out = read_len_delimited(&mut reader, 8 * 1024 * 1024)
            .await
            .expect("a fully-delivered frame reads back");
        assert_eq!(out, payload);

        // A truncated body (declares more than it delivers) fails with an EOF Io
        // error after consuming only the delivered bytes, never allocating `len`.
        let mut short = Vec::new();
        short.extend_from_slice(&(64u32 * 1024).to_be_bytes());
        short.extend_from_slice(&[1u8; 10]); // only 10 of 65536 bytes delivered
        let mut reader = std::io::Cursor::new(short);
        let err = read_len_delimited(&mut reader, 8 * 1024 * 1024)
            .await
            .expect_err("a truncated frame is rejected");
        assert!(matches!(err, IrohLaneError::Io(_)), "unexpected: {err:?}");
    }

    // -- Inbox-reservation lifecycle (InboxSlotGuard) --
    //
    // The winner's slot lifecycle is: reserve -> receive (self-commits) -> record.
    // These drive the guard's state machine directly (the real receiver's report
    // type is not nameable here, so the store seam is exercised through the guard,
    // observing outcomes via reserve/lookup).

    const GUARD_SENDER: &str = "did:chio:llamaworks";

    #[test]
    fn receive_fail_releases_slot_for_reclaim() {
        // Winner reserves, then models a FAILED receive: the guard stays ARMED and
        // drops (the `?`-return / cancel / panic path). Nothing committed, so the
        // slot must be released and a redelivery re-wins and re-receives.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let nonce = "iroh-pheromone-batch:receive-fail";
        assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
        {
            let _slot = InboxSlotGuard::new(
                Arc::clone(&store),
                GUARD_SENDER.to_string(),
                nonce.to_string(),
            );
            // receive fails -> guard drops ARMED -> RELEASE.
        }
        assert!(
            store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
            "a failed receive must release so a redelivery can re-receive"
        );
        assert!(
            store
                .lookup_inbox_report(GUARD_SENDER, nonce)
                .unwrap()
                .is_none(),
            "no durable verdict is recorded when nothing committed"
        );
    }

    #[test]
    fn record_fail_leaves_slot_held_so_redelivery_never_re_receives() {
        // Winner reserves, the receive COMMITS (disarm), then record FAILS: the slot
        // must stay HELD so a redelivery loses the reservation and takes the loser /
        // fail-closed path, NEVER re-receiving the already-admitted batch (defect a).
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let nonce = "iroh-pheromone-batch:record-fail";
        assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
        {
            let mut slot = InboxSlotGuard::new(
                Arc::clone(&store),
                GUARD_SENDER.to_string(),
                nonce.to_string(),
            );
            slot.commit().unwrap(); // deposits committed (disarm + durable marker)
                                    // record_inbox fails -> do NOT release -> guard drops DISARMED.
        }
        assert!(
            !store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
            "a committed-but-unrecorded batch must leave the slot held, fail-closed"
        );
        assert!(
            store
                .lookup_inbox_report(GUARD_SENDER, nonce)
                .unwrap()
                .is_none(),
            "with no durable verdict the loser waits then fails closed, never re-receiving"
        );
    }

    #[test]
    fn record_ok_release_frees_slot_and_bounds_growth() {
        // Winner reserves, the receive COMMITS (disarm), record succeeds, then the
        // now-redundant reservation is released explicitly (bounds table growth). In
        // production the durable verdict recorded before release short-circuits any
        // redelivery at lookup_inbox_report BEFORE the reservation, so re-winning the
        // freed slot here is harmless.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let nonce = "iroh-pheromone-batch:record-ok";
        assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
        {
            let mut slot = InboxSlotGuard::new(
                Arc::clone(&store),
                GUARD_SENDER.to_string(),
                nonce.to_string(),
            );
            slot.commit().unwrap(); // deposits committed (disarm + durable marker)
            slot.release().unwrap(); // durable verdict recorded -> release the redundant row
                                     // guard drops already-disarmed -> no double release.
        }
        assert!(
            store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
            "a recorded success must release the redundant reservation"
        );
    }

    #[test]
    fn winning_the_reservation_does_not_prove_the_batch_is_unreceived() {
        // Premise of handle()'s post-win RE-READ (the "reservation won after
        // another handler recorded+released" race): because the winner RELEASES its slot
        // after recording the durable verdict (to bound reservation-table growth), a later
        // redelivery can WIN the SAME (sender, nonce) reservation AGAIN even though the
        // batch is already admitted. Winning therefore does NOT prove un-receipt, so
        // handle() must re-read lookup_inbox_report AFTER winning and return the recorded
        // verdict instead of re-running the receiver (which would re-enter the runtime
        // replay window and reject the already-accepted deposits).
        //
        // This isolates the store-level premise. The end-to-end winner-path re-read and
        // durable verdict adoption are covered by
        // `winner_path_adopts_durable_verdict_after_commit_before_mark_crash` below.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let nonce = "iroh-pheromone-batch:win-after-release";
        // Winner: reserve -> commit -> release, exactly as handle()'s record-Ok path does.
        assert!(store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won);
        {
            let mut slot = InboxSlotGuard::new(
                Arc::clone(&store),
                GUARD_SENDER.to_string(),
                nonce.to_string(),
            );
            slot.commit().unwrap();
            slot.release().unwrap();
        }
        // A redelivery re-WINS the freed slot: winning cannot be treated as proof of
        // un-receipt, which is precisely why handle() re-reads the durable inbox here.
        assert!(
            store.reserve_inbox_slot(GUARD_SENDER, nonce).unwrap().won,
            "a released slot is re-won by a redelivery, so a post-win re-read is required \
             to avoid re-receiving an already-admitted batch"
        );
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

    #[test]
    fn outbox_retry_and_dead_letter_bump_outbox_counters() {
        // OBSERVE-ONLY proof: the retry/dead-letter accounting is unchanged AND now
        // emits the outbox family the shipped HTTP relay already meters.
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let batch = direct_batch("did:chio:llamaworks");
        enqueue_batch_for_delivery(
            &store,
            "did:chio:llamaworks",
            RECIPIENT,
            TREATY,
            &batch,
            NOW,
        )
        .unwrap();
        let mut entry = store
            .lease_due_batches(NOW, 10)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let before_retry = crate::metrics::outbox_total(crate::metrics::OUTBOX_RETRIED);
        let before_dead = crate::metrics::outbox_total(crate::metrics::OUTBOX_DEAD_LETTERED);
        let mut report = OutboxDrainReport::default();
        for attempts in 0..3u64 {
            entry.attempts = attempts;
            record_delivery_failure(&store, &entry, "transport", NOW, &mut report).unwrap();
        }
        assert_eq!(report.retried, 2);
        assert_eq!(report.dead_lettered, 1);
        assert!(
            crate::metrics::outbox_total(crate::metrics::OUTBOX_RETRIED) > before_retry,
            "retries must be counted (observe-only)"
        );
        assert!(
            crate::metrics::outbox_total(crate::metrics::OUTBOX_DEAD_LETTERED) > before_dead,
            "dead-letters must be counted (observe-only)"
        );
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
            let raw = read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES)
                .await
                .map_err(AcceptError::from_err)?;
            // Prove the received bytes decode to the real wire type.
            let batch: PheromoneGossipBatch =
                serde_json::from_slice(&raw).map_err(AcceptError::from_err)?;
            // Emit a COMPLETE receive report, faithfully mirroring the runtime
            // `PheromoneReceiveReport` the production handler serializes. A partial
            // report (for example only `accepted`) is rejected on the dial side before
            // a batch is marked delivered, so the double must carry every field.
            let report = serde_json::json!({
                "schema": "chio.pheromone-receive-report.v1",
                "accepted": true,
                "batchOutcome": "accepted",
                "acceptedFrameCount": batch.frames.len() as u64,
                "rejectedFrameCount": 0,
                "batchSha256": "0".repeat(64),
                "recipientKernelId": batch.recipient_kernel_id,
                "authenticatedSenderKernelId": sender,
                "receivedAtUnixMs": 0u64,
                "frames": [],
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
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
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

    /// A receiver double that records whether `receive_batch` ever ran, so a deny-all
    /// swap between admission and receive can be proven to admit nothing.
    struct ReceiveProbe {
        received: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RelayBatchReceiver for ReceiveProbe {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
            self.received.store(true, Ordering::SeqCst);
            Err(PheromoneRelayError::Json(
                "receiver must not run after a deny-all swap".to_string(),
            ))
        }
    }

    #[tokio::test]
    async fn deny_all_swap_between_admission_and_receive_admits_nothing() {
        // A peer admitted at the handshake must not deliver a batch once the directory has
        // swapped to deny-all. The swap is published mid-handle - after the connection was
        // admitted and the request frame read, but before any receiver state is touched -
        // modeling the reloader publishing deny-all while a peer is already in flight. The
        // handler must re-resolve against the live directory and refuse to receive, so the
        // batch never reaches the receiver.
        let dialer_seed = 60u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

        let received = Arc::new(AtomicBool::new(false));
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(ReceiveProbe {
            received: Arc::clone(&received),
        });

        // Swap the shared directory to deny-all at the exact instant the batch is scoped.
        let swap_gate = gate.clone();
        let scope_check: InboundBatchScopeCheck = Arc::new(
            move |_sender: &str,
                  _batch: &PheromoneGossipBatch|
                  -> Result<(), PheromoneRelayError> {
                swap_gate.swap(Arc::new(
                    crate::identity::VerifiedDirectory::empty_deny_all(),
                ));
                Ok(())
            },
        );

        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
        let handler = PheromoneBatchHandler::new(
            gate.clone(),
            receiver,
            Arc::clone(&store),
            now,
            scope_check,
        );

        let acceptor = bind_endpoint(61, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let batch = direct_batch("did:chio:bob");
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery attempt completes before timeout");

        assert!(
            outcome.is_err(),
            "a batch delivered after the directory swapped to deny-all must fail closed"
        );
        assert!(
            !received.load(Ordering::SeqCst),
            "the receiver must never run once the directory has swapped to deny-all"
        );

        router.shutdown().await.ok();
    }

    /// A receiver double shared by BOTH recovery tests (loser and winner path):
    /// its `receive_batch` must never run (neither recovery path re-receives an
    /// already-admitted batch), and its `recorded_report_for_batch` surfaces the
    /// durably-committed runtime verdict. The panic is the teeth: any recovery path
    /// that re-runs the receiver trips it.
    struct RecoveringReceiver {
        report: chio_pheromone_runtime::PheromoneReceiveReport,
    }

    #[async_trait::async_trait]
    impl RelayBatchReceiver for RecoveringReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
            panic!("recovery path must not re-run receive_batch");
        }

        async fn recorded_report_for_batch(
            &self,
            _batch_sha256: &str,
            _authenticated_sender_kernel_id: &str,
        ) -> Result<Option<chio_pheromone_runtime::PheromoneReceiveReport>, PheromoneRelayError>
        {
            Ok(Some(self.report.clone()))
        }
    }

    #[tokio::test]
    async fn verdict_recovery_converges_after_commit_before_record_crash() {
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
        // A crash after receive_batch self-commits its deposits but before record_inbox
        // writes the durable verdict leaves the reservation committed=1. A redelivery
        // loses the slot and reaches the loser path; it must recover the durable verdict
        // (via recorded_report_for_batch) and converge, never dead-letter the accepted
        // batch.
        let dialer_seed = 40u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

        // The batch the dialer delivers, and the (sender, nonce) it keys on.
        let batch = direct_batch("did:chio:bob");
        let batch_bytes = canonical_json_bytes(&batch).unwrap();
        let nonce = inbox_nonce(&batch_bytes);
        let sender = "did:chio:bob";

        // Seed the crash-after-commit-before-record state: a COMMITTED residual
        // reservation for (sender, nonce) with NO recorded verdict, so the handler's
        // reserve_inbox_slot loses and the redelivery takes the loser path.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        assert!(store.reserve_inbox_slot(sender, &nonce).unwrap().won);
        store
            .mark_inbox_reservation_committed(sender, &nonce)
            .unwrap();
        assert!(store.lookup_inbox_report(sender, &nonce).unwrap().is_none());

        // The durable verdict the runtime store committed before the crash, surfaced
        // by the receiver double. Its batch_sha256 matches the handler's lookup key
        // (canonical_sha256 of the batch), though the double returns it regardless.
        let canned = chio_pheromone_runtime::PheromoneReceiveReport {
            schema: "chio.pheromone-receive-report.v1".to_string(),
            accepted: true,
            batch_outcome: chio_pheromone_runtime::PheromoneBatchOutcome::Accepted,
            accepted_frame_count: batch.frames.len() as u64,
            rejected_frame_count: 0,
            batch_sha256: core_sha256_hex(&batch_bytes),
            recipient_kernel_id: RECIPIENT.to_string(),
            authenticated_sender_kernel_id: sender.to_string(),
            received_at_unix_ms: NOW,
            frames: Vec::new(),
        };

        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RecoveringReceiver { report: canned });
        let scope_check: InboundBatchScopeCheck = Arc::new(
            |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
                Ok(())
            },
        );
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
        let handler = PheromoneBatchHandler::new(
            gate.clone(),
            receiver,
            Arc::clone(&store),
            now,
            scope_check,
        );

        let before = crate::metrics::lane_total(
            crate::metrics::LANE_PHEROMONE,
            crate::metrics::LANE_OUTCOME_ACCEPT,
        );

        let acceptor = bind_endpoint(41, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("loser path recovers the durable verdict and returns it");

        // Convergence: the dialer reads the recovered accepted verdict, and the
        // durable inbox now records it so a further redelivery short-circuits.
        assert!(
            outcome.accepted,
            "the recovered verdict is the accepted one"
        );
        assert!(
            store.lookup_inbox_report(sender, &nonce).unwrap().is_some(),
            "recovery adopts the durable verdict as the inbox record"
        );
        // Metric dedupe: a recovered redelivery must count EXACTLY ONE accept, like a
        // fresh delivery or an inbox hit. `accept` counts one accept for every Ok(()); a
        // stray inner count in handle's loser-path recovery would emit a SECOND sample
        // (delta == 2 instead of 1).
        let after = settled_pheromone_accept_total(before, 1).await;
        assert_eq!(
            after - before,
            1,
            "loser-path recovery counts exactly one accept, not two"
        );

        router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn winner_path_adopts_durable_verdict_after_commit_before_mark_crash() {
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
        // WINNER path, symmetric with the loser-path recovery above.
        // The winner and loser paths cover two DIFFERENT crash windows, distinguished
        // solely by the reservation's committed flag at open:
        //  - LOSER window (test above): a crash AFTER slot.commit() leaves a
        //    committed = 1 reservation that SURVIVES clear-at-open, so a redelivery
        //    LOSES reserve_inbox_slot and takes the loser path.
        //  - WINNER window (this test): a crash BETWEEN receive_batch self-committing
        //    its runtime deposits (in the RUNTIME store) and slot.commit() marking the
        //    RELAY reservation committed leaves committed = 0, which the store reclaims
        //    at open. A redelivery therefore WINS reserve_inbox_slot, re-reads the RELAY
        //    inbox (still None), and, absent the runtime-store consult, would re-run
        //    receive_batch on an already-admitted batch. The runtime replay-nonce
        //    idempotency then turns every frame into ReplayWindowExceeded, recording +
        //    returning a spurious REJECTED verdict that dead-letters an accepted batch.
        //    The winner path instead consults the RUNTIME store by batch_sha256 first and
        //    ADOPTS the durable verdict, never re-running receive_batch.
        //
        // The shared RecoveringReceiver double PANICS if receive_batch is called: a winner
        // path that re-ran the receiver would trip the panic (the delivery fails / never
        // returns the accepted report). The recovery path instead adopts the durable
        // verdict without touching the receiver.
        let dialer_seed = 44u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

        // The batch the dialer redelivers, and the (sender, nonce) it keys on.
        let batch = direct_batch("did:chio:bob");
        let batch_bytes = canonical_json_bytes(&batch).unwrap();
        let nonce = inbox_nonce(&batch_bytes);
        let sender = "did:chio:bob";

        // Reproduce the crash-before-mark residual: an EMPTY relay reservation table
        // (the committed = 0 reservation was reclaimed at open) and NO recorded inbox
        // verdict, so the handler's own reserve_inbox_slot WINS and the post-win re-read
        // finds None - the winner path. Only the RUNTIME store (via the receiver double)
        // holds the durable verdict.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        assert!(
            store.lookup_inbox_report(sender, &nonce).unwrap().is_none(),
            "no relay inbox verdict is recorded before recovery (winner-path premise)"
        );

        // The durable verdict the runtime store committed before the crash, surfaced by
        // the receiver double. Its batch_sha256 matches the handler's lookup key
        // (canonical sha256 of the batch), though the double returns it regardless.
        let canned = chio_pheromone_runtime::PheromoneReceiveReport {
            schema: "chio.pheromone-receive-report.v1".to_string(),
            accepted: true,
            batch_outcome: chio_pheromone_runtime::PheromoneBatchOutcome::Accepted,
            accepted_frame_count: batch.frames.len() as u64,
            rejected_frame_count: 0,
            batch_sha256: core_sha256_hex(&batch_bytes),
            recipient_kernel_id: RECIPIENT.to_string(),
            authenticated_sender_kernel_id: sender.to_string(),
            received_at_unix_ms: NOW,
            frames: Vec::new(),
        };

        // The SHARED double: receive_batch PANICS (teeth), recorded_report_for_batch
        // returns the durable verdict. A winner path that re-ran the receiver would panic
        // here; the recovery path adopts the durable verdict instead.
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(RecoveringReceiver { report: canned });
        let scope_check: InboundBatchScopeCheck = Arc::new(
            |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
                Ok(())
            },
        );
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
        let handler = PheromoneBatchHandler::new(
            gate.clone(),
            receiver,
            Arc::clone(&store),
            now,
            scope_check,
        );

        let before = crate::metrics::lane_total(
            crate::metrics::LANE_PHEROMONE,
            crate::metrics::LANE_OUTCOME_ACCEPT,
        );

        let acceptor = bind_endpoint(45, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("the winner path adopts the durable verdict (never re-runs receive_batch)");

        // Convergence: the dialer reads the recovered ACCEPTED verdict (not a spurious
        // ReplayWindowExceeded REJECTED), the durable inbox now records it so a further
        // redelivery short-circuits, and the recovery counts an accept, never a
        // dead-letter.
        assert!(
            outcome.accepted,
            "the winner path returns the recovered accepted verdict, not a spurious rejection"
        );
        assert!(
            store.lookup_inbox_report(sender, &nonce).unwrap().is_some(),
            "winner-path recovery adopts the durable verdict as the inbox record"
        );
        // Metric dedupe: a recovered redelivery must count EXACTLY ONE accept. A stray
        // winner-path inner count would make delta == 2 instead of 1.
        let after = settled_pheromone_accept_total(before, 1).await;
        assert_eq!(
            after - before,
            1,
            "winner-path recovery counts exactly one accept, not two"
        );

        router.shutdown().await.ok();
    }

    /// A receiver double for the sender-scoping tests: its
    /// `recorded_report_for_batch` returns a durable verdict recorded under a
    /// DIFFERENT authenticated sender, and its `receive_batch` records that it ran
    /// (via `received`) and returns a distinguishable FRESH verdict. A recovery
    /// path that (wrongly) adopts the cross-sender verdict never runs receive_batch;
    /// the SCOPED path discards it and either falls through to receive_batch (winner)
    /// or denies (loser).
    struct WrongSenderRecoveringReceiver {
        recovered: chio_pheromone_runtime::PheromoneReceiveReport,
        fresh: chio_pheromone_runtime::PheromoneReceiveReport,
        received: Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait::async_trait]
    impl RelayBatchReceiver for WrongSenderRecoveringReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
            self.received
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(self.fresh.clone())
        }

        async fn recorded_report_for_batch(
            &self,
            _batch_sha256: &str,
            _authenticated_sender_kernel_id: &str,
        ) -> Result<Option<chio_pheromone_runtime::PheromoneReceiveReport>, PheromoneRelayError>
        {
            Ok(Some(self.recovered.clone()))
        }
    }

    /// Build a `PheromoneReceiveReport` for these `batch` bytes under `sender` with
    /// the given `accepted` outcome, for the sender-scoping tests.
    fn scoping_report(
        batch: &PheromoneGossipBatch,
        batch_bytes: &[u8],
        sender: &str,
        accepted: bool,
    ) -> chio_pheromone_runtime::PheromoneReceiveReport {
        let frame_count = batch.frames.len() as u64;
        chio_pheromone_runtime::PheromoneReceiveReport {
            schema: "chio.pheromone-receive-report.v1".to_string(),
            accepted,
            batch_outcome: if accepted {
                chio_pheromone_runtime::PheromoneBatchOutcome::Accepted
            } else {
                chio_pheromone_runtime::PheromoneBatchOutcome::Rejected
            },
            accepted_frame_count: if accepted { frame_count } else { 0 },
            rejected_frame_count: if accepted { 0 } else { frame_count },
            batch_sha256: core_sha256_hex(batch_bytes),
            recipient_kernel_id: RECIPIENT.to_string(),
            authenticated_sender_kernel_id: sender.to_string(),
            received_at_unix_ms: NOW,
            frames: Vec::new(),
        }
    }

    #[tokio::test]
    async fn winner_path_rejects_recovered_verdict_from_a_different_sender() {
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
        // Sender-scoping (SECURITY). The runtime store keys receive reports by
        // batch_sha256 ALONE, so a verdict it holds for these batch bytes may have been
        // recorded under a DIFFERENT authenticated sender. The winner path must NOT adopt
        // such a verdict verbatim: that would attribute another sender's accept/reject to
        // THIS (sender, nonce), bypassing the per-frame gossiping_peer_kernel_id ==
        // authenticated_sender binding. It must discard the cross-sender verdict and fall
        // through to receive_batch, re-verifying under THIS sender.
        //
        // recorded_report_for_batch returns an ACCEPTED verdict recorded under
        // "did:chio:alice"; the authenticated sender is "did:chio:bob"; the fresh
        // receive_batch verdict for bob is a distinguishable REJECTED one. An unscoped
        // winner path would adopt alice's accepted verdict (the dialer reads accepted ==
        // true and receive_batch never runs); the scoped winner path discards alice's
        // verdict, runs receive_batch under bob, and returns bob's rejected verdict.
        let dialer_seed = 46u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

        let batch = direct_batch("did:chio:bob");
        let batch_bytes = canonical_json_bytes(&batch).unwrap();
        let nonce = inbox_nonce(&batch_bytes);
        let sender = "did:chio:bob";

        // Empty reservation table + no recorded inbox verdict => the handler wins its
        // own reserve_inbox_slot and the post-win re-read finds None: the winner path.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        assert!(store.lookup_inbox_report(sender, &nonce).unwrap().is_none());

        // The runtime store holds an ACCEPTED verdict for these bytes recorded under a
        // DIFFERENT authenticated sender (alice); the fresh receive_batch verdict for
        // bob is a distinguishable REJECTED one.
        let recovered = scoping_report(&batch, &batch_bytes, "did:chio:alice", true);
        let fresh = scoping_report(&batch, &batch_bytes, sender, false);
        let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(WrongSenderRecoveringReceiver {
            recovered,
            fresh,
            received: Arc::clone(&received),
        });
        let scope_check: InboundBatchScopeCheck = Arc::new(
            |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
                Ok(())
            },
        );
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
        let handler = PheromoneBatchHandler::new(
            gate.clone(),
            receiver,
            Arc::clone(&store),
            now,
            scope_check,
        );

        let acceptor = bind_endpoint(47, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("the scoped winner path returns the fresh verdict, not the cross-sender one");

        assert!(
            !outcome.accepted,
            "a verdict recorded under a DIFFERENT sender is NOT adopted; the fresh receive_batch verdict (rejected) is returned"
        );
        assert!(
            received.load(std::sync::atomic::Ordering::SeqCst),
            "the scoped winner path falls through to receive_batch under THIS sender"
        );
        let stored = store.lookup_inbox_report(sender, &nonce).unwrap().unwrap();
        assert_eq!(
            stored.authenticated_sender_kernel_id, sender,
            "the recorded inbox verdict is scoped to THIS authenticated sender, not the recovered one"
        );

        router.shutdown().await.ok();
    }

    #[tokio::test]
    async fn loser_path_rejects_recovered_verdict_from_a_different_sender() {
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
        // Sender-scoping (SECURITY), loser path. Symmetric with the winner-path test: a
        // committed residual reservation with no recorded inbox verdict sends the
        // redelivery down the loser path, where the runtime store holds a verdict for
        // these bytes recorded under a DIFFERENT sender. The loser path must NOT adopt it
        // (that would hand THIS sender another sender's accepted verdict); it must deny
        // (fail-closed DedupInFlight).
        //
        // recorded_report_for_batch returns an ACCEPTED verdict recorded under
        // "did:chio:alice"; the authenticated sender is "did:chio:bob". The loser path
        // never calls receive_batch, so `received` stays false either way. An unscoped
        // loser path would adopt alice's accepted verdict (the dialer reads accepted ==
        // true); the scoped loser path denies and the delivery fails closed.
        let dialer_seed = 48u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);

        let batch = direct_batch("did:chio:bob");
        let batch_bytes = canonical_json_bytes(&batch).unwrap();
        let nonce = inbox_nonce(&batch_bytes);
        let sender = "did:chio:bob";

        // Seed the crash-after-commit residual: a COMMITTED reservation for
        // (sender, nonce) with NO recorded verdict, so reserve_inbox_slot LOSES and
        // the redelivery takes the loser path.
        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        assert!(store.reserve_inbox_slot(sender, &nonce).unwrap().won);
        store
            .mark_inbox_reservation_committed(sender, &nonce)
            .unwrap();
        assert!(store.lookup_inbox_report(sender, &nonce).unwrap().is_none());

        let recovered = scoping_report(&batch, &batch_bytes, "did:chio:alice", true);
        let fresh = scoping_report(&batch, &batch_bytes, sender, false);
        let received = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(WrongSenderRecoveringReceiver {
            recovered,
            fresh,
            received: Arc::clone(&received),
        });
        let scope_check: InboundBatchScopeCheck = Arc::new(
            |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
                Ok(())
            },
        );
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
        let handler = PheromoneBatchHandler::new(
            gate.clone(),
            receiver,
            Arc::clone(&store),
            now,
            scope_check,
        );

        let acceptor = bind_endpoint(49, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout");

        assert!(
            result.is_err(),
            "the scoped loser path denies a cross-sender recovered verdict (fail-closed), never adopts it"
        );
        assert!(
            !received.load(std::sync::atomic::Ordering::SeqCst),
            "the loser path never re-runs receive_batch"
        );
        assert!(
            store.lookup_inbox_report(sender, &nonce).unwrap().is_none(),
            "no cross-sender verdict is recorded as THIS sender's inbox record"
        );

        router.shutdown().await.ok();
    }

    /// A receiver double that always accepts, for the per-peer-cap wiring test.
    struct AcceptingReceiver {
        report: chio_pheromone_runtime::PheromoneReceiveReport,
    }

    #[async_trait::async_trait]
    impl RelayBatchReceiver for AcceptingReceiver {
        async fn receive_batch(
            &self,
            _batch: PheromoneGossipBatch,
            _authenticated_sender_kernel_id: String,
            _received_at_unix_ms: u64,
        ) -> Result<chio_pheromone_runtime::PheromoneReceiveReport, PheromoneRelayError> {
            Ok(self.report.clone())
        }
    }

    #[tokio::test]
    async fn per_peer_cap_one_still_admits_a_single_dialer() {
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
        // A per-peer cap of 1 must not break a single, sequential dialer: the guard
        // releases when the handler task ends, so the exchange completes (the accept site
        // calls admit_peer, not admit).
        let dialer_seed = 42u8;
        let gate = verified_gate("did:chio:bob", 1, dialer_seed, false);
        let batch = direct_batch("did:chio:bob");
        let batch_bytes = canonical_json_bytes(&batch).unwrap();
        let report = chio_pheromone_runtime::PheromoneReceiveReport {
            schema: "chio.pheromone-receive-report.v1".to_string(),
            accepted: true,
            batch_outcome: chio_pheromone_runtime::PheromoneBatchOutcome::Accepted,
            accepted_frame_count: batch.frames.len() as u64,
            rejected_frame_count: 0,
            batch_sha256: core_sha256_hex(&batch_bytes),
            recipient_kernel_id: RECIPIENT.to_string(),
            authenticated_sender_kernel_id: "did:chio:bob".to_string(),
            received_at_unix_ms: NOW,
            frames: Vec::new(),
        };

        let store = Arc::new(SqlitePheromoneRelayStore::open_in_memory().unwrap());
        let receiver: Arc<dyn RelayBatchReceiver> = Arc::new(AcceptingReceiver { report });
        let scope_check: InboundBatchScopeCheck = Arc::new(
            |_sender: &str, _batch: &PheromoneGossipBatch| -> Result<(), PheromoneRelayError> {
                Ok(())
            },
        );
        let now: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(|| NOW);
        let handler = PheromoneBatchHandler::new(gate.clone(), receiver, store, now, scope_check)
            .with_accept_limits(AcceptLimitConfig {
                max_in_flight_per_peer: 1,
                ..AcceptLimitConfig::default()
            });

        let acceptor = bind_endpoint(43, Some(gate.clone())).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, handler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(dialer_seed, None).await;
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh(&dialer, acceptor_addr, &batch),
        )
        .await
        .expect("delivery completes before timeout")
        .expect("a per-peer cap of 1 still admits a single dialer");
        assert!(
            outcome.accepted,
            "single dialer under per-peer cap 1 is accepted"
        );

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
    // `CannedReportHandler` isolates handshake rejection. The focused handler below
    // binds the gate-resolved sender to per-frame verification over QUIC. The
    // `PheromoneBatchHandler` receive, persistence, and recovery paths are exercised
    // by the preceding loopback tests.

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
            let raw = read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES)
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

            // A COMPLETE receive report, faithfully mirroring the runtime type; a
            // partial report is rejected on the dial side before a batch is marked
            // delivered (see [`ReceiveReportShape`]).
            let frame_count = batch.frames.len() as u64;
            let report = serde_json::json!({
                "schema": "chio.pheromone-receive-report.v1",
                "accepted": accepted,
                "batchOutcome": if accepted { "accepted" } else { "rejected" },
                "acceptedFrameCount": if accepted { frame_count } else { 0 },
                "rejectedFrameCount": if accepted { 0 } else { frame_count },
                "batchSha256": "0".repeat(64),
                "recipientKernelId": batch.recipient_kernel_id,
                "authenticatedSenderKernelId": sender,
                "receivedAtUnixMs": self.now_unix_ms,
                "frames": [],
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
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
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
        let _serial = COUNTED_ACCEPT_SERIAL.lock().await;
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

    // -- Client-side slowloris bound --
    //
    // A recipient that completes the handshake and reads the batch but never
    // returns the report frame must not hang the dialer forever (which would
    // block the sequential outbox drain of every later batch). This handler is
    // that hostile-but-admitted recipient.

    #[derive(Debug, Clone)]
    struct SilentAfterReadHandler;

    impl ProtocolHandler for SilentAfterReadHandler {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let (mut _send, mut recv) = conn.accept_bi().await?;
            // Read the request frame, then deliberately never write the report:
            // exactly the "recipient never returns the report" hang the client
            // read bound defends against.
            let _raw = read_len_delimited(&mut recv, MAX_PHEROMONE_BATCH_BYTES)
                .await
                .map_err(AcceptError::from_err)?;
            conn.closed().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn client_read_bound_drops_a_recipient_that_never_returns_the_report() {
        // No admission gate on the acceptor: this isolates the CLIENT read bound
        // (the recipient handshakes and reads the batch, then goes silent).
        let acceptor = bind_endpoint(40, None).await;
        let router = Router::builder(acceptor)
            .accept(ALPN_PHEROMONE_BATCH, SilentAfterReadHandler)
            .spawn();
        let acceptor_addr = direct_addr(router.endpoint());

        let dialer = bind_endpoint(41, None).await;
        let batch = direct_batch("did:chio:llamaworks");
        // A tight read bound; connect/open/write keep their generous defaults so
        // only the (hung) report read trips.
        let limits = AcceptLimitConfig {
            read_timeout: Duration::from_millis(200),
            ..AcceptLimitConfig::default()
        };
        let outcome = tokio::time::timeout(
            Duration::from_secs(15),
            deliver_batch_over_iroh_with_limits(&dialer, acceptor_addr, &batch, &limits),
        )
        .await
        .expect("the client read bound must fire well before the outer test timeout");
        let error = outcome.expect_err("a silent recipient must fail closed at the read bound");
        assert!(
            matches!(
                error,
                IrohLaneError::AcceptLimit(AcceptLimitError::Timeout {
                    phase: AcceptPhase::ReadFrame,
                    ..
                })
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(error.code(), "accept_timeout");

        router.shutdown().await.ok();
    }

    // -- Sender-mismatch rows are re-queued, never dead-lettered --

    #[tokio::test]
    async fn sender_mismatch_row_is_requeued_not_dead_lettered() {
        // A leased outbox row whose sender_kernel_id != the sender being drained
        // belongs to a DIFFERENT sender's drain. It must be re-queued (mirroring the
        // HTTP tick), never routed through the dead-letter path: draining it
        // repeatedly must NEVER dead-letter another sender's batch.
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let batch = direct_batch("did:chio:other");
        enqueue_batch_for_delivery(&store, "did:chio:other", RECIPIENT, TREATY, &batch, NOW)
            .unwrap();

        // The mismatch is caught before any dial, so resolve_addr / scope_check must
        // never run; the endpoint is likewise never used.
        let endpoint = bind_endpoint(43, None).await;
        let mut now = NOW;
        for _ in 0..4 {
            let report = drain_outbox_over_iroh(
                &store,
                &endpoint,
                |_recipient: &str| -> Option<EndpointAddr> {
                    panic!("a sender-mismatched row must never be resolved or dialed")
                },
                |_recipient: &str, _batch: &PheromoneGossipBatch| {
                    panic!("a sender-mismatched row must never be scope-checked")
                },
                // Draining for a DIFFERENT sender than the queued row.
                "did:chio:llamaworks",
                now,
                10,
            )
            .await
            .unwrap();
            assert_eq!(report.delivered, 0);
            assert_eq!(
                report.dead_lettered, 0,
                "a mismatched-sender row must never be dead-lettered"
            );
            assert_eq!(
                report.retried, 1,
                "the row is re-queued so its correct sender can drain it"
            );
            assert!(
                report.failures[0].contains("sender_mismatch"),
                "unexpected failures: {:?}",
                report.failures
            );
            // Advance past the fixed 60s re-queue backoff so the row leases again.
            now = now.saturating_add(60_001);
        }
    }

    // -- Outbound directory-scope enforcement on the drain --

    #[tokio::test]
    async fn outbound_scope_rejection_skips_dial_and_folds_into_retry() {
        let store = SqlitePheromoneRelayStore::open_in_memory().unwrap();
        let batch = direct_batch("did:chio:llamaworks");
        enqueue_batch_for_delivery(
            &store,
            "did:chio:llamaworks",
            RECIPIENT,
            TREATY,
            &batch,
            NOW,
        )
        .unwrap();

        // A real endpoint satisfies the signature, but the scope check rejects
        // BEFORE any dial, so resolve_addr (and the endpoint) are never used.
        let endpoint = bind_endpoint(42, None).await;

        let report = drain_outbox_over_iroh(
            &store,
            &endpoint,
            |_recipient: &str| -> Option<EndpointAddr> {
                panic!("a scope-rejected batch must never be resolved or dialed")
            },
            |recipient: &str, _batch: &PheromoneGossipBatch| {
                // Mirror a recipient removed from the current directory scope.
                Err(PheromoneRelayError::PeerRemoved(recipient.to_string()))
            },
            "did:chio:llamaworks",
            NOW,
            10,
        )
        .await
        .unwrap();

        assert_eq!(
            report.delivered, 0,
            "a scope-rejected batch is never delivered"
        );
        assert_eq!(report.retried, 1, "it folds into the durable retry path");
        assert_eq!(report.dead_lettered, 0);
        assert_eq!(report.failures.len(), 1);
        assert!(
            report.failures[0].contains("peer_removed"),
            "the mirrored scope code must be recorded, got {:?}",
            report.failures
        );
    }
}
