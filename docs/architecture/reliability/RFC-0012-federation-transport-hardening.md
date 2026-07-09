# RFC-0012: Federation transport hardening: per-peer fairness, incremental reads, refreshable trust

- Status: Draft (proposed, wave-3 reliability program)
- Date: 2026-07-04
- Extends: ADR-0014 (iroh federation transport)
- Depends on: RFC-0001 (hot-path deadlines and watchdogs); shares the durable-verdict-recovery pattern of RFC-0003 (dispatch intent journal)
- Closes findings: F33, F34, F35, F36, F37 (see ./README.md and the readiness review; deep-dive D6)

## Summary

The iroh federation transport (`chio-federation-transport-iroh`) admits a peer with
a cryptographically authenticated `EndpointId` and then serves it with per-lane
resource bounds that are shared across all peers, a trust directory that is frozen
at process start, and an inbox verdict that is not recoverable across a crash. This
RFC adds four hardening changes and ratifies one already-landed invariant: (1) a
per-peer in-flight cap checked before the shared lane semaphore, plus incremental
frame reads and tightened QUIC transport limits, so one admitted peer can no longer
hold every lane permit or force large speculative allocations (F33); (2) a live
directory reloader behind an `ArcSwap` so eviction, key rotation, and expiry take
effect without a restart and an expired-while-running bundle fails closed (F34);
(3) a durable-verdict-recovery path that consults the runtime store's own recorded
receive report on the crash-replay window so both federated peers converge to one
verdict instead of dead-lettering an accepted batch (F35); (4) explicit accounting
of gossip `Lagged` events instead of silently dropping them (F36); and (5) a record
that fan-out swarm admission is already treaty-scoped (F37 is closed in code) plus a
production-wiring gate so it stays that way. The posture stays fail-closed: every
new limit denies or resets, never admits.

## Motivation

The Ubicloud "PostgreSQL and the OOM Killer" lens asks an overloaded component to
fail early, local, and graceful (not process death, not unbounded growth); to know
the blast radius when something dies mid-operation; to keep internal accounting
trustworthy or loudly broken; to keep budgets predictable; and to recover durably.
The transport fails several of these under concrete triggers.

- **F33 (high): per-lane accept caps have no per-peer fairness.** Trigger: one
  admitted-but-hostile or buggy operator opens up to `DEFAULT_MAX_IN_FLIGHT = 1024`
  concurrent connections to the pheromone lane and dribbles. Effect (fairness): all
  1024 permits of the single shared lane semaphore are held for up to the phase
  bounds (30s read + 30s write + 60s linger) per cycle, so every other operator's
  dial sheds `Busy` after the 250ms bounded wait - federation ingress is starved for
  all tenants by one peer. Effect (memory): each admitted handler reads a frame into
  a buffer sized from the peer-declared length, so a single peer holding all permits
  pins live allocation proportional to `1024 x max_batch_bytes`. Who is impacted:
  every operator federating through that relay, and the co-located HTTP relay
  sharing the host. Recovery is worsened by F34 (evicting the abuser needs a
  restart).

- **F34 (high): directory trust state is startup-frozen.** Trigger: an issuer
  publishes a successor bundle tombstoning a compromised operator (`removed: true`),
  rotating a transport key, or the running bundle passes `expires_at_unix_ms`.
  Effect: a long-running relay keeps admitting the old endpoint set indefinitely -
  the tombstoned peer retains full federation access (and can hold accept permits
  per F33), a rotated key's new endpoint is rejected (availability), and an expired
  bundle keeps serving as if valid. The bounded-admission-staleness guarantee the
  directory exists to provide is bounded only by ops restart discipline, silently.

- **F35 (medium): a crash in the commit-to-record window loses the verdict.**
  Trigger: the receiver crashes (or is OOM-killed per F33) after the runtime store's
  `receive_batch` self-commits its deposits but before the relay store's
  `record_inbox` writes the durable verdict. Effect: the sender redelivers, the
  handler cannot find or reproduce the verdict, and the two federated peers durably
  disagree about what was delivered (silent cross-org accounting divergence). The
  reservation-clearing half of this is already crash-safe (see Current behavior);
  the verdict-recovery half is not, so the batch dead-letters after three attempts
  even though the receiver admitted every deposit.

- **F36 (medium): gossip `Lagged` events are silently swallowed.** Trigger (once
  lane c is wired): a fan-out subscriber falls behind under burst load and
  iroh-gossip emits `Event::Lagged` after dropping messages. Effect: the receive
  loop continues as if nothing happened, no metric or log records the drop, and no
  anti-entropy exists to repair the hole - the "gate looks green but measures
  nothing" failure. No production binary can mount the fan-out lane today, so this is
  currently latent, not live.

- **F37 (high, now closed in code): fan-out swarm admission must be treaty-scoped,
  not federation-global.** Trigger: a federation-admitted operator that is not a
  party to treaty T computes T's deterministic `TopicId` and joins T's swarm.
  Historic effect: it would silently receive every frame on T's swarm. This RFC
  records that the per-treaty membership gate has since been implemented (verified
  below) and specifies the invariant plus the production-wiring guard that keeps it
  enforced.

## Current behavior (verified 2026-07-04)

All signatures below were re-read from current source; several finding citations had
drifted and are corrected here (see the manifest).

### Accept limiting is per-lane, keyed by nothing (F33)

`AcceptLimiter` (`crates/trust/chio-federation-transport-iroh/src/lanes/limits.rs:229`)
holds one shared semaphore and no per-peer state:

```rust
// limits.rs:229
pub struct AcceptLimiter {
    config: AcceptLimitConfig,
    semaphore: Arc<Semaphore>,
}

// limits.rs:263
pub async fn admit(&self) -> Result<OwnedSemaphorePermit, AcceptLimitError> { /* ... */ }
```

`admit()` waits at most `DEFAULT_SHED_WAIT = 250ms` (limits.rs:92) for one of
`DEFAULT_MAX_IN_FLIGHT = 1024` (limits.rs:87) permits, then sheds
`AcceptLimitError::Busy { cap }` (limits.rs:187). It cannot see which peer holds the
permits. The pheromone handler acquires the permit for the whole handler at
`pheromone.rs:590` (`let _permit = match self.limiter.admit().await`).

The frame read allocates the full declared length up front, after a cap check:

```rust
// pheromone.rs:307
async fn read_len_delimited<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, IrohLaneError>
where R: AsyncRead + Unpin,
{
    let len = reader.read_u32().await? as usize;
    if len > max_bytes {                      // pheromone.rs:312, fail-closed cap
        return Err(IrohLaneError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];             // pheromone.rs:315, speculative allocation
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
```

Correction to the finding: production wiring does lower the effective cap.
`build_iroh_router` calls `.with_max_batch_bytes(max_batch_bytes)`
(`crates/products/chio-cli/src/cli/chio/dispatch/pheromone/iroh_mount.rs:490-491`)
with the relay profile body limit (256 KiB production, 1 MiB local-dev), clamped by
`with_max_batch_bytes` to `MAX_PHEROMONE_BATCH_BYTES = 8 * 1024 * 1024`
(pheromone.rs:71, :418-419). So the per-handler speculative buffer is ~256 KiB in
production, not 8 MiB; the single-peer worst case is ~256 MiB of live buffers
(1024 x 256 KiB), not ~8 GiB. It is still a fairness and memory-pressure problem: a
declared-length-only attacker forces `vec![0u8; 256 KiB]` per permit before any body
byte arrives, and holds all 1024 permits.

Below the app, only the QUIC idle timeout is set. `build_iroh_router` builds
`QuicTransportConfig::builder().max_idle_timeout(Some(idle_timeout)).build()`
(iroh_mount.rs:453-455) and sets nothing else, so noq (iroh's quinn fork) defaults
apply: `max_concurrent_bidi_streams: 100u32` and `receive_window: VarInt::MAX`
(noq-proto `config/transport.rs:553,558`), with `stream_receive_window` about
1.25 MB (:557). Every lane uses exactly one bidi stream per connection, so 100 is
100x too generous: a peer can buffer roughly `100 x 1.25 MB` per connection in
streams the handler never accepts, across connections iroh's `Router` spawns without
a count cap. The `QuicTransportConfigBuilder` already exposes the knobs to fix this:
`max_concurrent_bidi_streams` (iroh 1.0.1 `endpoint/quic.rs:176`),
`stream_receive_window` (:224), and `receive_window` (:235).

Related blast radius (article "know when a component dies"): in iroh 1.0.1 a closed
connection does not abort in-flight accept tasks, but a panic in any accept task
breaks the `Router` run loop, which cancels all accepts and closes the endpoint. The
serve loop (`relay.rs:299-311`) awaits only `service.serve(listener)` (the HTTP
relay) and merely holds `mount.router`; nothing watches router liveness, so a dead
router freezes iroh metrics silently while HTTP keeps serving.

### The directory gate is built once from an immutable Arc (F34)

```rust
// admission.rs:41
pub struct DirectoryGate { directory: Arc<VerifiedDirectory> }

// admission.rs:48 / :64 / :75
pub fn new(directory: Arc<VerifiedDirectory>) -> Self
pub fn resolve(&self, endpoint: &EndpointId) -> Option<String>   // -> directory.authorize(..)
pub fn decide(&self, endpoint: &EndpointId) -> AfterHandshakeOutcome
```

`VerifiedDirectory::authorize` (identity.rs:412) reads a fixed `by_endpoint` map;
there is no setter and no interior mutability. The bundle is verified exactly once at
`bundle.verify_bundle(&trust)` (iroh_mount.rs:379) against a `now_unix_ms` captured
once at serve start (`let now = unix_now_ms();`, relay.rs:147) and threaded through
`load_iroh_serve_inputs(.., now)` (relay.rs:152) and
`transport_bundle_trust(trusted_issuers, transport_directory_state, now_unix_ms)`
(iroh_mount.rs:272). The verified directory is moved into `DirectoryGate::new`
(iroh_mount.rs:448) and never re-read. The trust input is:

```rust
// identity.rs:266
pub struct TransportDirectoryBundleTrust {
    pub issuers: Vec<TrustedTransportDirectoryIssuer>,   // :268
    pub version_floor: u64,                              // :270
    pub expected_previous_version_sha256: Option<String>,// :274
    pub now_unix_ms: u64,                                // :276
}
```

`verify_bundle` (identity.rs:519) checks, fail-closed and in order: schema pins,
rollback gate (`version` above the floor, `previous_version_sha256` chains onto the
expected predecessor), validity window `now in [issued_at, expires_at)`, body-hash
pin, pinned-issuer signature, per-entry endorsements, and per-treaty party sets. All
of that runs against the frozen `now_unix_ms`.

### The commit-to-record window is reservation-safe but verdict-lossy (F35)

The runtime store commits deposits and its own receive report atomically:

```rust
// crates/trust/chio-pheromone-runtime/src/store.rs:438
fn receive_batch(&self, batch: &PheromoneGossipBatch, /* ... */)
    -> Result<PheromoneReceiveReport, PheromoneRuntimeError>
{
    let batch_sha256 = canonical_sha256(batch)?;            // :445
    // ... verify + admit each frame under savepoints ...
    let report = build_receive_report(config, batch_sha256, frames); // :526
    record_receive_report_tx(&tx, &report)?;               // :527
    tx.commit()?;                                          // :528 (one transaction)
    Ok(report)
}
```

`PheromoneReceiveReport` carries the batch hash (`pub batch_sha256: String`,
`chio-pheromone-runtime/src/lib.rs:192`), but the receive-report table is keyed by
`report_sha256`, not `batch_sha256` (store.rs:791-793), so there is no lookup by
batch today.

The relay store's reservation is now crash-safe (this is newer than the finding).
`chio_pheromone_relay_inbox_reservations` gained a `committed` column, and store open
clears only provably-pre-commit rows:

```rust
// crates/trust/chio-pheromone-relay/src/store.rs:317
conn.execute("DELETE FROM chio_pheromone_relay_inbox_reservations WHERE committed = 0", [])?;
```

The handler drives `lookup_inbox_report` (pheromone.rs:467) -> `reserve_inbox_slot`
(:480) -> `receive_batch` -> `InboxSlotGuard::commit` (which calls
`mark_inbox_reservation_committed`, pheromone.rs:257-262 / relay store.rs:824) ->
`record_inbox` (:525) -> `release` (:267). The relay-store functions are
`reserve_inbox_slot` (store.rs:794, returns `InboxReserveResult { won }`),
`mark_inbox_reservation_committed` (:824), `record_inbox` (:871), `lookup_inbox_report`
(:908), `release_inbox_slot` (:855). The `RelayBatchReceiver` seam
(`crates/trust/chio-pheromone-relay/src/service.rs:195`) exposes only
`receive_batch`.

Residual gap: if the process dies after `commit` (reservation `committed = 1`) but
before `record_inbox`, the reservation survives (correct), so a redelivery loses the
slot and takes the loser path, which polls `lookup_inbox_report` for
`DEDUP_WAIT_ATTEMPTS = 150 x 20ms` (pheromone.rs:85-88) and then fails closed with
`IrohLaneError::DedupInFlight`. The verdict was durably computed by the runtime store
but is never consulted, so the sender never learns the batch was accepted and
dead-letters it after three attempts. The peers converge to two different verdicts.

### Gossip Lagged is dropped; treaty membership is enforced (F36, F37)

`FanoutTopic::next_payload` (fanout.rs:750) drops non-payload events, including
`Lagged`:

```rust
// fanout.rs:750
pub async fn next_payload(&mut self) -> Option<Result<Message, FanoutError>> {
    loop {
        match self.receiver.next().await {
            Some(Ok(Event::Received(message))) => return Some(Ok(message)),
            Some(Ok(_)) => continue,     // fanout.rs:755: NeighborUp/Down AND Lagged, no signal
            Some(Err(error)) => return Some(Err(FanoutError::Gossip(error.to_string()))),
            None => return None,
        }
    }
}
```

`metrics.rs` has a fixed 4-wide outcome set (`LANE_OUTCOME_ACCEPT`, `_REJECT`,
`_BUSY`, `_TIMEOUT`; `NUM_LANE_OUTCOME = 4`, metrics.rs:62-97) and no lagged family;
`FanoutError` (fanout.rs:143) has no `Lagged` variant.

Correction to the finding: F37 is already closed in code. `VerifiedDirectory` carries
an issuer-signed `treaty_id -> {party kernel_ids}` index and exposes
`is_treaty_party(&self, treaty_id, kernel_id) -> bool` (identity.rs:462), wired into
the fan-out lane through the `TreatyMembership` trait (fanout.rs:292, impl for
`VerifiedDirectory` at :297-301). The gate is enforced fail-closed in two places:
`subscribe_treaty_with_timeout` rejects `FanoutError::TreatyMembershipDenied` before
computing the topic or dialing if the local operator is not a party (fanout.rs:653);
`verify_fanout_frame` rejects the same variant if a received frame's origin kernel is
not a party (fanout.rs:418-423). No production binary can mount lane c today: the
serve hook accepts only the pheromone lane (iroh_mount.rs:441-446).

## Design

Five parts, one per finding. New Rust respects fail-closed and the workspace
`unwrap_used`/`expect_used = deny` lints (no `.unwrap()`/`.expect()`; `?` or explicit
typed `match`).

### 1. Per-peer fairness, incremental reads, tighter transport limits (F33)

**(a) Per-peer in-flight cap in `AcceptLimiter`.** Add a per-peer counter consulted
before the shared semaphore, so a single `EndpointId` can hold at most a small
fraction of a lane's permits. Extend the config and the limiter:

```rust
// limits.rs, additive
/// Max concurrently admitted handlers for ONE peer (EndpointId) on ONE lane.
/// A single admitted peer can never hold more than this many of the lane's
/// `max_in_flight` permits, so it cannot starve other operators. `0` is clamped
/// to `1` (a zero per-peer cap would deny every peer, a fail-closed footgun).
pub const DEFAULT_MAX_IN_FLIGHT_PER_PEER: usize = 16;

pub struct AcceptLimitConfig {
    // ... existing fields ...
    pub max_in_flight_per_peer: usize,   // Default: DEFAULT_MAX_IN_FLIGHT_PER_PEER
}

pub struct AcceptLimiter {
    config: AcceptLimitConfig,
    semaphore: Arc<Semaphore>,
    /// Per-peer in-flight counts. Keyed by the authenticated remote EndpointId.
    /// Entries are removed at zero so a churn of peers cannot grow the map.
    per_peer: Arc<Mutex<HashMap<EndpointId, usize>>>,
}
```

Add a typed shed reason and a peer-scoped admit that reserves the per-peer slot
first, then the shared permit, releasing the per-peer slot if the shared wait sheds:

```rust
// limits.rs, AcceptLimitError gains a variant:
#[error("accept handler shed: peer {peer} at its per-peer cap of {cap}")]
PeerBusy { peer: String, cap: usize },

// close_code(): PeerBusy => ACCEPT_BUSY_CLOSE_CODE (shares the busy code)
// code():       PeerBusy => "accept_peer_busy"

impl AcceptLimiter {
    /// Admit one handler for `peer`, enforcing the per-peer cap BEFORE the shared
    /// lane semaphore. Returns a guard that releases the per-peer slot on drop and
    /// carries the shared permit. Fail-closed: over-cap or a saturated lane sheds.
    pub async fn admit_peer(
        &self,
        peer: &EndpointId,
    ) -> Result<PeerAdmitGuard, AcceptLimitError> {
        let cap = self.config.max_in_flight_per_peer.max(1);
        // 1. Reserve the per-peer slot (fast, bounded). Poisoned lock fails closed.
        {
            let mut counts = self
                .per_peer
                .lock()
                .map_err(|_| AcceptLimitError::PeerBusy { peer: peer.fmt_short().to_string(), cap })?;
            let entry = counts.entry(*peer).or_insert(0);
            if *entry >= cap {
                return Err(AcceptLimitError::PeerBusy { peer: peer.fmt_short().to_string(), cap });
            }
            *entry += 1;
        }
        // 2. Acquire the shared permit under the existing bounded shed wait. On a
        //    shed, release the per-peer slot so it is not leaked.
        match self.admit().await {
            Ok(permit) => Ok(PeerAdmitGuard {
                _permit: permit,
                per_peer: Arc::clone(&self.per_peer),
                peer: *peer,
            }),
            Err(busy) => {
                self.release_peer(peer);
                Err(busy)
            }
        }
    }

    fn release_peer(&self, peer: &EndpointId) {
        // Poisoned lock: log and leave the count (fail-closed: the peer stays
        // capped) rather than panicking in a hot path.
        match self.per_peer.lock() {
            Ok(mut counts) => {
                if let Some(entry) = counts.get_mut(peer) {
                    *entry = entry.saturating_sub(1);
                    if *entry == 0 { counts.remove(peer); }
                }
            }
            Err(_poisoned) => tracing::warn!(peer = %peer.fmt_short(),
                "per-peer accept counter lock poisoned; slot held fail-closed"),
        }
    }
}

pub struct PeerAdmitGuard {
    _permit: OwnedSemaphorePermit,
    per_peer: Arc<Mutex<HashMap<EndpointId, usize>>>,
    peer: EndpointId,
}
impl Drop for PeerAdmitGuard {
    fn drop(&mut self) { /* mirror release_peer against self.per_peer/self.peer */ }
}
```

Ordering: reserving the per-peer slot before the shared permit guarantees the
invariant "one peer holds at most `max_in_flight_per_peer` shared permits" without
holding the per-peer lock across the semaphore await (the lock is taken, mutated, and
dropped in step 1). The existing lane-wide `admit()` stays as the shared-permit
primitive. The three direct-lane handlers change their accept entry from
`self.limiter.admit().await` to `self.limiter.admit_peer(&conn.remote_id()).await`
(pheromone.rs:590; bilateral and revocation call sites likewise). `PeerBusy` is
metered through the existing `record_lane_frame(lane, LANE_OUTCOME_BUSY)` path and
carried on the wire with `ACCEPT_BUSY_CLOSE_CODE`, so a shed peer is still
diagnosable and never confused with a protocol reset. Two metering touch points:
the accept-entry shed branch already hardcodes `LANE_OUTCOME_BUSY` for any
`AcceptLimitError` (pheromone.rs:593), and `accept_outcome_for_code`
(metrics.rs:274-280) must gain an `"accept_peer_busy" => LANE_OUTCOME_BUSY` arm so
a `PeerBusy` surfaced through the generic error path is counted busy, not reject.

**(b) Incremental frame read.** Replace the speculative `vec![0u8; len]` with a
buffer grown as bytes actually arrive, capped at `max_bytes`, so a peer that declares
a large length and dribbles holds only the bytes it has actually sent, not the full
declared length:

```rust
// pheromone.rs, replacing read_len_delimited's body after the cap check
let len = reader.read_u32().await? as usize;
if len > max_bytes {
    return Err(IrohLaneError::FrameTooLarge(len));
}
// Grow the buffer in bounded chunks instead of committing `len` bytes up front.
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
```

Live memory is now proportional to bytes received (bounded by `max_bytes` at the
tail of a legitimate transfer), not to the declared length up front. The per-phase
`ReadFrame` timeout (30s) already bounds a dribble; combined with (a) and the
transport limits below, a declared-length-only attacker holds neither a permit for
long nor a large buffer.

**(c) Tighten QUIC transport limits at the wiring.** In `build_iroh_router`
(iroh_mount.rs:453-455), set the two knobs that match actual lane usage (exactly one
bidi stream per connection):

```rust
let transport_config = QuicTransportConfig::builder()
    .max_idle_timeout(Some(idle_timeout))
    .max_concurrent_bidi_streams(1u32.into())        // each lane uses one stream
    .receive_window(bounded_receive_window)          // bound below VarInt::MAX
    .build();
```

`bounded_receive_window` is a `VarInt` derived from `max_batch_bytes` with headroom
(for example `2 * max_batch_bytes`), so per-connection buffering is proportional to
one in-flight batch rather than `100 x stream_receive_window`. This is a wiring-only
change; the crate's `RECOMMENDED_MAX_IDLE_TIMEOUT` guidance (limits.rs:101) is
extended with a `RECOMMENDED_MAX_BIDI_STREAMS = 1` and a helper that computes the
receive window from a batch cap.

**(d) Router-liveness watchdog (blast-radius alarm).** Since a panicked accept task
silently kills the whole router while HTTP keeps serving, spawn a small task in the
serve loop (relay.rs, alongside the `mount`) that periodically checks router
liveness (iroh 1.0.1 exposes both `Router::is_shutdown()`, protocol.rs:416, which
detects the run-loop death directly, and `Endpoint::is_closed()`, endpoint.rs:1708,
reachable via `Router::endpoint()`) and, on transition to dead, emits a
`tracing::error!` and flips a `chio_iroh_router_alive` gauge to 0, so the freeze is
loud, not silent. This mirrors RFC-0001's receipt-writer watchdog
pattern (a dedicated liveness task feeding a gauge the operator can alert on).

### 2. Refreshable trust directory (F34)

Make the gate's directory swappable and add a periodic reloader.

**Gate holds an `ArcSwap`.** Change `DirectoryGate` so `authorize`/`decide` read the
current directory through a load, not a fixed `Arc`:

```rust
// admission.rs
use arc_swap::ArcSwap;

pub struct DirectoryGate {
    directory: Arc<ArcSwap<VerifiedDirectory>>,
}

impl DirectoryGate {
    pub fn new(directory: Arc<VerifiedDirectory>) -> Self {
        Self { directory: Arc::new(ArcSwap::from(directory)) }
    }
    /// Atomically publish a freshly re-verified directory. Only the reloader calls
    /// this, and only with a `VerifiedDirectory` that passed `verify_bundle`, so the
    /// gate can never resolve against an unverified or rolled-back bundle.
    pub fn swap(&self, next: Arc<VerifiedDirectory>) { self.directory.store(next); }

    pub fn resolve(&self, endpoint: &EndpointId) -> Option<String> {
        self.directory.load().authorize(endpoint).map(str::to_owned)
    }
    pub fn decide(&self, endpoint: &EndpointId) -> AfterHandshakeOutcome {
        // unchanged body, reading self.directory.load()
    }
}
```

`ArcSwap` gives lock-free reads on the hot admission path (every handshake and every
`resolve`) and a single-writer publish. `DirectoryGate: Clone` still shares one
`Arc<ArcSwap<..>>`, so the clone installed on the endpoint via `.hooks(gate)`
(iroh_mount.rs:465) and the clones held by handlers all observe a swap immediately.
Two API details: the existing `directory()` accessor (admission.rs:54, returns
`&Arc<VerifiedDirectory>`) cannot borrow through an `ArcSwap`; it changes to return
`Arc<VerifiedDirectory>` via `load_full()` (no production callers today, only
tests). And `arc-swap` 1.9 is already in the workspace lockfile as a transitive
dependency, so this adds a direct dependency, not a new resolution.

**Reloader task.** Add a bounded reloader spawned in the serve loop (a sibling of the
router mount), holding the bundle path, the trusted-issuers/state paths, and a clone
of the gate:

```rust
// iroh_mount.rs (new), invoked from the serve loop
pub struct DirectoryReloadConfig {
    pub interval: Duration,          // Default: 60s
    pub bundle_path: PathBuf,
    pub trusted_issuers_path: PathBuf,
    pub state_path: Option<PathBuf>,
}

async fn run_directory_reloader(
    gate: DirectoryGate,
    config: DirectoryReloadConfig,
    now_fn: Arc<dyn Fn() -> u64 + Send + Sync>,
    alive: Arc<AtomicBool>,
) {
    let mut ticker = tokio::time::interval(config.interval);
    loop {
        ticker.tick().await;
        let now = now_fn();
        match reload_verified_directory(&config, now, gate.current_version()) {
            Ok(ReloadOutcome::Updated(next)) => {
                gate.swap(Arc::new(next));
                crate::metrics::record_directory_reload(RELOAD_UPDATED);
            }
            Ok(ReloadOutcome::Unchanged) => {
                crate::metrics::record_directory_reload(RELOAD_UNCHANGED);
            }
            Ok(ReloadOutcome::ExpiredWhileRunning) => {
                // Fail closed: the running bundle passed expires_at and no valid
                // successor exists. Stop admitting new connections and alarm.
                gate.swap(Arc::new(VerifiedDirectory::empty_deny_all()));
                alive.store(false, Ordering::SeqCst);
                crate::metrics::record_directory_reload(RELOAD_EXPIRED_FAILCLOSED);
                tracing::error!(target: crate::observability::TARGET_ADMISSION,
                    "transport directory expired with no valid successor; admitting nothing");
            }
            Err(error) => {
                // A transient read/verify error keeps the last-good directory
                // (availability) but is counted and logged, never silently ignored.
                crate::metrics::record_directory_reload(RELOAD_ERROR);
                tracing::warn!(target: crate::observability::TARGET_ADMISSION,
                    error = %error, "transport directory reload failed; keeping last-good");
            }
        }
    }
}
```

`reload_verified_directory` checks expiry BEFORE the unchanged fast path: if the
current (last-good) directory's `expires_at_unix_ms <= now`, it must not short-circuit
to `Unchanged`, because an unchanged-but-expired directory has to fail closed. In that
case it returns `ExpiredWhileRunning` unless the re-read yields a strictly-newer
in-window successor to swap in. Only when the current directory is still in-window does
it detect `Unchanged` by comparing the re-read bundle's version and body hash to the
current directory BEFORE any verification (the rollback gate is
`version <= version_floor`, so verifying the same-version bundle against a floor of the
current version would spuriously reject it), and only for a strictly newer bundle builds
`TransportDirectoryBundleTrust` with a fresh `now_unix_ms`, `version_floor` set to
the current version, and `expected_previous_version_sha256` set to the current
bundle's hash, then calls `verify_bundle`. Monotonicity is preserved fail-closed: a
reload whose `version` is not strictly above `gate.current_version()` is rejected as
a rollback by the existing `verify_bundle` machinery (identity.rs:519, rollback gate
inside `verify_bundle_inner`), and on an accepted newer bundle the reloader advances
the persisted state floor to the new version before the swap, so a later downgrade
cannot be re-accepted. `ExpiredWhileRunning` is detected
when the last-good bundle's `expires_at_unix_ms <= now` and no re-read produces a
valid in-window successor; the fail-closed response replaces the gate with a
deny-all directory (`VerifiedDirectory::empty_deny_all`, a new constructor building
empty indices) and lowers the router-alive gauge, so an operator alerts rather than
silently serving an expired trust set. `current_version()` is a new accessor on the
gate returning `self.directory.load().version()`.

This is deliberately a poll (default 60s), not a filesystem watch: polling is simpler,
survives atomic bundle-file replacement, and the 60s staleness bound is far tighter
than the "until restart" it replaces. A SIGHUP-triggered immediate reload is a
possible additive refinement, not required.

### 3. Durable verdict recovery on crash replay (F35)

Close the seam by recovering the durably-computed verdict instead of re-running the
receiver. The runtime store already persisted the receive report (carrying
`batch_sha256`) atomically with the deposit commit (store.rs:527-528), so the true
verdict survives the crash; it is only unreachable because there is no lookup by
batch and no seam to surface it.

**Runtime store: add a lookup by batch hash.** Add a `batch_sha256` column and index
to `chio_pheromone_receive_reports` (populated from the report on insert) and a
query:

```rust
// chio-pheromone-runtime/src/store.rs (new)
fn lookup_receive_report_by_batch(
    &self,
    batch_sha256: &str,
) -> Result<Option<PheromoneReceiveReport>, PheromoneRuntimeError> {
    let conn = self.conn.lock()?;
    let json: Option<String> = conn
        .query_row(
            "SELECT json FROM chio_pheromone_receive_reports WHERE batch_sha256 = ?1",
            params![batch_sha256],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    match json {
        Some(text) => Ok(Some(serde_json::from_str(&text)?)),
        None => Ok(None),
    }
}
```

**Seam: extend `RelayBatchReceiver` with a default-`None` recovery method** so
existing receivers are unaffected and only the runtime-backed receiver overrides it:

```rust
// chio-pheromone-relay/src/service.rs, RelayBatchReceiver gains:
/// Return a previously durably-recorded receive report for `batch_sha256`, if the
/// runtime store committed one for that batch. Used to recover the verdict after a
/// crash in the commit-to-record window WITHOUT re-running `receive_batch` (which
/// would re-enter the replay window and reject already-accepted deposits).
/// Default: `Ok(None)` (a receiver with no durable report cannot recover; the
/// handler then keeps the current fail-closed loser path).
async fn recorded_report_for_batch(
    &self,
    _batch_sha256: &str,
) -> Result<Option<PheromoneReceiveReport>, PheromoneRelayError> {
    Ok(None)
}
```

**Handler: recover on the loser / committed-residual path.** In the pheromone
handler's loser branch (pheromone.rs, after the bounded dedup poll fails, ~:548-561),
before returning `DedupInFlight`, attempt recovery. The batch hash is
`sha256_hex(&batch_bytes)` over the `batch_bytes = canonical_json_bytes(&batch)` the
handler already computed for the nonce (pheromone.rs:462); this equals the runtime
store's key because `canonical_sha256` is exactly `sha256_hex` over
`canonical_json_bytes` (chio-pheromone-runtime/src/lib.rs:743-747). That identity is
load-bearing: if either side changed its canonicalization, the lookup would miss.

```rust
// after the DEDUP_WAIT poll finds no recorded inbox verdict:
let batch_sha256 = sha256_hex(&batch_bytes);
if let Some(recovered) = self.receiver.recorded_report_for_batch(&batch_sha256).await? {
    // The runtime store durably committed this batch before the crash. Adopt its
    // verdict as the inbox record so both peers converge, then return it. record_inbox
    // is idempotent (ON CONFLICT DO NOTHING), so a concurrent winner recording first
    // is harmless.
    let _ = self
        .store
        .record_inbox(&authenticated_sender, &nonce, &batch, &recovered)?;
    crate::metrics::record_lane_frame(
        crate::metrics::LANE_PHEROMONE,
        crate::metrics::LANE_OUTCOME_ACCEPT,
    );
    recovered
} else {
    // No durable runtime verdict: keep the existing fail-closed behavior.
    return Err(IrohLaneError::DedupInFlight(format!(
        "sender {authenticated_sender} nonce {nonce} still receiving"
    )));
}
```

Convergence argument: `receive_batch`'s report and its deposit admission commit in
one runtime transaction (store.rs:527-528), so `recorded_report_for_batch` returns
Some exactly when the deposits were durably admitted. Recording that report into the
relay inbox reproduces the winner's verdict byte-for-byte, so the sender reads
`accepted` and does not dead-letter, and both peers hold the one true verdict. This is
the RFC-0003 durable-intent-recovery pattern applied to the transport inbox: the
runtime receive report is the journal; the relay inbox is the recovery target. The
existing `committed = 1` reservation and clear-at-open logic (store.rs:317) are
unchanged; recovery is purely additive to the loser path.

Two implementation constraints, both already satisfied by the seam shape. First, the
transport crate deliberately never names `PheromoneReceiveReport` (module note,
pheromone.rs:29-35: `chio-pheromone-runtime` is not a dependency of the adapter);
the recovered report flows through by inference from the trait method's return type
into `record_inbox`, exactly as `receive_batch`'s return does today, so no new
dependency edge is created. Second, `RelayBatchReceiver` is consumed as
`Arc<dyn RelayBatchReceiver>` (the handler field, pheromone.rs:348) and is an
`#[async_trait]` trait (service.rs:194), so the default-`Ok(None)` async method is
object-safe and existing implementors compile unchanged. Finally, after recovery
records the verdict, the handler releases the residual `committed = 1` reservation
row via `release_inbox_slot` (relay store.rs:855), mirroring the winner's
release-after-record, so committed residuals do not accumulate across crashes (the
durable inbox row now short-circuits any later redelivery at `lookup_inbox_report`
before the reservation is consulted).

### 4. Surface gossip Lagged (F36)

Give `Lagged` a metric, a log, and a distinct caller surface so a future lane-c
wiring can react (re-sync or at least alarm). Note the shape of the upstream event:
in iroh-gossip 0.101.0 `Event::Lagged` is a unit variant carrying no drop count
(api.rs:336-345), so the error variant is fieldless; the number of dropped messages
is unknowable at this layer and the variant must not pretend otherwise:

```rust
// metrics.rs: add a fifth outcome and widen the fixed table.
pub const LANE_OUTCOME_LAGGED: &str = "lagged";
const NUM_LANE_OUTCOME: usize = 5;   // was 4

// fanout.rs: FanoutError gains a variant (fieldless: iroh-gossip reports no count).
#[error("gossip receiver lagged: an unknown number of messages were dropped")]
Lagged,   // code(): "lagged"

// fanout.rs next_payload: match Lagged explicitly instead of the catch-all.
pub async fn next_payload(&mut self) -> Option<Result<Message, FanoutError>> {
    loop {
        match self.receiver.next().await {
            Some(Ok(Event::Received(message))) => return Some(Ok(message)),
            Some(Ok(Event::Lagged)) => {
                crate::metrics::record_lane_frame(
                    crate::metrics::LANE_FANOUT,
                    crate::metrics::LANE_OUTCOME_LAGGED,
                );
                tracing::warn!(target: crate::observability::TARGET_VERIFY,
                    treaty = %self.treaty_id, "fan-out gossip receiver lagged; messages dropped");
                return Some(Err(FanoutError::Lagged));
            }
            Some(Ok(_)) => continue,   // NeighborUp / NeighborDown only
            Some(Err(error)) => return Some(Err(FanoutError::Gossip(error.to_string()))),
            None => return None,
        }
    }
}
```

Returning a distinct `Err` (rather than swallowing) lets a receive loop count the
hole and, once anti-entropy exists for pheromone fan-out, trigger a re-sync; until
then it is at minimum a loud, metered signal. Lane-c production wiring is gated (part
5) on having either an anti-entropy path or an explicit accepted-loss decision for
this event.

### 5. Ratify treaty-scoped fan-out admission and gate its wiring (F37)

F37 is closed in code: the per-treaty membership gate is enforced fail-closed at
JOIN (fanout.rs:653) and RECEIVE (fanout.rs:418) against the issuer-signed
`VerifiedDirectory` party set (identity.rs:462). This RFC records the invariant and
adds a wiring guard so a future lane-c mount cannot regress it:

- Any production lane-c mount MUST pass the `VerifiedDirectory` (not a
  `StaticTreatyMembership` and never the raw topic id) as the `TreatyMembership`
  oracle, and MUST derive origin keys from the same trusted admission set. The
  serve-hook lane allow-list (iroh_mount.rs:441-446) stays pheromone-only until this
  is wired; enabling lane c there is a fail-closed error today and remains so until
  the membership oracle and the F36 Lagged handling are both present.
- The gate rests on routing (topic-per-treaty) plus enforced membership, not on
  encryption. An optional defense-in-depth follow-up (not required by this RFC) is a
  per-treaty group key so fan-out frames are ciphertext to a non-party even if swarm
  admission were ever loosened; it is tracked as future work, not scope here.

### Error taxonomy (typed, fail-closed)

- `AcceptLimitError::PeerBusy { peer, cap }` (limits.rs): per-peer cap saturated;
  `close_code() == ACCEPT_BUSY_CLOSE_CODE`, `code() == "accept_peer_busy"`. Resets
  the connection; never admits.
- `FanoutError::Lagged` (fanout.rs, fieldless: iroh-gossip 0.101 reports no drop
  count): metered, logged, surfaced to the caller; a dropped-message signal, never
  an accepted frame.
- Directory reload outcomes are an internal `ReloadOutcome`/error enum; the
  fail-closed terminal state is `ExpiredWhileRunning -> deny-all + alarm`.
- No new error crosses the trust boundary as an Allow. Every added path denies,
  sheds, or recovers a verdict that was already durably true.

### Crates, LOC, CI-tier placement

All changes are edits to existing crates; no new crate.

| Area | Files | Rough LOC |
| --- | --- | --- |
| Per-peer limiter + guard | `chio-federation-transport-iroh/src/lanes/limits.rs`, three lane accept sites | ~150 |
| Incremental read | `.../lanes/pheromone.rs` (and revocation/bilateral readers) | ~50 |
| QUIC transport limits + router watchdog | `chio-cli/.../pheromone/iroh_mount.rs`, `.../pheromone/relay.rs` | ~90 |
| Directory ArcSwap + reloader | `.../src/admission.rs`, `.../src/identity.rs` (empty_deny_all, version accessor), `iroh_mount.rs`, `relay.rs` | ~200 |
| Verdict recovery | `chio-pheromone-runtime/src/store.rs` (column + query), `chio-pheromone-relay/src/service.rs` (trait method), `.../lanes/pheromone.rs` (loser path) | ~120 |
| Lagged surfacing | `.../src/metrics.rs`, `.../lanes/fanout.rs` | ~40 |

CI tiers: unit and property tests on the PR gate; loom on the per-peer counter and
the `ArcSwap` publish/read interaction nightly; soak and chaos (per-peer starvation,
crash-in-window, reload-under-load) weekly under the load-chaos program. Honest
runtimes: PR-gate additions are sub-second; the loom nightly for the per-peer counter
is a few minutes; the weekly soak that drives 1024 connections from one peer plus a
crash-replay injection is tens of minutes.

## Wire, schema, and receipt impact

- **Signed payloads / receipt kinds: none.** No new signed bundle, receipt kind, or
  canonical-JSON (RFC 8785) shape. The directory bundle format is unchanged; the
  reloader re-verifies the existing `TransportDirectoryBundleDocument` with a fresh
  `now_unix_ms`. Recovered inbox verdicts reuse the existing `PheromoneReceiveReport`
  bytes verbatim.
- **Storage schema: additive, backward-compatible.** A `batch_sha256 TEXT` column
  plus an index on `chio_pheromone_receive_reports` (runtime store), added idempotently
  with `ensure_*_column` migrators mirroring the existing
  `ensure_inbox_reservation_committed_column` pattern (store.rs:291). No existing row
  is rewritten destructively; a pre-migration report row simply has a NULL batch hash
  and is not recoverable-by-batch (acceptable: only reports written after the migration
  need recovery).
- **Config: additive.** `max_in_flight_per_peer` on `AcceptLimitConfig` (default 16),
  `DirectoryReloadConfig` (default 60s interval), and the QUIC bidi/receive-window
  knobs are all defaulted; a deployment that sets none keeps today's numbers except
  the two deliberate behavior changes below.
- **Metrics: additive.** New `LANE_OUTCOME_LAGGED`, a `chio_iroh_router_alive` gauge,
  and directory-reload counters (`updated`/`unchanged`/`expired_failclosed`/`error`).
  Existing series are unchanged.

## Migration and compatibility

- **Per-peer cap is default-on but generous.** With `max_in_flight_per_peer = 16`
  against a 1024 lane cap, a single peer can hold at most 16 permits; legitimate
  single-peer fan-in (a burst of concurrent deliveries from one operator) above 16
  concurrent handlers now sheds `PeerBusy` and retries, which is the intended
  fairness behavior. Operators who run few, high-volume peers can raise it.
- **QUIC `max_concurrent_bidi_streams = 1` is a deliberate change.** Each lane uses
  one stream, so this is exact, but any future multi-stream lane must raise it. It is
  wiring-only and does not affect the crate's default `AcceptLimitConfig`.
- **Directory reload is default-on in the serve binary, off in the library.** The
  library `DirectoryGate` still works with a one-shot `new`; only the serve loop
  spawns a reloader. A deployment that does not run the reloader behaves exactly as
  today (frozen), so the reloader can roll out independently.
- **Verdict recovery is purely additive** and only fires on the crash-replay loser
  path; steady-state delivery is unchanged.
- **Staged rollout:** (1) incremental read + QUIC limits + `batch_sha256` migration +
  verdict recovery + Lagged surfacing (all safe, additive); (2) per-peer cap
  (default-on, tune per deployment); (3) directory reloader + router watchdog (flip on
  after soak); (4) lane-c wiring only after F36 and the F37 membership-oracle guard
  are both satisfied.

## Test and verification plan

Unit and property (PR gate):
- `per_peer_cap_bounds_single_peer_below_lane_cap`: one peer opens `cap + N` handlers,
  assert at most `cap` are admitted concurrently and the rest shed `PeerBusy`, while a
  second peer is still admitted (proves fairness, not just a global cap).
- `incremental_read_holds_only_delivered_bytes`: a reader that declares `max_bytes`
  and dribbles is bounded by the `ReadFrame` timeout and never allocates the full
  declared length up front (assert buffer growth tracks delivered bytes).
- `directory_reload_swaps_in_successor_and_evicts_tombstoned_peer`: build gate at
  version N admitting E; reload version N+1 tombstoning E; assert `decide(E)` flips to
  403 without reconstructing the gate.
- `directory_reload_rejects_rollback_and_keeps_last_good`: a reload with `version <=
  current` is rejected and the last-good directory stays live.
- `directory_expired_while_running_fails_closed`: advance `now` past `expires_at` with
  no successor; assert the gate admits nothing and the alive gauge reads 0.
- `verdict_recovery_converges_after_commit_before_record_crash`: commit `receive_batch`,
  simulate a crash before `record_inbox`, redeliver, assert the handler recovers the
  runtime report by `batch_sha256`, records it, and returns `accepted` (no dead-letter,
  both peers agree). This is the named acceptance test the F35 fix stands or falls on.
- `lagged_event_is_metered_and_surfaced`: inject `Event::Lagged`, assert
  `LANE_OUTCOME_LAGGED` advances and `next_payload` returns `FanoutError::Lagged`.
- `fanout_membership_gate_rejects_non_party_at_join_and_receive`: pins the already-
  landed F37 invariant against regression using `VerifiedDirectory` as the oracle.

loom (nightly): `per_peer_counter_no_lost_decrement` over concurrent `admit_peer` and
`PeerAdmitGuard` drop, and `directory_arcswap_no_torn_read` over a swap concurrent with
`decide`, ensuring the gate never reads a torn or stale-forever directory and the
per-peer count never underflows or leaks.

Soak and chaos (weekly, load-chaos program):
- `soak_single_peer_cannot_starve_lane` (one peer drives 1024 connections; assert
  other tenants keep completing and steady-state ingress holds).
- `chaos_crash_in_commit_record_window_converges` (kill the receiver mid-window under
  load; assert every accepted batch is recovered on replay, zero dead-letters for
  admitted batches).
- `chaos_directory_reload_under_ingress` (rotate + tombstone while 1024 peers dial;
  assert eviction takes effect within one reload interval and no admitted stream is
  torn spuriously).
- `chaos_router_panic_is_loud` (force an accept-task panic; assert the router-alive
  gauge drops and an error is logged rather than metrics silently freezing).

Where a recovered verdict's content is asserted, the test ties into the RFC-0003
journal-recovery acceptance suite so the crash-replay path and the durable-report path
are proven to produce identical verdicts. A formal-methods follow-up may model the
reservation/commit/record/recover state machine (reserved -> committed -> recorded ->
recovered) as a small TLA+ spec proving "every committed batch converges to exactly
one verdict"; noted, not required for this RFC.

## Acceptance criteria

- No single admitted `EndpointId` can hold more than `max_in_flight_per_peer` of a
  lane's permits; a second peer is always admissible while the first is at its cap.
- A frame read never allocates more than the bytes actually delivered (bounded by the
  effective `max_batch_bytes`), and an over-cap declared length is still rejected
  before any allocation.
- QUIC per-connection buffering is bounded (`max_concurrent_bidi_streams = 1`,
  `receive_window` below `VarInt::MAX`), so a peer cannot buffer ~100 streams' worth
  of un-accepted data per connection.
- Directory eviction, key rotation, and expiry take effect within one reload interval
  (default 60s) with no restart; an expired-while-running bundle with no valid
  successor makes the gate admit nothing and raises an alarm.
- A crash between `receive_batch` commit and `record_inbox` converges both peers to
  the one true verdict on replay (the accepted batch is not dead-lettered).
- A gossip `Lagged` event increments `LANE_OUTCOME_LAGGED`, logs a warning, and is
  returned to the caller, never silently dropped.
- The fan-out membership gate remains enforced at JOIN and RECEIVE against the
  issuer-signed party set, and lane-c production wiring stays disabled until its
  membership oracle and Lagged handling are in place.
- With defaults unchanged, existing single-tenant behavior is preserved except the
  two deliberate changes (per-peer cap default-on, QUIC bidi limit).

## Risks and alternatives

- **Per-peer cap set too low starves a legitimate high-fan-in operator.** Mitigation:
  default 16 is well above typical concurrent-delivery counts, the value is tunable,
  and `PeerBusy` is a retryable shed (the durable outbox re-drains), not a drop.
  Rejected alternative: a global fair-queue scheduler across peers, which is far more
  code for a marginal gain over a simple per-peer cap.
- **`EndpointId` is the fairness key, not the operator.** One operator running many
  endpoints gets `max_in_flight_per_peer` per endpoint. Accepted: every endpoint is
  still directory-bound and admission-gated, and keying on the resolved `kernel_id`
  instead is a straightforward change if endpoint sprawl becomes an abuse vector.
- **Reload interval vs. staleness.** A 60s poll leaves up to 60s of admission
  staleness after an eviction; shorter intervals cost a re-verify (a signature check
  plus a hash) each tick. Accepted: 60s is far tighter than "until restart," and the
  interval is configurable; a SIGHUP fast-path is available if needed.
- **Reload flapping / partial writes.** A bundle file replaced non-atomically could be
  read mid-write. Mitigation: verification is fail-closed, so a malformed read is
  counted as `RELOAD_ERROR` and the last-good directory is kept; operators are expected
  to replace the bundle atomically (write-temp-then-rename).
- **Verdict recovery reads a report the runtime store never committed.** Impossible by
  construction: the report and the deposit admission commit in one transaction, so
  `recorded_report_for_batch` returns Some only when the deposits were durably
  admitted. If the runtime and relay stores are ever separated onto different
  databases, this argument must be re-checked (they share one process and store today).
- **Latency/throughput.** The per-peer check is one short mutex section per accept
  (negligible); the incremental read adds a bounded loop with no steady-state cost; the
  `ArcSwap` read is lock-free and faster than the current `Arc` clone-through; the
  reloader is one re-verify per minute. Net effect on the hot path is neutral to
  slightly positive.

## Rollout and sequencing

- **RFC-0001 should land first** for the watchdog/liveness-task and bounded-task
  discipline the router-liveness watchdog and the directory reloader reuse (a dedicated
  tokio task feeding a gauge, joined on shutdown). The transport changes here do not
  depend on RFC-0001's mediation-path budgets, only its watchdog pattern, so they can
  proceed in parallel if needed.
- **F35 verdict recovery shares RFC-0003's durable-journal-recovery pattern** (runtime
  report as journal, relay inbox as recovery target); it does not require RFC-0003 to
  land but should cite it and reuse its acceptance harness for the convergence proof.
- Within this RFC: stage 1 (incremental read, QUIC limits, `batch_sha256` migration,
  verdict recovery, Lagged surfacing) is safe and additive and lands first; stage 2
  (per-peer cap, default-on) follows once soaked; stage 3 (directory reloader plus
  router watchdog) flips on after the reload-under-load chaos test is green; stage 4
  (any lane-c production wiring) is gated on stages for F36 and the F37 membership-oracle
  guard being complete.
- This RFC sits in the wave-3 reliability program next to RFC-0001; the load-chaos
  program supplies the single-peer-flood, crash-in-window, and reload-under-load fault
  injectors the weekly acceptance tests run in.
