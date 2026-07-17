//! Mpsc-backed receipt signing task.
//!
//! ## Why this exists
//!
//! A dedicated signing task decouples receipt signing from the evaluate critical
//! path, preventing the synchronous `build_and_sign_receipt` step from pinning a
//! worker thread per concurrent evaluate call.
//!
//! A single signing task owns a clone of the kernel signing keypair and
//! pulls signing requests from a bounded [`tokio::sync::mpsc`] channel.
//! Producers `.await` on a oneshot reply channel rather than on a mutex.
//! Admission is non-blocking: when the queue is full (by count or by the
//! aggregate byte budget), the producer signs INLINE through the same WYSIWYS
//! primitive rather than parking while holding the preimage, so the memory held
//! by would-be waiters stays bounded by the configured queue budget. The async
//! task is the off-critical-path optimisation; the inline
//! fallback is the always-correct floor.
//!
//! The synchronous `build_and_sign_receipt` helper in `kernel/responses.rs`
//! remains the inline path for internal call sites (deny-receipt builders,
//! child-receipt builders, federation cosign hook). The mpsc path signs the
//! same canonical receipt body bytes through the shared canonical-byte signing
//! API, so receipt bytes are byte-identical across the two paths. Persistence
//! stays inline; only the signature step crosses the channel.
//!
//! ## Crash recovery contract
//!
//! Integration tests in `tests/signer_crash.rs` cover crash recovery. This
//! module only guarantees:
//!
//! - The signing task runs until the last [`SigningTaskHandle`] sender
//!   is dropped, at which point the channel closes and the task returns.
//! - [`SigningTaskHandle::shutdown`] drains every in-flight request that
//!   reached the channel before returning, so callers that successfully
//!   `.send().await`-ed get a reply (or an error) before shutdown
//!   completes.
//! - Producers whose oneshot reply receiver is dropped (e.g. the caller
//!   timed out waiting) do not poison the task; the signed receipt is
//!   discarded.
//!
//! ## Channel capacity
//!
//! Default capacity is [`DEFAULT_SIGNING_CHANNEL_CAPACITY`] (256). This is a
//! fail-closed default: a bounded channel where a full queue routes the
//! producer to the inline fallback rather than an unbounded queue that lets
//! memory grow without limit. Tests can pick a smaller capacity to exercise
//! backpressure deterministically via [`SigningTaskHandle::with_capacity`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use chio_core::crypto::{Ed25519Backend, SigningBackend};
use chio_log_redact::redacted;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::{ChioReceipt, ChioReceiptBody, KernelError, Keypair, DEFAULT_MAX_STREAM_TOTAL_BYTES};

/// Default bounded capacity for the signing-task mpsc channel.
///
/// 256 in-flight signing requests is generous for a single-process kernel
/// (each request is a `ChioReceiptBody` plus a `oneshot::Sender`, well under
/// 1 KiB amortised) and small enough to surface backpressure during a
/// signing-task stall before producer memory grows unbounded. Operators
/// can override via [`SigningTaskHandle::with_capacity`].
pub const DEFAULT_SIGNING_CHANNEL_CAPACITY: usize = 256;

/// Default *per-request* byte budget on a single queued canonical-content
/// preimage.
///
/// This is an OPTIONAL safety valve that bounds the bytes any **single** request
/// may enqueue. `0` means *no per-request cap* (see
/// [`SigningTaskHandle::with_capacity_and_max_content_bytes`]); a non-zero value
/// fail-closed refuses ([`KernelError::ReceiptSigningFailed`]) a preimage over
/// the cap rather than silently truncating it, since truncating would break the
/// WYSIWYS recompute.
///
/// The default is aligned to the kernel's configured stream/output max
/// ([`crate::DEFAULT_MAX_STREAM_TOTAL_BYTES`], 256 MiB) for the convenience
/// constructors. The async signing task is the documented off-critical-path
/// signer, so a fixed 1 MiB hard-reject would refuse legitimate large async
/// receipts. The budget is always BOUNDED.
///
/// Note the kernel itself wires the per-request cap to **0 (unlimited)** so the
/// async path admits exactly what the inline signer admits: the inline path
/// applies no preimage cap, and `max_stream_total_bytes` limits *raw stream
/// bytes*, which is a different unit from the *preimage bytes* a queued request
/// holds (a stream receipt's preimage is the concatenation of 64-char per-chunk
/// digests, not the raw payload). Comparing a preimage length against
/// `max_stream_total_bytes` would falsely reject stream receipts the inline
/// signer accepts. Queue memory is instead bounded by the AGGREGATE byte budget
/// ([`DEFAULT_MAX_SIGNING_QUEUED_BYTES`]) below.
///
/// Referenced inside the crate only via [`SigningTaskHandle::with_capacity`]
/// (itself reached only from the `#[path]`-included signing-task test modules),
/// so the lib build sees it as dead; the `#[allow(dead_code)]` keeps the symbol
/// available to those test binaries without a clippy warning.
#[allow(dead_code)]
pub const DEFAULT_MAX_SIGNING_CONTENT_BYTES: usize =
    clamp_u64_to_usize(DEFAULT_MAX_STREAM_TOTAL_BYTES);

/// Sentinel: a per-request `max_content_bytes` of `0` means *no per-request
/// cap* (unlimited), matching the inline signer which applies no preimage cap.
/// Used so the kernel can wire `KernelConfig::max_stream_total_bytes == 0`
/// (operator "unlimited stream") straight through to "no async per-request cap"
/// without coercing 0 into a 1-byte cap that rejects almost
/// every receipt.
const PER_REQUEST_BUDGET_UNLIMITED: usize = 0;

/// Default AGGREGATE byte budget across ALL in-flight queued preimages.
///
/// A bounded channel of [`DEFAULT_SIGNING_CHANNEL_CAPACITY`] (256) requests
/// bounds the queue by *count* but not by *bytes*: with a 256 MiB per-request
/// budget that is up to ~64 GiB of preimage bytes retained before count-based
/// backpressure even engages. This aggregate budget
/// is the real memory bound: producers acquire `preimage_len` permits from a
/// shared [`Semaphore`] before enqueueing and release them once the signing task
/// finishes the request, so the *sum* of queued preimage bytes is held under the
/// budget. When the aggregate is exhausted producers `.await` (backpressure),
/// never reject, so a receipt the inline signer would accept is never refused by
/// the async path.
///
/// Defaulted to the configured stream/output max (256 MiB). Always BOUNDED.
pub(crate) const DEFAULT_MAX_SIGNING_QUEUED_BYTES: usize =
    clamp_u64_to_usize(DEFAULT_MAX_STREAM_TOTAL_BYTES);

/// Clamp an aggregate-budget byte count into the permit range a
/// [`Semaphore`] can vend in a single `acquire_many` call.
///
/// `Semaphore::acquire_many*` takes a `u32`, so the aggregate budget (and any
/// single acquire derived from it) must fit in `u32`. An operator-configured
/// budget larger than `u32::MAX` is clamped down to a still-bounded value; the
/// aggregate stays a memory bound, never unbounded. A zero budget collapses to 1
/// so the semaphore can always vend at least one permit. A request whose
/// preimage exceeds the budget is NOT queued at all (it inline-signs), so only
/// preimages that fit the budget ever acquire permits.
const fn clamp_aggregate_permits(budget: usize) -> u32 {
    let ceiling = u32::MAX as usize;
    let clamped = if budget > ceiling { ceiling } else { budget };
    if clamped == 0 {
        1
    } else {
        clamped as u32
    }
}

/// Saturating `u64 -> usize` conversion, usable in a `const` context.
///
/// On a 32-bit target a 256 MiB `u64` budget still fits in `usize`, but the
/// generic conversion saturates at `usize::MAX` so an operator-configured budget
/// larger than the address space clamps to a representable, still-bounded value.
#[allow(dead_code)]
const fn clamp_u64_to_usize(value: u64) -> usize {
    if value > usize::MAX as u64 {
        usize::MAX
    } else {
        value as usize
    }
}
#[cfg_attr(test, allow(unused_imports))]
pub use chio_metrics_spec::CHIO_SIGNING_QUEUE_BLOCK_TOTAL as METRIC_CHIO_SIGNING_QUEUE_BLOCK_TOTAL;

/// +1 on chio_signing_queue_block_total{reason}. `reason` is one of
/// "byte_budget", "channel_full", "oversized".
fn record_signing_queue_block(reason: &str) {
    chio_metrics_spec::runtime::families::SIGNING_QUEUE_BLOCK.incr(&[reason]);
}

/// Result of a non-blocking [`SigningTaskHandle::try_sign`]: either the oneshot
/// receiver for the signed receipt, or -- when the channel is at capacity or
/// closed -- the `(body, canonical_content)` pair returned so the caller can
/// retry without reconstructing them.
#[allow(dead_code)]
type TrySignOutcome =
    Result<oneshot::Receiver<Result<ChioReceipt, KernelError>>, (ChioReceiptBody, Vec<u8>)>;

/// Result of the atomic [`SigningTaskHandle::try_enqueue_if_open`] admission
/// step. Exactly one of three terminal paths for a request:
///
/// - [`Self::Enqueued`]: the request reached the channel; await the oneshot.
/// - [`Self::Backpressure`]: the aggregate budget was exhausted or the channel
///   was full. The `(body, canonical_content)` are returned so the caller can
///   INLINE-sign them rather than parking with the preimage held. Memory held
///   by would-be waiters is thereby bounded.
/// - [`Self::Closed`]: shutdown had begun (the closed flag was latched, or the
///   sender was already taken). The request is refused, never enqueued after
///   shutdown.
enum EnqueueOutcome {
    Enqueued(oneshot::Receiver<Result<ChioReceipt, KernelError>>),
    Backpressure(ChioReceiptBody, Vec<u8>),
    Closed(ChioReceiptBody, Vec<u8>),
}

/// One unit of work submitted to the signing task.
///
/// Carries the constructed receipt body and a oneshot reply channel for
/// the signed `ChioReceipt`. The body is moved into the task; the task
/// signs it and sends the result (or a [`KernelError`]) back through
/// `reply`. Callers that drop the receiver before the task replies cause
/// the task to silently discard the signed receipt without poisoning
/// itself.
pub(crate) struct SignRequest {
    /// Receipt body to sign. Constructed on the producer side
    /// (`build_and_sign_receipt` and friends) so the task only owns the
    /// pure cryptographic step.
    pub(crate) body: ChioReceiptBody,

    /// The exact byte preimage `body.content_hash` was derived from. The task
    /// recomputes `sha256_hex(canonical_content)` at the signing boundary and
    /// refuses to sign on mismatch (WYSIWYS), so this async funnel is
    /// byte-identical *and* equally fail-closed to the inline
    /// `build_and_sign_receipt` path.
    pub(crate) canonical_content: Vec<u8>,

    /// Oneshot channel for the signed receipt or signing error. The task
    /// uses `send` and ignores `Err(_)` (dropped receiver).
    pub(crate) reply: oneshot::Sender<Result<ChioReceipt, KernelError>>,

    /// Aggregate byte-budget permit held for the lifetime of this queued
    /// request. Acquired (sized to the preimage) before the request is
    /// enqueued and dropped by the signing task once `sign_one` returns, which
    /// releases the permits back to the shared [`Semaphore`] so the *sum* of
    /// queued preimage bytes stays under the aggregate budget. `None` only on
    /// the `#[path]`-included test/crash binaries that
    /// build `SignRequest` directly without an aggregate budget; the lib path
    /// always carries a permit.
    pub(crate) _aggregate_permit: Option<OwnedSemaphorePermit>,
}

/// Inner state shared between the kernel-side handle and the signing
/// task. Holds the bounded channel sender and the join handle for the
/// task. Built once on first `sign` call (lazily) so callers that
/// construct a `ChioKernel` outside a tokio runtime keep working; the
/// signing path itself is always async, so by the time we reach `sign`
/// the runtime is necessarily live.
///
/// `sender` is held in a `Mutex<Option<_>>` so [`SigningTaskHandle::shutdown`]
/// can take ownership of it exactly once and drop it, which closes the
/// channel for the receiver. After all senders are gone the receiver's
/// `recv` returns `None`, the task drains any in-flight messages, and
/// the JoinHandle resolves.
struct SigningTaskInner {
    /// Bounded channel into the signing task. Producers `.await` on
    /// `send` when full. Wrapped in `Mutex<Option<_>>` so
    /// [`SigningTaskHandle::shutdown`] can drop it deterministically;
    /// after shutdown subsequent `sign` calls observe `None` and
    /// surface `KernelError::Internal`.
    sender: Mutex<Option<mpsc::Sender<SignRequest>>>,

    /// JoinHandle for the spawned signing task. Wrapped in
    /// `Mutex<Option<_>>` so [`SigningTaskHandle::shutdown`] can take
    /// ownership exactly once even though the kernel handle is shared
    /// (`Arc<ChioKernel>`). `None` after a successful
    /// shutdown; subsequent shutdown calls are no-ops.
    join: Mutex<Option<JoinHandle<()>>>,
}

impl SigningTaskInner {
    /// Returns a clone of the active sender, or `None` if shutdown has
    /// already taken it out. Cloning the sender is cheap (Arc bump);
    /// holding a clone briefly across the mutex guard means we release
    /// the lock before doing the actual `.await` send.
    fn sender_clone(&self) -> Option<mpsc::Sender<SignRequest>> {
        match self.sender.lock() {
            Ok(slot) => slot.as_ref().cloned(),
            Err(poisoned) => poisoned.into_inner().as_ref().cloned(),
        }
    }
}

/// Handle owned by [`crate::ChioKernel`] for routing signing requests
/// through the dedicated signing task.
///
/// The handle stores the signing keypair and the configured channel
/// capacity. The task is spawned **lazily** on the first call to
/// [`Self::sign`] so the kernel can be constructed outside a tokio
/// runtime (the existing `ChioKernel::new` is sync and is invoked from
/// hundreds of sync test harnesses). Once spawned, the [`SigningTaskInner`]
/// is held inside a [`OnceLock`] for the lifetime of the kernel.
pub(crate) struct SigningTaskHandle {
    /// Lazy state: spawned on first `sign` call inside an async context.
    inner: OnceLock<SigningTaskInner>,

    /// Cloned signing keypair. Held alongside the lazy `inner` so the
    /// task can be spawned without re-deriving from `KernelConfig` at
    /// the call site.
    keypair: Keypair,

    /// Configured channel capacity. Exposed for diagnostics and tests.
    capacity: usize,

    /// Optional per-request byte cap on a single queued canonical-content
    /// preimage. `0` ([`PER_REQUEST_BUDGET_UNLIMITED`]) means *no per-request
    /// cap* (matching the inline signer). A non-zero value fail-closed refuses
    /// an oversized single preimage. The kernel wires this to `0` so the async
    /// path admits exactly what the inline path admits; tests configure a small
    /// non-zero cap to exercise the fail-closed boundary.
    max_content_bytes: usize,

    /// Shared AGGREGATE byte budget across all in-flight queued preimages.
    /// Producers acquire `preimage_len` permits before enqueueing and release
    /// them once the request is signed, bounding the *sum* of queued preimage
    /// bytes. Always bounded; the semaphore size is
    /// [`Self::aggregate_budget_permits`].
    aggregate_byte_budget: Arc<Semaphore>,

    /// Permit count the [`Self::aggregate_byte_budget`] semaphore was built
    /// with. A queued request acquires exactly `preimage_len` permits; a request
    /// whose preimage exceeds this count is never queued (it inline-signs,
    /// case 1), so an in-queue request can always be satisfied
    /// once the queue drains, without deadlock.
    aggregate_budget_permits: u32,

    /// Serializes lazy spawn against shutdown so a shutdown request cannot
    /// race between the closed-state check and task creation.
    spawn_gate: Mutex<()>,

    /// Set once shutdown is requested, including pre-spawn shutdown.
    closed: AtomicBool,
}

impl SigningTaskHandle {
    /// Build a handle that will spawn the signing task lazily on first
    /// [`Self::sign`] call, with the default channel capacity
    /// ([`DEFAULT_SIGNING_CHANNEL_CAPACITY`]).
    ///
    /// The kernel itself now constructs via
    /// [`Self::with_capacity_and_max_content_bytes`] to wire the configured
    /// stream/output max through, so this convenience constructor is reached
    /// only from the `#[path]`-included signing-task test modules; the
    /// `#[allow(dead_code)]` keeps it available to those binaries.
    #[allow(dead_code)]
    pub(crate) fn spawn(keypair: Keypair) -> Self {
        Self::with_capacity(keypair, DEFAULT_SIGNING_CHANNEL_CAPACITY)
    }

    /// Build a handle with a caller-chosen channel capacity and the default
    /// per-request byte budget ([`DEFAULT_MAX_SIGNING_CONTENT_BYTES`]). The task
    /// is spawned lazily on first [`Self::sign`] call.
    ///
    /// `capacity` must be `>= 1`; a zero capacity collapses to 1 to
    /// preserve the `send().await` semantics callers rely on (a
    /// rendezvous channel still surfaces backpressure but blocks on
    /// every send, which the default bounded capacity avoids).
    ///
    /// Reached only from the `#[path]`-included signing-task test modules now
    /// that the kernel passes an explicit byte budget; `#[allow(dead_code)]`
    /// keeps it available to those binaries.
    #[allow(dead_code)]
    pub(crate) fn with_capacity(keypair: Keypair, capacity: usize) -> Self {
        Self::with_capacity_and_max_content_bytes(
            keypair,
            capacity,
            DEFAULT_MAX_SIGNING_CONTENT_BYTES,
        )
    }

    /// Build a handle with a caller-chosen channel capacity and per-request
    /// byte cap, deriving the aggregate byte budget from the per-request cap.
    ///
    /// `max_content_bytes` is the optional per-request preimage cap: 0 is the
    /// explicit no-per-request-cap sentinel and is NOT coerced to max(1); a
    /// 1-byte cap would reject almost every receipt. A non-zero value
    /// fail-closed refuses a single preimage over the cap.
    ///
    /// The aggregate byte budget (the real queue-memory bound) is derived from
    /// the per-request cap: a non-zero cap budgets the aggregate at the cap; an
    /// unlimited (`0`) cap budgets the aggregate at
    /// [`DEFAULT_MAX_SIGNING_QUEUED_BYTES`] so queued memory stays BOUNDED even
    /// when the per-request cap is disabled.
    pub(crate) fn with_capacity_and_max_content_bytes(
        keypair: Keypair,
        capacity: usize,
        max_content_bytes: usize,
    ) -> Self {
        Self::with_capacity_max_content_and_queued_bytes(
            keypair,
            capacity,
            max_content_bytes,
            // Derive the aggregate budget from the per-request cap so callers
            // that only know one budget still get a bounded queue.
            if max_content_bytes == PER_REQUEST_BUDGET_UNLIMITED {
                DEFAULT_MAX_SIGNING_QUEUED_BYTES
            } else {
                max_content_bytes
            },
        )
    }

    /// Build a handle with an explicit aggregate (queue-wide) byte budget in
    /// addition to the per-request cap. The aggregate budget bounds the *sum* of
    /// in-flight queued preimage bytes; producers
    /// `.await` on it (backpressure) rather than being rejected, so the async
    /// path admits exactly what the inline signer admits while keeping queue
    /// memory BOUNDED.
    ///
    /// Reached from the lib path via
    /// [`Self::with_capacity_and_max_content_bytes`] and directly from the
    /// aggregate-backpressure tests; `#[allow(dead_code)]` keeps it available to
    /// the `#[path]`-included test binaries that do not exercise it.
    #[allow(dead_code)]
    pub(crate) fn with_capacity_max_content_and_queued_bytes(
        keypair: Keypair,
        capacity: usize,
        max_content_bytes: usize,
        max_queued_bytes: usize,
    ) -> Self {
        let capacity = capacity.max(1);
        // Do NOT `max(1)`: 0 is the explicit "no per-request cap" sentinel.
        let aggregate_budget_permits = clamp_aggregate_permits(max_queued_bytes);
        Self {
            inner: OnceLock::new(),
            keypair,
            capacity,
            max_content_bytes,
            aggregate_byte_budget: Arc::new(Semaphore::new(aggregate_budget_permits as usize)),
            aggregate_budget_permits,
            spawn_gate: Mutex::new(()),
            closed: AtomicBool::new(false),
        }
    }

    fn lock_spawn_gate(&self) -> MutexGuard<'_, ()> {
        match self.spawn_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn shutdown_error() -> KernelError {
        KernelError::Internal("receipt signing task already shut down".to_string())
    }

    /// Fail-closed error for a request whose canonical-content preimage exceeds
    /// the per-handle budget ([`Self::max_content_bytes`]). Refused before the
    /// request is enqueued so the bounded queue cannot retain an oversized
    /// buffer.
    fn oversized_content_error(&self, len: usize) -> KernelError {
        let budget = self.max_content_bytes;
        KernelError::ReceiptSigningFailed(format!(
            "receipt signing refused: canonical content is {len} bytes, over the \
             {budget}-byte per-request queue budget (sign oversized \
             receipts inline rather than through the async queue)"
        ))
    }

    /// Whether `len` exceeds the per-request cap. `0`
    /// ([`PER_REQUEST_BUDGET_UNLIMITED`]) means no cap, so nothing is ever
    /// oversized; this is what makes a `max_stream_total_bytes == 0` config (or
    /// the kernel's default of an unlimited per-request cap) admit large
    /// receipts on the async path, matching the inline signer.
    fn exceeds_per_request_cap(&self, len: usize) -> bool {
        self.max_content_bytes != PER_REQUEST_BUDGET_UNLIMITED && len > self.max_content_bytes
    }

    /// Number of aggregate-budget permits a preimage of `len` bytes must hold
    /// while queued. Only ever called for a preimage that *fits* the budget
    /// (`len <= aggregate_budget_permits`, guaranteed by
    /// [`Self::exceeds_aggregate_budget`] being checked first), so this is a
    /// direct `len as u32` with no clamp: a request whose byte count cannot fit
    /// the queue under the advertised aggregate bound is NEVER enqueued (it
    /// inline-signs instead, see [`Self::sign`]), so we never clamp-and-enqueue
    /// an oversized buffer that would hold more bytes than the budget admits.
    fn permits_for(&self, len: usize) -> u32 {
        debug_assert!(
            len <= self.aggregate_budget_permits as usize,
            "permits_for must only run for a preimage that fits the aggregate budget",
        );
        len as u32
    }

    /// Whether a `len`-byte preimage is too large to be queued under the
    /// advertised aggregate byte budget. Such a request would have to acquire
    /// MORE permits than the semaphore can ever vend, so enqueueing it (even
    /// after clamping the permit count) would retain a buffer larger than the
    /// queue memory bound. It must inline-sign instead.
    fn exceeds_aggregate_budget(&self, len: usize) -> bool {
        len > self.aggregate_budget_permits as usize
    }

    /// Lazily spawn the signing task and return a reference to the
    /// resulting [`SigningTaskInner`]. Idempotent: every caller after
    /// the first observes the existing task without spawning.
    fn ensure_spawned(&self) -> Result<&SigningTaskInner, KernelError> {
        let _spawn_guard = self.lock_spawn_gate();
        if self.closed.load(Ordering::Acquire) {
            return Err(Self::shutdown_error());
        }
        if let Some(inner) = self.inner.get() {
            return Ok(inner);
        }

        let handle = Handle::try_current().map_err(|_| {
            KernelError::Internal(
                "receipt signing task requires an active tokio runtime".to_string(),
            )
        })?;
        let (sender, receiver) = mpsc::channel::<SignRequest>(self.capacity);
        let join = handle.spawn(run_signing_task(self.keypair.clone(), receiver));
        let candidate = SigningTaskInner {
            sender: Mutex::new(Some(sender)),
            join: Mutex::new(Some(join)),
        };

        // `set` returns `Err(candidate)` when another thread won the
        // race; in that case the task we just spawned is orphaned. The
        // candidate's sender drops with the candidate, closing its
        // channel and letting the orphaned task return cleanly. The
        // lost JoinHandle is detached, which is safe because the task
        // body short-circuits on a closed channel.
        match self.inner.set(candidate) {
            Ok(()) => self.inner.get().ok_or_else(|| {
                KernelError::Internal("receipt signing task failed to initialize".to_string())
            }),
            Err(_orphan) => {
                // _orphan drops here: its sender mutex drops, channel
                // closes, orphan task exits.
                self.inner.get().ok_or_else(|| {
                    KernelError::Internal("receipt signing task failed to initialize".to_string())
                })
            }
        }
    }

    /// Atomically (relative to [`Self::shutdown`]) check the closed flag,
    /// acquire the aggregate byte-budget permit *without blocking*, and enqueue
    /// the request onto the channel. Returns an [`EnqueueOutcome`] telling the
    /// caller which of the three terminal paths to take.
    ///
    /// ## Why this whole step runs under the spawn gate
    ///
    /// `shutdown` latches `closed` AND drops the canonical sender while holding
    /// the [`Self::spawn_gate`]. Doing the closed-check, the sender clone, and
    /// the `try_send` all under the SAME gate makes admission a single atomic
    /// step relative to shutdown, which closes the clone-then-send window:
    /// there is no instant where a producer holds a
    /// live sender clone after `closed` was observed false but before the
    /// request is on the channel. Either shutdown wins the gate (we observe
    /// `closed` and return [`EnqueueOutcome::Closed`], refusing) or we win the
    /// gate and `try_send` onto the still-open channel BEFORE shutdown can drop
    /// the canonical sender (the request reaches the channel and shutdown drains
    /// it). No request can be enqueued after shutdown began.
    ///
    /// ## Why it never blocks
    ///
    /// The gate is a `std::sync::Mutex`, so nothing here may `.await`. That is
    /// deliberate: blocking on the aggregate permit (or on a full channel) while
    /// holding the full preimage is exactly the unbounded-waiter retention this
    /// path removes. Both `try_acquire` and
    /// `try_send` are non-blocking. When either reports no room, the caller
    /// falls back to INLINE signing rather than parking with the preimage held,
    /// so the bytes retained by would-be waiters cannot exceed the configured
    /// queue budget. The async signer is the documented off-critical-path
    /// signer, and the inline primitive is byte-identical and equally
    /// fail-closed (WYSIWYS), so the fallback is safe.
    fn try_enqueue_if_open(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> EnqueueOutcome {
        let _spawn_guard = self.lock_spawn_gate();
        // Hole 3: the closed-check is INSIDE the gate and stays held through the
        // `try_send` below, so shutdown cannot interleave between the check and
        // the enqueue.
        if self.closed.load(Ordering::Acquire) {
            return EnqueueOutcome::Closed(body, canonical_content);
        }
        let Some(sender) = self.inner.get().and_then(SigningTaskInner::sender_clone) else {
            return EnqueueOutcome::Closed(body, canonical_content);
        };
        // Hole 2: non-blocking permit acquisition. If the aggregate budget is
        // exhausted we do NOT park holding the preimage; we report backpressure
        // and the caller inline-signs.
        let permits = self.permits_for(canonical_content.len());
        let permit = match Arc::clone(&self.aggregate_byte_budget).try_acquire_many_owned(permits) {
            Ok(permit) => permit,
            Err(_) => {
                record_signing_queue_block("byte_budget");
                return EnqueueOutcome::Backpressure(body, canonical_content);
            }
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = SignRequest {
            body,
            canonical_content,
            reply: reply_tx,
            _aggregate_permit: Some(permit),
        };
        // Non-blocking send: holding the gate across `try_send` is what makes
        // the closed-check and the enqueue atomic relative to shutdown. A full
        // channel is treated as backpressure (inline fallback), never as a park.
        match sender.try_send(request) {
            Ok(()) => EnqueueOutcome::Enqueued(reply_rx),
            Err(mpsc::error::TrySendError::Full(rejected)) => {
                record_signing_queue_block("channel_full");
                EnqueueOutcome::Backpressure(rejected.body, rejected.canonical_content)
            }
            Err(mpsc::error::TrySendError::Closed(rejected)) => {
                EnqueueOutcome::Closed(rejected.body, rejected.canonical_content)
            }
        }
    }

    /// Inline (synchronous) fallback signer for requests that cannot be cleanly
    /// enqueued: a preimage too large for the aggregate budget (case 1) or a
    /// request that hit backpressure (case 2). Routes through the SAME
    /// `sign_one` primitive the signing task uses, which recomputes
    /// `sha256_hex(canonical_content)` inside the trust boundary and refuses on
    /// mismatch, so the inline path is byte-identical AND equally fail-closed
    /// (WYSIWYS): a render-A/sign-B attempt is rejected here too. Memory stays
    /// bounded because the preimage is consumed immediately rather than retained
    /// in a queue.
    fn sign_inline(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> Result<ChioReceipt, KernelError> {
        sign_one(&self.keypair, body, canonical_content)
    }

    /// Submit a signing request and `.await` the signed receipt.
    ///
    /// Returns `Err(KernelError::Internal)` if the signing task has
    /// already shut down (channel closed) or if the task replied that
    /// signing failed.
    ///
    /// ## Admission order
    ///
    /// Memory is BOUNDED at every branch and no request is ever enqueued after
    /// shutdown begins:
    ///
    /// 1. Per-request cap (OPTIONAL): a non-zero cap fail-closed refuses an
    ///    oversized single preimage. A `0` cap is unlimited (matches the inline
    ///    signer).
    /// 2. Oversized-for-aggregate (case 1): a preimage larger than the aggregate
    ///    byte budget can NEVER be queued under the advertised memory bound, so
    ///    it is NOT enqueued (no clamp-and-enqueue). It inline-signs instead, but
    ///    only after the closed-check so a post-shutdown oversized request is
    ///    refused.
    /// 3. Atomic enqueue ([`Self::try_enqueue_if_open`]): under the spawn gate,
    ///    re-check `closed`, `try_acquire` the budget (never block), and
    ///    `try_send` (never block). This is one atomic step relative to shutdown
    ///    (case 3) and never parks while holding the preimage (case 2).
    /// 4. Backpressure (case 2): when the budget is exhausted or the channel is
    ///    full, the request inline-signs rather than parking with the preimage
    ///    held, so the bytes retained by would-be waiters cannot exceed the
    ///    configured queue budget.
    ///
    /// Every inline fallback routes through the same WYSIWYS primitive
    /// ([`Self::sign_inline`] -> `sign_one`), so a render-A/sign-B attempt is
    /// rejected on the fallback path too.
    pub(crate) async fn sign(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> Result<ChioReceipt, KernelError> {
        let len = canonical_content.len();

        // Step 1: per-request cap. Fail-closed: never truncate, which
        // would break the WYSIWYS recompute).
        if self.exceeds_per_request_cap(len) {
            return Err(self.oversized_content_error(len));
        }

        // Step 2: a single preimage larger than the aggregate budget cannot be
        // enqueued without retaining more bytes than the queue bound advertises
        // Sign it inline instead of clamp-and-enqueue.
        // The closed-check inside `sign_inline_if_open` keeps shutdown exclusion:
        // a post-shutdown oversized request is refused, not inline-signed.
        if self.exceeds_aggregate_budget(len) {
            record_signing_queue_block("oversized");
            return self.sign_inline_if_open(body, canonical_content);
        }

        // Spawn the task (and surface a pre-spawn shutdown) before admission.
        self.ensure_spawned()?;

        // Step 3: atomic, non-blocking admission. No sender clone is held across
        // any `.await`, and no park happens while the preimage is owned.
        match self.try_enqueue_if_open(body, canonical_content) {
            EnqueueOutcome::Enqueued(reply_rx) => match reply_rx.await {
                Ok(result) => result,
                Err(_) => Err(KernelError::Internal(
                    "receipt signing task dropped reply channel".to_string(),
                )),
            },
            // Step 4: backpressure -> inline fallback (case 2). The request is
            // signed off-queue rather than blocking while holding the preimage,
            // so retained memory stays bounded under load.
            EnqueueOutcome::Backpressure(body, canonical_content) => {
                self.sign_inline(body, canonical_content)
            }
            // Shutdown began before the request reached the channel (case 3).
            EnqueueOutcome::Closed(_body, _canonical_content) => Err(KernelError::Internal(
                "receipt signing task already shut down".to_string(),
            )),
        }
    }

    /// Inline-sign a request UNLESS shutdown has begun, in which case refuse.
    ///
    /// Used for the oversized-for-aggregate path (case 1): such a request never
    /// reaches the channel, so it cannot be caught by the channel-close shutdown
    /// drain. Checking `closed` under the spawn gate here preserves the same
    /// shutdown-exclusion invariant the enqueue path enforces: no work (queued
    /// OR inline) is admitted after shutdown began.
    fn sign_inline_if_open(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> Result<ChioReceipt, KernelError> {
        {
            let _spawn_guard = self.lock_spawn_gate();
            if self.closed.load(Ordering::Acquire) {
                return Err(KernelError::Internal(
                    "receipt signing task already shut down".to_string(),
                ));
            }
        }
        self.sign_inline(body, canonical_content)
    }

    /// Try to submit a signing request without blocking on backpressure.
    ///
    /// Returns `Err((body, canonical_content))` immediately when the channel is
    /// at capacity (the inputs are returned so the caller can retry without
    /// reconstructing them). The returned future still `.await`s on the
    /// oneshot reply when the send succeeds. Used by tests that want to
    /// assert backpressure behaviour deterministically and by
    /// crash-recovery harnesses.
    ///
    /// The Err-variant carries the full receipt body (~544 bytes today) plus
    /// its content preimage because retry-on-backpressure callers want them
    /// back without re-allocating; boxing would force a heap allocation on
    /// every successful send. The lint is silenced because the size is a
    /// deliberate trade-off.
    #[allow(dead_code, clippy::result_large_err)]
    pub(crate) fn try_sign(
        &self,
        body: ChioReceiptBody,
        canonical_content: Vec<u8>,
    ) -> TrySignOutcome {
        // Per-request cap here too: an oversized preimage is returned unsent (the
        // Err variant means "not enqueued"). It is non-retryable, but the bounded
        // queue never holds it. A `0` cap is unlimited (matches the inline
        // signer).
        if self.exceeds_per_request_cap(canonical_content.len()) {
            return Err((body, canonical_content));
        }
        // Oversized-for-aggregate: a preimage larger
        // than the aggregate budget can never be queued under the advertised
        // memory bound, so it is returned unsent (never clamp-and-enqueue). The
        // non-blocking contract leaves the inline/refuse decision to the caller.
        if self.exceeds_aggregate_budget(canonical_content.len()) {
            return Err((body, canonical_content));
        }
        let inner = match self.ensure_spawned() {
            Ok(inner) => inner,
            Err(_) => return Err((body, canonical_content)),
        };
        let Some(sender) = inner.sender_clone() else {
            return Err((body, canonical_content));
        };
        // Aggregate byte budget: non-blocking acquire. When the budget is
        // exhausted the request is returned unsent (same "not enqueued"
        // contract as a full channel) rather than `.await`-ing, since this is
        // the non-blocking entrypoint.
        let permits = self.permits_for(canonical_content.len());
        let permit = match Arc::clone(&self.aggregate_byte_budget).try_acquire_many_owned(permits) {
            Ok(permit) => permit,
            Err(_) => return Err((body, canonical_content)),
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = SignRequest {
            body,
            canonical_content,
            reply: reply_tx,
            _aggregate_permit: Some(permit),
        };
        match sender.try_send(request) {
            Ok(()) => Ok(reply_rx),
            Err(mpsc::error::TrySendError::Full(rejected)) => {
                Err((rejected.body, rejected.canonical_content))
            }
            Err(mpsc::error::TrySendError::Closed(rejected)) => {
                Err((rejected.body, rejected.canonical_content))
            }
        }
    }

    /// Configured channel capacity (mostly for diagnostics / tests).
    #[allow(dead_code)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// True iff the lazy task has been spawned (i.e. at least one
    /// `sign` or `try_sign` call has reached `ensure_spawned`).
    #[allow(dead_code)]
    pub(crate) fn is_spawned(&self) -> bool {
        self.inner.get().is_some()
    }

    /// Abort the spawned task and close the canonical sender.
    ///
    /// Intentionally crate-private: exists for crash-recovery integration
    /// tests that need to model a hard task loss rather than a graceful
    /// [`Self::shutdown`]. Producers that were queued observe a dropped reply
    /// channel; producers that arrive afterward observe a closed signing task.
    #[allow(dead_code)]
    pub(crate) fn abort_for_crash_recovery_test(&self) {
        let Some(inner) = self.inner.get() else {
            return;
        };

        let dropped_sender = match inner.sender.lock() {
            Ok(mut slot) => slot.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        drop(dropped_sender);

        let guard = match inner.join.lock() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(join) = guard.as_ref() {
            join.abort();
        }
    }

    /// Drain in-flight requests and join the signing task.
    ///
    /// 1. Drops the canonical channel sender. The receiver inside the
    ///    task continues pulling messages until the queue is empty,
    ///    after which `recv()` returns `None` and the task exits.
    /// 2. `.await`s the task's `JoinHandle`. Every signing request
    ///    that successfully `.send().await`-ed before shutdown will
    ///    have been signed and replied to; producers that were blocked
    ///    on `send()` after shutdown observe `Err(SendError(_))` and
    ///    surface `KernelError::Internal`.
    /// 3. Panics inside the task body surface as `warn!` events but
    ///    do not propagate; the kernel is already on a shutdown path.
    ///
    /// Safe to call more than once: subsequent calls observe the
    /// sender / join slots empty and return immediately. Safe to call
    /// before the task has been spawned (no-op).
    pub(crate) async fn shutdown(&self) {
        let join = {
            let _spawn_guard = self.lock_spawn_gate();
            self.closed.store(true, Ordering::Release);
            let Some(inner) = self.inner.get() else {
                // Task was never spawned (no signing happened on this
                // kernel); closed is still latched so later signing fails.
                return;
            };

            // Step 1: drop the canonical sender. We take it out of the
            // mutex-guarded slot under a short critical section so the
            // drop happens AFTER the lock is released; this avoids a
            // deadlock with any concurrent `sender_clone` caller.
            let dropped_sender = match inner.sender.lock() {
                Ok(mut slot) => slot.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            drop(dropped_sender);

            // Step 2: take the JoinHandle out under the mutex so concurrent
            // shutdowns do not double-join.
            match inner.join.lock() {
                Ok(mut slot) => slot.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            }
        };

        let Some(join) = join else {
            return;
        };

        // Step 3: await join. The task drains the channel naturally
        // because we just dropped the only sender clone the kernel
        // held. Any oneshot reply senders in the queue are processed
        // and replied to in order before the task returns.
        match join.await {
            Ok(()) => {}
            Err(err) if err.is_cancelled() => {
                debug!("signing task cancelled before shutdown completed");
            }
            Err(err) => {
                warn!(error = %redacted!(&err), "signing task join failed (panic)");
            }
        }
    }
}

impl Drop for SigningTaskHandle {
    /// Best-effort drop: relies on the channel closing once every
    /// `Sender` clone is gone, at which point the task returns. Does NOT
    /// `.await` (Drop cannot be async); operators that need a synchronous
    /// shutdown call [`Self::shutdown`] from an async context first.
    ///
    /// When [`Self::shutdown`] has not been called the JoinHandle for
    /// the spawned task is detached: tokio will run the task to
    /// completion on the runtime that spawned it (or cancel it on
    /// runtime teardown). Pending oneshot receivers receive their reply
    /// if the task signs before the runtime stops, or observe a
    /// dropped sender otherwise. This matches the existing kernel
    /// semantics for any in-flight async work at process exit.
    fn drop(&mut self) {
        // Nothing to do: the inner cell drops, which drops the sender
        // mutex (closing the channel for the receiver), which lets the
        // signing task return naturally on the next `recv` poll. The
        // JoinHandle inside `inner.join` drops too; tokio detaches
        // detached JoinHandles without aborting them, so the task gets
        // a chance to drain.
    }
}

/// Body of the signing task. Pulls requests from `receiver`, signs each
/// one against `keypair`, and replies on the per-request oneshot.
///
/// Returns when `receiver` is closed (every `Sender` clone has been
/// dropped). The task does not panic on signing errors; it surfaces them
/// via the oneshot reply so producers can observe them as
/// [`KernelError::ReceiptSigningFailed`].
async fn run_signing_task(keypair: Keypair, mut receiver: mpsc::Receiver<SignRequest>) {
    debug!("signing task started");
    while let Some(request) = receiver.recv().await {
        let SignRequest {
            body,
            canonical_content,
            reply,
            _aggregate_permit,
        } = request;
        let result = sign_one(&keypair, body, canonical_content);
        // Release the aggregate byte-budget permit only AFTER `sign_one` has
        // consumed `canonical_content` (the preimage is no longer retained), so
        // the budget reflects bytes actually held in memory. Dropping the
        // permit returns its bytes to the shared
        // semaphore, unblocking a producer waiting on backpressure.
        drop(_aggregate_permit);
        // A dropped receiver is not an error: the producer either timed
        // out or was cancelled. Discard the signed receipt silently
        // rather than poisoning the task; signing is a pure function so
        // the cost is bounded.
        let _ = reply.send(result);
    }
    debug!("signing task exited (channel closed)");
}

/// Pure signing step: matches the inline path in `responses.rs` so
/// receipts produced via the channel are byte-identical to receipts
/// produced via `build_and_sign_receipt`.
fn sign_one(
    keypair: &Keypair,
    body: ChioReceiptBody,
    canonical_content: Vec<u8>,
) -> Result<ChioReceipt, KernelError> {
    let backend = Ed25519Backend::new(keypair.clone());
    sign_one_with_backend(body, &backend, canonical_content)
}

fn sign_one_with_backend(
    body: ChioReceiptBody,
    backend: &dyn SigningBackend,
    canonical_content: Vec<u8>,
) -> Result<ChioReceipt, KernelError> {
    // Delegate to the single canonical signing primitive
    // `chio_kernel_core::sign_receipt_with_handle`, the same WYSIWYS primitive
    // the inline `build_and_sign_receipt` path uses. The primitive recomputes
    // `sha256_hex(canonical_content)` inside the trust boundary and refuses to
    // sign when it disagrees with `body.content_hash` (fail-closed),
    // then routes through `ChioReceipt::sign_with_backend`, which performs the
    // authoritative signing sequence: validate semantics, bind the
    // `chio_receipt_signing_nonce` metadata key to the pre-nonce receipt id,
    // compute the content-addressed id, build the `ChioReceiptSigningBody`
    // wrapper, and sign. Routing the mpsc task through the same primitive means
    // there is exactly one signing implementation, so the inline and async
    // funnels are byte-identical *and* equally fail-closed by construction
    // rather than by hand synchronization. The mpsc task still owns the keypair
    // and channel plumbing; only the pure crypto step is delegated. We call the
    // portable kernel-core function directly (rather than the
    // `crate::receipt_support` wrapper) because this module is also
    // `#[path]`-included by the crash/backpressure integration tests, whose
    // crate root does not carry the `receipt_support` module;
    // `chio_kernel_core` is reachable in both contexts.
    let handle =
        chio_core::receipt::signing::ReceiptSigningHandle::from_content_preimage(canonical_content);
    chio_kernel_core::sign_receipt_with_handle(body, backend, handle).map_err(|error| {
        use chio_kernel_core::ReceiptSigningError;
        let message = match error {
            ReceiptSigningError::KernelKeyMismatch => {
                "kernel signing key does not match receipt body kernel_key".to_string()
            }
            ReceiptSigningError::ContentHashMismatch {
                recomputed,
                claimed,
            } => format!(
                "receipt content_hash mismatch: body claimed {claimed} but signer \
                 recomputed {recomputed} over the canonical content (WYSIWYS refused)"
            ),
            ReceiptSigningError::SigningFailed(reason) => reason,
        };
        KernelError::ReceiptSigningFailed(message)
    })
}
