//! Mpsc-backed receipt signing task.
//!
//! ## Why this exists
//!
//! The kernel previously signed receipts inline on the evaluate critical path,
//! holding the synchronous `build_and_sign_receipt` step inside the same call
//! stack that was already running guard pipelines and store mutations. Under
//! load that funnel pinned a worker thread per concurrent evaluate call.
//!
//! A single signing task now owns a clone of the kernel signing keypair and
//! pulls signing requests from a bounded [`tokio::sync::mpsc`] channel.
//! Producers `.await` on a oneshot reply channel rather than on a mutex;
//! backpressure surfaces naturally when the bounded queue fills.
//!
//! The existing synchronous `build_and_sign_receipt` helper in
//! `kernel/responses.rs` is unchanged. Internal call sites (deny-receipt
//! builders, child-receipt builders, federation cosign hook) keep their inline
//! path. The mpsc path delegates to the same `chio_kernel_core::sign_receipt`
//! portable helper, so receipt bytes are byte-identical across the two paths.
//! Persistence stays inline; only the signature step crosses the channel.
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
//!   simply discarded.
//!
//! ## Channel capacity
//!
//! Default capacity is [`DEFAULT_SIGNING_CHANNEL_CAPACITY`] (256). The
//! milestone names "fail-closed default" -- a bounded channel where
//! producers `.await` on `send` until capacity frees up, rather than an
//! unbounded queue that lets memory grow without limit. Tests can pick a
//! smaller capacity to exercise backpressure deterministically via
//! [`SigningTaskHandle::with_capacity`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

use tokio::runtime::Handle;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::{ChioReceipt, ChioReceiptBody, KernelError, Keypair};

/// Default bounded capacity for the signing-task mpsc channel.
///
/// 256 in-flight signing requests is generous for a single-process kernel
/// (each request is a `ChioReceiptBody` plus a `oneshot::Sender`, well under
/// 1 KiB amortised) and small enough to surface backpressure during a
/// signing-task stall before producer memory grows unbounded. Operators
/// can override via [`SigningTaskHandle::with_capacity`] until a config
/// knob lands in a later phase.
pub const DEFAULT_SIGNING_CHANNEL_CAPACITY: usize = 256;

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

    /// Oneshot channel for the signed receipt or signing error. The task
    /// uses `send` and ignores `Err(_)` (dropped receiver).
    pub(crate) reply: oneshot::Sender<Result<ChioReceipt, KernelError>>,
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
    /// (`Arc<ChioKernel>` after Phase 3). `None` after a successful
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
    pub(crate) fn spawn(keypair: Keypair) -> Self {
        Self::with_capacity(keypair, DEFAULT_SIGNING_CHANNEL_CAPACITY)
    }

    /// Build a handle with a caller-chosen channel capacity. The task
    /// is spawned lazily on first [`Self::sign`] call.
    ///
    /// `capacity` must be `>= 1`; a zero capacity collapses to 1 to
    /// preserve the `send().await` semantics callers rely on (a
    /// rendezvous channel still surfaces backpressure but blocks on
    /// every send, which the milestone-doc default explicitly avoids).
    pub(crate) fn with_capacity(keypair: Keypair, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: OnceLock::new(),
            keypair,
            capacity,
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

    /// Lazily spawn the signing task and return a reference to the
    /// resulting [`SigningTaskInner`]. Idempotent: every caller after
    /// the first observes the existing task without spawning.
    ///
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

    /// Submit a signing request and `.await` the signed receipt.
    ///
    /// Returns `Err(KernelError::Internal)` if the signing task has
    /// already shut down (channel closed) or if the task replied that
    /// signing failed. Producers wait on bounded backpressure, never on
    /// a mutex.
    pub(crate) async fn sign(&self, body: ChioReceiptBody) -> Result<ChioReceipt, KernelError> {
        let inner = self.ensure_spawned()?;
        let sender = inner.sender_clone().ok_or_else(|| {
            KernelError::Internal("receipt signing task already shut down".to_string())
        })?;

        let (reply_tx, reply_rx) = oneshot::channel();
        let request = SignRequest {
            body,
            reply: reply_tx,
        };

        sender.send(request).await.map_err(|_| {
            KernelError::Internal("receipt signing task is no longer running".to_string())
        })?;

        match reply_rx.await {
            Ok(result) => result,
            Err(_) => Err(KernelError::Internal(
                "receipt signing task dropped reply channel".to_string(),
            )),
        }
    }

    /// Try to submit a signing request without blocking on backpressure.
    ///
    /// Returns `Err(body)` immediately when the channel is at capacity
    /// (the body is returned so the caller can retry without
    /// reconstructing it). The returned future still `.await`s on the
    /// oneshot reply when the send succeeds. Used by tests that want to
    /// assert backpressure behaviour deterministically and by
    /// crash-recovery harnesses.
    ///
    /// The Err-variant carries the full receipt body (~544 bytes today)
    /// because retry-on-backpressure callers want the body back without
    /// allocating; boxing it would force a heap allocation on every
    /// successful send. The lint is silenced because the size is a
    /// deliberate trade-off.
    #[allow(dead_code, clippy::result_large_err)]
    pub(crate) fn try_sign(
        &self,
        body: ChioReceiptBody,
    ) -> Result<oneshot::Receiver<Result<ChioReceipt, KernelError>>, ChioReceiptBody> {
        let inner = match self.ensure_spawned() {
            Ok(inner) => inner,
            Err(_) => return Err(body),
        };
        let Some(sender) = inner.sender_clone() else {
            return Err(body);
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = SignRequest {
            body,
            reply: reply_tx,
        };
        match sender.try_send(request) {
            Ok(()) => Ok(reply_rx),
            Err(mpsc::error::TrySendError::Full(rejected)) => Err(rejected.body),
            Err(mpsc::error::TrySendError::Closed(rejected)) => Err(rejected.body),
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
                warn!(error = %err, "signing task join failed (panic)");
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
        let SignRequest { body, reply } = request;
        let result = sign_one(&keypair, body);
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
fn sign_one(keypair: &Keypair, body: ChioReceiptBody) -> Result<ChioReceipt, KernelError> {
    let backend = chio_core::crypto::Ed25519Backend::new(keypair.clone());
    chio_kernel_core::sign_receipt(body, &backend).map_err(|error| {
        use chio_kernel_core::ReceiptSigningError;
        let message = match error {
            ReceiptSigningError::KernelKeyMismatch => {
                "kernel signing key does not match receipt body kernel_key".to_string()
            }
            ReceiptSigningError::SigningFailed(reason) => reason,
        };
        KernelError::ReceiptSigningFailed(message)
    })
}
