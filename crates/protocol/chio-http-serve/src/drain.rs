use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;
use tracing::warn;

use crate::signal::wait_for_shutdown;

/// How a bounded drain finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// Every in-flight request completed before the drain deadline.
    Clean,
    /// The drain deadline elapsed and the remaining connections were
    /// force-closed.
    Forced,
}

/// Terminal error from a bounded serve. Either variant is a non-zero process
/// exit; neither is ever swallowed.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The serve future itself failed.
    #[error("serve I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The post-drain flush of a receipt store failed. This is loud on purpose:
    /// it means a receipt may not be durable, so the operator must see a
    /// non-zero exit rather than a silent success.
    #[error("post-drain receipt flush failed: {0}")]
    Flush(String),
}

/// Run a graceful serve future to completion, bounding only the post-signal
/// drain, then run a flush hook.
///
/// `server` is the site's `axum::serve(..).with_graceful_shutdown(ctrl.signalled())`
/// future, `shutdown` is a receiver from the same controller, and `on_drained`
/// flushes the site's receipt store (or is a no-op).
///
/// The drain deadline arms only once the shutdown signal fires, never at server
/// start: a naive timeout around the whole serve future would kill a healthy
/// server `drain_timeout` after boot. So the serve runs unbounded until either
/// it ends on its own or the signal arrives; only then does the remaining
/// in-flight drain get a deadline.
///
/// Flush-hook contract: on a clean drain the flush runs after every accepted
/// connection has finished, so it has the store to itself. On a forced drain a
/// connection outlived the deadline; axum serves each connection on a detached
/// task that a bounded drain can neither join nor cancel, so `on_drained` can run
/// while such a straggler is still finishing and MUST be safe against a concurrent
/// writer. Sites keep this safe by making every acknowledged receipt durable
/// synchronously in the handler (or via a commit actor that acks only after the
/// write reaches the WAL), never in the flush hook, so a straggler can never cost
/// an acknowledged receipt.
pub async fn run_until_drained<S, D>(
    server: S,
    shutdown: watch::Receiver<bool>,
    drain_timeout: Duration,
    on_drained: D,
) -> Result<DrainOutcome, ServeError>
where
    // `axum::serve(..).with_graceful_shutdown(..)` is an `IntoFuture`, not a
    // `Future`; accept it directly so a call site passes it as-is.
    S: std::future::IntoFuture<Output = std::io::Result<()>>,
    D: Future<Output = Result<(), String>>,
{
    // Box-pin rather than stack-pin so the forced-drain path can drop the serve
    // future to force-close a connection still stuck at the deadline. A stack
    // `Pin<&mut _>` only borrows and cannot be dropped early; an owned
    // `Pin<Box<_>>` can.
    let mut server = Box::pin(server.into_future());
    let signalled = wait_for_shutdown(shutdown);

    let outcome = tokio::select! {
        // Phase 1: serve until the server exits on its own or the signal fires.
        result = &mut server => match result {
            Ok(()) => DrainOutcome::Clean,
            Err(source) => return Err(ServeError::Io(source)),
        },
        () = signalled => {
            // Phase 2: graceful shutdown has stopped the accept loop; bound only
            // the remaining in-flight drain.
            match tokio::time::timeout(drain_timeout, &mut server).await {
                Ok(Ok(())) => DrainOutcome::Clean,
                Ok(Err(source)) => return Err(ServeError::Io(source)),
                Err(_elapsed) => {
                    let drain_ms = u64::try_from(drain_timeout.as_millis()).unwrap_or(u64::MAX);
                    warn!(
                        drain_timeout_ms = drain_ms,
                        "drain deadline exceeded; force-closing remaining connections"
                    );
                    DrainOutcome::Forced
                }
            }
        }
    };

    // On a forced drain the serve future is still parked waiting on a connection
    // that outlived the deadline. Drop it to release the accept loop and the
    // listener before the flush. This does not guarantee the connection's handler
    // has stopped: axum runs it on a detached task, so it may still be finishing
    // (see the flush-hook contract above). A clean outcome already ran the future
    // to completion, so the drop is a no-op there.
    if matches!(outcome, DrainOutcome::Forced) {
        drop(server);
    }

    on_drained.await.map_err(ServeError::Flush)?;
    Ok(outcome)
}
