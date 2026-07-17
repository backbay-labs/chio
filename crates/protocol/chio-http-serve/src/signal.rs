use std::future::Future;

use tokio::sync::watch;
use tracing::error;

/// Resolve on the first SIGTERM (unix) or Ctrl-C / SIGINT (all platforms).
///
/// The future is fail-closed against handler-install failure: a handler that
/// cannot be installed logs loudly and yields to a pending branch rather than
/// resolving, so a missing handler never triggers a spurious shutdown at
/// startup. If both handlers fail to install the future simply never resolves
/// and the process keeps running until the platform escalates to an
/// unconditional kill, which is no worse than having no shutdown wiring at all.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {}
            Err(source) => {
                error!(%source, "cannot install Ctrl-C handler; the SIGTERM path still governs shutdown");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(source) => {
                error!(%source, "cannot install SIGTERM handler; the Ctrl-C path still governs shutdown");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}

/// Owns the shutdown watch channel that fans one stop signal out to the serve
/// loop and every cooperating background task. The receivers it hands out are
/// cheap to clone.
pub struct ShutdownController {
    tx: watch::Sender<bool>,
    rx: watch::Receiver<bool>,
}

impl ShutdownController {
    /// Spawn the OS-signal task and return a controller that is live
    /// immediately. Requires an active Tokio runtime; the spawned task
    /// translates the first [`shutdown_signal`] into a `true` on the channel.
    #[must_use]
    pub fn install() -> Self {
        let (tx, rx) = watch::channel(false);
        let task_tx = tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            // A closed channel (every receiver dropped) is not an error here: it
            // just means there is nothing left to notify.
            let _ = task_tx.send(true);
        });
        Self { tx, rx }
    }

    /// Build a controller with no OS-signal task, triggered only through
    /// [`ShutdownController::trigger`]. Useful for tests and for embeddings that
    /// drive shutdown from their own signal source.
    #[must_use]
    pub fn manual() -> Self {
        let (tx, rx) = watch::channel(false);
        Self { tx, rx }
    }

    /// A receiver for a cooperating background loop. The canonical stop check is
    /// `while !*rx.borrow_and_update() { if rx.changed().await.is_err() { break } }`.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }

    /// Request a drain programmatically. This is the same path a signal takes,
    /// so an admin endpoint or a fatal-error handler can ask for the same clean
    /// teardown.
    pub fn trigger(&self) {
        // A closed channel means every receiver is gone; there is nothing to
        // wake, so a send error is expected and ignored.
        let _ = self.tx.send(true);
    }

    /// Whether a shutdown has already been requested.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        *self.rx.borrow()
    }

    /// The future to hand to `axum::serve(..).with_graceful_shutdown(..)`.
    pub fn signalled(&self) -> impl Future<Output = ()> + Send + 'static {
        wait_for_shutdown(self.rx.clone())
    }
}

/// Resolve once `rx` observes a shutdown request. A dropped sender is treated as
/// a request so a lost controller can never wedge a drain open.
pub(crate) async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            break;
        }
    }
}
