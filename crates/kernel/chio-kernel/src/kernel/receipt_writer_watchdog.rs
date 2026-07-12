//! Receipt-writer liveness watchdog. Opt-in: the hosting edge starts the poll
//! task, which samples the store's writer liveness on a cadence and publishes
//! the latest verdict into an `ArcSwap` cell the pre-dispatch readiness gate
//! reads. With no watchdog running, the cell stays `Unknown` and the gate keeps
//! its prior config-presence behavior. A single publisher (the poll task) and
//! many lock-free readers (every evaluate call) make `ArcSwap` the right fit.

use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use tokio::task::JoinHandle;

use crate::receipt_store::ReceiptWriterLiveness;

pub(crate) struct ReceiptWriterWatchdogHandle {
    verdict: ArcSwap<ReceiptWriterLiveness>,
    join: Mutex<Option<JoinHandle<()>>>,
}

impl ReceiptWriterWatchdogHandle {
    pub(crate) fn new() -> Self {
        Self {
            verdict: ArcSwap::from_pointee(ReceiptWriterLiveness::Unknown),
            join: Mutex::new(None),
        }
    }

    pub(crate) fn current(&self) -> ReceiptWriterLiveness {
        **self.verdict.load()
    }

    pub(crate) fn publish(&self, verdict: ReceiptWriterLiveness) {
        self.verdict.store(Arc::new(verdict));
    }

    /// Record the poll task handle so `shutdown` can join it. Replaces any
    /// prior handle, aborting it, so a second `spawn` call cannot leak a task.
    pub(crate) fn set_join_handle(&self, handle: JoinHandle<()>) {
        let previous = match self.join.lock() {
            Ok(mut join) => join.replace(handle),
            Err(poisoned) => poisoned.into_inner().replace(handle),
        };
        if let Some(previous) = previous {
            previous.abort();
        }
    }

    /// Whether a background poll task is currently installed.
    #[cfg(test)]
    pub(crate) fn is_running(&self) -> bool {
        match self.join.lock() {
            Ok(join) => join.is_some(),
            Err(poisoned) => poisoned.into_inner().is_some(),
        }
    }

    pub(crate) async fn shutdown(&self) {
        let handle = {
            let mut join = match self.join.lock() {
                Ok(join) => join,
                Err(poisoned) => poisoned.into_inner(),
            };
            join.take()
        };
        if let Some(handle) = handle {
            handle.abort();
            let _ = handle.await;
        }
    }
}
