//! Explicit ownership of asynchronous jobs and bounded blocking work.
use anyhow::{anyhow, Result};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    sync::Semaphore,
    task::{AbortHandle, JoinSet},
    time::Instant,
};

#[derive(Default)]
struct State {
    closed: bool,
    tasks: JoinSet<Result<()>>,
    failure: Option<String>,
}

/// Owns jobs independently of request futures. Call close, request cooperative
/// cancellation, then drain before dropping the application or its stores.
#[derive(Clone, Default)]
pub struct TaskGroup(Arc<Mutex<State>>);

impl TaskGroup {
    pub fn spawn(
        &self,
        work: impl Future<Output = Result<()>> + Send + 'static,
    ) -> Result<AbortHandle> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| anyhow!("task registry poisoned"))?;
        if state.closed {
            anyhow::bail!("host is draining; new work is refused");
        }
        while let Some(result) = state.tasks.try_join_next() {
            if let Err(error) = result.map_err(anyhow::Error::from).and_then(|value| value) {
                eprintln!("Background work failed: {error:#}");
                state.failure.get_or_insert_with(|| error.to_string());
            }
        }
        Ok(state.tasks.spawn(work))
    }

    pub fn close(&self) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| anyhow!("task registry poisoned"))?
            .closed = true;
        Ok(())
    }

    /// Wait through final persistence, then abort and join stragglers. A forced
    /// stop is an error: callers must inspect retained intent and effects.
    pub async fn drain(&self, timeout: Duration) -> Result<()> {
        let (mut tasks, mut failure) = {
            let mut state = self
                .0
                .lock()
                .map_err(|_| anyhow!("task registry poisoned"))?;
            state.closed = true;
            (std::mem::take(&mut state.tasks), state.failure.take())
        };
        let deadline = Instant::now() + timeout;
        while !tasks.is_empty() {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(result)) => {
                    if let Err(error) = result.map_err(anyhow::Error::from).and_then(|value| value)
                    {
                        failure.get_or_insert_with(|| error.to_string());
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    anyhow::bail!(
                        "shutdown deadline reached; unfinished effects require reconciliation"
                    );
                }
            }
        }
        if let Some(error) = failure {
            anyhow::bail!("background work failed: {error}");
        }
        Ok(())
    }
}

/// An explicit concurrency limit, with immediate overload refusal. The closure
/// owns its permit until completion even when the caller stops awaiting it.
#[derive(Clone)]
pub struct BlockingPool {
    permits: Arc<Semaphore>,
    closed: Arc<AtomicBool>,
    limit: u32,
}
impl BlockingPool {
    pub fn new(limit: u32) -> Self {
        assert!(limit > 0, "blocking capacity must be positive");
        Self {
            permits: Arc::new(Semaphore::new(limit as usize)),
            closed: Arc::new(AtomicBool::new(false)),
            limit,
        }
    }
    pub async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow!("blocking capacity exhausted"))?;
        if self.closed.load(Ordering::Acquire) {
            anyhow::bail!("blocking worker is draining");
        }
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|error| anyhow!("blocking worker stopped: {error}"))?
    }
    pub async fn drain(&self, timeout: Duration) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        let _all =
            tokio::time::timeout(timeout, self.permits.clone().acquire_many_owned(self.limit))
                .await
                .map_err(|_| {
                    anyhow!("blocking work is still running; inspect effects before exit")
                })??;
        Ok(())
    }
}

/// A scoped child task. Dropping its supervisor aborts the child instead of
/// detaching it. Normal paths still await the join to observe finalization.
pub struct OwnedTask<T>(tokio::task::JoinHandle<T>);
impl<T: Send + 'static> OwnedTask<T> {
    pub fn spawn(work: impl Future<Output = T> + Send + 'static) -> Self {
        Self(tokio::spawn(work))
    }
    pub fn abort(&self) {
        self.0.abort();
    }
    pub fn abort_handle(&self) -> AbortHandle {
        self.0.abort_handle()
    }
    pub async fn join(&mut self) -> Result<T, tokio::task::JoinError> {
        (&mut self.0).await
    }
}
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn drain_waits_for_finalization_and_rejects_new_work() {
        let group = TaskGroup::default();
        let finished = Arc::new(AtomicBool::new(false));
        let flag = finished.clone();
        group
            .spawn(async move {
                tokio::time::sleep(Duration::from_millis(5)).await;
                flag.store(true, Ordering::Release);
                Ok(())
            })
            .unwrap();
        group.close().unwrap();
        assert!(group.spawn(async { Ok(()) }).is_err());
        group.drain(Duration::from_secs(1)).await.unwrap();
        assert!(finished.load(Ordering::Acquire));
    }
    #[tokio::test]
    async fn failed_or_aborted_work_cannot_report_clean_shutdown() {
        let group = TaskGroup::default();
        group
            .spawn(async { anyhow::bail!("retention failed") })
            .unwrap();
        assert!(group.drain(Duration::from_secs(1)).await.is_err());
        let group = TaskGroup::default();
        group.spawn(std::future::pending()).unwrap();
        assert!(group.drain(Duration::from_millis(1)).await.is_err());
    }
    #[tokio::test]
    async fn abandoned_waiter_does_not_release_blocking_capacity() {
        let pool = BlockingPool::new(1);
        let worker = pool.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let caller = tokio::spawn(async move {
            worker
                .run(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    Ok(())
                })
                .await
        });
        started_rx.await.unwrap();
        caller.abort();
        let _ = caller.await;
        assert!(pool.run(|| Ok(())).await.is_err());
        release_tx.send(()).unwrap();
        pool.drain(Duration::from_secs(1)).await.unwrap();
        assert!(pool.run(|| Ok(())).await.is_err());
    }
    #[tokio::test]
    async fn dropping_a_supervisor_aborts_its_scoped_child() {
        struct Notify(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Notify {
            fn drop(&mut self) {
                if let Some(send) = self.0.take() {
                    let _ = send.send(());
                }
            }
        }
        let (started, ready) = tokio::sync::oneshot::channel();
        let (dropped, observed) = tokio::sync::oneshot::channel();
        let child = OwnedTask::spawn(async move {
            let _notify = Notify(Some(dropped));
            started.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        drop(child);
        tokio::time::timeout(Duration::from_secs(1), observed)
            .await
            .unwrap()
            .unwrap();
    }
}
