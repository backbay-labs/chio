use chio_log_redact::redacted;

/// Default interval between sweeps of orphaned budget holds.
pub const DEFAULT_HOLD_SWEEP_INTERVAL_SECS: u64 = 300;
/// Default age beyond which an open hold counts as orphaned. Generously
/// above any legitimate in-flight call, so the sweeper only ever collects
/// true orphans; reclaiming is fail-closed under-spend (a released hold
/// returns capacity, never records spend).
pub const DEFAULT_HOLD_EXPIRY_HORIZON_SECS: u64 = 3_600;
/// Holds expired per sweep pass, bounding each pass's write volume.
const HOLD_SWEEP_BATCH: usize = 256;

/// Background task that sweeps orphaned budget holds: once at start, then
/// periodically. Never panics; joined on drop so a dropped kernel leaves no
/// detached sweeper thread.
pub struct BudgetHoldSweepHandle {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl BudgetHoldSweepHandle {
    pub(crate) fn spawn(
        budget_store: std::sync::Arc<dyn crate::budget_store::BudgetStore>,
        interval_secs: u64,
        horizon_secs: u64,
    ) -> Self {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = std::sync::Arc::clone(&stop);
        let join = std::thread::spawn(move || {
            let interval = std::time::Duration::from_secs(interval_secs.max(1));
            loop {
                sweep_once(budget_store.as_ref(), horizon_secs, HOLD_SWEEP_BATCH);
                let slice = std::time::Duration::from_millis(200);
                let mut waited = std::time::Duration::ZERO;
                while waited < interval && !worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    std::thread::sleep(slice);
                    waited += slice;
                }
                if worker_stop.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
        });
        Self {
            stop,
            join: Some(join),
        }
    }
}

impl Drop for BudgetHoldSweepHandle {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// One sweep pass: expire every open hold older than the horizon, then
/// refresh the open-holds gauge. Errors are warned and retried on the next
/// pass; the sweeper never unwinds.
fn sweep_once(store: &dyn crate::budget_store::BudgetStore, horizon_secs: u64, batch: usize) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0);
    let cutoff = now_ms.saturating_sub(horizon_secs.saturating_mul(1_000));
    match store.list_open_holds_older_than(cutoff, batch) {
        Ok(holds) => {
            for hold in holds {
                match store.expire_open_hold(&hold.hold_id) {
                    Ok(true) => {
                        chio_metrics_spec::runtime::families::BUDGET_HOLDS_EXPIRED.incr(&[]);
                        tracing::warn!(
                            hold_id = %hold.hold_id,
                            capability_id = %hold.capability_id,
                            released_units = hold.remaining_exposure_units,
                            "expired an orphaned budget hold; capacity released"
                        );
                    }
                    Ok(false) => {}
                    Err(error) => tracing::warn!(
                        hold_id = %hold.hold_id,
                        reason = %redacted!(&error.to_string()),
                        "expire_open_hold failed; retrying next sweep"
                    ),
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                reason = %redacted!(&error.to_string()),
                "listing open holds failed; retrying next sweep"
            );
        }
    }
    if let Ok(count) = store.open_hold_count() {
        chio_metrics_spec::runtime::families::BUDGET_OPEN_HOLDS.set(&[], count);
    }
}
