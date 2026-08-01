//! Default-off deterministic hooks for separate-process store fault tests.

#[cfg(feature = "chaos-test-hooks")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "chaos-test-hooks")]
use std::time::{Duration, Instant};

#[cfg(feature = "chaos-test-hooks")]
use chio_kernel::ReceiptStoreError;

/// Pause after a new receipt and its claim-log projection have been written in
/// the SQLite transaction, but before the transaction commits. The
/// separate-process chaos victim enables this hook with unique paths and a
/// seeded batch number. A release file lets focused harnesses resume; the crash
/// lane kills the process. An all-idempotent or all-rejected batch cannot
/// publish the marker because it made no new durable-state mutation.
#[cfg(feature = "chaos-test-hooks")]
pub(super) fn pause_after_receipt_write_before_commit(
    inserted_new_receipt: bool,
) -> Result<(), ReceiptStoreError> {
    const READY_ENV: &str = "CHIO_CHAOS_APPEND_READY_PATH";
    const RELEASE_ENV: &str = "CHIO_CHAOS_APPEND_RELEASE_PATH";
    const PAUSE_BATCH_ENV: &str = "CHIO_CHAOS_APPEND_PAUSE_BATCH";
    const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

    if !inserted_new_receipt {
        return Ok(());
    }
    let (ready, release, pause_batch) = match (
        std::env::var_os(READY_ENV),
        std::env::var_os(RELEASE_ENV),
        std::env::var_os(PAUSE_BATCH_ENV),
    ) {
        (None, None, None) => return Ok(()),
        (Some(ready), Some(release), Some(pause_batch)) => (ready, release, pause_batch),
        _ => {
            return Err(ReceiptStoreError::Conflict(format!(
                "{READY_ENV}, {RELEASE_ENV}, and {PAUSE_BATCH_ENV} must either all be set or all be absent"
            )))
        }
    };
    let pause_batch = pause_batch
        .to_str()
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!("{PAUSE_BATCH_ENV} is not valid Unicode"))
        })?
        .parse::<u64>()
        .map_err(|_| {
            ReceiptStoreError::Conflict(format!("{PAUSE_BATCH_ENV} must be a positive u64"))
        })?;
    if pause_batch == 0 {
        return Err(ReceiptStoreError::Conflict(format!(
            "{PAUSE_BATCH_ENV} must be at least 1"
        )));
    }
    static APPEND_BATCH_COUNT: AtomicU64 = AtomicU64::new(0);
    let current_batch = APPEND_BATCH_COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    if current_batch != pause_batch {
        return Ok(());
    }

    let ready = std::path::PathBuf::from(ready);
    let release = std::path::PathBuf::from(release);
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ready)
        .map_err(ReceiptStoreError::Io)?;
    std::io::Write::write_all(&mut marker, b"receipt-written-before-commit\n")
        .map_err(ReceiptStoreError::Io)?;
    marker.sync_all().map_err(ReceiptStoreError::Io)?;

    let deadline = Instant::now() + HOOK_TIMEOUT;
    loop {
        match std::fs::metadata(&release) {
            Ok(_) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ReceiptStoreError::Io(error)),
        }
        if Instant::now() >= deadline {
            return Err(ReceiptStoreError::Conflict(
                "chaos append hook timed out waiting for release".to_string(),
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
