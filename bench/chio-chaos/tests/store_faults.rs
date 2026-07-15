//! Real store-fault chaos scenarios against a live `SqliteReceiptStore`.
//!
//! Each scenario injects a genuine fault (a page-count exhaustion, a competing
//! writer holding the write lock, retention maintenance racing appends) and
//! asserts the store denies fail-closed with a typed error and then recovers.
//! Every scenario carries the InjectionNoOp discipline: if the fault provably
//! never took effect, the scenario fails with [`ChaosError::InjectionNoOp`]
//! rather than passing vacuously.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chio_chaos::{ack_line, chaos_receipt, check_durable_acks, wait_until_healthy, ChaosError};
use chio_kernel::ReceiptStoreError;
use chio_store_sqlite::{SqlitePoolConfig, SqliteReceiptStore};

/// Map any `Display` error into a boot failure with context.
fn boot<E: std::fmt::Display>(context: &str) -> impl Fn(E) -> ChaosError + '_ {
    move |error| ChaosError::Boot(format!("{context}: {error}"))
}

/// Map any `Display` error into an invariant violation with context.
fn invariant<E: std::fmt::Display>(context: &str) -> impl Fn(E) -> ChaosError + '_ {
    move |error| ChaosError::InvariantViolated(format!("{context}: {error}"))
}

/// A store growth cap expressed as construction options.
fn capped(max_page_count: u32) -> SqlitePoolConfig {
    SqlitePoolConfig {
        max_page_count: Some(max_page_count),
        ..SqlitePoolConfig::default()
    }
}

/// The live logical page count of the database, read through an independent
/// connection so the cap can be pinned just above the current size.
fn page_count(db: &Path) -> Result<i64, ChaosError> {
    let connection = rusqlite::Connection::open(db).map_err(boot("open db to measure pages"))?;
    connection
        .query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(boot("read page_count"))
}

/// Assert an error is the typed SQLITE_FULL surface: `ReceiptStoreError::Sqlite`
/// whose sqlite error code is `DiskFull`. Asserts on the variant and code, not a
/// string match.
fn expect_disk_full(error: &ReceiptStoreError, context: &str) -> Result<(), ChaosError> {
    match error {
        ReceiptStoreError::Sqlite(sqlite_error)
            if sqlite_error.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull) =>
        {
            Ok(())
        }
        other => Err(ChaosError::InvariantViolated(format!(
            "{context}: expected a typed SQLITE_FULL (ReceiptStoreError::Sqlite / DiskFull), got {other:?}"
        ))),
    }
}

/// Append a receipt, flush as the durability barrier, and only then record its
/// `ack <seq>` line. Mirrors the crash victim's contract: a recorded ack means
/// the store promised the receipt was durable.
fn append_flush_ack(
    store: &SqliteReceiptStore,
    ack_file: &mut std::fs::File,
    unique: &str,
    timestamp: u64,
) -> Result<(), ChaosError> {
    let receipt = chaos_receipt(unique, timestamp)?;
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .map_err(invariant("append pre-fault receipt"))?;
    store
        .flush_receipt_writes()
        .map_err(invariant("flush pre-fault receipt"))?;
    ack_file
        .write_all(ack_line(seq).as_bytes())
        .map_err(boot("write ack line"))?;
    ack_file.sync_data().map_err(boot("sync ack line"))?;
    Ok(())
}

/// ENOSPC: a store opened with a bounded page count rejects appends with a typed
/// full-database error once the cap is reached, keeps rejecting on the same
/// handle, and recovers when reopened with a larger cap without losing any
/// pre-fault durable ack.
#[test]
fn chaos_enospc_denies_typed_and_recovers() -> Result<(), ChaosError> {
    let dir = tempfile::tempdir().map_err(boot("tempdir"))?;
    let db = dir.path().join("enospc.db");
    let ack = dir.path().join("acks.log");

    // Phase A: baseline under the default config. Record durable acks for a set
    // of pre-fault receipts, then (after the store closes) measure the page
    // count so the cap can sit just above the schema-and-data floor.
    {
        let store = SqliteReceiptStore::open(&db).map_err(boot("open baseline store"))?;
        let mut ack_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ack)
            .map_err(boot("open ack file"))?;
        for i in 0..24u64 {
            append_flush_ack(&store, &mut ack_file, &format!("enospc-pre-{i}"), i + 1)?;
        }
    }
    let baseline_pages = page_count(&db)?;
    let cap = u32::try_from(baseline_pages).map_err(boot("page count to u32"))? + 48;

    // Phase B: reopen capped and append until the bound rejects a write.
    let mut fault: Option<ReceiptStoreError> = None;
    {
        let store = SqliteReceiptStore::open_with_pool_config(&db, capped(cap))
            .map_err(boot("reopen capped store"))?;
        let mut ack_file = OpenOptions::new()
            .append(true)
            .open(&ack)
            .map_err(boot("reopen ack file"))?;
        for i in 0..50_000u64 {
            let receipt = chaos_receipt(&format!("enospc-cap-{i}"), 1_000 + i)?;
            let seq = match store.append_chio_receipt_returning_seq(&receipt) {
                Ok(seq) => seq,
                Err(error) => {
                    fault = Some(error);
                    break;
                }
            };
            // Durability barrier before the ack: a flush that fails on the cap is
            // also a fault, and the receipt is left unacked (no durability
            // promise was made).
            if let Err(error) = store.flush_receipt_writes() {
                fault = Some(error);
                break;
            }
            ack_file
                .write_all(ack_line(seq).as_bytes())
                .map_err(boot("write under-cap ack"))?;
            ack_file.sync_data().map_err(boot("sync under-cap ack"))?;
        }

        // InjectionNoOp: the cap must have actually forced a rejection.
        let fault = match fault.as_ref() {
            Some(error) => error,
            None => {
                return Err(ChaosError::InjectionNoOp(
                    "bounded page count never rejected an append",
                ))
            }
        };
        // (a) The rejection is the typed SQLITE_FULL surface.
        expect_disk_full(fault, "initial full")?;
        // (b) Fail-closed persistence: the store keeps rejecting on the same
        // handle. Every subsequent append also denies with SQLITE_FULL.
        for i in 0..8u64 {
            let receipt = chaos_receipt(&format!("enospc-after-{i}"), 2_000 + i)?;
            match store.append_chio_receipt_returning_seq(&receipt) {
                Ok(seq) => {
                    return Err(ChaosError::InvariantViolated(format!(
                        "append returned seq {seq} after the store reported full; rejection did not persist"
                    )))
                }
                Err(error) => expect_disk_full(&error, "post-fault persistence")?,
            }
        }
    }

    // Phase C: reopen with a larger cap. Recovery must be clean: health OK,
    // appends succeed, and every pre-fault durable ack survives.
    {
        let store = SqliteReceiptStore::open_with_pool_config(&db, capped(cap.saturating_mul(8)))
            .map_err(boot("reopen recovered store"))?;
        wait_until_healthy(
            &store,
            "recovery health after reopen with a larger page cap",
        )?;
        check_durable_acks(&store, &ack)?;
        let receipt = chaos_receipt("enospc-recovered", 3_000_000)?;
        store
            .append_chio_receipt_returning_seq(&receipt)
            .map_err(invariant("append after recovery"))?;
    }

    Ok(())
}

/// Wedged writer: a competing raw connection holds `BEGIN IMMEDIATE`, so the
/// store's writer cannot acquire the write lock. The append must deny with a
/// typed busy error within a bounded time (never hang, never silently succeed),
/// and appends must recover once the wedge is released.
#[test]
fn chaos_wedged_writer_yields_typed_busy_deny() -> Result<(), ChaosError> {
    let dir = tempfile::tempdir().map_err(boot("tempdir"))?;
    let db = dir.path().join("wedged.db");
    let store = Arc::new(SqliteReceiptStore::open(&db).map_err(boot("open store"))?);

    // Seed one receipt so the writer head is verified before the wedge lands.
    let seed = chaos_receipt("wedged-seed", 1)?;
    store
        .append_chio_receipt_returning_seq(&seed)
        .map_err(invariant("seed append"))?;
    store
        .flush_receipt_writes()
        .map_err(invariant("seed flush"))?;

    // The wedge: a raw connection takes the WAL write lock with BEGIN IMMEDIATE.
    // Its own busy_timeout is 0 so it never yields; the store's writer must
    // contend for the lock the wedge holds.
    let wedge = rusqlite::Connection::open(&db).map_err(boot("open wedge connection"))?;
    wedge
        .pragma_update(None, "busy_timeout", 0i64)
        .map_err(boot("set wedge busy_timeout"))?;
    wedge
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(boot("acquire wedge write lock"))?;

    // The store's busy_timeout is 5000ms (bootstrap/open.rs
    // configure_sqlite_connection), so the contended append returns after about
    // that long. A generous watchdog well above it turns a genuine hang into a
    // failure rather than wedging CI.
    let watchdog = Duration::from_secs(30);
    let append_store = Arc::clone(&store);
    let receipt = chaos_receipt("wedged-blocked", 2)?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let start = Instant::now();
    std::thread::spawn(move || {
        let _ = sender.send(append_store.append_chio_receipt_returning_seq(&receipt));
    });
    let result = match receiver.recv_timeout(watchdog) {
        Ok(result) => result,
        Err(_) => {
            return Err(ChaosError::InjectionNoOp(
                "store append neither returned nor was bounded by busy_timeout while the writer was wedged",
            ))
        }
    };
    let elapsed = start.elapsed();

    match result {
        Ok(seq) => {
            return Err(ChaosError::InvariantViolated(format!(
                "append returned seq {seq} while a competing writer held BEGIN IMMEDIATE"
            )))
        }
        Err(ReceiptStoreError::Sqlite(sqlite_error))
            if sqlite_error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) => {}
        Err(other) => {
            return Err(ChaosError::InvariantViolated(format!(
                "expected a typed SQLITE_BUSY deny, got {other:?}"
            )))
        }
    }
    // A near-instant failure would mean the writer never actually contended on
    // the lock: the deny must have waited on the busy_timeout backoff.
    if elapsed < Duration::from_millis(500) {
        return Err(ChaosError::InjectionNoOp(
            "append failed too quickly to have contended on the wedged write lock",
        ));
    }

    // Release the wedge and recover. The busy failure is a top-level batch fault
    // that poisons the verified head, so recovery runs the store's documented
    // repair path (chio receipt audit --repair) before appends resume.
    drop(wedge);
    store
        .reseed_verified_head()
        .map_err(invariant("reseed head after wedge released"))?;
    let recovered = chaos_receipt("wedged-recovered", 3)?;
    store
        .append_chio_receipt_returning_seq(&recovered)
        .map_err(invariant("append after wedge released"))?;

    Ok(())
}

/// Retention under load: a thread appends continuously while the main thread
/// runs `retention_repair` mid-stream. Afterward the store must be healthy, its
/// committed floor must not have regressed, and a fresh append must succeed.
#[test]
fn chaos_retention_under_load_keeps_verified_head() -> Result<(), ChaosError> {
    let dir = tempfile::tempdir().map_err(boot("tempdir"))?;
    let db = dir.path().join("retention.db");
    let archive = dir.path().join("archive.db");
    let store = Arc::new(SqliteReceiptStore::open(&db).map_err(boot("open store"))?);

    // Seed a committed prefix to snapshot the floor against.
    for i in 0..16u64 {
        let receipt = chaos_receipt(&format!("retention-seed-{i}"), i + 1)?;
        store
            .append_chio_receipt_returning_seq(&receipt)
            .map_err(invariant("seed append"))?;
    }
    store
        .flush_receipt_writes()
        .map_err(invariant("seed flush"))?;
    let seq_before = store
        .latest_committed_entry_seq()
        .map_err(invariant("read committed floor before retention"))?;

    // A thread appends continuously until told to stop.
    let stop = Arc::new(AtomicBool::new(false));
    let appended = Arc::new(AtomicU64::new(0));
    let worker_store = Arc::clone(&store);
    let worker_stop = Arc::clone(&stop);
    let worker_appended = Arc::clone(&appended);
    let worker = std::thread::spawn(move || -> Result<(), ChaosError> {
        let mut i = 0u64;
        while !worker_stop.load(Ordering::Relaxed) {
            let receipt = chaos_receipt(&format!("retention-load-{i}"), 100_000 + i)?;
            worker_store
                .append_chio_receipt_returning_seq(&receipt)
                .map_err(invariant("concurrent append during retention load"))?;
            worker_appended.fetch_add(1, Ordering::Relaxed);
            i += 1;
        }
        Ok(())
    });

    // Run retention_repair repeatedly mid-load. A healthy store has no orphaned
    // claim-log row, so each call is a serialized maintenance command that
    // interleaves with the append stream through the single writer actor.
    let archive_path = archive
        .to_str()
        .ok_or_else(|| ChaosError::Boot("archive path is not valid UTF-8".to_string()))?;
    for _ in 0..16 {
        store
            .retention_repair(archive_path)
            .map_err(invariant("retention_repair under load"))?;
        std::thread::sleep(Duration::from_millis(2));
    }

    stop.store(true, Ordering::Relaxed);
    worker
        .join()
        .map_err(|_| ChaosError::Victim("retention load thread panicked".to_string()))??;

    // InjectionNoOp: the load thread must actually have appended across the
    // retention calls, or the race was never exercised.
    let appended = appended.load(Ordering::Relaxed);
    if appended == 0 {
        return Err(ChaosError::InjectionNoOp(
            "no receipts were appended during the retention load window",
        ));
    }

    // Invariants: health OK, committed floor monotone, fresh append works.
    wait_until_healthy(&store, "store health after retention under load")?;
    let seq_after = store
        .latest_committed_entry_seq()
        .map_err(invariant("read committed floor after retention"))?;
    if seq_after < seq_before {
        return Err(ChaosError::InvariantViolated(format!(
            "latest_committed_entry_seq regressed under retention load: {seq_before} -> {seq_after}"
        )));
    }
    let receipt = chaos_receipt("retention-final", 200_000_000)?;
    store
        .append_chio_receipt_returning_seq(&receipt)
        .map_err(invariant("append after retention load"))?;

    Ok(())
}
