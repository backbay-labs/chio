use super::super::*;
use super::support::*;
use chio_kernel::ReceiptStore;

#[test]
fn receipt_commit_actor_channel_has_fixed_capacity() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _receiver) = receipt_commit_channel();
    for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
        let (response, _result) = mpsc::sync_channel(1);
        sender.try_send(ReceiptCommitCommand::Flush(response))?;
    }

    let (response, _result) = mpsc::sync_channel(1);
    match sender.try_send(ReceiptCommitCommand::Flush(response)) {
        Err(mpsc::TrySendError::Full(_)) => Ok(()),
        Err(mpsc::TrySendError::Disconnected(_)) => {
            Err("commit actor channel disconnected unexpectedly".into())
        }
        Ok(()) => Err("commit actor channel accepted beyond fixed capacity".into()),
    }
}

#[test]
fn receipt_commit_actor_append_fails_closed_when_queue_is_full(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _receiver) = receipt_commit_channel();
    let health = Arc::new(ReceiptCommitWriterHealth::default());
    for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
        let (response, _result) = mpsc::sync_channel(1);
        sender.try_send(ReceiptCommitCommand::Flush(response))?;
    }
    let actor = ReceiptCommitActor {
        sender,
        health,
        worker: Arc::new(ReceiptCommitWorker { join: None }),
    };

    let receipt = sample_receipt_with_id("rcpt-actor-queue-full");
    let error = actor.append(receipt, "{}".to_string(), false);

    assert!(error
        .err()
        .ok_or("expected queue saturation error")?
        .to_string()
        .contains("sqlite receipt commit queue saturated"));
    Ok(())
}

#[test]
fn writer_handle_keeps_actor_alive_until_last_owner_drops() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-writer-drop");
    let wal_path = std::path::PathBuf::from(format!("{}-wal", path.display()));
    let shm_path = std::path::PathBuf::from(format!("{}-shm", path.display()));

    let writer = {
        let store = SqliteReceiptStore::open(&path)?;
        store.append_chio_receipt_returning_seq(&sample_receipt())?;
        store.writer_handle()
    };

    writer.run_write(|connection| {
        connection.execute_batch("CREATE TABLE actor_lifetime_probe (id INTEGER PRIMARY KEY)")?;
        Ok(())
    })?;
    drop(writer);

    assert!(!wal_path.exists());
    assert!(!shm_path.exists());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn last_owner_drop_drains_queued_append() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-writer-drain");
    let store = SqliteReceiptStore::open(&path)?;
    let blocker = store.writer_handle();
    let queued = store.writer_handle();
    let (started_tx, started_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);

    let blocked = thread::spawn(move || {
        blocker.run_write(move |_| {
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
    });
    started_rx.recv()?;

    let receipt = sample_receipt_with_id("rcpt-drain-on-last-owner-drop");
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, result) = mpsc::sync_channel(1);
    queued
        .sender
        .try_send(ReceiptCommitCommand::Append(Box::new(
            ReceiptCommitRequest {
                receipt,
                raw_json,
                ensure_lineage: false,
                response,
            },
        )))?;

    drop(queued);
    drop(store);
    release_tx.send(())?;
    blocked
        .join()
        .map_err(|_| "blocking writer thread panicked")??;
    assert_eq!(result.recv()??, 1);

    let reopened = SqliteReceiptStore::open(&path)?;
    assert_eq!(reopened.receipts_canonical_bytes_range(1, 1)?.len(), 1);
    drop(reopened);
    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn last_owner_drop_drains_commands_queued_behind_restart() -> Result<(), Box<dyn std::error::Error>>
{
    let (temp_dir, path) = temp_db("chio-writer-drain-restart")?;
    let store = SqliteReceiptStore::open(&path)?;
    let queued = store.writer_handle();
    queued
        .sender
        .try_send(ReceiptCommitCommand::RestartSupervisor)?;

    let receipt = sample_receipt_with_id("rcpt-drain-after-restart");
    let raw_json = serde_json::to_string(&receipt)?;
    let (response, result) = mpsc::sync_channel(1);
    queued
        .sender
        .try_send(ReceiptCommitCommand::Append(Box::new(
            ReceiptCommitRequest {
                receipt,
                raw_json,
                ensure_lineage: false,
                response,
            },
        )))?;

    drop(queued);
    drop(store);
    assert_eq!(result.recv()??, 1);

    let reopened = SqliteReceiptStore::open(&path)?;
    assert_eq!(reopened.receipts_canonical_bytes_range(1, 1)?.len(), 1);
    drop(reopened);
    temp_dir.close()?;
    Ok(())
}

/// A panic inside a Write-routed job (one of
/// the ~30 rerouted write families: lineage, liability, underwriting,
/// reconciliation, capability, federated, IOU, checkpoint, reseed) must not
/// take down the single writer thread for the rest of the process lifetime.
///
/// Two assertions:
///   (a) the panicking job's own caller gets a typed `Err`, not a hang;
///   (b) a SUBSEQUENT normal append on the SAME store still succeeds. This
///       is the teeth: without `catch_unwind` isolating the job, the writer
///       thread is dead here and every later append/write/flush observes
///       `Disconnected` -> `receipt_actor_unavailable_error()` forever (or,
///       if the caller happened to be blocked on `recv()` at the moment the
///       thread died mid-response, a hang).
#[test]
fn writer_job_panic_does_not_kill_the_actor() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-writer-job-panic")?;
    let store = SqliteReceiptStore::open(&path)?;

    let panic_result =
        store
            .writer_handle()
            .run_write(|_connection| -> Result<(), ReceiptStoreError> {
                panic!("injected test panic in writer job")
            });
    let error = match panic_result {
        Ok(()) => return Err("expected the panicking job to return Err, got Ok".into()),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("receipt writer job panicked"),
        "unexpected error message: {message}"
    );

    // Teeth: the writer thread survived. A normal Write-routed job still
    // reaches the (same) actor thread and completes.
    let _thread_id = store
        .writer_handle()
        .run_write(|_connection| Ok(std::thread::current().id()))?;

    // Teeth: a normal append still commits durably.
    let receipt = sample_receipt_with_id("rcpt-after-writer-job-panic");
    let seq = store.append_chio_receipt_returning_seq(&receipt)?;
    assert_eq!(
        seq, 1,
        "append after a caught writer-job panic must still commit"
    );

    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert_eq!(
        health.writer.inflight, 0,
        "inflight must drain to zero across the panicking job and the two jobs after it"
    );

    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// A panic inside `commit_receipt_batch` (the append path itself, not a
/// Write-routed job) is at least as serious as the store-wide append faults
/// that path already poisons on: the writer's durable position is now
/// unverifiable, so the head is poisoned and the pre-dispatch gate fails closed.
/// The writer thread itself survives (the panic is caught), so an operator
/// reseed recovers the store. Uses the `test_hooks::PANIC_DURING_APPEND_BATCH`
/// fault hook, which fires inside the per-request insert loop before the
/// interrupted request's transaction commits and before any response is sent,
/// exercising the `fan_out_batch_panic_error` path (the pre-cloned response
/// senders, not the normal `receipt_batch_error_results` fan-out).
///
/// This crate's tests run in parallel and the fault-hook flag is process-global,
/// so the hook is additionally gated on
/// `PANIC_DURING_APPEND_BATCH_MARKER_CONTENT_HASH`: only a request carrying that
/// exact `content_hash` can panic (not `receipt.id` -- `ChioReceipt::sign`
/// always overwrites `id` with a content-derived hash, so a caller-chosen id
/// string does not survive signing), so a concurrently running, unrelated append
/// test cannot be hit by this test's injected panic.
#[test]
fn append_batch_panic_poisons_the_head_and_fails_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let (temp_dir, path) = temp_db("chio-append-batch-panic")?;
    let store = SqliteReceiptStore::open(&path)?;

    test_hooks::PANIC_DURING_APPEND_BATCH.store(true, std::sync::atomic::Ordering::SeqCst);
    let receipt = sample_receipt_with_id(test_hooks::PANIC_DURING_APPEND_BATCH_MARKER_RECEIPT_ID);
    let panic_result = store.append_chio_receipt_returning_seq(&receipt);
    test_hooks::PANIC_DURING_APPEND_BATCH.store(false, std::sync::atomic::Ordering::SeqCst);

    let error = match panic_result {
        Ok(seq) => {
            return Err(
                format!("expected the panicking append to return Err, got seq {seq}").into(),
            )
        }
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("receipt writer job panicked"),
        "unexpected error message: {error}"
    );

    // Teeth: the caught panic poisoned the head, so the pre-dispatch gate reports
    // the writer is no longer serving and denies before another tool runs.
    assert!(
        store.writer_serving_closed(),
        "a caught append-batch panic must trip the serving-closed gate"
    );

    // The writer THREAD survived the caught panic (a dead thread would answer
    // Disconnected): the next append is rejected with the recoverable
    // poisoned-head Conflict, not an actor-unavailable error.
    match store
        .append_chio_receipt_returning_seq(&sample_receipt_with_id("rcpt-after-append-panic"))
    {
        Ok(seq) => {
            return Err(format!(
                "expected the poisoned head to reject the next append, got seq {seq}"
            )
            .into())
        }
        Err(rejected) => assert!(
            rejected
                .to_string()
                .contains("verified head is unavailable"),
            "expected a poisoned-head rejection, got: {rejected}"
        ),
    }

    // An operator reseed clears the poison; the interrupted append's transaction
    // rolled back cleanly, so the store resumes serving at seq 1.
    store.reseed_verified_head()?;
    assert!(
        !store.writer_serving_closed(),
        "reseed must clear the poisoned head"
    );
    let seq = store.append_chio_receipt_returning_seq(&sample_receipt_with_id(
        "rcpt-after-append-recovered",
    ))?;
    assert_eq!(
        seq, 1,
        "the panicking append's tx must have rolled back cleanly, leaving seq 1 free"
    );

    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn run_write_fails_closed_when_queue_is_full() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _receiver) = receipt_commit_channel();
    let health = Arc::new(ReceiptCommitWriterHealth::default());
    for _ in 0..RECEIPT_COMMIT_ACTOR_CHANNEL_CAPACITY {
        let (response, _result) = mpsc::sync_channel(1);
        sender.try_send(ReceiptCommitCommand::Flush(response))?;
    }
    let handle = WriterHandle {
        sender,
        health: Arc::clone(&health),
        worker: Arc::new(ReceiptCommitWorker { join: None }),
        settlement_store_binding: None,
    };

    let error = handle.run_write(|_connection| Ok(()));

    assert!(error
        .err()
        .ok_or("expected queue saturation error")?
        .to_string()
        .contains("sqlite receipt commit queue saturated"));
    assert_eq!(
        health.inflight.load(Ordering::SeqCst),
        0,
        "speculative inflight increment must be undone on saturation"
    );
    assert_eq!(health.saturated_total.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn disconnected_writer_routes_preserve_supervisor_context() -> Result<(), Box<dyn std::error::Error>>
{
    let (sender, receiver) = receipt_commit_channel();
    drop(receiver);
    let supervisor_health = HealthFlag::new(true);
    supervisor_health.record_failure("writer restart failed: disk full", 1, 1);
    let worker = Arc::new(ReceiptCommitWorker {
        join: Some(SupervisedReceiptWriter {
            supervisor: None,
            health: supervisor_health,
            thread_id: Arc::new(OnceLock::new()),
        }),
    });
    let health = Arc::new(ReceiptCommitWriterHealth::default());
    let writer = WriterHandle {
        sender: sender.clone(),
        health: Arc::clone(&health),
        worker: Arc::clone(&worker),
        settlement_store_binding: None,
    };
    let actor = ReceiptCommitActor {
        sender,
        health,
        worker,
    };

    let errors = [
        writer
            .run_write(|_| Ok(()))
            .err()
            .ok_or("disconnected writer handle must fail")?,
        actor
            .reseed_head()
            .err()
            .ok_or("disconnected reseed must fail")?,
        actor
            .install_signer(BackgroundCheckpointSigner {
                keypair: Arc::new(receipt_test_keypair()),
                max_batch: 1,
            })
            .err()
            .ok_or("disconnected signer install must fail")?,
    ];
    for error in errors {
        match error {
            ReceiptStoreError::WriterDead {
                restarts,
                last_error,
            } => {
                assert_eq!(restarts, 1);
                assert_eq!(last_error, "writer restart failed: disk full");
            }
            other => return Err(format!("expected WriterDead, got {other}").into()),
        }
    }
    Ok(())
}

#[test]
fn accepted_flush_samples_supervisor_failure_after_response_loss(
) -> Result<(), Box<dyn std::error::Error>> {
    let (sender, receiver) = receipt_commit_channel();
    let supervisor_health = HealthFlag::new(true);
    let receiver_health = supervisor_health.clone();
    let worker = Arc::new(ReceiptCommitWorker {
        join: Some(SupervisedReceiptWriter {
            supervisor: None,
            health: supervisor_health,
            thread_id: Arc::new(OnceLock::new()),
        }),
    });
    let actor = ReceiptCommitActor {
        sender,
        health: Arc::new(ReceiptCommitWriterHealth::default()),
        worker,
    };
    let receiver_thread = thread::spawn(move || -> Result<(), &'static str> {
        let command = receiver.recv().map_err(|_| "flush command was not sent")?;
        let ReceiptCommitCommand::Flush(response) = command else {
            return Err("expected flush command");
        };
        receiver_health.record_failure("writer failed after accepting flush", 1, 1);
        drop(response);
        Ok(())
    });

    let error = actor.flush().err().ok_or("accepted flush must fail")?;
    receiver_thread
        .join()
        .map_err(|_| "flush receiver thread panicked")??;
    match error {
        ReceiptStoreError::WriterDead {
            restarts,
            last_error,
        } => {
            assert_eq!(restarts, 1);
            assert_eq!(last_error, "writer failed after accepting flush");
        }
        other => return Err(format!("expected WriterDead, got {other}").into()),
    }
    Ok(())
}

/// {Append, Write, Flush} from many threads: every Write closure executes on
/// exactly one thread (single-writer serialization), all appends commit, and
/// inflight accounting drains to zero (no lost pre-send increments).
#[test]
fn writer_commands_serialize_and_never_lose_inflight_accounting(
) -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-single-writer-stress")?;
    let store = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);

    // `std::thread::ThreadId` implements `Hash + Eq` but not `Ord`, so a
    // `HashSet` (not `BTreeSet`) tracks the distinct writer thread here.
    let writer_threads: std::sync::Arc<Mutex<std::collections::HashSet<std::thread::ThreadId>>> =
        std::sync::Arc::new(Mutex::new(std::collections::HashSet::new()));
    let mut handles = Vec::new();

    for worker in 0..4u32 {
        let store = std::sync::Arc::clone(&store);
        let writer_threads = std::sync::Arc::clone(&writer_threads);
        handles.push(thread::spawn(move || -> Result<(), String> {
            for i in 0..25u32 {
                match i % 3 {
                    0 => {
                        let receipt = sample_receipt_with_id(&format!("rcpt-stress-{worker}-{i}"));
                        ReceiptStore::append_chio_receipt_returning_seq(store.as_ref(), &receipt)
                            .map_err(|error| error.to_string())?;
                    }
                    1 => {
                        let observed = store
                            .writer_handle()
                            .run_write(|_connection| Ok(std::thread::current().id()))
                            .map_err(|error| error.to_string())?;
                        writer_threads
                            .lock()
                            .map_err(|_| "writer thread set poisoned".to_string())?
                            .insert(observed);
                    }
                    _ => {
                        store
                            .flush_receipt_writes()
                            .map_err(|error| error.to_string())?;
                    }
                }
            }
            Ok(())
        }));
    }
    for handle in handles {
        handle
            .join()
            .map_err(|_| "stress worker panicked")?
            .map_err(std::io::Error::other)?;
    }

    // Single-writer serialization: every Write job ran on one thread.
    let distinct = writer_threads
        .lock()
        .map_err(|_| "writer thread set poisoned")?
        .len();
    assert_eq!(
        distinct, 1,
        "expected exactly one writer thread, got {distinct}"
    );

    // Quiesce, then check the books: nothing in flight, all appends counted.
    store.flush_receipt_writes()?;
    let health = store.receipt_store_health()?;
    assert_eq!(health.writer.inflight, 0, "inflight must drain to zero");
    // committed_total reconciles BOTH commit paths: the Append path (i % 3 == 0
    // on 9 of 25 iterations per worker) AND the writer-routed `run_write` path
    // (i % 3 == 1 on 8 of 25 iterations per worker), whose successful outcome is
    // folded into committed_total. Flushes (i % 3 == 2) are not commits.
    assert_eq!(health.writer.committed_total, 4 * 9 + 4 * 8);
    assert_eq!(health.writer.failed_total, 0);
    // Only the Append path inserts claim-log entries; the run_write closures
    // return a thread id without writing, so the log length tracks appends only.
    assert_eq!(health.latest_committed_entry_seq, 4 * 9);

    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// Force every pooled reader connection into `PRAGMA query_only = ON`, then
/// exercise the routed write surface: all writes must still succeed (they run
/// on the writer connection), while a direct write through the reader pool
/// must fail. r2d2 creates connections lazily up to max_size, so grabbing all
/// DEFAULT_READER_POOL_MAX_SIZE connections at once pins the whole pool.
#[test]
fn reader_pool_never_begins_a_write_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-reader-pool-readonly")?;
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    {
        let mut held = Vec::new();
        for _ in 0..crate::DEFAULT_READER_POOL_MAX_SIZE {
            held.push(store.connection()?);
        }
        for connection in &held {
            connection.execute_batch("PRAGMA query_only = ON;")?;
        }
    }

    // Control: the reader pool now refuses writes.
    {
        let connection = store.connection()?;
        let denied = connection.execute("CREATE TABLE reader_probe (x INTEGER)", []);
        assert!(denied.is_err(), "reader pool accepted a write");
    }

    // The routed write surface still works end to end.
    let receipt = sample_receipt_with_keypair("rcpt-ro-pool-0", 1, &keypair);
    ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt)?.ok_or("expected seq")?;
    let child = sample_child_receipt_with_keypair_and_timestamp("child-ro-pool-0", 2, &keypair);
    store.append_child_receipt_record(&child)?;
    store.record_session_anchor_record(
        "sess-ro",
        "anchor-ro",
        "fp-ro",
        3,
        None,
        &serde_json::json!({"anchor": "ro"}),
    )?;
    // `record_request_lineage_record` validates `lineage_json` against
    // `chio_core::session::RequestLineageRecord` (requires a `schema` field
    // among others), unlike `record_session_anchor_record`'s unvalidated
    // passthrough JSON above; `request_lineage_json` builds a
    // schema-compliant payload.
    store.record_request_lineage_record(
        "sess-ro",
        "req-ro",
        None,
        Some("anchor-ro"),
        4,
        None,
        &request_lineage_json("req-ro", "anchor-ro", None),
    )?;
    let _links = store.list_receipt_lineage_statement_links("rcpt-ro-pool-0")?;
    let _verification = store.receipt_lineage_verification("rcpt-ro-pool-0")?;
    store.create_next_receipt_checkpoint(2, &keypair)?;

    let iou_store = crate::SqliteIouEnvelopeStore::open_alongside(&store)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    drop(iou_store); // migration DDL ran on the writer; construction succeeding is the assertion

    drop(store);
    temp_dir.close()?;
    Ok(())
}

#[test]
fn writer_health_starts_with_a_poisoned_head_until_seeding_clears_it() {
    // The commit writer seeds its verified head asynchronously on the actor
    // thread. Until that seed succeeds, durable persistence is unproven, so a
    // freshly constructed health mirror must report a poisoned head. Starting
    // open would let a corrupt or still-attaching store pass
    // `writer_serving_closed` and execute a tool before its first append can
    // reject, which is exactly the fail-open window the pre-dispatch gate
    // exists to prevent.
    let health = ReceiptCommitWriterHealth::default();
    assert!(
        health.head_poisoned.load(Ordering::SeqCst),
        "writer health must start head-poisoned (serving closed) until a seeded head clears it"
    );
}

#[test]
fn receipt_commit_actor_flush_honors_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let (sender, _receiver) = receipt_commit_channel();
    let health = Arc::new(ReceiptCommitWriterHealth::default());
    let actor = ReceiptCommitActor {
        sender,
        health,
        worker: Arc::new(ReceiptCommitWorker { join: None }),
    };

    let error = actor.flush_with_timeout(Duration::from_millis(1));

    match error.err().ok_or("expected flush timeout error")? {
        ReceiptStoreError::Timeout {
            operation,
            timeout_ms,
        } => {
            assert_eq!(operation, "sqlite receipt commit flush");
            assert_eq!(timeout_ms, 1);
        }
        other => {
            return Err(
                std::io::Error::other(format!("expected timeout error, got {other}")).into(),
            );
        }
    }
    Ok(())
}

#[test]
fn run_write_executes_jobs_serially_on_the_writer_thread() -> Result<(), Box<dyn std::error::Error>>
{
    let (temp_dir, path) = temp_db("chio-run-write")?;
    let store = SqliteReceiptStore::open(&path)?;
    let writer = store.writer_handle();

    let first_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;
    let second_thread = writer.run_write(|_connection| Ok(std::thread::current().id()))?;

    assert_eq!(
        first_thread, second_thread,
        "all write jobs must run on the single writer thread"
    );
    assert_ne!(
        first_thread,
        std::thread::current().id(),
        "write jobs must not run on the caller thread"
    );

    // The closure really gets a usable writer connection.
    let journal_mode = writer.run_write(|connection| {
        connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .map_err(ReceiptStoreError::from)
    })?;
    assert!(journal_mode.eq_ignore_ascii_case("wal"));

    // Inflight accounting drains back to zero after the jobs complete.
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(Ordering::SeqCst),
        0
    );

    drop(writer);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// A writer-routed `Write` job (liability write, manual checkpoint creation)
/// must keep `writer_inflight` nonzero for the DURATION of the job, not just
/// at enqueue, so a health poll during a slow or stuck Write does not report
/// `inflight: 0` and hide active writer work. The `WriterInflightGuard`
/// holds the count until the job completes, mirroring the Append path.
#[test]
fn write_job_holds_inflight_for_its_duration() -> Result<(), Box<dyn std::error::Error>> {
    let (temp_dir, path) = temp_db("chio-write-inflight")?;
    let store = SqliteReceiptStore::open(&path)?;
    let writer = store.writer_handle();

    // Drain any open-time writer activity to a known baseline before running
    // the coordinated job.
    let drained_baseline = wait_until(|| {
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(Ordering::SeqCst)
            == 0
    });
    assert!(drained_baseline, "writer failed to drain to baseline");

    // Coordinate a Write job that blocks inside its closure until released.
    let (started_tx, started_rx) = mpsc::sync_channel::<()>(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let worker = std::thread::spawn(move || {
        writer.run_write(move |_connection| {
            // Signal that the job is now executing on the writer thread, then
            // block until the test releases it.
            let _ = started_tx.send(());
            let _ = release_rx.recv();
            Ok(())
        })
    });

    // The job is running: inflight must be nonzero for the DURATION of the
    // Write, not merely at enqueue.
    started_rx.recv().map_err(|_| "write job never started")?;
    assert_eq!(
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(Ordering::SeqCst),
        1,
        "a running Write job must report inflight > 0"
    );

    // Release the job and confirm inflight drains back to baseline. The
    // `WriterInflightGuard` decrements just BEFORE the caller's response is
    // delivered, so this is already at baseline once the worker join
    // returns; poll defensively regardless.
    release_tx.send(())?;
    worker
        .join()
        .map_err(|_| "write worker thread panicked")??;
    let drained = wait_until(|| {
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(Ordering::SeqCst)
            == 0
    });
    assert!(
        drained,
        "inflight must return to baseline after the Write completes"
    );

    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// The `WriterInflightGuard` decrement must be SYNCHRONOUS with
/// caller-return: the guard drops IMMEDIATELY BEFORE each `respond(...)`,
/// matching the Append path's decrement-then-fan-out ordering
/// (`commit_receipt_batch`), so caller-return implies the decrement already
/// happened. If the guard instead dropped at the END of the Write arm (after
/// `respond(...)` unblocked `run_write`), a caller could return while
/// `inflight` was still counted, the exact window that would make
/// `run_write_executes_jobs_serially_on_the_writer_thread` intermittently
/// observe `inflight == 1`. This asserts the guarantee DIRECTLY and
/// deterministically (no `wait_until`): right after `run_write` returns,
/// `inflight` reads 0 on every one of many iterations.
#[test]
fn write_decrements_inflight_before_returning_to_caller() -> Result<(), Box<dyn std::error::Error>>
{
    let (temp_dir, path) = temp_db("chio-write-inflight-order")?;
    let store = SqliteReceiptStore::open(&path)?;
    let writer = store.writer_handle();

    // Drain any open-time writer activity to a known baseline first.
    let drained_baseline = wait_until(|| {
        store
            .receipt_commit_actor
            .health
            .inflight
            .load(Ordering::SeqCst)
            == 0
    });
    assert!(drained_baseline, "writer failed to drain to baseline");

    // Many iterations to expose the ordering race: if the guard dropped
    // AFTER the response reached the caller (while the writer thread still
    // had the head snapshot, error clear, connection drop and catch-up build
    // to run), this load could intermittently observe 1. Because the
    // decrement precedes the response, caller-return happens-before this
    // load and it must read 0 on EVERY iteration with no polling.
    for iteration in 0..512 {
        writer.run_write(|_connection| Ok(()))?;
        let observed = store
            .receipt_commit_actor
            .health
            .inflight
            .load(Ordering::SeqCst);
        assert_eq!(
            observed, 0,
            "caller returned from run_write with inflight still counted \
             (iteration {iteration}); the decrement must precede the response"
        );
    }

    drop(writer);
    drop(store);
    temp_dir.close()?;
    Ok(())
}

/// Poll `predicate` for up to ~1s (1ms steps), returning whether it held.
fn wait_until(predicate: impl Fn() -> bool) -> bool {
    for _ in 0..1_000 {
        if predicate() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    predicate()
}
