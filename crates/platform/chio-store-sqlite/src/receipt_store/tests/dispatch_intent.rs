//! Dispatch-intent journal tests: schema creation, durable insert/consume,
//! boot reconciliation, and the health surface.

use crate::SqliteReceiptStore;

use super::support::unique_db_path;

fn sample_intent(request_id: &str) -> chio_kernel::receipt_store::DispatchIntentRecord {
    use chio_kernel::receipt_store::{DispatchIntentRecord, SideEffectClass};
    DispatchIntentRecord {
        request_id: request_id.to_string(),
        capability_id: "cap-abc".to_string(),
        tool_server: "srv".to_string(),
        tool_name: "write_file".to_string(),
        parameter_hash: "ph-123".to_string(),
        side_effect_class: SideEffectClass::SideEffecting,
        monetary: false,
        rail: None,
        rail_authorization_id: None,
        tenant_id: None,
        created_at_unix_ms: 42,
    }
}

fn open_intent_row_count(store: &SqliteReceiptStore) -> Result<i64, Box<dyn std::error::Error>> {
    let connection = store.reader_connection_for_test()?;
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'open'",
        [],
        |row| row.get(0),
    )?;
    Ok(count)
}

#[test]
fn record_dispatch_intent_inserts_and_rejects_duplicate() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-intents-insert");
    let store = SqliteReceiptStore::open(&path)?;

    store.record_dispatch_intent(&sample_intent("req-A"))?;
    assert_eq!(open_intent_row_count(&store)?, 1);

    // A second write reusing the request id is rejected fail-closed rather
    // than duplicating an effect record.
    let duplicate = store.record_dispatch_intent(&sample_intent("req-A"));
    let message = duplicate
        .err()
        .ok_or("expected duplicate request_id to be rejected")?
        .to_string();
    assert!(
        message.contains("dispatch intent"),
        "unexpected error: {message}"
    );
    assert_eq!(open_intent_row_count(&store)?, 1);

    // The bounded variant commits durably within budget on a live writer.
    store.record_dispatch_intent_with_timeout(
        &sample_intent("req-B"),
        std::time::Duration::from_secs(5),
    )?;
    assert_eq!(open_intent_row_count(&store)?, 2);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn record_dispatch_intent_rejects_an_empty_string_tenant_id(
) -> Result<(), Box<dyn std::error::Error>> {
    // The unique index folds a NULL tenant to '' so tenantless rows still
    // conflict with each other. An explicit "" tenant would fold to the same
    // value and collide with tenantless rows it does not belong to; this
    // must be an explicit, named rejection rather than a bare unique-index
    // conflict the caller has to puzzle out.
    let path = unique_db_path("chio-intents-empty-tenant");
    let store = SqliteReceiptStore::open(&path)?;

    let mut intent = sample_intent("req-empty-tenant");
    intent.tenant_id = Some(String::new());
    let result = store.record_dispatch_intent(&intent);
    let error = result
        .err()
        .ok_or("an empty-string tenant id must be rejected")?;
    assert!(
        matches!(
            error,
            chio_kernel::receipt_store::ReceiptStoreError::Conflict(_)
        ),
        "expected Conflict, got {error:?}"
    );
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a rejected insert must not leave a row behind"
    );

    // A genuinely tenantless intent (None) still journals normally.
    store.record_dispatch_intent(&sample_intent("req-empty-tenant"))?;
    assert_eq!(open_intent_row_count(&store)?, 1);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn attach_rail_ref_updates_open_intent_and_notfound_when_absent(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-attach");
    let store = SqliteReceiptStore::open(&path)?;
    store.record_dispatch_intent(&sample_intent("req-M"))?;

    store.attach_dispatch_intent_rail_ref("req-M", None, "auth-xyz")?;
    let connection = store.reader_connection_for_test()?;
    let attached: String = connection.query_row(
        "SELECT rail_authorization_id FROM chio_dispatch_intents WHERE request_id = 'req-M'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(attached, "auth-xyz");

    // Attaching to a non-existent intent reports NotFound; the best-effort
    // caller logs and continues.
    let missing = store.attach_dispatch_intent_rail_ref("req-absent", None, "auth-1");
    assert!(missing.is_err());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn same_request_id_journals_independently_across_tenants() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-intents-tenant-scope");
    let store = SqliteReceiptStore::open(&path)?;

    let mut tenant_a = sample_intent("req-shared");
    tenant_a.tenant_id = Some("tenant-a".to_string());
    let mut tenant_b = sample_intent("req-shared");
    tenant_b.tenant_id = Some("tenant-b".to_string());

    // Request ids are caller-supplied and only unique within a tenant: one
    // tenant's open intent must not deny an unrelated tenant's request that
    // reuses the id.
    store.record_dispatch_intent(&tenant_a)?;
    store.record_dispatch_intent(&tenant_b)?;
    assert_eq!(open_intent_row_count(&store)?, 2);

    // Within one tenant the id still journals exactly once.
    let same_tenant = store.record_dispatch_intent(&tenant_a);
    assert!(same_tenant.is_err(), "same-tenant duplicate must conflict");

    // Tenantless rows conflict with each other too: the unique index folds
    // a NULL tenant to '', where a plain UNIQUE constraint would admit
    // duplicate NULLs.
    store.record_dispatch_intent(&sample_intent("req-tenantless"))?;
    let no_tenant = store.record_dispatch_intent(&sample_intent("req-tenantless"));
    assert!(no_tenant.is_err(), "no-tenant duplicate must conflict");

    // The rail-ref attach is keyed to its own tenant's row and never
    // annotates the other tenant's row sharing the request id.
    store.attach_dispatch_intent_rail_ref("req-shared", Some("tenant-a"), "auth-a")?;
    let connection = store.reader_connection_for_test()?;
    let mut statement = connection.prepare(
        "SELECT tenant_id, rail_authorization_id FROM chio_dispatch_intents \
         WHERE request_id = 'req-shared' ORDER BY tenant_id",
    )?;
    let rows: Vec<(Option<String>, Option<String>)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(
        rows,
        vec![
            (Some("tenant-a".to_string()), Some("auth-a".to_string())),
            (Some("tenant-b".to_string()), None),
        ],
        "the attach lands on exactly its tenant's row"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn journal_durability_follows_the_database_backing() -> Result<(), Box<dyn std::error::Error>> {
    // A file-backed database commits intent rows through WAL with
    // synchronous FULL, so the journal outlives the process and the store
    // claims crash durability to the kernel's dispatch gate.
    let path = unique_db_path("chio-intents-durability");
    let file_backed = SqliteReceiptStore::open(&path)?;
    assert!(
        file_backed.supports_durable_dispatch_intent_journal(),
        "a file-backed store keeps journal rows across a crash"
    );
    drop(file_backed);
    let _ = std::fs::remove_file(&path);

    // An in-memory database never gets far enough to make the claim: the
    // durability pragmas require WAL, which in-memory SQLite cannot
    // provide, so the open itself is refused and a volatile receipt store
    // never comes into existence.
    let in_memory =
        SqliteReceiptStore::open("file:chio-intents-durability-mem?mode=memory&cache=shared");
    assert!(
        in_memory.is_err(),
        "an in-memory receipt store must be refused at open"
    );
    Ok(())
}

#[test]
fn consume_intent_removes_row_and_persists_receipt_atomically(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::receipt_store::{DispatchIntentKey, ReceiptStore};

    let path = unique_db_path("chio-intents-consume");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = super::support::sample_receipt_with_keypair("consume-ok", 1, &keypair);
    let mut intent = sample_intent("req-C");
    intent.capability_id = receipt.capability_id.clone();
    intent.tool_server = receipt.tool_server.clone();
    intent.tool_name = receipt.tool_name.clone();
    intent.parameter_hash = receipt.action.parameter_hash.clone();
    intent.tenant_id = receipt.tenant_id.clone();
    store.record_dispatch_intent(&intent)?;

    let key = DispatchIntentKey {
        request_id: "req-C".to_string(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        tenant_id: receipt.tenant_id.clone(),
    };
    let seq = store.append_chio_receipt_consuming_intent(&receipt, &key)?;
    assert!(seq.is_some(), "receipt persisted, returns its entry seq");
    store.flush_receipt_writes()?;

    // Intent gone, receipt present: the two shared one commit.
    assert_eq!(open_intent_row_count(&store)?, 0);
    assert!(store.load_chio_receipt(&receipt.id)?.is_some());

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn consume_intent_parameter_hash_mismatch_aborts_and_keeps_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    use chio_kernel::receipt_store::{DispatchIntentKey, ReceiptStore};

    let path = unique_db_path("chio-intents-consume-mismatch");
    let keypair = super::support::receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = super::support::sample_receipt_with_keypair("consume-bad", 1, &keypair);

    // A key whose parameter_hash disagrees with the receipt is rejected before
    // any write reaches the transaction.
    let mut intent = sample_intent("req-X");
    intent.parameter_hash = receipt.action.parameter_hash.clone();
    intent.tenant_id = receipt.tenant_id.clone();
    store.record_dispatch_intent(&intent)?;
    let disagreeing_key = DispatchIntentKey {
        request_id: "req-X".to_string(),
        parameter_hash: "wrong-hash".to_string(),
        tenant_id: receipt.tenant_id.clone(),
    };
    assert!(store
        .append_chio_receipt_consuming_intent(&receipt, &disagreeing_key)
        .is_err());

    // A key that matches the receipt but not the STORED intent row (the intent
    // was journaled for different parameters) must abort the whole
    // transaction: the receipt must not persist and the intent must stay open.
    let mut stale_intent = sample_intent("req-Y");
    stale_intent.parameter_hash = "journaled-for-other-parameters".to_string();
    store.record_dispatch_intent(&stale_intent)?;
    let key_for_y = DispatchIntentKey {
        request_id: "req-Y".to_string(),
        parameter_hash: receipt.action.parameter_hash.clone(),
        tenant_id: receipt.tenant_id.clone(),
    };
    let result = store.append_chio_receipt_consuming_intent(&receipt, &key_for_y);
    assert!(result.is_err(), "stored-intent mismatch must abort");
    store.flush_receipt_writes()?;

    assert_eq!(
        open_intent_row_count(&store)?,
        2,
        "both intents remain open after the aborted consumes"
    );
    assert!(
        store.load_chio_receipt(&receipt.id)?.is_none(),
        "receipt must not persist when the consume aborts"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn timed_out_intent_write_does_not_land_after_the_writer_drains(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-timeout-abandon");
    let store = SqliteReceiptStore::open(&path)?;

    // Occupy the single writer with a job that parks until released, so the
    // bounded intent write below times out while its own job is still queued
    // behind it.
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let error = store.record_dispatch_intent_with_timeout(
        &sample_intent("req-timeout-abandon"),
        std::time::Duration::from_millis(100),
    );
    assert!(
        matches!(
            error,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "the bounded intent write must fail closed on a stalled writer"
    );

    // Unblock the writer and drain the queue past the abandoned job.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;

    // The caller already denied before dispatch, so the queued insert must
    // not land afterwards: a row here would dead-letter at the next boot as
    // a false orphan for a call that never executed.
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a timed-out intent write must not land after the caller denied"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn timeout_deny_returns_within_one_budget_on_a_stalled_writer(
) -> Result<(), Box<dyn std::error::Error>> {
    // The bounded intent write exists to cap the pre-dispatch wall-clock: a
    // stalled writer must fail the caller closed after ONE budget. The
    // compensating sweep enqueued on timeout needs no answer before the
    // caller denies (FIFO order already runs it after the insert), so it
    // must not spend a second budget waiting on the same stalled writer.
    let path = unique_db_path("chio-intents-timeout-budget");
    let store = SqliteReceiptStore::open(&path)?;

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let budget = std::time::Duration::from_millis(500);
    let started = std::time::Instant::now();
    let error = store.record_dispatch_intent_with_timeout(&sample_intent("req-budget"), budget);
    let elapsed = started.elapsed();
    assert!(
        matches!(
            error,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "the bounded intent write must fail closed on a stalled writer"
    );
    assert!(
        elapsed < budget + std::time::Duration::from_millis(400),
        "the timeout deny must not stack a second sweep wait on top of the \
         insert's budget; elapsed {elapsed:?} for budget {budget:?}"
    );

    // The detached sweep still drains with the writer: no stale row survives.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "the sweep must still run behind the insert after the writer drains"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn straddling_intent_commit_is_cleared_after_a_timeout_deny(
) -> Result<(), Box<dyn std::error::Error>> {
    // A slow-but-successful insert can pass its final abandoned check and be
    // inside its commit when the caller's deadline expires: the abandoned
    // marker can no longer stop the row from landing, the caller reports a
    // timeout, and the evaluator denies before dispatch. The landed row must
    // then be swept by the job the timeout path enqueues behind the insert
    // on the single writer; otherwise it would dead-letter at the next boot
    // as a false orphan for a call that never executed. The instant between
    // the deadline expiring and the marker landing cannot be held open from
    // outside, so this drives the production job pair through the writer
    // with the shared slots staged exactly as that race leaves them.
    let path = unique_db_path("chio-intents-straddle-clear");
    let store = SqliteReceiptStore::open(&path)?;

    let intent = sample_intent("req-straddle-clear");
    let abandoned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let landed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let insert = super::super::support::dispatch_intent_insert_job_unless_abandoned(
        &intent,
        store.instance_token.clone(),
        std::sync::Arc::clone(&abandoned),
        std::sync::Arc::clone(&landed),
    );
    // The final abandoned check races ahead of the marker and the commit
    // lands: the caller's own insert is durable even though the caller is
    // about to observe a timeout.
    store.writer_handle().run_write(insert)?;
    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "the straddling insert must be durable before the caller times out"
    );
    // Only now does the deadline fire: too late for the marker to stop the
    // commit, which already recorded itself in the shared slot.
    abandoned.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        landed.load(std::sync::atomic::Ordering::SeqCst),
        "a commit that outruns the marker must record itself as landed"
    );

    // The sweep the timeout path enqueues behind the insert reads the slot
    // and deletes exactly the row this attempt created.
    let key = chio_kernel::receipt_store::DispatchIntentKey {
        request_id: intent.request_id.clone(),
        parameter_hash: intent.parameter_hash.clone(),
        tenant_id: intent.tenant_id.clone(),
    };
    store
        .writer_handle()
        .run_write(super::super::support::dispatch_intent_sweep_landed_job(
            &key, landed,
        ))?;

    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a landed intent row must not survive a timeout deny as a false orphan"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn duplicate_timeout_does_not_clear_the_preexisting_open_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // A retry (or concurrent duplicate) of a request that already has an
    // open intent can time out on a slow writer. Its queued insert then
    // refuses (abandoned marker, or the tenant-scoped request id it
    // collides with), so
    // the compensating sweep behind it has nothing of its own to delete:
    // removing the first invocation's row would erase that call's durable
    // crash marker and reject its terminal receipt's consume.
    let path = unique_db_path("chio-intents-duplicate-timeout");
    let store = SqliteReceiptStore::open(&path)?;

    // The first invocation's intent is durably open; its call is in flight.
    let intent = sample_intent("req-duplicate-timeout");
    store.record_dispatch_intent(&intent)?;
    assert_eq!(open_intent_row_count(&store)?, 1);

    // Park the writer so the duplicate attempt's bounded wait expires while
    // its insert (and the sweep behind it) are still queued.
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let error =
        store.record_dispatch_intent_with_timeout(&intent, std::time::Duration::from_millis(100));
    assert!(
        matches!(
            error,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "the duplicate attempt must still fail closed on expiry"
    );

    // Drain the queue past the refused insert and the sweep behind it.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;

    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "the first invocation's open intent must survive a duplicate's timeout"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

struct RecordingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for RecordingReconciler {
    fn resolve(
        &self,
        intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        // Default posture: dead-letter every orphan; a monetary orphan records
        // its rail so an operator can reconcile against the rail.
        let detail = match (&intent.rail, &intent.rail_authorization_id) {
            (Some(rail), Some(auth)) => {
                format!("outcome unknown; rail={rail}; rail_authorization_id={auth}")
            }
            (Some(rail), None) => format!("outcome unknown; rail={rail}"),
            _ => "outcome unknown".to_string(),
        };
        Ok(chio_kernel::receipt_store::DispatchIntentResolution::DeadLetter { detail })
    }
}

#[test]
fn reconcile_dead_letters_orphans_and_reports_counts() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-reconcile");

    {
        let store = SqliteReceiptStore::open(&path)?;
        // A clean run: no open intents means nothing to reconcile.
        let clean = store.reconcile_dispatch_intents(&RecordingReconciler)?;
        assert_eq!(clean.open, 0);
        assert_eq!(clean.dead_lettered, 0);

        // Two intents whose writer then crashes: one side-effecting, one
        // monetary with a rail attached.
        store.record_dispatch_intent(&sample_intent("orphan-se"))?;
        let mut monetary = sample_intent("orphan-mon");
        monetary.side_effect_class = chio_kernel::receipt_store::SideEffectClass::Monetary;
        monetary.monetary = true;
        monetary.rail = Some("x402".to_string());
        monetary.rail_authorization_id = Some("auth-9".to_string());
        store.record_dispatch_intent(&monetary)?;
    }

    // The restarted instance holds the file exclusively and both rows are
    // foreign to it: true orphans.
    let store = SqliteReceiptStore::open(&path)?;
    let report = store.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.open, 2);
    assert_eq!(report.dead_lettered, 2);

    // Both are now dead_letter; the monetary detail names the rail reference.
    let connection = store.reader_connection_for_test()?;
    let dead: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_dispatch_intents WHERE state = 'dead_letter'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(dead, 2);
    let detail: String = connection.query_row(
        "SELECT resolution_detail FROM chio_dispatch_intents WHERE request_id = 'orphan-mon'",
        [],
        |row| row.get(0),
    )?;
    assert!(
        detail.contains("x402") && detail.contains("auth-9"),
        "monetary detail names the rail reference: {detail}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn reconcile_resolution_batch_times_out_cleanly_on_a_wedged_writer(
) -> Result<(), Box<dyn std::error::Error>> {
    // The resolution batch (dead-letter / monetary-reconciled / replay-release)
    // used to go through an unbounded write while holding the reconcile probe
    // mutex. A wedged-but-alive writer therefore hung the whole pass, and
    // because `DispatchIntentRecoveryHandle::drop` joins the background
    // recovery worker thread that calls this method on its cadence, a wedged
    // writer could hang kernel shutdown along with it. The write must now
    // return within its budget, releasing the probe mutex and downgrading any
    // exclusive mark exactly as a successful pass does, and must leave the
    // claimed row untouched so a later pass (once the writer recovers) can
    // still resolve it.
    let path = unique_db_path("chio-intents-reconcile-wedged-writer");

    {
        let store = SqliteReceiptStore::open(&path)?;
        store.record_dispatch_intent(&sample_intent("orphan-wedged"))?;
    }

    // The restarted instance holds the file exclusively, so the row above is
    // a true orphan and reconciliation has real resolution work to do.
    let store = SqliteReceiptStore::open(&path)?;

    // Occupy the single writer with a job that parks until released, so the
    // reconciliation resolution batch below queues up behind it and never
    // drains on its own.
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let blocker_handle = store.writer_handle();
    let blocker = std::thread::spawn(move || {
        blocker_handle.run_write(move |_connection| {
            let _ = started_tx.send(());
            let _ = release_rx.recv_timeout(std::time::Duration::from_secs(30));
            Ok(())
        })
    });
    started_rx.recv_timeout(std::time::Duration::from_secs(5))?;

    let started = std::time::Instant::now();
    let result = store.reconcile_dispatch_intents(&RecordingReconciler);
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "a wedged writer must not hang the reconciliation pass; elapsed {elapsed:?}"
    );
    assert!(
        matches!(
            result,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Timeout { .. })
        ),
        "a timed-out resolution batch must surface a timeout, not hang or silently \
         succeed: {result:?}"
    );

    // Release the blocker and drain the queue behind it. The abandoned
    // resolution write must not have landed: the row stays open for the next
    // pass rather than being resolved twice or resolving the wrong epoch of
    // the row.
    release_tx.send(())?;
    blocker.join().map_err(|_| "blocker thread panicked")??;
    store.writer_handle().run_write(|_connection| Ok(()))?;
    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "a timed-out resolution write must leave the claimed row open for a later pass"
    );

    // The next cadence tick retries against a writer that has since
    // recovered and resolves the orphan normally.
    let report = store.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.dead_lettered, 1);
    assert_eq!(open_intent_row_count(&store)?, 0);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn attach_defers_reconciliation_while_a_sibling_writer_is_live(
) -> Result<(), Box<dyn std::error::Error>> {
    // The store supports sibling writer instances on one database file. An
    // open intent then proves only that ITS writer has not consumed it yet:
    // while that writer is alive the call may still be in flight, and
    // claiming the row as a restart orphan would erase a live crash marker,
    // reject the owner's terminal receipt, and flip health for work that is
    // not an incident. Reconciliation must defer a row while its owner
    // holds its liveness mark.
    let path = unique_db_path("chio-intents-live-sibling");
    let owner = SqliteReceiptStore::open(&path)?;
    owner.record_dispatch_intent(&sample_intent("req-live-sibling"))?;

    // A second instance attaching to the shared file observes the owner's
    // in-flight intent but must leave it to its owner.
    let sibling = SqliteReceiptStore::open(&path)?;
    let report = sibling.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(
        report.dead_lettered, 0,
        "a live sibling's open intent must not dead-letter"
    );
    assert_eq!(
        report.deferred_to_live_writer, 1,
        "the deferral must be reported, never silent"
    );
    assert_eq!(
        open_intent_row_count(&sibling)?,
        1,
        "the owner's crash marker must survive the sibling's attach"
    );

    // Once both instances are gone the same row is a true restart orphan: a
    // fresh attach holds the file exclusively and still reconciles it.
    drop(owner);
    drop(sibling);
    let restarted = SqliteReceiptStore::open(&path)?;
    let report = restarted.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        report.dead_lettered, 1,
        "a true restart must still dead-letter its orphans"
    );
    assert_eq!(report.deferred_to_live_writer, 0);
    assert_eq!(open_intent_row_count(&restarted)?, 0);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn surviving_writer_reclaims_a_crashed_siblings_orphan_without_restarting(
) -> Result<(), Box<dyn std::error::Error>> {
    // A sibling writer can crash while this instance stays up, leaving an
    // outcome-unknown intent that no attach will ever revisit (attaches
    // defer to live siblings, and the survivor may never restart). The
    // survivor must therefore be able to re-run reconciliation while
    // serving: its OWN in-flight intents are never candidates (they carry
    // its owner token), and the crashed sibling's rows are claimed the
    // moment its liveness mark reads gone, surfacing the orphan as an
    // incident without every writer going down.
    let path = unique_db_path("chio-intents-sibling-crash");
    let survivor = SqliteReceiptStore::open(&path)?;
    survivor.record_dispatch_intent(&sample_intent("req-survivor-live"))?;

    let doomed = SqliteReceiptStore::open(&path)?;
    doomed.record_dispatch_intent(&sample_intent("req-doomed-orphan"))?;

    // While the sibling lives, the survivor's pass considers only the
    // sibling's row (its own is not a reconciliation candidate) and defers
    // it to its owner.
    let deferred = survivor.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        deferred.open, 1,
        "the survivor's own in-flight intent is not a reconciliation candidate"
    );
    assert_eq!(deferred.dead_lettered, 0);
    assert_eq!(deferred.deferred_to_live_writer, 1);

    // The sibling crashes: the OS releases its lifetime mark, its open
    // intent stays behind as the crash marker.
    drop(doomed);

    // The next recovery pass on the still-serving survivor proves
    // exclusivity and claims exactly the orphan.
    let recovered = survivor.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        recovered.dead_lettered, 1,
        "the crashed sibling's orphan must surface without a restart"
    );
    let connection = survivor.reader_connection_for_test()?;
    let (survivor_state, orphan_state): (String, String) = (
        connection.query_row(
            "SELECT state FROM chio_dispatch_intents WHERE request_id = 'req-survivor-live'",
            [],
            |row| row.get(0),
        )?,
        connection.query_row(
            "SELECT state FROM chio_dispatch_intents WHERE request_id = 'req-doomed-orphan'",
            [],
            |row| row.get(0),
        )?,
    );
    assert_eq!(
        survivor_state, "open",
        "the survivor's own in-flight intent must never be claimed"
    );
    assert_eq!(orphan_state, "dead_letter");

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn crashed_tenants_orphan_never_dead_letters_a_live_tenants_same_id_intent(
) -> Result<(), Box<dyn std::error::Error>> {
    // Two tenants share a request id; the writer that journaled tenant-b's
    // intent crashes while tenant-a's writer stays live with its own
    // in-flight intent. Reconciliation must claim exactly the orphan: every
    // resolution write is keyed on (tenant, request id), so the live
    // tenant's row is never swept into the incident.
    let path = unique_db_path("chio-intents-tenant-reconcile");
    let survivor = SqliteReceiptStore::open(&path)?;
    let mut live = sample_intent("req-shared");
    live.tenant_id = Some("tenant-a".to_string());
    survivor.record_dispatch_intent(&live)?;

    let doomed = SqliteReceiptStore::open(&path)?;
    let mut orphan = sample_intent("req-shared");
    orphan.tenant_id = Some("tenant-b".to_string());
    doomed.record_dispatch_intent(&orphan)?;
    drop(doomed);

    let recovered = survivor.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        recovered.dead_lettered, 1,
        "exactly the crashed tenant's orphan surfaces"
    );

    let connection = survivor.reader_connection_for_test()?;
    let (live_state, orphan_state): (String, String) = (
        connection.query_row(
            "SELECT state FROM chio_dispatch_intents \
             WHERE request_id = 'req-shared' AND tenant_id = 'tenant-a'",
            [],
            |row| row.get(0),
        )?,
        connection.query_row(
            "SELECT state FROM chio_dispatch_intents \
             WHERE request_id = 'req-shared' AND tenant_id = 'tenant-b'",
            [],
            |row| row.get(0),
        )?,
    );
    assert_eq!(
        live_state, "open",
        "a live tenant's same-id intent must never be dead-lettered"
    );
    assert_eq!(orphan_state, "dead_letter");

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn concurrent_sibling_reconciles_never_claim_each_others_live_intents(
) -> Result<(), Box<dyn std::error::Error>> {
    // Two live sibling instances reconciling at the same time must both
    // defer: each holds its own liveness mark, so the other's probe reads
    // it live. The historical hazard the probe mutex guards against is the
    // shared-to-exclusive flock conversion, which is not atomic: it can
    // drop this instance's mark before the exclusive attempt resolves, and
    // two unserialized probes can each observe the other markless, win in
    // turn, and dead-letter the other's LIVE in-flight intents. The race
    // window is inside the conversion syscall and cannot be held open from
    // outside, so this hammers concurrent passes and requires that no
    // interleaving ever claims a row.
    let path = unique_db_path("chio-intents-concurrent-reconcile");
    let store_a = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    let store_b = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    store_a.record_dispatch_intent(&sample_intent("req-live-a"))?;
    store_b.record_dispatch_intent(&sample_intent("req-live-b"))?;

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let claimed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut workers = Vec::new();
    for store in [
        std::sync::Arc::clone(&store_a),
        std::sync::Arc::clone(&store_b),
    ] {
        let barrier = std::sync::Arc::clone(&barrier);
        let claimed = std::sync::Arc::clone(&claimed);
        workers.push(std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                // Record violations without breaking out of the loop: the
                // peer parks on the rendezvous every pass, so an early exit
                // would strand it instead of reporting the claim.
                for _ in 0..4000 {
                    // Rendezvous each pass so the two exclusivity probes run
                    // as close to simultaneously as the scheduler allows.
                    barrier.wait();
                    let report = store.reconcile_dispatch_intents(&RecordingReconciler)?;
                    claimed.fetch_add(report.dead_lettered, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(())
            },
        ));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| "reconcile worker panicked")?
            .map_err(|error| error.to_string())?;
    }

    assert_eq!(
        claimed.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no concurrent reconcile pass may ever claim a live sibling's intents"
    );
    assert_eq!(
        open_intent_row_count(&store_a)?,
        2,
        "both live intents must survive every concurrent reconcile pass"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Reconciler that fails by unwinding, standing in for any implementation
/// bug that panics while resolving an orphan.
struct PanickingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for PanickingReconciler {
    fn resolve(
        &self,
        _intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        panic!("injected reconciler failure");
    }
}

#[test]
fn reconciler_panic_re_shares_the_writer_lifetime_mark() -> Result<(), Box<dyn std::error::Error>> {
    // The background recovery worker catches reconciler panics and keeps
    // the store serving, so the pass itself must restore the shared
    // lifetime mark on the unwind path. The mark descriptor outlives the
    // pass (it lives on the store), so a mark left exclusive would block
    // every sibling open and defer every sibling reconcile for the rest of
    // this process's life, with no operator-visible signal.
    let path = unique_db_path("chio-intents-panic-downgrade");
    {
        let doomed = SqliteReceiptStore::open(&path)?;
        doomed.record_dispatch_intent(&sample_intent("req-panic-orphan"))?;
    }
    // Strip the owner token so the orphan is claimable only under the
    // whole-file exclusive conversion, the section whose unwind must not
    // strand the mark.
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("UPDATE chio_dispatch_intents SET owner_token = NULL", [])?;
    drop(connection);

    let survivor = SqliteReceiptStore::open(&path)?;
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        survivor.reconcile_dispatch_intents(&PanickingReconciler)
    }));
    assert!(
        unwound.is_err(),
        "the pass must reach the reconciler and unwind"
    );

    // A sibling's open acquires the mark shared and blocks until it can, so
    // probe non-blockingly: a stranded mark fails fast instead of hanging.
    let mark_path = crate::sqlite_writer_lock_path(&path).ok_or("writer mark sidecar path")?;
    let mark = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&mark_path)?;
    match mark.try_lock_shared() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err("writer lifetime mark stranded exclusive after a reconciler panic".into());
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    drop(mark);

    // The probe mutex must be free again as well: its descriptor is a pass
    // local, closed by the unwind.
    let probe_path = crate::sqlite_reconcile_lock_path(&path).ok_or("probe mutex sidecar path")?;
    let probe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&probe_path)?;
    match probe.try_lock() {
        Ok(()) => {}
        Err(std::fs::TryLockError::WouldBlock) => {
            return Err("reconcile probe mutex still held after a reconciler panic".into());
        }
        Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
    }
    drop(probe);

    // Recovery resumes on the very next pass.
    let report = survivor.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        report.dead_lettered, 1,
        "the orphan must still surface once the panicking reconciler is replaced"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn crashed_owner_orphan_surfaces_while_multiple_siblings_survive(
) -> Result<(), Box<dyn std::error::Error>> {
    // Whole-file exclusivity is unreachable while two or more writers
    // survive, so it cannot be the only way to claim: a crashed third
    // writer's orphans would stay open (and health green) until the
    // deployment happened to shrink to a single live writer. Liveness is
    // therefore judged per owner: each instance holds its own owner mark
    // for its open's lifetime, and a foreign row defers only while ITS
    // owner's mark is held.
    let path = unique_db_path("chio-intents-multi-survivor");
    let crashed = SqliteReceiptStore::open(&path)?;
    crashed.record_dispatch_intent(&sample_intent("req-crashed"))?;
    let survivor_b = SqliteReceiptStore::open(&path)?;
    survivor_b.record_dispatch_intent(&sample_intent("req-live-b"))?;
    let survivor_c = SqliteReceiptStore::open(&path)?;
    survivor_c.record_dispatch_intent(&sample_intent("req-live-c"))?;

    // The crash: the OS drops the owner's locks with its descriptors, and
    // the open row stays behind as the crash marker.
    drop(crashed);

    // B's pass sees two foreign rows, claims exactly the crashed owner's,
    // and defers the live sibling's to its owner.
    let report = survivor_b.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.open, 2);
    assert_eq!(
        report.dead_lettered, 1,
        "the crashed owner's orphan must surface while siblings survive"
    );
    assert_eq!(
        report.deferred_to_live_writer, 1,
        "the live sibling's row must defer to its owner"
    );
    let connection = survivor_b.reader_connection_for_test()?;
    let mut statement = connection
        .prepare("SELECT request_id, state FROM chio_dispatch_intents ORDER BY request_id")?;
    let states = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        states,
        vec![
            ("req-crashed".to_string(), "dead_letter".to_string()),
            ("req-live-b".to_string(), "open".to_string()),
            ("req-live-c".to_string(), "open".to_string()),
        ],
        "exactly the crashed owner's row is claimed; both live rows stay open"
    );
    drop(statement);
    drop(connection);

    // C's own pass afterwards finds nothing left to claim and defers B's
    // row to B.
    let report = survivor_c.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(report.deferred_to_live_writer, 1);

    // Sidecar hygiene: the claimed owner's mark file was removed with its
    // rows, and clean closes remove their own, so opens do not accumulate
    // one file per store lifetime.
    drop(survivor_b);
    drop(survivor_c);
    let db_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("database file name")?
        .to_string();
    let leftover: Vec<String> = std::fs::read_dir(path.parent().ok_or("database parent dir")?)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| entry.file_name().to_str().map(String::from))
        .filter(|name| name.starts_with(&db_name) && name.contains(".owner-"))
        .collect();
    assert!(
        leftover.is_empty(),
        "owner mark files must not accumulate: {leftover:?}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn concurrent_survivor_passes_claim_only_the_crashed_owners_row(
) -> Result<(), Box<dyn std::error::Error>> {
    // Two survivors reconciling at the same time must together claim the
    // crashed owner's row exactly once and never each other's: passes are
    // serialized on the probe mutex, and each pass judges liveness against
    // owner marks it never holds itself.
    let path = unique_db_path("chio-intents-concurrent-survivors");
    let crashed = SqliteReceiptStore::open(&path)?;
    crashed.record_dispatch_intent(&sample_intent("req-crashed"))?;
    let store_b = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    store_b.record_dispatch_intent(&sample_intent("req-live-b"))?;
    let store_c = std::sync::Arc::new(SqliteReceiptStore::open(&path)?);
    store_c.record_dispatch_intent(&sample_intent("req-live-c"))?;
    drop(crashed);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let claimed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut workers = Vec::new();
    for store in [
        std::sync::Arc::clone(&store_b),
        std::sync::Arc::clone(&store_c),
    ] {
        let barrier = std::sync::Arc::clone(&barrier);
        let claimed = std::sync::Arc::clone(&claimed);
        workers.push(std::thread::spawn(
            move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
                for _ in 0..500 {
                    // Rendezvous each pass so the probes run as close to
                    // simultaneously as the scheduler allows.
                    barrier.wait();
                    let report = store.reconcile_dispatch_intents(&RecordingReconciler)?;
                    claimed.fetch_add(report.dead_lettered, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(())
            },
        ));
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| "reconcile worker panicked")?
            .map_err(|error| error.to_string())?;
    }

    assert_eq!(
        claimed.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the crashed owner's row must be claimed exactly once, and no live row ever"
    );
    assert_eq!(
        open_intent_row_count(&store_b)?,
        2,
        "both survivors' live intents must stay open through every pass"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn rows_naming_no_owner_claim_only_under_whole_file_exclusivity(
) -> Result<(), Box<dyn std::error::Error>> {
    // A row journaled before owner tokens existed names no owner mark to
    // probe, so the only safe claim is the original whole-file one: prove
    // no sibling is live at all. While any sibling survives the row
    // defers; a true single-writer restart still reconciles it.
    let path = unique_db_path("chio-intents-unattributed");
    {
        let legacy = SqliteReceiptStore::open(&path)?;
        legacy.record_dispatch_intent(&sample_intent("req-unattributed"))?;
    }
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("UPDATE chio_dispatch_intents SET owner_token = NULL", [])?;
    drop(connection);

    let survivor = SqliteReceiptStore::open(&path)?;
    let sibling = SqliteReceiptStore::open(&path)?;
    let deferred = survivor.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        deferred.dead_lettered, 0,
        "an unattributable row must not be claimed while a sibling could own it"
    );
    assert_eq!(deferred.deferred_to_live_writer, 1);

    drop(sibling);
    let report = survivor.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(
        report.dead_lettered, 1,
        "a single surviving writer still claims unattributable rows"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Rail-aware reconciler: proves the outcome of monetary orphans against the
/// rail and dead-letters everything else.
struct RailProvingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for RailProvingReconciler {
    fn resolve(
        &self,
        intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        if intent.monetary {
            Ok(
                chio_kernel::receipt_store::DispatchIntentResolution::MonetaryReconciled {
                    rail_reference: "tx-123".to_string(),
                },
            )
        } else {
            Ok(
                chio_kernel::receipt_store::DispatchIntentResolution::DeadLetter {
                    detail: "outcome unknown".to_string(),
                },
            )
        }
    }
}

#[test]
fn monetary_reconciled_intent_is_not_a_dead_letter_and_health_stays_green(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-monetary-reconciled");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let mut monetary = sample_intent("orphan-reconciled");
        monetary.side_effect_class = chio_kernel::receipt_store::SideEffectClass::Monetary;
        monetary.monetary = true;
        monetary.rail = Some("x402".to_string());
        monetary.rail_authorization_id = Some("auth-7".to_string());
        store.record_dispatch_intent(&monetary)?;
    }

    // The writer crashed; the restarted instance reconciles its orphan.
    let store = SqliteReceiptStore::open(&path)?;
    // One writer round trip so the later health sample observes the seeded
    // verified head rather than racing writer-thread startup.
    store.flush_receipt_writes()?;

    let report = store.reconcile_dispatch_intents(&RailProvingReconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(report.monetary_reconciled, 1);
    assert_eq!(report.dead_lettered, 0);

    // The reconciled intent reaches its own terminal state carrying the rail
    // reference: the reconciler PROVED the outcome, so the row is neither
    // open nor an outcome-unknown dead letter.
    let connection = store.reader_connection_for_test()?;
    let (state, detail): (String, String) = connection.query_row(
        "SELECT state, resolution_detail FROM chio_dispatch_intents \
         WHERE request_id = 'orphan-reconciled'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    drop(connection);
    assert_eq!(state, "reconciled");
    assert!(
        detail.contains("tx-123"),
        "the terminal disposition names the rail reference: {detail}"
    );
    assert_eq!(store.open_dispatch_intent_count()?, 0);
    assert_eq!(store.dead_letter_dispatch_intent_count()?, 0);

    let health = store.receipt_store_health()?;
    assert!(
        health.healthy,
        "a rail-proven reconciliation is not an incident and must not flip health"
    );
    assert_eq!(health.dead_letter_dispatch_intents, 0);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Reconciler that proves every orphan's effect never ran, so each is safe
/// to replay.
struct ReplayProvingReconciler;

impl chio_kernel::receipt_store::DispatchIntentReconciler for ReplayProvingReconciler {
    fn resolve(
        &self,
        _intent: &chio_kernel::receipt_store::DispatchIntentRecord,
    ) -> Result<
        chio_kernel::receipt_store::DispatchIntentResolution,
        chio_kernel::receipt_store::ReceiptStoreError,
    > {
        Ok(chio_kernel::receipt_store::DispatchIntentResolution::SafeToReplay)
    }
}

#[test]
fn safe_to_replay_frees_the_request_id_for_a_fresh_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    // "Safe to replay" means the reconciler PROVED the effect never ran and
    // the resolution is to run the request again. The replay travels the
    // normal pre-dispatch path, which journals its own intent under the
    // same (tenant, request id) identity, so the proven-effectless row must
    // not survive: any leftover row would refuse the replay's insert and
    // fail the request before the tool runs.
    let path = unique_db_path("chio-intents-safe-to-replay");
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.record_dispatch_intent(&sample_intent("req-replay"))?;
    }

    // The writer crashed; the restarted instance reconciles its orphan.
    let store = SqliteReceiptStore::open(&path)?;
    let report = store.reconcile_dispatch_intents(&ReplayProvingReconciler)?;
    assert_eq!(report.open, 1);
    assert_eq!(report.replayed, 1);
    assert_eq!(report.dead_lettered, 0);
    assert_eq!(
        open_intent_row_count(&store)?,
        0,
        "a proven-effectless row must not linger as an open crash marker"
    );

    // The replayed request journals a fresh intent under the same id.
    store.record_dispatch_intent(&sample_intent("req-replay"))?;
    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "the replay's own pre-dispatch insert must succeed after reconciliation"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn dead_letter_intent_flips_store_unhealthy() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-health");
    {
        let store = SqliteReceiptStore::open(&path)?;

        // Health folds in `writer_serving_closed`, which reads closed until
        // the writer thread's one-time startup seed publishes a verified
        // head. Wait for one writer round trip so the sample observes the
        // seeded head rather than racing thread startup.
        store.flush_receipt_writes()?;

        // A clean store is healthy with zero intent counts.
        let clean = store.receipt_store_health()?;
        assert!(clean.healthy);
        assert_eq!(clean.open_dispatch_intents, 0);
        assert_eq!(clean.dead_letter_dispatch_intents, 0);

        // An open intent alone does not flip health: it is in flight, not
        // orphaned.
        store.record_dispatch_intent(&sample_intent("open-1"))?;
        let with_open = store.receipt_store_health()?;
        assert_eq!(with_open.open_dispatch_intents, 1);
        assert!(with_open.healthy, "an in-flight intent is not an incident");
    }

    // The writer crashed with the intent open. Reconciling the orphan into
    // a dead-letter incident flips the restarted store unhealthy.
    let store = SqliteReceiptStore::open(&path)?;
    store.flush_receipt_writes()?;
    store.reconcile_dispatch_intents(&RecordingReconciler)?;
    let after = store.receipt_store_health()?;
    assert_eq!(after.dead_letter_dispatch_intents, 1);
    assert!(
        !after.healthy,
        "a dead-letter incident flips health to false"
    );
    assert_eq!(store.open_dispatch_intent_count()?, 0);
    assert_eq!(store.dead_letter_dispatch_intent_count()?, 1);

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn resolve_dead_letter_intent_clears_health_and_preserves_audit_trail(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-resolve");
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.record_dispatch_intent(&sample_intent("req-resolve"))?;
    }
    let store = SqliteReceiptStore::open(&path)?;
    store.flush_receipt_writes()?;
    store.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert!(
        !store.receipt_store_health()?.healthy,
        "the dead-lettered orphan must flip health unhealthy before resolution"
    );

    store.resolve_dead_letter_dispatch_intent(
        "req-resolve",
        None,
        "confirmed via rail statement, no funds moved",
    )?;

    let after = store.receipt_store_health()?;
    assert!(
        after.healthy,
        "a resolved dead letter must stop counting against health"
    );
    assert_eq!(after.open_dispatch_intents, 0);
    assert_eq!(after.dead_letter_dispatch_intents, 0);

    // The row survives (auditable), carrying both the original incident
    // detail and the operator's note, rather than being deleted.
    let connection = store.reader_connection_for_test()?;
    let (state, detail): (String, String) = connection.query_row(
        "SELECT state, resolution_detail FROM chio_dispatch_intents WHERE request_id = 'req-resolve'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(state, "resolved");
    assert!(
        detail.contains("outcome unknown"),
        "the original incident detail must survive: {detail}"
    );
    assert!(
        detail.contains("confirmed via rail statement, no funds moved"),
        "the operator's note must be appended: {detail}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn resolve_dead_letter_intent_refuses_a_missing_request() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-intents-resolve-missing");
    let store = SqliteReceiptStore::open(&path)?;
    let result = store.resolve_dead_letter_dispatch_intent("no-such-request", None, "note");
    let error = result
        .err()
        .ok_or("resolving a nonexistent request must refuse, not no-op")?;
    assert!(
        matches!(
            error,
            chio_kernel::receipt_store::ReceiptStoreError::NotFound(_)
        ),
        "expected NotFound, got {error:?}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn resolve_dead_letter_intent_refuses_a_still_open_row() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-resolve-still-open");
    let store = SqliteReceiptStore::open(&path)?;
    // The intent is open (in flight, still owned by this live instance),
    // never dead-lettered.
    store.record_dispatch_intent(&sample_intent("req-still-open"))?;

    let result = store.resolve_dead_letter_dispatch_intent("req-still-open", None, "note");
    let error = result
        .err()
        .ok_or("resolving a non-dead-letter row must refuse")?;
    assert!(
        matches!(
            error,
            chio_kernel::receipt_store::ReceiptStoreError::Conflict(_)
        ),
        "expected Conflict, got {error:?}"
    );
    assert_eq!(
        open_intent_row_count(&store)?,
        1,
        "a refused resolution must not disturb the still-open row"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn resolve_dead_letter_intent_refuses_a_row_already_resolved(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-intents-resolve-twice");
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.record_dispatch_intent(&sample_intent("req-resolve-twice"))?;
    }
    // Reopen so the row is foreign to this instance and reconciliation can
    // actually dead-letter it (a store never claims its own live intents).
    let store = SqliteReceiptStore::open(&path)?;
    store.flush_receipt_writes()?;
    store.reconcile_dispatch_intents(&RecordingReconciler)?;
    assert_eq!(store.dead_letter_dispatch_intent_count()?, 1);

    store.resolve_dead_letter_dispatch_intent("req-resolve-twice", None, "first resolution")?;

    // Resolving it a second time (already resolved, not dead_letter) must
    // refuse, not silently succeed: the state check re-runs against the
    // CURRENT row rather than trusting the caller's belief that it is still
    // a dead letter.
    let second = store.resolve_dead_letter_dispatch_intent(
        "req-resolve-twice",
        None,
        "second resolution attempt",
    );
    assert!(
        matches!(
            second,
            Err(chio_kernel::receipt_store::ReceiptStoreError::Conflict(_))
        ),
        "resolving an already-resolved row must refuse, got {second:?}"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

fn stamped_receipt_schema_version(
    connection: &rusqlite::Connection,
) -> Result<i32, Box<dyn std::error::Error>> {
    Ok(connection.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'receipt'",
        [],
        |row| row.get(0),
    )?)
}

#[test]
fn receipt_schema_revision_covers_the_dispatch_intent_journal(
) -> Result<(), Box<dyn std::error::Error>> {
    // A journal-bearing database must carry a schema revision above the
    // pre-journal one, so an older binary (which would neither reconcile
    // open intents nor surface them in health) refuses the file instead of
    // serving it while orphaned effects sit invisible.
    let path = unique_db_path("chio-intents-schema-revision");
    let store = SqliteReceiptStore::open(&path)?;
    let connection = store.reader_connection_for_test()?;
    assert_eq!(
        stamped_receipt_schema_version(&connection)?,
        1,
        "a freshly created journal-bearing store stamps revision 1"
    );

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn open_existing_migrates_a_pre_journal_database() -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::dispatch_intents_table_exists;

    let path = unique_db_path("chio-intents-schema-migration");
    // Build a pre-journal database: create a full store, then rewind it by
    // dropping the journal table and stamping the pre-journal revision.
    {
        let store = SqliteReceiptStore::open(&path)?;
        store.flush_receipt_writes()?;
    }
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection
            .execute_batch("PRAGMA busy_timeout = 5000; DROP TABLE chio_dispatch_intents;")?;
        crate::stamp_schema_version(&connection, "receipt", 0)?;
    }

    // open_existing on the pre-journal file runs the additive migration: the
    // journal table exists afterwards and the current revision is stamped,
    // so an older binary refuses the migrated file from then on.
    {
        let store = SqliteReceiptStore::open_existing(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(
            dispatch_intents_table_exists(&connection)?,
            "open_existing must create the journal table on a pre-journal database"
        );
        assert_eq!(
            stamped_receipt_schema_version(&connection)?,
            1,
            "the migrated database is stamped with the journal revision"
        );
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

#[test]
fn open_creates_dispatch_intents_table_and_open_existing_tolerates_absence(
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::receipt_store::support::dispatch_intents_table_exists;

    let path = unique_db_path("chio-intents-schema");
    {
        let store = SqliteReceiptStore::open(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(
            dispatch_intents_table_exists(&connection)?,
            "open() must create chio_dispatch_intents"
        );
    }
    // Reopening the same file via open_existing keeps the table (the
    // database is already at the journal revision, so no migration runs).
    {
        let store = SqliteReceiptStore::open_existing(&path)?;
        let connection = store.reader_connection_for_test()?;
        assert!(dispatch_intents_table_exists(&connection)?);
    }
    let _ = std::fs::remove_file(&path);
    Ok(())
}
