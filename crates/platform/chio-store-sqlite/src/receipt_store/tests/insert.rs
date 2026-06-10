use super::super::*;
use super::support::*;

#[test]
fn append_chio_receipt_returning_seq_returns_seq() {
    let path = unique_db_path("chio-receipts-seq");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-seq-001");
    let seq = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    assert!(seq > 0, "seq should be non-zero for a new insert");
    let _ = fs::remove_file(path);
}

#[test]
fn append_chio_receipt_consuming_authorization_rejects_reuse_after_reopen() {
    let path = unique_db_path("chio-auth-consume");
    let keypair = receipt_test_keypair();
    let tenant_id = "tenant-acp";
    let authorization =
        sample_receipt_with_keypair_and_tenant("auth-consume", 101, tenant_id, &keypair);
    let consumer =
        sample_receipt_with_keypair_and_tenant("consumer-consume", 102, tenant_id, &keypair);
    let replay_consumer =
        sample_receipt_with_keypair_and_tenant("consumer-replay", 103, tenant_id, &keypair);
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    store.append_chio_receipt(&authorization).test_unwrap();
    store.flush_receipt_writes().test_unwrap();
    let consumption = AuthorizationReceiptConsumption {
        authorization_receipt_id: authorization.id.clone(),
        consumer_receipt_id: consumer.id.clone(),
        request_id: "auth-consume-request".to_string(),
        session_id: "auth-consume-session".to_string(),
        tool_call_id: "auth-consume-tool-call".to_string(),
        tenant_id: Some(tenant_id.to_string()),
        parameter_hash: "auth-consume-parameter-hash".to_string(),
        consumed_at_unix_ms: 101_000,
    };
    store
        .append_chio_receipt_consuming_authorization(&consumer, &consumption)
        .test_unwrap();
    drop(store);

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    let replay = AuthorizationReceiptConsumption {
        consumer_receipt_id: replay_consumer.id.clone(),
        consumed_at_unix_ms: 102_000,
        ..consumption
    };
    let error = reopened
        .append_chio_receipt_consuming_authorization(&replay_consumer, &replay)
        .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("authorization receipt already consumed"),
        "unexpected error: {error}"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn append_returned_claim_log_seqs_survive_reopen() {
    let path = unique_db_path("chio-receipts-seq-reopen");
    let tool_seq;
    let child_seq;
    {
        let store = SqliteReceiptStore::open(&path).test_unwrap();
        tool_seq = store
            .append_chio_receipt_returning_seq(&sample_receipt_with_id("rcpt-seq-reopen-tool"))
            .test_unwrap();
        child_seq = ReceiptStore::append_child_receipt_returning_seq(
            &store,
            &sample_child_receipt_with_id_and_timestamp("child-seq-reopen", 2),
        )
        .test_unwrap()
        .test_expect("sqlite child seq");
        assert_eq!(store.latest_committed_entry_seq().test_unwrap(), child_seq);
    }

    let reopened = SqliteReceiptStore::open(&path).test_unwrap();
    let rows = load_claim_log_rows(&reopened);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, tool_seq);
    assert_eq!(rows[0].2, "tool_receipt");
    assert_eq!(rows[1].0, child_seq);
    assert_eq!(rows[1].2, "child_receipt");
    assert_eq!(
        reopened.latest_committed_entry_seq().test_unwrap(),
        child_seq
    );

    let _ = fs::remove_file(path);
}

#[test]
fn append_100_receipts_seqs_span_1_to_100() {
    let path = unique_db_path("chio-receipts-100");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let mut seqs = Vec::new();
    for i in 0..100usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-{i:04}"));
        let seq = store
            .append_chio_receipt_returning_seq(&receipt)
            .test_unwrap();
        seqs.push(seq);
    }
    assert_eq!(seqs[0], 1);
    assert_eq!(seqs[99], 100);
    let _ = fs::remove_file(path);
}

#[test]
fn receipt_writer_pool_accepts_writes_when_reader_pool_is_saturated(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-pool-split");
    let store = Arc::new(SqliteReceiptStore::open_with_pool_sizes(&path, 1, 1)?);
    let reader_connection = store.connection()?;
    let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(1);
    let writer_store = Arc::clone(&store);

    thread::spawn(move || {
        let receipt = sample_receipt_with_id("rcpt-pool-split-writer");
        let result = writer_store.append_chio_receipt_returning_seq(&receipt);
        let _ = result_sender.send(result);
    });

    let seq = result_receiver
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| std::io::Error::other("writer pool waited for saturated reader pool"))??;
    assert_eq!(seq, 1);

    drop(reader_connection);
    assert_eq!(store.tool_receipt_count()?, 1);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn append_receipt_batch_commits_multiple_receipts_together(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-group-batch");
    let store = SqliteReceiptStore::open(&path)?;

    let mut requests = Vec::new();
    for i in 0..4usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-group-batch-{i}"));
        let raw_json = serde_json::to_string(&receipt)?;
        let (response, _result) = std::sync::mpsc::sync_channel(1);
        requests.push(ReceiptCommitRequest {
            receipt,
            raw_json,
            response,
        });
    }

    let seqs: Vec<u64> = append_receipt_batch(&store.pool, &requests)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(seqs, vec![1, 2, 3, 4]);
    assert_eq!(store.tool_receipt_count()?, 4);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn duplicate_tool_receipt_bytes_return_existing_claim_log_seq() {
    let path = unique_db_path("chio-receipts-duplicate-tool");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-duplicate-tool");

    let first = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();
    let second = store
        .append_chio_receipt_returning_seq(&receipt)
        .test_unwrap();

    assert_eq!(first, second);
    assert!(first > 0);
    assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
    assert_eq!(load_claim_log_rows(&store).len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn duplicate_tool_receipt_id_with_different_bytes_conflicts() {
    let path = unique_db_path("chio-receipts-duplicate-tool-conflict");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_receipt_with_id("rcpt-duplicate-tool-conflict");
    let raw_json = serde_json::to_string(&receipt).test_unwrap();
    let mut connection = store.connection().test_unwrap();

    {
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .test_unwrap();
        let seq = append_chio_receipt_tx(&tx, &receipt, &raw_json).test_unwrap();
        assert_eq!(seq, 1);
        tx.commit().test_unwrap();
    }

    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .test_unwrap();
    let error = append_chio_receipt_tx(&tx, &receipt, &format!("{raw_json}\n")).test_unwrap_err();

    assert!(error
        .to_string()
        .contains("already exists with different content"));
    drop(tx);
    drop(connection);
    assert_eq!(store.tool_receipt_count().test_unwrap(), 1);
    assert_eq!(load_claim_log_rows(&store).len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn duplicate_child_receipt_bytes_return_existing_claim_log_seq() {
    let path = unique_db_path("chio-receipts-duplicate-child");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_child_receipt_with_id_and_timestamp("child-duplicate", 2);

    let first = ReceiptStore::append_child_receipt_returning_seq(&store, &receipt)
        .test_unwrap()
        .test_expect("sqlite child seq");
    let second = ReceiptStore::append_child_receipt_returning_seq(&store, &receipt)
        .test_unwrap()
        .test_expect("sqlite child seq");

    assert_eq!(first, second);
    assert!(first > 0);
    assert_eq!(store.child_receipt_count().test_unwrap(), 1);
    assert_eq!(load_claim_log_rows(&store).len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn duplicate_child_receipt_id_with_different_bytes_conflicts() {
    let path = unique_db_path("chio-receipts-duplicate-child-conflict");
    let store = SqliteReceiptStore::open(&path).test_unwrap();
    let receipt = sample_child_receipt_with_id_and_timestamp("child-duplicate-conflict", 2);
    let conflicting = sample_child_receipt_with_id_and_timestamp("child-duplicate-conflict", 3);

    ReceiptStore::append_child_receipt_returning_seq(&store, &receipt)
        .test_unwrap()
        .test_expect("sqlite child seq");
    let error =
        ReceiptStore::append_child_receipt_returning_seq(&store, &conflicting).test_unwrap_err();

    assert!(error
        .to_string()
        .contains("already exists with different content"));
    assert_eq!(store.child_receipt_count().test_unwrap(), 1);
    assert_eq!(load_claim_log_rows(&store).len(), 1);

    let _ = fs::remove_file(path);
}

#[test]
fn append_receipt_batch_rolls_back_all_receipts_on_batch_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-group-rollback");
    let store = SqliteReceiptStore::open(&path)?;
    let mut requests = Vec::new();

    for receipt in [sample_receipt_with_id("rcpt-group-rollback-valid"), {
        let mut receipt = sample_receipt_with_id("rcpt-group-rollback-invalid");
        receipt.timestamp = u64::MAX;
        receipt
    }] {
        let raw_json = serde_json::to_string(&receipt)?;
        let (response, _result) = std::sync::mpsc::sync_channel(1);
        requests.push(ReceiptCommitRequest {
            receipt,
            raw_json,
            response,
        });
    }

    let results = append_receipt_batch(&store.pool, &requests);

    assert!(results.into_iter().all(|result| result.is_err()));
    assert_eq!(store.tool_receipt_count()?, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_commit_flush_waits_for_queued_receipts() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-group-flush");
    let store = SqliteReceiptStore::open(&path)?;
    let mut results = Vec::new();

    for i in 0..3usize {
        let receipt = sample_receipt_with_id(&format!("rcpt-group-flush-{i}"));
        let raw_json = serde_json::to_string(&receipt)?;
        let (response, result) = std::sync::mpsc::sync_channel(1);
        store
            .receipt_commit_actor
            .sender
            .send(ReceiptCommitCommand::Append(Box::new(
                ReceiptCommitRequest {
                    receipt,
                    raw_json,
                    response,
                },
            )))
            .map_err(|_| std::io::Error::other("send receipt append command"))?;
        results.push(result);
    }

    store.flush_receipt_writes()?;
    let seqs: Vec<u64> = results
        .into_iter()
        .map(|result| {
            result
                .recv()
                .map_err(|_| std::io::Error::other("receive receipt append result"))?
                .map_err(Box::<dyn std::error::Error>::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(seqs, vec![1, 2, 3]);
    assert_eq!(store.tool_receipt_count()?, 3);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn receipt_commit_flush_reports_queued_batch_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-group-flush-error");
    let store = SqliteReceiptStore::open(&path)?;
    let mut invalid = sample_receipt_with_id("rcpt-group-flush-error-invalid");
    invalid.timestamp = u64::MAX;
    let raw_json = serde_json::to_string(&invalid)?;
    let (response, result) = std::sync::mpsc::sync_channel(1);
    store
        .receipt_commit_actor
        .sender
        .send(ReceiptCommitCommand::Append(Box::new(
            ReceiptCommitRequest {
                receipt: invalid,
                raw_json,
                response,
            },
        )))
        .map_err(|_| std::io::Error::other("send receipt append command"))?;

    let error = match store.flush_receipt_writes() {
        Ok(_) => panic!("expected timestamp conflict when flushing receipt writes"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        chio_kernel::ReceiptStoreError::Conflict(message)
            if message.contains("receipt timestamp")
    ));
    assert!(result
        .recv()
        .map_err(|_| std::io::Error::other("receive receipt append result"))?
        .is_err());
    assert_eq!(store.tool_receipt_count()?, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn append_receipt_batch_rolls_back_full_batch_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-full-batch-flush-error");
    let store = SqliteReceiptStore::open(&path)?;
    let mut requests = Vec::new();

    for i in 0..RECEIPT_GROUP_COMMIT_MAX_BATCH {
        let mut receipt = sample_receipt_with_id(&format!("rcpt-full-batch-flush-error-{i}"));
        if i == RECEIPT_GROUP_COMMIT_MAX_BATCH - 1 {
            receipt.timestamp = u64::MAX;
        }
        let raw_json = serde_json::to_string(&receipt)?;
        let (response, _result) = std::sync::mpsc::sync_channel(1);
        requests.push(ReceiptCommitRequest {
            receipt,
            raw_json,
            response,
        });
    }

    let results = append_receipt_batch(&store.pool, &requests);
    assert!(results.into_iter().all(|result| {
        matches!(
            result,
            Err(chio_kernel::ReceiptStoreError::Conflict(message))
                if message.contains("receipt timestamp")
        )
    }));
    assert_eq!(store.tool_receipt_count()?, 0);

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn append_chio_receipt_returning_seq_supports_concurrent_writers() {
    let path = unique_db_path("chio-receipts-concurrent");
    let store = Arc::new(SqliteReceiptStore::open(&path).test_unwrap());
    let thread_count = 8usize;
    let receipts_per_thread = 24usize;
    let barrier = Arc::new(Barrier::new(thread_count));
    let mut handles = Vec::new();

    for worker in 0..thread_count {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut seqs = Vec::new();
            for receipt_index in 0..receipts_per_thread {
                let receipt =
                    sample_receipt_with_id(&format!("rcpt-concurrent-{worker}-{receipt_index}"));
                seqs.push(
                    store
                        .append_chio_receipt_returning_seq(&receipt)
                        .test_unwrap(),
                );
            }
            seqs
        }));
    }

    let mut seqs = Vec::new();
    for handle in handles {
        seqs.extend(handle.join().test_unwrap());
    }

    assert_eq!(seqs.len(), thread_count * receipts_per_thread);
    assert!(seqs.iter().all(|seq| *seq > 0));

    let mut deduped = seqs.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(deduped.len(), seqs.len());
    assert_eq!(store.tool_receipt_count().test_unwrap(), seqs.len() as u64);

    let _ = fs::remove_file(path);
}

#[test]
fn append_inflight_counter_does_not_underflow_on_concurrent_drain() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    let path = unique_db_path("chio-receipts-inflight-race");
    let store = Arc::new(SqliteReceiptStore::open(&path).test_unwrap());

    let thread_count = 12usize;
    let max_appends_per_thread = 1024usize;
    let total_budget = Duration::from_millis(200);
    let total_cap: usize = thread_count * max_appends_per_thread;

    let start_barrier = Arc::new(Barrier::new(thread_count + 1));
    let stop = Arc::new(AtomicBool::new(false));
    let observed_max_inflight = Arc::new(AtomicU64::new(0));
    let total_appended = Arc::new(AtomicU64::new(0));

    // Appender threads: race to enqueue receipts as fast as possible until
    // `stop` is set or the per-thread cap is hit.
    let mut appenders = Vec::with_capacity(thread_count);
    for worker in 0..thread_count {
        let store = Arc::clone(&store);
        let start_barrier = Arc::clone(&start_barrier);
        let stop = Arc::clone(&stop);
        let total_appended = Arc::clone(&total_appended);
        appenders.push(thread::spawn(move || -> u64 {
            start_barrier.wait();
            let mut local: u64 = 0;
            for receipt_index in 0..max_appends_per_thread {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let receipt =
                    sample_receipt_with_id(&format!("rcpt-inflight-race-{worker}-{receipt_index}"));
                match store.append_chio_receipt_returning_seq(&receipt) {
                    Ok(_) => {
                        local += 1;
                        total_appended.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(_) => {
                        // The actor channel may saturate under pressure; the
                        // bug we are exercising is independent of saturation.
                        thread::yield_now();
                    }
                }
            }
            local
        }));
    }

    // Sampler thread: poll the inflight counter while appenders run. If the
    // counter ever exceeds the cumulative accepted-total by more than a
    // bounded slack, the speculative increment leaked past drain.
    let sampler_store = Arc::clone(&store);
    let sampler_stop = Arc::clone(&stop);
    let sampler_max = Arc::clone(&observed_max_inflight);
    let sampler_leak = Arc::new(AtomicBool::new(false));
    let sampler_leak_clone = Arc::clone(&sampler_leak);
    let slack = u64::try_from(thread_count).unwrap_or(u64::MAX);
    let sampler = thread::spawn(move || {
        while !sampler_stop.load(Ordering::SeqCst) {
            let counters = match sampler_store.receipt_store_health() {
                Ok(report) => report.writer,
                Err(_) => {
                    thread::yield_now();
                    continue;
                }
            };
            let inflight = counters.inflight;
            let accepted = counters.accepted_total;
            let previous = sampler_max.load(Ordering::SeqCst);
            if inflight > previous {
                let _ = sampler_max.compare_exchange(
                    previous,
                    inflight,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
            // The slack tolerates a thread holding an unincremented receipt between `fetch_add` (now
            // pre-send) and its corresponding decrement.
            if inflight > accepted.saturating_add(slack) {
                sampler_leak_clone.store(true, Ordering::SeqCst);
            }
            thread::yield_now();
        }
    });

    // Release appenders; bound total work by `total_budget`.
    start_barrier.wait();
    let start = Instant::now();
    while start.elapsed() < total_budget {
        if total_appended.load(Ordering::SeqCst) as usize >= total_cap {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    stop.store(true, Ordering::SeqCst);

    for handle in appenders {
        let _ = handle.join().test_unwrap();
    }
    sampler.join().test_unwrap();

    // Drain the actor so every accepted command has been committed and the
    // worker has run its decrement.
    let report = store.flush_receipt_writes().test_unwrap();

    let writer = report.writer;
    assert_eq!(
        writer.inflight, 0,
        "inflight must return to 0 after flush; leaked phantom inflight indicates the pre-fix race \
         (try_send visible to worker before fetch_add): accepted={}, committed={}, inflight={}",
        writer.accepted_total, writer.committed_total, writer.inflight
    );
    assert_eq!(
        writer.accepted_total, writer.committed_total,
        "every accepted append must commit cleanly under drain; mismatch indicates a leak: \
         accepted={}, committed={}, failed={}",
        writer.accepted_total, writer.committed_total, writer.failed_total
    );
    assert!(
        !sampler_leak.load(Ordering::SeqCst),
        "sampler observed inflight > accepted_total + thread_count slack during the run, which \
         means a speculative increment leaked past drain (pre-fix race signature); \
         observed_max_inflight={}",
        observed_max_inflight.load(Ordering::SeqCst)
    );
    // Sanity: the run actually exercised concurrent traffic.
    let appended = total_appended.load(Ordering::SeqCst);
    assert!(
        appended > 0,
        "stress run did not append any receipts within the budget; raise the budget or check the \
         actor channel"
    );
    assert_eq!(
        writer.committed_total, appended,
        "committed_total ({}) must equal the number of successful appends ({})",
        writer.committed_total, appended
    );

    let _ = fs::remove_file(path);
}
