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
            ensure_lineage: false,
            response,
        });
    }

    let seqs: Vec<u64> =
        append_receipt_batch(&store.pool, &mut VerifiedHead::default(), true, &requests)
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

/// A per-receipt failure in a coalesced group-commit batch is isolated to that
/// record via per-record savepoints: the valid sibling still commits and
/// persists instead of the whole batch rolling back and failing every caller.
/// Independent producers keep independent success/failure semantics.
#[test]
fn append_receipt_batch_isolates_per_record_error() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-group-isolation");
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
            ensure_lineage: false,
            response,
        });
    }

    let results = append_receipt_batch(&store.pool, &mut VerifiedHead::default(), true, &requests);

    assert!(
        results[0].is_ok(),
        "the valid append must commit despite a bad sibling: {:?}",
        results[0]
    );
    assert!(
        results[1].is_err(),
        "the invalid receipt must fail in isolation: {:?}",
        results[1]
    );
    assert_eq!(
        store.tool_receipt_count()?,
        1,
        "only the valid receipt persists"
    );

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
                    ensure_lineage: false,
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
                ensure_lineage: false,
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

/// In a full group-commit batch, only the one invalid receipt fails; every
/// valid sibling still commits, via per-record savepoint isolation.
#[test]
fn append_receipt_batch_isolates_trailing_invalid_in_full_batch(
) -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipts-full-batch-isolation");
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
            ensure_lineage: false,
            response,
        });
    }

    let results = append_receipt_batch(&store.pool, &mut VerifiedHead::default(), true, &requests);
    let last = results.len() - 1;
    for (index, result) in results.iter().enumerate() {
        if index == last {
            assert!(
                matches!(
                    result,
                    Err(chio_kernel::ReceiptStoreError::Conflict(message))
                        if message.contains("receipt timestamp")
                ),
                "the trailing invalid receipt must fail: {result:?}"
            );
        } else {
            assert!(
                result.is_ok(),
                "valid receipt {index} must commit despite the trailing bad sibling: {result:?}"
            );
        }
    }
    assert_eq!(
        store.tool_receipt_count()?,
        (RECEIPT_GROUP_COMMIT_MAX_BATCH - 1) as u64,
        "every valid receipt persists; only the invalid one is dropped"
    );

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

/// `ensure_receipt_lineage_statement_for_receipt_id_tx` only inserts a
/// `receipt_lineage_statements` row for receipts carrying governed-transaction
/// call-chain metadata (see `tests/lineage.rs`); a bare `sample_receipt_with_id`
/// receipt never reaches the lineage insert at all. The atomicity fold under
/// test only matters for receipts that actually trigger that insert, so this
/// helper builds one.
fn sample_receipt_with_id_and_call_chain(id: &str) -> ChioReceipt {
    let keypair = receipt_test_keypair();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1,
            capability_id: "cap-1".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: valid_tool_action(serde_json::json!({"receipt": id})),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: format!("content-{id}"),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "governed_transaction": GovernedTransactionReceiptMetadata {
                    intent_id: format!("intent-{id}"),
                    intent_hash: format!("intent-hash-{id}"),
                    purpose: "atomic receipt+lineage fold test".to_string(),
                    server_id: "shell".to_string(),
                    tool_name: "bash".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    approval: None,
                    runtime_assurance: None,
                    call_chain: Some(GovernedCallChainProvenance::verified(
                        GovernedCallChainContext {
                            chain_id: format!("chain-{id}"),
                            parent_request_id: format!("req-parent-{id}"),
                            parent_receipt_id: None,
                            origin_subject: "subject-root".to_string(),
                            delegator_subject: "subject-delegator".to_string(),
                        },
                    )),
                    autonomy: None,
                    economic_authorization: None,
                }
            })),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .test_unwrap()
}

#[test]
fn receipt_and_lineage_commit_atomically() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-receipt-lineage-atomic");
    let store = SqliteReceiptStore::open(&path)?;

    // Baseline: the trait append writes receipt AND lineage in one tx.
    let receipt_ok = sample_receipt_with_id_and_call_chain("rcpt-atomic-ok");
    let seq = chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt_ok)?
        .ok_or("expected a claim-log seq")?;
    assert!(seq > 0);
    let connection = store.connection()?;
    let lineage_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        rusqlite::params![receipt_ok.id],
        |row| row.get(0),
    )?;
    assert_eq!(lineage_rows, 1, "lineage row must exist after append");
    drop(connection);

    // Inject a failure between the receipt insert and the lineage insert.
    test_hooks::FAIL_BETWEEN_RECEIPT_AND_LINEAGE.store(true, std::sync::atomic::Ordering::SeqCst);
    let receipt_fail = sample_receipt_with_id_and_call_chain("rcpt-atomic-fail");
    let result =
        chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt_fail);
    test_hooks::FAIL_BETWEEN_RECEIPT_AND_LINEAGE.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(
        matches!(result, Err(ReceiptStoreError::Conflict(_))),
        "injected failure must surface as Conflict, got {result:?}"
    );

    // The folded transaction rolled back: no receipt row, no claim-log row,
    // no lineage row survives (no receipt-without-lineage state possible).
    let connection = store.connection()?;
    let receipt_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![receipt_fail.id],
        |row| row.get(0),
    )?;
    let claim_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries WHERE receipt_id = ?1",
        rusqlite::params![receipt_fail.id],
        |row| row.get(0),
    )?;
    let lineage_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM receipt_lineage_statements WHERE receipt_id = ?1",
        rusqlite::params![receipt_fail.id],
        |row| row.get(0),
    )?;
    assert_eq!((receipt_rows, claim_rows, lineage_rows), (0, 0, 0));

    // The store is healthy again after the injected fault clears.
    let receipt_retry = sample_receipt_with_id("rcpt-atomic-retry");
    chio_kernel::ReceiptStore::append_chio_receipt_returning_seq(&store, &receipt_retry)?
        .ok_or("expected a claim-log seq on retry")?;

    let _ = fs::remove_file(path);
    Ok(())
}

/// Group-commit idempotency: when the SAME receipt is appended
/// concurrently and both requests land in one group-commit batch, the first
/// insert creates entry_seq E and the second (byte-identical duplicate)
/// returns that SAME E from `append_chio_receipt_tx`'s idempotent branch while
/// adding exactly one projection row. The batch's projection cross-check must
/// count DISTINCT new entry_seqs (1), not the two Ok results, or it would
/// false-trigger the projection-drift Conflict and roll back a valid batch.
#[test]
fn batched_duplicate_receipts_commit_without_false_drift() -> Result<(), Box<dyn std::error::Error>>
{
    let path = unique_db_path("chio-batch-dup-drift");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    let receipt = sample_receipt_with_keypair("rcpt-batch-dup-0", 1, &keypair);
    let raw_json = serde_json::to_string(&receipt)?;

    // Two byte-identical requests for the same receipt inside ONE batch: the
    // concurrent-duplicate group-commit scenario. `append_receipt_batch` never
    // touches `response`, so a discarded receiver is fine.
    let make_request = || {
        let (response, _rx) = std::sync::mpsc::sync_channel(1);
        ReceiptCommitRequest {
            receipt: receipt.clone(),
            raw_json: raw_json.clone(),
            ensure_lineage: false,
            response,
        }
    };
    let requests = vec![make_request(), make_request()];

    let mut head = {
        let connection = store.connection()?;
        seed_verified_head(&connection)?
    };
    let results = append_receipt_batch(
        &store.pool,
        &mut head,
        store.incremental_verification,
        &requests,
    );

    // The batch COMMITS: no projection-drift Conflict. Both results carry the
    // same entry_seq (the idempotent duplicate returns the original's E).
    assert!(
        results.iter().all(|result| result.is_ok()),
        "batched idempotent duplicate must commit, got {results:?}"
    );
    let seqs: std::collections::BTreeSet<u64> = results
        .iter()
        .filter_map(|result| result.as_ref().ok().copied())
        .collect();
    assert_eq!(seqs.len(), 1, "both requests must resolve to one entry_seq");

    // The head advances by the DISTINCT new-row count (1), not by 2.
    assert_eq!(head.claim_log_count, 1);
    assert_eq!(head.claim_log_max_seq, 1);

    // Exactly one projection row persisted.
    assert_eq!(load_claim_log_rows(&store).len(), 1);

    let _ = fs::remove_file(path);
    Ok(())
}

/// A coalesced group-commit batch must not abort entirely when one request
/// hits a per-receipt error (a conflicting duplicate raw JSON, a lineage insert
/// failure). Each record is wrapped in its own SAVEPOINT so a per-receipt
/// failure is isolated to that record: earlier successful inserts still commit,
/// and an unrelated valid append coalesced into the same batch is never lost.
/// Independent callers keep independent success/failure semantics.
#[test]
fn group_commit_isolates_per_record_failure() -> Result<(), Box<dyn std::error::Error>> {
    let path = unique_db_path("chio-group-commit-isolation");
    let keypair = receipt_test_keypair();
    let store = SqliteReceiptStore::open(&path)?;

    // Pre-commit a base receipt so its receipt_id already exists with its own
    // stored raw_json (claim-log entry 1).
    let base = sample_receipt_with_keypair("rcpt-p2-base", 1, &keypair);
    store.append_chio_receipt_returning_seq(&base)?;
    store.flush_receipt_writes()?;

    // One group-commit batch from three independent producers: two fresh valid
    // appends bracketing ONE bad request that reuses `base`'s receipt_id with
    // DIFFERENT raw JSON (a conflicting duplicate). `append_chio_receipt_tx`
    // rejects it with "already exists with different content".
    let good_one = sample_receipt_with_keypair("rcpt-p2-good-1", 2, &keypair);
    let good_two = sample_receipt_with_keypair("rcpt-p2-good-2", 3, &keypair);
    let (r0_tx, _r0) = std::sync::mpsc::sync_channel(1);
    let (r1_tx, _r1) = std::sync::mpsc::sync_channel(1);
    let (r2_tx, _r2) = std::sync::mpsc::sync_channel(1);
    let requests = vec![
        ReceiptCommitRequest {
            receipt: good_one.clone(),
            raw_json: serde_json::to_string(&good_one)?,
            ensure_lineage: false,
            response: r0_tx,
        },
        ReceiptCommitRequest {
            receipt: base.clone(),
            raw_json: "{\"conflicting\":\"payload\"}".to_string(),
            ensure_lineage: false,
            response: r1_tx,
        },
        ReceiptCommitRequest {
            receipt: good_two.clone(),
            raw_json: serde_json::to_string(&good_two)?,
            ensure_lineage: false,
            response: r2_tx,
        },
    ];

    let mut head = {
        let connection = store.connection()?;
        seed_verified_head(&connection)?
    };
    let results = append_receipt_batch(
        &store.pool,
        &mut head,
        store.incremental_verification,
        &requests,
    );

    // The two valid appends COMMIT; only the conflicting middle request fails.
    // A whole-batch rollback would instead fail all three and persist neither
    // good receipt.
    assert!(
        results[0].is_ok(),
        "first valid append must commit: {:?}",
        results[0]
    );
    assert!(
        results[1].is_err(),
        "the conflicting duplicate must fail: {:?}",
        results[1]
    );
    assert!(
        results[2].is_ok(),
        "third valid append must commit: {:?}",
        results[2]
    );
    match &results[1] {
        Err(ReceiptStoreError::Conflict(message)) => assert!(
            message.contains("different content"),
            "expected the conflicting-duplicate Conflict, got: {message}"
        ),
        other => {
            return Err(format!("expected a Conflict for the bad record, got {other:?}").into())
        }
    }

    // Both good receipts are DURABLY persisted, not rolled back with the bad
    // sibling.
    let connection = store.connection()?;
    let good_one_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![good_one.id],
        |row| row.get(0),
    )?;
    assert_eq!(
        good_one_rows, 1,
        "the first valid append must survive a batched sibling failure"
    );
    let good_two_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts WHERE receipt_id = ?1",
        rusqlite::params![good_two.id],
        |row| row.get(0),
    )?;
    assert_eq!(
        good_two_rows, 1,
        "the third valid append must survive a batched sibling failure"
    );

    let _ = fs::remove_file(path);
    Ok(())
}
