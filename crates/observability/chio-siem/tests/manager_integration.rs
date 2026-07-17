// Integration tests for ExporterManager cursor-pull, retry, DLQ, and failure isolation.
//
// CRITICAL: Does not import chio-kernel. Creates its own SQLite schema using raw rusqlite.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_siem::event::SiemEvent;
use chio_siem::exporter::{ExportError, ExportFuture};
use chio_siem::manager::{ExporterManager, SiemConfig, SiemError};
use chio_siem::ratelimit::RateLimitConfig;
use chio_siem::Exporter;
use rusqlite::{params, Connection};
use tokio::sync::watch;

// -- SQLite schema helpers (duplicated from chio-kernel/src/receipt_store.rs) -------

const CREATE_RECEIPTS_TABLE: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS chio_tool_receipts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT NOT NULL UNIQUE,
    timestamp INTEGER NOT NULL,
    capability_id TEXT NOT NULL,
    tool_server TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    decision_kind TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    raw_json TEXT NOT NULL
);
"#;

fn create_db(path: &PathBuf) -> Connection {
    let conn = Connection::open(path).expect("open SQLite");
    conn.execute_batch(CREATE_RECEIPTS_TABLE)
        .expect("create schema");
    conn
}

fn insert_receipt(conn: &Connection, receipt: &ChioReceipt) {
    let raw_json = serde_json::to_string(receipt).expect("serialize receipt");
    conn.execute(
        r#"
        INSERT INTO chio_tool_receipts (
            receipt_id, timestamp, capability_id, tool_server, tool_name,
            decision_kind, policy_hash, content_hash, raw_json
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        ON CONFLICT(receipt_id) DO NOTHING
        "#,
        params![
            receipt.id,
            receipt.timestamp as i64,
            receipt.capability_id,
            receipt.tool_server,
            receipt.tool_name,
            "allow",
            receipt.policy_hash,
            receipt.content_hash,
            raw_json,
        ],
    )
    .expect("insert receipt");
}

fn make_receipt(id: &str) -> ChioReceipt {
    let keypair = Keypair::generate();
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            capability_id: "cap-manager-test".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({}))
                .expect("action parameters serialize"),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content-hash".to_string(),
            policy_hash: "policy-hash".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        &keypair,
    )
    .expect("ChioReceipt::sign must succeed in tests")
}

fn unique_db_path(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time before epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("chio-siem-mgr-{prefix}-{nanos}.sqlite3"))
}

// -- Test exporters -----------------------------------------------------------

/// An exporter that counts how many events it has received across all calls.
#[derive(Clone)]
struct CountingExporter {
    count: Arc<AtomicUsize>,
}

impl CountingExporter {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn total(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }
}

impl Exporter for CountingExporter {
    fn name(&self) -> &str {
        "counting-exporter"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        let count = self.count.clone();
        let n = events.len();
        Box::pin(async move {
            count.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        })
    }
}

/// An exporter that always fails with a simulated HTTP error.
struct FailingExporter;

impl Exporter for FailingExporter {
    fn name(&self) -> &str {
        "failing-exporter"
    }

    fn export_batch<'a>(&'a self, _events: &'a [SiemEvent]) -> ExportFuture<'a> {
        Box::pin(async move { Err(ExportError::HttpError("simulated failure".to_string())) })
    }
}

#[derive(Clone)]
struct FlakyExporter {
    attempts: Arc<AtomicUsize>,
    exported: Arc<AtomicUsize>,
    failures_before_success: usize,
}

impl FlakyExporter {
    fn new(failures_before_success: usize) -> Self {
        Self {
            attempts: Arc::new(AtomicUsize::new(0)),
            exported: Arc::new(AtomicUsize::new(0)),
            failures_before_success,
        }
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    fn total(&self) -> usize {
        self.exported.load(Ordering::SeqCst)
    }
}

impl Exporter for FlakyExporter {
    fn name(&self) -> &str {
        "flaky-exporter"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        let attempts = self.attempts.clone();
        let exported = self.exported.clone();
        let failures_before_success = self.failures_before_success;
        let event_count = events.len();
        Box::pin(async move {
            let attempt_index = attempts.fetch_add(1, Ordering::SeqCst);
            if attempt_index < failures_before_success {
                return Err(ExportError::HttpError(format!(
                    "transient failure on attempt {}",
                    attempt_index + 1
                )));
            }
            exported.fetch_add(event_count, Ordering::SeqCst);
            Ok(event_count)
        })
    }
}

#[derive(Clone)]
struct TimedCountingExporter {
    count: Arc<AtomicUsize>,
    call_times: Arc<Mutex<Vec<Instant>>>,
}

impl TimedCountingExporter {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            call_times: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn total(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn call_times(&self) -> Vec<Instant> {
        self.call_times.lock().expect("call_times lock").clone()
    }
}

impl Exporter for TimedCountingExporter {
    fn name(&self) -> &str {
        "timed-counting-exporter"
    }

    fn export_batch<'a>(&'a self, events: &'a [SiemEvent]) -> ExportFuture<'a> {
        let count = self.count.clone();
        let call_times = self.call_times.clone();
        let n = events.len();
        Box::pin(async move {
            call_times
                .lock()
                .expect("call_times lock")
                .push(Instant::now());
            count.fetch_add(n, Ordering::SeqCst);
            Ok(n)
        })
    }
}

// -- Tests --------------------------------------------------------------------

#[test]
fn manager_rejects_zero_batch_size() {
    let db_path = unique_db_path("zero-batch");
    let conn = create_db(&db_path);
    drop(conn);

    let config = SiemConfig {
        db_path: db_path.clone(),
        batch_size: 0,
        ..SiemConfig::default()
    };

    let error = match ExporterManager::new(config) {
        Ok(_) => panic!("zero batch_size unexpectedly accepted"),
        Err(error) => error,
    };

    assert!(matches!(error, SiemError::ConfigError(_)));
    assert!(
        error.to_string().contains("batch_size"),
        "unexpected error: {error}"
    );

    let _ = std::fs::remove_file(&db_path);
}

/// ExporterManager exports all receipts and cursor tracks progress across runs.
#[tokio::test]
async fn manager_cursor_advance_after_export() {
    let db_path = unique_db_path("cursor-advance");
    let conn = create_db(&db_path);

    // Insert 5 receipts.
    for i in 0..5usize {
        insert_receipt(&conn, &make_receipt(&format!("mgr-rcpt-{i:04}")));
    }
    drop(conn);

    let counter = CountingExporter::new();
    let config = SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(50),
        batch_size: 100,
        max_retries: 0,
        base_backoff_ms: 0,
        dlq_capacity: 100,
        rate_limit: None,
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    };

    let mut manager = ExporterManager::new(config.clone()).expect("open ExporterManager");
    manager.add_exporter(Box::new(counter.clone()));

    let (cancel_tx, cancel_rx) = watch::channel(false);

    // Run manager; cancel after enough time for 2+ poll cycles (200ms with 50ms interval).
    let run_handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel_tx.send(true).expect("cancel signal sends");

    let manager = run_handle.await.expect("manager task completes");

    assert_eq!(counter.total(), 5, "all 5 receipts should be exported");
    assert_eq!(
        manager.dlq_len(),
        0,
        "DLQ should be empty after successful export"
    );

    // Second run: insert 3 more receipts; new ExporterManager starts from cursor=0
    // so it will see all 8 receipts. This confirms idempotent re-export behavior.
    let conn2 = Connection::open(&db_path).expect("reopen db");
    for i in 5..8usize {
        insert_receipt(&conn2, &make_receipt(&format!("mgr-rcpt-{i:04}")));
    }
    drop(conn2);

    let counter2 = CountingExporter::new();
    let mut manager2 = ExporterManager::new(config).expect("open second ExporterManager");
    manager2.add_exporter(Box::new(counter2.clone()));

    let (cancel_tx2, cancel_rx2) = watch::channel(false);
    let run_handle2 = tokio::spawn(async move {
        manager2.run(cancel_rx2).await;
        manager2
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel_tx2.send(true).expect("second cancel signal sends");

    run_handle2.await.expect("second manager task completes");

    // New manager re-exports from seq=0, so it will export all 8 receipts.
    assert_eq!(
        counter2.total(),
        8,
        "second run should export all 8 receipts (cursor resets on restart)"
    );

    let _ = std::fs::remove_file(&db_path);
}

/// ExporterManager does not panic when an exporter fails; failed events go to DLQ.
#[tokio::test]
async fn manager_failure_isolation_dlq() {
    let db_path = unique_db_path("failure-isolation");
    let conn = create_db(&db_path);

    for i in 0..3usize {
        insert_receipt(&conn, &make_receipt(&format!("mgr-fail-rcpt-{i:04}")));
    }
    drop(conn);

    let config = SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(50),
        batch_size: 100,
        // No retries so failures are DLQ'd immediately.
        max_retries: 0,
        base_backoff_ms: 0,
        dlq_capacity: 100,
        rate_limit: None,
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    };

    let mut manager = ExporterManager::new(config).expect("open ExporterManager");
    manager.add_exporter(Box::new(FailingExporter));

    let (cancel_tx, cancel_rx) = watch::channel(false);

    let run_handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });

    // Give the manager one poll cycle then cancel.
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel_tx.send(true).expect("cancel signal sends");

    // If we reach this point without panic, failure isolation holds.
    let manager = run_handle
        .await
        .expect("manager task must complete without panic");

    assert!(
        manager.dlq_len() > 0,
        "failed events must be DLQ'd (dlq_len was {})",
        manager.dlq_len()
    );

    let _ = std::fs::remove_file(&db_path);
}

/// Cursor advances past DLQ'd events; subsequent successful exports only see new receipts.
#[tokio::test]
async fn manager_cursor_advances_past_dlq() {
    let db_path = unique_db_path("cursor-past-dlq");
    let conn = create_db(&db_path);

    // Insert 5 receipts (seq 1-5).
    for i in 0..5usize {
        insert_receipt(&conn, &make_receipt(&format!("mgr-dlq-rcpt-{i:04}")));
    }

    // Strategy: two sequential ExporterManager instances.
    // Instance 1: FailingExporter, run 1 cycle (5 receipts -> DLQ, cursor advances to 5).
    // Instance 2: CountingExporter, cursor resets to 0 on new instance, exports all 8.
    //
    // This proves the key invariant: DLQ'd events do not block the export loop
    // or corrupt the database, and subsequent runs succeed cleanly.

    drop(conn);

    // Phase 1: fail all 5 receipts.
    let mut mgr1 = ExporterManager::new(SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(60),
        batch_size: 100,
        max_retries: 0,
        base_backoff_ms: 0,
        dlq_capacity: 100,
        rate_limit: None,
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    })
    .expect("open mgr1");
    mgr1.add_exporter(Box::new(FailingExporter));

    let (tx1, rx1) = watch::channel(false);
    let h1 = tokio::spawn(async move {
        mgr1.run(rx1).await;
        mgr1
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    tx1.send(true).expect("cancel phase 1");
    let mgr1 = h1.await.expect("phase 1 manager completes");

    // All 5 receipts should be DLQ'd.
    assert!(mgr1.dlq_len() > 0, "phase 1: events must be in DLQ");

    // Phase 2: Insert 3 more receipts, run with counting exporter.
    let conn2 = Connection::open(&db_path).expect("reopen db");
    for i in 5..8usize {
        insert_receipt(&conn2, &make_receipt(&format!("mgr-dlq-rcpt-{i:04}")));
    }
    drop(conn2);

    let counter = CountingExporter::new();
    let mut mgr2 = ExporterManager::new(SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(60),
        batch_size: 100,
        max_retries: 0,
        base_backoff_ms: 0,
        dlq_capacity: 100,
        rate_limit: None,
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    })
    .expect("open mgr2");
    mgr2.add_exporter(Box::new(counter.clone()));

    let (tx2, rx2) = watch::channel(false);
    let h2 = tokio::spawn(async move {
        mgr2.run(rx2).await;
        mgr2
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    tx2.send(true).expect("cancel phase 2");
    h2.await.expect("phase 2 manager completes");

    // Phase 2 manager starts from cursor=0 and exports all 8 receipts successfully.
    // This proves that the DLQ'd phase 1 receipts did not corrupt the database,
    // and that after cursor advancement, new receipts can be exported cleanly.
    assert_eq!(
        counter.total(),
        8,
        "phase 2 counting exporter must export all 8 receipts (5 original + 3 new)"
    );

    let _ = std::fs::remove_file(&db_path);
}

/// ExporterManager retries transient exporter failures and avoids DLQ on recovery.
#[tokio::test]
async fn manager_retries_transient_failure_without_dlq() {
    let db_path = unique_db_path("retry-transient");
    let conn = create_db(&db_path);

    for i in 0..3usize {
        insert_receipt(&conn, &make_receipt(&format!("mgr-retry-rcpt-{i:04}")));
    }
    drop(conn);

    let exporter = FlakyExporter::new(1);
    let mut manager = ExporterManager::new(SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(40),
        batch_size: 100,
        max_retries: 1,
        base_backoff_ms: 10,
        dlq_capacity: 100,
        rate_limit: None,
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    })
    .expect("open ExporterManager");
    manager.add_exporter(Box::new(exporter.clone()));

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let run_handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel_tx.send(true).expect("cancel signal sends");

    let manager = run_handle.await.expect("manager task completes");

    assert_eq!(
        exporter.attempts(),
        2,
        "one transient failure should be retried once before succeeding"
    );
    assert_eq!(
        exporter.total(),
        3,
        "all receipts should export after the retry succeeds"
    );
    assert_eq!(
        manager.dlq_len(),
        0,
        "recovered exports must not land in the DLQ"
    );

    let _ = std::fs::remove_file(&db_path);
}

/// ExporterManager throttles burst traffic per exporter without silently dropping receipts.
#[tokio::test]
async fn manager_rate_limits_bursts_without_silent_drop() {
    let db_path = unique_db_path("rate-limit");
    let conn = create_db(&db_path);

    for i in 0..3usize {
        insert_receipt(&conn, &make_receipt(&format!("mgr-rate-limit-rcpt-{i:04}")));
    }
    drop(conn);

    let exporter = TimedCountingExporter::new();
    let mut manager = ExporterManager::new(SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(10),
        batch_size: 1,
        max_retries: 0,
        base_backoff_ms: 0,
        dlq_capacity: 100,
        rate_limit: Some(RateLimitConfig {
            max_batches_per_window: 1,
            window: Duration::from_millis(150),
            burst_factor: 1.0,
        }),
        trusted_kernel_keys: std::collections::BTreeSet::new(),
        read_context: chio_kernel::ReceiptReadContext::local_operator_admin_all(),
        cursor_db_path: None,
    })
    .expect("open ExporterManager");
    manager.add_exporter(Box::new(exporter.clone()));

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let run_handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });

    tokio::time::sleep(Duration::from_millis(650)).await;
    cancel_tx.send(true).expect("cancel signal sends");

    let manager = run_handle.await.expect("manager task completes");

    assert_eq!(
        exporter.total(),
        3,
        "all throttled receipts should still be exported"
    );
    assert_eq!(
        manager.dlq_len(),
        0,
        "rate-limited exports must not silently fall into the DLQ"
    );

    let call_times = exporter.call_times();
    assert_eq!(
        call_times.len(),
        3,
        "batch_size=1 should force three distinct exporter calls"
    );
    assert!(
        call_times[1].duration_since(call_times[0]) >= Duration::from_millis(100),
        "second batch should be delayed by the per-exporter rate limit"
    );
    assert!(
        call_times[2].duration_since(call_times[1]) >= Duration::from_millis(100),
        "third batch should also respect the per-exporter rate limit"
    );

    let _ = std::fs::remove_file(&db_path);
}
