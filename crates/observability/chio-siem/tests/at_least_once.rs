//! At-least-once SIEM delivery with a persisted high-water mark, and malformed
//! rows captured (not silently skipped).
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chio_siem::cursor_store::SiemCursorStore;
use chio_siem::manager::{ExporterManager, SiemConfig};
use chio_siem::{ExportOutcome, SiemMetricsSink};
use proptest::prelude::*;
use rusqlite::Connection;
use tokio::sync::watch;

#[test]
fn cursor_store_persists_and_min_acked_resumes() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("cursor.sqlite3");
    {
        let store = SiemCursorStore::open(&path)?;
        store.set_acked("splunk", 100)?;
        store.set_acked("elastic", 40)?;
        assert_eq!(store.min_acked()?, Some(40));
    }
    // Reopen: acked marks survive, so resume is targeted, not seq=0.
    let store = SiemCursorStore::open(&path)?;
    let acked = store.acked_seqs()?;
    assert_eq!(acked.get("splunk"), Some(&100));
    assert_eq!(acked.get("elastic"), Some(&40));
    assert_eq!(store.min_acked()?, Some(40));
    // Monotonic: a lower value never regresses the mark.
    store.set_acked("splunk", 90)?;
    assert_eq!(store.acked_seqs()?.get("splunk"), Some(&100));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]
    #[test]
    fn siem_high_water_mark_never_skips(
        outage_pattern in prop::collection::vec(any::<bool>(), 1..24)
    ) {
        // Model: an exporter that is "down" on ticks where the pattern is true
        // (export fails -> no ack) and "up" otherwise. Assert the high-water mark
        // is monotonic and, once up long enough, covers every seq (no skip).
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SiemCursorStore::open(&dir.path().join("c.sqlite3")).expect("open");
        let total: u64 = 20;
        let mut cursor = store.min_acked().expect("min").unwrap_or(0);
        for down in &outage_pattern {
            if cursor >= total {
                break;
            }
            let batch_end = (cursor + 5).min(total);
            if !*down {
                store.set_acked("splunk", batch_end).expect("ack");
                cursor = store.min_acked().expect("min").unwrap_or(0);
            }
            // Down: no ack, cursor holds -> the same range is redelivered.
        }
        // Drain any remaining while up.
        while cursor < total {
            let batch_end = (cursor + 5).min(total);
            store.set_acked("splunk", batch_end).expect("ack");
            cursor = store.min_acked().expect("min").unwrap_or(0);
        }
        let acked = store.acked_seqs().expect("acked");
        prop_assert_eq!(acked.get("splunk"), Some(&total));
    }
}

const CREATE_RECEIPTS_TABLE: &str = r#"
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

#[derive(Default)]
struct RecordingSink {
    outcomes: Mutex<Vec<(String, String)>>,
}

impl SiemMetricsSink for RecordingSink {
    fn record_export(&self, exporter: &str, outcome: ExportOutcome) {
        self.outcomes
            .lock()
            .expect("lock")
            .push((exporter.to_string(), outcome.as_label().to_string()));
    }
    fn observe_export_lag(&self, _: &str, _: &str, _: f64) {}
    fn set_dlq_depth(&self, _: &str, _: u64) {}
    fn record_alert_dispatch(&self, _: &str, _: &str) {}
    fn observe_alert_dispatch_latency(&self, _: &str, _: &str, _: f64) {}
}

impl RecordingSink {
    fn saw_malformed(&self) -> bool {
        self.outcomes
            .lock()
            .expect("lock")
            .iter()
            .any(|(_, outcome)| outcome == "malformed")
    }
}

#[tokio::test]
async fn malformed_row_is_captured_not_silently_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path: PathBuf = dir.path().join("receipts.sqlite3");
    {
        let conn = Connection::open(&db_path).expect("open receipt db");
        conn.execute_batch(CREATE_RECEIPTS_TABLE)
            .expect("create schema");
        // A malformed raw_json row: valid schema columns, invalid JSON payload.
        conn.execute(
            "INSERT INTO chio_tool_receipts (receipt_id, timestamp, capability_id, \
             tool_server, tool_name, decision_kind, policy_hash, content_hash, raw_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                "malformed-1",
                1_712_345_678i64,
                "cap",
                "srv",
                "tool",
                "allow",
                "policy",
                "content",
                "this is not valid receipt json",
            ],
        )
        .expect("insert malformed row");
    }

    let recorder = Arc::new(RecordingSink::default());
    let config = SiemConfig {
        db_path: db_path.clone(),
        poll_interval: Duration::from_millis(10),
        ..SiemConfig::default()
    };
    let mut manager = ExporterManager::new(config)
        .expect("open manager")
        .with_metrics_sink(Arc::clone(&recorder) as Arc<dyn SiemMetricsSink>);

    let (cancel_tx, cancel_rx) = watch::channel(false);
    let run_handle = tokio::spawn(async move {
        manager.run(cancel_rx).await;
        manager
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    cancel_tx.send(true).expect("cancel");
    let manager = run_handle.await.expect("join");

    assert!(
        recorder.saw_malformed(),
        "a malformed row must record outcome=malformed"
    );
    assert!(
        manager.dlq_len() >= 1,
        "a malformed row must land a replayable DLQ entry, dlq_len={}",
        manager.dlq_len()
    );
}
