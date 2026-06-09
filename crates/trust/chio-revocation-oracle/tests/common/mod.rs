#![allow(dead_code)]
//! Shared on-disk receipt log used by `swarm_revocation_e2e` (the writer)
//! and `receipt_chain_proof` (the reader).
//!
//! The writer emits one JSONL line per consult (`allow` or `deny`) plus
//! header / per-trial summary / footer lines. The reader walks the file
//! and asserts the receipt-chain invariant `seen_epoch < revoke_epoch` on
//! every allow line.
//!
//! The schema is intentionally tiny and self-describing so the file
//! can also be inspected by hand from a CI artifact.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

/// Top-of-file header. Records the trial budget so the reader can assert
/// it matches the value its own gate runs against.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptHeader {
    pub kind: String,
    pub trials: u64,
    pub median_budget_ms: u64,
}

/// One consult event. Emitted by every iteration of the per-child
/// tight loop in the writer test.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptRecord {
    pub kernel_id: String,
    pub cap_id: String,
    pub ts_unix_us: u64,
    pub seen_epoch: u64,
    pub decision: String,
}

/// Per-trial summary line. Records the planner-oracle epoch advanced
/// during the trial alongside the wall-clock revoke->deny latency.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrialSummary {
    pub kind: String,
    pub trial_idx: u64,
    pub revoke_epoch: u64,
    pub revoke_to_deny_ms: u128,
}

/// Footer line. Records the run's median latency so the reader can
/// confirm the file is from a complete run, not a partial one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptFooter {
    pub kind: String,
    pub median_ms: u128,
    pub budget_ms: u128,
}

/// Wraps the JSONL writer for the receipt log file. Cheap to
/// `clone_writer()` so per-thread consult loops can append concurrently.
pub struct ReceiptLog {
    writer: Arc<Mutex<File>>,
    path: PathBuf,
}

impl ReceiptLog {
    pub fn create(path: &Path) -> std::io::Result<Self> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let file = OpenOptions::new().create_new(true).write(true).open(path)?;
        Ok(Self {
            writer: Arc::new(Mutex::new(file)),
            path: path.to_path_buf(),
        })
    }

    pub fn clone_writer(&self) -> Arc<Mutex<File>> {
        Arc::clone(&self.writer)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_header(&self, trials: usize, median_budget_ms: u64) {
        let header = ReceiptHeader {
            kind: "header".to_string(),
            trials: trials as u64,
            median_budget_ms,
        };
        write_json_line(&self.writer, &header);
    }

    pub fn write_trial_summary(&self, trial_idx: u64, revoke_epoch: u64, revoke_to_deny_ms: u128) {
        let summary = TrialSummary {
            kind: "trial_summary".to_string(),
            trial_idx,
            revoke_epoch,
            revoke_to_deny_ms,
        };
        write_json_line(&self.writer, &summary);
    }

    pub fn write_footer(&self, median_ms: u128, budget_ms: u128) {
        let footer = ReceiptFooter {
            kind: "footer".to_string(),
            median_ms,
            budget_ms,
        };
        write_json_line(&self.writer, &footer);
    }
}

pub fn write_record(writer: &Arc<Mutex<File>>, record: &ReceiptRecord) {
    write_json_line(writer, record);
}

fn write_json_line<T: Serialize>(writer: &Arc<Mutex<File>>, value: &T) {
    let line = match serde_json::to_string(value) {
        Ok(line) => line,
        Err(err) => {
            // Test instrumentation: never silently drop, but never
            // panic on a serialization edge either, just record on
            // stderr so the test still surfaces the underlying
            // failure mode.
            eprintln!("receipt-log serialize error: {err}");
            return;
        }
    };
    if let Ok(mut guard) = writer.lock() {
        let _ = writeln!(guard, "{line}");
    }
}

/// Read a JSONL receipt log into typed records. Used by the proof
/// test. Returns the header, every trial summary, every consult
/// receipt, and the footer.
pub struct ReadbackLog {
    pub header: ReceiptHeader,
    pub trials: Vec<TrialSummary>,
    pub records: Vec<ReceiptRecord>,
    pub footer: ReceiptFooter,
}

pub fn read_log(path: &Path) -> Result<ReadbackLog, String> {
    let bytes = std::fs::read(path).map_err(|err| format!("read {path:?}: {err}"))?;
    let text = String::from_utf8(bytes).map_err(|err| format!("utf8 {path:?}: {err}"))?;

    let mut header: Option<ReceiptHeader> = None;
    let mut footer: Option<ReceiptFooter> = None;
    let mut trials: Vec<TrialSummary> = Vec::new();
    let mut records: Vec<ReceiptRecord> = Vec::new();

    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        // Dispatch by inspecting the structural fields rather than a
        // serde tag enum: the four record types use disjoint field
        // names (`decision` is unique to ReceiptRecord;
        // `medianMs` is unique to ReceiptFooter; `medianBudgetMs` to
        // ReceiptHeader; `trialIdx` to TrialSummary), so a tiny
        // first-pass `Value` lookup picks the right type without
        // requiring every emitter to embed a discriminator string.
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|err| format!("parse line {}: {err}: {line}", idx + 1))?;
        if value.get("decision").is_some() {
            let r: ReceiptRecord = serde_json::from_value(value)
                .map_err(|err| format!("parse record line {}: {err}", idx + 1))?;
            records.push(r);
        } else if value.get("medianMs").is_some() {
            let f: ReceiptFooter = serde_json::from_value(value)
                .map_err(|err| format!("parse footer line {}: {err}", idx + 1))?;
            footer = Some(f);
        } else if value.get("medianBudgetMs").is_some() {
            let h: ReceiptHeader = serde_json::from_value(value)
                .map_err(|err| format!("parse header line {}: {err}", idx + 1))?;
            header = Some(h);
        } else if value.get("trialIdx").is_some() {
            let t: TrialSummary = serde_json::from_value(value)
                .map_err(|err| format!("parse trial line {}: {err}", idx + 1))?;
            trials.push(t);
        } else {
            return Err(format!("unrecognised receipt-log line {}: {line}", idx + 1));
        }
    }

    let header = header.ok_or_else(|| "missing header line".to_string())?;
    let footer = footer.ok_or_else(|| "missing footer line".to_string())?;
    Ok(ReadbackLog {
        header,
        trials,
        records,
        footer,
    })
}
