//! Per-session journal for the Chio runtime.
//!
//! This crate provides an append-only, hash-chained journal that tracks
//! request history, cumulative data flow (bytes read/written), delegation
//! depth, and tool invocation sequence within a single session.
//!
//! The journal persists across requests within a session and is available
//! to all guards. Entries are tamper-evident: each entry includes a SHA-256
//! hash of the previous entry, forming a hash chain.
//!
//! # Design
//!
//! - **Append-only**: entries can only be added, never modified or removed.
//! - **Hash-chained**: each entry hashes the previous entry's hash for
//!   tamper detection.
//! - **Thread-safe**: the journal is wrapped in a `Mutex` for safe concurrent
//!   access from multiple guards.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors produced by the session journal.
#[derive(Debug, thiserror::Error)]
pub enum SessionJournalError {
    /// The journal's internal lock was poisoned.
    #[error("session journal lock poisoned")]
    LockPoisoned,

    /// Hash chain integrity check failed.
    #[error("hash chain integrity violation at entry {index}: expected {expected}, got {actual}")]
    IntegrityViolation {
        index: usize,
        expected: String,
        actual: String,
    },
}

// ---------------------------------------------------------------------------
// Journal entry
// ---------------------------------------------------------------------------

/// A single entry in the session journal.
///
/// Each entry records a tool invocation along with data flow metrics and
/// a hash link to the previous entry for tamper detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Monotonically increasing sequence number within the session (0-based).
    pub sequence: u64,
    /// SHA-256 hash of the previous entry's canonical representation.
    /// The first entry uses the zero hash (64 hex zeros).
    pub prev_hash: String,
    /// SHA-256 hash of this entry's canonical representation (computed on append).
    pub entry_hash: String,
    /// Unix timestamp (seconds) when this entry was recorded.
    pub timestamp_secs: u64,
    /// The tool that was invoked.
    pub tool_name: String,
    /// The server that hosted the tool.
    pub server_id: String,
    /// The agent that made the invocation.
    pub agent_id: String,
    /// Bytes read during this invocation.
    pub bytes_read: u64,
    /// Bytes written during this invocation.
    pub bytes_written: u64,
    /// Delegation depth at the time of invocation.
    pub delegation_depth: u32,
    /// Whether the invocation was allowed or denied.
    pub allowed: bool,
}

/// The zero hash used as prev_hash for the first entry.
const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute the SHA-256 hash of an entry's canonical fields (excluding entry_hash).
fn compute_entry_hash(entry: &JournalEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.sequence.to_le_bytes());
    hasher.update(entry.prev_hash.as_bytes());
    hasher.update(entry.timestamp_secs.to_le_bytes());
    hasher.update(entry.tool_name.as_bytes());
    hasher.update(entry.server_id.as_bytes());
    hasher.update(entry.agent_id.as_bytes());
    hasher.update(entry.bytes_read.to_le_bytes());
    hasher.update(entry.bytes_written.to_le_bytes());
    hasher.update(entry.delegation_depth.to_le_bytes());
    hasher.update(if entry.allowed { &[1u8] } else { &[0u8] });
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Cumulative stats
// ---------------------------------------------------------------------------

/// Cumulative data flow statistics for a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CumulativeDataFlow {
    /// Total bytes read across all invocations in the session.
    pub total_bytes_read: u64,
    /// Total bytes written across all invocations in the session.
    pub total_bytes_written: u64,
    /// Total number of tool invocations recorded.
    pub total_invocations: u64,
    /// Maximum delegation depth seen in the session.
    pub max_delegation_depth: u32,
}

// ---------------------------------------------------------------------------
// Session journal (inner, not thread-safe)
// ---------------------------------------------------------------------------

/// Inner journal state (not thread-safe -- wrapped by `SessionJournal`).
#[derive(Debug)]
struct JournalInner {
    /// The ordered list of entries.
    entries: Vec<JournalEntry>,
    /// Cumulative data flow stats.
    data_flow: CumulativeDataFlow,
    /// Tool invocation sequence (tool names in order).
    tool_sequence: Vec<String>,
    /// Per-tool invocation counts.
    tool_counts: HashMap<String, u64>,
}

impl JournalInner {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            data_flow: CumulativeDataFlow::default(),
            tool_sequence: Vec::new(),
            tool_counts: HashMap::new(),
        }
    }

    fn last_hash(&self) -> &str {
        self.entries
            .last()
            .map(|e| e.entry_hash.as_str())
            .unwrap_or(ZERO_HASH)
    }
}

// ---------------------------------------------------------------------------
// Session journal (thread-safe public API)
// ---------------------------------------------------------------------------

/// Thread-safe, append-only, hash-chained session journal.
///
/// Create one per session and share it (via `Arc<SessionJournal>`) with all
/// guards that need session-aware context.
pub struct SessionJournal {
    inner: Mutex<JournalInner>,
    session_id: String,
}

impl std::fmt::Debug for SessionJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionJournal")
            .field("session_id", &self.session_id)
            .finish()
    }
}

/// Parameters for recording a journal entry.
#[derive(Debug, Clone)]
pub struct RecordParams {
    /// The tool that was invoked.
    pub tool_name: String,
    /// The server hosting the tool.
    pub server_id: String,
    /// The agent making the request.
    pub agent_id: String,
    /// Bytes read during this invocation.
    pub bytes_read: u64,
    /// Bytes written during this invocation.
    pub bytes_written: u64,
    /// Current delegation depth.
    pub delegation_depth: u32,
    /// Whether the invocation was allowed.
    pub allowed: bool,
}

impl SessionJournal {
    fn lock_inner(&self) -> Result<MutexGuard<'_, JournalInner>, SessionJournalError> {
        self.inner
            .lock()
            .map_err(|_| SessionJournalError::LockPoisoned)
    }

    /// Create a new empty journal for the given session.
    pub fn new(session_id: String) -> Self {
        Self {
            inner: Mutex::new(JournalInner::new()),
            session_id,
        }
    }

    /// Return the session identifier.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Append a new entry to the journal.
    ///
    /// The entry is hash-chained to the previous entry. Returns the
    /// sequence number of the new entry.
    pub fn record(&self, params: RecordParams) -> Result<u64, SessionJournalError> {
        let mut inner = self.lock_inner()?;

        let sequence = inner.entries.len() as u64;
        let prev_hash = inner.last_hash().to_string();
        let timestamp_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let tool_name = params.tool_name;
        let mut entry = JournalEntry {
            sequence,
            prev_hash,
            entry_hash: String::new(),
            timestamp_secs,
            tool_name: tool_name.clone(),
            server_id: params.server_id,
            agent_id: params.agent_id,
            bytes_read: params.bytes_read,
            bytes_written: params.bytes_written,
            delegation_depth: params.delegation_depth,
            allowed: params.allowed,
        };
        entry.entry_hash = compute_entry_hash(&entry);

        // Update cumulative stats.
        inner.data_flow.total_bytes_read = inner
            .data_flow
            .total_bytes_read
            .saturating_add(params.bytes_read);
        inner.data_flow.total_bytes_written = inner
            .data_flow
            .total_bytes_written
            .saturating_add(params.bytes_written);
        inner.data_flow.total_invocations = inner.data_flow.total_invocations.saturating_add(1);
        inner.data_flow.max_delegation_depth = inner
            .data_flow
            .max_delegation_depth
            .max(params.delegation_depth);

        // Update tool sequence and counts.
        inner.tool_sequence.push(tool_name.clone());
        let count = inner.tool_counts.entry(tool_name).or_insert(0);
        *count = count.saturating_add(1);

        inner.entries.push(entry);

        Ok(sequence)
    }

    /// Return a snapshot of the cumulative data flow statistics.
    pub fn data_flow(&self) -> Result<CumulativeDataFlow, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.data_flow.clone())
    }

    /// Return the ordered tool invocation sequence.
    pub fn tool_sequence(&self) -> Result<Vec<String>, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.tool_sequence.clone())
    }

    /// Return per-tool invocation counts.
    pub fn tool_counts(&self) -> Result<HashMap<String, u64>, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.tool_counts.clone())
    }

    /// Return the number of entries in the journal.
    pub fn len(&self) -> Result<usize, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.entries.len())
    }

    /// Return whether the journal is empty.
    pub fn is_empty(&self) -> Result<bool, SessionJournalError> {
        Ok(self.len()? == 0)
    }

    /// Return a clone of all journal entries.
    pub fn entries(&self) -> Result<Vec<JournalEntry>, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.entries.clone())
    }

    /// Return the most recent N entries (or all if fewer than N exist).
    pub fn recent_entries(&self, n: usize) -> Result<Vec<JournalEntry>, SessionJournalError> {
        let inner = self.lock_inner()?;
        let start = inner.entries.len().saturating_sub(n);
        Ok(inner.entries[start..].to_vec())
    }

    /// Verify the integrity of the hash chain.
    ///
    /// Returns `Ok(())` if all entries are correctly chained, or an error
    /// indicating where the chain breaks.
    pub fn verify_integrity(&self) -> Result<(), SessionJournalError> {
        let inner = self.lock_inner()?;

        for (index, entry) in inner.entries.iter().enumerate() {
            // Check prev_hash linkage.
            let expected_prev = if index == 0 {
                ZERO_HASH
            } else {
                inner.entries[index - 1].entry_hash.as_str()
            };

            if entry.prev_hash != expected_prev {
                return Err(SessionJournalError::IntegrityViolation {
                    index,
                    expected: expected_prev.to_string(),
                    actual: entry.prev_hash.clone(),
                });
            }

            // Recompute entry hash to detect tampering.
            let recomputed = compute_entry_hash(entry);
            if entry.entry_hash != recomputed {
                return Err(SessionJournalError::IntegrityViolation {
                    index,
                    expected: recomputed,
                    actual: entry.entry_hash.clone(),
                });
            }
        }

        Ok(())
    }

    /// Return the hash of the most recent entry (or the zero hash if empty).
    pub fn head_hash(&self) -> Result<String, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.last_hash().to_string())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params(tool: &str) -> RecordParams {
        RecordParams {
            tool_name: tool.to_string(),
            server_id: "srv-1".to_string(),
            agent_id: "agent-1".to_string(),
            bytes_read: 100,
            bytes_written: 50,
            delegation_depth: 0,
            allowed: true,
        }
    }

    #[test]
    fn empty_journal() {
        let journal = SessionJournal::new("sess-1".to_string());
        assert_eq!(journal.len().unwrap(), 0);
        assert!(journal.is_empty().unwrap());
        assert_eq!(journal.head_hash().unwrap(), ZERO_HASH);
    }

    #[test]
    fn single_entry() {
        let journal = SessionJournal::new("sess-1".to_string());
        let seq = journal.record(test_params("read_file")).unwrap();
        assert_eq!(seq, 0);
        assert_eq!(journal.len().unwrap(), 1);
        assert!(!journal.is_empty().unwrap());

        let entries = journal.entries().unwrap();
        assert_eq!(entries[0].prev_hash, ZERO_HASH);
        assert!(!entries[0].entry_hash.is_empty());
        assert_eq!(entries[0].tool_name, "read_file");
    }

    #[test]
    fn hash_chain_links() {
        let journal = SessionJournal::new("sess-chain".to_string());
        journal.record(test_params("read_file")).unwrap();
        journal.record(test_params("write_file")).unwrap();
        journal.record(test_params("bash")).unwrap();

        let entries = journal.entries().unwrap();
        assert_eq!(entries[0].prev_hash, ZERO_HASH);
        assert_eq!(entries[1].prev_hash, entries[0].entry_hash);
        assert_eq!(entries[2].prev_hash, entries[1].entry_hash);
    }

    #[test]
    fn integrity_check_passes() {
        let journal = SessionJournal::new("sess-integrity".to_string());
        for tool in &["read_file", "write_file", "bash", "http_request"] {
            journal.record(test_params(tool)).unwrap();
        }
        assert!(journal.verify_integrity().is_ok());
    }

    #[test]
    fn cumulative_data_flow() {
        let journal = SessionJournal::new("sess-flow".to_string());
        journal
            .record(RecordParams {
                tool_name: "read_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 200,
                bytes_written: 0,
                delegation_depth: 0,
                allowed: true,
            })
            .unwrap();
        journal
            .record(RecordParams {
                tool_name: "write_file".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 0,
                bytes_written: 300,
                delegation_depth: 1,
                allowed: true,
            })
            .unwrap();

        let flow = journal.data_flow().unwrap();
        assert_eq!(flow.total_bytes_read, 200);
        assert_eq!(flow.total_bytes_written, 300);
        assert_eq!(flow.total_invocations, 2);
        assert_eq!(flow.max_delegation_depth, 1);
    }

    #[test]
    fn tool_sequence_tracking() {
        let journal = SessionJournal::new("sess-seq".to_string());
        journal.record(test_params("read_file")).unwrap();
        journal.record(test_params("bash")).unwrap();
        journal.record(test_params("read_file")).unwrap();

        let seq = journal.tool_sequence().unwrap();
        assert_eq!(seq, vec!["read_file", "bash", "read_file"]);

        let counts = journal.tool_counts().unwrap();
        assert_eq!(counts.get("read_file"), Some(&2));
        assert_eq!(counts.get("bash"), Some(&1));
    }

    #[test]
    fn recent_entries_subset() {
        let journal = SessionJournal::new("sess-recent".to_string());
        for i in 0..10 {
            journal.record(test_params(&format!("tool_{i}"))).unwrap();
        }

        let recent = journal.recent_entries(3).unwrap();
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].tool_name, "tool_7");
        assert_eq!(recent[1].tool_name, "tool_8");
        assert_eq!(recent[2].tool_name, "tool_9");
    }

    #[test]
    fn recent_entries_all_when_fewer() {
        let journal = SessionJournal::new("sess-few".to_string());
        journal.record(test_params("tool_a")).unwrap();
        journal.record(test_params("tool_b")).unwrap();

        let recent = journal.recent_entries(10).unwrap();
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn session_id_accessible() {
        let journal = SessionJournal::new("my-session-42".to_string());
        assert_eq!(journal.session_id(), "my-session-42");
    }

    #[test]
    fn denied_invocations_tracked() {
        let journal = SessionJournal::new("sess-denied".to_string());
        journal
            .record(RecordParams {
                tool_name: "bash".to_string(),
                server_id: "srv".to_string(),
                agent_id: "agent".to_string(),
                bytes_read: 0,
                bytes_written: 0,
                delegation_depth: 0,
                allowed: false,
            })
            .unwrap();

        let entries = journal.entries().unwrap();
        assert!(!entries[0].allowed);
        // Denied invocations still count toward totals.
        let flow = journal.data_flow().unwrap();
        assert_eq!(flow.total_invocations, 1);
    }

    #[test]
    fn entry_hash_determinism() {
        // Two entries with the same fields should produce the same hash.
        let e1 = JournalEntry {
            sequence: 0,
            prev_hash: ZERO_HASH.to_string(),
            entry_hash: String::new(),
            timestamp_secs: 1700000000,
            tool_name: "read_file".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            bytes_read: 100,
            bytes_written: 0,
            delegation_depth: 0,
            allowed: true,
        };
        let e2 = e1.clone();
        assert_eq!(compute_entry_hash(&e1), compute_entry_hash(&e2));
    }

    #[test]
    fn entry_hash_changes_with_content() {
        let e1 = JournalEntry {
            sequence: 0,
            prev_hash: ZERO_HASH.to_string(),
            entry_hash: String::new(),
            timestamp_secs: 1700000000,
            tool_name: "read_file".to_string(),
            server_id: "srv".to_string(),
            agent_id: "agent".to_string(),
            bytes_read: 100,
            bytes_written: 0,
            delegation_depth: 0,
            allowed: true,
        };
        let mut e2 = e1.clone();
        e2.bytes_read = 999;
        assert_ne!(compute_entry_hash(&e1), compute_entry_hash(&e2));
    }

    #[test]
    fn serde_roundtrip() {
        let journal = SessionJournal::new("sess-serde".to_string());
        journal.record(test_params("read_file")).unwrap();

        let entries = journal.entries().unwrap();
        let json = serde_json::to_string_pretty(&entries).unwrap();
        let restored: Vec<JournalEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(entries.len(), restored.len());
        assert_eq!(entries[0].entry_hash, restored[0].entry_hash);
        assert_eq!(entries[0].tool_name, restored[0].tool_name);
    }
}
