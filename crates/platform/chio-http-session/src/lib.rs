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

    /// A record field was empty, padded, or contained control characters.
    #[error("session journal record field {field} must be non-empty, unpadded, and control-free")]
    InvalidRecordField { field: &'static str },

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

fn update_len_prefixed(hasher: &mut Sha256, value: &str) {
    let bytes = value.as_bytes();
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Compute the SHA-256 hash of an entry's canonical fields (excluding entry_hash).
fn compute_entry_hash(entry: &JournalEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry.sequence.to_le_bytes());
    update_len_prefixed(&mut hasher, &entry.prev_hash);
    hasher.update(entry.timestamp_secs.to_le_bytes());
    update_len_prefixed(&mut hasher, &entry.tool_name);
    update_len_prefixed(&mut hasher, &entry.server_id);
    update_len_prefixed(&mut hasher, &entry.agent_id);
    hasher.update(entry.bytes_read.to_le_bytes());
    hasher.update(entry.bytes_written.to_le_bytes());
    hasher.update(entry.delegation_depth.to_le_bytes());
    hasher.update([u8::from(entry.allowed)]);
    hex::encode(hasher.finalize())
}

fn validate_record_field(value: &str, field: &'static str) -> Result<(), SessionJournalError> {
    if value.trim().is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(SessionJournalError::InvalidRecordField { field });
    }
    Ok(())
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

/// Immutable guard-read snapshot captured under one journal lock.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionJournalSnapshot {
    /// Session identifier for the journal that produced this snapshot.
    pub session_id: String,
    /// Number of entries present when the snapshot was captured.
    pub entry_count: usize,
    /// Hash of the most recent entry, or the zero hash for an empty journal.
    pub head_hash: String,
    /// Cumulative data flow state.
    pub data_flow: CumulativeDataFlow,
    /// Ordered tool invocation sequence.
    pub tool_sequence: Vec<String>,
    /// Per-tool invocation counts.
    pub tool_counts: HashMap<String, u64>,
    /// The tool name of the current consecutive run (the last tool recorded), or
    /// `None` if nothing has been recorded. Cumulative and O(1): it survives ring
    /// eviction so a same-tool streak longer than `journal_entry_cap` is still
    /// counted in full.
    pub current_streak_tool: Option<String>,
    /// Length of the current consecutive run of `current_streak_tool`. Resets to
    /// 1 whenever a different tool is recorded, so it stays bounded semantically
    /// (a single running count, not a growing collection).
    pub current_streak_len: u64,
}

// ---------------------------------------------------------------------------
// Session journal (inner, not thread-safe)
// ---------------------------------------------------------------------------

/// Default entry-ring capacity when a journal is created without an explicit
/// budget, single-sourced from the process memory budget
/// ([`chio_kernel::MemoryBudgetConfig`]'s `journal_entry_cap`) rather than a
/// duplicated literal, so lowering the budget lowers this cap. The `entries` and
/// `tool_sequence` rings are bounded; `data_flow` stays cumulative and
/// `tool_counts` is cumulative but distinct-key bounded (see
/// [`default_journal_tool_counts_cap`]).
fn default_journal_entry_cap() -> usize {
    chio_kernel::MemoryBudgetConfig::defaults().journal_entry_cap
}

/// Default distinct-tool-name cap for the cumulative `tool_counts` map,
/// single-sourced from the process memory budget
/// ([`chio_kernel::MemoryBudgetConfig`]'s `journal_tool_counts_cap`) so lowering
/// the budget lowers this cap.
fn default_journal_tool_counts_cap() -> usize {
    chio_kernel::MemoryBudgetConfig::defaults().journal_tool_counts_cap
}

/// Fold an evicted entry's hash into the running head hash so the dropped prefix
/// stays committed after eviction.
fn fold_head_hash(prev: Option<&str>, evicted_entry_hash: &str) -> String {
    let mut hasher = Sha256::new();
    update_len_prefixed(&mut hasher, prev.unwrap_or(""));
    update_len_prefixed(&mut hasher, evicted_entry_hash);
    hex::encode(hasher.finalize())
}

/// Inner journal state (not thread-safe -- wrapped by `SessionJournal`).
#[derive(Debug)]
struct JournalInner {
    /// The capacity-bounded ring of retained entries.
    entries: chio_bounded::Ring<JournalEntry>,
    /// Running fold over the hashes of entries evicted from the ring, so the
    /// chain stays committed after the prefix is dropped. `None` until the first
    /// eviction.
    evicted_head_hash: Option<String>,
    /// Monotonic sequence counter, independent of the (bounded) ring length so
    /// sequence numbers never repeat after eviction.
    next_sequence: u64,
    /// Cumulative data flow stats.
    data_flow: CumulativeDataFlow,
    /// Tool invocation sequence (tool names in order), bounded to the entry cap.
    tool_sequence: chio_bounded::Ring<String>,
    /// Per-tool invocation counts (cumulative). The counts survive entry-ring
    /// eviction so the behavioral-sequence guard can answer "was this tool ever
    /// invoked", but the set of DISTINCT keys is bounded fail-closed by
    /// `tool_counts_cap`. See `record` for the overflow rule.
    tool_counts: HashMap<String, u64>,
    /// Maximum number of distinct tool names retained in `tool_counts`. Once
    /// reached, a previously-unseen tool name is dropped from the cumulative
    /// counts (fail-closed): a dependent required-predecessor check then treats
    /// it as never-invoked and denies. Already-seen tools keep
    /// counting so legitimate (registry-bounded) predecessor checks stay
    /// correct across ring eviction.
    tool_counts_cap: usize,
    /// The tool name of the current consecutive run, or `None` before the first
    /// record. Together with `current_streak_len` this is an O(1), bounded
    /// cumulative streak counter (last-tool plus consecutive-count) that survives
    /// entry-ring eviction, so a `max_consecutive` check can be enforced even when
    /// the streak is longer than `journal_entry_cap` and the older part of the
    /// streak has been evicted from `tool_sequence`.
    current_streak_tool: Option<String>,
    /// Length of the current consecutive run of `current_streak_tool`. Reset to 1
    /// when a different tool is recorded, so it never accumulates unboundedly as a
    /// collection: it is a single running scalar.
    current_streak_len: u64,
}

impl JournalInner {
    fn new(entry_cap: usize, tool_counts_cap: usize) -> Self {
        Self {
            entries: chio_bounded::Ring::with_capacity(entry_cap, chio_bounded::SizeGauge::new()),
            evicted_head_hash: None,
            next_sequence: 0,
            data_flow: CumulativeDataFlow::default(),
            tool_sequence: chio_bounded::Ring::with_capacity(
                entry_cap,
                chio_bounded::SizeGauge::new(),
            ),
            tool_counts: HashMap::new(),
            tool_counts_cap,
            current_streak_tool: None,
            current_streak_len: 0,
        }
    }

    fn last_hash(&self) -> &str {
        self.entries
            .iter()
            .last()
            .map(|e| e.entry_hash.as_str())
            .unwrap_or(ZERO_HASH)
    }

    /// The externally visible head hash. Before any eviction this is the most
    /// recent retained entry hash; once the ring has evicted a prefix, the head
    /// folds the running `evicted_head_hash` together with the retained tail so
    /// the exported head still commits to the dropped prefix. This keeps the
    /// snapshot/`head_hash()` commitment consistent with the full pre-eviction
    /// sequence, so an audit can detect truncation or tampering of the evicted
    /// prefix.
    fn exported_head_hash(&self) -> String {
        match self.evicted_head_hash.as_deref() {
            None => self.last_hash().to_string(),
            Some(evicted) => fold_head_hash(Some(evicted), self.last_hash()),
        }
    }

    fn snapshot(&self, session_id: &str) -> SessionJournalSnapshot {
        SessionJournalSnapshot {
            session_id: session_id.to_string(),
            entry_count: self.entries.len(),
            head_hash: self.exported_head_hash(),
            data_flow: self.data_flow.clone(),
            tool_sequence: self.tool_sequence.iter().cloned().collect(),
            tool_counts: self.tool_counts.clone(),
            current_streak_tool: self.current_streak_tool.clone(),
            current_streak_len: self.current_streak_len,
        }
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

    /// Create a new empty journal for the given session using the DEFAULT process
    /// memory budget caps.
    ///
    /// Session-aware guards that hold a CONFIGURED process memory budget should
    /// prefer [`Self::from_memory_budget`] so lowering `journal_entry_cap` (or
    /// `journal_tool_counts_cap`) actually tightens each per-session journal
    /// instead of every caller silently retaining the compiled-in default.
    pub fn new(session_id: String) -> Self {
        Self::with_caps(
            session_id,
            default_journal_entry_cap(),
            default_journal_tool_counts_cap(),
        )
    }

    /// Create a new empty journal whose entry-ring and distinct-tool-name caps come
    /// from a CONFIGURED process memory budget. Threading the operator's
    /// [`chio_kernel::MemoryBudgetConfig`] (rather than a fresh `defaults()` read
    /// inside [`Self::new`]) means lowering `journal_entry_cap` /
    /// `journal_tool_counts_cap` on the process budget actually bounds each
    /// per-session journal, so a multi-session workload stays within the configured
    /// budget instead of every session retaining the default 4096 entries.
    pub fn from_memory_budget(
        session_id: String,
        budget: &chio_kernel::MemoryBudgetConfig,
    ) -> Self {
        Self::with_caps(
            session_id,
            budget.journal_entry_cap,
            budget.journal_tool_counts_cap,
        )
    }

    /// Create a new empty journal with an explicit entry-ring capacity and the
    /// default distinct-tool-name cap. The `entries` and `tool_sequence` rings
    /// are bounded to `entry_cap`; `data_flow` stays cumulative and
    /// `tool_counts` is cumulative but distinct-key bounded.
    pub fn with_entry_cap(session_id: String, entry_cap: usize) -> Self {
        Self::with_caps(session_id, entry_cap, default_journal_tool_counts_cap())
    }

    /// Create a new empty journal with explicit entry-ring and distinct-tool-name
    /// caps. `entry_cap` bounds the `entries` and `tool_sequence` rings;
    /// `tool_counts_cap` bounds the number of DISTINCT tool names retained in the
    /// cumulative `tool_counts` map fail-closed.
    pub fn with_caps(session_id: String, entry_cap: usize, tool_counts_cap: usize) -> Self {
        Self {
            inner: Mutex::new(JournalInner::new(entry_cap, tool_counts_cap)),
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
        validate_record_field(&params.tool_name, "tool_name")?;
        validate_record_field(&params.server_id, "server_id")?;
        validate_record_field(&params.agent_id, "agent_id")?;

        let mut inner = self.lock_inner()?;

        let sequence = inner.next_sequence;
        inner.next_sequence = inner.next_sequence.saturating_add(1);
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

        // Update tool sequence and counts. tool_sequence is a bounded ring; the
        // cumulative tool_counts survive ring eviction so the "ever invoked"
        // predecessor check stays correct. The distinct-key set
        // is bounded fail-closed by tool_counts_cap: an already-seen tool keeps
        // counting, but once the cap is reached a previously-unseen tool name is
        // NOT inserted, so a dependent required-predecessor check treats it as
        // never-invoked and denies (fail-closed). This bounds the one long-lived
        // per-session collection a ring cannot bound, without breaking the
        // cumulative predecessor semantics for the naturally registry-bounded
        // legitimate tool set. The append-only entry, sequence ring, and
        // data-flow totals above are unaffected by the overflow.
        let _ = inner.tool_sequence.push(tool_name.clone());

        // Maintain the cumulative consecutive-run counter (O(1), bounded scalar).
        // This survives entry-ring eviction so a `max_consecutive` policy is
        // enforced even when the streak is longer than `journal_entry_cap` and the
        // older part of the streak has been evicted from `tool_sequence`
        // (fail-closed): the guard consults this counter, not the truncated ring
        // tail.
        if inner.current_streak_tool.as_deref() == Some(tool_name.as_str()) {
            inner.current_streak_len = inner.current_streak_len.saturating_add(1);
        } else {
            inner.current_streak_tool = Some(tool_name.clone());
            inner.current_streak_len = 1;
        }

        if inner.tool_counts.contains_key(&tool_name) {
            if let Some(count) = inner.tool_counts.get_mut(&tool_name) {
                *count = count.saturating_add(1);
            }
        } else if inner.tool_counts.len() < inner.tool_counts_cap {
            inner.tool_counts.insert(tool_name, 1);
        }

        if let Some(evicted) = inner.entries.push(entry) {
            // Fold the evicted prefix into a running head hash so the chain
            // remains committed after the prefix is dropped.
            let folded = fold_head_hash(inner.evicted_head_hash.as_deref(), &evicted.entry_hash);
            inner.evicted_head_hash = Some(folded);
        }

        Ok(sequence)
    }

    /// Return a snapshot of the cumulative data flow statistics.
    pub fn data_flow(&self) -> Result<CumulativeDataFlow, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.data_flow.clone())
    }

    /// Return a coherent snapshot of guard-facing journal state.
    ///
    /// The snapshot captures cumulative data flow, tool sequence, tool counts,
    /// entry count, and head hash while holding one journal lock. Guards that
    /// need more than one view should prefer this method over multiple getters.
    pub fn snapshot(&self) -> Result<SessionJournalSnapshot, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.snapshot(&self.session_id))
    }

    /// Return the ordered tool invocation sequence (bounded to the entry cap).
    pub fn tool_sequence(&self) -> Result<Vec<String>, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.tool_sequence.iter().cloned().collect())
    }

    /// Return per-tool invocation counts.
    pub fn tool_counts(&self) -> Result<HashMap<String, u64>, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.tool_counts.clone())
    }

    /// Number of DISTINCT tool names currently retained in the cumulative
    /// `tool_counts` map. Bounded above by the journal's `tool_counts_cap`.
    /// Exposed so a telemetry exporter or the kernel's
    /// bounded-structure registry can observe how close the per-session
    /// distinct-key set is to saturation once the journal is wired into a live
    /// dispatch path.
    pub fn tool_counts_len(&self) -> Result<usize, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.tool_counts.len())
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

    /// Return a clone of the retained journal entries (bounded to the entry cap).
    pub fn entries(&self) -> Result<Vec<JournalEntry>, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.entries.iter().cloned().collect())
    }

    /// Return the most recent N entries (or all retained if fewer than N exist).
    pub fn recent_entries(&self, n: usize) -> Result<Vec<JournalEntry>, SessionJournalError> {
        let inner = self.lock_inner()?;
        let all: Vec<JournalEntry> = inner.entries.iter().cloned().collect();
        let start = all.len().saturating_sub(n);
        Ok(all[start..].to_vec())
    }

    /// Verify the integrity of the hash chain.
    ///
    /// Returns `Ok(())` if all entries are correctly chained, or an error
    /// indicating where the chain breaks.
    pub fn verify_integrity(&self) -> Result<(), SessionJournalError> {
        let inner = self.lock_inner()?;

        let entries: Vec<&JournalEntry> = inner.entries.iter().collect();
        for (index, entry) in entries.iter().enumerate() {
            // Check prev_hash linkage.
            let expected_prev = if index == 0 {
                if inner.evicted_head_hash.is_some() {
                    // The oldest retained entry links into the evicted prefix,
                    // which we no longer hold; that prefix is committed via
                    // evicted_head_hash. Accept this boundary link and verify only
                    // the entry hash.
                    entry.prev_hash.as_str()
                } else {
                    ZERO_HASH
                }
            } else {
                entries[index - 1].entry_hash.as_str()
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

    /// Return the exported head hash: the most recent entry hash before any
    /// eviction, or (once a prefix has been evicted) a fold of the evicted
    /// prefix and the retained tail, so the head stays committed to the full
    /// sequence across eviction (or the zero hash if empty).
    pub fn head_hash(&self) -> Result<String, SessionJournalError> {
        let inner = self.lock_inner()?;
        Ok(inner.exported_head_hash())
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
    fn journal_entries_ring_caps_but_counts_stay_cumulative() {
        // The entries ring is bounded, but data_flow / tool_counts remain
        // cumulative, and the retained window stays hash-verifiable.
        let journal = SessionJournal::with_entry_cap("sess-cap".to_string(), 4);
        for i in 0..10u32 {
            journal
                .record(test_params(&format!("tool-{}", i % 2)))
                .unwrap();
        }
        assert!(
            journal.entries().unwrap().len() <= 4,
            "entries ring not capped"
        );
        let counts = journal.tool_counts().unwrap();
        let total: u64 = counts.values().sum();
        assert_eq!(total, 10, "cumulative counts must survive eviction");
        assert_eq!(
            journal.data_flow().unwrap().total_invocations,
            10,
            "cumulative invocation count must survive eviction"
        );
        // Sequence numbers keep climbing past the cap (monotonic, not len-based),
        // and the retained window remains internally verifiable across the
        // eviction boundary.
        let entries = journal.entries().unwrap();
        assert_eq!(entries.last().map(|e| e.sequence), Some(9));
        journal.verify_integrity().unwrap();
    }

    #[test]
    fn from_memory_budget_honors_lowered_journal_caps() {
        // The CONFIGURED process memory budget must reach each per-session
        // journal. A budget lowering `journal_entry_cap` to 4 and
        // `journal_tool_counts_cap` to 3 must bound this journal at those caps, not
        // the compiled-in default of 4096; `from_memory_budget` threads the budget
        // through where `new` would read `defaults()`.
        let budget = chio_kernel::MemoryBudgetConfig {
            journal_entry_cap: 4,
            journal_tool_counts_cap: 3,
            ..chio_kernel::MemoryBudgetConfig::defaults()
        };
        let journal = SessionJournal::from_memory_budget("sess-budget".to_string(), &budget);

        // Flood distinct tool names: entries ring stays <= 4, distinct tool-counts
        // keys stay <= 3, while cumulative invocation totals still survive.
        for i in 0..100u32 {
            journal.record(test_params(&format!("tool-{i}"))).unwrap();
        }
        assert!(
            journal.entries().unwrap().len() <= 4,
            "configured journal_entry_cap did not take effect: {} entries",
            journal.entries().unwrap().len()
        );
        assert!(
            journal.tool_counts_len().unwrap() <= 3,
            "configured journal_tool_counts_cap did not take effect: {} keys",
            journal.tool_counts_len().unwrap()
        );
        assert_eq!(
            journal.data_flow().unwrap().total_invocations,
            100,
            "cumulative invocation total must survive eviction"
        );
    }

    #[test]
    fn tool_counts_distinct_keys_are_capped_fail_closed() {
        // tool_counts is cumulative (survives ring eviction) but its DISTINCT-KEY
        // set must be bounded, or a writer that can influence tool
        // names (the journal only validates non-empty/trimmed/control-free, not
        // registry membership) could grow one long-lived per-session map without
        // bound. Cap the distinct keys fail-closed: already-seen tools keep
        // counting; a previously-unseen tool name past the cap is dropped so a
        // dependent predecessor check treats it as never-invoked.
        let journal = SessionJournal::with_caps("sess-tool-cap".to_string(), 1024, 2);

        // Fill the distinct-key cap with two legitimate tools.
        journal.record(test_params("setup")).unwrap();
        journal.record(test_params("helper")).unwrap();
        assert_eq!(journal.tool_counts_len().unwrap(), 2);

        // Already-seen tools keep counting cumulatively past the cap.
        journal.record(test_params("setup")).unwrap();
        journal.record(test_params("setup")).unwrap();
        let counts = journal.tool_counts().unwrap();
        assert_eq!(
            counts.get("setup"),
            Some(&3),
            "known tool must keep counting"
        );
        assert_eq!(counts.get("helper"), Some(&1));

        // Flood with many previously-unseen tool names: none are inserted, so the
        // distinct-key set never exceeds the cap.
        for i in 0..10_000u32 {
            journal
                .record(test_params(&format!("attacker-tool-{i}")))
                .unwrap();
        }
        assert_eq!(
            journal.tool_counts_len().unwrap(),
            2,
            "distinct-key set must stay at the cap under unbounded new tool names"
        );
        let counts = journal.tool_counts().unwrap();
        assert!(
            !counts.contains_key("attacker-tool-0"),
            "an overflow tool name must be treated as never-invoked (fail-closed)"
        );

        // The append-only journal itself is unaffected: every record still counts
        // toward the cumulative invocation total and the sequence ring.
        assert_eq!(journal.data_flow().unwrap().total_invocations, 10_004);
        journal.verify_integrity().unwrap();
    }

    #[test]
    fn exported_head_hash_commits_to_evicted_prefix() {
        // Once the ring evicts a prefix, the exported head hash must still commit
        // to the dropped entries -- it must NOT collapse
        // to a hash of only the retained suffix, so an audit using the snapshot
        // can detect truncation or tampering of the evicted prefix.
        let journal = SessionJournal::with_entry_cap("sess-head".to_string(), 2);

        // Fill exactly to the cap: no eviction yet, so the head is the retained
        // tail entry hash.
        journal.record(test_params("t0")).unwrap();
        journal.record(test_params("t1")).unwrap();
        let retained_tail_before = journal
            .entries()
            .unwrap()
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap();
        assert_eq!(
            journal.head_hash().unwrap(),
            retained_tail_before,
            "pre-eviction head must be the most recent entry hash"
        );

        // Push past the cap: this evicts the prefix (t0, then t1).
        journal.record(test_params("t2")).unwrap();
        journal.record(test_params("t3")).unwrap();

        let head_after = journal.head_hash().unwrap();
        let retained_tail_after = journal
            .entries()
            .unwrap()
            .last()
            .map(|e| e.entry_hash.clone())
            .unwrap();
        assert_ne!(
            head_after, retained_tail_after,
            "exported head must fold the evicted prefix, not equal the retained suffix tail"
        );

        // The snapshot's head hash stays consistent with head_hash().
        assert_eq!(
            journal.snapshot().unwrap().head_hash,
            head_after,
            "snapshot head hash diverged from head_hash()"
        );
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
    fn record_rejects_padded_tool_name() {
        let journal = SessionJournal::new("sess-1".to_string());
        let mut params = test_params("read_file");
        params.tool_name = " read_file".to_string();

        let error = journal.record(params).unwrap_err();

        assert!(matches!(
            error,
            SessionJournalError::InvalidRecordField { field: "tool_name" }
        ));
    }

    #[test]
    fn record_rejects_control_characters_in_identity_fields() {
        for (field, params) in [
            {
                let mut params = test_params("read\nfile");
                params.server_id = "srv-1".to_string();
                params.agent_id = "agent-1".to_string();
                ("tool_name", params)
            },
            {
                let mut params = test_params("read_file");
                params.server_id = "srv\t1".to_string();
                params.agent_id = "agent-1".to_string();
                ("server_id", params)
            },
            {
                let mut params = test_params("read_file");
                params.server_id = "srv-1".to_string();
                params.agent_id = "agent\r1".to_string();
                ("agent_id", params)
            },
        ] {
            let journal = SessionJournal::new(format!("sess-control-{field}"));

            let error = journal.record(params).unwrap_err();

            assert!(matches!(
                error,
                SessionJournalError::InvalidRecordField { field: actual } if actual == field
            ));
        }
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
    fn snapshot_captures_guard_state_under_one_read_boundary() {
        let journal = SessionJournal::new("sess-snapshot".to_string());
        journal.record(test_params("read_file")).unwrap();
        journal
            .record(RecordParams {
                tool_name: "bash".to_string(),
                server_id: "srv-1".to_string(),
                agent_id: "agent-1".to_string(),
                bytes_read: 25,
                bytes_written: 10,
                delegation_depth: 2,
                allowed: false,
            })
            .unwrap();

        let snapshot = journal.snapshot().unwrap();

        assert_eq!(snapshot.session_id, "sess-snapshot");
        assert_eq!(snapshot.entry_count, 2);
        assert_eq!(snapshot.head_hash, journal.head_hash().unwrap());
        assert_eq!(snapshot.data_flow.total_bytes_read, 125);
        assert_eq!(snapshot.data_flow.total_bytes_written, 60);
        assert_eq!(snapshot.data_flow.total_invocations, 2);
        assert_eq!(snapshot.data_flow.max_delegation_depth, 2);
        assert_eq!(snapshot.tool_sequence, vec!["read_file", "bash"]);
        assert_eq!(snapshot.tool_counts.get("read_file"), Some(&1));
        assert_eq!(snapshot.tool_counts.get("bash"), Some(&1));
    }

    #[test]
    fn snapshot_is_an_immutable_view_of_capture_time() {
        let journal = SessionJournal::new("sess-snapshot-stale".to_string());
        journal.record(test_params("read_file")).unwrap();

        let snapshot = journal.snapshot().unwrap();
        journal.record(test_params("write_file")).unwrap();

        assert_eq!(snapshot.entry_count, 1);
        assert_eq!(snapshot.tool_sequence, vec!["read_file"]);
        assert_eq!(snapshot.tool_counts.get("write_file"), None);
        assert_eq!(journal.len().unwrap(), 2);
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
    fn entry_hash_separates_adjacent_string_fields() {
        fn first_hash(tool_name: &str, server_id: &str, agent_id: &str) -> String {
            compute_entry_hash(&JournalEntry {
                sequence: 0,
                prev_hash: ZERO_HASH.to_string(),
                entry_hash: String::new(),
                timestamp_secs: 42,
                tool_name: tool_name.to_string(),
                server_id: server_id.to_string(),
                agent_id: agent_id.to_string(),
                bytes_read: 1,
                bytes_written: 2,
                delegation_depth: 3,
                allowed: true,
            })
        }

        let left = first_hash("ab", "c", "d");
        let right = first_hash("a", "bc", "d");

        assert_ne!(left, right);
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
