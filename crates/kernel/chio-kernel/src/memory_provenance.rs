//! Memory-entry provenance.
//!
//! Structural security gap #3 in `docs/protocols/STRUCTURAL-SECURITY-FIXES.md`
//! points out that agent memory writes (vector DBs, conversation history,
//! scratchpads) normally happen outside Chio's guard pipeline, which lets a
//! compromised or confused agent plant cross-session prompt-injection
//! payloads with no attribution. The guard layer governs the writes; this
//! module is the **evidence** side: every
//! governed write appends an entry to an append-only, hash-chained
//! provenance log that ties the write to the capability and receipt that
//! authorized it. On read, the kernel looks up the latest provenance
//! entry for the `(store, key)` pair and attaches it to the receipt as
//! `memory_provenance` evidence.
//!
//! Keys are *pairs* (`store`, `key`); the empty key string is the
//! canonical "whole-collection" marker emitted by `MemoryRead` when a
//! read does not target a specific document id. Reads whose key has no
//! chain entry are marked [`ProvenanceVerification::Unverified`] so the
//! caller can distinguish "never governed" from "tampered chain".
//!
//! Fail-closed semantics:
//! * Append returns [`MemoryProvenanceError`] on any store failure; the
//!   kernel wiring treats that as a fatal error on the memory-write
//!   path (the write has already been signed as allowed, but the
//!   provenance chain must not silently drop entries).
//! * Verification returns [`ProvenanceVerification::Unverified`] rather
//!   than an error when the chain is intact but no entry exists, and
//!   returns it with a `tampered: true` reason when the stored hash
//!   disagrees with what canonical-JSON + SHA-256 would produce.
//!
//! The trait is intentionally synchronous and mirrors the pattern used
//! by [`crate::approval::ApprovalStore`],
//! [`crate::execution_nonce::ExecutionNonceStore`], and the other kernel
//! stores: in-memory reference impl lives here, SQLite impl lives in
//! `chio-store-sqlite`.

use std::sync::Mutex;

use chio_core::canonical::canonical_json_bytes;
use chio_core::crypto::sha256_hex;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Schema tag used in canonical-JSON hashing. Bumping this invalidates
/// existing chains.
pub const MEMORY_PROVENANCE_ENTRY_SCHEMA: &str = "chio.memory_provenance_entry.v1";

/// Sentinel `prev_hash` used for the first entry in a chain. Kept as a
/// fixed 64-character hex string of zeros so canonical-JSON hashing is
/// deterministic and the chain has no special-case branch.
pub const MEMORY_PROVENANCE_GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Entry committed to the append-only provenance chain.
///
/// `hash = sha256_hex(canonical_json(MemoryProvenanceHashInput))`, where
/// the hash input carries every field *except* `hash` itself and is
/// serialised in the canonical-JSON form mandated by the rest of Chio
/// (RFC 8785 via [`chio_core::canonical::canonical_json_bytes`]). The
/// `prev_hash` field is baked into the hash input, so replacing or
/// reordering entries after the fact breaks the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryProvenanceEntry {
    /// Globally unique entry id, assigned by the store.
    pub entry_id: String,
    /// Memory store / collection / namespace the write targeted.
    pub store: String,
    /// Key, document id, or namespace identifier within `store`.
    /// Empty string is the canonical "whole-collection" marker.
    pub key: String,
    /// Capability id that authorized the write.
    pub capability_id: String,
    /// Receipt id emitted for the write.
    pub receipt_id: String,
    /// Unix seconds at write time.
    pub written_at: u64,
    /// `hash` of the previous entry in the chain, or
    /// [`MEMORY_PROVENANCE_GENESIS_PREV_HASH`] for the very first entry.
    pub prev_hash: String,
    /// `sha256_hex(canonical_json(self_without_hash))`. Verified by
    /// [`recompute_entry_hash`].
    pub hash: String,
}

/// Canonical-JSON form used to compute `MemoryProvenanceEntry.hash`.
///
/// Kept in lockstep with [`MemoryProvenanceEntry`] minus the `hash`
/// field: every other field participates in the hash, and the `schema`
/// tag binds the format so an old chain cannot be mis-interpreted under
/// a future schema.
#[derive(Debug, Clone, Serialize)]
struct MemoryProvenanceHashInput<'a> {
    schema: &'a str,
    entry_id: &'a str,
    store: &'a str,
    key: &'a str,
    capability_id: &'a str,
    receipt_id: &'a str,
    written_at: u64,
    prev_hash: &'a str,
}

impl MemoryProvenanceEntry {
    /// Return the canonical hash for this entry, ignoring the currently
    /// stored `hash` field. Used by [`MemoryProvenanceStore::verify_entry`]
    /// implementations to detect in-place tampering.
    pub fn expected_hash(&self) -> Result<String, MemoryProvenanceError> {
        recompute_entry_hash(
            &self.entry_id,
            &self.store,
            &self.key,
            &self.capability_id,
            &self.receipt_id,
            self.written_at,
            &self.prev_hash,
        )
    }
}

/// Input accepted by [`MemoryProvenanceStore::append`].
///
/// The store assigns `entry_id`, `prev_hash`, and `hash` internally;
/// callers (the kernel wiring) only supply the business-level fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryProvenanceAppend {
    pub store: String,
    pub key: String,
    pub capability_id: String,
    pub receipt_id: String,
    pub written_at: u64,
}

/// Result of looking up provenance for a `(store, key)` pair.
///
/// `Verified` carries the entry whose chain linkage and hash both
/// check out. `Unverified` is the fail-closed signal that either no
/// entry was ever written, the chain has been tampered, or the chain
/// cannot currently be read (store unavailable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ProvenanceVerification {
    /// A chain entry was found and its hash / link verified locally.
    Verified {
        entry: MemoryProvenanceEntry,
        /// Current aggregate chain digest, useful for correlating
        /// receipts with a chain root.
        chain_digest: String,
    },
    /// No chain entry for this `(store, key)` pair, OR the chain is
    /// currently inaccessible / tampered. `reason` narrows the case so
    /// receipt consumers can log it without swallowing failures.
    Unverified { reason: UnverifiedReason },
}

/// Why a memory read could not be verified against the provenance chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnverifiedReason {
    /// No entry has ever been appended for the `(store, key)` pair.
    /// The memory entry predates governance (or bypassed it).
    NoProvenance,
    /// A stored entry exists but its recomputed hash disagrees with
    /// the hash field. Chain tamper detected.
    ChainTampered,
    /// A stored entry exists but its `prev_hash` does not line up with
    /// the entry that sits before it. Chain linkage broken.
    ChainLinkBroken,
    /// The provenance store is unavailable (mutex poisoned, SQLite
    /// error, etc.). Operators must treat this as fail-closed: the
    /// memory read surfaces the `Unverified` verdict so callers can
    /// deny rather than silently accept.
    StoreUnavailable,
}

impl UnverifiedReason {
    /// Stable string label for this reason, useful for logs and
    /// receipt metadata.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoProvenance => "no_provenance",
            Self::ChainTampered => "chain_tampered",
            Self::ChainLinkBroken => "chain_link_broken",
            Self::StoreUnavailable => "store_unavailable",
        }
    }
}

/// Errors returned by [`MemoryProvenanceStore`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum MemoryProvenanceError {
    #[error("memory provenance store backend error: {0}")]
    Backend(String),
    #[error("memory provenance canonical serialization failed: {0}")]
    Serialization(String),
    #[error("memory provenance entry not found: {0}")]
    NotFound(String),
}

/// Contract for the append-only, hash-chained memory provenance log.
///
/// Implementations MUST:
/// 1. Compute `prev_hash` by reading the tail entry inside the same
///    transactional scope as the append, so concurrent appenders cannot
///    both read the same tail and produce a forked chain.
/// 2. Populate `hash` with [`recompute_entry_hash`] (or equivalent) so
///    every consumer can independently verify the entry.
/// 3. Keep the chain insertion order total: `append` followed by
///    `latest_for_key` / `chain_digest` must observe the freshly written
///    entry.
pub trait MemoryProvenanceStore: Send + Sync {
    /// Append a new entry, computing the chain linkage atomically.
    fn append(
        &self,
        input: MemoryProvenanceAppend,
    ) -> Result<MemoryProvenanceEntry, MemoryProvenanceError>;

    /// Fetch an entry by its unique id. Returns `Ok(None)` when the id
    /// is absent; consumers should treat that as
    /// [`UnverifiedReason::NoProvenance`] when it happens during a read.
    fn get_entry(
        &self,
        entry_id: &str,
    ) -> Result<Option<MemoryProvenanceEntry>, MemoryProvenanceError>;

    /// Fetch the most-recent entry for a `(store, key)` pair, or
    /// `Ok(None)` when no entry has ever been appended for that key.
    fn latest_for_key(
        &self,
        store: &str,
        key: &str,
    ) -> Result<Option<MemoryProvenanceEntry>, MemoryProvenanceError>;

    /// Verify a specific entry: recompute its hash, confirm its
    /// `prev_hash` matches the entry that sits immediately before it
    /// (or the genesis marker for entry #1), and return
    /// [`ProvenanceVerification::Verified`] when everything checks out.
    fn verify_entry(&self, entry_id: &str)
        -> Result<ProvenanceVerification, MemoryProvenanceError>;

    /// Aggregate digest of the chain -- the `hash` of the tail entry,
    /// or [`MEMORY_PROVENANCE_GENESIS_PREV_HASH`] when the chain is
    /// empty. Useful for embedding into receipts as a snapshot marker.
    fn chain_digest(&self) -> Result<String, MemoryProvenanceError>;
}

/// Compute the canonical hash that binds every field of an entry into
/// the chain.
///
/// Separated from [`MemoryProvenanceEntry::expected_hash`] so SQLite
/// impls can call it before they have constructed the full entry.
pub fn recompute_entry_hash(
    entry_id: &str,
    store: &str,
    key: &str,
    capability_id: &str,
    receipt_id: &str,
    written_at: u64,
    prev_hash: &str,
) -> Result<String, MemoryProvenanceError> {
    let input = MemoryProvenanceHashInput {
        schema: MEMORY_PROVENANCE_ENTRY_SCHEMA,
        entry_id,
        store,
        key,
        capability_id,
        receipt_id,
        written_at,
        prev_hash,
    };
    let bytes = canonical_json_bytes(&input)
        .map_err(|error| MemoryProvenanceError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Mint a new entry id. UUIDv7 so ids sort monotonically by issuance
/// time, matching [`crate::receipt_support::next_receipt_id`].
#[must_use]
pub fn next_entry_id() -> String {
    format!("mem-prov-{}", Uuid::now_v7())
}

// ---------------------------------------------------------------------
// In-memory reference implementation.
// ---------------------------------------------------------------------

/// Thread-safe in-memory [`MemoryProvenanceStore`]. Useful for tests and
/// for ephemeral deployments; production deployments should use the
/// SQLite-backed store in `chio-store-sqlite`.
#[derive(Default)]
pub struct InMemoryMemoryProvenanceStore {
    entries: Mutex<Vec<MemoryProvenanceEntry>>,
}

impl InMemoryMemoryProvenanceStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Test helper: overwrite an already-committed entry's `hash`
    /// in place to simulate tamper. Always returns the previous entry
    /// for assertion convenience.
    #[cfg(test)]
    pub(crate) fn tamper_entry_hash(
        &self,
        entry_id: &str,
        forged_hash: &str,
    ) -> Result<MemoryProvenanceEntry, MemoryProvenanceError> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| MemoryProvenanceError::Backend("entries mutex poisoned".to_string()))?;
        for entry in guard.iter_mut() {
            if entry.entry_id == entry_id {
                let previous = entry.clone();
                entry.hash = forged_hash.to_string();
                return Ok(previous);
            }
        }
        Err(MemoryProvenanceError::NotFound(entry_id.to_string()))
    }
}

impl MemoryProvenanceStore for InMemoryMemoryProvenanceStore {
    fn append(
        &self,
        input: MemoryProvenanceAppend,
    ) -> Result<MemoryProvenanceEntry, MemoryProvenanceError> {
        let mut guard = self
            .entries
            .lock()
            .map_err(|_| MemoryProvenanceError::Backend("entries mutex poisoned".to_string()))?;
        let prev_hash = guard
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string());
        let entry_id = next_entry_id();
        let hash = recompute_entry_hash(
            &entry_id,
            &input.store,
            &input.key,
            &input.capability_id,
            &input.receipt_id,
            input.written_at,
            &prev_hash,
        )?;
        let entry = MemoryProvenanceEntry {
            entry_id,
            store: input.store,
            key: input.key,
            capability_id: input.capability_id,
            receipt_id: input.receipt_id,
            written_at: input.written_at,
            prev_hash,
            hash,
        };
        guard.push(entry.clone());
        Ok(entry)
    }

    fn get_entry(
        &self,
        entry_id: &str,
    ) -> Result<Option<MemoryProvenanceEntry>, MemoryProvenanceError> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| MemoryProvenanceError::Backend("entries mutex poisoned".to_string()))?;
        Ok(guard
            .iter()
            .find(|entry| entry.entry_id == entry_id)
            .cloned())
    }

    fn latest_for_key(
        &self,
        store: &str,
        key: &str,
    ) -> Result<Option<MemoryProvenanceEntry>, MemoryProvenanceError> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| MemoryProvenanceError::Backend("entries mutex poisoned".to_string()))?;
        Ok(guard
            .iter()
            .rev()
            .find(|entry| entry.store == store && entry.key == key)
            .cloned())
    }

    fn verify_entry(
        &self,
        entry_id: &str,
    ) -> Result<ProvenanceVerification, MemoryProvenanceError> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| MemoryProvenanceError::Backend("entries mutex poisoned".to_string()))?;
        let Some(index) = guard.iter().position(|entry| entry.entry_id == entry_id) else {
            return Ok(ProvenanceVerification::Unverified {
                reason: UnverifiedReason::NoProvenance,
            });
        };
        let entry = &guard[index];
        let expected = entry.expected_hash()?;
        if expected != entry.hash {
            return Ok(ProvenanceVerification::Unverified {
                reason: UnverifiedReason::ChainTampered,
            });
        }
        let expected_prev = if index == 0 {
            MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string()
        } else {
            guard[index - 1].hash.clone()
        };
        if expected_prev != entry.prev_hash {
            return Ok(ProvenanceVerification::Unverified {
                reason: UnverifiedReason::ChainLinkBroken,
            });
        }
        let chain_digest = guard
            .last()
            .map(|tail| tail.hash.clone())
            .unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string());
        Ok(ProvenanceVerification::Verified {
            entry: entry.clone(),
            chain_digest,
        })
    }

    fn chain_digest(&self) -> Result<String, MemoryProvenanceError> {
        let guard = self
            .entries
            .lock()
            .map_err(|_| MemoryProvenanceError::Backend("entries mutex poisoned".to_string()))?;
        Ok(guard
            .last()
            .map(|entry| entry.hash.clone())
            .unwrap_or_else(|| MEMORY_PROVENANCE_GENESIS_PREV_HASH.to_string()))
    }
}

// ---------------------------------------------------------------------
// Memory action resolution helpers.
//
// The kernel does not depend on `chio-guards`, so we reimplement just
// enough memory-action detection here to wire the provenance chain
// without touching `ToolAction`. This is intentionally conservative:
// it accepts the same tool-name conventions `chio-guards::action`
// already uses (`memory_write`, `remember`, `vector_upsert`, etc.)
// plus the canonical argument keys for store / key extraction.
// ---------------------------------------------------------------------

/// Classification of a memory-shaped tool call extracted from a
/// `ToolCallRequest`. Empty `key` values mean "whole collection".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemoryActionKind {
    Write { store: String, key: String },
    Read { store: String, key: String },
}

/// Inspect `tool_name` + `arguments` and return a memory action if the
/// call matches one of the well-known memory-write / memory-read tool
/// name conventions. Returns `None` for everything else so non-memory
/// tool calls bypass the provenance hook entirely.
#[must_use]
pub fn classify_memory_action(
    tool_name: &str,
    arguments: &serde_json::Value,
) -> Option<MemoryActionKind> {
    let tool = tool_name.to_ascii_lowercase();

    if is_memory_write_tool_name(&tool) {
        let (store, key) = extract_store_and_key(&tool, arguments);
        return Some(MemoryActionKind::Write { store, key });
    }
    if is_memory_read_tool_name(&tool) {
        let (store, key) = extract_store_and_key(&tool, arguments);
        return Some(MemoryActionKind::Read { store, key });
    }
    None
}

fn is_memory_write_tool_name(tool: &str) -> bool {
    matches!(
        tool,
        "memory_write"
            | "remember"
            | "store_memory"
            | "vector_upsert"
            | "vector_write"
            | "upsert"
            | "pinecone_upsert"
            | "weaviate_write"
            | "qdrant_upsert"
    )
}

fn is_memory_read_tool_name(tool: &str) -> bool {
    matches!(
        tool,
        "memory_read"
            | "recall"
            | "retrieve_memory"
            | "vector_query"
            | "vector_search"
            | "similarity_search"
            | "pinecone_query"
            | "weaviate_search"
            | "qdrant_search"
    )
}

fn extract_store_and_key(tool: &str, arguments: &serde_json::Value) -> (String, String) {
    let store = arguments
        .get("collection")
        .or_else(|| arguments.get("index"))
        .or_else(|| arguments.get("namespace"))
        .or_else(|| arguments.get("store"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| tool.to_string());
    let key = arguments
        .get("id")
        .or_else(|| arguments.get("key"))
        .or_else(|| arguments.get("memory_id"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .unwrap_or_default();
    (store, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_assigns_genesis_prev_hash_and_hex_hash() {
        let store = InMemoryMemoryProvenanceStore::new();
        let entry = store
            .append(MemoryProvenanceAppend {
                store: "vector:rag-notes".into(),
                key: "doc-1".into(),
                capability_id: "cap-1".into(),
                receipt_id: "rcpt-1".into(),
                written_at: 100,
            })
            .expect("append succeeds");
        assert_eq!(entry.prev_hash, MEMORY_PROVENANCE_GENESIS_PREV_HASH);
        assert_eq!(entry.hash.len(), 64);
        assert!(entry.hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn append_links_successive_entries_via_prev_hash() {
        let store = InMemoryMemoryProvenanceStore::new();
        let first = store
            .append(MemoryProvenanceAppend {
                store: "s".into(),
                key: "a".into(),
                capability_id: "cap-1".into(),
                receipt_id: "rcpt-1".into(),
                written_at: 100,
            })
            .unwrap();
        let second = store
            .append(MemoryProvenanceAppend {
                store: "s".into(),
                key: "b".into(),
                capability_id: "cap-1".into(),
                receipt_id: "rcpt-2".into(),
                written_at: 101,
            })
            .unwrap();
        assert_eq!(second.prev_hash, first.hash);
        assert_ne!(second.hash, first.hash);
    }

    #[test]
    fn latest_for_key_returns_most_recent_entry() {
        let store = InMemoryMemoryProvenanceStore::new();
        store
            .append(MemoryProvenanceAppend {
                store: "s".into(),
                key: "doc-1".into(),
                capability_id: "cap-1".into(),
                receipt_id: "rcpt-1".into(),
                written_at: 100,
            })
            .unwrap();
        let later = store
            .append(MemoryProvenanceAppend {
                store: "s".into(),
                key: "doc-1".into(),
                capability_id: "cap-2".into(),
                receipt_id: "rcpt-2".into(),
                written_at: 150,
            })
            .unwrap();
        let latest = store
            .latest_for_key("s", "doc-1")
            .unwrap()
            .expect("an entry for doc-1 should exist");
        assert_eq!(latest.entry_id, later.entry_id);
        assert_eq!(latest.capability_id, "cap-2");
    }

    #[test]
    fn verify_entry_detects_hash_tamper() {
        let store = InMemoryMemoryProvenanceStore::new();
        let entry = store
            .append(MemoryProvenanceAppend {
                store: "s".into(),
                key: "doc-1".into(),
                capability_id: "cap-1".into(),
                receipt_id: "rcpt-1".into(),
                written_at: 100,
            })
            .unwrap();
        let forged = "f".repeat(64);
        store
            .tamper_entry_hash(&entry.entry_id, &forged)
            .expect("test helper should overwrite the entry");
        let verification = store.verify_entry(&entry.entry_id).unwrap();
        assert!(
            matches!(
                verification,
                ProvenanceVerification::Unverified {
                    reason: UnverifiedReason::ChainTampered
                }
            ),
            "expected chain_tampered verification, got {verification:?}"
        );
    }

    #[test]
    fn verify_entry_flags_unverified_when_id_absent() {
        let store = InMemoryMemoryProvenanceStore::new();
        let verification = store.verify_entry("missing-id").unwrap();
        assert!(matches!(
            verification,
            ProvenanceVerification::Unverified {
                reason: UnverifiedReason::NoProvenance
            }
        ));
    }

    #[test]
    fn classify_memory_action_detects_writes_and_reads() {
        let args = serde_json::json!({"collection": "notes", "id": "doc-42"});
        match classify_memory_action("memory_write", &args) {
            Some(MemoryActionKind::Write { store, key }) => {
                assert_eq!(store, "notes");
                assert_eq!(key, "doc-42");
            }
            other => panic!("expected MemoryActionKind::Write, got {other:?}"),
        }
        match classify_memory_action("vector_query", &args) {
            Some(MemoryActionKind::Read { store, key }) => {
                assert_eq!(store, "notes");
                assert_eq!(key, "doc-42");
            }
            other => panic!("expected MemoryActionKind::Read, got {other:?}"),
        }
        assert!(classify_memory_action("read_file", &args).is_none());
    }

    #[test]
    fn chain_digest_matches_tail_hash() {
        let store = InMemoryMemoryProvenanceStore::new();
        assert_eq!(
            store.chain_digest().unwrap(),
            MEMORY_PROVENANCE_GENESIS_PREV_HASH
        );
        let entry = store
            .append(MemoryProvenanceAppend {
                store: "s".into(),
                key: "k".into(),
                capability_id: "cap-1".into(),
                receipt_id: "rcpt-1".into(),
                written_at: 10,
            })
            .unwrap();
        assert_eq!(store.chain_digest().unwrap(), entry.hash);
    }
}
