//! SQLite-backed persistence, query, and report layer for the Chio protocol.
//!
//! This crate is the concrete persistent backend for the kernel's receipt log
//! and its supporting state. It implements the receipt store and query path,
//! budget and approval stores, capability-lineage and revocation stores, an
//! execution-nonce store, an encrypted-blob store, IOU and dead-letter stores,
//! and evidence-export queries. The store traits it implements are defined by
//! `chio-kernel` and `chio-core`. Reader-heavy receipt queries use a
//! connection pool (eight readers by default); writes are serialized through a
//! group-commit actor onto a single writer connection.
//!
//! # Modules
//!
//! - [`receipt_store`] / [`receipt_query`] -- receipt persistence and the
//!   query path.
//! - [`budget_store`] -- durable budget state.
//! - [`approval_store`] / [`batch_approval_store`] -- human-approval state.
//! - [`capability_lineage`] / [`revocation_store`] -- capability provenance and
//!   revocation.
//! - [`execution_nonce_store`] / [`dead_letters`] / [`iou_store`] -- nonce
//!   replay guard, settlement dead letters, and IOU envelopes.
//! - [`encrypted_blob`] / [`memory_provenance_store`] / [`evidence_export`] --
//!   encrypted payloads, memory provenance, and evidence export.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

pub mod approval_store;
pub mod authority;
pub mod batch_approval_store;
pub mod budget_store;
pub mod capability_lineage;
pub mod dead_letters;
pub mod eip3009_nonces;
pub mod encrypted_blob;
pub mod evidence_export;
pub mod execution_nonce_store;
pub mod iou_store;
#[cfg(feature = "lineage")]
pub mod lineage_cte;
pub mod memory_provenance_store;
pub mod receipt_query;
pub mod receipt_store;
pub mod revocation_store;
pub mod schema_version;
pub mod settle_attempts;

pub use chio_core::crypto::SharedCanonicalBytes;
pub use chio_core::{CanonicalBytes, CanonicalJsonWitness};
pub use chio_kernel::{EvidenceChildReceiptScope, EvidenceExportQuery};

/// Default SQLite reader pool size.
///
/// Reader-heavy receipt queries keep the existing eight-connection default.
pub const DEFAULT_READER_POOL_MAX_SIZE: u32 = 8;

/// Default SQLite writer pool size.
///
/// Receipt writes are serialized through the group-commit actor, so the
/// writer pool defaults to a single connection.
pub const DEFAULT_WRITER_POOL_MAX_SIZE: u32 = 1;

/// SQLite pool sizing for receipt-store read and write paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqlitePoolConfig {
    pub reader_pool_max_size: u32,
    pub writer_pool_max_size: u32,
}

impl Default for SqlitePoolConfig {
    fn default() -> Self {
        Self {
            reader_pool_max_size: DEFAULT_READER_POOL_MAX_SIZE,
            writer_pool_max_size: DEFAULT_WRITER_POOL_MAX_SIZE,
        }
    }
}

/// Receipt-store construction options.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SqliteStoreOptions {
    pub pool: SqlitePoolConfig,
    /// When true (default), the append path uses the actor-owned verified
    /// head (O(1) predecessor check + O(b) delta cross-check). When false,
    /// the store keeps today's full per-append verification so operators can
    /// A/B a suspect database. Read-only after open.
    pub incremental_verification: bool,
}

impl Default for SqliteStoreOptions {
    fn default() -> Self {
        Self {
            pool: SqlitePoolConfig::default(),
            incremental_verification: true,
        }
    }
}

/// Whether a SQLite path opens a database that lives only in memory for the life
/// of the process. rusqlite enables URI filenames, so the bare `:memory:`
/// sentinel, `file::memory:`, and any `file:...?mode=memory` URI all open a
/// non-durable database that loses its contents on restart and must not be
/// mistaken for a durable store. Durability gates use this to refuse an in-memory
/// path where they would otherwise advertise durable persistence.
#[must_use]
pub fn is_in_memory_sqlite_path(path: &str) -> bool {
    if path.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    let (name, query) = match rest.split_once('?') {
        Some((name, query)) => (name, Some(query)),
        None => (rest, None),
    };
    if name.eq_ignore_ascii_case(":memory:") {
        return true;
    }
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
    })
}

/// The directory that must exist before SQLite opens `path`, or `None` when
/// there is nothing to create.
///
/// rusqlite accepts `file:` URIs whose query string (`?mode=rwc`) and optional
/// `//authority` are not part of the on-disk filename. Treating such a URI as a
/// plain [`Path`] makes `parent()` resolve to a bogus directory (for example
/// `file:/var/lib/chio`) and skips creating the real one, so SQLite then fails
/// to open the database. This strips the `file:` scheme, any authority, and the
/// query so callers create the directory that actually backs the database. An
/// in-memory database (`:memory:`, `file:...?mode=memory`) has no backing
/// directory and returns `None`.
#[must_use]
pub(crate) fn sqlite_parent_dir_to_create(path: &Path) -> Option<PathBuf> {
    let Some(text) = path.to_str() else {
        // A non-UTF8 path cannot be a `file:` URI, so use it verbatim.
        return non_empty_parent(path);
    };
    if is_in_memory_sqlite_path(text) {
        return None;
    }
    non_empty_parent(&sqlite_uri_filesystem_path(text))
}

/// The sidecar path a receipt store locks to mark itself a live writer on
/// `path`, or `None` for an in-memory database (which has no on-disk file for
/// sibling instances to coordinate on). Derived from the resolved filesystem
/// path so a `file:` URI and its plain-path spelling coordinate on the same
/// lock.
pub(crate) fn sqlite_writer_lock_path(path: &Path) -> Option<PathBuf> {
    sqlite_sidecar_lock_path(path, ".writer-lock")
}

/// The sidecar path serializing dispatch-intent reconcile passes across
/// sibling instances of the database at `path`. Separate from the writer
/// mark on purpose: taking this mutex must never disturb any instance's
/// lifetime mark, because the mark's continuous presence is what proves the
/// instance live to its siblings.
pub(crate) fn sqlite_reconcile_lock_path(path: &Path) -> Option<PathBuf> {
    sqlite_sidecar_lock_path(path, ".reconcile-lock")
}

/// The sidecar path an instance holds locked to mark the owner token
/// `owner_token` live on the database at `path`, or `None` for an in-memory
/// database. One file per open: the owner locks it before it can journal a
/// row and the OS releases the lock when the process exits, cleanly or not,
/// so reconciliation reads an acquirable lock as "this owner is gone"
/// without consulting a clock. Callers must shape-check foreign tokens with
/// [`is_owner_token_shaped`] before deriving a path from them.
pub(crate) fn sqlite_owner_mark_path(path: &Path, owner_token: &str) -> Option<PathBuf> {
    sqlite_sidecar_lock_path(path, &format!(".owner-{owner_token}-lock"))
}

/// True when `token` has the exact shape of an owner token this crate
/// generates (a hyphenated UUID). Journal rows are data: an arbitrary
/// `owner_token` string must never reach a filename, where it could escape
/// the database's directory or collide with another sidecar. A row whose
/// token fails the check simply has no mark to probe and stays claimable
/// only under whole-file exclusivity.
pub(crate) fn is_owner_token_shaped(token: &str) -> bool {
    token.len() == 36
        && token.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
}

fn sqlite_sidecar_lock_path(path: &Path, extension: &str) -> Option<PathBuf> {
    let Some(text) = path.to_str() else {
        // A non-UTF8 path cannot be a `file:` URI, so use it verbatim.
        return Some(append_lock_extension(path.to_path_buf(), extension));
    };
    if is_in_memory_sqlite_path(text) {
        return None;
    }
    Some(append_lock_extension(
        sqlite_uri_filesystem_path(text),
        extension,
    ))
}

fn append_lock_extension(path: PathBuf, extension: &str) -> PathBuf {
    let mut path = path.into_os_string();
    path.push(extension);
    PathBuf::from(path)
}

/// The parent of `path`, unless it is empty (a bare filename with no directory
/// component), in which case there is nothing to create.
fn non_empty_parent(path: &Path) -> Option<PathBuf> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
}

/// The filesystem path a rusqlite path points at, resolving a `file:` URI to
/// its on-disk filename by stripping the scheme, any `//authority`, and the
/// `?query`. A plain path (no `file:` scheme) is returned unchanged.
fn sqlite_uri_filesystem_path(text: &str) -> PathBuf {
    let Some(rest) = text.strip_prefix("file:") else {
        return PathBuf::from(text);
    };
    // Drop the URI query (`?mode=rwc`, `?cache=shared`); it is not part of the
    // filename.
    let without_query = rest.split_once('?').map_or(rest, |(name, _query)| name);
    // `file://authority/path` places the filesystem path after the authority;
    // `file:/path` and `file:path` have no authority. Strip a leading `//` and
    // the authority up to the next `/`.
    let filesystem = match without_query.strip_prefix("//") {
        Some(after_authority_marker) => match after_authority_marker.find('/') {
            Some(path_start) => &after_authority_marker[path_start..],
            None => "",
        },
        None => without_query,
    };
    PathBuf::from(filesystem)
}

pub use approval_store::SqliteApprovalStore;
pub use authority::SqliteCapabilityAuthority;
pub use batch_approval_store::SqliteBatchApprovalStore;
pub use budget_store::SqliteBudgetStore;
pub use eip3009_nonces::SqliteEip3009NonceStore;
pub use encrypted_blob::{
    decrypt_blob, encrypt_blob, BlobHandle, BlobStoreError, DecryptError, EncryptError,
    EncryptedBlob, SqliteEncryptedBlobStore, TenantId, TenantKey,
};
pub use execution_nonce_store::{SqliteExecutionNonceStore, SqliteExecutionNonceStoreError};
pub use iou_store::{SqliteIouEnvelopeStore, IOU_ENVELOPE_MIGRATION};
pub use memory_provenance_store::{SqliteMemoryProvenanceStore, SqliteMemoryProvenanceStoreError};
pub use receipt_store::{BackgroundCheckpointSigner, SqliteReceiptStore};
pub use revocation_store::SqliteRevocationStore;
pub use schema_version::{
    check_schema_version, stamp_schema_version, SchemaVersionError, CHIO_SQLITE_APPLICATION_ID,
};
pub use settle_attempts::SqliteSettlementRetryStore;

#[cfg(test)]
mod tests {
    use super::{is_in_memory_sqlite_path, sqlite_parent_dir_to_create};
    use std::path::{Path, PathBuf};

    #[test]
    fn resolves_parent_dir_from_file_uris_and_plain_paths() {
        // A `file:` URI with a query resolves to the real filesystem parent, not
        // a `file:`-prefixed directory folded out of the raw string.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new(
                "file:/var/lib/chio/receipts.db.revocations?mode=rwc"
            )),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A `file://` URI with an empty authority drops the `//`.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:///var/lib/chio/db?cache=shared")),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A plain filesystem path keeps its parent unchanged.
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("/var/lib/chio/receipts.db")),
            Some(PathBuf::from("/var/lib/chio"))
        );
        // A bare filename has no directory component to create.
        assert_eq!(sqlite_parent_dir_to_create(Path::new("receipts.db")), None);
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=rwc")),
            None
        );
        // In-memory databases have no backing directory.
        assert_eq!(sqlite_parent_dir_to_create(Path::new(":memory:")), None);
        assert_eq!(
            sqlite_parent_dir_to_create(Path::new("file:receipts.db?mode=memory")),
            None
        );
    }

    #[test]
    fn owner_token_shape_admits_only_hyphenated_uuids() {
        use super::is_owner_token_shaped;
        assert!(is_owner_token_shaped(
            "0198c0de-9a71-7bd2-8c8f-3a2b1c4d5e6f"
        ));
        for token in [
            "",
            "0198c0de-9a71-7bd2-8c8f-3a2b1c4d5e6",
            "0198c0de-9a71-7bd2-8c8f-3a2b1c4d5e6f0",
            "0198c0de/9a71-7bd2-8c8f-3a2b1c4d5e6f",
            "../escape-attempt-9a71-7bd2-8c8f-3a2b",
            "0198c0de.9a71.7bd2.8c8f.3a2b1c4d5e6f",
        ] {
            assert!(
                !is_owner_token_shaped(token),
                "{token:?} must not shape as an owner token"
            );
        }
    }

    #[test]
    fn classifies_in_memory_sqlite_paths() {
        for path in [
            ":memory:",
            ":MEMORY:",
            "file::memory:",
            "file:receipts.db?mode=memory",
            "file:receipts.db?cache=shared&mode=memory",
        ] {
            assert!(
                is_in_memory_sqlite_path(path),
                "{path} must classify as in-memory"
            );
        }
    }

    #[test]
    fn classifies_durable_sqlite_paths() {
        for path in [
            "receipts.db",
            "/var/lib/chio/receipts.db",
            "file:/var/lib/chio/receipts.db?mode=rwc",
            "file:receipts.db",
            "memory-notes.db",
        ] {
            assert!(
                !is_in_memory_sqlite_path(path),
                "{path} must classify as durable"
            );
        }
    }
}
