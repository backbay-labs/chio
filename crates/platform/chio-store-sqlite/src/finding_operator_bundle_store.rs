//! Durable public-artifact bundles used by the operator purchase runtime.
//!
//! Admission retains several digest-addressed constituents, but a production
//! purchase also needs one closed, typed set of exact artifacts to reconstruct
//! the verified market handshake and buyer proof. This store preserves that
//! canonical bundle under the Finding identity with exact-replay semantics.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::sha256_hex;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use thiserror::Error;

const SCHEMA_KEY: &str = "finding_operator_bundle";
const SUPPORTED_SCHEMA_VERSION: i32 = 0;
const SCHEMA_ANCHORS: &[&str] = &[
    "chio_finding_operator_bundles",
    "chio_finding_payloads",
    "chio_finding_operator_payments",
];
const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_TERMINAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 24 * 1024 * 1024;
const MAX_PURCHASE_JOB_BYTES: usize = 2 * 1024 * 1024;
const MAX_RETAINED_BUNDLES: i64 = 10_000;
const MAX_RETAINED_PURCHASE_JOBS: i64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingOperatorBundleRecord {
    pub finding_id: String,
    pub bundle_sha256: String,
    pub bundle_json: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingOperatorProofRecord {
    pub finding_id: String,
    pub proof_sha256: String,
    pub proof_json: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingOperatorPurchaseJobRecord {
    pub request_id: String,
    pub principal_id: String,
    pub request_sha256: String,
    pub job_sha256: String,
    pub job_json: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingOperatorBundleWriteOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingOperatorTerminalRecord {
    pub request_id: String,
    pub principal_id: String,
    pub request_sha256: String,
    pub result_sha256: String,
    pub result_json: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingOperatorTerminalWriteOutcome {
    Inserted,
    ExactReplay,
}

#[derive(Debug, Error)]
pub enum FindingOperatorBundleStoreError {
    #[error("finding operator bundle store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding operator bundle is invalid: {0}")]
    Invalid(&'static str),
    #[error("finding operator bundle exceeds the {MAX_BUNDLE_BYTES}-byte limit")]
    TooLarge,
    #[error("finding operator bundle conflicts with durable state")]
    Conflict,
    #[error("finding operator bundle store reached its 10000-bundle capacity")]
    Capacity,
    #[error("finding operator bundle store reached its 10000-purchase-job capacity")]
    PurchaseJobCapacity,
    #[error("finding operator bundle was not found")]
    NotFound,
    #[error("finding operator bundle failed its durable digest check")]
    DigestMismatch,
}

#[derive(Clone)]
pub struct SqliteFindingOperatorBundleStore {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteFindingOperatorBundleStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, FindingOperatorBundleStoreError> {
        let path = path.as_ref();
        if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
            fs::create_dir_all(parent)
                .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        }
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, FindingOperatorBundleStoreError> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(1)
            .build(manager)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let store = Self { pool };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), FindingOperatorBundleStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        crate::check_schema_version(&conn, SCHEMA_KEY, SUPPORTED_SCHEMA_VERSION, SCHEMA_ANCHORS)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_finding_operator_bundles (
                finding_id TEXT PRIMARY KEY,
                bundle_sha256 TEXT NOT NULL CHECK(length(bundle_sha256) = 64),
                bundle_json BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_finding_operator_terminals (
                request_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                result_sha256 TEXT NOT NULL CHECK(length(result_sha256) = 64),
                result_json BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_finding_operator_proofs (
                finding_id TEXT PRIMARY KEY,
                proof_sha256 TEXT NOT NULL CHECK(length(proof_sha256) = 64),
                proof_json BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_finding_operator_purchase_jobs (
                request_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                job_sha256 TEXT NOT NULL CHECK(length(job_sha256) = 64),
                job_json BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            "#,
        )
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        crate::stamp_schema_version(&conn, SCHEMA_KEY, SUPPORTED_SCHEMA_VERSION)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        Ok(())
    }

    pub fn put(
        &self,
        finding_id: &str,
        bundle_json: &[u8],
    ) -> Result<FindingOperatorBundleWriteOutcome, FindingOperatorBundleStoreError> {
        validate_finding_id(finding_id)?;
        validate_canonical_bundle(bundle_json)?;
        let bundle_sha256 = sha256_hex(bundle_json);
        let mut conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let existing = tx
            .query_row(
                "SELECT bundle_sha256, bundle_json FROM chio_finding_operator_bundles WHERE finding_id = ?1",
                [finding_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        if let Some((stored_sha256, stored_json)) = existing {
            if stored_sha256 != sha256_hex(&stored_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            if stored_sha256 == bundle_sha256 && stored_json == bundle_json {
                tx.commit().map_err(|error| {
                    FindingOperatorBundleStoreError::Unavailable(error.to_string())
                })?;
                return Ok(FindingOperatorBundleWriteOutcome::ExactReplay);
            }
            return Err(FindingOperatorBundleStoreError::Conflict);
        }
        let retained: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_bundles",
                [],
                |row| row.get(0),
            )
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        if retained >= MAX_RETAINED_BUNDLES {
            return Err(FindingOperatorBundleStoreError::Capacity);
        }
        tx.execute(
            "INSERT INTO chio_finding_operator_bundles (finding_id, bundle_sha256, bundle_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![finding_id, bundle_sha256, bundle_json, now_secs()],
        )
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        tx.commit()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        Ok(FindingOperatorBundleWriteOutcome::Inserted)
    }

    pub fn get(
        &self,
        finding_id: &str,
    ) -> Result<FindingOperatorBundleRecord, FindingOperatorBundleStoreError> {
        validate_finding_id(finding_id)?;
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let row = conn
            .query_row(
                "SELECT bundle_sha256, bundle_json FROM chio_finding_operator_bundles WHERE finding_id = ?1",
                [finding_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let Some((bundle_sha256, bundle_json)) = row else {
            return Err(FindingOperatorBundleStoreError::NotFound);
        };
        if sha256_hex(&bundle_json) != bundle_sha256 {
            return Err(FindingOperatorBundleStoreError::DigestMismatch);
        }
        validate_canonical_bundle(&bundle_json)?;
        Ok(FindingOperatorBundleRecord {
            finding_id: finding_id.to_owned(),
            bundle_sha256,
            bundle_json,
        })
    }

    /// Return retained bundles in deterministic Finding-id order. The caller
    /// supplies a hard bound so digest-addressed resolution cannot become an
    /// unbounded database scan.
    pub fn list(
        &self,
        limit: u64,
    ) -> Result<Vec<FindingOperatorBundleRecord>, FindingOperatorBundleStoreError> {
        if limit == 0 || limit > 10_000 {
            return Err(FindingOperatorBundleStoreError::Invalid(
                "bundle list limit",
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| FindingOperatorBundleStoreError::Invalid("bundle list limit"))?;
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let mut statement = conn
            .prepare(
                "SELECT finding_id, bundle_sha256, bundle_json FROM chio_finding_operator_bundles ORDER BY finding_id ASC LIMIT ?1",
            )
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let rows = statement
            .query_map([limit], |row| {
                Ok(FindingOperatorBundleRecord {
                    finding_id: row.get(0)?,
                    bundle_sha256: row.get(1)?,
                    bundle_json: row.get(2)?,
                })
            })
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let mut records = Vec::new();
        for row in rows {
            let record = row
                .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
            validate_finding_id(&record.finding_id)?;
            if record.bundle_sha256 != sha256_hex(&record.bundle_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            validate_canonical_bundle(&record.bundle_json)?;
            records.push(record);
        }
        Ok(records)
    }

    pub fn put_proof(
        &self,
        finding_id: &str,
        proof_json: &[u8],
    ) -> Result<FindingOperatorBundleWriteOutcome, FindingOperatorBundleStoreError> {
        validate_finding_id(finding_id)?;
        validate_canonical_json(proof_json, MAX_PROOF_BYTES, "proof bundle")?;
        let proof_sha256 = sha256_hex(proof_json);
        let mut conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let existing = tx
            .query_row(
                "SELECT proof_sha256, proof_json FROM chio_finding_operator_proofs WHERE finding_id = ?1",
                [finding_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        if let Some((stored_sha256, stored_json)) = existing {
            if stored_sha256 != sha256_hex(&stored_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            if stored_sha256 == proof_sha256 && stored_json == proof_json {
                tx.commit().map_err(|error| {
                    FindingOperatorBundleStoreError::Unavailable(error.to_string())
                })?;
                return Ok(FindingOperatorBundleWriteOutcome::ExactReplay);
            }
            return Err(FindingOperatorBundleStoreError::Conflict);
        }
        tx.execute(
            "INSERT INTO chio_finding_operator_proofs (finding_id, proof_sha256, proof_json, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![finding_id, proof_sha256, proof_json, now_secs()],
        )
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        tx.commit()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        Ok(FindingOperatorBundleWriteOutcome::Inserted)
    }

    pub fn get_proof(
        &self,
        finding_id: &str,
    ) -> Result<FindingOperatorProofRecord, FindingOperatorBundleStoreError> {
        validate_finding_id(finding_id)?;
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let row = conn
            .query_row(
                "SELECT proof_sha256, proof_json FROM chio_finding_operator_proofs WHERE finding_id = ?1",
                [finding_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let Some((proof_sha256, proof_json)) = row else {
            return Err(FindingOperatorBundleStoreError::NotFound);
        };
        if proof_sha256 != sha256_hex(&proof_json) {
            return Err(FindingOperatorBundleStoreError::DigestMismatch);
        }
        validate_canonical_json(&proof_json, MAX_PROOF_BYTES, "proof bundle")?;
        Ok(FindingOperatorProofRecord {
            finding_id: finding_id.to_owned(),
            proof_sha256,
            proof_json,
        })
    }

    pub fn proof_count(&self) -> Result<u64, FindingOperatorBundleStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_proofs",
                [],
                |row| row.get(0),
            )
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        u64::try_from(count).map_err(|_| {
            FindingOperatorBundleStoreError::Unavailable("proof count is negative".to_owned())
        })
    }

    /// Retain the immutable prepared purchase context before opening its
    /// reservation. This closes the crash window where a durable reservation
    /// exists but its signed bid and ask can no longer be reconstructed.
    pub fn put_purchase_job(
        &self,
        request_id: &str,
        principal_id: &str,
        request_sha256: &str,
        job_json: &[u8],
    ) -> Result<FindingOperatorBundleWriteOutcome, FindingOperatorBundleStoreError> {
        validate_digest(request_id, "request_id")?;
        validate_identifier(principal_id, "principal_id")?;
        validate_digest(request_sha256, "request_sha256")?;
        validate_canonical_json(job_json, MAX_PURCHASE_JOB_BYTES, "purchase job")?;
        let job_sha256 = sha256_hex(job_json);
        let mut conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let existing = load_purchase_job(&tx, request_id)?;
        if let Some(existing) = existing {
            if existing.job_sha256 != sha256_hex(&existing.job_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            if existing.principal_id == principal_id
                && existing.request_sha256 == request_sha256
                && existing.job_sha256 == job_sha256
                && existing.job_json == job_json
            {
                tx.commit().map_err(|error| {
                    FindingOperatorBundleStoreError::Unavailable(error.to_string())
                })?;
                return Ok(FindingOperatorBundleWriteOutcome::ExactReplay);
            }
            return Err(FindingOperatorBundleStoreError::Conflict);
        }
        let retained: i64 = tx
            .query_row(
                "SELECT COUNT(*) FROM chio_finding_operator_purchase_jobs",
                [],
                |row| row.get(0),
            )
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        if retained >= MAX_RETAINED_PURCHASE_JOBS {
            return Err(FindingOperatorBundleStoreError::PurchaseJobCapacity);
        }
        tx.execute(
            "INSERT INTO chio_finding_operator_purchase_jobs (request_id, principal_id, request_sha256, job_sha256, job_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![request_id, principal_id, request_sha256, job_sha256, job_json, now_secs()],
        )
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        tx.commit()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        Ok(FindingOperatorBundleWriteOutcome::Inserted)
    }

    pub fn get_purchase_job(
        &self,
        request_id: &str,
    ) -> Result<Option<FindingOperatorPurchaseJobRecord>, FindingOperatorBundleStoreError> {
        validate_digest(request_id, "request_id")?;
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let job = load_purchase_job(&conn, request_id)?;
        if let Some(record) = job.as_ref() {
            if record.job_sha256 != sha256_hex(&record.job_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            validate_canonical_json(&record.job_json, MAX_PURCHASE_JOB_BYTES, "purchase job")?;
        }
        Ok(job)
    }

    pub fn purchase_job_count(&self) -> Result<u64, FindingOperatorBundleStoreError> {
        self.count_rows("chio_finding_operator_purchase_jobs")
    }

    /// Retain an exact public purchase terminal for restart-safe route replay.
    pub fn put_terminal(
        &self,
        request_id: &str,
        principal_id: &str,
        request_sha256: &str,
        result_json: &[u8],
    ) -> Result<FindingOperatorTerminalWriteOutcome, FindingOperatorBundleStoreError> {
        validate_digest(request_id, "request_id")?;
        validate_identifier(principal_id, "principal_id")?;
        validate_digest(request_sha256, "request_sha256")?;
        validate_canonical_terminal(result_json)?;
        let result_sha256 = sha256_hex(result_json);
        let mut conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let existing = load_terminal(&tx, request_id)?;
        if let Some(existing) = existing {
            if existing.result_sha256 != sha256_hex(&existing.result_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            if existing.principal_id == principal_id
                && existing.request_sha256 == request_sha256
                && existing.result_sha256 == result_sha256
                && existing.result_json == result_json
            {
                tx.commit().map_err(|error| {
                    FindingOperatorBundleStoreError::Unavailable(error.to_string())
                })?;
                return Ok(FindingOperatorTerminalWriteOutcome::ExactReplay);
            }
            return Err(FindingOperatorBundleStoreError::Conflict);
        }
        tx.execute(
            "INSERT INTO chio_finding_operator_terminals (request_id, principal_id, request_sha256, result_sha256, result_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![request_id, principal_id, request_sha256, result_sha256, result_json, now_secs()],
        )
        .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        tx.commit()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        Ok(FindingOperatorTerminalWriteOutcome::Inserted)
    }

    pub fn get_terminal(
        &self,
        request_id: &str,
    ) -> Result<Option<FindingOperatorTerminalRecord>, FindingOperatorBundleStoreError> {
        validate_digest(request_id, "request_id")?;
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let terminal = load_terminal(&conn, request_id)?;
        if let Some(record) = terminal.as_ref() {
            if record.result_sha256 != sha256_hex(&record.result_json) {
                return Err(FindingOperatorBundleStoreError::DigestMismatch);
            }
            validate_canonical_terminal(&record.result_json)?;
        }
        Ok(terminal)
    }

    /// Number of retained public artifact bundles.
    pub fn bundle_count(&self) -> Result<u64, FindingOperatorBundleStoreError> {
        self.count_rows("chio_finding_operator_bundles")
    }

    /// Number of retained public purchase terminals.
    pub fn terminal_count(&self) -> Result<u64, FindingOperatorBundleStoreError> {
        self.count_rows("chio_finding_operator_terminals")
    }

    fn count_rows(&self, table: &'static str) -> Result<u64, FindingOperatorBundleStoreError> {
        let conn = self
            .pool
            .get()
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))?;
        u64::try_from(count).map_err(|_| {
            FindingOperatorBundleStoreError::Unavailable("negative row count".to_owned())
        })
    }
}

fn load_terminal(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Option<FindingOperatorTerminalRecord>, FindingOperatorBundleStoreError> {
    conn.query_row(
        "SELECT principal_id, request_sha256, result_sha256, result_json FROM chio_finding_operator_terminals WHERE request_id = ?1",
        [request_id],
        |row| {
            Ok(FindingOperatorTerminalRecord {
                request_id: request_id.to_owned(),
                principal_id: row.get(0)?,
                request_sha256: row.get(1)?,
                result_sha256: row.get(2)?,
                result_json: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))
}

fn load_purchase_job(
    conn: &rusqlite::Connection,
    request_id: &str,
) -> Result<Option<FindingOperatorPurchaseJobRecord>, FindingOperatorBundleStoreError> {
    conn.query_row(
        "SELECT principal_id, request_sha256, job_sha256, job_json FROM chio_finding_operator_purchase_jobs WHERE request_id = ?1",
        [request_id],
        |row| {
            Ok(FindingOperatorPurchaseJobRecord {
                request_id: request_id.to_owned(),
                principal_id: row.get(0)?,
                request_sha256: row.get(1)?,
                job_sha256: row.get(2)?,
                job_json: row.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|error| FindingOperatorBundleStoreError::Unavailable(error.to_string()))
}

fn validate_finding_id(finding_id: &str) -> Result<(), FindingOperatorBundleStoreError> {
    if finding_id.len() != 64
        || !finding_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FindingOperatorBundleStoreError::Invalid("finding_id"));
    }
    Ok(())
}

fn validate_canonical_bundle(bundle_json: &[u8]) -> Result<(), FindingOperatorBundleStoreError> {
    if bundle_json.is_empty() {
        return Err(FindingOperatorBundleStoreError::Invalid("bundle_json"));
    }
    if bundle_json.len() > MAX_BUNDLE_BYTES {
        return Err(FindingOperatorBundleStoreError::TooLarge);
    }
    let raw = std::str::from_utf8(bundle_json)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid("bundle_json"))?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid("bundle_json"))?;
    if canonical != bundle_json {
        return Err(FindingOperatorBundleStoreError::Invalid("bundle_json"));
    }
    let value: serde_json::Value = serde_json::from_slice(bundle_json)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid("bundle_json"))?;
    if !value.is_object() {
        return Err(FindingOperatorBundleStoreError::Invalid("bundle_json"));
    }
    Ok(())
}

fn validate_canonical_terminal(result_json: &[u8]) -> Result<(), FindingOperatorBundleStoreError> {
    if result_json.is_empty() || result_json.len() > MAX_TERMINAL_BYTES {
        return Err(FindingOperatorBundleStoreError::Invalid("result_json"));
    }
    let raw = std::str::from_utf8(result_json)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid("result_json"))?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid("result_json"))?;
    let value: serde_json::Value = serde_json::from_slice(result_json)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid("result_json"))?;
    if canonical != result_json || !value.is_object() {
        return Err(FindingOperatorBundleStoreError::Invalid("result_json"));
    }
    Ok(())
}

fn validate_canonical_json(
    bytes: &[u8],
    max_bytes: usize,
    field: &'static str,
) -> Result<(), FindingOperatorBundleStoreError> {
    if bytes.is_empty() || bytes.len() > max_bytes {
        return Err(FindingOperatorBundleStoreError::Invalid(field));
    }
    let raw =
        std::str::from_utf8(bytes).map_err(|_| FindingOperatorBundleStoreError::Invalid(field))?;
    let canonical = chio_core::canonical::canonical_json_bytes_from_str(raw)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid(field))?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| FindingOperatorBundleStoreError::Invalid(field))?;
    if canonical != bytes || !value.is_object() {
        return Err(FindingOperatorBundleStoreError::Invalid(field));
    }
    Ok(())
}

fn validate_digest(
    value: &str,
    field: &'static str,
) -> Result<(), FindingOperatorBundleStoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(FindingOperatorBundleStoreError::Invalid(field));
    }
    Ok(())
}

fn validate_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), FindingOperatorBundleStoreError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(FindingOperatorBundleStoreError::Invalid(field));
    }
    Ok(())
}

fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn finding_id() -> String {
        "a".repeat(64)
    }

    #[test]
    fn canonical_bundle_survives_restart_and_replays_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let bundle = br#"{"schema":"chio.finding.operator-bundle.v1"}"#;
        let store = SqliteFindingOperatorBundleStore::open(&path).unwrap();
        assert_eq!(
            store.put(&finding_id(), bundle).unwrap(),
            FindingOperatorBundleWriteOutcome::Inserted
        );
        drop(store);
        let reopened = SqliteFindingOperatorBundleStore::open(&path).unwrap();
        assert_eq!(
            reopened.put(&finding_id(), bundle).unwrap(),
            FindingOperatorBundleWriteOutcome::ExactReplay
        );
        assert_eq!(reopened.get(&finding_id()).unwrap().bundle_json, bundle);
    }

    #[test]
    fn changed_or_noncanonical_bundle_is_rejected() {
        let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
        let first = br#"{"a":1}"#;
        store.put(&finding_id(), first).unwrap();
        assert!(matches!(
            store.put(&finding_id(), br#"{"a":2}"#),
            Err(FindingOperatorBundleStoreError::Conflict)
        ));
        assert!(matches!(
            store.put(&"b".repeat(64), b"{ \"a\": 1 }"),
            Err(FindingOperatorBundleStoreError::Invalid("bundle_json"))
        ));
    }

    #[test]
    fn admission_capacity_matches_the_complete_resolver_scan() {
        let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
        let bundle = br#"{"a":1}"#;
        let digest = sha256_hex(bundle);
        {
            let mut conn = store.pool.get().unwrap();
            let tx = conn.transaction().unwrap();
            for index in 0..MAX_RETAINED_BUNDLES {
                tx.execute(
                    "INSERT INTO chio_finding_operator_bundles (finding_id, bundle_sha256, bundle_json, created_at) VALUES (?1, ?2, ?3, 1)",
                    params![format!("{index:064x}"), digest, bundle],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        assert_eq!(
            store.list(MAX_RETAINED_BUNDLES as u64).unwrap().len(),
            10_000
        );
        assert!(matches!(
            store.put(&"f".repeat(64), bundle),
            Err(FindingOperatorBundleStoreError::Capacity)
        ));
        assert_eq!(
            store.put(&format!("{:064x}", 1), bundle).unwrap(),
            FindingOperatorBundleWriteOutcome::ExactReplay
        );
    }

    #[test]
    fn public_proof_survives_restart_and_replays_exactly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operator.db");
        let proof = br#"{"schema":"chio.finding.operator-proof-bundle.v1"}"#;
        let store = SqliteFindingOperatorBundleStore::open(&path).unwrap();
        assert_eq!(
            store.put_proof(&finding_id(), proof).unwrap(),
            FindingOperatorBundleWriteOutcome::Inserted
        );
        assert_eq!(store.proof_count().unwrap(), 1);
        drop(store);

        let reopened = SqliteFindingOperatorBundleStore::open(&path).unwrap();
        assert_eq!(
            reopened.put_proof(&finding_id(), proof).unwrap(),
            FindingOperatorBundleWriteOutcome::ExactReplay
        );
        let record = reopened.get_proof(&finding_id()).unwrap();
        assert_eq!(record.proof_json, proof);
        assert_eq!(record.proof_sha256, sha256_hex(proof));
        assert!(matches!(
            reopened.put_proof(&finding_id(), br#"{"schema":"changed"}"#),
            Err(FindingOperatorBundleStoreError::Conflict)
        ));
    }

    #[test]
    fn purchase_job_precedes_and_survives_terminal_state() {
        let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
        let request_id = "e".repeat(64);
        let request_sha256 = "f".repeat(64);
        let job = br#"{"schema":"chio.finding.operator-purchase-job.v1"}"#;
        assert_eq!(
            store
                .put_purchase_job(&request_id, "buyer-1", &request_sha256, job)
                .unwrap(),
            FindingOperatorBundleWriteOutcome::Inserted
        );
        assert_eq!(
            store
                .put_purchase_job(&request_id, "buyer-1", &request_sha256, job)
                .unwrap(),
            FindingOperatorBundleWriteOutcome::ExactReplay
        );
        let record = store.get_purchase_job(&request_id).unwrap().unwrap();
        assert_eq!(record.job_json, job);
        assert_eq!(store.purchase_job_count().unwrap(), 1);
        assert!(matches!(
            store.put_purchase_job(&request_id, "buyer-2", &request_sha256, job),
            Err(FindingOperatorBundleStoreError::Conflict)
        ));
    }

    #[test]
    fn purchase_job_capacity_preserves_exact_replay() {
        let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
        let job = br#"{"schema":"chio.finding.operator-purchase-job.v1"}"#;
        let job_sha256 = sha256_hex(job);
        let request_sha256 = "f".repeat(64);
        {
            let mut conn = store.pool.get().unwrap();
            let tx = conn.transaction().unwrap();
            for index in 0..MAX_RETAINED_PURCHASE_JOBS {
                let request_id = format!("{index:064x}");
                tx.execute(
                    "INSERT INTO chio_finding_operator_purchase_jobs (request_id, principal_id, request_sha256, job_sha256, job_json, created_at) VALUES (?1, 'buyer-1', ?2, ?3, ?4, 1)",
                    params![request_id, request_sha256, job_sha256, job],
                )
                .unwrap();
            }
            tx.commit().unwrap();
        }
        assert_eq!(
            store.purchase_job_count().unwrap(),
            MAX_RETAINED_PURCHASE_JOBS as u64
        );
        assert!(matches!(
            store.put_purchase_job(&"e".repeat(64), "buyer-1", &request_sha256, job),
            Err(FindingOperatorBundleStoreError::PurchaseJobCapacity)
        ));
        assert_eq!(
            store
                .put_purchase_job(&format!("{:064x}", 1), "buyer-1", &request_sha256, job)
                .unwrap(),
            FindingOperatorBundleWriteOutcome::ExactReplay
        );
    }

    #[test]
    fn terminal_replay_is_principal_and_request_bound() {
        let store = SqliteFindingOperatorBundleStore::open_in_memory().unwrap();
        let request_id = "c".repeat(64);
        let request_sha256 = "d".repeat(64);
        let result = br#"{"schema":"chio.finding.purchase-result.v1"}"#;
        assert_eq!(
            store
                .put_terminal(&request_id, "buyer-1", &request_sha256, result)
                .unwrap(),
            FindingOperatorTerminalWriteOutcome::Inserted
        );
        assert_eq!(
            store
                .put_terminal(&request_id, "buyer-1", &request_sha256, result)
                .unwrap(),
            FindingOperatorTerminalWriteOutcome::ExactReplay
        );
        assert_eq!(
            store
                .get_terminal(&request_id)
                .unwrap()
                .unwrap()
                .result_json,
            result
        );
        assert!(matches!(
            store.put_terminal(&request_id, "buyer-2", &request_sha256, result),
            Err(FindingOperatorBundleStoreError::Conflict)
        ));
    }
}
