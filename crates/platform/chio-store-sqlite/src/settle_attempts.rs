//! SQLite-backed leased settlement work.

use chio_core::hashing::sha256;
use chio_kernel::ReceiptStoreError;
use chio_settle::{
    classify_attempt, validate_settlement_claim, DeadLetterRecord, RetryDecision, RetryPolicy,
    SettlementAttemptClaim, SettlementFailureCode, SettlementOutcomeStore, SettlementRoute,
    SettlementRouteError, SettlementRoutingInput, SettlementStoreBinding,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

use crate::dead_letters::{
    insert_dead_letter_on_connection, read_dead_letter_on_connection, DeadLetterStoreError,
    SETTLE_DEAD_LETTERS_MIGRATION,
};

/// Additive schema for pending and retryable settlement work.
pub const SETTLE_ATTEMPTS_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS settle_attempts (
    receipt_id           TEXT PRIMARY KEY,
    finalized_at         INTEGER NOT NULL CHECK (finalized_at >= 0),
    work_kind            TEXT NOT NULL CHECK (
                            work_kind IN ('pending_observation', 'retry_scheduled')
                         ),
    attempts             INTEGER NOT NULL CHECK (attempts BETWEEN 0 AND 4294967295),
    next_visible_at_ms   INTEGER NOT NULL CHECK (next_visible_at_ms >= 0),
    row_version          INTEGER NOT NULL CHECK (row_version >= 0),
    lease_owner          TEXT CHECK (
                            lease_owner IS NULL OR
                            (length(lease_owner) BETWEEN 1 AND 128)
                         ),
    lease_token          TEXT CHECK (
                            lease_token IS NULL OR
                            (length(lease_token) BETWEEN 1 AND 128)
                         ),
    lease_until_ms       INTEGER CHECK (lease_until_ms IS NULL OR lease_until_ms >= 0),
    reason_code          TEXT,
    reason_detail_sha256 BLOB CHECK (
                            reason_detail_sha256 IS NULL OR
                            length(reason_detail_sha256) = 32
                         ),
    updated_at_ms        INTEGER NOT NULL CHECK (updated_at_ms >= 0),
    CHECK ((lease_owner IS NULL AND lease_token IS NULL AND lease_until_ms IS NULL) OR
           (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_until_ms IS NOT NULL)),
    CHECK ((work_kind = 'pending_observation' AND attempts = 0 AND
            reason_code IS NULL AND reason_detail_sha256 IS NULL) OR
           (work_kind = 'retry_scheduled' AND attempts > 0 AND
            reason_code IS NOT NULL AND reason_detail_sha256 IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_settle_attempts_visible
    ON settle_attempts(next_visible_at_ms, lease_until_ms, receipt_id);

CREATE TRIGGER IF NOT EXISTS trg_settle_attempts_reject_terminal_insert
BEFORE INSERT ON settle_attempts
WHEN EXISTS (
    SELECT 1 FROM settle_dead_letters WHERE receipt_id = NEW.receipt_id
)
BEGIN
    SELECT RAISE(ABORT, 'settlement receipt already dead-lettered');
END;

CREATE TRIGGER IF NOT EXISTS trg_settle_attempts_reject_terminal_update
BEFORE UPDATE OF receipt_id ON settle_attempts
WHEN EXISTS (
    SELECT 1 FROM settle_dead_letters WHERE receipt_id = NEW.receipt_id
)
BEGIN
    SELECT RAISE(ABORT, 'settlement receipt already dead-lettered');
END;

CREATE TRIGGER IF NOT EXISTS trg_settle_dead_letters_reject_attempt_insert
BEFORE INSERT ON settle_dead_letters
WHEN EXISTS (
    SELECT 1 FROM settle_attempts WHERE receipt_id = NEW.receipt_id
)
BEGIN
    SELECT RAISE(ABORT, 'settlement receipt still has active work');
END;

CREATE TRIGGER IF NOT EXISTS trg_settle_dead_letters_reject_attempt_update
BEFORE UPDATE OF receipt_id ON settle_dead_letters
WHEN EXISTS (
    SELECT 1 FROM settle_attempts WHERE receipt_id = NEW.receipt_id
)
BEGIN
    SELECT RAISE(ABORT, 'settlement receipt still has active work');
END;
"#;

/// SQLite implementation of the leased settlement outcome store.
pub struct SqliteSettlementOutcomeStore {
    pool: Pool<SqliteConnectionManager>,
    writer: Option<crate::receipt_store::WriterHandle>,
    binding: SettlementStoreBinding,
}

impl SqliteSettlementOutcomeStore {
    /// Open a standalone store for tests and operator tooling.
    pub fn open_with_pool(
        pool: Pool<SqliteConnectionManager>,
    ) -> Result<Self, SettlementRouteError> {
        let connection = pool.get().map_err(backend_error)?;
        connection
            .execute_batch(SETTLE_DEAD_LETTERS_MIGRATION)
            .map_err(backend_error)?;
        connection
            .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
            .map_err(backend_error)?;
        Ok(Self {
            pool,
            writer: None,
            binding: new_store_binding(),
        })
    }

    /// Open a store sharing the receipt store's single writer and binding.
    pub fn open_alongside(store: &crate::SqliteReceiptStore) -> Result<Self, SettlementRouteError> {
        let writer = store.writer_handle();
        let Some(binding) = writer.settlement_store_binding() else {
            return Err(invalid_record("receipt store lacks settlement projection"));
        };
        writer
            .run_write(|connection| {
                connection.execute_batch(SETTLE_DEAD_LETTERS_MIGRATION)?;
                connection.execute_batch(SETTLE_ATTEMPTS_MIGRATION)?;
                Ok(())
            })
            .map_err(receipt_error_to_route)?;
        Ok(Self {
            pool: store.pool.clone(),
            writer: Some(writer),
            binding,
        })
    }

    fn run_write<T, F>(&self, job: F) -> Result<T, SettlementRouteError>
    where
        T: Send + 'static,
        F: FnOnce(&mut rusqlite::Connection) -> Result<T, SettlementRouteError> + Send + 'static,
    {
        match &self.writer {
            Some(writer) => writer
                .run_write(move |connection| job(connection).map_err(route_error_to_receipt))
                .map_err(receipt_error_to_route),
            None => {
                let mut connection = self.pool.get().map_err(backend_error)?;
                job(&mut connection)
            }
        }
    }
}

fn new_store_binding() -> SettlementStoreBinding {
    SettlementStoreBinding::from_digest(*sha256(Uuid::now_v7().as_bytes()).as_bytes())
}

fn backend_error(error: impl std::fmt::Display) -> SettlementRouteError {
    SettlementRouteError::Backend {
        detail: error.to_string(),
    }
}

fn conflict(detail: impl Into<String>) -> SettlementRouteError {
    SettlementRouteError::Conflict {
        detail: detail.into(),
    }
}

fn invalid_record(detail: impl Into<String>) -> SettlementRouteError {
    SettlementRouteError::InvalidRecord {
        detail: detail.into(),
    }
}

const WRITER_ROUTE_BACKEND_TAG: &str = "chio-store-sqlite/settlement-route/backend:";
const WRITER_ROUTE_CONFLICT_TAG: &str = "chio-store-sqlite/settlement-route/conflict:";
const WRITER_ROUTE_INVALID_TAG: &str = "chio-store-sqlite/settlement-route/invalid-record:";

fn route_error_to_receipt(error: SettlementRouteError) -> ReceiptStoreError {
    match error {
        SettlementRouteError::Backend { detail } => {
            ReceiptStoreError::Pool(format!("{WRITER_ROUTE_BACKEND_TAG}{detail}"))
        }
        SettlementRouteError::Conflict { detail } => {
            ReceiptStoreError::Conflict(format!("{WRITER_ROUTE_CONFLICT_TAG}{detail}"))
        }
        SettlementRouteError::InvalidRecord { detail } => {
            ReceiptStoreError::InvalidOutcome(format!("{WRITER_ROUTE_INVALID_TAG}{detail}"))
        }
    }
}

fn receipt_error_to_route(error: ReceiptStoreError) -> SettlementRouteError {
    match error {
        ReceiptStoreError::Pool(detail) => match detail.strip_prefix(WRITER_ROUTE_BACKEND_TAG) {
            Some(detail) => backend_error(detail),
            None => backend_error(format!("receipt writer pool error: {detail}")),
        },
        ReceiptStoreError::Conflict(detail) => {
            match detail.strip_prefix(WRITER_ROUTE_CONFLICT_TAG) {
                Some(detail) => conflict(detail),
                None => backend_error(format!("receipt writer conflict: {detail}")),
            }
        }
        ReceiptStoreError::InvalidOutcome(detail) => {
            match detail.strip_prefix(WRITER_ROUTE_INVALID_TAG) {
                Some(detail) => invalid_record(detail),
                None => backend_error(format!("receipt writer invalid outcome: {detail}")),
            }
        }
        other => backend_error(other),
    }
}

fn attempt_projection_read_error(error: rusqlite::Error) -> ReceiptStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => ReceiptStoreError::Conflict(
            "settlement attempt zero contains an invalid SQLite value".to_string(),
        ),
        other => ReceiptStoreError::Sqlite(other),
    }
}

fn dead_letter_error_to_route(error: DeadLetterStoreError) -> SettlementRouteError {
    match error {
        DeadLetterStoreError::Backend(detail) => backend_error(detail),
        DeadLetterStoreError::Conflict(detail) => conflict(detail),
        DeadLetterStoreError::InvalidRecord(detail) => invalid_record(detail),
    }
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, SettlementRouteError> {
    value
        .try_into()
        .map_err(|_| invalid_record(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, SettlementRouteError> {
    value
        .try_into()
        .map_err(|_| invalid_record(format!("{field} is negative")))
}

fn stored_u32(value: i64, field: &'static str) -> Result<u32, SettlementRouteError> {
    value
        .try_into()
        .map_err(|_| invalid_record(format!("{field} is outside the u32 range")))
}

fn attempt_row_error(error: rusqlite::Error) -> SettlementRouteError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => {
            invalid_record("settlement attempt row contains an invalid SQLite value")
        }
        other => backend_error(other),
    }
}

fn validate_claim_input(
    worker_id: &str,
    now_ms: u64,
    lease_ms: u64,
    limit: usize,
) -> Result<(i64, i64), SettlementRouteError> {
    validate_settlement_claim(worker_id, lease_ms, limit)
        .map_err(|error| invalid_record(error.to_string()))?;
    let lease_until_ms = now_ms
        .checked_add(lease_ms)
        .ok_or_else(|| invalid_record("settlement lease deadline overflows u64"))?;
    Ok((
        sqlite_i64(now_ms, "claim time")?,
        sqlite_i64(lease_until_ms, "lease deadline")?,
    ))
}

/// Insert attempt-zero work inside the caller's receipt transaction.
pub(crate) fn insert_attempt_zero_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
    finalized_at: u64,
    next_visible_at_ms: u64,
) -> Result<(), ReceiptStoreError> {
    let finalized_at: i64 = finalized_at
        .try_into()
        .map_err(|_: std::num::TryFromIntError| {
            ReceiptStoreError::Canonical(
                "settlement finalization time exceeds SQLite integer range".to_string(),
            )
        })?;
    let next_visible_at_ms: i64 =
        next_visible_at_ms
            .try_into()
            .map_err(|_: std::num::TryFromIntError| {
                ReceiptStoreError::Canonical(
                    "settlement visibility time exceeds SQLite integer range".to_string(),
                )
            })?;
    let inserted = tx
        .execute(
            "INSERT INTO settle_attempts (\
            receipt_id, finalized_at, work_kind, attempts, next_visible_at_ms, row_version, \
            lease_owner, lease_token, lease_until_ms, reason_code, reason_detail_sha256, \
            updated_at_ms\
         ) VALUES (?1, ?2, 'pending_observation', 0, ?3, 0, NULL, NULL, NULL, NULL, NULL, ?3)",
            params![receipt_id, finalized_at, next_visible_at_ms],
        )
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) {
                ReceiptStoreError::Conflict(
                    "settlement attempt zero conflicts with durable state".to_string(),
                )
            } else {
                ReceiptStoreError::Sqlite(error)
            }
        })?;
    if inserted != 1 {
        return Err(ReceiptStoreError::Conflict(
            "settlement attempt zero did not insert exactly one row".to_string(),
        ));
    }
    let stored = tx
        .query_row(
            "SELECT finalized_at, work_kind, attempts, next_visible_at_ms, row_version, \
                    lease_owner, lease_token, lease_until_ms, reason_code, \
                    reason_detail_sha256, updated_at_ms \
             FROM settle_attempts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<i64>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(attempt_projection_read_error)?;
    let expected = (
        finalized_at,
        "pending_observation".to_string(),
        0,
        next_visible_at_ms,
        0,
        None,
        None,
        None,
        None,
        None,
        next_visible_at_ms,
    );
    if stored != Some(expected) {
        return Err(ReceiptStoreError::Conflict(
            "settlement attempt zero does not match its inserted projection".to_string(),
        ));
    }
    Ok(())
}

struct AttemptState {
    finalized_at: u64,
    attempts: u32,
    row_version: u64,
    next_visible_at_ms: u64,
    lease_until_ms: Option<u64>,
}

struct ClaimedAttemptState {
    finalized_at: u64,
    attempts: u32,
    row_version: u64,
    lease_owner: String,
    lease_token: String,
    lease_until_ms: u64,
}

fn validate_work_shape(
    work_kind: &str,
    attempts: u32,
    reason_code: Option<String>,
    reason_detail_sha256: Option<Vec<u8>>,
) -> Result<(), SettlementRouteError> {
    match (work_kind, attempts, reason_code, reason_detail_sha256) {
        ("pending_observation", 0, None, None) => Ok(()),
        ("retry_scheduled", attempt, Some(code), Some(digest)) if attempt > 0 => {
            SettlementFailureCode::try_from(code.as_str())
                .map_err(|error| invalid_record(error.to_string()))?;
            let _: [u8; 32] = digest
                .try_into()
                .map_err(|_| invalid_record("settlement reason digest is not 32 bytes"))?;
            Ok(())
        }
        _ => Err(invalid_record(
            "settlement attempt work shape is inconsistent",
        )),
    }
}

fn validate_lease_shape(
    lease_owner: Option<&str>,
    lease_token: Option<&str>,
    lease_until_ms: Option<i64>,
) -> Result<Option<u64>, SettlementRouteError> {
    match (lease_owner, lease_token, lease_until_ms) {
        (None, None, None) => Ok(None),
        (Some(owner), Some(token), Some(deadline))
            if !owner.is_empty()
                && owner.len() <= chio_settle::MAX_SETTLEMENT_WORKER_ID_BYTES
                && !token.is_empty()
                && token.len() <= 128 =>
        {
            stored_u64(deadline, "lease_until_ms").map(Some)
        }
        _ => Err(invalid_record(
            "settlement attempt lease fields are inconsistent",
        )),
    }
}

fn read_attempt_state(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
) -> Result<Option<AttemptState>, SettlementRouteError> {
    let overlaps_terminal = tx
        .query_row(
            "SELECT EXISTS(\
                 SELECT 1 FROM settle_attempts AS attempt \
                 INNER JOIN settle_dead_letters AS terminal USING (receipt_id) \
                 WHERE attempt.receipt_id = ?1\
             )",
            [receipt_id],
            |row| row.get::<_, bool>(0),
        )
        .map_err(attempt_row_error)?;
    if overlaps_terminal {
        return Err(invalid_record(
            "settlement attempt overlaps terminal dead-letter state",
        ));
    }

    let stored = tx
        .query_row(
            "SELECT finalized_at, attempts, row_version, next_visible_at_ms, lease_owner, \
                    lease_token, lease_until_ms, work_kind, reason_code, \
                    reason_detail_sha256, updated_at_ms \
             FROM settle_attempts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(attempt_row_error)?;
    stored
        .map(
            |(
                finalized_at,
                attempts,
                row_version,
                next_visible_at_ms,
                lease_owner,
                lease_token,
                lease_until_ms,
                work_kind,
                reason_code,
                reason_detail_sha256,
                updated_at_ms,
            )| {
                let attempts = stored_u32(attempts, "attempts")?;
                validate_work_shape(&work_kind, attempts, reason_code, reason_detail_sha256)?;
                let lease_until_ms = validate_lease_shape(
                    lease_owner.as_deref(),
                    lease_token.as_deref(),
                    lease_until_ms,
                )?;
                stored_u64(updated_at_ms, "updated_at_ms")?;
                Ok(AttemptState {
                    finalized_at: stored_u64(finalized_at, "finalized_at")?,
                    attempts,
                    row_version: stored_u64(row_version, "row_version")?,
                    next_visible_at_ms: stored_u64(next_visible_at_ms, "next_visible_at_ms")?,
                    lease_until_ms,
                })
            },
        )
        .transpose()
}

fn claim_one_tx(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
    worker_id: &str,
    now_ms: u64,
    now_i64: i64,
    lease_until_ms: u64,
    lease_until_i64: i64,
) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
    let Some(state) = read_attempt_state(tx, receipt_id)? else {
        return Ok(None);
    };
    if state.next_visible_at_ms > now_ms
        || matches!(state.lease_until_ms, Some(deadline) if deadline > now_ms)
    {
        return Ok(None);
    }
    let row_version = state
        .row_version
        .checked_add(1)
        .ok_or_else(|| invalid_record("settlement row version overflows u64"))?;
    let row_version_i64 = sqlite_i64(row_version, "row_version")?;
    let lease_token = Uuid::now_v7().to_string();
    let affected = tx
        .execute(
            "UPDATE settle_attempts SET row_version = ?1, lease_owner = ?2, lease_token = ?3, \
                lease_until_ms = ?4, updated_at_ms = ?5 \
             WHERE receipt_id = ?6 AND row_version = ?7 AND next_visible_at_ms <= ?5 \
               AND (lease_until_ms IS NULL OR lease_until_ms <= ?5)",
            params![
                row_version_i64,
                worker_id,
                lease_token.as_str(),
                lease_until_i64,
                now_i64,
                receipt_id,
                sqlite_i64(state.row_version, "row_version")?,
            ],
        )
        .map_err(backend_error)?;
    if affected != 1 {
        return Err(conflict("settlement claim changed before lease commit"));
    }
    Ok(Some(SettlementAttemptClaim {
        receipt_id: receipt_id.to_string(),
        finalized_at: state.finalized_at,
        attempts: state.attempts,
        row_version,
        lease_owner: worker_id.to_string(),
        lease_token,
        lease_until_ms,
    }))
}

fn read_claimed_attempt(
    tx: &rusqlite::Transaction<'_>,
    receipt_id: &str,
) -> Result<Option<ClaimedAttemptState>, SettlementRouteError> {
    let stored = tx
        .query_row(
            "SELECT finalized_at, attempts, row_version, lease_owner, lease_token, \
                    lease_until_ms, work_kind, reason_code, reason_detail_sha256, \
                    next_visible_at_ms, updated_at_ms \
             FROM settle_attempts WHERE receipt_id = ?1",
            [receipt_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            },
        )
        .optional()
        .map_err(attempt_row_error)?;
    let Some((
        finalized_at,
        attempts,
        row_version,
        lease_owner,
        lease_token,
        lease_until_ms,
        work_kind,
        reason_code,
        reason_detail_sha256,
        next_visible_at_ms,
        updated_at_ms,
    )) = stored
    else {
        return Ok(None);
    };
    let finalized_at = stored_u64(finalized_at, "finalized_at")?;
    let attempts = stored_u32(attempts, "attempts")?;
    let row_version = stored_u64(row_version, "row_version")?;
    stored_u64(next_visible_at_ms, "next_visible_at_ms")?;
    stored_u64(updated_at_ms, "updated_at_ms")?;
    let Some(validated_lease_until_ms) = validate_lease_shape(
        lease_owner.as_deref(),
        lease_token.as_deref(),
        lease_until_ms,
    )?
    else {
        return Err(invalid_record(
            "claimed settlement row has an incomplete lease",
        ));
    };
    let (Some(lease_owner), Some(lease_token)) = (lease_owner, lease_token) else {
        return Err(invalid_record(
            "claimed settlement row has an incomplete lease",
        ));
    };
    validate_work_shape(&work_kind, attempts, reason_code, reason_detail_sha256)?;
    Ok(Some(ClaimedAttemptState {
        finalized_at,
        attempts,
        row_version,
        lease_owner,
        lease_token,
        lease_until_ms: validated_lease_until_ms,
    }))
}

fn verify_live_claim(
    tx: &rusqlite::Transaction<'_>,
    claim: &SettlementAttemptClaim,
    observed_at_ms: u64,
) -> Result<(), SettlementRouteError> {
    let Some(stored) = read_claimed_attempt(tx, &claim.receipt_id)? else {
        return Err(conflict("settlement attempt no longer exists"));
    };
    if stored.finalized_at != claim.finalized_at
        || stored.attempts != claim.attempts
        || stored.row_version != claim.row_version
        || stored.lease_owner != claim.lease_owner
        || stored.lease_token != claim.lease_token
        || stored.lease_until_ms != claim.lease_until_ms
    {
        return Err(conflict(
            "settlement claim does not match durable lease state",
        ));
    }
    if stored.lease_until_ms <= observed_at_ms {
        return Err(conflict("settlement claim lease has expired"));
    }
    Ok(())
}

fn expected_dead_letter(
    claim: &SettlementAttemptClaim,
    decision: &RetryDecision,
) -> Result<Option<(DeadLetterRecord, u32)>, SettlementRouteError> {
    let RetryDecision::DeadLetter { reason } = decision else {
        return Ok(None);
    };
    let attempts = claim
        .attempts
        .checked_add(1)
        .ok_or_else(|| invalid_record("settlement attempt count overflows u32"))?;
    Ok(Some((
        DeadLetterRecord::new(
            claim.receipt_id.clone(),
            claim.finalized_at,
            attempts,
            reason.clone(),
        ),
        attempts,
    )))
}

fn delete_claimed_attempt(
    tx: &rusqlite::Transaction<'_>,
    claim: &SettlementAttemptClaim,
    observed_at_i64: i64,
) -> Result<(), SettlementRouteError> {
    let affected = tx
        .execute(
            "DELETE FROM settle_attempts WHERE receipt_id = ?1 AND finalized_at = ?2 \
             AND attempts = ?3 AND row_version = ?4 AND lease_owner = ?5 \
             AND lease_token = ?6 AND lease_until_ms = ?7 AND lease_until_ms > ?8",
            params![
                claim.receipt_id.as_str(),
                sqlite_i64(claim.finalized_at, "finalized_at")?,
                i64::from(claim.attempts),
                sqlite_i64(claim.row_version, "row_version")?,
                claim.lease_owner.as_str(),
                claim.lease_token.as_str(),
                sqlite_i64(claim.lease_until_ms, "lease_until_ms")?,
                observed_at_i64,
            ],
        )
        .map_err(backend_error)?;
    if affected != 1 {
        return Err(conflict("settlement claim changed before delete"));
    }
    Ok(())
}

fn schedule_retry(
    tx: &rusqlite::Transaction<'_>,
    claim: &SettlementAttemptClaim,
    observed_at_ms: u64,
    observed_at_i64: i64,
    attempt: u32,
    backoff: std::time::Duration,
    reason: &chio_settle::SettlementFailureReason,
) -> Result<u64, SettlementRouteError> {
    let backoff_ms: u64 = backoff
        .as_millis()
        .try_into()
        .map_err(|_| invalid_record("settlement backoff exceeds u64"))?;
    let next_visible_at_ms = observed_at_ms
        .checked_add(backoff_ms)
        .ok_or_else(|| invalid_record("settlement visibility deadline overflows u64"))?;
    let next_visible_at_i64 = sqlite_i64(next_visible_at_ms, "next_visible_at_ms")?;
    let affected = tx
        .execute(
            "UPDATE settle_attempts SET work_kind = 'retry_scheduled', attempts = ?1, \
                next_visible_at_ms = ?2, lease_owner = NULL, lease_token = NULL, \
                lease_until_ms = NULL, reason_code = ?3, reason_detail_sha256 = ?4, \
                updated_at_ms = ?5 \
             WHERE receipt_id = ?6 AND finalized_at = ?7 AND attempts = ?8 \
               AND row_version = ?9 AND lease_owner = ?10 AND lease_token = ?11 \
               AND lease_until_ms = ?12 AND lease_until_ms > ?5",
            params![
                i64::from(attempt),
                next_visible_at_i64,
                reason.code().as_str(),
                reason.detail_sha256().as_slice(),
                observed_at_i64,
                claim.receipt_id.as_str(),
                sqlite_i64(claim.finalized_at, "finalized_at")?,
                i64::from(claim.attempts),
                sqlite_i64(claim.row_version, "row_version")?,
                claim.lease_owner.as_str(),
                claim.lease_token.as_str(),
                sqlite_i64(claim.lease_until_ms, "lease_until_ms")?,
            ],
        )
        .map_err(backend_error)?;
    if affected != 1 {
        return Err(conflict("settlement claim changed before retry scheduling"));
    }
    Ok(next_visible_at_ms)
}

impl SettlementOutcomeStore for SqliteSettlementOutcomeStore {
    fn settlement_store_binding(&self) -> SettlementStoreBinding {
        self.binding
    }

    fn claim_receipt(
        &self,
        receipt_id: &str,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> Result<Option<SettlementAttemptClaim>, SettlementRouteError> {
        let (now_i64, lease_until_i64) = validate_claim_input(worker_id, now_ms, lease_ms, 1)?;
        let lease_until_ms = now_ms
            .checked_add(lease_ms)
            .ok_or_else(|| invalid_record("settlement lease deadline overflows u64"))?;
        let receipt_id = receipt_id.to_string();
        let worker_id = worker_id.to_string();
        self.run_write(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_error)?;
            let claim = claim_one_tx(
                &tx,
                &receipt_id,
                &worker_id,
                now_ms,
                now_i64,
                lease_until_ms,
                lease_until_i64,
            )?;
            tx.commit().map_err(backend_error)?;
            Ok(claim)
        })
    }

    fn claim_due(
        &self,
        worker_id: &str,
        now_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<SettlementAttemptClaim>, SettlementRouteError> {
        let (now_i64, lease_until_i64) = validate_claim_input(worker_id, now_ms, lease_ms, limit)?;
        let lease_until_ms = now_ms
            .checked_add(lease_ms)
            .ok_or_else(|| invalid_record("settlement lease deadline overflows u64"))?;
        let sql_limit: i64 = limit
            .try_into()
            .map_err(|_| invalid_record("settlement claim limit exceeds SQLite range"))?;
        let worker_id = worker_id.to_string();
        self.run_write(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_error)?;
            let receipt_ids = {
                let mut statement = tx
                    .prepare(
                        "SELECT receipt_id FROM settle_attempts \
                         WHERE next_visible_at_ms <= ?1 \
                           AND (lease_until_ms IS NULL OR lease_until_ms <= ?1) \
                         ORDER BY next_visible_at_ms ASC, receipt_id ASC LIMIT ?2",
                    )
                    .map_err(backend_error)?;
                let rows = statement
                    .query_map(params![now_i64, sql_limit], |row| row.get::<_, String>(0))
                    .map_err(backend_error)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(attempt_row_error)?
            };
            let mut claims = Vec::with_capacity(receipt_ids.len());
            for receipt_id in receipt_ids {
                let claim = claim_one_tx(
                    &tx,
                    &receipt_id,
                    &worker_id,
                    now_ms,
                    now_i64,
                    lease_until_ms,
                    lease_until_i64,
                )?
                .ok_or_else(|| conflict("due settlement row changed before batch claim"))?;
                claims.push(claim);
            }
            tx.commit().map_err(backend_error)?;
            Ok(claims)
        })
    }

    fn record_claimed_outcome(
        &self,
        claim: &SettlementAttemptClaim,
        outcome: &SettlementRoutingInput,
        policy: RetryPolicy,
        observed_at_ms: u64,
    ) -> Result<SettlementRoute, SettlementRouteError> {
        policy
            .validate()
            .map_err(|error| invalid_record(error.to_string()))?;
        let observed_at_i64 = sqlite_i64(observed_at_ms, "observed_at_ms")?;
        let decision = classify_attempt(&policy, claim.attempts, outcome);
        let terminal = expected_dead_letter(claim, &decision)?;
        let claim = claim.clone();
        self.run_write(move |connection| {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(backend_error)?;

            if read_dead_letter_on_connection(&tx, &claim.receipt_id)
                .map_err(dead_letter_error_to_route)?
                .is_some()
            {
                let Some((record, attempts)) = terminal.as_ref() else {
                    return Err(conflict("terminal settlement state blocks this outcome"));
                };
                let inserted = insert_dead_letter_on_connection(&tx, record)
                    .map_err(dead_letter_error_to_route)?;
                if inserted {
                    return Err(backend_error(
                        "terminal settlement row disappeared during replay",
                    ));
                }
                tx.commit().map_err(backend_error)?;
                return Ok(SettlementRoute::DeadLettered {
                    attempts: *attempts,
                });
            }

            verify_live_claim(&tx, &claim, observed_at_ms)?;
            let route = match decision {
                RetryDecision::Accepted | RetryDecision::Skip { .. } => {
                    delete_claimed_attempt(&tx, &claim, observed_at_i64)?;
                    SettlementRoute::NoAction
                }
                RetryDecision::Retry {
                    attempt,
                    backoff,
                    reason,
                } => {
                    let next_visible_at_ms = schedule_retry(
                        &tx,
                        &claim,
                        observed_at_ms,
                        observed_at_i64,
                        attempt,
                        backoff,
                        &reason,
                    )?;
                    SettlementRoute::RetryScheduled {
                        attempt,
                        next_visible_at_ms,
                    }
                }
                RetryDecision::DeadLetter { .. } => {
                    let Some((record, attempts)) = terminal.as_ref() else {
                        return Err(invalid_record(
                            "dead-letter decision lacks a terminal record",
                        ));
                    };
                    delete_claimed_attempt(&tx, &claim, observed_at_i64)?;
                    let inserted = insert_dead_letter_on_connection(&tx, record)
                        .map_err(dead_letter_error_to_route)?;
                    if !inserted {
                        return Err(conflict(
                            "terminal settlement row appeared during claimed transition",
                        ));
                    }
                    SettlementRoute::DeadLettered {
                        attempts: *attempts,
                    }
                }
            };
            tx.commit().map_err(backend_error)?;
            Ok(route)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use chio_kernel::ReceiptStore;
    use chio_settle::{
        RetryPolicy, SettlementFailureCode, SettlementFailureReason, SettlementOutcomeStore,
        SettlementRoute, SettlementRouteError, SettlementRoutingInput, SettlementSkipReason,
    };
    use chio_test_support::prelude::*;
    use r2d2::Pool;
    use r2d2_sqlite::SqliteConnectionManager;

    use super::*;
    use crate::dead_letters::{DeadLetterStoreError, SqliteDeadLetterStore};

    fn pool() -> Pool<SqliteConnectionManager> {
        Pool::builder()
            .max_size(1)
            .build(SqliteConnectionManager::memory())
            .test_expect("test pool builds")
    }

    fn file_pool(path: &std::path::Path) -> Pool<SqliteConnectionManager> {
        let manager = SqliteConnectionManager::file(path).with_init(|connection| {
            connection.busy_timeout(Duration::from_secs(5))?;
            connection.pragma_update(None, "journal_mode", "WAL")?;
            Ok(())
        });
        Pool::builder()
            .max_size(1)
            .build(manager)
            .test_expect("file-backed test pool builds")
    }

    fn seed(pool: &Pool<SqliteConnectionManager>, receipt_id: &str, visible_at_ms: u64) {
        let mut connection = pool.get().test_expect("test connection");
        let tx = connection.transaction().test_expect("test transaction");
        insert_attempt_zero_tx(&tx, receipt_id, 10, visible_at_ms)
            .test_expect("attempt zero inserts");
        tx.commit().test_expect("attempt zero commits");
    }

    fn rpc_failure(detail: &str) -> SettlementFailureReason {
        SettlementFailureReason::from_detail(SettlementFailureCode::Rpc, detail)
    }

    fn dead_letter(receipt_id: &str) -> DeadLetterRecord {
        DeadLetterRecord::new(
            receipt_id,
            10,
            1,
            SettlementFailureReason::from_detail(
                SettlementFailureCode::InvalidBinding,
                "binding mismatch",
            ),
        )
    }

    fn seed_overlap(pool: &Pool<SqliteConnectionManager>, attempt_id: &str, terminal_id: &str) {
        seed(pool, attempt_id, 0);
        let dead_letters =
            SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("dead letters open");
        assert!(dead_letters
            .insert(&dead_letter(terminal_id))
            .test_expect("dead letter inserts"));

        let connection = pool.get().test_expect("test connection");
        connection
            .execute_batch("DROP TRIGGER IF EXISTS trg_settle_attempts_reject_terminal_update;")
            .test_expect("update guard drops");
        connection
            .execute(
                "UPDATE settle_attempts SET receipt_id = ?1 WHERE receipt_id = ?2",
                params![terminal_id, attempt_id],
            )
            .test_expect("corrupt overlap seeds");
        connection
            .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
            .test_expect("attempt migration reinstalls");
    }

    fn assert_attempt_unleased(pool: &Pool<SqliteConnectionManager>, receipt_id: &str) {
        let state: (i64, Option<String>, Option<String>, Option<i64>) = pool
            .get()
            .test_expect("test connection")
            .query_row(
                "SELECT row_version, lease_owner, lease_token, lease_until_ms \
                 FROM settle_attempts WHERE receipt_id = ?1",
                [receipt_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .test_expect("attempt state reads");
        assert_eq!(state, (0, None, None, None));
    }

    fn claim(
        store: &SqliteSettlementOutcomeStore,
        receipt_id: &str,
        now_ms: u64,
        lease_ms: u64,
    ) -> chio_settle::SettlementAttemptClaim {
        store
            .claim_receipt(receipt_id, "worker", now_ms, lease_ms)
            .test_expect("claim succeeds")
            .test_expect("claim is present")
    }

    fn attempt_count(pool: &Pool<SqliteConnectionManager>, receipt_id: &str) -> i64 {
        pool.get()
            .test_expect("test connection")
            .query_row(
                "SELECT COUNT(*) FROM settle_attempts WHERE receipt_id = ?1",
                [receipt_id],
                |row| row.get(0),
            )
            .test_expect("attempt count reads")
    }

    fn dead_letter_count(pool: &Pool<SqliteConnectionManager>, receipt_id: &str) -> i64 {
        pool.get()
            .test_expect("test connection")
            .query_row(
                "SELECT COUNT(*) FROM settle_dead_letters WHERE receipt_id = ?1",
                [receipt_id],
                |row| row.get(0),
            )
            .test_expect("dead letter count reads")
    }

    #[test]
    fn settlement_migration_is_idempotent() {
        let pool = pool();
        SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("first open");
        SqliteSettlementOutcomeStore::open_with_pool(pool).test_expect("second open");
    }

    #[test]
    fn attempt_zero_requires_one_inserted_row() {
        let pool = pool();
        let mut connection = pool.get().test_expect("test connection");
        connection
            .execute_batch(SETTLE_DEAD_LETTERS_MIGRATION)
            .test_expect("dead-letter schema installs");
        connection
            .execute_batch(SETTLE_ATTEMPTS_MIGRATION)
            .test_expect("attempt schema installs");
        connection
            .execute_batch(
                "CREATE TRIGGER swallow_settlement_attempt \
                 BEFORE INSERT ON settle_attempts BEGIN SELECT RAISE(IGNORE); END;",
            )
            .test_expect("no-op settlement trigger installs");
        let tx = connection.transaction().test_expect("test transaction");

        assert!(matches!(
            insert_attempt_zero_tx(&tx, "receipt-1", 1, 1),
            Err(ReceiptStoreError::Conflict(_))
        ));
    }

    #[test]
    fn alongside_store_copies_the_receipt_writer_binding() {
        let directory = tempfile::tempdir().test_expect("temporary directory");
        let receipts = crate::SqliteReceiptStore::open(directory.path().join("receipts.db"))
            .test_expect("receipt store opens");
        let alongside =
            SqliteSettlementOutcomeStore::open_alongside(&receipts).test_expect("alongside opens");
        let standalone = SqliteSettlementOutcomeStore::open_with_pool(receipts.pool.clone())
            .test_expect("standalone opens");
        let receipt_binding = ReceiptStore::settlement_store_binding(&receipts)
            .test_expect("receipt binding is available");

        assert_eq!(alongside.settlement_store_binding(), receipt_binding);
        assert_ne!(standalone.settlement_store_binding(), receipt_binding);
    }

    #[test]
    fn writer_error_transport_preserves_only_tagged_route_classes() {
        let cases = [
            backend_error("backend"),
            conflict("conflict"),
            invalid_record("invalid"),
        ];
        for error in cases {
            let class = error.class();
            assert_eq!(
                receipt_error_to_route(route_error_to_receipt(error)).class(),
                class
            );
        }
        assert!(matches!(
            receipt_error_to_route(ReceiptStoreError::Conflict("writer conflict".to_string())),
            SettlementRouteError::Backend { .. }
        ));
    }

    #[test]
    fn settlement_tables_reject_attempt_dead_letter_overlap() {
        let pool = pool();
        SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let dead_letters =
            SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("dead letters open");
        let record = dead_letter("receipt-1");

        assert!(matches!(
            dead_letters.insert(&record),
            Err(DeadLetterStoreError::Conflict(_))
        ));
        pool.get()
            .test_expect("test connection")
            .execute(
                "DELETE FROM settle_attempts WHERE receipt_id = ?1",
                ["receipt-1"],
            )
            .test_expect("attempt deletes");
        assert!(dead_letters
            .insert(&record)
            .test_expect("dead letter inserts"));

        let mut connection = pool.get().test_expect("test connection");
        let tx = connection.transaction().test_expect("test transaction");
        assert!(matches!(
            insert_attempt_zero_tx(&tx, "receipt-1", 10, 0),
            Err(ReceiptStoreError::Conflict(_))
        ));
    }

    #[test]
    fn settlement_tables_reject_receipt_id_updates_that_create_overlap() {
        let pool = pool();
        SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "attempt-1", 0);
        seed(&pool, "attempt-2", 0);
        let dead_letters =
            SqliteDeadLetterStore::open_with_pool(pool.clone()).test_expect("dead letters open");
        assert!(dead_letters
            .insert(&dead_letter("terminal-1"))
            .test_expect("first dead letter inserts"));
        assert!(dead_letters
            .insert(&dead_letter("terminal-2"))
            .test_expect("second dead letter inserts"));
        let connection = pool.get().test_expect("test connection");

        let attempt_error = connection
            .execute(
                "UPDATE settle_attempts SET receipt_id = 'terminal-1' \
                 WHERE receipt_id = 'attempt-1'",
                [],
            )
            .test_expect_err("attempt overlap update rejects");
        assert_eq!(
            attempt_error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        );

        let terminal_error = connection
            .execute(
                "UPDATE settle_dead_letters SET receipt_id = 'attempt-2' \
                 WHERE receipt_id = 'terminal-2'",
                [],
            )
            .test_expect_err("terminal overlap update rejects");
        assert_eq!(
            terminal_error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::ConstraintViolation)
        );
    }

    #[test]
    fn claim_receipt_rejects_preexisting_attempt_dead_letter_overlap() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed_overlap(&pool, "attempt-1", "terminal-1");

        assert!(matches!(
            store.claim_receipt("terminal-1", "worker", 0, 100),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        assert_attempt_unleased(&pool, "terminal-1");
    }

    #[test]
    fn claim_due_rejects_preexisting_attempt_dead_letter_overlap() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "a-valid", 0);
        seed_overlap(&pool, "attempt-1", "z-terminal");

        assert!(matches!(
            store.claim_due("worker", 0, 100, 2),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        assert_attempt_unleased(&pool, "a-valid");
        assert_attempt_unleased(&pool, "z-terminal");
    }

    #[test]
    fn claim_receipt_increments_version_and_uses_fresh_token() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 5);

        let first = store
            .claim_receipt("receipt-1", "worker-1", 5, 100)
            .test_expect("first claim")
            .test_expect("claim present");
        assert_eq!(first.receipt_id, "receipt-1");
        assert_eq!(first.finalized_at, 10);
        assert_eq!(first.attempts, 0);
        assert_eq!(first.row_version, 1);
        assert_eq!(first.lease_owner, "worker-1");
        assert_eq!(first.lease_until_ms, 105);

        assert!(store
            .claim_receipt("receipt-1", "worker-2", 104, 100)
            .test_expect("live lease check")
            .is_none());
        let second = store
            .claim_receipt("receipt-1", "worker-2", 105, 100)
            .test_expect("expired lease claim")
            .test_expect("expired row claimed");
        assert_eq!(second.row_version, 2);
        assert_eq!(second.lease_owner, "worker-2");
        assert_ne!(second.lease_token, first.lease_token);
    }

    #[test]
    fn claim_due_orders_and_limits_due_rows() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-b", 5);
        seed(&pool, "receipt-a", 5);
        seed(&pool, "receipt-c", 6);

        let claims = store
            .claim_due("worker", 6, 100, 2)
            .test_expect("due claim");
        assert_eq!(
            claims
                .iter()
                .map(|claim| claim.receipt_id.as_str())
                .collect::<Vec<_>>(),
            vec!["receipt-a", "receipt-b"]
        );
    }

    #[test]
    fn invalid_claim_bounds_do_not_mutate_work() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);

        for result in [
            store.claim_receipt("receipt-1", "", 0, 1).map(|_| ()),
            store.claim_receipt("receipt-1", "worker", 0, 0).map(|_| ()),
            store.claim_due("worker", 0, 1, 0).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(SettlementRouteError::InvalidRecord { .. })
            ));
        }

        let claim = store
            .claim_receipt("receipt-1", "worker", 0, 1)
            .test_expect("valid claim")
            .test_expect("row remains claimable");
        assert_eq!(claim.row_version, 1);
    }

    #[test]
    fn row_version_overflow_is_invalid_without_mutation() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        pool.get()
            .test_expect("test connection")
            .execute(
                "UPDATE settle_attempts SET row_version = ?1 WHERE receipt_id = ?2",
                rusqlite::params![i64::MAX, "receipt-1"],
            )
            .test_expect("seed row version overflow");

        assert!(matches!(
            store.claim_receipt("receipt-1", "worker", 0, 1),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        let version: i64 = pool
            .get()
            .test_expect("test connection")
            .query_row(
                "SELECT row_version FROM settle_attempts WHERE receipt_id = ?1",
                ["receipt-1"],
                |row| row.get(0),
            )
            .test_expect("row version reads");
        assert_eq!(version, i64::MAX);
    }

    #[test]
    fn unknown_persisted_reason_fails_before_claim_mutation() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        pool.get()
            .test_expect("test connection")
            .execute(
                "UPDATE settle_attempts SET work_kind = 'retry_scheduled', attempts = 1, \
                    reason_code = 'unknown_code', reason_detail_sha256 = zeroblob(32) \
                 WHERE receipt_id = ?1",
                ["receipt-1"],
            )
            .test_expect("corrupt retry reason");

        assert!(matches!(
            store.claim_receipt("receipt-1", "worker", 0, 1),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        let state = pool
            .get()
            .test_expect("test connection")
            .query_row(
                "SELECT row_version, lease_owner FROM settle_attempts WHERE receipt_id = ?1",
                ["receipt-1"],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .test_expect("corrupt row remains");
        assert_eq!(state, (0, None));
    }

    #[test]
    fn malformed_persisted_numeric_type_is_invalid_record() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        pool.get()
            .test_expect("test connection")
            .execute(
                "UPDATE settle_attempts SET work_kind = 'retry_scheduled', attempts = 1.5, \
                    reason_code = 'rpc', reason_detail_sha256 = zeroblob(32) \
                 WHERE receipt_id = ?1",
                ["receipt-1"],
            )
            .test_expect("malformed numeric value persists");

        assert!(matches!(
            store.claim_receipt("receipt-1", "worker", 0, 1),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn retries_preserve_reason_and_millisecond_backoff() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let reason = rpc_failure("temporary outage");
        let first_claim = claim(&store, "receipt-1", 0, 1_000);

        assert_eq!(
            store
                .record_claimed_outcome(
                    &first_claim,
                    &SettlementRoutingInput::Retryable {
                        reason: reason.clone(),
                    },
                    RetryPolicy::default(),
                    100,
                )
                .test_expect("first retry records"),
            SettlementRoute::RetryScheduled {
                attempt: 1,
                next_visible_at_ms: 350,
            }
        );
        let row = pool
            .get()
            .test_expect("test connection")
            .query_row(
                "SELECT attempts, next_visible_at_ms, reason_code, reason_detail_sha256, \
                        lease_owner, lease_token, lease_until_ms \
                 FROM settle_attempts WHERE receipt_id = ?1",
                ["receipt-1"],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<i64>>(6)?,
                    ))
                },
            )
            .test_expect("retry row reads");
        assert_eq!(row.0, 1);
        assert_eq!(row.1, 350);
        assert_eq!(row.2, "rpc");
        assert_eq!(row.3.as_slice(), reason.detail_sha256());
        assert_eq!((row.4, row.5, row.6), (None, None, None));

        let second_claim = claim(&store, "receipt-1", 350, 1_000);
        assert_eq!(
            store
                .record_claimed_outcome(
                    &second_claim,
                    &SettlementRoutingInput::Retryable { reason },
                    RetryPolicy::default(),
                    400,
                )
                .test_expect("second retry records"),
            SettlementRoute::RetryScheduled {
                attempt: 2,
                next_visible_at_ms: 900,
            }
        );
    }

    #[test]
    fn permanent_outcome_atomically_replaces_attempt_with_dead_letter() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let claim = claim(&store, "receipt-1", 0, 100);

        assert_eq!(
            store
                .record_claimed_outcome(
                    &claim,
                    &SettlementRoutingInput::Permanent {
                        reason: SettlementFailureReason::from_detail(
                            SettlementFailureCode::InvalidBinding,
                            "binding mismatch",
                        ),
                    },
                    RetryPolicy::default(),
                    1,
                )
                .test_expect("permanent outcome records"),
            SettlementRoute::DeadLettered { attempts: 1 }
        );
        assert_eq!(attempt_count(&pool, "receipt-1"), 0);
        assert_eq!(dead_letter_count(&pool, "receipt-1"), 1);
    }

    #[test]
    fn accepted_and_skipped_remove_only_live_claimed_work() {
        for outcome in [
            SettlementRoutingInput::Accepted,
            SettlementRoutingInput::Skipped {
                reason: SettlementSkipReason::ZeroCharge,
            },
        ] {
            let pool = pool();
            let store = SqliteSettlementOutcomeStore::open_with_pool(pool.clone())
                .test_expect("store opens");
            seed(&pool, "receipt-1", 0);
            let claim = claim(&store, "receipt-1", 0, 100);

            assert_eq!(
                store
                    .record_claimed_outcome(&claim, &outcome, RetryPolicy::default(), 1)
                    .test_expect("terminal cleanup records"),
                SettlementRoute::NoAction
            );
            assert_eq!(attempt_count(&pool, "receipt-1"), 0);
            assert_eq!(dead_letter_count(&pool, "receipt-1"), 0);
        }
    }

    #[test]
    fn retry_exhaustion_is_terminal_and_exact_replay_is_idempotent() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let reason = rpc_failure("still unavailable");
        let outcome = SettlementRoutingInput::Retryable {
            reason: reason.clone(),
        };
        let policy = RetryPolicy {
            max_retries: 0,
            ..RetryPolicy::default()
        };
        let claim = claim(&store, "receipt-1", 0, 100);

        assert_eq!(
            store
                .record_claimed_outcome(&claim, &outcome, policy, 1)
                .test_expect("exhaustion records"),
            SettlementRoute::DeadLettered { attempts: 1 }
        );
        assert_eq!(
            store
                .record_claimed_outcome(&claim, &outcome, policy, 1)
                .test_expect("exact replay is idempotent"),
            SettlementRoute::DeadLettered { attempts: 1 }
        );
        assert!(matches!(
            store.record_claimed_outcome(
                &claim,
                &SettlementRoutingInput::Retryable {
                    reason: rpc_failure("different failure"),
                },
                policy,
                1,
            ),
            Err(SettlementRouteError::Conflict { .. })
        ));
        assert!(matches!(
            store.record_claimed_outcome(&claim, &SettlementRoutingInput::Accepted, policy, 1,),
            Err(SettlementRouteError::Conflict { .. })
        ));
        assert_eq!(attempt_count(&pool, "receipt-1"), 0);
        assert_eq!(dead_letter_count(&pool, "receipt-1"), 1);
    }

    #[test]
    fn stale_or_expired_claim_cannot_commit() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let stale = claim(&store, "receipt-1", 0, 10);
        let current = claim(&store, "receipt-1", 10, 10);

        assert!(matches!(
            store.record_claimed_outcome(
                &stale,
                &SettlementRoutingInput::Accepted,
                RetryPolicy::default(),
                10,
            ),
            Err(SettlementRouteError::Conflict { .. })
        ));
        assert!(matches!(
            store.record_claimed_outcome(
                &current,
                &SettlementRoutingInput::Accepted,
                RetryPolicy::default(),
                current.lease_until_ms,
            ),
            Err(SettlementRouteError::Conflict { .. })
        ));
        assert_eq!(attempt_count(&pool, "receipt-1"), 1);
    }

    #[test]
    fn invalid_policy_and_visibility_overflow_preserve_claimed_state() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let now_ms = (i64::MAX as u64) - 600;
        let claim = claim(&store, "receipt-1", now_ms, 600);
        let invalid_policy = RetryPolicy {
            initial_backoff_ms: 0,
            ..RetryPolicy::default()
        };
        let outcome = SettlementRoutingInput::Retryable {
            reason: rpc_failure("temporary"),
        };

        assert!(matches!(
            store.record_claimed_outcome(&claim, &outcome, invalid_policy, now_ms + 1),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        assert!(matches!(
            store.record_claimed_outcome(
                &claim,
                &outcome,
                RetryPolicy {
                    initial_backoff_ms: 1_000,
                    backoff_cap_ms: 1_000,
                    ..RetryPolicy::default()
                },
                now_ms + 100,
            ),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        assert_eq!(attempt_count(&pool, "receipt-1"), 1);
        assert_eq!(dead_letter_count(&pool, "receipt-1"), 0);
    }

    #[test]
    fn attempt_count_overflow_is_invalid_without_mutation() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        pool.get()
            .test_expect("test connection")
            .execute(
                "UPDATE settle_attempts SET work_kind = 'retry_scheduled', attempts = ?1, \
                    reason_code = 'rpc', reason_detail_sha256 = zeroblob(32) \
                 WHERE receipt_id = ?2",
                rusqlite::params![i64::from(u32::MAX), "receipt-1"],
            )
            .test_expect("maximum attempt count persists");
        let claim = claim(&store, "receipt-1", 0, 100);

        assert!(matches!(
            store.record_claimed_outcome(
                &claim,
                &SettlementRoutingInput::Permanent {
                    reason: SettlementFailureReason::from_detail(
                        SettlementFailureCode::InvalidBinding,
                        "binding mismatch",
                    ),
                },
                RetryPolicy::default(),
                1,
            ),
            Err(SettlementRouteError::InvalidRecord { .. })
        ));
        let durable = pool
            .get()
            .test_expect("test connection")
            .query_row(
                "SELECT attempts, row_version, lease_token FROM settle_attempts \
                 WHERE receipt_id = ?1",
                ["receipt-1"],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .test_expect("claimed row remains");
        assert_eq!(durable, (i64::from(u32::MAX), 1, claim.lease_token));
        assert_eq!(dead_letter_count(&pool, "receipt-1"), 0);
    }

    #[test]
    fn dead_letter_insert_failure_rolls_back_attempt_delete() {
        let pool = pool();
        let store =
            SqliteSettlementOutcomeStore::open_with_pool(pool.clone()).test_expect("store opens");
        seed(&pool, "receipt-1", 0);
        let claim = claim(&store, "receipt-1", 0, 100);
        pool.get()
            .test_expect("test connection")
            .execute_batch(
                "CREATE TRIGGER reject_settlement_dead_letter \
                 BEFORE INSERT ON settle_dead_letters BEGIN \
                     SELECT RAISE(ABORT, 'forced dead-letter failure'); \
                 END;",
            )
            .test_expect("rejecting trigger installs");

        assert!(matches!(
            store.record_claimed_outcome(
                &claim,
                &SettlementRoutingInput::Permanent {
                    reason: SettlementFailureReason::from_detail(
                        SettlementFailureCode::InvalidBinding,
                        "binding mismatch",
                    ),
                },
                RetryPolicy::default(),
                1,
            ),
            Err(SettlementRouteError::Conflict { .. })
        ));
        let durable = pool
            .get()
            .test_expect("test connection")
            .query_row(
                "SELECT row_version, lease_owner, lease_token, lease_until_ms \
                 FROM settle_attempts WHERE receipt_id = ?1",
                ["receipt-1"],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .test_expect("claimed row survives rollback");
        assert_eq!(
            durable,
            (
                i64::try_from(claim.row_version).test_expect("row version fits"),
                claim.lease_owner,
                claim.lease_token,
                i64::try_from(claim.lease_until_ms).test_expect("lease deadline fits"),
            )
        );
        assert_eq!(dead_letter_count(&pool, "receipt-1"), 0);
    }

    #[test]
    fn concurrent_terminal_transitions_commit_exactly_one_record() {
        let database = tempfile::NamedTempFile::new().test_expect("temporary database");
        let pool_one = file_pool(database.path());
        let pool_two = file_pool(database.path());
        let store_one = Arc::new(
            SqliteSettlementOutcomeStore::open_with_pool(pool_one.clone())
                .test_expect("first store opens"),
        );
        let store_two = Arc::new(
            SqliteSettlementOutcomeStore::open_with_pool(pool_two)
                .test_expect("second store opens"),
        );
        seed(&pool_one, "receipt-1", 0);
        let claim = claim(&store_one, "receipt-1", 0, 1_000);
        let barrier = Arc::new(Barrier::new(2));

        let mut handles = Vec::new();
        for (store, detail) in [
            (Arc::clone(&store_one), "failure-a"),
            (Arc::clone(&store_two), "failure-b"),
        ] {
            let claim = claim.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.record_claimed_outcome(
                    &claim,
                    &SettlementRoutingInput::Permanent {
                        reason: SettlementFailureReason::from_detail(
                            SettlementFailureCode::InvalidBinding,
                            detail,
                        ),
                    },
                    RetryPolicy::default(),
                    1,
                )
            }));
        }
        let results = handles
            .into_iter()
            .map(|handle| handle.join().test_expect("transition thread joins"))
            .collect::<Vec<_>>();

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(SettlementRouteError::Conflict { .. })))
                .count(),
            1
        );
        assert_eq!(attempt_count(&pool_one, "receipt-1"), 0);
        assert_eq!(dead_letter_count(&pool_one, "receipt-1"), 1);
    }
}
