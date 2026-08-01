//! Durable issuance, shared quota, and receipt lineage for no-charge finding
//! recovery.

use std::sync::{Arc, Mutex, MutexGuard};

use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use thiserror::Error;

use crate::admission_operation_store::verify_active_owner;
use crate::serving_owner::SqliteServingOwner;

const SCHEMA_KEY: &str = "finding_recovery";
const SUPPORTED_SCHEMA_VERSION: i32 = 1;
const SCHEMA_ANCHORS: &[&str] = &["finding_recovery_issuances", "purchase_records"];
const SCHEMA: &str = include_str!("finding_recovery_store.sql");
const MAX_IDENTIFIER_BYTES: usize = 512;

#[derive(Debug, Error)]
pub enum FindingRecoveryStoreError {
    #[error("finding recovery store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding recovery store fence rejected the caller")]
    Fenced,
    #[error("finding recovery issuance not found")]
    NotFound,
    #[error("finding recovery quota exhausted")]
    QuotaExhausted,
    #[error("finding recovery conflict: {0}")]
    Conflict(String),
    #[error("finding recovery invariant violated: {0}")]
    Invariant(String),
    #[error("finding recovery commit outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingRecoveryWriteOutcome {
    Inserted,
    ExistingSame,
}

#[derive(Debug, Clone, Copy)]
pub struct FindingRecoveryIssuanceInput<'a> {
    pub recovery_id: &'a str,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub original_capability_id: &'a str,
    pub original_delivery_receipt_id: &'a str,
    pub purchase_key: &'a str,
    pub original_subject_key_hex: &'a str,
    pub max_recoveries: u32,
    pub issued_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRecoveryIssuanceRecord {
    pub recovery_id: String,
    pub finding_id: String,
    pub listing_id: String,
    pub original_capability_id: String,
    pub original_delivery_receipt_id: String,
    pub purchase_key: String,
    pub original_subject_key_hex: String,
    pub max_recoveries: u32,
    pub issued_at: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct FindingRecoveryReceiptLineageInput<'a> {
    pub recovery_receipt_id: &'a str,
    pub recovery_id: &'a str,
    pub original_delivery_receipt_id: &'a str,
    pub purchase_key: &'a str,
    pub recorded_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingRecoveryReceiptLineageRecord {
    pub recovery_receipt_id: String,
    pub recovery_id: String,
    pub original_delivery_receipt_id: String,
    pub purchase_key: String,
    pub recorded_at: u64,
}

#[derive(Clone)]
pub struct SqliteFindingRecoveryStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFindingRecoveryStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FindingRecoveryStoreError> {
        self.connection.lock().map_err(|_| {
            FindingRecoveryStoreError::Unavailable("sqlite finding recovery lock poisoned".into())
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingRecoveryStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingRecoveryStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingRecoveryStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingRecoveryStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn commit(&self, transaction: Transaction<'_>) -> Result<(), FindingRecoveryStoreError> {
        transaction.commit().map_err(|error| {
            FindingRecoveryStoreError::OutcomeUnknown(
                self.serving_owner
                    .outcome_unknown(format!(
                        "sqlite finding recovery commit outcome is unknown: {error}"
                    ))
                    .to_string(),
            )
        })
    }

    fn sync(&self, connection: &Connection) -> Result<(), FindingRecoveryStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| FindingRecoveryStoreError::Unavailable(error.to_string()))
    }

    pub fn issue(
        &self,
        input: &FindingRecoveryIssuanceInput<'_>,
    ) -> Result<FindingRecoveryWriteOutcome, FindingRecoveryStoreError> {
        validate_issuance(input)?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_issuance_tx(&transaction, input.recovery_id)? {
            if issuance_matches(&existing, input) {
                return Ok(FindingRecoveryWriteOutcome::ExistingSame);
            }
            return Err(FindingRecoveryStoreError::Conflict(
                "recovery id is already issued under different bindings".into(),
            ));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO finding_recovery_issuances (
                    recovery_id, finding_id, listing_id, original_capability_id,
                    original_delivery_receipt_id, purchase_key,
                    original_subject_key_hex, max_recoveries, issued_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    input.recovery_id,
                    input.finding_id,
                    input.listing_id,
                    input.original_capability_id,
                    input.original_delivery_receipt_id,
                    input.purchase_key,
                    input.original_subject_key_hex,
                    i64::from(input.max_recoveries),
                    sqlite_i64(input.issued_at, "issued_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("recovery issuance insert did not affect one row"));
        }
        self.commit(transaction)?;
        self.sync(&connection)?;
        Ok(FindingRecoveryWriteOutcome::Inserted)
    }

    /// Reserve one shared attempt under an Immediate transaction. Identical
    /// request replay returns its original ordinal without consuming again.
    pub fn reserve_attempt(
        &self,
        recovery_id: &str,
        request_id: &str,
        expected_max_recoveries: u32,
        reserved_at: u64,
    ) -> Result<u32, FindingRecoveryStoreError> {
        require_hex64(recovery_id, "recovery_id")?;
        require_identifier(request_id, "request_id")?;
        require_time(reserved_at, "reserved_at")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let issuance = load_issuance_tx(&transaction, recovery_id)?
            .ok_or(FindingRecoveryStoreError::NotFound)?;
        if issuance.max_recoveries != expected_max_recoveries {
            return Err(FindingRecoveryStoreError::Conflict(
                "recovery grant changed the durable retry ceiling".into(),
            ));
        }
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT attempt_ordinal FROM finding_recovery_attempts WHERE recovery_id = ?1 AND request_id = ?2",
                params![recovery_id, request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(ordinal) = existing {
            return stored_u32(ordinal, "attempt_ordinal");
        }
        let count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM finding_recovery_attempts WHERE recovery_id = ?1",
                [recovery_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        let ordinal = stored_u32(count, "attempt count")?
            .checked_add(1)
            .ok_or_else(|| invariant("recovery attempt ordinal overflowed"))?;
        if ordinal > issuance.max_recoveries {
            return Err(FindingRecoveryStoreError::QuotaExhausted);
        }
        transaction
            .execute(
                "INSERT INTO finding_recovery_attempts (recovery_id, request_id, attempt_ordinal, reserved_at) VALUES (?1, ?2, ?3, ?4)",
                params![recovery_id, request_id, i64::from(ordinal), sqlite_i64(reserved_at, "reserved_at")?],
            )
            .map_err(sqlite_error)?;
        self.commit(transaction)?;
        self.sync(&connection)?;
        Ok(ordinal)
    }

    pub fn record_receipt_lineage(
        &self,
        input: &FindingRecoveryReceiptLineageInput<'_>,
    ) -> Result<FindingRecoveryWriteOutcome, FindingRecoveryStoreError> {
        require_identifier(input.recovery_receipt_id, "recovery_receipt_id")?;
        require_hex64(input.recovery_id, "recovery_id")?;
        require_identifier(
            input.original_delivery_receipt_id,
            "original_delivery_receipt_id",
        )?;
        require_hex64(input.purchase_key, "purchase_key")?;
        require_time(input.recorded_at, "recorded_at")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let issuance = load_issuance_tx(&transaction, input.recovery_id)?
            .ok_or(FindingRecoveryStoreError::NotFound)?;
        if issuance.original_delivery_receipt_id != input.original_delivery_receipt_id
            || issuance.purchase_key != input.purchase_key
        {
            return Err(FindingRecoveryStoreError::Conflict(
                "receipt lineage does not match the durable issuance".into(),
            ));
        }
        if let Some(existing) = load_lineage_tx(&transaction, input.recovery_receipt_id)? {
            if existing.recovery_id == input.recovery_id
                && existing.original_delivery_receipt_id == input.original_delivery_receipt_id
                && existing.purchase_key == input.purchase_key
            {
                return Ok(FindingRecoveryWriteOutcome::ExistingSame);
            }
            return Err(FindingRecoveryStoreError::Conflict(
                "recovery receipt is already bound to different lineage".into(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO finding_recovery_receipt_lineage (recovery_receipt_id, recovery_id, original_delivery_receipt_id, purchase_key, recorded_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![input.recovery_receipt_id, input.recovery_id, input.original_delivery_receipt_id, input.purchase_key, sqlite_i64(input.recorded_at, "recorded_at")?],
            )
            .map_err(sqlite_error)?;
        self.commit(transaction)?;
        self.sync(&connection)?;
        Ok(FindingRecoveryWriteOutcome::Inserted)
    }

    pub fn get_issuance(
        &self,
        recovery_id: &str,
    ) -> Result<Option<FindingRecoveryIssuanceRecord>, FindingRecoveryStoreError> {
        require_hex64(recovery_id, "recovery_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_issuance_tx(&transaction, recovery_id)
    }

    pub fn get_receipt_lineage(
        &self,
        receipt_id: &str,
    ) -> Result<Option<FindingRecoveryReceiptLineageRecord>, FindingRecoveryStoreError> {
        require_identifier(receipt_id, "recovery_receipt_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_lineage_tx(&transaction, receipt_id)
    }
}

fn load_issuance_tx(
    transaction: &Transaction<'_>,
    recovery_id: &str,
) -> Result<Option<FindingRecoveryIssuanceRecord>, FindingRecoveryStoreError> {
    transaction
        .query_row(
            r#"
            SELECT recovery_id, finding_id, listing_id, original_capability_id,
                   original_delivery_receipt_id, purchase_key,
                   original_subject_key_hex, max_recoveries, issued_at
            FROM finding_recovery_issuances WHERE recovery_id = ?1
            "#,
            [recovery_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|row| {
            Ok(FindingRecoveryIssuanceRecord {
                recovery_id: row.0,
                finding_id: row.1,
                listing_id: row.2,
                original_capability_id: row.3,
                original_delivery_receipt_id: row.4,
                purchase_key: row.5,
                original_subject_key_hex: row.6,
                max_recoveries: stored_u32(row.7, "max_recoveries")?,
                issued_at: stored_u64(row.8, "issued_at")?,
            })
        })
        .transpose()
}

fn load_lineage_tx(
    transaction: &Transaction<'_>,
    receipt_id: &str,
) -> Result<Option<FindingRecoveryReceiptLineageRecord>, FindingRecoveryStoreError> {
    transaction
        .query_row(
            "SELECT recovery_receipt_id, recovery_id, original_delivery_receipt_id, purchase_key, recorded_at FROM finding_recovery_receipt_lineage WHERE recovery_receipt_id = ?1",
            [receipt_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, i64>(4)?)),
        )
        .optional()
        .map_err(sqlite_error)?
        .map(|row| Ok(FindingRecoveryReceiptLineageRecord { recovery_receipt_id: row.0, recovery_id: row.1, original_delivery_receipt_id: row.2, purchase_key: row.3, recorded_at: stored_u64(row.4, "recorded_at")? }))
        .transpose()
}

fn issuance_matches(
    existing: &FindingRecoveryIssuanceRecord,
    input: &FindingRecoveryIssuanceInput<'_>,
) -> bool {
    existing.recovery_id == input.recovery_id
        && existing.finding_id == input.finding_id
        && existing.listing_id == input.listing_id
        && existing.original_capability_id == input.original_capability_id
        && existing.original_delivery_receipt_id == input.original_delivery_receipt_id
        && existing.purchase_key == input.purchase_key
        && existing.original_subject_key_hex == input.original_subject_key_hex
        && existing.max_recoveries == input.max_recoveries
}

fn validate_issuance(
    input: &FindingRecoveryIssuanceInput<'_>,
) -> Result<(), FindingRecoveryStoreError> {
    require_hex64(input.recovery_id, "recovery_id")?;
    require_hex64(input.finding_id, "finding_id")?;
    require_identifier(input.listing_id, "listing_id")?;
    require_identifier(input.original_capability_id, "original_capability_id")?;
    require_identifier(
        input.original_delivery_receipt_id,
        "original_delivery_receipt_id",
    )?;
    require_hex64(input.purchase_key, "purchase_key")?;
    require_hex64(input.original_subject_key_hex, "original_subject_key_hex")?;
    if !(1..=8).contains(&input.max_recoveries) {
        return Err(invariant("max_recoveries must be between 1 and 8"));
    }
    require_time(input.issued_at, "issued_at")
}

pub(crate) fn initialize_finding_recovery_schema(
    connection: &mut Connection,
) -> Result<(), FindingRecoveryStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        SCHEMA_KEY,
        SUPPORTED_SCHEMA_VERSION,
        SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == SUPPORTED_SCHEMA_VERSION {
        return Ok(());
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction.execute_batch(SCHEMA).map_err(sqlite_error)?;
    crate::stamp_schema_version(&transaction, SCHEMA_KEY, SUPPORTED_SCHEMA_VERSION)
        .map_err(|error| invariant(error.to_string()))?;
    transaction.commit().map_err(sqlite_error)
}

fn require_identifier(value: &str, field: &str) -> Result<(), FindingRecoveryStoreError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

fn require_hex64(value: &str, field: &str) -> Result<(), FindingRecoveryStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

fn require_time(value: u64, field: &str) -> Result<(), FindingRecoveryStoreError> {
    if value == 0 {
        return Err(invariant(format!("{field} must be nonzero")));
    }
    Ok(())
}

fn sqlite_i64(value: u64, field: &str) -> Result<i64, FindingRecoveryStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &str) -> Result<u64, FindingRecoveryStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn stored_u32(value: i64, field: &str) -> Result<u32, FindingRecoveryStoreError> {
    u32::try_from(value).map_err(|_| invariant(format!("{field} is out of range")))
}

fn invariant(detail: impl Into<String>) -> FindingRecoveryStoreError {
    FindingRecoveryStoreError::Invariant(detail.into())
}

fn admission_error(error: AdmissionOperationStoreError) -> FindingRecoveryStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingRecoveryStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingRecoveryStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingRecoveryStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingRecoveryStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingRecoveryStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> FindingRecoveryStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingRecoveryStoreError::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
#[path = "finding_recovery_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
