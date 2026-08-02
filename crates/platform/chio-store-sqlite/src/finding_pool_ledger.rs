//! Qualifying SQLite ledger for authenticated cognition-market pool debits.
//!
//! Each debit runs in a SQLite `BEGIN IMMEDIATE` transaction. The signed pool
//! amount and accumulated spend are stored as canonical decimal text so the
//! complete Rust `u64` domain is preserved. A unique `pool_id` binding enforces
//! one purchaser allocation per pool, and exact purchase-id replay is durable.

use std::path::Path;
use std::time::Duration;

use chio_kernel::finding_pool::{
    AuthorizedFindingPoolDebit, FindingPoolDebitReceipt, FindingPoolLedger, FindingPoolLedgerError,
    QualifiedFindingPoolLedger,
};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{is_in_memory_sqlite_path, sqlite_parent_dir_to_create};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS finding_pool_allocations (
    allocation_envelope_sha256 TEXT PRIMARY KEY,
    allocation_id TEXT NOT NULL UNIQUE,
    pool_id TEXT NOT NULL UNIQUE,
    pool_sha256 TEXT NOT NULL,
    purchaser_id TEXT NOT NULL,
    purchaser_key_json TEXT NOT NULL,
    currency TEXT NOT NULL,
    signed_amount_units TEXT NOT NULL,
    spent_units TEXT NOT NULL,
    expires_at_unix_ms TEXT NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS finding_pool_debits (
    purchase_id TEXT PRIMARY KEY,
    allocation_envelope_sha256 TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    listing_id TEXT NOT NULL,
    reservation_id TEXT NOT NULL,
    authoritative_payment_operation_id TEXT NOT NULL,
    accepted_bid_envelope_sha256 TEXT NOT NULL,
    venue_admission_envelope_sha256 TEXT NOT NULL,
    amount_units TEXT NOT NULL,
    currency TEXT NOT NULL,
    spent_after_units TEXT NOT NULL,
    FOREIGN KEY (allocation_envelope_sha256)
        REFERENCES finding_pool_allocations(allocation_envelope_sha256)
) STRICT;
"#;

#[derive(Clone)]
pub struct SqliteFindingPoolLedger {
    pool: Pool<SqliteConnectionManager>,
}

impl SqliteFindingPoolLedger {
    /// Open the qualifying durable backend.
    ///
    /// In-memory paths are refused because restart durability is part of the
    /// hard-ceiling qualification.
    pub fn open_qualified(path: impl AsRef<Path>) -> Result<Self, FindingPoolLedgerError> {
        let path = path.as_ref();
        let path_text = path.to_str().ok_or_else(|| {
            FindingPoolLedgerError::Storage("SQLite path is not valid UTF-8".to_string())
        })?;
        let empty_uri_filename = path_text == "file:"
            || path_text.starts_with("file:?")
            || path_text.starts_with("file:#");
        if path_text.is_empty() || empty_uri_filename || is_in_memory_sqlite_path(path_text) {
            return Err(FindingPoolLedgerError::Storage(
                "qualified finding pool ledger requires a durable SQLite path".to_string(),
            ));
        }
        if let Some(parent) = sqlite_parent_dir_to_create(path) {
            std::fs::create_dir_all(parent)
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        }
        let manager = SqliteConnectionManager::file(path).with_init(|connection| {
            connection.busy_timeout(Duration::from_secs(30))?;
            connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
            Ok(())
        });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        {
            let connection = pool
                .get()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            connection
                .execute_batch(SCHEMA)
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        }
        Ok(Self { pool })
    }

    /// Return the accumulated spend for one signed allocation envelope.
    pub fn spent_units(
        &self,
        allocation_envelope_sha256: &str,
    ) -> Result<Option<u64>, FindingPoolLedgerError> {
        let connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let value = connection
            .query_row(
                "SELECT spent_units FROM finding_pool_allocations \
                 WHERE allocation_envelope_sha256 = ?1",
                [allocation_envelope_sha256],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        value
            .map(|text| parse_units(&text, "spent_units"))
            .transpose()
    }
}

impl FindingPoolLedger for SqliteFindingPoolLedger {
    fn contains_purchase(&self, purchase_id: &str) -> Result<bool, FindingPoolLedgerError> {
        let connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        connection
            .query_row(
                "SELECT 1 FROM finding_pool_debits WHERE purchase_id = ?1 LIMIT 1",
                [purchase_id],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
    }

    fn debit(
        &self,
        debit: &AuthorizedFindingPoolDebit,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        let mut connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;

        if let Some(existing) = transaction
            .query_row(
                "SELECT allocation_envelope_sha256, finding_id, listing_id, \
                        reservation_id, authoritative_payment_operation_id, \
                        accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                        amount_units, currency, spent_after_units \
                 FROM finding_pool_debits WHERE purchase_id = ?1",
                [debit.purchase_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
        {
            let amount = parse_units(&existing.7, "debit.amount_units")?;
            let spent_after = parse_units(&existing.9, "debit.spent_after_units")?;
            if existing.0 != debit.allocation_envelope_sha256()
                || existing.1 != debit.finding_id()
                || existing.2 != debit.listing_id()
                || existing.3 != debit.reservation_id()
                || existing.4 != debit.authoritative_payment_operation_id()
                || existing.5 != debit.accepted_bid_envelope_sha256()
                || existing.6 != debit.venue_admission_envelope_sha256()
                || amount != debit.debit_amount_units()
                || existing.8 != debit.currency()
            {
                return Err(FindingPoolLedgerError::ReplayConflict);
            }
            let remaining = debit
                .signed_amount_units()
                .checked_sub(spent_after)
                .ok_or(FindingPoolLedgerError::ReplayConflict)?;
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(FindingPoolDebitReceipt {
                purchase_id: debit.purchase_id().to_string(),
                allocation_id: debit.allocation_id().to_string(),
                allocation_envelope_sha256: debit.allocation_envelope_sha256().to_string(),
                amount_units: amount,
                currency: debit.currency().to_string(),
                spent_after_units: spent_after,
                remaining_after_units: remaining,
                replayed: true,
            });
        }

        if debit.debit_requested_at_unix_ms() < debit.allocation_issued_at_unix_ms()
            || debit.debit_requested_at_unix_ms() >= debit.allocation_expires_at_unix_ms()
        {
            return Err(FindingPoolLedgerError::AllocationNotLive);
        }

        let purchaser_key_json = serde_json::to_string(debit.purchaser_key())
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        transaction
            .execute(
                "INSERT OR IGNORE INTO finding_pool_allocations (\
                    allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                    purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                    spent_units, expires_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '0', ?9)",
                params![
                    debit.allocation_envelope_sha256(),
                    debit.allocation_id(),
                    debit.pool_id(),
                    debit.pool_sha256(),
                    debit.purchaser_id(),
                    purchaser_key_json,
                    debit.currency(),
                    debit.signed_amount_units().to_string(),
                    debit.allocation_expires_at_unix_ms().to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;

        let allocation = transaction
            .query_row(
                "SELECT allocation_envelope_sha256, allocation_id, pool_sha256, \
                        purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                        spent_units, expires_at_unix_ms \
                 FROM finding_pool_allocations WHERE pool_id = ?1",
                [debit.pool_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                        row.get::<_, String>(8)?,
                    ))
                },
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if allocation.0 != debit.allocation_envelope_sha256()
            || allocation.1 != debit.allocation_id()
            || allocation.2 != debit.pool_sha256()
            || allocation.3 != debit.purchaser_id()
            || allocation.4 != purchaser_key_json
            || allocation.5 != debit.currency()
            || parse_units(&allocation.6, "signed_amount_units")? != debit.signed_amount_units()
            || parse_units(&allocation.8, "expires_at_unix_ms")?
                != debit.allocation_expires_at_unix_ms()
        {
            return Err(FindingPoolLedgerError::PoolBindingConflict);
        }
        let spent = parse_units(&allocation.7, "spent_units")?;
        let spent_after = spent
            .checked_add(debit.debit_amount_units())
            .ok_or(FindingPoolLedgerError::AmountExceeded)?;
        if spent_after > debit.signed_amount_units() {
            return Err(FindingPoolLedgerError::AmountExceeded);
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_allocations SET spent_units = ?2 \
                 WHERE allocation_envelope_sha256 = ?1 AND spent_units = ?3",
                params![
                    debit.allocation_envelope_sha256(),
                    spent_after.to_string(),
                    spent.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(FindingPoolLedgerError::Storage(
                "finding pool ledger compare-and-set failed".to_string(),
            ));
        }
        transaction
            .execute(
                "INSERT INTO finding_pool_debits (\
                    purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                    reservation_id, authoritative_payment_operation_id, \
                    accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                    amount_units, currency, spent_after_units\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    debit.purchase_id(),
                    debit.allocation_envelope_sha256(),
                    debit.finding_id(),
                    debit.listing_id(),
                    debit.reservation_id(),
                    debit.authoritative_payment_operation_id(),
                    debit.accepted_bid_envelope_sha256(),
                    debit.venue_admission_envelope_sha256(),
                    debit.debit_amount_units().to_string(),
                    debit.currency(),
                    spent_after.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        Ok(FindingPoolDebitReceipt {
            purchase_id: debit.purchase_id().to_string(),
            allocation_id: debit.allocation_id().to_string(),
            allocation_envelope_sha256: debit.allocation_envelope_sha256().to_string(),
            amount_units: debit.debit_amount_units(),
            currency: debit.currency().to_string(),
            spent_after_units: spent_after,
            remaining_after_units: debit.signed_amount_units() - spent_after,
            replayed: false,
        })
    }
}

impl QualifiedFindingPoolLedger for SqliteFindingPoolLedger {}

fn parse_units(value: &str, field: &str) -> Result<u64, FindingPoolLedgerError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(FindingPoolLedgerError::Storage(format!(
            "stored {field} is not a canonical u64"
        )));
    }
    value.parse::<u64>().map_err(|error| {
        FindingPoolLedgerError::Storage(format!("stored {field} is invalid: {error}"))
    })
}
