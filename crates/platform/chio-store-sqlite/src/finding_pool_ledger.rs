//! Qualifying SQLite ledger for authenticated cognition-market pool debits.
//!
//! Each mutation runs in a SQLite `BEGIN IMMEDIATE` transaction. The signed
//! pool amount, pending reservations, and finalized spend are stored as
//! canonical decimal text so the complete Rust `u64` domain is preserved. A
//! unique `pool_id` binding enforces one purchaser allocation per pool, and
//! exact purchase-id and delivery-terminal replay are durable.

use std::path::Path;
use std::time::Duration;

use chio_kernel::finding_pool::{
    AuthorizedFindingPoolClaim, AuthorizedFindingPoolDebit, AuthorizedFindingPoolTerminal,
    FindingPoolDebitReceipt, FindingPoolDebitState, FindingPoolLedger, FindingPoolLedgerError,
    FindingPoolTerminalDecision, QualifiedFindingPoolLedger,
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
    reserved_units TEXT NOT NULL,
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
    state TEXT NOT NULL CHECK (state IN ('reserved', 'finalized', 'released')),
    claim_deadline_unix_ms TEXT NOT NULL,
    claimed_at_unix_ms TEXT,
    reserved_after_units TEXT NOT NULL,
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
            ensure_lifecycle_columns(&connection)?;
        }
        Ok(Self { pool })
    }

    /// Return the finalized spend for one signed allocation envelope.
    pub fn spent_units(
        &self,
        allocation_envelope_sha256: &str,
    ) -> Result<Option<u64>, FindingPoolLedgerError> {
        self.allocation_counter(allocation_envelope_sha256, "spent_units")
    }

    /// Return the currently reserved, not-yet-finalized amount for one signed
    /// allocation envelope.
    pub fn reserved_units(
        &self,
        allocation_envelope_sha256: &str,
    ) -> Result<Option<u64>, FindingPoolLedgerError> {
        self.allocation_counter(allocation_envelope_sha256, "reserved_units")
    }

    fn allocation_counter(
        &self,
        allocation_envelope_sha256: &str,
        column: &'static str,
    ) -> Result<Option<u64>, FindingPoolLedgerError> {
        let connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let sql = format!(
            "SELECT {column} FROM finding_pool_allocations \
             WHERE allocation_envelope_sha256 = ?1"
        );
        let value = connection
            .query_row(&sql, [allocation_envelope_sha256], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        value.map(|text| parse_units(&text, column)).transpose()
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

        reclaim_expired_unclaimed(
            &transaction,
            debit.allocation_envelope_sha256(),
            debit.debit_requested_at_unix_ms(),
        )?;

        if let Some(existing) = transaction
            .query_row(
                "SELECT d.allocation_envelope_sha256, a.allocation_id, d.finding_id, \
                        d.listing_id, d.reservation_id, \
                        d.authoritative_payment_operation_id, \
                        d.accepted_bid_envelope_sha256, \
                        d.venue_admission_envelope_sha256, d.amount_units, \
                        d.currency, d.state, d.reserved_after_units, \
                        d.spent_after_units, a.signed_amount_units \
                 FROM finding_pool_debits d \
                 JOIN finding_pool_allocations a \
                   ON a.allocation_envelope_sha256 = d.allocation_envelope_sha256 \
                 WHERE d.purchase_id = ?1",
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
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
        {
            let amount = parse_units(&existing.8, "debit.amount_units")?;
            let state = parse_state(&existing.10)?;
            let reserved_after = parse_units(&existing.11, "debit.reserved_after_units")?;
            let spent_after = parse_units(&existing.12, "debit.spent_after_units")?;
            let signed = parse_units(&existing.13, "signed_amount_units")?;
            if existing.0 != debit.allocation_envelope_sha256()
                || existing.1 != debit.allocation_id()
                || existing.2 != debit.finding_id()
                || existing.3 != debit.listing_id()
                || existing.4 != debit.reservation_id()
                || existing.5 != debit.authoritative_payment_operation_id()
                || existing.6 != debit.accepted_bid_envelope_sha256()
                || existing.7 != debit.venue_admission_envelope_sha256()
                || amount != debit.debit_amount_units()
                || existing.9 != debit.currency()
                || signed != debit.signed_amount_units()
            {
                return Err(FindingPoolLedgerError::ReplayConflict);
            }
            let remaining = remaining_units(signed, reserved_after, spent_after)?;
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(FindingPoolDebitReceipt {
                purchase_id: debit.purchase_id().to_string(),
                allocation_id: existing.1,
                allocation_envelope_sha256: debit.allocation_envelope_sha256().to_string(),
                amount_units: amount,
                currency: debit.currency().to_string(),
                state,
                reserved_after_units: reserved_after,
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
                    reserved_units, spent_units, expires_at_unix_ms\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '0', '0', ?9)",
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
                        reserved_units, spent_units, expires_at_unix_ms \
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
                        row.get::<_, String>(9)?,
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
            || parse_units(&allocation.9, "expires_at_unix_ms")?
                != debit.allocation_expires_at_unix_ms()
        {
            return Err(FindingPoolLedgerError::PoolBindingConflict);
        }
        let reserved = parse_units(&allocation.7, "reserved_units")?;
        let spent = parse_units(&allocation.8, "spent_units")?;
        let reserved_after = reserved
            .checked_add(debit.debit_amount_units())
            .ok_or(FindingPoolLedgerError::AmountExceeded)?;
        let encumbered = spent
            .checked_add(reserved_after)
            .ok_or(FindingPoolLedgerError::AmountExceeded)?;
        if encumbered > debit.signed_amount_units() {
            return Err(FindingPoolLedgerError::AmountExceeded);
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_allocations SET reserved_units = ?2 \
                 WHERE allocation_envelope_sha256 = ?1 AND reserved_units = ?3",
                params![
                    debit.allocation_envelope_sha256(),
                    reserved_after.to_string(),
                    reserved.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("reservation compare-and-set failed"));
        }
        transaction
            .execute(
                "INSERT INTO finding_pool_debits (\
                    purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                    reservation_id, authoritative_payment_operation_id, \
                    accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                    amount_units, currency, state, claim_deadline_unix_ms, \
                    claimed_at_unix_ms, reserved_after_units, spent_after_units\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                           'reserved', ?11, NULL, ?12, ?13)",
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
                    debit.claim_deadline_unix_ms().to_string(),
                    reserved_after.to_string(),
                    spent.to_string(),
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
            state: FindingPoolDebitState::Reserved,
            reserved_after_units: reserved_after,
            spent_after_units: spent,
            remaining_after_units: remaining_units(
                debit.signed_amount_units(),
                reserved_after,
                spent,
            )?,
            replayed: false,
        })
    }

    fn claim(&self, claim: &AuthorizedFindingPoolClaim) -> Result<(), FindingPoolLedgerError> {
        let mut connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let stored = transaction
            .query_row(
                "SELECT allocation_envelope_sha256, finding_id, listing_id, \
                        reservation_id, authoritative_payment_operation_id, \
                        accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                        amount_units, currency, state, claim_deadline_unix_ms, \
                        claimed_at_unix_ms \
                 FROM finding_pool_debits WHERE purchase_id = ?1",
                [claim.purchase_id()],
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
                        row.get::<_, String>(10)?,
                        row.get::<_, Option<String>>(11)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
            .ok_or(FindingPoolLedgerError::ReservationMissing)?;
        let amount = parse_units(&stored.7, "debit.amount_units")?;
        let state = parse_state(&stored.9)?;
        let claim_deadline = parse_units(&stored.10, "debit.claim_deadline_unix_ms")?;
        if stored.1 != claim.finding_id()
            || stored.2 != claim.listing_id()
            || stored.3 != claim.reservation_id()
            || stored.4 != claim.authoritative_payment_operation_id()
            || stored.5 != claim.accepted_bid_envelope_sha256()
            || stored.6 != claim.venue_admission_envelope_sha256()
            || amount != claim.amount_units()
            || stored.8 != claim.currency()
        {
            return Err(FindingPoolLedgerError::ReplayConflict);
        }
        if state != FindingPoolDebitState::Reserved {
            return Err(FindingPoolLedgerError::TerminalConflict);
        }
        if let Some(claimed_at) = stored.11 {
            parse_units(&claimed_at, "debit.claimed_at_unix_ms")?;
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(());
        }
        if claim.claimed_at_unix_ms() >= claim_deadline {
            reclaim_expired_unclaimed(&transaction, &stored.0, claim.claimed_at_unix_ms())?;
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Err(FindingPoolLedgerError::ClaimDeadlineElapsed);
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_debits SET claimed_at_unix_ms = ?2 \
                 WHERE purchase_id = ?1 AND state = 'reserved' \
                   AND claimed_at_unix_ms IS NULL",
                params![claim.purchase_id(), claim.claimed_at_unix_ms().to_string(),],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("reservation claim compare-and-set failed"));
        }
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
    }

    fn settle(
        &self,
        terminal: &AuthorizedFindingPoolTerminal,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        let mut connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let stored = transaction
            .query_row(
                "SELECT d.allocation_envelope_sha256, a.allocation_id, d.finding_id, \
                        d.listing_id, d.reservation_id, \
                        d.authoritative_payment_operation_id, d.amount_units, \
                        d.currency, d.state, d.reserved_after_units, \
                        d.spent_after_units, a.signed_amount_units, \
                        a.reserved_units, a.spent_units \
                 FROM finding_pool_debits d \
                 JOIN finding_pool_allocations a \
                   ON a.allocation_envelope_sha256 = d.allocation_envelope_sha256 \
                 WHERE d.purchase_id = ?1",
                [terminal.purchase_id()],
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
                        row.get::<_, String>(10)?,
                        row.get::<_, String>(11)?,
                        row.get::<_, String>(12)?,
                        row.get::<_, String>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
            .ok_or(FindingPoolLedgerError::ReservationMissing)?;
        let amount = parse_units(&stored.6, "debit.amount_units")?;
        let state = parse_state(&stored.8)?;
        let recorded_reserved_after = parse_units(&stored.9, "debit.reserved_after_units")?;
        let recorded_spent_after = parse_units(&stored.10, "debit.spent_after_units")?;
        let signed = parse_units(&stored.11, "signed_amount_units")?;
        let current_reserved = parse_units(&stored.12, "reserved_units")?;
        let current_spent = parse_units(&stored.13, "spent_units")?;
        if stored.2 != terminal.finding_id()
            || stored.3 != terminal.listing_id()
            || stored.4 != terminal.reservation_id()
            || stored.5 != terminal.authoritative_payment_operation_id()
            || amount != terminal.amount_units()
            || stored.7 != terminal.currency()
        {
            return Err(FindingPoolLedgerError::TerminalConflict);
        }
        let target = match terminal.decision() {
            FindingPoolTerminalDecision::Finalize => FindingPoolDebitState::Finalized,
            FindingPoolTerminalDecision::Release => FindingPoolDebitState::Released,
        };
        if state != FindingPoolDebitState::Reserved {
            if state != target {
                return Err(FindingPoolLedgerError::TerminalConflict);
            }
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(FindingPoolDebitReceipt {
                purchase_id: terminal.purchase_id().to_string(),
                allocation_id: stored.1,
                allocation_envelope_sha256: stored.0,
                amount_units: amount,
                currency: terminal.currency().to_string(),
                state,
                reserved_after_units: recorded_reserved_after,
                spent_after_units: recorded_spent_after,
                remaining_after_units: remaining_units(
                    signed,
                    recorded_reserved_after,
                    recorded_spent_after,
                )?,
                replayed: true,
            });
        }
        let reserved_after = current_reserved
            .checked_sub(amount)
            .ok_or_else(|| invariant("reservation exceeds allocation reserved amount"))?;
        let spent_after = match target {
            FindingPoolDebitState::Finalized => current_spent
                .checked_add(amount)
                .ok_or(FindingPoolLedgerError::AmountExceeded)?,
            FindingPoolDebitState::Released => current_spent,
            FindingPoolDebitState::Reserved => {
                return Err(invariant("terminal target remained reserved"));
            }
        };
        remaining_units(signed, reserved_after, spent_after)?;
        let changed = transaction
            .execute(
                "UPDATE finding_pool_allocations \
                 SET reserved_units = ?2, spent_units = ?3 \
                 WHERE allocation_envelope_sha256 = ?1 \
                   AND reserved_units = ?4 AND spent_units = ?5",
                params![
                    stored.0,
                    reserved_after.to_string(),
                    spent_after.to_string(),
                    current_reserved.to_string(),
                    current_spent.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("allocation terminal compare-and-set failed"));
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_debits \
                 SET state = ?2, reserved_after_units = ?3, spent_after_units = ?4 \
                 WHERE purchase_id = ?1 AND state = 'reserved'",
                params![
                    terminal.purchase_id(),
                    state_text(target),
                    reserved_after.to_string(),
                    spent_after.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("reservation terminal compare-and-set failed"));
        }
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        Ok(FindingPoolDebitReceipt {
            purchase_id: terminal.purchase_id().to_string(),
            allocation_id: stored.1,
            allocation_envelope_sha256: stored.0,
            amount_units: amount,
            currency: terminal.currency().to_string(),
            state: target,
            reserved_after_units: reserved_after,
            spent_after_units: spent_after,
            remaining_after_units: remaining_units(signed, reserved_after, spent_after)?,
            replayed: false,
        })
    }
}

impl QualifiedFindingPoolLedger for SqliteFindingPoolLedger {}

fn reclaim_expired_unclaimed(
    transaction: &rusqlite::Transaction<'_>,
    allocation_envelope_sha256: &str,
    trusted_now_unix_ms: u64,
) -> Result<(), FindingPoolLedgerError> {
    let Some((signed_text, reserved_text, spent_text)) = transaction
        .query_row(
            "SELECT signed_amount_units, reserved_units, spent_units \
             FROM finding_pool_allocations WHERE allocation_envelope_sha256 = ?1",
            [allocation_envelope_sha256],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
    else {
        return Ok(());
    };
    let signed = parse_units(&signed_text, "signed_amount_units")?;
    let original_reserved = parse_units(&reserved_text, "reserved_units")?;
    let spent = parse_units(&spent_text, "spent_units")?;
    let mut statement = transaction
        .prepare(
            "SELECT purchase_id, amount_units, claim_deadline_unix_ms \
             FROM finding_pool_debits \
             WHERE allocation_envelope_sha256 = ?1 AND state = 'reserved' \
               AND claimed_at_unix_ms IS NULL ORDER BY purchase_id",
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut rows = statement
        .query([allocation_envelope_sha256])
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut expired = Vec::new();
    while let Some(row) = rows
        .next()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
    {
        let purchase_id = row
            .get::<_, String>(0)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let amount_text = row
            .get::<_, String>(1)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let deadline_text = row
            .get::<_, String>(2)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let amount = parse_units(&amount_text, "debit.amount_units")?;
        let deadline = parse_units(&deadline_text, "debit.claim_deadline_unix_ms")?;
        if trusted_now_unix_ms >= deadline {
            expired.push((purchase_id, amount));
        }
    }
    drop(rows);
    drop(statement);
    if expired.is_empty() {
        return Ok(());
    }
    let mut reserved_after = original_reserved;
    let mut releases = Vec::with_capacity(expired.len());
    for (purchase_id, amount) in expired {
        reserved_after = reserved_after
            .checked_sub(amount)
            .ok_or_else(|| invariant("expired reservation exceeds allocation reserve"))?;
        releases.push((purchase_id, reserved_after));
    }
    remaining_units(signed, reserved_after, spent)?;
    let changed = transaction
        .execute(
            "UPDATE finding_pool_allocations SET reserved_units = ?2 \
             WHERE allocation_envelope_sha256 = ?1 AND reserved_units = ?3 \
               AND spent_units = ?4",
            params![
                allocation_envelope_sha256,
                reserved_after.to_string(),
                original_reserved.to_string(),
                spent.to_string(),
            ],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(invariant(
            "expired reservation allocation compare-and-set failed",
        ));
    }
    for (purchase_id, release_reserved_after) in releases {
        let changed = transaction
            .execute(
                "UPDATE finding_pool_debits \
                 SET state = 'released', reserved_after_units = ?2, spent_after_units = ?3 \
                 WHERE purchase_id = ?1 AND state = 'reserved' \
                   AND claimed_at_unix_ms IS NULL",
                params![
                    purchase_id,
                    release_reserved_after.to_string(),
                    spent.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("expired reservation compare-and-set failed"));
        }
    }
    Ok(())
}

fn ensure_lifecycle_columns(
    connection: &rusqlite::Connection,
) -> Result<(), FindingPoolLedgerError> {
    ensure_column(
        connection,
        "finding_pool_allocations",
        "reserved_units",
        "ALTER TABLE finding_pool_allocations \
         ADD COLUMN reserved_units TEXT NOT NULL DEFAULT '0'",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "state",
        "ALTER TABLE finding_pool_debits ADD COLUMN state TEXT NOT NULL \
         DEFAULT 'finalized' CHECK (state IN ('reserved', 'finalized', 'released'))",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "reserved_after_units",
        "ALTER TABLE finding_pool_debits \
         ADD COLUMN reserved_after_units TEXT NOT NULL DEFAULT '0'",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "claim_deadline_unix_ms",
        "ALTER TABLE finding_pool_debits \
         ADD COLUMN claim_deadline_unix_ms TEXT NOT NULL DEFAULT '0'",
    )?;
    ensure_column(
        connection,
        "finding_pool_debits",
        "claimed_at_unix_ms",
        "ALTER TABLE finding_pool_debits ADD COLUMN claimed_at_unix_ms TEXT",
    )?;
    connection
        .execute(
            "UPDATE finding_pool_debits SET claimed_at_unix_ms = '0' \
             WHERE state = 'reserved' AND claim_deadline_unix_ms = '0' \
               AND claimed_at_unix_ms IS NULL",
            [],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    Ok(())
}

fn ensure_column(
    connection: &rusqlite::Connection,
    table: &str,
    column: &str,
    ddl: &str,
) -> Result<(), FindingPoolLedgerError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut rows = statement
        .query([])
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
    {
        let name = row
            .get::<_, String>(1)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if name == column {
            return Ok(());
        }
    }
    drop(rows);
    drop(statement);
    connection
        .execute_batch(ddl)
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
}

fn parse_state(value: &str) -> Result<FindingPoolDebitState, FindingPoolLedgerError> {
    match value {
        "reserved" => Ok(FindingPoolDebitState::Reserved),
        "finalized" => Ok(FindingPoolDebitState::Finalized),
        "released" => Ok(FindingPoolDebitState::Released),
        _ => Err(invariant("stored reservation state is invalid")),
    }
}

const fn state_text(state: FindingPoolDebitState) -> &'static str {
    match state {
        FindingPoolDebitState::Reserved => "reserved",
        FindingPoolDebitState::Finalized => "finalized",
        FindingPoolDebitState::Released => "released",
    }
}

fn remaining_units(signed: u64, reserved: u64, spent: u64) -> Result<u64, FindingPoolLedgerError> {
    let encumbered = reserved
        .checked_add(spent)
        .ok_or(FindingPoolLedgerError::AmountExceeded)?;
    signed
        .checked_sub(encumbered)
        .ok_or(FindingPoolLedgerError::AmountExceeded)
}

fn invariant(message: &str) -> FindingPoolLedgerError {
    FindingPoolLedgerError::Storage(format!("finding pool ledger invariant failed: {message}"))
}

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
