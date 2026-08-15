//! Qualifying SQLite ledger for authenticated cognition-market pool debits.
//!
//! Each mutation runs in a SQLite `BEGIN IMMEDIATE` transaction. The signed
//! pool amount, pending reservations, and finalized spend are stored as
//! canonical decimal text so the complete Rust `u64` domain is preserved. A
//! unique `pool_id` binding enforces one purchaser allocation per pool, and
//! exact purchase-id and delivery-terminal replay are durable.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use chio_core::crypto::PublicKey;
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::finding_pool::{
    AuthorizedFindingPoolClaim, AuthorizedFindingPoolDebit, AuthorizedFindingPoolDebitReplay,
    AuthorizedFindingPoolRecoveryRelease, AuthorizedFindingPoolTerminal,
    AuthorizedFindingPoolUnknownDispatchTerminal, FindingPoolDebitReceipt, FindingPoolDebitState,
    FindingPoolLedger, FindingPoolLedgerError, FindingPoolMutation, FindingPoolMutationAttestor,
    FindingPoolMutationKind, FindingPoolTerminalDecision, QualifiedFindingPoolLedger,
    FINDING_POOL_MUTATION_SCHEMA_V1,
};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, OptionalExtension};

use crate::{is_in_memory_sqlite_path, sqlite_parent_dir_to_create};

mod expiration;
mod outbox;
mod qualification;
mod schema;

use crate::rollback_generation::RollbackGenerationAnchor;
use expiration::expired_unclaimed_reservations;
use outbox::{
    acknowledge_mutation_receipt, advance_outbox_lease_epoch, claim_pending_mutation_receipts,
    has_pending_mutation_receipts, OutboxLeaseClock,
};
use qualification::{
    acquire_domain_lease, bind_ledger_store, bind_receipt_authority, bind_receipt_configuration,
    bind_rollback_anchor, canonical_receipt_authority_json, open_rollback_anchor,
    prepare_database_identity, verify_rollback_anchor, AnchoredLedgerTransaction,
    FindingPoolDomainLease, QualifiedDatabaseIdentity,
};
use schema::{
    ensure_column, ensure_lifecycle_columns, ensure_outbox_delivery_claim_columns,
    ensure_query_indexes,
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS finding_pool_ledger_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    ledger_domain TEXT NOT NULL,
    receipt_sink_id TEXT,
    receipt_authority_json TEXT,
    ledger_store_binding_sha256 TEXT,
    store_generation TEXT NOT NULL DEFAULT '0',
    outbox_lease_epoch INTEGER NOT NULL DEFAULT 0,
    trusted_time_high_water_unix_ms TEXT NOT NULL DEFAULT '0'
) STRICT;

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
    tenant_id TEXT,
    allocation_envelope_sha256 TEXT NOT NULL,
    debit_request_binding_sha256 TEXT,
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
    durable_admission_operation_id TEXT,
    reserved_after_units TEXT NOT NULL,
    spent_after_units TEXT NOT NULL,
    FOREIGN KEY (allocation_envelope_sha256)
        REFERENCES finding_pool_allocations(allocation_envelope_sha256)
) STRICT;

CREATE TABLE IF NOT EXISTS finding_pool_receipt_outbox (
    receipt_id TEXT PRIMARY KEY,
    purchase_id TEXT NOT NULL,
    allocation_envelope_sha256 TEXT NOT NULL,
    mutation_kind TEXT NOT NULL,
    signed_receipt_json TEXT NOT NULL,
    occurred_at_unix_ms TEXT NOT NULL,
    acknowledged_at_unix_ms TEXT,
    delivery_claim_owner TEXT,
    delivery_claim_expires_at_unix_ms INTEGER,
    delivery_claim_epoch INTEGER,
    delivery_sequence INTEGER
) STRICT;
"#;

const MAX_EXPIRED_RECLAMATIONS_PER_DEBIT: usize = 64;

#[derive(Clone)]
pub struct SqliteFindingPoolLedger {
    pool: Pool<SqliteConnectionManager>,
    ledger_domain: String,
    ledger_store_binding_sha256: String,
    database_identity: QualifiedDatabaseIdentity,
    rollback_anchor: Arc<RollbackGenerationAnchor>,
    outbox_lease_clock: Arc<OutboxLeaseClock>,
    _domain_lease: Arc<FindingPoolDomainLease>,
}

impl SqliteFindingPoolLedger {
    /// Open the qualifying durable backend.
    ///
    /// In-memory paths are refused because restart durability is part of the
    /// hard-ceiling qualification. `store_identity` must be held outside the
    /// SQLite database. `rollback_anchor_root` must be on a different
    /// filesystem device so the same storage snapshot cannot roll back both
    /// records. The identity's live proof, canonical identity, and external
    /// anchor instance id bind it globally, so a copy cannot qualify elsewhere.
    pub fn open_qualified(
        path: impl AsRef<Path>,
        ledger_domain: impl Into<String>,
        store_identity: &dyn chio_core::crypto::SigningBackend,
        rollback_anchor_root: impl AsRef<Path>,
    ) -> Result<Self, FindingPoolLedgerError> {
        let ledger_domain = ledger_domain.into();
        validate_ledger_domain(&ledger_domain)?;
        let path = path.as_ref();
        let path_text = path.to_str().ok_or_else(|| {
            FindingPoolLedgerError::Storage("SQLite path is not valid UTF-8".to_string())
        })?;
        let empty_uri_filename = sqlite_uri_filename_is_empty(path_text);
        if path_text.is_empty()
            || empty_uri_filename
            || is_in_memory_sqlite_path(path_text)
            || crate::sqlite_uri_disables_locking(path_text)
            || crate::sqlite_uri_is_read_only(path_text)
        {
            return Err(FindingPoolLedgerError::Storage(
                "qualified finding pool ledger requires a durable SQLite path".to_string(),
            ));
        }
        if let Some(parent) = qualified_sqlite_parent_dir(path, path_text)? {
            std::fs::create_dir_all(parent)
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        }
        let database_identity = prepare_database_identity(path_text)?;
        crate::rollback_generation::require_separate_snapshot_domain(
            database_identity.path(),
            rollback_anchor_root.as_ref(),
        )
        .map_err(FindingPoolLedgerError::Storage)?;
        let manager =
            SqliteConnectionManager::file(database_identity.path()).with_init(|connection| {
                connection.busy_timeout(Duration::from_secs(30))?;
                connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
                Ok(())
            });
        let pool = Pool::builder()
            .max_size(8)
            .build(manager)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let domain_lease = acquire_domain_lease(&ledger_domain, database_identity.path())?;
        let rollback_anchor = open_rollback_anchor(
            rollback_anchor_root.as_ref(),
            &ledger_domain,
            &database_identity,
            store_identity,
        )?;
        let ledger_store_binding_sha256;
        let outbox_lease_epoch;
        {
            let mut connection = pool
                .get()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            connection
                .execute_batch(SCHEMA)
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            ensure_column(
                &connection,
                "finding_pool_ledger_metadata",
                "receipt_sink_id",
                "ALTER TABLE finding_pool_ledger_metadata ADD COLUMN receipt_sink_id TEXT",
            )?;
            ensure_column(
                &connection,
                "finding_pool_ledger_metadata",
                "receipt_authority_json",
                "ALTER TABLE finding_pool_ledger_metadata ADD COLUMN receipt_authority_json TEXT",
            )?;
            ensure_column(
                &connection,
                "finding_pool_ledger_metadata",
                "ledger_store_binding_sha256",
                "ALTER TABLE finding_pool_ledger_metadata \
                 ADD COLUMN ledger_store_binding_sha256 TEXT",
            )?;
            ensure_column(
                &connection,
                "finding_pool_ledger_metadata",
                "store_generation",
                "ALTER TABLE finding_pool_ledger_metadata \
                 ADD COLUMN store_generation TEXT NOT NULL DEFAULT '0'",
            )?;
            ensure_column(
                &connection,
                "finding_pool_ledger_metadata",
                "outbox_lease_epoch",
                "ALTER TABLE finding_pool_ledger_metadata \
                 ADD COLUMN outbox_lease_epoch INTEGER NOT NULL DEFAULT 0",
            )?;
            ensure_column(
                &connection,
                "finding_pool_ledger_metadata",
                "trusted_time_high_water_unix_ms",
                "ALTER TABLE finding_pool_ledger_metadata \
                 ADD COLUMN trusted_time_high_water_unix_ms TEXT NOT NULL DEFAULT '0'",
            )?;
            bind_ledger_domain(&connection, &ledger_domain)?;
            bind_rollback_anchor(&connection, &rollback_anchor)?;
            ledger_store_binding_sha256 = bind_ledger_store(
                &mut connection,
                &ledger_domain,
                &database_identity,
                store_identity,
                &rollback_anchor,
            )?;
            ensure_lifecycle_columns(&connection)?;
            ensure_outbox_delivery_claim_columns(&connection)?;
            outbox_lease_epoch = domain_lease
                .initialize_outbox_lease_epoch(|| advance_outbox_lease_epoch(&connection))?;
            ensure_query_indexes(&connection)?;
            verify_qualified_connection(&connection)?;
            connection
                .execute_batch("BEGIN IMMEDIATE; ROLLBACK;")
                .map_err(|error| {
                    FindingPoolLedgerError::Storage(format!(
                        "qualified finding pool ledger is not writable: {error}"
                    ))
                })?;
        }
        Ok(Self {
            pool,
            ledger_domain,
            ledger_store_binding_sha256,
            database_identity,
            rollback_anchor,
            outbox_lease_clock: Arc::new(OutboxLeaseClock::new(outbox_lease_epoch)),
            _domain_lease: domain_lease,
        })
    }

    fn connection(
        &self,
    ) -> Result<PooledConnection<SqliteConnectionManager>, FindingPoolLedgerError> {
        self.database_identity.validate()?;
        let connection = self
            .pool
            .get()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        self.database_identity.validate_connection(&connection)?;
        verify_rollback_anchor(&connection, &self.rollback_anchor)?;
        Ok(connection)
    }

    fn transaction<'connection>(
        &self,
        connection: &'connection mut rusqlite::Connection,
    ) -> Result<AnchoredLedgerTransaction<'connection>, FindingPoolLedgerError> {
        self.database_identity.validate_connection(connection)?;
        AnchoredLedgerTransaction::begin(connection, Arc::clone(&self.rollback_anchor))
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
        let connection = self.connection()?;
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

fn qualified_sqlite_parent_dir(
    path: &Path,
    path_text: &str,
) -> Result<Option<std::path::PathBuf>, FindingPoolLedgerError> {
    if !path_text.starts_with("file:") {
        return Ok(sqlite_parent_dir_to_create(path));
    }
    let filesystem_path = crate::sqlite_filesystem_path(path_text);
    let encoded_filename = filesystem_path.to_str().ok_or_else(|| {
        FindingPoolLedgerError::Storage("SQLite URI filename is not valid UTF-8".to_string())
    })?;
    let decoded_filename = crate::percent_decode_sqlite_uri_component(encoded_filename)
        .ok_or_else(|| {
            FindingPoolLedgerError::Storage(
                "SQLite URI filename has invalid percent encoding".to_string(),
            )
        })?;
    if decoded_filename.contains('\0') {
        return Err(FindingPoolLedgerError::Storage(
            "SQLite URI filename contains a NUL byte".to_string(),
        ));
    }
    Ok(Path::new(&decoded_filename)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf))
}

fn sqlite_uri_filename_is_empty(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("file:") else {
        return false;
    };
    let rest = rest.split_once('#').map_or(rest, |(uri, _)| uri);
    let name = rest.split_once('?').map_or(rest, |(name, _)| name);
    if let Some(authority_and_path) = name.strip_prefix("//") {
        return !authority_and_path.contains('/');
    }
    name.is_empty()
}

fn verify_qualified_connection(
    connection: &rusqlite::Connection,
) -> Result<(), FindingPoolLedgerError> {
    let journal_mode = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let foreign_keys = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let locking_mode = connection
        .query_row("PRAGMA locking_mode", [], |row| row.get::<_, String>(0))
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if !journal_mode.eq_ignore_ascii_case("wal")
        || foreign_keys != 1
        || (!locking_mode.eq_ignore_ascii_case("normal")
            && !locking_mode.eq_ignore_ascii_case("exclusive"))
    {
        return Err(FindingPoolLedgerError::Storage(
            "qualified finding pool ledger did not activate WAL, foreign keys, and file locking"
                .to_string(),
        ));
    }
    Ok(())
}

impl FindingPoolLedger for SqliteFindingPoolLedger {
    fn contains_purchase(&self, purchase_id: &str) -> Result<bool, FindingPoolLedgerError> {
        let connection = self.connection()?;
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

    fn replay_debit(
        &self,
        replay: &AuthorizedFindingPoolDebitReplay,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        let connection = self.connection()?;
        let stored = connection
            .query_row(
                "SELECT d.allocation_envelope_sha256, a.allocation_id, \
                        d.debit_request_binding_sha256, d.tenant_id, d.amount_units, \
                        d.currency, d.state, d.reserved_after_units, \
                        d.spent_after_units, a.signed_amount_units \
                 FROM finding_pool_debits d \
                 JOIN finding_pool_allocations a \
                   ON a.allocation_envelope_sha256 = d.allocation_envelope_sha256 \
                 WHERE d.purchase_id = ?1",
                [replay.purchase_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
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
            .ok_or(FindingPoolLedgerError::ReservationMissing)?;
        if stored.0 != replay.allocation_envelope_sha256()
            || stored.2.as_deref() != Some(replay.debit_request_binding_sha256())
            || stored.3.as_deref() != replay.tenant_id()
        {
            return Err(FindingPoolLedgerError::ReplayConflict);
        }
        let amount = parse_units(&stored.4, "debit.amount_units")?;
        let state = parse_state(&stored.6)?;
        let reserved_after = parse_units(&stored.7, "debit.reserved_after_units")?;
        let spent_after = parse_units(&stored.8, "debit.spent_after_units")?;
        let signed = parse_units(&stored.9, "signed_amount_units")?;
        Ok(FindingPoolDebitReceipt {
            purchase_id: replay.purchase_id().to_owned(),
            allocation_id: stored.1,
            allocation_envelope_sha256: stored.0,
            amount_units: amount,
            currency: stored.5,
            state,
            reserved_after_units: reserved_after,
            spent_after_units: spent_after,
            remaining_after_units: remaining_units(signed, reserved_after, spent_after)?,
            replayed: true,
        })
    }

    fn list_claimed_admission_operations(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, FindingPoolLedgerError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).map_err(|_| {
            FindingPoolLedgerError::Storage(
                "finding pool claimed-operation page limit exceeds SQLite range".to_owned(),
            )
        })?;
        let connection = self.connection()?;
        let mut statement = connection
            .prepare(
                "SELECT durable_admission_operation_id \
                 FROM finding_pool_debits \
                 WHERE state = 'reserved' \
                   AND claimed_at_unix_ms IS NOT NULL \
                   AND durable_admission_operation_id IS NOT NULL \
                   AND (?1 IS NULL OR durable_admission_operation_id > ?1) \
                 ORDER BY durable_admission_operation_id ASC \
                 LIMIT ?2",
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let rows = statement
            .query_map(params![after_operation_id, limit], |row| {
                row.get::<_, String>(0)
            })
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
    }

    fn debit(
        &self,
        debit: &AuthorizedFindingPoolDebit,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        if debit.ledger_domain() != self.ledger_domain {
            return Err(FindingPoolLedgerError::LedgerDomainMismatch);
        }
        let mut connection = self.connection()?;
        let cleanup_transaction = self.transaction(&mut connection)?;

        reclaim_expired_unclaimed(
            &cleanup_transaction,
            debit.allocation_envelope_sha256(),
            debit.debit_requested_at_unix_ms(),
            None,
            attestor,
        )?;
        cleanup_transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;

        let transaction = self.transaction(&mut connection)?;

        if let Some(existing) = transaction
            .query_row(
                "SELECT d.allocation_envelope_sha256, a.allocation_id, \
                        d.debit_request_binding_sha256, d.tenant_id, d.finding_id, \
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
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
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
                        row.get::<_, String>(14)?,
                        row.get::<_, String>(15)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
        {
            let amount = parse_units(&existing.10, "debit.amount_units")?;
            let state = parse_state(&existing.12)?;
            let reserved_after = parse_units(&existing.13, "debit.reserved_after_units")?;
            let spent_after = parse_units(&existing.14, "debit.spent_after_units")?;
            let signed = parse_units(&existing.15, "signed_amount_units")?;
            if existing.0 != debit.allocation_envelope_sha256()
                || existing.1 != debit.allocation_id()
                || existing.2.as_deref() != Some(debit.debit_request_binding_sha256())
                || existing.3.as_deref() != debit.tenant_id()
                || existing.4 != debit.finding_id()
                || existing.5 != debit.listing_id()
                || existing.6 != debit.reservation_id()
                || existing.7 != debit.authoritative_payment_operation_id()
                || existing.8 != debit.accepted_bid_envelope_sha256()
                || existing.9 != debit.venue_admission_envelope_sha256()
                || amount != debit.debit_amount_units()
                || existing.11 != debit.currency()
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
                    purchase_id, tenant_id, allocation_envelope_sha256, \
                    debit_request_binding_sha256, finding_id, listing_id, \
                    reservation_id, authoritative_payment_operation_id, \
                    accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                    amount_units, currency, state, claim_deadline_unix_ms, \
                    claimed_at_unix_ms, reserved_after_units, spent_after_units\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
                           'reserved', ?13, NULL, ?14, ?15)",
                params![
                    debit.purchase_id(),
                    debit.tenant_id(),
                    debit.allocation_envelope_sha256(),
                    debit.debit_request_binding_sha256(),
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
        record_mutation_receipt(
            &transaction,
            mutation_for_purchase(
                &transaction,
                debit.purchase_id(),
                FindingPoolMutationKind::Reserve,
                debit.debit_requested_at_unix_ms(),
            )?,
            attestor,
        )?;
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

    fn claim(
        &self,
        claim: &AuthorizedFindingPoolClaim,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        let stored = transaction
            .query_row(
                "SELECT allocation_envelope_sha256, tenant_id, finding_id, listing_id, \
                        reservation_id, authoritative_payment_operation_id, \
                        accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                        amount_units, currency, state, claim_deadline_unix_ms, \
                        claimed_at_unix_ms, durable_admission_operation_id \
                 FROM finding_pool_debits WHERE purchase_id = ?1",
                [claim.purchase_id()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
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
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, Option<String>>(13)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
            .ok_or(FindingPoolLedgerError::ReservationMissing)?;
        let amount = parse_units(&stored.8, "debit.amount_units")?;
        let state = parse_state(&stored.10)?;
        let claim_deadline = parse_units(&stored.11, "debit.claim_deadline_unix_ms")?;
        if stored.1.as_deref() != claim.tenant_id()
            || stored.2 != claim.finding_id()
            || stored.3 != claim.listing_id()
            || stored.4 != claim.reservation_id()
            || stored.5 != claim.authoritative_payment_operation_id()
            || stored.6 != claim.accepted_bid_envelope_sha256()
            || stored.7 != claim.venue_admission_envelope_sha256()
            || amount != claim.amount_units()
            || stored.9 != claim.currency()
        {
            return Err(FindingPoolLedgerError::ReplayConflict);
        }
        if state != FindingPoolDebitState::Reserved {
            return Err(FindingPoolLedgerError::TerminalConflict);
        }
        if let Some(claimed_at) = stored.12 {
            parse_units(&claimed_at, "debit.claimed_at_unix_ms")?;
            if stored.13.as_deref() != Some(claim.durable_admission_operation_id()) {
                return Err(FindingPoolLedgerError::ReplayConflict);
            }
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(());
        }
        if claim.claimed_at_unix_ms() >= claim_deadline {
            reclaim_expired_unclaimed(
                &transaction,
                &stored.0,
                claim.claimed_at_unix_ms(),
                Some(claim.purchase_id()),
                attestor,
            )?;
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Err(FindingPoolLedgerError::ClaimDeadlineElapsed);
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_debits SET claimed_at_unix_ms = ?2, \
                        durable_admission_operation_id = ?3 \
                 WHERE purchase_id = ?1 AND state = 'reserved' \
                   AND claimed_at_unix_ms IS NULL \
                   AND durable_admission_operation_id IS NULL",
                params![
                    claim.purchase_id(),
                    claim.claimed_at_unix_ms().to_string(),
                    claim.durable_admission_operation_id(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("reservation claim compare-and-set failed"));
        }
        record_mutation_receipt(
            &transaction,
            mutation_for_purchase(
                &transaction,
                claim.purchase_id(),
                FindingPoolMutationKind::Claim,
                claim.claimed_at_unix_ms(),
            )?,
            attestor,
        )?;
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
    }

    fn release_claimed_before_dispatch(
        &self,
        release: &AuthorizedFindingPoolRecoveryRelease,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        let stored = transaction
            .query_row(
                "SELECT d.purchase_id, d.allocation_envelope_sha256, d.state, \
                        d.amount_units, d.reserved_after_units, d.spent_after_units, \
                        a.signed_amount_units, a.reserved_units, a.spent_units, \
                        d.claimed_at_unix_ms \
                 FROM finding_pool_debits d \
                 JOIN finding_pool_allocations a \
                   ON a.allocation_envelope_sha256 = d.allocation_envelope_sha256 \
                 WHERE d.durable_admission_operation_id = ?1",
                [release.durable_admission_operation_id()],
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
                        row.get::<_, Option<String>>(9)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let Some(stored) = stored else {
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(());
        };
        let state = parse_state(&stored.2)?;
        if state != FindingPoolDebitState::Reserved {
            if state != FindingPoolDebitState::Released {
                return Err(FindingPoolLedgerError::TerminalConflict);
            }
            transaction
                .commit()
                .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
            return Ok(());
        }
        if stored.9.is_none() {
            return Err(invariant(
                "durable admission binding identifies an unclaimed reservation",
            ));
        }
        let amount = parse_units(&stored.3, "debit.amount_units")?;
        let signed = parse_units(&stored.6, "signed_amount_units")?;
        let current_reserved = parse_units(&stored.7, "reserved_units")?;
        let current_spent = parse_units(&stored.8, "spent_units")?;
        let reserved_after = current_reserved
            .checked_sub(amount)
            .ok_or_else(|| invariant("claimed reservation exceeds allocation reserved amount"))?;
        remaining_units(signed, reserved_after, current_spent)?;
        let changed = transaction
            .execute(
                "UPDATE finding_pool_allocations SET reserved_units = ?2 \
                 WHERE allocation_envelope_sha256 = ?1 \
                   AND reserved_units = ?3 AND spent_units = ?4",
                params![
                    stored.1,
                    reserved_after.to_string(),
                    current_reserved.to_string(),
                    current_spent.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant(
                "pre-dispatch claim release allocation compare-and-set failed",
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_debits \
                 SET state = 'released', reserved_after_units = ?2, spent_after_units = ?3 \
                 WHERE purchase_id = ?1 AND state = 'reserved' \
                   AND durable_admission_operation_id = ?4",
                params![
                    stored.0,
                    reserved_after.to_string(),
                    current_spent.to_string(),
                    release.durable_admission_operation_id(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant(
                "pre-dispatch claim release compare-and-set failed",
            ));
        }
        record_mutation_receipt(
            &transaction,
            mutation_for_purchase(
                &transaction,
                &stored.0,
                FindingPoolMutationKind::Release,
                release.released_at_unix_ms(),
            )?,
            attestor,
        )?;
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
    }

    fn finalize_claimed_after_unknown_dispatch(
        &self,
        terminal: &AuthorizedFindingPoolUnknownDispatchTerminal,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        finalize_claimed_after_unknown_dispatch_by_operation(
            self,
            terminal.durable_admission_operation_id(),
            terminal.finalized_at_unix_ms(),
            attestor,
        )
    }

    fn settle(
        &self,
        terminal: &AuthorizedFindingPoolTerminal,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        let stored = transaction
            .query_row(
                "SELECT d.allocation_envelope_sha256, a.allocation_id, d.finding_id, \
                        d.listing_id, d.reservation_id, \
                        d.authoritative_payment_operation_id, d.amount_units, \
                        d.currency, d.state, d.reserved_after_units, \
                        d.spent_after_units, a.signed_amount_units, \
                        a.reserved_units, a.spent_units, \
                        d.claimed_at_unix_ms, d.durable_admission_operation_id \
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
                        row.get::<_, Option<String>>(14)?,
                        row.get::<_, Option<String>>(15)?,
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
        require_terminal_claim_binding(
            stored.14.as_deref(),
            stored.15.as_deref(),
            terminal.durable_admission_operation_id(),
        )?;
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
                 WHERE purchase_id = ?1 AND state = 'reserved' \
                   AND claimed_at_unix_ms IS NOT NULL \
                   AND durable_admission_operation_id = ?5",
                params![
                    terminal.purchase_id(),
                    state_text(target),
                    reserved_after.to_string(),
                    spent_after.to_string(),
                    terminal.durable_admission_operation_id(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("reservation terminal compare-and-set failed"));
        }
        let mutation_kind = match terminal.decision() {
            FindingPoolTerminalDecision::Finalize => FindingPoolMutationKind::Finalize,
            FindingPoolTerminalDecision::Release => FindingPoolMutationKind::Release,
        };
        record_mutation_receipt(
            &transaction,
            mutation_for_purchase(
                &transaction,
                terminal.purchase_id(),
                mutation_kind,
                terminal.occurred_at_unix_ms(),
            )?,
            attestor,
        )?;
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

    fn claim_pending_mutation_receipts(
        &self,
        claimant_id: &str,
        claimed_at_unix_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ChioReceipt>, FindingPoolLedgerError> {
        claim_pending_mutation_receipts(self, claimant_id, claimed_at_unix_ms, lease_ms, limit)
    }

    fn acknowledge_mutation_receipt(
        &self,
        receipt_id: &str,
        claimant_id: &str,
        acknowledged_at_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError> {
        acknowledge_mutation_receipt(self, receipt_id, claimant_id, acknowledged_at_unix_ms)
    }

    fn has_pending_mutation_receipts(&self) -> Result<bool, FindingPoolLedgerError> {
        has_pending_mutation_receipts(self)
    }
}

fn finalize_claimed_after_unknown_dispatch_by_operation(
    ledger: &SqliteFindingPoolLedger,
    durable_admission_operation_id: &str,
    finalized_at_unix_ms: u64,
    attestor: &FindingPoolMutationAttestor<'_>,
) -> Result<(), FindingPoolLedgerError> {
    let mut connection = ledger.connection()?;
    let transaction = ledger.transaction(&mut connection)?;
    let stored = transaction
        .query_row(
            "SELECT d.purchase_id, d.allocation_envelope_sha256, d.state, \
                    d.amount_units, d.reserved_after_units, d.spent_after_units, \
                    a.signed_amount_units, a.reserved_units, a.spent_units, \
                    d.claimed_at_unix_ms \
             FROM finding_pool_debits d \
             JOIN finding_pool_allocations a \
               ON a.allocation_envelope_sha256 = d.allocation_envelope_sha256 \
             WHERE d.durable_admission_operation_id = ?1",
            [durable_admission_operation_id],
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
                    row.get::<_, Option<String>>(9)?,
                ))
            },
        )
        .optional()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let Some(stored) = stored else {
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        return Ok(());
    };
    let state = parse_state(&stored.2)?;
    let amount = parse_units(&stored.3, "debit.amount_units")?;
    let recorded_reserved_after = parse_units(&stored.4, "debit.reserved_after_units")?;
    let recorded_spent_after = parse_units(&stored.5, "debit.spent_after_units")?;
    let signed = parse_units(&stored.6, "signed_amount_units")?;
    let claimed_at = stored.9.as_deref().ok_or_else(|| {
        invariant("outcome-unknown durable admission identifies an unclaimed reservation")
    })?;
    parse_units(claimed_at, "debit.claimed_at_unix_ms")?;
    if state != FindingPoolDebitState::Reserved {
        if state != FindingPoolDebitState::Finalized {
            return Err(FindingPoolLedgerError::TerminalConflict);
        }
        // These are the immutable post-transition counters recorded on this
        // debit. Allocation-wide counters may have advanced through unrelated
        // later debits and must not participate in exact replay.
        remaining_units(signed, recorded_reserved_after, recorded_spent_after)?;
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        return Ok(());
    }
    let current_reserved = parse_units(&stored.7, "reserved_units")?;
    let current_spent = parse_units(&stored.8, "spent_units")?;
    let reserved_after = current_reserved
        .checked_sub(amount)
        .ok_or_else(|| invariant("claimed reservation exceeds allocation reserved amount"))?;
    let spent_after = current_spent
        .checked_add(amount)
        .ok_or(FindingPoolLedgerError::AmountExceeded)?;
    remaining_units(signed, reserved_after, spent_after)?;
    let changed = transaction
        .execute(
            "UPDATE finding_pool_allocations \
             SET reserved_units = ?2, spent_units = ?3 \
             WHERE allocation_envelope_sha256 = ?1 \
               AND reserved_units = ?4 AND spent_units = ?5",
            params![
                stored.1,
                reserved_after.to_string(),
                spent_after.to_string(),
                current_reserved.to_string(),
                current_spent.to_string(),
            ],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(invariant(
            "outcome-unknown allocation finalization compare-and-set failed",
        ));
    }
    let changed = transaction
        .execute(
            "UPDATE finding_pool_debits \
             SET state = 'finalized', reserved_after_units = ?2, spent_after_units = ?3 \
             WHERE purchase_id = ?1 AND state = 'reserved' \
               AND durable_admission_operation_id = ?4",
            params![
                stored.0,
                reserved_after.to_string(),
                spent_after.to_string(),
                durable_admission_operation_id,
            ],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if changed != 1 {
        return Err(invariant(
            "outcome-unknown reservation finalization compare-and-set failed",
        ));
    }
    record_mutation_receipt(
        &transaction,
        mutation_for_purchase(
            &transaction,
            &stored.0,
            FindingPoolMutationKind::Finalize,
            finalized_at_unix_ms,
        )?,
        attestor,
    )?;
    transaction
        .commit()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
}

impl QualifiedFindingPoolLedger for SqliteFindingPoolLedger {
    fn ledger_domain(&self) -> &str {
        &self.ledger_domain
    }

    fn ledger_store_binding_sha256(&self) -> &str {
        &self.ledger_store_binding_sha256
    }

    fn advance_trusted_time_floor(
        &self,
        observed_unix_ms: u64,
    ) -> Result<u64, FindingPoolLedgerError> {
        if observed_unix_ms == 0 {
            return Err(FindingPoolLedgerError::Storage(
                "finding pool trusted time is invalid".to_owned(),
            ));
        }
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        let encoded = transaction
            .query_row(
                "SELECT trusted_time_high_water_unix_ms \
                 FROM finding_pool_ledger_metadata WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let current = parse_units(&encoded, "trusted_time_high_water_unix_ms")?;
        let trusted = current.max(observed_unix_ms);
        if trusted == current {
            return Ok(current);
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_ledger_metadata \
                 SET trusted_time_high_water_unix_ms = ?1 \
                 WHERE singleton = 1 AND trusted_time_high_water_unix_ms = ?2",
                params![trusted.to_string(), encoded],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant(
                "finding pool trusted-time compare-and-set failed",
            ));
        }
        transaction.commit()?;
        Ok(trusted)
    }

    fn bind_receipt_authority(&self, authority: &PublicKey) -> Result<(), FindingPoolLedgerError> {
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        bind_receipt_authority(&transaction, authority)?;
        transaction.commit()
    }

    fn bind_receipt_configuration(
        &self,
        authority: &PublicKey,
        receipt_sink_id: &str,
    ) -> Result<(), FindingPoolLedgerError> {
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        bind_receipt_configuration(&transaction, authority, receipt_sink_id)?;
        transaction.commit()
    }

    fn bind_receipt_sink(&self, receipt_sink_id: &str) -> Result<(), FindingPoolLedgerError> {
        validate_receipt_sink_id(receipt_sink_id)?;
        let mut connection = self.connection()?;
        let transaction = self.transaction(&mut connection)?;
        transaction
            .execute(
                "UPDATE finding_pool_ledger_metadata SET receipt_sink_id = ?1 \
                 WHERE singleton = 1 AND receipt_sink_id IS NULL",
                [receipt_sink_id],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let persisted = transaction
            .query_row(
                "SELECT receipt_sink_id FROM finding_pool_ledger_metadata WHERE singleton = 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if persisted.as_deref() != Some(receipt_sink_id) {
            return Err(FindingPoolLedgerError::ReceiptSinkMismatch);
        }
        transaction
            .commit()
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
    }
}

fn validate_ledger_domain(ledger_domain: &str) -> Result<(), FindingPoolLedgerError> {
    if ledger_domain.is_empty()
        || ledger_domain.len() > 512
        || !ledger_domain
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
        || !ledger_domain.bytes().any(|byte| byte != b' ')
    {
        Err(FindingPoolLedgerError::Storage(
            "qualified finding pool ledger domain is invalid".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn validate_receipt_sink_id(receipt_sink_id: &str) -> Result<(), FindingPoolLedgerError> {
    if receipt_sink_id.is_empty()
        || receipt_sink_id.len() > 512
        || !receipt_sink_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        Err(FindingPoolLedgerError::InvalidReceiptSink)
    } else {
        Ok(())
    }
}

fn bind_ledger_domain(
    connection: &rusqlite::Connection,
    ledger_domain: &str,
) -> Result<(), FindingPoolLedgerError> {
    connection
        .execute(
            "INSERT OR IGNORE INTO finding_pool_ledger_metadata (singleton, ledger_domain) \
             VALUES (1, ?1)",
            [ledger_domain],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let persisted = connection
        .query_row(
            "SELECT ledger_domain FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if persisted != ledger_domain {
        return Err(FindingPoolLedgerError::LedgerDomainMismatch);
    }
    Ok(())
}

fn mutation_for_purchase(
    transaction: &rusqlite::Transaction<'_>,
    purchase_id: &str,
    kind: FindingPoolMutationKind,
    occurred_at_unix_ms: u64,
) -> Result<FindingPoolMutation, FindingPoolLedgerError> {
    let stored = transaction
        .query_row(
            "SELECT d.purchase_id, d.tenant_id, a.allocation_id, \
                    d.allocation_envelope_sha256, d.amount_units, d.currency, d.state, a.reserved_units, \
                    a.spent_units, a.signed_amount_units, \
                    d.durable_admission_operation_id \
             FROM finding_pool_debits d \
             JOIN finding_pool_allocations a \
               ON a.allocation_envelope_sha256 = d.allocation_envelope_sha256 \
             WHERE d.purchase_id = ?1",
            [purchase_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, Option<String>>(10)?,
                ))
            },
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let amount = parse_units(&stored.4, "debit.amount_units")?;
    let reserved = parse_units(&stored.7, "reserved_units")?;
    let spent = parse_units(&stored.8, "spent_units")?;
    let signed = parse_units(&stored.9, "signed_amount_units")?;
    Ok(FindingPoolMutation {
        schema: FINDING_POOL_MUTATION_SCHEMA_V1.to_string(),
        kind,
        purchase_id: stored.0,
        tenant_id: stored.1,
        allocation_id: stored.2,
        allocation_envelope_sha256: stored.3,
        amount_units: amount.to_string(),
        currency: stored.5,
        state: parse_state(&stored.6)?,
        reserved_after_units: reserved.to_string(),
        spent_after_units: spent.to_string(),
        remaining_after_units: remaining_units(signed, reserved, spent)?.to_string(),
        occurred_at_unix_ms: occurred_at_unix_ms.to_string(),
        durable_admission_operation_id: stored.10,
    })
}

fn record_mutation_receipt(
    transaction: &rusqlite::Transaction<'_>,
    mutation: FindingPoolMutation,
    attestor: &FindingPoolMutationAttestor<'_>,
) -> Result<(), FindingPoolLedgerError> {
    let receipt = attestor(&mutation)?;
    let expected_parameters = serde_json::to_value(&mutation)
        .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
    let expected_content = chio_core::canonical::canonical_json_bytes(&mutation)
        .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
    let expected_content_hash = chio_core::crypto::sha256_hex(&expected_content);
    let signature_valid = receipt
        .verify_signature()
        .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
    if !signature_valid
        || receipt.capability_id != mutation.allocation_envelope_sha256
        || receipt.tenant_id.as_deref() != mutation.tenant_id.as_deref()
        || receipt.tool_server != "chio-kernel"
        || receipt.tool_name != "finding_pool_mutation"
        || receipt.decision != Some(chio_core::receipt::decision::Decision::Allow)
        || receipt.action.parameters != expected_parameters
        || receipt.content_hash != expected_content_hash
        || receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("finding_pool_mutation"))
            != Some(&expected_parameters)
    {
        return Err(FindingPoolLedgerError::Receipt(
            "signed mutation receipt does not bind the committed transition".to_string(),
        ));
    }
    let persisted_authority_json = transaction
        .query_row(
            "SELECT receipt_authority_json FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
        .ok_or(FindingPoolLedgerError::ReceiptAuthorityMissing)?;
    let expected_authority_json = canonical_receipt_authority_json(&receipt.kernel_key)?;
    if persisted_authority_json != expected_authority_json {
        return Err(FindingPoolLedgerError::ReceiptAuthorityMismatch);
    }
    let receipt_json = String::from_utf8(
        chio_core::canonical::canonical_json_bytes(&receipt)
            .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?,
    )
    .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
    let last_delivery_sequence = transaction
        .query_row(
            "SELECT MAX(delivery_sequence) FROM finding_pool_receipt_outbox",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
        .unwrap_or(0);
    let delivery_sequence = last_delivery_sequence
        .checked_add(1)
        .ok_or_else(|| invariant("mutation receipt delivery sequence overflowed"))?;
    transaction
        .execute(
            "INSERT INTO finding_pool_receipt_outbox (\
                receipt_id, purchase_id, allocation_envelope_sha256, mutation_kind, \
                signed_receipt_json, occurred_at_unix_ms, acknowledged_at_unix_ms, \
                delivery_sequence\
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7)",
            params![
                receipt.id,
                mutation.purchase_id,
                mutation.allocation_envelope_sha256,
                mutation_kind_text(mutation.kind),
                receipt_json,
                mutation.occurred_at_unix_ms,
                delivery_sequence,
            ],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    Ok(())
}

const fn mutation_kind_text(kind: FindingPoolMutationKind) -> &'static str {
    match kind {
        FindingPoolMutationKind::Reserve => "reserve",
        FindingPoolMutationKind::Claim => "claim",
        FindingPoolMutationKind::Finalize => "finalize",
        FindingPoolMutationKind::Release => "release",
        FindingPoolMutationKind::ExpiredRelease => "expired_release",
    }
}

fn reclaim_expired_unclaimed(
    transaction: &rusqlite::Transaction<'_>,
    allocation_envelope_sha256: &str,
    trusted_now_unix_ms: u64,
    required_purchase_id: Option<&str>,
    attestor: &FindingPoolMutationAttestor<'_>,
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
    let expired = expired_unclaimed_reservations(
        transaction,
        allocation_envelope_sha256,
        trusted_now_unix_ms,
        required_purchase_id,
    )?;
    if expired.is_empty() {
        return Ok(());
    }
    let mut current_reserved = original_reserved;
    for (purchase_id, amount) in expired {
        let reserved_after = current_reserved
            .checked_sub(amount)
            .ok_or_else(|| invariant("expired reservation exceeds allocation reserve"))?;
        remaining_units(signed, reserved_after, spent)?;
        let changed = transaction
            .execute(
                "UPDATE finding_pool_allocations SET reserved_units = ?2 \
                 WHERE allocation_envelope_sha256 = ?1 AND reserved_units = ?3 \
                   AND spent_units = ?4",
                params![
                    allocation_envelope_sha256,
                    reserved_after.to_string(),
                    current_reserved.to_string(),
                    spent.to_string(),
                ],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant(
                "expired reservation allocation compare-and-set failed",
            ));
        }
        let changed = transaction
            .execute(
                "UPDATE finding_pool_debits \
                 SET state = 'released', reserved_after_units = ?2, spent_after_units = ?3 \
                 WHERE purchase_id = ?1 AND state = 'reserved' \
                   AND claimed_at_unix_ms IS NULL",
                params![purchase_id, reserved_after.to_string(), spent.to_string(),],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(invariant("expired reservation compare-and-set failed"));
        }
        record_mutation_receipt(
            transaction,
            mutation_for_purchase(
                transaction,
                &purchase_id,
                FindingPoolMutationKind::ExpiredRelease,
                trusted_now_unix_ms,
            )?,
            attestor,
        )?;
        current_reserved = reserved_after;
    }
    Ok(())
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

fn require_terminal_claim_binding(
    claimed_at_unix_ms: Option<&str>,
    durable_admission_operation_id: Option<&str>,
    expected_operation_id: &str,
) -> Result<(), FindingPoolLedgerError> {
    let claimed_at_unix_ms = claimed_at_unix_ms.ok_or(FindingPoolLedgerError::TerminalConflict)?;
    parse_units(claimed_at_unix_ms, "debit.claimed_at_unix_ms")?;
    if durable_admission_operation_id != Some(expected_operation_id) {
        return Err(FindingPoolLedgerError::TerminalConflict);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core::crypto::{Ed25519Backend, Keypair};
    use chio_test_support::prelude::*;

    fn rollback_anchor_root() -> &'static Path {
        static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        ROOT.get_or_init(|| {
            let root = Path::new("/dev/shm").join(format!(
                "chio-finding-pool-unit-anchors-{}",
                std::process::id()
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                builder.mode(0o700);
            }
            if let Err(error) = builder.create(&root) {
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    panic!("create test rollback anchor root: {error}");
                }
            }
            root
        })
    }

    #[cfg(unix)]
    #[test]
    fn qualified_open_rejects_anchor_on_the_database_snapshot_device() {
        use std::os::unix::fs::PermissionsExt as _;

        let identity = Ed25519Backend::new(Keypair::from_seed(&[71_u8; 32]));
        for (suffix, use_database_root) in [("same-directory", true), ("same-device", false)] {
            let database_root = tempfile::tempdir().test_expect("create database root");
            let anchor_root = tempfile::tempdir().test_expect("create sibling anchor root");
            for root in [database_root.path(), anchor_root.path()] {
                std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
                    .test_expect("secure qualification test root");
            }
            let selected_anchor = if use_database_root {
                database_root.path()
            } else {
                anchor_root.path()
            };
            let error = SqliteFindingPoolLedger::open_qualified(
                database_root.path().join("pool.sqlite3"),
                format!("ledger:test-snapshot-domain:{suffix}"),
                &identity,
                selected_anchor,
            )
            .err()
            .test_expect("co-located rollback anchor must fail qualification");
            assert!(matches!(
                error,
                FindingPoolLedgerError::Storage(message)
                    if message.contains("shares the protected database snapshot domain")
            ));
        }
    }

    fn open_qualified(
        path: impl AsRef<Path>,
        ledger_domain: impl Into<String>,
    ) -> Result<SqliteFindingPoolLedger, FindingPoolLedgerError> {
        let path = path.as_ref();
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .test_expect("secure pool ledger parent");
        }
        let identity = Ed25519Backend::new(Keypair::from_seed(&[70_u8; 32]));
        SqliteFindingPoolLedger::open_qualified(
            path,
            ledger_domain,
            &identity,
            rollback_anchor_root(),
        )
    }

    #[test]
    fn qualified_schema_indexes_pending_outbox_and_expiration_reclamation() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let ledger = open_qualified(directory.path().join("pool.sqlite3"), "ledger:test-indexes")
            .test_expect("open qualified pool ledger");
        let connection = ledger.pool.get().test_expect("open pool ledger connection");
        for index in [
            "finding_pool_receipt_outbox_pending",
            "finding_pool_receipt_outbox_delivery_sequence",
            "finding_pool_debits_expiration_reclamation",
            "finding_pool_debits_expiration_reclamation_v2",
        ] {
            let present = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = ?1)",
                    [index],
                    |row| row.get::<_, bool>(0),
                )
                .test_expect("query qualified index");
            assert!(present, "qualified schema is missing {index}");
        }
        let mut plan = connection
            .prepare(
                "EXPLAIN QUERY PLAN \
                 SELECT receipt_id, signed_receipt_json \
                 FROM finding_pool_receipt_outbox \
                 WHERE acknowledged_at_unix_ms IS NULL \
                   AND (delivery_claim_epoch IS NULL \
                        OR delivery_claim_epoch < ?1 \
                        OR (delivery_claim_epoch = ?1 \
                            AND (delivery_claim_expires_at_unix_ms IS NULL \
                                 OR delivery_claim_expires_at_unix_ms <= ?2))) \
                 ORDER BY delivery_sequence LIMIT ?3",
            )
            .test_expect("prepare pending outbox query plan");
        let details = plan
            .query_map(params![1_i64, 1_i64, 1_i64], |row| row.get::<_, String>(3))
            .test_expect("query pending outbox plan")
            .collect::<Result<Vec<_>, _>>()
            .test_expect("collect pending outbox plan");
        assert!(details
            .iter()
            .all(|detail| !detail.contains("USE TEMP B-TREE")));
        assert!(details
            .iter()
            .any(|detail| detail.contains("finding_pool_receipt_outbox_pending")));
    }

    #[cfg(unix)]
    #[test]
    fn qualified_ledger_binds_validation_to_the_borrowed_database_file() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let database = directory.path().join("pool.sqlite3");
        let replacement = directory.path().join("replacement.sqlite3");
        let ledger = open_qualified(&database, "ledger:test-borrowed-file")
            .test_expect("open qualified pool ledger");
        {
            let connection = ledger.pool.get().test_expect("borrow qualified database");
            connection
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                .test_expect("checkpoint qualified database");
        }
        std::fs::copy(&database, &replacement).test_expect("copy qualified database");
        let borrowed_replacement =
            rusqlite::Connection::open(&replacement).test_expect("open replacement database");

        let error = ledger
            .database_identity
            .validate_connection(&borrowed_replacement)
            .test_expect_err("different borrowed database file must reject");
        assert!(error.to_string().contains("borrowed file identity changed"));
    }

    #[test]
    fn outbox_lease_clock_does_not_regress_with_wall_time() {
        let clock = OutboxLeaseClock::new(1);
        assert_eq!(
            clock
                .nondecreasing_now(10_000)
                .test_expect("initialize lease clock"),
            10_000
        );
        std::thread::sleep(Duration::from_millis(3));
        assert!(
            clock
                .nondecreasing_now(1)
                .test_expect("advance lease clock across rollback")
                > 10_000
        );
    }

    #[test]
    fn leased_outbox_rows_remain_observable_as_pending() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let ledger = open_qualified(
            directory.path().join("pool.sqlite3"),
            "ledger:test-active-outbox-lease",
        )
        .test_expect("open qualified pool ledger");
        let connection = ledger.pool.get().test_expect("open pool ledger connection");
        connection
            .execute(
                "INSERT INTO finding_pool_receipt_outbox (\
                    receipt_id, purchase_id, allocation_envelope_sha256, mutation_kind, \
                    signed_receipt_json, occurred_at_unix_ms, acknowledged_at_unix_ms, \
                    delivery_claim_owner, delivery_claim_expires_at_unix_ms, \
                    delivery_claim_epoch, delivery_sequence\
                 ) VALUES ('receipt:leased', 'purchase:leased', ?1, 'reserve', '{}', '1', \
                           NULL, 'worker:crashed', 100000, ?2, 1)",
                params![
                    "a".repeat(64),
                    i64::try_from(ledger.outbox_lease_clock.epoch)
                        .test_expect("lease epoch fits SQLite")
                ],
            )
            .test_expect("seed leased outbox row");
        drop(connection);

        assert!(ledger
            .claim_pending_mutation_receipts("worker:replacement", 1, 60_000, 1)
            .test_expect("active lease produces no duplicate claim")
            .is_empty());
        assert!(ledger
            .has_pending_mutation_receipts()
            .test_expect("pending outbox state remains visible"));
    }

    #[test]
    fn qualified_ledger_rejects_unusable_domains() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        for (suffix, domain) in [("unicode", "ledger:é"), ("spaces", "   ")] {
            assert!(
                open_qualified(directory.path().join(format!("{suffix}.sqlite3")), domain,)
                    .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn qualified_ledger_rejects_a_writable_parent_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777))
            .test_expect("make pool ledger parent unsafe");
        let identity = Ed25519Backend::new(Keypair::from_seed(&[70_u8; 32]));
        let error = SqliteFindingPoolLedger::open_qualified(
            directory.path().join("pool.sqlite3"),
            "ledger:test-unsafe-parent",
            &identity,
            rollback_anchor_root(),
        )
        .test_expect_err("writable parent must not qualify");
        assert!(error.to_string().contains("parent has unsafe ownership"));
    }

    #[test]
    fn qualified_ledger_persists_one_receipt_sink() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let path = directory.path().join("pool.sqlite3");
        let ledger =
            open_qualified(&path, "ledger:test-sink").test_expect("open qualified pool ledger");
        ledger
            .bind_receipt_sink("receipt-sink:first")
            .test_expect("bind first receipt sink");
        ledger
            .bind_receipt_sink("receipt-sink:first")
            .test_expect("replay first receipt sink binding");
        assert_eq!(
            ledger.bind_receipt_sink("receipt-sink:second"),
            Err(FindingPoolLedgerError::ReceiptSinkMismatch)
        );

        let reopened =
            open_qualified(&path, "ledger:test-sink").test_expect("reopen qualified pool ledger");
        reopened
            .bind_receipt_sink("receipt-sink:first")
            .test_expect("reopen with bound receipt sink");
    }

    #[test]
    fn claimed_admission_operation_scan_is_bounded_and_cursor_ordered() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let ledger = open_qualified(
            directory.path().join("pool.sqlite3"),
            "ledger:test-internal-scan",
        )
        .test_expect("open qualified pool ledger");
        let allocation_digest = "d".repeat(64);
        let first_operation = "a".repeat(64);
        let second_operation = "c".repeat(64);
        let terminal_operation = "e".repeat(64);
        {
            let connection = ledger.pool.get().test_expect("open pool ledger connection");
            connection
                .execute(
                    "INSERT INTO finding_pool_allocations (\
                        allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                        purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                        reserved_units, spent_units, expires_at_unix_ms\
                     ) VALUES (?1, 'allocation:scan', 'pool:scan', ?2, 'buyer:scan', '{}', \
                               'USD', '100', '20', '0', '100000')",
                    params![allocation_digest, "f".repeat(64)],
                )
                .test_expect("seed scan allocation");
            for (purchase_id, state, claimed_at, operation_id) in [
                (
                    "purchase:first",
                    "reserved",
                    Some("1000"),
                    Some(first_operation.as_str()),
                ),
                (
                    "purchase:second",
                    "reserved",
                    Some("1001"),
                    Some(second_operation.as_str()),
                ),
                ("purchase:unclaimed", "reserved", None, None),
                (
                    "purchase:terminal",
                    "released",
                    Some("1002"),
                    Some(terminal_operation.as_str()),
                ),
            ] {
                connection
                    .execute(
                        "INSERT INTO finding_pool_debits (\
                            purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                            reservation_id, authoritative_payment_operation_id, \
                            accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                            amount_units, currency, state, claim_deadline_unix_ms, \
                            claimed_at_unix_ms, durable_admission_operation_id, \
                            reserved_after_units, spent_after_units\
                         ) VALUES (?1, ?2, ?3, 'listing:scan', ?4, ?5, ?6, ?7, \
                                   '5', 'USD', ?8, '30000', ?9, ?10, '20', '0')",
                        params![
                            purchase_id,
                            allocation_digest,
                            "1".repeat(64),
                            format!("reservation:{purchase_id}"),
                            format!("payment:{purchase_id}"),
                            "2".repeat(64),
                            "3".repeat(64),
                            state,
                            claimed_at,
                            operation_id,
                        ],
                    )
                    .test_expect("seed claimed-operation scan row");
            }
        }

        assert_eq!(
            ledger
                .list_claimed_admission_operations(None, 1)
                .test_expect("read first claimed-operation page"),
            vec![first_operation.clone()]
        );
        assert_eq!(
            ledger
                .list_claimed_admission_operations(Some(&first_operation), 1)
                .test_expect("read second claimed-operation page"),
            vec![second_operation.clone()]
        );
        assert!(ledger
            .list_claimed_admission_operations(Some(&second_operation), 1)
            .test_expect("read terminal claimed-operation page")
            .is_empty());
    }

    #[test]
    fn settlement_requires_claim_bound_to_same_admission_operation() {
        assert_eq!(
            require_terminal_claim_binding(None, None, "operation:completed"),
            Err(FindingPoolLedgerError::TerminalConflict)
        );
        assert_eq!(
            require_terminal_claim_binding(
                Some("1000"),
                Some("operation:other"),
                "operation:completed",
            ),
            Err(FindingPoolLedgerError::TerminalConflict)
        );
        assert_eq!(
            require_terminal_claim_binding(
                Some("1000"),
                Some("operation:completed"),
                "operation:completed",
            ),
            Ok(())
        );
    }

    #[test]
    fn recovered_mutation_loads_the_reservations_persisted_tenant() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let ledger = open_qualified(
            directory.path().join("pool.sqlite3"),
            "ledger:test-tenant-recovery",
        )
        .test_expect("open qualified pool ledger");
        let allocation_digest = "a".repeat(64);
        let mut connection = ledger.pool.get().test_expect("open pool ledger connection");
        connection
            .execute(
                "INSERT INTO finding_pool_allocations (\
                    allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                    purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                    reserved_units, spent_units, expires_at_unix_ms\
                 ) VALUES (?1, 'allocation:tenant', 'pool:tenant', ?2, 'buyer:tenant', '{}', \
                           'USD', '100', '25', '0', '100000')",
                params![allocation_digest, "b".repeat(64)],
            )
            .test_expect("seed tenant allocation");
        connection
            .execute(
                "INSERT INTO finding_pool_debits (\
                    purchase_id, tenant_id, allocation_envelope_sha256, finding_id, listing_id, \
                    reservation_id, authoritative_payment_operation_id, \
                    accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                    amount_units, currency, state, claim_deadline_unix_ms, \
                    claimed_at_unix_ms, durable_admission_operation_id, \
                    reserved_after_units, spent_after_units\
                 ) VALUES ('purchase:tenant', 'tenant-recovery', ?1, ?2, 'listing:tenant', \
                           'reservation:tenant', 'payment:tenant', ?3, ?4, '25', 'USD', \
                           'reserved', '30000', '2000', 'operation:tenant', '25', '0')",
                params![
                    allocation_digest,
                    "c".repeat(64),
                    "d".repeat(64),
                    "e".repeat(64),
                ],
            )
            .test_expect("seed tenant reservation");
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .test_expect("start tenant recovery transaction");
        let mutation = mutation_for_purchase(
            &transaction,
            "purchase:tenant",
            FindingPoolMutationKind::Release,
            3_000,
        )
        .test_expect("build recovered tenant mutation");

        assert_eq!(mutation.tenant_id.as_deref(), Some("tenant-recovery"));
    }

    #[test]
    fn unknown_dispatch_exact_replay_ignores_later_allocation_totals() {
        let directory = tempfile::tempdir().test_expect("create pool ledger directory");
        let ledger = open_qualified(
            directory.path().join("pool.sqlite3"),
            "ledger:test-internal-unknown-dispatch",
        )
        .test_expect("open qualified pool ledger");
        let allocation_digest = "a".repeat(64);
        let operation_id = "operation:unknown-dispatch";
        {
            let connection = ledger.pool.get().test_expect("open pool ledger connection");
            connection
                .execute(
                    "INSERT INTO finding_pool_allocations (\
                        allocation_envelope_sha256, allocation_id, pool_id, pool_sha256, \
                        purchaser_id, purchaser_key_json, currency, signed_amount_units, \
                        reserved_units, spent_units, expires_at_unix_ms\
                     ) VALUES (?1, 'allocation:test', 'pool:test', ?2, 'buyer:test', '{}', \
                               'USD', '100', '20', '10', '100000')",
                    params![allocation_digest, "b".repeat(64)],
                )
                .test_expect("seed allocation with later counters");
            connection
                .execute(
                    "INSERT INTO finding_pool_debits (\
                        purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                        reservation_id, authoritative_payment_operation_id, \
                        accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                        amount_units, currency, state, claim_deadline_unix_ms, \
                        claimed_at_unix_ms, durable_admission_operation_id, \
                        reserved_after_units, spent_after_units\
                     ) VALUES ('purchase:finalized', ?1, ?2, 'listing:test', \
                               'reservation:finalized', 'payment:finalized', ?3, ?4, \
                               '10', 'USD', 'finalized', '30000', '2000', ?5, '0', '10')",
                    params![
                        allocation_digest,
                        "c".repeat(64),
                        "d".repeat(64),
                        "e".repeat(64),
                        operation_id,
                    ],
                )
                .test_expect("seed finalized unknown-dispatch debit");
            connection
                .execute(
                    "INSERT INTO finding_pool_debits (\
                        purchase_id, allocation_envelope_sha256, finding_id, listing_id, \
                        reservation_id, authoritative_payment_operation_id, \
                        accepted_bid_envelope_sha256, venue_admission_envelope_sha256, \
                        amount_units, currency, state, claim_deadline_unix_ms, \
                        claimed_at_unix_ms, durable_admission_operation_id, \
                        reserved_after_units, spent_after_units\
                     ) VALUES ('purchase:later', ?1, ?2, 'listing:test', \
                               'reservation:later', 'payment:later', ?3, ?4, \
                               '20', 'USD', 'reserved', '40000', NULL, NULL, '20', '10')",
                    params![
                        allocation_digest,
                        "f".repeat(64),
                        "1".repeat(64),
                        "2".repeat(64),
                    ],
                )
                .test_expect("seed later reservation that advanced allocation totals");
        }

        let attestor = |_mutation: &FindingPoolMutation| {
            Err(FindingPoolLedgerError::Receipt(
                "exact replay must not attest another mutation".to_owned(),
            ))
        };
        finalize_claimed_after_unknown_dispatch_by_operation(
            &ledger,
            operation_id,
            3_000,
            &attestor,
        )
        .test_expect("exact finalized replay ignores mutable allocation counters");

        assert_eq!(
            ledger
                .reserved_units(&allocation_digest)
                .test_expect("read retained reservations"),
            Some(20)
        );
        assert_eq!(
            ledger
                .spent_units(&allocation_digest)
                .test_expect("read retained spend"),
            Some(10)
        );
    }
}
