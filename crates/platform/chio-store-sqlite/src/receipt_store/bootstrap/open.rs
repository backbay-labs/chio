use super::*;

/// Tables that identify a database this receipt store may open, all of them the
/// store's own: `chio_tool_receipts` is the current anchor (also the table the
/// store shipped before schema stamping existed) and `http_receipts` /
/// `tool_receipts` are legacy names it may still encounter on disk. A populated
/// database carrying none of these is refused rather than adopted, so a path
/// mistargeted at another store's file (an approval, revocation, budget, or
/// authority database) never has receipt tables written into it.
///
/// `chio api protect` co-locates the receipt and approval stores in one SQLite
/// file and opens the receipt store first, so this store owns the shared file's
/// provenance anchor. The approval store, opened second, adopts the
/// receipt-anchored file through its own co-located open; the receipt store never
/// needs to recognize a neighbor's table to bootstrap the shared file, so a
/// standalone approval database is refused here.
const RECEIPT_STORE_LEGACY_ANCHOR_TABLES: &[&str] =
    &["chio_tool_receipts", "http_receipts", "tool_receipts"];

/// The subset of legacy anchors whose names are generic enough that an unrelated
/// SQLite database could carry them by coincidence. Adopting an unstamped
/// database on one of these names alone would let a mistargeted path capture a
/// foreign file, so each must also carry a receipt payload column before it is
/// accepted. The Chio-specific `chio_tool_receipts` anchor needs no such check.
const RECEIPT_STORE_GENERIC_LEGACY_ANCHOR_TABLES: &[&str] = &["http_receipts", "tool_receipts"];

fn configure_sqlite_connection(
    connection: &mut Connection,
    max_page_count: Option<u32>,
) -> Result<(), ReceiptStoreError> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = FULL;
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = ON;
        PRAGMA auto_vacuum = INCREMENTAL;
        "#,
    )?;
    assert_sqlite_durability_pragmas(connection)?;
    // Operational growth bound (see `SqlitePoolConfig::max_page_count`): cap the
    // logical page count of the MAIN database file. A write that would push the
    // main file past the cap fails closed with SQLITE_FULL. This bounds the main
    // file only, not the `-wal` sidecar, so it is not a whole-volume exhaustion
    // guard: under checkpoint starvation the WAL can still grow unbounded. `None`
    // leaves SQLite's built-in page ceiling untouched.
    if let Some(max_page_count) = max_page_count {
        connection.pragma_update(None, "max_page_count", max_page_count)?;
        // Verify the cap took effect. SQLite silently ignores a max_page_count of 0
        // (leaving the default multi-gigabyte ceiling) and raises the effective
        // limit to the current database size when the requested cap sits below it,
        // so a caller could otherwise believe a fail-closed growth ceiling is
        // installed while the file is effectively uncapped or already over the
        // ceiling. Read the effective limit back and deny when it is not exactly
        // the requested cap.
        let effective: i64 = connection.query_row("PRAGMA max_page_count", [], |row| row.get(0))?;
        if effective != i64::from(max_page_count) {
            return Err(ReceiptStoreError::Conflict(format!(
                "sqlite max_page_count requested {max_page_count} but effective limit is {effective}"
            )));
        }
    }
    Ok(())
}

fn assert_sqlite_durability_pragmas(connection: &Connection) -> Result<(), ReceiptStoreError> {
    let journal_mode: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store journal_mode must be WAL, got {journal_mode}"
        )));
    }

    let synchronous: i64 = connection.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    if synchronous != 2 {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store synchronous must be FULL, got {synchronous}"
        )));
    }

    let busy_timeout: i64 = connection.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if busy_timeout < 5000 {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store busy_timeout must be at least 5000ms, got {busy_timeout}"
        )));
    }

    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(ReceiptStoreError::Conflict(format!(
            "sqlite receipt store foreign_keys must be ON, got {foreign_keys}"
        )));
    }

    Ok(())
}

fn settlement_store_binding_if_ready(
    connection: &Connection,
) -> Result<Option<chio_settle::SettlementStoreBinding>, ReceiptStoreError> {
    if !settlement_projection_schema_is_installed(connection)? {
        return Ok(None);
    }
    let mut digest = [0u8; 32];
    OsRng.try_fill_bytes(&mut digest).map_err(|error| {
        ReceiptStoreError::Io(std::io::Error::other(format!(
            "failed to generate settlement store binding: {error}"
        )))
    })?;
    Ok(Some(chio_settle::SettlementStoreBinding::from_digest(
        digest,
    )))
}

fn ensure_receipt_sink_identity(connection: &Connection) -> Result<String, ReceiptStoreError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS chio_receipt_sink_identity (\
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1), \
             sink_id TEXT NOT NULL UNIQUE\
         ) STRICT;",
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO chio_receipt_sink_identity (singleton, sink_id) VALUES (1, ?1)",
        [uuid::Uuid::now_v7().to_string()],
    )?;
    load_receipt_sink_identity(connection)
}

fn load_receipt_sink_identity(connection: &Connection) -> Result<String, ReceiptStoreError> {
    let sink_id = connection
        .query_row(
            "SELECT sink_id FROM chio_receipt_sink_identity WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "receipt database has no durable sink identity: {error}"
            ))
        })?;
    let parsed = uuid::Uuid::parse_str(&sink_id).map_err(|_| {
        ReceiptStoreError::Conflict("receipt database sink identity is invalid".to_owned())
    })?;
    if parsed.to_string() != sink_id {
        return Err(ReceiptStoreError::Conflict(
            "receipt database sink identity is not canonical".to_owned(),
        ));
    }
    Ok(sink_id)
}

fn settlement_projection_schema_is_installed(
    connection: &Connection,
) -> Result<bool, ReceiptStoreError> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch(crate::dead_letters::SETTLE_DEAD_LETTERS_MIGRATION)?;
    reference.execute_batch(crate::settle_attempts::SETTLE_ATTEMPTS_MIGRATION)?;
    Ok(settlement_schema_manifest(connection)? == settlement_schema_manifest(&reference)?)
}

#[derive(Debug, PartialEq, Eq)]
struct SettlementSchemaObject {
    object_type: String,
    name: String,
    table_name: String,
    sql: String,
}

fn settlement_schema_manifest(
    connection: &Connection,
) -> Result<Vec<SettlementSchemaObject>, ReceiptStoreError> {
    let mut statement = connection.prepare(
        "SELECT type, name, tbl_name, sql FROM sqlite_master \
         WHERE name IN (\
             'settle_attempts', \
             'idx_settle_attempts_visible', \
             'settle_dead_letters', \
             'idx_settle_dead_letters_finalized_at', \
             'trg_settle_attempts_reject_terminal_insert', \
             'trg_settle_dead_letters_reject_attempt_insert'\
         ) OR (\
             type = 'trigger' AND \
             tbl_name IN ('settle_attempts', 'settle_dead_letters')\
         ) ORDER BY type ASC, name ASC",
    )?;
    let manifest = statement
        .query_map([], |row| {
            Ok(SettlementSchemaObject {
                object_type: row.get(0)?,
                name: row.get(1)?,
                table_name: row.get(2)?,
                sql: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(ReceiptStoreError::from)?;
    Ok(manifest)
}

impl SqliteReceiptStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config(path, crate::SqlitePoolConfig::default())
    }

    /// Wait until the commit actor has seeded its durable head before a host
    /// advertises readiness. The flush barrier is processed only after actor
    /// initialization, and the serving check preserves a poisoned-head failure.
    pub fn wait_for_writer_ready(&self, timeout: Duration) -> Result<(), ReceiptStoreError> {
        self.receipt_commit_actor.flush_with_timeout(timeout)?;
        if !self.writer_serving_closed() {
            return Ok(());
        }
        let detail = self
            .receipt_commit_actor
            .writer_counters()
            .last_error
            .unwrap_or_else(|| "durable receipt head is unavailable".to_string());
        Err(ReceiptStoreError::Conflict(format!(
            "receipt commit writer failed startup readiness: {detail}"
        )))
    }

    pub fn open_existing(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        Self::open_existing_with_pool_config(path, crate::SqlitePoolConfig::default())
    }

    pub fn open_with_pool_config(
        path: impl AsRef<Path>,
        pool_config: crate::SqlitePoolConfig,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_options(
            path,
            crate::SqliteStoreOptions {
                pool: pool_config,
                ..crate::SqliteStoreOptions::default()
            },
        )
    }

    fn open_existing_with_pool_config(
        path: impl AsRef<Path>,
        pool_config: crate::SqlitePoolConfig,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_existing_with_options(
            path,
            crate::SqliteStoreOptions {
                pool: pool_config,
                ..crate::SqliteStoreOptions::default()
            },
        )
    }

    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: crate::SqliteStoreOptions,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config_and_flags(path, options, true)
    }

    pub fn open_existing_with_options(
        path: impl AsRef<Path>,
        options: crate::SqliteStoreOptions,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config_and_flags(path, options, false)
    }

    fn open_with_pool_config_and_flags(
        path: impl AsRef<Path>,
        options: crate::SqliteStoreOptions,
        create_if_missing: bool,
    ) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        let connection_flags = if create_if_missing {
            None
        } else {
            Some(existing_database_open_flags())
        };

        if create_if_missing {
            // Resolve `file:` URIs to their on-disk path before deriving the
            // parent: a raw `parent()` on `file:/dir/db?mode=rwc` folds the
            // scheme and query into a bogus directory and skips the real one.
            if let Some(parent) = crate::sqlite_parent_dir_to_create(path) {
                fs::create_dir_all(&parent)?;
            }
        }

        let mut connection = match connection_flags {
            Some(flags) => Connection::open_with_flags(path, flags).map_err(|error| {
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::CannotOpen) {
                    ReceiptStoreError::NotFound(format!(
                        "receipt database {} does not exist",
                        path.display()
                    ))
                } else {
                    ReceiptStoreError::Sqlite(error)
                }
            })?,
            None => Connection::open(path)?,
        };
        if !create_if_missing {
            require_existing_receipt_schema(path, &connection)?;
            // Validate provenance before configuring pragmas: a foreign or
            // future database must be refused before any write touches its
            // header, so a mistargeted path is never mutated into WAL mode.
            let on_disk_schema_version = crate::check_schema_version(
                &connection,
                RECEIPT_STORE_SCHEMA_KEY,
                RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
                RECEIPT_STORE_LEGACY_ANCHOR_TABLES,
            )
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
            if on_disk_schema_version < RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION {
                return Err(ReceiptStoreError::Conflict(format!(
                    "receipt database schema version {on_disk_schema_version} requires writable migration to version {RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION}; reopen it with SqliteReceiptStore::open"
                )));
            }
            configure_sqlite_connection(&mut connection, options.pool.max_page_count)?;
            super::support::ensure_transparency_projection_guards(&connection)?;
            verify_receipt_cost_projection(&connection)?;
            let durable_sink_id = load_receipt_sink_identity(&connection)?;
            let settlement_store_binding = settlement_store_binding_if_ready(&connection)?;
            drop(connection);

            let reader_pool = build_receipt_pool(
                path,
                options.pool.reader_pool_max_size,
                "reader",
                connection_flags,
                options.pool.max_page_count,
            )?;
            let writer_pool = build_receipt_pool(
                path,
                options.pool.writer_pool_max_size,
                "writer",
                connection_flags,
                options.pool.max_page_count,
            )?;

            return Ok(Self {
                receipt_commit_actor: ReceiptCommitActor::start(
                    writer_pool,
                    options.incremental_verification,
                ),
                pool: reader_pool,
                settlement_store_binding,
                durable_sink_id,
                strict_tenant_isolation: std::sync::atomic::AtomicBool::new(true),
                incremental_verification: options.incremental_verification,
            });
        }

        // Validate provenance before configuring pragmas: an existing file that
        // is a foreign database must be refused before any write touches its
        // header, so a mistargeted path is never mutated into WAL mode. The
        // schema-version check adopts an unstamped database on a legacy anchor
        // name alone, so first reject one whose generic anchor lacks the receipt
        // shape, keeping a foreign file that merely reuses the name out.
        reject_foreign_legacy_receipt_anchor(&connection)?;
        let on_disk_schema_version = crate::check_schema_version(
            &connection,
            RECEIPT_STORE_SCHEMA_KEY,
            RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
            RECEIPT_STORE_LEGACY_ANCHOR_TABLES,
        )
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        configure_sqlite_connection(&mut connection, options.pool.max_page_count)?;
        let schema_migration =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        schema_migration.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                grant_index INTEGER,
                tool_server TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                decision_kind TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                cost_currency TEXT CHECK (
                    cost_currency IS NULL OR (
                        typeof(cost_currency) = 'text' AND
                        length(cost_currency) = 3 AND
                        cost_currency NOT GLOB '*[^A-Z]*'
                    )
                ),
                cost_charged_be BLOB CHECK (
                    (cost_currency IS NULL AND cost_charged_be IS NULL) OR
                    (
                        cost_currency IS NOT NULL AND
                        typeof(cost_charged_be) = 'blob' AND
                        length(cost_charged_be) = 8
                    )
                )
            );

            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_timestamp
                ON chio_tool_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_capability
                ON chio_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_subject
                ON chio_tool_receipts(subject_key);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_grant
                ON chio_tool_receipts(capability_id, grant_index);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_tool
                ON chio_tool_receipts(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_chio_tool_receipts_decision
                ON chio_tool_receipts(decision_kind);

            CREATE TABLE IF NOT EXISTS chio_authorization_receipt_consumptions (
                authorization_receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE RESTRICT,
                consumer_receipt_id TEXT NOT NULL UNIQUE,
                request_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                tool_call_id TEXT NOT NULL,
                -- tenant_id may be NULL for non-enterprise / single-tenant
                -- deployments where the authorization receipt itself carries
                -- `tenant_id: None`. The consumption record mirrors the
                -- receipt's tenant scope verbatim.
                tenant_id TEXT,
                parameter_hash TEXT NOT NULL,
                consumed_at_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_chio_authorization_consumptions_consumer
                ON chio_authorization_receipt_consumptions(consumer_receipt_id);
            CREATE INDEX IF NOT EXISTS idx_chio_authorization_consumptions_scope
                ON chio_authorization_receipt_consumptions(session_id, tool_call_id, request_id);

            CREATE TABLE IF NOT EXISTS settlement_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_settlement_reconciliations_updated_at
                ON settlement_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS metered_billing_reconciliations (
                receipt_id TEXT PRIMARY KEY REFERENCES chio_tool_receipts(receipt_id) ON DELETE CASCADE,
                adapter_kind TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                observed_units INTEGER NOT NULL,
                billed_cost_units INTEGER NOT NULL,
                billed_cost_currency TEXT NOT NULL,
                evidence_sha256 TEXT,
                recorded_at INTEGER NOT NULL,
                reconciliation_state TEXT NOT NULL,
                note TEXT,
                updated_at INTEGER NOT NULL,
                UNIQUE (adapter_kind, evidence_id)
            );
            CREATE INDEX IF NOT EXISTS idx_metered_billing_reconciliations_updated_at
                ON metered_billing_reconciliations(updated_at);

            CREATE TABLE IF NOT EXISTS underwriting_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                outcome TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                review_state TEXT NOT NULL,
                risk_class TEXT NOT NULL,
                supersedes_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                superseded_by_decision_id TEXT REFERENCES underwriting_decisions(decision_id),
                premium_units INTEGER,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_issued_at
                ON underwriting_decisions(issued_at);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_capability
                ON underwriting_decisions(capability_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_subject
                ON underwriting_decisions(subject_key);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_tool
                ON underwriting_decisions(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_outcome
                ON underwriting_decisions(outcome);
            CREATE INDEX IF NOT EXISTS idx_underwriting_decisions_lifecycle
                ON underwriting_decisions(lifecycle_state);

            CREATE TABLE IF NOT EXISTS underwriting_appeals (
                appeal_id TEXT PRIMARY KEY,
                decision_id TEXT NOT NULL REFERENCES underwriting_decisions(decision_id) ON DELETE CASCADE,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                note TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                resolved_by TEXT,
                replacement_decision_id TEXT REFERENCES underwriting_decisions(decision_id)
            );
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_decision
                ON underwriting_appeals(decision_id);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_status
                ON underwriting_appeals(status);
            CREATE INDEX IF NOT EXISTS idx_underwriting_appeals_updated_at
                ON underwriting_appeals(updated_at);

            CREATE TABLE IF NOT EXISTS credit_facilities (
                facility_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_facility_id TEXT REFERENCES credit_facilities(facility_id),
                superseded_by_facility_id TEXT REFERENCES credit_facilities(facility_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_issued_at
                ON credit_facilities(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_expires_at
                ON credit_facilities(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_capability
                ON credit_facilities(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_subject
                ON credit_facilities(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_tool
                ON credit_facilities(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_disposition
                ON credit_facilities(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_facilities_lifecycle
                ON credit_facilities(lifecycle_state);

            CREATE TABLE IF NOT EXISTS credit_bonds (
                bond_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                disposition TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_bond_id TEXT REFERENCES credit_bonds(bond_id),
                superseded_by_bond_id TEXT REFERENCES credit_bonds(bond_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_issued_at
                ON credit_bonds(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_expires_at
                ON credit_bonds(expires_at);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_facility
                ON credit_bonds(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_capability
                ON credit_bonds(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_subject
                ON credit_bonds(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_tool
                ON credit_bonds(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_disposition
                ON credit_bonds(disposition);
            CREATE INDEX IF NOT EXISTS idx_credit_bonds_lifecycle
                ON credit_bonds(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_providers (
                provider_record_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                lifecycle_state TEXT NOT NULL,
                supersedes_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                superseded_by_provider_record_id TEXT REFERENCES liability_providers(provider_record_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_providers_issued_at
                ON liability_providers(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_provider_id
                ON liability_providers(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_providers_lifecycle
                ON liability_providers(lifecycle_state);

            CREATE TABLE IF NOT EXISTS liability_quote_requests (
                quote_request_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                coverage_class TEXT NOT NULL,
                currency TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_issued_at
                ON liability_quote_requests(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_provider
                ON liability_quote_requests(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_requests_subject
                ON liability_quote_requests(subject_key);

            CREATE TABLE IF NOT EXISTS liability_quote_responses (
                quote_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                expires_at INTEGER,
                supersedes_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                superseded_by_quote_response_id TEXT REFERENCES liability_quote_responses(quote_response_id),
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_issued_at
                ON liability_quote_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_request
                ON liability_quote_responses(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_quote_responses_provider
                ON liability_quote_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_pricing_authorities (
                authority_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                provider_id TEXT NOT NULL,
                facility_id TEXT NOT NULL,
                underwriting_decision_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_pricing_authorities_request
                ON liability_pricing_authorities(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_pricing_authorities_provider
                ON liability_pricing_authorities(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_pricing_authorities_facility
                ON liability_pricing_authorities(facility_id);

            CREATE TABLE IF NOT EXISTS liability_placements (
                placement_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_request
                ON liability_placements(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_placements_response
                ON liability_placements(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_placements_provider
                ON liability_placements(provider_id);

            CREATE TABLE IF NOT EXISTS liability_bound_coverages (
                bound_coverage_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                placement_id TEXT NOT NULL REFERENCES liability_placements(placement_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_request
                ON liability_bound_coverages(quote_request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_response
                ON liability_bound_coverages(quote_response_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_bound_coverages_placement
                ON liability_bound_coverages(placement_id);
            CREATE INDEX IF NOT EXISTS idx_liability_bound_coverages_provider
                ON liability_bound_coverages(provider_id);

            CREATE TABLE IF NOT EXISTS liability_auto_bind_decisions (
                decision_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                quote_request_id TEXT NOT NULL REFERENCES liability_quote_requests(quote_request_id),
                quote_response_id TEXT NOT NULL REFERENCES liability_quote_responses(quote_response_id),
                authority_id TEXT NOT NULL REFERENCES liability_pricing_authorities(authority_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_response
                ON liability_auto_bind_decisions(quote_response_id);
            CREATE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_request
                ON liability_auto_bind_decisions(quote_request_id);
            CREATE INDEX IF NOT EXISTS idx_liability_auto_bind_decisions_authority
                ON liability_auto_bind_decisions(authority_id);

            CREATE TABLE IF NOT EXISTS liability_claim_packages (
                claim_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                provider_id TEXT NOT NULL,
                policy_number TEXT NOT NULL,
                jurisdiction TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                claim_event_at INTEGER NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_issued_at
                ON liability_claim_packages(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_provider
                ON liability_claim_packages(provider_id);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_policy_number
                ON liability_claim_packages(policy_number);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_packages_subject
                ON liability_claim_packages(subject_key);

            CREATE TABLE IF NOT EXISTS liability_claim_responses (
                claim_response_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                provider_id TEXT NOT NULL,
                disposition TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_issued_at
                ON liability_claim_responses(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_responses_provider
                ON liability_claim_responses(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_disputes (
                dispute_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                claim_response_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_responses(claim_response_id),
                provider_id TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_issued_at
                ON liability_claim_disputes(issued_at);
            CREATE INDEX IF NOT EXISTS idx_liability_claim_disputes_provider
                ON liability_claim_disputes(provider_id);

            CREATE TABLE IF NOT EXISTS liability_claim_adjudications (
                adjudication_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                dispute_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_disputes(dispute_id),
                outcome TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_adjudications_issued_at
                ON liability_claim_adjudications(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_payout_instructions (
                payout_instruction_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                adjudication_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_adjudications(adjudication_id),
                payout_amount_units INTEGER NOT NULL,
                payout_amount_currency TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_payout_instructions_issued_at
                ON liability_claim_payout_instructions(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_payout_receipts (
                payout_receipt_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                payout_instruction_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_payout_instructions(payout_instruction_id),
                reconciliation_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_payout_receipts_issued_at
                ON liability_claim_payout_receipts(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_settlement_instructions (
                settlement_instruction_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                payout_receipt_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_payout_receipts(payout_receipt_id),
                settlement_kind TEXT NOT NULL,
                payer_role TEXT NOT NULL,
                payer_id TEXT NOT NULL,
                payee_role TEXT NOT NULL,
                payee_id TEXT NOT NULL,
                settlement_amount_units INTEGER NOT NULL,
                settlement_amount_currency TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_settlement_instructions_issued_at
                ON liability_claim_settlement_instructions(issued_at);

            CREATE TABLE IF NOT EXISTS liability_claim_settlement_receipts (
                settlement_receipt_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                claim_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_packages(claim_id),
                settlement_instruction_id TEXT NOT NULL UNIQUE REFERENCES liability_claim_settlement_instructions(settlement_instruction_id),
                reconciliation_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_liability_claim_settlement_receipts_issued_at
                ON liability_claim_settlement_receipts(issued_at);

            CREATE TABLE IF NOT EXISTS credit_loss_lifecycle (
                event_id TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                bond_id TEXT NOT NULL REFERENCES credit_bonds(bond_id),
                facility_id TEXT,
                capability_id TEXT,
                subject_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                event_kind TEXT NOT NULL,
                projected_bond_lifecycle_state TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                signer_key TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_issued_at
                ON credit_loss_lifecycle(issued_at);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_bond
                ON credit_loss_lifecycle(bond_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_facility
                ON credit_loss_lifecycle(facility_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_capability
                ON credit_loss_lifecycle(capability_id);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_subject
                ON credit_loss_lifecycle(subject_key);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_tool
                ON credit_loss_lifecycle(tool_server, tool_name);
            CREATE INDEX IF NOT EXISTS idx_credit_loss_lifecycle_kind
                ON credit_loss_lifecycle(event_kind);

            CREATE TABLE IF NOT EXISTS chio_child_receipts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                timestamp INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                parent_request_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                operation_kind TEXT NOT NULL,
                terminal_state TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                outcome_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_timestamp
                ON chio_child_receipts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_session
                ON chio_child_receipts(session_id);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_parent
                ON chio_child_receipts(parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_chio_child_receipts_request
                ON chio_child_receipts(request_id);

            CREATE TABLE IF NOT EXISTS claim_receipt_log_entries (
                entry_seq INTEGER PRIMARY KEY AUTOINCREMENT,
                receipt_id TEXT NOT NULL UNIQUE,
                receipt_kind TEXT NOT NULL,
                source_seq INTEGER NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT,
                session_id TEXT,
                parent_request_id TEXT,
                request_id TEXT,
                subject_key TEXT,
                issuer_key TEXT,
                tool_server TEXT,
                tool_name TEXT,
                raw_json TEXT NOT NULL,
                CHECK (entry_seq > 0),
                CHECK (source_seq > 0),
                CHECK (receipt_kind IN ('tool_receipt', 'child_receipt')),
                CHECK (
                    (receipt_kind = 'tool_receipt'
                        AND capability_id IS NOT NULL
                        AND session_id IS NULL
                        AND parent_request_id IS NULL
                        AND request_id IS NULL
                        AND tool_server IS NOT NULL
                        AND tool_name IS NOT NULL)
                    OR
                    (receipt_kind = 'child_receipt'
                        AND capability_id IS NULL
                        AND session_id IS NOT NULL
                        AND parent_request_id IS NOT NULL
                        AND request_id IS NOT NULL
                        AND tool_server IS NULL
                        AND tool_name IS NULL)
                )
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_claim_receipt_log_kind_source
                ON claim_receipt_log_entries(receipt_kind, source_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_timestamp
                ON claim_receipt_log_entries(timestamp, entry_seq);
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_tool
                ON claim_receipt_log_entries(tool_server, tool_name, timestamp)
                WHERE receipt_kind = 'tool_receipt';
            CREATE INDEX IF NOT EXISTS idx_claim_receipt_log_child_request
                ON claim_receipt_log_entries(session_id, request_id, timestamp)
                WHERE receipt_kind = 'child_receipt';

            DROP TRIGGER IF EXISTS chio_tool_receipts_project_claim_log_entry;
            CREATE TRIGGER chio_tool_receipts_project_claim_log_entry
            AFTER INSERT ON chio_tool_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'tool_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NEW.capability_id,
                    NULL,
                    NULL,
                    NULL,
                    NEW.subject_key,
                    NEW.issuer_key,
                    NEW.tool_server,
                    NEW.tool_name,
                    NEW.raw_json
                );
            END;

            DROP TRIGGER IF EXISTS chio_child_receipts_project_claim_log_entry;
            CREATE TRIGGER chio_child_receipts_project_claim_log_entry
            AFTER INSERT ON chio_child_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id,
                    receipt_kind,
                    source_seq,
                    timestamp,
                    capability_id,
                    session_id,
                    parent_request_id,
                    request_id,
                    subject_key,
                    issuer_key,
                    tool_server,
                    tool_name,
                    raw_json
                ) VALUES (
                    NEW.receipt_id,
                    'child_receipt',
                    NEW.seq,
                    NEW.timestamp,
                    NULL,
                    NEW.session_id,
                    NEW.parent_request_id,
                    NEW.request_id,
                    NULL,
                    NULL,
                    NULL,
                    NULL,
                    NEW.raw_json
                );
            END;

            CREATE TABLE IF NOT EXISTS session_anchors (
                anchor_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                auth_context_fingerprint TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                supersedes_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                is_current INTEGER NOT NULL DEFAULT 1,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_session_anchors_session
                ON session_anchors(session_id, issued_at DESC);
            CREATE INDEX IF NOT EXISTS idx_session_anchors_supersedes
                ON session_anchors(supersedes_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_session_anchors_current
                ON session_anchors(session_id)
                WHERE is_current = 1;

            CREATE TABLE IF NOT EXISTS request_lineage (
                session_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                parent_request_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                recorded_at INTEGER NOT NULL,
                request_fingerprint TEXT,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (session_id, request_id)
            );
            CREATE INDEX IF NOT EXISTS idx_request_lineage_parent
                ON request_lineage(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_request_lineage_anchor
                ON request_lineage(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_request_lineage_fingerprint
                ON request_lineage(session_id, COALESCE(session_anchor_id, ''), request_fingerprint)
                WHERE request_fingerprint IS NOT NULL;

            CREATE TABLE IF NOT EXISTS receipt_lineage_statements (
                receipt_id TEXT PRIMARY KEY,
                statement_id TEXT,
                request_id TEXT,
                session_id TEXT,
                session_anchor_id TEXT REFERENCES session_anchors(anchor_id),
                chain_id TEXT,
                parent_request_id TEXT,
                parent_receipt_id TEXT,
                evidence_class TEXT,
                evidence_sources_json TEXT,
                verified_session_anchor INTEGER NOT NULL DEFAULT 0,
                verified_parent_request INTEGER NOT NULL DEFAULT 0,
                verified_parent_receipt INTEGER NOT NULL DEFAULT 0,
                replay_protected INTEGER NOT NULL DEFAULT 0,
                recorded_at INTEGER NOT NULL,
                source_kind TEXT NOT NULL,
                json_sha256 TEXT NOT NULL,
                raw_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_request
                ON receipt_lineage_statements(session_id, request_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_statement_id
                ON receipt_lineage_statements(statement_id)
                WHERE statement_id IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_request
                ON receipt_lineage_statements(session_id, parent_request_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_parent_receipt
                ON receipt_lineage_statements(parent_receipt_id);
            CREATE INDEX IF NOT EXISTS idx_receipt_lineage_anchor
                ON receipt_lineage_statements(session_anchor_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_receipt_lineage_request_anchor
                ON receipt_lineage_statements(session_id, COALESCE(session_anchor_id, ''), request_id)
                WHERE session_id IS NOT NULL
                  AND request_id IS NOT NULL;

            CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                checkpoint_seq INTEGER NOT NULL UNIQUE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL,
                kernel_key TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kernel_checkpoints_batch_end
                ON kernel_checkpoints(batch_end_seq);

            CREATE TABLE IF NOT EXISTS checkpoint_tree_heads (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                batch_start_seq INTEGER NOT NULL,
                batch_end_seq INTEGER NOT NULL,
                tree_size INTEGER NOT NULL,
                merkle_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                previous_checkpoint_sha256 TEXT,
                statement_json TEXT NOT NULL,
                signature TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_tree_size
                ON checkpoint_tree_heads(tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_tree_heads_previous
                ON checkpoint_tree_heads(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_predecessor_witnesses (
                predecessor_checkpoint_seq INTEGER NOT NULL
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                witness_checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES checkpoint_tree_heads(checkpoint_seq) ON DELETE CASCADE,
                previous_checkpoint_sha256 TEXT NOT NULL,
                witnessed_at INTEGER NOT NULL,
                witness_statement_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_predecessor
                ON checkpoint_predecessor_witnesses(predecessor_checkpoint_seq);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_predecessor_witnesses_previous
                ON checkpoint_predecessor_witnesses(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_metadata (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                publication_schema TEXT NOT NULL,
                merkle_root TEXT NOT NULL,
                published_at INTEGER NOT NULL,
                kernel_key TEXT NOT NULL,
                log_tree_size INTEGER NOT NULL,
                entry_start_seq INTEGER NOT NULL,
                entry_end_seq INTEGER NOT NULL,
                previous_checkpoint_sha256 TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_published_at
                ON checkpoint_publication_metadata(published_at);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_log_tree_size
                ON checkpoint_publication_metadata(log_tree_size);
            CREATE INDEX IF NOT EXISTS idx_checkpoint_publication_metadata_previous
                ON checkpoint_publication_metadata(previous_checkpoint_sha256);

            CREATE TABLE IF NOT EXISTS checkpoint_publication_trust_anchor_bindings (
                checkpoint_seq INTEGER PRIMARY KEY
                    REFERENCES kernel_checkpoints(checkpoint_seq) ON DELETE CASCADE,
                binding_json TEXT NOT NULL
            );

            DROP TRIGGER IF EXISTS kernel_checkpoints_project_tree_head;
            CREATE TRIGGER kernel_checkpoints_project_tree_head
            AFTER INSERT ON kernel_checkpoints
            BEGIN
                INSERT INTO checkpoint_tree_heads (
                    checkpoint_seq,
                    batch_start_seq,
                    batch_end_seq,
                    tree_size,
                    merkle_root,
                    issued_at,
                    kernel_key,
                    previous_checkpoint_sha256,
                    statement_json,
                    signature
                ) VALUES (
                    NEW.checkpoint_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    NEW.tree_size,
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
                    NEW.statement_json,
                    NEW.signature
                );

                INSERT INTO checkpoint_predecessor_witnesses (
                    predecessor_checkpoint_seq,
                    witness_checkpoint_seq,
                    previous_checkpoint_sha256,
                    witnessed_at,
                    witness_statement_json
                )
                SELECT
                    NEW.checkpoint_seq - 1,
                    NEW.checkpoint_seq,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT),
                    NEW.issued_at,
                    NEW.statement_json
                WHERE json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') IS NOT NULL;

                INSERT INTO checkpoint_publication_metadata (
                    checkpoint_seq,
                    publication_schema,
                    merkle_root,
                    published_at,
                    kernel_key,
                    log_tree_size,
                    entry_start_seq,
                    entry_end_seq,
                    previous_checkpoint_sha256
                ) VALUES (
                    NEW.checkpoint_seq,
                    'chio.checkpoint_publication.v1',
                    NEW.merkle_root,
                    NEW.issued_at,
                    NEW.kernel_key,
                    NEW.batch_end_seq,
                    NEW.batch_start_seq,
                    NEW.batch_end_seq,
                    CAST(json_extract(NEW.statement_json, '$.previous_checkpoint_sha256') AS TEXT)
                );
            END;

            CREATE TABLE IF NOT EXISTS capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT REFERENCES capability_lineage(capability_id),
                federated_parent_capability_id TEXT,
                provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                    CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection')),
                signed_capability_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_subject
                ON capability_lineage(subject_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issuer
                ON capability_lineage(issuer_key);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_issued_at
                ON capability_lineage(issued_at);
            CREATE INDEX IF NOT EXISTS idx_capability_lineage_parent
                ON capability_lineage(parent_capability_id);
            CREATE TABLE IF NOT EXISTS federated_lineage_bridges (
                local_capability_id TEXT PRIMARY KEY REFERENCES capability_lineage(capability_id) ON DELETE CASCADE,
                parent_capability_id TEXT NOT NULL,
                share_id TEXT REFERENCES federated_evidence_shares(share_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_lineage_bridges_parent
                ON federated_lineage_bridges(parent_capability_id);

            CREATE TABLE IF NOT EXISTS federated_evidence_shares (
                share_id TEXT PRIMARY KEY,
                manifest_hash TEXT NOT NULL,
                imported_at INTEGER NOT NULL,
                exported_at INTEGER NOT NULL,
                issuer TEXT NOT NULL,
                partner TEXT NOT NULL,
                signer_public_key TEXT NOT NULL,
                require_proofs INTEGER NOT NULL DEFAULT 0,
                query_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_federated_evidence_shares_imported_at
                ON federated_evidence_shares(imported_at);

            CREATE TABLE IF NOT EXISTS federated_share_tool_receipts (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                seq INTEGER NOT NULL,
                receipt_id TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                capability_id TEXT NOT NULL,
                subject_key TEXT,
                issuer_key TEXT,
                raw_json TEXT NOT NULL,
                PRIMARY KEY (share_id, seq),
                UNIQUE (share_id, receipt_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_capability
                ON federated_share_tool_receipts(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_receipts_subject
                ON federated_share_tool_receipts(subject_key);

            CREATE TABLE IF NOT EXISTS federated_share_capability_lineage (
                share_id TEXT NOT NULL REFERENCES federated_evidence_shares(share_id) ON DELETE CASCADE,
                capability_id TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                issuer_key TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                grants_json TEXT NOT NULL,
                delegation_depth INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT,
                federated_parent_capability_id TEXT,
                provenance TEXT NOT NULL DEFAULT 'legacy_projection'
                    CHECK (provenance IN ('signed_token', 'synthetic_anchor', 'legacy_projection')),
                signed_capability_json TEXT,
                PRIMARY KEY (share_id, capability_id)
            );
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_capability
                ON federated_share_capability_lineage(capability_id);
            CREATE INDEX IF NOT EXISTS idx_federated_share_lineage_subject
                ON federated_share_capability_lineage(subject_key);

            CREATE TABLE IF NOT EXISTS receipt_retention_watermark (
                archived_through_entry_seq INTEGER NOT NULL,
                archived_through_timestamp INTEGER NOT NULL,
                archive_path               TEXT NOT NULL,
                archive_sha256             TEXT,
                rotated_at                 INTEGER NOT NULL,
                CHECK (archived_through_entry_seq >= 0)
            );

            "#,
        )?;
        schema_migration.commit()?;
        connection.execute_batch(crate::IOU_ENVELOPE_MIGRATION)?;
        connection.execute_batch(crate::dead_letters::SETTLE_DEAD_LETTERS_MIGRATION)?;
        connection.execute_batch(crate::settle_attempts::SETTLE_ATTEMPTS_MIGRATION)?;
        ensure_tool_receipt_attribution_columns(&connection)?;
        super::support::ensure_receipt_lineage_statement_columns(&connection)?;
        super::support::drop_transparency_projection_guards(&connection)?;
        let backfill_result = (|| -> Result<(), ReceiptStoreError> {
            super::support::ensure_receipt_retention_watermark_table(&connection)?;
            super::support::ensure_receipt_retention_tombstones(&connection)?;
            backfill_tool_receipt_attribution_columns(&connection)?;
            let projection_backfill =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            super::support::backfill_provenance_lineage_tables(&projection_backfill)?;
            super::support::backfill_claim_receipt_log_entries(&projection_backfill)?;
            super::support::backfill_checkpoint_transparency_projections(&projection_backfill)?;
            projection_backfill.commit()?;
            if on_disk_schema_version < RECEIPT_COST_PROJECTION_SCHEMA_VERSION {
                let migration = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                migrate_receipt_cost_projection(&migration)?;
                migration.commit()?;
            }
            Ok(())
        })();
        let guard_result = super::support::ensure_transparency_projection_guards(&connection);
        match (backfill_result, guard_result) {
            (Ok(()), Ok(())) => {}
            (Err(error), Ok(())) => return Err(error),
            (Ok(()), Err(error)) => return Err(error),
            (Err(backfill_error), Err(guard_error)) => {
                return Err(ReceiptStoreError::Canonical(format!(
                    "receipt projection backfill failed ({backfill_error}); restoring immutability guards also failed ({guard_error})"
                )));
            }
        }
        verify_receipt_cost_projection(&connection)?;

        let migration =
            connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure_capability_lineage_provenance_columns(&migration)?;
        let durable_sink_id = ensure_receipt_sink_identity(&migration)?;
        crate::stamp_schema_version(
            &migration,
            RECEIPT_STORE_SCHEMA_KEY,
            RECEIPT_STORE_SUPPORTED_SCHEMA_VERSION,
        )
        .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        migration.commit()?;

        let settlement_store_binding = settlement_store_binding_if_ready(&connection)?;

        drop(connection);

        let reader_pool = build_receipt_pool(
            path,
            options.pool.reader_pool_max_size,
            "reader",
            connection_flags,
            options.pool.max_page_count,
        )?;
        let writer_pool = build_receipt_pool(
            path,
            options.pool.writer_pool_max_size,
            "writer",
            connection_flags,
            options.pool.max_page_count,
        )?;

        Ok(Self {
            receipt_commit_actor: ReceiptCommitActor::start(
                writer_pool,
                options.incremental_verification,
            ),
            pool: reader_pool,
            settlement_store_binding,
            durable_sink_id,
            strict_tenant_isolation: std::sync::atomic::AtomicBool::new(true),
            incremental_verification: options.incremental_verification,
        })
    }

    pub fn open_with_pool_sizes(
        path: impl AsRef<Path>,
        reader_pool_max_size: u32,
        writer_pool_max_size: u32,
    ) -> Result<Self, ReceiptStoreError> {
        Self::open_with_pool_config(
            path,
            crate::SqlitePoolConfig {
                reader_pool_max_size,
                writer_pool_max_size,
                max_page_count: None,
            },
        )
    }
}

fn build_receipt_pool(
    path: &Path,
    max_size: u32,
    pool_name: &str,
    flags: Option<rusqlite::OpenFlags>,
    max_page_count: Option<u32>,
) -> Result<Pool<SqliteConnectionManager>, ReceiptStoreError> {
    if max_size == 0 {
        return Err(ReceiptStoreError::Pool(format!(
            "{pool_name} receipt sqlite pool max_size must be greater than zero"
        )));
    }
    let mut manager = SqliteConnectionManager::file(path);
    if let Some(flags) = flags {
        manager = manager.with_flags(flags);
    }
    let manager = manager.with_init(move |connection| {
        configure_sqlite_connection(connection, max_page_count).map_err(|error| match error {
            ReceiptStoreError::Sqlite(error) => error,
            other => rusqlite::Error::InvalidParameterName(other.to_string()),
        })
    });
    Pool::builder()
        .max_size(max_size)
        .build(manager)
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))
}

fn existing_database_open_flags() -> rusqlite::OpenFlags {
    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
}

fn require_existing_receipt_schema(
    path: &Path,
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    const REQUIRED_TABLES: &[&str] = &[
        "chio_tool_receipts",
        "chio_child_receipts",
        "claim_receipt_log_entries",
        "kernel_checkpoints",
        "checkpoint_tree_heads",
        "checkpoint_predecessor_witnesses",
        "checkpoint_publication_metadata",
    ];

    for table in REQUIRED_TABLES {
        let exists: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [*table],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ReceiptStoreError::NotFound(format!(
                "receipt database {} is not an initialized Chio receipt store: missing table {table}",
                path.display()
            )));
        }
    }

    Ok(())
}

/// Refuse an unstamped database whose generic legacy anchor (`http_receipts` or
/// `tool_receipts`) does not carry a receipt payload column. These names are
/// generic enough that an unrelated SQLite database could hold one by
/// coincidence; the schema-version check would otherwise adopt and stamp such a
/// file as a receipt store. A database already carrying the Chio application_id
/// is provably a Chio store and is left to the schema-version check.
fn reject_foreign_legacy_receipt_anchor(connection: &Connection) -> Result<(), ReceiptStoreError> {
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    if application_id != 0 {
        return Ok(());
    }
    for anchor in RECEIPT_STORE_GENERIC_LEGACY_ANCHOR_TABLES {
        if table_exists(connection, anchor)?
            && !table_has_receipt_payload_column(connection, anchor)?
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "database has a `{anchor}` table without a receipt payload column \
                 (raw_json or receipt_json); refusing to adopt a foreign database as a receipt store"
            )));
        }
    }
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, ReceiptStoreError> {
    let present: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )?;
    Ok(present)
}

/// Whether `table` stores a receipt payload under a recognised JSON column:
/// `raw_json` on the current store, `receipt_json` on the pre-stamping one. The
/// table name is one of the store's own compile-time anchors, never caller
/// input, and `PRAGMA table_info` takes no bound parameter for it.
fn table_has_receipt_payload_column(
    connection: &Connection,
    table: &str,
) -> Result<bool, ReceiptStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let column: String = row.get(1)?;
        if column.eq_ignore_ascii_case("raw_json") || column.eq_ignore_ascii_case("receipt_json") {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ensure_capability_lineage_provenance_columns(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    for table in ["capability_lineage", "federated_share_capability_lineage"] {
        if !table_has_column(connection, table, "signed_capability_json")? {
            connection.execute(
                &format!("ALTER TABLE {table} ADD COLUMN signed_capability_json TEXT"),
                [],
            )?;
        }
        if !table_has_column(connection, table, "federated_parent_capability_id")? {
            connection.execute(
                &format!("ALTER TABLE {table} ADD COLUMN federated_parent_capability_id TEXT"),
                [],
            )?;
        }
        if !table_has_column(connection, table, "provenance")? {
            connection.execute(
                &format!(
                    "ALTER TABLE {table} ADD COLUMN provenance TEXT NOT NULL DEFAULT \
                     'legacy_projection' CHECK (provenance IN ('signed_token', \
                     'synthetic_anchor', 'legacy_projection'))"
                ),
                [],
            )?;
        }
        connection.execute(
            &format!(
                "UPDATE {table} SET provenance = 'signed_token' \
                 WHERE provenance = 'legacy_projection' \
                   AND signed_capability_json IS NOT NULL"
            ),
            [],
        )?;
    }

    let conflicting_bridge: bool = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM capability_lineage c
            INNER JOIN federated_lineage_bridges b
                ON b.local_capability_id = c.capability_id
            WHERE c.federated_parent_capability_id IS NOT NULL
              AND c.federated_parent_capability_id != b.parent_capability_id
        )
        "#,
        [],
        |row| row.get(0),
    )?;
    if conflicting_bridge {
        return Err(ReceiptStoreError::Conflict(
            "capability lineage federation metadata conflicts with its persisted bridge"
                .to_string(),
        ));
    }
    let bridges_to_backfill = {
        let mut statement = connection.prepare(
            r#"
            SELECT b.local_capability_id, b.parent_capability_id
            FROM federated_lineage_bridges b
            INNER JOIN capability_lineage c
                ON c.capability_id = b.local_capability_id
            WHERE c.federated_parent_capability_id IS NULL
            ORDER BY c.rowid
            "#,
        )?;
        let bridges = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        bridges
    };
    let mut next_rowid: i64 = connection.query_row(
        "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
        [],
        |row| row.get(0),
    )?;
    for (local_capability_id, parent_capability_id) in bridges_to_backfill {
        next_rowid = next_rowid.checked_add(1).ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "capability lineage replication sequence is exhausted".to_string(),
            )
        })?;
        connection.execute(
            r#"
            UPDATE capability_lineage
            SET federated_parent_capability_id = ?2,
                rowid = ?3
            WHERE capability_id = ?1
              AND federated_parent_capability_id IS NULL
            "#,
            params![local_capability_id, parent_capability_id, next_rowid],
        )?;
    }
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_capability_lineage_federated_parent \
         ON capability_lineage(federated_parent_capability_id)",
        [],
    )?;
    Ok(())
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    expected_column: &str,
) -> Result<bool, ReceiptStoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let column: String = row.get(1)?;
        if column.eq_ignore_ascii_case(expected_column) {
            return Ok(true);
        }
    }
    Ok(false)
}
