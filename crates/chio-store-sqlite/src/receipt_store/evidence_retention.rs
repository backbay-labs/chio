use super::support::{
    checkpoint_error_to_receipt_store, ensure_checkpoint_transparency_guards,
    ensure_chio_receipt_verified, ensure_transparency_projection_guards,
    load_claim_tree_canonical_bytes_range, load_persisted_checkpoint_row,
    parse_persisted_checkpoint_row, verify_checkpoint_chain_integrity,
};
use super::*;

impl SqliteReceiptStore {
    pub fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_chio_receipt_verified(receipt)?;
        let raw_json = serde_json::to_string(receipt)?;
        let attribution = extract_receipt_attribution(receipt);
        let mut connection = self.connection()?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut subject_key = attribution.subject_key;
        let mut issuer_key = attribution.issuer_key;
        if subject_key.is_none() || issuer_key.is_none() {
            if let Some((lineage_subject_key, lineage_issuer_key)) = tx
                .query_row(
                    "SELECT subject_key, issuer_key FROM capability_lineage WHERE capability_id = ?1",
                    params![receipt.capability_id.as_str()],
                    |row| {
                        Ok((
                            row.get::<_, Option<String>>(0)?,
                            row.get::<_, Option<String>>(1)?,
                        ))
                    },
                )
                .optional()?
            {
                if subject_key.is_none() {
                    subject_key = lineage_subject_key;
                }
                if issuer_key.is_none() {
                    issuer_key = lineage_issuer_key;
                }
            }
        }
        // Phase 1.5: tenant_id is populated directly from the signed
        // receipt body. The evaluate path derived it from the session's
        // enterprise_identity; we carry it through to a dedicated column
        // so the tenant-scoped WHERE clause can filter without having
        // to json_extract on every query.
        let tenant_id = receipt.tenant_id.clone();
        let inserted = tx.execute(
            r#"
            INSERT INTO chio_tool_receipts (
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                issuer_key,
                grant_index,
                tool_server,
                tool_name,
                decision_kind,
                policy_hash,
                content_hash,
                tenant_id,
                raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(receipt_id) DO NOTHING
            "#,
            params![
                receipt.id,
                sqlite_i64(receipt.timestamp, "receipt timestamp")?,
                receipt.capability_id,
                subject_key,
                issuer_key,
                attribution.grant_index.map(i64::from),
                receipt.tool_server,
                receipt.tool_name,
                decision_kind(&receipt.decision),
                receipt.policy_hash,
                receipt.content_hash,
                tenant_id,
                raw_json,
            ],
        )?;
        if inserted == 0 {
            tx.commit()?;
            return Ok(0);
        }
        let source_seq = tx.query_row(
            "SELECT seq FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt.id.as_str()],
            |row| row.get::<_, i64>(0),
        )?;
        let source_seq = sqlite_u64(source_seq, "tool receipt source_seq")?;
        let entry_seq = tx.query_row(
            r#"
            SELECT entry_seq
            FROM claim_receipt_log_entries
            WHERE receipt_kind = 'tool_receipt' AND source_seq = ?1
            "#,
            params![sqlite_i64(source_seq, "tool receipt source_seq")?],
            |row| row.get::<_, i64>(0),
        )?;
        tx.commit()?;
        sqlite_u64(entry_seq, "tool receipt claim log entry_seq")
    }

    /// Store a signed KernelCheckpoint in the kernel_checkpoints table.
    pub fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;

        chio_kernel::checkpoint::validate_checkpoint(checkpoint)
            .map_err(checkpoint_error_to_receipt_store)?;
        if let Some(existing) =
            load_persisted_checkpoint_row(&connection, checkpoint.body.checkpoint_seq)?
        {
            let existing = parse_persisted_checkpoint_row(existing)?;
            if existing == *checkpoint {
                return Ok(());
            }
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} already exists with different content",
                checkpoint.body.checkpoint_seq
            )));
        }

        match verify_checkpoint_chain_integrity(&connection)? {
            Some(predecessor) => {
                if checkpoint.body.checkpoint_seq <= predecessor.body.checkpoint_seq {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "checkpoint {} must be appended after existing checkpoint {}",
                        checkpoint.body.checkpoint_seq, predecessor.body.checkpoint_seq
                    )));
                }
                chio_kernel::checkpoint::validate_checkpoint_predecessor(&predecessor, checkpoint)
                    .map_err(|error| {
                        ReceiptStoreError::Conflict(format!(
                            "checkpoint predecessor continuity violation: {error}"
                        ))
                    })?;
            }
            None if checkpoint.body.checkpoint_seq != 1 => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "checkpoint {} cannot initialize an empty checkpoint log",
                    checkpoint.body.checkpoint_seq
                )));
            }
            None => {}
        }

        let statement_json = serde_json::to_string(&checkpoint.body)?;
        connection
            .execute(
                r#"
            INSERT INTO kernel_checkpoints (
                checkpoint_seq, batch_start_seq, batch_end_seq, tree_size,
                merkle_root, issued_at, statement_json, signature, kernel_key
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
                params![
                    sqlite_i64(checkpoint.body.checkpoint_seq, "checkpoint_seq")?,
                    sqlite_i64(checkpoint.body.batch_start_seq, "batch_start_seq")?,
                    sqlite_i64(checkpoint.body.batch_end_seq, "batch_end_seq")?,
                    sqlite_i64(checkpoint.body.tree_size as u64, "tree_size")?,
                    checkpoint.body.merkle_root.to_hex(),
                    sqlite_i64(checkpoint.body.issued_at, "issued_at")?,
                    statement_json,
                    checkpoint.signature.to_hex(),
                    checkpoint.body.kernel_key.to_hex(),
                ],
            )
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!("checkpoint append conflict: {error}"))
            })?;

        let stored = load_persisted_checkpoint_row(&connection, checkpoint.body.checkpoint_seq)?
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "checkpoint {} was not visible after persistence",
                    checkpoint.body.checkpoint_seq
                ))
            })?;
        let stored = parse_persisted_checkpoint_row(stored)?;
        if stored != *checkpoint {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint {} persisted with conflicting contents",
                checkpoint.body.checkpoint_seq
            )));
        }
        Ok(())
    }

    /// Load a KernelCheckpoint by its checkpoint_seq.
    pub fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        load_persisted_checkpoint_row(&connection, checkpoint_seq)?
            .map(parse_persisted_checkpoint_row)
            .transpose()
    }

    /// Return canonical JSON bytes for receipts with seq in [start_seq, end_seq], ordered by seq.
    ///
    /// Uses RFC 8785 canonical JSON for deterministic Merkle leaf hashing.
    pub fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let connection = self.connection()?;
        load_claim_tree_canonical_bytes_range(&connection, start_seq, end_seq)
    }

    /// Return the current on-disk size of the database in bytes.
    ///
    /// Uses `PRAGMA page_count` and `PRAGMA page_size` to compute the size
    /// without requiring a filesystem stat, which is consistent in WAL mode.
    pub fn db_size_bytes(&self) -> Result<u64, ReceiptStoreError> {
        let page_count: i64 = self
            .connection()?
            .query_row("PRAGMA page_count", [], |row| row.get(0))?;
        let page_size: i64 = self
            .connection()?
            .query_row("PRAGMA page_size", [], |row| row.get(0))?;
        Ok((page_count.max(0) as u64) * (page_size.max(0) as u64))
    }

    /// Return the Unix timestamp (seconds) of the oldest receipt in the live
    /// database, or `None` if there are no receipts.
    pub fn oldest_receipt_timestamp(&self) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection()?.query_row(
            "SELECT MIN(timestamp) FROM chio_tool_receipts",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Return the oldest live receipt timestamp for a tenant.
    pub fn oldest_receipt_timestamp_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let ts = self.connection()?.query_row(
            "SELECT MIN(timestamp) FROM chio_tool_receipts WHERE tenant_id = ?1",
            params![tenant_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        Ok(ts.map(|t| t.max(0) as u64))
    }

    /// Archive all receipts with `timestamp < cutoff_unix_secs` to an external
    /// SQLite file while retaining the live append-only receipt log.
    ///
    /// Checkpoint rows whose entire batch (`batch_end_seq`) falls within the
    /// archived receipt range are also copied to the archive. Partial batches
    /// are never archived to avoid breaking inclusion proofs.
    ///
    /// Returns the number of newly archived tool receipt rows.
    pub fn archive_receipts_before(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
    ) -> Result<u64, ReceiptStoreError> {
        self.archive_receipts_before_scoped(cutoff_unix_secs, archive_path, None)
    }

    /// Archive receipts for a single tenant without deleting other tenants'
    /// evidence that may have a longer retention window.
    pub fn archive_receipts_before_for_tenant(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
        tenant_id: &str,
    ) -> Result<u64, ReceiptStoreError> {
        self.archive_receipts_before_scoped(cutoff_unix_secs, archive_path, Some(tenant_id))
    }

    fn archive_receipts_before_scoped(
        &mut self,
        cutoff_unix_secs: u64,
        archive_path: &str,
        tenant_id: Option<&str>,
    ) -> Result<u64, ReceiptStoreError> {
        let connection = self.connection()?;
        // Escape single quotes in the path to safely embed it in an ATTACH statement.
        let escaped_path = archive_path.replace('\'', "''");

        // Attach the archive database.
        connection.execute_batch(&format!("ATTACH DATABASE '{escaped_path}' AS archive"))?;

        let archive_result = (|| -> Result<u64, ReceiptStoreError> {
            // Create archive tables with the same schema as the main database.
            connection.execute_batch(
                r#"
            CREATE TABLE IF NOT EXISTS archive.chio_tool_receipts (
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
                tenant_id TEXT
            );

            CREATE TABLE IF NOT EXISTS archive.chio_child_receipts (
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

            CREATE TABLE IF NOT EXISTS archive.kernel_checkpoints (
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

            CREATE TABLE IF NOT EXISTS archive.capability_lineage (
                capability_id        TEXT PRIMARY KEY,
                subject_key          TEXT NOT NULL,
                issuer_key           TEXT NOT NULL,
                issued_at            INTEGER NOT NULL,
                expires_at           INTEGER NOT NULL,
                grants_json          TEXT NOT NULL,
                delegation_depth     INTEGER NOT NULL DEFAULT 0,
                parent_capability_id TEXT
            );
            "#,
            )?;

            let cutoff = cutoff_unix_secs as i64;

            let archived_before = archived_tool_receipt_count(&connection, cutoff, tenant_id)?;

            // Copy qualifying receipts to the archive (ignore duplicates from prior runs).
            match tenant_id {
                Some(tenant_id) => {
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.chio_tool_receipts \
                     SELECT * FROM main.chio_tool_receipts WHERE timestamp < ?1 AND tenant_id = ?2",
                        params![cutoff, tenant_id],
                    )?;
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.chio_child_receipts \
                     SELECT child.* \
                     FROM main.chio_child_receipts child \
                     WHERE child.timestamp < ?1 \
                       AND EXISTS ( \
                           SELECT 1 \
                           FROM main.receipt_lineage_statements lineage \
                           INNER JOIN main.chio_tool_receipts parent \
                               ON parent.receipt_id = lineage.parent_receipt_id \
                           WHERE lineage.receipt_id = child.receipt_id \
                             AND parent.tenant_id = ?2 \
                       )",
                        params![cutoff, tenant_id],
                    )?;
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.capability_lineage
                     SELECT DISTINCT cl.*
                     FROM main.capability_lineage cl
                     INNER JOIN main.chio_tool_receipts r ON r.capability_id = cl.capability_id
                     WHERE r.timestamp < ?1 AND r.tenant_id = ?2",
                        params![cutoff, tenant_id],
                    )?;
                }
                None => {
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.chio_tool_receipts \
                     SELECT * FROM main.chio_tool_receipts WHERE timestamp < ?1",
                        params![cutoff],
                    )?;
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.chio_child_receipts \
                     SELECT * FROM main.chio_child_receipts WHERE timestamp < ?1",
                        params![cutoff],
                    )?;
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.capability_lineage
                     SELECT DISTINCT cl.*
                     FROM main.capability_lineage cl
                     INNER JOIN main.chio_tool_receipts r ON r.capability_id = cl.capability_id
                     WHERE r.timestamp < ?1",
                        params![cutoff],
                    )?;
                }
            }

            // Find the maximum seq among archived receipts (for checkpoint filtering).
            let max_archived_seq: Option<i64> = match tenant_id {
            Some(tenant_id) => connection.query_row(
                "SELECT MAX(seq) FROM main.chio_tool_receipts WHERE timestamp < ?1 AND tenant_id = ?2",
                params![cutoff, tenant_id],
                |row| row.get(0),
            )?,
            None => connection.query_row(
                "SELECT MAX(seq) FROM main.chio_tool_receipts WHERE timestamp < ?1",
                params![cutoff],
                |row| row.get(0),
            )?,
        };

            if tenant_id.is_none() {
                if let Some(max_seq) = max_archived_seq {
                    // Copy checkpoint rows whose full batch is covered by the archived receipts.
                    // Never archive a checkpoint whose batch_end_seq exceeds the max archived seq
                    // because that would leave a partial batch in the archive.
                    connection.execute(
                        "INSERT OR IGNORE INTO archive.kernel_checkpoints \
                     SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                        params![max_seq],
                    )?;

                    // Verify that every checkpoint covering the archived range is now present
                    // in the archive. If any checkpoint failed to transfer, refuse to delete the
                    // receipts from the live database to preserve inclusion-proof integrity.
                    let live_count: i64 = connection.query_row(
                        "SELECT COUNT(*) FROM main.kernel_checkpoints WHERE batch_end_seq <= ?1",
                        params![max_seq],
                        |row| row.get(0),
                    )?;
                    let archive_count: i64 = connection.query_row(
                        "SELECT COUNT(*) FROM archive.kernel_checkpoints WHERE batch_end_seq <= ?1",
                        params![max_seq],
                        |row| row.get(0),
                    )?;
                    if archive_count < live_count {
                        return Err(ReceiptStoreError::Canonical(format!(
                            "checkpoint co-archival incomplete: {live_count} checkpoints in live, \
                         only {archive_count} transferred to archive; aborting receipt deletion \
                         to preserve inclusion-proof integrity"
                        )));
                    }
                }
            }

            let archived_after = archived_tool_receipt_count(&connection, cutoff, tenant_id)?;
            let archived = archived_after.saturating_sub(archived_before) as u64;

            if archived_after > 0 {
                Self::delete_archived_live_receipts(&connection, cutoff, tenant_id)?;
            }

            Ok(archived)
        })();

        let detach_result = connection.execute_batch("DETACH DATABASE archive");
        let archived = match (archive_result, detach_result) {
            (Ok(archived), Ok(())) => archived,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error.into()),
            (Err(archive_error), Err(detach_error)) => {
                return Err(ReceiptStoreError::Canonical(format!(
                    "receipt archive failed ({archive_error}); detaching archive database also failed ({detach_error})"
                )));
            }
        };

        // Checkpoint WAL after archive detach.
        connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;

        Ok(archived)
    }

    fn delete_archived_live_receipts(
        connection: &rusqlite::Connection,
        cutoff: i64,
        tenant_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        connection.execute_batch(
            r#"
            DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;
            DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
            "#,
        )?;

        let delete_result = (|| -> Result<(), ReceiptStoreError> {
            match tenant_id {
                Some(tenant_id) => {
                    connection.execute(
                        "DELETE FROM main.chio_child_receipts \
                         WHERE timestamp < ?1 \
                           AND EXISTS ( \
                               SELECT 1 \
                               FROM main.receipt_lineage_statements lineage \
                               INNER JOIN archive.chio_child_receipts archived_child \
                                   ON archived_child.receipt_id = main.chio_child_receipts.receipt_id \
                               INNER JOIN main.chio_tool_receipts parent \
                                   ON parent.receipt_id = lineage.parent_receipt_id \
                               WHERE lineage.receipt_id = main.chio_child_receipts.receipt_id \
                                 AND parent.tenant_id = ?2 \
                           )",
                        params![cutoff, tenant_id],
                    )?;
                    connection.execute(
                        "DELETE FROM main.chio_tool_receipts \
                         WHERE timestamp < ?1 \
                           AND tenant_id = ?2 \
                           AND EXISTS ( \
                               SELECT 1 \
                               FROM archive.chio_tool_receipts archived \
                               WHERE archived.receipt_id = main.chio_tool_receipts.receipt_id \
                           )",
                        params![cutoff, tenant_id],
                    )?;
                }
                None => {
                    connection.execute(
                        "DELETE FROM main.chio_child_receipts \
                         WHERE timestamp < ?1 \
                           AND EXISTS ( \
                               SELECT 1 \
                               FROM archive.chio_child_receipts archived \
                               WHERE archived.receipt_id = main.chio_child_receipts.receipt_id \
                           )",
                        params![cutoff],
                    )?;
                    connection.execute(
                        "DELETE FROM main.chio_tool_receipts \
                         WHERE timestamp < ?1 \
                           AND EXISTS ( \
                               SELECT 1 \
                               FROM archive.chio_tool_receipts archived \
                               WHERE archived.receipt_id = main.chio_tool_receipts.receipt_id \
                           )",
                        params![cutoff],
                    )?;
                }
            }
            Ok(())
        })();

        let restore_result = ensure_transparency_projection_guards(connection);
        match (delete_result, restore_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Err(delete_error), Err(restore_error)) => Err(ReceiptStoreError::Canonical(format!(
                "retention delete failed ({delete_error}); restoring receipt immutability guards also failed ({restore_error})"
            ))),
        }
    }

    /// Check time and size thresholds and archive receipts if either is exceeded.
    ///
    /// - Time threshold: receipts older than `config.retention_days` days are archived.
    /// - Size threshold: if `db_size_bytes()` exceeds `config.max_size_bytes`, receipts
    ///   older than the median timestamp are archived (removes roughly half the receipts).
    ///
    /// Returns the number of receipt rows archived (0 if no threshold was exceeded).
    pub fn rotate_if_needed(&mut self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        // Check time threshold.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let time_cutoff = now.saturating_sub(config.retention_days.saturating_mul(86_400));
        let tenant_id = config.tenant_id.as_deref();
        let oldest = match tenant_id {
            Some(tenant_id) => self.oldest_receipt_timestamp_for_tenant(tenant_id)?,
            None => self.oldest_receipt_timestamp()?,
        };

        if let Some(oldest_ts) = oldest {
            if oldest_ts < time_cutoff {
                return match tenant_id {
                    Some(tenant_id) => self.archive_receipts_before_for_tenant(
                        time_cutoff,
                        &config.archive_path,
                        tenant_id,
                    ),
                    None => self.archive_receipts_before(time_cutoff, &config.archive_path),
                };
            }
        }

        // Check size threshold.
        let size = self.db_size_bytes()?;
        if size > config.max_size_bytes {
            // Use the median timestamp as the cutoff to archive roughly half the receipts.
            let median_cutoff: Option<i64> = match tenant_id {
                Some(tenant_id) => self
                    .connection()?
                    .query_row(
                        r#"
                        SELECT timestamp FROM chio_tool_receipts
                        WHERE tenant_id = ?1
                        ORDER BY timestamp
                        LIMIT 1
                        OFFSET (SELECT COUNT(*) FROM chio_tool_receipts WHERE tenant_id = ?1) / 2
                        "#,
                        params![tenant_id],
                        |row| row.get(0),
                    )
                    .optional()?,
                None => self
                    .connection()?
                    .query_row(
                        r#"
                        SELECT timestamp FROM chio_tool_receipts
                        ORDER BY timestamp
                        LIMIT 1
                        OFFSET (SELECT COUNT(*) FROM chio_tool_receipts) / 2
                        "#,
                        [],
                        |row| row.get(0),
                    )
                    .optional()?,
            };

            if let Some(cutoff) = median_cutoff {
                return match tenant_id {
                    Some(tenant_id) => self.archive_receipts_before_for_tenant(
                        cutoff.max(0) as u64,
                        &config.archive_path,
                        tenant_id,
                    ),
                    None => {
                        self.archive_receipts_before(cutoff.max(0) as u64, &config.archive_path)
                    }
                };
            }
        }

        Ok(0)
    }

    /// Internal implementation for `query_receipts` (called from `receipt_query` module).
    ///
    /// Requires access to the private `connection` field, so it lives here in `receipt_store`.
    pub(crate) fn query_receipts_impl(
        &self,
        query: &ReceiptQuery,
    ) -> Result<ReceiptQueryResult, ReceiptStoreError> {
        // Validate the `outcome` filter against the known decision_kind values.
        // Silently accepting unknown values would return zero results and could
        // mask caller bugs; fail explicitly instead.
        const VALID_OUTCOMES: &[&str] = &["allow", "deny", "cancelled", "incomplete"];
        if let Some(outcome) = query.outcome.as_deref() {
            if !VALID_OUTCOMES.contains(&outcome) {
                return Err(ReceiptStoreError::InvalidOutcome(format!(
                    "unknown outcome filter {:?}; valid values are: allow, deny, cancelled, incomplete",
                    outcome
                )));
            }
        }

        let limit = query.limit.clamp(1, MAX_QUERY_LIMIT);

        // Phase 1.5 multi-tenant receipt isolation: compute the tenant
        // WHERE fragment. Three modes:
        //
        //   * `tenant_filter = None`           -> "1=1" (admin/compat).
        //   * `tenant_filter = Some(id)` w/ strict_tenant_isolation=true
        //     -> `tenant_id = ?X` (legacy rows hidden).
        //   * `tenant_filter = Some(id)` w/ strict_tenant_isolation=false
        //     -> `tenant_id = ?X OR tenant_id IS NULL` so legacy
        //     pre-1.5 receipts stay visible during explicit
        //     compatibility mode.
        //
        // Bound parameter ?12 carries the tenant string when present.
        // When `tenant_filter = None`, `?12 IS NULL` makes the fragment
        // a tautology and no rows are removed.
        let tenant_fragment = match (
            query.tenant_filter.as_deref(),
            self.strict_tenant_isolation_enabled(),
        ) {
            (None, _) => "(?12 IS NULL)",
            (Some(_), true) => "(r.tenant_id = ?12)",
            (Some(_), false) => "(r.tenant_id = ?12 OR r.tenant_id IS NULL)",
        };

        // Both queries share the same filter parameters.
        // Parameters:
        //   ?1  capability_id
        //   ?2  tool_server
        //   ?3  tool_name
        //   ?4  outcome (decision_kind)
        //   ?5  since (timestamp >=, inclusive)
        //   ?6  until (timestamp <=, inclusive)
        //   ?7  min_cost (json_extract cost_charged >=)
        //   ?8  max_cost (json_extract cost_charged <=)
        //   ?9  agent_subject (receipt subject_key, falling back to capability_lineage)
        //   ?12 tenant_filter (tenant_id exact match or NULL fallback)
        // Data query also uses:
        //   ?10 cursor (seq >, exclusive)
        //   ?11 limit
        //
        // When agent_subject is None, the LEFT JOIN produces NULL for cl.subject_key,
        // and the (?9 IS NULL OR ...) guard passes -- no rows are filtered out.
        let data_sql = format!(
            r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
              AND {tenant_fragment}
              AND (?10 IS NULL OR r.seq > ?10)
            ORDER BY r.seq ASC
            LIMIT ?11
        "#
        );

        // Count query uses identical WHERE clause but no cursor and no LIMIT.
        // total_count reflects the full filtered set regardless of pagination.
        let count_sql = format!(
            r#"
            SELECT COUNT(*)
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.decision_kind = ?4)
              AND (?5 IS NULL OR r.timestamp >= ?5)
              AND (?6 IS NULL OR r.timestamp <= ?6)
              AND (?7 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) >= ?7)
              AND (?8 IS NULL OR CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER) <= ?8)
              AND (?9 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?9)
              AND {tenant_fragment}
        "#
        );

        let cap_id = query.capability_id.as_deref();
        let tool_srv = query.tool_server.as_deref();
        let tool_nm = query.tool_name.as_deref();
        let outcome = query.outcome.as_deref();
        let since = query.since.map(|v| v as i64);
        let until = query.until.map(|v| v as i64);
        let min_cost = query.min_cost.map(|v| v as i64);
        let max_cost = query.max_cost.map(|v| v as i64);
        let agent_sub = query.agent_subject.as_deref();
        let tenant = query.tenant_filter.as_deref();
        // Convert cursor to signed i64 for SQLite. SQLite AUTOINCREMENT seq
        // values are bounded by i64::MAX; a cursor above that can never be
        // exceeded. Convert with a checked cast: on overflow return an empty
        // receipts page (the cursor excludes everything) while still reporting
        // the correct total_count for the uncursored filter set.
        let cursor_i64: Option<i64> = match query.cursor {
            None => None,
            Some(c) => match i64::try_from(c) {
                Ok(v) => Some(v),
                Err(_) => {
                    // cursor > i64::MAX: no AUTOINCREMENT seq can exceed it.
                    // Run only the count query (no cursor applied) and return empty.
                    // ?10 and ?11 (cursor/limit) are not used in the count query
                    // but must still bind placeholders if we reuse `params!`;
                    // the count SQL uses only ?1..=?9 and ?12, so we need to
                    // bind ?10 and ?11 as NULL / 0 to keep indexes stable.
                    let total_count: u64 = self
                        .connection()?
                        .query_row(
                            &count_sql,
                            params![
                                cap_id,
                                tool_srv,
                                tool_nm,
                                outcome,
                                since,
                                until,
                                min_cost,
                                max_cost,
                                agent_sub,
                                // ?10, ?11 unused in count_sql but bound so ?12
                                // resolves to the tenant filter.
                                None::<i64>,
                                0i64,
                                tenant,
                            ],
                            |row| row.get::<_, i64>(0),
                        )
                        .map(|n| n.max(0) as u64)?;
                    return Ok(ReceiptQueryResult {
                        receipts: Vec::new(),
                        total_count,
                        next_cursor: None,
                    });
                }
            },
        };

        // Execute data query.
        let connection = self.connection()?;
        let mut stmt = connection.prepare(&data_sql)?;
        let rows = stmt.query_map(
            params![
                cap_id,
                tool_srv,
                tool_nm,
                outcome,
                since,
                until,
                min_cost,
                max_cost,
                agent_sub,
                cursor_i64,
                limit as i64,
                tenant,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            let receipt =
                decode_verified_chio_receipt(&raw_json, "persisted tool receipt", Some(seq))?;
            receipts.push(StoredToolReceipt { seq, receipt });
        }

        // Execute count query (same filters, no cursor, no limit).
        let total_count: u64 = self
            .connection()?
            .query_row(
                &count_sql,
                params![
                    cap_id,
                    tool_srv,
                    tool_nm,
                    outcome,
                    since,
                    until,
                    min_cost,
                    max_cost,
                    agent_sub,
                    // ?10, ?11 unused in count_sql; bound to keep ?12 stable.
                    None::<i64>,
                    0i64,
                    tenant,
                ],
                |row| row.get::<_, i64>(0),
            )
            .map(|n| n.max(0) as u64)?;

        // next_cursor is Some(last_seq) when the page is full (more results may exist).
        let next_cursor = if receipts.len() == limit {
            receipts.last().map(|r| r.seq)
        } else {
            None
        };

        Ok(ReceiptQueryResult {
            receipts,
            total_count,
            next_cursor,
        })
    }
}

fn archived_tool_receipt_count<C>(
    connection: &C,
    cutoff: i64,
    tenant_id: Option<&str>,
) -> Result<i64, ReceiptStoreError>
where
    C: std::ops::Deref<Target = rusqlite::Connection>,
{
    match tenant_id {
        Some(tenant_id) => connection.query_row(
            "SELECT COUNT(*) FROM archive.chio_tool_receipts WHERE timestamp < ?1 AND tenant_id = ?2",
            params![cutoff, tenant_id],
            |row| row.get::<_, i64>(0),
        ),
        None => connection.query_row(
            "SELECT COUNT(*) FROM archive.chio_tool_receipts WHERE timestamp < ?1",
            params![cutoff],
            |row| row.get::<_, i64>(0),
        ),
    }
    .map_err(ReceiptStoreError::from)
}
