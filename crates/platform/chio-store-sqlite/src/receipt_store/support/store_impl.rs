use super::*;

/// Flatten a capability-lineage error into the receipt-store error the
/// `ReceiptStore` trait surface speaks.
fn capability_lineage_store_error(error: chio_kernel::CapabilityLineageError) -> ReceiptStoreError {
    match error {
        chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
        chio_kernel::CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
        chio_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
    }
}

/// Open the archive recorded by the live retention ledger only after the
/// archive has authenticated the entire deleted prefix. Returning an archived
/// point lookup on the strength of the ledger path alone would let a replaced
/// or incomplete archive supply governed provenance.
fn trusted_retention_archive_path(
    store: &SqliteReceiptStore,
) -> Result<Option<String>, ReceiptStoreError> {
    let connection = store.connection()?;
    let recorded = retention_watermark(&connection)?.unwrap_or(0);
    if recorded == 0 {
        return Ok(None);
    }
    let trusted = trusted_retention_watermark(&connection)?;
    if trusted != recorded {
        return Err(ReceiptStoreError::ReadBoundary(
            "configured retention archive does not authenticate the recorded prefix".to_owned(),
        ));
    }
    latest_watermark_archive_path(&connection)?.map_or_else(
        || {
            Err(ReceiptStoreError::ReadBoundary(
                "retention watermark does not name an authenticated archive".to_owned(),
            ))
        },
        |path| Ok(Some(path)),
    )
}

fn open_retention_archive(path: &str) -> Result<Connection, ReceiptStoreError> {
    Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(ReceiptStoreError::from)
}

fn load_chio_receipt_row(
    connection: &Connection,
    receipt_id: &str,
    context: &str,
) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
            params![receipt_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(seq, raw_json)| {
            decode_verified_chio_receipt(&raw_json, context, Some(seq.max(0) as u64))
        })
        .transpose()
}

fn load_receipt_lineage_statement_row(
    connection: &Connection,
    receipt_id: &str,
) -> Result<Option<chio_core::receipt::lineage::ReceiptLineageStatement>, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT raw_json FROM receipt_lineage_statements WHERE receipt_id = ?1",
            params![receipt_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|raw| serde_json::from_str(&raw).map_err(ReceiptStoreError::from))
        .transpose()
}

impl SqliteReceiptStore {
    pub fn record_session_anchor_record(
        &self,
        session_id: &str,
        anchor_id: &str,
        auth_context_fingerprint: &str,
        issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let session_id = session_id.to_string();
        let anchor_id = anchor_id.to_string();
        let auth_context_fingerprint = auth_context_fingerprint.to_string();
        let supersedes_anchor_id = supersedes_anchor_id.map(ToString::to_string);
        let anchor_json = anchor_json.clone();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            persist_session_anchor_tx(
                &tx,
                &session_id,
                &anchor_id,
                &auth_context_fingerprint,
                issued_at,
                supersedes_anchor_id.as_deref(),
                SESSION_ANCHOR_SOURCE_KIND,
                &anchor_json,
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_request_lineage_record(
        &self,
        session_id: &str,
        request_id: &str,
        parent_request_id: Option<&str>,
        session_anchor_id: Option<&str>,
        recorded_at: u64,
        request_fingerprint: Option<&str>,
        lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let session_id = session_id.to_string();
        let request_id = request_id.to_string();
        let parent_request_id = parent_request_id.map(ToString::to_string);
        let session_anchor_id = session_anchor_id.map(ToString::to_string);
        let request_fingerprint = request_fingerprint.map(ToString::to_string);
        let lineage_json = lineage_json.clone();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            persist_request_lineage_tx(
                &tx,
                &session_id,
                &request_id,
                parent_request_id.as_deref(),
                session_anchor_id.as_deref(),
                recorded_at,
                request_fingerprint.as_deref(),
                REQUEST_LINEAGE_SOURCE_KIND,
                &lineage_json,
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record_receipt_lineage_statement_record(
        &self,
        child_receipt_id: &str,
        request_id: Option<&str>,
        session_id: Option<&str>,
        session_anchor_id: Option<&str>,
        parent_request_id: Option<&str>,
        parent_receipt_id: Option<&str>,
        chain_id: Option<&str>,
        recorded_at: u64,
        statement_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        let child_receipt_id = child_receipt_id.to_string();
        let request_id = request_id.map(ToString::to_string);
        let session_id = session_id.map(ToString::to_string);
        let session_anchor_id = session_anchor_id.map(ToString::to_string);
        let parent_request_id = parent_request_id.map(ToString::to_string);
        let parent_receipt_id = parent_receipt_id.map(ToString::to_string);
        let chain_id = chain_id.map(ToString::to_string);
        let statement_json = statement_json.clone();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            persist_receipt_lineage_statement_tx(
                &tx,
                &child_receipt_id,
                request_id.as_deref(),
                session_id.as_deref(),
                session_anchor_id.as_deref(),
                parent_request_id.as_deref(),
                parent_receipt_id.as_deref(),
                chain_id.as_deref(),
                recorded_at,
                RECEIPT_LINEAGE_SOURCE_KIND,
                &statement_json,
            )?;
            tx.commit()?;
            Ok(())
        })
    }

    pub fn list_receipt_lineage_statement_links(
        &self,
        receipt_id: &str,
    ) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
        let receipt_id = receipt_id.to_string();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt_id)?;
            refresh_receipt_lineage_rows_for_parent_receipt_tx(&tx, &receipt_id)?;
            let links = load_receipt_lineage_statement_links(&tx, &receipt_id)?;
            tx.commit()?;
            Ok(links)
        })
    }

    pub fn receipt_lineage_statement(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::lineage::ReceiptLineageStatement>, ReceiptStoreError>
    {
        let receipt_id = receipt_id.to_string();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt_id)?;
            let raw = tx
                .query_row(
                    "SELECT raw_json FROM receipt_lineage_statements WHERE receipt_id = ?1",
                    params![&receipt_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let statement = raw
                .map(|raw| {
                    serde_json::from_str::<chio_core::receipt::lineage::ReceiptLineageStatement>(
                        &raw,
                    )
                    .map_err(ReceiptStoreError::from)
                })
                .transpose()?;
            tx.commit()?;
            Ok(statement)
        })
    }

    pub fn receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        let receipt_id = receipt_id.to_string();
        self.writer_handle().run_write(move |connection| {
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt_id)?;
            let verification = load_receipt_lineage_verification(&tx, &receipt_id)?;
            tx.commit()?;
            Ok(verification)
        })
    }

    pub fn append_child_receipt_record(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_child_receipt_verified(receipt)?;
        let job = Self::build_child_receipt_write_job(receipt)?;
        self.writer_handle().run_write_receipt(job)
    }

    /// Deadline-bounded variant of [`append_child_receipt_record`]. Fails closed
    /// with `ReceiptStoreError::Timeout` if the commit round trip exceeds
    /// `budget`, so a wedged writer cannot pin the kernel-wide receipt write lock
    /// while nested-flow child receipts drain.
    pub fn append_child_receipt_record_with_timeout(
        &self,
        receipt: &ChildRequestReceipt,
        budget: std::time::Duration,
    ) -> Result<u64, ReceiptStoreError> {
        ensure_child_receipt_verified(receipt)?;
        let job = Self::build_child_receipt_write_job(receipt)?;
        self.writer_handle()
            .run_write_receipt_with_timeout(job, budget)
    }

    /// Build the single-writer transaction that inserts one child receipt and
    /// its request-lineage row, returning the assigned claim-log entry seq. The
    /// job owns cloned receipt data so it can run bounded or unbounded on the
    /// commit actor.
    fn build_child_receipt_write_job(
        receipt: &ChildRequestReceipt,
    ) -> Result<
        impl FnOnce(&mut SqliteStoreConnection) -> Result<u64, ReceiptStoreError> + Send + 'static,
        ReceiptStoreError,
    > {
        let raw_json = serde_json::to_string(receipt)?;
        let lineage_json = child_receipt_request_lineage_json(receipt)?;
        let receipt = receipt.clone();
        Ok(move |connection: &mut SqliteStoreConnection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let inserted = tx.execute(
                r#"
                INSERT INTO chio_child_receipts (
                    receipt_id,
                    timestamp,
                    session_id,
                    parent_request_id,
                    request_id,
                    operation_kind,
                    terminal_state,
                    policy_hash,
                    outcome_hash,
                    raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
                params![
                    receipt.id,
                    sqlite_i64(receipt.timestamp, "child receipt timestamp")?,
                    receipt.session_id.as_str(),
                    receipt.parent_request_id.as_str(),
                    receipt.request_id.as_str(),
                    receipt.operation_kind.as_str(),
                    terminal_state_kind(&receipt.terminal_state),
                    receipt.policy_hash,
                    receipt.outcome_hash,
                    &raw_json,
                ],
            )?;
            if inserted == 0 {
                let (existing_source_seq, existing_raw_json) = tx.query_row(
                    "SELECT seq, raw_json FROM chio_child_receipts WHERE receipt_id = ?1",
                    params![receipt.id.as_str()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
                )?;
                if existing_raw_json != raw_json {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "child receipt `{}` already exists with different content",
                        receipt.id
                    )));
                }
                let existing_source_seq =
                    sqlite_positive_u64(existing_source_seq, "child receipt source_seq")?;
                let entry_seq =
                    claim_log_entry_seq_for_source_tx(&tx, "child_receipt", existing_source_seq)?;
                tx.commit()?;
                return Ok(entry_seq);
            }
            let source_seq = tx.query_row(
                "SELECT seq FROM chio_child_receipts WHERE receipt_id = ?1",
                params![receipt.id.as_str()],
                |row| row.get::<_, i64>(0),
            )?;
            let source_seq = sqlite_positive_u64(source_seq, "child receipt source_seq")?;
            let entry_seq = claim_log_entry_seq_for_source_tx(&tx, "child_receipt", source_seq)?;
            persist_request_lineage_tx(
                &tx,
                receipt.session_id.as_str(),
                receipt.request_id.as_str(),
                Some(receipt.parent_request_id.as_str()),
                None,
                receipt.timestamp,
                None,
                CHILD_RECEIPT_BACKFILL_SOURCE_KIND,
                &lineage_json,
            )?;
            tx.commit()?;
            Ok(entry_seq)
        })
    }

    fn build_pending_observation_write_job(
        receipt: &ChioReceipt,
        pending: &PendingSettlementObservation,
    ) -> Result<
        impl FnOnce(&mut SqliteStoreConnection) -> Result<u64, ReceiptStoreError> + Send + 'static,
        ReceiptStoreError,
    > {
        ensure_chio_receipt_verified(receipt)?;
        sqlite_i64(receipt.timestamp, "receipt timestamp")?;
        sqlite_i64(
            pending.next_visible_at_ms,
            "settlement attempt visibility deadline",
        )?;
        let raw_json = serde_json::to_string(receipt)?;
        let receipt = receipt.clone();
        let next_visible_at_ms = pending.next_visible_at_ms;
        Ok(move |connection: &mut SqliteStoreConnection| {
            ensure_checkpoint_transparency_guards(connection)?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (seq, inserted) =
                append_chio_receipt_tx_with_insert_status(&tx, &receipt, &raw_json)?;
            ensure_receipt_lineage_statement_for_receipt_id_tx(&tx, &receipt.id)?;
            if inserted {
                crate::settle_attempts::insert_attempt_zero_tx(
                    &tx,
                    &receipt.id,
                    receipt.timestamp,
                    next_visible_at_ms,
                )?;
            } else {
                let settlement_obligation_exists = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM settle_attempts WHERE receipt_id = ?1 \
                     UNION ALL SELECT 1 FROM settle_dead_letters WHERE receipt_id = ?1)",
                    [receipt.id.as_str()],
                    |row| row.get::<_, bool>(0),
                )?;
                if !settlement_obligation_exists {
                    return Err(ReceiptStoreError::Conflict(format!(
                        "receipt `{}` exists without a settlement obligation",
                        receipt.id
                    )));
                }
            }
            tx.commit()?;
            Ok(seq)
        })
    }
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt).map(|_| ())
    }

    fn settlement_store_binding(&self) -> Option<chio_settle::SettlementStoreBinding> {
        self.settlement_store_binding
    }

    fn atomic_receipt_projection(&self) -> AtomicReceiptProjection {
        if self.settlement_store_binding.is_some() {
            AtomicReceiptProjection::SettlementObservationV1
        } else {
            AtomicReceiptProjection::Unsupported
        }
    }

    fn supports_atomic_receipt_projection_with_timeout(&self) -> bool {
        self.settlement_store_binding.is_some()
    }

    fn append_chio_receipt_with_pending_observation(
        &self,
        receipt: &ChioReceipt,
        pending: &PendingSettlementObservation,
    ) -> Result<(), ReceiptStoreError> {
        if self.settlement_store_binding.is_none() {
            return Err(ReceiptStoreError::Unsupported(
                "atomic settlement observation projection".to_string(),
            ));
        }
        let job = Self::build_pending_observation_write_job(receipt, pending)?;
        self.writer_handle()
            .run_critical_receipt_write(job)
            .map(|_| ())
    }

    fn append_chio_receipt_with_pending_observation_and_timeout(
        &self,
        receipt: &ChioReceipt,
        pending: &PendingSettlementObservation,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        if self.settlement_store_binding.is_none() {
            return Err(ReceiptStoreError::Unsupported(
                "atomic settlement observation projection".to_string(),
            ));
        }
        let job = Self::build_pending_observation_write_job(receipt, pending)?;
        self.writer_handle()
            .run_critical_receipt_write_with_timeout(job, budget)
            .map(Some)
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        connection
            .query_row(
                "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(seq, raw_json)| {
                decode_verified_chio_receipt(
                    &raw_json,
                    "persisted tool receipt",
                    Some(seq.max(0) as u64),
                )
            })
            .transpose()
    }

    fn load_retained_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        let Some(archive_path) = trusted_retention_archive_path(self)? else {
            return self.load_chio_receipt(receipt_id);
        };
        let connection = self.connection()?;
        if let Some(receipt) =
            load_chio_receipt_row(&connection, receipt_id, "retained live tool receipt")?
        {
            return Ok(Some(receipt));
        }
        drop(connection);
        let archive = open_retention_archive(&archive_path)?;
        load_chio_receipt_row(&archive, receipt_id, "retained archived tool receipt")
    }

    fn load_child_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_latest_checkpoint_integrity(&connection)?;
        connection
            .query_row(
                "SELECT seq, raw_json FROM chio_child_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(seq, raw_json)| {
                decode_verified_child_receipt(
                    &raw_json,
                    "persisted child receipt",
                    Some(seq.max(0) as u64),
                )
            })
            .transpose()
    }

    fn append_chio_receipt_canonical(
        &self,
        _receipt: &ChioReceipt,
        canonical: &CanonicalBytes,
    ) -> Result<(), ReceiptStoreError> {
        let decoded = decode_canonical_chio_receipt(canonical)?;
        let raw_json = canonical_receipt_json(canonical)?;
        self.append_verified_chio_receipt_record(&decoded, raw_json, true)?;
        Ok(())
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let seq = self.append_verified_chio_receipt_record(receipt, &raw_json, true)?;
        Ok(Some(seq))
    }

    fn append_chio_receipt_with_timeout(
        &self,
        receipt: &ChioReceipt,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let seq = self
            .append_verified_chio_receipt_record_with_timeout(receipt, &raw_json, true, budget)?;
        Ok(Some(seq))
    }

    fn writer_liveness(
        &self,
        stall_threshold: std::time::Duration,
    ) -> chio_kernel::ReceiptWriterLiveness {
        SqliteReceiptStore::writer_liveness(self, stall_threshold)
    }

    fn append_chio_receipt_consuming_authorization(
        &self,
        receipt: &ChioReceipt,
        consumption: &AuthorizationReceiptConsumption,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::append_chio_receipt_consuming_authorization(self, receipt, consumption)
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        SqliteReceiptStore::receipts_canonical_bytes_range(self, start_seq, end_seq)
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        SqliteReceiptStore::flush_receipt_writes(self)
    }

    fn flush_receipt_writes_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        SqliteReceiptStore::flush_receipt_writes_with_timeout(self, timeout)
    }

    fn receipt_store_health(&self) -> Result<ReceiptStoreHealthReport, ReceiptStoreError> {
        SqliteReceiptStore::receipt_store_health(self)
    }

    fn writer_serving_closed(&self) -> bool {
        SqliteReceiptStore::writer_serving_closed(self)
    }

    fn latest_committed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        SqliteReceiptStore::latest_committed_entry_seq(self)
    }

    fn latest_checkpointed_entry_seq(&self) -> Result<u64, ReceiptStoreError> {
        SqliteReceiptStore::latest_checkpointed_entry_seq(self)
    }

    fn next_checkpoint_range(
        &self,
        max_batch: u64,
    ) -> Result<Option<ReceiptCheckpointRange>, ReceiptStoreError> {
        SqliteReceiptStore::next_checkpoint_range(self, max_batch)
    }

    fn receipt_checkpoint_status(
        &self,
        max_batch: Option<u64>,
    ) -> Result<ReceiptCheckpointStatusReport, ReceiptStoreError> {
        SqliteReceiptStore::receipt_checkpoint_status(self, max_batch)
    }

    fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::store_checkpoint(self, checkpoint)
    }

    fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        SqliteReceiptStore::create_next_receipt_checkpoint(self, max_batch, keypair)
    }

    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        SqliteReceiptStore::load_checkpoint_by_seq(self, checkpoint_seq)
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let connection = self.connection()?;
        ensure_checkpoint_transparency_guards(&connection)?;
        verify_checkpoint_chain_integrity(&connection)?;
        load_latest_persisted_checkpoint_row(&connection)?
            .map(parse_persisted_checkpoint_row)
            .transpose()
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn enable_background_checkpoints(
        &self,
        keypair: Keypair,
        max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        SqliteReceiptStore::enable_background_checkpoints(
            self,
            crate::receipt_store::BackgroundCheckpointSigner {
                keypair: std::sync::Arc::new(keypair),
                max_batch,
            },
        )
        .map(|()| true)
    }

    fn supports_retention(&self) -> bool {
        true
    }

    fn rotate_receipts(&self, config: &RetentionConfig) -> Result<u64, ReceiptStoreError> {
        self.rotate_if_needed(config)
    }

    fn record_retention_rotation_outcome(&self, failure: Option<&str>) {
        SqliteReceiptStore::record_retention_rotation_outcome(self, failure)
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::record_capability_snapshot(self, token, parent_capability_id)
            .map_err(capability_lineage_store_error)
    }

    fn record_capability_snapshot_with_timeout(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
        budget: std::time::Duration,
    ) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::record_capability_snapshot_with_timeout(
            self,
            token,
            parent_capability_id,
            budget,
        )
        .map_err(capability_lineage_store_error)
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        // Admission resolves only exact signed-token projections. Synthetic
        // federation anchors, legacy rows, and imported evidence remain
        // available through explicit lineage/reporting APIs but are not roots
        // of authority for a live kernel evaluation.
        let snapshot =
            SqliteReceiptStore::get_lineage(self, capability_id).map_err(|error| match error {
                chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
                chio_kernel::CapabilityLineageError::Sqlite(error) => {
                    ReceiptStoreError::Sqlite(error)
                }
                chio_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            })?;
        Ok(snapshot.filter(|snapshot| {
            snapshot.provenance == chio_kernel::CapabilitySnapshotProvenance::SignedToken
        }))
    }

    fn get_capability_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        let chain =
            SqliteReceiptStore::get_delegation_chain(self, capability_id).map_err(|error| {
                match error {
                    chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
                    chio_kernel::CapabilityLineageError::Sqlite(error) => {
                        ReceiptStoreError::Sqlite(error)
                    }
                    chio_kernel::CapabilityLineageError::Json(error) => {
                        ReceiptStoreError::Json(error)
                    }
                }
            })?;
        let complete_signed_chain = chain.is_empty()
            || (chain.first().is_some_and(|root| {
                root.provenance == chio_kernel::CapabilitySnapshotProvenance::SignedToken
                    && root.parent_capability_id.is_none()
                    && root.delegation_depth == 0
            }) && chain.windows(2).all(|pair| {
                let parent = &pair[0];
                let child = &pair[1];
                child.provenance == chio_kernel::CapabilitySnapshotProvenance::SignedToken
                    && child.parent_capability_id.as_deref() == Some(parent.capability_id.as_str())
                    && parent
                        .delegation_depth
                        .checked_add(1)
                        .is_some_and(|depth| child.delegation_depth == depth)
            }) && chain
                .last()
                .is_some_and(|leaf| leaf.capability_id == capability_id));
        if complete_signed_chain {
            Ok(chain)
        } else {
            Ok(Vec::new())
        }
    }

    fn record_session_anchor(
        &self,
        session_id: &str,
        anchor_id: &str,
        auth_context_fingerprint: &str,
        issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.record_session_anchor_record(
            session_id,
            anchor_id,
            auth_context_fingerprint,
            issued_at,
            supersedes_anchor_id,
            anchor_json,
        )
    }

    fn record_request_lineage(
        &self,
        session_id: &str,
        request_id: &str,
        parent_request_id: Option<&str>,
        session_anchor_id: Option<&str>,
        recorded_at: u64,
        request_fingerprint: Option<&str>,
        lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.record_request_lineage_record(
            session_id,
            request_id,
            parent_request_id,
            session_anchor_id,
            recorded_at,
            request_fingerprint,
            lineage_json,
        )
    }

    fn record_receipt_lineage_statement(
        &self,
        child_receipt_id: &str,
        request_id: Option<&str>,
        session_id: Option<&str>,
        session_anchor_id: Option<&str>,
        parent_request_id: Option<&str>,
        parent_receipt_id: Option<&str>,
        chain_id: Option<&str>,
        recorded_at: u64,
        statement_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.record_receipt_lineage_statement_record(
            child_receipt_id,
            request_id,
            session_id,
            session_anchor_id,
            parent_request_id,
            parent_receipt_id,
            chain_id,
            recorded_at,
            statement_json,
        )
    }

    fn get_receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        self.receipt_lineage_verification(receipt_id)
    }

    fn get_retained_receipt_lineage_verification(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ReceiptLineageVerification>, ReceiptStoreError> {
        let Some(archive_path) = trusted_retention_archive_path(self)? else {
            return self.get_receipt_lineage_verification(receipt_id);
        };
        let connection = self.connection()?;
        if let Some(verification) = load_receipt_lineage_verification(&connection, receipt_id)? {
            return Ok(Some(verification));
        }
        drop(connection);
        let archive = open_retention_archive(&archive_path)?;
        load_receipt_lineage_verification(&archive, receipt_id)
    }

    fn list_receipt_lineage_statement_links(
        &self,
        receipt_id: &str,
    ) -> Result<Vec<ReceiptLineageStatementLink>, ReceiptStoreError> {
        SqliteReceiptStore::list_receipt_lineage_statement_links(self, receipt_id)
    }

    fn load_receipt_lineage_statement(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::lineage::ReceiptLineageStatement>, ReceiptStoreError>
    {
        self.receipt_lineage_statement(receipt_id)
    }

    fn load_retained_receipt_lineage_statement(
        &self,
        receipt_id: &str,
    ) -> Result<Option<chio_core::receipt::lineage::ReceiptLineageStatement>, ReceiptStoreError>
    {
        let Some(archive_path) = trusted_retention_archive_path(self)? else {
            return self.load_receipt_lineage_statement(receipt_id);
        };
        let connection = self.connection()?;
        if let Some(statement) = load_receipt_lineage_statement_row(&connection, receipt_id)? {
            return Ok(Some(statement));
        }
        drop(connection);
        let archive = open_retention_archive(&archive_path)?;
        load_receipt_lineage_statement_row(&archive, receipt_id)
    }

    fn as_any_mut(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        self.query_credit_bonds(&CreditBondListQuery {
            bond_id: Some(bond_id.to_string()),
            facility_id: None,
            capability_id: None,
            agent_subject: None,
            tool_server: None,
            tool_name: None,
            disposition: None,
            lifecycle_state: None,
            limit: Some(1),
        })
        .map(|report| report.bonds.into_iter().next())
    }

    fn append_child_receipt(&self, receipt: &ChildRequestReceipt) -> Result<(), ReceiptStoreError> {
        SqliteReceiptStore::append_child_receipt_record(self, receipt).map(|_| ())
    }

    fn append_child_receipt_returning_seq(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        SqliteReceiptStore::append_child_receipt_record(self, receipt).map(Some)
    }

    fn append_child_receipt_with_timeout(
        &self,
        receipt: &ChildRequestReceipt,
        budget: std::time::Duration,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        SqliteReceiptStore::append_child_receipt_record_with_timeout(self, receipt, budget)
            .map(Some)
    }
}

impl SqliteReceiptStore {
    pub fn record_checkpoint_publication_trust_anchor_binding(
        &self,
        checkpoint_seq: u64,
        binding: &chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding,
    ) -> Result<(), ReceiptStoreError> {
        binding
            .validate()
            .map_err(|error| ReceiptStoreError::Conflict(error.to_string()))?;
        let checkpoint = self
            .load_checkpoint_by_seq(checkpoint_seq)?
            .ok_or_else(|| {
                ReceiptStoreError::NotFound(format!(
                    "checkpoint {} does not exist for publication binding",
                    checkpoint_seq
                ))
            })?;
        let publication = chio_kernel::checkpoint::build_trust_anchored_checkpoint_publication(
            &checkpoint,
            binding.clone(),
        )
        .map_err(checkpoint_error_to_receipt_store)?;
        let normalized_binding = publication.trust_anchor_binding.ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "checkpoint {} trust-anchor binding was not preserved during validation",
                checkpoint_seq
            ))
        })?;

        self.writer_handle().run_write(move |connection| {
            ensure_checkpoint_transparency_guards(connection)?;
            ensure_transparency_projection_guards(connection)?;

            let existing = connection
                .query_row(
                    r#"
                SELECT binding_json
                FROM checkpoint_publication_trust_anchor_bindings
                WHERE checkpoint_seq = ?1
                "#,
                    params![sqlite_i64(checkpoint_seq, "checkpoint_seq")?],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match existing {
                Some(binding_json) => {
                    let existing_binding: chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding =
                        serde_json::from_str(&binding_json)?;
                    if existing_binding == normalized_binding {
                        return Ok(());
                    }
                    Err(ReceiptStoreError::Conflict(format!(
                        "checkpoint {} already has a different trust-anchor publication binding",
                        checkpoint_seq
                    )))
                }
                None => {
                    connection.execute(
                        r#"
                    INSERT INTO checkpoint_publication_trust_anchor_bindings (
                        checkpoint_seq,
                        binding_json
                    ) VALUES (?1, ?2)
                    "#,
                        params![
                            sqlite_i64(checkpoint_seq, "checkpoint_seq")?,
                            serde_json::to_string(&normalized_binding)?,
                        ],
                    )?;
                    Ok(())
                }
            }
        })
    }
}

pub(crate) fn decision_kind(decision: Option<&Decision>) -> &'static str {
    match decision {
        Some(Decision::Allow) => "allow",
        Some(Decision::Deny { .. }) => "deny",
        Some(Decision::Cancelled { .. }) => "cancelled",
        Some(Decision::Incomplete { .. }) => "incomplete",
        None => "none",
    }
}

pub(crate) fn receipt_decision_kind(receipt: &ChioReceipt) -> &'static str {
    let semantics = receipt.semantic_fields();
    if !semantics.is_authorized(receipt.decision.as_ref())
        && matches!(&receipt.decision, Some(Decision::Allow))
    {
        return semantics.receipt_kind.as_str();
    }
    match receipt.decision.as_ref() {
        Some(decision) => decision_kind(Some(decision)),
        None => semantics.receipt_kind.as_str(),
    }
}

pub(crate) fn terminal_state_kind(state: &OperationTerminalState) -> &'static str {
    match state {
        OperationTerminalState::Completed => "completed",
        OperationTerminalState::Cancelled { .. } => "cancelled",
        OperationTerminalState::Incomplete { .. } => "incomplete",
    }
}
