impl SqliteReceiptStore {
    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ReceiptStoreError> {
        self.connection.lock().map_err(|_| {
            ReceiptStoreError::Conflict("sqlite receipt store lock poisoned".to_string())
        })
    }

    fn load_checkpoint_by_seq_locked(
        connection: &Connection,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        connection
            .query_row(
                "SELECT raw_json FROM kernel_checkpoints WHERE checkpoint_seq = ?1",
                params![checkpoint_seq as i64],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|raw_json| serde_json::from_str(&raw_json))
            .transpose()
            .map_err(Into::into)
    }

    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let connection = self.connection()?;
        Self::load_checkpoint_by_seq_locked(&connection, checkpoint_seq)
    }

    fn flip_status_on_checkpoint(&self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        *self
            .checkpoint_status_flip
            .lock()
            .expect("checkpoint status flip lock") = Some(flag);
    }

    fn load_chio_receipt_for_test(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        self.connection()?
            .query_row(
                "SELECT raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|raw| serde_json::from_str(&raw).map_err(ReceiptStoreError::from))
            .transpose()
    }

    fn load_retained_chio_receipt_commitment_for_test(
        &self,
        receipt_id: &str,
    ) -> Result<Option<crate::receipt_store::RetainedReceiptCommitment>, ReceiptStoreError> {
        let connection = self.connection()?;
        let row = connection
            .query_row(
                "SELECT seq, raw_json FROM chio_tool_receipts WHERE receipt_id = ?1",
                params![receipt_id],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((entry_seq, raw)) = row else {
            return Ok(None);
        };
        let entry_seq = entry_seq.max(0) as u64;
        let checkpoint = Self::load_latest_checkpoint_locked(&connection)?.ok_or_else(|| {
            ReceiptStoreError::ReadBoundary("retained test receipt is not checkpointed".to_owned())
        })?;
        if entry_seq < checkpoint.body.batch_start_seq || entry_seq > checkpoint.body.batch_end_seq {
            return Err(ReceiptStoreError::ReadBoundary(
                "retained test receipt is outside the latest checkpoint".to_owned(),
            ));
        }
        let receipt: ChioReceipt = serde_json::from_str(&raw)?;
        let canonical = canonical_json_bytes(&receipt)
            .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
        Ok(Some(crate::receipt_store::RetainedReceiptCommitment {
            entry_seq,
            receipt_id: receipt.id,
            receipt_sha256: chio_core::crypto::sha256_hex(&canonical),
            kernel_key: receipt.kernel_key,
        }))
    }

    fn create_next_receipt_checkpoint_with_status_flip(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        let connection = self.connection()?;
        let report = Self::create_next_receipt_checkpoint_locked(&connection, max_batch, keypair)?;
        if let Some(flag) = self
            .checkpoint_status_flip
            .lock()
            .map_err(|_| {
                ReceiptStoreError::Conflict("checkpoint status flip lock poisoned".to_owned())
            })?
            .as_ref()
        {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(report)
    }
}
