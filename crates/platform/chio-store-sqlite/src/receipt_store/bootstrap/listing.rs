use super::*;

impl SqliteReceiptStore {
    pub fn tool_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count =
            self.connection()?
                .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
                    row.get::<_, i64>(0)
                })?;
        sqlite_u64(count, "chio_tool_receipts count")
    }

    pub fn child_receipt_count(&self) -> Result<u64, ReceiptStoreError> {
        let count = self.connection()?.query_row(
            "SELECT COUNT(*) FROM chio_child_receipts",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        sqlite_u64(count, "chio_child_receipts count")
    }

    pub(crate) fn load_underwriting_appeals_by_decision(
        &self,
    ) -> Result<BTreeMap<String, Vec<UnderwritingAppealRecord>>, ReceiptStoreError> {
        let mut appeals_by_decision = BTreeMap::new();
        let connection = self.connection()?;
        for appeal in load_underwriting_appeal_rows(&connection)? {
            appeals_by_decision
                .entry(appeal.decision_id.clone())
                .or_insert_with(Vec::new)
                .push(appeal);
        }
        Ok(appeals_by_decision)
    }

    pub fn list_tool_receipts(
        &self,
        limit: usize,
        capability_id: Option<&str>,
        tool_server: Option<&str>,
        tool_name: Option<&str>,
        decision_kind: Option<&str>,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_tool_receipts
            WHERE (?1 IS NULL OR capability_id = ?1)
              AND (?2 IS NULL OR tool_server = ?2)
              AND (?3 IS NULL OR tool_name = ?3)
              AND (?4 IS NULL OR decision_kind = ?4)
            ORDER BY seq DESC
            LIMIT ?5
            "#,
        )?;
        let rows = statement.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                decision_kind,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )
        })
        .collect()
    }

    pub fn list_tool_receipts_with_context(
        &self,
        read_context: &ReceiptReadContext,
        limit: usize,
        capability_id: Option<&str>,
        tool_server: Option<&str>,
        tool_name: Option<&str>,
        decision_kind: Option<&str>,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        require_admin_list_context(read_context, "tool receipt admin list")?;
        self.list_tool_receipts(limit, capability_id, tool_server, tool_name, decision_kind)
    }

    /// List all tool receipts attributed to a given subject public key.
    ///
    /// Uses the persisted `subject_key` column when present and falls back to
    /// the capability lineage join for older rows.
    pub fn list_tool_receipts_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT r.seq, r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            WHERE COALESCE(r.subject_key, cl.subject_key) = ?1
            ORDER BY r.timestamp ASC, r.seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![subject_key], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(seq.max(0) as u64),
            )
        })
        .collect()
    }

    pub fn list_tool_receipts_for_subject_with_context(
        &self,
        read_context: &ReceiptReadContext,
        subject_key: &str,
    ) -> Result<Vec<ChioReceipt>, ReceiptStoreError> {
        require_admin_list_context(read_context, "subject receipt reputation read")?;
        self.list_tool_receipts_for_subject(subject_key)
    }

    pub fn list_tool_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredToolReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_tool_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            Ok(StoredToolReceipt {
                seq,
                receipt: decode_verified_chio_receipt(
                    &raw_json,
                    "persisted tool receipt",
                    Some(seq),
                )?,
            })
        })
        .collect()
    }

    pub fn list_tool_receipts_after_seq_with_context(
        &self,
        read_context: &ReceiptReadContext,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredToolReceipt>, ReceiptStoreError> {
        require_admin_list_context(read_context, "tool receipt replication read")?;
        self.list_tool_receipts_after_seq(after_seq, limit)
    }

    pub fn list_child_receipts(
        &self,
        limit: usize,
        session_id: Option<&str>,
        parent_request_id: Option<&str>,
        request_id: Option<&str>,
        operation_kind: Option<&str>,
        terminal_state: Option<&str>,
    ) -> Result<Vec<ChildRequestReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_child_receipts
            WHERE (?1 IS NULL OR session_id = ?1)
              AND (?2 IS NULL OR parent_request_id = ?2)
              AND (?3 IS NULL OR request_id = ?3)
              AND (?4 IS NULL OR operation_kind = ?4)
              AND (?5 IS NULL OR terminal_state = ?5)
            ORDER BY seq DESC
            LIMIT ?6
            "#,
        )?;
        let rows = statement.query_map(
            params![
                session_id,
                parent_request_id,
                request_id,
                operation_kind,
                terminal_state,
                limit as i64,
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            decode_verified_child_receipt(
                &raw_json,
                "persisted child receipt",
                Some(seq.max(0) as u64),
            )
        })
        .collect()
    }

    // Six optional SQL filter columns plus the admin read context; the
    // positional list mirrors list_child_receipts by design.
    #[allow(clippy::too_many_arguments)]
    pub fn list_child_receipts_with_context(
        &self,
        read_context: &ReceiptReadContext,
        limit: usize,
        session_id: Option<&str>,
        parent_request_id: Option<&str>,
        request_id: Option<&str>,
        operation_kind: Option<&str>,
        terminal_state: Option<&str>,
    ) -> Result<Vec<ChildRequestReceipt>, ReceiptStoreError> {
        require_admin_list_context(read_context, "child receipt admin list")?;
        self.list_child_receipts(
            limit,
            session_id,
            parent_request_id,
            request_id,
            operation_kind,
            terminal_state,
        )
    }

    pub fn list_child_receipts_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredChildReceipt>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_child_receipts
            WHERE seq > ?1
            ORDER BY seq ASC
            LIMIT ?2
            "#,
        )?;
        let rows = statement.query_map(params![after_seq as i64, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            Ok(StoredChildReceipt {
                seq,
                receipt: decode_verified_child_receipt(
                    &raw_json,
                    "persisted child receipt",
                    Some(seq),
                )?,
            })
        })
        .collect()
    }

    pub fn list_child_receipts_after_seq_with_context(
        &self,
        read_context: &ReceiptReadContext,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredChildReceipt>, ReceiptStoreError> {
        require_admin_list_context(read_context, "child receipt replication read")?;
        self.list_child_receipts_after_seq(after_seq, limit)
    }
}
