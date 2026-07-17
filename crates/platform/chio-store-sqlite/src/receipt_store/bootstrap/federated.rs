use super::*;

impl SqliteReceiptStore {
    pub fn import_federated_evidence_share(
        &mut self,
        import: &FederatedEvidenceShareImport,
    ) -> Result<FederatedEvidenceShareSummary, ReceiptStoreError> {
        let imported_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let import_owned = import.clone();
        self.writer_handle().run_write(move |connection| {
            let import = &import_owned;
            let tx = connection.transaction()?;
            tx.execute(
                r#"
            INSERT INTO federated_evidence_shares (
                share_id,
                manifest_hash,
                imported_at,
                exported_at,
                issuer,
                partner,
                signer_public_key,
                require_proofs,
                query_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            ON CONFLICT(share_id) DO UPDATE SET
                manifest_hash = excluded.manifest_hash,
                imported_at = excluded.imported_at,
                exported_at = excluded.exported_at,
                issuer = excluded.issuer,
                partner = excluded.partner,
                signer_public_key = excluded.signer_public_key,
                require_proofs = excluded.require_proofs,
                query_json = excluded.query_json
            "#,
                params![
                    import.share_id,
                    import.manifest_hash,
                    imported_at as i64,
                    import.exported_at as i64,
                    import.issuer,
                    import.partner,
                    import.signer_public_key,
                    if import.require_proofs { 1_i64 } else { 0_i64 },
                    import.query_json,
                ],
            )?;

            let lineage_by_capability = import
                .capability_lineage
                .iter()
                .map(|snapshot| (snapshot.capability_id.as_str(), snapshot))
                .collect::<BTreeMap<_, _>>();

            for snapshot in &import.capability_lineage {
                tx.execute(
                    r#"
                INSERT INTO federated_share_capability_lineage (
                    share_id,
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(share_id, capability_id) DO UPDATE SET
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    issued_at = excluded.issued_at,
                    expires_at = excluded.expires_at,
                    grants_json = excluded.grants_json,
                    delegation_depth = excluded.delegation_depth,
                    parent_capability_id = excluded.parent_capability_id
                "#,
                    params![
                        import.share_id,
                        snapshot.capability_id,
                        snapshot.subject_key,
                        snapshot.issuer_key,
                        snapshot.issued_at as i64,
                        snapshot.expires_at as i64,
                        snapshot.grants_json,
                        snapshot.delegation_depth as i64,
                        snapshot.parent_capability_id,
                    ],
                )?;
            }

            for record in &import.tool_receipts {
                let attribution = extract_receipt_attribution(&record.receipt);
                let lineage_subject = lineage_by_capability
                    .get(record.receipt.capability_id.as_str())
                    .map(|snapshot| snapshot.subject_key.as_str());
                let lineage_issuer = lineage_by_capability
                    .get(record.receipt.capability_id.as_str())
                    .map(|snapshot| snapshot.issuer_key.as_str());
                tx.execute(
                    r#"
                INSERT INTO federated_share_tool_receipts (
                    share_id,
                    seq,
                    receipt_id,
                    timestamp,
                    capability_id,
                    subject_key,
                    issuer_key,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                ON CONFLICT(share_id, seq) DO UPDATE SET
                    receipt_id = excluded.receipt_id,
                    timestamp = excluded.timestamp,
                    capability_id = excluded.capability_id,
                    subject_key = excluded.subject_key,
                    issuer_key = excluded.issuer_key,
                    raw_json = excluded.raw_json
                "#,
                    params![
                        import.share_id,
                        record.seq as i64,
                        record.receipt.id,
                        record.receipt.timestamp as i64,
                        record.receipt.capability_id,
                        attribution
                            .subject_key
                            .or_else(|| lineage_subject.map(ToOwned::to_owned)),
                        attribution
                            .issuer_key
                            .or_else(|| lineage_issuer.map(ToOwned::to_owned)),
                        serde_json::to_string(&record.receipt)?,
                    ],
                )?;
            }

            tx.commit()?;

            Ok(FederatedEvidenceShareSummary {
                share_id: import.share_id.clone(),
                manifest_hash: import.manifest_hash.clone(),
                imported_at,
                exported_at: import.exported_at,
                issuer: import.issuer.clone(),
                partner: import.partner.clone(),
                signer_public_key: import.signer_public_key.clone(),
                require_proofs: import.require_proofs,
                tool_receipts: import.tool_receipts.len() as u64,
                capability_lineage: import.capability_lineage.len() as u64,
            })
        })
    }

    pub fn get_federated_share_for_capability(
        &self,
        capability_id: &str,
    ) -> Result<Option<(FederatedEvidenceShareSummary, CapabilitySnapshot)>, ReceiptStoreError>
    {
        let row = self
            .connection()?
            .query_row(
                r#"
                SELECT
                    s.share_id,
                    s.manifest_hash,
                    s.imported_at,
                    s.exported_at,
                    s.issuer,
                    s.partner,
                    s.signer_public_key,
                    s.require_proofs,
                    (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                    (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id),
                    l.capability_id,
                    l.subject_key,
                    l.issuer_key,
                    l.issued_at,
                    l.expires_at,
                    l.grants_json,
                    l.delegation_depth,
                    l.parent_capability_id
                FROM federated_share_capability_lineage l
                INNER JOIN federated_evidence_shares s ON s.share_id = l.share_id
                WHERE l.capability_id = ?1
                ORDER BY s.imported_at DESC, s.share_id DESC
                LIMIT 1
                "#,
                params![capability_id],
                |row| {
                    Ok((
                        FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        },
                        CapabilitySnapshot {
                            capability_id: row.get::<_, String>(10)?,
                            subject_key: row.get::<_, String>(11)?,
                            issuer_key: row.get::<_, String>(12)?,
                            issued_at: row.get::<_, i64>(13)?.max(0) as u64,
                            expires_at: row.get::<_, i64>(14)?.max(0) as u64,
                            grants_json: row.get::<_, String>(15)?,
                            delegation_depth: row.get::<_, i64>(16)?.max(0) as u64,
                            parent_capability_id: row.get::<_, Option<String>>(17)?,
                        },
                    ))
                },
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_federated_share_subject_corpora(
        &self,
        subject_key: &str,
        since: Option<u64>,
        until: Option<u64>,
    ) -> Result<Vec<FederatedShareSubjectCorpus>, ReceiptStoreError> {
        let mut share_ids = self
            .connection()?
            .prepare(
                r#"
                SELECT DISTINCT share_id
                FROM federated_share_tool_receipts
                WHERE subject_key = ?1
                  AND (?2 IS NULL OR timestamp >= ?2)
                  AND (?3 IS NULL OR timestamp <= ?3)
                ORDER BY share_id
                "#,
            )?
            .query_map(
                params![
                    subject_key,
                    since.map(|value| value as i64),
                    until.map(|value| value as i64)
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;

        share_ids.sort();
        let mut results = Vec::new();
        for share_id in share_ids {
            let summary = self
                .connection()?
                .query_row(
                    r#"
                    SELECT
                        share_id,
                        manifest_hash,
                        imported_at,
                        exported_at,
                        issuer,
                        partner,
                        signer_public_key,
                        require_proofs,
                        (SELECT COUNT(*) FROM federated_share_tool_receipts r WHERE r.share_id = s.share_id),
                        (SELECT COUNT(*) FROM federated_share_capability_lineage c WHERE c.share_id = s.share_id)
                    FROM federated_evidence_shares s
                    WHERE share_id = ?1
                    "#,
                    params![share_id],
                    |row| {
                        Ok(FederatedEvidenceShareSummary {
                            share_id: row.get::<_, String>(0)?,
                            manifest_hash: row.get::<_, String>(1)?,
                            imported_at: row.get::<_, i64>(2)?.max(0) as u64,
                            exported_at: row.get::<_, i64>(3)?.max(0) as u64,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts: row.get::<_, i64>(8)?.max(0) as u64,
                            capability_lineage: row.get::<_, i64>(9)?.max(0) as u64,
                        })
                    },
                )?;

            let receipts = self
                .connection()?
                .prepare(
                    r#"
                    SELECT seq, raw_json
                    FROM federated_share_tool_receipts
                    WHERE share_id = ?1
                      AND subject_key = ?2
                      AND (?3 IS NULL OR timestamp >= ?3)
                      AND (?4 IS NULL OR timestamp <= ?4)
                    ORDER BY seq ASC
                    "#,
                )?
                .query_map(
                    params![
                        summary.share_id,
                        subject_key,
                        since.map(|value| value as i64),
                        until.map(|value| value as i64)
                    ],
                    |row| {
                        let raw_json = row.get::<_, String>(1)?;
                        let seq = row.get::<_, i64>(0)?.max(0) as u64;
                        Ok(StoredToolReceipt {
                            seq,
                            receipt: decode_verified_chio_receipt(
                                &raw_json,
                                "federated share tool receipt",
                                Some(seq),
                            )
                            .map_err(|error| {
                                rusqlite::Error::FromSqlConversionFailure(
                                    raw_json.len(),
                                    rusqlite::types::Type::Text,
                                    Box::new(error),
                                )
                            })?,
                        })
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?;

            let capabilities = self
                .connection()?
                .prepare(
                    r#"
                    SELECT
                        capability_id,
                        subject_key,
                        issuer_key,
                        issued_at,
                        expires_at,
                        grants_json,
                        delegation_depth,
                        parent_capability_id
                    FROM federated_share_capability_lineage
                    WHERE share_id = ?1
                      AND (subject_key = ?2 OR issuer_key = ?2)
                    ORDER BY issued_at ASC, capability_id ASC
                    "#,
                )?
                .query_map(params![summary.share_id, subject_key], |row| {
                    Ok(CapabilitySnapshot {
                        capability_id: row.get::<_, String>(0)?,
                        subject_key: row.get::<_, String>(1)?,
                        issuer_key: row.get::<_, String>(2)?,
                        issued_at: row.get::<_, i64>(3)?.max(0) as u64,
                        expires_at: row.get::<_, i64>(4)?.max(0) as u64,
                        grants_json: row.get::<_, String>(5)?,
                        delegation_depth: row.get::<_, i64>(6)?.max(0) as u64,
                        parent_capability_id: row.get::<_, Option<String>>(7)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;

            results.push((summary, receipts, capabilities));
        }

        Ok(results)
    }

    pub fn record_federated_lineage_bridge(
        &mut self,
        local_capability_id: &str,
        parent_capability_id: &str,
        share_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        let local_capability_id = local_capability_id.to_string();
        let parent_capability_id = parent_capability_id.to_string();
        let share_id = share_id.map(ToString::to_string);
        self.writer_handle().run_write(move |connection| {
            connection.execute(
                r#"
                INSERT INTO federated_lineage_bridges (
                    local_capability_id,
                    parent_capability_id,
                    share_id
                ) VALUES (?1, ?2, ?3)
                ON CONFLICT(local_capability_id) DO UPDATE SET
                    parent_capability_id = excluded.parent_capability_id,
                    share_id = excluded.share_id
                "#,
                params![local_capability_id, parent_capability_id, share_id],
            )?;
            Ok(())
        })
    }

    pub(crate) fn federated_lineage_bridge_parent(
        &self,
        local_capability_id: &str,
    ) -> Result<Option<String>, ReceiptStoreError> {
        self.connection()?
            .query_row(
                r#"
                SELECT parent_capability_id
                FROM federated_lineage_bridges
                WHERE local_capability_id = ?1
                "#,
                params![local_capability_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn get_combined_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        if let Some(mut snapshot) =
            self.get_lineage(capability_id)
                .map_err(|error| match error {
                    chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
                    chio_kernel::CapabilityLineageError::Sqlite(error) => {
                        ReceiptStoreError::Sqlite(error)
                    }
                    chio_kernel::CapabilityLineageError::Json(error) => {
                        ReceiptStoreError::Json(error)
                    }
                })?
        {
            if snapshot.parent_capability_id.is_none() {
                snapshot.parent_capability_id =
                    self.federated_lineage_bridge_parent(&snapshot.capability_id)?;
            }
            return Ok(Some(snapshot));
        }
        Ok(self
            .get_federated_share_for_capability(capability_id)?
            .map(|(_, snapshot)| snapshot))
    }

    pub fn get_combined_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());
        let mut seen = BTreeSet::new();

        while let Some(current_capability_id) = current.take() {
            if !seen.insert(current_capability_id.clone()) || chain.len() >= 32 {
                break;
            }
            let Some(snapshot) = self.get_combined_lineage(&current_capability_id)? else {
                break;
            };
            current = snapshot.parent_capability_id.clone();
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }
}
