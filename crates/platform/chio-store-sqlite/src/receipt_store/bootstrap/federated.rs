use super::*;

fn persist_immutable_federated_lineage_bridge(
    transaction: &rusqlite::Transaction<'_>,
    local_capability_id: &str,
    parent_capability_id: &str,
    share_id: Option<&str>,
) -> Result<(), ReceiptStoreError> {
    if local_capability_id == parent_capability_id {
        return Err(ReceiptStoreError::Conflict(format!(
            "capability lineage {local_capability_id} cannot bridge to itself"
        )));
    }
    let projected_parent = transaction
        .query_row(
            "SELECT federated_parent_capability_id FROM capability_lineage WHERE capability_id = ?1",
            params![local_capability_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "local capability {local_capability_id} is missing for its federation bridge"
            ))
        })?;
    if let Some(existing_parent) = projected_parent.as_deref() {
        if existing_parent != parent_capability_id {
            return Err(ReceiptStoreError::Conflict(format!(
                "capability lineage {local_capability_id} already has federated parent {existing_parent}"
            )));
        }
    }
    let target_exists: bool = match share_id {
        Some(share_id) => transaction.query_row(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM federated_share_capability_lineage
                WHERE share_id = ?1 AND capability_id = ?2
            )
            "#,
            params![share_id, parent_capability_id],
            |row| row.get(0),
        )?,
        None => transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM capability_lineage WHERE capability_id = ?1)",
            params![parent_capability_id],
            |row| row.get(0),
        )?,
    };
    if !target_exists {
        return Err(ReceiptStoreError::Conflict(format!(
            "federated lineage bridge {local_capability_id} references missing parent {parent_capability_id}"
        )));
    }

    let existing = transaction
        .query_row(
            r#"
            SELECT parent_capability_id, share_id
            FROM federated_lineage_bridges
            WHERE local_capability_id = ?1
            "#,
            params![local_capability_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?;
    if let Some((existing_parent, existing_share)) = existing {
        if existing_parent != parent_capability_id || existing_share.as_deref() != share_id {
            return Err(ReceiptStoreError::Conflict(format!(
                "capability lineage bridge {local_capability_id} is immutable"
            )));
        }
    } else {
        transaction.execute(
            r#"
            INSERT INTO federated_lineage_bridges (
                local_capability_id,
                parent_capability_id,
                share_id
            ) VALUES (?1, ?2, ?3)
            "#,
            params![local_capability_id, parent_capability_id, share_id],
        )?;
    }

    if projected_parent.is_none() {
        let max_rowid: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
            [],
            |row| row.get(0),
        )?;
        let next_rowid = max_rowid.checked_add(1).ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "capability lineage replication sequence is exhausted".to_string(),
            )
        })?;
        let updated = transaction.execute(
            r#"
            UPDATE capability_lineage
            SET federated_parent_capability_id = ?2,
                rowid = ?3
            WHERE capability_id = ?1
              AND federated_parent_capability_id IS NULL
            "#,
            params![local_capability_id, parent_capability_id, next_rowid],
        )?;
        if updated != 1 {
            return Err(ReceiptStoreError::Conflict(format!(
                "capability lineage {local_capability_id} changed while recording its federation bridge"
            )));
        }
    }
    Ok(())
}

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
            let imported_at_sqlite = sqlite_i64(imported_at, "federated share imported_at")?;
            let exported_at_sqlite = sqlite_i64(import.exported_at, "federated share exported_at")?;
            let tx =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
                    imported_at_sqlite,
                    exported_at_sqlite,
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
                crate::capability_lineage::validate_snapshot_for_transport(snapshot)?;
                let issued_at = sqlite_i64(snapshot.issued_at, "federated lineage issued_at")?;
                let expires_at = sqlite_i64(snapshot.expires_at, "federated lineage expires_at")?;
                let delegation_depth = sqlite_i64(
                    snapshot.delegation_depth,
                    "federated lineage delegation_depth",
                )?;
                {
                    let mut statement = tx.prepare(
                        r#"
                        SELECT
                            capability_id,
                            subject_key,
                            issuer_key,
                            issued_at,
                            expires_at,
                            grants_json,
                            delegation_depth,
                            parent_capability_id,
                            federated_parent_capability_id,
                            provenance,
                            signed_capability_json
                        FROM federated_share_capability_lineage
                        WHERE capability_id = ?1
                        "#,
                    )?;
                    let existing = statement.query_map(
                        params![snapshot.capability_id],
                        crate::capability_lineage::snapshot_from_row,
                    )?;
                    for existing in existing {
                        crate::capability_lineage::ensure_snapshots_compatible(
                            &existing?, snapshot,
                        )?;
                    }
                }
                let signed_capability_json = snapshot
                    .signed_capability
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?;
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
                    parent_capability_id,
                    federated_parent_capability_id,
                    provenance,
                    signed_capability_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                ON CONFLICT(share_id, capability_id) DO UPDATE SET
                    provenance = excluded.provenance,
                    signed_capability_json = excluded.signed_capability_json
                WHERE federated_share_capability_lineage.provenance = 'legacy_projection'
                "#,
                    params![
                        import.share_id,
                        snapshot.capability_id,
                        snapshot.subject_key,
                        snapshot.issuer_key,
                        issued_at,
                        expires_at,
                        snapshot.grants_json,
                        delegation_depth,
                        snapshot.parent_capability_id,
                        snapshot.federated_parent_capability_id,
                        snapshot.provenance.as_str(),
                        signed_capability_json,
                    ],
                )?;
            }

            for record in &import.tool_receipts {
                let seq = sqlite_i64(record.seq, "federated receipt seq")?;
                let timestamp =
                    sqlite_i64(record.receipt.timestamp, "federated receipt timestamp")?;
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
                        seq,
                        record.receipt.id,
                        timestamp,
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
                    l.parent_capability_id,
                    l.federated_parent_capability_id,
                    l.provenance,
                    l.signed_capability_json
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
                            imported_at:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    2,
                                    "federated share imported_at",
                                )?,
                            exported_at:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    3,
                                    "federated share exported_at",
                                )?,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    8,
                                    "federated share receipt count",
                                )?,
                            capability_lineage:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    9,
                                    "federated share lineage count",
                                )?,
                        },
                        crate::capability_lineage::validate_snapshot_from_row(
                            CapabilitySnapshot {
                                capability_id: row.get::<_, String>(10)?,
                                subject_key: row.get::<_, String>(11)?,
                                issuer_key: row.get::<_, String>(12)?,
                                issued_at:
                                    crate::capability_lineage::non_negative_u64_from_column(
                                        row,
                                        13,
                                        "federated lineage issued_at",
                                    )?,
                                expires_at:
                                    crate::capability_lineage::non_negative_u64_from_column(
                                        row,
                                        14,
                                        "federated lineage expires_at",
                                    )?,
                                grants_json: row.get::<_, String>(15)?,
                                delegation_depth:
                                    crate::capability_lineage::non_negative_u64_from_column(
                                        row,
                                        16,
                                        "federated lineage delegation_depth",
                                    )?,
                                parent_capability_id: row.get::<_, Option<String>>(17)?,
                                federated_parent_capability_id: row
                                    .get::<_, Option<String>>(18)?,
                                provenance: crate::capability_lineage::provenance_from_row(row, 19)?,
                                signed_capability:
                                    crate::capability_lineage::signed_capability_from_row(row, 20)?,
                            },
                            20,
                            false,
                        )?,
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
        let since = since
            .map(|value| sqlite_i64(value, "federated corpus since"))
            .transpose()?;
        let until = until
            .map(|value| sqlite_i64(value, "federated corpus until"))
            .transpose()?;
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
            .query_map(params![subject_key, since, until], |row| {
                row.get::<_, String>(0)
            })?
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
                            imported_at:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    2,
                                    "federated share imported_at",
                                )?,
                            exported_at:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    3,
                                    "federated share exported_at",
                                )?,
                            issuer: row.get::<_, String>(4)?,
                            partner: row.get::<_, String>(5)?,
                            signer_public_key: row.get::<_, String>(6)?,
                            require_proofs: row.get::<_, i64>(7)? != 0,
                            tool_receipts:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    8,
                                    "federated share receipt count",
                                )?,
                            capability_lineage:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    9,
                                    "federated share lineage count",
                                )?,
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
                    params![summary.share_id, subject_key, since, until],
                    |row| {
                        let raw_json = row.get::<_, String>(1)?;
                        let seq = crate::capability_lineage::non_negative_u64_from_column(
                            row,
                            0,
                            "federated receipt seq",
                        )?;
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
                        parent_capability_id,
                        federated_parent_capability_id,
                        provenance,
                        signed_capability_json
                    FROM federated_share_capability_lineage
                    WHERE share_id = ?1
                      AND (subject_key = ?2 OR issuer_key = ?2)
                    ORDER BY issued_at ASC, capability_id ASC
                    "#,
                )?
                .query_map(params![summary.share_id, subject_key], |row| {
                    crate::capability_lineage::validate_snapshot_from_row(
                        CapabilitySnapshot {
                            capability_id: row.get::<_, String>(0)?,
                            subject_key: row.get::<_, String>(1)?,
                            issuer_key: row.get::<_, String>(2)?,
                            issued_at: crate::capability_lineage::non_negative_u64_from_column(
                                row,
                                3,
                                "federated lineage issued_at",
                            )?,
                            expires_at: crate::capability_lineage::non_negative_u64_from_column(
                                row,
                                4,
                                "federated lineage expires_at",
                            )?,
                            grants_json: row.get::<_, String>(5)?,
                            delegation_depth:
                                crate::capability_lineage::non_negative_u64_from_column(
                                    row,
                                    6,
                                    "federated lineage delegation_depth",
                                )?,
                            parent_capability_id: row.get::<_, Option<String>>(7)?,
                            federated_parent_capability_id: row.get::<_, Option<String>>(8)?,
                            provenance: crate::capability_lineage::provenance_from_row(row, 9)?,
                            signed_capability:
                                crate::capability_lineage::signed_capability_from_row(row, 10)?,
                        },
                        10,
                        false,
                    )
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
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            persist_immutable_federated_lineage_bridge(
                &transaction,
                &local_capability_id,
                &parent_capability_id,
                share_id.as_deref(),
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    /// Persist a federated issuance lineage as one all-or-nothing operation.
    pub fn persist_federated_delegation_lineage(
        &mut self,
        anchor: &CapabilitySnapshot,
        upstream_bridge: Option<(&str, &str)>,
        child: &CapabilitySnapshot,
    ) -> Result<(), ReceiptStoreError> {
        crate::capability_lineage::validate_snapshot_for_transport(anchor)?;
        crate::capability_lineage::validate_snapshot_for_transport(child)?;
        if anchor.provenance != chio_kernel::CapabilitySnapshotProvenance::SyntheticAnchor {
            return Err(ReceiptStoreError::Conflict(format!(
                "federated delegation anchor {} is not synthetic",
                anchor.capability_id
            )));
        }
        if child.provenance != chio_kernel::CapabilitySnapshotProvenance::SignedToken {
            return Err(ReceiptStoreError::Conflict(format!(
                "federated delegation child {} is not signed",
                child.capability_id
            )));
        }
        if child.parent_capability_id.is_some() || child.delegation_depth != 0 {
            return Err(ReceiptStoreError::Conflict(format!(
                "federated delegation child {} must be a direct signed capability",
                child.capability_id
            )));
        }
        if anchor.federated_parent_capability_id.as_deref()
            != upstream_bridge.map(|(parent, _)| parent)
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "federated delegation anchor {} does not match its upstream bridge",
                anchor.capability_id
            )));
        }
        if child.federated_parent_capability_id.as_deref() != Some(anchor.capability_id.as_str()) {
            return Err(ReceiptStoreError::Conflict(format!(
                "federated delegation child {} is not bridged to anchor {}",
                child.capability_id, anchor.capability_id
            )));
        }

        let anchor = anchor.clone();
        let child = child.clone();
        let upstream_bridge =
            upstream_bridge.map(|(parent, share)| (parent.to_string(), share.to_string()));
        self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            crate::capability_lineage::persist_compatible_snapshot(&transaction, &anchor)?;
            if let Some((parent, share)) = upstream_bridge.as_ref() {
                persist_immutable_federated_lineage_bridge(
                    &transaction,
                    &anchor.capability_id,
                    parent,
                    Some(share),
                )?;
            }
            crate::capability_lineage::persist_compatible_snapshot(&transaction, &child)?;
            persist_immutable_federated_lineage_bridge(
                &transaction,
                &child.capability_id,
                &anchor.capability_id,
                None,
            )?;
            transaction.commit()?;
            Ok(())
        })
    }

    pub fn get_combined_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<chio_kernel::CapabilitySnapshot>, ReceiptStoreError> {
        if let Some(snapshot) = self
            .get_lineage(capability_id)
            .map_err(|error| match error {
                chio_kernel::CapabilityLineageError::ReceiptStore(error) => error,
                chio_kernel::CapabilityLineageError::Sqlite(error) => {
                    ReceiptStoreError::Sqlite(error)
                }
                chio_kernel::CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            })?
        {
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
        const MAX_CHAIN_LENGTH: usize = 32;

        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());
        let mut seen = BTreeSet::new();

        while let Some(current_capability_id) = current.take() {
            if !seen.insert(current_capability_id.clone()) {
                return Err(ReceiptStoreError::Conflict(format!(
                    "combined delegation chain for {capability_id} contains a cycle at {current_capability_id}"
                )));
            }
            if chain.len() >= MAX_CHAIN_LENGTH {
                return Err(ReceiptStoreError::Conflict(format!(
                    "combined delegation chain for {capability_id} exceeds {MAX_CHAIN_LENGTH} capabilities"
                )));
            }
            let Some(snapshot) = self.get_combined_lineage(&current_capability_id)? else {
                if chain.is_empty() {
                    return Ok(Vec::new());
                }
                return Err(ReceiptStoreError::Conflict(format!(
                    "combined delegation chain for {capability_id} references missing parent {current_capability_id}"
                )));
            };
            current = snapshot
                .parent_capability_id
                .clone()
                .or_else(|| snapshot.federated_parent_capability_id.clone());
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }
}
