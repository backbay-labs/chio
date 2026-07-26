use chio_core::capability::token::CapabilityToken;
pub use chio_kernel::capability_lineage::{
    CapabilityLineageError, CapabilitySnapshot, CapabilitySnapshotProvenance,
    StoredCapabilitySnapshot,
};
use rusqlite::types::Type;
use rusqlite::{params, OptionalExtension, Row};

use crate::receipt_store::support::sqlite_i64;
use crate::receipt_store::{SqliteReceiptStore, SqliteStoreConnection};

pub(crate) fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
    snapshot_from_row_with_boundary(row, true)
}

fn snapshot_from_row_with_boundary(
    row: &Row<'_>,
    allow_legacy: bool,
) -> rusqlite::Result<CapabilitySnapshot> {
    validate_snapshot_from_row(
        CapabilitySnapshot {
            capability_id: row.get::<_, String>(0)?,
            subject_key: row.get::<_, String>(1)?,
            issuer_key: row.get::<_, String>(2)?,
            issued_at: non_negative_u64_from_column(row, 3, "issued_at")?,
            expires_at: non_negative_u64_from_column(row, 4, "expires_at")?,
            grants_json: row.get::<_, String>(5)?,
            delegation_depth: non_negative_u64_from_column(row, 6, "delegation_depth")?,
            parent_capability_id: row.get::<_, Option<String>>(7)?,
            federated_parent_capability_id: row.get::<_, Option<String>>(8)?,
            provenance: provenance_from_row(row, 9)?,
            signed_capability: signed_capability_from_row(row, 10)?,
        },
        10,
        allow_legacy,
    )
}

pub(crate) fn validate_snapshot_from_row(
    snapshot: CapabilitySnapshot,
    signed_capability_column: usize,
    allow_legacy: bool,
) -> rusqlite::Result<CapabilitySnapshot> {
    let validation = if allow_legacy {
        snapshot.validate_for_local_read()
    } else {
        snapshot.validate_for_transport()
    };
    validation.map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            signed_capability_column,
            Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })?;
    Ok(snapshot)
}

pub(crate) fn provenance_from_row(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<CapabilitySnapshotProvenance> {
    row.get::<_, String>(column)?.parse().map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        )
    })
}

pub(crate) fn signed_capability_from_row(
    row: &Row<'_>,
    column: usize,
) -> rusqlite::Result<Option<CapabilityToken>> {
    row.get::<_, Option<String>>(column)?
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(column, Type::Text, Box::new(error))
            })
        })
        .transpose()
}

pub(crate) fn validate_snapshot_for_transport(
    snapshot: &CapabilitySnapshot,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    snapshot.validate_for_transport()
}

pub(crate) fn ensure_snapshots_compatible(
    existing: &CapabilitySnapshot,
    incoming: &CapabilitySnapshot,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let existing_scope: serde_json::Value = serde_json::from_str(&existing.grants_json)?;
    let incoming_scope: serde_json::Value = serde_json::from_str(&incoming.grants_json)?;
    let scalar_fields_match = existing.capability_id == incoming.capability_id
        && existing.subject_key == incoming.subject_key
        && existing.issuer_key == incoming.issuer_key
        && existing.issued_at == incoming.issued_at
        && existing.expires_at == incoming.expires_at
        && existing_scope == incoming_scope
        && existing.delegation_depth == incoming.delegation_depth
        && existing.parent_capability_id == incoming.parent_capability_id
        && existing.federated_parent_capability_id == incoming.federated_parent_capability_id;
    if !scalar_fields_match {
        return Err(chio_kernel::ReceiptStoreError::Conflict(format!(
            "capability lineage {} conflicts with the persisted projection",
            incoming.capability_id
        )));
    }
    if existing.provenance != incoming.provenance
        && existing.provenance != CapabilitySnapshotProvenance::LegacyProjection
    {
        return Err(chio_kernel::ReceiptStoreError::Conflict(format!(
            "capability lineage {} has conflicting provenance",
            incoming.capability_id
        )));
    }
    match (
        existing.signed_capability.as_ref(),
        incoming.signed_capability.as_ref(),
    ) {
        (Some(_), None) => Err(chio_kernel::ReceiptStoreError::Conflict(format!(
            "capability lineage {} cannot discard its signed capability",
            incoming.capability_id
        ))),
        (Some(existing), Some(incoming))
            if serde_json::to_value(existing)? != serde_json::to_value(incoming)? =>
        {
            Err(chio_kernel::ReceiptStoreError::Conflict(format!(
                "capability lineage {} has conflicting signed capabilities",
                incoming.id
            )))
        }
        _ => Ok(()),
    }
}

pub(crate) fn persist_compatible_snapshot(
    transaction: &rusqlite::Transaction<'_>,
    incoming: &CapabilitySnapshot,
) -> Result<(), chio_kernel::ReceiptStoreError> {
    let issued_at = sqlite_i64(incoming.issued_at, "capability lineage issued_at")?;
    let expires_at = sqlite_i64(incoming.expires_at, "capability lineage expires_at")?;
    let delegation_depth = sqlite_i64(
        incoming.delegation_depth,
        "capability lineage delegation_depth",
    )?;
    let existing = transaction
        .query_row(
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
            FROM capability_lineage
            WHERE capability_id = ?1
            "#,
            params![incoming.capability_id],
            snapshot_from_row,
        )
        .optional()?;
    let signed_capability_json = incoming
        .signed_capability
        .as_ref()
        .map(serde_json::to_string)
        .transpose()?;
    let provenance = incoming.provenance.as_str();

    if let Some(existing) = existing.as_ref() {
        ensure_snapshots_compatible(existing, incoming)?;
        if existing.provenance == CapabilitySnapshotProvenance::LegacyProjection
            && incoming.provenance != CapabilitySnapshotProvenance::LegacyProjection
        {
            let max_rowid: i64 = transaction.query_row(
                "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
                [],
                |row| row.get(0),
            )?;
            let next_rowid = max_rowid.checked_add(1).ok_or_else(|| {
                chio_kernel::ReceiptStoreError::Conflict(
                    "capability lineage replication sequence is exhausted".to_string(),
                )
            })?;
            let updated = transaction.execute(
                r#"
                UPDATE capability_lineage
                SET signed_capability_json = ?2,
                    provenance = ?3,
                    rowid = ?4
                WHERE capability_id = ?1
                "#,
                params![
                    incoming.capability_id,
                    signed_capability_json,
                    provenance,
                    next_rowid
                ],
            )?;
            if updated != 1 {
                return Err(chio_kernel::ReceiptStoreError::Conflict(format!(
                    "capability lineage {} disappeared during signed-token upgrade",
                    incoming.capability_id
                )));
            }
        }
        return Ok(());
    }

    transaction.execute(
        r#"
        INSERT INTO capability_lineage (
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
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        "#,
        params![
            incoming.capability_id,
            incoming.subject_key,
            incoming.issuer_key,
            issued_at,
            expires_at,
            incoming.grants_json,
            delegation_depth,
            incoming.parent_capability_id,
            incoming.federated_parent_capability_id,
            provenance,
            signed_capability_json,
        ],
    )?;
    Ok(())
}

pub(crate) fn non_negative_u64_from_column(
    row: &Row<'_>,
    column: usize,
    field_name: &'static str,
) -> rusqlite::Result<u64> {
    let value = row.get::<_, i64>(column)?;
    if value < 0 {
        return Err(negative_lineage_integer_error(column, field_name, value));
    }
    Ok(value as u64)
}

fn negative_lineage_integer_error(
    column: usize,
    field_name: &'static str,
    value: i64,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("capability_lineage.{field_name} must be non-negative, got {value}"),
        )),
    )
}

impl SqliteReceiptStore {
    /// Record a capability snapshot at issuance time.
    ///
    /// Identical duplicate inserts are idempotent. Conflicting projections are
    /// rejected before the first-writer-wins insert.
    ///
    /// The `parent_capability_id` argument must refer to a capability already
    /// present in the lineage table. If it is `Some` but the parent is missing,
    /// the depth defaults to 1 (the minimum delegation depth).
    pub fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), CapabilityLineageError> {
        self.record_capability_snapshot_bounded(token, parent_capability_id, None)
    }

    /// Bounded variant of [`record_capability_snapshot`]: the writer round trip
    /// is capped at `budget`. The evaluation hot path uses this so a wedged or
    /// dying commit writer that passed the pre-dispatch liveness check but stalls
    /// on this snapshot cannot hang the request inside an unbounded write.
    pub fn record_capability_snapshot_with_timeout(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
        budget: std::time::Duration,
    ) -> Result<(), CapabilityLineageError> {
        self.record_capability_snapshot_bounded(token, parent_capability_id, Some(budget))
    }

    fn record_capability_snapshot_bounded(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
        budget: Option<std::time::Duration>,
    ) -> Result<(), CapabilityLineageError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();

        let capability_id = token.id.clone();
        let issued_at = token.issued_at;
        let expires_at = token.expires_at;
        let signed_capability = token.clone();
        validate_snapshot_for_transport(&CapabilitySnapshot {
            capability_id: capability_id.clone(),
            subject_key: subject_key.clone(),
            issuer_key: issuer_key.clone(),
            issued_at,
            expires_at,
            grants_json: grants_json.clone(),
            delegation_depth: token.delegation_chain.len() as u64,
            parent_capability_id: token
                .delegation_chain
                .last()
                .map(|link| link.capability_id.clone()),
            federated_parent_capability_id: None,
            provenance: CapabilitySnapshotProvenance::SignedToken,
            signed_capability: Some(signed_capability.clone()),
        })?;
        let parent_capability_id = parent_capability_id.map(ToString::to_string);
        let job = move |connection: &mut SqliteStoreConnection| {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            // Resolve the parent's delegation depth on the writer connection,
            // inside the bounded job, so the read shares the same wall-clock
            // budget as the insert. Running it earlier on a reader-pool
            // connection would leave a stalled or pool-starved lookup unbounded
            // on the pre-dispatch hot path, defeating the snapshot deadline.
            let delegation_depth: u64 = if let Some(parent_id) = parent_capability_id.as_deref() {
                let parent_depth: Option<u64> = transaction
                    .query_row(
                        "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                        params![parent_id],
                        |row: &Row<'_>| non_negative_u64_from_column(row, 0, "delegation_depth"),
                    )
                    .optional()?;

                parent_depth.map(|d| d.saturating_add(1)).unwrap_or(1)
            } else {
                0
            };
            let incoming = CapabilitySnapshot {
                capability_id: capability_id.clone(),
                subject_key: subject_key.clone(),
                issuer_key: issuer_key.clone(),
                issued_at,
                expires_at,
                grants_json: grants_json.clone(),
                delegation_depth,
                parent_capability_id: parent_capability_id.clone(),
                federated_parent_capability_id: None,
                provenance: CapabilitySnapshotProvenance::SignedToken,
                signed_capability: Some(signed_capability),
            };
            validate_snapshot_for_transport(&incoming)?;
            persist_compatible_snapshot(&transaction, &incoming)?;
            transaction.commit()?;
            Ok(())
        };
        match budget {
            Some(budget) => self.writer_handle().run_write_with_timeout(job, budget)?,
            None => self.writer_handle().run_write(job)?,
        }

        Ok(())
    }

    /// Upsert an already-materialized capability snapshot.
    ///
    /// This is used by cluster replication so followers can converge on the
    /// leader's lineage table without reconstructing full signed tokens.
    pub fn upsert_capability_snapshot(
        &mut self,
        snapshot: &CapabilitySnapshot,
    ) -> Result<(), CapabilityLineageError> {
        validate_snapshot_for_transport(snapshot)?;
        let snapshot = snapshot.clone();
        self.writer_handle().run_write(move |connection| {
            let transaction =
                connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            persist_compatible_snapshot(&transaction, &snapshot)?;
            transaction.commit()?;
            Ok(())
        })?;
        Ok(())
    }

    /// Retrieve a single capability snapshot by its ID.
    ///
    /// Returns `None` if no snapshot exists for the given capability_id.
    pub fn get_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, CapabilityLineageError> {
        let row = self
            .connection()?
            .query_row(
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
                FROM capability_lineage
                WHERE capability_id = ?1
                "#,
                params![capability_id],
                snapshot_from_row,
            )
            .optional()?;

        Ok(row)
    }

    /// Walk the delegation chain for a capability, returning root-first ordering.
    ///
    /// Uses a WITH RECURSIVE CTE that walks from the given capability up through
    /// its parent chain, tracking depth level. The ORDER BY level DESC produces
    /// root-first ordering because the root has the highest level value.
    ///
    /// A max-depth guard (level < 20) prevents infinite recursion caused by
    /// accidental cycles in the parent chain.
    pub fn get_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            WITH RECURSIVE chain(
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
                signed_capability_json,
                level
            ) AS (
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
                    signed_capability_json,
                    0 AS level
                FROM capability_lineage
                WHERE capability_id = ?1

                UNION ALL

                SELECT
                    cl.capability_id,
                    cl.subject_key,
                    cl.issuer_key,
                    cl.issued_at,
                    cl.expires_at,
                    cl.grants_json,
                    cl.delegation_depth,
                    cl.parent_capability_id,
                    cl.federated_parent_capability_id,
                    cl.provenance,
                    cl.signed_capability_json,
                    chain.level + 1
                FROM capability_lineage cl
                INNER JOIN chain ON cl.capability_id = chain.parent_capability_id
                WHERE chain.level < 20
            )
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
            FROM chain
            ORDER BY level DESC
            "#,
        )?;

        let rows = stmt.query_map(params![capability_id], snapshot_from_row)?;

        let mut chain = Vec::new();
        for row in rows {
            chain.push(row?);
        }

        Ok(chain)
    }

    /// List all capability snapshots for a given subject key.
    ///
    /// Returns snapshots ordered newest-first by issued_at.
    pub fn list_capabilities_for_subject(
        &self,
        subject_key: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        self.list_capability_snapshots(Some(subject_key), None)
    }

    /// List capability snapshots filtered by subject and/or issuer.
    ///
    /// If both filters are present they are combined with AND semantics.
    /// Results are ordered deterministically oldest-first to keep reputation
    /// corpus construction stable across runs.
    pub fn list_capability_snapshots(
        &self,
        subject_key: Option<&str>,
        issuer_key: Option<&str>,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
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
            FROM capability_lineage
            WHERE (?1 IS NULL OR subject_key = ?1)
              AND (?2 IS NULL OR issuer_key = ?2)
            ORDER BY issued_at ASC, capability_id ASC
            "#,
        )?;

        let rows = stmt.query_map(params![subject_key, issuer_key], snapshot_from_row)?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Return capability lineage snapshots added after a given local sequence.
    ///
    /// The sequence is the SQLite `rowid`, which is monotonic for this
    /// append-only table and therefore suitable as a replication cursor.
    pub fn list_capability_snapshots_after_seq(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<StoredCapabilitySnapshot>, CapabilityLineageError> {
        let after_seq = sqlite_i64(after_seq, "capability lineage after_seq")?;
        let limit = i64::try_from(limit).map_err(|_| {
            chio_kernel::ReceiptStoreError::Conflict(format!(
                "capability lineage limit value {limit} exceeds SQLite INTEGER range"
            ))
        })?;
        let connection = self.connection()?;
        let mut stmt = connection.prepare(
            r#"
            SELECT
                rowid,
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
            FROM capability_lineage
            WHERE rowid > ?1
            ORDER BY rowid ASC
            LIMIT ?2
            "#,
        )?;

        let rows = stmt.query_map(params![after_seq, limit], |row| {
            Ok(StoredCapabilitySnapshot {
                seq: non_negative_u64_from_column(row, 0, "rowid")?,
                snapshot: validate_snapshot_from_row(
                    CapabilitySnapshot {
                        capability_id: row.get::<_, String>(1)?,
                        subject_key: row.get::<_, String>(2)?,
                        issuer_key: row.get::<_, String>(3)?,
                        issued_at: non_negative_u64_from_column(row, 4, "issued_at")?,
                        expires_at: non_negative_u64_from_column(row, 5, "expires_at")?,
                        grants_json: row.get::<_, String>(6)?,
                        delegation_depth: non_negative_u64_from_column(row, 7, "delegation_depth")?,
                        parent_capability_id: row.get::<_, Option<String>>(8)?,
                        federated_parent_capability_id: row.get::<_, Option<String>>(9)?,
                        provenance: provenance_from_row(row, 10)?,
                        signed_capability: signed_capability_from_row(row, 11)?,
                    },
                    11,
                    false,
                )?,
            })
        })?;

        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }

        Ok(snapshots)
    }

    /// Highest lineage snapshot seq (capability_lineage rowid), or 0 when empty.
    /// list_capability_snapshots_after_seq paginates on rowid, so the head is
    /// MAX(rowid). Returns ReceiptStoreError so the cluster status
    /// path converts it through the same CliError variant as the receipt heads.
    pub fn max_lineage_seq(&self) -> Result<u64, chio_kernel::ReceiptStoreError> {
        let connection = self.connection()?;
        let seq: i64 = connection.query_row(
            "SELECT COALESCE(MAX(rowid), 0) FROM capability_lineage",
            [],
            |row| row.get(0),
        )?;
        crate::receipt_store::sqlite_u64(seq, "capability lineage max rowid")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
#[path = "capability_lineage_tests.rs"]
mod tests;
