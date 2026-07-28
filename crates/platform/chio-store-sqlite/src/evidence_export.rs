use std::collections::BTreeMap;

use chio_core::merkle::MerkleTree;
use chio_core::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding;
use chio_kernel::capability_lineage::CapabilitySnapshot;
use chio_kernel::checkpoint::{
    bind_checkpoint_publication_trust_anchor, build_inclusion_proof,
    validate_checkpoint_transparency, CheckpointPublication, CheckpointTransparencySummary,
    KernelCheckpoint, ReceiptInclusionProof,
};
use chio_kernel::evidence_export::{
    EvidenceChildReceiptRecord, EvidenceChildReceiptScope, EvidenceExportBundle,
    EvidenceExportError, EvidenceExportQuery, EvidenceRetentionMetadata, EvidenceToolReceiptRecord,
    EvidenceUncheckpointedReceipt,
};
use chio_kernel::ReceiptStoreError;
use rusqlite::{params, Connection, OptionalExtension};

use crate::receipt_store::{sqlite_u64, SqliteReceiptStore};

impl SqliteReceiptStore {
    /// Build a local-only evidence export bundle from the current SQLite store.
    ///
    /// This method never fabricates joins that the runtime does not persist.
    /// Tool receipts can be scoped by capability or agent subject. Child
    /// receipts do not currently have the same attribution fields, so they are
    /// either included by query window or omitted with an explicit scope flag.
    pub fn build_evidence_export_bundle(
        &self,
        query: &EvidenceExportQuery,
    ) -> Result<EvidenceExportBundle, EvidenceExportError> {
        let (bundle, _) = self.collect_evidence_export_bundle(query)?;
        Ok(bundle)
    }

    /// Build a bundle and its transparency summary with one checkpoint
    /// validation pass.
    pub fn build_evidence_export_bundle_with_transparency(
        &self,
        query: &EvidenceExportQuery,
    ) -> Result<(EvidenceExportBundle, CheckpointTransparencySummary), EvidenceExportError> {
        let (bundle, transparency) = self.collect_evidence_export_bundle(query)?;
        let transparency = self.enrich_evidence_export_transparency_summary(transparency)?;
        Ok((bundle, transparency))
    }

    fn collect_evidence_export_bundle(
        &self,
        query: &EvidenceExportQuery,
    ) -> Result<(EvidenceExportBundle, CheckpointTransparencySummary), EvidenceExportError> {
        query.validate_read_boundary()?;
        let query = query.normalized_for_read_boundary();
        let tool_receipts = self.collect_tool_receipts_for_export(&query)?;
        let child_receipt_scope = self.resolve_child_receipt_scope(&query);
        let child_receipts = self.collect_child_receipts_for_export(&query, child_receipt_scope)?;
        let (checkpoints, transparency) = self.collect_checkpoints_for_export(&tool_receipts)?;
        let capability_lineage = self.collect_lineage_for_export(&tool_receipts)?;
        let (inclusion_proofs, uncheckpointed_receipts) =
            self.collect_inclusion_proofs_for_export(&tool_receipts, &checkpoints)?;
        let retention = match &query.read_boundary {
            Some(chio_kernel::ReceiptReadBoundary::TenantScoped { tenant }) => {
                EvidenceRetentionMetadata {
                    live_db_size_bytes: None,
                    oldest_live_receipt_timestamp: self
                        .oldest_receipt_timestamp_for_tenant(tenant)?,
                }
            }
            Some(chio_kernel::ReceiptReadBoundary::AdminAll) | None => EvidenceRetentionMetadata {
                live_db_size_bytes: Some(self.db_size_bytes()?),
                oldest_live_receipt_timestamp: self.oldest_receipt_timestamp()?,
            },
        };

        Ok((
            EvidenceExportBundle {
                query: query.clone(),
                tool_receipts,
                child_receipts,
                child_receipt_scope,
                checkpoints,
                capability_lineage,
                inclusion_proofs,
                uncheckpointed_receipts,
                retention,
            },
            transparency,
        ))
    }

    pub fn build_evidence_export_transparency_summary(
        &self,
        checkpoints: &[KernelCheckpoint],
    ) -> Result<CheckpointTransparencySummary, EvidenceExportError> {
        let summary = validate_checkpoint_transparency(checkpoints)?;
        self.enrich_evidence_export_transparency_summary(summary)
    }

    fn enrich_evidence_export_transparency_summary(
        &self,
        mut summary: CheckpointTransparencySummary,
    ) -> Result<CheckpointTransparencySummary, EvidenceExportError> {
        if summary.publications.is_empty() {
            return Ok(summary);
        }

        let connection = self.connection()?;
        for publication in &mut summary.publications {
            let persisted =
                load_checkpoint_publication_core(&connection, publication.checkpoint_seq)?
                    .ok_or_else(|| {
                        EvidenceExportError::ReceiptStore(ReceiptStoreError::Conflict(format!(
                            "checkpoint {} is missing persisted publication metadata",
                            publication.checkpoint_seq
                        )))
                    })?;
            if !publication_core_matches(publication, &persisted) {
                return Err(EvidenceExportError::ReceiptStore(
                    ReceiptStoreError::Conflict(format!(
                        "checkpoint {} publication metadata diverges from persisted projection",
                        publication.checkpoint_seq
                    )),
                ));
            }
            if let Some(binding) = load_checkpoint_publication_trust_anchor_binding(
                &connection,
                publication.checkpoint_seq,
            )? {
                *publication =
                    bind_checkpoint_publication_trust_anchor(publication.clone(), binding)?;
            }
        }

        Ok(summary)
    }

    fn collect_tool_receipts_for_export(
        &self,
        query: &EvidenceExportQuery,
    ) -> Result<Vec<EvidenceToolReceiptRecord>, EvidenceExportError> {
        let mut cursor = None;
        let mut records = Vec::new();

        loop {
            let page = self.query_receipts(&query.as_receipt_query(cursor))?;
            if page.receipts.is_empty() {
                break;
            }
            let next_cursor = page.next_cursor;
            let page_records = page
                .receipts
                .into_iter()
                .map(|stored| {
                    let seq = self.claim_log_entry_seq_for_receipt_id(&stored.receipt.id)?;
                    Ok(EvidenceToolReceiptRecord {
                        seq,
                        receipt: stored.receipt,
                    })
                })
                .collect::<Result<Vec<_>, EvidenceExportError>>()?;
            records.extend(page_records);
            match next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        Ok(records)
    }

    fn claim_log_entry_seq_for_receipt_id(
        &self,
        receipt_id: &str,
    ) -> Result<u64, EvidenceExportError> {
        let connection = self.connection()?;
        let seq = connection
            .query_row(
                "SELECT entry_seq FROM claim_receipt_log_entries WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .ok_or_else(|| {
                EvidenceExportError::ReceiptStore(ReceiptStoreError::Conflict(format!(
                    "receipt {receipt_id} is missing from claim receipt log"
                )))
            })?;
        sqlite_u64(seq, "claim receipt log entry_seq").map_err(EvidenceExportError::ReceiptStore)
    }

    fn resolve_child_receipt_scope(
        &self,
        query: &EvidenceExportQuery,
    ) -> EvidenceChildReceiptScope {
        query.child_receipt_scope()
    }

    fn collect_child_receipts_for_export(
        &self,
        query: &EvidenceExportQuery,
        scope: EvidenceChildReceiptScope,
    ) -> Result<Vec<EvidenceChildReceiptRecord>, EvidenceExportError> {
        if matches!(scope, EvidenceChildReceiptScope::OmittedNoJoinPath) {
            return Ok(Vec::new());
        }

        let since = query.since.map(|value| value as i64);
        let until = query.until.map(|value| value as i64);
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT seq, raw_json
            FROM chio_child_receipts
            WHERE (?1 IS NULL OR timestamp >= ?1)
              AND (?2 IS NULL OR timestamp <= ?2)
            ORDER BY seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![since, until], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            let seq = seq.max(0) as u64;
            Ok(EvidenceChildReceiptRecord {
                seq,
                receipt: crate::receipt_store::decode_verified_child_receipt(
                    &raw_json,
                    "persisted child receipt",
                    Some(seq),
                )?,
            })
        })
        .collect()
    }

    fn collect_checkpoints_for_export(
        &self,
        tool_receipts: &[EvidenceToolReceiptRecord],
    ) -> Result<(Vec<KernelCheckpoint>, CheckpointTransparencySummary), EvidenceExportError> {
        if tool_receipts.is_empty() {
            return Ok((Vec::new(), CheckpointTransparencySummary::default()));
        }
        let min_seq = tool_receipts
            .iter()
            .map(|record| record.seq)
            .min()
            .unwrap_or(0);
        let max_seq = tool_receipts
            .iter()
            .map(|record| record.seq)
            .max()
            .unwrap_or(0);

        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT checkpoint_seq
            FROM kernel_checkpoints
            WHERE checkpoint_seq <= (
                SELECT MAX(checkpoint_seq)
                FROM kernel_checkpoints
                WHERE batch_end_seq >= ?1
                  AND batch_start_seq <= ?2
            )
            ORDER BY checkpoint_seq ASC
            "#,
        )?;
        let rows = statement.query_map(params![min_seq as i64, max_seq as i64], |row| {
            row.get::<_, i64>(0)
        })?;

        let mut checkpoints = Vec::new();
        for row in rows {
            let checkpoint_seq = row?.max(0) as u64;
            if let Some(checkpoint) = self.load_checkpoint_by_seq(checkpoint_seq)? {
                checkpoints.push(checkpoint);
            }
        }

        let transparency = validate_checkpoint_transparency(&checkpoints)?;
        Ok((checkpoints, transparency))
    }

    fn collect_lineage_for_export(
        &self,
        tool_receipts: &[EvidenceToolReceiptRecord],
    ) -> Result<Vec<CapabilitySnapshot>, EvidenceExportError> {
        let mut snapshots = BTreeMap::<String, CapabilitySnapshot>::new();
        for record in tool_receipts {
            for snapshot in self.get_combined_delegation_chain(&record.receipt.capability_id)? {
                snapshot.validate_for_transport()?;
                snapshots
                    .entry(snapshot.capability_id.clone())
                    .or_insert(snapshot);
            }
        }
        Ok(snapshots.into_values().collect())
    }

    fn collect_inclusion_proofs_for_export(
        &self,
        tool_receipts: &[EvidenceToolReceiptRecord],
        checkpoints: &[KernelCheckpoint],
    ) -> Result<
        (
            Vec<ReceiptInclusionProof>,
            Vec<EvidenceUncheckpointedReceipt>,
        ),
        EvidenceExportError,
    > {
        let exported_by_seq = tool_receipts
            .iter()
            .map(|record| (record.seq, record.receipt.id.as_str()))
            .collect::<BTreeMap<_, _>>();
        let mut proofs = Vec::new();
        let mut covered_seqs = BTreeMap::<u64, ()>::new();

        for checkpoint in checkpoints {
            if exported_by_seq
                .range(checkpoint.body.batch_start_seq..=checkpoint.body.batch_end_seq)
                .next()
                .is_none()
            {
                // Scoped exports retain the complete checkpoint prefix for
                // transparency validation. An earlier checkpoint batch may
                // already have been archived and deleted from the live claim
                // log, but it does not need to be rebuilt when none of its
                // receipts are in this export.
                continue;
            }
            let canonical_bytes = self.receipts_canonical_bytes_range(
                checkpoint.body.batch_start_seq,
                checkpoint.body.batch_end_seq,
            )?;
            if canonical_bytes.is_empty() {
                continue;
            }

            let leaves = canonical_bytes
                .iter()
                .map(|(_, bytes)| bytes.clone())
                .collect::<Vec<_>>();
            let tree = MerkleTree::from_leaves(&leaves)?;
            let leaf_index_by_seq = canonical_bytes
                .iter()
                .enumerate()
                .map(|(index, (seq, _))| (*seq, index))
                .collect::<BTreeMap<_, _>>();

            for (seq, _) in exported_by_seq
                .range(checkpoint.body.batch_start_seq..=checkpoint.body.batch_end_seq)
            {
                if let Some(leaf_index) = leaf_index_by_seq.get(seq) {
                    proofs.push(build_inclusion_proof(
                        &tree,
                        *leaf_index,
                        checkpoint.body.checkpoint_seq,
                        *seq,
                    )?);
                    covered_seqs.insert(*seq, ());
                }
            }
        }

        let uncheckpointed_receipts = tool_receipts
            .iter()
            .filter(|record| !covered_seqs.contains_key(&record.seq))
            .map(|record| EvidenceUncheckpointedReceipt {
                seq: record.seq,
                receipt_id: record.receipt.id.clone(),
            })
            .collect();

        Ok((proofs, uncheckpointed_receipts))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistedCheckpointPublicationCore {
    publication_schema: String,
    merkle_root: String,
    published_at: u64,
    kernel_key: String,
    log_tree_size: u64,
    entry_start_seq: u64,
    entry_end_seq: u64,
    previous_checkpoint_sha256: Option<String>,
}

fn load_checkpoint_publication_core(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<PersistedCheckpointPublicationCore>, EvidenceExportError> {
    let checkpoint_seq = i64::try_from(checkpoint_seq).map_err(|_| {
        EvidenceExportError::ReceiptStore(ReceiptStoreError::Conflict(
            "checkpoint_seq exceeds SQLite INTEGER range".to_string(),
        ))
    })?;
    connection
        .query_row(
            r#"
            SELECT publication_schema, merkle_root, published_at, kernel_key,
                   log_tree_size, entry_start_seq, entry_end_seq, previous_checkpoint_sha256
            FROM checkpoint_publication_metadata
            WHERE checkpoint_seq = ?1
            "#,
            params![checkpoint_seq],
            |row| {
                Ok(PersistedCheckpointPublicationCore {
                    publication_schema: row.get::<_, String>(0)?,
                    merkle_root: row.get::<_, String>(1)?,
                    published_at: row.get::<_, i64>(2)?.max(0) as u64,
                    kernel_key: row.get::<_, String>(3)?,
                    log_tree_size: row.get::<_, i64>(4)?.max(0) as u64,
                    entry_start_seq: row.get::<_, i64>(5)?.max(0) as u64,
                    entry_end_seq: row.get::<_, i64>(6)?.max(0) as u64,
                    previous_checkpoint_sha256: row.get::<_, Option<String>>(7)?,
                })
            },
        )
        .optional()
        .map_err(EvidenceExportError::from)
}

fn load_checkpoint_publication_trust_anchor_binding(
    connection: &Connection,
    checkpoint_seq: u64,
) -> Result<Option<CheckpointPublicationTrustAnchorBinding>, EvidenceExportError> {
    let checkpoint_seq = i64::try_from(checkpoint_seq).map_err(|_| {
        EvidenceExportError::ReceiptStore(ReceiptStoreError::Conflict(
            "checkpoint_seq exceeds SQLite INTEGER range".to_string(),
        ))
    })?;
    let binding_json = connection
        .query_row(
            r#"
            SELECT binding_json
            FROM checkpoint_publication_trust_anchor_bindings
            WHERE checkpoint_seq = ?1
            "#,
            params![checkpoint_seq],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    binding_json
        .map(|value| serde_json::from_str::<CheckpointPublicationTrustAnchorBinding>(&value))
        .transpose()
        .map_err(EvidenceExportError::from)
}

fn publication_core_matches(
    publication: &CheckpointPublication,
    persisted: &PersistedCheckpointPublicationCore,
) -> bool {
    publication.schema == persisted.publication_schema
        && publication.merkle_root.to_hex() == persisted.merkle_root
        && publication.published_at == persisted.published_at
        && publication.kernel_key.to_hex() == persisted.kernel_key
        && publication.log_tree_size == persisted.log_tree_size
        && publication.entry_start_seq == persisted.entry_start_seq
        && publication.entry_end_seq == persisted.entry_end_seq
        && publication.previous_checkpoint_sha256 == persisted.previous_checkpoint_sha256
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chio_core::capability::{
        attenuation::{DelegationLink, DelegationLinkBody},
        scope::{ChioScope, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
        lineage::ChildRequestReceipt, lineage::ChildRequestReceiptBody,
    };
    use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
    use chio_kernel::checkpoint::validate_checkpoint_transparency;
    use chio_kernel::checkpoint::{build_checkpoint_with_previous, checkpoint_chain_leaf_hash};
    use chio_kernel::{build_checkpoint, ReceiptStore};

    use super::*;

    fn unique_db_path(prefix: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}-{nonce}.sqlite3"))
    }

    fn capability_with_id(
        id: &str,
        subject: &Keypair,
        issuer: &Keypair,
        parent_capability_id: Option<&str>,
    ) -> CapabilityToken {
        let mut delegation_chain = Vec::new();
        if let Some(parent) = parent_capability_id {
            delegation_chain.push(
                DelegationLink::sign(
                    DelegationLinkBody {
                        capability_id: parent.to_string(),
                        delegator: issuer.public_key(),
                        delegatee: subject.public_key(),
                        attenuations: Vec::new(),
                        timestamp: 100,
                        scope_hash: None,
                        aggregate_budget: None,
                        cumulative_approval: None,
                    },
                    issuer,
                )
                .expect("sign delegation link"),
            );
        }
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: subject.public_key(),
                scope: ChioScope {
                    grants: vec![ToolGrant {
                        server_id: "shell".to_string(),
                        tool_name: "bash".to_string(),
                        operations: vec![Operation::Invoke],
                        constraints: vec![],
                        max_invocations: None,
                        max_cost_per_invocation: None,
                        max_total_cost: None,
                        dpop_required: None,
                    }],
                    ..ChioScope::default()
                },
                issued_at: 100,
                expires_at: 10_000,
                delegation_chain,
                aggregate_invocation_budget: None,
            },
            issuer,
        )
        .expect("sign capability")
    }

    fn receipt_with_ts(id: &str, capability_id: &str, timestamp: u64) -> ChioReceipt {
        receipt_with_ts_and_tenant(id, capability_id, timestamp, None)
    }

    fn evidence_receipt_keypair() -> Keypair {
        Keypair::from_seed(&[0x42; 32])
    }

    fn receipt_with_ts_and_tenant(
        id: &str,
        capability_id: &str,
        timestamp: u64,
        tenant_id: Option<&str>,
    ) -> ChioReceipt {
        let keypair = evidence_receipt_keypair();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction::from_parameters(
                    serde_json::json!({"cmd":"echo hi", "receipt": id}),
                )
                .expect("action"),
                decision: Some(Decision::Allow),
                receipt_kind: Default::default(),
                boundary_class: Default::default(),
                observation_outcome: None,
                tool_origin: Default::default(),
                redaction_mode: Default::default(),
                actor_chain: Vec::new(),
                content_hash: format!("content-{id}"),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::receipt::kinds::TrustLevel::default(),
                tenant_id: tenant_id.map(ToOwned::to_owned),
                kernel_key: keypair.public_key(),
                bbs_projection_version: None,
            },
            &keypair,
        )
        .expect("sign receipt")
    }

    fn child_receipt_with_ts(id: &str, timestamp: u64) -> ChildRequestReceipt {
        let keypair = Keypair::generate();
        ChildRequestReceipt::sign(
            ChildRequestReceiptBody {
                id: id.to_string(),
                timestamp,
                session_id: SessionId::new("sess-evidence"),
                parent_request_id: RequestId::new("parent-evidence"),
                request_id: RequestId::new(format!("request-{id}")),
                operation_kind: OperationKind::CreateMessage,
                terminal_state: OperationTerminalState::Completed,
                outcome_hash: format!("outcome-{id}"),
                policy_hash: "policy-evidence".to_string(),
                metadata: None,
                kernel_key: keypair.public_key(),
            },
            &keypair,
        )
        .expect("sign child receipt")
    }

    #[test]
    fn builds_bundle_with_receipts_lineage_and_proofs() {
        let path = unique_db_path("evidence-export");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let root = capability_with_id("cap-root", &subject, &issuer, None);
        let child = capability_with_id("cap-child", &subject, &issuer, Some("cap-root"));

        store.record_capability_snapshot(&root, None).unwrap();
        store
            .record_capability_snapshot(&child, Some("cap-root"))
            .unwrap();

        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-child", 100))
            .unwrap();
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-child", 101))
            .unwrap();
        store
            .append_child_receipt(&child_receipt_with_ts("child-1", 100))
            .unwrap();

        let canonical = store.receipts_canonical_bytes_range(seq1, seq2).unwrap();
        let checkpoint = build_checkpoint(
            1,
            seq1,
            seq2,
            &canonical
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &evidence_receipt_keypair(),
        )
        .unwrap();
        store.store_checkpoint(&checkpoint).unwrap();

        let bundle = store
            .build_evidence_export_bundle(&EvidenceExportQuery::admin_all())
            .unwrap();

        assert_eq!(bundle.tool_receipts.len(), 2);
        assert_eq!(bundle.child_receipts.len(), 1);
        assert_eq!(
            bundle.child_receipt_scope,
            EvidenceChildReceiptScope::FullQueryWindow
        );
        assert_eq!(bundle.checkpoints.len(), 1);
        assert_eq!(bundle.inclusion_proofs.len(), 2);
        assert!(bundle.uncheckpointed_receipts.is_empty());
        assert_eq!(bundle.capability_lineage.len(), 2);
        assert!(bundle
            .capability_lineage
            .iter()
            .all(|snapshot| snapshot.signed_capability.is_some()));
        assert!(bundle
            .retention
            .live_db_size_bytes
            .is_some_and(|size| size > 0));

        let transparency = validate_checkpoint_transparency(&bundle.checkpoints).unwrap();
        assert_eq!(transparency.publications.len(), 1);
        assert!(transparency.witnesses.is_empty());
        assert!(transparency.equivocations.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn scoped_export_includes_checkpoint_prefix_to_genesis() {
        let path = unique_db_path("evidence-export-checkpoint-prefix");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let checkpoint_key = evidence_receipt_keypair();

        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-1", 100))
            .unwrap();
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-1", 101))
            .unwrap();
        let seq3 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-3", "cap-1", 102))
            .unwrap();
        let seq4 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-4", "cap-1", 103))
            .unwrap();

        let first_bytes = store.receipts_canonical_bytes_range(seq1, seq2).unwrap();
        let first = build_checkpoint(
            1,
            seq1,
            seq2,
            &first_bytes
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &checkpoint_key,
        )
        .unwrap();
        store.store_checkpoint(&first).unwrap();

        let second_bytes = store.receipts_canonical_bytes_range(seq3, seq4).unwrap();
        let second = build_checkpoint_with_previous(
            2,
            seq3,
            seq4,
            &second_bytes
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &checkpoint_key,
            Some(&first),
            &[checkpoint_chain_leaf_hash(&first.body).unwrap()],
        )
        .unwrap();
        store.store_checkpoint(&second).unwrap();

        let mut query = EvidenceExportQuery::admin_all();
        query.since = Some(102);
        let (bundle, transparency) = store
            .build_evidence_export_bundle_with_transparency(&query)
            .unwrap();

        assert_eq!(bundle.tool_receipts.len(), 2);
        assert_eq!(
            bundle
                .checkpoints
                .iter()
                .map(|checkpoint| checkpoint.body.checkpoint_seq)
                .collect::<Vec<_>>(),
            vec![1, 2],
            "a scoped export must carry the predecessor prefix to checkpoint 1"
        );
        assert_eq!(transparency.publications.len(), 2);
        assert_eq!(transparency.witnesses.len(), 1);
        assert!(transparency.equivocations.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn scoped_export_skips_archived_checkpoint_batches_without_selected_receipts() {
        let path = unique_db_path("evidence-export-archived-prefix");
        let archive = unique_db_path("evidence-export-archived-prefix-archive");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let checkpoint_key = evidence_receipt_keypair();

        let seq1 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-1", 100))
            .unwrap();
        let seq2 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-2", "cap-1", 101))
            .unwrap();
        let seq3 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-3", "cap-1", 102))
            .unwrap();
        let seq4 = store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-4", "cap-1", 103))
            .unwrap();

        let first_bytes = store.receipts_canonical_bytes_range(seq1, seq2).unwrap();
        let first = build_checkpoint(
            1,
            seq1,
            seq2,
            &first_bytes
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &checkpoint_key,
        )
        .unwrap();
        store.store_checkpoint(&first).unwrap();

        let second_bytes = store.receipts_canonical_bytes_range(seq3, seq4).unwrap();
        let second = build_checkpoint_with_previous(
            2,
            seq3,
            seq4,
            &second_bytes
                .into_iter()
                .map(|(_, bytes)| bytes)
                .collect::<Vec<_>>(),
            &checkpoint_key,
            Some(&first),
            &[checkpoint_chain_leaf_hash(&first.body).unwrap()],
        )
        .unwrap();
        store.store_checkpoint(&second).unwrap();

        let archived = store
            .archive_receipts_before(102, archive.to_str().unwrap())
            .unwrap();
        assert_eq!(archived, 2);

        let mut query = EvidenceExportQuery::admin_all();
        query.since = Some(102);
        let bundle = store.build_evidence_export_bundle(&query).unwrap();

        assert_eq!(bundle.checkpoints.len(), 2);
        assert_eq!(bundle.inclusion_proofs.len(), 2);
        assert!(bundle.uncheckpointed_receipts.is_empty());
        assert!(bundle
            .inclusion_proofs
            .iter()
            .all(|proof| proof.checkpoint_seq == 2));

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(archive);
    }

    #[test]
    fn evidence_export_requires_explicit_receipt_read_boundary() {
        let path = unique_db_path("evidence-export-read-boundary");
        let store = SqliteReceiptStore::open(&path).unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-1", 100))
            .unwrap();

        let error = store
            .build_evidence_export_bundle(&EvidenceExportQuery::default())
            .expect_err("missing read boundary must fail closed");
        assert!(error.to_string().contains("receipt read boundary"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tenant_scoped_evidence_export_cannot_see_other_tenants() {
        let path = unique_db_path("evidence-export-tenant");
        let store = SqliteReceiptStore::open(&path).unwrap();
        store.with_strict_tenant_isolation(true);
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                "rcpt-a",
                "cap-a",
                100,
                Some("tenant-a"),
            ))
            .unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                "rcpt-b",
                "cap-b",
                100,
                Some("tenant-b"),
            ))
            .unwrap();

        let bundle = store
            .build_evidence_export_bundle(&EvidenceExportQuery::tenant_scoped("tenant-a"))
            .unwrap();

        assert_eq!(bundle.query.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(bundle.tool_receipts.len(), 1);
        assert_eq!(
            bundle.tool_receipts[0].receipt.tenant_id.as_deref(),
            Some("tenant-a")
        );
        assert_eq!(bundle.retention.live_db_size_bytes, None);
        assert_eq!(bundle.retention.oldest_live_receipt_timestamp, Some(100));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tenant_scoped_evidence_export_omits_child_receipts_without_tenant_join() {
        let path = unique_db_path("evidence-export-tenant-child");
        let store = SqliteReceiptStore::open(&path).unwrap();
        store.with_strict_tenant_isolation(true);
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                "rcpt-a",
                "cap-a",
                100,
                Some("tenant-a"),
            ))
            .unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts_and_tenant(
                "rcpt-b",
                "cap-b",
                100,
                Some("tenant-b"),
            ))
            .unwrap();
        store
            .append_child_receipt(&child_receipt_with_ts("child-tenant-unknown", 100))
            .unwrap();

        let bundle = store
            .build_evidence_export_bundle(&EvidenceExportQuery::tenant_scoped("tenant-a"))
            .unwrap();

        assert_eq!(
            bundle.child_receipt_scope,
            EvidenceChildReceiptScope::OmittedNoJoinPath
        );
        assert!(bundle.child_receipts.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn omits_child_receipts_for_capability_scoped_export_without_time_window() {
        let path = unique_db_path("evidence-export-scope");
        let store = SqliteReceiptStore::open(&path).unwrap();
        let issuer = Keypair::generate();
        let subject = Keypair::generate();
        let capability = capability_with_id("cap-scoped", &subject, &issuer, None);
        store.record_capability_snapshot(&capability, None).unwrap();
        store
            .append_chio_receipt_returning_seq(&receipt_with_ts("rcpt-1", "cap-scoped", 100))
            .unwrap();
        store
            .append_child_receipt(&child_receipt_with_ts("child-1", 100))
            .unwrap();

        let bundle = store
            .build_evidence_export_bundle(&EvidenceExportQuery {
                capability_id: Some("cap-scoped".to_string()),
                ..EvidenceExportQuery::admin_all()
            })
            .unwrap();

        assert_eq!(
            bundle.child_receipt_scope,
            EvidenceChildReceiptScope::OmittedNoJoinPath
        );
        assert!(bundle.child_receipts.is_empty());

        let _ = std::fs::remove_file(path);
    }
}
