use std::collections::BTreeMap;

use chio_core::merkle::MerkleTree;
use chio_core::receipt::CheckpointPublicationTrustAnchorBinding;
use chio_kernel::capability_lineage::CapabilitySnapshot;
use chio_kernel::checkpoint::{
    build_inclusion_proof, build_trust_anchored_checkpoint_publication,
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

use crate::receipt_store::SqliteReceiptStore;

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
        let tool_receipts = self.collect_tool_receipts_for_export(query)?;
        let child_receipt_scope = self.resolve_child_receipt_scope(query);
        let child_receipts = self.collect_child_receipts_for_export(query, child_receipt_scope)?;
        let checkpoints = self.collect_checkpoints_for_export(&tool_receipts)?;
        let capability_lineage = self.collect_lineage_for_export(&tool_receipts)?;
        let (inclusion_proofs, uncheckpointed_receipts) =
            self.collect_inclusion_proofs_for_export(&tool_receipts, &checkpoints)?;
        let retention = EvidenceRetentionMetadata {
            live_db_size_bytes: self.db_size_bytes()?,
            oldest_live_receipt_timestamp: self.oldest_receipt_timestamp()?,
        };

        Ok(EvidenceExportBundle {
            query: query.clone(),
            tool_receipts,
            child_receipts,
            child_receipt_scope,
            checkpoints,
            capability_lineage,
            inclusion_proofs,
            uncheckpointed_receipts,
            retention,
        })
    }

    pub fn build_evidence_export_transparency_summary(
        &self,
        checkpoints: &[KernelCheckpoint],
    ) -> Result<CheckpointTransparencySummary, EvidenceExportError> {
        let mut summary = validate_checkpoint_transparency(checkpoints)?;
        if summary.publications.is_empty() {
            return Ok(summary);
        }

        let checkpoint_by_seq = checkpoints
            .iter()
            .map(|checkpoint| (checkpoint.body.checkpoint_seq, checkpoint))
            .collect::<BTreeMap<_, _>>();
        let connection = self.connection()?;
        for publication in &mut summary.publications {
            let Some(checkpoint) = checkpoint_by_seq.get(&publication.checkpoint_seq).copied()
            else {
                return Err(EvidenceExportError::ReceiptStore(
                    ReceiptStoreError::Conflict(format!(
                        "checkpoint {} is missing while deriving publication summary",
                        publication.checkpoint_seq
                    )),
                ));
            };
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
                *publication = build_trust_anchored_checkpoint_publication(checkpoint, binding)?;
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
            records.extend(
                page.receipts
                    .into_iter()
                    .map(|stored| EvidenceToolReceiptRecord {
                        seq: stored.seq,
                        receipt: stored.receipt,
                    }),
            );
            match next_cursor {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }

        Ok(records)
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
    ) -> Result<Vec<KernelCheckpoint>, EvidenceExportError> {
        let (Some(min_seq), Some(max_seq)) = (
            tool_receipts.first().map(|record| record.seq),
            tool_receipts.last().map(|record| record.seq),
        ) else {
            return Ok(Vec::new());
        };

        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
            SELECT checkpoint_seq
            FROM kernel_checkpoints
            WHERE batch_end_seq >= ?1
              AND batch_start_seq <= ?2
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

        validate_checkpoint_transparency(&checkpoints)?;

        Ok(checkpoints)
    }

    fn collect_lineage_for_export(
        &self,
        tool_receipts: &[EvidenceToolReceiptRecord],
    ) -> Result<Vec<CapabilitySnapshot>, EvidenceExportError> {
        let mut snapshots = BTreeMap::<String, CapabilitySnapshot>::new();
        for record in tool_receipts {
            for snapshot in self.get_combined_delegation_chain(&record.receipt.capability_id)? {
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
        CapabilityToken, CapabilityTokenBody, ChioScope, DelegationLink, DelegationLinkBody,
        Operation, ToolGrant,
    };
    use chio_core::crypto::Keypair;
    use chio_core::receipt::{
        ChildRequestReceipt, ChildRequestReceiptBody, ChioReceipt, ChioReceiptBody, Decision,
        ToolCallAction,
    };
    use chio_core::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
    use chio_kernel::checkpoint::validate_checkpoint_transparency;
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
            },
            issuer,
        )
        .expect("sign capability")
    }

    fn receipt_with_ts(id: &str, capability_id: &str, timestamp: u64) -> ChioReceipt {
        let keypair = Keypair::generate();
        ChioReceipt::sign(
            ChioReceiptBody {
                id: id.to_string(),
                timestamp,
                capability_id: capability_id.to_string(),
                tool_server: "shell".to_string(),
                tool_name: "bash".to_string(),
                action: ToolCallAction::from_parameters(serde_json::json!({"cmd":"echo hi"}))
                    .expect("action"),
                decision: Decision::Allow,
                content_hash: "content-1".to_string(),
                policy_hash: "policy-1".to_string(),
                evidence: Vec::new(),
                metadata: None,
                trust_level: chio_core::TrustLevel::default(),
                tenant_id: None,
                kernel_key: keypair.public_key(),
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
            &issuer,
        )
        .unwrap();
        store.store_checkpoint(&checkpoint).unwrap();

        let bundle = store
            .build_evidence_export_bundle(&EvidenceExportQuery::default())
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
        assert!(bundle.retention.live_db_size_bytes > 0);

        let transparency = validate_checkpoint_transparency(&bundle.checkpoints).unwrap();
        assert_eq!(transparency.publications.len(), 1);
        assert!(transparency.witnesses.is_empty());
        assert!(transparency.equivocations.is_empty());

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
                ..EvidenceExportQuery::default()
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
