use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::thread;

use chio_core::capability::{attenuation::{AttenuationProof, DelegationLink, DelegationLinkBody, compute_attenuation_witness, scope_hash}, governance::{CallChainContinuationAudience, CallChainContinuationToken, CallChainContinuationTokenBody, GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY, GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY, GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody, GovernedAutonomyContext, GovernedAutonomyTier, GovernedCallChainContext, GovernedTransactionIntent, GovernedUpstreamCallChainProof, GovernedUpstreamCallChainProofBody}, scope::{ChioScope, Constraint, MonetaryAmount, Operation, PromptGrant, ResourceGrant, ToolGrant}, token::{CapabilityToken, CapabilityTokenAttenuationBody, CapabilityTokenBody}};
use chio_core::credit::{
    CreditBondArtifact, CreditBondDisposition, CreditBondLifecycleState, CreditBondPrerequisites,
    CreditBondReport, CreditBondSupportBoundary, CreditScorecardBand, CreditScorecardConfidence,
    CreditScorecardSummary, ExposureLedgerQuery, ExposureLedgerSummary, SignedCreditBond,
    CREDIT_BOND_ARTIFACT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, metadata::GuardEvidence, decision::ToolCallAction,
};
use chio_core::session::{
    CompleteOperation, CompletionArgument, CompletionReference, CreateMessageOperation,
    GetPromptOperation, OperationContext, RequestId, SamplingMessage, SamplingTool,
    SamplingToolChoice, SessionAnchorReference, SessionAuthContext, SessionId, SessionOperation,
    ToolCallOperation,
};
use chio_core::{
    PromptArgument, PromptDefinition, PromptMessage, PromptResult, ReadResourceOperation,
    ResourceContent, ResourceDefinition, ResourceTemplateDefinition,
};
use chio_link::{ExchangeRate, PriceOracle, PriceOracleError};
use rusqlite::{params, Connection, OptionalExtension, Row};

struct SqliteReceiptStore {
    connection: Mutex<Connection>,
    // Test-double analogue of the real store's writer-actor signer install
    // (`enable_background_checkpoints`). `None` until installed;
    // `max_batch == 0` disables checkpointing (ADR-0008).
    background_checkpoint_signer: Mutex<Option<(std::sync::Arc<Keypair>, u64)>>,
}

static UNIQUE_RECEIPT_DB_COUNTER: AtomicU64 = AtomicU64::new(0);

impl SqliteReceiptStore {
    fn open(path: impl AsRef<Path>) -> Result<Self, ReceiptStoreError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(
            r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS chio_tool_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    timestamp INTEGER NOT NULL,
                    capability_id TEXT NOT NULL,
                    raw_json TEXT NOT NULL
                );

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

                CREATE TABLE IF NOT EXISTS kernel_checkpoints (
                    checkpoint_seq INTEGER PRIMARY KEY,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS capability_lineage (
                    capability_id TEXT PRIMARY KEY,
                    subject_key TEXT NOT NULL,
                    issuer_key TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    grants_json TEXT NOT NULL,
                    delegation_depth INTEGER NOT NULL DEFAULT 0,
                    parent_capability_id TEXT
                );

                CREATE TABLE IF NOT EXISTS credit_bonds (
                    bond_id TEXT PRIMARY KEY,
                    lifecycle_state TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS session_anchors (
                    anchor_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    auth_context_fingerprint TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    supersedes_anchor_id TEXT,
                    is_current INTEGER NOT NULL DEFAULT 1,
                    raw_json TEXT NOT NULL
                );
                "#,
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            background_checkpoint_signer: Mutex::new(None),
        })
    }

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

    /// Locked analogue of the `ReceiptStore::load_latest_checkpoint` default,
    /// usable from a call site that already holds `self.connection`'s guard
    /// (avoids re-locking the non-reentrant `Mutex<Connection>`).
    fn load_latest_checkpoint_locked(
        connection: &Connection,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        let mut checkpoint_seq = 1;
        let mut latest = None;
        loop {
            let Some(checkpoint) = Self::load_checkpoint_by_seq_locked(connection, checkpoint_seq)?
            else {
                return Ok(latest);
            };
            checkpoint_seq = checkpoint.body.checkpoint_seq.checked_add(1).ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "checkpoint_seq overflow while loading latest".to_string(),
                )
            })?;
            latest = Some(checkpoint);
        }
    }

    fn receipts_canonical_bytes_range_locked(
        connection: &Connection,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let mut statement = connection.prepare(
            r#"
                SELECT seq, raw_json
                FROM chio_tool_receipts
                WHERE seq >= ?1 AND seq <= ?2
                ORDER BY seq ASC
                "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            let value = serde_json::from_str::<serde_json::Value>(&raw_json)?;
            let bytes = canonical_json_bytes(&value)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            Ok((seq.max(0) as u64, bytes))
        })
        .collect()
    }

    fn store_checkpoint_locked(
        connection: &Connection,
        checkpoint: &KernelCheckpoint,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(checkpoint)?;
        connection.execute(
            r#"
                INSERT INTO kernel_checkpoints (checkpoint_seq, raw_json)
                VALUES (?1, ?2)
                ON CONFLICT(checkpoint_seq) DO UPDATE SET raw_json = excluded.raw_json
                "#,
            params![checkpoint.body.checkpoint_seq as i64, raw_json],
        )?;
        Ok(())
    }

    fn create_next_receipt_checkpoint_locked(
        connection: &Connection,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        if max_batch == 0 {
            return Err(ReceiptStoreError::Conflict(
                "checkpoint max_batch must be greater than zero".to_string(),
            ));
        }
        let latest_committed_entry_seq = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let latest_committed_entry_seq = latest_committed_entry_seq.max(0) as u64;
        let previous_checkpoint = Self::load_latest_checkpoint_locked(connection)?;
        let latest_checkpointed_entry_seq = previous_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        if latest_committed_entry_seq <= latest_checkpointed_entry_seq {
            return Ok(ReceiptCheckpointCreateReport {
                created: false,
                checkpoint_seq: None,
                batch_start_seq: None,
                batch_end_seq: None,
                latest_committed_entry_seq,
                latest_checkpointed_entry_seq,
            });
        }
        let batch_start_seq = latest_checkpointed_entry_seq + 1;
        let batch_end_seq = latest_committed_entry_seq.min(batch_start_seq + max_batch - 1);
        let receipt_bytes_with_seqs = Self::receipts_canonical_bytes_range_locked(
            connection,
            batch_start_seq,
            batch_end_seq,
        )?;
        let expected_len = batch_end_seq - batch_start_seq + 1;
        if receipt_bytes_with_seqs.len() as u64 != expected_len
            || receipt_bytes_with_seqs
                .first()
                .map(|(seq, _)| *seq)
                .unwrap_or(0)
                != batch_start_seq
            || receipt_bytes_with_seqs
                .last()
                .map(|(seq, _)| *seq)
                .unwrap_or(0)
                != batch_end_seq
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "checkpoint receipt range {}..={} is not contiguous",
                batch_start_seq, batch_end_seq
            )));
        }
        let receipt_bytes = receipt_bytes_with_seqs
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        let checkpoint_seq = previous_checkpoint
            .as_ref()
            .map_or(Ok(1), |checkpoint| {
                checkpoint.body.checkpoint_seq.checked_add(1).ok_or_else(|| {
                    ReceiptStoreError::Conflict(
                        "checkpoint_seq overflow while creating receipt checkpoint".to_string(),
                    )
                })
            })?;
        let checkpoint = build_checkpoint_with_previous(
            checkpoint_seq,
            batch_start_seq,
            batch_end_seq,
            &receipt_bytes,
            keypair,
            previous_checkpoint.as_ref(),
        )
        .map_err(|error| ReceiptStoreError::Conflict(format!("checkpoint build failed: {error}")))?;
        Self::store_checkpoint_locked(connection, &checkpoint)?;
        Ok(ReceiptCheckpointCreateReport {
            created: true,
            checkpoint_seq: Some(checkpoint.body.checkpoint_seq),
            batch_start_seq: Some(checkpoint.body.batch_start_seq),
            batch_end_seq: Some(checkpoint.body.batch_end_seq),
            latest_committed_entry_seq,
            latest_checkpointed_entry_seq: checkpoint.body.batch_end_seq,
        })
    }

    /// Test-double analogue of the real store's writer-actor checkpoint
    /// construction: synchronous, but performed under the same
    /// connection lock as the triggering append, so concurrent callers see
    /// contiguous batches without needing a conflict-retry loop.
    fn maybe_build_background_checkpoint_locked(
        connection: &Connection,
        seq: u64,
        signer: &(std::sync::Arc<Keypair>, u64),
    ) -> Result<(), ReceiptStoreError> {
        let (keypair, max_batch) = signer;
        if *max_batch == 0 {
            return Ok(());
        }
        let latest_checkpointed_entry_seq = Self::load_latest_checkpoint_locked(connection)?
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        if seq <= latest_checkpointed_entry_seq
            || (seq - latest_checkpointed_entry_seq) < *max_batch
        {
            return Ok(());
        }
        Self::create_next_receipt_checkpoint_locked(connection, *max_batch, keypair)?;
        Ok(())
    }

    fn get_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, CapabilityLineageError> {
        fn snapshot_from_row(row: &Row<'_>) -> rusqlite::Result<CapabilitySnapshot> {
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
        }

        let mut chain = Vec::new();
        let mut current = Some(capability_id.to_string());

        while let Some(current_id) = current.take() {
            let snapshot = self
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
                            parent_capability_id
                        FROM capability_lineage
                        WHERE capability_id = ?1
                        "#,
                    params![current_id],
                    snapshot_from_row,
                )
                .optional()?;
            let Some(snapshot) = snapshot else {
                break;
            };
            current = snapshot.parent_capability_id.clone();
            chain.push(snapshot);
        }

        chain.reverse();
        Ok(chain)
    }

    fn get_lineage(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, CapabilityLineageError> {
        self.connection()?
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
                        parent_capability_id
                    FROM capability_lineage
                    WHERE capability_id = ?1
                "#,
                params![capability_id],
                |row| {
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
                },
            )
            .optional()
            .map_err(Into::into)
    }

    fn record_credit_bond(
        &self,
        bond: &SignedCreditBond,
        lifecycle_state: CreditBondLifecycleState,
    ) -> Result<(), ReceiptStoreError> {
        self.connection()?.execute(
            "INSERT OR REPLACE INTO credit_bonds (bond_id, lifecycle_state, expires_at, raw_json)
                 VALUES (?1, ?2, ?3, ?4)",
            params![
                bond.body.bond_id,
                match lifecycle_state {
                    CreditBondLifecycleState::Active => "active",
                    CreditBondLifecycleState::Superseded => "superseded",
                    CreditBondLifecycleState::Released => "released",
                    CreditBondLifecycleState::Impaired => "impaired",
                    CreditBondLifecycleState::Expired => "expired",
                },
                bond.body.expires_at as i64,
                serde_json::to_string(bond)?,
            ],
        )?;
        Ok(())
    }
}

impl ReceiptStore for SqliteReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.append_chio_receipt_returning_seq(receipt)?;
        Ok(())
    }

    fn supports_kernel_signed_checkpoints(&self) -> bool {
        true
    }

    fn enable_background_checkpoints(
        &self,
        keypair: Keypair,
        max_batch: u64,
    ) -> Result<bool, ReceiptStoreError> {
        let mut signer = self.background_checkpoint_signer.lock().map_err(|_| {
            ReceiptStoreError::Conflict(
                "background checkpoint signer lock poisoned".to_string(),
            )
        })?;
        *signer = Some((std::sync::Arc::new(keypair), max_batch));
        Ok(true)
    }

    fn append_chio_receipt_returning_seq(
        &self,
        receipt: &ChioReceipt,
    ) -> Result<Option<u64>, ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        let connection = self.connection()?;
        let rows = connection.execute(
            r#"
                INSERT INTO chio_tool_receipts (
                    receipt_id,
                    timestamp,
                    capability_id,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
            params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.capability_id,
                raw_json,
            ],
        )?;
        let seq = (rows > 0).then(|| connection.last_insert_rowid().max(0) as u64);
        if let Some(seq) = seq {
            // Test-double analogue of the real store's writer-actor checkpoint
            // construction: performed synchronously, still under the
            // connection lock this append holds, so it never observes a
            // concurrent writer's half-committed state.
            let signer = self.background_checkpoint_signer.lock().map_err(|_| {
                ReceiptStoreError::Conflict(
                    "background checkpoint signer lock poisoned".to_string(),
                )
            })?;
            if let Some(signer) = signer.as_ref() {
                Self::maybe_build_background_checkpoint_locked(&connection, seq, signer)?;
            }
        }
        Ok(seq)
    }

    fn flush_receipt_writes(&self) -> Result<ReceiptFlushReport, ReceiptStoreError> {
        // The double builds checkpoints synchronously, in-line with each
        // append (see `append_chio_receipt_returning_seq`), so there is
        // nothing queued to drain; report the current committed and
        // checkpointed positions.
        let connection = self.connection()?;
        let latest_committed_entry_seq = connection.query_row(
            "SELECT COALESCE(MAX(seq), 0) FROM chio_tool_receipts",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        let latest_committed_entry_seq = latest_committed_entry_seq.max(0) as u64;
        let latest_checkpoint = Self::load_latest_checkpoint_locked(&connection)?;
        let latest_checkpointed_entry_seq = latest_checkpoint
            .as_ref()
            .map_or(0, |checkpoint| checkpoint.body.batch_end_seq);
        let latest_checkpoint_seq =
            latest_checkpoint.map(|checkpoint| checkpoint.body.checkpoint_seq);
        Ok(ReceiptFlushReport {
            latest_committed_entry_seq,
            latest_checkpoint_seq,
            latest_checkpointed_entry_seq,
            ..Default::default()
        })
    }

    fn append_child_receipt(
        &self,
        receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        let raw_json = serde_json::to_string(receipt)?;
        self.connection()?.execute(
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
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                ON CONFLICT(receipt_id) DO NOTHING
                "#,
            params![
                receipt.id,
                receipt.timestamp as i64,
                receipt.session_id.as_str(),
                receipt.parent_request_id.as_str(),
                receipt.request_id.as_str(),
                receipt.operation_kind.as_str(),
                match &receipt.terminal_state {
                    OperationTerminalState::Completed => "completed",
                    OperationTerminalState::Cancelled { .. } => "cancelled",
                    OperationTerminalState::Incomplete { .. } => "incomplete",
                },
                receipt.policy_hash,
                receipt.outcome_hash,
                raw_json,
            ],
        )?;
        Ok(())
    }

    fn receipts_canonical_bytes_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<(u64, Vec<u8>)>, ReceiptStoreError> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            r#"
                SELECT seq, raw_json
                FROM chio_tool_receipts
                WHERE seq >= ?1 AND seq <= ?2
                ORDER BY seq ASC
                "#,
        )?;
        let rows = statement.query_map(params![start_seq as i64, end_seq as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;

        rows.map(|row| {
            let (seq, raw_json) = row?;
            let value = serde_json::from_str::<serde_json::Value>(&raw_json)?;
            let bytes = canonical_json_bytes(&value)
                .map_err(|error| ReceiptStoreError::Canonical(error.to_string()))?;
            Ok((seq.max(0) as u64, bytes))
        })
        .collect()
    }

    fn store_checkpoint(&self, checkpoint: &KernelCheckpoint) -> Result<(), ReceiptStoreError> {
        let connection = self.connection()?;
        Self::store_checkpoint_locked(&connection, checkpoint)
    }

    fn create_next_receipt_checkpoint(
        &self,
        max_batch: u64,
        keypair: &Keypair,
    ) -> Result<ReceiptCheckpointCreateReport, ReceiptStoreError> {
        let connection = self.connection()?;
        Self::create_next_receipt_checkpoint_locked(&connection, max_batch, keypair)
    }

    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        SqliteReceiptStore::load_checkpoint_by_seq(self, checkpoint_seq)
    }

    fn resolve_credit_bond(
        &self,
        bond_id: &str,
    ) -> Result<Option<CreditBondRow>, ReceiptStoreError> {
        self.connection()?
            .query_row(
                "SELECT raw_json, lifecycle_state FROM credit_bonds WHERE bond_id = ?1",
                params![bond_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
            .map(|(raw_json, lifecycle_state)| {
                let bond = serde_json::from_str::<SignedCreditBond>(&raw_json)?;
                let lifecycle_state = match lifecycle_state.as_str() {
                    "active" => CreditBondLifecycleState::Active,
                    "superseded" => CreditBondLifecycleState::Superseded,
                    "released" => CreditBondLifecycleState::Released,
                    "impaired" => CreditBondLifecycleState::Impaired,
                    "expired" => CreditBondLifecycleState::Expired,
                    other => {
                        return Err(ReceiptStoreError::Conflict(format!(
                            "unknown credit bond lifecycle state `{other}`"
                        )));
                    }
                };
                Ok(CreditBondRow {
                    bond,
                    lifecycle_state,
                    superseded_by_bond_id: None,
                })
            })
            .transpose()
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
        let connection = self.connection()?;
        let replaces_current_anchor = match supersedes_anchor_id {
            Some(supersedes_anchor_id) => connection
                .query_row(
                    r#"
                    SELECT is_current
                    FROM session_anchors
                    WHERE session_id = ?1
                      AND anchor_id = ?2
                    "#,
                    params![session_id, supersedes_anchor_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|is_current| is_current != 0)
                .unwrap_or(false),
            None => false,
        };
        let existing_anchor = connection
            .query_row(
                r#"
                    SELECT anchor_id
                    FROM session_anchors
                    WHERE session_id = ?1
                      AND auth_context_fingerprint = ?2
                      AND anchor_id <> ?3
                    LIMIT 1
                    "#,
                params![session_id, auth_context_fingerprint, anchor_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(existing_anchor) = existing_anchor {
            if !replaces_current_anchor {
                return Err(ReceiptStoreError::Conflict(format!(
                    "session anchor replay detected for session `{session_id}` auth_context_fingerprint `{auth_context_fingerprint}` existing `{existing_anchor}`"
                )));
            }
        }

        connection.execute(
            "UPDATE session_anchors SET is_current = 0 WHERE session_id = ?1 AND anchor_id <> ?2",
            params![session_id, anchor_id],
        )?;
        connection.execute(
            r#"
                INSERT INTO session_anchors (
                    anchor_id,
                    session_id,
                    auth_context_fingerprint,
                    issued_at,
                    supersedes_anchor_id,
                    is_current,
                    raw_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, 1, ?6)
                ON CONFLICT(anchor_id) DO UPDATE SET
                    auth_context_fingerprint = excluded.auth_context_fingerprint,
                    issued_at = excluded.issued_at,
                    supersedes_anchor_id = COALESCE(excluded.supersedes_anchor_id, session_anchors.supersedes_anchor_id),
                    is_current = 1,
                    raw_json = excluded.raw_json
                "#,
            params![
                anchor_id,
                session_id,
                auth_context_fingerprint,
                issued_at as i64,
                supersedes_anchor_id,
                serde_json::to_string(anchor_json)?,
            ],
        )?;
        Ok(())
    }

    fn record_capability_snapshot(
        &self,
        token: &CapabilityToken,
        parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        let grants_json = serde_json::to_string(&token.scope)?;
        let subject_key = token.subject.to_hex();
        let issuer_key = token.issuer.to_hex();
        let delegation_depth = if let Some(parent_id) = parent_capability_id {
            self.connection()?
                .query_row(
                    "SELECT delegation_depth FROM capability_lineage WHERE capability_id = ?1",
                    params![parent_id],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|depth| depth.max(0) as u64 + 1)
                .unwrap_or(1)
        } else {
            0
        };

        self.connection()?.execute(
            r#"
                INSERT OR REPLACE INTO capability_lineage (
                    capability_id,
                    subject_key,
                    issuer_key,
                    issued_at,
                    expires_at,
                    grants_json,
                    delegation_depth,
                    parent_capability_id
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
            params![
                token.id,
                subject_key,
                issuer_key,
                token.issued_at as i64,
                token.expires_at as i64,
                grants_json,
                delegation_depth as i64,
                parent_capability_id,
            ],
        )?;
        Ok(())
    }

    fn get_capability_snapshot(
        &self,
        capability_id: &str,
    ) -> Result<Option<CapabilitySnapshot>, ReceiptStoreError> {
        self.get_lineage(capability_id)
            .map_err(|error| match error {
                CapabilityLineageError::ReceiptStore(error) => error,
                CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
                CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            })
    }

    fn get_capability_delegation_chain(
        &self,
        capability_id: &str,
    ) -> Result<Vec<CapabilitySnapshot>, ReceiptStoreError> {
        self.get_delegation_chain(capability_id)
            .map_err(|error| match error {
                CapabilityLineageError::ReceiptStore(error) => error,
                CapabilityLineageError::Sqlite(error) => ReceiptStoreError::Sqlite(error),
                CapabilityLineageError::Json(error) => ReceiptStoreError::Json(error),
            })
    }
}

struct SqliteRevocationStore {
    path: PathBuf,
}

impl SqliteRevocationStore {
    fn open(path: impl AsRef<Path>) -> Result<Self, RevocationStoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            r#"
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = FULL;
                PRAGMA busy_timeout = 5000;

                CREATE TABLE IF NOT EXISTS revoked_capabilities (
                    capability_id TEXT PRIMARY KEY,
                    revoked_at INTEGER NOT NULL
                );
                "#,
        )?;
        Ok(Self { path })
    }

    fn connection(&self) -> Result<rusqlite::Connection, RevocationStoreError> {
        Ok(rusqlite::Connection::open(&self.path)?)
    }
}

impl RevocationStore for SqliteRevocationStore {
    fn is_revoked(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let connection = self.connection()?;
        let exists = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_capabilities WHERE capability_id = ?1)",
            params![capability_id],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(exists != 0)
    }

    fn revoke(&self, capability_id: &str) -> Result<bool, RevocationStoreError> {
        let connection = self.connection()?;
        let revoked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let rows = connection.execute(
            r#"
                INSERT INTO revoked_capabilities (capability_id, revoked_at)
                VALUES (?1, ?2)
                ON CONFLICT(capability_id) DO NOTHING
                "#,
            params![capability_id, revoked_at],
        )?;
        Ok(rows > 0)
    }
}

fn make_keypair() -> Keypair {
    Keypair::generate()
}

fn make_config() -> KernelConfig {
    KernelConfig {
        keypair: make_keypair(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "test-policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: crate::MemoryBudgetConfig::defaults(),
        deadlines: crate::HotPathDeadlineConfig::default(),
    }
}

fn make_kernel(config: KernelConfig) -> ChioKernel {
    ChioKernel::new(config)
}

fn make_signed_receipt(kp: &Keypair, id: &str) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_100,
            capability_id: "cap-receipt".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"message": "hello"}))
                .expect("tool action"),
            decision: Some(Decision::Allow),
            receipt_kind: chio_core::receipt::kinds::ReceiptKind::MediatedDecision,
            boundary_class: chio_core::receipt::kinds::BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: chio_core::receipt::kinds::ToolOrigin::CallerExecuted,
            redaction_mode: chio_core::receipt::kinds::RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "0".repeat(64),
            policy_hash: "1".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
            bbs_projection_version: None,
        },
        kp,
    )
    .expect("sign receipt")
}

fn unique_receipt_db_path(prefix: &str) -> std::path::PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_RECEIPT_DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("{prefix}-{}-{nonce}-{counter}.sqlite3", std::process::id()))
}

fn make_elicited_content() -> CreateElicitationResult {
    CreateElicitationResult {
        action: chio_core::session::ElicitationAction::Accept,
        content: Some(serde_json::json!({
            "environment": "staging",
        })),
    }
}

fn make_grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn make_scope(grants: Vec<ToolGrant>) -> ChioScope {
    ChioScope {
        grants,
        ..ChioScope::default()
    }
}

fn make_capability(
    kernel: &ChioKernel,
    subject_kp: &Keypair,
    scope: ChioScope,
    ttl: u64,
) -> CapabilityToken {
    kernel
        .issue_capability(&subject_kp.public_key(), scope, ttl)
        .unwrap()
}

fn make_direct_attenuated_capability(
    issuer: &Keypair,
    subject: &PublicKey,
    scope: ChioScope,
) -> CapabilityToken {
    let now = current_unix_timestamp();
    let parent_hash = scope_hash(&scope).expect("hash parent scope");
    let child_hash = scope_hash(&scope).expect("hash child scope");
    let witness = compute_attenuation_witness(&scope, &scope).expect("compute attenuation witness");
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: "cap-direct-attenuated".to_string(),
                issuer: issuer.public_key(),
                subject: subject.clone(),
                scope,
                issued_at: now.saturating_sub(60),
                expires_at: now.saturating_add(300),
                delegation_chain: Vec::new(),
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: parent_hash,
                child_scope_hash: child_hash,
                normalized_subset_proof: witness,
            },
            budget_share_bps: None,
        },
        issuer,
    )
    .expect("sign attenuated capability")
}

fn make_request(
    request_id: &str,
    cap: &CapabilityToken,
    tool: &str,
    server: &str,
) -> ToolCallRequest {
    make_request_with_arguments(
        request_id,
        cap,
        tool,
        server,
        serde_json::json!({"path": "/app/src/main.rs"}),
    )
}

fn make_request_with_arguments(
    request_id: &str,
    cap: &CapabilityToken,
    tool: &str,
    server: &str,
    arguments: serde_json::Value,
) -> ToolCallRequest {
    ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: cap.subject.to_hex(),
        arguments,
        dpop_proof: None,
        execution_nonce: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
        federated_origin_kernel_id: None,
    }
}

fn make_operation_context(
    session_id: &SessionId,
    request_id: &str,
    agent_id: &str,
) -> OperationContext {
    OperationContext::new(
        session_id.clone(),
        RequestId::new(request_id),
        agent_id.to_string(),
    )
}

fn session_tool_call(response: SessionOperationResponse) -> Option<ToolCallResponse> {
    if let SessionOperationResponse::ToolCall(response) = response {
        Some(response)
    } else {
        None
    }
}

fn session_capability_list(response: SessionOperationResponse) -> Option<Vec<CapabilityToken>> {
    if let SessionOperationResponse::CapabilityList { capabilities } = response {
        Some(capabilities)
    } else {
        None
    }
}

fn session_root_list(response: SessionOperationResponse) -> Option<Vec<RootDefinition>> {
    if let SessionOperationResponse::RootList { roots } = response {
        Some(roots)
    } else {
        None
    }
}

fn session_resource_list(response: SessionOperationResponse) -> Option<Vec<ResourceDefinition>> {
    if let SessionOperationResponse::ResourceList { resources } = response {
        Some(resources)
    } else {
        None
    }
}

fn session_resource_read(response: SessionOperationResponse) -> Option<Vec<ResourceContent>> {
    if let SessionOperationResponse::ResourceRead { contents } = response {
        Some(contents)
    } else {
        None
    }
}

fn session_prompt_list(response: SessionOperationResponse) -> Option<Vec<PromptDefinition>> {
    if let SessionOperationResponse::PromptList { prompts } = response {
        Some(prompts)
    } else {
        None
    }
}

fn session_prompt_get(response: SessionOperationResponse) -> Option<PromptResult> {
    if let SessionOperationResponse::PromptGet { prompt } = response {
        Some(prompt)
    } else {
        None
    }
}

fn session_completion(response: SessionOperationResponse) -> Option<CompletionResult> {
    if let SessionOperationResponse::Completion { completion } = response {
        Some(completion)
    } else {
        None
    }
}

fn tool_call_value_output(output: Option<ToolCallOutput>) -> Option<serde_json::Value> {
    if let Some(ToolCallOutput::Value(value)) = output {
        Some(value)
    } else {
        None
    }
}

fn tool_call_stream_output(output: Option<ToolCallOutput>) -> Option<ToolCallStream> {
    if let Some(ToolCallOutput::Stream(stream)) = output {
        Some(stream)
    } else {
        None
    }
}

fn assert_content_addressed_receipt_id(id: &str) {
    assert_eq!(id.len(), 64, "receipt id should be a SHA-256 hex digest");
    assert!(
        id.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "receipt id should be lowercase hex"
    );
}

fn make_chain_bound_delegation_link(
    capability_id: &str,
    delegator_kp: &Keypair,
    delegatee: &PublicKey,
    authorized_scope: &ChioScope,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator_kp.public_key(),
            delegatee: delegatee.clone(),
            attenuations: vec![],
            timestamp,
            scope_hash: Some(scope_hash(authorized_scope).unwrap()),
        },
        delegator_kp,
    )
    .unwrap()
}

fn make_chain_bound_capability(
    kernel: &ChioKernel,
    id: &str,
    subject: PublicKey,
    scope: ChioScope,
    delegation_chain: Vec<DelegationLink>,
    proof_parent_scope: &ChioScope,
    budget_share_bps: Option<u16>,
) -> CapabilityToken {
    let proof = AttenuationProof {
        parent_scope_hash: scope_hash(proof_parent_scope).unwrap(),
        child_scope_hash: scope_hash(&scope).unwrap(),
        normalized_subset_proof: compute_attenuation_witness(proof_parent_scope, &scope).unwrap(),
    };
    // Keep the delegated child strictly inside its parent's lifetime. The parent
    // helpers issue a 300s window; capture the clock once and use a shorter child
    // window so a sub-second tick between the parent's and child's timestamp reads
    // cannot make the child outlive the parent, which validate_delegation_admission
    // rejects before the scope checks these tests assert on.
    let issued_at = current_unix_timestamp();
    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.to_string(),
                issuer: kernel.config.keypair.public_key(),
                subject,
                scope,
                issued_at,
                expires_at: issued_at.saturating_add(120),
                delegation_chain,
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps,
        },
        &kernel.config.keypair,
    )
    .unwrap()
}

fn set_capability_trust_root_for_scope(kernel: &ChioKernel, scope: &ChioScope) {
    kernel.set_capability_trust_root(kernel.config.keypair.public_key(), scope_hash(scope).unwrap());
}

struct V2DelegatedChildInput<'a> {
    kernel: &'a ChioKernel,
    parent: &'a CapabilityToken,
    parent_kp: &'a Keypair,
    child_kp: &'a Keypair,
    parent_scope: &'a ChioScope,
    child_scope: ChioScope,
    id: &'a str,
    share_bps: u16,
}

fn make_v2_delegated_child(input: V2DelegatedChildInput<'_>) -> CapabilityToken {
    let parent_scope_hash = scope_hash(input.parent_scope).unwrap();
    let child_scope_hash = scope_hash(&input.child_scope).unwrap();
    let issued_at = current_unix_timestamp();
    let expires_at = issued_at.saturating_add(300).min(input.parent.expires_at);
    let proof = AttenuationProof {
        parent_scope_hash: parent_scope_hash.clone(),
        child_scope_hash,
        normalized_subset_proof: compute_attenuation_witness(
            input.parent_scope,
            &input.child_scope,
        )
        .unwrap(),
    };
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: input.parent.id.clone(),
            delegator: input.parent_kp.public_key(),
            delegatee: input.child_kp.public_key(),
            attenuations: vec![],
            timestamp: current_unix_timestamp(),
            scope_hash: Some(parent_scope_hash),
        },
        input.parent_kp,
    )
    .unwrap();

    CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: input.id.to_string(),
                issuer: input.kernel.config.keypair.public_key(),
                subject: input.child_kp.public_key(),
                scope: input.child_scope,
                issued_at,
                expires_at,
                delegation_chain: vec![link],
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(input.share_bps),
        },
        &input.kernel.config.keypair,
    )
    .unwrap()
}

struct EchoServer {
    id: String,
    tools: Vec<String>,
}

struct SideEffectServer {
    id: String,
    tools: Vec<String>,
    invocations: std::sync::Arc<AtomicU64>,
}

struct IncompleteServer {
    id: String,
}

struct StreamingServer {
    id: String,
    chunks: Vec<serde_json::Value>,
}

struct EventDrainServer {
    id: String,
    events: Vec<ToolServerEvent>,
}

struct FailingEventDrainServer {
    id: String,
}

struct NestedFlowServer {
    id: String,
}

struct MockNestedFlowClient {
    roots: Vec<RootDefinition>,
    sampled_message: CreateMessageResult,
    elicited_content: CreateElicitationResult,
    cancel_parent_on_create_message: bool,
    cancel_child_on_create_message: bool,
    completed_elicitation_ids: Vec<String>,
    resource_updates: Vec<String>,
    resources_list_changed_count: u32,
}

struct DocsResourceProvider;
struct FilesystemResourceProvider;
struct ExamplePromptProvider;
struct StubPaymentAdapter;
struct DecliningPaymentAdapter;
struct PrepaidSettledPaymentAdapter;

impl EchoServer {
    fn new(id: &str, tools: Vec<&str>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
        }
    }
}

impl SideEffectServer {
    fn new(id: &str, tools: Vec<&str>, invocations: std::sync::Arc<AtomicU64>) -> Self {
        Self {
            id: id.to_string(),
            tools: tools.into_iter().map(String::from).collect(),
            invocations,
        }
    }
}

impl EventDrainServer {
    fn new(id: &str, events: Vec<ToolServerEvent>) -> Self {
        Self {
            id: id.to_string(),
            events,
        }
    }
}

impl FailingEventDrainServer {
    fn new(id: &str) -> Self {
        Self { id: id.to_string() }
    }
}

impl PaymentAdapter for StubPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "auth_stub".to_string(),
            settled: false,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "txn_stub".to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "release_stub".to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: "refund_stub".to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "stub" }),
        })
    }
}

impl PaymentAdapter for DecliningPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Err(PaymentError::InsufficientFunds)
    }

    fn capture(
        &self,
        _authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "capture should not run".to_string(),
        ))
    }

    fn release(
        &self,
        _authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError(
            "release should not run".to_string(),
        ))
    }

    fn refund(
        &self,
        _transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Err(PaymentError::RailError("refund should not run".to_string()))
    }
}

impl PaymentAdapter for PrepaidSettledPaymentAdapter {
    fn authorize(
        &self,
        _request: &PaymentAuthorizeRequest,
    ) -> Result<PaymentAuthorization, PaymentError> {
        Ok(PaymentAuthorization {
            authorization_id: "x402_txn_paid".to_string(),
            settled: true,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }

    fn capture(
        &self,
        authorization_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Settled,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }

    fn release(
        &self,
        authorization_id: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: authorization_id.to_string(),
            settlement_status: RailSettlementStatus::Released,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }

    fn refund(
        &self,
        transaction_id: &str,
        _amount_units: u64,
        _currency: &str,
        _reference: &str,
    ) -> Result<PaymentResult, PaymentError> {
        Ok(PaymentResult {
            transaction_id: transaction_id.to_string(),
            settlement_status: RailSettlementStatus::Refunded,
            metadata: serde_json::json!({ "adapter": "x402" }),
        })
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for EchoServer {
    fn server_id(&self) -> &str {
        &self.id
    }
    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }
    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for SideEffectServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        self.tools.clone()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::json!({
            "tool": tool_name,
            "echo": arguments,
        }))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for EventDrainServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolNotRegistered(tool_name.to_string()))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Ok(self.events.clone())
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for FailingEventDrainServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        Vec::new()
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::ToolNotRegistered(tool_name.to_string()))
    }

    async fn drain_events(&self) -> Result<Vec<ToolServerEvent>, KernelError> {
        Err(KernelError::Internal("drain failed".to_string()))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for NestedFlowServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "sample_via_client".to_string(),
            "elicit_via_client".to_string(),
            "roots_via_client".to_string(),
            "notify_resources_via_client".to_string(),
        ]
    }

    async fn invoke(
        &self,
        tool_name: &str,
        _arguments: serde_json::Value,
        nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        let nested_flow_bridge = nested_flow_bridge
            .ok_or_else(|| KernelError::Internal("nested-flow bridge is required".to_string()))?;

        match tool_name {
            "sample_via_client" => {
                let message = nested_flow_bridge.create_message(CreateMessageOperation {
                    messages: vec![SamplingMessage {
                        role: "user".to_string(),
                        content: serde_json::json!({
                            "type": "text",
                            "text": "Summarize the roadmap",
                        }),
                        meta: None,
                    }],
                    model_preferences: None,
                    system_prompt: None,
                    include_context: None,
                    temperature: Some(0.2),
                    max_tokens: 128,
                    stop_sequences: vec![],
                    metadata: None,
                    tools: vec![],
                    tool_choice: None,
                })?;

                Ok(serde_json::json!({
                    "model": message.model,
                    "content": message.content,
                }))
            }
            "elicit_via_client" => {
                let elicitation =
                    nested_flow_bridge.create_elicitation(CreateElicitationOperation::Form {
                        meta: None,
                        message: "Which environment should this run against?".to_string(),
                        requested_schema: serde_json::json!({
                            "type": "object",
                            "properties": {
                                "environment": {
                                    "type": "string",
                                    "enum": ["staging", "production"]
                                }
                            },
                            "required": ["environment"]
                        }),
                    })?;

                Ok(serde_json::json!({
                    "action": elicitation.action,
                    "content": elicitation.content,
                }))
            }
            "roots_via_client" => {
                let roots = nested_flow_bridge.list_roots()?;
                Ok(serde_json::json!({
                    "roots": roots,
                }))
            }
            "notify_resources_via_client" => {
                nested_flow_bridge.notify_resource_updated("repo://docs/roadmap")?;
                nested_flow_bridge.notify_resource_updated("repo://secret/ops")?;
                nested_flow_bridge.notify_resources_list_changed()?;
                Ok(serde_json::json!({
                    "notified": true,
                }))
            }
            _ => Err(KernelError::ToolNotRegistered(tool_name.to_string())),
        }
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for IncompleteServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["drop_stream".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::RequestIncomplete(
            "upstream stream closed before tool response completed".to_string(),
        ))
    }
}

#[async_trait::async_trait]
impl ToolServerConnection for StreamingServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["stream_file".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"unused": true}))
    }

    async fn invoke_stream(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<Option<ToolServerStreamResult>, KernelError> {
        Ok(Some(ToolServerStreamResult::Complete(ToolCallStream {
            chunks: self
                .chunks
                .iter()
                .cloned()
                .map(|data| ToolCallChunk { data })
                .collect(),
        })))
    }
}

impl NestedFlowClient for MockNestedFlowClient {
    fn list_roots(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
    ) -> Result<Vec<RootDefinition>, KernelError> {
        Ok(self.roots.clone())
    }

    fn create_message(
        &mut self,
        parent_context: &OperationContext,
        child_context: &OperationContext,
        _operation: &CreateMessageOperation,
    ) -> Result<CreateMessageResult, KernelError> {
        if self.cancel_parent_on_create_message {
            return Err(KernelError::RequestCancelled {
                request_id: parent_context.request_id.clone(),
                reason: "client cancelled parent request".to_string(),
            });
        }

        if self.cancel_child_on_create_message {
            return Err(KernelError::RequestCancelled {
                request_id: child_context.request_id.clone(),
                reason: "client cancelled nested request".to_string(),
            });
        }

        Ok(self.sampled_message.clone())
    }

    fn create_elicitation(
        &mut self,
        _parent_context: &OperationContext,
        _child_context: &OperationContext,
        _operation: &CreateElicitationOperation,
    ) -> Result<CreateElicitationResult, KernelError> {
        Ok(self.elicited_content.clone())
    }

    fn notify_elicitation_completed(
        &mut self,
        _parent_context: &OperationContext,
        elicitation_id: &str,
    ) -> Result<(), KernelError> {
        self.completed_elicitation_ids
            .push(elicitation_id.to_string());
        Ok(())
    }

    fn notify_resource_updated(
        &mut self,
        _parent_context: &OperationContext,
        uri: &str,
    ) -> Result<(), KernelError> {
        self.resource_updates.push(uri.to_string());
        Ok(())
    }

    fn notify_resources_list_changed(
        &mut self,
        _parent_context: &OperationContext,
    ) -> Result<(), KernelError> {
        self.resources_list_changed_count += 1;
        Ok(())
    }
}

impl ResourceProvider for DocsResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "repo://docs/roadmap".to_string(),
                name: "Roadmap".to_string(),
                title: Some("Roadmap".to_string()),
                description: Some("Project roadmap".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(128),
                annotations: None,
                icons: None,
            },
            ResourceDefinition {
                uri: "repo://secret/ops".to_string(),
                name: "Ops".to_string(),
                title: None,
                description: Some("Hidden".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: None,
                annotations: None,
                icons: None,
            },
        ]
    }

    fn list_resource_templates(&self) -> Vec<ResourceTemplateDefinition> {
        vec![ResourceTemplateDefinition {
            uri_template: "repo://docs/{slug}".to_string(),
            name: "Doc Template".to_string(),
            title: None,
            description: Some("Template".to_string()),
            mime_type: Some("text/markdown".to_string()),
            annotations: None,
            icons: None,
        }]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "repo://docs/roadmap" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Roadmap".to_string()),
                blob: None,
                annotations: None,
            }])),
            _ => Ok(None),
        }
    }

    fn complete_resource_argument(
        &self,
        uri: &str,
        argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        if uri == "repo://docs/{slug}" && argument_name == "slug" {
            let values = ["roadmap", "architecture", "api"]
                .into_iter()
                .filter(|candidate| candidate.starts_with(value))
                .map(str::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(CompletionResult {
                total: Some(values.len() as u32),
                has_more: false,
                values,
            }));
        }

        Ok(None)
    }
}

#[derive(Default)]
struct AppendOnlyReceiptStore;

impl ReceiptStore for AppendOnlyReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

/// A receipt store whose supervised commit writer has died. Appends would still
/// nominally succeed, but the writer flag reports serving-closed, so the kernel
/// pre-dispatch gate must fail closed before any tool executes.
struct DeadWriterReceiptStore;

impl ReceiptStore for DeadWriterReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }
}

/// A receipt store whose supervised commit writer is serving-closed AND whose
/// appends now fail, modelling a real poisoned-head or dead-writer store rather
/// than one that still silently accepts writes. The pre-dispatch gate must deny
/// before any tool executes, and the fail-closed deny it builds must not be
/// masked into an error by attempting to persist itself through the same closed
/// writer.
struct RejectingDeadWriterReceiptStore;

impl ReceiptStore for RejectingDeadWriterReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "receipt append rejected by a serving-closed commit writer".to_string(),
        ))
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Pool(
            "child receipt append rejected by a serving-closed commit writer".to_string(),
        ))
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }
}

/// A commit writer that is always serving closed and, once armed, fails every
/// capability-lineage write like a poisoned writer. It records whether the
/// lineage write was attempted so a test can prove the pre-dispatch gate denies
/// BEFORE any writer-backed metadata write runs. Arming is deferred so capability
/// issuance during test setup (which also records lineage) still succeeds.
struct SnapshotTrackingDeadWriterStore {
    snapshot_attempted: std::sync::Arc<AtomicBool>,
    fail_snapshots: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for SnapshotTrackingDeadWriterStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn writer_serving_closed(&self) -> bool {
        true
    }

    fn record_capability_snapshot(
        &self,
        _token: &CapabilityToken,
        _parent_capability_id: Option<&str>,
    ) -> Result<(), ReceiptStoreError> {
        if self.fail_snapshots.load(Ordering::SeqCst) {
            self.snapshot_attempted.store(true, Ordering::SeqCst);
            return Err(ReceiptStoreError::Pool(
                "capability lineage write rejected by a dead receipt writer".to_string(),
            ));
        }
        Ok(())
    }
}

/// A store-authoritative point-lookup store: appended chio receipts are retained
/// in-memory and `load_chio_receipt` resolves them by id. Models a durable store
/// that implements point loads, so an evicted parent receipt still resolves from
/// the store after the bounded mirror drops it.
#[derive(Default)]
struct PointLookupReceiptStore {
    chio: std::sync::Mutex<std::collections::HashMap<String, ChioReceipt>>,
}

impl ReceiptStore for PointLookupReceiptStore {
    fn append_chio_receipt(&self, receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        if let Ok(mut map) = self.chio.lock() {
            map.insert(receipt.id.clone(), receipt.clone());
        }
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Ok(self
            .chio
            .lock()
            .ok()
            .and_then(|map| map.get(receipt_id).cloned()))
    }
}

/// A store that appends fine (so the local mirror is populated) but fails every
/// point load with a read-boundary error, exercising the fail-closed
/// error-propagation path.
#[derive(Default)]
struct ErroringReceiptStore;

impl ReceiptStore for ErroringReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_chio_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChioReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::ReadBoundary(
            "simulated receipt store read failure".to_string(),
        ))
    }

    fn load_child_receipt(
        &self,
        _receipt_id: &str,
    ) -> Result<Option<ChildRequestReceipt>, ReceiptStoreError> {
        Err(ReceiptStoreError::ReadBoundary(
            "simulated child receipt store read failure".to_string(),
        ))
    }
}

#[derive(Default)]
struct FailingCheckpointHydrationReceiptStore;

impl ReceiptStore for FailingCheckpointHydrationReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn load_latest_checkpoint(&self) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "checkpoint chain corrupted".to_string(),
        ))
    }
}

#[derive(Default)]
struct FailingSessionAnchorReceiptStore;

impl ReceiptStore for FailingSessionAnchorReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        _anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        _supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "session anchor write failed".to_string(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedSessionAnchor {
    anchor_id: String,
    supersedes_anchor_id: Option<String>,
}

#[derive(Default)]
struct RecordingSessionAnchorReceiptStore {
    anchors: std::sync::Arc<Mutex<Vec<RecordedSessionAnchor>>>,
}

impl ReceiptStore for RecordingSessionAnchorReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn record_session_anchor(
        &self,
        _session_id: &str,
        anchor_id: &str,
        _auth_context_fingerprint: &str,
        _issued_at: u64,
        supersedes_anchor_id: Option<&str>,
        _anchor_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        self.anchors
            .lock()
            .map_err(|_| ReceiptStoreError::Conflict("anchor recorder lock poisoned".to_string()))?
            .push(RecordedSessionAnchor {
                anchor_id: anchor_id.to_string(),
                supersedes_anchor_id: supersedes_anchor_id.map(str::to_string),
            });
        Ok(())
    }
}

#[derive(Default)]
struct FailingRequestLineageReceiptStore;

impl ReceiptStore for FailingRequestLineageReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn record_request_lineage(
        &self,
        _session_id: &str,
        _request_id: &str,
        _parent_request_id: Option<&str>,
        _session_anchor_id: Option<&str>,
        _recorded_at: u64,
        _request_fingerprint: Option<&str>,
        _lineage_json: &serde_json::Value,
    ) -> Result<(), ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "request lineage write failed".to_string(),
        ))
    }
}

impl ResourceProvider for FilesystemResourceProvider {
    fn list_resources(&self) -> Vec<ResourceDefinition> {
        vec![
            ResourceDefinition {
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
                name: "Filesystem Roadmap".to_string(),
                title: Some("Filesystem Roadmap".to_string()),
                description: Some("In-root file-backed resource".to_string()),
                mime_type: Some("text/markdown".to_string()),
                size: Some(64),
                annotations: None,
                icons: None,
            },
            ResourceDefinition {
                uri: "file:///workspace/private/ops.md".to_string(),
                name: "Filesystem Ops".to_string(),
                title: None,
                description: Some("Out-of-root file-backed resource".to_string()),
                mime_type: Some("text/plain".to_string()),
                size: Some(32),
                annotations: None,
                icons: None,
            },
        ]
    }

    fn read_resource(&self, uri: &str) -> Result<Option<Vec<ResourceContent>>, KernelError> {
        match uri {
            "file:///workspace/project/docs/roadmap.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/markdown".to_string()),
                text: Some("# Filesystem Roadmap".to_string()),
                blob: None,
                annotations: None,
            }])),
            "file:///workspace/private/ops.md" => Ok(Some(vec![ResourceContent {
                uri: uri.to_string(),
                mime_type: Some("text/plain".to_string()),
                text: Some("ops".to_string()),
                blob: None,
                annotations: None,
            }])),
            _ => Ok(None),
        }
    }
}

impl PromptProvider for ExamplePromptProvider {
    fn list_prompts(&self) -> Vec<PromptDefinition> {
        vec![
            PromptDefinition {
                name: "summarize_docs".to_string(),
                title: Some("Summarize Docs".to_string()),
                description: Some("Summarize documentation".to_string()),
                arguments: vec![PromptArgument {
                    name: "topic".to_string(),
                    title: None,
                    description: Some("Topic to summarize".to_string()),
                    required: Some(true),
                }],
                icons: None,
            },
            PromptDefinition {
                name: "ops_secret".to_string(),
                title: None,
                description: Some("Hidden".to_string()),
                arguments: vec![],
                icons: None,
            },
        ]
    }

    fn get_prompt(
        &self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<Option<PromptResult>, KernelError> {
        match name {
            "summarize_docs" => Ok(Some(PromptResult {
                description: Some("Summarize docs".to_string()),
                messages: vec![PromptMessage {
                    role: "user".to_string(),
                    content: serde_json::json!({
                        "type": "text",
                        "text": format!(
                            "Summarize {}",
                            arguments["topic"].as_str().unwrap_or("the docs")
                        ),
                    }),
                }],
            })),
            _ => Ok(None),
        }
    }

    fn complete_prompt_argument(
        &self,
        name: &str,
        argument_name: &str,
        value: &str,
        _context: &serde_json::Value,
    ) -> Result<Option<CompletionResult>, KernelError> {
        if name == "summarize_docs" && argument_name == "topic" {
            let values = ["roadmap", "architecture", "release-plan"]
                .into_iter()
                .filter(|candidate| candidate.starts_with(value))
                .map(str::to_string)
                .collect::<Vec<_>>();
            return Ok(Some(CompletionResult {
                total: Some(values.len() as u32),
                has_more: false,
                values,
            }));
        }

        Ok(None)
    }
}
