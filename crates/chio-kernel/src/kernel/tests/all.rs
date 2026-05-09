use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};
use std::thread;

use chio_core::capability::{
    compute_attenuation_witness, scope_hash, AttenuationProof, CallChainContinuationAudience,
    CallChainContinuationToken, CallChainContinuationTokenBody, CapabilityToken,
    CapabilityTokenBody, CapabilityTokenV2Body, ChioScope, Constraint, DelegationLink,
    DelegationLinkBody, GovernedApprovalDecision, GovernedApprovalToken,
    GovernedApprovalTokenBody, GovernedAutonomyContext, GovernedAutonomyTier,
    GovernedCallChainContext, GovernedTransactionIntent, GovernedUpstreamCallChainProof,
    GovernedUpstreamCallChainProofBody, MonetaryAmount, Operation, PromptGrant, ResourceGrant,
    ToolGrant, GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY,
    GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY,
};
use chio_core::credit::{
    CreditBondArtifact, CreditBondDisposition, CreditBondLifecycleState, CreditBondPrerequisites,
    CreditBondReport, CreditBondSupportBoundary, CreditScorecardBand, CreditScorecardConfidence,
    CreditScorecardSummary, ExposureLedgerQuery, ExposureLedgerSummary, SignedCreditBond,
    CREDIT_BOND_ARTIFACT_SCHEMA, CREDIT_BOND_REPORT_SCHEMA,
};
use chio_core::crypto::{Keypair, PublicKey};
use chio_core::receipt::{
    ChioReceipt, ChioReceiptBody, ChioReceiptV2, Decision, ToolCallAction,
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
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, ReceiptStoreError> {
        self.connection.lock().map_err(|_| {
            ReceiptStoreError::Conflict("sqlite receipt store lock poisoned".to_string())
        })
    }

    fn load_checkpoint_by_seq(
        &self,
        checkpoint_seq: u64,
    ) -> Result<Option<KernelCheckpoint>, ReceiptStoreError> {
        self.connection()?
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
        Ok((rows > 0).then(|| connection.last_insert_rowid().max(0) as u64))
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
        let raw_json = serde_json::to_string(checkpoint)?;
        self.connection()?.execute(
            r#"
                INSERT INTO kernel_checkpoints (checkpoint_seq, raw_json)
                VALUES (?1, ?2)
                ON CONFLICT(checkpoint_seq) DO UPDATE SET raw_json = excluded.raw_json
                "#,
            params![checkpoint.body.checkpoint_seq as i64, raw_json],
        )?;
        Ok(())
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
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    }
}

fn make_signed_receipt(kp: &Keypair, id: &str) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_100,
            capability_id: "cap-receipt-v2".to_string(),
            tool_server: "srv".to_string(),
            tool_name: "echo".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"message": "hello"}))
                .expect("tool action"),
            decision: Decision::Allow,
            content_hash: "0".repeat(64),
            policy_hash: "1".repeat(64),
            evidence: Vec::new(),
            metadata: None,
            trust_level: chio_core::receipt::TrustLevel::default(),
            tenant_id: None,
            kernel_key: kp.public_key(),
        },
        kp,
    )
    .expect("sign receipt")
}

#[test]
fn kernel_rejects_classical_capability_under_pq_required_floor() {
    let keypair = make_keypair();
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-classical-floor".to_string(),
            issuer: keypair.public_key(),
            subject: keypair.public_key(),
            scope: ChioScope::default(),
            issued_at: 100,
            expires_at: 200,
            delegation_chain: Vec::new(),
        },
        &keypair,
    )
    .expect("sign classical capability");
    let mut config = make_config();
    config.keypair = keypair;
    let mut kernel = ChioKernel::new(config);
    kernel.set_capability_crypto_floor(KernelCryptoFloor::PqRequired);

    let error = kernel
        .verify_capability_full_pre_admit(&token, None, 150)
        .expect_err("classical capability must fail under pq_required");

    assert!(
        error.contains("crypto_floor=pq_required"),
        "expected crypto floor rejection, got {error}"
    );
}

#[test]
fn production_evaluate_rejects_direct_v2_without_trust_root_resolver() {
    let issuer = make_keypair();
    let subject = make_keypair();
    let mut config = make_config();
    config.ca_public_keys = vec![issuer.public_key()];
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let capability = make_direct_v2_capability(
        &issuer,
        &subject.public_key(),
        make_scope(vec![make_grant("srv-a", "read_file")]),
    );
    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-direct-v2",
            &capability,
            "read_file",
            "srv-a",
        ))
        .expect("v2 rejection should produce a deny receipt");

    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("v2 chain-binding requires a trust-root resolver"),
        "expected v2 chain-binding deny, got: {reason}"
    );
}

#[test]
fn receipt_v2_replay_set_rolls_back_when_persistence_fails() {
    let keypair = make_keypair();
    let mut config = make_config();
    config.keypair = keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(FailingV2ReceiptStore));
    let receipt = make_signed_receipt(&keypair, "rcpt-v2-rollback");
    let v2 = kernel
        .mint_chio_receipt_v2_from_v1_for_test(&receipt)
        .expect("mint v2 receipt");

    let err = kernel
        .record_chio_receipt_v2(&v2, Some(receipt.id.as_str()))
        .expect_err("v2 persistence failure must surface");
    assert!(
        format!("{err}").contains("v2 receipt persistence failed"),
        "unexpected error: {err}"
    );
    assert!(
        !kernel.contains_chio_receipt_v2_body_hash(&v2.body_hash),
        "failed persistence must not poison the in-memory replay set"
    );
}

#[test]
fn receipt_v2_zero_seq_replay_conflict_rolls_back() {
    let keypair = make_keypair();
    let mut config = make_config();
    config.keypair = keypair.clone();
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(ZeroSeqV2ReceiptStore));
    let receipt = make_signed_receipt(&keypair, "rcpt-v2-zero-seq");
    let v2 = kernel
        .mint_chio_receipt_v2_from_v1_for_test(&receipt)
        .expect("mint v2 receipt");

    let err = kernel
        .record_chio_receipt_v2(&v2, Some(receipt.id.as_str()))
        .expect_err("zero seq means durable replay conflict");
    assert!(
        format!("{err}").contains("already exists"),
        "unexpected error: {err}"
    );
    assert!(
        !kernel.contains_chio_receipt_v2_body_hash(&v2.body_hash),
        "durable replay conflict must not poison the in-memory replay set"
    );
}

#[test]
fn receipt_v2_failure_prevents_v1_persistence() {
    let keypair = make_keypair();
    let mut config = make_config();
    config.keypair = keypair.clone();
    let mut kernel = ChioKernel::new(config);
    let v1_called = std::sync::Arc::new(AtomicBool::new(false));
    kernel.set_receipt_store(Box::new(V2FailsBeforeV1Store {
        v1_called: std::sync::Arc::clone(&v1_called),
    }));
    let subject = Keypair::generate();
    let capability = make_capability(&kernel, &subject, ChioScope::default(), 60);
    let request = make_request("req-v2-before-v1", &capability, "echo", "srv");
    let receipt = make_signed_receipt(&keypair, "rcpt-v2-before-v1");

    let err = kernel
        .record_chio_receipt_with_federation(&request, &receipt)
        .expect_err("v2 persistence failure must abort before v1 append");

    assert!(
        format!("{err}").contains("v2 receipt persistence failed"),
        "unexpected error: {err}"
    );
    assert!(
        !v1_called.load(Ordering::SeqCst),
        "v1 receipt append must not happen after v2 persistence fails"
    );
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

fn make_direct_v2_capability(
    issuer: &Keypair,
    subject: &PublicKey,
    scope: ChioScope,
) -> CapabilityToken {
    let now = current_unix_timestamp();
    let parent_hash = scope_hash(&scope).expect("hash parent scope");
    let child_hash = scope_hash(&scope).expect("hash child scope");
    let witness = compute_attenuation_witness(&scope, &scope).expect("compute attenuation witness");
    CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body: CapabilityTokenBody {
                id: "cap-direct-v2".to_string(),
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
    .expect("sign v2 capability")
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

fn make_delegation_link(
    capability_id: &str,
    delegator_kp: &Keypair,
    delegatee_kp: &Keypair,
    timestamp: u64,
) -> DelegationLink {
    DelegationLink::sign(
        DelegationLinkBody {
            capability_id: capability_id.to_string(),
            delegator: delegator_kp.public_key(),
            delegatee: delegatee_kp.public_key(),
            attenuations: vec![],
            timestamp,
            scope_hash: None,
        },
        delegator_kp,
    )
    .unwrap()
}

fn make_v2_delegated_child(
    kernel: &ChioKernel,
    parent: &CapabilityToken,
    parent_kp: &Keypair,
    child_kp: &Keypair,
    parent_scope: &ChioScope,
    child_scope: ChioScope,
    id: &str,
    share_bps: u16,
) -> CapabilityToken {
    let parent_scope_hash = scope_hash(parent_scope).unwrap();
    let child_scope_hash = scope_hash(&child_scope).unwrap();
    let proof = AttenuationProof {
        parent_scope_hash: parent_scope_hash.clone(),
        child_scope_hash,
        normalized_subset_proof: compute_attenuation_witness(parent_scope, &child_scope).unwrap(),
    };
    let link = DelegationLink::sign(
        DelegationLinkBody {
            capability_id: parent.id.clone(),
            delegator: parent_kp.public_key(),
            delegatee: child_kp.public_key(),
            attenuations: vec![],
            timestamp: current_unix_timestamp(),
            scope_hash: Some(parent_scope_hash),
        },
        parent_kp,
    )
    .unwrap();

    CapabilityToken::sign_v2(
        CapabilityTokenV2Body {
            body: CapabilityTokenBody {
                id: id.to_string(),
                issuer: kernel.config.keypair.public_key(),
                subject: child_kp.public_key(),
                scope: child_scope,
                issued_at: current_unix_timestamp(),
                expires_at: current_unix_timestamp() + 300,
                delegation_chain: vec![link],
            },
            caveats: vec![],
            scope_attenuations: vec![],
            attenuation_proof: proof,
            budget_share_bps: Some(share_bps),
        },
        &kernel.config.keypair,
    )
    .unwrap()
}

struct EchoServer {
    id: String,
    tools: Vec<String>,
}

struct IncompleteServer {
    id: String,
}

struct StreamingServer {
    id: String,
    chunks: Vec<serde_json::Value>,
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

#[async_trait::async_trait(?Send)]
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

#[async_trait::async_trait(?Send)]
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

#[async_trait::async_trait(?Send)]
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

#[async_trait::async_trait(?Send)]
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

#[derive(Default)]
struct FailingV2ReceiptStore;

impl ReceiptStore for FailingV2ReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_chio_receipt_v2(
        &self,
        _receipt: &ChioReceiptV2,
        _legacy_receipt_id_alias: Option<&str>,
    ) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "v2 receipt write failed".to_string(),
        ))
    }
}

#[derive(Default)]
struct ZeroSeqV2ReceiptStore;

impl ReceiptStore for ZeroSeqV2ReceiptStore {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_chio_receipt_v2(
        &self,
        _receipt: &ChioReceiptV2,
        _legacy_receipt_id_alias: Option<&str>,
    ) -> Result<u64, ReceiptStoreError> {
        Ok(0)
    }
}

struct V2FailsBeforeV1Store {
    v1_called: std::sync::Arc<AtomicBool>,
}

impl ReceiptStore for V2FailsBeforeV1Store {
    fn append_chio_receipt(&self, _receipt: &ChioReceipt) -> Result<(), ReceiptStoreError> {
        self.v1_called.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn append_child_receipt(
        &self,
        _receipt: &ChildRequestReceipt,
    ) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn append_chio_receipt_v2(
        &self,
        _receipt: &ChioReceiptV2,
        _legacy_receipt_id_alias: Option<&str>,
    ) -> Result<u64, ReceiptStoreError> {
        Err(ReceiptStoreError::Conflict(
            "v2 receipt write failed".to_string(),
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

#[test]
fn issue_and_use_capability() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    assert!(matches!(response.output, Some(ToolCallOutput::Value(_))));
    assert!(response.reason.is_none());

    // Receipt was logged.
    assert_eq!(kernel.receipt_log().len(), 1);

    // Receipt signature verifies.
    let receipt_log = kernel.receipt_log();
    let r = receipt_log.get(0).unwrap();
    assert!(r.verify_signature().unwrap());
}

#[test]
fn kernel_persists_tool_receipts_to_sqlite_store() {
    let path = unique_receipt_db_path("chio-kernel-tool-receipts");
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-sqlite-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    drop(kernel);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let (count, distinct_count, receipt_id): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM chio_tool_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let child_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_child_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();

    assert_eq!(count, 1);
    assert_eq!(distinct_count, 1);
    assert_eq!(child_count, 0);
    assert!(receipt_id.starts_with("rcpt-"));

    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn kernel_accepts_capabilities_from_configured_authority() {
    let authority_keypair = make_keypair();
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
        authority_keypair.clone(),
    )));
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-authority-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(cap.issuer, authority_keypair.public_key());
    assert_eq!(response.verdict, Verdict::Allow);
}

#[test]
fn kernel_reports_capability_issuer_trust() {
    let authority_keypair = make_keypair();
    let untrusted_keypair = make_keypair();
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
        authority_keypair.clone(),
    )));

    assert!(kernel.capability_issuer_is_trusted(&authority_keypair.public_key()));
    assert!(kernel.capability_issuer_is_trusted(&kernel.public_key()));
    assert!(!kernel.capability_issuer_is_trusted(&untrusted_keypair.public_key()));
}

#[test]
fn expired_capability_denied() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    // TTL=0 means it expires at the same second it was issued.
    let cap = make_capability(&kernel, &agent_kp, scope, 0);
    let request = make_request("req-1", &cap, "read_file", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("expired"), "reason was: {reason}");

    // Denial also produces a receipt.
    assert_eq!(kernel.receipt_log().len(), 1);
    assert!(kernel.receipt_log().get(0).unwrap().is_denied());
}

#[test]
fn revoked_capability_denied() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    kernel.revoke_capability(&cap.id).unwrap();

    let request = make_request("req-1", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("revoked"), "reason was: {reason}");
}

#[test]
fn sqlite_revocation_store_survives_kernel_restart() {
    let path = unique_receipt_db_path("chio-kernel-revocations");
    let authority_keypair = make_keypair();
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);

    let cap = {
        let mut kernel = ChioKernel::new(make_config());
        kernel.set_capability_authority(Box::new(LocalCapabilityAuthority::new(
            authority_keypair.clone(),
        )));
        kernel.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
        kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

        let cap = make_capability(&kernel, &agent_kp, scope.clone(), 300);
        kernel.revoke_capability(&cap.id).unwrap();
        cap
    };

    let mut restarted = ChioKernel::new(make_config());
    restarted.set_capability_authority(Box::new(LocalCapabilityAuthority::new(authority_keypair)));
    restarted.set_revocation_store(Box::new(SqliteRevocationStore::open(&path).unwrap()));
    restarted.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let request = make_request("req-revoked-after-restart", &cap, "read_file", "srv-a");
    let response = restarted.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.reason.as_deref().unwrap_or("").contains("revoked"),
        "reason was: {:?}",
        response.reason
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn out_of_scope_tool_denied() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file"],
    )));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Request write_file, but capability only grants read_file.
    let request = make_request("req-1", &cap, "write_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("not in capability scope"),
        "reason was: {reason}"
    );
}

#[test]
fn subject_mismatch_denied() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let mut request = make_request("req-1", &cap, "read_file", "srv-a");
    request.agent_id = make_keypair().public_key().to_hex();

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("does not match capability subject"));
}

#[test]
fn path_prefix_constraint_is_enforced() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::PathPrefix("/app/src".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let allowed = make_request_with_arguments(
        "req-allow",
        &cap,
        "read_file",
        "srv-a",
        serde_json::json!({"path": "/app/src/lib.rs"}),
    );
    let denied = make_request_with_arguments(
        "req-deny",
        &cap,
        "read_file",
        "srv-a",
        serde_json::json!({"path": "/etc/passwd"}),
    );

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&allowed)
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    let denied_response = kernel.evaluate_tool_call_blocking(&denied).unwrap();
    assert_eq!(denied_response.verdict, Verdict::Deny);
    assert!(denied_response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("not in capability scope"));
}

#[test]
fn domain_exact_constraint_is_enforced() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["fetch"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "fetch".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![Constraint::DomainExact("api.example.com".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let allowed = make_request_with_arguments(
        "req-allow",
        &cap,
        "fetch",
        "srv-a",
        serde_json::json!({"url": "https://api.example.com/v1/data"}),
    );
    let denied = make_request_with_arguments(
        "req-deny",
        &cap,
        "fetch",
        "srv-a",
        serde_json::json!({"url": "https://evil.example.com/v1/data"}),
    );

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&allowed)
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        kernel.evaluate_tool_call_blocking(&denied).unwrap().verdict,
        Verdict::Deny
    );
}

#[test]
fn budget_exhaustion() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: Some(2),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // First two calls succeed.
    for i in 0..2 {
        let req = make_request(&format!("req-{i}"), &cap, "read_file", "srv-a");
        let resp = kernel.evaluate_tool_call_blocking(&req).unwrap();
        assert_eq!(resp.verdict, Verdict::Allow, "call {i} should succeed");
    }

    // Third call is denied.
    let req = make_request("req-2", &cap, "read_file", "srv-a");
    let resp = kernel.evaluate_tool_call_blocking(&req).unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);
    let reason = resp.reason.as_deref().unwrap_or("");
    assert!(reason.contains("budget"), "reason was: {reason}");
}

#[test]
fn budgets_are_tracked_per_matching_grant() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new(
        "srv-a",
        vec!["read_file", "write_file"],
    )));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        grants: vec![
            ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "read_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(2),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            },
            ToolGrant {
                server_id: "srv-a".to_string(),
                tool_name: "write_file".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: Some(1),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            },
        ],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&make_request("read-1", &cap, "read_file", "srv-a"))
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&make_request("read-2", &cap, "read_file", "srv-a"))
            .unwrap()
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        kernel
            .evaluate_tool_call_blocking(&make_request("write-1", &cap, "write_file", "srv-a"))
            .unwrap()
            .verdict,
        Verdict::Allow
    );

    let denied = kernel
        .evaluate_tool_call_blocking(&make_request("write-2", &cap, "write_file", "srv-a"))
        .unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.reason.as_deref().unwrap_or("").contains("budget"));
}

#[test]
fn guard_denies_request() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["dangerous"])));

    struct DenyAll;
    impl Guard for DenyAll {
        fn name(&self) -> &str {
            "deny-all"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            Ok(Verdict::Deny)
        }
    }
    kernel.add_guard(Box::new(DenyAll));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "dangerous")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "dangerous", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("deny-all"), "reason was: {reason}");
}

#[test]
fn guard_error_treated_as_deny() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["tool"])));

    struct BrokenGuard;
    impl Guard for BrokenGuard {
        fn name(&self) -> &str {
            "broken"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            Err(KernelError::Internal("guard crashed".to_string()))
        }
    }
    kernel.add_guard(Box::new(BrokenGuard));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "tool")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "tool", "srv-a");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("fail-closed"), "reason was: {reason}");
}

#[test]
fn unregistered_server_denied() {
    let kernel = ChioKernel::new(make_config());
    // No tool servers registered.

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-missing", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);
    let request = make_request("req-1", &cap, "read_file", "srv-missing");

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(reason.contains("not registered"), "reason was: {reason}");
}

#[test]
fn untrusted_issuer_denied() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let rogue_kp = make_keypair();
    let agent_kp = make_keypair();

    // Sign a capability with the rogue key (not trusted by this kernel).
    let body = CapabilityTokenBody {
        id: "cap-rogue".to_string(),
        issuer: rogue_kp.public_key(),
        subject: agent_kp.public_key(),
        scope: make_scope(vec![make_grant("srv-a", "read_file")]),
        issued_at: current_unix_timestamp(),
        expires_at: current_unix_timestamp() + 300,
        delegation_chain: vec![],
    };
    let cap = CapabilityToken::sign(body, &rogue_kp).unwrap();

    let request = ToolCallRequest {
        request_id: "req-rogue".to_string(),
        capability: cap,
        tool_name: "read_file".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("not found among trusted"),
        "reason was: {reason}"
    );
}

#[test]
fn all_calls_produce_verified_receipts() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Allowed call.
    let req = make_request("req-1", &cap, "read_file", "srv-a");
    let _ = kernel.evaluate_tool_call_blocking(&req).unwrap();

    // Denied call (wrong tool).
    let req2 = make_request("req-2", &cap, "write_file", "srv-a");
    let _ = kernel.evaluate_tool_call_blocking(&req2).unwrap();

    assert_eq!(kernel.receipt_log().len(), 2);

    for r in kernel.receipt_log().receipts() {
        assert!(r.verify_signature().unwrap());
    }
}

#[test]
fn wildcard_server_grant_allows_real_server() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("filesystem", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("*", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request("req-1", &cap, "read_file", "filesystem");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
}

#[test]
fn revoked_ancestor_capability_denies_descendant() {
    let path = unique_receipt_db_path("chio-kernel-revoked-ancestor-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let link = make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-child".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![link],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    kernel.revoke_capability(&parent.id).unwrap();

    let request = make_request("req-1", &child, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains(&parent.id));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_records_observed_capability_lineage() {
    let path = unique_receipt_db_path("chio-kernel-observed-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope, 300);
    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);

    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let link = make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-observed-child".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![link],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("req-observed", &child, "read_file", "srv-a"))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);

    let reopened = SqliteReceiptStore::open(&path).unwrap();
    let chain = reopened.get_delegation_chain(&child.id).unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].capability_id, parent.id);
    assert_eq!(chain[0].delegation_depth, 0);
    assert_eq!(chain[1].capability_id, child.id);
    assert_eq!(
        chain[1].parent_capability_id.as_deref(),
        Some(parent.id.as_str())
    );
    assert_eq!(chain[1].delegation_depth, 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_without_parent_snapshot_denies() {
    let path = unique_receipt_db_path("chio-kernel-missing-parent-lineage");
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-missing-parent".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![link],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-missing-parent",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("missing capability snapshot"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_without_delegate_operation_denies() {
    let path = unique_receipt_db_path("chio-kernel-missing-delegate-op");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let parent_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope, 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-missing-delegate".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![link],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-missing-delegate",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("does not authorize delegated tool grant"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_with_scope_escalation_denies() {
    let path = unique_receipt_db_path("chio-kernel-scope-escalation");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let parent_scope = ChioScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "read_file".to_string(),
            operations: vec![Operation::Invoke, Operation::Delegate],
            constraints: vec![Constraint::PathPrefix("/workspace/safe".to_string())],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        ..ChioScope::default()
    };
    let parent = make_capability(&kernel, &parent_kp, parent_scope, 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-escalated-child".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![link],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-escalated-child",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("does not authorize delegated tool grant"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_with_delegatee_subject_mismatch_denies() {
    let path = unique_receipt_db_path("chio-kernel-delegatee-mismatch");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let parent_kp = make_keypair();
    let child_kp = make_keypair();
    let other_child_kp = make_keypair();
    let mut parent_grant = make_grant("srv-a", "read_file");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let link = make_delegation_link(
        &parent.id,
        &parent_kp,
        &other_child_kp,
        current_unix_timestamp(),
    );
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-delegatee-mismatch".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![link],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-delegatee-mismatch",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("delegatee"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_exceeding_configured_max_depth_denies() {
    let path = unique_receipt_db_path("chio-kernel-max-delegation-depth");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut config = make_config();
    config.max_delegation_depth = 1;
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let root_kp = make_keypair();
    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let mut delegable_grant = make_grant("srv-a", "read_file");
    delegable_grant.operations.push(Operation::Delegate);
    let delegable_scope = make_scope(vec![delegable_grant.clone()]);
    let root = make_capability(&kernel, &root_kp, delegable_scope.clone(), 300);
    seed_store.record_capability_snapshot(&root, None).unwrap();

    let root_to_parent =
        make_delegation_link(&root.id, &root_kp, &parent_kp, current_unix_timestamp());
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-max-depth-parent".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: parent_kp.public_key(),
            scope: delegable_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![root_to_parent.clone()],
        },
        &kernel.config.keypair,
    )
    .unwrap();
    seed_store
        .record_capability_snapshot(&parent, Some(root.id.as_str()))
        .unwrap();
    drop(seed_store);

    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent_to_child =
        make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-max-depth-child".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![root_to_parent, parent_to_child],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request("req-max-depth", &child, "read_file", "srv-a"))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("delegation depth 2 exceeds maximum 1"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn delegated_tool_call_with_truncated_ancestor_chain_denies() {
    let path = unique_receipt_db_path("chio-kernel-truncated-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();

    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let root_kp = make_keypair();
    let parent_kp = make_keypair();
    let child_kp = make_keypair();

    let mut delegable_grant = make_grant("srv-a", "read_file");
    delegable_grant.operations.push(Operation::Delegate);
    let delegable_scope = make_scope(vec![delegable_grant.clone()]);
    let root = make_capability(&kernel, &root_kp, delegable_scope.clone(), 300);
    seed_store.record_capability_snapshot(&root, None).unwrap();

    let root_to_parent =
        make_delegation_link(&root.id, &root_kp, &parent_kp, current_unix_timestamp());
    let parent = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-truncated-parent".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: parent_kp.public_key(),
            scope: delegable_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![root_to_parent],
        },
        &kernel.config.keypair,
    )
    .unwrap();
    seed_store
        .record_capability_snapshot(&parent, Some(root.id.as_str()))
        .unwrap();
    drop(seed_store);

    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let child_scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let parent_to_child =
        make_delegation_link(&parent.id, &parent_kp, &child_kp, current_unix_timestamp());
    let child = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-truncated-child".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: child_scope,
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![parent_to_child],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&make_request(
            "req-truncated-lineage",
            &child,
            "read_file",
            "srv-a",
        ))
        .unwrap();
    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("stored depth"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn wildcard_tool_grant_allows_any_tool() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["anything"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "*")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request("req-1", &cap, "anything", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
}

#[test]
fn in_memory_revocation_store() {
    let store = InMemoryRevocationStore::default();
    assert!(!store.is_revoked("cap-1").unwrap());
    assert!(store.revoke("cap-1").unwrap());
    assert!(store.is_revoked("cap-1").unwrap());
    assert!(!store.revoke("cap-1").unwrap());
}

#[test]
fn receipt_log_basics() {
    let log = ReceiptLog::new();
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
}

#[test]
fn kernel_guard_registration() {
    let mut kernel = ChioKernel::new(make_config());
    assert_eq!(kernel.guard_count(), 0);
    assert_eq!(kernel.ca_count(), 0);

    struct TestGuard;
    impl Guard for TestGuard {
        fn name(&self) -> &str {
            "test-guard"
        }
        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            Ok(Verdict::Allow)
        }
    }

    kernel.add_guard(Box::new(TestGuard));
    assert_eq!(kernel.guard_count(), 1);
}

#[test]
fn session_lifecycle_is_hosted_by_kernel() {
    let kernel = ChioKernel::new(make_config());
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

    assert_eq!(kernel.session_count(), 1);
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Initializing)
    );

    kernel.activate_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Ready)
    );

    kernel.begin_draining_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Draining)
    );

    kernel.close_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Closed)
    );
}

#[test]
fn open_session_assigns_unique_ids_across_kernel_instances() {
    let kernel_a = ChioKernel::new(make_config());
    let kernel_b = ChioKernel::new(make_config());

    let session_a = kernel_a.open_session("agent-a".to_string(), Vec::new());
    let session_b = kernel_b.open_session("agent-b".to_string(), Vec::new());

    assert_ne!(session_a, session_b);
}

/// Session ids are minted from the OS CSPRNG: assert structure (sess- prefix,
/// 22 base64url chars, charset) rather than pinning to a literal value.
#[test]
fn open_session_id_has_csprng_structure() {
    let kernel = ChioKernel::new(make_config());
    let session_id = kernel.open_session("agent-a".to_string(), Vec::new());
    let raw = session_id.as_str();

    let suffix = raw
        .strip_prefix("sess-")
        .expect("session id must carry the sess- prefix");
    // 16 bytes encoded as base64url-without-padding => 22 chars.
    assert_eq!(suffix.len(), 22, "unexpected session id suffix length");
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "session id suffix must use the base64url charset",
    );
}

/// Across N=1024 freshly minted ids, none should collide. Sequential ids
/// trivially satisfied this; the property is what keeps the random scheme
/// honest in the face of a regression to a low-entropy generator.
#[test]
fn open_session_ids_do_not_collide_across_many_calls() {
    let kernel = ChioKernel::new(make_config());
    let mut seen = std::collections::HashSet::with_capacity(1024);
    let mut last: Option<SessionId> = None;
    for _ in 0..1024 {
        let id = kernel.open_session("agent-a".to_string(), Vec::new());
        if let Some(previous) = last.as_ref() {
            assert_ne!(
                &id, previous,
                "consecutive session ids must not be equal"
            );
        }
        assert!(seen.insert(id.clone()), "session id collision: {id}");
        last = Some(id);
    }
}

#[test]
fn open_session_with_id_rejects_duplicate_ids() {
    let kernel = ChioKernel::new(make_config());
    let session_id = SessionId::new("sess-restored");

    let opened = kernel
        .open_session_with_id(session_id.clone(), "agent-a".to_string(), Vec::new())
        .unwrap();
    assert_eq!(opened, session_id);

    let error = kernel
        .open_session_with_id(session_id.clone(), "agent-b".to_string(), Vec::new())
        .unwrap_err();
    assert!(matches!(
        error,
        KernelError::SessionAlreadyExists(existing) if existing == session_id
    ));
    assert_eq!(kernel.session_count(), 1);
    assert_eq!(
        kernel
            .session(&session_id)
            .map(|session| session.agent_id().to_string()),
        Some("agent-a".to_string())
    );
}

#[test]
fn open_session_with_id_rolls_back_insert_when_anchor_persistence_fails() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(FailingSessionAnchorReceiptStore));
    let session_id = SessionId::new("sess-anchor-fail");

    let error = kernel
        .open_session_with_id(session_id.clone(), "agent-a".to_string(), Vec::new())
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "session anchor write failed"
    ));
    assert_eq!(kernel.session_count(), 0);
    assert!(kernel.session(&session_id).is_none());

    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore));
    let opened = kernel
        .open_session_with_id(session_id.clone(), "agent-a".to_string(), Vec::new())
        .unwrap();
    assert_eq!(opened, session_id);
    assert_eq!(kernel.session_count(), 1);
}

#[test]
fn set_session_auth_context_rolls_back_when_anchor_persistence_fails() {
    let mut kernel = ChioKernel::new(make_config());
    let session_id =
        kernel.open_session_with_id(SessionId::new("sess-auth-rollback"), "agent-a".to_string(), Vec::new())
            .unwrap();
    let initial_auth = kernel
        .session(&session_id)
        .map(|session| session.auth_context())
        .unwrap();
    let initial_anchor = kernel
        .session(&session_id)
        .map(|session| session.session_anchor())
        .unwrap();

    kernel.set_receipt_store(Box::new(FailingSessionAnchorReceiptStore));
    let error = kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:rollback",
                "cafebabe",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "session anchor write failed"
    ));
    let session = kernel.session(&session_id).unwrap();
    assert_eq!(session.auth_context(), initial_auth);
    assert_eq!(session.session_anchor(), initial_anchor);
}

#[test]
fn close_session_persists_anonymous_anchor_and_rejects_late_auth_rotation() {
    let store = RecordingSessionAnchorReceiptStore::default();
    let anchors = std::sync::Arc::clone(&store.anchors);
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(store));
    let session_id = kernel
        .open_session_with_id(
            SessionId::new("sess-auth-close"),
            "agent-a".to_string(),
            Vec::new(),
        )
        .unwrap();
    kernel.activate_session(&session_id).unwrap();
    let initial_anchor_id = kernel
        .session(&session_id)
        .map(|session| session.session_anchor().id().to_string())
        .unwrap();

    kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:close",
                "deadbeef",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap();
    let authenticated_anchor_id = kernel
        .session(&session_id)
        .map(|session| session.session_anchor().id().to_string())
        .unwrap();

    kernel.close_session(&session_id).unwrap();
    let closed = kernel.session(&session_id).unwrap();
    assert_eq!(closed.state(), SessionState::Closed);
    assert!(!closed.auth_context().is_authenticated());

    let closed_anchor_id = closed.session_anchor().id().to_string();
    kernel.close_session(&session_id).unwrap();
    let reclosed = kernel.session(&session_id).unwrap();
    assert_eq!(reclosed.state(), SessionState::Closed);
    assert_eq!(reclosed.session_anchor().id(), closed_anchor_id);

    let records = anchors.lock().unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[2].anchor_id, closed_anchor_id);
    assert_ne!(closed_anchor_id, initial_anchor_id);
    assert_ne!(closed_anchor_id, authenticated_anchor_id);
    assert_eq!(
        records[2].supersedes_anchor_id.as_deref(),
        Some(authenticated_anchor_id.as_str())
    );
    drop(records);

    let error = kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:late",
                "cafebabe",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        KernelError::Session(SessionError::OperationNotAllowed {
            operation: "set_auth_context",
            state: "closed",
            ..
        })
    ));
}

#[test]
fn close_session_with_sqlite_store_reuses_initial_anonymous_anchor() {
    let path = unique_receipt_db_path("session-close-anonymous-anchor");
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    let session_id = kernel
        .open_session_with_id(
            SessionId::new("sess-auth-close-sqlite"),
            "agent-a".to_string(),
            Vec::new(),
        )
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    kernel
        .set_session_auth_context(
            &session_id,
            SessionAuthContext::streamable_http_static_bearer(
                "static-bearer:sqlite-close",
                "deadbeef",
                Some("http://localhost:3000".to_string()),
            ),
        )
        .unwrap();

    kernel.close_session(&session_id).unwrap();
    let closed = kernel.session(&session_id).unwrap();
    assert_eq!(closed.state(), SessionState::Closed);
    assert!(!closed.auth_context().is_authenticated());
}

#[test]
fn web3_evidence_required_activation_rejects_missing_receipt_store() {
    let mut config = make_config();
    config.require_web3_evidence = true;
    let kernel = ChioKernel::new(config);
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

    let error = kernel.activate_session(&session_id).unwrap_err();
    assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
    assert!(error.to_string().contains("durable receipt store"));
}

#[test]
fn web3_evidence_required_activation_rejects_checkpoint_disabled() {
    let path = unique_receipt_db_path("web3-evidence-disabled");
    let mut config = make_config();
    config.require_web3_evidence = true;
    config.checkpoint_batch_size = 0;
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

    let error = kernel.activate_session(&session_id).unwrap_err();
    assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
    assert!(error.to_string().contains("checkpoint_batch_size > 0"));

    let _ = std::fs::remove_file(path);
}

#[test]
fn web3_evidence_required_activation_rejects_append_only_receipt_store() {
    let mut config = make_config();
    config.require_web3_evidence = true;
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore));
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

    let error = kernel.activate_session(&session_id).unwrap_err();
    assert!(matches!(error, KernelError::Web3EvidenceUnavailable(_)));
    assert!(error
        .to_string()
        .contains("append-only remote receipt mirrors are unsupported"));
}

#[test]
fn web3_evidence_required_activation_allows_checkpoint_capable_store() {
    let path = unique_receipt_db_path("web3-evidence-capable");
    let mut config = make_config();
    config.require_web3_evidence = true;
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    let session_id = kernel.open_session("agent-1".to_string(), Vec::new());

    kernel.activate_session(&session_id).unwrap();
    assert_eq!(
        kernel.session(&session_id).map(|session| session.state()),
        Some(SessionState::Ready)
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn session_operation_tool_call_tracks_and_clears_inflight() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(&session_id, "req-1", &agent_kp.public_key().to_hex());
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        model_metadata: None,
    });

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected tool call response");
    assert_eq!(response.verdict, Verdict::Allow);

    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
}

#[test]
fn session_operation_capability_list_uses_session_snapshot() {
    let kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]);
    let context = make_operation_context(&session_id, "control-1", &agent_kp.public_key().to_hex());

    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListCapabilities)
        .unwrap();

    let capabilities =
        session_capability_list(response).expect("expected capability list response");
    assert_eq!(capabilities.len(), 1);
}

#[test]
fn session_operation_list_roots_uses_session_snapshot() {
    let kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: true,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let context = make_operation_context(&session_id, "roots-1", &agent_kp.public_key().to_hex());
    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListRoots)
        .unwrap();

    let roots = session_root_list(response).expect("expected root list response");
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].uri, "file:///workspace/project");
}

#[test]
fn kernel_exposes_normalized_session_roots_for_later_enforcement() {
    let kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![
                RootDefinition {
                    uri: "file:///workspace/project/../project/src".to_string(),
                    name: Some("Code".to_string()),
                },
                RootDefinition {
                    uri: "repo://docs/roadmap".to_string(),
                    name: Some("Roadmap".to_string()),
                },
                RootDefinition {
                    uri: "file://remote-host/workspace/project".to_string(),
                    name: Some("Remote".to_string()),
                },
            ],
        )
        .unwrap();

    let normalized = kernel.normalized_session_roots(&session_id).unwrap();
    assert_eq!(normalized.len(), 3);
    assert!(matches!(
        normalized[0],
        NormalizedRoot::EnforceableFileSystem {
            ref normalized_path,
            ..
        } if normalized_path == "/workspace/project/src"
    ));
    assert!(matches!(
        normalized[1],
        NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
    ));
    assert!(matches!(
        normalized[2],
        NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
            if reason == "non_local_file_authority"
    ));
    assert_eq!(
        kernel
            .enforceable_filesystem_root_paths(&session_id)
            .unwrap(),
        vec!["/workspace/project/src"]
    );
}

#[test]
fn begin_child_request_requires_parent_lineage() {
    let kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-1"),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();

    let session = kernel.session(&session_id).unwrap();
    let child = session.inflight().get(&child_context.request_id).unwrap();
    assert_eq!(child.parent_request_id, Some(RequestId::new("parent-1")));
}

#[test]
fn begin_session_request_clears_inflight_when_lineage_persistence_fails() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(FailingRequestLineageReceiptStore));
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "lineage-fail-root",
        &agent_kp.public_key().to_hex(),
    );
    let error = kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "request lineage write failed"
    ));
    let session = kernel.session(&session_id).unwrap();
    assert!(session.inflight().is_empty());
    assert_eq!(
        session.terminal().get(&context.request_id),
        None,
        "failed non-durable start does not leave terminal state"
    );
    assert_eq!(
        session.request_lineage(&context.request_id),
        None,
        "failed non-durable start does not leave in-memory lineage"
    );

    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore));
    kernel
        .begin_session_request(&context, OperationKind::ToolCall, true)
        .unwrap();
}

#[test]
fn begin_child_request_clears_child_inflight_when_lineage_persistence_fails() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore));
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-ok", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    kernel.set_receipt_store(Box::new(FailingRequestLineageReceiptStore));

    let child_request_id = RequestId::new("lineage-fail-child");
    let error = kernel
        .begin_child_request(
            &parent_context,
            child_request_id.clone(),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap_err();

    assert!(matches!(
        error,
        KernelError::ReceiptPersistence(ReceiptStoreError::Conflict(message))
            if message == "request lineage write failed"
    ));
    let session = kernel.session(&session_id).unwrap();
    assert!(
        session.inflight().get(&parent_context.request_id).is_some(),
        "parent request remains active"
    );
    assert!(
        session.inflight().get(&child_request_id).is_none(),
        "failed child request is removed from active tracking"
    );
    assert_eq!(
        session.terminal().get(&child_request_id),
        None,
        "failed child start does not leave terminal state"
    );
    assert_eq!(
        session.request_lineage(&child_request_id),
        None,
        "failed child start does not leave in-memory lineage"
    );

    kernel.set_receipt_store(Box::new(AppendOnlyReceiptStore));
    kernel
        .begin_child_request(
            &parent_context,
            child_request_id,
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();
}

#[test]
fn sampling_validation_requires_policy_and_negotiation() {
    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();

    let parent_context =
        make_operation_context(&session_id, "parent-1", &agent_kp.public_key().to_hex());
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-1"),
            OperationKind::CreateMessage,
            None,
            true,
        )
        .unwrap();
    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "Summarize the diff"
            }),
            meta: None,
        }],
        model_preferences: None,
        system_prompt: None,
        include_context: None,
        temperature: None,
        max_tokens: 256,
        stop_sequences: vec![],
        metadata: None,
        tools: vec![],
        tool_choice: None,
    };

    let denied = kernel.validate_sampling_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingNotAllowedByPolicy)
    ));

    kernel.config.allow_sampling = true;
    let denied = kernel.validate_sampling_request(&child_context, &operation);
    assert!(matches!(denied, Err(KernelError::SamplingNotNegotiated)));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: true,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .validate_sampling_request(&child_context, &operation)
        .unwrap();

    let tool_operation = CreateMessageOperation {
        tools: vec![SamplingTool {
            name: "search_docs".to_string(),
            description: Some("Search docs".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                }
            }),
        }],
        tool_choice: Some(SamplingToolChoice {
            mode: "auto".to_string(),
        }),
        ..operation
    };
    let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingToolUseNotAllowedByPolicy)
    ));

    kernel.config.allow_sampling_tool_use = true;
    let denied = kernel.validate_sampling_request(&child_context, &tool_operation);
    assert!(matches!(
        denied,
        Err(KernelError::SamplingToolUseNotNegotiated)
    ));
}

#[test]
fn elicitation_validation_requires_policy_and_form_negotiation() {
    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![]);
    kernel.activate_session(&session_id).unwrap();

    let parent_context = make_operation_context(
        &session_id,
        "parent-elicit-1",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let child_context = kernel
        .begin_child_request(
            &parent_context,
            RequestId::new("child-elicit-1"),
            OperationKind::CreateElicitation,
            None,
            true,
        )
        .unwrap();
    let operation = CreateElicitationOperation::Form {
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
    };

    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationNotAllowedByPolicy)
    ));

    kernel.config.allow_elicitation = true;
    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(denied, Err(KernelError::ElicitationNotNegotiated)));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();
    let denied = kernel.validate_elicitation_request(&child_context, &operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationFormNotSupported)
    ));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: false,
            },
        )
        .unwrap();
    kernel
        .validate_elicitation_request(&child_context, &operation)
        .unwrap();

    let url_operation = CreateElicitationOperation::Url {
        meta: None,
        message: "Open the secure enrollment flow".to_string(),
        url: "https://example.test/consent".to_string(),
        elicitation_id: "elicitation-123".to_string(),
    };
    let denied = kernel.validate_elicitation_request(&child_context, &url_operation);
    assert!(matches!(
        denied,
        Err(KernelError::ElicitationUrlNotSupported)
    ));

    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: true,
            },
        )
        .unwrap();
    kernel
        .validate_elicitation_request(&child_context, &url_operation)
        .unwrap();
}

#[test]
fn tool_call_nested_flow_bridge_roundtrips_sampling() {
    let mut config = make_config();
    config.allow_sampling = true;
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: true,
                supports_sampling: true,
                sampling_context: true,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: vec![RootDefinition {
            uri: "file:///workspace/project".to_string(),
            name: Some("Project".to_string()),
        }],
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "Roadmap summary",
            }),
            model: "gpt-test".to_string(),
            stop_reason: Some("end_turn".to_string()),
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-1",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let value = tool_call_value_output(response.output).expect("expected value output");
    assert_eq!(value["model"], "gpt-test");
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(kernel.child_receipt_log().len(), 1);
    let child_receipt_log = kernel.child_receipt_log();
    let child_receipt = child_receipt_log.get(0).unwrap();
    assert_eq!(child_receipt.parent_request_id, context.request_id);
    assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
    assert_eq!(
        child_receipt.terminal_state,
        OperationTerminalState::Completed
    );
    assert!(child_receipt.verify_signature().unwrap());
    assert_eq!(
        child_receipt.metadata.as_ref().unwrap()["outcome"],
        "result"
    );
}

#[test]
fn kernel_persists_child_receipts_to_sqlite_store() {
    let path = unique_receipt_db_path("chio-kernel-child-receipts");
    let mut config = make_config();
    config.allow_sampling = true;
    let mut kernel = ChioKernel::new(config);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "sampled via durable store test",
            }),
            model: "gpt-test".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-sqlite-1",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();
    assert_eq!(response.verdict, Verdict::Allow);
    drop(kernel);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let tool_count: i64 = connection
        .query_row("SELECT COUNT(*) FROM chio_tool_receipts", [], |row| {
            row.get(0)
        })
        .unwrap();
    let (child_count, distinct_child_count, child_receipt_id): (i64, i64, String) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(DISTINCT receipt_id), MIN(receipt_id) FROM chio_child_receipts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();

    assert_eq!(tool_count, 1);
    assert_eq!(child_count, 1);
    assert_eq!(distinct_child_count, 1);
    assert!(child_receipt_id.starts_with("child-rcpt-"));

    drop(connection);
    let _ = std::fs::remove_file(path);
}

#[test]
fn tool_call_nested_flow_bridge_roundtrips_elicitation() {
    let mut config = make_config();
    config.allow_elicitation = true;
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "elicit_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: true,
                elicitation_form: true,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-elicit-1",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "elicit_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let value = tool_call_value_output(response.output).expect("expected value output");
    assert_eq!(value["action"], "accept");
    assert_eq!(value["content"]["environment"], "staging");
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
}

#[test]
fn tool_call_nested_flow_bridge_updates_session_roots() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "roots_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: false,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: true,
                roots_list_changed: true,
                supports_sampling: false,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let expected_roots = vec![RootDefinition {
        uri: "file:///workspace/project".to_string(),
        name: Some("Project".to_string()),
    }];
    let mut client = MockNestedFlowClient {
        roots: expected_roots.clone(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-2",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "roots_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(kernel.session(&session_id).unwrap().roots(), expected_roots);
}

#[test]
fn tool_call_nested_flow_bridge_propagates_parent_cancellation() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.config.allow_sampling = true;
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: true,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: true,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-parent-cancel",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();
    let expected_reason = "client cancelled parent request".to_string();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
    assert_eq!(
        response.terminal_state,
        OperationTerminalState::Cancelled {
            reason: expected_reason.clone(),
        }
    );
    assert!(response.receipt.is_cancelled());
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&context.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: expected_reason,
        })
    );
}

#[test]
fn tool_call_nested_flow_bridge_propagates_child_cancellation() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.config.allow_sampling = true;
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "sample_via_client")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .set_session_peer_capabilities(
            &session_id,
            PeerCapabilities {
                supports_progress: false,
                supports_cancellation: true,
                supports_subscriptions: false,
                supports_chio_tool_streaming: false,
                supports_roots: false,
                roots_list_changed: false,
                supports_sampling: true,
                sampling_context: false,
                sampling_tools: false,
                supports_elicitation: false,
                elicitation_form: false,
                elicitation_url: false,
            },
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: true,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-child-cancel",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability,
        server_id: "nested".to_string(),
        tool_name: "sample_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();
    let expected_reason = "client cancelled nested request".to_string();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
    assert_eq!(
        response.terminal_state,
        OperationTerminalState::Cancelled {
            reason: expected_reason.clone(),
        }
    );
    assert!(response.receipt.is_cancelled());
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&context.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: expected_reason,
        })
    );
    assert_eq!(kernel.child_receipt_log().len(), 1);
    let child_receipt_log = kernel.child_receipt_log();
    let child_receipt = child_receipt_log.get(0).unwrap();
    assert_eq!(child_receipt.parent_request_id, context.request_id);
    assert_eq!(child_receipt.operation_kind, OperationKind::CreateMessage);
    assert_eq!(
        child_receipt.terminal_state,
        OperationTerminalState::Cancelled {
            reason: "client cancelled nested request".to_string(),
        }
    );
    assert!(child_receipt.verify_signature().unwrap());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&child_receipt.request_id),
        Some(OperationTerminalState::Cancelled {
            reason: "client cancelled nested request".to_string(),
        })
    );
}

#[test]
fn session_tool_call_records_incomplete_terminal_state() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(IncompleteServer {
        id: "broken".to_string(),
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("broken", "drop_stream")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "incomplete-tool-call",
        &agent_kp.public_key().to_hex(),
    );
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability,
        server_id: "broken".to_string(),
        tool_name: "drop_stream".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    });

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected tool call response");

    let expected_reason = "upstream stream closed before tool response completed".to_string();
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(response.reason.as_deref(), Some(expected_reason.as_str()));
    assert_eq!(
        response.terminal_state,
        OperationTerminalState::Incomplete {
            reason: expected_reason.clone(),
        }
    );
    assert!(response.receipt.is_incomplete());
    assert!(kernel.session(&session_id).unwrap().inflight().is_empty());
    assert_eq!(
        kernel
            .session(&session_id)
            .unwrap()
            .terminal()
            .get(&context.request_id),
        Some(OperationTerminalState::Incomplete {
            reason: expected_reason,
        })
    );
}

#[test]
fn streamed_tool_receipt_records_chunk_hash_metadata() {
    let mut kernel = ChioKernel::new(make_config());
    let chunk_a = serde_json::json!({"delta": "hello"});
    let chunk_b = serde_json::json!({"delta": {"path": "/workspace/README.md"}});
    kernel.register_tool_server(Box::new(StreamingServer {
        id: "stream".to_string(),
        chunks: vec![chunk_a.clone(), chunk_b.clone()],
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("stream", "stream_file")]),
        300,
    );
    let request = make_request_with_arguments(
        "stream-receipt",
        &capability,
        "stream_file",
        "stream",
        serde_json::json!({"path": "/workspace/README.md"}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("stream metadata");
    let stream_metadata = metadata.get("stream").expect("stream metadata object");
    assert_eq!(stream_metadata["chunks_expected"].as_u64(), Some(2));
    assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(2));

    let chunk_a_bytes = chio_core::canonical::canonical_json_bytes(&chunk_a).unwrap();
    let chunk_b_bytes = chio_core::canonical::canonical_json_bytes(&chunk_b).unwrap();
    let expected_total_bytes = (chunk_a_bytes.len() + chunk_b_bytes.len()) as u64;
    assert_eq!(
        stream_metadata["total_bytes"].as_u64(),
        Some(expected_total_bytes)
    );

    let chunk_hashes = stream_metadata["chunk_hashes"]
        .as_array()
        .expect("chunk hashes array")
        .iter()
        .map(|value| value.as_str().expect("chunk hash string").to_string())
        .collect::<Vec<_>>();
    let expected_hashes = vec![
        chio_core::crypto::sha256_hex(&chunk_a_bytes),
        chio_core::crypto::sha256_hex(&chunk_b_bytes),
    ];
    assert_eq!(chunk_hashes, expected_hashes);

    let expected_content_hash = chio_core::crypto::sha256_hex(expected_hashes.join("").as_bytes());
    assert_eq!(response.receipt.content_hash, expected_content_hash);
}

#[test]
fn streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete() {
    let mut config = make_config();
    config.max_stream_total_bytes = 20;
    let mut kernel = ChioKernel::new(config);
    let first_chunk = serde_json::json!({"delta": "ok"});
    let second_chunk = serde_json::json!({"delta": "this chunk exceeds the configured byte limit"});
    kernel.register_tool_server(Box::new(StreamingServer {
        id: "stream".to_string(),
        chunks: vec![first_chunk.clone(), second_chunk],
    }));

    let agent_kp = make_keypair();
    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("stream", "stream_file")]),
        300,
    );
    let request = make_request_with_arguments(
        "stream-byte-limit",
        &capability,
        "stream_file",
        "stream",
        serde_json::json!({}),
    );

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.receipt.is_incomplete());
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));
    assert!(response
        .reason
        .as_deref()
        .unwrap_or("")
        .contains("max total bytes"));

    let output_stream = tool_call_stream_output(response.output).expect("expected stream output");
    assert_eq!(output_stream.chunk_count(), 1);
    assert_eq!(output_stream.chunks[0].data, first_chunk);

    let stream_metadata = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("stream"))
        .expect("stream metadata");
    assert!(stream_metadata["chunks_expected"].is_null());
    assert_eq!(stream_metadata["chunks_received"].as_u64(), Some(1));
}

#[test]
fn apply_stream_limits_marks_duration_exceeded_stream_incomplete() {
    let mut config = make_config();
    config.max_stream_duration_secs = 1;
    let kernel = ChioKernel::new(config);
    let output = ToolServerOutput::Stream(ToolServerStreamResult::Complete(ToolCallStream {
        chunks: vec![ToolCallChunk {
            data: serde_json::json!({"delta": "slow"}),
        }],
    }));

    let limited = kernel
        .apply_stream_limits(output, std::time::Duration::from_secs(2))
        .unwrap();

    let (stream, reason) = match limited {
        ToolServerOutput::Stream(ToolServerStreamResult::Incomplete { stream, reason }) => {
            Some((stream, reason))
        }
        _ => None,
    }
    .expect("expected limited incomplete stream");
    assert_eq!(stream.chunk_count(), 1);
    assert!(reason.contains("max duration of 1s"));
}

#[test]
fn tool_call_nested_flow_bridge_filters_resource_notifications_to_session_subscriptions() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_tool_server(Box::new(NestedFlowServer {
        id: "nested".to_string(),
    }));
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let tool_capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("nested", "notify_resources_via_client")]),
        300,
    );
    let resource_capability = make_capability(
        &kernel,
        &agent_kp,
        ChioScope {
            resource_grants: vec![ResourceGrant {
                uri_pattern: "repo://docs/*".to_string(),
                operations: vec![Operation::Read, Operation::Subscribe],
            }],
            ..ChioScope::default()
        },
        300,
    );
    let session_id = kernel.open_session(
        agent_kp.public_key().to_hex(),
        vec![tool_capability.clone(), resource_capability.clone()],
    );
    kernel.activate_session(&session_id).unwrap();
    kernel
        .subscribe_session_resource(
            &session_id,
            &resource_capability,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        )
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "unused",
            }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let context = make_operation_context(
        &session_id,
        "nested-tool-resource-notify",
        &agent_kp.public_key().to_hex(),
    );
    let operation = ToolCallOperation {
        capability: tool_capability,
        server_id: "nested".to_string(),
        tool_name: "notify_resources_via_client".to_string(),
        arguments: serde_json::json!({}),
        model_metadata: None,
    };

    let response = kernel
        .evaluate_tool_call_operation_with_nested_flow_client(&context, &operation, &mut client)
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        client.resource_updates,
        vec!["repo://docs/roadmap".to_string()]
    );
    assert_eq!(client.resources_list_changed_count, 1);
}

#[test]
fn session_operation_list_resources_filters_to_session_scope() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap]);
    kernel.activate_session(&session_id).unwrap();
    let context =
        make_operation_context(&session_id, "resources-1", &agent_kp.public_key().to_hex());

    let response = kernel
        .evaluate_session_operation(&context, &SessionOperation::ListResources)
        .unwrap();

    let resources = session_resource_list(response).expect("expected resource list response");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].uri, "repo://docs/roadmap");
}

#[test]
fn session_operation_read_resource_enforces_scope() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let allowed_context = make_operation_context(
        &session_id,
        "resource-read-1",
        &agent_kp.public_key().to_hex(),
    );
    let allowed = kernel
        .evaluate_session_operation(
            &allowed_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap.clone(),
                uri: "repo://docs/roadmap".to_string(),
            }),
        )
        .unwrap();
    let contents = session_resource_read(allowed).expect("expected resource read response");
    assert_eq!(contents[0].text.as_deref(), Some("# Roadmap"));

    let denied_context = make_operation_context(
        &session_id,
        "resource-read-2",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "repo://secret/ops".to_string(),
        }),
    );
    assert!(matches!(
        denied,
        Err(KernelError::OutOfScopeResource { .. })
    ));
}

#[test]
fn session_operation_read_resource_enforces_session_roots_for_filesystem_resources() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .replace_session_roots(
            &session_id,
            vec![RootDefinition {
                uri: "file:///workspace/project".to_string(),
                name: Some("Project".to_string()),
            }],
        )
        .unwrap();

    let allowed_context = make_operation_context(
        &session_id,
        "resource-read-file-1",
        &agent_kp.public_key().to_hex(),
    );
    let allowed = kernel
        .evaluate_session_operation(
            &allowed_context,
            &SessionOperation::ReadResource(ReadResourceOperation {
                capability: cap.clone(),
                uri: "file:///workspace/project/docs/roadmap.md".to_string(),
            }),
        )
        .unwrap();
    let contents = session_resource_read(allowed).expect("expected resource read response");
    assert_eq!(contents[0].text.as_deref(), Some("# Filesystem Roadmap"));

    let denied_context = make_operation_context(
        &session_id,
        "resource-read-file-2",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "file:///workspace/private/ops.md".to_string(),
        }),
    );
    let receipt = match denied {
        Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
        _ => None,
    }
    .expect("expected signed resource read denial");
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert_eq!(receipt.tool_name, "resources/read");
    assert_eq!(receipt.tool_server, "session");
    assert_eq!(
            receipt.decision,
            Decision::Deny {
                reason:
                    "filesystem-backed resource path /workspace/private/ops.md is outside the negotiated roots"
                        .to_string(),
                guard: "session_roots".to_string(),
            }
        );
}

#[test]
fn session_operation_read_resource_fails_closed_when_filesystem_roots_are_missing() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(FilesystemResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "file:///workspace/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(
        &session_id,
        "resource-read-file-3",
        &agent_kp.public_key().to_hex(),
    );
    let denied = kernel.evaluate_session_operation(
        &context,
        &SessionOperation::ReadResource(ReadResourceOperation {
            capability: cap,
            uri: "file:///workspace/project/docs/roadmap.md".to_string(),
        }),
    );
    let receipt = match denied {
        Ok(SessionOperationResponse::ResourceReadDenied { receipt }) => Some(receipt),
        _ => None,
    }
    .expect("expected signed resource read denial");
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.is_denied());
    assert_eq!(
        receipt.decision,
        Decision::Deny {
            reason: "no enforceable filesystem roots are available for this session".to_string(),
            guard: "session_roots".to_string(),
        }
    );
}

#[test]
fn subscribe_session_resource_requires_subscribe_operation() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let read_only_scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        ..ChioScope::default()
    };
    let read_only_cap = make_capability(&kernel, &agent_kp, read_only_scope, 300);

    let session_id =
        kernel.open_session(agent_kp.public_key().to_hex(), vec![read_only_cap.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let denied = kernel.subscribe_session_resource(
        &session_id,
        &read_only_cap,
        &agent_kp.public_key().to_hex(),
        "repo://docs/roadmap",
    );
    assert!(matches!(
        denied,
        Err(KernelError::OutOfScopeResource { .. })
    ));

    let subscribe_scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read, Operation::Subscribe],
        }],
        ..ChioScope::default()
    };
    let subscribe_cap = make_capability(&kernel, &agent_kp, subscribe_scope, 300);
    kernel
        .subscribe_session_resource(
            &session_id,
            &subscribe_cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        )
        .unwrap();

    assert!(kernel
        .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
        .unwrap());
}

#[test]
fn unsubscribe_session_resource_is_idempotent() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read, Operation::Subscribe],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();
    kernel
        .subscribe_session_resource(
            &session_id,
            &cap,
            &agent_kp.public_key().to_hex(),
            "repo://docs/roadmap",
        )
        .unwrap();

    kernel
        .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
        .unwrap();
    kernel
        .unsubscribe_session_resource(&session_id, "repo://docs/roadmap")
        .unwrap();

    assert!(!kernel
        .session_has_resource_subscription(&session_id, "repo://docs/roadmap")
        .unwrap());
}

#[test]
fn session_operation_get_prompt_enforces_scope() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        prompt_grants: vec![PromptGrant {
            prompt_name: "summarize_*".to_string(),
            operations: vec![Operation::Get],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let list_context =
        make_operation_context(&session_id, "prompts-1", &agent_kp.public_key().to_hex());
    let list_response = kernel
        .evaluate_session_operation(&list_context, &SessionOperation::ListPrompts)
        .unwrap();
    let prompts = session_prompt_list(list_response).expect("expected prompt list response");
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].name, "summarize_docs");

    let get_context =
        make_operation_context(&session_id, "prompts-2", &agent_kp.public_key().to_hex());
    let get_response = kernel
        .evaluate_session_operation(
            &get_context,
            &SessionOperation::GetPrompt(GetPromptOperation {
                capability: cap.clone(),
                prompt_name: "summarize_docs".to_string(),
                arguments: serde_json::json!({"topic": "roadmap"}),
            }),
        )
        .unwrap();
    let prompt = session_prompt_get(get_response).expect("expected prompt get response");
    assert_eq!(prompt.messages[0].content["text"], "Summarize roadmap");

    let denied_context =
        make_operation_context(&session_id, "prompts-3", &agent_kp.public_key().to_hex());
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::GetPrompt(GetPromptOperation {
            capability: cap,
            prompt_name: "ops_secret".to_string(),
            arguments: serde_json::json!({}),
        }),
    );
    assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
}

#[test]
fn session_operation_completion_returns_candidates_and_enforces_scope() {
    let mut kernel = ChioKernel::new(make_config());
    kernel.register_resource_provider(Box::new(DocsResourceProvider));
    kernel.register_prompt_provider(Box::new(ExamplePromptProvider));

    let agent_kp = make_keypair();
    let scope = ChioScope {
        resource_grants: vec![ResourceGrant {
            uri_pattern: "repo://docs/*".to_string(),
            operations: vec![Operation::Read],
        }],
        prompt_grants: vec![PromptGrant {
            prompt_name: "summarize_*".to_string(),
            operations: vec![Operation::Get],
        }],
        ..ChioScope::default()
    };
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let prompt_context =
        make_operation_context(&session_id, "complete-1", &agent_kp.public_key().to_hex());
    let prompt_completion = kernel
        .evaluate_session_operation(
            &prompt_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap.clone(),
                reference: CompletionReference::Prompt {
                    name: "summarize_docs".to_string(),
                },
                argument: CompletionArgument {
                    name: "topic".to_string(),
                    value: "r".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        )
        .unwrap();
    let completion = session_completion(prompt_completion).expect("expected completion response");
    assert_eq!(completion.total, Some(2));
    assert_eq!(completion.values, vec!["roadmap", "release-plan"]);

    let resource_context =
        make_operation_context(&session_id, "complete-2", &agent_kp.public_key().to_hex());
    let resource_completion = kernel
        .evaluate_session_operation(
            &resource_context,
            &SessionOperation::Complete(CompleteOperation {
                capability: cap.clone(),
                reference: CompletionReference::Resource {
                    uri: "repo://docs/{slug}".to_string(),
                },
                argument: CompletionArgument {
                    name: "slug".to_string(),
                    value: "a".to_string(),
                },
                context_arguments: serde_json::json!({}),
            }),
        )
        .unwrap();
    let completion = session_completion(resource_completion).expect("expected completion response");
    assert_eq!(completion.total, Some(2));
    assert_eq!(completion.values, vec!["architecture", "api"]);

    let denied_context =
        make_operation_context(&session_id, "complete-3", &agent_kp.public_key().to_hex());
    let denied = kernel.evaluate_session_operation(
        &denied_context,
        &SessionOperation::Complete(CompleteOperation {
            capability: cap,
            reference: CompletionReference::Prompt {
                name: "ops_secret".to_string(),
            },
            argument: CompletionArgument {
                name: "topic".to_string(),
                value: "o".to_string(),
            },
            context_arguments: serde_json::json!({}),
        }),
    );
    assert!(matches!(denied, Err(KernelError::OutOfScopePrompt { .. })));
}

/// A tool server that always reports a specific actual cost.
struct MonetaryCostServer {
    id: String,
    reported_cost: Option<ToolInvocationCost>,
}

struct FailingMonetaryServer {
    id: String,
}

struct CountingMonetaryServer {
    id: String,
    invocations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

struct StaticPriceOracle {
    rates: std::collections::BTreeMap<(String, String), Result<ExchangeRate, PriceOracleError>>,
}

impl StaticPriceOracle {
    fn new(
        rates: impl IntoIterator<Item = ((String, String), Result<ExchangeRate, PriceOracleError>)>,
    ) -> Self {
        Self {
            rates: rates.into_iter().collect(),
        }
    }
}

impl PriceOracle for StaticPriceOracle {
    fn get_rate<'a>(
        &'a self,
        base: &'a str,
        quote: &'a str,
    ) -> Pin<
        Box<dyn std::future::Future<Output = Result<ExchangeRate, PriceOracleError>> + Send + 'a>,
    > {
        let response = self
            .rates
            .get(&(base.to_ascii_uppercase(), quote.to_ascii_uppercase()))
            .cloned()
            .unwrap_or_else(|| {
                Err(PriceOracleError::NoPairAvailable {
                    base: base.to_ascii_uppercase(),
                    quote: quote.to_ascii_uppercase(),
                })
            });
        Box::pin(async move { response })
    }

    fn supported_pairs(&self) -> Vec<String> {
        self.rates
            .keys()
            .map(|(base, quote)| format!("{base}/{quote}"))
            .collect()
    }
}

impl MonetaryCostServer {
    fn new(id: &str, cost_units: u64, currency: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: Some(ToolInvocationCost {
                units: cost_units,
                currency: currency.to_string(),
                breakdown: None,
            }),
        }
    }

    fn no_cost(id: &str) -> Self {
        Self {
            id: id.to_string(),
            reported_cost: None,
        }
    }
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for MonetaryCostServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec![
            "compute".to_string(),
            "compute-a".to_string(),
            "compute-b".to_string(),
        ]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, self.reported_cost.clone()))
    }
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for FailingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        Err(KernelError::Internal("tool server failure".to_string()))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let _ = (tool_name, arguments, bridge);
        Err(KernelError::Internal("tool server failure".to_string()))
    }
}

#[async_trait::async_trait(?Send)]
impl ToolServerConnection for CountingMonetaryServer {
    fn server_id(&self) -> &str {
        &self.id
    }

    fn tool_names(&self) -> Vec<String> {
        vec!["compute".to_string()]
    }

    async fn invoke(
        &self,
        _tool_name: &str,
        _arguments: serde_json::Value,
        _nested_flow_bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<serde_json::Value, KernelError> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(serde_json::json!({"result": "ok"}))
    }

    async fn invoke_with_cost(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
        bridge: Option<&mut dyn NestedFlowBridge>,
    ) -> Result<(serde_json::Value, Option<ToolInvocationCost>), KernelError> {
        let value = self.invoke(tool_name, arguments, bridge).await?;
        Ok((value, None))
    }
}

fn make_monetary_grant(
    server: &str,
    tool: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
) -> ToolGrant {
    use chio_core::capability::MonetaryAmount;
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: Some(MonetaryAmount {
            units: max_cost_per_invocation,
            currency: currency.to_string(),
        }),
        max_total_cost: Some(MonetaryAmount {
            units: max_total_cost,
            currency: currency.to_string(),
        }),
        dpop_required: None,
    }
}

fn make_monetary_config() -> KernelConfig {
    KernelConfig {
        keypair: make_keypair(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "monetary-policy-hash".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    }
}

struct SiblingSumMonetaryFixture {
    kernel: ChioKernel,
    child_a: CapabilityToken,
    child_b: CapabilityToken,
    child_a_kp: Keypair,
    child_b_kp: Keypair,
    path: PathBuf,
}

fn make_sibling_sum_monetary_fixture(prefix: &str) -> SiblingSumMonetaryFixture {
    let path = unique_receipt_db_path(prefix);
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let parent_kp = make_keypair();
    let child_a_kp = make_keypair();
    let child_b_kp = make_keypair();
    let mut parent_grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
    parent_grant.operations.push(Operation::Delegate);
    let parent_scope = make_scope(vec![parent_grant]);
    let child_scope = make_scope(vec![make_monetary_grant(
        "cost-srv", "compute", 100, 1_000, "USD",
    )]);
    let parent = make_capability(&kernel, &parent_kp, parent_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&parent, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    kernel
        .register_budget_parent(parent.id.clone(), 5_000)
        .unwrap();
    kernel.set_capability_trust_root(
        kernel.config.keypair.public_key(),
        scope_hash(&parent_scope).unwrap(),
    );

    let child_a = make_v2_delegated_child(
        &kernel,
        &parent,
        &parent_kp,
        &child_a_kp,
        &parent_scope,
        child_scope.clone(),
        &format!("cap-{prefix}-child-a"),
        4_000,
    );
    let child_b = make_v2_delegated_child(
        &kernel,
        &parent,
        &parent_kp,
        &child_b_kp,
        &parent_scope,
        child_scope,
        &format!("cap-{prefix}-child-b"),
        4_000,
    );

    SiblingSumMonetaryFixture {
        kernel,
        child_a,
        child_b,
        child_a_kp,
        child_b_kp,
        path,
    }
}

fn spawn_payment_test_server(
    status_code: u16,
    body: serde_json::Value,
) -> (String, mpsc::Receiver<String>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("listener should bind");
    let address = listener
        .local_addr()
        .expect("listener should expose local address");
    let (request_tx, request_rx) = mpsc::channel();
    let body_text = body.to_string();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("server should accept request");
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let mut header_end = None;
        let mut content_length = 0_usize;

        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("server should configure read timeout");
        loop {
            let read = stream
                .read(&mut chunk)
                .expect("server should read request bytes");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);

            if header_end.is_none() {
                header_end = find_http_header_end(&request);
                if let Some(end) = header_end {
                    content_length = parse_http_content_length(&request[..end]);
                }
            }

            if let Some(end) = header_end {
                if request.len() >= end + content_length {
                    break;
                }
            }
        }

        request_tx
            .send(String::from_utf8_lossy(&request).into_owned())
            .expect("request should be sent to test");
        let response = format!(
            "HTTP/1.1 {status_code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            http_status_text(status_code),
            body_text.len(),
            body_text
        );
        stream
            .write_all(response.as_bytes())
            .expect("server should write response");
    });

    (format!("http://{address}"), request_rx, handle)
}

fn find_http_header_end(request: &[u8]) -> Option<usize> {
    request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn parse_http_content_length(headers: &[u8]) -> usize {
    let text = String::from_utf8_lossy(headers);
    text.lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

fn http_status_text(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        402 => "Payment Required",
        _ => "Error",
    }
}

fn make_governed_monetary_grant(
    server: &str,
    tool: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> ToolGrant {
    let mut grant = make_monetary_grant(
        server,
        tool,
        max_cost_per_invocation,
        max_total_cost,
        currency,
    );
    grant.constraints = vec![
        Constraint::GovernedIntentRequired,
        Constraint::RequireApprovalAbove {
            threshold_units: approval_threshold_units,
        },
    ];
    grant
}

fn with_minimum_runtime_assurance(mut grant: ToolGrant, tier: RuntimeAssuranceTier) -> ToolGrant {
    grant
        .constraints
        .push(Constraint::MinimumRuntimeAssurance(tier));
    grant
}

fn with_minimum_autonomy_tier(mut grant: ToolGrant, tier: GovernedAutonomyTier) -> ToolGrant {
    grant
        .constraints
        .push(Constraint::MinimumAutonomyTier(tier));
    grant
}

fn make_governed_acp_monetary_grant(
    server: &str,
    tool: &str,
    seller: &str,
    max_cost_per_invocation: u64,
    max_total_cost: u64,
    currency: &str,
    approval_threshold_units: u64,
) -> ToolGrant {
    let mut grant = make_governed_monetary_grant(
        server,
        tool,
        max_cost_per_invocation,
        max_total_cost,
        currency,
        approval_threshold_units,
    );
    grant
        .constraints
        .push(Constraint::SellerExact(seller.to_string()));
    grant
}

fn make_governed_intent(
    id: &str,
    server: &str,
    tool: &str,
    purpose: &str,
    units: u64,
    currency: &str,
) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: id.to_string(),
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        purpose: purpose.to_string(),
        max_amount: Some(MonetaryAmount {
            units,
            currency: currency.to_string(),
        }),
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "invoice_id": "inv-1001",
            "operator": "finance-ops",
        })),
    }
}

struct GovernedAcpIntentFixture<'a> {
    id: &'a str,
    server: &'a str,
    tool: &'a str,
    purpose: &'a str,
    seller: &'a str,
    shared_payment_token_id: &'a str,
    units: u64,
    currency: &'a str,
}

fn make_governed_acp_intent(fixture: GovernedAcpIntentFixture<'_>) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: fixture.id.to_string(),
        server_id: fixture.server.to_string(),
        tool_name: fixture.tool.to_string(),
        purpose: fixture.purpose.to_string(),
        max_amount: Some(MonetaryAmount {
            units: fixture.units,
            currency: fixture.currency.to_string(),
        }),
        commerce: Some(chio_core::capability::GovernedCommerceContext {
            seller: fixture.seller.to_string(),
            shared_payment_token_id: fixture.shared_payment_token_id.to_string(),
        }),
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context: Some(serde_json::json!({
            "invoice_id": "inv-2002",
            "operator": "commerce-ops",
        })),
    }
}

fn make_runtime_attestation(
    tier: RuntimeAssuranceTier,
) -> chio_core::capability::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.enterprise-verifier.json.v1".to_string(),
        verifier: "https://attest.chio.example".to_string(),
        tier,
        issued_at: now.saturating_sub(1),
        expires_at: now + 300,
        evidence_sha256: format!("digest-{tier:?}"),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: Some(
            chio_core::capability::WorkloadIdentity::parse_spiffe_uri("spiffe://chio/runtime/test")
                .expect("parse runtime workload identity"),
        ),
        claims: Some(serde_json::json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": format!("sha384:digest-{tier:?}")
            }
        })),
    }
}

fn make_trusted_azure_runtime_attestation() -> chio_core::capability::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
        verifier: "https://maa.contoso.test/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-azure-attestation".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "azureMaa": {
                "attestationType": "sgx"
            }
        })),
    }
}

fn make_trusted_google_runtime_attestation() -> chio_core::capability::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
        verifier: "https://confidentialcomputing.googleapis.com".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-google-attestation".to_string(),
        runtime_identity: Some(
            "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1".to_string(),
        ),
        workload_identity: None,
        claims: Some(serde_json::json!({
            "googleAttestation": {
                "attestationType": "confidential_vm",
                "hardwareModel": "GCP_AMD_SEV",
                "secureBoot": "enabled"
            }
        })),
    }
}

fn make_trusted_nitro_runtime_attestation() -> chio_core::capability::RuntimeAttestationEvidence {
    let now = current_unix_timestamp();
    chio_core::capability::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
        verifier: "https://nitro.aws.example/".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "digest-nitro-attestation".to_string(),
        runtime_identity: None,
        workload_identity: None,
        claims: Some(serde_json::json!({
            "awsNitro": {
                "moduleId": "nitro-enclave-1",
                "digest": "sha384:aws-measurement",
                "pcrs": { "0": "0123" }
            }
        })),
    }
}

fn make_attestation_trust_policy() -> chio_core::capability::AttestationTrustPolicy {
    chio_core::capability::AttestationTrustPolicy {
        rules: vec![
            chio_core::capability::AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: std::collections::BTreeMap::new(),
            },
            chio_core::capability::AttestationTrustRule {
                name: "google-confidential".to_string(),
                schema: "chio.runtime-attestation.google-confidential-vm.jwt.v1".to_string(),
                verifier: "https://confidentialcomputing.googleapis.com".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(
                    chio_core::appraisal::AttestationVerifierFamily::GoogleAttestation,
                ),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["confidential_vm".to_string()],
                required_assertions: std::collections::BTreeMap::from([
                    ("hardwareModel".to_string(), "GCP_AMD_SEV".to_string()),
                    ("secureBoot".to_string(), "enabled".to_string()),
                ]),
            },
            chio_core::capability::AttestationTrustRule {
                name: "aws-nitro".to_string(),
                schema: "chio.runtime-attestation.aws-nitro-attestation.v1".to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: std::collections::BTreeMap::from([(
                    "moduleId".to_string(),
                    "nitro-enclave-1".to_string(),
                )]),
            },
        ],
    }
}

fn make_attested_attestation_trust_policy() -> chio_core::capability::AttestationTrustPolicy {
    chio_core::capability::AttestationTrustPolicy {
        rules: vec![chio_core::capability::AttestationTrustRule {
            name: "azure-contoso-attested".to_string(),
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            effective_tier: RuntimeAssuranceTier::Attested,
            verifier_family: Some(chio_core::appraisal::AttestationVerifierFamily::AzureMaa),
            max_evidence_age_seconds: Some(120),
            allowed_attestation_types: vec!["sgx".to_string()],
            required_assertions: std::collections::BTreeMap::new(),
        }],
    }
}

fn make_metered_billing_context(
    quote_id: &str,
    provider: &str,
    units: u64,
    currency: &str,
) -> chio_core::capability::MeteredBillingContext {
    let now = current_unix_timestamp();
    chio_core::capability::MeteredBillingContext {
        settlement_mode: chio_core::capability::MeteredSettlementMode::AllowThenSettle,
        quote: chio_core::capability::MeteredBillingQuote {
            quote_id: quote_id.to_string(),
            provider: provider.to_string(),
            billing_unit: "1k_tokens".to_string(),
            quoted_units: units,
            quoted_cost: MonetaryAmount {
                units: 60,
                currency: currency.to_string(),
            },
            issued_at: now.saturating_sub(5),
            expires_at: Some(now + 300),
        },
        max_billed_units: Some(units + 4),
    }
}

fn make_governed_call_chain_context(
    chain_id: &str,
    parent_request_id: &str,
) -> GovernedCallChainContext {
    GovernedCallChainContext {
        chain_id: chain_id.to_string(),
        parent_request_id: parent_request_id.to_string(),
        parent_receipt_id: Some("rc-upstream-1".to_string()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    }
}

fn make_governed_upstream_call_chain_proof(
    signer: &Keypair,
    subject: &PublicKey,
    call_chain: &GovernedCallChainContext,
) -> GovernedUpstreamCallChainProof {
    let now = current_unix_timestamp();
    GovernedUpstreamCallChainProof::sign(
        GovernedUpstreamCallChainProofBody {
            signer: signer.public_key(),
            subject: subject.clone(),
            chain_id: call_chain.chain_id.clone(),
            parent_request_id: call_chain.parent_request_id.clone(),
            parent_receipt_id: call_chain.parent_receipt_id.clone(),
            origin_subject: call_chain.origin_subject.clone(),
            delegator_subject: call_chain.delegator_subject.clone(),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        signer,
    )
    .unwrap()
}

fn attach_governed_upstream_call_chain_proof(
    intent: &mut GovernedTransactionIntent,
    proof: &GovernedUpstreamCallChainProof,
) {
    let mut context = match intent.context.take() {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    context.insert(
        GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY.to_string(),
        serde_json::to_value(proof).unwrap(),
    );
    intent.context = Some(serde_json::Value::Object(context));
}

struct GovernedCallChainContinuationTokenFixture<'a> {
    signer: &'a Keypair,
    subject: &'a PublicKey,
    call_chain: &'a GovernedCallChainContext,
    parent_session_anchor: SessionAnchorReference,
    parent_receipt_hash: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    governed_intent_hash: Option<&'a str>,
}

fn make_governed_call_chain_continuation_token(
    fixture: GovernedCallChainContinuationTokenFixture<'_>,
) -> CallChainContinuationToken {
    let now = current_unix_timestamp();
    CallChainContinuationToken::sign(
        CallChainContinuationTokenBody {
            schema: chio_core::capability::CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
            token_id: "continuation-token-1".to_string(),
            signer: fixture.signer.public_key(),
            subject: fixture.subject.clone(),
            chain_id: fixture.call_chain.chain_id.clone(),
            parent_request_id: fixture.call_chain.parent_request_id.clone(),
            parent_receipt_id: fixture.call_chain.parent_receipt_id.clone(),
            parent_receipt_hash: Some(fixture.parent_receipt_hash.to_string()),
            parent_session_anchor: Some(fixture.parent_session_anchor),
            current_subject: fixture.subject.to_hex(),
            delegator_subject: fixture.call_chain.delegator_subject.clone(),
            origin_subject: fixture.call_chain.origin_subject.clone(),
            parent_capability_id: None,
            delegation_link_hash: None,
            governed_intent_hash: fixture.governed_intent_hash.map(str::to_string),
            audience: Some(CallChainContinuationAudience {
                server_id: fixture.server_id.to_string(),
                tool_name: fixture.tool_name.to_string(),
            }),
            nonce: Some("nonce-continuation-1".to_string()),
            issued_at: now.saturating_sub(5),
            expires_at: now + 300,
        },
        fixture.signer,
    )
    .unwrap()
}

fn attach_governed_call_chain_continuation_token(
    intent: &mut GovernedTransactionIntent,
    token: &CallChainContinuationToken,
) {
    let mut context = match intent.context.take() {
        Some(serde_json::Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    context.insert(
        GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY.to_string(),
        serde_json::to_value(token).unwrap(),
    );
    intent.context = Some(serde_json::Value::Object(context));
}

fn make_governed_autonomy_context(
    tier: GovernedAutonomyTier,
    bond_id: Option<&str>,
) -> GovernedAutonomyContext {
    GovernedAutonomyContext {
        tier,
        delegation_bond_id: bond_id.map(str::to_string),
    }
}

struct CreditBondFixture<'a> {
    signer: &'a Keypair,
    cap: &'a CapabilityToken,
    server: &'a str,
    tool: &'a str,
    disposition: CreditBondDisposition,
    lifecycle_state: CreditBondLifecycleState,
    expires_at: u64,
    runtime_assurance_met: bool,
}

fn make_credit_bond(fixture: CreditBondFixture<'_>) -> SignedCreditBond {
    let now = current_unix_timestamp();
    let report = CreditBondReport {
        schema: CREDIT_BOND_REPORT_SCHEMA.to_string(),
        generated_at: now.saturating_sub(1),
        filters: ExposureLedgerQuery {
            capability_id: Some(fixture.cap.id.clone()),
            agent_subject: Some(fixture.cap.subject.to_hex()),
            tool_server: Some(fixture.server.to_string()),
            tool_name: Some(fixture.tool.to_string()),
            since: None,
            until: None,
            receipt_limit: Some(10),
            decision_limit: Some(5),
        },
        exposure: ExposureLedgerSummary {
            matching_receipts: 1,
            returned_receipts: 1,
            matching_decisions: 0,
            returned_decisions: 0,
            active_decisions: 0,
            superseded_decisions: 0,
            actionable_receipts: 0,
            pending_settlement_receipts: 0,
            failed_settlement_receipts: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            truncated_receipts: false,
            truncated_decisions: false,
        },
        scorecard: CreditScorecardSummary {
            matching_receipts: 1,
            returned_receipts: 1,
            matching_decisions: 0,
            returned_decisions: 0,
            currencies: vec!["USD".to_string()],
            mixed_currency_book: false,
            confidence: CreditScorecardConfidence::High,
            band: CreditScorecardBand::Prime,
            overall_score: 0.95,
            anomaly_count: 0,
            probationary: false,
        },
        disposition: fixture.disposition,
        prerequisites: CreditBondPrerequisites {
            active_facility_required: true,
            active_facility_met: true,
            runtime_assurance_met: fixture.runtime_assurance_met,
            certification_required: false,
            certification_met: true,
            currency_coherent: true,
        },
        support_boundary: CreditBondSupportBoundary {
            autonomy_gating_supported: true,
            ..CreditBondSupportBoundary::default()
        },
        latest_facility_id: Some("facility-1".to_string()),
        terms: None,
        findings: Vec::new(),
    };
    SignedCreditBond::sign(
        CreditBondArtifact {
            schema: CREDIT_BOND_ARTIFACT_SCHEMA.to_string(),
            bond_id: format!("bond-{}-{}-{}", fixture.server, fixture.tool, now),
            issued_at: now.saturating_sub(5),
            expires_at: fixture.expires_at,
            lifecycle_state: fixture.lifecycle_state,
            supersedes_bond_id: None,
            report,
        },
        fixture.signer,
    )
    .unwrap()
}

fn make_governed_approval_token(
    approver: &Keypair,
    subject: &PublicKey,
    intent: &GovernedTransactionIntent,
    request_id: &str,
) -> GovernedApprovalToken {
    let now = current_unix_timestamp();
    GovernedApprovalToken::sign(
        GovernedApprovalTokenBody {
            id: format!("approval-{request_id}"),
            approver: approver.public_key(),
            subject: subject.clone(),
            governed_intent_hash: intent.binding_hash().unwrap(),
            request_id: request_id.to_string(),
            issued_at: now.saturating_sub(1),
            expires_at: now + 300,
            decision: GovernedApprovalDecision::Approved,
        },
        approver,
    )
    .unwrap()
}

// --- Monetary enforcement tests ---

#[test]
fn monetary_denial_exceeds_per_invocation_cap() {
    // Grant max_cost_per_invocation=100; tool server reports actual cost 150 (> cap).
    // The budget check should deny because the worst-case debit (100) passes the cap,
    // but the server reports 150 which exceeds the cap -- actually no: we charge the
    // max_cost_per_invocation as the worst-case DEBIT upfront. The per-invocation check
    // is: cost_units (=max_per) must be <= max_cost_per_invocation. With cost_units=100
    // and max_per=100 that passes. After invocation, server reports 150; we log a warning
    // and set settlement_status=failed. But the invocation is NOT denied before execution.
    //
    // To produce a pre-execution monetary denial, the requested cost must exceed the cap.
    // This happens when we charge cost_units = max_cost_per_invocation but the total budget
    // is already exhausted.
    //
    // Test: accumulated 500 + max_cost_per_invocation=100 exceeds max_total_cost=500 -> deny.
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    let server = MonetaryCostServer::no_cost("cost-srv");
    kernel.register_tool_server(Box::new(server));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 500, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = |id: &str| ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    // 5 invocations: 5 * 100 = 500 total -- all should pass.
    for i in 0..5 {
        let resp = kernel
            .evaluate_tool_call_blocking(&request(&format!("req-{i}")))
            .unwrap();
        assert_eq!(
            resp.verdict,
            Verdict::Allow,
            "invocation {i} should be allowed"
        );
    }

    // 6th invocation would need 600 total, exceeding max_total_cost=500.
    let resp = kernel
        .evaluate_tool_call_blocking(&request("req-6"))
        .unwrap();
    assert_eq!(
        resp.verdict,
        Verdict::Deny,
        "6th invocation should be denied"
    );
}

#[test]
fn monetary_denial_receipt_contains_financial_metadata() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = ToolCallRequest {
        request_id: "req-1".to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    // First invocation uses up the entire budget (100 of 100).
    let _allow = kernel.evaluate_tool_call_blocking(&request).unwrap();

    // Second invocation should be denied.
    let deny_req = ToolCallRequest {
        request_id: "req-2".to_string(),
        ..request
    };
    let resp = kernel.evaluate_tool_call_blocking(&deny_req).unwrap();
    assert_eq!(resp.verdict, Verdict::Deny);

    // Receipt must contain financial metadata.
    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    assert_eq!(financial["settlement_status"], "not_applicable");
    assert!(financial["attempted_cost"].as_u64().is_some());
    assert_eq!(financial["currency"], "USD");
    let attribution = metadata
        .get("attribution")
        .expect("should have 'attribution' key");
    assert_eq!(attribution["grant_index"].as_u64(), Some(0));
    assert!(attribution["subject_key"].as_str().is_some());
}

#[test]
fn monetary_guard_denial_releases_budget_and_records_attempted_cost() {
    use std::sync::{Arc, Mutex};

    struct DenyOnceGuard {
        denied: Arc<Mutex<bool>>,
    }

    impl Guard for DenyOnceGuard {
        fn name(&self) -> &str {
            "deny-once"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            let mut denied = self.denied.lock().unwrap();
            if !*denied {
                *denied = true;
                Ok(Verdict::Deny)
            } else {
                Ok(Verdict::Allow)
            }
        }
    }

    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.add_guard(Box::new(DenyOnceGuard {
        denied: Arc::new(Mutex::new(false)),
    }));
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 100, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = |request_id: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let denied_response = kernel
        .evaluate_tool_call_blocking(&request("req-deny"))
        .unwrap();
    assert_eq!(denied_response.verdict, Verdict::Deny);
    let denied_metadata = denied_response
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let denied_financial = denied_metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(denied_financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(denied_financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(denied_financial["budget_remaining"].as_u64(), Some(100));
    assert_eq!(denied_financial["settlement_status"], "not_applicable");

    let allowed_response = kernel
        .evaluate_tool_call_blocking(&request("req-allow"))
        .unwrap();
    assert_eq!(allowed_response.verdict, Verdict::Allow);
    let allowed_metadata = allowed_response
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let allowed_financial = allowed_metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(allowed_financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(allowed_financial["budget_remaining"].as_u64(), Some(0));
}

#[test]
fn kernel_accepts_optional_payment_adapter_installation() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    assert!(kernel.payment_adapter.is_none());

    kernel.set_payment_adapter(Box::new(StubPaymentAdapter));

    assert!(kernel.payment_adapter.is_some());
}

#[test]
fn monetary_payment_authorization_denial_releases_budget_and_skips_tool_invocation() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_payment_adapter(Box::new(DecliningPaymentAdapter));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-payment-deny".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "tool should not run when payment authorization fails"
    );
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn monetary_prepaid_adapter_sets_payment_reference_on_allow_receipt() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_payment_adapter(Box::new(PrepaidSettledPaymentAdapter));
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-prepaid".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["payment_reference"], "x402_txn_paid");
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(900));
    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.committed_cost_units().unwrap(), 100);
}

#[test]
fn monetary_allow_receipt_contains_financial_metadata() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Server reports actual cost of 75 cents (< max 100).
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(resp.verdict, Verdict::Allow);

    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    // The actual reported cost (75) should be recorded.
    assert_eq!(financial["cost_charged"].as_u64().unwrap(), 75);
    assert_eq!(financial["budget_remaining"].as_u64(), Some(925));
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["currency"], "USD");
    let attribution = metadata
        .get("attribution")
        .expect("should have 'attribution' key");
    assert_eq!(attribution["grant_index"].as_u64(), Some(0));

    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 1);
    assert_eq!(usage.committed_cost_units().unwrap(), 75);
}

#[test]
fn monetary_allow_records_budget_hold_and_append_only_events() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-budget-event-log";
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);

    let hold_id = format!("budget-hold:{request_id}:{}:0", cap.id);
    let authorize_event_id = format!("{hold_id}:authorize");
    let reconcile_event_id = format!("{hold_id}:reconcile");
    let events = kernel
        
        .budget_store
        .list_mutation_events(10, Some(&cap.id), Some(0))
        .unwrap();

    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event_id, authorize_event_id);
    assert_eq!(events[0].hold_id.as_deref(), Some(hold_id.as_str()));
    assert_eq!(events[0].allowed, Some(true));
    assert_eq!(events[0].exposure_units, 100);
    assert_eq!(events[1].event_id, reconcile_event_id);
    assert_eq!(events[1].hold_id.as_deref(), Some(hold_id.as_str()));
    assert_eq!(events[1].realized_spend_units, 75);
    assert_eq!(events[1].total_cost_exposed_after, 0);
    assert_eq!(events[1].total_cost_realized_spend_after, 75);
}

#[test]
fn governed_monetary_allow_receipt_contains_approval_metadata() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-allow";
    let intent = make_governed_intent(
        "intent-governed-allow",
        "cost-srv",
        "compute",
        "settle approved invoice",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("allow receipt should carry metadata");
    let governed = metadata
        .get("governed_transaction")
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["intent_hash"], intent.binding_hash().unwrap());
    assert_eq!(governed["purpose"], intent.purpose);
    assert_eq!(governed["approval"]["approved"], true);
    assert_eq!(
        governed["approval"]["approver_key"],
        kernel.config.keypair.public_key().to_hex()
    );

    let financial = metadata
        .get("financial")
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(75));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(925));
}

#[test]
fn governed_monetary_allow_receipt_preserves_metered_billing_quote_context() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-metered-allow";
    let mut intent = make_governed_intent(
        "intent-governed-metered-allow",
        "cost-srv",
        "compute",
        "execute governed metered compute",
        100,
        "USD",
    );
    intent.metered_billing = Some(make_metered_billing_context(
        "quote-governed-1",
        "billing.chio",
        12,
        "USD",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed["metered_billing"]["quote"]["quoteId"],
        serde_json::Value::String("quote-governed-1".to_string())
    );
    assert_eq!(
        governed["metered_billing"]["quote"]["provider"],
        serde_json::Value::String("billing.chio".to_string())
    );
    assert_eq!(
        governed["metered_billing"]["settlementMode"],
        serde_json::Value::String("allow_then_settle".to_string())
    );
    assert_eq!(
        governed["metered_billing"]["maxBilledUnits"].as_u64(),
        Some(16)
    );
    assert!(governed["metered_billing"]["usageEvidence"].is_null());
}

#[test]
fn governed_request_rejects_empty_metered_billing_provider() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-metered-invalid";
    let mut intent = make_governed_intent(
        "intent-governed-metered-invalid",
        "cost-srv",
        "compute",
        "execute governed metered compute",
        100,
        "USD",
    );
    intent.metered_billing = Some(make_metered_billing_context(
        "quote-governed-2",
        "",
        8,
        "USD",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("metered billing provider must not be empty")));

    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn governed_monetary_allow_receipt_preserves_call_chain_context() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-allow";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-allow",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-ops-1",
        "req-parent-1",
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed["call_chain"]["chainId"],
        serde_json::Value::String("chain-ops-1".to_string())
    );
    assert_eq!(
        governed["call_chain"]["parentRequestId"],
        serde_json::Value::String("req-parent-1".to_string())
    );
    assert_eq!(
        governed["intent_hash"],
        serde_json::Value::String(intent.binding_hash().unwrap())
    );
}

#[test]
fn governed_call_chain_receipt_observes_local_parent_receipt_linkage() {
    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let prior_response = kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "req-local-parent-receipt",
            &capability,
            "delegate",
            "srv-echo",
            serde_json::json!({ "stage": "parent" }),
        ))
        .unwrap();

    let request_id = "req-governed-local-parent-receipt";
    let intent = GovernedTransactionIntent {
        id: "intent-local-parent-receipt".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(chio_core::capability::GovernedCallChainContext {
            chain_id: "chain-local-parent-receipt".to_string(),
            parent_request_id: "req-upstream-local".to_string(),
            parent_receipt_id: Some(prior_response.receipt.id.clone()),
            origin_subject: "origin-subject".to_string(),
            delegator_subject: "delegator-subject".to_string(),
        }),
        autonomy: None,
        context: None,
    };

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "child" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["local_parent_receipt_linkage"])
    );
}

#[test]
fn governed_call_chain_receipt_observes_capability_lineage_subjects() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-capability-lineage");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = ChioKernel::new(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_scope = make_scope(vec![root_grant.clone()]);
    let root_capability = make_capability(&kernel, &root_kp, root_scope.clone(), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let delegated_capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-governed-child".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-echo", "delegate")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![make_delegation_link(
                &root_capability.id,
                &root_kp,
                &child_kp,
                current_unix_timestamp(),
            )],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let request_id = "req-governed-capability-lineage";
    let root_subject = root_kp.public_key().to_hex();
    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-capability-lineage".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "continue delegated workflow".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(chio_core::capability::GovernedCallChainContext {
                    chain_id: "chain-capability-lineage".to_string(),
                    parent_request_id: "req-upstream-capability".to_string(),
                    parent_receipt_id: None,
                    origin_subject: root_subject.clone(),
                    delegator_subject: root_subject,
                }),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["capability_delegator_subject", "capability_origin_subject"])
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_call_chain_receipt_verifies_signed_upstream_delegator_proof() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-upstream-proof");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = ChioKernel::new(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_capability = make_capability(&kernel, &root_kp, make_scope(vec![root_grant]), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let delegated_capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-governed-upstream-proof".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-echo", "delegate")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![make_delegation_link(
                &root_capability.id,
                &root_kp,
                &child_kp,
                current_unix_timestamp(),
            )],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let root_subject = root_kp.public_key().to_hex();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-upstream-proof".to_string(),
        parent_request_id: "req-upstream-proof-parent".to_string(),
        parent_receipt_id: Some("rc-upstream-proof-parent".to_string()),
        origin_subject: root_subject.clone(),
        delegator_subject: root_subject,
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-upstream-proof".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with signed upstream provenance".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: Some(serde_json::json!({ "workflow": "delegated-proof" })),
    };
    let upstream_proof =
        make_governed_upstream_call_chain_proof(&root_kp, &child_kp.public_key(), &call_chain);
    attach_governed_upstream_call_chain_proof(&mut intent, &upstream_proof);

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-upstream-proof".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "verified");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!([
            "capability_delegator_subject",
            "capability_origin_subject",
            "upstream_delegator_proof"
        ])
    );
    assert_eq!(
        governed["call_chain"]["upstreamProof"]["signer"],
        serde_json::Value::String(root_kp.public_key().to_hex())
    );
    assert_eq!(
        governed["call_chain"]["upstreamProof"]["subject"],
        serde_json::Value::String(child_kp.public_key().to_hex())
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_call_chain_receipt_follows_asserted_observed_verified_execution_order() {
    let mut asserted_kernel = ChioKernel::new(make_config());
    let asserted_agent_kp = make_keypair();
    asserted_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));
    let asserted_capability = make_capability(
        &asserted_kernel,
        &asserted_agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let asserted_response = asserted_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-asserted-order".to_string(),
            capability: asserted_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: asserted_agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "asserted" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-asserted-order".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "preserve caller-supplied delegated context".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(make_governed_call_chain_context(
                    "chain-asserted-order",
                    "req-upstream-asserted-order",
                )),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();
    let asserted_governed = asserted_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("asserted receipt should carry governed transaction metadata");
    assert_eq!(asserted_governed["call_chain"]["evidenceClass"], "asserted");
    assert!(asserted_governed["call_chain"]["evidenceSources"].is_null());
    assert!(asserted_governed["call_chain"]["upstreamProof"].is_null());

    let mut observed_kernel = ChioKernel::new(make_config());
    let observed_agent_kp = make_keypair();
    observed_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));
    let observed_capability = make_capability(
        &observed_kernel,
        &observed_agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let parent_response = observed_kernel
        .evaluate_tool_call_blocking(&make_request_with_arguments(
            "req-observed-parent-order",
            &observed_capability,
            "delegate",
            "srv-echo",
            serde_json::json!({ "stage": "parent" }),
        ))
        .unwrap();
    let observed_response = observed_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-observed-order".to_string(),
            capability: observed_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: observed_agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "observed" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-observed-order".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "upgrade local delegated context from receipt linkage".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(GovernedCallChainContext {
                    chain_id: "chain-observed-order".to_string(),
                    parent_request_id: "req-upstream-observed-order".to_string(),
                    parent_receipt_id: Some(parent_response.receipt.id.clone()),
                    origin_subject: "subject-origin".to_string(),
                    delegator_subject: "subject-delegator".to_string(),
                }),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();
    let observed_governed = observed_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("observed receipt should carry governed transaction metadata");
    assert_eq!(observed_governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        observed_governed["call_chain"]["evidenceSources"],
        serde_json::json!(["local_parent_receipt_linkage"])
    );
    assert!(observed_governed["call_chain"]["upstreamProof"].is_null());

    let path = unique_receipt_db_path("chio-kernel-call-chain-execution-order");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut verified_kernel = ChioKernel::new(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    verified_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_capability = make_capability(
        &verified_kernel,
        &root_kp,
        make_scope(vec![root_grant]),
        300,
    );
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    verified_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let delegated_capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-governed-execution-order".to_string(),
            issuer: verified_kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-echo", "delegate")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![make_delegation_link(
                &root_capability.id,
                &root_kp,
                &child_kp,
                current_unix_timestamp(),
            )],
        },
        &verified_kernel.config.keypair,
    )
    .unwrap();

    let root_subject = root_kp.public_key().to_hex();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-verified-order".to_string(),
        parent_request_id: "req-upstream-verified-order".to_string(),
        parent_receipt_id: Some("rc-upstream-verified-order".to_string()),
        origin_subject: root_subject.clone(),
        delegator_subject: root_subject,
    };
    let mut verified_intent = GovernedTransactionIntent {
        id: "intent-verified-order".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "upgrade delegated context with signed upstream provenance".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
    };
    let upstream_proof =
        make_governed_upstream_call_chain_proof(&root_kp, &child_kp.public_key(), &call_chain);
    attach_governed_upstream_call_chain_proof(&mut verified_intent, &upstream_proof);

    let verified_response = verified_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-verified-order".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "verified" }),
            dpop_proof: None,
            governed_intent: Some(verified_intent),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();
    let verified_governed = verified_response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("verified receipt should carry governed transaction metadata");
    assert_eq!(verified_governed["call_chain"]["evidenceClass"], "verified");
    assert_eq!(
        verified_governed["call_chain"]["evidenceSources"],
        serde_json::json!([
            "capability_delegator_subject",
            "capability_origin_subject",
            "upstream_delegator_proof"
        ])
    );
    assert_eq!(
        verified_governed["call_chain"]["upstreamProof"]["signer"],
        serde_json::Value::String(root_kp.public_key().to_hex())
    );

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_request_rejects_upstream_call_chain_proof_subject_mismatch() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-upstream-proof-subject-mismatch");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = ChioKernel::new(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_capability = make_capability(&kernel, &root_kp, make_scope(vec![root_grant]), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let delegated_capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-governed-upstream-proof-subject-mismatch".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-echo", "delegate")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![make_delegation_link(
                &root_capability.id,
                &root_kp,
                &child_kp,
                current_unix_timestamp(),
            )],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let root_subject = root_kp.public_key().to_hex();
    let call_chain = GovernedCallChainContext {
        chain_id: "chain-upstream-proof-subject-mismatch".to_string(),
        parent_request_id: "req-upstream-proof-subject-parent".to_string(),
        parent_receipt_id: Some("rc-upstream-proof-subject-parent".to_string()),
        origin_subject: root_subject.clone(),
        delegator_subject: root_subject,
    };
    let wrong_subject = make_keypair();
    let mut intent = GovernedTransactionIntent {
        id: "intent-upstream-proof-subject-mismatch".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with mismatched proof subject".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: Some(serde_json::json!({ "workflow": "delegated-proof" })),
    };
    let upstream_proof =
        make_governed_upstream_call_chain_proof(&root_kp, &wrong_subject.public_key(), &call_chain);
    attach_governed_upstream_call_chain_proof(&mut intent, &upstream_proof);

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-upstream-proof-subject-mismatch".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("call_chain upstream proof subject")
            && reason.contains("capability subject")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_request_rejects_call_chain_delegator_subject_that_conflicts_with_capability_lineage() {
    let path = unique_receipt_db_path("chio-kernel-call-chain-delegator-mismatch");
    let seed_store = SqliteReceiptStore::open(&path).unwrap();
    let mut kernel = ChioKernel::new(make_config());
    let root_kp = make_keypair();
    let child_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let mut root_grant = make_grant("srv-echo", "delegate");
    root_grant.operations.push(Operation::Delegate);
    let root_capability = make_capability(&kernel, &root_kp, make_scope(vec![root_grant]), 300);
    seed_store
        .record_capability_snapshot(&root_capability, None)
        .unwrap();
    drop(seed_store);
    kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let delegated_capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-governed-child-mismatch".to_string(),
            issuer: kernel.config.keypair.public_key(),
            subject: child_kp.public_key(),
            scope: make_scope(vec![make_grant("srv-echo", "delegate")]),
            issued_at: current_unix_timestamp(),
            expires_at: current_unix_timestamp() + 300,
            delegation_chain: vec![make_delegation_link(
                &root_capability.id,
                &root_kp,
                &child_kp,
                current_unix_timestamp(),
            )],
        },
        &kernel.config.keypair,
    )
    .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-capability-lineage-deny".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "delegated" }),
            dpop_proof: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-capability-lineage-deny".to_string(),
                server_id: "srv-echo".to_string(),
                tool_name: "delegate".to_string(),
                purpose: "continue delegated workflow".to_string(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: Some(chio_core::capability::GovernedCallChainContext {
                    chain_id: "chain-capability-lineage-deny".to_string(),
                    parent_request_id: "req-upstream-capability-deny".to_string(),
                    parent_receipt_id: None,
                    origin_subject: root_kp.public_key().to_hex(),
                    delegator_subject: "subject-wrong".to_string(),
                }),
                autonomy: None,
                context: None,
            }),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("call_chain.delegator_subject")
            && reason.contains("validated capability delegation source")
    }));

    let _ = std::fs::remove_file(path);
}

#[test]
fn governed_call_chain_receipt_observes_session_parent_request_lineage() {
    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = make_keypair();
    kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let capability = make_capability(
        &kernel,
        &agent_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![capability.clone()]);
    kernel.activate_session(&session_id).unwrap();

    let parent_context = make_operation_context(
        &session_id,
        "req-parent-session-lineage",
        &agent_kp.public_key().to_hex(),
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();

    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };
    let response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-child-session-lineage".to_string(),
                capability,
                tool_name: "delegate".to_string(),
                server_id: "srv-echo".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({ "stage": "child" }),
                dpop_proof: None,
                governed_intent: Some(GovernedTransactionIntent {
                    id: "intent-session-lineage".to_string(),
                    server_id: "srv-echo".to_string(),
                    tool_name: "delegate".to_string(),
                    purpose: "continue nested delegated workflow".to_string(),
                    max_amount: None,
                    commerce: None,
                    metered_billing: None,
                    runtime_attestation: None,
                    call_chain: Some(chio_core::capability::GovernedCallChainContext {
                        chain_id: "chain-session-lineage".to_string(),
                        parent_request_id: parent_context.request_id.to_string(),
                        parent_receipt_id: None,
                        origin_subject: "origin-subject".to_string(),
                        delegator_subject: "delegator-subject".to_string(),
                    }),
                    autonomy: None,
                    context: None,
                }),
                approval_token: None,
                model_metadata: None,
            federated_origin_kernel_id: None,
            },
            &mut client,
        )
        .unwrap();

    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["session_parent_request_lineage"])
    );
}

#[test]
fn cross_kernel_continuation_token_verifies_parent_receipt_hash_and_session_anchor() {
    let parent_kernel = ChioKernel::new(make_config());
    let mut child_config = make_config();
    child_config.ca_public_keys.push(parent_kernel.public_key());
    let mut child_kernel = ChioKernel::new(child_config);
    let child_kp = make_keypair();
    child_kernel.register_tool_server(Box::new(EchoServer::new("srv-echo", vec!["delegate"])));

    let delegated_capability = make_capability(
        &child_kernel,
        &child_kp,
        make_scope(vec![make_grant("srv-echo", "delegate")]),
        300,
    );

    let parent_session_id = parent_kernel.open_session(child_kp.public_key().to_hex(), Vec::new());
    parent_kernel.activate_session(&parent_session_id).unwrap();
    parent_kernel
        .with_session_mut(&parent_session_id, |session| {
            assert!(
                session.set_auth_context(SessionAuthContext::streamable_http_static_bearer(
                    "static-bearer:parent",
                    "token-parent",
                    Some("https://parent.example".to_string()),
                ))
                .0
            );
            Ok(())
        })
        .unwrap();
    let parent_anchor = parent_kernel
        .with_session(&parent_session_id, |session| {
            Ok(session.session_anchor().reference())
        })
        .unwrap();

    let parent_receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "rc-parent-continuation".to_string(),
            timestamp: current_unix_timestamp(),
            capability_id: "cap-parent-continuation".to_string(),
            tool_server: "srv-echo".to_string(),
            tool_name: "delegate".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({ "stage": "parent" }))
                .unwrap(),
            decision: Decision::Allow,
            content_hash: chio_core::crypto::sha256_hex(br#"{"ok":true}"#),
            policy_hash: "policy-parent-continuation".to_string(),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "lineageReferences": {
                    "sessionAnchorId": parent_anchor.session_anchor_id.clone(),
                    "sessionAnchorHash": parent_anchor.session_anchor_hash.clone(),
                }
            })),
            trust_level: chio_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: parent_kernel.public_key(),
        },
        &parent_kernel.config.keypair,
    )
    .unwrap();
    let parent_receipt_hash = chio_core::crypto::sha256_hex(
        &chio_core::canonical::canonical_json_bytes(&parent_receipt).unwrap(),
    );
    child_kernel.record_chio_receipt(&parent_receipt).unwrap();

    let call_chain = GovernedCallChainContext {
        chain_id: "chain-cross-kernel-continuation".to_string(),
        parent_request_id: "req-parent-continuation".to_string(),
        parent_receipt_id: Some(parent_receipt.id.clone()),
        origin_subject: "subject-origin".to_string(),
        delegator_subject: "subject-delegator".to_string(),
    };
    let mut intent = GovernedTransactionIntent {
        id: "intent-continuation".to_string(),
        server_id: "srv-echo".to_string(),
        tool_name: "delegate".to_string(),
        purpose: "continue delegated workflow with continuation token".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: Some(call_chain.clone()),
        autonomy: None,
        context: None,
    };
    let continuation_token =
        make_governed_call_chain_continuation_token(GovernedCallChainContinuationTokenFixture {
            signer: &parent_kernel.config.keypair,
            subject: &child_kp.public_key(),
            call_chain: &call_chain,
            parent_session_anchor: parent_anchor.clone(),
            parent_receipt_hash: &parent_receipt_hash,
            server_id: "srv-echo",
            tool_name: "delegate",
            governed_intent_hash: None,
        });
    attach_governed_call_chain_continuation_token(&mut intent, &continuation_token);

    let response = child_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-child-continuation".to_string(),
            capability: delegated_capability,
            tool_name: "delegate".to_string(),
            server_id: "srv-echo".to_string(),
            agent_id: child_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "stage": "child" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "cross-kernel continuation token should allow; reason: {:?}",
        response.reason
    );
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["call_chain"]["evidenceClass"], "observed");
    assert_eq!(
        governed["call_chain"]["continuationTokenId"],
        serde_json::json!("continuation-token-1")
    );
    assert_eq!(
        governed["call_chain"]["sessionAnchorId"],
        serde_json::json!(parent_anchor.session_anchor_id.clone())
    );
    assert_eq!(
        governed["call_chain"]["evidenceSources"],
        serde_json::json!(["local_parent_receipt_linkage"])
    );
}

#[test]
fn governed_request_rejects_self_referential_call_chain_parent_request() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-invalid";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-invalid",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    intent.call_chain = Some(make_governed_call_chain_context("chain-ops-2", request_id));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_ref().is_some_and(|reason| {
        reason.contains("call_chain.parent_request_id must not equal the current request_id")
    }));
}

#[test]
fn governed_request_rejects_empty_call_chain_chain_id() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-call-chain-empty";
    let mut intent = make_governed_intent(
        "intent-governed-call-chain-empty",
        "cost-srv",
        "compute",
        "execute delegated governed compute",
        100,
        "USD",
    );
    let mut call_chain = make_governed_call_chain_context("chain-ops-3", "req-parent-3");
    call_chain.chain_id.clear();
    intent.call_chain = Some(call_chain);
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_ref()
        .is_some_and(|reason| reason.contains("call_chain.chain_id must not be empty")));
}

#[test]
fn governed_monetary_denial_without_required_runtime_assurance_releases_budget() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Attested,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-deny";
    let intent = make_governed_intent(
        "intent-governed-assurance-deny",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("runtime attestation tier")),
        "denial should explain the missing runtime attestation"
    );
    let financial = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("financial"))
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn governed_request_denies_unverified_attestation_when_runtime_assurance_is_required() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Attested,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-allow";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-allow",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.reason.as_deref().is_some_and(|reason| {
            reason.contains("runtime attestation tier 'Attested' required by grant")
                && reason.contains("did not cross a local verified trust boundary")
        }),
        "denial should explain that raw attestation did not satisfy the local verified boundary"
    );
}

#[test]
fn governed_monetary_allow_omits_unverified_runtime_assurance_metadata_when_optional() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-optional";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-optional",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_runtime_attestation(RuntimeAssuranceTier::Attested));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(
        governed.get("runtime_assurance"),
        None,
        "optional raw attestation should not be emitted as verified runtime authority"
    );
}

#[test]
fn governed_request_denies_conflicting_workload_identity_binding() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-workload-identity-deny";
    let mut intent = make_governed_intent(
        "intent-governed-workload-identity-deny",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(chio_core::capability::RuntimeAttestationEvidence {
        schema: "chio.runtime-attestation.enterprise-verifier.json.v1".to_string(),
        verifier: "https://attest.chio.example".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: current_unix_timestamp().saturating_sub(1),
        expires_at: current_unix_timestamp() + 300,
        evidence_sha256: "digest-invalid-workload".to_string(),
        runtime_identity: Some("spiffe://chio/runtime/test".to_string()),
        workload_identity: Some(chio_core::capability::WorkloadIdentity {
            scheme: chio_core::capability::WorkloadIdentityScheme::Spiffe,
            credential_kind: chio_core::capability::WorkloadCredentialKind::X509Svid,
            uri: "spiffe://other/runtime/test".to_string(),
            trust_domain: "other".to_string(),
            path: "/runtime/test".to_string(),
        }),
        claims: Some(serde_json::json!({
            "enterpriseVerifier": {
                "attestationType": "enterprise_confidential_vm",
                "hardwareModel": "AMD_SEV_SNP",
                "secureBoot": "enabled",
                "digest": "sha384:digest-invalid-workload"
            }
        })),
    });
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1002" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("workload identity is invalid")),
        "denial should explain the workload-identity binding failure"
    );
}

#[test]
fn governed_monetary_allow_rebinds_trusted_attestation_to_verified() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Verified,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-verified";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-verified",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1003" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
    assert_eq!(governed["runtime_assurance"]["verifierFamily"], "azure_maa");
    assert_eq!(
        governed["runtime_assurance"]["verifier"],
        "https://maa.contoso.test"
    );
    assert_eq!(
        governed["runtime_assurance"]["workloadIdentity"]["trustDomain"],
        "chio"
    );
}

#[test]
fn governed_request_denies_untrusted_attestation_when_trust_policy_is_configured() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-untrusted";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-untrusted",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    let mut attestation = make_trusted_azure_runtime_attestation();
    attestation.verifier = "https://maa.untrusted.test".to_string();
    intent.runtime_attestation = Some(attestation);
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1004" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response.reason.as_deref().is_some_and(|reason| {
            reason.contains("rejected by local verification boundary")
                && reason.contains("did not match any trusted verifier rule")
        }),
        "denial should explain the local verification-boundary mismatch"
    );
}

#[test]
fn governed_monetary_allow_rebinds_google_attestation_to_verified() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Verified,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-google-verified";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-google-verified",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_google_runtime_attestation());
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1005" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
    assert_eq!(
        governed["runtime_assurance"]["verifierFamily"],
        "google_attestation"
    );
}

#[test]
fn governed_monetary_allow_rebinds_nitro_attestation_to_verified() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_runtime_assurance(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        RuntimeAssuranceTier::Verified,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-assurance-nitro-verified";
    let mut intent = make_governed_intent(
        "intent-governed-assurance-nitro-verified",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_nitro_runtime_attestation());
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1006" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
    assert_eq!(governed["runtime_assurance"]["verifierFamily"], "aws_nitro");
    assert_eq!(
        governed["runtime_assurance"]["verifier"],
        "https://nitro.aws.example"
    );
    assert_eq!(
        governed["runtime_assurance"]["evidenceSha256"],
        "digest-nitro-attestation"
    );
}

#[test]
fn governed_request_denies_delegated_autonomy_without_bond_attachment() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Delegated,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-autonomy-missing-bond";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-missing-bond",
        "cost-srv",
        "compute",
        "execute delegated bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-1",
        "req-parent-1",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Delegated,
        None,
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-1" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| { reason.contains("requires a delegation bond attachment") }));
}

#[test]
fn governed_request_denies_autonomous_tier_with_weak_runtime_assurance() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attested_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Autonomous,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-autonomy-weak-assurance";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-weak-assurance",
        "cost-srv",
        "compute",
        "execute autonomous bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-2",
        "req-parent-2",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Autonomous,
        Some("bond-required"),
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-2" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response.reason.as_deref().is_some_and(|reason| {
        reason.contains("runtime attestation tier 'Attested'")
            && reason.contains("below required 'Verified'")
    }));
}

#[test]
fn governed_request_denies_delegated_autonomy_with_expired_bond() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let path = unique_receipt_db_path("kernel-bond-expired");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Delegated,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let bond = make_credit_bond(CreditBondFixture {
        signer: &kernel.config.keypair,
        cap: &cap,
        server: "cost-srv",
        tool: "compute",
        disposition: CreditBondDisposition::Hold,
        lifecycle_state: CreditBondLifecycleState::Active,
        expires_at: current_unix_timestamp().saturating_sub(1),
        runtime_assurance_met: true,
    });
    let bond_id = bond.body.bond_id.clone();
    store
        .record_credit_bond(&bond, CreditBondLifecycleState::Active)
        .unwrap();
    kernel.set_receipt_store(Box::new(store));

    let request_id = "req-governed-autonomy-expired-bond";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-expired-bond",
        "cost-srv",
        "compute",
        "execute delegated bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-3",
        "req-parent-3",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Delegated,
        Some(&bond_id),
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-3" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(response
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("is expired")));
}

#[test]
fn governed_request_allows_delegated_autonomy_with_active_bond_and_receipt_metadata() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_attestation_trust_policy(make_attestation_trust_policy());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let path = unique_receipt_db_path("kernel-bond-active");
    let store = SqliteReceiptStore::open(&path).unwrap();

    let grant = with_minimum_autonomy_tier(
        make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50),
        GovernedAutonomyTier::Delegated,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let bond = make_credit_bond(CreditBondFixture {
        signer: &kernel.config.keypair,
        cap: &cap,
        server: "cost-srv",
        tool: "compute",
        disposition: CreditBondDisposition::Hold,
        lifecycle_state: CreditBondLifecycleState::Active,
        expires_at: current_unix_timestamp() + 300,
        runtime_assurance_met: true,
    });
    let bond_id = bond.body.bond_id.clone();
    store
        .record_credit_bond(&bond, CreditBondLifecycleState::Active)
        .unwrap();
    kernel.set_receipt_store(Box::new(store));

    let request_id = "req-governed-autonomy-allow";
    let mut intent = make_governed_intent(
        "intent-governed-autonomy-allow",
        "cost-srv",
        "compute",
        "execute delegated bonded payout",
        100,
        "USD",
    );
    intent.runtime_attestation = Some(make_trusted_azure_runtime_attestation());
    intent.call_chain = Some(make_governed_call_chain_context(
        "chain-bond-4",
        "req-parent-4",
    ));
    intent.autonomy = Some(make_governed_autonomy_context(
        GovernedAutonomyTier::Delegated,
        Some(&bond_id),
    ));
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-bond-4" }),
            dpop_proof: None,
            governed_intent: Some(intent),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let governed = response
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("governed_transaction"))
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["autonomy"]["tier"], "delegated");
    assert_eq!(governed["autonomy"]["delegationBondId"], bond_id);
    assert_eq!(governed["runtime_assurance"]["tier"], "verified");
}

#[test]
fn sibling_sum_denial_reverses_pre_execution_monetary_charge() {
    let fixture = make_sibling_sum_monetary_fixture("sibling-sum-rollback");
    let kernel = fixture.kernel;

    let allow_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-sibling-sum-rollback-a".to_string(),
            capability: fixture.child_a.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_a_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    assert_eq!(allow_response.verdict, Verdict::Allow);

    let deny_response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-sibling-sum-rollback-b".to_string(),
            capability: fixture.child_b.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_b_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));

    let metadata = deny_response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry rollback metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1_000));

    let usage = kernel
        .budget_store
        .get_usage(&fixture.child_b.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn nested_hosted_sibling_sum_denial_reverses_pre_execution_monetary_charge() {
    let fixture = make_sibling_sum_monetary_fixture("nested-sibling-sum-rollback");
    let kernel = fixture.kernel;
    let session_id = kernel.open_session("nested-parent-agent".to_string(), Vec::new());
    kernel.activate_session(&session_id).unwrap();
    let parent_context = make_operation_context(
        &session_id,
        "req-nested-sibling-sum-parent",
        "nested-parent-agent",
    );
    kernel
        .begin_session_request(&parent_context, OperationKind::ToolCall, true)
        .unwrap();
    let mut client = MockNestedFlowClient {
        roots: Vec::new(),
        sampled_message: CreateMessageResult {
            role: "assistant".to_string(),
            content: serde_json::json!({ "type": "text", "text": "unused" }),
            model: "unused".to_string(),
            stop_reason: None,
        },
        elicited_content: make_elicited_content(),
        cancel_parent_on_create_message: false,
        cancel_child_on_create_message: false,
        completed_elicitation_ids: Vec::new(),
        resource_updates: Vec::new(),
        resources_list_changed_count: 0,
    };

    let allow_response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-nested-sibling-sum-rollback-a".to_string(),
                capability: fixture.child_a.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: fixture.child_a_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            },
            &mut client,
        )
        .unwrap();
    assert_eq!(allow_response.verdict, Verdict::Allow);

    let deny_response = kernel
        .evaluate_tool_call_with_nested_flow_client(
            &parent_context,
            &ToolCallRequest {
                request_id: "req-nested-sibling-sum-rollback-b".to_string(),
                capability: fixture.child_b.clone(),
                tool_name: "compute".to_string(),
                server_id: "cost-srv".to_string(),
                agent_id: fixture.child_b_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            },
            &mut client,
        )
        .unwrap();
    assert_eq!(deny_response.verdict, Verdict::Deny);
    assert!(deny_response.reason.as_deref().is_some_and(|reason| {
        reason.contains("sibling-sum") || reason.contains("sibling sum")
    }));

    let metadata = deny_response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry rollback metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1_000));

    let usage = kernel
        .budget_store
        .get_usage(&fixture.child_b.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn hosted_named_remote_without_fresh_peer_fails_before_dispatch() {
    let fixture = make_sibling_sum_monetary_fixture("missing-remote-peer");
    let kernel = fixture.kernel;

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-missing-remote-peer".to_string(),
            capability: fixture.child_a.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: fixture.child_a_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: Some("stale-or-missing-peer".to_string()),
        })
        .expect("missing peer must produce a structured Deny response");

    // The kernel returns a signed Deny ToolCallResponse for the
    // named-peer-not-pinned-fresh case BEFORE dispatch, instead of
    // propagating an Err out of `evaluate_tool_call_blocking`. The Err
    // propagation form was unsafe: callers could miss it and the
    // receipt-store invariant would not be satisfied.
    assert_eq!(response.verdict, Verdict::Deny);
    let reason = response.reason.unwrap_or_default();
    assert!(
        reason.contains("receipt negotiation downgrade")
            || reason.contains("not pinned fresh"),
        "unexpected deny reason: {reason}"
    );

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn portable_subject_denial_does_not_consume_sibling_budget() {
    let fixture = make_sibling_sum_monetary_fixture("portable-subject-deny-budget");
    let kernel = fixture.kernel;
    let clock = chio_kernel_core::FixedClock::new(current_unix_timestamp());
    let guards: [&dyn chio_kernel_core::Guard; 0] = [];

    let wrong_subject = chio_kernel_core::PortableToolCallRequest {
        request_id: "req-portable-wrong-subject".to_string(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: fixture.child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
    };
    let denied = kernel.evaluate_portable_verdict(
        &fixture.child_a,
        &wrong_subject,
        &guards,
        &clock,
        None,
    );
    assert_eq!(denied.verdict, chio_kernel_core::Verdict::Deny);

    let valid_sibling = chio_kernel_core::PortableToolCallRequest {
        request_id: "req-portable-valid-sibling".to_string(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: fixture.child_b_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
    };
    let allowed = kernel.evaluate_portable_verdict(
        &fixture.child_b,
        &valid_sibling,
        &guards,
        &clock,
        None,
    );
    assert_eq!(allowed.verdict, chio_kernel_core::Verdict::Allow);

    let _ = std::fs::remove_file(fixture.path);
}

#[test]
fn governed_monetary_denial_without_approval_releases_budget_and_records_intent() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let intent = make_governed_intent(
        "intent-governed-deny",
        "cost-srv",
        "compute",
        "execute governed payout",
        100,
        "USD",
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-governed-deny".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "invoice_id": "inv-1001" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("approval token required")),
        "denial should explain the missing approval token"
    );

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry metadata");
    let governed = metadata
        .get("governed_transaction")
        .expect("deny receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert!(governed["approval"].is_null());

    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    assert_eq!(financial["settlement_status"], "not_applicable");

    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn governed_monetary_incomplete_receipt_keeps_financial_and_governed_metadata() {
    let mut config = make_monetary_config();
    config.max_stream_total_bytes = 1;

    let mut kernel = ChioKernel::new(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(StreamingServer {
        id: "stream".to_string(),
        chunks: vec![serde_json::json!({ "chunk": "governed-stream-payload" })],
    }));

    let grant = make_governed_monetary_grant("stream", "stream_file", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-incomplete";
    let intent = make_governed_intent(
        "intent-governed-incomplete",
        "stream",
        "stream_file",
        "stream governed artifact",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "stream_file".to_string(),
            server_id: "stream".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "path": "/tmp/governed.txt" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(matches!(
        response.terminal_state,
        OperationTerminalState::Incomplete { .. }
    ));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("incomplete receipt should carry metadata");
    let governed = metadata
        .get("governed_transaction")
        .expect("incomplete receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["approval"]["approved"], true);

    let financial = metadata
        .get("financial")
        .expect("incomplete receipt should retain financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(900));

    let stream = match response
        .output
        .expect("partial stream output should be preserved")
    {
        ToolCallOutput::Stream(stream) => Some(stream),
        ToolCallOutput::Value(_) => None,
    }
    .expect("expected streamed partial output");
    assert!(
        stream.chunks.is_empty(),
        "truncated stream should drop chunks once byte limit is exceeded"
    );
}

#[test]
fn governed_x402_prepaid_flow_records_governed_authorization_and_receipt_metadata() {
    let (url, request_rx, handle) = spawn_payment_test_server(
        200,
        serde_json::json!({
            "authorizationId": "x402_txn_governed",
            "settled": true,
            "metadata": {
                "network": "base",
                "merchant": "pay-per-api"
            }
        }),
    );

    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        X402PaymentAdapter::new(url)
            .with_bearer_token("bridge-token")
            .with_timeout(Duration::from_secs(2)),
    ));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-x402";
    let intent = make_governed_intent(
        "intent-governed-x402",
        "cost-srv",
        "compute",
        "purchase premium API result",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "dataset-pro" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token.clone()),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "tool should run after x402 authorization succeeds"
    );

    let request = request_rx.recv().expect("request should be captured");
    assert!(request.starts_with("POST /authorize HTTP/1.1"));
    assert!(request.contains("Authorization: Bearer bridge-token"));
    assert!(request.contains("\"amountUnits\":100"));
    assert!(request.contains("\"reference\":\"req-governed-x402\""));
    assert!(request.contains("\"governed\":{"));
    assert!(request.contains("\"intentId\":\"intent-governed-x402\""));
    assert!(request.contains("\"approvalTokenId\":\"approval-req-governed-x402\""));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("allow receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["payment_reference"], "x402_txn_governed");
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["cost_charged"].as_u64(), Some(100));
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "x402_txn_governed"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "x402"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["merchant"],
        "pay-per-api"
    );

    let governed = metadata
        .get("governed_transaction")
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["approval"]["token_id"], approval_token.id);

    handle.join().expect("server thread should exit cleanly");
}

#[test]
fn governed_x402_authorization_failure_denies_before_tool_execution() {
    let (url, request_rx, handle) = spawn_payment_test_server(
        402,
        serde_json::json!({
            "error": "insufficient funds"
        }),
    );

    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        X402PaymentAdapter::new(url).with_timeout(Duration::from_secs(2)),
    ));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "cost-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_monetary_grant("cost-srv", "compute", 100, 1000, "USD", 50);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-x402-deny";
    let intent = make_governed_intent(
        "intent-governed-x402-deny",
        "cost-srv",
        "compute",
        "purchase premium API result",
        100,
        "USD",
    );
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "dataset-pro" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("payment authorization failed")),
        "denial should explain the x402 authorization failure"
    );
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "tool should not run when x402 authorization fails"
    );

    let request = request_rx.recv().expect("request should be captured");
    assert!(request.contains("\"intentId\":\"intent-governed-x402-deny\""));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(1000));
    assert_eq!(financial["settlement_status"], "not_applicable");

    let governed = metadata
        .get("governed_transaction")
        .expect("deny receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);

    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);

    handle.join().expect("server thread should exit cleanly");
}

#[test]
fn governed_acp_hold_flow_records_commerce_scope_and_payment_metadata() {
    let (url, request_rx, handle) = spawn_payment_test_server(
        200,
        serde_json::json!({
            "authorizationId": "acp_hold_governed",
            "settled": false,
            "metadata": {
                "provider": "stripe",
                "seller": "merchant.example"
            }
        }),
    );

    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        AcpPaymentAdapter::new(url)
            .with_authorize_path("/commerce/authorize")
            .with_bearer_token("acp-token")
            .with_timeout(Duration::from_secs(2)),
    ));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "commerce-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_acp_monetary_grant(
        "commerce-srv",
        "compute",
        "merchant.example",
        100,
        1000,
        "USD",
        50,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-acp";
    let intent = make_governed_acp_intent(GovernedAcpIntentFixture {
        id: "intent-governed-acp",
        server: "commerce-srv",
        tool: "compute",
        purpose: "purchase seller-bound result",
        seller: "merchant.example",
        shared_payment_token_id: "spt_live_governed",
        units: 100,
        currency: "USD",
    });
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "commerce-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "merchant-result-pro" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token.clone()),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "tool should run after ACP authorization succeeds"
    );

    let request = request_rx.recv().expect("request should be captured");
    assert!(request.starts_with("POST /commerce/authorize HTTP/1.1"));
    assert!(request.contains("Authorization: Bearer acp-token"));
    assert!(request.contains("\"commerce\":{"));
    assert!(request.contains("\"seller\":\"merchant.example\""));
    assert!(request.contains("\"sharedPaymentTokenId\":\"spt_live_governed\""));

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("allow receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("allow receipt should carry financial metadata");
    assert_eq!(financial["payment_reference"], "acp_hold_governed");
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(
        financial["cost_breakdown"]["payment"]["authorization_id"],
        "acp_hold_governed"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["adapter"],
        "acp"
    );
    assert_eq!(
        financial["cost_breakdown"]["payment"]["adapter_metadata"]["mode"],
        "shared_payment_token_hold"
    );

    let governed = metadata
        .get("governed_transaction")
        .expect("allow receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["commerce"]["seller"], "merchant.example");
    assert_eq!(
        governed["commerce"]["shared_payment_token_id"],
        "spt_live_governed"
    );
    assert_eq!(governed["approval"]["token_id"], approval_token.id);

    handle.join().expect("server thread should exit cleanly");
}

#[test]
fn governed_acp_seller_mismatch_denies_before_payment_or_tool_execution() {
    let invocations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_payment_adapter(Box::new(
        AcpPaymentAdapter::new("http://127.0.0.1:1").with_timeout(Duration::from_millis(50)),
    ));
    kernel.register_tool_server(Box::new(CountingMonetaryServer {
        id: "commerce-srv".to_string(),
        invocations: invocations.clone(),
    }));

    let agent_kp = Keypair::generate();
    let grant = make_governed_acp_monetary_grant(
        "commerce-srv",
        "compute",
        "merchant.example",
        100,
        1000,
        "USD",
        50,
    );
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request_id = "req-governed-acp-seller-mismatch";
    let intent = make_governed_acp_intent(GovernedAcpIntentFixture {
        id: "intent-governed-acp-seller-mismatch",
        server: "commerce-srv",
        tool: "compute",
        purpose: "attempt purchase for wrong seller",
        seller: "wrong-merchant.example",
        shared_payment_token_id: "spt_live_wrong",
        units: 100,
        currency: "USD",
    });
    let approval_token = make_governed_approval_token(
        &kernel.config.keypair,
        &agent_kp.public_key(),
        &intent,
        request_id,
    );

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: request_id.to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "commerce-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({ "sku": "merchant-result-pro" }),
            dpop_proof: None,
            governed_intent: Some(intent.clone()),
            approval_token: Some(approval_token),
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    assert!(
        response
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("seller")),
        "denial should explain the seller-scope mismatch"
    );
    assert_eq!(
        invocations.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "tool should not run when the seller scope does not match"
    );

    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("deny receipt should carry metadata");
    let financial = metadata
        .get("financial")
        .expect("deny receipt should carry financial metadata");
    assert_eq!(financial["cost_charged"].as_u64(), Some(0));
    assert_eq!(financial["attempted_cost"].as_u64(), Some(100));
    assert_eq!(financial["settlement_status"], "not_applicable");

    let governed = metadata
        .get("governed_transaction")
        .expect("deny receipt should carry governed transaction metadata");
    assert_eq!(governed["intent_id"], intent.id);
    assert_eq!(governed["commerce"]["seller"], "wrong-merchant.example");

    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn monetary_allow_receipt_marks_failed_settlement_when_reported_cost_exceeds_charge() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 150, "USD")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-overrun".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    assert_eq!(financial["cost_charged"].as_u64(), Some(150));
    assert_eq!(financial["settlement_status"], "failed");
    assert!(financial["payment_reference"].is_null());
}

#[test]
fn monetary_server_not_reporting_cost_charges_max_cost_per_invocation() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    // Server does NOT report cost (returns None).
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(resp.verdict, Verdict::Allow);
    let metadata = resp
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have 'financial' key");
    // Worst-case debit: max_cost_per_invocation = 100.
    assert_eq!(financial["cost_charged"].as_u64().unwrap(), 100);
}

#[test]
fn monetary_tool_server_error_releases_precharged_budget() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(FailingMonetaryServer {
        id: "cost-srv".to_string(),
    }));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 1000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-tool-error".to_string(),
            capability: cap.clone(),
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Deny);
    let usage = kernel
        
        .budget_store
        .get_usage(&cap.id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(usage.invocation_count, 0);
    assert_eq!(usage.committed_cost_units().unwrap(), 0);
}

#[test]
fn monetary_full_pipeline_three_invocations_third_denied() {
    // max_total_cost=250, max_cost_per_invocation=100.
    // Invocation 1: charges 100, total = 100. Allowed.
    // Invocation 2: charges 100, total = 200. Allowed.
    // Invocation 3: would charge 100, total would be 300 > 250. Denied.
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant = make_monetary_grant("cost-srv", "compute", 100, 250, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let make_req = |id: &str| ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: "compute".to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let r1 = kernel
        .evaluate_tool_call_blocking(&make_req("req-1"))
        .unwrap();
    assert_eq!(r1.verdict, Verdict::Allow, "first invocation should pass");

    let r2 = kernel
        .evaluate_tool_call_blocking(&make_req("req-2"))
        .unwrap();
    assert_eq!(r2.verdict, Verdict::Allow, "second invocation should pass");

    let r3 = kernel
        .evaluate_tool_call_blocking(&make_req("req-3"))
        .unwrap();
    assert_eq!(
        r3.verdict,
        Verdict::Deny,
        "third invocation should be denied"
    );

    // Verify the denial receipt has financial metadata.
    let metadata = r3.receipt.metadata.as_ref().expect("should have metadata");
    assert!(metadata.get("financial").is_some());
}

#[test]
fn multi_grant_budget_remaining_uses_matched_grant_total() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(MonetaryCostServer::no_cost("cost-srv")));

    let grant_a = make_monetary_grant("cost-srv", "compute-a", 100, 500, "USD");
    let grant_b = make_monetary_grant("cost-srv", "compute-b", 40, 200, "USD");
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![grant_a, grant_b]),
            3600,
        )
        .unwrap();

    let invoke = |request_id: &str, tool_name: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: cap.clone(),
        tool_name: tool_name.to_string(),
        server_id: "cost-srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let _ = kernel
        .evaluate_tool_call_blocking(&invoke("req-a", "compute-a"))
        .unwrap();
    let response_b = kernel
        .evaluate_tool_call_blocking(&invoke("req-b", "compute-b"))
        .unwrap();

    let metadata = response_b
        .receipt
        .metadata
        .as_ref()
        .expect("should have metadata");
    let financial = metadata
        .get("financial")
        .expect("should have financial metadata");
    assert_eq!(financial["grant_index"].as_u64(), Some(1));
    assert_eq!(financial["cost_charged"].as_u64(), Some(40));
    assert_eq!(financial["budget_total"].as_u64(), Some(200));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(160));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_evaluate_tool_call_supports_shared_kernel_concurrency() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    struct ConcurrentServer {
        barrier: Arc<Barrier>,
        current: Arc<AtomicUsize>,
        max_concurrent: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait(?Send)]
    impl ToolServerConnection for ConcurrentServer {
        fn server_id(&self) -> &str {
            "srv"
        }

        fn tool_names(&self) -> Vec<String> {
            vec!["echo".to_string()]
        }

        async fn invoke(
            &self,
            tool_name: &str,
            arguments: serde_json::Value,
            _bridge: Option<&mut dyn NestedFlowBridge>,
        ) -> Result<serde_json::Value, KernelError> {
            assert_eq!(tool_name, "echo");

            let concurrent = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            let _ =
                self.max_concurrent
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |observed| {
                        (concurrent > observed).then_some(concurrent)
                    });

            self.barrier.wait();
            std::thread::sleep(Duration::from_millis(25));
            self.current.fetch_sub(1, Ordering::SeqCst);

            Ok(arguments)
        }
    }

    let barrier = Arc::new(Barrier::new(2));
    let max_concurrent = Arc::new(AtomicUsize::new(0));

    let mut configured_kernel = ChioKernel::new(make_config());
    configured_kernel.register_tool_server(Box::new(ConcurrentServer {
        barrier: barrier.clone(),
        current: Arc::new(AtomicUsize::new(0)),
        max_concurrent: max_concurrent.clone(),
    }));

    let agent_kp = Keypair::generate();
    let capability = configured_kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![ToolGrant {
                server_id: "srv".to_string(),
                tool_name: "echo".to_string(),
                operations: vec![Operation::Invoke],
                constraints: vec![],
                max_invocations: None,
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }]),
            3600,
        )
        .unwrap();

    let kernel = Arc::new(configured_kernel);
    let make_request = |request_id: &str| ToolCallRequest {
        request_id: request_id.to_string(),
        capability: capability.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({ "request_id": request_id }),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let task_a = {
        let kernel = kernel.clone();
        let request = make_request("req-a");
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };
    let task_b = {
        let kernel = kernel.clone();
        let request = make_request("req-b");
        tokio::spawn(async move { kernel.evaluate_tool_call(&request).await })
    };

    let (response_a, response_b) = tokio::time::timeout(Duration::from_secs(2), async move {
        tokio::try_join!(task_a, task_b)
    })
    .await
    .expect("shared kernel evaluation should not deadlock")
    .unwrap();

    let response_a = response_a.unwrap();
    let response_b = response_b.unwrap();
    assert_eq!(response_a.verdict, Verdict::Allow);
    assert_eq!(response_b.verdict, Verdict::Allow);
    assert!(
        max_concurrent.load(Ordering::SeqCst) >= 2,
        "expected concurrent server invocations on a shared kernel"
    );
}

#[test]
fn matched_grant_index_populated_in_guard_context() {
    // A guard that records the matched_grant_index from its context.
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct IndexCapturingGuard {
        captured: Arc<Mutex<Option<usize>>>,
    }

    impl Guard for IndexCapturingGuard {
        fn name(&self) -> &str {
            "index-capture"
        }

        fn evaluate(&self, ctx: &GuardContext) -> Result<Verdict, KernelError> {
            let mut lock = self.captured.lock().unwrap();
            *lock = ctx.matched_grant_index;
            Ok(Verdict::Allow)
        }
    }

    let captured = Arc::new(Mutex::new(None::<usize>));
    let guard = IndexCapturingGuard {
        captured: captured.clone(),
    };

    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["tool1", "tool2"])));
    kernel.add_guard(Box::new(guard));

    // Two grants; first matches "tool1", second matches "tool2".
    let grant0 = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool1".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let grant1 = ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool2".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    };
    let cap = kernel
        .issue_capability(
            &agent_kp.public_key(),
            make_scope(vec![grant0, grant1]),
            3600,
        )
        .unwrap();

    // Request tool2 -- matched grant should be at index 1.
    let resp = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-1".to_string(),
            capability: cap.clone(),
            tool_name: "tool2".to_string(),
            server_id: "srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();
    assert_eq!(resp.verdict, Verdict::Allow);

    let idx = *captured.lock().unwrap();
    assert_eq!(
        idx,
        Some(1),
        "guard should see matched_grant_index=Some(1) for tool2 (second grant)"
    );
}

#[test]
fn velocity_guard_denial_produces_signed_deny_receipt_no_panic() {
    // Simulate a velocity-style guard with a simple counter that denies
    // after N invocations. This tests the kernel's handling of guard denials
    // (producing a signed deny receipt without panic) without importing chio-guards.
    use std::sync::{Arc, Mutex};

    struct CountingRateLimitGuard {
        count: Arc<Mutex<u32>>,
        max: u32,
    }

    impl Guard for CountingRateLimitGuard {
        fn name(&self) -> &str {
            "counting-rate-limit"
        }

        fn evaluate(&self, _ctx: &GuardContext) -> Result<Verdict, KernelError> {
            let mut count = self.count.lock().unwrap();
            *count += 1;
            if *count > self.max {
                Ok(Verdict::Deny)
            } else {
                Ok(Verdict::Allow)
            }
        }
    }

    let counter = Arc::new(Mutex::new(0u32));
    let guard = CountingRateLimitGuard {
        count: counter.clone(),
        max: 2,
    };

    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    kernel.add_guard(Box::new(guard));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let make_req = |id: &str| ToolCallRequest {
        request_id: id.to_string(),
        capability: cap.clone(),
        tool_name: "echo".to_string(),
        server_id: "srv".to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    // First two invocations allowed.
    let r1 = kernel
        .evaluate_tool_call_blocking(&make_req("req-1"))
        .unwrap();
    assert_eq!(r1.verdict, Verdict::Allow);
    let r2 = kernel
        .evaluate_tool_call_blocking(&make_req("req-2"))
        .unwrap();
    assert_eq!(r2.verdict, Verdict::Allow);

    // Third invocation should be denied by the counting guard.
    let r3 = kernel
        .evaluate_tool_call_blocking(&make_req("req-3"))
        .unwrap();
    assert_eq!(
        r3.verdict,
        Verdict::Deny,
        "counting guard should deny 3rd invocation"
    );
    // Verify it's a properly signed deny receipt (not a panic/unwrap).
    assert!(
        r3.receipt.id.starts_with("rcpt-"),
        "receipt should have valid id"
    );
    assert!(r3.reason.is_some(), "denial should have a reason");
}

#[test]
fn checkpoint_triggers_at_100_receipts() {
    let path = unique_receipt_db_path("chio-checkpoint-trigger");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 10; // Use 10 for speed.

    let mut kernel = ChioKernel::new(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let store = SqliteReceiptStore::open(&path).unwrap();
    kernel.set_receipt_store(Box::new(store));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    for i in 0..10 {
        kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
            federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    // Verify a checkpoint was stored in the database.
    let store2 = SqliteReceiptStore::open(&path).unwrap();
    let checkpoint = store2.load_checkpoint_by_seq(1).unwrap();
    assert!(
        checkpoint.is_some(),
        "checkpoint should have been stored after 10 receipts"
    );
    let cp = checkpoint.unwrap();
    assert_eq!(cp.body.checkpoint_seq, 1);
    assert_eq!(cp.body.batch_start_seq, 1);
    assert_eq!(cp.body.batch_end_seq, 10);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn concurrent_receipt_checkpointing_keeps_contiguous_batches() {
    let path = unique_receipt_db_path("chio-checkpoint-concurrent");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 2;

    let mut kernel = ChioKernel::new(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let store = SqliteReceiptStore::open(&path).unwrap();
    kernel.set_receipt_store(Box::new(store));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let kernel = std::sync::Arc::new(kernel);
    let agent_id = agent_kp.public_key().to_hex();

    let handles = (0..12)
        .map(|i| {
            let kernel = std::sync::Arc::clone(&kernel);
            let cap = cap.clone();
            let agent_id = agent_id.clone();
            std::thread::spawn(move || {
                kernel
                    .evaluate_tool_call_blocking(&ToolCallRequest {
                        request_id: format!("req-concurrent-{i}"),
                        capability: cap,
                        tool_name: "echo".to_string(),
                        server_id: "srv".to_string(),
                        agent_id,
                        arguments: serde_json::json!({ "i": i }),
                        dpop_proof: None,
                        governed_intent: None,
                        approval_token: None,
                        model_metadata: None,
                        federated_origin_kernel_id: None,
                    })
                    .unwrap();
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().unwrap();
    }

    let store2 = SqliteReceiptStore::open(&path).unwrap();
    for checkpoint_seq in 1..=6 {
        let checkpoint = store2
            .load_checkpoint_by_seq(checkpoint_seq)
            .unwrap()
            .unwrap_or_else(|| panic!("checkpoint {checkpoint_seq} should exist"));
        assert_eq!(checkpoint.body.checkpoint_seq, checkpoint_seq);
        assert_eq!(checkpoint.body.batch_start_seq, (checkpoint_seq - 1) * 2 + 1);
        assert_eq!(checkpoint.body.batch_end_seq, checkpoint_seq * 2);
    }
    assert!(store2.load_checkpoint_by_seq(7).unwrap().is_none());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_counters_restore_when_store_is_reattached() {
    let path = unique_receipt_db_path("chio-checkpoint-restart");
    let kernel_kp = make_keypair();
    let mut first_config = make_monetary_config();
    first_config.keypair = kernel_kp.clone();
    first_config.checkpoint_batch_size = 2;
    let mut second_config = make_monetary_config();
    second_config.keypair = kernel_kp;
    second_config.checkpoint_batch_size = 2;

    let agent_kp = Keypair::generate();
    let grant = make_grant("srv", "echo");
    let mut first_kernel = ChioKernel::new(first_config);
    first_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    first_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    let cap = first_kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let agent_id = agent_kp.public_key().to_hex();

    for i in 0..2 {
        first_kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-before-restart-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_id.clone(),
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    let mut restarted_kernel = ChioKernel::new(second_config);
    restarted_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    restarted_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    assert_eq!(
        restarted_kernel
            .checkpoint_seq_counter
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    assert_eq!(
        restarted_kernel
            .last_checkpoint_seq
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );

    for i in 2..4 {
        restarted_kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-after-restart-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_id.clone(),
                arguments: serde_json::json!({ "i": i }),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
                federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    let store = SqliteReceiptStore::open(&path).unwrap();
    let first_checkpoint = store
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("checkpoint 1 should exist before restart");
    let second_checkpoint = store
        .load_checkpoint_by_seq(2)
        .unwrap()
        .expect("checkpoint 2 should exist after restart");
    assert_eq!(first_checkpoint.body.batch_start_seq, 1);
    assert_eq!(first_checkpoint.body.batch_end_seq, 2);
    assert_eq!(second_checkpoint.body.batch_start_seq, 3);
    assert_eq!(second_checkpoint.body.batch_end_seq, 4);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn checkpoint_counters_refresh_across_kernels_sharing_store() {
    let path = unique_receipt_db_path("chio-checkpoint-two-kernels");
    let kernel_kp = make_keypair();
    let mut first_config = make_monetary_config();
    first_config.keypair = kernel_kp.clone();
    first_config.checkpoint_batch_size = 1;
    let mut second_config = make_monetary_config();
    second_config.keypair = kernel_kp;
    second_config.checkpoint_batch_size = 1;

    let agent_kp = Keypair::generate();
    let grant = make_grant("srv", "echo");
    let mut first_kernel = ChioKernel::new(first_config);
    let mut second_kernel = ChioKernel::new(second_config);
    first_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    second_kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));
    first_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));
    second_kernel.set_receipt_store(Box::new(SqliteReceiptStore::open(&path).unwrap()));

    let cap = first_kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let agent_id = agent_kp.public_key().to_hex();

    first_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-two-kernels-1".to_string(),
            capability: cap.clone(),
            tool_name: "echo".to_string(),
            server_id: "srv".to_string(),
            agent_id: agent_id.clone(),
            arguments: serde_json::json!({ "i": 1 }),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();
    second_kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-two-kernels-2".to_string(),
            capability: cap,
            tool_name: "echo".to_string(),
            server_id: "srv".to_string(),
            agent_id,
            arguments: serde_json::json!({ "i": 2 }),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        })
        .unwrap();

    let store = SqliteReceiptStore::open(&path).unwrap();
    let first_checkpoint = store
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("first kernel checkpoint should exist");
    let second_checkpoint = store
        .load_checkpoint_by_seq(2)
        .unwrap()
        .expect("second kernel checkpoint should extend the chain");
    assert_eq!(first_checkpoint.body.batch_start_seq, 1);
    assert_eq!(first_checkpoint.body.batch_end_seq, 1);
    assert_eq!(second_checkpoint.body.batch_start_seq, 2);
    assert_eq!(second_checkpoint.body.batch_end_seq, 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn receipt_store_install_fails_closed_on_checkpoint_hydration_error() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    let result =
        kernel.try_set_receipt_store_handle(std::sync::Arc::new(
            FailingCheckpointHydrationReceiptStore,
        ));

    assert!(result.is_err());
    assert!(kernel.receipt_store.is_none());
    assert_eq!(
        kernel
            .checkpoint_seq_counter
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert_eq!(
        kernel
            .last_checkpoint_seq
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[test]
fn inclusion_proof_verifies_against_stored_checkpoint() {
    let path = unique_receipt_db_path("chio-checkpoint-proof");
    let mut config = make_monetary_config();
    config.checkpoint_batch_size = 5;

    let mut kernel = ChioKernel::new(config);
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let store = SqliteReceiptStore::open(&path).unwrap();
    kernel.set_receipt_store(Box::new(store));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    for i in 0..5 {
        kernel
            .evaluate_tool_call_blocking(&ToolCallRequest {
                request_id: format!("req-{i}"),
                capability: cap.clone(),
                tool_name: "echo".to_string(),
                server_id: "srv".to_string(),
                agent_id: agent_kp.public_key().to_hex(),
                arguments: serde_json::json!({}),
                dpop_proof: None,
                governed_intent: None,
                approval_token: None,
                model_metadata: None,
            federated_origin_kernel_id: None,
            })
            .unwrap();
    }

    // Load checkpoint and receipts, build and verify an inclusion proof.
    let store2 = SqliteReceiptStore::open(&path).unwrap();
    let checkpoint = store2
        .load_checkpoint_by_seq(1)
        .unwrap()
        .expect("checkpoint should exist");

    let bytes_range = store2.receipts_canonical_bytes_range(1, 5).unwrap();
    assert_eq!(bytes_range.len(), 5, "should have 5 receipts in range");

    let all_bytes: Vec<Vec<u8>> = bytes_range.iter().map(|(_, b)| b.clone()).collect();
    let tree = chio_core::merkle::MerkleTree::from_leaves(&all_bytes).expect("tree build failed");

    // Build proof for receipt at leaf index 2 (seq 3).
    let proof = build_inclusion_proof(&tree, 2, 1, 3).expect("proof build failed");
    assert!(
        proof.verify(&all_bytes[2], &checkpoint.body.merkle_root),
        "inclusion proof for receipt #3 should verify against checkpoint"
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn tool_invocation_cost_serde_roundtrip() {
    let cost = ToolInvocationCost {
        units: 500,
        currency: "USD".to_string(),
        breakdown: None,
    };
    let json = serde_json::to_string(&cost).unwrap();
    let restored: ToolInvocationCost = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.units, 500);
    assert_eq!(restored.currency, "USD");
    assert!(restored.breakdown.is_none());

    // With breakdown
    let cost_with = ToolInvocationCost {
        units: 200,
        currency: "EUR".to_string(),
        breakdown: Some(serde_json::json!({"compute": 150, "network": 50})),
    };
    let json_with = serde_json::to_string(&cost_with).unwrap();
    let restored_with: ToolInvocationCost = serde_json::from_str(&json_with).unwrap();
    assert_eq!(restored_with.units, 200);
    assert!(restored_with.breakdown.is_some());
}

#[test]
fn cross_currency_reported_cost_attaches_oracle_evidence_and_converted_units() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.set_price_oracle(Box::new(StaticPriceOracle::new([(
        ("ETH".to_string(), "USD".to_string()),
        Ok(ExchangeRate {
            base: "ETH".to_string(),
            quote: "USD".to_string(),
            rate_numerator: 300_000,
            rate_denominator: 100,
            updated_at: now.saturating_sub(45),
            fetched_at: now,
            source: "chainlink".to_string(),
            feed_reference: "0x71041dddad3595F9CEd3DcCFBe3D1F4b0a16Bb70".to_string(),
            max_age_seconds: 600,
            conversion_margin_bps: 200,
            confidence_numerator: None,
            confidence_denominator: None,
        }),
    )])));
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        1_000_000_000_000_000,
        "ETH",
    )));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-cross-currency-ok".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("metadata");
    let financial = metadata.get("financial").expect("financial");
    assert_eq!(financial["cost_charged"].as_u64(), Some(306));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(694));
    assert_eq!(financial["settlement_status"], "settled");
    assert_eq!(financial["oracle_evidence"]["base"], "ETH");
    assert_eq!(financial["oracle_evidence"]["quote"], "USD");
    assert_eq!(
        financial["oracle_evidence"]["converted_cost_units"].as_u64(),
        Some(306)
    );
    assert_eq!(
        financial["cost_breakdown"]["oracle_conversion"]["status"],
        "applied"
    );
}

#[test]
fn cross_currency_without_oracle_keeps_provisional_charge_and_marks_failed_settlement() {
    let mut kernel = ChioKernel::new(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new(
        "cost-srv",
        1_000_000_000_000_000,
        "ETH",
    )));

    let agent_kp = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 400, 1_000, "USD");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let response = kernel
        .evaluate_tool_call_blocking(&ToolCallRequest {
            request_id: "req-cross-currency-failed".to_string(),
            capability: cap,
            tool_name: "compute".to_string(),
            server_id: "cost-srv".to_string(),
            agent_id: agent_kp.public_key().to_hex(),
            arguments: serde_json::json!({}),
            dpop_proof: None,
            governed_intent: None,
            approval_token: None,
            model_metadata: None,
        federated_origin_kernel_id: None,
        })
        .unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    let metadata = response.receipt.metadata.as_ref().expect("metadata");
    let financial = metadata.get("financial").expect("financial");
    assert_eq!(financial["cost_charged"].as_u64(), Some(400));
    assert_eq!(financial["budget_remaining"].as_u64(), Some(600));
    assert_eq!(financial["settlement_status"], "failed");
    assert!(financial.get("oracle_evidence").is_none());
    assert_eq!(
        financial["cost_breakdown"]["oracle_conversion"]["status"],
        "failed"
    );
}

#[tokio::test]
async fn echo_server_invoke_with_cost_returns_none() {
    let server = EchoServer::new("srv-a", vec!["echo"]);
    let args = serde_json::json!({"msg": "hello"});
    let (value, cost) = server
        .invoke_with_cost("echo", args, None)
        .await
        .expect("invoke_with_cost should succeed");
    assert!(cost.is_none(), "EchoServer should return None cost");
    assert!(value.is_object());
}

// ---------------------------------------------------------------------------
// DPoP wiring tests
// ---------------------------------------------------------------------------

fn make_dpop_grant(server: &str, tool: &str) -> ToolGrant {
    ToolGrant {
        server_id: server.to_string(),
        tool_name: tool.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: Some(true),
    }
}

/// Build a kernel that has a DPoP store configured and a single DPoP-required grant.
fn make_dpop_kernel_and_cap(
    agent_kp: &Keypair,
    server: &str,
    tool: &str,
) -> (ChioKernel, CapabilityToken) {
    let config = KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: "dpop-test-policy".to_string(),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        checkpoint_batch_size: DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
    };
    let mut kernel = ChioKernel::new(config);
    kernel.register_tool_server(Box::new(EchoServer::new(server, vec![tool])));

    let nonce_store = dpop::DpopNonceStore::new(1024, std::time::Duration::from_secs(300));
    kernel.set_dpop_store(nonce_store, dpop::DpopConfig::default());

    let grant = make_dpop_grant(server, tool);
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    (kernel, cap)
}

/// Build a valid DPoP proof for a given request context.
fn make_dpop_proof(
    agent_kp: &Keypair,
    cap: &CapabilityToken,
    server: &str,
    tool: &str,
    arguments: &serde_json::Value,
    nonce: &str,
) -> dpop::DpopProof {
    let args_bytes =
        chio_core::canonical::canonical_json_bytes(arguments).expect("canonical_json_bytes failed");
    let action_hash = chio_core::crypto::sha256_hex(&args_bytes);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time error")
        .as_secs();
    let body = dpop::DpopProofBody {
        schema: dpop::DPOP_SCHEMA.to_string(),
        capability_id: cap.id.clone(),
        tool_server: server.to_string(),
        tool_name: tool.to_string(),
        action_hash,
        nonce: nonce.to_string(),
        issued_at: now_secs,
        agent_key: agent_kp.public_key(),
    };
    dpop::DpopProof::sign(body, agent_kp).expect("DPoP sign failed")
}

#[test]
fn dpop_required_grant_allows_when_valid_proof_provided() {
    let agent_kp = Keypair::generate();
    let server = "dpop-srv";
    let tool = "secure_op";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

    let arguments = serde_json::json!({"action": "read"});
    let proof = make_dpop_proof(&agent_kp, &cap, server, tool, &arguments, "nonce-abc-001");

    let request = ToolCallRequest {
        request_id: "req-dpop-allow".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments,
        dpop_proof: Some(proof),
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "valid DPoP proof should allow; reason: {:?}",
        response.reason
    );
}

#[test]
fn dpop_required_grant_denies_when_no_proof_provided() {
    let agent_kp = Keypair::generate();
    let server = "dpop-srv";
    let tool = "secure_op";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

    let request = ToolCallRequest {
        request_id: "req-dpop-deny-no-proof".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments: serde_json::json!({"action": "read"}),
        dpop_proof: None,
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "missing DPoP proof should deny"
    );
    let reason = response.reason.as_deref().unwrap_or("");
    assert!(
        reason.contains("DPoP proof"),
        "denial reason should mention DPoP; got: {reason}"
    );
}

#[test]
fn dpop_required_grant_denies_when_proof_has_wrong_tool_name() {
    let agent_kp = Keypair::generate();
    let server = "dpop-srv";
    let tool = "secure_op";
    let (kernel, cap) = make_dpop_kernel_and_cap(&agent_kp, server, tool);

    let arguments = serde_json::json!({"action": "read"});
    // Proof claims wrong tool name -- binding check should fail.
    let proof = make_dpop_proof(
        &agent_kp,
        &cap,
        server,
        "other_tool",
        &arguments,
        "nonce-bad-001",
    );

    let request = ToolCallRequest {
        request_id: "req-dpop-deny-wrong-tool".to_string(),
        capability: cap,
        tool_name: tool.to_string(),
        server_id: server.to_string(),
        agent_id: agent_kp.public_key().to_hex(),
        arguments,
        dpop_proof: Some(proof),
        governed_intent: None,
        approval_token: None,
        model_metadata: None,
    federated_origin_kernel_id: None,
    };

    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Deny,
        "proof with wrong tool name should deny"
    );
}

#[test]
fn dpop_not_required_grant_allows_without_proof() {
    // Verify non-DPoP grants are unaffected.
    let mut kernel = ChioKernel::new(make_config());
    let agent_kp = Keypair::generate();
    kernel.register_tool_server(Box::new(EchoServer::new("srv", vec!["echo"])));

    let grant = make_grant("srv", "echo");
    let cap = kernel
        .issue_capability(&agent_kp.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();

    let request = make_request("req-no-dpop", &cap, "echo", "srv");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();
    assert_eq!(
        response.verdict,
        Verdict::Allow,
        "non-DPoP grant should allow without proof"
    );
}

#[test]
fn kernel_error_report_includes_out_of_scope_context() {
    let report = KernelError::OutOfScope {
        tool: "read_file".to_string(),
        server: "fs".to_string(),
    }
    .report();

    assert_eq!(report.code, "CHIO-KERNEL-OUT-OF-SCOPE-TOOL");
    assert_eq!(report.context["tool"], "read_file");
    assert_eq!(report.context["server"], "fs");
    assert!(report
        .suggested_fix
        .contains("Issue a capability that grants this tool"));
}

#[test]
fn kernel_error_report_includes_request_cancel_context() {
    let report = KernelError::RequestCancelled {
        request_id: "req-123".to_string().into(),
        reason: "operator cancelled".to_string(),
    }
    .report();

    assert_eq!(report.code, "CHIO-KERNEL-REQUEST-CANCELLED");
    assert_eq!(report.context["request_id"], "req-123");
    assert_eq!(report.context["reason"], "operator cancelled");
    assert!(report.suggested_fix.contains("cancelled request ID"));
}

#[test]
fn sync_bridge_current_thread_diagnostic_only_advertises_multithread_runtime() {
    let report = KernelError::SyncBridgeIncompatibleWithCurrentThreadRuntime.report();

    assert_eq!(report.code, "CHIO-KERNEL-SYNC-BRIDGE-INCOMPATIBLE");
    assert!(report
        .message
        .contains("multi-thread Tokio runtime"));
    assert!(!report.message.contains("evaluate_tool_call"));
    assert!(report.suggested_fix.contains("multi-thread Tokio runtime"));
    assert!(!report.suggested_fix.contains("API directly"));
}
