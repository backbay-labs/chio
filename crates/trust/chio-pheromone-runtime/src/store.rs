use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

use chio_federation::pheromone_gossip::{
    verify_pheromone_gossip_batch_envelope, verify_pheromone_gossip_frame_for_batch,
    PheromoneGossipBatch, PheromoneGossipBatchVerificationContext, PheromoneTransitPolicy,
};
use chio_pheromone::{
    agent_passport_key_hash, newcomer_discount_for_deposit, scarcity_admissions_for_deposit,
    scarcity_admissions_for_deposit_treaty, validate_deposit_for_admission, PassportAdmission,
    PheromoneConcentration, PheromoneDeposit, PheromoneError, PheromoneScarcityAdmission,
    PheromoneValidationContext, PHEROMONE_CONCENTRATION_SCHEMA,
};
use rusqlite::{params, Connection, OptionalExtension};

use crate::{
    canonical_sha256, PeerWeightProvider, PheromoneBatchOutcome, PheromoneFrameReport,
    PheromoneReceiveReport, PheromoneReceiverConfig, PheromoneRuntimeError, PheromoneRuntimeStore,
    WorkflowContextResolver, PHEROMONE_RECEIVE_REPORT_SCHEMA,
};

fn build_receive_report(
    config: &PheromoneReceiverConfig,
    batch_sha256: String,
    frames: Vec<PheromoneFrameReport>,
) -> PheromoneReceiveReport {
    let accepted_frame_count = frames.iter().filter(|frame| frame.accepted).count() as u64;
    let rejected_frame_count = frames.len() as u64 - accepted_frame_count;
    let batch_outcome = match (accepted_frame_count, rejected_frame_count) {
        (_, 0) => PheromoneBatchOutcome::Accepted,
        (0, _) => PheromoneBatchOutcome::Rejected,
        _ => PheromoneBatchOutcome::Partial,
    };
    PheromoneReceiveReport {
        schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
        accepted: batch_outcome == PheromoneBatchOutcome::Accepted,
        batch_outcome,
        accepted_frame_count,
        rejected_frame_count,
        batch_sha256,
        recipient_kernel_id: config.recipient_kernel_id.clone(),
        authenticated_sender_kernel_id: config.authenticated_sender_kernel_id.clone(),
        received_at_unix_ms: config.validation_context.now_unix_ms,
        frames,
    }
}

fn frame_failure_code(error: &PheromoneRuntimeError) -> &'static str {
    if is_storage_commit_error(error) {
        "storage_commit_failed"
    } else {
        error.code()
    }
}

fn is_storage_commit_error(error: &PheromoneRuntimeError) -> bool {
    matches!(
        error,
        PheromoneRuntimeError::Sqlite(_) | PheromoneRuntimeError::StorePoisoned
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::PheromoneRuntimeError;
    use super::SqlitePheromoneRuntimeStore;
    use crate::{
        PheromoneBatchOutcome, PheromoneReceiveReport, PheromoneRuntimeStore,
        PHEROMONE_RECEIVE_REPORT_SCHEMA,
    };

    fn receive_report(
        batch_sha256: &str,
        sender: &str,
        accepted: bool,
        received_at_unix_ms: u64,
    ) -> PheromoneReceiveReport {
        PheromoneReceiveReport {
            schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
            accepted,
            batch_outcome: if accepted {
                PheromoneBatchOutcome::Accepted
            } else {
                PheromoneBatchOutcome::Rejected
            },
            accepted_frame_count: u64::from(accepted),
            rejected_frame_count: u64::from(!accepted),
            batch_sha256: batch_sha256.to_string(),
            recipient_kernel_id: "did:chio:bob".to_string(),
            authenticated_sender_kernel_id: sender.to_string(),
            received_at_unix_ms,
            frames: Vec::new(),
        }
    }

    #[test]
    fn receive_report_is_recoverable_by_batch_sha256() {
        let store = SqlitePheromoneRuntimeStore::open_in_memory().expect("store opens");

        // A batch hash that was never recorded is not found.
        assert!(store
            .lookup_receive_report_by_batch("deadbeef", "did:chio:alice")
            .expect("lookup runs")
            .is_none());

        // Record a report carrying a known batch hash, then recover it by (batch, sender).
        let report = receive_report("abc123", "did:chio:alice", true, 1);
        store.record_receive_report(&report).expect("record report");
        let found = store
            .lookup_receive_report_by_batch("abc123", "did:chio:alice")
            .expect("lookup runs")
            .expect("report recovered by batch hash");
        assert_eq!(found.batch_sha256, "abc123");
    }

    #[test]
    fn receive_report_lookup_is_scoped_to_the_authenticated_sender() {
        // A batch hash is NOT sender-unique. A wrong-sender replay can record a REJECTED
        // verdict for the same bytes BEFORE the correct sender's crash-recovery report.
        // The lookup must return the row for the QUERIED sender, never an arbitrary
        // cross-sender row, or recovery would adopt the wrong verdict and re-run receive on
        // an already-committed batch.
        //
        // An unqualified `SELECT ... WHERE batch_sha256 = ?` returns whichever row the
        // engine yields first (here the wrong-sender REJECTED report, recorded first); the
        // sender-scoped query returns each sender's own row.
        let store = SqlitePheromoneRuntimeStore::open_in_memory().expect("store opens");
        // Wrong sender records a rejected verdict for the batch FIRST (earlier timestamp).
        let wrong = receive_report("shared-batch", "did:chio:mallory", false, 1);
        store.record_receive_report(&wrong).expect("record wrong");
        // Correct sender records an accepted verdict for the SAME batch bytes.
        let correct = receive_report("shared-batch", "did:chio:alice", true, 2);
        store
            .record_receive_report(&correct)
            .expect("record correct");

        let found = store
            .lookup_receive_report_by_batch("shared-batch", "did:chio:alice")
            .expect("lookup runs")
            .expect("the correct sender's verdict is recovered");
        assert_eq!(found.authenticated_sender_kernel_id, "did:chio:alice");
        assert!(
            found.accepted,
            "the correct sender's accepted verdict is returned"
        );

        // The wrong sender's own row is still addressable under its own scope.
        let mallory = store
            .lookup_receive_report_by_batch("shared-batch", "did:chio:mallory")
            .expect("lookup runs")
            .expect("mallory's own verdict is addressable under its own scope");
        assert!(!mallory.accepted);

        // A sender that recorded nothing for this batch gets None (fail-closed).
        assert!(store
            .lookup_receive_report_by_batch("shared-batch", "did:chio:nobody")
            .expect("lookup runs")
            .is_none());
    }

    #[test]
    fn recovery_prefers_the_committed_acceptance_over_a_later_replay_rejection() {
        // After `receive_batch` commits an accepted report but before the relay inbox is
        // recorded, a retry over the same batch bytes after a crash records a replay-window
        // REJECTION with a LATER `received_at`. Recovery must return the committed ACCEPTED
        // verdict, never the later rejection, or it would dead-letter deposits the batch
        // already admitted.
        let store = SqlitePheromoneRuntimeStore::open_in_memory().expect("store opens");
        // The committed accepted verdict lands first.
        let accepted = receive_report("batch-1", "did:chio:alice", true, 10);
        store
            .record_receive_report(&accepted)
            .expect("record accepted");
        // A retry after a crash records a replay rejection for the same batch LATER.
        let rejection = receive_report("batch-1", "did:chio:alice", false, 20);
        store
            .record_receive_report(&rejection)
            .expect("record rejection");

        let recovered = store
            .lookup_receive_report_by_batch("batch-1", "did:chio:alice")
            .expect("lookup runs")
            .expect("the committed verdict is recoverable");
        assert!(
            recovered.accepted,
            "recovery returns the committed accepted verdict, not the later replay rejection"
        );
    }

    #[test]
    fn recovery_prefers_a_committed_partial_over_a_later_replay_rejection() {
        // A PARTIAL batch admitted some frames, so its committed verdict must also win over
        // a later replay rejection even though `accepted` is false for a partial outcome.
        // Preferring on the batch OUTCOME (not the accepted flag) keeps partially-admitted
        // deposits from being dead-lettered on crash recovery.
        let store = SqlitePheromoneRuntimeStore::open_in_memory().expect("store opens");
        let partial = PheromoneReceiveReport {
            schema: PHEROMONE_RECEIVE_REPORT_SCHEMA.to_string(),
            accepted: false,
            batch_outcome: PheromoneBatchOutcome::Partial,
            accepted_frame_count: 1,
            rejected_frame_count: 1,
            batch_sha256: "batch-2".to_string(),
            recipient_kernel_id: "did:chio:bob".to_string(),
            authenticated_sender_kernel_id: "did:chio:alice".to_string(),
            received_at_unix_ms: 10,
            frames: Vec::new(),
        };
        store
            .record_receive_report(&partial)
            .expect("record partial");
        let rejection = receive_report("batch-2", "did:chio:alice", false, 20);
        store
            .record_receive_report(&rejection)
            .expect("record rejection");

        let recovered = store
            .lookup_receive_report_by_batch("batch-2", "did:chio:alice")
            .expect("lookup runs")
            .expect("the committed partial verdict is recoverable");
        assert_eq!(
            recovered.batch_outcome,
            PheromoneBatchOutcome::Partial,
            "recovery returns the committed partial verdict, not the later replay rejection"
        );
    }

    #[test]
    fn storage_commit_error_helper_selects_only_storage_failures() {
        assert!(super::is_storage_commit_error(
            &PheromoneRuntimeError::Sqlite("disk full".to_string())
        ));
        assert!(super::is_storage_commit_error(
            &PheromoneRuntimeError::StorePoisoned
        ));
        assert!(!super::is_storage_commit_error(
            &PheromoneRuntimeError::InvalidField("bad frame".to_string())
        ));
    }
}

#[derive(Debug)]
pub struct SqlitePheromoneRuntimeStore {
    conn: Mutex<Connection>,
}

impl SqlitePheromoneRuntimeStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PheromoneRuntimeError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.run_migrations()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self, PheromoneRuntimeError> {
        let store = Self {
            conn: Mutex::new(Connection::open_in_memory()?),
        };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;

            CREATE TABLE IF NOT EXISTS chio_pheromone_deposits (
                deposit_sha256 TEXT PRIMARY KEY,
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                timestamp_unix_ms INTEGER NOT NULL,
                json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_replay_nonces (
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                nonce TEXT NOT NULL,
                expires_at_unix_ms INTEGER NOT NULL,
                PRIMARY KEY (kernel_id, passport_key_hash, nonce)
            );

            CREATE INDEX IF NOT EXISTS idx_chio_pheromone_replay_expiry
                ON chio_pheromone_replay_nonces(expires_at_unix_ms);

            CREATE TABLE IF NOT EXISTS chio_pheromone_pair_counts (
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (kernel_id, passport_key_hash, subject_class, treaty_id)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_passport_caps (
                kernel_id TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                PRIMARY KEY (kernel_id, subject_class, passport_key_hash)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_scarcity_buckets (
                reputation_epoch INTEGER NOT NULL,
                window_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (
                    reputation_epoch,
                    window_id,
                    treaty_id,
                    subject_class_namespace,
                    subject_class
                )
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_pair_buckets (
                reputation_epoch INTEGER NOT NULL,
                window_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                count INTEGER NOT NULL,
                PRIMARY KEY (
                    reputation_epoch,
                    window_id,
                    treaty_id,
                    subject_class_namespace,
                    subject_class,
                    kernel_id,
                    passport_key_hash
                )
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_passport_caps_v2 (
                reputation_epoch INTEGER NOT NULL,
                window_id TEXT NOT NULL,
                treaty_id TEXT NOT NULL,
                subject_class_namespace TEXT NOT NULL,
                subject_class TEXT NOT NULL,
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                PRIMARY KEY (
                    reputation_epoch,
                    window_id,
                    treaty_id,
                    subject_class_namespace,
                    subject_class,
                    kernel_id,
                    passport_key_hash
                )
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_passport_admissions (
                kernel_id TEXT NOT NULL,
                passport_key_hash TEXT NOT NULL,
                json TEXT NOT NULL,
                PRIMARY KEY (kernel_id, passport_key_hash)
            );

            CREATE TABLE IF NOT EXISTS chio_pheromone_receive_reports (
                report_sha256 TEXT PRIMARY KEY,
                received_at_unix_ms INTEGER NOT NULL,
                json TEXT NOT NULL,
                batch_sha256 TEXT,
                sender_kernel_id TEXT
            );
            "#,
        )?;
        ensure_receive_report_recovery_columns(&conn)?;
        Ok(())
    }

    fn stored_passports(&self) -> Result<Vec<PassportAdmission>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT json FROM chio_pheromone_passport_admissions ORDER BY kernel_id, passport_key_hash")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut passports = Vec::new();
        for row in rows {
            passports.push(serde_json::from_str(&row?)?);
        }
        Ok(passports)
    }

    fn query_context_with_stored_passports(
        &self,
        context: &PheromoneValidationContext,
    ) -> Result<PheromoneValidationContext, PheromoneRuntimeError> {
        let mut query_context = context.clone();
        let mut seen = BTreeSet::new();
        for passport in &query_context.passports {
            seen.insert(passport_identity(passport));
        }
        for passport in self.stored_passports()? {
            if seen.insert(passport_identity(&passport)) {
                query_context.passports.push(passport);
            }
        }
        Ok(query_context)
    }

    fn admit_deposit_scoped(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
        treaty_id: Option<&str>,
    ) -> Result<(), PheromoneRuntimeError> {
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        admit_deposit_scoped_tx(&tx, &deposit, context, treaty_id)?;
        tx.commit()?;
        Ok(())
    }

    /// Recover a durably-recorded receive report by its batch hash SCOPED to the
    /// authenticated sender, if the store committed one for that (batch, sender) pair.
    /// The sender scope is applied AT THE QUERY LEVEL: a batch hash is
    /// NOT sender-unique (a wrong-sender replay can record a rejected report for the same
    /// bytes before the correct sender's crash-recovery report), so an unqualified
    /// `SELECT` could return an arbitrary cross-sender row. Filtering by
    /// `sender_kernel_id` returns the correct sender's durable verdict; the adoption site
    /// re-checks the deserialized `authenticated_sender_kernel_id` as belt-and-suspenders.
    ///
    /// An ADMITTING verdict (accepted or partial) wins over a rejection, then recency
    /// breaks ties. `receive_batch` also records replay-window rejections for the same
    /// (batch, sender), and a retry after a crash (a fresh relay nonce over the same batch
    /// bytes) records that rejection with a LATER `received_at_unix_ms` than the original
    /// committed verdict. Ordering by recency alone would recover the replay rejection and
    /// dead-letter deposits the committed report already admitted, so any report that
    /// admitted a frame is preferred over a later rejection of the same batch. When no
    /// admitting verdict exists, the most recent (rejected) row is returned, keeping
    /// crash recovery idempotent. Returns None when no row for the (batch, sender) pair
    /// exists (pre-migration rows have NULL columns and are not returned). Read-only.
    pub fn lookup_receive_report_by_batch(
        &self,
        batch_sha256: &str,
        authenticated_sender_kernel_id: &str,
    ) -> Result<Option<PheromoneReceiveReport>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT json FROM chio_pheromone_receive_reports \
             WHERE batch_sha256 = ?1 AND sender_kernel_id = ?2 \
             ORDER BY received_at_unix_ms DESC",
        )?;
        let rows = stmt.query_map(
            params![batch_sha256, authenticated_sender_kernel_id],
            |row| row.get::<_, String>(0),
        )?;
        let mut most_recent: Option<PheromoneReceiveReport> = None;
        for row in rows {
            let report: PheromoneReceiveReport = serde_json::from_str(&row?)?;
            if report.batch_outcome != PheromoneBatchOutcome::Rejected {
                return Ok(Some(report));
            }
            if most_recent.is_none() {
                most_recent = Some(report);
            }
        }
        Ok(most_recent)
    }
}

fn admit_deposit_scoped_tx(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    context: &PheromoneValidationContext,
    treaty_id: Option<&str>,
) -> Result<(), PheromoneRuntimeError> {
    let passport = validate_deposit_for_admission(deposit, context)?;
    let admissions = match treaty_id {
        Some(treaty_id) => scarcity_admissions_for_deposit_treaty(deposit, context, treaty_id)?,
        None => scarcity_admissions_for_deposit(deposit, context)?,
    };
    let now = i64_from_u64(context.now_unix_ms, "now_unix_ms")?;
    tx.execute(
        "DELETE FROM chio_pheromone_replay_nonces WHERE expires_at_unix_ms <= ?1",
        params![now],
    )?;
    let expires_at = context.now_unix_ms.saturating_add(context.replay_window_ms);
    let inserted = tx.execute(
        r#"
        INSERT INTO chio_pheromone_replay_nonces
            (kernel_id, passport_key_hash, nonce, expires_at_unix_ms)
        VALUES (?1, ?2, ?3, ?4)
        ON CONFLICT(kernel_id, passport_key_hash, nonce) DO NOTHING
        "#,
        params![
            deposit.body.kernel_id,
            deposit.body.agent_passport_key_hash,
            deposit.body.nonce,
            i64_from_u64(expires_at, "replay_expires_at_unix_ms")?,
        ],
    )?;
    if inserted == 0 {
        return Err(PheromoneRuntimeError::Pheromone(
            PheromoneError::ReplayWindowExceeded(deposit.body.nonce.clone()),
        ));
    }

    for admission in &admissions {
        let bucket_count = scarcity_bucket_count(tx, admission)?;
        if bucket_count >= admission.token_capacity {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::RateLimitExhausted(format!(
                    "{}:{}:{}:{}",
                    admission.reputation_epoch,
                    admission.window_id,
                    admission.treaty_id,
                    admission.subject_class
                )),
            ));
        }
        let count = pair_bucket_count(tx, deposit, admission)?;
        if count >= context.max_deposits_per_pair {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::DiversityCapExceeded(deposit.body.agent_passport_key_hash.clone()),
            ));
        }
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_scarcity_buckets
                (reputation_epoch, window_id, treaty_id, subject_class_namespace,
                 subject_class, count)
            VALUES (?1, ?2, ?3, ?4, ?5, 1)
            ON CONFLICT(reputation_epoch, window_id, treaty_id,
                subject_class_namespace, subject_class)
            DO UPDATE SET count = count + 1
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
            ],
        )?;
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_pair_buckets
                (reputation_epoch, window_id, treaty_id, subject_class_namespace,
                 subject_class, kernel_id, passport_key_hash, count)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)
            ON CONFLICT(reputation_epoch, window_id, treaty_id,
                subject_class_namespace, subject_class, kernel_id, passport_key_hash)
            DO UPDATE SET count = count + 1
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
        )?;
    }

    for admission in &admissions {
        let passport_seen = passport_seen(tx, deposit, admission)?;
        let passport_count = passport_count(tx, deposit, admission)?;
        let projected = passport_count.saturating_add(u64::from(!passport_seen));
        if projected > sqrt_passport_cap(context.active_peers_in_treaty) {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::SqrtNPassportCapExceeded(deposit.body.kernel_id.clone()),
            ));
        }
        tx.execute(
            r#"
            INSERT INTO chio_pheromone_passport_caps_v2
                (reputation_epoch, window_id, treaty_id, subject_class_namespace,
                 subject_class, kernel_id, passport_key_hash)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(reputation_epoch, window_id, treaty_id,
                subject_class_namespace, subject_class, kernel_id, passport_key_hash)
            DO NOTHING
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
        )?;
    }

    let passport_json = serde_json::to_string(&passport)?;
    tx.execute(
        r#"
        INSERT INTO chio_pheromone_passport_admissions
            (kernel_id, passport_key_hash, json)
        VALUES (?1, ?2, ?3)
        ON CONFLICT(kernel_id, passport_key_hash)
        DO UPDATE SET json = excluded.json
        "#,
        params![
            passport.kernel_id,
            agent_passport_key_hash(&passport.public_key),
            passport_json,
        ],
    )?;

    let json = serde_json::to_string(deposit)?;
    tx.execute(
        r#"
        INSERT INTO chio_pheromone_deposits
            (deposit_sha256, kernel_id, passport_key_hash, subject_class,
             subject_class_namespace, timestamp_unix_ms, json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        ON CONFLICT(deposit_sha256) DO NOTHING
        "#,
        params![
            canonical_sha256(deposit)?,
            deposit.body.kernel_id,
            deposit.body.agent_passport_key_hash,
            deposit.body.subject_class,
            deposit.body.subject_class_namespace,
            i64_from_u64(deposit.body.timestamp_unix_ms, "timestamp_unix_ms")?,
            json,
        ],
    )?;
    Ok(())
}

impl PheromoneRuntimeStore for SqlitePheromoneRuntimeStore {
    fn receive_batch(
        &self,
        batch: &PheromoneGossipBatch,
        policy: &PheromoneTransitPolicy,
        config: &PheromoneReceiverConfig,
        resolver: &dyn WorkflowContextResolver,
    ) -> Result<PheromoneReceiveReport, PheromoneRuntimeError> {
        let batch_sha256 = canonical_sha256(batch)?;
        let mut frames = Vec::new();
        let verification_context = PheromoneGossipBatchVerificationContext {
            now_unix_ms: config.validation_context.now_unix_ms,
            recipient_kernel_id: config.recipient_kernel_id.clone(),
            authenticated_sender_kernel_id: config.authenticated_sender_kernel_id.clone(),
        };
        let mut conn = self.conn.lock()?;
        let tx = conn.transaction()?;
        if let Err(error) = verify_pheromone_gossip_batch_envelope(batch, &verification_context) {
            frames.push(PheromoneFrameReport {
                frame_index: 0,
                accepted: false,
                code: error.code().to_string(),
                detail: error.to_string(),
                deposit_nonce: None,
            });
            let report = build_receive_report(config, batch_sha256, frames);
            record_receive_report_tx(&tx, &report)?;
            tx.commit()?;
            return Ok(report);
        }

        for (index, frame) in batch.frames.iter().enumerate() {
            let preflight = verify_pheromone_gossip_frame_for_batch(
                frame,
                batch,
                policy,
                &verification_context,
            )
            .map_err(PheromoneRuntimeError::from)
            .and_then(|()| {
                frame
                    .deposit
                    .body
                    .workflow_context
                    .as_ref()
                    .map_or(Ok(()), |context| resolver.resolve(context))
            });
            let result = match preflight {
                Ok(()) => {
                    let savepoint = format!("frame_{index}");
                    tx.execute_batch(&format!("SAVEPOINT {savepoint}"))?;
                    let admission = admit_deposit_scoped_tx(
                        &tx,
                        &frame.deposit,
                        &config.validation_context,
                        Some(&frame.treaty_id),
                    );
                    match admission {
                        Ok(()) => {
                            tx.execute_batch(&format!("RELEASE SAVEPOINT {savepoint}"))?;
                            Ok(())
                        }
                        Err(error) => {
                            tx.execute_batch(&format!(
                                "ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint}"
                            ))?;
                            Err(error)
                        }
                    }
                }
                Err(error) => Err(error),
            };
            match result {
                Ok(()) => frames.push(PheromoneFrameReport {
                    frame_index: index,
                    accepted: true,
                    code: "accepted".to_string(),
                    detail: "accepted".to_string(),
                    deposit_nonce: Some(frame.deposit.body.nonce.clone()),
                }),
                Err(error) => frames.push(PheromoneFrameReport {
                    frame_index: index,
                    accepted: false,
                    code: frame_failure_code(&error).to_string(),
                    detail: error.to_string(),
                    deposit_nonce: Some(frame.deposit.body.nonce.clone()),
                }),
            }
        }
        let report = build_receive_report(config, batch_sha256, frames);
        record_receive_report_tx(&tx, &report)?;
        tx.commit()?;
        Ok(report)
    }

    fn admit_deposit(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
    ) -> Result<(), PheromoneRuntimeError> {
        self.admit_deposit_scoped(deposit, context, None)
    }

    fn admit_deposit_for_treaty(
        &self,
        deposit: PheromoneDeposit,
        context: &PheromoneValidationContext,
        treaty_id: &str,
    ) -> Result<(), PheromoneRuntimeError> {
        self.admit_deposit_scoped(deposit, context, Some(treaty_id))
    }

    fn query_deposits(
        &self,
        subject_class: Option<&str>,
        treaty_id: Option<&str>,
    ) -> Result<Vec<PheromoneDeposit>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt =
            conn.prepare("SELECT json FROM chio_pheromone_deposits ORDER BY deposit_sha256")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut deposits = Vec::new();
        for row in rows {
            let deposit: PheromoneDeposit = serde_json::from_str(&row?)?;
            if subject_class
                .map(|value| value == deposit.body.subject_class)
                .unwrap_or(true)
                && treaty_id
                    .map(|value| {
                        deposit
                            .body
                            .treaty_scope
                            .iter()
                            .any(|treaty| treaty == value)
                    })
                    .unwrap_or(true)
            {
                deposits.push(deposit);
            }
        }
        Ok(deposits)
    }

    fn query_concentration(
        &self,
        subject_class: &str,
        subject_class_namespace: &str,
        now_unix_ms: u64,
        reputation_epoch: u64,
        context: &PheromoneValidationContext,
        peer_weight: &dyn PeerWeightProvider,
    ) -> Result<PheromoneConcentration, PheromoneRuntimeError> {
        if !context.known_reputation_epochs.contains(&reputation_epoch) {
            return Err(PheromoneRuntimeError::Pheromone(
                PheromoneError::UnknownReputationEpoch(reputation_epoch),
            ));
        }
        let query_context = self.query_context_with_stored_passports(context)?;
        let deposits = self.query_deposits(Some(subject_class), None)?;
        let mut total_strength = 0.0;
        let mut unweighted_total_strength = 0.0;
        let mut peak_confidence = 0.0;
        let mut origins = BTreeSet::new();
        let mut treaties = BTreeSet::new();
        for deposit in deposits
            .iter()
            .filter(|deposit| deposit.body.subject_class_namespace == subject_class_namespace)
        {
            let strength = strength_at(deposit, now_unix_ms);
            if let Some(floor) = deposit.body.evaporation_floor {
                if strength < floor {
                    continue;
                }
            }
            let weight = peer_weight.weight(&deposit.body.kernel_id, reputation_epoch)?;
            let discount = newcomer_discount_for_deposit(
                deposit,
                &query_context,
                reputation_epoch,
                subject_class_namespace,
                subject_class,
            )?;
            total_strength += strength * weight * discount;
            unweighted_total_strength += strength;
            if deposit.body.confidence > peak_confidence {
                peak_confidence = deposit.body.confidence;
            }
            origins.insert((
                deposit.body.kernel_id.clone(),
                deposit.body.agent_passport_key_hash.clone(),
            ));
            for treaty in &deposit.body.treaty_scope {
                treaties.insert(treaty.clone());
            }
        }
        Ok(PheromoneConcentration {
            schema: PHEROMONE_CONCENTRATION_SCHEMA.to_string(),
            subject_class: subject_class.to_string(),
            subject_class_namespace: subject_class_namespace.to_string(),
            total_strength,
            unweighted_total_strength,
            distinct_origin_pairs: origins.len() as u64,
            peak_confidence,
            reputation_epoch,
            evaluated_at_unix_ms: now_unix_ms,
            treaty_scopes: treaties.into_iter().collect(),
        })
    }

    fn record_receive_report(
        &self,
        report: &PheromoneReceiveReport,
    ) -> Result<(), PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        record_receive_report_connection(&conn, report)?;
        Ok(())
    }

    fn receive_reports(&self) -> Result<Vec<PheromoneReceiveReport>, PheromoneRuntimeError> {
        let conn = self.conn.lock()?;
        let mut stmt = conn.prepare(
            "SELECT json FROM chio_pheromone_receive_reports ORDER BY received_at_unix_ms",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut reports = Vec::new();
        for row in rows {
            reports.push(serde_json::from_str(&row?)?);
        }
        Ok(reports)
    }
}

/// Additive migration: the recovery columns + index for verdict recovery.
/// `batch_sha256` keys the recovery lookup; `sender_kernel_id` SCOPES it to the
/// authenticated sender, so a lookup for a batch that several senders recorded reports
/// for (for example a wrong-sender replay that recorded a rejected verdict alongside the
/// correct sender's crash-recovery report) returns the CORRECT sender's row rather than
/// an arbitrary one. Existing rows keep NULL columns and are not recoverable-by-batch
/// (acceptable: only reports written after the migration need recovery). Idempotent.
pub(crate) fn ensure_receive_report_recovery_columns(
    conn: &rusqlite::Connection,
) -> Result<(), PheromoneRuntimeError> {
    let mut existing_columns = std::collections::HashSet::new();
    let mut stmt = conn.prepare("PRAGMA table_info(chio_pheromone_receive_reports)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        existing_columns.insert(name);
    }
    drop(rows);
    drop(stmt);
    if !existing_columns.contains("batch_sha256") {
        conn.execute(
            "ALTER TABLE chio_pheromone_receive_reports ADD COLUMN batch_sha256 TEXT",
            [],
        )?;
    }
    if !existing_columns.contains("sender_kernel_id") {
        conn.execute(
            "ALTER TABLE chio_pheromone_receive_reports ADD COLUMN sender_kernel_id TEXT",
            [],
        )?;
    }
    // Composite index so the sender-scoped recovery lookup is a single index probe.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_receive_reports_batch_sender \
         ON chio_pheromone_receive_reports (batch_sha256, sender_kernel_id)",
        [],
    )?;
    Ok(())
}

fn scarcity_bucket_count(
    tx: &rusqlite::Transaction<'_>,
    admission: &PheromoneScarcityAdmission,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx
        .query_row(
            r#"
            SELECT count FROM chio_pheromone_scarcity_buckets
            WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
              AND subject_class_namespace = ?4 AND subject_class = ?5
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("scarcity count is negative".to_string()))
}

fn pair_bucket_count(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx
        .query_row(
            r#"
            SELECT count FROM chio_pheromone_pair_buckets
            WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
              AND subject_class_namespace = ?4 AND subject_class = ?5
              AND kernel_id = ?6 AND passport_key_hash = ?7
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("pair bucket count is negative".to_string()))
}

fn passport_seen(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> Result<bool, PheromoneRuntimeError> {
    Ok(tx
        .query_row(
            r#"
            SELECT 1 FROM chio_pheromone_passport_caps_v2
            WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
              AND subject_class_namespace = ?4 AND subject_class = ?5
              AND kernel_id = ?6 AND passport_key_hash = ?7
            "#,
            params![
                i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
                admission.window_id,
                admission.treaty_id,
                admission.subject_class_namespace,
                admission.subject_class,
                deposit.body.kernel_id,
                deposit.body.agent_passport_key_hash,
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn passport_count(
    tx: &rusqlite::Transaction<'_>,
    deposit: &PheromoneDeposit,
    admission: &PheromoneScarcityAdmission,
) -> Result<u64, PheromoneRuntimeError> {
    let count = tx.query_row(
        r#"
        SELECT COUNT(*) FROM chio_pheromone_passport_caps_v2
        WHERE reputation_epoch = ?1 AND window_id = ?2 AND treaty_id = ?3
          AND subject_class_namespace = ?4 AND subject_class = ?5 AND kernel_id = ?6
        "#,
        params![
            i64_from_u64(admission.reputation_epoch, "reputation_epoch")?,
            admission.window_id,
            admission.treaty_id,
            admission.subject_class_namespace,
            admission.subject_class,
            deposit.body.kernel_id,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    u64::try_from(count)
        .map_err(|_| PheromoneRuntimeError::Sqlite("passport count is negative".to_string()))
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, PheromoneRuntimeError> {
    i64::try_from(value).map_err(|_| {
        PheromoneRuntimeError::InvalidField(format!("{field} does not fit signed SQLite integer"))
    })
}

fn record_receive_report_tx(
    tx: &rusqlite::Transaction<'_>,
    report: &PheromoneReceiveReport,
) -> Result<(), PheromoneRuntimeError> {
    let json = serde_json::to_string(report)?;
    tx.execute(
        r#"
        INSERT OR REPLACE INTO chio_pheromone_receive_reports
            (report_sha256, received_at_unix_ms, json, batch_sha256, sender_kernel_id)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            canonical_sha256(report)?,
            i64_from_u64(report.received_at_unix_ms, "received_at_unix_ms")?,
            json,
            report.batch_sha256,
            report.authenticated_sender_kernel_id,
        ],
    )?;
    Ok(())
}

fn record_receive_report_connection(
    conn: &Connection,
    report: &PheromoneReceiveReport,
) -> Result<(), PheromoneRuntimeError> {
    let json = serde_json::to_string(report)?;
    conn.execute(
        r#"
        INSERT OR REPLACE INTO chio_pheromone_receive_reports
            (report_sha256, received_at_unix_ms, json, batch_sha256, sender_kernel_id)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#,
        params![
            canonical_sha256(report)?,
            i64_from_u64(report.received_at_unix_ms, "received_at_unix_ms")?,
            json,
            report.batch_sha256,
            report.authenticated_sender_kernel_id,
        ],
    )?;
    Ok(())
}

fn passport_identity(passport: &PassportAdmission) -> (String, String) {
    (
        passport.kernel_id.clone(),
        agent_passport_key_hash(&passport.public_key),
    )
}

fn strength_at(deposit: &PheromoneDeposit, now_unix_ms: u64) -> f64 {
    if now_unix_ms <= deposit.body.timestamp_unix_ms {
        return deposit.body.confidence;
    }
    let elapsed_secs = now_unix_ms.saturating_sub(deposit.body.timestamp_unix_ms) as f64 / 1000.0;
    deposit.body.confidence * 2_f64.powf(-(elapsed_secs / deposit.body.decay_half_life_secs))
}

fn sqrt_passport_cap(active_peers: u64) -> u64 {
    (active_peers.max(1) as f64).sqrt().ceil() as u64
}
