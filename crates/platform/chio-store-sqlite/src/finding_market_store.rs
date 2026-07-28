//! Durable storage for the cognition finding market: publication,
//! discovery, collateral backing, fee accounting, and venue admission.
//!
//! Five tables back the cognition market: `findings` (the exact accepted
//! canonical artifact bytes plus the descriptor index), `recipe_blobs`
//! (content-addressed replay-recipe preimages, retained without
//! deletion), `collateral_allocations` (live, exclusive, non-reusable
//! backing allocations), `fee_events` (the durable idempotency fence for
//! evidenced fee collection), and `admissions` (venue-signed admission
//! bundles). Writes run under
//! `TransactionBehavior::Immediate` behind the serving-owner fence; reads
//! run `Deferred`; a commit whose outcome cannot be observed surfaces as
//! outcome-unknown and poisons the owner exactly like the sibling stores.
//!
//! The store is not an authority boundary: pinned-authority signature
//! verification over backing and admission envelopes belongs to the
//! surfaces that call in here. The store enforces the durable invariants
//! those surfaces rely on (exact-bytes retention, digest agreement between
//! raw envelope bytes and their parsed bodies, allocation exclusivity and
//! single consumption, fee idempotency, and the atomic activation
//! transaction).

use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::capability::scope::MonetaryAmount;
use chio_core::sha256_hex;
use chio_finding::{
    FindingAdmission, FindingBondBacking, FindingFeeEvent, SignedFindingAdmission,
    SignedFindingBondBacking,
};
use chio_kernel::admission_operation::AdmissionOperationStoreError;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use thiserror::Error;

use crate::admission_operation_store::verify_active_owner;
use crate::serving_owner::SqliteServingOwner;

const FINDING_MARKET_SCHEMA_KEY: &str = "finding_market";
pub(crate) const FINDING_MARKET_SUPPORTED_SCHEMA_VERSION: i32 = 1;
const FINDING_MARKET_SCHEMA_ANCHORS: &[&str] =
    &["findings", "admission_operations", "chio_serving_owner"];
const FINDING_MARKET_SCHEMA: &str = include_str!("finding_market_store.sql");

/// Publish bodies are capped at 256 KiB (the `MAX_PERSISTED_OPERATION_BYTES`
/// scale precedent), so a persisted finding artifact never exceeds it.
const MAX_FINDING_ARTIFACT_BYTES: usize = 256 * 1024;
/// Recipe uploads are capped at 1 MiB at the surface; the store holds the
/// same bound so an oversized preimage cannot arrive through another door.
const MAX_RECIPE_BLOB_BYTES: usize = 1024 * 1024;
/// Signed backing and admission envelopes share the publish-body scale.
const MAX_ENVELOPE_BYTES: usize = 256 * 1024;
/// Topic byte-length bound for the descriptor index and the publish
/// path that populates it.
const MAX_TOPIC_BYTES: usize = 120;
/// Search page clamp, matching the page-size bound shared by the other
/// paginated query surfaces (for example
/// `chio_listing::MAX_GENERIC_LISTING_LIMIT`).
const MAX_SEARCH_PAGE: usize = 200;

/// Errors surfaced by the finding-market store. Fail-closed: every
/// rejection denies the mutation and rolls the transaction back.
#[derive(Debug, Error)]
pub enum FindingMarketStoreError {
    #[error("finding market store is unavailable: {0}")]
    Unavailable(String),
    #[error("finding market store fence rejected the caller")]
    Fenced,
    #[error("finding market record not found")]
    NotFound,
    #[error("finding market conflict: {0}")]
    Conflict(String),
    #[error("finding market invariant violated: {0}")]
    Invariant(String),
    #[error("finding market commit outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

/// Input for one published finding: the exact accepted canonical artifact
/// bytes plus the descriptor fields the search index serves.
#[derive(Debug, Clone, Copy)]
pub struct FindingRecordInput<'a> {
    pub finding_id: &'a str,
    /// Exact canonical artifact bytes as accepted at publish; served
    /// verbatim by [`SqliteFindingMarketStore::get_finding_bytes`].
    pub artifact_json: &'a str,
    pub topic: &'a str,
    pub context_sha256: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Whether a put created the row or replayed an identical prior put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPutOutcome {
    Inserted,
    ExactReplay,
}

/// One descriptor row from the search index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSearchRow {
    pub finding_id: String,
    pub artifact_sha256: String,
    pub topic: String,
    pub context_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Lifecycle of a collateral allocation. `live` is the only state that
/// backs an admission; every exit from `live` is final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingAllocationState {
    Live,
    Consumed,
    Expired,
    Released,
}

/// Snapshot of one collateral allocation: the parsed backing body, its
/// exact envelope digest, the lifecycle state, and the venue trusted
/// time at which the collateral authority's registration was accepted.
/// Callers compare this against a report's timestamp to confirm the
/// backing predates the report it covers.
#[derive(Debug, Clone)]
pub struct FindingAllocationSnapshot {
    pub backing: FindingBondBacking,
    pub backing_envelope_sha256: String,
    pub state: FindingAllocationState,
    pub accepted_at: u64,
}

/// Lifecycle of a durable fee event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingFeeState {
    Intent,
    Reconciled,
    Failed,
}

/// Parameters fencing one fee charge before dispatch. The idempotency
/// key derives from the schedule digest, event, finding, and listing;
/// every other field must be identical on replay.
#[derive(Debug, Clone, Copy)]
pub struct FindingFeeIntent<'a> {
    pub fee_schedule_envelope_sha256: &'a str,
    pub event: &'a FindingFeeEvent,
    pub finding_id: &'a str,
    pub listing_id: &'a str,
    pub payer: &'a str,
    pub amount: &'a MonetaryAmount,
    pub pool_principal_id: &'a str,
    pub rail_destination: &'a str,
    pub instruction_sha256: &'a str,
}

/// One durable fee event row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingFeeEventRecord {
    pub idempotency_key: String,
    pub fee_schedule_envelope_sha256: String,
    pub event: FindingFeeEvent,
    pub finding_id: String,
    pub listing_id: String,
    pub payer: String,
    pub amount_units: u64,
    pub currency: String,
    pub pool_principal_id: String,
    pub rail_destination: String,
    pub instruction_sha256: String,
    pub observation_sha256: Option<String>,
    pub state: FindingFeeState,
}

/// Whether activation performed the transaction or replayed a prior
/// identical success as a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingActivationOutcome {
    Activated,
    ExactReplay,
}

/// The current admission for a finding: exact envelope bytes plus the
/// data a reader needs to re-check collateral liveness.
#[derive(Debug, Clone)]
pub struct FindingAdmissionSnapshot {
    pub admission_id: String,
    pub listing_id: String,
    pub envelope_json: String,
    pub envelope_sha256: String,
    pub expires_at: u64,
    pub activated_at: u64,
    pub backing_allocation_id: String,
    pub allocation_state: FindingAllocationState,
}

/// Deterministic idempotency key for one fee event:
/// `fee_schedule_envelope_sha256 : event kind : epoch index : finding_id :
/// listing_id`. Every segment before `listing_id` comes from a fixed-width
/// or closed vocabulary, so placing the only free-form segment last keeps
/// the join unambiguous.
#[must_use]
pub fn finding_fee_idempotency_key(
    fee_schedule_envelope_sha256: &str,
    event: &FindingFeeEvent,
    finding_id: &str,
    listing_id: &str,
) -> String {
    let (kind, epoch_index) = fee_event_parts(event);
    format!("{fee_schedule_envelope_sha256}:{kind}:{epoch_index}:{finding_id}:{listing_id}")
}

const fn fee_event_parts(event: &FindingFeeEvent) -> (&'static str, u64) {
    match event {
        FindingFeeEvent::Publication => ("publication", 0),
        FindingFeeEvent::ParticipationEpoch { epoch_index } => {
            ("participation_epoch", *epoch_index)
        }
    }
}

#[derive(Clone)]
pub struct SqliteFindingMarketStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFindingMarketStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FindingMarketStoreError> {
        self.connection.lock().map_err(|_| {
            FindingMarketStoreError::Unavailable("sqlite finding market lock poisoned".to_owned())
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingMarketStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingMarketStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
    ) -> Result<Transaction<'a>, FindingMarketStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, None).map_err(admission_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FindingMarketStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), FindingMarketStoreError> {
        transaction.commit().map_err(|error| {
            FindingMarketStoreError::OutcomeUnknown(
                self.serving_owner
                    .outcome_unknown(format!(
                        "sqlite finding market commit outcome is unknown: {error}"
                    ))
                    .to_string(),
            )
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), FindingMarketStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| FindingMarketStoreError::Unavailable(error.to_string()))
    }

    /// Persist the exact accepted canonical artifact bytes of one finding
    /// plus its descriptor row. Idempotent on a byte-identical replay;
    /// conflicting bytes (or a conflicting descriptor) for the same id
    /// reject.
    pub fn put_finding(
        &self,
        finding: &FindingRecordInput<'_>,
        indexed_at: u64,
    ) -> Result<FindingPutOutcome, FindingMarketStoreError> {
        require_hex64(finding.finding_id, "finding_id")?;
        require_hex64(finding.context_sha256, "context_sha256")?;
        if finding.topic.is_empty() || finding.topic.len() > MAX_TOPIC_BYTES {
            return Err(invariant("finding topic byte length is out of bounds"));
        }
        if finding.artifact_json.is_empty()
            || finding.artifact_json.len() > MAX_FINDING_ARTIFACT_BYTES
        {
            return Err(invariant("finding artifact byte length is out of bounds"));
        }
        if finding.issued_at >= finding.expires_at {
            return Err(invariant("finding expiry does not follow issuance"));
        }
        if indexed_at == 0 {
            return Err(invariant("finding indexed_at must be nonzero"));
        }
        let artifact_sha256 = sha256_hex(finding.artifact_json.as_bytes());
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_finding_row_tx(&transaction, finding.finding_id)? {
            if existing.artifact_json == finding.artifact_json
                && existing.topic == finding.topic
                && existing.context_sha256 == finding.context_sha256
                && existing.issued_at == finding.issued_at
                && existing.expires_at == finding.expires_at
            {
                return Ok(FindingPutOutcome::ExactReplay);
            }
            return Err(FindingMarketStoreError::Conflict(
                "finding id is already bound to different bytes".to_owned(),
            ));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO findings (
                    finding_id, artifact_json, artifact_sha256, topic,
                    context_sha256, issued_at, expires_at, indexed_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    finding.finding_id,
                    finding.artifact_json,
                    &artifact_sha256,
                    finding.topic,
                    finding.context_sha256,
                    sqlite_i64(finding.issued_at, "issued_at")?,
                    sqlite_i64(finding.expires_at, "expires_at")?,
                    sqlite_i64(indexed_at, "indexed_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("finding insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingPutOutcome::Inserted)
    }

    /// Serve the exact stored artifact bytes verbatim, re-checking the
    /// stored digest on the read path.
    pub fn get_finding_bytes(
        &self,
        finding_id: &str,
    ) -> Result<Option<String>, FindingMarketStoreError> {
        require_hex64(finding_id, "finding_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        Ok(load_finding_row_tx(&transaction, finding_id)?.map(|row| row.artifact_json))
    }

    /// One page of descriptor rows live at `now` (`issued_at <= now <
    /// expires_at`, both bounds), ordered by `finding_id` ascending with
    /// exclusive start-after cursor semantics. An unfiltered scan is
    /// rejected fail-closed; `limit` clamps to 1..=200.
    pub fn search_findings(
        &self,
        topic_prefix: Option<&str>,
        context_sha256: Option<&str>,
        after_finding_id: Option<&str>,
        limit: usize,
        now: u64,
    ) -> Result<Vec<FindingSearchRow>, FindingMarketStoreError> {
        if topic_prefix.is_none() && context_sha256.is_none() {
            return Err(invariant("finding search requires at least one filter"));
        }
        if let Some(prefix) = topic_prefix {
            if prefix.is_empty() || prefix.len() > MAX_TOPIC_BYTES {
                return Err(invariant(
                    "finding topic prefix byte length is out of bounds",
                ));
            }
        }
        if let Some(context) = context_sha256 {
            require_hex64(context, "context_sha256")?;
        }
        if let Some(cursor) = after_finding_id {
            require_hex64(cursor, "after_finding_id")?;
        }
        let limit = limit.clamp(1, MAX_SEARCH_PAGE);
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        // `substr(topic, 1, length(?)) = ?` is exact string-prefix match:
        // both sides count characters, and for valid UTF-8 a character
        // prefix is a byte prefix.
        let mut statement = transaction
            .prepare(
                r#"
                SELECT finding_id, artifact_sha256, topic, context_sha256,
                       issued_at, expires_at
                FROM findings
                WHERE issued_at <= ?1 AND ?1 < expires_at
                  AND (?2 IS NULL OR substr(topic, 1, length(?2)) = ?2)
                  AND (?3 IS NULL OR context_sha256 = ?3)
                  AND (?4 IS NULL OR finding_id > ?4)
                ORDER BY finding_id ASC
                LIMIT ?5
                "#,
            )
            .map_err(sqlite_error)?;
        let rows = statement
            .query_map(
                params![
                    sqlite_i64(now, "now")?,
                    topic_prefix,
                    context_sha256,
                    after_finding_id,
                    sqlite_i64(u64::try_from(limit).unwrap_or(u64::MAX), "limit")?,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        rows.into_iter()
            .map(
                |(finding_id, artifact_sha256, topic, context, issued_at, expires_at)| {
                    Ok(FindingSearchRow {
                        finding_id,
                        artifact_sha256,
                        topic,
                        context_sha256: context,
                        issued_at: stored_u64(issued_at, "issued_at")?,
                        expires_at: stored_u64(expires_at, "expires_at")?,
                    })
                },
            )
            .collect()
    }

    /// Persist a content-addressed recipe preimage, idempotently by
    /// digest. The digest is recomputed server-side and must equal the
    /// claimed key; the store enforces retention, so there is no delete.
    pub fn put_recipe_blob(
        &self,
        canonical_sha256: &str,
        bytes: &[u8],
        stored_at: u64,
    ) -> Result<FindingPutOutcome, FindingMarketStoreError> {
        require_hex64(canonical_sha256, "canonical_sha256")?;
        if bytes.is_empty() || bytes.len() > MAX_RECIPE_BLOB_BYTES {
            return Err(invariant("recipe blob byte length is out of bounds"));
        }
        if sha256_hex(bytes) != canonical_sha256 {
            return Err(FindingMarketStoreError::Conflict(
                "recipe blob bytes do not match the claimed canonical digest".to_owned(),
            ));
        }
        if stored_at == 0 {
            return Err(invariant("recipe stored_at must be nonzero"));
        }
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT blob_bytes FROM recipe_blobs WHERE canonical_sha256 = ?1",
                [canonical_sha256],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if let Some(existing) = existing {
            if existing == bytes {
                return Ok(FindingPutOutcome::ExactReplay);
            }
            return Err(invariant("recipe blob digest collision"));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO recipe_blobs (canonical_sha256, blob_bytes, stored_at)
                VALUES (?1, ?2, ?3)
                "#,
                params![canonical_sha256, bytes, sqlite_i64(stored_at, "stored_at")?],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("recipe blob insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingPutOutcome::Inserted)
    }

    /// Load a retained recipe preimage by digest, re-checking the digest
    /// on the read path.
    pub fn get_recipe_blob(
        &self,
        canonical_sha256: &str,
    ) -> Result<Option<Vec<u8>>, FindingMarketStoreError> {
        require_hex64(canonical_sha256, "canonical_sha256")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let bytes: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT blob_bytes FROM recipe_blobs WHERE canonical_sha256 = ?1",
                [canonical_sha256],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        match bytes {
            Some(bytes) if sha256_hex(&bytes) == canonical_sha256 => Ok(Some(bytes)),
            Some(_) => Err(invariant("stored recipe blob failed its digest re-check")),
            None => Ok(None),
        }
    }

    /// Register one live collateral allocation from a collateral-authority
    /// backing envelope. `accepted_at` is the venue trusted time of
    /// acceptance. The raw envelope bytes must parse to exactly the
    /// supplied backing body; pinned-authority signature verification
    /// is the caller's boundary. Exclusivity: at most one live allocation
    /// per (seller, finding, listing), and an allocation id registers
    /// exactly once whatever its state, so an already-encumbered or reused
    /// allocation rejects.
    pub fn register_allocation(
        &self,
        backing_envelope_json: &str,
        backing: &FindingBondBacking,
        accepted_at: u64,
    ) -> Result<(), FindingMarketStoreError> {
        backing
            .validate()
            .map_err(|error| invariant(format!("bond backing rejected: {error}")))?;
        if backing_envelope_json.is_empty() || backing_envelope_json.len() > MAX_ENVELOPE_BYTES {
            return Err(invariant("backing envelope byte length is out of bounds"));
        }
        let parsed: SignedFindingBondBacking = serde_json::from_str(backing_envelope_json)
            .map_err(|error| invariant(format!("backing envelope bytes are invalid: {error}")))?;
        if parsed.body != *backing {
            return Err(invariant(
                "backing envelope bytes do not carry the supplied backing body",
            ));
        }
        if accepted_at == 0 || accepted_at >= backing.expires_at {
            return Err(FindingMarketStoreError::Conflict(
                "backing allocation is stale at acceptance time".to_owned(),
            ));
        }
        let backing_envelope_sha256 = sha256_hex(backing_envelope_json.as_bytes());
        let seller_hex = backing.seller.to_hex();
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing: Option<String> = transaction
            .query_row(
                "SELECT state FROM collateral_allocations WHERE allocation_id = ?1",
                [backing.allocation_id.as_str()],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if existing.is_some() {
            return Err(FindingMarketStoreError::Conflict(
                "collateral allocation id was already registered".to_owned(),
            ));
        }
        let live_for_listing: i64 = transaction
            .query_row(
                r#"
                SELECT COUNT(*) FROM collateral_allocations
                WHERE seller_hex = ?1 AND finding_id = ?2 AND listing_id = ?3
                  AND state = 'live'
                "#,
                params![&seller_hex, &backing.finding_id, &backing.listing_id],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if live_for_listing != 0 {
            return Err(FindingMarketStoreError::Conflict(
                "a live collateral allocation already backs this finding listing".to_owned(),
            ));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO collateral_allocations (
                    allocation_id, seller_hex, finding_id, listing_id,
                    backing_envelope_sha256, backing_envelope_json, currency,
                    locked_units, maximum_sale_exposure_units, expires_at,
                    accepted_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'live')
                "#,
                params![
                    &backing.allocation_id,
                    &seller_hex,
                    &backing.finding_id,
                    &backing.listing_id,
                    &backing_envelope_sha256,
                    backing_envelope_json,
                    &backing.locked_amount.currency,
                    sqlite_i64(backing.locked_amount.units, "locked_units")?,
                    sqlite_i64(
                        backing.maximum_sale_exposure.units,
                        "maximum_sale_exposure_units"
                    )?,
                    sqlite_i64(backing.expires_at, "expires_at")?,
                    sqlite_i64(accepted_at, "accepted_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("allocation insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(())
    }

    /// Consume a live allocation exactly once; a second call rejects.
    pub fn consume_allocation(&self, allocation_id: &str) -> Result<(), FindingMarketStoreError> {
        require_hex64(allocation_id, "allocation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        consume_allocation_tx(&transaction, allocation_id)?;
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(())
    }

    /// Snapshot one allocation: parsed backing, state, and acceptance
    /// trusted time.
    pub fn get_allocation(
        &self,
        allocation_id: &str,
    ) -> Result<Option<FindingAllocationSnapshot>, FindingMarketStoreError> {
        require_hex64(allocation_id, "allocation_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_allocation_snapshot_tx(&transaction, allocation_id)
    }

    /// Fence one fee charge before dispatch. Absent key inserts an
    /// `intent` row. An identical retry returns the existing row
    /// whatever its state; conflicting parameters under the same key
    /// reject.
    pub fn begin_fee_intent(
        &self,
        intent: &FindingFeeIntent<'_>,
    ) -> Result<FindingFeeEventRecord, FindingMarketStoreError> {
        require_hex64(
            intent.fee_schedule_envelope_sha256,
            "fee_schedule_envelope_sha256",
        )?;
        require_hex64(intent.finding_id, "finding_id")?;
        require_hex64(intent.instruction_sha256, "instruction_sha256")?;
        require_non_empty(intent.listing_id, "listing_id")?;
        require_non_empty(intent.payer, "payer")?;
        require_non_empty(intent.pool_principal_id, "pool_principal_id")?;
        require_non_empty(intent.rail_destination, "rail_destination")?;
        require_currency(&intent.amount.currency)?;
        if intent.amount.units == 0 {
            return Err(invariant("fee amount must be nonzero"));
        }
        let key = finding_fee_idempotency_key(
            intent.fee_schedule_envelope_sha256,
            intent.event,
            intent.finding_id,
            intent.listing_id,
        );
        let (event_kind, epoch_index) = fee_event_parts(intent.event);
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(existing) = load_fee_event_tx(&transaction, &key)? {
            if existing.payer == intent.payer
                && existing.amount_units == intent.amount.units
                && existing.currency == intent.amount.currency
                && existing.pool_principal_id == intent.pool_principal_id
                && existing.rail_destination == intent.rail_destination
                && existing.instruction_sha256 == intent.instruction_sha256
            {
                return Ok(existing);
            }
            return Err(FindingMarketStoreError::Conflict(
                "conflicting fee parameters under an existing idempotency key".to_owned(),
            ));
        }
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO fee_events (
                    idempotency_key, fee_schedule_envelope_sha256, event_kind,
                    epoch_index, finding_id, listing_id, payer, amount_units,
                    currency, pool_principal_id, rail_destination,
                    instruction_sha256, observation_sha256, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, 'intent')
                "#,
                params![
                    &key,
                    intent.fee_schedule_envelope_sha256,
                    event_kind,
                    sqlite_i64(epoch_index, "epoch_index")?,
                    intent.finding_id,
                    intent.listing_id,
                    intent.payer,
                    sqlite_i64(intent.amount.units, "amount_units")?,
                    &intent.amount.currency,
                    intent.pool_principal_id,
                    intent.rail_destination,
                    intent.instruction_sha256,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("fee intent insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        load_fee_event_committed(&connection, &key)?
            .ok_or_else(|| invariant("fee intent disappeared after commit"))
    }

    /// Mark one fee event reconciled against its matched rail observation.
    /// The stored amount, currency, and rail destination are re-checked
    /// exactly; a mismatch rejects without touching the row. Reconciling
    /// an already-reconciled event with the same observation is a no-op.
    pub fn mark_fee_reconciled(
        &self,
        idempotency_key: &str,
        observation_sha256: &str,
        amount: &MonetaryAmount,
        rail_destination: &str,
    ) -> Result<(), FindingMarketStoreError> {
        require_hex64(observation_sha256, "observation_sha256")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing = load_fee_event_tx(&transaction, idempotency_key)?
            .ok_or(FindingMarketStoreError::NotFound)?;
        if existing.amount_units != amount.units
            || existing.currency != amount.currency
            || existing.rail_destination != rail_destination
        {
            return Err(FindingMarketStoreError::Conflict(
                "rail observation does not match the fee intent exactly".to_owned(),
            ));
        }
        match existing.state {
            FindingFeeState::Reconciled => {
                if existing.observation_sha256.as_deref() == Some(observation_sha256) {
                    return Ok(());
                }
                return Err(FindingMarketStoreError::Conflict(
                    "fee event was reconciled against a different observation".to_owned(),
                ));
            }
            FindingFeeState::Intent | FindingFeeState::Failed => {}
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE fee_events
                SET state = 'reconciled', observation_sha256 = ?2
                WHERE idempotency_key = ?1 AND state IN ('intent', 'failed')
                "#,
                params![idempotency_key, observation_sha256],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("fee reconciliation did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(())
    }

    /// Mark one fee event failed. Idempotent on an already-failed event;
    /// a reconciled event cannot fail.
    pub fn mark_fee_failed(&self, idempotency_key: &str) -> Result<(), FindingMarketStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        let existing = load_fee_event_tx(&transaction, idempotency_key)?
            .ok_or(FindingMarketStoreError::NotFound)?;
        match existing.state {
            FindingFeeState::Failed => return Ok(()),
            FindingFeeState::Reconciled => {
                return Err(FindingMarketStoreError::Conflict(
                    "a reconciled fee event cannot fail".to_owned(),
                ));
            }
            FindingFeeState::Intent => {}
        }
        let changed = transaction
            .execute(
                r#"
                UPDATE fee_events SET state = 'failed'
                WHERE idempotency_key = ?1 AND state = 'intent'
                "#,
                [idempotency_key],
            )
            .map_err(sqlite_error)?;
        if changed != 1 {
            return Err(invariant("fee failure did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(())
    }

    /// Load one fee event by its idempotency key.
    pub fn get_fee_event(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<FindingFeeEventRecord>, FindingMarketStoreError> {
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        load_fee_event_tx(&transaction, idempotency_key)
    }

    /// Highest participation epoch reconciled contiguously from epoch 0
    /// for one finding listing; a gap stops the count. `None` means epoch
    /// 0 itself is unpaid.
    pub fn paid_through_epoch(
        &self,
        finding_id: &str,
        listing_id: &str,
    ) -> Result<Option<u64>, FindingMarketStoreError> {
        require_hex64(finding_id, "finding_id")?;
        require_non_empty(listing_id, "listing_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let mut statement = transaction
            .prepare(
                r#"
                SELECT DISTINCT epoch_index FROM fee_events
                WHERE finding_id = ?1 AND listing_id = ?2
                  AND event_kind = 'participation_epoch' AND state = 'reconciled'
                ORDER BY epoch_index ASC
                "#,
            )
            .map_err(sqlite_error)?;
        let epochs = statement
            .query_map(params![finding_id, listing_id], |row| row.get::<_, i64>(0))
            .map_err(sqlite_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sqlite_error)?;
        let mut paid_through: Option<u64> = None;
        let mut expected: u64 = 0;
        for epoch in epochs {
            if stored_u64(epoch, "epoch_index")? != expected {
                break;
            }
            paid_through = Some(expected);
            expected = expected
                .checked_add(1)
                .ok_or_else(|| invariant("participation epoch index overflowed"))?;
        }
        Ok(paid_through)
    }

    /// The durable idempotent activation transaction. In ONE immediate
    /// transaction it (a) asserts every fee event named by the admission's
    /// fee terminals is reconciled with exactly the bound parameters,
    /// (b) consumes the named collateral allocation, and (c) inserts the
    /// admission active, superseding any prior active admission for the
    /// listing (and for the finding, so the by-finding admission surface
    /// stays single-valued). Any failed step rolls the whole transaction
    /// back: a failed charge cannot admit. Re-running with the same
    /// admission id after success replays as a no-op; after a failure the
    /// activation can retry.
    pub fn activate_listing(
        &self,
        admission_envelope_json: &str,
        admission: &FindingAdmission,
        activated_at: u64,
    ) -> Result<FindingActivationOutcome, FindingMarketStoreError> {
        admission
            .validate()
            .map_err(|error| invariant(format!("admission rejected: {error}")))?;
        if admission_envelope_json.is_empty() || admission_envelope_json.len() > MAX_ENVELOPE_BYTES
        {
            return Err(invariant("admission envelope byte length is out of bounds"));
        }
        let parsed: SignedFindingAdmission = serde_json::from_str(admission_envelope_json)
            .map_err(|error| invariant(format!("admission envelope bytes are invalid: {error}")))?;
        if parsed.body != *admission {
            return Err(invariant(
                "admission envelope bytes do not carry the supplied admission body",
            ));
        }
        if activated_at == 0 {
            return Err(invariant("activation time must be nonzero"));
        }
        let envelope_sha256 = sha256_hex(admission_envelope_json.as_bytes());
        let mut connection = self.connection()?;
        let transaction = self.begin_write(&mut connection)?;
        if let Some(stored) = load_admission_bytes_tx(&transaction, &admission.admission_id)? {
            if stored == admission_envelope_json {
                return Ok(FindingActivationOutcome::ExactReplay);
            }
            return Err(FindingMarketStoreError::Conflict(
                "admission id is already bound to different bytes".to_owned(),
            ));
        }
        let finding =
            load_finding_row_tx(&transaction, &admission.finding_id)?.ok_or_else(|| {
                FindingMarketStoreError::Conflict(
                    "admission names an unpublished finding".to_owned(),
                )
            })?;
        if finding.artifact_sha256 != admission.finding_artifact_sha256 {
            return Err(FindingMarketStoreError::Conflict(
                "admission binds a different finding artifact digest".to_owned(),
            ));
        }
        for terminal in &admission.fee_terminals {
            let key = finding_fee_idempotency_key(
                &terminal.fee_schedule_envelope_sha256,
                &terminal.event,
                &admission.finding_id,
                &admission.listing_id,
            );
            let event = load_fee_event_tx(&transaction, &key)?.ok_or_else(|| {
                FindingMarketStoreError::Conflict(
                    "admission names a fee event with no durable record".to_owned(),
                )
            })?;
            if event.state != FindingFeeState::Reconciled {
                return Err(FindingMarketStoreError::Conflict(
                    "admission names a fee event that is not reconciled".to_owned(),
                ));
            }
            if event.payer != terminal.payer
                || event.amount_units != terminal.amount.units
                || event.currency != terminal.amount.currency
                || event.pool_principal_id != terminal.pool_principal_id
                || event.rail_destination != terminal.rail_destination
                || event.instruction_sha256 != terminal.instruction_sha256
                || event.observation_sha256.as_deref() != Some(terminal.observation_sha256.as_str())
            {
                return Err(FindingMarketStoreError::Conflict(
                    "admission fee terminal does not match the durable fee event".to_owned(),
                ));
            }
        }
        let allocation =
            load_allocation_snapshot_tx(&transaction, &admission.backing_allocation_id)?
                .ok_or_else(|| {
                    FindingMarketStoreError::Conflict(
                        "admission names an unknown collateral allocation".to_owned(),
                    )
                })?;
        if allocation.backing.finding_id != admission.finding_id
            || allocation.backing.listing_id != admission.listing_id
            || allocation.backing_envelope_sha256 != admission.backing_envelope_sha256
        {
            return Err(FindingMarketStoreError::Conflict(
                "admission backing bindings do not match the stored allocation".to_owned(),
            ));
        }
        consume_allocation_tx(&transaction, &admission.backing_allocation_id)?;
        transaction
            .execute(
                r#"
                UPDATE admissions SET state = 'superseded'
                WHERE state = 'active' AND (listing_id = ?1 OR finding_id = ?2)
                "#,
                params![&admission.listing_id, &admission.finding_id],
            )
            .map_err(sqlite_error)?;
        let inserted = transaction
            .execute(
                r#"
                INSERT INTO admissions (
                    admission_id, finding_id, listing_id, backing_allocation_id,
                    admission_envelope_sha256, admission_envelope_json,
                    expires_at, activated_at, state
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')
                "#,
                params![
                    &admission.admission_id,
                    &admission.finding_id,
                    &admission.listing_id,
                    &admission.backing_allocation_id,
                    &envelope_sha256,
                    admission_envelope_json,
                    sqlite_i64(admission.expires_at, "expires_at")?,
                    sqlite_i64(activated_at, "activated_at")?,
                ],
            )
            .map_err(sqlite_error)?;
        if inserted != 1 {
            return Err(invariant("admission insert did not affect one row"));
        }
        self.commit_write(transaction)?;
        self.sync_after_write(&connection)?;
        Ok(FindingActivationOutcome::Activated)
    }

    /// The current (active) admission for a finding: exact envelope bytes
    /// plus the allocation-liveness hook data readers re-check.
    pub fn get_current_admission(
        &self,
        finding_id: &str,
    ) -> Result<Option<FindingAdmissionSnapshot>, FindingMarketStoreError> {
        require_hex64(finding_id, "finding_id")?;
        let mut connection = self.connection()?;
        let transaction = self.begin_read(&mut connection)?;
        let row = transaction
            .query_row(
                r#"
                SELECT admission_id, listing_id, backing_allocation_id,
                       admission_envelope_sha256, admission_envelope_json,
                       expires_at, activated_at
                FROM admissions WHERE finding_id = ?1 AND state = 'active'
                "#,
                [finding_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite_error)?;
        let Some((
            admission_id,
            listing_id,
            backing_allocation_id,
            envelope_sha256,
            envelope_json,
            expires_at,
            activated_at,
        )) = row
        else {
            return Ok(None);
        };
        if sha256_hex(envelope_json.as_bytes()) != envelope_sha256 {
            return Err(invariant("stored admission failed its digest re-check"));
        }
        let allocation = load_allocation_snapshot_tx(&transaction, &backing_allocation_id)?
            .ok_or_else(|| invariant("active admission lost its collateral allocation"))?;
        Ok(Some(FindingAdmissionSnapshot {
            admission_id,
            listing_id,
            envelope_json,
            envelope_sha256,
            expires_at: stored_u64(expires_at, "expires_at")?,
            activated_at: stored_u64(activated_at, "activated_at")?,
            backing_allocation_id,
            allocation_state: allocation.state,
        }))
    }
}

struct FindingRow {
    artifact_json: String,
    artifact_sha256: String,
    topic: String,
    context_sha256: String,
    issued_at: u64,
    expires_at: u64,
}

fn load_finding_row_tx(
    transaction: &Transaction<'_>,
    finding_id: &str,
) -> Result<Option<FindingRow>, FindingMarketStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT artifact_json, artifact_sha256, topic, context_sha256,
                   issued_at, expires_at
            FROM findings WHERE finding_id = ?1
            "#,
            [finding_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((artifact_json, artifact_sha256, topic, context_sha256, issued_at, expires_at)) = row
    else {
        return Ok(None);
    };
    if sha256_hex(artifact_json.as_bytes()) != artifact_sha256 {
        return Err(invariant("stored finding failed its digest re-check"));
    }
    Ok(Some(FindingRow {
        artifact_json,
        artifact_sha256,
        topic,
        context_sha256,
        issued_at: stored_u64(issued_at, "issued_at")?,
        expires_at: stored_u64(expires_at, "expires_at")?,
    }))
}

fn consume_allocation_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
) -> Result<(), FindingMarketStoreError> {
    let changed = transaction
        .execute(
            r#"
            UPDATE collateral_allocations SET state = 'consumed'
            WHERE allocation_id = ?1 AND state = 'live'
            "#,
            [allocation_id],
        )
        .map_err(sqlite_error)?;
    if changed == 1 {
        return Ok(());
    }
    let state: Option<String> = transaction
        .query_row(
            "SELECT state FROM collateral_allocations WHERE allocation_id = ?1",
            [allocation_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)?;
    match state {
        Some(state) => Err(FindingMarketStoreError::Conflict(format!(
            "collateral allocation is not live (state is {state})"
        ))),
        None => Err(FindingMarketStoreError::NotFound),
    }
}

fn load_allocation_snapshot_tx(
    transaction: &Transaction<'_>,
    allocation_id: &str,
) -> Result<Option<FindingAllocationSnapshot>, FindingMarketStoreError> {
    let row = transaction
        .query_row(
            r#"
            SELECT seller_hex, finding_id, listing_id, backing_envelope_sha256,
                   backing_envelope_json, currency, locked_units,
                   maximum_sale_exposure_units, expires_at, accepted_at, state
            FROM collateral_allocations WHERE allocation_id = ?1
            "#,
            [allocation_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        seller_hex,
        finding_id,
        listing_id,
        backing_envelope_sha256,
        backing_envelope_json,
        currency,
        locked_units,
        exposure_units,
        expires_at,
        accepted_at,
        state,
    )) = row
    else {
        return Ok(None);
    };
    if sha256_hex(backing_envelope_json.as_bytes()) != backing_envelope_sha256 {
        return Err(invariant(
            "stored backing envelope failed its digest re-check",
        ));
    }
    let parsed: SignedFindingBondBacking = serde_json::from_str(&backing_envelope_json)
        .map_err(|error| invariant(format!("stored backing envelope decode failed: {error}")))?;
    let backing = parsed.body;
    if backing.allocation_id != allocation_id
        || backing.seller.to_hex() != seller_hex
        || backing.finding_id != finding_id
        || backing.listing_id != listing_id
        || backing.locked_amount.currency != currency
        || sqlite_i64(backing.locked_amount.units, "locked_units")? != locked_units
        || sqlite_i64(
            backing.maximum_sale_exposure.units,
            "maximum_sale_exposure_units",
        )? != exposure_units
        || sqlite_i64(backing.expires_at, "expires_at")? != expires_at
    {
        return Err(invariant(
            "allocation columns do not match the stored backing body",
        ));
    }
    Ok(Some(FindingAllocationSnapshot {
        backing,
        backing_envelope_sha256,
        state: allocation_state_from_name(&state)?,
        accepted_at: stored_u64(accepted_at, "accepted_at")?,
    }))
}

fn allocation_state_from_name(
    name: &str,
) -> Result<FindingAllocationState, FindingMarketStoreError> {
    match name {
        "live" => Ok(FindingAllocationState::Live),
        "consumed" => Ok(FindingAllocationState::Consumed),
        "expired" => Ok(FindingAllocationState::Expired),
        "released" => Ok(FindingAllocationState::Released),
        other => Err(invariant(format!("unknown allocation state {other}"))),
    }
}

fn fee_state_from_name(name: &str) -> Result<FindingFeeState, FindingMarketStoreError> {
    match name {
        "intent" => Ok(FindingFeeState::Intent),
        "reconciled" => Ok(FindingFeeState::Reconciled),
        "failed" => Ok(FindingFeeState::Failed),
        other => Err(invariant(format!("unknown fee event state {other}"))),
    }
}

fn fee_event_from_parts(
    kind: &str,
    epoch_index: u64,
) -> Result<FindingFeeEvent, FindingMarketStoreError> {
    match kind {
        "publication" if epoch_index == 0 => Ok(FindingFeeEvent::Publication),
        "participation_epoch" => Ok(FindingFeeEvent::ParticipationEpoch { epoch_index }),
        other => Err(invariant(format!("unknown fee event kind {other}"))),
    }
}

fn load_fee_event_tx(
    transaction: &Transaction<'_>,
    idempotency_key: &str,
) -> Result<Option<FindingFeeEventRecord>, FindingMarketStoreError> {
    load_fee_event_connection(transaction, idempotency_key)
}

fn load_fee_event_committed(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<FindingFeeEventRecord>, FindingMarketStoreError> {
    load_fee_event_connection(connection, idempotency_key)
}

fn load_fee_event_connection(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Option<FindingFeeEventRecord>, FindingMarketStoreError> {
    let row = connection
        .query_row(
            r#"
            SELECT fee_schedule_envelope_sha256, event_kind, epoch_index,
                   finding_id, listing_id, payer, amount_units, currency,
                   pool_principal_id, rail_destination, instruction_sha256,
                   observation_sha256, state
            FROM fee_events WHERE idempotency_key = ?1
            "#,
            [idempotency_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, Option<String>>(11)?,
                    row.get::<_, String>(12)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_error)?;
    let Some((
        fee_schedule_envelope_sha256,
        event_kind,
        epoch_index,
        finding_id,
        listing_id,
        payer,
        amount_units,
        currency,
        pool_principal_id,
        rail_destination,
        instruction_sha256,
        observation_sha256,
        state,
    )) = row
    else {
        return Ok(None);
    };
    let event = fee_event_from_parts(&event_kind, stored_u64(epoch_index, "epoch_index")?)?;
    let expected_key = finding_fee_idempotency_key(
        &fee_schedule_envelope_sha256,
        &event,
        &finding_id,
        &listing_id,
    );
    if expected_key != idempotency_key {
        return Err(invariant(
            "fee event columns do not rederive the stored idempotency key",
        ));
    }
    Ok(Some(FindingFeeEventRecord {
        idempotency_key: idempotency_key.to_owned(),
        fee_schedule_envelope_sha256,
        event,
        finding_id,
        listing_id,
        payer,
        amount_units: stored_u64(amount_units, "amount_units")?,
        currency,
        pool_principal_id,
        rail_destination,
        instruction_sha256,
        observation_sha256,
        state: fee_state_from_name(&state)?,
    }))
}

fn load_admission_bytes_tx(
    transaction: &Transaction<'_>,
    admission_id: &str,
) -> Result<Option<String>, FindingMarketStoreError> {
    transaction
        .query_row(
            "SELECT admission_envelope_json FROM admissions WHERE admission_id = ?1",
            [admission_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(sqlite_error)
}

pub(crate) fn initialize_finding_market_schema(
    connection: &mut Connection,
) -> Result<(), FindingMarketStoreError> {
    let on_disk = crate::check_schema_version(
        connection,
        FINDING_MARKET_SCHEMA_KEY,
        FINDING_MARKET_SUPPORTED_SCHEMA_VERSION,
        FINDING_MARKET_SCHEMA_ANCHORS,
    )
    .map_err(|error| invariant(error.to_string()))?;
    if on_disk == FINDING_MARKET_SUPPORTED_SCHEMA_VERSION {
        return verify_finding_market_invariants(connection);
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(FINDING_MARKET_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FINDING_MARKET_SCHEMA_KEY,
        FINDING_MARKET_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| invariant(error.to_string()))?;
    verify_finding_market_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_finding_market_invariants(
    connection: &Connection,
) -> Result<(), FindingMarketStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FINDING_MARKET_SCHEMA)
        .map_err(sqlite_error)?;
    if finding_market_schema_catalog(connection)? != finding_market_schema_catalog(&expected)? {
        return Err(invariant(
            "finding market schema differs from the canonical definition",
        ));
    }
    let mut statement = connection
        .prepare("SELECT artifact_json, artifact_sha256 FROM findings ORDER BY finding_id")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let artifact: String = row.get(0).map_err(sqlite_error)?;
        let digest: String = row.get(1).map_err(sqlite_error)?;
        if sha256_hex(artifact.as_bytes()) != digest {
            return Err(invariant("finding artifact digest is invalid"));
        }
    }
    drop(rows);
    drop(statement);
    let mut statement = connection
        .prepare("SELECT canonical_sha256, blob_bytes FROM recipe_blobs ORDER BY canonical_sha256")
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let digest: String = row.get(0).map_err(sqlite_error)?;
        let bytes: Vec<u8> = row.get(1).map_err(sqlite_error)?;
        if sha256_hex(&bytes) != digest {
            return Err(invariant("recipe blob digest is invalid"));
        }
    }
    drop(rows);
    drop(statement);
    let mut statement = connection
        .prepare(
            "SELECT backing_envelope_json, backing_envelope_sha256
             FROM collateral_allocations ORDER BY allocation_id",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let envelope: String = row.get(0).map_err(sqlite_error)?;
        let digest: String = row.get(1).map_err(sqlite_error)?;
        if sha256_hex(envelope.as_bytes()) != digest {
            return Err(invariant("backing envelope digest is invalid"));
        }
    }
    drop(rows);
    drop(statement);
    let mut statement = connection
        .prepare(
            "SELECT admission_envelope_json, admission_envelope_sha256
             FROM admissions ORDER BY admission_id",
        )
        .map_err(sqlite_error)?;
    let mut rows = statement.query([]).map_err(sqlite_error)?;
    while let Some(row) = rows.next().map_err(sqlite_error)? {
        let envelope: String = row.get(0).map_err(sqlite_error)?;
        let digest: String = row.get(1).map_err(sqlite_error)?;
        if sha256_hex(envelope.as_bytes()) != digest {
            return Err(invariant("admission envelope digest is invalid"));
        }
    }
    Ok(())
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

fn finding_market_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, FindingMarketStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql
            FROM sqlite_schema
            WHERE name GLOB 'findings*' OR tbl_name GLOB 'findings*'
               OR name GLOB 'recipe_blobs*' OR tbl_name GLOB 'recipe_blobs*'
               OR name GLOB 'collateral_allocations*'
               OR tbl_name GLOB 'collateral_allocations*'
               OR name GLOB 'fee_events*' OR tbl_name GLOB 'fee_events*'
               OR name GLOB 'admissions*' OR tbl_name GLOB 'admissions*'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let entries = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(entries)
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingMarketStoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(invariant(format!(
        "{field} is not 64 lowercase hex characters"
    )))
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), FindingMarketStoreError> {
    if value.is_empty() || value.len() > 512 {
        return Err(invariant(format!("{field} byte length is out of bounds")));
    }
    Ok(())
}

fn require_currency(currency: &str) -> Result<(), FindingMarketStoreError> {
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(invariant("currency is not a three-letter uppercase code"));
    }
    Ok(())
}

fn sqlite_i64(value: u64, field: &'static str) -> Result<i64, FindingMarketStoreError> {
    i64::try_from(value).map_err(|_| invariant(format!("{field} exceeds SQLite integer range")))
}

fn stored_u64(value: i64, field: &'static str) -> Result<u64, FindingMarketStoreError> {
    u64::try_from(value).map_err(|_| invariant(format!("{field} is negative")))
}

fn invariant(detail: impl Into<String>) -> FindingMarketStoreError {
    FindingMarketStoreError::Invariant(detail.into())
}

fn admission_error(error: AdmissionOperationStoreError) -> FindingMarketStoreError {
    match error {
        AdmissionOperationStoreError::Fenced => FindingMarketStoreError::Fenced,
        AdmissionOperationStoreError::NotFound => FindingMarketStoreError::NotFound,
        AdmissionOperationStoreError::Unavailable(detail) => {
            FindingMarketStoreError::Unavailable(detail)
        }
        AdmissionOperationStoreError::OutcomeUnknown(detail) => {
            FindingMarketStoreError::OutcomeUnknown(detail)
        }
        AdmissionOperationStoreError::Invariant(detail) => {
            FindingMarketStoreError::Invariant(detail)
        }
        AdmissionOperationStoreError::Operation(error) => invariant(error.to_string()),
    }
}

fn sqlite_error(error: rusqlite::Error) -> FindingMarketStoreError {
    match error {
        rusqlite::Error::FromSqlConversionFailure(..)
        | rusqlite::Error::IntegralValueOutOfRange(..)
        | rusqlite::Error::InvalidColumnType(..)
        | rusqlite::Error::Utf8Error(..) => invariant(error.to_string()),
        other => FindingMarketStoreError::Unavailable(other.to_string()),
    }
}

#[cfg(test)]
#[path = "finding_market_store_tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
