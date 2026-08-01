use std::sync::{Arc, Mutex, MutexGuard};

use chio_core::StoreMutationFence;
use chio_federation_authority::{FrostAuthenticatedDkgPackage, FrostCeremonySecret};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

use crate::admission_operation_store::verify_active_owner;
use crate::encrypted_blob::TenantKey;
use crate::serving_owner::SqliteServingOwner;

mod ceremony;
mod commit;
mod coordinator;
mod rotation;
mod rotation_validation;
mod schema;
mod signer;

use schema::FROST_STORE_SCHEMA;

const FROST_STORE_SCHEMA_KEY: &str = "frost";
pub(crate) const FROST_STORE_SUPPORTED_SCHEMA_VERSION: i32 = 0;
const FROST_STORE_SCHEMA_ANCHORS: &[&str] = &[
    "frost_ceremonies",
    "chio_serving_owner",
    "capability_grant_budgets",
];

#[derive(Debug, thiserror::Error)]
pub enum FrostStoreError {
    #[error("sqlite FROST store is fenced")]
    Fenced,
    #[error("sqlite FROST store conflict: {0}")]
    Conflict(&'static str),
    #[error("sqlite FROST store state is invalid: {0}")]
    InvalidState(String),
    #[error("sqlite FROST custody failed: {0}")]
    Custody(&'static str),
    #[error("sqlite FROST store unavailable: {0}")]
    Unavailable(String),
    #[error(transparent)]
    Ceremony(#[from] chio_federation_authority::FrostCeremonyError),
}

pub struct FrostCustodyKey {
    generation: String,
    key: TenantKey,
}

impl std::fmt::Debug for FrostCustodyKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FrostCustodyKey")
            .field("generation", &self.generation)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl FrostCustodyKey {
    pub fn new(
        generation: impl Into<String>,
        key_bytes: [u8; 32],
    ) -> Result<Self, FrostStoreError> {
        let generation = generation.into();
        if generation.is_empty()
            || generation.len() > 128
            || generation.trim() != generation
            || !generation.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(FrostStoreError::Custody(
                "generation must be unpadded printable ASCII",
            ));
        }
        Ok(Self {
            generation,
            key: TenantKey::from_bytes(key_bytes),
        })
    }

    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    pub(super) fn key(&self) -> &TenantKey {
        &self.key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostCeremonyState {
    Round1Ready,
    Round2Ready,
    Completed,
}

impl FrostCeremonyState {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Round1Ready => "round1_ready",
            Self::Round2Ready => "round2_ready",
            Self::Completed => "completed",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, FrostStoreError> {
        match value {
            "round1_ready" => Ok(Self::Round1Ready),
            "round2_ready" => Ok(Self::Round2Ready),
            "completed" => Ok(Self::Completed),
            _ => Err(FrostStoreError::InvalidState(
                "unknown ceremony state".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostCeremonyRecord {
    pub ceremony_id: String,
    pub state: FrostCeremonyState,
    pub state_version: u64,
    pub participant_set_digest: String,
    pub scope_id: String,
    pub key_epoch: u64,
    pub local_participant_id: String,
    pub input_transcript_digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostCeremonyRound1Record {
    pub ceremony_id: String,
    pub state: FrostCeremonyState,
    pub state_version: u64,
    pub package: FrostAuthenticatedDkgPackage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostCeremonyRound2Record {
    pub ceremony_id: String,
    pub state: FrostCeremonyState,
    pub state_version: u64,
    pub packages: Vec<FrostAuthenticatedDkgPackage>,
    pub round1_transcript_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFrostCeremonyCompletion {
    pub ceremony_id: String,
    pub state: FrostCeremonyState,
    pub state_version: u64,
    pub public_key_package: Vec<u8>,
    pub group_public_key: String,
    pub verification_shares: std::collections::BTreeMap<String, String>,
    pub transcript_digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostRotationState {
    Staged,
    AnchorAdvanced,
    Active,
    Discarded,
}

impl FrostRotationState {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Staged => "staged",
            Self::AnchorAdvanced => "anchor_advanced",
            Self::Active => "active",
            Self::Discarded => "discarded",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, FrostStoreError> {
        match value {
            "staged" => Ok(Self::Staged),
            "anchor_advanced" => Ok(Self::AnchorAdvanced),
            "active" => Ok(Self::Active),
            "discarded" => Ok(Self::Discarded),
            _ => Err(FrostStoreError::InvalidState(
                "unknown FROST rotation state".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostActiveRosterRecord {
    pub scope_id: String,
    pub key_epoch: u64,
    pub roster_digest: String,
    pub checkpoint_sequence: u64,
    pub checkpoint_digest: String,
    pub activation_fence: u64,
    pub clock_high_water: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostRotationRecord {
    pub rotation_id: String,
    pub scope_id: String,
    pub state: FrostRotationState,
    pub state_version: u64,
    pub predecessor_checkpoint_digest: String,
    pub target_roster_digest: String,
    pub target_key_epoch: u64,
    pub anchored_checkpoint_digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StagedFrostRotation {
    rotation_id: String,
    advance: chio_federation::frost::VerifiedFrostEpochAdvance,
}

pub struct FrostSignerSessionRequest<'a> {
    pub body: &'a chio_federation::frost::FrostAuthorizationBodyV1,
    pub active_roster: &'a chio_federation::frost::VerifiedActiveFrostRoster,
    pub epoch_anchor: &'a dyn chio_federation::frost::FrostEpochAnchor,
    pub slot_anchor: &'a dyn chio_federation::frost::FrostAuthorizationSlotAnchorWriter,
    pub artifact_trust: &'a chio_federation::frost::FrostArtifactTrustStore,
    pub ceremony_id: &'a str,
    pub participant_id: &'a str,
    pub coordinator_id: &'a str,
}

pub struct FrostCoordinatorSessionRequest<'a> {
    pub body: &'a chio_federation::frost::FrostAuthorizationBodyV1,
    pub active_roster: &'a chio_federation::frost::VerifiedActiveFrostRoster,
    pub epoch_anchor: &'a dyn chio_federation::frost::FrostEpochAnchor,
    pub slot_anchor: &'a dyn chio_federation::frost::FrostAuthorizationSlotAnchorWriter,
    pub artifact_trust: &'a chio_federation::frost::FrostArtifactTrustStore,
    pub coordinator_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorLease {
    pub session_id: String,
    pub authorization_slot_id: String,
    pub coordinator_id: String,
    pub worker_id: String,
    pub lease_id: String,
    pub owner_epoch: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorCommitment {
    pub participant_id: String,
    pub signer_identifier: Vec<u8>,
    pub commitment_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorShare {
    pub participant_id: String,
    pub share_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorSigningPackage {
    pub session_id: String,
    pub participant_ids: Vec<String>,
    pub signing_package_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorSessionRecord {
    pub session_id: String,
    pub authorization_slot_id: String,
    pub state: FrostCoordinatorSessionState,
    pub row_version: u64,
    pub commitment_count: usize,
    pub share_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrostCoordinatorCancellation {
    pub session: FrostCoordinatorSessionRecord,
    pub participant_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostCoordinatorSessionState {
    CollectingCommitments,
    PackageReady,
    AuthorizationReady,
    Completed,
    Burned,
}

impl FrostCoordinatorSessionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CollectingCommitments => "collecting_commitments",
            Self::PackageReady => "package_ready",
            Self::AuthorizationReady => "authorization_ready",
            Self::Completed => "completed",
            Self::Burned => "burned",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, FrostStoreError> {
        match value {
            "collecting_commitments" => Ok(Self::CollectingCommitments),
            "package_ready" => Ok(Self::PackageReady),
            "authorization_ready" => Ok(Self::AuthorizationReady),
            "completed" => Ok(Self::Completed),
            "burned" => Ok(Self::Burned),
            _ => Err(FrostStoreError::InvalidState(
                "unknown FROST coordinator state".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignerSessionRecord {
    pub session_id: String,
    pub participant_id: String,
    pub authorization_slot_id: String,
    pub state: FrostSignerSessionState,
    pub state_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignerCommitment {
    pub session_id: String,
    pub participant_id: String,
    pub signer_identifier: Vec<u8>,
    pub commitment_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrostSignerShare {
    pub session_id: String,
    pub participant_id: String,
    pub share_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrostSignerSessionState {
    Prepared,
    CommitmentPublished,
    ShareReady,
    Completed,
    Burned,
}

impl FrostSignerSessionState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::CommitmentPublished => "commitment_published",
            Self::ShareReady => "share_ready",
            Self::Completed => "completed",
            Self::Burned => "burned",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, FrostStoreError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "commitment_published" => Ok(Self::CommitmentPublished),
            "share_ready" => Ok(Self::ShareReady),
            "completed" => Ok(Self::Completed),
            "burned" => Ok(Self::Burned),
            _ => Err(FrostStoreError::InvalidState(
                "unknown FROST signer state".to_string(),
            )),
        }
    }
}

impl StagedFrostRotation {
    #[must_use]
    pub fn rotation_id(&self) -> &str {
        &self.rotation_id
    }

    #[must_use]
    pub fn advance(&self) -> &chio_federation::frost::VerifiedFrostEpochAdvance {
        &self.advance
    }
}

#[derive(Clone)]
pub struct SqliteFrostStore {
    connection: Arc<Mutex<Connection>>,
    serving_owner: Arc<SqliteServingOwner>,
}

impl SqliteFrostStore {
    pub(crate) fn open_alongside(
        connection: Arc<Mutex<Connection>>,
        serving_owner: Arc<SqliteServingOwner>,
    ) -> Self {
        Self {
            connection,
            serving_owner,
        }
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>, FrostStoreError> {
        self.connection.lock().map_err(|_| {
            FrostStoreError::Unavailable("sqlite FROST store lock is poisoned".to_string())
        })
    }

    fn begin_read<'a>(
        &self,
        connection: &'a mut Connection,
        fence: Option<&StoreMutationFence>,
    ) -> Result<Transaction<'a>, FrostStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, fence).map_err(owner_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FrostStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn begin_write<'a>(
        &self,
        connection: &'a mut Connection,
        fence: &StoreMutationFence,
    ) -> Result<Transaction<'a>, FrostStoreError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_error)?;
        verify_active_owner(&transaction, &self.serving_owner, Some(fence)).map_err(owner_error)?;
        self.serving_owner
            .verify_authority_anchor(&transaction)
            .map_err(|error| FrostStoreError::Unavailable(error.to_string()))?;
        Ok(transaction)
    }

    fn commit_write(&self, transaction: Transaction<'_>) -> Result<(), FrostStoreError> {
        transaction.commit().map_err(|error| {
            FrostStoreError::Unavailable(
                self.serving_owner
                    .outcome_unknown(format!("sqlite FROST commit outcome is unknown: {error}"))
                    .to_string(),
            )
        })
    }

    fn sync_after_write(&self, connection: &Connection) -> Result<(), FrostStoreError> {
        self.serving_owner
            .sync_authority_anchor(connection)
            .map_err(|error| FrostStoreError::Unavailable(error.to_string()))
    }
}

pub(crate) fn initialize_frost_schema(connection: &mut Connection) -> Result<(), FrostStoreError> {
    crate::check_schema_version(
        connection,
        FROST_STORE_SCHEMA_KEY,
        FROST_STORE_SUPPORTED_SCHEMA_VERSION,
        FROST_STORE_SCHEMA_ANCHORS,
    )
    .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(sqlite_error)?;
    transaction
        .execute_batch(FROST_STORE_SCHEMA)
        .map_err(sqlite_error)?;
    crate::stamp_schema_version(
        &transaction,
        FROST_STORE_SCHEMA_KEY,
        FROST_STORE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| FrostStoreError::InvalidState(error.to_string()))?;
    verify_frost_store_invariants(&transaction)?;
    transaction.commit().map_err(sqlite_error)
}

pub(crate) fn verify_frost_store_invariants(
    connection: &Connection,
) -> Result<(), FrostStoreError> {
    let expected = Connection::open_in_memory().map_err(sqlite_error)?;
    expected
        .execute_batch(FROST_STORE_SCHEMA)
        .map_err(sqlite_error)?;
    if frost_schema_catalog(connection)? != frost_schema_catalog(&expected)? {
        return Err(FrostStoreError::InvalidState(
            "FROST store schema differs from the canonical definition".to_string(),
        ));
    }
    ceremony::verify_ceremony_invariants(connection)?;
    rotation::verify_rotation_invariants(connection)?;
    signer::verify_signer_invariants(connection)?;
    coordinator::verify_coordinator_invariants(connection)
}

type FrostSchemaCatalogEntry = (String, String, String, Option<String>);

fn frost_schema_catalog(
    connection: &Connection,
) -> Result<Vec<FrostSchemaCatalogEntry>, FrostStoreError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT type, name, tbl_name, sql FROM sqlite_schema
            WHERE name GLOB 'frost_*' OR tbl_name GLOB 'frost_*'
            ORDER BY type, name, tbl_name
            "#,
        )
        .map_err(sqlite_error)?;
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .map_err(sqlite_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sqlite_error)?;
    Ok(catalog)
}

fn sqlite_error(error: rusqlite::Error) -> FrostStoreError {
    FrostStoreError::Unavailable(error.to_string())
}

fn owner_error(
    error: chio_kernel::admission_operation::AdmissionOperationStoreError,
) -> FrostStoreError {
    if matches!(
        error,
        chio_kernel::admission_operation::AdmissionOperationStoreError::Fenced
    ) {
        FrostStoreError::Fenced
    } else {
        FrostStoreError::Unavailable(error.to_string())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", content = "output", rename_all = "snake_case")]
enum StoredCeremonyOutput {
    Round1(Box<FrostAuthenticatedDkgPackage>),
    Round2(Vec<FrostAuthenticatedDkgPackage>),
}

pub(super) fn secret_kind_name(secret: &FrostCeremonySecret) -> &'static str {
    match secret.kind() {
        chio_federation_authority::FrostCeremonySecretKind::Round1 => "round1",
        chio_federation_authority::FrostCeremonySecretKind::Round2 => "round2",
        chio_federation_authority::FrostCeremonySecretKind::KeyPackage => "key_package",
    }
}
