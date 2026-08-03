use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::StoreMutationFence;
use chio_kernel::budget_store::{
    BudgetEventAuthority, BudgetGuaranteeLevel, RevocationCommitMetadata,
};
use chio_kernel::{BudgetStoreError, RevocationStoreError};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};

use crate::budget_store::BUDGET_STORE_SUPPORTED_SCHEMA_VERSION;
use crate::revocation_store::{
    initialize_revocation_schema, verify_admission_authority_invariants,
    REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
};
use crate::{SqliteBudgetStore, SqliteRevocationStore};

mod global_commit_chain;
mod lease_history;
mod path_identity;
mod rollback_anchor;

use global_commit_chain::{
    append_finding_challenge_projection_if_changed, append_finding_status_projection_if_changed,
};
use global_commit_chain::{
    append_global_commit, initialize_global_commit_schema, reset_derived_budget_ack_cache,
    seed_global_baseline, verify_global_commit_schema, verify_pristine_authority_tables,
};
use lease_history::{initialize_serving_lease_schema, verify_serving_lease_history};
use rollback_anchor::RollbackAnchor;

#[cfg(all(test, feature = "cognition-market-experimental"))]
pub(crate) fn verify_finding_market_projection_for_tests(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    global_commit_chain::verify_finding_challenge_projection_coverage(connection)
}

const SERVING_OWNER_SCHEMA: &str = r#"
CREATE TABLE chio_serving_owner (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_uuid TEXT UNIQUE NOT NULL,
    database_path TEXT NOT NULL,
    database_device INTEGER NOT NULL CHECK (database_device >= 0),
    database_inode INTEGER NOT NULL CHECK (database_inode >= 0),
    lock_root TEXT NOT NULL,
    lock_device INTEGER NOT NULL CHECK (lock_device >= 0),
    lock_inode INTEGER NOT NULL CHECK (lock_inode >= 0),
    owner_epoch INTEGER NOT NULL DEFAULT 0 CHECK (owner_epoch >= 0),
    lease_id TEXT,
    opened_at_ms INTEGER
);
"#;

struct FixedAuthorityIds {
    store_uuid: String,
    lease_ids: VecDeque<String>,
}

thread_local! {
    static FIXED_AUTHORITY_IDS: RefCell<Option<FixedAuthorityIds>> = const { RefCell::new(None) };
}

pub struct FixedAuthorityIdScope {
    previous: Option<FixedAuthorityIds>,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for FixedAuthorityIdScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        FIXED_AUTHORITY_IDS.with(|slot| {
            *slot.borrow_mut() = previous;
        });
    }
}

pub fn scope_fixed_authority_ids_for_current_thread(
    store_uuid: impl Into<String>,
    lease_ids: impl IntoIterator<Item = String>,
) -> Result<FixedAuthorityIdScope, SqliteServingOwnerError> {
    let store_uuid = store_uuid.into();
    validate_uuid_v7(&store_uuid, "fixed authority store UUID")?;
    let lease_ids = lease_ids
        .into_iter()
        .map(|lease_id| validate_uuid_v7(&lease_id, "fixed authority lease ID").map(|_| lease_id))
        .collect::<Result<VecDeque<_>, _>>()?;
    let previous = FIXED_AUTHORITY_IDS.with(|slot| {
        slot.replace(Some(FixedAuthorityIds {
            store_uuid,
            lease_ids,
        }))
    });
    Ok(FixedAuthorityIdScope {
        previous,
        _not_send: std::marker::PhantomData,
    })
}

fn next_store_uuid() -> String {
    FIXED_AUTHORITY_IDS.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|ids| ids.store_uuid.clone())
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string())
    })
}

fn next_lease_id() -> Result<String, SqliteServingOwnerError> {
    FIXED_AUTHORITY_IDS.with(|slot| {
        let mut ids = slot.borrow_mut();
        match ids.as_mut() {
            Some(ids) => ids.lease_ids.pop_front().ok_or_else(|| {
                SqliteServingOwnerError::Invalid(
                    "fixed authority lease ID set is exhausted".to_string(),
                )
            }),
            None => Ok(uuid::Uuid::now_v7().to_string()),
        }
    })
}

type SchemaCatalogEntry = (String, String, String, Option<String>);

#[derive(Debug, thiserror::Error)]
pub enum SqliteServingOwnerError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite authority store is not provisioned: {0}")]
    NotProvisioned(String),
    #[error("sqlite authority store is partially provisioned: {0}")]
    PartialProvision(String),
    #[error("sqlite authority store is already serving: {0}")]
    AlreadyServing(String),
    #[error("invalid sqlite authority store: {0}")]
    Invalid(String),
    #[error("sqlite authority durable outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

pub(crate) struct SqliteServingOwner {
    rollback_anchor: RollbackAnchor,
    pub(crate) fence: StoreMutationFence,
    poisoned: AtomicBool,
    expected_data_version: AtomicU64,
}

impl SqliteServingOwner {
    pub(crate) fn outcome_unknown(&self, detail: impl Into<String>) -> SqliteServingOwnerError {
        self.poisoned.store(true, Ordering::Release);
        SqliteServingOwnerError::OutcomeUnknown(detail.into())
    }

    pub(crate) fn verify_authority_anchor(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteServingOwnerError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(SqliteServingOwnerError::OutcomeUnknown(
                "sqlite authority owner is poisoned after an outcome-unknown anchor sync"
                    .to_string(),
            ));
        }
        let actual = authority_data_version(connection)?;
        if actual != self.expected_data_version.load(Ordering::Acquire) {
            self.poisoned.store(true, Ordering::Release);
            return Err(SqliteServingOwnerError::OutcomeUnknown(
                "authority database changed outside its serving-owner connection".to_string(),
            ));
        }
        self.rollback_anchor.verify_current(connection)
    }

    pub(crate) fn append_global_commit(
        &self,
        transaction: &Transaction<'_>,
        mutation_kind: &str,
        projection_kind: &str,
        projection_key: &str,
        projection_sequence: u64,
    ) -> Result<(), SqliteServingOwnerError> {
        append_global_commit(
            transaction,
            mutation_kind,
            projection_kind,
            projection_key,
            projection_sequence,
            &self.fence,
        )
    }

    pub(crate) fn append_finding_challenge_projection_if_changed(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<bool, SqliteServingOwnerError> {
        append_finding_challenge_projection_if_changed(transaction, &self.fence)
    }

    pub(crate) fn append_finding_status_projection_if_changed(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<bool, SqliteServingOwnerError> {
        append_finding_status_projection_if_changed(transaction, &self.fence)
    }

    pub(crate) fn sync_authority_anchor(
        &self,
        connection: &Connection,
    ) -> Result<(), SqliteServingOwnerError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(SqliteServingOwnerError::OutcomeUnknown(
                "sqlite authority owner is poisoned after an outcome-unknown anchor sync"
                    .to_string(),
            ));
        }
        if authority_data_version(connection)? != self.expected_data_version.load(Ordering::Acquire)
        {
            self.poisoned.store(true, Ordering::Release);
            return Err(SqliteServingOwnerError::OutcomeUnknown(
                "authority database changed outside its serving-owner connection".to_string(),
            ));
        }
        if let Err(error) = self.rollback_anchor.sync_after_commit(connection) {
            self.poisoned.store(true, Ordering::Release);
            return Err(SqliteServingOwnerError::OutcomeUnknown(error.to_string()));
        }
        Ok(())
    }
}

pub struct SqliteAuthorityStore {
    connection: Arc<Mutex<Connection>>,
    owner: Arc<SqliteServingOwner>,
}

struct ProvisioningRecord {
    store_uuid: String,
    database_path: String,
    database_device: u64,
    database_inode: u64,
    lock_root: String,
    lock_device: u64,
    lock_inode: u64,
    owner_epoch: u64,
}

impl SqliteAuthorityStore {
    /// Rejects platforms that cannot provide the filesystem identity and
    /// positioned I/O required by durable authority serving.
    pub fn ensure_serving_supported() -> Result<(), SqliteServingOwnerError> {
        #[cfg(unix)]
        {
            Ok(())
        }
        #[cfg(not(unix))]
        {
            Err(SqliteServingOwnerError::Invalid(
                UNSUPPORTED_SERVING_PLATFORM_MESSAGE.to_string(),
            ))
        }
    }

    pub fn provision(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<(), SqliteServingOwnerError> {
        Self::ensure_serving_supported()?;
        let database_path = database_path.as_ref();
        let lock_root = canonical_lock_root(lock_root.as_ref())?;
        let provision_lock = File::open(&lock_root)?;
        provision_lock.lock()?;
        if let Some(parent) = crate::sqlite_parent_dir_to_create(database_path) {
            fs::create_dir_all(parent)?;
        }
        let authority_parent = database_parent(database_path);
        validate_secure_directory(authority_parent, "authority database parent")?;

        if !database_path.exists() {
            let database_file = create_database_file(database_path)?;
            validate_database_metadata(&database_file.metadata()?)?;
            database_file.sync_all()?;
            File::open(authority_parent)?.sync_all()?;
        }
        validate_database_path_component(database_path)?;
        let expected_database = fs::metadata(database_path)?;

        let canonical_database_path = fs::canonicalize(database_path)?;
        let mut connection = open_existing_database(&canonical_database_path)?;
        validate_database_identity(&canonical_database_path, &expected_database)?;
        if owner_table_exists(&connection)? {
            verify_serving_owner_schema(&connection)?;
            let record = load_provisioning_record(&connection)?.ok_or_else(|| {
                SqliteServingOwnerError::PartialProvision(
                    canonical_database_path.display().to_string(),
                )
            })?;
            validate_provisioning_record(&canonical_database_path, &lock_root, &record)?;
            path_identity::inspect(
                &lock_root,
                &canonical_database_path,
                Some(&record.store_uuid),
            )?;
            let lock_path = lock_root.join(format!("{}.lock", record.store_uuid));
            let lock_file = open_lock_file(&lock_path)?;
            validate_open_lock_file(&lock_root, &lock_file, &record)?;
            acquire_serving_lock(&lock_file, &canonical_database_path)?;
            validate_open_lock_file(&lock_root, &lock_file, &record)?;
            validate_provisioning_record(&canonical_database_path, &lock_root, &record)?;
            initialize_offline_authority_schemas(&mut connection)?;
            initialize_serving_lease_schema(&connection)?;
            crate::admission_operation_store::initialize_admission_operation_schema(
                &mut connection,
            )?;
            crate::channel_lifecycle_store::initialize_channel_lifecycle_schema(&mut connection)?;
            crate::channel_release_publisher_store::initialize_channel_release_publisher_schema(
                &mut connection,
            )?;
            crate::tool_outcome_store::initialize_tool_outcome_schema(&mut connection)
                .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
            crate::finding_market_store::initialize_finding_market_schema(&mut connection)
                .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
            crate::finding_purchase_store::initialize_finding_purchase_schema(&mut connection)
                .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
            crate::finding_recovery_store::initialize_finding_recovery_schema(&mut connection)
                .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
            crate::finding_challenge_store::initialize_finding_challenge_schema(&mut connection)
                .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
            crate::finding_status_store::initialize_finding_status_schema(&mut connection)
                .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
            initialize_global_commit_schema(&connection)?;
            seed_global_baseline(&mut connection)?;
            reset_derived_budget_ack_cache(&connection)?;
            verify_authority_store_invariants(&connection)?;
            validate_database_identity(&canonical_database_path, &expected_database)?;
            connection.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
            File::open(&canonical_database_path)?.sync_all()?;
            File::open(database_parent(&canonical_database_path))?.sync_all()?;
            validate_database_identity(&canonical_database_path, &expected_database)?;
            let rollback_anchor = RollbackAnchor::new(
                lock_file,
                &lock_root,
                &record.store_uuid,
                record.lock_device,
                record.lock_inode,
            )?;
            rollback_anchor.migrate_offline(&connection)?;
            validate_database_identity(&canonical_database_path, &expected_database)?;
            path_identity::ensure(&lock_root, &canonical_database_path, &record.store_uuid)?;
            return Ok(());
        }
        verify_path_available_for_new_identity(&lock_root, &canonical_database_path)?;
        initialize_offline_authority_schemas(&mut connection)?;
        validate_database_identity(&canonical_database_path, &expected_database)?;
        let database_path = canonical_database_path;
        for (key, supported) in [
            ("budget", BUDGET_STORE_SUPPORTED_SCHEMA_VERSION),
            ("revocation", REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION),
            (
                "admission_operation",
                crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "tool_outcome",
                crate::tool_outcome_store::TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "frost",
                crate::frost_store::FROST_STORE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "economic_state_cache",
                crate::economic_state_cache::ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "fiscal",
                crate::fiscal_store::FISCAL_STORE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "channel_lifecycle",
                crate::channel_lifecycle_store::CHANNEL_LIFECYCLE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "channel_release_publisher",
                crate::channel_release_publisher_store::CHANNEL_RELEASE_PUBLISHER_SUPPORTED_SCHEMA_VERSION,
            ),
        ] {
            crate::check_schema_version(
                &connection,
                key,
                supported,
                &["capability_grant_budgets", "revoked_capabilities"],
            )
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        }
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        // Refuse a store the global baseline cannot adopt before anything is created,
        // so a refused provision leaves the pre-existing database exactly as it was.
        verify_pristine_authority_tables(&connection)?;

        let store_uuid = next_store_uuid();
        let lock_path = lock_root.join(format!("{store_uuid}.lock"));
        // The owner table and its row are created in a single transaction so a
        // failure rolls the table back with the row. Nothing that depends on the
        // owner table is created before that transaction commits, which leaves an
        // interrupted provision recoverable rather than wedged half way.
        let mut lock_file_created = false;
        let provision_owner = (|| -> Result<(File, fs::Metadata), SqliteServingOwnerError> {
            let lock_file = create_lock_file(&lock_path)?;
            lock_file_created = true;
            let lock_metadata = lock_file.metadata()?;
            validate_lock_metadata(&lock_root, &lock_metadata)?;
            lock_file.sync_all()?;
            File::open(&lock_root)?.sync_all()?;
            validate_database_identity(&database_path, &expected_database)?;
            let database_metadata = fs::metadata(&database_path)?;
            validate_database_metadata(&database_metadata)?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute_batch(SERVING_OWNER_SCHEMA)?;
            let changed = transaction.execute(
                r#"
                INSERT INTO chio_serving_owner (
                    singleton, store_uuid, database_path,
                    database_device, database_inode, lock_root,
                    lock_device, lock_inode, owner_epoch
                ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)
                "#,
                params![
                    &store_uuid,
                    path_text(&database_path)?,
                    metadata_device(&database_metadata)?,
                    metadata_inode(&database_metadata)?,
                    path_text(&lock_root)?,
                    metadata_device(&lock_metadata)?,
                    metadata_inode(&lock_metadata)?,
                ],
            )?;
            if changed != 1 {
                return Err(SqliteServingOwnerError::Invalid(
                    "serving-owner insert did not affect exactly one row".to_string(),
                ));
            }
            transaction.commit().map_err(|error| {
                SqliteServingOwnerError::OutcomeUnknown(format!(
                    "sqlite authority provisioning commit outcome is unknown: {error}"
                ))
            })?;
            Ok((lock_file, lock_metadata))
        })();
        let (lock_file, lock_metadata) = match provision_owner {
            Ok(artifacts) => artifacts,
            Err(error) => {
                // An unknown commit outcome stays untouched for manual inspection.
                if !matches!(error, SqliteServingOwnerError::OutcomeUnknown(_)) && lock_file_created
                {
                    let _ = fs::remove_file(&lock_path);
                    let _ = File::open(&lock_root).and_then(|directory| directory.sync_all());
                }
                return Err(error);
            }
        };
        verify_serving_owner_schema(&connection)?;
        initialize_serving_lease_schema(&connection)?;
        crate::admission_operation_store::initialize_admission_operation_schema(&mut connection)?;
        crate::channel_lifecycle_store::initialize_channel_lifecycle_schema(&mut connection)?;
        crate::channel_release_publisher_store::initialize_channel_release_publisher_schema(
            &mut connection,
        )?;
        crate::tool_outcome_store::initialize_tool_outcome_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_market_store::initialize_finding_market_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_purchase_store::initialize_finding_purchase_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_recovery_store::initialize_finding_recovery_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_challenge_store::initialize_finding_challenge_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_status_store::initialize_finding_status_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        initialize_global_commit_schema(&connection)?;
        seed_global_baseline(&mut connection)?;
        reset_derived_budget_ack_cache(&connection)?;
        verify_authority_store_invariants(&connection)?;
        validate_database_identity(&database_path, &expected_database)?;
        File::open(&database_path)?.sync_all()?;
        File::open(&lock_root)?.sync_all()?;
        if let Some(parent) = database_path.parent() {
            File::open(parent)?.sync_all()?;
        }
        validate_database_identity(&database_path, &expected_database)?;
        let rollback_anchor = RollbackAnchor::new(
            lock_file,
            &lock_root,
            &store_uuid,
            read_u64(metadata_device(&lock_metadata)?, "lock_device")?,
            read_u64(metadata_inode(&lock_metadata)?, "lock_inode")?,
        )?;
        rollback_anchor.seed_new(&connection)?;
        validate_database_identity(&database_path, &expected_database)?;
        path_identity::ensure(&lock_root, &database_path, &store_uuid)?;
        Ok(())
    }

    pub fn open_serving(
        database_path: impl AsRef<Path>,
        lock_root: impl AsRef<Path>,
    ) -> Result<Self, SqliteServingOwnerError> {
        Self::ensure_serving_supported()?;
        let database_path = database_path.as_ref();
        validate_database_path_component(database_path)?;
        let database_path = fs::canonicalize(database_path)?;
        let lock_root = canonical_lock_root(lock_root.as_ref())?;
        let open_lock = File::open(&lock_root)?;
        open_lock.lock()?;
        validate_secure_directory(database_parent(&database_path), "authority database parent")?;
        let expected_database = fs::metadata(&database_path)?;
        let mut connection = open_existing_database(&database_path)?;
        let expected_data_version = authority_data_version(&connection)?;
        validate_database_identity(&database_path, &expected_database)?;
        if !owner_table_exists(&connection)? {
            verify_path_available_for_new_identity(&lock_root, &database_path)?;
            return Err(SqliteServingOwnerError::NotProvisioned(path_text(
                &database_path,
            )?));
        }
        verify_serving_owner_schema(&connection)?;
        let record = load_provisioning_record(&connection)?.ok_or_else(|| {
            SqliteServingOwnerError::PartialProvision(database_path.display().to_string())
        })?;
        validate_provisioning_record(&database_path, &lock_root, &record)?;
        path_identity::inspect(&lock_root, &database_path, Some(&record.store_uuid))?;
        let lock_path = lock_root.join(format!("{}.lock", record.store_uuid));
        let lock_file = open_lock_file(&lock_path)?;
        validate_open_lock_file(&lock_root, &lock_file, &record)?;
        acquire_serving_lock(&lock_file, &database_path)?;
        validate_open_lock_file(&lock_root, &lock_file, &record)?;
        validate_provisioning_record(&database_path, &lock_root, &record)?;

        connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = FULL;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = ON;
            "#,
        )?;
        initialize_serving_lease_schema(&connection)?;
        crate::admission_operation_store::initialize_admission_operation_schema(&mut connection)?;
        crate::channel_lifecycle_store::initialize_channel_lifecycle_schema(&mut connection)?;
        crate::channel_release_publisher_store::initialize_channel_release_publisher_schema(
            &mut connection,
        )?;
        crate::tool_outcome_store::initialize_tool_outcome_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_market_store::initialize_finding_market_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_purchase_store::initialize_finding_purchase_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_recovery_store::initialize_finding_recovery_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_challenge_store::initialize_finding_challenge_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        crate::finding_status_store::initialize_finding_status_schema(&mut connection)
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        verify_global_commit_schema(&connection)?;
        reset_derived_budget_ack_cache(&connection)?;
        for (key, supported) in [
            ("budget", BUDGET_STORE_SUPPORTED_SCHEMA_VERSION),
            ("revocation", REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION),
            (
                "admission_operation",
                crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "tool_outcome",
                crate::tool_outcome_store::TOOL_OUTCOME_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "frost",
                crate::frost_store::FROST_STORE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "economic_state_cache",
                crate::economic_state_cache::ECONOMIC_STATE_CACHE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "fiscal",
                crate::fiscal_store::FISCAL_STORE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "channel_lifecycle",
                crate::channel_lifecycle_store::CHANNEL_LIFECYCLE_SUPPORTED_SCHEMA_VERSION,
            ),
            (
                "channel_release_publisher",
                crate::channel_release_publisher_store::CHANNEL_RELEASE_PUBLISHER_SUPPORTED_SCHEMA_VERSION,
            ),
        ] {
            crate::check_schema_version(
                &connection,
                key,
                supported,
                &["capability_grant_budgets", "revoked_capabilities"],
            )
            .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
        }
        verify_authority_store_invariants(&connection)?;
        let rollback_anchor = RollbackAnchor::new(
            lock_file,
            &lock_root,
            &record.store_uuid,
            record.lock_device,
            record.lock_inode,
        )?;
        rollback_anchor.reconcile_startup(&connection)?;
        validate_database_identity(&database_path, &expected_database)?;
        path_identity::ensure(&lock_root, &database_path, &record.store_uuid)?;

        let owner_epoch = record.owner_epoch.checked_add(1).ok_or_else(|| {
            SqliteServingOwnerError::Invalid("serving owner epoch overflowed u64".to_string())
        })?;
        let lease_id = next_lease_id()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = load_provisioning_record_tx(&transaction)?.ok_or_else(|| {
            SqliteServingOwnerError::NotProvisioned(database_path.display().to_string())
        })?;
        if current.store_uuid != record.store_uuid || current.owner_epoch != record.owner_epoch {
            return Err(SqliteServingOwnerError::AlreadyServing(
                "serving owner changed while acquiring the lock".to_string(),
            ));
        }
        verify_authority_store_invariants(&transaction)?;
        let authority_head = transaction.query_row(
            "SELECT head_index FROM admission_authority_meta WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        if authority_head <= 0 {
            return Err(SqliteServingOwnerError::Invalid(
                "admission authority head is not positive".to_string(),
            ));
        }
        if record.owner_epoch > 0 {
            let previous_lease_id = transaction
                .query_row(
                    "SELECT lease_id FROM chio_serving_owner WHERE singleton = 1",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )?
                .ok_or_else(|| {
                    SqliteServingOwnerError::Invalid(
                        "active serving owner lost its lease identity".to_string(),
                    )
                })?;
            let closed = transaction.execute(
                r#"
                UPDATE chio_serving_leases
                SET end_head_index = ?1
                WHERE store_uuid = ?2 AND owner_epoch = ?3
                  AND lease_id = ?4 AND end_head_index IS NULL
                "#,
                params![
                    authority_head,
                    &record.store_uuid,
                    sqlite_u64(record.owner_epoch, "owner_epoch")?,
                    previous_lease_id,
                ],
            )?;
            if closed != 1 {
                return Err(SqliteServingOwnerError::Invalid(
                    "previous serving lease was not open exactly once".to_string(),
                ));
            }
        }
        let opened_at_ms = now_ms()?;
        let changed = transaction.execute(
            r#"
            UPDATE chio_serving_owner
            SET owner_epoch = ?1, lease_id = ?2, opened_at_ms = ?3
            WHERE singleton = 1 AND owner_epoch = ?4
            "#,
            params![
                sqlite_u64(owner_epoch, "owner_epoch")?,
                &lease_id,
                opened_at_ms,
                sqlite_u64(record.owner_epoch, "owner_epoch")?,
            ],
        )?;
        if changed != 1 {
            return Err(SqliteServingOwnerError::AlreadyServing(
                "serving owner changed while advancing its epoch".to_string(),
            ));
        }
        let inserted = transaction.execute(
            r#"
            INSERT INTO chio_serving_leases (
                store_uuid, owner_epoch, lease_id,
                start_head_index, end_head_index, opened_at_ms
            ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)
            "#,
            params![
                &record.store_uuid,
                sqlite_u64(owner_epoch, "owner_epoch")?,
                &lease_id,
                authority_head,
                opened_at_ms,
            ],
        )?;
        if inserted != 1 {
            return Err(SqliteServingOwnerError::Invalid(
                "serving lease insert did not affect exactly one row".to_string(),
            ));
        }
        verify_authority_store_invariants(&transaction)?;
        transaction.commit().map_err(|error| {
            SqliteServingOwnerError::OutcomeUnknown(format!(
                "sqlite serving-owner epoch commit outcome is unknown: {error}"
            ))
        })?;
        rollback_anchor.sync_after_commit(&connection)?;
        if authority_data_version(&connection)? != expected_data_version {
            return Err(SqliteServingOwnerError::Invalid(
                "authority database changed concurrently while opening".to_string(),
            ));
        }
        let owner = Arc::new(SqliteServingOwner {
            rollback_anchor,
            fence: StoreMutationFence {
                store_uuid: record.store_uuid,
                lease_id,
                owner_epoch,
            },
            poisoned: AtomicBool::new(false),
            expected_data_version: AtomicU64::new(expected_data_version),
        });
        crate::channel_release_publisher_store::quarantine_incomplete_dispatches_at_startup(
            &mut connection,
            &owner,
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            owner,
        })
    }

    #[must_use]
    pub fn mutation_fence(&self) -> StoreMutationFence {
        self.owner.fence.clone()
    }

    /// Verify that this live serving owner is bound to the configured
    /// authority database path and the provisioned filesystem identity.
    pub fn verify_database_path(
        &self,
        expected_path: impl AsRef<Path>,
    ) -> Result<(), SqliteServingOwnerError> {
        let expected_path = fs::canonicalize(expected_path.as_ref())?;
        let connection = self.connection.lock().map_err(|_| {
            SqliteServingOwnerError::Invalid(
                "sqlite authority connection mutex is poisoned".to_string(),
            )
        })?;
        self.owner.verify_authority_anchor(&connection)?;
        let record = load_provisioning_record(&connection)?.ok_or_else(|| {
            SqliteServingOwnerError::PartialProvision(expected_path.display().to_string())
        })?;
        validate_provisioning_record(&expected_path, Path::new(&record.lock_root), &record)
    }

    #[must_use]
    pub fn budget_store(&self) -> SqliteBudgetStore {
        SqliteBudgetStore::open_alongside(self.connection.clone(), self.owner.clone())
    }

    #[must_use]
    pub fn revocation_store(&self) -> SqliteRevocationStore {
        SqliteRevocationStore::open_alongside(self.connection.clone(), self.owner.clone())
    }

    #[must_use]
    pub fn admission_operation_store(
        &self,
    ) -> crate::admission_operation_store::SqliteAdmissionOperationStore {
        crate::admission_operation_store::SqliteAdmissionOperationStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn tool_outcome_store(&self) -> crate::tool_outcome_store::SqliteToolOutcomeStore {
        crate::tool_outcome_store::SqliteToolOutcomeStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn finding_market_store(&self) -> crate::finding_market_store::SqliteFindingMarketStore {
        crate::finding_market_store::SqliteFindingMarketStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn finding_purchase_store(
        &self,
    ) -> crate::finding_purchase_store::SqliteFindingPurchaseStore {
        crate::finding_purchase_store::SqliteFindingPurchaseStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn finding_recovery_store(
        &self,
    ) -> crate::finding_recovery_store::SqliteFindingRecoveryStore {
        crate::finding_recovery_store::SqliteFindingRecoveryStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn finding_challenge_store(
        &self,
    ) -> crate::finding_challenge_store::SqliteFindingChallengeStore {
        crate::finding_challenge_store::SqliteFindingChallengeStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn finding_status_store(&self) -> crate::finding_status_store::SqliteFindingStatusStore {
        crate::finding_status_store::SqliteFindingStatusStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn frost_store(&self) -> crate::frost_store::SqliteFrostStore {
        crate::frost_store::SqliteFrostStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn economic_state_cache(&self) -> crate::economic_state_cache::SqliteEconomicStateCache {
        crate::economic_state_cache::SqliteEconomicStateCache::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn fiscal_store(&self) -> crate::fiscal_store::SqliteFiscalStore {
        crate::fiscal_store::SqliteFiscalStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn channel_lifecycle_store(
        &self,
    ) -> crate::channel_lifecycle_store::SqliteChannelLifecycleStore {
        crate::channel_lifecycle_store::SqliteChannelLifecycleStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }

    #[must_use]
    pub fn channel_release_publisher_store(
        &self,
    ) -> crate::channel_release_publisher_store::SqliteChannelReleasePublisherStore {
        crate::channel_release_publisher_store::SqliteChannelReleasePublisherStore::open_alongside(
            self.connection.clone(),
            self.owner.clone(),
        )
    }
}

fn initialize_offline_authority_schemas(
    connection: &mut Connection,
) -> Result<(), SqliteServingOwnerError> {
    let has_revocation_schema = connection.query_row(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM sqlite_master
            WHERE type = 'table' AND name = 'revoked_capabilities'
        )
        "#,
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if has_revocation_schema {
        crate::check_schema_version(
            connection,
            "revocation",
            REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
            &["revoked_capabilities"],
        )
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    }
    SqliteBudgetStore::initialize_connection_offline(connection).map_err(|error| {
        SqliteServingOwnerError::Invalid(format!("failed to initialize budget schema: {error}"))
    })?;
    initialize_revocation_schema(connection, true).map_err(|error| {
        SqliteServingOwnerError::Invalid(format!("failed to initialize revocation schema: {error}"))
    })?;
    crate::stamp_schema_version(
        connection,
        "revocation",
        REVOCATION_STORE_SUPPORTED_SCHEMA_VERSION,
    )
    .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::frost_store::initialize_frost_schema(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::economic_state_cache::initialize_economic_state_cache_schema(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::fiscal_store::initialize_fiscal_schema(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    Ok(())
}

pub(crate) fn verify_budget_fence(
    transaction: &Transaction<'_>,
    owner: Option<&SqliteServingOwner>,
) -> Result<(), BudgetStoreError> {
    let current = load_fence_tx(transaction).map_err(BudgetStoreError::from)?;
    match (owner, current) {
        (None, FenceState::Unprovisioned) => Ok(()),
        (Some(owner), FenceState::Active(current)) if owner.fence == current => Ok(()),
        (Some(owner), current) => Err(BudgetStoreError::Fenced {
            expected_epoch: owner.fence.owner_epoch,
            actual_epoch: current.owner_epoch(),
        }),
        (None, current) => Err(BudgetStoreError::Fenced {
            expected_epoch: 0,
            actual_epoch: current.owner_epoch(),
        }),
    }
}

pub(crate) fn verify_revocation_fence(
    transaction: &Transaction<'_>,
    owner: Option<&SqliteServingOwner>,
) -> Result<(), RevocationStoreError> {
    verify_budget_fence(transaction, owner).map_err(|error| match error {
        BudgetStoreError::Fenced {
            expected_epoch,
            actual_epoch,
        } => RevocationStoreError::Fenced {
            expected_epoch,
            actual_epoch,
        },
        error => RevocationStoreError::Sync(error.to_string()),
    })
}

fn owner_table_exists(connection: &Connection) -> Result<bool, rusqlite::Error> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_serving_owner')",
        [],
        |row| row.get(0),
    )
}

fn verify_path_available_for_new_identity(
    lock_root: &Path,
    canonical_database_path: &Path,
) -> Result<(), SqliteServingOwnerError> {
    if path_identity::inspect(lock_root, canonical_database_path, None)?
        == path_identity::MarkerStatus::Present
    {
        return Err(SqliteServingOwnerError::Invalid(format!(
            "local path identity continuity marker remains for `{}` but the database lost its provisioning record; refusing to mint a replacement store UUID (this marker is local continuity evidence, not independent rollback protection)",
            canonical_database_path.display()
        )));
    }
    Ok(())
}

fn verify_serving_owner_schema(connection: &Connection) -> Result<(), SqliteServingOwnerError> {
    let expected = Connection::open_in_memory()?;
    expected.execute_batch(SERVING_OWNER_SCHEMA)?;
    if serving_owner_schema_catalog(connection)? != serving_owner_schema_catalog(&expected)? {
        return Err(SqliteServingOwnerError::Invalid(
            "serving owner schema differs from the canonical definition".to_string(),
        ));
    }
    Ok(())
}

fn serving_owner_schema_catalog(
    connection: &Connection,
) -> Result<Vec<SchemaCatalogEntry>, SqliteServingOwnerError> {
    let mut statement = connection.prepare(
        r#"
        SELECT type, name, tbl_name, sql FROM sqlite_schema
        WHERE name = 'chio_serving_owner' OR tbl_name = 'chio_serving_owner'
        ORDER BY type, name, tbl_name
        "#,
    )?;
    let catalog = statement
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(catalog)
}

pub(crate) fn verify_historical_revocation_commit(
    connection: &Connection,
    metadata: &RevocationCommitMetadata,
) -> Result<(), BudgetStoreError> {
    metadata.validate()?;
    if metadata.guarantee_level != BudgetGuaranteeLevel::SingleNodeAtomic {
        return Err(BudgetStoreError::Invariant(
            "local revocation provenance requires a single-node authority".to_string(),
        ));
    }
    verify_historical_budget_authority(connection, &metadata.authority)?;
    let lease_epoch = i64::try_from(metadata.authority.lease_epoch).map_err(|_| {
        BudgetStoreError::Invariant("revocation lease epoch exceeds SQLite range".to_string())
    })?;
    let commit_index = i64::try_from(metadata.commit_index).map_err(|_| {
        BudgetStoreError::Invariant("revocation commit index exceeds SQLite range".to_string())
    })?;
    let valid = connection.query_row(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM chio_serving_leases AS lease
            JOIN admission_authority_commits AS committed
              ON committed.commit_index = ?4
            JOIN admission_authority_meta AS authority ON authority.singleton = 1
            WHERE lease.store_uuid = ?1
              AND lease.owner_epoch = ?2
              AND lease.lease_id = ?3
              AND ?4 >= lease.start_head_index
              AND (
                    (lease.end_head_index IS NOT NULL
                     AND ?4 <= lease.end_head_index)
                    OR
                    (lease.end_head_index IS NULL
                     AND ?4 <= authority.head_index)
              )
        )
        "#,
        params![
            &metadata.authority.authority_id,
            lease_epoch,
            &metadata.authority.lease_id,
            commit_index,
        ],
        |row| row.get::<_, bool>(0),
    )?;
    if !valid {
        return Err(BudgetStoreError::Invariant(
            "revocation commit is outside its durable serving lease".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_historical_budget_authority(
    connection: &Connection,
    authority: &BudgetEventAuthority,
) -> Result<(), BudgetStoreError> {
    if authority.authority_id.is_empty()
        || authority.lease_id.is_empty()
        || authority.lease_epoch == 0
    {
        return Err(BudgetStoreError::Invariant(
            "budget authority requires a durable serving lease".to_string(),
        ));
    }
    let lease_epoch = i64::try_from(authority.lease_epoch).map_err(|_| {
        BudgetStoreError::Invariant("budget authority epoch exceeds SQLite range".to_string())
    })?;
    let valid = connection.query_row(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM chio_serving_leases AS lease
            JOIN chio_serving_owner AS owner ON owner.singleton = 1
            WHERE lease.store_uuid = ?1
              AND lease.owner_epoch = ?2
              AND lease.lease_id = ?3
              AND (
                    lease.end_head_index IS NOT NULL
                    OR
                    (owner.store_uuid = lease.store_uuid
                     AND owner.owner_epoch = lease.owner_epoch
                     AND owner.lease_id = lease.lease_id)
              )
        )
        "#,
        params![&authority.authority_id, lease_epoch, &authority.lease_id,],
        |row| row.get::<_, bool>(0),
    )?;
    if !valid {
        return Err(BudgetStoreError::Invariant(
            "budget authority is outside durable serving lease history".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn provisioned_owner_epoch(
    connection: &Connection,
) -> Result<Option<u64>, BudgetStoreError> {
    if !owner_table_exists(connection)? {
        return Ok(None);
    }
    let epoch = connection
        .query_row(
            "SELECT owner_epoch FROM chio_serving_owner WHERE singleton = 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| {
            BudgetStoreError::Invariant(
                "sqlite authority store is partially provisioned".to_string(),
            )
        })?;
    u64::try_from(epoch)
        .map(Some)
        .map_err(|_| BudgetStoreError::Invariant("negative serving owner epoch".to_string()))
}

fn load_provisioning_record(
    connection: &Connection,
) -> Result<Option<ProvisioningRecord>, SqliteServingOwnerError> {
    if !owner_table_exists(connection)? {
        return Ok(None);
    }
    load_provisioning_record_query(connection).map_err(Into::into)
}

fn load_provisioning_record_tx(
    transaction: &Transaction<'_>,
) -> Result<Option<ProvisioningRecord>, rusqlite::Error> {
    load_provisioning_record_query(transaction)
}

fn load_provisioning_record_query(
    connection: &Connection,
) -> Result<Option<ProvisioningRecord>, rusqlite::Error> {
    connection
        .query_row(
            r#"
            SELECT store_uuid, database_path, database_device, database_inode,
                   lock_root, lock_device, lock_inode, owner_epoch
            FROM chio_serving_owner WHERE singleton = 1
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?
        .map(|row| {
            Ok(ProvisioningRecord {
                store_uuid: row.0,
                database_path: row.1,
                database_device: read_u64(row.2, "database_device")?,
                database_inode: read_u64(row.3, "database_inode")?,
                lock_root: row.4,
                lock_device: read_u64(row.5, "lock_device")?,
                lock_inode: read_u64(row.6, "lock_inode")?,
                owner_epoch: read_u64(row.7, "owner_epoch")?,
            })
        })
        .transpose()
        .map_err(|error: SqliteServingOwnerError| {
            rusqlite::Error::InvalidParameterName(error.to_string())
        })
}

enum FenceState {
    Unprovisioned,
    Inactive(u64),
    Active(StoreMutationFence),
}

impl FenceState {
    fn owner_epoch(&self) -> Option<u64> {
        match self {
            Self::Unprovisioned => None,
            Self::Inactive(epoch) => Some(*epoch),
            Self::Active(fence) => Some(fence.owner_epoch),
        }
    }
}

fn load_fence_tx(transaction: &Transaction<'_>) -> Result<FenceState, rusqlite::Error> {
    let table_exists = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chio_serving_owner')",
        [],
        |row| row.get::<_, bool>(0),
    )?;
    if !table_exists {
        return Ok(FenceState::Unprovisioned);
    }
    let row = transaction
        .query_row(
            "SELECT store_uuid, lease_id, owner_epoch FROM chio_serving_owner WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let Some((store_uuid, lease_id, owner_epoch)) = row else {
        return Err(rusqlite::Error::InvalidQuery);
    };
    let owner_epoch = u64::try_from(owner_epoch).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(match lease_id {
        Some(lease_id) => FenceState::Active(StoreMutationFence {
            store_uuid,
            lease_id,
            owner_epoch,
        }),
        None => FenceState::Inactive(owner_epoch),
    })
}

fn validate_provisioning_record(
    database_path: &Path,
    lock_root: &Path,
    record: &ProvisioningRecord,
) -> Result<(), SqliteServingOwnerError> {
    validate_store_uuid(&record.store_uuid)?;
    if record.database_path != path_text(database_path)?
        || record.lock_root != path_text(lock_root)?
    {
        return Err(SqliteServingOwnerError::Invalid(
            "provisioned path identity changed".to_string(),
        ));
    }
    let database_metadata = fs::metadata(database_path)?;
    validate_database_metadata(&database_metadata)?;
    if metadata_device(&database_metadata)? != sqlite_u64(record.database_device, "device")?
        || metadata_inode(&database_metadata)? != sqlite_u64(record.database_inode, "inode")?
    {
        return Err(SqliteServingOwnerError::Invalid(
            "database file identity changed".to_string(),
        ));
    }
    let lock_path = lock_root.join(format!("{}.lock", record.store_uuid));
    let lock_metadata = fs::symlink_metadata(&lock_path)?;
    validate_lock_metadata(lock_root, &lock_metadata)?;
    if metadata_device(&lock_metadata)? != sqlite_u64(record.lock_device, "lock_device")?
        || metadata_inode(&lock_metadata)? != sqlite_u64(record.lock_inode, "lock_inode")?
    {
        return Err(SqliteServingOwnerError::Invalid(
            "serving lock inode changed".to_string(),
        ));
    }
    Ok(())
}

fn validate_open_lock_file(
    lock_root: &Path,
    lock_file: &File,
    record: &ProvisioningRecord,
) -> Result<(), SqliteServingOwnerError> {
    let metadata = lock_file.metadata()?;
    validate_lock_metadata(lock_root, &metadata)?;
    if metadata_device(&metadata)? != sqlite_u64(record.lock_device, "lock_device")?
        || metadata_inode(&metadata)? != sqlite_u64(record.lock_inode, "lock_inode")?
    {
        return Err(SqliteServingOwnerError::Invalid(
            "opened serving lock identity changed".to_string(),
        ));
    }
    Ok(())
}

fn validate_store_uuid(value: &str) -> Result<(), SqliteServingOwnerError> {
    validate_uuid_v7(value, "provisioned store UUID")
}

fn validate_uuid_v7(value: &str, field: &str) -> Result<(), SqliteServingOwnerError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| {
        SqliteServingOwnerError::Invalid(format!("{field} is not canonical UUID-v7"))
    })?;
    if parsed.get_version_num() != 7 || parsed.to_string() != value {
        return Err(SqliteServingOwnerError::Invalid(format!(
            "{field} is not canonical UUID-v7"
        )));
    }
    Ok(())
}

fn canonical_lock_root(path: &Path) -> Result<PathBuf, SqliteServingOwnerError> {
    let canonical = fs::canonicalize(path)?;
    validate_secure_directory(&canonical, "serving lock root")?;
    Ok(canonical)
}

fn validate_secure_directory(
    path: &Path,
    description: &str,
) -> Result<(), SqliteServingOwnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(SqliteServingOwnerError::Invalid(format!(
            "{description} is not a directory"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o022 != 0 {
            return Err(SqliteServingOwnerError::Invalid(format!(
                "{description} must be owned by the effective user and not group or world writable"
            )));
        }
    }
    Ok(())
}

fn database_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn create_database_file(path: &Path) -> Result<File, SqliteServingOwnerError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(Into::into)
}

fn open_existing_database(path: &Path) -> Result<Connection, SqliteServingOwnerError> {
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    // Provisioning writes before `open_serving` sets its own pragmas, so the busy
    // timeout has to be in place here or a transient lock aborts it instantly.
    connection.execute_batch("PRAGMA busy_timeout = 5000;")?;
    Ok(connection)
}

fn create_lock_file(path: &Path) -> Result<File, SqliteServingOwnerError> {
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(Into::into)
}

fn open_lock_file(path: &Path) -> Result<File, SqliteServingOwnerError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path).map_err(Into::into)
}

fn acquire_serving_lock(
    lock_file: &File,
    database_path: &Path,
) -> Result<(), SqliteServingOwnerError> {
    lock_file
        .try_lock()
        .map_err(|error| classify_lock_error(database_path, error.into()))
}

fn classify_lock_error(database_path: &Path, error: std::io::Error) -> SqliteServingOwnerError {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        SqliteServingOwnerError::AlreadyServing(format!("{}: {error}", database_path.display()))
    } else {
        SqliteServingOwnerError::Io(error)
    }
}

fn validate_database_metadata(metadata: &fs::Metadata) -> Result<(), SqliteServingOwnerError> {
    if !metadata.file_type().is_file() {
        return Err(SqliteServingOwnerError::Invalid(
            "authority database is not a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(SqliteServingOwnerError::Invalid(
                "authority database ownership, mode, or link count is invalid".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_database_path_component(path: &Path) -> Result<(), SqliteServingOwnerError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(SqliteServingOwnerError::Invalid(
            "authority database path must not be a symlink".to_string(),
        ));
    }
    validate_database_metadata(&metadata)
}

fn validate_database_identity(
    path: &Path,
    expected: &fs::Metadata,
) -> Result<(), SqliteServingOwnerError> {
    validate_database_path_component(path)?;
    let actual = fs::metadata(path)?;
    if metadata_device(&actual)? != metadata_device(expected)?
        || metadata_inode(&actual)? != metadata_inode(expected)?
    {
        return Err(SqliteServingOwnerError::Invalid(
            "authority database identity changed while opening".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
const UNSUPPORTED_SERVING_PLATFORM_MESSAGE: &str =
    "sqlite authority serving requires Unix file identity and positioned I/O";

fn validate_lock_metadata(
    lock_root: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SqliteServingOwnerError> {
    if !metadata.file_type().is_file() {
        return Err(SqliteServingOwnerError::Invalid(
            "serving lock is not a regular file".to_string(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let root_metadata = fs::metadata(lock_root)?;
        if metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.uid() != root_metadata.uid()
            || metadata.gid() != root_metadata.gid()
        {
            return Err(SqliteServingOwnerError::Invalid(
                "serving lock ownership, mode, or link count is invalid".to_string(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn metadata_device(metadata: &fs::Metadata) -> Result<i64, SqliteServingOwnerError> {
    use std::os::unix::fs::MetadataExt;
    sqlite_u64(metadata.dev(), "device")
}

#[cfg(not(unix))]
fn metadata_device(_metadata: &fs::Metadata) -> Result<i64, SqliteServingOwnerError> {
    Err(SqliteServingOwnerError::Invalid(
        "sqlite serving ownership requires Unix file identity".to_string(),
    ))
}

#[cfg(unix)]
fn metadata_inode(metadata: &fs::Metadata) -> Result<i64, SqliteServingOwnerError> {
    use std::os::unix::fs::MetadataExt;
    sqlite_u64(metadata.ino(), "inode")
}

#[cfg(not(unix))]
fn metadata_inode(_metadata: &fs::Metadata) -> Result<i64, SqliteServingOwnerError> {
    Err(SqliteServingOwnerError::Invalid(
        "sqlite serving ownership requires Unix file identity".to_string(),
    ))
}

fn sqlite_u64(value: u64, field: &str) -> Result<i64, SqliteServingOwnerError> {
    i64::try_from(value).map_err(|_| {
        SqliteServingOwnerError::Invalid(format!("{field} exceeds SQLite INTEGER range"))
    })
}

pub(super) fn read_u64(value: i64, field: &str) -> Result<u64, SqliteServingOwnerError> {
    u64::try_from(value)
        .map_err(|_| SqliteServingOwnerError::Invalid(format!("{field} is negative")))
}

fn path_text(path: &Path) -> Result<String, SqliteServingOwnerError> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| SqliteServingOwnerError::Invalid("path is not valid UTF-8".to_string()))
}

fn now_ms() -> Result<i64, SqliteServingOwnerError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| SqliteServingOwnerError::Invalid("wall clock overflowed i64".to_string()))
}

fn authority_data_version(connection: &Connection) -> Result<u64, SqliteServingOwnerError> {
    let version = connection.query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))?;
    read_u64(version, "sqlite data_version")
}

fn verify_authority_store_invariants(
    connection: &Connection,
) -> Result<(), SqliteServingOwnerError> {
    verify_serving_owner_schema(connection)?;
    let foreign_key_violation = connection
        .query_row("PRAGMA foreign_key_check", [], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    if let Some((table, rowid)) = foreign_key_violation {
        return Err(SqliteServingOwnerError::Invalid(format!(
            "sqlite foreign key violation in `{table}` row {rowid}"
        )));
    }
    verify_serving_lease_history(connection)?;
    crate::budget_store::composite_schema::verify_budget_projection_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    verify_admission_authority_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::admission_operation_store::verify_admission_operation_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::tool_outcome_store::verify_tool_outcome_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::frost_store::verify_frost_store_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::economic_state_cache::verify_cache_sql_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::fiscal_store::verify_fiscal_sql_invariants(connection)
        .map_err(|error| SqliteServingOwnerError::Invalid(error.to_string()))?;
    crate::channel_lifecycle_store::verify_channel_lifecycle_invariants(connection)?;
    crate::channel_release_publisher_store::verify_channel_release_publisher_invariants(
        connection,
    )?;
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "serving_owner/tests.rs"]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;

#[cfg(all(test, windows))]
mod windows_platform_tests {
    use super::*;

    #[test]
    fn provision_rejects_windows_before_creating_database_ancestry(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let lock_root = temp.path().join("locks");
        fs::create_dir(&lock_root)?;
        let database_parent = temp.path().join("state");
        let database = database_parent.join("authority.sqlite3");

        let error = match SqliteAuthorityStore::provision(&database, &lock_root) {
            Ok(()) => {
                return Err(std::io::Error::other(
                    "Windows authority provisioning unexpectedly succeeded",
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SqliteServingOwnerError::Invalid(message)
                if message == UNSUPPORTED_SERVING_PLATFORM_MESSAGE
        ));
        assert!(!database_parent.exists());
        assert!(!database.exists());
        assert!(fs::read_dir(&lock_root)?.next().is_none());
        Ok(())
    }

    #[test]
    fn open_serving_rejects_windows_before_accessing_paths(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let database = temp.path().join("missing").join("authority.sqlite3");
        let lock_root = temp.path().join("missing-locks");

        let error = match SqliteAuthorityStore::open_serving(&database, &lock_root) {
            Ok(_) => {
                return Err(std::io::Error::other(
                    "Windows authority serving unexpectedly succeeded",
                )
                .into());
            }
            Err(error) => error,
        };

        assert!(matches!(
            error,
            SqliteServingOwnerError::Invalid(message)
                if message == UNSUPPORTED_SERVING_PLATFORM_MESSAGE
        ));
        assert!(!database.exists());
        assert!(!lock_root.exists());
        Ok(())
    }
}
