use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use chio_core::crypto::{PublicKey, SigningAlgorithm, SigningBackend};
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::finding_pool::FindingPoolLedgerError;
use rand_core::{OsRng, RngCore};
use rusqlite::{Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::rollback_generation::RollbackGenerationAnchor;

pub(super) struct FindingPoolDomainLease {
    database_identity: PathBuf,
    _lock_file: File,
}

#[derive(Clone)]
pub(super) struct QualifiedDatabaseIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl QualifiedDatabaseIdentity {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn validate(&self) -> Result<(), FindingPoolLedgerError> {
        let metadata = std::fs::metadata(&self.path)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        validate_database_metadata(&metadata)?;
        if metadata_device(&metadata)? != self.device || metadata_inode(&metadata)? != self.inode {
            return Err(FindingPoolLedgerError::Storage(
                "qualified finding pool database inode changed".to_string(),
            ));
        }
        Ok(())
    }
}

pub(super) struct AnchoredLedgerTransaction<'connection> {
    transaction: Transaction<'connection>,
    anchor: Arc<RollbackGenerationAnchor>,
    generation: u64,
}

impl<'connection> AnchoredLedgerTransaction<'connection> {
    pub(super) fn begin(
        connection: &'connection mut rusqlite::Connection,
        anchor: Arc<RollbackGenerationAnchor>,
    ) -> Result<Self, FindingPoolLedgerError> {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let generation = load_store_generation(&transaction)?;
        anchor.verify(generation).map_err(rollback_anchor_error)?;
        Ok(Self {
            transaction,
            anchor,
            generation,
        })
    }

    pub(super) fn commit(self) -> Result<(), FindingPoolLedgerError> {
        let next = self.generation.checked_add(1).ok_or_else(|| {
            FindingPoolLedgerError::Storage(
                "finding pool rollback generation overflowed".to_string(),
            )
        })?;
        let changed = self
            .transaction
            .execute(
                "UPDATE finding_pool_ledger_metadata SET store_generation = ?1 \
                 WHERE singleton = 1 AND store_generation = ?2",
                rusqlite::params![next.to_string(), self.generation.to_string()],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        if changed != 1 {
            return Err(FindingPoolLedgerError::Storage(
                "finding pool rollback generation compare-and-set failed".to_string(),
            ));
        }
        let Self {
            transaction,
            anchor,
            generation,
        } = self;
        anchor
            .advance_while(generation, next, || {
                transaction
                    .commit()
                    .map_err(|error| format!("SQLite commit failed: {error}"))
            })
            .map_err(rollback_anchor_error)
    }
}

impl<'connection> Deref for AnchoredLedgerTransaction<'connection> {
    type Target = Transaction<'connection>;

    fn deref(&self) -> &Self::Target {
        &self.transaction
    }
}

impl<'connection> DerefMut for AnchoredLedgerTransaction<'connection> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transaction
    }
}

static FINDING_POOL_DOMAIN_LEASES: OnceLock<Mutex<BTreeMap<String, Weak<FindingPoolDomainLease>>>> =
    OnceLock::new();

pub(super) fn prepare_database_identity(
    path_text: &str,
) -> Result<QualifiedDatabaseIdentity, FindingPoolLedgerError> {
    let filesystem_path = if path_text.starts_with("file:") {
        let encoded = sqlite_uri_filename(path_text);
        let decoded = super::percent_decode_uri_component(encoded).ok_or_else(|| {
            FindingPoolLedgerError::Storage(
                "SQLite URI filename has invalid percent encoding".to_string(),
            )
        })?;
        if decoded.contains('\0') {
            return Err(FindingPoolLedgerError::Storage(
                "SQLite URI filename contains a NUL byte".to_string(),
            ));
        }
        PathBuf::from(decoded)
    } else {
        PathBuf::from(path_text)
    };
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(&filesystem_path).map_err(|error| {
        FindingPoolLedgerError::Storage(format!(
            "qualified finding pool database cannot be securely opened: {error}"
        ))
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    validate_database_metadata(&metadata)?;
    let device = metadata_device(&metadata)?;
    let inode = metadata_inode(&metadata)?;
    let path = std::fs::canonicalize(&filesystem_path).map_err(|error| {
        FindingPoolLedgerError::Storage(format!(
            "qualified finding pool database identity is unavailable: {error}"
        ))
    })?;
    let identity = QualifiedDatabaseIdentity {
        path,
        device,
        inode,
    };
    identity.validate()?;
    Ok(identity)
}

pub(super) fn open_rollback_anchor(
    root: &Path,
    ledger_domain: &str,
    database_identity: &QualifiedDatabaseIdentity,
    store_identity: &dyn SigningBackend,
) -> Result<Arc<RollbackGenerationAnchor>, FindingPoolLedgerError> {
    let public_key = store_identity.public_key();
    let public_key_bytes = chio_core::canonical::canonical_json_bytes(&public_key)
        .map_err(|_| FindingPoolLedgerError::InvalidLedgerStoreIdentity)?;
    let mut scope = Vec::new();
    append_binding_part(&mut scope, b"chio.finding-pool.rollback-generation.v1");
    append_binding_part(&mut scope, ledger_domain.as_bytes());
    append_binding_part(
        &mut scope,
        database_identity.path().as_os_str().as_encoded_bytes(),
    );
    append_binding_part(&mut scope, &public_key_bytes);
    RollbackGenerationAnchor::open(root, &scope)
        .map(Arc::new)
        .map_err(rollback_anchor_error)
}

pub(super) fn bind_rollback_anchor(
    connection: &rusqlite::Connection,
    anchor: &RollbackGenerationAnchor,
) -> Result<(), FindingPoolLedgerError> {
    anchor
        .bind_initial_while(|| {
            let generation =
                load_store_generation(connection).map_err(|error| error.to_string())?;
            let populated = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM finding_pool_allocations LIMIT 1) \
                            OR EXISTS(SELECT 1 FROM finding_pool_debits LIMIT 1) \
                            OR EXISTS(SELECT 1 FROM finding_pool_receipt_outbox LIMIT 1)",
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .map_err(|error| error.to_string())?;
            Ok((generation, !populated))
        })
        .map_err(rollback_anchor_error)
}

pub(super) fn verify_rollback_anchor(
    connection: &rusqlite::Connection,
    anchor: &RollbackGenerationAnchor,
) -> Result<(), FindingPoolLedgerError> {
    anchor
        .verify_while(|| load_store_generation(connection).map_err(|error| error.to_string()))
        .map_err(rollback_anchor_error)
}

pub(super) fn acquire_domain_lease(
    ledger_domain: &str,
    database_identity: &Path,
) -> Result<Arc<FindingPoolDomainLease>, FindingPoolLedgerError> {
    let leases = FINDING_POOL_DOMAIN_LEASES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut leases = leases.lock().map_err(|_| {
        FindingPoolLedgerError::Storage("finding pool domain lease registry is poisoned".to_owned())
    })?;
    leases.retain(|_, lease| lease.strong_count() > 0);
    if let Some(active) = leases.get(ledger_domain).and_then(Weak::upgrade) {
        if active.database_identity == database_identity {
            return Ok(active);
        }
        return Err(FindingPoolLedgerError::LedgerDomainInUse);
    }

    let lock_root = domain_lock_root()?;
    let lock_name = format!(
        "{}.lock",
        hex::encode(Sha256::digest(ledger_domain.as_bytes()))
    );
    let lock_path = lock_root.join(lock_name);
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock_file = options
        .open(&lock_path)
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    validate_domain_lock(&lock_file)?;
    lock_file.try_lock().map_err(|error| {
        let error: std::io::Error = error.into();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            FindingPoolLedgerError::LedgerDomainInUse
        } else {
            FindingPoolLedgerError::Storage(error.to_string())
        }
    })?;
    let lease = Arc::new(FindingPoolDomainLease {
        database_identity: database_identity.to_path_buf(),
        _lock_file: lock_file,
    });
    leases.insert(ledger_domain.to_owned(), Arc::downgrade(&lease));
    Ok(lease)
}

pub(super) fn bind_receipt_authority(
    transaction: &rusqlite::Transaction<'_>,
    authority: &PublicKey,
) -> Result<(), FindingPoolLedgerError> {
    let authority_json = canonical_receipt_authority_json(authority)?;
    let persisted = transaction
        .query_row(
            "SELECT receipt_authority_json FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if let Some(persisted) = persisted.as_deref() {
        if persisted != authority_json {
            return Err(FindingPoolLedgerError::ReceiptAuthorityMismatch);
        }
    } else {
        verify_legacy_outbox_authority(transaction, &authority_json)?;
    }
    transaction
        .execute(
            "UPDATE finding_pool_ledger_metadata SET receipt_authority_json = ?1 \
             WHERE singleton = 1 AND receipt_authority_json IS NULL",
            [&authority_json],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let persisted = transaction
        .query_row(
            "SELECT receipt_authority_json FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if persisted.as_deref() != Some(authority_json.as_str()) {
        return Err(FindingPoolLedgerError::ReceiptAuthorityMismatch);
    }
    Ok(())
}

pub(super) fn bind_receipt_configuration(
    transaction: &rusqlite::Transaction<'_>,
    authority: &PublicKey,
    receipt_sink_id: &str,
) -> Result<(), FindingPoolLedgerError> {
    super::validate_receipt_sink_id(receipt_sink_id)?;
    let authority_json = canonical_receipt_authority_json(authority)?;
    let (persisted_sink, persisted_authority) = transaction
        .query_row(
            "SELECT receipt_sink_id, receipt_authority_json \
             FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if persisted_sink
        .as_deref()
        .is_some_and(|persisted| persisted != receipt_sink_id)
    {
        return Err(FindingPoolLedgerError::ReceiptSinkMismatch);
    }
    if persisted_authority
        .as_deref()
        .is_some_and(|persisted| persisted != authority_json)
    {
        return Err(FindingPoolLedgerError::ReceiptAuthorityMismatch);
    }
    if persisted_authority.is_none() {
        verify_legacy_outbox_authority(transaction, &authority_json)?;
    }
    transaction
        .execute(
            "UPDATE finding_pool_ledger_metadata \
             SET receipt_sink_id = COALESCE(receipt_sink_id, ?1), \
                 receipt_authority_json = COALESCE(receipt_authority_json, ?2) \
             WHERE singleton = 1",
            rusqlite::params![receipt_sink_id, authority_json],
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let rebound = transaction
        .query_row(
            "SELECT receipt_sink_id, receipt_authority_json \
             FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if rebound.0.as_deref() != Some(receipt_sink_id)
        || rebound.1.as_deref() != Some(authority_json.as_str())
    {
        return Err(FindingPoolLedgerError::ReceiptConfigurationMismatch);
    }
    Ok(())
}

pub(super) fn bind_ledger_store(
    connection: &mut rusqlite::Connection,
    ledger_domain: &str,
    database_identity: &QualifiedDatabaseIdentity,
    store_identity: &dyn SigningBackend,
    rollback_anchor: &RollbackGenerationAnchor,
) -> Result<String, FindingPoolLedgerError> {
    let anchor_instance_id = rollback_anchor
        .instance_id()
        .map_err(rollback_anchor_error)?;
    let expected = derive_ledger_store_binding(
        ledger_domain,
        database_identity,
        store_identity,
        &anchor_instance_id,
    )?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let persisted = transaction
        .query_row(
            "SELECT ledger_store_binding_sha256 FROM finding_pool_ledger_metadata \
             WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if let Some(persisted) = persisted.as_deref() {
        if persisted != expected {
            return Err(FindingPoolLedgerError::LedgerStoreBindingMismatch);
        }
    } else {
        transaction
            .execute(
                "UPDATE finding_pool_ledger_metadata \
                 SET ledger_store_binding_sha256 = ?1 \
                 WHERE singleton = 1 AND ledger_store_binding_sha256 IS NULL",
                [&expected],
            )
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    }
    let bound = transaction
        .query_row(
            "SELECT ledger_store_binding_sha256 FROM finding_pool_ledger_metadata \
             WHERE singleton = 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
        .ok_or_else(|| super::invariant("ledger store binding is absent"))?;
    if bound.len() != 64
        || !bound
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(super::invariant(
            "ledger store binding is not canonical SHA-256",
        ));
    }
    if bound != expected {
        return Err(FindingPoolLedgerError::LedgerStoreBindingMismatch);
    }
    transaction
        .commit()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    Ok(expected)
}

fn derive_ledger_store_binding(
    ledger_domain: &str,
    database_identity: &QualifiedDatabaseIdentity,
    store_identity: &dyn SigningBackend,
    anchor_instance_id: &str,
) -> Result<String, FindingPoolLedgerError> {
    let public_key = store_identity.public_key();
    if public_key.algorithm() == SigningAlgorithm::Ed25519 && public_key.is_weak_ed25519() {
        return Err(FindingPoolLedgerError::InvalidLedgerStoreIdentity);
    }
    let identity_material = database_identity_material(database_identity)?;
    let public_key_bytes = chio_core::canonical::canonical_json_bytes(&public_key)
        .map_err(|_| FindingPoolLedgerError::InvalidLedgerStoreIdentity)?;

    let mut nonce = [0_u8; 32];
    OsRng.try_fill_bytes(&mut nonce).map_err(|error| {
        FindingPoolLedgerError::Storage(format!(
            "qualified finding pool store identity challenge entropy failed: {error}"
        ))
    })?;
    let mut challenge = Vec::new();
    append_binding_part(&mut challenge, b"chio.finding-pool.store-identity-proof.v1");
    append_binding_part(&mut challenge, ledger_domain.as_bytes());
    append_binding_part(&mut challenge, &identity_material);
    append_binding_part(&mut challenge, &nonce);
    let proof = store_identity
        .sign_bytes(&challenge)
        .map_err(|_| FindingPoolLedgerError::InvalidLedgerStoreIdentity)?;
    if !public_key.verify(&challenge, &proof) {
        return Err(FindingPoolLedgerError::InvalidLedgerStoreIdentity);
    }

    let mut binding = Sha256::new();
    binding.update(b"chio.finding-pool.store-binding.v3");
    binding.update((ledger_domain.len() as u64).to_be_bytes());
    binding.update(ledger_domain.as_bytes());
    binding.update((identity_material.len() as u64).to_be_bytes());
    binding.update(&identity_material);
    binding.update((public_key_bytes.len() as u64).to_be_bytes());
    binding.update(public_key_bytes);
    binding.update((anchor_instance_id.len() as u64).to_be_bytes());
    binding.update(anchor_instance_id.as_bytes());
    Ok(hex::encode(binding.finalize()))
}

fn database_identity_material(
    identity: &QualifiedDatabaseIdentity,
) -> Result<Vec<u8>, FindingPoolLedgerError> {
    identity.validate()?;
    let path = identity.path();
    let canonical_path = path.to_str().ok_or_else(|| {
        FindingPoolLedgerError::Storage(
            "qualified finding pool database identity is not valid UTF-8".to_string(),
        )
    })?;
    let mut material = Vec::new();
    append_binding_part(&mut material, canonical_path.as_bytes());
    #[cfg(unix)]
    {
        append_binding_part(&mut material, &identity.device.to_be_bytes());
        append_binding_part(&mut material, &identity.inode.to_be_bytes());
    }
    Ok(material)
}

fn append_binding_part(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn verify_legacy_outbox_authority(
    transaction: &rusqlite::Transaction<'_>,
    authority_json: &str,
) -> Result<(), FindingPoolLedgerError> {
    let mut statement = transaction
        .prepare("SELECT signed_receipt_json FROM finding_pool_receipt_outbox ORDER BY rowid")
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let mut rows = statement
        .query([])
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    while let Some(row) = rows
        .next()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?
    {
        let receipt_json = row
            .get::<_, String>(0)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        let receipt = serde_json::from_str::<ChioReceipt>(&receipt_json)
            .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
        if canonical_receipt_authority_json(&receipt.kernel_key)? != authority_json {
            return Err(FindingPoolLedgerError::ReceiptAuthorityMismatch);
        }
    }
    Ok(())
}

pub(super) fn canonical_receipt_authority_json(
    authority: &PublicKey,
) -> Result<String, FindingPoolLedgerError> {
    if authority.algorithm() != SigningAlgorithm::Ed25519 || authority.is_weak_ed25519() {
        return Err(FindingPoolLedgerError::InvalidReceiptAuthority);
    }
    String::from_utf8(
        chio_core::canonical::canonical_json_bytes(authority)
            .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?,
    )
    .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
}

fn sqlite_uri_filename(path: &str) -> &str {
    let rest = path.strip_prefix("file:").unwrap_or(path);
    let rest = rest.split_once('#').map_or(rest, |(uri, _)| uri);
    let name = rest.split_once('?').map_or(rest, |(name, _)| name);
    match name.strip_prefix("//") {
        Some(authority_and_path) => authority_and_path
            .find('/')
            .map_or("", |path_start| &authority_and_path[path_start..]),
        None => name,
    }
}

fn domain_lock_root() -> Result<PathBuf, FindingPoolLedgerError> {
    #[cfg(unix)]
    let mut root = PathBuf::from("/tmp");
    #[cfg(not(unix))]
    let mut root = std::env::temp_dir();
    #[cfg(unix)]
    root.push(format!(
        "chio-finding-pool-domain-leases-{}",
        nix::unistd::geteuid().as_raw()
    ));
    #[cfg(not(unix))]
    root.push("chio-finding-pool-domain-leases");

    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(&root) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(FindingPoolLedgerError::Storage(error.to_string())),
    }
    let metadata = std::fs::symlink_metadata(&root)
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if !metadata.file_type().is_dir() {
        return Err(FindingPoolLedgerError::Storage(
            "finding pool domain lock root is not a directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(FindingPoolLedgerError::Storage(
                "finding pool domain lock root must be private to the effective user".to_owned(),
            ));
        }
    }
    std::fs::canonicalize(root).map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
}

fn validate_domain_lock(lock_file: &File) -> Result<(), FindingPoolLedgerError> {
    let metadata = lock_file
        .metadata()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(FindingPoolLedgerError::Storage(
            "finding pool domain lease is not a regular file".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.mode() & 0o022 != 0
        {
            return Err(FindingPoolLedgerError::Storage(
                "finding pool domain lease has unsafe ownership or permissions".to_owned(),
            ));
        }
    }
    Ok(())
}

fn load_store_generation(connection: &rusqlite::Connection) -> Result<u64, FindingPoolLedgerError> {
    let generation = connection
        .query_row(
            "SELECT store_generation FROM finding_pool_ledger_metadata WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    if generation.is_empty()
        || (generation.len() > 1 && generation.starts_with('0'))
        || !generation.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(FindingPoolLedgerError::Storage(
            "finding pool rollback generation is not canonical".to_string(),
        ));
    }
    generation.parse::<u64>().map_err(|error| {
        FindingPoolLedgerError::Storage(format!(
            "finding pool rollback generation is invalid: {error}"
        ))
    })
}

fn rollback_anchor_error(error: String) -> FindingPoolLedgerError {
    FindingPoolLedgerError::Storage(format!("finding pool rollback protection failed: {error}"))
}

#[cfg(unix)]
fn validate_database_metadata(metadata: &std::fs::Metadata) -> Result<(), FindingPoolLedgerError> {
    use std::os::unix::fs::MetadataExt as _;

    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(FindingPoolLedgerError::Storage(
            "qualified finding pool database has unsafe ownership or permissions".to_string(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_database_metadata(_metadata: &std::fs::Metadata) -> Result<(), FindingPoolLedgerError> {
    Err(FindingPoolLedgerError::Storage(
        "qualified finding pool databases require Unix file identity".to_string(),
    ))
}

#[cfg(unix)]
fn metadata_device(metadata: &std::fs::Metadata) -> Result<u64, FindingPoolLedgerError> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(metadata.dev())
}

#[cfg(not(unix))]
fn metadata_device(_metadata: &std::fs::Metadata) -> Result<u64, FindingPoolLedgerError> {
    Err(FindingPoolLedgerError::Storage(
        "qualified finding pool databases require Unix file identity".to_string(),
    ))
}

#[cfg(unix)]
fn metadata_inode(metadata: &std::fs::Metadata) -> Result<u64, FindingPoolLedgerError> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(metadata.ino())
}

#[cfg(not(unix))]
fn metadata_inode(_metadata: &std::fs::Metadata) -> Result<u64, FindingPoolLedgerError> {
    Err(FindingPoolLedgerError::Storage(
        "qualified finding pool databases require Unix file identity".to_string(),
    ))
}
