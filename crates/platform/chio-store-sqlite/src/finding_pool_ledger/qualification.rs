use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use chio_core::crypto::{PublicKey, SigningAlgorithm, SigningBackend};
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::finding_pool::FindingPoolLedgerError;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rand_core::{OsRng, RngCore};
use rusqlite::TransactionBehavior;
use sha2::{Digest, Sha256};

pub(super) struct FindingPoolDomainLease {
    database_identity: PathBuf,
    _lock_file: File,
}

static FINDING_POOL_DOMAIN_LEASES: OnceLock<Mutex<BTreeMap<String, Weak<FindingPoolDomainLease>>>> =
    OnceLock::new();

pub(super) fn database_identity(path_text: &str) -> Result<PathBuf, FindingPoolLedgerError> {
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
    std::fs::canonicalize(&filesystem_path).map_err(|error| {
        FindingPoolLedgerError::Storage(format!(
            "qualified finding pool database identity is unavailable: {error}"
        ))
    })
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
    pool: &Pool<SqliteConnectionManager>,
    authority: &PublicKey,
) -> Result<(), FindingPoolLedgerError> {
    let authority_json = canonical_receipt_authority_json(authority)?;
    let mut connection = pool
        .get()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
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
        verify_legacy_outbox_authority(&transaction, &authority_json)?;
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
    transaction
        .commit()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
}

pub(super) fn bind_receipt_configuration(
    pool: &Pool<SqliteConnectionManager>,
    authority: &PublicKey,
    receipt_sink_id: &str,
) -> Result<(), FindingPoolLedgerError> {
    super::validate_receipt_sink_id(receipt_sink_id)?;
    let authority_json = canonical_receipt_authority_json(authority)?;
    let mut connection = pool
        .get()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
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
        verify_legacy_outbox_authority(&transaction, &authority_json)?;
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
    transaction
        .commit()
        .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))
}

pub(super) fn bind_ledger_store(
    connection: &mut rusqlite::Connection,
    ledger_domain: &str,
    database_identity: &Path,
    store_identity: &dyn SigningBackend,
) -> Result<String, FindingPoolLedgerError> {
    let expected = derive_ledger_store_binding(ledger_domain, database_identity, store_identity)?;
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
    database_identity: &Path,
    store_identity: &dyn SigningBackend,
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
    binding.update(b"chio.finding-pool.store-binding.v2");
    binding.update((ledger_domain.len() as u64).to_be_bytes());
    binding.update(ledger_domain.as_bytes());
    binding.update((identity_material.len() as u64).to_be_bytes());
    binding.update(&identity_material);
    binding.update((public_key_bytes.len() as u64).to_be_bytes());
    binding.update(public_key_bytes);
    Ok(hex::encode(binding.finalize()))
}

fn database_identity_material(path: &Path) -> Result<Vec<u8>, FindingPoolLedgerError> {
    let canonical_path = path.to_str().ok_or_else(|| {
        FindingPoolLedgerError::Storage(
            "qualified finding pool database identity is not valid UTF-8".to_string(),
        )
    })?;
    let mut material = Vec::new();
    append_binding_part(&mut material, canonical_path.as_bytes());
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::metadata(path)
            .map_err(|error| FindingPoolLedgerError::Storage(error.to_string()))?;
        append_binding_part(&mut material, &metadata.dev().to_be_bytes());
        append_binding_part(&mut material, &metadata.ino().to_be_bytes());
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
