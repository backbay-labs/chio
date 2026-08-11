use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use chio_core::crypto::{PublicKey, SigningAlgorithm};
use chio_core::receipt::body::ChioReceipt;
use chio_kernel::finding_pool::FindingPoolLedgerError;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
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
