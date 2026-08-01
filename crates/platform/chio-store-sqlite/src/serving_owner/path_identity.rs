//! Local database-path identity continuity.
//!
//! This marker prevents an older, pre-provision database image from silently
//! receiving a new store UUID while the local lock root survives. It is local
//! continuity evidence, not independent rollback protection: restoring or
//! deleting the lock root can remove both this marker and the rollback anchor.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use chio_core::canonical::canonical_json_bytes;
use chio_core::sha256_hex;
use serde::{Deserialize, Serialize};

use super::{
    metadata_device, metadata_inode, path_text, read_u64, validate_lock_metadata,
    validate_store_uuid, SqliteServingOwnerError,
};

const FORMAT: &str = "chio.sqlite-local-path-identity.v1";
const MAX_MARKER_BYTES: u64 = 4 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MarkerStatus {
    Missing,
    Present,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PathIdentityRecord {
    format: String,
    canonical_database_path: String,
    store_uuid: String,
    marker_device: u64,
    marker_inode: u64,
}

pub(super) fn marker_path(
    lock_root: &Path,
    canonical_database_path: &Path,
) -> Result<PathBuf, SqliteServingOwnerError> {
    let path = path_text(canonical_database_path)?;
    Ok(lock_root.join(format!(
        ".chio-path-{}.identity",
        sha256_hex(path.as_bytes())
    )))
}

pub(super) fn inspect(
    lock_root: &Path,
    canonical_database_path: &Path,
    expected_store_uuid: Option<&str>,
) -> Result<MarkerStatus, SqliteServingOwnerError> {
    let marker_path = marker_path(lock_root, canonical_database_path)?;
    let path_metadata = match fs::symlink_metadata(&marker_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(MarkerStatus::Missing),
        Err(error) => return Err(error.into()),
    };
    validate_marker_metadata(lock_root, &path_metadata)?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&marker_path)?;
    let file_metadata = file.metadata()?;
    validate_marker_metadata(lock_root, &file_metadata)?;
    validate_inode_identity(&path_metadata, &file_metadata, None)?;
    if file_metadata.len() == 0 || file_metadata.len() > MAX_MARKER_BYTES {
        return Err(invalid(
            "local path identity continuity marker has an invalid size",
        ));
    }

    let capacity = usize::try_from(file_metadata.len()).map_err(|_| {
        invalid("local path identity continuity marker length exceeds address space")
    })?;
    let mut encoded = Vec::with_capacity(capacity);
    Read::by_ref(&mut file)
        .take(MAX_MARKER_BYTES + 1)
        .read_to_end(&mut encoded)?;
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| invalid("local path identity continuity marker length exceeds u64"))?;
    if encoded_len != file_metadata.len() {
        return Err(invalid(
            "local path identity continuity marker changed while reading",
        ));
    }
    let record: PathIdentityRecord = serde_json::from_slice(&encoded).map_err(|error| {
        invalid(format!(
            "local path identity continuity marker is not canonical JSON: {error}"
        ))
    })?;
    validate_record(
        &record,
        canonical_database_path,
        expected_store_uuid,
        &file_metadata,
    )?;
    let canonical = canonical_json_bytes(&record).map_err(|error| {
        invalid(format!(
            "local path identity continuity marker encoding failed: {error}"
        ))
    })?;
    if canonical != encoded {
        return Err(invalid(
            "local path identity continuity marker encoding is not canonical",
        ));
    }

    let current_path_metadata = fs::symlink_metadata(&marker_path)?;
    validate_marker_metadata(lock_root, &current_path_metadata)?;
    validate_inode_identity(&current_path_metadata, &file_metadata, Some(&record))?;
    Ok(MarkerStatus::Present)
}

pub(super) fn ensure(
    lock_root: &Path,
    canonical_database_path: &Path,
    store_uuid: &str,
) -> Result<(), SqliteServingOwnerError> {
    if inspect(lock_root, canonical_database_path, Some(store_uuid))? == MarkerStatus::Present {
        return Ok(());
    }
    validate_store_uuid(store_uuid)?;

    let marker_path = marker_path(lock_root, canonical_database_path)?;
    let staged_path = lock_root.join(format!(
        ".chio-path-identity-stage-{}.tmp",
        uuid::Uuid::now_v7()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut staged = options.open(&staged_path)?;
    let metadata = staged.metadata()?;
    validate_marker_metadata(lock_root, &metadata)?;
    let record = PathIdentityRecord {
        format: FORMAT.to_string(),
        canonical_database_path: path_text(canonical_database_path)?,
        store_uuid: store_uuid.to_string(),
        marker_device: read_u64(metadata_device(&metadata)?, "path identity marker device")?,
        marker_inode: read_u64(metadata_inode(&metadata)?, "path identity marker inode")?,
    };
    let encoded = match canonical_json_bytes(&record) {
        Ok(encoded) => encoded,
        Err(error) => {
            drop(staged);
            let _ = fs::remove_file(&staged_path);
            return Err(invalid(format!(
                "local path identity continuity marker encoding failed: {error}"
            )));
        }
    };
    let stage_result = staged.write_all(&encoded).and_then(|()| staged.sync_all());
    drop(staged);
    if let Err(error) = stage_result {
        let _ = fs::remove_file(&staged_path);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&staged_path, &marker_path) {
        let _ = fs::remove_file(&staged_path);
        return Err(error.into());
    }

    if let Err(error) = File::open(lock_root).and_then(|directory| directory.sync_all()) {
        return Err(outcome_unknown(error));
    }
    inspect(lock_root, canonical_database_path, Some(store_uuid))
        .map(|_| ())
        .map_err(|error| outcome_unknown(error.to_string()))
}

fn validate_record(
    record: &PathIdentityRecord,
    canonical_database_path: &Path,
    expected_store_uuid: Option<&str>,
    metadata: &fs::Metadata,
) -> Result<(), SqliteServingOwnerError> {
    validate_store_uuid(&record.store_uuid)?;
    if record.format != FORMAT
        || record.canonical_database_path != path_text(canonical_database_path)?
        || expected_store_uuid.is_some_and(|expected| expected != record.store_uuid)
    {
        return Err(invalid(
            "local path identity continuity marker does not match the provisioned database",
        ));
    }
    validate_inode_identity(metadata, metadata, Some(record))
}

fn validate_inode_identity(
    path_metadata: &fs::Metadata,
    file_metadata: &fs::Metadata,
    record: Option<&PathIdentityRecord>,
) -> Result<(), SqliteServingOwnerError> {
    let path_device = read_u64(
        metadata_device(path_metadata)?,
        "path identity marker device",
    )?;
    let path_inode = read_u64(metadata_inode(path_metadata)?, "path identity marker inode")?;
    let file_device = read_u64(
        metadata_device(file_metadata)?,
        "path identity marker device",
    )?;
    let file_inode = read_u64(metadata_inode(file_metadata)?, "path identity marker inode")?;
    if path_device != file_device
        || path_inode != file_inode
        || record.is_some_and(|value| {
            value.marker_device != file_device || value.marker_inode != file_inode
        })
    {
        return Err(invalid(
            "local path identity continuity marker inode changed",
        ));
    }
    Ok(())
}

fn validate_marker_metadata(
    lock_root: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SqliteServingOwnerError> {
    validate_lock_metadata(lock_root, metadata).map_err(|error| {
        invalid(format!(
            "local path identity continuity marker security check failed: {error}"
        ))
    })
}

fn invalid(detail: impl Into<String>) -> SqliteServingOwnerError {
    SqliteServingOwnerError::Invalid(detail.into())
}

fn outcome_unknown(detail: impl std::fmt::Display) -> SqliteServingOwnerError {
    SqliteServingOwnerError::OutcomeUnknown(format!(
        "local path identity continuity marker outcome is unknown: {detail}"
    ))
}
