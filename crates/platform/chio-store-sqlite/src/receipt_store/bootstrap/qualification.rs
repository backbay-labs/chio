use super::super::*;

use std::path::{Path, PathBuf};

use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;

/// Exact database identity retained by a qualified finding-pool receipt store.
#[derive(Debug)]
pub(crate) struct ReceiptSinkQualification {
    filesystem_path: PathBuf,
    canonical_path: PathBuf,
    internal_sink_id: String,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl ReceiptSinkQualification {
    pub(in crate::receipt_store) fn capture(
        filesystem_path: &Path,
        internal_sink_id: &str,
    ) -> Result<Self, ReceiptStoreError> {
        let canonical_path = fs::canonicalize(filesystem_path).map_err(|error| {
            ReceiptStoreError::Io(std::io::Error::new(
                error.kind(),
                format!(
                    "receipt database filesystem identity is unavailable for {}: {error}",
                    filesystem_path.display()
                ),
            ))
        })?;
        let path_metadata = fs::symlink_metadata(filesystem_path)?;
        let metadata = fs::metadata(&canonical_path)?;
        validate_receipt_sink_metadata(&canonical_path, &path_metadata, &metadata)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            Ok(Self {
                filesystem_path: filesystem_path.to_path_buf(),
                canonical_path,
                internal_sink_id: internal_sink_id.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let _ = (canonical_path, internal_sink_id);
            Err(ReceiptStoreError::Conflict(
                "finding-pool receipt sinks require Unix file identity".to_owned(),
            ))
        }
    }

    pub(in crate::receipt_store) fn durable_file_binding(&self) -> String {
        let mut material = Vec::new();
        append_binding_part(&mut material, b"chio.receipt-store.durable-sink-binding.v1");
        append_binding_part(&mut material, self.internal_sink_id.as_bytes());
        append_binding_part(
            &mut material,
            self.canonical_path.as_os_str().as_encoded_bytes(),
        );
        #[cfg(unix)]
        {
            append_binding_part(&mut material, &self.device.to_be_bytes());
            append_binding_part(&mut material, &self.inode.to_be_bytes());
        }
        sha256_hex(&material)
    }

    pub(in crate::receipt_store) fn validate_filesystem_identity(
        &self,
    ) -> Result<(), ReceiptStoreError> {
        let canonical_path = fs::canonicalize(&self.filesystem_path).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "qualified receipt database filesystem identity is unavailable: {error}"
            ))
        })?;
        let path_metadata = fs::symlink_metadata(&self.filesystem_path)?;
        let metadata = fs::metadata(&canonical_path)?;
        validate_receipt_sink_metadata(&canonical_path, &path_metadata, &metadata)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            if canonical_path != self.canonical_path
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
            {
                return Err(ReceiptStoreError::Conflict(
                    "qualified receipt database filesystem identity changed".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub(in crate::receipt_store) fn validate_connection(
        &self,
        connection: &Connection,
    ) -> Result<(), ReceiptStoreError> {
        self.validate_filesystem_identity()?;
        let internal_sink_id = connection
            .query_row(
                "SELECT sink_id FROM chio_receipt_sink_identity WHERE singleton = 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "qualified receipt database has no internal sink identity: {error}"
                ))
            })?;
        if internal_sink_id != self.internal_sink_id {
            return Err(ReceiptStoreError::Conflict(
                "qualified receipt database internal sink identity changed".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(in crate::receipt_store) struct ReceiptWriterQualification<'a> {
    pub(in crate::receipt_store) incremental_verification: bool,
    pub(in crate::receipt_store) rollback_anchor:
        Option<&'a crate::rollback_generation::RollbackGenerationAnchor>,
    pub(in crate::receipt_store) sink_qualification: Option<&'a ReceiptSinkQualification>,
}

pub(crate) fn receipt_pool_connection(
    pool: &Pool<SqliteConnectionManager>,
    qualification: Option<&ReceiptSinkQualification>,
) -> Result<PooledConnection<SqliteConnectionManager>, ReceiptStoreError> {
    let connection = pool
        .get()
        .map_err(|error| ReceiptStoreError::Pool(error.to_string()))?;
    if let Some(qualification) = qualification {
        qualification.validate_connection(&connection)?;
    }
    Ok(connection)
}

fn append_binding_part(material: &mut Vec<u8>, part: &[u8]) {
    material.extend_from_slice(&(part.len() as u64).to_be_bytes());
    material.extend_from_slice(part);
}

pub(in crate::receipt_store) fn receipt_actor_unavailable_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit actor is unavailable".to_string())
}

pub(in crate::receipt_store) fn receipt_actor_saturated_error() -> ReceiptStoreError {
    ReceiptStoreError::Pool("sqlite receipt commit queue saturated".to_string())
}

#[cfg(unix)]
fn validate_receipt_sink_metadata(
    canonical_path: &Path,
    path_metadata: &fs::Metadata,
    metadata: &fs::Metadata,
) -> Result<(), ReceiptStoreError> {
    use std::os::unix::fs::MetadataExt as _;

    if !path_metadata.file_type().is_file()
        || !metadata.file_type().is_file()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(ReceiptStoreError::Conflict(
            "finding-pool receipt sink has unsafe ownership or permissions".to_owned(),
        ));
    }
    let parent = canonical_path.parent().ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "finding-pool receipt sink has no durable parent directory".to_owned(),
        )
    })?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != nix::unistd::geteuid().as_raw()
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(ReceiptStoreError::Conflict(
            "finding-pool receipt sink parent has unsafe ownership or permissions".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_receipt_sink_metadata(
    _canonical_path: &Path,
    _path_metadata: &fs::Metadata,
    _metadata: &fs::Metadata,
) -> Result<(), ReceiptStoreError> {
    Err(ReceiptStoreError::Conflict(
        "finding-pool receipt sinks require Unix file identity".to_owned(),
    ))
}
