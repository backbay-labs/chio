use super::*;
use std::path::{Path, PathBuf};

pub(super) fn extract_proof_archive(path: &Path) -> Result<Option<ExtractedProofBundle>, CliError> {
    if is_zstd_tar_path(path) {
        Ok(Some(unpack_zstd_tar_bundle(path)?))
    } else if is_gzip_tar_path(path) {
        Ok(Some(unpack_gzip_tar_bundle(path)?))
    } else {
        Ok(None)
    }
}

pub(super) fn is_gzip_tar_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".tgz") || name.ends_with(".tar.gz"))
}

pub(super) fn is_zstd_tar_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".tar.zst"))
}

pub(super) struct ExtractedProofBundle {
    path: PathBuf,
}

impl ExtractedProofBundle {
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ExtractedProofBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn unpack_gzip_tar_bundle(path: &Path) -> Result<ExtractedProofBundle, CliError> {
    let tempdir = create_proof_tempdir()?;
    let entries =
        crate::archive::read_tar_gz_file(path, "proof archive", export::proof_archive_limits())?;
    crate::archive::write_entries_to_existing_dir(tempdir.path(), "proof archive", &entries)?;
    Ok(tempdir)
}

fn unpack_zstd_tar_bundle(path: &Path) -> Result<ExtractedProofBundle, CliError> {
    let tempdir = create_proof_tempdir()?;
    let entries =
        crate::archive::read_tar_zstd_file(path, "proof archive", export::proof_archive_limits())?;
    crate::archive::write_entries_to_existing_dir(tempdir.path(), "proof archive", &entries)?;
    Ok(tempdir)
}

fn create_proof_tempdir() -> Result<ExtractedProofBundle, CliError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| CliError::cli_io_error(format!("proof tempdir clock error: {error}")))?;
    let base = std::env::temp_dir();
    for attempt in 0..16 {
        let path = base.join(format!(
            "chio-proof-bundle-{}-{}-{attempt}",
            std::process::id(),
            now.as_nanos()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(ExtractedProofBundle { path }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(CliError::from(error)),
        }
    }
    Err(CliError::cli_io_error(
        "could not create proof archive extraction directory".to_string(),
    ))
}
