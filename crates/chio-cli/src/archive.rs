use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::CliError;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SafeArchiveLimits {
    pub max_compressed_bytes: u64,
    pub max_member_bytes: u64,
    pub max_total_bytes: u64,
    pub max_member_count: usize,
    pub max_decompression_ratio: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafeArchiveEntry {
    pub path: String,
    pub bytes: Vec<u8>,
    pub mode: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SafeArchiveWriteEntry<'a> {
    pub path: &'a str,
    pub bytes: &'a [u8],
}

pub(crate) fn read_tar_gz_file(
    archive_path: &Path,
    label: &str,
    limits: SafeArchiveLimits,
) -> Result<Vec<SafeArchiveEntry>, CliError> {
    let compressed_len = fs::metadata(archive_path)
        .map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to inspect {label} {}: {error}",
                archive_path.display()
            ))
        })?
        .len();
    if compressed_len > limits.max_compressed_bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} {} exceeds compressed byte limit",
            archive_path.display()
        )));
    }

    let file = fs::File::open(archive_path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to open {label} {}: {error}",
            archive_path.display()
        ))
    })?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    let mut entries_out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut seen_casefold = BTreeSet::new();
    let mut total_bytes = 0_u64;
    let entries = archive.entries().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read {label} {}: {error}",
            archive_path.display()
        ))
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read {label} entry {}: {error}",
                archive_path.display()
            ))
        })?;
        let entry_path = entry.path().map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read {label} entry path {}: {error}",
                archive_path.display()
            ))
        })?;
        let entry_path = entry_path.to_str().ok_or_else(|| {
            CliError::cli_other_error(format!("{label} member path is not UTF-8"))
        })?;
        if entry.header().entry_type().is_dir() {
            let directory_path = entry_path.trim_end_matches('/');
            let _ = safe_archive_member_path(directory_path, label)?;
            continue;
        }
        let path = safe_archive_member_path(entry_path, label)?;
        if !entry.header().entry_type().is_file() {
            return Err(CliError::cli_other_error(format!(
                "{label} contains a non-regular member"
            )));
        }
        if !seen.insert(path.clone()) {
            return Err(CliError::cli_other_error(format!(
                "{label} duplicate member {path}"
            )));
        }
        if !seen_casefold.insert(path.to_ascii_lowercase()) {
            return Err(CliError::cli_other_error(format!(
                "{label} member has a casefold collision"
            )));
        }
        let size = entry.size();
        if size > limits.max_member_bytes {
            return Err(CliError::cli_other_error(format!(
                "{label} member {path} exceeds byte limit"
            )));
        }
        total_bytes = total_bytes.checked_add(size).ok_or_else(|| {
            CliError::cli_other_error(format!("{label} byte count overflow"))
        })?;
        if total_bytes > limits.max_total_bytes {
            return Err(CliError::cli_other_error(format!(
                "{label} exceeds decompressed byte limit"
            )));
        }
        if entries_out.len() >= limits.max_member_count {
            return Err(CliError::cli_other_error(format!(
                "{label} has too many members"
            )));
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).map_err(|error| {
            CliError::cli_io_error(format!("failed to read {label} member {path}: {error}"))
        })?;
        let actual_size = u64::try_from(bytes.len()).map_err(|_| {
            CliError::cli_other_error(format!("{label} member size overflow"))
        })?;
        if actual_size != size {
            return Err(CliError::cli_other_error(format!(
                "{label} member {path} size changed while reading"
            )));
        }
        let mode = entry
            .header()
            .mode()
            .map(safe_archive_file_mode)
            .unwrap_or(0o600);
        entries_out.push(SafeArchiveEntry { path, bytes, mode });
    }

    enforce_decompression_ratio(total_bytes, compressed_len, limits.max_decompression_ratio, label)?;
    Ok(entries_out)
}

pub(crate) fn write_tar_gz_file(
    out: &Path,
    label: &str,
    entries: &[SafeArchiveWriteEntry<'_>],
    limits: SafeArchiveLimits,
) -> Result<(), CliError> {
    if out.exists() {
        return Err(CliError::cli_other_error(format!(
            "{label} output {} already exists",
            out.display()
        )));
    }
    if entries.is_empty() {
        return Err(CliError::cli_other_error(format!("{label} has no members")));
    }
    if entries.len() > limits.max_member_count {
        return Err(CliError::cli_other_error(format!(
            "{label} has too many members"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut seen_casefold = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in entries {
        let path = safe_archive_member_path(entry.path, label)?;
        if !seen.insert(path.clone()) {
            return Err(CliError::cli_other_error(format!(
                "{label} duplicate member {path}"
            )));
        }
        if !seen_casefold.insert(path.to_ascii_lowercase()) {
            return Err(CliError::cli_other_error(format!(
                "{label} member has a casefold collision"
            )));
        }
        let len = u64::try_from(entry.bytes.len()).map_err(|_| {
            CliError::cli_other_error(format!("{label} member size overflow"))
        })?;
        if len > limits.max_member_bytes {
            return Err(CliError::cli_other_error(format!(
                "{label} member {path} exceeds byte limit"
            )));
        }
        total_bytes = total_bytes.checked_add(len).ok_or_else(|| {
            CliError::cli_other_error(format!("{label} byte count overflow"))
        })?;
        if total_bytes > limits.max_total_bytes {
            return Err(CliError::cli_other_error(format!(
                "{label} exceeds decompressed byte limit"
            )));
        }
    }
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| {
                CliError::cli_io_error(format!(
                    "failed to create {label} parent {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|error| {
            CliError::cli_io_error(format!("failed to create {label} {}: {error}", out.display()))
        })?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    for entry in entries {
        append_regular_file(&mut builder, entry.path, entry.bytes, label)?;
    }
    builder.finish().map_err(|error| {
        CliError::cli_io_error(format!("failed to finish {label} {}: {error}", out.display()))
    })?;
    let encoder = builder.into_inner().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to finish {label} encoder {}: {error}",
            out.display()
        ))
    })?;
    encoder.finish().map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to finish {label} gzip {}: {error}",
            out.display()
        ))
    })?;
    Ok(())
}

pub(crate) fn write_entries_to_fresh_dir(
    out_dir: &Path,
    label: &str,
    entries: &[SafeArchiveEntry],
) -> Result<u64, CliError> {
    if out_dir.exists() {
        return Err(CliError::cli_other_error(format!(
            "{label} output {} must not exist",
            out_dir.display()
        )));
    }
    let parent = out_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create {label} parent {}: {error}",
            parent.display()
        ))
    })?;
    let staging = parent.join(staging_dir_name(label));
    fs::create_dir(&staging).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create {label} staging {}: {error}",
            staging.display()
        ))
    })?;
    let result = write_entries_to_existing_dir(&staging, label, entries);
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    fs::rename(&staging, out_dir).map_err(|error| {
        let _ = fs::remove_dir_all(&staging);
        CliError::cli_io_error(format!(
            "failed to promote {label} staging {} to {}: {error}",
            staging.display(),
            out_dir.display()
        ))
    })?;
    u64::try_from(entries.len())
        .map_err(|_| CliError::cli_other_error(format!("{label} member count overflow")))
}

pub(crate) fn write_entries_to_existing_dir(
    root: &Path,
    label: &str,
    entries: &[SafeArchiveEntry],
) -> Result<(), CliError> {
    fs::create_dir_all(root).map_err(|error| {
        CliError::cli_io_error(format!("failed to create {label} root {}: {error}", root.display()))
    })?;
    for entry in entries {
        write_entry(root, label, entry, false)?;
    }
    Ok(())
}

pub(crate) fn replace_entries_in_existing_dir(
    root: &Path,
    label: &str,
    entries: &[SafeArchiveEntry],
) -> Result<(), CliError> {
    fs::create_dir_all(root).map_err(|error| {
        CliError::cli_io_error(format!("failed to create {label} root {}: {error}", root.display()))
    })?;
    for entry in entries {
        write_entry(root, label, entry, true)?;
    }
    Ok(())
}

pub(crate) fn safe_archive_member_path(relative: &str, label: &str) -> Result<String, CliError> {
    if relative.trim() != relative
        || relative.is_empty()
        || relative.contains('\\')
        || relative.contains(':')
        || relative.contains("//")
        || !relative.is_ascii()
        || relative.chars().any(char::is_whitespace)
        || relative.chars().any(char::is_control)
        || Path::new(relative).is_absolute()
    {
        return Err(CliError::cli_other_error(format!(
            "{label} member path {relative} is not portable"
        )));
    }
    for segment in relative.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CliError::cli_other_error(format!(
                "{label} member path {relative} is unsafe"
            )));
        }
    }
    Ok(relative.to_string())
}

pub(crate) fn safe_single_component(value: &str, label: &str) -> Result<String, CliError> {
    let component = safe_archive_member_path(value, label)?;
    if component.contains('/') {
        return Err(CliError::cli_other_error(format!(
            "{label} must be one safe path component"
        )));
    }
    Ok(component)
}

fn append_regular_file<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
    label: &str,
) -> Result<(), CliError> {
    let safe_path = safe_archive_member_path(path, label)?;
    let size = u64::try_from(bytes.len())
        .map_err(|_| CliError::cli_other_error(format!("{label} member size overflow")))?;
    let mut header = tar::Header::new_ustar();
    header.set_size(size);
    header.set_mode(0o600);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    builder
        .append_data(&mut header, safe_path, std::io::Cursor::new(bytes))
        .map_err(|error| CliError::cli_io_error(format!("failed to append {label} member: {error}")))
}

fn write_entry(
    root: &Path,
    label: &str,
    entry: &SafeArchiveEntry,
    overwrite: bool,
) -> Result<(), CliError> {
    let relative = safe_archive_member_path(&entry.path, label)?;
    let path = safe_join(root, &relative, label)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to create {label} dir {}: {error}",
                parent.display()
            ))
        })?;
    }
    let mut options = fs::OpenOptions::new();
    options.write(true);
    if overwrite {
        options.create(true).truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options.open(&path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create {label} file {}: {error}",
            path.display()
        ))
    })?;
    file.write_all(&entry.bytes).map_err(|error| {
        CliError::cli_io_error(format!("failed to write {label} file {}: {error}", path.display()))
    })?;
    apply_safe_archive_file_mode(&path, entry.mode, label)?;
    let written = fs::read(&path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read back {label} file {}: {error}",
            path.display()
        ))
    })?;
    if written != entry.bytes {
        return Err(CliError::cli_other_error(format!(
            "{label} file {} did not read back",
            path.display()
        )));
    }
    Ok(())
}

fn safe_archive_file_mode(mode: u32) -> u32 {
    if mode & 0o111 == 0 {
        0o600
    } else {
        0o755
    }
}

#[cfg(unix)]
fn apply_safe_archive_file_mode(path: &Path, mode: u32, label: &str) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(safe_archive_file_mode(mode))).map_err(
        |error| {
            CliError::cli_io_error(format!(
                "failed to set {label} file mode {}: {error}",
                path.display()
            ))
        },
    )
}

#[cfg(not(unix))]
fn apply_safe_archive_file_mode(_path: &Path, _mode: u32, _label: &str) -> Result<(), CliError> {
    Ok(())
}

fn safe_join(root: &Path, relative: &str, label: &str) -> Result<PathBuf, CliError> {
    let relative = safe_archive_member_path(relative, label)?;
    let mut path = root.to_path_buf();
    for segment in relative.split('/') {
        path.push(segment);
    }
    Ok(path)
}

fn enforce_decompression_ratio(
    total_bytes: u64,
    compressed_len: u64,
    ratio: u64,
    label: &str,
) -> Result<(), CliError> {
    if total_bytes == 0 {
        return Ok(());
    }
    let allowed = compressed_len.checked_mul(ratio).ok_or_else(|| {
        CliError::cli_other_error(format!("{label} decompression ratio overflow"))
    })?;
    if compressed_len == 0 || total_bytes > allowed {
        return Err(CliError::cli_other_error(format!(
            "{label} decompression ratio exceeds limit"
        )));
    }
    Ok(())
}

fn staging_dir_name(label: &str) -> String {
    let safe_label: String = label
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '-')
        .take(24)
        .collect();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    format!(".chio-{safe_label}-{}-{nanos}", std::process::id())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const TEST_LIMITS: SafeArchiveLimits = SafeArchiveLimits {
        max_compressed_bytes: 1024 * 1024,
        max_member_bytes: 1024 * 1024,
        max_total_bytes: 1024 * 1024,
        max_member_count: 8,
        max_decompression_ratio: 1000,
    };

    #[test]
    fn safe_archive_helper_rejects_traversal_path() {
        let err = safe_archive_member_path("../escape", "test archive").unwrap_err();
        assert!(err.to_string().contains("unsafe"));
    }

    #[test]
    fn safe_archive_helper_rejects_backslash_and_colon() {
        assert!(safe_archive_member_path("a\\b", "test archive").is_err());
        assert!(safe_archive_member_path("C:evil", "test archive").is_err());
    }

    #[test]
    fn safe_archive_helper_roundtrips_regular_files() {
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("bundle.tar.gz");
        let entries = [
            SafeArchiveWriteEntry {
                path: "one.txt",
                bytes: b"one",
            },
            SafeArchiveWriteEntry {
                path: "nested/two.txt",
                bytes: b"two",
            },
        ];
        write_tar_gz_file(&archive, "test archive", &entries, TEST_LIMITS).unwrap();
        let read = read_tar_gz_file(&archive, "test archive", TEST_LIMITS).unwrap();
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].path, "one.txt");
        assert_eq!(read[1].path, "nested/two.txt");
    }
}
