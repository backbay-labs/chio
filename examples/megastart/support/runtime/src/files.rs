//! File operations inside an application-owned directory.
//!
//! Ancestor directories must be trusted and must not be replaced by another
//! principal. On Unix the final input component is opened with O_NOFOLLOW.
//! Publication is atomic within one filesystem. On Unix we synchronize both
//! the file and directory. An error after publication requires reconciliation:
//! the destination may already exist. No rollback is implied.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

pub fn private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Read at most `limit + 1` bytes from the opened handle, including if a writer
/// grows the file after open. Size metadata is never the enforcement boundary.
pub fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_read(path)?;
    let mut bytes = Vec::with_capacity(limit.min(8192));
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds the input limit",
        ));
    }
    Ok(bytes)
}

pub fn read_text(path: &Path, limit: usize) -> io::Result<String> {
    String::from_utf8(read_bounded(path, limit)?)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Publish a new immutable artifact. A competing publisher cannot overwrite it.
pub fn create(path: &Path, bytes: &[u8]) -> io::Result<()> {
    publish(path, bytes, false)
}

/// Replace an application-owned snapshot atomically.
pub fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    publish(path, bytes, true)
}

pub fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path; // Atomic visibility only; no directory durability claim here.
    Ok(())
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!(
                    "Temporary file cleanup failed for {}: {error}",
                    self.0.display()
                );
            }
        }
    }
}

fn publish(path: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = Temporary(parent.join(format!(".chio-write-{}", uuid::Uuid::new_v4())));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary.0)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if replace {
        fs::rename(&temporary.0, path)?;
    } else {
        // link is an atomic, no-clobber publication of the complete file.
        fs::hard_link(&temporary.0, path)?;
        fs::remove_file(&temporary.0)?;
    }
    sync_directory(parent)
}

/// Open a regular input file without following its final symlink on Unix.
pub fn open_read(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a regular file",
        ));
    }
    Ok(file)
}

/// A private staged directory, removed on ordinary error paths. A hard crash
/// may leave staging behind, but readers only recognize the published name.
pub struct StagedDirectory(PathBuf);
impl StagedDirectory {
    pub fn new(parent: &Path) -> io::Result<Self> {
        let path = parent.join(format!(".chio-stage-{}", uuid::Uuid::new_v4()));
        private_directory(&path)?;
        Ok(Self(path))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn publish(self, destination: &Path) -> io::Result<()> {
        sync_directory(&self.0)?;
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &self.0,
            rustix::fs::CWD,
            destination,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "directory publication requires atomic no-replace rename on this platform",
        ));
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
        sync_directory(destination.parent().unwrap_or(Path::new(".")))
    }
}
impl Drop for StagedDirectory {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            if error.kind() != io::ErrorKind::NotFound {
                eprintln!("Staging cleanup failed: {error}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("chio-files-{}", uuid::Uuid::new_v4()));
            private_directory(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn publication_is_complete_and_create_never_overwrites() {
        let root = Directory::new();
        let path = root.0.join("artifact");
        create(&path, b"original").unwrap();
        assert_eq!(
            create(&path, b"replacement").unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(read_bounded(&path, 8).unwrap(), b"original");
        replace(&path, b"next").unwrap();
        assert_eq!(read_bounded(&path, 4).unwrap(), b"next");
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }
    #[test]
    fn input_limit_applies_to_actual_bytes() {
        let root = Directory::new();
        let path = root.0.join("input");
        create(&path, b"12345").unwrap();
        assert!(read_bounded(&path, 4).is_err());
        assert_eq!(read_bounded(&path, 5).unwrap().len(), 5);
        assert!(read_bounded(&root.0, 10).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn final_symlink_is_refused() {
        let root = Directory::new();
        create(&root.0.join("target"), b"secret").unwrap();
        std::os::unix::fs::symlink("target", root.0.join("link")).unwrap();
        assert!(read_bounded(&root.0.join("link"), 100).is_err());
    }
    #[test]
    fn concurrent_publishers_have_one_winner() {
        let root = Directory::new();
        let path = root.0.join("publication");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let path = path.clone();
                std::thread::spawn(move || create(&path, &[i; 1024]))
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .filter_map(|t| t.join().unwrap().ok())
                .count(),
            1
        );
        let bytes = read_bounded(&path, 1024).unwrap();
        assert!(bytes.iter().all(|byte| *byte == bytes[0]));
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    #[test]
    fn directory_publication_conflict_preserves_the_winner() {
        let root = Directory::new();
        let target = root.0.join("release");
        let first = StagedDirectory::new(&root.0).unwrap();
        create(&first.path().join("manifest.json"), b"first").unwrap();
        first.publish(&target).unwrap();
        let second = StagedDirectory::new(&root.0).unwrap();
        create(&second.path().join("manifest.json"), b"second").unwrap();
        assert_eq!(
            second.publish(&target).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(
            read_bounded(&target.join("manifest.json"), 5).unwrap(),
            b"first"
        );
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
    }
    #[test]
    fn abandoning_a_stage_leaves_no_public_release() {
        let root = Directory::new();
        let stage = StagedDirectory::new(&root.0).unwrap();
        create(&stage.path().join("partial"), b"incomplete").unwrap();
        drop(stage);
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
    }
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
    #[test]
    fn process_exit_before_publication_leaves_only_unpublished_staging() {
        const CHILD_DIRECTORY: &str = "CHIO_STAGE_EXIT_TEST_DIRECTORY";
        if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
            let stage = StagedDirectory::new(Path::new(&directory)).unwrap();
            create(&stage.path().join("partial"), b"unpublished input").unwrap();
            // Exit bypasses Drop, modeling abrupt process loss before rename.
            // This is not a storage-device power-loss test.
            std::process::exit(73);
        }
        let root = Directory::new();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "files::tests::process_exit_before_publication_leaves_only_unpublished_staging",
            ])
            .env(CHILD_DIRECTORY, &root.0)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(73));
        assert!(!root.0.join("release").exists());
        assert_eq!(fs::read_dir(&root.0).unwrap().count(), 1);
        let resumed = StagedDirectory::new(&root.0).unwrap();
        create(&resumed.path().join("manifest"), b"complete").unwrap();
        resumed.publish(&root.0.join("release")).unwrap();
        assert_eq!(
            read_bounded(&root.0.join("release/manifest"), 8).unwrap(),
            b"complete"
        );
    }
}
