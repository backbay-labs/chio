use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use chio_core::crypto::{Keypair, PublicKey};
use chio_kernel::admission_operation::{DurableAdmissionMode, StoreMutationFence};
use chio_kernel::tool_outcome::QualifiedToolOutcomeStore;
use chio_kernel::{BudgetStore, ChioKernel, QualifiedAdmissionProjectionStore, RevocationStore};
use chio_store_sqlite::{SqliteAuthorityStore, SqliteBudgetStore, SqliteRevocationStore};

use crate::{load_or_create_authority_keypair, CliError};

#[cfg(windows)]
#[path = "durable_admission/windows.rs"]
mod windows;

#[derive(Clone)]
pub struct DurableAdmissionRuntime {
    operations: Arc<dyn QualifiedAdmissionProjectionStore>,
    outcomes: Arc<dyn QualifiedToolOutcomeStore>,
    budget: Arc<dyn BudgetStore>,
    revocations: Arc<dyn RevocationStore>,
    local_budget: Option<SqliteBudgetStore>,
    local_revocations: Option<SqliteRevocationStore>,
    fence: StoreMutationFence,
    kernel_keypair: Keypair,
}

impl DurableAdmissionRuntime {
    pub fn open(path: &Path) -> Result<Self, CliError> {
        if path
            .to_str()
            .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
        {
            return Err(CliError::cli_other_error(
                "refusing to attach an in-memory database as durable admission state".to_string(),
            ));
        }

        SqliteAuthorityStore::ensure_serving_supported()?;
        let lock_root = durable_admission_lock_root(path)?;
        create_private_directory(&lock_root)?;
        SqliteAuthorityStore::provision(path, &lock_root)?;
        let authority = SqliteAuthorityStore::open_serving(path, &lock_root)?;
        let budget = authority.budget_store();
        let revocations = authority.revocation_store();
        let kernel_keypair =
            load_or_create_authority_keypair(&durable_admission_kernel_seed_path(path)?)?;
        bind_durable_admission_kernel_identity(path, &kernel_keypair.public_key())?;

        Ok(Self {
            operations: Arc::new(authority.admission_operation_store()),
            outcomes: Arc::new(authority.tool_outcome_store()),
            budget: Arc::new(budget.clone()),
            revocations: Arc::new(revocations.clone()),
            local_budget: Some(budget),
            local_revocations: Some(revocations),
            fence: authority.mutation_fence(),
            kernel_keypair,
        })
    }

    pub fn open_remote(
        identity_path: &Path,
        control_url: &str,
        control_token: &str,
    ) -> Result<Self, CliError> {
        if identity_path
            .to_str()
            .is_some_and(chio_store_sqlite::is_in_memory_sqlite_path)
        {
            return Err(CliError::cli_other_error(
                "refusing to persist durable admission identity beside an in-memory database"
                    .to_owned(),
            ));
        }
        let kernel_keypair =
            load_or_create_authority_keypair(&durable_admission_kernel_seed_path(identity_path)?)?;
        bind_durable_admission_kernel_identity(identity_path, &kernel_keypair.public_key())?;
        let stores =
            crate::trust_control::service_runtime::remote_admission::build_remote_admission_stores(
                control_url,
                control_token,
                kernel_keypair.clone(),
            )?;
        let revocations = Arc::from(
            crate::trust_control::service_runtime::remote_stores::build_remote_revocation_store(
                control_url,
                control_token,
            )?,
        );
        Ok(Self {
            operations: stores.operations,
            outcomes: stores.outcomes,
            budget: stores.budget,
            revocations,
            local_budget: None,
            local_revocations: None,
            fence: stores.fence,
            kernel_keypair,
        })
    }

    #[must_use]
    pub fn kernel_keypair(&self) -> Keypair {
        self.kernel_keypair.clone()
    }

    #[must_use]
    pub fn local_budget_store(&self) -> Option<SqliteBudgetStore> {
        self.local_budget.clone()
    }

    #[must_use]
    pub fn local_revocation_store(&self) -> Option<SqliteRevocationStore> {
        self.local_revocations.clone()
    }

    pub fn attach(&self, kernel: &mut ChioKernel) -> Result<(), CliError> {
        if kernel.public_key() != self.kernel_keypair.public_key() {
            return Err(CliError::cli_other_error(
                "kernel signing key does not match the durable admission authority".to_string(),
            ));
        }
        kernel.set_durable_admission_store(
            self.operations.clone(),
            self.outcomes.clone(),
            self.fence.clone(),
        )?;
        kernel.set_budget_store_handle(self.budget.clone());
        kernel.set_revocation_store_handle(self.revocations.clone());
        kernel.reconcile_durable_admission_startup()?;
        Ok(())
    }
}

pub fn validate_durable_admission_participant_paths(
    mode: DurableAdmissionMode,
    control_url: Option<&str>,
    revocation_database: Option<&Path>,
    budget_database: Option<&Path>,
) -> Result<(), CliError> {
    if mode == DurableAdmissionMode::Off
        || revocation_database.is_none() && budget_database.is_none()
    {
        return Ok(());
    }
    if control_url.is_some() {
        return Err(CliError::cli_other_error(
            "--control-url cannot be combined with --revocation-db or --budget-db when durable admission is enabled"
                .to_owned(),
        ));
    }
    Err(CliError::cli_other_error(
        "the durable admission authority owns revocation and budget state; remove --revocation-db and --budget-db so all admission participants share one fenced transaction coordinator"
            .to_owned(),
    ))
}

pub fn open_durable_admission_runtime(
    mode: DurableAdmissionMode,
    database_path: Option<&Path>,
) -> Result<Option<DurableAdmissionRuntime>, CliError> {
    if mode == DurableAdmissionMode::Off {
        return Ok(None);
    }
    let path = database_path.ok_or_else(|| {
        CliError::cli_other_error(
            "durable admission mode requires a database so operations and tool outcomes survive restart"
                .to_string(),
        )
    })?;
    DurableAdmissionRuntime::open(path).map(Some)
}

pub fn durable_admission_sidecar_path(session_database: &Path) -> Result<PathBuf, CliError> {
    sibling_path(session_database, ".admission", "session database")
}

pub fn validate_distinct_database_paths(paths: &[(&str, &Path)]) -> Result<(), CliError> {
    for (index, (left_label, left_path)) in paths.iter().enumerate() {
        for (right_label, right_path) in &paths[index + 1..] {
            if database_paths_alias(left_path, right_path)? {
                return Err(CliError::cli_other_error(format!(
                    "{left_label} must not alias {right_label}"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn durable_admission_lock_root(path: &Path) -> Result<PathBuf, CliError> {
    sibling_path(path, ".locks", "durable admission database")
}

pub(crate) fn create_private_directory(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let absolute = absolute_private_directory_path_unix(path)?;
        prepare_private_directory_unix(&absolute, ExistingPrivateDirectory::Harden)?;
    }
    #[cfg(windows)]
    {
        let absolute = normalize_private_directory_path(path)?;
        windows::prepare_private_directory(&absolute)?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure private-directory creation is unavailable on this platform",
        ));
    }
    Ok(())
}

/// A private directory pinned by a platform directory handle.
///
/// Relative operations remain anchored to the validated directory even if its
/// pathname is renamed or replaced after preparation.
pub struct PreparedPrivateDirectory {
    path: PathBuf,
    #[cfg(unix)]
    directory: File,
    #[cfg(windows)]
    directory: windows::PreparedPrivateDirectory,
}

impl PreparedPrivateDirectory {
    /// Returns the resolved absolute path used to prepare this directory.
    /// Security-sensitive operations use the retained handle, not this
    /// pathname.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reports whether the pinned directory contains no entries.
    pub fn is_empty(&self) -> Result<bool, std::io::Error> {
        #[cfg(unix)]
        {
            private_directory_is_empty_unix(&self.directory)
        }
        #[cfg(windows)]
        {
            self.directory.is_empty()
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure private-directory inspection is unavailable on this platform",
            ))
        }
    }

    /// Creates every missing directory in a relative path without following
    /// symlinks or Windows reparse points.
    pub fn create_dir_all(&self, relative: &Path) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            create_private_directories_unix(&self.directory, relative)
        }
        #[cfg(windows)]
        {
            self.directory.create_dir_all(relative)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = relative;
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure relative-directory creation is unavailable on this platform",
            ))
        }
    }

    /// Creates and durably writes a new relative file without overwriting an
    /// existing entry.
    pub fn write_new(&self, relative: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
        #[cfg(unix)]
        {
            write_new_private_file_unix(&self.directory, relative, contents)
        }
        #[cfg(windows)]
        {
            self.directory.write_new(relative, contents)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (relative, contents);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "secure relative-file creation is unavailable on this platform",
            ))
        }
    }
}

/// Creates a missing private directory or validates an existing one without
/// changing its permissions.
///
/// On Unix, the path is traversed relative to open directory descriptors so
/// symlinks cannot redirect validation or creation. A missing target is created
/// with mode `0700`. An existing target must be owned by the effective user and
/// must not be group or world writable.
pub fn ensure_private_directory(path: &Path) -> Result<(), std::io::Error> {
    prepare_private_directory(path).map(drop)
}

/// Creates or validates a private directory and retains a secure handle for
/// subsequent relative operations.
pub fn prepare_private_directory(path: &Path) -> Result<PreparedPrivateDirectory, std::io::Error> {
    #[cfg(unix)]
    {
        let absolute = absolute_private_directory_path_unix(path)?;
        let (directory, resolved) =
            prepare_private_directory_unix(&absolute, ExistingPrivateDirectory::Preserve)?;
        Ok(PreparedPrivateDirectory {
            path: resolved,
            directory,
        })
    }
    #[cfg(windows)]
    {
        let absolute = normalize_private_directory_path(path)?;
        let directory = windows::prepare_private_directory(&absolute)?;
        Ok(PreparedPrivateDirectory {
            path: absolute,
            directory,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "secure private-directory creation is unavailable on this platform",
        ))
    }
}

#[cfg(unix)]
fn absolute_private_directory_path_unix(path: &Path) -> Result<PathBuf, std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let mut components = absolute.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unix private directory path must be absolute",
        ));
    }
    let Some(Component::Normal(first)) = components.next() else {
        return Ok(absolute);
    };
    let root_child = Path::new("/").join(first);
    let metadata = match fs::symlink_metadata(&root_child) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(absolute),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_symlink() {
        return Ok(absolute);
    }

    let root_metadata = fs::metadata(Path::new("/"))?;
    if root_metadata.uid() != 0 || root_metadata.mode() & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to resolve a root alias from untrusted root ancestry",
        ));
    }
    let mut resolved = fs::canonicalize(root_child)?;
    for component in components {
        resolved.push(component.as_os_str());
    }
    Ok(resolved)
}

#[cfg(windows)]
fn normalize_private_directory_path(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.is_absolute() {
        if path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private directory path must not contain parent components after a named component",
            ));
        }
        return Ok(path
            .components()
            .filter(|component| !matches!(component, Component::CurDir))
            .collect());
    }

    let mut normalized = std::env::current_dir()?;
    let mut reached_named_component = false;
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir if !reached_named_component => {
                normalized.pop();
            }
            Component::ParentDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "private directory path must not contain parent components after a named component",
                ));
            }
            Component::Normal(name) => {
                normalized.push(name);
                reached_named_component = true;
            }
            Component::Prefix(_) | Component::RootDir => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "relative private directory path must not contain a platform prefix or root",
                ));
            }
        }
    }
    if !reached_named_component {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private directory path must name a directory below the filesystem root",
        ));
    }
    Ok(normalized)
}

#[cfg(unix)]
#[derive(Clone, Copy)]
enum ExistingPrivateDirectory {
    Harden,
    Preserve,
}

/// Access mode for the ancestors of a private directory.
///
/// Walking a directory needs execute permission, not read: an ancestor with
/// mode `0711` is traversable by ordinary path resolution, so the
/// descriptor-relative walk must traverse it too. Platforms with neither a
/// traversal-only mode nor a search-only mode fall back to read access, which
/// refuses such an ancestor rather than admitting an unchecked one.
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
const ANCESTOR_ACCESS_MODE: nix::fcntl::OFlag = nix::fcntl::OFlag::O_PATH;

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    )
))]
const ANCESTOR_ACCESS_MODE: nix::fcntl::OFlag = nix::fcntl::OFlag::O_SEARCH;

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    ))
))]
const ANCESTOR_ACCESS_MODE: nix::fcntl::OFlag = nix::fcntl::OFlag::O_RDONLY;

#[cfg(unix)]
fn prepare_private_directory_unix(
    path: &Path,
    existing_target: ExistingPrivateDirectory,
) -> Result<(File, PathBuf), std::io::Error> {
    use nix::errno::Errno;
    use nix::fcntl::{open, openat};
    use nix::sys::stat::{mkdirat, Mode};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let components = path.components().collect::<Vec<_>>();
    let mut resolved_positions = Vec::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(_) => resolved_positions.push(index),
            Component::ParentDir => {
                if resolved_positions.pop().is_none() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "private directory path must name a directory below the filesystem root",
                    ));
                }
            }
            Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unix private directory path must not contain a platform prefix",
                ));
            }
        }
    }
    let final_position = resolved_positions.last().copied().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private directory path must name a directory below the filesystem root",
        )
    })?;

    let root = File::from(open(
        Path::new("/"),
        private_directory_traversal_flags_unix(),
        Mode::empty(),
    )?);
    let mut directories = vec![(root, false)];
    let mut resolved = PathBuf::from("/");
    let effective_uid = nix::unistd::geteuid().as_raw();

    for (index, component) in components.into_iter().enumerate() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Prefix(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unix private directory path must not contain a platform prefix",
                ));
            }
            Component::ParentDir => {
                if directories.len() == 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "private directory path must name a directory below the filesystem root",
                    ));
                }
                directories.pop();
                resolved.pop();
            }
            Component::Normal(name) => {
                let (parent, _) = directories.last().ok_or_else(|| {
                    std::io::Error::other("private directory descriptor stack is empty")
                })?;
                let parent_metadata = parent.metadata()?;
                let flags = if index == final_position {
                    private_directory_read_flags_unix()
                } else {
                    private_directory_traversal_flags_unix()
                };
                let (child, created) = match openat(parent, name, flags, Mode::empty()) {
                    Ok(file) => (File::from(file), false),
                    Err(Errno::ENOENT) => {
                        validate_private_directory_parent(&parent_metadata, None, effective_uid)?;
                        let created = match mkdirat(parent, name, Mode::from_bits_truncate(0o700)) {
                            Ok(()) => true,
                            Err(Errno::EEXIST) => false,
                            Err(error) => return Err(error.into()),
                        };
                        let child = File::from(
                            openat(parent, name, flags, Mode::empty()).map_err(|error| {
                                let io_error: std::io::Error = error.into();
                                std::io::Error::new(
                                    io_error.kind(),
                                    format!(
                                        "failed to reopen private directory component {}: {io_error}",
                                        resolved.join(name).display(),
                                    ),
                                )
                            })?,
                        );
                        if created {
                            set_private_directory_permissions_unix(parent, name).map_err(
                                |error| {
                                    std::io::Error::new(
                                        error.kind(),
                                        format!(
                                        "failed to secure private directory component {}: {error}",
                                        resolved.join(name).display()
                                    ),
                                    )
                                },
                            )?;
                        }
                        (child, created)
                    }
                    Err(error) => {
                        let io_error: std::io::Error = error.into();
                        return Err(std::io::Error::new(
                            io_error.kind(),
                            format!(
                                "failed to open private directory component {}: {io_error}",
                                resolved.join(name).display(),
                            ),
                        ));
                    }
                };
                let child_metadata = child.metadata()?;
                validate_private_directory_parent(
                    &parent_metadata,
                    Some(child_metadata.uid()),
                    effective_uid,
                )?;
                directories.push((child, created));
                resolved.push(name);
            }
        }
    }

    if directories.len() == 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private directory path must name a directory below the filesystem root",
        ));
    }
    let (target, created) = directories
        .pop()
        .ok_or_else(|| std::io::Error::other("private directory descriptor stack is empty"))?;
    let target_metadata = target.metadata()?;
    validate_private_directory_owner(target_metadata.uid(), effective_uid)?;
    match existing_target {
        ExistingPrivateDirectory::Harden => {
            target.set_permissions(fs::Permissions::from_mode(0o700))?;
        }
        ExistingPrivateDirectory::Preserve if created => {}
        ExistingPrivateDirectory::Preserve => {
            validate_private_directory_mode(target_metadata.mode())?;
        }
    }
    Ok((target, resolved))
}

#[cfg(unix)]
fn private_directory_traversal_flags_unix() -> nix::fcntl::OFlag {
    use nix::fcntl::OFlag;

    OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | ANCESTOR_ACCESS_MODE
}

#[cfg(unix)]
fn private_directory_read_flags_unix() -> nix::fcntl::OFlag {
    use nix::fcntl::OFlag;

    OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW
}

#[cfg(unix)]
fn set_private_directory_permissions_unix(
    parent: &File,
    component: &std::ffi::OsStr,
) -> Result<(), std::io::Error> {
    use nix::fcntl::openat;
    use nix::sys::stat::Mode;
    use std::os::unix::fs::PermissionsExt;

    let child = File::from(openat(
        parent,
        component,
        private_directory_read_flags_unix(),
        Mode::empty(),
    )?);
    child.set_permissions(fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn private_directory_is_empty_unix(directory: &File) -> Result<bool, std::io::Error> {
    use nix::dir::Dir;
    use nix::sys::stat::Mode;

    let mut entries = Dir::openat(
        directory,
        Path::new("."),
        private_directory_read_flags_unix(),
        Mode::empty(),
    )?;
    for entry in entries.iter() {
        let entry = entry?;
        if !matches!(entry.file_name().to_bytes(), b"." | b"..") {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(unix)]
fn private_relative_components(path: &Path) -> Result<Vec<&std::ffi::OsStr>, std::io::Error> {
    let components = path
        .components()
        .map(|component| match component {
            Component::Normal(name) => Ok(name),
            Component::Prefix(_)
            | Component::RootDir
            | Component::CurDir
            | Component::ParentDir => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private relative path must contain only normal components",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "private relative path must not be empty",
        ));
    }
    Ok(components)
}

#[cfg(unix)]
fn open_private_child_directory_unix(
    parent: &File,
    component: &std::ffi::OsStr,
) -> Result<File, std::io::Error> {
    use nix::fcntl::openat;
    use nix::sys::stat::Mode;
    use std::os::unix::fs::MetadataExt;

    let child = File::from(openat(
        parent,
        component,
        private_directory_traversal_flags_unix(),
        Mode::empty(),
    )?);
    let metadata = child.metadata()?;
    let effective_uid = nix::unistd::geteuid().as_raw();
    validate_private_directory_owner(metadata.uid(), effective_uid)?;
    validate_private_directory_mode(metadata.mode())?;
    Ok(child)
}

#[cfg(unix)]
fn create_private_directories_unix(root: &File, relative: &Path) -> Result<(), std::io::Error> {
    use nix::errno::Errno;
    use nix::sys::stat::{mkdirat, Mode};

    let components = private_relative_components(relative)?;
    let mut directory = root.try_clone()?;
    for component in components {
        let child = match open_private_child_directory_unix(&directory, component) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let created = match mkdirat(&directory, component, Mode::from_bits_truncate(0o755))
                {
                    Ok(()) => true,
                    Err(Errno::EEXIST) => false,
                    Err(error) => return Err(error.into()),
                };
                let child = open_private_child_directory_unix(&directory, component)?;
                if created {
                    sync_private_directory_unix(&directory)?;
                }
                child
            }
            Err(error) => return Err(error),
        };
        directory = child;
    }
    sync_private_directory_unix(&directory)
}

#[cfg(unix)]
fn sync_private_directory_unix(directory: &File) -> Result<(), std::io::Error> {
    File::from(nix::fcntl::openat(
        directory,
        Path::new("."),
        private_directory_read_flags_unix(),
        nix::sys::stat::Mode::empty(),
    )?)
    .sync_all()
}

#[cfg(unix)]
fn write_new_private_file_unix(
    root: &File,
    relative: &Path,
    contents: &[u8],
) -> Result<(), std::io::Error> {
    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;
    use nix::unistd::{unlinkat, UnlinkatFlags};

    let components = private_relative_components(relative)?;
    let (file_name, parents) = components
        .split_last()
        .ok_or_else(|| std::io::Error::other("private relative path must name a file"))?;
    let mut directory = root.try_clone()?;
    for component in parents {
        directory = open_private_child_directory_unix(&directory, component)?;
    }
    let descriptor = openat(
        &directory,
        *file_name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        Mode::from_bits_truncate(0o666),
    )?;
    let mut file = File::from(descriptor);
    let operation = file
        .write_all(contents)
        .and_then(|()| file.sync_all())
        .and_then(|()| sync_private_directory_unix(&directory));
    if let Err(error) = operation {
        drop(file);
        let _ = unlinkat(&directory, *file_name, UnlinkatFlags::NoRemoveDir);
        return Err(error);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory_owner(uid: u32, effective_uid: u32) -> Result<(), std::io::Error> {
    if uid != effective_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory must be owned by the effective user",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory_mode(mode: u32) -> Result<(), std::io::Error> {
    if mode & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory must not be group or world writable",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_directory_parent(
    parent: &fs::Metadata,
    child_uid: Option<u32>,
    effective_uid: u32,
) -> Result<(), std::io::Error> {
    use std::os::unix::fs::MetadataExt;

    let parent_uid = parent.uid();
    let parent_mode = parent.mode();
    if parent_uid != effective_uid && parent_uid != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "private directory ancestry must be owned by the effective user or root",
        ));
    }
    if parent_mode & 0o022 != 0 {
        if parent_mode & 0o1000 == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private directory ancestry must not be group or world writable unless sticky",
            ));
        }
        if child_uid.is_some_and(|uid| uid != effective_uid && uid != 0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "private directory entry in sticky ancestry must be owned by the effective user or root",
            ));
        }
    }
    Ok(())
}

pub(super) fn write_private_file_atomically(path: &Path, contents: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_other_error("private file path must name a file"))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::now_v7()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut staged = options.open(&temporary)?;
    if let Err(error) = staged.write_all(contents).and_then(|()| staged.sync_all()) {
        drop(staged);
        let _ = fs::remove_file(&temporary);
        return Err(CliError::Io(error));
    }
    drop(staged);
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(CliError::Io(error));
    }
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn durable_admission_kernel_seed_path(path: &Path) -> Result<PathBuf, CliError> {
    sibling_path(path, ".kernel.seed", "durable admission database")
}

fn durable_admission_kernel_identity_path(path: &Path) -> Result<PathBuf, CliError> {
    sibling_path(path, ".kernel.pub", "durable admission database")
}

fn sibling_path(path: &Path, suffix: &str, label: &str) -> Result<PathBuf, CliError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::cli_other_error(format!("{label} path must name a file")))?;
    let mut sibling_name = file_name.to_os_string();
    sibling_name.push(suffix);
    Ok(path.with_file_name(sibling_name))
}

fn database_paths_alias(left: &Path, right: &Path) -> Result<bool, CliError> {
    if left == right {
        return Ok(true);
    }
    let left_metadata = optional_metadata(left)?;
    let right_metadata = optional_metadata(right)?;
    #[cfg(unix)]
    if let (Some(left), Some(right)) = (&left_metadata, &right_metadata) {
        use std::os::unix::fs::MetadataExt;

        if left.dev() == right.dev() && left.ino() == right.ino() {
            return Ok(true);
        }
    }
    Ok(resolve_database_path(left)? == resolve_database_path(right)?)
}

fn optional_metadata(path: &Path) -> Result<Option<fs::Metadata>, CliError> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn resolve_database_path(path: &Path) -> Result<PathBuf, CliError> {
    resolve_database_path_inner(path, 0)
}

fn resolve_database_path_inner(path: &Path, symlink_depth: usize) -> Result<PathBuf, CliError> {
    const MAX_SYMLINK_DEPTH: usize = 40;

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let normalized = normalize_path(&absolute);
    let components = normalized.components().collect::<Vec<_>>();
    let mut resolved = PathBuf::new();

    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Prefix(_) | Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(_) => {
                let candidate = resolved.join(component.as_os_str());
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        if symlink_depth >= MAX_SYMLINK_DEPTH {
                            return Err(CliError::cli_other_error(
                                "database path exceeds the supported symlink depth",
                            ));
                        }
                        let target = fs::read_link(&candidate)?;
                        let mut redirected = if target.is_absolute() {
                            target
                        } else {
                            resolved.join(target)
                        };
                        for remaining in &components[index + 1..] {
                            redirected.push(remaining.as_os_str());
                        }
                        return resolve_database_path_inner(&redirected, symlink_depth + 1);
                    }
                    Ok(_) => resolved.push(component.as_os_str()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        resolved.push(component.as_os_str());
                        for remaining in &components[index + 1..] {
                            resolved.push(remaining.as_os_str());
                        }
                        return Ok(normalize_path(&resolved));
                    }
                    Err(error) => return Err(CliError::Io(error)),
                }
            }
        }
    }

    match fs::canonicalize(&resolved) {
        Ok(canonical) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(resolved),
        Err(error) => Err(CliError::Io(error)),
    }
}

fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn bind_durable_admission_kernel_identity(
    database_path: &Path,
    public_key: &PublicKey,
) -> Result<(), CliError> {
    let identity_path = durable_admission_kernel_identity_path(database_path)?;
    let expected = public_key.to_hex();
    match std::fs::read_to_string(&identity_path) {
        Ok(stored) if stored.trim() == expected => Ok(()),
        Ok(_) => Err(CliError::cli_other_error(
            "durable admission database is bound to a different kernel signing key".to_string(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_durable_admission_kernel_identity(&identity_path, &expected)
        }
        Err(error) => Err(CliError::Io(error)),
    }
}

fn write_durable_admission_kernel_identity(path: &Path, public_key: &str) -> Result<(), CliError> {
    write_private_file_atomically(path, format!("{public_key}\n").as_bytes())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn durable_admission_rejects_split_local_participant_databases() -> Result<(), CliError> {
        let revocations = Path::new("revocations.sqlite3");
        let budget = Path::new("budget.sqlite3");

        for (revocation_database, budget_database) in [
            (Some(revocations), None),
            (None, Some(budget)),
            (Some(revocations), Some(budget)),
        ] {
            let Err(error) = validate_durable_admission_participant_paths(
                DurableAdmissionMode::SideEffecting,
                None,
                revocation_database,
                budget_database,
            ) else {
                return Err(CliError::cli_other_error(
                    "split local participant databases were accepted",
                ));
            };
            assert!(error
                .to_string()
                .contains("durable admission authority owns revocation and budget state"));
        }
        Ok(())
    }

    #[test]
    fn durable_admission_rejects_local_participants_with_remote_authority() -> Result<(), CliError>
    {
        let Err(error) = validate_durable_admission_participant_paths(
            DurableAdmissionMode::Monetary,
            Some("http://127.0.0.1:8080"),
            Some(Path::new("revocations.sqlite3")),
            None,
        ) else {
            return Err(CliError::cli_other_error(
                "remote authority accepted a local participant database",
            ));
        };
        assert!(error
            .to_string()
            .contains("--control-url cannot be combined with --revocation-db or --budget-db"));
        Ok(())
    }

    #[test]
    fn participant_path_validation_is_inactive_when_durable_admission_is_off(
    ) -> Result<(), CliError> {
        validate_durable_admission_participant_paths(
            DurableAdmissionMode::Off,
            None,
            Some(Path::new("revocations.sqlite3")),
            Some(Path::new("budget.sqlite3")),
        )
    }

    #[test]
    fn database_path_validation_rejects_hard_link_aliases() -> Result<(), CliError> {
        let directory = tempfile::tempdir()?;
        let first = directory.path().join("first.sqlite3");
        let second = directory.path().join("second.sqlite3");
        fs::write(&first, [])?;
        fs::hard_link(&first, &second)?;

        let Err(error) = validate_distinct_database_paths(&[
            ("first database", first.as_path()),
            ("second database", second.as_path()),
        ]) else {
            return Err(CliError::cli_other_error(
                "hard-linked databases were treated as distinct",
            ));
        };
        assert!(error
            .to_string()
            .contains("first database must not alias second database"));
        Ok(())
    }

    #[test]
    fn database_path_validation_rejects_dangling_symlink_aliases() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target.sqlite3");
        let alias = directory.path().join("alias.sqlite3");
        symlink(&target, &alias)?;

        let Err(error) = validate_distinct_database_paths(&[
            ("target database", target.as_path()),
            ("alias database", alias.as_path()),
        ]) else {
            return Err(CliError::cli_other_error(
                "dangling database symlink was treated as distinct",
            ));
        };
        assert!(error
            .to_string()
            .contains("target database must not alias alias database"));
        Ok(())
    }

    #[test]
    fn database_path_validation_rejects_dangling_parent_symlink_aliases() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let target_directory = directory.path().join("target");
        let alias_directory = directory.path().join("alias");
        symlink(&target_directory, &alias_directory)?;
        let target = target_directory.join("state.sqlite3");
        let alias = alias_directory.join("state.sqlite3");

        let Err(error) = validate_distinct_database_paths(&[
            ("target database", target.as_path()),
            ("alias database", alias.as_path()),
        ]) else {
            return Err(CliError::cli_other_error(
                "databases below a dangling symlink were treated as distinct",
            ));
        };
        assert!(error
            .to_string()
            .contains("target database must not alias alias database"));
        Ok(())
    }

    #[test]
    fn private_directory_rejects_symlink_without_chmod_target() -> Result<(), CliError> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir()?;
        let target = directory.path().join("attacker-selected");
        let alias = directory.path().join("authority.locks");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        symlink(&target, &alias)?;

        let Err(error) = create_private_directory(&alias) else {
            return Err(CliError::cli_other_error(
                "a symlinked private-directory path was accepted",
            ));
        };
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_rejects_a_parent_writable_by_other_users() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let insecure_parent = directory.path().join("shared");
        fs::create_dir(&insecure_parent)?;
        fs::set_permissions(&insecure_parent, fs::Permissions::from_mode(0o777))?;

        let Err(error) = create_private_directory(&insecure_parent.join("authority.locks")) else {
            return Err(CliError::cli_other_error(
                "an attacker-writable parent was accepted",
            ));
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable unless sticky"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_rejects_an_attacker_writable_ancestor() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let insecure_ancestor = directory.path().join("shared");
        let secure_parent = insecure_ancestor.join("victim");
        fs::create_dir(&insecure_ancestor)?;
        fs::set_permissions(&insecure_ancestor, fs::Permissions::from_mode(0o777))?;
        fs::create_dir(&secure_parent)?;
        fs::set_permissions(&secure_parent, fs::Permissions::from_mode(0o700))?;

        let Err(error) = create_private_directory(&secure_parent.join("authority.locks")) else {
            return Err(CliError::cli_other_error(
                "an attacker-writable ancestor was accepted",
            ));
        };
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable unless sticky"));
        Ok(())
    }

    fn private_directory_test_root() -> Result<tempfile::TempDir, CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    #[test]
    fn ensured_private_directory_is_created_with_private_permissions() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");

        ensure_private_directory(&target)?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_preserves_safe_existing_permissions() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;

        ensure_private_directory(&target)?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_and_preserves_writable_target() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o775))?;

        let Err(error) = ensure_private_directory(&target) else {
            return Err(CliError::cli_other_error(
                "a group-writable private directory was accepted",
            ));
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable"));
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o775);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_final_symlink_with_trailing_slash() -> Result<(), CliError>
    {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = private_directory_test_root()?;
        let target = directory.path().join("attacker-selected");
        let alias = directory.path().join("project");
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        symlink(&target, &alias)?;
        let trailing_slash = PathBuf::from(format!("{}/", alias.display()));

        let Err(error) = ensure_private_directory(&trailing_slash) else {
            return Err(CliError::cli_other_error(
                "a trailing slash made a final symlink safe",
            ));
        };

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_resolves_parent_components() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        // The lock root derived from a relative database path such as
        // `../state/session.sqlite3` keeps its parent component once joined
        // with the working directory.
        let directory = private_directory_test_root()?;
        let state = directory.path().join("state");
        fs::create_dir(directory.path().join("bin"))?;
        fs::create_dir(&state)?;
        let traversed = durable_admission_lock_root(
            &directory
                .path()
                .join("bin")
                .join("..")
                .join("state")
                .join("session.sqlite3"),
        )?;

        ensure_private_directory(&traversed)?;

        let created = state.join("session.sqlite3.locks");
        assert!(created.is_dir(), "{} is not a directory", created.display());
        assert_eq!(fs::metadata(&created)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    /// Requires a platform with a traversal-only or search-only open mode; see
    /// `ANCESTOR_ACCESS_MODE`.
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    ))]
    #[test]
    fn ensured_private_directory_traverses_execute_only_ancestors() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let ancestor = directory.path().join("execute-only");
        let target = ancestor.join("project");
        fs::create_dir(&ancestor)?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
        // Traversable but not readable: ordinary path resolution walks it.
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o311))?;

        let walked = ensure_private_directory(&target);
        fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))?;
        walked?;

        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_intermediate_symlink() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = private_directory_test_root()?;
        let target_parent = directory.path().join("attacker-selected");
        let alias_parent = directory.path().join("alias");
        fs::create_dir(&target_parent)?;
        fs::create_dir(target_parent.join("project"))?;
        symlink(&target_parent, &alias_parent)?;

        if ensure_private_directory(&alias_parent.join("project")).is_ok() {
            return Err(CliError::cli_other_error(
                "an intermediate symlink was accepted",
            ));
        }
        Ok(())
    }

    #[test]
    fn ensured_private_directory_rejects_unsafe_ancestor() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let insecure_ancestor = directory.path().join("shared");
        let target = insecure_ancestor.join("project");
        fs::create_dir(&insecure_ancestor)?;
        fs::set_permissions(&insecure_ancestor, fs::Permissions::from_mode(0o777))?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;

        let Err(error) = ensure_private_directory(&target) else {
            return Err(CliError::cli_other_error(
                "a nonsticky writable ancestor was accepted",
            ));
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must not be group or world writable unless sticky"));
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o755);
        Ok(())
    }

    #[test]
    fn prepared_directory_rejects_symlink_before_parent_component() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;

        let directory = private_directory_test_root()?;
        let working = directory.path().join("working");
        let outside = directory.path().join("outside");
        fs::create_dir(&working)?;
        fs::create_dir(&outside)?;
        symlink(&outside, working.join("link"))?;
        let lexical_target = working.join("project");
        let redirected_target = directory.path().join("project");

        let error = prepare_private_directory(&working.join("link").join("..").join("project"))
            .err()
            .ok_or_else(|| {
                CliError::cli_other_error("private directory walk followed a symlink before ..")
            })?;

        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(!lexical_target.exists());
        assert!(!redirected_target.exists());
        assert!(!outside.join("proof.txt").exists());
        Ok(())
    }

    #[test]
    fn prepared_directory_resolves_nested_parent_components() -> Result<(), CliError> {
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let first = directory.path().join("first");
        let second = first.join("second");
        let target = fs::canonicalize(directory.path())?.join("state");
        fs::create_dir(&first)?;
        fs::create_dir(&second)?;

        let prepared = prepare_private_directory(&second.join("..").join("..").join("state"))?;

        assert_eq!(prepared.path(), target);
        assert!(target.is_dir());
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o700);
        Ok(())
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    #[test]
    fn prepared_directory_traverses_search_only_ancestor() -> Result<(), CliError> {
        use nix::fcntl::OFlag;
        use std::os::unix::fs::PermissionsExt;

        let flags = private_directory_traversal_flags_unix();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(flags.contains(OFlag::O_PATH));
        #[cfg(any(target_vendor = "apple", target_os = "freebsd", target_os = "netbsd",))]
        assert!(flags.contains(OFlag::O_SEARCH));
        let directory = private_directory_test_root()?;
        let search_only = directory.path().join("search-only");
        let target = search_only.join("project");
        fs::create_dir(&search_only)?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(&search_only, fs::Permissions::from_mode(0o100))?;

        let prepared = prepare_private_directory(&target);
        fs::set_permissions(&search_only, fs::Permissions::from_mode(0o700))?;
        let prepared = prepared?;

        assert!(prepared.is_empty()?);
        Ok(())
    }

    #[test]
    fn prepared_directory_operations_remain_bound_after_path_replacement() -> Result<(), CliError> {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        let pinned = directory.path().join("pinned-project");
        let prepared = prepare_private_directory(&target)?;
        fs::rename(&target, &pinned)?;
        fs::create_dir(&target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;

        assert!(prepared.is_empty()?);
        prepared.create_dir_all(Path::new("src/bin"))?;
        prepared.write_new(Path::new("src/bin/demo.rs"), b"fn main() {}\n")?;
        let mut reference_builder = fs::DirBuilder::new();
        reference_builder.mode(0o755);
        reference_builder.create(pinned.join("reference"))?;

        assert_eq!(fs::read(pinned.join("src/bin/demo.rs"))?, b"fn main() {}\n");
        assert_eq!(
            fs::metadata(pinned.join("src"))?.permissions().mode() & 0o777,
            fs::metadata(pinned.join("reference"))?.permissions().mode() & 0o777,
            "guard-created scaffold directories must preserve ordinary 0755 creation modes"
        );
        assert!(fs::read_dir(&target)?.next().is_none());
        Ok(())
    }

    #[test]
    fn prepared_directory_write_new_never_overwrites_entries() -> Result<(), CliError> {
        use std::os::unix::fs::symlink;
        use std::os::unix::fs::PermissionsExt;

        let directory = private_directory_test_root()?;
        let target = directory.path().join("project");
        let outside = directory.path().join("outside.txt");
        let prepared = prepare_private_directory(&target)?;
        prepared.write_new(Path::new("Cargo.toml"), b"first")?;
        fs::write(target.join("reference.txt"), b"reference")?;

        assert_eq!(
            fs::metadata(target.join("Cargo.toml"))?
                .permissions()
                .mode()
                & 0o777,
            fs::metadata(target.join("reference.txt"))?
                .permissions()
                .mode()
                & 0o777,
            "guard writes must preserve normal fs::write creation permissions"
        );

        let overwrite = prepared.write_new(Path::new("Cargo.toml"), b"second");
        assert!(overwrite.is_err());
        assert_eq!(fs::read(target.join("Cargo.toml"))?, b"first");

        fs::write(&outside, b"outside")?;
        symlink(&outside, target.join("README.md"))?;
        let redirected = prepared.write_new(Path::new("README.md"), b"redirected");
        assert!(redirected.is_err());
        assert_eq!(fs::read(&outside)?, b"outside");
        Ok(())
    }

    #[test]
    fn private_directory_owner_must_match_effective_user() -> Result<(), CliError> {
        let effective_uid = nix::unistd::geteuid().as_raw();
        let foreign_uid = if effective_uid == 0 { 1 } else { 0 };

        let Err(error) = validate_private_directory_owner(foreign_uid, effective_uid) else {
            return Err(CliError::cli_other_error(
                "foreign private-directory ownership was accepted",
            ));
        };

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("must be owned by the effective user"));
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod windows_authority_tests {
    use super::*;

    #[test]
    fn durable_admission_rejects_windows_without_creating_state() -> Result<(), CliError> {
        let directory = tempfile::tempdir()?;
        let state_parent = directory.path().join("state");
        let database = state_parent.join("admission.sqlite3");
        let lock_root = durable_admission_lock_root(&database)?;
        let kernel_seed = durable_admission_kernel_seed_path(&database)?;
        let kernel_identity = durable_admission_kernel_identity_path(&database)?;

        let Err(error) = DurableAdmissionRuntime::open(&database) else {
            return Err(CliError::cli_other_error(
                "Windows durable admission unexpectedly opened",
            ));
        };

        assert!(error
            .to_string()
            .contains("sqlite authority serving requires Unix file identity and positioned I/O"));
        assert!(!state_parent.exists());
        assert!(!database.exists());
        assert!(!lock_root.exists());
        assert!(!kernel_seed.exists());
        assert!(!kernel_identity.exists());
        Ok(())
    }
}
