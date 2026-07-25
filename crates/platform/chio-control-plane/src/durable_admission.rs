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

        let lock_root = durable_admission_lock_root(path)?;
        fs::create_dir_all(&lock_root)?;
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
}
