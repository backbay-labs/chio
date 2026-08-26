use super::*;

use super::sandbox::add_runtime_mounts;

const APPROVED_ROOT_MOUNT: &str = "/approved";
const STAGING_ROOT_MOUNT: &str = "/work";

pub(super) fn approved_repository(
    configured_root: &str,
    requested: &Path,
) -> Result<(PathBuf, PathBuf), CliError> {
    let approved_root = fs::canonicalize(configured_root).map_err(|error| {
        CliError::cli_other_error(format!("seller repository root is unavailable: {error}"))
    })?;
    if !approved_root.is_dir() {
        return Err(CliError::cli_other_error(
            "seller repository root is not a directory".to_owned(),
        ));
    }
    let repository = fs::canonicalize(requested).map_err(|_| {
        CliError::cli_other_error(
            "verified-fix repository is unavailable to the operator".to_owned(),
        )
    })?;
    if !repository.is_dir() || !repository.starts_with(&approved_root) {
        return Err(CliError::cli_other_error(
            "verified-fix repository is outside the approved repository root".to_owned(),
        ));
    }
    if approved_root.to_str().is_none() || repository.to_str().is_none() {
        return Err(CliError::cli_other_error(
            "verified-fix repository paths must be valid UTF-8".to_owned(),
        ));
    }
    Ok((approved_root, repository))
}

pub(super) fn isolated_git_stdout_bounded(
    approved_root: &Path,
    repository: &Path,
    args: &[&str],
    max_bytes: usize,
    timeout: Duration,
    label: &str,
) -> Result<String, CliError> {
    let mut command = isolated_source_git_command(approved_root, repository)?;
    command.args(args);
    let bytes = run_bounded_output_command(command, max_bytes, timeout, label)?;
    let value = String::from_utf8(bytes)
        .map_err(|_| CliError::cli_other_error("git output is not UTF-8".to_owned()))?;
    Ok(value.trim().to_owned())
}

pub(super) fn isolated_repository_identity(
    approved_root: &Path,
    repository: &Path,
    timeout: Duration,
) -> Result<String, CliError> {
    let mut command = isolated_source_git_command(approved_root, repository)?;
    command.args(["remote", "get-url", "origin"]);
    let output = run_bounded_output_command_capture(
        command,
        MAX_REPOSITORY_IDENTITY_BYTES,
        timeout,
        "resolve seller repository identity",
    )?;
    if !output.status.success() {
        return Ok(repository.display().to_string());
    }
    let remote = String::from_utf8(output.stdout)
        .map_err(|_| CliError::cli_other_error("git output is not UTF-8".to_owned()))?;
    Ok(credential_free_repository_url(remote.trim())
        .unwrap_or_else(|| repository.display().to_string()))
}

pub(super) fn stage_repository_isolated(
    source: &Path,
    approved_root: &Path,
    work_root: &Path,
    timeout: Duration,
) -> Result<(), CliError> {
    validate_repository_metadata_confined(approved_root, source)?;
    let template = work_root.join("git-template");
    fs::create_dir(&template)?;
    let source_relative = source.strip_prefix(approved_root).map_err(|_| {
        CliError::cli_other_error(
            "verified-fix repository is outside the approved repository root".to_owned(),
        )
    })?;
    let sandbox_source = Path::new(APPROVED_ROOT_MOUNT).join(source_relative);
    let mut command = isolated_git_command(approved_root, Some(work_root))?;
    add_hardened_git_arguments(&mut command);
    command
        .args(["clone", "--no-local", "--no-checkout"])
        .arg(format!("--template={STAGING_ROOT_MOUNT}/git-template"))
        .arg(sandbox_source)
        .arg(format!("{STAGING_ROOT_MOUNT}/repository"));
    run_repository_staging_command(
        command,
        work_root,
        "stage the source repository in operator-owned storage",
        timeout,
        REPOSITORY_STAGE_MAX_BYTES,
    )?;
    if work_root
        .join("repository/.git/objects/info/alternates")
        .exists()
    {
        return Err(CliError::cli_other_error(
            "staged repository retained an external object store".to_owned(),
        ));
    }
    Ok(())
}

fn isolated_source_git_command(
    approved_root: &Path,
    repository: &Path,
) -> Result<Command, CliError> {
    validate_repository_metadata_confined(approved_root, repository)?;
    let relative = repository.strip_prefix(approved_root).map_err(|_| {
        CliError::cli_other_error(
            "verified-fix repository is outside the approved repository root".to_owned(),
        )
    })?;
    let mut command = isolated_git_command(approved_root, None)?;
    add_hardened_git_arguments(&mut command);
    command
        .arg("-C")
        .arg(Path::new(APPROVED_ROOT_MOUNT).join(relative));
    Ok(command)
}

fn validate_repository_metadata_confined(
    approved_root: &Path,
    repository: &Path,
) -> Result<(), CliError> {
    let git_marker = repository.join(".git");
    let metadata = fs::symlink_metadata(&git_marker).map_err(|_| {
        CliError::cli_other_error("verified-fix repository has no readable Git metadata".to_owned())
    })?;
    let git_directory = if metadata.is_dir() {
        confined_metadata_path(approved_root, &git_marker, "Git directory")?
    } else if metadata.is_file() {
        let marker = read_confined_metadata_file(approved_root, &git_marker, 4096, "Git marker")?;
        let relative = marker
            .trim()
            .strip_prefix("gitdir:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CliError::cli_other_error("verified-fix Git marker is invalid".to_owned())
            })?;
        let path = Path::new(relative);
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            repository.join(path)
        };
        confined_metadata_path(approved_root, &candidate, "Git directory")?
    } else {
        return Err(CliError::cli_other_error(
            "verified-fix Git marker is not a file or directory".to_owned(),
        ));
    };

    let common_marker = git_directory.join("commondir");
    let common_directory = if common_marker.exists() {
        let relative = read_confined_metadata_file(
            approved_root,
            &common_marker,
            4096,
            "Git common-directory marker",
        )?;
        let path = Path::new(relative.trim());
        if path.as_os_str().is_empty() {
            return Err(CliError::cli_other_error(
                "verified-fix Git common-directory marker is empty".to_owned(),
            ));
        }
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            git_directory.join(path)
        };
        confined_metadata_path(approved_root, &candidate, "Git common directory")?
    } else {
        git_directory.clone()
    };
    let object_directory = confined_metadata_path(
        approved_root,
        &common_directory.join("objects"),
        "Git object directory",
    )?;
    let alternates = object_directory.join("info/alternates");
    if alternates.exists() {
        let entries = read_confined_metadata_file(
            approved_root,
            &alternates,
            64 * 1024,
            "Git alternates file",
        )?;
        for entry in entries.lines().map(str::trim).filter(|line| !line.is_empty()) {
            let path = Path::new(entry);
            let candidate = if path.is_absolute() {
                path.to_path_buf()
            } else {
                object_directory.join(path)
            };
            confined_metadata_path(approved_root, &candidate, "Git alternate object directory")?;
        }
    }
    for config in [
        git_directory.join("config"),
        common_directory.join("config"),
        common_directory.join("config.worktree"),
    ] {
        if !config.exists() {
            continue;
        }
        let contents =
            read_confined_metadata_file(approved_root, &config, 1024 * 1024, "Git config")?;
        if contents.lines().any(|line| {
            let normalized = line.trim().to_ascii_lowercase();
            normalized.starts_with("[include") || normalized.starts_with("include.path")
        }) {
            return Err(CliError::cli_other_error(
                "verified-fix repository config includes are not allowed".to_owned(),
            ));
        }
    }
    Ok(())
}

fn confined_metadata_path(
    approved_root: &Path,
    candidate: &Path,
    label: &str,
) -> Result<PathBuf, CliError> {
    let canonical = fs::canonicalize(candidate).map_err(|_| {
        CliError::cli_other_error(format!("verified-fix {label} is unavailable"))
    })?;
    if !canonical.starts_with(approved_root) {
        return Err(CliError::cli_other_error(format!(
            "verified-fix {label} is outside the approved repository root"
        )));
    }
    Ok(canonical)
}

fn read_confined_metadata_file(
    approved_root: &Path,
    path: &Path,
    maximum_bytes: usize,
    label: &str,
) -> Result<String, CliError> {
    confined_metadata_path(approved_root, path, label)?;
    let bytes = fs::read(path)?;
    if bytes.len() > maximum_bytes {
        return Err(CliError::cli_other_error(format!(
            "verified-fix {label} exceeds its size bound"
        )));
    }
    String::from_utf8(bytes)
        .map_err(|_| CliError::cli_other_error(format!("verified-fix {label} is not UTF-8")))
}

fn isolated_git_command(
    approved_root: &Path,
    work_root: Option<&Path>,
) -> Result<Command, CliError> {
    let mut command = Command::new("bwrap");
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-user",
        "--unshare-net",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-cgroup-try",
        "--disable-userns",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/tmp",
    ]);
    add_runtime_mounts(&mut command, None)?;
    command
        .arg("--ro-bind")
        .arg(approved_root)
        .arg(APPROVED_ROOT_MOUNT);
    if let Some(work_root) = work_root {
        command
            .arg("--bind")
            .arg(work_root)
            .arg(STAGING_ROOT_MOUNT);
    }
    command.args([
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "PATH",
        "/runtime/bin",
        "--setenv",
        "GIT_EXEC_PATH",
        "/runtime/git-core",
        "--setenv",
        "PYTHONHOME",
        "/runtime/python",
        "--setenv",
        "GIT_CONFIG_GLOBAL",
        "/dev/null",
        "--setenv",
        "GIT_CONFIG_NOSYSTEM",
        "1",
        "--setenv",
        "GIT_TERMINAL_PROMPT",
        "0",
        "--",
        "git",
    ]);
    Ok(command)
}

fn add_hardened_git_arguments(command: &mut Command) {
    command.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.ext.allow=never",
    ]);
}
