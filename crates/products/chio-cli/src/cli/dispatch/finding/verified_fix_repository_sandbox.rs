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
    let template = work_root.join("git-template");
    fs::create_dir(&template)?;
    let source_relative = source.strip_prefix(approved_root).map_err(|_| {
        CliError::cli_other_error(
            "verified-fix repository is outside the approved repository root".to_owned(),
        )
    })?;
    let sandbox_source = Path::new(APPROVED_ROOT_MOUNT).join(source_relative);
    let mut command = isolated_git_command(approved_root, Some(work_root));
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
    let relative = repository.strip_prefix(approved_root).map_err(|_| {
        CliError::cli_other_error(
            "verified-fix repository is outside the approved repository root".to_owned(),
        )
    })?;
    let mut command = isolated_git_command(approved_root, None);
    add_hardened_git_arguments(&mut command);
    command
        .arg("-C")
        .arg(Path::new(APPROVED_ROOT_MOUNT).join(relative));
    Ok(command)
}

fn isolated_git_command(approved_root: &Path, work_root: Option<&Path>) -> Command {
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
    add_runtime_mounts(&mut command, None);
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
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
    command
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
