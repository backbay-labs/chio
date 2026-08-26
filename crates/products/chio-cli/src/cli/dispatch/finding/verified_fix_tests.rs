use super::*;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn staged_worktree_disables_source_repository_hooks() {
    if require_sandbox().is_err() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    assert!(Command::new("git")
        .arg("init")
        .arg(&source)
        .status()
        .unwrap()
        .success());
    fs::write(source.join("file.txt"), "content").unwrap();
    assert!(Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["add", "file.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .arg("-C")
        .arg(&source)
        .args([
            "-c",
            "user.name=Chio Test",
            "-c",
            "user.email=chio@example.invalid",
            "commit",
            "-m",
            "test",
        ])
        .status()
        .unwrap()
        .success());
    let marker = root.path().join("hook-ran");
    let hook = source.join(".git/hooks/post-checkout");
    fs::write(&hook, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).unwrap();

    let work_root = root.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let worktrees = StagedRepositorySet::new(work_root);
    let deadline = Instant::now() + Duration::from_secs(5);
    worktrees.stage(&source, root.path(), deadline).unwrap();
    let revision = git_stdout_bounded(
        &worktrees.repository,
        &["rev-parse", "HEAD"],
        128,
        REPOSITORY_STAGE_TIMEOUT,
        "resolve staged repository revision",
    )
    .unwrap();
    worktrees.add("candidate", &revision, deadline).unwrap();
    assert!(!marker.exists());
}

#[test]
fn source_git_sandbox_rejects_an_external_alternate_object_store() {
    if require_sandbox().is_err() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let approved = root.path().join("approved");
    let source = approved.join("source");
    let outside = root.path().join("outside");
    fs::create_dir_all(&approved).unwrap();
    for repository in [&source, &outside] {
        assert!(Command::new("git")
            .arg("init")
            .arg(repository)
            .status()
            .unwrap()
            .success());
    }
    fs::write(outside.join("secret.txt"), "operator secret").unwrap();
    assert!(Command::new("git")
        .arg("-C")
        .arg(&outside)
        .args(["add", "secret.txt"])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("git")
        .arg("-C")
        .arg(&outside)
        .args([
            "-c",
            "user.name=Chio Test",
            "-c",
            "user.email=chio@example.invalid",
            "commit",
            "-m",
            "secret",
        ])
        .status()
        .unwrap()
        .success());
    let outside_commit = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(&outside)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let outside_objects = fs::canonicalize(outside.join(".git/objects")).unwrap();
    let alternates = source.join(".git/objects/info/alternates");
    fs::create_dir_all(alternates.parent().unwrap()).unwrap();
    fs::write(&alternates, format!("{}\n", outside_objects.display())).unwrap();
    assert!(Command::new("git")
        .arg("-C")
        .arg(&source)
        .args(["cat-file", "-e", outside_commit.trim()])
        .status()
        .unwrap()
        .success());

    let error = isolated_git_stdout_bounded(
        &approved,
        &source,
        &["cat-file", "-t", outside_commit.trim()],
        64,
        Duration::from_secs(1),
        "read seller object",
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("outside the approved repository root"));
}

#[test]
fn source_git_sandbox_rejects_repository_config_includes() {
    let root = tempfile::tempdir().unwrap();
    let approved = root.path().join("approved");
    let source = approved.join("source");
    fs::create_dir_all(&approved).unwrap();
    assert!(Command::new("git")
        .arg("init")
        .arg(&source)
        .status()
        .unwrap()
        .success());
    let config = source.join(".git/config");
    let mut file = OpenOptions::new().append(true).open(config).unwrap();
    writeln!(file, "[include]\n\tpath = /usr/local/operator-private.conf").unwrap();

    let error = isolated_git_stdout_bounded(
        &approved,
        &source,
        &["rev-parse", "HEAD"],
        64,
        Duration::from_secs(1),
        "read seller revision",
    )
    .unwrap_err();
    assert!(error.to_string().contains("config includes are not allowed"));
}

#[test]
fn failed_repository_staging_removes_its_partial_root() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("not-a-repository");
    fs::create_dir(&source).unwrap();
    let work_root = root.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let result = {
        let worktrees = StagedRepositorySet::new(work_root.clone());
        worktrees.stage(
            &source,
            root.path(),
            Instant::now() + Duration::from_secs(5),
        )
    };
    assert!(result.is_err());
    assert!(!work_root.exists());
}

#[test]
fn expired_package_deadline_stops_before_repository_staging() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir(&source).unwrap();
    let work_root = root.path().join("work");
    fs::create_dir(&work_root).unwrap();
    let result = {
        let worktrees = StagedRepositorySet::new(work_root.clone());
        worktrees.stage(&source, root.path(), Instant::now())
    };
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("aggregate deadline"));
    assert!(!work_root.exists());
}

#[test]
fn repository_staging_enforces_deadline_and_aggregate_storage() {
    let root = tempfile::tempdir().unwrap();
    let mut stalled = Command::new("sh");
    stalled.args(["-c", "sleep 5"]);
    let started = Instant::now();
    let timeout = run_repository_staging_command(
        stalled,
        root.path(),
        "run test staging command",
        Duration::from_millis(50),
        1024 * 1024,
    )
    .unwrap_err();
    assert!(timeout.to_string().contains("deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));

    let mut oversized = Command::new("sh");
    oversized.current_dir(root.path()).args([
        "-c",
        "dd if=/dev/zero of=one bs=700 count=1 status=none && dd if=/dev/zero of=two bs=700 count=1 status=none",
    ]);
    let storage = run_repository_staging_command(
        oversized,
        root.path(),
        "run test staging command",
        Duration::from_secs(2),
        1024,
    )
    .unwrap_err();
    assert!(storage.to_string().contains("storage bound"));
}

#[test]
fn patch_output_runner_enforces_deadline_and_output_bound() {
    let mut stalled = Command::new("sh");
    stalled.args(["-c", "sleep 5"]);
    let started = Instant::now();
    let timeout = run_bounded_output_command(
        stalled,
        1024,
        Duration::from_millis(50),
        "test patch generation",
    )
    .unwrap_err();
    assert!(timeout.to_string().contains("deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));

    let mut oversized = Command::new("sh");
    oversized.args(["-c", "printf '123456789'"]);
    let output = run_bounded_output_command(
        oversized,
        8,
        Duration::from_secs(2),
        "test patch generation",
    )
    .unwrap_err();
    assert!(output.to_string().contains("output exceeded"));
}

#[test]
fn sandbox_mounts_only_explicit_runtime_components() {
    let root = tempfile::tempdir().unwrap();
    for path in [
        ".cargo/bin",
        ".cargo/registry/private-package",
        ".cargo/git/private-checkout",
        ".rustup/toolchains/stable",
    ] {
        fs::create_dir_all(root.path().join(path)).unwrap();
    }
    let mut command = Command::new("bwrap");
    add_runtime_mounts(&mut command, Some(root.path())).unwrap();
    let arguments = command
        .get_args()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();

    for forbidden in ["/usr", "/usr/local", "/etc/ssl", "/lib", "/lib64"] {
        assert!(!arguments.windows(3).any(|window| {
            window[0] == "--ro-bind" && (window[1] == forbidden || window[2] == forbidden)
        }));
    }
    assert!(arguments.iter().any(|argument| argument == "/runtime/bin/sh"));
    let temporary_root = root.path().to_string_lossy().into_owned();
    assert!(arguments
        .iter()
        .all(|argument| !argument.contains(temporary_root.as_str())));
}

#[test]
fn private_new_output_is_published_only_after_complete_write() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("package.draft.json");
    let bytes = vec![b'x'; 64 * 1024];
    write_private_new_atomic(&output, &bytes).unwrap();
    assert_eq!(fs::read(&output).unwrap(), bytes);
    assert!(!root.path().join(".package.draft.json.tmp").exists());
    assert!(write_private_new_atomic(&output, b"replacement").is_err());
    assert_eq!(fs::read(&output).unwrap(), bytes);
}

#[test]
fn repository_identity_strips_remote_credentials_and_url_secrets() {
    assert_eq!(
        credential_free_repository_url(
            "https://token:secret@example.com/org/repo.git?access_token=hidden#fragment"
        )
        .as_deref(),
        Some("https://example.com/org/repo.git")
    );
    assert_eq!(
        credential_free_repository_url("credential@example.com:org/repo.git?token=hidden")
            .as_deref(),
        Some("example.com:org/repo.git")
    );

    let repository = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .arg("init")
        .arg(repository.path())
        .status()
        .unwrap()
        .success());
    let oversized_remote = format!(
        "https://example.com/{}.git",
        "a".repeat(MAX_REPOSITORY_IDENTITY_BYTES)
    );
    assert!(Command::new("git")
        .arg("-C")
        .arg(repository.path())
        .args(["config", "remote.origin.url", &oversized_remote])
        .status()
        .unwrap()
        .success());
    let error = repository_identity(repository.path()).unwrap_err();
    assert!(error.to_string().contains("output exceeded"));
}

#[test]
fn paid_terminal_uses_its_authenticated_historical_verification_time() {
    assert_eq!(proof_verification_time(Some(1_700_000_000)).unwrap(), 1_700_000_000);
}

#[test]
fn admission_reconciliation_continues_after_one_job_fails() {
    let pending = vec![
        ("a".repeat(64), PathBuf::from("/tmp/first")),
        ("b".repeat(64), PathBuf::from("/tmp/second")),
        ("c".repeat(64), PathBuf::from("/tmp/third")),
    ];
    let mut visited = Vec::new();
    let result = reconcile_pending_admissions(pending, |package| {
        visited.push(package.to_path_buf());
        if package.ends_with("first") {
            Err(CliError::cli_other_error("terminal failure".to_owned()))
        } else {
            Ok(())
        }
    });

    assert_eq!(visited.len(), 3);
    assert_eq!(result.reconciled_jobs, 2);
    assert_eq!(result.failed_jobs.len(), 1);
    assert_eq!(result.failed_jobs[0].finding_id, "a".repeat(64));
    assert_eq!(result.failed_jobs[0].error, "terminal failure");
}

#[test]
fn isolated_test_cannot_read_operator_sibling_and_has_a_deadline() {
    if require_sandbox().is_err() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let worktree = root.path().join("worktree");
    fs::create_dir(&worktree).unwrap();
    assert!(Command::new("git")
        .arg("init")
        .arg(&worktree)
        .status()
        .unwrap()
        .success());
    let secret = root.path().join("operator-profile.json");
    fs::write(&secret, "operator-secret").unwrap();
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
    let command = format!("test ! -e '{}'", secret.display());
    let result =
        run_test_command_with_timeout(&worktree, &command, Duration::from_secs(2)).unwrap();
    assert_eq!(result.exit_code, 0);
    let git_result = run_test_command_with_timeout(
        &worktree,
        "test \"$(git rev-parse --is-inside-work-tree)\" = true",
        Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(git_result.exit_code, 0);

    let bounded_write = run_test_command_with_limits(
        &worktree,
        "dd if=/dev/zero of=too-large bs=1048576 count=2 status=none",
        Duration::from_secs(2),
        TestSandboxLimits {
            address_space_bytes: 512 * 1024 * 1024,
            file_bytes: 4 * 1024 * 1024,
            tmpfs_bytes: 1024 * 1024,
            process_count: 64,
            open_files: 128,
            cpu_secs: 2,
        },
    )
    .unwrap();
    assert_ne!(bounded_write.exit_code, 0);

    let started = Instant::now();
    let error = run_test_command_with_timeout(
        &worktree,
        "sleep 5",
        Duration::from_millis(50),
    )
    .unwrap_err();
    assert!(error.to_string().contains("execution deadline"));
    assert!(started.elapsed() < Duration::from_secs(2));
}
