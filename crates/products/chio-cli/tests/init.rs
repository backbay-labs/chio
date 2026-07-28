#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_test_dir() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_nanos();
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "chio-cli-init-{}-{nonce}-{counter}",
        std::process::id()
    ))
}

#[test]
fn init_creates_expected_project_files() {
    let project_dir = unique_test_dir();
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");

    assert!(
        output.status.success(),
        "chio init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for path in [
        project_dir.join("Cargo.toml"),
        project_dir.join("README.md"),
        project_dir.join("policy.yaml"),
        project_dir.join(".gitignore"),
        project_dir.join("src/bin/hello_server.rs"),
        project_dir.join("src/bin/demo.rs"),
    ] {
        assert!(path.exists(), "expected scaffold file `{}`", path.display());
    }

    let readme = fs::read_to_string(project_dir.join("README.md")).expect("read scaffold readme");
    assert!(readme.contains("cargo build"));
    assert!(readme.contains("cargo run --quiet --bin demo"));

    let cargo_toml =
        fs::read_to_string(project_dir.join("Cargo.toml")).expect("read scaffold manifest");
    assert!(cargo_toml.contains("[package]"));
    assert!(!cargo_toml.contains("{{PACKAGE_NAME}}"));

    assert_private_directory(&project_dir);
}

#[cfg(unix)]
#[test]
fn init_accepts_parent_relative_project_directory() {
    let test_root = unique_test_dir();
    let working_directory = test_root.join("working");
    let project_dir = test_root.join("new-project");
    fs::create_dir_all(&working_directory).expect("create working directory");
    fs::set_permissions(&test_root, fs::Permissions::from_mode(0o700)).expect("secure test root");
    fs::set_permissions(&working_directory, fs::Permissions::from_mode(0o700))
        .expect("secure working directory");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg("../new-project")
        .current_dir(&working_directory)
        .output()
        .expect("run chio init");

    assert!(
        output.status.success(),
        "chio init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        project_dir.join("Cargo.toml").exists(),
        "chio init did not create the parent-relative project"
    );
    assert_private_directory(&project_dir);
}

#[cfg(unix)]
#[test]
fn init_rejects_parent_component_after_symlink_segment() {
    let test_root = unique_test_dir();
    let working_directory = test_root.join("working");
    let symlink_destination = test_root.join("destination");
    let redirected_project = test_root.join("project");
    let lexical_project = working_directory.join("project");
    fs::create_dir_all(&working_directory).expect("create working directory");
    fs::create_dir_all(&symlink_destination).expect("create symlink destination");
    fs::set_permissions(&test_root, fs::Permissions::from_mode(0o700)).expect("secure test root");
    fs::set_permissions(&working_directory, fs::Permissions::from_mode(0o700))
        .expect("secure working directory");
    std::os::unix::fs::symlink(&symlink_destination, working_directory.join("link"))
        .expect("create path symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg("link/../project")
        .current_dir(&working_directory)
        .output()
        .expect("run chio init");

    assert!(
        !output.status.success(),
        "chio init accepted a parent component after a symlink segment"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("parent components after a path segment"),
        "unexpected chio init error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !redirected_project.exists() && !lexical_project.exists(),
        "chio init created a project after ambiguous symlink traversal"
    );
}

#[cfg(unix)]
#[test]
fn init_rejects_writable_existing_empty_project_directory_without_mutation() {
    let project_dir = unique_test_dir();
    fs::create_dir(&project_dir).expect("create existing project directory");
    fs::set_permissions(&project_dir, fs::Permissions::from_mode(0o777))
        .expect("make existing project directory permissive");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");

    assert!(
        !output.status.success(),
        "chio init accepted a group- or world-writable target"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must not be group or world writable"),
        "unexpected chio init error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_directory_mode(&project_dir, 0o777);
    assert!(
        fs::read_dir(&project_dir)
            .expect("read rejected project directory")
            .next()
            .is_none(),
        "chio init mutated the rejected project directory"
    );
}

#[cfg(unix)]
#[test]
fn init_rejects_unsafe_ancestor_without_creating_project() {
    let unsafe_ancestor = unique_test_dir();
    let project_dir = unsafe_ancestor.join("project");
    fs::create_dir(&unsafe_ancestor).expect("create unsafe project ancestor");
    fs::set_permissions(&unsafe_ancestor, fs::Permissions::from_mode(0o777))
        .expect("make project ancestor writable");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");

    assert!(
        !output.status.success(),
        "chio init accepted an unsafe project ancestor"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "private directory ancestry must not be group or world writable unless sticky"
        ),
        "unexpected chio init error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !project_dir.exists(),
        "chio init created a project below an unsafe ancestor"
    );
    assert_directory_mode(&unsafe_ancestor, 0o777);
    assert!(
        fs::read_dir(&unsafe_ancestor)
            .expect("read unsafe project ancestor")
            .next()
            .is_none(),
        "chio init mutated the unsafe project ancestor"
    );
}

#[cfg(unix)]
#[test]
fn init_accepts_safe_existing_empty_project_directory_without_chmod() {
    let project_dir = unique_test_dir();
    fs::create_dir(&project_dir).expect("create existing project directory");
    fs::set_permissions(&project_dir, fs::Permissions::from_mode(0o755))
        .expect("set safe existing project directory permissions");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");

    assert!(
        output.status.success(),
        "chio init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_directory_mode(&project_dir, 0o755);
}

#[cfg(unix)]
#[test]
fn init_rejects_symlink_target_without_mutating_destination() {
    let test_root = unique_test_dir();
    let destination = test_root.join("destination");
    let project_link = test_root.join("project-link");
    fs::create_dir_all(&destination).expect("create symlink destination");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
        .expect("set destination permissions");
    std::os::unix::fs::symlink(&destination, &project_link).expect("create project symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_link)
        .output()
        .expect("run chio init");

    assert!(
        !output.status.success(),
        "chio init accepted a symlink target"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("symbolic link"),
        "unexpected chio init error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_directory_mode(&destination, 0o755);
    assert!(
        fs::read_dir(&destination)
            .expect("read symlink destination")
            .next()
            .is_none(),
        "chio init mutated the symlink destination"
    );
}

#[cfg(unix)]
#[test]
fn init_rejects_symlink_target_with_trailing_separator() {
    let test_root = unique_test_dir();
    let destination = test_root.join("destination");
    let project_link = test_root.join("project-link");
    fs::create_dir_all(&destination).expect("create symlink destination");
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755))
        .expect("set destination permissions");
    std::os::unix::fs::symlink(&destination, &project_link).expect("create project symlink");
    let mut project_link_with_separator = project_link.into_os_string();
    project_link_with_separator.push("/");

    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_link_with_separator)
        .output()
        .expect("run chio init");

    assert!(
        !output.status.success(),
        "chio init accepted a symlink target with a trailing separator"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("symbolic link"),
        "unexpected chio init error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_directory_mode(&destination, 0o755);
    assert!(
        fs::read_dir(&destination)
            .expect("read symlink destination")
            .next()
            .is_none(),
        "chio init mutated the symlink destination"
    );
}

#[test]
fn scaffolded_demo_runs_governed_hello_flow() {
    let project_dir = unique_test_dir();
    let init = Command::new(env!("CARGO_BIN_EXE_chio"))
        .arg("init")
        .arg(&project_dir)
        .output()
        .expect("run chio init");
    assert!(
        init.status.success(),
        "chio init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let cargo_target_dir = project_dir.join(".chio-test-target");
    let output = Command::new("cargo")
        .arg("run")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(project_dir.join("Cargo.toml"))
        .arg("--bin")
        .arg("demo")
        .arg("--")
        .arg("Ada")
        .env("CHIO_BIN", env!("CARGO_BIN_EXE_chio"))
        .env("CARGO_TARGET_DIR", &cargo_target_dir)
        .output()
        .expect("run scaffold demo");

    assert!(
        output.status.success(),
        "scaffold demo failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Hello, Ada! This call was mediated by Chio."));
    assert!(stdout.contains("latest receipt:"));
    assert!(project_dir.join(".chio/receipts.db").exists());
    assert!(project_dir.join(".chio/session.db").exists());
    assert_private_directory(&project_dir.join(".chio"));
}

#[cfg(unix)]
fn assert_private_directory(path: &std::path::Path) {
    assert_directory_mode(path, 0o700);
}

#[cfg(unix)]
fn assert_directory_mode(path: &std::path::Path, expected_mode: u32) {
    let mode = fs::metadata(path)
        .expect("read directory metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode,
        expected_mode,
        "`{}` must have mode {expected_mode:04o}",
        path.display()
    );
}

#[cfg(not(unix))]
fn assert_private_directory(_path: &std::path::Path) {}
