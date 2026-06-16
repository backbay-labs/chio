use std::{
    error::Error,
    path::PathBuf,
    process::{Child, Command, Output},
    thread,
    time::{Duration, Instant},
};

#[test]
fn proof_room_help_succeeds() -> Result<(), Box<dyn Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_chio-proof-room"))
        .arg("--help")
        .output()?;

    assert!(
        output.status.success(),
        "chio-proof-room --help failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("usage: chio-proof-room"), "{stdout}");
    assert!(stdout.contains("--bundle"), "{stdout}");
    assert!(stdout.contains("--ui-dir"), "{stdout}");
    assert!(stdout.contains("--fixture-root"), "{stdout}");
    assert!(stdout.contains("--listen"), "{stdout}");
    assert!(stdout.contains("--doctor-report"), "{stdout}");
    assert!(stdout.contains("--verify-only"), "{stdout}");
    Ok(())
}

#[test]
fn proof_room_verify_only_writes_doctor_report() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let report_path = tempdir.path().join("proof-room-doctor.json");
    let bundle = workspace_root()?
        .join("fixtures/proof-room/first-run/single-call-authority/proof-room-bundle");

    let output = Command::new(env!("CARGO_BIN_EXE_chio-proof-room"))
        .args([
            "--bundle",
            path_str(&bundle)?,
            "--verify-only",
            "--doctor-report",
            path_str(&report_path)?,
        ])
        .output()?;

    assert!(
        output.status.success(),
        "chio-proof-room --verify-only failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&report_path)?)?;
    assert_eq!(
        report["schema"],
        "chio.proof-room.quickstart-doctor-report.v1"
    );
    assert_eq!(report["verdict"], "verified");
    assert_eq!(report["bundle_id"], "proof-room-single-call-authority");
    assert_eq!(report["fixture_id"], "single-call-authority");
    assert!(
        report["bundle"]
            .as_str()
            .is_some_and(|bundle| bundle.ends_with("proof-room-bundle")),
        "{report}"
    );
    let negative_cases = report["negative_cases"]
        .as_array()
        .ok_or("negative cases missing from doctor report")?;
    assert!(negative_cases.iter().any(|negative_case| {
        negative_case["id"] == "policy-hash-mismatch"
            && negative_case["observed_failure_code"] == "verifier policy digest mismatch"
    }));
    let receipt_coverage = report["receipt_coverage"]
        .as_array()
        .ok_or("receipt coverage missing from doctor report")?;
    assert!(receipt_coverage.iter().any(|coverage| {
        coverage["category"] == "runtime_terminal_failure"
            && coverage["status"] == "excluded"
            && coverage["exclusion_reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("Single-call authority fixture"))
    }));
    Ok(())
}

#[test]
fn proof_room_serve_rejects_ui_dir_without_index() -> Result<(), Box<dyn Error>> {
    let tempdir = tempfile::tempdir()?;
    let ui_dir = tempdir.path().join("empty-ui");
    std::fs::create_dir_all(&ui_dir)?;
    let bundle = tempdir.path().join("bundle-not-needed-for-ui-validation");

    let child = Command::new(env!("CARGO_BIN_EXE_chio-proof-room"))
        .args([
            "--bundle",
            path_str(&bundle)?,
            "--ui-dir",
            path_str(&ui_dir)?,
            "--listen",
            "127.0.0.1:0",
        ])
        .output_with_timeout(Duration::from_secs(15))?;

    assert!(
        !child.status.success(),
        "chio-proof-room unexpectedly served an empty UI directory\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let stderr = String::from_utf8(child.stderr)?;
    assert!(stderr.contains("proof-room.ui.index-missing"), "{stderr}");
    Ok(())
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|products_dir| products_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .map(PathBuf::from)
        .ok_or_else(|| {
            format!(
                "could not resolve workspace root from {}",
                manifest_dir.display()
            )
            .into()
        })
}

fn path_str(path: &std::path::Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()).into())
}

trait CommandTimeout {
    fn output_with_timeout(&mut self, timeout: Duration) -> Result<Output, Box<dyn Error>>;
}

impl CommandTimeout for Command {
    fn output_with_timeout(&mut self, timeout: Duration) -> Result<Output, Box<dyn Error>> {
        let child = self
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        wait_for_child_output(child, timeout)
    }
}

fn wait_for_child_output(mut child: Child, timeout: Duration) -> Result<Output, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.kill()?;
    let output = child.wait_with_output()?;
    Err(format!(
        "chio-proof-room did not reject empty UI directory before binding\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}
