#![cfg(unix)]

use std::fs;
use std::os::unix::fs::symlink;

use chio_trace_validate::{write_trace_artifact, TraceError};

#[test]
fn artifact_writer_rejects_symlink_targets_and_components() -> Result<(), TraceError> {
    let temp = tempfile::tempdir()?;
    let target = temp.path().join("target.json");
    fs::write(&target, b"original\n")?;
    let link = temp.path().join("link.json");
    symlink(&target, &link)?;
    let target_error = write_trace_artifact(&link, b"replacement\n")
        .err()
        .ok_or_else(|| TraceError::InvalidInput("symlink target was accepted".to_string()))?;
    assert!(target_error.to_string().contains("symlink"));
    assert_eq!(fs::read(&target)?, b"original\n");

    let real_dir = temp.path().join("real");
    fs::create_dir(&real_dir)?;
    let linked_dir = temp.path().join("linked");
    symlink(&real_dir, &linked_dir)?;
    let component_error = write_trace_artifact(&linked_dir.join("report.json"), b"report\n")
        .err()
        .ok_or_else(|| TraceError::InvalidInput("symlink component was accepted".to_string()))?;
    assert!(component_error.to_string().contains("symlink"));
    assert!(!real_dir.join("report.json").exists());
    Ok(())
}
