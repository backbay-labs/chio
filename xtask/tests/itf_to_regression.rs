use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

#[path = "golden/regression_formal_receipt_before_allow_abfe825d1266.rs"]
mod generated_fixture;

static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new() -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let counter = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "chio-itf-converter-{}-{timestamp}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn converter_output_name(trace: &[u8]) -> String {
    let digest = format!("{:x}", Sha256::digest(trace));
    format!(
        "regression_formal_receipt_before_allow_{}.rs",
        &digest[..12]
    )
}

fn run_converter(trace: &Path, out: &Path, family: &str) -> Result<(), Box<dyn Error>> {
    let output = converter_command(trace, out, family).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "converter failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .into())
}

fn converter_command(trace: &Path, out: &Path, family: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command
        .current_dir(manifest_dir().join(".."))
        .args(["formal", "itf-to-regression", "--trace"])
        .arg(trace)
        .args(["--spec", family, "--out"])
        .arg(out);
    command
}

fn fixture_run(root: &Path, label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let run = root.join(label);
    let fixtures = run.join("fixtures");
    let out = run.join("golden");
    fs::create_dir_all(&fixtures)?;
    fs::create_dir_all(&out)?;
    let fixture = manifest_dir().join("tests/fixtures/sample.itf.json");
    let trace = fixtures.join("sample.itf.json");
    fs::copy(&fixture, &trace)?;
    let trace_bytes = fs::read(&trace)?;
    run_converter(&trace, &out, "ReceiptBeforeAllow")?;
    Ok(out.join(converter_output_name(&trace_bytes)))
}

#[test]
fn conversion_is_deterministic_and_matches_golden() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let first = fixture_run(&scratch.path, "first")?;
    let second = fixture_run(&scratch.path, "second")?;
    let first_bytes = fs::read(first)?;
    let second_bytes = fs::read(second)?;
    assert_eq!(first_bytes, second_bytes);

    let golden = fs::read(
        manifest_dir().join("tests/golden/regression_formal_receipt_before_allow_abfe825d1266.rs"),
    )?;
    assert_eq!(first_bytes, golden);
    Ok(())
}

#[test]
fn malformed_trace_is_rejected_without_output() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let trace = scratch.path.join("malformed.itf.json");
    let out = scratch.path.join("out");
    fs::create_dir_all(&out)?;
    fs::write(
        &trace,
        br##"{"#meta":{"format":"ITF"},"vars":["x"],"states":[]}"##,
    )?;

    let result = run_converter(&trace, &out, "ReceiptBeforeAllow");
    assert!(result.is_err());
    assert_eq!(fs::read_dir(out)?.count(), 0);
    Ok(())
}

#[test]
fn unknown_replay_family_is_rejected_without_output() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let trace = manifest_dir().join("tests/fixtures/sample.itf.json");
    let out = scratch.path.join("out");
    fs::create_dir_all(&out)?;

    let result = run_converter(&trace, &out, "UnknownFamily");
    assert!(result.is_err());
    assert_eq!(fs::read_dir(out)?.count(), 0);
    Ok(())
}

#[test]
fn divergent_existing_output_is_not_overwritten() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let output = fixture_run(&scratch.path, "existing")?;
    fs::write(&output, b"locally modified\n")?;
    let trace = scratch.path.join("existing/fixtures/sample.itf.json");
    let out = scratch.path.join("existing/golden");

    let result = run_converter(&trace, &out, "ReceiptBeforeAllow");
    assert!(result.is_err());
    assert_eq!(fs::read(output)?, b"locally modified\n");
    Ok(())
}

#[test]
fn nonviolating_trace_is_rejected_without_output() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let mut trace = fixture_value()?;
    let allowed = trace
        .pointer("/states/1/allowed")
        .cloned()
        .ok_or("missing allowed")?;
    trace["states"][2]["allowed"] = allowed;
    assert_rejected_without_output(&scratch.path, "nonviolating.itf.json", trace)
}

#[test]
fn allowed_without_budget_check_is_still_a_violation() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let mut trace = fixture_value()?;
    trace["states"][2]["budget_checked"]["#map"][0][1]["#set"] = serde_json::json!([]);
    let trace_path = scratch.path.join("without-budget-check.itf.json");
    let out = scratch.path.join("out");
    fs::create_dir_all(&out)?;
    write_trace_value(&trace_path, &trace)?;

    run_converter(&trace_path, &out, "ReceiptBeforeAllow")?;
    assert_eq!(fs::read_dir(out)?.count(), 1);
    Ok(())
}

#[test]
fn malformed_family_integer_is_rejected_without_output() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let mut trace = fixture_value()?;
    trace["states"][2]["allowed"]["#map"][0][0] = serde_json::json!("authority");
    assert_rejected_without_output(&scratch.path, "malformed-family.itf.json", trace)?;

    let mut noncanonical = fixture_value()?;
    noncanonical["states"][2]["allowed"]["#map"][0][0]["#bigint"] = serde_json::json!("01");
    assert_rejected_without_output(&scratch.path, "noncanonical-family.itf.json", noncanonical)
}

#[test]
fn duplicate_collections_are_rejected_without_output() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;

    let mut duplicate_set = fixture_value()?;
    let capability = duplicate_set
        .pointer("/states/2/allowed/#map/0/1/#set/0")
        .cloned()
        .ok_or("missing capability")?;
    duplicate_set["states"][2]["allowed"]["#map"][0][1]["#set"]
        .as_array_mut()
        .ok_or("missing set")?
        .push(capability);
    assert_rejected_without_output(
        &scratch.path.join("set"),
        "duplicate-set.itf.json",
        duplicate_set,
    )?;

    let mut duplicate_map = fixture_value()?;
    let authority = duplicate_map
        .pointer("/states/2/budget_checked/#map/0")
        .cloned()
        .ok_or("missing authority")?;
    duplicate_map["states"][2]["budget_checked"]["#map"]
        .as_array_mut()
        .ok_or("missing map")?
        .push(authority);
    assert_rejected_without_output(
        &scratch.path.join("map"),
        "duplicate-map.itf.json",
        duplicate_map,
    )
}

#[test]
fn malformed_receipt_is_rejected_without_output() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let mut trace = fixture_value()?;
    trace["states"][2]["receipt_log"]["#map"][0][1] = serde_json::json!([{
        "cap": {"#bigint": "1"},
        "verdict": "deny",
        "t": {"#bigint": "1"}
    }]);
    assert_rejected_without_output(&scratch.path, "malformed-receipt.itf.json", trace)
}

#[test]
fn empty_action_metadata_uses_state_difference() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let mut trace = fixture_value()?;
    trace["states"][2]["#meta"]["action"] = serde_json::json!("");
    let trace_path = scratch.path.join("empty-action.itf.json");
    let out = scratch.path.join("out");
    fs::create_dir_all(&out)?;
    write_trace_value(&trace_path, &trace)?;
    run_converter(&trace_path, &out, "ReceiptBeforeAllow")?;
    let emitted = fs::read_to_string(out.join(converter_output_name(&fs::read(&trace_path)?)))?;
    assert!(emitted.contains("action_hint: \"changed: allowed\""));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_backslash_in_trace_name_is_preserved() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let trace = scratch.path.join(r"sample\backslash.itf.json");
    let out = scratch.path.join("out");
    fs::create_dir_all(&out)?;
    fs::copy(
        manifest_dir().join("tests/fixtures/sample.itf.json"),
        &trace,
    )?;
    run_converter(&trace, &out, "ReceiptBeforeAllow")?;

    let emitted = fs::read_to_string(out.join(converter_output_name(&fs::read(&trace)?)))?;
    assert!(emitted.contains(r#"sample\\backslash.itf.json"#));
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_fifo_trace_is_rejected_without_blocking() -> Result<(), Box<dyn Error>> {
    let scratch = ScratchDir::new()?;
    let trace = scratch.path.join("blocked.itf.json");
    let out = scratch.path.join("out");
    fs::create_dir_all(&out)?;
    let status = Command::new("mkfifo").arg(&trace).status()?;
    if !status.success() {
        return Err("mkfifo failed".into());
    }

    let mut child = converter_command(&trace, &out, "ReceiptBeforeAllow")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    for _ in 0..200 {
        if let Some(status) = child.try_wait()? {
            assert!(!status.success());
            assert_eq!(fs::read_dir(out)?.count(), 0);
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.kill()?;
    child.wait()?;
    Err("converter blocked while opening a nonregular trace".into())
}

fn fixture_value() -> Result<serde_json::Value, Box<dyn Error>> {
    let bytes = fs::read(manifest_dir().join("tests/fixtures/sample.itf.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_trace_value(path: &Path, trace: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    fs::write(path, serde_json::to_vec_pretty(trace)?)?;
    Ok(())
}

fn assert_rejected_without_output(
    root: &Path,
    name: &str,
    trace: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let trace_path = root.join(name);
    let out = root.join("out");
    fs::create_dir_all(&out)?;
    write_trace_value(&trace_path, &trace)?;
    assert!(run_converter(&trace_path, &out, "ReceiptBeforeAllow").is_err());
    assert_eq!(fs::read_dir(out)?.count(), 0);
    Ok(())
}
