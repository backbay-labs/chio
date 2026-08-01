mod support;

use std::fs;
use std::path::{Path, PathBuf};

use chio_trace_validate::TraceError;

#[test]
fn checked_signed_traces_match_the_deterministic_builder() -> Result<(), TraceError> {
    let root = workspace_root();
    let fixture_dir = root.join("formal/tla/trace/fixtures");
    let good = support::good_trace()?;
    let bad = support::bad_trace()?;
    let trusted_key = format!("{}\n", good.observer_key.to_hex());

    let expected = [
        (fixture_dir.join("revocation-good.ndjson"), good.ndjson),
        (fixture_dir.join("allow-after-revoke.ndjson"), bad.ndjson),
        (
            fixture_dir.join("trusted-observer-key.txt"),
            trusted_key.into_bytes(),
        ),
    ];

    if std::env::var_os("CHIO_UPDATE_TRACE_FIXTURES").is_some() {
        fs::create_dir_all(&fixture_dir)?;
        for (path, bytes) in &expected {
            fs::write(path, bytes)?;
        }
        return Ok(());
    }

    for (path, bytes) in expected {
        let actual = fs::read(&path).map_err(|error| {
            TraceError::InvalidInput(format!("failed to read {}: {error}", path.display()))
        })?;
        assert_eq!(actual, bytes, "fixture drifted: {}", path.display());
    }
    Ok(())
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}
