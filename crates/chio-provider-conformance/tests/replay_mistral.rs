#![cfg(feature = "fixtures-mistral")]

use std::fs;
use std::path::{Path, PathBuf};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/mistral")
}

fn fixture_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(fixture_dir()) {
        Ok(entries) => entries,
        Err(error) => panic!("read mistral fixture dir: {error}"),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => panic!("read mistral fixture entry: {error}"),
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("ndjson") {
            out.push(path);
        }
    }
    out.sort();
    out
}

#[test]
fn replays_all_mistral_fixtures_with_canonical_byte_assertions() {
    let paths = fixture_paths();
    assert_eq!(
        paths.len(),
        12,
        "Mistral corpus must contain exactly 12 NDJSON fixtures"
    );

    let mut total_invocations = 0;
    let mut kernel_denials = 0;

    for path in &paths {
        let body = match fs::read_to_string(path) {
            Ok(body) => body,
            Err(error) => panic!("read {}: {error}", path.display()),
        };
        assert!(
            body.contains("\"x-mistral-api-version\":\"2025-04\""),
            "{} did not pin x-mistral-api-version",
            path.display()
        );
        assert!(
            body.contains("\"api_snapshot\":\"2025-04\""),
            "{} did not include api_snapshot pin",
            path.display()
        );
        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(error) => panic!("{} parse: {error}", path.display()),
            };
            if value.get("direction").and_then(|d| d.as_str()) == Some("kernel_verdict") {
                total_invocations += 1;
                if value.get("verdict").and_then(|v| v.as_str()) == Some("deny") {
                    kernel_denials += 1;
                }
            }
        }
    }

    assert_eq!(total_invocations, 12);
    assert_eq!(
        kernel_denials, 1,
        "Mistral corpus must include exactly one kernel denial fixture"
    );
}
