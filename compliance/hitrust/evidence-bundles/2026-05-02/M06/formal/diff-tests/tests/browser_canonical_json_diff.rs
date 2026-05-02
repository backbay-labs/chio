//! Browser wasm canonical-JSON differential test.
//!
//! The native half validates the frozen canonical vector corpus against the
//! Rust oracle. The second native test launches this file under
//! `wasm-bindgen-test` in a headless browser, where the same production
//! canonicalizer runs as wasm and must emit byte-identical UTF-8 for every
//! frozen corpus case.

use chio_core::canonical::canonical_json_bytes;
#[cfg(not(target_arch = "wasm32"))]
use chio_core::canonical::canonical_json_string;
use serde_json::Value;

const CANONICAL_V1: &str = include_str!("../../../tests/bindings/vectors/canonical/v1.json");

#[derive(Debug)]
struct CanonicalCase {
    id: String,
    input_json: String,
    canonical_json: String,
}

#[cfg(target_arch = "wasm32")]
#[derive(Debug, PartialEq, Eq)]
struct BindingErrorShape {
    code: &'static str,
    message: String,
}

#[cfg(target_arch = "wasm32")]
impl BindingErrorShape {
    fn canonicalize_rejected(message: impl Into<String>) -> Self {
        Self {
            code: "CanonicalizeRejected",
            message: message.into(),
        }
    }
}

fn canonical_cases() -> Result<Vec<CanonicalCase>, String> {
    let corpus: Value = serde_json::from_str(CANONICAL_V1)
        .map_err(|error| format!("parse canonical vector corpus: {error}"))?;
    let version = corpus
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| "canonical vector corpus missing numeric version".to_string())?;
    if version != 1 {
        return Err(format!(
            "expected canonical vector corpus version 1, got {version}"
        ));
    }

    let raw_cases = corpus
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "canonical vector corpus missing cases array".to_string())?;
    if raw_cases.is_empty() {
        return Err("canonical vector corpus has no cases".to_string());
    }

    raw_cases
        .iter()
        .enumerate()
        .map(|(idx, raw)| {
            Ok(CanonicalCase {
                id: string_field(raw, idx, "id")?,
                input_json: string_field(raw, idx, "input_json")?,
                canonical_json: string_field(raw, idx, "canonical_json")?,
            })
        })
        .collect()
}

fn string_field(raw: &Value, index: usize, field: &str) -> Result<String, String> {
    raw.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("case {index} missing string field `{field}`"))
}

fn parse_input(case: &CanonicalCase) -> Result<Value, String> {
    serde_json::from_str(&case.input_json)
        .map_err(|error| format!("case `{}` input_json parse failed: {error}", case.id))
}

#[cfg(not(target_arch = "wasm32"))]
fn rust_oracle_bytes(case: &CanonicalCase) -> Result<Vec<u8>, String> {
    let input = parse_input(case)?;
    canonical_json_bytes(&input)
        .map_err(|error| format!("case `{}` oracle canonicalize failed: {error}", case.id))
}

#[cfg(target_arch = "wasm32")]
fn browser_wasm_canonical_json_bytes(value: &Value) -> Result<Vec<u8>, BindingErrorShape> {
    canonical_json_bytes(value).map_err(|error| {
        BindingErrorShape::canonicalize_rejected(format!(
            "browser wasm canonicalize rejected input: {error}"
        ))
    })
}

fn assert_bytes_eq(case_id: &str, expected: &[u8], actual: &[u8]) -> Result<(), String> {
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "case `{case_id}` byte mismatch: expected `{}`, got `{}`",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(actual)
    ))
}

#[cfg(target_arch = "wasm32")]
fn assert_browser_parity(raw: &str, expected: &str, label: &str) -> Result<(), String> {
    let input: Value =
        serde_json::from_str(raw).map_err(|error| format!("{label}: parse failed: {error}"))?;
    let actual = browser_wasm_canonical_json_bytes(&input)
        .map_err(|error| format!("{label}: {}: {}", error.code, error.message))?;
    assert_bytes_eq(label, expected.as_bytes(), &actual)
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn rust_oracle_matches_frozen_canonical_vector_bytes() -> Result<(), String> {
    for case in canonical_cases()? {
        let input = parse_input(&case)?;
        let actual_string = canonical_json_string(&input)
            .map_err(|error| format!("case `{}` oracle string failed: {error}", case.id))?;
        let actual_bytes = rust_oracle_bytes(&case)?;

        if actual_string != case.canonical_json {
            return Err(format!(
                "case `{}` string mismatch: expected `{}`, got `{}`",
                case.id, case.canonical_json, actual_string
            ));
        }
        assert_bytes_eq(&case.id, case.canonical_json.as_bytes(), &actual_bytes)?;
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn headless_browser_wasm_matches_frozen_canonical_vector_bytes() -> Result<(), String> {
    use std::path::Path;
    use std::process::Command;

    if !wasm_c_toolchain_available()? {
        eprintln!(
            "skipping wasm-bindgen differential test because the host C compiler cannot target wasm32-unknown-unknown"
        );
        return Ok(());
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let runner =
        std::env::var("CHIO_CANONICAL_DIFF_WASM_RUNNER").unwrap_or_else(|_| "auto".to_string());
    let attempts = match runner.as_str() {
        "auto" => {
            let mut attempts = Vec::new();
            if chrome_and_driver_major_match() {
                attempts.push((
                    "headless Chrome",
                    vec!["test", "--headless", "--chrome", ".", "--test"],
                ));
            }
            attempts.push(("Node wasm-bindgen", vec!["test", "--node", ".", "--test"]));
            attempts
        }
        "chrome" => vec![(
            "headless Chrome",
            vec!["test", "--headless", "--chrome", ".", "--test"],
        )],
        "node" => vec![("Node wasm-bindgen", vec!["test", "--node", ".", "--test"])],
        other => {
            return Err(format!(
                "unsupported CHIO_CANONICAL_DIFF_WASM_RUNNER `{other}`; expected `auto`, `chrome`, or `node`"
            ));
        }
    };

    let mut failures = Vec::new();
    for (mode, mut args) in attempts {
        args.push("browser_canonical_json_diff");
        let mut command = Command::new("wasm-pack");
        command.args(args).current_dir(manifest_dir);
        apply_wasm_safe_rustflags(&mut command);
        let output = command
            .output()
            .map_err(|error| format!("spawn wasm-pack {mode} test: {error}"))?;

        if output.status.success() {
            return Ok(());
        }
        failures.push(format_wasm_pack_failure(mode, &output));
    }

    let failure = failures.join("\n\n");
    eprintln!("{failure}");
    Err(failure)
}

#[cfg(not(target_arch = "wasm32"))]
fn apply_wasm_safe_rustflags(command: &mut std::process::Command) {
    let Ok(rustflags) = std::env::var("RUSTFLAGS") else {
        return;
    };
    let filtered = filter_wasm_rustflags(&rustflags);
    if filtered.is_empty() {
        command.env_remove("RUSTFLAGS");
    } else {
        command.env("RUSTFLAGS", filtered);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn filter_wasm_rustflags(rustflags: &str) -> String {
    let mut filtered = Vec::new();
    let mut parts = rustflags.split_whitespace().peekable();
    while let Some(part) = parts.next() {
        if part == "-C" && parts.peek() == Some(&"link-arg=-Wl,--threads=1") {
            let _ = parts.next();
            continue;
        }
        if part == "-Clink-arg=-Wl,--threads=1" || part == "link-arg=-Wl,--threads=1" {
            continue;
        }
        filtered.push(part);
    }
    filtered.join(" ")
}

#[cfg(not(target_arch = "wasm32"))]
fn format_wasm_pack_failure(mode: &str, output: &std::process::Output) -> String {
    format!(
        "wasm-pack {mode} test failed with status {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn wasm_c_toolchain_available() -> Result<bool, String> {
    use std::fs;
    use std::process::{Command, Stdio};

    let cc = std::env::var("CC_wasm32_unknown_unknown")
        .or_else(|_| std::env::var("TARGET_CC"))
        .or_else(|_| std::env::var("CC"))
        .unwrap_or_else(|_| "clang".to_string());
    let dir = std::env::temp_dir().join(format!("chio-wasm-cc-check-{}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|error| format!("create wasm cc check dir: {error}"))?;
    let source = dir.join("check.c");
    let object = dir.join("check.o");
    fs::write(&source, "int chio_wasm_cc_check(void) { return 0; }\n")
        .map_err(|error| format!("write wasm cc check source: {error}"))?;

    let status = Command::new(&cc)
        .arg("--target=wasm32-unknown-unknown")
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("spawn wasm C compiler `{cc}`: {error}"))?;

    let _ = fs::remove_file(&source);
    let _ = fs::remove_file(&object);
    let _ = fs::remove_dir(&dir);

    Ok(status.success())
}

#[cfg(not(target_arch = "wasm32"))]
fn chrome_and_driver_major_match() -> bool {
    let chrome_major = chrome_major_version();
    let driver_major = command_major_version("chromedriver", &["--version"]);
    chrome_major.is_some() && chrome_major == driver_major
}

#[cfg(not(target_arch = "wasm32"))]
fn chrome_major_version() -> Option<u32> {
    command_major_version("google-chrome", &["--version"])
        .or_else(|| command_major_version("chromium", &["--version"]))
        .or_else(|| command_major_version("chromium-browser", &["--version"]))
        .or_else(|| {
            command_major_version(
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                &["--version"],
            )
        })
}

#[cfg(not(target_arch = "wasm32"))]
fn command_major_version(command: &str, args: &[&str]) -> Option<u32> {
    let output = std::process::Command::new(command)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    major_version_from_text(&stdout)
}

#[cfg(not(target_arch = "wasm32"))]
fn major_version_from_text(text: &str) -> Option<u32> {
    text.split_whitespace()
        .find(|part| part.as_bytes().first().is_some_and(u8::is_ascii_digit))
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok())
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_rustflags_filter_removes_linux_host_link_thread_arg() {
    assert_eq!(
        filter_wasm_rustflags("-D warnings -C link-arg=-Wl,--threads=1 -C debuginfo=0"),
        "-D warnings -C debuginfo=0"
    );
    assert_eq!(
        filter_wasm_rustflags("-D warnings -Clink-arg=-Wl,--threads=1"),
        "-D warnings"
    );
}

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

#[cfg(target_arch = "wasm32")]
fn browser_wasm_corpus_result() -> Result<(), String> {
    for case in canonical_cases()? {
        let input = parse_input(&case)?;
        let actual = browser_wasm_canonical_json_bytes(&input)
            .map_err(|error| format!("case `{}` {}: {}", case.id, error.code, error.message))?;
        assert_bytes_eq(&case.id, case.canonical_json.as_bytes(), &actual)?;
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn browser_wasm_corpus_matches_oracle_bytes() {
    let result = browser_wasm_corpus_result();
    assert!(result.is_ok(), "{}", result.err().unwrap_or_default());
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn browser_wasm_rejection_parity_uses_binding_error_shape() {
    for raw in [
        "NaN",
        "Infinity",
        "-Infinity",
        "{\"bad\":NaN}",
        "\"\\uD800\"",
    ] {
        let result = serde_json::from_str::<Value>(raw).map_err(|error| {
            BindingErrorShape::canonicalize_rejected(format!(
                "browser wasm rejected non-canonical JSON input: {error}"
            ))
        });
        assert!(
            result.is_err(),
            "{raw} should reject before canonicalization"
        );
        let error = result.err().unwrap_or_else(|| {
            BindingErrorShape::canonicalize_rejected("expected rejection did not occur")
        });
        assert_eq!(error.code, "CanonicalizeRejected");
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn browser_wasm_empty_collection_parity() {
    let result = (|| -> Result<(), String> {
        assert_browser_parity("{}", "{}", "empty object")?;
        assert_browser_parity("[]", "[]", "empty array")
    })();
    assert!(result.is_ok(), "{}", result.err().unwrap_or_default());
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn browser_wasm_utf16_key_ordering_parity() {
    let result = assert_browser_parity(
        "{\"\\ue000\":1,\"\\ud800\\udc00\":2}",
        "{\"𐀀\":2,\"\":1}",
        "UTF-16 key ordering",
    );
    assert!(result.is_ok(), "{}", result.err().unwrap_or_default());
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn browser_wasm_number_shortest_form_parity() {
    let result = assert_browser_parity(
        "{\"big\":1e21,\"min_subnormal\":5e-324,\"above_safe\":9007199254740993,\"sum\":0.30000000000000004,\"negative_zero\":-0.0}",
        "{\"above_safe\":9007199254740993,\"big\":1e+21,\"min_subnormal\":5e-324,\"negative_zero\":0,\"sum\":0.30000000000000004}",
        "number shortest form",
    );
    assert!(result.is_ok(), "{}", result.err().unwrap_or_default());
}
