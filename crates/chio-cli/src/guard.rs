use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::CliError;

use base64::Engine;
use chio_guard_registry::{
    GuardArtifactConfig, GuardCache, GuardOciRef, GuardPublishArtifact,
    GuardPublishArtifactInput, GuardPublishRef, GuardPullRequest, GuardRegistryClient,
    GuardRegistryConfig, RegistryCredentials, GUARD_ARTIFACT_MEDIA_TYPE, GUARD_CONFIG_MEDIA_TYPE,
    GUARD_WIT_WORLD,
};
use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::blocklist::{GuardDigestBlocklist, E_GUARD_DIGEST_BLOCKLISTED};
use chio_wasm_guards::manifest::GuardManifest;
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

const CARGO_TOML_TEMPLATE: &str = r#"[package]
name = "{{PACKAGE_NAME}}"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
crate-type = ["cdylib"]

[dependencies]
chio-guard-sdk = "0.1"
chio-guard-sdk-macros = "0.1"

[lints.clippy]
unwrap_used = "deny"
expect_used = "deny"
"#;

const LIB_RS_TEMPLATE: &str = r#"use chio_guard_sdk::prelude::*;
use chio_guard_sdk_macros::chio_guard;

#[chio_guard]
fn evaluate(req: GuardRequest) -> GuardVerdict {
    // TODO: implement your guard logic here.
    //
    // Access request fields:
    //   req.tool_name      -- the tool being invoked
    //   req.action_type    -- pre-extracted action category
    //   req.extracted_path -- normalized file path (if applicable)
    //
    // Return GuardVerdict::allow() or GuardVerdict::deny("reason").
    let _ = &req;
    GuardVerdict::allow()
}
"#;

const MANIFEST_YAML_TEMPLATE: &str = r#"name: {{PACKAGE_NAME}}
version: "0.1.0"
abi_version: "1"
wasm_path: "target/wasm32-unknown-unknown/release/{{UNDERSCORED_NAME}}.wasm"
wasm_sha256: "TODO: run `chio guard build` and update this hash"
"#;

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

pub(crate) fn cmd_guard_new(name: &str) -> Result<(), CliError> {
    let project_dir = Path::new(name);
    ensure_target_dir(project_dir)?;

    let dir_name = project_dir
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.trim().is_empty())
        .ok_or_else(|| {
            CliError::Other(format!(
                "could not derive a project name from `{}`",
                project_dir.display()
            ))
        })?;
    let package_name = sanitize_package_name(dir_name);
    let underscored_name = package_name.replace('-', "_");

    // Write Cargo.toml
    let cargo_toml = CARGO_TOML_TEMPLATE.replace("{{PACKAGE_NAME}}", &package_name);
    write_file(&project_dir.join("Cargo.toml"), &cargo_toml)?;

    // Write src/lib.rs
    let src_dir = project_dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| {
        CliError::Other(format!("failed to create {}: {e}", src_dir.display()))
    })?;
    write_file(&src_dir.join("lib.rs"), LIB_RS_TEMPLATE)?;

    // Write guard-manifest.yaml
    let manifest_yaml = MANIFEST_YAML_TEMPLATE
        .replace("{{PACKAGE_NAME}}", &package_name)
        .replace("{{UNDERSCORED_NAME}}", &underscored_name);
    write_file(&project_dir.join("guard-manifest.yaml"), &manifest_yaml)?;

    println!("created guard project at ./{name}");
    println!();
    println!("Next steps:");
    println!("  cd {name}");
    println!("  chio guard build");
    println!(
        "  chio guard inspect target/wasm32-unknown-unknown/release/{underscored_name}.wasm"
    );

    Ok(())
}

pub(crate) fn cmd_guard_build() -> Result<(), CliError> {
    // Verify Cargo.toml exists and contains cdylib crate-type
    let cargo_toml_contents = fs::read_to_string("Cargo.toml").map_err(|e| {
        CliError::Other(format!(
            "could not read Cargo.toml in current directory: {e}"
        ))
    })?;
    if !cargo_toml_contents.contains("cdylib") {
        return Err(CliError::Other(
            "current directory does not appear to be a guard project (no cdylib crate-type in Cargo.toml)"
                .to_string(),
        ));
    }

    // Extract the package name from Cargo.toml
    let package_name = cargo_toml_contents
        .lines()
        .find(|line| line.starts_with("name = "))
        .and_then(|line| {
            let trimmed = line.trim_start_matches("name = ").trim();
            let unquoted = trimmed.trim_matches('"');
            if unquoted.is_empty() {
                None
            } else {
                Some(unquoted.to_string())
            }
        })
        .ok_or_else(|| {
            CliError::Other("could not extract package name from Cargo.toml".to_string())
        })?;
    let underscored_name = package_name.replace('-', "_");

    // Run cargo build
    let status = Command::new("cargo")
        .args(["build", "--target", "wasm32-unknown-unknown", "--release"])
        .status()
        .map_err(|e| CliError::Other(format!("failed to run cargo: {e}")))?;

    if !status.success() {
        return Err(CliError::Other("cargo build failed".to_string()));
    }

    // Verify the output .wasm file exists
    let wasm_path = format!(
        "target/wasm32-unknown-unknown/release/{underscored_name}.wasm"
    );
    let metadata = fs::metadata(&wasm_path).map_err(|e| {
        CliError::Other(format!("expected output not found at {wasm_path}: {e}"))
    })?;

    let size = metadata.len();
    let formatted_size = format_size(size);

    println!("build complete: {wasm_path}");
    println!("binary size: {formatted_size}");

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} bytes")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub(crate) fn cmd_guard_inspect(path: &Path) -> Result<(), CliError> {
    let wasm_bytes = fs::read(path).map_err(|e| {
        CliError::Other(format!("failed to read {}: {e}", path.display()))
    })?;

    let file_size = wasm_bytes.len() as u64;

    // Parse the WASM binary
    let parser = wasmparser::Parser::new(0);
    let mut export_list: Vec<(String, &str)> = Vec::new();
    let mut memory_info: Vec<String> = Vec::new();

    for payload in parser.parse_all(&wasm_bytes) {
        let payload = payload.map_err(|e| {
            CliError::Other(format!("wasm parse error: {e}"))
        })?;
        match payload {
            wasmparser::Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| {
                        CliError::Other(format!("wasm export parse error: {e}"))
                    })?;
                    let kind_str = match export.kind {
                        wasmparser::ExternalKind::Func => "function",
                        wasmparser::ExternalKind::Memory => "memory",
                        wasmparser::ExternalKind::Table => "table",
                        wasmparser::ExternalKind::Global => "global",
                        wasmparser::ExternalKind::Tag => "tag",
                    };
                    export_list.push((export.name.to_string(), kind_str));
                }
            }
            wasmparser::Payload::MemorySection(reader) => {
                for memory in reader {
                    let memory = memory.map_err(|e| {
                        CliError::Other(format!("wasm memory parse error: {e}"))
                    })?;
                    let initial_pages = memory.initial;
                    let max_str = memory
                        .maximum
                        .map(|m| format!("{m}"))
                        .unwrap_or_else(|| "unbounded".to_string());
                    let initial_kib = initial_pages * 64;
                    memory_info.push(format!(
                        "initial={initial_pages} pages ({initial_kib} KiB), max={max_str} pages"
                    ));
                }
            }
            _ => {}
        }
    }

    // Print header
    println!("=== WASM Guard Inspection ===");
    println!();
    println!("File: {}", path.display());
    println!("Size: {}", format_size(file_size));
    println!();

    // Print exported functions
    println!("Exported functions:");
    if export_list.is_empty() {
        println!("  (none)");
    } else {
        // Find the longest export name for alignment
        let max_name_len = export_list
            .iter()
            .map(|(name, _)| name.len())
            .max()
            .unwrap_or(0);
        for (name, kind) in &export_list {
            println!("  {name:<width$} ({kind})", width = max_name_len);
        }
    }
    println!();

    // ABI compatibility check
    let required_abi = ["evaluate", "chio_alloc", "chio_deny_reason"];
    let exported_func_names: Vec<&str> = export_list
        .iter()
        .filter(|(_, kind)| *kind == "function")
        .map(|(name, _)| name.as_str())
        .collect();

    let all_present = required_abi
        .iter()
        .all(|name| exported_func_names.contains(name));

    if all_present {
        println!("ABI compatibility: COMPATIBLE");
    } else {
        println!("ABI compatibility: INCOMPATIBLE");
    }
    for name in &required_abi {
        if exported_func_names.contains(name) {
            println!("  [+] {name}");
        } else {
            println!("  [-] {name} (MISSING)");
        }
    }
    println!();

    // Memory info
    println!("Memory:");
    if memory_info.is_empty() {
        println!("  (no memory section found)");
    } else {
        for info in &memory_info {
            println!("  {info}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// A single test fixture entry loaded from a YAML file.
#[derive(Debug, Deserialize)]
struct TestFixture {
    /// Human-readable fixture name.
    name: String,
    /// Request fields matching GuardRequest shape.
    request: GuardRequest,
    /// Expected verdict: "allow" or "deny".
    expected_verdict: String,
    /// If verdict is deny, the deny reason must contain this substring.
    #[serde(default)]
    deny_reason_contains: Option<String>,
}

pub(crate) fn cmd_guard_test(
    wasm_path: &Path,
    fixture_paths: &[PathBuf],
    fuel_limit: u64,
) -> Result<(), CliError> {
    let wasm_bytes = fs::read(wasm_path).map_err(|e| {
        CliError::Other(format!("failed to read {}: {e}", wasm_path.display()))
    })?;

    let mut total = 0u32;
    let mut passed = 0u32;
    let mut failed = 0u32;

    for fixture_path in fixture_paths {
        let yaml_content = fs::read_to_string(fixture_path).map_err(|e| {
            CliError::Other(format!(
                "failed to read fixture file {}: {e}",
                fixture_path.display()
            ))
        })?;
        let fixtures: Vec<TestFixture> = serde_yml::from_str(&yaml_content).map_err(|e| {
            CliError::Other(format!(
                "failed to parse fixture file {}: {e}",
                fixture_path.display()
            ))
        })?;

        for fixture in &fixtures {
            total += 1;

            // Create a fresh backend per fixture to reset fuel and memory state.
            let mut backend = WasmtimeBackend::new().map_err(|e| {
                CliError::Other(format!("failed to create wasmtime backend: {e}"))
            })?;
            backend.load_module(&wasm_bytes, fuel_limit).map_err(|e| {
                CliError::Other(format!("failed to load wasm module: {e}"))
            })?;

            match backend.evaluate(&fixture.request) {
                Ok(verdict) => {
                    let result = check_verdict(&fixture.name, &verdict, fixture);
                    match result {
                        FixtureResult::Pass => {
                            passed += 1;
                            println!("[PASS] {}", fixture.name);
                        }
                        FixtureResult::Fail(reason) => {
                            failed += 1;
                            println!("[FAIL] {}: {reason}", fixture.name);
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    println!("[FAIL] {}: evaluation error: {e}", fixture.name);
                }
            }
        }
    }

    println!();
    println!("{passed} passed, {failed} failed out of {total} total");

    if failed > 0 {
        Err(CliError::Other(format!("{failed} test(s) failed")))
    } else {
        Ok(())
    }
}

enum FixtureResult {
    Pass,
    Fail(String),
}

fn check_verdict(
    _name: &str,
    verdict: &GuardVerdict,
    fixture: &TestFixture,
) -> FixtureResult {
    match fixture.expected_verdict.as_str() {
        "allow" => {
            if verdict.is_allow() {
                FixtureResult::Pass
            } else {
                let reason = match verdict {
                    GuardVerdict::Deny { reason } => reason
                        .as_deref()
                        .unwrap_or("(no reason)")
                        .to_string(),
                    _ => String::new(),
                };
                FixtureResult::Fail(format!("expected allow, got deny: {reason}"))
            }
        }
        "deny" => match verdict {
            GuardVerdict::Allow => {
                FixtureResult::Fail("expected deny, got allow".to_string())
            }
            GuardVerdict::Deny { reason } => {
                if let Some(expected_substr) = &fixture.deny_reason_contains {
                    let actual = reason.as_deref().unwrap_or("");
                    if actual.contains(expected_substr.as_str()) {
                        FixtureResult::Pass
                    } else {
                        FixtureResult::Fail(format!(
                            "deny reason '{}' does not contain '{expected_substr}'",
                            actual
                        ))
                    }
                } else {
                    FixtureResult::Pass
                }
            }
        },
        other => FixtureResult::Fail(format!(
            "unknown expected_verdict '{other}' (use 'allow' or 'deny')"
        )),
    }
}

pub(crate) fn cmd_guard_bench(
    wasm_path: &Path,
    iterations: u32,
    fuel_limit: u64,
) -> Result<(), CliError> {
    let wasm_bytes = fs::read(wasm_path).map_err(|e| {
        CliError::Other(format!("failed to read {}: {e}", wasm_path.display()))
    })?;

    let sample_request = GuardRequest {
        tool_name: "bench_tool".to_string(),
        server_id: "bench-server".to_string(),
        agent_id: "bench-agent".to_string(),
        arguments: serde_json::json!({"key": "value"}),
        scopes: vec!["bench-server:bench_tool".to_string()],
        action_type: Some("mcp_tool".to_string()),
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    };

    // Warmup: 5 iterations (discard results, ensures JIT compilation is warm)
    let warmup_count = 5u32;
    for _ in 0..warmup_count {
        let mut backend = WasmtimeBackend::new().map_err(|e| {
            CliError::Other(format!("failed to create wasmtime backend: {e}"))
        })?;
        backend.load_module(&wasm_bytes, fuel_limit).map_err(|e| {
            CliError::Other(format!("failed to load wasm module: {e}"))
        })?;
        let _ = backend.evaluate(&sample_request);
    }

    // Benchmark iterations
    let mut durations_ns: Vec<u64> = Vec::with_capacity(iterations as usize);
    let mut fuel_values: Vec<u64> = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let mut backend = WasmtimeBackend::new().map_err(|e| {
            CliError::Other(format!("failed to create wasmtime backend: {e}"))
        })?;
        backend.load_module(&wasm_bytes, fuel_limit).map_err(|e| {
            CliError::Other(format!("failed to load wasm module: {e}"))
        })?;

        let start = std::time::Instant::now();
        let _verdict = backend.evaluate(&sample_request).map_err(|e| {
            CliError::Other(format!("evaluation failed during benchmark: {e}"))
        })?;
        let elapsed = start.elapsed();

        durations_ns.push(elapsed.as_nanos() as u64);
        if let Some(fuel) = backend.last_fuel_consumed() {
            fuel_values.push(fuel);
        }
    }

    durations_ns.sort_unstable();
    fuel_values.sort_unstable();

    // Print results
    println!("=== Guard Benchmark ===");
    println!();
    println!("File: {}", wasm_path.display());
    println!("Iterations: {iterations}");
    println!("Fuel limit: {}", format_number(fuel_limit));
    println!();

    println!("Latency:");
    println!("  p50:  {}", format_duration_us(percentile(&durations_ns, 50)));
    println!("  p99:  {}", format_duration_us(percentile(&durations_ns, 99)));
    println!(
        "  min:  {}",
        format_duration_us(durations_ns.first().copied().unwrap_or(0))
    );
    println!(
        "  max:  {}",
        format_duration_us(durations_ns.last().copied().unwrap_or(0))
    );
    println!("  mean: {}", format_duration_us(mean_u64(&durations_ns)));
    println!();

    println!("Fuel consumed:");
    println!("  p50:  {}", format_number(percentile(&fuel_values, 50)));
    println!("  p99:  {}", format_number(percentile(&fuel_values, 99)));
    println!(
        "  min:  {}",
        format_number(fuel_values.first().copied().unwrap_or(0))
    );
    println!(
        "  max:  {}",
        format_number(fuel_values.last().copied().unwrap_or(0))
    );
    println!("  mean: {}", format_number(mean_u64(&fuel_values)));

    Ok(())
}

/// Compute the value at the given percentile from a sorted slice.
/// Returns 0 for an empty slice.
fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() * pct / 100).min(sorted.len() - 1);
    sorted[idx]
}

/// Compute the arithmetic mean of a slice of u64 values.
/// Returns 0 for an empty slice.
fn mean_u64(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let sum: u128 = values.iter().map(|v| u128::from(*v)).sum();
    (sum / values.len() as u128) as u64
}

/// Format nanoseconds as microseconds with 2 decimal places.
fn format_duration_us(nanos: u64) -> String {
    let us = nanos as f64 / 1_000.0;
    format!("{us:.2} us")
}

/// Format a number with comma separators.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

pub(crate) fn cmd_guard_pack() -> Result<(), CliError> {
    pack_from_dir(Path::new("."))
}

pub(crate) struct GuardPublishCommand<'a> {
    pub project_dir: &'a Path,
    pub reference: &'a str,
    pub wit_path: &'a Path,
    pub signer_public_key: Option<&'a str>,
    pub signer_subject: Option<&'a str>,
    pub fuel_limit: u64,
    pub memory_limit_bytes: u64,
    pub epoch_id_seed: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub allow_http_registry: Vec<String>,
}

pub(crate) fn cmd_guard_publish(command: GuardPublishCommand<'_>) -> Result<(), CliError> {
    let manifest_path = command.project_dir.join("guard-manifest.yaml");
    let manifest_content = fs::read_to_string(&manifest_path).map_err(|e| {
        CliError::Other(format!(
            "failed to read {}: {e}",
            manifest_path.display()
        ))
    })?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content).map_err(|e| {
        CliError::Other(format!("failed to parse guard-manifest.yaml: {e}"))
    })?;

    let wit_world = manifest.wit_world.as_deref().unwrap_or(GUARD_WIT_WORLD);
    if wit_world != GUARD_WIT_WORLD {
        return Err(CliError::Other(format!(
            "guard publish requires wit_world {GUARD_WIT_WORLD}, got {wit_world}"
        )));
    }

    let wasm_path = command.project_dir.join(Path::new(&manifest.wasm_path));
    let wasm_bytes = fs::read(&wasm_path).map_err(|e| {
        CliError::Other(format!("failed to read {}: {e}", wasm_path.display()))
    })?;
    let wit_bytes = fs::read(command.wit_path).map_err(|e| {
        CliError::Other(format!(
            "failed to read WIT file {}: {e}",
            command.wit_path.display()
        ))
    })?;

    let signer_public_key = resolve_signer_public_key(command.signer_public_key, &manifest)?;
    let artifact_config = GuardArtifactConfig::new(
        signer_public_key,
        command.fuel_limit,
        command.memory_limit_bytes,
        command.epoch_id_seed,
    );
    let artifact = GuardPublishArtifact::build(GuardPublishArtifactInput {
        wit: wit_bytes,
        module: wasm_bytes,
        manifest: manifest_content.into_bytes(),
        config: artifact_config,
        signer_subject: command.signer_subject.map(str::to_owned),
    })
    .map_err(|e| CliError::Other(e.to_string()))?;

    let reference = command
        .reference
        .parse::<GuardPublishRef>()
        .map_err(|e| CliError::Other(e.to_string()))?;
    let credentials = registry_credentials(command.username, command.password);
    let client = GuardRegistryClient::try_new(GuardRegistryConfig {
        allow_http_registries: command.allow_http_registry,
        ..GuardRegistryConfig::default()
    })
    .map_err(|e| CliError::Other(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Other(format!("failed to create publish runtime: {e}")))?;
    let response = runtime
        .block_on(client.publish_guard_artifact(&reference, artifact, &credentials))
        .map_err(|e| CliError::Other(e.to_string()))?;

    println!("published guard artifact");
    println!("reference:         {reference}");
    println!("artifact_type:     {GUARD_ARTIFACT_MEDIA_TYPE}");
    println!("config_media_type: {GUARD_CONFIG_MEDIA_TYPE}");
    println!("config_digest:     {}", response.config_digest);
    println!("config_url:        {}", response.config_url);
    println!("manifest_url:      {}", response.manifest_url);

    Ok(())
}

pub(crate) struct GuardPullCommand<'a> {
    pub reference: &'a str,
    pub username: Option<&'a str>,
    pub password: Option<&'a str>,
    pub allow_http_registry: Vec<String>,
}

pub(crate) fn cmd_guard_pull(command: GuardPullCommand<'_>) -> Result<(), CliError> {
    let reference = command
        .reference
        .parse::<GuardOciRef>()
        .map_err(|e| CliError::Other(e.to_string()))?;
    let blocklist = GuardDigestBlocklist::from_environment()
        .map_err(|e| CliError::Other(format!("failed to load guard blocklist: {e}")))?;
    if blocklist
        .is_blocklisted(reference.digest().as_str())
        .map_err(|e| CliError::Other(format!("failed to check guard blocklist: {e}")))?
    {
        return Err(CliError::Other(format!(
            "{E_GUARD_DIGEST_BLOCKLISTED}: guard digest {} is blocklisted",
            reference.digest()
        )));
    }
    let credentials = registry_credentials(command.username, command.password);
    let cache = GuardCache::from_environment().map_err(|e| CliError::Other(e.to_string()))?;
    let client = GuardRegistryClient::try_new(GuardRegistryConfig {
        allow_http_registries: command.allow_http_registry,
        ..GuardRegistryConfig::default()
    })
    .map_err(|e| CliError::Other(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::Other(format!("failed to create pull runtime: {e}")))?;
    let response = runtime
        .block_on(client.pull_guard_to_cache(GuardPullRequest {
            reference: &reference,
            credentials: &credentials,
            cache: &cache,
        }))
        .map_err(|e| CliError::Other(e.to_string()))?;

    println!("pulled guard artifact");
    println!("reference:        {reference}");
    println!("digest:           {}", response.cached.digest);
    println!(
        "manifest_digest:  {}",
        response.registry_manifest_digest
    );
    println!("cache_dir:        {}", response.cached.layout.directory().display());
    println!(
        "manifest_json:    {}",
        response.cached.layout.manifest_json_path().display()
    );
    println!(
        "config_json:      {}",
        response.cached.layout.config_json_path().display()
    );
    println!("wit_bin:          {}", response.cached.layout.wit_bin_path().display());
    println!(
        "module_wasm:      {}",
        response.cached.layout.module_wasm_path().display()
    );
    println!(
        "sigstore_bundle:  {}",
        response
            .cached
            .layout
            .sigstore_bundle_json_path()
            .display()
    );

    Ok(())
}

fn pack_from_dir(project_dir: &Path) -> Result<(), CliError> {
    let manifest_path = project_dir.join("guard-manifest.yaml");
    let manifest_content = fs::read_to_string(&manifest_path).map_err(|e| {
        CliError::Other(format!(
            "failed to read {}: {e}",
            manifest_path.display()
        ))
    })?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content).map_err(|e| {
        CliError::Other(format!("failed to parse guard-manifest.yaml: {e}"))
    })?;

    // Resolve the wasm file relative to the project directory
    let wasm_rel_path = Path::new(&manifest.wasm_path);
    let wasm_abs_path = project_dir.join(wasm_rel_path);
    let wasm_bytes = fs::read(&wasm_abs_path).map_err(|e| {
        CliError::Other(format!(
            "failed to read wasm file {}: {e}",
            wasm_abs_path.display()
        ))
    })?;

    // Derive the wasm filename (strip any directory components)
    let wasm_filename = wasm_rel_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            CliError::Other(format!(
                "could not derive filename from wasm_path '{}'",
                manifest.wasm_path
            ))
        })?;

    let archive_name = format!("{}-{}.arcguard", manifest.name, manifest.version);
    let archive_path = project_dir.join(&archive_name);

    let file = fs::File::create(&archive_path).map_err(|e| {
        CliError::Other(format!("failed to create {}: {e}", archive_path.display()))
    })?;
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar_builder = tar::Builder::new(enc);

    // Add guard-manifest.yaml (read from disk, store as "guard-manifest.yaml")
    let manifest_bytes = manifest_content.as_bytes();
    let mut manifest_header = tar::Header::new_gnu();
    manifest_header.set_size(manifest_bytes.len() as u64);
    manifest_header.set_mode(0o644);
    manifest_header.set_cksum();
    tar_builder
        .append_data(&mut manifest_header, "guard-manifest.yaml", manifest_bytes)
        .map_err(|e| {
            CliError::Other(format!("failed to add manifest to archive: {e}"))
        })?;

    // Add the .wasm file (store as filename only, not full relative path)
    let mut wasm_header = tar::Header::new_gnu();
    wasm_header.set_size(wasm_bytes.len() as u64);
    wasm_header.set_mode(0o644);
    wasm_header.set_cksum();
    tar_builder
        .append_data(&mut wasm_header, wasm_filename, wasm_bytes.as_slice())
        .map_err(|e| {
            CliError::Other(format!("failed to add wasm to archive: {e}"))
        })?;

    let enc = tar_builder.into_inner().map_err(|e| {
        CliError::Other(format!("failed to finalize tar archive: {e}"))
    })?;
    enc.finish().map_err(|e| {
        CliError::Other(format!("failed to finish gzip: {e}"))
    })?;

    let archive_size = fs::metadata(&archive_path)
        .map(|m| m.len())
        .unwrap_or(0);
    println!("packed: {archive_name} ({})", format_size(archive_size));

    Ok(())
}

fn resolve_signer_public_key(
    explicit: Option<&str>,
    manifest: &GuardManifest,
) -> Result<String, CliError> {
    let Some(value) = explicit.or(manifest.signer_public_key.as_deref()) else {
        return Err(CliError::Other(
            "guard publish requires --signer-public-key or signer_public_key in guard-manifest.yaml"
                .to_string(),
        ));
    };

    if value.starts_with("ed25519:") {
        return Ok(value.to_owned());
    }

    let decoded = hex::decode(value).map_err(|e| {
        CliError::Other(format!(
            "signer public key must be ed25519:<base64> or hex-encoded Ed25519 bytes: {e}"
        ))
    })?;
    let encoded = base64::engine::general_purpose::STANDARD.encode(decoded);
    Ok(format!("ed25519:{encoded}"))
}

fn registry_credentials(username: Option<&str>, password: Option<&str>) -> RegistryCredentials {
    match (username, password) {
        (Some(username), Some(password)) => RegistryCredentials::Basic {
            username: username.to_owned(),
            password: password.to_owned(),
        },
        _ => RegistryCredentials::Anonymous,
    }
}

pub(crate) fn cmd_guard_install(archive_path: &Path, target_dir: &Path) -> Result<(), CliError> {
    let file = fs::File::open(archive_path).map_err(|e| {
        CliError::Other(format!(
            "failed to open {}: {e}",
            archive_path.display()
        ))
    })?;
    let dec = GzDecoder::new(file);
    let mut archive = tar::Archive::new(dec);

    // Extract to a temporary directory first, then determine guard name from manifest.
    // Use std::env::temp_dir with a unique suffix derived from the archive filename
    // to avoid requiring tempfile as a regular dependency.
    let archive_stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("chio-install");
    let tmp_path = std::env::temp_dir().join(format!(
        "chio-install-{}-{}",
        archive_stem,
        std::process::id()
    ));
    if tmp_path.exists() {
        fs::remove_dir_all(&tmp_path).map_err(|e| {
            CliError::Other(format!(
                "failed to clean existing temp directory {}: {e}",
                tmp_path.display()
            ))
        })?;
    }
    fs::create_dir_all(&tmp_path).map_err(|e| {
        CliError::Other(format!(
            "failed to create temp directory {}: {e}",
            tmp_path.display()
        ))
    })?;

    // Collect entries into the temp directory
    for entry_result in archive.entries().map_err(|e| {
        CliError::Other(format!("failed to read archive entries: {e}"))
    })? {
        let mut entry = entry_result.map_err(|e| {
            CliError::Other(format!("failed to read archive entry: {e}"))
        })?;
        entry.unpack_in(&tmp_path).map_err(|e| {
            CliError::Other(format!("failed to extract archive entry: {e}"))
        })?;
    }

    // Read the manifest from the temp directory to determine the guard name
    let tmp_manifest_path = tmp_path.join("guard-manifest.yaml");
    let manifest_content = fs::read_to_string(&tmp_manifest_path).map_err(|e| {
        CliError::Other(format!(
            "archive does not contain guard-manifest.yaml: {e}"
        ))
    })?;
    let manifest: GuardManifest = serde_yml::from_str(&manifest_content).map_err(|e| {
        CliError::Other(format!("failed to parse manifest from archive: {e}"))
    })?;

    let guard_name = &manifest.name;
    let guard_dir = target_dir.join(guard_name);
    fs::create_dir_all(&guard_dir).map_err(|e| {
        CliError::Other(format!(
            "failed to create directory {}: {e}",
            guard_dir.display()
        ))
    })?;

    // Find the .wasm file in the temp directory (the non-manifest entry)
    let wasm_filename = {
        let mut found: Option<String> = None;
        for entry in fs::read_dir(&tmp_path).map_err(|e| {
            CliError::Other(format!("failed to list temp directory: {e}"))
        })? {
            let entry = entry.map_err(|e| {
                CliError::Other(format!("failed to read directory entry: {e}"))
            })?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str != "guard-manifest.yaml" {
                found = Some(name_str.into_owned());
            }
        }
        found.ok_or_else(|| {
            CliError::Other("archive does not contain a .wasm file".to_string())
        })?
    };

    // Copy the .wasm file
    let src_wasm = tmp_path.join(&wasm_filename);
    let dst_wasm = guard_dir.join(&wasm_filename);
    fs::copy(&src_wasm, &dst_wasm).map_err(|e| {
        CliError::Other(format!("failed to copy wasm file: {e}"))
    })?;

    // Update the manifest's wasm_path to point to the co-located filename and write it
    let updated_manifest_content = update_manifest_wasm_path(&manifest_content, &wasm_filename)?;
    fs::write(guard_dir.join("guard-manifest.yaml"), updated_manifest_content).map_err(|e| {
        CliError::Other(format!("failed to write updated manifest: {e}"))
    })?;

    // Clean up temp directory (best-effort)
    let _ = fs::remove_dir_all(&tmp_path);

    println!("installed: {guard_name} to {}/", guard_dir.display());

    Ok(())
}

/// Rewrite the `wasm_path` field in the manifest YAML to point to the given filename.
fn update_manifest_wasm_path(content: &str, new_wasm_path: &str) -> Result<String, CliError> {
    let mut value: serde_yml::Value = serde_yml::from_str(content).map_err(|e| {
        CliError::Other(format!("failed to parse manifest for wasm_path update: {e}"))
    })?;
    if let serde_yml::Value::Mapping(ref mut map) = value {
        map.insert(
            serde_yml::Value::String("wasm_path".to_string()),
            serde_yml::Value::String(new_wasm_path.to_string()),
        );
    }
    serde_yml::to_string(&value).map_err(|e| {
        CliError::Other(format!("failed to serialize updated manifest: {e}"))
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_target_dir(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(CliError::Other(format!(
                "refusing to scaffold into non-directory `{}`",
                path.display()
            )));
        }
        if path.read_dir()?.next().is_some() {
            return Err(CliError::Other(format!(
                "refusing to scaffold into non-empty directory `{}`",
                path.display()
            )));
        }
        return Ok(());
    }

    fs::create_dir_all(path)?;
    Ok(())
}

fn sanitize_package_name(input: &str) -> String {
    let mut package = input
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>();

    while package.contains("--") {
        package = package.replace("--", "-");
    }
    package = package.trim_matches('-').to_string();

    if package.is_empty() {
        "chio-guard".to_string()
    } else {
        package
    }
}

fn write_file(path: &Path, content: &str) -> Result<(), CliError> {
    fs::write(path, content).map_err(|e| {
        CliError::Other(format!("failed to write {}: {e}", path.display()))
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_package_name_normalizes_input() {
        assert_eq!(sanitize_package_name("my-guard"), "my-guard");
        assert_eq!(sanitize_package_name("My Guard"), "my-guard");
        assert_eq!(sanitize_package_name("UPPER_CASE"), "upper-case");
        assert_eq!(sanitize_package_name("___"), "chio-guard");
        assert_eq!(sanitize_package_name("a--b"), "a-b");
    }

    #[test]
    fn cmd_guard_new_creates_project_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("test-guard");
        let project_name = project_path.to_str().unwrap();

        cmd_guard_new(project_name).unwrap();

        // Check files exist
        assert!(project_path.join("Cargo.toml").exists());
        assert!(project_path.join("src/lib.rs").exists());
        assert!(project_path.join("guard-manifest.yaml").exists());

        // Check Cargo.toml content
        let cargo = fs::read_to_string(project_path.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("name = \"test-guard\""));
        assert!(cargo.contains("crate-type = [\"cdylib\"]"));
        assert!(cargo.contains("chio-guard-sdk = \"0.1\""));
        assert!(cargo.contains("chio-guard-sdk-macros = \"0.1\""));
        assert!(cargo.contains("unwrap_used = \"deny\""));

        // Check src/lib.rs content
        let lib_rs = fs::read_to_string(project_path.join("src/lib.rs")).unwrap();
        assert!(lib_rs.contains("#[chio_guard]"));
        assert!(lib_rs.contains("fn evaluate(req: GuardRequest) -> GuardVerdict"));
        assert!(lib_rs.contains("GuardVerdict::allow()"));

        // Check guard-manifest.yaml content
        let manifest = fs::read_to_string(project_path.join("guard-manifest.yaml")).unwrap();
        assert!(manifest.contains("name: test-guard"));
        assert!(manifest.contains("abi_version: \"1\""));
        assert!(manifest.contains("wasm_sha256: \"TODO:"));
        assert!(manifest.contains("test_guard.wasm"));
    }

    #[test]
    fn cmd_guard_new_refuses_non_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let project_path = dir.path().join("existing-guard");
        fs::create_dir_all(&project_path).unwrap();
        fs::write(project_path.join("some-file.txt"), "content").unwrap();

        let result = cmd_guard_new(project_path.to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_fixture_yaml_deserializes() {
        let yaml = r#"
- name: "allows read in /home"
  request:
    tool_name: read_file
    server_id: fs-server
    agent_id: agent-1
    arguments:
      path: "/home/user/doc.txt"
    scopes:
      - "fs-server:read_file"
    action_type: file_access
    extracted_path: "/home/user/doc.txt"
  expected_verdict: allow

- name: "denies read in /etc"
  request:
    tool_name: read_file
    server_id: fs-server
    agent_id: agent-1
    arguments:
      path: "/etc/shadow"
    scopes:
      - "fs-server:read_file"
    action_type: file_access
    extracted_path: "/etc/shadow"
  expected_verdict: deny
  deny_reason_contains: "restricted"
"#;

        let fixtures: Vec<TestFixture> = serde_yml::from_str(yaml).unwrap();
        assert_eq!(fixtures.len(), 2);

        // First fixture: allow
        assert_eq!(fixtures[0].name, "allows read in /home");
        assert_eq!(fixtures[0].request.tool_name, "read_file");
        assert_eq!(fixtures[0].request.server_id, "fs-server");
        assert_eq!(fixtures[0].request.agent_id, "agent-1");
        assert_eq!(fixtures[0].request.scopes, vec!["fs-server:read_file"]);
        assert_eq!(
            fixtures[0].request.action_type.as_deref(),
            Some("file_access")
        );
        assert_eq!(
            fixtures[0].request.extracted_path.as_deref(),
            Some("/home/user/doc.txt")
        );
        assert_eq!(fixtures[0].expected_verdict, "allow");
        assert!(fixtures[0].deny_reason_contains.is_none());

        // Second fixture: deny with reason substring
        assert_eq!(fixtures[1].name, "denies read in /etc");
        assert_eq!(fixtures[1].expected_verdict, "deny");
        assert_eq!(
            fixtures[1].deny_reason_contains.as_deref(),
            Some("restricted")
        );
    }

    #[test]
    fn test_fixture_expected_verdict_values() {
        let allow_yaml = r#"
- name: "allow case"
  request:
    tool_name: t
    server_id: s
    agent_id: a
    arguments: {}
  expected_verdict: allow
"#;
        let deny_yaml = r#"
- name: "deny case"
  request:
    tool_name: t
    server_id: s
    agent_id: a
    arguments: {}
  expected_verdict: deny
"#;

        let allow_fixtures: Vec<TestFixture> = serde_yml::from_str(allow_yaml).unwrap();
        assert_eq!(allow_fixtures[0].expected_verdict, "allow");

        let deny_fixtures: Vec<TestFixture> = serde_yml::from_str(deny_yaml).unwrap();
        assert_eq!(deny_fixtures[0].expected_verdict, "deny");
    }

    #[test]
    fn test_fixture_all_guard_request_fields() {
        let yaml = r#"
- name: "full fields"
  request:
    tool_name: write_file
    server_id: fs-server
    agent_id: agent-2
    arguments:
      content: "hello"
    scopes:
      - "fs-server:write_file"
    action_type: file_write
    extracted_path: "/tmp/out.txt"
    extracted_target: "example.com"
    filesystem_roots:
      - "/tmp"
      - "/home"
    matched_grant_index: 3
  expected_verdict: allow
"#;

        let fixtures: Vec<TestFixture> = serde_yml::from_str(yaml).unwrap();
        assert_eq!(fixtures.len(), 1);
        let req = &fixtures[0].request;
        assert_eq!(req.tool_name, "write_file");
        assert_eq!(req.server_id, "fs-server");
        assert_eq!(req.agent_id, "agent-2");
        assert_eq!(req.action_type.as_deref(), Some("file_write"));
        assert_eq!(req.extracted_path.as_deref(), Some("/tmp/out.txt"));
        assert_eq!(req.extracted_target.as_deref(), Some("example.com"));
        assert_eq!(req.filesystem_roots, vec!["/tmp", "/home"]);
        assert_eq!(req.matched_grant_index, Some(3));
    }

    #[test]
    fn test_check_verdict_allow_pass() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "allow".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Allow;
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_deny_pass() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("blocked".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_allow_but_denied_fails() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "allow".to_string(),
            deny_reason_contains: None,
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("nope".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => panic!("expected fail, got pass"),
            FixtureResult::Fail(_) => {}
        }
    }

    #[test]
    fn test_check_verdict_deny_reason_contains_match() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: Some("restricted".to_string()),
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("path is restricted zone".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => {}
            FixtureResult::Fail(reason) => panic!("expected pass, got fail: {reason}"),
        }
    }

    #[test]
    fn test_check_verdict_deny_reason_contains_mismatch() {
        let fixture = TestFixture {
            name: "test".to_string(),
            request: make_test_request(),
            expected_verdict: "deny".to_string(),
            deny_reason_contains: Some("restricted".to_string()),
        };
        let verdict = GuardVerdict::Deny {
            reason: Some("blocked by policy".to_string()),
        };
        match check_verdict("test", &verdict, &fixture) {
            FixtureResult::Pass => panic!("expected fail, got pass"),
            FixtureResult::Fail(_) => {}
        }
    }

    fn make_test_request() -> GuardRequest {
        GuardRequest {
            tool_name: "test_tool".to_string(),
            server_id: "test-server".to_string(),
            agent_id: "test-agent".to_string(),
            arguments: serde_json::json!({}),
            scopes: Vec::new(),
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        }
    }

    // --- Percentile / bench helper tests ---

    #[test]
    fn test_percentile_basic() {
        let data = vec![1, 2, 3, 4, 5];
        // p50: index = 5 * 50 / 100 = 2 -> data[2] = 3
        assert_eq!(percentile(&data, 50), 3);
        // p99: index = 5 * 99 / 100 = 4 -> data[4] = 5
        assert_eq!(percentile(&data, 99), 5);
    }

    #[test]
    fn test_percentile_single_element() {
        let data = vec![42];
        assert_eq!(percentile(&data, 50), 42);
        assert_eq!(percentile(&data, 99), 42);
    }

    #[test]
    fn test_percentile_empty() {
        let data: Vec<u64> = vec![];
        assert_eq!(percentile(&data, 50), 0);
        assert_eq!(percentile(&data, 99), 0);
    }

    #[test]
    fn test_mean_u64_basic() {
        assert_eq!(mean_u64(&[10, 20, 30]), 20);
        assert_eq!(mean_u64(&[1, 2, 3, 4, 5]), 3);
    }

    #[test]
    fn test_mean_u64_empty() {
        assert_eq!(mean_u64(&[]), 0);
    }

    #[test]
    fn test_format_duration_us() {
        // 1000 ns = 1.00 us
        assert_eq!(format_duration_us(1000), "1.00 us");
        // 1500 ns = 1.50 us
        assert_eq!(format_duration_us(1500), "1.50 us");
        // 0 ns = 0.00 us
        assert_eq!(format_duration_us(0), "0.00 us");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1_000_000), "1,000,000");
        assert_eq!(format_number(12_345), "12,345");
    }

    // --- Pack / Install tests ---

    #[test]
    fn test_pack_and_install_round_trip() {
        let project_dir = tempfile::tempdir().unwrap();

        // Create a minimal guard-manifest.yaml
        let manifest_content = r#"name: test-guard
version: "0.1.0"
abi_version: "1"
wasm_path: "test_guard.wasm"
wasm_sha256: "deadbeef"
"#;
        fs::write(
            project_dir.path().join("guard-manifest.yaml"),
            manifest_content,
        )
        .unwrap();

        let wasm_content = b"\x00asm\x01\x00\x00\x00fixture wasm content for round-trip test";
        fs::write(project_dir.path().join("test_guard.wasm"), wasm_content).unwrap();

        pack_from_dir(project_dir.path()).unwrap();

        let archive_path = project_dir.path().join("test-guard-0.1.0.arcguard");
        assert!(
            archive_path.exists(),
            "archive should exist at {}",
            archive_path.display()
        );
        assert!(
            archive_path.metadata().unwrap().len() > 0,
            "archive should be non-empty"
        );

        // Install to a separate directory
        let install_dir = tempfile::tempdir().unwrap();
        cmd_guard_install(&archive_path, install_dir.path()).unwrap();

        // Verify extracted files exist in {target_dir}/test-guard/
        let guard_dir = install_dir.path().join("test-guard");
        assert!(guard_dir.exists(), "guard subdirectory should exist");

        let extracted_manifest = guard_dir.join("guard-manifest.yaml");
        assert!(
            extracted_manifest.exists(),
            "extracted manifest should exist"
        );

        let extracted_wasm = guard_dir.join("test_guard.wasm");
        assert!(extracted_wasm.exists(), "extracted wasm should exist");

        // Verify wasm content is identical
        let extracted_wasm_bytes = fs::read(&extracted_wasm).unwrap();
        assert_eq!(
            extracted_wasm_bytes, wasm_content,
            "extracted wasm content should match original"
        );

        // Verify manifest has updated wasm_path pointing to co-located filename
        let extracted_manifest_content = fs::read_to_string(&extracted_manifest).unwrap();
        assert!(
            extracted_manifest_content.contains("wasm_path"),
            "extracted manifest should contain wasm_path"
        );
        // The wasm_path in the extracted manifest should point to the local filename
        let parsed: serde_yml::Value =
            serde_yml::from_str(&extracted_manifest_content).unwrap();
        let wasm_path_val = parsed.get("wasm_path").unwrap();
        assert_eq!(
            wasm_path_val.as_str().unwrap(),
            "test_guard.wasm",
            "extracted manifest wasm_path should be the co-located filename"
        );
    }

    #[test]
    fn test_pack_fails_without_manifest() {
        let project_dir = tempfile::tempdir().unwrap();
        // No guard-manifest.yaml created
        let result = pack_from_dir(project_dir.path());
        assert!(result.is_err(), "pack should fail without manifest");
    }

    #[test]
    fn test_pack_fails_with_missing_wasm() {
        let project_dir = tempfile::tempdir().unwrap();

        // Create manifest pointing to a .wasm that does not exist
        let manifest_content = r#"name: test-guard
version: "0.1.0"
abi_version: "1"
wasm_path: "nonexistent.wasm"
wasm_sha256: "deadbeef"
"#;
        fs::write(
            project_dir.path().join("guard-manifest.yaml"),
            manifest_content,
        )
        .unwrap();

        let result = pack_from_dir(project_dir.path());
        assert!(result.is_err(), "pack should fail with missing wasm");
    }

    #[test]
    fn test_install_fails_with_missing_archive() {
        let install_dir = tempfile::tempdir().unwrap();
        let bogus_path = install_dir.path().join("nonexistent.arcguard");
        let result = cmd_guard_install(&bogus_path, install_dir.path());
        assert!(result.is_err(), "install should fail with missing archive");
    }
}
