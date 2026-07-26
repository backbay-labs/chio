use std::fs;
use std::path::{Path, PathBuf};

use chio_wasm_guards::abi::{GuardRequest, GuardVerdict, WasmGuardAbi};
use chio_wasm_guards::runtime::wasmtime_backend::WasmtimeBackend;
use serde::Deserialize;

use crate::CliError;

use super::formatting::{format_duration_us, format_number, format_size, mean_u64, percentile};
use super::{guard_io_error, guard_yaml_error};

pub(crate) fn cmd_guard_inspect(path: &Path) -> Result<(), CliError> {
    let wasm_bytes = fs::read(path)
        .map_err(|e| guard_io_error(format!("failed to read {}: {e}", path.display())))?;

    let file_size = wasm_bytes.len() as u64;

    let parser = wasmparser::Parser::new(0);
    let mut export_list: Vec<(String, &str)> = Vec::new();
    let mut memory_info: Vec<String> = Vec::new();

    for payload in parser.parse_all(&wasm_bytes) {
        let payload =
            payload.map_err(|e| CliError::guard_error(format!("wasm parse error: {e}")))?;
        match payload {
            wasmparser::Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(|e| {
                        CliError::guard_error(format!("wasm export parse error: {e}"))
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
                        CliError::guard_error(format!("wasm memory parse error: {e}"))
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
pub(super) struct TestFixture {
    /// Human-readable fixture name.
    pub(super) name: String,
    /// Request fields matching GuardRequest shape.
    pub(super) request: GuardRequest,
    /// Expected verdict: "allow" or "deny".
    pub(super) expected_verdict: String,
    /// If verdict is deny, the deny reason must contain this substring.
    #[serde(default)]
    pub(super) deny_reason_contains: Option<String>,
}

pub(crate) fn cmd_guard_test(
    wasm_path: &Path,
    fixture_paths: &[PathBuf],
    fuel_limit: u64,
) -> Result<(), CliError> {
    let wasm_bytes = fs::read(wasm_path)
        .map_err(|e| guard_io_error(format!("failed to read {}: {e}", wasm_path.display())))?;

    let mut total = 0u32;
    let mut passed = 0u32;
    let mut failed = 0u32;

    for fixture_path in fixture_paths {
        let yaml_content = fs::read_to_string(fixture_path).map_err(|e| {
            guard_io_error(format!(
                "failed to read fixture file {}: {e}",
                fixture_path.display()
            ))
        })?;
        let fixtures: Vec<TestFixture> = serde_yml::from_str(&yaml_content).map_err(|e| {
            guard_yaml_error(format!(
                "failed to parse fixture file {}: {e}",
                fixture_path.display()
            ))
        })?;

        for fixture in &fixtures {
            total += 1;

            // Create a fresh backend per fixture to reset fuel and memory state.
            let mut backend = WasmtimeBackend::new().map_err(|e| {
                CliError::guard_error(format!("failed to create wasmtime backend: {e}"))
            })?;
            backend
                .load_module(&wasm_bytes, fuel_limit)
                .map_err(|e| CliError::guard_error(format!("failed to load wasm module: {e}")))?;

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
        Err(CliError::guard_error(format!("{failed} test(s) failed")))
    } else {
        Ok(())
    }
}

pub(super) enum FixtureResult {
    Pass,
    Fail(String),
}

pub(super) fn check_verdict(
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
                    GuardVerdict::Deny { reason } => {
                        reason.as_deref().unwrap_or("(no reason)").to_string()
                    }
                    _ => String::new(),
                };
                FixtureResult::Fail(format!("expected allow, got deny: {reason}"))
            }
        }
        "deny" => match verdict {
            GuardVerdict::Allow => FixtureResult::Fail("expected deny, got allow".to_string()),
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
    let wasm_bytes = fs::read(wasm_path)
        .map_err(|e| guard_io_error(format!("failed to read {}: {e}", wasm_path.display())))?;

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
            CliError::guard_error(format!("failed to create wasmtime backend: {e}"))
        })?;
        backend
            .load_module(&wasm_bytes, fuel_limit)
            .map_err(|e| CliError::guard_error(format!("failed to load wasm module: {e}")))?;
        let _ = backend.evaluate(&sample_request);
    }

    // Benchmark iterations
    let mut durations_ns: Vec<u64> = Vec::with_capacity(iterations as usize);
    let mut fuel_values: Vec<u64> = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let mut backend = WasmtimeBackend::new().map_err(|e| {
            CliError::guard_error(format!("failed to create wasmtime backend: {e}"))
        })?;
        backend
            .load_module(&wasm_bytes, fuel_limit)
            .map_err(|e| CliError::guard_error(format!("failed to load wasm module: {e}")))?;

        let start = std::time::Instant::now();
        let _verdict = backend.evaluate(&sample_request).map_err(|e| {
            CliError::guard_error(format!("evaluation failed during benchmark: {e}"))
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
    println!(
        "  p50:  {}",
        format_duration_us(percentile(&durations_ns, 50))
    );
    println!(
        "  p99:  {}",
        format_duration_us(percentile(&durations_ns, 99))
    );
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
