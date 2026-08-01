//! libFuzzer entry-point module for `chio-wasm-guards`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the standalone
//! `chio-fuzz` workspace at `../../fuzz`. Production builds never pull in
//! `arbitrary`, never expose these symbols, and never get recompiled with
//! libFuzzer instrumentation.
//!
//! # Entry point: `ComponentBackend::load_module`
//!
//! The chosen trust-boundary surface is
//! [`crate::component::ComponentBackend::load_module`], the WASM Component
//! Model preinstantiate-validate path that wraps
//! `wasmtime::component::Component::new`. Every arbitrary byte string fed
//! through this path must surface as `Err(WasmGuardError::*)` rather than a
//! panic, abort, or undefined behavior.
//!
//! # Coverage shape
//!
//! On every iteration the same `data` byte slice is driven through three
//! independent surfaces:
//!
//! 1. [`crate::runtime::wasmtime_backend::detect_wasm_format`] - the format
//!    sniff via `wasmparser::Parser::is_component` /
//!    `Parser::is_core_wasm`.
//! 2. [`crate::component::ComponentBackend::load_module`] - the
//!    Component Model preinstantiate-validate path.
//! 3. [`crate::runtime::wasmtime_backend::WasmtimeBackend::load_module`] -
//!    the core-module preinstantiate-validate path with the
//!    import-namespace check.
//!
//! # Process-wide engine cache
//!
//! `wasmtime::Engine::new` allocates JIT machinery and is far too expensive
//! to repeat per fuzz iteration. The engine is built once per process via a
//! `OnceLock`. If the embedded wasmtime config cannot build an engine at
//! startup, there is no fuzz signal, so the harness skips the input without
//! aborting.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::OnceLock;

use arbitrary::Unstructured;
use wasm_encoder::reencode::{self, Reencode};
use wasm_encoder::{
    CodeSection, ComponentSectionId, Encode, ExportKind, ExportSection, Function, FunctionSection,
    Instruction,
};
use wasmtime::{Config, Engine};

use crate::abi::WasmGuardAbi;
use crate::component::ComponentBackend;
use crate::runtime::wasmtime_backend::{detect_wasm_format, WasmtimeBackend};

/// Process-wide shared `Engine` for the fuzz harness.
///
/// Fuel metering on, Component Model on. Built once via `OnceLock` so
/// libFuzzer iterations only pay the JIT-init cost once per process. `None`
/// means engine construction failed at startup.
static ENGINE: OnceLock<Option<Arc<Engine>>> = OnceLock::new();

/// Build (or fetch) the process-wide engine. Returns `None` only if the
/// embedded wasmtime config cannot build an engine.
fn engine() -> Option<&'static Arc<Engine>> {
    ENGINE
        .get_or_init(|| {
            let mut config = Config::new();
            config.consume_fuel(true);
            config.wasm_component_model(true);
            config.wasm_component_model_async(true);
            Engine::new(&config).ok().map(Arc::new)
        })
        .as_ref()
}

/// Fuel limit handed to `load_module`. The preinstantiate-validate path
/// stores the limit but does not consume fuel; we never call `evaluate`.
/// A non-zero value avoids any short-circuit on zero-fuel pre-checks.
const FUZZ_FUEL_LIMIT: u64 = 1_000_000;

/// Drive arbitrary bytes through the WASM preinstantiate-validate trust
/// boundary.
///
/// Bytes are forwarded through three independent surfaces:
///
/// 1. `detect_wasm_format` (the wasmparser format sniff).
/// 2. `ComponentBackend::load_module` (Component Model parse + validate).
/// 3. `WasmtimeBackend::load_module` (core module parse + validate +
///    import-namespace check).
///
/// Errors at every step are silently consumed: the only outcomes are
/// `Err(WasmGuardError::*)` (good) or a panic / abort (which libFuzzer
/// reports as a crash).
pub fn fuzz_wasm_preinstantiate_validate(data: &[u8]) {
    let Some(engine) = engine() else {
        return;
    };

    // Surface 1: format detection (wasmparser sniff).
    let _ = detect_wasm_format(data);

    // Surface 2: Component Model preinstantiate-validate via
    // `wasmtime::component::Component::new`. Reuses the process-wide engine;
    // never calls `evaluate` so no `Store` is built and no fuel is consumed.
    let mut component_backend = ComponentBackend::with_engine(Arc::clone(engine));
    let _ = component_backend.load_module(data, FUZZ_FUEL_LIMIT);

    // Surface 3: core module preinstantiate-validate via
    // `wasmtime::Module::new` plus the import-namespace check.
    let mut wasmtime_backend = WasmtimeBackend::with_engine(Arc::clone(engine));
    let _ = wasmtime_backend.load_module(data, FUZZ_FUEL_LIMIT);
}

// ---------------------------------------------------------------------------
// WIT host-call boundary deserialization fuzzer
// ---------------------------------------------------------------------------

/// Drive arbitrary bytes through the WIT host-call boundary serde surface.
///
/// The trust boundary is the point at which the host accepts bytes that
/// crossed the WIT marshaller from the guest WASM module and invokes serde
/// to materialize them into typed Rust structs. A panic here lets a
/// malicious guest crash the host process.
///
/// # Chosen ABI surfaces
///
/// 1. [`GuardRequest`](crate::abi::GuardRequest) - the host-to-guest
///    WIT-marshalled request envelope. Exercises the `Deserialize` impl and
///    the nested `serde_json::Value` field (`arguments`) against arbitrary
///    input.
/// 2. [`GuestDenyResponse`](crate::abi::GuestDenyResponse) - the
///    canonical guest-to-host wire payload at
///    `crate::runtime::wasmtime_backend::WasmtimeBackend::read_structured_deny_reason`.
///
/// [`GuardVerdict`](crate::abi::GuardVerdict) is intentionally NOT fuzzed:
/// it crosses the WIT boundary as an `i32` return code, not a serialized
/// struct.
///
/// Errors are silently consumed; the post-condition is "no panic".
pub fn fuzz_wit_host_call_boundary(data: &[u8]) {
    use crate::abi::{GuardRequest, GuestDenyResponse};

    // Surface 1: GuardRequest -- host-to-guest WIT request envelope.
    let _ = serde_json::from_slice::<GuardRequest>(data);

    // Surface 2: GuestDenyResponse -- guest-to-host host-call boundary
    // deser site (see runtime.rs read_structured_deny_reason).
    let _ = serde_json::from_slice::<GuestDenyResponse>(data);
}

// ---------------------------------------------------------------------------
// WASM guard escape fuzzer
// ---------------------------------------------------------------------------

/// Tiny fuel ceiling used for the escape harness `evaluate` step.
///
/// Distinct from [`FUZZ_FUEL_LIMIT`] (which is the preinstantiate-validate
/// fuel field; that path never consumes fuel). The escape harness actually
/// runs guest code, so fuel must be small enough that an adversarial
/// deep-recursion or unbounded-loop module is denied with
/// [`crate::error::WasmGuardError::FuelExhausted`] rather than dragging the
/// fuzzer into a multi-second iteration. 50k units lets a `chio_alloc` stub
/// plus a handful of guest instructions clear without giving an attacker
/// enough budget to amplify a fuel-bomb seed.
const ESCAPE_FUZZ_FUEL_LIMIT: u64 = 50_000;

/// Drive arbitrary bytes through the WASM guard runtime-execution surface.
///
/// Companion to [`fuzz_wasm_preinstantiate_validate`]: that target validates
/// the pre-execution parse + import-namespace check; this one drives the
/// post-load runtime path through a single `evaluate` call. Together they
/// span the eight escape classes:
/// undeclared host imports, oversized linear memory, fuel-budget exhaustion,
/// table grow/abuse, stack overflow via deep recursion, host reentry,
/// malformed component-model encoding, and signed-but-malicious modules.
///
/// # Coverage shape
///
/// On every iteration the same `data` byte slice is driven through:
///
/// 1. [`crate::runtime::wasmtime_backend::detect_wasm_format`] - format
///    sniff; rejects pure garbage early so the escape signal is concentrated
///    on well-formed-but-malicious modules.
/// 2. [`crate::component::ComponentBackend::load_module`] - Component
///    Model preinstantiate-validate; the malformed-component-encoding class
///    lands here.
/// 3. [`crate::runtime::wasmtime_backend::WasmtimeBackend::load_module`] -
///    core-module preinstantiate-validate plus the
///    import-namespace check; the undeclared-imports class lands here.
/// 4. **(Escape-specific)** When step 3 succeeds, drive the loaded module
///    through one `evaluate` call against a constant minimal
///    [`crate::abi::GuardRequest`]. The fuel cap is fixed at
///    [`ESCAPE_FUZZ_FUEL_LIMIT`] so fuel-exhaustion, deep-recursion,
///    table-grow-abuse, and host-reentry escapes surface as typed
///    [`crate::error::WasmGuardError`] values rather than libFuzzer-visible
///    timeouts or aborts.
///
/// # Post-condition
///
/// Every iteration MUST conclude with the host process intact. Errors at
/// every step are silently consumed; the only failures are panics, aborts,
/// or sanitizer-reported memory escapes (which libFuzzer treats as crashes).
pub fn fuzz_wasm_guard_escape(data: &[u8]) {
    use crate::abi::{GuardRequest, WasmGuardAbi};

    let Some(engine) = engine() else {
        return;
    };

    // Surface 1: format sniff. Pure garbage falls out here.
    let _ = detect_wasm_format(data);

    // Surface 2: Component Model preinstantiate-validate. The
    // malformed-component-encoding class lands here.
    let mut component_backend = ComponentBackend::with_engine(Arc::clone(engine));
    let _ = component_backend.load_module(data, ESCAPE_FUZZ_FUEL_LIMIT);

    // Surface 3: core-module preinstantiate-validate. The undeclared-
    // imports, oversize-memory, and signed-but-malicious classes (which
    // all parse cleanly) land here. On successful load we proceed to
    // surface 4.
    let mut wasmtime_backend = WasmtimeBackend::with_engine(Arc::clone(engine));
    if wasmtime_backend
        .load_module(data, ESCAPE_FUZZ_FUEL_LIMIT)
        .is_ok()
    {
        // Surface 4: runtime execution. Drives fuel-exhaustion, deep-
        // recursion, table-grow-abuse, and host-reentry classes through
        // the `evaluate` boundary.
        let request = GuardRequest {
            tool_name: String::new(),
            server_id: String::new(),
            agent_id: "fuzz".to_string(),
            arguments: serde_json::Value::Null,
            scopes: Vec::new(),
            action_type: None,
            extracted_path: None,
            extracted_target: None,
            filesystem_roots: Vec::new(),
            matched_grant_index: None,
        };
        let _ = wasmtime_backend.evaluate(&request);
    }
}

// ---------------------------------------------------------------------------
// Structure-aware WASM guard fuzzer
// ---------------------------------------------------------------------------

const SMITH_FUEL_LIMIT: u64 = 50_000;
const SMITH_MEMORY_LIMIT: usize = 2 * 64 * 1024;
const SMITH_COMPONENT_MEMORY_LIMIT: usize = 2 * 1024 * 1024;
const SMITH_MODULE_LIMIT: usize = 512 * 1024;
const GUARD_WORLD_COMPONENT: &[u8] = include_bytes!("../fuzz/guard_world.wasm");

fn smith_config() -> wasm_smith::Config {
    wasm_smith::Config {
        allow_floats: false,
        allow_start_export: true,
        export_everything: true,
        max_components: 2,
        max_data_segments: 8,
        max_element_segments: 8,
        max_elements: 16,
        max_exports: 32,
        max_funcs: 8,
        max_globals: 8,
        max_imports: 0,
        max_instances: 4,
        max_instructions: 64,
        max_memories: 1,
        max_memory32_bytes: SMITH_MEMORY_LIMIT as u64,
        max_modules: 2,
        max_tables: 2,
        max_types: 16,
        max_values: 8,
        min_funcs: 1,
        min_imports: 0,
        min_memories: 1,
        min_types: 1,
        memory64_enabled: false,
        memory_max_size_required: true,
        exceptions_enabled: false,
        gc_enabled: false,
        reference_types_enabled: false,
        relaxed_simd_enabled: false,
        shared_everything_threads_enabled: false,
        simd_enabled: false,
        tail_call_enabled: false,
        threads_enabled: false,
        ..wasm_smith::Config::default()
    }
}

struct GuardShapeReencoder {
    guard_type_index: u32,
    guard_function_index: u32,
    verdict_code: i32,
    callee: GeneratedCall,
}

#[derive(Clone, Copy)]
enum ZeroValue {
    I32,
    I64,
}

struct GeneratedCall {
    function_index: u32,
    params: Vec<ZeroValue>,
    result_count: usize,
}

impl Reencode for GuardShapeReencoder {
    type Error = Infallible;

    fn parse_type_section(
        &mut self,
        types: &mut wasm_encoder::TypeSection,
        section: wasmparser::TypeSectionReader<'_>,
    ) -> Result<(), reencode::Error<Self::Error>> {
        reencode::utils::parse_type_section(self, types, section)?;
        self.guard_type_index = types.len();
        types.ty().function(
            [wasm_encoder::ValType::I32, wasm_encoder::ValType::I32],
            [wasm_encoder::ValType::I32],
        );
        Ok(())
    }

    fn parse_function_section(
        &mut self,
        functions: &mut FunctionSection,
        section: wasmparser::FunctionSectionReader<'_>,
    ) -> Result<(), reencode::Error<Self::Error>> {
        reencode::utils::parse_function_section(self, functions, section)?;
        self.guard_function_index = functions.len();
        functions.function(self.guard_type_index);
        Ok(())
    }

    fn parse_export_section(
        &mut self,
        exports: &mut ExportSection,
        section: wasmparser::ExportSectionReader<'_>,
    ) -> Result<(), reencode::Error<Self::Error>> {
        for export in section {
            let export = export?;
            if export.name != "memory" && export.name != "evaluate" {
                self.parse_export(exports, export);
            }
        }
        exports.export("memory", ExportKind::Memory, 0);
        exports.export("evaluate", ExportKind::Func, self.guard_function_index);
        Ok(())
    }

    fn parse_code_section(
        &mut self,
        code: &mut CodeSection,
        section: wasmparser::CodeSectionReader<'_>,
    ) -> Result<(), reencode::Error<Self::Error>> {
        reencode::utils::parse_code_section(self, code, section)?;
        let mut evaluate = Function::new([]);
        for param in &self.callee.params {
            match param {
                ZeroValue::I32 => evaluate.instruction(&Instruction::I32Const(0)),
                ZeroValue::I64 => evaluate.instruction(&Instruction::I64Const(0)),
            };
        }
        evaluate.instruction(&Instruction::Call(self.callee.function_index));
        for _ in 0..self.callee.result_count {
            evaluate.instruction(&Instruction::Drop);
        }
        evaluate.instruction(&Instruction::I32Const(self.verdict_code));
        evaluate.instruction(&Instruction::End);
        code.function(&evaluate);
        Ok(())
    }
}

fn generated_call(bytes: &[u8]) -> Option<GeneratedCall> {
    let mut function_types = Vec::new();
    let mut first_defined_type = None;

    for payload in wasmparser::Parser::new(0).parse_all(bytes) {
        match payload.ok()? {
            wasmparser::Payload::TypeSection(section) => {
                for function_type in section.into_iter_err_on_gc_types() {
                    function_types.push(function_type.ok()?);
                }
            }
            wasmparser::Payload::ImportSection(section) => {
                if section.count() != 0 {
                    return None;
                }
            }
            wasmparser::Payload::FunctionSection(section) => {
                if first_defined_type.is_none() {
                    first_defined_type = section.into_iter().next().transpose().ok()?;
                }
            }
            _ => {}
        }
    }

    let function_type = function_types.get(first_defined_type? as usize)?;
    let mut params = Vec::with_capacity(function_type.params().len());
    for param in function_type.params() {
        params.push(match param {
            wasmparser::ValType::I32 => ZeroValue::I32,
            wasmparser::ValType::I64 => ZeroValue::I64,
            _ => return None,
        });
    }
    Some(GeneratedCall {
        function_index: 0,
        params,
        result_count: function_type.results().len(),
    })
}

fn guard_shaped_core(data: &[u8], verdict_code: i32) -> Option<Vec<u8>> {
    let mut unstructured = Unstructured::new(data);
    let mut generated = wasm_smith::Module::new(smith_config(), &mut unstructured).ok()?;
    generated.ensure_termination(1_024).ok()?;
    let generated_bytes = generated.to_bytes();
    let callee = generated_call(&generated_bytes)?;
    let mut encoded = wasm_encoder::Module::new();
    let mut reencoder = GuardShapeReencoder {
        guard_type_index: 0,
        guard_function_index: 0,
        verdict_code,
        callee,
    };
    reencoder
        .parse_core_module(&mut encoded, wasmparser::Parser::new(0), &generated_bytes)
        .ok()?;
    let bytes = encoded.finish();
    wasmparser::Validator::new().validate_all(&bytes).ok()?;
    Some(bytes)
}

fn generated_component(data: &[u8]) -> Option<Vec<u8>> {
    let mut unstructured = Unstructured::new(data);
    let component = wasm_smith::Component::new(smith_config(), &mut unstructured).ok()?;
    let bytes = component.to_bytes();
    wasmparser::Validator::new().validate_all(&bytes).ok()?;
    Some(bytes)
}

fn guard_shaped_component(data: &[u8]) -> Vec<u8> {
    let nested =
        generated_component(data).unwrap_or_else(|| wasm_encoder::Component::new().finish());
    let mut bytes = GUARD_WORLD_COMPONENT.to_vec();
    bytes.push(ComponentSectionId::Component.into());
    nested.as_slice().encode(&mut bytes);
    assert!(wasmparser::Validator::new().validate_all(&bytes).is_ok());
    bytes
}

fn assert_named_error(error: &crate::error::WasmGuardError) {
    use crate::error::WasmGuardError;

    match error {
        WasmGuardError::ModuleLoad { .. }
        | WasmGuardError::Compilation(_)
        | WasmGuardError::MissingExport(_)
        | WasmGuardError::InvalidSignature { .. }
        | WasmGuardError::FuelExhausted { .. }
        | WasmGuardError::Memory(_)
        | WasmGuardError::Serialization(_)
        | WasmGuardError::Trap(_)
        | WasmGuardError::HostFunction(_)
        | WasmGuardError::ImportViolation { .. }
        | WasmGuardError::ModuleTooLarge { .. }
        | WasmGuardError::BackendUnavailable
        | WasmGuardError::ManifestParse(_)
        | WasmGuardError::ManifestLoad { .. }
        | WasmGuardError::HashMismatch { .. }
        | WasmGuardError::UnsupportedAbiVersion { .. }
        | WasmGuardError::UnsupportedWitWorld { .. }
        | WasmGuardError::UnrecognizedFormat
        | WasmGuardError::SignatureVerification(_) => {}
    }
}

#[derive(Clone, Copy)]
enum ExpectedVerdict {
    Allow,
    Deny,
}

fn smith_request(expected: ExpectedVerdict) -> crate::abi::GuardRequest {
    crate::abi::GuardRequest {
        tool_name: match expected {
            ExpectedVerdict::Allow => "smith-allow".to_string(),
            ExpectedVerdict::Deny => "smith-deny".to_string(),
        },
        server_id: "fuzz".to_string(),
        agent_id: "fuzz".to_string(),
        arguments: serde_json::Value::Null,
        scopes: Vec::new(),
        action_type: None,
        extracted_path: None,
        extracted_target: None,
        filesystem_roots: Vec::new(),
        matched_grant_index: None,
    }
}

fn blocking_dispatch_allows(
    outcome: &Result<crate::abi::GuardVerdict, crate::error::WasmGuardError>,
) -> bool {
    matches!(outcome, Ok(crate::abi::GuardVerdict::Allow))
}

fn assert_typed_output_confinement(
    outcome: &Result<crate::abi::GuardVerdict, crate::error::WasmGuardError>,
) {
    let same_typed_channel = match outcome {
        Ok(crate::abi::GuardVerdict::Allow) => Ok(crate::abi::GuardVerdict::Allow),
        Ok(crate::abi::GuardVerdict::Deny { .. }) => Ok(crate::abi::GuardVerdict::Deny {
            reason: Some("different telemetry".to_string()),
        }),
        Err(_) => Err(crate::error::WasmGuardError::BackendUnavailable),
    };
    assert_eq!(
        blocking_dispatch_allows(outcome),
        blocking_dispatch_allows(&same_typed_channel)
    );
}

fn exercise_core(bytes: &[u8], verdict_code: i32) {
    let Some(engine) = engine() else {
        return;
    };
    let mut backend = WasmtimeBackend::with_engine(Arc::clone(engine))
        .with_limits(SMITH_MEMORY_LIMIT, SMITH_MODULE_LIMIT);
    if let Err(error) = backend.load_module(bytes, SMITH_FUEL_LIMIT) {
        assert_named_error(&error);
        return;
    }

    let outcome = backend.evaluate(&smith_request(ExpectedVerdict::Allow));
    if let Ok(verdict) = &outcome {
        assert!(matches!(
            verdict,
            crate::abi::GuardVerdict::Allow | crate::abi::GuardVerdict::Deny { .. }
        ));
    }
    if let Err(error) = &outcome {
        assert_named_error(error);
    }
    assert_typed_output_confinement(&outcome);
    if outcome.is_ok() {
        let Some(consumed) = backend.last_fuel_consumed() else {
            panic!("successful core guard evaluation did not report fuel consumption");
        };
        assert!(consumed <= SMITH_FUEL_LIMIT);
    } else if let Some(consumed) = backend.last_fuel_consumed() {
        assert!(consumed <= SMITH_FUEL_LIMIT);
    }
    if outcome.is_ok() {
        let observed = backend.last_memory_bytes();
        assert!(matches!(observed, Some(bytes) if bytes <= SMITH_MEMORY_LIMIT));
    }
    if blocking_dispatch_allows(&outcome) {
        assert_eq!(verdict_code, crate::abi::VERDICT_ALLOW);
    }
}

fn exercise_component(bytes: &[u8], expected: ExpectedVerdict) {
    let Some(engine) = engine() else {
        return;
    };
    let mut backend = ComponentBackend::with_engine(Arc::clone(engine))
        .with_limits(SMITH_COMPONENT_MEMORY_LIMIT, SMITH_MODULE_LIMIT);
    if let Err(error) = backend.load_module(bytes, SMITH_FUEL_LIMIT) {
        panic!("guard-shaped component failed to load: {error}");
    }
    let outcome = backend.evaluate(&smith_request(expected));
    assert_typed_output_confinement(&outcome);
    match (expected, &outcome) {
        (ExpectedVerdict::Allow, Ok(crate::abi::GuardVerdict::Allow))
        | (ExpectedVerdict::Deny, Ok(crate::abi::GuardVerdict::Deny { .. })) => {}
        _ => panic!(
            "component verdict did not match the independently selected guest result: {outcome:?}"
        ),
    }
    let Some(consumed) = backend.last_fuel_consumed() else {
        panic!("successful component guard evaluation did not report fuel consumption");
    };
    assert!(consumed <= SMITH_FUEL_LIMIT);
}

/// Generate valid, bounded modules and components, then drive Chio's load and
/// evaluation boundary. Crashes are libFuzzer failures; typed errors are
/// expected and checked exhaustively.
pub fn fuzz_wasm_guard_smith(data: &[u8]) {
    let Some((&format_selector, rest)) = data.split_first() else {
        return;
    };
    let Some((&verdict_selector, generation_data)) = rest.split_first() else {
        return;
    };

    if format_selector & 1 == 0 {
        let verdict_code = match verdict_selector % 3 {
            0 => crate::abi::VERDICT_ALLOW,
            1 => crate::abi::VERDICT_DENY,
            _ => i32::from(verdict_selector).saturating_add(2),
        };
        if let Some(bytes) = guard_shaped_core(generation_data, verdict_code) {
            exercise_core(&bytes, verdict_code);
        }
    } else {
        let bytes = guard_shaped_component(generation_data);
        let expected = if verdict_selector & 1 == 0 {
            ExpectedVerdict::Allow
        } else {
            ExpectedVerdict::Deny
        };
        exercise_component(&bytes, expected);
    }
}

#[cfg(test)]
mod smith_tests {
    use super::fuzz_wasm_guard_smith;

    #[test]
    fn component_fixture_preserves_selected_allow() {
        fuzz_wasm_guard_smith(&[1, 0, 0]);
    }

    #[test]
    fn component_fixture_preserves_selected_deny() {
        fuzz_wasm_guard_smith(&[1, 1, 0]);
    }
}
