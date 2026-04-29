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
//!    the core-module preinstantiate-validate path with the WGSEC-02
//!    import-namespace check.
//!
//! # Process-wide engine cache
//!
//! `wasmtime::Engine::new` allocates JIT machinery and is far too expensive
//! to repeat per fuzz iteration. The engine is built once per process via a
//! `OnceLock`. Engine construction is fail-closed: if the embedded wasmtime
//! config cannot build an engine at startup we have no fuzz signal and
//! returning keeps libFuzzer happy without aborting.

use std::sync::Arc;
use std::sync::OnceLock;

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
    // `wasmtime::Module::new` plus the WGSEC-02 import-namespace check.
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
