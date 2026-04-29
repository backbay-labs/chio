//! libFuzzer entry-point module for `chio-openapi-mcp-bridge`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the standalone
//! `chio-fuzz` workspace at `../../fuzz`. Production builds never pull in
//! `arbitrary`, never expose these symbols, and never get recompiled with
//! libFuzzer instrumentation.
//!
//! [`fuzz_openapi_ingest`] drives arbitrary bytes through the canonical
//! OpenAPI-spec ingest trust boundary: [`crate::OpenApiMcpBridge::from_spec`].
//! That call covers the full ingest pipeline:
//!
//! 1. JSON-vs-YAML auto-detection plus parse (`chio_openapi::OpenApiSpec::parse`).
//! 2. OpenAPI 3.x version validation and `info` / `paths` extraction.
//! 3. Manifest generation (`chio_openapi::ManifestGenerator::generate_tools`).
//! 4. Tool-definition conversion plus route-binding map population.
//! 5. Manifest validation (`chio_manifest::validate_manifest`).
//!
//! `chio-openapi-mcp-bridge` ingests untrusted bytes (operator-supplied
//! OpenAPI specs at runtime), so this target catches parse-path panics and
//! allocator regressions in the `serde_json` / `serde_yaml` -> `OpenApiSpec`
//! -> manifest-validate chain.

use crate::{BridgeConfig, OpenApiMcpBridge};

/// Drive arbitrary bytes through the OpenAPI-spec ingest trust boundary
/// at [`crate::OpenApiMcpBridge::from_spec`].
///
/// Bytes are first decoded as UTF-8 (non-UTF-8 inputs are silently dropped,
/// mirroring the `serde_json` / `serde_yaml` contracts). The decoded text is
/// then handed to `OpenApiMcpBridge::from_spec`, which auto-detects JSON vs
/// YAML, parses the spec, generates an MCP tool manifest, populates route
/// bindings, and validates the manifest end-to-end.
///
/// Every error variant is silently consumed: the trust-boundary contract
/// guarantees the only outcomes are `Err(_)` (good), `Ok(OpenApiMcpBridge)`
/// (good), or a panic / abort (which libFuzzer surfaces as a crash).
pub fn fuzz_openapi_ingest(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let config = BridgeConfig {
        server_id: "fuzz-bridge".to_string(),
        server_name: "Fuzz Bridge".to_string(),
        server_version: "0.0.0".to_string(),
        public_key: "00".to_string(),
        base_url: "https://fuzz.invalid".to_string(),
    };
    let _ = OpenApiMcpBridge::from_spec(text, config);
}
