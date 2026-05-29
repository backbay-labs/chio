// DO NOT EDIT - regenerate via 'make regen-rust' or 'cargo xtask codegen rust'.
//
// Source: spec/schemas/chio-wire/v1/**/*.schema.json
// Tool:   typify =0.4.3 (see xtask/codegen-tools.lock.toml)
// Crate:  chio-spec-codegen
//
// Manual edits will be overwritten by the next regeneration; the
// `_generated_check` integration test enforces this header on every file
// under `crates/chio-core-types/src/_generated/`.

//! Aggregator for the threat-model codegen stubs.
//!
//! The chio-conformance test crate does NOT
//! pull this module into its `lib.rs`; each per-threat `.rs` file
//! under this directory is its own integration test. The module
//! aggregator is emitted for documentation purposes only.

// covers: capability_token_theft
// covers: kernel_impersonation
// covers: tool_server_escape
// covers: native_channel_replay
// covers: resource_exhaustion_dos
// covers: delegation_chain_abuse
// covers: ssrf_via_http_substrate
// covers: pii_phi_exposure
// covers: agent_velocity_abuse
// covers: cumulative_data_exfiltration
// covers: behavioral_sequence_attack
// covers: wasm_guard_resource_exhaustion
// covers: pq_signature_downgrade
// covers: tee_quote_forgery
// covers: passkey_credential_theft
// covers: audience_confusion
// covers: weights_hash_spoof
