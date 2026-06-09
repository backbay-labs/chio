//! libFuzzer entry-point module for `chio-config`.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the
//! standalone `chio-fuzz` workspace at `../../fuzz`. The production build of
//! `chio-config` never pulls in `arbitrary`, never exposes these symbols, and
//! never gets recompiled with libFuzzer instrumentation.
//!
//! The single entry point [`fuzz_chio_yaml_parse`] consumes arbitrary bytes
//! and drives them through the canonical YAML-loader trust boundary:
//! [`crate::loader::load_from_str`]. That call covers the full
//! configuration-ingest pipeline:
//!
//! 1. `${VAR}` and `${VAR:-default}` interpolation
//!    ([`crate::interpolation::interpolate`]).
//! 2. YAML deserialization with `serde_yml` plus `deny_unknown_fields`
//!    ([`crate::schema::ChioConfig`]).
//! 3. Post-deserialization validation
//!    ([`crate::validation::validate`]).
//!
//! `chio-config` is not in the trust-boundary set per `OWNERS.toml`, but
//! the loader still ingests untrusted bytes from disk (`chio.yaml`),
//! environment variables (interpolation), and embedded config strings.
//! This target catches parse-path panics and allocator regressions in the
//! `serde_yml` -> `ChioConfig` -> `validate` chain rather than security
//! regressions.

use crate::loader::load_from_str;

/// Drive arbitrary bytes through the `chio-config` YAML-loader trust boundary.
///
/// Bytes are first decoded as UTF-8 (non-UTF-8 inputs are silently dropped,
/// mirroring the `serde_yml` contract that operates on `&str`). The decoded
/// text is then handed to `load_from_str`, which performs environment-variable
/// interpolation, `serde_yml` deserialization with `deny_unknown_fields`, and
/// post-deserialization validation.
///
/// Every error variant is silently consumed: the trust-boundary contract
/// guarantees the only outcomes are `Err(_)` (good), `Ok(ChioConfig)` (good,
/// exercised by valid seed corpus), or a panic / abort (which libFuzzer
/// surfaces as a crash).
pub fn fuzz_chio_yaml_parse(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = load_from_str(text);
    }
}
