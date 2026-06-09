//! CLI subcommands for WASM guard module signing and verification.
//!
//! WASM Guard Module Signing: requires Ed25519 signatures on
//! `.wasm` guard binaries. This module provides:
//!
//! - `chio guard sign <wasm> --key <seed-file>` -- produce a `.wasm.sig` sidecar
//!   alongside the given WASM file.
//! - `chio guard verify <wasm>` -- verify the sidecar signature for the guard
//!   (returns exit code 0 on success, 1 on any failure).
//!
//! The signing key is loaded from a hex-encoded 32-byte seed file, matching
//! the `.chio-authority-seed` convention used elsewhere in the CLI.
//!
//! See `docs/protocols/STRUCTURAL-SECURITY-FIXES.md` section 4 for the design.

pub mod sign;
