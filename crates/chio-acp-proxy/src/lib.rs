//! # chio-acp-proxy
//!
//! Security proxy for the Agent Client Protocol (ACP). Sits between an
//! editor/IDE client and an ACP coding agent, intercepting JSON-RPC
//! messages to enforce Chio capability-based access control.
//!
//! The proxy:
//!
//! 1. Spawns the ACP agent as a subprocess with stdio transport.
//! 2. Forwards JSON-RPC messages bidirectionally (client <-> agent).
//! 3. Intercepts `session/request_permission` to enforce capability tokens.
//! 4. Intercepts `fs/read_text_file` and `fs/write_text_file` to validate
//!    path-scoped capabilities.
//! 5. Intercepts `terminal/create` to run command guards.
//! 6. Generates unsigned audit entries for all `tool_call` events observed
//!    in `session/update` notifications. These can be promoted to signed
//!    Chio receipts by a downstream component with key material.

use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "otel")]
pub mod otel;

// ---------- source files (include! pattern) ----------

include!("protocol.rs");
include!("config.rs");
include!("fs_guard.rs");
include!("terminal_guard.rs");
include!("permission.rs");
include!("receipt.rs");
include!("attestation.rs");
include!("kernel_signer.rs");
include!("kernel_checker.rs");
include!("compliance.rs");
include!("telemetry.rs");
include!("interceptor.rs");
include!("transport.rs");
include!("proxy.rs");
include!("tests.rs");

// ---------- error type ----------

/// Errors produced by the ACP proxy.
#[derive(Debug, thiserror::Error)]
pub enum AcpProxyError {
    /// A JSON-RPC protocol-level error (malformed message, bad params).
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Access was denied by a guard or policy check.
    #[error("access denied: {0}")]
    AccessDenied(String),

    /// A path traversal attempt was detected.
    #[error("path traversal detected: {0}")]
    PathTraversal(String),

    /// A transport-level error (process spawn, pipe I/O).
    #[error("transport error: {0}")]
    Transport(String),
}
