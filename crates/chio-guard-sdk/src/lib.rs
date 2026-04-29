//! Guest-side SDK for writing Chio WASM guards.
//!
//! This SDK targets the `chio:guard@0.2.0` WIT world.
//!
//! This crate is the primary dependency for guard authors. It provides:
//!
//! - **Types** ([`types`]): `GuardRequest`, `GuardVerdict`, `GuestDenyResponse`
//!   with serde annotations matching the host ABI exactly.
//! - **Host bindings** ([`host`]): safe wrappers for `chio.log`, `chio.get_config`,
//!   `chio.get_time_unix_secs`, and `chio:guard/host.fetch-blob` host imports,
//!   plus the `policy-context.bundle-handle` resource wrapper.
//! - **ABI glue** ([`glue`]): `read_request` to deserialize from linear memory,
//!   `encode_verdict` to produce the ABI return code, and the `chio_deny_reason`
//!   export for structured deny reasons.
//! - **Allocator** ([`alloc`]): `chio_alloc`/`chio_free` exports that the host
//!   runtime probes for dynamic memory allocation in guest linear memory.
//!
//! The crate compiles to `wasm32-unknown-unknown` for production guards. On
//! native targets it compiles with no-op fallbacks for host imports, allowing
//! `cargo test` to run without a WASM runtime.
//!
//! The `#[chio_guard]` proc macro (Phase 383) will generate the `evaluate`
//! export automatically. Until then, guard authors wire the pieces together
//! manually.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use chio_guard_sdk::prelude::*;
//!
//! fn evaluate(req: GuardRequest) -> GuardVerdict {
//!     if req.tool_name == "dangerous_tool" {
//!         GuardVerdict::deny("tool is blocked by policy")
//!     } else {
//!         GuardVerdict::allow()
//!     }
//! }
//! ```

pub mod alloc;
pub mod glue;
pub mod host;
pub mod types;

// Top-level re-exports for convenience.
pub use glue::{encode_verdict, read_request};
pub use host::{fetch_blob, get_config, get_time, log, log_level, PolicyContext};
pub use types::{GuardRequest, GuardVerdict, GuestDenyResponse, VERDICT_ALLOW, VERDICT_DENY};

/// Prelude module re-exporting the complete guard-author API.
///
/// Import with `use chio_guard_sdk::prelude::*;` to get all types, host
/// bindings, and glue functions needed to write a guard.
pub mod prelude {
    pub use crate::glue::{encode_verdict, read_request};
    pub use crate::host::{fetch_blob, get_config, get_time, log, log_level, PolicyContext};
    pub use crate::types::{GuardRequest, GuardVerdict, VERDICT_ALLOW, VERDICT_DENY};
}
