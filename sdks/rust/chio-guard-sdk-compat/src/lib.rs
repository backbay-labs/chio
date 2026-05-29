//! Rust compatibility path for the `chio:guard@0.2.0` guest SDK.
//!
//! The canonical workspace crate lives at `crates/chio-guard-sdk`. This path
//! is a compatibility shim that re-exports the same guard author API without
//! changing existing request/verdict call sites.

pub use chio_guard_sdk_workspace::*;
