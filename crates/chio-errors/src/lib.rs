//! Typed Chio error codes and diagnostics.
//!
//! Defines the canonical error `Code`/`Domain`/`Severity` taxonomy, the
//! `ChioError` diagnostic type, lookups over the generated error-code table, and
//! a JSON-RPC bridge for surfacing errors on the wire.

#![forbid(unsafe_code)]

pub mod _generated;
mod code;
mod diagnostic;
mod domain;
pub mod jsonrpc_bridge;
mod severity;

pub use _generated::error_codes::{
    lookup_error_code, lookup_jsonrpc_code, lookup_string_code, lookup_string_code_matches,
    ErrorCodeSpec, ERROR_CODES,
};
pub use code::Code;
pub use diagnostic::{diagnostic, error, ChioError, Diagnostic};
pub use domain::{Domain, UnknownDomain};
pub use severity::{Severity, UnknownSeverity};

pub type Result<T> = std::result::Result<T, ChioError>;
