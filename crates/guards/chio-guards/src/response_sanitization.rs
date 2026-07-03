//! Response sanitization guard: scans tool results for secrets, PII/PHI,
//! and other sensitive data, then redacts them before the agent sees them.
//!
//! This module exposes two layered APIs:
//!
//! - A simple, backwards-compatible [`ResponseSanitizationGuard`] that uses a
//!   small fixed pattern set and Block/Redact binary actions.
//! - A full-featured [`OutputSanitizer`] with secret detectors, configurable
//!   allowlist/denylist, deterministic overlap resolution, and multiple
//!   redaction strategies.
//!
//! The guard fails closed: if pattern compilation fails or an internal error
//! occurs, the response is blocked.

mod detectors;
mod formatting;
mod overlap;
mod sanitizer;
mod simple;
mod types;
mod validators;
mod vault;

pub use sanitizer::OutputSanitizer;
pub use simple::{
    build_pattern, ResponseSanitizationGuard, SanitizationAction, ScanResult, SensitivePattern,
    SensitivityLevel,
};
pub use types::{
    AllowlistConfig, CategoryConfig, DenylistConfig, EntropyConfig, OutputSanitizerConfig,
    OutputSanitizerConfigError, ProcessingStats, Redaction, RedactionStrategy, SanitizationResult,
    SanitizedValue, SensitiveCategory, SensitiveDataFinding, Span,
};
pub use vault::TokenVault;

#[cfg(test)]
mod tests;
