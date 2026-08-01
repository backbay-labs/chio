//! HushSpec policy format for the Chio runtime.
//!
//! This crate provides a portable, standards-based policy format for AI agent
//! security rules, integrated with Chio's guard pipeline and capability system.
//!
//! # Key modules
//!
//! - [`models`] -- HushSpec YAML schema types
//! - [`evaluate`] -- Policy evaluation producing allow/warn/deny decisions
//! - [`merge`] -- Policy inheritance via `extends`
//! - [`validate`] -- Schema and semantic validation
//! - [`resolve`] -- `extends` chain resolution from filesystem
//! - [`compiler`] -- **Bridge**: compile HushSpec policies into Chio guards
//! - [`conditions`] -- Conditional rule activation
//! - [`detection`] -- Regex-based content detectors
//! - [`receipt`] -- Decision receipts with timing and hashing
//! - [`rulesets`] -- Built-in HushSpec rulesets embedded at compile time

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod compiler;
pub mod conditions;
pub mod crypto_floor;
pub mod detection;
pub mod evaluate;
pub mod merge;
pub mod models;
pub mod receipt;
mod regex_safety;
pub mod resolve;
pub mod rulesets;
pub mod validate;
pub mod version;
pub mod weights;

pub use compiler::{
    compile_policy, compile_policy_with_approver_directory, compile_policy_with_memory_budget,
    compile_policy_with_source, compile_policy_with_source_and_approver_directory, CompileError,
    CompiledPolicy,
};
pub use conditions::{evaluate_condition, Condition, RuntimeContext};
pub use crypto_floor::{CryptoFloor, CryptoFloorLoadError};
pub use evaluate::{
    activate_panic, deactivate_panic, evaluate, evaluate_with_context, is_panic_active,
    selected_origin_profile_id, Decision, EvaluationAction, EvaluationResult, OriginContext,
    PostureContext, PostureResult,
};
pub use merge::merge;
pub use models::{HushSpec, OriginMatch};
pub use receipt::{evaluate_audited, AuditConfig, DecisionReceipt};
pub use resolve::{resolve_from_path, resolve_with_loader, LoadedSpec, ResolveError};
pub use rulesets::{
    builtin_yaml, list_builtin_names, load_builtin, RulesetError, BUILTIN_RULESETS,
};
pub use validate::{validate, ValidationError, ValidationResult};
pub use version::HUSHSPEC_VERSION;
pub use weights::{WeightsCardConfig, WeightsCardLoadError, WeightsCardRequired};

/// Detect whether a YAML string is a HushSpec document by checking for the
/// `hushspec` top-level key. This enables auto-detection when loading policies.
pub fn is_hushspec_format(yaml: &str) -> bool {
    yaml.lines().any(line_starts_with_hushspec_key)
}

fn line_starts_with_hushspec_key(line: &str) -> bool {
    let Some(rest) = line
        .strip_prefix("hushspec")
        .or_else(|| line.strip_prefix("\"hushspec\""))
        .or_else(|| line.strip_prefix("'hushspec'"))
    else {
        return false;
    };

    rest.trim_start().starts_with(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hushspec_format_detection_requires_a_top_level_mapping_key() {
        assert!(is_hushspec_format("hushspec: \"0.1.0\""));
        assert!(is_hushspec_format("\"hushspec\": \"0.1.0\""));
        assert!(is_hushspec_format("hushspec : \"0.1.0\""));

        assert!(!is_hushspec_format("\"hushspec\"\nname: not-a-policy"));
        assert!(!is_hushspec_format("not_hushspec: true"));
        assert!(!is_hushspec_format("  hushspec: nested"));
    }
}
