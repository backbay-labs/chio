//! Security guards for the Chio runtime kernel.
//!
//! This crate provides policy-driven security guards.  Each guard
//! implements `chio_kernel::Guard` and can be registered on the kernel via
//! `kernel.add_guard(...)` or composed into a [`GuardPipeline`].
//!
//! # Implemented guards
//!
//! | Guard | Status | Description |
//! |-------|--------|-------------|
//! | [`ForbiddenPathGuard`] | **Full** | Blocks access to sensitive filesystem paths |
//! | [`ShellCommandGuard`] | **Full** | Blocks dangerous shell commands |
//! | [`EgressAllowlistGuard`] | **Full** | Controls network egress by domain |
//! | [`PathAllowlistGuard`] | **Full** | Allowlist-based path access control |
//! | [`McpToolGuard`] | **Full** | Restricts MCP tool invocations |
//! | [`SecretLeakGuard`] | **Full** | Detects secrets in file writes |
//! | [`PatchIntegrityGuard`] | **Full** | Validates patch safety |
//! | [`InternalNetworkGuard`] | **Full** | Blocks SSRF targeting private/reserved addresses |
//! | [`AgentVelocityGuard`] | **Full** | Per-agent and per-session rate limiting |
//! | [`DataFlowGuard`] | **Full** | Cumulative bytes-read/written limits via session journal |
//! | [`BehavioralSequenceGuard`] | **Full** | Tool ordering policies via session journal |
//! | [`ResponseSanitizationGuard`] | **Full** | PII/PHI pattern detection and redaction |
//! | [`AdvisoryPipeline`] | **Full** | Non-blocking advisory signals with optional promotion |
//! | [`AnomalyAdvisoryGuard`] | **Full** | Flags unusual invocation patterns and delegation depth |
//! | [`DataTransferAdvisoryGuard`] | **Full** | Flags high data transfer volumes |
//! | [`JailbreakGuard`] | **Full** | Multi-layer jailbreak detection (heuristic + statistical + ML) |
//!
//! # Guard pipeline
//!
//! The [`GuardPipeline`] runs guards in sequence, fail-closed.  If any guard
//! denies, the pipeline denies.  Register it on the kernel:
//!
//! ```ignore
//! use chio_guards::GuardPipeline;
//!
//! let pipeline = GuardPipeline::default_pipeline();
//! kernel.add_guard(Box::new(pipeline));
//! ```

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod action;
mod path_normalization;

pub mod external;

pub mod advisory;
pub mod agent_velocity;
pub mod behavioral_profile;
pub mod behavioral_sequence;
pub mod data_flow;
mod egress_allowlist;
mod forbidden_path;
pub mod internal_network;
pub mod jailbreak;
pub mod jailbreak_detector;
pub mod mcp_tool;
pub mod patch_integrity;
pub mod path_allowlist;
mod pipeline;
pub mod post_invocation;
pub mod prompt_injection;
pub mod response_sanitization;
pub mod secret_leak;
mod shell_command;
pub mod text_utils;
pub mod velocity;

// Computer Use Agent (CUA) and EmbeddingAnomaly guards.
pub mod computer_use;
pub mod embedding_anomaly;
pub mod input_injection;
pub mod remote_desktop;

// Code execution, browser automation, content review, and memory
// governance guards.
pub mod browser_automation;
pub mod code_execution;
pub mod content_review;
pub mod memory_governance;

pub use advisory::{
    AdvisoryGuard, AdvisoryPipeline, AdvisorySeverity, AdvisorySignal, AnomalyAdvisoryGuard,
    DataTransferAdvisoryGuard, GuardOutput, PromotionPolicy, PromotionRule,
};
pub use agent_velocity::{AgentVelocityConfig, AgentVelocityGuard};
pub use behavioral_profile::{
    BehavioralMetric, BehavioralProfileConfig, BehavioralProfileGuard, InMemoryReceiptFeed,
    ObservationOutcome, ReceiptFeedSource, DEFAULT_BASELINE_MIN_WINDOWS, DEFAULT_EMA_ALPHA,
    DEFAULT_SIGMA_THRESHOLD, DEFAULT_WINDOW_SECS,
};
pub use behavioral_sequence::{BehavioralSequenceGuard, SequencePolicy};
pub use data_flow::{DataFlowConfig, DataFlowGuard};
pub use egress_allowlist::EgressAllowlistGuard;
pub use forbidden_path::{ForbiddenPathConfigError, ForbiddenPathGuard};
pub use internal_network::InternalNetworkGuard;
pub use jailbreak::{
    JailbreakGuard, JailbreakGuardConfig,
    DEFAULT_FINGERPRINT_CAPACITY as JAILBREAK_DEFAULT_FINGERPRINT_CAPACITY,
};
pub use jailbreak_detector::{
    Detection as JailbreakDetection, DetectorConfig as JailbreakDetectorConfig, JailbreakCategory,
    JailbreakDetector, LayerScores as JailbreakLayerScores, LayerWeights,
    LinearModel as JailbreakLinearModel, Signal as JailbreakSignal,
    StatisticalThresholds as JailbreakStatisticalThresholds,
    DEFAULT_DENY_THRESHOLD as JAILBREAK_DEFAULT_DENY_THRESHOLD,
};
pub use mcp_tool::McpToolGuard;
pub use patch_integrity::PatchIntegrityGuard;
pub use path_allowlist::PathAllowlistGuard;
pub use pipeline::GuardPipeline;
pub use post_invocation::{
    sanitize_json, PipelineOutcome, PostInvocationHook, PostInvocationHookIdentity,
    PostInvocationPipeline, PostInvocationVerdict, SanitizerHook,
};
pub use prompt_injection::{
    Detection as PromptInjectionDetection, PromptInjectionConfig, PromptInjectionGuard,
    Signal as PromptInjectionSignal,
};
pub use response_sanitization::{
    AllowlistConfig, CategoryConfig, DenylistConfig, EntropyConfig, OutputSanitizer,
    OutputSanitizerConfig, OutputSanitizerConfigError, ProcessingStats, Redaction,
    RedactionStrategy, ResponseSanitizationGuard, SanitizationAction, SanitizationResult,
    SanitizedValue, ScanResult, SensitiveCategory, SensitiveDataFinding, SensitivityLevel, Span,
    TokenVault,
};
pub use secret_leak::SecretLeakGuard;
pub use shell_command::{ShellCommandConfigError, ShellCommandGuard};
pub use velocity::VelocityGuard;

pub use action::{extract_action, extract_action_checked, MalformedAction, ToolAction};

pub use external::{
    AsyncGuardAdapter, AsyncGuardAdapterBuilder, AsyncGuardAdapterConfig, CircuitBreaker,
    CircuitBreakerConfig, CircuitOpenVerdict, CircuitState, ExternalGuard, ExternalGuardError,
    GuardCallContext, RateLimitedVerdict, RetryConfig, TokenBucket, TtlCache,
};

fn revalidate_non_consuming_guard(
    guard: &(impl chio_kernel::Guard + ?Sized),
    ctx: &chio_kernel::GuardContext<'_>,
) -> Result<(), chio_kernel::KernelError> {
    match guard.evaluate(ctx)?.verdict {
        chio_kernel::Verdict::Allow => Ok(()),
        // Admission owns approval adjudication. A pure re-evaluation may still
        // describe the original threshold as pending, but must not turn an
        // already-adjudicated request into a hard denial at dispatch.
        chio_kernel::Verdict::PendingApproval => Ok(()),
        chio_kernel::Verdict::Deny => Err(chio_kernel::KernelError::GuardDenied(
            "guard dispatch revalidation denied".to_string(),
        )),
    }
}

/// Default guard material installed by the control-plane runtime profile.
pub struct RuntimeGuardProfile {
    pub pre_invocation_guards: Vec<Box<dyn chio_kernel::Guard>>,
    pub post_invocation_pipeline: PostInvocationPipeline,
}

/// Build the default Chio runtime guard profile without coupling the kernel to
/// concrete guard implementations.
pub fn default_runtime_guard_profile() -> RuntimeGuardProfile {
    let mut post_invocation_pipeline = PostInvocationPipeline::new();
    post_invocation_pipeline.add(Box::new(SanitizerHook::new()));

    RuntimeGuardProfile {
        pre_invocation_guards: vec![
            Box::new(InternalNetworkGuard::new()),
            Box::new(AgentVelocityGuard::new(AgentVelocityConfig::default())),
            Box::new(AdvisoryPipeline::new(PromotionPolicy::new())),
        ],
        post_invocation_pipeline,
    }
}

// Computer Use Agent (CUA) and EmbeddingAnomaly re-exports.
pub use computer_use::{
    default_allowed_action_types as computer_use_default_allowed_action_types, ComputerUseConfig,
    ComputerUseGuard, EnforcementMode,
};
pub use embedding_anomaly::{
    cosine_similarity as embedding_anomaly_cosine_similarity, extract_embedding, AmbiguousPolicy,
    EmbeddingAnomalyConfig, EmbeddingAnomalyError, EmbeddingAnomalyGuard,
    EmbeddingAnomalyPatternDb, PatternEntry, DEFAULT_AMBIGUITY_BAND, DEFAULT_SIMILARITY_THRESHOLD,
    DEFAULT_TOP_K,
};
pub use input_injection::{
    default_allowed_input_types, InputInjectionCapabilityConfig, InputInjectionCapabilityGuard,
};
pub use remote_desktop::{RemoteDesktopSideChannelConfig, RemoteDesktopSideChannelGuard};

// Code execution, browser automation, content review, and memory
// governance re-exports.
pub use browser_automation::{
    default_allowed_verbs as browser_automation_default_allowed_verbs, BrowserAutomationConfig,
    BrowserAutomationError, BrowserAutomationGuard,
};
pub use code_execution::{
    default_dangerous_modules as code_execution_default_dangerous_modules, CodeExecutionConfig,
    CodeExecutionError, CodeExecutionGuard,
};
pub use content_review::{
    ContentReviewConfig, ContentReviewError, ContentReviewGuard, ContentReviewRules,
};
pub use memory_governance::{MemoryGovernanceConfig, MemoryGovernanceError, MemoryGovernanceGuard};
