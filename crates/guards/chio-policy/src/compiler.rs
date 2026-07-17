//! HushSpec-to-Chio compiler.
//!
//! This is the key bridge between HushSpec policies and Chio's guard pipeline.
//! It translates HushSpec rule blocks into configured Chio guards and builds
//! a default capability scope from the policy's tool_access rules.
//!
//! # Guard coverage
//!
//! The compiler materializes 12 distinct guard types from a HushSpec
//! document. The first seven are driven directly by the `rules` section; the
//! remaining five are driven either by the `extensions.detection`
//! sub-section or by auxiliary semantics layered on top of existing rule
//! blocks (SSRF protection on egress, per-agent velocity from origin
//! budgets).
//!
//! | # | Guard | Triggered by |
//! |---|----------------------------|----------------------------------------|
//! | 1 | `ForbiddenPathGuard`       | `rules.forbidden_paths` |
//! | 2 | `ShellCommandGuard`        | `rules.shell_commands` |
//! | 3 | `EgressAllowlistGuard`     | `rules.egress` |
//! | 4 | `McpToolGuard`             | `rules.tool_access` |
//! | 5 | `SecretLeakGuard`          | `rules.secret_patterns` |
//! | 6 | `PatchIntegrityGuard`      | `rules.patch_integrity` |
//! | 7 | `PathAllowlistGuard`       | `rules.path_allowlist` |
//! | 8 | `PromptInjectionGuard`     | `extensions.detection.prompt_injection`|
//! | 9 | `JailbreakGuard`           | `extensions.detection.jailbreak` |
//! |10 | `EmbeddingAnomalyGuard`         | `extensions.detection.threat_intel` |
//! |11 | `InternalNetworkGuard`     | `rules.egress` (SSRF companion) |
//! |12 | `AgentVelocityGuard`       | `extensions.origins.profiles[].budgets` |

mod budgets;
mod detection;
mod patterns;
mod rules;
mod scope;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

use std::path::Path;

use crate::models::HushSpec;

use chio_core::capability::scope::ChioScope;
use chio_guards::{GuardPipeline, PostInvocationPipeline};
use chio_kernel::MemoryBudgetConfig;

use budgets::compile_budget_guards;
use detection::compile_detection_guards;
use rules::compile_rule_guards;
use scope::compile_scope;

/// Errors that can occur during policy compilation.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// The result of compiling a HushSpec policy into Chio primitives.
pub struct CompiledPolicy {
    /// A guard pipeline configured from the policy's rule blocks.
    pub guards: GuardPipeline,
    /// A post-invocation pipeline configured from the policy's rule blocks.
    pub post_invocation: PostInvocationPipeline,
    /// A default capability scope derived from the policy's tool_access rules.
    pub default_scope: ChioScope,
    /// Ordered list of guard names emitted by compilation.
    ///
    /// The compiler is required to emit a
    /// `Vec<Box<dyn Guard>>` containing all 12 guard types; because
    /// [`GuardPipeline`] does not publicly expose its contained guards,
    /// this sidecar records the `Guard::name()` of each guard added to the
    /// pipeline in insertion order. Deduplicated, this is the set of
    /// concrete guard types that compiled successfully.
    pub guard_names: Vec<String>,
}

/// Compile a HushSpec policy into a Chio guard pipeline and default scope.
///
/// This maps HushSpec rule blocks and detection-extension blocks to Chio
/// guard configurations. See the module-level documentation for the full
/// mapping table. Missing sections compile to an empty pipeline; no error
/// is raised for policies that do not exercise every guard type.
///
/// Uses the DEFAULT process memory budget for bounded-collection caps (e.g. the
/// velocity guard's bucket cap). Deployments that lower the process memory budget
/// should use [`compile_policy_with_memory_budget`] so the configured caps reach
/// the compiled guards.
pub fn compile_policy(policy: &HushSpec) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_source(policy, None)
}

/// Compile a HushSpec policy with an optional source path used to resolve
/// relative auxiliary assets referenced by the policy. Uses the DEFAULT process
/// memory budget; see [`compile_policy_with_memory_budget`].
pub fn compile_policy_with_source(
    policy: &HushSpec,
    source_path: Option<&Path>,
) -> Result<CompiledPolicy, CompileError> {
    compile_policy_with_memory_budget(policy, source_path, &MemoryBudgetConfig::defaults())
}

/// Compile a HushSpec policy threading a CONFIGURED process memory budget into
/// the bounded-collection guards. Lowering `velocity_bucket_cap` on `budget`
/// tightens the compiled velocity guard's bucket cap instead of it silently
/// using the compiled-in default.
pub fn compile_policy_with_memory_budget(
    policy: &HushSpec,
    source_path: Option<&Path>,
    budget: &MemoryBudgetConfig,
) -> Result<CompiledPolicy, CompileError> {
    ensure_compilable_policy(policy)?;

    let mut builder = PipelineBuilder::new();
    let mut post_invocation = PostInvocationPipeline::new();
    let source_dir = source_path.and_then(|path| path.parent());
    compile_rule_guards(policy, &mut builder, &mut post_invocation, budget)?;
    compile_detection_guards(policy, &mut builder, source_dir)?;
    compile_budget_guards(policy, &mut builder, budget)?;
    let default_scope = compile_scope(policy)?;
    let (guards, guard_names) = builder.finish();
    Ok(CompiledPolicy {
        guards,
        post_invocation,
        default_scope,
        guard_names,
    })
}

fn ensure_compilable_policy(policy: &HushSpec) -> Result<(), CompileError> {
    let validation = crate::validate::validate(policy);
    if validation.is_valid() {
        return Ok(());
    }

    let messages = validation
        .errors
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ");
    Err(CompileError::Invalid(format!(
        "HushSpec validation failed: {messages}"
    )))
}

// ---------------------------------------------------------------------------
// Pipeline builder
// ---------------------------------------------------------------------------

/// Helper that keeps the [`GuardPipeline`] and the parallel `guard_names`
/// list in lockstep so callers cannot forget to record a guard's name when
/// they add it.
struct PipelineBuilder {
    pipeline: GuardPipeline,
    names: Vec<String>,
}

impl PipelineBuilder {
    fn new() -> Self {
        Self {
            pipeline: GuardPipeline::new(),
            names: Vec::new(),
        }
    }

    fn add<G: chio_kernel::Guard + 'static>(&mut self, guard: G) {
        self.names.push(guard.name().to_string());
        self.pipeline.add(Box::new(guard));
    }

    fn finish(self) -> (GuardPipeline, Vec<String>) {
        (self.pipeline, self.names)
    }
}
