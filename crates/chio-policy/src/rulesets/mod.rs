//! Built-in HushSpec rulesets embedded at compile time.
//!
//! Each ruleset is a YAML document shipped as a `&'static str` via
//! `include_str!()`. The rulesets provide curated starting points operators
//! can extend from (e.g. `extends: chio:strict`) without shipping YAML files
//! alongside their deployment.
//!
//! The set provides curated base rulesets so operators can adopt a sensible
//! starting policy without authoring one from scratch.

use crate::compiler::{compile_policy, CompileError, CompiledPolicy};
use crate::models::HushSpec;

// ---------------------------------------------------------------------------
// Embedded YAML blobs
// ---------------------------------------------------------------------------

/// **default** -- Balanced security for general-purpose AI agent execution.
///
/// Blocks access to SSH keys, cloud credentials, environment files, and
/// system credential stores; restricts egress to AI-provider, source-host,
/// and package-registry domains; redacts common secret patterns; and gates
/// destructive tool calls behind user confirmation. A good starting point
/// for most deployments.
const DEFAULT_YAML: &str = include_str!("default.yaml");

/// **strict** -- Maximum-security ruleset with minimal permissions.
///
/// Uses an allow-only egress default (no outbound hosts permitted), denies
/// all tool calls except read-only primitives, enforces patch-integrity
/// balance, and expands the secret-pattern set to include Anthropic, NPM,
/// and Slack tokens. Intended for production or regulated environments
/// where fail-closed is non-negotiable.
const STRICT_YAML: &str = include_str!("strict.yaml");

/// **permissive** -- Relaxed rules for development environments only.
///
/// Opens egress to all hosts and loosens patch-integrity limits to ten
/// thousand additions. Explicitly not for production; this ruleset exists
/// so developers can iterate locally without tripping guards that belong in
/// deployed environments.
const PERMISSIVE_YAML: &str = include_str!("permissive.yaml");

/// **ai-agent** -- Security rules optimized for AI coding assistants.
///
/// Extends the default posture with additional AI-provider egress targets
/// (Together, Fireworks, GitLab, Bitbucket), carves out `.env.example` /
/// `.env.template` exceptions so templates can be read, and layers shell
/// command pattern bans on top of tool-level blocks. Larger
/// `max_args_size` (2 MiB) accommodates realistic coding-tool payloads.
const AI_AGENT_YAML: &str = include_str!("ai-agent.yaml");

/// **cicd** -- Security rules for CI/CD pipelines.
///
/// Restricts egress to package registries, container registries, and build
/// tool hosts (npm, PyPI, crates.io, Docker Hub, GHCR, Maven Central,
/// etc.), blocks destructive deploy tools, and allows only the minimum set
/// of filesystem and build primitives. Tuned for automated pipeline
/// execution where no interactive user is present.
const CICD_YAML: &str = include_str!("cicd.yaml");

/// **remote-desktop** -- Controls for remote-desktop and computer-use
/// agents.
///
/// Enables the `computer_use`, `remote_desktop_channels`, and
/// `input_injection` rule blocks with conservative defaults: audio allowed,
/// clipboard and file transfer disabled, drive mapping disabled, keyboard
/// and mouse injection permitted but no post-condition probe required.
/// Intended as the baseline for RDP-style agent sessions.
const REMOTE_DESKTOP_YAML: &str = include_str!("remote-desktop.yaml");

/// **panic** -- Emergency deny-all policy, activated by panic mode.
///
/// Forbids every path, blocks every egress target, forbids every shell
/// command, denies every tool call, and puts computer-use into
/// fail-closed mode. Loaded by the kernel when an operator trips the
/// emergency kill switch; the agent retains no usable capabilities while
/// this ruleset is active.
const PANIC_YAML: &str = include_str!("panic.yaml");

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// The catalogue of built-in rulesets as `(name, yaml)` pairs.
///
/// Names match the stem of the file on disk (`default`, `strict`, etc.),
/// with the sole exception of `panic`, whose embedded `name:` field uses the
/// reserved identifier `__hushspec_panic__`. Callers should prefer
/// [`load_builtin`] to obtain a validated [`CompiledPolicy`] directly.
pub const BUILTIN_RULESETS: &[(&str, &str)] = &[
    ("default", DEFAULT_YAML),
    ("strict", STRICT_YAML),
    ("permissive", PERMISSIVE_YAML),
    ("ai-agent", AI_AGENT_YAML),
    ("cicd", CICD_YAML),
    ("remote-desktop", REMOTE_DESKTOP_YAML),
    ("panic", PANIC_YAML),
];

/// Errors that can arise when resolving a built-in ruleset.
#[derive(Debug, thiserror::Error)]
pub enum RulesetError {
    #[error("unknown built-in ruleset: {0}")]
    Unknown(String),
    #[error("failed to parse built-in ruleset {name}: {source}")]
    Parse {
        name: String,
        #[source]
        source: serde_yml::Error,
    },
    #[error("failed to compile built-in ruleset {name}: {source}")]
    Compile {
        name: String,
        #[source]
        source: CompileError,
    },
}

impl From<RulesetError> for CompileError {
    fn from(value: RulesetError) -> Self {
        CompileError::Invalid(value.to_string())
    }
}

/// Return the embedded YAML source for a built-in ruleset, if one exists.
///
/// Accepts both the raw name (e.g. `"default"`) and the `chio:` or `hushspec:`
/// prefixed form (`"chio:default"`, `"hushspec:default"`).
pub fn builtin_yaml(name: &str) -> Option<&'static str> {
    let key = name
        .strip_prefix("chio:")
        .or_else(|| name.strip_prefix("hushspec:"))
        .unwrap_or(name);
    BUILTIN_RULESETS
        .iter()
        .find(|(n, _)| *n == key)
        .map(|(_, yaml)| *yaml)
}

/// Load and compile a built-in ruleset by name.
///
/// This is a shorthand for
/// `compile_policy(&HushSpec::parse(builtin_yaml(name)?)?)` with helpful
/// error wrapping. Returns [`RulesetError::Unknown`] if `name` is not
/// recognised, [`RulesetError::Parse`] if the embedded YAML fails to parse
/// (should not happen in shipped builds), and [`RulesetError::Compile`] if
/// the HushSpec-to-guard compilation fails.
pub fn load_builtin(name: &str) -> Result<CompiledPolicy, RulesetError> {
    let yaml = builtin_yaml(name).ok_or_else(|| RulesetError::Unknown(name.to_string()))?;
    let spec = HushSpec::parse(yaml).map_err(|source| RulesetError::Parse {
        name: name.to_string(),
        source,
    })?;
    compile_policy(&spec).map_err(|source| RulesetError::Compile {
        name: name.to_string(),
        source,
    })
}

/// Return the list of built-in ruleset names in registration order.
pub fn list_builtin_names() -> impl Iterator<Item = &'static str> {
    BUILTIN_RULESETS.iter().map(|(name, _)| *name)
}
