//! Probe trait and report types shared by every `chio doctor` probe.
//!
//! A probe is a side-effect-light check that reports a
//! single `ProbeReport`. Reports carry a `urn:chio:error:*` code (always
//! anchored in `spec/errors/registry.yaml`), a severity, a message, and
//! optional context. The doctor runner aggregates reports and derives a
//! process exit code from the worst observed severity.

use std::fmt;

use serde::Serialize;

/// Severity of a single probe outcome. Mirrors the registry severity enum
/// so probe reports can be cross-referenced against the registry without
/// translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeSeverity {
    /// Probe passed. No remediation required.
    Ok,
    /// Probe surfaced an informational note. Exit code stays zero.
    Info,
    /// Probe surfaced a non-blocking warning. Exit code stays zero unless
    /// the runner is configured to treat warnings as errors.
    Warning,
    /// Probe failed. Exit code becomes non-zero.
    Error,
    /// Probe encountered a fatal condition. Exit code becomes non-zero
    /// and subsequent probes may be skipped at the runner's discretion.
    Fatal,
}

impl ProbeSeverity {
    /// Severity is "failing" when it should drive a non-zero exit.
    #[must_use]
    pub const fn is_failing(self) -> bool {
        matches!(self, Self::Error | Self::Fatal)
    }
}

impl fmt::Display for ProbeSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Ok => "ok",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        };
        f.write_str(label)
    }
}

/// Single line of context attached to a probe report.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeContext {
    pub key: String,
    pub value: String,
}

impl ProbeContext {
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Report emitted by a single probe.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeReport {
    /// Stable probe identifier, e.g. `toolchain`, `oci`, `cosign`.
    pub probe: &'static str,
    /// Severity of this run.
    pub severity: ProbeSeverity,
    /// Registry URN code anchoring the diagnostic.
    pub code: &'static str,
    /// Human-readable message.
    pub message: String,
    /// Optional remediation guidance pulled from the registry.
    pub help: Option<String>,
    /// Structured context lines.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<ProbeContext>,
    /// Set to `true` when `--fix` ran an idempotent repair.
    pub repaired: bool,
}

impl ProbeReport {
    /// Construct a passing report.
    pub fn ok(probe: &'static str, message: impl Into<String>) -> Self {
        Self {
            probe,
            severity: ProbeSeverity::Ok,
            code: "urn:chio:error:cli:other",
            message: message.into(),
            help: None,
            context: Vec::new(),
            repaired: false,
        }
    }

    /// Construct a failing report keyed to a registry code.
    pub fn fail(
        probe: &'static str,
        severity: ProbeSeverity,
        code: &'static str,
        message: impl Into<String>,
    ) -> Self {
        Self {
            probe,
            severity,
            code,
            message: message.into(),
            help: None,
            context: Vec::new(),
            repaired: false,
        }
    }

    #[must_use]
    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.push(ProbeContext::new(key, value));
        self
    }

    #[must_use]
    pub fn mark_repaired(mut self) -> Self {
        self.repaired = true;
        self
    }
}

/// Configuration shared by every probe. Probes consume this read-only.
#[derive(Debug, Clone, Default)]
pub struct ProbeConfig {
    /// When set, probes that would otherwise reach the network skip and
    /// return an info-level report. Wired to `CHIO_DOCTOR_SKIP_NETWORK`
    /// at runner construction time.
    pub skip_network: bool,
    /// When set, probes may run idempotent repairs. The runner enforces
    /// the "no destructive action" rule by limiting the repair surface.
    pub fix_enabled: bool,
    /// Optional working directory override (default: cwd). Used by tests
    /// to run probes against fixture directories.
    pub workdir: Option<std::path::PathBuf>,
}

/// Trait implemented by every doctor probe.
///
/// Probes return a single `ProbeReport`. They must not panic; any error
/// that bubbles out should be surfaced as a `ProbeReport` with an
/// appropriate registry code.
pub trait Probe {
    /// Stable probe identifier. Must be lowercase ASCII, no spaces.
    fn name(&self) -> &'static str;

    /// Execute the probe.
    fn run(&self, config: &ProbeConfig) -> ProbeReport;
}
