use serde::{Deserialize, Serialize};

/// Trust level of a receipt's authorization, recording HOW the Kernel
/// participated in the evaluation. Captured per-receipt so downstream
/// consumers (audit, regulatory, dashboards) can reason about the strength
/// of mediation that produced each authorization.
///
/// See `docs/protocols/STRUCTURAL-SECURITY-FIXES.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Tool invocation was synchronously mediated by the kernel (the
    /// strongest form: kernel observed the call inline and authorized it).
    /// This is the default and the safest baseline.
    #[default]
    Mediated,
    /// Authorization happened inline in the agent process (e.g. a
    /// long-running orchestrator embedded the kernel via FFI). The kernel
    /// observed the call but did not synchronously mediate it through a
    /// separate trust boundary.
    Verified,
    /// Authorization was advisory only -- the kernel evaluated but the
    /// caller may have proceeded regardless. Used for shadow-mode
    /// integrations and observability-only deployments.
    Advisory,
}

impl TrustLevel {
    /// Return the canonical snake_case string for this trust level.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Mediated => "mediated",
            Self::Verified => "verified",
            Self::Advisory => "advisory",
        }
    }
}

/// Semantic class of a signed receipt in the v1 receipt model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptKind {
    #[default]
    MediatedDecision,
    TraceObservation,
    AdvisoryEvaluation,
}

impl ReceiptKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MediatedDecision => "mediated_decision",
            Self::TraceObservation => "trace_observation",
            Self::AdvisoryEvaluation => "advisory_evaluation",
        }
    }
}

/// Runtime boundary class for what Chio can enforce on this receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryClass {
    #[default]
    Prevent,
    DetectOnly,
    AdvisoryOnly,
    CannotSee,
}

impl BoundaryClass {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prevent => "prevent",
            Self::DetectOnly => "detect_only",
            Self::AdvisoryOnly => "advisory_only",
            Self::CannotSee => "cannot_see",
        }
    }
}

/// Outcome for non-mediated observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationOutcome {
    Observed,
    Evaluated,
    Dropped,
}

impl ObservationOutcome {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Evaluated => "evaluated",
            Self::Dropped => "dropped",
        }
    }
}

/// Where the tool effect was executed relative to Chio.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ToolOrigin {
    #[default]
    CallerExecuted,
    HostExecutedProviderReported,
    HostExecutedUnmediated,
}

impl ToolOrigin {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallerExecuted => "caller_executed",
            Self::HostExecutedProviderReported => "host_executed_provider_reported",
            Self::HostExecutedUnmediated => "host_executed_unmediated",
        }
    }
}

/// Redaction mode applied to signed or exported receipt details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    #[default]
    None,
    Summary,
    Redacted,
}

impl RedactionMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Summary => "summary",
            Self::Redacted => "redacted",
        }
    }
}
