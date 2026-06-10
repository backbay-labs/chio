//! Shared provider capture fixture shape.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Current NDJSON capture schema consumed by the replay harness.
pub const CAPTURE_SCHEMA: &str = "chio-provider-conformance.capture.v1";

/// Provider fixture root directory.
pub fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Return one provider's fixture directory.
pub fn provider_fixture_dir(provider: &str) -> PathBuf {
    fixture_root().join(provider)
}

/// Return one provider scenario fixture path.
pub fn provider_fixture_path(provider: &str, scenario: &str) -> PathBuf {
    provider_fixture_dir(provider).join(format!("{scenario}.ndjson"))
}

/// Direction of one provider capture record.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CaptureDirection {
    /// Request sent to the upstream provider.
    UpstreamRequest,
    /// Non-streaming response returned by the upstream provider.
    UpstreamResponse,
    /// Streaming event returned by the upstream provider.
    UpstreamEvent,
    /// Verdict returned by the Chio kernel.
    KernelVerdict,
}

/// Captured kernel verdict kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapturedVerdictKind {
    /// The tool invocation was allowed.
    Allow,
    /// The tool invocation was denied.
    Deny,
}

/// One line in a provider conformance NDJSON fixture.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureRecord {
    /// Event timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    /// Capture schema marker.
    pub schema: String,
    /// Scenario id embedded in every line.
    pub fixture_id: String,
    /// Fixture family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Provider API snapshot or version pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_snapshot: Option<String>,
    /// Record direction.
    pub direction: CaptureDirection,
    /// Provider namespace.
    pub provider: String,
    /// Provider invocation id for verdict records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,
    /// Captured verdict kind for kernel verdict records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<CapturedVerdictKind>,
    /// Receipt id for kernel verdict records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Provider-native or Chio-normalized payload.
    #[serde(default)]
    pub payload: Value,
}
