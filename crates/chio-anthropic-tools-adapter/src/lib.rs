//! Provider-native adapter that mediates Anthropic Messages API tool-use
//! traffic through the Chio kernel. Pinned upstream API version:
//! `anthropic-version: 2023-06-01` (see [`transport::ANTHROPIC_VERSION`]).

#![forbid(unsafe_code)]

pub mod adapter;
pub mod manifest;
pub mod native;
pub mod transport;

use std::sync::Arc;

use chio_tool_call_fabric::ProviderId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use manifest::AnthropicServerToolGate;
pub use native::{ToolResultBlock, ToolUseBlock};
pub use transport::{Transport, ANTHROPIC_VERSION, COMPUTER_USE_BETA};

/// Configuration for the Anthropic Messages adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnthropicAdapterConfig {
    /// Stable identifier for this adapter instance.
    pub server_id: String,
    /// Human-readable name surfaced in logs and the manifest.
    pub server_name: String,
    /// Adapter version string (independent of the upstream API version).
    pub server_version: String,
    /// Hex-encoded Ed25519 public key for receipt provenance.
    pub public_key: String,
    /// Pinned upstream API version, always [`ANTHROPIC_VERSION`].
    pub api_version: String,
    /// Anthropic workspace identifier (populates
    /// [`chio_tool_call_fabric::Principal::AnthropicWorkspace`] on every
    /// emitted [`chio_tool_call_fabric::ProvenanceStamp`]).
    pub workspace_id: String,
}

impl AnthropicAdapterConfig {
    /// Construct a configuration with the API version pinned to
    /// [`ANTHROPIC_VERSION`]. Other fields are passed through verbatim.
    pub fn new(
        server_id: impl Into<String>,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
        public_key: impl Into<String>,
        workspace_id: impl Into<String>,
    ) -> Self {
        Self {
            server_id: server_id.into(),
            server_name: server_name.into(),
            server_version: server_version.into(),
            public_key: public_key.into(),
            api_version: ANTHROPIC_VERSION.to_string(),
            workspace_id: workspace_id.into(),
        }
    }
}

/// Adapter handle.
#[derive(Clone)]
pub struct AnthropicAdapter {
    config: AnthropicAdapterConfig,
    transport: Arc<dyn Transport>,
    server_tool_gate: AnthropicServerToolGate,
}

impl AnthropicAdapter {
    /// Build a new adapter from a config and a transport handle.
    pub fn new(config: AnthropicAdapterConfig, transport: Arc<dyn Transport>) -> Self {
        Self {
            config,
            transport,
            server_tool_gate: AnthropicServerToolGate::deny_all(),
        }
    }

    /// Build a new adapter whose server-tool gate is sourced from a validated
    /// Chio tool manifest.
    pub fn new_with_manifest(
        config: AnthropicAdapterConfig,
        transport: Arc<dyn Transport>,
        manifest: &chio_manifest::ToolManifest,
    ) -> Result<Self, AnthropicAdapterError> {
        Ok(Self {
            config,
            transport,
            server_tool_gate: AnthropicServerToolGate::from_manifest(manifest)?,
        })
    }

    /// Provider identifier for this adapter.
    pub fn provider(&self) -> ProviderId {
        ProviderId::Anthropic
    }

    /// Pinned upstream API version (always [`ANTHROPIC_VERSION`]).
    pub fn api_version(&self) -> &str {
        &self.config.api_version
    }

    /// Borrow the configuration.
    pub fn config(&self) -> &AnthropicAdapterConfig {
        &self.config
    }

    /// Borrow the transport handle.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Borrow the manifest-derived server-tool gate.
    pub fn server_tool_gate(&self) -> &AnthropicServerToolGate {
        &self.server_tool_gate
    }

    /// Whether this build was compiled with the `computer-use` cargo
    /// feature. Surfaced here so callers can refuse to start a session that
    /// requests server tools without the feature flag set, without having
    /// to thread `cfg` macros through their own code.
    pub fn computer_use_enabled() -> bool {
        cfg!(feature = "computer-use")
    }
}

/// Adapter-local error taxonomy.
#[derive(Debug, Error)]
pub enum AnthropicAdapterError {
    /// Placeholder for call sites not yet implemented.
    #[error("anthropic adapter call site is not implemented: {0}")]
    NotImplemented(&'static str),
    /// Bubbled up from the transport layer.
    #[error(transparent)]
    Transport(#[from] transport::TransportError),
    /// The `computer-use` cargo feature is required but not enabled.
    #[error("server-tool surface requires the `computer-use` cargo feature")]
    ComputerUseFeatureDisabled,
    /// Raised when the manifest used to build the server-tool gate is invalid.
    #[error(transparent)]
    Manifest(#[from] chio_manifest::ManifestError),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn config() -> AnthropicAdapterConfig {
        AnthropicAdapterConfig::new(
            "anthropic-1",
            "Anthropic Messages",
            "0.1.0",
            "deadbeef",
            "wks_test",
        )
    }

    #[test]
    fn config_pins_api_version() {
        let cfg = config();
        assert_eq!(cfg.api_version, ANTHROPIC_VERSION);
        assert_eq!(cfg.api_version, "2023-06-01");
    }

    #[test]
    fn adapter_reports_provider_and_pin() {
        let cfg = config();
        let transport = transport::MockTransport::new();
        let adapter = AnthropicAdapter::new(cfg, Arc::new(transport));
        assert_eq!(adapter.provider(), ProviderId::Anthropic);
        assert_eq!(adapter.api_version(), "2023-06-01");
    }

    #[test]
    fn config_round_trips_canonical_json() {
        let cfg = config();
        let bytes = serde_json::to_vec(&cfg).unwrap();
        let back: AnthropicAdapterConfig = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn error_display_is_em_dash_free() {
        let cases = vec![
            AnthropicAdapterError::NotImplemented("messages.create lift"),
            AnthropicAdapterError::ComputerUseFeatureDisabled,
        ];
        for err in cases {
            let s = err.to_string();
            assert!(!s.contains('\u{2014}'), "em dash in {s}");
        }
    }

    #[test]
    fn computer_use_flag_matches_cfg() {
        // Whatever the cargo feature is set to in this build, the helper
        // must reflect it. Both branches are covered: the gate-check builds
        // the crate with and without `--features computer-use`.
        assert_eq!(
            AnthropicAdapter::computer_use_enabled(),
            cfg!(feature = "computer-use")
        );
    }
}
