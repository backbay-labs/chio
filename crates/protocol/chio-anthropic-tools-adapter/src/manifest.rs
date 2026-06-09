//! Manifest allowlist gate for Anthropic server tools.
//!
//! Server tools (`computer_use_*`, `bash_*`, and `text_editor_*`) are
//! Anthropic-hosted beta surfaces. They are only allowed when the adapter is
//! compiled with `computer-use` and the Chio tool manifest explicitly lists
//! the matching stable entry in `server_tools`.

use chio_manifest::{validate_manifest, ManifestError, ServerTool, ToolManifest};
use chio_tool_call_fabric::ProviderError;

/// Runtime copy of the manifest server-tool allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnthropicServerToolGate {
    allowed: Vec<ServerTool>,
}

impl AnthropicServerToolGate {
    /// Build a fail-closed gate with no server tools allowed.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Build a gate from a validated Chio tool manifest.
    pub fn from_manifest(manifest: &ToolManifest) -> Result<Self, ManifestError> {
        validate_manifest(manifest)?;
        Ok(Self {
            allowed: manifest.server_tools.clone(),
        })
    }

    /// Borrow the stable manifest entries allowed by this gate.
    pub fn allowed(&self) -> &[ServerTool] {
        &self.allowed
    }

    /// Enforce the allowlist for one Anthropic tool-use name.
    ///
    /// Regular custom tools pass through. Known Anthropic server-tool names
    /// fail closed unless their stable manifest entry is present.
    pub fn ensure_tool_allowed(&self, tool_name: &str) -> Result<(), ProviderError> {
        let Some(server_tool) = ServerTool::from_anthropic_wire_name(tool_name) else {
            return Ok(());
        };

        if self.allowed.contains(&server_tool) {
            return Ok(());
        }

        Err(ProviderError::Malformed(format!(
            "Anthropic server tool `{tool_name}` maps to `{}` but manifest server_tools does not allow it",
            server_tool.as_str()
        )))
    }
}
