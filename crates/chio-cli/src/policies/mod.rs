//! Bundled policy presets for `chio mcp serve --preset <name>`.
//!
//! Each preset is a YAML document embedded at compile time via
//! [`include_str!`]. The string is materialized to a temp file when
//! requested so that the existing `load_policy` plumbing (which takes
//! a `&Path`) can be reused verbatim -- this keeps the policy hash,
//! guard pipeline, and receipt store wiring identical to a normal
//! `--policy path.yaml` run.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::CliError;

/// Raw YAML of the bundled `code-agent` preset.
///
/// Kept byte-identical with
/// `sdks/python/chio-code-agent/src/chio_code_agent/default_policy.yaml`
/// so the Python SDK and the Rust CLI evaluate the same rules.
pub const CODE_AGENT_POLICY_YAML: &str = include_str!("code_agent.yaml");

/// Supported MCP preset names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpPreset {
    /// `code-agent`: defaults for coding agents (Claude Code, Cursor,
    /// MCP-based file/shell/git tool servers). Fails closed.
    CodeAgent,
}

impl McpPreset {
    /// Parse a preset name from the CLI flag value.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "code-agent" | "code_agent" => Some(Self::CodeAgent),
            _ => None,
        }
    }

    /// Raw YAML for the preset.
    pub fn yaml(self) -> &'static str {
        match self {
            Self::CodeAgent => CODE_AGENT_POLICY_YAML,
        }
    }

    /// Stable filename used when materializing the preset to disk.
    pub fn filename(self) -> &'static str {
        match self {
            Self::CodeAgent => "code_agent_preset.yaml",
        }
    }

    /// Materialize the preset YAML into a temporary file and return the
    /// path. The caller is responsible for cleaning up the surrounding
    /// directory, which is also returned so its lifetime is explicit.
    ///
    /// Using a temp file (rather than a pure in-memory parse) keeps us
    /// compatible with `load_policy`, which takes a `&Path` so the
    /// source hash and runtime hash computations use the bytes on
    /// disk.
    pub fn materialize_to_temp(self) -> Result<MaterializedPreset, CliError> {
        let dir = tempdir_in_ci_friendly()?;
        let path = dir.join(self.filename());
        let mut file = fs::File::create(&path)
            .map_err(|e| CliError::cli_io_error(format!("failed to materialize preset: {e}")))?;
        file.write_all(self.yaml().as_bytes())
            .map_err(|e| CliError::cli_io_error(format!("failed to write preset yaml: {e}")))?;
        Ok(MaterializedPreset { path, _dir: dir })
    }
}

/// RAII holder for a preset YAML materialized to disk.
///
/// The policy file is removed when this value is dropped so long-lived
/// `chio mcp serve` processes do not accumulate temp files. Callers
/// keep the holder alive for the entire duration they need the
/// `.path()` to remain valid.
pub struct MaterializedPreset {
    path: PathBuf,
    _dir: PresetDir,
}

impl MaterializedPreset {
    /// Path to the materialized YAML file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Owned temporary directory that removes itself on drop.
struct PresetDir {
    path: PathBuf,
}

impl PresetDir {
    fn join(&self, leaf: &str) -> PathBuf {
        self.path.join(leaf)
    }
}

impl Drop for PresetDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn tempdir_in_ci_friendly() -> Result<PresetDir, CliError> {
    // Use a 128-bit random suffix so two rapid invocations from the same
    // process can never collide, even on coarse-clock CI runners where
    // SystemTime has millisecond resolution. A PID+timestamp-only nonce
    // could otherwise reuse an existing directory under concurrent calls
    // and silently clobber each other's preset files.
    use rand_core::{OsRng, RngCore};
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut rng_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut rng_bytes);
    let suffix = hex::encode(rng_bytes);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("chio-preset-{pid}-{stamp}-{suffix}"));
    fs::create_dir_all(&path)
        .map_err(|e| CliError::cli_io_error(format!("failed to create preset temp dir: {e}")))?;
    Ok(PresetDir { path })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn code_agent_preset_yaml_embedded() {
        assert!(CODE_AGENT_POLICY_YAML.contains("kernel:"));
        assert!(CODE_AGENT_POLICY_YAML.contains("forbidden_path"));
        assert!(CODE_AGENT_POLICY_YAML.contains("shell_command"));
        assert!(CODE_AGENT_POLICY_YAML.contains(".env"));
    }

    #[test]
    fn preset_name_parses() {
        assert_eq!(
            McpPreset::from_name("code-agent"),
            Some(McpPreset::CodeAgent)
        );
        assert_eq!(
            McpPreset::from_name("code_agent"),
            Some(McpPreset::CodeAgent)
        );
        assert_eq!(McpPreset::from_name("nope"), None);
    }

    #[test]
    fn code_agent_preset_materializes_to_disk() {
        let materialized = McpPreset::CodeAgent
            .materialize_to_temp()
            .expect("materialize preset");
        assert!(materialized.path().exists());
        let bytes = std::fs::read_to_string(materialized.path()).expect("read preset");
        assert_eq!(bytes, CODE_AGENT_POLICY_YAML);
    }
}
