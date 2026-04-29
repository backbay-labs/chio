//! Configuration sources for the TEE shadow runner.
//!
//! Three layers feed [`crate::mode::ResolvedMode::resolve`]:
//!
//! - [`load_env_mode`]: reads `CHIO_TEE_MODE`.
//! - [`load_toml_mode`]: parses `[tee] mode` from a sidecar TOML file. The
//!   path is taken from `CHIO_TEE_CONFIG`, falling back to
//!   `/etc/chio/tee.toml`.
//! - [`load_tenant_manifest_mode`]: reads `tenant.tee.mode` from a manifest
//!   document. Callers can pass the tenant TOML directly via
//!   [`load_tenant_manifest_mode_from_str`].
//!
//! This module is deliberately I/O-light and side-effect-free where possible
//! so tests can drive it with explicit env mutations and `tempfile` paths.
//!
//! SIGUSR1 wiring lives in [`install_sigusr1_handler`]: the handler is a
//! thin shim that reads `${CHIO_TEE_RUNTIME_DIR}/mode-request` and applies
//! the transition through [`crate::mode::MoteState::transition`]. The unit
//! tests in `tests/mode_precedence.rs` drive [`MoteState::transition`]
//! directly so the test surface does not depend on signal delivery.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::mode::{Mode, ParseModeError};

/// Default sidecar TOML path when `CHIO_TEE_CONFIG` is unset.
pub const DEFAULT_TOML_PATH: &str = "/etc/chio/tee.toml";

/// Env var name that overrides the resolved mode.
pub const ENV_MODE: &str = "CHIO_TEE_MODE";

/// Env var name that overrides the sidecar TOML path.
pub const ENV_CONFIG_PATH: &str = "CHIO_TEE_CONFIG";

/// Errors produced when loading config layers.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// I/O error reading a config file.
    #[error("io error reading {path}: {source}")]
    Io {
        /// Path being read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// TOML parse error.
    #[error("toml parse error in {path}: {source}")]
    Toml {
        /// Path being parsed.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// A mode tag was present but not a known value.
    #[error("invalid mode tag: {0}")]
    Mode(#[from] ParseModeError),
}

/// Sidecar TOML schema fragment.
///
/// Only the `[tee]` table is parsed; other tables pass through.
#[derive(Debug, Default, Deserialize)]
struct SidecarConfig {
    #[serde(default)]
    tee: SidecarTeeSection,
}

#[derive(Debug, Default, Deserialize)]
struct SidecarTeeSection {
    #[serde(default)]
    mode: Option<String>,
}

/// Tenant manifest schema fragment.
///
/// Parsed locally until `chio-manifest` exposes a shared type.
#[derive(Debug, Default, Deserialize)]
struct TenantManifest {
    #[serde(default)]
    tenant: TenantSection,
}

#[derive(Debug, Default, Deserialize)]
struct TenantSection {
    #[serde(default)]
    tee: TenantTeeSection,
}

#[derive(Debug, Default, Deserialize)]
struct TenantTeeSection {
    #[serde(default)]
    mode: Option<String>,
}

/// Load the env-layer mode from `CHIO_TEE_MODE`.
///
/// Returns `Ok(None)` if unset or empty (so the next layer can take over).
/// Returns `Err` if set to an unrecognised value (fail-closed).
pub fn load_env_mode() -> Result<Option<Mode>, ConfigError> {
    parse_env_mode(std::env::var(ENV_MODE).ok())
}

/// Pure helper for env-layer parsing. Splitting it out lets tests drive the
/// resolver without mutating the live process env.
pub fn parse_env_mode(raw: Option<String>) -> Result<Option<Mode>, ConfigError> {
    match raw {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => Ok(Some(s.trim().parse::<Mode>()?)),
    }
}

/// Resolve the sidecar TOML path. Honours `CHIO_TEE_CONFIG`; otherwise
/// returns [`DEFAULT_TOML_PATH`]. The resolved path may not exist; callers
/// should treat ENOENT as "no TOML layer configured".
pub fn resolve_toml_path() -> PathBuf {
    std::env::var(ENV_CONFIG_PATH)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_TOML_PATH))
}

/// Load the TOML-layer mode from `path`. Returns `Ok(None)` if the file does
/// not exist or `[tee] mode` is unset; returns `Err` for I/O errors, TOML
/// parse errors, or invalid mode tags.
pub fn load_toml_mode(path: &Path) -> Result<Option<Mode>, ConfigError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    parse_toml_mode_from_str(path, &raw)
}

/// Pure helper for TOML-layer parsing. Useful in tests that supply
/// configuration as a string instead of touching the filesystem.
pub fn parse_toml_mode_from_str(path: &Path, raw: &str) -> Result<Option<Mode>, ConfigError> {
    let cfg: SidecarConfig = toml::from_str(raw).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    match cfg.tee.mode {
        None => Ok(None),
        Some(s) => Ok(Some(s.parse::<Mode>()?)),
    }
}

/// Load the tenant-manifest-layer mode from `path`.
///
/// Returns `Ok(None)` if the manifest file does not exist or
/// `tenant.tee.mode` is unset.
pub fn load_tenant_manifest_mode(path: &Path) -> Result<Option<Mode>, ConfigError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ConfigError::Io {
                path: path.to_path_buf(),
                source: e,
            });
        }
    };
    load_tenant_manifest_mode_from_str(path, &raw)
}

/// Pure helper for tenant-manifest parsing.
pub fn load_tenant_manifest_mode_from_str(
    path: &Path,
    raw: &str,
) -> Result<Option<Mode>, ConfigError> {
    let cfg: TenantManifest = toml::from_str(raw).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    match cfg.tenant.tee.mode {
        None => Ok(None),
        Some(s) => Ok(Some(s.parse::<Mode>()?)),
    }
}

/// Optional SIGUSR1 wiring.
///
/// Spawns a background thread that listens for SIGUSR1 via `signal-hook` and
/// invokes `on_signal` on each delivery. The closure is responsible for
/// reading the request file and calling `MoteState::transition`. Returns the
/// `signal-hook` `SignalsInfo` handle so the caller can shut the listener
/// down at process exit.
///
/// Implementations should keep the closure short: signal handlers run on a
/// dedicated thread but the [`crate::mode::MoteState::transition`] path takes
/// no locks beyond the `ArcSwap` swap, so the typical handler stays well
/// under microseconds.
///
/// This shim is gated behind `cfg(unix)` because Windows does not deliver
/// POSIX signals; on non-Unix platforms callers should drive
/// `MoteState::transition` exclusively through the control-plane RPC.
#[cfg(unix)]
pub fn install_sigusr1_handler<F>(mut on_signal: F) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnMut() + Send + 'static,
{
    use signal_hook::consts::SIGUSR1;
    use signal_hook::iterator::Signals;

    let mut signals = Signals::new([SIGUSR1])?;
    let handle = std::thread::Builder::new()
        .name("chio-tee-sigusr1".to_string())
        .spawn(move || {
            for sig in signals.forever() {
                if sig == SIGUSR1 {
                    on_signal();
                }
            }
        })?;
    Ok(handle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn env_parse_unset() {
        assert_eq!(parse_env_mode(None).unwrap(), None);
    }

    #[test]
    fn env_parse_empty_is_none() {
        assert_eq!(parse_env_mode(Some(String::new())).unwrap(), None);
        assert_eq!(parse_env_mode(Some("   ".to_string())).unwrap(), None);
    }

    #[test]
    fn env_parse_valid() {
        assert_eq!(
            parse_env_mode(Some("shadow".to_string())).unwrap(),
            Some(Mode::Shadow)
        );
    }

    #[test]
    fn env_parse_invalid() {
        assert!(parse_env_mode(Some("monitor".to_string())).is_err());
    }

    #[test]
    fn toml_parse_table() {
        let raw = "[tee]\nmode = \"enforce\"\n";
        let mode = parse_toml_mode_from_str(&PathBuf::from("test.toml"), raw)
            .unwrap()
            .unwrap();
        assert_eq!(mode, Mode::Enforce);
    }

    #[test]
    fn toml_parse_missing_table() {
        let raw = "# empty\n";
        let mode = parse_toml_mode_from_str(&PathBuf::from("test.toml"), raw).unwrap();
        assert_eq!(mode, None);
    }

    #[test]
    fn tenant_parse_table() {
        let raw = "[tenant.tee]\nmode = \"shadow\"\n";
        let mode = load_tenant_manifest_mode_from_str(&PathBuf::from("manifest.toml"), raw)
            .unwrap()
            .unwrap();
        assert_eq!(mode, Mode::Shadow);
    }
}
