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
/// Only the `[tee]` table is parsed; other tables pass through. The top
/// level intentionally does NOT use `deny_unknown_fields`, so the same
/// file can be shared with other tools that mount tables alongside
/// `[tee]`. The `[tee]` table itself IS strict (see [`SidecarTeeSection`]):
/// a typo in a key name there silently downgrading to the implicit
/// `verdict-only` default would be a fail-open misconfiguration vector
/// for the trust-boundary that decides shadow/enforce participation.
#[derive(Debug, Default, Deserialize)]
struct SidecarConfig {
    #[serde(default)]
    tee: SidecarTeeSection,
}

/// Strict `[tee]` table.
///
/// `deny_unknown_fields` catches typos in the operator-supplied config
/// (e.g. `Mode = "enforce"` instead of `mode = "enforce"`) at load time
/// rather than silently treating the table as empty and defaulting to
/// `verdict-only`. The non-`mode` deployment-shape fields below are part
/// of the sidecar config surface but are resolved by the binary from
/// environment variables (see `src/main.rs`), not by the mode resolver;
/// they are pinned here so the example sidecar TOML in
/// `examples/tee-sidecar/chio-tee.toml` loads under `deny_unknown_fields`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarTeeSection {
    #[serde(default)]
    mode: Option<String>,
    /// Runtime working directory. The binary takes this from
    /// `CHIO_TEE_RUNTIME_DIR`; the TOML mirror is accepted for documentation
    /// parity and kept loadable under `deny_unknown_fields`.
    #[serde(default)]
    #[allow(dead_code)]
    runtime_dir: Option<String>,
    /// Reserved: persistent spool directory.
    #[serde(default)]
    #[allow(dead_code)]
    spool_dir: Option<String>,
    /// Reserved: spool size cap in bytes.
    #[serde(default)]
    #[allow(dead_code)]
    max_spool_bytes: Option<u64>,
    /// Reserved: pinned wire format identifier.
    #[serde(default)]
    #[allow(dead_code)]
    frame_format: Option<String>,
    /// Reserved: redaction-pass identifier.
    #[serde(default)]
    #[allow(dead_code)]
    redaction_pass: Option<String>,
}

/// Tenant manifest schema fragment.
///
/// Parsed locally until `chio-manifest` exposes a shared type. Same
/// strictness rationale as [`SidecarConfig`]: the top level is
/// permissive (the manifest carries many tables), but the
/// `[tenant.tee]` table itself is strict.
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

/// Strict `[tenant.tee]` table. See [`SidecarTeeSection`] for rationale.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
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
    let Some(raw) = read_optional_config(path)? else {
        return Ok(None);
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
    let Some(raw) = read_optional_config(path)? else {
        return Ok(None);
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

fn read_optional_config(path: &Path) -> Result<Option<String>, ConfigError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        }),
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

    #[test]
    fn optional_config_reader_returns_none_for_missing_and_contents_for_present_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.toml");
        assert_eq!(read_optional_config(&missing).unwrap(), None);

        let present = dir.path().join("tee.toml");
        std::fs::write(&present, "[tee]\nmode = \"shadow\"\n").unwrap();
        assert_eq!(
            read_optional_config(&present).unwrap().as_deref(),
            Some("[tee]\nmode = \"shadow\"\n")
        );
    }

    /// Regression: a typo in the `[tee]` table key (e.g. capitalised
    /// `Mode`) MUST fail-closed at load time. Without
    /// `deny_unknown_fields` on the table, the parser would silently
    /// treat the layer as unset, the resolver would fall through to the
    /// implicit `verdict-only` default, and the operator's intent to run
    /// in `enforce` would be lost without any signal.
    #[test]
    fn toml_rejects_typo_in_tee_table_key() {
        let raw = "[tee]\nMode = \"enforce\"\n";
        let result = parse_toml_mode_from_str(&PathBuf::from("test.toml"), raw);
        assert!(
            matches!(result, Err(ConfigError::Toml { .. })),
            "typo in [tee] key must fail-closed; got {result:?}"
        );
    }

    #[test]
    fn toml_rejects_unknown_key_in_tee_table() {
        let raw = "[tee]\nmode = \"shadow\"\nunknown_key = \"value\"\n";
        let result = parse_toml_mode_from_str(&PathBuf::from("test.toml"), raw);
        assert!(
            matches!(result, Err(ConfigError::Toml { .. })),
            "unknown key in [tee] must fail-closed; got {result:?}"
        );
    }

    #[test]
    fn tenant_rejects_unknown_key_in_tee_table() {
        let raw = "[tenant.tee]\nmode = \"enforce\"\nrogue = true\n";
        let result = load_tenant_manifest_mode_from_str(&PathBuf::from("manifest.toml"), raw);
        assert!(
            matches!(result, Err(ConfigError::Toml { .. })),
            "unknown key in [tenant.tee] must fail-closed; got {result:?}"
        );
    }

    /// Top-level tables outside `[tee]` are tolerated so the same file
    /// can host adjacent configuration for other tools.
    #[test]
    fn toml_top_level_remains_permissive() {
        let raw = "[tee]\nmode = \"shadow\"\n\n[other_tool]\nfoo = \"bar\"\n";
        let mode = parse_toml_mode_from_str(&PathBuf::from("test.toml"), raw)
            .unwrap()
            .unwrap();
        assert_eq!(mode, Mode::Shadow);
    }

    /// The deployment-shape fields documented in
    /// `examples/tee-sidecar/chio-tee.toml` are accepted today (they
    /// are wired in a later task) so the example continues to load.
    #[test]
    fn toml_accepts_documented_deployment_fields() {
        let raw = r#"
[tee]
mode = "shadow"
runtime_dir = "/run/chio-tee"
spool_dir = "/var/lib/chio/tee/spool"
max_spool_bytes = 67108864
frame_format = "chio-tee-frame.v1"
redaction_pass = "chio:guards/redact@0.1.0"
"#;
        let mode = parse_toml_mode_from_str(&PathBuf::from("test.toml"), raw)
            .unwrap()
            .unwrap();
        assert_eq!(mode, Mode::Shadow);
    }
}
